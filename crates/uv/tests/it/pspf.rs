// crates/uv/tests/it/pspf.rs

use std::fs::{self, File};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command; // For running `uv` CLI

use assert_cmd::prelude::*; // Add methods on commands
use predicates::prelude::*; // Used for writing assertions
use tempfile::{tempdir, NamedTempFile};
use flate2::read::GzDecoder;
use tar::Archive;
use rsa::pkcs1::DecodeRsaPublicKey;

use uv::pspf::{PspFileFooter, PSP_EOF_MAGIC, PSP_FOOTER_SIZE, INTERNAL_FOOTER_MAGIC, PSPF_VERSION_V0_1, ConfigJson};
use sha2::{Sha256, Digest};


// Helper to create a dummy RSA key pair (private and public PEM)
// For tests, using 2048 bits for speed. Spec requires 4096.
fn generate_test_rsa_keypair() -> Result<(NamedTempFile, NamedTempFile), anyhow::Error> {
    let mut rng = rand::rngs::OsRng;
    let bits = 2048;
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, bits)
        .expect("failed to generate a key");
    let pub_key = rsa::RsaPublicKey::from(&priv_key);

    let priv_key_pem = priv_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?;
    let pub_key_pem = pub_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?;

    let priv_temp_file = NamedTempFile::new()?;
    fs::write(priv_temp_file.path(), priv_key_pem.as_bytes())?;

    let pub_temp_file = NamedTempFile::new()?;
    fs::write(pub_temp_file.path(), pub_key_pem.as_bytes())?;

    Ok((priv_temp_file, pub_temp_file))
}


#[test]
fn test_pspf_package_command_basic() -> Result<(), anyhow::Error> {
    let temp_dir = tempdir()?;
    let test_data_dir = temp_dir.path();

    // 1. Setup dummy files and project
    let go_launcher_content = b"#!/bin/sh\necho 'Go Launcher'";
    let go_launcher_file = test_data_dir.join("dummy_launcher");
    fs::write(&go_launcher_file, go_launcher_content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&go_launcher_file)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&go_launcher_file, perms)?;
    }


    let uv_binary_content = b"dummy uv binary content";
    let uv_binary_file = test_data_dir.join("dummy_uv");
    fs::write(&uv_binary_file, uv_binary_content)?;
     #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&uv_binary_file)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&uv_binary_file, perms)?;
    }


    let project_name = "my_dummy_app";
    let python_project_dir = test_data_dir.join(project_name);
    fs::create_dir_all(python_project_dir.join("src").join(project_name))?;

    let pyproject_content = format!(r#"[project]
name = "{}"
version = "0.1.0"
dependencies = []
"#, project_name);
    fs::write(python_project_dir.join("pyproject.toml"), pyproject_content)?;
    fs::write(python_project_dir.join("src").join(project_name).join("__init__.py"), "def main(): print('Hello')")?;

    let (priv_key_file, pub_key_file) = generate_test_rsa_keypair()?;
    let output_pspf_file = test_data_dir.join("my_app.pspf");

    // 2. Run `uv pspf package` command
    let mut cmd = Command::cargo_bin("uv")?;
    cmd.arg("pspf")
        .arg("package")
        .arg("--go-launcher")
        .arg(&go_launcher_file)
        .arg("--uv-binary")
        .arg(&uv_binary_file)
        .arg("--project-dir")
        .arg(&python_project_dir)
        .arg("--output-path")
        .arg(&output_pspf_file)
        .arg("--private-key")
        .arg(priv_key_file.path())
        .arg("--entry-point")
        .arg(format!("{}.__init__:main", project_name))
        .arg("--python-version")
        .arg("python3.10");

    cmd.assert().success().stdout(predicate::str::contains("PSPF package created successfully"));

    // 3. Verify the PSPF package
    assert!(output_pspf_file.exists());
    let mut pspf_file_reader = File::open(&output_pspf_file)?;
    let file_size = pspf_file_reader.metadata()?.len();

    // Verify EOF magic
    let mut eof_magic_buffer = [0u8; PSP_EOF_MAGIC.len()];
    pspf_file_reader.seek(SeekFrom::End(-(PSP_EOF_MAGIC.len() as i64)))?;
    pspf_file_reader.read_exact(&mut eof_magic_buffer)?;
    assert_eq!(&eof_magic_buffer, PSP_EOF_MAGIC);

    // Verify Footer
    let mut footer_buffer = [0u8; PSP_FOOTER_SIZE];
    pspf_file_reader.seek(SeekFrom::End(-((PSP_EOF_MAGIC.len() + PSP_FOOTER_SIZE) as i64)))?;
    pspf_file_reader.read_exact(&mut footer_buffer)?;

    let footer = PspFileFooter::from_le_bytes(&footer_buffer)
        .expect("Failed to deserialize footer from PSPF file");

    assert_eq!(footer.internal_footer_magic, INTERNAL_FOOTER_MAGIC, "Internal footer magic mismatch");
    assert_eq!(footer.pspf_version, PSPF_VERSION_V0_1, "PSPF version mismatch");
    assert!(footer.verify_internal_consistency().is_ok(), "Footer internal consistency check failed: {:?}", footer.verify_internal_consistency().err());

    // Extract and verify blocks
    let go_launcher_offset = 0; // Go launcher is always at the beginning
    let go_launcher_size = footer.uv_binary_offset; // Size is up to the start of next block
                                                      // More accurately, we need the size of the go_launcher_file used to create it.
                                                      // The footer itself doesn't store go_launcher_size.
                                                      // For this test, we can assume its size is footer.uv_binary_offset.

    let mut extracted_go_launcher = vec![0u8; go_launcher_size as usize];
    pspf_file_reader.seek(SeekFrom::Start(go_launcher_offset))?;
    pspf_file_reader.read_exact(&mut extracted_go_launcher)?;
    assert_eq!(extracted_go_launcher, go_launcher_content);

    let mut extracted_uv_binary = vec![0u8; footer.uv_binary_size as usize];
    pspf_file_reader.seek(SeekFrom::Start(footer.uv_binary_offset))?;
    pspf_file_reader.read_exact(&mut extracted_uv_binary)?;
    assert_eq!(extracted_uv_binary, uv_binary_content);

    let mut extracted_metadata_tgz = vec![0u8; footer.metadata_tgz_size as usize];
    pspf_file_reader.seek(SeekFrom::Start(footer.metadata_tgz_offset))?;
    pspf_file_reader.read_exact(&mut extracted_metadata_tgz)?;

    let mut extracted_payload_tgz = vec![0u8; footer.payload_tgz_size as usize];
    pspf_file_reader.seek(SeekFrom::Start(footer.payload_tgz_offset))?;
    pspf_file_reader.read_exact(&mut extracted_payload_tgz)?;

    let mut extracted_signature = vec![0u8; footer.package_signature_size as usize];
    pspf_file_reader.seek(SeekFrom::Start(footer.package_signature_offset))?;
    pspf_file_reader.read_exact(&mut extracted_signature)?;

    // Verify Signature
    let mut hasher = Sha256::new();
    hasher.update(&extracted_go_launcher);
    hasher.update(&extracted_uv_binary);
    hasher.update(&extracted_metadata_tgz);
    hasher.update(&extracted_payload_tgz);
    let digest = hasher.finalize();

    let pub_key_pem = fs::read_to_string(pub_key_file.path())?;
    let rsa_pub_key = rsa::RsaPublicKey::from_pkcs1_pem(&pub_key_pem)?;

    let verifying_key = rsa::pss::VerifyingKey::<rsa::sha2::Sha256>::new(rsa_pub_key);

    use rsa::signature::Verifier;
    assert!(verifying_key.verify(&digest, &extracted_signature).is_ok(), "Signature verification failed");

    // Verify metadata.tgz contents (config.json)
    let tar = GzDecoder::new(extracted_metadata_tgz.as_slice());
    let mut archive = Archive::new(tar);
    let mut config_json_data: Option<ConfigJson> = None;

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        if entry.path()?.to_string_lossy() == "config.json" {
            let mut contents = String::new();
            entry.read_to_string(&mut contents)?;
            config_json_data = Some(serde_json::from_str(&contents)?);
            break;
        }
    }
    assert!(config_json_data.is_some(), "config.json not found in metadata.tgz");
    let config = config_json_data.unwrap();
    assert_eq!(config.entry_point, format!("{}.__init__:main", project_name));
    assert_eq!(config.python_version, "python3.10");

    // Verify payload.tgz contents (currently placeholder, so expect empty or minimal)
    let tar_payload = GzDecoder::new(extracted_payload_tgz.as_slice());
    let mut archive_payload = Archive::new(tar_payload);
    // For now, just check if it's a valid tar.gz, possibly empty
    assert!(archive_payload.entries()?.next().is_none(), "Payload TGZ should be empty for now as placeholder is used");


    temp_dir.close()?;
    Ok(())
}
