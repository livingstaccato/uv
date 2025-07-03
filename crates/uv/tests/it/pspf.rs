// crates/uv/tests/it/pspf.rs

use std::fs::{self, File};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::collections::HashMap;
use std::env;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use tempfile::{tempdir, NamedTempFile};
use flate2::read::GzDecoder;
use tar::Archive;

use uv_pspf_format::{
    PspFileFooter, ConfigJson, PSP_EOF_MAGIC, PSP_FOOTER_SIZE,
    INTERNAL_FOOTER_MAGIC, PSPF_VERSION_V0_1, PUBLIC_KEY_DER_SIZE
};
use sha2::{Sha256, Digest};
use rsa::pkcs1::{DecodeRsaPrivateKey}; // For parsing private key PEM
use rsa::pkcs8::DecodePublicKey; // For parsing public key DER
use rsa::RsaPublicKey;


// Helper to create a dummy RSA key pair (private PEM, public DER for embedding)
fn generate_test_rsa_keypair_for_pspf_embedding() -> Result<(NamedTempFile, Vec<u8>, RsaPublicKey), anyhow::Error> {
    let mut rng = rand::rngs::OsRng;
    let bits = 2048; // Use 2048 for tests for speed. Spec requires 4096.
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, bits)?;
    let pub_key_rsa = RsaPublicKey::from(&priv_key);

    let priv_key_pem_str = priv_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?;

    let priv_temp_file = NamedTempFile::new()?;
    fs::write(priv_temp_file.path(), priv_key_pem_str.as_bytes())?;

    use rsa::pkcs8::EncodePublicKey; // Trait for to_public_key_der
    let pub_key_der_vec = pub_key_rsa.to_public_key_der()
      .map_err(|e| anyhow::anyhow!("Failed to encode pub key to DER: {}", e))?;

    let mut final_public_key_bytes = vec![0u8; PUBLIC_KEY_DER_SIZE];
    if pub_key_der_vec.len() > PUBLIC_KEY_DER_SIZE {
        return Err(anyhow::anyhow!("Generated public key DER ({} bytes) is larger than allocated size ({} bytes)", pub_key_der_vec.len(), PUBLIC_KEY_DER_SIZE));
    }
    final_public_key_bytes[..pub_key_der_vec.len()].copy_from_slice(&pub_key_der_vec);

    Ok((priv_temp_file, final_public_key_bytes, pub_key_rsa))
}


#[test]
fn test_pspf_package_self_unwrapping() -> Result<(), anyhow::Error> {
    let temp_dir = tempdir()?;
    let test_data_dir = temp_dir.path();

    // 1. Setup
    let uv_binary_to_package = env::current_exe()?; // Use the test runner itself as the base UV

    let project_name = "my_self_unwrap_app";
    let python_project_dir = test_data_dir.join(project_name);
    fs::create_dir_all(&python_project_dir)?;

    let pyproject_content = format!(r#"[project]
name = "{}"
version = "0.1.0"
dependencies = []
"#, project_name);
    fs::write(python_project_dir.join("pyproject.toml"), pyproject_content)?;
    // Create a dummy entry point file
    let src_dir = python_project_dir.join("src").join(project_name);
    fs::create_dir_all(&src_dir)?;
    fs::write(src_dir.join("__init__.py"), "def main():\n    print('Hello from PSPF self-unwrapped payload!')\n")?;


    let (priv_key_file, expected_embedded_pub_key_der, verification_pub_key) =
        generate_test_rsa_keypair_for_pspf_embedding()?;
    let output_pspf_file = test_data_dir.join(format!("{}.pspf", project_name));

    // 2. Run `uv pspf package`
    let mut cmd = StdCommand::cargo_bin("uv")?;
    cmd.arg("pspf")
        .arg("package")
        .arg("--uv-binary-to-package")
        .arg(&uv_binary_to_package) // Explicitly provide current exe
        .arg("--project-dir")
        .arg(&python_project_dir)
        .arg("--output-path")
        .arg(&output_pspf_file)
        .arg("--private-key")
        .arg(priv_key_file.path())
        .arg("--entry-point")
        .arg(format!("{}.__init__:main", project_name))
        .arg("--python-version")
        .arg("python3.10"); // Ensure this python is findable by the test env or adjust

    let package_output = cmd.output()?;
    if !package_output.status.success() {
        eprintln!("Packaging stdout: {}", String::from_utf8_lossy(&package_output.stdout));
        eprintln!("Packaging stderr: {}", String::from_utf8_lossy(&package_output.stderr));
    }
    package_output.assert().success();
    assert!(String::from_utf8_lossy(&package_output.stdout).contains("Successfully created PSPF package"));


    // 3. Verify PSPF Structure and Signature (Static Analysis)
    assert!(output_pspf_file.exists(), "Output PSPF file was not created");
    let mut pspf_file_reader = File::open(&output_pspf_file)?;

    let mut eof_magic_buffer = [0u8; PSP_EOF_MAGIC.len()];
    pspf_file_reader.seek(SeekFrom::End(-(PSP_EOF_MAGIC.len() as i64)))?;
    pspf_file_reader.read_exact(&mut eof_magic_buffer)?;
    assert_eq!(&eof_magic_buffer, PSP_EOF_MAGIC, "EOF Magic mismatch");

    let mut footer_buffer = [0u8; PSP_FOOTER_SIZE];
    pspf_file_reader.seek(SeekFrom::End(-((PSP_EOF_MAGIC.len() + PSP_FOOTER_SIZE) as i64)))?;
    pspf_file_reader.read_exact(&mut footer_buffer)?;
    let footer = PspFileFooter::from_le_bytes(&footer_buffer)?;
    footer.verify_internal_consistency().map_err(|e| anyhow::anyhow!(e))?;

    // Verify Embedded Public Key
    let mut actual_embedded_pub_key_der = vec![0u8; PUBLIC_KEY_DER_SIZE];
    pspf_file_reader.seek(SeekFrom::Start(0))?;
    pspf_file_reader.read_exact(&mut actual_embedded_pub_key_der)?;
    assert_eq!(actual_embedded_pub_key_der, expected_embedded_pub_key_der, "Embedded public key DER mismatch");

    // Verify Signature
    // Signed data: Modified UV Binary (Key + UV code) + Metadata TGZ + Payload TGZ
    let mut hasher = Sha256::new();

    // Hash Modified UV Binary part (which is footer.uv_binary_size bytes from start of file)
    assert_eq!(footer.uv_binary_offset, 0, "Footer UV binary offset should be 0 for self-unwrapping model relative to signed content");
    let modified_uv_binary_size = footer.uv_binary_size;
    let mut modified_uv_binary_bytes = vec![0u8; modified_uv_binary_size as usize];
    pspf_file_reader.seek(SeekFrom::Start(0))?;
    pspf_file_reader.read_exact(&mut modified_uv_binary_bytes)?;
    hasher.update(&modified_uv_binary_bytes);

    // Hash Metadata TGZ
    let mut metadata_tgz_bytes = vec![0u8; footer.metadata_tgz_size as usize];
    if footer.metadata_tgz_size > 0 {
        pspf_file_reader.seek(SeekFrom::Start(footer.metadata_tgz_offset))?;
        pspf_file_reader.read_exact(&mut metadata_tgz_bytes)?;
        hasher.update(&metadata_tgz_bytes);
    }

    // Hash Payload TGZ
    let mut payload_tgz_bytes = vec![0u8; footer.payload_tgz_size as usize];
    if footer.payload_tgz_size > 0 {
        pspf_file_reader.seek(SeekFrom::Start(footer.payload_tgz_offset))?;
        pspf_file_reader.read_exact(&mut payload_tgz_bytes)?;
        hasher.update(&payload_tgz_bytes);
    }
    let digest = hasher.finalize();

    let mut signature_bytes = vec![0u8; footer.package_signature_size as usize];
    pspf_file_reader.seek(SeekFrom::Start(footer.package_signature_offset))?;
    pspf_file_reader.read_exact(&mut signature_bytes)?;

    let verifying_key = rsa::pss::VerifyingKey::<rsa::sha2::Sha256>::new(verification_pub_key);
    assert!(verifying_key.verify(&digest, &signature_bytes).is_ok(), "Signature verification failed");

    // Verify metadata.tgz contents (config.json)
    // ... (same as previous test)
    let tar_metadata = GzDecoder::new(metadata_tgz_bytes.as_slice());
    let mut archive_metadata = Archive::new(tar_metadata);
    let mut config_json_data: Option<ConfigJson> = None;
    for entry_result in archive_metadata.entries()? {
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


    // 4. Verify PSPF Execution (Dynamic Analysis - Basic)
    #[cfg(unix)] { // Make executable on Unix
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&output_pspf_file, fs::Permissions::from_mode(0o755))?;
    }

    let pspf_run_output = StdCommand::new(&output_pspf_file).output()?;

    // Check stderr for PSPF detection messages
    let stderr_str = String::from_utf8_lossy(&pspf_run_output.stderr);
    assert!(stderr_str.contains("uv: Detected PSPF package format. Attempting to execute..."), "PSPF detection message not found in stderr. Stderr: {}", stderr_str);
    assert!(stderr_str.contains("uv: PSPF signature verified."), "PSPF signature verification message not found in stderr. Stderr: {}", stderr_str);

    // Check for placeholder execution message (current state of Step 2)
    assert!(stderr_str.contains("uv: PSPF payload execution would start here (currently placeholder)."), "PSPF placeholder execution message not found. Stderr: {}", stderr_str);

    // Placeholder execution should be successful
    assert!(pspf_run_output.status.success(), "PSPF execution failed. Stderr: {}", stderr_str);

    // When payload execution is implemented, check stdout for:
    // assert!(String::from_utf8_lossy(&pspf_run_output.stdout).contains("Hello from PSPF self-unwrapped payload!"));

    temp_dir.close()?;
    Ok(())
}
