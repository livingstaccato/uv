//! Commands for PSPF (Pyvider Secure Package Format) operations.

use std::fs::File;
use std::fs::File;
use std::io::{Write, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use anyhow::{Context, Result, bail};
use tracing::debug;
use fs_err;

use rsa::pkcs1::DecodeRsaPrivateKey; // For reading PEM private key
use rsa::RsaPrivateKey;
use rsa::RsaPublicKey; // To work with public key object
use rsa::pkcs1::der::Encode; // For Encode<RsaPublicKey> to get DER bytes

use uv_cli::PsPfPackageArgs;
use uv_fs::Simplified; // For user_display

// Need to bring PspConfig into scope if it's defined in lib.rs or elsewhere
// For now, assuming it might be moved to pspf_format.rs or a new shared types location.
// If it remains in lib.rs, we'd need `crate::PspConfig` and ensure lib.rs exposes it.
// Let's assume for now we'll define/import it appropriately.
// For this step, we will use a local definition if not easily importable, then refactor.
use serde::Serialize; // For serializing config.json
use std::collections::HashMap;
use std::io::BufReader;
use flate2::write::GzEncoder;
use flate2::Compression;
use tar::Builder as TarBuilder;
use tempfile::NamedTempFile;
use sha2::{Sha256, Digest};
use rsa::signature::{RandomizedSigner, SignatureEncoding}; // For PSS
use rsa::pss::Pss;


use crate::commands::ExitStatus;
use crate::printer::Printer;
use crate::pspf_format::{PspConfig, PspFileFooterV1, PSPF_EOF_MAGIC_STRING, PUBLIC_KEY_EMBED_OFFSET, PUBLIC_KEY_MAX_SIZE};


/// Core logic for the `uv pspf package` command.
///
/// This function orchestrates the creation of a PSPF file by:
/// 1. Determining output path and the `uv` binary to use as a base.
/// 2. Copying the base `uv` binary to the output location.
/// 3. Reading the provided private key, deriving the public key, and embedding the
///    DER-encoded public key into the copied `uv` binary at a predefined offset.
/// 4. Creating a `config.json` file with application metadata (entry point,
///    Python version placeholder, environment variables) and packaging it into
///    `metadata.tgz`.
/// 5. Creating a placeholder `payload.tgz` (actual wheel bundling is a TODO).
/// 6. Calculating a SHA-256 hash of the (uv binary + metadata.tgz + payload.tgz).
/// 7. Signing this hash with the private key using RSA-PSS.
/// 8. Assembling the final PSPF file by appending `metadata.tgz`, `payload.tgz`,
///    the signature, a `PspFileFooterV1`, and the `PSPF_EOF_MAGIC_STRING`.
pub(crate) async fn pspf_package(
    args: PsPfPackageArgs,
    printer: Printer,
) -> Result<ExitStatus> {
    debug!("Starting `pspf package` command");

    // 1. Determine output path
    let output_path = if let Some(output) = args.output {
        output
    } else {
        let project_name = args
            .project_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        PathBuf::from(format!("{}.pspf", project_name))
    };
    writeln!(printer.stdout(), "Output PSPF file: {}", output_path.user_display())?;

    // 2. Determine uv_binary_to_use
    let uv_binary_to_use = if let Some(custom_uv_bin) = args.uv_bin {
        if !custom_uv_bin.exists() {
            bail!("Specified uv binary path does not exist: {}", custom_uv_bin.user_display());
        }
        custom_uv_bin
    } else {
        std::env::current_exe().context("Failed to get current executable path")?
    };
    writeln!(printer.stdout(), "Using uv binary: {}", uv_binary_to_use.user_display())?;

    // 3. Copy uv_binary_to_use to output_path (or temporary path initially)
    // For now, we'll copy to the output path and then append to it.
    // If output_path exists, we might want to confirm overwrite or use a temp file first.
    // For simplicity in this step, we overwrite.
    if output_path.exists() {
        writeln!(printer.stderr(), "Warning: Output file {} already exists and will be overwritten.", output_path.user_display())?;
    }
    fs_err::copy(&uv_binary_to_use, &output_path).with_context(|| {
        format!(
            "Failed to copy uv binary from {} to {}",
            uv_binary_to_use.user_display(),
            output_path.user_display()
        )
    })?;
    let mut pspf_file = fs_err::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&output_path)
        .with_context(|| format!("Failed to open PSPF file for writing: {}", output_path.user_display()))?;

    let uv_binary_size = pspf_file.metadata()
        .with_context(|| format!("Failed to get metadata for copied uv binary: {}", output_path.user_display()))?
        .len();

    writeln!(printer.stdout(), "Copied uv binary (size: {} bytes) to output path.", uv_binary_size)?;

    // 4. Derive public key from args.private_key & 5. Embed public key
    // This is a complex step involving crypto operations.
    // We'll add a placeholder for now and implement it properly next.
    // For embedding, we'd need to:
    //    a. Read private key from args.private_key_path - DONE
    //    b. Derive public key (e.g., in DER format) - DONE
    //    c. Ensure PUBLIC_KEY_EMBED_OFFSET + public_key.len() <= uv_binary_size. This is a critical check. - DONE
    //       If the binary is too small, we must fail or have a strategy.
    //       The spec says "predefined, fixed offset". If the binary is smaller than this offset, packaging fails.
    //    d. Seek to PUBLIC_KEY_EMBED_OFFSET in pspf_file and write the public key. - DONE
    //    e. Pad with zeros up to PUBLIC_KEY_MAX_SIZE if the key is smaller. - DONE

    // Read private key from PEM file
    let private_key_pem = fs_err::read_to_string(&args.private_key)
        .with_context(|| format!("Failed to read private key from {}", args.private_key.user_display()))?;
    let private_key = RsaPrivateKey::from_pkcs1_pem(&private_key_pem)
        .context("Failed to parse RSA private key from PEM file. Ensure it's a valid PKCS#1 RSA private key.")?;

    // Derive public key
    let public_key: RsaPublicKey = private_key.to_public_key();

    // Serialize public key to DER format
    // RsaPublicKey.to_der() is not directly available.
    // We need to use `public_key.to_pkcs1_der()` which returns a `Result<Document, Error>`
    // where Document is `alloc::vec::Vec<u8>`.
    let public_key_der_doc = public_key.to_pkcs1_der()
        .map_err(|e| anyhow::anyhow!("Failed to serialize public key to PKCS#1 DER: {}", e))?;
    let public_key_der = public_key_der_doc.as_bytes();


    if public_key_der.len() > PUBLIC_KEY_MAX_SIZE {
        bail!(
            "Derived public key size ({} bytes) exceeds maximum allowed size ({} bytes). Try a smaller RSA key or increase PUBLIC_KEY_MAX_SIZE.",
            public_key_der.len(),
            PUBLIC_KEY_MAX_SIZE
        );
    }

    if uv_binary_size < PUBLIC_KEY_EMBED_OFFSET + PUBLIC_KEY_MAX_SIZE as u64 {
        // This check should ideally use public_key_der.len() for the actual key size,
        // but fixed offset embedding implies we always reserve PUBLIC_KEY_MAX_SIZE space.
        bail!(
            "The selected uv binary (size: {} bytes) is too small to embed the public key (max {} bytes) at offset {}. Minimum required size for key area: {}.",
            uv_binary_size, PUBLIC_KEY_MAX_SIZE, PUBLIC_KEY_EMBED_OFFSET, PUBLIC_KEY_EMBED_OFFSET + PUBLIC_KEY_MAX_SIZE as u64
        );
    }

    // Seek to the predefined offset and write the DER-encoded public key
    pspf_file.seek(SeekFrom::Start(PUBLIC_KEY_EMBED_OFFSET))
        .context("Failed to seek to public key embed offset in PSPF file")?;
    pspf_file.write_all(public_key_der)
        .context("Failed to write public key DER to PSPF file")?;

    // Pad the rest of the public key area with zeros if the key is smaller than PUBLIC_KEY_MAX_SIZE
    if public_key_der.len() < PUBLIC_KEY_MAX_SIZE {
        let padding_size = PUBLIC_KEY_MAX_SIZE - public_key_der.len();
        let padding = vec![0u8; padding_size];
        pspf_file.write_all(&padding)
            .context("Failed to write public key padding to PSPF file")?;
        debug!("Padded public key area with {} zero bytes.", padding_size);
    }

    writeln!(printer.stdout(), "Public key ({} bytes) embedded at offset {} (padded to {} bytes).", public_key_der.len(), PUBLIC_KEY_EMBED_OFFSET, PUBLIC_KEY_MAX_SIZE)?;

    // 6. Create metadata.tgz
    //    - config.json (entry_point, python_version, env_vars)
    //    - (Potentially other metadata files)

    // Parse environment variables from args
    let mut env_vars_map = HashMap::new();
    for env_str in args.env {
        if let Some((key, value)) = env_str.split_once('=') {
            env_vars_map.insert(key.to_string(), value.to_string());
        } else {
            writeln!(printer.stderr(), "Warning: Ignoring malformed environment variable string: {}", env_str)?;
        }
    }

    // TODO: Python version for config.json should be detected from the project or specified via CLI.
    // For now, it's None, and a warning is printed.
    let python_version_for_config: Option<String> = None;
    if python_version_for_config.is_none() {
        writeln!(
            printer.stderr(),
            "{}",
            "Warning: Python version for the packaged application is not specified. \
            Execution will attempt to use a default Python. \
            Future versions will allow specifying or detecting this."
            .yellow()
        )?;
    }

    let pspf_config = PspConfig {
        entry_point: args.entry_point.clone(),
        python_version: python_version_for_config,
        env_vars: if env_vars_map.is_empty() { None } else { Some(env_vars_map) },
    };

    let config_json_bytes = serde_json::to_vec_pretty(&pspf_config)
        .context("Failed to serialize pspf_config to JSON")?;

    // Create metadata.tgz in memory (or a temp file)
    let mut metadata_tgz_data = Vec::new();
    let gz_encoder = GzEncoder::new(&mut metadata_tgz_data, Compression::default());
    let mut tar_builder = TarBuilder::new(gz_encoder);

    let mut header = tar::Header::new_gnu();
    header.set_path("config.json")?;
    header.set_size(config_json_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum(); // Calculate checksum
    tar_builder.append(&header, config_json_bytes.as_slice())?;

    // Add other metadata files here if needed in the future

    tar_builder.finish()?; // Finish writing to the tar archive
    let gz_encoder = tar_builder.into_inner()?; // Get the GzEncoder back
    gz_encoder.finish()?; // Finish writing to the GzEncoder (writes compressed data to metadata_tgz_data)

    // Append metadata.tgz to the PSPF file
    // The current end of the file is where the uv_binary_size (with embedded key) ends.
    pspf_file.seek(SeekFrom::Start(uv_binary_size))
        .context("Failed to seek to metadata.tgz offset")?;
    pspf_file.write_all(&metadata_tgz_data)
        .context("Failed to write metadata.tgz to PSPF file")?;

    let metadata_offset = uv_binary_size; // Metadata starts right after the uv_binary part
    let metadata_size = metadata_tgz_data.len() as u64;
    writeln!(printer.stdout(), "Appended metadata.tgz (size: {} bytes) at offset {}.", metadata_size, metadata_offset)?;

    // 7. Create payload.tgz
    //    - Gather/build necessary Python wheels for the project.
    //    - This is a MAJOR TODO requiring integration with uv's resolver and wheel builder.
    //    - For now, create a placeholder payload.tgz with a dummy wheel file.

    writeln!(printer.stdout(), "Starting payload creation (currently placeholder)...")?;

    // Placeholder: Simulate having a list of wheel files.
    // In reality, this list would come from resolving and fetching/building project dependencies.
    let temp_payload_dir = tempfile::tempdir()
        .context("Failed to create temporary directory for payload wheels")?;

    let dummy_wheel_name = "dummy_package-1.0-py3-none-any.whl";
    let dummy_wheel_path = temp_payload_dir.path().join(dummy_wheel_name);
    let mut dummy_wheel_file = File::create(&dummy_wheel_path)
        .context("Failed to create dummy wheel file")?;
    dummy_wheel_file.write_all(b"This is a dummy wheel file content.")
        .context("Failed to write to dummy wheel file")?;

    let wheel_files_to_package: Vec<PathBuf> = vec![dummy_wheel_path];
    // TODO: Replace above with actual logic:
    // let project_workspace = uv_workspace::Workspace::discover(&args.project_path, &uv_workspace::DiscoveryOptions::default()).await
    //    .context("Failed to discover workspace for project.")?;
    // let requirements = ... extract from project_workspace ...
    // let resolved_wheels = ... resolve requirements using uv_resolver ... (needs Cache, Python env info etc.)
    // let wheel_files_to_package = ... fetch/build wheels from resolved_wheels ... (needs uv_distribution, uv_installer)

    let mut payload_tgz_data = Vec::new();
    let gz_encoder_payload = GzEncoder::new(&mut payload_tgz_data, Compression::default());
    let mut tar_builder_payload = TarBuilder::new(gz_encoder_payload);

    for wheel_path in &wheel_files_to_package {
        let wheel_filename = wheel_path.file_name()
            .ok_or_else(|| anyhow::anyhow!("Failed to get filename from wheel path: {}", wheel_path.display()))?
            .to_string_lossy();

        tar_builder_payload.append_path_with_name(wheel_path, &*wheel_filename)
            .with_context(|| format!("Failed to add wheel {} to payload.tgz", wheel_path.display()))?;
        debug!("Added {} to payload.tgz", wheel_filename);
    }

    tar_builder_payload.finish()?;
    let gz_encoder_payload = tar_builder_payload.into_inner()?;
    gz_encoder_payload.finish()?;

    // Append payload.tgz to the PSPF file
    pspf_file.seek(SeekFrom::Start(metadata_offset + metadata_size))
        .context("Failed to seek to payload.tgz offset")?;
    pspf_file.write_all(&payload_tgz_data)
        .context("Failed to write payload.tgz to PSPF file")?;

    let payload_offset = metadata_offset + metadata_size;
    let payload_size = payload_tgz_data.len() as u64;
    writeln!(printer.stdout(), "Appended payload.tgz (size: {} bytes) at offset {}.", payload_size, payload_offset)?;

    temp_payload_dir.close().context("Failed to clean up temporary payload directory")?;

    // 8. Sign the package
    // This involves hashing the (modified uv binary + metadata.tgz + payload.tgz)
    // and then signing that hash with the private key.
    writeln!(printer.stdout(), "Signing the package...")?;
    let mut hasher = Sha256::new();

    // Hash uv_binary_portion (from the beginning of the file up to uv_binary_size)
    // This part now includes the embedded public key.
    pspf_file.seek(SeekFrom::Start(0))
        .context("Failed to seek to start of PSPF file for signing hash")?;
    let mut binary_reader = BufReader::new(&mut pspf_file).take(uv_binary_size);
    std::io::copy(&mut binary_reader, &mut hasher)
        .context("Failed to hash uv binary content for signing")?;
    drop(binary_reader); // Release borrow of pspf_file

    // Hash metadata.tgz (already in memory in metadata_tgz_data)
    hasher.update(&metadata_tgz_data);

    // Hash payload.tgz (already in memory in payload_tgz_data)
    hasher.update(&payload_tgz_data);

    let digest_to_sign = hasher.finalize();
    debug!("Digest to sign: {:x}", digest_to_sign);

    // Sign the hash with the private key using RSA-PSS
    // The private_key was loaded earlier during public key embedding.
    let mut rng = rand::thread_rng();
    let padding_scheme = Pss::new::<Sha256>();
    let signature_bytes = private_key.sign_with_rng(&mut rng, padding_scheme, &digest_to_sign)
        .map_err(|e| anyhow::anyhow!("Failed to sign data with RSA-PSS: {}", e))?
        .to_vec();

    // Append signature to the PSPF file
    pspf_file.seek(SeekFrom::Start(payload_offset + payload_size))
        .context("Failed to seek to signature offset")?;
    pspf_file.write_all(&signature_bytes)
        .context("Failed to write signature to PSPF file")?;

    let signature_offset = payload_offset + payload_size;
    let signature_size = signature_bytes.len() as u64;
    writeln!(printer.stdout(), "Appended signature (size: {} bytes) at offset {}.", signature_size, signature_offset)?;

    // 9. Assemble final PSPF file (continued):
    //    - PspFileFooterV1 (populated with correct offsets and sizes)
    //    - PSPF_EOF_MAGIC_STRING
    let footer = PspFileFooterV1::new(
        uv_binary_size, // This is the size of the "Modified uv binary" part
        metadata_size,
        uv_binary_size, // metadata_offset is uv_binary_size
        payload_size,
        payload_offset,
        signature_size,
        signature_offset,
    );

    let footer_offset_actual = pspf_file.seek(SeekFrom::End(0))?;
    if signature_offset + signature_size != footer_offset_actual {
        bail!("Internal error: signature end offset {} does not match current file end offset {}", signature_offset + signature_size, footer_offset_actual);
    }

    footer.write_to(&mut pspf_file).context("Failed to write PSPF footer")?;
    writeln!(printer.stdout(), "Appended PSPF footer at offset {}.", footer_offset_actual)?;

    pspf_file.write_all(PSPF_EOF_MAGIC_STRING).context("Failed to write PSPF EOF magic string")?;
    writeln!(printer.stdout(), "Appended PSPF EOF magic string.")?;

    writeln!(printer.stdout(), "PSPF package created successfully: {}", output_path.user_display())?;

    Ok(ExitStatus::Success)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use crate::pspf_format::PspConfig; // Assuming PspConfig might be moved/exposed from pspf_format or lib for testing
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use rsa::pkcs1::der::{DecodeRsaPrivateKey, Encode};
    use rsa::signature::{RandomizedSigner, Verifier, SignatureEncoding};
    use rsa::pss::Pss;
    use sha2::{Sha256, Digest};
    use rand::rngs::OsRng; // For key generation and signing
    use flate2::read::GzDecoder;
    use tar::Archive;

    // Helper to create a new PspConfig for package tests
    // Note: This is distinct from the PspConfig in lib.rs used for deserialization during execution.
    // This one uses Serialize.
    fn new_test_pspf_config_for_package() -> PspConfigForPackage {
        let mut env_vars = HashMap::new();
        env_vars.insert("TEST_KEY".to_string(), "TEST_VALUE".to_string());
        PspConfigForPackage {
            entry_point: "test_module.main:run".to_string(),
            python_version: Some("3.10".to_string()),
            env_vars: Some(env_vars),
        }
    }

    #[test]
    fn test_psp_config_serialization() {
        let config = new_test_pspf_config_for_package();
        let json_bytes = serde_json::to_vec_pretty(&config).unwrap();
        let json_string = String::from_utf8(json_bytes).unwrap();

        // Basic check for key fields
        assert!(json_string.contains("\"entry_point\": \"test_module.main:run\""));
        assert!(json_string.contains("\"python_version\": \"3.10\""));
        assert!(json_string.contains("\"TEST_KEY\": \"TEST_VALUE\""));
    }

    #[test]
    fn test_metadata_tgz_creation_and_extraction() -> Result<()> {
        let config = new_test_pspf_config_for_package();
        let config_json_bytes = serde_json::to_vec_pretty(&config)
            .context("Test: Failed to serialize pspf_config to JSON")?;

        let mut metadata_tgz_data = Vec::new();
        let gz_encoder = GzEncoder::new(&mut metadata_tgz_data, Compression::default());
        let mut tar_builder = TarBuilder::new(gz_encoder);

        let mut header = tar::Header::new_gnu();
        header.set_path("config.json")?;
        header.set_size(config_json_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder.append(&header, config_json_bytes.as_slice())?;
        tar_builder.finish()?;
        let gz_encoder = tar_builder.into_inner()?;
        gz_encoder.finish()?;

        // Now, extract and verify
        let mut extracted_config_json_bytes = Vec::new();
        let tar = GzDecoder::new(Cursor::new(metadata_tgz_data));
        let mut archive = Archive::new(tar);
        for entry_result in archive.entries()? {
            let mut entry = entry_result?;
            if entry.path()?.to_string_lossy() == "config.json" {
                entry.read_to_end(&mut extracted_config_json_bytes)?;
                break;
            }
        }

        assert_eq!(config_json_bytes, extracted_config_json_bytes, "Extracted config.json does not match original");

        // Also deserialize and check struct
        let extracted_config_str = String::from_utf8(extracted_config_json_bytes)?;
        let deserialized_config: PspConfigForPackage = serde_json::from_str(&extracted_config_str)?;

        assert_eq!(config.entry_point, deserialized_config.entry_point);
        assert_eq!(config.python_version, deserialized_config.python_version);
        assert_eq!(config.env_vars, deserialized_config.env_vars);

        Ok(())
    }

    #[test]
    fn test_rsa_pss_sign_verify_roundtrip() -> Result<()> {
        let mut rng = OsRng;
        let bits = 2048; // Standard size for testing
        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .context("Failed to generate RSA private key")?;
        let public_key = private_key.to_public_key();

        let data_to_sign = b"this is some data to sign for the PSPF test";
        let mut hasher = Sha256::new();
        hasher.update(data_to_sign);
        let hashed_data = hasher.finalize();

        let padding_scheme = Pss::new::<Sha256>();

        let signature = private_key.sign_with_rng(&mut rng, padding_scheme.clone(), &hashed_data)
            .map_err(|e| anyhow::anyhow!("RSA-PSS signing failed: {}",e))?
            .to_vec();

        public_key.verify(padding_scheme, &hashed_data, &signature)
            .context("RSA-PSS signature verification failed")?;

        Ok(())
    }

    // TODO: Add integration-style test for pspf_package function itself,
    // mocking file system ops or using temp dirs to verify output structure.
    // This would involve:
    // 1. Generating a key pair.
    // 2. Setting up PsPfPackageArgs.
    // 3. Calling pspf_package (may need to be refactored for testability if it directly uses std::env::current_exe).
    // 4. Opening the output PSPF file.
    // 5. Reading footer, checking magic string.
    // 6. Extracting and verifying embedded public key.
    // 7. Extracting and verifying metadata.tgz and config.json.
    // 8. Verifying signature over (uv_bin_part + metadata.tgz + dummy_payload.tgz).
}
