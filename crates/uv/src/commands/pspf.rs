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

use crate::commands::ExitStatus;
use crate::printer::Printer;
use crate::pspf_format::{PspFileFooterV1, PSPF_EOF_MAGIC_STRING, PUBLIC_KEY_EMBED_OFFSET, PUBLIC_KEY_MAX_SIZE};


/// Core logic for the `uv pspf package` command.
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

    // TODO: 6. Create metadata.tgz:
    //    - config.json (entry_point, python_version, env_policies)
    //    - (Potentially other metadata files)
    let metadata_tgz_placeholder = b"metadata_content_placeholder"; // Replace with actual tgz
    let metadata_offset = pspf_file.seek(SeekFrom::End(0))?; // Should be uv_binary_size if key is within binary
                                                              // Actually, uv_binary_size is fixed after copy. Appending starts after original binary content.
                                                              // The public key is *embedded within* the uv_binary_size portion.
                                                              // So, metadata_offset should indeed be uv_binary_size.
    if metadata_offset != uv_binary_size {
         // This implies the public key embed logic or uv_binary_size definition needs refinement.
         // For now, let's assume uv_binary_size is the size of the *original* uv binary, and metadata starts after it.
         // The "Modified uv Binary" in the diagram includes the embedded key. So its size is `uv_binary_size`.
         // The key is written *into* this section.
         // So, the first append (metadata.tgz) happens at `uv_binary_size`.
        pspf_file.seek(SeekFrom::Start(uv_binary_size))?;
    }

    pspf_file.write_all(metadata_tgz_placeholder)?;
    let metadata_size = metadata_tgz_placeholder.len() as u64;
    writeln!(printer.stdout(), "Appended placeholder metadata.tgz (size: {} bytes) at offset {}.", metadata_size, uv_binary_size)?;


    // TODO: 7. Create payload.tgz:
    //    - Gather/build necessary Python wheels for the project.
    let payload_tgz_placeholder = b"payload_content_placeholder_longer"; // Replace with actual tgz
    let payload_offset = pspf_file.seek(SeekFrom::End(0))?;
    pspf_file.write_all(payload_tgz_placeholder)?;
    let payload_size = payload_tgz_placeholder.len() as u64;
    writeln!(printer.stdout(), "Appended placeholder payload.tgz (size: {} bytes) at offset {}.", payload_size, payload_offset)?;

    // TODO: 8. Sign the package:
    //    - Concatenate (uv_binary_with_embedded_key || metadata.tgz || payload.tgz).
    //    - Hash the concatenation (SHA-256).
    //    - Sign the hash with args.private_key (RSA-PSS).
    let signature_placeholder = b"signature_placeholder_even_longer"; // Replace with actual signature
    let signature_offset = pspf_file.seek(SeekFrom::End(0))?;
    pspf_file.write_all(signature_placeholder)?;
    let signature_size = signature_placeholder.len() as u64;
    writeln!(printer.stdout(), "Appended placeholder signature (size: {} bytes) at offset {}.", signature_size, signature_offset)?;

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
