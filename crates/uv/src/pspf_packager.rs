// crates/uv/src/pspf_packager.rs

use std::fs::{File, OpenOptions};
use std::io::{Write, Read, Seek, SeekFrom, BufWriter};
use std::path::Path;
use std::env;
use anyhow::{Context, Result, bail};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json;
use tar::Builder as TarBuilder;
use sha2::{Sha256, Digest};
use rsa::pss::SigningKey as PssSigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::sha2::Sha256 as RsaSha256;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::RsaPublicKey;
use rsa::pkcs8::EncodePublicKey; // For DER encoding of public key
use rand::rngs::OsRng;

use crate::pspf_format::{PspFileFooter, ConfigJson, PSP_EOF_MAGIC, PSP_FOOTER_SIZE, PUBLIC_KEY_DER_SIZE};

pub struct PspPackageInputs<'a> {
    pub uv_binary_to_package_path: &'a Path,
    pub payload_project_path: &'a Path,
    pub config_json: ConfigJson,
    pub output_path: &'a Path,
    pub private_key_pem_path: &'a Path,
    // TODO: Add Cache, RegistryClientBuilder etc. when create_payload_tgz is implemented
}

fn create_metadata_tgz(config: &ConfigJson) -> Result<Vec<u8>> {
    let config_json_bytes = serde_json::to_vec_pretty(config)
        .context("Failed to serialize config.json for metadata.tgz")?;

    let mut tar_gz_bytes = Vec::new();
    let gz_encoder = GzEncoder::new(&mut tar_gz_bytes, Compression::default());
    let mut tar_builder = TarBuilder::new(gz_encoder);

    let mut header = tar::Header::new_gnu();
    header.set_path("config.json")?;
    header.set_size(config_json_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar_builder.append(&header, config_json_bytes.as_slice())
        .context("Failed to append config.json to metadata.tgz tarball")?;

    tar_builder.into_inner()
        .context("Failed to get inner GzEncoder from TarBuilder for metadata.tgz")?
        .finish()
        .context("Failed to finish Gzip encoding for metadata.tgz")?;

    Ok(tar_gz_bytes)
}

fn create_payload_tgz(
    _project_path: &Path,
    _uv_exe_for_build: &Path,
    // _cache: &uv_cache::Cache,
    // _client_builder: &uv_client::RegistryClientBuilder,
) -> Result<Vec<u8>> {
    eprintln!("WARNING: Using placeholder for create_payload_tgz. Payload will be empty.");
    let mut tar_gz_bytes = Vec::new();
    let gz_encoder = GzEncoder::new(&mut tar_gz_bytes, Compression::default());
    let mut tar_builder = TarBuilder::new(gz_encoder);
    tar_builder.into_inner()?.finish()?;
    Ok(tar_gz_bytes)
}

fn sign_data(
    modified_uv_binary_bytes: &[u8], // This now includes the embedded public key
    metadata_tgz_bytes: &[u8],
    payload_tgz_bytes: &[u8],
    private_key_pem_path: &Path,
) -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    hasher.update(modified_uv_binary_bytes);
    // metadata_tgz_offset is relative to start of file, which is start of modified_uv_binary_bytes
    // So, we hash modified_uv_binary_bytes, then metadata, then payload.
    hasher.update(metadata_tgz_bytes);
    hasher.update(payload_tgz_bytes);
    let digest = hasher.finalize();

    let key_pem = std::fs::read_to_string(private_key_pem_path)
        .with_context(|| format!("Failed to read private key from {:?}", private_key_pem_path))?;

    let private_key = rsa::RsaPrivateKey::from_pkcs1_pem(&key_pem)
        .context("Failed to parse RSA private key from PEM for signing")?;
    let signing_key = PssSigningKey::<RsaSha256>::new(private_key);

    let mut rng = OsRng;
    let signature = signing_key.sign_with_rng(&mut rng, &digest);

    Ok(signature.to_vec())
}

pub fn create_pspf_package(inputs: &PspPackageInputs) -> Result<()> {
    // 1. Load uv binary to be packaged
    let original_uv_binary_bytes = std::fs::read(inputs.uv_binary_to_package_path)
        .with_context(|| format!("Failed to read uv binary to package from {:?}", inputs.uv_binary_to_package_path))?;

    // 2. Load Private Key and Derive Public Key (DER format)
    let private_key_pem = std::fs::read_to_string(inputs.private_key_pem_path)
        .with_context(|| format!("Failed to read private key from {:?}", inputs.private_key_pem_path))?;
    let private_key = rsa::RsaPrivateKey::from_pkcs1_pem(&private_key_pem)
        .context("Failed to parse RSA private key from PEM")?;
    let public_key = RsaPublicKey::from(&private_key);

    let public_key_der_vec = public_key.to_public_key_der()
        .context("Failed to encode public key to DER (SubjectPublicKeyInfo)")?;

    let mut final_public_key_bytes = vec![0u8; PUBLIC_KEY_DER_SIZE];
    if public_key_der_vec.len() > PUBLIC_KEY_DER_SIZE {
        bail!("Encoded public key DER ({} bytes) is larger than allocated PSPF public key size ({} bytes)", public_key_der_vec.len(), PUBLIC_KEY_DER_SIZE);
    }
    final_public_key_bytes[..public_key_der_vec.len()].copy_from_slice(&public_key_der_vec);

    // 3. Create Modified UV Binary Segment (Public Key DER + Original UV Binary)
    let mut modified_uv_binary_bytes = Vec::with_capacity(PUBLIC_KEY_DER_SIZE + original_uv_binary_bytes.len());
    modified_uv_binary_bytes.extend_from_slice(&final_public_key_bytes);
    modified_uv_binary_bytes.extend_from_slice(&original_uv_binary_bytes);

    // 4. Create metadata.tgz
    let metadata_tgz_bytes = create_metadata_tgz(&inputs.config_json)?;

    // 5. Create payload.tgz (using placeholder for now)
    //    The `uv_exe_for_build` would ideally be the original, unmodified uv binary path.
    let payload_tgz_bytes = create_payload_tgz(
        inputs.payload_project_path,
        inputs.uv_binary_to_package_path,
    )?;

    // 6. Sign the package: (Modified UV Binary + Metadata + Payload)
    let signature_bytes = sign_data(
        &modified_uv_binary_bytes,
        &metadata_tgz_bytes,
        &payload_tgz_bytes,
        inputs.private_key_pem_path,
    )?;

    // 7. Assemble the file
    let mut file = BufWriter::new(File::create(inputs.output_path)
        .with_context(|| format!("Failed to create output PSPF file {:?}", inputs.output_path))?);

    let mut current_offset: u64 = 0;

    // Write Modified UV Binary (Public Key + Original UV)
    file.write_all(&modified_uv_binary_bytes)?;
    current_offset += modified_uv_binary_bytes.len() as u64;
    // In the footer, UvBinaryOffset (relative to start of signed content) is 0.
    // UvBinarySize is the size of this modified_uv_binary_bytes.
    let pspf_uv_binary_offset_in_footer = 0;
    let pspf_uv_binary_size_in_footer = modified_uv_binary_bytes.len() as u64;

    let metadata_tgz_offset_in_file = current_offset;
    file.write_all(&metadata_tgz_bytes)?;
    current_offset += metadata_tgz_bytes.len() as u64;

    let payload_tgz_offset_in_file = current_offset;
    file.write_all(&payload_tgz_bytes)?;
    current_offset += payload_tgz_bytes.len() as u64;

    let package_signature_offset_in_file = current_offset;
    file.write_all(&signature_bytes)?;

    let footer = PspFileFooter::new(
        pspf_uv_binary_offset_in_footer, // Offset of UV block relative to start of signed content
        pspf_uv_binary_size_in_footer,   // Size of the (modified) UV binary block
        metadata_tgz_offset_in_file,     // Absolute file offset for metadata
        metadata_tgz_bytes.len() as u64,
        payload_tgz_offset_in_file,      // Absolute file offset for payload
        payload_tgz_bytes.len() as u64,
        package_signature_offset_in_file,// Absolute file offset for signature
        signature_bytes.len() as u64,
    );

    let footer_bytes = footer.to_le_bytes();
    file.write_all(&footer_bytes)?;
    file.write_all(PSP_EOF_MAGIC)?;
    file.flush()?;

    Ok(())
}
