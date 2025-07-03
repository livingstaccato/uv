// crates/uv/src/pspf.rs

use std::fs::{File, OpenOptions};
use std::io::{Write, Read, Seek, SeekFrom, BufWriter};
use std::path::Path;
use anyhow::{Context, Result, bail};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use serde_json;
use tar::Builder as TarBuilder;
use sha2::{Sha256, Digest};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::sha2::Sha256 as RsaSha256; // Alias to avoid conflict with sha2::Sha256
use rand::rngs::OsRng;


use crc32fast::Hasher;

// Assuming uv_core or similar will provide these. For now, placeholders.
// use uv_client::RegistryClientBuilder;
// use uv_resolver::{ResolutionOptions, Resolver};
// use uv_installer::Downloader;
// use uv_interpreter::PythonEnvironment;

pub const PSPF_VERSION_V0_1: u16 = 0x0001;
pub const INTERNAL_FOOTER_MAGIC: u32 = 0x30505350; // "PSP0" in ASCII
pub const PSP_EOF_MAGIC: &[u8; 8] = b"!PSPF\x00\x00\x00";
pub const PSP_FOOTER_SIZE: usize = 76;

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)] // Ensure C-like layout, important for predictable size and field order
pub struct PspFileFooter {
    pub uv_binary_offset: u64,
    pub uv_binary_size: u64,
    pub metadata_tgz_offset: u64,
    pub metadata_tgz_size: u64,
    pub payload_tgz_offset: u64,
    pub payload_tgz_size: u64,
    pub package_signature_offset: u64,
    pub package_signature_size: u64,
    pub pspf_version: u16,
    pub reserved: u16,
    pub footer_struct_checksum: u32, // CRC32 of all other fields in this footer
    pub internal_footer_magic: u32,   // Should be "PSP0"
}

impl PspFileFooter {
    pub fn new(
        uv_binary_offset: u64,
        uv_binary_size: u64,
        metadata_tgz_offset: u64,
        metadata_tgz_size: u64,
        payload_tgz_offset: u64,
        payload_tgz_size: u64,
        package_signature_offset: u64,
        package_signature_size: u64,
    ) -> Self {
        let mut footer = Self {
            uv_binary_offset,
            uv_binary_size,
            metadata_tgz_offset,
            metadata_tgz_size,
            payload_tgz_offset,
            payload_tgz_size,
            package_signature_offset,
            package_signature_size,
            pspf_version: PSPF_VERSION_V0_1,
            reserved: 0,
            footer_struct_checksum: 0, // Will be calculated later
            internal_footer_magic: INTERNAL_FOOTER_MAGIC,
        };
        footer.footer_struct_checksum = footer.calculate_checksum();
        footer
    }

    /// Calculates the CRC32 IEEE checksum of the footer fields,
    /// excluding the `footer_struct_checksum` field itself.
    pub fn calculate_checksum(&self) -> u32 {
        let mut hasher = Hasher::new();
        hasher.update(&self.uv_binary_offset.to_le_bytes());
        hasher.update(&self.uv_binary_size.to_le_bytes());
        hasher.update(&self.metadata_tgz_offset.to_le_bytes());
        hasher.update(&self.metadata_tgz_size.to_le_bytes());
        hasher.update(&self.payload_tgz_offset.to_le_bytes());
        hasher.update(&self.payload_tgz_size.to_le_bytes());
        hasher.update(&self.package_signature_offset.to_le_bytes());
        hasher.update(&self.package_signature_size.to_le_bytes());
        hasher.update(&self.pspf_version.to_le_bytes());
        hasher.update(&self.reserved.to_le_bytes());
        // The checksum field itself is not included in the checksum calculation.
        hasher.update(&self.internal_footer_magic.to_le_bytes());
        hasher.finalize()
    }

    /// Serializes the footer into a 76-byte array in little-endian format.
    pub fn to_le_bytes(&self) -> [u8; PSP_FOOTER_SIZE] {
        let mut bytes = [0u8; PSP_FOOTER_SIZE];
        let mut offset = 0;

        bytes[offset..offset+8].copy_from_slice(&self.uv_binary_offset.to_le_bytes());
        offset += 8;
        bytes[offset..offset+8].copy_from_slice(&self.uv_binary_size.to_le_bytes());
        offset += 8;
        bytes[offset..offset+8].copy_from_slice(&self.metadata_tgz_offset.to_le_bytes());
        offset += 8;
        bytes[offset..offset+8].copy_from_slice(&self.metadata_tgz_size.to_le_bytes());
        offset += 8;
        bytes[offset..offset+8].copy_from_slice(&self.payload_tgz_offset.to_le_bytes());
        offset += 8;
        bytes[offset..offset+8].copy_from_slice(&self.payload_tgz_size.to_le_bytes());
        offset += 8;
        bytes[offset..offset+8].copy_from_slice(&self.package_signature_offset.to_le_bytes());
        offset += 8;
        bytes[offset..offset+8].copy_from_slice(&self.package_signature_size.to_le_bytes());
        offset += 8;
        bytes[offset..offset+2].copy_from_slice(&self.pspf_version.to_le_bytes());
        offset += 2;
        bytes[offset..offset+2].copy_from_slice(&self.reserved.to_le_bytes());
        offset += 2;
        bytes[offset..offset+4].copy_from_slice(&self.footer_struct_checksum.to_le_bytes());
        offset += 4;
        bytes[offset..offset+4].copy_from_slice(&self.internal_footer_magic.to_le_bytes());
        // offset += 4; // No need, this is the last field

        assert_eq!(offset + 4, PSP_FOOTER_SIZE, "Footer serialization size mismatch");
        bytes
    }

    /// Deserializes the footer from a 76-byte array in little-endian format.
    /// Returns an error if the input slice is not 76 bytes.
    pub fn from_le_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != PSP_FOOTER_SIZE {
            return Err("Input byte slice is not 76 bytes long");
        }

        let mut current_offset = 0;
        let read_u64 = |offset: &mut usize| -> u64 {
            let val = u64::from_le_bytes(bytes[*offset..*offset+8].try_into().unwrap());
            *offset += 8;
            val
        };
        let read_u16 = |offset: &mut usize| -> u16 {
            let val = u16::from_le_bytes(bytes[*offset..*offset+2].try_into().unwrap());
            *offset += 2;
            val
        };
        let read_u32 = |offset: &mut usize| -> u32 {
            let val = u32::from_le_bytes(bytes[*offset..*offset+4].try_into().unwrap());
            *offset += 4;
            val
        };

        let uv_binary_offset = read_u64(&mut current_offset);
        let uv_binary_size = read_u64(&mut current_offset);
        let metadata_tgz_offset = read_u64(&mut current_offset);
        let metadata_tgz_size = read_u64(&mut current_offset);
        let payload_tgz_offset = read_u64(&mut current_offset);
        let payload_tgz_size = read_u64(&mut current_offset);
        let package_signature_offset = read_u64(&mut current_offset);
        let package_signature_size = read_u64(&mut current_offset);
        let pspf_version = read_u16(&mut current_offset);
        let reserved = read_u16(&mut current_offset);
        let footer_struct_checksum = read_u32(&mut current_offset);
        let internal_footer_magic = read_u32(&mut current_offset);

        Ok(Self {
            uv_binary_offset,
            uv_binary_size,
            metadata_tgz_offset,
            metadata_tgz_size,
            payload_tgz_offset,
            payload_tgz_size,
            package_signature_offset,
            package_signature_size,
            pspf_version,
            reserved,
            footer_struct_checksum,
            internal_footer_magic,
        })
    }

    /// Verifies the internal consistency of the footer.
    /// Checks magic number and checksum.
    pub fn verify_internal_consistency(&self) -> Result<(), String> {
        if self.internal_footer_magic != INTERNAL_FOOTER_MAGIC {
            return Err(format!(
                "Invalid internal footer magic. Expected: {:#010X}, Found: {:#010X}",
                INTERNAL_FOOTER_MAGIC, self.internal_footer_magic
            ));
        }
        let expected_checksum = self.calculate_checksum();
        if self.footer_struct_checksum != expected_checksum {
            return Err(format!(
                "Footer checksum mismatch. Expected: {:#010X}, Found: {:#010X}",
                expected_checksum, self.footer_struct_checksum
            ));
        }
        Ok(())
    }
}

/// Represents the structure of `config.json` within `metadata.tgz`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfigJson {
    pub entry_point: String,
    pub python_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_mode: Option<String>, // "restricted" or "passthrough"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_allowed: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_set: Option<std::collections::HashMap<String, String>>,
}

/// Inputs required for creating a PSPF package.
pub struct PspPackageInputs<'a> {
    pub go_launcher_path: &'a Path,
    pub uv_binary_path: &'a Path,
    pub payload_project_path: &'a Path, // Path to the Python project to be packaged
    pub config_json: ConfigJson,
    pub output_path: &'a Path,
    pub private_key_pem_path: &'a Path,
    // Potentially add:
    // pub cache: &'a Cache,
    // pub client: &'a RegistryClient,
    // pub python_env: &'a PythonEnvironment,
}

/// Creates the `metadata.tgz` archive.
fn create_metadata_tgz(config: &ConfigJson) -> Result<Vec<u8>> {
    let config_json_bytes = serde_json::to_vec_pretty(config)
        .context("Failed to serialize config.json")?;

    let mut tar_gz_bytes = Vec::new();
    let gz_encoder = GzEncoder::new(&mut tar_gz_bytes, Compression::default());
    let mut tar_builder = TarBuilder::new(gz_encoder);

    let mut header = tar::Header::new_gnu();
    header.set_path("config.json")?;
    header.set_size(config_json_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum(); // Calculate checksum for the header
    tar_builder.append(&header, config_json_bytes.as_slice())?;

    tar_builder.into_inner()?.finish()?; // Finish Gzip encoding

    Ok(tar_gz_bytes)
}

/// Creates the `payload.tgz` archive containing Python wheels.
/// This is a placeholder and will need to integrate with `uv`'s building/fetching logic.
fn create_payload_tgz(
    _project_path: &Path,
    // _cache: &Cache,
    // _client: &RegistryClient,
    // _venv: &PythonEnvironment,
) -> Result<Vec<u8>> {
    // TODO:
    // 1. Use uv's resolver to get all dependencies for project_path.
    // 2. For each dependency (and the project itself if it's a local package):
    //    - Check if a pre-built wheel is available in cache or on PyPI. Download/use it.
    //    - If not, and it's an sdist, build it into a wheel using uv_build.
    // 3. Collect all wheel files (.whl).
    // 4. Create a tar.gz archive containing all these .whl files.

    // Placeholder: create an empty tar.gz for now
    let mut tar_gz_bytes = Vec::new();
    let gz_encoder = GzEncoder::new(&mut tar_gz_bytes, Compression::default());
    let mut tar_builder = TarBuilder::new(gz_encoder);

    // Example: Adding a dummy file to the payload
    // let dummy_wheel_content = b"This is a dummy wheel file.";
    // let mut header = tar::Header::new_gnu();
    // header.set_path("dummy_package-1.0.0-py3-none-any.whl")?;
    // header.set_size(dummy_wheel_content.len() as u64);
    // header.set_mode(0o644);
    // header.set_cksum();
    // tar_builder.append(&header, dummy_wheel_content.as_slice())?;

    tar_builder.into_inner()?.finish()?;
    Ok(tar_gz_bytes)
}

/// Signs the combined data of launcher, uv_binary, metadata, and payload.
fn sign_data(
    launcher_bytes: &[u8],
    uv_binary_bytes: &[u8],
    metadata_tgz_bytes: &[u8],
    payload_tgz_bytes: &[u8],
    private_key_pem_path: &Path,
) -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    hasher.update(launcher_bytes);
    hasher.update(uv_binary_bytes);
    hasher.update(metadata_tgz_bytes);
    hasher.update(payload_tgz_bytes);
    let digest = hasher.finalize();

    let key_pem = std::fs::read_to_string(private_key_pem_path)
        .with_context(|| format!("Failed to read private key from {:?}", private_key_pem_path))?;

    let signing_key = SigningKey::<RsaSha256>::new(
        rsa::RsaPrivateKey::from_pkcs1_pem(&key_pem)
            .context("Failed to parse RSA private key from PEM")?
    );

    // let mut rng = OsRng;
    // For RSA PSS, the rng is typically used in the padding scheme.
    // The `rsa` crate's PSS signing handles RNG internally if needed or uses deterministic variants.
    // For PKCS#1 v1.5, RNG is not directly used in the signing operation itself after hashing.
    // The SigningKey::sign method will produce a PKCS#1 v1.5 signature.
    // If PSS was desired, one would use `RsaPssSigningKey`.
    // The spec says "RSA-4096 with PSS". Let's adjust if `SigningKey` isn't PSS.
    // `SigningKey<Sha256>` with `pkcs1v15` feature implies PKCS#1 v1.5.
    // To use PSS, we need `RsaPssSigningKey` from `rsa::pss`.
    // However, the current `rsa` crate version (0.9.x) `SigningKey` from `pkcs1v15` IS for PKCS#1 v1.5.
    // For PSS, we need `rsa::pss::SigningKey`. Let's assume PKCS#1 v1.5 for now based on the current `use`
    // and adjust if explicit PSS types are required and available.
    // The spec *explicitly* says PSS. So we must use PSS.
    // `rsa::pkcs1v15::SigningKey` is NOT PSS. We need `rsa::pss::SigningKey`.

    // Re-checking the `rsa` crate features and types for PSS:
    // Yes, `rsa::pss::SigningKey` is the correct type.
    // It requires `features = ["pss"]` on the `rsa` crate.
    // Let's assume the Cargo.toml for `uv` will have this feature enabled for `rsa`.

    // Corrected for PSS:
    let pss_signing_key = rsa::pss::SigningKey::<RsaSha256>::new(
        rsa::RsaPrivateKey::from_pkcs1_pem(&key_pem)
            .context("Failed to parse RSA private key from PEM for PSS")?
    );

    let mut rng = OsRng;
    let signature = pss_signing_key.sign_with_rng(&mut rng, &digest);

    Ok(signature.to_vec())
}


/// Main function to create a PSPF package.
pub fn create_pspf_package(inputs: &PspPackageInputs) -> Result<()> {
    // 1. Read Go Launcher
    let go_launcher_bytes = std::fs::read(inputs.go_launcher_path)
        .with_context(|| format!("Failed to read Go launcher from {:?}", inputs.go_launcher_path))?;

    // 2. Read UV Binary
    let uv_binary_bytes = std::fs::read(inputs.uv_binary_path)
        .with_context(|| format!("Failed to read UV binary from {:?}", inputs.uv_binary_path))?;

    // 3. Create metadata.tgz
    let metadata_tgz_bytes = create_metadata_tgz(&inputs.config_json)
        .context("Failed to create metadata.tgz")?;

    // 4. Create payload.tgz
    //    This needs actual implementation using uv's capabilities.
    let payload_tgz_bytes = create_payload_tgz(
        inputs.payload_project_path,
        // inputs.cache,
        // inputs.client,
        // inputs.venv,
    ).context("Failed to create payload.tgz")?;

    // 5. Sign the package (Launcher + UV + Metadata + Payload)
    let signature_bytes = sign_data(
        &go_launcher_bytes,
        &uv_binary_bytes,
        &metadata_tgz_bytes,
        &payload_tgz_bytes,
        inputs.private_key_pem_path,
    ).context("Failed to sign package data")?;

    // 6. Assemble the file
    let mut file = BufWriter::new(File::create(inputs.output_path)
        .with_context(|| format!("Failed to create output file {:?}", inputs.output_path))?);

    let mut current_offset: u64 = 0;

    file.write_all(&go_launcher_bytes)?;
    current_offset += go_launcher_bytes.len() as u64;
    let uv_binary_offset = current_offset;

    file.write_all(&uv_binary_bytes)?;
    current_offset += uv_binary_bytes.len() as u64;
    let metadata_tgz_offset = current_offset;

    file.write_all(&metadata_tgz_bytes)?;
    current_offset += metadata_tgz_bytes.len() as u64;
    let payload_tgz_offset = current_offset;

    file.write_all(&payload_tgz_bytes)?;
    current_offset += payload_tgz_bytes.len() as u64;
    let package_signature_offset = current_offset;

    file.write_all(&signature_bytes)?;
    // current_offset += signature_bytes.len() as u64; // Footer offset is this value

    // 7. Construct and write footer
    let footer = PspFileFooter::new(
        uv_binary_offset,
        uv_binary_bytes.len() as u64,
        metadata_tgz_offset,
        metadata_tgz_bytes.len() as u64,
        payload_tgz_offset,
        payload_tgz_bytes.len() as u64,
        package_signature_offset,
        signature_bytes.len() as u64,
    );

    let footer_bytes = footer.to_le_bytes();
    file.write_all(&footer_bytes)?;

    // 8. Write EOF Magic String
    file.write_all(PSP_EOF_MAGIC)?;

    file.flush().context("Failed to flush PSPF file output")?;

    println!("PSPF package created successfully at: {:?}", inputs.output_path);
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Cursor;

    // Helper to create a dummy file with content
    fn create_dummy_file(content: &[u8]) -> Result<NamedTempFile> {
        let temp_file = NamedTempFile::new()?;
        let mut file = File::create(temp_file.path())?;
        file.write_all(content)?;
        Ok(temp_file)
    }

    // Helper to create a dummy PEM private key (RSA 2048 for speed in tests, spec is 4096)
    // In a real scenario, use a proper 4096-bit key.
    fn create_dummy_private_key_pem() -> Result<NamedTempFile> {
        let mut rng = OsRng;
        let bits = 2048; // Use 2048 for tests for speed. Spec requires 4096.
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, bits)
            .expect("failed to generate a key");
        let key_pem = priv_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("failed to encode key to PEM");

        let temp_file = NamedTempFile::new()?;
        let mut file = File::create(temp_file.path())?;
        file.write_all(key_pem.as_bytes())?;
        Ok(temp_file)
    }


    #[test]
    fn test_footer_serialization_deserialization() {
        let footer = PspFileFooter::new(
            1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000,
        );

        let bytes = footer.to_le_bytes();
        assert_eq!(bytes.len(), PSP_FOOTER_SIZE);

        let deserialized_footer = PspFileFooter::from_le_bytes(&bytes).unwrap();
        assert_eq!(footer, deserialized_footer);
        assert_eq!(deserialized_footer.pspf_version, PSPF_VERSION_V0_1);
        assert_eq!(deserialized_footer.internal_footer_magic, INTERNAL_FOOTER_MAGIC);

        // Verify checksum calculation consistency
        let checksum_on_new = footer.footer_struct_checksum;
        let recalculated_checksum = deserialized_footer.calculate_checksum();
        assert_eq!(checksum_on_new, recalculated_checksum);

        // Verify internal consistency check
        assert!(deserialized_footer.verify_internal_consistency().is_ok());
    }

    #[test]
    fn test_footer_checksum_logic() {
        let mut footer1 = PspFileFooter::new(1,2,3,4,5,6,7,8);
        let checksum1 = footer1.footer_struct_checksum;

        // Change a field that IS part of the checksum
        footer1.uv_binary_size = 200;
        // Recalculate checksum (as `new` would do)
        footer1.footer_struct_checksum = footer1.calculate_checksum();
        let checksum2 = footer1.footer_struct_checksum;

        assert_ne!(checksum1, checksum2, "Checksum should change when a relevant field changes.");

        // Test that calculate_checksum gives the same result as what's stored
        // if no fields were changed after `new()` or manual recalculation.
        let footer = PspFileFooter::new(10,20,30,40,50,60,70,80);
        assert_eq!(footer.footer_struct_checksum, footer.calculate_checksum());
    }

    #[test]
    fn test_footer_internal_consistency_failure_magic() {
        let mut footer = PspFileFooter::new(1,2,3,4,5,6,7,8);
        footer.internal_footer_magic = 0xDEADBEEF; // Corrupt magic
        // Checksum is now also wrong, but magic is checked first by verify_internal_consistency
        let verification_result = footer.verify_internal_consistency();
        assert!(verification_result.is_err());
        assert!(verification_result.unwrap_err().contains("Invalid internal footer magic"));
    }

    #[test]
    fn test_footer_internal_consistency_failure_checksum() {
        let mut footer = PspFileFooter::new(1,2,3,4,5,6,7,8);
        footer.footer_struct_checksum = 0xDEADBEEF; // Corrupt checksum directly
        let verification_result = footer.verify_internal_consistency();
        assert!(verification_result.is_err());
        assert!(verification_result.unwrap_err().contains("Footer checksum mismatch"));
    }

     #[test]
    fn test_from_le_bytes_invalid_size() {
        let too_short = [0u8; PSP_FOOTER_SIZE - 1];
        let result_short = PspFileFooter::from_le_bytes(&too_short);
        assert!(result_short.is_err());
        assert_eq!(result_short.unwrap_err(), "Input byte slice is not 76 bytes long");

        let too_long = [0u8; PSP_FOOTER_SIZE + 1];
        let result_long = PspFileFooter::from_le_bytes(&too_long);
        assert!(result_long.is_err());
        assert_eq!(result_long.unwrap_err(), "Input byte slice is not 76 bytes long");
    }
}
