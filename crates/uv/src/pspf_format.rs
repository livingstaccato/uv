// crates/uv/src/pspf_format.rs

use crc32fast::Hasher;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap; // For ConfigJson env_set

pub const PSPF_VERSION_V0_1: u16 = 0x0001;
pub const INTERNAL_FOOTER_MAGIC: u32 = 0x30505350; // "PSP0" in ASCII
pub const PSP_EOF_MAGIC: &[u8; 8] = b"!PSPF\x00\x00\x00";
pub const PSP_FOOTER_SIZE: usize = 76;
pub const PUBLIC_KEY_DER_SIZE: usize = 550; // Standardized size for the embedded public key (DER format)

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct PspFileFooter {
    pub uv_binary_offset: u64,       // For self-contained UV, this offset is relative to start of signed content.
                                     // If UV is the first part of signed content, this would be 0.
    pub uv_binary_size: u64,         // Size of the (potentially modified) UV binary segment.
    pub metadata_tgz_offset: u64,
    pub metadata_tgz_size: u64,
    pub payload_tgz_offset: u64,
    pub payload_tgz_size: u64,
    pub package_signature_offset: u64,
    pub package_signature_size: u64,
    pub pspf_version: u16,
    pub reserved: u16,
    pub footer_struct_checksum: u32,
    pub internal_footer_magic: u32,
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
            footer_struct_checksum: 0,
            internal_footer_magic: INTERNAL_FOOTER_MAGIC,
        };
        footer.footer_struct_checksum = footer.calculate_checksum();
        footer
    }

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
        hasher.update(&self.internal_footer_magic.to_le_bytes());
        hasher.finalize()
    }

    pub fn to_le_bytes(&self) -> [u8; PSP_FOOTER_SIZE] {
        let mut bytes = [0u8; PSP_FOOTER_SIZE];
        let mut current_offset = 0;
        let mut write_u64 = |offset: &mut usize, val: u64| {
            bytes[*offset..*offset+8].copy_from_slice(&val.to_le_bytes());
            *offset += 8;
        };
        let mut write_u16 = |offset: &mut usize, val: u16| {
            bytes[*offset..*offset+2].copy_from_slice(&val.to_le_bytes());
            *offset += 2;
        };
        let mut write_u32 = |offset: &mut usize, val: u32| {
            bytes[*offset..*offset+4].copy_from_slice(&val.to_le_bytes());
            *offset += 4;
        };

        write_u64(&mut current_offset, self.uv_binary_offset);
        write_u64(&mut current_offset, self.uv_binary_size);
        write_u64(&mut current_offset, self.metadata_tgz_offset);
        write_u64(&mut current_offset, self.metadata_tgz_size);
        write_u64(&mut current_offset, self.payload_tgz_offset);
        write_u64(&mut current_offset, self.payload_tgz_size);
        write_u64(&mut current_offset, self.package_signature_offset);
        write_u64(&mut current_offset, self.package_signature_size);
        write_u16(&mut current_offset, self.pspf_version);
        write_u16(&mut current_offset, self.reserved);
        write_u32(&mut current_offset, self.footer_struct_checksum);
        write_u32(&mut current_offset, self.internal_footer_magic);

        assert_eq!(current_offset, PSP_FOOTER_SIZE, "Footer serialization size mismatch");
        bytes
    }

    pub fn from_le_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PSP_FOOTER_SIZE {
            bail!("Input byte slice is not {} bytes long, got {}", PSP_FOOTER_SIZE, bytes.len());
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

        Ok(Self {
            uv_binary_offset: read_u64(&mut current_offset),
            uv_binary_size: read_u64(&mut current_offset),
            metadata_tgz_offset: read_u64(&mut current_offset),
            metadata_tgz_size: read_u64(&mut current_offset),
            payload_tgz_offset: read_u64(&mut current_offset),
            payload_tgz_size: read_u64(&mut current_offset),
            package_signature_offset: read_u64(&mut current_offset),
            package_signature_size: read_u64(&mut current_offset),
            pspf_version: read_u16(&mut current_offset),
            reserved: read_u16(&mut current_offset),
            footer_struct_checksum: read_u32(&mut current_offset),
            internal_footer_magic: read_u32(&mut current_offset),
        })
    }

    pub fn verify_internal_consistency(&self) -> Result<()> {
        if self.internal_footer_magic != INTERNAL_FOOTER_MAGIC {
            bail!(
                "Invalid internal footer magic. Expected: {:#010X}, Found: {:#010X}",
                INTERNAL_FOOTER_MAGIC, self.internal_footer_magic
            );
        }
        let expected_checksum = self.calculate_checksum();
        if self.footer_struct_checksum != expected_checksum {
            bail!(
                "Footer checksum mismatch. Expected: {:#010X}, Found: {:#010X}",
                expected_checksum, self.footer_struct_checksum
            );
        }
        if self.pspf_version != PSPF_VERSION_V0_1 {
            bail!(
                "Unsupported PSPF version. Expected: {:#06X}, Found: {:#06X}",
                PSPF_VERSION_V0_1, self.pspf_version
            );
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConfigJson {
    pub entry_point: String,
    pub python_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_allowed: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_set: Option<HashMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_footer_serialization_deserialization() {
        let footer = PspFileFooter::new(
            0, 100, 100, 50, 150, 200, 350, 256,
        );
        let bytes = footer.to_le_bytes();
        let deserialized_footer = PspFileFooter::from_le_bytes(&bytes).unwrap();
        assert_eq!(footer, deserialized_footer);
        deserialized_footer.verify_internal_consistency().unwrap();
    }
}
