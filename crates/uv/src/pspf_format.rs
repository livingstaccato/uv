//! Defines the PSPF file format structures, including the footer and magic string.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write, Result as IoResult};

/// The 8-byte magic string that identifies a PSPF file at its very end.
/// ASCII: `!PSPF\x00\x00\x00`
pub const PSPF_EOF_MAGIC_STRING: &[u8; 8] = b"!PSPF\x00\x00\x00";

/// Version identifier for PSPF v0.1.
pub const PSPF_VERSION_V0_1: u16 = 0x0001;

/// The current version of the PSPF format being produced or consumed.
pub const CURRENT_PSPF_VERSION: u16 = PSPF_VERSION_V0_1;

/// Predefined fixed offset within the `uv` binary portion where the public key is embedded.
/// This value needs to be carefully chosen. For example, it could be a value like 1MB (1024 * 1024 bytes)
// TODO: Determine a robust and safe value for this offset. It must be fixed.
// For now, placeholder. This might also need to be coordinated with how `uv` is built
// or if we reserve space in the `uv` binary itself.
// A simpler approach for a PoC might be to append it and store its offset in the footer too,
// but the spec says "fixed offset".
pub const PUBLIC_KEY_EMBED_OFFSET: u64 = 1024 * 1024; // Example: 1MB
pub const PUBLIC_KEY_MAX_SIZE: usize = 2048; // RSA Public key size (e.g. 2048 bits / 8 = 256 bytes for DER, plus padding/structure)

/// `PspFileFooterV1` defines the structure of the footer appended to a PSPF file,
/// just before the `PSPF_EOF_MAGIC_STRING`.
///
/// The total size of this struct is 64 bytes.
/// All integer fields are stored in little-endian format.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PspFileFooterV1 {
    /// Structure format version. For v0.1, this is `PSPF_VERSION_V0_1`.
    pub version: u16,

    /// Size of the `uv` binary content from the beginning of the file.
    /// `metadata.tgz` starts immediately after this section.
    pub uv_binary_size: u64,

    /// Size of `metadata.tgz`.
    pub metadata_size: u64,
    /// Offset of `metadata.tgz` from the beginning of the file.
    /// (Should be equal to `uv_binary_size`).
    pub metadata_offset: u64,

    /// Size of `payload.tgz`.
    pub payload_size: u64,
    /// Offset of `payload.tgz` from the beginning of the file.
    /// (Should be `metadata_offset + metadata_size`).
    pub payload_offset: u64,

    /// Size of the signature data.
    pub signature_size: u64,
    /// Offset of the signature data from the beginning of the file.
    /// (Should be `payload_offset + payload_size`).
    pub signature_offset: u64,

    /// CRC32 checksum of the `PspFileFooterV1` structure itself.
    /// Calculated with this field initially set to 0.
    pub footer_checksum: u32,

    /// Reserved for future use, must be zero for v0.1. Pads struct to 64 bytes.
    pub reserved: [u8; 2],
}

// Statically assert the size of the footer structure.
// This requires an external crate like `static_assertions`.
// const _: () = assert!(std::mem::size_of::<PspFileFooterV1>() == 64, "PspFileFooterV1 must be 64 bytes");
// For now, we use a runtime check or a constant.
impl PspFileFooterV1 {
    /// The fixed size of the `PspFileFooterV1` structure in bytes.
    pub const SIZE: usize = 64;

    /// Creates a new `PspFileFooterV1` with the given parameters, calculating the checksum.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        uv_binary_size: u64,
        metadata_size: u64,
        metadata_offset: u64,
        payload_size: u64,
        payload_offset: u64,
        signature_size: u64,
        signature_offset: u64,
    ) -> Self {
        let mut footer = Self {
            version: CURRENT_PSPF_VERSION,
            uv_binary_size,
            metadata_size,
            metadata_offset,
            payload_size,
            payload_offset,
            signature_size,
            signature_offset,
            footer_checksum: 0, // Placeholder for calculation
            reserved: [0; 2],
        };
        footer.footer_checksum = footer.calculate_checksum();
        footer
    }

    /// Calculates the CRC32 checksum of the footer.
    /// The `footer_checksum` field is treated as 0 during this calculation.
    fn calculate_checksum(&self) -> u32 {
        let mut temp_footer = *self;
        temp_footer.footer_checksum = 0; // Ensure checksum field is zero for calculation

        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                &temp_footer as *const _ as *const u8,
                Self::SIZE,
            )
        };

        // The checksum calculation should exclude the checksum field itself from the input buffer
        // when that field is part of the slice. A common way is to slice up to checksum field,
        // then slice after it, or serialize all fields except checksum.
        // For simplicity here, we use a direct slice and rely on `footer_checksum` being zeroed.
        // A more robust way:
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&temp_footer.version.to_le_bytes());
        hasher.update(&temp_footer.uv_binary_size.to_le_bytes());
        hasher.update(&temp_footer.metadata_size.to_le_bytes());
        hasher.update(&temp_footer.metadata_offset.to_le_bytes());
        hasher.update(&temp_footer.payload_size.to_le_bytes());
        hasher.update(&temp_footer.payload_offset.to_le_bytes());
        hasher.update(&temp_footer.signature_size.to_le_bytes());
        hasher.update(&temp_footer.signature_offset.to_le_bytes());
        // Skip actual footer_checksum field, effectively treating it as zero
        hasher.update(&temp_footer.reserved); // Add reserved bytes

        hasher.finalize()
    }

    /// Verifies the integrity of the footer using its checksum.
    pub fn verify_checksum(&self) -> bool {
        if self.footer_checksum == 0 {
            // A checksum of 0 might be valid, but often indicates an uninitialized/corrupt footer.
            // Depending on the checksum algorithm, 0 could be a possible output for valid data.
            // For CRC32, it's possible. If it's a concern, one might ensure the checksum is non-zero
            // for an all-zero input (e.g. by XORing with a final constant).
            // Here, we assume 0 is a possible valid checksum.
        }
        self.calculate_checksum() == self.footer_checksum
    }

    /// Writes the footer to a writer in little-endian byte order.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> IoResult<()> {
        assert_eq!(std::mem::size_of::<Self>(), Self::SIZE, "PspFileFooterV1 size invariant violated");

        writer.write_u16::<LittleEndian>(self.version)?;
        writer.write_u64::<LittleEndian>(self.uv_binary_size)?;
        writer.write_u64::<LittleEndian>(self.metadata_size)?;
        writer.write_u64::<LittleEndian>(self.metadata_offset)?;
        writer.write_u64::<LittleEndian>(self.payload_size)?;
        writer.write_u64::<LittleEndian>(self.payload_offset)?;
        writer.write_u64::<LittleEndian>(self.signature_size)?;
        writer.write_u64::<LittleEndian>(self.signature_offset)?;
        writer.write_u32::<LittleEndian>(self.footer_checksum)?;
        writer.write_all(&self.reserved)?;
        Ok(())
    }

    /// Reads a footer from a reader in little-endian byte order.
    pub fn read_from<R: Read>(reader: &mut R) -> IoResult<Self> {
        assert_eq!(std::mem::size_of::<Self>(), Self::SIZE, "PspFileFooterV1 size invariant violated");

        let version = reader.read_u16::<LittleEndian>()?;
        let uv_binary_size = reader.read_u64::<LittleEndian>()?;
        let metadata_size = reader.read_u64::<LittleEndian>()?;
        let metadata_offset = reader.read_u64::<LittleEndian>()?;
        let payload_size = reader.read_u64::<LittleEndian>()?;
        let payload_offset = reader.read_u64::<LittleEndian>()?;
        let signature_size = reader.read_u64::<LittleEndian>()?;
        let signature_offset = reader.read_u64::<LittleEndian>()?;
        let footer_checksum = reader.read_u32::<LittleEndian>()?;
        let mut reserved = [0u8; 2];
        reader.read_exact(&mut reserved)?;

        Ok(Self {
            version,
            uv_binary_size,
            metadata_size,
            metadata_offset,
            payload_size,
            payload_offset,
            signature_size,
            signature_offset,
            footer_checksum,
            reserved,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_pspf_footer_v1_size() {
        assert_eq!(std::mem::size_of::<PspFileFooterV1>(), PspFileFooterV1::SIZE);
        assert_eq!(PspFileFooterV1::SIZE, 64);
    }

    #[test]
    fn test_pspf_footer_v1_checksum_and_serialization() {
        let footer = PspFileFooterV1::new(
            1000, // uv_binary_size
            200,  // metadata_size
            1000, // metadata_offset
            3000, // payload_size
            1200, // payload_offset
            256,  // signature_size
            4200, // signature_offset
        );

        assert!(footer.verify_checksum(), "Footer checksum verification failed");

        let mut buffer = Vec::new();
        footer.write_to(&mut buffer).unwrap();
        assert_eq!(buffer.len(), PspFileFooterV1::SIZE);

        let mut cursor = Cursor::new(buffer);
        let deserialized_footer = PspFileFooterV1::read_from(&mut cursor).unwrap();

        assert_eq!(footer, deserialized_footer, "Serialized and deserialized footers do not match");
        assert!(deserialized_footer.verify_checksum(), "Deserialized footer checksum verification failed");
    }

    #[test]
    fn test_pspf_footer_v1_checksum_tampered() {
        let mut footer = PspFileFooterV1::new(
            1000, 200, 1000, 3000, 1200, 256, 4200
        );
        assert!(footer.verify_checksum());

        // Tamper with a field AFTER checksum calculation (as if data was corrupted)
        footer.metadata_size += 1;
        assert!(!footer.verify_checksum(), "Tampered footer checksum should fail");
    }

    #[test]
    fn test_eof_magic_string() {
        assert_eq!(PSPF_EOF_MAGIC_STRING.len(), 8);
        assert_eq!(PSPF_EOF_MAGIC_STRING, b"!PSPF\x00\x00\x00");
    }
}
