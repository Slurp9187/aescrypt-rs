//! # Header Parsing
//!
//! This module provides functions for parsing AES Crypt file headers.
//! The header contains the magic bytes "AES", version information, and other metadata.

use crate::error::AescryptError;
use std::io::Read;

/// Read and validate the AES Crypt file version from the header.
///
/// This function reads the minimal header information needed to determine the file version
/// without performing a full decryption. It's optimized for fast version detection in batch
/// operations or file management tools.
///
/// # Thread Safety
///
/// This function is **thread-safe** and can be called concurrently from multiple threads.
/// All operations are pure (no shared mutable state), making it ideal for parallel batch processing.
///
/// # Header Format
///
/// - **v0**: `"AES"` (3 bytes) or `"AES\x00"` (4 bytes) or `"AES\x00\x00"` (5 bytes)
/// - **v1-v3**: `"AES"` + version byte (0x01-0x03) + reserved byte (0x00) = 5 bytes
///
/// # Arguments
///
/// * `reader` - A reader that implements `Read`, positioned at the start of the file
///
/// # Returns
///
/// Returns the version number (0-3) if the header is valid, or an error if:
/// - The magic bytes are not "AES"
/// - The version is greater than 3
/// - The reserved byte is invalid (for v1-v3)
/// - An I/O error occurs
///
/// # Errors
///
/// - [`AescryptError::Io`] - If an I/O error occurs while reading
/// - [`AescryptError::Header`] - If the header is invalid or malformed
///
/// # Example
///
/// ```
/// use aescrypt_rs::read_version;
/// use std::io::Cursor;
///
/// // v3 file header
/// let header = b"AES\x03\x00";
/// let version = read_version(Cursor::new(header))?;
/// assert_eq!(version, 3);
///
/// // v0 file header (3-byte)
/// let header = b"AES";
/// let version = read_version(Cursor::new(header))?;
/// assert_eq!(version, 0);
/// # Ok::<(), aescrypt_rs::AescryptError>(())
/// ```
pub fn read_version<R: Read>(mut reader: R) -> Result<u8, AescryptError> {
    let mut magic = [0u8; 3];
    reader.read_exact(&mut magic).map_err(AescryptError::Io)?;

    if magic != [b'A', b'E', b'S'] {
        return Err(AescryptError::Header(
            "Not an AES Crypt file: invalid magic".into(),
        ));
    }

    let mut buf = [0u8; 2];
    match reader.read(&mut buf) {
        Ok(2) => {
            let version = buf[0];
            let reserved = buf[1];

            if version > 3 {
                return Err(AescryptError::Header(format!(
                    "Unsupported version: {version}"
                )));
            }
            if version >= 1 && reserved != 0x00 {
                return Err(AescryptError::Header(
                    "Invalid header: reserved byte != 0x00".into(),
                ));
            }
            Ok(version)
        }
        Ok(1) => {
            // Only one byte after "AES" → legacy v0 4-byte header
            if buf[0] == 0 {
                Ok(0)
            } else {
                Err(AescryptError::Header(
                    "Invalid v0 header: version byte not zero".into(),
                ))
            }
        }
        Ok(0) | Err(_) => {
            // EOF after "AES" → classic 3-byte v0 header
            Ok(0)
        }
        _ => unreachable!("read() only returns 0–2 for a 2-byte buffer"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn real_world_vectors() {
        let cases = &[
            ("41455300", 0u8),   // v0: 4-byte
            ("4145530000", 0u8), // v0: 5-byte clean
            ("41455300ff", 0u8), // v0: 5-byte garbage
            ("4145530100", 1u8),
            ("4145530200", 2u8),
            ("4145530300", 3u8),
        ];

        for &(hex, expected) in cases {
            let bytes = hex::decode(hex).unwrap();
            assert_eq!(read_version(Cursor::new(&bytes)).unwrap(), expected);
        }
    }

    #[test]
    fn short_file_only_aes() {
        assert_eq!(read_version(Cursor::new(b"AES")).unwrap(), 0);
    }

    #[test]
    fn invalid_magic() {
        let err = read_version(Cursor::new(b"XYZ\x03\x00")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Header error: Not an AES Crypt file: invalid magic"
        );
    }
}
