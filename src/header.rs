//! AES Crypt file-header parsing.
//!
//! This module exposes [`read_version`], a fast, allocation-free reader for the
//! 3- to 5-byte fixed prefix shared by every AES Crypt file format version (v0–v3).
//! It is the cheapest way to triage a file before deciding whether to invoke
//! [`crate::decrypt()`].
//!
//! For the full header layout — including iteration count, public IV, extensions,
//! encrypted session block, and HMAC — see [`crate::decryption::read_file_version`]
//! (the strict version-prefix parser used by [`crate::decrypt()`]) and the
//! per-stage table in [`crate::decryption`].

use crate::error::AescryptError;
use std::io::Read;

/// Reads the AES Crypt format version from the head of `reader` without decrypting.
///
/// `read_version` consumes the minimum number of bytes needed to identify the
/// format version (3 to 5 bytes depending on the version) and returns the
/// version number `0..=3`. It is the canonical entry point for batch tools that
/// need to triage `.aes` files before committing to a full
/// [`crate::decrypt()`] call.
///
/// # Format
///
/// All AES Crypt files start with the ASCII bytes `"AES"`. The bytes that follow
/// disambiguate the version:
///
/// | Bytes after `"AES"` | Detected version | Notes                                   |
/// | ------------------- | :--------------: | --------------------------------------- |
/// | none (EOF)          | `0`              | Classic 3-byte v0 stub.                 |
/// | `\x00` (1 byte)     | `0`              | 4-byte v0 stub.                         |
/// | `\x00 \x00`         | `0`              | 5-byte v0 with zero modulo.             |
/// | `\x00 X` (X any)    | `0`              | 5-byte v0; the modulo byte is ignored.  |
/// | `\x01 \x00`         | `1`              | v1; reserved byte must be `0x00`.       |
/// | `\x02 \x00`         | `2`              | v2; reserved byte must be `0x00`.       |
/// | `\x03 \x00`         | `3`              | v3; reserved byte must be `0x00`.       |
///
/// # Compatibility
///
/// This function only parses the version prefix. It does not validate extension
/// blocks, the iteration count, the public IV, the encrypted session block, or
/// the payload HMAC — all of which live further into the file and are validated
/// by [`crate::decrypt()`].
///
/// # Errors
///
/// - [`AescryptError::Io`] — the reader returned an error before the first three
///   bytes could be read (the trailing 1–2 bytes are read with `read`, not
///   `read_exact`, so EOF after `"AES"` is **not** an error and is reported as
///   v0).
/// - [`AescryptError::Header`] — the magic is not `b"AES"`, the version byte
///   exceeds `3`, or the reserved byte after a v1/v2/v3 version is not `0x00`.
///
/// # Panics
///
/// Never panics on valid or malformed input. The internal `unreachable!` is
/// guarded by a 2-byte buffer for which `Read::read` only returns `0..=2`.
///
/// # Security
///
/// `read_version` is deliberately permissive about the trailing v0 modulo byte
/// (it accepts any value) because legacy AES Crypt files in the wild are not
/// always padded with `0x00`. The reserved-byte check for v1–v3 is **strict**
/// (must be `0x00`) to reject crafted headers that hide payload behind an
/// otherwise-valid magic. No keys, IVs, or plaintext are touched.
///
/// # Thread Safety
///
/// `read_version` borrows the reader; it is `Send + Sync` whenever the reader is.
/// The function holds no shared state and is safe to call concurrently on
/// independent readers.
///
/// # Examples
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
///
/// # See also
///
/// - [`crate::decrypt()`] — full decryption pipeline.
/// - [`crate::decryption::read_file_version`] — internal version reader used by
///   [`crate::decrypt()`]; stricter than `read_version` (always reads 5 bytes).
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
