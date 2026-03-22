//! src/decryption/read.rs
//! Safe, zero-copy, stack-first Aescrypt header parsing
//! Fully optimized for 2025 Rust + secure-gate v0.5.10+ ecosystem

use crate::aliases::SpanBuffer;
use crate::error::AescryptError;
use secure_gate::{RevealSecret, RevealSecretMut};
use std::io::Read;

/// Read exactly `N` bytes into a secure, auto-zeroizing stack buffer.
///
/// This is the **primary stream reader** for the constant-memory decryption path.
/// Returns `SpanBuffer<N>` (alias to `secure_gate::Fixed<[u8; N]>`).
/// Panics on EOF — expected for malformed AES Crypt files.
#[inline(always)]
pub fn read_exact_span<R, const N: usize>(reader: &mut R) -> Result<SpanBuffer<N>, AescryptError>
where
    R: Read,
{
    let mut buf = SpanBuffer::new([0u8; N]);
    buf.with_secret_mut(|b| reader.read_exact(b))
        .map_err(AescryptError::Io)?;
    Ok(buf)
}

/// Validate file magic `"AES"` + version byte (0–3 supported), and read the 5th byte.
///
/// Returns `(version, modulo_or_reserved)` where:
/// - `version` is the file format version (0–3)
/// - `modulo_or_reserved` is the 5th header byte: the modulo byte for v0 (any value), or the
///   reserved byte for v1–v3 (must be `0x00`; an error is returned if it is not)
///
/// This consolidates what was previously `read_file_version` + `read_reserved_modulo_byte`
/// so that both the version and the reserved-byte validation happen in one place, matching
/// the behaviour of the public [`crate::read_version`] API.
#[inline(always)]
pub fn read_file_version<R>(reader: &mut R) -> Result<(u8, u8), AescryptError>
where
    R: Read,
{
    let header = read_exact_span::<_, 4>(reader)?;
    let is_aes = header.with_secret(|h| &h[..3] == b"AES");
    if !is_aes {
        return Err(AescryptError::Header(
            "invalid magic header (expected 'AES')".into(),
        ));
    }
    let version = header.with_secret(|h| h[3]);
    if version > 3 {
        return Err(AescryptError::UnsupportedVersion(version));
    }
    let modulo_or_reserved = read_exact_span::<_, 1>(reader)?.with_secret(|b| b[0]);
    if version >= 1 && modulo_or_reserved != 0x00 {
        return Err(AescryptError::Header(
            "invalid header: reserved byte must be 0x00 for v1–v3".into(),
        ));
    }
    Ok((version, modulo_or_reserved))
}

/// Maximum number of extensions accepted before returning an error.
///
/// A crafted file with an unbounded number of small extensions could consume
/// proportional CPU/IO before the HMAC check. Limiting to 256 extensions is
/// well above any legitimate use while capping the pre-auth work.
const MAX_EXTENSIONS: usize = 256;

/// Consume all v2+ extensions (zero-copy skip)
#[inline(always)]
pub fn consume_all_extensions<R>(reader: &mut R, version: u8) -> Result<(), AescryptError>
where
    R: Read,
{
    if version < 2 {
        return Ok(());
    }

    let mut count = 0usize;
    loop {
        if count >= MAX_EXTENSIONS {
            return Err(AescryptError::Header(
                "too many extensions (limit: 256)".into(),
            ));
        }

        let len_bytes = read_exact_span::<_, 2>(reader)?;
        let len = len_bytes.with_secret(|lb| u16::from_be_bytes(*lb));

        if len == 0 {
            break; // end of extensions
        }

        // Safe skip — no allocation needed
        let mut discard = [0u8; 256]; // reuse buffer for small extensions
        let mut remaining = len as usize;

        while remaining > 0 {
            let to_read = remaining.min(discard.len());
            reader
                .read_exact(&mut discard[..to_read])
                .map_err(AescryptError::Io)?;
            remaining -= to_read;
        }
        count += 1;
    }
    Ok(())
}

/// Read KDF iterations (v3+ only). Returns 0 for older versions.
#[inline(always)]
pub fn read_kdf_iterations<R>(reader: &mut R, version: u8) -> Result<u32, AescryptError>
where
    R: Read,
{
    if version < 3 {
        return Ok(0);
    }

    let iter_bytes = read_exact_span::<_, 4>(reader)?;
    let iterations = iter_bytes.with_secret(|ib| u32::from_be_bytes(*ib));

    if iterations == 0 {
        return Err(AescryptError::Header(
            "KDF iterations cannot be zero".into(),
        ));
    }
    if iterations > 5_000_000 {
        return Err(AescryptError::Header(
            "KDF iterations unreasonably high (>5M)".into(),
        ));
    }

    Ok(iterations)
}
