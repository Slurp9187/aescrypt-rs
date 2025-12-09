//! src/decryption/read.rs
//! Safe, zero-copy, stack-first Aescrypt header parsing
//! Fully optimized for 2025 Rust + secure-gate v0.5.10+ ecosystem

use crate::aliases::SpanBuffer;
use crate::error::AescryptError;
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
    reader
        .read_exact(buf.expose_secret_mut())
        .map_err(AescryptError::Io)?;
    Ok(buf)
}

/// Validate file magic `"AES"` + version byte (0–3 supported)
#[inline(always)]
pub fn read_file_version<R>(reader: &mut R) -> Result<u8, AescryptError>
where
    R: Read,
{
    let header = read_exact_span::<_, 4>(reader)?;
    if header.expose_secret()[..3] != *b"AES" {
        return Err(AescryptError::Header(
            "invalid magic header (expected 'AES')".into(),
        ));
    }
    let version = header.expose_secret()[3];
    if version > 3 {
        return Err(AescryptError::UnsupportedVersion(version));
    }
    Ok(version)
}

/// Read the reserved/modulo byte (v0–v2: modulo, v3: reserved)
#[inline(always)]
pub fn read_reserved_modulo_byte<R>(reader: &mut R) -> Result<u8, AescryptError>
where
    R: Read,
{
    Ok(read_exact_span::<_, 1>(reader)?.expose_secret()[0])
}

/// Consume all v2+ extensions (zero-copy skip)
#[inline(always)]
pub fn consume_all_extensions<R>(reader: &mut R, version: u8) -> Result<(), AescryptError>
where
    R: Read,
{
    if version < 2 {
        return Ok(());
    }

    loop {
        let len_bytes = read_exact_span::<_, 2>(reader)?;
        let len = u16::from_be_bytes(*len_bytes.expose_secret());

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
    let iterations = u32::from_be_bytes(*iter_bytes.expose_secret());

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
