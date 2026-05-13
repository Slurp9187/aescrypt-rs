//! src/decryption/read.rs
//! Header / extension / iteration-count parsers for the AES Crypt v0–v3 read path.
//!
//! Every parser in this module reads into a [`SpanBuffer<N>`](crate::aliases::SpanBuffer),
//! the [`secure-gate`] auto-zeroizing fixed-size buffer, so that even
//! pre-authentication header bytes never linger on the stack after the call
//! returns. The parsers are sequenced by [`crate::decrypt()`]; they are
//! exposed publicly so that callers driving custom containers can rebuild the
//! read pipeline themselves.
//!
//! # Security
//!
//! These parsers run **before** the session HMAC is verified, so any allocation
//! or work they perform is attacker-influenceable. They are deliberately kept
//! to fixed-size reads with hard-coded upper bounds (e.g. `MAX_EXTENSIONS`,
//! [`PBKDF2_MAX_ITER`](crate::constants::PBKDF2_MAX_ITER)).
//!
//! [`secure-gate`]: https://github.com/Slurp9187/secure-gate

use crate::aliases::{ExtensionChunk256, SpanBuffer};
use crate::error::AescryptError;
use secure_gate::{RevealSecret, RevealSecretMut};
use std::io::Read;

/// Reads exactly `N` bytes from `reader` into a fresh auto-zeroizing
/// [`SpanBuffer<N>`](crate::aliases::SpanBuffer).
///
/// `read_exact_span` is the primary stream reader for the constant-memory
/// decryption path. The returned buffer lives on the stack inside a
/// [`secure-gate`] wrapper so its contents are wiped on drop — important
/// because pre-authentication header bytes pass through this function.
///
/// # Errors
///
/// - [`AescryptError::Io`] — `reader.read_exact` returned an error, including
///   premature EOF.
///
/// # Panics
///
/// Never panics. EOF is surfaced as [`AescryptError::Io`], not a panic.
///
/// # Security
///
/// Output buffer auto-zeroizes via [`secure-gate`] regardless of which
/// branch of the caller eventually returns.
///
/// [`secure-gate`]: https://github.com/Slurp9187/secure-gate
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

/// Reads and validates the 5-byte AES Crypt file header.
///
/// Returns `(version, modulo_or_reserved)` where:
///
/// - `version` is the file format version (`0..=3`).
/// - `modulo_or_reserved` is the 5th header byte:
///   - For v0: the **modulo** byte (any value; passed to
///     [`StreamConfig::V0`](crate::decryption::StreamConfig::V0) for final
///     plaintext-length recovery).
///   - For v1–v3: the **reserved** byte; an error is returned unless it is
///     `0x00`.
///
/// This is the strict counterpart to [`crate::read_version`], which only
/// reads as many bytes as needed and is permissive about short v0 stubs.
///
/// # Errors
///
/// - [`AescryptError::Io`] — premature EOF or other reader error.
/// - [`AescryptError::Header`] — magic bytes are not `b"AES"`, or the v1–v3
///   reserved byte is not `0x00`.
/// - [`AescryptError::UnsupportedVersion`] — version byte is `> 3`.
///
/// # Security
///
/// Reads exactly 5 bytes regardless of input, capping pre-authentication
/// effort. The output is plain `(u8, u8)` — there is nothing secret to
/// zeroize.
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

/// Consumes all v2/v3 extension blocks from `reader`, stopping at the
/// zero-length terminator.
///
/// For `version < 2`, this is a no-op (v0/v1 files have no extension section).
/// For v2/v3, each extension is parsed as a `u16` big-endian length followed by
/// `length` payload bytes, and is discarded. The loop stops when a zero-length
/// extension is encountered.
///
/// # Errors
///
/// - [`AescryptError::Io`] — reader error or premature EOF inside an
///   extension.
/// - [`AescryptError::Header`] — more than 256 extension blocks encountered
///   (`"too many extensions (limit: 256)"`).
///
/// # Security
///
/// Capped at 256 extensions to bound CPU/I/O on attacker-controlled files.
/// The discard buffer is fixed at 256 bytes and reused across reads.
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

        let mut chunk = ExtensionChunk256::new([0u8; 256]);
        let mut remaining = len as usize;

        while remaining > 0 {
            let to_read = remaining.min(256);
            chunk
                .with_secret_mut(|d| reader.read_exact(&mut d[..to_read]))
                .map_err(AescryptError::Io)?;
            remaining -= to_read;
        }
        count += 1;
    }
    Ok(())
}

/// Reads the 4-byte big-endian PBKDF2 iteration count from a v3 file header.
///
/// Returns `0` for `version < 3` (v0/v1/v2 do not store an iteration count;
/// they use the fixed [`ACKDF_ITERATIONS`](crate::kdf::ackdf::ACKDF_ITERATIONS)
/// instead). For v3, the value is validated against an internal upper bound of
/// 5 000 000 iterations (matching
/// [`PBKDF2_MAX_ITER`](crate::constants::PBKDF2_MAX_ITER)) and rejected if
/// zero.
///
/// # Errors
///
/// - [`AescryptError::Io`] — reader error or premature EOF.
/// - [`AescryptError::Header`] — iteration count is `0`
///   (`"KDF iterations cannot be zero"`) or exceeds 5 000 000
///   (`"KDF iterations unreasonably high (>5M)"`).
///
/// # Security
///
/// The 5 000 000 ceiling is enforced before any password-dependent work to
/// prevent denial-of-service via crafted headers with `iterations = u32::MAX`.
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
