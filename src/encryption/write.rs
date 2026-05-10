//! Low-level v3 header / trailer writers for custom encryption flows.
//!
//! Most callers should use [`crate::encrypt()`] which composes these helpers
//! into a complete v3 file. The writers in this module are exposed for
//! advanced use cases that need to interleave the AES Crypt header with their
//! own framing — for example, embedding ciphertext inside another container.
//!
//! All writers in this module reject pre-v3 versions with
//! [`AescryptError::UnsupportedVersion`]. This crate does not produce legacy
//! formats; see the [crate-level Security Model](crate#security-model) for
//! rationale.

use crate::aliases::{HmacSha256, Iv16};
use crate::constants::{PBKDF2_MAX_ITER, PBKDF2_MIN_ITER};
use crate::error::AescryptError;
use hmac::Mac;
use secure_gate::RevealSecret;
use std::io::Write;

/// Writes `data` to `writer` as a single contiguous run.
///
/// Thin wrapper over [`Write::write_all`] that converts I/O failures into
/// [`AescryptError::Io`]. Used internally by every other writer in this module
/// and by [`crate::encryption::encrypt_session_block`] / payload streaming.
///
/// # Errors
///
/// - [`AescryptError::Io`] — `writer.write_all` returned an error.
///
/// # Panics
///
/// Never panics on its own. Panics in `writer` propagate normally.
#[inline]
pub fn write_octets<W: Write>(writer: &mut W, data: &[u8]) -> Result<(), AescryptError> {
    writer.write_all(data).map_err(AescryptError::Io)
}

/// Writes the 5-byte AES Crypt v3 file header `b"AES" || version || 0x00`.
///
/// # Format
///
/// ```text
/// 'A' 'E' 'S'  version  0x00
///  0   1   2     3       4
/// ```
///
/// # Errors
///
/// - [`AescryptError::UnsupportedVersion`] — `version < 3`. This crate only
///   writes v3.
/// - [`AescryptError::Io`] — `writer` returned an error.
#[inline]
pub fn write_header<W: Write>(writer: &mut W, version: u8) -> Result<(), AescryptError> {
    if version < 3 {
        return Err(AescryptError::UnsupportedVersion(version));
    }
    write_octets(writer, &[b'A', b'E', b'S', version, 0x00])
}

/// Writes the v3 extension-block section, terminated by a zero-length record.
///
/// If `extensions` is `Some(bytes)`, those bytes are written verbatim. If
/// `None`, the canonical "no extensions" terminator `[0x00, 0x00]` is written.
///
/// # Format
///
/// Each extension is a `u16` big-endian length followed by `length` payload
/// bytes; a length of `0` ends the section. When `extensions` is `Some`, the
/// caller is responsible for emitting any payload extensions and the trailing
/// `[0x00, 0x00]` terminator.
///
/// # Errors
///
/// - [`AescryptError::UnsupportedVersion`] — `version < 3`.
/// - [`AescryptError::Io`] — `writer` returned an error.
#[inline]
pub fn write_extensions<W: Write>(
    writer: &mut W,
    version: u8,
    extensions: Option<&[u8]>,
) -> Result<(), AescryptError> {
    if version < 3 {
        return Err(AescryptError::UnsupportedVersion(version));
    }
    let data = extensions.unwrap_or(&[0x00, 0x00]);
    write_octets(writer, data)
}

/// Writes the v3 PBKDF2 iteration count as 4 big-endian bytes.
///
/// # Format
///
/// `iterations.to_be_bytes()`, written immediately after the extensions block
/// and immediately before the public IV.
///
/// # Errors
///
/// - [`AescryptError::UnsupportedVersion`] — `version < 3` (v0/v1/v2 do not
///   carry an iteration count in the header).
/// - [`AescryptError::Header`] — `iterations` is outside
///   [`PBKDF2_MIN_ITER`](crate::constants::PBKDF2_MIN_ITER) `..=`
///   [`PBKDF2_MAX_ITER`](crate::constants::PBKDF2_MAX_ITER).
/// - [`AescryptError::Io`] — `writer` returned an error.
///
/// # Security
///
/// The iteration count gates PBKDF2 cost and is therefore the primary
/// password-cracking-resistance knob. Use
/// [`DEFAULT_PBKDF2_ITERATIONS`](crate::constants::DEFAULT_PBKDF2_ITERATIONS)
/// for new files unless you have measured your platform.
#[inline]
pub fn write_iterations<W: Write>(
    writer: &mut W,
    iterations: u32,
    version: u8,
) -> Result<(), AescryptError> {
    if version < 3 {
        return Err(AescryptError::UnsupportedVersion(version));
    }
    if !(PBKDF2_MIN_ITER..=PBKDF2_MAX_ITER).contains(&iterations) {
        return Err(AescryptError::Header("invalid KDF iterations".into()));
    }
    write_octets(writer, &iterations.to_be_bytes())
}

/// Writes the 16-byte public IV after revealing it from its [`secure-gate`]
/// wrapper.
///
/// The public IV is the per-file salt fed to PBKDF2 (and the CBC IV for the
/// session-block encryption). It is generated with the [`secure-gate`] CSPRNG
/// inside [`crate::encrypt()`]; downstream callers writing custom flows must
/// generate a fresh, unpredictable IV per file.
///
/// # Errors
///
/// - [`AescryptError::Io`] — `writer` returned an error.
///
/// # Security
///
/// The public IV is **not** secret; it is written in the clear and read back
/// during decryption. It must be **unique and unpredictable** per file. Reusing
/// a public IV with the same password yields the same setup key and breaks the
/// uniqueness of the encrypted session block.
///
/// [`secure-gate`]: https://github.com/Slurp9187/secure-gate
#[inline]
pub fn write_public_iv<W: Write>(writer: &mut W, iv: &Iv16) -> Result<(), AescryptError> {
    iv.with_secret(|i| write_octets(writer, i))
}

/// Finalizes `hmac` and writes the resulting 32-byte HMAC-SHA256 tag.
///
/// Consumes `hmac` (it is no longer reusable) and writes the 32-byte tag
/// produced by [`Mac::finalize`]. Used to seal both the encrypted session block
/// (after [`crate::encryption::encrypt_session_block`]) and, separately, the
/// payload stream (inside [`crate::encryption::encrypt_stream`]).
///
/// # Errors
///
/// - [`AescryptError::Io`] — `writer` returned an error while writing the
///   32-byte tag.
///
/// # Security
///
/// HMAC-SHA256 with a 32-byte key derived from PBKDF2-HMAC-SHA512 (the "setup
/// key" for the session block, the session key for the payload). Verification
/// on the read side uses constant-time equality via [`secure-gate`]'s
/// `ConstantTimeEq`.
///
/// [`secure-gate`]: https://github.com/Slurp9187/secure-gate
#[inline]
pub fn write_hmac<W: Write>(writer: &mut W, hmac: HmacSha256) -> Result<(), AescryptError> {
    write_octets(writer, hmac.finalize().into_bytes().as_ref())
}
