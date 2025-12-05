//! src/crypto/kdf/ackdf.rs
//! Aescrypt v0–v2 ACKDF — out-param, zero-exposure, secure-gate v0.5.5+

use crate::aliases::{Aes256Key32, PasswordString, Salt16};
use crate::utils::utf8_to_utf16le;
use crate::AescryptError; // ← Use crate root re-exports
use sha2::{Digest, Sha256};

/// Fixed iteration count for ACKDF as defined by AES Crypt v0–v2 specification
pub const ACKDF_ITERATIONS: u32 = 8192;

/// Derive ACKDF key directly into caller buffer (zero-cost, zero-exposure)
///
/// - 8192 × SHA-256 iterations
/// - UTF-16LE password encoding
/// - Salt must be exactly 16 bytes
///
/// Writes result into `out_key` — no return value, fastest possible
/// Derive ACKDF key directly into caller-provided Aes256Key buffer
#[inline(always)]
pub fn derive_secure_ackdf_key(
    password: &PasswordString,
    salt: &Salt16,
    out_key: &mut Aes256Key32,
) -> Result<(), AescryptError> {
    let password_utf16le = utf8_to_utf16le(password.expose_secret().as_bytes())?;

    let mut hasher = Sha256::new();
    let mut hash = [0u8; 32];
    hash[..16].copy_from_slice(salt.expose_secret());

    for _ in 0..ACKDF_ITERATIONS {
        hasher.update(hash);
        hasher.update(&password_utf16le);
        hash = hasher.finalize_reset().into();
    }

    out_key.expose_secret_mut().copy_from_slice(&hash);
    Ok(())
}
