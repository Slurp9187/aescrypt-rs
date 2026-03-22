//! src/kdf/ackdf.rs
//! AES Crypt v0–v2 ACKDF — out-param, zero-exposure, secure-gate

use crate::aliases::{AckdfHashState32, Aes256Key32, PasswordString, Salt16};
use crate::utilities::utf8_to_utf16le;
use crate::AescryptError;
use secure_gate::{Dynamic, RevealSecret, RevealSecretMut};
use sha2::{Digest, Sha256};

/// Fixed iteration count for ACKDF as defined by AES Crypt v0–v2 specification
pub const ACKDF_ITERATIONS: u32 = 8192;

#[inline(always)]
fn hash_once<F1, F2>(hasher: &mut Sha256, update_prev: F1, update_pw: F2) -> [u8; 32]
where
    F1: FnOnce(&mut Sha256),
    F2: FnOnce(&mut Sha256),
{
    update_prev(hasher);
    update_pw(hasher);
    hasher.finalize_reset().into()
}

/// Derive ACKDF key directly into caller buffer (zero-cost, zero-exposure)
///
/// - 8192 × SHA-256 iterations
/// - UTF-16-LE password encoding
/// - Salt must be exactly 16 bytes
///
/// Writes result into `out_key` — no return value, fastest possible
///
/// # Thread Safety
///
/// This function is **thread-safe** and can be called concurrently from multiple threads.
/// All operations are pure (no shared mutable state).
#[inline(always)]
pub fn derive_ackdf_key(
    password: &PasswordString,
    salt: &Salt16,
    out_key: &mut Aes256Key32,
) -> Result<(), AescryptError> {
    let password_utf16le_result = password.with_secret(|pw| utf8_to_utf16le(pw.as_bytes()));
    let password_utf16le: Dynamic<Vec<u8>> = Dynamic::new(password_utf16le_result?);

    let mut hasher = Sha256::new();
    let mut hash = AckdfHashState32::new([0u8; 32]); // ← semantic, zero-cost, auto-zeroized

    // First 16 bytes = salt
    salt.with_secret(|s| {
        hash.with_secret_mut(|h| h[..16].copy_from_slice(s));
    });

    for _ in 0..ACKDF_ITERATIONS {
        hash = AckdfHashState32::new(hash_once(
            &mut hasher,
            |hasher| hash.with_secret(|h| hasher.update(h)),
            |hasher| password_utf16le.with_secret(|p| hasher.update(p)),
        ));
    }

    hash.with_secret(|h| {
        out_key.with_secret_mut(|out| out.copy_from_slice(h));
    });
    // hash is auto-zeroized on drop here

    Ok(())
}
