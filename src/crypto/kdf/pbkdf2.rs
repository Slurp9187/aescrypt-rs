//! src/crypto/kdf/pbkdf2.rs

use crate::aliases::{Aes256Key, Password, Salt16};
use crate::AescryptError;

use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha512;

/// Derive PBKDF2-HMAC-SHA512 directly into Aes256Key buffer
/// Zero allocation, zero copy, maximum speed + security
#[inline(always)]
pub fn derive_secure_pbkdf2_key(
    password: &Password,     // &Dynamic<String>
    salt: &Salt16,           // &Fixed<[u8; 16]>
    iterations: u32,         // ← primitive → by value = correct
    out_key: &mut Aes256Key, // &mut Fixed<[u8; 32]>
) -> Result<(), AescryptError> {
    if iterations == 0 {
        return Err(AescryptError::Crypto("PBKDF2 iterations must be ≥1".into()));
    }

    pbkdf2::<Hmac<Sha512>>(
        password.expose_secret().as_bytes(),
        salt.expose_secret(),
        iterations, // ← direct, zero-cost, idiomatic
        out_key.expose_secret_mut(),
    )
    .map_err(|e| AescryptError::Crypto(format!("PBKDF2 failed: {e}")))?;

    Ok(())
}
