//! src/kdf/pbkdf2.rs

use crate::aliases::{Aes256Key32, PasswordString, Salt16};
use crate::AescryptError;

use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha512;

/// Derive PBKDF2-HMAC-SHA512 directly into Aes256Key buffer
///
/// # Security
/// - Uses secure-gate types throughout
/// - Output buffer is zeroized on drop
/// - Password never exposed in plain form
#[inline(always)]
pub fn derive_secure_pbkdf2_key(
    password: &PasswordString,
    salt: &Salt16,
    iterations: u32,
    out_key: &mut Aes256Key32,
) -> Result<(), AescryptError> {
    if iterations == 0 {
        return Err(AescryptError::Crypto("PBKDF2 iterations must be ≥1".into()));
    }

    pbkdf2::<Hmac<Sha512>>(
        password.expose_secret().as_bytes(),
        salt.expose_secret(),
        iterations,
        out_key.expose_secret_mut(),
    )
    .map_err(|e| AescryptError::Crypto(format!("PBKDF2 failed: {e}")))?;
    Ok(())
}

