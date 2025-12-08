//! # PBKDF2-HMAC-SHA512 Key Derivation
//!
//! This module provides PBKDF2-HMAC-SHA512 key derivation for AES Crypt v3 files.
//! PBKDF2 (Password-Based Key Derivation Function 2) is used to derive encryption
//! keys from passwords with a configurable iteration count for security.

use crate::aliases::{Aes256Key32, PasswordString, Salt16};
use crate::AescryptError;

use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha512;

/// Derive PBKDF2-HMAC-SHA512 key directly into a secure buffer.
///
/// This function performs PBKDF2 key derivation using HMAC-SHA512 as the underlying
/// pseudorandom function. The derived key is written directly into the provided output
/// buffer, avoiding unnecessary allocations and copies.
///
/// # Arguments
///
/// * `password` - The password to derive the key from (wrapped in `PasswordString` for security)
/// * `salt` - 16-byte salt value (should be random and unique per encryption)
/// * `iterations` - Number of PBKDF2 iterations (must be ≥ 1, typically 100,000-500,000)
/// * `out_key` - Output buffer where the 32-byte derived key will be written
///
/// # Returns
///
/// Returns `Ok(())` if key derivation succeeds, or an error if:
/// - `iterations` is 0
/// - PBKDF2 computation fails
///
/// # Security
///
/// - Uses secure-gate types throughout for automatic zeroization
/// - Output buffer is zeroized on drop
/// - Password never exposed in plain form (requires `.expose_secret()` to access)
/// - Salt and key are protected by secure-gate wrappers
///
/// # Errors
///
/// - [`AescryptError::Crypto`] - If iterations is 0 or PBKDF2 computation fails
///
/// # Example
///
/// ```
/// use aescrypt_rs::kdf::pbkdf2::derive_secure_pbkdf2_key;
/// use aescrypt_rs::aliases::{PasswordString, Salt16, Aes256Key32, RandomSalt16};
///
/// let password = PasswordString::new("my-secret-password".to_string());
/// let salt: Salt16 = RandomSalt16::generate().into();
/// let mut key = Aes256Key32::new([0u8; 32]);
///
/// derive_secure_pbkdf2_key(&password, &salt, 300_000, &mut key)?;
/// // Key is now derived and stored securely in `key`
/// # Ok::<(), aescrypt_rs::AescryptError>(())
/// ```
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

