//! PBKDF2-HMAC-SHA512 key derivation for AES Crypt v3 files.
//!
//! PBKDF2 (Password-Based Key Derivation Function 2, RFC 8018) is the
//! password-hardening primitive used to derive the v3 setup key from the
//! user's password and the per-file public IV (which doubles as the salt).
//! The iteration count is caller-controlled within the bounds enforced by
//! [`crate::constants::PBKDF2_MIN_ITER`] /
//! [`crate::constants::PBKDF2_MAX_ITER`], with
//! [`crate::constants::DEFAULT_PBKDF2_ITERATIONS`] as the recommended value.
//!
//! For a more ergonomic builder API see [`crate::Pbkdf2Builder`].

use crate::aliases::{PasswordString, Pbkdf2DerivedKey32, Salt16};
use crate::AescryptError;

use hmac::Hmac;
use pbkdf2::pbkdf2;
use secure_gate::{RevealSecret, RevealSecretMut};
use sha2::Sha512;

/// Derives a 32-byte AES-256 key from `password` and `salt` using
/// PBKDF2-HMAC-SHA512 and writes it into `out_key`.
///
/// Output is written directly into the caller-provided
/// [`crate::aliases::Pbkdf2DerivedKey32`] — no intermediate allocation, no
/// plaintext key bytes on a non-zeroizing buffer.
///
/// # Errors
///
/// - [`AescryptError::Crypto`] — the underlying `pbkdf2` crate returned an
///   error (e.g. `iterations` is rejected or the output length is invalid).
///   The wrapped string is `PBKDF2 failed: <inner>`.
///
/// # Panics
///
/// Never panics on valid input.
///
/// # Security
///
/// - **Iteration count** is the only password-cracking-resistance knob in the
///   AES Crypt v3 format. Use
///   [`DEFAULT_PBKDF2_ITERATIONS`](crate::constants::DEFAULT_PBKDF2_ITERATIONS)
///   (300 000) or higher for new files; the encryption path additionally
///   clamps to
///   [`PBKDF2_MIN_ITER..=PBKDF2_MAX_ITER`](crate::constants::PBKDF2_MAX_ITER).
///   `iterations == 0` is silently clamped to `1` for parity with
///   [`crate::Pbkdf2Builder::with_iterations`].
/// - **Salt uniqueness**: `salt` must be unique per encryption to avoid
///   rainbow-table attacks. [`crate::encrypt()`] generates a fresh random
///   `Salt16` (the public IV) per call.
/// - **Memory hygiene**: `password`, `salt`, and `out_key` are all
///   [`secure-gate`] aliases and zeroize on drop. The password is only
///   revealed via scoped `with_secret` closures.
///
/// # Thread Safety
///
/// Pure function with no shared state; safe to call concurrently.
///
/// # Examples
///
/// ```
/// use aescrypt_rs::kdf::pbkdf2::derive_pbkdf2_key;
/// use aescrypt_rs::aliases::{PasswordString, Salt16, Pbkdf2DerivedKey32};
///
/// let password = PasswordString::new("my-secret-password".to_string());
/// // In production, prefer `Salt16::from_random()` or `Pbkdf2Builder`.
/// let salt = Salt16::from([0x42; 16]);
/// let mut key = Pbkdf2DerivedKey32::new([0u8; 32]);
///
/// derive_pbkdf2_key(&password, &salt, 300_000, &mut key)?;
/// # Ok::<(), aescrypt_rs::AescryptError>(())
/// ```
///
/// # See also
///
/// - [`crate::Pbkdf2Builder`] — fluent builder around this function.
/// - [`crate::derive_ackdf_key`] — legacy KDF for v0–v2 files.
///
/// [`secure-gate`]: https://github.com/Slurp9187/secure-gate
#[inline(always)]
pub fn derive_pbkdf2_key(
    password: &PasswordString,
    salt: &Salt16,
    iterations: u32,
    out_key: &mut Pbkdf2DerivedKey32,
) -> Result<(), AescryptError> {
    // Clamp 0 to 1 — consistent with `Pbkdf2Builder::with_iterations`.
    let iterations = iterations.max(1);

    password
        .with_secret(|pw| {
            salt.with_secret(|s| {
                out_key.with_secret_mut(|key| {
                    pbkdf2::<Hmac<Sha512>>(pw.as_bytes(), s, iterations, key)
                })
            })
        })
        .map_err(|e| AescryptError::Crypto(format!("PBKDF2 failed: {e}")))?;
    Ok(())
}
