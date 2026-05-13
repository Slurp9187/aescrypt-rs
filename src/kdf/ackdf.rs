//! src/kdf/ackdf.rs
//! AES Crypt Key Derivation Function (ACKDF) for v0–v2 files (read-only).
//!
//! ACKDF is the legacy KDF used by AES Crypt v0–v2: 8192 iterations of
//! SHA-256 over the previous hash and the UTF-16-LE-encoded password,
//! seeded with a 16-byte salt. It is exposed for callers that need to
//! decrypt legacy files; new files always use PBKDF2-HMAC-SHA512 (see
//! [`crate::kdf::pbkdf2`]) and are written by [`crate::encrypt()`].
//!
//! # Security
//!
//! - **Iteration count is fixed at 8192** by the AES Crypt v0–v2 spec; do not
//!   reduce it. By modern standards 8192 SHA-256 iterations are weak; this
//!   crate uses ACKDF only on the read path for legacy file compatibility.
//! - The intermediate `Sha256` hasher state lives on the stack and is reset
//!   (but not explicitly zeroized) between iterations. The 32-byte hash state
//!   is wrapped in [`crate::aliases::AckdfHashState32`] so it does zeroize on
//!   drop. See the inline comment in the implementation.

use crate::aliases::{AckdfDerivedKey32, AckdfHashState32, PasswordString, Salt16};
use crate::utilities::utf8_to_utf16le;
use crate::AescryptError;
use secure_gate::{Dynamic, RevealSecret, RevealSecretMut};
use sha2::{Digest, Sha256};

/// Fixed ACKDF iteration count mandated by the AES Crypt v0–v2 file format
/// specification.
///
/// The unit is **iterations** (each iteration is a SHA-256 of the previous
/// 32-byte hash state followed by the UTF-16-LE password). This value is part
/// of the on-wire format and cannot be changed without breaking compatibility.
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

/// Derives the AES-256 setup key for AES Crypt v0–v2 files using ACKDF.
///
/// Performs [`ACKDF_ITERATIONS`] iterations of SHA-256 over the running
/// 32-byte hash state and the UTF-16-LE encoded password, writing the final
/// state into `out_key` directly (no return value, no intermediate
/// allocation).
///
/// # Format
///
/// `salt` is the 16-byte public IV from a v0/v1/v2 file header; the password
/// is re-encoded UTF-8 → UTF-16-LE because the AES Crypt v0–v2 spec hashes
/// passwords as UTF-16-LE little-endian code units.
///
/// # Errors
///
/// - [`AescryptError::Crypto`] — `password` is not valid UTF-8 (forwarded
///   from [`crate::utilities::utf8_to_utf16le`]).
///
/// # Panics
///
/// Never panics on valid input.
///
/// # Security
///
/// - Iteration count is fixed at 8192 by the AES Crypt v0–v2 spec. ACKDF is
///   weaker than PBKDF2-HMAC-SHA512; new files use
///   [`crate::derive_pbkdf2_key`] instead.
/// - `out_key` is a [`secure-gate`] alias and zeroizes on drop.
/// - The intermediate `Sha256` hasher state holds 8 × `u32` of derived data on
///   the stack and is `finalize_reset()`-ed between iterations, but is not
///   explicitly zeroized when the function returns. The intermediate hash
///   state is wrapped in [`crate::aliases::AckdfHashState32`] and does
///   zeroize on drop.
///
/// # Thread Safety
///
/// Pure function with no shared state; safe to call concurrently.
///
/// # See also
///
/// - [`crate::derive_pbkdf2_key`] — modern KDF used by v3 files.
///
/// [`secure-gate`]: https://github.com/Slurp9187/secure-gate
#[inline(always)]
pub fn derive_ackdf_key(
    password: &PasswordString,
    salt: &Salt16,
    out_key: &mut AckdfDerivedKey32,
) -> Result<(), AescryptError> {
    let password_utf16le_result = password.with_secret(|pw| utf8_to_utf16le(pw.as_bytes()));
    let password_utf16le: Dynamic<Vec<u8>> = Dynamic::new(password_utf16le_result?);

    // Note: `Sha256` holds internal chaining state (8 × u32) on the stack and is not wrapped
    // in a secure-gate type. The intermediate SHA-256 state derived from the password will
    // persist on the stack until the frame is reused. `finalize_reset()` clears the hasher
    // back to its IV after each iteration, so only the most recent state survives, but it
    // is not explicitly zeroized on function exit. The output `hash` is auto-zeroized via
    // secure-gate on drop.
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
