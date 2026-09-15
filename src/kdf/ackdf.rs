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
//! - The running 32-byte hash state is wrapped in
//!   [`crate::aliases::AckdfHashState32`] and each iteration finalizes
//!   directly into it (`finalize_into_reset`) — no unwrapped intermediate
//!   copies. The `Sha256` hasher's *internal* state (chaining variables and
//!   block buffer) cannot be explicitly zeroized through `sha2`'s public API;
//!   see the inline comment in the implementation.

use crate::AescryptError;
use crate::aliases::{AckdfDerivedKey32, AckdfHashState32, Salt16};
use crate::utilities::utf8_to_utf16le;
use secure_gate::{Dynamic, RevealSecret, RevealSecretMut};
use sha2::{Digest, Sha256, digest::Output};

/// Fixed ACKDF iteration count mandated by the AES Crypt v0–v2 file format
/// specification.
///
/// The unit is **iterations** (each iteration is a SHA-256 of the previous
/// 32-byte hash state followed by the UTF-16-LE password). This value is part
/// of the on-wire format and cannot be changed without breaking compatibility.
pub const ACKDF_ITERATIONS: u32 = 8192;

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
/// - [`AescryptError::Crypto`] — forwarded from
///   [`crate::utilities::utf8_to_utf16le`] when the password bytes are not
///   valid UTF-8. Because `password` is a `&str`, this is structurally
///   unreachable; the `Result` is kept so the signature stays stable and so
///   the error path remains shared with the public byte-slice helper.
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
/// - `out_key` is a [`secure-gate`] alias and zeroizes on drop. `password` is
///   a plain `&str` **borrow** — it is read in place, never copied and never
///   stored, so **zeroizing the password is the caller's responsibility**.
///   Keep it in a zeroize-on-drop container and pass a scoped borrow (see
///   [`crate::derive_pbkdf2_key`] for the pattern).
/// - The UTF-16-LE re-encoding of the password is unavoidable (the v0–v2 spec
///   hashes UTF-16-LE code units) and is wrapped in a `Dynamic<Vec<u8>>` the
///   moment it exists, so that derived copy zeroizes on drop.
/// - Each iteration finalizes directly into the [`secure-gate`]-wrapped hash
///   state ([`crate::aliases::AckdfHashState32`], zeroized on drop) via
///   `finalize_into_reset`; no unwrapped copy of the running hash is made.
///   The `Sha256` hasher's internal chaining state and block buffer are
///   re-initialized between iterations but cannot be explicitly zeroized
///   through `sha2`'s public API.
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
    password: &str,
    salt: &Salt16,
    out_key: &mut AckdfDerivedKey32,
) -> Result<(), AescryptError> {
    // `password.as_bytes()` borrows in place — no copy of the password itself.
    // The UTF-16-LE expansion is a *derived* secret, so it is wrapped in a
    // zeroize-on-drop `Dynamic<Vec<u8>>` immediately.
    let password_utf16le: Dynamic<Vec<u8>> = Dynamic::new(utf8_to_utf16le(password.as_bytes())?);

    // Note: `Sha256` holds internal chaining state (8 × u32) and a 64-byte block buffer on
    // the stack, neither wrapped in a secure-gate type. `finalize_into_reset()` re-initializes
    // the chaining state to the SHA-256 IV after each iteration, but the block buffer is only
    // position-reset, so password-derived bytes may linger there until the frame is reused —
    // `sha2` 0.10 exposes no zeroize hook for hasher internals. The running `hash` state is
    // auto-zeroized via secure-gate on drop.
    let mut hasher = Sha256::new();
    let mut hash = AckdfHashState32::new([0u8; 32]); // ← semantic, zero-cost, auto-zeroized

    // First 16 bytes = salt
    salt.with_secret(|s| {
        hash.with_secret_mut(|h| h[..16].copy_from_slice(s));
    });

    for _ in 0..ACKDF_ITERATIONS {
        hash.with_secret(|h| hasher.update(h));
        password_utf16le.with_secret(|p| hasher.update(p));
        // Finalize straight into the wrapped state — no unwrapped [u8; 32] copy.
        hash.with_secret_mut(|h| hasher.finalize_into_reset(Output::<Sha256>::from_mut_slice(h)));
    }

    hash.with_secret(|h| {
        out_key.with_secret_mut(|out| out.copy_from_slice(h));
    });
    // hash is auto-zeroized on drop here

    Ok(())
}
