// src/encryption/session.rs

//! Session-block encryption for the AES Crypt v3 format.
//!
//! This module mirrors [`crate::decryption::session`] on the write side. It
//! contains the password-derived setup-key derivation and the AES-256-CBC
//! encryption of the 48-byte session block (16-byte session IV + 32-byte
//! session key), authenticated with HMAC-SHA256.
//!
//! These are pure crypto primitives — no I/O. They are exposed for advanced
//! callers that compose their own v3-compatible encryption flow.

use crate::aliases::{
    Aes256Key32, Block16, EncryptedSessionBlock48, HmacSha256, Iv16, PasswordString,
};
use crate::constants::{PBKDF2_MAX_ITER, PBKDF2_MIN_ITER};
use crate::error::AescryptError;
use crate::kdf::pbkdf2::derive_pbkdf2_key;
use crate::utilities::xor_blocks;
use aes::cipher::BlockEncrypt;
use aes::{Aes256Enc, Block as AesBlock};
use hmac::Mac;
use secure_gate::{RevealSecret, RevealSecretMut};

/// Derives the AES-256 setup key from a password and public IV using
/// PBKDF2-HMAC-SHA512.
///
/// The setup key is the master key used to encrypt the AES Crypt v3 session
/// block. It is derived from the user's password and the per-file public IV
/// (which doubles as the PBKDF2 salt). This is the only place in the v3
/// encryption path where the password touches real cryptography; the bulk
/// payload uses a separate, randomly generated session key.
///
/// # Errors
///
/// - [`AescryptError::Header`] — `iterations` is outside
///   [`PBKDF2_MIN_ITER`](crate::constants::PBKDF2_MIN_ITER) `..=`
///   [`PBKDF2_MAX_ITER`](crate::constants::PBKDF2_MAX_ITER).
/// - [`AescryptError::Crypto`] — the underlying PBKDF2 implementation rejected
///   its parameters (forwarded from [`crate::derive_pbkdf2_key`]).
///
/// # Security
///
/// - 32-byte output written directly into the caller-provided
///   [`Aes256Key32`](crate::aliases::Aes256Key32) without ever materializing
///   the key in a non-zeroizing buffer.
/// - The public IV is reused as the PBKDF2 salt by the AES Crypt v3 spec; it
///   **must** be unique per file (callers using [`crate::encrypt()`] get a
///   CSPRNG-generated public IV automatically).
/// - Iteration count is the only password-cracking-resistance knob; never go
///   below [`DEFAULT_PBKDF2_ITERATIONS`](crate::constants::DEFAULT_PBKDF2_ITERATIONS)
///   for new files.
#[inline]
pub fn derive_setup_key(
    password: &PasswordString,
    public_iv: &Iv16,
    iterations: u32,
    out_key: &mut Aes256Key32,
) -> Result<(), AescryptError> {
    if !(PBKDF2_MIN_ITER..=PBKDF2_MAX_ITER).contains(&iterations) {
        return Err(AescryptError::Header("invalid KDF iterations".into()));
    }
    derive_pbkdf2_key(password, public_iv, iterations, out_key)
}

/// Encrypts the 48-byte session block (session IV + session key) under the
/// setup key and feeds each ciphertext block into the running HMAC.
///
/// The session block is laid out as three 16-byte AES-CBC plaintext blocks:
///
/// 1. `session_iv` (16 bytes)
/// 2. first half of `session_key` (16 bytes)
/// 3. second half of `session_key` (16 bytes)
///
/// CBC chains off `public_iv`. Each ciphertext block is written to `enc_block`
/// and folded into `hmac` (which is the same HMAC instance the caller will
/// later finalize and serialize with [`crate::encryption::write_hmac`]).
///
/// # Errors
///
/// This function is currently infallible at the type level (returns
/// `Ok(())`); the `Result` is preserved to keep the signature stable across
/// future security-hardening changes.
///
/// # Panics
///
/// Never panics on valid input.
///
/// # Security
///
/// - All sensitive values (`session_iv`, `session_key`, `enc_block`) are
///   [`secure-gate`] aliases that zeroize on drop.
/// - `public_iv` is treated as a public, unique-per-file value (it appears in
///   the file header verbatim).
/// - `hmac` is keyed with the setup key by the caller; this function only
///   updates it.
///
/// # Arguments
///
/// * `cipher`      — AES-256 encryption initialized with the setup key.
/// * `session_iv`  — Randomly generated 16-byte session IV.
/// * `session_key` — Randomly generated 32-byte session key.
/// * `public_iv`   — 16-byte public IV from the file header (CBC IV).
/// * `enc_block`   — Output buffer (48 bytes) for the encrypted session block.
/// * `hmac`        — Running HMAC-SHA256 instance, updated in place.
///
/// [`secure-gate`]: https://github.com/Slurp9187/secure-gate
#[inline]
pub fn encrypt_session_block(
    cipher: &Aes256Enc,
    session_iv: &Iv16,
    session_key: &Aes256Key32,
    public_iv: &Iv16,
    enc_block: &mut EncryptedSessionBlock48,
    hmac: &mut HmacSha256,
) -> Result<(), AescryptError> {
    let mut prev_block = public_iv.with_secret(|iv| Block16::new(*iv));
    let mut block = Block16::new([0u8; 16]);

    // === Block 1: session IV (16 bytes) ===
    session_iv.with_secret(|siv| {
        prev_block.with_secret(|pb| block.with_secret_mut(|b| xor_blocks(siv, pb, b)))
    });
    let mut aes_block = block.with_secret(|b| AesBlock::from(*b));
    cipher.encrypt_block(&mut aes_block);
    enc_block.with_secret_mut(|eb| eb[0..16].copy_from_slice(aes_block.as_ref()));
    hmac.update(aes_block.as_ref());
    let temp_block = Block16::new(*aes_block.as_ref());
    prev_block = temp_block;

    // === Block 2: first half of session key (16 bytes) ===
    session_key.with_secret(|sk| {
        prev_block.with_secret(|pb| block.with_secret_mut(|b| xor_blocks(&sk[0..16], pb, b)))
    });
    aes_block = block.with_secret(|b| AesBlock::from(*b));
    cipher.encrypt_block(&mut aes_block);
    enc_block.with_secret_mut(|eb| eb[16..32].copy_from_slice(aes_block.as_ref()));
    hmac.update(aes_block.as_ref());
    let temp_block = Block16::new(*aes_block.as_ref());
    prev_block = temp_block;

    // === Block 3: second half of session key (16 bytes) ===
    session_key.with_secret(|sk| {
        prev_block.with_secret(|pb| block.with_secret_mut(|b| xor_blocks(&sk[16..32], pb, b)))
    });
    aes_block = block.with_secret(|b| AesBlock::from(*b));
    cipher.encrypt_block(&mut aes_block);
    enc_block.with_secret_mut(|eb| eb[32..48].copy_from_slice(aes_block.as_ref()));
    hmac.update(aes_block.as_ref());

    Ok(())
}
