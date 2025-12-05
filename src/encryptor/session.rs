//! src/encryptor/session.rs
//! Session key + IV encryption for AES Crypt v3 format
//!
//! This module is the **exact mirror** of `decryptor/session.rs`.
//! It contains the logic for encrypting the 48-byte session block
//! (session IV + session key) using the setup/master key derived from
//! the user password and public IV.
//!
//! The encrypted session block is authenticated with HMAC-SHA256
//! (the same HMAC instance used for the entire ciphertext stream).
//!
//! This is a pure crypto primitive — no I/O.

use crate::aliases::{
    Aes256Key32, EncryptedSessionBlock48, HmacSha256, Iv16, PasswordString, PlainTextBlock16,
};
use crate::consts::PBKDF2_MAX_ITER;
use crate::crypto::kdf::pbkdf2::derive_secure_pbkdf2_key;
use crate::error::AescryptError;
use crate::utils::xor_blocks;
use aes::cipher::BlockEncrypt;
use aes::{Aes256Enc, Block as AesBlock};
use hmac::Mac;

/// Derive the AES-256 setup key from password + public IV using PBKDF2-HMAC-SHA512.
/// Used to encrypt the session key/IV block.
///
/// This is the only place in the entire encrypt path where the user's password touches
/// real cryptography — belongs next to the session block logic.
#[inline]
pub fn derive_setup_key(
    password: &PasswordString,
    public_iv: &Iv16,
    iterations: u32,
    out_key: &mut Aes256Key32,
) -> Result<(), AescryptError> {
    if iterations == 0 || iterations > PBKDF2_MAX_ITER {
        return Err(AescryptError::Header("invalid KDF iterations".into()));
    }
    derive_secure_pbkdf2_key(password, public_iv, iterations, out_key)
}

/// Encrypts the 48-byte session block (session IV + session key) using
/// AES-256-CBC with the master/setup key derived from the password.
///
/// The encryption is performed in CBC mode with the **public IV** as the
/// initial vector. Each encrypted block is also fed into the running
/// HMAC-SHA256 instance (used for the entire file).
///
/// This function is deliberately inlined and zero-allocation — it is
/// called exactly once per encryption operation.
///
/// # Arguments
///
/// * `cipher`        – AES-256 encryptor initialized with the master key
/// * `session_iv`    – Randomly generated 16-byte session IV
/// * `session_key`   – Randomly generated 32-byte session key
/// * `public_iv`     – 16-byte public IV from the file header
/// * `enc_block`     – Output buffer (48 bytes) for the encrypted session block
/// * `hmac`          – Running HMAC-SHA256 instance (updated in-place)
///
/// # Security
///
/// All sensitive values are wrapped in `secure-gate` fixed-size aliases
/// with automatic zeroing on drop (when `zeroize` feature is enabled).
#[inline]
pub fn encrypt_session_block(
    cipher: &Aes256Enc,
    session_iv: &Iv16,
    session_key: &Aes256Key32,
    public_iv: &Iv16,
    enc_block: &mut EncryptedSessionBlock48,
    hmac: &mut HmacSha256,
) -> Result<(), AescryptError> {
    let mut prev = *public_iv.expose_secret();
    let mut block = PlainTextBlock16::new([0u8; 16]);

    // === Block 1: session IV (16 bytes) ===
    xor_blocks(session_iv.expose_secret(), &prev, block.expose_secret_mut());
    let mut aes_block = AesBlock::from(*block.expose_secret());
    cipher.encrypt_block(&mut aes_block);
    enc_block.expose_secret_mut()[0..16].copy_from_slice(aes_block.as_ref());
    hmac.update(&enc_block.expose_secret()[0..16]);
    prev.copy_from_slice(&enc_block.expose_secret()[0..16]);

    // === Block 2: first half of session key (16 bytes) ===
    xor_blocks(
        &session_key.expose_secret()[0..16],
        &prev,
        block.expose_secret_mut(),
    );
    aes_block = AesBlock::from(*block.expose_secret());
    cipher.encrypt_block(&mut aes_block);
    enc_block.expose_secret_mut()[16..32].copy_from_slice(aes_block.as_ref());
    hmac.update(&enc_block.expose_secret()[16..32]);
    prev.copy_from_slice(&enc_block.expose_secret()[16..32]);

    // === Block 3: second half of session key (16 bytes) ===
    xor_blocks(
        &session_key.expose_secret()[16..32],
        &prev,
        block.expose_secret_mut(),
    );
    aes_block = AesBlock::from(*block.expose_secret());
    cipher.encrypt_block(&mut aes_block);
    enc_block.expose_secret_mut()[32..48].copy_from_slice(aes_block.as_ref());
    hmac.update(&enc_block.expose_secret()[32..48]);

    Ok(())
}
