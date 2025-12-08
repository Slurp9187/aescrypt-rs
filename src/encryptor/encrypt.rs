//! src/core/encryptor/encrypt.rs
//! Aescrypt encryption — secure-gate gold standard
//! Zero secret exposure, zero-cost, auto-zeroizing

use crate::aliases::{Aes256Key32, EncryptedSessionBlock48, PasswordString};
use crate::aliases::{HmacSha256, RandomAes256Key32, RandomIv16};
use crate::consts::{AESCRYPT_LATEST_VERSION, PBKDF2_MAX_ITER, PBKDF2_MIN_ITER};
use crate::encryptor::derive_setup_key;
use crate::encryptor::encrypt_session_block;
use crate::encryptor::stream::encrypt_stream;
use crate::encryptor::write::{
    write_extensions, write_header, write_hmac, write_iterations, write_octets, write_public_iv,
};
use crate::error::AescryptError;
use aes::cipher::KeyInit;
use aes::Aes256Enc;
use hmac::Mac;
use secure_gate::Fixed;
// use secure_gate::DynamicRng;
use std::io::{Read, Write};

/// Encrypt an Aescrypt file (v3+) — zero secret exposure, maximum security
#[inline(always)]
pub fn encrypt<R, W>(
    mut input: R,
    mut output: W,
    password: &PasswordString,
    kdf_iterations: u32,
) -> Result<(), AescryptError>
where
    R: Read,
    W: Write,
{
    // Validation
    if password.expose_secret().is_empty() {
        return Err(AescryptError::Header("empty password".into()));
    }

    // Fixed: parentheses around range + proper contains call
    if !(PBKDF2_MIN_ITER..=PBKDF2_MAX_ITER).contains(&kdf_iterations) {
        return Err(AescryptError::Header("invalid KDF iterations".into()));
    }

    write_header(&mut output, AESCRYPT_LATEST_VERSION)?;
    write_extensions(&mut output, AESCRYPT_LATEST_VERSION, None)?;

    // Generate secure random values — wrapped from birth
    let public_iv = Fixed::from(*RandomIv16::generate().expose_secret());
    let session_iv = Fixed::from(*RandomIv16::generate().expose_secret());
    let session_key = Fixed::from(*RandomAes256Key32::generate().expose_secret());

    write_iterations(&mut output, kdf_iterations, AESCRYPT_LATEST_VERSION)?;
    write_public_iv(&mut output, &public_iv)?;

    // Derive setup key directly into secure buffer — zero exposure
    let mut setup_key = Aes256Key32::new([0u8; 32]);
    derive_setup_key(password, &public_iv, kdf_iterations, &mut setup_key)?;

    // Create cipher and HMAC from secure key
    let cipher = Aes256Enc::new(setup_key.expose_secret().into());

    // Fixed: unambiguous HMAC init
    let mut hmac = <HmacSha256 as Mac>::new_from_slice(setup_key.expose_secret())
        .expect("setup_key is 32 bytes — valid HMAC key");

    // Encrypt session block
    let mut enc_block = EncryptedSessionBlock48::new([0u8; 48]);
    encrypt_session_block(
        &cipher,
        &session_iv,
        &session_key,
        &public_iv,
        &mut enc_block,
        &mut hmac,
    )?;

    // Include version byte in HMAC (v3+)
    hmac.update(&[AESCRYPT_LATEST_VERSION]);

    write_octets(&mut output, enc_block.expose_secret())?;
    write_hmac(&mut output, hmac)?; // hmac moved here — correct

    // Final stream encryption
    encrypt_stream(&mut input, &mut output, &session_iv, &session_key)?;

    Ok(())
}
