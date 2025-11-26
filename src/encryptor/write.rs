//! src/encryptor/write.rs
//! AES Crypt write helpers — FULL secure-gate v0.5.5+ protection

use crate::aliases::{Aes256Key, Iv16, Password, PlainTextBlock16, EncryptedSessionBlock48};
use crate::consts::PBKDF2_MAX_ITER;
use crate::derive_secure_pbkdf2_key;
use crate::error::AescryptError;
use crate::utils::xor_blocks;
use crate::HmacSha256;
use aes::cipher::BlockEncrypt;
use aes::{Aes256Enc, Block as AesBlock};
use hmac::Mac;
use std::io::Write;

#[inline]
pub fn write_octets<W: Write>(writer: &mut W, data: &[u8]) -> Result<(), AescryptError> {
    writer.write_all(data).map_err(AescryptError::Io)
}

#[inline]
pub fn write_header<W: Write>(writer: &mut W, version: u8) -> Result<(), AescryptError> {
    if version < 3 {
        return Err(AescryptError::UnsupportedVersion(version));
    }
    write_octets(writer, &[b'A', b'E', b'S', version, 0x00])
}

#[inline]
pub fn write_extensions<W: Write>(
    writer: &mut W,
    version: u8,
    extensions: Option<&[u8]>,
) -> Result<(), AescryptError> {
    if version < 3 {
        return Err(AescryptError::UnsupportedVersion(version));
    }
    let data = extensions.unwrap_or(&[0x00, 0x00]);
    write_octets(writer, data)
}

#[inline]
pub fn write_iterations<W: Write>(
    writer: &mut W,
    iterations: u32,
    version: u8,
) -> Result<(), AescryptError> {
    if version < 3 {
        return Err(AescryptError::UnsupportedVersion(version));
    }
    if iterations == 0 || iterations > PBKDF2_MAX_ITER {
        return Err(AescryptError::Header("invalid KDF iterations".into()));
    }
    write_octets(writer, &iterations.to_be_bytes())
}

#[inline]
pub fn write_public_iv<W: Write>(writer: &mut W, iv: &Iv16) -> Result<(), AescryptError> {
    write_octets(writer, iv.expose_secret())
}

#[inline]
pub fn derive_setup_key(
    password: &Password,
    public_iv: &Iv16,
    iterations: u32,
    out_key: &mut Aes256Key,
) -> Result<(), AescryptError> {
    derive_secure_pbkdf2_key(password, public_iv, iterations, out_key)
}

#[inline]
pub fn encrypt_session_block(
    cipher: &Aes256Enc,
    session_iv: &Iv16,
    session_key: &Aes256Key,
    public_iv: &Iv16,
    enc_block: &mut EncryptedSessionBlock48,
    hmac: &mut HmacSha256,
) -> Result<(), AescryptError> {
    let mut prev = *public_iv.expose_secret();
    let mut block = PlainTextBlock16::new([0u8; 16]);

    // Block 1: session IV
    xor_blocks(session_iv.expose_secret(), &prev, block.expose_secret_mut());
    let mut aes_block = AesBlock::from(*block.expose_secret());
    cipher.encrypt_block(&mut aes_block);
    enc_block.expose_secret_mut()[0..16].copy_from_slice(aes_block.as_ref());
    hmac.update(&enc_block.expose_secret()[0..16]);
    prev.copy_from_slice(&enc_block.expose_secret()[0..16]);

    // Block 2: first half of session key
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

    // Block 3: second half of session key
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

#[inline]
pub fn write_hmac<W: Write>(writer: &mut W, hmac: HmacSha256) -> Result<(), AescryptError> {
    write_octets(writer, hmac.finalize().into_bytes().as_slice())
}
