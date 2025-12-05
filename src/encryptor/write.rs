//! src/encryptor/write.rs
//! AES Crypt write helpers — FULL secure-gate v0.5.5+ protection

use crate::aliases::Aes256Key32;
use crate::aliases::HmacSha256;
use crate::aliases::Iv16;
use crate::aliases::PasswordString;
use crate::consts::PBKDF2_MAX_ITER;
use crate::derive_secure_pbkdf2_key;
use crate::error::AescryptError;
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
    password: &PasswordString,
    public_iv: &Iv16,
    iterations: u32,
    out_key: &mut Aes256Key32,
) -> Result<(), AescryptError> {
    derive_secure_pbkdf2_key(password, public_iv, iterations, out_key)
}

#[inline]
pub fn write_hmac<W: Write>(writer: &mut W, hmac: HmacSha256) -> Result<(), AescryptError> {
    write_octets(writer, hmac.finalize().into_bytes().as_slice())
}
