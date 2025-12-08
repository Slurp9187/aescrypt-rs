//! src/decryptor/stream/versions.rs
//! Final version — matches original working code exactly
//! All tests pass, zero warnings, secure-gate everywhere

use crate::aliases::{Aes256Key32, Iv16};
use crate::decryptor::stream::context::DecryptionContext;
use crate::decryptor::stream::trailer::{
    extract_hmac_scattered, extract_hmac_simple, write_final_modulo, write_final_pkcs7,
};
use crate::error::AescryptError;
use aes::cipher::KeyInit;
use aes::Aes256Dec;
use crate::aliases::HmacSha256;
use hmac::Mac;
use std::io::{Read, Write};

#[derive(Clone, Copy)]
pub enum StreamConfig {
    V0 { reserved_modulo: u8 },
    V1,
    V2,
    V3,
}

#[inline(always)]
pub fn decrypt_ciphertext_stream<R, W>(
    mut input_reader: R,
    mut output_writer: W,
    initial_vector: &Iv16,
    encryption_key: &Aes256Key32,
    config: StreamConfig,
) -> Result<(), AescryptError>
where
    R: Read,
    W: Write,
{
    let key_bytes = encryption_key.expose_secret();
    let cipher = Aes256Dec::new(key_bytes.into());

    // This is the exact same construction used in encrypt_stream
    let mut hmac = <HmacSha256 as Mac>::new_from_slice(key_bytes)
        .expect("encryption_key is always 32 bytes — valid HMAC key");

    let mut ctx = DecryptionContext::new_with_iv(initial_vector);
    ctx.decrypt_cbc_loop(&mut input_reader, &mut output_writer, &cipher, &mut hmac)?;

    ctx.advance_tail();
    let remaining = ctx.remaining();

    match config {
        StreamConfig::V0 { reserved_modulo } => {
            if remaining != 32 {
                return Err(AescryptError::Header(
                    "v0: expected 32-byte HMAC trailer".into(),
                ));
            }

            let expected_hmac = extract_hmac_simple(&ctx);

            if &*hmac.finalize().into_bytes() != expected_hmac.expose_secret().as_ref() {
                return Err(AescryptError::Header("HMAC verification failed".into()));
            }

            write_final_modulo(&ctx, &mut output_writer, reserved_modulo)?;
        }

        StreamConfig::V1 | StreamConfig::V2 => {
            if remaining != 33 {
                return Err(AescryptError::Header(
                    "v1/v2: expected 33-byte trailer".into(),
                ));
            }

            let (expected_hmac, modulo_byte) = extract_hmac_scattered(&ctx);

            if &*hmac.finalize().into_bytes() != expected_hmac.expose_secret().as_ref() {
                return Err(AescryptError::Header("HMAC verification failed".into()));
            }

            write_final_modulo(&ctx, &mut output_writer, modulo_byte)?;
        }

        StreamConfig::V3 => {
            if remaining != 32 {
                return Err(AescryptError::Header(
                    "v3: expected 32-byte HMAC trailer".into(),
                ));
            }

            let expected_hmac = extract_hmac_simple(&ctx);

            if &*hmac.finalize().into_bytes() != expected_hmac.expose_secret().as_ref() {
                return Err(AescryptError::Header("HMAC verification failed".into()));
            }

            write_final_pkcs7(&ctx, &mut output_writer)?;
        }
    }

    Ok(())
}
