//! src/core/decryptor/decrypt.rs
//! Aescrypt decryption — secure-gate v0.5.5+ perfection (2025)

use secure_gate::secure;

use crate::decryptor::read::{
    consume_all_extensions, read_exact_span, read_file_version, read_kdf_iterations,
    read_reserved_modulo_byte,
};
use crate::decryptor::session::extract_session_data;
use crate::decryptor::stream::{decrypt_ciphertext_stream, StreamConfig};

use crate::aliases::{Aes256Key, Iv16, Password};
use crate::error::AescryptError;
use crate::{derive_secure_ackdf_key, derive_secure_pbkdf2_key};
use std::io::{Read, Write};

/// Decrypt an Aescrypt file (v0–v3) — zero secret exposure, maximum security
#[inline(always)]
pub fn decrypt<R: Read, W: Write>(
    password: Password,
    mut input_reader: R,
    mut output_writer: W,
) -> Result<(), AescryptError> {
    let file_version = read_file_version(&mut input_reader)?;
    let reserved_modulo = read_reserved_modulo_byte(&mut input_reader)?;
    consume_all_extensions(&mut input_reader, file_version)?;

    let kdf_iterations = read_kdf_iterations(&mut input_reader, file_version)?;

    // Public IV — secure from the start
    let public_iv: Iv16 = Iv16::from(read_exact_span(&mut input_reader)?);

    // Setup key — secure buffer from birth
    let mut setup_key = secure!(Aes256Key, [0u8; 32].into());

    if file_version <= 2 {
        derive_secure_ackdf_key(&password, &public_iv, &mut setup_key)?;
    } else {
        derive_secure_pbkdf2_key(&password, &public_iv, kdf_iterations, &mut setup_key)?;
    }

    // Session key/IV — secure buffers from birth
    let mut session_iv = Iv16::new([0u8; 16]);
    let mut session_key = Aes256Key::new([0u8; 32]);

    // ← THIS WAS MISSING THE `?`
    extract_session_data(
        &mut input_reader,
        file_version,
        &public_iv,
        &setup_key,
        &mut session_iv,
        &mut session_key,
    )?;

    let stream_config = match file_version {
        0 => StreamConfig::V0 { reserved_modulo },
        1 => StreamConfig::V1,
        2 => StreamConfig::V2,
        3 => StreamConfig::V3,
        _ => unreachable!("file_version validated in read_file_version"),
    };

    decrypt_ciphertext_stream(
        &mut input_reader,
        &mut output_writer,
        &session_iv,
        &session_key,
        stream_config,
    )?;

    Ok(())
}
