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
use secure_gate::conversions::SecureConversionsExt;
use std::io::{Read, Write};

/// Configuration for different AES Crypt stream formats.
///
/// This enum specifies the version-specific behavior for decryption, including
/// padding schemes, HMAC trailer layouts, and other format-specific details.
///
/// # Variants
///
/// ## `V0 { reserved_modulo: u8 }`
///
/// AES Crypt v0 format configuration.
///
/// - Uses legacy modulo padding (not PKCS#7)
/// - HMAC trailer is 32 bytes, stored contiguously
/// - The `reserved_modulo` byte is used to determine the final block length
/// - This is the original AES Crypt format from the early 2000s
///
/// ## `V1`
///
/// AES Crypt v1 format configuration.
///
/// - Uses legacy modulo padding (not PKCS#7)
/// - HMAC trailer is 32 bytes, stored with a scattered layout
/// - Includes a modulo byte for final block length determination
/// - Improved over v0 but still uses legacy padding
///
/// ## `V2`
///
/// AES Crypt v2 format configuration.
///
/// - Uses legacy modulo padding (not PKCS#7)
/// - HMAC trailer is 32 bytes, stored with a scattered layout
/// - Similar to v1 but with improved HMAC handling
///
/// ## `V3`
///
/// AES Crypt v3 format configuration (recommended).
///
/// - Uses PKCS#7 padding (standard, secure)
/// - HMAC trailer is 32 bytes, stored contiguously
/// - This is the only format produced by this library
/// - All encryption operations create v3 files
#[derive(Clone, Copy)]
pub enum StreamConfig {
    /// Version 0 configuration with reserved modulo byte.
    V0 { 
        /// Reserved modulo byte used for final block length determination.
        reserved_modulo: u8 
    },
    /// Version 1 configuration.
    V1,
    /// Version 2 configuration.
    V2,
    /// Version 3 configuration (recommended, uses PKCS#7 padding).
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

            let computed_hmac = hmac.finalize().into_bytes();
            let computed_hmac_slice: &[u8] = computed_hmac.as_ref();
            if !computed_hmac_slice.ct_eq(expected_hmac.expose_secret()) {
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

            let computed_hmac = hmac.finalize().into_bytes();
            let computed_hmac_slice: &[u8] = computed_hmac.as_ref();
            if !computed_hmac_slice.ct_eq(expected_hmac.expose_secret()) {
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

            let computed_hmac = hmac.finalize().into_bytes();
            let computed_hmac_slice: &[u8] = computed_hmac.as_ref();
            if !computed_hmac_slice.ct_eq(expected_hmac.expose_secret()) {
                return Err(AescryptError::Header("HMAC verification failed".into()));
            }

            write_final_pkcs7(&ctx, &mut output_writer)?;
        }
    }

    Ok(())
}
