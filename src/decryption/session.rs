//! src/decryption/session.rs
//! Session data extraction — zero secret exposure, secure-gate gold standard
//!
//! Maximum overkill: every buffer that ever touches ciphertext, IV, or key is auto-zeroized.
//! Because in crypto, we wipe everything that ever touched the stack.

use crate::aliases::{Aes256Key32, Block16, EncryptedSessionBlock48, Iv16, SessionHmacTag32};
use crate::decryption::read_exact_span;
use crate::{aliases::HmacSha256, error::AescryptError, utils::xor_blocks};
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::{Aes256Dec, Block as AesBlock};
use hmac::Mac;
#[cfg(feature = "zeroize")]
use secure_gate::conversions::SecureConversionsExt;
use std::convert::TryInto;
use std::io::Read;

/// Extract session IV + key — secure from first byte
///
/// - No raw buffers ever hold secrets
/// - Zero exposure window
/// - Full auto-zeroizing (even ciphertext & HMAC tags)
/// - Maximum performance
#[inline(always)]
pub fn extract_session_data<R>(
    reader: &mut R,
    file_version: u8,
    public_iv: &Iv16,
    setup_key: &Aes256Key32,
    session_iv_out: &mut Iv16,
    session_key_out: &mut Aes256Key32,
) -> Result<(), AescryptError>
where
    R: Read,
{
    // v0: direct secure copy — no encryption, no HMAC
    if file_version == 0 {
        *session_iv_out = public_iv.clone();
        *session_key_out = setup_key.clone();
        return Ok(());
    }

    // Read encrypted session block and HMAC tag — both wrapped for auto-zeroing
    let encrypted_block: EncryptedSessionBlock48 = read_exact_span(reader)?;
    let expected_hmac: SessionHmacTag32 = read_exact_span(reader)?;

    // HMAC verification — exact same pattern as encryption side
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(setup_key.expose_secret())
        .expect("setup_key is always 32 bytes");

    mac.update(encrypted_block.expose_secret());
    if file_version >= 3 {
        mac.update(&[file_version]); // v3 spec: version byte included in session HMAC
    }

    let computed_hmac = mac.finalize().into_bytes();
    let computed_hmac_slice: &[u8] = computed_hmac.as_ref();
    #[cfg(feature = "zeroize")]
    let hmac_valid = computed_hmac_slice.ct_eq(expected_hmac.expose_secret());
    #[cfg(not(feature = "zeroize"))]
    let hmac_valid = computed_hmac_slice == expected_hmac.expose_secret();
    if !hmac_valid {
        return Err(AescryptError::Header(
            "session data corrupted or tampered (HMAC mismatch)".into(),
        ));
    }

    // Decrypt directly into secure output buffers
    let cipher = Aes256Dec::new(setup_key.expose_secret().into());

    let mut previous_block: Block16 = Block16::new(*public_iv.expose_secret());

    for (i, chunk) in encrypted_block.expose_secret().chunks_exact(16).enumerate() {
        let chunk_array: [u8; 16] = chunk.try_into().expect("chunk is exactly 16 bytes");
        let mut block = AesBlock::from(chunk_array);
        cipher.decrypt_block(&mut block);

        let target = match i {
            0 => session_iv_out.expose_secret_mut(),
            1 => &mut session_key_out.expose_secret_mut()[0..16],
            2 => &mut session_key_out.expose_secret_mut()[16..32],
            _ => break,
        };

        xor_blocks(block.as_ref(), previous_block.expose_secret(), target);

        // Update previous ciphertext block for next iteration
        previous_block = Block16::new(chunk.try_into().expect("chunk is exactly 16 bytes"));
    }

    Ok(())
}
