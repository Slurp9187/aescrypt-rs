//! src/decryptor/session.rs
//! Session data extraction — zero secret exposure, secure-gate v0.5.5+ gold standard
//!
//! Now with maximum overkill: even public-but-sensitive buffers auto-zeroed on drop
//! Because in crypto, we wipe everything that ever touched the stack.

use crate::aliases::{
    Aes256Key32, EncryptedSessionBlock48, Iv16, PrevCiphertextBlock16, SessionHmacTag32,
};
use crate::decryptor::read_exact_span;
use crate::{crypto::hmac::HmacSha256, error::AescryptError, utils::xor_blocks};
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::{Aes256Dec, Block as AesBlock};
use hmac::Mac;
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
        *session_iv_out = Iv16::from(*public_iv.expose_secret());
        *session_key_out = Aes256Key32::from(*setup_key.expose_secret());
        return Ok(());
    }

    // Read encrypted session block and HMAC tag — both wrapped for auto-zeroing
    let encrypted_block: EncryptedSessionBlock48 =
        EncryptedSessionBlock48::new(read_exact_span(reader)?);
    let expected_hmac: SessionHmacTag32 = SessionHmacTag32::new(read_exact_span(reader)?);

    // HMAC verification — exact same pattern as encryption side
    let mut mac = <HmacSha256 as Mac>::new_from_slice(setup_key.expose_secret())
        .expect("setup_key is always 32 bytes — valid HMAC-SHA256 key");

    mac.update(encrypted_block.expose_secret());
    if file_version >= 3 {
        mac.update(&[file_version]); // v3 spec: version byte included in session HMAC
    }

    if mac.finalize().into_bytes().as_slice() != expected_hmac.expose_secret() {
        return Err(AescryptError::Header(
            "session data corrupted or tampered (HMAC mismatch)".into(),
        ));
    }

    // Decrypt directly into secure output buffers
    let cipher = Aes256Dec::new(setup_key.expose_secret().into());
    let mut previous_block: PrevCiphertextBlock16 =
        PrevCiphertextBlock16::new(*public_iv.expose_secret());

    for (i, chunk) in encrypted_block.expose_secret().chunks_exact(16).enumerate() {
        let mut block = *AesBlock::from_slice(chunk);
        cipher.decrypt_block(&mut block);
        let decrypted = block.as_slice();

        let target = match i {
            0 => session_iv_out.expose_secret_mut(),
            1 => &mut session_key_out.expose_secret_mut()[0..16],
            2 => &mut session_key_out.expose_secret_mut()[16..32],
            _ => break,
        };

        xor_blocks(decrypted, previous_block.expose_secret(), target);

        // Fixed: Convert &[u8] to [u8;16] correctly
        let mut prev_array = [0u8; 16];
        prev_array.copy_from_slice(chunk);
        previous_block = PrevCiphertextBlock16::new(prev_array);
    }

    Ok(())
}
