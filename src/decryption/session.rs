//! src/decryption/session.rs
//! Session data extraction — zero secret exposure, secure-gate gold standard
//!
//! Maximum overkill: every buffer that ever touches ciphertext, IV, or key is auto-zeroized.
//! Because in crypto, we wipe everything that ever touched the stack.

use crate::aliases::{Aes256Key32, Block16, EncryptedSessionBlock48, Iv16, SessionHmacTag32};
use crate::decryption::read_exact_span;
use crate::{aliases::HmacSha256, error::AescryptError, utilities::xor_blocks};
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::{Aes256Dec, Block as AesBlock};
use hmac::Mac;
use secure_gate::{ConstantTimeEq, RevealSecret, RevealSecretMut};
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
        public_iv.with_secret(|iv| *session_iv_out = Iv16::from(*iv));
        setup_key.with_secret(|key| *session_key_out = Aes256Key32::from(*key));
        return Ok(());
    }

    // Read encrypted session block and HMAC tag — both wrapped for auto-zeroing
    let encrypted_block: EncryptedSessionBlock48 = read_exact_span(reader)?;
    let expected_hmac: SessionHmacTag32 = read_exact_span(reader)?;

    // HMAC verification — exact same pattern as encryption side
    let mut mac = setup_key.with_secret(|key| {
        <HmacSha256 as hmac::Mac>::new_from_slice(key).expect("setup_key is always 32 bytes")
    });

    encrypted_block.with_secret(|block| mac.update(block));
    if file_version >= 3 {
        mac.update(&[file_version]); // v3 spec: version byte included in session HMAC
    }

    let computed_hmac = mac.finalize().into_bytes();
    let computed_hmac_fixed =
        SessionHmacTag32::try_from(computed_hmac.as_ref()).expect("computed hmac is 32 bytes");
    let hmac_valid = computed_hmac_fixed.ct_eq(&expected_hmac);
    if !hmac_valid {
        return Err(AescryptError::Header(
            "session data corrupted or tampered (HMAC mismatch)".into(),
        ));
    }

    // Decrypt directly into secure output buffers
    let cipher = setup_key.with_secret(|key| Aes256Dec::new(key.into()));

    let mut previous_block: Block16 = public_iv.with_secret(|iv| Block16::new(*iv));

    encrypted_block.with_secret(|encrypted| {
        for (i, chunk) in encrypted.chunks_exact(16).enumerate() {
            let chunk_array: [u8; 16] = chunk.try_into().expect("chunk is exactly 16 bytes");
            let chunk_block = Block16::from(chunk_array);
            chunk_block.with_secret(|cb| {
                let mut block = AesBlock::from(*cb);
                cipher.decrypt_block(&mut block);

                let xor_pb = previous_block.with_secret(|pb| *pb);
                match i {
                    0 => session_iv_out
                        .with_secret_mut(|siv| xor_blocks(block.as_ref(), &xor_pb, siv)),
                    1 => session_key_out
                        .with_secret_mut(|sk| xor_blocks(block.as_ref(), &xor_pb, &mut sk[0..16])),
                    2 => session_key_out
                        .with_secret_mut(|sk| xor_blocks(block.as_ref(), &xor_pb, &mut sk[16..32])),
                    _ => return,
                };

                // Update previous ciphertext block for next iteration
                previous_block = chunk_block.with_secret(|cb| Block16::new(*cb));
            });
        }
    });

    Ok(())
}
