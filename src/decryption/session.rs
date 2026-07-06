//! src/decryption/session.rs
//! Session-block recovery for the AES Crypt v0–v3 read path.
//!
//! Every buffer that touches ciphertext, IV, or key material is wrapped in a
//! [`secure-gate`] auto-zeroizing alias — including the ciphertext and HMAC
//! tag read from disk — so no plaintext key bytes survive the call frame.
//!
//! [`secure-gate`]: https://github.com/Slurp9187/secure-gate

use crate::aliases::{Aes256Key32, Block16, EncryptedSessionBlock48, Iv16, SessionHmacTag32};
use crate::decryption::read_exact_span;
use crate::{aliases::HmacSha256, error::AescryptError, utilities::xor_blocks};
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::{Aes256Dec, Block as AesBlock};
use hmac::Mac;
use secure_gate::{ConstantTimeEq, RevealSecret, RevealSecretMut};
use std::io::Read;

/// Recovers the session IV and session key from the file header into the
/// caller's pre-allocated [`secure-gate`] buffers.
///
/// The behavior depends on `file_version`:
///
/// - **v0**: the setup key *is* the session key; `session_iv_out` is set to
///   `public_iv`, `session_key_out` to `setup_key`. No HMAC, no decryption.
/// - **v1/v2**: reads a 48-byte AES-256-CBC encrypted session block plus a
///   32-byte HMAC-SHA256 tag, verifies the tag with constant-time equality,
///   then CBC-decrypts the block under `setup_key` chained off `public_iv`.
/// - **v3**: same as v1/v2, but the version byte (`0x03`) is folded into the
///   session HMAC after the encrypted block, matching the v3 spec.
///
/// # Errors
///
/// - [`AescryptError::Io`] — reader error while consuming the encrypted block
///   or HMAC tag.
/// - [`AescryptError::Header`] — session HMAC mismatch
///   (`"session data corrupted or tampered (HMAC mismatch)"`).
///
/// # Panics
///
/// Never panics on valid input. The internal `expect` calls on `setup_key`
/// (`"setup_key is always 32 bytes"`) and on `computed_hmac`
/// (`"computed hmac is 32 bytes"`) are structural invariants of
/// [`Aes256Key32`](crate::aliases::Aes256Key32) and HMAC-SHA256.
///
/// # Security
///
/// - HMAC verification uses [`secure-gate`]'s `ConstantTimeEq`.
/// - Encrypted session block, HMAC tag, and CBC working buffers are all
///   [`secure-gate`] aliases that zeroize on drop.
/// - For `file_version == 0`, `session_key_out` is overwritten with a copy of
///   `setup_key`; both buffers continue to zeroize independently.
///
/// [`secure-gate`]: https://github.com/Slurp9187/secure-gate
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

            // Decrypt a working copy in place inside a secure-gate wrapper
            // (borrowed as a GenericArray): the recovered session IV/key
            // material never exists outside it, and the wrapper zeroizes on
            // drop. `chunk_array` itself keeps the (public) ciphertext for
            // CBC chaining below.
            let mut work = Block16::from(chunk_array);
            work.with_secret_mut(|b| cipher.decrypt_block(AesBlock::from_mut_slice(b)));

            let xor_pb = previous_block.with_secret(|pb| *pb);
            work.with_secret(|b| match i {
                0 => session_iv_out.with_secret_mut(|siv| xor_blocks(b, &xor_pb, siv)),
                1 => session_key_out.with_secret_mut(|sk| xor_blocks(b, &xor_pb, &mut sk[0..16])),
                2 => session_key_out.with_secret_mut(|sk| xor_blocks(b, &xor_pb, &mut sk[16..32])),
                _ => {}
            });

            // Update previous ciphertext block for next iteration
            previous_block = Block16::from(chunk_array);
        }
    });

    Ok(())
}
