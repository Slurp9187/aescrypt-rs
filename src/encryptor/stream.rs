//! src/encryptor/stream.rs
//! AES Crypt v3 streaming encryption — 100% secure-gate, all tests pass

use crate::aliases::{Aes256Key, Iv16, PlainTextBlock16};
use crate::error::AescryptError;
use crate::utils::xor_blocks;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes256Enc, Block as AesBlock};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{Read, Write};

type HmacSha256 = Hmac<Sha256>;

#[inline(always)]
pub fn encrypt_stream<R, W>(
    mut source: R,
    mut destination: W,
    session_iv: &Iv16,
    session_key: &Aes256Key,
) -> Result<(), AescryptError>
where
    R: Read,
    W: Write,
{
    let cipher = Aes256Enc::new(session_key.expose_secret().into());
    let mut hmac = <HmacSha256 as Mac>::new_from_slice(session_key.expose_secret())
        .expect("session_key is 32 bytes");

    // previous ciphertext block – must stay a real [u8; 16]
    let mut prev_block: [u8; 16] = *session_iv.expose_secret();

    let mut plaintext_block = PlainTextBlock16::new([0u8; 16]);

    loop {
        let n = source.read(plaintext_block.expose_secret_mut())?;

        let is_final = n < 16;
        if is_final {
            let pad = (16 - n) as u8;
            plaintext_block.expose_secret_mut()[n..].fill(pad);
        }

        // XOR with previous ciphertext
        let mut xor_output = PlainTextBlock16::new([0u8; 16]);
        xor_blocks(
            plaintext_block.expose_secret(),
            &prev_block,
            xor_output.expose_secret_mut(),
        );

        // Encrypt
        let mut aes_block = AesBlock::from(*xor_output.expose_secret());
        cipher.encrypt_block(&mut aes_block);
        let ct_slice = aes_block.as_ref(); // &[u8]
        let mut ct_array = [0u8; 16];
        ct_array.copy_from_slice(ct_slice); // ← convert to owned array

        // HMAC + write ciphertext
        hmac.update(&ct_array);
        destination.write_all(&ct_array)?;

        // Update previous block for next iteration
        prev_block = ct_array; // ← now both sides are [u8; 16]

        if is_final {
            break;
        }
    }

    destination.write_all(hmac.finalize().into_bytes().as_slice())?;
    Ok(())
}
