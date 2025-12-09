//! src/encryption/stream.rs
//! AES Crypt v3 streaming encryption — secure-gate protection, all tests pass

use crate::aliases::{Aes256Key32, Block16, Iv16};
use crate::error::AescryptError;
use crate::utils::xor_blocks;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes256Enc, Block as AesBlock};
use crate::aliases::HmacSha256;
use hmac::Mac;
use std::convert::TryFrom;
use std::io::{Read, Write};

#[inline(always)]
pub fn encrypt_stream<R, W>(
    mut source: R,
    mut destination: W,
    session_iv: &Iv16,
    session_key: &Aes256Key32,
) -> Result<(), AescryptError>
where
    R: Read,
    W: Write,
{
    let cipher = Aes256Enc::new(session_key.expose_secret().into());
    let mut hmac = <HmacSha256 as Mac>::new_from_slice(session_key.expose_secret())
        .expect("session_key is 32 bytes");

    // previous ciphertext block — secure from birth
    let mut prev_block: Block16 = Block16::new(*session_iv.expose_secret());

    let mut plaintext_block = Block16::new([0u8; 16]);

    loop {
        let n = source.read(plaintext_block.expose_secret_mut())?;

        let is_final = n < 16;
        if is_final {
            let pad = (16 - n) as u8;
            plaintext_block.expose_secret_mut()[n..].fill(pad);
        }

        // XOR with previous ciphertext
        let mut xor_output = Block16::new([0u8; 16]);
        xor_blocks(
            plaintext_block.expose_secret(),
            prev_block.expose_secret(),
            xor_output.expose_secret_mut(),
        );

        // Encrypt
        let mut aes_block = AesBlock::from(*xor_output.expose_secret());
        cipher.encrypt_block(&mut aes_block);
        let ct_slice = aes_block.as_ref(); // &[u8]

        // HMAC + write ciphertext
        hmac.update(ct_slice);
        destination.write_all(ct_slice)?;

        // Update previous block for next iteration
        prev_block = Block16::new(*<&[u8; 16]>::try_from(ct_slice).expect("always 16 bytes"));

        if is_final {
            break;
        }
    }

    destination.write_all(hmac.finalize().into_bytes().as_ref())?;
    Ok(())
}
