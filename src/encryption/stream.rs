// src/encryption/stream.rs

//! AES Crypt v3 streaming encryption — secure-gate protection, all tests pass

use crate::aliases::HmacSha256;
use crate::aliases::{Aes256Key32, Block16, Iv16};
use crate::error::AescryptError;
use crate::utilities::xor_blocks;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes256Enc, Block as AesBlock};
use hmac::Mac;
use secure_gate::{RevealSecret, RevealSecretMut};
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
    let cipher = session_key.with_secret(|sk| Aes256Enc::new(sk.into()));
    let mut hmac = session_key.with_secret(|sk| <HmacSha256 as Mac>::new_from_slice(sk).unwrap());

    // previous ciphertext block — secure from birth
    let mut prev_block = session_iv.with_secret(|siv| Block16::new(*siv));

    let mut plaintext_block = Block16::new([0u8; 16]);

    loop {
        // Read up to 16 bytes, accumulating partial `read()` results until the buffer is full
        // or the source returns 0 (EOF). A single `read()` may return fewer than requested even
        // when more data exist (sockets, pipes); treating that as EOF would silently truncate.
        let (n, is_final) = plaintext_block
            .with_secret_mut(|pb| -> Result<(usize, bool), std::io::Error> {
                let mut bytes = 0usize;
                while bytes < 16 {
                    match source.read(&mut pb[bytes..]) {
                        Ok(0) => return Ok((bytes, true)),
                        Ok(k) => bytes += k,
                        Err(e) => return Err(e),
                    }
                }
                Ok((bytes, false))
            })
            .map_err(AescryptError::Io)?;

        if is_final {
            let pad = (16 - n) as u8;
            plaintext_block.with_secret_mut(|pb| pb[n..].fill(pad));
        }

        // XOR with previous ciphertext
        let mut xor_output = Block16::new([0u8; 16]);
        plaintext_block.with_secret(|pb| {
            prev_block
                .with_secret(|pb_prev| xor_output.with_secret_mut(|xo| xor_blocks(pb, pb_prev, xo)))
        });

        // Encrypt
        let mut aes_block = xor_output.with_secret(|xo| AesBlock::from(*xo));
        cipher.encrypt_block(&mut aes_block);
        let ct_slice = aes_block.as_ref(); // &[u8]

        // HMAC + write ciphertext
        hmac.update(ct_slice);
        destination.write_all(ct_slice)?;

        // Update previous block for next iteration
        prev_block = Block16::new(ct_slice.try_into().unwrap());

        if is_final {
            break;
        }
    }

    destination.write_all(hmac.finalize().into_bytes().as_ref())?;
    Ok(())
}
