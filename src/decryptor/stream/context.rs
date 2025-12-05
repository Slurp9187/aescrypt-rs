use crate::aliases::{EncryptedSessionBlock48, Iv16, Block16, RingBuffer64};
use crate::error::AescryptError;
use crate::utils::xor_blocks; // Note: This is crate::utils (existing), not stream/utils
use aes::cipher::BlockDecrypt;
use aes::{Aes256Dec, Block as AesBlock};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{Read, Write};

type HmacSha256 = Hmac<Sha256>;

pub struct DecryptionContext {
    pub ring_buffer: RingBuffer64,
    pub tail_index: usize,
    pub current_index: usize,
    pub head_index: usize,
    pub plaintext_block: Block16,
    pub need_write_plaintext: bool,
}

impl DecryptionContext {
    #[inline(always)]
    pub fn new_with_iv(iv: &Iv16) -> Self {
        let mut this = Self {
            ring_buffer: RingBuffer64::new([0u8; 64]),
            tail_index: 0,
            current_index: 16,
            head_index: 16,
            plaintext_block: Block16::new([0u8; 16]),
            need_write_plaintext: false,
        };
        this.ring_buffer.expose_secret_mut()[0..16].copy_from_slice(iv.expose_secret());
        this
    }

    #[inline(always)]
    pub fn decrypt_cbc_loop<R, W>(
        &mut self,
        input: &mut R,
        output: &mut W,
        cipher: &Aes256Dec,
        hmac: &mut HmacSha256,
    ) -> Result<(), AescryptError>
    where
        R: Read,
        W: Write,
    {
        let mut initial_buffer = EncryptedSessionBlock48::new([0u8; 48]);
        let bytes_read = input.read(initial_buffer.expose_secret_mut())?;
        self.ring_buffer.expose_secret_mut()[self.head_index..self.head_index + bytes_read]
            .copy_from_slice(&initial_buffer.expose_secret()[..bytes_read]);
        self.head_index += bytes_read;
        if bytes_read == 48 {
            loop {
                if self.need_write_plaintext {
                    output.write_all(self.plaintext_block.expose_secret())?;
                }
                hmac.update(
                    &self.ring_buffer.expose_secret()[self.current_index..self.current_index + 16],
                );
                let mut block_bytes = [0u8; 16];
                block_bytes.copy_from_slice(
                    &self.ring_buffer.expose_secret()[self.current_index..self.current_index + 16],
                );
                let mut aes_block = AesBlock::from(block_bytes);
                cipher.decrypt_block(&mut aes_block);
                xor_blocks(
                    aes_block.as_slice(),
                    &self.ring_buffer.expose_secret()[self.tail_index..self.tail_index + 16],
                    self.plaintext_block.expose_secret_mut(),
                );
                self.need_write_plaintext = true;
                self.tail_index = (self.tail_index + 16) % 64;
                self.current_index = (self.current_index + 16) % 64;
                if self.head_index == 64 {
                    self.head_index = 0;
                }
                let mut next_block = [0u8; 16];
                let n = input.read(&mut next_block[..])?;
                if n < 16 {
                    self.ring_buffer.expose_secret_mut()[self.head_index..self.head_index + n]
                        .copy_from_slice(&next_block[..n]);
                    self.head_index += n;
                    break;
                }
                self.ring_buffer.expose_secret_mut()[self.head_index..self.head_index + 16]
                    .copy_from_slice(&next_block[..]);
                self.head_index += 16;
            }
        }
        Ok(())
    }

    #[inline(always)]
    pub fn advance_tail(&mut self) {
        self.tail_index = (self.tail_index + 16) % 64;
    }

    #[inline(always)]
    pub fn remaining(&self) -> usize {
        if self.head_index >= self.tail_index {
            self.head_index - self.tail_index
        } else {
            64 - self.tail_index + self.head_index
        }
    }
}
