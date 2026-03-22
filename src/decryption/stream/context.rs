//! # Decryption Context
//!
//! This module provides the decryption context for streaming decryption operations.
//! The context manages a 64-byte ring buffer that enables constant-memory decryption
//! of arbitrarily large files.

use crate::aliases::HmacSha256;
use crate::aliases::{Block16, EncryptedSessionBlock48, Iv16, RingBuffer64};
use crate::error::AescryptError;
use crate::utilities::xor_blocks; // Note: This is crate::utilities (existing), not stream/utilities
use aes::cipher::BlockDecrypt;
use aes::{Aes256Dec, Block as AesBlock};
use hmac::Mac;
use secure_gate::{RevealSecret, RevealSecretMut};
use std::io::{Read, Write};

/// Decryption context for streaming CBC decryption.
///
/// This struct manages a 64-byte ring buffer that holds ciphertext blocks during
/// the decryption process. The ring buffer allows for constant-memory decryption
/// by reusing a fixed-size buffer regardless of file size.
///
/// ## Ring Buffer Layout
///
/// The 64-byte ring buffer is divided into four 16-byte blocks:
/// - Block 0 (indices 0-15): Previous ciphertext block for CBC chaining
/// - Block 1 (indices 16-31): Current ciphertext block being decrypted
/// - Block 2 (indices 32-47): Next ciphertext block (if available)
/// - Block 3 (indices 48-63): Future ciphertext block (if available)
///
/// ## Indices
///
/// - `tail_index`: Points to the start of the previous block (for CBC chaining)
/// - `current_index`: Points to the start of the current block being decrypted
/// - `head_index`: Points to where new data will be written
pub struct DecryptionContext {
    pub ring_buffer: RingBuffer64,
    pub tail_index: usize,
    pub current_index: usize,
    pub head_index: usize,
    pub plaintext_block: Block16,
    pub need_write_plaintext: bool,
}

impl DecryptionContext {
    /// Create a new decryption context initialized with the given IV.
    ///
    /// The IV is placed at the start of the ring buffer (indices 0-15) to serve
    /// as the initial previous block for CBC chaining.
    ///
    /// # Arguments
    ///
    /// * `iv` - The initialization vector for CBC mode
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
        iv.with_secret(|iv_bytes| {
            this.ring_buffer
                .with_secret_mut(|rb| rb[0..16].copy_from_slice(iv_bytes))
        });
        this
    }

    /// Perform CBC decryption loop using the ring buffer.
    ///
    /// This method processes ciphertext blocks in a streaming fashion, decrypting
    /// them one at a time and writing the plaintext to the output. The ring buffer
    /// is used to maintain the previous ciphertext block for CBC chaining.
    ///
    /// # Arguments
    ///
    /// * `input` - Reader providing encrypted data
    /// * `output` - Writer receiving decrypted plaintext
    /// * `cipher` - AES-256 decryption initialized with the session key
    /// * `hmac` - HMAC instance that is updated with each ciphertext block
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if decryption completes successfully, or an error if
    /// I/O fails or the stream is malformed.
    ///
    /// # Errors
    ///
    /// Returns [`AescryptError::Io`] if an I/O error occurs during reading or writing.
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
        // Accumulate partial `read()` results until 48 bytes or EOF (same contract as encrypt_stream).
        let bytes_read = initial_buffer
            .with_secret_mut(|ib| -> Result<usize, std::io::Error> {
                let mut total = 0usize;
                while total < 48 {
                    match input.read(&mut ib[total..]) {
                        Ok(0) => break,
                        Ok(k) => total += k,
                        Err(e) => return Err(e),
                    }
                }
                Ok(total)
            })
            .map_err(AescryptError::Io)?;
        self.ring_buffer.with_secret_mut(|rb| {
            initial_buffer.with_secret(|ib| {
                rb[self.head_index..self.head_index + bytes_read]
                    .copy_from_slice(&ib[..bytes_read]);
            });
        });
        self.head_index += bytes_read;
        if bytes_read == 48 {
            loop {
                if self.need_write_plaintext {
                    self.plaintext_block
                        .with_secret(|pb| output.write_all(pb))?;
                }
                self.ring_buffer.with_secret(|rb| {
                    hmac.update(&rb[self.current_index..self.current_index + 16])
                });
                let mut block_bytes = Block16::new([0u8; 16]);
                block_bytes.with_secret_mut(|bb| {
                    self.ring_buffer.with_secret(|rb| {
                        bb.copy_from_slice(&rb[self.current_index..self.current_index + 16]);
                    });
                });
                let mut aes_block = block_bytes.with_secret(|bb| AesBlock::from(*bb));
                cipher.decrypt_block(&mut aes_block);
                self.ring_buffer.with_secret(|rb| {
                    self.plaintext_block.with_secret_mut(|pb| {
                        xor_blocks(
                            aes_block.as_ref(),
                            &rb[self.tail_index..self.tail_index + 16],
                            pb,
                        );
                    });
                });
                self.need_write_plaintext = true;
                self.tail_index = (self.tail_index + 16) % 64;
                self.current_index = (self.current_index + 16) % 64;
                if self.head_index == 64 {
                    self.head_index = 0;
                }
                let mut next_block = Block16::new([0u8; 16]);
                let n = next_block
                    .with_secret_mut(|nb| -> Result<usize, std::io::Error> {
                        let mut total = 0usize;
                        while total < 16 {
                            match input.read(&mut nb[total..]) {
                                Ok(0) => break,
                                Ok(k) => total += k,
                                Err(e) => return Err(e),
                            }
                        }
                        Ok(total)
                    })
                    .map_err(AescryptError::Io)?;
                if n < 16 {
                    self.ring_buffer.with_secret_mut(|rb| {
                        next_block.with_secret(|nb| {
                            rb[self.head_index..self.head_index + n].copy_from_slice(&nb[..n]);
                        });
                    });
                    self.head_index += n;
                    break;
                }
                self.ring_buffer.with_secret_mut(|rb| {
                    next_block.with_secret(|nb| {
                        rb[self.head_index..self.head_index + 16].copy_from_slice(nb);
                    });
                });
                self.head_index += 16;
            }
        }
        Ok(())
    }

    /// Advance the tail index to the next block in the ring buffer.
    ///
    /// This is called after processing a block to move the tail pointer forward,
    /// making room for new data and updating the previous block reference for
    /// the next CBC operation.
    #[inline(always)]
    pub fn advance_tail(&mut self) {
        self.tail_index = (self.tail_index + 16) % 64;
    }

    /// Calculate the number of bytes remaining in the ring buffer.
    ///
    /// This accounts for the circular nature of the ring buffer, returning
    /// the number of bytes between the tail and head indices.
    ///
    /// # Returns
    ///
    /// The number of bytes remaining in the ring buffer (0-64).
    #[inline(always)]
    pub fn remaining(&self) -> usize {
        if self.head_index >= self.tail_index {
            self.head_index - self.tail_index
        } else {
            64 - self.tail_index + self.head_index
        }
    }
}
