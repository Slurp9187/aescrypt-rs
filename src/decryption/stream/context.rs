//! # Decryption Context
//!
//! This module provides the decryption context for streaming decryption operations.
//! The context manages a 64-byte ring buffer that enables constant-memory decryption
//! of arbitrarily large files.

use crate::aliases::HmacSha256;
use crate::aliases::{Block16, Iv16, RingBuffer64, SpanBuffer};
use crate::error::AescryptError;
use crate::utilities::{read_until_full, xor_blocks}; // Note: This is crate::utilities (existing), not stream/utilities
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
pub(crate) struct DecryptionContext {
    /// The four 16-byte blocks described above; zeroized on drop.
    pub(crate) ring_buffer: RingBuffer64,
    /// Start of the previous ciphertext block, the CBC chaining input.
    pub(crate) tail_index: usize,
    /// Start of the ciphertext block being decrypted.
    pub(crate) current_index: usize,
    /// Where the next bytes read from the input are written.
    pub(crate) head_index: usize,
    /// The last decrypted block, held back until it is known not to be the
    /// final, padded block; zeroized on drop.
    pub(crate) plaintext_block: Block16,
    /// Whether `plaintext_block` holds a block that still has to be written.
    pub(crate) need_write_plaintext: bool,
    /// Ciphertext blocks processed by the loop so far.
    pub(crate) blocks: u64,
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
    pub(crate) fn new_with_iv(iv: &Iv16) -> Self {
        let mut this = Self {
            ring_buffer: RingBuffer64::new([0u8; 64]),
            tail_index: 0,
            current_index: 16,
            head_index: 16,
            plaintext_block: Block16::new([0u8; 16]),
            need_write_plaintext: false,
            blocks: 0,
        };
        iv.with_secret(|iv_bytes| {
            this.ring_buffer
                .with_secret_mut(|rb| rb[0..16].copy_from_slice(iv_bytes))
        });
        this
    }

    /// Appends `src` to the ring buffer at `head_index` and advances it.
    ///
    /// # Panics
    ///
    /// If `src` does not fit between `head_index` and the end of the buffer.
    /// Callers only pass reads sized to the space left, so this is unreachable.
    #[inline(always)]
    fn write_at_head(&mut self, src: &[u8]) {
        self.ring_buffer.with_secret_mut(|rb| {
            rb[self.head_index..self.head_index + src.len()].copy_from_slice(src);
        });
        self.head_index += src.len();
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
    pub(crate) fn decrypt_cbc_loop<R, W>(
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
        self.cbc_loop(input, hmac, |ctx| {
            if ctx.need_write_plaintext {
                ctx.plaintext_block.with_secret(|pb| output.write_all(pb))?;
            }
            ctx.decrypt_block_into_plaintext(cipher, ctx.current_index, ctx.tail_index);
            Ok(())
        })
    }

    /// Runs the same loop as [`Self::decrypt_cbc_loop`] but only feeds the
    /// ciphertext to `hmac`: nothing is decrypted and nothing is written.
    ///
    /// The framing (the 48-byte priming read, the index advance, where the
    /// trailer ends up) is shared with the decrypting loop, so the two passes
    /// of [`crate::decrypt_verified()`] cannot disagree about where the
    /// ciphertext ends.
    ///
    /// # Errors
    ///
    /// Returns [`AescryptError::Io`] if an I/O error occurs during reading.
    #[inline(always)]
    pub(crate) fn mac_cbc_loop<R>(
        &mut self,
        input: &mut R,
        hmac: &mut HmacSha256,
    ) -> Result<(), AescryptError>
    where
        R: Read,
    {
        self.cbc_loop(input, hmac, |_| Ok(()))
    }

    /// The ring-buffer loop both passes share. For each ciphertext block it
    /// updates `hmac`, then calls `per_block` while `current_index` still
    /// points at that block and `tail_index` at its CBC chaining input, then
    /// advances.
    ///
    /// # Errors
    ///
    /// Returns [`AescryptError::Io`] on a read error, or whatever `per_block`
    /// returns.
    #[inline(always)]
    fn cbc_loop<R, F>(
        &mut self,
        input: &mut R,
        hmac: &mut HmacSha256,
        mut per_block: F,
    ) -> Result<(), AescryptError>
    where
        R: Read,
        F: FnMut(&mut Self) -> Result<(), AescryptError>,
    {
        // A plain 48-byte secure buffer, not a session block — this primes the
        // ciphertext ring, and `EncryptedSessionBlock48` (the same underlying
        // type) would misname what it holds.
        let mut initial_buffer = SpanBuffer::<48>::new([0u8; 48]);
        // Accumulate partial `read()` results until 48 bytes or EOF (same contract as encrypt_stream).
        let bytes_read = initial_buffer
            .with_secret_mut(|ib| read_until_full(input, ib))
            .map_err(AescryptError::Io)?;
        initial_buffer.with_secret(|ib| self.write_at_head(&ib[..bytes_read]));
        if bytes_read == 48 {
            loop {
                self.ring_buffer.with_secret(|rb| {
                    hmac.update(&rb[self.current_index..self.current_index + 16])
                });
                per_block(self)?;
                self.blocks += 1;
                self.tail_index = (self.tail_index + 16) % 64;
                self.current_index = (self.current_index + 16) % 64;
                if self.head_index == 64 {
                    self.head_index = 0;
                }
                let mut next_block = Block16::new([0u8; 16]);
                let n = next_block
                    .with_secret_mut(|nb| read_until_full(input, nb))
                    .map_err(AescryptError::Io)?;
                next_block.with_secret(|nb| self.write_at_head(&nb[..n]));
                if n < 16 {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Decrypts the ciphertext block at `block_index` into `plaintext_block`,
    /// chaining off the block at `chain_index`, and marks it as pending.
    #[inline(always)]
    fn decrypt_block_into_plaintext(
        &mut self,
        cipher: &Aes256Dec,
        block_index: usize,
        chain_index: usize,
    ) {
        let mut block_bytes = Block16::new([0u8; 16]);
        block_bytes.with_secret_mut(|bb| {
            self.ring_buffer.with_secret(|rb| {
                bb.copy_from_slice(&rb[block_index..block_index + 16]);
            });
        });
        // Decrypt in place inside the secure-gate wrapper (borrowed as a
        // GenericArray): the plaintext-equivalent bytes never exist outside
        // it, and the wrapper zeroizes on drop.
        block_bytes.with_secret_mut(|bb| cipher.decrypt_block(AesBlock::from_mut_slice(bb)));
        self.ring_buffer.with_secret(|rb| {
            self.plaintext_block.with_secret_mut(|pb| {
                block_bytes
                    .with_secret(|bb| xor_blocks(bb, &rb[chain_index..chain_index + 16], pb));
            });
        });
        self.need_write_plaintext = true;
    }

    /// After [`Self::mac_cbc_loop`] and [`Self::advance_tail`] over a stream
    /// with a 32-byte trailer, decrypts the final ciphertext block into
    /// `plaintext_block` so its padding can be checked before any plaintext
    /// is released. Nothing is written.
    ///
    /// With a 32-byte trailer the ring holds exactly four slots from
    /// `tail_index`: the two trailer slots, then the block before the final
    /// one (the session IV for a one-block payload), then the final block.
    /// Does nothing when the payload had no blocks.
    #[inline(always)]
    pub(crate) fn decrypt_final_block(&mut self, cipher: &Aes256Dec) {
        if self.blocks == 0 {
            return;
        }
        let final_index = (self.tail_index + 48) % 64;
        let chain_index = (self.tail_index + 32) % 64;
        self.decrypt_block_into_plaintext(cipher, final_index, chain_index);
    }

    /// Advance the tail index to the next block in the ring buffer.
    ///
    /// This is called after processing a block to move the tail pointer forward,
    /// making room for new data and updating the previous block reference for
    /// the next CBC operation.
    #[inline(always)]
    pub(crate) fn advance_tail(&mut self) {
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
    pub(crate) fn remaining(&self) -> usize {
        if self.head_index >= self.tail_index {
            self.head_index - self.tail_index
        } else {
            64 - self.tail_index + self.head_index
        }
    }
}
