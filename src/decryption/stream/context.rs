//! # Decryption Context
//!
//! This module provides the decryption context for streaming decryption
//! operations. The context reads the ciphertext a span of up to 64 KiB at a
//! time and holds back the last 32 or more bytes until the end of input shows
//! where the trailer starts, so memory stays constant however large the file.

use crate::aliases::HmacSha256;
use crate::aliases::{Block16, HeapSpan, Iv16, grow_span, heap_span};
use crate::constants::{FIRST_FILL, SPAN};
use crate::error::AescryptError;
use crate::utilities::read_until_full;
use aes::cipher::BlockDecrypt;
use aes::cipher::consts::U16;
use aes::cipher::inout::InOutBuf;
use aes::{Aes256Dec, Block as AesBlock};
use hmac::Mac;
use secure_gate::{RevealSecret, RevealSecretMut};
use std::io::{Read, Write};

/// The largest ciphertext span: up to 47 bytes carried over from the last fill,
/// then a fresh read. Exactly [`SPAN`], so no read asks for more than that, and
/// a multiple of 16, so a full fill processes whole blocks.
const CIPHER_SPAN_LEN: usize = SPAN;

/// The plaintext span a ciphertext span of `cipher_len` bytes needs: the pending
/// block at `[0..16]`, then the most blocks one fill can process,
/// `cipher_len / 16 − 2`. For the largest span that is `SPAN − 16`, and a write
/// is at most `SPAN − 32` bytes.
const fn plain_len_for(cipher_len: usize) -> usize {
    cipher_len - 16
}

/// Decryption context for streaming CBC decryption.
///
/// ## Framing
///
/// After each fill of `B` buffered ciphertext bytes, the context processes
/// `floor(B / 16) − 2` blocks when that is positive and carries the rest (at
/// most 47 bytes) to the front of `cipher_span`. At the end of input it does the
/// same once more. Over a payload stream of `T` bytes that processes exactly
/// `max(0, floor(T / 16) − 2)` blocks and leaves `32 + T mod 16` bytes (all of
/// `T` when `T < 48`) in the carry: the 32-byte v0/v3 trailer or the 33-byte
/// v1/v2 one, which the caller checks. Since `B ≤ T`, a fill never processes a
/// block the final answer would not, so the trailer is never treated as
/// ciphertext, whatever the version.
pub(crate) struct DecryptionContext {
    /// Ciphertext: the carry at the front, then the latest read, on the heap.
    /// It starts at [`FIRST_FILL`] bytes and grows toward `CIPHER_SPAN_LEN`
    /// while fills come back full, so a small file never allocates the large
    /// span. Ciphertext is public, but kept in a wiped wrapper like the
    /// IVs, for the same auditability reason.
    cipher_span: HeapSpan,
    /// Plaintext of the current span at `[16..]`, written out in one call
    /// together with the pending block copied to `[0..16]`; sized by
    /// [`plain_len_for`] from the ciphertext span, on the heap, zeroized on
    /// drop. Allocated by the first span that is decrypted, so the MAC-only pass
    /// never pays for it, and replaced if the ciphertext span grows.
    plain_span: Option<HeapSpan>,
    /// How many bytes at the front of `cipher_span` are carried, unprocessed.
    carry_len: usize,
    /// The last processed ciphertext block, the CBC chaining input of the
    /// next one. Starts as the IV.
    chain: Block16,
    /// The block before `chain` (the IV when only one block was processed),
    /// so the final block can be decrypted alone after a MAC-only pass.
    chain_before: Block16,
    /// The last decrypted block, held back until it is known not to be the
    /// final, padded block; zeroized on drop.
    pub(crate) plaintext_block: Block16,
    /// Whether `plaintext_block` holds a block that still has to be written.
    pub(crate) need_write_plaintext: bool,
    /// Ciphertext blocks processed so far.
    pub(crate) blocks: u64,
}

impl DecryptionContext {
    /// Creates a context whose CBC chain starts at `iv`.
    #[inline(always)]
    pub(crate) fn new_with_iv(iv: &Iv16) -> Self {
        let mut this = Self {
            cipher_span: heap_span(FIRST_FILL),
            plain_span: None,
            carry_len: 0,
            chain: Block16::new([0u8; 16]),
            chain_before: Block16::new([0u8; 16]),
            plaintext_block: Block16::new([0u8; 16]),
            need_write_plaintext: false,
            blocks: 0,
        };
        iv.with_secret(|iv_bytes| {
            this.chain.with_secret_mut(|c| c.copy_from_slice(iv_bytes));
            this.chain_before
                .with_secret_mut(|c| c.copy_from_slice(iv_bytes));
        });
        this
    }

    /// Decrypts the ciphertext from `input` to `output`, a span at a time,
    /// feeding every ciphertext block to `hmac`. The last decrypted block is
    /// held back in `plaintext_block` and the trailer in the carry, for the
    /// caller to check and write.
    ///
    /// # Errors
    ///
    /// Returns [`AescryptError::Io`] if an I/O error occurs during reading or
    /// writing.
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
        self.span_loop(input, hmac, |ctx, len| {
            ctx.decrypt_span(cipher, output, len)
        })
    }

    /// Runs the same loop as [`Self::decrypt_cbc_loop`] but only feeds the
    /// ciphertext to `hmac`: nothing is decrypted and nothing is written.
    ///
    /// The framing (the fill, the block count, the carry) is shared with the
    /// decrypting loop, so the two passes of [`crate::decrypt_verified()`]
    /// cannot disagree about where the ciphertext ends.
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
        self.span_loop(input, hmac, |_, _| Ok(()))
    }

    /// The span loop both passes share; see the type's Framing section. For
    /// each fill that has blocks to process it updates `hmac` once over them,
    /// calls `per_span` with their length in bytes while `chain` still holds
    /// the CBC input of the first one, then advances `chain`, `chain_before`
    /// and the carry.
    ///
    /// # Errors
    ///
    /// Returns [`AescryptError::Io`] on a read error, or whatever `per_span`
    /// returns.
    #[inline(always)]
    fn span_loop<R, F>(
        &mut self,
        input: &mut R,
        hmac: &mut HmacSha256,
        mut per_span: F,
    ) -> Result<(), AescryptError>
    where
        R: Read,
        F: FnMut(&mut Self, usize) -> Result<(), AescryptError>,
    {
        loop {
            // Fill everything after the carry, accumulating partial `read()`
            // results until the span is full or the input ends: a single short
            // `read()` is not EOF (sockets, pipes).
            let carry = self.carry_len;
            let mut filled = carry
                + self
                    .cipher_span
                    .with_secret_mut(|c| read_until_full(input, &mut c[carry..]))
                    .map_err(AescryptError::Io)?;
            let mut capacity = self.cipher_span.with_secret(|c| c.len());
            // A span still below full size came back full, so more input may
            // follow: grow it and keep filling. Every fill is still either full
            // or the end of the input, which is all the framing needs.
            while filled == capacity && capacity < CIPHER_SPAN_LEN {
                capacity = grow_span(&mut self.cipher_span, filled);
                filled += self
                    .cipher_span
                    .with_secret_mut(|c| read_until_full(input, &mut c[filled..]))
                    .map_err(AescryptError::Io)?;
            }
            let len = 16 * (filled / 16).saturating_sub(2);

            if len > 0 {
                self.cipher_span.with_secret(|c| hmac.update(&c[..len]));
                per_span(self, len)?;
                self.advance_chain(len);
                self.blocks += (len / 16) as u64;
                self.cipher_span
                    .with_secret_mut(|c| c.copy_within(len..filled, 0));
            }
            self.carry_len = filled - len;

            if filled < capacity {
                return Ok(());
            }
        }
    }

    /// Moves `chain` and `chain_before` past the `len` bytes just processed at
    /// the front of `cipher_span`.
    #[inline(always)]
    fn advance_chain(&mut self, len: usize) {
        let Self {
            cipher_span,
            chain,
            chain_before,
            ..
        } = self;
        cipher_span.with_secret(|c| {
            chain_before.with_secret_mut(|before| {
                if len >= 32 {
                    before.copy_from_slice(&c[len - 32..len - 16]);
                } else {
                    chain.with_secret(|ch| before.copy_from_slice(ch));
                }
            });
            chain.with_secret_mut(|ch| ch.copy_from_slice(&c[len - 16..len]));
        });
    }

    /// Decrypts the `len` bytes at the front of `cipher_span` (AES-NI
    /// pipelines them, since CBC decryption has no chain), writes them out
    /// behind the pending block in one call, and holds back their last block
    /// as the new pending block.
    ///
    /// # Errors
    ///
    /// Returns [`AescryptError::Io`] if the write fails.
    ///
    /// # Panics
    ///
    /// Never: `InOutBuf::new` gets two slices of length `len`, and `len` is a
    /// whole number of blocks no larger than the ciphertext span minus 32, so
    /// it fits behind the pending block in a span of [`plain_len_for`] that
    /// length.
    #[inline(always)]
    fn decrypt_span<W: Write>(
        &mut self,
        cipher: &Aes256Dec,
        output: &mut W,
        len: usize,
    ) -> Result<(), AescryptError> {
        let Self {
            cipher_span,
            plain_span,
            chain,
            plaintext_block,
            need_write_plaintext,
            ..
        } = self;
        // Sized to the ciphertext span it serves; replaced (and so wiped) if that
        // span has grown since. Its contents never outlive one call.
        let needed = plain_len_for(cipher_span.with_secret(|c| c.len()));
        if plain_span
            .as_ref()
            .is_none_or(|p| p.with_secret(|p| p.len()) < needed)
        {
            *plain_span = Some(heap_span(needed));
        }
        let plain_span = plain_span.as_mut().expect("just ensured");
        cipher_span.with_secret(|c| {
            plain_span.with_secret_mut(|p| {
                let (blocks, _) = InOutBuf::new(&c[..len], &mut p[16..16 + len])
                    .expect("equal lengths")
                    .into_chunks::<U16>();
                cipher.decrypt_blocks_inout(blocks);
                // CBC: block i is XORed with ciphertext block i − 1, and the
                // first with the chain carried over from the previous span.
                chain.with_secret(|ch| {
                    for (b, x) in p[16..32].iter_mut().zip(ch.iter()) {
                        *b ^= *x;
                    }
                });
                for (b, x) in p[32..16 + len].iter_mut().zip(&c[..len - 16]) {
                    *b ^= *x;
                }
                plaintext_block.with_secret(|pb| p[..16].copy_from_slice(pb));
            })
        });

        // The pending block and every new block but the last, contiguous.
        let start = if *need_write_plaintext { 0 } else { 16 };
        if len > start {
            plain_span.with_secret(|p| output.write_all(&p[start..len]))?;
        }
        plain_span.with_secret(|p| {
            plaintext_block.with_secret_mut(|pb| pb.copy_from_slice(&p[len..len + 16]))
        });
        *need_write_plaintext = true;
        Ok(())
    }

    /// After [`Self::mac_cbc_loop`], decrypts the final ciphertext block into
    /// `plaintext_block` so its padding can be checked before any plaintext
    /// is released. Nothing is written. Does nothing when the payload had no
    /// blocks.
    #[inline(always)]
    pub(crate) fn decrypt_final_block(&mut self, cipher: &Aes256Dec) {
        if self.blocks == 0 {
            return;
        }
        let Self {
            chain,
            chain_before,
            plaintext_block,
            need_write_plaintext,
            ..
        } = self;
        plaintext_block.with_secret_mut(|pb| {
            chain.with_secret(|ch| pb.copy_from_slice(ch));
            // Decrypt in place inside the wrapper (borrowed as a GenericArray).
            cipher.decrypt_block(AesBlock::from_mut_slice(pb));
            chain_before.with_secret(|before| {
                for (b, x) in pb.iter_mut().zip(before.iter()) {
                    *b ^= *x;
                }
            });
        });
        *need_write_plaintext = true;
    }

    /// The bytes carried after the loop: the trailer, if the input was well
    /// formed.
    #[inline(always)]
    pub(crate) fn remaining(&self) -> usize {
        self.carry_len
    }

    /// Runs `f` over the carried trailer bytes.
    #[inline(always)]
    pub(crate) fn with_trailer<T>(&self, f: impl FnOnce(&[u8]) -> T) -> T {
        self.cipher_span.with_secret(|c| f(&c[..self.carry_len]))
    }
}
