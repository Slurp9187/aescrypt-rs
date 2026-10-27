// src/encryption/stream.rs

//! v3 streaming AES-256-CBC payload encryption with HMAC-SHA256 trailer.

use crate::aliases::HmacSha256;
use crate::aliases::{Aes256Key32, Block16, Iv16, heap_span};
use crate::constants::SPAN;
use crate::error::AescryptError;
use crate::utilities::read_until_full;
use aes::cipher::consts::U16;
use aes::cipher::{BlockBackend, BlockClosure, BlockEncrypt, BlockSizeUser, KeyInit};
use aes::{Aes256Enc, Block as AesBlock};
use hmac::Mac;
use secure_gate::{RevealSecret, RevealSecretMut};
use std::io::{Read, Write};

/// Bytes encrypted before the HMAC catches up, inside one span. CBC encryption
/// and SHA-256 are each a serial chain, but independent of each other; feeding
/// the MAC a piece that was just encrypted keeps both chains in flight and the
/// piece still in L1. In three alternating rounds of `benches/throughput.rs` on
/// one desktop, [`CbcSpan`] per 256 bytes was about 10% faster than either
/// [`CbcSpan`] per whole span or per-block `encrypt_block` at 256 bytes, which
/// tied. The output is the same at any value (`tests/span_golden_tests.rs`).
const INTERLEAVE: usize = 256;

/// Encrypts the payload stream of an AES Crypt v3 file with PKCS#7 padding and
/// appends a 32-byte HMAC-SHA256 trailer.
///
/// `encrypt_stream` reads `source` until EOF, encrypts the plaintext in CBC
/// mode using `session_key` chained off `session_iv`, writes the resulting
/// ciphertext to `destination`, and finishes with a 32-byte HMAC-SHA256 tag
/// computed over every ciphertext block. The final block is always padded with
/// PKCS#7; even an empty or 16-aligned input emits one full pad block.
///
/// It works a span of up to 64 KiB at a time: one read loop fills the span,
/// the span is encrypted in place, and the ciphertext goes to the HMAC and to
/// one `write_all`. The bytes written are the same as a block-at-a-time
/// encryption would write.
///
/// This is the streaming primitive called by [`crate::encrypt()`] after the
/// header, public IV, encrypted session block, and session HMAC have already
/// been written.
///
/// # Format
///
/// - Block cipher: AES-256 in CBC mode (`session_key`, `session_iv`).
/// - Padding: PKCS#7 (1..=16 bytes), always present.
/// - Authentication: HMAC-SHA256 keyed with `session_key` over the ciphertext;
///   the tag is appended after the last ciphertext block.
///
/// # Errors
///
/// - [`AescryptError::Io`] — `source.read` or `destination.write_all` returned
///   an error.
///
/// # Panics
///
/// Never panics on valid input. `GenericArray::from_mut_slice` is only called
/// on 16-byte chunks of a span whose used length is a multiple of 16.
///
/// # Security
///
/// - `session_key` is consumed only inside scoped [`secure-gate`] reveals; it
///   never escapes a `with_secret` closure.
/// - The plaintext span is a 64 KiB `secure_gate::Dynamic<[u8]>`, allocated
///   zeroed on the heap; a boxed slice cannot reallocate, and it is wiped on
///   drop. It holds plaintext only until
///   the in-place encryption overwrites it with ciphertext.
/// - `session_iv` **must** be unique per file. [`crate::encrypt()`] generates
///   it via the [`secure-gate`] CSPRNG (`Iv16::from_random`).
/// - PKCS#7 padding is always applied so the ciphertext length cannot leak the
///   true plaintext length modulo 16.
/// - HMAC verification on the read side uses constant-time equality.
///
/// # See also
///
/// - [`crate::encrypt()`] — high-level API that wraps this function.
/// - [`crate::decryption::decrypt_ciphertext_stream`] — read-side counterpart.
///
/// [`secure-gate`]: https://github.com/Slurp9187/secure-gate
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
    // Note: the returned `HmacSha256` carries opad/ipad state derived from
    // `session_key` and is not wrapped — `hmac` 0.12 exposes no zeroize hook.
    // See the crate-level Security Model.
    let mut hmac = session_key.with_secret(|sk| {
        <HmacSha256 as Mac>::new_from_slice(sk)
            .expect("session_key is always 32 bytes — valid HMAC key")
    });

    // Previous ciphertext block — secure from birth, and copied wrapper-to-wrapper.
    // `Block16::new(*siv)` would deref the session IV into a bare `[u8; 16]` that
    // nothing zeroizes; the session IV is encrypted inside the session block, so it
    // is protected material, not public like the file's IV.
    let mut prev_block = Block16::new([0u8; 16]);
    session_iv.with_secret(|siv| prev_block.with_secret_mut(|pb| pb.copy_from_slice(siv)));

    // Allocated zeroed on the heap, so 64 KiB never sits in the caller's
    // stack frame, and building it leaves no secret behind.
    let mut span = heap_span(SPAN);

    loop {
        // Fill the span, accumulating partial `read()` results until it is full
        // or the source returns 0 (EOF). A single `read()` may return fewer bytes
        // than requested even when more exist (sockets, pipes); treating that as
        // EOF would silently truncate.
        let n = span
            .with_secret_mut(|s| read_until_full(&mut source, s))
            .map_err(AescryptError::Io)?;
        let is_final = n < SPAN;

        // A short fill is the last span: pad its partial block (1..=16 bytes,
        // so an empty or aligned tail gets a full block). There is room, since
        // n < SPAN and SPAN is a multiple of 16. A full span is never final:
        // the next fill decides, and pads an empty tail into one whole block.
        let len = if is_final {
            let pad = 16 - n % 16;
            span.with_secret_mut(|s| s[n..n + pad].fill(pad as u8));
            n + pad
        } else {
            SPAN
        };

        span.with_secret_mut(|s| {
            prev_block.with_secret_mut(|prev| {
                for piece in s[..len].chunks_mut(INTERLEAVE) {
                    cipher.encrypt_with_backend(CbcSpan {
                        prev: &mut *prev,
                        data: &mut *piece,
                    });
                    hmac.update(piece);
                }
            })
        });
        span.with_secret(|ct| destination.write_all(&ct[..len]))?;

        if is_final {
            break;
        }
    }

    destination.write_all(hmac.finalize().into_bytes().as_ref())?;
    Ok(())
}

/// CBC-encrypts `data` (a multiple of 16 bytes) in place, chaining off `prev`
/// and leaving the last ciphertext block in it.
///
/// A `BlockClosure`, so the whole loop runs inside the AES backend's own
/// `#[target_feature(enable = "aes")]` function: one feature check and call per
/// piece, where `encrypt_block` paid both for every block. Each block is
/// encrypted in place inside the span wrapper, and `prev` is the `Block16`
/// wrapper's own storage, so no plaintext block is copied out (the `cbc`
/// crate's backend copies each one to the stack).
struct CbcSpan<'a> {
    /// The previous ciphertext block; the last one written, afterwards.
    prev: &'a mut [u8; 16],
    /// Whole blocks of plaintext, encrypted in place.
    data: &'a mut [u8],
}

impl BlockSizeUser for CbcSpan<'_> {
    type BlockSize = U16;
}

impl BlockClosure for CbcSpan<'_> {
    #[inline(always)]
    fn call<B: BlockBackend<BlockSize = U16>>(self, backend: &mut B) {
        for block in self.data.chunks_exact_mut(16) {
            for (b, p) in block.iter_mut().zip(self.prev.iter()) {
                *b ^= *p;
            }
            backend.proc_block_inplace(AesBlock::from_mut_slice(block));
            self.prev.copy_from_slice(block);
        }
    }
}
