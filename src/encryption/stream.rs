// src/encryption/stream.rs

//! v3 streaming AES-256-CBC payload encryption with HMAC-SHA256 trailer.

use crate::aliases::HmacSha256;
use crate::aliases::{Aes256Key32, Block16, Iv16, grow_span, heap_span};
use crate::constants::{FIRST_FILL, SPAN};
use crate::error::AescryptError;
use crate::utilities::read_until_full;
use aes::cipher::consts::U16;
use aes::cipher::{
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, KeyInit,
};
use aes::{Aes256Enc, Block as AesBlock};
use hmac::Mac;
use secure_gate::{RevealSecret, RevealSecretMut};
use std::io::{Read, Write};

/// Bytes encrypted before the HMAC catches up, inside one span. CBC encryption
/// and SHA-256 are each a serial chain, but independent of each other; feeding
/// the MAC a piece that was just encrypted keeps both chains in flight and the
/// piece still in L1. In three alternating rounds of `benches/throughput.rs` on
/// one x86 desktop with AES-NI, [`CbcSpan`] per 256 bytes was about 10% faster
/// than either [`CbcSpan`] per whole span or per-block `encrypt_block` at 256
/// bytes, which tied. It must be a whole number of blocks: [`CbcSpan`] encrypts
/// whole blocks only, so a remainder would be written unencrypted. The asserts
/// below refuse to compile otherwise. Any such value writes the same bytes
/// (`tests/span_golden_tests.rs`).
const INTERLEAVE: usize = 256;

const _: () = assert!(INTERLEAVE > 0 && INTERLEAVE % 16 == 0);
const _: () = assert!(SPAN % INTERLEAVE == 0);

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
/// Never panics on valid input. The conversion to `aes::Block` is only made
/// on 16-byte chunks of a span whose used length is a multiple of 16.
///
/// # Security
///
/// - `session_key` is consumed only inside scoped [`secure-gate`] reveals; it
///   never escapes a `with_secret` closure.
/// - The plaintext span is a `secure_gate::Dynamic<[u8]>` that starts at 1 KiB
///   and is replaced by larger ones, up to 64 KiB, while fills come back full.
///   Each is allocated zeroed on the heap, and is a boxed slice that cannot
///   reallocate. Each is wiped on drop, the smaller ones as they are replaced. It holds plaintext only until
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
    // `session_key`. It is not a secure-gate type, but it is wiped when it drops
    // (`hmac` and `sha2` are built with `zeroize`); see the crate-level Security
    // Model.
    let mut hmac = session_key.with_secret(|sk| {
        <HmacSha256 as KeyInit>::new_from_slice(sk)
            .expect("session_key is always 32 bytes — valid HMAC key")
    });

    // Previous ciphertext block — secure from birth, and copied wrapper-to-wrapper.
    // `Block16::new(*siv)` would deref the session IV into a bare `[u8; 16]` that
    // nothing zeroizes; the session IV is encrypted inside the session block, so it
    // is protected material, not public like the file's IV.
    let mut prev_block = Block16::new([0u8; 16]);
    session_iv.with_secret(|siv| prev_block.with_secret_mut(|pb| pb.copy_from_slice(siv)));

    // Allocated zeroed on the heap, so a span never sits in the caller's stack
    // frame, and building it leaves no secret behind. It starts small and grows
    // toward `SPAN` only while fills come back full, so a small file never pays
    // to allocate, zero and wipe 64 KiB.
    let mut span = heap_span(FIRST_FILL);

    loop {
        // Fill the span, accumulating partial `read()` results until it is full
        // or the source returns 0 (EOF). A single `read()` may return fewer bytes
        // than requested even when more exist (sockets, pipes); treating that as
        // EOF would silently truncate.
        let mut n = span
            .with_secret_mut(|s| read_until_full(&mut source, s))
            .map_err(AescryptError::Io)?;
        let mut capacity = span.with_secret(|s| s.len());
        while n == capacity && capacity < SPAN {
            // A span still below full size is full, so more may follow: grow it,
            // carrying what was read (the smaller span is wiped as it drops),
            // and keep filling.
            capacity = grow_span(&mut span, n);
            n += span
                .with_secret_mut(|s| read_until_full(&mut source, &mut s[n..]))
                .map_err(AescryptError::Io)?;
        }
        let is_final = n < capacity;

        // A short fill is the last span: pad its partial block (1..=16 bytes,
        // so an empty or aligned tail gets a full block). There is room, since
        // n < capacity and every span is a multiple of 16. A full span is never
        // final: the next fill decides, and pads an empty tail into one block.
        let len = if is_final {
            let pad = 16 - n % 16;
            span.with_secret_mut(|s| s[n..n + pad].fill(pad as u8));
            n + pad
        } else {
            capacity
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
/// A `BlockCipherEncClosure`, so the whole loop runs inside one call into the
/// AES backend. On x86 that call is `aes`'s `#[target_feature(enable = "aes")]`
/// function, so one feature check and call cover the piece where
/// `encrypt_block` paid both for every block; that is the saving measured.
/// Where `aes` uses its software backend (no AES-NI or Arm AES extensions, or
/// `--cfg aes_backend="soft"`) there is no such dispatch to save.
///
/// This code copies no block out: each is encrypted in place inside the span
/// wrapper, and `prev` is the `Block16` wrapper's own storage. What the AES
/// backend does inside `encrypt_block_inplace` is out of its reach. The
/// hardware backends load each block into SIMD values, but `aes`'s software
/// backend copies each block (plaintext XOR the previous ciphertext) into a
/// stack batch it does not wipe. That is equally true of the cipher's own
/// `encrypt_block`, which runs the same backend.
struct CbcSpan<'a> {
    /// The previous ciphertext block; the last one written, afterwards.
    prev: &'a mut [u8; 16],
    /// Whole blocks of plaintext, encrypted in place.
    data: &'a mut [u8],
}

impl BlockSizeUser for CbcSpan<'_> {
    type BlockSize = U16;
}

impl BlockCipherEncClosure for CbcSpan<'_> {
    #[inline(always)]
    fn call<B: BlockCipherEncBackend<BlockSize = U16>>(self, backend: &B) {
        for block in self.data.chunks_exact_mut(16) {
            for (b, p) in block.iter_mut().zip(self.prev.iter()) {
                *b ^= *p;
            }
            let block: &mut AesBlock = block.try_into().expect("chunks_exact_mut(16)");
            backend.encrypt_block_inplace(block);
            self.prev.copy_from_slice(block);
        }
    }
}
