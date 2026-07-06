// src/encryption/stream.rs

//! v3 streaming AES-256-CBC payload encryption with HMAC-SHA256 trailer.

use crate::aliases::HmacSha256;
use crate::aliases::{Aes256Key32, Block16, Iv16};
use crate::error::AescryptError;
use crate::utilities::{read_until_full, xor_blocks};
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes256Enc, Block as AesBlock};
use hmac::Mac;
use secure_gate::{RevealSecret, RevealSecretMut};
use std::io::{Read, Write};

/// Encrypts the payload stream of an AES Crypt v3 file with PKCS#7 padding and
/// appends a 32-byte HMAC-SHA256 trailer.
///
/// `encrypt_stream` reads `source` until EOF, encrypts each 16-byte plaintext
/// block in CBC mode using `session_key` chained off `session_iv`, writes the
/// resulting ciphertext to `destination`, and finishes with a 32-byte
/// HMAC-SHA256 tag computed over every ciphertext block. The final block is
/// always padded with PKCS#7; even an empty or 16-aligned input emits one full
/// pad block.
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
/// Never panics on valid input. The internal `GenericArray::from_mut_slice`
/// is over a buffer that is always exactly 16 bytes by construction.
///
/// # Security
///
/// - `session_key` is consumed only inside scoped [`secure-gate`] reveals; it
///   never escapes a `with_secret` closure.
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
    let mut hmac = session_key.with_secret(|sk| {
        <HmacSha256 as Mac>::new_from_slice(sk)
            .expect("session_key is always 32 bytes — valid HMAC key")
    });

    // previous ciphertext block — secure from birth
    let mut prev_block = session_iv.with_secret(|siv| Block16::new(*siv));

    let mut plaintext_block = Block16::new([0u8; 16]);

    loop {
        // Read up to 16 bytes, accumulating partial `read()` results until the buffer is full
        // or the source returns 0 (EOF). A single `read()` may return fewer than requested even
        // when more data exist (sockets, pipes); treating that as EOF would silently truncate.
        let n = plaintext_block
            .with_secret_mut(|pb| read_until_full(&mut source, pb))
            .map_err(AescryptError::Io)?;
        let is_final = n < 16;

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

        // Encrypt in place inside the secure-gate wrapper (borrowed as a
        // GenericArray); afterwards `xor_output` holds the ciphertext block.
        xor_output.with_secret_mut(|xo| cipher.encrypt_block(AesBlock::from_mut_slice(xo)));

        // HMAC + write ciphertext
        xor_output.with_secret(|ct| {
            hmac.update(ct);
            destination.write_all(ct)
        })?;

        // Update previous block for next iteration
        prev_block = xor_output;

        if is_final {
            break;
        }
    }

    destination.write_all(hmac.finalize().into_bytes().as_ref())?;
    Ok(())
}
