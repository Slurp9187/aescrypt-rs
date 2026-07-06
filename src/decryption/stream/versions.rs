//! src/decryption/stream/versions.rs
//! Version-aware streaming CBC decryption + final-block / HMAC trailer handling.

use crate::aliases::HmacSha256;
use crate::aliases::{Aes256Key32, Iv16, Trailer32};
use crate::decryption::stream::context::DecryptionContext;
use crate::decryption::stream::trailer::{
    extract_hmac_scattered, extract_hmac_simple, write_final_modulo, write_final_pkcs7,
};
use crate::error::AescryptError;
use aes::cipher::KeyInit;
use aes::Aes256Dec;
use hmac::Mac;
use secure_gate::{ConstantTimeEq, RevealSecret};
use std::io::{Read, Write};

fn verify_payload_hmac(hmac: HmacSha256, expected: &Trailer32) -> Result<(), AescryptError> {
    let computed = hmac.finalize().into_bytes();
    let computed_fixed = Trailer32::try_from(computed.as_ref()).expect("computed hmac is 32 bytes");
    if !computed_fixed.ct_eq(expected) {
        return Err(AescryptError::Header("HMAC verification failed".into()));
    }
    Ok(())
}

/// Per-version configuration for [`decrypt_ciphertext_stream`].
///
/// Selects the padding scheme and trailer layout to use after the streaming
/// CBC loop has consumed the ciphertext. Construct this from the `(version,
/// modulo_or_reserved)` tuple returned by
/// [`crate::decryption::read_file_version`].
///
/// # Format
///
/// | Variant | Padding scheme | Trailer length | Trailer layout                    |
/// | ------- | -------------- | :------------: | --------------------------------- |
/// | [`V0`](Self::V0) | legacy modulo (low nibble of `reserved_modulo`) | 32 B | contiguous HMAC tag |
/// | [`V1`](Self::V1) | legacy modulo (last buffered byte) | 33 B | modulo byte then HMAC tag |
/// | [`V2`](Self::V2) | legacy modulo (last buffered byte) | 33 B | modulo byte then HMAC tag |
/// | [`V3`](Self::V3) | PKCS#7 (1..=16) | 32 B | contiguous HMAC tag |
///
/// # Security
///
/// `V0`/`V1`/`V2` exist only for read compatibility; this crate never produces
/// them. Use [`V3`](Self::V3) for any new file.
///
/// The v0–v2 final-block length ("modulo") byte is **not covered by the
/// payload HMAC** — inherent to the legacy wire format — so the last plaintext
/// block's length is malleable by up to 15 bytes without failing verification.
/// v3 recovers the length from PKCS#7 padding inside the authenticated
/// ciphertext and is not affected.
#[derive(Clone, Copy)]
pub enum StreamConfig {
    /// AES Crypt v0 — legacy modulo padding, 32-byte contiguous HMAC trailer.
    ///
    /// `reserved_modulo` is the 5th header byte (the v0 modulo byte) and
    /// determines the final-block length: `len = (reserved_modulo & 0x0F)`,
    /// or `16` when that nibble is zero.
    V0 {
        /// 5th header byte; low nibble is the final-block byte count.
        reserved_modulo: u8,
    },
    /// AES Crypt v1 — legacy modulo padding with the modulo byte embedded in
    /// a 33-byte scattered trailer.
    V1,
    /// AES Crypt v2 — same trailer/padding shape as v1, plus header
    /// extensions before the encrypted session block.
    V2,
    /// AES Crypt v3 — PKCS#7 padding and a 32-byte contiguous HMAC-SHA256
    /// trailer. The only format this crate writes.
    V3,
}

/// Streams ciphertext from `input_reader` through AES-256-CBC decryption,
/// writes the recovered plaintext to `output_writer`, and verifies the
/// version-appropriate HMAC trailer.
///
/// `decrypt_ciphertext_stream` is the per-block worker for [`crate::decrypt()`].
/// It consumes the encrypted payload (everything after the encrypted session
/// block on disk), decrypts each 16-byte CBC block into the
/// [`crate::decryption`] ring buffer, and finally validates the trailer:
///
/// - [`StreamConfig::V0`] / [`StreamConfig::V3`]: 32-byte contiguous
///   HMAC-SHA256 tag.
/// - [`StreamConfig::V1`] / [`StreamConfig::V2`]: 33-byte trailer (modulo
///   byte plus HMAC-SHA256 tag).
///
/// # Errors
///
/// - [`AescryptError::Io`] — reader or writer error during the streaming loop
///   or trailer write.
/// - [`AescryptError::Header`] — trailer length mismatch
///   (`"v0: expected 32-byte HMAC trailer"`,
///   `"v1/v2: expected 33-byte trailer"`,
///   `"v3: expected 32-byte HMAC trailer"`),
///   payload-HMAC mismatch (`"HMAC verification failed"`),
///   or invalid v3 PKCS#7 padding (`"v3: invalid PKCS#7 padding"`).
///
/// # Panics
///
/// Never panics on valid input. The internal `expect("computed hmac is 32 bytes")`
/// is a structural invariant of HMAC-SHA256.
///
/// # Security
///
/// - **Decrypt-then-verify**. Plaintext blocks are written to `output_writer`
///   as they are produced. The HMAC tag is checked **after** the stream ends,
///   so partial unauthenticated plaintext may already be on `output_writer`
///   when this function returns an error. See [`crate::decrypt()`] for the
///   caller contract.
/// - HMAC and PKCS#7 padding comparisons use [`secure-gate`]'s
///   `ConstantTimeEq`.
/// - All session keys, IVs, ring-buffer slots, and trailers live in
///   [`secure-gate`] aliases that zeroize on drop.
///
/// # Compatibility
///
/// - `V0`/`V1`/`V2` are read-only legacy-format support.
/// - `V3` is bit-identical to ciphertext produced by [`crate::encrypt()`] and
///   the official AES Crypt v3 reference implementation.
///
/// [`secure-gate`]: https://github.com/Slurp9187/secure-gate
#[inline(always)]
pub fn decrypt_ciphertext_stream<R, W>(
    mut input_reader: R,
    mut output_writer: W,
    initial_vector: &Iv16,
    encryption_key: &Aes256Key32,
    config: StreamConfig,
) -> Result<(), AescryptError>
where
    R: Read,
    W: Write,
{
    let cipher = encryption_key.with_secret(|key| Aes256Dec::new(key.into()));

    // This is the exact same construction used in encrypt_stream
    let mut hmac = encryption_key.with_secret(|key| {
        <HmacSha256 as Mac>::new_from_slice(key)
            .expect("encryption_key is always 32 bytes — valid HMAC key")
    });

    let mut ctx = DecryptionContext::new_with_iv(initial_vector);
    ctx.decrypt_cbc_loop(&mut input_reader, &mut output_writer, &cipher, &mut hmac)?;

    ctx.advance_tail();
    let remaining = ctx.remaining();

    match config {
        StreamConfig::V0 { reserved_modulo } => {
            if remaining != 32 {
                return Err(AescryptError::Header(
                    "v0: expected 32-byte HMAC trailer".into(),
                ));
            }

            let expected_hmac = extract_hmac_simple(&ctx);
            verify_payload_hmac(hmac, &expected_hmac)?;
            write_final_modulo(&ctx, &mut output_writer, reserved_modulo)?;
        }

        StreamConfig::V1 | StreamConfig::V2 => {
            if remaining != 33 {
                return Err(AescryptError::Header(
                    "v1/v2: expected 33-byte trailer".into(),
                ));
            }

            let (expected_hmac, modulo_byte) = extract_hmac_scattered(&ctx);
            verify_payload_hmac(hmac, &expected_hmac)?;
            write_final_modulo(&ctx, &mut output_writer, modulo_byte)?;
        }

        StreamConfig::V3 => {
            if remaining != 32 {
                return Err(AescryptError::Header(
                    "v3: expected 32-byte HMAC trailer".into(),
                ));
            }

            let expected_hmac = extract_hmac_simple(&ctx);
            verify_payload_hmac(hmac, &expected_hmac)?;
            write_final_pkcs7(&ctx, &mut output_writer)?;
        }
    }

    Ok(())
}
