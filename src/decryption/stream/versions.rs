//! src/decryption/stream/versions.rs
//! Version-aware streaming CBC decryption + final-block / HMAC trailer handling.

use crate::aliases::HmacSha256;
use crate::aliases::{Aes256Key32, Iv16, Trailer32};
use crate::decryption::stream::context::DecryptionContext;
use crate::decryption::stream::trailer::{
    extract_hmac_scattered, extract_hmac_simple, validate_final_pkcs7, write_final_modulo,
    write_final_pkcs7,
};
use crate::error::AescryptError;
use aes::Aes256Dec;
use aes::cipher::KeyInit;
use hmac::Mac;
use secure_gate::{ConstantTimeEq, RevealSecret};
use std::io::{Read, Write};

/// Finishes the payload HMAC and compares it with the trailer's, in constant
/// time.
///
/// # Errors
///
/// [`AescryptError::Header`] with "HMAC verification failed" if they differ.
/// What that means depends on the version. In v0, which has no session block,
/// it is a wrong password or damaged data, which v0 cannot tell apart. In
/// v1–v3 it is damaged or tampered data, *if* the session check has already
/// passed, as it has when the caller came through [`crate::decrypt()`]; a
/// direct caller of [`decrypt_ciphertext_stream`] that skipped
/// `extract_session_data` gets no such guarantee.
///
/// # Panics
///
/// Never in practice: an HMAC-SHA256 tag is always 32 bytes.
fn verify_payload_hmac(hmac: HmacSha256, expected: &Trailer32) -> Result<(), AescryptError> {
    if !finalize_tag(hmac).ct_eq(expected) {
        return Err(AescryptError::Header("HMAC verification failed".into()));
    }
    Ok(())
}

/// Finishes the payload HMAC into a [`Trailer32`].
///
/// # Panics
///
/// Never in practice: an HMAC-SHA256 tag is always 32 bytes.
fn finalize_tag(hmac: HmacSha256) -> Trailer32 {
    let computed = hmac.finalize().into_bytes();
    Trailer32::try_from(computed.as_ref()).expect("computed hmac is 32 bytes")
}

/// The payload HMAC keyed with `encryption_key`, the same construction
/// `encrypt_stream` uses.
///
/// The returned `HmacSha256` carries opad/ipad state derived from
/// `encryption_key` and is not wrapped — `hmac` 0.12 exposes no zeroize hook.
/// See the crate-level Security Model.
///
/// # Panics
///
/// Never: the key is always 32 bytes, a valid HMAC key length.
fn payload_hmac(encryption_key: &Aes256Key32) -> HmacSha256 {
    encryption_key.with_secret(|key| {
        <HmacSha256 as Mac>::new_from_slice(key)
            .expect("encryption_key is always 32 bytes — valid HMAC key")
    })
}

/// Checks the trailer length for `config` and reads the expected HMAC tag
/// and the final-block modulo byte out of the carried trailer (`None` for v3, which
/// uses PKCS#7 instead).
///
/// # Errors
///
/// [`AescryptError::Header`] with the per-version trailer-length message.
fn read_trailer(
    ctx: &DecryptionContext,
    config: StreamConfig,
) -> Result<(Trailer32, Option<u8>), AescryptError> {
    let remaining = ctx.remaining();
    match config {
        StreamConfig::V0 { reserved_modulo } => {
            if remaining != 32 {
                return Err(AescryptError::Header(
                    "v0: expected 32-byte HMAC trailer".into(),
                ));
            }
            Ok((extract_hmac_simple(ctx), Some(reserved_modulo)))
        }
        StreamConfig::V1 | StreamConfig::V2 => {
            if remaining != 33 {
                return Err(AescryptError::Header(
                    "v1/v2: expected 33-byte trailer".into(),
                ));
            }
            let (expected_hmac, modulo_byte) = extract_hmac_scattered(ctx);
            Ok((expected_hmac, Some(modulo_byte)))
        }
        StreamConfig::V3 => {
            if remaining != 32 {
                return Err(AescryptError::Header(
                    "v3: expected 32-byte HMAC trailer".into(),
                ));
            }
            Ok((extract_hmac_simple(ctx), None))
        }
    }
}

/// What pass 1 of [`crate::decrypt_verified()`] verified: the payload tag
/// and the final-block modulo byte (`None` for v3). Pass 2 must see the same.
pub(crate) struct VerifiedTrailer {
    /// The payload HMAC tag, already checked against the ciphertext.
    tag: Trailer32,
    /// The final-block modulo byte, `None` for v3.
    modulo: Option<u8>,
}

/// Pass 1 of [`crate::decrypt_verified()`]: streams the ciphertext through
/// the payload HMAC and checks the tag in constant time, writing nothing.
///
/// For v3 it also decrypts the final block alone, inside a wrapper that is
/// wiped and never written, and checks its PKCS#7 padding, so a file pass 2
/// would reject on padding is rejected here before any plaintext is
/// released.
///
/// # Errors
///
/// - [`AescryptError::Io`] — reader error.
/// - [`AescryptError::Header`] — trailer length mismatch, payload-HMAC
///   mismatch (`"HMAC verification failed"`), or invalid v3 padding — the
///   same messages [`decrypt_ciphertext_stream`] gives.
pub(crate) fn verify_ciphertext_stream<R>(
    mut input_reader: R,
    initial_vector: &Iv16,
    encryption_key: &Aes256Key32,
    config: StreamConfig,
) -> Result<VerifiedTrailer, AescryptError>
where
    R: Read,
{
    let mut hmac = payload_hmac(encryption_key);
    let mut ctx = DecryptionContext::new_with_iv(initial_vector);
    ctx.mac_cbc_loop(&mut input_reader, &mut hmac)?;

    let (tag, modulo) = read_trailer(&ctx, config)?;
    verify_payload_hmac(hmac, &tag)?;

    if let StreamConfig::V3 = config {
        let cipher = encryption_key.with_secret(|key| Aes256Dec::new(key.into()));
        ctx.decrypt_final_block(&cipher);
        validate_final_pkcs7(&ctx)?;
    }

    Ok(VerifiedTrailer { tag, modulo })
}

/// Pass 2 of [`crate::decrypt_verified()`]: [`decrypt_ciphertext_stream`],
/// except that the tag it computes, the trailer it reads and the modulo byte
/// must all match what `verified` recorded in pass 1.
///
/// # Errors
///
/// As [`decrypt_ciphertext_stream`], except that any mismatch with pass 1 is
/// [`AescryptError::Header`] with
/// `"input changed between verification and decryption"`.
pub(crate) fn decrypt_verified_stream<R, W>(
    input_reader: R,
    output_writer: W,
    initial_vector: &Iv16,
    encryption_key: &Aes256Key32,
    config: StreamConfig,
    verified: &VerifiedTrailer,
) -> Result<(), AescryptError>
where
    R: Read,
    W: Write,
{
    decrypt_stream(
        input_reader,
        output_writer,
        initial_vector,
        encryption_key,
        config,
        Some(verified),
    )
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
/// `decrypt_ciphertext_stream` is the streaming worker for [`crate::decrypt()`].
/// It consumes the encrypted payload (everything after the encrypted session
/// block on disk) a span of up to 64 KiB at a time, decrypts each span's CBC
/// blocks together, writes their plaintext with one call, holds back the
/// trailer until the input ends, and finally validates the trailer:
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
/// - **Decrypt-then-verify**. Plaintext is written to `output_writer` a span
///   (up to 64 KiB) at a time as it is produced, every block but the final
///   one. The HMAC tag is checked **after** the stream ends,
///   so partial unauthenticated plaintext may already be on `output_writer`
///   when this function returns an error. See [`crate::decrypt()`] for the
///   caller contract.
/// - HMAC and PKCS#7 padding comparisons use [`secure-gate`]'s
///   `ConstantTimeEq`.
/// - All session keys, IVs, span buffers, and trailers live in
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
    input_reader: R,
    output_writer: W,
    initial_vector: &Iv16,
    encryption_key: &Aes256Key32,
    config: StreamConfig,
) -> Result<(), AescryptError>
where
    R: Read,
    W: Write,
{
    decrypt_stream(
        input_reader,
        output_writer,
        initial_vector,
        encryption_key,
        config,
        None,
    )
}

/// The decrypting pass behind [`decrypt_ciphertext_stream`] and
/// [`decrypt_verified_stream`]. With `verified`, the tag must also match
/// pass 1's, and a mismatch reads as the input having changed.
///
/// # Errors
///
/// As [`decrypt_ciphertext_stream`] and [`decrypt_verified_stream`].
#[inline(always)]
fn decrypt_stream<R, W>(
    mut input_reader: R,
    mut output_writer: W,
    initial_vector: &Iv16,
    encryption_key: &Aes256Key32,
    config: StreamConfig,
    verified: Option<&VerifiedTrailer>,
) -> Result<(), AescryptError>
where
    R: Read,
    W: Write,
{
    let cipher = encryption_key.with_secret(|key| Aes256Dec::new(key.into()));
    let mut hmac = payload_hmac(encryption_key);

    let mut ctx = DecryptionContext::new_with_iv(initial_vector);
    ctx.decrypt_cbc_loop(&mut input_reader, &mut output_writer, &cipher, &mut hmac)?;

    let (expected_hmac, modulo) = read_trailer(&ctx, config)?;
    match verified {
        None => verify_payload_hmac(hmac, &expected_hmac)?,
        Some(pass_one) => {
            // Non-short-circuiting `&`: every comparison runs.
            let unchanged = finalize_tag(hmac).ct_eq(&pass_one.tag)
                & expected_hmac.ct_eq(&pass_one.tag)
                & (modulo == pass_one.modulo);
            if !unchanged {
                return Err(AescryptError::Header(
                    "input changed between verification and decryption".into(),
                ));
            }
        }
    }

    match modulo {
        Some(modulo_byte) => write_final_modulo(&ctx, &mut output_writer, modulo_byte)?,
        None => write_final_pkcs7(&ctx, &mut output_writer)?,
    }

    Ok(())
}
