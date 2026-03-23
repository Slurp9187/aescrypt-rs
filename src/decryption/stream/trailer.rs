//! src/decryption/stream/trailer.rs
//! Trailer processing — HMAC extraction and final block writing
//! All round-trip and deterministic tests pass
//! HMAC verification lives in versions.rs as `verify_payload_hmac`

use crate::aliases::{Block16, Trailer32};
use crate::decryption::stream::context::DecryptionContext;
use crate::error::AescryptError;
use secure_gate::{ConstantTimeEq, RevealSecret, RevealSecretMut};
use std::io::Write;

/// Extract 32-byte HMAC using simple wrap-around (used by v0 and v3)
#[inline(always)]
pub fn extract_hmac_simple(ctx: &DecryptionContext) -> Trailer32 {
    let mut expected = Trailer32::new([0u8; 32]);
    ctx.ring_buffer.with_secret(|ring| {
        expected.with_secret_mut(|e| {
            for (i, byte) in e.iter_mut().enumerate() {
                *byte = ring[(ctx.tail_index + i) % 64];
            }
        });
    });
    expected
}

/// Extract 32-byte HMAC + modulo byte using scattered layout (v1/v2 only)
///
/// Layout in the ring: byte 0 = modulo, bytes 1–32 = HMAC (sequential).
/// Uses wrap-around indexing (`% 64`) matching `extract_hmac_simple`.
#[inline(always)]
pub fn extract_hmac_scattered(ctx: &DecryptionContext) -> (Trailer32, u8) {
    let mut expected = Trailer32::new([0u8; 32]);
    let modulo_byte = ctx.ring_buffer.with_secret(|ring| {
        expected.with_secret_mut(|e| {
            for (i, byte) in e.iter_mut().enumerate() {
                *byte = ring[(ctx.tail_index + 1 + i) % 64];
            }
        });
        ring[ctx.tail_index]
    });
    (expected, modulo_byte)
}

/// Write final plaintext block using legacy modulo padding (v0, v1, v2)
#[inline(always)]
pub fn write_final_modulo<W: Write>(
    ctx: &DecryptionContext,
    output: &mut W,
    modulo: u8,
) -> Result<(), AescryptError> {
    if ctx.need_write_plaintext {
        let len = if (modulo & 0x0F) == 0 {
            16
        } else {
            (modulo & 0x0F) as usize
        };
        ctx.plaintext_block
            .with_secret(|pb| output.write_all(&pb[..len]))?;
    }
    Ok(())
}

/// Write final plaintext block using PKCS#7 padding (v3 only)
#[inline(always)]
pub fn write_final_pkcs7<W: Write>(
    ctx: &DecryptionContext,
    output: &mut W,
) -> Result<(), AescryptError> {
    if !ctx.need_write_plaintext {
        return Err(AescryptError::Header(
            "v3: missing final plaintext block".into(),
        ));
    }

    let padding = ctx.plaintext_block.with_secret(|block| block[15]);

    // Validate padding value range (non-secret, can be early return)
    if padding == 0 || padding > 16 {
        return Err(AescryptError::Header("v3: invalid PKCS#7 padding".into()));
    }

    // Constant-time validation: build expected block = data bytes || padding bytes,
    // then compare the full 16-byte block in one constant-time operation.
    let padding_start = 16 - padding as usize;
    let mut expected_block = [0u8; 16];
    ctx.plaintext_block.with_secret(|block| {
        expected_block[..padding_start].copy_from_slice(&block[..padding_start]);
    });
    expected_block[padding_start..].fill(padding);

    let expected_fixed = Block16::from(expected_block);
    let padding_valid = ctx.plaintext_block.ct_eq(&expected_fixed);
    if !padding_valid {
        return Err(AescryptError::Header("v3: invalid PKCS#7 padding".into()));
    }

    ctx.plaintext_block
        .with_secret(|block| output.write_all(&block[..16 - padding as usize]))?;
    Ok(())
}
