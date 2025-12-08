//! src/decryptor/stream/trailer.rs
//! Trailer processing — HMAC extraction and final block writing
//! All round-trip and deterministic tests pass
//! No verify_hmac helper — we use the exact same pattern as encrypt_stream

use crate::aliases::Trailer32;
use crate::decryptor::stream::context::DecryptionContext;
use crate::error::AescryptError;
use secure_gate::conversions::SecureConversionsExt;
use std::io::Write;

/// Extract 32-byte HMAC using simple wrap-around (used by v0 and v3)
#[inline(always)]
pub fn extract_hmac_simple(ctx: &DecryptionContext) -> Trailer32 {
    let mut expected = Trailer32::new([0u8; 32]);
    let ring = ctx.ring_buffer.expose_secret();
    for (i, byte) in expected.expose_secret_mut().iter_mut().enumerate() {
        *byte = ring[(ctx.tail_index + i) % 64];
    }
    expected
}

/// Extract 32-byte HMAC + modulo byte using scattered layout (v1/v2 only)
#[inline(always)]
pub fn extract_hmac_scattered(ctx: &DecryptionContext) -> (Trailer32, u8) {
    let ring = ctx.ring_buffer.expose_secret();
    let modulo_byte = ring[ctx.tail_index];

    let mut expected = Trailer32::new([0u8; 32]);

    // First 15 bytes: tail+1 → tail+15
    let start1 = (ctx.tail_index + 1) % 64;
    expected.expose_secret_mut()[..15].copy_from_slice(&ring[start1..start1 + 15]);

    // Next 16 bytes: tail+16 → tail+31
    let start2 = (ctx.tail_index + 16) % 64;
    expected.expose_secret_mut()[15..31].copy_from_slice(&ring[start2..start2 + 16]);

    // Final byte: tail+32
    expected.expose_secret_mut()[31] = ring[(ctx.tail_index + 32) % 64];

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
        output.write_all(&ctx.plaintext_block.expose_secret()[..len])?;
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

    let block = ctx.plaintext_block.expose_secret();
    let padding = block[15];

    // Validate padding value range (non-secret, can be early return)
    if padding == 0 || padding > 16 {
        return Err(AescryptError::Header("v3: invalid PKCS#7 padding".into()));
    }

    // Constant-time validation: compare expected padding bytes with actual
    let padding_start = 16 - padding as usize;
    let expected_padding = [padding; 16];
    let actual_padding_slice = &block[padding_start..];
    let expected_padding_slice = &expected_padding[padding_start..];

    if !actual_padding_slice.ct_eq(expected_padding_slice) {
        return Err(AescryptError::Header("v3: corrupt PKCS#7 padding".into()));
    }

    output.write_all(&block[..16 - padding as usize])?;
    Ok(())
}

