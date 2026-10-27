//! src/decryption/stream/trailer.rs
//! Trailer processing — HMAC extraction and final block writing
//! All round-trip and deterministic tests pass
//! HMAC verification lives in versions.rs as `verify_payload_hmac`

use crate::aliases::{Block16, Trailer32};
use crate::decryption::stream::context::DecryptionContext;
use crate::error::AescryptError;
use secure_gate::{ConstantTimeEq, RevealSecret, RevealSecretMut};
use std::io::Write;

/// Extracts the 32-byte HMAC trailer (v0 and v3): the whole carry left after
/// the loop, which the caller has checked is 32 bytes.
#[inline(always)]
pub(crate) fn extract_hmac_simple(ctx: &DecryptionContext) -> Trailer32 {
    let mut expected = Trailer32::new([0u8; 32]);
    ctx.with_trailer(|t| expected.with_secret_mut(|e| e.copy_from_slice(&t[..32])));
    expected
}

/// Extracts the modulo byte and the 32-byte HMAC (v1/v2 only): byte 0 of the
/// 33-byte carry is the modulo, bytes 1–32 the HMAC.
#[inline(always)]
pub(crate) fn extract_hmac_scattered(ctx: &DecryptionContext) -> (Trailer32, u8) {
    let mut expected = Trailer32::new([0u8; 32]);
    let modulo_byte = ctx.with_trailer(|t| {
        expected.with_secret_mut(|e| e.copy_from_slice(&t[1..33]));
        t[0]
    });
    (expected, modulo_byte)
}

/// Write final plaintext block using legacy modulo padding (v0, v1, v2)
#[inline(always)]
pub(crate) fn write_final_modulo<W: Write>(
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
pub(crate) fn write_final_pkcs7<W: Write>(
    ctx: &DecryptionContext,
    output: &mut W,
) -> Result<(), AescryptError> {
    let data_len = validate_final_pkcs7(ctx)?;
    ctx.plaintext_block
        .with_secret(|block| output.write_all(&block[..data_len]))?;
    Ok(())
}

/// Checks the PKCS#7 padding of the final plaintext block (v3 only) and
/// returns how many of its bytes are data. Writes nothing.
///
/// # Errors
///
/// [`AescryptError::Header`] when there is no final block
/// (`"v3: missing final plaintext block"`) or its padding is invalid
/// (`"v3: invalid PKCS#7 padding"`).
#[inline(always)]
pub(crate) fn validate_final_pkcs7(ctx: &DecryptionContext) -> Result<usize, AescryptError> {
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
    // Built inside the wrapper, so the copied plaintext bytes never sit in a
    // plain stack array that outlives the comparison.
    let padding_start = 16 - padding as usize;
    let mut expected_fixed = Block16::new([0u8; 16]);
    expected_fixed.with_secret_mut(|expected| {
        ctx.plaintext_block.with_secret(|block| {
            expected[..padding_start].copy_from_slice(&block[..padding_start]);
        });
        expected[padding_start..].fill(padding);
    });
    let padding_valid = ctx.plaintext_block.ct_eq(&expected_fixed);
    if !padding_valid {
        return Err(AescryptError::Header("v3: invalid PKCS#7 padding".into()));
    }

    Ok(padding_start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aliases::Iv16;

    /// Runs `write_final_pkcs7` on a context whose final decrypted block is
    /// `block`, returning what it wrote or the error message.
    fn final_block(block: [u8; 16]) -> Result<Vec<u8>, String> {
        let mut ctx = DecryptionContext::new_with_iv(&Iv16::new([0u8; 16]));
        ctx.plaintext_block = Block16::new(block);
        ctx.need_write_plaintext = true;
        let mut out = Vec::new();
        match write_final_pkcs7(&ctx, &mut out) {
            Ok(()) => Ok(out),
            Err(AescryptError::Header(msg)) => Err(msg),
            Err(e) => Err(format!("unexpected error: {e}")),
        }
    }

    /// Valid padding strips exactly the padding bytes, for every length.
    #[test]
    fn valid_padding_is_stripped() {
        for pad in 1..=16u8 {
            let data_len = 16 - pad as usize;
            let mut block = [0xAB; 16];
            block[data_len..].fill(pad);
            assert_eq!(
                final_block(block).unwrap(),
                vec![0xAB; data_len],
                "pad {pad}"
            );
        }
    }

    /// Out-of-range padding values are rejected before the comparison.
    #[test]
    fn padding_value_out_of_range() {
        for last in [0u8, 17, 0xFF] {
            let mut block = [last; 16];
            block[15] = last;
            assert_eq!(
                final_block(block).unwrap_err(),
                "v3: invalid PKCS#7 padding",
                "last byte {last}"
            );
        }
    }

    /// An in-range padding value whose bytes don't all match fails the
    /// constant-time comparison against the block built in `expected_fixed`,
    /// and nothing is written.
    #[test]
    fn padding_bytes_inconsistent() {
        // Claims 4 padding bytes, but one of them is wrong.
        let mut block = [0x11; 16];
        block[12..].copy_from_slice(&[4, 4, 3, 4]);
        assert_eq!(
            final_block(block).unwrap_err(),
            "v3: invalid PKCS#7 padding"
        );

        // Claims a full block of padding, but the first byte differs.
        let mut block = [16u8; 16];
        block[0] = 15;
        assert_eq!(
            final_block(block).unwrap_err(),
            "v3: invalid PKCS#7 padding"
        );
    }

    /// No final block at all is its own error.
    #[test]
    fn missing_final_block() {
        let ctx = DecryptionContext::new_with_iv(&Iv16::new([0u8; 16]));
        let err = write_final_pkcs7(&ctx, &mut Vec::new()).unwrap_err();
        assert!(
            matches!(err, AescryptError::Header(m) if m == "v3: missing final plaintext block")
        );
    }
}
