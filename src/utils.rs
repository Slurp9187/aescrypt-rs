// ============================================================================
// FILE: src/utils.rs
// ============================================================================

//! Utility functions used across the library.

use crate::error::AescryptError;

/// Converts a UTF-8 password to UTF-16LE (required for ACKDF).
pub fn utf8_to_utf16le(input_utf8: &[u8]) -> Result<Vec<u8>, AescryptError> {
    let utf8_str = std::str::from_utf8(input_utf8)
        .map_err(|_| AescryptError::Crypto("input is not valid UTF-8".into()))?;
    let mut output = Vec::with_capacity(utf8_str.encode_utf16().count() * 2);
    for code_unit in utf8_str.encode_utf16() {
        output.extend_from_slice(&code_unit.to_le_bytes());
    }
    Ok(output)
}

/// XORs two 16-byte blocks and writes the result to `output`.
#[inline(always)]
pub const fn xor_blocks(block_a: &[u8], block_b: &[u8], output: &mut [u8]) {
    let mut i = 0;
    while i < 16 {
        output[i] = block_a[i] ^ block_b[i];
        i += 1;
    }
}
