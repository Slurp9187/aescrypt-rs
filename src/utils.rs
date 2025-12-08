//! # Utility Functions
//!
//! This module provides low-level utility functions used throughout the library
//! for password encoding and cryptographic operations.

use crate::error::AescryptError;

/// Convert UTF-8 password bytes to UTF-16LE encoding.
///
/// This function is used for ACKDF (AES Crypt Key Derivation Function) in v0-v2 files,
/// which require passwords to be encoded as UTF-16LE before hashing.
///
/// # Arguments
///
/// * `input_utf8` - UTF-8 encoded password bytes
///
/// # Returns
///
/// Returns a `Vec<u8>` containing the UTF-16LE encoded password, or an error if
/// the input is not valid UTF-8.
///
/// # Errors
///
/// Returns [`AescryptError::Crypto`] if the input is not valid UTF-8.
///
/// # Example
///
/// ```
/// use aescrypt_rs::utils::utf8_to_utf16le;
///
/// let utf8_bytes = b"Hello";
/// let utf16le = utf8_to_utf16le(utf8_bytes)?;
/// // utf16le now contains: [0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00]
/// # Ok::<(), aescrypt_rs::AescryptError>(())
/// ```
#[inline(always)]
pub fn utf8_to_utf16le(input_utf8: &[u8]) -> Result<Vec<u8>, AescryptError> {
    let utf8_str = std::str::from_utf8(input_utf8)
        .map_err(|_| AescryptError::Crypto("password is not valid UTF-8".into()))?;

    let mut output = Vec::with_capacity(utf8_str.encode_utf16().count() * 2);
    for code_unit in utf8_str.encode_utf16() {
        output.extend_from_slice(&code_unit.to_le_bytes());
    }

    Ok(output)
}

/// XOR two 16-byte blocks together, writing the result to the output buffer.
///
/// This function performs byte-wise XOR of two 16-byte blocks, which is used
/// in CBC mode encryption/decryption for chaining blocks together.
///
/// # Arguments
///
/// * `block_a` - First 16-byte block
/// * `block_b` - Second 16-byte block
/// * `output` - Output buffer (must be at least 16 bytes)
///
/// # Safety
///
/// This function assumes both input blocks and the output buffer are at least 16 bytes.
/// Calling with smaller buffers will result in undefined behavior.
///
/// # Example
///
/// ```
/// use aescrypt_rs::utils::xor_blocks;
///
/// let block_a = [0xFF; 16];
/// let block_b = [0xAA; 16];
/// let mut output = [0u8; 16];
///
/// xor_blocks(&block_a, &block_b, &mut output);
/// // output now contains: [0x55; 16] (0xFF ^ 0xAA = 0x55)
/// ```
#[inline(always)]
pub const fn xor_blocks(block_a: &[u8], block_b: &[u8], output: &mut [u8]) {
    let mut i = 0;
    while i < 16 {
        output[i] = block_a[i] ^ block_b[i];
        i += 1;
    }
}
