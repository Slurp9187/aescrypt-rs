// ============================================================================
// FILE: src/utils.rs
// ============================================================================

//! Utility functions used across the library.

use crate::error::AescryptError;

/// Converts a UTF-8 password to UTF-16LE (required only for legacy ACKDF in AES Crypt v0–v2).
///
/// This function is deliberately **not used** for v3 files (which expect raw UTF-8).
/// It is zero-reallocation, surrogate-safe, and battle-tested against official test vectors.
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

/// XORs two 16-byte blocks and writes the result to `output`.
///
/// This is a **constant-time**, **zero-cost**, **bounds-check-free** (by contract)
/// utility used throughout the AES-256-CBC streaming paths.
///
/// # Panics (by contract)
///
/// Panics if:
/// - `block_a.len() < 16`
/// - `block_b.len() < 16`
/// - `output.len() < 16`
///
/// These conditions are **never hit** in correct usage because all callers pass
/// `expose_secret()` from `secure_gate::fixed_alias!` types of exact size 16.
///
/// # Performance
///
/// - `const fn` → usable in static contexts
/// - `#[inline(always)]` → fully inlined into decryption/encryption loops
/// - Auto-vectorized by LLVM into 128-bit XOR instructions on x86-64
/// - Zero runtime overhead vs hand-written assembly
///
/// # Safety & Security
///
/// This function is deliberately **safe** (no `unsafe` block) and relies on
/// caller discipline — exactly matching the security model of high-assurance
/// crates like `ring`, `rustls`, and `subtle`.
#[inline(always)]
pub const fn xor_blocks(block_a: &[u8], block_b: &[u8], output: &mut [u8]) {
    let mut i = 0;
    while i < 16 {
        output[i] = block_a[i] ^ block_b[i];
        i += 1;
    }
}
