//! Low-level utility functions used by the encryption and decryption pipelines.
//!
//! Most callers will not need anything from this module directly; the helpers
//! are exposed because they are useful when composing custom v0–v2 read flows
//! ([`utf8_to_utf16le`]) or custom CBC pipelines ([`xor_blocks`]).

use crate::error::AescryptError;

/// Re-encodes UTF-8 password bytes as a UTF-16-LE byte vector.
///
/// AES Crypt v0–v2 ACKDF hashes passwords as little-endian UTF-16 code units;
/// this helper performs the conversion inside [`crate::derive_ackdf_key`] but
/// is also useful for callers building custom legacy decryption flows.
///
/// The output `Vec<u8>` length is always twice the number of UTF-16 code units
/// produced from `input_utf8` — i.e. **bytes**, not code units.
///
/// # Errors
///
/// - [`AescryptError::Crypto`] — `input_utf8` is not valid UTF-8.
///
/// # Panics
///
/// Never panics.
///
/// # Security
///
/// Returns a plain `Vec<u8>` (not a [`secure-gate`] alias). When this function
/// is called from [`crate::derive_ackdf_key`] the output is immediately wrapped
/// in `Dynamic<Vec<u8>>`. External callers that pass through real passwords
/// should also wrap the output in a zeroizing container before letting it
/// drop, otherwise the UTF-16-LE password copy lingers on the heap until the
/// allocator overwrites it.
///
/// # Examples
///
/// ```
/// use aescrypt_rs::utilities::utf8_to_utf16le;
///
/// let utf8_bytes = b"Hello";
/// let utf16le = utf8_to_utf16le(utf8_bytes)?;
/// assert_eq!(
///     utf16le,
///     [0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00]
/// );
/// # Ok::<(), aescrypt_rs::AescryptError>(())
/// ```
///
/// [`secure-gate`]: https://github.com/Slurp9187/secure-gate
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

/// XORs the first 16 bytes of `block_a` and `block_b` into the first 16 bytes
/// of `output`.
///
/// Used by both encryption and decryption paths for AES-CBC chaining. The
/// fixed length of 16 makes this function easy to inline as a tight loop on
/// every supported target.
///
/// # Errors
///
/// Infallible.
///
/// # Panics
///
/// Panics if any of `block_a`, `block_b`, or `output` is shorter than 16
/// bytes (Rust's normal slice-bounds panic; this is **not** undefined
/// behavior).
///
/// # Compatibility
///
/// This function is `pub fn`, **not** `pub const fn`, because the MSRV (1.70)
/// does not yet stabilize mutable references in `const fn` for this access
/// pattern. The signature is intentionally identical to the eventual `const`
/// variant so the change can land as a non-breaking minor upgrade once MSRV
/// is bumped. See `CHANGELOG.md` (0.2.0-rc.8) for the rationale.
///
/// # Examples
///
/// ```
/// use aescrypt_rs::utilities::xor_blocks;
///
/// let block_a = [0xFF; 16];
/// let block_b = [0xAA; 16];
/// let mut output = [0u8; 16];
///
/// xor_blocks(&block_a, &block_b, &mut output);
/// assert_eq!(output, [0x55; 16]); // 0xFF ^ 0xAA = 0x55
/// ```
#[inline(always)]
pub fn xor_blocks(block_a: &[u8], block_b: &[u8], output: &mut [u8]) {
    let mut i = 0;
    while i < 16 {
        output[i] = block_a[i] ^ block_b[i];
        i += 1;
    }
}

#[inline(always)]
pub(crate) fn read_until_full<R: std::io::Read>(
    reader: &mut R,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(k) => total += k,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}
