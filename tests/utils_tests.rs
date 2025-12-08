//! tests/utils_tests.rs
//! Unit tests for utility functions

use aescrypt_rs::utils::{utf8_to_utf16le, xor_blocks};
use aescrypt_rs::AescryptError;

#[test]
fn utf8_to_utf16le_ascii() {
    let input = b"hello";
    let result = utf8_to_utf16le(input).unwrap();
    
    // "hello" in UTF-16LE: h(0x68,0x00) e(0x65,0x00) l(0x6C,0x00) l(0x6C,0x00) o(0x6F,0x00)
    let expected = vec![0x68, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00];
    assert_eq!(result, expected);
}

#[test]
fn utf8_to_utf16le_empty() {
    let input = b"";
    let result = utf8_to_utf16le(input).unwrap();
    assert_eq!(result, Vec::<u8>::new());
}

#[test]
fn utf8_to_utf16le_unicode() {
    let input = "パスワード".as_bytes();
    let result = utf8_to_utf16le(input).unwrap();
    
    // Should be valid UTF-16LE encoding
    assert!(!result.is_empty());
    assert_eq!(result.len() % 2, 0, "UTF-16LE should have even length");
    
    // Verify we can decode it back
    let utf16: Vec<u16> = result
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    let decoded = String::from_utf16(&utf16).unwrap();
    assert_eq!(decoded, "パスワード");
}

#[test]
fn utf8_to_utf16le_emoji() {
    let input = "🔐💻".as_bytes();
    let result = utf8_to_utf16le(input).unwrap();
    
    // Emojis are surrogate pairs in UTF-16
    assert!(!result.is_empty());
    assert_eq!(result.len() % 2, 0);
    
    // Verify we can decode it back
    let utf16: Vec<u16> = result
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    let decoded = String::from_utf16(&utf16).unwrap();
    assert_eq!(decoded, "🔐💻");
}

#[test]
fn utf8_to_utf16le_invalid_utf8() {
    // Invalid UTF-8 sequence
    let input = &[0xFF, 0xFE, 0xFD];
    let result = utf8_to_utf16le(input);
    
    assert!(result.is_err());
    match result.unwrap_err() {
        AescryptError::Crypto(msg) => {
            assert!(msg.contains("UTF-8") || msg.contains("password"));
        }
        e => panic!("Unexpected error type: {:?}", e),
    }
}

#[test]
fn utf8_to_utf16le_partial_utf8() {
    // Partial UTF-8 sequence (incomplete multi-byte character)
    let input = &[0xE2, 0x82]; // Incomplete 3-byte sequence
    let result = utf8_to_utf16le(input);
    
    assert!(result.is_err());
}

#[test]
fn utf8_to_utf16le_various_unicode() {
    let test_cases = vec![
        "A",
        "AB",
        "Hello",
        "中文", // Chinese characters
        "русский", // Cyrillic
        "🌍", // Emoji
        "test123!@#",
    ];
    
    for input_str in test_cases {
        let input = input_str.as_bytes();
        let result = utf8_to_utf16le(input).unwrap();
        
        // Verify it's valid UTF-16LE by decoding it back
        assert_eq!(result.len() % 2, 0, "UTF-16LE should have even length for: {}", input_str);
        let utf16: Vec<u16> = result
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        let decoded = String::from_utf16(&utf16).unwrap();
        assert_eq!(decoded, input_str, "Round-trip failed for: {}", input_str);
    }
}

#[test]
fn utf8_to_utf16le_special_chars() {
    let input = "!@#$%^&*()_+-=[]{}|;':\",./<>?".as_bytes();
    let result = utf8_to_utf16le(input).unwrap();
    
    // All ASCII special chars should encode to their ASCII value + 0x00
    assert_eq!(result.len(), input.len() * 2);
    for (i, &byte) in input.iter().enumerate() {
        assert_eq!(result[i * 2], byte);
        assert_eq!(result[i * 2 + 1], 0x00);
    }
}

#[test]
fn xor_blocks_basic() {
    let block_a = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    let block_b = [0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF];
    let mut output = [0u8; 16];
    
    xor_blocks(&block_a, &block_b, &mut output);
    
    let expected = [
        0x00 ^ 0xF0, 0x01 ^ 0xF1, 0x02 ^ 0xF2, 0x03 ^ 0xF3,
        0x04 ^ 0xF4, 0x05 ^ 0xF5, 0x06 ^ 0xF6, 0x07 ^ 0xF7,
        0x08 ^ 0xF8, 0x09 ^ 0xF9, 0x0A ^ 0xFA, 0x0B ^ 0xFB,
        0x0C ^ 0xFC, 0x0D ^ 0xFD, 0x0E ^ 0xFE, 0x0F ^ 0xFF,
    ];
    assert_eq!(output, expected);
}

#[test]
fn xor_blocks_zeros() {
    let block_a = [0u8; 16];
    let block_b = [0xFFu8; 16];
    let mut output = [0u8; 16];
    
    xor_blocks(&block_a, &block_b, &mut output);
    
    assert_eq!(output, [0xFFu8; 16]);
}

#[test]
fn xor_blocks_identity() {
    let block = [0x42u8; 16];
    let zeros = [0u8; 16];
    let mut output = [0u8; 16];
    
    xor_blocks(&block, &zeros, &mut output);
    
    assert_eq!(output, block);
}

#[test]
fn xor_blocks_self_xor() {
    let block = [0x55u8; 16];
    let mut output = [0u8; 16];
    
    xor_blocks(&block, &block, &mut output);
    
    // XORing with itself should produce zeros
    assert_eq!(output, [0u8; 16]);
}

#[test]
fn xor_blocks_commutative() {
    let block_a = [0xAAu8; 16];
    let block_b = [0x55u8; 16];
    let mut output1 = [0u8; 16];
    let mut output2 = [0u8; 16];
    
    xor_blocks(&block_a, &block_b, &mut output1);
    xor_blocks(&block_b, &block_a, &mut output2);
    
    // XOR is commutative
    assert_eq!(output1, output2);
}

#[test]
fn xor_blocks_patterns() {
    // Test various patterns
    let patterns = vec![
        ([0x00u8; 16], [0xFFu8; 16], [0xFFu8; 16]),
        ([0xFFu8; 16], [0xFFu8; 16], [0x00u8; 16]),
        ([0xAAu8; 16], [0x55u8; 16], [0xFFu8; 16]),
        ([0x55u8; 16], [0xAAu8; 16], [0xFFu8; 16]),
    ];
    
    for (block_a, block_b, expected) in patterns {
        let mut output = [0u8; 16];
        xor_blocks(&block_a, &block_b, &mut output);
        assert_eq!(output, expected);
    }
}

#[test]
fn xor_blocks_incremental() {
    let mut block_a = [0u8; 16];
    let block_b = [1u8; 16];
    let mut output = [0u8; 16];
    
    // Initialize block_a with incrementing values
    for i in 0..16 {
        block_a[i] = i as u8;
    }
    
    xor_blocks(&block_a, &block_b, &mut output);
    
    // Each byte should be XORed with 1
    for i in 0..16 {
        assert_eq!(output[i], (i as u8) ^ 1);
    }
}

#[test]
fn xor_blocks_reversible() {
    let original = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let key = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
    let mut encrypted = [0u8; 16];
    let mut decrypted = [0u8; 16];
    
    // Encrypt: original XOR key
    xor_blocks(&original, &key, &mut encrypted);
    
    // Decrypt: encrypted XOR key (should get original back)
    xor_blocks(&encrypted, &key, &mut decrypted);
    
    assert_eq!(decrypted, original);
}

