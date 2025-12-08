//! tests/encrypt/encrypt_tests.rs
//! High-level encryption tests – clean, parameterized, and green (2025)

use aescrypt_rs::aliases::PasswordString;
use aescrypt_rs::consts::DEFAULT_PBKDF2_ITERATIONS;
use aescrypt_rs::decrypt;
use aescrypt_rs::encrypt;
use aescrypt_rs::AescryptError;
use std::io::Cursor;

// Fast iteration count for tests - performance testing is in benches/
const TEST_ITERATIONS: u32 = 5;

#[test]
fn encrypt_v3_basics() {
    let password = PasswordString::new("password".to_string());

    // Pre-allocate the large buffer so it lives long enough
    let large_100kb = vec![0x41u8; 100_000];

    let cases = vec![
        (&[] as &[u8], true, 100, 220, "empty input"),
        (b"Hello, World!" as &[u8], true, 140, 220, "small input"),
        (
            &large_100kb as &[u8],
            true,
            100_000,
            100_512,
            "large input (100 KB)",
        ),
    ];

    for (plaintext, check_header, min_size, max_size, desc) in cases {
        let mut encrypted = Vec::new();
        encrypt(
            Cursor::new(plaintext),
            &mut encrypted,
            &password,
            TEST_ITERATIONS,
        )
        .unwrap_or_else(|e| panic!("Encryption failed for {desc}: {e:?}"));

        if check_header {
            assert_eq!(&encrypted[0..3], b"AES", "{desc}: invalid magic");
            assert_eq!(encrypted[3], 3, "{desc}: invalid version");
            assert_eq!(encrypted[4], 0x00, "{desc}: invalid reserved");
        }

        let len = encrypted.len();
        assert!(
            len >= min_size && len <= max_size,
            "{desc}: unreasonable size ({len} bytes)"
        );
    }
}

#[test]
fn encrypt_unicode_password() {
    let password = PasswordString::new("パスワード123!@#".to_string());
    let mut encrypted = Vec::new();

    encrypt(
        Cursor::new(b"unicode test"),
        &mut encrypted,
        &password,
        TEST_ITERATIONS,
    )
    .unwrap();

    assert!(!encrypted.is_empty());
}

#[test]
fn encrypt_invalid_iterations() {
    let password = PasswordString::new("invalid-iter".to_string());
    let plaintext = b"test";

    // Zero iterations → Header error
    let err = encrypt(Cursor::new(plaintext), &mut Vec::new(), &password, 0).unwrap_err();
    assert!(matches!(err, AescryptError::Header(_)));

    // Too many iterations → Header error
    let err = encrypt(
        Cursor::new(plaintext),
        &mut Vec::new(),
        &password,
        5_000_001,
    )
    .unwrap_err();
    assert!(matches!(err, AescryptError::Header(_)));
}

#[test]
fn encrypt_empty_password() {
    let password = PasswordString::new(String::new());
    let plaintext = b"test";
    
    let err = encrypt(Cursor::new(plaintext), &mut Vec::new(), &password, 5).unwrap_err();
    assert!(matches!(err, AescryptError::Header(_)));
    assert!(err.to_string().contains("empty password") || err.to_string().contains("password"));
}

#[test]
fn encrypt_roundtrip() {
    use aescrypt_rs::decrypt;
    
    let password = PasswordString::new("roundtrip-test".to_string());
    let plaintext = b"Hello, encrypted world!";
    
    let mut encrypted = Vec::new();
    encrypt(
        Cursor::new(plaintext),
        &mut encrypted,
        &password,
        TEST_ITERATIONS,
    )
    .unwrap();
    
    let mut decrypted = Vec::new();
    decrypt(Cursor::new(&encrypted), &mut decrypted, &password).unwrap();
    
    assert_eq!(decrypted, plaintext);
}

#[test]
fn encrypt_determinism_different_outputs() {
    // Same input should produce different outputs due to random IVs/keys
    let password = PasswordString::new("determinism".to_string());
    let plaintext = b"same input";
    
    let mut encrypted1 = Vec::new();
    encrypt(
        Cursor::new(plaintext),
        &mut encrypted1,
        &password,
        TEST_ITERATIONS,
    )
    .unwrap();
    
    let mut encrypted2 = Vec::new();
    encrypt(
        Cursor::new(plaintext),
        &mut encrypted2,
        &password,
        TEST_ITERATIONS,
    )
    .unwrap();
    
    // Outputs should be different (due to random IVs/session keys)
    assert_ne!(encrypted1, encrypted2, "Same input should produce different encrypted output");
    
    // But both should decrypt to same plaintext
    use aescrypt_rs::decrypt;
    let mut decrypted1 = Vec::new();
    let mut decrypted2 = Vec::new();
    decrypt(Cursor::new(&encrypted1), &mut decrypted1, &password).unwrap();
    decrypt(Cursor::new(&encrypted2), &mut decrypted2, &password).unwrap();
    
    assert_eq!(decrypted1, plaintext);
    assert_eq!(decrypted2, plaintext);
}

#[test]
fn encrypt_different_passwords_produce_different_outputs() {
    let password1 = PasswordString::new("password1".to_string());
    let password2 = PasswordString::new("password2".to_string());
    let plaintext = b"same plaintext";
    
    let mut encrypted1 = Vec::new();
    encrypt(
        Cursor::new(plaintext),
        &mut encrypted1,
        &password1,
        TEST_ITERATIONS,
    )
    .unwrap();
    
    let mut encrypted2 = Vec::new();
    encrypt(
        Cursor::new(plaintext),
        &mut encrypted2,
        &password2,
        TEST_ITERATIONS,
    )
    .unwrap();
    
    // Different passwords should produce different outputs
    assert_ne!(encrypted1, encrypted2);
}

// Note: Block boundary and iteration count tests are in vector_tests.rs
// to avoid duplication. See roundtrip_block_boundary_sizes and roundtrip_various_kdf_iterations

#[test]
fn encrypt_header_structure() {
    let password = PasswordString::new("header-test".to_string());
    let plaintext = b"test";
    
    let mut encrypted = Vec::new();
    encrypt(
        Cursor::new(plaintext),
        &mut encrypted,
        &password,
        TEST_ITERATIONS,
    )
    .unwrap();
    
    // Verify header structure
    assert!(encrypted.len() >= 5, "Should have at least header (5 bytes)");
    assert_eq!(&encrypted[0..3], b"AES", "Invalid magic");
    assert_eq!(encrypted[3], 3, "Invalid version");
    assert_eq!(encrypted[4], 0x00, "Invalid reserved byte");
    
    // Verify extensions (2 bytes after header)
    if encrypted.len() >= 7 {
        // Extensions should be present (0x00 0x00 for v3 with no extensions)
        assert_eq!(encrypted[5], 0x00);
        assert_eq!(encrypted[6], 0x00);
    }
    
    // Verify iterations (4 bytes, big-endian)
    if encrypted.len() >= 11 {
        let iterations_bytes = &encrypted[7..11];
        let iterations = u32::from_be_bytes([
            iterations_bytes[0],
            iterations_bytes[1],
            iterations_bytes[2],
            iterations_bytes[3],
        ]);
        assert_eq!(iterations, TEST_ITERATIONS);
    }
    
    // Verify public IV (16 bytes after iterations)
    if encrypted.len() >= 27 {
        let public_iv = &encrypted[11..27];
        assert_eq!(public_iv.len(), 16, "Public IV should be 16 bytes");
    }
}

#[test]
fn encrypt_large_file() {
    use aescrypt_rs::decrypt;
    
    let password = PasswordString::new("large-file".to_string());
    // 1 MB of data
    let plaintext = vec![0x42u8; 1_000_000];
    
    let mut encrypted = Vec::new();
    encrypt(
        Cursor::new(&plaintext),
        &mut encrypted,
        &password,
        TEST_ITERATIONS,
    )
    .unwrap();
    
    // Encrypted should be larger than plaintext (due to padding, headers, HMAC)
    assert!(encrypted.len() > plaintext.len());
    
    let mut decrypted = Vec::new();
    decrypt(Cursor::new(&encrypted), &mut decrypted, &password).unwrap();
    
    assert_eq!(decrypted, plaintext);
}

#[test]
fn encrypt_various_passwords() {
    use aescrypt_rs::decrypt;
    
    let plaintext = b"test data";
    let passwords = vec![
        PasswordString::new("simple".to_string()),
        PasswordString::new("complex!@#$%^&*()".to_string()),
        PasswordString::new("very-long-password-that-exceeds-normal-length-expectations".to_string()),
        PasswordString::new("with\nnewlines\tand\ttabs".to_string()),
    ];
    
    for password in passwords {
        let mut encrypted = Vec::new();
        encrypt(
            Cursor::new(plaintext),
            &mut encrypted,
            &password,
            TEST_ITERATIONS,
        )
        .unwrap();
        
        let mut decrypted = Vec::new();
        decrypt(Cursor::new(&encrypted), &mut decrypted, &password).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }
}

#[test]
fn encrypt_with_real_world_iterations() {
    // Test with real-world DEFAULT_PBKDF2_ITERATIONS (300,000) to verify production settings work
    let password = PasswordString::new("real-world-test".to_string());
    let plaintext = b"test data for real-world iteration count";
    
    let mut encrypted = Vec::new();
    encrypt(
        Cursor::new(plaintext),
        &mut encrypted,
        &password,
        DEFAULT_PBKDF2_ITERATIONS,
    )
    .unwrap();
    
    let mut decrypted = Vec::new();
    decrypt(Cursor::new(&encrypted), &mut decrypted, &password).unwrap();
    
    assert_eq!(decrypted, plaintext);
}