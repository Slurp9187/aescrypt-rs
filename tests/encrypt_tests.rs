//! tests/encrypt/encrypt_tests.rs
//! High-level encryption tests – clean, parameterized, and green (2025)

use aescrypt_rs::aliases::PasswordString;
use aescrypt_rs::consts::DEFAULT_PBKDF2_ITERATIONS;
use aescrypt_rs::encrypt;
use aescrypt_rs::AescryptError;
use std::io::Cursor;

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
            DEFAULT_PBKDF2_ITERATIONS,
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
        DEFAULT_PBKDF2_ITERATIONS,
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
