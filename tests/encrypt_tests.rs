//! tests/encrypt_tests.rs
//! Production iteration validation test
//!
//! This minimal test suite focuses on validating production settings (300k iterations).
//! Comprehensive encryption testing is covered by vector_tests.rs.

#[cfg(feature = "rand")]
use aescrypt_rs::aliases::PasswordString;
#[cfg(feature = "rand")]
use aescrypt_rs::consts::DEFAULT_PBKDF2_ITERATIONS;
#[cfg(feature = "rand")]
use aescrypt_rs::decrypt;
#[cfg(feature = "rand")]
use aescrypt_rs::encrypt;
#[cfg(feature = "rand")]
use std::io::Cursor;

#[test]
#[cfg(feature = "rand")]
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