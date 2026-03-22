//! tests/encrypt_tests.rs
//! Production iteration validation test
//!
//! This minimal test suite focuses on validating production settings (300k iterations).
//! Comprehensive encryption testing is covered by vector_tests.rs.

use aescrypt_rs::aliases::PasswordString;
use aescrypt_rs::constants::DEFAULT_PBKDF2_ITERATIONS;
use aescrypt_rs::decrypt;
use aescrypt_rs::encrypt;
use aescrypt_rs::error::AescryptError;
use std::io::{Cursor, Read, Result as IoResult};

/// `Read` adapter that returns at most one byte per call (exercises `encrypt_stream` and
/// `decrypt_cbc_loop` partial-read handling).
struct StingyReader<R> {
    inner: R,
}

impl<R: Read> Read for StingyReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut one = [0u8; 1];
        let n = self.inner.read(&mut one)?;
        if n == 0 {
            return Ok(0);
        }
        buf[0] = one[0];
        Ok(1)
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

#[test]
fn encrypt_round_trip_with_stingy_reader() {
    let password = PasswordString::new("stingy-read-test".to_string());
    let plaintext: Vec<u8> = (0u8..=127).collect();

    let mut encrypted = Vec::new();
    encrypt(
        StingyReader {
            inner: Cursor::new(&plaintext),
        },
        &mut encrypted,
        &password,
        DEFAULT_PBKDF2_ITERATIONS,
    )
    .unwrap();

    let mut decrypted = Vec::new();
    decrypt(Cursor::new(&encrypted), &mut decrypted, &password).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn decrypt_round_trip_with_stingy_reader() {
    let password = PasswordString::new("stingy-decrypt-test".to_string());
    let plaintext: Vec<u8> = (0u8..=255).collect();

    let mut encrypted = Vec::new();
    encrypt(
        Cursor::new(&plaintext),
        &mut encrypted,
        &password,
        DEFAULT_PBKDF2_ITERATIONS,
    )
    .unwrap();

    let mut decrypted = Vec::new();
    decrypt(
        StingyReader {
            inner: Cursor::new(&encrypted),
        },
        &mut decrypted,
        &password,
    )
    .unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn encrypt_empty_password() {
    let empty_password = PasswordString::new("".to_string());
    let plaintext = b"dummy data";
    let mut encrypted = Vec::new();
    let result = encrypt(
        Cursor::new(plaintext),
        &mut encrypted,
        &empty_password,
        DEFAULT_PBKDF2_ITERATIONS,
    );
    match result {
        Err(AescryptError::Header(msg)) if msg == "empty password" => {}
        _ => panic!("Expected Header error with 'empty password'"),
    }
}
