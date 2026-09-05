//! tests/encrypt_tests.rs
//! Production iteration validation test
//!
//! This minimal test suite focuses on validating production settings (300k iterations).
//! Comprehensive encryption testing is covered by vector_tests.rs.

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
    let password = "real-world-test";
    let plaintext = b"test data for real-world iteration count";

    let mut encrypted = Vec::new();
    encrypt(
        Cursor::new(plaintext),
        &mut encrypted,
        password,
        DEFAULT_PBKDF2_ITERATIONS,
    )
    .unwrap();

    let mut decrypted = Vec::new();
    decrypt(Cursor::new(&encrypted), &mut decrypted, password).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn encrypt_round_trip_with_stingy_reader() {
    let password = "stingy-read-test";
    let plaintext: Vec<u8> = (0u8..=127).collect();

    let mut encrypted = Vec::new();
    encrypt(
        StingyReader {
            inner: Cursor::new(&plaintext),
        },
        &mut encrypted,
        password,
        DEFAULT_PBKDF2_ITERATIONS,
    )
    .unwrap();

    let mut decrypted = Vec::new();
    decrypt(Cursor::new(&encrypted), &mut decrypted, password).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn decrypt_round_trip_with_stingy_reader() {
    let password = "stingy-decrypt-test";
    let plaintext: Vec<u8> = (0u8..=255).collect();

    let mut encrypted = Vec::new();
    encrypt(
        Cursor::new(&plaintext),
        &mut encrypted,
        password,
        DEFAULT_PBKDF2_ITERATIONS,
    )
    .unwrap();

    let mut decrypted = Vec::new();
    decrypt(
        StingyReader {
            inner: Cursor::new(&encrypted),
        },
        &mut decrypted,
        password,
    )
    .unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn encrypt_empty_password() {
    let empty_password = "";
    let plaintext = b"dummy data";
    let mut encrypted = Vec::new();
    let result = encrypt(
        Cursor::new(plaintext),
        &mut encrypted,
        empty_password,
        DEFAULT_PBKDF2_ITERATIONS,
    );
    match result {
        Err(AescryptError::Header(msg)) if msg == "empty password" => {}
        _ => panic!("Expected Header error with 'empty password'"),
    }
}

/// The documented memory-hygiene pattern: the caller keeps the password in a
/// zeroize-on-drop container and hands `encrypt`/`decrypt` a scoped borrow that
/// never escapes the closure. This is a compile-and-behaviour guard for the
/// examples in the crate docs — if the public signature ever stops accepting a
/// borrowed `&str`, this test breaks first.
#[test]
fn roundtrip_with_wrapped_secret_borrow() {
    use aescrypt_rs::aliases::PasswordString;
    use secure_gate::RevealSecret;

    let secret = PasswordString::new("wrapped-secret-borrow".to_string());
    let plaintext = b"test data behind a scoped borrow";

    let mut encrypted = Vec::new();
    secret
        .with_secret(|pw| {
            encrypt(
                Cursor::new(plaintext),
                &mut encrypted,
                pw,
                DEFAULT_PBKDF2_ITERATIONS,
            )
        })
        .unwrap();

    let mut decrypted = Vec::new();
    secret
        .with_secret(|pw| decrypt(Cursor::new(&encrypted), &mut decrypted, pw))
        .unwrap();

    assert_eq!(decrypted, plaintext);
}
