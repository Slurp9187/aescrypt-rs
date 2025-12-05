// tests/convert_ext_tests.rs

use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};

#[allow(deprecated)]
use aescrypt_rs::convert_to_v3;
use aescrypt_rs::{aliases::PasswordString, convert_to_v3_ext, decrypt, encrypt};

/// Thread-safe Vec<u8> writer — the ONLY thing that satisfies W: Write + 'static
#[derive(Clone)]
struct ThreadSafeVec(Arc<Mutex<Vec<u8>>>);

impl ThreadSafeVec {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    fn into_inner(self) -> Vec<u8> {
        Arc::try_unwrap(self.0).ok().unwrap().into_inner().unwrap()
    }
}

impl Write for ThreadSafeVec {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

const TEST_KDF_ITERATIONS: u32 = if cfg!(debug_assertions) { 64 } else { 300_000 };

#[test]
fn convert_to_v3_ext_reuse_password_works() {
    let old_pw = PasswordString::new("weak-legacy-pass".to_string());
    let new_pw = PasswordString::new("strong-new-pass-2025!".to_string());
    let plaintext = b"Secret message that must survive migration";

    // Create legacy file
    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 1000).unwrap();

    // THIS IS THE ONLY PATTERN THAT WORKS
    let writer = ThreadSafeVec::new();
    let generated = convert_to_v3_ext(
        Cursor::new(legacy),
        writer.clone(),
        &old_pw,
        Some(&new_pw),
        500_000,
    )
    .unwrap();

    assert!(generated.is_none());

    // Extract the written data
    let v3_output = writer.into_inner();

    let mut recovered = Vec::new();
    decrypt(Cursor::new(&v3_output), &mut recovered, &new_pw).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn convert_to_v3_ext_random_password_generates_256bit() {
    let old_pw = PasswordString::new("old123".to_string());
    let plaintext = b"Upgrade me to quantum-resistant!";

    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 1000).unwrap();

    let writer = ThreadSafeVec::new();
    let generated =
        convert_to_v3_ext(Cursor::new(legacy), writer.clone(), &old_pw, None, 300_000).unwrap();

    let new_pw = generated.expect("random password was generated");
    assert_eq!(new_pw.expose_secret().len(), 64);
    assert!(new_pw
        .expose_secret()
        .chars()
        .all(|c| c.is_ascii_hexdigit()));

    let v3_output = writer.into_inner();

    let mut recovered = Vec::new();
    decrypt(Cursor::new(&v3_output), &mut recovered, &new_pw).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
#[allow(deprecated)]
fn convert_to_v3_backward_compatibility_still_works() {
    let old_pw: PasswordString = PasswordString::new("compat-test".to_string());
    let plaintext = b"Backward compatibility is preserved";

    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 1000).unwrap();

    let writer = ThreadSafeVec::new();
    convert_to_v3(
        Cursor::new(legacy),
        writer.clone(),
        &old_pw,
        TEST_KDF_ITERATIONS,
    )
    .unwrap();

    let v3_output = writer.into_inner();

    let mut recovered = Vec::new();
    decrypt(Cursor::new(&v3_output), &mut recovered, &old_pw).unwrap();
    assert_eq!(recovered, plaintext);
}
