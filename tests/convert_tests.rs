//! tests/convert_tests.rs
//! Comprehensive legacy (v0/v1/v2) → v3 conversion test suite
//!
//! - Real 300,000 PBKDF2 iterations in release mode
//! - 64 iterations in debug for speed
//! - 63 official vectors + random generation + empty-string trigger
//! - Bit-perfect round-trip verification

use aescrypt_rs::aliases::PasswordString;
use aescrypt_rs::{convert_to_v3, decrypt, encrypt};
use hex::decode;
use serde::Deserialize;
use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};
use std::time::Instant;

const REAL_WORLD_ITERATIONS: u32 = 300_000;
const DEBUG_ITERATIONS: u32 = 64;
const TEST_KDF_ITERATIONS: u32 = if cfg!(debug_assertions) {
    DEBUG_ITERATIONS
} else {
    REAL_WORLD_ITERATIONS
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AescryptVersion {
    V0,
    V1,
    V2,
}

impl AescryptVersion {
    const fn name(self) -> &'static str {
        match self {
            Self::V0 => "v0",
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

// —————————————————————————————————————————————————————————————————————————————
// 1. All 63 official vectors — bit-perfect round-trip (same password)
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_preserves_content_perfectly() {
    println!("\nStarting legacy → v3 conversion test suite");
    println!(
        "PBKDF2 iterations: {} ({})",
        TEST_KDF_ITERATIONS,
        if cfg!(debug_assertions) {
            "debug → fast"
        } else {
            "release → real security"
        }
    );

    let password = PasswordString::new("Hello".to_string());

    for version in [
        AescryptVersion::V0,
        AescryptVersion::V1,
        AescryptVersion::V2,
    ] {
        let vectors: Vec<DecryptVector> =
            load_json(&format!("test_vectors_{}.json", version.name()));
        println!("Loaded {} vectors for {}", vectors.len(), version.name());

        for (i, v) in vectors.iter().enumerate() {
            let start = Instant::now();
            let legacy_ciphertext = decode(&v.ciphertext_hex).expect("invalid hex").clone(); // Clone to own for 'static

            let writer = ThreadSafeVec::new();
            convert_to_v3(
                Cursor::new(legacy_ciphertext),
                writer.clone(),
                &password,
                Some(&password), // keep same password
                TEST_KDF_ITERATIONS,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "convert_to_v3 failed on {} vector {i}: {e:?}",
                    version.name()
                )
            });

            let v3_file = writer.into_inner();

            let mut recovered = Vec::new();
            decrypt(Cursor::new(&v3_file), &mut recovered, &password).unwrap_or_else(|e| {
                panic!(
                    "decrypt failed on converted {} vector {i}: {e:?}",
                    version.name()
                )
            });

            assert_eq!(
                recovered,
                v.plaintext.as_bytes(),
                "BIT-PERFECT round-trip failed on {} vector {i}",
                version.name()
            );

            println!(
                "[{}] vector {i:>2} OK → {} → {} bytes in {:.2?}",
                version.name(),
                v.plaintext.len(),
                v3_file.len(),
                start.elapsed()
            );
        }
    }

    println!("\nAll 63 legacy files converted to v3 with bit-perfect round-trip!");
}

// —————————————————————————————————————————————————————————————————————————————
// 2. Random password generation (None + Some("")) → 256-bit hex, 1 iteration
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_random_password_works() {
    let old_pw = PasswordString::new("weak123".to_string());
    let plaintext = b"Upgrade me to quantum-resistant!";

    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 1000).unwrap();

    // Test both None and Some("")
    for new_pw_opt in [
        None,
        Some(PasswordString::new(String::new())), // "" → trigger random
    ] {
        let writer = ThreadSafeVec::new();

        let generated = convert_to_v3(
            Cursor::new(legacy.clone()), // Clone to own for 'static
            writer.clone(),
            &old_pw,
            new_pw_opt.as_ref(), // ← &Option<PasswordString>
            300_000,
        )
        .unwrap();

        let new_pw = generated.expect("should have generated a password");
        assert_eq!(new_pw.expose_secret().len(), 64);
        assert!(new_pw
            .expose_secret()
            .chars()
            .all(|c| c.is_ascii_hexdigit()));

        let v3_file = writer.into_inner();
        let mut recovered = Vec::new();
        decrypt(Cursor::new(&v3_file), &mut recovered, &new_pw).unwrap();
        assert_eq!(&recovered, plaintext);
    }
}

// —————————————————————————————————————————————————————————————————————————————
// 3. Explicit new password → full iterations
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_explicit_new_password_works() {
    let old_pw = PasswordString::new("old123".to_string());
    let new_pw = PasswordString::new("strong-new-2025!".to_string());
    let plaintext = b"Secret message that must survive migration";

    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 1000).unwrap();

    let writer = ThreadSafeVec::new();
    let generated = convert_to_v3(
        Cursor::new(legacy.clone()), // Clone to own for 'static
        writer.clone(),
        &old_pw,
        Some(&new_pw), // ← &PasswordString
        500_000,
    )
    .unwrap();

    assert!(generated.is_none());

    let v3_file = writer.into_inner();
    let mut recovered = Vec::new();
    decrypt(Cursor::new(&v3_file), &mut recovered, &new_pw).unwrap();
    assert_eq!(&recovered, plaintext);
}

// —————————————————————————————————————————————————————————————————————————————
// Helper types
// —————————————————————————————————————————————————————————————————————————————
#[derive(Debug, Deserialize)]
struct DecryptVector {
    #[serde(alias = "encrypted_hex")]
    #[serde(alias = "ciphertext_hex")]
    ciphertext_hex: String,
    plaintext: String,
}

#[derive(Clone)]
struct ThreadSafeVec(Arc<Mutex<Vec<u8>>>);

impl ThreadSafeVec {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }
    fn into_inner(self) -> Vec<u8> {
        Arc::try_unwrap(self.0).unwrap().into_inner().unwrap()
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

fn load_json<T>(filename: &str) -> Vec<T>
where
    T: for<'de> Deserialize<'de>,
{
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vector")
        .join("data")
        .join(filename);

    let content = std::fs::read_to_string(&path).expect("failed to read test vector file");
    serde_json::from_str(&content).expect("failed to parse test vector JSON")
}
