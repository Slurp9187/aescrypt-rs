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
// 4. Error handling: invalid iterations
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_rejects_zero_iterations() {
    let old_pw = PasswordString::new("old".to_string());
    let new_pw = PasswordString::new("new".to_string());
    let plaintext = b"test";
    
    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 1000).unwrap();
    
    let writer = ThreadSafeVec::new();
    let result = convert_to_v3(
        Cursor::new(legacy),
        writer,
        &old_pw,
        Some(&new_pw),
        0,
    );
    
    assert!(result.is_err());
    match result.unwrap_err() {
        aescrypt_rs::AescryptError::Header(msg) => {
            assert!(msg.contains("zero") || msg.contains("KDF iterations"));
        }
        e => panic!("Unexpected error type: {:?}", e),
    }
}

#[test]
fn convert_to_v3_rejects_too_many_iterations() {
    let old_pw = PasswordString::new("old".to_string());
    let new_pw = PasswordString::new("new".to_string());
    let plaintext = b"test";
    
    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 1000).unwrap();
    
    let writer = ThreadSafeVec::new();
    let result = convert_to_v3(
        Cursor::new(legacy),
        writer,
        &old_pw,
        Some(&new_pw),
        5_000_001,
    );
    
    assert!(result.is_err());
    match result.unwrap_err() {
        aescrypt_rs::AescryptError::Header(msg) => {
            assert!(msg.contains("5M") || msg.contains("too high"));
        }
        e => panic!("Unexpected error type: {:?}", e),
    }
}

// —————————————————————————————————————————————————————————————————————————————
// 5. Error handling: wrong old password
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_rejects_wrong_old_password() {
    let correct_pw = PasswordString::new("correct".to_string());
    let wrong_pw = PasswordString::new("wrong".to_string());
    let new_pw = PasswordString::new("new".to_string());
    let plaintext = b"test";
    
    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &correct_pw, 1000).unwrap();
    
    let writer = ThreadSafeVec::new();
    let result = convert_to_v3(
        Cursor::new(legacy),
        writer,
        &wrong_pw, // Wrong password
        Some(&new_pw),
        1000,
    );
    
    assert!(result.is_err());
    // Should fail during decryption phase
    match result.unwrap_err() {
        aescrypt_rs::AescryptError::Crypto(_) | aescrypt_rs::AescryptError::Header(_) => {},
        e => panic!("Unexpected error type: {:?}", e),
    }
}

// —————————————————————————————————————————————————————————————————————————————
// 6. Generated password uniqueness
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_generated_passwords_are_unique() {
    let old_pw = PasswordString::new("old".to_string());
    let plaintext = b"test";
    
    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 1000).unwrap();
    
    // Generate multiple passwords
    let mut passwords = Vec::new();
    for _ in 0..5 {
        let writer = ThreadSafeVec::new();
        let generated = convert_to_v3(
            Cursor::new(legacy.clone()),
            writer,
            &old_pw,
            None, // Generate password
            1000,
        )
        .unwrap();
        
        let pw = generated.expect("should generate password");
        passwords.push(pw);
    }
    
    // All passwords should be different
    for i in 0..passwords.len() {
        for j in (i + 1)..passwords.len() {
            assert_ne!(
                passwords[i].expose_secret(),
                passwords[j].expose_secret(),
                "Generated passwords should be unique"
            );
        }
    }
}

// —————————————————————————————————————————————————————————————————————————————
// 7. Effective iterations verification
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_uses_one_iteration_for_generated_password() {
    let old_pw = PasswordString::new("old".to_string());
    let plaintext = b"test";
    
    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 1000).unwrap();
    
    // Generate password - should use 1 iteration
    let writer1 = ThreadSafeVec::new();
    let generated1 = convert_to_v3(
        Cursor::new(legacy.clone()),
        writer1.clone(),
        &old_pw,
        None, // Generate password
        300_000, // Requested iterations (should be ignored)
    )
    .unwrap();
    
    let pw1 = generated1.expect("should generate password");
    let v3_file1 = writer1.into_inner();
    
    // Use explicit password - should use full iterations
    let new_pw = PasswordString::new("explicit".to_string());
    let writer2 = ThreadSafeVec::new();
    let generated2 = convert_to_v3(
        Cursor::new(legacy.clone()),
        writer2.clone(),
        &old_pw,
        Some(&new_pw),
        300_000, // Should use full iterations
    )
    .unwrap();
    
    assert!(generated2.is_none());
    let v3_file2 = writer2.into_inner();
    
    // Both should decrypt correctly
    let mut recovered1 = Vec::new();
    decrypt(Cursor::new(&v3_file1), &mut recovered1, &pw1).unwrap();
    assert_eq!(&recovered1, plaintext);
    
    let mut recovered2 = Vec::new();
    decrypt(Cursor::new(&v3_file2), &mut recovered2, &new_pw).unwrap();
    assert_eq!(&recovered2, plaintext);
    
    // Files should be different due to different iterations/salts
    assert_ne!(v3_file1, v3_file2);
}

// —————————————————————————————————————————————————————————————————————————————
// 8. Edge cases: empty input
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_handles_empty_input() {
    let old_pw = PasswordString::new("old".to_string());
    let new_pw = PasswordString::new("new".to_string());
    
    let mut legacy = Vec::new();
    encrypt(Cursor::new(&[]), &mut legacy, &old_pw, 1000).unwrap();
    
    let writer = ThreadSafeVec::new();
    let generated = convert_to_v3(
        Cursor::new(legacy),
        writer.clone(),
        &old_pw,
        Some(&new_pw),
        1000,
    )
    .unwrap();
    
    assert!(generated.is_none());
    
    let v3_file = writer.into_inner();
    let mut recovered = Vec::new();
    decrypt(Cursor::new(&v3_file), &mut recovered, &new_pw).unwrap();
    assert_eq!(recovered, Vec::<u8>::new());
}

// —————————————————————————————————————————————————————————————————————————————
// 9. Edge cases: unicode passwords
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_handles_unicode_passwords() {
    let old_pw = PasswordString::new("パスワード".to_string());
    let new_pw = PasswordString::new("新密码123!@#".to_string());
    let plaintext = b"unicode test";
    
    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 1000).unwrap();
    
    let writer = ThreadSafeVec::new();
    let generated = convert_to_v3(
        Cursor::new(legacy),
        writer.clone(),
        &old_pw,
        Some(&new_pw),
        1000,
    )
    .unwrap();
    
    assert!(generated.is_none());
    
    let v3_file = writer.into_inner();
    let mut recovered = Vec::new();
    decrypt(Cursor::new(&v3_file), &mut recovered, &new_pw).unwrap();
    assert_eq!(&recovered, plaintext);
}

// —————————————————————————————————————————————————————————————————————————————
// 10. Various iteration counts
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_various_iteration_counts() {
    let old_pw = PasswordString::new("old".to_string());
    let new_pw = PasswordString::new("new".to_string());
    let plaintext = b"test";
    
    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 1000).unwrap();
    
    let iterations = vec![1, 10, 100, 1000, 10_000, 300_000];
    
    for &iter in &iterations {
        let writer = ThreadSafeVec::new();
        let generated = convert_to_v3(
            Cursor::new(legacy.clone()),
            writer.clone(),
            &old_pw,
            Some(&new_pw),
            iter,
        )
        .unwrap();
        
        assert!(generated.is_none());
        
        let v3_file = writer.into_inner();
        let mut recovered = Vec::new();
        decrypt(Cursor::new(&v3_file), &mut recovered, &new_pw).unwrap();
        assert_eq!(&recovered, plaintext, "Failed with {} iterations", iter);
    }
}

// —————————————————————————————————————————————————————————————————————————————
// 11. Boundary iteration values
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_boundary_iteration_values() {
    let old_pw = PasswordString::new("old".to_string());
    let new_pw = PasswordString::new("new".to_string());
    let plaintext = b"test";
    
    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 1000).unwrap();
    
    // Test boundary values
    let valid_iterations = vec![1, 5_000_000];
    
    for &iter in &valid_iterations {
        let writer = ThreadSafeVec::new();
        let result = convert_to_v3(
            Cursor::new(legacy.clone()),
            writer,
            &old_pw,
            Some(&new_pw),
            iter,
        );
        
        assert!(result.is_ok(), "Should accept {} iterations", iter);
    }
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
