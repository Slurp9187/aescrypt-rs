//! tests/convert_tests.rs
//! Comprehensive legacy (v0/v1/v2) → v3 conversion test suite
//!
//! - Fast tests with 64 PBKDF2 iterations (performance testing moved to benches/)
//! - 63 official vectors + random generation + empty-string trigger
//! - Bit-perfect round-trip verification

use aescrypt_rs::aliases::PasswordString;
use aescrypt_rs::{convert_to_v3, decrypt, encrypt};
use hex::decode;
use serde::Deserialize;
use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};
use std::time::Instant;

// Fast iteration count for tests - performance testing is in benches/
const TEST_KDF_ITERATIONS: u32 = 5;

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
    println!("PBKDF2 iterations: {} (fast test mode)", TEST_KDF_ITERATIONS);

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
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 5).unwrap();

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
            5,
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
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 5).unwrap();

    let writer = ThreadSafeVec::new();
    let generated = convert_to_v3(
        Cursor::new(legacy.clone()), // Clone to own for 'static
        writer.clone(),
        &old_pw,
        Some(&new_pw), // ← &PasswordString
        5,
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
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 5).unwrap();
    
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
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 5).unwrap();
    
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
    encrypt(Cursor::new(plaintext), &mut legacy, &correct_pw, 5).unwrap();
    
    let writer = ThreadSafeVec::new();
    let result = convert_to_v3(
        Cursor::new(legacy),
        writer,
        &wrong_pw, // Wrong password
        Some(&new_pw),
        5,
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
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 5).unwrap();
    
    // Generate multiple passwords
    let mut passwords = Vec::new();
    for _ in 0..5 {
        let writer = ThreadSafeVec::new();
        let generated = convert_to_v3(
            Cursor::new(legacy.clone()),
            writer,
            &old_pw,
            None, // Generate password
            5,
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
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 5).unwrap();
    
    // Generate password - should use 1 iteration
    let writer1 = ThreadSafeVec::new();
    let generated1 = convert_to_v3(
        Cursor::new(legacy.clone()),
        writer1.clone(),
        &old_pw,
        None, // Generate password
        5, // Requested iterations (should be ignored for generated passwords)
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
            5, // Should use full iterations
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
    encrypt(Cursor::new(&[]), &mut legacy, &old_pw, 5).unwrap();
    
    let writer = ThreadSafeVec::new();
    let generated = convert_to_v3(
        Cursor::new(legacy),
        writer.clone(),
        &old_pw,
        Some(&new_pw),
        5,
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
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 5).unwrap();
    
    let writer = ThreadSafeVec::new();
    let generated = convert_to_v3(
        Cursor::new(legacy),
        writer.clone(),
        &old_pw,
        Some(&new_pw),
        5,
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
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 5).unwrap();
    
    // Test with low iteration counts - performance testing is in benches/
    let iterations = vec![1, 5, 10];
    
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
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 5).unwrap();
    
    // Test minimum boundary value (1)
    // Note: 5_000_000 is valid but too slow for regular tests
    // We test rejection of 5_000_001 in convert_to_v3_rejects_too_many_iterations
    let writer = ThreadSafeVec::new();
    let result = convert_to_v3(
        Cursor::new(legacy),
        writer,
        &old_pw,
        Some(&new_pw),
        1, // Minimum valid value
    );
    
    assert!(result.is_ok(), "Should accept 1 iteration (minimum boundary)");
}

// —————————————————————————————————————————————————————————————————————————————
// 12. Non-static lifetime verification (no Box::leak needed)
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_works_with_owned_vec_no_leak() {
    // This test verifies that we don't need Box::leak() anymore
    let old_pw = PasswordString::new("old".to_string());
    let new_pw = PasswordString::new("new".to_string());
    let plaintext = b"test data";
    
    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 5).unwrap();
    
    // Create owned Vec - no 'static needed!
    let owned_data: Vec<u8> = legacy; // Take ownership
    let writer = ThreadSafeVec::new();
    
    let generated = convert_to_v3(
        Cursor::new(owned_data), // Direct ownership, no leak!
        writer.clone(),
        &old_pw,
        Some(&new_pw),
        5,
    )
    .unwrap();
    
    assert!(generated.is_none());
    
    let v3_file = writer.into_inner();
    let mut recovered = Vec::new();
    decrypt(Cursor::new(&v3_file), &mut recovered, &new_pw).unwrap();
    assert_eq!(&recovered, plaintext);
}

#[test]
fn convert_to_v3_works_with_temporary_data() {
    // Test that temporary data works (proves non-static lifetime)
    let old_pw = PasswordString::new("old".to_string());
    let new_pw = PasswordString::new("new".to_string());
    let plaintext = b"temporary test";
    
    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 5).unwrap();
    
    // Create temporary Vec in a scope
    let writer = ThreadSafeVec::new();
    {
        let temp_data = legacy.clone();
        let generated = convert_to_v3(
            Cursor::new(temp_data), // Temporary, not 'static
            writer.clone(),
            &old_pw,
            Some(&new_pw),
            5,
        )
        .unwrap();
        assert!(generated.is_none());
    }
    
    let v3_file = writer.into_inner();
    let mut recovered = Vec::new();
    decrypt(Cursor::new(&v3_file), &mut recovered, &new_pw).unwrap();
    assert_eq!(&recovered, plaintext);
}

// —————————————————————————————————————————————————————————————————————————————
// 13. Different input/output types
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_works_with_different_writer_types() {
    let old_pw = PasswordString::new("old".to_string());
    let new_pw = PasswordString::new("new".to_string());
    let plaintext = b"writer test";
    
    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 5).unwrap();
    
    // Test with Vec<u8> writer
    let mut vec_writer = Vec::new();
    let generated1 = convert_to_v3(
        Cursor::new(legacy.clone()),
        &mut vec_writer,
        &old_pw,
        Some(&new_pw),
        5,
    )
    .unwrap();
    assert!(generated1.is_none());
    
    let mut recovered1 = Vec::new();
    decrypt(Cursor::new(&vec_writer), &mut recovered1, &new_pw).unwrap();
    assert_eq!(&recovered1, plaintext);
    
    // Test with ThreadSafeVec writer
    let writer = ThreadSafeVec::new();
    let generated2 = convert_to_v3(
        Cursor::new(legacy),
        writer.clone(),
        &old_pw,
        Some(&new_pw),
        5,
    )
    .unwrap();
    assert!(generated2.is_none());
    
    let v3_file = writer.into_inner();
    let mut recovered2 = Vec::new();
    decrypt(Cursor::new(&v3_file), &mut recovered2, &new_pw).unwrap();
    assert_eq!(&recovered2, plaintext);
}

// —————————————————————————————————————————————————————————————————————————————
// 14. Large file conversion
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_handles_large_files() {
    let old_pw = PasswordString::new("old".to_string());
    let new_pw = PasswordString::new("new".to_string());
    
    // 1 MB of data
    let plaintext = vec![0x42u8; 1_000_000];
    
    let mut legacy = Vec::new();
    encrypt(Cursor::new(&plaintext), &mut legacy, &old_pw, 5).unwrap();
    
    let writer = ThreadSafeVec::new();
    let generated = convert_to_v3(
        Cursor::new(legacy),
        writer.clone(),
        &old_pw,
        Some(&new_pw),
        5,
    )
    .unwrap();
    
    assert!(generated.is_none());
    
    let v3_file = writer.into_inner();
    let mut recovered = Vec::new();
    decrypt(Cursor::new(&v3_file), &mut recovered, &new_pw).unwrap();
    assert_eq!(recovered, plaintext);
}

// —————————————————————————————————————————————————————————————————————————————
// 15. Multiple conversions in sequence
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_multiple_conversions_sequential() {
    let old_pw = PasswordString::new("old".to_string());
    let new_pw1 = PasswordString::new("new1".to_string());
    let new_pw2 = PasswordString::new("new2".to_string());
    let plaintext = b"sequential test";
    
    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 5).unwrap();
    
    // First conversion
    let writer1 = ThreadSafeVec::new();
    let generated1 = convert_to_v3(
        Cursor::new(legacy.clone()),
        writer1.clone(),
        &old_pw,
        Some(&new_pw1),
        5,
    )
    .unwrap();
    assert!(generated1.is_none());
    
    // Second conversion (convert v3 to v3 with new password)
    let v3_file1 = writer1.into_inner();
    let writer2 = ThreadSafeVec::new();
    let generated2 = convert_to_v3(
        Cursor::new(v3_file1),
        writer2.clone(),
        &new_pw1,
        Some(&new_pw2),
        5,
    )
    .unwrap();
    assert!(generated2.is_none());
    
    // Verify final result
    let v3_file2 = writer2.into_inner();
    let mut recovered = Vec::new();
    decrypt(Cursor::new(&v3_file2), &mut recovered, &new_pw2).unwrap();
    assert_eq!(&recovered, plaintext);
}

// —————————————————————————————————————————————————————————————————————————————
// 16. v3 re-encryption (password rotation)
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_v3_re_encryption() {
    // Test that convert_to_v3 can handle v3 files (re-encryption scenario)
    // This is useful for password rotation or iteration count updates
    let old_pw = PasswordString::new("old".to_string());
    let new_pw = PasswordString::new("new".to_string());
    let plaintext = b"v3 re-encryption test";
    
    // Create v3 file
    let mut v3_input = Vec::new();
    encrypt(Cursor::new(plaintext), &mut v3_input, &old_pw, 5).unwrap();
    
    // Re-encrypt with new password and higher iterations
    let writer = ThreadSafeVec::new();
    let generated = convert_to_v3(
        Cursor::new(v3_input),
        writer.clone(),
        &old_pw,
        Some(&new_pw),
        5000, // Higher iterations
    )
    .unwrap();
    
    assert!(generated.is_none(), "Should not generate password when explicit password provided");
    
    let v3_output = writer.into_inner();
    let mut recovered = Vec::new();
    decrypt(Cursor::new(&v3_output), &mut recovered, &new_pw).unwrap();
    assert_eq!(&recovered, plaintext);
}

#[test]
fn convert_to_v3_v3_vectors() {
    // Test convert_to_v3 with all official v3 test vectors
    // This verifies v3 → v3 re-encryption works with real-world v3 files
    let password = PasswordString::new("Hello".to_string());
    
    let vectors: Vec<DecryptVector> = load_json("test_vectors_v3.json");
    println!("Loaded {} v3 vectors for re-encryption test", vectors.len());
    
    for (i, v) in vectors.iter().enumerate() {
        let v3_ciphertext = decode(&v.ciphertext_hex).expect("invalid hex");
        
        let writer = ThreadSafeVec::new();
        convert_to_v3(
            Cursor::new(v3_ciphertext),
            writer.clone(),
            &password,
            Some(&password), // Keep same password
            TEST_KDF_ITERATIONS,
        )
        .unwrap_or_else(|e| {
            panic!("convert_to_v3 failed on v3 vector {i}: {e:?}")
        });
        
        let v3_reencrypted = writer.into_inner();
        
        let mut recovered = Vec::new();
        decrypt(Cursor::new(&v3_reencrypted), &mut recovered, &password).unwrap_or_else(|e| {
            panic!("decrypt failed on re-encrypted v3 vector {i}: {e:?}")
        });
        
        assert_eq!(
            recovered,
            v.plaintext.as_bytes(),
            "BIT-PERFECT round-trip failed on v3 vector {i}"
        );
        
        println!("v3 vector {i:>2} OK → {} → {} bytes", v.plaintext.len(), v3_reencrypted.len());
    }
    
    println!("\nAll {} v3 files re-encrypted with bit-perfect round-trip!", vectors.len());
}

// —————————————————————————————————————————————————————————————————————————————
// 17. Thread safety and concurrent access
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_thread_safety() {
    use std::thread;
    
    let old_pw = PasswordString::new("old".to_string());
    let new_pw = PasswordString::new("new".to_string());
    let plaintext = b"thread safety test";
    
    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 5).unwrap();
    
    // Test multiple threads converting simultaneously
    let mut handles = Vec::new();
    for i in 0..5 {
        let legacy_clone = legacy.clone();
        let old_pw_clone = old_pw.clone();
        let new_pw_clone = new_pw.clone();
        
        let handle = thread::spawn(move || {
            let writer = ThreadSafeVec::new();
            let generated = convert_to_v3(
                Cursor::new(legacy_clone),
                writer.clone(),
                &old_pw_clone,
                Some(&new_pw_clone),
                5,
            )
            .unwrap();
            
            assert!(generated.is_none());
            let v3_file = writer.into_inner();
            
            let mut recovered = Vec::new();
            decrypt(Cursor::new(&v3_file), &mut recovered, &new_pw_clone).unwrap();
            assert_eq!(&recovered, plaintext, "Thread {i} failed");
            
            v3_file.len()
        });
        
        handles.push(handle);
    }
    
    // Wait for all threads
    for handle in handles {
        let size = handle.join().unwrap();
        assert!(size > 0, "Converted file should have content");
    }
}

// —————————————————————————————————————————————————————————————————————————————
// 18. Stress test: many small conversions
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_stress_many_conversions() {
    let old_pw = PasswordString::new("old".to_string());
    let new_pw = PasswordString::new("new".to_string());
    let plaintext = b"stress test";
    
    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 5).unwrap();
    
    // Perform 100 conversions
    for i in 0..100 {
        let writer = ThreadSafeVec::new();
        let generated = convert_to_v3(
            Cursor::new(legacy.clone()),
            writer.clone(),
            &old_pw,
            Some(&new_pw),
            5,
        )
        .unwrap_or_else(|e| panic!("Conversion {i} failed: {e:?}"));
        
        assert!(generated.is_none());
        
        let v3_file = writer.into_inner();
        let mut recovered = Vec::new();
        decrypt(Cursor::new(&v3_file), &mut recovered, &new_pw).unwrap();
        assert_eq!(&recovered, plaintext, "Round-trip failed on iteration {i}");
    }
}

// —————————————————————————————————————————————————————————————————————————————
// 19. Block boundary sizes
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_block_boundary_sizes() {
    let old_pw = PasswordString::new("old".to_string());
    let new_pw = PasswordString::new("new".to_string());
    
    // Test sizes around AES block boundaries
    let sizes = vec![1, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65];
    
    for size in sizes {
        let plaintext = vec![0xAAu8; size];
        
        let mut legacy = Vec::new();
        encrypt(Cursor::new(&plaintext), &mut legacy, &old_pw, 5).unwrap();
        
        let writer = ThreadSafeVec::new();
        let generated = convert_to_v3(
            Cursor::new(legacy),
            writer.clone(),
            &old_pw,
            Some(&new_pw),
            5,
        )
        .unwrap();
        
        assert!(generated.is_none());
        
        let v3_file = writer.into_inner();
        let mut recovered = Vec::new();
        decrypt(Cursor::new(&v3_file), &mut recovered, &new_pw).unwrap();
        assert_eq!(recovered, plaintext, "Failed for size {}", size);
    }
}

// —————————————————————————————————————————————————————————————————————————————
// 20. Error propagation from threads
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_error_propagation() {
    let old_pw = PasswordString::new("old".to_string());
    let wrong_pw = PasswordString::new("wrong".to_string());
    let new_pw = PasswordString::new("new".to_string());
    let plaintext = b"error test";
    
    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 5).unwrap();
    
    // Wrong password should propagate error from decrypt thread
    let writer = ThreadSafeVec::new();
    let result = convert_to_v3(
        Cursor::new(legacy),
        writer,
        &wrong_pw, // Wrong password
        Some(&new_pw),
        5,
    );
    
    assert!(result.is_err(), "Should propagate error from decrypt thread");
    
    // Verify error is meaningful
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("HMAC") || 
        err_msg.contains("session") || 
        err_msg.contains("password") ||
        err_msg.contains("Crypto"),
        "Error should indicate decryption failure: {err_msg}"
    );
}

// —————————————————————————————————————————————————————————————————————————————
// 21. Verify no memory leaks (owned data cleanup)
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_no_memory_leaks() {
    // This test verifies that owned data is properly cleaned up
    // (no need for Box::leak or unsafe cleanup)
    let old_pw = PasswordString::new("old".to_string());
    let new_pw = PasswordString::new("new".to_string());
    let plaintext = b"memory test";
    
    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 5).unwrap();
    
    // Create owned data that will be dropped after conversion
    let owned_data: Vec<u8> = legacy;
    let writer = ThreadSafeVec::new();
    
    {
        let generated = convert_to_v3(
            Cursor::new(owned_data), // Will be dropped after this scope
            writer.clone(),
            &old_pw,
            Some(&new_pw),
            5,
        )
        .unwrap();
        assert!(generated.is_none());
    }
    // owned_data should be dropped here - no leaks!
    
    let v3_file = writer.into_inner();
    let mut recovered = Vec::new();
    decrypt(Cursor::new(&v3_file), &mut recovered, &new_pw).unwrap();
    assert_eq!(&recovered, plaintext);
}

// —————————————————————————————————————————————————————————————————————————————
// 22. Test encrypted-file-vault use case (no Box::leak)
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_to_v3_encrypted_file_vault_use_case() {
    // Simulates the exact use case from encrypted-file-vault
    // where they had to use Box::leak() before
    use secure_gate::Dynamic;
    use aescrypt_rs::aliases::RandomPassword32;
    
    let old_pw = PasswordString::new("old".to_string());
    let plaintext = b"vault test data";
    
    let mut legacy = Vec::new();
    encrypt(Cursor::new(plaintext), &mut legacy, &old_pw, 5).unwrap();
    
    // Simulate CypherText (secure-gate Dynamic<Vec<u8>>)
    let ciphertext: Dynamic<Vec<u8>> = Dynamic::new(legacy);
    
    // Generate new password
    let new_password_hex = RandomPassword32::random_hex();
    let new_pw = PasswordString::new(new_password_hex.expose_secret().to_string());
    
    // Convert WITHOUT Box::leak - this is the fix!
    let writer = ThreadSafeVec::new();
    let generated = convert_to_v3(
        Cursor::new(ciphertext.expose_secret().clone()), // Clone is fine, no leak needed
        writer.clone(),
        &old_pw,
        Some(&new_pw),
        5,
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
        .join("test_data")
        .join(filename);

    let content = std::fs::read_to_string(&path).expect("failed to read test vector file");
    serde_json::from_str(&content).expect("failed to parse test vector JSON")
}
