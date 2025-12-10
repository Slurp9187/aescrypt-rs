//! tests/file_ops_tests.rs
//! Real-world file-based operations using actual .aes files
//!
//! Tests decryption, conversion, and rotation using actual AES Crypt files
//! from tests/test_data/aes_test_files/

mod common;
use common::TEST_PASSWORD;
#[cfg(feature = "rand")]
use common::TEST_ITERATIONS;

use aescrypt_rs::aliases::PasswordString;
use aescrypt_rs::decrypt;
#[cfg(feature = "rand")]
use aescrypt_rs::encrypt;
#[cfg(feature = "rand")]
use serde::Deserialize;
use std::fs::File;
use std::io::BufReader;
#[cfg(feature = "rand")]
use std::io::Cursor;
use std::path::PathBuf;

fn get_aes_test_file_path(version: &str, index: usize) -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest_dir)
        .join("tests")
        .join("test_data")
        .join("aes_test_files")
        .join(version)
        .join(format!("{version}_test_{index:02}.txt.aes"))
}

fn get_v3_deterministic_path(index: usize) -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest_dir)
        .join("tests")
        .join("test_data")
        .join("aes_test_files")
        .join("v3")
        .join(format!("v3_deterministic_{index:02}.txt.aes"))
}

// JSON vector loader for migration tests
#[cfg(feature = "rand")]
#[derive(Debug, Deserialize)]
struct TestVector {
    #[allow(dead_code)]
    plaintext: String,
    #[serde(alias = "encrypted_hex")] // v0–v2
    #[serde(alias = "ciphertext_hex")] // v3
    #[allow(dead_code)] // Field needed for deserialization but not used in migration tests
    ciphertext_hex: String,
}

#[cfg(feature = "rand")]
fn load_json_vectors(filename: &str) -> Vec<TestVector> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("test_data")
        .join(filename);

    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {filename}: {e}"));

    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse {filename}: {e}"))
}

// —————————————————————————————————————————————————————————————————————————————
// 1. Direct file decryption (v0, v1, v2, v3)
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn decrypt_actual_v0_files() {
    let password = PasswordString::new(TEST_PASSWORD.to_string());
    
    for i in 0..21 {
        let file_path = get_aes_test_file_path("v0", i);
        let file = File::open(&file_path)
            .unwrap_or_else(|e| panic!("Failed to open {file_path:?}: {e}"));
        let mut reader = BufReader::new(file);
        
        let mut decrypted = Vec::new();
        let result = decrypt(&mut reader, &mut decrypted, &password);
        
        if let Err(e) = result {
            // Some files might be empty (test vector 0), so empty content is valid
            // But decryption should still succeed
            panic!("Failed to decrypt v0 file {i}: {e:?}");
        }
        
        // Note: Empty files are valid (test vector 0 is empty string)
        // So we just verify decryption succeeded, not that content exists
    }
}

#[test]
fn decrypt_actual_v1_files() {
    let password = PasswordString::new(TEST_PASSWORD.to_string());
    
    for i in 0..21 {
        let file_path = get_aes_test_file_path("v1", i);
        let file = File::open(&file_path)
            .unwrap_or_else(|e| panic!("Failed to open {file_path:?}: {e}"));
        let mut reader = BufReader::new(file);
        
        let mut decrypted = Vec::new();
        decrypt(&mut reader, &mut decrypted, &password)
            .unwrap_or_else(|e| panic!("Failed to decrypt v1 file {i}: {e:?}"));
        
        // Note: Empty files are valid (test vector 0 is empty string)
    }
}

#[test]
fn decrypt_actual_v2_files() {
    let password = PasswordString::new(TEST_PASSWORD.to_string());
    
    for i in 0..21 {
        let file_path = get_aes_test_file_path("v2", i);
        let file = File::open(&file_path)
            .unwrap_or_else(|e| panic!("Failed to open {file_path:?}: {e}"));
        let mut reader = BufReader::new(file);
        
        let mut decrypted = Vec::new();
        decrypt(&mut reader, &mut decrypted, &password)
            .unwrap_or_else(|e| panic!("Failed to decrypt v2 file {i}: {e:?}"));
        
        // Note: Empty files are valid (test vector 0 is empty string)
    }
}

#[test]
fn decrypt_actual_v3_files() {
    let password = PasswordString::new(TEST_PASSWORD.to_string());
    
    for i in 0..21 {
        let file_path = get_aes_test_file_path("v3", i);
        let file = File::open(&file_path)
            .unwrap_or_else(|e| panic!("Failed to open {file_path:?}: {e}"));
        let mut reader = BufReader::new(file);
        
        let mut decrypted = Vec::new();
        decrypt(&mut reader, &mut decrypted, &password)
            .unwrap_or_else(|e| panic!("Failed to decrypt v3 file {i}: {e:?}"));
        
        // Note: Empty files are valid (test vector 0 is empty string)
    }
}

// —————————————————————————————————————————————————————————————————————————————
// 2. Round-trip: decrypt → encrypt → decrypt from actual files (v3 only)
// —————————————————————————————————————————————————————————————————————————————
#[test]
#[cfg(feature = "rand")]
fn round_trip_from_actual_files() {
    let password = PasswordString::new(TEST_PASSWORD.to_string());
    
    for i in 0..5 {
        // Decrypt original file
        let input_path = get_aes_test_file_path("v3", i);
        let input_file = File::open(&input_path)
            .unwrap_or_else(|e| panic!("Failed to open {input_path:?}: {e}"));
        let mut reader = BufReader::new(input_file);
        
        let mut plaintext = Vec::new();
        decrypt(&mut reader, &mut plaintext, &password)
            .unwrap_or_else(|e| panic!("Failed to decrypt v3 file {i}: {e:?}"));
        
        // Re-encrypt as v3 (encrypt() always creates v3 format)
        let mut re_encrypted = Vec::new();
        encrypt(Cursor::new(&plaintext), &mut re_encrypted, &password, TEST_ITERATIONS)
            .unwrap_or_else(|e| panic!("Failed to re-encrypt file {i}: {e:?}"));
        
        // Decrypt again
        let mut final_plaintext = Vec::new();
        decrypt(Cursor::new(&re_encrypted), &mut final_plaintext, &password)
            .unwrap_or_else(|e| panic!("Failed to decrypt re-encrypted file {i}: {e:?}"));
        
        assert_eq!(
            plaintext, final_plaintext,
            "Round-trip failed for v3 file {i}"
        );
    }
}

// —————————————————————————————————————————————————————————————————————————————
// 3. Migration tests: v0/v1/v2 → v3 (legacy compatibility)
// —————————————————————————————————————————————————————————————————————————————
// Note: These are migration tests, not literal roundtrips. We can only encrypt
// to v3 format, so we verify that legacy files can be decrypted and re-encrypted
// as v3 while preserving data integrity.

#[test]
#[cfg(feature = "rand")]
fn migrate_v0_to_v3() {
    let password = PasswordString::new(TEST_PASSWORD.to_string());
    let vectors = load_json_vectors("test_vectors_v0.json");
    
    // Test all 21 files (or at least 15 for performance)
    let test_count = vectors.len().min(21);
    
    for (i, vector) in vectors.iter().enumerate().take(test_count) {
        // Load expected plaintext from vectors
        let expected_plaintext = vector.plaintext.as_bytes();
        
        // Decrypt v0 file
        let file_path = get_aes_test_file_path("v0", i);
        let file = File::open(&file_path)
            .unwrap_or_else(|e| panic!("Failed to open {file_path:?}: {e}"));
        let mut reader = BufReader::new(file);
        
        let mut decrypted = Vec::new();
        decrypt(&mut reader, &mut decrypted, &password)
            .unwrap_or_else(|e| panic!("Failed to decrypt v0 file {i}: {e:?}"));
        
        // Verify decrypted plaintext matches expected from vectors
        assert_eq!(
            decrypted.as_slice(),
            expected_plaintext,
            "Plaintext mismatch for v0 file {i}"
        );
        
        // Encrypt plaintext as v3 (encrypt() always creates v3 format, we cannot encrypt to v0)
        let mut v3_encrypted = Vec::new();
        encrypt(Cursor::new(&decrypted), &mut v3_encrypted, &password, TEST_ITERATIONS)
            .unwrap_or_else(|e| panic!("Failed to encrypt v0→v3 migration for file {i}: {e:?}"));
        
        // Decrypt v3 encrypted data
        let mut final_plaintext = Vec::new();
        decrypt(Cursor::new(&v3_encrypted), &mut final_plaintext, &password)
            .unwrap_or_else(|e| panic!("Failed to decrypt v3 migrated file {i}: {e:?}"));
        
        // Verify plaintext matches (migration preserved data integrity)
        assert_eq!(
            decrypted, final_plaintext,
            "Migration v0→v3 failed for file {i}: data integrity not preserved"
        );
    }
}

#[test]
#[cfg(feature = "rand")]
fn migrate_v1_to_v3() {
    let password = PasswordString::new(TEST_PASSWORD.to_string());
    let vectors = load_json_vectors("test_vectors_v1.json");
    
    // Test all 21 files (or at least 15 for performance)
    let test_count = vectors.len().min(21);
    
    for (i, vector) in vectors.iter().enumerate().take(test_count) {
        // Load expected plaintext from vectors
        let expected_plaintext = vector.plaintext.as_bytes();
        
        // Decrypt v1 file
        let file_path = get_aes_test_file_path("v1", i);
        let file = File::open(&file_path)
            .unwrap_or_else(|e| panic!("Failed to open {file_path:?}: {e}"));
        let mut reader = BufReader::new(file);
        
        let mut decrypted = Vec::new();
        decrypt(&mut reader, &mut decrypted, &password)
            .unwrap_or_else(|e| panic!("Failed to decrypt v1 file {i}: {e:?}"));
        
        // Verify decrypted plaintext matches expected from vectors
        assert_eq!(
            decrypted.as_slice(),
            expected_plaintext,
            "Plaintext mismatch for v1 file {i}"
        );
        
        // Encrypt plaintext as v3 (encrypt() always creates v3 format, we cannot encrypt to v1)
        let mut v3_encrypted = Vec::new();
        encrypt(Cursor::new(&decrypted), &mut v3_encrypted, &password, TEST_ITERATIONS)
            .unwrap_or_else(|e| panic!("Failed to encrypt v1→v3 migration for file {i}: {e:?}"));
        
        // Decrypt v3 encrypted data
        let mut final_plaintext = Vec::new();
        decrypt(Cursor::new(&v3_encrypted), &mut final_plaintext, &password)
            .unwrap_or_else(|e| panic!("Failed to decrypt v3 migrated file {i}: {e:?}"));
        
        // Verify plaintext matches (migration preserved data integrity)
        assert_eq!(
            decrypted, final_plaintext,
            "Migration v1→v3 failed for file {i}: data integrity not preserved"
        );
    }
}

#[test]
#[cfg(feature = "rand")]
fn migrate_v2_to_v3() {
    let password = PasswordString::new(TEST_PASSWORD.to_string());
    let vectors = load_json_vectors("test_vectors_v2.json");
    
    // Test all 21 files (or at least 15 for performance)
    let test_count = vectors.len().min(21);
    
    for (i, vector) in vectors.iter().enumerate().take(test_count) {
        // Load expected plaintext from vectors
        let expected_plaintext = vector.plaintext.as_bytes();
        
        // Decrypt v2 file
        let file_path = get_aes_test_file_path("v2", i);
        let file = File::open(&file_path)
            .unwrap_or_else(|e| panic!("Failed to open {file_path:?}: {e}"));
        let mut reader = BufReader::new(file);
        
        let mut decrypted = Vec::new();
        decrypt(&mut reader, &mut decrypted, &password)
            .unwrap_or_else(|e| panic!("Failed to decrypt v2 file {i}: {e:?}"));
        
        // Verify decrypted plaintext matches expected from vectors
        assert_eq!(
            decrypted.as_slice(),
            expected_plaintext,
            "Plaintext mismatch for v2 file {i}"
        );
        
        // Encrypt plaintext as v3 (encrypt() always creates v3 format, we cannot encrypt to v2)
        let mut v3_encrypted = Vec::new();
        encrypt(Cursor::new(&decrypted), &mut v3_encrypted, &password, TEST_ITERATIONS)
            .unwrap_or_else(|e| panic!("Failed to encrypt v2→v3 migration for file {i}: {e:?}"));
        
        // Decrypt v3 encrypted data
        let mut final_plaintext = Vec::new();
        decrypt(Cursor::new(&v3_encrypted), &mut final_plaintext, &password)
            .unwrap_or_else(|e| panic!("Failed to decrypt v3 migrated file {i}: {e:?}"));
        
        // Verify plaintext matches (migration preserved data integrity)
        assert_eq!(
            decrypted, final_plaintext,
            "Migration v2→v3 failed for file {i}: data integrity not preserved"
        );
    }
}

// —————————————————————————————————————————————————————————————————————————————
// 6. File I/O error handling
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn handle_missing_file_gracefully() {
    let non_existent = PathBuf::from("nonexistent_file.aes");
    
    let file = File::open(&non_existent);
    assert!(file.is_err(), "Should fail to open non-existent file");
}

// —————————————————————————————————————————————————————————————————————————————
// 7. Deterministic v3 files
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn decrypt_deterministic_v3_files() {
    let password = PasswordString::new(TEST_PASSWORD.to_string());
    
    for i in 0..21 {
        let file_path = get_v3_deterministic_path(i);
        let file = File::open(&file_path)
            .unwrap_or_else(|e| panic!("Failed to open {file_path:?}: {e}"));
        let mut reader = BufReader::new(file);
        
        let mut decrypted = Vec::new();
        decrypt(&mut reader, &mut decrypted, &password)
            .unwrap_or_else(|e| panic!("Failed to decrypt deterministic v3 file {i}: {e:?}"));
        
        // Note: Empty files are valid (test vector 0 is empty string)
    }
}


