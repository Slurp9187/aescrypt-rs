//! tests/file_ops_tests.rs
//! Real-world file-based operations using actual .aes files
//!
//! Tests decryption, conversion, and rotation using actual AES Crypt files
//! from tests/test_data/aes_test_files/

mod common;
use common::{TEST_ITERATIONS, TEST_PASSWORD};

use aescrypt_rs::aliases::PasswordString;
use aescrypt_rs::{decrypt, encrypt};
use std::fs::File;
use std::io::{BufReader, Cursor};
use std::path::PathBuf;

fn get_aes_test_file_path(version: &str, index: usize) -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest_dir)
        .join("tests")
        .join("test_data")
        .join("aes_test_files")
        .join(version)
        .join(format!("{}_test_{:02}.txt.aes", version, index))
}

fn get_v3_deterministic_path(index: usize) -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest_dir)
        .join("tests")
        .join("test_data")
        .join("aes_test_files")
        .join("v3")
        .join(format!("v3_deterministic_{:02}.txt.aes", index))
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
            .unwrap_or_else(|e| panic!("Failed to open {:?}: {e}", file_path));
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
            .unwrap_or_else(|e| panic!("Failed to open {:?}: {e}", file_path));
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
            .unwrap_or_else(|e| panic!("Failed to open {:?}: {e}", file_path));
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
            .unwrap_or_else(|e| panic!("Failed to open {:?}: {e}", file_path));
        let mut reader = BufReader::new(file);
        
        let mut decrypted = Vec::new();
        decrypt(&mut reader, &mut decrypted, &password)
            .unwrap_or_else(|e| panic!("Failed to decrypt v3 file {i}: {e:?}"));
        
        // Note: Empty files are valid (test vector 0 is empty string)
    }
}

// —————————————————————————————————————————————————————————————————————————————
// 2. Round-trip: decrypt → encrypt → decrypt from actual files
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn round_trip_from_actual_files() {
    let password = PasswordString::new(TEST_PASSWORD.to_string());
    
    for i in 0..5 {
        // Decrypt original file
        let input_path = get_aes_test_file_path("v3", i);
        let input_file = File::open(&input_path)
            .unwrap_or_else(|e| panic!("Failed to open {:?}: {e}", input_path));
        let mut reader = BufReader::new(input_file);
        
        let mut plaintext = Vec::new();
        decrypt(&mut reader, &mut plaintext, &password)
            .unwrap_or_else(|e| panic!("Failed to decrypt v3 file {i}: {e:?}"));
        
        // Re-encrypt
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
            .unwrap_or_else(|e| panic!("Failed to open {:?}: {e}", file_path));
        let mut reader = BufReader::new(file);
        
        let mut decrypted = Vec::new();
        decrypt(&mut reader, &mut decrypted, &password)
            .unwrap_or_else(|e| panic!("Failed to decrypt deterministic v3 file {i}: {e:?}"));
        
        // Note: Empty files are valid (test vector 0 is empty string)
    }
}


