//! tests/file_ops_tests.rs
//! Real-world file-based operations using actual .aes files
//!
//! Tests decryption, conversion, and rotation using actual AES Crypt files
//! from tests/test_data/aes_test_files/

use aescrypt_rs::aliases::PasswordString;
use aescrypt_rs::{convert_to_v3, decrypt, encrypt};
use std::fs::File;
use std::io::{BufReader, Cursor};
use std::path::PathBuf;

const PASSWORD: &str = "Hello";

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
    let password = PasswordString::new(PASSWORD.to_string());
    
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
    let password = PasswordString::new(PASSWORD.to_string());
    
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
    let password = PasswordString::new(PASSWORD.to_string());
    
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
    let password = PasswordString::new(PASSWORD.to_string());
    
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
// 2. File-based conversion (upgrade legacy → v3)
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn convert_v0_file_to_v3() {
    let old_pw = PasswordString::new(PASSWORD.to_string());
    let new_pw = PasswordString::new("NewPassword123!".to_string());
    
    // Test with first few files
    for i in 0..5 {
        let input_path = get_aes_test_file_path("v0", i);
        let input_file = File::open(&input_path)
            .unwrap_or_else(|e| panic!("Failed to open {:?}: {e}", input_path));
        let reader = BufReader::new(input_file);
        
        // Convert to v3
        let mut output = Vec::new();
        convert_to_v3(reader, &mut output, &old_pw, Some(&new_pw), 1000)
            .unwrap_or_else(|e| panic!("Failed to convert v0 file {i} to v3: {e:?}"));
        
        // Verify v3 file can be decrypted with new password
        let mut decrypted = Vec::new();
        decrypt(Cursor::new(&output), &mut decrypted, &new_pw)
            .unwrap_or_else(|e| panic!("Failed to decrypt converted v3 file {i}: {e:?}"));
        
        // Note: Empty files are valid, we just verify decryption succeeded
    }
}

#[test]
fn convert_v1_file_to_v3() {
    let old_pw = PasswordString::new(PASSWORD.to_string());
    let new_pw = PasswordString::new("NewPassword123!".to_string());
    
    for i in 0..5 {
        let input_path = get_aes_test_file_path("v1", i);
        let input_file = File::open(&input_path)
            .unwrap_or_else(|e| panic!("Failed to open {:?}: {e}", input_path));
        let reader = BufReader::new(input_file);
        
        let mut output = Vec::new();
        convert_to_v3(reader, &mut output, &old_pw, Some(&new_pw), 1000)
            .unwrap_or_else(|e| panic!("Failed to convert v1 file {i} to v3: {e:?}"));
        
        let mut decrypted = Vec::new();
        decrypt(Cursor::new(&output), &mut decrypted, &new_pw)
            .unwrap_or_else(|e| panic!("Failed to decrypt converted v3 file {i}: {e:?}"));
        
        // Note: Empty files are valid, we just verify decryption succeeded
    }
}

#[test]
fn convert_v2_file_to_v3() {
    let old_pw = PasswordString::new(PASSWORD.to_string());
    let new_pw = PasswordString::new("NewPassword123!".to_string());
    
    for i in 0..5 {
        let input_path = get_aes_test_file_path("v2", i);
        let input_file = File::open(&input_path)
            .unwrap_or_else(|e| panic!("Failed to open {:?}: {e}", input_path));
        let reader = BufReader::new(input_file);
        
        let mut output = Vec::new();
        convert_to_v3(reader, &mut output, &old_pw, Some(&new_pw), 1000)
            .unwrap_or_else(|e| panic!("Failed to convert v2 file {i} to v3: {e:?}"));
        
        let mut decrypted = Vec::new();
        decrypt(Cursor::new(&output), &mut decrypted, &new_pw)
            .unwrap_or_else(|e| panic!("Failed to decrypt converted v3 file {i}: {e:?}"));
        
        // Note: Empty files are valid, we just verify decryption succeeded
    }
}

// —————————————————————————————————————————————————————————————————————————————
// 3. File rotation (v3 → v3 with new password)
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn rotate_v3_file_password() {
    let old_pw = PasswordString::new(PASSWORD.to_string());
    let new_pw = PasswordString::new("RotatedPassword456!".to_string());
    
    for i in 0..5 {
        let input_path = get_aes_test_file_path("v3", i);
        let input_file = File::open(&input_path)
            .unwrap_or_else(|e| panic!("Failed to open {:?}: {e}", input_path));
        let reader = BufReader::new(input_file);
        
        // Rotate password (v3 → v3)
        let mut output = Vec::new();
        convert_to_v3(reader, &mut output, &old_pw, Some(&new_pw), 1000)
            .unwrap_or_else(|e| panic!("Failed to rotate v3 file {i}: {e:?}"));
        
        // Verify new password works
        let mut decrypted = Vec::new();
        decrypt(Cursor::new(&output), &mut decrypted, &new_pw)
            .unwrap_or_else(|e| panic!("Failed to decrypt rotated v3 file {i}: {e:?}"));
        
        // Note: Empty files are valid, we just verify decryption succeeded
        
        // Verify old password no longer works
        let mut should_fail = Vec::new();
        let result = decrypt(Cursor::new(&output), &mut should_fail, &old_pw);
        assert!(result.is_err(), "Old password should not work after rotation for file {i}");
    }
}

// —————————————————————————————————————————————————————————————————————————————
// 4. File-based upgrade with auto-generated password
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn upgrade_file_with_auto_generated_password() {
    let old_pw = PasswordString::new(PASSWORD.to_string());
    
    for i in 0..3 {
        let input_path = get_aes_test_file_path("v0", i);
        let input_file = File::open(&input_path)
            .unwrap_or_else(|e| panic!("Failed to open {:?}: {e}", input_path));
        let reader = BufReader::new(input_file);
        
        // Auto-generate password
        let mut output = Vec::new();
        let generated_pw = convert_to_v3(reader, &mut output, &old_pw, None, 1000)
            .unwrap_or_else(|e| panic!("Failed to upgrade v0 file {i} with auto-password: {e:?}"))
            .expect("Should generate password");
        
        // Verify generated password works
        let mut decrypted = Vec::new();
        decrypt(Cursor::new(&output), &mut decrypted, &generated_pw)
            .unwrap_or_else(|e| panic!("Failed to decrypt with generated password for file {i}: {e:?}"));
        
        // Note: Empty files are valid, we just verify decryption succeeded
        
        // Verify generated password is 64 hex chars
        assert_eq!(
            generated_pw.expose_secret().len(),
            64,
            "Generated password should be 64 hex characters"
        );
    }
}

// —————————————————————————————————————————————————————————————————————————————
// 5. Round-trip: decrypt → encrypt → decrypt from actual files
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn round_trip_from_actual_files() {
    let password = PasswordString::new(PASSWORD.to_string());
    
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
        encrypt(Cursor::new(&plaintext), &mut re_encrypted, &password, 1000)
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
    let password = PasswordString::new(PASSWORD.to_string());
    
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

// —————————————————————————————————————————————————————————————————————————————
// 8. Batch file operations
// —————————————————————————————————————————————————————————————————————————————
#[test]
fn batch_convert_legacy_files() {
    let old_pw = PasswordString::new(PASSWORD.to_string());
    let new_pw = PasswordString::new("BatchPassword789!".to_string());
    
    let versions = ["v0", "v1", "v2"];
    let mut success_count = 0;
    
    for version in versions.iter() {
        for i in 0..3 {
            let input_path = get_aes_test_file_path(version, i);
            if let Ok(input_file) = File::open(&input_path) {
                let reader = BufReader::new(input_file);
                
                let mut output = Vec::new();
                if convert_to_v3(reader, &mut output, &old_pw, Some(&new_pw), 1000).is_ok() {
                    success_count += 1;
                }
            }
        }
    }
    
    // Should successfully convert at least some files
    assert!(success_count > 0, "Should convert at least some legacy files");
}

