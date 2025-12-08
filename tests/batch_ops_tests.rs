#[cfg(feature = "batch-ops")]
use aescrypt_rs::aliases::PasswordString;
#[cfg(feature = "batch-ops")]
use aescrypt_rs::{decrypt_batch, encrypt_batch, AescryptError};
#[cfg(feature = "batch-ops")]
use std::io::Cursor;

#[cfg(feature = "batch-ops")]
#[test]
fn batch_roundtrip_sanity_check() {
    let password = PasswordString::new("sanity".to_string());
    let data = [b"hello parallel world"; 4]; // 4 tiny files

    let mut encrypted = data.map(|d| (Cursor::new(d.to_vec()), Vec::new()));
    encrypt_batch(&mut encrypted, &password, 1000).unwrap();

    let mut decrypted = encrypted
        .into_iter()
        .map(|(_, buf)| (Cursor::new(buf), Vec::new()))
        .collect::<Vec<_>>();
    decrypt_batch(&mut decrypted, &password).unwrap();

    let results: Vec<_> = decrypted.into_iter().map(|(_, buf)| buf).collect();
    assert_eq!(results, data.as_ref());
}

#[cfg(feature = "batch-ops")]
#[test]
fn batch_empty_batch() {
    let password = PasswordString::new("test".to_string());
    let mut batch: Vec<(Cursor<Vec<u8>>, Vec<u8>)> = Vec::new();
    
    // Empty batch should succeed (no-op)
    encrypt_batch(&mut batch, &password, 1000).unwrap();
    assert!(batch.is_empty());
}

#[cfg(feature = "batch-ops")]
#[test]
fn batch_single_file() {
    let password = PasswordString::new("single".to_string());
    let data = b"single file test";
    
    let mut encrypted = vec![(Cursor::new(data.to_vec()), Vec::new())];
    encrypt_batch(&mut encrypted, &password, 1000).unwrap();
    
    let mut decrypted = vec![(Cursor::new(encrypted[0].1.clone()), Vec::new())];
    decrypt_batch(&mut decrypted, &password).unwrap();
    
    assert_eq!(decrypted[0].1, data);
}

#[cfg(feature = "batch-ops")]
#[test]
fn batch_different_file_sizes() {
    let password = PasswordString::new("sizes".to_string());
    let data = vec![
        vec![], // empty
        vec![0u8; 1], // 1 byte
        vec![0u8; 15], // 15 bytes (just under block)
        vec![0u8; 16], // exactly one block
        vec![0u8; 17], // one block + 1 byte
        vec![0u8; 1024], // 1 KB
        vec![0u8; 100_000], // 100 KB
    ];
    
    let mut encrypted: Vec<_> = data.iter()
        .map(|d| (Cursor::new(d.clone()), Vec::new()))
        .collect();
    encrypt_batch(&mut encrypted, &password, 1000).unwrap();
    
    let mut decrypted: Vec<_> = encrypted.iter()
        .map(|(_, buf)| (Cursor::new(buf.clone()), Vec::new()))
        .collect();
    decrypt_batch(&mut decrypted, &password).unwrap();
    
    let results: Vec<_> = decrypted.into_iter().map(|(_, buf)| buf).collect();
    assert_eq!(results, data);
}

#[cfg(feature = "batch-ops")]
#[test]
fn batch_large_batch() {
    let password = PasswordString::new("large".to_string());
    let data = b"test data";
    
    // Create 100 files
    let mut encrypted: Vec<_> = (0..100)
        .map(|_| (Cursor::new(data.to_vec()), Vec::new()))
        .collect();
    encrypt_batch(&mut encrypted, &password, 1000).unwrap();
    
    let mut decrypted: Vec<_> = encrypted.iter()
        .map(|(_, buf)| (Cursor::new(buf.clone()), Vec::new()))
        .collect();
    decrypt_batch(&mut decrypted, &password).unwrap();
    
    for (_, buf) in decrypted {
        assert_eq!(buf, data);
    }
}

#[cfg(feature = "batch-ops")]
#[test]
fn batch_wrong_password() {
    let password = PasswordString::new("correct".to_string());
    let wrong_password = PasswordString::new("wrong".to_string());
    let data = b"secret data";
    
    let mut encrypted = vec![(Cursor::new(data.to_vec()), Vec::new())];
    encrypt_batch(&mut encrypted, &password, 1000).unwrap();
    
    let mut decrypted = vec![(Cursor::new(encrypted[0].1.clone()), Vec::new())];
    let result = decrypt_batch(&mut decrypted, &wrong_password);
    
    assert!(result.is_err());
    match result.unwrap_err() {
        AescryptError::Crypto(_) | AescryptError::Header(_) => {},
        e => panic!("Unexpected error type: {:?}", e),
    }
}

#[cfg(feature = "batch-ops")]
#[test]
fn batch_invalid_iterations_zero() {
    let password = PasswordString::new("test".to_string());
    let data = b"test data";
    let mut batch = vec![(Cursor::new(data.to_vec()), Vec::new())];
    
    let result = encrypt_batch(&mut batch, &password, 0);
    assert!(result.is_err());
    match result.unwrap_err() {
        AescryptError::Header(_) => {},
        e => panic!("Unexpected error type: {:?}", e),
    }
}

#[cfg(feature = "batch-ops")]
#[test]
fn batch_invalid_iterations_too_large() {
    let password = PasswordString::new("test".to_string());
    let data = b"test data";
    let mut batch = vec![(Cursor::new(data.to_vec()), Vec::new())];
    
    let result = encrypt_batch(&mut batch, &password, 5_000_001);
    assert!(result.is_err());
    match result.unwrap_err() {
        AescryptError::Header(_) => {},
        e => panic!("Unexpected error type: {:?}", e),
    }
}

#[cfg(feature = "batch-ops")]
#[test]
fn batch_empty_password() {
    let password = PasswordString::new(String::new());
    let data = b"test data";
    let mut batch = vec![(Cursor::new(data.to_vec()), Vec::new())];
    
    let result = encrypt_batch(&mut batch, &password, 1000);
    assert!(result.is_err());
    match result.unwrap_err() {
        AescryptError::Header(_) => {},
        e => panic!("Unexpected error type: {:?}", e),
    }
}

#[cfg(feature = "batch-ops")]
#[test]
fn batch_partial_failure_wrong_password() {
    let password1 = PasswordString::new("password1".to_string());
    let password2 = PasswordString::new("password2".to_string());
    let data = b"test data";
    
    // Encrypt two files with different passwords
    let mut encrypted1 = vec![(Cursor::new(data.to_vec()), Vec::new())];
    encrypt_batch(&mut encrypted1, &password1, 1000).unwrap();
    
    let mut encrypted2 = vec![(Cursor::new(data.to_vec()), Vec::new())];
    encrypt_batch(&mut encrypted2, &password2, 1000).unwrap();
    
    // Try to decrypt both with password1 (second should fail)
    let mut batch = vec![
        (Cursor::new(encrypted1[0].1.clone()), Vec::new()),
        (Cursor::new(encrypted2[0].1.clone()), Vec::new()),
    ];
    
    let result = decrypt_batch(&mut batch, &password1);
    assert!(result.is_err());
}

#[cfg(feature = "batch-ops")]
#[test]
fn batch_various_iteration_counts() {
    let password = PasswordString::new("iterations".to_string());
    let data = b"test data";
    
    // Test with different iteration counts
    for iterations in [1, 10, 100, 1000, 8192, 300_000] {
        let mut encrypted = vec![(Cursor::new(data.to_vec()), Vec::new())];
        encrypt_batch(&mut encrypted, &password, iterations).unwrap();
        
        let mut decrypted = vec![(Cursor::new(encrypted[0].1.clone()), Vec::new())];
        decrypt_batch(&mut decrypted, &password).unwrap();
        
        assert_eq!(decrypted[0].1, data, "Failed with {} iterations", iterations);
    }
}

#[cfg(feature = "batch-ops")]
#[test]
fn batch_mixed_sizes_and_empty() {
    let password = PasswordString::new("mixed".to_string());
    let data = vec![
        vec![], // empty
        vec![0u8; 1],
        vec![0u8; 16],
        vec![0u8; 100],
    ];
    
    let mut encrypted: Vec<_> = data.iter()
        .map(|d| (Cursor::new(d.clone()), Vec::new()))
        .collect();
    encrypt_batch(&mut encrypted, &password, 1000).unwrap();
    
    let mut decrypted: Vec<_> = encrypted.iter()
        .map(|(_, buf)| (Cursor::new(buf.clone()), Vec::new()))
        .collect();
    decrypt_batch(&mut decrypted, &password).unwrap();
    
    let results: Vec<_> = decrypted.into_iter().map(|(_, buf)| buf).collect();
    assert_eq!(results, data);
}
