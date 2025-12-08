//! tests/vector_tests.rs
//! Final merged vector test suite – fully compatible with v0–v3 JSON formats (2025)

use aescrypt_rs::aliases::{Aes256Key32, EncryptedSessionBlock48, Iv16, PasswordString};
use aescrypt_rs::decrypt;
use aescrypt_rs::encrypt;

// Deterministic v3 encryption helper – TEST ONLY
// Exactly matches the official test vectors (including CREATED_BY extension + version byte in HMAC)
use aescrypt_rs::encryptor::{
    derive_setup_key, encrypt_session_block, encrypt_stream, write_header, write_hmac,
    write_iterations, write_public_iv,
};
use aes::cipher::KeyInit;
use aes::Aes256Enc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{Read, Write};

// Exact extension blob used in the official deterministic test vectors
const V3_CREATED_BY_EXTENSION: [u8; 29] = [
    0x00, 0x1B, b'C', b'R', b'E', b'A', b'T', b'E', b'D', b'_', b'B', b'Y', 0x00, b'a', b'e', b's',
    b'c', b'r', b'y', b'p', b't', b' ', b'4', b'.', b'0', b'.', b'0', b'.', b'0',
];

fn encrypt_with_fixed_session<R: Read, W: Write>(
    mut source: R,
    mut destination: W,
    password: &PasswordString,
    iterations: u32,
    public_iv: &Iv16,
    session_iv: &Iv16,
    session_key: &Aes256Key32,
) -> Result<(), aescrypt_rs::AescryptError> {
    // Header
    write_header(&mut destination, 3)?;

    // CREATED_BY extension + terminator (required by test vectors)
    destination.write_all(&V3_CREATED_BY_EXTENSION)?;
    destination.write_all(&[0x00, 0x00])?;

    // KDF parameters
    write_iterations(&mut destination, iterations, 3)?;
    write_public_iv(&mut destination, public_iv)?;

    // Derive setup key
    let mut setup_key = Aes256Key32::new([0u8; 32]);
    derive_setup_key(password, public_iv, iterations, &mut setup_key)?;

    let cipher = Aes256Enc::new(setup_key.expose_secret().into());

    // Create HMAC – disambiguate using the Mac trait directly
    let mut session_hmac = <Hmac<Sha256> as Mac>::new_from_slice(setup_key.expose_secret())
        .expect("setup_key is exactly 32 bytes");

    // Encrypt the session block (IV + key)
    let mut enc_session_block = EncryptedSessionBlock48::new([0u8; 48]);
    encrypt_session_block(
        &cipher,
        session_iv,
        session_key,
        public_iv,
        &mut enc_session_block,
        &mut session_hmac,
    )?;

    // Official spec includes the version byte (3) in the session HMAC
    session_hmac.update(&[3]);

    // Write encrypted session + HMAC
    destination.write_all(enc_session_block.expose_secret())?;
    write_hmac(&mut destination, session_hmac)?;

    // Encrypt payload
    encrypt_stream(&mut source, &mut destination, session_iv, session_key)?;

    Ok(())
}

use hex::decode;
use serde::Deserialize;
use std::io::Cursor;

const PASSWORD: &str = "Hello";
const DEFAULT_KDF_ITERATIONS: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AescryptVersion {
    V0,
    V1,
    V2,
    V3,
}

impl AescryptVersion {
    const fn name(self) -> &'static str {
        match self {
            Self::V0 => "v0",
            Self::V1 => "v1",
            Self::V2 => "v2",
            Self::V3 => "v3",
        }
    }

    const fn json_filename(self) -> &'static str {
        match self {
            Self::V0 => "test_vectors_v0.json",
            Self::V1 => "test_vectors_v1.json",
            Self::V2 => "test_vectors_v2.json",
            Self::V3 => "test_vectors_v3.json",
        }
    }

    const fn deterministic_json() -> &'static str {
        "deterministic_test_vectors_v3.json"
    }

    const fn all() -> [Self; 4] {
        [Self::V0, Self::V1, Self::V2, Self::V3]
    }
}

// Shared JSON loader
fn load_json<T>(filename: &str) -> Vec<T>
where
    T: for<'de> Deserialize<'de>,
{
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("test_data")
        .join(filename);

    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to read {filename}: {e}"));

    serde_json::from_str(&content).unwrap_or_else(|e| panic!("Failed to parse {filename}: {e}"))
}

// === Decrypt-only vectors (v0–v3 compatible) ===
#[derive(Debug, Deserialize)]
struct DecryptVector {
    #[serde(alias = "encrypted_hex")] // v0–v2
    #[serde(alias = "ciphertext_hex")] // v3
    ciphertext_hex: String,
    plaintext: String,
}

fn run_decrypt_for_version(version: AescryptVersion) {
    eprintln!(
        "RUNNING: Decrypt test for AES Crypt {}",
        version.name().to_uppercase()
    );

    let vectors: Vec<DecryptVector> = load_json(version.json_filename());
    let password = PasswordString::new(PASSWORD.to_string());

    for (i, v) in vectors.iter().enumerate() {
        let encrypted = decode(&v.ciphertext_hex)
            .unwrap_or_else(|e| panic!("Vector {i} ({}) invalid hex: {e}", version.name()));

        let mut decrypted = Vec::new();
        decrypt(Cursor::new(&encrypted), &mut decrypted, &password)
            .unwrap_or_else(|e| panic!("Vector {i} ({}) decrypt failed: {e:?}", version.name()));

        assert_eq!(
            decrypted.as_slice(),
            v.plaintext.as_bytes(),
            "Plaintext mismatch in vector {i} ({})",
            version.name()
        );
    }

    eprintln!("SUCCESS: All {} decrypt tests PASSED!\n", version.name());
}

// === Round-trip vectors (same schema as decrypt) ===
type RoundTripVector = DecryptVector;

fn run_roundtrip_for_version(version: AescryptVersion) {
    eprintln!(
        "RUNNING: Round-trip test for AES Crypt {}",
        version.name().to_uppercase()
    );

    let vectors: Vec<RoundTripVector> = load_json(version.json_filename());
    let password = PasswordString::new(PASSWORD.to_string());

    for (i, v) in vectors.iter().enumerate() {
        let plaintext = v.plaintext.as_bytes();

        let mut encrypted = Vec::new();
        encrypt(
            Cursor::new(plaintext),
            &mut encrypted,
            &password,
            DEFAULT_KDF_ITERATIONS,
        )
        .unwrap_or_else(|e| panic!("Vector {i} ({}) encrypt failed: {e:?}", version.name()));

        let mut decrypted = Vec::new();
        decrypt(Cursor::new(&encrypted), &mut decrypted, &password)
            .unwrap_or_else(|e| panic!("Vector {i} ({}) decrypt failed: {e:?}", version.name()));

        assert_eq!(
            decrypted,
            plaintext,
            "Round-trip failed: vector {i} ({})",
            version.name()
        );
    }

    eprintln!("SUCCESS: All {} round-trip tests PASSED!\n", version.name());
}

// === Deterministic v3 ===
#[derive(Debug, Deserialize)]
struct DeterministicVector {
    plaintext: String,
    ciphertext_hex: String,
    kdf_iterations: u32,
    public_iv: String,
    session_iv: String,
    session_key: String,
}

#[test]
fn roundtrip_v3_deterministic() {
    eprintln!("RUNNING: Deterministic v3 test (exact ciphertext + round-trip)");
    let vectors: Vec<DeterministicVector> = load_json(AescryptVersion::deterministic_json());
    let password = PasswordString::new(PASSWORD.to_string());

    for (i, v) in vectors.iter().enumerate() {
        let plaintext = v.plaintext.as_bytes();
        let expected_ct =
            decode(&v.ciphertext_hex).unwrap_or_else(|e| panic!("Vector {i}: invalid hex: {e}"));

        let public_iv_bytes = decode(&v.public_iv)
            .unwrap_or_else(|e| panic!("Vector {i}: invalid public_iv hex: {e}"));
        let public_iv_arr: [u8; 16] = public_iv_bytes
            .try_into()
            .unwrap_or_else(|_| panic!("Vector {i}: public_iv must be 16 bytes"));
        let public_iv = Iv16::from(public_iv_arr);

        let session_iv_bytes = decode(&v.session_iv)
            .unwrap_or_else(|e| panic!("Vector {i}: invalid session_iv hex: {e}"));
        let session_iv_arr: [u8; 16] = session_iv_bytes
            .try_into()
            .unwrap_or_else(|_| panic!("Vector {i}: session_iv must be 16 bytes"));
        let session_iv = Iv16::from(session_iv_arr);

        let session_key_bytes = decode(&v.session_key)
            .unwrap_or_else(|e| panic!("Vector {i}: invalid session_key hex: {e}"));
        let session_key_arr: [u8; 32] = session_key_bytes
            .try_into()
            .unwrap_or_else(|_| panic!("Vector {i}: session_key must be 32 bytes"));
        let session_key = Aes256Key32::from(session_key_arr);

        let mut encrypted = Vec::new();
        encrypt_with_fixed_session(
            Cursor::new(plaintext),
            &mut encrypted,
            &password,
            v.kdf_iterations,
            &public_iv,
            &session_iv,
            &session_key,
        )
        .unwrap_or_else(|e| panic!("Vector {i}: fixed encrypt failed: {e:?}"));

        assert_eq!(encrypted, expected_ct, "Ciphertext mismatch in vector {i}");

        let mut decrypted = Vec::new();
        decrypt(Cursor::new(&encrypted), &mut decrypted, &password)
            .unwrap_or_else(|e| panic!("Vector {i}: decrypt failed: {e:?}"));

        assert_eq!(decrypted, plaintext, "Round-trip failed in vector {i}");
    }
    eprintln!(
        "SUCCESS: All {} deterministic v3 tests PASSED!\n",
        vectors.len()
    );
}

// === Combined tests ===
#[test]
fn decrypt_all_versions() {
    eprintln!("RUNNING: Full decryption suite (v0–v3)\n");
    for version in AescryptVersion::all() {
        run_decrypt_for_version(version);
    }
    eprintln!("SUCCESS: All decryption tests PASSED!\n");
}

#[test]
fn roundtrip_all_versions() {
    eprintln!("RUNNING: Full round-trip suite (v0–v3 + deterministic v3)\n");
    for version in AescryptVersion::all() {
        run_roundtrip_for_version(version);
    }
    roundtrip_v3_deterministic();
    eprintln!("SUCCESS: All round-trip tests PASSED!\n");
}

// === Extreme tests ===
#[test]
fn roundtrip_v3_empty_input() {
    let password = PasswordString::new("test-empty".to_string());
    let mut encrypted = Vec::new();
    encrypt(
        Cursor::new(b""),
        &mut encrypted,
        &password,
        DEFAULT_KDF_ITERATIONS,
    )
    .unwrap();
    let mut decrypted = Vec::new();
    decrypt(Cursor::new(&encrypted), &mut decrypted, &password).unwrap();
    assert!(decrypted.is_empty());
}

#[test]
fn roundtrip_v3_large_input() {
    let plaintext = vec![0x41u8; 10_000];
    let password = PasswordString::new("test-large".to_string());
    let mut encrypted = Vec::new();
    encrypt(
        Cursor::new(&plaintext),
        &mut encrypted,
        &password,
        DEFAULT_KDF_ITERATIONS,
    )
    .unwrap();
    let mut decrypted = Vec::new();
    decrypt(Cursor::new(&encrypted), &mut decrypted, &password).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn roundtrip_v3_huge_input() {
    let plaintext = vec![0x41u8; 10 * 1024 * 1024];
    let password = PasswordString::new("test-huge-10mib".to_string());
    let mut encrypted = Vec::new();
    encrypt(
        Cursor::new(&plaintext),
        &mut encrypted,
        &password,
        DEFAULT_KDF_ITERATIONS,
    )
    .unwrap();
    let mut decrypted = Vec::new();
    decrypt(Cursor::new(&encrypted), &mut decrypted, &password).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
#[ignore = "1 GiB round-trip is intentionally heavy"]
fn roundtrip_extreme_1gib() {
    const ONE_GIB: usize = 1024 * 1024 * 1024;
    let password = PasswordString::new("test-1gib-streaming".to_string());

    let chunk = [0x41u8; 4096];
    let mut plaintext = Vec::with_capacity(ONE_GIB);
    for _ in 0..(ONE_GIB / chunk.len()) {
        plaintext.extend_from_slice(&chunk);
    }
    plaintext.extend_from_slice(&chunk[0..(ONE_GIB % chunk.len())]);

    let mut encrypted = Vec::new();
    encrypt(
        Cursor::new(&plaintext),
        &mut encrypted,
        &password,
        DEFAULT_KDF_ITERATIONS,
    )
    .unwrap();
    let mut decrypted = Vec::new();
    decrypt(Cursor::new(&encrypted), &mut decrypted, &password).unwrap();
    assert_eq!(decrypted, plaintext);
}

// === Error Handling Tests ===
#[test]
fn decrypt_wrong_password() {
    let correct_password = PasswordString::new(PASSWORD.to_string());
    let wrong_password = PasswordString::new("WrongPassword".to_string());

    // Encrypt with correct password
    let plaintext = b"secret data";
    let mut encrypted = Vec::new();
    encrypt(
        Cursor::new(plaintext),
        &mut encrypted,
        &correct_password,
        DEFAULT_KDF_ITERATIONS,
    )
    .unwrap();

    // Try to decrypt with wrong password
    let mut decrypted = Vec::new();
    let result = decrypt(Cursor::new(&encrypted), &mut decrypted, &wrong_password);

    assert!(result.is_err(), "Decryption with wrong password should fail");
    if let Err(e) = result {
        assert!(
            e.to_string().contains("HMAC") || e.to_string().contains("session"),
            "Error should indicate HMAC or session verification failure"
        );
    }
}

#[test]
fn decrypt_corrupted_hmac() {
    let password = PasswordString::new(PASSWORD.to_string());
    let plaintext = b"test data";
    let mut encrypted = Vec::new();
    encrypt(
        Cursor::new(plaintext),
        &mut encrypted,
        &password,
        DEFAULT_KDF_ITERATIONS,
    )
    .unwrap();

    // Corrupt the HMAC (last 32 bytes)
    let hmac_start = encrypted.len() - 32;
    encrypted[hmac_start] ^= 0xFF; // Flip bits

    let mut decrypted = Vec::new();
    let result = decrypt(Cursor::new(&encrypted), &mut decrypted, &password);

    assert!(result.is_err(), "Decryption with corrupted HMAC should fail");
    if let Err(e) = result {
        assert!(
            e.to_string().contains("HMAC"),
            "Error should mention HMAC verification failure"
        );
    }
}

#[test]
fn decrypt_corrupted_session_hmac() {
    let password = PasswordString::new(PASSWORD.to_string());
    let plaintext = b"test data";
    let mut encrypted = Vec::new();
    encrypt(
        Cursor::new(plaintext),
        &mut encrypted,
        &password,
        DEFAULT_KDF_ITERATIONS,
    )
    .unwrap();

    // Corrupt the session HMAC (32 bytes after the encrypted session block)
    // Session block is 48 bytes, so HMAC starts at offset after header + extensions + iterations + IV + 48
    // For v3: header(5) + extensions(2) + iterations(4) + IV(16) + session_block(48) = 75
    // Session HMAC is at bytes 75-106
    if encrypted.len() > 106 {
        encrypted[75] ^= 0xFF; // Flip a bit in session HMAC
    }

    let mut decrypted = Vec::new();
    let result = decrypt(Cursor::new(&encrypted), &mut decrypted, &password);

    assert!(result.is_err(), "Decryption with corrupted session HMAC should fail");
    if let Err(e) = result {
        assert!(
            e.to_string().contains("session") || e.to_string().contains("HMAC"),
            "Error should mention session or HMAC verification failure"
        );
    }
}

#[test]
fn decrypt_invalid_magic() {
    let password = PasswordString::new(PASSWORD.to_string());
    let mut invalid_data = vec![0xFFu8; 100];
    invalid_data[0] = b'X'; // Wrong magic
    invalid_data[1] = b'Y';
    invalid_data[2] = b'Z';

    let mut decrypted = Vec::new();
    let result = decrypt(Cursor::new(&invalid_data), &mut decrypted, &password);

    assert!(result.is_err(), "Decryption with invalid magic should fail");
    if let Err(e) = result {
        assert!(
            e.to_string().contains("magic") || e.to_string().contains("AES"),
            "Error should mention invalid magic or AES"
        );
    }
}

#[test]
fn decrypt_unsupported_version() {
    let password = PasswordString::new(PASSWORD.to_string());
    let mut invalid_data = vec![0u8; 100];
    invalid_data[0] = b'A';
    invalid_data[1] = b'E';
    invalid_data[2] = b'S';
    invalid_data[3] = 0x04; // Unsupported version 4

    let mut decrypted = Vec::new();
    let result = decrypt(Cursor::new(&invalid_data), &mut decrypted, &password);

    assert!(result.is_err(), "Decryption with unsupported version should fail");
    if let Err(e) = result {
        assert!(
            e.to_string().contains("Unsupported version") || e.to_string().contains("version"),
            "Error should mention unsupported version"
        );
    }
}

#[test]
fn decrypt_truncated_file() {
    let password = PasswordString::new(PASSWORD.to_string());
    let plaintext = b"test data";
    let mut encrypted = Vec::new();
    encrypt(
        Cursor::new(plaintext),
        &mut encrypted,
        &password,
        DEFAULT_KDF_ITERATIONS,
    )
    .unwrap();

    // Truncate the file (remove last 50 bytes)
    encrypted.truncate(encrypted.len().saturating_sub(50));

    let mut decrypted = Vec::new();
    let result = decrypt(Cursor::new(&encrypted), &mut decrypted, &password);

    assert!(result.is_err(), "Decryption of truncated file should fail");
}

#[test]
fn encrypt_empty_password() {
    let empty_password = PasswordString::new("".to_string());
    let plaintext = b"test";

    let result = encrypt(
        Cursor::new(plaintext),
        &mut Vec::new(),
        &empty_password,
        DEFAULT_KDF_ITERATIONS,
    );

    assert!(result.is_err(), "Encryption with empty password should fail");
    if let Err(e) = result {
        assert!(
            e.to_string().contains("empty password"),
            "Error should mention empty password"
        );
    }
}

#[test]
fn encrypt_invalid_iterations() {
    let password = PasswordString::new("test".to_string());
    let plaintext = b"test";

    // Zero iterations
    let result = encrypt(
        Cursor::new(plaintext),
        &mut Vec::new(),
        &password,
        0,
    );
    assert!(result.is_err(), "Encryption with 0 iterations should fail");

    // Too many iterations
    let result = encrypt(
        Cursor::new(plaintext),
        &mut Vec::new(),
        &password,
        5_000_001,
    );
    assert!(result.is_err(), "Encryption with >5M iterations should fail");
}

// === Edge Case Tests ===
#[test]
fn roundtrip_block_boundary_sizes() {
    let password = PasswordString::new("boundary-test".to_string());
    let sizes = vec![
        1,   // 1 byte
        15,  // Just before block boundary
        16,  // Exactly one block
        17,  // Just after block boundary
        31,  // Just before two blocks
        32,  // Exactly two blocks
        33,  // Just after two blocks
        47,  // Just before three blocks
        48,  // Exactly three blocks
        49,  // Just after three blocks
    ];

    for size in sizes {
        let plaintext = vec![0x42u8; size];
        let mut encrypted = Vec::new();
        encrypt(
            Cursor::new(&plaintext),
            &mut encrypted,
            &password,
            DEFAULT_KDF_ITERATIONS,
        )
        .unwrap();

        let mut decrypted = Vec::new();
        decrypt(Cursor::new(&encrypted), &mut decrypted, &password).unwrap();

        assert_eq!(
            decrypted, plaintext,
            "Round-trip failed for size {size} bytes"
        );
    }
}

#[test]
fn roundtrip_various_passwords() {
    let plaintext = b"test data";
    let passwords = vec![
        PasswordString::new("simple".to_string()),
        PasswordString::new("complex!@#$%^&*()".to_string()),
        PasswordString::new("unicode-パスワード-中文".to_string()),
        PasswordString::new("very-long-password-that-exceeds-normal-length-expectations".to_string()),
        PasswordString::new("with\nnewlines\tand\ttabs".to_string()),
        PasswordString::new("with spaces and special chars !@#$%".to_string()),
    ];

    for password in passwords {
        let mut encrypted = Vec::new();
        encrypt(
            Cursor::new(plaintext),
            &mut encrypted,
            &password,
            DEFAULT_KDF_ITERATIONS,
        )
        .unwrap();

        let mut decrypted = Vec::new();
        decrypt(Cursor::new(&encrypted), &mut decrypted, &password).unwrap();

        assert_eq!(decrypted, plaintext, "Round-trip failed for password");
    }
}

#[test]
fn roundtrip_various_kdf_iterations() {
    let password = PasswordString::new("iterations-test".to_string());
    let plaintext = b"test data";
    // Test with low iteration counts - performance testing is in benches/
    let iterations = vec![1, 5, 10];

    for &iter in &iterations {
        let mut encrypted = Vec::new();
        encrypt(
            Cursor::new(plaintext),
            &mut encrypted,
            &password,
            iter,
        )
        .unwrap();

        let mut decrypted = Vec::new();
        decrypt(Cursor::new(&encrypted), &mut decrypted, &password).unwrap();

        assert_eq!(
            decrypted, plaintext,
            "Round-trip failed with {iter} iterations"
        );
    }
}

#[test]
fn roundtrip_various_input_patterns() {
    let password = PasswordString::new("pattern-test".to_string());
    let patterns = vec![
        vec![0x00u8; 16],           // All zeros
        vec![0xFFu8; 16],           // All ones
        (0..16).collect::<Vec<u8>>(), // Sequential
        (0..32).rev().collect::<Vec<u8>>(), // Reverse sequential
        vec![0xAAu8; 16],           // Alternating pattern
        vec![0x55u8; 16],           // Alternating pattern (inverse)
    ];

    for pattern in patterns {
        let mut encrypted = Vec::new();
        encrypt(
            Cursor::new(&pattern),
            &mut encrypted,
            &password,
            DEFAULT_KDF_ITERATIONS,
        )
        .unwrap();

        let mut decrypted = Vec::new();
        decrypt(Cursor::new(&encrypted), &mut decrypted, &password).unwrap();

        assert_eq!(decrypted, pattern, "Round-trip failed for pattern");
    }
}

#[test]
fn roundtrip_small_inputs() {
    let password = PasswordString::new("small-test".to_string());
    let sizes = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];

    for size in sizes {
        let plaintext = vec![0xAAu8; size];
        let mut encrypted = Vec::new();
        encrypt(
            Cursor::new(&plaintext),
            &mut encrypted,
            &password,
            DEFAULT_KDF_ITERATIONS,
        )
        .unwrap();

        let mut decrypted = Vec::new();
        decrypt(Cursor::new(&encrypted), &mut decrypted, &password).unwrap();

        assert_eq!(
            decrypted, plaintext,
            "Round-trip failed for {size} byte input"
        );
    }
}

#[test]
fn decrypt_corrupted_ciphertext() {
    let password = PasswordString::new(PASSWORD.to_string());
    let plaintext = b"test data";
    let mut encrypted = Vec::new();
    encrypt(
        Cursor::new(plaintext),
        &mut encrypted,
        &password,
        DEFAULT_KDF_ITERATIONS,
    )
    .unwrap();

    // Corrupt a byte in the ciphertext (not the HMAC)
    // Skip header, extensions, iterations, IV, session block, session HMAC
    // Start corrupting in the payload area (after ~107 bytes)
    if encrypted.len() > 120 {
        encrypted[120] ^= 0xFF; // Flip bits in payload
    }

    let mut decrypted = Vec::new();
    let result = decrypt(Cursor::new(&encrypted), &mut decrypted, &password);

    assert!(result.is_err(), "Decryption with corrupted ciphertext should fail");
    if let Err(e) = result {
        assert!(
            e.to_string().contains("HMAC"),
            "Error should mention HMAC verification failure"
        );
    }
}

#[test]
fn roundtrip_deterministic_with_different_iterations() {
    let password = PasswordString::new(PASSWORD.to_string());
    let plaintext = b"deterministic test";
    // Test with low iteration counts - performance testing is in benches/
    let iterations = vec![1, 5, 10];

    for &iter in &iterations {
        let mut encrypted1 = Vec::new();
        let mut encrypted2 = Vec::new();

        encrypt(
            Cursor::new(plaintext),
            &mut encrypted1,
            &password,
            iter,
        )
        .unwrap();

        encrypt(
            Cursor::new(plaintext),
            &mut encrypted2,
            &password,
            iter,
        )
        .unwrap();

        // Encryptions should be different (random IVs and session keys)
        // But both should decrypt to the same plaintext
        assert_ne!(
            encrypted1, encrypted2,
            "Encryptions with same password should differ (random IVs)"
        );

        let mut decrypted1 = Vec::new();
        let mut decrypted2 = Vec::new();

        decrypt(Cursor::new(&encrypted1), &mut decrypted1, &password).unwrap();
        decrypt(Cursor::new(&encrypted2), &mut decrypted2, &password).unwrap();

        assert_eq!(decrypted1, plaintext, "First decryption failed");
        assert_eq!(decrypted2, plaintext, "Second decryption failed");
    }
}