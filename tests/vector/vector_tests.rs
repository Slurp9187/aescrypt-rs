//! tests/vector/vector_tests.rs
//! Final merged vector test suite – fully compatible with v0–v3 JSON formats (2025)

use aescrypt_rs::aliases::{Aes256Key, Iv16, Password};
use aescrypt_rs::decrypt;
use aescrypt_rs::encrypt;
use aescrypt_rs::encryptor::encrypt_with_fixed_session;
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
        .join("vector")
        .join("data")
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
    let password = Password::new(PASSWORD.to_string());

    for (i, v) in vectors.iter().enumerate() {
        let encrypted = decode(&v.ciphertext_hex)
            .unwrap_or_else(|e| panic!("Vector {i} ({}) invalid hex: {e}", version.name()));

        let mut decrypted = Vec::new();
        decrypt(password.clone(), Cursor::new(&encrypted), &mut decrypted)
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
    let password = Password::new(PASSWORD.to_string());

    for (i, v) in vectors.iter().enumerate() {
        let plaintext = v.plaintext.as_bytes();

        let mut encrypted = Vec::new();
        encrypt(
            password.clone(),
            Cursor::new(plaintext),
            &mut encrypted,
            DEFAULT_KDF_ITERATIONS,
        )
        .unwrap_or_else(|e| panic!("Vector {i} ({}) encrypt failed: {e:?}", version.name()));

        let mut decrypted = Vec::new();
        decrypt(password.clone(), Cursor::new(&encrypted), &mut decrypted)
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
    let password = Password::new(PASSWORD.to_string());

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
        let session_key = Aes256Key::from(session_key_arr);

        let mut encrypted = Vec::new();
        encrypt_with_fixed_session(
            password.clone(),
            Cursor::new(plaintext),
            &mut encrypted,
            v.kdf_iterations,
            &public_iv,
            &session_iv,
            &session_key,
        )
        .unwrap_or_else(|e| panic!("Vector {i}: fixed encrypt failed: {e:?}"));

        assert_eq!(encrypted, expected_ct, "Ciphertext mismatch in vector {i}");

        let mut decrypted = Vec::new();
        decrypt(password.clone(), Cursor::new(&encrypted), &mut decrypted)
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
    let password = Password::new("test-empty".to_string());
    let mut encrypted = Vec::new();
    encrypt(
        password.clone(),
        Cursor::new(b""),
        &mut encrypted,
        DEFAULT_KDF_ITERATIONS,
    )
    .unwrap();
    let mut decrypted = Vec::new();
    decrypt(password, Cursor::new(&encrypted), &mut decrypted).unwrap();
    assert!(decrypted.is_empty());
}

#[test]
fn roundtrip_v3_large_input() {
    let plaintext = vec![0x41u8; 10_000];
    let password = Password::new("test-large".to_string());
    let mut encrypted = Vec::new();
    encrypt(
        password.clone(),
        Cursor::new(&plaintext),
        &mut encrypted,
        DEFAULT_KDF_ITERATIONS,
    )
    .unwrap();
    let mut decrypted = Vec::new();
    decrypt(password, Cursor::new(&encrypted), &mut decrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn roundtrip_v3_huge_input() {
    let plaintext = vec![0x41u8; 10 * 1024 * 1024];
    let password = Password::new("test-huge-10mib".to_string());
    let mut encrypted = Vec::new();
    encrypt(
        password.clone(),
        Cursor::new(&plaintext),
        &mut encrypted,
        DEFAULT_KDF_ITERATIONS,
    )
    .unwrap();
    let mut decrypted = Vec::new();
    decrypt(password, Cursor::new(&encrypted), &mut decrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
#[ignore = "1 GiB round-trip is intentionally heavy"]
fn roundtrip_extreme_1gib() {
    const ONE_GIB: usize = 1024 * 1024 * 1024;
    let password = Password::new("test-1gib-streaming".to_string());

    let chunk = [0x41u8; 4096];
    let mut plaintext = Vec::with_capacity(ONE_GIB);
    for _ in 0..(ONE_GIB / chunk.len()) {
        plaintext.extend_from_slice(&chunk);
    }
    plaintext.extend_from_slice(&chunk[0..(ONE_GIB % chunk.len())]);

    let mut encrypted = Vec::new();
    encrypt(
        password.clone(),
        Cursor::new(&plaintext),
        &mut encrypted,
        DEFAULT_KDF_ITERATIONS,
    )
    .unwrap();
    let mut decrypted = Vec::new();
    decrypt(password, Cursor::new(&encrypted), &mut decrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}
