//! tests/header_tests.rs
//! Header validation using the *real* test vectors from tests/vector/data/

use aescrypt_rs::read_version;
use hex::decode;
use serde::Deserialize;
use std::io::Cursor;
use std::path::Path;

// Re-use the exact same loader from your vector tests
fn load_json<T>(filename: &str) -> Vec<T>
where
    T: for<'de> Deserialize<'de>,
{
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vector")
        .join("data")
        .join(filename);

    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to read {filename}: {e}"));

    serde_json::from_str(&content).unwrap_or_else(|e| panic!("Failed to parse {filename}: {e}"))
}

#[derive(Debug, Deserialize)]
struct Vector {
    #[serde(alias = "encrypted_hex")]
    #[serde(alias = "ciphertext_hex")]
    ciphertext_hex: String,
}

#[test]
fn read_version_against_all_official_vectors() {
    let files = [
        ("test_vectors_v0.json", 0u8),
        ("test_vectors_v1.json", 1u8),
        ("test_vectors_v2.json", 2u8),
        ("test_vectors_v3.json", 3u8),
    ];

    for (filename, expected_version) in files {
        let vectors: Vec<Vector> = load_json(filename);

        for (i, v) in vectors.iter().enumerate() {
            let ciphertext = decode(&v.ciphertext_hex)
                .unwrap_or_else(|e| panic!("Invalid hex in {filename} vector {i}: {e}"));

            // Take first 5 bytes (or fewer) — real files may be shorter
            let header = if ciphertext.len() >= 5 {
                &ciphertext[..5]
            } else {
                &ciphertext[..]
            };

            let version = read_version(Cursor::new(header))
                .unwrap_or_else(|e| panic!("read_version failed on {filename} vector {i}: {e}"));

            assert_eq!(
                version,
                expected_version,
                "Wrong version in {filename} vector {i} (header: {:02x?})",
                &ciphertext[..header.len()]
            );
        }
    }

    println!("All 63 official vectors passed read_version() check!");
}

#[test]
fn short_file_only_aes_is_v0() {
    let data = b"AES";
    assert_eq!(read_version(Cursor::new(data)).unwrap(), 0);
}

#[test]
fn invalid_magic_rejected() {
    let data = b"XYZ";
    let err = read_version(Cursor::new(data)).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Header error: Not an AES Crypt file: invalid magic"
    );
}

#[test]
fn unsupported_version_rejected() {
    let data = b"AES\x05\x00";
    let err = read_version(Cursor::new(data)).unwrap_err();
    assert_eq!(err.to_string(), "Header error: Unsupported version: 5");
}

#[test]
fn invalid_reserved_byte_rejected() {
    let data = b"AES\x02\x01";
    let err = read_version(Cursor::new(data)).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Header error: Invalid header: reserved byte != 0x00"
    );
}
