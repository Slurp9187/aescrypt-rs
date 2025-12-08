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

#[test]
fn v0_4byte_header_zero_byte() {
    // v0 legacy 4-byte header: "AES" + 0x00
    let data = b"AES\x00";
    assert_eq!(read_version(Cursor::new(data)).unwrap(), 0);
}

#[test]
fn v0_4byte_header_nonzero_byte_rejected() {
    // v0 legacy 4-byte header with non-zero byte should error
    let data = b"AES\x01";
    let err = read_version(Cursor::new(data)).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Header error: Invalid v0 header: version byte not zero"
    );
}

#[test]
fn v0_allows_nonzero_reserved_byte() {
    // v0 allows non-zero reserved byte (only v1+ require 0x00)
    let data = b"AES\x00\xFF"; // v0 with reserved = 0xFF
    assert_eq!(read_version(Cursor::new(data)).unwrap(), 0);
}

#[test]
fn version_boundary_values() {
    // Test all valid versions
    let valid_versions = [
        (b"AES\x00\x00".as_slice(), 0u8),
        (b"AES\x01\x00".as_slice(), 1u8),
        (b"AES\x02\x00".as_slice(), 2u8),
        (b"AES\x03\x00".as_slice(), 3u8),
    ];
    
    for (data, expected) in valid_versions {
        assert_eq!(
            read_version(Cursor::new(data)).unwrap(),
            expected,
            "Failed for version {}",
            expected
        );
    }
}

#[test]
fn unsupported_version_boundary_values() {
    // Test versions > 3
    let unsupported_versions = [4u8, 5u8, 10u8, 255u8];
    
    for version in unsupported_versions {
        let data = [b'A', b'E', b'S', version, 0x00];
        let err = read_version(Cursor::new(&data)).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("Header error: Unsupported version: {}", version)
        );
    }
}

#[test]
fn io_error_on_short_magic_read() {
    // Test I/O error when magic read fails (short read)
    use std::io::{self, Read};
    
    struct ShortReader;
    impl Read for ShortReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            // Only read 2 bytes instead of 3
            if buf.len() >= 2 {
                buf[0] = b'A';
                buf[1] = b'E';
                Ok(2)
            } else {
                Ok(0)
            }
        }
    }
    
    let err = read_version(ShortReader).unwrap_err();
    // Should be I/O error from read_exact
    match err {
        aescrypt_rs::AescryptError::Io(_) => {},
        e => panic!("Expected I/O error, got: {:?}", e),
    }
}

#[test]
fn all_version_combinations() {
    // Test all valid version/reserved combinations
    let cases = vec![
        // v0 allows any reserved byte
        (b"AES\x00\x00".as_slice(), 0u8),
        (b"AES\x00\x01".as_slice(), 0u8),
        (b"AES\x00\xFF".as_slice(), 0u8),
        // v1+ require reserved = 0x00
        (b"AES\x01\x00".as_slice(), 1u8),
        (b"AES\x02\x00".as_slice(), 2u8),
        (b"AES\x03\x00".as_slice(), 3u8),
    ];
    
    for (data, expected) in cases {
        assert_eq!(
            read_version(Cursor::new(data)).unwrap(),
            expected,
            "Failed for data: {:02x?}",
            data
        );
    }
}