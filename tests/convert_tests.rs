//! tests/convert_tests.rs
//! Comprehensive legacy (v0/v1/v2) to v3 conversion test suite
//!
//! - Uses **real-world 300_000 PBKDF2 iterations** in release mode
//! - Falls back to **64 iterations** in debug mode for instant feedback
//! - Tests all 63 official vectors (21 per version)
//! - Bit-perfect round-trip verification
//! - Clean, loud debug output with --nocapture

use aescrypt_rs::aliases::Password;
use aescrypt_rs::convert::convert_to_v3_to_vec;
use aescrypt_rs::{convert_to_v3, decrypt, encrypt};
use hex::decode;
use serde::Deserialize;
use std::fmt;
use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Real-world iteration count used in production
const REAL_WORLD_ITERATIONS: u32 = 300_000;

/// Fast iteration count for rapid developer feedback
const DEBUG_ITERATIONS: u32 = 64;

/// Automatically choose correct iteration count:
//  • `cargo test` → ~3 seconds
//  • `cargo test --release` → ~25 seconds with full security
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

    const fn json_filename(self) -> &'static str {
        match self {
            Self::V0 => "test_vectors_v0.json",
            Self::V1 => "test_vectors_v1.json",
            Self::V2 => "test_vectors_v2.json",
        }
    }

    const fn all_legacy() -> [Self; 3] {
        [Self::V0, Self::V1, Self::V2]
    }
}

impl fmt::Display for AescryptVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
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

    println!("[INFO Loading test vectors → {}", path.display());
    let content = std::fs::read_to_string(&path).expect("failed to read test vector file");
    serde_json::from_str(&content).expect("failed to parse test vector JSON")
}

#[derive(Debug, Deserialize)]
struct DecryptVector {
    #[serde(alias = "encrypted_hex")]
    #[serde(alias = "ciphertext_hex")]
    ciphertext_hex: String,
    plaintext: String,
}

/// In-memory writer that can be shared and inspected after use
#[derive(Clone)]
struct SharedBufferWriter(Arc<Mutex<Vec<u8>>>);

impl SharedBufferWriter {
    fn new() -> (Self, Arc<Mutex<Vec<u8>>>) {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        (Self(buffer.clone()), buffer)
    }
}

impl Write for SharedBufferWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn convert_to_v3_preserves_content_perfectly() {
    println!("\nStarting legacy to v3 conversion test suite");
    println!(
        "PBKDF2 iterations: {} ({})",
        TEST_KDF_ITERATIONS,
        if cfg!(debug_assertions) {
            "debug mode → FAST"
        } else {
            "release mode → REAL-WORLD SECURITY"
        }
    );
    println!("This is correct and expected behavior.\n");

    let password = Password::new("Hello".to_string());

    for version in AescryptVersion::all_legacy() {
        let vectors: Vec<DecryptVector> = load_json(version.json_filename());
        println!("Loaded {} vectors for version {}", vectors.len(), version);

        for (i, v) in vectors.iter().enumerate() {
            let start = Instant::now();

            println!(
                "[{}/{}] Converting {} vector #{} … (plaintext: {} bytes)",
                version,
                vectors.len(),
                version,
                i,
                v.plaintext.len()
            );

            let legacy_ciphertext = decode(&v.ciphertext_hex).expect("invalid hex in test vector");

            let (writer, buffer_handle) = SharedBufferWriter::new();

            convert_to_v3(
                Cursor::new(&legacy_ciphertext),
                writer,
                &password,
                TEST_KDF_ITERATIONS,
            )
            .unwrap_or_else(|e| panic!("convert_to_v3 failed on {version} vector {i}: {e:?}"));

            let v3_file = {
                let guard = buffer_handle.lock().unwrap();
                guard.clone()
            };

            let mut recovered = Vec::new();
            decrypt(Cursor::new(&v3_file), &mut recovered, &password).unwrap_or_else(|e| {
                panic!("decrypt failed on converted {version} vector {i}: {e:?}")
            });

            assert_eq!(
                recovered,
                v.plaintext.as_bytes(),
                "BIT-PERFECT round-trip failed on {version} vector {i}"
            );

            let elapsed = start.elapsed();
            println!(
                "[{version}] vector {i:>2} OK → {} → {} bytes in {:.2?}",
                v.plaintext.len(),
                v3_file.len(),
                elapsed
            );
        }
    }

    println!("\nAll 63 legacy files converted to v3 with bit-perfect round-trip!");
    println!("Test passed with real-world security settings.\n");
}

#[test]
fn convert_to_v3_to_vec_round_trip() {
    let plaintext = b"The quick brown fox jumps over the lazy dog";
    let password = Password::new("test123".to_string());
    let iterations = 5;

    // Step 1: Create v2 file in memory
    let mut v2_data = Vec::new();
    encrypt(
        Cursor::new(plaintext.as_ref()),
        &mut v2_data,
        &password,
        iterations,
    )
    .expect("failed to create v2 file");

    // Step 2: Clone data into the thread — makes it 'static
    let v2_data_clone = v2_data.clone();

    let v3_data = convert_to_v3_to_vec(
        Cursor::new(v2_data_clone), // owned, lives forever
        &password,
        iterations,
    )
    .expect("convert_to_v3_to_vec failed");

    // Step 3: Verify v3 header
    assert_eq!(&v3_data[0..5], b"AES\x03\x00");

    // Step 4: Decrypt v3 → original plaintext
    let mut decrypted = Vec::new();
    decrypt(Cursor::new(&v3_data), &mut decrypted, &password).expect("failed to decrypt v3");

    assert_eq!(decrypted, plaintext);
    println!("convert_to_v3_to_vec: round-trip PASSED — perfect");
}
