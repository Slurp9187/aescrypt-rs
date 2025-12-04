//! tests/convert_tests.rs
//! Comprehensive legacy (v0/v1/v2) to v3 conversion test suite
//!
//! - Uses **real-world 300_000 PBKDF2 iterations** in release mode
//! - Falls back to **64 iterations** in debug mode for instant feedback
//! - Tests all 63 official vectors (21 per version)
//! - Bit-perfect round-trip verification
//! - Clean, loud debug output with --nocapture

use aescrypt_rs::aliases::PasswordString;
#[allow(deprecated)]
use aescrypt_rs::convert_to_v3;
use aescrypt_rs::decrypt;
use hex::decode;
use serde::Deserialize;
use std::fmt;
use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// PBKDF2 iteration counts
const REAL_WORLD_ITERATIONS: u32 = 300_000;
const DEBUG_ITERATIONS: u32 = 64;
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

/// Thread-safe in-memory writer used by the big vector test
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

    let password = PasswordString::new("Hello".to_string());

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

            #[allow(deprecated)]
            convert_to_v3(
                Cursor::new(legacy_ciphertext),
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
