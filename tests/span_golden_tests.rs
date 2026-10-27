//! `tests/span_golden_tests.rs`
//! Pins the bytes the crate writes and reads at sizes around the 16-byte block
//! and the 64 KiB span, for every version (#68).
//!
//! Two independent checks guard the span loop:
//!
//! - **An oracle.** `encrypt_stream` must equal `reference_v3_payload`, a
//!   hand-rolled CBC + PKCS#7 + HMAC in `tests/common.rs`, at every size and
//!   whatever sizes the reader hands back.
//! - **A pin.** For each version, the SHA-256 over every file built at every
//!   size is a constant generated before the span loop existed (at `d12acc3`).
//!   For v3 that pins what the crate itself writes. The crate only reads
//!   v0–v2, so for those the pin holds the test builder's files steady, and
//!   what guards the crate is the next check.
//!
//! Every built file must then decrypt, through both `decrypt` and
//! `decrypt_verified`, to exactly the plaintext it was built from, whether
//! the reader returns everything at once or a few odd-sized bytes at a time.

// Test crate: helpers and fixtures are explained by the tests that use them.
#![allow(clippy::missing_docs_in_private_items)]

use aescrypt_rs::aliases::{Aes256Key32, Iv16};
use aescrypt_rs::constants::SPAN;
use aescrypt_rs::encryption::encrypt_stream;
use aescrypt_rs::{decrypt, decrypt_verified};
use sha2::{Digest, Sha256};
use std::io::{self, Cursor, Read, Seek, SeekFrom};

mod common;
use common::{
    SESSION_IV, SESSION_KEY, TEST_PASSWORD, build_fixed_file, pattern, reference_v3_payload,
};

/// Around the block (0..49), around one span, two and three spans, and well
/// past them.
const SIZES: &[usize] = &[
    0,
    1,
    15,
    16,
    17,
    31,
    32,
    33,
    47,
    48,
    49,
    SPAN - 17,
    SPAN - 1,
    SPAN,
    SPAN + 1,
    2 * SPAN,
    3 * SPAN + 5,
    1024 * 1024 + 7,
];

/// SHA-256 over every file of a version, in `SIZES` order, each prefixed by
/// its length as a little-endian `u64`. Generated at `d12acc3`, before the
/// span loop: these must never change.
const GOLDEN: [&str; 4] = [
    "689d780154afba32f16f30b404f601a53895b29e7a11ddb955b5c2127af9102c",
    "6324e1240fb2addca1c9647fdc49e2671748e4fbacaceb22fa3102cc190f15fd",
    "9990d65b38cce486d5dcbcc4ece0ce2f49fc802688f49e3b7eb7a2ff3e713fe8",
    "ab4efd83394bc54c28b298c24f3e310326d0705ac54aa5bcee63aa5d4c5dfd5d",
];

/// Hands back at most `max` bytes per `read`, so reads land across block and
/// span boundaries at odd offsets.
struct Choppy<R> {
    inner: R,
    max: usize,
}

impl<R: Read> Read for Choppy<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.max);
        self.inner.read(&mut buf[..n])
    }
}

/// `decrypt_verified` needs `Seek`; seeking is passed straight through.
impl<R: Seek> Seek for Choppy<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

fn encrypt_stream_to_vec<R: Read>(source: R) -> Vec<u8> {
    let mut out = Vec::new();
    encrypt_stream(
        source,
        &mut out,
        &Iv16::new(SESSION_IV),
        &Aes256Key32::new(SESSION_KEY),
    )
    .unwrap();
    out
}

/// `encrypt_stream` equals the hand-rolled reference at every size, whether
/// the reader returns everything at once or a few odd-sized bytes at a time.
#[test]
fn encrypt_stream_matches_reference_at_every_size() {
    for &len in SIZES {
        let plaintext = pattern(len);
        let expected = reference_v3_payload(&SESSION_KEY, &SESSION_IV, &plaintext);
        assert!(
            encrypt_stream_to_vec(Cursor::new(&plaintext)) == expected,
            "whole reads, {len} bytes"
        );
        for max in [1, 7, 4097, SPAN - 1, SPAN + 3] {
            if len > 200_000 && max < 4097 {
                continue; // tiny reads over a megabyte prove nothing new and are slow
            }
            let source = Choppy {
                inner: Cursor::new(&plaintext),
                max,
            };
            assert!(
                encrypt_stream_to_vec(source) == expected,
                "reads of at most {max}, {len} bytes"
            );
        }
    }
}

/// Every version's files hash to the constant generated before the span loop.
#[test]
fn files_match_golden_for_every_version() {
    let mut actual = Vec::new();
    for version in 0..=3u8 {
        let mut hasher = Sha256::new();
        for &len in SIZES {
            let file = build_fixed_file(version, &pattern(len));
            hasher.update((len as u64).to_le_bytes());
            hasher.update(&file);
        }
        actual.push(hex::encode(hasher.finalize()));
    }
    let expected: Vec<String> = GOLDEN.iter().map(|s| s.to_string()).collect();
    assert_eq!(actual, expected, "golden digests for v0, v1, v2, v3");
}

/// Every file of every version decrypts back to its plaintext, through both
/// entry points and through a reader that hands back odd-sized pieces.
#[test]
fn every_version_decrypts_at_every_size() {
    for version in 0..=3u8 {
        for &len in SIZES {
            let plaintext = pattern(len);
            let file = build_fixed_file(version, &plaintext);

            let mut one_pass = Vec::new();
            decrypt(Cursor::new(&file), &mut one_pass, TEST_PASSWORD).unwrap();
            assert!(one_pass == plaintext, "decrypt v{version}, {len} bytes");

            let mut verified = Vec::new();
            let outcome = decrypt_verified(Cursor::new(&file), &mut verified, TEST_PASSWORD)
                .unwrap_or_else(|e| panic!("decrypt_verified v{version}, {len} bytes: {e}"));
            assert!(
                verified == plaintext,
                "decrypt_verified v{version}, {len} bytes"
            );
            assert_eq!(outcome.plaintext_len, len as u64);

            let mut choppy = Vec::new();
            let source = Choppy {
                inner: Cursor::new(&file),
                max: 4097,
            };
            decrypt(source, &mut choppy, TEST_PASSWORD).unwrap();
            assert!(
                choppy == plaintext,
                "decrypt v{version}, {len} bytes, 4097-byte reads"
            );
        }
    }
}

/// Decryption's fill and carry see reads that end at every offset within a
/// block: 1, 7, 33 and 47 bytes at a time, and 4097. Both entry points, every
/// version, every size up to two spans and a bit (tiny reads past one span
/// only add time).
#[test]
fn every_version_decrypts_through_small_reads() {
    for version in 0..=3u8 {
        for &len in SIZES.iter().filter(|&&len| len <= 2 * SPAN) {
            let plaintext = pattern(len);
            let file = build_fixed_file(version, &plaintext);
            for max in [1, 7, 33, 47, 4097] {
                if len > SPAN + 1 && max < 33 {
                    continue;
                }
                let mut one_pass = Vec::new();
                let source = Choppy {
                    inner: Cursor::new(&file),
                    max,
                };
                decrypt(source, &mut one_pass, TEST_PASSWORD).unwrap();
                assert!(
                    one_pass == plaintext,
                    "decrypt v{version}, {len} bytes, reads of {max}"
                );

                let mut verified = Vec::new();
                let source = Choppy {
                    inner: Cursor::new(&file),
                    max,
                };
                decrypt_verified(source, &mut verified, TEST_PASSWORD).unwrap();
                assert!(
                    verified == plaintext,
                    "decrypt_verified v{version}, {len} bytes, reads of {max}"
                );
            }
        }
    }
}
