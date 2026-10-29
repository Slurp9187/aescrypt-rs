//! `tests/verified_decrypt_tests.rs`
//! `decrypt_verified`: byte-identical to `decrypt` on success, and nothing
//! written to the output when verification fails (#58).
//!
//! Each guard of the two-pass design has a test here that fails without it:
//!
//! | Guard | Test |
//! |---|---|
//! | G1 pass-1 tag check | `tampered_ciphertext_writes_nothing` |
//! | G2 v3 padding checked in pass 1 | `v3_valid_hmac_bad_padding_writes_nothing` |
//! | G3 pass 2 must match pass 1 | `input_changed_between_passes_*` |
//! | G4 seek to the recorded payload start | `input_at_an_offset_decrypts_the_same` |
//! | G6 reader errors surface in pass 1 | `reader_cancel_in_pass_one_writes_nothing` |
//! | Span loop (#68): no plaintext before the tag, across spans | `multi_span_tamper_writes_nothing`, `multi_span_truncation_writes_nothing` |

// Test crate: helpers and fixtures are explained by the tests that use them.
#![allow(clippy::missing_docs_in_private_items)]

use aes::Aes256Enc;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aescrypt_rs::aliases::{Aes256Key32, EncryptedSessionBlock48, Iv16};
use aescrypt_rs::encryption::{
    derive_setup_key, encrypt_session_block, write_header, write_hmac, write_iterations,
    write_public_iv,
};
use aescrypt_rs::{AescryptError, decrypt, decrypt_verified, encrypt};
use hmac::{Hmac, Mac};
use secure_gate::RevealSecret;
use sha2::Sha256;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

mod common;
use common::{TEST_ITERATIONS, TEST_PASSWORD, build_fixed_file, pattern};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Every official `.aes` vector file, v0–v3, with its format version.
fn vector_files() -> Vec<(u8, PathBuf)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("test_data")
        .join("aes_test_files");
    let mut files = Vec::new();
    for version in 0..=3u8 {
        let dir = root.join(format!("v{version}"));
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "aes") {
                files.push((version, path));
            }
        }
    }
    files.sort();
    assert!(
        files.len() >= 63,
        "expected the 63 official vectors, found {}",
        files.len()
    );
    files
}

/// The largest vector of `version`, so it has several payload blocks.
fn largest_vector(version: u8) -> Vec<u8> {
    vector_files()
        .into_iter()
        .filter(|(v, _)| *v == version)
        .map(|(_, p)| std::fs::read(p).unwrap())
        .max_by_key(Vec::len)
        .unwrap()
}

/// Trailer length after the payload: 33 for v1/v2 (modulo byte + tag), 32 otherwise.
fn trailer_len(version: u8) -> usize {
    if matches!(version, 1 | 2) { 33 } else { 32 }
}

/// A writer that counts what reaches it and keeps nothing.
#[derive(Default)]
struct CountingSink {
    written: usize,
}

impl Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Runs `decrypt_verified` into a counting sink: the result and the byte count.
fn verified_count(file: &[u8], password: &str) -> (Result<(), AescryptError>, usize) {
    let mut sink = CountingSink::default();
    let result = decrypt_verified(Cursor::new(file), &mut sink, password).map(|_| ());
    (result, sink.written)
}

/// Runs the one-pass `decrypt` into a counting sink: the result and the byte count.
fn one_pass_count(file: &[u8], password: &str) -> (Result<(), AescryptError>, usize) {
    let mut sink = CountingSink::default();
    let result = decrypt(Cursor::new(file), &mut sink, password);
    (result, sink.written)
}

fn header_message(result: Result<(), AescryptError>) -> String {
    match result {
        Err(AescryptError::Header(m)) => m,
        other => panic!("expected a Header error, got {other:?}"),
    }
}

/// Builds a v3 file whose payload is `blocks` CBC-encrypted as given, with
/// no padding applied, and a valid payload HMAC. Lets a test produce a file
/// that authenticates but carries invalid PKCS#7 padding.
fn v3_file_with_raw_blocks(blocks: &[[u8; 16]]) -> Vec<u8> {
    let public_iv = Iv16::new([0x11; 16]);
    let session_iv = Iv16::new([0x22; 16]);
    let session_key = Aes256Key32::new([0x33; 32]);
    let mut out = Vec::new();

    write_header(&mut out, 3).unwrap();
    out.extend_from_slice(&[0x00, 0x00]); // no extensions
    write_iterations(&mut out, TEST_ITERATIONS, 3).unwrap();
    write_public_iv(&mut out, &public_iv).unwrap();

    let mut setup_key = Aes256Key32::new([0u8; 32]);
    derive_setup_key(TEST_PASSWORD, &public_iv, TEST_ITERATIONS, &mut setup_key).unwrap();
    let setup_cipher = setup_key.with_secret(|k| Aes256Enc::new(k.into()));
    let mut session_hmac =
        setup_key.with_secret(|k| <Hmac<Sha256> as KeyInit>::new_from_slice(k).unwrap());
    let mut session_block = EncryptedSessionBlock48::new([0u8; 48]);
    encrypt_session_block(
        &setup_cipher,
        &session_iv,
        &session_key,
        &public_iv,
        &mut session_block,
        &mut session_hmac,
    )
    .unwrap();
    session_hmac.update(&[3]);
    session_block.with_secret(|b| out.extend_from_slice(b));
    write_hmac(&mut out, session_hmac).unwrap();

    let cipher = session_key.with_secret(|k| Aes256Enc::new(k.into()));
    let mut payload_hmac =
        session_key.with_secret(|k| <Hmac<Sha256> as KeyInit>::new_from_slice(k).unwrap());
    let mut chain = session_iv.with_secret(|iv| *iv);
    for plain in blocks {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = plain[i] ^ chain[i];
        }
        cipher.encrypt_block((&mut block).into());
        payload_hmac.update(&block);
        out.extend_from_slice(&block);
        chain = block;
    }
    write_hmac(&mut out, payload_hmac).unwrap();
    out
}

/// A `Read + Seek` over a buffer that flips one byte the first time it is
/// sought to an absolute position: that is, between pass 1 and pass 2.
struct MutateBetweenPasses {
    inner: Cursor<Vec<u8>>,
    flip_at: usize,
    xor: u8,
    flipped: bool,
}

impl Read for MutateBetweenPasses {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Seek for MutateBetweenPasses {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        if matches!(pos, SeekFrom::Start(_)) && !self.flipped {
            self.inner.get_mut()[self.flip_at] ^= self.xor;
            self.flipped = true;
        }
        self.inner.seek(pos)
    }
}

/// Runs `decrypt_verified` with one byte changed between the passes.
fn changed_between_passes(
    file: Vec<u8>,
    flip_at: usize,
    xor: u8,
) -> (Result<(), AescryptError>, usize) {
    let input = MutateBetweenPasses {
        inner: Cursor::new(file),
        flip_at,
        xor,
        flipped: false,
    };
    let mut sink = CountingSink::default();
    let result = decrypt_verified(input, &mut sink, TEST_PASSWORD).map(|_| ());
    (result, sink.written)
}

/// A reader that fails with a non-`Interrupted` error once `limit` bytes
/// have been read in total: a caller cancelling mid-stream.
struct CancelAfter {
    inner: Cursor<Vec<u8>>,
    read: usize,
    limit: usize,
}

impl Read for CancelAfter {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.read >= self.limit {
            return Err(io::Error::other("cancelled"));
        }
        let room = (self.limit - self.read).min(buf.len());
        let n = self.inner.read(&mut buf[..room])?;
        self.read += n;
        Ok(n)
    }
}

impl Seek for CancelAfter {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

// ---------------------------------------------------------------------------
// Byte-identical on success
// ---------------------------------------------------------------------------

/// All official vectors: same plaintext as `decrypt`, the right version, and
/// `plaintext_len` equal to what was written.
#[test]
fn identical_to_decrypt_on_every_vector() {
    let files = vector_files();
    for (version, path) in &files {
        let file = std::fs::read(path).unwrap();

        let mut expected = Vec::new();
        decrypt(Cursor::new(&file), &mut expected, TEST_PASSWORD)
            .unwrap_or_else(|e| panic!("{}: decrypt failed: {e}", path.display()));

        let mut actual = Vec::new();
        let outcome = decrypt_verified(Cursor::new(&file), &mut actual, TEST_PASSWORD)
            .unwrap_or_else(|e| panic!("{}: decrypt_verified failed: {e}", path.display()));

        assert_eq!(actual, expected, "{}", path.display());
        assert_eq!(outcome.version, *version, "{}", path.display());
        assert_eq!(
            outcome.plaintext_len,
            actual.len() as u64,
            "{}",
            path.display()
        );
        assert_eq!(outcome.length_authenticated(), *version == 3);
    }
    eprintln!("checked {} vectors", files.len());
}

/// Round trip at every length across the block and padding boundaries,
/// empty included.
#[test]
fn round_trip_every_length_to_three_blocks() {
    for len in 0..=48usize {
        let plaintext: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let mut file = Vec::new();
        encrypt(
            Cursor::new(&plaintext),
            &mut file,
            TEST_PASSWORD,
            TEST_ITERATIONS,
        )
        .unwrap();

        let mut out = Vec::new();
        let outcome = decrypt_verified(Cursor::new(&file), &mut out, TEST_PASSWORD).unwrap();
        assert_eq!(out, plaintext, "len {len}");
        assert_eq!(outcome.plaintext_len, len as u64);
    }
}

// ---------------------------------------------------------------------------
// G1: nothing is written when the tag does not verify
// ---------------------------------------------------------------------------

#[test]
fn tampered_ciphertext_writes_nothing() {
    for version in 0..=3u8 {
        let mut file = largest_vector(version);
        let last_ciphertext_byte = file.len() - trailer_len(version) - 1;
        file[last_ciphertext_byte] ^= 0x01;

        let (result, written) = verified_count(&file, TEST_PASSWORD);
        assert_eq!(
            header_message(result),
            "HMAC verification failed",
            "v{version}"
        );
        assert_eq!(
            written, 0,
            "v{version}: plaintext reached W before the tag was checked"
        );

        // The contrast: the one-pass decrypt has already written plaintext.
        let (one_pass, one_pass_written) = one_pass_count(&file, TEST_PASSWORD);
        assert!(one_pass.is_err());
        assert!(
            one_pass_written > 0,
            "v{version}: vector too short to show the difference"
        );
    }
}

#[test]
fn tampered_tag_writes_nothing() {
    for version in 0..=3u8 {
        let mut file = largest_vector(version);
        let last = file.len() - 1;
        file[last] ^= 0x80;

        let (result, written) = verified_count(&file, TEST_PASSWORD);
        assert_eq!(
            header_message(result),
            "HMAC verification failed",
            "v{version}"
        );
        assert_eq!(written, 0, "v{version}");
    }
}

#[test]
fn truncated_payload_writes_nothing() {
    for version in 0..=3u8 {
        let mut file = largest_vector(version);
        let cut = file.len() - trailer_len(version) - 16;
        file.drain(cut..cut + 16); // drop the last whole ciphertext block

        let (result, written) = verified_count(&file, TEST_PASSWORD);
        assert!(result.is_err(), "v{version}");
        assert_eq!(written, 0, "v{version}");
    }
}

/// v0 has no session block, so a wrong password only shows at the payload
/// tag. `decrypt` writes garbage first; `decrypt_verified` writes nothing.
#[test]
fn v0_wrong_password_writes_nothing() {
    let file = largest_vector(0);

    let (result, written) = verified_count(&file, "wrong");
    assert_eq!(header_message(result), "HMAC verification failed");
    assert_eq!(written, 0);

    let (one_pass, one_pass_written) = one_pass_count(&file, "wrong");
    assert!(one_pass.is_err());
    assert!(one_pass_written > 0);
}

/// v1–v3 reject a wrong password at the session block, before the payload.
#[test]
fn v1_to_v3_wrong_password_writes_nothing() {
    for version in 1..=3u8 {
        let (result, written) = verified_count(&largest_vector(version), "wrong");
        assert!(
            header_message(result).contains("session data"),
            "v{version}"
        );
        assert_eq!(written, 0, "v{version}");
    }
}

// ---------------------------------------------------------------------------
// G2: v3 padding is checked before any plaintext is released
// ---------------------------------------------------------------------------

/// The helper is sound: with valid padding the file decrypts.
#[test]
fn v3_raw_block_helper_round_trips() {
    let mut last = [0xCC; 16];
    last[12..].fill(4);
    let file = v3_file_with_raw_blocks(&[[0xAA; 16], [0xBB; 16], last]);

    let mut out = Vec::new();
    decrypt_verified(Cursor::new(&file), &mut out, TEST_PASSWORD).unwrap();
    let mut expected = [[0xAA; 16], [0xBB; 16]].concat();
    expected.extend_from_slice(&[0xCC; 12]);
    assert_eq!(out, expected);
}

/// A v3 file whose HMAC is valid but whose final block's padding is not.
#[test]
fn v3_valid_hmac_bad_padding_writes_nothing() {
    for bad_last in [[0x00; 16], [0x11; 16], {
        let mut b = [4u8; 16];
        b[13] = 3; // claims 4 padding bytes, one is wrong
        b
    }] {
        let file = v3_file_with_raw_blocks(&[[0xAA; 16], [0xBB; 16], bad_last]);

        let (result, written) = verified_count(&file, TEST_PASSWORD);
        assert_eq!(header_message(result), "v3: invalid PKCS#7 padding");
        assert_eq!(
            written, 0,
            "padding was checked only after plaintext was written"
        );

        let (one_pass, one_pass_written) = one_pass_count(&file, TEST_PASSWORD);
        assert_eq!(header_message(one_pass), "v3: invalid PKCS#7 padding");
        assert_eq!(one_pass_written, 32);
    }
}

/// A one-block payload: the padding check chains off the session IV.
#[test]
fn v3_single_block_bad_padding_writes_nothing() {
    let file = v3_file_with_raw_blocks(&[[0x00; 16]]);
    let (result, written) = verified_count(&file, TEST_PASSWORD);
    assert_eq!(header_message(result), "v3: invalid PKCS#7 padding");
    assert_eq!(written, 0);

    let mut ok = [0x55; 16];
    ok[15] = 1;
    let mut out = Vec::new();
    decrypt_verified(
        Cursor::new(v3_file_with_raw_blocks(&[ok])),
        &mut out,
        TEST_PASSWORD,
    )
    .unwrap();
    assert_eq!(out, [0x55; 15]);
}

/// A v3 payload with no blocks at all is malformed and writes nothing.
#[test]
fn v3_empty_payload_is_rejected() {
    let file = v3_file_with_raw_blocks(&[]);
    let (result, written) = verified_count(&file, TEST_PASSWORD);
    assert_eq!(header_message(result), "v3: missing final plaintext block");
    assert_eq!(written, 0);
}

// ---------------------------------------------------------------------------
// G3: pass 2 must read what pass 1 verified
// ---------------------------------------------------------------------------

#[test]
fn input_changed_between_passes_ciphertext() {
    for version in 0..=3u8 {
        let file = largest_vector(version);
        let at = file.len() - trailer_len(version) - 1;
        let (result, _) = changed_between_passes(file, at, 0x01);
        assert_eq!(
            header_message(result),
            "input changed between verification and decryption",
            "v{version}"
        );
    }
}

/// The v1/v2 length byte is outside the HMAC, so only the cross-check sees
/// it change between the passes.
#[test]
fn input_changed_between_passes_modulo_byte() {
    for version in [1u8, 2] {
        let file = largest_vector(version);
        let modulo_at = file.len() - 33;
        let (result, _) = changed_between_passes(file, modulo_at, 0x01);
        assert_eq!(
            header_message(result),
            "input changed between verification and decryption",
            "v{version}"
        );
    }
}

#[test]
fn input_changed_between_passes_tag() {
    for version in 0..=3u8 {
        let file = largest_vector(version);
        let at = file.len() - 1;
        let (result, _) = changed_between_passes(file, at, 0x01);
        assert_eq!(
            header_message(result),
            "input changed between verification and decryption",
            "v{version}"
        );
    }
}

// ---------------------------------------------------------------------------
// G4: the payload start is recorded, not assumed
// ---------------------------------------------------------------------------

#[test]
fn input_at_an_offset_decrypts_the_same() {
    for version in 0..=3u8 {
        let file = largest_vector(version);
        let mut expected = Vec::new();
        decrypt(Cursor::new(&file), &mut expected, TEST_PASSWORD).unwrap();

        let mut embedded = b"PREFIX!".to_vec();
        embedded.extend_from_slice(&file);
        let mut input = Cursor::new(embedded);
        input.set_position(7);

        let mut out = Vec::new();
        decrypt_verified(&mut input, &mut out, TEST_PASSWORD).unwrap();
        assert_eq!(out, expected, "v{version}");
    }
}

// ---------------------------------------------------------------------------
// G6: a cancelling reader
// ---------------------------------------------------------------------------

/// Cancelling during pass 1 (after the header) returns `Io` and writes nothing.
#[test]
fn reader_cancel_in_pass_one_writes_nothing() {
    for version in 0..=3u8 {
        let file = largest_vector(version);
        let limit = file.len() - trailer_len(version) - 8; // inside the last block
        let input = CancelAfter {
            inner: Cursor::new(file),
            read: 0,
            limit,
        };
        let mut sink = CountingSink::default();
        let result = decrypt_verified(input, &mut sink, TEST_PASSWORD);
        assert!(
            matches!(&result, Err(AescryptError::Io(e)) if e.to_string() == "cancelled"),
            "v{version}: {result:?}"
        );
        assert_eq!(sink.written, 0, "v{version}");
    }
}

/// Cancelling during pass 2 still surfaces as `Io`.
#[test]
fn reader_cancel_in_pass_two_is_an_error() {
    for version in 0..=3u8 {
        let file = largest_vector(version);
        let limit = file.len() + 40; // all of pass 1, then part of pass 2
        let input = CancelAfter {
            inner: Cursor::new(file),
            read: 0,
            limit,
        };
        let result = decrypt_verified(input, io::sink(), TEST_PASSWORD);
        assert!(
            matches!(&result, Err(AescryptError::Io(e)) if e.to_string() == "cancelled"),
            "v{version}: {result:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The documented v0–v2 limit
// ---------------------------------------------------------------------------

/// v0–v2 leave the final-block length byte outside the HMAC. Changing it is
/// not detected: the output stays a run of authenticated bytes, only its
/// final-block length differs. This pins the documented format limit; it is
/// not a guarantee `decrypt_verified` can give.
#[test]
fn legacy_length_byte_is_not_authenticated() {
    for version in 1..=2u8 {
        let file = largest_vector(version);
        let mut expected = Vec::new();
        decrypt(Cursor::new(&file), &mut expected, TEST_PASSWORD).unwrap();

        let mut altered = file.clone();
        let modulo_at = altered.len() - 33;
        altered[modulo_at] = 1; // keep one byte of the final block

        let mut out = Vec::new();
        let outcome = decrypt_verified(Cursor::new(&altered), &mut out, TEST_PASSWORD).unwrap();
        assert!(!outcome.length_authenticated());
        let full_blocks = expected.len().div_ceil(16).saturating_sub(1) * 16;
        assert_eq!(out.len(), full_blocks + 1, "v{version}");
        assert_eq!(
            out[..full_blocks + 1],
            expected[..full_blocks + 1],
            "v{version}"
        );
    }
}

// ---------------------------------------------------------------------------
// Span loop (#68): files several 64 KiB spans long
// ---------------------------------------------------------------------------

use aescrypt_rs::constants::SPAN;

/// Plaintext length of the multi-span files: four spans and a partial block.
const MULTI_SPAN_LEN: usize = 4 * SPAN + 5;

/// Where the payload ciphertext starts in a multi-span file of `version`.
fn payload_start(version: u8, file: &[u8]) -> usize {
    let ciphertext = if version == 3 {
        (MULTI_SPAN_LEN / 16 + 1) * 16
    } else {
        MULTI_SPAN_LEN.div_ceil(16) * 16
    };
    file.len() - ciphertext - trailer_len(version)
}

/// A flipped ciphertext bit in a later span, or in the last block, is caught
/// by pass 1 before any plaintext of the earlier spans is released.
#[test]
fn multi_span_tamper_writes_nothing() {
    for version in 0..=3u8 {
        let clean = build_fixed_file(version, &pattern(MULTI_SPAN_LEN));
        let start = payload_start(version, &clean);
        let last_ciphertext_byte = clean.len() - trailer_len(version) - 1;
        for offset in [start + 3 * SPAN + 5, last_ciphertext_byte] {
            let mut file = clean.clone();
            file[offset] ^= 0x01;

            let (result, written) = verified_count(&file, TEST_PASSWORD);
            assert_eq!(
                header_message(result),
                "HMAC verification failed",
                "v{version}, byte {offset}"
            );
            assert_eq!(written, 0, "v{version}, byte {offset}: plaintext released");
            assert!(one_pass_count(&file, TEST_PASSWORD).0.is_err());
        }
    }
}

/// A file cut at a span boundary, at the edge of the first fill, mid-span, or
/// 1 to 47 bytes short (every carry length the framing can see) is refused
/// with nothing written.
#[test]
fn multi_span_truncation_writes_nothing() {
    for version in 0..=3u8 {
        let clean = build_fixed_file(version, &pattern(MULTI_SPAN_LEN));
        let start = payload_start(version, &clean);
        let mut cuts = vec![start + SPAN, start + SPAN + 48, start + 2 * SPAN + 777];
        cuts.extend((1..=47).map(|short| clean.len() - short));
        for cut in cuts {
            let file = &clean[..cut];

            let (result, written) = verified_count(file, TEST_PASSWORD);
            assert!(result.is_err(), "v{version}, cut at {cut}");
            assert_eq!(written, 0, "v{version}, cut at {cut}: plaintext released");
            assert!(
                one_pass_count(file, TEST_PASSWORD).0.is_err(),
                "v{version}, cut at {cut}"
            );
        }
    }
}

/// A writer that counts its calls as well as its bytes.
#[derive(Default)]
struct CallCounter {
    calls: usize,
    bytes: usize,
}

impl Write for CallCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        self.bytes += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Decryption writes its plaintext a span at a time, not a block at a time:
/// one call per span, plus the final block. Block-at-a-time output was about
/// 65 000 calls for this file.
#[test]
fn decrypt_writes_whole_spans() {
    let len: usize = 1024 * 1024 + 7;
    let most = len.div_ceil(SPAN) + 2;
    for version in 0..=3u8 {
        let file = build_fixed_file(version, &pattern(len));

        let mut verified = CallCounter::default();
        decrypt_verified(Cursor::new(&file), &mut verified, TEST_PASSWORD).unwrap();
        assert_eq!(verified.bytes, len, "v{version}");
        assert!(
            verified.calls <= most,
            "v{version}: decrypt_verified made {} writes",
            verified.calls
        );

        let mut one_pass = CallCounter::default();
        decrypt(Cursor::new(&file), &mut one_pass, TEST_PASSWORD).unwrap();
        assert_eq!(one_pass.bytes, len, "v{version}");
        assert!(
            one_pass.calls <= most,
            "v{version}: decrypt made {} writes",
            one_pass.calls
        );
    }
}

/// Encryption writes its ciphertext a span at a time too. The header, the
/// session block and the tags account for the fixed allowance.
#[test]
fn encrypt_writes_whole_spans() {
    let len: usize = 1024 * 1024 + 7;
    let mut out = CallCounter::default();
    encrypt(
        Cursor::new(pattern(len)),
        &mut out,
        TEST_PASSWORD,
        TEST_ITERATIONS,
    )
    .unwrap();
    assert!(
        out.calls <= len.div_ceil(SPAN) + 16,
        "encrypt made {} writes",
        out.calls
    );
}
