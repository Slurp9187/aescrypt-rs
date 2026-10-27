//! `tests/common.rs`
//! Common constants and utilities shared across test files

// Test crate: helpers and fixtures are explained by the tests that use them.
#![allow(clippy::missing_docs_in_private_items)]

/// Fast iteration count for tests - performance testing is in `benches/`
/// Most tests use this value to keep test execution fast.
pub const TEST_ITERATIONS: u32 = 5;

/// Standard test password used across test vectors and test files
/// Matches the password used in the `test_data/` test vectors and `.aes` files
#[allow(dead_code)] // Used across multiple test files
pub const TEST_PASSWORD: &str = "Hello";

/// Common test data strings used across multiple tests
#[allow(dead_code)] // Used across multiple test files
pub const TEST_DATA: &[u8] = b"test data";

/// A 4-byte plaintext, shorter than one AES block
#[allow(dead_code)] // Used across multiple test files
pub const TEST_DATA_SHORT: &[u8] = b"test";

/// Common iteration count vectors for testing various iteration values
#[allow(dead_code)] // Used across multiple test files
pub const TEST_ITERATION_VALUES: &[u32] = &[1, TEST_ITERATIONS, 10];

// ─────────────────────────────────────────────────────────────────────────────
// Deterministic file builders
// ─────────────────────────────────────────────────────────────────────────────
//
// `encrypt_with_fixed_session` drives the crate's own v3 write path with a fixed
// public IV, session IV and session key, so its output is reproducible and can
// be pinned. The legacy builder and `reference_v3_payload` do not touch the
// crate's stream code: they are hand-rolled CBC and HMAC over the same RustCrypto
// primitives, ported from `fuzz/src/lib.rs`, whose
// `smoke_legacy_builder_roundtrips` differential-tests the legacy builder
// against the real decryptor.

/// The `CREATED_BY` extension the official deterministic v3 vectors carry.
#[allow(dead_code)] // Used across multiple test files
pub const V3_CREATED_BY_EXTENSION: [u8; 29] = [
    0x00, 0x1B, b'C', b'R', b'E', b'A', b'T', b'E', b'D', b'_', b'B', b'Y', 0x00, b'a', b'e', b's',
    b'c', b'r', b'y', b'p', b't', b' ', b'4', b'.', b'0', b'.', b'0', b'.', b'0',
];

/// Writes a complete v3 file through the crate's own write path with a fixed
/// session, matching the official deterministic vectors (`CREATED_BY`
/// extension, version byte in the session HMAC).
///
/// # Errors
///
/// Whatever the crate's write helpers or `encrypt_stream` return: an I/O error
/// on `source` or `destination`, or an iteration count out of range.
///
/// # Panics
///
/// Never: the setup key is always a valid 32-byte HMAC key.
#[allow(dead_code)] // Used across multiple test files
pub fn encrypt_with_fixed_session<R: std::io::Read, W: std::io::Write>(
    mut source: R,
    mut destination: W,
    password: &str,
    iterations: u32,
    public_iv: &aescrypt_rs::aliases::Iv16,
    session_iv: &aescrypt_rs::aliases::Iv16,
    session_key: &aescrypt_rs::aliases::Aes256Key32,
) -> Result<(), aescrypt_rs::AescryptError> {
    use aes::cipher::KeyInit;
    use aescrypt_rs::aliases::{Aes256Key32, EncryptedSessionBlock48, HmacSha256};
    use aescrypt_rs::encryption::{
        derive_setup_key, encrypt_session_block, encrypt_stream, write_header, write_hmac,
        write_iterations, write_public_iv,
    };
    use hmac::Mac;
    use secure_gate::RevealSecret;

    write_header(&mut destination, 3)?;
    destination.write_all(&V3_CREATED_BY_EXTENSION)?;
    destination.write_all(&[0x00, 0x00])?;
    write_iterations(&mut destination, iterations, 3)?;
    write_public_iv(&mut destination, public_iv)?;

    let mut setup_key = Aes256Key32::new([0u8; 32]);
    derive_setup_key(password, public_iv, iterations, &mut setup_key)?;
    let cipher = setup_key.with_secret(|sk| aes::Aes256Enc::new(sk.into()));
    let mut session_hmac =
        setup_key.with_secret(|sk| <HmacSha256 as Mac>::new_from_slice(sk).unwrap());

    let mut enc_session_block = EncryptedSessionBlock48::new([0u8; 48]);
    encrypt_session_block(
        &cipher,
        session_iv,
        session_key,
        public_iv,
        &mut enc_session_block,
        &mut session_hmac,
    )?;
    // The official spec folds the version byte (3) into the session HMAC.
    session_hmac.update(&[3]);
    enc_session_block.with_secret(|eb| destination.write_all(eb))?;
    write_hmac(&mut destination, session_hmac)?;

    encrypt_stream(&mut source, &mut destination, session_iv, session_key)?;
    Ok(())
}

/// AES-256-CBC over `padded` (a multiple of 16 bytes), one block at a time.
///
/// # Panics
///
/// If `padded` is not a whole number of blocks.
#[allow(dead_code)] // Used across multiple test files
pub fn reference_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], padded: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockEncrypt, KeyInit};
    assert_eq!(padded.len() % 16, 0);
    let cipher = aes::Aes256Enc::new(key.into());
    let mut prev = *iv;
    let mut out = Vec::with_capacity(padded.len());
    for chunk in padded.chunks_exact(16) {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = chunk[i] ^ prev[i];
        }
        let mut b = aes::Block::from(block);
        cipher.encrypt_block(&mut b);
        prev.copy_from_slice(b.as_ref());
        out.extend_from_slice(b.as_ref());
    }
    out
}

/// HMAC-SHA256 of `data` under `key`.
///
/// # Panics
///
/// Never: any 32-byte key is a valid HMAC key.
#[allow(dead_code)] // Used across multiple test files
pub fn reference_hmac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    use hmac::Mac;
    let mut mac = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// What `encrypt_stream` must write for `plaintext`: CBC over PKCS#7-padded
/// plaintext (always 1..=16 pad bytes), then the HMAC of that ciphertext.
#[allow(dead_code)] // Used across multiple test files
pub fn reference_v3_payload(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let pad = 16 - plaintext.len() % 16;
    let mut padded = plaintext.to_vec();
    padded.resize(plaintext.len() + pad, pad as u8);
    let mut out = reference_cbc_encrypt(key, iv, &padded);
    let tag = reference_hmac(key, &out);
    out.extend_from_slice(&tag);
    out
}

/// Builds a well-formed legacy (v0/v1/v2) file byte for byte, without the
/// crate's stream code. Plaintext is zero-padded to a block, and the modulo
/// byte is `len % 16`. v0 has no session block and puts the modulo in header
/// byte 5; v1/v2 put it before the payload HMAC; v2 adds an empty extension
/// section. Ported from `build_legacy_file` in `fuzz/src/lib.rs`.
///
/// # Panics
///
/// If `password` is rejected by the key derivation, which a `&str` never is.
#[allow(dead_code)] // Used across multiple test files
pub fn build_legacy_file(
    version: u8,
    password: &str,
    plaintext: &[u8],
    public_iv: &[u8; 16],
    session_iv: &[u8; 16],
    session_key: &[u8; 32],
) -> Vec<u8> {
    use aescrypt_rs::aliases::{AckdfDerivedKey32, Salt16};
    use secure_gate::RevealSecret;

    let mut derived = AckdfDerivedKey32::new([0u8; 32]);
    aescrypt_rs::derive_ackdf_key(password, &Salt16::from(*public_iv), &mut derived)
        .expect("valid UTF-8 password");
    let setup_key = derived.with_secret(|k| *k);

    let modulo = (plaintext.len() % 16) as u8;
    let mut padded = plaintext.to_vec();
    padded.resize(plaintext.len().div_ceil(16) * 16, 0);

    let mut file = b"AES".to_vec();
    file.push(version);
    if version == 0 {
        file.push(modulo);
        file.extend_from_slice(public_iv);
        let ct = reference_cbc_encrypt(&setup_key, public_iv, &padded);
        let tag = reference_hmac(&setup_key, &ct);
        file.extend_from_slice(&ct);
        file.extend_from_slice(&tag);
        return file;
    }

    file.push(0x00);
    if version == 2 {
        file.extend_from_slice(&[0x00, 0x00]);
    }
    file.extend_from_slice(public_iv);
    let mut session_plain = [0u8; 48];
    session_plain[..16].copy_from_slice(session_iv);
    session_plain[16..].copy_from_slice(session_key);
    let enc_block = reference_cbc_encrypt(&setup_key, public_iv, &session_plain);
    let session_tag = reference_hmac(&setup_key, &enc_block);
    file.extend_from_slice(&enc_block);
    file.extend_from_slice(&session_tag);

    let ct = reference_cbc_encrypt(session_key, session_iv, &padded);
    let payload_tag = reference_hmac(session_key, &ct);
    file.extend_from_slice(&ct);
    file.push(modulo);
    file.extend_from_slice(&payload_tag);
    file
}

/// A deterministic plaintext of `len` bytes with no short period.
#[allow(dead_code)] // Used across multiple test files
pub fn pattern(len: usize) -> Vec<u8> {
    (0..len as u64)
        .map(|i| (i.wrapping_mul(31) ^ (i >> 9)) as u8)
        .collect()
}

// Fixed session for reproducible files. Never use fixed values outside tests.

/// Public IV of the fixed-session files; also the KDF salt.
#[allow(dead_code)] // Used across multiple test files
pub const PUBLIC_IV: [u8; 16] = [0x11; 16];
/// Session IV of the fixed-session files (v1–v3).
#[allow(dead_code)] // Used across multiple test files
pub const SESSION_IV: [u8; 16] = [
    0x7b, 0x68, 0x69, 0xff, 0xd7, 0xd1, 0x06, 0xbf, 0xee, 0x4e, 0xab, 0x45, 0x06, 0x98, 0xc3, 0xb1,
];
/// Session key of the fixed-session files (v1–v3).
#[allow(dead_code)] // Used across multiple test files
pub const SESSION_KEY: [u8; 32] = [
    0xa1, 0xfb, 0xa1, 0xaf, 0x16, 0x9f, 0x1a, 0x48, 0x9a, 0xec, 0x5d, 0x2e, 0x01, 0x93, 0x44, 0x7c,
    0x3b, 0x9d, 0x20, 0x55, 0xe6, 0x0f, 0x71, 0xc8, 0x28, 0xb4, 0x6a, 0x13, 0xd7, 0x8e, 0x42, 0x09,
];

/// A file of `version` holding `plaintext`, built with the fixed session above:
/// v0–v2 by the independent legacy builder, v3 by the crate's own write path.
///
/// # Panics
///
/// If writing the v3 file to a `Vec` fails, which it cannot.
#[allow(dead_code)] // Used across multiple test files
pub fn build_fixed_file(version: u8, plaintext: &[u8]) -> Vec<u8> {
    use aescrypt_rs::aliases::{Aes256Key32, Iv16};
    if version < 3 {
        return build_legacy_file(
            version,
            TEST_PASSWORD,
            plaintext,
            &PUBLIC_IV,
            &SESSION_IV,
            &SESSION_KEY,
        );
    }
    let mut out = Vec::new();
    encrypt_with_fixed_session(
        std::io::Cursor::new(plaintext),
        &mut out,
        TEST_PASSWORD,
        TEST_ITERATIONS,
        &Iv16::new(PUBLIC_IV),
        &Iv16::new(SESSION_IV),
        &Aes256Key32::new(SESSION_KEY),
    )
    .unwrap();
    out
}
