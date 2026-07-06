//! Fuzz harness library for `aescrypt-rs`.
//!
//! All fuzz logic lives here as plain `pub fn fuzz_*` entry points so that the
//! harness (and its smoke tests) compiles on the crate's pinned stable/MSRV
//! toolchain. The `fuzz_targets/*.rs` binaries are 3-line libFuzzer wrappers
//! gated behind the `fuzzing` feature (nightly-only). Run the smoke tests on
//! any toolchain with:
//!
//! ```text
//! cargo test --no-default-features --manifest-path fuzz/Cargo.toml
//! ```
//!
//! The legacy file builder ([`build_legacy_file`]) is the byte-for-byte inverse
//! of the crate's v0–v2 read path; [`fuzz_roundtrip_legacy`] and the
//! `smoke_legacy_builder_roundtrips` test continuously differential-test it
//! against the real decryptor.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes256Enc, Block};
use aescrypt_rs::aliases::{AckdfDerivedKey32, Aes256Key32, Iv16, PasswordString, Salt16};
use aescrypt_rs::decryption::{
    consume_all_extensions, decrypt_ciphertext_stream, read_file_version, read_kdf_iterations,
    StreamConfig,
};
use aescrypt_rs::{decrypt, derive_ackdf_key, encrypt, read_version};
use arbitrary::Arbitrary;
use hmac::{Hmac, Mac};
use secure_gate::RevealSecret;
use sha2::Sha256;
use std::io::Cursor;

type HmacSha256 = Hmac<Sha256>;

// ─────────────────────────────────────────────────────────────────────────────
// Low-level crypto helpers (mirror the crate's primitives with the same crates)
// ─────────────────────────────────────────────────────────────────────────────

/// ACKDF setup key for the legacy builder (v0–v2: 8192 × SHA-256, UTF-16-LE password).
fn ackdf_key(password: &str, iv: &[u8; 16]) -> [u8; 32] {
    let pw = PasswordString::new(password.to_string());
    let salt = Salt16::from(*iv);
    let mut out = AckdfDerivedKey32::new([0u8; 32]);
    derive_ackdf_key(&pw, &salt, &mut out).expect("valid UTF-8 password");
    out.with_secret(|k| *k)
}

/// Manual AES-256-CBC encrypt (input must be a multiple of 16 bytes).
fn cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], padded: &[u8]) -> Vec<u8> {
    assert_eq!(padded.len() % 16, 0);
    let cipher = Aes256Enc::new(key.into());
    let mut prev = *iv;
    let mut out = Vec::with_capacity(padded.len());
    for chunk in padded.chunks_exact(16) {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = chunk[i] ^ prev[i];
        }
        let mut b = Block::from(block);
        cipher.encrypt_block(&mut b);
        prev.copy_from_slice(b.as_ref());
        out.extend_from_slice(b.as_ref());
    }
    out
}

fn hmac_tag(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().into()
}

// ─────────────────────────────────────────────────────────────────────────────
// File builders
// ─────────────────────────────────────────────────────────────────────────────

/// Build a valid v3 file with the real encryptor. `iterations` must be 1..=5_000_000.
pub fn build_v3_file(password: &PasswordString, plaintext: &[u8], iterations: u32) -> Vec<u8> {
    let mut out = Vec::new();
    encrypt(Cursor::new(plaintext), &mut out, password, iterations).expect("encrypt");
    out
}

/// Build a well-formed legacy (v0/v1/v2) file byte-for-byte per the AES Crypt wire format.
///
/// This is the inverse of the crate's `src/decryption/` read path. Wire formats:
///
/// - Plaintext is zero-padded to a multiple of 16; `modulo = plaintext.len() % 16`
///   (0 means "final block is full"). Empty plaintext ⇒ zero ciphertext blocks.
/// - **v0**: `"AES" 0x00 <modulo>` ‖ `IV(16)` ‖ `CBC(ACKDF, IV, padded)` ‖
///   `HMAC(ACKDF, ciphertext)(32)`. No session block, no session HMAC.
/// - **v1**: `"AES" 0x01 0x00` ‖ `IV(16)` ‖
///   `enc_block = CBC(ACKDF, IV, session_iv‖session_key)(48)` ‖
///   `HMAC(ACKDF, enc_block)(32)` — **no version byte in the session HMAC** ‖
///   `CBC(session_key, session_iv, padded)` ‖ `<modulo>` ‖
///   `HMAC(session_key, payload-ciphertext)(32)`.
/// - **v2**: same as v1, plus an extension section right after the 5-byte header:
///   each extension is `u16 BE length` + payload; terminated by `0x00 0x00`.
///   Empty extensions must be pre-filtered by the caller (a zero length would
///   terminate the section early).
#[allow(clippy::too_many_arguments)]
pub fn build_legacy_file(
    version: u8, // 0..=2
    password: &str,
    plaintext: &[u8],
    public_iv: &[u8; 16],
    session_iv: &[u8; 16],  // v1/v2 only
    session_key: &[u8; 32], // v1/v2 only
    extensions: &[Vec<u8>], // v2 only; empties must be pre-filtered by caller
) -> Vec<u8> {
    let setup_key = ackdf_key(password, public_iv);
    let modulo = (plaintext.len() % 16) as u8;
    let mut padded = plaintext.to_vec();
    let rem = padded.len() % 16;
    if rem != 0 {
        padded.resize(padded.len() + (16 - rem), 0);
    }

    let mut file = Vec::new();
    file.extend_from_slice(b"AES");
    file.push(version);

    if version == 0 {
        file.push(modulo);
        file.extend_from_slice(public_iv);
        let ct = cbc_encrypt(&setup_key, public_iv, &padded);
        let tag = hmac_tag(&setup_key, &ct);
        file.extend_from_slice(&ct);
        file.extend_from_slice(&tag);
        return file;
    }

    file.push(0x00); // reserved byte, must be 0 for v1/v2
    if version == 2 {
        for ext in extensions {
            file.extend_from_slice(&(ext.len() as u16).to_be_bytes());
            file.extend_from_slice(ext);
        }
        file.extend_from_slice(&[0x00, 0x00]);
    }
    file.extend_from_slice(public_iv);

    let mut session_plain = [0u8; 48];
    session_plain[..16].copy_from_slice(session_iv);
    session_plain[16..].copy_from_slice(session_key);
    let enc_block = cbc_encrypt(&setup_key, public_iv, &session_plain);
    let session_tag = hmac_tag(&setup_key, &enc_block);
    file.extend_from_slice(&enc_block);
    file.extend_from_slice(&session_tag);

    let ct = cbc_encrypt(session_key, session_iv, &padded);
    let payload_tag = hmac_tag(session_key, &ct);
    file.extend_from_slice(&ct);
    file.push(modulo);
    file.extend_from_slice(&payload_tag);
    file
}

// ─────────────────────────────────────────────────────────────────────────────
// Fuzz entry points
// ─────────────────────────────────────────────────────────────────────────────

/// Largest PBKDF2 iteration count the `decrypt_raw` harness lets through. Real
/// v3 files may request up to 5_000_000 (the crate's DoS ceiling), but grinding
/// that many iterations under the sanitizer takes tens of seconds and trips
/// libFuzzer's per-exec timeout on an input that is *intentionally* expensive,
/// not buggy. Capping keeps execs fast; the KDF loop runs identical code at any
/// count, so no parser/stream/crypto coverage is lost.
const FUZZ_MAX_ITERS: u32 = 4096;

/// If `data` is a v3 file, return the byte offset of its 4-byte big-endian
/// iteration field. The field follows the 5-byte header and the
/// variable-length extension section (`u16` length + payload, terminated by a
/// zero-length entry), mirroring the crate's read order. Returns `None` for
/// non-v3 or malformed input — those fail before any KDF work anyway, so they
/// are already fast.
fn v3_iter_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 5 || &data[..3] != b"AES" || data[3] != 3 || data[4] != 0 {
        return None;
    }
    let mut pos = 5usize;
    loop {
        let end = pos.checked_add(2)?;
        if end > data.len() {
            return None;
        }
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos = end;
        if len == 0 {
            break; // end of extensions; the iteration field starts here
        }
        pos = pos.checked_add(len)?;
        if pos > data.len() {
            return None;
        }
    }
    if pos.checked_add(4)? <= data.len() {
        Some(pos)
    } else {
        None
    }
}

/// Target 1: raw adversarial bytes → `decrypt()`. Oracle: no panic, no OOM.
pub fn fuzz_decrypt_raw(data: &[u8]) {
    let password = PasswordString::new("fuzz-password".to_string());

    // Clamp a v3 file's iteration count so the fuzzer spends its budget finding
    // defects rather than grinding the intentional PBKDF2 DoS ceiling. Only the
    // iteration bytes change, and only when they exceed the cap; everything else
    // stays adversarial, and small/zero counts (their own code paths) pass
    // through untouched.
    let mut owned;
    let input: &[u8] = match v3_iter_offset(data) {
        Some(off)
            if u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
                > FUZZ_MAX_ITERS =>
        {
            owned = data.to_vec();
            owned[off..off + 4].copy_from_slice(&FUZZ_MAX_ITERS.to_be_bytes());
            &owned
        }
        _ => data,
    };

    let mut out = Vec::new();
    let _ = decrypt(Cursor::new(input), &mut out, &password);
}

/// Target 5: pure header parsers on raw bytes. Oracle: no panic.
pub fn fuzz_parsers(data: &[u8]) {
    let _ = read_version(Cursor::new(data));
    let mut cursor = Cursor::new(data);
    if let Ok((version, _)) = read_file_version(&mut cursor) {
        if consume_all_extensions(&mut cursor, version).is_ok() {
            let _ = read_kdf_iterations(&mut cursor, version);
        }
    }
}

/// Target 4: ring-buffer / trailer / PKCS#7 hammering with a fixed key.
///
/// `data[0] & 3` selects `StreamConfig`, `data[1]` is v0's `reserved_modulo`,
/// the rest is the ciphertext stream.
pub fn fuzz_stream_decrypt(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let config = match data[0] & 0x03 {
        0 => StreamConfig::V0 {
            reserved_modulo: data[1],
        },
        1 => StreamConfig::V1,
        2 => StreamConfig::V2,
        _ => StreamConfig::V3,
    };
    let key = Aes256Key32::new([0x42u8; 32]);
    let iv = Iv16::new([0x24u8; 16]);
    let mut out = Vec::new();
    let _ = decrypt_ciphertext_stream(Cursor::new(&data[2..]), &mut out, &iv, &key, config);
}

/// Target 2 input: valid v3 file + optional byte mutations / truncation.
#[derive(Arbitrary, Debug)]
pub struct V3Case {
    pub password: String,
    pub plaintext: Vec<u8>,
    pub iterations_sel: u8,        // mapped to 1..=256 (keeps PBKDF2 fast)
    pub mutations: Vec<(u16, u8)>, // (offset % len, XOR byte); zero XOR = no-op
    pub truncate_tail: Option<u16>,
}

/// Target 2: v3 round-trip with an authentication oracle. Any accepted mutated
/// file whose plaintext diverges from the original is an auth bypass → crash.
pub fn fuzz_roundtrip_v3(case: &V3Case) {
    let password_str = if case.password.is_empty() {
        "p"
    } else {
        case.password.as_str()
    };
    let password = PasswordString::new(password_str.to_string());
    let plaintext = &case.plaintext[..case.plaintext.len().min(2048)];
    let iterations = 1 + u32::from(case.iterations_sel);
    // `tampered` takes ownership of the built file; nothing else reads `file`.
    let mut tampered = build_v3_file(&password, plaintext, iterations);
    let mut changed = false;
    for &(off, x) in case.mutations.iter().take(8) {
        if x != 0 {
            let idx = usize::from(off) % tampered.len();
            tampered[idx] ^= x;
            changed = true;
        }
    }
    if let Some(t) = case.truncate_tail {
        let cut = usize::from(t) % (tampered.len() + 1);
        if cut > 0 {
            tampered.truncate(tampered.len() - cut);
            changed = true;
        }
    }

    let mut out = Vec::new();
    let result = decrypt(Cursor::new(&tampered), &mut out, &password);

    if !changed {
        result.expect("decrypt of untampered v3 file failed");
        assert_eq!(out, plaintext, "v3 round-trip mismatch");
    } else if result.is_ok() {
        // v3 is fully authenticated: accepting tampered bytes that yield
        // different plaintext would be an authentication bypass → crash.
        assert_eq!(
            out, plaintext,
            "v3 accepted tampered file with divergent plaintext"
        );
    }
}

/// Target 3 input: hand-built valid legacy file + optional mutations.
#[derive(Arbitrary, Debug)]
pub struct LegacyCase {
    pub version_sel: u8, // mapped % 3 to 0..=2
    pub password: String,
    pub plaintext: Vec<u8>,
    pub public_iv: [u8; 16],
    pub session_iv: [u8; 16],
    pub session_key: [u8; 32],
    pub extensions: Vec<Vec<u8>>, // v2 only; capped 3 × 64 bytes
    pub mutations: Vec<(u16, u8)>,
}

/// Target 3: legacy round-trip (continuous differential test of the builder)
/// plus a tamper oracle that tolerates the format's unauthenticated modulo byte.
pub fn fuzz_roundtrip_legacy(case: &LegacyCase) {
    let version = case.version_sel % 3;
    let password_str = if case.password.is_empty() {
        "p"
    } else {
        case.password.as_str()
    };
    let plaintext = &case.plaintext[..case.plaintext.len().min(2048)];
    let exts: Vec<Vec<u8>> = case
        .extensions
        .iter()
        .filter(|e| !e.is_empty())
        .take(3)
        .map(|e| e[..e.len().min(64)].to_vec())
        .collect();

    // KDF-DoS guard: force the IV's first bit high. If a mutation flips the
    // version byte to 3, the reader parses IV bytes 0..4 as the PBKDF2
    // iteration count; >= 0x8000_0000 exceeds the 5M cap and is rejected
    // instantly instead of burning seconds of PBKDF2 per exec.
    let mut public_iv = case.public_iv;
    public_iv[0] |= 0x80;

    let file = build_legacy_file(
        version,
        password_str,
        plaintext,
        &public_iv,
        &case.session_iv,
        &case.session_key,
        &exts,
    );
    let password = PasswordString::new(password_str.to_string());

    // Untampered: must round-trip exactly. This doubles as a continuous
    // differential test of the builder against the real read path.
    let mut out = Vec::new();
    decrypt(Cursor::new(&file), &mut out, &password)
        .unwrap_or_else(|e| panic!("well-formed v{version} file rejected: {e}"));
    assert_eq!(out, plaintext, "legacy v{version} round-trip mismatch");

    // Tampered: never panic. If accepted, the modulo byte is legitimately
    // malleable (unauthenticated in v0–v2), so only the final-block LENGTH
    // may differ (by <= 15 bytes); the decrypted byte prefix must match.
    let mut tampered = file.clone();
    let mut changed = false;
    for &(off, x) in case.mutations.iter().take(8) {
        if x != 0 {
            let idx = usize::from(off) % tampered.len();
            tampered[idx] ^= x;
            changed = true;
        }
    }
    if changed {
        let mut out2 = Vec::new();
        if decrypt(Cursor::new(&tampered), &mut out2, &password).is_ok() {
            let n = out2.len().min(plaintext.len());
            assert_eq!(
                &out2[..n],
                &plaintext[..n],
                "legacy tamper diverged within prefix"
            );
            assert!(
                out2.len().abs_diff(plaintext.len()) <= 15,
                "legacy tamper changed length by more than one block"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Smoke tests — validate the harness on the stable/MSRV toolchain (no nightly).
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    /// The most important test: prove `build_legacy_file` matches the real wire
    /// format for every version and every final-block shape. Any format bug in
    /// the builder surfaces here as "well-formed file rejected" or a mismatch.
    #[test]
    fn smoke_legacy_builder_roundtrips() {
        for version in 0u8..=2 {
            for &len in &[0usize, 1, 15, 16, 17, 100] {
                let plaintext: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
                let exts = if version == 2 {
                    vec![vec![1u8, 2, 3]]
                } else {
                    vec![]
                };
                let case = LegacyCase {
                    version_sel: version,
                    password: "correct horse".to_string(),
                    plaintext: plaintext.clone(),
                    public_iv: [0x11; 16],
                    session_iv: [0x22; 16],
                    session_key: [0x33; 32],
                    extensions: exts,
                    mutations: vec![],
                };
                fuzz_roundtrip_legacy(&case);
            }
        }
    }

    #[test]
    fn smoke_v3_roundtrip_and_tamper() {
        // No mutations → must round-trip.
        let clean = V3Case {
            password: "hunter2".to_string(),
            plaintext: b"the quick brown fox".to_vec(),
            iterations_sel: 0, // → 1 iteration
            mutations: vec![],
            truncate_tail: None,
        };
        fuzz_roundtrip_v3(&clean);

        // One mutation somewhere in the payload → must not panic (typically
        // HMAC-rejects; if accepted, the oracle checks plaintext equality).
        let tampered = V3Case {
            password: "hunter2".to_string(),
            plaintext: b"the quick brown fox".to_vec(),
            iterations_sel: 0,
            mutations: vec![(90, 0xFF)],
            truncate_tail: None,
        };
        fuzz_roundtrip_v3(&tampered);
    }

    #[test]
    fn smoke_raw_and_parsers() {
        let password = PasswordString::new("fuzz-password".to_string());
        let v3 = build_v3_file(&password, b"seed", 1);
        let v0 = build_legacy_file(
            0,
            "fuzz-password",
            b"hi there",
            &[9; 16],
            &[0; 16],
            &[0; 32],
            &[],
        );

        let inputs: Vec<Vec<u8>> = vec![
            vec![],
            b"AES".to_vec(),
            b"AES\x03\x00".to_vec(),
            b"AES\x03\x00\x00\x00\x00\x00\x00\x01".to_vec(),
            v3,
            v0,
        ];
        for inp in &inputs {
            fuzz_decrypt_raw(inp);
            fuzz_parsers(inp);
        }
    }

    #[test]
    fn smoke_v3_iter_offset_and_clamp() {
        // Empty-extension v3 header: the iteration field sits right after the
        // 0x00 0x00 terminator, at offset 7.
        let hdr = b"AES\x03\x00\x00\x00\x00\x00\x00\x01".to_vec();
        let off = v3_iter_offset(&hdr).expect("v3 offset");
        assert_eq!(off, 7);
        assert_eq!(&hdr[off..off + 4], &[0, 0, 0, 1]);

        // A real v3 file (whatever extension section the encryptor writes) must
        // still have a locatable iteration field equal to the requested count.
        let pw = PasswordString::new("fuzz-password".to_string());
        let file = build_v3_file(&pw, b"x", 1234);
        let off = v3_iter_offset(&file).expect("real v3 offset");
        let got = u32::from_be_bytes([file[off], file[off + 1], file[off + 2], file[off + 3]]);
        assert_eq!(got, 1234, "located the wrong iteration field");

        // Non-v3 / malformed → None (fast path, nothing to clamp).
        assert_eq!(v3_iter_offset(b"AES\x02\x00"), None);
        assert_eq!(v3_iter_offset(b"not aes at all"), None);
        assert_eq!(v3_iter_offset(b"AES\x03\x00\x00"), None); // truncated ext length

        // The clamp must let a 5M-iteration header return quickly without a
        // panic (a bounded run instead of tens of seconds of PBKDF2).
        let mut huge = b"AES\x03\x00\x00\x00".to_vec(); // header + empty-ext terminator
        huge.extend_from_slice(&5_000_000u32.to_be_bytes()); // iterations = 5_000_000
        huge.extend_from_slice(&[0u8; 16]); // public IV so decrypt reaches the KDF
        fuzz_decrypt_raw(&huge);
    }

    #[test]
    fn smoke_stream_decrypt() {
        // Empty / short inputs must be handled.
        fuzz_stream_decrypt(&[]);
        fuzz_stream_decrypt(&[0x03]);
        fuzz_stream_decrypt(&[0x03, 0x00]);

        // A real v3 stream produced by the crate's own encryptor, prefixed with
        // the [config_selector, reserved_modulo] header the target consumes.
        let key = Aes256Key32::new([0x42u8; 32]);
        let iv = Iv16::new([0x24u8; 16]);
        let mut stream = Vec::new();
        aescrypt_rs::encryption::encrypt_stream(Cursor::new(b"stream me"), &mut stream, &iv, &key)
            .expect("encrypt_stream");
        let mut input = vec![0x03, 0x00];
        input.extend_from_slice(&stream);
        fuzz_stream_decrypt(&input);
    }

    /// Regenerates the committed seed corpora. Run explicitly:
    /// `cargo test --no-default-features --manifest-path fuzz/Cargo.toml \
    ///     generate_seed_corpus -- --ignored`
    #[test]
    #[ignore]
    fn generate_seed_corpus() {
        use std::path::PathBuf;

        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus");
        let write = |target: &str, name: &str, bytes: &[u8]| {
            let dir = root.join(target);
            std::fs::create_dir_all(&dir).expect("create corpus dir");
            std::fs::write(dir.join(name), bytes).expect("write seed");
        };

        let password = PasswordString::new("fuzz-password".to_string());

        // decrypt_raw: real files at iterations=1 so execs stay fast. Password
        // MUST match the target's fixed "fuzz-password" so coverage reaches the
        // success path.
        let v3 = build_v3_file(&password, b"seed plaintext for fuzzing", 1);
        let v3_empty = build_v3_file(&password, b"", 1);
        let v0 = build_legacy_file(
            0,
            "fuzz-password",
            b"seed plaintext",
            &[1; 16],
            &[0; 16],
            &[0; 32],
            &[],
        );
        let v1 = build_legacy_file(
            1,
            "fuzz-password",
            b"seed plaintext",
            &[2; 16],
            &[3; 16],
            &[4; 32],
            &[],
        );
        let v2 = build_legacy_file(
            2,
            "fuzz-password",
            b"seed plaintext",
            &[5; 16],
            &[6; 16],
            &[7; 32],
            &[vec![
                b'C', b'R', b'E', b'A', b'T', b'E', b'D', b'_', b'B', b'Y',
            ]],
        );
        write("decrypt_raw", "v3_iter1.aes", &v3);
        write("decrypt_raw", "v3_empty_iter1.aes", &v3_empty);
        write("decrypt_raw", "v0.aes", &v0);
        write("decrypt_raw", "v1.aes", &v1);
        write("decrypt_raw", "v2.aes", &v2);
        write("decrypt_raw", "header_v3", b"AES\x03\x00");
        write("decrypt_raw", "header_v0", b"AES");

        // parsers: header stubs + a v2 extension section.
        write("parsers", "header_v3", b"AES\x03\x00");
        write("parsers", "header_v0", b"AES");
        write("parsers", "v2_ext", b"AES\x02\x00\x00\x05hello\x00\x00");

        // stream_decrypt: [config, modulo] prefix + a real stream.
        let key = Aes256Key32::new([0x42u8; 32]);
        let iv = Iv16::new([0x24u8; 16]);
        let mut v3_stream = vec![0x03, 0x00];
        {
            let mut s = Vec::new();
            aescrypt_rs::encryption::encrypt_stream(Cursor::new(b"stream seed"), &mut s, &iv, &key)
                .expect("encrypt_stream");
            v3_stream.extend_from_slice(&s);
        }
        write("stream_decrypt", "v3_stream", &v3_stream);

        // v1-shaped stream: ct ‖ modulo ‖ HMAC(key, ct), same fixed key/iv.
        let raw = b"stream seed";
        let mut padded = raw.to_vec();
        let modulo = (raw.len() % 16) as u8;
        let rem = padded.len() % 16;
        if rem != 0 {
            padded.resize(padded.len() + (16 - rem), 0);
        }
        let fixed_key = [0x42u8; 32];
        let fixed_iv = [0x24u8; 16];
        let ct = cbc_encrypt(&fixed_key, &fixed_iv, &padded);
        let tag = hmac_tag(&fixed_key, &ct);
        let mut v1_stream = vec![0x01, 0x00];
        v1_stream.extend_from_slice(&ct);
        v1_stream.push(modulo);
        v1_stream.extend_from_slice(&tag);
        write("stream_decrypt", "v1_stream", &v1_stream);
    }
}
