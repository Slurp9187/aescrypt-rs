# Fuzz Suite Implementation Plan

**Date**: 2026-07-06 (plan authored; environment facts verified this date)
**Status**: `fuzz/Cargo.toml` is already created (step 1 done). Everything else is to-do.
**Branch**: work on `claude/fuzz-test`.
**Goal**: a cargo-fuzz (libFuzzer) suite with 5 targets, seed corpora, stable-toolchain smoke
tests, a CI workflow, and a CHANGELOG entry. Every design decision below was worked out against
the actual source — follow it precisely; the "why" notes exist so you don't "fix" intentional
choices.

---

## Architecture

All fuzz logic lives in a **library** (`fuzz/src/lib.rs`) with plain `pub fn fuzz_*` entry
points. The `fuzz_targets/*.rs` binaries are 3-line libFuzzer wrappers. Reasons:

- The lib (and its `#[cfg(test)]` smoke tests) compiles on the **stable/MSRV 1.70 toolchain**
  (the repo's `rust-toolchain.toml` pins 1.70), so the harness itself is testable everywhere,
  including Windows. Only the bins need nightly.
- `libfuzzer-sys` is an **optional dependency** behind a `fuzzing` feature (default-on). Each
  `[[bin]]` has `required-features = ["fuzzing"]`. Therefore:
  - `cargo test --no-default-features --manifest-path fuzz/Cargo.toml` → builds/tests only the
    lib on 1.70 (bins skipped).
  - `cargo +nightly fuzz run <target>` → works out of the box (default features on).

The fuzz package is standalone (root `Cargo.toml` declares no workspace, so no exclusion is
needed). It gets its own `fuzz/Cargo.lock` — commit it.

## Environment facts (verified on this machine)

- `cargo-fuzz 0.13.1` is installed; `nightly-x86_64-pc-windows-msvc` toolchain is installed.
- Root `rust-toolchain.toml` pins 1.70. **Gotcha**: `cargo fuzz` invoked bare will resolve 1.70
  and fail. Always use `cargo +nightly fuzz ...` — the `+nightly` sets `RUSTUP_TOOLCHAIN` for
  child processes, which overrides the toolchain file for cargo-fuzz's nested cargo calls.
- libFuzzer on Windows/MSVC may fail to link. If `cargo +nightly fuzz build` fails locally,
  that is acceptable: the suite's runtime home is Linux CI. Do NOT gut the design to force
  local Windows runs; the stable smoke tests are the local validation.

---

## Step 1 — `fuzz/Cargo.toml` (DONE, verify it matches)

Already written. Canonical content (verify, don't blindly rewrite):

- package `aescrypt-rs-fuzz`, version 0.0.0, publish=false, edition 2021,
  `[package.metadata] cargo-fuzz = true`
- `[features] default = ["fuzzing"]`, `fuzzing = ["dep:libfuzzer-sys"]`
- deps: `aescrypt-rs = { path = ".." }`, `arbitrary = { version = "1", features = ["derive"] }`,
  `libfuzzer-sys = { version = "0.4", optional = true }`,
  `secure-gate = { version = "=0.8.0-rc.10", features = ["rand", "ct-eq"] }`,
  `aes = "0.8"`, `hmac = "0.12"`, `sha2 = "0.10"`
- five `[[bin]]` entries — names `decrypt_raw`, `roundtrip_v3`, `roundtrip_legacy`,
  `stream_decrypt`, `parsers`; paths `fuzz_targets/<name>.rs`; each with
  `test = false, doc = false, bench = false, required-features = ["fuzzing"]`

**If `cargo check` later fails because latest `arbitrary`/`derive_arbitrary` needs rustc >
1.70**: pin with `=` to the newest version that compiles on 1.70 (try `=1.3.2` for both), and
add a comment in the style of the root Cargo.toml's MSRV pin tables.

## Step 2 — `fuzz/.gitignore`

```gitignore
target/
artifacts/
coverage/
Cargo.lock is committed; corpus/ is committed (seed corpora).
```
(Drop that last explanatory line — gitignore comments need `#`. Use: `target/`, `artifacts/`,
`coverage/` only.)

## Step 3 — `fuzz/src/lib.rs` (the core)

### 3a. Imports and helpers

```rust
use aescrypt_rs::aliases::{
    AckdfDerivedKey32, Aes256Key32, Iv16, PasswordString, Salt16,
};
use aescrypt_rs::decryption::{
    consume_all_extensions, decrypt_ciphertext_stream, read_file_version,
    read_kdf_iterations, StreamConfig,
};
use aescrypt_rs::{decrypt, derive_ackdf_key, encrypt, read_version};
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes256Enc, Block};
use arbitrary::Arbitrary;
use hmac::{Hmac, Mac};
use secure_gate::RevealSecret;
use sha2::Sha256;
use std::io::Cursor;

type HmacSha256 = Hmac<Sha256>;

/// ACKDF setup key for the legacy builder (v0-v2: 8192 x SHA-256, UTF-16-LE password).
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
```

### 3b. File builders

```rust
/// Build a valid v3 file with the real encryptor. iterations must be 1..=5_000_000.
pub fn build_v3_file(password: &PasswordString, plaintext: &[u8], iterations: u32) -> Vec<u8> {
    let mut out = Vec::new();
    encrypt(Cursor::new(plaintext), &mut out, password, iterations).expect("encrypt");
    out
}
```

Legacy builder — this is the inverse of the crate's read path. **Wire formats (verified against
`src/decryption/`)**:

- Plaintext is zero-padded up to a multiple of 16; `modulo = plaintext.len() % 16` (nibble
  semantics: 0 means "final block is full"; consistent because we pad to full blocks). Empty
  plaintext ⇒ zero ciphertext blocks; modulo value is then ignored by the reader.
- **v0**: `"AES" 0x00 <modulo:1>` ‖ `IV(16)` ‖ `CBC(key=ACKDF(pw,IV), iv=IV, padded)` ‖
  `HMAC-SHA256(key=ACKDF, ciphertext)(32)`. No session block, no session HMAC.
- **v1**: `"AES" 0x01 0x00` ‖ `IV(16)` ‖
  `enc_block = CBC(key=ACKDF(pw,IV), iv=IV, session_iv(16)‖session_key(32))` (48 bytes) ‖
  `HMAC(ACKDF-key, enc_block)(32)` — **NO version byte in the session HMAC for v1/v2**
  (only v3 appends it; see `extract_session_data`) ‖
  `CBC(session_key, session_iv, padded)` ‖ `<modulo:1>` ‖
  `HMAC(session_key, payload-ciphertext)(32)`.
- **v2**: same as v1, plus an extension section right after the 5-byte header: each extension
  is `u16 BE length` + payload bytes; terminated by `0x00 0x00`. Skip empty extensions
  (a zero length would terminate the section early).

```rust
/// Build a well-formed legacy (v0/v1/v2) file byte-for-byte per the AES Crypt wire format.
#[allow(clippy::too_many_arguments)]
pub fn build_legacy_file(
    version: u8,                 // 0..=2
    password: &str,
    plaintext: &[u8],
    public_iv: &[u8; 16],
    session_iv: &[u8; 16],       // v1/v2 only
    session_key: &[u8; 32],      // v1/v2 only
    extensions: &[Vec<u8>],      // v2 only; empties must be pre-filtered by caller
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
```

### 3c. Fuzz entry points

```rust
/// Target 1: raw adversarial bytes -> decrypt(). Oracle: no panic, no OOM.
pub fn fuzz_decrypt_raw(data: &[u8]) {
    let password = PasswordString::new("fuzz-password".to_string());
    let mut out = Vec::new();
    let _ = decrypt(Cursor::new(data), &mut out, &password);
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

/// Target 4: ring-buffer / trailer / PKCS#7 hammering with fixed key.
/// data[0] & 3 selects StreamConfig, data[1] is v0's reserved_modulo, rest is the stream.
pub fn fuzz_stream_decrypt(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let config = match data[0] & 0x03 {
        0 => StreamConfig::V0 { reserved_modulo: data[1] },
        1 => StreamConfig::V1,
        2 => StreamConfig::V2,
        _ => StreamConfig::V3,
    };
    let key = Aes256Key32::new([0x42u8; 32]);
    let iv = Iv16::new([0x24u8; 16]);
    let mut out = Vec::new();
    let _ = decrypt_ciphertext_stream(Cursor::new(&data[2..]), &mut out, &iv, &key, config);
}
```

Structured targets use `#[derive(Arbitrary, Debug)]` input structs:

```rust
/// Target 2 input: valid v3 file + optional byte mutations / truncation.
#[derive(Arbitrary, Debug)]
pub struct V3Case {
    pub password: String,
    pub plaintext: Vec<u8>,
    pub iterations_sel: u8,          // mapped to 1..=256 (keeps PBKDF2 fast)
    pub mutations: Vec<(u16, u8)>,   // (offset % len, XOR byte); zero XOR = no-op
    pub truncate_tail: Option<u16>,
}

pub fn fuzz_roundtrip_v3(case: &V3Case) {
    let password_str = if case.password.is_empty() { "p" } else { case.password.as_str() };
    let password = PasswordString::new(password_str.to_string());
    let plaintext = &case.plaintext[..case.plaintext.len().min(2048)];
    let iterations = 1 + u32::from(case.iterations_sel);
    let file = build_v3_file(&password, plaintext, iterations);

    let mut tampered = file.clone();
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
        // v3 is fully authenticated: accepting tampered bytes with different
        // plaintext would be an authentication bypass -> crash the fuzzer.
        assert_eq!(out, plaintext, "v3 accepted tampered file with divergent plaintext");
    }
}

/// Target 3 input: hand-built valid legacy file + optional mutations.
#[derive(Arbitrary, Debug)]
pub struct LegacyCase {
    pub version_sel: u8,             // mapped % 3 to 0..=2
    pub password: String,
    pub plaintext: Vec<u8>,
    pub public_iv: [u8; 16],
    pub session_iv: [u8; 16],
    pub session_key: [u8; 32],
    pub extensions: Vec<Vec<u8>>,    // v2 only; capped 3 x 64 bytes
    pub mutations: Vec<(u16, u8)>,
}

pub fn fuzz_roundtrip_legacy(case: &LegacyCase) {
    let version = case.version_sel % 3;
    let password_str = if case.password.is_empty() { "p" } else { case.password.as_str() };
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
        version, password_str, plaintext, &public_iv,
        &case.session_iv, &case.session_key, &exts,
    );
    let password = PasswordString::new(password_str.to_string());

    // Untampered: must round-trip exactly. This doubles as a continuous
    // differential test of the builder against the real read path.
    let mut out = Vec::new();
    decrypt(Cursor::new(&file), &mut out, &password)
        .unwrap_or_else(|e| panic!("well-formed v{version} file rejected: {e}"));
    assert_eq!(out, plaintext, "legacy v{version} round-trip mismatch");

    // Tampered: never panic. If accepted, the modulo byte is legitimately
    // malleable (unauthenticated in v0-v2), so only the final-block LENGTH
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
            assert_eq!(&out2[..n], &plaintext[..n], "legacy tamper diverged within prefix");
            assert!(
                out2.len().abs_diff(plaintext.len()) <= 15,
                "legacy tamper changed length by more than one block"
            );
        }
    }
}
```

Note: `usize::abs_diff` needs Rust 1.60+ — fine on 1.70.

### 3d. Smoke tests (`#[cfg(test)]`, run on stable 1.70)

Purpose: validate the harness itself — especially that `build_legacy_file` matches the real
wire format — without any nightly/libFuzzer machinery.

- `smoke_legacy_builder_roundtrips`: for `version in 0..=2`, plaintext lengths
  `[0, 1, 15, 16, 17, 100]`, call `fuzz_roundtrip_legacy` with a hand-filled `LegacyCase`
  (fixed IVs/keys, no mutations, for v2 one extension `vec![1,2,3]`). Any format mismatch in
  the builder panics here. **This is the most important test.**
- `smoke_v3_roundtrip_and_tamper`: `fuzz_roundtrip_v3` with no mutations (must pass), then a
  case with one mutation at a payload offset (must not panic; typically HMAC-rejects).
- `smoke_raw_and_parsers`: run `fuzz_decrypt_raw` and `fuzz_parsers` on: empty input,
  `b"AES"`, `b"AES\x03\x00"`, `b"AES\x03\x00\x00\x00\x00\x00\x00\x01"`, a full valid v3 file
  from `build_v3_file` (password "fuzz-password" to match the raw target), and a valid v0 file.
- `smoke_stream_decrypt`: run `fuzz_stream_decrypt` on empty/short inputs and on
  `[3, 0] ++ encrypt_stream(...)` output built with key `[0x42; 32]` / iv `[0x24; 16]`
  (use `aescrypt_rs::encryption::encrypt_stream`) — must not panic.
- `generate_seed_corpus` (see step 5) marked `#[ignore]`.

## Step 4 — `fuzz/fuzz_targets/*.rs` (5 thin wrappers)

Each file:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| aescrypt_rs_fuzz::fuzz_decrypt_raw(data));
```

- `decrypt_raw.rs`, `stream_decrypt.rs`, `parsers.rs`: `|data: &[u8]|` calling the matching fn.
- `roundtrip_v3.rs`: `fuzz_target!(|case: aescrypt_rs_fuzz::V3Case| aescrypt_rs_fuzz::fuzz_roundtrip_v3(&case));`
- `roundtrip_legacy.rs`: same shape with `LegacyCase`.

(Crate name on disk is `aescrypt-rs-fuzz` → import path `aescrypt_rs_fuzz`.)

## Step 5 — Seed corpora (committed under `fuzz/corpus/<target>/`)

Generated by the `#[ignore]`d test `generate_seed_corpus` in the lib (cwd during `cargo test`
is `fuzz/`, so write relative paths `corpus/<target>/<name>`). Create dirs with
`std::fs::create_dir_all`. Seeds:

- `corpus/decrypt_raw/`: `v3_iter1.aes` (plaintext `b"seed plaintext for fuzzing"`,
  **password "fuzz-password"** — must match the target's fixed password so coverage reaches the
  success path; **iterations=1** so execs stay fast), `v3_empty_iter1.aes`, `v0.aes`, `v1.aes`,
  `v2.aes` (built via `build_legacy_file`, same password), `header_v3` (`b"AES\x03\x00"`),
  `header_v0` (`b"AES"`).
- `corpus/parsers/`: the header stubs above plus `b"AES\x02\x00\x00\x05hello\x00\x00"`.
- `corpus/stream_decrypt/`: `v3_stream` = `[0x03, 0x00]` + `encrypt_stream` output (key
  `[0x42;32]`, iv `[0x24;16]`, small plaintext); `v1_stream` = `[0x01, 0x00]` +
  `cbc_encrypt(key, iv, padded)` + modulo byte + `hmac_tag(key, ct)` with the same fixed
  key/iv.
- No seeds for the two structured targets (libFuzzer synthesizes `Arbitrary` inputs).

Do NOT seed `decrypt_raw` with the repo's `tests/test_data` v3 files — they likely carry large
iteration counts and would poison fuzzing throughput with multi-second execs.

## Step 6 — Verification sequence (run in this order)

```powershell
# 1. Harness compiles + smoke tests pass on the pinned 1.70 toolchain (no nightly needed):
cargo test --no-default-features --manifest-path fuzz/Cargo.toml
# 2. Generate + commit seed corpora:
cargo test --no-default-features --manifest-path fuzz/Cargo.toml generate_seed_corpus -- --ignored
# 3. Fuzz binaries compile on nightly (may fail on Windows/MSVC at link time — acceptable, see note):
cargo +nightly fuzz build
# 4. If (3) worked, short sanity runs (from repo root):
cargo +nightly fuzz run parsers -- -max_total_time=30 -max_len=512
cargo +nightly fuzz run stream_decrypt -- -max_total_time=30 -max_len=4096
cargo +nightly fuzz run decrypt_raw -- -max_total_time=60 -timeout=10 -max_len=4096
cargo +nightly fuzz run roundtrip_v3 -- -max_total_time=60 -timeout=10
cargo +nightly fuzz run roundtrip_legacy -- -max_total_time=60 -timeout=10
# 5. Lint/format the fuzz crate:
cargo fmt --manifest-path fuzz/Cargo.toml
cargo clippy --no-default-features --manifest-path fuzz/Cargo.toml
```

Expected: step 1 all green (if the legacy builder has a format bug, `smoke_legacy_builder_*`
fails — fix the builder against the wire-format spec in step 3b, do not weaken the oracle).
Step 4 should find no crashes; any crash artifact is a real finding — save it, minimize with
`cargo +nightly fuzz tmin <target> <artifact>`, and report it rather than suppressing.

## Step 7 — `fuzz/README.md`

Document: the 5 targets (one line each + oracle), how to run
(`cargo +nightly fuzz run <target> -- -timeout=10 -max_len=4096`), the toolchain-file gotcha
(`+nightly` required), why `decrypt_raw` needs `-timeout` (headers can legally demand up to 5M
PBKDF2 iterations ≈ seconds per exec; the cap is the crate's DoS bound, not a bug), corpus
regeneration command, and the stable smoke-test command for Windows users.

## Step 8 — CI workflow `.github/workflows/fuzz.yml`

Note: the repo currently has **no** `.github/workflows/` directory — this will be the first
workflow; keep it self-contained.

```yaml
name: fuzz
on:
  workflow_dispatch:
  schedule:
    - cron: "0 6 * * 1"   # weekly, Monday 06:00 UTC
  pull_request:
    paths: ["fuzz/**", "src/**"]
jobs:
  fuzz:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        target: [decrypt_raw, roundtrip_v3, roundtrip_legacy, stream_decrypt, parsers]
    steps:
      - uses: actions/checkout@v4
      - run: rustup toolchain install nightly --profile minimal
      - run: cargo install cargo-fuzz --locked
      - run: cargo +nightly fuzz run ${{ matrix.target }} -- -max_total_time=180 -timeout=10 -max_len=4096 -rss_limit_mb=4096
      - uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: fuzz-artifacts-${{ matrix.target }}
          path: fuzz/artifacts
```

## Step 9 — CHANGELOG + commit

Add under `## [Unreleased]` → `### Added`:

> - **Fuzz suite** (`fuzz/`): five cargo-fuzz targets — `decrypt_raw` (adversarial bytes →
>   `decrypt()`), `roundtrip_v3` (valid file + mutations with an authentication oracle:
>   accepted output must equal the original plaintext), `roundtrip_legacy` (hand-built v0–v2
>   files continuously differential-tested against the read path; tamper oracle tolerates the
>   format's unauthenticated modulo byte), `stream_decrypt` (ring-buffer/trailer/PKCS#7
>   hammering), and `parsers` (header chain). Harness logic lives in a stable-compilable
>   library with smoke tests (`cargo test --no-default-features --manifest-path
>   fuzz/Cargo.toml`); seed corpora committed; weekly + PR-triggered CI job.

Commit everything on `claude/fuzz-test` with a `test(fuzz): ...` conventional message ending in
`Co-Authored-By:` per repo convention.

## Acceptance checklist

- [ ] `cargo test --no-default-features --manifest-path fuzz/Cargo.toml` passes on the pinned
      1.70 toolchain (includes the legacy-builder differential smoke test).
- [ ] Seed corpora exist under `fuzz/corpus/{decrypt_raw,parsers,stream_decrypt}/` and are
      committed.
- [ ] `cargo +nightly fuzz build` succeeds (or, if it fails on Windows/MSVC, the failure is
      link-stage only and is documented in fuzz/README.md as CI-only).
- [ ] Short local fuzz runs (if buildable) produce no crashes.
- [ ] `cargo clippy --no-default-features --manifest-path fuzz/Cargo.toml` is clean.
- [ ] Root crate untouched except CHANGELOG (the fuzz crate must not require any changes to
      `src/` — all APIs used are already public).
- [ ] CI workflow present; README present.

## Known pitfalls (do not rediscover these)

1. **Do not** call `decrypt()` in a hot loop with large iteration counts — always build v3
   inputs with `iterations ∈ 1..=256` in harnesses, and rely on `-timeout` for the raw target.
2. **Session HMAC version byte**: v3 appends the version byte to the session HMAC; v1/v2 do
   NOT. Getting this wrong makes every `roundtrip_legacy` exec fail at "well-formed file
   rejected".
3. **v1 has no extension section**; v2 and v3 do. `consume_all_extensions` is a no-op for
   version < 2.
4. **Zero-length extensions terminate the section** — the builder must filter empties.
5. **The `public_iv[0] |= 0x80` line in `fuzz_roundtrip_legacy` is intentional** (KDF-DoS
   guard for version-byte flips) — keep it and its comment.
6. **The legacy tamper oracle intentionally tolerates length changes ≤ 15 bytes** — that is
   the documented, inherent v0–v2 modulo malleability, not a bug. Byte divergence within the
   common prefix IS a bug.
7. `cargo fuzz` without `+nightly` resolves the repo's pinned 1.70 toolchain and fails.
