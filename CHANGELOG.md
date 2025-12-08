# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),  
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-12-04

### Breaking Changes

- Renamed `convert_to_v3_ext` to `convert_to_v3` (now the only conversion API).
- Removed the old `convert_to_v3` entirely (soft-deprecated since 0.1.6).
- Replaced all short aliases with explicit, size-tagged CamelCase names (e.g., `Aes256Key` → `Aes256Key32`, `Iv16` remains, `EncryptedSessionBlock48` unchanged).
- Random aliases now size-tagged (e.g., `RandomAes256Key32`).
- Public API in `lib.rs` minimized and re-exported with new names.

### Security

- **Fixed timing attack vulnerabilities**: All HMAC comparisons now use constant-time operations via `secure-gate`'s `ct_eq()` method.
  - Session HMAC verification uses constant-time comparison.
  - Stream HMAC verification (v0, v1/v2, v3) uses constant-time comparison.
- **Fixed PKCS#7 padding validation timing leak**: Padding validation now always compares a fixed 16-byte block instead of variable-length slices, preventing timing attacks that could reveal padding values.
- All constant-time operations use `secure-gate::conversions::SecureConversionsExt::ct_eq()`, which leverages `subtle::ConstantTimeEq` internally.

### Added

- Generic `SpanBuffer<const N: usize>` as secure stack buffer (alias to `secure-gate::Fixed<[u8; N]>`).
- Strongly-typed sub-types of `SpanBuffer` for semantic clarity: `Block16`, `Trailer32`, `Trailer33`, `InitialRead48`, `Pbkdf2HashState32`, `Pbkdf2DerivedKey32`, `AckdfHashState32`.
- Empty string (`Some("")`) now triggers random 256-bit password generation (same as `None`).
- Generated random passwords use 1 PBKDF2 iteration; supplied passwords use full count.
- Comprehensive rust-doc documentation for all public modules and functions.
- `PBKDF2_MIN_ITER` constant for consistent iteration validation across the codebase.

### Changed

- **Removed `'static` lifetime requirement from `convert_to_v3()`**: Now uses `std::thread::scope` instead of requiring `'static` lifetimes, allowing owned data (like `Vec<u8>`) wrapped in `Cursor` without `Box::leak()` workarounds. This greatly improves ergonomics for downstream crates.
- Moved `derive_setup_key` from `encryptor/write.rs` to `encryptor/session.rs` for better cohesion.
- Hardened ACKDF temporary hash buffer with `AckdfHashState32`.
- Updated all internal code, tests, and benchmarks to use new alias names.
- Consolidated conversion tests into single file (`tests/convert_tests.rs`).
- Renamed `src/decryptor/stream/utils.rs` to `src/decryptor/stream/trailer.rs` for better clarity.
- Consolidated test file generation scripts into a single unified script (`tests/test_data/scripts/generate_test_files.py`).
- Enhanced KDF iteration validation with consistent bounds checking using `PBKDF2_MIN_ITER` constant.

### Removed

- Deprecated `convert_to_v3` and related wrappers.
- Unused or redundant aliases (e.g., `PrevCiphertextBlock16` replaced by `Block16`).
- Legacy test file generation scripts (replaced by unified script).
- `encrypt_with_fixed_session` function and associated deterministic encryption test file.

### Fixed

- Resolved HMAC constructor ambiguity in session extraction.
- Fixed doctest in `batch_ops.rs` by defining missing variables in example code.
- Cleaned up `.gitignore` by removing redundant patterns.

All tests (including 63 vectors) pass with and without `zeroize`. Benchmarks unchanged (>165 MiB/s decrypt, >160 MiB/s encrypt).

## [0.1.6] - 2025-12-03

### Features

- Added `convert_to_v3_ext` — supports separate old/new passwords and **256-bit random password generation**
  - `new_password = None` → generates secure 64-char hex password (256-bit entropy)
  - Uses `RandomPassword32::random_hex()` (secure-gate v0.5.10 best practice)

### Deprecations

- Soft-deprecated `convert_to_v3` (since 0.1.6)
  - Still fully supported and backward compatible
  - Thin wrapper added so old code keeps compiling with a helpful warning
  - Will be removed in v1.0

### Internal

- All new code uses `PasswordString` and `RandomPassword32` aliases
- No breaking changes — safe upgrade for all users

## [0.1.5] - 2025-12-03

### Added

- **Quick version detection**: New `read_version<R: Read>() -> Result<u8, AescryptError>` for header-only file checks (#17)  
  → Reads just 3–5 bytes to extract/validate version (0–3) + magic ("AES")  
  → Errors on invalid magic, short files, or bad reserved bytes  
  → Perfect for batch validation, legacy detection, or CLI tools
  - No crypto/KDF deps, fully `no_std`, <1μs per file
  - 100% tested against all 63 official v0–v3 vectors + edges (invalid/short/malformed)
  - Closes #17

### Changed

- **Upgraded `secure-gate` to v0.5.10 and adopted its new zero-cost random aliases** (#42)  
  → All cryptographically secure random values (`public_iv`, `session_iv`, `session_key`) are now created with the brand-new `RandomIv16::new()` and `RandomAes256Key::new()` types introduced in secure-gate 0.5.10
  - Replaces the previous `Iv16::random()` / `Aes256Key::random()` calls
  - Zero-cost, panic-on-failure, thread-local `OsRng` (exactly the same underlying implementation)
  - Cleaner, more explicit intent at the call site
  - No allocation, no behavior change, no performance regression (benchmarks unchanged)

### Maintenance

- Added the new `RandomIv16` and `RandomAes256Key` aliases to `src/aliases/mod.rs`
- Minor import tidy-up in `encrypt.rs` – removed unused `SecureRandomExt` re-export

A tiny but extremely satisfying ergonomics win — the encryption path now reads like pure intent while staying 100% locked down with secure-gate’s gold-standard memory safety.

## [0.1.4] – 2025-11-29

### Security

- Removed `convert_to_v3_to_vec` entirely. It allocated the entire plaintext in a `Vec<u8>`,
  violating the streaming guarantee and creating unnecessary memory-exposure risk.
  Use `convert_to_v3` with any `Write` (including `Vec<u8>` if you really need it).

## [0.1.3] - 2025-11-29

### Added

- **`convert_to_v3_to_vec`** – new convenience function that converts legacy v0/v1/v2 files to v3 and returns an owned `Vec<u8>`  
  This eliminates the painful `'static` mutable writer requirement that made testing and one-off conversions extremely difficult.  
  Internally uses `thread::scope` for safe, zero-cost streaming (no `Box::leak`, no `unsafe`, no extra cloning).  
  Greatly improves ergonomics for downstream crates like `encrypted-file-vault`.

### Fixed

- Lifetime and borrow-checker issues when using `convert_to_v3` with stack-allocated buffers (the root cause of many test failures).

### Documentation

- Added detailed comments and examples for the new `convert_to_v3_to_vec` API.

Thanks to the heroic struggle against the borrow checker — this release finally makes the conversion API pleasant to use.

## [0.1.2] – 2025-11-28

### Fixed

- Fixed error propagation in `convert_to_v3`: decryption errors are no longer masked by the background encryption thread. Failures now surface correctly and immediately.

### Maintenance

- Ran `cargo machete` and ruthlessly purged all unused dependencies. Cargo.toml is once again pristine and minimal.

No experimental channels, no dead code, no wasted bytes — just a tiny but important bug fix and a cleaner dependency tree.

## [0.1.1] - 2025-11-27

### Changed

- **Upgraded `secure-gate` to v0.5.7** and enabled its new `rand` feature  
  → All cryptographically secure random values (`Aes256Key`, `Iv16`, salts, etc.) are now generated with `SecureRandomExt::random()` from `secure-gate`
  - Removes the duplicated RNG implementation (`src/crypto/rng.rs` → deleted)
  - Zero-cost, thread-local `OsRng`, lazy-initialized, fully `no_std`-compatible
  - Panics on RNG failure (high-assurance crypto standard)
  - No behavior or performance regression — benchmarks remain identical (>160 MiB/s encrypt, >170 MiB/s decrypt)

### Fixed

- Minor internal clean-ups and import tidy-ups after the RNG migration

### Documentation

- Updated dependency list and feature explanations in `README.md` to reflect the new `secure-gate` version

No breaking changes — fully backward compatible with 0.1.0.
All 100+ tests (including bit-perfect v0–v3 round-trips and deterministic vectors) continue to pass.

## [0.1.0] - 2025-11-27

### Added

- **Initial public release** – full-featured, production-ready implementation of the AES Crypt file format (v0–v3)
- Full **read support** for all official versions (v0, v1, v2, v3)
- Full **write support** for modern **v3** format only (PBKDF2-SHA256, PKCS#7 padding, UTF-8 passwords, proper session key encryption)
- High-level API: `encrypt()` and `decrypt()` with `std::io::Read`/`Write` streaming
- `convert_to_v3()` for seamless migration of legacy files to modern v3 format
- Batch processing API: `encrypt_batch()` and `decrypt_batch()` with optional Rayon parallelism (via `batch-ops` feature)
- Secure memory handling via [`secure-gate`](https://github.com/Slurp9187/secure-gate) v0.5.6+ with full `zeroize` integration (enabled by default)
- Constant-memory streaming decryption using a 64-byte ring buffer (no heap allocations during bulk processing)
- Comprehensive test suite:
  - 100% passing round-trip tests against official AES Crypt v0–v3 reference files
  - Deterministic v3 test vectors with known public IV, session IV, and session key
  - KDF edge-case tests (ACKDF, PBKDF2, unicode passwords, empty inputs)
- Benchmark suite using Criterion.rs (`cargo bench`) with realistic 1 KiB → 10 MiB workloads
- `#![no_std]`-compatible core (only `std` feature adds convenience wrappers)
- Detailed documentation and examples in `README.md`
- CI workflow (GitHub Actions) with full test + bench matrix

### Security

- All sensitive values (keys, IVs, passwords) wrapped in `secure-gate` types
- Automatic zeroing on drop via `zeroize` (default feature)
- No `unsafe` code in the core encryption/decryption paths when `zeroize` is enabled
- PBKDF2 iteration count bounds enforced (1 to 5,000,000)
- Default recommended 300,000 iterations (~180 ms on i7-10510U)

### Performance

- Real-world benchmarks on Intel i7-10510U (4c/8t, 16 GB RAM, Windows 11):
  - Decrypt 10 MiB → **~171 MiB/s**
  - Encrypt 10 MiB (with KDF) → **~160 MiB/s**
  - Full round-trip 10 MiB → **~76 MiB/s**
- Expect **>1 GiB/s** on modern desktop CPUs and Apple Silicon

### Notes

- This release is intentionally **v3-only on write** — legacy v0–v2 formats are supported for decryption only.
- The library is **independent** and contains **no code** from the original AES Crypt C++ implementation.

This is the first stable, crate-publishable version. Ready for `cargo publish`!

---

**aescrypt-rs** – Fast, safe, and future-proof AES Crypt in Rust.
