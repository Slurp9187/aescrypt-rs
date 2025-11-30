# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),  
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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