# aescrypt-rs

**Fast, safe, streaming Rust implementation of the AES Crypt file format**

- **Read**: Full compatibility with **all versions** — v0, v1, v2, and v3
- **Write**: Modern **v3 only** (PBKDF2-HMAC-SHA512, PKCS#7 padding, proper session-key encryption)
- **Detect**: `read_version()` — header-only version check in <1 μs (ideal for batch tools)
- AES-256-CBC with **HMAC-SHA256** (payload) + **HMAC-SHA512** (session) authentication
- Constant-memory streaming (64-byte ring buffer)
- **Zero-cost secure memory & cryptographically secure RNG** via [`secure-gate`](https://github.com/Slurp9187/secure-gate) v0.6.1 (enabled by default)
- **Constant-time security**: All HMAC comparisons and padding validation use constant-time operations
- No `unsafe` in the core decryption path when `zeroize` is enabled
- Pure Rust, `#![no_std]`-compatible core
- **100% bit-perfect round-trip verified** against all 63 official v0–v3 test vectors

[![Crates.io](https://img.shields.io/crates/v/aescrypt-rs.svg)](https://crates.io/crates/aescrypt-rs)
[![Docs.rs](https://docs.rs/aescrypt-rs/badge.svg)](https://docs.rs/aescrypt-rs)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](#license)

## Support the Original Author

AES Crypt was created and maintained for over two decades by **Paul E. Jones**.

If you find AES Crypt (or this Rust port) useful, please consider supporting Paul directly:

- Official apps & licenses: https://www.aescrypt.com/download/
- Business/enterprise licensing: https://www.aescrypt.com/license.html

## Version Support Summary

| Operation          | v0  | v1  | v2  | v3  |
| ------------------ | --- | --- | --- | --- |
| Decrypt            | Yes | Yes | Yes | Yes |
| Encrypt            | –   | –   | –   | Yes |
| **Detect version** | Yes | Yes | Yes | Yes |

> **Why v3-only on write?**  
> Version 3 is the only secure, future-proof variant. Producing legacy formats today would be a security downgrade.

## Cryptographic Primitives (v3)

| Layer                   | Encryption  | Integrity / KDF    |
| ----------------------- | ----------- | ------------------ |
| Password → Master Key   | –           | PBKDF2-HMAC-SHA512 |
| Session Key + IV (48 B) | AES-256-CBC | HMAC-SHA256        |
| File Payload            | AES-256-CBC | HMAC-SHA256        |

## Security Features

- **Constant-time operations**: All HMAC verifications and PKCS#7 padding validation use constant-time comparisons to prevent timing attacks
- **Secure memory management**: All sensitive data (keys, passwords, IVs) wrapped in `secure-gate` types with automatic zeroization
- **Streaming architecture**: Constant-memory decryption using 64-byte ring buffer (no full-file buffering)

## Core API

The library provides a minimal, focused API at the root level:

**High-level functions** (99% of use cases):

- `encrypt()` - Encrypt data to AES Crypt v3 format
- `decrypt()` - Decrypt AES Crypt files (v0-v3)
- `read_version()` - Quick version detection without full decryption

**Key derivation**:

- `Pbkdf2Builder` - Fluent builder for PBKDF2 key derivation
- `derive_ackdf_key()` - Low-level ACKDF for v0-v2 files
- `derive_pbkdf2_key()` - Low-level PBKDF2 for v3 files

**Types and constants**:

- `AescryptError` - Comprehensive error type
- `PasswordString` and other secure types via `aliases::*`
- Configuration constants via `consts::*`

**Advanced access**: Lower-level functions available via `decryption::*` and `encryption::*` module paths for custom flows.

## API Examples

### Detect file version (header only)

```rust
use aescrypt_rs::read_version;
use std::io::Cursor;

// v3 file header
let header = b"AES\x03\x00";
let version = read_version(Cursor::new(header))?;
assert_eq!(version, 3);

// v0 file header (3-byte)
let header = b"AES";
let version = read_version(Cursor::new(header))?;
assert_eq!(version, 0);
# Ok::<(), aescrypt_rs::AescryptError>(())
```

### Standard encrypt / decrypt

```rust
use aescrypt_rs::{encrypt, decrypt, PasswordString, consts::DEFAULT_PBKDF2_ITERATIONS};
use std::io::Cursor;

let pw = PasswordString::new("correct horse battery staple".to_string());
let data = b"top secret";

let mut ciphertext = Vec::new();
encrypt(Cursor::new(data), &mut ciphertext, &pw, DEFAULT_PBKDF2_ITERATIONS)?;

let mut plaintext = Vec::new();
decrypt(Cursor::new(&ciphertext), &mut plaintext, &pw)?;
assert_eq!(data, &plaintext[..]);
# Ok::<(), aescrypt_rs::AescryptError>(())
```

### PBKDF2 Key Derivation Builder

For custom key derivation with a fluent API:

```rust
use aescrypt_rs::{Pbkdf2Builder, PasswordString, aliases::Aes256Key32};

let password = PasswordString::new("my-secret-password".to_string());

// Use defaults (300k iterations, random salt)
let mut key = Aes256Key32::new([0u8; 32]);
Pbkdf2Builder::new()
    .derive_secure(&password, &mut key)?;

// Or customize
let mut custom_key = Aes256Key32::new([0u8; 32]);
Pbkdf2Builder::new()
    .with_iterations(500_000)
    .with_salt([0x42; 16])
    .derive_secure(&password, &mut custom_key)?;

// Or get a new key directly
let derived_key = Pbkdf2Builder::new()
    .derive_secure_new(&password)?;
# Ok::<(), aescrypt_rs::AescryptError>(())
```

### Advanced API Access

For custom decryption/encryption flows, access lower-level functions via module paths:

```rust
use aescrypt_rs::{
    decryption::{extract_session_data, StreamConfig, read_file_version},
    encryption::{derive_setup_key, encrypt_session_block},
    aliases::{Aes256Key32, Iv16, PasswordString},
    consts::DEFAULT_PBKDF2_ITERATIONS,
};
use std::io::Cursor;

// Custom decryption flow example
# fn example() -> Result<(), aescrypt_rs::AescryptError> {
let mut reader = Cursor::new(b"encrypted data...");
let version = read_file_version(&mut reader)?;
let password = PasswordString::new("password".to_string());

// Extract session data manually
// Read public IV from file header (example placeholder)
let public_iv = Iv16::new([0u8; 16]); // In real code, read from file
let mut setup_key = Aes256Key32::new([0u8; 32]);
// Derive setup key using appropriate KDF for version
// derive_setup_key(&password, &public_iv, version, &mut setup_key)?;
let mut session_iv = Iv16::new([0u8; 16]);
let mut session_key = Aes256Key32::new([0u8; 32]);
extract_session_data(&mut reader, version, &public_iv, &setup_key, &mut session_iv, &mut session_key)?;

// Use StreamConfig for version-specific decryption
let config = StreamConfig::V3;
// Continue custom decryption with config...
# Ok(())
# }
```

## Constants

Configuration constants are available via the `consts` module:

```rust
use aescrypt_rs::consts::{
    DEFAULT_PBKDF2_ITERATIONS,  // 300,000 (recommended default)
    PBKDF2_MIN_ITER,            // 1
    PBKDF2_MAX_ITER,            // 5,000,000
    AESCRYPT_LATEST_VERSION,    // 3
};

// Use in encryption
# use aescrypt_rs::{encrypt, PasswordString};
# use std::io::Cursor;
# let input = Cursor::new(b"data");
# let mut output = Vec::new();
# let password = PasswordString::new("password".to_string());
encrypt(input, &mut output, &password, DEFAULT_PBKDF2_ITERATIONS)?;
# Ok::<(), aescrypt_rs::AescryptError>(())
```

## Performance (release mode, modern laptop)

| Workload                  | Throughput |
| ------------------------- | ---------- |
| Decrypt 10 MiB            | ~158 MiB/s |
| Encrypt 10 MiB (with KDF) | ~149 MiB/s |
| Round-trip 10 MiB         | ~75 MiB/s  |

All benchmarks include full 300,000 PBKDF2 iterations when applicable.

## Features

| Feature             | Description                            |
| ------------------- | -------------------------------------- |
| `zeroize` (default) | Automatic secure memory wiping on drop |

No optional features - the library is focused and minimal. All functionality is always available.

## Installation

```toml
[dependencies]
aescrypt-rs = "0.2.0"
```

## License

Licensed under MIT or Apache-2.0 at your option.

## Contributing

Pull requests welcome! `main` is the stable branch.

---

**aescrypt-rs** — the modern, safe, and future-proof way to handle AES Crypt files in Rust.
