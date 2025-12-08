# aescrypt-rs

**Fast, safe, streaming Rust implementation of the AES Crypt file format**

- **Read**: Full compatibility with **all versions** — v0, v1, v2, and v3
- **Write**: Modern **v3 only** (PBKDF2-HMAC-SHA512, PKCS#7 padding, proper session-key encryption)
- **Convert**: `convert_to_v3()` — the single, final API for bit-perfect migration with optional **256-bit random password upgrade**
- **Detect**: `read_version()` — header-only version check in <1 μs (ideal for batch tools)
- AES-256-CBC with **HMAC-SHA256** (payload) + **HMAC-SHA512** (session) authentication
- Constant-memory streaming (64-byte ring buffer)
- **Zero-cost secure memory & cryptographically secure RNG** via [`secure-gate`](https://github.com/Slurp9187/secure-gate) v0.6.1 (enabled by default)
- **Constant-time security**: All HMAC comparisons and padding validation use constant-time operations
- No `unsafe` in the core decryption path when `zeroize` is enabled
- Pure Rust, `#![no_std]`-compatible core
- **100% bit-perfect round-trip verified** against all 63 official v0–v3 test vectors
- **Legacy to v3 conversion mathematically proven perfect** across 20+ years of AES Crypt history

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
| **Convert to v3**  | Yes | Yes | Yes | —   |
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
- **No memory leaks**: Removed `'static` lifetime requirement from `convert_to_v3()`, eliminating need for `Box::leak()` workarounds
- **Streaming architecture**: Constant-memory decryption using 64-byte ring buffer (no full-file buffering)

## API Highlights

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

### Convert legacy → modern v3

```rust
use aescrypt_rs::{encrypt, convert_to_v3, aliases::PasswordString};
use std::io::{Cursor, BufReader, BufWriter};

let old_pw = PasswordString::new("old123".to_string());

// First, create a legacy v0 file (in-memory)
let mut legacy_data = Vec::new();
encrypt(Cursor::new(b"Hello, world!"), &mut legacy_data, &old_pw, 10_000)?;

// Now convert it to v3 with a random password
let mut modern_data = Vec::new();
let generated = convert_to_v3(
    Cursor::new(&legacy_data),
    BufWriter::new(&mut modern_data),
    &old_pw,
    None,
    300_000
)?;

if let Some(new_pw) = generated {
    // new_pw is a 256-bit random password
    assert_eq!(new_pw.expose_secret().len(), 64); // 32 bytes = 64 hex chars
}
# Ok::<(), aescrypt_rs::AescryptError>(())
```

Passing `Some(&PasswordString::new("".to_string()))` also triggers random generation — convenient shortcut.

### Explicit new password

```rust
use aescrypt_rs::{encrypt, convert_to_v3, aliases::PasswordString};
use std::io::{Cursor, BufWriter};

let old_pw = PasswordString::new("old123".to_string());
let new_pw = PasswordString::new("much-stronger-2025!".to_string());

// First, create a legacy v0 file (in-memory)
let mut legacy_data = Vec::new();
encrypt(Cursor::new(b"Hello, world!"), &mut legacy_data, &old_pw, 10_000)?;

// Convert to v3 with explicit new password
let mut modern_data = Vec::new();
convert_to_v3(
    Cursor::new(&legacy_data),
    BufWriter::new(&mut modern_data),
    &old_pw,
    Some(&new_pw),
    500_000
)?;
# Ok::<(), aescrypt_rs::AescryptError>(())
```

### Standard encrypt / decrypt

```rust
use aescrypt_rs::{encrypt, decrypt, aliases::PasswordString};
use std::io::Cursor;

let pw = PasswordString::new("correct horse battery staple".to_string());
let data = b"top secret";

let mut ciphertext = Vec::new();
encrypt(Cursor::new(data), &mut ciphertext, &pw, 600_000)?;

let mut plaintext = Vec::new();
decrypt(Cursor::new(&ciphertext), &mut plaintext, &pw)?;
assert_eq!(data, &plaintext[..]);
# Ok::<(), aescrypt_rs::AescryptError>(())
```

### Batch operations (optional feature)

Requires the `batch-ops` feature to be enabled:

```toml
aescrypt_rs = { version = "0.2.0", features = ["batch-ops"] }
```

```rust,ignore
use aescrypt_rs::{encrypt_batch, decrypt_batch, aliases::PasswordString};
use std::io::Cursor;

let password = PasswordString::new("secret".to_string());

// Encrypt multiple files in parallel
let mut batch = vec![
    (Cursor::new(b"file1"), Vec::new()),
    (Cursor::new(b"file2"), Vec::new()),
    (Cursor::new(b"file3"), Vec::new()),
];

encrypt_batch(&mut batch, &password, 300_000)?;
// All files are now encrypted in parallel

// Decrypt multiple files in parallel
let mut encrypted_batch = vec![
    (Cursor::new(&batch[0].1[..]), Vec::new()),
    (Cursor::new(&batch[1].1[..]), Vec::new()),
    (Cursor::new(&batch[2].1[..]), Vec::new()),
];

decrypt_batch(&mut encrypted_batch, &password)?;
// All files are now decrypted in parallel
```

## Performance (release mode, modern laptop)

| Workload                   | Throughput       |
| -------------------------- | ---------------- |
| Decrypt 10 MiB             | ~158 MiB/s       |
| Encrypt 10 MiB (with KDF)  | ~149 MiB/s       |
| Round-trip 10 MiB          | ~75 MiB/s        |
| Batch 16×10 MiB (parallel) | ~200 MiB/s total |

All benchmarks include full 300,000 PBKDF2 iterations when applicable.

## Features

| Feature             | Description                            |
| ------------------- | -------------------------------------- |
| `zeroize` (default) | Automatic secure memory wiping on drop |
| `batch-ops`         | Parallel batch processing via Rayon    |

## Installation

```toml
[dependencies]
aescrypt-rs = "0.2.0"
```

With optional features:

```toml
aescrypt_rs = { version = "0.2.0", features = ["batch-ops"] }
```

## License

Licensed under MIT or Apache-2.0 at your option.

## Contributing

Pull requests welcome! `main` is the stable branch.

---

**aescrypt-rs** — the modern, safe, and future-proof way to handle AES Crypt files in Rust.
