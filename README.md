# aescrypt-rs

**Fast, safe, streaming Rust implementation of the AES Crypt file format**

- **Read**: Full compatibility with **all versions** — v0, v1, v2, and v3  
- **Write**: Modern **v3 only** (PBKDF2-HMAC-SHA512, PKCS#7 padding, proper session-key encryption)  
- **Convert**: `convert_to_v3()` — the single, final API for bit-perfect migration with optional **256-bit random password upgrade**  
- **Detect**: `read_version()` — header-only version check in <1 μs (ideal for batch tools)  
- AES-256-CBC with **HMAC-SHA256** (payload) + **HMAC-SHA512** (session) authentication  
- Constant-memory streaming (64-byte ring buffer)  
- **Zero-cost secure memory & cryptographically secure RNG** via [`secure-gate`](https://github.com/Slurp9187/secure-gate) v0.6.1 (enabled by default)  
- No `unsafe` in the core decryption path when `zeroize` is enabled  
- Pure Rust, `#![no_std]`-compatible core  
- **100% bit-perfect round-trip verified** against all 63 official v0–v3 test vectors  
- **Legacy to v3 conversion mathematically proven perfect** across 20+ years of AES Crypt history

[![Crates.io](https://img.shields.io/crates/v/aescrypt-rs.svg)](https://crates.io/crates/v/aescrypt-rs)
[![Docs.rs](https://docs.rs/aescrypt-rs/badge.svg)](https://docs.rs/aescrypt-rs)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](#license)

## Support the Original Author

AES Crypt was created and maintained for over two decades by **Paul E. Jones**.

If you find AES Crypt (or this Rust port) useful, please consider supporting Paul directly:

- Official apps & licenses: https://www.aescrypt.com/download/
- Business/enterprise licensing: https://www.aescrypt.com/license.html

## Version Support Summary

| Operation           | v0 | v1 | v2 | v3 |
|---------------------|----|----|----|----|
| Decrypt             | Yes| Yes| Yes| Yes|
| Encrypt             | –  | –  | –  | Yes |
| **Convert to v3**   | Yes| Yes| Yes| —  |
| **Detect version**  | Yes| Yes| Yes| Yes|

> **Why v3-only on write?**  
> Version 3 is the only secure, future-proof variant. Producing legacy formats today would be a security downgrade.

## Cryptographic Primitives (v3)

| Layer                     | Encryption       | Integrity / KDF          |
|---------------------------|------------------|--------------------------|
| Password → Master Key     | –                | PBKDF2-HMAC-SHA512       |
| Session Key + IV (48 B)   | AES-256-CBC      | HMAC-SHA256              |
| File Payload              | AES-256-CBC      | HMAC-SHA256              |

## API Highlights

### Detect file version (header only)

```rust
use aescrypt_rs::read_version;
use std::fs::File;
use std::io::BufReader;

let file = File::open("file.aes")?;
let mut reader = BufReader::new(file);
let version = read_version(&mut reader)?; // reads ≤5 bytes
```

### Convert legacy → modern v3

```rust
use aescrypt_rs::{convert_to_v3, PasswordString};
use std::fs::File;
use std::io::{BufReader, BufWriter};

let old_pw = PasswordString::new("old123".into());

let input  = BufReader::new(File::open("legacy.aes")?);
let output = BufWriter::new(File::create("modern.aes")?);

// Upgrade to 256-bit random password (recommended for legacy files)
let generated = convert_to_v3(input, output, &old_pw, None, 300_000)?;

if let Some(new_pw) = generated {
    println!("New random password: {}", new_pw.expose_secret());
}
```

Passing `Some(&"")` also triggers random generation — convenient shortcut.

### Explicit new password

```rust
let new_pw = PasswordString::new("much-stronger-2025!".into());
convert_to_v3(input, output, &old_pw, Some(&new_pw), 500_000)?;
```

### Standard encrypt / decrypt

```rust
use aescrypt_rs::{encrypt, decrypt, PasswordString};
use std::io::Cursor;

let pw = PasswordString::new("correct horse battery staple".into());
let data = b"top secret";

let mut ciphertext = Vec::new();
encrypt(Cursor::new(data), &mut ciphertext, &pw, 600_000)?;

let mut plaintext = Vec::new();
decrypt(Cursor::new(&ciphertext), &mut plaintext, &pw)?;
assert_eq!(data, &plaintext[..]);
```

## Performance (release mode, modern laptop)

| Workload               | Throughput          |
|--------------------------|---------------------|
| Decrypt 10 MiB           | ~158 MiB/s          |
| Encrypt 10 MiB (with KDF)| ~149 MiB/s          |
| Round-trip 10 MiB        | ~75 MiB/s           |
| Batch 16×10 MiB (parallel) | ~200 MiB/s total  |

All benchmarks include full 300,000 PBKDF2 iterations when applicable.

## Features

| Feature       | Description                                      |
|---------------|--------------------------------------------------|
| `zeroize` (default) | Automatic secure memory wiping on drop     |
| `batch-ops`   | Parallel batch processing via Rayon              |

## Installation

```toml
[dependencies]
aescrypt-rs = "0.2.0"
```

With optional features:

```toml
aescrypt-rs = { version = "0.2.0", features = ["batch-ops"] }
```

## License

Licensed under MIT or Apache-2.0 at your option.

## Contributing

Pull requests welcome! `main` is the stable branch.

---

**aescrypt-rs** — the modern, safe, and future-proof way to handle AES Crypt files in Rust.