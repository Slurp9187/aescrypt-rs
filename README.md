# aescrypt-rs

**Fast, safe, streaming Rust implementation of the AES Crypt file format**

- **Read**: Full compatibility with **all versions** — v0, v1, v2, and v3  
- **Write**: Modern **v3 only** (PBKDF2-SHA512, PKCS#7 padding, proper session-key encryption)  
- AES-256-CBC + HMAC-SHA256 integrity  
- Constant-memory streaming (64-byte ring buffer)  
- Zero-cost secure memory via [`secure-gate`](https://github.com/Slurp9187/secure-gate) (enabled by default)  
- No `unsafe` in the core decryption path when `zeroize` is on  
- Pure Rust, `#![no_std]`-compatible core  
- Passes round-trip + deterministic tests against official AES Crypt v0–v3 files  

[![Crates.io](https://img.shields.io/crates/v/aescrypt-rs.svg)](https://crates.io/crates/aescrypt-rs)
[![Docs.rs](https://docs.rs/aescrypt-rs/badge.svg)](https://docs.rs/aescrypt-rs)
[![CI](https://github.com/Slurp9187/aescrypt-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/Slurp9187/aescrypt-rs/actions)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](#license)

## Support the Original Author

AES Crypt was created and maintained for over two decades by **Paul E. Jones**.

Paul’s work laid the foundation for secure, cross-platform file encryption that benefits everyone.

If you find AES Crypt (or this Rust port) useful, please consider supporting Paul directly:

- Official apps & licenses: https://www.aescrypt.com/download/
- Business/enterprise licensing: https://www.aescrypt.com/license.html

Your support keeps the original tools alive and funds future development.

## Version Support Summary

| Operation  | v0 | v1 | v2 | v3 |
|------------|----|----|----|----|
| Decrypt    | Yes| Yes| Yes| Yes|
| Encrypt    | –  | –  | –  | Yes (recommended modern format) |

> **Why v3-only on write?**  
> Version 3 is the only secure, future-proof variant (PBKDF2 with configurable iterations, UTF-8 passwords, PKCS#7 padding). Producing legacy formats today would be a downgrade.

## Quick Example

```rust
use aescrypt_rs::{encrypt, decrypt, Password};
use std::io::Cursor;

let plaintext = b"The quick brown fox jumps over the lazy dog";
let password = Password::new("correct horse battery staple".to_string());

let mut encrypted = Vec::new();
encrypt(password.clone(), Cursor::new(plaintext), &mut encrypted, 600_000)?;

let mut decrypted = Vec::new();
decrypt(password, Cursor::new(&encrypted), &mut decrypted)?;
assert_eq!(plaintext.as_slice(), decrypted);
println!("Round-trip successful!");
```

## Features

| Feature     | Description                                                      |
|-------------|------------------------------------------------------------------|
| `zeroize` (default) | Automatic secure zeroing of keys/IVs on drop (recommended)     |
| `std` (default)     | Convenience `std::io` wrappers (`encrypt`, `decrypt`)           |

## Installation

```toml
[dependencies]
aescrypt-rs = "0.1"
```

## Performance (Apple M2 Max – Rust 1.82 – release)

```
encrypt  1 GiB → 1.28 GiB/s
decrypt  1 GiB → 1.41 GiB/s
```

## Legal & Independence

`aescrypt-rs` is an **independent, community-maintained implementation** of the publicly documented AES Crypt file format ([specification](https://www.aescrypt.com/aes_file_format.html)).

It is **not affiliated with, endorsed by, or supported by** Paul E. Jones, Packetizer, Inc., or Terrapane Corporation.

Correctness was verified against the official open-source C++ reference implementation (publicly available for audit at the time of development), but **no source code was copied**. All logic is idiomatic Rust using the zero-cost `secure-gate` crate.

This software is provided **“as is”**, without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement.

## License

Dual-licensed under either

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contributing

Pull requests are very welcome!

The `secure` branch contains the latest work with full `secure-gate` integration.

`main` is the stable line.

---

**aescrypt-rs** – the modern, safe, blazing-fast way to read and write AES Crypt files in Rust.