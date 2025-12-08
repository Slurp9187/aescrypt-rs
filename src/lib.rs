//! # aescrypt-rs
//!
//! Fast, safe, streaming Rust implementation of the AES Crypt file format.
//!
//! ## Features
//!
//! - **Read**: Full compatibility with all versions (v0, v1, v2, and v3)
//! - **Write**: Modern v3 only (PBKDF2-HMAC-SHA512, PKCS#7 padding, proper session-key encryption)
//! - **Convert**: `convert_to_v3()` for bit-perfect migration with optional 256-bit random password upgrade
//! - **Detect**: `read_version()` for header-only version checks
//! - AES-256-CBC with HMAC-SHA256 (payload) + HMAC-SHA512 (session) authentication
//! - Constant-memory streaming (64-byte ring buffer)
//! - Zero-cost secure memory & cryptographically secure RNG via [`secure-gate`](https://github.com/Slurp9187/secure-gate) v0.6.1
//! - Pure Rust, `#![no_std]`-compatible core
//!
//! ## Quick Start
//!
//! ```no_run
//! use aescrypt_rs::{encrypt, decrypt, aliases::PasswordString};
//! use std::io::Cursor;
//!
//! let password = PasswordString::new("my-secret-password".to_string());
//! let data = b"Hello, world!";
//!
//! // Encrypt
//! let mut ciphertext = Vec::new();
//! encrypt(Cursor::new(data), &mut ciphertext, &password, 300_000)?;
//!
//! // Decrypt
//! let mut plaintext = Vec::new();
//! decrypt(Cursor::new(&ciphertext), &mut plaintext, &password)?;
//!
//! assert_eq!(plaintext, data);
//! # Ok::<(), aescrypt_rs::AescryptError>(())
//! ```
//!
//! ## High-Level API
//!
//! The primary API consists of:
//!
//! - [`encrypt`] - Encrypt data to AES Crypt v3 format
//! - [`decrypt`] - Decrypt AES Crypt files (v0-v3)
//! - [`convert_to_v3`] - Convert legacy files to v3 format
//! - [`read_version`] - Detect file version without full decryption
//!
//! ## Low-Level API
//!
//! For custom decryption flows, the following are available:
//!
//! - [`derive_secure_pbkdf2_key`] - PBKDF2-HMAC-SHA512 key derivation
//! - [`derive_secure_ackdf_key`] - ACKDF key derivation (v0-v2)
//! - [`Pbkdf2Builder`] - Builder for PBKDF2 key derivation
//!
//! ## Batch Operations
//!
//! When the `batch-ops` feature is enabled:
//!
//! - `encrypt_batch` - Parallel encryption of multiple files
//! - `decrypt_batch` - Parallel decryption of multiple files
//!
//! ## Error Handling
//!
//! All operations return [`Result<T, AescryptError>`](AescryptError) for comprehensive error handling.

#[cfg(feature = "batch-ops")]
pub mod batch_ops;
pub mod builders;
pub mod consts;
pub mod convert;
pub mod kdf;
pub mod decryptor;
pub mod encryptor;
pub mod error;
pub mod header;
pub mod utils;

pub mod aliases;

// High-level API — this is what 99% of users import
pub use decryptor::decrypt;
pub use encryptor::encrypt;
pub use error::AescryptError;

// Low-level KDFs — intentionally public at the root because:
// • They are needed for custom decryption flows (e (e.g. reading v0–v2 files without the high-level API)
// • They are the only non-wrapper crypto functions users ever need directly
// • Keeping them at the root is the established pattern in the ecosystem (see `ring`, `password-hash`, etc.)
pub use builders::pbkdf2_builder::Pbkdf2Builder;

pub use kdf::ackdf::derive_secure_ackdf_key;
pub use kdf::pbkdf2::derive_secure_pbkdf2_key;

#[cfg(feature = "batch-ops")]
pub use batch_ops::{decrypt_batch, encrypt_batch};

#[allow(deprecated)]
pub use convert::convert_to_v3;

pub use header::read_version; // New: Quick version check
