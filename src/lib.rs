// uncomment to run doctests
// cargo test --doc lib
//#![doc = include_str!("../README.md")]

//! # Quick Start
//!
//! Encrypt and decrypt data using AES Crypt format v3:
//!
//! ```rust,no_run
//! use aescrypt_rs::{encrypt, decrypt, PasswordString, constants::DEFAULT_PBKDF2_ITERATIONS};
//! use std::io::Cursor;
//!
//! let password = PasswordString::new("correct horse battery staple".to_string());
//! let data = b"top secret";
//!
//! // Encrypt
//! let mut ciphertext = Vec::new();
//! encrypt(Cursor::new(data), &mut ciphertext, &password, DEFAULT_PBKDF2_ITERATIONS)?;
//!
//! // Decrypt
//! let mut plaintext = Vec::new();
//! decrypt(Cursor::new(&ciphertext), &mut plaintext, &password)?;
//!
//! assert_eq!(data, &plaintext[..]);
//! # Ok::<(), aescrypt_rs::AescryptError>(())
//! ```
//!
//! Detect file format version without decrypting:
//!
//! ```rust
//! use aescrypt_rs::read_version;
//! use std::io::Cursor;
//!
//! let header = b"AES\x03\x00";
//! let version = read_version(Cursor::new(header))?;
//! assert_eq!(version, 3);
//! # Ok::<(), aescrypt_rs::AescryptError>(())
//! ```

pub mod aliases;
pub mod constants;
pub mod decryption;
pub mod encryption;
pub mod error;
pub mod header;
pub mod kdf;
pub mod pbkdf2_builder;
pub mod utilities;

// High-level API — this is what 99% of users import
pub use aliases::PasswordString;
pub use decryption::decrypt;
pub use encryption::encrypt;
pub use error::AescryptError; // Core type used in every encrypt/decrypt call

// Low-level KDFs — intentionally public at the root because:
// • They are needed for custom decryption flows (e (e.g. reading v0–v2 files without the high-level API)
// • They are the only non-wrapper crypto functions users ever need directly
// • Keeping them at the root is the established pattern in the ecosystem (see `ring`, `password-hash`, etc.)
pub use pbkdf2_builder::Pbkdf2Builder;

pub use kdf::ackdf::derive_ackdf_key;
pub use kdf::pbkdf2::derive_pbkdf2_key;

pub use header::read_version; // New: Quick version check
