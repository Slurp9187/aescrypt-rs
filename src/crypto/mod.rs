// src/core/crypto/mod.rs

//! Low-level crypto primitives (HMAC, KDF).
//!
//! Sub-modules for primitives; see crate root for re-exports (e.g., `HmacSha256`, `KdfBuilder`).

pub mod hmac;
pub mod kdf;
