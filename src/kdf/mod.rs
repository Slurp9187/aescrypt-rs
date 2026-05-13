//! Key Derivation Functions used by AES Crypt v0–v3.
//!
//! Two KDFs are wired in, gated by file format version:
//!
//! - [`ackdf`] — AES Crypt Key Derivation Function: 8192 SHA-256 iterations
//!   over a UTF-16-LE password and 16-byte salt, used by v0/v1/v2 files
//!   (read-only).
//! - [`pbkdf2`] — PBKDF2-HMAC-SHA512 with caller-controlled iteration count
//!   (default [`crate::constants::DEFAULT_PBKDF2_ITERATIONS`]), used by v3
//!   files (read and write).
//!
//! Most callers should use the high-level [`encrypt`](crate::encrypt()) and
//! [`decrypt`](crate::decrypt()) functions, which select the right KDF
//! automatically. These primitives are exposed for custom decryption flows,
//! such as reading legacy files outside the full high-level API.
//!
//! # Security
//!
//! ACKDF is fixed at 8192 SHA-256 iterations by spec; it is weak by modern
//! standards and exists solely for compatibility with v0–v2 files. PBKDF2
//! iterations should never go below
//! [`DEFAULT_PBKDF2_ITERATIONS`](crate::constants::DEFAULT_PBKDF2_ITERATIONS).

pub mod ackdf;
pub mod pbkdf2;
