//! # Key Derivation Functions (KDF)
//!
//! This module provides key derivation functions used by AES Crypt for converting
//! passwords into encryption keys.
//!
//! ## Modules
//!
//! - [`ackdf`] - AES Crypt Key Derivation Function (used in v0-v2 files)
//! - [`pbkdf2`] - PBKDF2-HMAC-SHA512 (used in v3 files)
//!
//! ## Usage
//!
//! For most use cases, you should use the high-level [`encrypt`](crate::encrypt) and
//! [`decrypt`](crate::decrypt) functions, which handle KDF operations automatically.
//!
//! These low-level functions are exposed for custom decryption flows, such as reading
//! legacy files without using the full high-level API.

pub mod ackdf;
pub mod pbkdf2;

