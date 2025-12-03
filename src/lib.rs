// src/lib.rs

pub mod aliases;
pub mod consts;
pub mod convert;
pub mod crypto;
pub mod decryptor;
pub mod encryptor;
pub mod error;
pub mod header;
pub mod utils;

#[cfg(feature = "batch-ops")]
pub mod batch_ops;

// High-level API — this is what 99% of users import
pub use decryptor::decrypt;
pub use encryptor::encrypt;
pub use error::AescryptError;

// Low-level KDFs — intentionally public at the root because:
// • They are needed for custom decryption flows (e (e.g. reading v0–v2 files without the high-level API)
// • They are the only non-wrapper crypto functions users ever need directly
// • Keeping them at the root is the established pattern in the ecosystem (see `ring`, `password-hash`, etc.)
pub use crypto::kdf::ackdf::derive_secure_ackdf_key;
pub use crypto::kdf::pbkdf2::derive_secure_pbkdf2_key;
pub use crypto::kdf::pbkdf2_builder::Pbkdf2Builder;

#[cfg(feature = "batch-ops")]
pub use batch_ops::{decrypt_batch, encrypt_batch};

pub use convert::convert_to_v3;

pub use header::read_version; // New: Quick version check
