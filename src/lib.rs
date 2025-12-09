#![doc = include_str!("../README.md")]

pub mod aliases;
pub mod builders;
pub mod consts;
pub mod decryption;
pub mod encryption;
pub mod error;
pub mod header;
pub mod kdf;
pub mod utils;

// High-level API — this is what 99% of users import
pub use decryption::decrypt;
pub use encryption::encrypt;
pub use error::AescryptError;
pub use aliases::PasswordString; // Core type used in every encrypt/decrypt call

// Low-level KDFs — intentionally public at the root because:
// • They are needed for custom decryption flows (e (e.g. reading v0–v2 files without the high-level API)
// • They are the only non-wrapper crypto functions users ever need directly
// • Keeping them at the root is the established pattern in the ecosystem (see `ring`, `password-hash`, etc.)
pub use builders::pbkdf2_builder::Pbkdf2Builder;

pub use kdf::ackdf::derive_ackdf_key;
pub use kdf::pbkdf2::derive_pbkdf2_key;

pub use header::read_version; // New: Quick version check
