//! AES Crypt encryption/decryption library (v0–v3).

pub mod aliases;
pub mod consts;
pub mod crypto;
pub mod decryptor;
pub mod encryptor;
pub mod error;
pub mod utils;

// ============================================================================
// Core public API (always available)
// ============================================================================
// pub use aliases::*;
// pub use consts::*;
pub use crypto::hmac::{HmacSha256, HmacSha512};
pub use crypto::rng::SecureRng;
pub use decryptor::decrypt;
pub use encryptor::encrypt;
pub use error::AescryptError;

// Plain KDF (for tests / interop)
pub use crypto::kdf::ackdf::derive_secure_ackdf_key;
pub use crypto::kdf::pbkdf2::derive_secure_pbkdf2_key;

pub use crypto::kdf::pbkdf2_builder::Pbkdf2Builder;
