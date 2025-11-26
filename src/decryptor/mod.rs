// src/core/decryptor/mod.rs

//! High-level decryption facade.
//!
//! Core API: `decrypt(password, input, output)?` for full file handling.
//! Helpers: `read_file_version`, `extract_session_data`, `StreamConfig` for custom flows.

pub(crate) mod decrypt;
pub(crate) mod read;
pub(crate) mod session;
pub(crate) mod stream;

pub use decrypt::decrypt;
pub use read::{
    consume_all_extensions, read_exact_span, read_file_version, read_kdf_iterations,
    read_reserved_modulo_byte,
};
pub use session::extract_session_data;
pub use stream::{decrypt_ciphertext_stream, StreamConfig};
