// src/core/encryptor/mod.rs

//! High-level encryption facade.
//!
//! Core API: `encrypt(&password, src, dst, iterations)?` for full file encryption.
//! Utility: `write_octets(writer, bytes)?` for raw writes.

pub(crate) mod encrypt;
// pub(crate) mod encrypt_fixed_session;
pub(crate) mod stream;
pub(crate) mod write;

pub use encrypt::encrypt;
// pub use encrypt_fixed_session::encrypt_with_fixed_session;
pub use stream::encrypt_stream;
pub use write::{
    derive_setup_key, encrypt_session_block, write_extensions, write_header, write_hmac,
    write_iterations, write_octets, write_public_iv,
};
