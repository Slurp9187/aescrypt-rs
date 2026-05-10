// src/core/encryption/mod.rs

//! AES Crypt v3 encryption surface.
//!
//! This crate writes the AES Crypt v3 format only; v0–v2 are not supported on
//! the write side. The high-level entry point is [`encrypt()`], which composes
//! every helper exposed here into a complete `.aes` file. The lower-level
//! pieces are public so that callers integrating with custom containers
//! (mmap'd files, framed network protocols, etc.) can drive each stage
//! themselves.
//!
//! # Layout of a v3 file
//!
//! ```text
//! +----------------------------------+
//! | "AES" 0x03 0x00                  |  write_header
//! | extensions (0x00 0x00 to end)    |  write_extensions
//! | iterations (4 BE bytes)          |  write_iterations
//! | public IV (16 bytes)             |  write_public_iv
//! | encrypted session block (48 B)   |  encrypt_session_block + write_octets
//! | session HMAC (32 bytes)          |  write_hmac
//! | ciphertext stream + payload HMAC |  encrypt_stream
//! +----------------------------------+
//! ```
//!
//! # Security
//!
//! See the [crate-level Security Model](crate#security-model) for the
//! full primitive list. Briefly: AES-256-CBC + HMAC-SHA256 over the encrypted
//! session block and ciphertext, PBKDF2-HMAC-SHA512 for password hardening,
//! [`secure-gate`]-managed memory for every secret. Random IVs and session
//! keys come from the [`secure-gate`] CSPRNG.
//!
//! [`secure-gate`]: https://github.com/Slurp9187/secure-gate

pub(crate) mod encrypt;
pub(crate) mod session;
pub(crate) mod stream;
pub(crate) mod write;

pub use encrypt::encrypt;
pub use session::{derive_setup_key, encrypt_session_block};
pub use stream::encrypt_stream;
pub use write::{
    write_extensions, write_header, write_hmac, write_iterations, write_octets, write_public_iv,
};
