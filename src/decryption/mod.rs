// src/core/decryption/mod.rs

//! AES Crypt v0–v3 decryption surface.
//!
//! [`decrypt()`] is the high-level entry point and handles every supported
//! format version. The lower-level helpers — header parsing, extension
//! consumption, session-block recovery, and the streaming CBC loop — are
//! exposed so that callers integrating with custom containers can drive each
//! stage themselves.
//!
//! # Compatibility
//!
//! | Stage                 | v0  | v1  | v2  | v3  |
//! | --------------------- | :-: | :-: | :-: | :-: |
//! | [`read_file_version`] |  Y  |  Y  |  Y  |  Y  |
//! | [`consume_all_extensions`] | n/a | n/a | Y | Y |
//! | [`read_kdf_iterations`] | n/a | n/a | n/a | Y |
//! | [`extract_session_data`] | identity | encrypted | encrypted | encrypted+v3-tag |
//! | [`decrypt_ciphertext_stream`] | [`StreamConfig::V0`] | [`StreamConfig::V1`] | [`StreamConfig::V2`] | [`StreamConfig::V3`] |
//!
//! # Security
//!
//! See [`decrypt()`] for the **decrypt-then-verify** caveat: the v3 payload
//! HMAC is checked only after the ciphertext stream has been processed, so
//! partial unauthenticated plaintext may be written to the output before an
//! error is returned. Callers must discard or overwrite the output on error.

pub(crate) mod decrypt;
pub(crate) mod read;
pub(crate) mod session;
pub(crate) mod stream;

pub use decrypt::decrypt;
pub use read::{consume_all_extensions, read_exact_span, read_file_version, read_kdf_iterations};
pub use session::extract_session_data;
pub use stream::{decrypt_ciphertext_stream, StreamConfig};
