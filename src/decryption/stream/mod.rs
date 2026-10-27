//! # Streaming Decryption
//!
//! This module provides streaming decryption functionality for AES Crypt files.
//! It decrypts ciphertext streams in constant memory, a span of up to 64 KiB at a
//! time, holding back the trailer until the input ends.
//!
//! ## Modules
//!
//! - [`context`] - Decryption context: span framing and CBC decryption (internal)
//! - [`trailer`] - HMAC trailer extraction and final block writing (internal)
//! - [`versions`] - Version-specific decryption logic and configuration
//!
//! ## Public API
//!
//! - [`decrypt_ciphertext_stream`] - Main streaming decryption function
//! - [`StreamConfig`] - Configuration for different AES Crypt versions

pub(crate) mod context;
pub(crate) mod trailer;
pub(crate) mod versions;

pub use versions::{StreamConfig, decrypt_ciphertext_stream};
pub(crate) use versions::{decrypt_verified_stream, verify_ciphertext_stream};
