//! # Streaming Decryption
//!
//! This module provides streaming decryption functionality for AES Crypt files.
//! It handles the decryption of ciphertext streams using a constant-memory ring buffer
//! approach for efficient processing of large files.
//!
//! ## Modules
//!
//! - [`context`] - Decryption context and ring buffer management (internal)
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

pub use versions::{decrypt_ciphertext_stream, StreamConfig};
