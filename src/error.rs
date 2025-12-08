//! # Error Types
//!
//! This module defines the error types used throughout the library.
//! All operations return [`Result<T, AescryptError>`](AescryptError) for comprehensive error handling.

use thiserror::Error;

/// The error type for all AES Crypt operations.
///
/// This enum covers I/O errors, cryptographic errors, header parsing errors,
/// and version compatibility issues.
#[derive(Error, Debug)]
pub enum AescryptError {
    /// I/O error occurred during file operations.
    ///
    /// This variant wraps [`std::io::Error`] and is automatically created
    /// when I/O operations fail (e.g., file not found, read/write errors).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Cryptographic operation failed.
    ///
    /// This variant is used for errors in cryptographic operations such as:
    /// - KDF derivation failures
    /// - Invalid password encoding
    /// - HMAC verification failures
    /// - Other cryptographic errors
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Header parsing or validation error.
    ///
    /// This variant is used for errors related to AES Crypt file headers:
    /// - Invalid magic bytes
    /// - Invalid version byte
    /// - Invalid reserved byte
    /// - Invalid KDF iteration count
    /// - Missing or corrupted header data
    #[error("Header error: {0}")]
    Header(String),

    /// Unsupported AES Crypt file version.
    ///
    /// This variant is returned when attempting to read a file with a version
    /// that is not supported (currently only versions 0-3 are supported).
    /// The contained value is the unsupported version number.
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),
}

impl From<&'static str> for AescryptError {
    fn from(msg: &'static str) -> Self {
        AescryptError::Crypto(msg.to_string())
    }
}
