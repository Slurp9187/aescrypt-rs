//! Error types for AES Crypt operations.
//!
//! Every fallible function in this crate returns
//! [`Result<T, AescryptError>`](AescryptError). [`AescryptError`] discriminates between
//! I/O failures, cryptographic failures, header / extension parsing failures, and
//! unsupported file format versions.
//!
//! # Variant → API table
//!
//! | Variant                                | Typical producer                                                                                                                                                                                                                                                                                |
//! | -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
//! | [`AescryptError::Io`]                  | [`encrypt`], [`decrypt`], [`read_version`], every reader/writer helper in [`crate::encryption`] / [`crate::decryption`]                                                                                                                                                                        |
//! | [`AescryptError::Crypto`]              | [`derive_ackdf_key`], [`derive_pbkdf2_key`], [`Pbkdf2Builder::derive_secure`], [`utf8_to_utf16le`]                                                                                                                                                                                              |
//! | [`AescryptError::Header`]              | [`encrypt`], [`decrypt`], [`read_version`], [`derive_setup_key`], [`write_header`] / [`write_extensions`] / [`write_iterations`], [`read_file_version`], [`read_kdf_iterations`], [`consume_all_extensions`], [`extract_session_data`], [`decrypt_ciphertext_stream`] |
//! | [`AescryptError::UnsupportedVersion`]  | [`write_header`], [`write_extensions`], [`write_iterations`], [`read_file_version`]                                                                                                                                                                                                            |
//!
//! [`encrypt`]: crate::encrypt()
//! [`decrypt`]: crate::decrypt()
//! [`read_version`]: crate::read_version
//! [`derive_ackdf_key`]: crate::derive_ackdf_key
//! [`derive_pbkdf2_key`]: crate::derive_pbkdf2_key
//! [`Pbkdf2Builder::derive_secure`]: crate::Pbkdf2Builder::derive_secure
//! [`utf8_to_utf16le`]: crate::utilities::utf8_to_utf16le
//! [`derive_setup_key`]: crate::encryption::derive_setup_key
//! [`write_header`]: crate::encryption::write_header
//! [`write_extensions`]: crate::encryption::write_extensions
//! [`write_iterations`]: crate::encryption::write_iterations
//! [`read_file_version`]: crate::decryption::read_file_version
//! [`read_kdf_iterations`]: crate::decryption::read_kdf_iterations
//! [`consume_all_extensions`]: crate::decryption::consume_all_extensions
//! [`extract_session_data`]: crate::decryption::extract_session_data
//! [`decrypt_ciphertext_stream`]: crate::decryption::decrypt_ciphertext_stream

use thiserror::Error;

/// The error type returned by every fallible AES Crypt operation in this crate.
///
/// `AescryptError` is non-exhaustive in spirit: it discriminates four classes of
/// failure (I/O, cryptographic, header/format, unsupported version) but the
/// human-readable message inside [`Crypto`](Self::Crypto) and
/// [`Header`](Self::Header) is part of the error display, not the structured API,
/// and may be refined in patch releases.
///
/// # Errors
///
/// All four variants are constructed by code inside this crate; downstream callers
/// generally pattern-match on the variant and surface a friendly message based on
/// the [`Display`](std::fmt::Display) impl provided by [`thiserror`].
///
/// See the [variant → API table](self) at the module level for which public APIs
/// produce each variant.
///
/// # Security
///
/// Error messages are written for human diagnostics. They never embed the
/// password, derived keys, IVs, salts, or plaintext. Untrusted callers may safely
/// log the [`Display`](std::fmt::Display) form. Wrap-and-`?` is the recommended
/// pattern; do not attempt to recover from [`Header`](Self::Header) by retrying
/// with different inputs.
#[derive(Error, Debug)]
pub enum AescryptError {
    /// An I/O operation on the underlying reader or writer failed.
    ///
    /// This variant wraps [`std::io::Error`] verbatim and is produced by every
    /// public function that performs streaming reads or writes — including
    /// [`crate::encrypt()`], [`crate::decrypt()`], [`crate::read_version`], and
    /// the lower-level helpers in [`crate::encryption`] / [`crate::decryption`].
    /// Common causes: file not found, permission denied, broken pipe, premature
    /// EOF inside the header / session block / payload.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A cryptographic primitive returned an error.
    ///
    /// Produced by:
    ///
    /// - [`crate::derive_pbkdf2_key`] / [`crate::Pbkdf2Builder::derive_secure`]
    ///   when the underlying `pbkdf2` crate rejects its parameters.
    /// - [`crate::derive_ackdf_key`] when the password is not valid UTF-8
    ///   (forwarded from [`crate::utilities::utf8_to_utf16le`]).
    /// - [`crate::utilities::utf8_to_utf16le`] for non-UTF-8 password bytes.
    ///
    /// The wrapped `String` is a short human-readable description and is part of
    /// the [`Display`](std::fmt::Display) output only — it is not a stable
    /// machine-readable code.
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// A header, extension, or trailer in the AES Crypt file failed validation.
    ///
    /// Triggered by, for example:
    ///
    /// - Invalid magic bytes (header is not `b"AES"`).
    /// - Reserved byte after the version is not `0x00` for v1–v3.
    /// - More than 256 extension blocks in a v2/v3 header (DoS guard).
    /// - PBKDF2 iteration count outside
    ///   [`PBKDF2_MIN_ITER`](crate::constants::PBKDF2_MIN_ITER)
    ///   `..=` [`PBKDF2_MAX_ITER`](crate::constants::PBKDF2_MAX_ITER).
    /// - Empty password supplied to [`crate::encrypt()`].
    /// - Session-block HMAC mismatch ("session data corrupted or tampered").
    /// - Payload HMAC mismatch ("HMAC verification failed").
    /// - v3 PKCS#7 padding malformed ("v3: invalid PKCS#7 padding").
    /// - v0/v1/v2/v3 trailer length wrong ("expected … trailer").
    ///
    /// **Security note**: an HMAC failure is reported as `Header(...)` for
    /// historical reasons; treat it as authenticated-decryption failure and
    /// discard any plaintext already written to the output.
    #[error("Header error: {0}")]
    Header(String),

    /// The file declares an AES Crypt format version this crate cannot handle.
    ///
    /// Returned by [`crate::decryption::read_file_version`] when the version
    /// byte is `> 3`, and by the encryption-side [`crate::encryption::write_header`]
    /// / [`write_extensions`](crate::encryption::write_extensions) /
    /// [`write_iterations`](crate::encryption::write_iterations) when callers
    /// request a version `< 3` (this crate writes v3 only). The contained `u8`
    /// is the rejected version number.
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),
}

impl From<&'static str> for AescryptError {
    fn from(msg: &'static str) -> Self {
        AescryptError::Crypto(msg.to_string())
    }
}
