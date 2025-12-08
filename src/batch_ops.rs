//! # Batch Operations
//!
//! This module provides parallel batch encryption and decryption operations using [`rayon`].
//! These functions are only available when the `batch-ops` feature is enabled.
//!
//! Batch operations process multiple files in parallel, significantly improving throughput
//! when encrypting or decrypting large numbers of files.
//!
//! # Requirements
//!
//! - The `batch-ops` feature must be enabled
//! - All readers and writers must implement `Send` (required for parallel processing)
//!
//! # Performance
//!
//! Batch operations automatically scale to use all available CPU cores. The actual speedup
//! depends on the number of files, file sizes, and system resources.

#[cfg(feature = "batch-ops")]
use rayon::prelude::*;
#[cfg(feature = "batch-ops")]
use std::io::{Read, Write};

#[cfg(feature = "batch-ops")]
use crate::aliases::PasswordString;
#[cfg(feature = "batch-ops")]
use crate::{decrypt, encrypt, AescryptError};

/// Encrypt multiple files in parallel.
///
/// This function processes all files in the batch concurrently, using all available
/// CPU cores for maximum throughput.
///
/// # Arguments
///
/// * `batch` - A mutable slice of `(reader, writer)` tuples, where each tuple represents
///   one file to encrypt. The reader provides the plaintext, and the writer receives
///   the encrypted output.
/// * `password` - The password to use for encryption (same for all files)
/// * `iterations` - PBKDF2 iteration count (same for all files)
///
/// # Returns
///
/// Returns `Ok(())` if all files were encrypted successfully, or the first error
/// encountered if any file fails.
///
/// # Errors
///
/// Returns the first [`AescryptError`] encountered during encryption. If one file fails,
/// the function returns immediately without processing remaining files.
///
/// # Example
///
/// ```no_run
/// use aescrypt_rs::{batch_ops::encrypt_batch, aliases::PasswordString};
/// use std::io::Cursor;
///
/// let password = PasswordString::new("secret".to_string());
/// let mut batch = vec![
///     (Cursor::new(b"file1"), Vec::new()),
///     (Cursor::new(b"file2"), Vec::new()),
///     (Cursor::new(b"file3"), Vec::new()),
/// ];
///
/// encrypt_batch(&mut batch, &password, 300_000)?;
/// // All files are now encrypted in parallel
/// # Ok::<(), aescrypt_rs::AescryptError>(())
/// ```
#[cfg(feature = "batch-ops")]
pub fn encrypt_batch<R, W>(
    batch: &mut [(R, W)],
    password: &PasswordString,
    iterations: u32,
) -> Result<(), AescryptError>
where
    R: Read + Send,
    W: Write + Send,
{
    batch
        .par_iter_mut()
        .try_for_each(|(src, dst)| encrypt(src, dst, password, iterations))
}

/// Decrypt multiple files in parallel.
///
/// This function processes all files in the batch concurrently, using all available
/// CPU cores for maximum throughput.
///
/// # Arguments
///
/// * `batch` - A mutable slice of `(reader, writer)` tuples, where each tuple represents
///   one file to decrypt. The reader provides the encrypted data, and the writer receives
///   the decrypted plaintext.
/// * `password` - The password to use for decryption (same for all files)
///
/// # Returns
///
/// Returns `Ok(())` if all files were decrypted successfully, or the first error
/// encountered if any file fails.
///
/// # Errors
///
/// Returns the first [`AescryptError`] encountered during decryption. If one file fails,
/// the function returns immediately without processing remaining files.
///
/// # Example
///
/// ```no_run
/// use aescrypt_rs::{batch_ops::decrypt_batch, aliases::PasswordString};
/// use std::io::Cursor;
///
/// let password = PasswordString::new("secret".to_string());
/// let encrypted_file1 = b"encrypted data 1";
/// let encrypted_file2 = b"encrypted data 2";
/// let encrypted_file3 = b"encrypted data 3";
/// let mut batch = vec![
///     (Cursor::new(&encrypted_file1[..]), Vec::new()),
///     (Cursor::new(&encrypted_file2[..]), Vec::new()),
///     (Cursor::new(&encrypted_file3[..]), Vec::new()),
/// ];
///
/// decrypt_batch(&mut batch, &password)?;
/// // All files are now decrypted in parallel
/// # Ok::<(), aescrypt_rs::AescryptError>(())
/// ```
#[cfg(feature = "batch-ops")]
pub fn decrypt_batch<R, W>(batch: &mut [(R, W)], password: &PasswordString) -> Result<(), AescryptError>
where
    R: Read + Send,
    W: Write + Send,
{
    batch
        .par_iter_mut()
        .try_for_each(|(src, dst)| decrypt(src, dst, password))
}
