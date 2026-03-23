// src/encryption/encrypt.rs

//! Aescrypt encryption — secure-gate gold standard
//! Zero secret exposure, zero-cost, auto-zeroizing

use crate::aliases::PasswordString;
use crate::aliases::{Aes256Key32, EncryptedSessionBlock48, HmacSha256, Iv16};
use crate::constants::AESCRYPT_LATEST_VERSION;
use crate::constants::{PBKDF2_MAX_ITER, PBKDF2_MIN_ITER};
use crate::encryption::derive_setup_key;
use crate::encryption::encrypt_session_block;
use crate::encryption::stream::encrypt_stream;
use crate::encryption::write::{
    write_extensions, write_header, write_hmac, write_iterations, write_octets, write_public_iv,
};
use crate::error::AescryptError;
use aes::cipher::KeyInit;
use aes::Aes256Enc;
use hmac::Mac;
use secure_gate::RevealSecret;
use std::io::{Read, Write};

/// Encrypt an Aescrypt file (v3+) — zero secret exposure, maximum security
///
/// Encrypted files use the v3 format only, ensuring the highest level of security. The password must not be empty.
/// The `kdf_iterations` must be between [`crate::constants::PBKDF2_MIN_ITER`] and [`crate::constants::PBKDF2_MAX_ITER`].
///
/// # Thread Safety
///
/// This function is **thread-safe** and can be called concurrently from multiple threads.
/// All operations are pure (no shared mutable state), making it safe to:
/// - Spawn in threads for parallel processing
/// - Use with async runtimes (spawn_blocking)
/// - Implement cancellation by wrapping in a thread and joining/detaching as needed
///
/// # Performance
///
/// For large files, this operation may take significant time. In release mode, expect:
/// - ~150 MiB/s throughput for encryption
/// - Processing time scales linearly with file size
///
/// Users requiring cancellation should spawn this function in a thread and implement
/// their own cancellation mechanism (e.g., using channels or thread handles).
///
/// # Example: Threaded Usage
///
/// ```no_run
/// use aescrypt_rs::{encrypt, PasswordString};
/// use std::io::Cursor;
/// use std::thread;
///
/// let password = PasswordString::new("secret".to_string());
/// let data = b"large file data...";
///
/// // Spawn encryption in a thread
/// let handle = thread::spawn(move || {
///     let mut encrypted = Vec::new();
///     encrypt(
///         Cursor::new(data),
///         &mut encrypted,
///         &password,
///         300_000,
///     )
/// });
///
/// // Can wait for completion or implement cancellation
/// let result = handle.join().unwrap();
/// ```
#[inline(always)]
pub fn encrypt<R, W>(
    mut input: R,
    mut output: W,
    password: &PasswordString,
    kdf_iterations: u32,
) -> Result<(), AescryptError>
where
    R: Read,
    W: Write,
{
    // Validation
    if password.is_empty() {
        return Err(AescryptError::Header("empty password".into()));
    }

    if !(PBKDF2_MIN_ITER..=PBKDF2_MAX_ITER).contains(&kdf_iterations) {
        return Err(AescryptError::Header("invalid KDF iterations".into()));
    }

    write_header(&mut output, AESCRYPT_LATEST_VERSION)?;
    write_extensions(&mut output, AESCRYPT_LATEST_VERSION, None)?;

    // Generate secure random values — wrapped from birth
    let public_iv = Iv16::from_random();
    let session_iv = Iv16::from_random();
    let session_key = Aes256Key32::from_random();

    write_iterations(&mut output, kdf_iterations, AESCRYPT_LATEST_VERSION)?;
    write_public_iv(&mut output, &public_iv)?;

    // Derive setup key directly into secure buffer — zero exposure
    let mut setup_key = Aes256Key32::new([0u8; 32]);
    derive_setup_key(password, &public_iv, kdf_iterations, &mut setup_key)?;

    // Create cipher and HMAC from secure key
    let cipher = setup_key.with_secret(|key| Aes256Enc::new(key.into()));

    let mut hmac = setup_key.with_secret(|key| {
        <HmacSha256 as Mac>::new_from_slice(key)
            .expect("setup_key is always 32 bytes — valid HMAC key")
    });

    // Encrypt session block
    let mut enc_block = EncryptedSessionBlock48::new([0u8; 48]);
    encrypt_session_block(
        &cipher,
        &session_iv,
        &session_key,
        &public_iv,
        &mut enc_block,
        &mut hmac,
    )?;

    // Include version byte in HMAC (v3+)
    hmac.update(&[AESCRYPT_LATEST_VERSION]);

    enc_block.with_secret(|eb| write_octets(&mut output, eb))?;
    write_hmac(&mut output, hmac)?; // hmac moved here — correct

    // Final stream encryption
    encrypt_stream(&mut input, &mut output, &session_iv, &session_key)?;

    Ok(())
}
