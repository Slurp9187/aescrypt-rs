//! src/core/decryption/decrypt.rs
//! Aescrypt decryption — secure-gate perfection

use crate::decryption::read::{
    consume_all_extensions, read_exact_span, read_file_version, read_kdf_iterations,
};
use crate::decryption::session::extract_session_data;
use crate::decryption::stream::{decrypt_ciphertext_stream, StreamConfig};

use crate::aliases::{Aes256Key32, Iv16, PasswordString};
use crate::error::AescryptError;
use crate::{derive_ackdf_key, derive_pbkdf2_key};
use std::io::{Read, Write};

/// Decrypt an Aescrypt file (v0–v3) — zero secret exposure, maximum security
///
/// # Warning — Plaintext written before final payload authentication
///
/// For payloads larger than roughly two AES blocks (~32 bytes of ciphertext after the
/// session block), decrypted data is written to `output` **incrementally** as blocks are
/// processed. The payload HMAC (and v3 PKCS#7 validation) runs only after the ciphertext
/// stream has been read.
///
/// If this function returns an error—for example `"HMAC verification failed"` or a v3
/// padding error—`output` may already contain **partial, unauthenticated plaintext**.
/// Callers **must** discard or overwrite `output` on error and must not treat its
/// contents as secret or trustworthy.
///
/// ```no_run
/// use aescrypt_rs::{decrypt, PasswordString};
/// use std::io::Cursor;
///
/// # let reader = Cursor::new(vec![]);
/// # let password = PasswordString::new("pw".to_string());
/// let mut plaintext = Vec::new();
/// if decrypt(reader, &mut plaintext, &password).is_err() {
///     plaintext.clear(); // mandatory when using an accumulating buffer
/// }
/// ```
///
/// # Note — Empty password
///
/// Unlike [`encrypt`](crate::encrypt), this function does not reject an empty password.
/// An empty password against a file encrypted with a non-empty password will fail at HMAC
/// verification. This asymmetry is intentional: third-party AES Crypt tools may produce
/// files encrypted with an empty password, and `decrypt` must be able to handle them.
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
/// - ~158 MiB/s throughput for decryption
/// - Processing time scales linearly with file size
///
/// Users requiring cancellation should spawn this function in a thread and implement
/// their own cancellation mechanism (e.g., using channels or thread handles).
///
/// # Example: Threaded Usage
///
/// ```no_run
/// use aescrypt_rs::{decrypt, PasswordString};
/// use std::io::Cursor;
/// use std::thread;
///
/// let password = PasswordString::new("secret".to_string());
/// let encrypted = b"encrypted data...";
///
/// // Spawn decryption in a thread
/// let handle = thread::spawn(move || {
///     let mut plaintext = Vec::new();
///     decrypt(Cursor::new(encrypted), &mut plaintext, &password)
/// });
///
/// // Can wait for completion or implement cancellation
/// let result = handle.join().unwrap();
/// ```
#[inline(always)]
pub fn decrypt<R, W>(
    mut input: R,
    mut output: W,
    password: &PasswordString,
) -> Result<(), AescryptError>
where
    R: Read,
    W: Write,
{
    let (file_version, reserved_modulo) = read_file_version(&mut input)?;
    consume_all_extensions(&mut input, file_version)?;

    let kdf_iterations = read_kdf_iterations(&mut input, file_version)?;

    // Public IV — secure from the start
    let public_iv: Iv16 = Iv16::from(read_exact_span(&mut input)?);

    // Setup key — secure buffer from birth
    let mut setup_key = Aes256Key32::new([0u8; 32]);

    if file_version <= 2 {
        derive_ackdf_key(password, &public_iv, &mut setup_key)?;
    } else {
        derive_pbkdf2_key(password, &public_iv, kdf_iterations, &mut setup_key)?;
    }

    // Session key/IV — secure buffers from birth
    let mut session_iv = Iv16::new([0u8; 16]);
    let mut session_key = Aes256Key32::new([0u8; 32]);

    extract_session_data(
        &mut input,
        file_version,
        &public_iv,
        &setup_key,
        &mut session_iv,
        &mut session_key,
    )?;

    let stream_config = match file_version {
        0 => StreamConfig::V0 { reserved_modulo },
        1 => StreamConfig::V1,
        2 => StreamConfig::V2,
        3 => StreamConfig::V3,
        _ => unreachable!("file_version validated in read_file_version"),
    };

    decrypt_ciphertext_stream(
        &mut input,
        &mut output,
        &session_iv,
        &session_key,
        stream_config,
    )?;

    Ok(())
}
