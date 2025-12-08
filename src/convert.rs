// src/convert.rs

use crate::aliases::{PasswordString, RandomPassword32};
use crate::{decrypt, encrypt, AescryptError};
use pipe::pipe;
// use secure_gate::SecureRandomExt;
use std::io::{Read, Write};

/// Convert legacy AES Crypt file (v0-v2) to v3 format
///
/// This function uses parallel decryption/encryption via threads for maximum performance.
/// The `'static` lifetime requirement has been removed - you can now pass owned data
/// (like `Vec<u8>`) wrapped in `Cursor` without exposing plaintext unnecessarily.
///
/// # Performance
///
/// Uses `std::thread::scope` with pipes for zero-copy streaming between threads.
/// This maintains the same "wicked fast" performance as before.
///
/// # Security
///
/// - No plaintext exposure: data stays in secure buffers during conversion
/// - Automatic password generation available (None or Some(""))
/// - All sensitive data auto-zeroized on drop
///
/// # Example
///
/// ```no_run
/// use aescrypt_rs::{convert_to_v3, aliases::PasswordString};
/// use std::io::Cursor;
///
/// let old_pw = PasswordString::new("old".to_string());
/// let new_pw = PasswordString::new("new".to_string());
/// let encrypted_data: Vec<u8> = vec![]; // Your encrypted data
///
/// let mut output = Vec::new();
/// convert_to_v3(
///     Cursor::new(encrypted_data),  // No 'static needed!
///     &mut output,
///     &old_pw,
///     Some(&new_pw),
///     300_000,
/// )?;
/// # Ok::<(), aescrypt_rs::AescryptError>(())
/// ```
pub fn convert_to_v3<R, W>(
    input: R,
    output: W,
    old_password: &PasswordString,
    new_password: Option<&PasswordString>,
    iterations: u32,
) -> Result<Option<PasswordString>, AescryptError>
where
    R: Read + Send,
    W: Write + Send,
{
    // Validate iterations upfront
    if iterations == 0 {
        return Err(AescryptError::Header(
            "KDF iterations cannot be zero".into(),
        ));
    }
    if iterations > 5_000_000 {
        return Err(AescryptError::Header(
            "KDF iterations too high (>5M)".into(),
        ));
    }

    // AUTO-GENERATE if:
    //   • new_password is None
    //   • OR new_password is Some("") — the magic "upgrade me" shortcut
    let should_generate = new_password.is_none_or(|p| p.expose_secret().is_empty());

    let generated = if should_generate {
        Some(PasswordString::new(
            // RandomPassword32::random_hex().expose_secret().clone(),
            RandomPassword32::random_hex().expose_secret().to_string(),
        ))
    } else {
        None
    };

    let new_pass = generated
        .as_ref()
        .unwrap_or_else(|| new_password.expect("new_password is Some and non-empty here"));

    // High-entropy random password → only 1 iteration needed
    // Human or legacy password → full user-specified iterations
    let effective_iters = if generated.is_some() { 1 } else { iterations };

    std::thread::scope(|s| {
        let (pipe_reader, pipe_writer) = pipe();

        let decrypt_thread = s.spawn({
            let old_password = old_password.clone();
            move || decrypt(input, pipe_writer, &old_password)
        });

        let encrypt_thread = s.spawn({
            let new_pass = new_pass.clone();
            move || encrypt(pipe_reader, output, &new_pass, effective_iters)
        });

        decrypt_thread.join().unwrap()?;
        encrypt_thread.join().unwrap()
    })?;

    Ok(generated)
}
