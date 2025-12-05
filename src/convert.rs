//! src/convert.rs
//! Legacy → v3 conversion utilities
//!
//! Only **one** public function remains:
//! - `convert_to_v3` – the modern, flexible API with separate old/new passwords and **256-bit random generation**
//!
//! The old `convert_to_v3` has been removed entirely (was soft-deprecated since 0.1.6).

use crate::aliases::{PasswordString, RandomPassword32};
use crate::{decrypt, encrypt, AescryptError};
use pipe::pipe;
use secure_gate::SecureRandomExt;
use std::io::{Read, Write};

/// Convert any legacy v0–v2 file → modern v3
///
/// # Features
/// - Supports **separate old & new passwords**  
/// - `new_password = None` → generates a **256-bit (64 hex char) random password** and returns it  
/// - Streaming, constant memory, fully parallel (decrypt + encrypt in separate threads)
///
/// # Returns
/// - `Ok(Some(generated))` if a random password was created
/// - `Ok(None)` if a password was supplied
pub fn convert_to_v3<R, W>(
    input: R,
    output: W,
    old_password: &PasswordString,
    new_password: Option<&PasswordString>,
    iterations: u32,
) -> Result<Option<PasswordString>, AescryptError>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
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
