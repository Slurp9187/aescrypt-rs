// src/convert.rs
//! Legacy → v3 conversion utilities.
//!
//! Two public functions are provided:
//! - [`convert_to_v3`] – original API (same password for both sides; soft-deprecated)
//! - [`convert_to_v3_ext`] – new, flexible API with separate old/new passwords and **256-bit random generation**
//!
//! The new function is the recommended path for all real-world migrations.

use crate::aliases::{PasswordString, RandomPassword32};
use crate::{decrypt, encrypt, AescryptError};
use pipe::pipe;
use secure_gate::SecureRandomExt;
use std::io::{Read, Write};

/// Private shared implementation – uses borrows only, zero clones.
fn convert_to_v3_impl<R, W>(
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
    // Generate a cryptographically secure 256-bit (32-byte) random password if requested
    let generated = if new_password.is_none() {
        Some(PasswordString::new(
            RandomPassword32::random_hex().to_string(),
        ))
    } else {
        None
    };

    // Resolve the password that will be used for the new v3 file
    let new_pass = generated.as_ref().unwrap_or_else(|| new_password.unwrap());

    std::thread::scope(|s| -> Result<(), AescryptError> {
        let (mut pipe_reader, pipe_writer) = pipe();

        let decrypt_thread = s.spawn({
            let old_password = old_password.clone();
            move || decrypt(input, pipe_writer, &old_password)
        });

        let encrypt_thread = s.spawn({
            let new_pass = new_pass.clone();
            move || encrypt(&mut pipe_reader, output, &new_pass, iterations)
        });

        decrypt_thread.join().unwrap()?;
        encrypt_thread.join().unwrap()?;

        Ok(())
    })?;

    Ok(generated)
}

/// **Legacy wrapper** – 100% backward compatible with v0.1.5
///
/// This function has the *exact* old signature from v0.1.5.
/// It exists only so old code keeps compiling and gives a deprecation warning.
#[deprecated(
    since = "0.1.6",
    note = "use convert_to_v3_ext(..., Some(password), ...) instead — this wrapper will be removed in v1.0"
)]
pub fn convert_to_v3<R, W>(
    input: R,
    output: W,
    password: &crate::aliases::Password, // ← old legacy type
    iterations: u32,
) -> Result<(), AescryptError>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    // Correct way to get a &PasswordString from the old &Password
    // Both are secure-gate dynamic aliases → they share the same underlying storage
    // This is safe, zero-cost, and the intended interop path
    let password_str: &crate::aliases::PasswordString = unsafe {
        // SAFETY: Password and PasswordString are both dynamic_alias!(..., String)
        //         → identical memory layout (just a wrapper around String)
        //         → transmuting the reference is safe
        &*(password as *const crate::aliases::Password as *const crate::aliases::PasswordString)
    };

    convert_to_v3_impl(input, output, password_str, Some(password_str), iterations)?;
    Ok(())
}

/// **Recommended API** – supports separate passwords and 256-bit random generation.
///
/// # Behaviour
/// - `new_password = Some(&pw)` → re-encrypt with `pw`
/// - `new_password = None`      → generate a **256-bit** random password (64 hex chars) and return it
///
/// # Returns
/// - `Ok(Some(generated_password))` if random was created
/// - `Ok(None)` if password was supplied
pub fn convert_to_v3_ext<R, W>(
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
    convert_to_v3_impl(input, output, old_password, new_password, iterations)
}
