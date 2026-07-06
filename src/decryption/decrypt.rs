//! src/core/decryption/decrypt.rs
//! High-level [`decrypt`] entry point: streams an AES Crypt v0–v3 file to plaintext.

use crate::decryption::read::{
    consume_all_extensions, read_exact_span, read_file_version, read_kdf_iterations,
};
use crate::decryption::session::extract_session_data;
use crate::decryption::stream::{decrypt_ciphertext_stream, StreamConfig};

use crate::aliases::{Aes256Key32, Iv16, PasswordString};
use crate::error::AescryptError;
use crate::{derive_ackdf_key, derive_pbkdf2_key};
use std::io::{Read, Write};

/// Decrypts an AES Crypt v0–v3 file streamed from `input` and writes the
/// recovered plaintext to `output`.
///
/// `decrypt` parses the header (auto-detecting the format version), derives
/// the setup key (PBKDF2-HMAC-SHA512 for v3, ACKDF-SHA-256 for v0/v1/v2),
/// recovers the session IV/key, and runs the version-appropriate streaming
/// CBC loop. Only the version dispatched at the top of the function is
/// observable on output — the internal `StreamConfig` mapping is mediated by
/// [`crate::decryption::decrypt_ciphertext_stream`].
///
/// # Format
///
/// - v0: legacy modulo padding, 32-byte trailing HMAC, ACKDF setup key.
/// - v1/v2: scattered modulo + 32-byte HMAC, ACKDF setup key.
/// - v3: PKCS#7 padding, 32-byte HMAC, PBKDF2-HMAC-SHA512 setup key, version
///   byte folded into the session HMAC.
///
/// See [`crate::decryption`] for the full per-stage compatibility matrix.
///
/// # Errors
///
/// - [`AescryptError::Io`] — `input.read` or `output.write_all` returned an
///   I/O error.
/// - [`AescryptError::Header`] — invalid magic, non-zero v1–v3 reserved byte,
///   too many extensions, malformed iteration count, session-HMAC mismatch
///   (`"session data corrupted or tampered"`), payload-HMAC mismatch
///   (`"HMAC verification failed"`), or invalid v3 PKCS#7 padding.
/// - [`AescryptError::UnsupportedVersion`] — version byte is `> 3`.
/// - [`AescryptError::Crypto`] — KDF failure (PBKDF2 or ACKDF, including
///   non-UTF-8 password bytes for v0–v2).
///
/// # Panics
///
/// Never panics on valid or malformed input. The internal `unreachable!` is
/// guarded by [`crate::decryption::read_file_version`], which clamps the
/// version to `0..=3`.
///
/// # Security
///
/// **Decrypt-then-verify**. For payloads larger than roughly two AES blocks
/// (≈32 bytes of ciphertext after the session block), decrypted data is
/// written to `output` **incrementally** as blocks are processed. The payload
/// HMAC and v3 PKCS#7 validation run only after the ciphertext stream has been
/// read.
///
/// If this function returns an error — for example
/// `"HMAC verification failed"` or a v3 padding error — `output` may already
/// contain **partial, unauthenticated plaintext**. Callers **must** discard or
/// overwrite `output` on error and must not treat its contents as secret or
/// trustworthy.
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
/// Other security properties:
///
/// - Setup, session, and intermediate keys live in [`secure-gate`] aliases and
///   zeroize on drop. The [`PasswordString`] never appears in plain form
///   outside scoped reveals.
/// - HMAC and PKCS#7 padding are compared in constant time
///   (`secure-gate`'s `ConstantTimeEq`).
/// - Pre-authentication parsing is bounded: the header has fixed sizes,
///   extensions are capped at 256 entries, and the iteration count is clamped
///   to [`PBKDF2_MAX_ITER`](crate::constants::PBKDF2_MAX_ITER).
/// - **v0–v2 length malleability (inherent to the legacy format)**: the
///   final-block length ("modulo") byte — the 5th header byte for v0, the
///   trailer byte for v1/v2 — is **not** covered by any HMAC in the original
///   AES Crypt wire format, so this crate cannot authenticate it. An attacker
///   who alters that byte can silently truncate or extend the final plaintext
///   block by up to 15 bytes without failing verification. v3 is immune: its
///   plaintext length comes from PKCS#7 padding inside the authenticated
///   ciphertext.
///
/// # Compatibility — empty password
///
/// Unlike [`crate::encrypt()`], this function does not reject an empty
/// password. An empty password against a file encrypted with a non-empty
/// password will fail at HMAC verification. This asymmetry is intentional:
/// third-party AES Crypt tools may produce files encrypted with an empty
/// password, and `decrypt` must be able to handle them.
///
/// # Thread Safety
///
/// `decrypt` is `Send` whenever its `R`/`W` are. There is no shared mutable
/// state, so multiple threads may call `decrypt` concurrently on independent
/// inputs/outputs.
///
/// # Examples
///
/// ```no_run
/// use aescrypt_rs::{decrypt, PasswordString};
/// use std::io::Cursor;
///
/// let password = PasswordString::new("secret".to_string());
/// let ciphertext: &[u8] = b""; // contents of a .aes file
///
/// let mut plaintext = Vec::new();
/// match decrypt(Cursor::new(ciphertext), &mut plaintext, &password) {
///     Ok(()) => { /* plaintext is now authenticated */ }
///     Err(_) => plaintext.clear(),
/// }
/// ```
///
/// Threaded usage:
///
/// ```no_run
/// use aescrypt_rs::{decrypt, PasswordString};
/// use std::io::Cursor;
/// use std::thread;
///
/// let password = PasswordString::new("secret".to_string());
/// let encrypted = b"encrypted data...";
///
/// let handle = thread::spawn(move || {
///     let mut plaintext = Vec::new();
///     decrypt(Cursor::new(encrypted), &mut plaintext, &password)
/// });
///
/// let _result = handle.join().unwrap();
/// ```
///
/// # See also
///
/// - [`crate::encrypt()`] — inverse operation.
/// - [`crate::read_version`] — header-only version triage.
///
/// [`secure-gate`]: https://github.com/Slurp9187/secure-gate
/// [`PasswordString`]: crate::PasswordString
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
    let public_iv: Iv16 = read_exact_span(&mut input)?;

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
