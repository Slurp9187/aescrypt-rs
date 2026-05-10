// src/encryption/encrypt.rs

//! High-level [`encrypt`] entry point: streams plaintext to an AES Crypt v3 file.

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

/// Encrypts the bytes read from `input` into a complete AES Crypt v3 file
/// written to `output`.
///
/// `encrypt` consumes `input` until EOF and writes a self-contained `.aes`
/// file: header, extensions terminator, iteration count, public IV, encrypted
/// session block, session HMAC, ciphertext stream, and payload HMAC. The
/// session key, session IV, and public IV are freshly generated from the
/// [`secure-gate`] CSPRNG on every call; the same `(password, plaintext,
/// iterations)` tuple therefore produces a different ciphertext every time.
///
/// # Format
///
/// Always v3. To produce v0/v1/v2 files, use the official `aescrypt` reference
/// tooling — this crate intentionally does not support legacy formats on
/// write (see the [crate-level Security Model](crate#security-model)).
///
/// # Errors
///
/// - [`AescryptError::Header`] — `password` is empty, or `kdf_iterations` is
///   outside [`PBKDF2_MIN_ITER`](crate::constants::PBKDF2_MIN_ITER) `..=`
///   [`PBKDF2_MAX_ITER`](crate::constants::PBKDF2_MAX_ITER).
/// - [`AescryptError::Crypto`] — PBKDF2 setup-key derivation failed (forwarded
///   from [`crate::derive_pbkdf2_key`]).
/// - [`AescryptError::Io`] — `input.read` or `output.write_all` returned an
///   error at any stage of header serialization or payload streaming.
///
/// # Panics
///
/// Never panics on valid input; the internal `expect` on `setup_key` is a
/// 32-byte invariant that is structurally guaranteed by
/// [`Aes256Key32`](crate::aliases::Aes256Key32).
///
/// # Security
///
/// - All secrets ([`PasswordString`], session key, session IV, setup key) live
///   in [`secure-gate`] wrappers and zeroize on drop. Plaintext blocks
///   transit the stack inside [`Block16`](crate::aliases::Block16) for the
///   same reason.
/// - The public IV doubles as the PBKDF2 salt; it is generated with
///   `Iv16::from_random` per call and is therefore unique with overwhelming
///   probability.
/// - HMAC-SHA256 is computed over the encrypted session block (with the v3
///   version byte appended) and over the ciphertext stream. Decryption verifies
///   both with constant-time equality.
/// - PKCS#7 padding is always applied to the final plaintext block.
/// - `kdf_iterations` controls password-cracking cost. Use
///   [`DEFAULT_PBKDF2_ITERATIONS`](crate::constants::DEFAULT_PBKDF2_ITERATIONS)
///   unless you have measured your platform.
///
/// # Compatibility
///
/// - Output is byte-compatible with the official AES Crypt reference
///   implementation for v3 files.
/// - Files produced by this function are accepted by [`crate::decrypt()`] and
///   by `aescrypt`'s C/.NET/Java tooling.
///
/// # Thread Safety
///
/// `encrypt` is `Send` whenever its `R`/`W` are. There is no shared mutable
/// state, so multiple threads may call `encrypt` concurrently on independent
/// inputs/outputs. Cancellation is the caller's responsibility — spawn in a
/// thread and abandon the join handle, or wire up an interruptible reader/writer.
///
/// # Examples
///
/// ```no_run
/// use aescrypt_rs::{encrypt, PasswordString, constants::DEFAULT_PBKDF2_ITERATIONS};
/// use std::io::Cursor;
///
/// let password = PasswordString::new("correct horse battery staple".to_string());
/// let plaintext = b"top secret";
///
/// let mut ciphertext = Vec::new();
/// encrypt(Cursor::new(plaintext), &mut ciphertext, &password, DEFAULT_PBKDF2_ITERATIONS)?;
/// # Ok::<(), aescrypt_rs::AescryptError>(())
/// ```
///
/// Threaded usage:
///
/// ```no_run
/// use aescrypt_rs::{encrypt, PasswordString};
/// use std::io::Cursor;
/// use std::thread;
///
/// let password = PasswordString::new("secret".to_string());
/// let data = b"large file data...";
///
/// let handle = thread::spawn(move || {
///     let mut encrypted = Vec::new();
///     encrypt(Cursor::new(data), &mut encrypted, &password, 300_000)
/// });
///
/// let _result = handle.join().unwrap();
/// ```
///
/// # See also
///
/// - [`crate::decrypt()`] — inverse operation.
/// - [`crate::Pbkdf2Builder`] — convenient way to derive a PBKDF2 key for
///   custom flows.
///
/// [`secure-gate`]: https://github.com/Slurp9187/secure-gate
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
