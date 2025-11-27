//! src/core/encryptor/encrypt_fixed_session.rs
//! Deterministic AES Crypt v3 encryption with fixed session key/IV (for testing/fuzzing)
//! secure-gate v0.5.5+ gold standard (2025)

use crate::aliases::{Aes256Key, EncryptedSessionBlock48, Iv16, Password};
use crate::consts::{AESCRYPT_LATEST_VERSION, PBKDF2_MAX_ITER, PBKDF2_MIN_ITER};
use crate::encryptor::stream::encrypt_stream;
use crate::encryptor::write::{
    derive_setup_key, encrypt_session_block, write_header, write_hmac, write_iterations,
    write_octets, write_public_iv,
};
use crate::error::AescryptError;
use crate::HmacSha256;
use aes::cipher::KeyInit;
use aes::Aes256Enc;
use hmac::Mac;
use std::io::{Read, Write};

// Exact official extension blob used by AES Crypt 4.0.0
pub(crate) const V3_CREATED_BY_EXTENSION: [u8; 29] = [
    0x00, 0x1B, b'C', b'R', b'E', b'A', b'T', b'E', b'D', b'_', b'B', b'Y', 0x00, b'a', b'e', b's',
    b'c', b'r', b'y', b'p', b't', b' ', b'4', b'.', b'0', b'.', b'0', b'.', b'0',
];

/// Encrypt plaintext → AES Crypt v3 stream with **fixed** session IV/key
/// Used for deterministic testing and fuzzing
#[inline(always)]
pub fn encrypt_with_fixed_session<R, W>(
    mut input: R,
    mut output: W,
    password: &Password,
    kdf_iterations: u32,
    public_iv: &Iv16,
    session_iv: &Iv16,
    session_key: &Aes256Key,
) -> Result<(), AescryptError>
where
    R: Read,
    W: Write,
{
    // Validation
    if password.expose_secret().is_empty() {
        return Err(AescryptError::Header("empty password".into()));
    }
    if !(PBKDF2_MIN_ITER..=PBKDF2_MAX_ITER).contains(&kdf_iterations) {
        return Err(AescryptError::Header("invalid KDF iterations".into()));
    }

    // === Header ===
    write_header(&mut output, AESCRYPT_LATEST_VERSION)?;

    // === Extensions: official CREATED_BY + terminator ===
    output.write_all(&V3_CREATED_BY_EXTENSION)?;
    output.write_all(&[0x00, 0x00])?;

    // === KDF parameters + public IV ===
    write_iterations(&mut output, kdf_iterations, AESCRYPT_LATEST_VERSION)?;
    write_public_iv(&mut output, public_iv)?;

    // === Derive setup key directly into secure buffer ===
    let mut setup_key = Aes256Key::new([0u8; 32]);
    derive_setup_key(password, public_iv, kdf_iterations, &mut setup_key)?;

    // === Create cipher and HMAC ===
    let cipher = Aes256Enc::new(setup_key.expose_secret().into());
    let mut hmac = <HmacSha256 as Mac>::new_from_slice(setup_key.expose_secret())
        .expect("setup_key is 32 bytes — valid HMAC key");

    // === Encrypt session block ===
    let mut enc_block = EncryptedSessionBlock48::new([0u8; 48]);
    encrypt_session_block(
        &cipher,
        session_iv,
        session_key,
        public_iv,
        &mut enc_block,
        &mut hmac,
    )?;

    // v3+ includes version byte in HMAC
    hmac.update(&[AESCRYPT_LATEST_VERSION]);

    // === Write session block + HMAC ===
    write_octets(&mut output, enc_block.expose_secret())?;
    write_hmac(&mut output, hmac)?; // hmac moved — correct

    // === Final stream encryption ===
    encrypt_stream(&mut input, &mut output, session_iv, session_key)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aliases::Password;
    use crate::{decrypt, encrypt};
    use std::io::Cursor;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"Hello, AES Crypt!";
        let password = Password::new("testpass".to_string());
        let iterations = 1000u32;

        let mut encrypted = Vec::new();
        encrypt(
            Cursor::new(plaintext),
            &mut encrypted,
            &password,
            iterations,
        )
        .unwrap();

        let mut decrypted = Vec::new();
        decrypt(Cursor::new(&encrypted), &mut decrypted, &password).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_fixed_session_deterministic() {
        let public_iv = Iv16::from([0x01; 16]);
        let session_iv = Iv16::from([0x02; 16]);
        let password = Password::new("secret".to_string());
        let session_key = Aes256Key::from([0x03; 32]);

        let mut output1 = Vec::new();
        let mut output2 = Vec::new();

        // FIXED: password first, then iterations
        encrypt_with_fixed_session(
            Cursor::new(b"hello"),
            &mut output1,
            &password, // ← now correct
            1000,      // ← now correct
            &public_iv,
            &session_iv,
            &session_key,
        )
        .unwrap();

        // This one was already correct
        encrypt_with_fixed_session(
            Cursor::new(b"hello"),
            &mut output2,
            &password,
            1000,
            &public_iv,
            &session_iv,
            &session_key,
        )
        .unwrap();

        assert_eq!(output1, output2);
    }
}
