// tests/deterministic_encrypt/encrypt_fixed_session.rs
// Deterministic v3 encryption – TEST ONLY
// Exactly matches the official test vectors (including CREATED_BY extension + version byte in HMAC)

use aescrypt_rs::aliases::{Aes256Key, EncryptedSessionBlock48, Iv16, PasswordString};
use aescrypt_rs::error::AescryptError;

// Public re-exports from the library
use aescrypt_rs::encryptor::{
    derive_setup_key, encrypt_session_block, encrypt_stream, write_header, write_hmac,
    write_iterations, write_public_iv,
};

use aes::cipher::KeyInit;
use aes::Aes256Enc;
use hmac::{Hmac, Mac}; // Mac needed for .update()
use sha2::Sha256;
use std::io::{Read, Write};

// Exact extension blob used in the official deterministic test vectors
const V3_CREATED_BY_EXTENSION: [u8; 29] = [
    0x00, 0x1B, b'C', b'R', b'E', b'A', b'T', b'E', b'D', b'_', b'B', b'Y', 0x00, b'a', b'e', b's',
    b'c', b'r', b'y', b'p', b't', b' ', b'4', b'.', b'0', b'.', b'0', b'.', b'0',
];

pub fn encrypt_with_fixed_session<R: Read, W: Write>(
    mut source: R,
    mut destination: W,
    password: &PasswordString,
    iterations: u32,
    public_iv: &Iv16,
    session_iv: &Iv16,
    session_key: &Aes256Key,
) -> Result<(), AescryptError> {
    // Header
    write_header(&mut destination, 3)?;

    // CREATED_BY extension + terminator (required by test vectors)
    destination.write_all(&V3_CREATED_BY_EXTENSION)?;
    destination.write_all(&[0x00, 0x00])?;

    // KDF parameters
    write_iterations(&mut destination, iterations, 3)?;
    write_public_iv(&mut destination, public_iv)?;

    // Derive setup key
    let mut setup_key = Aes256Key::new([0u8; 32]);
    derive_setup_key(password, public_iv, iterations, &mut setup_key)?;

    let cipher = Aes256Enc::new(setup_key.expose_secret().into());

    // Create HMAC – disambiguate using the Mac trait directly
    let mut session_hmac = <Hmac<Sha256> as Mac>::new_from_slice(setup_key.expose_secret())
        .expect("setup_key is exactly 32 bytes");

    // Encrypt the session block (IV + key)
    let mut enc_session_block = EncryptedSessionBlock48::new([0u8; 48]);
    encrypt_session_block(
        &cipher,
        session_iv,
        session_key,
        public_iv,
        &mut enc_session_block,
        &mut session_hmac,
    )?;

    // Official spec includes the version byte (3) in the session HMAC
    session_hmac.update(&[3]);

    // Write encrypted session + HMAC
    destination.write_all(enc_session_block.expose_secret())?;
    write_hmac(&mut destination, session_hmac)?;

    // Encrypt payload
    encrypt_stream(&mut source, &mut destination, session_iv, session_key)?;

    Ok(())
}
