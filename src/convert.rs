//! src/convert.rs
//! Lossless conversion from legacy v0/v1/v2 → modern v3 format
//! Uses only the existing, fully-tested high-level decrypt + encrypt APIs
//! Streams directly from decryptor into encryptor via an in-memory pipe.

use crate::aliases::Password;
use crate::{decrypt, encrypt, AescryptError};
use std::io::{Read, Write};
use std::{panic, thread};

/// Convert any AES Crypt v0/v1/v2 file → modern v3 format
///
/// - Streaming pipeline: legacy → plaintext → v3, with no extra user-space buffering
/// - Bit-perfect content preservation (guaranteed by round-trip tests)
/// - Uses only existing, audited code paths
pub fn convert_to_v3<R: Read, W: Write + Send + 'static>(
    input: R,
    output: W,
    password: &Password,
    iterations: u32,
) -> Result<(), AescryptError> {
    // In-memory pipe: decryptor writes → encryptor reads
    let (pipe_reader, pipe_writer) = pipe::pipe();

    // Spawn encryption thread: reads from pipe, writes v3 to `output`
    let password_enc = password.clone();
    let encrypt_handle =
        thread::spawn(move || encrypt(pipe_reader, output, &password_enc, iterations));

    // Decrypt on the calling thread, streaming directly into the pipe.
    // Dropping `pipe_writer` (on return) closes the pipe so the encryptor sees EOF.
    let decrypt_result = decrypt(input, pipe_writer, password);

    // Wait for encryption to finish, handling possible panics explicitly.
    let encrypt_result = match encrypt_handle.join() {
        Ok(res) => res,
        Err(panic_payload) => {
            // Propagate the panic to the caller rather than silently unwrapping.
            panic::resume_unwind(panic_payload);
        }
    };

    // If decryption failed, return that error; otherwise return encryption result.
    decrypt_result?;
    encrypt_result
}
