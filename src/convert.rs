//! src/convert.rs
//! Lossless conversion from legacy v0/v1/v2 → modern v3 format
//! Uses only the existing, fully-tested high-level decrypt + encrypt APIs
//! Streams directly from decryptor into encryptor via an in-memory pipe.

use crate::aliases::Password;
use crate::{decrypt, encrypt, AescryptError};
use std::io::{Read, Write};
use std::{panic, thread};

use std::io::{self, Cursor};

/// Convert any AES Crypt v0/v1/v2 file → modern v3 format
///
/// - Streaming pipeline: legacy → plaintext → v3, with no extra user-space buffering
/// - Bit-perfect content preservation (guaranteed by round-trip tests)
/// - Uses only existing, audited code paths
pub fn convert_to_v3<R, W>(
    input: R,
    output: W,
    password: &Password,
    iterations: u32,
) -> Result<(), AescryptError>
where
    R: Read,
    W: Write + Send + 'static,
{
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

/// Convenience: convert legacy v0/v1/v2 to v3 and return owned Vec<u8>
/// Avoids the 'static lifetime pain in tests while keeping the original API intact
pub fn convert_to_v3_to_vec<R: Read + Send + 'static>(
    reader: R,
    password: &Password,
    iterations: u32,
) -> Result<Vec<u8>, AescryptError> {
    let mut output = Vec::new();

    thread::scope(|s| {
        let password_enc = password.clone();
        let mut pipe_reader = {
            let (pipe_reader, pipe_writer) = pipe::pipe();
            let input = reader;

            // Decryption thread
            s.spawn(move || decrypt(input, pipe_writer, password));

            pipe_reader
        };

        // Encryption happens on this thread
        encrypt(&mut pipe_reader, &mut output, &password_enc, iterations)
    })?;

    Ok(output)
}
