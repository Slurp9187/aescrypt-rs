//! src/core/decryption/decrypt.rs
//! High-level [`decrypt`] entry point: streams an AES Crypt v0–v3 file to plaintext.

use crate::decryption::read::{
    consume_all_extensions, read_exact_span, read_file_version, read_kdf_iterations,
};
use crate::decryption::session::extract_session_data;
use crate::decryption::stream::{
    StreamConfig, decrypt_ciphertext_stream, decrypt_verified_stream, verify_ciphertext_stream,
};

use crate::aliases::{Aes256Key32, Iv16};
use crate::error::AescryptError;
use crate::{derive_ackdf_key, derive_pbkdf2_key};
use std::io::{Read, Seek, SeekFrom, Write};

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
/// - [`AescryptError::Crypto`] — KDF failure (PBKDF2 or ACKDF). The ACKDF
///   non-UTF-8 password variant is structurally unreachable now that
///   `password` is a `&str`.
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
/// ```
/// use aescrypt_rs::decrypt;
/// use std::io::Cursor;
///
/// # let reader = Cursor::new(vec![]);
/// # let password = "pw";
/// let mut plaintext = Vec::new();
/// if decrypt(reader, &mut plaintext, password).is_err() {
///     plaintext.clear(); // mandatory when using an accumulating buffer
/// }
/// ```
///
/// Other security properties:
///
/// - Setup, session, and intermediate keys live in [`secure-gate`] aliases and
///   zeroize on drop.
/// - `password` is a plain `&str` **borrow**: it is forwarded to the KDF and
///   read in place, never copied and never stored, so **zeroizing the
///   password is the caller's responsibility**. Keep it in a zeroize-on-drop
///   container and pass a scoped borrow — see the examples below.
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
/// Keeping the secret wrapped in this crate's
/// [`PasswordString`](crate::aliases::PasswordString):
///
/// ```
/// use aescrypt_rs::{decrypt, aliases::PasswordString};
/// use secure_gate::RevealSecret;
/// use std::io::Cursor;
///
/// let secret = PasswordString::new("secret".to_string());
/// let ciphertext: &[u8] = b""; // contents of a .aes file
/// let mut plaintext = Vec::new();
///
/// // caller keeps the secret wrapped; the borrow never escapes
/// match secret.with_secret(|pw| decrypt(Cursor::new(ciphertext), &mut plaintext, pw)) {
///     Ok(()) => { /* plaintext is now authenticated */ }
///     Err(_) => plaintext.clear(),
/// }
/// ```
///
/// Threaded usage — the borrow is confined to the scoped thread, so the
/// secret stays wrapped in the parent frame and still zeroizes on drop:
///
/// ```
/// use aescrypt_rs::{decrypt, aliases::PasswordString};
/// use secure_gate::RevealSecret;
/// use std::io::Cursor;
///
/// let secret = PasswordString::new("secret".to_string());
/// let encrypted = b"encrypted data...";
///
/// let result = std::thread::scope(|s| {
///     let handle = s.spawn(|| {
///         let mut plaintext = Vec::new();
///         secret.with_secret(|pw| decrypt(Cursor::new(encrypted), &mut plaintext, pw))
///     });
///     handle.join().unwrap()
/// });
///
/// let _ = result;
/// ```
///
/// # See also
///
/// - [`crate::encrypt()`] — inverse operation.
/// - [`crate::read_version`] — header-only version triage.
///
/// [`secure-gate`]: https://github.com/Slurp9187/secure-gate
#[inline(always)]
pub fn decrypt<R, W>(mut input: R, mut output: W, password: &str) -> Result<(), AescryptError>
where
    R: Read,
    W: Write,
{
    let session = open_session(&mut input, password)?;

    decrypt_ciphertext_stream(
        &mut input,
        &mut output,
        &session.session_iv,
        &session.session_key,
        session.stream_config(),
    )?;

    Ok(())
}

/// Decrypts an AES Crypt v0–v3 file from a seekable `input`, checking the
/// payload HMAC **before** any plaintext reaches `output`.
///
/// AES Crypt authenticates the ciphertext (encrypt-then-MAC), so this reads
/// the payload twice and runs the KDF once:
///
/// 1. **Verify.** The header and session block are read and the key derived,
///    as in [`decrypt`]. The ciphertext is then streamed through the HMAC and
///    the tag compared in constant time. Nothing is decrypted or written,
///    except that for v3 the final block alone is decrypted, inside a wrapper
///    that is wiped and never written, to check its PKCS#7 padding.
/// 2. **Decrypt.** `input` is sought back to where the payload starts (not
///    to 0, so a file embedded at an offset works), and the payload is
///    decrypted to `output` with the same session key, re-computing the HMAC
///    as it goes. The tag, the trailer and the final-block length byte must
///    all match what pass 1 verified.
///
/// Use [`decrypt`] when `input` cannot seek. Wrap a [`std::fs::File`] in a
/// [`std::io::BufReader`] (which is also `Seek`): the payload is read in
/// 16-byte blocks.
///
/// Returns a [`DecryptOutcome`] naming the format version and the number of
/// plaintext bytes written.
///
/// # Errors
///
/// The same as [`decrypt`], plus:
///
/// - [`AescryptError::Io`] — `input.seek` or `input.stream_position` failed.
/// - [`AescryptError::Header`] with
///   `"input changed between verification and decryption"` — pass 2 read
///   different ciphertext, a different tag or a different length byte from
///   what pass 1 verified.
///
/// # Panics
///
/// Never panics on valid or malformed input; see [`decrypt`].
///
/// # Security
///
/// **Verify-then-decrypt.** When pass 1 fails — a tampered or truncated
/// payload, a wrong password, invalid v3 padding, or a read error — `output`
/// has received **nothing**. Every byte written in pass 2 belongs to
/// ciphertext pass 1 authenticated.
///
/// On any `Err` the caller discards W. Two cases can still leave bytes in
/// `output` when an error is returned:
///
/// - an I/O error in pass 2 (a cancelling reader, a failing writer): the
///   bytes are authenticated plaintext, but incomplete;
/// - `input` changing between the passes: pass 2 detects it and fails, but
///   only after writing what it had decrypted. **`input` must not change
///   during the call**: decrypt from a file nothing else writes to.
///
/// What verification proves depends on the version:
///
/// - **v3**: every byte and the exact length. On `Ok`, the output is the
///   plaintext that was encrypted.
/// - **v0–v2**: every byte, but not the length of the final block, whose
///   length byte the legacy format leaves outside the HMAC. Up to 15 bytes
///   can be trimmed from, or exposed at, the end without failing. No
///   attacker-chosen byte can be released. See
///   [`DecryptOutcome::length_authenticated`].
///
/// The session key is derived once and held only in its zeroizing wrapper
/// until this returns. The two payload HMAC states (one per pass) are
/// `hmac` 0.12 values that cannot be wiped; see the crate-level Security
/// Model. Plaintext is never stored: [`DecryptOutcome`] holds only counts.
///
/// # Examples
///
/// ```
/// use aescrypt_rs::{decrypt_verified, encrypt};
/// use std::io::Cursor;
///
/// let mut ciphertext = Vec::new();
/// encrypt(Cursor::new(b"hello"), &mut ciphertext, "pw", 1)?;
///
/// let mut plaintext = Vec::new();
/// let outcome = decrypt_verified(Cursor::new(&ciphertext), &mut plaintext, "pw")?;
/// assert_eq!(plaintext, b"hello");
/// assert_eq!(outcome.version, 3);
/// assert_eq!(outcome.plaintext_len, 5);
/// assert!(outcome.length_authenticated());
///
/// // A tampered payload writes nothing at all.
/// let last = ciphertext.len() - 33; // the last ciphertext byte, before the 32-byte tag
/// ciphertext[last] ^= 1;
/// let mut out = Vec::new();
/// assert!(decrypt_verified(Cursor::new(&ciphertext), &mut out, "pw").is_err());
/// assert!(out.is_empty());
/// # Ok::<(), aescrypt_rs::AescryptError>(())
/// ```
pub fn decrypt_verified<R, W>(
    mut input: R,
    output: W,
    password: &str,
) -> Result<DecryptOutcome, AescryptError>
where
    R: Read + Seek,
    W: Write,
{
    let session = open_session(&mut input, password)?;
    let payload_start = input.stream_position()?;
    let config = session.stream_config();

    let verified = verify_ciphertext_stream(
        &mut input,
        &session.session_iv,
        &session.session_key,
        config,
    )?;

    input.seek(SeekFrom::Start(payload_start))?;
    let mut counted = CountingWriter {
        inner: output,
        written: 0,
    };
    decrypt_verified_stream(
        &mut input,
        &mut counted,
        &session.session_iv,
        &session.session_key,
        config,
        &verified,
    )?;

    Ok(DecryptOutcome {
        version: session.version,
        plaintext_len: counted.written,
    })
}

/// What [`decrypt_verified`] reports on success. Holds no secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecryptOutcome {
    /// The file's format version, `0..=3`. Anything below 3 is a legacy file
    /// a caller may want to re-encrypt.
    pub version: u8,
    /// Plaintext bytes written to the output.
    pub plaintext_len: u64,
}

impl DecryptOutcome {
    /// Whether the plaintext's exact length was authenticated: `true` for v3,
    /// `false` for v0–v2, whose final-block length byte is outside the HMAC.
    #[must_use]
    pub fn length_authenticated(&self) -> bool {
        self.version == 3
    }
}

/// Passes writes through to `inner`, counting the bytes it accepts.
struct CountingWriter<W> {
    /// The caller's writer.
    inner: W,
    /// Bytes `inner` has accepted.
    written: u64,
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Everything recovered from a file before its payload: the format version,
/// the v0 modulo byte, and the session IV and key, each in its zeroizing
/// wrapper.
///
/// Deliberately not `Clone`: there is one copy of the session key, and it is
/// wiped when this is dropped.
pub(crate) struct SessionState {
    /// Format version, `0..=3`.
    pub(crate) version: u8,
    /// 5th header byte: the v0 modulo byte, `0x00` for v1–v3.
    pub(crate) reserved_modulo: u8,
    /// IV for the payload's CBC chain.
    pub(crate) session_iv: Iv16,
    /// Key for the payload's AES and HMAC.
    pub(crate) session_key: Aes256Key32,
}

impl SessionState {
    /// The per-version stream configuration for the payload.
    ///
    /// # Panics
    ///
    /// Never: `version` comes from [`read_file_version`], which rejects
    /// anything above 3.
    pub(crate) fn stream_config(&self) -> StreamConfig {
        match self.version {
            0 => StreamConfig::V0 {
                reserved_modulo: self.reserved_modulo,
            },
            1 => StreamConfig::V1,
            2 => StreamConfig::V2,
            3 => StreamConfig::V3,
            _ => unreachable!("file_version validated in read_file_version"),
        }
    }
}

/// Reads the header, derives the setup key and recovers the session block,
/// leaving `input` at the first payload byte. The KDF runs here, once; the
/// setup key is wiped when this returns.
///
/// # Errors
///
/// As for [`decrypt`], from the header parsers, the KDF and
/// [`extract_session_data`].
pub(crate) fn open_session<R>(input: &mut R, password: &str) -> Result<SessionState, AescryptError>
where
    R: Read,
{
    let (file_version, reserved_modulo) = read_file_version(input)?;
    consume_all_extensions(input, file_version)?;

    let kdf_iterations = read_kdf_iterations(input, file_version)?;

    // Public IV — secure from the start
    let public_iv: Iv16 = read_exact_span(input)?;

    // Setup key — secure buffer from birth
    let mut setup_key = Aes256Key32::new([0u8; 32]);

    if file_version <= 2 {
        derive_ackdf_key(password, &public_iv, &mut setup_key)?;
    } else {
        derive_pbkdf2_key(password, &public_iv, kdf_iterations, &mut setup_key)?;
    }

    // Session key/IV — secure buffers from birth
    let mut session = SessionState {
        version: file_version,
        reserved_modulo,
        session_iv: Iv16::new([0u8; 16]),
        session_key: Aes256Key32::new([0u8; 32]),
    };

    extract_session_data(
        input,
        file_version,
        &public_iv,
        &setup_key,
        &mut session.session_iv,
        &mut session.session_key,
    )?;

    Ok(session)
}
