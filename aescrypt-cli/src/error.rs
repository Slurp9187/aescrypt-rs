// ============================================================================
// FILE: aescrypt-cli/src/error.rs
// ============================================================================

//! [`CliError`], its exit codes, and the translation of library errors into
//! words a user can act on.

use std::{io, path::PathBuf};

use aescrypt_rs::AescryptError;

/// Everything the CLI can fail with. Kept separate from [`AescryptError`] so CLI
/// conditions (a mismatched confirmation, a missing TTY) never masquerade as
/// library errors.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Bad combination of arguments. Exit code 2, like clap's own usage errors.
    #[error("{0}")]
    Usage(String),

    /// No terminal to prompt on.
    #[error(
        "cannot prompt for a password: no terminal available ({0}); \
         use --password-command for non-interactive use"
    )]
    NoTty(io::Error),

    /// The prompt was interrupted (Ctrl-C).
    #[error("interrupted")]
    Interrupted,

    /// The terminal went away while the prompt was waiting for input.
    #[error("the terminal closed during the password prompt")]
    TerminalLost,

    /// Any other password problem: mismatch, empty, command failure.
    #[error("{0}")]
    Password(String),

    /// I/O on a named path.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file involved, or `<stdin>` / `<stdout>`.
        path: PathBuf,
        /// The operating system's error.
        source: io::Error,
    },

    /// The library rejected the input.
    #[error("{}: {}", path.display(), describe(source, decrypt.as_ref()))]
    Crypto {
        /// The input file, or `<stdin>`.
        path: PathBuf,
        /// How far a decryption got; `None` when encrypting.
        decrypt: Option<ReadState>,
        /// The library's error, translated for display (see the private
        /// `describe` below).
        source: AescryptError,
    },

    /// A refusal: decided while planning (output exists, same file, …), or at
    /// the final rename when the output appeared after planning.
    #[error("{}: {msg}", path.display())]
    Refused {
        /// The path refused, usually the output.
        path: PathBuf,
        /// Why, worded to follow the path.
        msg: String,
    },
}

impl CliError {
    /// A [`CliError::Io`] for `path`.
    pub(crate) fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// A [`CliError::Refused`] for `path`.
    pub(crate) fn refused(path: impl Into<PathBuf>, msg: impl Into<String>) -> Self {
        Self::Refused {
            path: path.into(),
            msg: msg.into(),
        }
    }

    /// Process exit code for this error when it ends the run on its own.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => 2,
            // Same code the signal handler exits with, so a hang-up ends the
            // same way whichever of the two sees it first.
            Self::Interrupted | Self::TerminalLost => 130,
            _ => 1,
        }
    }

    /// Whether decryption failed because the password was wrong (for a v0
    /// file: wrong, or the file is damaged; v0 cannot tell them apart).
    pub fn is_wrong_password(&self) -> bool {
        match self {
            Self::Crypto {
                decrypt: Some(state),
                source: AescryptError::Header(msg),
                ..
            } => is_wrong_password_msg(msg, state.version),
            _ => false,
        }
    }
}

/// How much of a ciphertext was read when decryption failed.
#[derive(Debug, Clone, Copy)]
pub struct ReadState {
    /// Format version from the header, if the header got that far.
    pub version: Option<u8>,
    /// Bytes read from the input.
    pub bytes: u64,
}

/// Library errors in words a user can act on, with the library's own message
/// kept in parentheses.
///
/// The library's messages are not a stable API, so this matches whole strings
/// and falls back to the raw message for anything it does not recognize.
/// `tests/run.rs` triggers each case for real, so a wording change in the
/// library fails a test rather than silently mislabelling errors.
///
/// What an HMAC failure means depends on the version. v1-v3 check the password
/// against the session block first; a payload HMAC failure after that means the
/// password was right and the data is damaged. v0 has no session block, so
/// there the payload HMAC is the only password check.
///
/// Input that ends inside the header or session block surfaces as the
/// library's raw read error (`UnexpectedEof`, "failed to fill whole buffer");
/// when decrypting, that means the file is empty or cut short.
fn describe(e: &AescryptError, decrypt: Option<&ReadState>) -> String {
    let Some(state) = decrypt else {
        return e.to_string();
    };
    let msg = match e {
        AescryptError::Io(io) if io.kind() == io::ErrorKind::UnexpectedEof => {
            return if state.bytes == 0 {
                "the file is empty".to_string()
            } else {
                format!("the file is truncated or damaged ({io})")
            };
        }
        AescryptError::Header(msg) => msg,
        other => return other.to_string(),
    };
    let version = state.version;
    let hint = match msg.as_str() {
        _ if is_wrong_password_msg(msg, version) => {
            if version == Some(0) {
                "wrong password, or the file is damaged or was tampered with"
            } else {
                "wrong password, or the file header is damaged"
            }
        }
        "HMAC verification failed" => {
            "the file is damaged or was tampered with (the password was correct)"
        }
        "v0: expected 32-byte HMAC trailer"
        | "v1/v2: expected 33-byte trailer"
        | "v3: expected 32-byte HMAC trailer"
        | "v3: missing final plaintext block" => "the file is truncated or damaged",
        "v3: invalid PKCS#7 padding" => "the file is damaged or was tampered with",
        "input changed between verification and decryption" => {
            "the file changed while it was being decrypted; no output was kept"
        }
        _ => return e.to_string(),
    };
    format!("{hint} ({msg})")
}

/// Whether a library header message means the password was wrong: the
/// session-block HMAC (v1–v3), or for v0, which has no session block, the
/// payload HMAC (so for v0 it may also mean damage). `describe` and
/// [`CliError::is_wrong_password`] both use this, so they cannot disagree.
fn is_wrong_password_msg(msg: &str, version: Option<u8>) -> bool {
    match msg {
        "session data corrupted or tampered (HMAC mismatch)" => true,
        "HMAC verification failed" => version == Some(0),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exit code 3 and the "wrong password" wording come from one predicate.
    #[test]
    fn wrong_password_agrees_with_message() {
        let cases = [
            (
                "session data corrupted or tampered (HMAC mismatch)",
                3,
                true,
            ),
            (
                "session data corrupted or tampered (HMAC mismatch)",
                1,
                true,
            ),
            ("HMAC verification failed", 0, true),
            ("HMAC verification failed", 2, false),
            ("HMAC verification failed", 3, false),
            ("v3: invalid PKCS#7 padding", 3, false),
            (
                "input changed between verification and decryption",
                0,
                false,
            ),
            (
                "input changed between verification and decryption",
                3,
                false,
            ),
        ];
        for (msg, version, expected) in cases {
            let e = CliError::Crypto {
                path: "f.aes".into(),
                decrypt: Some(ReadState {
                    version: Some(version),
                    bytes: 100,
                }),
                source: AescryptError::Header(msg.into()),
            };
            assert_eq!(e.is_wrong_password(), expected, "{msg} v{version}");
            assert_eq!(
                e.to_string().contains("wrong password"),
                expected,
                "{msg} v{version}: {e}"
            );
        }
    }

    /// `decrypt_verified`'s second pass reading something other than what its
    /// first pass verified gets a message of its own, and exit code 1.
    #[test]
    fn input_changed_is_described() {
        let e = CliError::Crypto {
            path: "f.aes".into(),
            decrypt: Some(ReadState {
                version: Some(3),
                bytes: 100,
            }),
            source: AescryptError::Header(
                "input changed between verification and decryption".into(),
            ),
        };
        let shown = e.to_string();
        assert!(
            shown.contains("the file changed while it was being decrypted; no output was kept"),
            "{shown}"
        );
        assert_eq!(e.exit_code(), 1);
    }
}
