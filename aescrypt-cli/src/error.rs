// ============================================================================
// FILE: aescrypt-cli/src/error.rs
// ============================================================================

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
    Io { path: PathBuf, source: io::Error },

    /// The library rejected the input.
    #[error("{}: {}", path.display(), describe(source, decrypt.as_ref()))]
    Crypto {
        path: PathBuf,
        /// How far a decryption got; `None` when encrypting.
        decrypt: Option<ReadState>,
        source: AescryptError,
    },

    /// A refusal decided before any work started (output exists, same file, …).
    #[error("{}: {msg}", path.display())]
    Refused { path: PathBuf, msg: String },
}

impl CliError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

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
/// and falls back to the raw message for anything it does not recognise.
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
        "session data corrupted or tampered (HMAC mismatch)" => {
            "wrong password, or the file header is damaged"
        }
        "HMAC verification failed" if version == Some(0) => {
            "wrong password, or the file is damaged or was tampered with"
        }
        "HMAC verification failed" => {
            "the file is damaged or was tampered with (the password was correct)"
        }
        "v0: expected 32-byte HMAC trailer"
        | "v1/v2: expected 33-byte trailer"
        | "v3: expected 32-byte HMAC trailer"
        | "v3: missing final plaintext block" => "the file is truncated or damaged",
        "v3: invalid PKCS#7 padding" => "the file is damaged or was tampered with",
        _ => return e.to_string(),
    };
    format!("{hint} ({msg})")
}
