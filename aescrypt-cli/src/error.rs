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

    /// Any other password problem: mismatch, empty, command failure.
    #[error("{0}")]
    Password(String),

    /// I/O on a named path.
    #[error("{}: {source}", path.display())]
    Io { path: PathBuf, source: io::Error },

    /// The library rejected the input.
    #[error("{}: {}", path.display(), describe(source))]
    Crypto {
        path: PathBuf,
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
            Self::Interrupted => 130,
            _ => 1,
        }
    }
}

/// Library errors with a hint where the raw message would leave a user guessing.
///
/// A wrong password surfaces as an HMAC failure on the session block, which
/// the library reports as a header error. Saying so is the single most useful
/// thing an encryption CLI can print.
fn describe(e: &AescryptError) -> String {
    match e {
        AescryptError::Header(msg) if msg.contains("HMAC") || msg.contains("tampered") => {
            format!("wrong password, or the file is corrupted ({msg})")
        }
        AescryptError::Header(msg) if msg.contains("padding") => {
            format!("the file is corrupted ({msg})")
        }
        other => other.to_string(),
    }
}
