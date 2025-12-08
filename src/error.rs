// ============================================================================
// FILE: src/error.rs
// ============================================================================


use thiserror::Error;

#[derive(Error, Debug)]
pub enum AescryptError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Header error: {0}")]
    Header(String),

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),
}

impl From<&'static str> for AescryptError {
    fn from(msg: &'static str) -> Self {
        AescryptError::Crypto(msg.to_string())
    }
}
