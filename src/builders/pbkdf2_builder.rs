//! src/crypto/kdf/builder/pbkdf2.rs
//! PBKDF2-HMAC-SHA512 builder — secure-gate v0.5.5+ best practices (2025)
//! Zero-cost, zero-exposure, idiomatic, audit-ready

use crate::aliases::{Aes256Key32, PasswordString, Salt16};
use crate::consts::DEFAULT_PBKDF2_ITERATIONS;
use crate::derive_secure_pbkdf2_key;
use crate::error::AescryptError;
use rand::{rngs::OsRng, TryRngCore};

/// PBKDF2-HMAC-SHA512 key derivation builder
///
/// Strong defaults: 16-byte random salt + 600,000 iterations (2025 recommended)
#[derive(Debug, Clone)]
pub struct Pbkdf2Builder {
    iterations: u32,
    salt: [u8; 16], // Fixed size = no heap, no capacity leaks, zeroizable
}

impl Pbkdf2Builder {
    /// Create builder with strong defaults
    #[must_use]
    pub fn new() -> Self {
        let mut salt = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut salt)
            .expect("OS RNG failed — system is critically broken");
        Self {
            // iterations: 600_000, // OWASP/NIST 2025+ recommendation
            iterations: DEFAULT_PBKDF2_ITERATIONS, // OWASP/NIST 2025+ recommendation
            salt,
        }
    }

    /// Set custom iteration count (minimum 1)
    #[must_use]
    pub fn with_iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations.max(1);
        self
    }

    /// Set custom salt — accepts [u8; 16], Salt16, etc.
    #[must_use]
    pub fn with_salt(mut self, salt: impl Into<[u8; 16]>) -> Self {
        self.salt = salt.into();
        self
    }

    /// Current salt as raw 16-byte array (for serialization)
    #[must_use]
    pub const fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    /// Current iteration count
    #[must_use]
    pub const fn iterations(&self) -> u32 {
        self.iterations
    }

    /// Derive key directly into caller-provided secure buffer — **preferred**
    #[inline(always)]
    pub fn derive_secure(
        self,
        password: &PasswordString,
        out_key: &mut Aes256Key32,
    ) -> Result<(), AescryptError> {
        derive_secure_pbkdf2_key(
            password,
            &Salt16::from(self.salt), // zero-cost temporary borrow
            self.iterations,
            out_key,
        )
    }

    /// Convenience: derive and return a fresh secure key
    #[inline(always)]
    pub fn derive_secure_new(
        self,
        password: &PasswordString,
    ) -> Result<Aes256Key32, AescryptError> {
        let mut key = Aes256Key32::new([0u8; 32]);
        self.derive_secure(password, &mut key)?;
        Ok(key)
    }
}

impl Default for Pbkdf2Builder {
    fn default() -> Self {
        Self::new()
    }
}
