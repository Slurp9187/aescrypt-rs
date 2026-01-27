//! src/builders/pbkdf2_builder.rs
//! PBKDF2-HMAC-SHA512 builder — secure-gate best practices
//! Zero-cost, zero-exposure, idiomatic, audit-ready

use crate::aliases::{Aes256Key32, PasswordString, Salt16};
use crate::constants::DEFAULT_PBKDF2_ITERATIONS;
use crate::derive_pbkdf2_key;
use crate::error::AescryptError;

/// PBKDF2-HMAC-SHA512 key derivation builder
///
/// Strong defaults: 16-byte random salt + 300,000 iterations (uses [`constants::DEFAULT_PBKDF2_ITERATIONS`])
///
/// # Thread Safety
///
/// This type is **thread-safe** (`Send + Sync`). Builders can be created and used
/// concurrently from multiple threads. All operations are pure (no shared mutable state).
///
/// # Example
///
/// ```
/// use aescrypt_rs::{Pbkdf2Builder, PasswordString, aliases::Aes256Key32};
///
/// let password = PasswordString::new("my-secret-password".to_string());
///
/// // Use defaults (300k iterations, random salt when 'rand' feature is enabled)
/// let mut key = Aes256Key32::new([0u8; 32]);
/// Pbkdf2Builder::new()
///     .with_salt([0x42; 16]) // Fixed salt for reproducible doctest
///     .derive_secure(&password, &mut key)?;
///
/// // Or get a new key directly
/// let derived_key = Pbkdf2Builder::new()
///     .with_salt([0x42; 16])
///     .derive_secure_new(&password)?;
/// # Ok::<(), aescrypt_rs::AescryptError>(())
/// ```
#[derive(Debug)]
pub struct Pbkdf2Builder {
    iterations: u32,
    salt: Salt16, // Secure from birth
}

impl Pbkdf2Builder {
    /// Create builder with strong defaults
    ///
    /// Uses [`constants::DEFAULT_PBKDF2_ITERATIONS`] (300,000) as the default iteration count.
    #[must_use]
    pub fn new() -> Self {
        Self {
            iterations: DEFAULT_PBKDF2_ITERATIONS,
            salt: Salt16::from_random(),
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
        self.salt = Salt16::from(salt.into());
        self
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
        derive_pbkdf2_key(password, &self.salt, self.iterations, out_key)
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
