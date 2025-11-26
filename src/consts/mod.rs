//! Global constants for AES Crypt implementation.
//!
//! Includes version, KDF parameters, and recommended defaults.

/// Current AES Crypt file format version.
pub const AESCRYPT_LATEST_VERSION: u8 = 3;

/// Minimum allowed PBKDF2 iterations.
pub const PBKDF2_MIN_ITER: u32 = 1;

/// Maximum allowed PBKDF2 iterations (5 million).
pub const PBKDF2_MAX_ITER: u32 = 5_000_000;

/// Recommended PBKDF2 iteration count for 2025 security.
/// Provides ~0.1–0.3s on modern hardware; balances usability and resistance to GPU attacks.
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 300_000;

/// Default key derivation output length (32 bytes = 256-bit key).
pub const DEFAULT_PBKDF2_LENGTH: usize = 32;

/// Default salt size (16 bytes).
/// Used for both ACKDF (required) and PBKDF2 (recommended).
pub const DEFAULT_SALT_SIZE: usize = 16;

pub const BYTE_LENGTH_32: usize = 32;
pub const BYTE_LENGTH_64: usize = 64;
