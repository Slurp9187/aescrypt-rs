//! # Constants
//!
//! This module defines constants used throughout the library for version detection,
//! PBKDF2 iteration counts, and other configuration values.

/// The latest supported AES Crypt file format version.
///
/// Currently set to `3`, which is the only version produced by this library.
/// All encryption operations create v3 files, while decryption supports v0-v3.
pub const AESCRYPT_LATEST_VERSION: u8 = 3;

/// Minimum allowed PBKDF2 iteration count.
///
/// Must be at least `1`. Values below this will be rejected during validation.
pub const PBKDF2_MIN_ITER: u32 = 1;

/// Maximum allowed PBKDF2 iteration count.
///
/// Set to `5_000_000` to prevent excessive computation times while allowing
/// high-security configurations. Values above this will be rejected during validation.
pub const PBKDF2_MAX_ITER: u32 = 5_000_000;

/// Default PBKDF2 iteration count for encryption operations.
///
/// Set to `300_000`, which provides a good balance between security and performance
/// for most use cases. This value aligns with OWASP/NIST 2025+ recommendations.
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 300_000;

