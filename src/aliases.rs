//! # Secure-Gate Type Aliases
//!
//! This module provides type aliases for secure memory management using [`secure-gate`](https://github.com/Slurp9187/secure-gate).
//! All types in this module provide automatic zeroization on drop and prevent accidental secret exposure.
//!
//! ## Type Categories
//!
//! ### HMAC Primitives
//! - [`HmacSha256`] - HMAC-SHA256 for session block and payload authentication
//! - [`HmacSha512`] - HMAC-SHA512 for PBKDF2 key derivation
//!
//! ### Generic Secure Buffers
//! - [`SpanBuffer<N>`] - Generic secure stack buffer for any size `N`
//!
//! ### Semantic Fixed-Size Types
//! - [`AckdfHashState32`] - 32-byte ACKDF hash state
//! - [`Block16`] - 16-byte AES block
//! - [`Trailer32`] - 32-byte HMAC trailer (v0/v3)
//!
//! ### Dynamic Secrets
//! - [`PasswordString`] - Secure password string wrapper
//!
//! ### Fixed-Size Secrets
//! - [`Aes256Key32`] - 32-byte AES-256 key
//! - [`EncryptedSessionBlock48`] - 48-byte encrypted session block
//! - [`Iv16`] - 16-byte initialization vector
//! - [`RingBuffer64`] - 64-byte ring buffer for streaming decryption
//! - [`Salt16`] - 16-byte salt for KDF operations
//! - [`SessionHmacTag32`] - 32-byte session block HMAC tag
//!
//! ### Random Secret Generators
//! - [`RandomAes256Key32`] - Generates random 32-byte AES keys
//! - [`RandomIv16`] - Generates random 16-byte IVs
//! - [`RandomPassword32`] - Generates random 32-byte passwords
//! - [`RandomSalt16`] - Generates random 16-byte salts
//!
//! ## Usage
//!
//! All secure types require explicit `.expose_secret()` or `.expose_secret_mut()` to access
//! the underlying data, ensuring no accidental secret exposure.

use secure_gate::dynamic_alias;
use secure_gate::fixed_alias;
#[cfg(feature = "rand")]
use secure_gate::fixed_alias_rng;

// ─────────────────────────────────────────────────────────────────────────────
// HMAC primitives — available via `aliases::*`
// ─────────────────────────────────────────────────────────────────────────────
use hmac::Hmac;
use sha2::{Sha256, Sha512};

pub type HmacSha256 = Hmac<Sha256>;
pub type HmacSha512 = Hmac<Sha512>;

// ─────────────────────────────────────────────────────────────────────────────
// SpanBuffer — generic secure stack buffer (direct alias to secure-gate's Fixed)
// ─────────────────────────────────────────────────────────────────────────────
pub type SpanBuffer<const N: usize> = secure_gate::Fixed<[u8; N]>;

// Semantic sub-types — compile-time safe
pub type AckdfHashState32 = SpanBuffer<32>;
pub type Block16 = SpanBuffer<16>; // one AES block
pub type Trailer32 = SpanBuffer<32>; // v0/v3 HMAC trailer

// ─────────────────────────────────────────────────────────────────────────────
// Dynamic secrets
// ─────────────────────────────────────────────────────────────────────────────
dynamic_alias!(pub PasswordString, String);

// ─────────────────────────────────────────────────────────────────────────────
// Fixed-size concrete secrets — alphabetical order
// ─────────────────────────────────────────────────────────────────────────────
fixed_alias!(pub Aes256Key32, 32); // session key, HMAC key
fixed_alias!(pub EncryptedSessionBlock48, 48); // encrypted session IV + key
fixed_alias!(pub Iv16, 16); // public IV, session IV
fixed_alias!(pub RingBuffer64, 64); // streaming decryption ring buffer
fixed_alias!(pub Salt16, 16); // PBKDF2/ACKDF salt
fixed_alias!(pub SessionHmacTag32, 32); // session block HMAC

// ─────────────────────────────────────────────────────────────────────────────
// Random secrets — cryptographically fresh
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(feature = "rand")]
fixed_alias_rng!(pub RandomAes256Key32, 32);
#[cfg(feature = "rand")]
fixed_alias_rng!(pub RandomIv16, 16);
#[cfg(feature = "rand")]
fixed_alias_rng!(pub RandomPassword32, 32);
#[cfg(feature = "rand")]
fixed_alias_rng!(pub RandomSalt16, 16);
