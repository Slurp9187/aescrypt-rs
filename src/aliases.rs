//! # Secure-Gate Type Aliases
//!
//! This module provides type aliases for secure memory management using [`secure-gate`](https://github.com/Slurp9187/secure-gate).
//! All types in this module provide automatic zeroization on drop and prevent accidental secret exposure.
//!
//! ## Type Categories
//!
//! ### HMAC Primitives
//! - [`HmacSha256`] - HMAC-SHA256 for session block and payload authentication
//!
//! ### Generic Secure Buffers
//! - [`SpanBuffer<N>`] - Generic secure stack buffer for any size `N`
//!
//! ### Semantic Fixed-Size Types
//! - [`AckdfHashState32`] - 32-byte ACKDF hash state
//! - [`Block16`] - 16-byte AES block
//! - [`ExtensionChunk256`] - 256-byte v2/v3 extension payload chunk
//! - [`Trailer32`] - 32-byte HMAC trailer (v0/v3)
//!
//! ### Dynamic Secrets
//! - [`PasswordString`] - Secure password string wrapper
//!
//! ### Fixed-Size Secrets
//! - [`AckdfDerivedKey32`] - 32-byte ACKDF-derived setup key (v0/v1/v2)
//! - [`Aes256Key32`] - 32-byte AES-256 key
//! - [`EncryptedSessionBlock48`] - 48-byte encrypted session block
//! - [`Iv16`] - 16-byte initialization vector
//! - [`Pbkdf2DerivedKey32`] - 32-byte PBKDF2-derived setup key (v3)
//! - [`RingBuffer64`] - 64-byte ring buffer for streaming decryption
//! - [`Salt16`] - 16-byte salt for KDF operations
//! - [`SessionHmacTag32`] - 32-byte session block HMAC tag
//!
//! ## Usage
//!
//! All secure types require scoped `.with_secret()` or `.with_secret_mut()` to access
//! the underlying data, ensuring no accidental secret exposure.
//!
//! ## Type Identity
//!
//! Every alias in this module is a plain `pub type` alias for
//! `secure_gate::Fixed<[u8; N]>` (or `secure_gate::Dynamic<T>`). They
//! are **not nominal newtypes**: any two size-equal aliases (`Aes256Key32` and
//! `Salt16` differ in size and so are not interchangeable, but `Aes256Key32`,
//! `SessionHmacTag32`, `Trailer32`, and `SpanBuffer<32>` all resolve to the
//! same type and are freely assignable to each other). The names exist for
//! readability and auditability, not for compile-time enforcement. Any
//! genuine type-level separation requires hand-rolled wrapper structs.

use secure_gate::{Dynamic, Fixed};

// ─────────────────────────────────────────────────────────────────────────────
// HMAC primitives — available via `aliases::*`
// ─────────────────────────────────────────────────────────────────────────────
use hmac::Hmac;
use sha2::Sha256;

pub type HmacSha256 = Hmac<Sha256>;

// ─────────────────────────────────────────────────────────────────────────────
// SpanBuffer — generic secure stack buffer (direct alias to secure-gate's Fixed)
// ─────────────────────────────────────────────────────────────────────────────
pub type SpanBuffer<const N: usize> = secure_gate::Fixed<[u8; N]>;

// Semantic sub-types — readability aliases for `SpanBuffer<N>`. Not nominally
// distinct: same-size aliases resolve to the same `Fixed<[u8; N]>` type and
// are freely assignable to each other.
pub type AckdfHashState32 = SpanBuffer<32>;
pub type Block16 = SpanBuffer<16>; // one AES block
pub type ExtensionChunk256 = SpanBuffer<256>; // v2/v3 extension payload chunk
pub type Trailer32 = SpanBuffer<32>; // v0/v3 HMAC trailer

// ─────────────────────────────────────────────────────────────────────────────
// Dynamic secrets
// ─────────────────────────────────────────────────────────────────────────────
pub type PasswordString = Dynamic<String>;

// ─────────────────────────────────────────────────────────────────────────────
// Fixed-size concrete secrets — alphabetical order
// ─────────────────────────────────────────────────────────────────────────────
pub type AckdfDerivedKey32 = Fixed<[u8; 32]>; // ACKDF-derived v0/v1/v2 setup key
pub type Aes256Key32 = Fixed<[u8; 32]>; // session key, HMAC key
pub type EncryptedSessionBlock48 = Fixed<[u8; 48]>; // encrypted session IV + key
pub type Iv16 = Fixed<[u8; 16]>; // public IV, session IV
pub type Pbkdf2DerivedKey32 = Fixed<[u8; 32]>; // PBKDF2-derived v3 setup key
pub type RingBuffer64 = Fixed<[u8; 64]>; // streaming decryption ring buffer
pub type Salt16 = Fixed<[u8; 16]>; // PBKDF2/ACKDF salt
pub type SessionHmacTag32 = Fixed<[u8; 32]>; // session block HMAC
