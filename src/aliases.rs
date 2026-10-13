//! # Secure-Gate Type Aliases
//!
//! This module provides type aliases for secure memory management using [`secure-gate`](https://github.com/Slurp9187/secure-gate).
//! Every alias except [`HmacSha256`] wraps a `secure-gate` type, which zeroizes its
//! contents on drop and only exposes them through scoped access. [`HmacSha256`] is
//! the `hmac` crate's own type: its internal state is *not* zeroized on drop.
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

/// HMAC-SHA256, the MAC every format version uses: over the session block (v1–v3)
/// and over the payload ciphertext (v0–v3).
///
/// This is the `hmac` crate's type, not a `secure-gate` wrapper. Its keyed
/// internal state is **not** zeroized on drop. The tags it computes come back as
/// plain arrays: encryption writes them straight to the output, and decryption
/// copies them into [`SessionHmacTag32`] / [`Trailer32`] for the constant-time
/// comparison. Tags are public; they are stored in the file.
pub type HmacSha256 = Hmac<Sha256>;

// ─────────────────────────────────────────────────────────────────────────────
// SpanBuffer — generic secure stack buffer (direct alias to secure-gate's Fixed)
// ─────────────────────────────────────────────────────────────────────────────
/// An `N`-byte stack buffer that zeroizes on drop: `secure_gate::Fixed<[u8; N]>`.
///
/// `decrypt` reads each fixed-size header and session field into one through
/// [`read_exact_span`](crate::decryption::read_exact_span). Not every parser
/// does: [`read_version`](crate::read_version) reads its few public bytes into
/// plain arrays. The other `*N` aliases below are the same type at a specific
/// `N`.
pub type SpanBuffer<const N: usize> = secure_gate::Fixed<[u8; N]>;

// Semantic sub-types — readability aliases for `SpanBuffer<N>`. Not nominally
// distinct: same-size aliases resolve to the same `Fixed<[u8; N]>` type and
// are freely assignable to each other.
/// The 32-byte running SHA-256 state of the ACKDF key derivation (v0–v2), kept
/// in a zeroizing buffer between its 8192 rounds.
pub type AckdfHashState32 = SpanBuffer<32>;
/// One 16-byte AES block: a ciphertext or plaintext block during CBC
/// encryption and decryption, in every version.
pub type Block16 = SpanBuffer<16>;
/// A 256-byte chunk used to read v2/v3 header extensions in pieces, so an
/// extension's bytes are never held outside a zeroizing buffer.
pub type ExtensionChunk256 = SpanBuffer<256>;
/// The 32-byte payload HMAC at the end of a file: the whole trailer in v0 and
/// v3. (v1 and v2 put a modulo byte in front of it, a 33-byte trailer.)
pub type Trailer32 = SpanBuffer<32>;

// ─────────────────────────────────────────────────────────────────────────────
// Dynamic secrets
// ─────────────────────────────────────────────────────────────────────────────
/// A password, as `secure_gate::Dynamic<String>`: heap-allocated, zeroized on
/// drop, readable only inside a scoped `with_secret` call. The library takes
/// it as UTF-8; v0–v2 key derivation converts it to UTF-16LE internally.
pub type PasswordString = Dynamic<String>;

// ─────────────────────────────────────────────────────────────────────────────
// Fixed-size concrete secrets — alphabetical order
// ─────────────────────────────────────────────────────────────────────────────
/// The 32-byte setup key ACKDF derives from the password (v0–v2). It decrypts
/// the session block (v1/v2), or the payload directly (v0).
pub type AckdfDerivedKey32 = Fixed<[u8; 32]>;
/// A 32-byte AES-256 key: the per-file session key, or a key used for HMAC.
pub type Aes256Key32 = Fixed<[u8; 32]>;
/// The 48-byte encrypted session block (v1–v3): the session IV and session key,
/// encrypted under the setup key.
pub type EncryptedSessionBlock48 = Fixed<[u8; 48]>;
/// A 16-byte initialization vector: the public IV in the header (which is also
/// the KDF salt), or the session IV inside the session block.
pub type Iv16 = Fixed<[u8; 16]>;
/// The 32-byte setup key PBKDF2-HMAC-SHA512 derives from the password (v3). It
/// decrypts the session block.
pub type Pbkdf2DerivedKey32 = Fixed<[u8; 32]>;
/// The 64-byte ring buffer of streaming decryption: the previous ciphertext
/// block (for CBC chaining), the current one, and the next 32 bytes held back
/// until the end of input shows whether they are ciphertext or the trailer.
pub type RingBuffer64 = Fixed<[u8; 64]>;
/// A 16-byte KDF salt. In a file it is the header's public IV (ACKDF for
/// v0–v2, PBKDF2 for v3); [`Pbkdf2Builder`](crate::Pbkdf2Builder) generates a
/// random one.
pub type Salt16 = Fixed<[u8; 16]>;
/// The 32-byte HMAC over the encrypted session block (v1–v3), read from the
/// header and compared in constant time.
pub type SessionHmacTag32 = Fixed<[u8; 32]>;
