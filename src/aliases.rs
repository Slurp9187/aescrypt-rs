// src/aliases.rs

//! Global secure type aliases — secure-gate v0.5.10+
//! Maximum overkill, minimal duplication, audit-perfect

use secure_gate::{dynamic_alias, fixed_alias, random_alias};

// ─────────────────────────────────────────────────────────────────────────────
// Re-exported crypto primitives — available via `aliases::*`
// ─────────────────────────────────────────────────────────────────────────────
pub use crate::crypto::hmac::{HmacSha256, HmacSha512};

// ─────────────────────────────────────────────────────────────────────────────
// SpanBuffer — generic secure stack buffer (direct alias to secure-gate's Fixed)
// ─────────────────────────────────────────────────────────────────────────────
/// Generic secure fixed-size buffer — zero-cost, auto-zeroizing via secure-gate
pub type SpanBuffer<const N: usize> = secure_gate::Fixed<[u8; N]>;

// Semantic sub-types — compile-time safe
pub type AckdfHashState32 = SpanBuffer<32>;
pub type Block16 = SpanBuffer<16>; // one AES block
pub type InitialRead48 = SpanBuffer<48>; // first read in streaming decryptor
pub type Pbkdf2DerivedKey32 = SpanBuffer<32>;
pub type Pbkdf2HashState32 = SpanBuffer<32>;
pub type Trailer32 = SpanBuffer<32>; // v0/v3 HMAC trailer
pub type Trailer33 = SpanBuffer<33>; // v1–v2 legacy scattered trailer

// ─────────────────────────────────────────────────────────────────────────────
// Dynamic secrets
// ─────────────────────────────────────────────────────────────────────────────
dynamic_alias!(PasswordString, String);

// ─────────────────────────────────────────────────────────────────────────────
// Fixed-size concrete secrets — alphabetical order
// ─────────────────────────────────────────────────────────────────────────────
fixed_alias!(Aes256Key32, 32); // session key, HMAC key
fixed_alias!(EncryptedSessionBlock48, 48); // encrypted session IV + key
fixed_alias!(Iv16, 16); // public IV, session IV
fixed_alias!(PlainTextBlock16, 16); // decrypted stream blocks
fixed_alias!(PrevCiphertextBlock16, 16); // CBC chaining
fixed_alias!(RingBuffer64, 64); // streaming decryptor ring buffer
fixed_alias!(Salt16, 16); // PBKDF2/ACKDF salt
fixed_alias!(SessionHmacTag32, 32); // session block HMAC

// ─────────────────────────────────────────────────────────────────────────────
// Random secrets — cryptographically fresh
// ─────────────────────────────────────────────────────────────────────────────
random_alias!(RandomAes256Key32, 32);
random_alias!(RandomIv16, 16);
random_alias!(RandomPassword32, 32);
