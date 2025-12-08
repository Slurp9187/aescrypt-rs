// src/aliases.rs

use secure_gate::dynamic_alias;
use secure_gate::{fixed_alias, fixed_alias_rng};

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
fixed_alias!(pub RingBuffer64, 64); // streaming decryptor ring buffer
fixed_alias!(pub Salt16, 16); // PBKDF2/ACKDF salt
fixed_alias!(pub SessionHmacTag32, 32); // session block HMAC

// ─────────────────────────────────────────────────────────────────────────────
// Random secrets — cryptographically fresh
// ─────────────────────────────────────────────────────────────────────────────
fixed_alias_rng!(pub RandomAes256Key32, 32);
fixed_alias_rng!(pub RandomIv16, 16);
fixed_alias_rng!(pub RandomPassword32, 32);
fixed_alias_rng!(pub RandomSalt16, 16);
