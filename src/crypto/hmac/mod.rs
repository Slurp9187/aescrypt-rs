// src/core/crypto/hmac/mod.rs

//! HMAC-SHA primitives (re-exports from `hmac` + `sha2`).
//!
//! Use `HmacSha256`/`HmacSha512` for message authentication.

use hmac::Hmac;
use sha2::{Sha256, Sha512};

pub type HmacSha256 = Hmac<Sha256>;
pub type HmacSha512 = Hmac<Sha512>;
