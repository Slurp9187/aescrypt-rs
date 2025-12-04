// src/aliases.rs

//! Global secure type aliases — secure-gate v0.5.5+
//! Maximum overkill, minimal duplication, audit-perfect

use secure_gate::{dynamic_alias, fixed_alias, random_alias};

// ─────────────────────────────────────────────────────────────────────────────
// Core secrets — must stay separate
// ─────────────────────────────────────────────────────────────────────────────
fixed_alias!(Aes256Key, 32); // Used: session key, HMAC key, encryption
fixed_alias!(Iv16, 16); // Used: public IV, session IV
fixed_alias!(PlainTextBlock16, 16); // Used: decrypted blocks in stream
fixed_alias!(Salt16, 16); // Used: PBKDF2/ACKDF salt

// ─────────────────────────────────────────────────────────────────────────────
// Random aliases
// ─────────────────────────────────────────────────────────────────────────────
random_alias!(RandomAes256Key, 32);
random_alias!(RandomIv16, 16);
random_alias!(RandomPassword32, 32);

// ─────────────────────────────────────────────────────────────────────────────
// Overkill public-but-sensitive — auto-zeroed on drop
// ─────────────────────────────────────────────────────────────────────────────
fixed_alias!(EncryptedSessionBlock48, 48); // Perfect name — used in session.rs + decrypt_cbc_loop
fixed_alias!(PrevCiphertextBlock16, 16); // Used in session.rs + stream/context.rs
fixed_alias!(RingBuffer64, 64); // Used in stream/context.rs
fixed_alias!(SessionHmacTag32, 32); // Used in session.rs + stream/utils.rs

// ─────────────────────────────────────────────────────────────────────────────
// Dynamic secrets
// ─────────────────────────────────────────────────────────────────────────────
dynamic_alias!(MasterKey, Vec<u8>);
dynamic_alias!(Password, String);
dynamic_alias!(Token, String);

dynamic_alias!(MasterKeyVec, Vec<u8>);
dynamic_alias!(PasswordString, String);
dynamic_alias!(TokenString, String);

// Re-exported crypto primitives — users get them from the same `aliases::*` import
pub use crate::crypto::hmac::{HmacSha256, HmacSha512};
