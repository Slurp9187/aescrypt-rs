//! Public configuration constants.
//!
//! These constants govern the AES Crypt format version this crate produces and
//! the PBKDF2 iteration bounds enforced by the encryption path. They are part
//! of the SemVer-stable surface; values may be raised in a major release as
//! security guidance evolves.

/// AES Crypt format version produced by this crate on every write.
///
/// Currently `3`. [`crate::encrypt()`] always emits v3; v0–v2 are read-only for
/// compatibility with legacy AES Crypt tools. See [`crate::decryption`] for the
/// full read-side compatibility matrix.
///
/// # Security
///
/// v3 is the only AES Crypt format with PBKDF2-HMAC-SHA512 password hardening
/// and PKCS#7 padding. Producing older versions would be a security downgrade,
/// which is why this crate has no opt-in to write v0/v1/v2.
pub const AESCRYPT_LATEST_VERSION: u8 = 3;

/// Lower inclusive bound for PBKDF2 iteration counts accepted by this crate.
///
/// The unit is **iterations** (one PBKDF2-HMAC-SHA512 round per count). Values
/// below this bound are rejected by [`crate::encrypt()`] and the
/// [`crate::encryption::write_iterations`] / [`crate::encryption::derive_setup_key`]
/// helpers with [`AescryptError::Header`](crate::AescryptError::Header).
///
/// # Security
///
/// `1` is intentionally permissive so that decryption can re-derive keys from
/// files produced by other tools with low iteration counts. **Do not use `1` for
/// new encryption.** The recommended floor for new files is
/// [`DEFAULT_PBKDF2_ITERATIONS`].
pub const PBKDF2_MIN_ITER: u32 = 1;

/// Upper inclusive bound for PBKDF2 iteration counts accepted by this crate.
///
/// The unit is **iterations**. Set to 5 000 000 to cap pre-authentication CPU
/// cost when reading attacker-controlled files (the iteration count is parsed
/// from the v3 header before the session HMAC has been verified) while still
/// allowing aggressive password-hardening profiles.
///
/// # Security
///
/// Files declaring more than `PBKDF2_MAX_ITER` are rejected by
/// [`crate::decryption::read_kdf_iterations`] and [`crate::encrypt()`] with
/// [`AescryptError::Header`](crate::AescryptError::Header). This bound exists to
/// prevent `iterations = u32::MAX` denial-of-service inputs.
pub const PBKDF2_MAX_ITER: u32 = 5_000_000;

/// Recommended PBKDF2 iteration count for new v3 files.
///
/// `600_000` iterations of PBKDF2-HMAC-SHA512: the default of the official
/// AES Crypt tool (4.7), and above OWASP/NIST 2025+ guidance for SHA-512-based
/// password hashing on commodity hardware. Releases up to 0.2.0-rc.11 used
/// `300_000`; files carry their own count, so files written with either
/// decrypt unchanged.
///
/// # Security
///
/// This is the value the [`Pbkdf2Builder`](crate::Pbkdf2Builder) defaults to and
/// the value used by every example in this crate's documentation. Lowering it
/// trades password-cracking resistance for CPU; do not lower it without a
/// documented reason. Raising it (up to [`PBKDF2_MAX_ITER`]) is always safe but
/// proportionally slows down [`crate::encrypt()`] and [`crate::decrypt()`].
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 600_000;

/// The most bytes the streaming loops read or write per call: 64 KiB.
///
/// [`crate::encrypt()`] fills a span of plaintext, encrypts it in place and
/// writes it with one `write_all`; [`crate::decrypt()`] and
/// [`crate::decrypt_verified()`] read a span of ciphertext and write its
/// plaintext the same way. No read asks for more than this, and no write is
/// larger. On a slow stream, output waits until a span has arrived or the
/// input ends.
///
/// Each call starts with a smaller span and grows toward this one only while
/// its fills come back full, so a small file never allocates 64 KiB.
///
/// The file format does not depend on it. It may change in any release.
pub const SPAN: usize = 64 * 1024;

/// The span each streaming call starts with: 1 KiB. Each time a fill comes
/// back full, the call grows the span by [`SPAN_GROWTH`], up to [`SPAN`]
/// (1, 4, 16, then 64 KiB), copying what it read and wiping the smaller span.
/// The cost of allocating, zeroing and wiping spans then follows the payload:
/// a single size leaves a cliff where a file just fills it.
pub(crate) const FIRST_FILL: usize = 1024;

/// How much a span grows each time a fill comes back full.
pub(crate) const SPAN_GROWTH: usize = 4;

// The decrypt framing needs spans that are whole blocks, and big enough to
// hold a block plus the trailer it holds back (48 bytes). Every size on the
// way from FIRST_FILL to SPAN is a whole number of blocks too.
const _: () = assert!(FIRST_FILL % 16 == 0 && FIRST_FILL >= 48 && FIRST_FILL <= SPAN);
const _: () = assert!(SPAN % 16 == 0 && SPAN_GROWTH >= 2);
