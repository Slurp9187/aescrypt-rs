use rand::{rngs::OsRng, TryRngCore};

/// A cryptographically secure RNG wrapper for encryption streams.
#[derive(Debug)]
pub struct SecureRng {
    rng: OsRng,
}

impl SecureRng {
    /// Create a new secure RNG instance.
    #[inline]
    pub fn new() -> Self {
        Self { rng: OsRng }
    }

    /// Generate a 16-byte IV (e.g. AES-GCM nonce)
    #[inline]
    pub fn iv_16(&mut self) -> [u8; 16] {
        self.fill_array()
    }

    /// Generate a 32-byte key (AES-256)
    #[inline]
    pub fn key_32(&mut self) -> [u8; 32] {
        self.fill_array()
    }

    /// Generate a 64-byte key
    #[inline]
    pub fn key_64(&mut self) -> [u8; 64] {
        self.fill_array()
    }

    /// Generate a 12-byte nonce (common in XChaCha20)
    #[inline]
    pub fn nonce_12(&mut self) -> [u8; 12] {
        self.fill_array()
    }

    /// Generic: fill any fixed-size array
    #[inline]
    fn fill_array<const N: usize>(&mut self) -> [u8; N] {
        let mut arr = [0u8; N];
        self.rng
            .try_fill_bytes(&mut arr)
            .expect("OsRng failed — system entropy exhausted");
        arr
    }
}

// Optional: Default impl so you can do `SecureRng::default()`
impl Default for SecureRng {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
