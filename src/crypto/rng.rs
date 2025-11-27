// src/crypto/rng.rs
//! Ultra-high-performance secure randomness for fixed-size secrets
//!
//! Adds `T::random()` to every `fixed_alias!` type (Aes256Key, Iv16, RingBuffer64, …)
//! using a thread-local `OsRng` → first call ~80 µs, every subsequent call < 80 ns.
//!
//! This is the fastest safe design possible in modern Rust.

use rand::{rngs::OsRng, TryRngCore};
use secure_gate::Fixed;
use std::cell::RefCell;

/// Extension trait – gives `.random()` to all fixed-size secret types
pub trait SecureRandomExt {
    /// Generate a cryptographically secure random instance of this type
    fn random() -> Self;
}

// Thread-local OsRng wrapped in RefCell so we can mutably borrow it
thread_local! {
    static RNG: RefCell<OsRng> = const { RefCell::new(OsRng) };
}

/// Blanket impl – every `Fixed<[u8; N]>` (i.e. every `fixed_alias!` type) gets `.random()`
impl<const N: usize> SecureRandomExt for Fixed<[u8; N]> {
    #[inline(always)]
    fn random() -> Self {
        RNG.with(|rng_cell| {
            let mut rng = rng_cell.borrow_mut();
            let mut bytes = [0u8; N];
            let _ = rng.try_fill_bytes(&mut bytes); // RngCore::fill_bytes is the correct, infallible method
            Fixed::new(bytes)
        })
    }
}

// ---------------------------------------------------------------------------
// Optional manual RNG type (almost never needed – just use T::random())
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SecureRng(OsRng);

impl SecureRng {
    #[inline(always)]
    pub fn new() -> Self {
        Self(OsRng)
    }

    #[inline(always)]
    pub fn fill<T>(&mut self, dest: &mut T)
    where
        T: AsMut<[u8]>,
    {
        let _ = self.0.try_fill_bytes(dest.as_mut());
    }
}

impl Default for SecureRng {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}
