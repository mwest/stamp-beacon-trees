//! Cryptographic nonce generation

use rand::RngCore;
use sbt_types::Nonce;

/// Generator for cryptographically secure random nonces.
///
/// Uses `ThreadRng` which is cryptographically secure (backed by the OS CSPRNG).
///
/// # Thread Safety
///
/// `ThreadRng` is not `Send` or `Sync`, so this generator cannot be shared
/// directly across threads. For multi-threaded use, wrap in `Arc<Mutex<NonceGenerator>>`
/// or create a separate generator per thread.
pub struct NonceGenerator {
    rng: rand::rngs::ThreadRng,
}

impl NonceGenerator {
    pub fn new() -> Self {
        Self {
            rng: rand::thread_rng(),
        }
    }

    /// Generate a new random nonce
    pub fn generate(&mut self) -> Nonce {
        let mut bytes = [0u8; 32];
        self.rng.fill_bytes(&mut bytes);
        Nonce::new(bytes)
    }
}

impl Default for NonceGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generation() {
        let mut gen = NonceGenerator::new();
        let nonce1 = gen.generate();
        let nonce2 = gen.generate();

        // Nonces should be different (with overwhelming probability)
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_many_nonces() {
        let mut gen = NonceGenerator::new();
        let mut nonces = std::collections::HashSet::new();

        for _ in 0..1000 {
            let nonce = gen.generate();
            assert!(nonces.insert(nonce), "Duplicate nonce generated");
        }
    }
}
