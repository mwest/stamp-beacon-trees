//! Cryptographic nonce generation

use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;
use sbt_types::Nonce;

/// Generator for cryptographically secure random nonces.
///
/// Uses `StdRng` seeded from OS entropy, which is cryptographically secure
/// and implements `Send` for use across threads.
pub struct NonceGenerator {
    rng: StdRng,
}

impl NonceGenerator {
    pub fn new() -> Self {
        Self {
            rng: StdRng::from_entropy(),
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
