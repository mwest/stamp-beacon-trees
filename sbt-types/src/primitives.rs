//! Primitive cryptographic types

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A cryptographic digest (hash output)
/// Using BLAKE3 as the primary hash function (32 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest([u8; 32]);

// Custom serde implementation for Digest - serialize as hex for readability
impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        Self::from_hex(&hex_str).map_err(serde::de::Error::custom)
    }
}

impl Digest {
    pub const LEN: usize = 32;

    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != Self::LEN {
            return Err(Error::InvalidDigestLength {
                expected: Self::LEN,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Self::from_slice(&bytes)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A cryptographic signature (Ed25519)
#[derive(Clone, PartialEq, Eq)]
pub struct Signature([u8; 64]);

// Custom serde implementation for Signature since [u8; 64] doesn't implement Serialize/Deserialize
impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as hex string for readability and JSON compatibility
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        Self::from_hex(&hex_str).map_err(serde::de::Error::custom)
    }
}

impl Signature {
    pub const LEN: usize = 64;

    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != Self::LEN {
            return Err(Error::InvalidSignature);
        }
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Self::from_slice(&bytes)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({}...)", hex::encode(&self.0[..8]))
    }
}

/// A public key (Ed25519)
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

// Custom serde implementation for PublicKey - serialize as hex for readability
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        Self::from_hex(&hex_str).map_err(serde::de::Error::custom)
    }
}

impl PublicKey {
    pub const LEN: usize = 32;

    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != Self::LEN {
            return Err(Error::InvalidPublicKey);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Self::from_slice(&bytes)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A cryptographic nonce (32 bytes of randomness)
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Nonce([u8; 32]);

// Custom serde implementation for Nonce - serialize as hex for readability
impl Serialize for Nonce {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        Self::from_hex(&hex_str).map_err(serde::de::Error::custom)
    }
}

impl Nonce {
    pub const LEN: usize = 32;

    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != Self::LEN {
            return Err(Error::InvalidNonce);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Self::from_slice(&bytes)
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({}...)", hex::encode(&self.0[..8]))
    }
}

/// A timestamp with nanosecond precision
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timestamp {
    /// Seconds since UNIX epoch
    pub seconds: i64,
    /// Nanoseconds (0-999,999,999)
    pub nanos: u32,
}

impl Timestamp {
    pub fn new(seconds: i64, nanos: u32) -> Result<Self> {
        if nanos >= 1_000_000_000 {
            return Err(Error::InvalidTimestamp(
                "nanoseconds must be less than 1,000,000,000".to_string(),
            ));
        }
        Ok(Self { seconds, nanos })
    }

    pub fn now() -> Self {
        let now = chrono::Utc::now();
        Self {
            seconds: now.timestamp(),
            nanos: now.timestamp_subsec_nanos(),
        }
    }

    /// Add a delta in nanoseconds (can be negative)
    pub fn add_nanos(&self, delta_nanos: i64) -> Self {
        let total_nanos = (self.seconds as i128) * 1_000_000_000
            + (self.nanos as i128)
            + (delta_nanos as i128);

        let seconds = (total_nanos / 1_000_000_000) as i64;
        let nanos = (total_nanos % 1_000_000_000) as u32;

        Self { seconds, nanos }
    }

    /// Calculate difference in nanoseconds
    pub fn diff_nanos(&self, other: &Timestamp) -> i64 {
        let self_total = (self.seconds as i128) * 1_000_000_000 + (self.nanos as i128);
        let other_total = (other.seconds as i128) * 1_000_000_000 + (other.nanos as i128);
        (self_total - other_total) as i64
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({}.{:09})", self.seconds, self.nanos)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(dt) = chrono::DateTime::from_timestamp(self.seconds, self.nanos) {
            write!(f, "{}", dt.format("%Y-%m-%d %H:%M:%S%.9f UTC"))
        } else {
            write!(f, "{}.{:09}", self.seconds, self.nanos)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_digest_roundtrip() {
        let digest = Digest::new([42u8; 32]);
        let hex = digest.to_hex();
        let parsed = Digest::from_hex(&hex).unwrap();
        assert_eq!(digest, parsed);
    }

    #[test]
    fn test_timestamp_arithmetic() {
        let t1 = Timestamp::new(100, 500_000_000).unwrap();
        let t2 = t1.add_nanos(1_000_000_000);
        assert_eq!(t2.seconds, 101);
        assert_eq!(t2.nanos, 500_000_000);

        let diff = t2.diff_nanos(&t1);
        assert_eq!(diff, 1_000_000_000);
    }

    // === Proptest strategies ===

    prop_compose! {
        fn arb_digest()(bytes in prop::array::uniform32(any::<u8>())) -> Digest {
            Digest::new(bytes)
        }
    }

    prop_compose! {
        fn arb_nonce()(bytes in prop::array::uniform32(any::<u8>())) -> Nonce {
            Nonce::new(bytes)
        }
    }

    prop_compose! {
        fn arb_signature()(bytes in prop::collection::vec(any::<u8>(), 64)) -> Signature {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&bytes);
            Signature::new(arr)
        }
    }

    prop_compose! {
        fn arb_public_key()(bytes in prop::array::uniform32(any::<u8>())) -> PublicKey {
            PublicKey::new(bytes)
        }
    }

    prop_compose! {
        fn arb_timestamp()(
            seconds in 0i64..=4_000_000_000i64,
            nanos in 0u32..1_000_000_000u32
        ) -> Timestamp {
            Timestamp::new(seconds, nanos).unwrap()
        }
    }

    // === Serde JSON roundtrip ===

    proptest! {
        #[test]
        fn prop_digest_serde_roundtrip(d in arb_digest()) {
            let json = serde_json::to_string(&d).unwrap();
            let parsed: Digest = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(d, parsed);
        }

        #[test]
        fn prop_signature_serde_roundtrip(s in arb_signature()) {
            let json = serde_json::to_string(&s).unwrap();
            let parsed: Signature = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(s, parsed);
        }

        #[test]
        fn prop_public_key_serde_roundtrip(pk in arb_public_key()) {
            let json = serde_json::to_string(&pk).unwrap();
            let parsed: PublicKey = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(pk, parsed);
        }

        #[test]
        fn prop_nonce_serde_roundtrip(n in arb_nonce()) {
            let json = serde_json::to_string(&n).unwrap();
            let parsed: Nonce = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(n, parsed);
        }

        #[test]
        fn prop_timestamp_serde_roundtrip(ts in arb_timestamp()) {
            let json = serde_json::to_string(&ts).unwrap();
            let parsed: Timestamp = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(ts, parsed);
        }
    }

    // === Hex roundtrip ===

    proptest! {
        #[test]
        fn prop_digest_hex_roundtrip(d in arb_digest()) {
            let hex = d.to_hex();
            let parsed = Digest::from_hex(&hex).unwrap();
            prop_assert_eq!(d, parsed);
        }

        #[test]
        fn prop_signature_hex_roundtrip(s in arb_signature()) {
            let hex = s.to_hex();
            let parsed = Signature::from_hex(&hex).unwrap();
            prop_assert_eq!(s, parsed);
        }

        #[test]
        fn prop_public_key_hex_roundtrip(pk in arb_public_key()) {
            let hex = pk.to_hex();
            let parsed = PublicKey::from_hex(&hex).unwrap();
            prop_assert_eq!(pk, parsed);
        }

        #[test]
        fn prop_nonce_hex_roundtrip(n in arb_nonce()) {
            let hex = n.to_hex();
            let parsed = Nonce::from_hex(&hex).unwrap();
            prop_assert_eq!(n, parsed);
        }
    }

    // === Timestamp arithmetic properties ===

    proptest! {
        #[test]
        fn prop_timestamp_add_nanos_roundtrip(
            ts in arb_timestamp(),
            delta in -1_000_000_000_000i64..1_000_000_000_000i64
        ) {
            let added = ts.add_nanos(delta);
            let diff = added.diff_nanos(&ts);
            prop_assert_eq!(diff, delta);
        }

        #[test]
        fn prop_timestamp_add_zero_identity(ts in arb_timestamp()) {
            let same = ts.add_nanos(0);
            prop_assert_eq!(ts.seconds, same.seconds);
            prop_assert_eq!(ts.nanos, same.nanos);
        }

        #[test]
        fn prop_timestamp_diff_self_is_zero(ts in arb_timestamp()) {
            prop_assert_eq!(ts.diff_nanos(&ts), 0);
        }

        #[test]
        fn prop_timestamp_invalid_nanos(seconds in any::<i64>(), nanos in 1_000_000_000u32..) {
            prop_assert!(Timestamp::new(seconds, nanos).is_err());
        }
    }

    // === from_slice length validation (fuzzing) ===

    proptest! {
        #[test]
        fn prop_digest_from_slice_validates_len(bytes in prop::collection::vec(any::<u8>(), 0..128)) {
            if bytes.len() != 32 {
                prop_assert!(Digest::from_slice(&bytes).is_err());
            } else {
                prop_assert!(Digest::from_slice(&bytes).is_ok());
            }
        }

        #[test]
        fn prop_signature_from_slice_validates_len(bytes in prop::collection::vec(any::<u8>(), 0..128)) {
            if bytes.len() != 64 {
                prop_assert!(Signature::from_slice(&bytes).is_err());
            } else {
                prop_assert!(Signature::from_slice(&bytes).is_ok());
            }
        }

        #[test]
        fn prop_public_key_from_slice_validates_len(bytes in prop::collection::vec(any::<u8>(), 0..128)) {
            if bytes.len() != 32 {
                prop_assert!(PublicKey::from_slice(&bytes).is_err());
            } else {
                prop_assert!(PublicKey::from_slice(&bytes).is_ok());
            }
        }

        #[test]
        fn prop_nonce_from_slice_validates_len(bytes in prop::collection::vec(any::<u8>(), 0..128)) {
            if bytes.len() != 32 {
                prop_assert!(Nonce::from_slice(&bytes).is_err());
            } else {
                prop_assert!(Nonce::from_slice(&bytes).is_ok());
            }
        }

        #[test]
        fn prop_digest_from_hex_validates(s in "[0-9a-fA-F]{0,100}") {
            match Digest::from_hex(&s) {
                Ok(_) => prop_assert_eq!(s.len(), 64),
                Err(_) => prop_assert_ne!(s.len(), 64),
            }
        }
    }
}
