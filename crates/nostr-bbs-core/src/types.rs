use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("invalid hex length")]
    InvalidLength,
    #[error("invalid hex encoding")]
    InvalidHex,
    #[error("invalid secp256k1 scalar")]
    InvalidScalar,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RelayUrlError {
    #[error("relay URL must start with ws:// or wss://")]
    InvalidScheme,
}

// ---------------------------------------------------------------------------
// EventId — SHA-256 of NIP-01 canonical JSON
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventId([u8; 32]);

impl EventId {
    /// Compute the event ID from NIP-01 canonical JSON:
    /// `[0, <pubkey_hex>, <created_at>, <kind>, <tags>, <content>]`
    pub fn compute(
        pubkey: &PublicKey,
        created_at: Timestamp,
        kind: u32,
        tags: &[Tag],
        content: &str,
    ) -> Self {
        let canonical = serde_json::to_string(&(
            0u8,
            pubkey.as_hex(),
            created_at.as_secs(),
            kind,
            tags,
            content,
        ))
        .expect("canonical JSON serialization cannot fail");
        let hash = Sha256::digest(canonical.as_bytes());
        Self(hash.into())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, KeyError> {
        if hex_str.len() != 64 {
            return Err(KeyError::InvalidLength);
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut bytes).map_err(|_| KeyError::InvalidHex)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventId({})", self.as_hex())
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_hex())
    }
}

impl Serialize for EventId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_hex())
    }
}

impl<'de> Deserialize<'de> for EventId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// PublicKey — 32-byte x-only secp256k1 key (BIP-340)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn from_hex(hex_str: &str) -> Result<Self, KeyError> {
        if hex_str.len() != 64 {
            return Err(KeyError::InvalidLength);
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut bytes).map_err(|_| KeyError::InvalidHex)?;
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.as_hex())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_hex())
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_hex())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Signature — 64-byte Schnorr BIP-340
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    pub fn from_hex(hex_str: &str) -> Result<Self, KeyError> {
        if hex_str.len() != 128 {
            return Err(KeyError::InvalidLength);
        }
        let mut bytes = [0u8; 64];
        hex::decode_to_slice(hex_str, &mut bytes).map_err(|_| KeyError::InvalidHex)?;
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({}..)", &self.as_hex()[..16])
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_hex())
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_hex())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Timestamp — Unix seconds
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(u64);

impl Timestamp {
    pub fn from_secs(secs: u64) -> Self {
        Self(secs)
    }

    pub fn as_secs(&self) -> u64 {
        self.0
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn now() -> Self {
        use std::time::SystemTime;
        let secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_secs();
        Self(secs)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Tag — Nostr event tag (string array)
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Tag(pub Vec<String>);

impl Tag {
    pub fn new(values: Vec<String>) -> Self {
        Self(values)
    }

    pub fn name(&self) -> &str {
        self.0.first().map(|s| s.as_str()).unwrap_or("")
    }

    pub fn value(&self) -> Option<&str> {
        self.0.get(1).map(|s| s.as_str())
    }

    pub fn extra(&self, index: usize) -> Option<&str> {
        self.0.get(index).map(|s| s.as_str())
    }

    // Factory methods for common tag types

    /// `["e", <event_id_hex>]` — event reference
    pub fn event_ref(id: &EventId) -> Self {
        Self(vec!["e".into(), id.as_hex()])
    }

    /// `["e", <event_id_hex>, <relay_url>, <marker>]` — event reference with relay hint
    pub fn event_ref_full(id: &EventId, relay_url: &str, marker: &str) -> Self {
        Self(vec![
            "e".into(),
            id.as_hex(),
            relay_url.into(),
            marker.into(),
        ])
    }

    /// `["p", <pubkey_hex>]` — pubkey reference
    pub fn pubkey_ref(pk: &PublicKey) -> Self {
        Self(vec!["p".into(), pk.as_hex()])
    }

    /// `["t", <hashtag>]` — hashtag
    pub fn hashtag(tag: &str) -> Self {
        Self(vec!["t".into(), tag.into()])
    }

    /// `["d", <identifier>]` — parameterized replaceable identifier
    pub fn identifier(d: &str) -> Self {
        Self(vec!["d".into(), d.into()])
    }

    /// `["u", <url>]` — URL (NIP-98)
    pub fn url(url: &str) -> Self {
        Self(vec!["u".into(), url.into()])
    }

    /// `["method", <method>]` — HTTP method (NIP-98)
    pub fn method(method: &str) -> Self {
        Self(vec!["method".into(), method.into()])
    }

    /// `["payload", <sha256_hex>]` — body hash (NIP-98)
    pub fn payload(sha256_hex: &str) -> Self {
        Self(vec!["payload".into(), sha256_hex.into()])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_id_from_hex_roundtrip() {
        let hex_str = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
        let id = EventId::from_hex(hex_str).unwrap();
        assert_eq!(id.as_hex(), hex_str);
    }

    #[test]
    fn event_id_rejects_short_hex() {
        assert_eq!(
            EventId::from_hex("abcd").unwrap_err(),
            KeyError::InvalidLength
        );
    }

    #[test]
    fn event_id_rejects_invalid_hex() {
        let bad = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert_eq!(EventId::from_hex(bad).unwrap_err(), KeyError::InvalidHex);
    }

    #[test]
    fn pubkey_from_hex_roundtrip() {
        let hex_str = "11ed64225dd5e2c5e18f61ad43d5ad9272d08739d3a20dd25886197b0738663c";
        let pk = PublicKey::from_hex(hex_str).unwrap();
        assert_eq!(pk.as_hex(), hex_str);
        assert_eq!(pk.as_bytes().len(), 32);
    }

    #[test]
    fn signature_from_hex_roundtrip() {
        let hex_str = "a".repeat(128);
        let sig = Signature::from_hex(&hex_str).unwrap();
        assert_eq!(sig.as_hex(), hex_str);
    }

    #[test]
    fn timestamp_ordering() {
        let t1 = Timestamp::from_secs(100);
        let t2 = Timestamp::from_secs(200);
        assert!(t1 < t2);
    }

    #[test]
    fn tag_event_ref() {
        let id =
            EventId::from_hex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
                .unwrap();
        let tag = Tag::event_ref(&id);
        assert_eq!(tag.name(), "e");
        assert_eq!(
            tag.value().unwrap(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
    }

    #[test]
    fn tag_pubkey_ref() {
        let pk =
            PublicKey::from_hex("11ed64225dd5e2c5e18f61ad43d5ad9272d08739d3a20dd25886197b0738663c")
                .unwrap();
        let tag = Tag::pubkey_ref(&pk);
        assert_eq!(tag.name(), "p");
        assert_eq!(
            tag.value().unwrap(),
            "11ed64225dd5e2c5e18f61ad43d5ad9272d08739d3a20dd25886197b0738663c"
        );
    }

    #[test]
    fn tag_hashtag() {
        let tag = Tag::hashtag("nostr");
        assert_eq!(tag.name(), "t");
        assert_eq!(tag.value().unwrap(), "nostr");
    }

    #[test]
    fn tag_nip98_fields() {
        let tag_u = Tag::url("https://example.com/api");
        assert_eq!(tag_u.name(), "u");
        let tag_m = Tag::method("POST");
        assert_eq!(tag_m.name(), "method");
        let tag_p = Tag::payload("abc123");
        assert_eq!(tag_p.name(), "payload");
    }

    #[test]
    fn pubkey_serde_json_roundtrip() {
        let pk =
            PublicKey::from_hex("11ed64225dd5e2c5e18f61ad43d5ad9272d08739d3a20dd25886197b0738663c")
                .unwrap();
        let json = serde_json::to_string(&pk).unwrap();
        assert_eq!(
            json,
            "\"11ed64225dd5e2c5e18f61ad43d5ad9272d08739d3a20dd25886197b0738663c\""
        );
        let pk2: PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn event_id_serde_json_roundtrip() {
        let id =
            EventId::from_hex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
                .unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let id2: EventId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn tag_serde_json() {
        let tag = Tag::new(vec!["e".into(), "abc".into(), "wss://relay".into()]);
        let json = serde_json::to_string(&tag).unwrap();
        assert_eq!(json, r#"["e","abc","wss://relay"]"#);
        let tag2: Tag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag, tag2);
    }
}
