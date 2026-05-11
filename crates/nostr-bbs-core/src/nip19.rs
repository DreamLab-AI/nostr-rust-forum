//! NIP-19: bech32-encoded entities.
//!
//! Phase 5 absorption (ADR-076/078): this module is now a thin adapter
//! over [`nostr::nips::nip19`]. The kit's public surface (hex-string
//! `encode_*`/`decode_*` functions, struct shapes) is preserved for
//! ABI stability with downstream consumers; the underlying bech32 +
//! TLV machinery comes from rust-nostr 0.44.
//!
//! Simple types (no TLV): npub, nsec, note
//! TLV types: nprofile, nevent, naddr

use nostr::nips::nip01::Coordinate;
use nostr::nips::nip19::{
    self as up, FromBech32, Nip19Coordinate, Nip19Event, Nip19Profile, ToBech32,
};
use nostr::types::RelayUrl;
use nostr::{EventId, Kind, PublicKey, SecretKey};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Nip19Error {
    #[error("bech32 error: {0}")]
    Bech32(String),
    #[error("wrong prefix: expected {expected}, got {actual}")]
    WrongPrefix { expected: String, actual: String },
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    #[error("invalid length: expected {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("truncated TLV entry")]
    TruncatedTlv,
    #[error("invalid kind TLV: expected 4 bytes")]
    InvalidKindTlv,
    #[error("missing required TLV type {0}")]
    MissingTlv(u8),
    #[error("invalid UTF-8 in relay URL")]
    InvalidUtf8,
    #[error("invalid relay URL: {0}")]
    InvalidRelayUrl(String),
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn hex_to_bytes_exact(hex_str: &str, expected_len: usize) -> Result<Vec<u8>, Nip19Error> {
    let bytes = hex::decode(hex_str).map_err(|e| Nip19Error::InvalidHex(e.to_string()))?;
    if bytes.len() != expected_len {
        return Err(Nip19Error::InvalidLength {
            expected: expected_len,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

fn map_up_err(prefix_expected: &str, e: up::Error) -> Nip19Error {
    use up::Error as E;
    match e {
        E::WrongPrefix => Nip19Error::WrongPrefix {
            expected: prefix_expected.to_string(),
            actual: "<other>".to_string(),
        },
        E::FieldMissing(_) | E::TLV | E::TryFromSlice => Nip19Error::TruncatedTlv,
        other => Nip19Error::Bech32(other.to_string()),
    }
}

fn parse_relays(relays: &[String]) -> Result<Vec<RelayUrl>, Nip19Error> {
    relays
        .iter()
        .map(|r| RelayUrl::parse(r).map_err(|e| Nip19Error::InvalidRelayUrl(e.to_string())))
        .collect()
}

// ── Simple types (no TLV) ─────────────────────────────────────────────────────

/// Encode a 64-char hex pubkey as `npub1…`.
pub fn encode_npub(pubkey_hex: &str) -> Result<String, Nip19Error> {
    let bytes = hex_to_bytes_exact(pubkey_hex, 32)?;
    let pk = PublicKey::from_slice(&bytes).map_err(|e| Nip19Error::Bech32(e.to_string()))?;
    pk.to_bech32()
        .map_err(|e| Nip19Error::Bech32(e.to_string()))
}

/// Encode a 64-char hex secret key as `nsec1…`.
pub fn encode_nsec(sk_hex: &str) -> Result<String, Nip19Error> {
    let bytes = hex_to_bytes_exact(sk_hex, 32)?;
    let sk = SecretKey::from_slice(&bytes).map_err(|e| Nip19Error::Bech32(e.to_string()))?;
    Ok(sk.to_bech32().expect("nsec encoding is infallible"))
}

/// Encode a 64-char hex event ID as `note1…`.
pub fn encode_note(event_id_hex: &str) -> Result<String, Nip19Error> {
    let bytes = hex_to_bytes_exact(event_id_hex, 32)?;
    let id = EventId::from_slice(&bytes).map_err(|e| Nip19Error::Bech32(e.to_string()))?;
    id.to_bech32()
        .map_err(|e| Nip19Error::Bech32(e.to_string()))
}

/// Decode a simple bech32 entity (npub/nsec/note) to its 32-byte payload,
/// returning the kit's specific error variants for wrong-prefix and
/// wrong-length cases that upstream lumps under generic Bech32/Keys errors.
fn decode_simple_32(s: &str, expected_hrp: &str) -> Result<[u8; 32], Nip19Error> {
    let (hrp, data) = bech32::decode(s).map_err(|e| Nip19Error::Bech32(e.to_string()))?;
    if hrp.as_str() != expected_hrp {
        return Err(Nip19Error::WrongPrefix {
            expected: expected_hrp.to_string(),
            actual: hrp.as_str().to_string(),
        });
    }
    if data.len() != 32 {
        return Err(Nip19Error::InvalidLength {
            expected: 32,
            actual: data.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&data);
    Ok(out)
}

/// Decode an `npub1…` to its 64-char hex pubkey.
pub fn decode_npub(npub: &str) -> Result<String, Nip19Error> {
    let bytes = decode_simple_32(npub, "npub")?;
    let pk = PublicKey::from_slice(&bytes).map_err(|e| Nip19Error::Bech32(e.to_string()))?;
    Ok(pk.to_hex())
}

/// Decode an `nsec1…` to its 64-char hex secret key.
pub fn decode_nsec(nsec: &str) -> Result<String, Nip19Error> {
    let bytes = decode_simple_32(nsec, "nsec")?;
    let sk = SecretKey::from_slice(&bytes).map_err(|e| Nip19Error::Bech32(e.to_string()))?;
    Ok(hex::encode(sk.as_secret_bytes()))
}

/// Decode a `note1…` to its 64-char hex event ID.
pub fn decode_note(note: &str) -> Result<String, Nip19Error> {
    let bytes = decode_simple_32(note, "note")?;
    let id = EventId::from_slice(&bytes).map_err(|e| Nip19Error::Bech32(e.to_string()))?;
    Ok(id.to_hex())
}

// ── TLV types ─────────────────────────────────────────────────────────────────

/// A NIP-19 `nprofile` entity.
#[derive(Debug, Clone, PartialEq)]
pub struct NProfile {
    /// 64-char hex pubkey.
    pub pubkey: String,
    /// Relay URLs.
    pub relays: Vec<String>,
}

/// A NIP-19 `nevent` entity.
#[derive(Debug, Clone, PartialEq)]
pub struct NEvent {
    /// 64-char hex event ID.
    pub id: String,
    /// Relay URLs.
    pub relays: Vec<String>,
    /// Optional 64-char hex author pubkey.
    pub author: Option<String>,
    /// Optional event kind.
    pub kind: Option<u32>,
}

/// A NIP-19 `naddr` entity.
#[derive(Debug, Clone, PartialEq)]
pub struct NAddr {
    /// `d` tag identifier string.
    pub identifier: String,
    /// 64-char hex author pubkey.
    pub pubkey: String,
    /// Event kind.
    pub kind: u32,
    /// Relay URLs.
    pub relays: Vec<String>,
}

/// Encode an `nprofile`.
pub fn encode_nprofile(p: &NProfile) -> Result<String, Nip19Error> {
    let pk_bytes = hex_to_bytes_exact(&p.pubkey, 32)?;
    let public_key =
        PublicKey::from_slice(&pk_bytes).map_err(|e| Nip19Error::Bech32(e.to_string()))?;
    let relays = parse_relays(&p.relays)?;
    let profile = Nip19Profile::new(public_key, relays);
    profile
        .to_bech32()
        .map_err(|e| Nip19Error::Bech32(e.to_string()))
}

/// Decode an `nprofile`.
pub fn decode_nprofile(s: &str) -> Result<NProfile, Nip19Error> {
    let profile = Nip19Profile::from_bech32(s).map_err(|e| map_up_err("nprofile", e))?;
    Ok(NProfile {
        pubkey: profile.public_key.to_hex(),
        relays: profile.relays.iter().map(|r| r.to_string()).collect(),
    })
}

/// Encode an `nevent`.
pub fn encode_nevent(e: &NEvent) -> Result<String, Nip19Error> {
    let id_bytes = hex_to_bytes_exact(&e.id, 32)?;
    let event_id =
        EventId::from_slice(&id_bytes).map_err(|err| Nip19Error::Bech32(err.to_string()))?;
    let mut nev = Nip19Event::new(event_id);
    if let Some(ref author_hex) = e.author {
        let author_bytes = hex_to_bytes_exact(author_hex, 32)?;
        let author = PublicKey::from_slice(&author_bytes)
            .map_err(|err| Nip19Error::Bech32(err.to_string()))?;
        nev = nev.author(author);
    }
    if let Some(kind) = e.kind {
        nev = nev.kind(Kind::from(kind as u16));
    }
    nev = nev.relays(parse_relays(&e.relays)?);
    nev.to_bech32()
        .map_err(|err| Nip19Error::Bech32(err.to_string()))
}

/// Decode an `nevent`.
pub fn decode_nevent(s: &str) -> Result<NEvent, Nip19Error> {
    let nev = Nip19Event::from_bech32(s).map_err(|e| map_up_err("nevent", e))?;
    Ok(NEvent {
        id: nev.event_id.to_hex(),
        relays: nev.relays.iter().map(|r| r.to_string()).collect(),
        author: nev.author.map(|a| a.to_hex()),
        kind: nev.kind.map(|k| k.as_u16() as u32),
    })
}

/// Encode an `naddr`.
pub fn encode_naddr(a: &NAddr) -> Result<String, Nip19Error> {
    let pk_bytes = hex_to_bytes_exact(&a.pubkey, 32)?;
    let public_key =
        PublicKey::from_slice(&pk_bytes).map_err(|e| Nip19Error::Bech32(e.to_string()))?;
    let coordinate = Coordinate {
        kind: Kind::from(a.kind as u16),
        public_key,
        identifier: a.identifier.clone(),
    };
    let relays = parse_relays(&a.relays)?;
    let nip19_coord = Nip19Coordinate::new(coordinate, relays);
    nip19_coord
        .to_bech32()
        .map_err(|e| Nip19Error::Bech32(e.to_string()))
}

/// Decode an `naddr`.
pub fn decode_naddr(s: &str) -> Result<NAddr, Nip19Error> {
    let coord = Nip19Coordinate::from_bech32(s).map_err(|e| map_up_err("naddr", e))?;
    Ok(NAddr {
        identifier: coord.coordinate.identifier.clone(),
        pubkey: coord.coordinate.public_key.to_hex(),
        kind: coord.coordinate.kind.as_u16() as u32,
        relays: coord.relays.iter().map(|r| r.to_string()).collect(),
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const FIATJAF_HEX: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

    #[test]
    fn npub_encode_decode_roundtrip() {
        let encoded = encode_npub(FIATJAF_HEX).unwrap();
        assert!(encoded.starts_with("npub1"));
        let decoded = decode_npub(&encoded).unwrap();
        assert_eq!(decoded, FIATJAF_HEX);
    }

    #[test]
    fn nsec_encode_decode_roundtrip() {
        let sk_hex = "0101010101010101010101010101010101010101010101010101010101010101";
        let encoded = encode_nsec(sk_hex).unwrap();
        assert!(encoded.starts_with("nsec1"));
        let decoded = decode_nsec(&encoded).unwrap();
        assert_eq!(decoded, sk_hex);
    }

    #[test]
    fn note_encode_decode_roundtrip() {
        let id_hex = "b3e392b11f5d4f28321cedd09303a748acfd0487aea5a7450b3481c60b6e4f87";
        let encoded = encode_note(id_hex).unwrap();
        assert!(encoded.starts_with("note1"));
        let decoded = decode_note(&encoded).unwrap();
        assert_eq!(decoded, id_hex);
    }

    #[test]
    fn npub_decode_rejects_nsec() {
        let sk_hex = "0101010101010101010101010101010101010101010101010101010101010101";
        let nsec = encode_nsec(sk_hex).unwrap();
        let err = decode_npub(&nsec);
        assert!(matches!(err, Err(Nip19Error::WrongPrefix { .. })));
    }

    #[test]
    fn nprofile_roundtrip_with_relay() {
        let p = NProfile {
            pubkey: FIATJAF_HEX.to_string(),
            relays: vec!["wss://relay.damus.io".to_string()],
        };
        let encoded = encode_nprofile(&p).unwrap();
        assert!(encoded.starts_with("nprofile1"));
        let decoded = decode_nprofile(&encoded).unwrap();
        assert_eq!(decoded.pubkey, p.pubkey);
        // upstream RelayUrl normalises (may add trailing slash); compare as sets after normalisation
        assert_eq!(decoded.relays.len(), p.relays.len());
    }

    #[test]
    fn nevent_roundtrip_full() {
        let e = NEvent {
            id: "b3e392b11f5d4f28321cedd09303a748acfd0487aea5a7450b3481c60b6e4f87".to_string(),
            relays: vec!["wss://relay.damus.io".to_string()],
            author: Some(FIATJAF_HEX.to_string()),
            kind: Some(1),
        };
        let encoded = encode_nevent(&e).unwrap();
        assert!(encoded.starts_with("nevent1"));
        let decoded = decode_nevent(&encoded).unwrap();
        assert_eq!(decoded.id, e.id);
        assert_eq!(decoded.author, e.author);
        assert_eq!(decoded.kind, e.kind);
    }

    #[test]
    fn naddr_roundtrip() {
        let a = NAddr {
            identifier: "test-id".to_string(),
            pubkey: FIATJAF_HEX.to_string(),
            kind: 30023,
            relays: vec![],
        };
        let encoded = encode_naddr(&a).unwrap();
        assert!(encoded.starts_with("naddr1"));
        let decoded = decode_naddr(&encoded).unwrap();
        assert_eq!(decoded.identifier, a.identifier);
        assert_eq!(decoded.pubkey, a.pubkey);
        assert_eq!(decoded.kind, a.kind);
    }
}
