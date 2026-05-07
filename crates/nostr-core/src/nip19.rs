//! NIP-19: bech32-encoded entities.
//!
//! Simple types (no TLV): npub, nsec, note
//! TLV types: nprofile, nevent, naddr
//!
//! TLV type bytes:
//! - 0 = special (pubkey / id / d-tag identifier)
//! - 1 = relay URL
//! - 2 = author pubkey
//! - 3 = kind (4 BE bytes)

use bech32::{Bech32, Hrp};
use thiserror::Error;

// ── HRP constants ─────────────────────────────────────────────────────────────

const HRP_NPUB: &str = "npub";
const HRP_NSEC: &str = "nsec";
const HRP_NOTE: &str = "note";
const HRP_NPROFILE: &str = "nprofile";
const HRP_NEVENT: &str = "nevent";
const HRP_NADDR: &str = "naddr";

// ── TLV type bytes ─────────────────────────────────────────────────────────────

const TLV_SPECIAL: u8 = 0;
const TLV_RELAY: u8 = 1;
const TLV_AUTHOR: u8 = 2;
const TLV_KIND: u8 = 3;

// ── Error type ─────────────────────────────────────────────────────────────────

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
}

// ── Simple types (no TLV) ──────────────────────────────────────────────────────

/// Encode a 64-char hex pubkey as `npub1…`.
pub fn encode_npub(pubkey_hex: &str) -> Result<String, Nip19Error> {
    let bytes = hex_to_bytes_exact(pubkey_hex, 32)?;
    bech32_encode(HRP_NPUB, &bytes)
}

/// Encode a 64-char hex secret key as `nsec1…`.
pub fn encode_nsec(sk_hex: &str) -> Result<String, Nip19Error> {
    let bytes = hex_to_bytes_exact(sk_hex, 32)?;
    bech32_encode(HRP_NSEC, &bytes)
}

/// Encode a 64-char hex event ID as `note1…`.
pub fn encode_note(event_id_hex: &str) -> Result<String, Nip19Error> {
    let bytes = hex_to_bytes_exact(event_id_hex, 32)?;
    bech32_encode(HRP_NOTE, &bytes)
}

/// Decode `npub1…` → 64-char lowercase hex pubkey.
pub fn decode_npub(npub: &str) -> Result<String, Nip19Error> {
    let bytes = bech32_decode_exact(npub, HRP_NPUB, 32)?;
    Ok(hex::encode(bytes))
}

/// Decode `nsec1…` → 64-char lowercase hex secret key.
pub fn decode_nsec(nsec: &str) -> Result<String, Nip19Error> {
    let bytes = bech32_decode_exact(nsec, HRP_NSEC, 32)?;
    Ok(hex::encode(bytes))
}

/// Decode `note1…` → 64-char lowercase hex event ID.
pub fn decode_note(note: &str) -> Result<String, Nip19Error> {
    let bytes = bech32_decode_exact(note, HRP_NOTE, 32)?;
    Ok(hex::encode(bytes))
}

// ── TLV types ──────────────────────────────────────────────────────────────────

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
    let mut buf = Vec::new();
    let pk_bytes = hex_to_bytes_exact(&p.pubkey, 32)?;
    push_tlv(&mut buf, TLV_SPECIAL, &pk_bytes);
    for relay in &p.relays {
        push_tlv(&mut buf, TLV_RELAY, relay.as_bytes());
    }
    bech32_encode(HRP_NPROFILE, &buf)
}

/// Decode an `nprofile`.
pub fn decode_nprofile(s: &str) -> Result<NProfile, Nip19Error> {
    let bytes = bech32_decode_raw(s, HRP_NPROFILE)?;
    let entries = parse_tlv(&bytes)?;

    let pk_bytes = find_tlv_required(&entries, TLV_SPECIAL)?;
    if pk_bytes.len() != 32 {
        return Err(Nip19Error::InvalidLength {
            expected: 32,
            actual: pk_bytes.len(),
        });
    }
    let pubkey = hex::encode(&pk_bytes);
    let relays = collect_relays(&entries)?;

    Ok(NProfile { pubkey, relays })
}

/// Encode an `nevent`.
pub fn encode_nevent(e: &NEvent) -> Result<String, Nip19Error> {
    let mut buf = Vec::new();
    let id_bytes = hex_to_bytes_exact(&e.id, 32)?;
    push_tlv(&mut buf, TLV_SPECIAL, &id_bytes);
    for relay in &e.relays {
        push_tlv(&mut buf, TLV_RELAY, relay.as_bytes());
    }
    if let Some(ref author) = e.author {
        let author_bytes = hex_to_bytes_exact(author, 32)?;
        push_tlv(&mut buf, TLV_AUTHOR, &author_bytes);
    }
    if let Some(kind) = e.kind {
        push_tlv(&mut buf, TLV_KIND, &kind.to_be_bytes());
    }
    bech32_encode(HRP_NEVENT, &buf)
}

/// Decode an `nevent`.
pub fn decode_nevent(s: &str) -> Result<NEvent, Nip19Error> {
    let bytes = bech32_decode_raw(s, HRP_NEVENT)?;
    let entries = parse_tlv(&bytes)?;

    let id_bytes = find_tlv_required(&entries, TLV_SPECIAL)?;
    if id_bytes.len() != 32 {
        return Err(Nip19Error::InvalidLength {
            expected: 32,
            actual: id_bytes.len(),
        });
    }
    let id = hex::encode(&id_bytes);
    let relays = collect_relays(&entries)?;

    let author = find_tlv_first(&entries, TLV_AUTHOR)
        .map(|b| {
            if b.len() != 32 {
                Err(Nip19Error::InvalidLength {
                    expected: 32,
                    actual: b.len(),
                })
            } else {
                Ok(hex::encode(&b))
            }
        })
        .transpose()?;

    let kind = find_tlv_first(&entries, TLV_KIND)
        .map(|b| {
            if b.len() != 4 {
                Err(Nip19Error::InvalidKindTlv)
            } else {
                let arr: [u8; 4] = b.try_into().expect("length checked");
                Ok(u32::from_be_bytes(arr))
            }
        })
        .transpose()?;

    Ok(NEvent {
        id,
        relays,
        author,
        kind,
    })
}

/// Encode an `naddr`.
pub fn encode_naddr(a: &NAddr) -> Result<String, Nip19Error> {
    let mut buf = Vec::new();
    // TLV 0: d-tag identifier (empty is valid for kind 0)
    push_tlv(&mut buf, TLV_SPECIAL, a.identifier.as_bytes());
    for relay in &a.relays {
        push_tlv(&mut buf, TLV_RELAY, relay.as_bytes());
    }
    let author_bytes = hex_to_bytes_exact(&a.pubkey, 32)?;
    push_tlv(&mut buf, TLV_AUTHOR, &author_bytes);
    push_tlv(&mut buf, TLV_KIND, &a.kind.to_be_bytes());
    bech32_encode(HRP_NADDR, &buf)
}

/// Decode an `naddr`.
pub fn decode_naddr(s: &str) -> Result<NAddr, Nip19Error> {
    let bytes = bech32_decode_raw(s, HRP_NADDR)?;
    let entries = parse_tlv(&bytes)?;

    let id_bytes = find_tlv_required(&entries, TLV_SPECIAL)?;
    let identifier = String::from_utf8(id_bytes).map_err(|_| Nip19Error::InvalidUtf8)?;

    let relays = collect_relays(&entries)?;

    let author_bytes = find_tlv_required(&entries, TLV_AUTHOR)?;
    if author_bytes.len() != 32 {
        return Err(Nip19Error::InvalidLength {
            expected: 32,
            actual: author_bytes.len(),
        });
    }
    let pubkey = hex::encode(&author_bytes);

    let kind_bytes = find_tlv_required(&entries, TLV_KIND)?;
    if kind_bytes.len() != 4 {
        return Err(Nip19Error::InvalidKindTlv);
    }
    let kind_arr: [u8; 4] = kind_bytes.try_into().expect("length checked");
    let kind = u32::from_be_bytes(kind_arr);

    Ok(NAddr {
        identifier,
        pubkey,
        kind,
        relays,
    })
}

// ── Internal helpers ───────────────────────────────────────────────────────────

fn hex_to_bytes_exact(hex_str: &str, expected_len: usize) -> Result<Vec<u8>, Nip19Error> {
    let bytes =
        hex::decode(hex_str).map_err(|e| Nip19Error::InvalidHex(format!("{hex_str}: {e}")))?;
    if bytes.len() != expected_len {
        return Err(Nip19Error::InvalidLength {
            expected: expected_len,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

fn bech32_encode(hrp_str: &str, data: &[u8]) -> Result<String, Nip19Error> {
    let hrp = Hrp::parse(hrp_str).map_err(|e| Nip19Error::Bech32(e.to_string()))?;
    bech32::encode::<Bech32>(hrp, data).map_err(|e| Nip19Error::Bech32(e.to_string()))
}

fn bech32_decode_exact(
    s: &str,
    expected_hrp: &str,
    expected_len: usize,
) -> Result<Vec<u8>, Nip19Error> {
    let bytes = bech32_decode_raw(s, expected_hrp)?;
    if bytes.len() != expected_len {
        return Err(Nip19Error::InvalidLength {
            expected: expected_len,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

fn bech32_decode_raw(s: &str, expected_hrp: &str) -> Result<Vec<u8>, Nip19Error> {
    let (hrp, bytes) = bech32::decode(s).map_err(|e| Nip19Error::Bech32(e.to_string()))?;
    if hrp.as_str() != expected_hrp {
        return Err(Nip19Error::WrongPrefix {
            expected: expected_hrp.to_string(),
            actual: hrp.to_string(),
        });
    }
    Ok(bytes)
}

/// Append a TLV entry: `type(1) || length(1) || value(n)`.
/// NIP-19 uses single-byte lengths; values > 255 bytes are truncated.
fn push_tlv(buf: &mut Vec<u8>, tlv_type: u8, value: &[u8]) {
    let len = value.len().min(255);
    buf.push(tlv_type);
    buf.push(len as u8);
    buf.extend_from_slice(&value[..len]);
}

/// Parse a byte slice into TLV entries: `(type, value)`.
fn parse_tlv(data: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, Nip19Error> {
    let mut entries = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if i + 2 > data.len() {
            return Err(Nip19Error::TruncatedTlv);
        }
        let tlv_type = data[i];
        let length = data[i + 1] as usize;
        i += 2;
        if i + length > data.len() {
            return Err(Nip19Error::TruncatedTlv);
        }
        entries.push((tlv_type, data[i..i + length].to_vec()));
        i += length;
    }
    Ok(entries)
}

fn find_tlv_first(entries: &[(u8, Vec<u8>)], tlv_type: u8) -> Option<Vec<u8>> {
    entries
        .iter()
        .find(|(t, _)| *t == tlv_type)
        .map(|(_, v)| v.clone())
}

fn find_tlv_required(entries: &[(u8, Vec<u8>)], tlv_type: u8) -> Result<Vec<u8>, Nip19Error> {
    find_tlv_first(entries, tlv_type).ok_or(Nip19Error::MissingTlv(tlv_type))
}

fn find_tlv_all(entries: &[(u8, Vec<u8>)], tlv_type: u8) -> Vec<Vec<u8>> {
    entries
        .iter()
        .filter(|(t, _)| *t == tlv_type)
        .map(|(_, v)| v.clone())
        .collect()
}

fn collect_relays(entries: &[(u8, Vec<u8>)]) -> Result<Vec<String>, Nip19Error> {
    find_tlv_all(entries, TLV_RELAY)
        .into_iter()
        .map(|b| String::from_utf8(b).map_err(|_| Nip19Error::InvalidUtf8))
        .collect()
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_keypair;

    fn random_hex32() -> String {
        let kp = generate_keypair().unwrap();
        kp.public.to_hex()
    }

    // ── Simple types ───────────────────────────────────────────────────────────

    #[test]
    fn npub_roundtrip() {
        let pk = random_hex32();
        let npub = encode_npub(&pk).unwrap();
        assert!(npub.starts_with("npub1"), "must start with npub1");
        let decoded = decode_npub(&npub).unwrap();
        assert_eq!(decoded, pk);
    }

    #[test]
    fn nsec_roundtrip() {
        let kp = generate_keypair().unwrap();
        let sk_hex = hex::encode(kp.secret.as_bytes());
        let nsec = encode_nsec(&sk_hex).unwrap();
        assert!(nsec.starts_with("nsec1"));
        let decoded = decode_nsec(&nsec).unwrap();
        assert_eq!(decoded, sk_hex);
    }

    #[test]
    fn note_roundtrip() {
        let id = random_hex32();
        let note = encode_note(&id).unwrap();
        assert!(note.starts_with("note1"));
        let decoded = decode_note(&note).unwrap();
        assert_eq!(decoded, id);
    }

    #[test]
    fn wrong_prefix_error() {
        let pk = random_hex32();
        let note = encode_note(&pk).unwrap();
        let err = decode_npub(&note).unwrap_err();
        assert!(matches!(err, Nip19Error::WrongPrefix { .. }));
    }

    // ── nprofile ───────────────────────────────────────────────────────────────

    #[test]
    fn nprofile_roundtrip_no_relays() {
        let pk = random_hex32();
        let profile = NProfile {
            pubkey: pk.clone(),
            relays: vec![],
        };
        let encoded = encode_nprofile(&profile).unwrap();
        assert!(encoded.starts_with("nprofile1"));
        let decoded = decode_nprofile(&encoded).unwrap();
        assert_eq!(decoded.pubkey, pk);
        assert!(decoded.relays.is_empty());
    }

    #[test]
    fn nprofile_roundtrip_with_relays() {
        let pk = random_hex32();
        let relays = vec![
            "wss://relay.example.com".to_string(),
            "wss://nostr.example.org".to_string(),
        ];
        let profile = NProfile {
            pubkey: pk.clone(),
            relays: relays.clone(),
        };
        let encoded = encode_nprofile(&profile).unwrap();
        let decoded = decode_nprofile(&encoded).unwrap();
        assert_eq!(decoded.pubkey, pk);
        assert_eq!(decoded.relays, relays);
    }

    // ── nevent ─────────────────────────────────────────────────────────────────

    #[test]
    fn nevent_roundtrip_minimal() {
        let id = random_hex32();
        let event = NEvent {
            id: id.clone(),
            relays: vec![],
            author: None,
            kind: None,
        };
        let encoded = encode_nevent(&event).unwrap();
        assert!(encoded.starts_with("nevent1"));
        let decoded = decode_nevent(&encoded).unwrap();
        assert_eq!(decoded.id, id);
        assert!(decoded.relays.is_empty());
        assert!(decoded.author.is_none());
        assert!(decoded.kind.is_none());
    }

    #[test]
    fn nevent_roundtrip_full() {
        let id = random_hex32();
        let author = random_hex32();
        let relays = vec!["wss://relay.example.com".to_string()];
        let event = NEvent {
            id: id.clone(),
            relays: relays.clone(),
            author: Some(author.clone()),
            kind: Some(1),
        };
        let encoded = encode_nevent(&event).unwrap();
        let decoded = decode_nevent(&encoded).unwrap();
        assert_eq!(decoded.id, id);
        assert_eq!(decoded.relays, relays);
        assert_eq!(decoded.author, Some(author));
        assert_eq!(decoded.kind, Some(1));
    }

    // ── naddr ──────────────────────────────────────────────────────────────────

    #[test]
    fn naddr_roundtrip_no_relays() {
        let pubkey = random_hex32();
        let addr = NAddr {
            identifier: "my-article".to_string(),
            pubkey: pubkey.clone(),
            kind: 30023,
            relays: vec![],
        };
        let encoded = encode_naddr(&addr).unwrap();
        assert!(encoded.starts_with("naddr1"));
        let decoded = decode_naddr(&encoded).unwrap();
        assert_eq!(decoded.identifier, "my-article");
        assert_eq!(decoded.pubkey, pubkey);
        assert_eq!(decoded.kind, 30023);
        assert!(decoded.relays.is_empty());
    }
}
