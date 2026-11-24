//! The signed index manifest: a NIP-01 event (kind 30078, application data)
//! stored only in the pod (`…/search/m.json`, behind the zone read gate),
//! never on the relay (review M1).
//!
//! Acceptance rules ([`Manifest::verify`]):
//! - `verify_event_strict` passes and `pubkey` is an allowed publisher;
//! - `d` = `nostr-bbs/sealed-search/<zone>`, the `relay` tag equals this
//!   deployment's relay URL (no cross-deployment replay, M2);
//! - the content parses, names the same zone, and every object's
//!   `(epoch, zone_pk)` appears in the `zone_pk` tags;
//! - `index_version` is strictly greater than the stored high-water mark, or
//!   equal with the same event id, and jumps by at most 2^20 (M2).

use nostr_bbs_core::event::{verify_event_strict, NostrEvent};
use serde::{Deserialize, Serialize};

use crate::format::Kind;

/// Event kind (NIP-78 application-specific data).
pub const KIND: u64 = 30078;
/// Largest accepted version jump (M2).
pub const MAX_VERSION_JUMP: u64 = 1 << 20;

/// `d` tag value for a zone.
pub fn d_tag(zone: &str) -> String {
    format!("nostr-bbs/sealed-search/{zone}")
}

/// One sealed object as listed in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectRef {
    /// Object name under the publisher's `search/` folder.
    pub name: String,
    /// bin or int8.
    pub kind: Kind,
    /// Zone key epoch.
    pub epoch: u32,
    /// Hex x-only zone key pubkey of that epoch.
    pub zone_pk: String,
    /// Shard number.
    pub shard: u32,
    /// Rows.
    pub count: u32,
    /// Sealed size in bytes.
    pub size: u64,
    /// Hex SHA-256 of the sealed bytes.
    pub sha256: String,
}

/// Manifest content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Content {
    /// Format version (1).
    pub v: u32,
    /// Zone id.
    pub zone: String,
    /// Monotonic index version.
    pub index_version: u64,
    /// Embedding dimension (384).
    pub dim: u32,
    /// Model label.
    pub model: String,
    /// Hex SHA-256 of the Q8 GGUF the browser must use (L5).
    pub model_sha256: String,
    /// Hex SHA-256 of `vocab.txt` (L5).
    pub vocab_sha256: String,
    /// Objects.
    pub objects: Vec<ObjectRef>,
}

/// A verified manifest.
#[derive(Debug, Clone)]
pub struct Manifest {
    /// The signed event.
    pub event: NostrEvent,
    /// Parsed content.
    pub content: Content,
}

/// Stored high-water mark for a zone (kept outside the wiped cache).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HighWater {
    /// Highest accepted version.
    pub version: u64,
    /// Event id accepted at that version.
    pub event_id: String,
}

fn tag<'a>(ev: &'a NostrEvent, name: &str) -> impl Iterator<Item = &'a Vec<String>> + 'a {
    let name = name.to_string();
    ev.tags.iter().filter(move |t| t.first().map(String::as_str) == Some(name.as_str()))
}

impl Manifest {
    /// The tags a publisher must put on the event.
    pub fn tags(content: &Content, relay_url: &str) -> Vec<Vec<String>> {
        let mut t = vec![vec!["d".into(), d_tag(&content.zone)], vec!["relay".into(), relay_url.into()]];
        let mut seen = std::collections::BTreeSet::new();
        for o in &content.objects {
            if seen.insert((o.epoch, o.zone_pk.clone())) {
                t.push(vec!["zone_pk".into(), o.epoch.to_string(), o.zone_pk.clone()]);
            }
        }
        t
    }

    /// Verify an event as the manifest for `zone` on `relay_url`, published
    /// by one of `publishers`, against the stored high-water mark.
    pub fn verify(
        ev: NostrEvent,
        zone: &str,
        relay_url: &str,
        publishers: &[String],
        high_water: Option<&HighWater>,
    ) -> Result<Self, String> {
        verify_event_strict(&ev).map_err(|e| format!("bad signature: {e}"))?;
        if ev.kind != KIND {
            return Err("wrong kind".into());
        }
        if !publishers.iter().any(|p| p.eq_ignore_ascii_case(&ev.pubkey)) {
            return Err("publisher is not an admin or archivist".into());
        }
        if tag(&ev, "d").next().and_then(|t| t.get(1)) != Some(&d_tag(zone)) {
            return Err("manifest is for another zone".into());
        }
        if tag(&ev, "relay").next().and_then(|t| t.get(1)).map(String::as_str) != Some(relay_url) {
            return Err("manifest is for another deployment".into());
        }
        let content: Content = serde_json::from_str(&ev.content).map_err(|e| format!("bad content: {e}"))?;
        if content.v != 1 || content.zone != zone || content.dim != 384 {
            return Err("unsupported manifest content".into());
        }
        let pks: Vec<(u32, String)> = tag(&ev, "zone_pk")
            .filter_map(|t| Some((t.get(1)?.parse().ok()?, t.get(2)?.to_lowercase())))
            .collect();
        for o in &content.objects {
            if !pks.contains(&(o.epoch, o.zone_pk.to_lowercase())) {
                return Err(format!("object {} names an unlisted zone key", o.name));
            }
            if o.count as usize > crate::format::MAX_ROWS || !valid_object_name(&o.name) {
                return Err(format!("object {} out of bounds", o.name));
            }
        }
        if let Some(h) = high_water {
            let ok = content.index_version > h.version || (content.index_version == h.version && ev.id == h.event_id);
            if !ok {
                return Err("manifest is older than one already accepted (rollback)".into());
            }
            if content.index_version - h.version > MAX_VERSION_JUMP {
                return Err("manifest version jump too large".into());
            }
        }
        Ok(Self { event: ev, content })
    }

    /// The new high-water mark after accepting this manifest.
    pub fn high_water(&self) -> HighWater {
        HighWater { version: self.content.index_version, event_id: self.event.id.clone() }
    }
}

fn digits(s: &str, max: u64) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'))
        && s.len() <= 20
        && s.parse::<u64>().map(|n| n <= max).unwrap_or(false)
}

/// Object names: `m.json`, or `[bq]-<epoch u32>-<shard u32>-v<version u64>.age`,
/// ASCII digits only, no leading zeros (review L1). Shared with the pod gate.
pub fn valid_object_name(name: &str) -> bool {
    if name == "m.json" {
        return true;
    }
    let Some(stem) = name.strip_suffix(".age") else { return false };
    let mut parts = stem.splitn(4, '-');
    let (Some(k), Some(e), Some(s), Some(v)) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    (k == "b" || k == "q")
        && digits(e, u32::MAX as u64)
        && digits(s, u32::MAX as u64)
        && v.strip_prefix('v').is_some_and(|v| digits(v, u64::MAX))
}

/// Object name for a layer.
pub fn object_name(kind: Kind, epoch: u32, shard: u32, version: u64) -> String {
    format!("{}-{epoch}-{shard}-v{version}.age", if kind == Kind::Bin { "b" } else { "q" })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_bbs_core::event::{sign_event_deterministic, UnsignedEvent};

    fn sk(b: u8) -> k256::schnorr::SigningKey {
        k256::schnorr::SigningKey::from_bytes((&[b; 32]).into()).unwrap()
    }

    fn signed(key: u8, content: &Content, relay: &str) -> NostrEvent {
        let k = sk(key);
        let pk = hex::encode(k.verifying_key().to_bytes());
        let ev = UnsignedEvent { pubkey: pk, created_at: 1, kind: KIND, tags: Manifest::tags(content, relay), content: serde_json::to_string(content).unwrap() };
        sign_event_deterministic(ev, &k).unwrap()
    }

    fn content(version: u64) -> Content {
        Content {
            v: 1, zone: "zone2".into(), index_version: version, dim: 384, model: "bge-small-en-v1.5".into(),
            model_sha256: "aa".into(), vocab_sha256: "bb".into(),
            objects: vec![ObjectRef { name: object_name(Kind::Bin, 1, 0, version), kind: Kind::Bin, epoch: 1, zone_pk: "11".repeat(32), shard: 0, count: 10, size: 999, sha256: "cc".into() }],
        }
    }

    #[test]
    fn accepts_valid_and_rejects_forgeries() {
        let pk1 = hex::encode(sk(1).verifying_key().to_bytes());
        let pubs = vec![pk1.clone()];
        let ev = signed(1, &content(5), "ws://r");
        let m = Manifest::verify(ev.clone(), "zone2", "ws://r", &pubs, None).unwrap();
        assert_eq!(m.content.index_version, 5);
        // Not a publisher.
        assert!(Manifest::verify(signed(2, &content(5), "ws://r"), "zone2", "ws://r", &pubs, None).is_err());
        // Other zone / other deployment.
        assert!(Manifest::verify(ev.clone(), "zone3", "ws://r", &pubs, None).is_err());
        assert!(Manifest::verify(ev.clone(), "zone2", "ws://other", &pubs, None).is_err());
        // Tampered content breaks the signature.
        let mut bad = ev.clone();
        bad.content = bad.content.replace("\"count\":10", "\"count\":11");
        assert!(Manifest::verify(bad, "zone2", "ws://r", &pubs, None).is_err());
        // Rollback, same-version swap, huge jump.
        let hw = m.high_water();
        assert!(Manifest::verify(signed(1, &content(4), "ws://r"), "zone2", "ws://r", &pubs, Some(&hw)).is_err());
        assert!(Manifest::verify(ev.clone(), "zone2", "ws://r", &pubs, Some(&hw)).is_ok());
        let mut other5 = content(5);
        other5.model = "x".into();
        assert!(Manifest::verify(signed(1, &other5, "ws://r"), "zone2", "ws://r", &pubs, Some(&hw)).is_err());
        assert!(Manifest::verify(signed(1, &content(5 + MAX_VERSION_JUMP + 1), "ws://r"), "zone2", "ws://r", &pubs, Some(&hw)).is_err());
        assert!(Manifest::verify(signed(1, &content(6), "ws://r"), "zone2", "ws://r", &pubs, Some(&hw)).is_ok());
    }

    #[test]
    fn object_names_are_strict() {
        for ok in ["m.json", "b-1-0-v1.age", "q-4294967295-12-v18446744073709551615.age", "b-0-0-v0.age"] {
            assert!(valid_object_name(ok), "{ok}");
        }
        for bad in ["b-01-0-v1.age", "b-1-0-v1.ag", "x-1-0-v1.age", "b-4294967296-0-v1.age", "b-١-0-v1.age", "b-1-0-1.age", "../m.json", "b-1-0-v1.age/x", ""] {
            assert!(!valid_object_name(bad), "{bad}");
        }
    }
}
