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
//!
//! # Content versions
//!
//! - **v1**: every object was built at `index_version` and lives in the
//!   signer's pod. Browsers built before v2 accept only this.
//! - **v2** (incremental updates): an object may carry the `version` its
//!   header was built at (an unchanged object from an earlier version) and the
//!   `owner` whose pod holds it (another trusted publisher, such as the
//!   archivist that built the base), and the content may list `excluded` row
//!   ids (deleted or superseded posts) that a searcher must not return. A v2
//!   manifest is refused by older browsers as unsupported, so they keep using
//!   the newest v1 manifest they can find. Every field v2 adds is optional
//!   with a default that reads exactly as v1, so a v1 manifest is a valid v2
//!   manifest without them.
//!
//! v2 adds these acceptance rules: an `owner` is one of the trusted
//! publishers; an object's `version` is at most `index_version` and equals the
//! `v<N>` in its name; no two objects share a name or an
//! `(epoch, zone_pk, shard, kind)`; every excluded id is 64 lowercase hex, and
//! there are at most [`MAX_EXCLUDED`] of them. A v1 manifest carrying any v2
//! field is refused, so an older browser can never misread one.

use nostr_bbs_core::event::{verify_event_strict, NostrEvent};
use serde::{Deserialize, Serialize};

use crate::format::Kind;

/// Parse a publisher list (`__ENV__.SEARCH_PUBLISHERS`, builder
/// `--publishers`): comma-separated 64-char hex pubkeys, whitespace ignored,
/// lowercased, invalid entries dropped, order kept, duplicates removed.
/// Typically `"<archivist pk>,<admin pk>"`.
pub fn parse_publishers(list: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for p in list.split(',').map(|s| s.trim().to_lowercase()) {
        if p.len() == 64 && p.bytes().all(|b| b.is_ascii_hexdigit()) && !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// Event kind (NIP-78 application-specific data).
pub const KIND: u64 = 30078;
/// Content version of a manifest every browser understands.
pub const V1: u32 = 1;
/// Content version with per-object `owner` and `version`, and `excluded`.
pub const V2: u32 = 2;
/// Most excluded ids one manifest may list.
pub const MAX_EXCLUDED: usize = 1 << 17;
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
    /// v2: the publisher whose pod holds the object (hex pubkey), when it is
    /// not the manifest's signer. Must be a trusted publisher.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// v2: the index version the object's header was built at, when it is
    /// not the manifest's `index_version` (an object carried over unchanged).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
}

impl ObjectRef {
    /// The index version this object's authenticated header must carry.
    pub fn effective_version(&self, content: &Content) -> u64 {
        self.version.unwrap_or(content.index_version)
    }

    /// The pubkey of the pod holding this object (`signer` when no `owner`).
    pub fn owner_or<'a>(&'a self, signer: &'a str) -> &'a str {
        self.owner.as_deref().unwrap_or(signer)
    }
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
    /// v2: hex ids of rows a searcher must skip (deleted or superseded posts
    /// still present in an unchanged object). Sorted, no duplicates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded: Vec<String>,
}

impl Content {
    /// The excluded ids as raw bytes (malformed entries, which
    /// [`Manifest::verify`] refuses, are skipped).
    pub fn excluded_ids(&self) -> std::collections::HashSet<[u8; 32]> {
        self.excluded
            .iter()
            .filter_map(|h| <[u8; 32]>::try_from(hex::decode(h).ok()?.as_slice()).ok())
            .collect()
    }
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
    ev.tags
        .iter()
        .filter(move |t| t.first().map(String::as_str) == Some(name.as_str()))
}

impl Manifest {
    /// The tags a publisher must put on the event.
    pub fn tags(content: &Content, relay_url: &str) -> Vec<Vec<String>> {
        let mut t = vec![
            vec!["d".into(), d_tag(&content.zone)],
            vec!["relay".into(), relay_url.into()],
        ];
        let mut seen = std::collections::BTreeSet::new();
        for o in &content.objects {
            if seen.insert((o.epoch, o.zone_pk.clone())) {
                t.push(vec![
                    "zone_pk".into(),
                    o.epoch.to_string(),
                    o.zone_pk.clone(),
                ]);
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
        if !publishers
            .iter()
            .any(|p| p.eq_ignore_ascii_case(&ev.pubkey))
        {
            return Err("publisher is not an admin or archivist".into());
        }
        if tag(&ev, "d").next().and_then(|t| t.get(1)) != Some(&d_tag(zone)) {
            return Err("manifest is for another zone".into());
        }
        if tag(&ev, "relay")
            .next()
            .and_then(|t| t.get(1))
            .map(String::as_str)
            != Some(relay_url)
        {
            return Err("manifest is for another deployment".into());
        }
        let content: Content =
            serde_json::from_str(&ev.content).map_err(|e| format!("bad content: {e}"))?;
        if !(content.v == V1 || content.v == V2) || content.zone != zone || content.dim != 384 {
            return Err("unsupported manifest content".into());
        }
        check_version_rules(&content, publishers)?;
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
            let ok = content.index_version > h.version
                || (content.index_version == h.version && ev.id == h.event_id);
            if !ok {
                return Err("manifest is older than one already accepted (rollback)".into());
            }
            if content.index_version - h.version > MAX_VERSION_JUMP {
                return Err("manifest version jump too large".into());
            }
        }
        Ok(Self { event: ev, content })
    }

    /// The pubkey of the pod holding `o` (its `owner`, else the signer).
    pub fn owner_of<'a>(&'a self, o: &'a ObjectRef) -> &'a str {
        o.owner_or(&self.event.pubkey)
    }

    /// The new high-water mark after accepting this manifest.
    pub fn high_water(&self) -> HighWater {
        HighWater {
            version: self.content.index_version,
            event_id: self.event.id.clone(),
        }
    }
}

fn is_hex64_lower(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The v1/v2 content rules (see the module documentation).
fn check_version_rules(c: &Content, publishers: &[String]) -> Result<(), String> {
    if c.v == V1 {
        if c.objects
            .iter()
            .any(|o| o.owner.is_some() || o.version.is_some())
            || !c.excluded.is_empty()
        {
            return Err("v1 manifest carries v2 fields".into());
        }
        return Ok(());
    }
    let mut names = std::collections::HashSet::new();
    let mut slots = std::collections::HashSet::new();
    for o in &c.objects {
        if let Some(owner) = &o.owner {
            if !is_hex64_lower(owner) || !publishers.iter().any(|p| p.eq_ignore_ascii_case(owner)) {
                return Err(format!("object {} is held by an untrusted pod", o.name));
            }
        }
        let v = o.effective_version(c);
        if v > c.index_version || object_name_version(&o.name) != Some(v) {
            return Err(format!("object {} has an inconsistent version", o.name));
        }
        if !names.insert(o.name.as_str())
            || !slots.insert((o.epoch, o.zone_pk.to_lowercase(), o.shard, o.kind as u8))
        {
            return Err(format!("object {} is listed twice", o.name));
        }
    }
    if c.excluded.len() > MAX_EXCLUDED || !c.excluded.iter().all(|h| is_hex64_lower(h)) {
        return Err("bad excluded list".into());
    }
    Ok(())
}

/// The `v<N>` index version in an object name (`None` for `m.json` or a
/// malformed name).
pub fn object_name_version(name: &str) -> Option<u64> {
    if !valid_object_name(name) || name == "m.json" {
        return None;
    }
    name.strip_suffix(".age")?.rsplit_once("-v")?.1.parse().ok()
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
    let Some(stem) = name.strip_suffix(".age") else {
        return false;
    };
    let mut parts = stem.splitn(4, '-');
    let (Some(k), Some(e), Some(s), Some(v)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    (k == "b" || k == "q")
        && digits(e, u32::MAX as u64)
        && digits(s, u32::MAX as u64)
        && v.strip_prefix('v').is_some_and(|v| digits(v, u64::MAX))
}

/// Object name for a layer.
pub fn object_name(kind: Kind, epoch: u32, shard: u32, version: u64) -> String {
    format!(
        "{}-{epoch}-{shard}-v{version}.age",
        if kind == Kind::Bin { "b" } else { "q" }
    )
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
        let ev = UnsignedEvent {
            pubkey: pk,
            created_at: 1,
            kind: KIND,
            tags: Manifest::tags(content, relay),
            content: serde_json::to_string(content).unwrap(),
        };
        sign_event_deterministic(ev, &k).unwrap()
    }

    fn content(version: u64) -> Content {
        Content {
            v: 1,
            zone: "zone2".into(),
            index_version: version,
            dim: 384,
            model: "bge-small-en-v1.5".into(),
            model_sha256: "aa".into(),
            vocab_sha256: "bb".into(),
            objects: vec![ObjectRef {
                name: object_name(Kind::Bin, 1, 0, version),
                kind: Kind::Bin,
                epoch: 1,
                zone_pk: "11".repeat(32),
                shard: 0,
                count: 10,
                size: 999,
                sha256: "cc".into(),
                owner: None,
                version: None,
            }],
            excluded: Vec::new(),
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
        assert!(Manifest::verify(
            signed(2, &content(5), "ws://r"),
            "zone2",
            "ws://r",
            &pubs,
            None
        )
        .is_err());
        // Other zone / other deployment.
        assert!(Manifest::verify(ev.clone(), "zone3", "ws://r", &pubs, None).is_err());
        assert!(Manifest::verify(ev.clone(), "zone2", "ws://other", &pubs, None).is_err());
        // Tampered content breaks the signature.
        let mut bad = ev.clone();
        bad.content = bad.content.replace("\"count\":10", "\"count\":11");
        assert!(Manifest::verify(bad, "zone2", "ws://r", &pubs, None).is_err());
        // Rollback, same-version swap, huge jump.
        let hw = m.high_water();
        assert!(Manifest::verify(
            signed(1, &content(4), "ws://r"),
            "zone2",
            "ws://r",
            &pubs,
            Some(&hw)
        )
        .is_err());
        assert!(Manifest::verify(ev.clone(), "zone2", "ws://r", &pubs, Some(&hw)).is_ok());
        let mut other5 = content(5);
        other5.model = "x".into();
        assert!(Manifest::verify(
            signed(1, &other5, "ws://r"),
            "zone2",
            "ws://r",
            &pubs,
            Some(&hw)
        )
        .is_err());
        assert!(Manifest::verify(
            signed(1, &content(5 + MAX_VERSION_JUMP + 1), "ws://r"),
            "zone2",
            "ws://r",
            &pubs,
            Some(&hw)
        )
        .is_err());
        assert!(Manifest::verify(
            signed(1, &content(6), "ws://r"),
            "zone2",
            "ws://r",
            &pubs,
            Some(&hw)
        )
        .is_ok());
    }

    #[test]
    fn publisher_lists_parse_and_any_listed_key_is_accepted() {
        let a = hex::encode(sk(1).verifying_key().to_bytes());
        let b = hex::encode(sk(2).verifying_key().to_bytes());
        let list = format!(" {} , {},nothex,{}, ", a.to_uppercase(), b, a);
        assert_eq!(parse_publishers(&list), vec![a.clone(), b.clone()]);
        assert!(parse_publishers("").is_empty());
        let pubs = parse_publishers(&list);
        // Archivist-signed and admin-signed manifests both verify; others do not.
        assert!(Manifest::verify(
            signed(1, &content(1), "ws://r"),
            "zone2",
            "ws://r",
            &pubs,
            None
        )
        .is_ok());
        assert!(Manifest::verify(
            signed(2, &content(1), "ws://r"),
            "zone2",
            "ws://r",
            &pubs,
            None
        )
        .is_ok());
        assert!(Manifest::verify(
            signed(3, &content(1), "ws://r"),
            "zone2",
            "ws://r",
            &pubs,
            None
        )
        .is_err());
    }

    #[test]
    fn object_names_are_strict() {
        for ok in [
            "m.json",
            "b-1-0-v1.age",
            "q-4294967295-12-v18446744073709551615.age",
            "b-0-0-v0.age",
        ] {
            assert!(valid_object_name(ok), "{ok}");
        }
        for bad in [
            "b-01-0-v1.age",
            "b-1-0-v1.ag",
            "x-1-0-v1.age",
            "b-4294967296-0-v1.age",
            "b-١-0-v1.age",
            "b-1-0-1.age",
            "../m.json",
            "b-1-0-v1.age/x",
            "",
        ] {
            assert!(!valid_object_name(bad), "{bad}");
        }
    }

    fn pk(b: u8) -> String {
        hex::encode(sk(b).verifying_key().to_bytes())
    }

    /// A v2 update over a v1 base by key 1, signed by key 2.
    fn update_content(version: u64) -> Content {
        let mut c = content(1);
        c.v = V2;
        c.index_version = version;
        c.objects[0].owner = Some(pk(1));
        c.objects[0].version = Some(1);
        c.objects.push(ObjectRef {
            name: object_name(Kind::Bin, 1, 1, version),
            shard: 1,
            owner: None,
            version: None,
            ..c.objects[0].clone()
        });
        c.excluded = vec!["ab".repeat(32)];
        c
    }

    #[test]
    fn a_v1_manifest_reads_as_before_under_v2_rules() {
        let pubs = vec![pk(1)];
        let c = content(5);
        let json = serde_json::to_string(&c).unwrap();
        for absent in ["owner", "\"version\"", "excluded"] {
            assert!(!json.contains(absent), "v1 JSON stays v1: {json}");
        }
        let m = Manifest::verify(signed(1, &c, "ws://r"), "zone2", "ws://r", &pubs, None).unwrap();
        let o = &m.content.objects[0];
        assert_eq!(
            m.owner_of(o),
            pk(1),
            "an object without owner is in the signer's pod"
        );
        assert_eq!(o.effective_version(&m.content), 5);
        assert!(m.content.excluded_ids().is_empty());
        // The JSON an older builder wrote (no v2 keys at all) parses the same.
        let old = json.replace(",\"excluded\":[]", "");
        assert_eq!(serde_json::from_str::<Content>(&old).unwrap(), c);
    }

    #[test]
    fn a_v1_manifest_with_v2_fields_is_refused() {
        let pubs = vec![pk(1)];
        let mut c = content(5);
        c.excluded = vec!["ab".repeat(32)];
        assert!(Manifest::verify(signed(1, &c, "ws://r"), "zone2", "ws://r", &pubs, None).is_err());
        let mut c = content(5);
        c.objects[0].owner = Some(pk(1));
        assert!(Manifest::verify(signed(1, &c, "ws://r"), "zone2", "ws://r", &pubs, None).is_err());
    }

    #[test]
    fn a_v2_update_may_reference_another_trusted_publishers_objects() {
        let pubs = vec![pk(1), pk(2)];
        let c = update_content(7);
        let m = Manifest::verify(signed(2, &c, "ws://r"), "zone2", "ws://r", &pubs, None).unwrap();
        assert_eq!(m.owner_of(&m.content.objects[0]), pk(1));
        assert_eq!(m.owner_of(&m.content.objects[1]), pk(2));
        assert_eq!(m.content.objects[0].effective_version(&m.content), 1);
        assert_eq!(m.content.objects[1].effective_version(&m.content), 7);
        assert_eq!(m.content.excluded_ids().len(), 1);
        // The same manifest with the base's publisher untrusted is refused.
        assert!(
            Manifest::verify(signed(2, &c, "ws://r"), "zone2", "ws://r", &[pk(2)], None).is_err()
        );
    }

    #[test]
    fn v2_rules_refuse_inconsistent_objects() {
        let pubs = vec![pk(1), pk(2)];
        let refuse = |c: Content, why: &str| {
            assert!(
                Manifest::verify(signed(2, &c, "ws://r"), "zone2", "ws://r", &pubs, None).is_err(),
                "{why}"
            );
        };
        let mut c = update_content(7);
        c.objects[0].owner = Some(pk(3));
        refuse(c, "owner outside the publisher list");
        let mut c = update_content(7);
        c.objects[0].owner = Some(pk(1).to_uppercase());
        refuse(c, "owner not canonical hex");
        let mut c = update_content(7);
        c.objects[0].version = Some(8);
        c.objects[0].name = object_name(Kind::Bin, 1, 0, 8);
        refuse(c, "object newer than the manifest");
        let mut c = update_content(7);
        c.objects[0].version = Some(2);
        refuse(c, "header version differs from the name");
        let mut c = update_content(7);
        c.objects[1].shard = 0;
        refuse(c, "two objects in one slot");
        let mut c = update_content(7);
        c.objects[1].name = c.objects[0].name.clone();
        c.objects[1].version = Some(1);
        refuse(c, "two objects with one name");
        let mut c = update_content(7);
        c.excluded = vec!["AB".repeat(32)];
        refuse(c, "excluded id not lowercase hex");
        let mut c = update_content(7);
        c.v = 3;
        refuse(c, "unknown content version");
    }

    #[test]
    fn object_name_versions_parse() {
        assert_eq!(object_name_version("b-1-0-v7.age"), Some(7));
        assert_eq!(object_name_version("q-4-12-v0.age"), Some(0));
        assert_eq!(object_name_version("m.json"), None);
        assert_eq!(object_name_version("b-1-0-v07.age"), None);
    }
}
