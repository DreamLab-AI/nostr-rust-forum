//! Rules for the on-device cache of sealed search objects (IndexedDB
//! `nostr-bbs-sealed-search`, store `objects`).
//!
//! What is cached is exactly what the pod serves: the age-sealed shards and
//! the public model files. Nothing decrypted is stored. Entries are keyed by
//! content:
//!
//! - a sealed object by the manifest's SHA-256 of its sealed bytes, so a new
//!   index version (new objects, new hashes) never reuses an old entry, and
//!   one object shared by two versions is fetched once;
//! - a model file by `static:<sha256>`, pinned by the manifest.
//!
//! The cache belongs to one identity on one relay deployment, recorded as a
//! scope fingerprint ([`scope_fingerprint`]). It is kept across page loads
//! for that scope ([`keep_on_wipe`]), emptied before another scope writes to
//! it ([`must_reset`]), and entries no current manifest names are pruned once
//! every zone's manifest is known ([`prune_allowed`], [`stale_keys`]).

use std::collections::HashSet;

use nostr_bbs_sealed_search::manifest::{Content, ObjectRef};
use sha2::{Digest, Sha256};

use super::state::ZoneLoad;

/// Domain label of the scope fingerprint.
const SCOPE_LABEL: &[u8] = b"nostr-bbs/sealed-search/cache-scope/v1";

/// Fingerprint of the scope the cache belongs to: the identity (`pubkey`,
/// hex, any case) on the relay deployment (`relay_url`, compared without
/// case or trailing slashes). Hex SHA-256 under a domain label; it names
/// only public values.
pub fn scope_fingerprint(pubkey: &str, relay_url: &str) -> String {
    let mut h = Sha256::new();
    h.update(SCOPE_LABEL);
    h.update([0]);
    h.update(pubkey.trim().to_ascii_lowercase().as_bytes());
    h.update([0]);
    h.update(
        relay_url
            .trim()
            .trim_end_matches('/')
            .to_ascii_lowercase()
            .as_bytes(),
    );
    hex::encode(h.finalize())
}

/// Whether a wipe (sign-out, identity switch, key swap, relay change, or the
/// owner being set again at page load) may keep the cached objects.
///
/// Kept only when the cache's recorded scope (`stored`) is the scope of the
/// identity now signed in (`current`): the page-load case, and a key swap
/// for the same identity (the worker, which held the derived keys, is
/// stopped either way). Signed out, another identity, another relay, or a
/// scope that cannot be read: emptied.
pub fn keep_on_wipe(stored: Option<&str>, current: Option<&str>) -> bool {
    matches!((stored, current), (Some(s), Some(c)) if s == c)
}

/// Whether the cache must be emptied before `current` writes to it.
pub fn must_reset(stored: Option<&str>, current: &str) -> bool {
    stored != Some(current)
}

/// Cache key of a sealed object.
pub fn object_key(o: &ObjectRef) -> String {
    o.sha256.clone()
}

/// Cache key of a model file pinned by `sha256`.
pub fn static_key(sha256: &str) -> String {
    format!("static:{sha256}")
}

/// Every cache key the given current manifests name: their objects and the
/// model files they pin.
pub fn keep_set<'a>(manifests: impl IntoIterator<Item = &'a Content>) -> HashSet<String> {
    let mut keep = HashSet::new();
    for c in manifests {
        keep.extend(c.objects.iter().map(object_key));
        keep.insert(static_key(&c.model_sha256));
        keep.insert(static_key(&c.vocab_sha256));
    }
    keep
}

/// Whether the cache may be pruned after the loads ended in `zones`: only
/// when every zone's current manifest is known (loaded, or every publisher
/// answered that there is none). A zone that failed or is still loading may
/// have cached objects that no known manifest names.
pub fn prune_allowed(zones: &[ZoneLoad]) -> bool {
    !zones.is_empty()
        && zones
            .iter()
            .all(|z| matches!(z, ZoneLoad::Ready | ZoneLoad::NoIndex))
}

/// The cached keys to delete: those not in `keep`.
pub fn stale_keys(existing: &[String], keep: &HashSet<String>) -> Vec<String> {
    existing
        .iter()
        .filter(|k| !keep.contains(*k))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_bbs_sealed_search::format::Kind;

    const ADMIN: &str = "75876d9075c15bda6d724511ab9edcaabd53ebfa69ace15f918527e89e077968";
    const OTHER: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const RELAY: &str = "wss://relay.example.com";

    fn obj(name: &str, sha: &str) -> ObjectRef {
        ObjectRef {
            name: name.into(),
            kind: if name.starts_with('b') {
                Kind::Bin
            } else {
                Kind::Int8
            },
            epoch: 5,
            zone_pk: "ab".repeat(32),
            shard: 0,
            count: 1,
            size: 1,
            sha256: sha.into(),
            owner: None,
            version: None,
        }
    }

    fn content(version: u64, objects: Vec<ObjectRef>) -> Content {
        Content {
            v: 1,
            zone: "zone2".into(),
            index_version: version,
            dim: 384,
            model: "bge".into(),
            model_sha256: "m0".into(),
            vocab_sha256: "v0".into(),
            objects,
            excluded: Vec::new(),
        }
    }

    #[test]
    fn the_scope_names_identity_and_relay_and_nothing_else() {
        let a = scope_fingerprint(ADMIN, RELAY);
        assert_eq!(a.len(), 64);
        assert_eq!(
            a,
            scope_fingerprint(&ADMIN.to_uppercase(), "WSS://relay.example.com/")
        );
        assert_ne!(a, scope_fingerprint(OTHER, RELAY), "another identity");
        assert_ne!(
            a,
            scope_fingerprint(ADMIN, "wss://other.example.com"),
            "another relay"
        );
        assert!(!a.contains(ADMIN), "a hash, not the pubkey itself");
    }

    #[test]
    fn a_wipe_keeps_the_cache_only_for_the_same_scope() {
        let a = scope_fingerprint(ADMIN, RELAY);
        let b = scope_fingerprint(OTHER, RELAY);
        // Page load: the owner is set again to the identity the cache is for.
        assert!(keep_on_wipe(Some(&a), Some(&a)));
        // Sign-out, another identity, unknown either side: emptied.
        assert!(!keep_on_wipe(Some(&a), None));
        assert!(!keep_on_wipe(Some(&a), Some(&b)));
        assert!(!keep_on_wipe(None, Some(&a)));
        assert!(!keep_on_wipe(None, None));
    }

    #[test]
    fn another_scope_resets_the_cache_before_writing() {
        let a = scope_fingerprint(ADMIN, RELAY);
        assert!(!must_reset(Some(&a), &a));
        assert!(
            must_reset(None, &a),
            "unmarked cache: maybe left by someone else"
        );
        assert!(must_reset(Some(&scope_fingerprint(OTHER, RELAY)), &a));
    }

    #[test]
    fn entries_are_keyed_by_content_so_a_new_version_never_reuses_an_old_one() {
        let v2 = content(
            2,
            vec![obj("b-5-0-v2.age", "aa"), obj("q-5-0-v2.age", "bb")],
        );
        let v3 = content(
            3,
            vec![obj("b-5-0-v3.age", "cc"), obj("q-5-0-v3.age", "bb")],
        );
        assert_eq!(object_key(&v2.objects[0]), "aa");
        assert_ne!(object_key(&v2.objects[0]), object_key(&v3.objects[0]));
        // An object identical in both versions is one entry, fetched once.
        assert_eq!(object_key(&v2.objects[1]), object_key(&v3.objects[1]));
        assert_eq!(static_key("m0"), "static:m0");
    }

    #[test]
    fn pruning_drops_what_no_current_manifest_names() {
        let v3 = content(
            3,
            vec![obj("b-5-0-v3.age", "cc"), obj("q-5-0-v3.age", "bb")],
        );
        let keep = keep_set([&v3]);
        let existing: Vec<String> = ["aa", "bb", "cc", "static:m0", "static:v0", "static:old"]
            .map(String::from)
            .to_vec();
        let mut stale = stale_keys(&existing, &keep);
        stale.sort();
        assert_eq!(stale, ["aa", "static:old"]);
    }

    #[test]
    fn pruning_waits_until_every_zone_manifest_is_known() {
        assert!(prune_allowed(&[ZoneLoad::Ready, ZoneLoad::NoIndex]));
        assert!(!prune_allowed(&[]));
        assert!(!prune_allowed(&[
            ZoneLoad::Ready,
            ZoneLoad::Failed("offline".into())
        ]));
        assert!(!prune_allowed(&[
            ZoneLoad::Ready,
            ZoneLoad::Loading {
                loaded: 1,
                total: 2
            }
        ]));
        assert!(!prune_allowed(&[ZoneLoad::Pending]));
    }
}
