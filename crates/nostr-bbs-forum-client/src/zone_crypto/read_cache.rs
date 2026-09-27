//! Per-message decryption state behind the zone read path (ADR-2016, ADR-2017).
//!
//! [`ReadCache`] remembers every zone-encrypted kind-42 this session has shown,
//! keyed by the id it arrived under, so a key that arrives later can re-run
//! the read path over what is already on screen:
//!
//! - a live encrypted post keeps its id; only its ciphertext is remembered and
//!   its content is swapped between placeholder and plaintext;
//! - a sealed original (`nostr_bbs_core::sealed`) is shown under the
//!   envelope's id while the key is missing, and becomes the *original* event
//!   (the original's own id) once it opens. The whole envelope is remembered
//!   so that swap can happen later, in place.
//!
//! Kept free of Leptos and IndexedDB so the swap rules are unit-tested
//! natively; [`ZoneKeyStore`](super::store::ZoneKeyStore) owns one inside a
//! `StoredValue` and applies it to the channel store.

use std::collections::{HashMap, HashSet};

use nostr_bbs_core::sealed::has_sealed_tag;
use nostr_bbs_core::NostrEvent;

use super::{display_text, read_outcome, resolve_event, ReadOutcome, ZoneKey};

/// Ciphertexts and sealed envelopes seen this session, plus which original
/// each envelope has been restored to.
#[derive(Debug, Default)]
pub struct ReadCache {
    /// Original ciphertext of each live zone-encrypted kind-42, by event id.
    ciphertexts: HashMap<String, String>,
    /// Each sealed-original envelope seen, by envelope (outer) id. Kept whole:
    /// opening needs its tags, author and timestamp, and once restored the
    /// channel store holds the original instead, so nothing else retains it.
    envelopes: HashMap<String, NostrEvent>,
    /// Original (inner) id → the envelope id it was first restored from.
    restored: HashMap<String, String>,
}

impl ReadCache {
    /// Run the read path over one incoming kind-42 and return what the reader
    /// should see. Call only for events [`is_zone_message`](super::is_zone_message)
    /// accepts; the caller marks the returned event's id as encrypted.
    ///
    /// A live encrypted post comes back with its own id and the decrypted
    /// text or a placeholder. A sealed envelope comes back as the original
    /// event when it opens, or as a placeholder under the envelope's id.
    pub fn prepare(
        &mut self,
        ev: &NostrEvent,
        lookup: impl Fn(&str, u32) -> Option<ZoneKey>,
    ) -> NostrEvent {
        if has_sealed_tag(&ev.tags) {
            self.envelopes
                .entry(ev.id.clone())
                .or_insert_with(|| ev.clone());
        } else {
            self.ciphertexts
                .entry(ev.id.clone())
                .or_insert_with(|| ev.content.clone());
        }
        let outcome = read_outcome(ev, lookup);
        if let ReadOutcome::Sealed(inner) = &outcome {
            self.restored
                .entry(inner.id.clone())
                .or_insert_with(|| ev.id.clone());
        }
        resolve_event(ev, outcome)
    }

    /// Re-run the read path over every message already on screen (a key just
    /// arrived), grouped as the channel store holds them.
    ///
    /// A live encrypted post has its content recomputed. A sealed-envelope
    /// placeholder that now opens is replaced **in place** by the original
    /// event; if that original's id is already in the same list (a copy
    /// fetched before the plaintext was purged, or a second envelope of the
    /// same original), the placeholder is dropped rather than duplicated. A
    /// restored original whose id `admits` refuses (a NIP-09 tombstone for
    /// the original id) is dropped too, the same gate every insertion path
    /// applies. Returns whether any list changed length or content.
    pub fn redecrypt(
        &mut self,
        messages: &mut HashMap<String, Vec<NostrEvent>>,
        lookup: impl Fn(&str, u32) -> Option<ZoneKey>,
        admits: impl Fn(&str) -> bool,
    ) -> bool {
        let mut changed = false;
        for events in messages.values_mut() {
            let mut restored_now: HashSet<String> = HashSet::new();
            for ev in events.iter_mut() {
                if let Some(ct) = self.ciphertexts.get(&ev.id) {
                    let mut original = ev.clone();
                    original.content = ct.clone();
                    let text = display_text(&read_outcome(&original, &lookup), ct);
                    if ev.content != text {
                        ev.content = text;
                        changed = true;
                    }
                } else if let Some(outer) = self.envelopes.get(&ev.id) {
                    match read_outcome(outer, &lookup) {
                        ReadOutcome::Sealed(inner) => {
                            self.restored
                                .entry(inner.id.clone())
                                .or_insert_with(|| outer.id.clone());
                            restored_now.insert(inner.id.clone());
                            *ev = inner;
                            changed = true;
                        }
                        other => {
                            let text = display_text(&other, &outer.content);
                            if ev.content != text {
                                ev.content = text;
                                changed = true;
                            }
                        }
                    }
                }
            }
            if restored_now.is_empty() {
                continue;
            }
            // First occurrence wins: the original keeps its created_at, so
            // the list's ordering is unchanged by the swap.
            let mut seen: HashSet<String> = HashSet::with_capacity(events.len());
            let before = events.len();
            events.retain(|e| {
                (!restored_now.contains(&e.id) || admits(&e.id)) && seen.insert(e.id.clone())
            });
            changed |= events.len() != before;
        }
        changed
    }

    /// The envelope id `inner_id` was restored from, if it came out of a
    /// sealed original this session.
    pub fn envelope_of(&self, inner_id: &str) -> Option<&str> {
        self.restored.get(inner_id).map(String::as_str)
    }

    /// Whether nothing has been cached yet (no zone-encrypted message seen).
    pub fn is_empty(&self) -> bool {
        self.ciphertexts.is_empty() && self.envelopes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stores::channels::insert_message;
    use crate::stores::reactions::{build_reactions, fold_add, parse_reaction};
    use crate::zone_crypto::{
        is_zone_message, zk_tag, PLACEHOLDER_MISSING_KEY, PLACEHOLDER_UNDECRYPTABLE,
    };
    use k256::schnorr::SigningKey;
    use nostr_bbs_core::keys::SecretKey;
    use nostr_bbs_core::sealed::seal_original;
    use nostr_bbs_core::{sign_event_deterministic, UnsignedEvent};

    const ALICE: [u8; 32] = [0x11; 32];
    const MIGRATOR: [u8; 32] = [0x22; 32];
    const ZONE: [u8; 32] = [0x33; 32];
    const BOB: [u8; 32] = [0x44; 32];

    fn channel() -> String {
        "c".repeat(64)
    }

    fn pk_hex(sk: [u8; 32]) -> String {
        SecretKey::from_bytes(sk).unwrap().public_key().to_hex()
    }

    fn zone_key() -> ZoneKey {
        ZoneKey {
            zone: "zone3".into(),
            epoch: 1,
            secret: hex::encode(ZONE),
            pubkey: pk_hex(ZONE),
            granted_by: pk_hex(MIGRATOR),
            received_at: 0,
        }
    }

    fn with_key(z: &str, e: u32) -> Option<ZoneKey> {
        (z == "zone3" && e == 1).then(zone_key)
    }

    fn no_key(_: &str, _: u32) -> Option<ZoneKey> {
        None
    }

    fn signed(sk: [u8; 32], created_at: u64, tags: Vec<Vec<String>>, content: &str) -> NostrEvent {
        sign_event_deterministic(
            UnsignedEvent {
                pubkey: pk_hex(sk),
                created_at,
                kind: 42,
                tags,
                content: content.into(),
            },
            &SigningKey::from_bytes(&sk).unwrap(),
        )
        .unwrap()
    }

    fn root_tag() -> Vec<String> {
        vec!["e".into(), channel(), "".into(), "root".into()]
    }

    /// A plaintext message from before encryption was switched on.
    fn original(created_at: u64, content: &str) -> NostrEvent {
        signed(ALICE, created_at, vec![root_tag()], content)
    }

    fn seal(orig: &NostrEvent) -> NostrEvent {
        let migrator = SecretKey::from_bytes(MIGRATOR).unwrap();
        seal_original(orig, "zone3", 1, &pk_hex(ZONE), &migrator).unwrap()
    }

    /// A live encrypted post (ADR-2016) by `sk`.
    fn live_encrypted(sk: [u8; 32], created_at: u64, text: &str) -> NostrEvent {
        let zone_pk: [u8; 32] = hex::decode(pk_hex(ZONE)).unwrap().try_into().unwrap();
        let ct = nostr_bbs_core::nip44_encrypt(&sk, &zone_pk, text).unwrap();
        signed(sk, created_at, vec![root_tag(), zk_tag(&zone_key())], &ct)
    }

    fn same_event(a: &NostrEvent, b: &NostrEvent) -> bool {
        ReadOutcome::Sealed(a.clone()) == ReadOutcome::Sealed(b.clone())
    }

    fn ids(v: &[NostrEvent]) -> Vec<&str> {
        v.iter().map(|e| e.id.as_str()).collect()
    }

    fn one_channel(events: Vec<NostrEvent>) -> HashMap<String, Vec<NostrEvent>> {
        HashMap::from([(channel(), events)])
    }

    #[test]
    fn sealed_original_round_trips_through_prepare() {
        let orig = original(1_700_000_000, "hello from before encryption");
        let env = seal(&orig);
        assert!(is_zone_message(&env));
        assert_ne!(env.id, orig.id);

        let mut cache = ReadCache::default();
        let shown = cache.prepare(&env, with_key);
        assert!(
            same_event(&shown, &orig),
            "the whole original event is substituted, not just its content"
        );
        assert_eq!(shown.pubkey, pk_hex(ALICE), "attributed to the author");
        assert_eq!(cache.envelope_of(&orig.id), Some(env.id.as_str()));
    }

    #[test]
    fn sealed_envelope_is_never_a_plain_decryption() {
        let orig = original(1_700_000_000, "hi");
        let env = seal(&orig);
        // The envelope carries a normal zk tag and NIP-44 content, so the live
        // path alone would "decrypt" it into the original's JSON.
        match read_outcome(&env, with_key) {
            ReadOutcome::Sealed(inner) => assert_eq!(inner.id, orig.id),
            other => panic!("expected Sealed, got {other:?}"),
        }
        assert_eq!(read_outcome(&env, no_key), ReadOutcome::MissingKey);

        // A key whose pubkey does not match the zk tag is a failure, as for
        // live posts.
        let mut wrong = zone_key();
        wrong.pubkey = pk_hex(BOB);
        assert_eq!(
            read_outcome(&env, move |_, _| Some(wrong.clone())),
            ReadOutcome::Failed
        );

        // A sealed tag with no zk tag cannot be opened: failure, not plaintext.
        let mut untagged = env.clone();
        untagged.tags.retain(|t| t[0] != "zk");
        assert_eq!(read_outcome(&untagged, with_key), ReadOutcome::Failed);
    }

    #[test]
    fn json_text_in_a_live_post_is_not_mistaken_for_an_envelope() {
        let orig = original(1_700_000_000, "inner");
        let json = serde_json::to_string(&orig).unwrap();
        let live = live_encrypted(BOB, 1_700_000_100, &json);
        assert_eq!(read_outcome(&live, with_key), ReadOutcome::Decrypted(json));
    }

    #[test]
    fn placeholder_becomes_the_original_in_place_when_the_key_arrives() {
        let before = original(100, "earlier plaintext");
        let orig = original(200, "sealed later");
        let after = original(300, "later plaintext");
        let env = seal(&orig);

        let mut cache = ReadCache::default();
        let placeholder = cache.prepare(&env, no_key);
        assert_eq!(placeholder.id, env.id, "placeholder keeps the envelope id");
        assert_eq!(placeholder.content, PLACEHOLDER_MISSING_KEY);

        let mut msgs = one_channel(Vec::new());
        let list = msgs.get_mut(&channel()).unwrap();
        for ev in [before.clone(), placeholder, after.clone()] {
            assert!(insert_message(list, ev));
        }

        assert!(cache.redecrypt(&mut msgs, with_key, |_| true));
        let list = &msgs[&channel()];
        assert_eq!(ids(list), vec![&before.id, &orig.id, &after.id]);
        assert!(same_event(&list[1], &orig));
        assert!(
            !list.iter().any(|e| e.id == env.id),
            "the placeholder is gone"
        );

        // Idempotent: nothing left to restore.
        assert!(!cache.redecrypt(&mut msgs, with_key, |_| true));
        assert_eq!(msgs[&channel()].len(), 3);

        // The relay re-sends the envelope (reconnect): the channel store's
        // id-dedupe sees the original id and refuses a second copy.
        let again = cache.prepare(&env, with_key);
        assert!(!insert_message(msgs.get_mut(&channel()).unwrap(), again));
        assert_eq!(msgs[&channel()].len(), 3);
    }

    #[test]
    fn restored_placeholder_dedupes_against_the_plaintext_copy() {
        // During migration the relay still holds the plaintext row, so a
        // member can have the original on screen next to the envelope's
        // placeholder.
        let orig = original(200, "both copies");
        let env = seal(&orig);
        let mut cache = ReadCache::default();
        let placeholder = cache.prepare(&env, no_key);

        let mut msgs = one_channel(Vec::new());
        let list = msgs.get_mut(&channel()).unwrap();
        assert!(insert_message(list, orig.clone()));
        assert!(insert_message(list, placeholder));
        assert_eq!(list.len(), 2);

        assert!(cache.redecrypt(&mut msgs, with_key, |_| true));
        assert_eq!(ids(&msgs[&channel()]), vec![orig.id.as_str()]);

        // Two envelopes of the same original (the migrator re-run) collapse
        // to one message as well.
        let migrator2 = SecretKey::from_bytes([0x55; 32]).unwrap();
        let env2 = seal_original(&orig, "zone3", 1, &pk_hex(ZONE), &migrator2).unwrap();
        assert_ne!(env2.id, env.id);
        let mut cache = ReadCache::default();
        let mut msgs = one_channel(Vec::new());
        let list = msgs.get_mut(&channel()).unwrap();
        assert!(insert_message(list, cache.prepare(&env, no_key)));
        assert!(insert_message(list, cache.prepare(&env2, no_key)));
        assert!(cache.redecrypt(&mut msgs, with_key, |_| true));
        assert_eq!(ids(&msgs[&channel()]), vec![orig.id.as_str()]);
    }

    #[test]
    fn envelope_with_key_held_dedupes_on_insertion() {
        let orig = original(200, "already here");
        let env = seal(&orig);
        let mut cache = ReadCache::default();
        let mut list = vec![orig.clone()];
        let shown = cache.prepare(&env, with_key);
        assert!(
            !insert_message(&mut list, shown),
            "dedupe sees the inner id"
        );
        assert_eq!(ids(&list), vec![orig.id.as_str()]);
    }

    #[test]
    fn tombstoned_original_is_not_restored() {
        let orig = original(200, "deleted by its author");
        let env = seal(&orig);
        let mut cache = ReadCache::default();
        let mut msgs = one_channel(vec![cache.prepare(&env, no_key)]);
        let deleted = orig.id.clone();
        assert!(cache.redecrypt(&mut msgs, with_key, |id| id != deleted));
        assert!(msgs[&channel()].is_empty());
    }

    #[test]
    fn tampered_envelope_shows_the_undecryptable_placeholder() {
        let orig = original(200, "tamper me");
        let mut env = seal(&orig);
        // Flip one base64 character in the NIP-44 payload: the MAC fails.
        let mut ct: Vec<char> = env.content.chars().collect();
        let i = ct.len() / 2;
        ct[i] = if ct[i] == 'A' { 'B' } else { 'A' };
        env.content = ct.into_iter().collect();

        let mut cache = ReadCache::default();
        let shown = cache.prepare(&env, with_key);
        assert_eq!(shown.id, env.id);
        assert_eq!(shown.pubkey, env.pubkey);
        assert_eq!(shown.content, PLACEHOLDER_UNDECRYPTABLE);

        // Arriving without a key first, it stays a placeholder (now the
        // undecryptable one) under the envelope id once the key arrives.
        let mut cache = ReadCache::default();
        let mut msgs = one_channel(vec![cache.prepare(&env, no_key)]);
        assert_eq!(msgs[&channel()][0].content, PLACEHOLDER_MISSING_KEY);
        assert!(cache.redecrypt(&mut msgs, with_key, |_| true));
        let list = &msgs[&channel()];
        assert_eq!(ids(list), vec![env.id.as_str()]);
        assert_eq!(list[0].content, PLACEHOLDER_UNDECRYPTABLE);
        assert_eq!(cache.envelope_of(&orig.id), None);
    }

    #[test]
    fn live_encrypted_posts_are_unchanged() {
        let live = live_encrypted(BOB, 500, "family news");
        let mut cache = ReadCache::default();

        let shown = cache.prepare(&live, with_key);
        assert_eq!(shown.id, live.id);
        assert_eq!(shown.pubkey, live.pubkey);
        assert_eq!(shown.tags, live.tags);
        assert_eq!(shown.content, "family news");

        let mut cache = ReadCache::default();
        let placeholder = cache.prepare(&live, no_key);
        assert_eq!(placeholder.id, live.id);
        assert_eq!(placeholder.content, PLACEHOLDER_MISSING_KEY);
        let mut msgs = one_channel(vec![placeholder]);
        assert!(cache.redecrypt(&mut msgs, with_key, |_| true));
        let list = &msgs[&channel()];
        assert_eq!(ids(list), vec![live.id.as_str()]);
        assert_eq!(list[0].content, "family news");
        assert!(!cache.redecrypt(&mut msgs, with_key, |_| true));
    }

    #[test]
    fn reactions_and_replies_to_the_original_attach_to_the_restored_message() {
        let orig = original(200, "topic opener");
        let env = seal(&orig);
        // A reply and a reaction written before migration, naming the original.
        let reply = signed(
            BOB,
            300,
            vec![
                root_tag(),
                vec!["e".into(), orig.id.clone(), "".into(), "reply".into()],
            ],
            "a reply",
        );
        let reaction = NostrEvent {
            id: "k7".into(),
            pubkey: pk_hex(BOB),
            created_at: 301,
            kind: 7,
            tags: vec![vec!["e".into(), orig.id.clone()]],
            content: "+".into(),
            sig: String::new(),
        };
        let mut aggregate = HashMap::new();
        let mut index = HashMap::new();
        fold_add(
            &mut aggregate,
            &mut index,
            &HashSet::new(),
            reaction.id.clone(),
            parse_reaction(&reaction).unwrap(),
        );

        let mut cache = ReadCache::default();
        let mut msgs = one_channel(Vec::new());
        let list = msgs.get_mut(&channel()).unwrap();
        assert!(insert_message(list, cache.prepare(&env, no_key)));
        assert!(insert_message(list, reply.clone()));

        // While only the placeholder is on screen nothing attaches to it.
        let placeholder = &msgs[&channel()][0];
        assert!(build_reactions(aggregate.get(&placeholder.id), "").is_empty());

        assert!(cache.redecrypt(&mut msgs, with_key, |_| true));
        let list = &msgs[&channel()];
        let restored = &list[0];
        assert_eq!(restored.id, orig.id);

        let pills = build_reactions(aggregate.get(&restored.id.to_lowercase()), "");
        assert_eq!(pills.len(), 1);
        assert_eq!(pills[0].count, 1);

        assert_eq!(
            nostr_bbs_core::reply_parent(&list[1]).as_deref(),
            Some(orig.id.as_str())
        );
        let thread = nostr_bbs_core::thread_messages(list, &channel(), &orig.id);
        assert_eq!(ids(&thread), vec![orig.id.as_str(), reply.id.as_str()]);
    }
}
