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
    /// arrived, or every key was dropped at sign-out), grouped as the channel
    /// store holds them.
    ///
    /// A live encrypted post has its content recomputed. A restored original
    /// whose envelope no longer opens (its key is gone) goes back to the
    /// envelope's placeholder under the envelope's id, so no plaintext stays
    /// on screen once the keys are dropped. A sealed-envelope
    /// placeholder that now opens is replaced **in place** by the original
    /// event; if that original's id is already in the same list (a copy
    /// fetched before the plaintext was purged, or a second envelope of the
    /// same original), the placeholder is dropped rather than duplicated. A
    /// restored original that `admits` refuses (a NIP-09 tombstone for the
    /// original id from its author or an admin) is dropped too, the same gate every insertion path
    /// applies. Returns whether any list changed length or content.
    pub fn redecrypt(
        &mut self,
        messages: &mut HashMap<String, Vec<NostrEvent>>,
        lookup: impl Fn(&str, u32) -> Option<ZoneKey>,
        admits: impl Fn(&NostrEvent) -> bool,
    ) -> bool {
        self.redecrypt_with(messages, |ev| Some(read_outcome(ev, &lookup)), admits)
    }

    /// The events [`redecrypt`](Self::redecrypt) would run the read path on
    /// for `messages`, newest first, each once: a live post's original
    /// ciphertext (under its own id), a placeholder's envelope, and the
    /// envelope of a restored original. A chunked pass opens these a few at a
    /// time (see `ZoneKeyStore::redecrypt_chunked`) and applies each chunk
    /// with [`redecrypt_with`](Self::redecrypt_with).
    pub fn open_targets(&self, messages: &HashMap<String, Vec<NostrEvent>>) -> Vec<NostrEvent> {
        let mut seen: HashSet<&str> = HashSet::new();
        let mut out: Vec<NostrEvent> = Vec::new();
        for ev in messages.values().flatten() {
            if let Some(ct) = self.ciphertexts.get(&ev.id) {
                if seen.insert(ev.id.as_str()) {
                    let mut original = ev.clone();
                    original.content = ct.clone();
                    out.push(original);
                }
            } else if let Some(outer) = self.envelopes.get(&ev.id).or_else(|| {
                self.restored
                    .get(&ev.id)
                    .and_then(|outer_id| self.envelopes.get(outer_id))
            }) {
                if seen.insert(outer.id.as_str()) {
                    out.push(outer.clone());
                }
            }
        }
        out.sort_by_key(|e| std::cmp::Reverse(e.created_at));
        out
    }

    /// [`redecrypt`](Self::redecrypt) with the read-path outcome supplied by
    /// `outcome_of`, called with the event to open (as
    /// [`open_targets`](Self::open_targets) lists them). `None` leaves that
    /// message exactly as it is, so a chunked pass applies only the outcomes
    /// it has computed so far; the swap and dedupe rules are the same.
    pub fn redecrypt_with(
        &mut self,
        messages: &mut HashMap<String, Vec<NostrEvent>>,
        mut outcome_of: impl FnMut(&NostrEvent) -> Option<ReadOutcome>,
        admits: impl Fn(&NostrEvent) -> bool,
    ) -> bool {
        let mut changed = false;
        for events in messages.values_mut() {
            let mut restored_now: HashSet<String> = HashSet::new();
            let mut reverted_now = false;
            for ev in events.iter_mut() {
                if let Some(ct) = self.ciphertexts.get(&ev.id) {
                    let mut original = ev.clone();
                    original.content = ct.clone();
                    let Some(outcome) = outcome_of(&original) else {
                        continue;
                    };
                    let text = display_text(&outcome, ct);
                    if ev.content != text {
                        ev.content = text;
                        changed = true;
                    }
                } else if let Some(outer) = self.envelopes.get(&ev.id) {
                    let Some(outcome) = outcome_of(outer) else {
                        continue;
                    };
                    match outcome {
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
                } else if let Some(outer) = self
                    .restored
                    .get(&ev.id)
                    .and_then(|outer_id| self.envelopes.get(outer_id))
                {
                    let Some(outcome) = outcome_of(outer) else {
                        continue;
                    };
                    if !matches!(outcome, ReadOutcome::Sealed(_)) {
                        let inner_id = ev.id.clone();
                        *ev = resolve_event(outer, outcome);
                        self.restored.remove(&inner_id);
                        reverted_now = true;
                        changed = true;
                    }
                }
            }
            if restored_now.is_empty() && !reverted_now {
                continue;
            }
            // First occurrence wins: the original keeps its created_at, so
            // the list's ordering is unchanged by the swap.
            let mut seen: HashSet<String> = HashSet::with_capacity(events.len());
            let before = events.len();
            events.retain(|e| {
                (!restored_now.contains(&e.id) || admits(e)) && seen.insert(e.id.clone())
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

    /// Forget the messages `ids` (ids as they appear in the channel lists),
    /// as history paging evicts them: a live post's ciphertext, a
    /// placeholder's envelope, and for a restored sealed original both the
    /// id mapping and the envelope it came from. The cache then holds no
    /// trace of an evicted message, so nothing of it can be re-opened or
    /// re-displayed until the relay delivers it again.
    pub fn evict<'a>(&mut self, ids: impl IntoIterator<Item = &'a str>) {
        for id in ids {
            self.ciphertexts.remove(id);
            self.envelopes.remove(id);
            if let Some(outer) = self.restored.remove(id) {
                self.envelopes.remove(&outer);
            }
        }
    }

    /// Entries held (ciphertexts, envelopes, restored mappings), for tests
    /// and the `alloc-stats` diagnostics.
    #[cfg(any(test, feature = "alloc-stats"))]
    pub fn len(&self) -> usize {
        self.ciphertexts.len() + self.envelopes.len() + self.restored.len()
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
            group: None,
            pending_delivery: false,
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
            &SigningKey::from_bytes((&sk).into()).unwrap(),
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

    /// The chunked pass (open `open_targets` a few at a time, apply each
    /// chunk with `redecrypt_with`) ends exactly where one full `redecrypt`
    /// does, and a partial pass leaves unreached messages untouched.
    #[test]
    fn chunked_redecrypt_matches_a_full_pass() {
        let build = |cache: &mut ReadCache| {
            let mut msgs = one_channel(Vec::new());
            let list = msgs.get_mut(&channel()).unwrap();
            for i in 0..12u64 {
                let ev = if i % 3 == 0 {
                    live_encrypted(ALICE, 100 + i, &format!("live {i}"))
                } else {
                    seal(&original(100 + i, &format!("sealed {i}")))
                };
                assert!(insert_message(list, cache.prepare(&ev, no_key)));
            }
            msgs
        };
        let mut full_cache = ReadCache::default();
        let mut full = build(&mut full_cache);
        assert!(full_cache.redecrypt(&mut full, with_key, |_| true));

        let mut cache = ReadCache::default();
        let mut msgs = build(&mut cache);
        let targets = cache.open_targets(&msgs);
        assert_eq!(targets.len(), 12, "each message's source once");
        assert!(
            targets
                .windows(2)
                .all(|w| w[0].created_at >= w[1].created_at),
            "newest first"
        );
        let mut first = true;
        for chunk in targets.chunks(5) {
            let mut outcomes: HashMap<String, ReadOutcome> = chunk
                .iter()
                .map(|ev| (ev.id.clone(), read_outcome(ev, with_key)))
                .collect();
            cache.redecrypt_with(&mut msgs, |ev| outcomes.remove(&ev.id), |_| true);
            if first {
                // Only the newest five are decrypted so far.
                let shown = &msgs[&channel()];
                let locked = shown
                    .iter()
                    .filter(|e| e.content == PLACEHOLDER_MISSING_KEY)
                    .count();
                assert_eq!(locked, 7);
                first = false;
            }
        }
        // Live posts are re-encrypted with a fresh nonce per build, so their
        // ids differ between the two lists; compare what the reader sees, and
        // the restored originals (deterministic) whole.
        let seen = |m: &HashMap<String, Vec<NostrEvent>>| -> Vec<(u64, String, Option<String>)> {
            m[&channel()]
                .iter()
                .map(|e| {
                    let sealed_id = (!e.tags.iter().any(|t| t[0] == "zk")).then(|| e.id.clone());
                    (e.created_at, e.content.clone(), sealed_id)
                })
                .collect()
        };
        assert_eq!(seen(&msgs), seen(&full));
        assert!(!msgs[&channel()]
            .iter()
            .any(|e| e.content == PLACEHOLDER_MISSING_KEY));
    }

    /// One event id can sit in two channel lists (the history paths resolve
    /// the list key differently). A chunked apply must reach every copy, as
    /// `apply_outcomes` does by cloning each outcome instead of taking it.
    #[test]
    fn a_chunk_outcome_reaches_every_copy_of_an_event() {
        let mut cache = ReadCache::default();
        let env = seal(&original(100, "twice"));
        let placeholder = cache.prepare(&env, no_key);
        let mut msgs: HashMap<String, Vec<NostrEvent>> = HashMap::new();
        msgs.insert("by-id".into(), vec![placeholder.clone()]);
        msgs.insert("by-name".into(), vec![placeholder]);
        let outcomes: HashMap<String, ReadOutcome> = cache
            .open_targets(&msgs)
            .iter()
            .map(|ev| (ev.id.clone(), read_outcome(ev, with_key)))
            .collect();
        assert_eq!(outcomes.len(), 1, "one source to open");
        cache.redecrypt_with(&mut msgs, |ev| outcomes.get(&ev.id).cloned(), |_| true);
        for list in msgs.values() {
            assert_eq!(list[0].content, "twice");
        }
    }

    /// Evicting a page leaves no cache entry behind: a restored original's
    /// envelope is reached through the restored mapping, a live post's
    /// ciphertext and a placeholder's envelope by their own ids.
    #[test]
    fn evict_drops_every_trace_of_the_evicted_messages() {
        let mut cache = ReadCache::default();
        let mut msgs = one_channel(Vec::new());
        let list = msgs.get_mut(&channel()).unwrap();
        let sealed = seal(&original(100, "sealed"));
        let live = live_encrypted(ALICE, 101, "live");
        let locked = seal(&original(102, "locked"));
        assert!(insert_message(list, cache.prepare(&sealed, with_key)));
        assert!(insert_message(list, cache.prepare(&live, with_key)));
        assert!(insert_message(list, cache.prepare(&locked, no_key)));
        assert!(
            cache.len() >= 4,
            "restored + envelope, ciphertext, envelope"
        );
        let ids: Vec<String> = msgs[&channel()].iter().map(|e| e.id.clone()).collect();
        assert_ne!(
            ids[0], sealed.id,
            "the list holds the restored original's id"
        );
        cache.evict(ids.iter().map(String::as_str));
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
        // The same envelopes delivered again are prepared afresh.
        let again = cache.prepare(&sealed, with_key);
        assert_eq!(again.content, "sealed");
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
    fn a_restored_original_reverts_to_the_placeholder_when_the_key_is_dropped() {
        let orig = original(100, "family plans");
        let env = seal(&orig);
        let mut cache = ReadCache::default();
        let mut msgs = one_channel(vec![cache.prepare(&env, with_key)]);
        assert!(
            same_event(&msgs[&channel()][0], &orig),
            "opened with the key"
        );
        // Sign-out: every key dropped, the store re-runs the read path.
        assert!(cache.redecrypt(&mut msgs, no_key, |_| true));
        let shown = &msgs[&channel()];
        assert_eq!(
            ids(shown),
            vec![env.id.as_str()],
            "back under the envelope id"
        );
        assert_eq!(shown[0].content, PLACEHOLDER_MISSING_KEY);
        assert!(cache.envelope_of(&orig.id).is_none());
        assert!(!shown.iter().any(|e| e.content.contains("family plans")));
        // Signing back in restores it in place again.
        assert!(cache.redecrypt(&mut msgs, with_key, |_| true));
        assert!(same_event(&msgs[&channel()][0], &orig));
    }

    #[test]
    fn a_live_post_goes_back_to_the_placeholder_when_the_key_is_dropped() {
        let ev = live_encrypted(ALICE, 100, "dinner at eight");
        let mut cache = ReadCache::default();
        let mut msgs = one_channel(vec![cache.prepare(&ev, with_key)]);
        assert_eq!(msgs[&channel()][0].content, "dinner at eight");
        assert!(cache.redecrypt(&mut msgs, no_key, |_| true));
        assert_eq!(msgs[&channel()][0].content, PLACEHOLDER_MISSING_KEY);
    }

    #[test]
    fn tombstoned_original_is_not_restored() {
        let orig = original(200, "deleted by its author");
        let env = seal(&orig);
        let mut cache = ReadCache::default();
        let mut msgs = one_channel(vec![cache.prepare(&env, no_key)]);
        let deleted = orig.id.clone();
        assert!(cache.redecrypt(&mut msgs, with_key, |e: &NostrEvent| e.id != deleted));
        assert!(msgs[&channel()].is_empty());
    }

    /// The sealed-original rule hangs on the read path recording which
    /// envelope an original came from: `envelope_of` must be set once it
    /// opens, by `prepare` and by the in-place restore, and the restore must
    /// then honour only the inner author's tombstone, not another member's.
    #[test]
    fn a_restored_original_is_hidden_only_by_its_authors_tombstone() {
        use crate::stores::tombstones::{admits, Target, Tombstones};
        let mallory = "d".repeat(64);

        let orig = original(200, "mine to delete");
        let env = seal(&orig);

        // Opened at once by `prepare`.
        let mut cache = ReadCache::default();
        let restored = cache.prepare(&env, with_key);
        assert_eq!(restored.id, orig.id);
        assert_eq!(restored.pubkey, orig.pubkey, "author is the inner author");
        assert_eq!(cache.envelope_of(&orig.id), Some(env.id.as_str()));

        // Opened later, in place, after a key arrives.
        for (deleter, kept) in [(mallory, true), (orig.pubkey.clone(), false)] {
            let mut t = Tombstones::default();
            t.record(&orig.id, &deleter);
            let mut cache = ReadCache::default();
            let mut msgs = one_channel(vec![cache.prepare(&env, no_key)]);
            assert!(cache.envelope_of(&orig.id).is_none(), "not opened yet");
            cache.redecrypt(&mut msgs, with_key, |e: &NostrEvent| {
                admits(&t, &e.id, Target::of(e, true), |_| false)
            });
            assert_eq!(cache.envelope_of(&orig.id), Some(env.id.as_str()));
            assert_eq!(!msgs[&channel()].is_empty(), kept, "deleter {deleter}");
        }
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
