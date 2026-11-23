//! Events already verified this session, so an envelope delivered on several
//! subscriptions pays its Schnorr verification once.
//!
//! The relay socket verifies every event before dispatch (id recomputed, then
//! the BIP-340 signature), and the per-subscription dedupe runs after that,
//! so the same sealed envelope arriving on the zone sync, the channel page and
//! a history page was verified up to three times (~620 µs each in wasm).
//!
//! **What is skipped, and why it is safe.** Only the signature check is
//! skipped, and only for an event whose `(id, sig)` pair was verified before
//! AND whose id still recomputes from the event's own fields. The id is the
//! SHA-256 of `[0, pubkey, created_at, kind, tags, content]`, so a recomputed
//! match proves every signed field is byte-identical to the verified event,
//! and the signature string is compared exactly. A relay replaying a known id
//! with altered content, author or signature therefore fails the id or the
//! sig comparison and goes through full verification (and is dropped). The
//! cache holds public data only (ids and signatures), never plaintext or
//! keys, and verification does not depend on who is signed in, so it is not
//! cleared on an identity switch.

use std::collections::{HashMap, VecDeque};

use nostr_bbs_core::NostrEvent;

/// Verified ids kept at most; least recently seen evicted first. The cache
/// only has to span re-deliveries close in time (one envelope on the zone
/// sync, the channel REQ and a history page), and each entry costs ~0.7 KB
/// of wasm heap (measured), so 5,000 keeps it near 3.5 MB.
pub(crate) const VERIFIED_CAPACITY: usize = 5_000;

/// A bounded least-recently-used set of verified `(id, sig)` pairs.
///
/// Recency is kept with a queue of `(id, tick)` and lazy deletion: a hit
/// pushes a fresh tick, and eviction skips queue entries whose tick is stale.
/// The queue is compacted when it outgrows twice the capacity.
pub(crate) struct VerifiedIds {
    capacity: usize,
    tick: u64,
    by_id: HashMap<String, (String, u64)>,
    order: VecDeque<(String, u64)>,
}

impl Default for VerifiedIds {
    fn default() -> Self {
        Self::with_capacity(VERIFIED_CAPACITY)
    }
}

impl VerifiedIds {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            tick: 0,
            by_id: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Whether `event` is one already verified: same id, same signature, and
    /// the id recomputes from the event's fields. A hit refreshes recency.
    pub(crate) fn already_verified(&mut self, event: &NostrEvent) -> bool {
        let Some((sig, _)) = self.by_id.get(&event.id) else {
            return false;
        };
        if *sig != event.sig {
            return false;
        }
        if hex::encode(nostr_bbs_core::event::recompute_event_id(event)) != event.id {
            return false;
        }
        self.touch(&event.id);
        true
    }

    /// Record `event` after it passed `verify_event_strict`.
    pub(crate) fn insert(&mut self, event: &NostrEvent) {
        self.tick += 1;
        self.by_id
            .insert(event.id.clone(), (event.sig.clone(), self.tick));
        self.order.push_back((event.id.clone(), self.tick));
        self.evict();
    }

    #[cfg(any(test, feature = "alloc-stats"))]
    pub(crate) fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Recency-queue length (diagnostics).
    #[cfg(feature = "alloc-stats")]
    pub(crate) fn queue_len(&self) -> usize {
        self.order.len()
    }

    fn touch(&mut self, id: &str) {
        self.tick += 1;
        if let Some(entry) = self.by_id.get_mut(id) {
            entry.1 = self.tick;
        }
        self.order.push_back((id.to_string(), self.tick));
        self.evict();
    }

    fn evict(&mut self) {
        while self.by_id.len() > self.capacity {
            let Some((id, tick)) = self.order.pop_front() else {
                break;
            };
            if self.by_id.get(&id).is_some_and(|(_, t)| *t == tick) {
                self.by_id.remove(&id);
            }
        }
        if self.order.len() > self.capacity * 2 {
            let by_id = &self.by_id;
            self.order
                .retain(|(id, tick)| by_id.get(id).is_some_and(|(_, t)| t == tick));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::SigningKey;
    use nostr_bbs_core::{sign_event_deterministic, verify_event_strict, UnsignedEvent};

    fn signed(content: &str, created_at: u64) -> NostrEvent {
        let sk = SigningKey::from_bytes(&[0x11; 32].into()).unwrap();
        sign_event_deterministic(
            UnsignedEvent {
                pubkey: hex::encode(sk.verifying_key().to_bytes()),
                created_at,
                kind: 42,
                tags: vec![vec!["e".into(), "c".repeat(64)]],
                content: content.into(),
            },
            &sk,
        )
        .unwrap()
    }

    #[test]
    fn an_unseen_event_is_not_known() {
        let mut v = VerifiedIds::default();
        assert!(!v.already_verified(&signed("a", 1)));
    }

    #[test]
    fn a_verified_event_delivered_again_skips_the_signature_check() {
        let mut v = VerifiedIds::default();
        let ev = signed("a", 1);
        verify_event_strict(&ev).unwrap();
        v.insert(&ev);
        assert!(v.already_verified(&ev.clone()));
    }

    #[test]
    fn a_known_id_with_altered_fields_or_signature_is_not_known() {
        let mut v = VerifiedIds::default();
        let ev = signed("a", 1);
        v.insert(&ev);

        let mut content = ev.clone();
        content.content = "forged".into();
        assert!(!v.already_verified(&content), "altered content");

        let mut author = ev.clone();
        author.pubkey = "ab".repeat(32);
        assert!(!v.already_verified(&author), "altered author");

        let mut tags = ev.clone();
        tags.tags.push(vec!["p".into(), "cd".repeat(32)]);
        assert!(!v.already_verified(&tags), "altered tags");

        let mut sig = ev.clone();
        sig.sig = signed("b", 2).sig;
        assert!(!v.already_verified(&sig), "another signature");
        assert!(verify_event_strict(&sig).is_err());
    }

    #[test]
    fn capacity_evicts_the_least_recently_seen() {
        let mut v = VerifiedIds::with_capacity(3);
        let evs: Vec<NostrEvent> = (0..4).map(|i| signed("x", i)).collect();
        v.insert(&evs[0]);
        v.insert(&evs[1]);
        v.insert(&evs[2]);
        assert!(v.already_verified(&evs[0]), "refreshes 0");
        v.insert(&evs[3]);
        assert_eq!(v.len(), 3);
        assert!(!v.already_verified(&evs[1]), "1 was least recent");
        assert!(v.already_verified(&evs[0]));
        assert!(v.already_verified(&evs[3]));
    }

    #[test]
    fn the_recency_queue_stays_bounded_under_repeated_hits() {
        let mut v = VerifiedIds::with_capacity(2);
        let ev = signed("x", 1);
        v.insert(&ev);
        for _ in 0..100 {
            assert!(v.already_verified(&ev));
        }
        assert!(v.order.len() <= 4);
    }
}
