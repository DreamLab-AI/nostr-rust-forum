//! The cross-device copy of a member's thread subscriptions.
//!
//! One NIP-78 application-data event per member: kind 30078, addressable by
//! its `d` tag, whose **only** tag is `["d", "nostr-bbs/thread-subs/v1"]`.
//! There are no `e`, `a` or `p` tags, ever: they would publish which topics
//! the member follows. Everything else is compact JSON
//! (`{"subs":[{r,c,z,on,at,rd}]}`, the same shape as the local copy, read
//! marker inline, no titles) inside NIP-44 content encrypted by the member to
//! their own key through the auth store's [`Signer`] — the precedent is the
//! zone inbox-key backup (`zone_crypto::inbox_key::build_backup`). No other
//! envelope, no hand-rolled cryptography.
//!
//! What the relay (and anyone who asks it: kind 30078 is not read-gated) can
//! still see: the author, the `d` tag, when the copy last changed and roughly
//! how large it is.
//!
//! ## Rules
//!
//! - Fetch, then merge entry by entry
//!   ([`Subs::join`](crate::stores::thread_subs)), before every publish: a
//!   replaceable event is last-writer-wins for the whole list. **One
//!   exception**: the best-effort publish on `pagehide` (local-key and passkey
//!   sessions only) cannot wait for a fetch, so it publishes the local list,
//!   which holds the last relay copy this session saw. A change another device
//!   published since then is overwritten on the relay until that device next
//!   merges and publishes it again (its local copy keeps it) — lost only if
//!   that device signed out meanwhile, since sign-out removes the local copy.
//! - Never publish before this session's first fetch succeeded (a timeout is
//!   a failure, an empty answer is not), nor over a copy that cannot be
//!   decrypted or read: that would wipe what another device wrote.
//! - At most one publish per minute, plus a best-effort one on `pagehide`.
//! - Without NIP-44 (a NIP-07 extension lacking `nip44`), or on any error, the
//!   feature stays local-only ([`SyncStatus::LocalOnly`]); the local list
//!   keeps working.
//! - The plaintext is held to [`MAX_PLAINTEXT_BYTES`] so the encrypted content
//!   stays under the relay's 64 KiB content cap; the oldest tombstones are
//!   left out first, a followed topic never.
//!
//! ## Device keys (ADR-099, `DEVICE_KEYS_ENABLED`)
//!
//! A device-key session holds only the device's derived key, and the client
//! cannot tell it from any other local key, so the copy is authored by, and
//! encrypted to, the device key. Reading it back always works (kind 30078 is
//! not read-gated). Whether the relay accepts the publish follows its write
//! gate, which checks the *effective* principal
//! (`relay_do/nip_handlers.rs`, `effective_principal`): with the gate on and
//! the device registered and not revoked, the owner is checked and the copy is
//! stored (under the device pubkey); with the gate off, or the device revoked,
//! the device pubkey itself is checked, so unless it is separately allowed the
//! relay refuses, and the feature stays local-only
//! ([`LocalOnlyReason::RelayError`], retried after the next change or
//! reconnect). Either way the copy is private to that device key and does not
//! follow the member's identity to their other devices. Nothing leaks.

use std::cell::RefCell;
use std::rc::Rc;

use nostr_bbs_core::signer::Signer;
use nostr_bbs_core::{verify_event_strict, NostrEvent, UnsignedEvent};

use crate::relay::{Filter, OneShot, RelayConnection};
use crate::stores::thread_subs::{Subs, SubsDoc};

pub use crate::zone_crypto::inbox_key::KIND_APP_DATA;

/// The `d` tag of the subscriptions copy, and its only tag.
pub const THREAD_SUBS_D_TAG: &str = "nostr-bbs/thread-subs/v1";

/// The relay's content cap (`relay_do/nip_handlers.rs`, `MAX_CONTENT_SIZE`).
pub const RELAY_CONTENT_CAP: usize = 64 * 1024;

/// The largest plaintext sent: NIP-44 v2 pads it to 40,960 bytes, which
/// base64-encodes (with version, nonce, length prefix and MAC) to 54,704
/// bytes, under [`RELAY_CONTENT_CAP`]. The next padding step (49,152) would
/// not fit.
pub const MAX_PLAINTEXT_BYTES: usize = 40_960;

/// How long a fetch or a publish waits for the relay, milliseconds.
const RELAY_WAIT_MS: u32 = 10_000;

/// State of the cross-device copy, for a view to show if it wishes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SyncStatus {
    /// Not started: signed out, or waiting for the relay session.
    #[default]
    Idle,
    /// Fetching, merging or publishing.
    Syncing,
    /// The relay copy holds everything this device has, as of the last
    /// exchange.
    Synced,
    /// Kept on this device only, for the reason given. The local list works
    /// as before.
    LocalOnly(LocalOnlyReason),
}

/// Why the cross-device copy is not in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalOnlyReason {
    /// No signer for the signed-in account (yet).
    NoSigner,
    /// The signer cannot encrypt to itself: a NIP-07 extension without
    /// `nip44`. Lasts the session.
    NoNip44,
    /// A relay copy exists that this signer cannot decrypt or read; it is
    /// left alone rather than overwritten. Lasts the session.
    Unreadable,
    /// The list is too large to publish (only when more than
    /// [`MAX_ACTIVE_SUBSCRIPTIONS`](crate::stores::thread_subs::MAX_ACTIVE_SUBSCRIPTIONS)
    /// topics were merged from several devices). Retried after the next
    /// change.
    TooLarge,
    /// The relay did not answer, refused, or the connection dropped. Retried
    /// after a reconnect or the next change.
    RelayError,
}

impl LocalOnlyReason {
    /// Whether this ends syncing for the rest of the session.
    pub(crate) fn ends_session(self) -> bool {
        matches!(self, LocalOnlyReason::NoNip44 | LocalOnlyReason::Unreadable)
    }
}

/// NIP-44 v2 padded plaintext length for an `n`-byte plaintext.
pub(crate) fn nip44_padded_len(n: usize) -> usize {
    if n <= 32 {
        return 32;
    }
    let next_power = 1usize << (usize::BITS - (n - 1).leading_zeros());
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    chunk * ((n - 1) / chunk + 1)
}

/// Length of the base64 NIP-44 v2 payload for an `n`-byte plaintext:
/// version (1) + nonce (32) + length prefix (2) + padded plaintext + MAC (32).
pub(crate) fn nip44_payload_len(n: usize) -> usize {
    let raw = 1 + 32 + 2 + nip44_padded_len(n) + 32;
    4 * raw.div_ceil(3)
}

/// The compact JSON published for `subs`, within [`MAX_PLAINTEXT_BYTES`].
///
/// Read markers of topics not followed are left out. When the whole list
/// does not fit, the oldest tombstones are left out until it does; if the
/// followed topics alone do not fit, nothing is published.
pub(crate) fn encode_bounded(subs: &Subs) -> Result<String, LocalOnlyReason> {
    let mut out = subs.clone();
    let entries = &out.entries;
    out.read.retain(|r, _| entries.get(r).is_some_and(|e| e.on));
    let encode =
        |s: &Subs| serde_json::to_string(&s.to_doc()).map_err(|_| LocalOnlyReason::TooLarge);
    let mut json = encode(&out)?;
    if json.len() <= MAX_PLAINTEXT_BYTES {
        return Ok(json);
    }
    let mut tombs: Vec<(u64, String)> = out
        .entries
        .values()
        .filter(|e| !e.on)
        .map(|e| (e.at, e.r.clone()))
        .collect();
    tombs.sort();
    let mut tombs = tombs.into_iter();
    // Drop by estimate first (each entry's own JSON plus its comma), then
    // check the real length, one more at a time.
    let mut excess = json.len() - MAX_PLAINTEXT_BYTES;
    for (_, root) in tombs.by_ref() {
        if let Some(e) = out.entries.remove(&root) {
            let len = serde_json::to_string(&e).map_or(0, |s| s.len() + 1);
            excess = excess.saturating_sub(len);
        }
        if excess == 0 {
            break;
        }
    }
    loop {
        json = encode(&out)?;
        if json.len() <= MAX_PLAINTEXT_BYTES {
            return Ok(json);
        }
        match tombs.next() {
            Some((_, root)) => {
                out.entries.remove(&root);
            }
            None => return Err(LocalOnlyReason::TooLarge),
        }
    }
}

/// Parse a decrypted copy; `None` when it is not the expected JSON.
pub(crate) fn decode(plain: &str) -> Option<Subs> {
    serde_json::from_str::<SubsDoc>(plain)
        .ok()
        .map(Subs::from_doc)
}

/// The unsigned event: kind 30078, the `d` tag and nothing else.
pub(crate) fn unsigned_event(owner: &str, content: String, created_at: u64) -> UnsignedEvent {
    UnsignedEvent {
        pubkey: owner.to_string(),
        created_at,
        kind: KIND_APP_DATA,
        tags: vec![vec!["d".to_string(), THREAD_SUBS_D_TAG.to_string()]],
        content,
    }
}

/// The current copy among `events`: kind 30078, authored by `owner`, exactly
/// the subscriptions `d` tag, id and signature verified; the newest, and at
/// equal `created_at` the lowest id (NIP-01's rule for replaceable events).
pub(crate) fn pick_latest<'a>(events: &'a [NostrEvent], owner: &str) -> Option<&'a NostrEvent> {
    events
        .iter()
        .filter(|e| {
            e.kind == KIND_APP_DATA
                && e.pubkey.eq_ignore_ascii_case(owner)
                && e.tags
                    .iter()
                    .any(|t| t.len() >= 2 && t[0] == "d" && t[1] == THREAD_SUBS_D_TAG)
                && verify_event_strict(e).is_ok()
        })
        .max_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| b.id.cmp(&a.id))
        })
}

/// Encrypt `subs` to the signer's own key and sign the copy.
pub(crate) async fn seal(
    signer: &dyn Signer,
    subs: &Subs,
    created_at: u64,
) -> Result<NostrEvent, LocalOnlyReason> {
    let owner = signer.public_key().to_string();
    let plain = encode_bounded(subs)?;
    // Known before encrypting (so a NIP-07 signer is not asked for a copy
    // the relay would refuse); `encode_bounded` already guarantees it.
    if nip44_payload_len(plain.len()) > RELAY_CONTENT_CAP {
        return Err(LocalOnlyReason::TooLarge);
    }
    let content = signer
        .nip44_encrypt(&owner, &plain)
        .await
        .map_err(|_| LocalOnlyReason::NoNip44)?;
    if content.len() > RELAY_CONTENT_CAP {
        return Err(LocalOnlyReason::TooLarge);
    }
    signer
        .sign_event(unsigned_event(&owner, content, created_at))
        .await
        .map_err(|_| LocalOnlyReason::NoSigner)
}

/// Decrypt and read a copy with the signer's own key.
pub(crate) async fn open(signer: &dyn Signer, ev: &NostrEvent) -> Result<Subs, LocalOnlyReason> {
    let owner = signer.public_key().to_string();
    let plain = signer
        .nip44_decrypt(&owner, &ev.content)
        .await
        .map_err(|_| LocalOnlyReason::Unreadable)?;
    decode(&plain).ok_or(LocalOnlyReason::Unreadable)
}

/// Ask the relay for `owner`'s current copy. `Ok(None)` when it answered with
/// none; an error when it did not answer in time or refused the REQ.
pub(crate) async fn fetch_latest(
    relay: &RelayConnection,
    owner: &str,
) -> Result<Option<NostrEvent>, LocalOnlyReason> {
    let slot: Rc<OneShot<Result<(), ()>>> = OneShot::new();
    let events: Rc<RefCell<Vec<NostrEvent>>> = Rc::default();
    let sink = events.clone();
    let answered = slot.clone();
    let refused = slot.clone();
    let sub = relay.subscribe_with_receipt_or_closed(
        vec![Filter {
            authors: Some(vec![owner.to_string()]),
            kinds: Some(vec![KIND_APP_DATA]),
            d_tags: Some(vec![THREAD_SUBS_D_TAG.to_string()]),
            limit: Some(10),
            ..Default::default()
        }],
        Rc::new(move |ev| sink.borrow_mut().push(ev)),
        Rc::new(move |_authed| answered.fill(Ok(()))),
        Rc::new(move |_reason| refused.fill(Err(()))),
    );
    let late = slot.clone();
    let _timer = gloo::timers::callback::Timeout::new(RELAY_WAIT_MS, move || late.fill(Err(())));
    let outcome = slot.wait().await;
    relay.unsubscribe(&sub);
    outcome.map_err(|()| LocalOnlyReason::RelayError)?;
    let events = events.borrow();
    Ok(pick_latest(&events, owner).cloned())
}

/// Publish `ev` and wait for the relay's `OK`.
pub(crate) async fn publish(
    relay: &RelayConnection,
    ev: &NostrEvent,
) -> Result<(), LocalOnlyReason> {
    let slot: Rc<OneShot<bool>> = OneShot::new();
    let done = slot.clone();
    relay
        .publish_with_ack(ev, Some(Rc::new(move |ok, _msg| done.fill(ok))))
        .map_err(|_| LocalOnlyReason::RelayError)?;
    let late = slot.clone();
    let _timer = gloo::timers::callback::Timeout::new(RELAY_WAIT_MS, move || late.fill(false));
    if slot.wait().await {
        Ok(())
    } else {
        Err(LocalOnlyReason::RelayError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stores::thread_subs::{Entry, MAX_ACTIVE_SUBSCRIPTIONS};
    use nostr_bbs_core::keys::generate_keypair;
    use nostr_bbs_core::signer::PrfSigner;

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        futures::executor::block_on(f)
    }

    fn id(n: u32) -> String {
        format!("{n:064x}")
    }

    fn signer() -> PrfSigner {
        PrfSigner::new(generate_keypair().unwrap())
    }

    /// The largest list a member can hold: every followed topic with a full
    /// channel id, a long zone id and a marker, plus the most tombstones.
    fn worst_case(active: usize, zone_len: usize) -> Subs {
        let mut s = Subs::default();
        let now = 1_800_000_000_000u64;
        for n in 0..active as u32 {
            let r = id(n);
            s.entries.insert(
                r.clone(),
                Entry {
                    r: r.clone(),
                    c: id(1_000_000 + n),
                    z: "z".repeat(zone_len),
                    on: true,
                    at: now + n as u64,
                },
            );
            s.read.insert(r, now / 1000 + n as u64);
        }
        for n in 0..crate::stores::thread_subs::MAX_TOMBSTONES as u32 {
            let r = id(2_000_000 + n);
            s.entries.insert(
                r.clone(),
                Entry {
                    r,
                    c: String::new(),
                    z: String::new(),
                    on: false,
                    at: now - 1000 + n as u64,
                },
            );
        }
        s
    }

    #[test]
    fn padding_matches_nip44_v2() {
        assert_eq!(nip44_padded_len(1), 32);
        assert_eq!(nip44_padded_len(32), 32);
        assert_eq!(nip44_padded_len(33), 64);
        assert_eq!(nip44_padded_len(257), 320);
        assert_eq!(nip44_padded_len(40_960), 40_960);
        assert_eq!(nip44_padded_len(40_961), 49_152);
        assert_eq!(nip44_payload_len(MAX_PLAINTEXT_BYTES), 54_704);
        assert!(nip44_payload_len(MAX_PLAINTEXT_BYTES) <= RELAY_CONTENT_CAP);
        assert!(nip44_payload_len(MAX_PLAINTEXT_BYTES + 1) > RELAY_CONTENT_CAP);
    }

    #[test]
    fn computed_payload_length_matches_a_real_encryption() {
        let s = signer();
        for n in [1usize, 31, 32, 33, 300, 5_000, 33_000, MAX_PLAINTEXT_BYTES] {
            let plain = "x".repeat(n);
            let ct = block_on(s.nip44_encrypt(s.public_key(), &plain)).unwrap();
            assert_eq!(ct.len(), nip44_payload_len(n), "plaintext {n}");
        }
    }

    #[test]
    fn the_event_has_kind_30078_and_only_the_d_tag() {
        let s = signer();
        let mut subs = Subs::default();
        subs.subscribe(&id(1), &id(2), "zone1", 1_000, 1).unwrap();
        let ev = block_on(seal(&s, &subs, 1_700_000_000)).unwrap();
        assert_eq!(ev.kind, 30078);
        assert_eq!(ev.pubkey, s.public_key());
        assert_eq!(
            ev.tags,
            vec![vec![
                "d".to_string(),
                "nostr-bbs/thread-subs/v1".to_string()
            ]]
        );
        assert!(!ev.content.contains(&id(1)), "ids are not in the clear");
        assert!(verify_event_strict(&ev).is_ok());
    }

    #[test]
    fn seal_then_open_round_trips() {
        let s = signer();
        let mut subs = Subs::default();
        subs.subscribe(&id(1), &id(2), "zone1", 1_000, 1).unwrap();
        subs.subscribe(&id(3), &id(2), "", 1_001, 1).unwrap();
        subs.mark_read(&id(3), 50);
        subs.unsubscribe(&id(1), 2_000);
        let ev = block_on(seal(&s, &subs, 1_700_000_000)).unwrap();
        let back = block_on(open(&s, &ev)).unwrap();
        assert_eq!(back, subs);
    }

    #[test]
    fn another_key_cannot_open_the_copy() {
        let mine = signer();
        let theirs = signer();
        let mut subs = Subs::default();
        subs.subscribe(&id(1), &id(2), "", 1_000, 1).unwrap();
        let ev = block_on(seal(&mine, &subs, 1_700_000_000)).unwrap();
        assert_eq!(
            block_on(open(&theirs, &ev)),
            Err(LocalOnlyReason::Unreadable)
        );
    }

    #[test]
    fn the_worst_case_list_fits_the_relay_cap_keeping_every_followed_topic() {
        let s = signer();
        // Longest accepted ids: 64-hex root and channel, longest zone id.
        let subs = worst_case(
            MAX_ACTIVE_SUBSCRIPTIONS,
            crate::stores::thread_subs::MAX_ZONE_LEN,
        );
        let plain = encode_bounded(&subs).unwrap();
        assert!(plain.len() <= MAX_PLAINTEXT_BYTES);
        let back = decode(&plain).unwrap();
        assert_eq!(back.active_count(), MAX_ACTIVE_SUBSCRIPTIONS);
        let ev = block_on(seal(&s, &subs, 1_700_000_000)).unwrap();
        assert!(
            ev.content.len() <= RELAY_CONTENT_CAP,
            "{}",
            ev.content.len()
        );
        // Tombstones were shed oldest first.
        let kept: Vec<&Entry> = back.entries.values().filter(|e| !e.on).collect();
        assert!(kept.len() < crate::stores::thread_subs::MAX_TOMBSTONES);
        if let Some(oldest_kept) = kept.iter().map(|e| e.at).min() {
            let dropped_newer = subs
                .entries
                .values()
                .filter(|e| !e.on && !back.entries.contains_key(&e.r))
                .any(|e| e.at > oldest_kept);
            assert!(
                !dropped_newer,
                "never a newer tombstone before an older one"
            );
        }
    }

    #[test]
    fn a_list_that_cannot_fit_is_refused_rather_than_cut() {
        // Followed topics alone over the budget (only reachable by merging
        // lists that several devices each filled to the cap): nothing is published.
        let subs = worst_case(2 * MAX_ACTIVE_SUBSCRIPTIONS, 16);
        assert_eq!(encode_bounded(&subs), Err(LocalOnlyReason::TooLarge));
    }

    #[test]
    fn markers_of_topics_not_followed_are_not_published() {
        let mut subs = Subs::default();
        subs.subscribe(&id(1), &id(2), "", 1_000, 1).unwrap();
        subs.read.insert(id(9), 5);
        let back = decode(&encode_bounded(&subs).unwrap()).unwrap();
        assert!(!back.read.contains_key(&id(9)));
        assert!(back.read.contains_key(&id(1)));
    }

    #[test]
    fn pick_latest_takes_only_valid_copies_of_the_owner() {
        let me = signer();
        let other = signer();
        let mut subs = Subs::default();
        subs.subscribe(&id(1), &id(2), "", 1_000, 1).unwrap();
        let old = block_on(seal(&me, &subs, 100)).unwrap();
        let new = block_on(seal(&me, &subs, 200)).unwrap();
        let theirs = block_on(seal(&other, &subs, 300)).unwrap();
        let mut forged = new.clone();
        forged.created_at = 400;
        let wrong_d = block_on(me.sign_event(UnsignedEvent {
            pubkey: me.public_key().to_string(),
            created_at: 500,
            kind: KIND_APP_DATA,
            tags: vec![vec!["d".into(), "nostr-bbs/zone-inbox/v1".into()]],
            content: old.content.clone(),
        }))
        .unwrap();
        let all = vec![old.clone(), new.clone(), theirs, forged, wrong_d];
        assert_eq!(
            pick_latest(&all, me.public_key()).map(|e| &e.id),
            Some(&new.id)
        );
        assert!(pick_latest(&[], me.public_key()).is_none());
    }

    #[test]
    fn decode_rejects_what_is_not_the_copy() {
        assert!(decode("not json").is_none());
        assert!(decode("[1,2]").is_none());
        assert_eq!(decode("{}"), Some(Subs::default()));
    }

    #[test]
    fn only_lasting_reasons_end_the_session() {
        assert!(LocalOnlyReason::NoNip44.ends_session());
        assert!(LocalOnlyReason::Unreadable.ends_session());
        assert!(!LocalOnlyReason::RelayError.ends_session());
        assert!(!LocalOnlyReason::TooLarge.ends_session());
        assert!(!LocalOnlyReason::NoSigner.ends_session());
    }
}
