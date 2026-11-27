//! Relay-held backup of the "granted" ledger, so the Encryption tab's
//! granted/missing status survives clearing site data.
//!
//! The ledger itself ([`super::grant_ledger`]) lives in this browser's
//! IndexedDB. After "Clear site data" every member reads as "missing" although
//! they hold the key. This module keeps a copy on the relay: one kind-30078
//! (NIP-78 application data, replaceable) event per `(admin, zone, epoch)`,
//! `d = nostr-bbs/grant-ledger/v1/<zone>/<epoch>`, whose content is the
//! admin's own NIP-44 self-encryption of the v2 entries (a JSON array of
//! `"<member>:<recipient key>"`). Only the admin who sent the grants can read
//! it, and the relay learns nothing it did not already know.
//!
//! # Why not look at the wraps themselves?
//!
//! The obvious alternative, "does a kind-1059 wrap to this member exist?",
//! cannot work: a grant is a NIP-59 wrap signed by a fresh ephemeral key (the
//! sending admin is invisible), its `created_at` is randomised, it is
//! addressed to the member's inbox key rather than their identity, it looks
//! like any other DM wrap, and the relay deliberately serves wraps only to
//! their recipient (admins included).
//!
//! # Limits of the heuristic
//!
//! * Only grants sent through this code, by this admin, are recorded. Grants
//!   sent by another admin, or before this backup existed, still show as
//!   "missing" until re-granted. That is the safe direction: re-sending
//!   repeats the same key, whereas a false "granted" would hide a member who
//!   cannot read the zone.
//! * The backup is written after the relay acknowledges a grant batch, so a
//!   tab closed mid-batch loses at most that batch's entries.
//! * One event holds a whole epoch's entries (about 130 bytes each) and the
//!   relay caps content at 64 KiB, so it holds roughly 400 members per epoch.
//! * It is merged into, never replaces, the local ledger, and malformed
//!   entries are dropped, so it can only ever add "granted" marks that this
//!   admin genuinely earned.

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::rc::Rc;

use nostr_bbs_core::signer::Signer;
use nostr_bbs_core::{verify_event_strict, NostrEvent, UnsignedEvent};

use super::grant_ledger::valid_entry;
use super::inbox_key::Slot;
use super::store::ZoneKeyStore;
use crate::relay::{Filter, RelayConnection};

/// Kind of the backup (NIP-78 application data, replaceable per `d`).
pub const KIND_APP_DATA: u64 = 30078;

/// How long to wait for the relay's answer before giving up on a pull or
/// push, counted from when the request leaves this client.
const RELAY_WAIT_MS: u32 = 8_000;

/// Allowance on top of the computed drain time before a request stops
/// waiting for the frames queued ahead of it (reconnects, AUTH, clock skew).
const QUEUE_SLACK_MS: u32 = 5_000;

/// Longest a request waits for the frames queued ahead of it.
const QUEUE_WAIT_CAP_MS: u32 = 120_000;

/// Pause before the one retry of a failed push.
const PUSH_RETRY_DELAY_MS: u32 = 2_000;

/// How long a backup request may wait for `frames_ahead` queued frames to
/// leave this client before its own `RELAY_WAIT_MS` round trip starts.
///
/// The connection paces every frame (see [`crate::relay::drain_time_ms`]).
/// A grant batch queues one frame per member, so a backup lookup made right
/// after it can sit behind well over a hundred wraps; a timer started at
/// queueing would expire before the lookup even left (the zone2 backup that
/// was never published, 2026-11-26).
pub fn queue_wait_ms(frames_ahead: usize) -> u32 {
    crate::relay::drain_time_ms(frames_ahead)
        .saturating_add(QUEUE_SLACK_MS)
        .min(QUEUE_WAIT_CAP_MS)
}

/// The `d` tag of `(zone, epoch)`'s backup.
pub fn d_tag(zone: &str, epoch: u32) -> String {
    format!("nostr-bbs/grant-ledger/v1/{zone}/{epoch}")
}

fn tag_d(ev: &NostrEvent) -> Option<&str> {
    ev.tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == "d")
        .map(|t| t[1].as_str())
}

/// The newest valid backup of `(zone, epoch)` among `events`: kind 30078,
/// authored by `owner`, the right `d` tag, id and signature verified.
pub fn pick<'a>(
    events: &'a [NostrEvent],
    owner: &str,
    zone: &str,
    epoch: u32,
) -> Option<&'a NostrEvent> {
    let want = d_tag(zone, epoch);
    events
        .iter()
        .filter(|e| {
            e.kind == KIND_APP_DATA
                && e.pubkey == owner
                && tag_d(e) == Some(want.as_str())
                && verify_event_strict(e).is_ok()
        })
        .max_by_key(|e| e.created_at)
}

/// Build and sign the backup of `entries` with the admin's identity signer.
pub async fn build(
    identity: &dyn Signer,
    zone: &str,
    epoch: u32,
    entries: &[String],
    now: u64,
) -> Result<NostrEvent, String> {
    let owner = identity.public_key().to_string();
    let payload = serde_json::to_string(entries).map_err(|e| e.to_string())?;
    let content = identity
        .nip44_encrypt(&owner, &payload)
        .await
        .map_err(|e| e.to_string())?;
    identity
        .sign_event(UnsignedEvent {
            pubkey: owner,
            created_at: now,
            kind: KIND_APP_DATA,
            tags: vec![vec!["d".to_string(), d_tag(zone, epoch)]],
            content,
        })
        .await
        .map_err(|e| e.to_string())
}

/// Decrypt a backup and return its well-formed entries.
pub async fn open(identity: &dyn Signer, ev: &NostrEvent) -> Result<Vec<String>, String> {
    let owner = identity.public_key().to_string();
    let plain = identity
        .nip44_decrypt(&owner, &ev.content)
        .await
        .map_err(|_| "grant backup does not decrypt".to_string())?;
    let all: Vec<String> =
        serde_json::from_str(&plain).map_err(|_| "grant backup malformed".to_string())?;
    Ok(all.into_iter().filter(|e| valid_entry(e)).collect())
}

thread_local! {
    /// `(admin, zone, epoch)` whose backup was found and merged this session:
    /// one fetch per key, not one per sweep. An answer of "no backup" is not
    /// cached (a REQ answered before the session settled would otherwise hide
    /// the real one for the whole session).
    static PULLED: RefCell<HashSet<(String, String, u32)>> = RefCell::new(HashSet::new());
}

/// Ask the relay for the admin's newest backup of `(zone, epoch)`. `Err`
/// means the relay could not be asked, which is not the same as "none".
async fn fetch_remote(
    relay: &RelayConnection,
    identity: &dyn Signer,
    zone: &str,
    epoch: u32,
) -> Result<Option<NostrEvent>, String> {
    let owner = identity.public_key().to_string();
    // Start the clock only once the frames ahead of this REQ have gone out:
    // the timer below measures the relay, not this client's send queue. A
    // queue that does not drain (socket down) leaves the timer to decide.
    relay
        .wait_until_sent(queue_wait_ms(relay.queued_frames()))
        .await;
    let slot: Rc<Slot<Result<(), String>>> = Slot::new();
    let events: Rc<RefCell<Vec<NostrEvent>>> = Rc::default();
    let sink = events.clone();
    let done = slot.clone();
    let sub = relay.subscribe(
        vec![Filter {
            authors: Some(vec![owner.clone()]),
            kinds: Some(vec![KIND_APP_DATA]),
            d_tags: Some(vec![d_tag(zone, epoch)]),
            ..Default::default()
        }],
        Rc::new(move |ev| sink.borrow_mut().push(ev)),
        Some(Rc::new(move || done.fill(Ok(())))),
    );
    let late = slot.clone();
    let _timer = gloo::timers::callback::Timeout::new(RELAY_WAIT_MS, move || {
        late.fill(Err("timed out waiting for the relay".into()))
    });
    let outcome = slot.wait().await;
    relay.unsubscribe(&sub);
    outcome?;
    let found = events.borrow().clone();
    Ok(pick(&found, &owner, zone, epoch).cloned())
}

/// What [`pull_detailed`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pulled {
    /// Already found and merged earlier this session; not asked again.
    Cached,
    /// A backup was found; this many entries were new to this device.
    Merged(usize),
    /// The relay answered and holds no backup of this `(zone, epoch)`.
    Missing,
}

/// Merge the relay-held backup of `(zone, epoch)` into this device's ledger
/// (once per session once found), saying whether the relay held a backup at
/// all, so a caller can publish one that is missing (see [`needs_repair`]).
/// `Err` when the relay could not be asked or the backup did not open, in
/// which case the local ledger stands alone.
pub async fn pull_detailed(
    relay: &RelayConnection,
    identity: &dyn Signer,
    store: ZoneKeyStore,
    zone: &str,
    epoch: u32,
) -> Result<Pulled, String> {
    let seen = (identity.public_key().to_string(), zone.to_string(), epoch);
    if PULLED.with(|p| p.borrow().contains(&seen)) {
        return Ok(Pulled::Cached);
    }
    let Some(ev) = fetch_remote(relay, identity, zone, epoch).await? else {
        return Ok(Pulled::Missing);
    };
    let entries = open(identity, &ev).await?;
    let added = store.merge_grant_backup(zone, epoch, &entries).await;
    PULLED.with(|p| p.borrow_mut().insert(seen));
    Ok(Pulled::Merged(added))
}

/// Whether a `(zone, epoch)` whose pull came back `pulled`, with `local`
/// ledger entries on this device, should have its backup published now.
///
/// Only a definite "the relay holds none" with something to publish
/// qualifies. This is how a backup a batch failed to publish (or one sent
/// before backups existed) reaches the relay without waiting for the next
/// grant: until it does, every other browser of this admin re-grants the
/// whole roster on sign-in.
///
/// `authed` is whether the connection had completed NIP-42 AUTH when the
/// relay answered: an answer given before AUTH can be empty because the
/// relay withheld the event, and publishing then would replace a fuller
/// backup with this device's subset.
pub fn needs_repair(pulled: Result<Pulled, &str>, local: usize, authed: bool) -> bool {
    authed && matches!(pulled, Ok(Pulled::Missing)) && local > 0
}

/// Whether a `(zone, epoch)` whose pull came back `pulled` counts as read
/// for the first-grant gate: this device then knows everything its admin's
/// backup records, so a member absent from both is genuinely never granted.
///
/// `Err` (the relay did not answer, or a backup was found but did not
/// decrypt) is not read. Neither is "none" answered before NIP-42 AUTH
/// (`authed` false), which the relay may have said because it withheld the
/// event (as in [`needs_repair`]). Either way the gate reports the zone as
/// unverified rather than presenting its members as never granted.
pub fn backup_verified(pulled: Result<Pulled, &str>, authed: bool) -> bool {
    match pulled {
        Ok(Pulled::Cached | Pulled::Merged(_)) => true,
        Ok(Pulled::Missing) => authed,
        Err(_) => false,
    }
}

thread_local! {
    /// `(admin, zone, epoch)` whose missing backup a repair was already
    /// attempted for this session, successful or not: one try per session,
    /// so a relay that refuses the backup is not asked on every sweep.
    static REPAIRED: RefCell<HashSet<(String, String, u32)>> = RefCell::new(HashSet::new());
}

/// Claim the one repair attempt of `(owner, zone, epoch)` this session.
/// `false` when it was already claimed.
pub fn claim_repair(owner: &str, zone: &str, epoch: u32) -> bool {
    REPAIRED.with(|r| {
        r.borrow_mut()
            .insert((owner.to_string(), zone.to_string(), epoch))
    })
}

/// [`push`], retried once after a short pause if it fails. The second try
/// re-reads the relay copy, so it never publishes blind.
pub async fn push_retrying(
    relay: &RelayConnection,
    identity: &dyn Signer,
    store: ZoneKeyStore,
    zone: &str,
    epoch: u32,
    now: impl Fn() -> u64,
) -> Result<(), String> {
    match push(relay, identity, store, zone, epoch, now()).await {
        Ok(()) => Ok(()),
        Err(first) => {
            web_sys::console::warn_1(
                &format!("[zone-key] grant backup {zone}/{epoch}: {first}; retrying").into(),
            );
            let promise = js_sys::Promise::new(&mut |resolve, _| {
                if let Some(win) = web_sys::window() {
                    let _ = win.set_timeout_with_callback_and_timeout_and_arguments_0(
                        &resolve,
                        PUSH_RETRY_DELAY_MS as i32,
                    );
                }
            });
            let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
            push(relay, identity, store, zone, epoch, now()).await
        }
    }
}

/// What a push should publish, given the relay's current copy (`Err`: could
/// not be fetched, `Ok(None)`: none yet, `Ok(Some((created_at, entries)))`)
/// and this device's entries. `None`: publish nothing.
///
/// The event is replaceable, so the last write wins. Publishing only the local
/// set could therefore shrink the backup (a fresh browser whose pull had not
/// finished, or a second browser of the same admin). So the published set is
/// always remote ∪ local, nothing is published when the remote copy cannot be
/// read, and `created_at` is at least one second after the remote copy's so a
/// rewrite in the same second is not lost to the NIP-01 tie-break.
pub fn plan_publish(
    remote: Result<Option<(u64, Vec<String>)>, String>,
    local: &[String],
    now: u64,
) -> Option<(u64, Vec<String>)> {
    let (remote_at, remote_entries) = match remote {
        Err(_) => return None,
        Ok(None) => (0, Vec::new()),
        Ok(Some((at, e))) => (at, e),
    };
    let mut all: Vec<String> = remote_entries
        .into_iter()
        .chain(local.iter().cloned())
        .filter(|e| valid_entry(e))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    all.sort();
    if all.is_empty() {
        return None;
    }
    Some((now.max(remote_at.saturating_add(1)), all))
}

/// Publish this admin's ledger for `(zone, epoch)`: read the relay's copy
/// fresh, merge it into the local ledger, publish the union (see
/// [`plan_publish`]). `Ok` only when the relay answered OK true, or when there
/// was nothing to publish.
pub async fn push(
    relay: &RelayConnection,
    identity: &dyn Signer,
    store: ZoneKeyStore,
    zone: &str,
    epoch: u32,
    now: u64,
) -> Result<(), String> {
    let remote = match fetch_remote(relay, identity, zone, epoch).await {
        Ok(None) => Ok(None),
        Ok(Some(ev)) => match open(identity, &ev).await {
            Ok(entries) => Ok(Some((ev.created_at, entries))),
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    };
    if let Err(e) = &remote {
        return Err(format!(
            "not published, the relay copy could not be read: {e}"
        ));
    }
    if let Ok(Some((_, entries))) = &remote {
        store.merge_grant_backup(zone, epoch, entries).await;
    }
    let local = store.export_grant_backup(zone, epoch).await;
    let Some((at, entries)) = plan_publish(remote, &local, now) else {
        return Ok(());
    };
    let ev = build(identity, zone, epoch, &entries, at).await?;
    // As in `fetch_remote`: the OK timer starts once the EVENT is out.
    relay
        .wait_until_sent(queue_wait_ms(relay.queued_frames()))
        .await;
    let slot: Rc<Slot<Result<(), String>>> = Slot::new();
    let done = slot.clone();
    relay.publish_with_ack(
        &ev,
        Some(Rc::new(move |ok, msg| {
            done.fill(if ok { Ok(()) } else { Err(msg) })
        })),
    )?;
    let late = slot.clone();
    let _timer = gloo::timers::callback::Timeout::new(RELAY_WAIT_MS, move || {
        late.fill(Err("timed out waiting for the relay".into()))
    });
    slot.wait().await
}

/// Counts answered grants (accepted and recorded, or refused) so a caller can
/// wait for a batch. Answers may arrive before the total is known (the sender
/// is still looping), so completion needs both the total
/// ([`expect`](Self::expect)) and the answers.
pub struct AckCounter {
    acked: Cell<usize>,
    expected: Cell<Option<usize>>,
    done: Rc<Slot<()>>,
}

impl AckCounter {
    /// A counter with no expected total yet.
    pub fn new() -> Rc<Self> {
        Rc::new(Self {
            acked: Cell::new(0),
            expected: Cell::new(None),
            done: Slot::new(),
        })
    }

    fn check(&self) {
        if self.expected.get().is_some_and(|n| self.acked.get() >= n) {
            self.done.fill(());
        }
    }

    /// The batch is `n` grants in total.
    pub fn expect(&self, n: usize) {
        self.expected.set(Some(n));
        self.check();
    }

    /// One grant was answered: accepted and recorded, or refused.
    pub fn ack(&self) {
        self.acked.set(self.acked.get() + 1);
        self.check();
    }

    /// Wait until every expected answer arrived, or `ms` elapsed. A grant the
    /// relay never answers (or whose answer a reconnect dropped) never acks,
    /// so the timeout is what ends such a batch.
    pub async fn wait(&self, ms: u32) {
        let late = self.done.clone();
        let _timer = gloo::timers::callback::Timeout::new(ms, move || late.fill(()));
        self.done.wait().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_bbs_core::keys::generate_keypair;
    use nostr_bbs_core::signer::PrfSigner;

    fn admin() -> PrfSigner {
        PrfSigner::new(generate_keypair().unwrap())
    }

    fn entries(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| format!("{i:064x}:{:064x}", i + 1000))
            .collect()
    }

    #[test]
    fn a_backup_round_trips_and_only_its_owner_can_open_it() {
        let a = admin();
        let e = entries(142);
        let ev = futures::executor::block_on(build(&a, "zone2", 4, &e, 1_000)).unwrap();
        assert_eq!(ev.kind, KIND_APP_DATA);
        assert!(ev.content.len() < 60 * 1024, "fits the relay's 64 KiB cap");
        assert_eq!(futures::executor::block_on(open(&a, &ev)).unwrap(), e);
        // Another admin cannot read it.
        let other = admin();
        assert!(futures::executor::block_on(open(&other, &ev)).is_err());
    }

    #[test]
    fn pick_takes_the_newest_valid_backup_of_the_right_zone_epoch_and_author() {
        let a = admin();
        let me = a.public_key().to_string();
        let old = futures::executor::block_on(build(&a, "zone2", 4, &entries(1), 100)).unwrap();
        let new = futures::executor::block_on(build(&a, "zone2", 4, &entries(3), 200)).unwrap();
        let other_epoch =
            futures::executor::block_on(build(&a, "zone2", 5, &entries(9), 300)).unwrap();
        let other_zone =
            futures::executor::block_on(build(&a, "zone3", 4, &entries(9), 300)).unwrap();
        // A forged event under another author is ignored even if newer.
        let b = admin();
        let foreign = futures::executor::block_on(build(&b, "zone2", 4, &entries(9), 900)).unwrap();
        // A tampered copy fails signature verification.
        let mut tampered = new.clone();
        tampered.created_at = 999;
        let all = vec![old, tampered, other_epoch, other_zone, foreign, new.clone()];
        let got = pick(&all, &me, "zone2", 4).unwrap();
        assert_eq!(got.id, new.id);
        assert!(pick(&all, &me, "zone9", 4).is_none());
    }

    #[test]
    fn open_drops_malformed_entries() {
        let a = admin();
        let mut e = entries(2);
        e.push("garbage".into());
        let ev = futures::executor::block_on(build(&a, "z", 1, &e, 1)).unwrap();
        assert_eq!(futures::executor::block_on(open(&a, &ev)).unwrap().len(), 2);
    }

    #[test]
    fn a_push_never_shrinks_the_relay_copy_or_publishes_blind() {
        let remote: Vec<String> = entries(5);
        let local: Vec<String> = entries(7)[5..].to_vec(); // two new ones
                                                           // The relay's copy could not be read: publish nothing.
        assert_eq!(plan_publish(Err("timeout".into()), &local, 500), None);
        // Remote and local are unioned, never replaced.
        let (at, all) = plan_publish(Ok(Some((100, remote.clone()))), &local, 500).unwrap();
        assert_eq!(at, 500);
        assert_eq!(all.len(), 7);
        for e in remote.iter().chain(local.iter()) {
            assert!(all.contains(e));
        }
        // A fresh browser with an empty local ledger still keeps the remote set.
        let (_, all) = plan_publish(Ok(Some((100, remote.clone()))), &[], 500).unwrap();
        assert_eq!(all.len(), 5);
        // No remote copy yet: the local set is published.
        assert_eq!(plan_publish(Ok(None), &local, 500).unwrap().1.len(), 2);
        // Nothing anywhere: nothing to publish.
        assert_eq!(plan_publish(Ok(None), &[], 500), None);
        // Same-second rewrite: created_at moves past the remote copy's.
        assert_eq!(
            plan_publish(Ok(Some((500, remote.clone()))), &local, 500)
                .unwrap()
                .0,
            501
        );
        // A clock behind the remote copy's still wins the replace.
        assert_eq!(
            plan_publish(Ok(Some((900, remote))), &local, 500)
                .unwrap()
                .0,
            901
        );
        // Malformed remote entries are dropped, duplicates collapse.
        let mut dirty = entries(2);
        dirty.push("junk".into());
        dirty.push(dirty[0].clone());
        assert_eq!(
            plan_publish(Ok(Some((1, dirty))), &[], 5).unwrap().1.len(),
            2
        );
    }

    #[test]
    fn a_backup_request_behind_a_grant_batch_waits_for_the_queue() {
        use crate::relay::drain_time_ms;
        // 2026-11-26: the zone2 lookup sat behind ~70 unsent wraps (~9 s at
        // 8/s) with an 8 s timer started at queueing, so it always expired
        // before leaving and the zone2 backup was never published.
        assert!(drain_time_ms(70) > RELAY_WAIT_MS);
        for frames in [0usize, 1, 8, 9, 70, 152, 400] {
            let wait = queue_wait_ms(frames);
            let drain = drain_time_ms(frames);
            if drain + QUEUE_SLACK_MS <= QUEUE_WAIT_CAP_MS {
                assert!(
                    wait >= drain + QUEUE_SLACK_MS,
                    "{frames} frames: {wait} < {drain}"
                );
            } else {
                assert_eq!(wait, QUEUE_WAIT_CAP_MS);
            }
        }
        // A whole roster's grants fit inside the cap.
        assert!(drain_time_ms(400) + QUEUE_SLACK_MS <= QUEUE_WAIT_CAP_MS);
        assert_eq!(queue_wait_ms(usize::MAX), QUEUE_WAIT_CAP_MS);
    }

    #[test]
    fn only_a_definitely_missing_backup_with_local_entries_is_repaired() {
        assert!(needs_repair(Ok(Pulled::Missing), 1, true));
        assert!(!needs_repair(Ok(Pulled::Missing), 0, true));
        assert!(!needs_repair(Ok(Pulled::Merged(0)), 5, true));
        assert!(!needs_repair(Ok(Pulled::Merged(3)), 5, true));
        assert!(!needs_repair(Ok(Pulled::Cached), 5, true));
        // An unreachable relay is not "none": publishing then could shrink
        // a backup this device simply failed to read.
        assert!(!needs_repair(
            Err("timed out waiting for the relay"),
            5,
            true
        ));
        // Nor is an answer given before AUTH, which may have withheld it.
        assert!(!needs_repair(Ok(Pulled::Missing), 5, false));
    }

    #[test]
    fn only_a_backup_actually_read_verifies_the_gate() {
        assert!(backup_verified(Ok(Pulled::Merged(0)), true));
        assert!(backup_verified(Ok(Pulled::Merged(4)), false));
        assert!(backup_verified(Ok(Pulled::Cached), false));
        // "None" is an answer only once AUTH completed.
        assert!(backup_verified(Ok(Pulled::Missing), true));
        assert!(!backup_verified(Ok(Pulled::Missing), false));
        // A timeout, or a backup that would not decrypt, is not read.
        assert!(!backup_verified(
            Err("timed out waiting for the relay"),
            true
        ));
        assert!(!backup_verified(Err("grant backup does not decrypt"), true));
    }

    #[test]
    fn a_repair_is_attempted_once_per_session() {
        let owner = "f".repeat(64);
        assert!(claim_repair(&owner, "zone2", 5));
        assert!(!claim_repair(&owner, "zone2", 5));
        assert!(claim_repair(&owner, "zone2", 6));
        assert!(claim_repair(&owner, "zone4", 5));
    }

    #[test]
    fn d_tag_is_scoped_to_zone_and_epoch() {
        assert_eq!(d_tag("zone2", 4), "nostr-bbs/grant-ledger/v1/zone2/4");
        assert_ne!(d_tag("zone2", 4), d_tag("zone2", 5));
    }
}
