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

/// How long to wait for the relay before giving up on a pull or push.
const RELAY_WAIT_MS: u32 = 8_000;

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
    /// `(admin, zone, epoch)` already pulled this session: one fetch per key,
    /// not one per sweep. Only a successful answer (even "no backup") counts.
    static PULLED: RefCell<HashSet<(String, String, u32)>> = RefCell::new(HashSet::new());
}

/// Merge the relay-held backup of `(zone, epoch)` into this device's ledger
/// (once per session). Returns the number of members newly marked granted;
/// `Err` when the relay could not be asked, in which case the local ledger
/// stands alone, as before.
pub async fn pull(
    relay: &RelayConnection,
    identity: &dyn Signer,
    store: ZoneKeyStore,
    zone: &str,
    epoch: u32,
) -> Result<usize, String> {
    let owner = identity.public_key().to_string();
    let seen = (owner.clone(), zone.to_string(), epoch);
    if PULLED.with(|p| p.borrow().contains(&seen)) {
        return Ok(0);
    }
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
    let added = match pick(&found, &owner, zone, epoch) {
        Some(ev) => {
            let entries = open(identity, ev).await?;
            store.merge_grant_backup(zone, epoch, &entries).await
        }
        None => 0,
    };
    PULLED.with(|p| p.borrow_mut().insert(seen));
    Ok(added)
}

/// Publish this device's ledger for `(zone, epoch)` as the admin's backup.
/// `Ok` only when the relay answered OK true.
pub async fn push(
    relay: &RelayConnection,
    identity: &dyn Signer,
    store: ZoneKeyStore,
    zone: &str,
    epoch: u32,
    now: u64,
) -> Result<(), String> {
    let entries = store.export_grant_backup(zone, epoch).await;
    if entries.is_empty() {
        return Ok(());
    }
    let ev = build(identity, zone, epoch, &entries, now).await?;
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

/// Counts acknowledged-and-recorded grants so a caller can wait for a batch.
/// Acks may arrive before the total is known (the sender is still looping),
/// so completion needs both the total ([`expect`](Self::expect)) and the acks.
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

    /// One grant was acknowledged and recorded.
    pub fn ack(&self) {
        self.acked.set(self.acked.get() + 1);
        self.check();
    }

    /// Wait until every expected acknowledgement arrived, or `ms` elapsed.
    /// Rejected grants never ack, so the timeout is what ends a partial batch.
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
    fn d_tag_is_scoped_to_zone_and_epoch() {
        assert_eq!(d_tag("zone2", 4), "nostr-bbs/grant-ledger/v1/zone2/4");
        assert_ne!(d_tag("zone2", 4), d_tag("zone2", 5));
    }
}
