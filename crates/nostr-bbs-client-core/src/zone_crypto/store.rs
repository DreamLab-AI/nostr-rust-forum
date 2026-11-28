//! Reactive zone-key store (ADR-2016).
//!
//! Holds the zone keys the signed-in identity sees, persists them in
//! IndexedDB, pulls key grants out of that identity's gift wraps, and is the
//! single place a zone-encrypted kind-42 is turned into readable text on its
//! way into the [`ChannelStore`](crate::stores::channels::ChannelStore).
//!
//! Keys are scoped to the signed-in identity ([`super::key_owner`]):
//! signing out drops every key from memory and turns decrypted messages back
//! into placeholders; the next sign-in, with or without a page reload, loads
//! that identity's keys before the Encryption card may offer Create or Rotate.
//! This keeps accounts that share a browser profile apart in the UI; it is not
//! access control (see the module docs of `key_owner`).

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::rc::Rc;
use std::sync::Arc;
use std::task::Poll;

use leptos::prelude::*;
use nostr_bbs_core::signer::Signer;
use nostr_bbs_core::NostrEvent;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};

use super::grant_backlog::{
    unwrap_failure_outcome, Attempt, GrantBacklog, KeyPhase, SignerKind, WrapOutcome,
};
use super::grant_ledger::{GrantKv, GrantLedger};
use super::grant_paging::{parse_marker, warm_marker, GrantScope, Marker, PagerAction, ScopePager};
use super::inbox_key::{
    deletion_for_wrap, ensure_inbox_key, grant_sweep_enabled, open_for_sync,
    recipient_keys_enabled, signer_kind_for, subscription_targets, sweep_targets, LivePort, Opener,
    SweepCandidate,
};
use super::key_owner::{self, Lease, Owner, Session, Switch};
use super::keyset::{self, SendKeyError};
use super::read_cache::ReadCache;
use super::wrap_queue::{Slot, Started, WrapQueue};
use super::{is_zone_message, read_outcome, resolve_event, validate_grant, ZoneKey};
use crate::relay::{EventCallback, Filter, RelayConnection};
use crate::stores::indexed_db::{ForumDb, MintPut, ZoneKeyPut};

/// `zone_kv` id holding the ids of gift wraps already unwrapped here, for the
/// current relay scope ([`crate::stores::relay_scope`]). Shared by every
/// identity on the device: the relay serves a wrap only to its addressee, so
/// one identity's entries never cover another's wraps. The scope in the id
/// means a new relay re-reads its wraps; it also retires the unscoped set
/// written before refused keys were kept, so grants refused then (marked
/// processed, their key dropped) are unwrapped once more and recorded.
/// Most post ids kept per `(zone, epoch, key)` as opening evidence: enough
/// to pass [`key_owner::MIN_SWAP_EVIDENCE`], bounded however much loads.
const OPEN_EVIDENCE_CAP: usize = 8;

/// Wait before an automatic re-check, so the normal grant sync lands first.
const RECHECK_DELAY_MS: u32 = 8_000;

fn kv_processed() -> String {
    format!("processed_wraps:{}", crate::stores::relay_scope::current())
}

/// Coalescing window for writing the processed-wrap set (see
/// [`ZoneKeyStore::mark_processed`]).
const PROCESSED_FLUSH_MS: i32 = 1_000;

/// How long one wrap may hold an unwrap slot (see [`super::wrap_queue`])
/// before the slot is given to the next wrap; not applied to a refusable
/// signer's single slot before its first success (see `pump_wraps`). The wrap itself is not
/// abandoned: it is accounted for when it finishes, and holds the backlog
/// open until then. One minute is three stall windows
/// ([`super::grant_backlog::KEYS_STALL_MS`]), long enough for a person to
/// answer a NIP-07 prompt, short enough that a hung fetch does not idle a
/// quarter of the queue for the session.
const UNWRAP_SLOT_TIMEOUT_MS: i32 = 60_000;

/// How long the sealer's admin check may take before it counts as
/// unanswered (a grant then ends in [`WrapOutcome::Retry`]). The fetch has no
/// timeout of its own. Ten seconds is half the stall window.
const ADMIN_CHECK_TIMEOUT_MS: i32 = 10_000;

/// One wrap waiting in [`ZoneKeyStore::wrap_queue`].
struct WrapJob {
    lease: Lease,
    ev: NostrEvent,
    signer: Rc<dyn Signer>,
    /// Whether that sign-in's identity signer can refuse, fixed when the
    /// wrap was queued (not read from the queue, which a switch resets).
    kind: SignerKind,
    relay: RelayConnection,
}

/// A page held back until the unwrap queue has room for it.
struct DeferredPage {
    ctx: Rc<ScopeCtx>,
    page: u32,
    until: u64,
}

/// One grant scope's paging context, shared by its page subscriptions.
struct ScopeCtx {
    relay: RelayConnection,
    lease: Lease,
    scope: GrantScope,
    /// The scope's backfill marker id ([`GrantScope::marker_id`]).
    marker: String,
    targets: Vec<String>,
    handler: EventCallback,
    pager: RefCell<ScopePager>,
}

fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Zone keys and the per-message decryption state.
#[derive(Clone, Copy)]
pub struct ZoneKeyStore {
    /// The signed-in identity's view of the stored keys, by
    /// [`ZoneKey::store_id`] (zone, group, epoch, pubkey with
    /// `ZONE_GROUPS_ENABLED`), so two keys claiming one epoch both stay
    /// visible (ADR-2028 decision 6). Empty while signed out.
    pub keys: RwSignal<HashMap<String, ZoneKey>>,
    /// Bumped whenever keys change or messages are re-decrypted.
    pub revision: RwSignal<u64>,
    /// Ids of zone-encrypted kind-42s (decrypted or not), as shown: a
    /// restored sealed original is listed under its own id. Views use this to
    /// keep link previews off: a preview would send the URL to the preview
    /// worker, outside the zone.
    pub encrypted_ids: RwSignal<HashSet<String>>,
    /// The identity whose keys have been loaded from IndexedDB (or whose load
    /// has failed), so nothing judges "no key held" too early. Compared with
    /// the current auth identity by [`ready_for`](Self::ready_for), so
    /// readiness never depends on which effect ran first.
    loaded_for: RwSignal<Option<Owner>>,
    /// The current sign-in's grant backlog (see [`GrantBacklog`]), with the
    /// identity it belongs to. Tracked, so pages re-judge "are this member's
    /// keys still arriving?" as it advances.
    grant_backlog: RwSignal<Option<(Owner, GrantBacklog)>>,
    /// The persisted "backfill complete" markers loaded for the signed-in
    /// identity: marker id to completion time in seconds (see
    /// [`super::grant_paging`]).
    backfill_done: StoredValue<HashMap<String, Marker>>,
    /// Pages waiting for room in the unwrap queue
    /// ([`WrapQueue::has_page_room`]).
    deferred_pages: StoredValue<Vec<DeferredPage>, LocalStorage>,
    /// Each running grant scope's marker id, for `try_write_markers`.
    scope_markers: StoredValue<HashMap<GrantScope, String>>,
    /// The processed-wrap set changed since it was last written to
    /// IndexedDB, and a flush is scheduled.
    processed_flush_pending: StoredValue<bool>,
    /// Wraps waiting to be processed, and the slots running them (see
    /// [`super::wrap_queue`]).
    wrap_queue: StoredValue<WrapQueue<WrapJob>, LocalStorage>,
    /// Wrap ids handed to the wrap handler this sign-in. Paging re-delivers
    /// the inclusive `until` boundary row, and a reconnect replays the
    /// long-lived subscriptions; neither should process a wrap twice.
    seen_wraps: StoredValue<HashSet<String>>,
    /// Every epoch held per zone by any row on this device, whatever its
    /// owner (epoch numbers only), so a mint never reuses an epoch another
    /// account on this browser holds but has not delivered.
    /// [`keyset::plan_mint`] decides which of them are believable.
    device_epochs: RwSignal<HashMap<String, std::collections::BTreeSet<u32>>>,
    /// Which identity is signed in, and its generation: work started for an
    /// earlier one touches memory, the relay and the UI only while its
    /// [`Lease`] is current.
    session: StoredValue<Session>,
    /// Ciphertexts and sealed-original envelopes seen, so a key that arrives
    /// later can decrypt what is already on screen, swapping an envelope's
    /// placeholder for the original event in place (ADR-2017).
    cache: StoredValue<ReadCache>,
    /// Bumped by every re-decryption pass; a chunked pass stops as soon as a
    /// newer pass (a key arrived or was replaced, or the keys were dropped)
    /// has started, so it can never apply outcomes computed with stale keys.
    redecrypt_gen: StoredValue<u64>,
    processed: StoredValue<HashSet<String>>,
    /// Keys (by [`key_owner::inbox_granted_entry`], the full store id) that
    /// have been received through the signed-in identity's inbox key on this
    /// device. A copy addressed to the identity is only ever
    /// swept once its id is here.
    inbox_granted: StoredValue<HashSet<String>>,
    admin_cache: StoredValue<HashMap<String, bool>>,
    /// "Granted from this device", shared by every Encryption-tab card.
    grants: StoredValue<Arc<GrantLedger>>,
    /// The lease the grant sync is running for.
    sync_for: StoredValue<Option<Lease>>,
    /// The grant sync's relay subscriptions, closed when the identity
    /// changes: the relay replays subscriptions on reconnect, and their
    /// callbacks hold the identity's signer.
    grant_subs: StoredValue<Vec<String>>,
    grant_relay: StoredValue<Option<RelayConnection>>,
    /// The app's relay connection, whose verified-id cache is cleared on
    /// every identity switch (security review H6).
    app_relay: StoredValue<Option<RelayConnection>>,
    /// Secret of the signed-in identity's inbox key (hex), once registered.
    /// Always `None` with `RECIPIENT_KEYS_ENABLED` off.
    inbox_sk: StoredValue<Option<String>>,
    /// Keys refused because the signed-in identity's view holds a different
    /// key for the same slot (see
    /// [`ForumDb::put_zone_key_unless_conflicting`]), and keys a resolution
    /// displaced: kept whole, and in `zone_kv`
    /// ([`key_owner::refused_keys_id`]), so a conflict can be resolved
    /// ([`Self::use_refused`]) without the grant being delivered again. The
    /// Encryption card lists them.
    pub conflicts: RwSignal<Vec<key_owner::RefusedKey>>,
    /// Posts that actually opened, per `(zone, epoch, epoch pubkey)` (ids,
    /// at most [`OPEN_EVIDENCE_CAP`] each): under the held key on the normal
    /// read path, and under a refused key in the zone's own channels while
    /// its slot is in conflict. The evidence for
    /// [`key_owner::grant_supersedes`]; a `zk` tag alone proves nothing.
    /// Dropped on every identity switch.
    opened: StoredValue<HashMap<(String, u32, String), HashSet<String>>>,
    /// Slots with an automatic resolution in flight: evidence arriving
    /// meanwhile must not start a second (its compare-and-swap would refuse).
    resolving: StoredValue<HashSet<(String, u32)>>,
    /// Automatic grant re-checks per `(zone, epoch)` this session
    /// ([`keyset::recheck_due`]).
    rechecks: StoredValue<HashMap<(String, u32), keyset::RecheckState>>,
    /// Automatic re-checks started this session, across all slots.
    recheck_total: StoredValue<u32>,
    /// The signed-in identity's signer, kept while its grant sync runs so a
    /// re-check can open wraps again. Cleared with the sync.
    grant_signer: StoredValue<Option<Rc<dyn Signer>>, leptos::prelude::LocalStorage>,
    /// Highest `zk` epoch seen per `(zone named in the tag, channel)`, with the
    /// post id. The Encryption card counts only channels that resolve to the
    /// zone, so a tag in some other channel cannot steer a rotation. Kept
    /// across sign-ins: it records posts, not keys, and only ever raises the
    /// epoch a mint picks.
    pub epochs_seen: RwSignal<HashMap<(String, String), std::collections::BTreeMap<u32, String>>>,
    /// Captured at construction: relay callbacks and spawned tasks run
    /// without a reactive owner, so `use_context` is not available there.
    channels: crate::stores::channels::ChannelStore,
}

impl ZoneKeyStore {
    fn new(channels: crate::stores::channels::ChannelStore) -> Self {
        Self {
            channels,
            keys: RwSignal::new(HashMap::new()),
            revision: RwSignal::new(0),
            encrypted_ids: RwSignal::new(HashSet::new()),
            loaded_for: RwSignal::new(None),
            grant_backlog: RwSignal::new(None),
            backfill_done: StoredValue::new(HashMap::new()),
            deferred_pages: StoredValue::new_local(Vec::new()),
            scope_markers: StoredValue::new(HashMap::new()),
            processed_flush_pending: StoredValue::new(false),
            wrap_queue: StoredValue::new_local(WrapQueue::new()),
            seen_wraps: StoredValue::new(HashSet::new()),
            device_epochs: RwSignal::new(HashMap::new()),
            session: StoredValue::new(Session::default()),
            cache: StoredValue::new(ReadCache::default()),
            redecrypt_gen: StoredValue::new(0),
            processed: StoredValue::new(HashSet::new()),
            inbox_granted: StoredValue::new(HashSet::new()),
            admin_cache: StoredValue::new(HashMap::new()),
            grants: StoredValue::new(Arc::new(GrantLedger::default())),
            sync_for: StoredValue::new(None),
            grant_subs: StoredValue::new(Vec::new()),
            grant_relay: StoredValue::new(None),
            app_relay: StoredValue::new(None),
            inbox_sk: StoredValue::new(None),
            conflicts: RwSignal::new(Vec::new()),
            opened: StoredValue::new(HashMap::new()),
            resolving: StoredValue::new(HashSet::new()),
            rechecks: StoredValue::new(HashMap::new()),
            recheck_total: StoredValue::new(0),
            grant_signer: StoredValue::new_local(None),
            epochs_seen: RwSignal::new(HashMap::new()),
        }
    }

    // -- Identity ---------------------------------------------------------

    fn is_current(&self, lease: &Lease) -> bool {
        self.session
            .try_with_value(|s| s.is_current(lease))
            .unwrap_or(false)
    }

    fn current_lease(&self) -> Option<Lease> {
        self.session.try_with_value(Session::lease).flatten()
    }

    /// Whether the keys of `me` (a pubkey, as auth reports it) are loaded,
    /// tracked. `false` while signed out, before the load finishes, and in the
    /// moment between a sign-in and the store's switch to it.
    pub fn ready_for(&self, me: Option<&str>) -> bool {
        let Some(me) = me.and_then(Owner::parse) else {
            return false;
        };
        self.loaded_for.with(|l| l.as_ref() == Some(&me))
    }

    /// Where `me`'s zone keys stand at `now` (epoch ms): settled (loaded
    /// from IndexedDB and the grant backlog worked through), still arriving,
    /// or stalled; `None` until the stored keys are loaded and the grant sync
    /// has started for `me`. Each key that arrived has already re-decrypted
    /// what is on screen, so once settled an encrypted post still locked is
    /// locked for want of a key this member does not hold, not for want of
    /// time. Tracked.
    pub fn key_phase_for(&self, me: Option<&str>, now: f64) -> Option<KeyPhase> {
        let me = me.and_then(Owner::parse)?;
        if !self.loaded_for.with(|l| l.as_ref() == Some(&me)) {
            return None;
        }
        self.grant_backlog.with(|b| match b {
            Some((owner, backlog)) if *owner == me => Some(backlog.phase(now)),
            _ => None,
        })
    }

    /// Apply `f` to the backlog of `lease`'s sign-in at the current time. A
    /// lease that is no longer current is ignored: its backlog has been
    /// reset.
    fn note_backlog(&self, lease: &Lease, f: impl FnOnce(&mut GrantBacklog, f64)) {
        if !self.is_current(lease) {
            return;
        }
        let now = js_sys::Date::now();
        let _ = self.grant_backlog.try_update(|b| match b {
            Some((owner, backlog)) if owner == lease.owner() => f(backlog, now),
            _ => {}
        });
    }

    /// Every epoch any row on this device holds for `zone`, whatever its
    /// owner, ascending, tracked. Feeds [`keyset::plan_mint`].
    pub fn device_epochs_for(&self, zone: &str) -> Vec<u32> {
        self.device_epochs.with(|m| {
            m.get(zone)
                .map(|s| s.iter().copied().collect())
                .unwrap_or_default()
        })
    }

    fn note_device_epoch(&self, zone: &str, epoch: u32) {
        if self
            .device_epochs
            .with_untracked(|m| m.get(zone).is_some_and(|s| s.contains(&epoch)))
        {
            return;
        }
        let _ = self.device_epochs.try_update(|m| {
            m.entry(zone.to_string()).or_default().insert(epoch);
        });
    }

    /// Make the store follow the signed-in identity. On any change (sign-out,
    /// or another identity signing in) everything the previous identity
    /// loaded or started is dropped: keys, conflicts, its inbox key, its grant
    /// subscriptions, held group signers, and the plaintext on screen, which
    /// goes back to placeholders. Then the new identity's keys are loaded.
    pub fn switch_owner(&self, next: Option<Owner>) {
        let Some(Switch::Changed(lease)) = self.session.try_update_value(|s| s.switch(next)) else {
            return;
        };
        self.stop_grant_sync();
        // A new identity starts with a fresh re-check budget and no stale slots.
        self.rechecks.set_value(HashMap::new());
        self.recheck_total.set_value(0);
        let _ = self.loaded_for.try_set(None);
        let _ = self.grant_backlog.try_set(None);
        self.backfill_done.set_value(HashMap::new());
        self.deferred_pages.set_value(Vec::new());
        self.scope_markers.set_value(HashMap::new());
        // Queued and parked wraps belong to the old sign-in; ones already
        // running finish and are ignored (their lease is no longer current),
        // and their slots belong to the old generation.
        self.wrap_queue.update_value(WrapQueue::reset);
        self.seen_wraps.set_value(HashSet::new());
        let _ = self.keys.try_set(HashMap::new());
        let _ = self.conflicts.try_set(Vec::new());
        self.opened.set_value(HashMap::new());
        self.inbox_granted.set_value(HashSet::new());
        self.inbox_sk.set_value(None);
        super::tickets::clear_group_identities();
        super::public_inbox::reset_sweep_tracker();
        super::conversation_keys::clear();
        // Sealed search: stop the worker (its derived keys and index), then
        // drop the cached sealed objects.
        crate::utils::sealed_search::wipe();
        if let Some(relay) = self.app_relay.get_value() {
            relay.clear_verified();
        }
        // Synchronous on purpose: with the keys gone this pass does no
        // cryptography, and it must revert every plaintext on screen before
        // anything else runs (it also stops any chunked pass in flight).
        self.redecrypt();
        if let Some(lease) = lease {
            let store = *self;
            spawn_local(async move {
                store.load_for(lease).await;
            });
        }
    }

    fn stop_grant_sync(&self) {
        self.sync_for.set_value(None);
        self.grant_signer.set_value(None);
        let subs = self
            .grant_subs
            .try_update_value(std::mem::take)
            .unwrap_or_default();
        if let Some(relay) = self.grant_relay.get_value() {
            for id in subs {
                relay.unsubscribe(&id);
            }
        }
    }

    // -- Reads ------------------------------------------------------------

    /// Key for `(zone, epoch)`, untracked. Deterministic when an epoch is
    /// inconsistent (see [`keyset::read_key`]); the read path still checks
    /// the result against the message's `zk` pubkey.
    pub fn lookup(&self, zone: &str, epoch: u32) -> Option<ZoneKey> {
        self.keys
            .with_untracked(|m| keyset::read_key(m.values(), zone, epoch))
    }

    /// The key to send under for `zone`: `Err` while any epoch of the zone is
    /// claimed by two different pubkeys, `Ok(None)` when no key is eligible
    /// (including a derived genesis epoch 0 with no live epoch yet). See
    /// [`keyset::send_key`].
    pub fn current_send_key(&self, zone: &str) -> Result<Option<ZoneKey>, SendKeyError> {
        self.keys
            .with_untracked(|m| keyset::send_key(m.values(), zone))
    }

    /// Every key held for `zone`, oldest epoch first, untracked.
    pub fn all_for_zone(&self, zone: &str) -> Vec<ZoneKey> {
        let mut v: Vec<ZoneKey> = self
            .keys
            .with_untracked(|m| m.values().filter(|k| k.zone == zone).cloned().collect());
        v.sort_by_key(|k| k.epoch);
        v
    }

    /// Highest-epoch key held for `zone`, tracked.
    pub fn latest_tracked(&self, zone: &str) -> Option<ZoneKey> {
        self.keys.with(|m| latest_in(m, zone))
    }

    // -- Memory, for the current identity only ----------------------------

    /// Put `key` in memory under `id` if `lease` is current. Returns whether
    /// it did.
    fn remember(&self, lease: &Lease, id: String, key: ZoneKey) -> bool {
        if !self.is_current(lease) {
            return false;
        }
        self.keys.update(|m| {
            m.insert(id, key);
        });
        self.redecrypt_chunked();
        true
    }

    /// Make memory hold what storage holds for `id` as the lease's identity
    /// sees it (their row, else the legacy row; every write is guarded on that
    /// view), dropping the in-memory entry only if storage has neither.
    async fn adopt_stored(&self, lease: &Lease, id: &str) {
        let Ok(db) = ForumDb::open().await else {
            return;
        };
        let Ok(stored) = db.get_zone_key(lease.owner(), id).await else {
            return;
        };
        if !self.is_current(lease) {
            return;
        }
        let id = id.to_string();
        self.keys.update(|m| match stored {
            Some(k) => {
                m.insert(id, k);
            }
            None => {
                m.remove(&id);
            }
        });
        // This path can REMOVE a key or REPLACE its secret (storage disagreed
        // with memory), so plaintext opened under the old key must go at once:
        // synchronous re-decryption, never the chunked pass, and conversation
        // keys derived from a secret that may no longer be held are dropped.
        super::conversation_keys::clear();
        self.redecrypt();
    }

    /// Note a refused key: logged, and listed for the Encryption card while
    /// its identity is signed in.
    fn record_conflict(&self, lease: &Lease, key: &ZoneKey) {
        web_sys::console::warn_1(
            &format!(
                "[zone-key] refused a second key for {} epoch {} (from {}): this device already holds a different one",
                key.zone, key.epoch, key.granted_by
            )
            .into(),
        );
        if !self.is_current(lease) {
            return;
        }
        let entry = key_owner::RefusedKey {
            key: key.clone(),
            displaced: false,
        };
        let mut changed = false;
        self.conflicts
            .update(|v| changed = key_owner::note_refused(v, entry.clone()));
        if changed {
            let store = *self;
            let lease = lease.clone();
            spawn_local(async move {
                store.save_refused(&lease, entry).await;
            });
        }
    }

    /// Merge `entry` into the lease's identity's stored refused list (one
    /// transaction, so tabs never overwrite each other) and adopt the merged
    /// list while that identity is signed in.
    async fn save_refused(&self, lease: &Lease, entry: key_owner::RefusedKey) {
        let Ok(db) = ForumDb::open().await else {
            return;
        };
        match db.add_refused_key(lease.owner(), entry).await {
            Ok(list) if self.is_current(lease) => {
                let _ = self.conflicts.try_set(list);
            }
            Ok(_) => {}
            Err(_) => web_sys::console::warn_1(&"[zone-key] refused key not saved".into()),
        }
    }

    /// Record which key `raw` (a zone-encrypted post) opened under: `shown`
    /// is what the normal read path made of it with the held keys. While its
    /// slot is in conflict, also try the slot's refused keys, but only for a
    /// post in a channel of that zone, so a post elsewhere cannot vouch for a
    /// key. New evidence re-judges the slot.
    fn note_evidence(&self, raw: &NostrEvent, shown: &NostrEvent) {
        let Some(zk) = super::parse_zk(&raw.tags) else {
            return;
        };
        let pk = zk.pubkey.to_ascii_lowercase();
        let opened_held = shown.id != raw.id
            || (shown.content != super::PLACEHOLDER_MISSING_KEY
                && shown.content != super::PLACEHOLDER_UNDECRYPTABLE);
        let mut news = false;
        if opened_held {
            news |= self.note_open(&zk.zone, zk.epoch, &pk, &raw.id);
        }
        let candidates: Vec<ZoneKey> = self.conflicts.with_untracked(|v| {
            v.iter()
                .map(|r| &r.key)
                .filter(|k| k.zone == zk.zone && k.epoch == zk.epoch)
                .filter(|k| k.pubkey.eq_ignore_ascii_case(&pk))
                .cloned()
                .collect()
        });
        if !candidates.is_empty() && self.in_zone(raw, &zk.zone) {
            for k in candidates {
                let opened = matches!(
                    read_outcome(raw, |_, _| Some(k.clone())),
                    super::ReadOutcome::Decrypted(_) | super::ReadOutcome::Sealed(_)
                );
                if opened {
                    news |= self.note_open(&zk.zone, zk.epoch, &pk, &raw.id);
                }
            }
        }
        if news {
            self.maybe_resolve(&zk.zone, zk.epoch);
        }
    }

    /// Whether `ev`'s channel belongs to `zone`.
    fn in_zone(&self, ev: &NostrEvent, zone: &str) -> bool {
        super::root_channel(&ev.tags)
            .and_then(|c| channel_zone(self.channels, &c))
            .is_some_and(|(z, _, _)| z == zone)
    }

    /// Note that post `id` opened under `(zone, epoch, pubkey)`. Returns
    /// whether that is news.
    fn note_open(&self, zone: &str, epoch: u32, pubkey: &str, id: &str) -> bool {
        self.opened
            .try_update_value(|m| {
                let ids = m
                    .entry((zone.to_string(), epoch, pubkey.to_string()))
                    .or_default();
                ids.len() < OPEN_EVIDENCE_CAP && ids.insert(id.to_string())
            })
            .unwrap_or(false)
    }

    fn opens(&self, zone: &str, epoch: u32, pubkey: &str) -> usize {
        self.opened.with_value(|m| {
            m.get(&(zone.to_string(), epoch, pubkey.to_ascii_lowercase()))
                .map_or(0, HashSet::len)
        })
    }

    /// Resolve `(zone, epoch)`'s conflict in favour of a refused grant when
    /// [`key_owner::grant_supersedes`] says the held key is the stale one.
    /// The sender's admin status is re-checked by [`Self::use_refused`].
    fn maybe_resolve(&self, zone: &str, epoch: u32) {
        let Some(lease) = self.current_lease() else {
            return;
        };
        let candidate = self.conflicts.with_untracked(|v| {
            v.iter()
                .filter(|r| !r.displaced && r.key.zone == zone && r.key.epoch == epoch)
                .find(|r| {
                    self.keys
                        .with_untracked(|m| m.get(&r.key.store_id()).cloned())
                        .is_some_and(|held| {
                            key_owner::grant_supersedes(
                                &held,
                                &r.key,
                                self.opens(zone, epoch, &held.pubkey),
                                self.opens(zone, epoch, &r.key.pubkey),
                            )
                        })
                })
                .cloned()
        });
        let Some(entry) = candidate else {
            return;
        };
        let slot = (zone.to_string(), epoch);
        let first = self
            .resolving
            .try_update_value(|s| s.insert(slot.clone()))
            .unwrap_or(false);
        if !first {
            return;
        }
        let store = *self;
        spawn_local(async move {
            let result = if store.is_current(&lease) {
                Some(store.use_refused(&entry).await)
            } else {
                None
            };
            store.resolving.update_value(|s| {
                s.remove(&slot);
            });
            let Some(result) = result else {
                return;
            };
            let k = &entry.key;
            match result {
                Ok(()) => web_sys::console::log_1(
                    &format!(
                        "[zone-key] {} epoch {}: replaced a held key that opened no post with the key an admin granted, which opened {} or more",
                        k.zone, k.epoch, key_owner::MIN_SWAP_EVIDENCE
                    )
                    .into(),
                ),
                Err(e) => web_sys::console::warn_1(
                    &format!("[zone-key] {} epoch {}: not replaced: {e}", k.zone, k.epoch).into(),
                ),
            }
        });
    }

    /// Resolve a conflict in favour of `entry`, one of [`Self::conflicts`]:
    /// its key replaces the key the signed-in identity holds for the slot,
    /// which is kept in the list as displaced so the choice can be reversed.
    /// The swap and that record are one IndexedDB transaction.
    ///
    /// Refused when `entry` is not listed, when the held key is this
    /// device's own key still awaiting delivery (displacing it could strand
    /// posts only it opens), when a refused grant's sender is no longer an
    /// admin (a displaced key was held already, so it is restored without
    /// that check, keeping its own delivery state), or when storage no
    /// longer holds the key memory holds. On success every post is decrypted
    /// again at once, with conversation keys and the sealed-search index
    /// derived from the replaced secret dropped.
    pub async fn use_refused(&self, entry: &key_owner::RefusedKey) -> Result<(), String> {
        let lease = self.current_lease().ok_or("Not signed in.")?;
        let listed = self.conflicts.with_untracked(|v| v.contains(entry));
        if !listed {
            return Err("That key is no longer offered.".into());
        }
        let key = &entry.key;
        let id = key.store_id();
        let held = self
            .keys
            .with_untracked(|m| m.get(&id).cloned())
            .ok_or("No key is held for that epoch.")?;
        if !super::conflicts(&held, key) {
            return Err("That key is already the one in use.".into());
        }
        if held.pending_delivery {
            return Err(
                "The key in use is this device's own new key and has not reached anyone yet; grant it first."
                    .into(),
            );
        }
        let mut new = key.clone();
        if !entry.displaced {
            match self.sealer_is_admin(&key.granted_by).await {
                Some(true) => {}
                Some(false) => return Err("Its sender is no longer an admin.".into()),
                None => return Err("Could not check its sender's admin status; try again.".into()),
            }
            new.pending_delivery = false;
        }
        let db = ForumDb::open()
            .await
            .map_err(|_| "Browser storage is unavailable.".to_string())?;
        let list = match db.swap_zone_key(lease.owner(), &held, &new).await {
            Ok(Some(list)) => list,
            Ok(None) => {
                self.adopt_stored(&lease, &id).await;
                return Err("The stored key changed meanwhile; review and try again.".into());
            }
            Err(_) => return Err("Could not write to browser storage.".into()),
        };
        if !self.is_current(&lease) {
            return Ok(());
        }
        let _ = self.conflicts.try_set(list);
        self.keys.update(|m| {
            m.insert(id, new);
        });
        // The replaced secret must stop opening anything at once.
        super::conversation_keys::clear();
        crate::utils::sealed_search::wipe();
        self.redecrypt();
        Ok(())
    }

    /// `key`, still pending when the slot holds the same secret as a key
    /// awaiting delivery. The creator's own grant comes back through the grant
    /// sync (both `insert_persisted` and `insert_local` paths); that alone must
    /// not adopt the key while members may lack it. Only [`mark_delivered`]
    /// clears it. Memory is the view for the current identity; for an earlier
    /// one, storage is asked.
    ///
    /// [`mark_delivered`]: Self::mark_delivered
    async fn keep_pending(&self, lease: &Lease, key: ZoneKey) -> ZoneKey {
        let id = key.store_id();
        if self.is_current(lease) {
            return self
                .keys
                .with_untracked(|m| keep_pending_against(key, m.get(&id)));
        }
        let held = match ForumDb::open().await {
            Ok(db) => db.get_zone_key(lease.owner(), &id).await.ok().flatten(),
            Err(_) => None,
        };
        keep_pending_against(key, held.as_ref())
    }

    /// Mark `owner`'s pending key for `(zone, epoch)` with `pubkey` delivered:
    /// it becomes eligible to send under. `owner` is the identity that sent
    /// the grants, captured when they were sent, so an ack that lands after
    /// that identity signed out still settles its key in storage. Returns
    /// `false` when the key is not pending in the signed-in identity's memory
    /// (storage is still updated for an earlier identity).
    pub fn mark_delivered(&self, owner: &str, zone: &str, epoch: u32, pubkey: &str) -> bool {
        let Some(owner) = Owner::parse(owner) else {
            return false;
        };
        let matches = |k: &ZoneKey| {
            k.zone == zone && k.epoch == epoch && k.pubkey == pubkey && k.pending_delivery
        };
        let lease = self.current_lease().filter(|l| *l.owner() == owner);
        let Some(lease) = lease else {
            // Signed out since: settle the key in storage only.
            let (zone, pubkey) = (zone.to_string(), pubkey.to_string());
            spawn_local(async move {
                let Ok(db) = ForumDb::open().await else {
                    return;
                };
                let Ok(rows) = db.zone_key_rows().await else {
                    return;
                };
                let view =
                    key_owner::visible_keys(rows, &owner, super::tickets::zone_groups_enabled());
                let found = view.into_values().find(|k| {
                    k.zone == zone && k.epoch == epoch && k.pubkey == pubkey && k.pending_delivery
                });
                if let Some(mut key) = found {
                    key.pending_delivery = false;
                    if !matches!(
                        db.put_zone_key_unless_conflicting(&owner, &key).await,
                        Ok(ZoneKeyPut::Stored)
                    ) {
                        web_sys::console::warn_1(
                            &"[zone-key] could not mark a key delivered in storage".into(),
                        );
                    }
                }
            });
            return false;
        };
        let found = self
            .keys
            .with_untracked(|m| m.values().find(|k| matches(k)).cloned());
        let Some(mut key) = found else {
            return false;
        };
        key.pending_delivery = false;
        let id = key.store_id();
        self.keys.update(|m| {
            m.insert(id, key.clone());
        });
        spawn_local(async move {
            if let Ok(db) = ForumDb::open().await {
                match db.put_zone_key_unless_conflicting(lease.owner(), &key).await {
                    Ok(ZoneKeyPut::Stored) => {}
                    Ok(ZoneKeyPut::Conflict(_)) => web_sys::console::warn_1(
                        &"[zone-key] not marked delivered in storage: it holds a different key for this epoch".into(),
                    ),
                    Err(_) => web_sys::console::warn_1(&"[zone-key] persist failed (IndexedDB write)".into()),
                }
            }
        });
        true
    }

    // -- Read path --------------------------------------------------------

    /// Turn an incoming kind-42 into what the reader should see. Events
    /// without a `zk` or `sealed` tag pass through untouched; zone-encrypted
    /// ones get their decrypted text or a placeholder, with the original event
    /// id, tags and signature kept. A sealed original that opens is replaced
    /// by the whole original event (its own id), so call this before any
    /// id-based dedupe or tombstone check that must see that id.
    pub fn prepare_incoming(&self, ev: NostrEvent) -> NostrEvent {
        if !is_zone_message(&ev) {
            return ev;
        }
        if let (Some((zone, epoch)), Some(channel)) = (
            super::zk_zone_epoch(&ev.tags),
            super::root_channel(&ev.tags),
        ) {
            let zone_for_check = zone.clone();
            let slot = (zone, channel);
            if !self
                .epochs_seen
                .with_untracked(|m| m.get(&slot).is_some_and(|s| s.contains_key(&epoch)))
            {
                let id = ev.id.clone();
                self.epochs_seen.update(|m| {
                    m.entry(slot).or_default().insert(epoch, id);
                });
                // A post at a key this device does not hold: ask the relay for
                // this identity's grant wraps again, whatever was marked done.
                if self.lookup(&zone_for_check, epoch).is_none() {
                    self.schedule_recheck();
                }
            }
        }
        let raw = ev;
        let ev = self
            .cache
            .try_update_value(|c| c.prepare(&raw, |z, e| self.lookup(z, e)))
            .unwrap_or_else(|| without_keys(&raw));
        self.note_evidence(&raw, &ev);
        let id = ev.id.clone();
        if !self.encrypted_ids.with_untracked(|s| s.contains(&id)) {
            self.encrypted_ids.update(|s| {
                s.insert(id);
            });
        }
        ev
    }

    // -- Grant re-check ---------------------------------------------------

    /// The epochs of `zone` that posts name but this device holds no key for,
    /// ascending. Reactive (reads `epochs_seen` and the keys).
    pub fn unheld_epochs(&self, zone: &str) -> Vec<u32> {
        let held = self.keys.get();
        let seen = self.epochs_seen.get();
        let slots = keyset::unheld_slots(
            seen.iter()
                .filter(|((z, _), _)| z == zone)
                .flat_map(|((z, _), eps)| eps.keys().map(move |e| (z.as_str(), *e))),
            |z, e| held.values().any(|k| k.zone == z && k.epoch == e),
        );
        slots.into_iter().map(|(_, e)| e).collect()
    }

    /// After a short delay (so the normal grant sync can land first), re-check
    /// the grants if any post names an epoch not held and a re-check is due.
    fn schedule_recheck(&self) {
        let store = *self;
        gloo::timers::callback::Timeout::new(RECHECK_DELAY_MS, move || store.recheck_unheld())
            .forget();
    }

    fn recheck_unheld(&self) {
        let held = |z: &str, e: u32| self.lookup(z, e).is_some();
        let slots = self.epochs_seen.with_untracked(|m| {
            keyset::unheld_slots(
                m.iter()
                    .flat_map(|((z, _), eps)| eps.keys().map(move |e| (z.as_str(), *e))),
                held,
            )
        });
        let now = js_sys::Date::now();
        let due = self.rechecks.with_value(|r| {
            slots
                .iter()
                .any(|s| keyset::recheck_due(r.get(s).copied(), now))
        });
        if slots.is_empty() || !due || !keyset::recheck_budget_left(self.recheck_total.get_value())
        {
            return;
        }
        if self.recheck_grants() {
            self.recheck_total.update_value(|n| *n += 1);
            self.rechecks.update_value(|r| {
                for s in slots {
                    let e = r.entry(s).or_default();
                    e.attempts += 1;
                    e.last_ms = now;
                }
            });
        }
    }

    /// Ask the relay for every kind-1059 wrap addressed to the signed-in
    /// identity (and its inbox key) again, with no `since`, and process each
    /// one even if it was marked processed or refused: an earlier pass may
    /// have settled a grant while the sealer's admin check said no (a stale or
    /// different relay), or while an older client could not adopt it. Admin
    /// answers cached as "not an admin" are dropped first. A key found is
    /// adopted through the normal path, which re-decrypts what is on screen.
    /// Returns false when no grant sync is running (nothing was asked).
    pub fn recheck_grants(&self) -> bool {
        let (Some(relay), Some(signer), Some(lease)) = (
            self.grant_relay.get_value(),
            self.grant_signer.get_value(),
            self.current_lease(),
        ) else {
            return false;
        };
        if self.sync_for.with_value(|l| l.as_ref() != Some(&lease)) {
            return false;
        }
        self.admin_cache.update_value(|m| m.retain(|_, v| *v));
        let me = lease.owner().as_str().to_string();
        let inbox_pk = self
            .inbox_sk
            .get_value()
            .and_then(|sk| super::inbox_key::inbox_signer(&sk).ok())
            .map(|s| s.public_key().to_string());
        let handler = self.wrap_handler(&relay, signer, lease, false, true);
        let sub: Rc<RefCell<Option<String>>> = Rc::default();
        let (done_sub, done_relay, store) = (sub.clone(), relay.clone(), *self);
        let eose = Rc::new(move || {
            if let Some(id) = done_sub.borrow_mut().take() {
                done_relay.unsubscribe(&id);
                store.grant_subs.update_value(|v| v.retain(|s| s != &id));
            }
        });
        let id = relay.subscribe(
            vec![wrap_filter(
                subscription_targets(&me, inbox_pk.as_deref()),
                None,
            )],
            handler,
            Some(eose),
        );
        // Tracked so an identity switch tears it down (and drops its signer).
        self.grant_subs.update_value(|v| v.push(id.clone()));
        *sub.borrow_mut() = Some(id);
        true
    }

    /// Re-run decryption over every zone-encrypted message already in the
    /// channel store (a key just arrived, or every key was just dropped).
    /// Sealed-original placeholders that now open become the original event
    /// in place, and restored originals whose key is gone go back to the
    /// placeholder; see [`ReadCache::redecrypt`].
    pub fn redecrypt(&self) {
        // Supersedes any chunked pass in flight (see `redecrypt_chunked`).
        self.redecrypt_gen.update_value(|g| *g += 1);
        let channels = self.channels;
        if self.cache.with_value(ReadCache::is_empty) {
            let _ = self.revision.try_update(|r| *r += 1);
            return;
        }
        let store = *self;
        let mut restored_ids: Vec<String> = Vec::new();
        channels.channel_messages.update(|m| {
            store.cache.update_value(|c| {
                c.redecrypt(
                    m,
                    |z, e| store.lookup(z, e),
                    |inner| channels.admits_restored_original(inner),
                );
                restored_ids = m
                    .values()
                    .flatten()
                    .filter(|ev| c.envelope_of(&ev.id).is_some())
                    .map(|ev| ev.id.clone())
                    .collect();
            });
        });
        let missing: Vec<String> = self.encrypted_ids.with_untracked(|s| {
            restored_ids
                .into_iter()
                .filter(|id| !s.contains(id))
                .collect()
        });
        if !missing.is_empty() {
            self.encrypted_ids.update(|s| s.extend(missing));
        }
        self.revision.update(|r| *r += 1);
    }

    /// Sizes of the per-id collections (`alloc-stats` diagnostics).
    #[cfg(feature = "alloc-stats")]
    pub fn debug_sizes(&self) -> Vec<(&'static str, usize)> {
        vec![
            ("zone.read_cache", self.cache.with_value(ReadCache::len)),
            (
                "zone.encrypted_ids",
                self.encrypted_ids.with_untracked(HashSet::len),
            ),
            ("zone.processed", self.processed.with_value(HashSet::len)),
            (
                "zone.admin_cache",
                self.admin_cache.with_value(HashMap::len),
            ),
        ]
    }

    /// Forget messages history paging has evicted from the channel store:
    /// their ciphertexts, envelopes and restored mappings
    /// ([`ReadCache::evict`]) and their encrypted marks, in one update each,
    /// so evicted plaintext is not kept anywhere. Conversation keys stay
    /// (they belong to the zone secret and author, not to a message), as do
    /// verified event ids.
    pub fn forget(&self, ids: &[String]) {
        if ids.is_empty() {
            return;
        }
        self.cache
            .update_value(|c| c.evict(ids.iter().map(String::as_str)));
        if self
            .encrypted_ids
            .with_untracked(|s| ids.iter().any(|id| s.contains(id)))
        {
            self.encrypted_ids.update(|s| {
                for id in ids {
                    s.remove(id);
                }
            });
        }
    }

    /// [`redecrypt`](Self::redecrypt) for a key that was ADDED (never one
    /// removed or replaced: those revert synchronously), spread
    /// over the event loop so a cold-key join does not freeze the page: the
    /// messages to open are taken newest first, opened
    /// [`REDECRYPT_CHUNK`] at a time with a yield (`setTimeout(0)`) between
    /// chunks, and each chunk's outcomes are applied to the channel store at
    /// once (the reader sees the newest messages decrypt first).
    ///
    /// The pass belongs to the identity and generation it started under. It
    /// stops when a newer pass starts (`redecrypt_gen`; every key change runs
    /// one) or the identity changes, checked after every yield and right
    /// before each apply, with no await in between: outcomes computed with
    /// keys that have since been replaced or dropped are never applied.
    /// Messages that arrive meanwhile are decrypted on arrival by
    /// `prepare_incoming`; a message the pass has not reached is left as is.
    pub fn redecrypt_chunked(&self) {
        let gen = self.redecrypt_gen.try_update_value(|g| {
            *g += 1;
            *g
        });
        let Some(gen) = gen else {
            return;
        };
        let channels = self.channels;
        if self.cache.with_value(ReadCache::is_empty) {
            let _ = self.revision.try_update(|r| *r += 1);
            return;
        }
        let lease = self.current_lease();
        let targets: Vec<NostrEvent> = channels
            .channel_messages
            .with_untracked(|m| self.cache.with_value(|c| c.open_targets(m)));
        let store = *self;
        spawn_local(async move {
            let still_current = |s: &ZoneKeyStore| {
                s.redecrypt_gen.try_get_value() == Some(gen) && s.current_lease() == lease
            };
            for chunk in targets.chunks(REDECRYPT_CHUNK) {
                if !still_current(&store) {
                    return;
                }
                let outcomes: HashMap<String, super::ReadOutcome> = chunk
                    .iter()
                    .map(|ev| (ev.id.clone(), read_outcome(ev, |z, e| store.lookup(z, e))))
                    .collect();
                if !still_current(&store) {
                    return;
                }
                store.apply_outcomes(outcomes);
                yield_to_event_loop().await;
            }
        });
    }

    /// Apply precomputed read-path outcomes (by the id of the event opened)
    /// to the channel store in one update, as [`redecrypt`](Self::redecrypt)
    /// does for all of them.
    fn apply_outcomes(&self, outcomes: HashMap<String, super::ReadOutcome>) {
        let channels = self.channels;
        let store = *self;
        let mut restored_ids: Vec<String> = Vec::new();
        let _ = channels.channel_messages.try_update(|m| {
            store.cache.update_value(|c| {
                // `get(..).cloned()`, not `remove`: one event id can sit in
                // more than one channel list, and every copy takes the outcome.
                c.redecrypt_with(
                    m,
                    |ev| outcomes.get(&ev.id).cloned(),
                    |inner| channels.admits_restored_original(inner),
                );
                restored_ids = m
                    .values()
                    .flatten()
                    .filter(|ev| c.envelope_of(&ev.id).is_some())
                    .map(|ev| ev.id.clone())
                    .collect();
            });
        });
        let missing: Vec<String> = self.encrypted_ids.with_untracked(|s| {
            restored_ids
                .into_iter()
                .filter(|id| !s.contains(id))
                .collect()
        });
        if !missing.is_empty() {
            self.encrypted_ids.update(|s| s.extend(missing));
        }
        let _ = self.revision.try_update(|r| *r += 1);
    }

    // -- Loading ----------------------------------------------------------

    /// Load the lease's identity's keys, its inbox-granted set and the
    /// processed-wrap set from IndexedDB, then mark that identity ready. A
    /// load that finishes after a switch is dropped.
    async fn load_for(&self, lease: Lease) {
        self.load_stored(&lease).await;
        if self.is_current(&lease) {
            let _ = self.loaded_for.try_set(Some(lease.owner().clone()));
        }
    }

    async fn load_stored(&self, lease: &Lease) {
        let Ok(db) = ForumDb::open().await else {
            return;
        };
        // Moves rows left under an id from before the last flag change.
        if db.migrate_zone_keys().await.is_err() {
            web_sys::console::warn_1(&"[zone-key] store migration failed".into());
        }
        let rows = db.zone_key_rows().await;
        let processed = db.get_zone_kv(&kv_processed()).await;
        let inbox = db
            .get_zone_kv(&key_owner::inbox_granted_id(lease.owner()))
            .await;
        let refused = db.refused_keys(lease.owner()).await;
        // The identity scope's marker; the inbox scope's is loaded once its
        // key is known (`start_grant_sync`).
        let mut markers = HashMap::new();
        let owner = lease.owner().as_str();
        let id = GrantScope::Identity.marker_id(owner, owner);
        if let Some(marker) = parse_marker(db.get_zone_kv(&id).await.ok().flatten().as_deref()) {
            markers.insert(id, marker);
        }
        if !self.is_current(lease) {
            return;
        }
        self.backfill_done.set_value(markers);
        if let Ok(rows) = rows {
            let floor = key_owner::device_epochs(&rows);
            let _ = self.device_epochs.try_update(|m| {
                for (zone, epochs) in floor {
                    m.entry(zone).or_default().extend(epochs);
                }
            });
            let visible =
                key_owner::visible_keys(rows, lease.owner(), super::tickets::zone_groups_enabled());
            if !visible.is_empty() {
                let mut added = false;
                self.keys
                    .update(|m| added = key_owner::merge_loaded(m, visible));
                if added {
                    self.redecrypt_chunked();
                }
            }
        }
        if let Ok(Some(json)) = processed {
            if let Ok(ids) = serde_json::from_str::<Vec<String>>(&json) {
                self.processed.update_value(|s| s.extend(ids));
            }
        }
        if let Ok(Some(json)) = inbox {
            if let Ok(ids) = serde_json::from_str::<Vec<String>>(&json) {
                self.inbox_granted.update_value(|s| s.extend(ids));
            }
        }
        // After the keys: each slot is judged against the key held for it.
        if let Ok(list) = refused {
            let mut slots = Vec::new();
            self.conflicts.update(|v| {
                for r in list {
                    let slot = (r.key.zone.clone(), r.key.epoch);
                    if key_owner::note_refused(v, r) {
                        slots.push(slot);
                    }
                }
            });
            for (zone, epoch) in slots {
                self.maybe_resolve(&zone, epoch);
            }
        }
    }

    // -- Grant sync -------------------------------------------------------

    /// Subscribe to the signed-in identity's gift wraps once the relay session
    /// is authenticated and pull zone-key grants out of them. Each wrap is
    /// unwrapped at most once per device (ids remembered in IndexedDB), so
    /// ordinary DMs are not re-decrypted on every visit. Runs once per
    /// sign-in; `me` must be the identity the store has switched to.
    /// `signer_can_refuse` marks a signer whose decrypt can fail without the
    /// wrap being unreadable (a NIP-07 extension); see
    /// [`unwrap_failure_outcome`].
    pub fn start_grant_sync(
        &self,
        relay: &RelayConnection,
        signer: Rc<dyn Signer>,
        me: String,
        signer_can_refuse: bool,
    ) {
        let Some(lease) = self.current_lease() else {
            return;
        };
        if Owner::parse(&me).as_ref() != Some(lease.owner())
            || self.sync_for.with_value(|l| l.as_ref() == Some(&lease))
        {
            return;
        }
        self.sync_for.set_value(Some(lease.clone()));
        self.grant_relay.set_value(Some(relay.clone()));
        self.grant_signer.set_value(Some(signer.clone()));
        // Posts already on screen may name an epoch this device lacks, and the
        // normal sync above may have refused or skipped its wraps.
        self.schedule_recheck();
        self.wrap_queue.update_value(|q| {
            q.set_signer(if signer_can_refuse {
                SignerKind::CanRefuse
            } else {
                SignerKind::Local
            })
        });
        let _ = self.grant_backlog.try_set(Some((
            lease.owner().clone(),
            GrantBacklog::new(recipient_keys_enabled(), js_sys::Date::now()),
        )));
        let me = lease.owner().as_str().to_string();
        let store = *self;
        self.run_scope(
            relay,
            &lease,
            GrantScope::Identity,
            subscription_targets(&me, None),
            self.wrap_handler(relay, signer.clone(), lease.clone(), false, false),
        );
        if !recipient_keys_enabled() {
            return;
        }
        // Inbox key: create, restore or confirm it, then listen on it too.
        // Grants may still arrive at the identity key during the transition,
        // which the subscription above keeps covering.
        let relay = relay.clone();
        spawn_local(async move {
            let live = {
                let lease = lease.clone();
                Rc::new(move || store.is_current(&lease))
            };
            let port = LivePort {
                relay: relay.clone(),
                identity: signer.clone(),
                live,
            };
            match ensure_inbox_key(&port, &*signer, now_secs()).await {
                Ok(key) if store.is_current(&lease) => {
                    store.inbox_sk.set_value(Some(key.sk_hex));
                    let handler =
                        store.wrap_handler(&relay, signer.clone(), lease.clone(), true, false);
                    store.note_backlog(&lease, GrantBacklog::inbox_opened);
                    // This inbox key's own backfill marker.
                    let marker = GrantScope::Inbox.marker_id(lease.owner().as_str(), &key.pubkey);
                    if let Ok(db) = ForumDb::open().await {
                        let raw = db.get_zone_kv(&marker).await.ok().flatten();
                        if let Some(stored) = parse_marker(raw.as_deref()) {
                            store.backfill_done.update_value(|m| {
                                m.insert(marker.clone(), stored);
                            });
                        }
                    }
                    if !store.is_current(&lease) {
                        return;
                    }
                    store.run_scope(&relay, &lease, GrantScope::Inbox, vec![key.pubkey], handler);
                }
                Ok(_) => {}
                Err(e) => {
                    store.note_backlog(&lease, GrantBacklog::inbox_failed);
                    web_sys::console::warn_1(&format!("[zone-key] inbox key: {e}").into());
                }
            }
        });
    }

    /// Fetch every stored wrap for one grant scope, paging past the relay's
    /// row cap, then stay subscribed for live wraps. The paging decisions are
    /// [`ScopePager`]'s (see [`super::grant_paging`]); this only opens and
    /// closes the subscriptions it asks for. The long-lived subscription is
    /// page 0; each further page is its own subscription, opened only after
    /// the previous one's EOSE and closed at its own, so a scope holds at
    /// most two relay subscriptions at once. The scope counts as delivered
    /// only when the last page is in.
    fn run_scope(
        &self,
        relay: &RelayConnection,
        lease: &Lease,
        scope: GrantScope,
        targets: Vec<String>,
        handler: EventCallback,
    ) {
        let owner = lease.owner().as_str();
        let target = targets.first().map_or(owner, String::as_str);
        let marker = scope.marker_id(owner, target);
        self.scope_markers.update_value(|m| {
            m.insert(scope, marker.clone());
        });
        let ctx = Rc::new(ScopeCtx {
            relay: relay.clone(),
            lease: lease.clone(),
            scope,
            marker,
            targets,
            handler,
            pager: RefCell::new(ScopePager::new()),
        });
        self.open_page(&ctx, 0, None);
    }

    /// Subscribe page `page` of a scope (`until` inclusive; none for page 0).
    /// Recorded with the grant subscriptions, so a sign-out mid-page closes
    /// it rather than leaving it to be replayed under the next sign-in.
    fn open_page(&self, ctx: &Rc<ScopeCtx>, page: u32, until: Option<u64>) {
        let store = *self;
        let sub_id: Rc<RefCell<Option<String>>> = Rc::default();
        let on_event = {
            let ctx = ctx.clone();
            Rc::new(move |ev: NostrEvent| {
                let processed = store.processed.with_value(|s| s.contains(&ev.id));
                ctx.pager
                    .borrow_mut()
                    .observe(page, &ev.id, ev.created_at, processed);
                (ctx.handler)(ev);
            })
        };
        let on_eose = {
            let (ctx, sub_id) = (ctx.clone(), sub_id.clone());
            Rc::new(move || store.after_page(&ctx, page, &sub_id))
        };
        let id = ctx.relay.subscribe(
            vec![wrap_filter(ctx.targets.clone(), until)],
            on_event,
            Some(on_eose),
        );
        self.grant_subs.update_value(|v| v.push(id.clone()));
        *sub_id.borrow_mut() = Some(id);
    }

    /// Act on page `page` of a scope reaching EOSE (its subscription id in
    /// `sub_id`).
    fn after_page(&self, ctx: &Rc<ScopeCtx>, page: u32, sub_id: &RefCell<Option<String>>) {
        let lease = &ctx.lease;
        if !self.is_current(lease) {
            return;
        }
        let stored = self
            .backfill_done
            .with_value(|m| m.get(&ctx.marker).copied());
        let warm = warm_marker(stored, grant_sweep_enabled());
        // `None`: a replayed or stale EOSE, not the current page's first.
        let Some(end) = ctx.pager.borrow_mut().eose(page, warm) else {
            return;
        };
        if end.close {
            if let Some(id) = sub_id.borrow_mut().take() {
                ctx.relay.unsubscribe(&id);
                // Closed: `stop_grant_sync` need not CLOSE it again.
                let _ = self.grant_subs.try_update_value(|v| v.retain(|s| s != &id));
            }
        }
        match end.then {
            // Only while the queue has room for a page; otherwise held until
            // it drains (`open_deferred_pages`).
            PagerAction::Fetch { page, until } => {
                if self.wrap_queue.with_value(WrapQueue::has_page_room) {
                    self.open_page(ctx, page, Some(until));
                } else {
                    self.deferred_pages.update_value(|d| {
                        d.push(DeferredPage {
                            ctx: ctx.clone(),
                            page,
                            until,
                        })
                    });
                }
            }
            PagerAction::Done { verified } => {
                if ctx.scope == GrantScope::Identity {
                    // The end of stored events on the identity scope settles
                    // the old-grant cleanup flag the public-inbox opt-in
                    // waits for. With the sweep on there is no warm stop, so
                    // this follows a full walk of the scope.
                    super::public_inbox::sweep_eose(lease.owner().as_str());
                }
                let scope = ctx.scope;
                self.note_backlog(lease, |b, now| b.scope_delivered(scope, verified, now));
                self.try_write_markers(lease);
            }
            PagerAction::GiveUp => {
                web_sys::console::warn_1(
                    &format!(
                        "[zone-key] {:?} grant paging stopped at page {page}",
                        ctx.scope
                    )
                    .into(),
                );
                self.note_backlog(lease, GrantBacklog::paging_gave_up);
            }
        }
    }

    /// Persist the completion time of every scope whose marker has come due
    /// ([`GrantBacklog::take_due_markers`]: a verified walk, every wrap of
    /// this sign-in finished, none waiting for a retry). Called when a scope
    /// finishes paging and whenever a wrap finishes. A session closed before
    /// then writes nothing, so the next one pages fully.
    fn try_write_markers(&self, lease: &Lease) {
        if !self.is_current(lease) {
            return;
        }
        // Untracked: taking the due set changes nothing a page renders.
        let (due, floor) = self
            .grant_backlog
            .try_update_untracked(|b| match b {
                Some((owner, backlog)) if owner == lease.owner() => {
                    (backlog.take_due_markers(), backlog.marker_floor())
                }
                _ => (Vec::new(), None),
            })
            .unwrap_or_default();
        if due.is_empty() {
            return;
        }
        let marker = Marker {
            done_at: now_secs(),
            floor,
        };
        let ids: Vec<String> = self.scope_markers.with_value(|m| {
            due.iter()
                .filter_map(|scope| m.get(scope).cloned())
                .collect()
        });
        self.backfill_done.update_value(|m| {
            for id in &ids {
                m.insert(id.clone(), marker);
            }
        });
        let store = *self;
        spawn_local(async move {
            // The processed set first, so the next session's warm stop sees
            // every wrap this one handled.
            store.flush_processed().await;
            if let Ok(db) = ForumDb::open().await {
                for id in ids {
                    let _ = db.put_zone_kv(&id, &marker.encode()).await;
                }
            }
        });
    }

    /// The callback for one grant subscription. `inbox` marks the inbox-key
    /// subscription: with the sweep on, its wraps are looked at again even
    /// when processed, so the identity's inbox-granted set is rebuilt from
    /// wraps provably addressed to it (it is not carried over from before
    /// keys had owners). The inbox key is a local key, so this prompts no one.
    fn wrap_handler(
        &self,
        relay: &RelayConnection,
        signer: Rc<dyn Signer>,
        lease: Lease,
        inbox: bool,
        force: bool,
    ) -> EventCallback {
        let store = *self;
        let relay = relay.clone();
        // Set by `start_grant_sync` before any handler is made.
        let kind = self.wrap_queue.with_value(WrapQueue::signer);
        Rc::new(move |ev: NostrEvent| {
            if ev.kind != nostr_bbs_core::gift_wrap::KIND_GIFT_WRAP || !store.is_current(&lease) {
                return;
            }
            // Once per sign-in, whichever subscription or page delivered it
            // (a transient failure removes it again, so a replay retries).
            // A forced re-check (`force`) looks again even at one already seen.
            let first = store
                .seen_wraps
                .try_update_value(|s| s.insert(ev.id.clone()))
                .unwrap_or(false);
            if !first && !force {
                return;
            }
            let me = lease.owner().as_str();
            // With the sweep on, wraps already handled are looked at again
            // when addressed to the identity (an old grant is deleted once its
            // key is safe here) or to its inbox key (see above).
            let revisit =
                force || (grant_sweep_enabled() && (inbox || p_tags(&ev).any(|p| p == me)));
            if !revisit && store.processed.with_value(|s| s.contains(&ev.id)) {
                return;
            }
            super::public_inbox::sweep_wrap_started();
            // Counted as backlog from the moment it is queued; progress is
            // when it finishes (see `GrantBacklog`).
            store.note_backlog(&lease, |b, _| b.wrap_started());
            store.enqueue_wrap(WrapJob {
                lease: lease.clone(),
                ev,
                signer: signer.clone(),
                kind,
                relay: relay.clone(),
            });
        })
    }

    /// Queue a wrap for processing and start as many as the queue allows.
    fn enqueue_wrap(&self, job: WrapJob) {
        self.wrap_queue.update_value(|q| q.push(job));
        self.pump_wraps();
    }

    /// Start queued wraps while the queue has free slots, then open any page
    /// that was waiting for the queue to drain.
    fn pump_wraps(&self) {
        self.start_wraps();
        self.open_deferred_pages();
    }

    /// Open the held pages once the queue has room for a page.
    fn open_deferred_pages(&self) {
        if !self.wrap_queue.with_value(WrapQueue::has_page_room) {
            return;
        }
        let ready = self
            .deferred_pages
            .try_update_value(std::mem::take)
            .unwrap_or_default();
        for d in ready {
            if self.is_current(&d.ctx.lease) {
                self.open_page(&d.ctx, d.page, Some(d.until));
            }
        }
    }

    /// Start queued wraps while the queue has free slots. Each slot is given
    /// back when its wrap finishes or after [`UNWRAP_SLOT_TIMEOUT_MS`],
    /// whichever comes first.
    fn start_wraps(&self) {
        loop {
            let Some(started) = self
                .wrap_queue
                .try_update_value(WrapQueue::start_next)
                .flatten()
            else {
                return;
            };
            let slot = Rc::new(Cell::new(Some(started.slot)));
            let store = *self;
            // Not while a refusable signer has yet to succeed: its one slot is
            // then waiting on a permission prompt (the admin check has its own
            // bound), and releasing it would raise another prompt every minute
            // for a person who has walked away.
            let refusable_unproven =
                started.successes_at_start == 0 && started.job.kind == SignerKind::CanRefuse;
            if !refusable_unproven {
                let slot = slot.clone();
                crate::utils::set_timeout_once(
                    move || store.release_slot(&slot),
                    UNWRAP_SLOT_TIMEOUT_MS,
                );
            }
            spawn_local(async move {
                store.run_wrap(started).await;
                store.release_slot(&slot);
            });
        }
    }

    /// Give a slot back once (the wrap finished, or it timed out first).
    fn release_slot(&self, slot: &Cell<Option<Slot>>) {
        if let Some(s) = slot.take() {
            let _ = self.wrap_queue.try_update_value(|q| q.release(s));
            self.pump_wraps();
        }
    }

    /// The refusable signer decrypted a wrap in the job holding `slot`: queue
    /// the wraps it refused earlier once more (see [`super::wrap_queue`]).
    /// Nothing for a sign-in that has since switched.
    fn note_signer_success(&self, lease: &Lease, slot: Slot) {
        if !self.is_current(lease) {
            return;
        }
        let requeued = self
            .wrap_queue
            .try_update_value(|q| q.signer_succeeded(slot))
            .unwrap_or(0);
        for _ in 0..requeued {
            self.note_backlog(lease, |b, _| b.wrap_started());
        }
        if requeued > 0 {
            self.pump_wraps();
        }
    }

    /// Process one queued wrap and account for it.
    async fn run_wrap(&self, started: Started<WrapJob>) {
        let Started {
            job,
            slot,
            attempt,
            successes_at_start,
        } = started;
        if !self.is_current(&job.lease) {
            return; // its sign-in is over; the backlog was reset
        }
        let outcome = self.process_wrap(&job, attempt, slot).await;
        let lease = job.lease.clone();
        let id = job.ev.id.clone();
        let created_at = job.ev.created_at;
        self.note_backlog(&lease, |b, now| b.wrap_done(now, &id, created_at, outcome));
        match outcome {
            WrapOutcome::Refused => {
                // Held for the signer's next success. Still seen, so a replay
                // does not queue it twice; still counted by the sweep.
                if self.is_current(&lease) {
                    let requeued = self
                        .wrap_queue
                        .try_update_value(|q| q.park(job, successes_at_start))
                        .unwrap_or(false);
                    if requeued {
                        self.note_backlog(&lease, |b, _| b.wrap_started());
                        self.pump_wraps();
                    }
                }
                return;
            }
            WrapOutcome::Retry => {
                // Left unmarked to be retried: let a reconnect's replay of the
                // same wrap in this session try again.
                self.seen_wraps.update_value(|s| {
                    s.remove(&id);
                });
            }
            WrapOutcome::Settled => {
                // Settled wraps are in the processed set, which turns a
                // re-delivery away, so `seen_wraps` need not keep them
                // (with the sweep on, processed wraps are revisited, so it
                // does).
                if !grant_sweep_enabled() {
                    self.seen_wraps.update_value(|s| {
                        s.remove(&id);
                    });
                }
            }
            WrapOutcome::Unreadable | WrapOutcome::UnreadableBySigner => {}
        }
        // A switch reset the tracker: an earlier identity's wrap no longer
        // counts towards the new one's cleanup.
        if self.is_current(&lease) {
            super::public_inbox::sweep_wrap_done(lease.owner().as_str());
        }
        self.try_write_markers(&lease);
    }

    async fn process_wrap(&self, job: &WrapJob, attempt: Attempt, slot: Slot) -> WrapOutcome {
        let (lease, wrap, signer, relay) = (&job.lease, &job.ev, &*job.signer, &job.relay);
        let me = lease.owner().as_str();
        let inbox = self
            .inbox_sk
            .get_value()
            .filter(|_| self.is_current(lease))
            .and_then(|sk| super::inbox_key::inbox_signer(&sk).ok());
        let inbox_ref = inbox.as_ref().map(|s| s as &dyn Signer);
        let identity_kind = job.kind;
        let (sealer, rumor, opener) =
            match open_for_sync(wrap, inbox_ref, signer, identity_kind, attempt).await {
                Ok(v) => v,
                // Left unmarked so a later session with a capable signer
                // retries; the outcome says whether it holds this one.
                Err(outcome) => return outcome,
            };
        if opener == Opener::Identity && identity_kind == SignerKind::CanRefuse {
            self.note_signer_success(lease, slot);
        }
        let via_inbox = opener == Opener::Inbox;
        let kind = signer_kind_for(wrap, inbox_ref, signer, identity_kind);
        match super::tickets::route(rumor.kind, super::tickets::zone_groups_enabled()) {
            super::tickets::Route::Grant => {}
            super::tickets::Route::Ignore => {
                self.mark_processed(&wrap.id).await;
                return WrapOutcome::Settled;
            }
            super::tickets::Route::Ticket => {
                return self
                    .process_ticket(lease, wrap, inbox_ref, signer, via_inbox, (kind, attempt))
                    .await;
            }
        }
        // A grant is marked processed only once its outcome is final. An
        // unreachable admin check or a key that did not reach IndexedDB leaves
        // the wrap unmarked, so the next session retries instead of losing the
        // key for good.
        let admin = self.sealer_is_admin(&sealer).await;
        let (valid, persisted, stored, grant_id) = match admin {
            None => (false, false, false, None),
            Some(is_admin) => match validate_grant(&rumor, &sealer, is_admin, now_secs()) {
                Ok(key) => {
                    let id =
                        key_owner::inbox_granted_entry(&key, super::tickets::zone_groups_enabled());
                    let outcome = self.insert_persisted(lease, key).await;
                    // A refused grant is settled, but the inbox copy did not
                    // replace anything: never let the sweep treat it as such.
                    if via_inbox && outcome == Persisted::Stored {
                        self.mark_inbox_granted(lease, &id).await;
                    }
                    (
                        true,
                        outcome.settled(),
                        outcome == Persisted::Stored,
                        Some(id),
                    )
                }
                Err(e) => {
                    web_sys::console::warn_1(&format!("[zone-key] grant refused: {e}").into());
                    (false, false, false, None)
                }
            },
        };
        let outcome = if super::grant_settled(admin, valid, persisted) {
            self.mark_processed(&wrap.id).await;
            WrapOutcome::Settled
        } else {
            WrapOutcome::Retry
        };
        // Nothing below runs once the identity has signed out: it publishes
        // deletions signed by that identity, and reports to the cleanup
        // tracker the next identity owns.
        if !self.is_current(lease) {
            return outcome;
        }
        // Deleting the identity copy is safe only once the SAME (zone, epoch)
        // key has also arrived addressed to the inbox key on this device, so a
        // replacement provably exists on the relay. Local persistence alone is
        // not enough: a wiped IndexedDB would then have no copy left anywhere.
        let replacement_exists = grant_id
            .as_deref()
            .is_some_and(|id| self.inbox_granted.with_value(|s| s.contains(id)));
        let candidate = SweepCandidate {
            wrap_id: wrap.id.clone(),
            to_identity: p_tags(wrap).any(|p| p == me),
            is_grant: true,
            // Only a grant whose key this device stored: a refused grant's
            // key lives nowhere else, so its wrap must never be swept.
            key_safe: valid && stored && replacement_exists,
        };
        let doomed = sweep_targets(grant_sweep_enabled(), std::slice::from_ref(&candidate));
        if candidate.to_identity
            && candidate.is_grant
            && super::public_inbox::grant_blocks_cleanup(admin.is_some(), valid, !doomed.is_empty())
        {
            // Still waiting on its replacement key: cleanup is not finished.
            super::public_inbox::sweep_grant_left(me);
        }
        for id in doomed {
            let unsigned = deletion_for_wrap(me, &id, now_secs());
            if let Ok(del) = signer.sign_event(unsigned).await {
                if self.is_current(lease) {
                    relay.publish(&del);
                }
            }
        }
        outcome
    }

    /// An NIP-171 epoch ticket (ADR-2028 decision 2): opened with its
    /// signature intact, accepted only from the zone's bound group identity,
    /// and stored as the same [`ZoneKey`] a 21453 grant yields. No admin
    /// check: the group identity is not an admin. Unloaded bindings leave the
    /// wrap unmarked so the next session retries; any other refusal is final.
    /// `failure` (the signer kind and attempt) classifies a ticket whose own
    /// decrypt failed (see [`unwrap_failure_outcome`]).
    async fn process_ticket(
        &self,
        lease: &Lease,
        wrap: &NostrEvent,
        inbox: Option<&dyn Signer>,
        identity: &dyn Signer,
        via_inbox: bool,
        failure: (SignerKind, Attempt),
    ) -> WrapOutcome {
        use super::tickets::{
            ensure_bindings_loaded, loaded_bindings, ticket_verdict, TicketVerdict,
        };
        if let Err(e) = ensure_bindings_loaded().await {
            web_sys::console::warn_1(&format!("[zone-key] bindings: {e}").into());
        }
        let opened = super::tickets::open_ticket(wrap, inbox, identity).await;
        let me = lease.owner().as_str();
        match ticket_verdict(opened, me, loaded_bindings().as_ref(), now_secs()) {
            TicketVerdict::Retry => WrapOutcome::Retry,
            // Left unmarked for a later session's bindings; holds nothing now.
            TicketVerdict::Unbound => WrapOutcome::Unreadable,
            // The outer unwrap opened, but the ticket's own decrypt did not: a
            // NIP-07 refusal is held and retried, never a final refusal.
            TicketVerdict::SignerFailed(e) => unwrap_failure_outcome(&e, failure.0, failure.1),
            TicketVerdict::Refuse(why) => {
                web_sys::console::warn_1(&format!("[zone-key] ticket refused: {why}").into());
                self.mark_processed(&wrap.id).await;
                WrapOutcome::Settled
            }
            TicketVerdict::Accept(key) => {
                let key = *key;
                let id =
                    key_owner::inbox_granted_entry(&key, super::tickets::zone_groups_enabled());
                let outcome = self.insert_persisted(lease, key).await;
                if via_inbox && outcome == Persisted::Stored {
                    self.mark_inbox_granted(lease, &id).await;
                }
                if outcome.settled() {
                    self.mark_processed(&wrap.id).await;
                    WrapOutcome::Settled
                } else {
                    WrapOutcome::Retry
                }
            }
        }
    }

    // -- Writes -----------------------------------------------------------

    /// Store a received key as the lease's identity's row and wait for it to
    /// reach IndexedDB. Memory, the conflict list and the screen change only
    /// while that identity is still signed in; a grant that finishes after a
    /// sign-out is still stored, under its own identity, for its next sign-in.
    async fn insert_persisted(&self, lease: &Lease, key: ZoneKey) -> Persisted {
        let key = self.keep_pending(lease, key).await;
        let id = key.store_id();
        if self.is_current(lease) {
            if let Some(held) = self.keys.with_untracked(|m| m.get(&id).cloned()) {
                if super::conflicts(&held, &key) {
                    self.record_conflict(lease, &key);
                    return Persisted::Refused;
                }
            }
        }
        let outcome = match ForumDb::open().await {
            Ok(db) => match db
                .put_zone_key_unless_conflicting(lease.owner(), &key)
                .await
            {
                Ok(ZoneKeyPut::Stored) => Persisted::Stored,
                Ok(ZoneKeyPut::Conflict(held)) => {
                    // Final: the held key stands and this grant is settled (the
                    // wrap is marked processed), so it is not retried forever.
                    self.record_conflict(lease, &key);
                    if self.is_current(lease)
                        && self.keys.with_untracked(|m| m.get(&id) != Some(&held))
                    {
                        self.remember(lease, id, held);
                    }
                    return Persisted::Refused;
                }
                Err(_) => {
                    web_sys::console::warn_1(&"[zone-key] persist failed (IndexedDB write)".into());
                    return Persisted::Failed;
                }
            },
            Err(_) => {
                // No IndexedDB at all (blocked storage, some private modes):
                // keep the key for this session only, as before, so the zone
                // stays readable. The memory conflict check above still holds,
                // and the grant stays unsettled so it is offered again.
                self.remember(lease, id, key);
                return Persisted::Failed;
            }
        };
        self.note_device_epoch(&key.zone, key.epoch);
        // Stored from here on. A key storage did not accept never enters memory
        // (the grant stays unsettled and is retried), so memory only diverges
        // from storage briefly, and storage is the side to believe.
        if !self.is_current(lease) {
            return outcome;
        }
        // Re-read after the awaits: an ack may have marked the key delivered
        // meanwhile, and an echo must neither undo that nor re-pend it; and a
        // different key may have arrived, which this one must not replace.
        let mut key = key;
        let wrote_pending = key.pending_delivery;
        let held_now = self.keys.with_untracked(|m| m.get(&id).cloned());
        if let Some(held) = &held_now {
            if super::conflicts(held, &key) {
                self.record_conflict(lease, &key);
                // Storage accepted this key, yet memory holds another (another
                // tab's write): make memory match storage, never the reverse.
                self.adopt_stored(lease, &id).await;
                return Persisted::Refused;
            }
        }
        key.pending_delivery = held_now
            .as_ref()
            .is_some_and(|k| k.pending_delivery && k.secret == key.secret);
        if wrote_pending && !key.pending_delivery {
            // Delivered during the awaits: the write above stored pending and
            // may have landed after mark_delivered's. Store the settled state.
            let settled = key.clone();
            let owner = lease.owner().clone();
            spawn_local(async move {
                if let Ok(db) = ForumDb::open().await {
                    if db
                        .put_zone_key_unless_conflicting(&owner, &settled)
                        .await
                        .is_err()
                    {
                        web_sys::console::warn_1(
                            &"[zone-key] persist failed (IndexedDB write)".into(),
                        );
                    }
                }
            });
        }
        if held_now.as_ref() != Some(&key) {
            self.remember(lease, id, key);
        }
        outcome
    }

    /// Save a key this device just created as the signed-in identity's row,
    /// refusing it if that identity's view already holds a different key for
    /// its epoch, or if any row on this device (any account) holds a different
    /// key for the zone at that epoch or above. Awaited before any grant is
    /// sent, so a refused key is never distributed. A sign-out during the save
    /// leaves the key stored, still pending, under the identity that created
    /// it, and nothing is sent.
    pub async fn insert_local(&self, key: ZoneKey) -> Result<(), String> {
        let lease = self
            .current_lease()
            .ok_or_else(|| "Sign in to create a key; nothing was sent.".to_string())?;
        let id = key.store_id();
        if self
            .keys
            .with_untracked(|m| m.get(&id).is_some_and(|h| super::conflicts(h, &key)))
        {
            return Err(format!(
                "This device already holds a different key for epoch {}.",
                key.epoch
            ));
        }
        let db = ForumDb::open().await.map_err(|_| {
            "Could not open this browser's key storage; nothing was sent.".to_string()
        })?;
        match db.put_minted_zone_key(lease.owner(), &key).await {
            Ok(MintPut::Stored) => {}
            Ok(MintPut::Conflict(held)) => {
                self.remember(&lease, id, held);
                return Err(format!(
                    "This device already holds a different key for epoch {}.",
                    key.epoch
                ));
            }
            Ok(MintPut::Superseded(epoch)) => {
                self.note_device_epoch(&key.zone, epoch);
                return Err(format!(
                    "This browser already holds key epoch {epoch} of this zone (possibly for another account). Nothing was created or sent; try again."
                ));
            }
            Err(_) => {
                return Err("Could not save the new key on this device; nothing was sent.".into())
            }
        }
        self.note_device_epoch(&key.zone, key.epoch);
        if !self.is_current(&lease) {
            return Err("You signed out while the key was being saved; nothing was sent.".into());
        }
        if self
            .keys
            .with_untracked(|m| m.get(&id).is_some_and(|h| super::conflicts(h, &key)))
        {
            // Storage accepted the new key, yet memory holds another: make
            // memory match storage; nothing is sent.
            self.adopt_stored(&lease, &id).await;
            return Err(format!(
                "A different key for epoch {} arrived meanwhile.",
                key.epoch
            ));
        }
        self.remember(&lease, id, key);
        Ok(())
    }

    /// Mark a wrap processed. Memory changes at once; the IndexedDB copy is
    /// written at most once a second ([`PROCESSED_FLUSH_MS`]) and when a
    /// scope's backfill completes. Writing the whole set per wrap made a
    /// paged backfill quadratic (thousands of wraps, each rewriting every id
    /// before it), inside the time the page waits for keys. A flush lost to a
    /// closed tab only means those wraps are retried next session, which the
    /// unmarked-wrap design already allows.
    async fn mark_processed(&self, wrap_id: &str) {
        self.processed.update_value(|s| {
            s.insert(wrap_id.to_string());
        });
        if self.processed_flush_pending.try_get_value().unwrap_or(true) {
            return;
        }
        self.processed_flush_pending.set_value(true);
        let store = *self;
        crate::utils::set_timeout_once(
            move || {
                spawn_local(async move {
                    store.flush_processed().await;
                });
            },
            PROCESSED_FLUSH_MS,
        );
    }

    /// Write the processed-wrap set to IndexedDB now.
    async fn flush_processed(&self) {
        let _ = self.processed_flush_pending.try_set_value(false);
        let Some(ids) = self
            .processed
            .try_with_value(|s| s.iter().cloned().collect::<Vec<String>>())
        else {
            return;
        };
        if let (Ok(db), Ok(json)) = (ForumDb::open().await, serde_json::to_string(&ids)) {
            let _ = db.put_zone_kv(&kv_processed(), &json).await;
        }
    }

    /// Record that `id` reached the lease's identity through its inbox key.
    /// The in-memory set is the identity's while it is signed in, and is
    /// written whole (acks arrive together; see [`GrantLedger`]); after a
    /// sign-out the stored set is extended instead.
    async fn mark_inbox_granted(&self, lease: &Lease, id: &str) {
        let kv_id = key_owner::inbox_granted_id(lease.owner());
        let Ok(db) = ForumDb::open().await else {
            return;
        };
        let ids: Vec<String> = if self.is_current(lease) {
            self.inbox_granted.update_value(|s| {
                s.insert(id.to_string());
            });
            self.inbox_granted
                .with_value(|s| s.iter().cloned().collect())
        } else {
            let mut stored: HashSet<String> = db
                .get_zone_kv(&kv_id)
                .await
                .ok()
                .flatten()
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default();
            stored.insert(id.to_string());
            stored.into_iter().collect()
        };
        if let Ok(json) = serde_json::to_string(&ids) {
            let _ = db.put_zone_kv(&kv_id, &json).await;
        }
    }

    // -- Admin bookkeeping ------------------------------------------------
    //
    // Device-wide on purpose: the ledger records grants this browser's admins
    // sent, and an approval is an admin's decision about zone membership,
    // which holds whichever admin is signed in.

    /// Whether `pubkey` is a relay admin, or `None` when the relay could not
    /// be asked. Only definite answers are cached (per session).
    pub async fn sealer_is_admin(&self, pubkey: &str) -> Option<bool> {
        if let Some(v) = self.admin_cache.with_value(|m| m.get(pubkey).copied()) {
            return Some(v);
        }
        // Bounded: the fetch has no timeout of its own, and a hung check
        // would hold an unwrap slot (finding 4).
        let v = with_timeout(fetch_is_admin(pubkey), ADMIN_CHECK_TIMEOUT_MS)
            .await
            .flatten()?;
        self.admin_cache.update_value(|m| {
            m.insert(pubkey.to_string(), v);
        });
        Some(v)
    }

    /// Pubkeys this admin has granted `(zone, epoch)` to, on this device.
    pub async fn grants_sent(&self, zone: &str, epoch: u32) -> HashSet<String> {
        let ledger = self.grants.get_value();
        ledger.sent(&IdbGrantKv, zone, epoch).await
    }

    /// Members already granted `(zone, epoch)` at the key they would be
    /// granted at now (`targets`: member to recipient key; absent means the
    /// member's identity).
    pub async fn grants_sent_to(
        &self,
        zone: &str,
        epoch: u32,
        targets: &HashMap<String, String>,
    ) -> HashSet<String> {
        let ledger = self.grants.get_value();
        ledger.sent_to(&IdbGrantKv, zone, epoch, targets).await
    }

    /// The ledger entries of `(zone, epoch)`, for the relay-held backup
    /// ([`super::grant_backup`]).
    pub async fn export_grant_backup(&self, zone: &str, epoch: u32) -> Vec<String> {
        let ledger = self.grants.get_value();
        ledger.export(&IdbGrantKv, zone, epoch).await
    }

    /// Merge entries restored from the relay-held backup into the ledger;
    /// returns how many were new to this device.
    pub async fn merge_grant_backup(&self, zone: &str, epoch: u32, entries: &[String]) -> usize {
        let ledger = self.grants.get_value();
        ledger.merge(&IdbGrantKv, zone, epoch, entries).await
    }

    /// Record that `(zone, epoch)` was granted to each `(member, recipient
    /// key)`. Safe to call
    /// concurrently: acks for one batch arrive together (see [`GrantLedger`]).
    pub async fn record_grants(&self, zone: &str, epoch: u32, recipients: &[(String, String)]) {
        let ledger = self.grants.get_value();
        ledger.record(&IdbGrantKv, zone, epoch, recipients).await;
    }

    /// Members this device has ever granted any of `epochs` of `zone` to
    /// (recipient key irrelevant): the "known" targets the first-grant gate
    /// auto-grants without a fresh confirmation.
    pub async fn members_ever_granted(&self, zone: &str, epochs: &[u32]) -> HashSet<String> {
        let ledger = self.grants.get_value();
        ledger.members_ever(&IdbGrantKv, zone, epochs).await
    }

    /// `zone`'s persisted set of admin-approved first-time grant targets.
    pub async fn approved_targets(&self, zone: &str) -> HashSet<String> {
        let ledger = self.grants.get_value();
        ledger.approved(&IdbGrantKv, zone).await
    }

    /// Record that an admin approved `pubkey` as a first-time grant target for
    /// `zone` (persisted), so this and later sweeps auto-grant to it.
    pub async fn approve_target(&self, zone: &str, pubkey: &str) {
        let ledger = self.grants.get_value();
        ledger.approve(&IdbGrantKv, zone, pubkey).await;
    }
}

/// The grant ledger's storage: the `zone_kv` IndexedDB store.
struct IdbGrantKv;

impl GrantKv for IdbGrantKv {
    async fn get(&self, id: &str) -> Option<String> {
        ForumDb::open()
            .await
            .ok()?
            .get_zone_kv(id)
            .await
            .ok()
            .flatten()
    }

    async fn put(&self, id: &str, json: &str) -> bool {
        match ForumDb::open().await {
            Ok(db) => db.put_zone_kv(id, json).await.is_ok(),
            Err(_) => false,
        }
    }
}

/// The grant-sync filter: kind-1059 wraps to `p`, at most
/// Envelopes opened per slice of a chunked re-decryption: ~25 × ~0.6 ms
/// (cached conversation key, inner verify) keeps each slice near 15 ms in
/// desktop wasm, under one frame.
pub const REDECRYPT_CHUNK: usize = 25;

/// Yield to the browser's event loop (a `setTimeout(0)` macrotask), so input
/// and rendering run between slices of work.
async fn yield_to_event_loop() {
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        let scheduled = web_sys::window().is_some_and(|w| {
            w.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 0)
                .is_ok()
        });
        if !scheduled {
            let _ = resolve.call0(&wasm_bindgen::JsValue::NULL);
        }
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

/// The grant-sync filter: kind-1059 wraps to `p`, at most
/// [`RELAY_FILTER_LIMIT`](crate::stores::channels::RELAY_FILTER_LIMIT) rows
/// (an explicit limit: the relay's default is 500), at or before `until`
/// when paging.
fn wrap_filter(p: Vec<String>, until: Option<u64>) -> Filter {
    Filter {
        kinds: Some(vec![nostr_bbs_core::gift_wrap::KIND_GIFT_WRAP]),
        p_tags: Some(p),
        until,
        limit: Some(crate::stores::channels::RELAY_FILTER_LIMIT),
        ..Default::default()
    }
}

fn p_tags(ev: &NostrEvent) -> impl Iterator<Item = &str> {
    ev.tags
        .iter()
        .filter(|t| t.len() >= 2 && t[0] == "p")
        .map(|t| t[1].as_str())
}

fn latest_in(m: &HashMap<String, ZoneKey>, zone: &str) -> Option<ZoneKey> {
    m.values()
        .filter(|k| k.zone == zone)
        .max_by_key(|k| k.epoch)
        .cloned()
}

/// Resolve after `ms` milliseconds.
async fn sleep_ms(ms: i32) {
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        if let Some(win) = web_sys::window() {
            let _ = win.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
        }
    });
    let _ = JsFuture::from(promise).await;
}

/// `fut`'s output, or `None` if `ms` milliseconds pass first. The future is
/// dropped on timeout; a fetch it started runs on and is ignored.
async fn with_timeout<F: Future>(fut: F, ms: i32) -> Option<F::Output> {
    let mut fut = std::pin::pin!(fut);
    let mut timer = std::pin::pin!(sleep_ms(ms));
    std::future::poll_fn(|cx| {
        if let Poll::Ready(v) = fut.as_mut().poll(cx) {
            return Poll::Ready(Some(v));
        }
        if timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        Poll::Pending
    })
    .await
}

async fn fetch_is_admin(pubkey: &str) -> Option<bool> {
    let url = format!(
        "{}/api/check-whitelist?pubkey={}",
        crate::utils::relay_url::relay_api_base(),
        pubkey
    );
    let win = web_sys::window()?;
    let resp: web_sys::Response = JsFuture::from(win.fetch_with_str(&url))
        .await
        .ok()?
        .dyn_into()
        .ok()?;
    if !resp.ok() {
        return None;
    }
    let text = JsFuture::from(resp.text().ok()?).await.ok()?.as_string()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("isAdmin").and_then(|b| b.as_bool())
}

// -- Context -----------------------------------------------------------------

/// Outcome of storing a received key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Persisted {
    /// Stored (or already held identically).
    Stored,
    /// Refused: this device holds a different key for the epoch. Settled, so
    /// the wrap is not retried, but nothing was replaced.
    Refused,
    /// Not stored (IndexedDB unavailable or the write failed): memory is left
    /// alone and the grant is retried later.
    Failed,
}

impl Persisted {
    fn settled(self) -> bool {
        self != Persisted::Failed
    }
}

/// Pure core of [`ZoneKeyStore::keep_pending`]: `key` stays pending when
/// `existing` (the stored entry at the same id) is pending with the same secret.
fn keep_pending_against(mut key: ZoneKey, existing: Option<&ZoneKey>) -> ZoneKey {
    if existing.is_some_and(|k| k.pending_delivery && k.secret == key.secret) {
        key.pending_delivery = true;
    }
    key
}

/// Provide the zone-key store and keep it on the signed-in identity's keys.
/// Call once at app root, after auth and the channel store and before channel
/// sync starts. Keys load when a session is authenticated (a restored but
/// locked session loads none), are dropped at sign-out, and are reloaded for
/// whoever signs in next, with or without a page reload.
pub fn provide_zone_key_store(channels: crate::stores::channels::ChannelStore) {
    let store = ZoneKeyStore::new(channels);
    store.app_relay.set_value(use_context::<RelayConnection>());
    channels.set_zone_store(store);
    provide_context(store);
    let auth = crate::auth::use_auth();
    Effect::new(move |_| {
        let owner = auth
            .state
            .with(|s| key_owner::owner_from_auth(s.is_authenticated, s.pubkey.as_deref()));
        store.switch_owner(owner);
    });
}

/// Whether `id` is an original this session restored from a sealed envelope
/// (ADR-2017), for a store captured at subscription time. Without a store
/// nothing has been restored.
///
/// Must not be called from inside the store's own cache update (the in-place
/// restore of [`ZoneKeyStore::redecrypt`]), which already knows its answer.
pub fn is_restored_original(store: Option<ZoneKeyStore>, id: &str) -> bool {
    store.is_some_and(|s| s.cache.with_value(|c| c.envelope_of(id).is_some()))
}

/// The envelope id sealed original `id` was restored from this session, if
/// it was (opened on arrival or by a later key). A topic list uses it to
/// keep the row in place when the original reverts to its envelope's
/// placeholder. Not reactive. Same restriction as [`is_restored_original`].
pub fn restored_envelope_of(store: Option<ZoneKeyStore>, id: &str) -> Option<String> {
    store.and_then(|s| {
        s.cache
            .with_value(|c| c.envelope_of(id).map(str::to_string))
    })
}

/// The zone-key store, if provided.
pub fn try_use_zone_key_store() -> Option<ZoneKeyStore> {
    use_context::<ZoneKeyStore>()
}

/// [`ZoneKeyStore::prepare_incoming`] for a store captured at subscription
/// time (relay callbacks have no reactive owner, so capture with
/// [`try_use_zone_key_store`] while setting the subscription up). Without a
/// store a zone-encrypted message still never renders as ciphertext: it
/// shows the missing-key placeholder.
pub fn prepare_incoming(store: Option<ZoneKeyStore>, ev: NostrEvent) -> NostrEvent {
    match store {
        Some(store) => store.prepare_incoming(ev),
        None if is_zone_message(&ev) => without_keys(&ev),
        None => ev,
    }
}

/// The read path with no keys at all: a zone-encrypted message or sealed
/// envelope shows the missing-key placeholder under its own id.
fn without_keys(ev: &NostrEvent) -> NostrEvent {
    resolve_event(ev, read_outcome(ev, |_, _| None))
}

/// Encrypted-zone lookup for a channel: `(zone id, display name, encrypted)`,
/// resolved through the channel's section tag and `ZONE_CONFIG`.
pub fn channel_zone(
    channels: crate::stores::channels::ChannelStore,
    channel_id: &str,
) -> Option<(String, String, bool)> {
    let section = channels.channels.with_untracked(|list| {
        list.iter()
            .find(|c| c.id == channel_id)
            .map(|c| c.section.clone())
    })?;
    let zones = crate::stores::zones::load_zones();
    let zone_id = crate::stores::zones::section_to_zone(&section, &zones)?;
    let zone = zones.iter().find(|z| z.id == zone_id)?;
    Some((
        zone.id.clone(),
        zone.display_name.clone(),
        super::zone_is_encrypted(super::encryption_enabled(), zone.encrypted),
    ))
}

/// Apply the zone write rules to an outgoing kind-42 for `channel_id`:
/// encrypt when the channel's zone is encrypted, refuse when the member has
/// no key, pass through otherwise. Every kind-42 publish path calls this
/// immediately before signing.
///
/// `keys` and `channels` are captured by the caller while it is still inside
/// a reactive owner (component setup), because publish paths run in spawned
/// tasks where `use_context` is unavailable.
pub async fn prepare_outgoing(
    keys: Option<ZoneKeyStore>,
    channels: crate::stores::channels::ChannelStore,
    channel_id: &str,
    signer: Option<Rc<dyn Signer>>,
    unsigned: nostr_bbs_core::UnsignedEvent,
) -> Result<nostr_bbs_core::UnsignedEvent, String> {
    let Some((zone_id, display, encrypted)) = channel_zone(channels, channel_id) else {
        return Ok(unsigned);
    };
    let latest = match keys {
        Some(s) => s.current_send_key(&zone_id).map_err(|e| e.to_string())?,
        None => None,
    };
    let plan = super::write_plan(encrypted, &display, latest)?;
    if plan == super::WritePlan::Plain {
        return Ok(unsigned);
    }
    let signer = signer.ok_or("Sign in to post in an encrypted zone.")?;
    super::apply_write_plan(&plan, &*signer, unsigned).await
}

/// The two stores a kind-42 publish path needs, captured together while the
/// caller is still inside a reactive owner (component setup). `Copy`, so it
/// moves freely into the spawned publish task.
#[derive(Clone, Copy)]
pub struct ZoneWriter {
    keys: Option<ZoneKeyStore>,
    channels: Option<crate::stores::channels::ChannelStore>,
}

impl ZoneWriter {
    /// Capture from context. Call during component setup, not in a task.
    pub fn capture() -> Self {
        Self {
            keys: try_use_zone_key_store(),
            channels: use_context::<crate::stores::channels::ChannelStore>(),
        }
    }

    /// [`prepare_outgoing`] for `channel_id`. Without a channel store the
    /// event passes through; the relay still refuses plaintext in an
    /// encrypted zone.
    pub async fn prepare(
        &self,
        channel_id: &str,
        signer: Option<Rc<dyn Signer>>,
        unsigned: nostr_bbs_core::UnsignedEvent,
    ) -> Result<nostr_bbs_core::UnsignedEvent, String> {
        match self.channels {
            Some(channels) => {
                prepare_outgoing(self.keys, channels, channel_id, signer, unsigned).await
            }
            None => Ok(unsigned),
        }
    }
}

#[cfg(test)]
mod pending_tests {
    use super::*;

    fn k(pending: bool, secret: &str) -> ZoneKey {
        ZoneKey {
            zone: "zone3".into(),
            epoch: 3,
            secret: secret.into(),
            pubkey: "p".repeat(64),
            granted_by: "a".repeat(64),
            received_at: 1,
            group: None,
            pending_delivery: pending,
        }
    }

    #[test]
    fn the_creators_own_grant_does_not_adopt_a_pending_key() {
        let back = keep_pending_against(k(false, "s"), Some(&k(true, "s")));
        assert!(
            back.pending_delivery,
            "the self-grant echo must not end pending"
        );
    }

    #[test]
    fn a_different_secret_or_a_delivered_key_is_not_held_back() {
        assert!(!keep_pending_against(k(false, "other"), Some(&k(true, "s"))).pending_delivery);
        assert!(!keep_pending_against(k(false, "s"), Some(&k(false, "s"))).pending_delivery);
        assert!(!keep_pending_against(k(false, "s"), None).pending_delivery);
    }
}
