//! Shared channel metadata store with localStorage cache.
//!
//! Subscribes once at app root to kind-40 (channel creation) and kind-42
//! (messages) events. All pages read from the same reactive signals —
//! no re-fetching on navigation. Channel metadata is cached to localStorage
//! for instant hydration on subsequent visits (stale-while-revalidate).

use gloo::storage::{LocalStorage, Storage};
use leptos::prelude::*;
use nostr_bbs_core::NostrEvent;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use wasm_bindgen::JsCast;

use crate::relay::{Filter, RelayConnection};
use crate::stores::deletion_sync::{self, DeletionProgress, DeletionScope, Source};
use crate::stores::signer_admin::SignerAdminCache;
use crate::stores::tombstones::{self, Target, Tombstones, LOCAL_DELETER};
use crate::stores::zones::Zone;
use crate::topics::section_stats::{SectionStats, SectionStatsState, SECTION_STATS_TIMEOUT_MS};
use crate::utils::lookup::SyncReceipt;
use crate::zone_crypto::store::{is_restored_original, ZoneKeyStore};

// -- Constants ----------------------------------------------------------------

const CACHE_KEY: &str = "nostrbbs_channel_cache";

// -- Types --------------------------------------------------------------------

/// Serializable channel metadata for localStorage cache.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelMeta {
    pub id: String,
    pub name: String,
    pub description: String,
    /// The section the channel is routed by: [`section_tag`](Self::section_tag),
    /// or the id of the zone that pins the channel in `ZONE_CONFIG` (ADR-2037).
    /// Set from [`crate::stores::zones::effective_section`] at ingest and
    /// recomputed whenever the cache is loaded, so every zone resolver follows
    /// a pin, and a removed pin, without a resolver of its own.
    pub section: String,
    /// The raw `section` tag of the signed kind-40 (ADR-2037). Caches written
    /// before this field existed load with it empty and are healed from
    /// `section` on load (see [`heal_cached_sections`]).
    #[serde(default)]
    pub section_tag: String,
    pub picture: String,
    pub created_at: u64,
}

impl ChannelMeta {
    /// The form a channel is cached in (ADR-2037): `section` holds the raw
    /// tag, so a cache read by a build without pin support routes exactly as
    /// it did before pins existed, and [`heal_cached_sections`] recomputes the
    /// routed section on load.
    pub fn cache_form(self) -> Self {
        Self {
            section: self.section_tag.clone(),
            ..self
        }
    }
}

/// ADR-2037: restore each cached channel's raw tag and recompute its routed
/// `section` from it against the current zone config.
///
/// The cache stores the raw tag in `section` (see `save_cache`), and caches
/// from builds before `section_tag` existed hold only that, so an empty
/// `section_tag` is taken from `section`. Recomputing on every load means a
/// pin added or removed since the cache was written takes effect before the
/// relay answers, and an old cache never keeps a channel in the wrong zone.
pub fn heal_cached_sections(channels: &mut [ChannelMeta], zones: &[Zone]) {
    for c in channels.iter_mut() {
        if c.section_tag.is_empty() {
            c.section_tag = std::mem::take(&mut c.section);
        }
        c.section = crate::stores::zones::effective_section(&c.id, &c.section_tag, zones);
    }
}

/// Cached channel data persisted to localStorage.
///
/// ADR-091: `message_counts` is no longer persisted — it is derived from
/// `channel_messages.len()` at runtime. Legacy caches that contain the field
/// continue to deserialize (extra fields are ignored by `serde_json`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct CachedData {
    #[serde(default)]
    channels: Vec<ChannelMeta>,
    #[serde(default)]
    last_active: HashMap<String, u64>,
    /// `created_at` of each channel's most-recent applied kind-41 metadata edit
    /// (admin rename), keyed by channel id. Persisted so a stale kind-41 that
    /// the relay replays after a reload cannot clobber a newer name — see
    /// [`fold_meta_into`]. Legacy caches without this field default to empty.
    #[serde(default)]
    meta_updated_at: HashMap<String, u64>,
    /// Timestamp of last successful relay sync.
    #[serde(default)]
    synced_at: u64,
}

// -- ChannelStore -------------------------------------------------------------

/// Global channel store provided via Leptos context.
/// Subscribe once at app root — all pages read from these signals.
///
/// ADR-091: post counts are NEVER stored as an independent field.
/// Use [`ChannelStore::count_for`] — it derives from `channel_messages`
/// which already dedups by event id. This eliminates the count-inflation
/// class of bugs.
#[derive(Clone, Copy)]
pub struct ChannelStore {
    pub channels: RwSignal<Vec<ChannelMeta>>,
    pub last_active: RwSignal<HashMap<String, u64>>,
    /// Raw kind-42 events stored per resolved channel ID, deduped by id.
    pub channel_messages: RwSignal<HashMap<String, Vec<NostrEvent>>>,
    pub loading: RwSignal<bool>,
    pub eose_received: RwSignal<bool>,
    /// Set when the broad kind-42 subscription reaches EOSE — the store has
    /// received all the message history the relay holds. ADR-092 closeout: this
    /// is a real "store is ready" receipt, used by pages instead of a timer to
    /// decide that an empty channel is authoritatively empty.
    pub msg_eose_received: RwSignal<bool>,
    /// EOSE receipts for the channel-list subscription, split by whether the
    /// relay's REQ ledger judged the answer authenticated (see
    /// `relay::ReceiptCallback`). `eose_received` flips on the FIRST
    /// EOSE, which before AUTH is an anonymous answer that omits Hidden-zone
    /// channels; pages deciding "section not found" read this instead.
    pub channel_receipt: RwSignal<SyncReceipt>,
    /// EOSE receipts for each `ensure_subscribed` history query, keyed by the
    /// id/slug it was called with. The authority for "this topic is not in
    /// this channel": the broad kind-42 sync is capped and its per-zone filters
    /// are a snapshot of the channels known when it started, so its EOSE can
    /// arrive without a given topic in it.
    history_receipts: RwSignal<HashMap<String, SyncReceipt>>,
    sub_id: RwSignal<Option<String>>,
    msg_sub_id: RwSignal<Option<String>>,
    /// Set of channel ids/slugs for which `ensure_subscribed` has been called.
    /// ADR-092: idempotent self-bootstrap.
    ensured: RwSignal<HashSet<String>>,
    /// `created_at` of each channel's most-recent applied kind-41 metadata edit,
    /// tracked SEPARATELY from `ChannelMeta::created_at` (the kind-40 creation
    /// time) so admin renames are last-write-wins and survive reloads. See
    /// [`fold_meta_into`].
    meta_updated_at: RwSignal<HashMap<String, u64>>,
    /// kind-41 edits whose kind-40 channel hasn't been seen yet, keyed by
    /// channel id, newest-wins. Applied when the kind-40 arrives (a kind-41 can
    /// outrun its kind-40 on the wire). Transient — not cached.
    pending_meta: RwSignal<HashMap<String, MetaUpdate>>,
    /// Kind-5 (NIP-09) tombstones as `(id, deleter)`. A tombstone both
    /// removes its target from `channel_messages` AND suppresses a kind-42
    /// that arrives AFTER its deletion (backfill order is not guaranteed);
    /// whether it counts depends on the deleter and the message, see
    /// [`tombstones`]. Seeded from the tombstones persisted by
    /// [`deletion_sync`] (the kind-5 sync only fetches deletions at or after
    /// the device's marker, and a sealed original restored from its envelope
    /// is hidden by nothing else), then extended by this session's kind-5s.
    tombstones: RwSignal<Tombstones>,
    /// The relay's answers on whether a deleter is an admin: the only
    /// authority, besides the original author, for hiding a restored sealed
    /// original. Fail-closed while unanswered.
    signer_admin: SignerAdminCache,
    /// Marker and persisted tombstones for this store's kind-5 filter,
    /// advanced and saved only when the channel subscription reaches EOSE.
    deletion_progress: StoredValue<DeletionProgress>,
    /// Paged history per channel id (see [`HistoryCursor`]). Reactive, so the
    /// channel page can show "loading older" and "start of history".
    history: RwSignal<HashMap<String, HistoryCursor>>,
    /// The most messages one channel's history window holds
    /// ([`HISTORY_WINDOW`], or `window.__ENV__.HISTORY_WINDOW`).
    window_max: usize,
    /// The most replies one thread's list holds ([`THREAD_WINDOW`], or
    /// `window.__ENV__.THREAD_WINDOW`).
    thread_window_max: usize,
    /// The zone-key store, set when it is provided
    /// (`provide_zone_key_store`). Relay callbacks run without a reactive
    /// owner, so `use_context` there returns `None`: eviction must reach the
    /// decrypt cache through this handle, never a context lookup.
    zone_keys: StoredValue<Option<crate::zone_crypto::store::ZoneKeyStore>>,
    /// True message totals per channel (see [`ChannelTotal`]).
    totals: RwSignal<HashMap<String, ChannelTotal>>,
    /// Topic lists: list key (`topic_key`) -> (channel id, topic root id,
    /// lower-case). A topic is paged on its own (`#e:[root]`, sealed replies
    /// carry the root as an outer `reply` tag) into its own list and window.
    topic_targets: StoredValue<HashMap<String, (String, String)>>,
    /// Topic-root lists: list key (`roots_key`) -> channel id. Filled by
    /// one `{"#t":["topic"],"#e":[channel]}` REQ per channel; not windowed.
    roots_targets: StoredValue<HashMap<String, String>>,
    /// Channels whose root list has been answered (reactive).
    roots_answered: RwSignal<HashSet<String>>,
    /// Channels whose last root-list request failed (timed out, or refused
    /// by the relay after its retry) and has not answered since. Its target
    /// is cleared, so a later request past the backoff asks again.
    roots_failed: RwSignal<HashSet<String>>,
    /// Root-list key -> its failure backoff ([`RootsBackoff`]): a failed
    /// root list is not asked again before its `retry_at`, however often a
    /// view asks, except on a new visit ([`Self::rearm_topic_roots`]).
    roots_backoff: StoredValue<HashMap<String, RootsBackoff>>,
    /// Channels whose root list came back under its limit: every marked
    /// topic root is held, so channel history paging lists no new topic.
    roots_complete: RwSignal<HashSet<String>>,
    /// Newest reply per topic as the relay answers it (`#e:[root]`,
    /// `limit:1`): lower-case root id -> (created_at, author). Only opened
    /// replies count (a still-locked envelope names the migrator, not the
    /// author). Reactive; feeds the section list's "last by" / activity.
    topic_latest: RwSignal<HashMap<String, (u64, String)>>,
    /// Topic stats (exact reply COUNT + newest reply) already asked for or
    /// queued, by lower-case root id: once per session.
    topic_stats_asked: StoredValue<HashSet<String>>,
    /// Topics waiting for their stats: (channel id, lower-case root, gated).
    topic_stats_queue: StoredValue<std::collections::VecDeque<(String, String, bool)>>,
    /// Whether a stats batch is in flight (batches go one at a time).
    topic_stats_busy: StoredValue<bool>,
    /// What each `ensure_subscribed` REQ delivered by its receipts, so the
    /// page that knows whether the channel is gated can record its first
    /// page ([`ChannelStore::settle_first_page`]).
    first_pages: StoredValue<HashMap<String, FirstPageSnapshot>>,
    /// Section stats (ADR-2038) per channel id: pending, answered or failed
    /// for this visit (reactive). Cleared per visit by
    /// [`ChannelStore::rearm_section_stats`].
    section_stats: RwSignal<HashMap<String, SectionStatsState>>,
    /// Request generation per channel id, so an answer or timeout of an
    /// earlier request never settles a later one.
    section_stats_gen: StoredValue<HashMap<String, u64>>,
}

/// Deliveries of a channel's `ensure_subscribed` REQ, snapshotted at its
/// first receipt and at its first authenticated receipt.
#[derive(Clone, Copy, Debug, Default)]
struct FirstPageSnapshot {
    delivered: u64,
    oldest: Option<u64>,
    any: Option<PageOutcome>,
    authed: Option<PageOutcome>,
}

impl ChannelStore {
    fn new() -> Self {
        // Hydrate from localStorage cache for instant render
        let cached = Self::load_cache();
        let has_cache = !cached.channels.is_empty();
        let deletions = deletion_sync::load(DeletionScope::Channels);
        let tombstones = Tombstones::from_persisted(&[&deletions.sealed, &deletions.held]);

        let store = Self {
            channels: RwSignal::new(cached.channels),
            last_active: RwSignal::new(cached.last_active),
            channel_messages: RwSignal::new(HashMap::new()),
            // If we have cache, don't show loading — render immediately
            loading: RwSignal::new(!has_cache),
            eose_received: RwSignal::new(false),
            msg_eose_received: RwSignal::new(false),
            channel_receipt: RwSignal::new(SyncReceipt::default()),
            history_receipts: RwSignal::new(HashMap::new()),
            sub_id: RwSignal::new(None),
            msg_sub_id: RwSignal::new(None),
            ensured: RwSignal::new(HashSet::new()),
            meta_updated_at: RwSignal::new(cached.meta_updated_at),
            pending_meta: RwSignal::new(HashMap::new()),
            tombstones: RwSignal::new(tombstones),
            signer_admin: SignerAdminCache::new(),
            deletion_progress: StoredValue::new(DeletionProgress::new(deletions)),
            history: RwSignal::new(HashMap::new()),
            window_max: configured_window(),
            thread_window_max: configured_thread_window(),
            zone_keys: StoredValue::new(None),
            totals: RwSignal::new(HashMap::new()),
            topic_targets: StoredValue::new(HashMap::new()),
            roots_targets: StoredValue::new(HashMap::new()),
            roots_answered: RwSignal::new(HashSet::new()),
            roots_failed: RwSignal::new(HashSet::new()),
            roots_backoff: StoredValue::new(HashMap::new()),
            roots_complete: RwSignal::new(HashSet::new()),
            topic_latest: RwSignal::new(HashMap::new()),
            topic_stats_asked: StoredValue::new(HashSet::new()),
            topic_stats_queue: StoredValue::new(std::collections::VecDeque::new()),
            topic_stats_busy: StoredValue::new(false),
            first_pages: StoredValue::new(HashMap::new()),
            section_stats: RwSignal::new(HashMap::new()),
            section_stats_gen: StoredValue::new(HashMap::new()),
        };
        store.prune_on_admin_answers();
        store
    }

    /// When the relay vouches for a new admin, drop the restored sealed
    /// originals that admin's held tombstones now hide. Tracks only the admin
    /// answers: messages and tombstones are read untracked, so an insertion
    /// does not re-run this over everything.
    fn prune_on_admin_answers(&self) {
        let store = *self;
        Effect::new(move |_| {
            store.signer_admin.track();
            let zone_keys = crate::zone_crypto::store::try_use_zone_key_store();
            let admin = store.signer_admin;
            let is_sealed = |id: &str| is_restored_original(zone_keys, id);
            let sealed = store.channel_messages.with_untracked(|m| {
                store
                    .tombstones
                    .with_untracked(|t| tombstones::sealed_with_tombstones(m, t, is_sealed))
            });
            store.resolve_persisted(&sealed);
            store.channel_messages.maybe_update(|m| {
                store.tombstones.with_untracked(|t| {
                    tombstones::prune(
                        m,
                        t,
                        |id| is_restored_original(zone_keys, id),
                        |d| admin.is_admin_untracked(d),
                    )
                })
            });
        });
    }

    /// Apply one kind-5 from `deleter` to the stored messages; see
    /// [`tombstones::fold_deletion`]. When it names a restored sealed
    /// original by someone else, ask the relay whether `deleter` is an admin;
    /// the answer re-runs [`Self::prune_on_admin_answers`].
    fn apply_deletion(&self, zone_keys: Option<ZoneKeyStore>, deleter: &str, targets: &[String]) {
        let admin = self.signer_admin;
        let tombstones_sig = self.tombstones;
        let is_sealed = |id: &str| is_restored_original(zone_keys, id);
        let mut ask = false;
        let mut sealed_targets = Vec::new();
        self.channel_messages.update(|m| {
            ask = tombstones::needs_admin_answer(m, deleter, targets, is_sealed);
            sealed_targets = tombstones::sealed_named(m, targets, is_sealed);
            tombstones_sig.update(|t| {
                tombstones::fold_deletion(m, t, deleter, targets, is_sealed, |d| {
                    admin.is_admin_untracked(d)
                });
            });
        });
        if ask {
            admin.request([deleter]);
        }
        self.resolve_persisted(&sealed_targets);
    }

    /// These `(id, author)` messages are restored sealed originals: resolve
    /// the held tombstones on them (promote honoured, drop refused; see
    /// [`deletion_sync::resolve_sealed`]) and persist if anything changed.
    /// Saving here, outside EOSE, writes the last settled marker, so it never
    /// advances the marker early.
    fn resolve_persisted(&self, sealed: &[(String, String)]) {
        if sealed.is_empty() {
            return;
        }
        let admin = self.signer_admin;
        let mut changed = false;
        self.deletion_progress.update_value(|p| {
            for (id, author) in sealed {
                changed |= deletion_sync::resolve_sealed(&mut p.state, id, author, |d| {
                    admin.answer_untracked(d)
                });
            }
        });
        if changed {
            deletion_sync::persist(DeletionScope::Channels, self.deletion_progress);
        }
    }

    /// Optimistically tombstone + remove a message by id.
    ///
    /// Used by the delete UI so the actor doesn't wait on the relay echo; it is
    /// idempotent with the kind-5 fold that runs when the deletion broadcast
    /// arrives ([`tombstones::fold_deletion`]).
    pub fn remove_message(&self, event_id: &str) {
        let deleted = [event_id.to_lowercase()];
        let tombstones_sig = self.tombstones;
        self.channel_messages.update(|m| {
            tombstones_sig.update(|t| {
                // The reader's own action: honoured whatever the message is.
                tombstones::fold_deletion(m, t, LOCAL_DELETER, &deleted, |_| false, |_| false);
            });
        });
    }

    /// Whether `event` may be shown: the single admission predicate for every
    /// way a kind-42 gets in (ADR-092): the broad subscription,
    /// `ensure_subscribed` and the deep-link replay in
    /// `pages::ChannelPage`.
    ///
    /// Call it on the event as delivered (an envelope id is never a restored
    /// original, so the ordinary rule applies) and again after
    /// `zone_crypto::store::prepare_incoming` (a restored sealed original
    /// carries the original's id and author, and only that author or a
    /// relay-vouched admin may hide it; see [`tombstones`]).
    ///
    /// Untracked: it gates an insert inside an event callback, and subscribing
    /// that callback to the tombstone signal would be a reactive cycle.
    pub fn admits_message(&self, zone_keys: Option<ZoneKeyStore>, event: &NostrEvent) -> bool {
        self.admits_as(event, is_restored_original(zone_keys, &event.id))
    }

    /// [`Self::admits_message`] for an original the read path has just
    /// restored from its envelope. Used by the in-place restore after a zone
    /// key arrives, which runs inside the zone store's own cache update and
    /// so must not query that store again.
    pub fn admits_restored_original(&self, inner: &NostrEvent) -> bool {
        self.admits_as(inner, true)
    }

    fn admits_as(&self, event: &NostrEvent, sealed: bool) -> bool {
        let target = Target::of(event, sealed);
        let admin = self.signer_admin;
        let (admitted, to_verify) = self.tombstones.with_untracked(|t| {
            (
                tombstones::admits(t, &event.id, target, |d| admin.is_admin_untracked(d)),
                tombstones::deleters_to_verify(t, &event.id, target),
            )
        });
        // Shown for now; if the relay vouches for one of these deleters as an
        // admin, `prune_on_admin_answers` removes it.
        if admitted && !to_verify.is_empty() {
            admin.request(to_verify.iter().map(String::as_str));
        }
        // A tombstone that landed before its target: now the target is known
        // to be a sealed original, resolve what is held on it.
        if sealed && self.tombstones.with_untracked(|t| t.names(&event.id)) {
            self.resolve_persisted(&[(event.id.to_lowercase(), event.pubkey.to_lowercase())]);
        }
        admitted
    }

    // -- Derived count accessors (ADR-091) ------------------------------------

    /// Post count for a single channel, derived from deduped event Vec.
    /// Reactive: re-runs when `channel_messages` changes.
    pub fn count_for(&self, cid: &str) -> u32 {
        self.channel_messages
            .with(|m| m.get(cid).map(|v| v.len() as u32).unwrap_or(0))
    }

    /// The channel's true message count (see [`ChannelTotal`]): the relay's
    /// count plus what arrived since, never less than what the store holds
    /// (which, with the history window, may be a fraction of the channel).
    /// Falls back to [`Self::count_for`] until [`Self::request_total`] has
    /// an answer. Reactive.
    pub fn total_for(&self, cid: &str) -> u32 {
        let held = self.count_for(cid);
        let total = self
            .totals
            .with(|m| m.get(cid).and_then(ChannelTotal::total));
        total.map_or(held, |t| (t.min(u32::MAX as u64) as u32).max(held))
    }

    /// Ask the relay for channel `cid`'s message count, once per session
    /// (`{"kinds":[42], "#e":[cid], "until": now}`, answered by the relay's
    /// exact single-channel COUNT). Messages newer than that are added as
    /// they are inserted ([`Self::note_inserted`]).
    pub fn request_total(&self, relay: &RelayConnection, cid: &str) {
        self.request_total_of(relay, cid, cid);
    }

    /// [`Self::request_total`] for list `key` counted by `#e:[value]`: a
    /// topic list (`topic_key(root)`) is counted by its root, which sealed
    /// replies carry as an outer `reply` tag (the relay gates the count by
    /// each reply's channel).
    pub fn request_total_of(&self, relay: &RelayConnection, key: &str, value: &str) {
        let cid = key;
        if self.totals.with_untracked(|m| m.contains_key(cid)) {
            return;
        }
        let as_of = (js_sys::Date::now() / 1000.0) as u64;
        self.totals.update(|m| {
            m.insert(
                cid.to_string(),
                ChannelTotal {
                    counted: None,
                    as_of,
                    newer_ids: HashSet::new(),
                },
            );
        });
        let totals = self.totals;
        let key = cid.to_string();
        relay.count(
            vec![Filter {
                kinds: Some(vec![42]),
                e_tags: Some(vec![value.to_string()]),
                until: Some(as_of),
                ..Default::default()
            }],
            // May answer twice (before and after AUTH); the later, authorised
            // answer is the complete one and replaces the first.
            Rc::new(move |n: u64| {
                let _ = totals.try_update(|m| {
                    if let Some(t) = m.get_mut(&key) {
                        t.counted = Some(n);
                    }
                });
            }),
        );
    }

    /// Record a message newly inserted into channel `cid`'s list for its
    /// true total (only messages newer than the count matter).
    pub fn note_inserted(&self, cid: &str, id: &str, created_at: u64) {
        let newer = self.totals.with_untracked(|m| {
            m.get(cid)
                .is_some_and(|t| created_at > t.as_of && !t.newer_ids.contains(id))
        });
        if newer {
            self.totals.update(|m| {
                if let Some(t) = m.get_mut(cid) {
                    t.newer_ids.insert(id.to_string());
                }
            });
        }
    }

    /// Newest message per channel as `(channel_id, event_id, created_at)`.
    ///
    /// The read model is timestamp-based (see `stores::read_position`), so
    /// "mark everything read" means stamping each channel's read position at
    /// its newest message — this is the input for that bulk stamp. Channels
    /// with no loaded messages fall back to `last_active` (with an empty
    /// event id) so a badge computed from the cached activity map also clears.
    pub fn latest_message_per_channel(&self) -> Vec<(String, String, u64)> {
        let mut out: HashMap<String, (String, u64)> = HashMap::new();
        self.channel_messages.with_untracked(|m| {
            for (cid, events) in m.iter() {
                if let Some(ev) = events.iter().max_by_key(|e| e.created_at) {
                    out.insert(cid.clone(), (ev.id.clone(), ev.created_at));
                }
            }
        });
        self.last_active.with_untracked(|m| {
            for (cid, ts) in m.iter() {
                out.entry(cid.clone()).or_insert((String::new(), *ts));
            }
        });
        out.into_iter()
            .map(|(cid, (eid, ts))| (cid, eid, ts))
            .collect()
    }

    fn load_cache() -> CachedData {
        let json: Result<String, _> = LocalStorage::get(CACHE_KEY);
        let mut data: CachedData = json
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        heal_cached_sections(&mut data.channels, &crate::stores::zones::load_zones());
        data
    }

    fn save_cache(&self) {
        let data = CachedData {
            // ADR-2037: `section` is cached as the raw tag, so a cache read by
            // a build without pin support routes as it always did.
            channels: self
                .channels
                .get_untracked()
                .into_iter()
                .map(ChannelMeta::cache_form)
                .collect(),
            last_active: self.last_active.get_untracked(),
            meta_updated_at: self.meta_updated_at.get_untracked(),
            synced_at: (js_sys::Date::now() / 1000.0) as u64,
        };
        if let Ok(json) = serde_json::to_string(&data) {
            let _ = LocalStorage::set(CACHE_KEY, json);
        }
    }

    /// Start relay subscriptions. Called once from App root after relay connects.
    pub fn start_sync(&self, relay: &RelayConnection) {
        // ADR-2038: the section stats check reads the relay's NIP-11
        // document; fetch it now so the first section visit does not wait.
        crate::relay::info::prefetch();
        if self.sub_id.get_untracked().is_some() {
            return;
        }

        let channels_sig = self.channels;
        let meta_ts_sig = self.meta_updated_at;
        let pending_meta_sig = self.pending_meta;
        let deletion_progress = self.deletion_progress;
        let zone_keys = crate::zone_crypto::store::try_use_zone_key_store();
        let loading_sig = self.loading;
        let eose_sig = self.eose_received;
        let channel_receipt_sig = self.channel_receipt;
        let store = *self;

        // Track which channel IDs came from the relay (vs stale cache)
        let relay_ids = Rc::new(std::cell::RefCell::new(HashSet::<String>::new()));
        let relay_ids_for_event = relay_ids.clone();

        // Kind 5: NIP-09 deletion — removes the target post and tombstones its
        // id. Shared by this subscription and its deletion pages.
        let on_kind5: deletion_sync::Kind5Handler =
            Rc::new(move |event: NostrEvent, source: Source| {
                let deleted = deletion_targets(&event);
                let deleter = event.pubkey.to_lowercase();
                // Every kind-5 counts towards the marker, even one with no
                // `e` target: the marker tracks what the relay delivered.
                let now = deletion_sync::now_secs();
                deletion_progress.update_value(|p| {
                    p.observe(event.created_at, &deleter, &deleted, true, now, source);
                });
                if !deleted.is_empty() {
                    store.apply_deletion(zone_keys, &deleter, &deleted);
                }
            });
        let on_kind5_main = on_kind5.clone();

        // Kind 40: channel creation. Kind 41: channel metadata edit (admin
        // rename) — folded last-write-wins; pin/unpin control 41s are ignored
        // (they carry empty content, so [`parse_meta_update`] returns `None`).
        let on_event = Rc::new(move |event: NostrEvent| {
            match event.kind {
                40 => {
                    relay_ids_for_event.borrow_mut().insert(event.id.clone());

                    let (name, description, picture) = parse_channel_content(&event.content);
                    let section = event
                        .tags
                        .iter()
                        .find(|t| t.len() >= 2 && t[0] == "section")
                        .map(|t| t[1].clone())
                        .unwrap_or_default();

                    let meta = ChannelMeta {
                        id: event.id.clone(),
                        name,
                        description,
                        section: crate::stores::zones::effective_section(
                            &event.id,
                            &section,
                            &crate::stores::zones::load_zones(),
                        ),
                        section_tag: section,
                        picture,
                        created_at: event.created_at,
                    };

                    // Notifies only when the channel is new: a cached
                    // channel the relay re-sends (every reconnect and AUTH
                    // replay) changes nothing a page could show.
                    let mut inserted = false;
                    channels_sig.maybe_update(|list| {
                        inserted = push_channel_if_new(list, meta);
                        inserted
                    });

                    // Apply any edit that outran this creation on the wire.
                    if inserted {
                        let mut pending = None;
                        pending_meta_sig.update(|p| pending = p.remove(&event.id));
                        if let Some(update) = pending {
                            channels_sig.update(|list| {
                                meta_ts_sig.update(|ts| {
                                    fold_meta_into(list, ts, &update);
                                });
                            });
                        }
                    }
                }
                41 => {
                    if let Some(update) = parse_meta_update(&event) {
                        let mut applied = false;
                        channels_sig.update(|list| {
                            meta_ts_sig.update(|ts| {
                                applied = fold_meta_into(list, ts, &update);
                            });
                        });
                        // Channel not known yet — buffer until its kind-40 lands.
                        if !applied {
                            pending_meta_sig.update(|p| buffer_pending_meta(p, update));
                        }
                    }
                }
                5 => on_kind5_main(event, Source::Main),
                _ => {}
            }
        });

        let store_for_eose = store;
        let relay_for_eose = relay.clone();
        // `authed` comes from the relay's per-subscription REQ ledger: true only
        // when this answer cannot be the anonymous pre-AUTH one.
        let on_eose = Rc::new(move |authed: bool| {
            // Prune channels that were in the cache but NOT received from relay
            // (they were deleted or the DB was wiped)
            let ids = relay_ids.borrow();
            if ids.is_empty() {
                // Empty EOSE. Only trust it as "the relay has no channels" when
                // there is nothing displayed to lose. If channels are already
                // shown (from cache or a prior sync), an empty EOSE is almost
                // always a transient artifact — a cold/reconnecting relay DO that
                // EOSEs before (re)delivering its stored kind-40s — and wiping
                // them here is the "panels flicker/disappear" bug. Keep them: real
                // deletions still arrive as kind-5 tombstones (handled above), and
                // a genuine reset is reconciled on a fresh reload. Counts are
                // derived from channel_messages (ADR-091).
                if channels_sig.get_untracked().is_empty() {
                    channels_sig.set(Vec::new());
                    store_for_eose.channel_messages.set(HashMap::new());
                    store_for_eose.last_active.set(HashMap::new());
                    store_for_eose.meta_updated_at.set(HashMap::new());
                    // Keep the persisted tombstones: their kind-5s may lie
                    // below the marker and would not be fetched again.
                    store_for_eose
                        .tombstones
                        .set(deletion_progress.with_value(|p| {
                            Tombstones::from_persisted(&[&p.state.sealed, &p.state.held])
                        }));
                }
            } else {
                // Notifies only when a channel was actually pruned.
                channels_sig.maybe_update(|list| retain_relay_channels(list, &ids));
                // Drop edit timestamps for pruned channels so the cache stays
                // in step with the live channel set.
                store_for_eose
                    .meta_updated_at
                    .update(|m| m.retain(|id, _| ids.contains(id)));
            }
            loading_sig.set(false);
            eose_sig.set(true);
            // After the prune above, so a page reading the receipt never sees
            // "settled" alongside a channel list that is about to change.
            channel_receipt_sig.update(|r| r.record(authed));
            // Cache the pruned result
            store_for_eose.save_cache();
            // EOSE ends the kind-5 backfill: settle the marker, or page down
            // when a marked filter hit the row cap (see `deletion_sync`). A
            // sync cut off before it settles writes nothing.
            let now = deletion_sync::now_secs();
            let action = deletion_progress
                .try_update_value(|p| p.on_main_eose(now))
                .unwrap_or(deletion_sync::EoseAction::Ignore);
            deletion_sync::drive(
                &relay_for_eose,
                DeletionScope::Channels,
                deletion_progress,
                on_kind5.clone(),
                action,
            );
        });

        // kind-40 = channel creation, kind-41 = metadata edit (rename),
        // kind-5 = post deletion (NIP-09). Separate filters: see
        // `channel_sync_filters`.
        let since = deletion_progress.with_value(|p| p.state.since);
        let id = relay.subscribe_with_receipt(channel_sync_filters(since), on_event, on_eose);
        self.sub_id.set(Some(id));

        // Loading timeout fallback
        let loading_timeout = loading_sig;
        let store_for_timeout = store;
        let cb = wasm_bindgen::closure::Closure::once(move || {
            if loading_timeout.get_untracked() {
                loading_timeout.set(false);
            }
            store_for_timeout.save_cache();
        });
        if let Some(window) = web_sys::window() {
            let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                cb.as_ref().unchecked_ref(),
                6000,
            );
        }
        cb.forget();
    }

    /// Start message count subscription (called after channel EOSE).
    ///
    /// Uses a BROAD kind-42 subscription (no e_tags filter) because legacy
    /// relay data tags messages with slugs or section names instead of the
    /// kind-40 event id. Client-side resolution matches each event's root
    /// `e` tag value against channel id, name, and section.
    ///
    /// ADR-092: the resolver re-reads `channels` *for every event* so that
    /// channels which arrive later (e.g. via `ChannelPage`'s direct kind-40
    /// fetch on a deep-link, or a delayed broadcast) can still claim their
    /// historical kind-42 events. The previous implementation captured the
    /// lookup maps at subscribe time and silently dropped any event whose
    /// channel wasn't yet known.
    pub fn start_msg_sync(&self, relay: &RelayConnection) {
        if self.msg_sub_id.get_untracked().is_some() {
            return;
        }

        let channels = self.channels.get_untracked();
        if channels.is_empty() {
            return;
        }
        // Readiness may have been granted early for an empty relay (see
        // `history_known_empty`). Channels now exist, so their history is
        // unseen until this subscription's own EOSE: withdraw it.
        self.msg_eose_received.set(false);

        let channels_sig = self.channels;
        let last_active = self.last_active;
        let channel_msgs = self.channel_messages;
        let store = *self;
        let zone_keys = crate::zone_crypto::store::try_use_zone_key_store();

        let on_msg = Rc::new(move |event: NostrEvent| {
            // Suppress a message that was already deleted — a kind-5 can land
            // before its target kind-42 in the same backfill (arrival order is
            // not guaranteed), so the tombstone is the durable gate.
            if !store.admits_message(zone_keys, &event) {
                return;
            }

            // Extract the root e-tag value (prefer explicit "root" marker)
            let tag_val = event
                .tags
                .iter()
                .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == "root")
                .or_else(|| event.tags.iter().find(|t| t.len() >= 2 && t[0] == "e"))
                .map(|t| t[1].clone());

            let tag_val = match tag_val {
                Some(v) => v,
                None => return,
            };
            let tag_lower = tag_val.to_lowercase();

            // Resolve against the CURRENT channel list. `get_untracked` so
            // we don't subscribe the outer effect to channels here — the
            // store re-emits this closure for every event, the freshness
            // comes from the inherent reactivity of the kind-42 stream.
            let resolved = channels_sig.with_untracked(|list| {
                list.iter()
                    .find(|c| {
                        c.id == tag_val
                            || c.name.to_lowercase() == tag_lower
                            || c.section.to_lowercase() == tag_lower
                    })
                    .map(|c| c.id.clone())
            });

            if let Some(cid) = resolved {
                // Not while the channel's history window is detached in older
                // history: a newer post here would open a gap; the window's
                // own reload brings it. Checked before decrypting, so a
                // dropped post leaves nothing in the decrypt cache.
                if !store.window_admits(&cid, event.created_at) {
                    return;
                }
                // Zone-encrypted messages become readable text (or a
                // placeholder) here, once, for every view (ADR-2016).
                let event = crate::zone_crypto::store::prepare_incoming(zone_keys, event);
                // Store raw event for channel page consumption. Dedup by
                // event id is the ONLY counter — ADR-091. Last-active only
                // advances when a genuinely new event is appended.
                // A restored sealed original carries the original id, which
                // a kind-5 may have tombstoned (ADR-2017); only its author
                // or a relay-vouched admin may hide it.
                if !store.admits_message(zone_keys, &event) {
                    return;
                }
                let mut newly_added = false;
                let event_ts = event.created_at;
                let event_id = event.id.clone();
                let topic = reply_topic(&event);
                channel_msgs.update(|m| {
                    let events = m.entry(cid.clone()).or_insert_with(Vec::new);
                    newly_added = insert_message(events, event);
                });
                if newly_added {
                    store.note_inserted(&cid, &event_id, event_ts);
                    // A live reply grows its topic's total too (seeded by the
                    // section stats or a COUNT), so the row's count moves.
                    if let Some(root) = topic {
                        store.note_inserted(&topic_key(&root), &event_id, event_ts);
                    }
                    last_active.update(|m| {
                        let ts = m.entry(cid).or_insert(0);
                        if event_ts > *ts {
                            *ts = event_ts;
                        }
                    });
                }
            }
        });

        let store_for_eose = store;
        let msg_eose_sig = self.msg_eose_received;
        let on_msg_eose = Rc::new(move || {
            msg_eose_sig.set(true);
            store_for_eose.save_cache();
        });

        // One filter per zone's known channels plus a broad catch-all, so no
        // zone's history crowds out another's: see `message_sync_filters`.
        let zones = crate::stores::zones::load_zones();
        let known: Vec<(String, String)> = channels
            .iter()
            .map(|c| (c.id.clone(), c.section.clone()))
            .collect();
        let id = relay.subscribe(
            message_sync_filters(&known, &zones),
            on_msg,
            Some(on_msg_eose),
        );
        self.msg_sub_id.set(Some(id));
    }

    /// Resolve a slug, section name, or hex id to a concrete channel id.
    /// Returns None if the channel list has no matching entry yet.
    pub fn resolve_channel(&self, cid_or_slug: &str) -> Option<String> {
        let needle_lower = cid_or_slug.to_lowercase();
        self.channels.with(|list| {
            list.iter()
                .find(|c| {
                    c.id == cid_or_slug
                        || c.name.to_lowercase() == needle_lower
                        || c.section.to_lowercase() == needle_lower
                })
                .map(|c| c.id.clone())
        })
    }

    /// EOSE receipts for the [`ensure_subscribed`](Self::ensure_subscribed)
    /// history query opened for `cid_or_slug` (the default when none has
    /// arrived yet, or none was opened). Reactive.
    pub fn history_receipt(&self, cid_or_slug: &str) -> SyncReceipt {
        self.history_receipts
            .with(|m| m.get(cid_or_slug).copied().unwrap_or_default())
    }

    /// Idempotent per-channel narrow subscription (ADR-092).
    ///
    /// Called from `ChannelPage::on_mount` so direct deep-links boot their
    /// own data instead of waiting for the global `start_msg_sync` chain.
    /// Safe to call repeatedly: the `ensured` set guards against duplicate
    /// REQs.
    pub fn ensure_subscribed(&self, relay: &RelayConnection, cid_or_slug: &str) {
        if cid_or_slug.is_empty() {
            return;
        }
        let key = cid_or_slug.to_string();
        if self.ensured.with_untracked(|s| s.contains(&key)) {
            return;
        }
        self.ensured.update(|s| {
            s.insert(key.clone());
        });

        // Resolve to a concrete id when possible — fall back to using the
        // raw value (the relay accepts either: kind-42 events may carry
        // slug-style e-tags from legacy data).
        let needle = self.resolve_channel(cid_or_slug).unwrap_or(key.clone());

        let last_active = self.last_active;
        let channel_msgs = self.channel_messages;
        let store = *self;
        let zone_keys = crate::zone_crypto::store::try_use_zone_key_store();

        let first_pages = self.first_pages;
        let key_for_count = key.clone();
        let on_event = Rc::new(move |event: NostrEvent| {
            // Count every delivery before admission: a page is short (the
            // start of history) only by what the relay sent.
            let ts = event.created_at;
            first_pages.update_value(|m| {
                let s = m.entry(key_for_count.clone()).or_default();
                s.delivered += 1;
                s.oldest = Some(s.oldest.map_or(ts, |o| o.min(ts)));
            });
            if event.kind != 42 {
                return;
            }
            // Skip messages already deleted via kind-5 (see `start_msg_sync`).
            if !store.admits_message(zone_keys, &event) {
                return;
            }
            // Re-resolve here as well in case channel metadata arrived after
            // this subscription was opened.
            let tag_val = event
                .tags
                .iter()
                .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == "root")
                .or_else(|| event.tags.iter().find(|t| t.len() >= 2 && t[0] == "e"))
                .map(|t| t[1].clone());
            let cid = match tag_val {
                Some(v) => v,
                None => return,
            };
            // As in `start_msg_sync`: nothing newer than a detached window.
            if !store.window_admits(&cid, event.created_at) {
                return;
            }
            let event = crate::zone_crypto::store::prepare_incoming(zone_keys, event);
            // A restored sealed original carries the original id (ADR-2017).
            if !store.admits_message(zone_keys, &event) {
                return;
            }
            let mut newly_added = false;
            let event_ts = event.created_at;
            let event_id = event.id.clone();
            let topic = reply_topic(&event);
            channel_msgs.update(|m| {
                let events = m.entry(cid.clone()).or_insert_with(Vec::new);
                newly_added = insert_message(events, event);
            });
            if newly_added {
                store.note_inserted(&cid, &event_id, event_ts);
                // A live reply grows its topic's total too (seeded by the
                // section stats or a COUNT), so the row's count moves.
                if let Some(root) = topic {
                    store.note_inserted(&topic_key(&root), &event_id, event_ts);
                }
                last_active.update(|m| {
                    let ts = m.entry(cid).or_insert(0);
                    if event_ts > *ts {
                        *ts = event_ts;
                    }
                });
            }
        });

        // Fires once for the first answer and again for the post-AUTH replay
        // of this same subscription; `authed` (from the relay's REQ ledger)
        // keeps the anonymous answer from counting for a gated zone.
        let history_receipts = self.history_receipts;
        let on_eose = Rc::new(move |authed: bool| {
            first_pages.update_value(|m| {
                let s = m.entry(key.clone()).or_default();
                let page = PageOutcome {
                    delivered: s.delivered,
                    oldest: s.oldest,
                };
                s.any.get_or_insert(page);
                if authed {
                    s.authed.get_or_insert(page);
                }
            });
            history_receipts.update(|m| m.entry(key.clone()).or_default().record(authed));
        });

        let _ = relay.subscribe_with_receipt(
            vec![Filter {
                kinds: Some(vec![42]),
                e_tags: Some(vec![needle]),
                limit: Some(HISTORY_PAGE),
                ..Default::default()
            }],
            on_event,
            on_eose,
        );
    }

    // -- Paged history -----------------------------------------------------

    /// The paged-history state of channel `cid`. Reactive.
    pub fn history_cursor(&self, cid: &str) -> HistoryCursor {
        self.history
            .with(|m| m.get(cid).cloned().unwrap_or_default())
    }

    /// Record channel `cid`'s first page from its `ensure_subscribed` REQ
    /// once the answer counts: the authenticated one for a `gated` zone,
    /// else the first (the rule of `SyncReceipt::settles`). Idempotent; a
    /// no-op until that receipt is in.
    pub fn settle_first_page(&self, cid: &str, gated: bool) {
        let page = self.first_pages.with_value(|m| {
            m.get(cid)
                .and_then(|s| if gated { s.authed } else { s.any })
        });
        if let Some(page) = page {
            self.record_first_page(cid, page);
        }
    }

    /// Record the channel's newest page (the channel page's first kind-42
    /// REQ, `limit` [`HISTORY_PAGE`]) once its authoritative answer is in.
    /// A channel already paged this session keeps its cursor, so re-opening
    /// it does not walk back over pages already held.
    pub fn record_first_page(&self, cid: &str, page: PageOutcome) {
        self.history.update(|m| {
            let c = m.entry(cid.to_string()).or_default();
            if !c.started {
                c.record_first(page);
            }
        });
    }

    /// Admit, place and decrypt one delivered kind-42, exactly as every other
    /// history path does: the kind-5 gate on the delivered event, channel
    /// resolution by its root `e` tag (falling back to `fallback_cid`),
    /// `prepare_incoming`, then the gate again on what it became (a restored
    /// sealed original carries the original's id, ADR-2017). `None` when the
    /// event is not to be shown.
    pub fn ingest(
        &self,
        zone_keys: Option<ZoneKeyStore>,
        event: NostrEvent,
        fallback_cid: &str,
    ) -> Option<(String, NostrEvent)> {
        if event.kind != 42 || !self.admits_message(zone_keys, &event) {
            return None;
        }
        let tag_val = event
            .tags
            .iter()
            .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == "root")
            .or_else(|| event.tags.iter().find(|t| t.len() >= 2 && t[0] == "e"))
            .map(|t| t[1].clone())?;
        let tag_lower = tag_val.to_lowercase();
        let cid = self
            .channels
            .with_untracked(|list| {
                list.iter()
                    .find(|c| {
                        c.id == tag_val
                            || c.name.to_lowercase() == tag_lower
                            || c.section.to_lowercase() == tag_lower
                    })
                    .map(|c| c.id.clone())
            })
            .unwrap_or_else(|| fallback_cid.to_string());
        let event = crate::zone_crypto::store::prepare_incoming(zone_keys, event);
        if !self.admits_message(zone_keys, &event) {
            return None;
        }
        Some((cid, event))
    }

    /// Insert a batch of ingested messages in ONE store update (a page of
    /// 100 would otherwise notify every subscriber 100 times), advancing
    /// each channel's last activity for genuinely new messages.
    ///
    /// Messages the channel's history window does not hold
    /// ([`HistoryCursor::admits`]: newer than the window while it is detached
    /// from the newest) are dropped, and their decrypt-cache entries with
    /// them; the window's own reload brings them back in order.
    pub fn apply_page(&self, events: Vec<(String, NostrEvent)>) {
        if events.is_empty() {
            return;
        }
        let (events, refused): (Vec<_>, Vec<_>) = events
            .into_iter()
            .partition(|(cid, ev)| self.window_admits(cid, ev.created_at));
        if !refused.is_empty() {
            let ids: Vec<String> = refused.into_iter().map(|(_, ev)| ev.id).collect();
            if let Some(z) = self.zone_store() {
                z.forget(&ids);
            }
        }
        if events.is_empty() {
            return;
        }
        let mut newest: HashMap<String, u64> = HashMap::new();
        let mut inserted: Vec<(String, String, u64, Option<String>)> = Vec::new();
        self.channel_messages.update(|m| {
            for (cid, ev) in events {
                let ts = ev.created_at;
                let id = ev.id.clone();
                let topic = reply_topic(&ev);
                if insert_message(m.entry(cid.clone()).or_default(), ev) {
                    inserted.push((cid.clone(), id, ts, topic));
                    let n = newest.entry(cid).or_insert(0);
                    *n = (*n).max(ts);
                }
            }
        });
        for (cid, id, ts, topic) in inserted {
            self.note_inserted(&cid, &id, ts);
            // A reply also grows its topic's exact total (the section list
            // shows it), however it arrived: live, a channel page, or the
            // topic's own list. `note_inserted` dedups by id.
            if let Some(root) = topic {
                let key = topic_key(&root);
                if key != cid {
                    self.note_inserted(&key, &id, ts);
                }
            }
        }
        if !newest.is_empty() {
            self.last_active.update(|m| {
                for (cid, ts) in newest {
                    let cur = m.entry(cid).or_insert(0);
                    if ts > *cur {
                        *cur = ts;
                    }
                }
            });
        }
    }

    /// Sizes of the per-id collections (`alloc-stats` diagnostics).
    #[cfg(feature = "alloc-stats")]
    pub fn debug_sizes(&self) -> Vec<(&'static str, usize)> {
        vec![
            (
                "channels.messages",
                self.channel_messages
                    .with_untracked(|m| m.values().map(Vec::len).sum()),
            ),
            (
                "channels.lists",
                self.channel_messages.with_untracked(HashMap::len),
            ),
            (
                "channels.segments",
                self.history
                    .with_untracked(|m| m.values().map(|c| c.newer.len()).sum()),
            ),
            (
                "channels.ensured",
                self.ensured.with_untracked(HashSet::len),
            ),
            (
                "channels.meta_updated_at",
                self.meta_updated_at.with_untracked(HashMap::len),
            ),
            (
                "channels.first_pages",
                self.first_pages.with_value(HashMap::len),
            ),
        ]
    }

    // -- Topic lists ---------------------------------------------------------

    /// Register topic `root` of `channel` for its own paged list and return
    /// the list key (also the key of its history cursor). Idempotent.
    pub fn register_topic(&self, channel: &str, root: &str) -> String {
        let key = topic_key(root);
        self.topic_targets.update_value(|m| {
            m.entry(key.clone())
                .or_insert_with(|| (channel.to_string(), root.to_lowercase()));
        });
        key
    }

    /// Where an ingested page event belongs. For a channel list, its own
    /// channel. For a topic list, the topic list, but only if the event is
    /// in the topic's channel (resolved from its root-marked channel tag,
    /// like the relay's gate) and replies to that topic: anything else a
    /// `#e:[root]` answer returns (a crafted event naming the root without
    /// being in the channel) is dropped, decrypt state and all.
    fn route_to_list(
        &self,
        key: &str,
        cid: String,
        ev: NostrEvent,
    ) -> Option<(String, NostrEvent)> {
        if let Some(channel) = self.roots_targets.with_value(|m| m.get(key).cloned()) {
            // A root list holds root-shaped messages of its channel only (a
            // sealed root still locked shows its outer marker instead).
            // The outer marker counts only on a still-locked SEALED envelope
            // (whose inner shape check 7 binds); an unsealed event must be
            // root-shaped itself, so a marker planted on a plaintext reply
            // never lists it as a topic.
            let sealed = nostr_bbs_core::sealed::parse_sealed(&ev.tags).is_some();
            let marked = sealed
                && ev.tags.iter().any(|t| {
                    t.len() == 2 && t[0] == "t" && t[1] == nostr_bbs_core::sealed::TOPIC_MARKER
                });
            let rooty = nostr_bbs_core::sealed::is_topic_root(&ev) || marked;
            if cid == channel && rooty {
                return Some((key.to_string(), ev));
            }
            if let Some(z) = self.zone_store() {
                z.forget(std::slice::from_ref(&ev.id));
            }
            return None;
        }
        let Some((channel, topic)) = self.topic_targets.with_value(|m| m.get(key).cloned()) else {
            return Some((cid, ev));
        };
        let replies_to_topic = nostr_bbs_core::sealed::reply_root_of(&ev)
            .is_some_and(|r| r.eq_ignore_ascii_case(&topic));
        if cid == channel && replies_to_topic {
            Some((key.to_string(), ev))
        } else {
            if let Some(z) = self.zone_store() {
                z.forget(std::slice::from_ref(&ev.id));
            }
            None
        }
    }

    /// Fetch channel `cid`'s topic roots once per session: one REQ
    /// `{"kinds":[42], "#t":["topic"], "#e":[cid]}` (sealed roots carry the
    /// outer marker; the relay drives it from the marker and gates it by the
    /// channel) into the unwindowed list [`roots_key`]`(cid)`. A section can
    /// then list every topic, dormant ones included, and a deep link's slug
    /// (an id prefix) is matched against it.
    ///
    /// A request that failed is only repeated when this is called again
    /// after its backoff has run out (from [`PAGE_TIMEOUT_MS`], doubling to
    /// five minutes), or after a new visit ([`Self::rearm_topic_roots`]).
    /// Nothing calls it when the backoff expires: callers re-run it on a
    /// revisit or when the channel's history changes. Views re-run it on
    /// every message, and a relay refusing subscriptions must not get two
    /// more REQs per message.
    pub fn request_topic_roots(&self, relay: &RelayConnection, cid: &str, wait_auth: bool) {
        let key = roots_key(cid);
        let fresh = self.roots_targets.with_value(|m| !m.contains_key(&key));
        let now = js_sys::Date::now();
        let backed_off = self
            .roots_backoff
            .with_value(|m| m.get(&key).is_some_and(|b| !b.may_ask(now)));
        if !fresh || backed_off {
            return;
        }
        self.roots_targets.update_value(|m| {
            m.insert(key.clone(), cid.to_string());
        });
        // A new request: the last failure no longer settles this visit's
        // root list (a board would otherwise freeze at once without it).
        if self.roots_failed.with_untracked(|s| s.contains(cid)) {
            self.roots_failed.update(|s| {
                clear_roots_failure(s, cid);
            });
        }
        let store = *self;
        let channel = cid.to_string();
        let failed_channel = cid.to_string();
        let failed_key = key.clone();
        self.one_shot_page_or_fail(
            relay,
            &key,
            Filter {
                kinds: Some(vec![42]),
                t_tags: Some(vec![nostr_bbs_core::sealed::TOPIC_MARKER.to_string()]),
                e_tags: Some(vec![cid.to_string()]),
                limit: Some(RELAY_FILTER_LIMIT),
                ..Default::default()
            },
            wait_auth,
            Box::new(move |events, page| {
                let held = !events.is_empty();
                let _ = store.roots_backoff.try_update_value(|m| {
                    m.remove(&roots_key(&channel));
                });
                // Answered after all: no longer failed.
                if store.roots_failed.with_untracked(|s| s.contains(&channel)) {
                    store.roots_failed.update(|s| {
                        s.remove(&channel);
                    });
                }
                store.apply_page(events);
                if held && page.delivered < RELAY_FILTER_LIMIT {
                    store.roots_complete.update(|s| {
                        s.insert(channel.clone());
                    });
                }
                store.roots_answered.update(|s| {
                    s.insert(channel);
                });
            }),
            Box::new(move || {
                // Unanswered: forget the target and back off, so a later
                // call past the backoff (or a revisit) asks again, and
                // record the failure (a page must not wait on an answer
                // that will never come).
                let now = js_sys::Date::now();
                let _ = store.roots_backoff.try_update_value(|m| {
                    m.entry(failed_key.clone()).or_default().failed(now);
                });
                let _ = store.roots_targets.try_update_value(|m| {
                    m.remove(&failed_key);
                });
                let _ = store.roots_failed.try_update(|s| {
                    s.insert(failed_channel);
                });
            }),
        );
    }

    /// A new visit to channel `cid`'s list (a page mounted, or switched to
    /// this channel): a root list that failed may be asked again at once,
    /// whatever its backoff. Call it once per visit, never from an effect
    /// that re-runs on traffic.
    pub fn rearm_topic_roots(&self, cid: &str) {
        let key = roots_key(cid);
        self.roots_backoff.update_value(|m| {
            if let Some(b) = m.get_mut(&key) {
                b.rearm();
            }
        });
    }

    /// Whether channel `cid`'s last root-list request failed (no answer
    /// within [`PAGE_TIMEOUT_MS`], or refused after its retry), and neither
    /// an answer nor a new request has come since. A later
    /// [`Self::request_topic_roots`] past the backoff, or on a revisit,
    /// asks again (and clears this). Reactive.
    pub fn topic_roots_failed(&self, cid: &str) -> bool {
        self.roots_failed.with(|s| s.contains(cid))
    }

    /// Whether channel `cid`'s root list is complete: answered under its
    /// limit with at least one root, so the section's topics are all listed
    /// and paging the channel's history adds none. Reactive.
    pub fn topic_roots_complete(&self, cid: &str) -> bool {
        self.roots_complete.with(|s| s.contains(cid))
    }

    /// Whether channel `cid`'s root list has been answered. Reactive.
    pub fn topic_roots_answered(&self, cid: &str) -> bool {
        self.roots_answered.with(|s| s.contains(cid))
    }

    /// Ask, once per session per topic, for the section list's per-topic
    /// stats of channel `cid`'s topics `roots`: the fallback, and the
    /// figures the section stats ([`Self::request_section_stats`],
    /// ADR-2038) do not carry; pages pass only those topics. The exact
    /// reply total (the
    /// relay's `#e:[root]` COUNT, as the thread page uses, kept current by
    /// [`Self::note_inserted`]) and the newest reply (`#e:[root]`,
    /// `limit:1`, into [`Self::topic_latest`]). Topics are taken in the
    /// order given (the list's order) in batches of [`TOPIC_STATS_BATCH`]:
    /// one REQ with one filter per topic plus
    /// one COUNT per topic (a COUNT sums its filters, so topics cannot share
    /// one), the next batch only once the previous REQ has answered.
    pub fn request_topic_stats(
        &self,
        relay: &RelayConnection,
        cid: &str,
        roots: &[String],
        gated: bool,
    ) {
        let mut added = false;
        self.topic_stats_asked.update_value(|asked| {
            self.topic_stats_queue.update_value(|q| {
                for r in roots {
                    let r = r.to_lowercase();
                    if asked.insert(r.clone()) {
                        q.push_back((cid.to_string(), r, gated));
                        added = true;
                    }
                }
            });
        });
        if added {
            self.pump_topic_stats(relay);
        }
    }

    /// Send the next batch of queued topic stats, unless one is in flight.
    fn pump_topic_stats(&self, relay: &RelayConnection) {
        if self.topic_stats_busy.get_value() {
            return;
        }
        let batch: Vec<(String, String, bool)> = self
            .topic_stats_queue
            .try_update_value(|q| {
                let n = q.len().min(TOPIC_STATS_BATCH);
                q.drain(..n).collect()
            })
            .unwrap_or_default();
        if batch.is_empty() {
            return;
        }
        self.topic_stats_busy.set_value(true);
        let wait_auth = batch.iter().any(|(_, _, g)| *g);
        for (_, root, _) in &batch {
            self.request_total_of(relay, &topic_key(root), root);
        }
        let store = *self;
        let zone_keys = self.zone_store();
        let wanted: HashMap<String, String> = batch
            .iter()
            .map(|(cid, root, _)| (root.clone(), cid.clone()))
            .collect();
        let on_event = Rc::new(move |ev: NostrEvent| {
            let Some((cid, ev)) = store.ingest(zone_keys, ev, "") else {
                return;
            };
            store.note_topic_latest(zone_keys, &wanted, &cid, &ev);
        });
        let sub: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
        let done = Rc::new(std::cell::Cell::new(false));
        let on_receipt = {
            let sub = sub.clone();
            let relay = relay.clone();
            Rc::new(move |authed: bool| {
                if (!authed && wait_auth) || done.replace(true) {
                    return;
                }
                if let Some(id) = sub.borrow_mut().take() {
                    relay.unsubscribe(&id);
                }
                store.topic_stats_busy.set_value(false);
                store.pump_topic_stats(&relay);
            })
        };
        let filters = batch
            .iter()
            .map(|(_, root, _)| Filter {
                kinds: Some(vec![42]),
                e_tags: Some(vec![root.clone()]),
                limit: Some(1),
                ..Default::default()
            })
            .collect();
        let id = relay.subscribe_with_receipt(filters, on_event, on_receipt);
        *sub.borrow_mut() = Some(id);
    }

    /// Record `ev` as topic `root`'s newest reply if it is one: in the
    /// topic's channel (`cid`, from its root-marked tag, like the relay's
    /// gate), replying to a topic in `wanted`, and opened (not a sealed or
    /// encrypted placeholder, whose author would be the migrator). The
    /// decrypt state of an event no list holds is dropped again.
    fn note_topic_latest(
        &self,
        zone_keys: Option<ZoneKeyStore>,
        wanted: &HashMap<String, String>,
        cid: &str,
        ev: &NostrEvent,
    ) {
        let root = nostr_bbs_core::sealed::reply_root_of(ev).map(str::to_lowercase);
        // An edit is not activity (`classify_topics`, ADR-2038): it carries
        // its topic's `reply` tag, so a limit-1 answer can be one.
        let opened = crate::topics::thread::edit_target_of(ev).is_none()
            && nostr_bbs_core::sealed::parse_sealed(&ev.tags).is_none()
            && ev.content != crate::zone_crypto::PLACEHOLDER_MISSING_KEY
            && ev.content != crate::zone_crypto::PLACEHOLDER_UNDECRYPTABLE;
        if let Some(root) = root.filter(|r| opened && wanted.get(r).is_some_and(|c| c == cid)) {
            let newer = self
                .topic_latest
                .with_untracked(|m| m.get(&root).is_none_or(|(ts, _)| ev.created_at > *ts));
            if newer {
                self.topic_latest.update(|m| {
                    m.insert(root, (ev.created_at, ev.pubkey.clone()));
                });
            }
        }
        let held = self.channel_messages.with_untracked(|m| {
            m.values().any(|v| {
                let at = v.partition_point(|e| e.created_at < ev.created_at);
                v[at..]
                    .iter()
                    .take_while(|e| e.created_at == ev.created_at)
                    .any(|e| e.id == ev.id)
            })
        });
        if !held {
            if let Some(z) = zone_keys {
                z.forget(std::slice::from_ref(&ev.id));
            }
        }
    }

    /// Ask the relay for channel `cid`'s section stats (ADR-2038), once per
    /// visit: every marked topic with its last activity, last participant
    /// and reply count, in one frame. Sent only when the relay's NIP-11
    /// document advertises it; anything else (not advertised, refused,
    /// malformed, or no answer within [`SECTION_STATS_TIMEOUT_MS`] of this
    /// call, the NIP-11 fetch included) settles as failed, and the board
    /// behaves as it did before. In a gated zone call it only once AUTH is
    /// accepted (as the root list is), so the relay answers the member.
    pub fn request_section_stats(&self, relay: &RelayConnection, cid: &str) {
        if self.section_stats.with_untracked(|m| m.contains_key(cid)) {
            return;
        }
        let gen = self
            .section_stats_gen
            .try_update_value(|g| {
                let n = g.entry(cid.to_string()).or_insert(0);
                *n += 1;
                *n
            })
            .unwrap_or(0);
        self.section_stats.update(|m| {
            m.insert(cid.to_string(), SectionStatsState::Pending);
        });
        let store = *self;
        let wire: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
        {
            let relay = relay.clone();
            let wire = wire.clone();
            let cid = cid.to_string();
            crate::utils::set_timeout_once(
                move || {
                    if let Some(id) = wire.borrow_mut().take() {
                        relay.cancel_section_stats(&id);
                    }
                    store.settle_section_stats(
                        &cid,
                        gen,
                        SectionStatsState::Failed("timeout".into()),
                    );
                },
                SECTION_STATS_TIMEOUT_MS,
            );
        }
        let relay = relay.clone();
        let cid = cid.to_string();
        leptos::task::spawn_local(async move {
            let advertised = crate::relay::info::nip11()
                .await
                .is_ok_and(|doc| crate::topics::section_stats::advertised(&doc));
            if !advertised {
                store.settle_section_stats(
                    &cid,
                    gen,
                    SectionStatsState::Failed("not advertised".into()),
                );
                return;
            }
            let for_cid = cid.clone();
            let on_answer = Rc::new(move |res: Result<serde_json::Value, String>| {
                store.settle_section_stats(
                    &for_cid,
                    gen,
                    SectionStatsState::from_answer(&for_cid, res),
                );
            });
            let id = relay.section_stats(&cid, on_answer);
            *wire.borrow_mut() = Some(id);
        });
    }

    /// Settle request `gen` of channel `cid`, unless a newer request (or
    /// an earlier settlement) got there first.
    fn settle_section_stats(&self, cid: &str, gen: u64, state: SectionStatsState) {
        let current = self
            .section_stats_gen
            .try_with_value(|g| g.get(cid).copied())
            .flatten();
        if current != Some(gen) {
            return;
        }
        if let Some(stats) = state.stats() {
            let as_of = stats.as_of;
            let seeds = section_stats_totals(stats);
            let _ = self.totals.try_update(|m| {
                for (key, n) in seeds {
                    // A COUNT already asked for (or answered) keeps its own.
                    m.entry(key).or_insert_with(|| ChannelTotal {
                        counted: Some(n),
                        as_of,
                        newer_ids: HashSet::new(),
                    });
                }
            });
        }
        let _ = self.section_stats.try_update(|m| {
            if let Some(slot) = m.get_mut(cid).filter(|s| !s.settled()) {
                *slot = state;
            }
        });
    }

    /// A new visit to channel `cid`'s list: forget this channel's section
    /// stats so the visit asks afresh. Call once per visit.
    pub fn rearm_section_stats(&self, cid: &str) {
        if self.section_stats.with_untracked(|m| m.contains_key(cid)) {
            self.section_stats.update(|m| {
                m.remove(cid);
            });
        }
    }

    /// Channel `cid`'s section stats state for this visit, if asked.
    /// Reactive.
    pub fn section_stats_state(&self, cid: &str) -> Option<SectionStatsState> {
        self.section_stats.with(|m| m.get(cid).cloned())
    }

    /// Channel `cid`'s section stats, when answered. Reactive.
    pub fn section_stats(&self, cid: &str) -> Option<std::sync::Arc<SectionStats>> {
        self.section_stats
            .with(|m| m.get(cid).and_then(|s| s.stats().cloned()))
    }

    /// Whether channel `cid`'s section stats have answered or failed this
    /// visit (not asked counts as not settled). Reactive.
    pub fn section_stats_settled(&self, cid: &str) -> bool {
        self.section_stats
            .with(|m| m.get(cid).is_some_and(SectionStatsState::settled))
    }

    /// Whether a deletion of message `id` by `author` is honoured: the
    /// store's own admission decision ([`tombstones::admits`]), with `id`
    /// judged as a restored sealed original when the zone cache says it is
    /// one. A topic list uses it to tell a deleted topic from one merely
    /// evicted from the history window. Read-only, not tracked.
    pub fn deletion_honoured(
        &self,
        zone_keys: Option<ZoneKeyStore>,
        id: &str,
        author: &str,
    ) -> bool {
        let sealed = is_restored_original(zone_keys, id);
        let admin = self.signer_admin;
        self.tombstones.with_untracked(|t| {
            deletion_honoured_by(t, id, sealed.then_some(author), |d| {
                admin.is_admin_untracked(d)
            })
        })
    }

    /// Topic `root`'s newest reply as the relay answered it, as
    /// (created_at, author). Reactive.
    pub fn topic_latest(&self, root: &str) -> Option<(u64, String)> {
        self.topic_latest
            .with(|m| m.get(&root.to_lowercase()).cloned())
    }

    /// The events of list `key` (a channel id or a [`topic_key`]). Reactive.
    pub fn list_events(&self, key: &str) -> Vec<NostrEvent> {
        self.channel_messages
            .with(|m| m.get(key).cloned().unwrap_or_default())
    }

    /// Fetch one event by its id: a live event by `ids`, a sealed one by the
    /// inner id in its `sealed` tag (`#sealed:[id]`, which the relay indexes
    /// like any tag). Used for a topic root known only from its replies.
    /// The event enters the store through the usual admission and decrypt
    /// path (into its own channel's list).
    pub fn fetch_by_id(&self, relay: &RelayConnection, id: &str) {
        let store = *self;
        let zone_keys = self.zone_store();
        let on_event = Rc::new(move |ev: NostrEvent| {
            if let Some(x) = store.ingest(zone_keys, ev, "") {
                store.apply_page(vec![x]);
            }
        });
        let sub: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
        let relay_close = relay.clone();
        let sub_close = sub.clone();
        let on_receipt = Rc::new(move |_authed: bool| {
            if let Some(id) = sub_close.borrow_mut().take() {
                relay_close.unsubscribe(&id);
            }
        });
        let mut sealed = Filter {
            kinds: Some(vec![42]),
            limit: Some(1),
            ..Default::default()
        };
        sealed.sealed_tags = Some(vec![id.to_lowercase()]);
        let id_sub = relay.subscribe_with_receipt(
            vec![
                Filter {
                    ids: Some(vec![id.to_lowercase()]),
                    limit: Some(1),
                    ..Default::default()
                },
                sealed,
            ],
            on_event,
            on_receipt,
        );
        *sub.borrow_mut() = Some(id_sub);
    }

    /// Record the zone-key store (called once by `provide_zone_key_store`).
    pub fn set_zone_store(&self, z: crate::zone_crypto::store::ZoneKeyStore) {
        self.zone_keys.set_value(Some(z));
    }

    /// The zone-key store: the recorded handle, else (before it is recorded,
    /// and only where a reactive owner exists) the context.
    pub fn zone_store(&self) -> Option<crate::zone_crypto::store::ZoneKeyStore> {
        self.zone_keys
            .try_get_value()
            .flatten()
            .or_else(crate::zone_crypto::store::try_use_zone_key_store)
    }

    /// Whether channel `cid`'s history window holds a message from `ts`
    /// (always, unless the window is detached from the newest messages).
    pub fn window_admits(&self, cid: &str, ts: u64) -> bool {
        self.history
            .with_untracked(|m| m.get(cid).is_none_or(|c| c.admits(ts)))
    }

    /// Bring channel `cid` back within [`Self::window_max`] after a page
    /// landed, evicting from the side away from the reader: the NEWEST
    /// messages after an older page (the cursor records the evicted range
    /// as a newer segment to reload), the OLDEST after a newer page (older
    /// paging reloads them). Evicted messages leave the store in one update
    /// and their decrypt-cache entries and plaintext go with them
    /// ([`ZoneKeyStore::forget`](crate::zone_crypto::store::ZoneKeyStore::forget)).
    fn enforce_window(&self, cid: &str, side: EvictSide) {
        let max = if cid.starts_with("topic:") {
            self.thread_window_max
        } else {
            self.window_max
        };
        if self
            .channel_messages
            .with_untracked(|m| m.get(cid).is_none_or(|l| l.len() <= max))
        {
            return;
        }
        let mut evicted: Option<(u64, Vec<NostrEvent>)> = None;
        self.channel_messages.update(|m| {
            if let Some(list) = m.get_mut(cid) {
                evicted = match side {
                    EvictSide::Newest => evict_newest(list, max),
                    EvictSide::Oldest => evict_oldest(list, max),
                };
            }
        });
        let Some((cut, gone)) = evicted else {
            return;
        };
        self.history.update(|m| {
            let c = m.entry(cid.to_string()).or_default();
            match side {
                EvictSide::Newest => c.on_evicted_newest(cut),
                EvictSide::Oldest => c.on_evicted_oldest(cut),
            }
        });
        let ids: Vec<String> = gone.into_iter().map(|e| e.id).collect();
        if let Some(z) = self.zone_store() {
            z.forget(&ids);
        }
    }

    /// Replace channel `cid`'s window with `events` (a newest page) and
    /// restart its cursor from that page, forgetting everything it held.
    fn reset_to_newest(&self, cid: &str, events: Vec<(String, NostrEvent)>, page: PageOutcome) {
        let mut gone: Vec<String> = Vec::new();
        self.channel_messages.update(|m| {
            if let Some(list) = m.get_mut(cid) {
                gone = list.drain(..).map(|e| e.id).collect();
            }
        });
        if let Some(z) = self.zone_store() {
            z.forget(&gone);
        }
        self.history.update(|m| {
            let mut c = HistoryCursor::default();
            c.record_first(page);
            m.insert(cid.to_string(), c);
        });
        self.apply_page(events);
    }

    /// One history page as a one-shot REQ for `filter`, closed on its
    /// answer; `on_done` gets what was ingested and what was delivered.
    ///
    /// With `wait_auth` (a signed-in reader), only an authenticated answer
    /// counts: before NIP-42 AUTH the relay withholds gated zones, and an
    /// empty anonymous answer must not read as the start of history; the
    /// relay replays the REQ after AUTH. A request with no answer within
    /// [`PAGE_TIMEOUT_MS`] is abandoned: the cursor is released (the next
    /// scroll retries; nothing was popped or recorded) and the decrypt-cache
    /// entries of what was buffered are forgotten.
    fn one_shot_page(
        &self,
        relay: &RelayConnection,
        cid: &str,
        filter: Filter,
        wait_auth: bool,
        on_done: PageDone,
    ) {
        self.one_shot_attempt(relay, cid, filter, wait_auth, on_done, None, 1);
    }

    /// [`Self::one_shot_page`], calling `on_fail` instead of `on_done` when
    /// the page is abandoned: no answer within [`PAGE_TIMEOUT_MS`], or
    /// refused (CLOSED) on its last attempt.
    fn one_shot_page_or_fail(
        &self,
        relay: &RelayConnection,
        cid: &str,
        filter: Filter,
        wait_auth: bool,
        on_done: PageDone,
        on_fail: PageFailed,
    ) {
        self.one_shot_attempt(relay, cid, filter, wait_auth, on_done, Some(on_fail), 1);
    }

    /// One attempt of [`Self::one_shot_page`]. A CLOSED answer (the relay
    /// refused the REQ, e.g. too many subscriptions on this connection)
    /// marks this attempt failed: its subscription is dropped, what it
    /// buffered is forgotten, and with `retries` left the page is requested
    /// again on a fresh subscription; otherwise the cursor is released so a
    /// later scroll asks again. `on_fail`, if any, runs when the page is
    /// abandoned (timeout, or CLOSED with no retries left).
    #[expect(
        clippy::too_many_arguments,
        reason = "the page's request, its two outcomes and its retry budget travel together"
    )]
    fn one_shot_attempt(
        &self,
        relay: &RelayConnection,
        cid: &str,
        filter: Filter,
        wait_auth: bool,
        on_done: PageDone,
        on_fail: Option<PageFailed>,
        retries: u8,
    ) {
        let retry_filter = filter.clone();
        self.history.update(|m| {
            m.entry(cid.to_string()).or_default().loading = true;
        });

        struct Buf {
            delivered: u64,
            oldest: Option<u64>,
            events: Vec<(String, NostrEvent)>,
            done: bool,
            sub: Option<String>,
            on_done: Option<PageDone>,
            on_fail: Option<PageFailed>,
        }
        let buf = Rc::new(RefCell::new(Buf {
            delivered: 0,
            oldest: None,
            events: Vec::new(),
            done: false,
            sub: None,
            on_done: Some(on_done),
            on_fail,
        }));
        let store = *self;
        let zone_keys = self.zone_store();
        let key = cid.to_string();

        let on_event = {
            let buf = buf.clone();
            let key = key.clone();
            Rc::new(move |ev: NostrEvent| {
                if buf.borrow().done {
                    return;
                }
                let ts = ev.created_at;
                let ingested = store
                    .ingest(zone_keys, ev, &key)
                    .and_then(|(cid, ev)| store.route_to_list(&key, cid, ev));
                let mut b = buf.borrow_mut();
                b.delivered += 1;
                b.oldest = Some(b.oldest.map_or(ts, |o| o.min(ts)));
                if let Some(x) = ingested {
                    b.events.push(x);
                }
            })
        };
        let on_receipt = {
            let buf = buf.clone();
            let relay = relay.clone();
            let key = key.clone();
            Rc::new(move |authed: bool| {
                if !authed && wait_auth {
                    return;
                }
                let (events, page, sub, done) = {
                    let mut b = buf.borrow_mut();
                    if b.done {
                        return;
                    }
                    b.done = true;
                    b.on_fail = None;
                    let page = PageOutcome {
                        delivered: b.delivered,
                        oldest: b.oldest,
                    };
                    (
                        std::mem::take(&mut b.events),
                        page,
                        b.sub.take(),
                        b.on_done.take(),
                    )
                };
                if let Some(id) = sub {
                    relay.unsubscribe(&id);
                }
                let _ = store.history.try_update(|m| {
                    if let Some(c) = m.get_mut(&key) {
                        c.loading = false;
                    }
                });
                if let Some(f) = done {
                    f(events, page);
                }
            })
        };
        let on_closed = {
            let buf = buf.clone();
            let relay = relay.clone();
            let key = key.clone();
            Rc::new(move |reason: String| {
                let (sub, buffered, done, on_fail) = {
                    let mut b = buf.borrow_mut();
                    if b.done {
                        return;
                    }
                    b.done = true;
                    (
                        b.sub.take(),
                        std::mem::take(&mut b.events),
                        b.on_done.take(),
                        b.on_fail.take(),
                    )
                };
                if let Some(id) = sub {
                    relay.unsubscribe(&id);
                }
                if let Some(z) = zone_keys {
                    let ids: Vec<String> = buffered.into_iter().map(|(_, ev)| ev.id).collect();
                    z.forget(&ids);
                }
                web_sys::console::warn_1(
                    &format!("[History] page request closed by relay: {reason}").into(),
                );
                let _ = store.history.try_update(|m| {
                    if let Some(c) = m.get_mut(&key) {
                        c.loading = false;
                    }
                });
                match (done, retries > 0) {
                    (Some(on_done), true) => store.one_shot_attempt(
                        &relay,
                        &key,
                        retry_filter.clone(),
                        wait_auth,
                        on_done,
                        on_fail,
                        retries - 1,
                    ),
                    _ => {
                        if let Some(f) = on_fail {
                            f();
                        }
                    }
                }
            })
        };
        let id =
            relay.subscribe_with_receipt_or_closed(vec![filter], on_event, on_receipt, on_closed);
        buf.borrow_mut().sub = Some(id);

        // `set_timeout_once` frees its closure once it has run (gloo's
        // `Timeout::forget` would leak it, and the `Buf` it holds, per page).
        // When the receipt came first the timeout finds `done` and returns.
        let relay = relay.clone();
        crate::utils::set_timeout_once(
            move || {
                let (sub, buffered, on_fail) = {
                    let mut b = buf.borrow_mut();
                    if b.done {
                        return;
                    }
                    b.done = true;
                    b.on_done = None;
                    (
                        b.sub.take(),
                        std::mem::take(&mut b.events),
                        b.on_fail.take(),
                    )
                };
                if let Some(id) = sub {
                    relay.unsubscribe(&id);
                }
                if let Some(z) = zone_keys {
                    let ids: Vec<String> = buffered.into_iter().map(|(_, ev)| ev.id).collect();
                    z.forget(&ids);
                }
                let _ = store.history.try_update(|m| {
                    if let Some(c) = m.get_mut(&key) {
                        c.loading = false;
                    }
                });
                if let Some(f) = on_fail {
                    f();
                }
            },
            PAGE_TIMEOUT_MS as i32,
        );
    }

    /// Fetch the next older page of channel `cid` (see [`HistoryCursor`])
    /// over the channel's `#e` `needles`. Returns whether a request went out
    /// (`false` before the first page, while one is in flight, or at the
    /// start of history). `before_apply` runs just before the page enters
    /// the store and `after_apply` just after (the page anchors its scroll
    /// position around them); the window is then brought back within bounds
    /// by evicting its newest messages.
    pub fn load_older(
        &self,
        relay: &RelayConnection,
        cid: &str,
        needles: Vec<String>,
        wait_auth: bool,
        before_apply: Rc<dyn Fn()>,
        after_apply: Rc<dyn Fn()>,
    ) -> bool {
        let Some(req) = self
            .history
            .with_untracked(|m| m.get(cid).and_then(HistoryCursor::next_request))
        else {
            return false;
        };
        let store = *self;
        let key = cid.to_string();
        self.one_shot_page(
            relay,
            cid,
            HistoryCursor::filter(req, &needles),
            wait_auth,
            Box::new(move |events, page| {
                before_apply();
                store.apply_page(events);
                let _ = store.history.try_update(|m| {
                    if let Some(c) = m.get_mut(&key) {
                        c.record(req, page);
                    }
                });
                store.enforce_window(&key, EvictSide::Newest);
                after_apply();
            }),
        );
        true
    }

    /// Reload the evicted messages next newer than channel `cid`'s window
    /// (the top of [`HistoryCursor::newer`]), then evict its oldest messages
    /// to stay within bounds. Returns whether a request went out (`false`
    /// while the window holds the newest messages, before the first page or
    /// while a request is in flight). The segment leaves the stack only when
    /// its page is applied, so a timed-out reload leaves no gap. Should the
    /// open-ended newest segment hold a full relay page (more live posts
    /// arrived while the window was detached than one request returns), the
    /// window restarts from that newest page instead.
    pub fn load_newer(
        &self,
        relay: &RelayConnection,
        cid: &str,
        needles: Vec<String>,
        wait_auth: bool,
        before_apply: Rc<dyn Fn()>,
        after_apply: Rc<dyn Fn()>,
    ) -> bool {
        let Some(seg) = self
            .history
            .with_untracked(|m| m.get(cid).and_then(HistoryCursor::next_newer))
        else {
            return false;
        };
        let store = *self;
        let key = cid.to_string();
        self.one_shot_page(
            relay,
            cid,
            HistoryCursor::newer_filter(seg, &needles),
            wait_auth,
            Box::new(move |events, page| {
                let mut outcome = NewerOutcome::Applied;
                let _ = store.history.try_update(|m| {
                    if let Some(c) = m.get_mut(&key) {
                        outcome = c.record_newer(seg, page);
                    }
                });
                before_apply();
                match outcome {
                    NewerOutcome::Applied => {
                        store.apply_page(events);
                        store.enforce_window(&key, EvictSide::Oldest);
                    }
                    NewerOutcome::Reset => store.reset_to_newest(&key, events, page),
                }
                after_apply();
            }),
        );
        true
    }

    /// Restart channel `cid`'s window from its newest page (a one-shot REQ
    /// of [`HISTORY_PAGE`]), dropping what it held. For a view that needs the
    /// newest messages while the window is detached in older history, such
    /// as a deep link to a topic newer than the window. Returns whether a
    /// request went out.
    pub fn reload_newest(
        &self,
        relay: &RelayConnection,
        cid: &str,
        needles: Vec<String>,
        wait_auth: bool,
    ) -> bool {
        if self
            .history
            .with_untracked(|m| m.get(cid).is_some_and(|c| c.loading))
        {
            return false;
        }
        let store = *self;
        let key = cid.to_string();
        self.one_shot_page(
            relay,
            cid,
            Filter {
                kinds: Some(vec![42]),
                e_tags: Some(needles),
                limit: Some(HISTORY_PAGE),
                ..Default::default()
            },
            wait_auth,
            Box::new(move |events, page| store.reset_to_newest(&key, events, page)),
        );
        true
    }

    /// Cleanup subscriptions.
    pub fn cleanup(&self, relay: &RelayConnection) {
        if let Some(id) = self.sub_id.get_untracked() {
            relay.unsubscribe(&id);
        }
        if let Some(id) = self.msg_sub_id.get_untracked() {
            relay.unsubscribe(&id);
        }
    }
}

// -- Context helpers ----------------------------------------------------------

/// Provide the channel store. Call once in App root.
pub fn provide_channel_store() {
    provide_context(ChannelStore::new());
}

/// Get the channel store from context.
pub fn use_channel_store() -> ChannelStore {
    expect_context::<ChannelStore>()
}

// -- Helpers ------------------------------------------------------------------

/// Insert a prepared kind-42 into a channel's list: dedupe by event id (the
/// only counter, ADR-091), keeping the list sorted by `created_at`. Returns
/// whether the event was new.
///
/// Callers pass the event *after* `zone_crypto::store::prepare_incoming`, so a
/// restored sealed original (ADR-2017) is deduped by the original's id.
///
/// The list is kept sorted, so the insert is a binary search plus one move
/// rather than a re-sort per event (which made loading `n` messages cost
/// `O(n² log n)`). An event id is the hash of the event, `created_at`
/// included, so an event already held sits in the run of equal timestamps:
/// only that run is checked for the id. A new event goes after its equals,
/// the order the stable sort used to give.
pub fn insert_message(events: &mut Vec<NostrEvent>, event: NostrEvent) -> bool {
    let ts = event.created_at;
    let start = events.partition_point(|e| e.created_at < ts);
    let end = start + events[start..].partition_point(|e| e.created_at <= ts);
    if events[start..end].iter().any(|e| e.id == event.id) {
        return false;
    }
    events.insert(end, event);
    true
}

/// Parse kind-40 channel content JSON into (name, description, picture).
pub fn parse_channel_content(content: &str) -> (String, String, String) {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(val) => {
            let name = val
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unnamed section")
                .to_string();
            let description = val
                .get("about")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let picture = val
                .get("picture")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            (name, description, picture)
        }
        Err(_) => ("Unnamed section".to_string(), String::new(), String::new()),
    }
}

// -- kind-41 metadata folding (admin channel rename) --------------------------

/// A channel-metadata edit distilled from a kind-41 event.
///
/// `name`/`about`/`picture` are `Some` only when the key was present in the
/// event's JSON content, so a fold updates just the fields the admin actually
/// sent (e.g. rename without disturbing the picture). A real edit carries at
/// least one of `name`/`about`.
#[derive(Clone, Debug, PartialEq)]
pub struct MetaUpdate {
    pub channel_id: String,
    pub name: Option<String>,
    pub about: Option<String>,
    pub picture: Option<String>,
    pub created_at: u64,
}

/// Distill a kind-41 event into a [`MetaUpdate`], or `None` when the event is
/// not a channel-metadata edit.
///
/// Returns `None` when: there is no `["e", <channel_id>, …]` tag; the content is
/// not a JSON object; or neither `name` nor `about` is present. That last rule
/// is what makes the fold ignore the pinned-message control 41s published by
/// `components/pinned_messages.rs` (empty content, only a `["pin", …]` /
/// `["unpin", …]` tag) — folding those would blank the channel name.
pub fn parse_meta_update(event: &NostrEvent) -> Option<MetaUpdate> {
    let channel_id = event
        .tags
        .iter()
        .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == "root")
        .or_else(|| event.tags.iter().find(|t| t.len() >= 2 && t[0] == "e"))
        .map(|t| t[1].clone())
        .filter(|id| !id.is_empty())?;

    let val = serde_json::from_str::<serde_json::Value>(&event.content).ok()?;
    let name = val.get("name").and_then(|v| v.as_str()).map(str::to_string);
    let about = val
        .get("about")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let picture = val
        .get("picture")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    if name.is_none() && about.is_none() {
        return None;
    }

    Some(MetaUpdate {
        channel_id,
        name,
        about,
        picture,
        created_at: event.created_at,
    })
}

/// Fold a [`MetaUpdate`] into the channel list, last-write-wins by metadata
/// timestamp. Returns `true` when a channel was updated.
///
/// `meta_ts` records the `created_at` of each channel's most-recent applied
/// metadata event, kept SEPARATE from `ChannelMeta::created_at` (the kind-40
/// creation time) so a stale kind-41 replayed after a reload cannot clobber a
/// newer name/description. The baseline for a channel with no recorded edit is
/// its own creation time, so no kind-41 can predate its kind-40. Ordering is
/// therefore arrival-order independent.
///
/// TRUST MODEL: the relay is whitelist + AUTH gated and already enforces WHO may
/// write kind-41 (TL2 for own channel, TL3/admin for any — see the relay's
/// `relay_do/nip_handlers.rs`). The client folds any stored 41 without
/// re-checking authorship; re-checking here would duplicate — and could
/// disagree with — the server's authority.
pub fn fold_meta_into(
    channels: &mut [ChannelMeta],
    meta_ts: &mut HashMap<String, u64>,
    update: &MetaUpdate,
) -> bool {
    let Some(channel) = channels.iter_mut().find(|c| c.id == update.channel_id) else {
        return false;
    };
    let baseline = meta_ts
        .get(&update.channel_id)
        .copied()
        .unwrap_or(channel.created_at);
    if update.created_at < baseline {
        return false;
    }

    // A blank name would break display; the edit UI forbids it, but guard the
    // fold too so a malformed 41 can't erase the name while still applying its
    // about/picture.
    if let Some(name) = update.name.as_ref() {
        if !name.trim().is_empty() {
            channel.name = name.clone();
        }
    }
    if let Some(about) = update.about.as_ref() {
        channel.description = about.clone();
    }
    if let Some(picture) = update.picture.as_ref() {
        channel.picture = picture.clone();
    }
    meta_ts.insert(update.channel_id.clone(), update.created_at);
    true
}

/// Buffer a metadata edit whose channel (kind-40) hasn't been seen yet, keeping
/// only the newest by `created_at`. Applied when the kind-40 arrives.
fn buffer_pending_meta(pending: &mut HashMap<String, MetaUpdate>, update: MetaUpdate) {
    match pending.get(&update.channel_id) {
        Some(existing) if existing.created_at >= update.created_at => {}
        _ => {
            pending.insert(update.channel_id.clone(), update);
        }
    }
}

/// Backoff of one failed root-list request: not asked again before
/// `retry_at` (ms since the epoch), the wait starting at
/// [`PAGE_TIMEOUT_MS`] and doubling per failure up to
/// [`ROOTS_BACKOFF_CAP_MS`]. A new visit re-arms it at once; an answer
/// clears it.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct RootsBackoff {
    failures: u32,
    retry_at: f64,
}

/// Longest wait between two asks of a failing root list.
const ROOTS_BACKOFF_CAP_MS: f64 = 300_000.0;

impl RootsBackoff {
    /// Wait after the `failures`-th failure in a row.
    fn wait_ms(failures: u32) -> f64 {
        let doublings = failures.saturating_sub(1).min(16);
        (f64::from(PAGE_TIMEOUT_MS) * f64::from(1u32 << doublings)).min(ROOTS_BACKOFF_CAP_MS)
    }

    /// Record a failure at `now`.
    fn failed(&mut self, now: f64) {
        self.failures = self.failures.saturating_add(1);
        self.retry_at = now + Self::wait_ms(self.failures);
    }

    /// A new visit: ask again now. The failure count stays, so a relay that
    /// keeps refusing backs off further each time.
    fn rearm(&mut self) {
        self.retry_at = 0.0;
    }

    /// Whether the root list may be asked at `now`.
    fn may_ask(&self, now: f64) -> bool {
        now >= self.retry_at
    }
}

#[cfg(test)]
mod roots_backoff_tests {
    use super::*;

    #[test]
    fn a_failed_root_list_waits_doubling_up_to_the_cap() {
        let mut b = RootsBackoff::default();
        assert!(b.may_ask(0.0), "never failed: ask");
        b.failed(1_000.0);
        assert!(!b.may_ask(1_000.0 + 19_999.0), "within PAGE_TIMEOUT_MS");
        assert!(b.may_ask(1_000.0 + 20_000.0));
        b.failed(50_000.0);
        assert_eq!(b.retry_at, 50_000.0 + 40_000.0);
        for _ in 0..20 {
            b.failed(0.0);
        }
        assert_eq!(b.retry_at, ROOTS_BACKOFF_CAP_MS, "capped");
    }

    #[test]
    fn every_message_in_between_is_refused() {
        // A view re-asking on each incoming message gets nothing out
        // until the wait has run out.
        let mut b = RootsBackoff::default();
        b.failed(0.0);
        let asked = (0..200)
            .map(|i| f64::from(i) * 100.0)
            .filter(|t| b.may_ask(*t))
            .count();
        assert_eq!(asked, 0);
    }

    #[test]
    fn a_new_visit_rearms_at_once_but_keeps_the_count() {
        let mut b = RootsBackoff::default();
        b.failed(0.0);
        b.failed(0.0);
        b.rearm();
        assert!(b.may_ask(1.0));
        b.failed(10.0);
        assert_eq!(b.retry_at, 10.0 + 80_000.0, "third failure: 4x");
    }
}

/// Forget channel `cid`'s root-list failure, as a new request goes out.
/// Returns whether it was recorded.
fn clear_roots_failure(failed: &mut HashSet<String>, cid: &str) -> bool {
    failed.remove(cid)
}

#[cfg(test)]
mod roots_failure_tests {
    use super::*;

    #[test]
    fn a_new_request_unsettles_a_failed_root_list() {
        // Fail, leave, return: the new request clears the failure, so the
        // list is unsettled (answered nor failed) until the new answer.
        let mut failed: HashSet<String> = ["c".to_string()].into_iter().collect();
        assert!(clear_roots_failure(&mut failed, "c"));
        assert!(!failed.contains("c"));
        assert!(!clear_roots_failure(&mut failed, "c"));
    }
}

/// Whether `tombstones` hide message `id`: [`tombstones::admits`] refuses
/// it, as a restored sealed original of `sealed_author` when given, else
/// as an ordinary message.
fn deletion_honoured_by(
    tombstones: &Tombstones,
    id: &str,
    sealed_author: Option<&str>,
    is_admin: impl Fn(&str) -> bool,
) -> bool {
    let target = match sealed_author {
        Some(author) => Target::SealedOriginal { author },
        None => Target::Ordinary,
    };
    !tombstones::admits(tombstones, id, target, is_admin)
}

#[cfg(test)]
mod deletion_honoured_tests {
    use super::*;

    #[test]
    fn only_an_honoured_deletion_hides_a_topic() {
        let mut t = Tombstones::default();
        assert!(!deletion_honoured_by(&t, "x", None, |_| false), "no kind-5");
        // A kind-5 by someone who is neither the author nor an admin, on a
        // restored sealed original: recorded, not honoured.
        t.record("sealed", "mallory");
        assert!(!deletion_honoured_by(&t, "sealed", Some("alice"), |_| {
            false
        }));
        // By the author, or by a relay-vouched admin: honoured.
        assert!(deletion_honoured_by(&t, "sealed", Some("mallory"), |_| {
            false
        }));
        assert!(deletion_honoured_by(&t, "sealed", Some("alice"), |d| d == "mallory"));
        // An ordinary message: the relay gated the deletion.
        t.record("plain", "bob");
        assert!(deletion_honoured_by(&t, "plain", None, |_| false));
    }
}

/// Append `meta` to the channel list unless a channel with its id is
/// already listed. Returns whether the list changed, so the caller notifies
/// readers only then.
fn push_channel_if_new(list: &mut Vec<ChannelMeta>, meta: ChannelMeta) -> bool {
    if list.iter().any(|c| c.id == meta.id) {
        return false;
    }
    list.push(meta);
    true
}

/// Keep only the channels the relay delivered (`ids`). Returns whether any
/// was dropped, so the caller notifies readers only then.
fn retain_relay_channels(list: &mut Vec<ChannelMeta>, ids: &HashSet<String>) -> bool {
    let before = list.len();
    list.retain(|c| ids.contains(&c.id));
    list.len() != before
}

#[cfg(test)]
mod channel_list_tests {
    use super::*;

    fn meta(id: &str) -> ChannelMeta {
        ChannelMeta {
            id: id.into(),
            name: id.into(),
            description: String::new(),
            section: String::new(),
            section_tag: String::new(),
            picture: String::new(),
            created_at: 1,
        }
    }

    #[test]
    fn a_channel_already_listed_is_not_a_change() {
        let mut list = vec![meta("a")];
        assert!(!push_channel_if_new(&mut list, meta("a")));
        assert_eq!(list.len(), 1);
        assert!(push_channel_if_new(&mut list, meta("b")));
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn pruning_nothing_is_not_a_change() {
        let mut list = vec![meta("a"), meta("b")];
        let all: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        assert!(!retain_relay_channels(&mut list, &all));
        assert_eq!(list.len(), 2);
        let some: HashSet<String> = ["b".to_string()].into_iter().collect();
        assert!(retain_relay_channels(&mut list, &some));
        assert_eq!(
            list.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            ["b"]
        );
    }

    #[test]
    fn an_unchanged_list_does_not_notify() {
        // The signal-level contract the section page relies on: a re-sent
        // channel and a prune that drops nothing leave readers untouched.
        let owner = Owner::new();
        owner.with(|| {
            let sig = RwSignal::new(vec![meta("a")]);
            let runs = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let seen = runs.clone();
            let memo = Memo::new(move |_| {
                sig.track();
                seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            });
            memo.get_untracked();
            let start = runs.load(std::sync::atomic::Ordering::Relaxed);
            sig.maybe_update(|l| push_channel_if_new(l, meta("a")));
            let ids: HashSet<String> = ["a".to_string()].into_iter().collect();
            sig.maybe_update(|l| retain_relay_channels(l, &ids));
            memo.get_untracked();
            assert_eq!(
                runs.load(std::sync::atomic::Ordering::Relaxed),
                start,
                "no change, no notification"
            );
            sig.maybe_update(|l| push_channel_if_new(l, meta("b")));
            memo.get_untracked();
            assert_eq!(runs.load(std::sync::atomic::Ordering::Relaxed), start + 1);
        });
    }
}

// -- kind-5 deletion folding (post deletion) ----------------------------------

/// Most rows the relay returns for one filter (`MAX_QUERY_LIMIT` in the relay
/// worker's `relay_do/storage.rs`). A filter that leaves `limit` unset gets the
/// relay's default of 500 instead, so every sync filter states it.
pub const RELAY_FILTER_LIMIT: u64 = 1000;

/// Filters the relay accepts in one REQ (`MAX_FILTERS` in the relay worker).
pub const RELAY_MAX_FILTERS: usize = 10;

/// How long a history page request may go unanswered before it is abandoned.
pub const PAGE_TIMEOUT_MS: u32 = 20_000;

/// Default size of a channel's history window: the most messages kept in
/// the store (and so in the DOM) for one channel. Paging past it evicts the
/// far end, which is reloaded on the way back. At ~13 KB of wasm heap per
/// loaded message (measured on a 50k-message channel), 3,000 keeps a
/// channel's history around 40 MB however long it is.
pub const HISTORY_WINDOW: usize = 3_000;

/// Default window of a single thread's reply list (`topic:<root>` lists).
/// A reply card renders ~45 DOM nodes (about twice a topic row) and its
/// controls, so a thread holds fewer rows: at 3,000 a 50k-reply thread
/// peaked at 179 MB of the 256 MiB wasm heap.
pub const THREAD_WINDOW: usize = 1_200;

/// The smallest window accepted: ten pages, so the older and newer loaders
/// are never both on screen evicting each other's pages.
pub const HISTORY_WINDOW_MIN: usize = 10 * HISTORY_PAGE as usize;

/// `n` clamped to at least [`HISTORY_WINDOW_MIN`].
pub fn clamp_window(n: usize) -> usize {
    n.max(HISTORY_WINDOW_MIN)
}

/// The window size for this deployment: `window.__ENV__.HISTORY_WINDOW`
/// (a number or numeric string) when set, else [`HISTORY_WINDOW`]; clamped.
fn configured_window() -> usize {
    env_window("HISTORY_WINDOW", HISTORY_WINDOW)
}

/// The thread window for this deployment: `window.__ENV__.THREAD_WINDOW`
/// when set, else [`THREAD_WINDOW`]; clamped.
fn configured_thread_window() -> usize {
    env_window("THREAD_WINDOW", THREAD_WINDOW)
}

/// `window.__ENV__[name]` (a number or numeric string) when set, else
/// `default`; clamped to [`HISTORY_WINDOW_MIN`].
fn env_window(name: &str, default: usize) -> usize {
    #[cfg(target_arch = "wasm32")]
    {
        let configured = web_sys::window()
            .and_then(|w| js_sys::Reflect::get(&w, &"__ENV__".into()).ok())
            .filter(|env| env.is_object())
            .and_then(|env| js_sys::Reflect::get(&env, &name.into()).ok())
            .and_then(|v| {
                v.as_f64()
                    .map(|f| f as usize)
                    .or_else(|| v.as_string().and_then(|s| s.trim().parse().ok()))
            });
        if let Some(n) = configured {
            return clamp_window(n);
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = name;
    clamp_window(default)
}

/// What a history page request hands back once answered: the ingested
/// messages and what the relay delivered.
type PageDone = Box<dyn FnOnce(Vec<(String, NostrEvent)>, PageOutcome)>;
/// Called once when a one-shot page is abandoned (see
/// `one_shot_page_or_fail`).
type PageFailed = Box<dyn FnOnce()>;

/// A channel's true message total: the relay's NIP-45 COUNT of its kind-42s
/// up to `as_of` (inclusive), plus the distinct messages newer than `as_of`
/// seen since. The two parts never overlap, and the second is keyed by id,
/// so a page evicted and reloaded by the history window is not counted
/// twice. A deletion lowers the relay's figure only on the next count (the
/// next session); a gated channel counts 0 for a non-member, and the
/// displayed total never drops below what the store holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChannelTotal {
    /// The COUNT answer, once in.
    pub counted: Option<u64>,
    /// The COUNT's `until`.
    pub as_of: u64,
    /// Ids of messages newer than `as_of` inserted since the count.
    pub newer_ids: HashSet<String>,
}

impl ChannelTotal {
    /// The total, when the count has answered.
    pub fn total(&self) -> Option<u64> {
        self.counted.map(|n| n + self.newer_ids.len() as u64)
    }
}

/// Topics per section-list stats batch (one REQ + one COUNT each, so 6
/// frames): under the relay's 10-filter cap, and small enough that the
/// client's own send pacing (`relay.rs` MAX_SENDS_PER_SECOND, 8/s) never
/// holds a reader's REQ behind more than a second of stats frames.
pub const TOPIC_STATS_BATCH: usize = 5;

/// The topic a message is a reply to, lower-case, when it is one: its
/// `reply`-marked `e` tag, and not an edit (`classify_topics`: an edit is
/// neither a reply nor activity).
pub fn reply_topic(ev: &NostrEvent) -> Option<String> {
    if crate::topics::thread::edit_target_of(ev).is_some() {
        return None;
    }
    nostr_bbs_core::sealed::reply_root_of(ev).map(str::to_lowercase)
}

/// The topic totals a section stats answer seeds (ADR-2038): for each topic
/// with an exact reply count, its list key and, for a sealed root, its
/// original's, each with the count as of the answer. A live reply then adds
/// to it ([`ChannelStore::note_inserted`]), so a row's count follows new
/// replies during the visit.
pub fn section_stats_totals(
    stats: &crate::topics::section_stats::SectionStats,
) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    for t in &stats.topics {
        if let Some(n) = t.replies {
            out.push((topic_key(&t.id), n as u64));
            if let Some(o) = &t.original {
                out.push((topic_key(o), n as u64));
            }
        }
    }
    out
}

/// The list key of channel `cid`'s topic roots.
pub fn roots_key(cid: &str) -> String {
    format!("roots:{cid}")
}

/// The list (and history-cursor) key of topic `root`'s own paged list.
pub fn topic_key(root: &str) -> String {
    format!("topic:{}", root.to_lowercase())
}

/// Whether `key` of [`ChannelStore::channel_messages`] is a channel's own
/// list, as opposed to a topic's paged list ([`topic_key`]) or a section's
/// root list ([`roots_key`]), which repeat posts the channel list may hold.
pub fn is_channel_key(key: &str) -> bool {
    !key.starts_with("topic:") && !key.starts_with("roots:")
}

/// Every post the store holds, once each (by event id, case-insensitively),
/// with its channel: the channel list's own id, or for a post held only in a
/// topic or root list the channel its tags name (`None` when they name none).
///
/// The store keeps a post in its channel list and again in its topic's list
/// and the section's root list, so reading every list shows it two or three
/// times. Channel lists are read first, so a post they hold is attributed to
/// them; the result is in no particular order.
pub fn distinct_posts(
    lists: &HashMap<String, Vec<NostrEvent>>,
) -> Vec<(Option<String>, NostrEvent)> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let (channel_lists, other_lists): (Vec<_>, Vec<_>) =
        lists.iter().partition(|(key, _)| is_channel_key(key));
    for (key, events) in channel_lists {
        for ev in events {
            if seen.insert(ev.id.to_ascii_lowercase()) {
                out.push((Some(key.clone()), ev.clone()));
            }
        }
    }
    for (_, events) in other_lists {
        for ev in events {
            if seen.insert(ev.id.to_ascii_lowercase()) {
                out.push((crate::utils::post_link::channel_of(ev), ev.clone()));
            }
        }
    }
    out
}

/// Which end of a channel's window to evict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvictSide {
    /// The newest messages (after an older page landed).
    Newest,
    /// The oldest messages (after a newer page was reloaded).
    Oldest,
}

/// Evict the newest messages of `events` (sorted by `created_at`) so at most
/// `max` remain, cutting only between seconds: every message from the cut
/// second on goes, so a run of equal timestamps is never split. Returns the
/// cut second and what was evicted; `None` when nothing needs to go, or when
/// the cut would empty the window (one second holding more than `max`).
pub fn evict_newest(events: &mut Vec<NostrEvent>, max: usize) -> Option<(u64, Vec<NostrEvent>)> {
    if events.len() <= max {
        return None;
    }
    let cut = events[max].created_at;
    let keep = events.partition_point(|e| e.created_at < cut);
    if keep == 0 {
        return None;
    }
    Some((cut, events.split_off(keep)))
}

/// Evict the oldest messages of `events` (sorted) so at most `max` remain,
/// cutting only between seconds: every message up to and including the
/// returned second goes. `None` as for [`evict_newest`].
pub fn evict_oldest(events: &mut Vec<NostrEvent>, max: usize) -> Option<(u64, Vec<NostrEvent>)> {
    let len = events.len();
    if len <= max {
        return None;
    }
    let cut = events[len - max - 1].created_at;
    let drop = events.partition_point(|e| e.created_at <= cut);
    if drop == len {
        return None;
    }
    Some((cut, events.drain(..drop).collect()))
}

/// A range of evicted messages newer than a channel's window: every message
/// with `from <= created_at`, and `created_at < to` unless `to` is `None`
/// (the range runs to the newest message, live posts included).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub from: u64,
    pub to: Option<u64>,
}

/// What [`HistoryCursor::record_newer`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewerOutcome {
    /// The segment's messages are back in the window.
    Applied,
    /// The open-ended newest segment overflowed one relay page: restart the
    /// window from the page returned (the newest messages).
    Reset,
}

/// Messages per history page: the newest page a channel opens with, and each
/// older page fetched when the reader scrolls to the top.
pub const HISTORY_PAGE: u64 = 100;

/// Boot-sync budget per known channel (home view: last activity, unread).
/// A channel's full history is paged in by the channel page, not here.
pub const SYNC_PER_CHANNEL: u64 = 20;

/// Where a channel's paged history stands (see [`ChannelStore::load_older`]).
///
/// Pages walk back with an inclusive `until` = the oldest timestamp delivered
/// so far: the boundary second is fetched again (a one-second overlap) and
/// the ids already held are dropped, so messages sharing that second are
/// neither skipped nor duplicated. A page shorter than the limit is the
/// start of history. If a full page comes back entirely at the `until`
/// second, more than a page shares that second: the next request fetches
/// that whole second (`since = until = t`, up to the relay's row cap), and
/// the walk then continues below it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HistoryCursor {
    /// `until` of the next older page; `None` until the first page has landed.
    pub until: Option<u64>,
    /// A second to fetch whole before paging on (see above).
    pub sweep: Option<u64>,
    /// The relay has returned the oldest message.
    pub exhausted: bool,
    /// A page request is in flight.
    pub loading: bool,
    /// The first (newest) page has been recorded.
    pub started: bool,
    /// `None` while the window holds the newest messages. `Some(t)` once
    /// newer messages were evicted: the window holds only messages older
    /// than `t`, and live posts from `t` on are not inserted (the reload of
    /// the newest segment brings them).
    pub newer_from: Option<u64>,
    /// Evicted ranges newer than the window, nearest last; reloaded by
    /// [`ChannelStore::load_newer`] in that order.
    pub newer: Vec<Segment>,
}

/// What one page request delivered: every event the relay sent for it,
/// counted before any client-side admission, and the oldest `created_at`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PageOutcome {
    pub delivered: u64,
    pub oldest: Option<u64>,
}

/// The request a [`HistoryCursor`] makes next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageRequest {
    /// `until` (inclusive), `limit` [`HISTORY_PAGE`].
    Older { until: u64 },
    /// `since = until = second`, `limit` [`RELAY_FILTER_LIMIT`].
    Sweep { second: u64 },
}

impl HistoryCursor {
    /// The next older page to ask for, or `None` when there is nothing to ask
    /// (not started, exhausted, or a request already in flight).
    pub fn next_request(&self) -> Option<PageRequest> {
        if self.loading || self.exhausted || !self.started {
            return None;
        }
        if let Some(second) = self.sweep {
            return Some(PageRequest::Sweep { second });
        }
        self.until.map(|until| PageRequest::Older { until })
    }

    /// The filter for `req` over the channel's `#e` needles.
    pub fn filter(req: PageRequest, needles: &[String]) -> Filter {
        let (since, until, limit) = match req {
            PageRequest::Older { until } => (None, until, HISTORY_PAGE),
            PageRequest::Sweep { second } => (Some(second), second, RELAY_FILTER_LIMIT),
        };
        Filter {
            kinds: Some(vec![42]),
            e_tags: Some(needles.to_vec()),
            since,
            until: Some(until),
            limit: Some(limit),
            ..Default::default()
        }
    }

    /// Whether the window holds a message from `ts`.
    pub fn admits(&self, ts: u64) -> bool {
        self.newer_from.is_none_or(|t| ts < t)
    }

    /// The evicted range to reload next (nearest the window), or `None`
    /// while the window holds the newest messages, before the first page,
    /// or while a request (either direction) is in flight.
    pub fn next_newer(&self) -> Option<Segment> {
        if self.loading || !self.started {
            return None;
        }
        self.newer.last().copied()
    }

    /// The filter reloading `seg`: `since = from`, `until = to - 1` (both
    /// inclusive), up to [`RELAY_FILTER_LIMIT`]. A closed segment holds what
    /// was evicted from it, about a page; the open one may also hold live
    /// posts that arrived while the window was detached.
    pub fn newer_filter(seg: Segment, needles: &[String]) -> Filter {
        Filter {
            kinds: Some(vec![42]),
            e_tags: Some(needles.to_vec()),
            since: Some(seg.from),
            until: seg.to.map(|t| t.saturating_sub(1)),
            limit: Some(RELAY_FILTER_LIMIT),
            ..Default::default()
        }
    }

    /// Record the reload of `seg` (the stack's top): it leaves the stack and
    /// the window now reaches its end. An open segment that came back full
    /// may have lost messages between `from` and the oldest returned: the
    /// caller restarts the window ([`NewerOutcome::Reset`]).
    pub fn record_newer(&mut self, seg: Segment, page: PageOutcome) -> NewerOutcome {
        self.loading = false;
        if seg.to.is_none() && page.delivered >= RELAY_FILTER_LIMIT {
            return NewerOutcome::Reset;
        }
        if self.newer.last() == Some(&seg) {
            self.newer.pop();
            self.newer_from = seg.to;
        }
        NewerOutcome::Applied
    }

    /// The newest messages from second `cut` on were evicted: remember them
    /// as the segment nearest the window.
    pub fn on_evicted_newest(&mut self, cut: u64) {
        self.newer.push(Segment {
            from: cut,
            to: self.newer_from,
        });
        self.newer_from = Some(cut);
    }

    /// The oldest messages up to second `cut` were evicted: older paging
    /// resumes from there (inclusive, so `cut` is fetched again and deduped).
    pub fn on_evicted_oldest(&mut self, cut: u64) {
        self.until = Some(cut);
        self.sweep = None;
        self.exhausted = false;
    }

    /// Record the newest page (the channel's first REQ, `limit` [`HISTORY_PAGE`]).
    pub fn record_first(&mut self, page: PageOutcome) {
        self.started = true;
        self.loading = false;
        self.record_older(None, page);
    }

    /// Record the answer to `req` (`None` for the first page).
    pub fn record(&mut self, req: PageRequest, page: PageOutcome) {
        self.loading = false;
        match req {
            PageRequest::Older { until } => self.record_older(Some(until), page),
            PageRequest::Sweep { second } => {
                self.sweep = None;
                // Everything at `second` is now held; page on below it.
                match second.checked_sub(1) {
                    Some(below) => self.until = Some(below),
                    None => self.exhausted = true,
                }
            }
        }
    }

    fn record_older(&mut self, asked_until: Option<u64>, page: PageOutcome) {
        if page.delivered < HISTORY_PAGE {
            self.exhausted = true;
            if let Some(o) = page.oldest {
                self.until = Some(o);
            }
            return;
        }
        let oldest = page.oldest.expect("a full page has an oldest event");
        if asked_until == Some(oldest) {
            // A full page, all at the boundary second: fetch that second whole.
            self.sweep = Some(oldest);
        } else {
            self.until = Some(oldest);
        }
    }
}

/// The kind-5 filter shared by the channel and reaction subscriptions.
///
/// `since` is the device's marker from [`deletion_sync`]; `None` (no completed
/// sync yet) takes the newest [`RELAY_FILTER_LIMIT`] deletions. The limit
/// stays either way: should more than that many deletions fall after the
/// marker, the relay returns the same newest rows an unmarked sync would.
fn deletion_filter(since: Option<u64>) -> Filter {
    Filter {
        kinds: Some(vec![5]),
        since,
        limit: Some(RELAY_FILTER_LIMIT),
        ..Default::default()
    }
}

/// One page of the kind-5 filter, for a marked sync that hit the row cap:
/// `until` is the oldest `created_at` delivered so far, inclusive, so rows
/// sharing that timestamp are not skipped (re-deliveries are idempotent).
/// See [`deletion_sync`].
pub fn deletion_page_filter(since: Option<u64>, until: u64) -> Filter {
    Filter {
        until: Some(until),
        ..deletion_filter(since)
    }
}

/// Filters for the channel-list subscription.
///
/// The relay returns the newest `limit` rows of a filter across every kind in
/// it. Kind-5 deletions keep accumulating while the channel definitions
/// (kinds 40 and 41) are few and old, so one `[5, 40, 41]` filter eventually
/// returns only deletions: once there were more than 500 of them, a device
/// with no cached channel list saw no sections at all. Each set gets its own
/// filter, channels first, so deletions can never displace a channel.
///
/// Only the deletion filter takes `deletions_since`: the channel definitions
/// are fetched in full every session, because the EOSE handler prunes cached
/// channels the relay did not return.
pub fn channel_sync_filters(deletions_since: Option<u64>) -> Vec<Filter> {
    vec![
        Filter {
            kinds: Some(vec![40, 41]),
            limit: Some(RELAY_FILTER_LIMIT),
            ..Default::default()
        },
        deletion_filter(deletions_since),
    ]
}

/// Filters for the reaction subscription: kind-7 reactions and kind-5
/// deletions as separate filters, for the reason given in
/// [`channel_sync_filters`]. Reactions are not cached between sessions, so
/// they are fetched in full; only the deletion filter takes `deletions_since`.
pub fn reaction_sync_filters(deletions_since: Option<u64>) -> Vec<Filter> {
    vec![
        Filter {
            kinds: Some(vec![7]),
            limit: Some(RELAY_FILTER_LIMIT),
            ..Default::default()
        },
        deletion_filter(deletions_since),
    ]
}

/// Filters for the message-count subscription: one `#e` filter per zone over
/// that zone's known channel ids, then a broad kind-42 catch-all for messages
/// whose channel is not known yet (ADR-092).
///
/// A single broad filter shares one row budget between every zone the reader
/// can see, so a busy zone pushes a quiet zone's history out of the result.
/// Grouping by zone gives each zone its own `RELAY_FILTER_LIMIT`. Channels whose
/// section maps to no zone share a group. When there are more groups than the
/// relay accepts filters, the overflow groups are merged into the last one.
/// `channels` is `(channel id, section)`.
pub fn message_sync_filters(channels: &[(String, String)], zones: &[Zone]) -> Vec<Filter> {
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    for (id, section) in channels {
        let zone = crate::stores::zones::section_to_zone(section, zones).unwrap_or_default();
        match groups.iter_mut().find(|(z, _)| *z == zone) {
            Some((_, ids)) => {
                if !ids.contains(id) {
                    ids.push(id.clone());
                }
            }
            None => groups.push((zone, vec![id.clone()])),
        }
    }
    groups.sort_by(|a, b| a.0.cmp(&b.0));
    let max_groups = RELAY_MAX_FILTERS - 1;
    if groups.len() > max_groups {
        let overflow: Vec<String> = groups
            .split_off(max_groups)
            .into_iter()
            .flat_map(|(_, ids)| ids)
            .collect();
        if let Some((_, ids)) = groups.last_mut() {
            ids.extend(overflow);
        }
    }
    let mut filters: Vec<Filter> = groups
        .into_iter()
        .map(|(_, ids)| Filter {
            kinds: Some(vec![42]),
            limit: Some(zone_sync_limit(ids.len())),
            e_tags: Some(ids),
            ..Default::default()
        })
        .collect();
    filters.push(Filter {
        kinds: Some(vec![42]),
        limit: Some(HISTORY_PAGE),
        ..Default::default()
    });
    filters
}

/// Row budget of one zone's boot-sync filter: [`SYNC_PER_CHANNEL`] per
/// channel, at most [`RELAY_FILTER_LIMIT`]. History beyond it is paged in by
/// the channel page ([`ChannelStore::load_older`]); the boot sync only feeds
/// the home view, and every envelope it fetches is decrypted on arrival.
pub fn zone_sync_limit(channels: usize) -> u64 {
    (channels as u64)
        .saturating_mul(SYNC_PER_CHANNEL)
        .clamp(SYNC_PER_CHANNEL, RELAY_FILTER_LIMIT)
}

/// Event ids referenced by a kind-5 deletion's `["e", <id>]` tags, lowercased.
///
/// Non-kind-5 events, and kind-5s carrying no `e` tag, yield an empty list — a
/// no-op fold. (Replaceable-event `a` tags used elsewhere, e.g. calendar
/// deletions, are ignored here; forum posts are addressed by event id.)
pub fn deletion_targets(event: &NostrEvent) -> Vec<String> {
    if event.kind != 5 {
        return Vec::new();
    }
    event
        .tags
        .iter()
        .filter(|t| t.len() >= 2 && t[0] == "e")
        .map(|t| t[1].to_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {

    /// A post in its channel list, its topic's list and the section's root
    /// list is one post, under its channel; a post only a topic list holds
    /// is attributed by its tags.
    #[test]
    fn distinct_posts_counts_each_post_once_under_its_channel() {
        let cid = "c".repeat(64);
        let post = |id: &str| NostrEvent {
            id: id.to_string(),
            pubkey: "p".repeat(64),
            created_at: 1,
            kind: 42,
            tags: vec![vec!["e".into(), cid.clone(), String::new(), "root".into()]],
            content: "hi".into(),
            sig: String::new(),
        };
        let root = post(&"a".repeat(64));
        let mut upper = root.clone();
        upper.id = upper.id.to_ascii_uppercase();
        let only_in_topic = post(&"b".repeat(64));
        let mut lists = HashMap::new();
        lists.insert(cid.clone(), vec![root.clone()]);
        lists.insert(topic_key(&root.id), vec![upper, only_in_topic.clone()]);
        lists.insert(roots_key(&cid), vec![root.clone()]);

        let mut posts = distinct_posts(&lists);
        posts.sort_by(|a, b| a.1.id.cmp(&b.1.id));
        assert_eq!(posts.len(), 2);
        assert_eq!(posts[0].0.as_deref(), Some(cid.as_str()));
        assert_eq!(posts[0].1.id, root.id, "the channel list's copy wins");
        assert_eq!(posts[1].0.as_deref(), Some(cid.as_str()));
        assert_eq!(posts[1].1.id, only_in_topic.id);
        assert!(posts
            .iter()
            .all(|(c, _)| c.as_deref().is_some_and(is_channel_key)));
    }

    #[test]
    fn list_keys_are_not_channels() {
        assert!(is_channel_key(&"c".repeat(64)));
        assert!(!is_channel_key(&topic_key("R")));
        assert!(!is_channel_key(&roots_key("c")));
    }
    use super::*;

    // --- subscription shape (regression: deletions crowded out channels) ---

    fn kinds(f: &Filter) -> Vec<u64> {
        f.kinds.clone().unwrap_or_default()
    }

    /// No sync filter may share kind 5 with another kind, and every one states
    /// its limit: the relay returns only the newest rows of a filter across
    /// all its kinds, and an unset limit falls back to the relay's 500.
    fn assert_isolated_and_limited(filters: &[Filter]) {
        assert!(!filters.is_empty());
        assert!(filters.len() <= RELAY_MAX_FILTERS);
        for f in filters {
            let k = kinds(f);
            assert!(
                !k.contains(&5) || k == vec![5],
                "kind 5 shares a filter with {k:?}"
            );
            let limit = f.limit.expect("every sync filter states its limit");
            assert!(
                (1..=RELAY_FILTER_LIMIT).contains(&limit),
                "filter {k:?} has limit {limit}"
            );
        }
    }

    const MARKER: u64 = 1_790_000_000;

    #[test]
    fn channel_definitions_never_share_a_filter_with_deletions() {
        for since in [None, Some(MARKER)] {
            let f = channel_sync_filters(since);
            assert_isolated_and_limited(&f);
            assert_eq!(kinds(&f[0]), vec![40, 41], "channels come first");
            assert!(
                f.iter().any(|x| kinds(x) == vec![5]),
                "deletions still synced"
            );
        }
    }

    #[test]
    fn reactions_never_share_a_filter_with_deletions() {
        for since in [None, Some(MARKER)] {
            let f = reaction_sync_filters(since);
            assert_isolated_and_limited(&f);
            assert!(f.iter().any(|x| kinds(x) == vec![7]));
            assert!(f.iter().any(|x| kinds(x) == vec![5]));
        }
    }

    /// The marker narrows the deletion filter only: channel definitions and
    /// reactions are always fetched in full.
    #[test]
    fn only_the_deletion_filters_carry_the_marker() {
        for f in channel_sync_filters(Some(MARKER))
            .into_iter()
            .chain(reaction_sync_filters(Some(MARKER)))
        {
            let expected = (kinds(&f) == vec![5]).then_some(MARKER);
            assert_eq!(f.since, expected, "filter {:?}", kinds(&f));
            assert_eq!(f.until, None);
        }
    }

    #[test]
    fn a_deletion_page_is_isolated_limited_and_bounded_above() {
        let f = deletion_page_filter(Some(MARKER), MARKER + 99);
        assert_isolated_and_limited(std::slice::from_ref(&f));
        assert_eq!(kinds(&f), vec![5]);
        assert_eq!(f.since, Some(MARKER));
        assert_eq!(f.until, Some(MARKER + 99));
    }

    #[test]
    fn without_a_marker_no_filter_has_since() {
        for f in channel_sync_filters(None)
            .into_iter()
            .chain(reaction_sync_filters(None))
        {
            assert_eq!(f.since, None, "filter {:?}", kinds(&f));
        }
    }

    #[test]
    fn the_channel_filter_serialises_with_its_own_limit() {
        let json = serde_json::to_value(channel_sync_filters(None)).unwrap();
        assert_eq!(
            json,
            serde_json::json!([
                {"kinds": [40, 41], "limit": RELAY_FILTER_LIMIT},
                {"kinds": [5], "limit": RELAY_FILTER_LIMIT}
            ])
        );
        let json = serde_json::to_value(channel_sync_filters(Some(MARKER))).unwrap();
        assert_eq!(
            json,
            serde_json::json!([
                {"kinds": [40, 41], "limit": RELAY_FILTER_LIMIT},
                {"kinds": [5], "since": MARKER, "limit": RELAY_FILTER_LIMIT}
            ])
        );
    }

    fn zones() -> Vec<Zone> {
        serde_json::from_str(
            r#"[{"id":"zone1","display_name":"Welcome","required_cohorts":[]},
                {"id":"zone2","display_name":"Two","required_cohorts":["zone2"]},
                {"id":"zone3","display_name":"Family","required_cohorts":["family"]}]"#,
        )
        .unwrap()
    }

    fn chan(id: &str, section: &str) -> (String, String) {
        (id.to_string(), section.to_string())
    }

    #[test]
    fn message_sync_gives_each_zone_its_own_budget_plus_a_catch_all() {
        let chans = [
            chan("c-intro", "zone1-introductions"),
            chan("c-rants", "zone2-rants"),
            chan("c-family", "zone3-chat"),
            chan("c-support", "zone1-support"),
        ];
        let f = message_sync_filters(&chans, &zones());
        assert_isolated_and_limited(&f);
        assert!(f.iter().all(|x| kinds(x) == vec![42]));
        let groups: Vec<Vec<String>> = f.iter().filter_map(|x| x.e_tags.clone()).collect();
        assert_eq!(
            groups,
            vec![
                vec!["c-intro".to_string(), "c-support".to_string()],
                vec!["c-rants".to_string()],
                vec!["c-family".to_string()],
            ]
        );
        let last = f.last().unwrap();
        assert!(
            last.e_tags.is_none(),
            "the catch-all comes last and is broad"
        );
    }

    #[test]
    fn message_sync_with_no_known_channels_is_the_catch_all_alone() {
        let f = message_sync_filters(&[], &zones());
        assert_eq!(f.len(), 1);
        assert!(f[0].e_tags.is_none());
        assert_eq!(f[0].limit, Some(HISTORY_PAGE));
    }

    #[test]
    fn a_zone_sync_filter_budgets_per_channel_within_the_relay_cap() {
        assert_eq!(zone_sync_limit(1), SYNC_PER_CHANNEL);
        assert_eq!(zone_sync_limit(3), 3 * SYNC_PER_CHANNEL);
        assert_eq!(zone_sync_limit(10_000), RELAY_FILTER_LIMIT);
        let chans = [chan("a", "zone2-rants"), chan("b", "zone2-rants")];
        let f = message_sync_filters(&chans, &zones());
        assert_eq!(f[0].limit, Some(2 * SYNC_PER_CHANNEL));
    }

    // --- paged history ---

    fn evt(id: &str, created_at: u64) -> NostrEvent {
        NostrEvent {
            id: id.into(),
            pubkey: "p".into(),
            created_at,
            kind: 42,
            tags: vec![],
            content: String::new(),
            sig: String::new(),
        }
    }

    #[test]
    fn ordered_insert_keeps_time_order_dedupes_and_appends_after_equals() {
        let mut v = Vec::new();
        for (id, t) in [("c", 30), ("a", 10), ("b2", 20), ("b1", 20), ("d", 40)] {
            assert!(insert_message(&mut v, evt(id, t)));
        }
        assert!(!insert_message(&mut v, evt("b1", 20)), "duplicate id");
        let order: Vec<&str> = v.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(order, vec!["a", "b2", "b1", "c", "d"]);
    }

    /// A relay holding `ts` (ascending) for one channel, answering the
    /// cursor's filters like the relay does: newest first, inclusive bounds.
    fn answer(ts: &[(String, u64)], f: &Filter) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = ts
            .iter()
            .filter(|(_, t)| f.since.is_none_or(|s| *t >= s) && f.until.is_none_or(|u| *t <= u))
            .cloned()
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(b.0.cmp(&a.0)));
        v.truncate(f.limit.unwrap() as usize);
        v
    }

    fn outcome(page: &[(String, u64)]) -> PageOutcome {
        PageOutcome {
            delivered: page.len() as u64,
            oldest: page.iter().map(|(_, t)| *t).min(),
        }
    }

    /// Walk a channel to its first message the way the channel page does.
    fn walk(ts: &[(String, u64)]) -> (std::collections::HashSet<String>, usize) {
        let mut held = std::collections::HashSet::new();
        let mut c = HistoryCursor::default();
        let first = answer(
            ts,
            &Filter {
                limit: Some(HISTORY_PAGE),
                ..Default::default()
            },
        );
        held.extend(first.iter().map(|(id, _)| id.clone()));
        c.record_first(outcome(&first));
        let mut requests = 1;
        while let Some(req) = c.next_request() {
            requests += 1;
            assert!(requests < 10_000, "the walk must terminate");
            c.loading = true;
            let page = answer(ts, &HistoryCursor::filter(req, &["c".into()]));
            held.extend(page.iter().map(|(id, _)| id.clone()));
            c.record(req, outcome(&page));
        }
        assert!(c.exhausted);
        (held, requests)
    }

    #[test]
    fn paging_reaches_the_first_message_across_ties_without_loss() {
        // Runs of equal seconds straddling page boundaries, and one run of
        // 250 messages in a single second (more than a page).
        let mut ts = Vec::new();
        let mut t = 1_000;
        for i in 0..2_000 {
            if i % 3 != 0 && !(900..1_150).contains(&i) {
                t += 1;
            }
            ts.push((format!("m{i:05}"), t));
        }
        let (held, requests) = walk(&ts);
        assert_eq!(held.len(), ts.len(), "every message, once");
        assert!(
            requests <= 2_000 / HISTORY_PAGE as usize + 5,
            "{requests} requests"
        );
    }

    #[test]
    fn a_short_first_page_is_the_whole_history() {
        let ts: Vec<(String, u64)> = (0..42).map(|i| (format!("m{i}"), 100 + i)).collect();
        let (held, requests) = walk(&ts);
        assert_eq!((held.len(), requests), (42, 1));
    }

    #[test]
    fn an_exact_multiple_of_the_page_ends_on_an_empty_page() {
        let ts: Vec<(String, u64)> = (0..300).map(|i| (format!("m{i}"), 100 + i)).collect();
        let (held, _) = walk(&ts);
        assert_eq!(held.len(), 300);
    }

    // --- bounded history window ---

    /// A channel walked through a bounded window against a relay holding
    /// `relay` (ascending): the store as a sorted list, the cursor, and every
    /// id the window has held.
    struct WindowSim {
        relay: Vec<(String, u64)>,
        store: Vec<NostrEvent>,
        cursor: HistoryCursor,
        max: usize,
        held: std::collections::HashSet<String>,
        peak: usize,
    }

    impl WindowSim {
        fn new(relay: Vec<(String, u64)>, max: usize) -> Self {
            let mut s = WindowSim {
                relay,
                store: Vec::new(),
                cursor: HistoryCursor::default(),
                max,
                held: Default::default(),
                peak: 0,
            };
            let first = answer(
                &s.relay,
                &Filter {
                    limit: Some(HISTORY_PAGE),
                    ..Default::default()
                },
            );
            s.insert(&first);
            s.cursor.record_first(outcome(&first));
            s
        }

        /// Insert as `apply_page` does: only what the window admits.
        fn insert(&mut self, page: &[(String, u64)]) {
            for (id, ts) in page {
                if self.cursor.admits(*ts) && insert_message(&mut self.store, evt(id, *ts)) {
                    self.held.insert(id.clone());
                }
            }
            self.check();
        }

        fn check(&mut self) {
            let ids: std::collections::HashSet<&String> =
                self.store.iter().map(|e| &e.id).collect();
            assert_eq!(
                ids.len(),
                self.store.len(),
                "no message twice in the window"
            );
            assert!(self
                .store
                .windows(2)
                .all(|w| w[0].created_at <= w[1].created_at));
            self.peak = self.peak.max(self.store.len());
        }

        fn older_step(&mut self) -> bool {
            let Some(req) = self.cursor.next_request() else {
                return false;
            };
            let page = answer(&self.relay, &HistoryCursor::filter(req, &["c".into()]));
            self.insert(&page);
            self.cursor.record(req, outcome(&page));
            if let Some((cut, _)) = evict_newest(&mut self.store, self.max) {
                self.cursor.on_evicted_newest(cut);
            }
            self.check();
            true
        }

        fn newer_step(&mut self) -> bool {
            let Some(seg) = self.cursor.next_newer() else {
                return false;
            };
            let page = answer(
                &self.relay,
                &HistoryCursor::newer_filter(seg, &["c".into()]),
            );
            match self.cursor.record_newer(seg, outcome(&page)) {
                NewerOutcome::Applied => {
                    self.insert(&page);
                    if let Some((cut, _)) = evict_oldest(&mut self.store, self.max) {
                        self.cursor.on_evicted_oldest(cut);
                    }
                }
                NewerOutcome::Reset => {
                    self.store.clear();
                    self.cursor = HistoryCursor::default();
                    self.cursor.record_first(outcome(&page));
                    self.insert(&page);
                }
            }
            self.check();
            true
        }

        /// A live post: on the relay at once, in the window only if admitted.
        fn live(&mut self, id: String, ts: u64) {
            self.relay.push((id.clone(), ts));
            self.insert(&[(id, ts)]);
        }

        fn ids_in_window(&self) -> std::collections::HashSet<String> {
            self.store.iter().map(|e| e.id.clone()).collect()
        }
    }

    /// 3,000 messages with runs of equal seconds straddling page and cut
    /// boundaries, and one 250-message second (longer than a page).
    fn tied_history() -> Vec<(String, u64)> {
        let mut v = Vec::new();
        let mut t = 10_000;
        for i in 0..3_000 {
            if i % 4 != 0 && !(1_200..1_450).contains(&i) {
                t += 1;
            }
            v.push((format!("m{i:05}"), t));
        }
        v
    }

    fn all_ids(relay: &[(String, u64)]) -> std::collections::HashSet<String> {
        relay.iter().map(|(id, _)| id.clone()).collect()
    }

    #[test]
    fn evicting_cuts_only_between_seconds() {
        let mut v: Vec<NostrEvent> = [(1, "a"), (2, "b"), (2, "c"), (2, "d"), (3, "e")]
            .iter()
            .map(|(t, id)| evt(id, *t))
            .collect();
        let (cut, gone) = evict_newest(&mut v.clone(), 2).unwrap();
        assert_eq!(
            (cut, gone.len()),
            (2, 4),
            "the whole second 2 goes, not half of it"
        );
        let (cut, gone) = evict_oldest(&mut v, 2).unwrap();
        assert_eq!(cut, 2);
        assert_eq!(gone.len(), 4);
        assert_eq!(v.len(), 1);
        let mut one_second: Vec<NostrEvent> = (0..5).map(|i| evt(&format!("x{i}"), 7)).collect();
        assert!(
            evict_newest(&mut one_second, 2).is_none(),
            "never empty the window"
        );
        assert!(evict_oldest(&mut one_second, 2).is_none());
    }

    #[test]
    fn the_window_walks_to_the_first_message_and_back_without_loss() {
        let relay = tied_history();
        let max = 300;
        let mut s = WindowSim::new(relay.clone(), max);
        let mut steps = 0;
        while s.older_step() {
            steps += 1;
            assert!(steps < 1_000);
        }
        assert!(s.cursor.exhausted);
        assert!(
            s.ids_in_window().contains("m00000"),
            "the first message is in the window"
        );
        assert_eq!(
            s.held,
            all_ids(&relay),
            "every message passed through the window"
        );
        assert!(
            s.cursor.newer_from.is_some(),
            "detached at the start of history"
        );

        s.held.clear();
        while s.newer_step() {
            steps += 1;
            assert!(steps < 2_000);
        }
        assert_eq!(s.cursor.newer_from, None, "back to the newest");
        assert!(s.cursor.newer.is_empty());
        assert!(
            s.ids_in_window().contains("m02999"),
            "the newest message is back"
        );
        let newer_half: std::collections::HashSet<String> = relay
            .iter()
            .filter(|(_, t)| *t > relay[1_000].1)
            .map(|(id, _)| id.clone())
            .collect();
        assert!(
            newer_half.is_subset(&s.held),
            "every evicted page came back"
        );
        // Bounded: each page lands, then the window is cut back to `max`; a
        // page plus the 250-message second is the most it ever briefly holds.
        assert!(
            s.peak <= max + 250 + HISTORY_PAGE as usize,
            "peak {}",
            s.peak
        );
        assert!(s.store.len() <= max);
    }

    #[test]
    fn live_posts_while_detached_wait_for_the_reload() {
        let relay = tied_history();
        let mut s = WindowSim::new(relay, 300);
        for _ in 0..10 {
            s.older_step();
        }
        assert!(s.cursor.newer_from.is_some());
        let before = s.store.len();
        for i in 0..20 {
            s.live(format!("live{i:02}"), 50_000 + i);
        }
        assert_eq!(
            s.store.len(),
            before,
            "nothing newer than a detached window is inserted"
        );
        while s.newer_step() {}
        let w = s.ids_in_window();
        assert!(
            (0..20).all(|i| w.contains(&format!("live{i:02}"))),
            "the newest segment brings them"
        );
    }

    #[test]
    fn an_overflowing_newest_segment_restarts_from_the_newest_page() {
        let relay = tied_history();
        let mut s = WindowSim::new(relay, 300);
        for _ in 0..10 {
            s.older_step();
        }
        for i in 0..1_500u64 {
            s.live(format!("live{i:04}"), 50_000 + i);
        }
        while s.newer_step() {}
        assert_eq!(s.cursor.newer_from, None);
        let w = s.ids_in_window();
        assert!(w.contains("live1499"), "the newest post is shown");
        // The restart dropped the window; older paging covers the gap.
        s.held.clear();
        let mut n = 0;
        while s.older_step() {
            n += 1;
            if s.held.contains("live0000") {
                break;
            }
            assert!(n < 100);
        }
        assert!(
            s.held.contains("live0000"),
            "older paging reaches the posts the restart skipped"
        );
    }

    #[test]
    fn a_timed_out_newer_reload_keeps_its_segment() {
        let relay = tied_history();
        let mut s = WindowSim::new(relay, 300);
        for _ in 0..10 {
            s.older_step();
        }
        let seg = s.cursor.next_newer().expect("a segment to reload");
        // The request goes out and is abandoned after PAGE_TIMEOUT_MS: the
        // store only releases `loading`, nothing is recorded or popped.
        s.cursor.loading = true;
        assert_eq!(s.cursor.next_newer(), None, "one request at a time");
        assert_eq!(s.cursor.next_request(), None, "in either direction");
        s.cursor.loading = false;
        assert_eq!(
            s.cursor.next_newer(),
            Some(seg),
            "the same segment is retried"
        );
    }

    #[test]
    fn a_channel_total_is_the_count_plus_distinct_newer_messages() {
        let mut t = ChannelTotal {
            counted: None,
            as_of: 100,
            newer_ids: HashSet::new(),
        };
        assert_eq!(t.total(), None, "no figure before the count answers");
        t.newer_ids.insert("x".into());
        t.newer_ids.insert("x".into());
        t.newer_ids.insert("y".into());
        t.counted = Some(210_000);
        assert_eq!(t.total(), Some(210_002), "newer ids counted once each");
    }

    #[test]
    fn the_window_size_is_clamped() {
        assert_eq!(clamp_window(10), HISTORY_WINDOW_MIN);
        assert_eq!(clamp_window(5_000), 5_000);
        const { assert!(THREAD_WINDOW >= HISTORY_WINDOW_MIN && THREAD_WINDOW < HISTORY_WINDOW) };
        const { assert!(HISTORY_WINDOW >= HISTORY_WINDOW_MIN) };
    }

    #[test]
    fn nothing_is_requested_before_the_first_page_or_while_loading() {
        let mut c = HistoryCursor::default();
        assert_eq!(c.next_request(), None);
        c.record_first(PageOutcome {
            delivered: HISTORY_PAGE,
            oldest: Some(500),
        });
        assert_eq!(c.next_request(), Some(PageRequest::Older { until: 500 }));
        c.loading = true;
        assert_eq!(c.next_request(), None);
    }

    #[test]
    fn message_sync_never_exceeds_the_relay_filter_cap() {
        let many: Vec<Zone> = serde_json::from_str(&format!(
            "[{}]",
            (0..15)
                .map(|i| format!(r#"{{"id":"z{i:02}","display_name":"Z","required_cohorts":[]}}"#))
                .collect::<Vec<_>>()
                .join(",")
        ))
        .unwrap();
        let chans: Vec<(String, String)> = (0..15)
            .map(|i| chan(&format!("c{i:02}"), &format!("z{i:02}-s")))
            .collect();
        let f = message_sync_filters(&chans, &many);
        assert_isolated_and_limited(&f);
        assert_eq!(f.len(), RELAY_MAX_FILTERS);
        let covered: usize = f
            .iter()
            .filter_map(|x| x.e_tags.as_ref())
            .map(Vec::len)
            .sum();
        assert_eq!(covered, 15, "every channel stays in some filter");
    }

    /// Build a test event with string tags.
    fn ev(kind: u64, created_at: u64, tags: &[&[&str]], content: &str) -> NostrEvent {
        NostrEvent {
            id: format!("evt-{kind}-{created_at}"),
            pubkey: "pk".into(),
            created_at,
            kind,
            tags: tags
                .iter()
                .map(|t| t.iter().map(|s| s.to_string()).collect())
                .collect(),
            content: content.to_string(),
            sig: String::new(),
        }
    }

    fn channel(id: &str, name: &str, created_at: u64) -> ChannelMeta {
        ChannelMeta {
            id: id.into(),
            name: name.into(),
            description: "orig desc".into(),
            section: "music".into(),
            section_tag: "music".into(),
            picture: String::new(),
            created_at,
        }
    }

    #[test]
    fn pin_control_41_is_ignored() {
        // Pin: empty content + ["pin", eid] — must not read as a metadata edit,
        // or a pin would wipe the channel name.
        let e = ev(
            41,
            2000,
            &[&["e", "chan", "", "root"], &["pin", "msg1"]],
            "",
        );
        assert!(parse_meta_update(&e).is_none());
    }

    #[test]
    fn malformed_json_41_is_ignored() {
        let e = ev(41, 2000, &[&["e", "chan", "", "root"]], "not json at all");
        assert!(parse_meta_update(&e).is_none());
    }

    #[test]
    fn json_without_name_or_about_is_ignored() {
        // A 41 carrying only a picture (no name/about) is not a rename edit.
        let e = ev(
            41,
            2000,
            &[&["e", "chan", "", "root"]],
            r#"{"picture":"x.png"}"#,
        );
        assert!(parse_meta_update(&e).is_none());
    }

    #[test]
    fn missing_channel_tag_is_ignored() {
        let e = ev(41, 2000, &[&["section", "music"]], r#"{"name":"X"}"#);
        assert!(parse_meta_update(&e).is_none());
    }

    #[test]
    fn newer_41_wins() {
        let mut chans = vec![channel("chan", "Old Name", 1000)];
        let mut ts = HashMap::new();
        let e = ev(
            41,
            1500,
            &[&["e", "chan", "", "root"]],
            r#"{"name":"New Name","about":"New desc"}"#,
        );
        let u = parse_meta_update(&e).unwrap();
        assert!(fold_meta_into(&mut chans, &mut ts, &u));
        assert_eq!(chans[0].name, "New Name");
        assert_eq!(chans[0].description, "New desc");
        assert_eq!(ts.get("chan"), Some(&1500));
    }

    #[test]
    fn older_41_is_ignored_after_newer() {
        let mut chans = vec![channel("chan", "Old Name", 1000)];
        let mut ts = HashMap::new();
        let newer = parse_meta_update(&ev(
            41,
            1500,
            &[&["e", "chan", "", "root"]],
            r#"{"name":"New Name"}"#,
        ))
        .unwrap();
        let older = parse_meta_update(&ev(
            41,
            1200,
            &[&["e", "chan", "", "root"]],
            r#"{"name":"Stale Name"}"#,
        ))
        .unwrap();
        assert!(fold_meta_into(&mut chans, &mut ts, &newer));
        assert!(!fold_meta_into(&mut chans, &mut ts, &older));
        assert_eq!(chans[0].name, "New Name");
        assert_eq!(ts.get("chan"), Some(&1500));
    }

    #[test]
    fn unknown_channel_is_ignored() {
        let mut chans = vec![channel("chan", "Old Name", 1000)];
        let mut ts = HashMap::new();
        let u = parse_meta_update(&ev(
            41,
            1500,
            &[&["e", "other", "", "root"]],
            r#"{"name":"X"}"#,
        ))
        .unwrap();
        assert!(!fold_meta_into(&mut chans, &mut ts, &u));
        assert_eq!(chans[0].name, "Old Name");
    }

    #[test]
    fn edit_predating_channel_creation_is_ignored() {
        // Baseline for an unedited channel is its kind-40 created_at (1000); a
        // 41 stamped before creation must not apply.
        let mut chans = vec![channel("chan", "Old Name", 1000)];
        let mut ts = HashMap::new();
        let u = parse_meta_update(&ev(
            41,
            900,
            &[&["e", "chan", "", "root"]],
            r#"{"name":"Ghost"}"#,
        ))
        .unwrap();
        assert!(!fold_meta_into(&mut chans, &mut ts, &u));
        assert_eq!(chans[0].name, "Old Name");
    }

    #[test]
    fn picture_preserved_when_absent_and_updated_when_present() {
        let mut chans = vec![channel("chan", "Old", 1000)];
        chans[0].picture = "old.png".into();
        let mut ts = HashMap::new();
        // Name-only edit leaves the picture intact.
        let u1 = parse_meta_update(&ev(
            41,
            1100,
            &[&["e", "chan", "", "root"]],
            r#"{"name":"N1"}"#,
        ))
        .unwrap();
        fold_meta_into(&mut chans, &mut ts, &u1);
        assert_eq!(chans[0].picture, "old.png");
        // Edit carrying a picture updates it.
        let u2 = parse_meta_update(&ev(
            41,
            1200,
            &[&["e", "chan", "", "root"]],
            r#"{"name":"N2","picture":"new.png"}"#,
        ))
        .unwrap();
        fold_meta_into(&mut chans, &mut ts, &u2);
        assert_eq!(chans[0].picture, "new.png");
    }

    #[test]
    fn blank_name_edit_keeps_name_but_applies_about() {
        let mut chans = vec![channel("chan", "Keep Me", 1000)];
        let mut ts = HashMap::new();
        let u = parse_meta_update(&ev(
            41,
            1100,
            &[&["e", "chan", "", "root"]],
            r#"{"name":"   ","about":"fresh about"}"#,
        ))
        .unwrap();
        assert!(fold_meta_into(&mut chans, &mut ts, &u));
        assert_eq!(chans[0].name, "Keep Me");
        assert_eq!(chans[0].description, "fresh about");
    }

    #[test]
    fn pending_buffer_keeps_newest() {
        let mut pending = HashMap::new();
        let u1 = parse_meta_update(&ev(
            41,
            1200,
            &[&["e", "chan", "", "root"]],
            r#"{"name":"First"}"#,
        ))
        .unwrap();
        let u2 = parse_meta_update(&ev(
            41,
            1500,
            &[&["e", "chan", "", "root"]],
            r#"{"name":"Second"}"#,
        ))
        .unwrap();
        let u_old = parse_meta_update(&ev(
            41,
            1300,
            &[&["e", "chan", "", "root"]],
            r#"{"name":"Third"}"#,
        ))
        .unwrap();
        buffer_pending_meta(&mut pending, u1);
        buffer_pending_meta(&mut pending, u2);
        buffer_pending_meta(&mut pending, u_old);
        assert_eq!(pending.get("chan").unwrap().name.as_deref(), Some("Second"));
        assert_eq!(pending.get("chan").unwrap().created_at, 1500);
    }

    // -- kind-5 deletion folding --------------------------------------------
    //
    // The authorisation rules live in `stores::tombstones` and are tested
    // there; these cover the target extraction and the ordinary-post path.

    fn fold(
        msgs: &mut HashMap<String, Vec<NostrEvent>>,
        t: &mut Tombstones,
        del: &NostrEvent,
    ) -> bool {
        tombstones::fold_deletion(
            msgs,
            t,
            &del.pubkey,
            &deletion_targets(del),
            |_| false,
            |_| false,
        )
    }

    #[test]
    fn kind5_removes_target_message() {
        let target = ev(42, 100, &[&["e", "chan", "", "root"]], "delete me");
        let keep = ev(42, 200, &[&["e", "chan", "", "root"]], "keep me");
        let tid = target.id.clone();
        let mut msgs: HashMap<String, Vec<NostrEvent>> = HashMap::new();
        msgs.insert("chan".into(), vec![target, keep]);
        let mut tomb = Tombstones::default();

        let del = ev(5, 300, &[&["e", tid.as_str()]], "");
        assert_eq!(deletion_targets(&del), vec![tid.to_lowercase()]);
        assert!(fold(&mut msgs, &mut tomb, &del));
        assert_eq!(msgs["chan"].len(), 1);
        assert_eq!(msgs["chan"][0].content, "keep me");
        assert!(tomb.names(&tid));
    }

    #[test]
    fn kind5_before_target_suppresses_later_message() {
        // Deletion lands with the target not yet stored (backfill order): nothing
        // is removed, but the tombstone must suppress the message when it arrives.
        let late = ev(42, 100, &[&["e", "chan", "", "root"]], "arrives late");
        let lid = late.id.clone();
        let mut msgs: HashMap<String, Vec<NostrEvent>> = HashMap::new();
        let mut tomb = Tombstones::default();

        let del = ev(5, 90, &[&["e", lid.as_str()]], "");
        assert!(!fold(&mut msgs, &mut tomb, &del));
        assert!(!tombstones::admits(&tomb, &lid, Target::Ordinary, |_| {
            false
        }));
    }

    #[test]
    fn kind5_without_e_tag_is_noop() {
        let del = ev(5, 100, &[&["p", "somebody"]], "");
        assert!(deletion_targets(&del).is_empty());

        let keep = ev(42, 100, &[&["e", "chan", "", "root"]], "keep");
        let mut msgs: HashMap<String, Vec<NostrEvent>> = HashMap::new();
        msgs.insert("chan".into(), vec![keep]);
        let mut tomb = Tombstones::default();
        assert!(!fold(&mut msgs, &mut tomb, &del));
        assert_eq!(msgs["chan"].len(), 1);
        assert_eq!(tomb, Tombstones::default());
    }

    #[test]
    fn kind5_targets_are_lowercased_for_a_casing_proof_gate() {
        let del = ev(5, 100, &[&["e", "DEADBEEF"]], "");
        let mut msgs: HashMap<String, Vec<NostrEvent>> = HashMap::new();
        let mut tomb = Tombstones::default();
        fold(&mut msgs, &mut tomb, &del);
        for id in ["deadbeef", "DEADBEEF", "DeAdBeEf"] {
            assert!(
                !tombstones::admits(&tomb, id, Target::Ordinary, |_| false),
                "casing bypassed the gate"
            );
        }
        assert!(tombstones::admits(
            &tomb,
            "cafebabe",
            Target::Ordinary,
            |_| false
        ));
    }

    #[test]
    fn kind5_unknown_id_removes_nothing() {
        let keep = ev(42, 100, &[&["e", "chan", "", "root"]], "keep");
        let mut msgs: HashMap<String, Vec<NostrEvent>> = HashMap::new();
        msgs.insert("chan".into(), vec![keep]);
        let mut tomb = Tombstones::default();

        let del = ev(5, 200, &[&["e", "nonexistent-id"]], "");
        assert!(!fold(&mut msgs, &mut tomb, &del));
        assert_eq!(msgs["chan"].len(), 1);
        // Still recorded, so a message with that id could never appear later.
        assert!(tomb.names("nonexistent-id"));
    }

    // -- ADR-2037: routed section, cache healing -------------------------------

    const PIN: &str = "9999999999999999999999999999999999999999999999999999999999999999";

    fn pin_zones(pinned: bool) -> Vec<Zone> {
        let mut zones: Vec<Zone> = serde_json::from_str(
            r#"[{"id":"open","required_cohorts":["members"],"encrypted":true},
                {"id":"staff","visibility":"hidden","encrypted":true}]"#,
        )
        .unwrap();
        if pinned {
            zones[1].channels = vec![PIN.to_string()];
        }
        zones
    }

    #[test]
    fn a_cache_from_before_section_tag_loads_and_routes_as_before() {
        // The exact shape older builds wrote: no `section_tag`.
        let old = format!(
            r#"{{"channels":[{{"id":"{PIN}","name":"Agents","description":"","section":"open-agents","picture":"","created_at":1}},
                             {{"id":"c2","name":"Music","description":"","section":"","picture":"","created_at":2}}],
                "last_active":{{}},"synced_at":5}}"#
        );
        let mut data: CachedData = serde_json::from_str(&old).unwrap();
        assert_eq!(data.channels[0].section_tag, "");
        heal_cached_sections(&mut data.channels, &pin_zones(false));
        assert_eq!(data.channels[0].section, "open-agents");
        assert_eq!(data.channels[0].section_tag, "open-agents");
        assert_eq!(data.channels[1].section, "");
        assert_eq!(data.channels[1].section_tag, "");
        // The same old cache under a pin routes the channel to the pinned zone.
        let mut data: CachedData = serde_json::from_str(&old).unwrap();
        heal_cached_sections(&mut data.channels, &pin_zones(true));
        assert_eq!(data.channels[0].section, "staff");
        assert_eq!(data.channels[0].section_tag, "open-agents");
    }

    #[test]
    fn removing_a_pin_heals_the_cached_section() {
        let mut list = vec![ChannelMeta {
            section: String::new(),
            section_tag: "open-agents".into(),
            ..channel(PIN, "Agents", 1)
        }];
        heal_cached_sections(&mut list, &pin_zones(true));
        assert_eq!(list[0].section, "staff");
        // Saved while pinned, then loaded after the pin was removed.
        let saved = serde_json::to_string(&CachedData {
            channels: list.into_iter().map(ChannelMeta::cache_form).collect(),
            ..CachedData::default()
        })
        .unwrap();
        let mut back: CachedData = serde_json::from_str(&saved).unwrap();
        heal_cached_sections(&mut back.channels, &pin_zones(false));
        assert_eq!(back.channels[0].section, "open-agents");
        // Loading twice changes nothing more (healing is idempotent).
        let again = back.channels.clone();
        heal_cached_sections(&mut back.channels, &pin_zones(false));
        assert_eq!(back.channels[0].section, again[0].section);
    }

    #[test]
    fn the_cache_form_holds_the_raw_tag_for_builds_without_pins() {
        let pinned = ChannelMeta {
            section: "staff".into(),
            section_tag: "open-agents".into(),
            ..channel(PIN, "Agents", 1)
        };
        let json = serde_json::to_value(pinned.cache_form()).unwrap();
        assert_eq!(json["section"], "open-agents");
        assert_eq!(json["section_tag"], "open-agents");
    }
}

#[cfg(test)]
mod section_stats_total_tests {
    //! PR #134 review finding 3: a live reply must move a row whose count
    //! came from the section stats.
    use super::*;
    use crate::topics::section_stats::SectionStats;

    fn reply_ev(id: &str, root: &str, ts: u64, edit: Option<&str>) -> NostrEvent {
        let mut tags = crate::topics::thread::topic_reply_tags("chan", root, "", None);
        if let Some(t) = edit {
            tags.push(vec!["e".into(), t.into(), String::new(), "edit".into()]);
        }
        NostrEvent {
            id: id.into(),
            pubkey: "p".into(),
            created_at: ts,
            kind: 42,
            tags,
            content: String::new(),
            sig: String::new(),
        }
    }

    #[test]
    fn stats_seed_a_total_that_live_replies_then_grow() {
        let stats = SectionStats::parse(&serde_json::json!({
            "channel": "chan", "as_of": 1_000,
            "fields": ["id", "created_at", "last_at", "last_pubkey", "replies", "original"],
            "topics": [["ROOT", 5, 900, "p", 50, null], ["env", 5, 800, null, 3, "orig"],
                       ["big", 5, 700, null, null, null]]
        }))
        .unwrap();
        let seeds = section_stats_totals(&stats);
        assert_eq!(
            seeds,
            vec![
                ("topic:root".to_string(), 50),
                ("topic:env".to_string(), 3),
                ("topic:orig".to_string(), 3)
            ],
            "no seed for an unknown count"
        );
        // The store's total for a seeded topic, then a live reply after the
        // answer, then the same reply again and an older one: 51.
        let mut t = ChannelTotal {
            counted: Some(50),
            as_of: stats.as_of,
            newer_ids: HashSet::new(),
        };
        for (id, ts) in [("r1", 1_005), ("r1", 1_005), ("r0", 990)] {
            if ts > t.as_of {
                t.newer_ids.insert(id.to_string());
            }
        }
        assert_eq!(t.total(), Some(51));
        // Which topic a live message grows: a reply's, never an edit's.
        assert_eq!(reply_topic(&reply_ev("r1", "ROOT", 1, None)).as_deref(), Some("root"));
        assert_eq!(reply_topic(&reply_ev("e1", "ROOT", 1, Some("r1"))), None);
    }
}
