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
    pub section: String,
    pub picture: String,
    pub created_at: u64,
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
    /// What each `ensure_subscribed` REQ delivered by its receipts, so the
    /// page that knows whether the channel is gated can record its first
    /// page ([`ChannelStore::settle_first_page`]).
    first_pages: StoredValue<HashMap<String, FirstPageSnapshot>>,
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
            first_pages: StoredValue::new(HashMap::new()),
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
    /// [`crate::pages::ChannelPage`].
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
        json.ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save_cache(&self) {
        let data = CachedData {
            channels: self.channels.get_untracked(),
            last_active: self.last_active.get_untracked(),
            meta_updated_at: self.meta_updated_at.get_untracked(),
            synced_at: (js_sys::Date::now() / 1000.0) as u64,
        };
        if let Ok(json) = serde_json::to_string(&data) {
            let _ = LocalStorage::set(CACHE_KEY, json);
        }
    }

    /// Start relay subscriptions. Called once from App root after relay connects.
    pub(crate) fn start_sync(&self, relay: &RelayConnection) {
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
                        section,
                        picture,
                        created_at: event.created_at,
                    };

                    let mut inserted = false;
                    channels_sig.update(|list| {
                        if !list.iter().any(|c| c.id == meta.id) {
                            list.push(meta);
                            inserted = true;
                        }
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
                channels_sig.update(|list| {
                    list.retain(|c| ids.contains(&c.id));
                });
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
    pub(crate) fn start_msg_sync(&self, relay: &RelayConnection) {
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
                channel_msgs.update(|m| {
                    let events = m.entry(cid.clone()).or_insert_with(Vec::new);
                    newly_added = insert_message(events, event);
                });
                if newly_added {
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
            let event = crate::zone_crypto::store::prepare_incoming(zone_keys, event);
            // A restored sealed original carries the original id (ADR-2017).
            if !store.admits_message(zone_keys, &event) {
                return;
            }
            let mut newly_added = false;
            let event_ts = event.created_at;
            channel_msgs.update(|m| {
                let events = m.entry(cid.clone()).or_insert_with(Vec::new);
                newly_added = insert_message(events, event);
            });
            if newly_added {
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
    pub fn apply_page(&self, events: Vec<(String, NostrEvent)>) {
        if events.is_empty() {
            return;
        }
        let mut newest: HashMap<String, u64> = HashMap::new();
        self.channel_messages.update(|m| {
            for (cid, ev) in events {
                let ts = ev.created_at;
                if insert_message(m.entry(cid.clone()).or_default(), ev) {
                    let n = newest.entry(cid).or_insert(0);
                    *n = (*n).max(ts);
                }
            }
        });
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

    /// Fetch the next older page of channel `cid` (see [`HistoryCursor`]) as
    /// a one-shot REQ over the channel's `#e` `needles`, closed on its
    /// answer. Returns whether a request went out (`false` before the first
    /// page, while one is in flight, or at the start of history).
    ///
    /// With `wait_auth` (a signed-in reader), only an authenticated answer
    /// counts: before NIP-42 AUTH the relay withholds gated zones, and an
    /// empty anonymous answer must not read as the start of history; the
    /// relay replays the REQ after AUTH. `before_apply` runs just before the
    /// page enters the store, so the page can anchor its scroll position.
    /// A request with no answer within [`PAGE_TIMEOUT_MS`] is abandoned and
    /// the cursor released, so the next scroll retries.
    pub fn load_older(
        &self,
        relay: &RelayConnection,
        cid: &str,
        needles: Vec<String>,
        wait_auth: bool,
        before_apply: Rc<dyn Fn()>,
    ) -> bool {
        let Some(req) = self
            .history
            .with_untracked(|m| m.get(cid).and_then(HistoryCursor::next_request))
        else {
            return false;
        };
        self.history.update(|m| {
            if let Some(c) = m.get_mut(cid) {
                c.loading = true;
            }
        });

        #[derive(Default)]
        struct Buf {
            delivered: u64,
            oldest: Option<u64>,
            events: Vec<(String, NostrEvent)>,
            done: bool,
            sub: Option<String>,
        }
        let buf = Rc::new(RefCell::new(Buf::default()));
        let store = *self;
        let zone_keys = crate::zone_crypto::store::try_use_zone_key_store();
        let key = cid.to_string();

        let on_event = {
            let buf = buf.clone();
            let key = key.clone();
            Rc::new(move |ev: NostrEvent| {
                if buf.borrow().done {
                    return;
                }
                let ts = ev.created_at;
                let ingested = store.ingest(zone_keys, ev, &key);
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
                let (events, page, sub) = {
                    let mut b = buf.borrow_mut();
                    if b.done {
                        return;
                    }
                    b.done = true;
                    let page = PageOutcome {
                        delivered: b.delivered,
                        oldest: b.oldest,
                    };
                    (std::mem::take(&mut b.events), page, b.sub.take())
                };
                if let Some(id) = sub {
                    relay.unsubscribe(&id);
                }
                before_apply();
                store.apply_page(events);
                let _ = store.history.try_update(|m| {
                    if let Some(c) = m.get_mut(&key) {
                        c.record(req, page);
                    }
                });
            })
        };
        let id = relay.subscribe_with_receipt(
            vec![HistoryCursor::filter(req, &needles)],
            on_event,
            on_receipt,
        );
        buf.borrow_mut().sub = Some(id);

        let relay = relay.clone();
        gloo::timers::callback::Timeout::new(PAGE_TIMEOUT_MS, move || {
            let sub = {
                let mut b = buf.borrow_mut();
                if b.done {
                    return;
                }
                b.done = true;
                b.sub.take()
            };
            if let Some(id) = sub {
                relay.unsubscribe(&id);
            }
            let _ = store.history.try_update(|m| {
                if let Some(c) = m.get_mut(&key) {
                    c.loading = false;
                }
            });
        })
        .forget();
        true
    }

    /// Cleanup subscriptions.
    pub(crate) fn cleanup(&self, relay: &RelayConnection) {
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
                .unwrap_or("Unnamed Channel")
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
        Err(_) => ("Unnamed Channel".to_string(), String::new(), String::new()),
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

// -- kind-5 deletion folding (post deletion) ----------------------------------

/// Most rows the relay returns for one filter (`MAX_QUERY_LIMIT` in the relay
/// worker's `relay_do/storage.rs`). A filter that leaves `limit` unset gets the
/// relay's default of 500 instead, so every sync filter states it.
pub const RELAY_FILTER_LIMIT: u64 = 1000;

/// Filters the relay accepts in one REQ (`MAX_FILTERS` in the relay worker).
pub const RELAY_MAX_FILTERS: usize = 10;

/// How long a history page request may go unanswered before it is abandoned.
pub const PAGE_TIMEOUT_MS: u32 = 20_000;

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
}
