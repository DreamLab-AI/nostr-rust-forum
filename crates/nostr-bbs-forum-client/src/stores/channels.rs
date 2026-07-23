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
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use wasm_bindgen::JsCast;

use crate::relay::{Filter, RelayConnection};

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
    /// Event ids deleted via kind-5 (NIP-09), lowercased. A tombstone both
    /// removes the target from `channel_messages` AND suppresses a kind-42 that
    /// arrives AFTER its deletion (backfill order is not guaranteed). Transient
    /// — rebuilt from the relay's replayed kind-5s each session. See
    /// [`fold_deletions`].
    tombstones: RwSignal<HashSet<String>>,
}

impl ChannelStore {
    fn new() -> Self {
        // Hydrate from localStorage cache for instant render
        let cached = Self::load_cache();
        let has_cache = !cached.channels.is_empty();

        Self {
            channels: RwSignal::new(cached.channels),
            last_active: RwSignal::new(cached.last_active),
            channel_messages: RwSignal::new(HashMap::new()),
            // If we have cache, don't show loading — render immediately
            loading: RwSignal::new(!has_cache),
            eose_received: RwSignal::new(false),
            sub_id: RwSignal::new(None),
            msg_sub_id: RwSignal::new(None),
            ensured: RwSignal::new(HashSet::new()),
            meta_updated_at: RwSignal::new(cached.meta_updated_at),
            pending_meta: RwSignal::new(HashMap::new()),
            tombstones: RwSignal::new(HashSet::new()),
        }
    }

    /// Optimistically tombstone + remove a message by id.
    ///
    /// Used by the delete UI so the actor doesn't wait on the relay echo; it is
    /// idempotent with the kind-5 fold that runs when the deletion broadcast
    /// arrives ([`fold_deletions`]).
    pub fn remove_message(&self, event_id: &str) {
        let deleted = [event_id.to_lowercase()];
        let tombstones = self.tombstones;
        self.channel_messages.update(|m| {
            tombstones.update(|t| {
                fold_deletions(m, t, &deleted);
            });
        });
    }

    // -- Derived count accessors (ADR-091) ------------------------------------

    /// Post count for a single channel, derived from deduped event Vec.
    /// Reactive: re-runs when `channel_messages` changes.
    pub fn count_for(&self, cid: &str) -> u32 {
        self.channel_messages
            .with(|m| m.get(cid).map(|v| v.len() as u32).unwrap_or(0))
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
        let channel_msgs_sig = self.channel_messages;
        let meta_ts_sig = self.meta_updated_at;
        let pending_meta_sig = self.pending_meta;
        let tombstones_sig = self.tombstones;
        let loading_sig = self.loading;
        let eose_sig = self.eose_received;
        let store = *self;

        // Track which channel IDs came from the relay (vs stale cache)
        let relay_ids = Rc::new(std::cell::RefCell::new(HashSet::<String>::new()));
        let relay_ids_for_event = relay_ids.clone();

        // Kind 40: channel creation. Kind 41: channel metadata edit (admin
        // rename) — folded last-write-wins; pin/unpin control 41s are ignored
        // (they carry empty content, so [`parse_meta_update`] returns `None`).
        // Kind 5: NIP-09 deletion — removes the target post and tombstones its id.
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
                5 => {
                    let deleted = deletion_targets(&event);
                    if !deleted.is_empty() {
                        channel_msgs_sig.update(|m| {
                            tombstones_sig.update(|t| {
                                fold_deletions(m, t, &deleted);
                            });
                        });
                    }
                }
                _ => {}
            }
        });

        let store_for_eose = store;
        let on_eose = Rc::new(move || {
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
                    store_for_eose.tombstones.set(HashSet::new());
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
            // Cache the pruned result
            store_for_eose.save_cache();
        });

        let id = relay.subscribe(
            vec![Filter {
                // kind-40 = channel creation, kind-41 = metadata edit (rename),
                // kind-5 = post deletion (NIP-09).
                kinds: Some(vec![5, 40, 41]),
                ..Default::default()
            }],
            on_event,
            Some(on_eose),
        );
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

        let channels_sig = self.channels;
        let last_active = self.last_active;
        let channel_msgs = self.channel_messages;
        let tombstones = self.tombstones;
        let store = *self;

        let on_msg = Rc::new(move |event: NostrEvent| {
            // Suppress a message that was already deleted — a kind-5 can land
            // before its target kind-42 in the same backfill (arrival order is
            // not guaranteed), so the tombstone is the durable gate.
            if tombstones.with_untracked(|t| is_tombstoned(t, &event.id)) {
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
                // Store raw event for channel page consumption. Dedup by
                // event id is the ONLY counter — ADR-091. Last-active only
                // advances when a genuinely new event is appended.
                let mut newly_added = false;
                let event_ts = event.created_at;
                channel_msgs.update(|m| {
                    let events = m.entry(cid.clone()).or_insert_with(Vec::new);
                    if !events.iter().any(|e| e.id == event.id) {
                        events.push(event);
                        events.sort_by_key(|e| e.created_at);
                        newly_added = true;
                    }
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
        let on_msg_eose = Rc::new(move || {
            store_for_eose.save_cache();
        });

        // Broad subscription: all kind-42 events, no e_tags restriction
        let id = relay.subscribe(
            vec![Filter {
                kinds: Some(vec![42]),
                ..Default::default()
            }],
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
        let needle = self.resolve_channel(cid_or_slug).unwrap_or(key);

        let last_active = self.last_active;
        let channel_msgs = self.channel_messages;
        let tombstones = self.tombstones;

        let on_event = Rc::new(move |event: NostrEvent| {
            if event.kind != 42 {
                return;
            }
            // Skip messages already deleted via kind-5 (see `start_msg_sync`).
            if tombstones.with_untracked(|t| is_tombstoned(t, &event.id)) {
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
            let mut newly_added = false;
            let event_ts = event.created_at;
            channel_msgs.update(|m| {
                let events = m.entry(cid.clone()).or_insert_with(Vec::new);
                if !events.iter().any(|e| e.id == event.id) {
                    events.push(event);
                    events.sort_by_key(|e| e.created_at);
                    newly_added = true;
                }
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

        let _ = relay.subscribe(
            vec![Filter {
                kinds: Some(vec![42]),
                e_tags: Some(vec![needle]),
                ..Default::default()
            }],
            on_event,
            None,
        );
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

/// Fold deleted ids into the message store: record each as a tombstone and drop
/// any matching event from every channel. Returns `true` when at least one
/// stored message was removed.
///
/// The tombstone set is what makes deletion arrival-order independent: a kind-5
/// landing BEFORE its target (same EOSE backfill or live) records the id, and
/// the kind-42 handlers consult [`is_tombstoned`] before inserting, so the post
/// never reappears; a kind-5 landing AFTER removes the already-stored copy here.
///
/// TRUST MODEL: identical to the kind-41 fold — the relay gates WHO may delete
/// (own events always; others' events admin/TL3+, enforced by the relay's kind-5
/// gate), so the client folds any stored/broadcast kind-5 unconditionally with
/// no author check; re-checking here would duplicate — and could disagree with —
/// the server's authority.
pub fn fold_deletions(
    channel_messages: &mut HashMap<String, Vec<NostrEvent>>,
    tombstones: &mut HashSet<String>,
    deleted: &[String],
) -> bool {
    let mut removed = false;
    for id in deleted {
        tombstones.insert(id.clone());
        for events in channel_messages.values_mut() {
            let before = events.len();
            events.retain(|e| e.id.to_lowercase() != *id);
            if events.len() != before {
                removed = true;
            }
        }
    }
    removed
}

/// Whether `id` (any casing) has been deleted (tombstoned).
pub fn is_tombstoned(tombstones: &HashSet<String>, id: &str) -> bool {
    tombstones.contains(&id.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn kind5_removes_target_message() {
        let target = ev(42, 100, &[&["e", "chan", "", "root"]], "delete me");
        let keep = ev(42, 200, &[&["e", "chan", "", "root"]], "keep me");
        let tid = target.id.clone();
        let mut msgs: HashMap<String, Vec<NostrEvent>> = HashMap::new();
        msgs.insert("chan".into(), vec![target, keep]);
        let mut tomb = HashSet::new();

        let del = ev(5, 300, &[&["e", tid.as_str()]], "");
        let targets = deletion_targets(&del);
        assert_eq!(targets, vec![tid.to_lowercase()]);
        assert!(fold_deletions(&mut msgs, &mut tomb, &targets));
        assert_eq!(msgs["chan"].len(), 1);
        assert_eq!(msgs["chan"][0].content, "keep me");
        assert!(is_tombstoned(&tomb, &tid));
    }

    #[test]
    fn kind5_before_target_suppresses_later_message() {
        // Deletion lands with the target not yet stored (backfill order): nothing
        // is removed, but the tombstone must suppress the message when it arrives.
        let late = ev(42, 100, &[&["e", "chan", "", "root"]], "arrives late");
        let lid = late.id.clone();
        let mut msgs: HashMap<String, Vec<NostrEvent>> = HashMap::new();
        let mut tomb = HashSet::new();

        let del = ev(5, 90, &[&["e", lid.as_str()]], "");
        assert!(!fold_deletions(
            &mut msgs,
            &mut tomb,
            &deletion_targets(&del)
        ));
        assert!(is_tombstoned(&tomb, &lid));
    }

    #[test]
    fn kind5_without_e_tag_is_noop() {
        let del = ev(5, 100, &[&["p", "somebody"]], "");
        assert!(deletion_targets(&del).is_empty());

        let keep = ev(42, 100, &[&["e", "chan", "", "root"]], "keep");
        let mut msgs: HashMap<String, Vec<NostrEvent>> = HashMap::new();
        msgs.insert("chan".into(), vec![keep]);
        let mut tomb = HashSet::new();
        assert!(!fold_deletions(
            &mut msgs,
            &mut tomb,
            &deletion_targets(&del)
        ));
        assert_eq!(msgs["chan"].len(), 1);
        assert!(tomb.is_empty());
    }

    #[test]
    fn kind5_unknown_id_removes_nothing() {
        let keep = ev(42, 100, &[&["e", "chan", "", "root"]], "keep");
        let mut msgs: HashMap<String, Vec<NostrEvent>> = HashMap::new();
        msgs.insert("chan".into(), vec![keep]);
        let mut tomb = HashSet::new();

        let del = ev(5, 200, &[&["e", "nonexistent-id"]], "");
        assert!(!fold_deletions(
            &mut msgs,
            &mut tomb,
            &deletion_targets(&del)
        ));
        assert_eq!(msgs["chan"].len(), 1);
        // Still recorded, so a message with that id could never appear later.
        assert!(is_tombstoned(&tomb, "nonexistent-id"));
    }
}
