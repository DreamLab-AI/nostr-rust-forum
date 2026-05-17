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
    /// Timestamp of last successful relay sync.
    #[serde(default)]
    synced_at: u64,
}

// -- ChannelStore -------------------------------------------------------------

/// Global channel store provided via Leptos context.
/// Subscribe once at app root — all pages read from these signals.
///
/// ADR-091: post counts are NEVER stored as an independent field.
/// Use [`ChannelStore::count_for`] / [`ChannelStore::count_map`] /
/// [`ChannelStore::total_messages`] — they derive from `channel_messages`
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
        }
    }

    // -- Derived count accessors (ADR-091) ------------------------------------

    /// Post count for a single channel, derived from deduped event Vec.
    /// Reactive: re-runs when `channel_messages` changes.
    pub fn count_for(&self, cid: &str) -> u32 {
        self.channel_messages
            .with(|m| m.get(cid).map(|v| v.len() as u32).unwrap_or(0))
    }

    /// Full count map (cid → count). Useful as a single Signal for filters
    /// that need to read multiple counts in one update tick.
    pub fn count_map(&self) -> HashMap<String, u32> {
        self.channel_messages
            .with(|m| m.iter().map(|(k, v)| (k.clone(), v.len() as u32)).collect())
    }

    /// Sum of all channel post counts.
    pub fn total_messages(&self) -> u32 {
        self.channel_messages
            .with(|m| m.values().map(|v| v.len() as u32).sum())
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
        let loading_sig = self.loading;
        let eose_sig = self.eose_received;
        let store = *self;

        // Track which channel IDs came from the relay (vs stale cache)
        let relay_ids = Rc::new(std::cell::RefCell::new(HashSet::<String>::new()));
        let relay_ids_for_event = relay_ids.clone();

        // Kind 40: channel creation events
        let on_event = Rc::new(move |event: NostrEvent| {
            if event.kind != 40 {
                return;
            }

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

            channels_sig.update(|list| {
                if !list.iter().any(|c| c.id == meta.id) {
                    list.push(meta);
                }
            });
        });

        let store_for_eose = store;
        let on_eose = Rc::new(move || {
            // Prune channels that were in the cache but NOT received from relay
            // (they were deleted or the DB was wiped)
            let ids = relay_ids.borrow();
            if ids.is_empty() {
                // Relay returned zero channels — clear everything.
                // Counts are derived from channel_messages (ADR-091), so
                // clearing that map zeroes all counts automatically.
                channels_sig.set(Vec::new());
                store_for_eose.channel_messages.set(HashMap::new());
                store_for_eose.last_active.set(HashMap::new());
            } else {
                channels_sig.update(|list| {
                    list.retain(|c| ids.contains(&c.id));
                });
            }
            loading_sig.set(false);
            eose_sig.set(true);
            // Cache the pruned result
            store_for_eose.save_cache();
        });

        let id = relay.subscribe(
            vec![Filter {
                kinds: Some(vec![40]),
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
        let store = *self;

        let on_msg = Rc::new(move |event: NostrEvent| {
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

        let on_event = Rc::new(move |event: NostrEvent| {
            if event.kind != 42 {
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
