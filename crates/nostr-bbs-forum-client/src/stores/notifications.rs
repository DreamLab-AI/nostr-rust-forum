//! Notification store backed by localStorage with 7-day eviction.
//!
//! Provides `NotificationStore` via Leptos context. Any component can push
//! notifications which persist across page reloads and auto-evict after 7 days.
//!
//! ## Live wiring (#31)
//!
//! [`NotificationStoreV2::init_sync`] attaches reactive effects to the shared
//! [`ChannelStore`](crate::stores::channels::ChannelStore) so that new topics
//! (kind-40 channel creations) and new posts (kind-42 messages) generate
//! notifications automatically — no extra relay subscription is opened, the
//! existing channel-store subscriptions already stream every event.
//!
//! Suppression rules:
//! - never notify on the user's OWN events (author == current pubkey),
//! - never notify on backlog (anything older than the sync baseline timestamp),
//! - never notify twice for the same event id,
//! - never notify on a post the user has already read (its `created_at` is at
//!   or before the channel's last-read position).

use std::collections::HashSet;

use gloo::storage::{LocalStorage, Storage};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};

use crate::auth::use_auth;
use crate::stores::channels::use_channel_store;
use crate::stores::profile_cache::try_use_profile_cache;
use crate::stores::read_position::use_read_positions;
use crate::utils::shorten_pubkey;

const STORAGE_KEY: &str = "nostrbbs:notifications";
const MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

// -- Types --------------------------------------------------------------------

/// Category of notification for icon display and routing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationKind {
    Message,
    Mention,
    DM,
    JoinRequest,
    JoinApproved,
    EventRSVP,
    System,
}

/// A single notification entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub kind: NotificationKind,
    pub title: String,
    pub body: String,
    pub timestamp: u64,
    pub read: bool,
    pub link: Option<String>,
}

/// Serializable store persisted to localStorage.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedNotifications {
    items: Vec<Notification>,
}

// -- Reactive store -----------------------------------------------------------

/// Reactive notification store, provided via context.
#[derive(Clone, Copy)]
pub struct NotificationStoreV2 {
    pub items: RwSignal<Vec<Notification>>,
    /// Set once `init_sync` has attached its effects, so the bell can call it
    /// idempotently from its (post-context) mount.
    synced: RwSignal<bool>,
    /// Sync baseline (UNIX secs). Content created at or before this is treated
    /// as backlog and never notified — only genuinely new arrivals fire.
    baseline: RwSignal<u64>,
    /// Channel ids already turned into a "new topic" notification.
    seen_channels: RwSignal<HashSet<String>>,
    /// Message event ids already turned into a "new post" notification.
    seen_messages: RwSignal<HashSet<String>>,
}

impl NotificationStoreV2 {
    fn new() -> Self {
        let loaded = load_from_storage();
        Self {
            items: RwSignal::new(loaded),
            synced: RwSignal::new(false),
            baseline: RwSignal::new(0),
            seen_channels: RwSignal::new(HashSet::new()),
            seen_messages: RwSignal::new(HashSet::new()),
        }
    }

    /// Number of unread notifications.
    pub fn unread_count(&self) -> Memo<usize> {
        let items = self.items;
        Memo::new(move |_| items.get().iter().filter(|n| !n.read).count())
    }

    /// Mark a single notification as read.
    pub fn mark_read(&self, id: &str) {
        let id = id.to_string();
        self.items.update(|list| {
            if let Some(n) = list.iter_mut().find(|n| n.id == id) {
                n.read = true;
            }
        });
        self.persist();
    }

    /// Mark all notifications as read.
    pub fn mark_all_read(&self) {
        self.items.update(|list| {
            for n in list.iter_mut() {
                n.read = true;
            }
        });
        self.persist();
    }

    /// Push a new notification.
    pub fn add(&self, kind: NotificationKind, title: &str, body: &str, link: Option<&str>) {
        let now = now_secs();
        self.add_at(kind, title, body, link, now, None);
    }

    /// Push a new notification carrying an explicit timestamp and optional
    /// stable dedup id (the source event id). When `dedup_id` is supplied and a
    /// notification with that id already exists, this is a no-op.
    fn add_at(
        &self,
        kind: NotificationKind,
        title: &str,
        body: &str,
        link: Option<&str>,
        timestamp: u64,
        dedup_id: Option<String>,
    ) {
        // Honour the user's notification level (#wire-settings). The level
        // gates which categories ever reach the store:
        //   None         -> nothing,
        //   MentionsOnly -> only @-mentions and direct-to-user events (DMs,
        //                   join approvals, RSVPs, system) — never generic
        //                   channel chatter,
        //   All          -> everything.
        if !notification_kind_allowed(&kind) {
            return;
        }

        let id = match dedup_id {
            Some(id) => {
                if self
                    .items
                    .with_untracked(|list| list.iter().any(|n| n.id == id))
                {
                    return;
                }
                id
            }
            None => {
                // Random ID via js_sys (WASM-safe, no getrandom crate needed).
                let mut bytes = [0u8; 8];
                for b in bytes.iter_mut() {
                    *b = (js_sys::Math::random() * 256.0) as u8;
                }
                hex::encode(bytes)
            }
        };

        let notification = Notification {
            id,
            kind,
            title: title.to_string(),
            body: body.to_string(),
            timestamp,
            read: false,
            link: link.map(|s| s.to_string()),
        };

        self.items.update(|list| {
            list.insert(0, notification);
            // Keep the list time-ordered (newest first) even when backfilling
            // events that arrive out of order from the relay.
            list.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            // Cap at 100 notifications.
            if list.len() > 100 {
                list.truncate(100);
            }
        });
        self.persist();
    }

    /// Clear all notifications.
    pub fn clear_all(&self) {
        self.items.set(Vec::new());
        self.persist();
    }

    /// Attach reactive effects that turn live relay traffic into notifications.
    ///
    /// Idempotent: safe to call from every render of the bell. Must be invoked
    /// AFTER `provide_channel_store` / `provide_read_positions` / `provide_auth`
    /// have run (the bell mounts inside the Layout, so by then all app-root
    /// context is available).
    ///
    /// Reads the channel store's `channels` (kind-40) and `channel_messages`
    /// (kind-42) reactive signals — no new relay subscription is opened.
    pub fn init_sync(&self) {
        if self.synced.get_untracked() {
            return;
        }
        self.synced.set(true);
        // Everything already on screen at attach time is backlog.
        self.baseline.set(now_secs());

        let store = *self;
        let channels_store = use_channel_store();
        let read_positions = use_read_positions();
        let auth = use_auth();
        let my_pubkey = auth.pubkey();

        // -- New topics (kind-40 channel creation) ----------------------------
        let channels_sig = channels_store.channels;
        Effect::new(move |_| {
            let baseline = store.baseline.get_untracked();
            let channels = channels_sig.get();
            for c in channels.iter() {
                if store.seen_channels.with_untracked(|s| s.contains(&c.id)) {
                    continue;
                }
                store.seen_channels.update(|s| {
                    s.insert(c.id.clone());
                });
                // Only notify on channels created after we started watching —
                // existing channels are backlog, not "new topics". ChannelMeta
                // carries no author pubkey, so OWN-topic suppression is not
                // possible here; backlog suppression already prevents notifying
                // on a channel the user made in a prior session (it predates
                // the baseline).
                if c.created_at <= baseline {
                    continue;
                }
                let name = if c.name.is_empty() {
                    "a new channel".to_string()
                } else {
                    c.name.clone()
                };
                store.add_at(
                    NotificationKind::Message,
                    "New topic",
                    &format!("{} was created", name),
                    Some(&format!("/chat/{}", c.id)),
                    c.created_at,
                    Some(format!("topic:{}", c.id)),
                );
            }
        });

        // -- New posts (kind-42 messages) -------------------------------------
        let messages_sig = channels_store.channel_messages;
        let channels_for_msgs = channels_store.channels;
        Effect::new(move |_| {
            let baseline = store.baseline.get_untracked();
            let me = my_pubkey.get();
            let msgs = messages_sig.get();
            // Channel id -> display name for the notification body.
            let names: std::collections::HashMap<String, String> = channels_for_msgs
                .with_untracked(|list| {
                    list.iter()
                        .map(|c| (c.id.clone(), c.name.clone()))
                        .collect()
                });
            for (cid, events) in msgs.iter() {
                // Last-read position for this channel: posts at or before it are
                // already read and must not re-notify.
                let last_read_ts = read_positions.read_timestamps();
                let read_ts = last_read_ts.get(cid).copied().unwrap_or(0);
                let channel_name = names
                    .get(cid)
                    .filter(|n| !n.is_empty())
                    .cloned()
                    .unwrap_or_else(|| "a channel".to_string());

                for event in events.iter() {
                    if store
                        .seen_messages
                        .with_untracked(|s| s.contains(&event.id))
                    {
                        continue;
                    }
                    store.seen_messages.update(|s| {
                        s.insert(event.id.clone());
                    });

                    // Backlog: anything from before we started watching.
                    if event.created_at <= baseline {
                        continue;
                    }
                    // Already read in this channel.
                    if event.created_at <= read_ts {
                        continue;
                    }
                    // Don't notify on the user's own posts.
                    if let Some(ref pk) = me {
                        if &event.pubkey == pk {
                            continue;
                        }
                    }

                    let author = author_display(&event.pubkey);
                    let preview = post_preview(&event.content);
                    // Classify @-mentions of the current user as `Mention` so
                    // they survive the MentionsOnly notification level; plain
                    // channel posts stay `Message` and are gated out under it.
                    let mentions_me = me
                        .as_deref()
                        .map(|pk| event_mentions(event, pk))
                        .unwrap_or(false);
                    let (kind, title) = if mentions_me {
                        (
                            NotificationKind::Mention,
                            format!("You were mentioned in {}", channel_name),
                        )
                    } else {
                        (
                            NotificationKind::Message,
                            format!("New reply in {}", channel_name),
                        )
                    };
                    store.add_at(
                        kind,
                        &title,
                        &format!("{}: {}", author, preview),
                        Some(&format!("/chat/{}", cid)),
                        event.created_at,
                        Some(format!("post:{}", event.id)),
                    );
                }
            }
        });
    }

    fn persist(&self) {
        let data = PersistedNotifications {
            items: self.items.get_untracked(),
        };
        let _ = LocalStorage::set(STORAGE_KEY, data);
    }
}

// -- Context providers --------------------------------------------------------

/// Provide the notification store context. Call once near the app root.
///
/// The created store is also registered as the fallback singleton so that any
/// later context miss (see [`use_notification_store`]) resolves to *this* exact
/// instance rather than a divergent one — keeping the bell badge and the
/// notification center in lock-step on a single `items` signal.
pub fn provide_notification_store() {
    let store = NotificationStoreV2::new();
    FALLBACK_STORE.with(|cell| {
        *cell.borrow_mut() = Some(store);
    });
    provide_context(store);
}

/// Read the notification store from context.
///
/// Resolves the single store installed by [`provide_notification_store`] at the
/// app root. If `use_context` misses (it can, when called inside a transiently
/// re-created reactive owner such as the body of a toggling `<Show>` — the
/// notification center is rendered inside one), this falls back to a **single
/// process-wide instance**, not a fresh one per call.
///
/// Root cause (BUG: bell badge shows a count while the expanded center is
/// empty): the old fallback minted a *new* `NotificationStoreV2` — with its own
/// empty `items` signal — on every context miss. The bell resolved the real
/// (root) store, `init_sync` populated it and the badge counted its unread
/// items, but a consumer that fell through to a freshly-minted empty store
/// rendered nothing. Same invariant ("badge and list read one signal") but two
/// physical stores. Sharing one singleton on the fallback path guarantees every
/// consumer observes the same `items`, so the badge and list can never diverge.
pub fn use_notification_store() -> NotificationStoreV2 {
    if let Some(store) = use_context::<NotificationStoreV2>() {
        return store;
    }
    let store = fallback_singleton();
    // Re-provide into the current reactive subtree so descendants resolve it via
    // context directly (and we don't hit this path repeatedly).
    provide_context(store);
    store
}

thread_local! {
    /// Single shared store used only when context resolution misses, so all
    /// consumers still observe one set of reactive signals (see
    /// `use_notification_store`). On WASM the app is single-threaded.
    static FALLBACK_STORE: std::cell::RefCell<Option<NotificationStoreV2>> =
        const { std::cell::RefCell::new(None) };
}

fn fallback_singleton() -> NotificationStoreV2 {
    FALLBACK_STORE.with(|cell| {
        if let Some(store) = *cell.borrow() {
            return store;
        }
        let store = NotificationStoreV2::new();
        *cell.borrow_mut() = Some(store);
        store
    })
}

// -- Helpers ------------------------------------------------------------------

fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Whether a notification of `kind` is allowed under the persisted
/// `notification_level` preference (#wire-settings).
///
/// - `None`: nothing is allowed.
/// - `MentionsOnly`: only `Mention` plus inherently direct-to-user categories
///   (`DM`, `JoinRequest`, `JoinApproved`, `EventRSVP`, `System`) — generic
///   channel `Message` traffic (new topics / new posts) is suppressed.
/// - `All`: everything is allowed.
fn notification_kind_allowed(kind: &NotificationKind) -> bool {
    use crate::stores::preferences::NotificationLevel;
    match crate::stores::preferences::notification_level_pref() {
        NotificationLevel::All => true,
        NotificationLevel::None => false,
        NotificationLevel::MentionsOnly => !matches!(kind, NotificationKind::Message),
    }
}

/// Whether `event` @-mentions `pubkey` — i.e. carries a `p` tag whose value is
/// that pubkey (NIP-10 mention convention; also how typed @-mentions in posts
/// are tagged). Case-insensitive hex compare.
fn event_mentions(event: &nostr_bbs_core::NostrEvent, pubkey: &str) -> bool {
    event
        .tags
        .iter()
        .any(|tag| tag.len() >= 2 && tag[0] == "p" && tag[1].eq_ignore_ascii_case(pubkey))
}

/// Resolve a pubkey to a human display name, falling back to a shortened hex.
fn author_display(pubkey: &str) -> String {
    if let Some(cache) = try_use_profile_cache() {
        if let Some(entry) = cache.lookup(pubkey) {
            if let Some(name) = entry.display_name.filter(|s| !s.is_empty()) {
                return name;
            }
            if let Some(name) = entry.name.filter(|s| !s.is_empty()) {
                return name;
            }
        }
    }
    shorten_pubkey(pubkey)
}

/// Trim a post body to a short single-line preview for the notification list.
fn post_preview(content: &str) -> String {
    let cleaned: String = content.split_whitespace().collect::<Vec<_>>().join(" ");
    const MAX: usize = 80;
    if cleaned.chars().count() > MAX {
        let truncated: String = cleaned.chars().take(MAX).collect();
        format!("{}…", truncated)
    } else {
        cleaned
    }
}

/// Load notifications from localStorage, evicting entries older than 7 days and
/// dropping any that fail to deserialize against the current schema.
///
/// Defensive against schema drift (BUG: count-but-not-render): a notification
/// written by an older build (e.g. a `NotificationKind` variant that no longer
/// exists, or a renamed field) must NOT poison the whole list. Strict
/// `LocalStorage::get::<PersistedNotifications>()` fails the *entire* blob on one
/// bad entry, so we parse leniently — element by element — and keep only the
/// entries that map cleanly onto the current `Notification` schema. The migrated
/// (cleaned) list is written straight back so the drift heals on first load.
fn load_from_storage() -> Vec<Notification> {
    let now = now_secs();

    // Parse leniently: read the raw JSON value, then deserialize each item on its
    // own so a single legacy/corrupt entry is dropped rather than blanking all.
    let items: Vec<Notification> = match LocalStorage::get::<serde_json::Value>(STORAGE_KEY) {
        Ok(value) => parse_persisted_items(&value, now),
        Err(_) => Vec::new(),
    };

    // Persist the cleaned/evicted/migrated list back.
    let _ = LocalStorage::set(
        STORAGE_KEY,
        PersistedNotifications {
            items: items.clone(),
        },
    );
    items
}

/// Lenient, per-item parse of the persisted `{ "items": [...] }` blob.
///
/// Each element is deserialized independently: entries that don't match the
/// current [`Notification`] schema (legacy variant, missing/renamed field) are
/// dropped rather than failing the whole list, and anything older than 7 days is
/// evicted. Extracted from [`load_from_storage`] so it is unit-testable without
/// a DOM.
fn parse_persisted_items(value: &serde_json::Value, now: u64) -> Vec<Notification> {
    value
        .get("items")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| serde_json::from_value::<Notification>(item.clone()).ok())
                .filter(|n| now.saturating_sub(n.timestamp) < MAX_AGE_SECS)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn lenient_parse_drops_corrupt_entry_keeps_valid() {
        let now = 1_000_000_000;
        // One valid entry + one with an unknown NotificationKind variant.
        let value = json!({
            "items": [
                { "id": "a", "kind": "Mention", "title": "ok", "body": "b",
                  "timestamp": now, "read": false, "link": null },
                { "id": "b", "kind": "LegacyKindThatNoLongerExists", "title": "x",
                  "body": "y", "timestamp": now, "read": true, "link": null },
            ]
        });
        let items = parse_persisted_items(&value, now);
        // The corrupt entry is dropped; the valid one survives — so a single
        // legacy notification can never blank the whole list (the count-but-not
        // -render failure mode).
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "a");
        assert_eq!(items[0].kind, NotificationKind::Mention);
    }

    #[test]
    fn lenient_parse_evicts_old_entries() {
        let now = MAX_AGE_SECS + 100;
        let value = json!({
            "items": [
                { "id": "fresh", "kind": "DM", "title": "t", "body": "b",
                  "timestamp": now, "read": false, "link": null },
                { "id": "stale", "kind": "DM", "title": "t", "body": "b",
                  "timestamp": 0, "read": false, "link": null },
            ]
        });
        let items = parse_persisted_items(&value, now);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "fresh");
    }

    #[test]
    fn lenient_parse_handles_missing_items_key() {
        assert!(parse_persisted_items(&json!({}), 0).is_empty());
        assert!(parse_persisted_items(&json!({ "items": "not-an-array" }), 0).is_empty());
        assert!(parse_persisted_items(&json!(null), 0).is_empty());
    }

    #[test]
    fn lenient_parse_missing_optional_link_is_dropped_when_required() {
        // `link` is `Option<String>` — absent should still deserialize fine.
        let now = 10;
        let value = json!({
            "items": [
                { "id": "x", "kind": "System", "title": "t", "body": "b",
                  "timestamp": now, "read": false },
            ]
        });
        let items = parse_persisted_items(&value, now);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].link, None);
    }
}
