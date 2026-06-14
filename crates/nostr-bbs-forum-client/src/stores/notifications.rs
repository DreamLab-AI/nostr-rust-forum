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
/// Persisted producer sync state (baseline high-water mark + already-notified
/// event ids). Separate key so it survives the 7-day eviction of the visible
/// notification list — otherwise a backlog post would re-notify once its
/// notification aged out (see [`SyncState`]).
const SYNC_STATE_KEY: &str = "nostrbbs:notif_sync";
const MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;
/// Cap on persisted dedup ids so the set can't grow without bound. Far above the
/// 100-notification visible cap; old ids are evicted FIFO-style on overflow.
const MAX_SEEN_IDS: usize = 2_000;

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

/// Persisted producer state so notifications survive reloads correctly.
///
/// Two fields, both load-bearing for the "burst reader" workflow (log in, glance,
/// leave; come back later to genuine unread activity):
///
/// - `baseline`: the FIRST-EVER-sync wall-clock floor, captured once and then
///   persisted forever (until the user clears storage). It exists only to stop
///   the very first sync from dumping the entire channel history as
///   notifications. Crucially it is NOT reset to `now()` on later logins — so a
///   post that arrived while the user was away (`created_at > baseline`) still
///   qualifies. Resetting it every `init_sync` (the old behaviour) is exactly
///   why a burst reader saw nothing: everything that happened between sessions
///   fell at-or-before the freshly-captured baseline and was filed as backlog.
/// - `notified_ids`: event ids already turned into a notification. Persisted so
///   a still-on-relay backlog post is not re-notified after its visible
///   notification is evicted by the 7-day rule, and so a reload does not
///   re-announce everything. Bounded by [`MAX_SEEN_IDS`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SyncState {
    #[serde(default)]
    baseline: u64,
    #[serde(default)]
    notified_ids: Vec<String>,
}

// -- Reactive store -----------------------------------------------------------

/// Reactive notification store, provided via context.
#[derive(Clone, Copy)]
pub struct NotificationStoreV2 {
    pub items: RwSignal<Vec<Notification>>,
    /// Set once `init_sync` has attached its effects, so the bell can call it
    /// idempotently from its (post-context) mount.
    synced: RwSignal<bool>,
    /// First-ever-sync floor (UNIX secs), loaded from / persisted to storage so
    /// it is stable across logins. Only the very first sync uses it to avoid
    /// dumping all history; thereafter the read-position is the real "already
    /// seen" signal. See [`SyncState`].
    baseline: RwSignal<u64>,
    /// Channel ids already turned into a "new topic" notification (in-memory;
    /// channel creations are rare and the persisted `notified_ids` covers reload
    /// dedup for posts, which is where flooding matters).
    seen_channels: RwSignal<HashSet<String>>,
    /// Message event ids already turned into a "new post" notification. Seeded
    /// from the persisted [`SyncState::notified_ids`] on construction so dedup
    /// survives reloads and 7-day item eviction.
    seen_messages: RwSignal<HashSet<String>>,
}

impl NotificationStoreV2 {
    fn new() -> Self {
        let loaded = load_from_storage();
        let sync_state = load_sync_state();
        let seen: HashSet<String> = sync_state.notified_ids.into_iter().collect();
        Self {
            items: RwSignal::new(loaded),
            synced: RwSignal::new(false),
            baseline: RwSignal::new(sync_state.baseline),
            seen_channels: RwSignal::new(HashSet::new()),
            seen_messages: RwSignal::new(seen),
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

        // First-ever sync floor: if no baseline has ever been persisted, capture
        // `now()` so this initial sync does not dump the entire channel backlog
        // as notifications. On every SUBSEQUENT login the persisted value is
        // reused (NOT reset) so activity that arrived between sessions still
        // qualifies as new. This is the fix for the silent producer: a burst
        // reader (log in → glance → leave → return) now gets notified for what
        // happened while they were away, instead of having it all re-filed as
        // backlog under a freshly-stamped `now()`.
        if self.baseline.get_untracked() == 0 {
            let now = now_secs();
            self.baseline.set(now);
            self.persist_sync_state();
        }

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
            // Read the read-position map ONCE per run (tracked: marking a channel
            // read re-runs this effect so the badge clears), then index per
            // channel below.
            let read_map = read_positions.read_timestamps();
            // Whether this run recorded any newly-seen event id; if so we persist
            // the dedup set + baseline once at the end (not per event).
            let mut seen_changed = false;
            for (cid, events) in msgs.iter() {
                // Last-read position for this channel: posts at or before it are
                // already read and must not re-notify.
                let read_ts = read_map.get(cid).copied().unwrap_or(0);
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
                        // Bound the persisted dedup set; on overflow drop an
                        // arbitrary oldest-ish entry. Re-notifying a long-evicted
                        // post is far less bad than an unbounded set.
                        if s.len() >= MAX_SEEN_IDS {
                            if let Some(victim) = s.iter().next().cloned() {
                                s.remove(&victim);
                            }
                        }
                        s.insert(event.id.clone());
                    });
                    seen_changed = true;

                    // Suppression model (the fix) — see `post_is_notifiable`.
                    // Notify only on genuinely unread activity from someone else:
                    // unread in-channel (`> read_ts`), past the persisted
                    // first-sync floor (`> baseline`), and not the user's own.
                    // De-dup against already-notified ids is the persisted
                    // `seen_messages` check above.
                    if !post_is_notifiable(
                        &event.pubkey,
                        event.created_at,
                        me.as_deref(),
                        read_ts,
                        baseline,
                    ) {
                        continue;
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
            // Persist the dedup set (and baseline) once per run if it grew, so
            // already-notified posts are not re-announced after a reload or once
            // their visible notification is evicted by the 7-day rule.
            if seen_changed {
                store.persist_sync_state();
            }
        });
    }

    fn persist(&self) {
        let data = PersistedNotifications {
            items: self.items.get_untracked(),
        };
        let _ = LocalStorage::set(STORAGE_KEY, data);
    }

    /// Persist the producer sync state (baseline + already-notified ids) to its
    /// own localStorage key. Cheap; called at most once per effect run.
    fn persist_sync_state(&self) {
        let state = SyncState {
            baseline: self.baseline.get_untracked(),
            notified_ids: self
                .seen_messages
                .with_untracked(|s| s.iter().cloned().collect()),
        };
        let _ = LocalStorage::set(SYNC_STATE_KEY, state);
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

/// Load the persisted producer sync state, tolerating absence and schema drift
/// (returns the default — baseline 0, empty set — on any parse failure, so a
/// corrupt blob just means "first sync" rather than a crash).
fn load_sync_state() -> SyncState {
    LocalStorage::get::<SyncState>(SYNC_STATE_KEY).unwrap_or_default()
}

/// Pure suppression predicate for a kind-42 post (extracted so it is unit
/// testable without a DOM). Returns `true` when the post represents genuine,
/// unseen activity that should raise a notification.
///
/// A post is notifiable iff ALL hold:
/// - it is not the user's own (`author != me`),
/// - it is unread in its channel (`created_at > read_ts`) — the canonical
///   timestamp read-model,
/// - it is newer than the first-ever-sync floor (`created_at > baseline`), which
///   only suppresses pre-first-visit history because `baseline` is persisted and
///   never reset between sessions.
///
/// De-dup against already-notified ids is handled by the caller's persisted
/// `seen_messages` set, not here.
fn post_is_notifiable(
    author: &str,
    created_at: u64,
    me: Option<&str>,
    read_ts: u64,
    baseline: u64,
) -> bool {
    if let Some(pk) = me {
        if author == pk {
            return false;
        }
    }
    created_at > read_ts && created_at > baseline
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

    // -- Producer suppression (the silent-producer fix) -----------------------

    const ME: &str = "11ed64225dd5e2c5e18f61ad43d5ad9272d08739d3a20dd25886197b0738663c";
    const OTHER: &str = "2de44d5622eef79519ac078f6e227a85aecbaefd561e4e50c5f51dfadbf916e9";

    #[test]
    fn own_posts_never_notify() {
        // Even when unread and well past the baseline, the user's own post is
        // suppressed.
        assert!(!post_is_notifiable(ME, 5_000, Some(ME), 0, 1_000));
    }

    #[test]
    fn fresh_live_foreign_post_notifies() {
        // Someone else, unread (read_ts=0), after the baseline → notify. This is
        // the "post arrives while I'm looking" case that always worked.
        assert!(post_is_notifiable(OTHER, 5_000, Some(ME), 0, 1_000));
    }

    #[test]
    fn unread_backlog_after_baseline_notifies_for_burst_reader() {
        // THE REGRESSION THIS FIXES: the operator logged in at t=1_000 (their
        // FIRST visit → baseline=1_000), left, and a foreign post landed at
        // t=2_000 while they were away. They have never opened the channel
        // (read_ts=0). On return it must notify — previously `baseline` was
        // reset to "now" on every login (e.g. 3_000), filing the 2_000 post as
        // backlog and silently dropping it.
        let baseline_from_first_visit = 1_000;
        assert!(post_is_notifiable(
            OTHER,
            2_000,
            Some(ME),
            0,
            baseline_from_first_visit
        ));
    }

    #[test]
    fn already_read_post_never_notifies() {
        // Read up to t=5_000; a post at 4_000 is below the read position → no
        // notification even though it post-dates the baseline.
        assert!(!post_is_notifiable(OTHER, 4_000, Some(ME), 5_000, 1_000));
        // Exactly at the read position is still "read".
        assert!(!post_is_notifiable(OTHER, 5_000, Some(ME), 5_000, 1_000));
        // One second newer than the read position → unread → notify.
        assert!(post_is_notifiable(OTHER, 5_001, Some(ME), 5_000, 1_000));
    }

    #[test]
    fn first_sync_history_is_suppressed_by_baseline_floor() {
        // On the very first visit (baseline just stamped at 10_000), the entire
        // pre-existing channel history (created_at < baseline) must NOT flood the
        // bell, even though it is all technically unread (read_ts=0).
        assert!(!post_is_notifiable(OTHER, 9_999, Some(ME), 0, 10_000));
        assert!(!post_is_notifiable(OTHER, 1, Some(ME), 0, 10_000));
        // Anything strictly after the floor is genuine new activity.
        assert!(post_is_notifiable(OTHER, 10_001, Some(ME), 0, 10_000));
    }

    #[test]
    fn unknown_self_pubkey_still_applies_read_and_baseline() {
        // Before auth resolves `me` is None; own-post filtering can't run, but the
        // unread + baseline gates still hold so we don't dump backlog.
        assert!(!post_is_notifiable(OTHER, 500, None, 0, 1_000));
        assert!(post_is_notifiable(OTHER, 2_000, None, 0, 1_000));
    }

    // -- Persisted sync state -------------------------------------------------

    #[test]
    fn sync_state_round_trips() {
        let state = SyncState {
            baseline: 1_700_000_000,
            notified_ids: vec!["a".into(), "b".into(), "c".into()],
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: SyncState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.baseline, state.baseline);
        assert_eq!(back.notified_ids, state.notified_ids);
    }

    #[test]
    fn sync_state_tolerates_missing_fields() {
        // A legacy/empty blob must deserialize to the "first sync" default rather
        // than failing (mirrors load_sync_state's unwrap_or_default contract).
        let back: SyncState = serde_json::from_str("{}").unwrap();
        assert_eq!(back.baseline, 0);
        assert!(back.notified_ids.is_empty());
        // Partial blob: only baseline present.
        let back: SyncState = serde_json::from_str(r#"{"baseline":42}"#).unwrap();
        assert_eq!(back.baseline, 42);
        assert!(back.notified_ids.is_empty());
    }
}
