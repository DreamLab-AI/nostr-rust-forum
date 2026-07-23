//! Notification store (F12) — mentions/replies count + bottom-bar badge.
//!
//! Watches the shared kind-42 stream (`RelayStore::posts`) for two classes of
//! event addressed to the signed-in viewer and turns them into unread
//! notifications:
//!
//! - **replies to the viewer's posts** — a NIP-28 reply carries `["p",
//!   <parent-author>]` (see `relay::channel_message_tags`), so a reply to the
//!   viewer p-tags the viewer;
//! - **@-mentions of the viewer** — `screens::mention_ptags` resolves `@handle`
//!   to `["p", <pubkey>]`, so a mention of the viewer p-tags the viewer.
//!
//! Both therefore reduce to a single predicate: a kind-42 event that **p-tags
//! the viewer and is not authored by the viewer**.
//!
//! The suppression model is a faithful port of the forum client's
//! `stores/notifications.rs` (the load-bearing fixes #8/#10/#12 are replicated):
//!
//! - **own-event suppression** — never notify on the viewer's own posts
//!   (`author == me`);
//! - **per-pubkey first-seen baseline** — the first time each account signs in
//!   on this device a `now()` floor is stamped and persisted PER PUBKEY
//!   (localStorage), so a fresh login (or a recovery-key login on a shared
//!   device) never surfaces the entire backlog. The SAME account's later logins
//!   reuse the persisted baseline, so activity that arrived while away still
//!   notifies (the "burst reader" case). A DIFFERENT account has no state under
//!   its own key and gets a fresh floor — it never inherits the prior user's
//!   history;
//! - **dedup by event id** — a persisted seen-id set (bounded) means a reload,
//!   or a still-on-relay backlog post whose visible notification aged out, never
//!   re-notifies.
//!
//! Pure decision logic (`event_p_tags`, `post_is_notifiable`, `dedup_key`,
//! `sync_state_key`, `resolved_baseline`, `has_reply_marker`, `preview`,
//! `classify_kind`, `author_name`, `parse_persisted_items`) is split out and
//! unit-tested without a DOM.
//!
//! Storage uses `web_sys` localStorage directly (no `gloo` dependency) under
//! BBS-scoped keys (`bbsnotif:*`) distinct from the forum client's
//! (`nostrbbs:*`) so the two same-origin SPAs never clobber each other's state.

use std::collections::HashSet;

#[cfg(target_arch = "wasm32")]
use gloo::events::EventListener;
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;

use nostr_bbs_core::event::NostrEvent;

use crate::relay::RelayStore;
use crate::signer::BbsSigner;

/// localStorage key for the persisted visible list (so the badge count survives
/// a reload). BBS-scoped — the forum client uses `nostrbbs:notifications`.
const ITEMS_KEY: &str = "bbsnotif:items";
/// Per-pubkey producer sync-state key prefix (baseline high-water mark + seen
/// ids). The signed-in pubkey is appended (see [`sync_state_key`]) so a
/// different account on the same device starts from a fresh baseline rather than
/// inheriting the previous user's history. Kept separate from the visible list
/// so it survives the 7-day eviction of that list.
const SYNC_STATE_KEY: &str = "bbsnotif:sync";
/// Storage-key owner suffix used before a pubkey is known (signed-out browsing).
const ANON_OWNER: &str = "anon";
/// Visible notifications older than this are evicted on load.
const MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;
/// Cap on persisted seen ids so the dedup set can't grow without bound. Old ids
/// are evicted (arbitrary-oldest) on overflow; re-notifying a long-evicted post
/// is far less bad than an unbounded set.
const MAX_SEEN_IDS: usize = 2_000;
/// Cap on the visible list.
const MAX_ITEMS: usize = 100;

// -- Types --------------------------------------------------------------------

/// Why a notification fired.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BbsNotifKind {
    /// A reply beneath one of the viewer's posts.
    Reply,
    /// An `@handle` mention of the viewer.
    Mention,
}

impl BbsNotifKind {
    /// Short phosphor label for the notifications list / badge tooltip.
    pub fn label(self) -> &'static str {
        match self {
            BbsNotifKind::Reply => "reply",
            BbsNotifKind::Mention => "mention",
        }
    }
}

/// A single notification entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BbsNotification {
    /// Stable dedup id derived from the source event id (`dedup_key`).
    pub id: String,
    /// Reply vs mention.
    pub kind: BbsNotifKind,
    /// Resolved author display name (kind-0), else a short hex.
    pub author: String,
    /// One-line preview of the post body.
    pub preview: String,
    /// Source event `created_at` (UNIX secs) — the list sorts newest-first on it.
    pub timestamp: u64,
    /// Whether the viewer has seen it (drives the unread count).
    pub read: bool,
}

/// Persisted visible-list envelope.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedItems {
    items: Vec<BbsNotification>,
}

/// Persisted per-pubkey producer state. Both fields are load-bearing for the
/// burst-reader workflow — see the module docs and the forum client's
/// `SyncState` for the full rationale.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SyncState {
    /// First-sync wall-clock floor for THIS account, captured once and persisted
    /// per-pubkey. Not reset on the same account's later logins.
    #[serde(default)]
    baseline: u64,
    /// Event ids already processed (notified OR suppressed), so a reload / 7-day
    /// eviction never re-notifies. Bounded by [`MAX_SEEN_IDS`].
    #[serde(default)]
    seen_ids: Vec<String>,
}

// -- Reactive store -----------------------------------------------------------

/// Reactive notification store, provided via Leptos context.
#[derive(Clone, Copy)]
pub struct NotificationStore {
    /// The visible notifications (newest-first).
    pub items: RwSignal<Vec<BbsNotification>>,
    /// Set once [`NotificationStore::init_sync`] has attached its effects, so it
    /// is idempotent across renders.
    synced: RwSignal<bool>,
    /// First-sync floor (UNIX secs) for the CURRENT account.
    baseline: RwSignal<u64>,
    /// Pubkey (or [`ANON_OWNER`]) whose sync-state is currently loaded. A change
    /// here (login / account switch) reloads the baseline and resets dedup.
    owner: RwSignal<Option<String>>,
    /// Event ids already processed — seeded from the persisted [`SyncState`] on
    /// construction so dedup survives reloads and 7-day item eviction.
    seen: RwSignal<HashSet<String>>,
}

impl NotificationStore {
    fn new() -> Self {
        // Owner is unknown at construction, so seed from the anon-scoped list; the
        // per-pubkey resolver in `init_sync` reloads the correct account's items
        // (and clears anon state) the moment auth resolves.
        let loaded = load_items(ANON_OWNER);
        Self {
            items: RwSignal::new(loaded),
            synced: RwSignal::new(false),
            baseline: RwSignal::new(0),
            owner: RwSignal::new(None),
            seen: RwSignal::new(HashSet::new()),
        }
    }

    /// Reactive count of unread notifications — the bottom-bar badge value.
    pub fn unread_count(&self) -> Memo<usize> {
        let items = self.items;
        Memo::new(move |_| items.get().iter().filter(|n| !n.read).count())
    }

    /// Mark a single notification (by id) read.
    pub fn mark_read(&self, id: &str) {
        let id = id.to_string();
        self.items.update(|list| {
            if let Some(n) = list.iter_mut().find(|n| n.id == id) {
                n.read = true;
            }
        });
        self.persist();
    }

    /// Mark every notification read — call when the viewer opens Boards (where
    /// replies/mentions live) so the badge clears.
    pub fn mark_all_read(&self) {
        let mut changed = false;
        self.items.update(|list| {
            for n in list.iter_mut() {
                if !n.read {
                    n.read = true;
                    changed = true;
                }
            }
        });
        if changed {
            self.persist();
        }
    }

    /// Clear the whole list.
    pub fn clear_all(&self) {
        self.items.set(Vec::new());
        self.persist();
    }

    /// Insert a notification, de-duplicated by its stable id. No-op if one with
    /// the same id already exists.
    fn add(&self, kind: BbsNotifKind, author: &str, preview: &str, timestamp: u64, event_id: &str) {
        let id = dedup_key(event_id);
        if self.items.with_untracked(|l| l.iter().any(|n| n.id == id)) {
            return;
        }
        let notification = BbsNotification {
            id,
            kind,
            author: author.to_string(),
            preview: preview.to_string(),
            timestamp,
            read: false,
        };
        self.items.update(|list| {
            list.insert(0, notification);
            // Newest-first even when backfilling out-of-order relay events.
            list.sort_by_key(|b| std::cmp::Reverse(b.timestamp));
            if list.len() > MAX_ITEMS {
                list.truncate(MAX_ITEMS);
            }
        });
        self.persist();
    }

    /// Attach the reactive effects that turn live kind-42 traffic into
    /// notifications. Idempotent. Must be called AFTER [`RelayStore`] and
    /// [`BbsSigner`] are in context (they are provided at the app root before
    /// this).
    pub fn init_sync(&self) {
        if self.synced.get_untracked() {
            return;
        }
        self.synced.set(true);

        // Reconcile read-state across same-account tabs / PWA clients (once).
        self.init_cross_tab_sync();

        // Provisional floor so no producer effect runs against baseline 0 (which
        // would treat the entire history as unread and flood the badge). The
        // per-pubkey resolver below refines it once auth resolves.
        if self.baseline.get_untracked() == 0 {
            self.baseline.set(now_secs());
        }

        let store = *self;
        let relay = match use_context::<RelayStore>() {
            Some(r) => r,
            None => return,
        };
        // `Option<BbsSigner>` is `Copy`, so it is captured (copied) into each
        // effect below; `s.pubkey().get()` is the tracked read of the signed-in
        // pubkey so the effects re-run on login / account switch.
        let signer = use_context::<BbsSigner>();

        // -- Per-pubkey sync-state resolver (#10/#12) -------------------------
        Effect::new(move |_| {
            let owner_key = signer
                .and_then(|s| s.pubkey().get())
                .unwrap_or_else(|| ANON_OWNER.to_string());
            if store.owner.get_untracked().as_deref() == Some(owner_key.as_str()) {
                return; // already loaded for this account
            }
            let state = load_sync_state(&owner_key);
            // Reset per-account dedup so a switch never leaks the prior account's
            // "already seen" set.
            store.seen.set(state.seen_ids.iter().cloned().collect());
            // Load THIS account's visible list (per-pubkey scoped), replacing the
            // prior owner's items wholesale so a new viewer on a shared device
            // never sees the previous user's notification previews/authors.
            store.items.set(load_items(&owner_key));
            store.owner.set(Some(owner_key));
            // First login for this account on this device (persisted 0) floors at
            // now so all pre-existing history is backlog, not a flood; a returning
            // account reuses its persisted floor (burst-reader).
            let first_sync = state.baseline == 0;
            store
                .baseline
                .set(resolved_baseline(state.baseline, now_secs()));
            if first_sync {
                store.persist_sync_state();
            }
        });

        // -- Replies + @-mentions to the viewer (kind-42) ---------------------
        let posts_sig = relay.posts;
        let profiles_sig = relay.profiles;
        Effect::new(move |_| {
            // Tracked reads: re-run once the per-pubkey baseline resolves, when
            // auth resolves (own-post suppression), and on every new post.
            let baseline = store.baseline.get();
            let me = signer.and_then(|s| s.pubkey().get());
            let posts = posts_sig.get();
            let mut changed = false;
            for ev in posts.iter() {
                if store.seen.with_untracked(|s| s.contains(&ev.id)) {
                    continue;
                }
                // Mark every processed event seen (notified or not) so it is never
                // re-scanned; bound the set FIFO-ish on overflow.
                store.seen.update(|s| {
                    if s.len() >= MAX_SEEN_IDS {
                        if let Some(victim) = s.iter().next().cloned() {
                            s.remove(&victim);
                        }
                    }
                    s.insert(ev.id.clone());
                });
                changed = true;

                let mentions_me = me
                    .as_deref()
                    .map(|pk| event_p_tags(&ev.tags, pk))
                    .unwrap_or(false);
                if !post_is_notifiable(
                    &ev.pubkey,
                    ev.created_at,
                    me.as_deref(),
                    baseline,
                    mentions_me,
                ) {
                    continue;
                }
                let kind = classify_kind(has_reply_marker(&ev.tags));
                let author =
                    profiles_sig.with_untracked(|profiles| author_name(profiles, &ev.pubkey));
                store.add(kind, &author, &preview(&ev.content), ev.created_at, &ev.id);
            }
            if changed {
                store.persist_sync_state();
            }
        });
    }

    /// Keep this tab's `items` in lock-step with any OTHER same-account tab /
    /// PWA client (all auto-authenticate the same account off shared
    /// localStorage). Without this, one tab marking notifications read persists
    /// `read:true`, then a STALE sibling tab persists its own `read:false`
    /// snapshot on its next write and reverts the shared per-pubkey list back to
    /// unread ("mark all read keeps resetting"). The `storage` event fires only
    /// in the OTHER tabs, so on a write to THIS owner's list key we reload from
    /// that authoritative snapshot. Load-only, so it can't echo into a loop. A
    /// faithful port of the forum client's `init_cross_tab_sync`.
    #[cfg(target_arch = "wasm32")]
    fn init_cross_tab_sync(&self) {
        let store = *self;
        let listener = EventListener::new(&gloo::utils::window(), "storage", move |event| {
            let changed = event
                .dyn_ref::<web_sys::StorageEvent>()
                .and_then(|e| e.key());
            let owner = store
                .owner
                .get_untracked()
                .unwrap_or_else(|| ANON_OWNER.to_string());
            if storage_change_is_ours(changed.as_deref(), &owner) {
                store.items.set(load_items_no_persist(&owner));
            }
        });
        // The store lives for the whole app session; keep the listener alive.
        listener.forget();
    }

    /// No-op off-wasm (host unit tests): there is no DOM `storage` event.
    #[cfg(not(target_arch = "wasm32"))]
    fn init_cross_tab_sync(&self) {}

    fn persist(&self) {
        let owner = self
            .owner
            .get_untracked()
            .unwrap_or_else(|| ANON_OWNER.to_string());
        let data = PersistedItems {
            items: self.items.get_untracked(),
        };
        if let Ok(json) = serde_json::to_string(&data) {
            ls_set(&items_key(&owner), &json);
        }
    }

    /// Persist the producer sync-state (baseline + seen ids) to the CURRENT
    /// account's per-pubkey key. No-op until the resolver has established an
    /// owner.
    fn persist_sync_state(&self) {
        let owner = match self.owner.get_untracked() {
            Some(o) => o,
            None => return,
        };
        let state = SyncState {
            baseline: self.baseline.get_untracked(),
            seen_ids: self.seen.with_untracked(|s| s.iter().cloned().collect()),
        };
        if let Ok(json) = serde_json::to_string(&state) {
            ls_set(&sync_state_key(&owner), &json);
        }
    }
}

// -- Context providers --------------------------------------------------------

/// Provide the notification store at the app root. Registers it as the fallback
/// singleton too, so any later context miss resolves to *this* instance (badge
/// and list stay on one `items` signal).
pub fn provide_notification_store() {
    let store = NotificationStore::new();
    FALLBACK_STORE.with(|cell| {
        *cell.borrow_mut() = Some(store);
    });
    provide_context(store);
}

/// Read the notification store from context, falling back to a single
/// process-wide instance on a context miss (never a fresh empty one, or the
/// badge could diverge from the list).
pub fn use_notification_store() -> NotificationStore {
    if let Some(store) = use_context::<NotificationStore>() {
        return store;
    }
    let store = fallback_singleton();
    provide_context(store);
    store
}

thread_local! {
    /// Shared store used only on a context miss so every consumer still observes
    /// one set of reactive signals. wasm is single-threaded.
    static FALLBACK_STORE: std::cell::RefCell<Option<NotificationStore>> =
        const { std::cell::RefCell::new(None) };
}

fn fallback_singleton() -> NotificationStore {
    FALLBACK_STORE.with(|cell| {
        if let Some(store) = *cell.borrow() {
            return store;
        }
        let store = NotificationStore::new();
        *cell.borrow_mut() = Some(store);
        store
    })
}

// -- Pure logic (unit-tested) -------------------------------------------------

/// Whether `tags` carry a `["p", pubkey]` entry (case-insensitive hex compare) —
/// the NIP-10 mention / reply-author convention. A reply to the viewer's post
/// p-tags the viewer (parent author); an `@handle` mention resolves to a p-tag.
fn event_p_tags(tags: &[Vec<String>], pubkey: &str) -> bool {
    tags.iter()
        .any(|t| t.len() >= 2 && t[0] == "p" && t[1].eq_ignore_ascii_case(pubkey))
}

/// Whether `tags` carry a NIP-28 `reply`-marked `e` tag — i.e. the event is a
/// reply, not a thread root. Distinguishes a reply-to-me from a mention-in-root.
fn has_reply_marker(tags: &[Vec<String>]) -> bool {
    tags.iter().any(|t| {
        t.first().map(String::as_str) == Some("e") && t.get(3).map(String::as_str) == Some("reply")
    })
}

/// Reply vs mention from whether the event is a reply.
fn classify_kind(is_reply: bool) -> BbsNotifKind {
    if is_reply {
        BbsNotifKind::Reply
    } else {
        BbsNotifKind::Mention
    }
}

/// Pure suppression predicate for a kind-42 post. Returns `true` when the post is
/// genuine, unseen activity addressed to the viewer that should raise a
/// notification. Notifiable iff ALL hold:
/// - it p-tags the viewer (`mentions_me`) — a reply-to-me or an @-mention;
/// - it is not the viewer's own (`author != me`);
/// - it is newer than the first-sync floor (`created_at > baseline`), which only
///   suppresses pre-first-visit history because `baseline` is persisted and never
///   reset between the same account's sessions.
///
/// Dedup against already-seen ids is the caller's persisted `seen` set, not here.
fn post_is_notifiable(
    author: &str,
    created_at: u64,
    me: Option<&str>,
    baseline: u64,
    mentions_me: bool,
) -> bool {
    if !mentions_me {
        return false;
    }
    if let Some(pk) = me {
        if author == pk {
            return false;
        }
    }
    created_at > baseline
}

/// Stable notification id from a source event id — namespaced so it never
/// collides with any other id space in localStorage.
fn dedup_key(event_id: &str) -> String {
    format!("notif:{event_id}")
}

/// Per-pubkey producer-state localStorage key.
fn sync_state_key(owner: &str) -> String {
    format!("{SYNC_STATE_KEY}:{owner}")
}

/// Per-pubkey visible-list localStorage key. Scoped like [`sync_state_key`] so a
/// different account on a shared device never inherits the previous user's
/// notification items (cross-account bleed fix).
fn items_key(owner: &str) -> String {
    format!("{ITEMS_KEY}:{owner}")
}

/// The baseline floor to use given a persisted value: `now` on the first sync
/// (persisted 0), else the persisted floor (preserving burst-reader behaviour).
fn resolved_baseline(persisted: u64, now: u64) -> u64 {
    if persisted == 0 {
        now
    } else {
        persisted
    }
}

/// Resolve a pubkey to a kind-0 display name (`display_name`, else `name`),
/// falling back to a short hex when unknown.
fn author_name(profiles: &[NostrEvent], pubkey: &str) -> String {
    for ev in profiles {
        if ev.pubkey == pubkey {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&ev.content) {
                if let Some(n) = v
                    .get("display_name")
                    .and_then(|x| x.as_str())
                    .filter(|s| !s.trim().is_empty())
                {
                    return n.to_string();
                }
                if let Some(n) = v
                    .get("name")
                    .and_then(|x| x.as_str())
                    .filter(|s| !s.trim().is_empty())
                {
                    return n.to_string();
                }
            }
        }
    }
    crate::relay::short_id(pubkey)
}

/// Trim a post body to a short single-line preview.
fn preview(content: &str) -> String {
    let cleaned: String = content.split_whitespace().collect::<Vec<_>>().join(" ");
    const MAX: usize = 80;
    if cleaned.chars().count() > MAX {
        let truncated: String = cleaned.chars().take(MAX).collect();
        format!("{truncated}…")
    } else {
        cleaned
    }
}

/// Lenient, per-item parse of the persisted `{ "items": [...] }` blob: entries
/// that don't match the current [`BbsNotification`] schema are dropped rather
/// than failing the whole list, and anything older than 7 days is evicted.
fn parse_persisted_items(value: &serde_json::Value, now: u64) -> Vec<BbsNotification> {
    value
        .get("items")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| serde_json::from_value::<BbsNotification>(item.clone()).ok())
                .filter(|n| now.saturating_sub(n.timestamp) < MAX_AGE_SECS)
                .collect()
        })
        .unwrap_or_default()
}

// -- Storage / time (wasm) ----------------------------------------------------

#[cfg(target_arch = "wasm32")]
fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

#[cfg(not(target_arch = "wasm32"))]
fn now_secs() -> u64 {
    0
}

#[cfg(target_arch = "wasm32")]
fn local_storage() -> Option<web_sys::Storage> {
    web_sys::window().and_then(|w| w.local_storage().ok().flatten())
}

#[cfg(target_arch = "wasm32")]
fn ls_get(key: &str) -> Option<String> {
    local_storage().and_then(|s| s.get_item(key).ok().flatten())
}

#[cfg(target_arch = "wasm32")]
fn ls_set(key: &str, val: &str) {
    if let Some(s) = local_storage() {
        let _ = s.set_item(key, val);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn ls_get(_key: &str) -> Option<String> {
    None
}

#[cfg(not(target_arch = "wasm32"))]
fn ls_set(_key: &str, _val: &str) {}

/// Load the persisted sync-state for `owner`, tolerating absence / schema drift
/// (returns the default — baseline 0, empty set — so a corrupt or missing blob
/// just means "first sync").
fn load_sync_state(owner: &str) -> SyncState {
    ls_get(&sync_state_key(owner))
        .and_then(|raw| serde_json::from_str::<SyncState>(&raw).ok())
        .unwrap_or_default()
}

/// Whether a `storage` event on `changed_key` should reload THIS owner's list:
/// a targeted write to `owner`'s per-pubkey items key, or a whole-storage clear
/// (`None`, e.g. `localStorage.clear()` on logout in another tab). A write to a
/// different account's list, or to the sync-state key, is irrelevant. Pure so
/// the cross-tab dispatch is unit-testable without a DOM. (Off-wasm the only
/// caller is the `#[cfg(test)]` unit test, so a non-test native build sees it
/// unused — hence the targeted allow.)
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn storage_change_is_ours(changed_key: Option<&str>, owner: &str) -> bool {
    match changed_key {
        None => true,
        Some(k) => k == items_key(owner),
    }
}

/// Load `owner`'s visible list WITHOUT re-persisting — the read-only path used
/// by the cross-tab `storage` handler ([`NotificationStore::init_cross_tab_sync`]).
/// Re-persisting there would bounce a fresh `storage` event to the other tabs;
/// mirrors [`load_items`] minus the migration write-back. Only the wasm cross-tab
/// handler calls it, so it is wasm-gated to keep native builds warning-clean.
#[cfg(target_arch = "wasm32")]
fn load_items_no_persist(owner: &str) -> Vec<BbsNotification> {
    let now = now_secs();
    match ls_get(&items_key(owner)) {
        Some(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(value) => parse_persisted_items(&value, now),
            Err(_) => Vec::new(),
        },
        None => Vec::new(),
    }
}

/// Load `owner`'s visible list (per-pubkey scoped), evicting >7-day entries and
/// dropping schema-drifted ones, then re-persisting the cleaned list so the
/// drift heals on first load.
fn load_items(owner: &str) -> Vec<BbsNotification> {
    let now = now_secs();
    let key = items_key(owner);
    let items = match ls_get(&key) {
        Some(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(value) => parse_persisted_items(&value, now),
            Err(_) => Vec::new(),
        },
        None => Vec::new(),
    };
    if let Ok(json) = serde_json::to_string(&PersistedItems {
        items: items.clone(),
    }) {
        ls_set(&key, &json);
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ME: &str = "11ed64225dd5e2c5e18f61ad43d5ad9272d08739d3a20dd25886197b0738663c";
    const OTHER: &str = "2de44d5622eef79519ac078f6e227a85aecbaefd561e4e50c5f51dfadbf916e9";

    // -- p-tag detection (reply-to-me + @-mention both reduce to this) --------

    #[test]
    fn p_tag_detects_mention_or_reply_author_case_insensitive() {
        // A reply to my post carries ["p", <me>] (parent author).
        let reply_tags = vec![
            vec!["e".into(), "chan".into(), "".into(), "root".into()],
            vec!["e".into(), "root".into(), "".into(), "reply".into()],
            vec!["p".into(), ME.to_string()],
        ];
        assert!(event_p_tags(&reply_tags, ME));
        assert!(!event_p_tags(&reply_tags, OTHER));
        // Case-insensitive hex compare.
        assert!(event_p_tags(&reply_tags, &ME.to_ascii_uppercase()));
        // A malformed p tag (no value) is not a match.
        assert!(!event_p_tags(&[vec!["p".into()]], ME));
        // A root post with no p tag is not a match.
        assert!(!event_p_tags(
            &[vec!["e".into(), "chan".into(), "".into(), "root".into()]],
            ME
        ));
    }

    #[test]
    fn reply_marker_distinguishes_reply_from_root_mention() {
        let root_mention = vec![
            vec!["e".into(), "chan".into(), "".into(), "root".into()],
            vec!["p".into(), ME.to_string()],
        ];
        let reply = vec![
            vec!["e".into(), "chan".into(), "".into(), "root".into()],
            vec!["e".into(), "root".into(), "".into(), "reply".into()],
            vec!["p".into(), ME.to_string()],
        ];
        assert!(!has_reply_marker(&root_mention));
        assert!(has_reply_marker(&reply));
        assert_eq!(classify_kind(has_reply_marker(&reply)), BbsNotifKind::Reply);
        assert_eq!(
            classify_kind(has_reply_marker(&root_mention)),
            BbsNotifKind::Mention
        );
    }

    // -- suppression predicate (own / baseline / mention gates) ---------------

    #[test]
    fn own_posts_never_notify() {
        // Even when it p-tags me (I @mentioned myself) and is well past baseline.
        assert!(!post_is_notifiable(ME, 5_000, Some(ME), 1_000, true));
    }

    #[test]
    fn foreign_post_that_pings_me_after_baseline_notifies() {
        assert!(post_is_notifiable(OTHER, 5_000, Some(ME), 1_000, true));
    }

    #[test]
    fn post_that_does_not_ping_me_is_ignored() {
        // A foreign post that doesn't p-tag me is not notifiable even if fresh.
        assert!(!post_is_notifiable(OTHER, 5_000, Some(ME), 1_000, false));
    }

    #[test]
    fn first_sync_history_suppressed_by_baseline_floor() {
        // On first visit (baseline just stamped at 10_000), the whole pre-existing
        // ping history (created_at <= baseline) must not flood the badge.
        assert!(!post_is_notifiable(OTHER, 9_999, Some(ME), 10_000, true));
        assert!(!post_is_notifiable(OTHER, 10_000, Some(ME), 10_000, true));
        // Strictly after the floor → genuine new activity.
        assert!(post_is_notifiable(OTHER, 10_001, Some(ME), 10_000, true));
    }

    #[test]
    fn burst_reader_backlog_after_baseline_notifies() {
        // Logged in first at t=1_000 (baseline=1_000), left; a ping landed at
        // t=2_000 while away. On return it must notify — the baseline is NOT reset
        // to now on the later login, so 2_000 > 1_000 still qualifies.
        assert!(post_is_notifiable(OTHER, 2_000, Some(ME), 1_000, true));
    }

    #[test]
    fn unknown_self_pubkey_still_applies_baseline_and_mention_gate() {
        // Before auth resolves `me` is None; own-post filtering can't run, but a
        // p-tag match can't be computed against an unknown self either — the
        // caller passes mentions_me=false, so nothing surfaces.
        assert!(!post_is_notifiable(OTHER, 2_000, None, 1_000, false));
        // If a mention were somehow flagged, the baseline gate still holds.
        assert!(!post_is_notifiable(OTHER, 500, None, 1_000, true));
        assert!(post_is_notifiable(OTHER, 2_000, None, 1_000, true));
    }

    // -- baseline / key / dedup helpers ---------------------------------------

    #[test]
    fn resolved_baseline_floors_first_sync_at_now_then_persists() {
        assert_eq!(resolved_baseline(0, 10_000), 10_000); // first sync
        assert_eq!(resolved_baseline(1_000, 10_000), 1_000); // persisted wins
    }

    #[test]
    fn sync_state_key_is_scoped_per_pubkey() {
        assert_eq!(sync_state_key(ME), format!("bbsnotif:sync:{ME}"));
        assert_ne!(sync_state_key(ME), sync_state_key(OTHER));
        assert_eq!(sync_state_key(ANON_OWNER), "bbsnotif:sync:anon");
    }

    #[test]
    fn cross_tab_reload_matches_current_owner_key_or_clear() {
        // The cross-tab `storage` handler reloads only when another tab wrote
        // THIS owner's list key or cleared all storage — not for a different
        // account's list nor for our own sync-state key. This is what stops a
        // stale sibling tab from clobbering a "mark all read" (the reset bug).
        assert!(storage_change_is_ours(Some(&items_key(ME)), ME));
        assert!(storage_change_is_ours(None, ME)); // localStorage.clear()
        assert!(!storage_change_is_ours(Some(&items_key(OTHER)), ME));
        assert!(!storage_change_is_ours(Some(&sync_state_key(ME)), ME));
    }

    #[test]
    fn items_key_is_scoped_per_pubkey() {
        // The visible list is now per-pubkey too, so account B never loads A's
        // notification items on a shared device.
        assert_eq!(items_key(ME), format!("bbsnotif:items:{ME}"));
        assert_ne!(items_key(ME), items_key(OTHER));
        assert_eq!(items_key(ANON_OWNER), "bbsnotif:items:anon");
    }

    #[test]
    fn dedup_key_is_namespaced_and_stable() {
        assert_eq!(dedup_key("abc"), "notif:abc");
        assert_eq!(dedup_key("abc"), dedup_key("abc"));
        assert_ne!(dedup_key("abc"), dedup_key("abd"));
    }

    // -- preview / author resolution ------------------------------------------

    #[test]
    fn preview_collapses_whitespace_and_truncates() {
        assert_eq!(preview("  hello\n\tworld  "), "hello world");
        let long = "x".repeat(200);
        let p = preview(&long);
        assert_eq!(p.chars().count(), 81); // 80 chars + ellipsis
        assert!(p.ends_with('…'));
    }

    fn profile(pubkey: &str, name: &str, display: &str) -> NostrEvent {
        NostrEvent {
            id: String::new(),
            pubkey: pubkey.to_string(),
            created_at: 0,
            kind: 0,
            tags: vec![],
            content: format!(r#"{{"name":"{name}","display_name":"{display}"}}"#),
            sig: String::new(),
        }
    }

    #[test]
    fn author_name_prefers_display_then_name_then_short_hex() {
        let profiles = vec![
            profile(ME, "junkiejarvis", "JunkieJarvis"),
            profile(OTHER, "aliceonly", ""),
        ];
        assert_eq!(author_name(&profiles, ME), "JunkieJarvis");
        assert_eq!(author_name(&profiles, OTHER), "aliceonly");
        // Unknown pubkey → short hex fallback (relay::short_id).
        let unknown = "ff".repeat(32);
        assert_eq!(
            author_name(&profiles, &unknown),
            crate::relay::short_id(&unknown)
        );
    }

    // -- persisted-list schema drift ------------------------------------------

    #[test]
    fn parse_items_drops_corrupt_keeps_valid() {
        let now = 1_000_000_000;
        let value = json!({
            "items": [
                { "id": "notif:a", "kind": "Mention", "author": "x", "preview": "hi",
                  "timestamp": now, "read": false },
                { "id": "notif:b", "kind": "LegacyKind", "author": "y", "preview": "z",
                  "timestamp": now, "read": true },
            ]
        });
        let items = parse_persisted_items(&value, now);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "notif:a");
        assert_eq!(items[0].kind, BbsNotifKind::Mention);
    }

    #[test]
    fn parse_items_evicts_older_than_seven_days() {
        let now = MAX_AGE_SECS + 100;
        let value = json!({
            "items": [
                { "id": "fresh", "kind": "Reply", "author": "a", "preview": "b",
                  "timestamp": now, "read": false },
                { "id": "stale", "kind": "Reply", "author": "a", "preview": "b",
                  "timestamp": 0, "read": false },
            ]
        });
        let items = parse_persisted_items(&value, now);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "fresh");
    }

    #[test]
    fn parse_items_handles_missing_or_wrong_shape() {
        assert!(parse_persisted_items(&json!({}), 0).is_empty());
        assert!(parse_persisted_items(&json!({ "items": "nope" }), 0).is_empty());
        assert!(parse_persisted_items(&json!(null), 0).is_empty());
    }

    #[test]
    fn sync_state_round_trips_and_tolerates_missing_fields() {
        let state = SyncState {
            baseline: 1_700_000_000,
            seen_ids: vec!["a".into(), "b".into()],
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: SyncState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.baseline, state.baseline);
        assert_eq!(back.seen_ids, state.seen_ids);
        // Legacy/empty blob → first-sync default.
        let empty: SyncState = serde_json::from_str("{}").unwrap();
        assert_eq!(empty.baseline, 0);
        assert!(empty.seen_ids.is_empty());
    }
}
