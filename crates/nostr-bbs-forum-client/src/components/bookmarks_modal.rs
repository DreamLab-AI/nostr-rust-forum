//! Bookmarks modal and bookmark store for persisting saved messages.
//!
//! Uses localStorage for persistence, with a reactive `RwSignal<Vec<Bookmark>>`
//! provided via Leptos context. Bookmarks are kept per signed-in identity
//! (`nostrbbs_bookmarks:v2:<pubkey>`; signed out or locked uses `anon`), and a
//! bookmark of a message from an encrypted zone stores no text preview: the
//! store is plain localStorage, readable by every account on the browser.
//!
//! Bookmarks saved before this lived under one browser-wide key and cannot be
//! attributed to an account. They stay visible to every account, as before
//! (removing one removes it for all), but their text previews are erased at
//! start-up: the channel was not recorded, so which ones came from an
//! encrypted zone cannot be told, and dropping the bookmarks themselves would
//! lose what members saved. The overlay shell is the shared
//! [`Modal`] primitive (backdrop-close, Esc,
//! body-scroll-lock, `role="dialog"`, `aria-modal`).

use gloo::storage::{LocalStorage, Storage};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};

use crate::app::base_href;
use crate::components::agent_badge::AgentBadge;
use crate::components::copy_key::KeyName;
use crate::components::modal::Modal;
use crate::utils::format_relative_time;

/// localStorage key of the bookmarks saved before bookmarks had owners.
const BOOKMARKS_KEY: &str = "nostrbbs_bookmarks";
/// Prefix of the owner-scoped keys (and of the legacy one).
const BOOKMARKS_PREFIX: &str = "nostrbbs_bookmarks";
/// Longest text preview kept, in characters.
const PREVIEW_CHARS: usize = 120;
/// Shown in place of a preview that was not kept.
const NO_PREVIEW: &str = "Open to read this message.";

/// localStorage key of `owner`'s bookmarks (`None`: signed out or locked).
fn bookmarks_key(owner: Option<&str>) -> String {
    format!("{BOOKMARKS_PREFIX}:v2:{}", owner.unwrap_or("anon"))
}

/// The preview stored for a bookmark: none for a message from an encrypted
/// zone, else up to [`PREVIEW_CHARS`] characters.
fn bookmark_preview(content: &str, encrypted: bool) -> String {
    if encrypted {
        return String::new();
    }
    if content.chars().count() > PREVIEW_CHARS {
        let head: String = content.chars().take(PREVIEW_CHARS - 3).collect();
        format!("{head}...")
    } else {
        content.to_string()
    }
}

/// Legacy bookmarks with their previews erased; `true` if any was erased.
fn redact_legacy(mut legacy: Vec<Bookmark>) -> (Vec<Bookmark>, bool) {
    let mut changed = false;
    for b in &mut legacy {
        if !b.content_preview.is_empty() {
            b.content_preview.clear();
            changed = true;
        }
    }
    (legacy, changed)
}

/// What an identity sees: its own bookmarks, then legacy ones it has not
/// bookmarked itself, most recent first.
fn merged(owned: &[Bookmark], legacy: &[Bookmark]) -> Vec<Bookmark> {
    let mut out: Vec<Bookmark> = owned.to_vec();
    out.extend(
        legacy
            .iter()
            .filter(|l| !owned.iter().any(|o| o.event_id == l.event_id))
            .cloned(),
    );
    out.sort_by_key(|x| std::cmp::Reverse(x.timestamp));
    out
}

// -- Bookmark data types ------------------------------------------------------

/// A single bookmarked message.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Bookmark {
    pub event_id: String,
    pub content_preview: String,
    pub author_pubkey: String,
    pub timestamp: u64,
    pub channel_id: String,
}

/// Reactive bookmark store backed by localStorage.
///
/// Provided as Leptos context via [`provide_bookmarks`]. Access with
/// [`use_bookmarks`].
#[derive(Clone, Copy)]
pub struct BookmarkStore {
    /// The signed-in identity's bookmarks.
    owned: RwSignal<Vec<Bookmark>>,
    /// Bookmarks from before bookmarks had owners, previews erased.
    legacy: RwSignal<Vec<Bookmark>>,
    /// Whose bookmarks `owned` holds (`None`: signed out or locked).
    owner: RwSignal<Option<String>>,
}

impl BookmarkStore {
    fn new() -> Self {
        let owner = current_owner();
        Self {
            owned: RwSignal::new(load_list(&bookmarks_key(owner.as_deref()))),
            legacy: RwSignal::new(load_list(BOOKMARKS_KEY)),
            owner: RwSignal::new(owner),
        }
    }

    /// Reactive signal of all bookmarks (sorted most recent first).
    pub fn list(&self) -> Signal<Vec<Bookmark>> {
        let (owned, legacy) = (self.owned, self.legacy);
        Signal::derive(move || owned.with(|o| legacy.with(|l| merged(o, l))))
    }

    /// Add a bookmark for the signed-in identity. `encrypted` marks a
    /// message from an encrypted zone, whose text is not stored. No-op if
    /// already bookmarked.
    pub fn add(
        &self,
        event_id: &str,
        content: &str,
        encrypted: bool,
        author: &str,
        timestamp: u64,
        channel_id: &str,
    ) {
        if self.is_bookmarked(event_id) {
            return;
        }
        self.owned.update(|bm| {
            bm.push(Bookmark {
                event_id: event_id.to_string(),
                content_preview: bookmark_preview(content, encrypted),
                author_pubkey: author.to_string(),
                timestamp,
                channel_id: channel_id.to_string(),
            });
        });
        self.persist();
    }

    /// Remove a bookmark by event ID (a legacy one is removed for everyone).
    pub fn remove(&self, event_id: &str) {
        self.owned
            .update(|bm| bm.retain(|b| b.event_id != event_id));
        let had_legacy = self
            .legacy
            .with_untracked(|l| l.iter().any(|b| b.event_id == event_id));
        if had_legacy {
            self.legacy
                .update(|bm| bm.retain(|b| b.event_id != event_id));
            save_list(BOOKMARKS_KEY, &self.legacy.get_untracked());
        }
        self.persist();
    }

    /// Check if an event is bookmarked.
    pub fn is_bookmarked(&self, event_id: &str) -> bool {
        let has = |v: &Vec<Bookmark>| v.iter().any(|b| b.event_id == event_id);
        self.owned.with_untracked(has) || self.legacy.with_untracked(has)
    }

    /// Reactive signal for checking bookmark state of a specific event.
    pub fn is_bookmarked_signal(&self, event_id: String) -> Memo<bool> {
        let (owned, legacy) = (self.owned, self.legacy);
        Memo::new(move |_| {
            let has = |v: &Vec<Bookmark>| v.iter().any(|b| b.event_id == event_id);
            owned.with(has) || legacy.with(has)
        })
    }

    /// Persist the identity's bookmarks to localStorage.
    fn persist(&self) {
        let key = bookmarks_key(self.owner.get_untracked().as_deref());
        save_list(&key, &self.owned.get_untracked());
    }

    /// Switch to `owner`'s bookmarks.
    fn follow(&self, owner: Option<String>) {
        if self.owner.get_untracked() == owner {
            return;
        }
        self.owned.set(load_list(&bookmarks_key(owner.as_deref())));
        self.owner.set(owner);
    }
}

/// The signed-in identity, if the session is authenticated.
fn current_owner() -> Option<String> {
    let auth = use_context::<crate::auth::AuthStore>()?;
    auth.state().with_untracked(owner_of)
}

fn owner_of(s: &crate::auth::AuthState) -> Option<String> {
    crate::zone_crypto::key_owner::owner_from_auth(s.is_authenticated, s.pubkey.as_deref())
        .map(|o| o.as_str().to_string())
}

/// Create and provide the bookmark store in Leptos context. Call once at app
/// root, after auth. Erases the previews of legacy bookmarks first.
pub fn provide_bookmarks() {
    let (legacy, changed) = redact_legacy(load_list(BOOKMARKS_KEY));
    if changed {
        save_list(BOOKMARKS_KEY, &legacy);
    }
    let store = BookmarkStore::new();
    provide_context(store);
    if let Some(auth) = use_context::<crate::auth::AuthStore>() {
        Effect::new(move |_| {
            let owner = auth.state().with(owner_of);
            store.follow(owner);
        });
    }
    // Cross-tab sync: without it, bookmarking a post in one tab is lost when a
    // stale sibling tab (same account) bookmarks something else and persists its
    // whole list. Reload load-only from any sibling's write. See notifications.rs.
    crate::utils::on_cross_tab_storage_prefix_write(BOOKMARKS_PREFIX, move || {
        let key = bookmarks_key(store.owner.get_untracked().as_deref());
        store.owned.set(load_list(&key));
        store.legacy.set(load_list(BOOKMARKS_KEY));
    });
}

/// Get the bookmark store from context.
///
/// `BookmarkStore` is `Copy`, so callers may resolve it once at component
/// construction and reuse it inside handlers. Historically several call sites
/// called this *inside* a click handler / `spawn_local`, where the reactive
/// owner can be detached — `expect_context` then panicked
/// ("expected context of type BookmarkStore"), and that panic aborts the whole
/// WASM runtime (dead app). This resolves defensively: if the context is
/// missing at call time we lazily provide a fresh store (backed by the same
/// localStorage key, so state is preserved) instead of panicking.
pub fn use_bookmarks() -> BookmarkStore {
    match use_context::<BookmarkStore>() {
        Some(store) => store,
        None => {
            let store = BookmarkStore::new();
            provide_context(store);
            store
        }
    }
}

// -- Modal component ----------------------------------------------------------

/// Modal displaying the user's bookmarked messages.
///
/// Shows a list sorted by most recent. Each entry shows a content preview,
/// author, timestamp, and navigation link. Bookmarks can be removed
/// individually.
#[component]
pub(crate) fn BookmarksModal(
    /// Controls modal visibility.
    is_open: RwSignal<bool>,
) -> impl IntoView {
    let store = use_bookmarks();
    let bookmarks = store.list();

    // Bookmark glyph rendered before the title in the shared Modal header.
    let title_icon = view! {
        <svg class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="currentColor">
            <path d="M5 2h14a1 1 0 011 1v19.143a.5.5 0 01-.766.424L12 18.03l-7.234 4.536A.5.5 0 014 22.143V3a1 1 0 011-1z"/>
        </svg>
    }
    .into_any();

    view! {
        <Modal
            is_open=is_open
            title="Bookmarks".to_string()
            title_icon=title_icon
            max_width="560px".to_string()
        >
            <div>
                    // Bookmark list
                    <div class="max-h-96 overflow-y-auto space-y-2">
                        <Show
                            when=move || !bookmarks.get().is_empty()
                            fallback=|| view! {
                                <div class="text-center py-10">
                                    <svg class="w-12 h-12 text-gray-700 mx-auto mb-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                        <path d="M5 2h14a1 1 0 011 1v19.143a.5.5 0 01-.766.424L12 18.03l-7.234 4.536A.5.5 0 014 22.143V3a1 1 0 011-1z" stroke-linecap="round" stroke-linejoin="round"/>
                                    </svg>
                                    <p class="text-gray-500 text-sm">"No bookmarks yet"</p>
                                    <p class="text-gray-600 text-xs mt-1">"Bookmark messages to find them later"</p>
                                </div>
                            }
                        >
                            {move || {
                                bookmarks.get().into_iter().map(|bm| {
                                    let event_id_rm = bm.event_id.clone();
                                    let preview = if bm.content_preview.is_empty() {
                                        NO_PREVIEW.to_string()
                                    } else {
                                        bm.content_preview.clone()
                                    };
                                    let avatar_text = bm.author_pubkey[..2].to_uppercase();
                                    // Tracked: the enclosing closure re-runs
                                    // when kind-0 metadata fills the cache.
                                    let author_pk = bm.author_pubkey.clone();
                                    // Disclosure badge (COM-13/F2): marks the
                                    // bookmarked message's author as an agent.
                                    let author_badge_pubkey = bm.author_pubkey.clone();
                                    let author_color = crate::utils::pubkey_color(&bm.author_pubkey);
                                    let time_str = format_relative_time(bm.timestamp);
                                    let href = base_href(&format!("/chat/{}", bm.channel_id));

                                    view! {
                                        <div class="glass-card p-3 rounded-xl group relative">
                                            <div class="flex items-start gap-3">
                                                // Author avatar dot
                                                <div
                                                    class="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold text-white flex-shrink-0 mt-0.5"
                                                    style=format!("background-color: {}", author_color)
                                                >
                                                    {avatar_text}
                                                </div>

                                                // Content
                                                <div class="flex-1 min-w-0">
                                                    <div class="flex items-center gap-2 text-xs text-gray-500 mb-1">
                                                        <span class="font-medium text-gray-400"><KeyName pubkey=author_pk key_class="font-mono" /></span>
                                                        <AgentBadge pubkey=author_badge_pubkey compact=true />
                                                        <span>{"\u{00B7}"}</span>
                                                        <span>{time_str}</span>
                                                    </div>
                                                    <a
                                                        href=href
                                                        class="text-sm text-gray-300 hover:text-white line-clamp-2 no-underline transition-colors"
                                                        on:click=move |_| is_open.set(false)
                                                    >
                                                        {preview}
                                                    </a>
                                                </div>

                                                // Remove button
                                                <button
                                                    class="opacity-0 group-hover:opacity-100 p-1 text-gray-600 hover:text-red-400 transition-all rounded-lg hover:bg-red-500/10 flex-shrink-0"
                                                    title="Remove bookmark"
                                                    on:click=move |_| {
                                                        store.remove(&event_id_rm);
                                                    }
                                                >
                                                    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                                        <line x1="18" y1="6" x2="6" y2="18" stroke-linecap="round"/>
                                                        <line x1="6" y1="6" x2="18" y2="18" stroke-linecap="round"/>
                                                    </svg>
                                                </button>
                                            </div>
                                        </div>
                                    }
                                }).collect_view()
                            }}
                        </Show>
                    </div>

                    // Footer count
                    <Show when=move || !bookmarks.get().is_empty()>
                        <div class="mt-3 pt-3 border-t border-gray-700/50 text-xs text-gray-600 text-center">
                            {move || format!("{} bookmark{}", bookmarks.get().len(), if bookmarks.get().len() == 1 { "" } else { "s" })}
                        </div>
                    </Show>
            </div>
        </Modal>
    }
}

// -- Helpers ------------------------------------------------------------------

fn load_list(key: &str) -> Vec<Bookmark> {
    LocalStorage::get::<String>(key)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_list(key: &str, list: &[Bookmark]) {
    if let Ok(json) = serde_json::to_string(list) {
        let _ = LocalStorage::set(key, json);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bm(id: &str, preview: &str, ts: u64) -> Bookmark {
        Bookmark {
            event_id: id.into(),
            content_preview: preview.into(),
            author_pubkey: "ab".repeat(32),
            timestamp: ts,
            channel_id: String::new(),
        }
    }

    #[test]
    fn keys_are_per_owner() {
        let a = "a".repeat(64);
        assert_ne!(bookmarks_key(Some(&a)), bookmarks_key(None));
        assert_ne!(bookmarks_key(Some(&a)), BOOKMARKS_KEY);
        assert!(bookmarks_key(Some(&a)).starts_with(BOOKMARKS_PREFIX));
    }

    #[test]
    fn an_encrypted_message_keeps_no_preview() {
        assert_eq!(bookmark_preview("the family secret", true), "");
        assert_eq!(bookmark_preview("hello", false), "hello");
        let long = "é".repeat(200);
        let p = bookmark_preview(&long, false);
        assert_eq!(p.chars().count(), PREVIEW_CHARS, "char-safe truncation");
        assert!(p.ends_with("..."));
    }

    #[test]
    fn legacy_previews_are_erased_and_bookmarks_kept() {
        let (out, changed) = redact_legacy(vec![bm("1", "secret", 1), bm("2", "", 2)]);
        assert!(changed);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|b| b.content_preview.is_empty()));
        assert!(!redact_legacy(out).1, "idempotent");
    }

    #[test]
    fn an_identity_sees_its_own_then_legacy_without_duplicates() {
        let owned = vec![bm("1", "mine", 5)];
        let legacy = vec![bm("1", "", 5), bm("2", "", 9)];
        let ids: Vec<String> = merged(&owned, &legacy)
            .into_iter()
            .map(|b| b.event_id)
            .collect();
        assert_eq!(ids, vec!["2", "1"]);
        assert_eq!(merged(&owned, &legacy)[1].content_preview, "mine");
    }
}
