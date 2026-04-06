//! Bookmarks modal and bookmark store for persisting saved messages.
//!
//! Uses localStorage for persistence, with a reactive `RwSignal<Vec<Bookmark>>`
//! provided via Leptos context. The modal uses `.modal-backdrop` / `.modal-panel`
//! CSS classes from `style.css`.

use gloo::storage::{LocalStorage, Storage};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};

use crate::app::base_href;
use crate::components::user_display::use_display_name;
use crate::utils::format_relative_time;

/// localStorage key for bookmarks.
const BOOKMARKS_KEY: &str = "bbs_bookmarks";

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
    bookmarks: RwSignal<Vec<Bookmark>>,
}

impl BookmarkStore {
    fn new() -> Self {
        let initial = load_bookmarks();
        Self {
            bookmarks: RwSignal::new(initial),
        }
    }

    /// Reactive signal of all bookmarks (sorted most recent first).
    pub fn list(&self) -> Signal<Vec<Bookmark>> {
        let sig = self.bookmarks;
        Signal::derive(move || {
            let mut bm = sig.get();
            bm.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            bm
        })
    }

    /// Add a bookmark. No-op if already bookmarked.
    pub fn add(
        &self,
        event_id: &str,
        content: &str,
        author: &str,
        timestamp: u64,
        channel_id: &str,
    ) {
        self.bookmarks.update(|bm| {
            if bm.iter().any(|b| b.event_id == event_id) {
                return;
            }
            let preview = if content.len() > 120 {
                format!("{}...", &content[..117])
            } else {
                content.to_string()
            };
            bm.push(Bookmark {
                event_id: event_id.to_string(),
                content_preview: preview,
                author_pubkey: author.to_string(),
                timestamp,
                channel_id: channel_id.to_string(),
            });
        });
        self.persist();
    }

    /// Remove a bookmark by event ID.
    pub fn remove(&self, event_id: &str) {
        self.bookmarks.update(|bm| {
            bm.retain(|b| b.event_id != event_id);
        });
        self.persist();
    }

    /// Check if an event is bookmarked.
    pub fn is_bookmarked(&self, event_id: &str) -> bool {
        self.bookmarks
            .get_untracked()
            .iter()
            .any(|b| b.event_id == event_id)
    }

    /// Reactive signal for checking bookmark state of a specific event.
    pub fn is_bookmarked_signal(&self, event_id: String) -> Memo<bool> {
        let sig = self.bookmarks;
        Memo::new(move |_| sig.get().iter().any(|b| b.event_id == event_id))
    }

    /// Persist current bookmarks to localStorage.
    fn persist(&self) {
        let bm = self.bookmarks.get_untracked();
        if let Ok(json) = serde_json::to_string(&bm) {
            let _ = LocalStorage::set(BOOKMARKS_KEY, json);
        }
    }
}

/// Create and provide the bookmark store in Leptos context. Call once at app root.
pub fn provide_bookmarks() {
    let store = BookmarkStore::new();
    provide_context(store);
}

/// Get the bookmark store from context. Panics if `provide_bookmarks` was not called.
pub fn use_bookmarks() -> BookmarkStore {
    expect_context::<BookmarkStore>()
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

    // Escape key + body scroll lock via Effect
    let is_open_esc = is_open;
    Effect::new(move |prev: Option<Option<gloo::events::EventListener>>| {
        if is_open_esc.get() {
            toggle_body_scroll(true);
            let listener =
                gloo::events::EventListener::new(&gloo::utils::document(), "keydown", move |e| {
                    use wasm_bindgen::JsCast;
                    let key_evt = e.unchecked_ref::<web_sys::KeyboardEvent>();
                    if key_evt.key() == "Escape" {
                        is_open_esc.set(false);
                    }
                });
            Some(listener)
        } else {
            toggle_body_scroll(false);
            drop(prev);
            None
        }
    });

    let on_backdrop = move |_| {
        is_open.set(false);
    };

    view! {
        <Show when=move || is_open.get()>
            <div class="modal-backdrop" on:click=on_backdrop>
                <div
                    class="modal-panel p-6"
                    style="width: min(90vw, 560px); max-width: 560px;"
                    on:click=|e| e.stop_propagation()
                >
                    // Header
                    <div class="flex items-center justify-between mb-4">
                        <div class="flex items-center gap-2">
                            <svg class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="currentColor">
                                <path d="M5 2h14a1 1 0 011 1v19.143a.5.5 0 01-.766.424L12 18.03l-7.234 4.536A.5.5 0 014 22.143V3a1 1 0 011-1z"/>
                            </svg>
                            <h2 class="text-lg font-bold text-white">"Bookmarks"</h2>
                        </div>
                        <button
                            class="text-gray-400 hover:text-white transition-colors p-1 rounded-lg hover:bg-gray-800"
                            on:click=move |_| is_open.set(false)
                        >
                            <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <line x1="18" y1="6" x2="6" y2="18" stroke-linecap="round"/>
                                <line x1="6" y1="6" x2="18" y2="18" stroke-linecap="round"/>
                            </svg>
                        </button>
                    </div>

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
                                    let preview = bm.content_preview.clone();
                                    let avatar_text = bm.author_pubkey[..2].to_uppercase();
                                    let author_short = use_display_name(&bm.author_pubkey);
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
                                                        <span class="font-medium text-gray-400">{author_short}</span>
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
            </div>
        </Show>
    }
}

// -- Helpers ------------------------------------------------------------------

fn load_bookmarks() -> Vec<Bookmark> {
    LocalStorage::get::<String>(BOOKMARKS_KEY)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn toggle_body_scroll(lock: bool) {
    if let Some(body) = gloo::utils::document().body() {
        let style = body.style();
        let _ = style.set_property("overflow", if lock { "hidden" } else { "" });
    }
}
