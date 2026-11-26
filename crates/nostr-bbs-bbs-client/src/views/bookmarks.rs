//! Per-identity saved bookmarks (`nostrbbs_bookmarks:v2:<pubkey>`).

use leptos::prelude::*;
use nostr_bbs_client_core::auth::use_auth;
use nostr_bbs_client_core::utils::format_relative_time;
use serde::{Deserialize, Serialize};

use crate::components::{AuthorChip, EmptyCard};
use crate::router::{use_router, Route};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BookmarkItem {
    pub event_id: String,
    pub zone: String,
    pub channel_id: String,
    pub root_id: String,
    pub author: String,
    pub preview: String,
    pub created_at: u64,
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn storage_key(pubkey: Option<&str>) -> String {
    format!("bbs_bookmarks:v2:{}", pubkey.unwrap_or("anon"))
}

pub fn load_bookmarks(pubkey: Option<&str>) -> Vec<BookmarkItem> {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(st) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
            if let Ok(Some(raw)) = st.get_item(&storage_key(pubkey)) {
                if let Ok(items) = serde_json::from_str::<Vec<BookmarkItem>>(&raw) {
                    return items;
                }
            }
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = pubkey;
    Vec::new()
}

fn save_bookmarks(pubkey: Option<&str>, items: &[BookmarkItem]) {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(st) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
            if let Ok(raw) = serde_json::to_string(items) {
                let _ = st.set_item(&storage_key(pubkey), &raw);
            }
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (pubkey, items);
}

pub fn is_bookmarked(pubkey: Option<&str>, event_id: &str) -> bool {
    load_bookmarks(pubkey)
        .iter()
        .any(|b| b.event_id == event_id)
}

/// Toggle a bookmark; returns `true` if now saved, `false` if removed.
pub fn toggle_bookmark(pubkey: Option<&str>, item: BookmarkItem) -> bool {
    let mut list = load_bookmarks(pubkey);
    if let Some(pos) = list.iter().position(|b| b.event_id == item.event_id) {
        list.remove(pos);
        save_bookmarks(pubkey, &list);
        false
    } else {
        list.insert(0, item);
        list.truncate(200);
        save_bookmarks(pubkey, &list);
        true
    }
}

/// Bookmarks view (`#/bookmarks`).
#[component]
pub fn BookmarksView() -> impl IntoView {
    let auth = use_auth();
    let router = use_router();
    let tick = RwSignal::new(0u32);

    view! {
        <div class="tui-container">
            <div class="tui-page-head">
                <div>
                    <h1 class="tui-page-title">"★ Bookmarks"</h1>
                    <p class="tui-page-sub">
                        "Per-identity saved posts. Encrypted-zone previews are redacted locally."
                    </p>
                </div>
            </div>

            {move || {
                let _ = tick.get();
                let pk = auth.pubkey().get();
                let list = load_bookmarks(pk.as_deref());
                if list.is_empty() {
                    return view! {
                        <EmptyCard
                            title="No bookmarks yet"
                            body="Tap '☆ Save' on any post in a thread to bookmark it here."
                        />
                    }.into_any();
                }

                view! {
                    <div class="tui-stack">
                        {list.into_iter().map(|b| {
                            let b_rm = b.clone();
                            let b_go = b.clone();
                            view! {
                                <div class="tui-card tui-stack">
                                    <div class="tui-row-between">
                                        <AuthorChip pubkey=b.author.clone() />
                                        <span class="tui-muted" style="font-size:0.78rem">
                                            {format_relative_time(b.created_at)}
                                        </span>
                                    </div>
                                    <div>{b.preview}</div>
                                    <div class="tui-row">
                                        <button
                                            type="button"
                                            class="bbs-btn bbs-btn-sm"
                                            on:click=move |_| router.go(Route::Thread {
                                                zone: b_go.zone.clone(),
                                                channel_id: b_go.channel_id.clone(),
                                                root_id: b_go.root_id.clone(),
                                            })
                                        >"Open Thread →"</button>
                                        <button
                                            type="button"
                                            class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                                            on:click=move |_| {
                                                let pk = auth.pubkey().get_untracked();
                                                toggle_bookmark(pk.as_deref(), b_rm.clone());
                                                tick.update(|n| *n += 1);
                                            }
                                        >"Remove"</button>
                                    </div>
                                </div>
                            }
                        }).collect_view()}
                    </div>
                }.into_any()
            }}
        </div>
    }
}
