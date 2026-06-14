//! Global search overlay activated by Cmd+K / Ctrl+K.
//!
//! Searches channels, messages, and users via relay and semantic search API.
//! Supports a "Semantic" toggle for RuVector-powered vector search.
//! Uses `.search-overlay` / `.search-panel` CSS classes from `style.css`.
//!
//! NOT built on the shared [`Modal`](crate::components::modal::Modal) primitive
//! by design: this is a Cmd/Ctrl+K *command palette*, not a dialog. It is
//! top-anchored (`padding-top: 15vh`, not centered), has a search input — not a
//! title+close-X header — as its head, and owns focus-scoped keyboard
//! navigation (ArrowUp/Down/Enter/Escape on the panel). Folding it into the
//! centered, title-bar `Modal` would lose the palette UX and double-bind
//! Escape (Modal's document-global Esc would race the palette's own handler).
//! It already implements backdrop-close, Escape-to-close, and auto-focus
//! itself.

use crate::app::base_href;
use crate::relay::{Filter, RelayConnection};
use crate::utils::search_client;
use gloo::events::EventListener;
use gloo::storage::{LocalStorage, Storage};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Shared open-state for the global search overlay. The app shell provides this
/// via context so a visible nav button can open the very same panel that the
/// Cmd/Ctrl+K shortcut toggles.
#[derive(Clone, Copy)]
pub struct SearchOpen(pub RwSignal<bool>);
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

const SEARCH_API: &str = match option_env!("VITE_SEARCH_API_URL") {
    Some(u) => u,
    None => "https://members-search-api.solitary-paper-764d.workers.dev",
};
const RECENT_KEY: &str = "nostrbbs_recent_searches";
const MAX_RECENT: usize = 5;
const DEBOUNCE_MS: i32 = 300;
const SEMANTIC_DEBOUNCE_MS: i32 = 500;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Tab {
    All,
    Channels,
    Messages,
    Users,
}
impl Tab {
    fn label(&self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Channels => "Channels",
            Self::Messages => "Messages",
            Self::Users => "Users",
        }
    }
}
const TABS: &[Tab] = &[Tab::All, Tab::Channels, Tab::Messages, Tab::Users];

#[derive(Clone, Debug)]
#[allow(dead_code)]
enum Hit {
    Channel {
        id: String,
        name: String,
        desc: String,
    },
    Message {
        content: String,
        author: String,
        channel_id: String,
    },
    /// Semantic search result with similarity score.
    SemanticMessage {
        id: String,
        content: String,
        label: String,
        score: f64,
    },
    User {
        pubkey: String,
        nickname: Option<String>,
    },
}
impl Hit {
    fn title(&self) -> String {
        match self {
            Self::Channel { name, .. } => name.clone(),
            Self::Message { content, .. } | Self::SemanticMessage { content, .. } => {
                if content.len() > 80 {
                    format!("{}...", &content[..77])
                } else {
                    content.clone()
                }
            }
            // Tracked: title()/subtitle() run inside the reactive results
            // closure, so the list re-renders when kind-0 metadata arrives.
            Self::User { nickname, pubkey } => nickname.clone().unwrap_or_else(|| {
                crate::components::user_display::use_display_name_tracked(pubkey)
            }),
        }
    }
    fn subtitle(&self) -> String {
        match self {
            Self::Channel { desc, .. } => desc.clone(),
            Self::Message { author, .. } => format!(
                "by {}",
                crate::components::user_display::use_display_name_tracked(author)
            ),
            Self::SemanticMessage { label, .. } if !label.is_empty() => {
                format!(
                    "by {}",
                    crate::components::user_display::use_display_name_tracked(label)
                )
            }
            Self::SemanticMessage { .. } => "semantic match".to_string(),
            Self::User { pubkey, .. } => {
                crate::components::user_display::use_display_name_tracked(pubkey)
            }
        }
    }
    fn icon(&self) -> (&'static str, &'static str) {
        match self {
            Self::Channel { .. } => ("#", "bg-blue-500/10 text-blue-400"),
            Self::Message { .. } => ("M", "bg-amber-500/10 text-amber-400"),
            Self::SemanticMessage { .. } => ("S", "bg-amber-500/10 text-amber-400"),
            Self::User { .. } => ("@", "bg-purple-500/10 text-purple-400"),
        }
    }
    fn href(&self) -> String {
        match self {
            Self::Channel { id, .. } => base_href(&format!("/chat/{}", id)),
            Self::Message { channel_id, .. } => base_href(&format!("/chat/{}", channel_id)),
            Self::SemanticMessage { id, .. } => base_href(&format!("/chat/{}", id)),
            Self::User { .. } => base_href("/chat"),
        }
    }
    fn score(&self) -> Option<f64> {
        match self {
            Self::SemanticMessage { score, .. } => Some(*score),
            _ => None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Recent {
    query: String,
}
#[derive(Clone, Deserialize)]
struct SHit {
    #[serde(default)]
    id: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    label: Option<String>,
}
#[derive(Clone, Deserialize)]
struct SResp {
    #[serde(default)]
    results: Vec<SHit>,
}

#[component]
pub(crate) fn GlobalSearch() -> impl IntoView {
    // Open-state is shared via context when the app shell provides it, so the
    // nav search button and Cmd/Ctrl+K drive one overlay. Falls back to a local
    // signal when rendered without a provider (keyboard-only).
    let is_open = use_context::<SearchOpen>()
        .map(|s| s.0)
        .unwrap_or_else(|| RwSignal::new(false));
    let query = RwSignal::new(String::new());
    let tab = RwSignal::new(Tab::All);
    let results: RwSignal<Vec<Hit>> = RwSignal::new(Vec::new());
    let loading = RwSignal::new(false);
    // Search/hydration errors surfaced in the panel (QA HIGH bug #4 — they
    // used to be swallowed silently while the list rendered nothing).
    let search_error: RwSignal<Option<String>> = RwSignal::new(None);
    let sel = RwSignal::new(0usize);
    let input_ref = NodeRef::<leptos::html::Input>::new();
    let recents = RwSignal::new(load_recents());

    // Semantic search toggle
    let semantic_mode = RwSignal::new(false);
    let api_online = RwSignal::new(false);

    // Capture the relay handle at setup time — `do_search` runs from a
    // debounce setTimeout callback where the reactive owner (and therefore
    // context lookup) is not guaranteed.
    let relay_handle = StoredValue::new(expect_context::<RelayConnection>());

    // Check search API status on open
    Effect::new(move |_| {
        if is_open.get() {
            wasm_bindgen_futures::spawn_local(async move {
                match search_client::get_search_status().await {
                    Ok(_) => api_online.set(true),
                    Err(_) => api_online.set(false),
                }
            });
        }
    });

    // Cmd/Ctrl+K global listener
    let listener = EventListener::new(&gloo::utils::document(), "keydown", move |e| {
        let e = e.dyn_ref::<web_sys::KeyboardEvent>().unwrap();
        if (e.meta_key() || e.ctrl_key()) && e.key() == "k" {
            e.prevent_default();
            is_open.update(|v| *v = !*v);
        }
    });
    let listener_sw = send_wrapper::SendWrapper::new(listener);
    on_cleanup(move || drop(listener_sw));

    // Auto-focus
    Effect::new(move |_| {
        if is_open.get() {
            let r = input_ref;
            crate::utils::set_timeout_once(
                move || {
                    if let Some(el) = r.get() {
                        let el: web_sys::HtmlElement = el.into();
                        let _ = el.focus();
                    }
                },
                50,
            );
        } else {
            query.set(String::new());
            results.set(Vec::new());
            sel.set(0);
            search_error.set(None);
        }
    });

    // Debounced search
    let dh = RwSignal::new(0i32);
    let do_search = move || {
        let q = query.get_untracked();
        let t = tab.get_untracked();
        let is_semantic = semantic_mode.get_untracked();
        if q.trim().is_empty() {
            results.set(Vec::new());
            loading.set(false);
            search_error.set(None);
            return;
        }
        loading.set(true);
        sel.set(0);
        search_error.set(None);
        let relay = relay_handle.with_value(|r| r.clone());
        wasm_bindgen_futures::spawn_local(async move {
            let mut out = Vec::new();
            let mut errors: Vec<String> = Vec::new();

            if t == Tab::All || t == Tab::Messages {
                // Collect raw API results as (event_id, score, content?, label?).
                // The search API responds with `{results:[{id,score},...]}` —
                // event bodies are NOT included, so hits must be hydrated
                // id→event via the relay below (QA HIGH bug #4: blank rows).
                let mut raw: Vec<(String, Option<f64>, Option<String>, Option<String>)> =
                    Vec::new();
                let mut fetch_err: Option<String> = None;

                let non_empty = |s: String| {
                    if s.trim().is_empty() {
                        None
                    } else {
                        Some(s)
                    }
                };

                if is_semantic {
                    // RuVector semantic search, with legacy text fallback.
                    match search_client::search_similar(&q, 10, 0.3, None).await {
                        Ok(hits) => {
                            for h in hits {
                                let content = h.content.and_then(non_empty);
                                raw.push((h.id, Some(h.score), content, h.label));
                            }
                        }
                        Err(sem_err) => match semantic_search(&q).await {
                            Ok(hits) => {
                                for h in hits {
                                    raw.push((h.id, None, non_empty(h.content), h.label));
                                }
                            }
                            Err(txt_err) => {
                                fetch_err = Some(format!("semantic: {sem_err}; text: {txt_err}"));
                            }
                        },
                    }
                } else {
                    // Legacy text search via /search
                    match semantic_search(&q).await {
                        Ok(hits) => {
                            for h in hits {
                                raw.push((h.id, None, non_empty(h.content), h.label));
                            }
                        }
                        Err(e) => fetch_err = Some(e),
                    }
                }

                if let Some(e) = fetch_err {
                    errors.push(format!("Message search failed: {e}"));
                }

                // Hydrate hits whose content is missing from the API response.
                let need: Vec<String> = raw
                    .iter()
                    .filter(|(_, _, content, _)| content.is_none())
                    .map(|(id, _, _, _)| id.clone())
                    .collect();
                let hydrated = hydrate_search_ids(&relay, need).await;

                let mut missing = 0usize;
                for (id, score, content, label) in raw {
                    let event = hydrated.get(&id);
                    let content = match content {
                        Some(c) => c,
                        None => match event {
                            Some(ev) if !ev.content.trim().is_empty() => ev.content.clone(),
                            _ => {
                                missing += 1;
                                continue;
                            }
                        },
                    };
                    let author = label
                        .filter(|l| !l.is_empty())
                        .or_else(|| event.map(|ev| ev.pubkey.clone()))
                        .unwrap_or_default();
                    // Link to the containing channel (kind-42 `e` tag) when
                    // known; fall back to the raw id.
                    let channel = event.and_then(channel_id_of).unwrap_or_else(|| id.clone());
                    match score {
                        Some(s) => out.push(Hit::SemanticMessage {
                            id: channel,
                            content,
                            label: author,
                            score: s,
                        }),
                        None => out.push(Hit::Message {
                            content,
                            author,
                            channel_id: channel,
                        }),
                    }
                }
                if missing > 0 {
                    errors.push(format!(
                        "{missing} matching message(s) could not be loaded from the relay"
                    ));
                }
            }

            if t == Tab::All || t == Tab::Channels {
                let ql = q.to_lowercase();
                let relay = relay.clone();
                let found: RwSignal<Vec<Hit>> = RwSignal::new(Vec::new());
                let qs = ql.clone();
                let cb = Rc::new(move |ev: nostr_bbs_core::NostrEvent| {
                    let nm = ev
                        .tags
                        .iter()
                        .find(|t| t.first().map(|v| v == "d").unwrap_or(false))
                        .and_then(|t| t.get(1))
                        .cloned()
                        .unwrap_or_default();
                    if nm.to_lowercase().contains(&qs) {
                        let d = if ev.content.len() > 100 {
                            format!("{}...", &ev.content[..97])
                        } else {
                            ev.content.clone()
                        };
                        found.update(|v| {
                            v.push(Hit::Channel {
                                id: nm.clone(),
                                name: nm,
                                desc: d,
                            })
                        });
                    }
                });
                let sid = relay.subscribe(
                    vec![Filter {
                        kinds: Some(vec![40]),
                        limit: Some(50),
                        ..Default::default()
                    }],
                    cb,
                    None,
                );
                crate::utils::set_timeout_once(
                    move || {
                        relay.unsubscribe(&sid);
                    },
                    800,
                );
                // Wait for relay results to arrive
                let delay = js_sys::Promise::new(&mut |resolve, _| {
                    let _ = web_sys::window()
                        .unwrap()
                        .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 900);
                });
                let _ = JsFuture::from(delay).await;
                out.extend(found.get_untracked());
            }
            if !errors.is_empty() {
                let msg = errors.join(" \u{2014} ");
                web_sys::console::warn_1(&format!("[search] {msg}").into());
                search_error.set(Some(msg));
            }
            results.set(out);
            loading.set(false);
        });
    };
    let trigger = move || {
        if let Some(w) = web_sys::window() {
            let p = dh.get_untracked();
            if p != 0 {
                w.clear_timeout_with_handle(p);
            }
        }
        let debounce = if semantic_mode.get_untracked() {
            SEMANTIC_DEBOUNCE_MS
        } else {
            DEBOUNCE_MS
        };
        if let Some(w) = web_sys::window() {
            let f = Closure::wrap(Box::new(move || {
                do_search();
            }) as Box<dyn FnMut()>);
            let h = w
                .set_timeout_with_callback_and_timeout_and_arguments_0(
                    f.as_ref().unchecked_ref(),
                    debounce,
                )
                .unwrap_or(0);
            dh.set(h);
            f.forget();
        }
    };
    let on_input = move |ev: leptos::ev::Event| {
        let t = ev.target().unwrap();
        let i: web_sys::HtmlInputElement = t.unchecked_into();
        query.set(i.value());
        trigger();
    };
    let nav_result = move |idx: usize| {
        let r = results.get_untracked();
        if let Some(hit) = r.get(idx) {
            save_recent(&query.get_untracked());
            recents.set(load_recents());
            let href = hit.href();
            is_open.set(false);
            if let Some(w) = web_sys::window() {
                let _ = w.location().set_href(&href);
            }
        }
    };
    let on_keydown = move |ev: leptos::ev::KeyboardEvent| {
        let n = results.get_untracked().len();
        match ev.key().as_str() {
            "Escape" => {
                ev.prevent_default();
                is_open.set(false);
            }
            "ArrowDown" => {
                ev.prevent_default();
                if n > 0 {
                    sel.update(|i| *i = (*i + 1) % n);
                }
            }
            "ArrowUp" => {
                ev.prevent_default();
                if n > 0 {
                    sel.update(|i| *i = if *i == 0 { n - 1 } else { *i - 1 });
                }
            }
            "Enter" => {
                ev.prevent_default();
                nav_result(sel.get_untracked());
            }
            _ => {}
        }
    };
    let tab_click = move |t: Tab| {
        tab.set(t);
        trigger();
    };
    let toggle_semantic = move |_| {
        semantic_mode.update(|v| *v = !*v);
        // Re-trigger search with current query
        if !query.get_untracked().trim().is_empty() {
            trigger();
        }
    };

    view! {
        <Show when=move || is_open.get()>
            <div class="search-overlay" on:click=move |_| is_open.set(false)>
                <div class="search-panel" on:click=|e| e.stop_propagation() on:keydown=on_keydown role="search" aria-label="Global search">
                    <div class="flex items-center gap-3 p-4 border-b border-gray-700/50">
                        <svg class="w-5 h-5 text-gray-400 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                        <input node_ref=input_ref type="text" class="flex-1 bg-transparent text-white placeholder-gray-500 focus:outline-none text-sm" placeholder="Search channels, messages, users..." prop:value=move || query.get() on:input=on_input aria-label="Search query" autocomplete="off" />
                        // Semantic toggle pill
                        <button
                            on:click=toggle_semantic
                            class=move || if semantic_mode.get() {
                                "px-2.5 py-1 rounded-full text-xs font-medium bg-amber-500/20 text-amber-400 border border-amber-500/30 transition-colors"
                            } else {
                                "px-2.5 py-1 rounded-full text-xs font-medium text-gray-500 hover:text-gray-300 border border-gray-700 hover:border-gray-600 transition-colors"
                            }
                            title="Toggle semantic search (RuVector)"
                        >
                            "Semantic"
                        </button>
                        <kbd class="hidden sm:inline-flex text-xs text-gray-500 bg-gray-800 px-2 py-1 rounded border border-gray-700">"ESC"</kbd>
                    </div>
                    <div class="flex items-center gap-1 px-4 pt-3 pb-2">
                        {TABS.iter().map(|t| { let t1 = t.clone(); let t2 = t.clone(); let l = t.label(); view! {
                            <button class=move || if tab.get() == t1 { "px-3 py-1 rounded-full text-xs font-medium bg-amber-500/20 text-amber-400 border border-amber-500/30" } else { "px-3 py-1 rounded-full text-xs font-medium text-gray-400 hover:text-white hover:bg-gray-800 border border-transparent transition-colors" } on:click=move |_| tab_click(t2.clone())>{l}</button>
                        }}).collect_view()}
                    </div>
                    <div class="max-h-80 overflow-y-auto px-2 pb-3">
                        <Show when=move || search_error.get().is_some()>
                            <div class="mx-1 mt-2 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2 text-xs text-red-300" role="alert">
                                {move || search_error.get().unwrap_or_default()}
                            </div>
                        </Show>
                        <Show when=move || loading.get()>
                            <div class="flex items-center justify-center py-8"><div class="animate-spin w-6 h-6 border-2 border-amber-400 border-t-transparent rounded-full"></div></div>
                        </Show>
                        <Show when=move || !loading.get() && !results.get().is_empty()>
                            <div class="space-y-1 mt-1">{move || { results.get().iter().enumerate().map(|(i, h)| {
                                let (il, ic) = h.icon(); let cls = format!("w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold {}", ic);
                                let ti = h.title(); let su = h.subtitle();
                                let score_badge = h.score();
                                view! { <button class=move || if sel.get() == i { "w-full flex items-center gap-3 px-3 py-2.5 rounded-lg bg-gray-800 text-left" } else { "w-full flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-gray-800/50 text-left transition-colors" } on:click=move |_| nav_result(i) on:mouseenter=move |_| sel.set(i)>
                                    <div class=cls.clone()>{il}</div>
                                    <div class="flex-1 min-w-0">
                                        <div class="flex items-center gap-2">
                                            {score_badge.map(|s| view! {
                                                <span class="text-xs px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-400 font-mono">
                                                    {format!("{:.0}%", s * 100.0)}
                                                </span>
                                            })}
                                            <p class="text-sm text-white truncate">{ti.clone()}</p>
                                        </div>
                                        <p class="text-xs text-gray-500 truncate">{su.clone()}</p>
                                    </div>
                                    <svg class="w-4 h-4 text-gray-600 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                                </button> }
                            }).collect_view() }}</div>
                        </Show>
                        <Show when=move || !loading.get() && results.get().is_empty() && !query.get().trim().is_empty()>
                            <p class="text-center text-gray-500 text-sm py-8">{move || format!("No results found for '{}'", query.get())}</p>
                        </Show>
                        <Show when=move || !loading.get() && query.get().trim().is_empty()>
                            <div class="px-2 py-4">
                                <Show when=move || !recents.get().is_empty()>
                                    <p class="text-xs text-gray-500 uppercase tracking-wider mb-2 px-1">"Recent"</p>
                                    {move || recents.get().iter().map(|rs| { let q1 = rs.query.clone(); let q2 = rs.query.clone(); view! {
                                        <button class="w-full flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-gray-800/50 text-left transition-colors" on:click=move |_| { query.set(q1.clone()); trigger(); }>
                                            <svg class="w-4 h-4 text-gray-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 102.13-9.36L1 10"/></svg>
                                            <span class="text-sm text-gray-400">{q2.clone()}</span>
                                        </button>
                                    }}).collect_view()}
                                </Show>
                                <Show when=move || recents.get().is_empty()>
                                    <p class="text-center text-gray-500 text-sm py-4">"Type to search..."</p>
                                </Show>
                            </div>
                        </Show>
                    </div>
                    <div class="border-t border-gray-700/50 px-4 py-2.5 flex items-center justify-between text-xs text-gray-600">
                        <div class="flex items-center gap-3">
                            <span class="flex items-center gap-1"><kbd class="px-1.5 py-0.5 bg-gray-800 rounded border border-gray-700">{"\u{2191}\u{2193}"}</kbd>" navigate"</span>
                            <span class="flex items-center gap-1"><kbd class="px-1.5 py-0.5 bg-gray-800 rounded border border-gray-700">{"\u{21B5}"}</kbd>" select"</span>
                        </div>
                        <div class="flex items-center gap-3">
                            // Search API status indicator
                            {move || if semantic_mode.get() {
                                if api_online.get() {
                                    view! { <span class="flex items-center gap-1 text-green-600"><span class="w-1.5 h-1.5 rounded-full bg-green-500"></span>"RuVector"</span> }.into_any()
                                } else {
                                    view! { <span class="flex items-center gap-1 text-yellow-600"><span class="w-1.5 h-1.5 rounded-full bg-yellow-500"></span>"text only"</span> }.into_any()
                                }
                            } else {
                                view! { <span></span> }.into_any()
                            }}
                            <span class="flex items-center gap-1"><kbd class="px-1.5 py-0.5 bg-gray-800 rounded border border-gray-700">"esc"</kbd>" close"</span>
                        </div>
                    </div>
                </div>
            </div>
        </Show>
    }
}

/// Extract the containing channel id from a kind-42 message event (`e` tag).
fn channel_id_of(ev: &nostr_bbs_core::NostrEvent) -> Option<String> {
    ev.tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == "e")
        .map(|t| t[1].clone())
}

/// Hydrate search-result event ids into full events via a relay `ids` REQ.
///
/// The search API only returns `{id, score}` pairs; the event body, author,
/// and channel must be fetched from the relay. Waits up to 1.2s for results
/// then unsubscribes. Missing ids (deleted or zone-withheld events) are
/// simply absent from the returned map — callers surface the count.
async fn hydrate_search_ids(
    relay: &RelayConnection,
    ids: Vec<String>,
) -> HashMap<String, nostr_bbs_core::NostrEvent> {
    if ids.is_empty() {
        return HashMap::new();
    }
    let found: RwSignal<HashMap<String, nostr_bbs_core::NostrEvent>> =
        RwSignal::new(HashMap::new());
    let cb = Rc::new(move |ev: nostr_bbs_core::NostrEvent| {
        found.update(|m| {
            m.insert(ev.id.clone(), ev);
        });
    });
    let sid = relay.subscribe(
        vec![Filter {
            ids: Some(ids),
            ..Default::default()
        }],
        cb,
        None,
    );
    let delay = js_sys::Promise::new(&mut |resolve, _| {
        let _ = web_sys::window()
            .unwrap()
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 1_200);
    });
    let _ = JsFuture::from(delay).await;
    relay.unsubscribe(&sid);
    found.get_untracked()
}

async fn semantic_search(query: &str) -> Result<Vec<SHit>, String> {
    let url = format!("{}/search", SEARCH_API);
    let body_str = serde_json::to_string(&serde_json::json!({ "query": query, "limit": 10 }))
        .map_err(|e| e.to_string())?;
    let window = web_sys::window().ok_or("No window")?;
    let init = web_sys::RequestInit::new();
    init.set_method("POST");
    let headers = web_sys::Headers::new().map_err(|e| format!("{e:?}"))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| format!("{e:?}"))?;
    init.set_headers(&headers);
    init.set_body(&JsValue::from_str(&body_str));
    let req = web_sys::Request::new_with_str_and_init(&url, &init).map_err(|e| format!("{e:?}"))?;
    let rv = JsFuture::from(window.fetch_with_request(&req))
        .await
        .map_err(|e| format!("{e:?}"))?;
    let resp: web_sys::Response = rv.unchecked_into();
    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let jv = JsFuture::from(resp.json().map_err(|e| format!("{e:?}"))?)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let data: SResp = serde_wasm_bindgen::from_value(jv).map_err(|e| format!("{e:?}"))?;
    Ok(data.results)
}

fn load_recents() -> Vec<Recent> {
    LocalStorage::get::<String>(RECENT_KEY)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_recent(q: &str) {
    if q.trim().is_empty() {
        return;
    }
    let mut r = load_recents();
    r.retain(|x| x.query != q);
    r.insert(
        0,
        Recent {
            query: q.to_string(),
        },
    );
    r.truncate(MAX_RECENT);
    if let Ok(j) = serde_json::to_string(&r) {
        let _ = LocalStorage::set(RECENT_KEY, j);
    }
}
