//! Global search overlay activated by Cmd+K / Ctrl+K.
//!
//! Searches channels, messages, and users via relay and semantic search API.
//! Supports a "Semantic" toggle for RuVector-powered vector search.
//! Uses `.search-overlay` / `.search-panel` CSS classes from `style.css`.

use crate::app::base_href;
use crate::relay::{Filter, RelayConnection};
use crate::utils::search_client;
use gloo::events::EventListener;
use gloo::storage::{LocalStorage, Storage};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

const SEARCH_API: &str = match option_env!("VITE_SEARCH_API_URL") {
    Some(u) => u,
    None => "https://your-search.your-subdomain.workers.dev",
};
const RECENT_KEY: &str = "bbs_recent_searches";
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
            Self::User { nickname, pubkey } => nickname
                .clone()
                .unwrap_or_else(|| crate::components::user_display::use_display_name(pubkey)),
        }
    }
    fn subtitle(&self) -> String {
        match self {
            Self::Channel { desc, .. } => desc.clone(),
            Self::Message { author, .. } => format!("by {}", crate::components::user_display::use_display_name(author)),
            Self::SemanticMessage { label, .. } if !label.is_empty() => {
                format!("by {}", crate::components::user_display::use_display_name(label))
            }
            Self::SemanticMessage { .. } => "semantic match".to_string(),
            Self::User { pubkey, .. } => crate::components::user_display::use_display_name(pubkey),
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
    let is_open = RwSignal::new(false);
    let query = RwSignal::new(String::new());
    let tab = RwSignal::new(Tab::All);
    let results: RwSignal<Vec<Hit>> = RwSignal::new(Vec::new());
    let loading = RwSignal::new(false);
    let sel = RwSignal::new(0usize);
    let input_ref = NodeRef::<leptos::html::Input>::new();
    let recents = RwSignal::new(load_recents());

    // Semantic search toggle
    let semantic_mode = RwSignal::new(false);
    let api_online = RwSignal::new(false);

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
            return;
        }
        loading.set(true);
        sel.set(0);
        wasm_bindgen_futures::spawn_local(async move {
            let mut out = Vec::new();

            if is_semantic && (t == Tab::All || t == Tab::Messages) {
                // Use RuVector semantic search
                match search_client::search_similar(&q, 10, 0.3, None).await {
                    Ok(hits) => {
                        for h in hits {
                            out.push(Hit::SemanticMessage {
                                id: h.id,
                                content: h.content.unwrap_or_default(),
                                label: h.label.unwrap_or_default(),
                                score: h.score,
                            });
                        }
                    }
                    Err(_) => {
                        // Fallback: try legacy text search on error
                        if let Ok(hits) = semantic_search(&q).await {
                            for h in hits {
                                out.push(Hit::Message {
                                    content: h.content,
                                    author: h.label.unwrap_or_default(),
                                    channel_id: h.id,
                                });
                            }
                        }
                    }
                }
            } else if t == Tab::All || t == Tab::Messages {
                // Legacy text search via /search
                if let Ok(hits) = semantic_search(&q).await {
                    for h in hits {
                        out.push(Hit::Message {
                            content: h.content,
                            author: h.label.unwrap_or_default(),
                            channel_id: h.id,
                        });
                    }
                }
            }

            if t == Tab::All || t == Tab::Channels {
                let ql = q.to_lowercase();
                let relay = expect_context::<RelayConnection>();
                let found: RwSignal<Vec<Hit>> = RwSignal::new(Vec::new());
                let qs = ql.clone();
                let cb = Rc::new(move |ev: nostr_core::NostrEvent| {
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
