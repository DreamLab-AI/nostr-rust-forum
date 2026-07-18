//! F11 — Global search: a phosphor-terminal command palette over the
//! search-worker plus the live relay stores.
//!
//! Opened by Cmd/Ctrl+K (accelerator), the `/search <q>` command, or a tappable
//! `⌕` affordance (its keyboard-accelerator twin — every hotkey has a tap path,
//! per the redesign spec §2.4). Top-anchored, backdrop- and Escape-closable, with
//! ArrowUp/Down/Enter navigation inside the panel.
//!
//! Design/origin: adapted from the forum client's `utils/search_client.rs`
//! (worker fetch + response shape) and `components/global_search.rs` (palette UX,
//! Cmd/Ctrl+K, keyboard nav), re-skinned to the BBS phosphor CSS and rewired to
//! the flat `Screen` state machine (`BbsState`) instead of `leptos_router`.
//! Reuses the shared relay stores (`RelayStore`) and runtime config
//! (`BbsConfig`); the write/identity path is untouched.
//!
//! Pure logic (query parsing, request/response shaping, ranking, match +
//! formatting helpers) lives in the sibling [`query`] module (native unit-tested).
//! Everything network-facing degrades gracefully: a worker that is unreachable
//! yields a friendly empty state — never a raw `JsValue` dump.

// Pure logic lives in `search_core.rs`; the module is named `query` (NOT `core`)
// to avoid shadowing / ambiguity with the std `core` crate in path position.
#[path = "search_core.rs"]
pub mod query;

use leptos::prelude::*;
// wasm-bindgen glue is only referenced on the wasm target — the crate gates all
// network / async work behind `cfg(target_arch = "wasm32")`, so the overlay
// still type-checks natively (unit tests) with these paths stubbed out.
#[cfg(target_arch = "wasm32")]
use send_wrapper::SendWrapper;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{prelude::*, JsCast};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;

use crate::chrome::BbsState;
use crate::config::BbsConfig;
use crate::menu::Screen;
use crate::relay::{self, RelayStore};
// `build_search_body` / `parse_results` are used only on the wasm fetch path
// (fully-qualified there) so the native unit-test build has no unused imports.
use query::{empty_state_message, format_score, name_matches, rank_and_dedup, truncate_title};

/// Max local message rows scanned from the open board, and the worker `limit`.
const LOCAL_MSG_CAP: usize = 20;
// Consumed only on the wasm fetch/debounce path; the native (unit-test) build
// never references them.
#[cfg(target_arch = "wasm32")]
const WORKER_LIMIT: usize = 12;
/// Total rows rendered (local + remote, after merge/dedup).
const RESULT_CAP: usize = 40;
#[cfg(target_arch = "wasm32")]
const DEBOUNCE_MS: i32 = 300;

/// Shared open-state for the search overlay, carried through Leptos context so
/// the `⌕` affordance, the `/search` command, and the Cmd/Ctrl+K accelerator all
/// drive the one overlay. `Copy` (both fields are signals).
#[derive(Clone, Copy)]
pub struct SearchOpen {
    /// Whether the overlay is visible.
    pub open: RwSignal<bool>,
    /// A query to seed the input with on the next open (from `/search <q>`).
    pub prefill: RwSignal<String>,
}

impl SearchOpen {
    pub fn new() -> Self {
        Self {
            open: RwSignal::new(false),
            prefill: RwSignal::new(String::new()),
        }
    }
}

impl Default for SearchOpen {
    fn default() -> Self {
        Self::new()
    }
}

/// Open the overlay from anywhere with a live reactive owner (the command line's
/// submit handler, a `⌕` button). No-op when the context isn't provided.
pub fn open_search(prefill: Option<String>) {
    if let Some(s) = use_context::<SearchOpen>() {
        if let Some(q) = prefill {
            s.prefill.set(q);
        }
        s.open.set(true);
    }
}

/// What a result row points at.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HitKind {
    Board,
    Member,
    Message,
}

/// A rendered result row.
#[derive(Clone)]
struct UiHit {
    kind: HitKind,
    /// Board: channel id · Member: pubkey · Message: event id.
    target: String,
    /// Message only: the containing board (kind-40) channel id, when resolved.
    channel: Option<String>,
    /// Message only: the thread root to open (when the hit is itself a root).
    thread: Option<String>,
    title: String,
    subtitle: String,
    score: Option<f64>,
}

impl UiHit {
    fn glyph(&self) -> &'static str {
        match self.kind {
            HitKind::Board => "\u{25A4}",   // ▤
            HitKind::Member => "\u{25CF}",  // ●
            HitKind::Message => "\u{25B8}", // ▸
        }
    }
}

/// kind-0 display name (display_name → name → short id), matching the Members
/// screen's resolver.
fn member_display(ev: &nostr_bbs_core::event::NostrEvent) -> String {
    serde_json::from_str::<serde_json::Value>(&ev.content)
        .ok()
        .and_then(|v| {
            v.get("display_name")
                .or_else(|| v.get("name"))
                .and_then(|n| n.as_str())
                .map(str::to_string)
        })
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| relay::short_id(&ev.pubkey))
}

/// Compute the LOCAL matches (boards, members, open-board messages) from the
/// live relay stores — instant, and the only results when the worker is down.
fn local_hits(store: &RelayStore, query: &str) -> Vec<UiHit> {
    let mut out: Vec<UiHit> = Vec::new();

    // Boards (kind-40) by channel name.
    for ev in store.channels.get_untracked() {
        let name = relay::channel_name(&ev);
        if name_matches(&name, query) {
            out.push(UiHit {
                kind: HitKind::Board,
                target: ev.id.clone(),
                channel: None,
                thread: None,
                title: name,
                subtitle: "board".to_string(),
                score: None,
            });
        }
    }

    // Members (kind-0) by display name.
    for ev in store.profiles.get_untracked() {
        let name = member_display(&ev);
        if name_matches(&name, query) {
            out.push(UiHit {
                kind: HitKind::Member,
                target: ev.pubkey.clone(),
                channel: None,
                thread: None,
                title: name,
                subtitle: format!("member \u{2022} #{}", relay::short_id(&ev.pubkey)),
                score: None,
            });
        }
    }

    // Messages (kind-42) in the currently-open board by content.
    for ev in store.posts.get_untracked().into_iter().take(200) {
        if name_matches(&ev.content, query) {
            let is_root = relay::reply_parent(&ev).is_none();
            out.push(UiHit {
                kind: HitKind::Message,
                target: ev.id.clone(),
                channel: relay::post_root_channel(&ev),
                thread: is_root.then(|| ev.id.clone()),
                title: truncate_title(&ev.content, 72),
                subtitle: format!("message \u{2022} {}", relay::short_id(&ev.pubkey)),
                score: None,
            });
            if out.iter().filter(|h| h.kind == HitKind::Message).count() >= LOCAL_MSG_CAP {
                break;
            }
        }
    }

    out
}

/// Map worker `/search` hits to message rows, resolving their board from the
/// loaded posts when possible (so the row opens the right board).
fn remote_hits(store: &RelayStore, raw: Vec<query::RawHit>) -> Vec<UiHit> {
    let posts = store.posts.get_untracked();
    rank_and_dedup(raw)
        .into_iter()
        .map(|h| {
            let local = posts.iter().find(|p| p.id == h.id);
            let channel = local.and_then(relay::post_root_channel);
            let thread = local
                .filter(|p| relay::reply_parent(p).is_none())
                .map(|p| p.id.clone());
            let body = h
                .content
                .filter(|c| !c.trim().is_empty())
                .or_else(|| local.map(|p| p.content.clone()))
                .unwrap_or_else(|| format!("message {}", relay::short_id(&h.id)));
            let who = h
                .label
                .filter(|l| !l.trim().is_empty())
                .or_else(|| local.map(|p| p.pubkey.clone()))
                .map(|pk| relay::short_id(&pk))
                .unwrap_or_default();
            let subtitle = if who.is_empty() {
                "message".to_string()
            } else {
                format!("message \u{2022} {who}")
            };
            UiHit {
                kind: HitKind::Message,
                target: h.id.clone(),
                channel,
                thread,
                title: truncate_title(&body, 72),
                subtitle,
                score: h.score,
            }
        })
        .collect()
}

/// Merge local + remote rows, dropping a remote message already shown locally,
/// and cap the total.
fn merge_hits(local: Vec<UiHit>, remote: Vec<UiHit>) -> Vec<UiHit> {
    let mut seen: std::collections::HashSet<String> =
        local.iter().map(|h| h.target.clone()).collect();
    let mut out = local;
    for h in remote {
        if seen.insert(h.target.clone()) {
            out.push(h);
        }
    }
    out.truncate(RESULT_CAP);
    out
}

/// Spawn the worker search off the UI, invoking `on_done` with the (friendly)
/// result. wasm: a real `spawn_local` + fetch. Native (unit tests): a no-op —
/// there is no event loop or `fetch`, so the closure is simply dropped.
#[cfg(target_arch = "wasm32")]
fn spawn_worker_search(
    base: String,
    query: String,
    on_done: impl Fn(Result<Vec<query::RawHit>, String>) + 'static,
) {
    wasm_bindgen_futures::spawn_local(async move {
        let outcome = worker_search(&base, &query).await;
        on_done(outcome);
    });
}

#[cfg(not(target_arch = "wasm32"))]
fn spawn_worker_search(
    _base: String,
    _query: String,
    _on_done: impl Fn(Result<Vec<query::RawHit>, String>) + 'static,
) {
}

/// POST the query to the worker `/search` endpoint and parse the hits. All
/// failure paths return a FRIENDLY message (never a raw `JsValue`); the caller
/// keeps the local results and shows the note.
#[cfg(target_arch = "wasm32")]
async fn worker_search(base: &str, query: &str) -> Result<Vec<query::RawHit>, String> {
    let url = format!("{}/search", base.trim_end_matches('/'));
    let body = query::build_search_body(query, WORKER_LIMIT);

    let opts = web_sys::RequestInit::new();
    opts.set_method("POST");
    opts.set_body(&JsValue::from_str(&body));
    let headers =
        web_sys::Headers::new().map_err(|_| "search request could not be built".to_string())?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|_| "search request could not be built".to_string())?;
    opts.set_headers(&headers);

    let request = web_sys::Request::new_with_str_and_init(&url, &opts)
        .map_err(|_| "search request could not be built".to_string())?;
    let window = web_sys::window().ok_or_else(|| "search is unavailable here".to_string())?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|_| "the search service is unreachable".to_string())?;
    let resp: web_sys::Response = resp_value
        .dyn_into()
        .map_err(|_| "the search service returned an unexpected reply".to_string())?;
    if !resp.ok() {
        return Err(format!(
            "the search service is unavailable ({})",
            resp.status()
        ));
    }
    let text = JsFuture::from(
        resp.text()
            .map_err(|_| "the search service returned no data".to_string())?,
    )
    .await
    .map_err(|_| "the search service returned no data".to_string())?;
    let text = text
        .as_string()
        .ok_or_else(|| "the search service returned no data".to_string())?;
    query::parse_results(&text)
}

/// The Cmd/Ctrl+K global accelerator: one window-level keydown listener that
/// toggles the overlay. Leaked for the app lifetime (single listener, mirrors
/// `chrome::install_key_handler`).
#[cfg(target_arch = "wasm32")]
fn install_hotkey(open: RwSignal<bool>) {
    let handler =
        Closure::<dyn FnMut(web_sys::KeyboardEvent)>::new(move |ev: web_sys::KeyboardEvent| {
            if (ev.meta_key() || ev.ctrl_key()) && ev.key().eq_ignore_ascii_case("k") {
                ev.prevent_default();
                open.update(|v| *v = !*v);
            }
        });
    if let Some(win) = web_sys::window() {
        let _ = win.add_event_listener_with_callback("keydown", handler.as_ref().unchecked_ref());
    }
    handler.forget();
}

/// The phosphor global-search overlay. Mount once at the app root (above the
/// screens); it is `position: fixed` and self-manages its own visibility.
#[component]
pub fn SearchOverlay(state: BbsState) -> impl IntoView {
    let cfg = use_context::<StoredValue<BbsConfig>>().expect("config");
    let store = use_context::<RelayStore>().expect("relay");
    let ctx = use_context::<SearchOpen>().unwrap_or_default();
    let is_open = ctx.open;
    let prefill = ctx.prefill;

    let query = RwSignal::new(String::new());
    let results: RwSignal<Vec<UiHit>> = RwSignal::new(Vec::new());
    let loading = RwSignal::new(false);
    let note: RwSignal<Option<String>> = RwSignal::new(None);
    let worker_ok = RwSignal::new(true);
    let sel = RwSignal::new(0usize);
    let input_ref = NodeRef::<leptos::html::Input>::new();

    // Search-worker base URL (new `SEARCH_API` config key). Empty → local-only.
    let search_base = cfg.with_value(|c| c.search_api.clone());
    let base_stored = StoredValue::new(search_base);

    // Cmd/Ctrl+K accelerator (installed once).
    #[cfg(target_arch = "wasm32")]
    install_hotkey(is_open);

    // The debounced search. Local matches render immediately; the worker (when
    // configured) augments them asynchronously and never blocks the UI.
    let do_search = move || {
        let q = query.get_untracked().trim().to_string();
        sel.set(0);
        note.set(None);
        if q.is_empty() {
            results.set(Vec::new());
            loading.set(false);
            worker_ok.set(true);
            return;
        }
        let local = local_hits(&store, &q);
        results.set(merge_hits(local.clone(), Vec::new()));
        let base = base_stored.get_value();
        if base.trim().is_empty() {
            // No worker configured — local-only; flag as "deep search offline".
            worker_ok.set(false);
            loading.set(false);
            return;
        }
        loading.set(true);
        let q_check = q.clone();
        spawn_worker_search(base, q, move |outcome| {
            // Guard against a stale response (query changed while awaiting).
            if query.get_untracked().trim() != q_check {
                return;
            }
            match outcome {
                Ok(raw) => {
                    worker_ok.set(true);
                    let remote = remote_hits(&store, raw);
                    results.set(merge_hits(local.clone(), remote));
                }
                Err(msg) => {
                    worker_ok.set(false);
                    note.set(Some(msg));
                }
            }
            loading.set(false);
        });
        // Native (tests) never runs the async callback — settle the flags so the
        // UI state is coherent under `cargo test`.
        #[cfg(not(target_arch = "wasm32"))]
        {
            worker_ok.set(false);
            loading.set(false);
        }
    };

    // Debounce: the setTimeout handle plus the single retained callback. Storing
    // the closure (instead of `forget()`-ing a fresh one each keystroke) keeps
    // only the latest alive — the previous is dropped when replaced, after its
    // timeout has been cleared — so N keystrokes no longer leak N closures for
    // the app lifetime.
    let dh = RwSignal::new(0i32);
    #[cfg(target_arch = "wasm32")]
    let debounce_cb: StoredValue<Option<SendWrapper<Closure<dyn FnMut()>>>> =
        StoredValue::new(None);
    let trigger = move || {
        #[cfg(target_arch = "wasm32")]
        {
            if let Some(w) = web_sys::window() {
                let prev = dh.get_untracked();
                if prev != 0 {
                    w.clear_timeout_with_handle(prev);
                }
                let f = Closure::wrap(Box::new(move || do_search()) as Box<dyn FnMut()>);
                let h = w
                    .set_timeout_with_callback_and_timeout_and_arguments_0(
                        f.as_ref().unchecked_ref(),
                        DEBOUNCE_MS,
                    )
                    .unwrap_or(0);
                dh.set(h);
                // Retain only this closure; dropping the previous one (its timeout
                // was cleared above) frees it instead of leaking it.
                debounce_cb.set_value(Some(SendWrapper::new(f)));
            }
        }
        // Native: no event loop / setTimeout — run synchronously.
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = dh;
            do_search();
        }
    };

    // On open: focus the input, seed any `/search <q>` prefill, run once. On
    // close: reset the transient panel state.
    Effect::new(move |_| {
        if is_open.get() {
            let seed = prefill.get_untracked();
            if !seed.is_empty() {
                query.set(seed);
                prefill.set(String::new());
                trigger();
            }
            if let Some(el) = input_ref.get() {
                let _ = el.focus();
            }
        } else {
            query.set(String::new());
            results.set(Vec::new());
            note.set(None);
            sel.set(0);
            loading.set(false);
        }
    });

    let on_input = move |ev: leptos::ev::Event| {
        query.set(event_target_value(&ev));
        trigger();
    };

    let open_hit = move |idx: usize| {
        let rows = results.get_untracked();
        let Some(hit) = rows.get(idx).cloned() else {
            return;
        };
        match hit.kind {
            HitKind::Member => state.go(Screen::Members),
            HitKind::Board | HitKind::Message => {
                let channels = store.channels.get_untracked();
                let cid = match hit.kind {
                    HitKind::Board => Some(hit.target.clone()),
                    _ => hit.channel.clone(),
                }
                .filter(|c| channels.iter().any(|e| &e.id == c));
                match cid {
                    Some(cid) => {
                        let zone_ids: Vec<String> =
                            cfg.with_value(|c| c.zones.iter().map(|z| z.id.clone()).collect());
                        let zsel = channels
                            .iter()
                            .find(|e| e.id == cid)
                            .and_then(|e| relay::channel_zone_index(e, &zone_ids))
                            .unwrap_or(relay::OTHER_ZONE);
                        state.screen.set(Screen::Boards);
                        state.zone.set(Some(zsel));
                        state.board.set(Some(cid.clone()));
                        state.thread.set(hit.thread.clone());
                        state.selection.set(0);
                        state.cmd_open.set(false);
                        relay::subscribe_board(&cid);
                    }
                    // Unresolved board (remote hit, board not loaded) → the Boards
                    // top level, so it is never a dead end.
                    None => state.go(Screen::Boards),
                }
            }
        }
        is_open.set(false);
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
                open_hit(sel.get_untracked());
            }
            _ => {}
        }
    };

    view! {
        <Show when=move || is_open.get() fallback=|| ()>
            <div class="bbs-search-overlay" on:click=move |_| is_open.set(false)>
                <div
                    class="bbs-search-panel"
                    role="search"
                    aria-label="Global search"
                    on:click=|e| e.stop_propagation()
                    on:keydown=on_keydown
                >
                    <div class="bbs-search-head">
                        <span class="bbs-search-glyph accent">"\u{2315}"</span>
                        <input
                            node_ref=input_ref
                            id="bbs-search-input"
                            name="bbs-search"
                            class="bbs-search-input"
                            type="text"
                            autocomplete="off"
                            aria-label="Search query"
                            placeholder="search boards, members, messages\u{2026}"
                            prop:value=move || query.get()
                            on:input=on_input
                        />
                        <span
                            class="bbs-search-esc bbs-link"
                            role="button"
                            tabindex="0"
                            aria-label="Close search"
                            on:click=move |_| is_open.set(false)
                        >
                            "[esc]"
                        </span>
                    </div>

                    <div class="bbs-search-body">
                        {move || {
                            if loading.get() && results.get().is_empty() {
                                view! {
                                    <div class="bbs-search-empty bbs-dim">
                                        "\u{25CC} searching\u{2026}"
                                    </div>
                                }
                                .into_any()
                            } else if results.get().is_empty() {
                                let msg = empty_state_message(&query.get(), worker_ok.get());
                                view! {
                                    <div class="bbs-search-empty bbs-dim">{msg}</div>
                                }
                                .into_any()
                            } else {
                                let rows = results.get();
                                view! {
                                    <div class="bbs-search-list">
                                        {rows
                                            .into_iter()
                                            .enumerate()
                                            .map(|(i, h)| {
                                                let glyph = h.glyph();
                                                let title = h.title.clone();
                                                let subtitle = h.subtitle.clone();
                                                let badge = h.score.map(format_score);
                                                let aria =
                                                    format!("Open {}: {}", subtitle, title);
                                                view! {
                                                    <div
                                                        class="bbs-search-row"
                                                        class:selected=move || sel.get() == i
                                                        role="button"
                                                        tabindex="0"
                                                        aria-label=aria
                                                        on:mouseenter=move |_| sel.set(i)
                                                        on:click=move |_| open_hit(i)
                                                    >
                                                        <span class="accent bbs-chip">{glyph}</span>
                                                        <span class="bbs-search-text">
                                                            <span class="bbs-search-title">
                                                                {badge
                                                                    .map(|b| view! {
                                                                        <span class="bbs-search-score">{b}</span>
                                                                    })}
                                                                {title}
                                                            </span>
                                                            <span class="bbs-dim bbs-search-sub">
                                                                {subtitle}
                                                            </span>
                                                        </span>
                                                    </div>
                                                }
                                            })
                                            .collect_view()}
                                    </div>
                                }
                                .into_any()
                            }
                        }}
                        {move || {
                            note.get().map(|m| view! {
                                <div class="bbs-search-note bbs-dim" role="status">{m}</div>
                            })
                        }}
                    </div>

                    <div class="bbs-search-foot bbs-dim">
                        <span>"\u{2191}\u{2193} move \u{2022} \u{21B5} open \u{2022} esc close"</span>
                    </div>
                </div>
            </div>
        </Show>
    }
}
