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

use crate::components::copy_key::KeyGlyph;
use crate::relay::{Filter, RelayConnection};
use gloo::events::EventListener;
use gloo::storage::{LocalStorage, Storage};
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;
use serde::{Deserialize, Serialize};

/// A raw message search hit before relay hydration: `(event_id, score, content, label)`.
/// Bodies are absent until the id→event hydration pass fills them in.
/// Truncate `text` to at most `max_chars` characters, appending an ellipsis
/// when it was shortened.
///
/// Counts and slices by CHARACTER, never by byte. The previous code did
/// `&content[..77]` after checking `content.len() > 80` — `len()` is bytes, so
/// any content whose 77th byte landed mid-codepoint panicked. In Rust a panic
/// in WASM aborts the module: one message containing an emoji or any non-ASCII
/// script at the wrong offset would take down the entire client for everyone
/// who searched and matched it. Both call sites read fully attacker-controlled
/// text (a message body, a channel description), so this was reachable by
/// anyone who can post.
fn ellipsise(text: &str, max_chars: usize) -> String {
    // `chars().count()` is O(n) but these strings are short and the alternative
    // (byte length) is exactly the bug.
    if text.chars().count() > max_chars {
        let keep = max_chars.saturating_sub(3);
        format!("{}...", text.chars().take(keep).collect::<String>())
    } else {
        text.to_string()
    }
}

/// Shared open-state for the global search overlay. The app shell provides this
/// via context so a visible nav button can open the very same panel that the
/// Cmd/Ctrl+K shortcut toggles.
#[derive(Clone, Copy)]
pub struct SearchOpen(pub RwSignal<bool>);
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

/// How many semantic hits to ask the worker for.
///
/// Sent as `k` — the ONLY field the worker's `SearchRequest` understands. This
/// used to be sent as `"limit"`, which serde silently discarded, leaving the
/// worker's `default_k()` in charge. That happened to also be 10, so the bug was
/// invisible until someone changed this number and nothing moved.
const SEMANTIC_K: u32 = 10;
const RECENT_KEY: &str = "nostrbbs_recent_searches";
const MAX_RECENT: usize = 5;

/// Storage slot for the pending debounce `setTimeout` `Closure`, wrapped in
/// `SendWrapper` to satisfy `on_cleanup`'s `Send + Sync` bound on this
/// otherwise-`!Send` wasm-bindgen type. Re-assigning `Some(..)` drops
/// whatever closure was previously stored, so it never leaks via `.forget()`.
type PendingDebounceClosure = StoredValue<Option<send_wrapper::SendWrapper<Closure<dyn FnMut()>>>>;
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
            Self::Channels => "Sections",
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
        /// The matching event itself — the link target.
        event_id: String,
        content: String,
        author: String,
        channel_id: String,
    },
    /// Semantic search result with similarity score.
    SemanticMessage {
        /// The matching event itself — the link target.
        event_id: String,
        /// Containing channel (fallback link when the event id is unknown).
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
    /// The member whose name this hit shows (title or "by …" subtitle). While
    /// that name is still the abridged key the row gets a copy glyph beside it.
    fn person(&self) -> Option<&str> {
        match self {
            Self::Message { author, .. } => Some(author),
            Self::SemanticMessage { label, .. } if crate::utils::is_hex_pubkey(label) => {
                Some(label)
            }
            Self::User { pubkey, .. } => Some(pubkey),
            _ => None,
        }
    }
    fn title(&self) -> String {
        match self {
            Self::Channel { name, .. } => name.clone(),
            Self::Message { content, .. } | Self::SemanticMessage { content, .. } => {
                ellipsise(content, 80)
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
    /// Router path of the hit, relative to the router base (`FORUM_BASE`),
    /// for `use_navigate`: a result opens in the app, not by a document load.
    fn path(&self) -> String {
        match self {
            Self::Channel { id, .. } => format!("/chat/{id}"),
            // Messages open AT the message: `/go/:id` resolves the topic it
            // lives in and lands on it (pages/message_jump.rs), rather than
            // dropping the reader one level up in the channel. The channel
            // rides along as a hint, as in notifications: in an encrypted
            // zone the post is found in its channel, not on the relay by id.
            Self::Message {
                event_id,
                channel_id,
                ..
            } => crate::pages::jump_link(event_id, Some(channel_id)),
            Self::SemanticMessage { event_id, id, .. } => {
                crate::pages::jump_link(event_id, Some(id))
            }
            Self::User { pubkey, .. } => format!("/profile/{pubkey}"),
        }
    }
    fn score(&self) -> Option<f64> {
        match self {
            Self::SemanticMessage { score, .. } => Some(*score),
            _ => None,
        }
    }
}

/// Where the on-device index for encrypted zones stands, as the panel sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SealedIndex {
    /// Nothing to wait for: no encrypted zone this member can search, or its
    /// load finished without anything to search.
    Idle,
    /// The member's zone keys or the index are still on their way.
    Loading,
    /// At least one encrypted zone is searchable in the worker.
    Ready,
}

/// The index state when the panel opens. `searchable` is "an encrypted zone
/// and an index publisher are configured"; `keys_ready` is "this member's
/// stored zone keys are read"; `holds_key` is "a key for one of those zones is
/// held"; `ready_now` is [`sealed_search::ready`](crate::utils::sealed_search::ready).
fn sealed_state_on_open(
    searchable: bool,
    keys_ready: bool,
    holds_key: bool,
    ready_now: bool,
) -> SealedIndex {
    if ready_now {
        SealedIndex::Ready
    } else if !searchable || (keys_ready && !holds_key) {
        SealedIndex::Idle
    } else {
        SealedIndex::Loading
    }
}

/// Whether `tab` searches message bodies (and so encrypted zones).
fn searches_messages(tab: &Tab) -> bool {
    matches!(tab, Tab::All | Tab::Messages)
}

/// Whether to tell the member that encrypted zones were not searched yet.
fn sealed_notice(state: SealedIndex, tab: &Tab, query: &str) -> bool {
    state == SealedIndex::Loading && searches_messages(tab) && !query.trim().is_empty()
}

/// Whether the index load that moved `prev` to `next` should re-run the
/// query in the open panel, so results appear without retyping.
fn rerun_on_ready(
    prev: SealedIndex,
    next: SealedIndex,
    open: bool,
    query: &str,
    tab: &Tab,
) -> bool {
    prev == SealedIndex::Loading
        && next == SealedIndex::Ready
        && open
        && searches_messages(tab)
        && !query.trim().is_empty()
}

/// Whether to say "No results found": not while searching, and not while
/// encrypted zones are still to come (the notice says so instead).
fn shows_no_results(loading: bool, empty: bool, query: &str, sealed_pending: bool) -> bool {
    !loading && empty && !query.trim().is_empty() && !sealed_pending
}

#[derive(Clone, Serialize, Deserialize)]
struct Recent {
    query: String,
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
    let search_gen = StoredValue::new(0u64);
    let input_ref = NodeRef::<leptos::html::Input>::new();
    let recents = RwSignal::new(load_recents());

    // Semantic search toggle
    let semantic_mode = RwSignal::new(false);
    let api_online = RwSignal::new(false);

    // Capture the relay handle at setup time — `do_search` runs from a
    // debounce setTimeout callback where the reactive owner (and therefore
    // context lookup) is not guaranteed.
    let relay_handle = StoredValue::new(expect_context::<RelayConnection>());

    // Sealed per-zone search (encrypted zones): on open, load each sealed
    // zone's verified index into the search worker. Nothing is sent to a
    // search server; the query is embedded in the worker, on this device.
    // The load runs once at a time; the panel shows its progress (`sealed`)
    // and re-runs the query when it completes (effect below `do_search`).
    let zone_store = crate::zone_crypto::store::try_use_zone_key_store();
    let auth = crate::auth::use_auth();
    let sealed = RwSignal::new(SealedIndex::Idle);
    let sealed_in_flight = StoredValue::new(false);
    let navigate = StoredValue::new(use_navigate());

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
            search_gen.update_value(|g| *g += 1);
            query.set(String::new());
            results.set(Vec::new());
            sel.set(0);
            search_error.set(None);
        }
    });

    // Debounced search. `dh` holds the pending `setTimeout` handle (0 = none)
    // so a new keystroke can cancel the previous debounce timer; without the
    // `on_cleanup` below (added alongside removing the `.forget()` on the
    // debounce closure), closing/unmounting the search overlay mid-debounce
    // left the timer running and its closure leaked, firing `do_search`
    // (and the `results`/`loading`/`search_error` signal writes inside it)
    // against a disposed component scope.
    let dh = RwSignal::new(0i32);
    let do_search = move || {
        let q = query.get_untracked();
        let t = tab.get_untracked();
        // Only the newest search writes the panel: a slower earlier one (say,
        // from before the encrypted index was ready) must not overwrite it.
        search_gen.update_value(|g| *g += 1);
        let generation = search_gen.get_value();
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

                // Text search goes to the RELAY (NIP-50 `search` on kind-42),
                // not to the vector worker. The worker's index is fed only by
                // the posting client's `/ingest` call, which is admin-gated —
                // so for every non-admin member their own posts were never
                // indexed and "search" could not find them ("I did a post
                // called Glastonbury. Searched for it and couldn't find it").
                // The relay already holds every post and matches `content`
                // as a case-insensitive substring, for members and admins
                // alike, so it is the authoritative text path. The vector
                // worker stays as the *semantic* layer on top.
                let relay_hits = relay_text_search(&relay, &q).await;
                let mut seen: std::collections::HashSet<String> =
                    relay_hits.iter().map(|ev| ev.id.clone()).collect();
                for ev in &relay_hits {
                    out.push(Hit::Message {
                        event_id: ev.id.clone(),
                        content: ev.content.clone(),
                        author: ev.pubkey.clone(),
                        channel_id: channel_id_of(ev).unwrap_or_else(|| ev.id.clone()),
                    });
                }

                // Sealed per-zone search over the encrypted zones this member
                // holds keys for: verified, decrypted events only.
                if let Some(store) = zone_store.filter(|_| crate::utils::sealed_search::ready()) {
                    match crate::utils::sealed_search::search(&relay, &store, &q, SEMANTIC_K).await
                    {
                        Ok(hits) => {
                            for h in hits {
                                if !seen.insert(h.event.id.clone()) {
                                    continue;
                                }
                                out.push(Hit::SemanticMessage {
                                    event_id: h.event.id.clone(),
                                    id: channel_id_of(&h.event)
                                        .unwrap_or_else(|| h.event.id.clone()),
                                    content: h.event.content.clone(),
                                    label: h.event.pubkey.clone(),
                                    score: h.score,
                                });
                            }
                        }
                        Err(e) => errors.push(format!("Encrypted-zone search failed: {e}")),
                    }
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
                        let d = ellipsise(&ev.content, 100);
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
            if search_gen.try_get_value() != Some(generation) {
                return;
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
    // Holds the pending debounce `Closure` so re-triggering (every keystroke)
    // or unmounting drops the previous one instead of leaking it via
    // `.forget()` — a fast typist cancelling-and-rescheduling on every
    // keystroke would otherwise accumulate one leaked closure per keystroke.
    let debounce_closure: PendingDebounceClosure = StoredValue::new(None);
    on_cleanup(move || {
        if let Some(w) = web_sys::window() {
            let h = dh.get_untracked();
            if h != 0 {
                w.clear_timeout_with_handle(h);
            }
        }
        debounce_closure.set_value(None);
    });
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
            debounce_closure.set_value(Some(send_wrapper::SendWrapper::new(f)));
        }
    };
    let on_input = move |ev: leptos::ev::Event| {
        let t = ev.target().unwrap();
        let i: web_sys::HtmlInputElement = t.unchecked_into();
        query.set(i.value());
        trigger();
    };

    // Sealed per-zone search (encrypted zones): on open, load each sealed
    // zone's verified index into the search worker. Nothing is sent to a
    // search server; the query is embedded in the worker, on this device.
    // Tracks the key store's readiness too, so a panel opened before the
    // member's keys are read starts the load once they are.
    Effect::new(move |_| {
        if !is_open.get() {
            return;
        }
        let (Some(store), Some(signer)) = (zone_store, auth.get_signer()) else {
            sealed.set(SealedIndex::Idle);
            return;
        };
        let zones = crate::utils::sealed_search::sealed_zones();
        let searchable = !zones.is_empty() && !crate::utils::sealed_search::publishers().is_empty();
        let keys_ready = store.ready_for(auth.pubkey().get().as_deref());
        let holds_key = keys_ready && zones.iter().any(|z| !store.all_for_zone(z).is_empty());
        let ready_now = crate::utils::sealed_search::ready();
        sealed.set(sealed_state_on_open(
            searchable, keys_ready, holds_key, ready_now,
        ));
        if !searchable || !holds_key || sealed_in_flight.get_value() {
            return;
        }
        sealed_in_flight.set_value(true);
        wasm_bindgen_futures::spawn_local(async move {
            for zone in zones {
                if let Err(e) =
                    crate::utils::sealed_search::ensure_zone(&zone, &store, &*signer).await
                {
                    web_sys::console::warn_1(&format!("[sealed-search] {zone}: {e}").into());
                }
            }
            let _ = sealed_in_flight.try_set_value(false);
            let next = if crate::utils::sealed_search::ready() {
                SealedIndex::Ready
            } else {
                SealedIndex::Idle
            };
            let Some(prev) = sealed.try_get_untracked() else {
                return;
            };
            sealed.set(next);
            api_online.set(next == SealedIndex::Ready);
            if rerun_on_ready(
                prev,
                next,
                is_open.get_untracked(),
                &query.get_untracked(),
                &tab.get_untracked(),
            ) {
                do_search();
            }
        });
    });

    // Results open in the app (router), as notification rows do, never by a
    // full document load; Enter takes the same path as a click.
    let nav_result = move |idx: usize| {
        let r = results.get_untracked();
        if let Some(hit) = r.get(idx) {
            save_recent(&query.get_untracked());
            recents.set(load_recents());
            let path = hit.path();
            is_open.set(false);
            navigate.with_value(|nav| nav(&path, NavigateOptions::default()));
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
                        <input node_ref=input_ref type="text" class="flex-1 bg-transparent text-white placeholder-gray-500 focus:outline-none text-sm" placeholder="Search sections, messages, users..." prop:value=move || query.get() on:input=on_input aria-label="Search query" autocomplete="off" />
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
                        <Show when=move || sealed_notice(sealed.get(), &tab.get(), &query.get())>
                            <div class="mx-1 mt-2 flex items-center gap-2 bg-amber-500/10 border border-amber-500/30 rounded-lg px-3 py-2 text-xs text-amber-300" role="status" aria-live="polite">
                                <span class="animate-pulse w-1.5 h-1.5 rounded-full bg-amber-400 flex-shrink-0"></span>
                                "Encrypted zones are still loading; results will appear here"
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
                                let person = h.person().map(str::to_string);
                                view! { <div class="flex items-center gap-1"><button class=move || if sel.get() == i { "flex-1 min-w-0 flex items-center gap-3 px-3 py-2.5 rounded-lg bg-gray-800 text-left" } else { "flex-1 min-w-0 flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-gray-800/50 text-left transition-colors" } on:click=move |_| nav_result(i) on:mouseenter=move |_| sel.set(i)>
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
                                </button>
                                {person.map(|pk| view! { <KeyGlyph pubkey=pk class="px-1" /> })}
                                </div> }
                            }).collect_view() }}</div>
                        </Show>
                        <Show when=move || shows_no_results(loading.get(), results.get().is_empty(), &query.get(), sealed_notice(sealed.get(), &tab.get(), &query.get()))>
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
                                    view! { <span class="flex items-center gap-1 text-green-600"><span class="w-1.5 h-1.5 rounded-full bg-green-500"></span>"encrypted zones (on device)"</span> }.into_any()
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

/// How many kind-42 events one NIP-50 text query asks the relay for.
const RELAY_TEXT_LIMIT: u64 = 50;

/// NIP-50 text search over kind-42 messages on the relay.
///
/// Waits up to 1.2s for the relay to answer, then unsubscribes. Newest first.
/// An empty result is indistinguishable from "relay has no NIP-50" — callers
/// treat it as a reason to consult the vector worker, never as an error.
async fn relay_text_search(
    relay: &RelayConnection,
    query: &str,
) -> Vec<nostr_bbs_core::NostrEvent> {
    let q = query.trim();
    if q.is_empty() {
        return Vec::new();
    }
    let found: RwSignal<Vec<nostr_bbs_core::NostrEvent>> = RwSignal::new(Vec::new());
    let cb = Rc::new(move |ev: nostr_bbs_core::NostrEvent| {
        // Zone-encrypted posts (ADR-2016) are never search results: the relay
        // matched their ciphertext, which is meaningless to the reader.
        if ev.kind == 42
            && !ev.content.trim().is_empty()
            && !crate::zone_crypto::has_zk_tag(&ev.tags)
        {
            found.update(|v| v.push(ev));
        }
    });
    let sid = relay.subscribe(
        vec![Filter {
            kinds: Some(vec![42]),
            search: Some(q.to_string()),
            limit: Some(RELAY_TEXT_LIMIT),
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
    let mut events = found.get_untracked();
    events.sort_by_key(|ev| std::cmp::Reverse(ev.created_at));
    events
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

#[cfg(test)]
mod tests {

    // ── UTF-8 truncation (WASM-abort regression) ────────────────────────────

    #[test]
    fn ellipsise_does_not_panic_on_a_multibyte_boundary() {
        // The regression: `&content[..77]` after `content.len() > 80`. `len()`
        // is bytes, so a codepoint straddling byte 77 panicked — and a panic in
        // WASM aborts the whole module. Every one of these strings puts a
        // multi-byte character at or across the old cut point.
        for s in [
            "a".repeat(76) + "\u{1F600}\u{1F600}\u{1F600}",
            "\u{1F600}".repeat(40),
            "e\u{0301}".repeat(60),
            "\u{4F60}\u{597D}".repeat(50),
            "\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}".repeat(10),
        ] {
            let out = ellipsise(&s, 80);
            assert!(out.chars().count() <= 80);
        }
    }

    #[test]
    fn ellipsise_leaves_short_text_alone() {
        assert_eq!(ellipsise("hello", 80), "hello");
        // Counted in CHARS: 40 emoji are 160 bytes but only 40 characters, so
        // this must NOT be truncated at a byte-based threshold of 80.
        let forty = "\u{1F600}".repeat(40);
        assert_eq!(ellipsise(&forty, 80), forty);
    }

    #[test]
    fn ellipsise_marks_truncation_and_respects_the_budget() {
        let long = "a".repeat(200);
        let out = ellipsise(&long, 80);
        assert!(out.ends_with("..."));
        assert_eq!(out.chars().count(), 80);
    }
    use super::*;

    #[test]
    fn message_hits_link_with_their_channel_hint() {
        // As notifications do: in an encrypted zone the jump page resolves
        // the post from its channel, not from the relay by id.
        let m = Hit::Message {
            event_id: "e1".into(),
            content: String::new(),
            author: String::new(),
            channel_id: "chan".into(),
        };
        assert_eq!(m.path(), "/go/e1?c=chan");
        let sm = Hit::SemanticMessage {
            event_id: "e2".into(),
            id: "chan".into(),
            content: String::new(),
            label: String::new(),
            score: 0.5,
        };
        assert_eq!(sm.path(), "/go/e2?c=chan");
        let unknown = Hit::Message {
            event_id: "e3".into(),
            content: String::new(),
            author: String::new(),
            channel_id: String::new(),
        };
        assert_eq!(unknown.path(), "/go/e3");
    }

    #[test]
    fn every_hit_path_is_app_relative_for_the_router() {
        // The router is mounted at `FORUM_BASE`, so a path handed to
        // `use_navigate` must not carry the base itself (or it doubles up).
        let hits = [
            Hit::Channel {
                id: "chan".into(),
                name: String::new(),
                desc: String::new(),
            },
            Hit::User {
                pubkey: "ab".into(),
                nickname: None,
            },
        ];
        assert_eq!(hits[0].path(), "/chat/chan");
        assert_eq!(hits[1].path(), "/profile/ab");
        for h in &hits {
            assert!(h.path().starts_with('/'), "{}", h.path());
            assert!(!h.path().starts_with("/community/"), "{}", h.path());
        }
    }

    // ── Encrypted-zone index readiness ──────────────────────────────────────

    #[test]
    fn nothing_to_load_means_no_loading_state() {
        // No sealed zone or no publisher: there is nothing to wait for.
        assert_eq!(
            sealed_state_on_open(false, true, true, false),
            SealedIndex::Idle
        );
        // Keys loaded, none held for a sealed zone: never "still loading".
        assert_eq!(
            sealed_state_on_open(true, true, false, false),
            SealedIndex::Idle
        );
    }

    #[test]
    fn loading_while_keys_or_index_are_on_their_way() {
        // Stored keys not yet read: the zones cannot be searched yet.
        assert_eq!(
            sealed_state_on_open(true, false, false, false),
            SealedIndex::Loading
        );
        assert_eq!(
            sealed_state_on_open(true, true, true, false),
            SealedIndex::Loading
        );
    }

    #[test]
    fn an_index_already_in_the_worker_is_ready() {
        assert_eq!(
            sealed_state_on_open(true, true, true, true),
            SealedIndex::Ready
        );
        assert_eq!(
            sealed_state_on_open(false, false, false, true),
            SealedIndex::Ready
        );
    }

    #[test]
    fn the_notice_shows_only_for_a_pending_message_search() {
        let l = SealedIndex::Loading;
        assert!(sealed_notice(l, &Tab::All, "Glastonbury"));
        assert!(sealed_notice(l, &Tab::Messages, "Glastonbury"));
        assert!(
            !sealed_notice(l, &Tab::Channels, "Glastonbury"),
            "no messages searched"
        );
        assert!(!sealed_notice(l, &Tab::Users, "Glastonbury"));
        assert!(!sealed_notice(l, &Tab::All, "  "), "no query yet");
        assert!(!sealed_notice(SealedIndex::Idle, &Tab::All, "Glastonbury"));
        assert!(!sealed_notice(SealedIndex::Ready, &Tab::All, "Glastonbury"));
    }

    #[test]
    fn the_query_reruns_once_the_index_becomes_ready() {
        let (l, r, i) = (SealedIndex::Loading, SealedIndex::Ready, SealedIndex::Idle);
        assert!(rerun_on_ready(l, r, true, "Glastonbury", &Tab::All));
        assert!(rerun_on_ready(l, r, true, "Glastonbury", &Tab::Messages));
        assert!(
            !rerun_on_ready(l, i, true, "Glastonbury", &Tab::All),
            "nothing loaded"
        );
        assert!(
            !rerun_on_ready(r, r, true, "Glastonbury", &Tab::All),
            "a refresh, not a load"
        );
        assert!(
            !rerun_on_ready(l, r, false, "Glastonbury", &Tab::All),
            "panel closed"
        );
        assert!(!rerun_on_ready(l, r, true, "", &Tab::All), "no query");
        assert!(!rerun_on_ready(l, r, true, "Glastonbury", &Tab::Users));
    }

    #[test]
    fn no_results_waits_for_encrypted_zones() {
        assert!(shows_no_results(false, true, "x", false));
        assert!(
            !shows_no_results(false, true, "x", true),
            "notice says more"
        );
        assert!(!shows_no_results(true, true, "x", false), "still searching");
        assert!(!shows_no_results(false, false, "x", false));
        assert!(!shows_no_results(false, true, " ", false));
    }

    // Pure tests only: the overlay itself is Leptos/wasm, but the wire contract
    // it depends on is pure, so it is pinned here on the host target.

    #[test]
    fn relay_text_filter_serialises_the_nip50_search_key() {
        // The relay-worker reads `search` (relay_do/filter.rs); a differently
        // spelled key would be silently ignored and the REQ would return the
        // newest 50 kind-42 events regardless of the query.
        let f = Filter {
            kinds: Some(vec![42]),
            search: Some("Glastonbury".to_string()),
            limit: Some(RELAY_TEXT_LIMIT),
            ..Default::default()
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains(r#""search":"Glastonbury""#), "was {json}");
        assert!(json.contains(r#""kinds":[42]"#), "was {json}");
        assert!(json.contains(r#""limit":50"#), "was {json}");
        // Absent by default, so existing filters are byte-identical.
        let plain = serde_json::to_string(&Filter::default()).unwrap();
        assert!(!plain.contains("search"), "was {plain}");
    }
}
