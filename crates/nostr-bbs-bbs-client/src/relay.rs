//! Minimal Nostr relay WebSocket client for the BBS.
//!
//! Reuses `nostr-bbs-core` for event types and `verify_event_strict`. A single
//! `onmessage` handler routes verified events into per-kind signals; screens
//! derive their data reactively. The WebSocket lives in a `thread_local`
//! (wasm is single-threaded) so the `Copy` [`RelayStore`] holds only Send+Sync
//! signals. The parsing/projection helpers are pure and unit-tested on native.

use leptos::prelude::*;
use nostr_bbs_core::event::NostrEvent;

/// Max events retained per bucket (newest-first).
const BUCKET_CAP: usize = 200;

/// Per-kind event buckets + connection state. `Copy` — all fields are signals.
#[derive(Clone, Copy)]
pub struct RelayStore {
    /// Whether the relay socket is currently open.
    pub connected: RwSignal<bool>,
    /// kind-0 profile metadata.
    pub profiles: RwSignal<Vec<NostrEvent>>,
    /// kind-40 channel definitions (boards).
    pub channels: RwSignal<Vec<NostrEvent>>,
    /// kind-42 channel messages for the currently-open board.
    pub posts: RwSignal<Vec<NostrEvent>>,
    /// Governance events (agent control panels), kinds 31400–31405.
    pub governance: RwSignal<Vec<NostrEvent>>,
}

impl RelayStore {
    /// Create empty buckets (requires a reactive owner — call inside a component).
    pub fn new() -> Self {
        RelayStore {
            connected: RwSignal::new(false),
            profiles: RwSignal::new(Vec::new()),
            channels: RwSignal::new(Vec::new()),
            posts: RwSignal::new(Vec::new()),
            governance: RwSignal::new(Vec::new()),
        }
    }

    /// Route a verified event into the matching bucket.
    pub fn ingest(&self, ev: NostrEvent) {
        let bucket = match ev.kind {
            0 => self.profiles,
            40 => self.channels,
            42 => self.posts,
            k if nostr_bbs_core::governance::is_governance_kind(k) => self.governance,
            _ => return,
        };
        bucket.update(|v| insert_event(v, ev));
    }
}

impl Default for RelayStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Insert an event newest-first, de-duplicated by id, capped at [`BUCKET_CAP`].
pub fn insert_event(v: &mut Vec<NostrEvent>, ev: NostrEvent) {
    if v.iter().any(|e| e.id == ev.id) {
        return;
    }
    v.push(ev);
    v.sort_by_key(|e| std::cmp::Reverse(e.created_at));
    v.truncate(BUCKET_CAP);
}

/// Extract the [`NostrEvent`] from a relay `["EVENT", sub, {…}]` frame.
/// Returns `None` for any other frame (EOSE / NOTICE / OK / malformed).
pub fn parse_event_frame(text: &str) -> Option<NostrEvent> {
    let val: serde_json::Value = serde_json::from_str(text).ok()?;
    let arr = val.as_array()?;
    if arr.first()?.as_str()? != "EVENT" || arr.len() < 3 {
        return None;
    }
    serde_json::from_value(arr[2].clone()).ok()
}

/// A kind-40 channel's display name (from its JSON content), else a short id.
pub fn channel_name(ev: &NostrEvent) -> String {
    serde_json::from_str::<serde_json::Value>(&ev.content)
        .ok()
        .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(str::to_string))
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("channel-{}", short_id(&ev.id)))
}

/// A channel's zone slug, from a `["zone", …]` or `["section", …]` tag.
pub fn channel_zone(ev: &NostrEvent) -> Option<String> {
    ev.tags
        .iter()
        .find(|t| {
            matches!(
                t.first().map(String::as_str),
                Some("zone") | Some("section")
            )
        })
        .and_then(|t| t.get(1))
        .cloned()
}

/// The root channel id a kind-42 post belongs to (first `e` tag, NIP-28).
pub fn post_root_channel(ev: &NostrEvent) -> Option<String> {
    ev.tags
        .iter()
        .find(|t| t.first().map(String::as_str) == Some("e"))
        .and_then(|t| t.get(1))
        .cloned()
}

/// Parse a governance event's content into a control-panel definition.
pub fn parse_panel(ev: &NostrEvent) -> Option<nostr_bbs_core::governance::PanelDefinition> {
    serde_json::from_str(&ev.content).ok()
}

/// Short, BBS-friendly id (`abcd…wxyz`).
pub fn short_id(id: &str) -> String {
    if id.len() >= 12 {
        format!("{}…{}", &id[..4], &id[id.len() - 4..])
    } else {
        id.to_string()
    }
}

/// Connect to the relay and start the standing subscriptions. No-op on native /
/// when the URL is empty.
pub fn connect(store: RelayStore, url: &str) {
    #[cfg(target_arch = "wasm32")]
    wasm::connect(store, url);
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (store, url);
    }
}

/// (Re)subscribe to a board's messages (kind-42, `#e` = channel id).
pub fn subscribe_board(channel_id: &str) {
    #[cfg(target_arch = "wasm32")]
    wasm::subscribe_board(channel_id);
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = channel_id;
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::RelayStore;
    use leptos::prelude::*;
    use std::cell::RefCell;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsCast;

    thread_local! {
        static WS: RefCell<Option<web_sys::WebSocket>> = const { RefCell::new(None) };
    }

    fn send(frame: &serde_json::Value) {
        let text = frame.to_string();
        WS.with(|c| {
            if let Some(ws) = c.borrow().as_ref() {
                if ws.ready_state() == web_sys::WebSocket::OPEN {
                    let _ = ws.send_with_str(&text);
                }
            }
        });
    }

    pub fn connect(store: RelayStore, url: &str) {
        if url.is_empty() {
            return;
        }
        let ws = match web_sys::WebSocket::new(url) {
            Ok(w) => w,
            Err(_) => return,
        };

        let onopen = Closure::<dyn FnMut()>::new(move || {
            store.connected.set(true);
            // Standing subscriptions: profiles + channels, and agent panels.
            let gov: Vec<u64> = nostr_bbs_core::governance::GOVERNANCE_KIND_RANGE.collect();
            send(&serde_json::json!(["REQ", "bbs-meta", { "kinds": [0, 40], "limit": 200 }]));
            send(&serde_json::json!(["REQ", "bbs-gov", { "kinds": gov, "limit": 100 }]));
        });
        ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
        onopen.forget();

        let onmessage =
            Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
                if let Some(txt) = e.data().as_string() {
                    if let Some(ev) = super::parse_event_frame(&txt) {
                        if nostr_bbs_core::verify_event_strict(&ev).is_ok() {
                            store.ingest(ev);
                        }
                    }
                }
            });
        ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        onmessage.forget();

        let onclose = Closure::<dyn FnMut(web_sys::CloseEvent)>::new(move |_| {
            store.connected.set(false);
        });
        ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));
        onclose.forget();

        WS.with(|c| *c.borrow_mut() = Some(ws));
    }

    pub fn subscribe_board(channel_id: &str) {
        send(&serde_json::json!(["CLOSE", "bbs-board"]));
        send(&serde_json::json!([
            "REQ",
            "bbs-board",
            { "kinds": [42], "#e": [channel_id], "limit": 100 }
        ]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_bbs_core::event::NostrEvent;

    fn ev(id: &str, kind: u64, created_at: u64, content: &str, tags: Vec<Vec<&str>>) -> NostrEvent {
        NostrEvent {
            id: id.to_string(),
            pubkey: "00".repeat(32),
            created_at,
            kind,
            tags: tags
                .into_iter()
                .map(|t| t.into_iter().map(str::to_string).collect())
                .collect(),
            content: content.to_string(),
            sig: String::new(),
        }
    }

    #[test]
    fn insert_dedups_and_sorts_newest_first() {
        let mut v = Vec::new();
        insert_event(&mut v, ev("a", 42, 100, "", vec![]));
        insert_event(&mut v, ev("b", 42, 200, "", vec![]));
        insert_event(&mut v, ev("a", 42, 100, "", vec![])); // dup id
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].id, "b"); // newest first
        assert_eq!(v[1].id, "a");
    }

    #[test]
    fn parse_event_frame_extracts_event() {
        let frame = r#"["EVENT","s",{"id":"x","pubkey":"p","created_at":1,"kind":1,"tags":[],"content":"hi","sig":"s"}]"#;
        let got = parse_event_frame(frame).expect("event");
        assert_eq!(got.id, "x");
        assert_eq!(got.content, "hi");
    }

    #[test]
    fn parse_event_frame_ignores_eose_and_garbage() {
        assert!(parse_event_frame(r#"["EOSE","s"]"#).is_none());
        assert!(parse_event_frame("not json").is_none());
        assert!(parse_event_frame(r#"["NOTICE","hi"]"#).is_none());
    }

    #[test]
    fn channel_name_from_json_else_short_id() {
        let named = ev("0123456789abcdef", 40, 1, r#"{"name":"General"}"#, vec![]);
        assert_eq!(channel_name(&named), "General");
        let unnamed = ev("0123456789abcdef", 40, 1, "", vec![]);
        assert_eq!(channel_name(&unnamed), "channel-0123…cdef");
    }

    #[test]
    fn channel_zone_and_post_root() {
        let chan = ev("c", 40, 1, "{}", vec![vec!["zone", "friends"]]);
        assert_eq!(channel_zone(&chan).as_deref(), Some("friends"));
        let post = ev("p", 42, 1, "hi", vec![vec!["e", "c"]]);
        assert_eq!(post_root_channel(&post).as_deref(), Some("c"));
    }

    #[test]
    fn parse_panel_round_trips_governance_content() {
        let panel = crate::agent::sample_panels().remove(0).panel;
        let content = serde_json::to_string(&panel).unwrap();
        let gov = ev("g", 31401, 1, &content, vec![]);
        let parsed = parse_panel(&gov).expect("panel");
        assert_eq!(parsed.title, panel.title);
    }
}
