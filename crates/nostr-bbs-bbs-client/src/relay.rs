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

/// Insert an event newest-first, de-duplicated by id, capped at `BUCKET_CAP`.
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

/// The 0-based index of the configured zone a channel belongs to — matched by
/// its zone/section tag ([`channel_zone`]) being exactly `zone_ids[i]` or
/// starting with `"{zone_ids[i]}-"` (boards are named e.g. `public-support`
/// under the `public` zone). `None` when it matches no configured zone.
pub fn channel_zone_index(ev: &NostrEvent, zone_ids: &[String]) -> Option<usize> {
    let z = channel_zone(ev)?;
    zone_ids.iter().position(|id| {
        z == *id
            || z.strip_prefix(id.as_str())
                .is_some_and(|r| r.starts_with('-'))
    })
}

/// Channels reordered so they group by configured-zone order (zone 0's boards,
/// then zone 1's, …, then any that match no zone), preserving the incoming order
/// within each group. This is the canonical order the Boards screen renders AND
/// the order the keyboard selection / ENTER indexes into, so the zone grouping
/// stays consistent with arrow-key navigation.
pub fn flat_zone_order(channels: Vec<NostrEvent>, zone_ids: &[String]) -> Vec<NostrEvent> {
    let mut indexed: Vec<(usize, NostrEvent)> = channels
        .into_iter()
        .map(|ev| (channel_zone_index(&ev, zone_ids).unwrap_or(usize::MAX), ev))
        .collect();
    indexed.sort_by_key(|(zi, _)| *zi); // stable sort preserves within-group order
    indexed.into_iter().map(|(_, ev)| ev).collect()
}

/// Build the NIP-28 tags for a kind-42 channel message, matching how the forum
/// client composes board posts and replies:
/// - every message anchors to the channel root: `["e", channel_id, "", "root"]`;
/// - a reply additionally references the parent post and its author:
///   `["e", reply_id, "", "reply"]` and `["p", reply_author]`.
pub fn channel_message_tags(
    channel_id: &str,
    reply_to: Option<(String, String)>,
) -> Vec<Vec<String>> {
    let mut tags = vec![vec![
        "e".to_string(),
        channel_id.to_string(),
        String::new(),
        "root".to_string(),
    ]];
    if let Some((reply_id, reply_author)) = reply_to {
        tags.push(vec![
            "e".to_string(),
            reply_id,
            String::new(),
            "reply".to_string(),
        ]);
        tags.push(vec!["p".to_string(), reply_author]);
    }
    tags
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

/// A NIP-42 AUTH challenge deferred until a signer exists.
///
/// The relay issues its AUTH challenge exactly once, at connect — which is
/// before a user pastes a key in Settings sign-in (`login_with_key`/`generate`
/// → [`set_signer`]). Discarding the challenge would leave the socket
/// unauthenticated for the whole session, so gated-zone reads never load. We
/// stash the unanswered challenge here and consume it when the signer arrives.
///
/// Pure logic (no wasm/WebSocket dependency) so it is unit-testable on native;
/// the wasm client keeps one instance in a `thread_local`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PendingAuth {
    challenge: Option<String>,
}

impl PendingAuth {
    /// Empty — no challenge waiting. `const` so it can init a `thread_local`.
    pub const fn new() -> Self {
        PendingAuth { challenge: None }
    }

    /// Record a challenge that arrived with no signer to answer it. Keeps only
    /// the newest — the relay honours the latest challenge it issued.
    pub fn stash(&mut self, challenge: String) {
        self.challenge = Some(challenge);
    }

    /// Take the stashed challenge, if any, clearing it so it is answered exactly
    /// once. Returns `None` when nothing is pending.
    pub fn take(&mut self) -> Option<String> {
        self.challenge.take()
    }

    /// Whether a challenge is waiting to be answered.
    pub fn is_pending(&self) -> bool {
        self.challenge.is_some()
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

/// Subscribe to a live tail of recent channel messages (kind-42) across all
/// channels — the Chat "lobby" feed and the Code snippet view read from it.
/// Reuses the shared `posts` bucket; idempotent (re-REQs on each screen entry).
pub fn subscribe_chat() {
    #[cfg(target_arch = "wasm32")]
    wasm::subscribe_chat();
}

/// Callback invoked when the relay ACKs a publish with a NIP-01
/// `["OK", id, accepted, message]` frame: `(accepted, message)`.
pub type PublishAck = std::rc::Rc<dyn Fn(bool, String)>;

/// Publish a signed event as a NIP-01 `["EVENT", event]` frame (fire-and-forget).
pub fn publish(event: &NostrEvent) {
    #[cfg(target_arch = "wasm32")]
    wasm::publish(event);
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = event;
    }
}

/// Publish a signed event and invoke `on_ok` when the relay responds with `OK`.
/// If the socket is not open the callback fires immediately with `(false, …)` so
/// the caller never hangs waiting for an ack that cannot arrive.
pub fn publish_with_ack(event: &NostrEvent, on_ok: Option<PublishAck>) {
    #[cfg(target_arch = "wasm32")]
    wasm::publish_with_ack(event, on_ok);
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (event, on_ok);
    }
}

/// Register the signer used to answer NIP-42 AUTH challenges. Called by
/// [`crate::signer::BbsSigner`] whenever the active signer changes. If the relay
/// already issued its one-shot AUTH challenge before this signer existed (the
/// paste-login path), that stashed challenge is answered immediately and the
/// subscriptions are replayed so gated zones re-evaluate authenticated.
pub fn set_signer(signer: std::rc::Rc<dyn nostr_bbs_core::signer::Signer>) {
    #[cfg(target_arch = "wasm32")]
    wasm::set_signer(signer);
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = signer;
    }
}

/// De-register the AUTH signer (called on sign-out).
pub fn clear_signer() {
    #[cfg(target_arch = "wasm32")]
    wasm::clear_signer();
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::{PublishAck, RelayStore};
    use leptos::prelude::*;
    use nostr_bbs_core::signer::Signer;
    use nostr_bbs_core::{NostrEvent, UnsignedEvent};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsCast;

    thread_local! {
        static WS: RefCell<Option<web_sys::WebSocket>> = const { RefCell::new(None) };
        /// Signer used to answer NIP-42 AUTH challenges (from `BbsSigner`).
        static SIGNER: RefCell<Option<Rc<dyn Signer>>> = const { RefCell::new(None) };
        /// The current relay URL, embedded in the kind-22242 AUTH `relay` tag.
        static RELAY_URL: RefCell<String> = const { RefCell::new(String::new()) };
        /// A NIP-42 AUTH challenge received before any signer was registered.
        /// The relay challenges once at connect, so a paste-login after connect
        /// must answer this stashed challenge (see `set_signer`).
        static PENDING_AUTH: RefCell<super::PendingAuth> =
            const { RefCell::new(super::PendingAuth::new()) };
        /// Active REQ frames by sub id, so they can be replayed after AUTH (the
        /// relay re-evaluates gated zones once the socket is authenticated) and
        /// on reconnect.
        static SUBS: RefCell<HashMap<String, serde_json::Value>> = RefCell::new(HashMap::new());
        /// Publish acks awaiting the relay's `OK`, keyed by event id.
        static PENDING: RefCell<HashMap<String, PublishAck>> = RefCell::new(HashMap::new());
    }

    /// Return the socket iff it is OPEN.
    fn ws_open() -> Option<web_sys::WebSocket> {
        WS.with(|c| {
            c.borrow()
                .as_ref()
                .filter(|ws| ws.ready_state() == web_sys::WebSocket::OPEN)
                .cloned()
        })
    }

    /// Send a raw text frame if the socket is open (else drop).
    fn send_str(text: &str) {
        if let Some(ws) = ws_open() {
            let _ = ws.send_with_str(text);
        }
    }

    fn send(frame: &serde_json::Value) {
        send_str(&frame.to_string());
    }

    /// Record a REQ (for replay) and send it.
    fn send_req(sub_id: &str, filter: serde_json::Value) {
        SUBS.with(|m| {
            m.borrow_mut().insert(sub_id.to_string(), filter.clone());
        });
        send(&serde_json::json!(["REQ", sub_id, filter]));
    }

    /// Re-send every tracked REQ (post-AUTH re-evaluation / reconnect).
    fn replay_subs() {
        SUBS.with(|m| {
            for (sub_id, filter) in m.borrow().iter() {
                send(&serde_json::json!(["REQ", sub_id, filter]));
            }
        });
    }

    pub fn set_signer(signer: Rc<dyn Signer>) {
        SIGNER.with(|s| *s.borrow_mut() = Some(signer));
        // Answer a challenge the relay issued before this signer existed (the
        // paste-login / generate path). `handle_auth_challenge` now sees the
        // signer, signs the kind-22242 response, and replays subscriptions so
        // gated zones re-evaluate authenticated.
        if let Some(challenge) = PENDING_AUTH.with(|c| c.borrow_mut().take()) {
            handle_auth_challenge(challenge);
        }
    }

    pub fn clear_signer() {
        SIGNER.with(|s| *s.borrow_mut() = None);
    }

    pub fn publish(event: &NostrEvent) {
        if let Ok(msg) = serde_json::to_string(&serde_json::json!(["EVENT", event])) {
            send_str(&msg);
        }
    }

    pub fn publish_with_ack(event: &NostrEvent, on_ok: Option<PublishAck>) {
        let msg = match serde_json::to_string(&serde_json::json!(["EVENT", event])) {
            Ok(m) => m,
            Err(e) => {
                if let Some(cb) = on_ok {
                    cb(false, format!("serialize error: {e}"));
                }
                return;
            }
        };
        match ws_open() {
            Some(ws) => {
                if let Some(cb) = on_ok {
                    PENDING.with(|m| m.borrow_mut().insert(event.id.clone(), cb));
                }
                let _ = ws.send_with_str(&msg);
            }
            None => {
                if let Some(cb) = on_ok {
                    cb(false, "not connected to relay".to_string());
                }
            }
        }
    }

    /// Answer a NIP-42 AUTH challenge: build + sign a kind-22242 event, send the
    /// `["AUTH", signed]` frame, then replay subscriptions so the relay serves
    /// gated zones. When no signer is registered yet it stashes the challenge in
    /// `PENDING_AUTH` (fail-closed until `set_signer` answers it on sign-in).
    fn handle_auth_challenge(challenge: String) {
        let signer = match SIGNER.with(|s| s.borrow().clone()) {
            Some(s) => s,
            None => {
                // Stash it: the relay challenges once at connect, often before
                // the user pastes a key. `set_signer` answers this on sign-in.
                PENDING_AUTH.with(|c| c.borrow_mut().stash(challenge));
                web_sys::console::warn_1(
                    &"[bbs-relay] AUTH challenge stashed; awaiting sign-in to authenticate".into(),
                );
                return;
            }
        };
        let relay_url = RELAY_URL.with(|u| u.borrow().clone());
        let now = (js_sys::Date::now() / 1000.0) as u64;
        let unsigned = UnsignedEvent {
            pubkey: signer.public_key().to_string(),
            created_at: now,
            kind: 22242,
            tags: vec![
                vec!["relay".to_string(), relay_url],
                vec!["challenge".to_string(), challenge],
            ],
            content: String::new(),
        };
        wasm_bindgen_futures::spawn_local(async move {
            match signer.sign_event(unsigned).await {
                Ok(signed) => {
                    if let Ok(msg) = serde_json::to_string(&serde_json::json!(["AUTH", signed])) {
                        send_str(&msg);
                        web_sys::console::log_1(&"[bbs-relay] NIP-42 AUTH response sent".into());
                    }
                    // Replay subs so the relay re-evaluates them authenticated.
                    replay_subs();
                }
                Err(e) => {
                    web_sys::console::warn_1(
                        &format!("[bbs-relay] AUTH signing failed: {e}").into(),
                    );
                }
            }
        });
    }

    /// Route one relay frame: verified EVENTs into buckets, OK acks to their
    /// pending callback, AUTH challenges to the NIP-42 handler. EOSE / NOTICE
    /// are ignored.
    fn handle_frame(store: RelayStore, txt: &str) {
        let val: serde_json::Value = match serde_json::from_str(txt) {
            Ok(v) => v,
            Err(_) => return,
        };
        let arr = match val.as_array() {
            Some(a) if !a.is_empty() => a,
            _ => return,
        };
        match arr[0].as_str() {
            Some("EVENT") => {
                if arr.len() >= 3 {
                    if let Ok(ev) = serde_json::from_value::<NostrEvent>(arr[2].clone()) {
                        if nostr_bbs_core::verify_event_strict(&ev).is_ok() {
                            store.ingest(ev);
                        }
                    }
                }
            }
            Some("OK") => {
                if arr.len() >= 3 {
                    let id = arr[1].as_str().unwrap_or_default().to_string();
                    let accepted = arr[2].as_bool().unwrap_or(false);
                    let message = arr
                        .get(3)
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let cb = PENDING.with(|m| m.borrow_mut().remove(&id));
                    if let Some(cb) = cb {
                        cb(accepted, message);
                    }
                }
            }
            Some("AUTH") => {
                if let Some(challenge) = arr.get(1).and_then(|v| v.as_str()) {
                    handle_auth_challenge(challenge.to_string());
                }
            }
            _ => {}
        }
    }

    pub fn connect(store: RelayStore, url: &str) {
        if url.is_empty() {
            return;
        }
        RELAY_URL.with(|u| *u.borrow_mut() = url.to_string());
        let ws = match web_sys::WebSocket::new(url) {
            Ok(w) => w,
            Err(_) => return,
        };

        let onopen = Closure::<dyn FnMut()>::new(move || {
            store.connected.set(true);
            // A fresh socket is not yet NIP-42 authenticated; a gated REQ triggers
            // the relay's AUTH challenge, answered in `handle_auth_challenge`,
            // which then replays these subs so gated zones re-evaluate.
            // Register the standing subscriptions (idempotent) then (re)send all
            // tracked subs — including a board sub opened before a reconnect.
            let gov: Vec<u64> = nostr_bbs_core::governance::GOVERNANCE_KIND_RANGE.collect();
            SUBS.with(|m| {
                let mut b = m.borrow_mut();
                b.insert(
                    "bbs-meta".to_string(),
                    serde_json::json!({ "kinds": [0, 40], "limit": 200 }),
                );
                b.insert(
                    "bbs-gov".to_string(),
                    serde_json::json!({ "kinds": gov, "limit": 100 }),
                );
            });
            replay_subs();
        });
        ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
        onopen.forget();

        let onmessage =
            Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
                if let Some(txt) = e.data().as_string() {
                    handle_frame(store, &txt);
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
        SUBS.with(|m| {
            m.borrow_mut().remove("bbs-board");
        });
        send(&serde_json::json!(["CLOSE", "bbs-board"]));
        send_req(
            "bbs-board",
            serde_json::json!({ "kinds": [42], "#e": [channel_id], "limit": 100 }),
        );
    }

    pub fn subscribe_chat() {
        SUBS.with(|m| {
            m.borrow_mut().remove("bbs-chat");
        });
        send(&serde_json::json!(["CLOSE", "bbs-chat"]));
        send_req(
            "bbs-chat",
            serde_json::json!({ "kinds": [42], "limit": 60 }),
        );
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
    fn zone_index_matches_exact_and_prefixed() {
        let ids = vec![
            "public".to_string(),
            "minimoonoir".to_string(),
            "business".to_string(),
        ];
        let z = |zone: &str| ev("c", 40, 1, "{}", vec![vec!["zone", zone]]);
        assert_eq!(channel_zone_index(&z("public"), &ids), Some(0));
        assert_eq!(channel_zone_index(&z("public-support"), &ids), Some(0));
        assert_eq!(channel_zone_index(&z("minimoonoir-photos"), &ids), Some(1));
        assert_eq!(channel_zone_index(&z("business-projects"), &ids), Some(2));
        assert_eq!(channel_zone_index(&z("family-chat"), &ids), None); // not configured
        assert_eq!(channel_zone_index(&z("publicfoo"), &ids), None); // prefix, not "public-"
    }

    #[test]
    fn flat_order_groups_by_zone_preserving_within_group() {
        let ids = vec!["public".to_string(), "business".to_string()];
        let z = |id: &str, zone: &str| ev(id, 40, 1, "{}", vec![vec!["zone", zone]]);
        let chans = vec![
            z("b1", "business-x"),
            z("p1", "public-a"),
            z("x1", "elsewhere"),
            z("p2", "public-b"),
            z("b2", "business-y"),
        ];
        let order: Vec<String> = flat_zone_order(chans, &ids)
            .into_iter()
            .map(|e| e.id)
            .collect();
        // public group (original order p1,p2), then business (b1,b2), then unmatched (x1)
        assert_eq!(order, vec!["p1", "p2", "b1", "b2", "x1"]);
    }

    #[test]
    fn channel_message_tags_top_level_anchors_to_root() {
        let tags = channel_message_tags("chan-id", None);
        assert_eq!(tags, vec![vec!["e", "chan-id", "", "root"]]);
    }

    #[test]
    fn channel_message_tags_reply_adds_parent_and_author() {
        let tags = channel_message_tags(
            "chan-id",
            Some(("parent-id".to_string(), "author-pk".to_string())),
        );
        assert_eq!(
            tags,
            vec![
                vec!["e", "chan-id", "", "root"],
                vec!["e", "parent-id", "", "reply"],
                vec!["p", "author-pk"],
            ]
        );
    }

    #[test]
    fn pending_auth_starts_empty() {
        let p = PendingAuth::new();
        assert!(!p.is_pending());
        assert_eq!(p, PendingAuth::default());
    }

    #[test]
    fn pending_auth_stashes_and_consumes_once() {
        let mut p = PendingAuth::new();
        p.stash("challenge-1".to_string());
        assert!(p.is_pending());
        // set_signer takes it exactly once…
        assert_eq!(p.take(), Some("challenge-1".to_string()));
        // …and a second take (or an early one) yields nothing: no double-AUTH.
        assert!(!p.is_pending());
        assert_eq!(p.take(), None);
    }

    #[test]
    fn pending_auth_keeps_newest_challenge() {
        // If the relay re-challenges before a signer arrives, the latest wins —
        // an older challenge would be rejected as stale.
        let mut p = PendingAuth::new();
        p.stash("old".to_string());
        p.stash("new".to_string());
        assert_eq!(p.take(), Some("new".to_string()));
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
