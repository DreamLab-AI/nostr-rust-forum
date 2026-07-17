//! Encrypted direct messages (NIP-44 / NIP-59 gift-wrap) for the BBS — F8.
//!
//! ORIGIN: the conversation model, gift-wrap send/receive pipeline, and the
//! kind-1059 AUTH-race handling are ported from the forum client
//! (`crates/nostr-bbs-forum-client/src/dm/mod.rs` + `pages/dm_chat.rs`). Both
//! clients take the shared `nostr_bbs_core::signer::Signer` trait, so the exact
//! same crypto is reused here without any auth rewrite: `BbsSigner::get_signer()`
//! hands us the `Rc<dyn Signer>` and `gift_wrap_with_signer` /
//! `unwrap_gift_with_signer` do the NIP-44/59 work.
//!
//! The BBS relay module (`src/relay.rs`) is a single global socket that only
//! buckets public kinds (0/40/42/governance) and drops kind-1059, and it is
//! frozen (spec §5.3). So this module owns a **dedicated DM WebSocket** that
//! NIP-42-authenticates as the viewer, subscribes to kind-1059/#p (+ legacy
//! kind-4), and publishes gift-wraps — mirroring the relay module's own
//! connect/AUTH/replay idioms. Everything network-facing is `#[cfg(wasm32)]`;
//! the pure logic (peer extraction, conversation grouping, filter/auth building,
//! peer-input parsing, message formatting) is `#[cfg(test)]`-covered on native.
//!
//! A 1:1 with the Jarvis agent is just a DM to `JARVIS_PUBKEY` (projected from
//! the operator's `VITE_JARVIS_PUBKEY` into `window.__ENV__`).

use std::rc::Rc;

use leptos::prelude::*;
use serde_json::Value;

use nostr_bbs_core::gift_wrap::{KIND_ENCRYPTED_DM, KIND_GIFT_WRAP};
use nostr_bbs_core::signer::Signer;

use crate::chrome::BbsState;
use crate::config::BbsConfig;
use crate::signer::BbsSigner;

/// NIP-59 gift-wraps randomise their outer `created_at` up to ~2 days into the
/// PAST to obscure timing metadata, so a realtime subscription anchored at `now`
/// silently drops freshly-sent DMs. Widen the `since` window to cover that
/// randomisation (2 days + margin); the id-dedup keeps re-streamed history from
/// duplicating. (Ported rationale from the forum DM store.)
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
const GIFT_WRAP_LOOKBACK_SECS: u64 = 2 * 24 * 60 * 60 + 3600;

// ── Data model ────────────────────────────────────────────────────────────────

/// A single decrypted direct message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmMessage {
    /// Outer event id (kind-1059 wrap id, kind-4 id, or a `local-…` optimistic id).
    pub id: String,
    /// Real sender hex pubkey (the seal signer for gift-wraps).
    pub sender_pubkey: String,
    /// Recipient hex pubkey (the rumor's `p` tag / the kind-4 `p` tag).
    pub recipient_pubkey: String,
    /// Plaintext body.
    pub content: String,
    /// Real timestamp (the rumor's `created_at`, not the randomised wrap stamp).
    pub timestamp: u64,
    /// True when the viewer authored it (right-aligned bubble).
    pub is_sent: bool,
}

/// Summary of a conversation with one counterparty (derived from the messages).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmConversation {
    /// The counterparty's hex pubkey.
    pub pubkey: String,
    /// Truncated preview of the most recent message.
    pub last_message: String,
    /// Timestamp of the most recent message.
    pub last_timestamp: u64,
    /// Count of received messages not yet viewed in the open thread.
    pub unread_count: u32,
}

/// Reactive inner state. `Clone` so view closures can `.get()` a snapshot.
#[derive(Clone, Debug, Default)]
struct DmInner {
    messages: Vec<DmMessage>,
    /// O(1) dedup index over `messages.id`.
    seen: std::collections::HashSet<String>,
    /// Per-peer last-read wall-clock (secs). Opening a thread stamps that peer
    /// to `now`; a received message whose timestamp is newer than the mark
    /// counts as unread, so the inbox badge clears when the thread is read and
    /// re-arms only for genuinely newer traffic. Cleared with the rest of
    /// `DmInner` on sign-out / account switch.
    read_marks: std::collections::HashMap<String, u64>,
    /// The open conversation (counterparty hex), or `None` for the inbox list.
    current_peer: Option<String>,
    /// Latest surfaced error (decrypt/extension capability/send failure).
    error: Option<String>,
    /// Whether the initial history load is still in flight.
    loading: bool,
}

/// Reactive DM store, provided as Leptos context (mirrors `RelayStore`: every
/// field is a `Copy` reactive handle, so the struct is `Copy` and needs no
/// unsafe Send/Sync — the `Rc<dyn Signer>` is never stored here, it is passed
/// per call from `BbsSigner::get_signer()`).
#[derive(Clone, Copy)]
pub struct DmStore {
    inner: RwSignal<DmInner>,
    /// Set once the dedicated DM socket has been opened (idempotent guard).
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    started: RwSignal<bool>,
    /// Signed-in pubkey whose decrypted state is currently loaded. A change here
    /// (login / sign-out / account switch) triggers a full [`Self::reset`] so a
    /// new viewer on a shared device never inherits the previous user's
    /// plaintext conversations. Driven by [`Self::watch_owner`].
    owner: RwSignal<Option<String>>,
}

impl Default for DmStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DmStore {
    /// Create an empty store (requires a reactive owner — call inside a component).
    pub fn new() -> Self {
        Self {
            inner: RwSignal::new(DmInner::default()),
            started: RwSignal::new(false),
            owner: RwSignal::new(None),
        }
    }

    /// Reactive current-conversation peer (hex), or `None` for the inbox list.
    pub fn current_peer(&self) -> Option<String> {
        self.inner.with(|s| s.current_peer.clone())
    }

    /// Open a conversation with `peer_hex` (drills into the thread + clears its
    /// unread by stamping a read mark at `now` and making it the current peer).
    pub fn open_peer(&self, peer_hex: &str) {
        let pk = peer_hex.to_string();
        let now = now_secs();
        self.inner.update(|s| {
            s.read_marks.insert(pk.clone(), now);
            s.current_peer = Some(pk);
        });
    }

    /// Close the open conversation, returning to the inbox list.
    pub fn close_peer(&self) {
        self.inner.update(|s| s.current_peer = None);
    }

    /// Latest error, if any.
    pub fn error(&self) -> Option<String> {
        self.inner.with(|s| s.error.clone())
    }

    /// Clear the surfaced error.
    pub fn clear_error(&self) {
        self.inner.update(|s| s.error = None);
    }

    /// Whether the history load is still running.
    pub fn loading(&self) -> bool {
        self.inner.with(|s| s.loading)
    }

    /// Clear all decrypted DM state (messages, dedup set, read marks, open peer,
    /// error, loading) and tear down the dedicated socket, so a new viewer never
    /// inherits the previous user's plaintext conversations. Called on sign-out /
    /// account switch by [`Self::watch_owner`].
    fn reset(&self) {
        self.inner.set(DmInner::default());
        self.started.set(false);
        #[cfg(target_arch = "wasm32")]
        dm_ws::reset();
    }

    /// Track the signed-in pubkey; on any change (login, sign-out, account
    /// switch) wipe all decrypted DM state. Installed once at the app root (which
    /// is always mounted) so the wipe fires even when the DM screen isn't open.
    /// Mirrors the notification store's per-pubkey owner resolver. The initial
    /// `None → signed-in` stamp is skipped (nothing to clear yet).
    pub fn watch_owner(&self) {
        let store = *self;
        let signer = use_context::<BbsSigner>();
        Effect::new(move |_| {
            let current = signer.and_then(|s| s.pubkey().get());
            let prev = store.owner.get_untracked();
            if prev == current {
                return;
            }
            if prev.is_some() {
                store.reset();
            }
            store.owner.set(current);
        });
    }

    /// Dedup + insert a decrypted message. New ids only; the derived conversation
    /// list / thread recompute from `messages` on the next reactive read.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    fn insert(&self, msg: DmMessage) {
        self.inner.update(|s| {
            if s.seen.insert(msg.id.clone()) {
                s.messages.push(msg);
            }
        });
    }

    // ── Network (wasm) ───────────────────────────────────────────────────────

    /// Open the dedicated DM socket and subscribe to the viewer's inbound
    /// gift-wraps. Idempotent — safe to call on every screen mount.
    #[cfg(target_arch = "wasm32")]
    pub fn start(&self, relay_url: String, signer: Rc<dyn Signer>, my_pk: String) {
        if relay_url.is_empty() || my_pk.len() != 64 {
            return;
        }
        let first = !self.started.get_untracked();
        self.started.set(true);
        if first {
            self.inner.update(|s| s.loading = true);
        }
        dm_ws::connect(*self, signer, &relay_url, &my_pk);
    }

    /// Native fallback (unit tests) — no socket.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn start(&self, _relay_url: String, _signer: Rc<dyn Signer>, _my_pk: String) {}

    /// Encrypt + send a DM to `recipient` via NIP-59 gift-wrap (kind-1059).
    ///
    /// The bubble is inserted optimistically (a `local-…` id); the async
    /// gift-wrap + publish happens on a spawned task because the signer is async
    /// and a NIP-07 extension prompts off the main flow. Our own gift-wrap is
    /// never echoed back to us (its author is a throwaway key, its `#p` is the
    /// recipient), so the optimistic bubble is the sole record — no re-key dance.
    #[cfg(target_arch = "wasm32")]
    pub fn send(&self, signer: Rc<dyn Signer>, my_pk: String, recipient: String, content: String) {
        let text = content.trim().to_string();
        if text.is_empty() || recipient.len() != 64 {
            return;
        }
        let now = (js_sys::Date::now() / 1000.0) as u64;
        // A monotonic counter (not `text.len()`) keys the optimistic-echo id, so
        // two equal-byte-length messages sent within the same wall-clock second
        // get distinct ids and neither is dropped by the seen-set dedup — a
        // sender never receives its own gift-wrap back, so this bubble is the
        // sole record of the sent line.
        let seq = LOCAL_ECHO_SEQ.with(|c| {
            let n = c.get().wrapping_add(1);
            c.set(n);
            n
        });
        let local_id = format!("local-{now}-{seq}");
        self.insert(DmMessage {
            id: local_id.clone(),
            sender_pubkey: my_pk.clone(),
            recipient_pubkey: recipient.clone(),
            content: text.clone(),
            timestamp: now,
            is_sent: true,
        });

        let store = *self;
        wasm_bindgen_futures::spawn_local(async move {
            match nostr_bbs_core::gift_wrap_with_signer(signer.as_ref(), &recipient, &text).await {
                Ok(wrapped) => dm_ws::publish(&wrapped),
                Err(e) => {
                    web_sys::console::error_1(&format!("[bbs-dm] gift wrap failed: {e}").into());
                    store.inner.update(|s| {
                        s.seen.remove(&local_id);
                        s.messages.retain(|m| m.id != local_id);
                        s.error = Some(format!("Could not send: {e}"));
                    });
                }
            }
        });
    }

    /// Native fallback (unit tests) — no crypto / socket.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn send(
        &self,
        _signer: Rc<dyn Signer>,
        _my_pk: String,
        _recipient: String,
        _content: String,
    ) {
    }
}

/// Provide the DM store as context (call once, in `App`). Also installs the
/// per-pubkey owner watcher so decrypted state is wiped on sign-out / account
/// switch (the signer context must already be provided).
pub fn provide_dm_store() {
    let store = DmStore::new();
    provide_context(store);
    store.watch_owner();
}

/// Read the DM store from context. Panics if `provide_dm_store()` was not called.
pub fn use_dm_store() -> DmStore {
    expect_context::<DmStore>()
}

#[cfg(target_arch = "wasm32")]
thread_local! {
    /// Monotonic per-session counter making optimistic-echo ids unique even when
    /// two equal-length messages are sent within the same wall-clock second.
    static LOCAL_ECHO_SEQ: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Current wall-clock in whole seconds. Native (unit tests) has no clock, so it
/// returns `u64::MAX` — opening a thread then marks every message currently
/// present as read, which is the correct "I have read this thread" semantics.
#[cfg(target_arch = "wasm32")]
fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}
#[cfg(not(target_arch = "wasm32"))]
fn now_secs() -> u64 {
    u64::MAX
}

// ── Pure logic (unit-tested on native) ────────────────────────────────────────

/// True iff `s` is a 64-char lowercase-or-mixed hex string (a Nostr x-only pk).
pub fn is_hex_pubkey(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse a peer identifier a user typed into the "new DM" box: a 64-char hex
/// pubkey or an `npub1…`. Returns the lowercase hex pubkey, or a friendly error.
pub fn parse_peer_input(input: &str) -> Result<String, String> {
    let t = input.trim();
    if t.is_empty() {
        return Err("Enter a pubkey (npub1… or 64-char hex).".to_string());
    }
    if t.starts_with("npub1") {
        return nostr_bbs_core::decode_npub(t)
            .map(|h| h.to_ascii_lowercase())
            .map_err(|e| format!("Invalid npub: {e}"));
    }
    let lower = t.to_ascii_lowercase();
    if is_hex_pubkey(&lower) {
        Ok(lower)
    } else {
        Err("Expected an npub1… or 64-char hex pubkey.".to_string())
    }
}

/// Truncate a message to `max` chars, appending an ellipsis when clipped.
pub fn truncate_message(content: &str, max: usize) -> String {
    let t = content.trim();
    if t.chars().count() <= max {
        t.to_string()
    } else {
        let head: String = t.chars().take(max).collect();
        format!("{head}…")
    }
}

/// The counterparty of a message relative to `my_pubkey`: the recipient when we
/// sent it, else the sender. Returns `None` if the resolved pubkey is not a
/// valid 64-hex key (drops self-DMs to a blank recipient and malformed events).
pub fn peer_of(my_pubkey: &str, sender: &str, recipient: &str) -> Option<String> {
    let peer = if sender == my_pubkey {
        recipient
    } else {
        sender
    };
    if is_hex_pubkey(peer) {
        Some(peer.to_string())
    } else {
        None
    }
}

/// The first `["p", <pubkey>]` value from a rumor's tags (the DM recipient).
pub fn rumor_recipient(tags: &[Vec<String>]) -> Option<String> {
    tags.iter()
        .find(|t| t.len() >= 2 && t[0] == "p")
        .map(|t| t[1].clone())
}

/// Build the DM subscription filters: everything addressed to us (`#p`) plus
/// everything we authored, across kind-4 (legacy) and kind-1059 (gift-wrap).
/// `since` bounds the live window (pass the gift-wrap lookback anchor).
pub fn dm_filters(my_pubkey: &str, since: Option<u64>) -> Vec<Value> {
    let mut recv = serde_json::json!({ "kinds": [4, 1059], "#p": [my_pubkey], "limit": 200 });
    let mut sent = serde_json::json!({ "kinds": [4, 1059], "authors": [my_pubkey], "limit": 200 });
    if let Some(s) = since {
        recv["since"] = Value::from(s);
        sent["since"] = Value::from(s);
    }
    vec![recv, sent]
}

/// Build the unsigned kind-22242 NIP-42 AUTH response event.
pub fn build_auth_unsigned(
    pubkey: &str,
    relay_url: &str,
    challenge: &str,
    now: u64,
) -> nostr_bbs_core::UnsignedEvent {
    nostr_bbs_core::UnsignedEvent {
        pubkey: pubkey.to_string(),
        created_at: now,
        kind: 22242,
        tags: vec![
            vec!["relay".to_string(), relay_url.to_string()],
            vec!["challenge".to_string(), challenge.to_string()],
        ],
        content: String::new(),
    }
}

/// Resolve the Jarvis agent pubkey from an `__ENV__` value. Accepts the operator
/// projection (`JARVIS_PUBKEY`), the raw Vite name, or a generic `AGENT_PUBKEY`.
pub fn jarvis_pubkey_from_env(env: &Value) -> Option<String> {
    ["JARVIS_PUBKEY", "VITE_JARVIS_PUBKEY", "AGENT_PUBKEY"]
        .iter()
        .find_map(|k| {
            env.get(k)
                .and_then(Value::as_str)
                .map(str::trim)
                .map(str::to_ascii_lowercase)
                .filter(|s| is_hex_pubkey(s))
        })
}

/// Messages of the conversation with `peer`, chronological (oldest first).
pub fn messages_for_peer(msgs: &[DmMessage], my_pubkey: &str, peer: &str) -> Vec<DmMessage> {
    let mut out: Vec<DmMessage> = msgs
        .iter()
        .filter(|m| {
            peer_of(my_pubkey, &m.sender_pubkey, &m.recipient_pubkey).as_deref() == Some(peer)
        })
        .cloned()
        .collect();
    out.sort_by_key(|m| m.timestamp);
    out
}

/// Group messages into per-counterparty conversation summaries, newest first.
/// `current_peer` is treated as read, so its unread count is zeroed. A received
/// message only counts as unread when its timestamp is newer than that peer's
/// entry in `read_marks` (stamped by [`DmStore::open_peer`]), so reading a
/// thread clears its badge and it re-arms only for genuinely newer traffic.
pub fn group_conversations(
    msgs: &[DmMessage],
    my_pubkey: &str,
    current_peer: Option<&str>,
    read_marks: &std::collections::HashMap<String, u64>,
) -> Vec<DmConversation> {
    use std::collections::HashMap;
    let mut map: HashMap<String, DmConversation> = HashMap::new();
    for m in msgs {
        let peer = match peer_of(my_pubkey, &m.sender_pubkey, &m.recipient_pubkey) {
            Some(p) => p,
            None => continue,
        };
        let entry = map.entry(peer.clone()).or_insert(DmConversation {
            pubkey: peer.clone(),
            last_message: String::new(),
            last_timestamp: 0,
            unread_count: 0,
        });
        if m.timestamp >= entry.last_timestamp {
            entry.last_message = truncate_message(&m.content, 60);
            entry.last_timestamp = m.timestamp;
        }
        if !m.is_sent && current_peer != Some(peer.as_str()) {
            let read_at = read_marks.get(&peer).copied().unwrap_or(0);
            if m.timestamp > read_at {
                entry.unread_count += 1;
            }
        }
    }
    let mut out: Vec<DmConversation> = map.into_values().collect();
    out.sort_by_key(|c| std::cmp::Reverse(c.last_timestamp));
    out
}

// ── Dedicated DM WebSocket (wasm only) ────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
mod dm_ws {
    use super::{build_auth_unsigned, dm_filters, DmStore, GIFT_WRAP_LOOKBACK_SECS};
    use leptos::prelude::Update;
    use nostr_bbs_core::gift_wrap::{KIND_ENCRYPTED_DM, KIND_GIFT_WRAP};
    use nostr_bbs_core::signer::Signer;
    use nostr_bbs_core::NostrEvent;
    use std::cell::RefCell;
    use std::rc::Rc;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsCast;

    thread_local! {
        static WS: RefCell<Option<web_sys::WebSocket>> = const { RefCell::new(None) };
        static SIGNER: RefCell<Option<Rc<dyn Signer>>> = const { RefCell::new(None) };
        static RELAY_URL: RefCell<String> = const { RefCell::new(String::new()) };
        static MY_PK: RefCell<String> = const { RefCell::new(String::new()) };
        /// AUTH challenge stashed if it arrives before the signer is registered.
        static PENDING_AUTH: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    const DM_SUB_ID: &str = "bbs-dm";

    fn ws_open() -> Option<web_sys::WebSocket> {
        WS.with(|c| {
            c.borrow()
                .as_ref()
                .filter(|ws| ws.ready_state() == web_sys::WebSocket::OPEN)
                .cloned()
        })
    }

    fn send_str(text: &str) {
        if let Some(ws) = ws_open() {
            let _ = ws.send_with_str(text);
        }
    }

    /// (Re)issue the DM REQ. The relay AUTH-gates kind-1059, so a pre-AUTH REQ is
    /// answered with an AUTH challenge and dropped; `handle_auth` replays this.
    fn send_dm_req() {
        let my_pk = MY_PK.with(|p| p.borrow().clone());
        if my_pk.is_empty() {
            return;
        }
        let now = (js_sys::Date::now() / 1000.0) as u64;
        let since = now.saturating_sub(GIFT_WRAP_LOOKBACK_SECS);
        let mut frame = vec![
            serde_json::Value::from("REQ"),
            serde_json::Value::from(DM_SUB_ID),
        ];
        frame.extend(dm_filters(&my_pk, Some(since)));
        send_str(&serde_json::Value::Array(frame).to_string());
    }

    pub fn publish(event: &NostrEvent) {
        if let Ok(msg) = serde_json::to_string(&serde_json::json!(["EVENT", event])) {
            send_str(&msg);
        }
    }

    /// Close the dedicated DM socket and drop every per-viewer thread-local (the
    /// signer, relay/pubkey, and any stashed AUTH challenge), so a subsequent
    /// `connect` for a new identity starts from a clean slate. Called by
    /// [`super::DmStore::reset`] on sign-out / account switch.
    pub fn reset() {
        WS.with(|c| {
            if let Some(ws) = c.borrow_mut().take() {
                let _ = ws.close();
            }
        });
        SIGNER.with(|s| *s.borrow_mut() = None);
        RELAY_URL.with(|u| u.borrow_mut().clear());
        MY_PK.with(|p| p.borrow_mut().clear());
        PENDING_AUTH.with(|c| *c.borrow_mut() = None);
    }

    /// Answer a NIP-42 challenge with a signed kind-22242, then replay the REQ so
    /// the relay serves our gift-wraps on the authenticated session.
    fn handle_auth(challenge: String) {
        let signer = match SIGNER.with(|s| s.borrow().clone()) {
            Some(s) => s,
            None => {
                PENDING_AUTH.with(|c| *c.borrow_mut() = Some(challenge));
                return;
            }
        };
        let relay_url = RELAY_URL.with(|u| u.borrow().clone());
        let now = (js_sys::Date::now() / 1000.0) as u64;
        let unsigned = build_auth_unsigned(signer.public_key(), &relay_url, &challenge, now);
        wasm_bindgen_futures::spawn_local(async move {
            match signer.sign_event(unsigned).await {
                Ok(signed) => {
                    if let Ok(msg) = serde_json::to_string(&serde_json::json!(["AUTH", signed])) {
                        send_str(&msg);
                    }
                    send_dm_req();
                }
                Err(e) => {
                    web_sys::console::warn_1(&format!("[bbs-dm] AUTH signing failed: {e}").into())
                }
            }
        });
    }

    fn spawn_ingest(store: DmStore, event: NostrEvent) {
        let signer = match SIGNER.with(|s| s.borrow().clone()) {
            Some(s) => s,
            None => return,
        };
        let my_pk = MY_PK.with(|p| p.borrow().clone());
        wasm_bindgen_futures::spawn_local(async move {
            if event.kind == KIND_GIFT_WRAP {
                match nostr_bbs_core::unwrap_gift_with_signer(&event, signer.as_ref()).await {
                    Ok(u) => {
                        let sender = u.sender_pubkey.clone();
                        let is_sent = sender == my_pk;
                        let recipient =
                            super::rumor_recipient(&u.rumor.tags).unwrap_or_else(|| {
                                if is_sent {
                                    String::new()
                                } else {
                                    my_pk.clone()
                                }
                            });
                        store.insert(super::DmMessage {
                            id: event.id.clone(),
                            sender_pubkey: sender,
                            recipient_pubkey: recipient,
                            content: u.rumor.content.clone(),
                            timestamp: u.rumor.created_at,
                            is_sent,
                        });
                    }
                    Err(e) => {
                        let m = e.to_string();
                        web_sys::console::warn_1(
                            &format!("[bbs-dm] gift unwrap failed for {}: {m}", event.id).into(),
                        );
                        if m.contains("nip44") {
                            store.inner.update(|s| {
                                if s.error.is_none() {
                                    s.error = Some(
                                        "Your signer can't do NIP-44 encryption, which these \
                                         messages need. Use a local key (or an extension that \
                                         supports NIP-44) to read DMs."
                                            .to_string(),
                                    );
                                }
                            });
                        }
                    }
                }
            } else if event.kind == KIND_ENCRYPTED_DM {
                // Legacy kind-4 (NIP-04). Counterparty = the `p` tag when we sent
                // it, else the author.
                let is_sent = event.pubkey == my_pk;
                let counterparty = if is_sent {
                    super::rumor_recipient(&event.tags)
                } else {
                    Some(event.pubkey.clone())
                };
                let counterparty = match counterparty {
                    Some(pk) if super::is_hex_pubkey(&pk) => pk,
                    _ => return,
                };
                match signer.nip04_decrypt(&counterparty, &event.content).await {
                    Ok(plaintext) => store.insert(super::DmMessage {
                        id: event.id.clone(),
                        sender_pubkey: event.pubkey.clone(),
                        recipient_pubkey: if is_sent { counterparty } else { my_pk.clone() },
                        content: plaintext,
                        timestamp: event.created_at,
                        is_sent,
                    }),
                    Err(e) => web_sys::console::warn_1(
                        &format!("[bbs-dm] kind-4 decrypt failed for {}: {e}", event.id).into(),
                    ),
                }
            }
        });
    }

    fn handle_frame(store: DmStore, txt: &str) {
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
                            spawn_ingest(store, ev);
                        }
                    }
                }
            }
            Some("AUTH") => {
                if let Some(ch) = arr.get(1).and_then(|v| v.as_str()) {
                    handle_auth(ch.to_string());
                }
            }
            Some("EOSE") => store.inner.update(|s| s.loading = false),
            _ => {}
        }
    }

    pub fn connect(store: DmStore, signer: Rc<dyn Signer>, url: &str, my_pk: &str) {
        RELAY_URL.with(|u| *u.borrow_mut() = url.to_string());
        MY_PK.with(|p| *p.borrow_mut() = my_pk.to_string());
        SIGNER.with(|s| *s.borrow_mut() = Some(signer));
        // A late-arriving signer answers a stashed challenge; a live socket just
        // re-subscribes on the (now authenticated) session.
        if let Some(ch) = PENDING_AUTH.with(|c| c.borrow_mut().take()) {
            handle_auth(ch);
        }
        if ws_open().is_some() {
            send_dm_req();
            return;
        }

        let ws = match web_sys::WebSocket::new(url) {
            Ok(w) => w,
            Err(_) => return,
        };

        let onopen = Closure::<dyn FnMut()>::new(move || {
            send_dm_req();
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

        WS.with(|c| *c.borrow_mut() = Some(ws));
    }
}

// ── Jarvis pubkey (wasm reads live `window.__ENV__`) ──────────────────────────

/// The configured Jarvis agent pubkey, if any. wasm reads `window.__ENV__`
/// directly (config.rs's reader is private and its struct is a frozen shared
/// file); native returns `None`.
#[cfg(target_arch = "wasm32")]
pub fn jarvis_pubkey() -> Option<String> {
    let window = web_sys::window()?;
    let env = js_sys::Reflect::get(&window, &"__ENV__".into()).ok()?;
    if env.is_undefined() || env.is_null() {
        return None;
    }
    let json = js_sys::JSON::stringify(&env).ok()?.as_string()?;
    let value: Value = serde_json::from_str(&json).ok()?;
    jarvis_pubkey_from_env(&value)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn jarvis_pubkey() -> Option<String> {
    None
}

// ── View ──────────────────────────────────────────────────────────────────────

/// A keydown handler that activates a `role="button"` on Enter / Space (mirrors
/// the private `on_activate` in `screens.rs`; every hotkey needs a tappable twin).
fn on_activate<F: Fn() + 'static>(action: F) -> impl Fn(web_sys::KeyboardEvent) + 'static {
    move |ev: web_sys::KeyboardEvent| {
        let k = ev.key();
        if k == "Enter" || k == " " || k == "Spacebar" {
            ev.prevent_default();
            action();
        }
    }
}

/// A friendly display label for a peer: `Jarvis (AI)` when it is the configured
/// agent, else the short id.
fn peer_label(peer: &str, jarvis: Option<&str>) -> String {
    if Some(peer) == jarvis {
        "Jarvis (AI)".to_string()
    } else {
        crate::relay::short_id(peer)
    }
}

/// The DM screen (F8): inbox list → per-peer thread → composer. Entered from the
/// bottom-nav "✉ DMs" tab / the `Screen::Dm` match arm. Fails closed when signed
/// out (write + read of gift-wraps both need the signer).
pub fn dm_screen(state: BbsState, cfg: StoredValue<BbsConfig>) -> impl IntoView {
    let store = use_dm_store();
    let signer = use_context::<BbsSigner>();
    let relay_url = cfg.with_value(|c| c.relay_url.clone());
    let jarvis = jarvis_pubkey();

    // Connect the dedicated DM socket once a signer is present (idempotent).
    Effect::new(move |_| {
        if let Some(sg) = signer {
            if let (Some(pk), Some(rc)) = (sg.pubkey().get(), sg.get_signer()) {
                store.start(relay_url.clone(), rc, pk);
            }
        }
    });

    view! {
        <div class="bbs-panel">
            <span class="title">"┌─ Direct Messages ─────────────────────────────"</span>
            "\n  " <span class="bbs-dim">"Encrypted 1:1 (NIP-44 sealed · NIP-59 gift-wrapped)"</span> "\n"
        </div>
        {move || {
            let authed = signer.and_then(|s| s.pubkey().get());
            match authed {
                None => view! {
                    <div class="bbs-panel bbs-dim">
                        "  Sign in to open encrypted DMs — tap " <span class="accent">"Sign in"</span>
                        " on the bottom bar, or open Settings. Messages are sealed to the\n"
                        "  recipient's key; nobody else (not even the relay) can read them."
                    </div>
                }.into_any(),
                Some(my_pk) => {
                    match store.current_peer() {
                        Some(peer) => dm_thread(state, store, my_pk, peer, jarvis.clone()).into_any(),
                        None => dm_inbox(state, store, my_pk, jarvis.clone()).into_any(),
                    }
                }
            }
        }}
    }
}

/// The inbox: a "message Jarvis" quick-start, a new-DM box, and the conversation
/// list (tappable rows).
fn dm_inbox(
    _state: BbsState,
    store: DmStore,
    my_pk: String,
    jarvis: Option<String>,
) -> impl IntoView {
    let new_peer = RwSignal::new(String::new());
    let new_err = RwSignal::new(None::<String>);

    let start_dm = {
        let store = store;
        std::rc::Rc::new(move || match parse_peer_input(&new_peer.get_untracked()) {
            Ok(pk) => {
                new_err.set(None);
                new_peer.set(String::new());
                store.open_peer(&pk);
            }
            Err(e) => new_err.set(Some(e)),
        }) as std::rc::Rc<dyn Fn()>
    };
    let start_click = start_dm.clone();
    let start_key = start_dm.clone();

    // "Message Jarvis" quick-start (only when the agent is configured and isn't us).
    let jarvis_cta = jarvis.clone().filter(|j| *j != my_pk).map(|j| {
        let store = store;
        let open = move || store.open_peer(&j);
        let open_key = open.clone();
        view! {
            <div class="bbs-panel">
                <span class="bbs-link accent bbs-cta" role="button" tabindex="0"
                    aria-label="Message the Jarvis AI agent"
                    on:click=move |_| open()
                    on:keydown=on_activate(move || open_key())
                >"[ \u{25B8} Message Jarvis (AI) ]"</span>
            </div>
        }
    });

    let my_pk_list = my_pk.clone();
    view! {
        {jarvis_cta}
        <div class="bbs-cmdline">
            <span class="prompt">"to/"</span>
            <input
                prop:value=move || new_peer.get()
                placeholder="npub1… or 64-char hex"
                aria-label="Recipient pubkey"
                on:input=move |ev| new_peer.set(event_target_value(&ev))
                on:keydown={
                    let s = start_key.clone();
                    move |ev| if ev.key() == "Enter" { ev.prevent_default(); s(); }
                }
            />
            <span class="bbs-link accent" role="button" tabindex="0"
                aria-label="Start conversation"
                on:click=move |_| start_click()
                on:keydown={ let s = start_dm.clone(); on_activate(move || s()) }
            >"[ open ]"</span>
            {move || new_err.get().map(|e| view! { <span class="bbs-dim">{format!(" \u{2717} {e}")}</span> })}
        </div>
        {move || {
            let (inner_msgs, marks) =
                store.inner.with(|s| (s.messages.clone(), s.read_marks.clone()));
            let convos = group_conversations(&inner_msgs, &my_pk_list, None, &marks);
            if convos.is_empty() {
                let hint = if store.loading() {
                    "  Syncing your encrypted inbox…"
                } else {
                    "  No conversations yet. Message Jarvis above, or paste a pubkey to\n  start an encrypted thread."
                };
                return view! { <div class="bbs-panel bbs-dim">{hint}</div> }.into_any();
            }
            let jarvis_ref = jarvis.clone();
            view! {
                <div class="bbs-list">
                    {convos.into_iter().map(|c| {
                        let peer = c.pubkey.clone();
                        let name = peer_label(&peer, jarvis_ref.as_deref());
                        let preview = c.last_message.clone();
                        let unread = c.unread_count;
                        let store = store;
                        let open = move || store.open_peer(&peer);
                        let open_key = open.clone();
                        let badge = if unread > 0 { format!("({unread})") } else { String::new() };
                        let aria = format!("Open conversation with {name}");
                        view! {
                            <div class="bbs-row bbs-dm-convo" role="button" tabindex="0"
                                aria-label=aria
                                on:click=move |_| open()
                                on:keydown=on_activate(move || open_key())
                            >
                                <span class="accent bbs-chip">"\u{2709}"</span>
                                <span class="bbs-dm-name accent">{name}</span>
                                <span class="bbs-dm-preview bbs-dim">{preview}</span>
                                <span class="bbs-dm-unread accent">{badge}</span>
                            </div>
                        }
                    }).collect_view()}
                </div>
            }.into_any()
        }}
    }
}

/// A per-peer thread: back control, message bubbles (oldest → newest), composer.
fn dm_thread(
    _state: BbsState,
    store: DmStore,
    my_pk: String,
    peer: String,
    jarvis: Option<String>,
) -> impl IntoView {
    let signer = use_context::<BbsSigner>();
    let draft = RwSignal::new(String::new());
    let name = peer_label(&peer, jarvis.as_deref());

    let send = {
        let peer = peer.clone();
        let my_pk = my_pk.clone();
        std::rc::Rc::new(move || {
            let text = draft.get_untracked().trim().to_string();
            if text.is_empty() {
                return;
            }
            let sg = match signer {
                Some(s) => s,
                None => return,
            };
            let rc = match sg.get_signer() {
                Some(r) => r,
                None => {
                    store.clear_error();
                    return;
                }
            };
            draft.set(String::new());
            store.send(rc, my_pk.clone(), peer.clone(), text);
        }) as std::rc::Rc<dyn Fn()>
    };
    let send_click = send.clone();
    let send_key = send.clone();

    let my_pk_msgs = my_pk.clone();
    let peer_msgs = peer.clone();
    let my_pk_self = my_pk.clone();
    view! {
        <div class="bbs-panel bbs-crumb">
            <span class="bbs-link accent" role="button" tabindex="0"
                aria-label="Back to inbox"
                on:click=move |_| store.close_peer()
                on:keydown=on_activate(move || store.close_peer())
            >"\u{2190} Inbox"</span>
            <span class="bbs-dim">"  chatting with "</span>
            <span class="accent">{name}</span>
        </div>
        {move || store.error().map(|e| view! {
            <div class="bbs-panel bbs-dim">{format!("  \u{2717} {e}")}</div>
        })}
        {move || {
            let all = store.inner.with(|s| s.messages.clone());
            let msgs = messages_for_peer(&all, &my_pk_msgs, &peer_msgs);
            if msgs.is_empty() {
                return view! {
                    <div class="bbs-panel bbs-dim">
                        "  No messages yet — say hello below. Your first line is sealed to\n  their key and gift-wrapped before it leaves this device."
                    </div>
                }.into_any();
            }
            let me = my_pk_self.clone();
            view! {
                <div class="bbs-list bbs-dm-thread">
                    {msgs.into_iter().map(|m| {
                        let is_me = m.sender_pubkey == me;
                        let who = if is_me { "you".to_string() } else { crate::relay::short_id(&m.sender_pubkey) };
                        let body = m.content.clone();
                        view! {
                            <div class="bbs-row bbs-dm-msg" class:bbs-dm-sent=is_me>
                                <span class="accent">{format!("<{who}> ")}</span>{body}
                            </div>
                        }
                    }).collect_view()}
                </div>
            }.into_any()
        }}
        <div class="bbs-cmdline">
            <span class="prompt">"dm/"</span>
            <input
                prop:value=move || draft.get()
                aria-label="Message"
                on:input=move |ev| draft.set(event_target_value(&ev))
                on:keydown={
                    let s = send_key.clone();
                    move |ev| if ev.key() == "Enter" { ev.prevent_default(); s(); }
                }
            />
            <span class="bbs-link accent" role="button" tabindex="0"
                aria-label="Send message"
                on:click=move |_| send_click()
                on:keydown={ let s = send.clone(); on_activate(move || s()) }
            >"[ send ]"</span>
        </div>
    }
}

// keep the DM-kind constants referenced so the import is not dead on native.
#[allow(dead_code)]
const _DM_KINDS: (u64, u64) = (KIND_ENCRYPTED_DM, KIND_GIFT_WRAP);

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(id: &str, from: &str, to: &str, body: &str, ts: u64, sent: bool) -> DmMessage {
        DmMessage {
            id: id.to_string(),
            sender_pubkey: from.to_string(),
            recipient_pubkey: to.to_string(),
            content: body.to_string(),
            timestamp: ts,
            is_sent: sent,
        }
    }

    const ME: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
    const BOB: &str = "22222222222222222222222222222222222222222222222222222222222222bb";
    const JAR: &str = "2de44d5622eef79519ac078f6e227a85aecbaefd561e4e50c5f51dfadbf916e9";

    #[test]
    fn hex_pubkey_validation() {
        assert!(is_hex_pubkey(ME));
        assert!(is_hex_pubkey(JAR));
        assert!(!is_hex_pubkey("short"));
        assert!(!is_hex_pubkey(&"zz".repeat(32)));
        assert!(!is_hex_pubkey(&"aa".repeat(31))); // 62 chars
    }

    #[test]
    fn peer_input_accepts_hex_and_rejects_garbage() {
        assert_eq!(
            parse_peer_input(&format!("  {} ", ME.to_uppercase())).unwrap(),
            ME
        );
        assert!(parse_peer_input("").is_err());
        assert!(parse_peer_input("not-a-key").is_err());
        assert!(parse_peer_input("npub1notvalid").is_err());
    }

    #[test]
    fn peer_input_accepts_npub() {
        let npub = nostr_bbs_core::encode_npub(BOB).expect("encode npub");
        assert_eq!(parse_peer_input(&npub).unwrap(), BOB);
    }

    #[test]
    fn peer_of_picks_counterparty() {
        // We sent → counterparty is the recipient.
        assert_eq!(peer_of(ME, ME, BOB).as_deref(), Some(BOB));
        // We received → counterparty is the sender.
        assert_eq!(peer_of(ME, BOB, ME).as_deref(), Some(BOB));
        // Malformed peer → dropped.
        assert_eq!(peer_of(ME, ME, "bad"), None);
    }

    #[test]
    fn rumor_recipient_extracts_p_tag() {
        let tags = vec![
            vec!["e".to_string(), "x".to_string()],
            vec!["p".to_string(), BOB.to_string()],
        ];
        assert_eq!(rumor_recipient(&tags).as_deref(), Some(BOB));
        assert_eq!(rumor_recipient(&[]), None);
    }

    #[test]
    fn dm_filters_target_viewer_and_kinds() {
        let f = dm_filters(ME, Some(1000));
        assert_eq!(f.len(), 2);
        // received filter: #p == me
        assert_eq!(f[0]["#p"][0], serde_json::Value::from(ME));
        assert_eq!(f[0]["kinds"], serde_json::json!([4, 1059]));
        assert_eq!(f[0]["since"], serde_json::Value::from(1000u64));
        // sent filter: authors == me
        assert_eq!(f[1]["authors"][0], serde_json::Value::from(ME));
    }

    #[test]
    fn dm_filters_omit_since_when_none() {
        let f = dm_filters(ME, None);
        assert!(f[0].get("since").is_none());
    }

    #[test]
    fn auth_event_is_kind_22242_with_tags() {
        let e = build_auth_unsigned(ME, "wss://relay", "chal", 42);
        assert_eq!(e.kind, 22242);
        assert_eq!(e.pubkey, ME);
        assert_eq!(e.created_at, 42);
        assert!(e
            .tags
            .contains(&vec!["relay".to_string(), "wss://relay".to_string()]));
        assert!(e
            .tags
            .contains(&vec!["challenge".to_string(), "chal".to_string()]));
    }

    #[test]
    fn jarvis_pubkey_resolves_known_keys() {
        let env = serde_json::json!({ "JARVIS_PUBKEY": JAR.to_uppercase() });
        assert_eq!(jarvis_pubkey_from_env(&env).as_deref(), Some(JAR));
        let env2 = serde_json::json!({ "VITE_JARVIS_PUBKEY": JAR });
        assert_eq!(jarvis_pubkey_from_env(&env2).as_deref(), Some(JAR));
        // Missing / malformed → None.
        assert_eq!(jarvis_pubkey_from_env(&serde_json::json!({})), None);
        assert_eq!(
            jarvis_pubkey_from_env(&serde_json::json!({ "JARVIS_PUBKEY": "nope" })),
            None
        );
    }

    #[test]
    fn truncate_message_clips_with_ellipsis() {
        assert_eq!(truncate_message("  hi  ", 10), "hi");
        assert_eq!(
            truncate_message(&"a".repeat(70), 60),
            format!("{}…", "a".repeat(60))
        );
    }

    fn no_marks() -> std::collections::HashMap<String, u64> {
        std::collections::HashMap::new()
    }

    #[test]
    fn group_conversations_summarises_newest_first() {
        let msgs = vec![
            msg("1", BOB, ME, "hi there", 100, false),
            msg("2", ME, BOB, "hey bob", 200, true),
            msg("3", JAR, ME, "beep boop", 300, false),
        ];
        let convos = group_conversations(&msgs, ME, None, &no_marks());
        assert_eq!(convos.len(), 2);
        // Jarvis has the newest activity → first.
        assert_eq!(convos[0].pubkey, JAR);
        assert_eq!(convos[0].last_message, "beep boop");
        assert_eq!(convos[0].unread_count, 1);
        // Bob conversation: last message is the newest one (ts 200, our reply).
        assert_eq!(convos[1].pubkey, BOB);
        assert_eq!(convos[1].last_message, "hey bob");
        // One received (hi there) → unread 1 when not current.
        assert_eq!(convos[1].unread_count, 1);
    }

    #[test]
    fn group_conversations_zeroes_unread_for_current_peer() {
        let msgs = vec![msg("1", BOB, ME, "hi", 100, false)];
        let convos = group_conversations(&msgs, ME, Some(BOB), &no_marks());
        assert_eq!(convos[0].unread_count, 0);
    }

    #[test]
    fn group_conversations_read_mark_clears_unread() {
        let msgs = vec![
            msg("1", BOB, ME, "old", 100, false),
            msg("2", BOB, ME, "newer", 300, false),
        ];
        // No mark → both received messages are unread.
        assert_eq!(
            group_conversations(&msgs, ME, None, &no_marks())[0].unread_count,
            2
        );
        // Read up to ts 200 → only the ts-300 message is still unread.
        let mut marks = std::collections::HashMap::new();
        marks.insert(BOB.to_string(), 200u64);
        assert_eq!(
            group_conversations(&msgs, ME, None, &marks)[0].unread_count,
            1
        );
        // Read past the newest → nothing unread (opening the thread cleared it).
        marks.insert(BOB.to_string(), 400u64);
        assert_eq!(
            group_conversations(&msgs, ME, None, &marks)[0].unread_count,
            0
        );
    }

    #[test]
    fn messages_for_peer_filters_and_sorts() {
        let msgs = vec![
            msg("2", ME, BOB, "second", 200, true),
            msg("1", BOB, ME, "first", 100, false),
            msg("x", JAR, ME, "other peer", 150, false),
        ];
        let thread = messages_for_peer(&msgs, ME, BOB);
        assert_eq!(thread.len(), 2);
        assert_eq!(thread[0].content, "first"); // oldest first
        assert_eq!(thread[1].content, "second");
    }
}
