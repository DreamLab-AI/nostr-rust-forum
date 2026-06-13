//! WebSocket relay connection manager for NIP-01 Nostr protocol.
//!
//! Manages a single WebSocket connection to the nostr-bbs relay, handling
//! subscriptions, event parsing, publishing, auto-reconnect with exponential
//! backoff, and connection state as a reactive Leptos signal.
//!
//! Uses `SendWrapper` to satisfy `Send + Sync` bounds required by Leptos
//! context in CSR mode. All access is single-threaded on the WASM main
//! thread, so this is safe.

use leptos::prelude::*;
use nostr_bbs_core::{NostrEvent, UnsignedEvent};
use send_wrapper::SendWrapper;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use web_sys::WebSocket;

/// Default relay URL when VITE_RELAY_URL is not set.
const DEFAULT_RELAY_URL: &str = "wss://relay.example.com";

/// Maximum reconnect delay in milliseconds.
const MAX_RECONNECT_DELAY_MS: u32 = 30_000;

/// Base reconnect delay in milliseconds.
const BASE_RECONNECT_DELAY_MS: u32 = 1_000;

/// Connection state for the relay WebSocket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Error,
}

/// A NIP-01 subscription filter.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<u64>>,
    #[serde(rename = "#e", skip_serializing_if = "Option::is_none")]
    pub e_tags: Option<Vec<String>>,
    #[serde(rename = "#p", skip_serializing_if = "Option::is_none")]
    pub p_tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
}

/// Callback type for received events on a subscription.
pub type EventCallback = Rc<dyn Fn(NostrEvent)>;

/// Callback type for EOSE (End of Stored Events) on a subscription.
pub type EoseCallback = Rc<dyn Fn()>;

/// Callback type for publish acknowledgement (accepted: bool, message: String).
pub type PublishCallback = Rc<dyn Fn(bool, String)>;

/// Tracks a pending publish awaiting relay OK response.
struct PendingPublish {
    on_ok: Option<PublishCallback>,
}

/// Internal subscription tracking.
struct Subscription {
    filters: Vec<Filter>,
    on_event: EventCallback,
    on_eose: Option<EoseCallback>,
}

/// Synchronous signer for NIP-42 AUTH (nsec / passkey logins).
pub(crate) type AuthSignCallback = Rc<dyn Fn(UnsignedEvent) -> Option<NostrEvent>>;

/// Async signer for NIP-42 AUTH (NIP-07 browser extension logins).
pub(crate) type AuthSignAsyncCallback = Rc<
    dyn Fn(
        UnsignedEvent,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<NostrEvent>>>>,
>;

/// Internal mutable state for the relay connection.
struct RelayInner {
    ws: Option<WebSocket>,
    subscriptions: HashMap<String, Subscription>,
    pending_publishes: HashMap<String, PendingPublish>,
    sub_counter: u32,
    reconnect_attempts: u32,
    pending_messages: Vec<String>,
    relay_url: String,
    seen_events: HashSet<String>,
    auth_signer: Option<AuthSignCallback>,
    auth_signer_async: Option<AuthSignAsyncCallback>,
    /// Reactive sink for relay NOTICE messages (cloned from the outer
    /// `RelayConnection::notice` signal so `handle_relay_message` can publish).
    notice_sink: Option<RwSignal<Option<RelayNotice>>>,
    /// Rate-limit state for NOTICE dedup: last surfaced text + epoch-ms time.
    last_notice: Option<(String, f64)>,
    /// Monotonic counter so each surfaced notice has a distinct `seq`.
    notice_seq: u64,
    _on_open: Option<Closure<dyn FnMut()>>,
    _on_message: Option<Closure<dyn FnMut(web_sys::MessageEvent)>>,
    _on_error: Option<Closure<dyn FnMut(web_sys::ErrorEvent)>>,
    _on_close: Option<Closure<dyn FnMut(web_sys::CloseEvent)>>,
}

/// Thread-safe wrapper around the relay inner state.
/// `SendWrapper` asserts single-thread access at runtime, which is
/// guaranteed in WASM.
type SharedInner = SendWrapper<Rc<RefCell<RelayInner>>>;

/// A relay NOTICE message surfaced to the UI. Carries a monotonically
/// increasing `seq` so consumers can react to *every* notice (even a repeat of
/// the same text) without missing one, while the relay layer still suppresses
/// rapid duplicates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayNotice {
    /// The human-readable notice text from the relay.
    pub message: String,
    /// Monotonic sequence — changes on every surfaced notice.
    pub seq: u64,
}

/// Relay connection manager. Provided as Leptos context so any component
/// can subscribe to events or publish.
#[derive(Clone)]
pub struct RelayConnection {
    inner: SharedInner,
    state: RwSignal<ConnectionState>,
    /// Latest relay NOTICE surfaced for the UI (rate-limited against rapid
    /// duplicates inside `handle_relay_message`). Components can read this to
    /// raise a warn toast.
    notice: RwSignal<Option<RelayNotice>>,
}

// SAFETY: In WASM, there is only one thread. SendWrapper enforces this
// at runtime. These impls allow RelayConnection to be used with
// provide_context.
#[cfg(target_arch = "wasm32")]
unsafe impl Send for RelayConnection {}
#[cfg(target_arch = "wasm32")]
unsafe impl Sync for RelayConnection {}

impl RelayConnection {
    /// Create a new relay connection manager. Does not connect immediately.
    pub fn new() -> Self {
        let relay_url = get_relay_url();
        let inner = Rc::new(RefCell::new(RelayInner {
            ws: None,
            subscriptions: HashMap::new(),
            pending_publishes: HashMap::new(),
            sub_counter: 0,
            reconnect_attempts: 0,
            pending_messages: Vec::new(),
            relay_url,
            seen_events: HashSet::new(),
            auth_signer: None,
            auth_signer_async: None,
            notice_sink: None,
            last_notice: None,
            notice_seq: 0,
            _on_open: None,
            _on_message: None,
            _on_error: None,
            _on_close: None,
        }));
        let notice = RwSignal::new(None);
        inner.borrow_mut().notice_sink = Some(notice);
        Self {
            inner: SendWrapper::new(inner),
            state: RwSignal::new(ConnectionState::Disconnected),
            notice,
        }
    }

    /// Reactive signal carrying the latest relay NOTICE (rate-limited). A
    /// consumer can raise a warn toast when this changes.
    pub fn notices(&self) -> RwSignal<Option<RelayNotice>> {
        self.notice
    }

    /// Get the reactive connection state signal.
    pub fn connection_state(&self) -> RwSignal<ConnectionState> {
        self.state
    }

    /// Register a synchronous signer for NIP-42 AUTH challenges (nsec / passkey).
    pub fn set_auth_signer(&self, signer: AuthSignCallback) {
        self.with_inner(|rc| {
            rc.borrow_mut().auth_signer = Some(signer);
        });
    }

    /// Register an async signer for NIP-42 AUTH challenges (NIP-07 extension).
    pub fn set_auth_signer_async(&self, signer: AuthSignAsyncCallback) {
        self.with_inner(|rc| {
            rc.borrow_mut().auth_signer_async = Some(signer);
        });
    }

    /// Access the inner Rc.
    fn with_inner<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Rc<RefCell<RelayInner>>) -> R,
    {
        f(&self.inner)
    }

    /// Connect to the relay WebSocket.
    pub fn connect(&self) {
        let url = self.with_inner(|rc| rc.borrow().relay_url.clone());
        self.connect_to(&url);
    }

    /// Connect to a specific relay URL.
    fn connect_to(&self, url: &str) {
        // Close existing connection. Detach the JS event handlers BEFORE the
        // closures are dropped below — otherwise the closing socket fires
        // onclose/onmessage on a later tick and invokes a freed Closure
        // ("closure invoked recursively or after being dropped", thrown from
        // WebSocket.real), and that stale onclose also re-triggers
        // schedule_reconnect() (state is not Disconnected here) → reconnect storm.
        self.with_inner(|rc| {
            let mut inner = rc.borrow_mut();
            if let Some(ws) = inner.ws.take() {
                ws.set_onopen(None);
                ws.set_onmessage(None);
                ws.set_onerror(None);
                ws.set_onclose(None);
                let _ = ws.close();
            }
            inner._on_open = None;
            inner._on_message = None;
            inner._on_error = None;
            inner._on_close = None;
        });

        self.state.set(ConnectionState::Connecting);

        let ws = match WebSocket::new(url) {
            Ok(ws) => ws,
            Err(e) => {
                web_sys::console::error_1(
                    &format!("[Relay] Failed to create WebSocket: {:?}", e).into(),
                );
                self.state.set(ConnectionState::Error);
                self.schedule_reconnect();
                return;
            }
        };

        ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

        // --- onopen ---
        let inner_rc = (*self.inner).clone();
        let state = self.state;
        let on_open = Closure::wrap(Box::new(move || {
            web_sys::console::log_1(&"[Relay] WebSocket connected".into());
            state.set(ConnectionState::Connected);
            let mut inner = inner_rc.borrow_mut();
            inner.reconnect_attempts = 0;
            inner.seen_events.clear();
            // Flush pending messages
            let pending: Vec<String> = inner.pending_messages.drain(..).collect();
            if let Some(ws) = &inner.ws {
                for msg in pending {
                    let _ = ws.send_with_str(&msg);
                }
                // Replay subscriptions on reconnect
                for (sub_id, sub) in inner.subscriptions.iter() {
                    let mut req = vec![
                        serde_json::Value::String("REQ".into()),
                        serde_json::Value::String(sub_id.clone()),
                    ];
                    for filter in &sub.filters {
                        if let Ok(v) = serde_json::to_value(filter) {
                            req.push(v);
                        }
                    }
                    if let Ok(msg) = serde_json::to_string(&req) {
                        let _ = ws.send_with_str(&msg);
                    }
                }
            }
        }) as Box<dyn FnMut()>);
        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));

        // --- onmessage ---
        let inner_rc_msg = (*self.inner).clone();
        let on_message = Closure::wrap(Box::new(move |e: web_sys::MessageEvent| {
            if let Some(text) = e.data().as_string() {
                handle_relay_message(&inner_rc_msg, &text);
            }
        }) as Box<dyn FnMut(web_sys::MessageEvent)>);
        ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

        // --- onerror ---
        let state_err = self.state;
        let on_error = Closure::wrap(Box::new(move |_e: web_sys::ErrorEvent| {
            web_sys::console::error_1(&"[Relay] WebSocket error".into());
            state_err.set(ConnectionState::Error);
        }) as Box<dyn FnMut(web_sys::ErrorEvent)>);
        ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));

        // --- onclose ---
        let self_clone = self.clone();
        let on_close = Closure::wrap(Box::new(move |_e: web_sys::CloseEvent| {
            web_sys::console::log_1(&"[Relay] WebSocket closed".into());
            let current = self_clone.state.get_untracked();
            if current != ConnectionState::Disconnected {
                self_clone.state.set(ConnectionState::Reconnecting);
                self_clone.schedule_reconnect();
            }
        }) as Box<dyn FnMut(web_sys::CloseEvent)>);
        ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

        // Store everything
        self.with_inner(|rc| {
            let mut inner = rc.borrow_mut();
            inner.ws = Some(ws);
            inner._on_open = Some(on_open);
            inner._on_message = Some(on_message);
            inner._on_error = Some(on_error);
            inner._on_close = Some(on_close);
        });
    }

    /// Disconnect from the relay and stop reconnecting.
    pub fn disconnect(&self) {
        self.state.set(ConnectionState::Disconnected);
        self.with_inner(|rc| {
            let mut inner = rc.borrow_mut();
            if let Some(ws) = inner.ws.take() {
                // Detach handlers before dropping the closures so the closing
                // socket cannot invoke a freed Closure on a later tick.
                ws.set_onopen(None);
                ws.set_onmessage(None);
                ws.set_onerror(None);
                ws.set_onclose(None);
                let _ = ws.close();
            }
            inner._on_open = None;
            inner._on_message = None;
            inner._on_error = None;
            inner._on_close = None;
            // NOTE: subscriptions are preserved so they can be replayed on reconnect.
            inner.pending_publishes.clear();
            inner.pending_messages.clear();
        });
    }

    /// Subscribe to events matching the given filters.
    /// Returns a subscription ID that can be used to unsubscribe.
    pub fn subscribe(
        &self,
        filters: Vec<Filter>,
        on_event: EventCallback,
        on_eose: Option<EoseCallback>,
    ) -> String {
        let sub_id = self.with_inner(|rc| {
            let mut inner = rc.borrow_mut();
            inner.sub_counter += 1;
            let sub_id = format!("sub_{}", inner.sub_counter);
            inner.subscriptions.insert(
                sub_id.clone(),
                Subscription {
                    filters: filters.clone(),
                    on_event,
                    on_eose,
                },
            );
            sub_id
        });

        // Build REQ message: ["REQ", sub_id, filter1, filter2, ...]
        let mut req = vec![Value::String("REQ".into()), Value::String(sub_id.clone())];
        for filter in &filters {
            if let Ok(v) = serde_json::to_value(filter) {
                req.push(v);
            }
        }

        let msg = serde_json::to_string(&req).unwrap_or_default();
        self.send_raw(&msg);

        sub_id
    }

    /// Unsubscribe from a subscription by ID.
    pub fn unsubscribe(&self, sub_id: &str) {
        self.with_inner(|rc| {
            rc.borrow_mut().subscriptions.remove(sub_id);
        });

        let close_msg = serde_json::to_string(&vec![
            Value::String("CLOSE".into()),
            Value::String(sub_id.into()),
        ])
        .unwrap_or_default();
        self.send_raw(&close_msg);
    }

    /// Publish a signed event to the relay.
    pub fn publish(&self, event: &NostrEvent) {
        let msg = serde_json::json!(["EVENT", event]);
        let serialized = serde_json::to_string(&msg).unwrap_or_default();
        self.send_raw(&serialized);
    }

    /// Publish a signed event and invoke `on_ok` when the relay responds with OK.
    ///
    /// The callback receives `(accepted: bool, message: String)` matching the
    /// NIP-01 `["OK", event_id, accepted, message]` response.
    pub fn publish_with_ack(
        &self,
        event: &NostrEvent,
        on_ok: Option<PublishCallback>,
    ) -> Result<(), String> {
        let event_id = event.id.clone();
        self.with_inner(|rc| {
            rc.borrow_mut()
                .pending_publishes
                .insert(event_id, PendingPublish { on_ok });
        });
        let msg = serde_json::json!(["EVENT", event]);
        let serialized =
            serde_json::to_string(&msg).map_err(|e| format!("serialize error: {}", e))?;
        self.send_raw(&serialized);
        Ok(())
    }

    /// Send a raw string message to the WebSocket.
    fn send_raw(&self, msg: &str) {
        self.with_inner(|rc| {
            let mut inner = rc.borrow_mut();
            if let Some(ws) = &inner.ws {
                if ws.ready_state() == WebSocket::OPEN {
                    let _ = ws.send_with_str(msg);
                    return;
                }
            }
            inner.pending_messages.push(msg.to_string());
        });
    }

    /// Schedule a reconnect with exponential backoff.
    ///
    /// Uses `set_timeout_once` which properly drops the closure after execution,
    /// preventing memory leaks on repeated reconnect cycles (e.g. spotty mobile).
    fn schedule_reconnect(&self) {
        let attempts = self.with_inner(|rc| rc.borrow().reconnect_attempts);

        let delay = std::cmp::min(
            BASE_RECONNECT_DELAY_MS * 2u32.saturating_pow(attempts),
            MAX_RECONNECT_DELAY_MS,
        );

        self.with_inner(|rc| {
            rc.borrow_mut().reconnect_attempts = attempts + 1;
        });

        web_sys::console::log_1(
            &format!(
                "[Relay] Reconnecting in {}ms (attempt {})",
                delay,
                attempts + 1
            )
            .into(),
        );

        let self_clone = self.clone();
        crate::utils::set_timeout_once(
            move || {
                let current = self_clone.state.get_untracked();
                if current != ConnectionState::Disconnected && current != ConnectionState::Connected
                {
                    self_clone.connect();
                }
            },
            delay as i32,
        );
    }
}

/// Parse and route incoming relay messages to the appropriate subscription callbacks.
fn handle_relay_message(inner_rc: &Rc<RefCell<RelayInner>>, text: &str) {
    let parsed: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => {
            web_sys::console::warn_1(&format!("[Relay] Failed to parse message: {}", e).into());
            return;
        }
    };

    let arr = match parsed.as_array() {
        Some(a) => a,
        None => return,
    };

    if arr.is_empty() {
        return;
    }

    let msg_type = match arr[0].as_str() {
        Some(s) => s,
        None => return,
    };

    match msg_type {
        "EVENT" => {
            if arr.len() < 3 {
                return;
            }
            let sub_id = match arr[1].as_str() {
                Some(s) => s.to_string(),
                None => return,
            };
            let event: NostrEvent = match serde_json::from_value(arr[2].clone()) {
                Ok(e) => e,
                Err(e) => {
                    web_sys::console::warn_1(
                        &format!("[Relay] Failed to parse event: {}", e).into(),
                    );
                    return;
                }
            };

            {
                let mut inner = inner_rc.borrow_mut();
                if !inner.seen_events.insert(event.id.clone()) {
                    return;
                }
                if inner.seen_events.len() > 10_000 {
                    inner.seen_events.clear();
                }
            }

            let callback = {
                let inner = inner_rc.borrow();
                inner
                    .subscriptions
                    .get(&sub_id)
                    .map(|s| Rc::clone(&s.on_event))
            };
            if let Some(cb) = callback {
                cb(event);
            }
        }
        "EOSE" => {
            if arr.len() < 2 {
                return;
            }
            let sub_id = match arr[1].as_str() {
                Some(s) => s.to_string(),
                None => return,
            };

            let callback = {
                let inner = inner_rc.borrow();
                inner
                    .subscriptions
                    .get(&sub_id)
                    .and_then(|s| s.on_eose.as_ref().map(Rc::clone))
            };
            if let Some(cb) = callback {
                cb();
            }
        }
        "NOTICE" => {
            if arr.len() >= 2 {
                if let Some(notice) = arr[1].as_str() {
                    web_sys::console::warn_1(&format!("[Relay] NOTICE: {}", notice).into());

                    // Surface to the UI as a warn toast, rate-limiting rapid
                    // duplicates: the same notice text within 5s is dropped so a
                    // chatty relay cannot spam the user.
                    const NOTICE_DEDUP_WINDOW_MS: f64 = 5_000.0;
                    let now = js_sys::Date::now();
                    let mut inner = inner_rc.borrow_mut();
                    let is_dup = inner
                        .last_notice
                        .as_ref()
                        .map(|(prev, ts)| prev == notice && (now - *ts) < NOTICE_DEDUP_WINDOW_MS)
                        .unwrap_or(false);
                    if !is_dup {
                        inner.last_notice = Some((notice.to_string(), now));
                        inner.notice_seq = inner.notice_seq.wrapping_add(1);
                        let seq = inner.notice_seq;
                        let sink = inner.notice_sink;
                        drop(inner);
                        if let Some(sink) = sink {
                            sink.set(Some(RelayNotice {
                                message: notice.to_string(),
                                seq,
                            }));
                        }
                    }
                }
            }
        }
        "OK" => {
            if arr.len() >= 4 {
                let event_id = arr[1].as_str().unwrap_or("unknown");
                let accepted = arr[2].as_bool().unwrap_or(false);
                let message = arr[3].as_str().unwrap_or("");
                if !accepted {
                    web_sys::console::warn_1(
                        &format!("[Relay] Event {} rejected: {}", event_id, message).into(),
                    );
                }
                // Dispatch to pending publish callback if registered
                let callback = {
                    inner_rc
                        .borrow_mut()
                        .pending_publishes
                        .remove(event_id)
                        .and_then(|p| p.on_ok)
                };
                if let Some(cb) = callback {
                    cb(accepted, message.to_string());
                }
            }
        }
        "AUTH" => {
            if arr.len() >= 2 {
                if let Some(challenge) = arr[1].as_str() {
                    let inner = inner_rc.borrow();
                    let relay_url = inner.relay_url.clone();
                    let sync_signer = inner.auth_signer.clone();
                    let async_signer = inner.auth_signer_async.clone();
                    let ws = inner.ws.clone();
                    drop(inner);

                    let now = (js_sys::Date::now() / 1000.0) as u64;
                    let make_unsigned = |url: String, ch: &str| UnsignedEvent {
                        pubkey: String::new(),
                        created_at: now,
                        kind: 22242,
                        tags: vec![
                            vec!["relay".into(), url],
                            vec!["challenge".into(), ch.to_string()],
                        ],
                        content: String::new(),
                    };

                    let send_auth = |signed: &NostrEvent, ws: &Option<WebSocket>| {
                        if let Ok(msg) = serde_json::to_string(&serde_json::json!(["AUTH", signed]))
                        {
                            if let Some(ws) = ws {
                                let _ = ws.send_with_str(&msg);
                                web_sys::console::log_1(
                                    &"[Relay] NIP-42 AUTH response sent".into(),
                                );
                            }
                        }
                    };

                    // Replay all active subscriptions after AUTH so the relay
                    // re-evaluates them with the authenticated session: REQs
                    // opened before the NIP-42 handshake completed were zone-
                    // filtered as unauthenticated. Same-socket ordering means
                    // the relay processes AUTH before these re-REQs.
                    let replay_rc = inner_rc.clone();
                    let replay_subs = move |ws: &Option<WebSocket>| {
                        let inner = replay_rc.borrow();
                        if let Some(ws) = ws {
                            for (sub_id, sub) in inner.subscriptions.iter() {
                                let mut req = vec![
                                    serde_json::Value::String("REQ".into()),
                                    serde_json::Value::String(sub_id.clone()),
                                ];
                                for filter in &sub.filters {
                                    if let Ok(v) = serde_json::to_value(filter) {
                                        req.push(v);
                                    }
                                }
                                if let Ok(msg) = serde_json::to_string(&req) {
                                    let _ = ws.send_with_str(&msg);
                                }
                            }
                            web_sys::console::log_1(
                                &"[Relay] replayed subscriptions post-AUTH".into(),
                            );
                        }
                    };

                    if let Some(sign_fn) = sync_signer {
                        let unsigned = make_unsigned(relay_url, challenge);
                        if let Some(signed) = sign_fn(unsigned) {
                            send_auth(&signed, &ws);
                            replay_subs(&ws);
                        } else {
                            web_sys::console::warn_1(&"[Relay] AUTH sync signing failed".into());
                        }
                    } else if let Some(async_sign) = async_signer {
                        let unsigned = make_unsigned(relay_url, challenge);
                        wasm_bindgen_futures::spawn_local(async move {
                            if let Some(signed) = async_sign(unsigned).await {
                                send_auth(&signed, &ws);
                                replay_subs(&ws);
                            } else {
                                web_sys::console::warn_1(
                                    &"[Relay] AUTH async signing failed".into(),
                                );
                            }
                        });
                    } else {
                        web_sys::console::warn_1(
                            &"[Relay] AUTH challenge received but no signer registered".into(),
                        );
                    }
                }
            }
        }
        _ => {
            web_sys::console::log_1(
                &format!("[Relay] Unhandled message type: {}", msg_type).into(),
            );
        }
    }
}

/// Read the relay URL from the environment or fall back to the default.
fn get_relay_url() -> String {
    if let Some(window) = web_sys::window() {
        if let Ok(val) = js_sys::Reflect::get(&window, &"__ENV__".into()) {
            if !val.is_undefined() && !val.is_null() {
                if let Ok(url) = js_sys::Reflect::get(&val, &"VITE_RELAY_URL".into()) {
                    if let Some(s) = url.as_string() {
                        if !s.is_empty() {
                            return s;
                        }
                    }
                }
            }
        }
    }

    option_env!("VITE_RELAY_URL")
        .unwrap_or(DEFAULT_RELAY_URL)
        .to_string()
}
