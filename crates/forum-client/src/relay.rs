//! WebSocket relay connection manager for NIP-01 Nostr protocol.
//!
//! Manages a single WebSocket connection to the Nostr BBS relay, handling
//! subscriptions, event parsing, publishing, auto-reconnect with exponential
//! backoff, and connection state as a reactive Leptos signal.
//!
//! Uses `SendWrapper` to satisfy `Send + Sync` bounds required by Leptos
//! context in CSR mode. All access is single-threaded on the WASM main
//! thread, so this is safe.

use leptos::prelude::*;
use nostr_core::NostrEvent;
use send_wrapper::SendWrapper;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use web_sys::WebSocket;

/// Default relay URL when VITE_RELAY_URL is not set.
const DEFAULT_RELAY_URL: &str = "wss://your-relay.your-subdomain.workers.dev";

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

/// Internal mutable state for the relay connection.
struct RelayInner {
    ws: Option<WebSocket>,
    subscriptions: HashMap<String, Subscription>,
    pending_publishes: HashMap<String, PendingPublish>,
    sub_counter: u32,
    reconnect_attempts: u32,
    pending_messages: Vec<String>,
    relay_url: String,
    _on_open: Option<Closure<dyn FnMut()>>,
    _on_message: Option<Closure<dyn FnMut(web_sys::MessageEvent)>>,
    _on_error: Option<Closure<dyn FnMut(web_sys::ErrorEvent)>>,
    _on_close: Option<Closure<dyn FnMut(web_sys::CloseEvent)>>,
}

/// Thread-safe wrapper around the relay inner state.
/// `SendWrapper` asserts single-thread access at runtime, which is
/// guaranteed in WASM.
type SharedInner = SendWrapper<Rc<RefCell<RelayInner>>>;

/// Relay connection manager. Provided as Leptos context so any component
/// can subscribe to events or publish.
#[derive(Clone)]
pub struct RelayConnection {
    inner: SharedInner,
    state: RwSignal<ConnectionState>,
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
            _on_open: None,
            _on_message: None,
            _on_error: None,
            _on_close: None,
        }));
        Self {
            inner: SendWrapper::new(inner),
            state: RwSignal::new(ConnectionState::Disconnected),
        }
    }

    /// Get the reactive connection state signal.
    pub fn connection_state(&self) -> RwSignal<ConnectionState> {
        self.state
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
        // Close existing connection
        self.with_inner(|rc| {
            let mut inner = rc.borrow_mut();
            if let Some(ws) = inner.ws.take() {
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
