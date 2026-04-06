//! Nostr Relay Durable Object (NIP-01 WebSocket relay).
//!
//! Handles WebSocket connections, NIP-01 message protocol (EVENT/REQ/CLOSE),
//! event validation, Schnorr signature verification via `nostr_core`, whitelist
//! gating, and subscription-based event broadcasting.
//!
//! Uses D1 for persistent event storage and in-memory maps for per-connection
//! subscriptions and rate limiting.
//!
//! The `DurableObject` trait methods take `&self`, so all mutable state is
//! wrapped in `RefCell` for interior mutability. This is safe because the DO
//! runs single-threaded in a V8 isolate.
//!
//! ## Module structure
//!
//! - `session` -- Session lifecycle (find, recover, remove, idle alarm)
//! - `filter` -- NIP-01 filter type, SQL query builder, in-memory matching
//! - `broadcast` -- Event broadcasting, NIP-16 treatment, wire protocol, rate limiting
//! - `nip_handlers` -- NIP-01/09/42/45 protocol handlers, event storage, whitelist

mod broadcast;
mod filter;
mod nip_handlers;
mod session;
mod storage;

use std::cell::RefCell;
use std::collections::HashMap;

use nostr_core::event::NostrEvent;
use worker::*;

use session::{generate_challenge, SessionInfo};

/// Maximum WebSocket connections per IP address.
const MAX_CONNECTIONS_PER_IP: u32 = 20;

// ---------------------------------------------------------------------------
// Durable Object
// ---------------------------------------------------------------------------

#[durable_object]
pub struct NostrRelayDO {
    pub(crate) state: State,
    pub(crate) env: Env,
    pub(crate) sessions: RefCell<HashMap<u64, SessionInfo>>,
    pub(crate) next_session_id: RefCell<u64>,
    pub(crate) rate_limits: RefCell<HashMap<String, Vec<f64>>>,
    pub(crate) connection_counts: RefCell<HashMap<String, u32>>,
}

impl DurableObject for NostrRelayDO {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            sessions: RefCell::new(HashMap::new()),
            next_session_id: RefCell::new(1),
            rate_limits: RefCell::new(HashMap::new()),
            connection_counts: RefCell::new(HashMap::new()),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        if req.headers().get("Upgrade")?.as_deref() != Some("websocket") {
            return Response::error("Expected WebSocket", 426);
        }

        let ip = req
            .headers()
            .get("CF-Connecting-IP")?
            .unwrap_or_else(|| "unknown".to_string());

        // Connection rate limit
        {
            let counts = self.connection_counts.borrow();
            let conn_count = counts.get(&ip).copied().unwrap_or(0);
            if conn_count >= MAX_CONNECTIONS_PER_IP {
                return Response::error("Too many connections", 429);
            }
        }

        let pair = WebSocketPair::new()?;
        let server = pair.server;
        let client = pair.client;

        let session_id = {
            let mut id = self.next_session_id.borrow_mut();
            let current = *id;
            *id += 1;
            current
        };

        // Tag the WebSocket so session data survives DO hibernation.
        // Tags are persisted by the runtime even when in-memory state is lost.
        self.state.accept_websocket_with_tags(
            &server,
            &[
                &format!("sid:{session_id}"),
                &format!("ip:{ip}"),
            ],
        );

        let challenge = generate_challenge(session_id);
        {
            let mut sessions = self.sessions.borrow_mut();
            sessions.insert(
                session_id,
                SessionInfo {
                    ws: server,
                    ip: ip.clone(),
                    subscriptions: HashMap::new(),
                    authed_pubkey: None,
                    challenge: challenge.clone(),
                },
            );
        }

        {
            let mut counts = self.connection_counts.borrow_mut();
            let count = counts.get(&ip).copied().unwrap_or(0);
            counts.insert(ip, count + 1);
        }

        // NIP-42: Send AUTH challenge to the newly connected client
        {
            let sessions = self.sessions.borrow();
            if let Some(session) = sessions.get(&session_id) {
                Self::send_auth(&session.ws, &challenge);
            }
        }

        Response::from_websocket(client)
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let msg = match message {
            WebSocketIncomingMessage::String(s) => s,
            WebSocketIncomingMessage::Binary(b) => String::from_utf8(b).unwrap_or_default(),
        };

        // Try to find the session in memory. If the DO woke from hibernation,
        // the in-memory sessions map is empty -- recover from WebSocket tags.
        let session_id = match self.find_session_id(&ws) {
            Some(id) => id,
            None => self.recover_session(&ws).await,
        };

        let ip = self.sessions.borrow()
            .get(&session_id)
            .map(|s| s.ip.clone())
            .unwrap_or_else(|| "unknown".into());

        let parsed: serde_json::Value = match serde_json::from_str(&msg) {
            Ok(v) => v,
            Err(_) => {
                Self::send_notice(&ws, "Invalid JSON");
                return Ok(());
            }
        };

        let arr = match parsed.as_array() {
            Some(a) if a.len() >= 2 => a.clone(),
            _ => {
                Self::send_notice(&ws, "Invalid message format");
                return Ok(());
            }
        };

        let msg_type = match arr[0].as_str() {
            Some(t) => t.to_string(),
            None => {
                Self::send_notice(&ws, "Invalid message format");
                return Ok(());
            }
        };

        match msg_type.as_str() {
            "EVENT" => {
                let event: NostrEvent = match serde_json::from_value(arr[1].clone()) {
                    Ok(e) => e,
                    Err(_) => {
                        Self::send_notice(&ws, "Invalid event");
                        return Ok(());
                    }
                };
                self.handle_event(&ws, &ip, event).await;
            }
            "REQ" => {
                let sub_id = match arr[1].as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        Self::send_notice(&ws, "Invalid subscription ID");
                        return Ok(());
                    }
                };
                let filters: Vec<filter::NostrFilter> = arr[2..]
                    .iter()
                    .filter_map(|v| serde_json::from_value(v.clone()).ok())
                    .collect();
                self.handle_req(session_id, &sub_id, filters).await;
            }
            "CLOSE" => {
                if let Some(sub_id) = arr[1].as_str() {
                    self.handle_close(session_id, sub_id).await;
                }
            }
            "AUTH" => {
                let auth_event: NostrEvent = match serde_json::from_value(arr[1].clone()) {
                    Ok(e) => e,
                    Err(_) => {
                        Self::send_notice(&ws, "Invalid auth event");
                        return Ok(());
                    }
                };
                self.handle_auth(session_id, &ws, auth_event).await;
            }
            "COUNT" => {
                let sub_id = match arr[1].as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        Self::send_notice(&ws, "Invalid subscription ID");
                        return Ok(());
                    }
                };
                let filters: Vec<filter::NostrFilter> = arr[2..]
                    .iter()
                    .filter_map(|v| serde_json::from_value(v.clone()).ok())
                    .collect();
                self.handle_count(&ws, &sub_id, filters).await;
            }
            _ => {
                Self::send_notice(&ws, &format!("Unknown message type: {msg_type}"));
            }
        }

        Ok(())
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        self.remove_session(&ws).await;
        Ok(())
    }

    async fn websocket_error(&self, ws: WebSocket, _error: Error) -> Result<()> {
        self.remove_session(&ws).await;
        Ok(())
    }

    /// Alarm handler: if no sessions remain, clear in-memory state so the DO
    /// can be evicted. If sessions exist (a new connection arrived during the
    /// timeout window), the alarm is a no-op.
    async fn alarm(&self) -> Result<Response> {
        if self.sessions.borrow().is_empty() {
            self.rate_limits.borrow_mut().clear();
            self.connection_counts.borrow_mut().clear();
            console_log!("[RelayDO] Idle timeout -- cleared in-memory state for eviction");
        }
        Response::ok("ok")
    }
}
