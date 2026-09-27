//! Native [`Relay`] implementation: one NIP-42-authenticated WebSocket plus
//! the relay worker's HTTP API on the same origin.
//!
//! Protocol facts, from `nostr-bbs-relay-worker`:
//! - the relay sends `["AUTH", <challenge>]` on connect (`relay_do/mod.rs`),
//!   and may re-issue one after hibernation (`relay_do/session.rs`); both are
//!   answered with a kind-22242 event tagged `relay` and `challenge`;
//! - `OK` is `["OK", <id>, <bool>, <message>]` (`relay_do/broadcast.rs`);
//! - the per-IP frame limit defaults to 30 per second and a refused frame is
//!   answered with `NOTICE "rate limit exceeded"` and dropped, so frames are
//!   paced and a refused frame is resent after a pause;
//! - NIP-98 admin routes verify the token's `u` tag against the full request
//!   URL (`lib.rs`, `auth::require_nip98_admin`).

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use nostr_bbs_core::keys::SecretKey;
use nostr_bbs_core::{sign_event, NostrEvent, UnsignedEvent};
use nostr_bbs_zone_migrate::relay::{DeleteOutcome, Filter, PublishOutcome, Relay, RelayError};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout_at, Instant};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Answer deadline for one REQ or EVENT.
const OP_TIMEOUT: Duration = Duration::from_secs(30);
/// How long to wait for the relay's AUTH challenge after connecting.
const CHALLENGE_WAIT: Duration = Duration::from_secs(5);
/// Minimum gap between frames: ~16/s, well inside the default 30/s.
const FRAME_GAP: Duration = Duration::from_millis(60);
/// Pause after `NOTICE "rate limit exceeded"` before resending.
const RATE_LIMIT_PAUSE: Duration = Duration::from_millis(1500);
/// Attempts per operation (rate-limit resends and one reconnect).
const ATTEMPTS: usize = 4;

/// NIP-42 AUTH event kind.
const KIND_AUTH: u64 = 22242;

/// The native relay client used by the binary.
pub struct NetRelay {
    url: String,
    origin: String,
    sk: SecretKey,
    ws: Option<Ws>,
    http: reqwest::Client,
    next_sub: u64,
    last_frame: Option<Instant>,
    authed: bool,
}

enum Frame {
    Json(Vec<Value>),
    Closed,
}

impl NetRelay {
    /// Connect to `url` as `sk` and complete NIP-42 AUTH if challenged.
    pub async fn connect(url: &str, origin: &str, sk: &SecretKey) -> Result<Self, RelayError> {
        let http = reqwest::Client::builder()
            .timeout(OP_TIMEOUT)
            .user_agent(concat!(
                "nostr-bbs-zone-migrate/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(|e| RelayError::Transport(e.to_string()))?;
        let mut relay = Self {
            url: url.to_string(),
            origin: origin.to_string(),
            sk: SecretKey::from_bytes(*sk.as_bytes())
                .map_err(|_| RelayError::Transport("invalid key".into()))?,
            ws: None,
            http,
            next_sub: 0,
            last_frame: None,
            authed: false,
        };
        relay.open().await?;
        Ok(relay)
    }

    /// Whether the relay challenged and accepted NIP-42 AUTH.
    pub fn authenticated(&self) -> bool {
        self.authed
    }

    async fn open(&mut self) -> Result<(), RelayError> {
        let (ws, _) = connect_async(self.url.as_str())
            .await
            .map_err(|e| RelayError::Transport(format!("connect {}: {e}", self.url)))?;
        self.ws = Some(ws);
        self.authed = false;
        let deadline = Instant::now() + CHALLENGE_WAIT;
        // Auth mode `allowlist` sends no challenge; carry on unauthenticated.
        let Ok(frame) = timeout_at(deadline, self.recv()).await else {
            return Ok(());
        };
        if let Frame::Json(msg) = frame? {
            if msg.first().and_then(Value::as_str) == Some("AUTH") {
                if let Some(challenge) = msg.get(1).and_then(Value::as_str) {
                    let challenge = challenge.to_string();
                    let auth_id = self.send_auth(&challenge).await?;
                    self.await_auth_ok(&auth_id).await?;
                }
            }
        }
        Ok(())
    }

    async fn send_auth(&mut self, challenge: &str) -> Result<String, RelayError> {
        let signing_key = nostr_bbs_core::keys::signing_key_from_bytes(self.sk.as_bytes())
            .map_err(|e| RelayError::Transport(e.to_string()))?;
        let ev = sign_event(
            UnsignedEvent {
                pubkey: self.sk.public_key().to_hex(),
                created_at: now_secs(),
                kind: KIND_AUTH,
                tags: vec![
                    vec!["relay".into(), self.url.clone()],
                    vec!["challenge".into(), challenge.to_string()],
                ],
                content: String::new(),
            },
            &signing_key,
        )
        .map_err(|e| RelayError::Transport(e.to_string()))?;
        self.send(json!(["AUTH", ev])).await?;
        Ok(ev.id)
    }

    async fn await_auth_ok(&mut self, auth_id: &str) -> Result<(), RelayError> {
        let deadline = Instant::now() + OP_TIMEOUT;
        loop {
            let frame = timeout_at(deadline, self.recv())
                .await
                .map_err(|_| RelayError::Timeout("AUTH OK".into()))??;
            let Frame::Json(msg) = frame else {
                return Err(RelayError::Transport("closed during AUTH".into()));
            };
            if is_ok_for(&msg, auth_id) {
                if msg.get(2).and_then(Value::as_bool) == Some(true) {
                    self.authed = true;
                    return Ok(());
                }
                let why = msg.get(3).and_then(Value::as_str).unwrap_or_default();
                return Err(RelayError::Protocol(format!("NIP-42 AUTH refused: {why}")));
            }
        }
    }

    async fn send(&mut self, msg: Value) -> Result<(), RelayError> {
        if let Some(last) = self.last_frame {
            let next = last + FRAME_GAP;
            if next > Instant::now() {
                tokio::time::sleep_until(next).await;
            }
        }
        self.last_frame = Some(Instant::now());
        let ws = self
            .ws
            .as_mut()
            .ok_or_else(|| RelayError::Transport("not connected".into()))?;
        ws.send(Message::Text(msg.to_string()))
            .await
            .map_err(|e| RelayError::Transport(e.to_string()))
    }

    async fn recv(&mut self) -> Result<Frame, RelayError> {
        loop {
            let ws = self
                .ws
                .as_mut()
                .ok_or_else(|| RelayError::Transport("not connected".into()))?;
            match ws.next().await {
                None => return Ok(Frame::Closed),
                Some(Err(e)) => return Err(RelayError::Transport(e.to_string())),
                Some(Ok(Message::Text(text))) => {
                    if let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(&text) {
                        return Ok(Frame::Json(arr));
                    }
                }
                Some(Ok(Message::Close(_))) => return Ok(Frame::Closed),
                Some(Ok(_)) => {}
            }
        }
    }

    /// Answer an AUTH re-issued mid-session (after relay hibernation).
    async fn handle_unsolicited(&mut self, msg: &[Value]) -> Result<(), RelayError> {
        if msg.first().and_then(Value::as_str) == Some("AUTH") {
            if let Some(challenge) = msg.get(1).and_then(Value::as_str) {
                let challenge = challenge.to_string();
                self.send_auth(&challenge).await?;
            }
        }
        Ok(())
    }

    async fn reconnect(&mut self) -> Result<(), RelayError> {
        if let Some(mut ws) = self.ws.take() {
            let _ = ws.close(None).await;
        }
        self.open().await
    }

    async fn query_once(
        &mut self,
        filter: &Filter,
    ) -> Result<Attempt<Vec<NostrEvent>>, RelayError> {
        self.next_sub += 1;
        let sub = format!("zm{}", self.next_sub);
        self.send(json!(["REQ", sub, filter])).await?;
        let deadline = Instant::now() + OP_TIMEOUT;
        let mut events = Vec::new();
        loop {
            let frame = timeout_at(deadline, self.recv())
                .await
                .map_err(|_| RelayError::Timeout(format!("EOSE for {sub}")))??;
            let Frame::Json(msg) = frame else {
                return Ok(Attempt::Reconnect);
            };
            match msg.first().and_then(Value::as_str) {
                Some("EVENT") if msg.get(1).and_then(Value::as_str) == Some(sub.as_str()) => {
                    if let Some(ev) = msg
                        .get(2)
                        .and_then(|v| serde_json::from_value::<NostrEvent>(v.clone()).ok())
                    {
                        events.push(ev);
                    }
                }
                Some("EOSE") if msg.get(1).and_then(Value::as_str) == Some(sub.as_str()) => {
                    self.send(json!(["CLOSE", sub])).await?;
                    return Ok(Attempt::Done(events));
                }
                Some("CLOSED") if msg.get(1).and_then(Value::as_str) == Some(sub.as_str()) => {
                    let why = msg.get(2).and_then(Value::as_str).unwrap_or_default();
                    return Err(RelayError::Closed(why.to_string()));
                }
                Some("NOTICE") if is_rate_limit(&msg) => return Ok(Attempt::RateLimited),
                Some("NOTICE") => {
                    let why = msg.get(1).and_then(Value::as_str).unwrap_or_default();
                    // A REQ the relay refuses outright is answered by NOTICE
                    // alone (e.g. "too many subscriptions"); surface it.
                    return Err(RelayError::Protocol(format!("relay notice: {why}")));
                }
                _ => self.handle_unsolicited(&msg).await?,
            }
        }
    }

    async fn publish_once(
        &mut self,
        event: &NostrEvent,
    ) -> Result<Attempt<PublishOutcome>, RelayError> {
        self.send(json!(["EVENT", event])).await?;
        let deadline = Instant::now() + OP_TIMEOUT;
        loop {
            let frame = timeout_at(deadline, self.recv())
                .await
                .map_err(|_| RelayError::Timeout(format!("OK for {}", event.id)))??;
            let Frame::Json(msg) = frame else {
                return Ok(Attempt::Reconnect);
            };
            if is_ok_for(&msg, &event.id) {
                return Ok(Attempt::Done(PublishOutcome {
                    accepted: msg.get(2).and_then(Value::as_bool).unwrap_or(false),
                    message: msg
                        .get(3)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                }));
            }
            if msg.first().and_then(Value::as_str) == Some("NOTICE") && is_rate_limit(&msg) {
                return Ok(Attempt::RateLimited);
            }
            self.handle_unsolicited(&msg).await?;
        }
    }
}

enum Attempt<T> {
    Done(T),
    RateLimited,
    Reconnect,
}

/// Retry an operation on rate limiting and once on a dropped connection.
macro_rules! with_retries {
    ($self:ident, $op:expr, $what:expr) => {{
        let mut reconnected = false;
        let mut result = Err(RelayError::Transport(format!("{} gave up", $what)));
        for _ in 0..ATTEMPTS {
            let attempt = match $op.await {
                Ok(a) => a,
                Err(RelayError::Transport(e)) if !reconnected => {
                    eprintln!("relay connection lost ({e}); reconnecting");
                    reconnected = true;
                    $self.reconnect().await?;
                    continue;
                }
                Err(e) => {
                    result = Err(e);
                    break;
                }
            };
            match attempt {
                Attempt::Done(v) => {
                    result = Ok(v);
                    break;
                }
                Attempt::RateLimited => {
                    eprintln!("relay rate limit hit; pausing");
                    sleep(RATE_LIMIT_PAUSE).await;
                }
                Attempt::Reconnect if !reconnected => {
                    eprintln!("relay closed the connection; reconnecting");
                    reconnected = true;
                    $self.reconnect().await?;
                }
                Attempt::Reconnect => {
                    result = Err(RelayError::Transport("relay closed the connection".into()));
                    break;
                }
            }
        }
        result
    }};
}

impl Relay for NetRelay {
    async fn query(&mut self, filter: &Filter) -> Result<Vec<NostrEvent>, RelayError> {
        with_retries!(self, self.query_once(filter), "REQ")
    }

    async fn publish(&mut self, event: &NostrEvent) -> Result<PublishOutcome, RelayError> {
        // Re-sending an event the relay already stored is answered OK true
        // ("duplicate:"), so a resend after a lost OK is safe.
        with_retries!(self, self.publish_once(event), "EVENT")
    }

    async fn is_admin(&mut self, pubkey: &str) -> Result<bool, RelayError> {
        let url = format!("{}/api/check-whitelist?pubkey={pubkey}", self.origin);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| RelayError::Transport(e.to_string()))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| RelayError::Transport(e.to_string()))?;
        if !status.is_success() {
            return Err(RelayError::Http {
                status: status.as_u16(),
                body,
            });
        }
        let v: Value =
            serde_json::from_str(&body).map_err(|e| RelayError::Protocol(e.to_string()))?;
        v.get("isAdmin")
            .and_then(Value::as_bool)
            .ok_or_else(|| RelayError::Protocol("check-whitelist answer has no isAdmin".into()))
    }

    async fn delete_events(
        &mut self,
        ids: &[String],
        reason: &str,
    ) -> Result<DeleteOutcome, RelayError> {
        let url = format!("{}/api/admin/events/delete", self.origin);
        let body = serde_json::to_vec(&json!({ "ids": ids, "reason": reason }))
            .map_err(|e| RelayError::Protocol(e.to_string()))?;
        let auth = nostr_bbs_core::nip98::sign_request_header(
            self.sk.as_bytes(),
            &url,
            "POST",
            Some(&body),
        )
        .map_err(|e| RelayError::Transport(format!("NIP-98 signing failed: {e}")))?;
        let resp = self
            .http
            .post(&url)
            .header("Authorization", auth)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| RelayError::Transport(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| RelayError::Transport(e.to_string()))?;
        if !status.is_success() {
            return Err(RelayError::Http {
                status: status.as_u16(),
                body: text,
            });
        }
        serde_json::from_str(&text).map_err(|e| RelayError::Protocol(format!("{e}: {text}")))
    }
}

fn is_ok_for(msg: &[Value], id: &str) -> bool {
    msg.first().and_then(Value::as_str) == Some("OK")
        && msg.get(1).and_then(Value::as_str) == Some(id)
}

fn is_rate_limit(msg: &[Value]) -> bool {
    msg.get(1)
        .and_then(Value::as_str)
        .is_some_and(|m| m.contains("rate limit"))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
