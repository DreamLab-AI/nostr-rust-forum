//! Native transport for the probe suite: one NIP-42-authenticated relay
//! WebSocket and a NIP-98-signing HTTP client.
//!
//! Signing is `nostr_bbs_core::sign_event` and `nostr_bbs_core::nip98`; no
//! primitive is implemented here. The secret is held in a zeroising buffer and
//! never formatted.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use nostr_bbs_core::keys::signing_key_from_bytes;
use nostr_bbs_core::{nip98, sign_event, NostrEvent, UnsignedEvent};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::time::{timeout_at, Instant};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use zeroize::Zeroizing;

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

const OP_TIMEOUT: Duration = Duration::from_secs(30);
const CHALLENGE_WAIT: Duration = Duration::from_secs(5);
const KIND_AUTH: u64 = 22242;

/// The signing identity. Debug-printing it prints only the public key.
pub struct Identity {
    secret: Zeroizing<[u8; 32]>,
    pubkey: String,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("pubkey", &self.pubkey)
            .finish()
    }
}

impl Identity {
    /// Load a 64-hex secret from environment variable `var`. Errors name the
    /// variable, never the value.
    pub fn from_env(var: &str) -> Result<Self, String> {
        let raw = Zeroizing::new(
            std::env::var(var).map_err(|_| format!("{var} is not set in the environment"))?,
        );
        let mut secret = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(raw.trim(), secret.as_mut())
            .map_err(|_| format!("{var} is not 64 hex characters"))?;
        let sk =
            signing_key_from_bytes(&secret).map_err(|_| format!("{var} is not a valid key"))?;
        let pubkey = hex::encode(sk.verifying_key().to_bytes());
        Ok(Self { secret, pubkey })
    }

    /// Lower-case hex x-only public key.
    pub fn pubkey(&self) -> &str {
        &self.pubkey
    }

    /// Sign `unsigned` (whose `pubkey` must be this identity's).
    pub fn sign(&self, unsigned: UnsignedEvent) -> Result<NostrEvent, String> {
        let sk = signing_key_from_bytes(&self.secret).map_err(|e| e.to_string())?;
        sign_event(unsigned, &sk).map_err(|e| e.to_string())
    }

    fn nip98(&self, url: &str, method: &str, body: Option<&[u8]>) -> Result<String, String> {
        nip98::sign_request_header(&self.secret, url, method, body).map_err(|e| e.to_string())
    }
}

/// Unix seconds now.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// An HTTP answer: status and body (JSON when it parses, else a string).
#[derive(Debug, Clone)]
pub struct HttpAnswer {
    pub status: u16,
    pub body: Value,
}

impl HttpAnswer {
    pub fn to_json(&self) -> Value {
        json!({"status": self.status, "body": self.body})
    }
}

/// HTTP client for the relay's NIP-11 document and the auth API.
pub struct Http {
    client: reqwest::Client,
}

impl Http {
    pub fn new() -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(OP_TIMEOUT)
            .user_agent(concat!(
                "nostr-bbs-governance-probe/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { client })
    }

    async fn answer(resp: reqwest::Response) -> Result<HttpAnswer, String> {
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| e.to_string())?;
        let body = serde_json::from_str(&text).unwrap_or(Value::String(text));
        Ok(HttpAnswer { status, body })
    }

    /// `GET url` with `Accept: application/nostr+json` (NIP-11).
    pub async fn nip11(&self, url: &str) -> Result<HttpAnswer, String> {
        let resp = self
            .client
            .get(url)
            .header("Accept", "application/nostr+json")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        Self::answer(resp).await
    }

    /// Unsigned `GET url` — what an anonymous reader is answered.
    pub async fn get_plain(&self, url: &str) -> Result<HttpAnswer, String> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        Self::answer(resp).await
    }

    /// NIP-98-signed `GET url`.
    pub async fn get_signed(&self, id: &Identity, url: &str) -> Result<HttpAnswer, String> {
        let auth = id.nip98(url, "GET", None)?;
        let resp = self
            .client
            .get(url)
            .header("Authorization", auth)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        Self::answer(resp).await
    }

    /// NIP-98-signed `POST url` with a JSON body (the token binds its hash).
    pub async fn post_signed(
        &self,
        id: &Identity,
        url: &str,
        body: &Value,
    ) -> Result<HttpAnswer, String> {
        let bytes = body.to_string().into_bytes();
        let auth = id.nip98(url, "POST", Some(&bytes))?;
        let resp = self
            .client
            .post(url)
            .header("Authorization", auth)
            .header("Content-Type", "application/json")
            .body(bytes)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        Self::answer(resp).await
    }
}

/// A relay `OK` answer.
#[derive(Debug, Clone)]
pub struct Ok_ {
    pub accepted: bool,
    pub message: String,
}

/// A NIP-42-authenticated relay session.
pub struct RelaySession {
    url: String,
    ws: Ws,
    next_sub: u64,
    pub authenticated: bool,
}

impl RelaySession {
    /// Connect and answer the relay's AUTH challenge, if any.
    pub async fn connect(url: &str, id: &Identity) -> Result<Self, String> {
        let (ws, _) = connect_async(url)
            .await
            .map_err(|e| format!("connect {url}: {e}"))?;
        let mut s = Self {
            url: url.to_string(),
            ws,
            next_sub: 0,
            authenticated: false,
        };
        let deadline = Instant::now() + CHALLENGE_WAIT;
        if let Ok(frame) = timeout_at(deadline, s.recv()).await {
            if let Some(msg) = frame? {
                if msg.first().and_then(Value::as_str) == Some("AUTH") {
                    if let Some(ch) = msg.get(1).and_then(Value::as_str) {
                        let ch = ch.to_string();
                        let auth = s.auth_event(id, &ch)?;
                        let auth_id = auth.id.clone();
                        s.send(json!(["AUTH", auth])).await?;
                        let ok = s.await_ok(&auth_id, id).await?;
                        if !ok.accepted {
                            return Err(format!("NIP-42 AUTH refused: {}", ok.message));
                        }
                        s.authenticated = true;
                    }
                }
            }
        }
        Ok(s)
    }

    fn auth_event(&self, id: &Identity, challenge: &str) -> Result<NostrEvent, String> {
        id.sign(UnsignedEvent {
            pubkey: id.pubkey().to_string(),
            created_at: now_secs(),
            kind: KIND_AUTH,
            tags: vec![
                vec!["relay".into(), self.url.clone()],
                vec!["challenge".into(), challenge.to_string()],
            ],
            content: String::new(),
        })
    }

    async fn send(&mut self, v: Value) -> Result<(), String> {
        self.ws
            .send(Message::Text(v.to_string()))
            .await
            .map_err(|e| e.to_string())
    }

    /// Next JSON-array frame; `None` when the socket closed.
    async fn recv(&mut self) -> Result<Option<Vec<Value>>, String> {
        loop {
            match self.ws.next().await {
                None | Some(Ok(Message::Close(_))) => return Ok(None),
                Some(Err(e)) => return Err(e.to_string()),
                Some(Ok(Message::Text(t))) => {
                    if let Ok(Value::Array(a)) = serde_json::from_str::<Value>(&t) {
                        return Ok(Some(a));
                    }
                }
                Some(Ok(_)) => {}
            }
        }
    }

    /// Wait for `["OK", event_id, …]`, answering any re-issued AUTH.
    async fn await_ok(&mut self, event_id: &str, id: &Identity) -> Result<Ok_, String> {
        let deadline = Instant::now() + OP_TIMEOUT;
        loop {
            let msg = timeout_at(deadline, self.recv())
                .await
                .map_err(|_| format!("timed out waiting for OK {event_id}"))??
                .ok_or("relay closed the connection")?;
            match msg.first().and_then(Value::as_str) {
                Some("OK") if msg.get(1).and_then(Value::as_str) == Some(event_id) => {
                    return Ok(Ok_ {
                        accepted: msg.get(2).and_then(Value::as_bool).unwrap_or(false),
                        message: msg
                            .get(3)
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                    });
                }
                Some("AUTH") => {
                    if let Some(ch) = msg.get(1).and_then(Value::as_str) {
                        let ch = ch.to_string();
                        let auth = self.auth_event(id, &ch)?;
                        self.send(json!(["AUTH", auth])).await?;
                    }
                }
                _ => {}
            }
        }
    }

    /// Publish a signed event and return the relay's OK.
    pub async fn publish(&mut self, ev: &NostrEvent, id: &Identity) -> Result<Ok_, String> {
        self.send(json!(["EVENT", ev])).await?;
        self.await_ok(&ev.id, id).await
    }

    /// Run one REQ to EOSE and return the events. A `CLOSED` is an error.
    pub async fn query(&mut self, filter: Value) -> Result<Vec<NostrEvent>, String> {
        self.next_sub += 1;
        let sub = format!("m4p{}", self.next_sub);
        self.send(json!(["REQ", sub, filter])).await?;
        let deadline = Instant::now() + OP_TIMEOUT;
        let mut out = Vec::new();
        loop {
            let msg = timeout_at(deadline, self.recv())
                .await
                .map_err(|_| format!("timed out waiting for EOSE {sub}"))??
                .ok_or("relay closed the connection")?;
            let same = msg.get(1).and_then(Value::as_str) == Some(sub.as_str());
            match msg.first().and_then(Value::as_str) {
                Some("EVENT") if same => {
                    if let Some(ev) = msg
                        .get(2)
                        .and_then(|v| serde_json::from_value::<NostrEvent>(v.clone()).ok())
                    {
                        out.push(ev);
                    }
                }
                Some("EOSE") if same => {
                    self.send(json!(["CLOSE", sub])).await?;
                    return Ok(out);
                }
                Some("CLOSED") if same => {
                    return Err(format!(
                        "CLOSED: {}",
                        msg.get(2).and_then(Value::as_str).unwrap_or_default()
                    ));
                }
                _ => {}
            }
        }
    }
}
