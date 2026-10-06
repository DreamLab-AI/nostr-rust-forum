//! One NIP-42-authenticated WebSocket to the forum relay, kept open: the
//! house subscribes to gift wraps addressed to it and publishes its own.
//!
//! Protocol facts, from `nostr-bbs-relay-worker`: the relay sends
//! `["AUTH", <challenge>]` on connect and may re-issue one after
//! hibernation; both are answered with a kind-22242 event tagged `relay` and
//! `challenge`. Reads of kind 1059 are gated on the authenticated pubkey
//! matching the wrap's `p` tag, so the house must be authenticated before
//! its REQ. `OK` is `["OK", <id>, <bool>, <message>]`. Frames are paced
//! under the relay's per-IP limit.
//!
//! A socket can outlive the relay behind it: after a worker redeploy the
//! connection has been seen to stay open for hours with nothing on it, the
//! house deaf to every member. So a quiet connection is probed with a REQ
//! the relay must answer (an `EOSE`), and one that stays silent through the
//! probe is treated as closed, which sends the runner round to reconnect.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use nostr_bbs_core::keys::signing_key_from_bytes;
use nostr_bbs_core::{sign_event, NostrEvent, UnsignedEvent};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::time::{timeout, Instant};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// NIP-42 AUTH event kind.
const KIND_AUTH: u64 = 22242;
/// How long to wait for the relay's AUTH challenge after connecting.
const CHALLENGE_WAIT: Duration = Duration::from_secs(5);
/// How long to wait for the AUTH `OK`.
const AUTH_WAIT: Duration = Duration::from_secs(20);
/// Minimum gap between frames: ~16/s, inside the default 30/s.
const FRAME_GAP: Duration = Duration::from_millis(60);
/// The subscription id for the house's inbox.
pub const SUB_ID: &str = "citizen-inbox";
/// The subscription id of the liveness probe.
const PROBE_ID: &str = "citizen-probe";
/// Silence after which the relay is probed.
const PROBE_AFTER: Duration = Duration::from_secs(90);
/// How long a probe may go unanswered before the socket counts as dead.
const PROBE_WAIT: Duration = Duration::from_secs(20);

/// What a read with no frame by its deadline means.
#[derive(Debug, PartialEq, Eq)]
enum Silence {
    /// Quiet, not yet probed: send the probe.
    Probe,
    /// The probe went unanswered: the relay is gone.
    Dead,
}

/// When the next read gives up waiting, and what that silence will mean:
/// [`PROBE_AFTER`] past the last frame, or [`PROBE_WAIT`] past a probe.
fn read_deadline(last_rx: Instant, probe_sent: Option<Instant>) -> (Instant, Silence) {
    match probe_sent {
        Some(at) => (at + PROBE_WAIT, Silence::Dead),
        None => (last_rx + PROBE_AFTER, Silence::Probe),
    }
}

/// A frame from the relay the runner acts on.
#[derive(Debug)]
pub enum Frame {
    /// An event on the inbox subscription.
    Event(NostrEvent),
    /// `["OK", id, accepted, message]`.
    Ok {
        /// The event id.
        id: String,
        /// Whether the relay took it.
        accepted: bool,
        /// The relay's words.
        message: String,
    },
    /// End of stored events on the inbox.
    Eose,
    /// A notice.
    Notice(String),
    /// The relay closed the subscription.
    Closed(String),
    /// The socket closed.
    Disconnected,
    /// Something the runner need not act on.
    Other,
}

/// The relay connection.
pub struct Relay {
    url: String,
    sk: zeroize::Zeroizing<[u8; 32]>,
    pubkey: String,
    ws: Ws,
    last_frame: Option<Instant>,
    authed: bool,
    /// When the relay last sent anything (any frame proves it is there).
    /// Kept on the connection, not in [`Relay::raw`], because the runners
    /// read inside `select!` and drop the read whenever another arm wins.
    last_rx: Instant,
    /// When the outstanding probe was sent, if one is.
    probe_sent: Option<Instant>,
}

impl Relay {
    /// Connect as `sk` and answer the AUTH challenge.
    pub async fn connect(url: &str, sk: &[u8; 32], pubkey: &str) -> Result<Self, String> {
        let (ws, _) = connect_async(url)
            .await
            .map_err(|e| format!("connect {url}: {e}"))?;
        let mut relay = Self {
            url: url.to_string(),
            sk: zeroize::Zeroizing::new(*sk),
            pubkey: pubkey.to_string(),
            ws,
            last_frame: None,
            authed: false,
            last_rx: Instant::now(),
            probe_sent: None,
        };
        if let Ok(Some(challenge)) = timeout(CHALLENGE_WAIT, relay.await_challenge()).await {
            let id = relay.send_auth(&challenge).await?;
            relay.await_auth_ok(&id).await?;
        }
        Ok(relay)
    }

    /// Whether the relay accepted the house's AUTH.
    pub fn authenticated(&self) -> bool {
        self.authed
    }

    async fn await_challenge(&mut self) -> Option<String> {
        loop {
            match self.raw().await {
                Some(msg) => {
                    if msg.first().and_then(Value::as_str) == Some("AUTH") {
                        return msg.get(1).and_then(Value::as_str).map(str::to_string);
                    }
                }
                None => return None,
            }
        }
    }

    async fn send_auth(&mut self, challenge: &str) -> Result<String, String> {
        let key = signing_key_from_bytes(&self.sk).map_err(|e| e.to_string())?;
        let ev = sign_event(
            UnsignedEvent {
                pubkey: self.pubkey.clone(),
                created_at: now_secs(),
                kind: KIND_AUTH,
                tags: vec![
                    vec!["relay".into(), self.url.clone()],
                    vec!["challenge".into(), challenge.to_string()],
                ],
                content: String::new(),
            },
            &key,
        )
        .map_err(|e| e.to_string())?;
        self.send(json!(["AUTH", ev])).await?;
        Ok(ev.id)
    }

    async fn await_auth_ok(&mut self, id: &str) -> Result<(), String> {
        let deadline = Instant::now() + AUTH_WAIT;
        loop {
            let msg = tokio::time::timeout_at(deadline, self.raw())
                .await
                .map_err(|_| "no OK for AUTH".to_string())?
                .ok_or("closed during AUTH")?;
            if msg.first().and_then(Value::as_str) == Some("OK")
                && msg.get(1).and_then(Value::as_str) == Some(id)
            {
                if msg.get(2).and_then(Value::as_bool) == Some(true) {
                    self.authed = true;
                    return Ok(());
                }
                let why = msg.get(3).and_then(Value::as_str).unwrap_or_default();
                return Err(format!("AUTH refused: {why}"));
            }
        }
    }

    async fn send(&mut self, msg: Value) -> Result<(), String> {
        if let Some(last) = self.last_frame {
            let next = last + FRAME_GAP;
            if next > Instant::now() {
                tokio::time::sleep_until(next).await;
            }
        }
        self.last_frame = Some(Instant::now());
        self.ws
            .send(Message::Text(msg.to_string()))
            .await
            .map_err(|e| e.to_string())
    }

    /// Open the inbox: gift wraps addressed to the house since `since`.
    pub async fn subscribe_inbox(&mut self, since: u64) -> Result<(), String> {
        let filter = json!({ "kinds": [1059], "#p": [self.pubkey], "since": since });
        self.send(json!(["REQ", SUB_ID, filter])).await
    }

    /// Publish an event; the `OK` arrives later as a [`Frame::Ok`].
    pub async fn publish(&mut self, event: &NostrEvent) -> Result<(), String> {
        self.send(json!(["EVENT", event])).await
    }

    /// Send the liveness probe: a REQ for an id no event has, which the
    /// relay answers with an `EOSE` alone.
    async fn probe(&mut self) -> Result<(), String> {
        let filter = json!({ "ids": ["0".repeat(64)], "limit": 1 });
        self.send(json!(["REQ", PROBE_ID, filter])).await
    }

    async fn raw(&mut self) -> Option<Vec<Value>> {
        loop {
            let (deadline, silence) = read_deadline(self.last_rx, self.probe_sent);
            let Ok(next) = tokio::time::timeout_at(deadline, self.ws.next()).await else {
                match silence {
                    Silence::Dead => {
                        eprintln!("relay: silent through a probe; treating the socket as closed");
                        return None;
                    }
                    Silence::Probe => {
                        self.probe_sent = Some(Instant::now());
                        if self.probe().await.is_err() {
                            return None;
                        }
                        continue;
                    }
                }
            };
            if next.is_some() {
                self.last_rx = Instant::now();
                self.probe_sent = None;
            }
            match next {
                None => return None,
                Some(Err(_)) => return None,
                Some(Ok(Message::Text(text))) => {
                    if let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(&text) {
                        // The probe's answer: close it and read on.
                        if arr.get(1).and_then(Value::as_str) == Some(PROBE_ID) {
                            if arr.first().and_then(Value::as_str) == Some("EOSE") {
                                let _ = self.send(json!(["CLOSE", PROBE_ID])).await;
                            }
                            continue;
                        }
                        return Some(arr);
                    }
                }
                Some(Ok(Message::Ping(p))) => {
                    let _ = self.ws.send(Message::Pong(p)).await;
                }
                Some(Ok(Message::Close(_))) => return None,
                Some(Ok(_)) => {}
            }
        }
    }

    /// The next frame, answering an unsolicited AUTH on the way.
    pub async fn next(&mut self) -> Frame {
        loop {
            let Some(msg) = self.raw().await else {
                return Frame::Disconnected;
            };
            let kind = msg.first().and_then(Value::as_str).unwrap_or_default();
            let arg = |i: usize| {
                msg.get(i)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            };
            match kind {
                "EVENT" if msg.get(1).and_then(Value::as_str) == Some(SUB_ID) => {
                    if let Some(ev) = msg
                        .get(2)
                        .and_then(|v| serde_json::from_value::<NostrEvent>(v.clone()).ok())
                    {
                        return Frame::Event(ev);
                    }
                }
                "OK" => {
                    return Frame::Ok {
                        id: arg(1),
                        accepted: msg.get(2).and_then(Value::as_bool).unwrap_or(false),
                        message: arg(3),
                    }
                }
                "EOSE" if msg.get(1).and_then(Value::as_str) == Some(SUB_ID) => return Frame::Eose,
                "NOTICE" => return Frame::Notice(arg(1)),
                "CLOSED" if msg.get(1).and_then(Value::as_str) == Some(SUB_ID) => {
                    return Frame::Closed(arg(2))
                }
                "AUTH" => {
                    let challenge = arg(1);
                    if let Err(e) = self.send_auth(&challenge).await {
                        eprintln!("relay: could not answer AUTH: {e}");
                    }
                }
                _ => return Frame::Other,
            }
        }
    }
}

/// Unix seconds now.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Publish one event to a public relay and wait for its `OK`, for the
/// kind-23500 transaction events the chain's producer follows. Best
/// effort: an unreachable relay is a `false`.
pub async fn publish_once(url: &str, event_json: &str, id: &str) -> bool {
    let Ok(Ok((mut ws, _))) = timeout(Duration::from_secs(10), connect_async(url)).await else {
        return false;
    };
    let frame = format!("[\"EVENT\",{event_json}]");
    if ws.send(Message::Text(frame)).await.is_err() {
        return false;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let next = tokio::time::timeout_at(deadline, ws.next()).await;
        let Ok(Some(Ok(Message::Text(text)))) = next else {
            let _ = ws.close(None).await;
            return false;
        };
        if let Ok(Value::Array(msg)) = serde_json::from_str::<Value>(&text) {
            if msg.first().and_then(Value::as_str) == Some("OK")
                && msg.get(1).and_then(Value::as_str) == Some(id)
            {
                let ok = msg.get(2).and_then(Value::as_bool) == Some(true);
                let _ = ws.close(None).await;
                return ok;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quiet_socket_is_probed_after_the_idle_spell() {
        let t = Instant::now();
        assert_eq!(read_deadline(t, None), (t + PROBE_AFTER, Silence::Probe));
    }

    #[test]
    fn an_unanswered_probe_means_the_relay_is_gone() {
        let t = Instant::now();
        let probed = t + PROBE_AFTER;
        assert_eq!(
            read_deadline(t, Some(probed)),
            (probed + PROBE_WAIT, Silence::Dead)
        );
    }

    #[test]
    fn a_dead_socket_is_noticed_within_two_minutes() {
        assert!(PROBE_AFTER + PROBE_WAIT <= Duration::from_secs(120));
    }
}
