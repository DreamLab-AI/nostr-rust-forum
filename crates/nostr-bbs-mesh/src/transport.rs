//! Mesh transport — the Nostr relay-backed federation wire (PRD-010 §5.2/§5.4).
//!
//! Federation is delivered as ordinary Nostr traffic: an IS-Envelope is
//! JCS-serialised, wrapped as a NIP-59 kind-1059 gift-wrap, and published to a
//! peer relay as `["EVENT", <wrap>]`; inbound wraps are unwrapped, validated,
//! and their delegation/attribution checked before the envelope is surfaced.
//!
//! # CF-Workers compatibility
//!
//! The relay-worker is a Cloudflare Worker (single-threaded V8 isolate,
//! `wasm32-unknown-unknown`, no `tokio`). Two design choices keep this module
//! runnable there:
//!
//! * All async is `#[async_trait(?Send)]` — futures need not be `Send`, and
//!   there is **no `tokio::spawn`** anywhere.
//! * Byte I/O is abstracted behind the [`MeshSocket`] trait. The CF Worker
//!   implements it over `worker::WebSocket`; tests implement it over an
//!   in-memory channel ([`crate::mock`]). The Nostr wire framing —
//!   `REQ`/`EVENT`/`AUTH`/`OK`/`EOSE` — lives here, transport-agnostic.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use nostr_bbs_core::event::{sign_event, NostrEvent, UnsignedEvent};
use nostr_bbs_core::gift_wrap::{gift_wrap, unwrap_gift};
use nostr_bbs_core::keys::{pubkey_hex, signing_key_from_bytes};

use crate::config::MeshConfig;
use crate::delegation::DelegationError;
use crate::envelope::{Envelope, EnvelopeError};

/// NIP-42 client-authentication event kind.
pub const KIND_AUTH: u64 = 22242;

/// Per-peer mesh session state (retained from the original scaffold shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSession {
    /// Peer relay URL (`wss://...`).
    pub url: String,
    /// Peer pubkey (hex) — the relay's own NIP-42 identity, when known.
    pub peer_pubkey: String,
    /// Authenticated state: `false` until the NIP-42 AUTH round-trip completes.
    pub authenticated: bool,
    /// Unix timestamp of the last successful interaction.
    pub last_seen: u64,
    /// The most recent AUTH challenge received from this peer, if any.
    pub pending_challenge: Option<String>,
}

impl PeerSession {
    /// A fresh, unauthenticated session for `url`.
    pub fn new(url: impl Into<String>) -> Self {
        PeerSession {
            url: url.into(),
            peer_pubkey: String::new(),
            authenticated: false,
            last_seen: 0,
            pending_challenge: None,
        }
    }
}

/// Errors raised by mesh transports.
#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    /// WebSocket / network error.
    #[error("transport: {0}")]
    Transport(String),
    /// NIP-42 AUTH handshake failed.
    #[error("AUTH failed: {0}")]
    Auth(String),
    /// Peer not yet authenticated for this operation.
    #[error("peer not authenticated")]
    NotAuthenticated,
    /// Serialization / deserialization error.
    #[error("serialization: {0}")]
    Serde(String),
    /// Malformed relay wire frame.
    #[error("protocol: {0}")]
    Protocol(String),
    /// The relay rejected an event (`OK false`).
    #[error("relay rejected {id}: {message}")]
    Rejected {
        /// The rejected event id.
        id: String,
        /// The relay's human-readable reason.
        message: String,
    },
    /// Gift-wrap / unwrap failure.
    #[error("gift-wrap: {0}")]
    GiftWrap(String),
    /// Envelope validation failure.
    #[error("envelope: {0}")]
    Envelope(#[from] EnvelopeError),
    /// Delegation verification failure.
    #[error("delegation: {0}")]
    Delegation(#[from] DelegationError),
    /// The envelope's claimed `from` does not match the verified signer chain.
    #[error("attribution: envelope `from` does not match seal signer / delegator")]
    AttributionMismatch,
    /// A cryptographic key error.
    #[error("key: {0}")]
    Key(String),
}

/// A parsed inbound relay message (NIP-01 / NIP-42).
///
/// Not `PartialEq` because [`NostrEvent`] (in the `Event` variant) is not — use
/// pattern matching to inspect frames.
#[derive(Debug, Clone)]
pub enum RelayMessage {
    /// `["EVENT", <sub_id>, <event>]` — an event matching a subscription.
    Event {
        /// The subscription id the event matched.
        subscription_id: String,
        /// The event itself.
        event: NostrEvent,
    },
    /// `["OK", <id>, <bool>, <message>]` — publish acknowledgement.
    Ok {
        /// The acknowledged event id.
        event_id: String,
        /// Whether the event was accepted.
        accepted: bool,
        /// The relay's message.
        message: String,
    },
    /// `["EOSE", <sub_id>]` — end of stored events.
    Eose {
        /// The subscription id.
        subscription_id: String,
    },
    /// `["AUTH", <challenge>]` — a NIP-42 challenge (inbound form is a string).
    Auth {
        /// The challenge token to sign.
        challenge: String,
    },
    /// `["NOTICE", <message>]`.
    Notice {
        /// The human-readable notice.
        message: String,
    },
    /// `["CLOSED", <sub_id>, <message>]`.
    Closed {
        /// The closed subscription id.
        subscription_id: String,
        /// The reason.
        message: String,
    },
    /// Any other/unrecognised frame, preserved verbatim.
    Other(Value),
}

impl RelayMessage {
    /// Parse a relay message from a text frame.
    pub fn parse(text: &str) -> Result<Self, MeshError> {
        let arr: Vec<Value> = serde_json::from_str(text)
            .map_err(|e| MeshError::Protocol(format!("not a JSON array: {e}")))?;
        let tag = arr
            .first()
            .and_then(Value::as_str)
            .ok_or_else(|| MeshError::Protocol("empty frame".into()))?;
        match tag {
            "EVENT" => {
                // Inbound: ["EVENT", sub_id, event]
                let subscription_id = arr
                    .get(1)
                    .and_then(Value::as_str)
                    .ok_or_else(|| MeshError::Protocol("EVENT missing sub_id".into()))?
                    .to_string();
                let event: NostrEvent = serde_json::from_value(
                    arr.get(2)
                        .cloned()
                        .ok_or_else(|| MeshError::Protocol("EVENT missing event".into()))?,
                )
                .map_err(|e| MeshError::Serde(e.to_string()))?;
                Ok(RelayMessage::Event {
                    subscription_id,
                    event,
                })
            }
            "OK" => Ok(RelayMessage::Ok {
                event_id: arr
                    .get(1)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                accepted: arr.get(2).and_then(Value::as_bool).unwrap_or(false),
                message: arr
                    .get(3)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            }),
            "EOSE" => Ok(RelayMessage::Eose {
                subscription_id: arr
                    .get(1)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            }),
            "AUTH" => Ok(RelayMessage::Auth {
                challenge: arr
                    .get(1)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            }),
            "NOTICE" => Ok(RelayMessage::Notice {
                message: arr
                    .get(1)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            }),
            "CLOSED" => Ok(RelayMessage::Closed {
                subscription_id: arr
                    .get(1)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                message: arr
                    .get(2)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            }),
            _ => Ok(RelayMessage::Other(Value::Array(arr))),
        }
    }
}

/// The byte-level transport seam. Implemented over `worker::WebSocket` in the
/// CF relay-worker and over an in-memory channel in tests ([`crate::mock`]).
#[async_trait(?Send)]
pub trait MeshSocket {
    /// Send a text frame to the peer.
    async fn send_text(&self, msg: &str) -> Result<(), MeshError>;
    /// Receive the next text frame. `Ok(None)` signals the socket is closed /
    /// has no further messages.
    async fn recv_text(&self) -> Result<Option<String>, MeshError>;
}

/// Abstract transport for connecting to a peer relay (evolved from the original
/// scaffold trait). Concrete transports (Nostr-over-WebSocket, libp2p, HTTP/3)
/// implement this; the mesh state machine on top is transport-agnostic.
#[async_trait(?Send)]
pub trait MeshTransport {
    /// Establish (or describe) a session for `url`.
    async fn connect(&self, url: &str) -> Result<PeerSession, MeshError>;

    /// Send a NIP-42 AUTH response carrying the local relay's signed challenge
    /// event (JSON of a kind-22242 event).
    async fn authenticate(
        &self,
        session: &mut PeerSession,
        signed_challenge_event_json: &str,
    ) -> Result<(), MeshError>;

    /// Publish a raw event (JSON object) to the peer as `["EVENT", <event>]`.
    async fn publish_event(&self, session: &PeerSession, event_json: &str)
        -> Result<(), MeshError>;

    /// Open a subscription: `["REQ", <sub_id>, <filter>]`.
    async fn subscribe(
        &self,
        session: &PeerSession,
        sub_id: &str,
        filter_json: &str,
    ) -> Result<(), MeshError>;

    /// Receive and parse the next inbound frame, if any.
    async fn next_message(&self, session: &PeerSession) -> Result<Option<RelayMessage>, MeshError>;

    /// Broadcast a kind-30033 mesh-anchor event (back-compat with the scaffold).
    async fn broadcast_kind30033(
        &self,
        session: &PeerSession,
        event_json: &str,
    ) -> Result<(), MeshError>;
}

/// A received, verified inbound envelope plus its provenance metadata.
#[derive(Debug, Clone)]
pub struct ReceivedEnvelope {
    /// The validated IS-Envelope.
    pub envelope: Envelope,
    /// The seal signer's pubkey (hex) — the *delegatee* under delegation, else
    /// the direct author.
    pub seal_pubkey: String,
    /// The outer kind-1059 event id (the dedup key, ADR-075 §D12).
    pub event_id: String,
    /// The inner rumor's `created_at`.
    pub rumor_created_at: u64,
}

/// Options controlling inbound envelope verification.
#[derive(Debug, Clone)]
pub struct ReceiveOptions {
    /// Current unix time for TTL evaluation. `None` skips TTL enforcement.
    pub now: Option<u64>,
    /// Require a NIP-26 delegation whenever `from != seal signer` (PRD-010
    /// §F12 `delegation_required`).
    pub delegation_required: bool,
}

impl Default for ReceiveOptions {
    fn default() -> Self {
        ReceiveOptions {
            now: None,
            delegation_required: true,
        }
    }
}

/// A Nostr relay-backed [`MeshTransport`] over a single [`MeshSocket`].
///
/// One `RelayTransport` drives one peer connection. The socket is established
/// out-of-band (the CF Worker opens a `worker::WebSocket`; a test builds a mock
/// pair) and handed in; this type owns the Nostr framing and the envelope
/// wrap/unwrap/verify pipeline on top of it.
pub struct RelayTransport<S: MeshSocket> {
    socket: S,
    peer_url: String,
}

impl<S: MeshSocket> RelayTransport<S> {
    /// Wrap an established socket connected to `peer_url`.
    pub fn new(socket: S, peer_url: impl Into<String>) -> Self {
        RelayTransport {
            socket,
            peer_url: peer_url.into(),
        }
    }

    /// Borrow the underlying socket (e.g. for the mock relay to drain it).
    pub fn socket(&self) -> &S {
        &self.socket
    }

    /// Publish an already-built event object.
    pub async fn publish(&self, event: &NostrEvent) -> Result<(), MeshError> {
        let event_val = serde_json::to_value(event).map_err(|e| MeshError::Serde(e.to_string()))?;
        let frame = Value::Array(vec![Value::String("EVENT".into()), event_val]);
        self.socket.send_text(&frame.to_string()).await
    }

    /// Open a subscription with one or more filter objects.
    pub async fn subscribe_filters(
        &self,
        sub_id: &str,
        filters: Vec<Value>,
    ) -> Result<(), MeshError> {
        let mut frame = vec![Value::String("REQ".into()), Value::String(sub_id.into())];
        frame.extend(filters);
        self.socket
            .send_text(&Value::Array(frame).to_string())
            .await
    }

    /// Subscribe to the gift-wrapped inbox for `recipient_hex`
    /// (`{"#p":[hex],"kinds":[1059]}`).
    pub async fn subscribe_inbox(
        &self,
        sub_id: &str,
        recipient_hex: &str,
    ) -> Result<(), MeshError> {
        let filter = json!({ "#p": [recipient_hex], "kinds": [1059] });
        self.subscribe_filters(sub_id, vec![filter]).await
    }

    /// Send a NIP-42 AUTH response (a signed kind-22242 event).
    pub async fn send_auth(&self, signed_auth_event: &NostrEvent) -> Result<(), MeshError> {
        let event_val =
            serde_json::to_value(signed_auth_event).map_err(|e| MeshError::Serde(e.to_string()))?;
        let frame = Value::Array(vec![Value::String("AUTH".into()), event_val]);
        self.socket.send_text(&frame.to_string()).await
    }

    /// Receive and parse the next inbound frame.
    pub async fn recv(&self) -> Result<Option<RelayMessage>, MeshError> {
        match self.socket.recv_text().await? {
            Some(text) => Ok(Some(RelayMessage::parse(&text)?)),
            None => Ok(None),
        }
    }

    /// Build and sign a NIP-42 AUTH event for `challenge` at time `created_at`.
    ///
    /// `secret_key` is the local relay/actor 32-byte key; the derived pubkey is
    /// embedded so the relay can bind the session.
    pub fn build_auth_event(
        &self,
        secret_key: &[u8; 32],
        challenge: &str,
        created_at: u64,
    ) -> Result<NostrEvent, MeshError> {
        let pk = pubkey_hex(secret_key).map_err(|e| MeshError::Key(e.to_string()))?;
        let unsigned = UnsignedEvent {
            pubkey: pk,
            created_at,
            kind: KIND_AUTH,
            tags: vec![
                vec!["relay".to_string(), self.peer_url.clone()],
                vec!["challenge".to_string(), challenge.to_string()],
            ],
            content: String::new(),
        };
        let sk = signing_key_from_bytes(secret_key).map_err(|e| MeshError::Key(e.to_string()))?;
        sign_event(unsigned, &sk).map_err(|e| MeshError::Key(e.to_string()))
    }

    /// Encode + wrap + publish an IS-Envelope to the peer.
    ///
    /// Validates the envelope, JCS-encodes it, gift-wraps it (kind-1059) to the
    /// recipient, and publishes it. Returns the outer wrap event id.
    pub async fn send_envelope(
        &self,
        sender_sk: &[u8; 32],
        envelope: &Envelope,
    ) -> Result<String, MeshError> {
        envelope.validate()?;
        let recipient_hex = envelope.recipient_hex()?;
        // Derive the sender pubkey from the secret key so the seal (kind-13)
        // signer and the rumor pubkey always agree.
        let sender_pubkey = pubkey_hex(sender_sk).map_err(|e| MeshError::Key(e.to_string()))?;
        let content = envelope.to_jcs_string();
        let wrap = gift_wrap(sender_sk, &sender_pubkey, &recipient_hex, &content)
            .map_err(|e| MeshError::GiftWrap(e.to_string()))?;
        let id = wrap.id.clone();
        self.publish(&wrap).await?;
        Ok(id)
    }

    /// Read frames until the next valid inbound envelope is decoded, or the
    /// socket closes (`Ok(None)`). Non-event frames (AUTH/OK/EOSE/NOTICE) are
    /// skipped; a gift-wrap that fails to decode for *this* recipient is
    /// skipped (it may be addressed to someone else), but a wrap that decodes
    /// yet fails verification returns an error.
    pub async fn recv_envelope(
        &self,
        recipient_sk: &[u8; 32],
        opts: &ReceiveOptions,
    ) -> Result<Option<ReceivedEnvelope>, MeshError> {
        while let Some(msg) = self.recv().await? {
            if let RelayMessage::Event { event, .. } = msg {
                if event.kind != 1059 {
                    continue;
                }
                match decode_incoming_wrap(&event, recipient_sk, opts) {
                    Ok(received) => return Ok(Some(received)),
                    // A wrap we can't unwrap is not for us — keep scanning.
                    Err(MeshError::GiftWrap(_)) => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(None)
    }
}

/// Decode, validate, and verify attribution of an inbound kind-1059 gift wrap.
///
/// This is the receive-side pipeline of ADR-075 §D6 + ADR-074 §D8:
/// unwrap → parse envelope → validate → TTL → delegation/attribution.
pub fn decode_incoming_wrap(
    wrap: &NostrEvent,
    recipient_sk: &[u8; 32],
    opts: &ReceiveOptions,
) -> Result<ReceivedEnvelope, MeshError> {
    let unwrapped =
        unwrap_gift(wrap, recipient_sk).map_err(|e| MeshError::GiftWrap(e.to_string()))?;
    let seal_pubkey = unwrapped.sender_pubkey.clone();
    let rumor = unwrapped.rumor;

    let envelope = Envelope::from_jcs_str(&rumor.content)?;

    // TTL (ADR-075 §D7).
    if let Some(now) = opts.now {
        if envelope.is_expired_with_default(now, rumor.created_at) {
            return Err(MeshError::Envelope(EnvelopeError::Json(
                "envelope-expired".into(),
            )));
        }
    }

    let from_hex = envelope.origin_hex()?;

    match &envelope.delegation {
        Some(token) => {
            // Delegatee is the seal signer; verify + apply conditions to the
            // rumor (ADR-074 §D8, and this module's documented rumor-binding
            // decision). Then the envelope `from` MUST be the delegator.
            token.verify_for_event(&seal_pubkey, rumor.kind, rumor.created_at)?;
            if token.delegator_hex() != from_hex {
                return Err(MeshError::AttributionMismatch);
            }
        }
        None => {
            // No delegation: the envelope `from` MUST be the seal signer.
            if from_hex != seal_pubkey {
                return Err(MeshError::AttributionMismatch);
            }
            // If the deployment requires delegation for cross-attribution, a
            // bare (non-delegated) envelope is only acceptable when the author
            // is signing for themselves — which the equality above already
            // guarantees. `delegation_required` therefore has no extra effect
            // here; it is enforced at the point a bridge re-attributes.
            let _ = opts.delegation_required;
        }
    }

    Ok(ReceivedEnvelope {
        envelope,
        seal_pubkey,
        event_id: wrap.id.clone(),
        rumor_created_at: rumor.created_at,
    })
}

#[async_trait(?Send)]
impl<S: MeshSocket> MeshTransport for RelayTransport<S> {
    async fn connect(&self, url: &str) -> Result<PeerSession, MeshError> {
        // The socket is already established; describe the session.
        Ok(PeerSession::new(url))
    }

    async fn authenticate(
        &self,
        session: &mut PeerSession,
        signed_challenge_event_json: &str,
    ) -> Result<(), MeshError> {
        let frame = format!("[\"AUTH\",{signed_challenge_event_json}]");
        self.socket.send_text(&frame).await?;
        session.authenticated = true;
        session.pending_challenge = None;
        Ok(())
    }

    async fn publish_event(
        &self,
        _session: &PeerSession,
        event_json: &str,
    ) -> Result<(), MeshError> {
        let frame = format!("[\"EVENT\",{event_json}]");
        self.socket.send_text(&frame).await
    }

    async fn subscribe(
        &self,
        _session: &PeerSession,
        sub_id: &str,
        filter_json: &str,
    ) -> Result<(), MeshError> {
        let frame = format!("[\"REQ\",{},{filter_json}]", json!(sub_id));
        self.socket.send_text(&frame).await
    }

    async fn next_message(
        &self,
        _session: &PeerSession,
    ) -> Result<Option<RelayMessage>, MeshError> {
        self.recv().await
    }

    async fn broadcast_kind30033(
        &self,
        _session: &PeerSession,
        event_json: &str,
    ) -> Result<(), MeshError> {
        let frame = format!("[\"EVENT\",{event_json}]");
        self.socket.send_text(&frame).await
    }
}

// ── Peer management + fan-out dedup ──────────────────────────────────────────

/// Capacity-bounded seen-event-id cache for fan-out loop prevention
/// (ADR-075 §D12, PRD-010 §F21). Insertion-ordered eviction at the configured capacity.
#[derive(Debug)]
pub struct SeenIds {
    capacity: usize,
    order: std::collections::VecDeque<String>,
    set: std::collections::HashSet<String>,
}

impl SeenIds {
    /// Default capacity mandated by PRD-010 §F21.
    pub const DEFAULT_CAPACITY: usize = 4096;

    /// A cache with the given capacity.
    pub fn new(capacity: usize) -> Self {
        SeenIds {
            capacity: capacity.max(1),
            order: std::collections::VecDeque::new(),
            set: std::collections::HashSet::new(),
        }
    }

    /// Record `id`. Returns `true` if it was newly inserted, `false` if it was
    /// already present (a duplicate that must not be re-federated).
    pub fn insert(&mut self, id: &str) -> bool {
        if self.set.contains(id) {
            return false;
        }
        if self.order.len() >= self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        self.order.push_back(id.to_string());
        self.set.insert(id.to_string());
        true
    }

    /// Whether `id` has been seen.
    pub fn contains(&self, id: &str) -> bool {
        self.set.contains(id)
    }
}

impl Default for SeenIds {
    fn default() -> Self {
        SeenIds::new(Self::DEFAULT_CAPACITY)
    }
}

/// Roster of peer relays derived from a [`MeshConfig`], plus the fan-out policy
/// (which kinds/pubkeys federate) and the dedup cache. This is the outbound
/// planner used by the relay-worker's federated code path.
pub struct PeerManager {
    config: MeshConfig,
    peers: Vec<PeerSession>,
    seen: SeenIds,
}

impl PeerManager {
    /// Build a roster from config `peer_relays`.
    pub fn from_config(config: MeshConfig) -> Self {
        let peers = config.peer_relays.iter().map(PeerSession::new).collect();
        PeerManager {
            config,
            peers,
            seen: SeenIds::default(),
        }
    }

    /// The configured peer sessions.
    pub fn peers(&self) -> &[PeerSession] {
        &self.peers
    }

    /// The underlying config.
    pub fn config(&self) -> &MeshConfig {
        &self.config
    }

    /// Record an event id; returns `true` if newly seen (i.e. eligible to
    /// federate), `false` if a duplicate.
    pub fn mark_seen(&mut self, event_id: &str) -> bool {
        self.seen.insert(event_id)
    }

    /// Decide whether an event authored locally by `author_hex` of `kind`
    /// should be federated (kind allowlist ∩ pubkey allowlist ∩ not-seen).
    pub fn should_federate(&mut self, kind: u64, author_hex: &str, event_id: &str) -> bool {
        if !self.config.is_federating() {
            return false;
        }
        if !self.config.is_federated_kind(kind) {
            return false;
        }
        if !self.config.is_federated_pubkey(author_hex) {
            return false;
        }
        // Only federate the first time we see this id (loop prevention).
        self.mark_seen(event_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_inbound_event_frame() {
        let text = r#"["EVENT","sub1",{"id":"aa","pubkey":"bb","created_at":1,"kind":1059,"tags":[],"content":"c","sig":"dd"}]"#;
        match RelayMessage::parse(text).unwrap() {
            RelayMessage::Event {
                subscription_id,
                event,
            } => {
                assert_eq!(subscription_id, "sub1");
                assert_eq!(event.kind, 1059);
            }
            other => panic!("wrong parse: {other:?}"),
        }
    }

    #[test]
    fn parses_auth_challenge() {
        let text = r#"["AUTH","challenge-token"]"#;
        match RelayMessage::parse(text).unwrap() {
            RelayMessage::Auth { challenge } => assert_eq!(challenge, "challenge-token"),
            other => panic!("wrong parse: {other:?}"),
        }
    }

    #[test]
    fn parses_ok_frame() {
        let text = r#"["OK","evid",false,"blocked: nope"]"#;
        match RelayMessage::parse(text).unwrap() {
            RelayMessage::Ok {
                event_id,
                accepted,
                message,
            } => {
                assert_eq!(event_id, "evid");
                assert!(!accepted);
                assert_eq!(message, "blocked: nope");
            }
            other => panic!("wrong parse: {other:?}"),
        }
    }

    #[test]
    fn seen_ids_dedup_and_evict() {
        let mut s = SeenIds::new(2);
        assert!(s.insert("a"));
        assert!(!s.insert("a")); // dup
        assert!(s.insert("b"));
        assert!(s.insert("c")); // evicts "a"
        assert!(!s.contains("a"));
        assert!(s.contains("b"));
        assert!(s.insert("a")); // "a" evicted, now newly seen again
    }

    #[test]
    fn peer_manager_federation_policy() {
        let cfg = MeshConfig {
            mode: "federated".into(),
            peer_relays: vec!["wss://a".into()],
            federated_kinds: vec![1059],
            ..MeshConfig::default()
        };
        let mut pm = PeerManager::from_config(cfg);
        assert_eq!(pm.peers().len(), 1);
        assert!(pm.should_federate(1059, "abc", "id1"));
        assert!(!pm.should_federate(1059, "abc", "id1")); // dup id
        assert!(!pm.should_federate(1, "abc", "id2")); // kind not federated
    }

    #[test]
    fn standalone_never_federates() {
        let mut pm = PeerManager::from_config(MeshConfig::default());
        assert!(!pm.should_federate(1059, "abc", "id1"));
    }
}
