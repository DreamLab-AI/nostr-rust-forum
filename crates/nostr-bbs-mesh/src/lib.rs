//! Federation mesh kit for nostr-bbs deployments.
//!
//! Implements [ADR-073] (mesh federation): per-peer connection state, NIP-42
//! AUTH session management, and kind-30033 federated-broadcast event emission.
//!
//! This crate provides the *substrate* — abstract traits + state machines —
//! that concrete worker implementations (e.g. `nostr-bbs-relay-worker` mesh
//! mode) plug into. The reference Cloudflare Worker implementation lives
//! alongside the relay-worker; alternative deployment targets (libp2p, HTTP/3,
//! Tailscale) implement [`MeshTransport`] themselves.
//!
//! # Status
//!
//! Sprint v9-v11: scaffold only. The mesh feature is gated by
//! `[mesh] mode = "federated"` in the operator config (default `"standalone"`),
//! and the relay-worker's runtime continues to short-circuit when in
//! standalone mode. Full implementation lands in Sprint v12+ per the PRD-012
//! Phase X3 plan.
//!
//! # Architecture sketch
//!
//! ```text
//!     [PeerRelay A]                         [Local Relay]
//!         │                                       │
//!         │ wss://A/.well-known/nostr.json#mesh   │
//!         │◀──────────────────────────────────────│
//!         │                                       │
//!         │   ["AUTH", <NIP-42 challenge>]        │
//!         │──────────────────────────────────────▶│
//!         │   ["AUTH", <signed challenge>]        │
//!         │◀──────────────────────────────────────│
//!         │   ["EVENT", <kind-30033 mesh anchor>] │
//!         │──────────────────────────────────────▶│
//!         │                                       │
//! ```
//!
//! [ADR-073]: https://github.com/DreamLab-AI/nostr-rust-forum/blob/main/docs/adr/ADR-073.md

#![warn(missing_docs)]

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Per-peer mesh session state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSession {
    /// Peer relay URL (`wss://...`).
    pub url: String,
    /// Peer pubkey (hex) — the relay's own NIP-42 identity.
    pub peer_pubkey: String,
    /// Authenticated state: `false` until NIP-42 AUTH round-trip completes.
    pub authenticated: bool,
    /// Unix timestamp of last successful interaction.
    pub last_seen: u64,
}

/// Errors raised by mesh transports.
#[derive(Debug, Error)]
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
    /// Serialization error.
    #[error("serialization: {0}")]
    Serde(String),
}

/// Abstract transport for connecting to a peer relay.
///
/// Cloudflare Workers provide a WebSocket impl; libp2p and other targets
/// provide their own. The mesh state machine on top is transport-agnostic.
#[async_trait(?Send)]
pub trait MeshTransport {
    /// Connect to a peer relay.
    async fn connect(&self, url: &str) -> Result<PeerSession, MeshError>;

    /// Send a NIP-42 AUTH response with the local relay's signed challenge.
    async fn authenticate(
        &self,
        session: &mut PeerSession,
        signed_challenge: &str,
    ) -> Result<(), MeshError>;

    /// Broadcast a kind-30033 federated-broadcast event to a peer relay.
    async fn broadcast_kind30033(
        &self,
        session: &PeerSession,
        event_json: &str,
    ) -> Result<(), MeshError>;
}

/// Build a kind-30033 mesh anchor event payload (signing + serialization
/// happens upstream via `nostr-bbs-core`).
///
/// The `d` tag identifies the source relay (canonical hostname); event
/// content carries a JSON array of mirrored event-IDs in this batch.
pub fn mesh_anchor_tags(source_relay: &str) -> Vec<Vec<String>> {
    vec![vec!["d".to_string(), source_relay.to_string()]]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesh_anchor_emits_d_tag() {
        let tags = mesh_anchor_tags("wss://example.com");
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0][0], "d");
        assert_eq!(tags[0][1], "wss://example.com");
    }
}
