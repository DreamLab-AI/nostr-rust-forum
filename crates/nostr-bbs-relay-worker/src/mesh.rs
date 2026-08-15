//! Relay-worker mesh federation integration (PRD-010 §5.2, F11/F12/F21).
//!
//! This module is the relay-worker's half of the DreamLab mesh. The federation
//! *core* — IS-Envelope, delegation verification, the config schema, and the
//! Nostr relay-backed [`MeshTransport`](nostr_bbs_mesh::MeshTransport) — lives
//! in the `nostr-bbs-mesh` crate; this module wires that core into the relay's
//! `MESH_*` environment configuration and provides the **outbound** fan-out
//! planner that complements the **inbound** F11 kind-allowlist filter already
//! present in `relay_do/nip_handlers.rs` (`is_mesh_peer` /
//! `is_federated_kind_allowed`, owned by the NIP-42 workstream — not edited
//! here).
//!
//! # What is wired here
//!
//! * [`mesh_config_from_reader`] — builds a [`MeshConfig`] from the relay's
//!   existing `MESH_MODE` / `MESH_ALLOWED_REMOTE_DIDS` / `MESH_FEDERATED_KINDS`
//!   env vars, plus `MESH_PEER_RELAYS` / `MESH_FEDERATED_PUBKEYS` /
//!   `MESH_DELEGATION_REQUIRED`. Reader-based so it is host-testable without a
//!   `worker::Env`.
//! * [`FederationManager`] — holds a
//!   [`PeerManager`](nostr_bbs_mesh::PeerManager) and answers the outbound
//!   question "should this accepted event be fanned out, and to which peers?"
//!   with loop-prevention dedup (ADR-075 §D12 / PRD-010 §F21).
//!
//! # Named join points (deferred wiring — Gate 6)
//!
//! Two seams are intentionally left as traits rather than hard-wired, because
//! completing them touches code owned by the concurrent NIP-42 workstream
//! (`relay_do/session.rs`, `nip_handlers.rs`) and the CF outbound-WebSocket
//! surface:
//!
//! 1. [`SessionAuthBoundary`] — how the fan-out worker learns whether a peer
//!    session is NIP-42-authenticated. Implemented below for `NostrRelayDO`
//!    over the session layer's `authed_pubkey` state.
//! 2. [`PeerConnector`] — the CF-Worker-side outbound socket. A concrete impl
//!    wraps `worker::WebSocket` as a
//!    [`MeshSocket`](nostr_bbs_mesh::MeshSocket) and drives
//!    [`RelayTransport`](nostr_bbs_mesh::RelayTransport). It is defined here so
//!    the DO's accept path can call `connector.publish_to(peer, frame)` once
//!    the session API stabilises.
//!
//! The mesh *crate* is complete and green; this module compiles and is
//! registered, and the two seams above are the documented remaining wiring.

// The fan-out planner and the two seam traits are consumed by the DO accept
// path once the concurrent NIP-42 session API stabilises (see join points
// above). Until that call site lands they are reachable-but-unused here.
#![allow(dead_code)]

use async_trait::async_trait;

use nostr_bbs_mesh::config::MeshConfig;
use nostr_bbs_mesh::transport::MeshError;
use nostr_bbs_mesh::PeerManager;

// Env var names — aligned with the existing F11 reads in `nip_handlers.rs`.
const VAR_MODE: &str = "MESH_MODE";
const VAR_PEER_RELAYS: &str = "MESH_PEER_RELAYS";
const VAR_FEDERATED_KINDS: &str = "MESH_FEDERATED_KINDS";
const VAR_FEDERATED_PUBKEYS: &str = "MESH_FEDERATED_PUBKEYS";
const VAR_ALLOWED_REMOTE_DIDS: &str = "MESH_ALLOWED_REMOTE_DIDS";
const VAR_DELEGATION_REQUIRED: &str = "MESH_DELEGATION_REQUIRED";

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn split_csv_u64(s: &str) -> Vec<u64> {
    s.split(',')
        .filter_map(|s| s.trim().parse::<u64>().ok())
        .collect()
}

/// Build a [`MeshConfig`] from the relay's `MESH_*` environment via a reader
/// closure. In the Worker the closure is `|name| env.var(name).ok().map(|v|
/// v.to_string())`; tests pass a map-backed closure.
///
/// Absent vars fall back to the [`MeshConfig`] defaults (standalone, default
/// federated-kind set, delegation required).
pub fn mesh_config_from_reader<F>(read: F) -> MeshConfig
where
    F: Fn(&str) -> Option<String>,
{
    let mut cfg = MeshConfig::default();
    if let Some(mode) = read(VAR_MODE).filter(|s| !s.is_empty()) {
        cfg.mode = mode;
    }
    if let Some(peers) = read(VAR_PEER_RELAYS) {
        let peers = split_csv(&peers);
        if !peers.is_empty() {
            cfg.peer_relays = peers;
        }
    }
    if let Some(kinds) = read(VAR_FEDERATED_KINDS) {
        let kinds = split_csv_u64(&kinds);
        if !kinds.is_empty() {
            cfg.federated_kinds = kinds;
        }
    }
    if let Some(pubkeys) = read(VAR_FEDERATED_PUBKEYS) {
        cfg.federated_pubkeys = split_csv(&pubkeys);
    }
    if let Some(dids) = read(VAR_ALLOWED_REMOTE_DIDS) {
        cfg.allowed_remote_dids = split_csv(&dids);
    }
    if let Some(req) = read(VAR_DELEGATION_REQUIRED) {
        // Truthy set matches the rest of the kit's env-bool convention.
        cfg.delegation_required = matches!(req.trim(), "1" | "true" | "TRUE" | "yes");
    }
    cfg
}

/// The seam the NIP-42 session layer fills so fan-out can gate on peer auth.
pub trait SessionAuthBoundary {
    /// Whether the peer identified by `pubkey_hex` currently holds an
    /// authenticated NIP-42 session on this relay.
    fn is_authenticated(&self, pubkey_hex: &str) -> bool;
}

/// A pubkey is authenticated iff some live WebSocket session on this Durable
/// Object completed NIP-42 AUTH as that pubkey (`SessionInfo.authed_pubkey`,
/// which the session layer persists across DO hibernation).
impl SessionAuthBoundary for crate::relay_do::NostrRelayDO {
    fn is_authenticated(&self, pubkey_hex: &str) -> bool {
        self.sessions
            .borrow()
            .values()
            .any(|s| s.authed_pubkey.as_deref() == Some(pubkey_hex))
    }
}

/// The CF-Worker-side outbound socket seam. A concrete impl wraps
/// `worker::WebSocket` and drives [`nostr_bbs_mesh::RelayTransport`] to actually
/// publish `["EVENT", <wrap>]` frames to a peer relay. Defined here as the
/// documented join point; the DO accept path calls it once the session API
/// stabilises.
#[async_trait(?Send)]
pub trait PeerConnector {
    /// Publish a pre-built wire frame to `peer_url`.
    async fn publish_to(&self, peer_url: &str, frame: &str) -> Result<(), MeshError>;
}

/// Outbound fan-out planner: wraps a [`PeerManager`] with the relay's mesh
/// policy and loop-prevention dedup.
pub struct FederationManager {
    peers: PeerManager,
}

impl FederationManager {
    /// Construct from a resolved [`MeshConfig`].
    pub fn new(config: MeshConfig) -> Self {
        FederationManager { peers: PeerManager::from_config(config) }
    }

    /// Construct directly from the environment reader.
    pub fn from_reader<F>(read: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        FederationManager::new(mesh_config_from_reader(read))
    }

    /// Whether federation is active at all.
    pub fn is_federating(&self) -> bool {
        self.peers.config().is_federating()
    }

    /// Peer relay URLs to fan out to.
    pub fn peer_urls(&self) -> Vec<String> {
        self.peers.peers().iter().map(|p| p.url.clone()).collect()
    }

    /// Decide whether an accepted event authored locally by `author_hex` of
    /// `kind` (with outer id `event_id`) should be fanned out. Applies the kind
    /// ∩ pubkey allowlists and the not-yet-seen dedup (ADR-075 §D12).
    ///
    /// Returns the peer URLs to publish to (empty = do not federate).
    pub fn plan_fanout(&mut self, kind: u64, author_hex: &str, event_id: &str) -> Vec<String> {
        if self.peers.should_federate(kind, author_hex, event_id) {
            self.peer_urls()
        } else {
            Vec::new()
        }
    }

    /// Build the outbound wire frame for a raw event JSON object string.
    pub fn outbound_frame(event_json: &str) -> String {
        format!("[\"EVENT\",{event_json}]")
    }

    /// Borrow the underlying [`PeerManager`].
    pub fn peer_manager(&self) -> &PeerManager {
        &self.peers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn reader(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |name: &str| map.get(name).cloned()
    }

    #[test]
    fn default_reader_is_standalone() {
        let cfg = mesh_config_from_reader(reader(&[]));
        assert!(!cfg.is_federating());
        assert!(cfg.delegation_required);
        assert!(cfg.is_federated_kind(1059)); // defaults populated
    }

    #[test]
    fn reads_federated_env() {
        let cfg = mesh_config_from_reader(reader(&[
            ("MESH_MODE", "federated"),
            ("MESH_PEER_RELAYS", "wss://a.example, wss://b.example"),
            ("MESH_FEDERATED_KINDS", "14,1059"),
            ("MESH_FEDERATED_PUBKEYS", "deadbeef"),
            ("MESH_DELEGATION_REQUIRED", "false"),
        ]));
        assert!(cfg.is_federating());
        assert_eq!(cfg.peer_relays.len(), 2);
        assert!(cfg.is_federated_kind(14));
        assert!(!cfg.is_federated_kind(30033)); // overridden set
        assert!(cfg.is_federated_pubkey("deadbeef"));
        assert!(!cfg.delegation_required);
    }

    #[test]
    fn fanout_plans_and_dedups() {
        let mut fm = FederationManager::from_reader(reader(&[
            ("MESH_MODE", "federated"),
            ("MESH_PEER_RELAYS", "wss://peer.example"),
            ("MESH_FEDERATED_KINDS", "1059"),
        ]));
        assert!(fm.is_federating());
        let first = fm.plan_fanout(1059, "abc", "evid-1");
        assert_eq!(first, vec!["wss://peer.example".to_string()]);
        // Same id again → deduped (loop prevention).
        assert!(fm.plan_fanout(1059, "abc", "evid-1").is_empty());
        // Non-federated kind → no fan-out.
        assert!(fm.plan_fanout(1, "abc", "evid-2").is_empty());
    }

    #[test]
    fn standalone_plans_nothing() {
        let mut fm = FederationManager::from_reader(reader(&[]));
        assert!(fm.plan_fanout(1059, "abc", "evid").is_empty());
    }

    #[test]
    fn outbound_frame_wraps_event() {
        let frame = FederationManager::outbound_frame(r#"{"id":"x"}"#);
        assert_eq!(frame, r#"["EVENT",{"id":"x"}]"#);
    }
}
