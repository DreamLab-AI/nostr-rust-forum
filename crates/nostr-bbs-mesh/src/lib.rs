//! Federation mesh kit for nostr-bbs deployments — the DreamLab mesh reference
//! implementation (PRD-010, ADR-073/074/075).
//!
//! This crate ships the **federation core** for the forum substrate: the
//! unified inter-system message envelope, its wire/crypto pipeline, NIP-26
//! delegation verification, the `[mesh]` deployment config, and a Nostr
//! relay-backed transport that is Cloudflare-Workers-compatible.
//!
//! # Status
//!
//! **Shipped (forum substrate) — 2026-08-15.** Supersedes the prior
//! *"designed, not shipped"* scaffold. The building blocks:
//!
//! | Module | PRD-010 clause | What it does |
//! |--------|----------------|--------------|
//! | [`envelope`]   | G2, F10, F19 | IS-Envelope v1 (ADR-075): serde types, JCS, validate, LDN/AS2 mapping |
//! | [`jcs`]        | ADR-075 §D5  | RFC 8785 (subset) canonicalisation |
//! | [`delegation`] | G5, F8       | NIP-26 delegation verify (ADR-074 §D8) |
//! | [`config`]     | G5, G7, F12  | `[mesh]` block → `standalone \| federated \| client` |
//! | [`transport`]  | §5.2, §5.4   | `MeshTransport` + Nostr relay wire + envelope send/recv + peer/fan-out mgmt |
//! | [`mock`]       | §D15         | In-memory relay for loopback + cross-substrate conformance |
//!
//! The other substrates (VisionClaw Rust, agentbox JS) conform to *this* shape.
//!
//! # Architecture sketch
//!
//! ```text
//!   IS-Envelope (JCS)  ──gift_wrap──▶  kind-1059  ──["EVENT"]──▶  [PeerRelay]
//!        ▲                                                            │
//!        │  validate + delegation/attribution verify                 │ ["EVENT", sub, wrap]
//!        └────────── decode_incoming_wrap ◀──── recv_envelope ◀───────┘
//! ```
//!
//! # CF-Workers compatibility
//!
//! All async is `#[async_trait(?Send)]` and there is no `tokio::spawn`. Byte
//! I/O is abstracted behind [`transport::MeshSocket`]; the CF relay-worker
//! implements it over `worker::WebSocket`, tests over [`mock::MockSocket`].
//!
//! [ADR-073]: https://github.com/DreamLab-AI/nostr-rust-forum/blob/main/docs/adr/ADR-073.md

#![warn(missing_docs)]

pub mod config;
pub mod delegation;
pub mod envelope;
pub mod jcs;
pub mod mock;
pub mod transport;

// ── Primary public surface ───────────────────────────────────────────────────

pub use config::{MeshConfig, MeshConfigError, MeshMode};
pub use delegation::{Conditions, DelegationError, DelegationToken};
pub use envelope::{
    Envelope, EnvelopeError, EnvelopeHint, EnvelopeKind, DEFAULT_TTL_SECS, ENVELOPE_VERSION,
    KIND_MESH_EVENT, KIND_MESH_SERVICES, MAX_BODY_BYTES, MAX_VIA_HOPS,
};
pub use transport::{
    decode_incoming_wrap, MeshError, MeshSocket, MeshTransport, PeerManager, PeerSession,
    ReceiveOptions, ReceivedEnvelope, RelayMessage, RelayTransport, SeenIds, KIND_AUTH,
};

/// Build a kind-30033 mesh anchor event's tag set (ADR-073). Signing +
/// serialisation happen upstream via `nostr-bbs-core`.
///
/// The `d` tag identifies the source relay (canonical hostname); the event
/// content carries a JSON array of the mirrored event ids in the batch.
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
