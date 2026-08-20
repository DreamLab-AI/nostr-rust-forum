//! The `[mesh]` deployment block (PRD-010 G5/G7/F11/F12).
//!
//! Every substrate exposes the same `[mesh]` table so operators flip federation
//! on without a recompile. PRD-010 §F12 fixes a **flat** schema (a `mode`
//! string plus arrays), *not* a TOML tagged enum — this module deserialises
//! exactly that flat shape, then [`MeshConfig::resolve`] projects it into the
//! ergonomic tri-state [`MeshMode`] (`Standalone | Federated { peers } |
//! Client { relay }`) the transport layer consumes.
//!
//! ```toml
//! [mesh]
//! mode                    = "standalone"   # | "federated" | "client"
//! peer_relays             = []
//! federated_kinds         = [14, 1059, 30033, 30910, 30911, 30912, 30913, 30914, 30915, 30916]
//! federated_pubkeys       = []
//! honor_remote_moderation = []
//! allowed_remote_dids     = []
//! delegation_required     = true
//! # client_relay          = "wss://peer.example.org"   # required only in client mode
//! ```
//!
//! # Ambiguity decision — `client` mode's relay (documented)
//!
//! PRD-010 §G5 describes `client { relay: ... }` but §F12's flat schema has no
//! dedicated relay field. Decision: an optional [`MeshConfig::client_relay`]
//! field names the upstream relay in client mode; when it is absent, the first
//! entry of `peer_relays` is used. If both are empty in client mode,
//! [`MeshConfig::resolve`] fails with [`MeshConfigError::ClientWithoutRelay`]
//! (fail-closed — a client with nowhere to connect is a misconfiguration, not a
//! silent no-op). This keeps §F12's flat wire while honouring §G5's semantics.

use serde::{Deserialize, Serialize};

/// Default federated-kind allowlist (PRD-010 §F11): kind-14 rumor, kind-1059
/// gift-wrap, kind-30033 mesh service-list, and the 30910–30916 moderation
/// range.
pub fn default_federated_kinds() -> Vec<u64> {
    vec![
        14, 1059, 30033, 30910, 30911, 30912, 30913, 30914, 30915, 30916,
    ]
}

fn default_delegation_required() -> bool {
    true
}

fn default_mode() -> String {
    "standalone".to_string()
}

/// The flat `[mesh]` configuration block (PRD-010 §F12).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    /// `"standalone"` | `"federated"` | `"client"`.
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Peer relay `wss://` URLs to federate with (federated mode) or to use as
    /// the upstream (client mode, if `client_relay` is unset).
    #[serde(default)]
    pub peer_relays: Vec<String>,
    /// Event kinds eligible for cross-relay fan-out.
    #[serde(default = "default_federated_kinds")]
    pub federated_kinds: Vec<u64>,
    /// Local actor pubkeys (hex) whose events federate. Empty = all local actors.
    #[serde(default)]
    pub federated_pubkeys: Vec<String>,
    /// Trust-root DIDs whose ban/mute actions are honoured locally.
    #[serde(default)]
    pub honor_remote_moderation: Vec<String>,
    /// Remote peer DIDs whose inbound events are accepted.
    #[serde(default)]
    pub allowed_remote_dids: Vec<String>,
    /// Require a NIP-26 delegation on any cross-system attribution.
    #[serde(default = "default_delegation_required")]
    pub delegation_required: bool,
    /// Upstream relay for `client` mode (see the module-level ambiguity note).
    #[serde(default)]
    pub client_relay: Option<String>,
}

impl Default for MeshConfig {
    fn default() -> Self {
        MeshConfig {
            mode: default_mode(),
            peer_relays: Vec::new(),
            federated_kinds: default_federated_kinds(),
            federated_pubkeys: Vec::new(),
            honor_remote_moderation: Vec::new(),
            allowed_remote_dids: Vec::new(),
            delegation_required: default_delegation_required(),
            client_relay: None,
        }
    }
}

/// The resolved, type-safe federation mode (PRD-010 §G5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshMode {
    /// No federation. The relay serves only local clients.
    Standalone,
    /// This relay federates bidirectionally with the listed peer relays.
    Federated {
        /// Peer relay `wss://` URLs.
        peers: Vec<String>,
    },
    /// This node runs no relay; it speaks to a single upstream relay.
    Client {
        /// The upstream relay `wss://` URL.
        relay: String,
    },
}

/// Errors from parsing or resolving a [`MeshConfig`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MeshConfigError {
    /// `mode` was not one of the three recognised values.
    #[error("mesh config: unknown mode '{0}' (expected standalone|federated|client)")]
    UnknownMode(String),
    /// `federated` mode with an empty `peer_relays`.
    #[error("mesh config: federated mode requires at least one peer relay")]
    FederatedWithoutPeers,
    /// `client` mode with neither `client_relay` nor any `peer_relays`.
    #[error("mesh config: client mode requires client_relay or a peer_relays entry")]
    ClientWithoutRelay,
    /// The TOML document could not be parsed.
    #[error("mesh config: toml parse error: {0}")]
    Toml(String),
}

impl MeshConfig {
    /// Extract the `[mesh]` table from a full `forum.toml` document string.
    /// Returns [`MeshConfig::default`] (standalone) when the table is absent.
    pub fn from_toml_str(doc: &str) -> Result<Self, MeshConfigError> {
        #[derive(Deserialize)]
        struct Doc {
            #[serde(default)]
            mesh: Option<MeshConfig>,
        }
        let parsed: Doc = toml::from_str(doc).map_err(|e| MeshConfigError::Toml(e.to_string()))?;
        Ok(parsed.mesh.unwrap_or_default())
    }

    /// Project the flat config into the type-safe [`MeshMode`], validating the
    /// mode string and its required companions.
    pub fn resolve(&self) -> Result<MeshMode, MeshConfigError> {
        match self.mode.as_str() {
            "standalone" => Ok(MeshMode::Standalone),
            "federated" => {
                if self.peer_relays.is_empty() {
                    Err(MeshConfigError::FederatedWithoutPeers)
                } else {
                    Ok(MeshMode::Federated {
                        peers: self.peer_relays.clone(),
                    })
                }
            }
            "client" => {
                let relay = self
                    .client_relay
                    .clone()
                    .or_else(|| self.peer_relays.first().cloned())
                    .ok_or(MeshConfigError::ClientWithoutRelay)?;
                Ok(MeshMode::Client { relay })
            }
            other => Err(MeshConfigError::UnknownMode(other.to_string())),
        }
    }

    /// Whether federation is active (any non-standalone mode).
    pub fn is_federating(&self) -> bool {
        self.mode != "standalone"
    }

    /// Whether `kind` is eligible for cross-relay fan-out (PRD-010 §F11).
    pub fn is_federated_kind(&self, kind: u64) -> bool {
        self.federated_kinds.contains(&kind)
    }

    /// Whether a local actor `pubkey_hex` federates. An empty
    /// `federated_pubkeys` means "all local actors" (PRD-010 §F11).
    pub fn is_federated_pubkey(&self, pubkey_hex: &str) -> bool {
        self.federated_pubkeys.is_empty() || self.federated_pubkeys.iter().any(|p| p == pubkey_hex)
    }

    /// Whether an inbound peer DID/pubkey is accepted (PRD-010 §F12
    /// `allowed_remote_dids`). Matches against the bare hex or a `did:nostr:`
    /// form.
    pub fn is_allowed_remote(&self, pubkey_hex: &str) -> bool {
        self.allowed_remote_dids
            .iter()
            .any(|d| d == pubkey_hex || d.strip_prefix("did:nostr:") == Some(pubkey_hex))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_block_is_standalone() {
        let cfg = MeshConfig::from_toml_str("[deployment]\nname='x'\n").unwrap();
        assert_eq!(cfg.resolve().unwrap(), MeshMode::Standalone);
        assert!(!cfg.is_federating());
        // default kinds present
        assert!(cfg.is_federated_kind(1059));
    }

    #[test]
    fn standalone_parses() {
        let cfg = MeshConfig::from_toml_str("[mesh]\nmode='standalone'\n").unwrap();
        assert_eq!(cfg.resolve().unwrap(), MeshMode::Standalone);
    }

    #[test]
    fn federated_parses_with_peers() {
        let doc = r#"
            [mesh]
            mode = "federated"
            peer_relays = ["wss://a.example", "wss://b.example"]
            federated_pubkeys = ["deadbeef"]
        "#;
        let cfg = MeshConfig::from_toml_str(doc).unwrap();
        assert_eq!(
            cfg.resolve().unwrap(),
            MeshMode::Federated {
                peers: vec!["wss://a.example".into(), "wss://b.example".into()]
            }
        );
        assert!(cfg.is_federated_pubkey("deadbeef"));
        assert!(!cfg.is_federated_pubkey("cafe"));
    }

    #[test]
    fn federated_without_peers_rejected() {
        let cfg = MeshConfig::from_toml_str("[mesh]\nmode='federated'\n").unwrap();
        assert_eq!(cfg.resolve(), Err(MeshConfigError::FederatedWithoutPeers));
    }

    #[test]
    fn client_uses_client_relay() {
        let doc = r#"
            [mesh]
            mode = "client"
            client_relay = "wss://hub.example"
        "#;
        let cfg = MeshConfig::from_toml_str(doc).unwrap();
        assert_eq!(
            cfg.resolve().unwrap(),
            MeshMode::Client {
                relay: "wss://hub.example".into()
            }
        );
    }

    #[test]
    fn client_falls_back_to_first_peer() {
        let doc = r#"
            [mesh]
            mode = "client"
            peer_relays = ["wss://hub.example"]
        "#;
        let cfg = MeshConfig::from_toml_str(doc).unwrap();
        assert_eq!(
            cfg.resolve().unwrap(),
            MeshMode::Client {
                relay: "wss://hub.example".into()
            }
        );
    }

    #[test]
    fn client_without_relay_rejected() {
        let cfg = MeshConfig::from_toml_str("[mesh]\nmode='client'\n").unwrap();
        assert_eq!(cfg.resolve(), Err(MeshConfigError::ClientWithoutRelay));
    }

    #[test]
    fn unknown_mode_rejected() {
        let cfg = MeshConfig::from_toml_str("[mesh]\nmode='bogus'\n").unwrap();
        assert_eq!(
            cfg.resolve(),
            Err(MeshConfigError::UnknownMode("bogus".into()))
        );
    }

    #[test]
    fn allowed_remote_matches_hex_and_did() {
        let doc = r#"
            [mesh]
            mode = "federated"
            peer_relays = ["wss://a"]
            allowed_remote_dids = ["did:nostr:abcd", "1234"]
        "#;
        let cfg = MeshConfig::from_toml_str(doc).unwrap();
        assert!(cfg.is_allowed_remote("abcd"));
        assert!(cfg.is_allowed_remote("1234"));
        assert!(!cfg.is_allowed_remote("ffff"));
    }
}
