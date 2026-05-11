//! Strongly-typed TOML schema for `forum.toml`.

use serde::{Deserialize, Serialize};

/// Top-level forum configuration: one struct per TOML `[section]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForumConfig {
    /// Deployment metadata (name + canonical hostname).
    pub deployment: Deployment,
    /// WebAuthn relying-party configuration.
    pub webauthn: WebAuthn,
    /// Solid pod backend configuration.
    pub pod: Pod,
    /// Nostr relay configuration.
    pub relay: Relay,
    /// Admin pubkey resolution.
    pub admin: Admin,
    /// UI branding (theme + copy + logos).
    #[serde(default)]
    pub branding: Branding,
    /// Zone definitions (display names + access rules).
    #[serde(default)]
    pub zones: Vec<Zone>,
    /// Trust thresholds.
    #[serde(default)]
    pub trust: Trust,
    /// Invite system configuration.
    #[serde(default)]
    pub invites: Invites,
    /// Moderation event-kind range.
    #[serde(default)]
    pub moderation: Moderation,
    /// Federation mesh configuration.
    #[serde(default)]
    pub mesh: Mesh,
    /// Per-route rate-limits.
    #[serde(default)]
    pub ratelimit: RateLimit,
    /// Feature flags.
    #[serde(default)]
    pub features: Features,
    /// Operator custody tier.
    pub custody: Custody,
}

/// Deployment metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deployment {
    /// Human-readable name (e.g. "Nostr BBS Community Forum").
    pub name: String,
    /// Canonical hostname (e.g. `https://example.com`). HTTPS REQUIRED.
    pub hostname: String,
}

/// WebAuthn relying-party configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthn {
    /// Relying party identifier (eTLD+1 of the deployment).
    pub rp_id: String,
    /// Expected origin for assertion / attestation requests.
    pub expected_origin: String,
}

/// Solid pod backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pod {
    /// Pod-API base URL.
    pub base_url: String,
    /// Storage backend identifier (e.g. "cf-r2", "s3", "fs").
    pub storage_backend: String,
    /// Optional R2 bucket name when `storage_backend = "cf-r2"`.
    #[serde(default)]
    pub r2_bucket: Option<String>,
}

/// Nostr relay configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relay {
    /// WebSocket URL (`wss://...`) for the relay.
    pub url: String,
    /// Ingress policy: `"allowlist"` (whitelist required) or `"open"`.
    pub ingress_policy: String,
}

/// Admin pubkey resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Admin {
    /// Admin resolution mode: `"static"` (pubkeys baked into config) or
    /// `"d1"` (resolved from D1 admins table at runtime).
    pub mode: String,
    /// Static admin pubkeys (hex). Used when `mode == "static"`.
    #[serde(default)]
    pub static_pubkeys: Vec<String>,
}

/// UI branding (theme + copy + logos).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Branding {
    /// Theme identifier (e.g. "amber", "blue", "neutral").
    #[serde(default)]
    pub theme: Option<String>,
    /// Logo URL (rendered in header).
    #[serde(default)]
    pub logo_url: Option<String>,
    /// Welcome copy (rendered in onboarding modal).
    #[serde(default)]
    pub welcome_copy: Option<String>,
}

/// Zone definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zone {
    /// Slug identifier (`"home"`, `"members"`, `"private"`, ...).
    pub id: String,
    /// Display name.
    pub display_name: String,
    /// Required cohorts to access this zone.
    #[serde(default)]
    pub required_cohorts: Vec<String>,
}

/// Trust system thresholds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Trust {
    /// Score required to join a moderated channel.
    #[serde(default)]
    pub join_threshold: Option<i32>,
    /// Score required to post in a moderated channel.
    #[serde(default)]
    pub post_threshold: Option<i32>,
}

/// Invite system configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Invites {
    /// Whether invites are enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Welcome bot pubkey (sends DM to newly-onboarded users). Hex.
    #[serde(default)]
    pub welcome_bot_pubkey: Option<String>,
}

/// Moderation event-kind range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Moderation {
    /// Inclusive lower-bound of moderation event kinds.
    pub kinds_lo: u64,
    /// Inclusive upper-bound of moderation event kinds.
    pub kinds_hi: u64,
}

impl Default for Moderation {
    fn default() -> Self {
        // PRD-009 default range: 30910..=30916.
        Self {
            kinds_lo: 30910,
            kinds_hi: 30916,
        }
    }
}

/// Federation mesh configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Mesh {
    /// Federation mode: `"standalone"` or `"federated"`.
    #[serde(default = "default_mesh_mode")]
    pub mode: String,
    /// Peer relay WebSocket URLs for mesh federation.
    #[serde(default)]
    pub peer_relays: Vec<String>,
}

fn default_mesh_mode() -> String {
    "standalone".into()
}

/// Per-route rate-limits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RateLimit {
    /// `/api/profiles/batch` requests per minute per IP.
    #[serde(default)]
    pub profiles_batch_per_min: Option<u32>,
    /// `/.well-known/nostr.json` requests per minute per IP.
    #[serde(default)]
    pub nostr_well_known_per_min: Option<u32>,
}

/// Feature flags.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Features {
    /// Marketplace UI tab.
    #[serde(default)]
    pub marketplace: bool,
    /// Calendar / events UI.
    #[serde(default)]
    pub calendar: bool,
    /// Direct messages UI.
    #[serde(default)]
    pub dms: bool,
}

/// Operator custody tier (per ADR-079 §4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Custody {
    /// Operator tier: `tier-1` (self-host) | `tier-2` (CF Workers Secrets) |
    /// `tier-3` (managed PaaS) | `tier-4` (turnkey hosted).
    pub operator: String,
}
