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
    /// NIP-05 resolution policy (JSS Phase 1; ADR-086).
    #[serde(default)]
    pub nip05: Nip05,
    /// Native solid-pod-rs server (agentbox tier) configuration.
    #[serde(default)]
    pub native_pod: NativePod,
    /// Pod creation / provisioning policy (JSS Phase 1).
    #[serde(default)]
    pub provision: Provision,
    /// Pod data export surface (`/api/exports/*`; JSS Phase 1).
    #[serde(default)]
    pub export: Export,
    /// Git-versioned pods (JSS #471; solid-pod-rs alpha.12).
    #[serde(default)]
    pub git: Git,
    /// Agent governance control-surface configuration (kinds 31400-31405).
    #[serde(default)]
    pub governance: Governance,
    /// Payments / micro-ledger configuration (HTTP 402 + community token).
    #[serde(default)]
    pub payments: Payments,
    /// Shared calendar / venue configuration (NIP-52 events).
    #[serde(default)]
    pub calendar: Calendar,
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
    /// BBS node name shown in the retro ASCII/BBS interface status bar
    /// (e.g. `"DREAMLAB BBS"`). Falls back to the deployment name when unset.
    #[serde(default)]
    pub node_name: Option<String>,
    /// Location string shown in the BBS status bar (e.g. `"Manchester, UK"`).
    #[serde(default)]
    pub location: Option<String>,
    /// Banner image / ASCII-art URL rendered at the top of the BBS interface.
    #[serde(default)]
    pub banner_url: Option<String>,
}

/// Zone visibility for non-members (members and admins always see content).
///
/// - `Public`: listed and readable without auth or cohort membership.
/// - `Locked` (default): listed to everyone as a tile (name + banner) but
///   content is withheld from non-members; channel definitions are still
///   returned so the tile renders.
/// - `Hidden`: omitted entirely for non-members (definitions and content
///   both withheld).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZoneVisibility {
    /// Listed + readable without auth/cohort.
    Public,
    /// Listed as a content-gated tile (default).
    #[default]
    Locked,
    /// Omitted entirely for non-members.
    Hidden,
}

/// Zone definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zone {
    /// Slug identifier (`"public"`, `"friends"`, `"family"`, `"business"`, ...).
    pub id: String,
    /// Display name.
    pub display_name: String,
    /// Cohorts required to READ this zone. Admins bypass this unconditionally.
    /// An empty list combined with `visibility = "public"` means unauthenticated
    /// read; an empty list with any other visibility means admin-only read.
    #[serde(default)]
    pub required_cohorts: Vec<String>,
    /// Cohorts required to WRITE to this zone. When absent, falls back to
    /// `required_cohorts` (read == write). The `public` zone uses this to allow
    /// unauthenticated read while restricting writes to e.g. `["friends"]`.
    #[serde(default)]
    pub write_cohorts: Option<Vec<String>>,
    /// Banner image rendered on the zone tile (including the locked tile shown
    /// to non-members).
    #[serde(default)]
    pub banner_image_url: Option<String>,
    /// Accent colour for this zone tile, as a CSS hex string (e.g. `"#3b82f6"`).
    /// Lets operators theme custom zones from config without editing the client.
    /// When absent, the client falls back to the global [`Branding`] theme.
    #[serde(default)]
    pub accent_hex: Option<String>,
    /// Visibility policy for non-members. See [`ZoneVisibility`].
    #[serde(default)]
    pub visibility: ZoneVisibility,
    /// Whether content in this zone is client-side encrypted (NIP-44). The relay
    /// only records the flag; encryption/decryption is a client concern.
    #[serde(default)]
    pub encrypted: bool,
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
    /// Agent governance UI (control surfaces, kinds 31400-31405). When `false`
    /// the governance route is hidden even if [`Governance::enabled`] is set.
    #[serde(default)]
    pub governance: bool,
}

/// Operator custody tier (per ADR-079 §4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Custody {
    /// Operator tier: `tier-1` (self-host) | `tier-2` (CF Workers Secrets) |
    /// `tier-3` (managed PaaS) | `tier-4` (turnkey hosted).
    pub operator: String,
}

/// NIP-05 resolution mode (JSS Phase 1; ADR-086).
///
/// `D1` (default) preserves the legacy central-registry behaviour:
/// `username_reservations` rows in D1 (mirrored to KV) are the sole source
/// of truth. `Federated` opts in to ADR-086 — on D1/KV miss, the auth-worker
/// falls through to `${pod_base_url}/.well-known/nostr.json?name=<local>`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResolverMode {
    /// D1+KV only; no pod fallback. Forum is authoritative.
    #[default]
    D1,
    /// D1+KV first; on miss, fall through to pod NIP-05 over HTTP.
    Federated,
}

/// NIP-05 resolution policy (JSS Phase 1; ADR-086).
///
/// Additive section. Defaults are conservative: `resolver_mode = "d1"` and
/// `pod_base_url = None` so existing deployments remain bit-for-bit
/// identical. Operators flip `resolver_mode` to `"federated"` once their
/// pod tier serves a real `/.well-known/nostr.json` and they've set
/// `pod_base_url`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Nip05 {
    /// Resolution mode. See [`ResolverMode`].
    #[serde(default)]
    pub resolver_mode: ResolverMode,
    /// Pod root URL (e.g. `https://pods.example.com`) used to build the
    /// fallback fetch when `resolver_mode = "federated"`. The federation
    /// fetch is `${pod_base_url}/.well-known/nostr.json?name=<local>`.
    #[serde(default)]
    pub pod_base_url: Option<String>,
}

/// Native solid-pod-rs server (agentbox tier) configuration.
/// When enabled, users in `allowlist_cohorts` get a second pod on the
/// native server with full git support.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NativePod {
    /// Whether the native (server-Tokio) pod tier is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Public base URL of the native server (e.g. "https://pods-native.example.com")
    #[serde(default)]
    pub base_url: String,
    /// Cohorts eligible for a native pod.  Empty = all authenticated users.
    #[serde(default)]
    pub allowlist_cohorts: Vec<String>,
    /// Whether git features are enabled on this native server.
    #[serde(default = "bool_true")]
    pub git_enabled: bool,
    /// URL the CF auth-worker POSTs to in order to provision a pod on the native server.
    /// Set to "{native_base_url}/_admin/provision/{pubkey}" pattern — auth-worker
    /// fills in the pubkey. Leave blank if admin provisioning is not needed.
    #[serde(default)]
    pub admin_provision_url: String,
}

impl Default for NativePod {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: String::new(),
            allowlist_cohorts: vec![],
            git_enabled: true,
            admin_provision_url: String::new(),
        }
    }
}

fn bool_true() -> bool {
    true
}

/// `[provision]` — pod creation / provisioning policy (JSS Phase 1).
///
/// When [`enabled`](Self::enabled) is `true`, authenticated `POST /.pods` and
/// `/pods/{pubkey}/.provision` requests create the user's Solid pod (WebID
/// profile, TypeIndex documents, media containers). Whether a generated
/// keypair is written into the pod at signup is governed by
/// [`keys_at_signup`](Self::keys_at_signup); deployments that generate keys
/// on-device should leave it `false` so the backend never stores private keys.
///
/// All defaults are conservative: provisioning is OFF unless an operator opts
/// in by adding the block (or setting `enabled = true`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provision {
    /// Master switch for authenticated pod creation. `false` = no pod is
    /// created at signup (legacy behaviour).
    #[serde(default)]
    pub enabled: bool,
    /// When `enabled`, write the generated keypair into the pod at signup.
    /// Leave `false` when keys are generated on-device and the backend must
    /// never store private keys.
    #[serde(default = "bool_true")]
    pub keys_at_signup: bool,
    /// WAC-locked container path on the pod (e.g. `/private/`).
    #[serde(default = "default_private_dir")]
    pub private_dir: String,
    /// NIP-19 bech32 keypair filename written under [`private_dir`](Self::private_dir).
    #[serde(default = "default_privkey_filename")]
    pub privkey_filename: String,
}

impl Default for Provision {
    fn default() -> Self {
        Self {
            enabled: false,
            keys_at_signup: true,
            private_dir: default_private_dir(),
            privkey_filename: default_privkey_filename(),
        }
    }
}

fn default_private_dir() -> String {
    "/private/".into()
}

fn default_privkey_filename() -> String {
    "privkey.jsonld".into()
}

/// `[export]` — pod data export surface (`/api/exports/*`; JSS Phase 1).
///
/// The export surface bundles a member's pod data (and, with owner consent,
/// `/private/*`) into a downloadable archive. It is bandwidth-heavy, so it is
/// rate-limited per-IP and OFF by default. Enable only on a backend that
/// actually serves the export route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    /// Master switch for the export surface.
    #[serde(default)]
    pub enabled: bool,
    /// Default for whether `/private/*` is included when the caller supplies no
    /// explicit query parameter. Owner WAC is always required for private
    /// inclusion regardless of this default.
    #[serde(default)]
    pub include_private_default: bool,
    /// Per-IP rate limit (requests per minute) for the export surface.
    #[serde(default = "default_export_rate_limit")]
    pub rate_limit_per_min: u32,
}

impl Default for Export {
    fn default() -> Self {
        Self {
            enabled: false,
            include_private_default: false,
            rate_limit_per_min: default_export_rate_limit(),
        }
    }
}

fn default_export_rate_limit() -> u32 {
    6
}

/// `[git]` — git-versioned pods (JSS #471; solid-pod-rs alpha.12).
///
/// When [`enabled`](Self::enabled), the pod backend `git init`s each pod at
/// creation with the configured [`default_branch`](Self::default_branch) and
/// `receive.denyCurrentBranch=updateInstead`, giving members a per-pod audit
/// trail and easy backup. Backends that cannot spawn subprocesses (e.g.
/// serverless Workers) must leave this disabled; native backends flip it on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Git {
    /// Master switch. Leave `false` on backends that cannot spawn subprocesses.
    #[serde(default)]
    pub enabled: bool,
    /// Informational — automatically `git init` each new pod when
    /// [`enabled`](Self::enabled) is `true`.
    #[serde(default = "bool_true")]
    pub auto_init: bool,
    /// Default branch name for newly-initialised pod repositories.
    #[serde(default = "default_git_default_branch")]
    pub default_branch: String,
    /// Base URL surfaced to the forum-client for `git clone` instructions.
    /// Empty string disables the UI hint.
    #[serde(default)]
    pub clone_url_base: String,
}

impl Default for Git {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_init: true,
            default_branch: default_git_default_branch(),
            clone_url_base: String::new(),
        }
    }
}

fn default_git_default_branch() -> String {
    "main".into()
}

/// `[governance]` — agent governance control surfaces (kinds 31400-31405).
///
/// Pre-registered agent pubkeys are authorised to publish governance control
/// panels (kind 31400) and action requests (kind 31402). The forum exposes a
/// governance route when [`enabled`](Self::enabled) is `true`. Disabled by
/// default; operators populate [`agent_pubkeys`](Self::agent_pubkeys) at
/// deploy time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Governance {
    /// Master switch for the governance control surface.
    #[serde(default)]
    pub enabled: bool,
    /// Client route under which the governance UI is mounted (e.g. `/governance`).
    #[serde(default = "default_governance_route")]
    pub route: String,
    /// Inclusive lower-bound of governance event kinds.
    #[serde(default = "default_governance_kinds_lo")]
    pub kinds_lo: u64,
    /// Inclusive upper-bound of governance event kinds.
    #[serde(default = "default_governance_kinds_hi")]
    pub kinds_hi: u64,
    /// Relay URL for governance events. Empty = reuse the main [`Relay`].
    #[serde(default)]
    pub relay_url: String,
    /// Agent pubkeys (hex) allowed to publish control-surface events.
    #[serde(default)]
    pub agent_pubkeys: Vec<String>,
}

impl Default for Governance {
    fn default() -> Self {
        Self {
            enabled: false,
            route: default_governance_route(),
            kinds_lo: default_governance_kinds_lo(),
            kinds_hi: default_governance_kinds_hi(),
            relay_url: String::new(),
            agent_pubkeys: Vec::new(),
        }
    }
}

fn default_governance_route() -> String {
    "/governance".into()
}

fn default_governance_kinds_lo() -> u64 {
    31400
}

fn default_governance_kinds_hi() -> u64 {
    31405
}

/// `[payments]` — HTTP 402 micro-ledger + optional community token.
///
/// Lets a deployment gate paid actions behind a per-action sats cost and,
/// optionally, mint a community token at a fixed rate against sats. Disabled
/// by default; the `[payments.token]` sub-table is purely descriptive metadata
/// surfaced to the client.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Payments {
    /// Master switch for paid actions.
    #[serde(default)]
    pub enabled: bool,
    /// Default cost (in sats) of a paid action.
    #[serde(default)]
    pub cost_sats: u64,
    /// Optional community token metadata.
    #[serde(default)]
    pub token: Option<PaymentToken>,
}

/// `[payments.token]` — descriptive community-token metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PaymentToken {
    /// Ticker symbol (e.g. `"COIN"`).
    #[serde(default)]
    pub ticker: String,
    /// Token units minted per sat.
    #[serde(default)]
    pub rate: u64,
    /// Total supply cap.
    #[serde(default)]
    pub supply: u64,
    /// Issuer pubkey/identifier. Empty until the operator sets it at deploy time.
    #[serde(default)]
    pub issuer: String,
}

/// `[calendar]` — shared calendar / venue configuration (NIP-52 events).
///
/// A deployment can expose one or more shared **venues** — named buckets that
/// scheduled NIP-52 events (kinds 31922/31923) are filed under. The venue model
/// keeps cross-zone scheduling tidy: a calendar bot writes an event tagged with
/// a venue from [`shared_venues`](Self::shared_venues), and the client groups
/// the agenda by venue. Operators name venues however they like (rooms,
/// channels, physical spaces); the default is two generic slots so the calendar
/// renders out-of-the-box.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Calendar {
    /// Named venues that scheduled events are filed under. Order is preserved
    /// and surfaced as the agenda's column/tab order. Defaults to
    /// `["primary", "secondary"]`.
    #[serde(default = "default_shared_venues")]
    pub shared_venues: Vec<String>,
}

impl Default for Calendar {
    fn default() -> Self {
        Self {
            shared_venues: default_shared_venues(),
        }
    }
}

fn default_shared_venues() -> Vec<String> {
    vec!["primary".into(), "secondary".into()]
}
