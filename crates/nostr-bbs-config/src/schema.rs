//! Strongly-typed TOML schema for `forum.toml`.

use std::collections::BTreeMap;

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
    /// Poker table configuration (stakes, buy-in, assets, house bot).
    #[serde(default)]
    pub poker: Poker,
    /// Zone end-to-end encryption master gate (ADR-2016).
    #[serde(default)]
    pub encryption: Encryption,
}

/// Zone end-to-end encryption master gate (ADR-2016).
///
/// Encryption is dormant unless the operator enables it: a zone is treated as
/// encrypted only when `encryption.enabled && zone.encrypted`. Projected as the
/// plain string env var `ENCRYPTION_ENABLED` (`"true"` / `"false"`) into both the
/// relay worker's `[vars]` and the forum client's `window.__ENV__`; anything
/// other than the exact string `"true"` means off. Turning the gate off stops
/// new messages being encrypted but never makes history unreadable: clients
/// still decrypt `zk`-tagged messages with any key they hold.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Encryption {
    /// Master switch. Default `false`.
    #[serde(default)]
    pub enabled: bool,
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
    /// Stable internal identifier (`"public"`, `"friends"`, `"family"`,
    /// `"business"`, ...). This is the key channels' `section` tags and cohort
    /// rules resolve against — renaming it orphans channels, so it must never
    /// change once deployed. For the URL segment, prefer [`slug`](Self::slug).
    pub id: String,
    /// Optional URL slug (issue #45). When present the client addresses this
    /// zone as `/<slug>` (e.g. `/welcome`, `/dreamlab`) instead of
    /// `/forums/<id>`, keeping the address bar short while the internal
    /// [`id`](Self::id) stays fixed. Validated as lowercase `[a-z0-9-]+`, unique
    /// across zones, and non-colliding with any other zone's `id`. Absent ⇒ the
    /// URL falls back to `id`.
    #[serde(default)]
    pub slug: Option<String>,
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
    /// End-to-end encrypt this zone's channel messages
    /// (`docs/adr/ADR-2016-end-to-end-encrypted-zones.md`): message text
    /// is NIP-44 encrypted to a per-epoch zone key held only by members, and the
    /// relay refuses plaintext posts into the zone. Effective only when the
    /// deployment gate [`Encryption::enabled`] is on. Not allowed on a
    /// `visibility = "public"` zone — anonymous readers can never hold a key.
    #[serde(default)]
    pub encrypted: bool,
    /// Whether members with the `agent` cohort may be granted this zone's key
    /// (ADR-2016). Default `false`: agents are excluded from key grants. Setting
    /// it means the zone's plaintext reaches the agent stack and whatever model
    /// the agent calls — an operator trade-off, made per zone.
    #[serde(default)]
    pub agent_keys: bool,
    /// Auto-approve new joiners into this zone. When `true`, a brand-new user
    /// (first kind-0 auto-whitelist) is automatically granted this zone's
    /// `required_cohorts`, so they land in it without an admin approving them.
    /// When `false` (default), the zone's cohort is admin-granted only. Per-zone,
    /// so an operator can open one zone while keeping others gated. Projected into
    /// the relay's `ZONE_CONFIG` where the relay enforces it at auto-whitelist.
    #[serde(default)]
    pub auto_approve: bool,
    /// Whether this zone offers a collaborative kanban task board. Board data
    /// rides zone-tagged Kanbanstr kinds (30301/30302); read/write follow the
    /// zone's `required_cohorts` / `write_cohorts` exactly like calendar
    /// events. Projected into `ZONE_CONFIG` so the client knows to surface the
    /// board entry; the relay gates by zone tag regardless of this flag.
    #[serde(default)]
    pub kanban: bool,
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
    /// Poker table UI. When `false` the poker route is hidden; the table
    /// parameters themselves live in [`Poker`].
    #[serde(default)]
    pub poker: bool,
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
    /// Public base URL of the native server (e.g. `https://pods-native.example.com`)
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

/// The chain a bare `[poker] citizen_pubkey` names: the house seat it gives
/// settles on `sidestr:dreamlab` (the only chain before the `citizens` map).
pub const LEGACY_CITIZEN_CHAIN: &str = "sidestr:dreamlab";

/// `[poker]` — poker table parameters.
///
/// Stakes and the buy-in are expressed in **big blinds** so a single table
/// definition works across every settlement asset. The UI is gated separately
/// by [`Features::poker`]; this section only describes the tables offered.
/// Projected to the forum client as the JSON object produced by
/// [`to_env_json`](Self::to_env_json) (`window.__ENV__.POKER_CONFIG`).
///
/// Each sidestr chain with an asset table has its own house seat, named in
/// the `citizens` map by chain id. The older scalar `citizen_pubkey` still
/// works and means the house seat of [`LEGACY_CITIZEN_CHAIN`].
///
/// # Example
///
/// ```
/// use nostr_bbs_config::schema::Poker;
///
/// let poker = Poker::default();
/// assert_eq!(poker.buyin_bb, 100);
/// assert_eq!(
///     poker.to_env_json(),
///     r#"{"stakes_bb":[2,10,20,100,200],"buyin_bb":100,"assets":["sats","dream"],"bot_profile":"tag","citizen_pubkey":null,"citizens":{}}"#,
/// );
///
/// // one house seat per chain; the scalar is folded in as sidestr:dreamlab
/// let two: Poker = toml::from_str(&format!(
///     "citizen_pubkey = \"{a}\"\ncitizens = {{ \"sidestr:dreamlab-txbt4\" = \"{b}\" }}\n",
///     a = "aa".repeat(32),
///     b = "bb".repeat(32),
/// ))
/// .unwrap();
/// two.validate().unwrap();
/// assert_eq!(two.citizen_for("sidestr:dreamlab"), Some("aa".repeat(32).as_str()));
/// assert_eq!(two.citizen_for("sidestr:dreamlab-txbt4"), Some("bb".repeat(32).as_str()));
/// let env: serde_json::Value = serde_json::from_str(&two.to_env_json()).unwrap();
/// assert_eq!(env["citizen_pubkey"], "aa".repeat(32));
/// assert_eq!(env["citizens"]["sidestr:dreamlab"], "aa".repeat(32));
/// assert_eq!(env["citizens"]["sidestr:dreamlab-txbt4"], "bb".repeat(32));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Poker {
    /// Big-blind sizes (in the asset's smallest unit) of the tables offered,
    /// in the order the lobby lists them. Defaults to `[2, 10, 20, 100, 200]`.
    #[serde(default = "default_poker_stakes_bb")]
    pub stakes_bb: Vec<u64>,
    /// Buy-in, measured in big blinds of the chosen table. Defaults to `100`.
    #[serde(default = "default_poker_buyin_bb")]
    pub buyin_bb: u64,
    /// Settlement assets a table may be played in, in lobby order. Defaults to
    /// `["sats", "dream"]`.
    #[serde(default = "default_poker_assets")]
    pub assets: Vec<String>,
    /// Playing style of the house bot that fills empty seats (e.g. `"tag"` —
    /// tight-aggressive). Defaults to `"tag"`.
    #[serde(default = "default_poker_bot_profile")]
    pub bot_profile: String,
    /// Optional 64-character lowercase hex pubkey of the citizen (house) agent
    /// of [`LEGACY_CITIZEN_CHAIN`], which seats bots and settles hands. `None`
    /// until the operator provisions one. Kept for configurations written
    /// before [`citizens`](Self::citizens); new ones name the chain there.
    #[serde(default)]
    pub citizen_pubkey: Option<String>,
    /// The house seat of each chain that runs an asset table: sidestr chain
    /// id (`sidestr:<name>`) → 64-character lowercase hex pubkey. Empty by
    /// default.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub citizens: BTreeMap<String, String>,
    /// Optional 64-character lowercase hex pubkey of the coach agent the
    /// practice table asks for advice by DM. `None` hides the coach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coach_pubkey: Option<String>,
}

impl Default for Poker {
    fn default() -> Self {
        Self {
            stakes_bb: default_poker_stakes_bb(),
            buyin_bb: default_poker_buyin_bb(),
            assets: default_poker_assets(),
            bot_profile: default_poker_bot_profile(),
            citizen_pubkey: None,
            citizens: BTreeMap::new(),
            coach_pubkey: None,
        }
    }
}

/// What [`Poker::to_env_json`] writes: the authored section with the house
/// seats resolved.
#[derive(Serialize)]
struct PokerEnv<'a> {
    stakes_bb: &'a [u64],
    buyin_bb: u64,
    assets: &'a [String],
    bot_profile: &'a str,
    citizen_pubkey: Option<&'a str>,
    citizens: BTreeMap<&'a str, &'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    coach_pubkey: Option<&'a str>,
}

fn is_lower_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Poker {
    /// The house seat of `chain_id`: its entry in
    /// [`citizens`](Self::citizens), else, for [`LEGACY_CITIZEN_CHAIN`], the
    /// scalar [`citizen_pubkey`](Self::citizen_pubkey).
    pub fn citizen_for(&self, chain_id: &str) -> Option<&str> {
        self.citizens.get(chain_id).map(String::as_str).or_else(|| {
            (chain_id == LEGACY_CITIZEN_CHAIN)
                .then_some(self.citizen_pubkey.as_deref())
                .flatten()
        })
    }

    /// Every chain's house seat, the scalar folded in as
    /// [`LEGACY_CITIZEN_CHAIN`] when the map does not name that chain.
    pub fn effective_citizens(&self) -> BTreeMap<&str, &str> {
        let mut all: BTreeMap<&str, &str> = self
            .citizens
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        if let Some(pk) = self.citizen_pubkey.as_deref() {
            all.entry(LEGACY_CITIZEN_CHAIN).or_insert(pk);
        }
        all
    }

    /// Render the compact JSON object the forum client reads from
    /// `window.__ENV__.POKER_CONFIG`:
    ///
    /// `{"stakes_bb":[..],"buyin_bb":N,"assets":[..],"bot_profile":"..","citizen_pubkey":null|"..","citizens":{"<chain id>":".."}[,"coach_pubkey":".."]}`
    ///
    /// `citizens` is [`effective_citizens`](Self::effective_citizens), and
    /// `citizen_pubkey` is the house seat of [`LEGACY_CITIZEN_CHAIN`] (from
    /// either source), so a client that reads only the scalar still finds the
    /// DREAM table. Every key is always present (`citizen_pubkey` is `null`
    /// and `citizens` is `{}` when unset), in declaration order, so the deploy
    /// pipeline's hand-synced mirror can be diffed against this output
    /// byte-for-byte. The one exception is `coach_pubkey`, written last and
    /// only when set, so a deployment without a coach projects exactly what
    /// it did before the key existed.
    pub fn to_env_json(&self) -> String {
        let env = PokerEnv {
            stakes_bb: &self.stakes_bb,
            buyin_bb: self.buyin_bb,
            assets: &self.assets,
            bot_profile: &self.bot_profile,
            citizen_pubkey: self.citizen_for(LEGACY_CITIZEN_CHAIN),
            citizens: self.effective_citizens(),
            coach_pubkey: self.coach_pubkey.as_deref(),
        };
        // Plain strings, integers, an `Option<&str>` and a string-keyed map
        // cannot fail to serialise.
        serde_json::to_string(&env).expect("Poker serialises to JSON")
    }

    /// Semantic checks beyond serde: at least one non-zero, unique stake; a
    /// non-zero buy-in; at least one non-empty, unique asset; a non-empty bot
    /// profile; when present, a 64-character lowercase hex `citizen_pubkey`;
    /// every `citizens` key a `sidestr:<name>` chain id and every value a
    /// 64-character lowercase hex pubkey; and, when both the scalar and
    /// `citizens` name the [`LEGACY_CITIZEN_CHAIN`] house seat, the same key;
    /// and, when present, a 64-character lowercase hex `coach_pubkey`.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message naming the offending `poker.*` key.
    pub fn validate(&self) -> Result<(), String> {
        if self.stakes_bb.is_empty() {
            return Err("poker.stakes_bb must list at least one stake".into());
        }
        let mut seen_stakes = std::collections::HashSet::new();
        for &bb in &self.stakes_bb {
            if bb == 0 {
                return Err("poker.stakes_bb entries must be greater than zero".into());
            }
            if !seen_stakes.insert(bb) {
                return Err(format!("poker.stakes_bb contains a duplicate stake: {bb}"));
            }
        }
        if self.buyin_bb == 0 {
            return Err("poker.buyin_bb must be greater than zero".into());
        }
        if self.assets.is_empty() {
            return Err("poker.assets must list at least one asset".into());
        }
        let mut seen_assets = std::collections::HashSet::new();
        for asset in &self.assets {
            if asset.trim().is_empty() {
                return Err("poker.assets entries must not be empty".into());
            }
            if !seen_assets.insert(asset.as_str()) {
                return Err(format!("poker.assets contains a duplicate asset: {asset}"));
            }
        }
        if self.bot_profile.trim().is_empty() {
            return Err("poker.bot_profile must not be empty".into());
        }
        if let Some(pk) = self.citizen_pubkey.as_deref() {
            if !is_lower_hex64(pk) {
                return Err(format!(
                    "poker.citizen_pubkey must be 64-char lowercase hex (got {pk})"
                ));
            }
        }
        for (chain, pk) in &self.citizens {
            let named = chain
                .strip_prefix("sidestr:")
                .is_some_and(|n| !n.is_empty() && !n.contains(char::is_whitespace));
            if !named {
                return Err(format!(
                    "poker.citizens keys must be sidestr chain ids like \"sidestr:dreamlab\" (got {chain:?})"
                ));
            }
            if !is_lower_hex64(pk) {
                return Err(format!(
                    "poker.citizens.\"{chain}\" must be 64-char lowercase hex (got {pk})"
                ));
            }
        }
        if let (Some(scalar), Some(mapped)) = (
            self.citizen_pubkey.as_deref(),
            self.citizens.get(LEGACY_CITIZEN_CHAIN),
        ) {
            if scalar != mapped {
                return Err(format!(
                    "poker.citizen_pubkey and poker.citizens.\"{LEGACY_CITIZEN_CHAIN}\" name different house seats"
                ));
            }
        }
        if let Some(pk) = self.coach_pubkey.as_deref() {
            if !is_lower_hex64(pk) {
                return Err(format!(
                    "poker.coach_pubkey must be 64-char lowercase hex (got {pk})"
                ));
            }
        }
        Ok(())
    }
}

fn default_poker_stakes_bb() -> Vec<u64> {
    vec![2, 10, 20, 100, 200]
}

fn default_poker_buyin_bb() -> u64 {
    100
}

fn default_poker_assets() -> Vec<String> {
    vec!["sats".into(), "dream".into()]
}

fn default_poker_bot_profile() -> String {
    "tag".into()
}

#[cfg(test)]
mod poker_tests {
    use super::*;

    const DEFAULT_JSON: &str = r#"{"stakes_bb":[2,10,20,100,200],"buyin_bb":100,"assets":["sats","dream"],"bot_profile":"tag","citizen_pubkey":null,"citizens":{}}"#;

    #[test]
    fn defaults_match_documented_values() {
        let p = Poker::default();
        assert_eq!(p.stakes_bb, vec![2, 10, 20, 100, 200]);
        assert_eq!(p.buyin_bb, 100);
        assert_eq!(p.assets, vec!["sats", "dream"]);
        assert_eq!(p.bot_profile, "tag");
        assert!(p.citizen_pubkey.is_none());
        assert!(p.validate().is_ok());
    }

    #[test]
    fn empty_section_takes_defaults() {
        let p: Poker = toml::from_str("").expect("parse empty [poker]");
        assert_eq!(p, Poker::default());
    }

    #[test]
    fn feature_flag_defaults_off() {
        let f: Features = toml::from_str("marketplace = true").expect("parse");
        assert!(!f.poker);
        let f: Features = toml::from_str("poker = true").expect("parse");
        assert!(f.poker);
    }

    #[test]
    fn env_json_shape_is_stable() {
        assert_eq!(Poker::default().to_env_json(), DEFAULT_JSON);
        let with_citizen = Poker {
            citizen_pubkey: Some("ab".repeat(32)),
            ..Poker::default()
        };
        let v: serde_json::Value = serde_json::from_str(&with_citizen.to_env_json()).unwrap();
        assert_eq!(v["citizen_pubkey"], serde_json::json!("ab".repeat(32)));
    }

    #[test]
    fn json_and_toml_round_trip() {
        let p = Poker {
            stakes_bb: vec![1, 5],
            buyin_bb: 40,
            assets: vec!["sats".into()],
            bot_profile: "lag".into(),
            citizen_pubkey: Some("0f".repeat(32)),
            citizens: BTreeMap::from([("sidestr:dreamlab-txbt4".into(), "1e".repeat(32))]),
            coach_pubkey: Some("2d".repeat(32)),
        };
        // the projection folds the scalar into the map; read back, it names
        // the same house seats
        let back: Poker = serde_json::from_str(&p.to_env_json()).unwrap();
        assert_eq!(back.effective_citizens(), p.effective_citizens());
        assert_eq!(back.citizen_pubkey, p.citizen_pubkey);
        assert_eq!(back.coach_pubkey, p.coach_pubkey);
        assert_eq!(
            (back.stakes_bb.clone(), back.buyin_bb),
            (p.stakes_bb.clone(), p.buyin_bb)
        );
        let back: Poker = toml::from_str(&toml::to_string(&p).unwrap()).unwrap();
        assert_eq!(back, p);
        // `None` is omitted by TOML and restored by the serde default.
        let back: Poker = toml::from_str(&toml::to_string(&Poker::default()).unwrap()).unwrap();
        assert_eq!(back, Poker::default());
    }

    #[test]
    fn toml_sample_parses() {
        let src = r#"
stakes_bb = [2, 10, 20, 100, 200]
buyin_bb = 100
assets = ["sats", "dream"]
bot_profile = "tag"
citizen_pubkey = "11ed64225dd5e2c5e18f61ad43d5ad9272d08739d3a20dd25886197b0738663c"
"#;
        let p: Poker = toml::from_str(src).expect("parse");
        assert!(p.validate().is_ok());
        assert_eq!(p.citizen_pubkey.as_deref().map(str::len), Some(64));
    }

    #[test]
    fn citizen_pubkey_must_be_64_lowercase_hex() {
        let with = |pk: String| Poker {
            citizen_pubkey: Some(pk),
            ..Poker::default()
        };
        assert!(with("a".repeat(64)).validate().is_ok());
        assert!(with("A".repeat(64)).validate().is_err(), "uppercase");
        assert!(with("a".repeat(63)).validate().is_err(), "short");
        assert!(with("a".repeat(65)).validate().is_err(), "long");
        assert!(with("g".repeat(64)).validate().is_err(), "non-hex");
        assert!(with(String::new()).validate().is_err(), "empty");
    }

    #[test]
    fn citizens_map_names_a_house_seat_per_chain() {
        let src = format!(
            "[citizens]\n\"sidestr:dreamlab\" = \"{}\"\n\"sidestr:dreamlab-txbt4\" = \"{}\"\n",
            "aa".repeat(32),
            "bb".repeat(32)
        );
        let p: Poker = toml::from_str(&src).expect("parse");
        assert!(p.validate().is_ok());
        assert_eq!(
            p.citizen_for("sidestr:dreamlab"),
            Some("aa".repeat(32).as_str())
        );
        assert_eq!(
            p.citizen_for("sidestr:dreamlab-txbt4"),
            Some("bb".repeat(32).as_str())
        );
        assert_eq!(p.citizen_for("sidestr:other"), None);
        let v: serde_json::Value = serde_json::from_str(&p.to_env_json()).unwrap();
        // the legacy key still carries the DREAM table's house seat
        assert_eq!(v["citizen_pubkey"], serde_json::json!("aa".repeat(32)));
        assert_eq!(v["citizens"].as_object().unwrap().len(), 2);
        // and TOML round-trips the map
        let back: Poker = toml::from_str(&toml::to_string(&p).unwrap()).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn the_scalar_means_sidestr_dreamlab_only() {
        let p = Poker {
            citizen_pubkey: Some("cc".repeat(32)),
            ..Poker::default()
        };
        assert_eq!(
            p.citizen_for(LEGACY_CITIZEN_CHAIN),
            Some("cc".repeat(32).as_str())
        );
        assert_eq!(p.citizen_for("sidestr:dreamlab-txbt4"), None);
        assert_eq!(
            p.to_env_json(),
            format!(
                r#"{{"stakes_bb":[2,10,20,100,200],"buyin_bb":100,"assets":["sats","dream"],"bot_profile":"tag","citizen_pubkey":"{0}","citizens":{{"sidestr:dreamlab":"{0}"}}}}"#,
                "cc".repeat(32)
            )
        );
        // a txbt4-only map leaves the legacy key null
        let only = Poker {
            citizens: BTreeMap::from([("sidestr:dreamlab-txbt4".into(), "dd".repeat(32))]),
            ..Poker::default()
        };
        let v: serde_json::Value = serde_json::from_str(&only.to_env_json()).unwrap();
        assert!(v["citizen_pubkey"].is_null());
    }

    #[test]
    fn citizens_entries_are_checked() {
        let with = |chain: &str, pk: String| Poker {
            citizens: BTreeMap::from([(chain.to_string(), pk)]),
            ..Poker::default()
        };
        assert!(with("sidestr:dreamlab-txbt4", "a".repeat(64))
            .validate()
            .is_ok());
        assert!(
            with("dreamlab", "a".repeat(64)).validate().is_err(),
            "not a chain id"
        );
        assert!(
            with("sidestr:", "a".repeat(64)).validate().is_err(),
            "no name"
        );
        assert!(
            with("sidestr:a b", "a".repeat(64)).validate().is_err(),
            "space"
        );
        assert!(
            with("sidestr:x", "A".repeat(64)).validate().is_err(),
            "uppercase"
        );
        assert!(
            with("sidestr:x", "a".repeat(63)).validate().is_err(),
            "short"
        );
        // the scalar and the map must agree on the DREAM table's house seat
        let mut both = with(LEGACY_CITIZEN_CHAIN, "a".repeat(64));
        both.citizen_pubkey = Some("a".repeat(64));
        assert!(both.validate().is_ok());
        both.citizen_pubkey = Some("b".repeat(64));
        assert!(both.validate().is_err());
    }

    #[test]
    fn coach_pubkey_projects_last_and_only_when_set() {
        // absent: the projection is exactly the pre-coach output
        assert_eq!(Poker::default().to_env_json(), DEFAULT_JSON);
        let jarvis = "2de44d5622eef79519ac078f6e227a85aecbaefd561e4e50c5f51dfadbf916e9";
        let p: Poker = toml::from_str(&format!("coach_pubkey = \"{jarvis}\"\n")).unwrap();
        p.validate().unwrap();
        assert_eq!(p.coach_pubkey.as_deref(), Some(jarvis));
        assert_eq!(
            p.to_env_json(),
            format!(
                r#"{{"stakes_bb":[2,10,20,100,200],"buyin_bb":100,"assets":["sats","dream"],"bot_profile":"tag","citizen_pubkey":null,"citizens":{{}},"coach_pubkey":"{jarvis}"}}"#
            ),
        );
        // the client reads the projection back
        let back: Poker = serde_json::from_str(&p.to_env_json()).unwrap();
        assert_eq!(back.coach_pubkey.as_deref(), Some(jarvis));
    }

    #[test]
    fn coach_pubkey_must_be_64_lowercase_hex() {
        let with = |pk: &str| Poker {
            coach_pubkey: Some(pk.to_string()),
            ..Poker::default()
        };
        assert!(with(&"c".repeat(64)).validate().is_ok());
        for bad in [
            "C".repeat(64),
            "c".repeat(63),
            "g".repeat(64),
            String::new(),
        ] {
            let err = with(&bad).validate().unwrap_err();
            assert!(err.contains("poker.coach_pubkey"), "{err}");
        }
    }

    #[test]
    fn degenerate_tables_rejected() {
        let base = Poker::default;
        assert!(Poker {
            stakes_bb: vec![],
            ..base()
        }
        .validate()
        .is_err());
        assert!(Poker {
            stakes_bb: vec![0, 2],
            ..base()
        }
        .validate()
        .is_err());
        assert!(Poker {
            stakes_bb: vec![2, 2],
            ..base()
        }
        .validate()
        .is_err());
        assert!(Poker {
            buyin_bb: 0,
            ..base()
        }
        .validate()
        .is_err());
        assert!(Poker {
            assets: vec![],
            ..base()
        }
        .validate()
        .is_err());
        assert!(Poker {
            assets: vec![" ".into()],
            ..base()
        }
        .validate()
        .is_err());
        assert!(Poker {
            assets: vec!["sats".into(), "sats".into()],
            ..base()
        }
        .validate()
        .is_err());
        assert!(Poker {
            bot_profile: " ".into(),
            ..base()
        }
        .validate()
        .is_err());
    }
}
