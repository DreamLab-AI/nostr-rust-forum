//! Runtime configuration, read from `window.__ENV__`.
//!
//! The branded host site injects the same `__ENV__` globals the main forum
//! client uses (`THEME`, `NODE_NAME`, `LOCATION`, `BANNER_URL`, `LOGO_URL`,
//! `RELAY_URL`, `POD_API`, `PREVIEW_API`, `ZONE_CONFIG`, optionally
//! `VIEWER_PUBKEY`). These are projected from `forum.toml`'s `[branding]` /
//! `[[zones]]` / `[relay]` / `[pod]` / `[preview]` sections by
//! `nostr_bbs_config` + the deploy pipeline.
//!
//! Parsing is split into a pure [`BbsConfig::from_env_value`] (unit-tested on the
//! native target) and a thin wasm [`BbsConfig::load`] that reads + stringifies
//! the `__ENV__` object.

use nostr_bbs_config::schema::Zone;
use nostr_bbs_core::BootProfile;
use serde_json::Value;

use crate::theme::Theme;

/// Resolved BBS runtime configuration.
#[derive(Debug, Clone)]
pub struct BbsConfig {
    /// Selected colour theme.
    pub theme: Theme,
    /// Node name shown in the masthead / status bar.
    pub node_name: String,
    /// Strapline rendered under the node name in the banner and the
    /// logged-out landing masthead. Operator branding (`[branding].tagline`);
    /// the kit default stays descriptive and brand-neutral.
    pub tagline: String,
    /// Location string shown in the status bar.
    pub location: String,
    /// Optional ASCII-art / image banner URL.
    pub banner_url: Option<String>,
    /// Optional logo URL.
    pub logo_url: Option<String>,
    /// Relay WebSocket URL (kind-40/42 + governance transport).
    pub relay_url: String,
    /// Solid pod API base URL (WebID, pod-git, storage).
    pub pod_api: String,
    /// Preview-worker base URL — serves `GET /ascii?url=…&cols=…&ramp=…`
    /// image→ASCII fragments for the on-theme image renderer.
    pub preview_api: String,
    /// Search-worker base URL — serves `POST /search` (semantic / keyword
    /// message search) for the global-search palette (F11). Empty → the palette
    /// searches only the live relay stores (boards, members, open-board posts).
    pub search_api: String,
    /// The signed-in viewer's hex pubkey, if the host injected one.
    pub viewer_pubkey: Option<String>,
    /// Config-driven zones (boards), shared with the rest of the kit.
    pub zones: Vec<Zone>,
    /// ADR-109 feature flag (`BBS_PWA_ENABLED` in `__ENV__`). Gates the whole
    /// zone-bound PWA surface: the `?pwa=1` one-shot boot, the service-worker
    /// registration, and any install affordance. **Default off** — the operator
    /// overlay sets it to `"true"` at deploy time; a missing/absent flag disables
    /// the feature so a bare `trunk serve` never boots into pwa mode.
    pub pwa_enabled: bool,
    /// Whether this launch requested the PWA one-shot boot via `?pwa=1` in the
    /// location query (read only in the wasm [`Self::load`]; always `false` in the
    /// pure [`Self::from_env_value`] so unit tests stay deterministic).
    pub pwa_mode: bool,
    /// The device-resident [`BootProfile`] read from `localStorage`, if present
    /// and valid — names the bound zone the installed app pins to. Read only in
    /// the wasm [`Self::load`]; `None` in [`Self::from_env_value`].
    pub boot_profile: Option<BootProfile>,
}

impl Default for BbsConfig {
    fn default() -> Self {
        BbsConfig {
            theme: Theme::Amber,
            node_name: "NOSTR-BBS".to_string(),
            tagline: "retro terminal · did:nostr · Solid pods".to_string(),
            location: "the decentralized frontier".to_string(),
            banner_url: None,
            logo_url: None,
            relay_url: String::new(),
            pod_api: String::new(),
            preview_api: String::new(),
            search_api: String::new(),
            viewer_pubkey: None,
            zones: Vec::new(),
            pwa_enabled: false,
            pwa_mode: false,
            boot_profile: None,
        }
    }
}

/// Read a non-empty string key from the `__ENV__` value.
fn str_key(env: &Value, key: &str) -> Option<String> {
    env.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Read the first present non-empty string among `keys`.
fn first_key(env: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| str_key(env, k))
}

/// Read a boolean feature flag from `__ENV__`, accepting either a real JSON
/// boolean or the string forms `"true"`/`"1"` (case-insensitive) the deploy
/// pipeline emits. Any other value — including a missing key — reads as `false`
/// (fail-closed / default-off, per ADR-109's `BBS_PWA_ENABLED`).
fn env_flag(env: &Value, key: &str) -> bool {
    match env.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => {
            let t = s.trim().to_ascii_lowercase();
            t == "true" || t == "1"
        }
        _ => false,
    }
}

/// Parse `ZONE_CONFIG` (a JSON string or an already-parsed array) into zones.
fn parse_zones(env: &Value) -> Vec<Zone> {
    match env.get("ZONE_CONFIG") {
        Some(Value::String(s)) if !s.trim().is_empty() => {
            serde_json::from_str(s).unwrap_or_default()
        }
        Some(v) if v.is_array() => serde_json::from_value(v.clone()).unwrap_or_default(),
        _ => Vec::new(),
    }
}

impl BbsConfig {
    /// Parse a configuration from a `__ENV__` JSON object. Pure + testable.
    pub fn from_env_value(env: &Value) -> Self {
        let default = BbsConfig::default();
        BbsConfig {
            theme: str_key(env, "THEME")
                .map(|t| Theme::parse(&t))
                .unwrap_or(default.theme),
            node_name: first_key(env, &["NODE_NAME", "FORUM_NAME", "SITE_NAME"])
                .unwrap_or(default.node_name),
            tagline: first_key(env, &["TAGLINE", "STRAPLINE"]).unwrap_or(default.tagline),
            location: str_key(env, "LOCATION").unwrap_or(default.location),
            banner_url: first_key(env, &["BANNER_URL", "BANNER"]),
            logo_url: first_key(env, &["LOGO_URL", "LOGO"]),
            relay_url: first_key(env, &["RELAY_URL", "RELAY"]).unwrap_or_default(),
            pod_api: first_key(env, &["POD_API", "POD_URL", "POD_BASE_URL"]).unwrap_or_default(),
            preview_api: first_key(env, &["PREVIEW_API", "PREVIEW_URL", "PREVIEW_BASE_URL"])
                .unwrap_or_default(),
            search_api: first_key(env, &["SEARCH_API", "SEARCH_URL", "SEARCH_BASE_URL"])
                .unwrap_or_default(),
            viewer_pubkey: first_key(env, &["VIEWER_PUBKEY", "PUBKEY"]),
            zones: parse_zones(env),
            // Feature flag is a pure read of `__ENV__`; the location/localStorage
            // reads that set `pwa_mode` / `boot_profile` live only in wasm `load`.
            pwa_enabled: env_flag(env, "BBS_PWA_ENABLED"),
            pwa_mode: false,
            boot_profile: None,
        }
    }

    /// Load configuration from the live `window.__ENV__` global (wasm).
    #[cfg(target_arch = "wasm32")]
    pub fn load() -> Self {
        let mut cfg = Self::from_env_value(&read_env_value().unwrap_or(Value::Null));
        // Adopt the forum's existing Nostr session. The BBS is served
        // same-origin as the main forum (`/community/bbs/` vs `/community/`),
        // so when the host hasn't injected `VIEWER_PUBKEY` we read the viewer's
        // PUBLIC key from the forum client's localStorage session — logging in
        // once at `/community/` carries into the BBS. Read-only: only the public
        // key is read; the separate private-key entry is never touched.
        if cfg.viewer_pubkey.is_none() {
            cfg.viewer_pubkey = read_forum_session_pubkey();
        }
        // ADR-109 one-shot boot inputs. `?pwa=1` in the launch query marks a PWA
        // boot (the manifest `start_url` carries it); the BootProfile in
        // localStorage names the bound zone. Both are read here — never in the
        // pure `from_env_value` — so the native unit tests stay deterministic.
        let search = web_sys::window()
            .and_then(|w| w.location().search().ok())
            .unwrap_or_default();
        cfg.pwa_mode = nostr_bbs_core::is_pwa_boot(&search);
        cfg.boot_profile = read_boot_profile();
        cfg
    }

    /// Native fallback (e.g. `trunk serve` outside a browser) — defaults only.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn load() -> Self {
        BbsConfig::default()
    }
}

/// localStorage key under which the main forum client persists its session
/// (a `StoredSession` JSON object with a `publicKey` field). Shared with the
/// BBS because both are served from the same origin. Only read on wasm.
#[cfg(target_arch = "wasm32")]
const FORUM_SESSION_KEY: &str = "nostr_bbs_keys";

/// Extract the viewer's public key from the forum client's stored-session JSON.
///
/// Returns `None` when the session is absent or logged out (`publicKey` missing
/// or empty). Only ever reads the PUBLIC key — never any private-key material.
/// Consumed by the wasm `read_forum_session_pubkey`, the signer's NIP-07 adopt
/// path ([`crate::signer::BbsSigner::adopt_forum_session`]), and the unit tests.
pub(crate) fn pubkey_from_session(json: &str) -> Option<String> {
    serde_json::from_str::<Value>(json)
        .ok()?
        .get("publicKey")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Whether the forum client's stored session was established via a NIP-07 browser
/// extension (`"isNip07": true`). These sessions persist no readable
/// `nostr_bbs_sk`, so the BBS adopts them by re-attaching a `Nip07Signer` to the
/// same same-origin `window.nostr` provider rather than importing a raw key.
/// Missing/false/malformed all read as `false` (fail-closed).
pub(crate) fn session_is_nip07(json: &str) -> bool {
    serde_json::from_str::<Value>(json)
        .ok()
        .and_then(|v| v.get("isNip07").and_then(Value::as_bool))
        .unwrap_or(false)
}

/// Read the forum client's raw stored-session JSON from localStorage (wasm).
/// The signer's adopt path parses both `publicKey` and `isNip07` from it via the
/// pure helpers above, so the storage access lives in one place.
#[cfg(target_arch = "wasm32")]
pub(crate) fn read_forum_session_json() -> Option<String> {
    let storage = web_sys::window()?.local_storage().ok()??;
    storage.get_item(FORUM_SESSION_KEY).ok()?
}

/// Read the forum client's session public key from localStorage (wasm).
#[cfg(target_arch = "wasm32")]
fn read_forum_session_pubkey() -> Option<String> {
    pubkey_from_session(&read_forum_session_json()?)
}

/// Read + validate the device-resident [`BootProfile`] from localStorage (wasm).
/// A corrupt or foreign record reads as `None` (never a panic) via
/// [`nostr_bbs_core::parse_boot_profile`]. On iOS's isolated installed-app bucket
/// this is absent on first launch — the one-shot boot then falls through to the
/// rebind screen. Non-secret: the key material lives in IndexedDB, not here.
#[cfg(target_arch = "wasm32")]
fn read_boot_profile() -> Option<BootProfile> {
    use gloo::storage::{LocalStorage, Storage};
    let raw: String = LocalStorage::get(nostr_bbs_core::BOOTPROFILE_KEY).ok()?;
    nostr_bbs_core::parse_boot_profile(&raw)
}

/// Whether this launch should enter the ADR-109 one-shot PWA boot: either the
/// `?pwa=1` query is present, or a valid [`BootProfile`] is stored. Pure so the
/// boot decision is unit-testable; the feature flag (`pwa_enabled`) is applied
/// by the caller (`app.rs`), keeping the gate and the mode read separable.
pub fn boot_is_pwa(pwa_mode: bool, bp: &Option<BootProfile>) -> bool {
    pwa_mode || bp.as_ref().map(BootProfile::validate).unwrap_or(false)
}

/// Read `window.__ENV__`, stringify it, and parse to a JSON [`Value`].
#[cfg(target_arch = "wasm32")]
fn read_env_value() -> Option<Value> {
    let window = web_sys::window()?;
    let env = js_sys::Reflect::get(&window, &"__ENV__".into()).ok()?;
    if env.is_undefined() || env.is_null() {
        return None;
    }
    let json = js_sys::JSON::stringify(&env).ok()?.as_string()?;
    serde_json::from_str(&json).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_when_env_empty() {
        let cfg = BbsConfig::from_env_value(&json!({}));
        assert_eq!(cfg.theme, Theme::Amber);
        assert_eq!(cfg.node_name, "NOSTR-BBS");
        assert_eq!(cfg.tagline, "retro terminal · did:nostr · Solid pods");
        assert!(cfg.relay_url.is_empty());
        assert!(cfg.zones.is_empty());
    }

    #[test]
    fn reads_branding_and_endpoints() {
        let cfg = BbsConfig::from_env_value(&json!({
            "THEME": "green",
            "NODE_NAME": "MINIMOONOIR",
            "TAGLINE": "private secure forums",
            "LOCATION": "Manchester, UK",
            "RELAY_URL": "wss://relay.example.com",
            "POD_API": "https://pods.example.com",
            "PREVIEW_API": "https://preview.example.com",
            "SEARCH_API": "https://search.example.com",
            "VIEWER_PUBKEY": "ab12"
        }));
        assert_eq!(cfg.theme, Theme::Green);
        assert_eq!(cfg.node_name, "MINIMOONOIR");
        assert_eq!(cfg.tagline, "private secure forums");
        assert_eq!(cfg.location, "Manchester, UK");
        assert_eq!(cfg.relay_url, "wss://relay.example.com");
        assert_eq!(cfg.pod_api, "https://pods.example.com");
        assert_eq!(cfg.preview_api, "https://preview.example.com");
        assert_eq!(cfg.search_api, "https://search.example.com");
        assert_eq!(cfg.viewer_pubkey.as_deref(), Some("ab12"));
    }

    #[test]
    fn blank_strings_fall_back_to_defaults() {
        let cfg = BbsConfig::from_env_value(&json!({ "NODE_NAME": "  ", "THEME": "" }));
        assert_eq!(cfg.node_name, "NOSTR-BBS");
        assert_eq!(cfg.theme, Theme::Amber);
    }

    #[test]
    fn parses_zone_config_json_string() {
        let zones = r##"[{"id":"public","display_name":"Public Square","visibility":"public","accent_hex":"#3b82f6"}]"##;
        let cfg = BbsConfig::from_env_value(&json!({ "ZONE_CONFIG": zones }));
        assert_eq!(cfg.zones.len(), 1);
        assert_eq!(cfg.zones[0].id, "public");
        assert_eq!(cfg.zones[0].display_name, "Public Square");
    }

    #[test]
    fn parses_zone_config_array() {
        let cfg = BbsConfig::from_env_value(&json!({
            "ZONE_CONFIG": [{ "id": "friends", "display_name": "Friends" }]
        }));
        assert_eq!(cfg.zones.len(), 1);
        assert_eq!(cfg.zones[0].id, "friends");
    }

    #[test]
    fn forum_session_pubkey_extraction() {
        // A logged-in forum StoredSession (privkey lives elsewhere, never here).
        let pk = "a".repeat(64);
        let json = format!(r#"{{"_v":2,"publicKey":"{pk}","isNip07":true,"nickname":"x"}}"#);
        assert_eq!(pubkey_from_session(&json).as_deref(), Some(pk.as_str()));
        // Logged out / absent / malformed → None (no identity).
        assert_eq!(pubkey_from_session(r#"{"_v":2,"publicKey":null}"#), None);
        assert_eq!(pubkey_from_session(r#"{"_v":2,"publicKey":"  "}"#), None);
        assert_eq!(pubkey_from_session(r#"{"_v":2}"#), None);
        assert_eq!(pubkey_from_session("not json"), None);
    }

    #[test]
    fn forum_session_nip07_detection() {
        // Extension-backed session → true; drives the BBS NIP-07 adopt path.
        assert!(session_is_nip07(
            r#"{"_v":2,"publicKey":"ab","isNip07":true}"#
        ));
        // Local-key / passkey / absent / malformed → false (fail closed).
        assert!(!session_is_nip07(
            r#"{"_v":2,"publicKey":"ab","isNip07":false,"isLocalKey":true}"#
        ));
        assert!(!session_is_nip07(r#"{"_v":2,"publicKey":"ab"}"#));
        assert!(!session_is_nip07(r#"{"_v":2,"isNip07":"yes"}"#));
        assert!(!session_is_nip07("not json"));
    }

    #[test]
    fn pwa_enabled_flag_defaults_off_and_reads_truthy_forms() {
        // Missing / absent → disabled (fail-closed, per ADR-109 override).
        assert!(!BbsConfig::from_env_value(&json!({})).pwa_enabled);
        // The deploy pipeline emits the string "true".
        assert!(BbsConfig::from_env_value(&json!({ "BBS_PWA_ENABLED": "true" })).pwa_enabled);
        assert!(BbsConfig::from_env_value(&json!({ "BBS_PWA_ENABLED": "TRUE" })).pwa_enabled);
        assert!(BbsConfig::from_env_value(&json!({ "BBS_PWA_ENABLED": "1" })).pwa_enabled);
        // A real JSON boolean also works.
        assert!(BbsConfig::from_env_value(&json!({ "BBS_PWA_ENABLED": true })).pwa_enabled);
        // Anything else is off.
        assert!(!BbsConfig::from_env_value(&json!({ "BBS_PWA_ENABLED": "false" })).pwa_enabled);
        assert!(!BbsConfig::from_env_value(&json!({ "BBS_PWA_ENABLED": "no" })).pwa_enabled);
        assert!(!BbsConfig::from_env_value(&json!({ "BBS_PWA_ENABLED": 0 })).pwa_enabled);
    }

    #[test]
    fn from_env_value_never_sets_pwa_mode_or_boot_profile() {
        // The pure parser must not touch location/localStorage — those reads live
        // only in the wasm `load()`, so unit tests stay deterministic.
        let cfg = BbsConfig::from_env_value(&json!({ "BBS_PWA_ENABLED": "true" }));
        assert!(!cfg.pwa_mode);
        assert!(cfg.boot_profile.is_none());
    }

    #[test]
    fn boot_is_pwa_truth_table() {
        use nostr_bbs_core::BootProfile;
        let valid = BootProfile::new("minimoonoir".into(), 1_784_000_000);
        let mut invalid = valid.clone();
        invalid.zone = "  ".into(); // fails validate()
                                    // pwa_mode true → always a pwa boot, regardless of the profile.
        assert!(boot_is_pwa(true, &None));
        assert!(boot_is_pwa(true, &Some(invalid.clone())));
        // A valid BootProfile alone → pwa boot (Android/desktop carry-in).
        assert!(boot_is_pwa(false, &Some(valid)));
        // Neither → not a pwa boot.
        assert!(!boot_is_pwa(false, &None));
        // An invalid BootProfile is not enough on its own.
        assert!(!boot_is_pwa(false, &Some(invalid)));
    }

    #[test]
    fn alternate_endpoint_keys_supported() {
        let cfg = BbsConfig::from_env_value(&json!({
            "POD_URL": "https://p.example",
            "RELAY": "wss://r.example",
            "PREVIEW_URL": "https://prev.example"
        }));
        assert_eq!(cfg.pod_api, "https://p.example");
        assert_eq!(cfg.relay_url, "wss://r.example");
        assert_eq!(cfg.preview_api, "https://prev.example");
    }
}
