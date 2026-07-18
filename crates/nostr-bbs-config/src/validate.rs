//! Semantic validation beyond serde.

use crate::schema::ForumConfig;

/// Validate a [`ForumConfig`] for semantic correctness.
pub fn validate_config(cfg: &ForumConfig) -> Result<(), String> {
    // hostname must be HTTPS for production deploys (deny http://)
    if !cfg.deployment.hostname.starts_with("https://")
        && !cfg.deployment.hostname.starts_with("http://localhost")
    {
        return Err(format!(
            "deployment.hostname must use https:// (got {})",
            cfg.deployment.hostname
        ));
    }

    // WebAuthn rp_id should be a non-empty domain (not URL).
    if cfg.webauthn.rp_id.is_empty() {
        return Err("webauthn.rp_id must not be empty".into());
    }
    if cfg.webauthn.rp_id.contains("://") {
        return Err(format!(
            "webauthn.rp_id must be a bare domain, not a URL (got {})",
            cfg.webauthn.rp_id
        ));
    }

    // pod.base_url must be HTTPS.
    if !cfg.pod.base_url.starts_with("https://")
        && !cfg.pod.base_url.starts_with("http://localhost")
    {
        return Err(format!(
            "pod.base_url must use https:// (got {})",
            cfg.pod.base_url
        ));
    }

    // relay.url must be wss://
    if !cfg.relay.url.starts_with("wss://") && !cfg.relay.url.starts_with("ws://localhost") {
        return Err(format!("relay.url must use wss:// (got {})", cfg.relay.url));
    }

    // mesh.peer_relays must each use wss:// (or a localhost dev URL), matching the
    // transport-security requirement enforced on relay.url and governance.relay_url.
    // A federation peer reached over plaintext ws:// would expose mesh traffic to
    // tampering and disclosure.
    for peer in &cfg.mesh.peer_relays {
        if !peer.starts_with("wss://") && !peer.starts_with("ws://localhost") {
            return Err(format!(
                "mesh.peer_relays entries must use wss:// (got {peer})"
            ));
        }
    }

    // relay.ingress_policy must be allowlist or open.
    if cfg.relay.ingress_policy != "allowlist" && cfg.relay.ingress_policy != "open" {
        return Err(format!(
            "relay.ingress_policy must be 'allowlist' or 'open' (got {})",
            cfg.relay.ingress_policy
        ));
    }

    // admin.mode must be 'static' or 'd1'.
    if cfg.admin.mode != "static" && cfg.admin.mode != "d1" {
        return Err(format!(
            "admin.mode must be 'static' or 'd1' (got {})",
            cfg.admin.mode
        ));
    }
    if cfg.admin.mode == "static" && cfg.admin.static_pubkeys.is_empty() {
        return Err(
            "admin.mode = 'static' requires at least one entry in admin.static_pubkeys".into(),
        );
    }
    for pk in &cfg.admin.static_pubkeys {
        if pk.len() != 64 || !pk.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("admin.static_pubkeys entry not 64-char hex: {pk}"));
        }
    }

    // moderation kinds_lo <= kinds_hi.
    if cfg.moderation.kinds_lo > cfg.moderation.kinds_hi {
        return Err(format!(
            "moderation.kinds_lo ({}) must be <= kinds_hi ({})",
            cfg.moderation.kinds_lo, cfg.moderation.kinds_hi
        ));
    }

    // mesh.mode must be standalone or federated.
    if cfg.mesh.mode != "standalone" && cfg.mesh.mode != "federated" {
        return Err(format!(
            "mesh.mode must be 'standalone' or 'federated' (got {})",
            cfg.mesh.mode
        ));
    }

    // custody.operator must be tier-1 .. tier-4.
    if !["tier-1", "tier-2", "tier-3", "tier-4"].contains(&cfg.custody.operator.as_str()) {
        return Err(format!(
            "custody.operator must be tier-1, tier-2, tier-3, or tier-4 (got {})",
            cfg.custody.operator
        ));
    }

    // nip05.pod_base_url, when set, must be HTTPS (ADR-086).
    if let Some(url) = cfg.nip05.pod_base_url.as_deref() {
        if !url.starts_with("https://") && !url.starts_with("http://localhost") {
            return Err(format!("nip05.pod_base_url must use https:// (got {url})"));
        }
        if url.ends_with('/') {
            return Err(format!(
                "nip05.pod_base_url must not have a trailing slash (got {url})"
            ));
        }
    }
    // Federated mode without pod_base_url is a configuration error — the
    // fallback fetch has nowhere to go.
    if matches!(
        cfg.nip05.resolver_mode,
        crate::schema::ResolverMode::Federated
    ) && cfg.nip05.pod_base_url.is_none()
    {
        return Err(
            "nip05.resolver_mode = \"federated\" requires nip05.pod_base_url to be set".into(),
        );
    }

    // provision.private_dir must be an absolute container path.
    if !cfg.provision.private_dir.starts_with('/') {
        return Err(format!(
            "provision.private_dir must be an absolute path starting with '/' (got {})",
            cfg.provision.private_dir
        ));
    }
    if cfg.provision.privkey_filename.is_empty() {
        return Err("provision.privkey_filename must not be empty".into());
    }

    // export.rate_limit_per_min, when export is enabled, must be > 0.
    if cfg.export.enabled && cfg.export.rate_limit_per_min == 0 {
        return Err("export.rate_limit_per_min must be > 0 when export.enabled = true".into());
    }

    // git.default_branch must not be empty.
    if cfg.git.default_branch.is_empty() {
        return Err("git.default_branch must not be empty".into());
    }
    // git.clone_url_base, when set, must be HTTPS (or a localhost dev URL).
    if !cfg.git.clone_url_base.is_empty()
        && !cfg.git.clone_url_base.starts_with("https://")
        && !cfg.git.clone_url_base.starts_with("http://localhost")
    {
        return Err(format!(
            "git.clone_url_base must use https:// (got {})",
            cfg.git.clone_url_base
        ));
    }

    // governance.kinds_lo <= kinds_hi.
    if cfg.governance.kinds_lo > cfg.governance.kinds_hi {
        return Err(format!(
            "governance.kinds_lo ({}) must be <= kinds_hi ({})",
            cfg.governance.kinds_lo, cfg.governance.kinds_hi
        ));
    }
    // governance.relay_url, when set, must be wss:// (or localhost dev URL).
    if !cfg.governance.relay_url.is_empty()
        && !cfg.governance.relay_url.starts_with("wss://")
        && !cfg.governance.relay_url.starts_with("ws://localhost")
    {
        return Err(format!(
            "governance.relay_url must use wss:// (got {})",
            cfg.governance.relay_url
        ));
    }
    // governance agent pubkeys must be 64-char hex.
    for pk in &cfg.governance.agent_pubkeys {
        if pk.len() != 64 || !pk.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "governance.agent_pubkeys entry not 64-char hex: {pk}"
            ));
        }
    }
    // Enabling governance with no authorised agents is a foot-gun.
    if cfg.governance.enabled && cfg.governance.agent_pubkeys.is_empty() {
        return Err(
            "governance.enabled = true requires at least one entry in governance.agent_pubkeys"
                .into(),
        );
    }

    // payments: when enabled, the token sub-table (if present) must be coherent.
    if let Some(token) = cfg.payments.token.as_ref() {
        if cfg.payments.enabled && token.ticker.is_empty() {
            return Err(
                "payments.token.ticker must not be empty when payments.enabled = true".into(),
            );
        }
        if token.supply != 0 && token.rate != 0 && token.rate > token.supply {
            return Err(format!(
                "payments.token.rate ({}) must not exceed supply ({})",
                token.rate, token.supply
            ));
        }
    }

    // calendar venues must be non-empty, unique strings.
    {
        let mut seen = std::collections::HashSet::new();
        for venue in &cfg.calendar.shared_venues {
            if venue.trim().is_empty() {
                return Err("calendar.shared_venues entries must not be empty".into());
            }
            if !seen.insert(venue.as_str()) {
                return Err(format!(
                    "calendar.shared_venues contains a duplicate venue: {venue}"
                ));
            }
        }
    }

    // Zone ids must be unique. `ZoneConfig::get` resolves by FIRST match, so a
    // duplicate `[[zones]]` id with weaker required_cohorts/visibility could
    // silently shadow the intended access rule — an operator typo must fail
    // validation, not quietly open (or close) a zone. Also validate accent_hex.
    {
        let mut seen_ids = std::collections::HashSet::new();
        for zone in &cfg.zones {
            if !seen_ids.insert(zone.id.as_str()) {
                return Err(format!(
                    "duplicate zone id '{}' — zone ids must be unique (a duplicate \
                     would silently shadow the intended access rule)",
                    zone.id
                ));
            }
            if let Some(accent) = zone.accent_hex.as_deref() {
                if !is_valid_hex_colour(accent) {
                    return Err(format!(
                        "zone '{}' accent_hex must be a CSS hex colour like #3b82f6 (got {})",
                        zone.id, accent
                    ));
                }
            }
        }
    }

    Ok(())
}

/// True for `#rgb`, `#rrggbb`, or `#rrggbbaa` CSS hex colour strings.
fn is_valid_hex_colour(s: &str) -> bool {
    let Some(hex) = s.strip_prefix('#') else {
        return false;
    };
    matches!(hex.len(), 3 | 6 | 8) && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::*;

    fn baseline_cfg() -> ForumConfig {
        ForumConfig {
            deployment: Deployment {
                name: "Test Forum".into(),
                hostname: "https://example.com".into(),
            },
            webauthn: WebAuthn {
                rp_id: "example.com".into(),
                expected_origin: "https://example.com".into(),
            },
            pod: Pod {
                base_url: "https://pods.example.com".into(),
                storage_backend: "cf-r2".into(),
                r2_bucket: Some("test-pods".into()),
            },
            relay: Relay {
                url: "wss://relay.example.com".into(),
                ingress_policy: "allowlist".into(),
            },
            admin: Admin {
                mode: "static".into(),
                static_pubkeys: vec!["a".repeat(64)],
            },
            branding: Branding::default(),
            zones: Vec::new(),
            trust: Trust::default(),
            invites: Invites::default(),
            moderation: Moderation::default(),
            mesh: Mesh {
                mode: "standalone".into(),
                peer_relays: Vec::new(),
            },
            ratelimit: RateLimit::default(),
            features: Features::default(),
            custody: Custody {
                operator: "tier-2".into(),
            },
            nip05: Nip05::default(),
            native_pod: NativePod {
                enabled: false,
                base_url: "https://pods-native.example.com".into(),
                allowlist_cohorts: Vec::new(),
                git_enabled: true,
                admin_provision_url: String::new(),
            },
            provision: Provision::default(),
            export: Export::default(),
            git: Git::default(),
            governance: Governance::default(),
            payments: Payments::default(),
            calendar: Calendar::default(),
        }
    }

    #[test]
    fn baseline_validates() {
        assert!(validate_config(&baseline_cfg()).is_ok());
    }

    #[test]
    fn http_hostname_rejected() {
        let mut cfg = baseline_cfg();
        cfg.deployment.hostname = "http://example.com".into();
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn rp_id_with_scheme_rejected() {
        let mut cfg = baseline_cfg();
        cfg.webauthn.rp_id = "https://example.com".into();
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn unknown_admin_mode_rejected() {
        let mut cfg = baseline_cfg();
        cfg.admin.mode = "ldap".into();
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn static_admin_with_empty_pubkeys_rejected() {
        let mut cfg = baseline_cfg();
        cfg.admin.static_pubkeys.clear();
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn admin_pubkey_not_hex_rejected() {
        let mut cfg = baseline_cfg();
        cfg.admin.static_pubkeys = vec!["not-hex".into()];
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn unknown_custody_tier_rejected() {
        let mut cfg = baseline_cfg();
        cfg.custody.operator = "tier-99".into();
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn bad_moderation_range_rejected() {
        let mut cfg = baseline_cfg();
        cfg.moderation.kinds_lo = 99999;
        cfg.moderation.kinds_hi = 1000;
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn nip05_default_d1_is_valid_without_pod_url() {
        // Default `resolver_mode = "d1"` and `pod_base_url = None` must
        // validate — existing deployments inherit this implicitly.
        let cfg = baseline_cfg();
        assert!(validate_config(&cfg).is_ok());
        assert_eq!(cfg.nip05.resolver_mode, ResolverMode::D1);
        assert!(cfg.nip05.pod_base_url.is_none());
    }

    #[test]
    fn nip05_federated_without_pod_url_rejected() {
        let mut cfg = baseline_cfg();
        cfg.nip05.resolver_mode = ResolverMode::Federated;
        cfg.nip05.pod_base_url = None;
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn nip05_federated_with_pod_url_validates() {
        let mut cfg = baseline_cfg();
        cfg.nip05.resolver_mode = ResolverMode::Federated;
        cfg.nip05.pod_base_url = Some("https://pods.example.com".into());
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn nip05_pod_url_http_rejected() {
        let mut cfg = baseline_cfg();
        cfg.nip05.pod_base_url = Some("http://pods.example.com".into());
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn nip05_pod_url_trailing_slash_rejected() {
        let mut cfg = baseline_cfg();
        cfg.nip05.pod_base_url = Some("https://pods.example.com/".into());
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn nip05_pod_url_localhost_http_accepted() {
        let mut cfg = baseline_cfg();
        cfg.nip05.pod_base_url = Some("http://localhost:8080".into());
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn nip05_toml_round_trip() {
        // Round-trip: TOML with [nip05] section parses back into the same
        // ResolverMode + pod_base_url values.
        let toml_src = r#"
[deployment]
name = "Test"
hostname = "https://example.com"

[webauthn]
rp_id = "example.com"
expected_origin = "https://example.com"

[pod]
base_url = "https://pods.example.com"
storage_backend = "cf-r2"

[relay]
url = "wss://relay.example.com"
ingress_policy = "allowlist"

[admin]
mode = "static"
static_pubkeys = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]

[mesh]
mode = "standalone"

[custody]
operator = "tier-2"

[nip05]
resolver_mode = "federated"
pod_base_url = "https://pods.example.com"
"#;
        let cfg: ForumConfig = toml::from_str(toml_src).expect("parse");
        assert_eq!(cfg.nip05.resolver_mode, ResolverMode::Federated);
        assert_eq!(
            cfg.nip05.pod_base_url.as_deref(),
            Some("https://pods.example.com")
        );
        validate_config(&cfg).expect("federated config with valid pod_base_url must validate");
    }

    #[test]
    fn nip05_missing_section_defaults_to_d1() {
        let toml_src = r#"
[deployment]
name = "Test"
hostname = "https://example.com"

[webauthn]
rp_id = "example.com"
expected_origin = "https://example.com"

[pod]
base_url = "https://pods.example.com"
storage_backend = "cf-r2"

[relay]
url = "wss://relay.example.com"
ingress_policy = "allowlist"

[admin]
mode = "static"
static_pubkeys = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]

[mesh]
mode = "standalone"

[custody]
operator = "tier-2"
"#;
        let cfg: ForumConfig = toml::from_str(toml_src).expect("parse");
        assert_eq!(cfg.nip05.resolver_mode, ResolverMode::D1);
        assert!(cfg.nip05.pod_base_url.is_none());
    }

    #[test]
    fn new_sections_default_to_valid() {
        // Provision, export, git, governance, payments, calendar all default
        // to a valid (conservative) state on a baseline config.
        let cfg = baseline_cfg();
        assert!(validate_config(&cfg).is_ok());
        assert!(!cfg.provision.enabled);
        assert_eq!(cfg.provision.private_dir, "/private/");
        assert!(!cfg.export.enabled);
        assert_eq!(cfg.export.rate_limit_per_min, 6);
        assert!(!cfg.git.enabled);
        assert_eq!(cfg.git.default_branch, "main");
        assert!(!cfg.governance.enabled);
        assert_eq!(cfg.governance.kinds_lo, 31400);
        assert_eq!(cfg.governance.kinds_hi, 31405);
        assert!(!cfg.payments.enabled);
        assert_eq!(cfg.calendar.shared_venues, vec!["primary", "secondary"]);
    }

    #[test]
    fn provision_relative_private_dir_rejected() {
        let mut cfg = baseline_cfg();
        cfg.provision.private_dir = "private/".into();
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn export_enabled_zero_rate_limit_rejected() {
        let mut cfg = baseline_cfg();
        cfg.export.enabled = true;
        cfg.export.rate_limit_per_min = 0;
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn git_empty_branch_rejected() {
        let mut cfg = baseline_cfg();
        cfg.git.default_branch = String::new();
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn git_http_clone_url_rejected() {
        let mut cfg = baseline_cfg();
        cfg.git.clone_url_base = "http://pods.example.com".into();
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn git_https_clone_url_accepted() {
        let mut cfg = baseline_cfg();
        cfg.git.clone_url_base = "https://pods.example.com".into();
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn governance_bad_kind_range_rejected() {
        let mut cfg = baseline_cfg();
        cfg.governance.kinds_lo = 31405;
        cfg.governance.kinds_hi = 31400;
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn governance_enabled_without_agents_rejected() {
        let mut cfg = baseline_cfg();
        cfg.governance.enabled = true;
        cfg.governance.agent_pubkeys.clear();
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn governance_enabled_with_agent_accepted() {
        let mut cfg = baseline_cfg();
        cfg.governance.enabled = true;
        cfg.governance.agent_pubkeys = vec!["a".repeat(64)];
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn governance_non_hex_agent_rejected() {
        let mut cfg = baseline_cfg();
        cfg.governance.agent_pubkeys = vec!["not-hex".into()];
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn governance_http_relay_url_rejected() {
        let mut cfg = baseline_cfg();
        cfg.governance.relay_url = "https://relay.example.com".into();
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn mesh_plaintext_peer_relay_rejected() {
        let mut cfg = baseline_cfg();
        cfg.mesh.peer_relays = vec!["ws://peer.example.com".into()];
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn mesh_wss_peer_relay_accepted() {
        let mut cfg = baseline_cfg();
        cfg.mesh.peer_relays = vec!["wss://peer.example.com".into()];
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn duplicate_zone_id_rejected() {
        let mut cfg = baseline_cfg();
        let zone: Zone = toml::from_str("id = \"general\"\ndisplay_name = \"General\"").unwrap();
        cfg.zones = vec![zone.clone(), zone];
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn payments_enabled_empty_ticker_rejected() {
        let mut cfg = baseline_cfg();
        cfg.payments.enabled = true;
        cfg.payments.token = Some(PaymentToken {
            ticker: String::new(),
            rate: 10,
            supply: 1000,
            issuer: String::new(),
        });
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn payments_token_rate_exceeds_supply_rejected() {
        let mut cfg = baseline_cfg();
        cfg.payments.enabled = true;
        cfg.payments.token = Some(PaymentToken {
            ticker: "COIN".into(),
            rate: 5000,
            supply: 1000,
            issuer: String::new(),
        });
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn calendar_empty_venue_rejected() {
        let mut cfg = baseline_cfg();
        cfg.calendar.shared_venues = vec!["primary".into(), "  ".into()];
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn calendar_duplicate_venue_rejected() {
        let mut cfg = baseline_cfg();
        cfg.calendar.shared_venues = vec!["primary".into(), "primary".into()];
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn zone_valid_accent_hex_accepted() {
        let mut cfg = baseline_cfg();
        cfg.zones = vec![Zone {
            id: "public".into(),
            display_name: "Public".into(),
            required_cohorts: Vec::new(),
            write_cohorts: None,
            banner_image_url: None,
            accent_hex: Some("#3b82f6".into()),
            visibility: ZoneVisibility::Public,
            encrypted: false,
            auto_approve: false,
        }];
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn zone_bad_accent_hex_rejected() {
        let mut cfg = baseline_cfg();
        cfg.zones = vec![Zone {
            id: "public".into(),
            display_name: "Public".into(),
            required_cohorts: Vec::new(),
            write_cohorts: None,
            banner_image_url: None,
            accent_hex: Some("blue".into()),
            visibility: ZoneVisibility::Public,
            encrypted: false,
            auto_approve: false,
        }];
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn new_sections_toml_round_trip() {
        // A TOML with every new section parses and validates.
        // (r##"…"##: the inner `accent_hex = "#…"` contains `"#`, which would
        // otherwise close an r#"…"# raw string early.)
        let toml_src = r##"
[deployment]
name = "Community Forum"
hostname = "https://forum.example.com"

[webauthn]
rp_id = "forum.example.com"
expected_origin = "https://forum.example.com"

[pod]
base_url = "https://pods.example.com"
storage_backend = "fs"

[relay]
url = "wss://relay.example.com"
ingress_policy = "allowlist"

[admin]
mode = "static"
static_pubkeys = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]

[[zones]]
id = "public"
display_name = "Public"
visibility = "public"
accent_hex = "#3b82f6"

[mesh]
mode = "standalone"

[custody]
operator = "tier-1"

[provision]
enabled = true
keys_at_signup = false

[export]
enabled = false
rate_limit_per_min = 6

[git]
enabled = false
default_branch = "main"
clone_url_base = "https://pods.example.com"

[governance]
enabled = true
agent_pubkeys = ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]

[payments]
enabled = true
cost_sats = 1

[payments.token]
ticker = "COIN"
rate = 10
supply = 1000000

[calendar]
shared_venues = ["primary", "secondary"]
"##;
        let cfg: ForumConfig = toml::from_str(toml_src).expect("parse");
        validate_config(&cfg).expect("validate");
        assert!(cfg.provision.enabled);
        assert!(!cfg.provision.keys_at_signup);
        assert_eq!(cfg.git.default_branch, "main");
        assert!(cfg.governance.enabled);
        assert_eq!(cfg.governance.agent_pubkeys.len(), 1);
        assert!(cfg.payments.enabled);
        assert_eq!(cfg.payments.token.as_ref().unwrap().ticker, "COIN");
        assert_eq!(cfg.calendar.shared_venues, vec!["primary", "secondary"]);
        assert_eq!(cfg.zones[0].accent_hex.as_deref(), Some("#3b82f6"));
    }
}
