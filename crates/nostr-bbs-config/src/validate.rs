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

    Ok(())
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
pod_base_url = "https://pods.dreamlab-ai.com"
"#;
        let cfg: ForumConfig = toml::from_str(toml_src).expect("parse");
        assert_eq!(cfg.nip05.resolver_mode, ResolverMode::Federated);
        assert_eq!(
            cfg.nip05.pod_base_url.as_deref(),
            Some("https://pods.dreamlab-ai.com")
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
}
