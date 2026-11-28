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

    // poker: coherent tables and a well-formed citizen pubkey.
    cfg.poker.validate()?;

    // ingress: well-formed, unique recipients for end-to-end-encrypted form traffic.
    crate::ingress::validate_ingress(&cfg.ingress)?;

    // Zone ids must be unique. `ZoneConfig::get` resolves by FIRST match, so a
    // duplicate `[[zones]]` id with weaker required_cohorts/visibility could
    // silently shadow the intended access rule — an operator typo must fail
    // validation, not quietly open (or close) a zone. Also validate accent_hex
    // and the optional URL slug (issue #45).
    {
        // Full id set up front so a slug can be checked against EVERY zone id,
        // not just the ones seen earlier in the loop.
        let all_ids: std::collections::HashSet<&str> =
            cfg.zones.iter().map(|z| z.id.as_str()).collect();
        let mut seen_ids = std::collections::HashSet::new();
        let mut seen_slugs = std::collections::HashSet::new();
        for zone in &cfg.zones {
            if !seen_ids.insert(zone.id.as_str()) {
                return Err(format!(
                    "duplicate zone id '{}' — zone ids must be unique (a duplicate \
                     would silently shadow the intended access rule)",
                    zone.id
                ));
            }
            // ADR-2016: a public zone is readable by anonymous visitors, who can
            // never hold a zone key, so it cannot be end-to-end encrypted.
            // Search mode (sealed-search design): a server index of an
            // encrypted zone would hand its plaintext to the server.
            if let Some(mode) = zone.search {
                use crate::schema::SearchMode;
                if zone.encrypted && mode == SearchMode::Server {
                    return Err(format!(
                        "zone '{}' has encrypted = true but search = \"server\" — a server-side \
                         index would expose the zone's plaintext to the server; use \
                         search = \"sealed\" (browser-side) or \"off\"",
                        zone.id
                    ));
                }
                if !zone.encrypted && mode == SearchMode::Sealed {
                    return Err(format!(
                        "zone '{}' has search = \"sealed\" but is not encrypted — sealed search \
                         needs a zone key; use search = \"server\" or \"off\"",
                        zone.id
                    ));
                }
                if zone.visibility == crate::schema::ZoneVisibility::Public
                    && mode != SearchMode::Off
                {
                    return Err(format!(
                        "zone '{}' is public; public zones get no search (search must be \"off\")",
                        zone.id
                    ));
                }
            }
            if zone.encrypted && zone.visibility == crate::schema::ZoneVisibility::Public {
                return Err(format!(
                    "zone '{}' has encrypted = true but visibility = \"public\" — a public \
                     zone cannot be end-to-end encrypted (anonymous readers can never hold \
                     a key); make it locked or hidden, or set encrypted = false",
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
            // ADR-2028: the NIP-171 group binding must be 64-char lowercase hex
            // (it is compared byte-for-byte against event pubkeys, which are
            // lowercase hex), and it only has meaning on an encrypted zone — a
            // binding on a plaintext zone signals a config mistake, not an
            // intent, so it is rejected rather than silently ignored.
            if let Some(gp) = zone.group_pubkey.as_deref() {
                if gp.len() != 64
                    || !gp
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                {
                    return Err(format!(
                        "zone '{}' group_pubkey must be 64-char lowercase hex (got {})",
                        zone.id, gp
                    ));
                }
                if !zone.encrypted {
                    return Err(format!(
                        "zone '{}' has a group_pubkey but encrypted = false — the NIP-171 \
                         group binding only applies to an end-to-end encrypted zone; remove \
                         the binding or set encrypted = true",
                        zone.id
                    ));
                }
            }
            // Slug (issue #45): the client resolves a URL segment to a zone by
            // slug-or-id, so a slug must be a clean URL segment, unique, and must
            // not equal a *different* zone's id (which would make one URL resolve
            // to two zones). A slug equal to its own id is a harmless identity.
            if let Some(slug) = zone.slug.as_deref() {
                if !is_valid_slug(slug) {
                    return Err(format!(
                        "zone '{}' slug must be lowercase letters, digits, and hyphens \
                         ([a-z0-9-]+) (got {})",
                        zone.id, slug
                    ));
                }
                if !seen_slugs.insert(slug) {
                    return Err(format!(
                        "duplicate zone slug '{slug}' — zone slugs must be unique"
                    ));
                }
                if slug != zone.id && all_ids.contains(slug) {
                    return Err(format!(
                        "zone '{}' slug '{}' collides with another zone's id — a slug must \
                         not shadow a different zone",
                        zone.id, slug
                    ));
                }
            }
        }
        validate_channel_pins(&cfg.zones)?;
    }

    for host in &cfg.preview.allowed_hosts {
        if let Err(why) = preview_host_problem(host) {
            return Err(format!("preview.allowed_hosts entry '{host}' {why}"));
        }
    }

    for pk in &cfg.search_archivists {
        if pk.len() != 64
            || !pk
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(format!(
                "search_archivists entry '{pk}' is not 64-char lowercase hex"
            ));
        }
    }
    Ok(())
}

/// Suffixes under which anyone can register or publish a host. Listing one
/// would let any such host through, so an entry must name a site beneath it.
/// A guard against the common mistakes, not a full public-suffix list.
const OPEN_SUFFIXES: &[&str] = &[
    "ac.uk",
    "co.jp",
    "co.nz",
    "co.uk",
    "com.au",
    "com.br",
    "github.io",
    "gov.uk",
    "herokuapp.com",
    "netlify.app",
    "org.uk",
    "pages.dev",
    "vercel.app",
    "web.app",
    "workers.dev",
];

/// Names that never resolve on the public internet.
const PRIVATE_SUFFIXES: &[&str] = &[
    "arpa",
    "home",
    "internal",
    "lan",
    "local",
    "localdomain",
    "localhost",
    "onion",
    "test",
];

/// Why `host` is not acceptable in `preview.allowed_hosts`, if it is not.
///
/// An entry is a bare public hostname: lower-case ASCII labels separated by
/// dots, at least two of them, with no scheme, port, path, wildcard or IP
/// address, and not a private-use or open-registration suffix.
fn preview_host_problem(host: &str) -> Result<(), &'static str> {
    if host.is_empty() || host.len() > 253 {
        return Err("must be a hostname of 1 to 253 characters");
    }
    if host.contains("://") || host.contains('/') {
        return Err("must be a bare hostname, without a scheme or path");
    }
    if host.contains(':') {
        return Err("must not carry a port or be an IPv6 address");
    }
    if host.contains('*') {
        return Err("must not use a wildcard (an entry already covers its subdomains)");
    }
    let labels: Vec<&str> = host.split('.').collect();
    let label_ok = |l: &&str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if !labels.iter().all(label_ok) {
        return Err("must be lower-case letters, digits and hyphens in dot-separated labels");
    }
    if labels.len() < 2 {
        return Err("must have at least two labels (a bare top-level name covers too much)");
    }
    let last = labels[labels.len() - 1];
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return Err("must be a hostname, not an IP address");
    }
    if PRIVATE_SUFFIXES.contains(&last) {
        return Err("is a private-use name the worker never fetches");
    }
    if OPEN_SUFFIXES.contains(&host) {
        return Err("is an open-registration suffix; list the specific site beneath it");
    }
    Ok(())
}

/// Keys an operator plausibly writes when meaning `channels` (ADR-2037),
/// compared case-insensitively.
const PIN_KEY_MISSPELLINGS: &[&str] = &["channel", "pin", "pins", "pinned", "pinned_channels"];

/// Whether a zone key looks like a misspelt `channels` (ADR-2037): one of a
/// short list of likely alternatives (`channel`, `pin`, `pins`, `pinned`,
/// `pinned_channels`), or within edit distance 2 of `channels`, in either
/// case, but never `channels` itself. Unrelated keys that merely contain
/// "pin" or "channel" (`mapping`, `channel_order`, `default_channel`) do not
/// match. The relay worker uses this same rule and fails such pins closed.
pub fn is_misspelt_pin_key(key: &str) -> bool {
    if key == "channels" {
        return false;
    }
    let k = key.to_ascii_lowercase();
    PIN_KEY_MISSPELLINGS.contains(&k.as_str()) || edit_distance(&k, "channels") <= 2
}

/// Levenshtein distance over bytes (keys are ASCII in practice).
fn edit_distance(a: &str, b: &str) -> usize {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            let sub = prev[j] + usize::from(ca != cb);
            cur[j + 1] = sub.min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        prev = cur;
    }
    prev[b.len()]
}

/// Refuse a `zones` array (as JSON: the `[[zones]]` tables of a `forum.toml`,
/// or a `ZONE_CONFIG` value) any of whose zones carries a misspelt pin key.
///
/// # Errors
///
/// A message naming the zone and the key.
pub fn check_zone_pin_keys(zones: &serde_json::Value) -> Result<(), String> {
    for z in zones.as_array().into_iter().flatten() {
        let Some(obj) = z.as_object() else { continue };
        let id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        if let Some(key) = obj.keys().find(|k| is_misspelt_pin_key(k)) {
            return Err(format!(
                "zone '{id}' has unknown key '{key}' — did you mean 'channels'? (an \
                 unrecognised pin key would leave the channel in its old zone)"
            ));
        }
    }
    Ok(())
}

/// Every key a [`crate::schema::Zone`] serialises when all its fields are
/// set. A test serialises a fully populated zone and checks this list against
/// it, so it cannot drift from the schema.
pub const ZONE_SCHEMA_KEYS: &[&str] = &[
    "id",
    "slug",
    "display_name",
    "required_cohorts",
    "write_cohorts",
    "banner_image_url",
    "accent_hex",
    "visibility",
    "encrypted",
    "agent_keys",
    "history_from_epoch",
    "group_pubkey",
    "auto_approve",
    "kanban",
    "search",
    "channels",
];

/// Zone keys a deployed `ZONE_CONFIG` legitimately carries that the config
/// schema does not model: `section_order` is read only by the clients
/// (`nostr_bbs_client_core::stores::zones::Zone::section_order`) and is in
/// every live projection.
pub const CLIENT_ONLY_ZONE_KEYS: &[&str] = &["section_order"];

/// Check a `ZONE_CONFIG` JSON value as deployed (ADR-2037): misspelt pin
/// keys, malformed or duplicate `channels` entries, and pinning zone ids that
/// extend another zone's id. Use it on a hand-edited projection before it is
/// handed to the workers; `forum.toml` gets the same checks on load.
///
/// # Errors
///
/// Invalid JSON or the first pin problem found.
pub fn validate_zone_config_json(raw: &str) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("ZONE_CONFIG is not valid JSON: {e}"))?;
    check_zone_pin_keys(&value)?;
    // Strict about keys here (the workers stay tolerant): any key that is
    // not a schema field or a known client-only field is refused, since the
    // workers would silently ignore it, and an ignored pin key leaves the
    // channel in its old zone.
    for z in value.as_array().into_iter().flatten() {
        let Some(obj) = z.as_object() else { continue };
        let id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        if let Some(key) = obj.keys().find(|k| {
            !ZONE_SCHEMA_KEYS.contains(&k.as_str()) && !CLIENT_ONLY_ZONE_KEYS.contains(&k.as_str())
        }) {
            return Err(format!(
                "zone '{id}' has unknown key '{key}': the workers would ignore it (known keys: {})",
                ZONE_SCHEMA_KEYS
                    .iter()
                    .chain(CLIENT_ONLY_ZONE_KEYS)
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    let zones: Vec<crate::schema::Zone> = value
        .as_array()
        .ok_or("ZONE_CONFIG must be a JSON array")?
        .iter()
        .map(|z| {
            let mut z = z.clone();
            // The projection's other fields are not this check's concern;
            // fill the one required field the workers do not need.
            if let Some(obj) = z.as_object_mut() {
                obj.entry("display_name")
                    .or_insert(serde_json::Value::String(String::new()));
            }
            serde_json::from_value(z).map_err(|e| format!("ZONE_CONFIG zone: {e}"))
        })
        .collect::<Result<_, String>>()?;
    validate_channel_pins(&zones)
}

/// ADR-2037 channel pins (`[[zones]] channels`): every entry is a kind-40
/// event id (64-char lowercase hex), no channel is listed twice, and a zone
/// that pins channels does not have an id of the form `<other zone id>-…`.
///
/// The last rule exists because the clients resolve a section to a zone by
/// exact id or by the first `<zone id>-` prefix in config order, and media
/// uploads use the prefix rule alone: a channel pinned to `staff-only` while a
/// zone `staff` exists would have its uploads filed under `staff`.
fn validate_channel_pins(zones: &[crate::schema::Zone]) -> Result<(), String> {
    let mut owner: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for zone in zones {
        for id in &zone.channels {
            let well_formed =
                id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
            if !well_formed {
                return Err(format!(
                    "zone '{}' channels entry '{}' must be a kind-40 event id: 64-char \
                     lowercase hex",
                    zone.id, id
                ));
            }
            if let Some(prev) = owner.insert(id.as_str(), zone.id.as_str()) {
                return Err(if prev == zone.id {
                    format!("zone '{}' lists channel {id} twice", zone.id)
                } else {
                    format!(
                        "channel {id} is pinned by both zone '{prev}' and zone '{}' — a \
                         channel can belong to one zone only",
                        zone.id
                    )
                });
            }
        }
        if zone.channels.is_empty() {
            continue;
        }
        if let Some(shadow) = zones
            .iter()
            .find(|z| z.id != zone.id && zone.id.starts_with(&format!("{}-", z.id)))
        {
            return Err(format!(
                "zone '{}' pins channels but its id starts with '{}-', so clients would \
                 file the pinned channels' media under zone '{}'; give the zone an id \
                 that does not extend another zone's",
                zone.id, shadow.id, shadow.id
            ));
        }
    }
    Ok(())
}

/// True for a non-empty lowercase URL slug: `[a-z0-9-]+`.
fn is_valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
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
            search_archivists: Vec::new(),
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
            poker: Poker::default(),
            preview: Preview::default(),
            encryption: Encryption::default(),
            ingress: Vec::new(),
        }
    }

    #[test]
    fn baseline_validates() {
        assert!(validate_config(&baseline_cfg()).is_ok());
    }

    #[test]
    fn preview_hosts_must_be_bare_public_hostnames() {
        let ok = |h: &str| {
            let mut cfg = baseline_cfg();
            cfg.preview.allowed_hosts = vec![h.into()];
            validate_config(&cfg)
        };
        for good in [
            "wikipedia.org",
            "bbc.co.uk",
            "youtu.be",
            "my-forum.example.com",
            "x.com",
        ] {
            assert!(ok(good).is_ok(), "{good} should be accepted");
        }
        for bad in [
            "",
            "https://github.com",
            "github.com/owner",
            "github.com:443",
            "*.github.com",
            "GitHub.com",
            "github.com.",
            "com",
            "10.0.0.1",
            "[::1]",
            "localhost",
            "router.lan",
            "printer.local",
            "co.uk",
            "github.io",
            "workers.dev",
            "-bad.example.com",
            "bad..example.com",
            "exa mple.com",
        ] {
            let err = ok(bad).expect_err(&format!("{bad:?} should be refused"));
            assert!(err.contains("preview.allowed_hosts"), "{err}");
        }
    }

    #[test]
    fn preview_hosts_project_in_canonical_form() {
        let p = Preview {
            allowed_hosts: vec![
                "youtube.com".into(),
                "wikipedia.org".into(),
                "en.wikipedia.org".into(),
                "youtube.com".into(),
                "bbc.co.uk".into(),
                // Not a subdomain of bbc.co.uk: kept.
                "notbbc.co.uk".into(),
            ],
        };
        assert_eq!(
            p.canonical_hosts(),
            vec!["bbc.co.uk", "notbbc.co.uk", "wikipedia.org", "youtube.com"]
        );
        assert_eq!(
            p.allowed_hosts_var(),
            "bbc.co.uk, notbbc.co.uk, wikipedia.org, youtube.com"
        );
        // No list: an empty var, which the worker treats as "refuse all".
        assert_eq!(Preview::default().allowed_hosts_var(), "");
    }

    #[test]
    fn preview_section_parses_from_toml_and_defaults_to_empty() {
        let with = "[preview]\nallowed_hosts = [\"wikipedia.org\", \"github.com\"]\n";
        let p: Preview = toml::from_str::<toml::Value>(with)
            .unwrap()
            .get("preview")
            .cloned()
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(p.allowed_hosts_var(), "github.com, wikipedia.org");
        assert!(baseline_cfg().preview.allowed_hosts.is_empty());
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
    fn ingress_is_validated_with_the_whole_config() {
        let mut cfg = baseline_cfg();
        assert!(validate_config(&cfg).is_ok(), "empty ingress is valid");
        cfg.ingress.push(crate::ingress::IngressRecipient {
            label: "inbox".into(),
            pubkey: "not-hex".into(),
            role: crate::ingress::IngressRole::Primary,
            description: String::new(),
            authorised_by: String::new(),
        });
        let err = validate_config(&cfg).unwrap_err();
        assert!(err.contains("ingress[0].pubkey"), "{err}");
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
        assert!(!cfg.features.poker);
        assert_eq!(cfg.poker, Poker::default());
    }

    #[test]
    fn poker_bad_citizen_pubkey_rejected() {
        let mut cfg = baseline_cfg();
        cfg.poker.citizen_pubkey = Some("B".repeat(64));
        assert!(validate_config(&cfg).is_err());
        cfg.poker.citizen_pubkey = Some("b".repeat(64));
        assert!(validate_config(&cfg).is_ok());
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

    fn zone_for_encryption(visibility: ZoneVisibility, encrypted: bool) -> Zone {
        Zone {
            id: "family".into(),
            slug: None,
            display_name: "Family".into(),
            required_cohorts: vec!["family".into()],
            write_cohorts: None,
            banner_image_url: None,
            accent_hex: None,
            visibility,
            encrypted,
            agent_keys: false,
            history_from_epoch: None,
            auto_approve: false,
            kanban: false,
            search: None,
            group_pubkey: None,
            channels: Vec::new(),
        }
    }

    #[test]
    fn encrypted_public_zone_is_rejected() {
        let mut cfg = baseline_cfg();
        cfg.zones = vec![zone_for_encryption(ZoneVisibility::Public, true)];
        let err = validate_config(&cfg).unwrap_err();
        assert!(err.contains("cannot be end-to-end encrypted"), "{err}");
    }

    #[test]
    fn zone_group_pubkey_validated() {
        let hex64 = "a".repeat(64);
        // Valid 64-char lowercase hex on an encrypted zone: accepted.
        let mut cfg = baseline_cfg();
        let mut z = zone_for_encryption(ZoneVisibility::Locked, true);
        z.group_pubkey = Some(hex64.clone());
        cfg.zones = vec![z];
        assert!(validate_config(&cfg).is_ok());

        // Uppercase hex: rejected (pubkeys are compared as lowercase hex).
        let mut cfg = baseline_cfg();
        let mut z = zone_for_encryption(ZoneVisibility::Locked, true);
        z.group_pubkey = Some("A".repeat(64));
        cfg.zones = vec![z];
        assert!(validate_config(&cfg)
            .unwrap_err()
            .contains("group_pubkey must be 64-char lowercase hex"));

        // Binding on a plaintext zone: rejected as a config mistake.
        let mut cfg = baseline_cfg();
        let mut z = zone_for_encryption(ZoneVisibility::Locked, false);
        z.group_pubkey = Some(hex64);
        cfg.zones = vec![z];
        assert!(validate_config(&cfg)
            .unwrap_err()
            .contains("encrypted = false"));
    }

    #[test]
    fn search_mode_rules() {
        use crate::schema::SearchMode;
        let mut cfg = baseline_cfg();
        // Defaults: encrypted locked → sealed, public → off.
        let enc = zone_for_encryption(ZoneVisibility::Locked, true);
        assert_eq!(enc.effective_search(), SearchMode::Sealed);
        assert_eq!(
            zone_for_encryption(ZoneVisibility::Public, false).effective_search(),
            SearchMode::Off
        );
        assert_eq!(
            zone_for_encryption(ZoneVisibility::Locked, false).effective_search(),
            SearchMode::Server
        );
        let mut bad = enc.clone();
        bad.search = Some(SearchMode::Server);
        cfg.zones = vec![bad];
        assert!(validate_config(&cfg)
            .unwrap_err()
            .contains("expose the zone's plaintext"));
        let mut sealed_plain = zone_for_encryption(ZoneVisibility::Locked, false);
        sealed_plain.search = Some(SearchMode::Sealed);
        cfg.zones = vec![sealed_plain];
        assert!(validate_config(&cfg).is_err());
        let mut pub_server = zone_for_encryption(ZoneVisibility::Public, false);
        pub_server.search = Some(SearchMode::Server);
        cfg.zones = vec![pub_server];
        assert!(validate_config(&cfg).is_err());
        let mut ok = enc;
        ok.search = Some(SearchMode::Off);
        cfg.zones = vec![ok];
        assert!(validate_config(&cfg).is_ok());
        cfg.search_archivists = vec!["AB".into()];
        assert!(validate_config(&cfg).is_err());
        cfg.search_archivists = vec!["ab".repeat(32)];
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn encrypted_locked_or_hidden_zone_is_accepted() {
        for vis in [ZoneVisibility::Locked, ZoneVisibility::Hidden] {
            let mut cfg = baseline_cfg();
            cfg.zones = vec![zone_for_encryption(vis, true)];
            assert!(validate_config(&cfg).is_ok());
        }
        let mut cfg = baseline_cfg();
        cfg.zones = vec![zone_for_encryption(ZoneVisibility::Public, false)];
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn encryption_gate_defaults_off() {
        let e: Encryption = serde_json::from_str("{}").unwrap();
        assert!(!e.enabled);
    }

    #[test]
    fn zone_valid_accent_hex_accepted() {
        let mut cfg = baseline_cfg();
        cfg.zones = vec![Zone {
            id: "public".into(),
            slug: None,
            display_name: "Public".into(),
            required_cohorts: Vec::new(),
            write_cohorts: None,
            banner_image_url: None,
            accent_hex: Some("#3b82f6".into()),
            visibility: ZoneVisibility::Public,
            encrypted: false,
            agent_keys: false,
            history_from_epoch: None,
            auto_approve: false,
            kanban: false,
            search: None,
            group_pubkey: None,
            channels: Vec::new(),
        }];
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn zone_bad_accent_hex_rejected() {
        let mut cfg = baseline_cfg();
        cfg.zones = vec![Zone {
            id: "public".into(),
            slug: None,
            display_name: "Public".into(),
            required_cohorts: Vec::new(),
            write_cohorts: None,
            banner_image_url: None,
            accent_hex: Some("blue".into()),
            visibility: ZoneVisibility::Public,
            encrypted: false,
            agent_keys: false,
            history_from_epoch: None,
            auto_approve: false,
            kanban: false,
            search: None,
            group_pubkey: None,
            channels: Vec::new(),
        }];
        assert!(validate_config(&cfg).is_err());
    }

    /// Build a zone with just an id + optional slug (other fields defaulted) for
    /// the slug validation tests (issue #45).
    fn zone_with_slug(id: &str, slug: Option<&str>) -> Zone {
        Zone {
            id: id.into(),
            slug: slug.map(str::to_string),
            display_name: id.into(),
            required_cohorts: Vec::new(),
            write_cohorts: None,
            banner_image_url: None,
            accent_hex: None,
            visibility: ZoneVisibility::Public,
            encrypted: false,
            agent_keys: false,
            history_from_epoch: None,
            auto_approve: false,
            kanban: false,
            search: None,
            group_pubkey: None,
            channels: Vec::new(),
        }
    }

    #[test]
    fn zone_valid_slug_accepted() {
        let mut cfg = baseline_cfg();
        cfg.zones = vec![zone_with_slug("business", Some("dreamlab"))];
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn zone_slug_equal_to_own_id_accepted() {
        // A slug identical to its own id is a harmless identity, not a collision.
        let mut cfg = baseline_cfg();
        cfg.zones = vec![zone_with_slug("welcome", Some("welcome"))];
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn zone_duplicate_slug_rejected() {
        let mut cfg = baseline_cfg();
        cfg.zones = vec![
            zone_with_slug("public", Some("welcome")),
            zone_with_slug("friends", Some("welcome")),
        ];
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn zone_slug_colliding_with_other_zone_id_rejected() {
        let mut cfg = baseline_cfg();
        cfg.zones = vec![
            zone_with_slug("family", None),
            // "business" zone claims the slug "family" — a different zone's id.
            zone_with_slug("business", Some("family")),
        ];
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn zone_invalid_slug_chars_rejected() {
        let mut cfg = baseline_cfg();
        cfg.zones = vec![zone_with_slug("business", Some("DreamLab!"))];
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn zone_slug_toml_round_trip() {
        let zone: Zone =
            toml::from_str("id = \"business\"\ndisplay_name = \"Business\"\nslug = \"dreamlab\"")
                .unwrap();
        assert_eq!(zone.slug.as_deref(), Some("dreamlab"));
        let mut cfg = baseline_cfg();
        cfg.zones = vec![zone];
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn zone_slug_absent_defaults_none() {
        let zone: Zone = toml::from_str("id = \"public\"\ndisplay_name = \"Public\"").unwrap();
        assert!(zone.slug.is_none());
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

[features]
poker = true

[poker]
stakes_bb = [2, 10, 20, 100, 200]
buyin_bb = 100
assets = ["sats", "dream"]
bot_profile = "tag"
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
        assert!(cfg.features.poker);
        assert_eq!(cfg.poker, Poker::default());
    }

    // -- ADR-2037 channel pins ----------------------------------------------

    const PIN_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PIN_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn pinning(id: &str, channels: &[&str]) -> Zone {
        Zone {
            channels: channels.iter().map(|c| c.to_string()).collect(),
            visibility: ZoneVisibility::Hidden,
            required_cohorts: vec![id.to_string()],
            ..zone_with_slug(id, None)
        }
    }

    #[test]
    fn well_formed_channel_pins_validate() {
        let mut cfg = baseline_cfg();
        cfg.zones = vec![pinning("open", &[]), pinning("staff", &[PIN_A, PIN_B])];
        assert!(validate_config(&cfg).is_ok(), "{:?}", validate_config(&cfg));
    }

    #[test]
    fn malformed_channel_pins_are_rejected() {
        let upper = PIN_A.to_uppercase();
        let short = &PIN_A[..63];
        let not_hex = "g".repeat(64);
        let padded = format!(" {}", &PIN_A[..63]);
        for bad in [upper.as_str(), short, not_hex.as_str(), padded.as_str(), ""] {
            let mut cfg = baseline_cfg();
            cfg.zones = vec![pinning("staff", &[bad])];
            let err = validate_config(&cfg).unwrap_err();
            assert!(err.contains("64-char"), "{bad:?}: {err}");
        }
    }

    #[test]
    fn a_channel_pinned_by_two_zones_is_rejected() {
        let mut cfg = baseline_cfg();
        cfg.zones = vec![
            pinning("staff", &[PIN_A]),
            pinning("board", &[PIN_B, PIN_A]),
        ];
        let err = validate_config(&cfg).unwrap_err();
        assert!(
            err.contains("pinned by both zone 'staff' and zone 'board'"),
            "{err}"
        );
    }

    #[test]
    fn a_channel_listed_twice_by_one_zone_is_rejected() {
        let mut cfg = baseline_cfg();
        cfg.zones = vec![pinning("staff", &[PIN_A, PIN_A])];
        let err = validate_config(&cfg).unwrap_err();
        assert!(err.contains("twice"), "{err}");
    }

    #[test]
    fn a_pinning_zone_may_not_extend_another_zone_id() {
        let mut cfg = baseline_cfg();
        cfg.zones = vec![pinning("staff", &[]), pinning("staff-only", &[PIN_A])];
        let err = validate_config(&cfg).unwrap_err();
        assert!(err.contains("starts with 'staff-'"), "{err}");
        // Without pins the same ids are as valid as they were before.
        cfg.zones = vec![pinning("staff", &[]), pinning("staff-only", &[])];
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn channel_pins_parse_from_toml_and_stay_out_of_an_unpinned_projection() {
        let toml = format!("id = \"staff\"\ndisplay_name = \"Staff\"\nchannels = [\"{PIN_A}\"]\n");
        let zone: Zone = toml::from_str(&toml).unwrap();
        assert_eq!(zone.channels, vec![PIN_A.to_string()]);
        let json = serde_json::to_value(&zone).unwrap();
        assert_eq!(json["channels"], serde_json::json!([PIN_A]));
        let plain: Zone = toml::from_str("id = \"open\"\ndisplay_name = \"Open\"\n").unwrap();
        assert!(plain.channels.is_empty());
        let json = serde_json::to_value(&plain).unwrap();
        assert!(json.get("channels").is_none(), "no pins, no key: {json}");
    }

    #[test]
    fn misspelt_pin_keys_are_refused_on_load() {
        let base = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../forum.example.toml"),
        )
        .unwrap();
        for key in ["channel", "Channels", "pins", "pinned_channels"] {
            let toml = format!(
                "{base}\n[[zones]]\nid = \"staff\"\ndisplay_name = \"Staff\"\n{key} = [\"{PIN_A}\"]\n"
            );
            let err = crate::load_from_str(&toml).unwrap_err().to_string();
            assert!(err.contains("did you mean 'channels'"), "{key}: {err}");
        }
    }

    #[test]
    fn a_zone_config_json_is_checked_like_forum_toml() {
        assert!(validate_zone_config_json(&format!(
            r#"[{{"id":"open"}},{{"id":"staff","channels":["{PIN_A}"]}}]"#
        ))
        .is_ok());
        let typo =
            validate_zone_config_json(&format!(r#"[{{"id":"staff","channel":["{PIN_A}"]}}]"#));
        assert!(typo.unwrap_err().contains("did you mean"));
        let bad = validate_zone_config_json(r#"[{"id":"staff","channels":["abc"]}]"#);
        assert!(bad.unwrap_err().contains("64-char"));
        let doubled = validate_zone_config_json(&format!(
            r#"[{{"id":"a","channels":["{PIN_A}"]}},{{"id":"b","channels":["{PIN_A}"]}}]"#
        ));
        assert!(doubled.unwrap_err().contains("pinned by both"));
        assert!(validate_zone_config_json("{}").is_err());
    }

    #[test]
    fn unrelated_zone_keys_still_load() {
        let base = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../forum.example.toml"),
        )
        .unwrap();
        for key in [
            "mapping",
            "shipping",
            "channel_order",
            "featured_channels",
            "default_channel",
        ] {
            let toml = format!(
                "{base}\n[[zones]]\nid = \"staff\"\ndisplay_name = \"Staff\"\n{key} = [\"{PIN_A}\"]\n"
            );
            assert!(crate::load_from_str(&toml).is_ok(), "{key}");
            assert!(!is_misspelt_pin_key(key), "{key}");
        }
        for key in [
            "channel",
            "Channels",
            "CHANNELS",
            "chanels",
            "pin",
            "pins",
            "pinned",
            "pinned_channels",
        ] {
            assert!(is_misspelt_pin_key(key), "{key}");
        }
        assert!(!is_misspelt_pin_key("channels"));
    }

    #[test]
    fn zone_schema_keys_match_a_fully_populated_zone() {
        let full = Zone {
            id: "z".into(),
            slug: Some("z".into()),
            display_name: "Z".into(),
            required_cohorts: vec!["z".into()],
            write_cohorts: Some(vec!["z".into()]),
            banner_image_url: Some("/b.webp".into()),
            accent_hex: Some("#123456".into()),
            visibility: ZoneVisibility::Hidden,
            encrypted: true,
            agent_keys: true,
            history_from_epoch: Some(1),
            group_pubkey: Some("ab".repeat(32)),
            auto_approve: true,
            kanban: true,
            search: Some(SearchMode::Sealed),
            channels: vec![PIN_A.into()],
        };
        let json = serde_json::to_value(&full).unwrap();
        let mut got: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut want = ZONE_SCHEMA_KEYS.to_vec();
        got.sort_unstable();
        want.sort_unstable();
        assert_eq!(got, want);
        // And the fully populated zone validates cleanly as a ZONE_CONFIG.
        let raw = serde_json::to_string(&vec![full]).unwrap();
        assert_eq!(validate_zone_config_json(&raw), Ok(()));
    }

    #[test]
    fn unknown_zone_keys_are_refused_by_the_zone_config_validator() {
        for key in [
            "channel_ids",
            "channel_pins",
            "pinnedChannels",
            "pinned-channels",
            "pinned_channel",
            "colour",
        ] {
            let raw = format!(r#"[{{"id":"staff","{key}":["{PIN_A}"]}}]"#);
            let err = validate_zone_config_json(&raw).unwrap_err();
            assert!(err.contains("staff") && err.contains(key), "{key}: {err}");
        }
        // The client-only key every live projection carries is accepted.
        assert_eq!(
            validate_zone_config_json(r#"[{"id":"open","section_order":["open-a"]}]"#),
            Ok(())
        );
    }
}
