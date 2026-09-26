//! Config-driven zone definitions for the relay worker.
//!
//! Zones (forum sections) are entirely data-driven: the operator declares them
//! in `forum.toml` under `[[zones]]`, and the deployment pipeline serialises the
//! `zones` array to JSON and exposes it to this worker as the `ZONE_CONFIG`
//! environment variable (a `wrangler` `[vars]` entry or secret). The shape is the
//! serde representation of `nostr_bbs_config::schema::Zone`, so config authored in
//! TOML round-trips through JSON without a second schema.
//!
//! Nothing here is hardcoded: if `ZONE_CONFIG` is absent or unparseable the
//! lookups fall back to a deny-by-default posture (no zone matched), and the
//! caller's admin bypass still applies. The relay never invents zone names.
//!
//! Access model (matches the operator-approved org redesign §3):
//! - read  gate: `required_cohorts` — empty + `visibility = public` ⇒ unauth read.
//! - write gate: `write_cohorts ?? required_cohorts`.
//! - admins bypass both, unconditionally (enforced at the call sites).

use serde::Deserialize;
use worker::Env;

/// Visibility policy for non-members. Mirrors
/// `nostr_bbs_config::schema::ZoneVisibility`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZoneVisibility {
    /// Listed + readable without auth/cohort.
    Public,
    /// Listed as a content-gated tile (default for non-members).
    #[default]
    Locked,
    /// Omitted entirely for non-members.
    Hidden,
}

/// A single zone definition. Mirrors the serde representation of
/// `nostr_bbs_config::schema::Zone` so `forum.toml` `[[zones]]` entries
/// serialise straight into `ZONE_CONFIG` JSON.
#[derive(Debug, Clone, Deserialize)]
pub struct Zone {
    /// Slug identifier (`"public"`, `"friends"`, `"family"`, `"business"`, ...).
    pub id: String,
    /// Cohorts required to READ. Empty + `Public` ⇒ unauthenticated read.
    #[serde(default)]
    pub required_cohorts: Vec<String>,
    /// Cohorts required to WRITE; falls back to `required_cohorts` when absent.
    #[serde(default)]
    pub write_cohorts: Option<Vec<String>>,
    /// Visibility policy for non-members.
    #[serde(default)]
    pub visibility: ZoneVisibility,
    /// Content in this zone is end-to-end encrypted by clients (the zone-key
    /// scheme in the forum client). The relay cannot decrypt; it only refuses
    /// kind-42 content that is not a zone-key ciphertext (see
    /// [`is_zone_ciphertext`]), so no client can downgrade the zone to
    /// plaintext.
    #[serde(default)]
    pub encrypted: bool,
}

impl Zone {
    /// Effective write cohorts: explicit `write_cohorts`, else `required_cohorts`.
    pub fn effective_write_cohorts(&self) -> &[String] {
        match &self.write_cohorts {
            Some(w) => w.as_slice(),
            None => self.required_cohorts.as_slice(),
        }
    }
}

/// The full set of zone definitions parsed from `ZONE_CONFIG`.
#[derive(Debug, Clone, Default)]
pub struct ZoneConfig {
    zones: Vec<Zone>,
    /// Deployment master gate (`ENCRYPTION_ENABLED`). With the gate off no
    /// zone is treated as encrypted, whatever its `encrypted` flag says.
    encryption_enabled: bool,
}

impl ZoneConfig {
    /// Load zone definitions from the `ZONE_CONFIG` env var (JSON array). An
    /// absent or malformed value yields an empty config (deny-by-default for
    /// non-admins). This is the single source of zone truth in the worker.
    pub fn load(env: &Env) -> Self {
        let enabled = env
            .var("ENCRYPTION_ENABLED")
            .map(|v| encryption_flag(&v.to_string()))
            .unwrap_or(false);
        let raw = match env.var("ZONE_CONFIG") {
            Ok(v) => v.to_string(),
            Err(_) => return Self::default(),
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Self::default();
        }
        Self::from_json(trimmed).with_encryption(enabled)
    }

    /// Set the deployment encryption gate (`ENCRYPTION_ENABLED`).
    pub fn with_encryption(mut self, enabled: bool) -> Self {
        self.encryption_enabled = enabled;
        self
    }

    /// Parse a `ZONE_CONFIG` JSON array from a string. Malformed input yields an
    /// empty config (deny-by-default). Shared by [`Self::load`] and unit tests.
    pub fn from_json(raw: &str) -> Self {
        match serde_json::from_str::<Vec<Zone>>(raw.trim()) {
            Ok(zones) => Self {
                zones,
                encryption_enabled: false,
            },
            Err(_) => Self::default(),
        }
    }

    /// Look up a zone definition by id.
    pub fn get(&self, id: &str) -> Option<&Zone> {
        self.zones.iter().find(|z| z.id == id)
    }

    /// Whether the zone's content must be end-to-end encrypted: the
    /// deployment gate is on, the zone is flagged `encrypted`, and the zone is
    /// not public (anonymous readers can never hold a zone key, so a public
    /// zone is never enforced even if misconfigured).
    pub fn is_encrypted(&self, id: &str) -> bool {
        self.encryption_enabled
            && self
                .get(id)
                .map(|z| z.encrypted && !self.is_public_read(id))
                .unwrap_or(false)
    }

    /// Whether the zone is readable with no auth and no cohort membership.
    /// True only for `Public` zones with no required read cohorts.
    pub fn is_public_read(&self, id: &str) -> bool {
        self.get(id)
            .map(|z| z.visibility == ZoneVisibility::Public && z.required_cohorts.is_empty())
            .unwrap_or(false)
    }

    /// Whether the channel definitions (kind-40) for this zone should be served
    /// to a non-member. `Public` and `Locked` zones expose their tile (defs);
    /// `Hidden` zones are omitted entirely. Admins/members are gated elsewhere.
    pub fn defs_visible_to_nonmember(&self, id: &str) -> bool {
        self.get(id)
            .map(|z| z.visibility != ZoneVisibility::Hidden)
            .unwrap_or(false)
    }

    /// Decide read access for a member given their cohort list. Membership in
    /// any `required_cohorts` entry grants read; an empty requirement grants
    /// read only when the zone is `Public`. Admin bypass is the caller's job.
    pub fn cohorts_can_read(&self, id: &str, cohorts: &[String]) -> bool {
        match self.get(id) {
            None => false,
            Some(z) => {
                if z.required_cohorts.is_empty() {
                    z.visibility == ZoneVisibility::Public
                } else {
                    cohorts.iter().any(|c| z.required_cohorts.contains(c))
                }
            }
        }
    }

    /// Decide write access for a member given their cohort list, using the
    /// effective write cohorts (write_cohorts ?? required_cohorts). An empty
    /// effective set denies all non-admins (writes are never anonymous).
    pub fn cohorts_can_write(&self, id: &str, cohorts: &[String]) -> bool {
        match self.get(id) {
            None => false,
            Some(z) => {
                let req = z.effective_write_cohorts();
                if req.is_empty() {
                    false
                } else {
                    cohorts.iter().any(|c| req.contains(&c.to_string()))
                }
            }
        }
    }
}

/// Parse the `ENCRYPTION_ENABLED` var: only the exact string `"true"`
/// (surrounding whitespace ignored) turns the gate on.
pub fn encryption_flag(raw: &str) -> bool {
    raw.trim() == "true"
}

/// Whether a kind-42 bound for an encrypted `zone` carries a zone-key
/// ciphertext: a `["zk", <zone>, <epoch ≥ 1>, <64-hex zone pubkey>]` tag and
/// content shaped like a NIP-44 v2 payload (base64 of version byte `0x02`,
/// 32-byte nonce, ≥ 34-byte padded ciphertext and 32-byte MAC, so ≥ 99 bytes,
/// and no more than NIP-44's 65 535-byte plaintext ceiling allows).
///
/// Shape only — the relay holds no key and cannot tell a real ciphertext from
/// random bytes. What it guarantees is that nothing *readable* is stored in an
/// encrypted zone: a plaintext post, from any client or any author (admins
/// included), is refused.
pub fn is_zone_ciphertext(zone: &str, tags: &[Vec<String>], content: &str) -> bool {
    use base64::Engine as _;
    let hex64 = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
    let tag_ok = tags.iter().any(|t| {
        t.len() >= 4
            && t[0] == "zk"
            && t[1] == zone
            && t[2].parse::<u32>().map(|e| e >= 1).unwrap_or(false)
            && hex64(&t[3])
    });
    if !tag_ok || content.len() < 132 || content.len() > 87_472 {
        return false;
    }
    match base64::engine::general_purpose::STANDARD.decode(content) {
        Ok(bytes) => bytes.len() >= 99 && bytes[0] == 0x02,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zk_payload() -> (Vec<Vec<String>>, String) {
        // A real NIP-44 v2 ciphertext from core (rust-nostr), author → zone key.
        let author = nostr_bbs_core::keys::generate_keypair().unwrap();
        let zone = nostr_bbs_core::keys::generate_keypair().unwrap();
        let zone_pk = *zone.public.as_bytes();
        let ct = nostr_bbs_core::nip44::encrypt(author.secret.as_bytes(), &zone_pk, "hi family")
            .unwrap();
        let tags = vec![
            vec!["e".into(), "chan".into(), "".into(), "root".into()],
            vec![
                "zk".into(),
                "zone3".into(),
                "1".into(),
                hex::encode(zone_pk),
            ],
        ];
        (tags, ct)
    }

    #[test]
    fn real_zone_ciphertext_is_accepted() {
        let (tags, ct) = zk_payload();
        assert!(is_zone_ciphertext("zone3", &tags, &ct));
    }

    #[test]
    fn plaintext_and_malformed_zk_are_refused() {
        let (tags, ct) = zk_payload();
        // Plaintext with a valid zk tag.
        assert!(!is_zone_ciphertext(
            "zone3",
            &tags,
            "hello everyone, dinner at 7?"
        ));
        // Ciphertext without a zk tag.
        let no_zk = vec![vec!["e".to_string(), "chan".into()]];
        assert!(!is_zone_ciphertext("zone3", &no_zk, &ct));
        // zk tag for a different zone, epoch 0, short pubkey.
        let bad = |zone: &str, epoch: &str, pk: &str| {
            vec![vec!["zk".to_string(), zone.into(), epoch.into(), pk.into()]]
        };
        let pk = "ab".repeat(32);
        assert!(!is_zone_ciphertext("zone3", &bad("zone2", "1", &pk), &ct));
        assert!(!is_zone_ciphertext("zone3", &bad("zone3", "0", &pk), &ct));
        assert!(!is_zone_ciphertext(
            "zone3",
            &bad("zone3", "1", "abcd"),
            &ct
        ));
        // Base64 of text that is long enough but not a v2 payload.
        use base64::Engine as _;
        let fake = base64::engine::general_purpose::STANDARD.encode("x".repeat(120));
        assert!(!is_zone_ciphertext("zone3", &tags, &fake));
    }

    #[test]
    fn encrypted_flag_parses_from_zone_config() {
        let zc = ZoneConfig::from_json(
            r#"[{"id":"zone3","required_cohorts":["family"],"visibility":"locked","encrypted":true},
                {"id":"zone2","required_cohorts":["friends"],"visibility":"locked"}]"#,
        )
        .with_encryption(true);
        assert!(zc.is_encrypted("zone3"));
        assert!(!zc.is_encrypted("zone2"));
        assert!(!zc.is_encrypted("nope"));
    }

    #[test]
    fn master_gate_off_disables_every_zone() {
        let zc = ZoneConfig::from_json(
            r#"[{"id":"zone3","required_cohorts":["family"],"visibility":"locked","encrypted":true}]"#,
        );
        assert!(!zc.is_encrypted("zone3"));
        assert!(!zc.with_encryption(false).is_encrypted("zone3"));
    }

    #[test]
    fn public_zone_is_never_enforced_as_encrypted() {
        let zc = ZoneConfig::from_json(
            r#"[{"id":"zone1","required_cohorts":[],"visibility":"public","encrypted":true}]"#,
        )
        .with_encryption(true);
        assert!(!zc.is_encrypted("zone1"));
    }

    #[test]
    fn encryption_flag_accepts_only_exact_true() {
        assert!(encryption_flag("true"));
        assert!(encryption_flag(" true\n"));
        for off in ["", "false", "TRUE", "1", "yes", "on"] {
            assert!(!encryption_flag(off), "{off:?}");
        }
    }

    fn cfg() -> ZoneConfig {
        let json = r#"[
            {"id":"public","required_cohorts":[],"write_cohorts":["friends"],"visibility":"public"},
            {"id":"friends","required_cohorts":["friends"],"visibility":"locked"},
            {"id":"family","required_cohorts":["family"],"visibility":"locked"},
            {"id":"business","required_cohorts":["business"],"visibility":"hidden"}
        ]"#;
        ZoneConfig {
            zones: serde_json::from_str(json).unwrap(),
            encryption_enabled: false,
        }
    }

    #[test]
    fn public_zone_is_unauth_readable_but_not_unauth_writable() {
        let c = cfg();
        assert!(c.is_public_read("public"));
        // empty cohorts => read ok (public), but write requires "friends"
        assert!(c.cohorts_can_read("public", &[]));
        assert!(!c.cohorts_can_write("public", &[]));
        assert!(c.cohorts_can_write("public", &["friends".to_string()]));
    }

    #[test]
    fn locked_zone_gates_content_but_shows_tile() {
        let c = cfg();
        assert!(!c.is_public_read("friends"));
        assert!(c.defs_visible_to_nonmember("friends")); // tile shown
        assert!(!c.cohorts_can_read("friends", &[])); // content withheld
        assert!(c.cohorts_can_read("friends", &["friends".to_string()]));
    }

    #[test]
    fn hidden_zone_omits_tile_for_nonmembers() {
        let c = cfg();
        assert!(!c.defs_visible_to_nonmember("business"));
        assert!(!c.cohorts_can_read("business", &[]));
        assert!(c.cohorts_can_read("business", &["business".to_string()]));
    }

    #[test]
    fn write_falls_back_to_required_when_unset() {
        let c = cfg();
        // friends zone has no write_cohorts => falls back to required_cohorts
        assert!(c.cohorts_can_write("friends", &["friends".to_string()]));
        assert!(!c.cohorts_can_write("friends", &["family".to_string()]));
    }

    #[test]
    fn unknown_zone_denies_all() {
        let c = cfg();
        assert!(!c.cohorts_can_read("nope", &["friends".to_string()]));
        assert!(!c.cohorts_can_write("nope", &["friends".to_string()]));
        assert!(!c.is_public_read("nope"));
        assert!(!c.defs_visible_to_nonmember("nope"));
    }
}
