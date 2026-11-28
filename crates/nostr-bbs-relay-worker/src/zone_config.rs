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
//!
//! Channel pins (ADR-2037): a zone may list kind-40 channel ids in `channels`.
//! A pinned channel belongs to that zone whatever its `channel_zones` row or
//! signed `section` tag says, so an existing section can be moved to another
//! zone from config alone. [`ZoneConfig::pinned_zone`] is the lookup; every
//! channel-to-zone resolution in the worker consults it before D1.

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
    /// ADR-2028 decision 4: the NIP-171 group identity pubkey bound to this
    /// zone (64 lowercase hex). The binding lives here and nowhere else; a `zk`
    /// tag's fifth element is only a hint checked against it.
    #[serde(default)]
    pub group_pubkey: Option<String>,
    /// ADR-2037: kind-40 channel ids (64 hex) pinned to this zone. A pinned
    /// channel is gated by this zone ahead of any `channel_zones` row. Entries
    /// are compared case-insensitively; an entry that is not 64 hex digits can
    /// name no channel and is ignored (config validation refuses it).
    #[serde(default)]
    pub channels: Vec<String>,
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

/// What the zone config says about one channel (ADR-2037).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelPin<'a> {
    /// No zone pins the channel: its `channel_zones` row decides.
    Unpinned,
    /// Exactly one zone pins the channel.
    Pinned(&'a str),
    /// Two or more zones pin the channel. Config validation refuses this; a
    /// hand-edited `ZONE_CONFIG` that does it anyway makes the channel's zone
    /// unknown, and callers fail closed (reads withheld, writes refused).
    Conflict,
}

/// Whether `s` is 64 hex digits, either case: the only form a channel id
/// (a kind-40 event id) can take.
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether a zone object key looks like a misspelt `channels` (ADR-2037):
/// any key other than exactly `channels` that mentions "pin" or "channel",
/// case-insensitively (`channel`, `Channels`, `pins`, `pinned_channels`, ...).
/// serde would silently ignore such a key, and the channel it meant to pin
/// would stay in its old zone.
pub fn is_misspelt_pin_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    key != "channels" && (k.contains("pin") || k.contains("channel"))
}

/// Every 64-hex string in `v` (a string, or an array of strings), lowercased.
fn hex_ids_in(v: &serde_json::Value) -> Vec<String> {
    let one = |s: &str| {
        let t = s.trim();
        is_hex64(t).then(|| t.to_ascii_lowercase())
    };
    match v {
        serde_json::Value::String(s) => one(s).into_iter().collect(),
        serde_json::Value::Array(a) => a.iter().filter_map(|x| x.as_str().and_then(one)).collect(),
        _ => Vec::new(),
    }
}

/// The full set of zone definitions parsed from `ZONE_CONFIG`.
#[derive(Debug, Clone, Default)]
pub struct ZoneConfig {
    zones: Vec<Zone>,
    /// Deployment master gate (`ENCRYPTION_ENABLED`). With the gate off no
    /// zone is treated as encrypted, whatever its `encrypted` flag says.
    encryption_enabled: bool,
    /// ADR-2037: zones whose `channels` list holds an entry that is not a
    /// 64-hex id, or that carry a misspelt pin key. Every pin such a zone
    /// declares fails closed ([`ChannelPin::Conflict`]).
    broken_pin_zones: Vec<String>,
    /// ADR-2037: 64-hex ids found under a misspelt pin key. The operator
    /// meant to pin them; which zone is unknown, so they fail closed.
    quarantined: Vec<String>,
    /// Pin configuration errors found at parse time, logged once per isolate
    /// by [`Self::load`].
    pin_errors: Vec<String>,
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
        let cfg = Self::from_json(trimmed).with_encryption(enabled);
        if !cfg.pin_errors().is_empty() {
            // Once per isolate: the config is parsed per request, and it can
            // only change with a redeploy, which starts new isolates.
            static LOGGED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !LOGGED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                worker::console_error!(
                    "ZONE_CONFIG channel pins misconfigured; affected pins fail closed: {}",
                    cfg.pin_errors().join("; ")
                );
            }
        }
        cfg
    }

    /// ADR-2037 pin configuration errors found when parsing (empty when the
    /// pins are well formed).
    pub fn pin_errors(&self) -> &[String] {
        &self.pin_errors
    }

    /// Set the deployment encryption gate (`ENCRYPTION_ENABLED`).
    pub fn with_encryption(mut self, enabled: bool) -> Self {
        self.encryption_enabled = enabled;
        self
    }

    /// Parse a `ZONE_CONFIG` JSON array from a string. Malformed input yields an
    /// empty config (deny-by-default). Shared by [`Self::load`] and unit tests.
    ///
    /// ADR-2037: a zone whose `channels` holds an entry that is not 64 hex
    /// digits, or that carries a misspelt pin key ([`is_misspelt_pin_key`]),
    /// has all its pins fail closed, and 64-hex ids under a misspelt key fail
    /// closed too; each case is recorded in [`Self::pin_errors`]. A malformed
    /// entry cannot be tied to the channel it was meant to name, so that
    /// channel itself still falls back to its `channel_zones` row: config
    /// validation is what catches it before deploy.
    pub fn from_json(raw: &str) -> Self {
        let Ok(values) = serde_json::from_str::<Vec<serde_json::Value>>(raw.trim()) else {
            return Self::default();
        };
        let mut out = Self::default();
        for v in values {
            let Ok(zone) = serde_json::from_value::<Zone>(v.clone()) else {
                return Self::default();
            };
            if let Some(obj) = v.as_object() {
                for (key, val) in obj.iter().filter(|(k, _)| is_misspelt_pin_key(k)) {
                    out.pin_errors.push(format!(
                        "zone {} has unknown key {key:?} (did you mean \"channels\"?)",
                        zone.id
                    ));
                    out.quarantined.extend(hex_ids_in(val));
                    out.broken_pin_zones.push(zone.id.clone());
                }
            }
            if let Some(bad) = zone.channels.iter().find(|c| !is_hex64(c.trim())) {
                out.pin_errors.push(format!(
                    "zone {} pins {bad:?}, which is not a 64-hex channel id",
                    zone.id
                ));
                out.broken_pin_zones.push(zone.id.clone());
            }
            out.zones.push(zone);
        }
        out
    }

    /// Ids of every configured zone (used by the opt-in Jev triage sweep to
    /// build its public-zone allow-list; admission does not use this).
    pub fn zone_ids(&self) -> impl Iterator<Item = &str> {
        self.zones.iter().map(|z| z.id.as_str())
    }

    /// Look up a zone definition by id.
    pub fn get(&self, id: &str) -> Option<&Zone> {
        self.zones.iter().find(|z| z.id == id)
    }

    /// The zone that pins `channel_id` through its `channels` list
    /// (ADR-2037). Ids compare case-insensitively, so a mixed-case alias of a
    /// pinned channel is still pinned. A channel pinned by a zone with a
    /// malformed pin list, or named under a misspelt pin key, is
    /// [`ChannelPin::Conflict`]. A channel listed by one zone more than once is still
    /// [`ChannelPin::Pinned`]; listed by two different zones it is
    /// [`ChannelPin::Conflict`].
    pub fn pinned_zone(&self, channel_id: &str) -> ChannelPin<'_> {
        if self
            .quarantined
            .iter()
            .any(|q| q.eq_ignore_ascii_case(channel_id))
        {
            return ChannelPin::Conflict;
        }
        let mut found: Option<&str> = None;
        for z in &self.zones {
            let pins = z
                .channels
                .iter()
                .map(|c| c.trim())
                .any(|c| is_hex64(c) && c.eq_ignore_ascii_case(channel_id));
            if !pins {
                continue;
            }
            if self.broken_pin_zones.contains(&z.id) {
                return ChannelPin::Conflict;
            }
            match found {
                Some(prev) if prev != z.id => return ChannelPin::Conflict,
                _ => found = Some(z.id.as_str()),
            }
        }
        match found {
            Some(z) => ChannelPin::Pinned(z),
            None => ChannelPin::Unpinned,
        }
    }

    /// Whether `POST /api/admin/channel-zone` must refuse to bind
    /// `channel_id` (ADR-2037): any pin, including a conflicting one, decides
    /// the channel's zone, and a row written now would take over silently
    /// once the pin is removed.
    pub fn pin_blocks_binding(&self, channel_id: &str) -> bool {
        !matches!(self.pinned_zone(channel_id), ChannelPin::Unpinned)
    }

    /// The zone's bound group pubkey, if one is configured and well formed
    /// (64 lowercase hex). A malformed value reads as unbound.
    pub fn group_for(&self, id: &str) -> Option<&str> {
        self.get(id)?
            .group_pubkey
            .as_deref()
            .filter(|g| g.len() == 64 && g.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
    }

    /// The `zone_groups` map served in the NIP-11 `nostr_bbs` block: zone id to
    /// bound group pubkey. `Hidden` zones are left out, since the document is
    /// public and `Hidden` means omitted entirely for non-members.
    pub fn zone_groups_block(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        for z in &self.zones {
            if z.visibility == ZoneVisibility::Hidden {
                continue;
            }
            if let Some(g) = self.group_for(&z.id) {
                m.insert(z.id.clone(), serde_json::Value::String(g.to_string()));
            }
        }
        serde_json::Value::Object(m)
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

/// ADR-2037: whether a kind-42 into a channel pinned to `pinned` names some
/// other zone in a `zk` tag. Such a post was encrypted to another zone's key,
/// typically by a client that does not know the pin, and anyone holding that
/// key could read it at rest; the relay refuses it whether or not the pinned
/// zone is encrypted. Only applied to pinned channels, so it changes nothing
/// when no pins are configured.
pub fn zk_names_other_zone(pinned: &str, tags: &[Vec<String>]) -> bool {
    tags.iter()
        .any(|t| t.len() >= 2 && t[0] == "zk" && t[1] != pinned)
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
    fn group_for_parses_and_is_served() {
        let g = "ab".repeat(32);
        let zc = ZoneConfig::from_json(&format!(
            r#"[{{"id":"family","required_cohorts":["family"],"group_pubkey":"{g}"}},
                {{"id":"secret","required_cohorts":["x"],"visibility":"hidden","group_pubkey":"{g}"}},
                {{"id":"bad","required_cohorts":["y"],"group_pubkey":"{}"}},
                {{"id":"plain","required_cohorts":["z"]}}]"#,
            "AB".repeat(32)
        ));
        assert_eq!(zc.group_for("family"), Some(g.as_str()));
        assert_eq!(zc.group_for("bad"), None, "uppercase is not the binding");
        assert_eq!(zc.group_for("plain"), None);
        assert_eq!(zc.group_for("nope"), None);
        let block = zc.zone_groups_block();
        assert_eq!(block, serde_json::json!({ "family": g }));
    }

    #[test]
    fn five_element_zk_tag_keeps_its_shape_pass() {
        let (mut tags, ct) = zk_payload();
        tags[1].push("cd".repeat(32));
        assert!(is_zone_ciphertext("zone3", &tags, &ct));
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
            ..ZoneConfig::default()
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

    // -- ADR-2037 channel pins ---------------------------------------------

    const PINNED: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const OTHER: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn pinned_cfg() -> ZoneConfig {
        ZoneConfig::from_json(&format!(
            r#"[{{"id":"open","required_cohorts":["members"],"visibility":"locked","encrypted":true}},
                {{"id":"staff","required_cohorts":["staff"],"visibility":"hidden","encrypted":true,
                  "channels":["{PINNED}"]}}]"#
        ))
        .with_encryption(true)
    }

    #[test]
    fn channels_default_to_empty_and_nothing_is_pinned() {
        let c = cfg();
        assert!(c.zones.iter().all(|z| z.channels.is_empty()));
        assert_eq!(c.pinned_zone(PINNED), ChannelPin::Unpinned);
    }

    #[test]
    fn a_listed_channel_is_pinned_to_its_zone() {
        let c = pinned_cfg();
        assert_eq!(c.pinned_zone(PINNED), ChannelPin::Pinned("staff"));
        assert_eq!(c.pinned_zone(OTHER), ChannelPin::Unpinned);
        assert_eq!(c.pinned_zone(""), ChannelPin::Unpinned);
    }

    #[test]
    fn pins_compare_case_insensitively() {
        let upper = "AB".repeat(32);
        let c = ZoneConfig::from_json(&format!(
            r#"[{{"id":"staff","required_cohorts":["staff"],"channels":[" {upper} "]}}]"#
        ));
        assert!(c.pin_errors().is_empty());
        // A mixed-case entry, or a mixed-case alias of the id, is still pinned.
        assert_eq!(c.pinned_zone(&"ab".repeat(32)), ChannelPin::Pinned("staff"));
        assert_eq!(c.pinned_zone(&upper), ChannelPin::Pinned("staff"));
    }

    #[test]
    fn a_malformed_entry_makes_every_pin_of_its_zone_fail_closed() {
        let good = "ab".repeat(32);
        let c = ZoneConfig::from_json(&format!(
            r#"[{{"id":"staff","required_cohorts":["staff"],"channels":["{good}","{}"]}},
                {{"id":"other","required_cohorts":["o"],"channels":["{OTHER}"]}}]"#,
            &OTHER[..63]
        ));
        // The well-formed pin in the broken zone is withheld from everyone
        // rather than falling back to its channel_zones row.
        assert_eq!(c.pinned_zone(&good), ChannelPin::Conflict);
        assert!(c.pin_blocks_binding(&good));
        // A well-formed zone elsewhere is unaffected.
        assert_eq!(c.pinned_zone(OTHER), ChannelPin::Pinned("other"));
        assert_eq!(c.pin_errors().len(), 1);
        assert!(c.pin_errors()[0].contains("staff"), "{:?}", c.pin_errors());
        // The zone itself still gates as before.
        assert!(c.cohorts_can_read("staff", &["staff".to_string()]));
    }

    #[test]
    fn a_misspelt_pin_key_fails_its_ids_closed() {
        for key in ["channel", "Channels", "pins", "pinned_channels"] {
            let c = ZoneConfig::from_json(&format!(
                r#"[{{"id":"staff","required_cohorts":["staff"],"{key}":["{PINNED}"]}}]"#
            ));
            assert_eq!(c.pinned_zone(PINNED), ChannelPin::Conflict, "{key}");
            assert!(c.pin_blocks_binding(PINNED), "{key}");
            assert_eq!(c.pin_errors().len(), 1, "{key}");
        }
        // A single string under a misspelt key is caught too.
        let c = ZoneConfig::from_json(&format!(
            r#"[{{"id":"staff","required_cohorts":["staff"],"channel":"{PINNED}"}}]"#
        ));
        assert_eq!(c.pinned_zone(PINNED), ChannelPin::Conflict);
        // Other zone keys are not mistaken for pin keys.
        for key in ["section_order", "kanban", "search"] {
            assert!(!is_misspelt_pin_key(key), "{key}");
        }
        assert!(!is_misspelt_pin_key("channels"));
    }

    #[test]
    fn an_unpinned_channel_may_be_bound() {
        let c = pinned_cfg();
        assert!(c.pin_blocks_binding(PINNED));
        assert!(!c.pin_blocks_binding(OTHER));
        assert!(!cfg().pin_blocks_binding(PINNED));
    }

    #[test]
    fn a_channel_pinned_by_two_zones_is_a_conflict() {
        let c = ZoneConfig::from_json(&format!(
            r#"[{{"id":"a","required_cohorts":["a"],"channels":["{PINNED}","{PINNED}"]}},
                {{"id":"b","required_cohorts":["b"],"channels":["{OTHER}"]}},
                {{"id":"c","required_cohorts":["c"],"channels":["{OTHER}"]}}]"#
        ));
        // Listed twice by one zone: still that zone.
        assert_eq!(c.pinned_zone(PINNED), ChannelPin::Pinned("a"));
        assert_eq!(c.pinned_zone(OTHER), ChannelPin::Conflict);
    }

    #[test]
    fn a_post_into_a_pinned_channel_under_the_old_zone_key_is_refused() {
        // The channel moved from "open" to "staff"; an old client still
        // encrypts for "open".
        let c = pinned_cfg();
        let ChannelPin::Pinned(zone) = c.pinned_zone(PINNED) else {
            panic!("pinned");
        };
        let (mut tags, ct) = zk_payload();
        tags[1][1] = "open".into();
        assert!(c.is_encrypted(zone));
        assert!(!is_zone_ciphertext(zone, &tags, &ct));
        assert!(zk_names_other_zone(zone, &tags));
        // The pinned zone's own ciphertext passes both checks.
        tags[1][1] = "staff".into();
        assert!(is_zone_ciphertext(zone, &tags, &ct));
        assert!(!zk_names_other_zone(zone, &tags));
    }

    #[test]
    fn foreign_zk_is_refused_even_when_the_pinned_zone_is_plaintext() {
        // The shape check is skipped for an unencrypted zone, so the pin
        // guard is what stops old-zone ciphertext from being stored.
        let c = ZoneConfig::from_json(&format!(
            r#"[{{"id":"staff","required_cohorts":["staff"],"channels":["{PINNED}"]}}]"#
        ))
        .with_encryption(true);
        assert!(!c.is_encrypted("staff"));
        let (mut tags, _) = zk_payload();
        tags[1][1] = "open".into();
        assert!(zk_names_other_zone("staff", &tags));
        // A plaintext post carries no zk and is untouched by the guard.
        assert!(!zk_names_other_zone(
            "staff",
            &[vec!["e".to_string(), PINNED.into()]]
        ));
    }
}
