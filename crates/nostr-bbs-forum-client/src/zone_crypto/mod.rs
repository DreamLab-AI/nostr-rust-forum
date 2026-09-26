//! Zone end-to-end encryption (ADR-2016).
//!
//! A zone whose `ZONE_CONFIG` entry has `"encrypted": true` keeps the TEXT of
//! its channel messages (kind 42, edits included) unreadable to the relay, the
//! host, backups and any Nostr client that is not a key-holding member. The
//! scheme is built only from published Nostr primitives — NIP-44 v2
//! (`nostr_bbs_core::nip44`, rust-nostr, upstream-vector tested) and NIP-59 gift
//! wraps (`nostr_bbs_core::gift_wrap`). No new cryptography lives here.
//!
//! ## Zone keys and epochs
//!
//! Each `(zone, epoch)` has its own random secp256k1 keypair. Epochs increase
//! from 1; removing a member means rotating to a new epoch and granting it to
//! everyone else.
//!
//! ## Message format
//!
//! `content = nip44_encrypt(author_secret, zone_epoch_pubkey, plaintext)` —
//! the conversation key is `ECDH(author_sk, zone_pk) = ECDH(zone_sk, author_pk)`,
//! so any holder of the zone secret decrypts it with the event's own author
//! pubkey, and the author's signature still proves who wrote it. The event
//! carries `["zk", <zone id>, <epoch>, <zone epoch pubkey hex>]`; every other tag
//! is unchanged. The relay (`relay_do::nip_handlers`) refuses a kind-42 in an
//! encrypted zone's channel without a well-formed `zk` tag and NIP-44 v2
//! ciphertext.
//!
//! ## Key grants
//!
//! An admin hands a member the zone secret inside a NIP-59 gift wrap whose
//! rumor is [`KIND_ZONE_KEY_GRANT`]. The grant is accepted only when the seal's
//! (verified) author is an admin and the secret derives to the stated pubkey.
//! This rumor kind and its content are a project-private construction: they
//! live in this unpublished client crate on purpose, never in the published
//! `nostr-bbs-core`.
//!
//! ## Deployment gate
//!
//! Encryption is dormant unless the operator enables it: a zone is treated as
//! encrypted only when `window.__ENV__.ENCRYPTION_ENABLED == "true"` AND the
//! zone's `encrypted` flag is set ([`zone_is_encrypted`]). With the gate off
//! nothing is encrypted on write and the admin Encryption tab is hidden, but a
//! `zk`-tagged message is still decrypted on read with any key held, so
//! switching the gate off never makes history unreadable.
//!
//! ## Agents
//!
//! Grant targeting excludes every pubkey whose cohorts include
//! [`AGENT_COHORT`] (admins included) unless the zone sets `agent_keys = true`
//! — a per-zone operator trade-off, since an agent holding the key means the
//! zone's plaintext reaches the agent stack and whatever model it calls.

pub mod store;

use nostr_bbs_core::signer::Signer;
use nostr_bbs_core::{verify_event_strict, NostrEvent, UnsignedEvent};
use serde::{Deserialize, Serialize};

/// NIP-59 rumor kind carrying a zone-key grant. Lives in the ephemeral range:
/// a rumor is never published on its own, only inside a seal + gift wrap.
pub const KIND_ZONE_KEY_GRANT: u64 = 21453;

/// `window.__ENV__` key of the deployment master gate. Only the exact string
/// `"true"` turns encryption on.
pub const GATE_ENV_KEY: &str = "ENCRYPTION_ENABLED";

/// Interpret the gate's raw value: only the exact string `"true"` is on.
pub fn gate_value_enabled(raw: Option<&str>) -> bool {
    raw == Some("true")
}

/// Whether the deployment has zone encryption switched on.
pub fn encryption_enabled() -> bool {
    let raw = web_sys::window()
        .and_then(|w| js_sys::Reflect::get(&w, &"__ENV__".into()).ok())
        .filter(|env| !env.is_undefined() && !env.is_null())
        .and_then(|env| js_sys::Reflect::get(&env, &GATE_ENV_KEY.into()).ok())
        .and_then(|v| v.as_string());
    gate_value_enabled(raw.as_deref())
}

/// Whether messages written into `zone` must be encrypted: gate on AND the
/// zone's own flag.
pub fn zone_is_encrypted(gate_on: bool, zone_flag: bool) -> bool {
    gate_on && zone_flag
}

/// Tag name marking a zone-encrypted kind-42.
pub const ZK_TAG: &str = "zk";

/// Cohort that marks an agent identity. Excluded from key grants unless the
/// zone sets `agent_keys`.
pub const AGENT_COHORT: &str = "agent";

/// Rendered in place of a zone-encrypted message the reader has no key for.
pub const PLACEHOLDER_MISSING_KEY: &str = "🔒 Encrypted message — you don't have the key for this";

/// Rendered in place of a zone-encrypted message that failed to decrypt with
/// the key the reader holds (corrupt or forged ciphertext).
pub const PLACEHOLDER_UNDECRYPTABLE: &str = "🔒 Encrypted message — it could not be decrypted";

/// The relay's rejection text for a plaintext post into an encrypted zone.
pub const RELAY_REJECT_PLAINTEXT: &str = "encrypted zone requires zone-key ciphertext";

const SEAL_KIND: u64 = 13;

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// A zone key the local client holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneKey {
    /// Zone id (`"zone3"`), matching `ZONE_CONFIG`.
    pub zone: String,
    /// Epoch, from 1.
    pub epoch: u32,
    /// 64-hex zone epoch secret.
    pub secret: String,
    /// 64-hex x-only zone epoch pubkey.
    pub pubkey: String,
    /// Admin who granted it (the verified seal author), or the local admin
    /// who created it.
    pub granted_by: String,
    /// Unix seconds this client learned the key.
    pub received_at: u64,
}

impl ZoneKey {
    /// Storage id: `"<zone>:<epoch>"`.
    pub fn id(&self) -> String {
        key_id(&self.zone, self.epoch)
    }

    /// The 32 secret bytes, if well-formed.
    pub fn secret_bytes(&self) -> Option<[u8; 32]> {
        hex32(&self.secret)
    }
}

/// Storage id for `(zone, epoch)`.
pub fn key_id(zone: &str, epoch: u32) -> String {
    format!("{zone}:{epoch}")
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let v = hex::decode(s).ok()?;
    v.try_into().ok()
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Generate a fresh zone key for `(zone, epoch)`.
pub fn generate_zone_key(
    zone: &str,
    epoch: u32,
    creator: &str,
    now: u64,
) -> Result<ZoneKey, String> {
    let kp = nostr_bbs_core::keys::generate_keypair().map_err(|e| e.to_string())?;
    Ok(ZoneKey {
        zone: zone.to_string(),
        epoch,
        secret: hex::encode(kp.secret.as_bytes()),
        pubkey: kp.public.to_hex(),
        granted_by: creator.to_string(),
        received_at: now,
    })
}

// ---------------------------------------------------------------------------
// The zk tag
// ---------------------------------------------------------------------------

/// A parsed `["zk", zone, epoch, pubkey]` tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkRef {
    pub zone: String,
    pub epoch: u32,
    pub pubkey: String,
}

/// Build the `zk` tag for a message encrypted to `key`.
pub fn zk_tag(key: &ZoneKey) -> Vec<String> {
    vec![
        ZK_TAG.to_string(),
        key.zone.clone(),
        key.epoch.to_string(),
        key.pubkey.clone(),
    ]
}

/// Parse the first well-formed `zk` tag: zone non-empty, epoch a decimal
/// `u32 >= 1`, pubkey 64 hex. The same shape the relay enforces.
pub fn parse_zk(tags: &[Vec<String>]) -> Option<ZkRef> {
    tags.iter().find_map(|t| {
        if t.len() < 4 || t[0] != ZK_TAG || t[1].is_empty() {
            return None;
        }
        let epoch: u32 = t[2].parse().ok().filter(|e| *e >= 1)?;
        if !is_hex64(&t[3]) {
            return None;
        }
        Some(ZkRef {
            zone: t[1].clone(),
            epoch,
            pubkey: t[3].to_ascii_lowercase(),
        })
    })
}

/// Whether an event carries any `zk` tag (well-formed or not).
pub fn has_zk_tag(tags: &[Vec<String>]) -> bool {
    tags.iter()
        .any(|t| t.first().map(String::as_str) == Some(ZK_TAG))
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

/// Content of a [`KIND_ZONE_KEY_GRANT`] rumor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantPayload {
    pub zone: String,
    pub epoch: u32,
    pub secret: String,
    pub pubkey: String,
    pub created_at: u64,
}

impl GrantPayload {
    pub fn from_key(key: &ZoneKey, now: u64) -> Self {
        Self {
            zone: key.zone.clone(),
            epoch: key.epoch,
            secret: key.secret.clone(),
            pubkey: key.pubkey.clone(),
            created_at: now,
        }
    }
}

/// Why a received grant was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    #[error("not a zone-key grant (rumor kind {0})")]
    WrongKind(u64),
    #[error("grant content is malformed")]
    Malformed,
    #[error("grant secret does not derive to its stated pubkey")]
    SecretMismatch,
    #[error("grant was not sealed by an admin ({0})")]
    NotAdmin(String),
}

/// Whether a zone-key grant wrap is settled and can be skipped from now on.
///
/// `admin` is the sealer's admin status (`None` when the relay could not be
/// asked), `valid` whether [`validate_grant`] accepted it, and `persisted`
/// whether the accepted key reached IndexedDB. A refused grant is final; a
/// grant whose admin check or storage failed is retried next session, so a
/// transient failure never loses a key.
pub fn grant_settled(admin: Option<bool>, valid: bool, persisted: bool) -> bool {
    match admin {
        None => false,
        Some(_) if valid => persisted,
        Some(_) => true,
    }
}

/// Validate a decrypted grant rumor sealed by `sealer`.
///
/// `is_admin` is injected so the check is testable; production passes the
/// relay's `check-whitelist` answer.
pub fn validate_grant(
    rumor: &UnsignedEvent,
    sealer: &str,
    is_admin: bool,
    now: u64,
) -> Result<ZoneKey, GrantError> {
    if rumor.kind != KIND_ZONE_KEY_GRANT {
        return Err(GrantError::WrongKind(rumor.kind));
    }
    let p: GrantPayload =
        serde_json::from_str(&rumor.content).map_err(|_| GrantError::Malformed)?;
    if p.zone.is_empty() || p.epoch == 0 || !is_hex64(&p.pubkey) {
        return Err(GrantError::Malformed);
    }
    let secret = hex32(&p.secret).ok_or(GrantError::Malformed)?;
    let derived = nostr_bbs_core::keys::pubkey_hex(&secret).map_err(|_| GrantError::Malformed)?;
    if !derived.eq_ignore_ascii_case(&p.pubkey) {
        return Err(GrantError::SecretMismatch);
    }
    if !is_admin {
        return Err(GrantError::NotAdmin(sealer.to_string()));
    }
    Ok(ZoneKey {
        zone: p.zone,
        epoch: p.epoch,
        secret: p.secret.to_ascii_lowercase(),
        pubkey: derived,
        granted_by: sealer.to_string(),
        received_at: now,
    })
}

/// Pubkeys that should hold `zone`'s key: members whose cohorts intersect the
/// zone's `required_cohorts`, plus the granting admin themself. Agents (cohort
/// [`AGENT_COHORT`]) are excluded — the admin included, if an agent — unless
/// the zone opts in with `agent_keys`. Sorted, deduplicated.
pub fn grant_targets(
    members: &[(String, Vec<String>)],
    required_cohorts: &[String],
    me: &str,
    agent_keys: bool,
) -> Vec<String> {
    let is_agent = |cohorts: &[String]| !agent_keys && cohorts.iter().any(|c| c == AGENT_COHORT);
    let mut out: Vec<String> = members
        .iter()
        .filter(|(_, cohorts)| {
            !is_agent(cohorts) && cohorts.iter().any(|c| required_cohorts.contains(c))
        })
        .map(|(pk, _)| pk.to_ascii_lowercase())
        .collect();
    let me_is_agent = members
        .iter()
        .find(|(pk, _)| pk.eq_ignore_ascii_case(me))
        .is_some_and(|(_, c)| is_agent(c));
    if !me.is_empty() && !me_is_agent {
        out.push(me.to_ascii_lowercase());
    }
    out.sort();
    out.dedup();
    out
}

// ---------------------------------------------------------------------------
// Read path
// ---------------------------------------------------------------------------

/// What the reader sees for one kind-42.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadOutcome {
    /// No `zk` tag: legacy/plaintext, render as-is.
    Plain,
    /// Decrypted text.
    Decrypted(String),
    /// Encrypted to an epoch the reader has no key for.
    MissingKey,
    /// A key was held but decryption failed (or the tag is malformed).
    Failed,
}

/// Decrypt `ev` with `key` (zone secret × event author).
pub fn decrypt_with(ev: &NostrEvent, key: &ZoneKey) -> Result<String, String> {
    let sk = key.secret_bytes().ok_or("bad zone secret")?;
    let author = hex32(&ev.pubkey).ok_or("bad author pubkey")?;
    nostr_bbs_core::nip44::decrypt(&sk, &author, &ev.content).map_err(|e| e.to_string())
}

/// Classify `ev` for display, looking keys up by `(zone, epoch)`.
pub fn read_outcome(ev: &NostrEvent, lookup: impl Fn(&str, u32) -> Option<ZoneKey>) -> ReadOutcome {
    if !has_zk_tag(&ev.tags) {
        return ReadOutcome::Plain;
    }
    let Some(zk) = parse_zk(&ev.tags) else {
        return ReadOutcome::Failed;
    };
    let Some(key) = lookup(&zk.zone, zk.epoch) else {
        return ReadOutcome::MissingKey;
    };
    if !key.pubkey.eq_ignore_ascii_case(&zk.pubkey) {
        return ReadOutcome::Failed;
    }
    match decrypt_with(ev, &key) {
        Ok(text) => ReadOutcome::Decrypted(text),
        Err(_) => ReadOutcome::Failed,
    }
}

/// The content to render for `outcome` (`original` is the event's content).
pub fn display_text(outcome: &ReadOutcome, original: &str) -> String {
    match outcome {
        ReadOutcome::Plain => original.to_string(),
        ReadOutcome::Decrypted(t) => t.clone(),
        ReadOutcome::MissingKey => PLACEHOLDER_MISSING_KEY.to_string(),
        ReadOutcome::Failed => PLACEHOLDER_UNDECRYPTABLE.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Write path
// ---------------------------------------------------------------------------

/// How an outgoing kind-42 must be published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WritePlan {
    /// The channel's zone is not encrypted.
    Plain,
    /// Encrypt to this key.
    Encrypt(ZoneKey),
}

/// Message shown when a member tries to post without the zone key.
pub fn missing_key_message(zone_display_name: &str) -> String {
    let name = if zone_display_name.trim().is_empty() {
        "this zone"
    } else {
        zone_display_name.trim()
    };
    format!(
        "You don't have the {name} encryption key yet — an admin needs to grant it. \
         Your message has not been sent."
    )
}

/// Decide how to publish into a zone. An encrypted zone without a held key is
/// an error — never a plaintext fallback.
pub fn write_plan(
    zone_encrypted: bool,
    zone_display_name: &str,
    latest: Option<ZoneKey>,
) -> Result<WritePlan, String> {
    if !zone_encrypted {
        return Ok(WritePlan::Plain);
    }
    latest
        .map(WritePlan::Encrypt)
        .ok_or_else(|| missing_key_message(zone_display_name))
}

/// Apply `plan` to an outgoing unsigned kind-42: encrypt its content to the
/// zone key through the author's signer (local key or NIP-07
/// `window.nostr.nip44.encrypt`) and add the `zk` tag. Plain plans pass the
/// event through untouched.
pub async fn apply_write_plan(
    plan: &WritePlan,
    signer: &dyn Signer,
    mut unsigned: UnsignedEvent,
) -> Result<UnsignedEvent, String> {
    let WritePlan::Encrypt(key) = plan else {
        return Ok(unsigned);
    };
    if unsigned.content.is_empty() {
        return Err("An encrypted message cannot be empty.".into());
    }
    let ct = signer
        .nip44_encrypt(&key.pubkey, &unsigned.content)
        .await
        .map_err(|e| format!("Could not encrypt the message: {e}"))?;
    unsigned.content = ct;
    unsigned
        .tags
        .retain(|t| t.first().map(String::as_str) != Some(ZK_TAG));
    unsigned.tags.push(zk_tag(key));
    Ok(unsigned)
}

/// Turn a relay rejection into something a member can act on.
pub fn explain_relay_rejection(message: &str) -> Option<String> {
    message.contains(RELAY_REJECT_PLAINTEXT).then(|| {
        "The relay refused this post because this zone is end-to-end encrypted and the \
         message was not. Reload the page so the forum picks up your zone key, then try again."
            .to_string()
    })
}

// ---------------------------------------------------------------------------
// Grant wrap / unwrap (composition of core NIP-44 + NIP-59 pieces)
// ---------------------------------------------------------------------------

fn seal_timestamp(now: u64) -> u64 {
    // NIP-59 recommends randomising seal/wrap timestamps into the past so the
    // relay cannot correlate the grant with the moment it was made.
    #[cfg(target_arch = "wasm32")]
    {
        now.saturating_sub((js_sys::Math::random() * 172_800.0) as u64)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        now
    }
}

/// Build the gift wrap that grants `key` to `recipient`, sealed by `signer`
/// (an admin). The rumor is [`KIND_ZONE_KEY_GRANT`]; the seal is NIP-44
/// encrypted to the recipient and signed by the admin; the wrap is
/// `nostr_bbs_core::gift_wrap::wrap_seal` (throwaway key).
pub async fn build_grant_wrap(
    signer: &dyn Signer,
    recipient: &str,
    key: &ZoneKey,
    now: u64,
) -> Result<NostrEvent, String> {
    let rumor = UnsignedEvent {
        pubkey: signer.public_key().to_string(),
        created_at: now,
        kind: KIND_ZONE_KEY_GRANT,
        tags: vec![vec!["p".to_string(), recipient.to_string()]],
        content: serde_json::to_string(&GrantPayload::from_key(key, now))
            .map_err(|e| e.to_string())?,
    };
    let rumor_json = serde_json::to_string(&rumor).map_err(|e| e.to_string())?;
    let sealed = signer
        .nip44_encrypt(recipient, &rumor_json)
        .await
        .map_err(|e| e.to_string())?;
    let seal = signer
        .sign_event(UnsignedEvent {
            pubkey: signer.public_key().to_string(),
            created_at: seal_timestamp(now),
            kind: SEAL_KIND,
            tags: vec![],
            content: sealed,
        })
        .await
        .map_err(|e| e.to_string())?;
    nostr_bbs_core::gift_wrap::wrap_seal(&seal, recipient).map_err(|e| e.to_string())
}

/// Unwrap a kind-1059 addressed to us, accepting any rumor kind (core's
/// `unwrap_gift_with_signer` admits only kind-14 DMs). Returns the verified
/// seal author and the rumor. Same checks as core: the seal's id and
/// signature verify, and the rumor's author is the seal's author.
pub async fn unwrap_any(
    gift: &NostrEvent,
    signer: &dyn Signer,
) -> Result<(String, UnsignedEvent), String> {
    if gift.kind != nostr_bbs_core::gift_wrap::KIND_GIFT_WRAP {
        return Err(format!("not a gift wrap (kind {})", gift.kind));
    }
    let seal_json = signer
        .nip44_decrypt(&gift.pubkey, &gift.content)
        .await
        .map_err(|e| e.to_string())?;
    let seal: NostrEvent = serde_json::from_str(&seal_json).map_err(|e| e.to_string())?;
    if seal.kind != SEAL_KIND {
        return Err(format!("not a seal (kind {})", seal.kind));
    }
    verify_event_strict(&seal).map_err(|e| e.to_string())?;
    let rumor_json = signer
        .nip44_decrypt(&seal.pubkey, &seal.content)
        .await
        .map_err(|e| e.to_string())?;
    let rumor: UnsignedEvent = serde_json::from_str(&rumor_json).map_err(|e| e.to_string())?;
    if rumor.pubkey != seal.pubkey {
        return Err("rumor author does not match seal author".into());
    }
    Ok((seal.pubkey, rumor))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_bbs_core::keys::generate_keypair;
    use nostr_bbs_core::signer::PrfSigner;

    fn signer() -> PrfSigner {
        PrfSigner::new(generate_keypair().unwrap())
    }

    /// Drive a future that never truly suspends (the local `PrfSigner` does
    /// all its work synchronously) without pulling in an executor crate.
    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        let mut f = std::pin::pin!(f);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    fn msg(author: &PrfSigner, content: &str, tags: Vec<Vec<String>>) -> NostrEvent {
        NostrEvent {
            id: "id".into(),
            pubkey: author.public_key().to_string(),
            created_at: 1,
            kind: 42,
            tags,
            content: content.into(),
            sig: String::new(),
        }
    }

    fn unsigned42(author: &PrfSigner, content: &str) -> UnsignedEvent {
        UnsignedEvent {
            pubkey: author.public_key().to_string(),
            created_at: 1,
            kind: 42,
            tags: vec![vec!["e".into(), "chan".into(), "".into(), "root".into()]],
            content: content.into(),
        }
    }

    #[test]
    fn author_encrypts_zone_decrypts_and_vice_versa() {
        let author = signer();
        let key = generate_zone_key("zone3", 1, "admin", 0).unwrap();
        let plan = WritePlan::Encrypt(key.clone());
        let out = block_on(apply_write_plan(
            &plan,
            &author,
            unsigned42(&author, "hello family"),
        ))
        .unwrap();
        assert_ne!(out.content, "hello family");
        assert_eq!(parse_zk(&out.tags).unwrap().epoch, 1);
        assert_eq!(out.tags[0][1], "chan", "other tags untouched");
        let ev = msg(&author, &out.content, out.tags.clone());
        assert_eq!(decrypt_with(&ev, &key).unwrap(), "hello family");
        // The other direction of the ECDH: the zone key encrypts, the author
        // (holding only their own secret) decrypts against the zone pubkey.
        let zone_sk = key.secret_bytes().unwrap();
        let author_pk = hex32(author.public_key()).unwrap();
        let ct = nostr_bbs_core::nip44::encrypt(&zone_sk, &author_pk, "reply").unwrap();
        let back = block_on(author.nip44_decrypt(&key.pubkey, &ct)).unwrap();
        assert_eq!(back, "reply");
    }

    #[test]
    fn ciphertext_is_what_the_relay_accepts() {
        let author = signer();
        let key = generate_zone_key("zone3", 2, "admin", 0).unwrap();
        let out = block_on(apply_write_plan(
            &WritePlan::Encrypt(key),
            &author,
            unsigned42(&author, "x"),
        ))
        .unwrap();
        use base64::Engine;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&out.content)
            .unwrap();
        assert_eq!(raw[0], 2, "NIP-44 v2 version byte");
        assert!(raw.len() >= 99);
        assert!((132..=87472).contains(&out.content.len()));
    }

    #[test]
    fn zk_tag_round_trips_and_rejects_malformed() {
        let key = generate_zone_key("zone3", 7, "a", 0).unwrap();
        let t = zk_tag(&key);
        let z = parse_zk(&[t]).unwrap();
        assert_eq!(
            (z.zone.as_str(), z.epoch, z.pubkey.as_str()),
            ("zone3", 7, key.pubkey.as_str())
        );
        let bad = |v: Vec<&str>| parse_zk(&[v.into_iter().map(String::from).collect()]);
        assert!(bad(vec!["zk", "zone3", "0", &key.pubkey]).is_none());
        assert!(bad(vec!["zk", "zone3", "x", &key.pubkey]).is_none());
        assert!(bad(vec!["zk", "", "1", &key.pubkey]).is_none());
        assert!(bad(vec!["zk", "zone3", "1", "abc"]).is_none());
        assert!(bad(vec!["zk", "zone3", "1"]).is_none());
    }

    fn grant_rumor(sealer: &str, payload: &GrantPayload) -> UnsignedEvent {
        UnsignedEvent {
            pubkey: sealer.into(),
            created_at: 1,
            kind: KIND_ZONE_KEY_GRANT,
            tags: vec![],
            content: serde_json::to_string(payload).unwrap(),
        }
    }

    #[test]
    fn grant_validation() {
        let key = generate_zone_key("zone3", 1, "a", 0).unwrap();
        let good = GrantPayload::from_key(&key, 5);
        let got = validate_grant(&grant_rumor("adm", &good), "adm", true, 9).unwrap();
        assert_eq!(
            (got.epoch, got.pubkey.as_str(), got.granted_by.as_str()),
            (1, key.pubkey.as_str(), "adm")
        );

        let other = generate_zone_key("zone3", 1, "a", 0).unwrap();
        let mismatched = GrantPayload {
            pubkey: other.pubkey.clone(),
            ..good.clone()
        };
        assert_eq!(
            validate_grant(&grant_rumor("adm", &mismatched), "adm", true, 9),
            Err(GrantError::SecretMismatch)
        );
        assert_eq!(
            validate_grant(&grant_rumor("mem", &good), "mem", false, 9),
            Err(GrantError::NotAdmin("mem".into()))
        );
        let mut dm = grant_rumor("adm", &good);
        dm.kind = 14;
        assert_eq!(
            validate_grant(&dm, "adm", true, 9),
            Err(GrantError::WrongKind(14))
        );
        let mut junk = grant_rumor("adm", &good);
        junk.content = "{}".into();
        assert_eq!(
            validate_grant(&junk, "adm", true, 9),
            Err(GrantError::Malformed)
        );
    }

    #[test]
    fn grant_wrap_round_trips_through_core_gift_wrap() {
        let admin = signer();
        let member = signer();
        let key = generate_zone_key("zone3", 1, admin.public_key(), 0).unwrap();
        let wrap = block_on(build_grant_wrap(&admin, member.public_key(), &key, 100)).unwrap();
        assert_eq!(wrap.kind, 1059);
        assert_ne!(
            wrap.pubkey,
            admin.public_key(),
            "wrap signed by a throwaway key"
        );
        let (sealer, rumor) = block_on(unwrap_any(&wrap, &member)).unwrap();
        assert_eq!(sealer, admin.public_key());
        let got = validate_grant(&rumor, &sealer, true, 1).unwrap();
        assert_eq!(got.secret, key.secret);
        // A third party cannot open it.
        assert!(block_on(unwrap_any(&wrap, &signer())).is_err());
    }

    #[test]
    fn agents_are_never_grant_targets() {
        let req = vec!["zone3".to_string(), "family".to_string()];
        let members = vec![
            (
                "aa".to_string(),
                vec!["members".to_string(), "family".to_string()],
            ),
            ("bb".to_string(), vec!["zone3".to_string()]),
            (
                "jj".to_string(),
                vec![
                    "members".to_string(),
                    "agent".to_string(),
                    "family".to_string(),
                ],
            ),
            ("cc".to_string(), vec!["minimoonoir".to_string()]),
        ];
        assert_eq!(
            grant_targets(&members, &req, "ME", false),
            vec!["aa", "bb", "me"]
        );
        // An agent admin never grants itself a key.
        assert_eq!(grant_targets(&members, &req, "jj", false), vec!["aa", "bb"]);
    }

    #[test]
    fn agent_keys_zone_includes_agents() {
        let req = vec!["family".to_string()];
        let members = vec![
            ("aa".to_string(), vec!["family".to_string()]),
            (
                "jj".to_string(),
                vec!["agent".to_string(), "family".to_string()],
            ),
        ];
        assert_eq!(
            grant_targets(&members, &req, "me", true),
            vec!["aa", "jj", "me"]
        );
        assert_eq!(grant_targets(&members, &req, "jj", true), vec!["aa", "jj"]);
    }

    #[test]
    fn gate_is_exact_string_true_and_ands_with_zone_flag() {
        assert!(gate_value_enabled(Some("true")));
        for off in [
            None,
            Some("false"),
            Some("TRUE"),
            Some("1"),
            Some(" true"),
            Some(""),
        ] {
            assert!(!gate_value_enabled(off), "{off:?}");
        }
        assert!(zone_is_encrypted(true, true));
        assert!(!zone_is_encrypted(false, true));
        assert!(!zone_is_encrypted(true, false));
    }

    #[test]
    fn encrypted_zone_without_key_refuses_never_plaintext() {
        let err = write_plan(true, "Family", None).unwrap_err();
        assert!(err.contains("Family encryption key"));
        assert_eq!(write_plan(false, "Public", None).unwrap(), WritePlan::Plain);
        let key = generate_zone_key("zone3", 1, "a", 0).unwrap();
        assert_eq!(
            write_plan(true, "Family", Some(key.clone())).unwrap(),
            WritePlan::Encrypt(key)
        );
        let author = signer();
        let plain = block_on(apply_write_plan(
            &WritePlan::Plain,
            &author,
            unsigned42(&author, "hi"),
        ))
        .unwrap();
        assert_eq!(plain.content, "hi");
        assert!(!has_zk_tag(&plain.tags));
    }

    #[test]
    fn read_path_placeholders_and_legacy() {
        let author = signer();
        let key = generate_zone_key("zone3", 3, "a", 0).unwrap();
        let out = block_on(apply_write_plan(
            &WritePlan::Encrypt(key.clone()),
            &author,
            unsigned42(&author, "secret"),
        ))
        .unwrap();
        let ev = msg(&author, &out.content, out.tags);
        let k2 = key.clone();
        assert_eq!(
            read_outcome(&ev, move |z, e| (z == "zone3" && e == 3)
                .then(|| k2.clone())),
            ReadOutcome::Decrypted("secret".into())
        );
        assert_eq!(read_outcome(&ev, |_, _| None), ReadOutcome::MissingKey);
        assert_eq!(
            display_text(&ReadOutcome::MissingKey, &ev.content),
            PLACEHOLDER_MISSING_KEY
        );
        let wrong = generate_zone_key("zone3", 3, "a", 0).unwrap();
        assert_eq!(
            read_outcome(&ev, move |_, _| Some(wrong.clone())),
            ReadOutcome::Failed
        );
        let legacy = msg(&author, "plain old message", vec![]);
        assert_eq!(read_outcome(&legacy, |_, _| None), ReadOutcome::Plain);
        assert_eq!(
            display_text(&ReadOutcome::Plain, &legacy.content),
            "plain old message"
        );
    }

    #[test]
    fn relay_rejection_is_explained() {
        assert!(
            explain_relay_rejection("blocked: encrypted zone requires zone-key ciphertext")
                .is_some()
        );
        assert!(explain_relay_rejection("rate limited").is_none());
    }

    /// Regression: a grant wrap was marked processed before its key was
    /// stored, so a failed IndexedDB write (or an unreachable admin check)
    /// lost the key permanently. Only a final outcome settles a wrap.
    #[test]
    fn grant_wrap_settles_only_on_a_final_outcome() {
        // Admin status unknown (relay unreachable): retry next session.
        assert!(!grant_settled(None, false, false));
        // Accepted but not persisted: retry, or the key is gone on reload.
        assert!(!grant_settled(Some(true), true, false));
        // Accepted and persisted: done.
        assert!(grant_settled(Some(true), true, true));
        // Refused (not an admin, bad secret, malformed): final.
        assert!(grant_settled(Some(false), false, false));
        assert!(grant_settled(Some(true), false, false));
    }
}
