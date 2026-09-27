//! Sealed originals: zone-encrypted envelopes that carry a complete, signed
//! plaintext kind-42 event (ADR-2017).
//!
//! ADR-2016 encrypted *new* posts in encrypted zones but left the older
//! kind-42 history as plaintext. Re-posting that history signed by an admin
//! would forge authorship. A **sealed original** instead re-publishes each
//! message as a zone-encrypted envelope whose plaintext is the *full original
//! signed event*. Its id, author, timestamp and reply graph survive, and the
//! author's own BIP-340 signature still proves the text. Once an envelope is
//! verified, the plaintext row can be removed from the relay.
//!
//! This module is the single source of truth for the wire format. The relay,
//! the forum client, the migrator CLI and any other reader must build and
//! open envelopes through [`seal_original`] and [`open_sealed`] rather than
//! re-implementing the checks.
//!
//! # Wire format, version 1
//!
//! Outer event (what the relay stores):
//!
//! | Field        | Value |
//! |--------------|-------|
//! | `kind`       | `42` |
//! | `pubkey`     | migrator key. The relay requires it to be an admin. |
//! | `created_at` | `== inner.created_at`. The relay exempts admin sealed events from its timestamp-drift check. |
//! | `tags[0]`    | `["e", <channel_id>, "", "root"]`, the same channel as the inner event's root `e` tag |
//! | `tags[1]`    | `["zk", <zone>, "<epoch>", <zone_pk_hex>]`, the existing zone-key tag |
//! | `tags[2]`    | `["sealed", <inner.id>, "1"]`: marker, inner id and format version |
//! | `content`    | `nip44_v2_encrypt(migrator_sk, zone_pk, inner_json)` |
//! | `sig`        | the migrator's Schnorr signature |
//!
//! `inner_json` is the JSON of the original **signed** event with exactly the
//! seven NIP-01 fields `{"id","pubkey","created_at","kind","tags","content","sig"}`.
//! Extra or duplicate fields are rejected.
//!
//! # Opening
//!
//! Any zone-key holder computes
//! `text = nip44_decrypt(zone_sk, outer.pubkey, outer.content)` and parses it
//! into a [`NostrEvent`]. Then **all** of the following must hold:
//!
//! 1. `inner.kind == 42`;
//! 2. [`verify_event`] accepts `inner` (id recomputed and BIP-340 signature valid);
//! 3. `inner.id` equals the id in the outer `sealed` tag (lowercase hex);
//! 4. `inner` carries **no** `zk` tag. A sealed original wraps plaintext only,
//!    so envelopes never nest;
//! 5. `inner`'s channel equals the outer event's channel (see [`channel_of`]);
//! 6. `inner.created_at == outer.created_at`.
//!
//! If any check fails, readers must treat the envelope as undecryptable and
//! never partly trust it.
//!
//! # Rationale
//!
//! - **The outer author is the migrator.** A zone-key holder already decrypts
//!   live posts by ECDH of `zone_sk` with the outer author's pubkey, and that
//!   path works unchanged for envelopes.
//! - **The `sealed` tag is the discriminator.** A normal encrypted message
//!   whose text happens to be JSON is never mistaken for an envelope.
//! - **`created_at` is preserved.** This keeps relay pagination and ordering
//!   correct, as well as clients' unread logic. The relay's 7-day drift check
//!   (`relay_do/nip_handlers.rs` `validate_event`) therefore needs a narrow
//!   exemption for sealed kind-42 events, and admin authorship is enforced
//!   separately.
//! - **Only the channel `e` tag is exposed.** The original's reply `e` tags
//!   and `p` tags stay inside the ciphertext. This leaks strictly less
//!   metadata than a live encrypted post does today.
//!
//! # Trust boundary
//!
//! [`open_sealed`] does not verify the *outer* signature. The relay verifies
//! every event on ingress, and a forged outer pubkey fails NIP-44 MAC
//! verification anyway. Callers that accept events from untrusted sources
//! other than the relay should run [`verify_event`] on the outer event first.
//! Matching the outer `zk` tag to the right zone key is also the caller's
//! job, as for any encrypted post.
//!
//! # Example
//!
//! ```
//! use nostr_bbs_core::keys::SecretKey;
//! use nostr_bbs_core::sealed::{open_sealed, parse_sealed, seal_original};
//! use nostr_bbs_core::{sign_event, UnsignedEvent};
//!
//! // Fixed test keys: the original author, the migrator (an admin) and the zone key.
//! let author = SecretKey::from_bytes([0x11; 32]).unwrap();
//! let migrator = SecretKey::from_bytes([0x22; 32]).unwrap();
//! let zone = SecretKey::from_bytes([0x33; 32]).unwrap();
//! let channel = "c".repeat(64);
//!
//! let signing_key = k256::schnorr::SigningKey::from_bytes(author.as_bytes()).unwrap();
//! let original = sign_event(
//!     UnsignedEvent {
//!         pubkey: author.public_key().to_hex(),
//!         created_at: 1_700_000_000,
//!         kind: 42,
//!         tags: vec![vec!["e".into(), channel.clone(), "".into(), "root".into()]],
//!         content: "hello from before encryption".into(),
//!     },
//!     &signing_key,
//! )
//! .unwrap();
//!
//! let envelope =
//!     seal_original(&original, "zone3", 1, &zone.public_key().to_hex(), &migrator).unwrap();
//! assert_eq!(envelope.created_at, original.created_at);
//! assert_eq!(parse_sealed(&envelope.tags).unwrap().inner_id, original.id);
//!
//! let opened = open_sealed(&envelope, zone.as_bytes()).unwrap();
//! assert_eq!(opened.id, original.id);
//! assert_eq!(opened.content, original.content);
//! ```

use crate::event::{sign_event, verify_event, NostrEvent, UnsignedEvent};
use crate::keys::SecretKey;
use crate::nip44;
use k256::schnorr::SigningKey;
use serde::Deserialize;
use thiserror::Error;

/// Tag name marking a sealed-original envelope: `["sealed", <inner id>, <version>]`.
pub const SEALED_TAG: &str = "sealed";

/// The only envelope format version this module builds and opens.
pub const SEALED_VERSION: &str = "1";

/// Kind of both the envelope and the original it wraps (NIP-28 channel message).
const KIND_CHANNEL_MESSAGE: u64 = 42;

/// Zone-key tag name. It must match the forum client's `zone_crypto::ZK_TAG`
/// and the relay's `zone_config::is_zone_ciphertext`.
const ZK_TAG: &str = "zk";

/// Errors from sealing or opening a sealed-original envelope.
///
/// The `Display` text is short and free of secrets, so it can be written to
/// UI or CLI logs. Every variant means the same thing to a reader: render the
/// envelope as undecryptable.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SealError {
    /// The event is not kind 42. On open this is **check 1** for the inner
    /// event; it also applies to the outer envelope and, on seal, to the
    /// original.
    #[error("sealed original: expected kind 42, got {0}")]
    WrongKind(u64),

    /// The inner or original event failed [`verify_event`]: its id does not
    /// match the canonical serialisation, or its signature is invalid
    /// (**check 2**).
    #[error("sealed original: inner event id or signature does not verify")]
    InvalidSignature,

    /// The decrypted event's id differs from the id in the outer `sealed`
    /// tag (**check 3**).
    #[error("sealed original: inner id does not match the sealed tag")]
    IdMismatch,

    /// The inner or original event already carries a `zk` tag. Sealed
    /// originals wrap plaintext only and never nest (**check 4**).
    #[error("sealed original: inner event is already zone-encrypted")]
    NestedZoneKey,

    /// The inner event's channel differs from the outer envelope's channel
    /// (**check 5**).
    #[error("sealed original: inner channel does not match the envelope channel")]
    ChannelMismatch,

    /// The inner `created_at` differs from the outer `created_at` (**check 6**).
    #[error("sealed original: inner created_at does not match the envelope")]
    CreatedAtMismatch,

    /// The outer event has no well-formed `sealed` tag (see [`parse_sealed`]).
    #[error("sealed original: missing or malformed sealed tag")]
    NotSealed,

    /// The `sealed` tag names a format version this build does not understand.
    #[error("sealed original: unsupported format version {0}")]
    UnsupportedVersion(u32),

    /// The original (on seal) or the outer envelope (on open) has no channel
    /// `e` tag.
    #[error("sealed original: no channel e-tag")]
    MissingChannel,

    /// The zone name, epoch or zone public key given to [`seal_original`] is
    /// not well formed. The zone must be non-empty, the epoch at least 1 and
    /// the key 64 hex characters on the curve.
    #[error("sealed original: invalid zone key parameters: {0}")]
    InvalidZoneKey(&'static str),

    /// NIP-44 encryption of the inner JSON failed, for example because the
    /// original exceeds the 65 535-byte plaintext ceiling.
    #[error("sealed original: encryption failed: {0}")]
    Encrypt(String),

    /// NIP-44 decryption failed: wrong zone key, wrong outer author or
    /// tampered ciphertext.
    #[error("sealed original: decryption failed")]
    Decrypt,

    /// The decrypted plaintext is not exactly one NIP-01 event with the
    /// seven standard fields. Extra, missing or duplicate fields all land here.
    #[error("sealed original: inner payload is not a well-formed event")]
    MalformedInner,

    /// Signing the outer envelope failed.
    #[error("sealed original: signing failed: {0}")]
    Sign(String),
}

/// A parsed `["sealed", <inner id>, <version>]` tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedRef {
    /// Id of the wrapped original event, as lowercase 64-character hex.
    pub inner_id: String,
    /// Envelope format version. Only `1` ([`SEALED_VERSION`]) can be opened.
    pub version: u32,
}

/// Parse the first well-formed `sealed` tag.
///
/// A tag is well formed when it has at least three elements, its second
/// element is 64 hex characters and its third is a decimal `u32`. The inner id
/// is lowercased. The version is **not** restricted to [`SEALED_VERSION`]
/// here; [`open_sealed`] rejects unknown versions. Use [`has_sealed_tag`] for
/// policy decisions that must also catch malformed markers.
///
/// ```
/// use nostr_bbs_core::sealed::parse_sealed;
/// let id = "ab".repeat(32);
/// let tags = vec![vec!["sealed".to_string(), id.clone(), "1".to_string()]];
/// let r = parse_sealed(&tags).unwrap();
/// assert_eq!((r.inner_id.as_str(), r.version), (id.as_str(), 1));
/// assert!(parse_sealed(&[vec!["sealed".to_string(), "nothex".to_string(), "1".to_string()]]).is_none());
/// ```
pub fn parse_sealed(tags: &[Vec<String>]) -> Option<SealedRef> {
    tags.iter().find_map(|t| {
        if t.len() < 3 || t[0] != SEALED_TAG || !is_hex64(&t[1]) {
            return None;
        }
        let version: u32 = t[2].parse().ok()?;
        Some(SealedRef {
            inner_id: t[1].to_ascii_lowercase(),
            version,
        })
    })
}

/// Whether any tag is named `sealed`, well formed or not.
///
/// Use this for gatekeeping, such as the relay's admin-only rule, so that a
/// malformed marker cannot slip past a check that keys on [`parse_sealed`].
///
/// ```
/// use nostr_bbs_core::sealed::has_sealed_tag;
/// assert!(has_sealed_tag(&[vec!["sealed".to_string()]]));
/// assert!(!has_sealed_tag(&[vec!["e".to_string(), "x".to_string()]]));
/// ```
pub fn has_sealed_tag(tags: &[Vec<String>]) -> bool {
    tags.iter()
        .any(|t| t.first().map(String::as_str) == Some(SEALED_TAG))
}

/// The channel a kind-42 event belongs to: the value of the first `e` tag
/// marked `root`, or else the first `e` tag.
///
/// This prefers the root marker, unlike [`crate::thread::post_root_channel`],
/// so a reply whose `reply`-marked `e` tag comes before its `root` tag still
/// maps to the right channel.
///
/// ```
/// use nostr_bbs_core::sealed::channel_of;
/// use nostr_bbs_core::NostrEvent;
/// let ev = NostrEvent {
///     id: String::new(), pubkey: String::new(), created_at: 0, kind: 42, sig: String::new(),
///     content: String::new(),
///     tags: vec![
///         vec!["e".into(), "parent".into(), "".into(), "reply".into()],
///         vec!["e".into(), "chan".into(), "".into(), "root".into()],
///     ],
/// };
/// assert_eq!(channel_of(&ev), Some("chan"));
/// ```
pub fn channel_of(ev: &NostrEvent) -> Option<&str> {
    let is_e = |t: &&Vec<String>| t.first().map(String::as_str) == Some("e") && t.len() >= 2;
    ev.tags
        .iter()
        .filter(is_e)
        .find(|t| t.get(3).map(String::as_str) == Some("root"))
        .or_else(|| ev.tags.iter().find(is_e))
        .map(|t| t[1].as_str())
}

/// Seal a plaintext kind-42 `original` into a zone-encrypted envelope signed
/// by `migrator_sk`.
///
/// First the original is validated: it must be kind 42 (**check 1**), pass
/// [`verify_event`] (**check 2**), carry no `zk` tag (**check 4**) and have a
/// channel `e` tag. The envelope then satisfies checks 3, 5 and 6 by
/// construction. Its tags are, in order, `["e", channel, "", "root"]`,
/// `["zk", zone, epoch, zone_pk_hex]` and `["sealed", original.id, "1"]`.
/// Its `created_at` is the original's, and its content is the NIP-44 v2
/// encryption of the original's JSON from `migrator_sk` to the zone public
/// key.
///
/// `zone` must be non-empty, `epoch` at least 1 and `zone_pk_hex` a valid
/// 64-hex x-only public key. These are the same shape rules the relay applies
/// to `zk` tags. The zone public key is written lowercase.
///
/// The migrator pubkey must be a relay admin for the relay to accept the
/// envelope. That rule is enforced by the relay, not here.
pub fn seal_original(
    original: &NostrEvent,
    zone: &str,
    epoch: u32,
    zone_pk_hex: &str,
    migrator_sk: &SecretKey,
) -> Result<NostrEvent, SealError> {
    if original.kind != KIND_CHANNEL_MESSAGE {
        return Err(SealError::WrongKind(original.kind));
    }
    if !verify_event(original) {
        return Err(SealError::InvalidSignature);
    }
    if has_zk_tag(&original.tags) {
        return Err(SealError::NestedZoneKey);
    }
    let channel = channel_of(original).ok_or(SealError::MissingChannel)?;

    if zone.is_empty() {
        return Err(SealError::InvalidZoneKey("empty zone"));
    }
    if epoch < 1 {
        return Err(SealError::InvalidZoneKey("epoch must be >= 1"));
    }
    let zone_pk =
        decode_hex32(zone_pk_hex).ok_or(SealError::InvalidZoneKey("zone pubkey must be 64 hex"))?;
    crate::keys::PublicKey::from_bytes(zone_pk)
        .map_err(|_| SealError::InvalidZoneKey("zone pubkey is not on the curve"))?;

    // `NostrEvent` serialises exactly the seven NIP-01 fields in declaration order.
    let inner_json = serde_json::to_string(original).map_err(|_| SealError::MalformedInner)?;

    build_envelope(
        &inner_json,
        channel,
        original.created_at,
        &original.id,
        zone,
        epoch,
        &zone_pk,
        migrator_sk,
    )
}

/// Open a sealed-original envelope with the zone secret key and return the
/// verified original event.
///
/// The outer event must be kind 42 with a well-formed version-1 `sealed` tag
/// and a channel `e` tag. Its content is NIP-44-decrypted with
/// `zone_sk × outer.pubkey` and parsed strictly: exactly the seven NIP-01
/// fields, with nothing extra or duplicated. Then **all six checks** must
/// pass:
///
/// 1. `inner.kind == 42` ([`SealError::WrongKind`]);
/// 2. [`verify_event`] accepts `inner` ([`SealError::InvalidSignature`]);
/// 3. `inner.id` equals the `sealed` tag's id ([`SealError::IdMismatch`]);
/// 4. `inner` has no `zk` tag ([`SealError::NestedZoneKey`]);
/// 5. [`channel_of`] `inner` equals [`channel_of`] `outer` ([`SealError::ChannelMismatch`]);
/// 6. `inner.created_at == outer.created_at` ([`SealError::CreatedAtMismatch`]).
///
/// Any error means the envelope is undecryptable. Callers must not fall back
/// to showing partial data. The outer signature is not verified here; see the
/// module-level *Trust boundary* section.
pub fn open_sealed(outer: &NostrEvent, zone_sk: &[u8; 32]) -> Result<NostrEvent, SealError> {
    if outer.kind != KIND_CHANNEL_MESSAGE {
        return Err(SealError::WrongKind(outer.kind));
    }
    let sealed = parse_sealed(&outer.tags).ok_or(SealError::NotSealed)?;
    if sealed.version.to_string() != SEALED_VERSION {
        return Err(SealError::UnsupportedVersion(sealed.version));
    }
    let outer_channel = channel_of(outer).ok_or(SealError::MissingChannel)?;
    let migrator_pk = decode_hex32(&outer.pubkey).ok_or(SealError::Decrypt)?;

    let text =
        nip44::decrypt(zone_sk, &migrator_pk, &outer.content).map_err(|_| SealError::Decrypt)?;
    let inner: NostrEvent = serde_json::from_str::<InnerWire>(&text)
        .map_err(|_| SealError::MalformedInner)?
        .into();

    // 1. kind
    if inner.kind != KIND_CHANNEL_MESSAGE {
        return Err(SealError::WrongKind(inner.kind));
    }
    // 2. id recomputed + BIP-340 signature
    if !verify_event(&inner) {
        return Err(SealError::InvalidSignature);
    }
    // 3. id bound to the outer marker (verified ids are lowercase hex)
    if inner.id != sealed.inner_id {
        return Err(SealError::IdMismatch);
    }
    // 4. no nesting
    if has_zk_tag(&inner.tags) {
        return Err(SealError::NestedZoneKey);
    }
    // 5. same channel
    if channel_of(&inner) != Some(outer_channel) {
        return Err(SealError::ChannelMismatch);
    }
    // 6. same timestamp
    if inner.created_at != outer.created_at {
        return Err(SealError::CreatedAtMismatch);
    }
    Ok(inner)
}

// ── Internals ────────────────────────────────────────────────────────────────

/// Strict mirror of [`NostrEvent`] for the inner payload. `NostrEvent` itself
/// tolerates unknown fields, but the wire format admits exactly seven.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InnerWire {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u64,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

impl From<InnerWire> for NostrEvent {
    fn from(w: InnerWire) -> Self {
        NostrEvent {
            id: w.id,
            pubkey: w.pubkey,
            created_at: w.created_at,
            kind: w.kind,
            tags: w.tags,
            content: w.content,
            sig: w.sig,
        }
    }
}

/// Encrypt `inner_json` to the zone key and sign the outer envelope. This does
/// not validate the plaintext, so tests can craft hostile envelopes with it.
#[allow(clippy::too_many_arguments)]
fn build_envelope(
    inner_json: &str,
    channel: &str,
    created_at: u64,
    inner_id: &str,
    zone: &str,
    epoch: u32,
    zone_pk: &[u8; 32],
    migrator_sk: &SecretKey,
) -> Result<NostrEvent, SealError> {
    let content = nip44::encrypt(migrator_sk.as_bytes(), zone_pk, inner_json)
        .map_err(|e| SealError::Encrypt(e.to_string()))?;
    let unsigned = UnsignedEvent {
        pubkey: migrator_sk.public_key().to_hex(),
        created_at,
        kind: KIND_CHANNEL_MESSAGE,
        tags: vec![
            vec![
                "e".to_string(),
                channel.to_string(),
                String::new(),
                "root".to_string(),
            ],
            vec![
                ZK_TAG.to_string(),
                zone.to_string(),
                epoch.to_string(),
                hex::encode(zone_pk),
            ],
            vec![
                SEALED_TAG.to_string(),
                inner_id.to_string(),
                SEALED_VERSION.to_string(),
            ],
        ],
        content,
    };
    let signing_key = SigningKey::from_bytes(migrator_sk.as_bytes())
        .map_err(|e| SealError::Sign(e.to_string()))?;
    sign_event(unsigned, &signing_key).map_err(|e| SealError::Sign(e.to_string()))
}

fn has_zk_tag(tags: &[Vec<String>]) -> bool {
    tags.iter()
        .any(|t| t.first().map(String::as_str) == Some(ZK_TAG))
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if !is_hex64(s) {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREATED_AT: u64 = 1_700_000_000;

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_bytes([byte; 32]).unwrap()
    }
    fn author() -> SecretKey {
        key(0x11)
    }
    fn migrator() -> SecretKey {
        key(0x22)
    }
    fn zone() -> SecretKey {
        key(0x33)
    }
    fn channel() -> String {
        "c".repeat(64)
    }
    fn zone_pk_hex() -> String {
        zone().public_key().to_hex()
    }

    fn sign(
        sk: &SecretKey,
        kind: u64,
        created_at: u64,
        tags: Vec<Vec<String>>,
        content: &str,
    ) -> NostrEvent {
        let signing_key = SigningKey::from_bytes(sk.as_bytes()).unwrap();
        sign_event(
            UnsignedEvent {
                pubkey: sk.public_key().to_hex(),
                created_at,
                kind,
                tags,
                content: content.to_string(),
            },
            &signing_key,
        )
        .unwrap()
    }

    fn tag(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    /// A threaded reply with a `p` tag, so the test proves the inner tags
    /// survive while only the channel tag is exposed.
    fn original() -> NostrEvent {
        sign(
            &author(),
            42,
            CREATED_AT,
            vec![
                tag(&["e", &channel(), "", "root"]),
                tag(&["e", &"d".repeat(64), "", "reply"]),
                tag(&["p", &"e".repeat(64)]),
            ],
            "the plaintext of a family-zone post",
        )
    }

    /// Envelope around arbitrary plaintext, bypassing `seal_original`'s checks.
    fn craft(inner_json: &str, channel: &str, created_at: u64, inner_id: &str) -> NostrEvent {
        let zone_pk = decode_hex32(&zone_pk_hex()).unwrap();
        build_envelope(
            inner_json,
            channel,
            created_at,
            inner_id,
            "zone3",
            1,
            &zone_pk,
            &migrator(),
        )
        .unwrap()
    }

    fn craft_around(inner: &NostrEvent) -> NostrEvent {
        craft(
            &serde_json::to_string(inner).unwrap(),
            &channel(),
            inner.created_at,
            &inner.id,
        )
    }

    fn open(outer: &NostrEvent) -> Result<NostrEvent, SealError> {
        open_sealed(outer, zone().as_bytes())
    }

    // ── Round trip and wire shape ───────────────────────────────────────────

    #[test]
    fn round_trip_restores_the_original_byte_for_byte() {
        let orig = original();
        let outer = seal_original(&orig, "zone3", 1, &zone_pk_hex(), &migrator()).unwrap();
        let inner = open(&outer).unwrap();
        assert_eq!(
            serde_json::to_string(&inner).unwrap(),
            serde_json::to_string(&orig).unwrap()
        );
    }

    #[test]
    fn envelope_matches_the_wire_format() {
        let orig = original();
        let outer = seal_original(&orig, "zone3", 7, &zone_pk_hex(), &migrator()).unwrap();
        assert!(verify_event(&outer));
        assert_eq!(outer.kind, 42);
        assert_eq!(outer.pubkey, migrator().public_key().to_hex());
        assert_eq!(outer.created_at, orig.created_at);
        assert_eq!(
            outer.tags,
            vec![
                tag(&["e", &channel(), "", "root"]),
                tag(&["zk", "zone3", "7", &zone_pk_hex()]),
                tag(&["sealed", &orig.id, "1"]),
            ]
        );
        // The original's reply and p tags are hidden inside the ciphertext.
        assert!(!outer.content.contains(&"d".repeat(64)));
        assert!(!outer.content.contains("plaintext"));
        assert_eq!(
            parse_sealed(&outer.tags),
            Some(SealedRef {
                inner_id: orig.id.clone(),
                version: 1
            })
        );
    }

    #[test]
    fn inner_json_has_exactly_the_seven_nip01_fields() {
        let json = serde_json::to_value(original()).unwrap();
        let mut keys: Vec<_> = json.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "content",
                "created_at",
                "id",
                "kind",
                "pubkey",
                "sig",
                "tags"
            ]
        );
    }

    // ── The six open checks, each failing on its own ────────────────────────

    #[test]
    fn check1_inner_kind_must_be_42() {
        let inner = sign(
            &author(),
            1,
            CREATED_AT,
            vec![tag(&["e", &channel(), "", "root"])],
            "x",
        );
        assert_eq!(
            open(&craft_around(&inner)).unwrap_err(),
            SealError::WrongKind(1)
        );
    }

    #[test]
    fn check2_inner_signature_must_verify() {
        let mut inner = original();
        let mut sig = inner.sig.into_bytes();
        sig[0] = if sig[0] == b'0' { b'1' } else { b'0' };
        inner.sig = String::from_utf8(sig).unwrap();
        assert_eq!(
            open(&craft_around(&inner)).unwrap_err(),
            SealError::InvalidSignature
        );
    }

    #[test]
    fn check2_tampered_inner_content_fails_signature() {
        let mut inner = original();
        inner.content = "words the author never wrote".into();
        assert_eq!(
            open(&craft_around(&inner)).unwrap_err(),
            SealError::InvalidSignature
        );
    }

    #[test]
    fn check3_inner_id_must_match_sealed_tag() {
        let inner = original();
        let outer = craft(
            &serde_json::to_string(&inner).unwrap(),
            &channel(),
            CREATED_AT,
            &"f".repeat(64),
        );
        assert_eq!(open(&outer).unwrap_err(), SealError::IdMismatch);
    }

    #[test]
    fn check3_sealed_tag_id_compare_is_case_insensitive_on_the_tag() {
        let inner = original();
        let outer = craft(
            &serde_json::to_string(&inner).unwrap(),
            &channel(),
            CREATED_AT,
            &inner.id.to_ascii_uppercase(),
        );
        assert_eq!(open(&outer).unwrap().id, inner.id);
    }

    #[test]
    fn check4_inner_must_not_carry_a_zk_tag() {
        let inner = sign(
            &author(),
            42,
            CREATED_AT,
            vec![
                tag(&["e", &channel(), "", "root"]),
                tag(&["zk", "zone3", "1", &zone_pk_hex()]),
            ],
            "x",
        );
        assert_eq!(
            open(&craft_around(&inner)).unwrap_err(),
            SealError::NestedZoneKey
        );
    }

    #[test]
    fn check5_inner_channel_must_match_outer() {
        let inner = original();
        let outer = craft(
            &serde_json::to_string(&inner).unwrap(),
            &"b".repeat(64),
            CREATED_AT,
            &inner.id,
        );
        assert_eq!(open(&outer).unwrap_err(), SealError::ChannelMismatch);
    }

    #[test]
    fn check6_inner_created_at_must_match_outer() {
        let inner = original();
        let outer = craft(
            &serde_json::to_string(&inner).unwrap(),
            &channel(),
            CREATED_AT + 1,
            &inner.id,
        );
        assert_eq!(open(&outer).unwrap_err(), SealError::CreatedAtMismatch);
    }

    // ── Payload strictness and key handling ─────────────────────────────────

    #[test]
    fn extra_json_field_is_rejected() {
        let orig = original();
        let mut value = serde_json::to_value(&orig).unwrap();
        value["relay_hint"] = serde_json::json!("wss://example");
        let outer = craft(&value.to_string(), &channel(), CREATED_AT, &orig.id);
        assert_eq!(open(&outer).unwrap_err(), SealError::MalformedInner);
    }

    #[test]
    fn duplicate_json_field_is_rejected() {
        let orig = original();
        let json = serde_json::to_string(&orig).unwrap();
        let dup = format!("{},\"content\":\"smuggled\"}}", &json[..json.len() - 1]);
        let outer = craft(&dup, &channel(), CREATED_AT, &orig.id);
        assert_eq!(open(&outer).unwrap_err(), SealError::MalformedInner);
    }

    #[test]
    fn missing_json_field_and_non_json_are_rejected() {
        let orig = original();
        let mut value = serde_json::to_value(&orig).unwrap();
        value.as_object_mut().unwrap().remove("sig");
        let outer = craft(&value.to_string(), &channel(), CREATED_AT, &orig.id);
        assert_eq!(open(&outer).unwrap_err(), SealError::MalformedInner);
        let outer = craft("just some text", &channel(), CREATED_AT, &orig.id);
        assert_eq!(open(&outer).unwrap_err(), SealError::MalformedInner);
    }

    #[test]
    fn wrong_zone_key_fails_decrypt() {
        let outer = seal_original(&original(), "zone3", 1, &zone_pk_hex(), &migrator()).unwrap();
        assert_eq!(
            open_sealed(&outer, key(0x44).as_bytes()).unwrap_err(),
            SealError::Decrypt
        );
    }

    #[test]
    fn tampered_outer_ciphertext_or_author_fails_decrypt() {
        let outer = seal_original(&original(), "zone3", 1, &zone_pk_hex(), &migrator()).unwrap();
        let mut bad = outer.clone();
        let mut bytes = bad.content.into_bytes();
        let mid = bytes.len() / 2;
        bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };
        bad.content = String::from_utf8(bytes).unwrap();
        assert_eq!(open(&bad).unwrap_err(), SealError::Decrypt);

        let mut reauthored = outer;
        reauthored.pubkey = key(0x55).public_key().to_hex();
        assert_eq!(open(&reauthored).unwrap_err(), SealError::Decrypt);
    }

    #[test]
    fn outer_preconditions_are_enforced() {
        let outer = seal_original(&original(), "zone3", 1, &zone_pk_hex(), &migrator()).unwrap();

        let mut no_tag = outer.clone();
        no_tag.tags.retain(|t| t[0] != SEALED_TAG);
        assert_eq!(open(&no_tag).unwrap_err(), SealError::NotSealed);

        let mut v2 = outer.clone();
        v2.tags[2][2] = "2".into();
        assert_eq!(open(&v2).unwrap_err(), SealError::UnsupportedVersion(2));

        let mut no_chan = outer.clone();
        no_chan.tags.retain(|t| t[0] != "e");
        assert_eq!(open(&no_chan).unwrap_err(), SealError::MissingChannel);

        let mut kind1 = outer;
        kind1.kind = 1;
        assert_eq!(open(&kind1).unwrap_err(), SealError::WrongKind(1));
    }

    // ── seal_original validation ────────────────────────────────────────────

    #[test]
    fn seal_rejects_invalid_originals() {
        let pk = zone_pk_hex();
        let m = migrator();

        let kind1 = sign(
            &author(),
            1,
            CREATED_AT,
            vec![tag(&["e", &channel(), "", "root"])],
            "x",
        );
        assert_eq!(
            seal_original(&kind1, "zone3", 1, &pk, &m).unwrap_err(),
            SealError::WrongKind(1)
        );

        let mut forged = original();
        forged.content.push('!');
        assert_eq!(
            seal_original(&forged, "zone3", 1, &pk, &m).unwrap_err(),
            SealError::InvalidSignature
        );

        let encrypted = sign(
            &author(),
            42,
            CREATED_AT,
            vec![
                tag(&["e", &channel(), "", "root"]),
                tag(&["zk", "zone3", "1", &pk]),
            ],
            "x",
        );
        assert_eq!(
            seal_original(&encrypted, "zone3", 1, &pk, &m).unwrap_err(),
            SealError::NestedZoneKey
        );

        let orphan = sign(&author(), 42, CREATED_AT, vec![tag(&["p", &pk])], "x");
        assert_eq!(
            seal_original(&orphan, "zone3", 1, &pk, &m).unwrap_err(),
            SealError::MissingChannel
        );
    }

    #[test]
    fn seal_rejects_invalid_zone_parameters() {
        let orig = original();
        let m = migrator();
        let pk = zone_pk_hex();
        assert!(matches!(
            seal_original(&orig, "", 1, &pk, &m),
            Err(SealError::InvalidZoneKey(_))
        ));
        assert!(matches!(
            seal_original(&orig, "zone3", 0, &pk, &m),
            Err(SealError::InvalidZoneKey(_))
        ));
        assert!(matches!(
            seal_original(&orig, "zone3", 1, "abc", &m),
            Err(SealError::InvalidZoneKey(_))
        ));
        // x = 0 is not the x-coordinate of any secp256k1 point.
        assert!(matches!(
            seal_original(&orig, "zone3", 1, &"0".repeat(64), &m),
            Err(SealError::InvalidZoneKey(_))
        ));
    }

    #[test]
    fn seal_lowercases_zone_pubkey() {
        let pk = zone_pk_hex().to_ascii_uppercase();
        let outer = seal_original(&original(), "zone3", 1, &pk, &migrator()).unwrap();
        assert_eq!(outer.tags[1][3], zone_pk_hex());
        assert!(open(&outer).is_ok());
    }

    // ── Tag helpers ─────────────────────────────────────────────────────────

    #[test]
    fn parse_sealed_requires_hex_id_and_numeric_version() {
        let id = "A".repeat(64);
        assert_eq!(
            parse_sealed(&[tag(&["sealed", &id, "1"])]),
            Some(SealedRef {
                inner_id: "a".repeat(64),
                version: 1
            })
        );
        assert_eq!(parse_sealed(&[tag(&["sealed", &id])]), None);
        assert_eq!(parse_sealed(&[tag(&["sealed", &id, "one"])]), None);
        assert_eq!(parse_sealed(&[tag(&["sealed", "abc", "1"])]), None);
        // A malformed marker is still a marker for gatekeeping.
        assert!(has_sealed_tag(&[tag(&["sealed", "abc"])]));
        // First well-formed tag wins.
        assert_eq!(
            parse_sealed(&[tag(&["sealed", "bad", "1"]), tag(&["sealed", &id, "3"])])
                .map(|r| r.version),
            Some(3)
        );
    }

    #[test]
    fn channel_of_prefers_root_marker_then_first_e_tag() {
        let mut ev = original();
        ev.tags = vec![
            tag(&["e", "reply-target", "", "reply"]),
            tag(&["e", "chan", "", "root"]),
        ];
        assert_eq!(channel_of(&ev), Some("chan"));
        ev.tags = vec![
            tag(&["p", "x"]),
            tag(&["e", "first"]),
            tag(&["e", "second"]),
        ];
        assert_eq!(channel_of(&ev), Some("first"));
        ev.tags = vec![tag(&["e"]), tag(&["p", "x"])];
        assert_eq!(channel_of(&ev), None);
    }

    #[test]
    fn seal_uses_root_marked_channel_for_reply_first_originals() {
        let orig = sign(
            &author(),
            42,
            CREATED_AT,
            vec![
                tag(&["e", &"d".repeat(64), "", "reply"]),
                tag(&["e", &channel(), "", "root"]),
            ],
            "reply listed first",
        );
        let outer = seal_original(&orig, "zone3", 1, &zone_pk_hex(), &migrator()).unwrap();
        assert_eq!(channel_of(&outer), Some(channel().as_str()));
        assert_eq!(open(&outer).unwrap().id, orig.id);
    }

    #[test]
    fn error_display_is_log_friendly() {
        assert_eq!(
            SealError::ChannelMismatch.to_string(),
            "sealed original: inner channel does not match the envelope channel"
        );
        assert_eq!(
            SealError::UnsupportedVersion(9).to_string(),
            "sealed original: unsupported format version 9"
        );
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod proptests {
    use super::*;
    use crate::keys::generate_keypair;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// seal → open is the identity over arbitrary Unicode content and
        /// timestamps, with fresh keys for every role.
        #[test]
        fn seal_then_open_is_identity(
            content in "\\PC{0,400}",
            created_at in 0u64..=4_000_000_000,
            epoch in 1u32..1000,
        ) {
            let author = generate_keypair().unwrap();
            let migrator = generate_keypair().unwrap();
            let zone = generate_keypair().unwrap();
            let channel = hex::encode(zone.public.as_bytes()).replace('0', "a");
            let signing_key = SigningKey::from_bytes(author.secret.as_bytes()).unwrap();
            let original = sign_event(
                UnsignedEvent {
                    pubkey: author.public.to_hex(),
                    created_at,
                    kind: 42,
                    tags: vec![vec!["e".into(), channel, String::new(), "root".into()]],
                    content,
                },
                &signing_key,
            )
            .unwrap();

            let outer = seal_original(&original, "zone2", epoch, &zone.public.to_hex(), &migrator.secret).unwrap();
            let inner = open_sealed(&outer, zone.secret.as_bytes()).unwrap();
            prop_assert_eq!(
                serde_json::to_string(&inner).unwrap(),
                serde_json::to_string(&original).unwrap()
            );
        }
    }
}
