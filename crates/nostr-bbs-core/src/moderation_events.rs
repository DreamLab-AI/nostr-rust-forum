//! Moderation event kinds for forum operation (parameterized-replaceable).
//!
//! Implements five custom kinds used by the admin CLI + auth-worker + relay:
//!
//! | Event             | Kind   | `d` tag                       |
//! |-------------------|--------|-------------------------------|
//! | Ban               | 30910  | banned pubkey (hex)           |
//! | Mute              | 30911  | muted pubkey (hex)            |
//! | Warning           | 30912  | warned pubkey + ":" + ts      |
//! | Report            | 30913  | reported event id             |
//! | ModerationAction  | 30914  | action uuid (audit log)       |
//!
//! All five are **parameterized-replaceable** per NIP-33 (30000-39999 range),
//! so the latest event per `(kind, pubkey, d-tag)` is the authoritative one.
//!
//! These events are signed by an admin pubkey. The relay + auth-worker are
//! expected to reject publication from non-admin signers; this module
//! provides a pure-function validator to support that check.

use crate::event::{NostrEvent, UnsignedEvent};
use std::collections::HashSet;
use thiserror::Error;

// ── Kind constants ────────────────────────────────────────────────────────

/// Permanent ban on a pubkey. `d` tag = banned pubkey (hex, 64 chars).
pub const KIND_BAN: u64 = 30910;

/// Temporary mute on a pubkey. `d` tag = muted pubkey. Add `expires` tag
/// with a unix-seconds value to bound the mute; absence = indefinite.
pub const KIND_MUTE: u64 = 30911;

/// Formal warning to a pubkey. `d` tag = `<pubkey>:<created_at_secs>`
/// (the timestamp suffix makes each warning independent rather than replacing
/// the previous one, giving the member an audit trail).
pub const KIND_WARNING: u64 = 30912;

/// User-submitted report against an event. `d` tag = reported event id.
pub const KIND_REPORT: u64 = 30913;

/// Freeform audit log entry. `d` tag = action uuid (e.g. nanoid/ulid).
pub const KIND_MODERATION_ACTION: u64 = 30914;

/// Lifts a ban issued via kind-30910. `d` tag = `{admin_pubkey}:{target_pubkey}`.
/// A target pubkey is NOT banned if a 30915 event exists with the same admin:target d-tag.
pub const KIND_UNBAN: u64 = 30915;

/// Lifts a mute issued via kind-30911. `d` tag = `{admin_pubkey}:{target_pubkey}`.
/// A target pubkey is NOT muted if a 30916 event exists with the same admin:target d-tag.
pub const KIND_UNMUTE: u64 = 30916;

/// Standard Nostr report event kind (NIP-56). Stored as regular events by the relay.
pub const KIND_REPORT_NIP56: u64 = 1984;

/// All moderation kinds, handy for bulk checks.
pub const MOD_KINDS: &[u64] = &[
    KIND_BAN,
    KIND_MUTE,
    KIND_WARNING,
    KIND_REPORT,
    KIND_MODERATION_ACTION,
    KIND_UNBAN,
    KIND_UNMUTE,
];

/// Kinds that MUST be signed by an admin to be accepted.
pub const ADMIN_ONLY_MOD_KINDS: &[u64] = &[
    KIND_BAN,
    KIND_MUTE,
    KIND_WARNING,
    KIND_MODERATION_ACTION,
    KIND_UNBAN,
    KIND_UNMUTE,
];

// ── Errors ────────────────────────────────────────────────────────────────

/// Reasons a moderation event can fail validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ModerationEventError {
    /// The event kind is not one of the known moderation kinds.
    #[error("kind {0} is not a moderation event kind")]
    UnknownKind(u64),

    /// The `d` tag required by parameterized-replaceable semantics is missing.
    #[error("missing `d` tag")]
    MissingDTag,

    /// The `d` tag is present but empty.
    #[error("`d` tag is empty")]
    EmptyDTag,

    /// The `d` tag doesn't match the expected shape for this kind.
    #[error("invalid `d` tag for kind {kind}: {reason}")]
    InvalidDTag {
        /// The kind being validated.
        kind: u64,
        /// Why the d-tag is invalid.
        reason: &'static str,
    },

    /// The event signer is not in the admin set for an admin-only kind.
    #[error("signer {pubkey} is not an admin")]
    NotAdmin {
        /// The offending signer pubkey.
        pubkey: String,
    },

    /// Report events must reference a target pubkey via `p` tag.
    #[error("report missing `p` (target pubkey) tag")]
    ReportMissingP,

    /// Report events must reference a target event id via `e` tag.
    #[error("report missing `e` (target event id) tag")]
    ReportMissingE,

    /// A mute with `expires` must carry a parseable unix-seconds value.
    #[error("invalid `expires` tag: {0}")]
    InvalidExpires(String),
}

// ── Tag helpers ───────────────────────────────────────────────────────────

/// Return the first value of the single-letter tag `name`, if present.
fn first_tag_value<'a>(event: &'a NostrEvent, name: &str) -> Option<&'a str> {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

/// Return the first value of the tag `name` from an unsigned event.
fn first_tag_value_unsigned<'a>(event: &'a UnsignedEvent, name: &str) -> Option<&'a str> {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

/// Is `s` a lowercase 64-char hex string? Matches Nostr pubkey / event-id shape.
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

// ── Public API: validation ────────────────────────────────────────────────

/// Validate that `event` is a well-formed moderation event of a known kind.
///
/// `admin_set` is the set of hex pubkeys authorised to sign
/// admin-only moderation kinds. Reports (kind 30913) bypass this check
/// because they can be filed by any member.
pub fn validate_moderation_event(
    event: &NostrEvent,
    admin_set: &HashSet<String>,
) -> Result<(), ModerationEventError> {
    if !MOD_KINDS.contains(&event.kind) {
        return Err(ModerationEventError::UnknownKind(event.kind));
    }

    // All moderation kinds are parameterized-replaceable: require a non-empty `d` tag.
    let d = first_tag_value(event, "d").ok_or(ModerationEventError::MissingDTag)?;
    if d.is_empty() {
        return Err(ModerationEventError::EmptyDTag);
    }

    match event.kind {
        KIND_BAN | KIND_MUTE | KIND_UNBAN | KIND_UNMUTE => {
            // d-tag is `{admin_pubkey}:{target_pubkey}` — split and validate both parts.
            let (admin_part, target_part) =
                d.split_once(':').ok_or(ModerationEventError::InvalidDTag {
                    kind: event.kind,
                    reason: "expected `{admin_pubkey}:{target_pubkey}`",
                })?;
            if !is_hex64(admin_part) {
                return Err(ModerationEventError::InvalidDTag {
                    kind: event.kind,
                    reason: "admin portion of d-tag must be 64-char hex pubkey",
                });
            }
            if !is_hex64(target_part) {
                return Err(ModerationEventError::InvalidDTag {
                    kind: event.kind,
                    reason: "target portion of d-tag must be 64-char hex pubkey",
                });
            }
            if event.kind == KIND_MUTE {
                if let Some(exp) = first_tag_value(event, "expires") {
                    exp.parse::<u64>()
                        .map_err(|e| ModerationEventError::InvalidExpires(e.to_string()))?;
                }
            }
        }
        KIND_WARNING => {
            // d-tag is `<pubkey>:<ts>` — split and validate
            let (pk, ts) = d.split_once(':').ok_or(ModerationEventError::InvalidDTag {
                kind: event.kind,
                reason: "expected `<pubkey>:<timestamp>`",
            })?;
            if !is_hex64(pk) {
                return Err(ModerationEventError::InvalidDTag {
                    kind: event.kind,
                    reason: "warning d-tag pubkey must be 64-char hex",
                });
            }
            ts.parse::<u64>()
                .map_err(|_| ModerationEventError::InvalidDTag {
                    kind: event.kind,
                    reason: "warning d-tag timestamp must be unix-seconds u64",
                })?;
        }
        KIND_REPORT => {
            // d-tag is the reported event id
            if !is_hex64(d) {
                return Err(ModerationEventError::InvalidDTag {
                    kind: event.kind,
                    reason: "report d-tag must be 64-char hex event id",
                });
            }
            // Report must also carry p (target pubkey) and e (target event).
            if first_tag_value(event, "p").is_none() {
                return Err(ModerationEventError::ReportMissingP);
            }
            if first_tag_value(event, "e").is_none() {
                return Err(ModerationEventError::ReportMissingE);
            }
        }
        KIND_MODERATION_ACTION => {
            // d-tag is the action uuid — any non-empty string acceptable
        }
        _ => {
            // All MOD_KINDS are handled above; this branch is unreachable
            // but we use a return rather than unreachable!() for safety.
            return Err(ModerationEventError::UnknownKind(event.kind));
        }
    }

    if ADMIN_ONLY_MOD_KINDS.contains(&event.kind) && !admin_set.contains(&event.pubkey) {
        return Err(ModerationEventError::NotAdmin {
            pubkey: event.pubkey.clone(),
        });
    }

    Ok(())
}

/// Read the `expires` tag as a unix-seconds value, if present.
///
/// Returns `Ok(None)` when the tag is absent, `Ok(Some(ts))` when it parses,
/// and `Err(...)` when the tag is present but malformed.
pub fn mute_expires_at(event: &NostrEvent) -> Result<Option<u64>, ModerationEventError> {
    match first_tag_value(event, "expires") {
        None => Ok(None),
        Some(v) => v
            .parse::<u64>()
            .map(Some)
            .map_err(|e| ModerationEventError::InvalidExpires(e.to_string())),
    }
}

// ── Public API: unsigned event builders ───────────────────────────────────

/// Build an unsigned Ban event. Caller must sign with an admin key.
///
/// The `d` tag is `{admin_pubkey}:{target_pubkey}` so that two different
/// admins banning the same user produce independent replaceable events that
/// don't overwrite each other.
pub fn build_ban(
    admin_pubkey: &str,
    target_pubkey: &str,
    reason: &str,
    created_at: u64,
) -> UnsignedEvent {
    let d_tag = format!("{admin_pubkey}:{target_pubkey}");
    UnsignedEvent {
        pubkey: admin_pubkey.to_string(),
        created_at,
        kind: KIND_BAN,
        tags: vec![
            vec!["d".to_string(), d_tag],
            vec!["p".to_string(), target_pubkey.to_string()],
        ],
        content: reason.to_string(),
    }
}

/// Build an unsigned Unban event. Caller must sign with the same admin key
/// that issued the original ban (same `{admin}:{target}` d-tag pair).
pub fn build_unban(
    admin_pubkey: &str,
    target_pubkey: &str,
    reason: &str,
    created_at: u64,
) -> UnsignedEvent {
    let d_tag = format!("{admin_pubkey}:{target_pubkey}");
    UnsignedEvent {
        pubkey: admin_pubkey.to_string(),
        created_at,
        kind: KIND_UNBAN,
        tags: vec![
            vec!["d".to_string(), d_tag],
            vec!["p".to_string(), target_pubkey.to_string()],
        ],
        content: reason.to_string(),
    }
}

/// Build an unsigned Mute event. `expires_at` is unix-seconds; pass 0 for
/// an indefinite mute (the `expires` tag is then omitted).
///
/// The `d` tag is `{admin_pubkey}:{target_pubkey}` (same scheme as ban).
pub fn build_mute(
    admin_pubkey: &str,
    target_pubkey: &str,
    expires_at: u64,
    reason: &str,
    created_at: u64,
) -> UnsignedEvent {
    let d_tag = format!("{admin_pubkey}:{target_pubkey}");
    let mut tags = vec![
        vec!["d".to_string(), d_tag],
        vec!["p".to_string(), target_pubkey.to_string()],
    ];
    if expires_at > 0 {
        tags.push(vec!["expires".to_string(), expires_at.to_string()]);
    }
    UnsignedEvent {
        pubkey: admin_pubkey.to_string(),
        created_at,
        kind: KIND_MUTE,
        tags,
        content: reason.to_string(),
    }
}

/// Build an unsigned Unmute event. Same `{admin}:{target}` d-tag as the mute.
pub fn build_unmute(
    admin_pubkey: &str,
    target_pubkey: &str,
    reason: &str,
    created_at: u64,
) -> UnsignedEvent {
    let d_tag = format!("{admin_pubkey}:{target_pubkey}");
    UnsignedEvent {
        pubkey: admin_pubkey.to_string(),
        created_at,
        kind: KIND_UNMUTE,
        tags: vec![
            vec!["d".to_string(), d_tag],
            vec!["p".to_string(), target_pubkey.to_string()],
        ],
        content: reason.to_string(),
    }
}

/// Build an unsigned Warning event. The `d` tag is `<pubkey>:<created_at>`
/// so each warning is a distinct replaceable event rather than overwriting
/// the previous one.
pub fn build_warning(
    admin_pubkey: &str,
    target_pubkey: &str,
    reason: &str,
    created_at: u64,
) -> UnsignedEvent {
    let d_tag = format!("{target_pubkey}:{created_at}");
    UnsignedEvent {
        pubkey: admin_pubkey.to_string(),
        created_at,
        kind: KIND_WARNING,
        tags: vec![
            vec!["d".to_string(), d_tag],
            vec!["p".to_string(), target_pubkey.to_string()],
        ],
        content: reason.to_string(),
    }
}

/// Build an unsigned Report event. `reporter_pubkey` is filed by any member,
/// not just admins.
pub fn build_report(
    reporter_pubkey: &str,
    reported_event_id: &str,
    reported_pubkey: &str,
    reason: &str,
    created_at: u64,
) -> UnsignedEvent {
    UnsignedEvent {
        pubkey: reporter_pubkey.to_string(),
        created_at,
        kind: KIND_REPORT,
        tags: vec![
            vec!["d".to_string(), reported_event_id.to_string()],
            vec!["e".to_string(), reported_event_id.to_string()],
            vec!["p".to_string(), reported_pubkey.to_string()],
        ],
        content: reason.to_string(),
    }
}

/// Build an unsigned ModerationAction audit-log event.
pub fn build_moderation_action(
    admin_pubkey: &str,
    action_id: &str,
    action: &str,
    target_pubkey: Option<&str>,
    created_at: u64,
    summary: &str,
) -> UnsignedEvent {
    let mut tags = vec![
        vec!["d".to_string(), action_id.to_string()],
        vec!["action".to_string(), action.to_string()],
    ];
    if let Some(pk) = target_pubkey {
        tags.push(vec!["p".to_string(), pk.to_string()]);
    }
    UnsignedEvent {
        pubkey: admin_pubkey.to_string(),
        created_at,
        kind: KIND_MODERATION_ACTION,
        tags,
        content: summary.to_string(),
    }
}

/// Convenience: inspect an unsigned event's d-tag (e.g. for building logging
/// output before signing).
pub fn d_tag_of(event: &UnsignedEvent) -> Option<&str> {
    first_tag_value_unsigned(event, "d")
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::sign_event_deterministic;
    use k256::schnorr::SigningKey;

    fn admin_key() -> SigningKey {
        SigningKey::from_bytes(&[0x02u8; 32]).unwrap()
    }

    fn admin_pk_hex() -> String {
        hex::encode(admin_key().verifying_key().to_bytes())
    }

    fn admin_set() -> HashSet<String> {
        let mut s = HashSet::new();
        s.insert(admin_pk_hex());
        s
    }

    fn target_pk() -> String {
        "ff".repeat(32)
    }

    fn sign(unsigned: UnsignedEvent) -> NostrEvent {
        sign_event_deterministic(unsigned, &admin_key()).unwrap()
    }

    // ---- basic builder + validate happy paths ----

    #[test]
    fn ban_builds_and_validates() {
        let u = build_ban(&admin_pk_hex(), &target_pk(), "spam", 1_700_000_000);
        let signed = sign(u);
        assert_eq!(signed.kind, KIND_BAN);
        assert!(validate_moderation_event(&signed, &admin_set()).is_ok());
    }

    #[test]
    fn mute_with_expiry_validates() {
        let u = build_mute(
            &admin_pk_hex(),
            &target_pk(),
            1_700_003_600,
            "cool down",
            1_700_000_000,
        );
        let signed = sign(u);
        assert_eq!(mute_expires_at(&signed).unwrap(), Some(1_700_003_600));
        assert!(validate_moderation_event(&signed, &admin_set()).is_ok());
    }

    #[test]
    fn mute_without_expiry_validates() {
        let u = build_mute(&admin_pk_hex(), &target_pk(), 0, "indef", 1_700_000_000);
        let signed = sign(u);
        assert_eq!(mute_expires_at(&signed).unwrap(), None);
        assert!(validate_moderation_event(&signed, &admin_set()).is_ok());
    }

    #[test]
    fn warning_validates() {
        let u = build_warning(&admin_pk_hex(), &target_pk(), "off topic", 1_700_000_000);
        let signed = sign(u);
        assert!(validate_moderation_event(&signed, &admin_set()).is_ok());
    }

    #[test]
    fn report_validates_without_admin_set_membership() {
        // Reports are filed by any user. Build with the admin key for signing
        // convenience, but the validator must not require admin membership.
        let u = build_report(
            &admin_pk_hex(),
            &"aa".repeat(32),
            &target_pk(),
            "spam",
            1_700_000_000,
        );
        let signed = sign(u);
        assert!(validate_moderation_event(&signed, &HashSet::new()).is_ok());
    }

    #[test]
    fn moderation_action_validates() {
        let u = build_moderation_action(
            &admin_pk_hex(),
            "act-123",
            "ban",
            Some(&target_pk()),
            1_700_000_000,
            "banned spammer",
        );
        let signed = sign(u);
        assert!(validate_moderation_event(&signed, &admin_set()).is_ok());
    }

    // ---- error cases ----

    #[test]
    fn non_admin_cannot_ban() {
        let u = build_ban(&admin_pk_hex(), &target_pk(), "spam", 1_700_000_000);
        let signed = sign(u);
        let err = validate_moderation_event(&signed, &HashSet::new()).unwrap_err();
        assert!(matches!(err, ModerationEventError::NotAdmin { .. }));
    }

    #[test]
    fn unknown_kind_rejected() {
        let u = UnsignedEvent {
            pubkey: admin_pk_hex(),
            created_at: 1_700_000_000,
            kind: 1,
            tags: vec![vec!["d".to_string(), "x".to_string()]],
            content: String::new(),
        };
        let signed = sign(u);
        assert_eq!(
            validate_moderation_event(&signed, &admin_set()),
            Err(ModerationEventError::UnknownKind(1)),
        );
    }

    #[test]
    fn missing_d_tag_rejected() {
        let u = UnsignedEvent {
            pubkey: admin_pk_hex(),
            created_at: 1_700_000_000,
            kind: KIND_BAN,
            tags: vec![],
            content: String::new(),
        };
        let signed = sign(u);
        assert_eq!(
            validate_moderation_event(&signed, &admin_set()),
            Err(ModerationEventError::MissingDTag),
        );
    }

    #[test]
    fn ban_d_tag_must_be_admin_colon_target_hex64() {
        // Missing colon entirely — should fail with InvalidDTag
        let u = UnsignedEvent {
            pubkey: admin_pk_hex(),
            created_at: 1_700_000_000,
            kind: KIND_BAN,
            tags: vec![vec!["d".to_string(), "not-hex-no-colon".to_string()]],
            content: String::new(),
        };
        let signed = sign(u);
        let err = validate_moderation_event(&signed, &admin_set()).unwrap_err();
        assert!(matches!(
            err,
            ModerationEventError::InvalidDTag { kind: KIND_BAN, .. }
        ));

        // Colon present but invalid hex in admin part
        let u2 = UnsignedEvent {
            pubkey: admin_pk_hex(),
            created_at: 1_700_000_000,
            kind: KIND_BAN,
            tags: vec![vec!["d".to_string(), format!("not-hex:{}", target_pk())]],
            content: String::new(),
        };
        let signed2 = sign(u2);
        let err2 = validate_moderation_event(&signed2, &admin_set()).unwrap_err();
        assert!(matches!(
            err2,
            ModerationEventError::InvalidDTag { kind: KIND_BAN, .. }
        ));
    }

    #[test]
    fn mute_with_garbage_expires_rejected() {
        let mut u = build_mute(&admin_pk_hex(), &target_pk(), 0, "r", 1_700_000_000);
        u.tags
            .push(vec!["expires".to_string(), "tomorrow".to_string()]);
        let signed = sign(u);
        assert!(matches!(
            validate_moderation_event(&signed, &admin_set()),
            Err(ModerationEventError::InvalidExpires(_)),
        ));
    }

    #[test]
    fn report_without_p_tag_rejected() {
        let u = UnsignedEvent {
            pubkey: admin_pk_hex(),
            created_at: 1_700_000_000,
            kind: KIND_REPORT,
            tags: vec![
                vec!["d".to_string(), "aa".repeat(32)],
                vec!["e".to_string(), "aa".repeat(32)],
            ],
            content: "spam".to_string(),
        };
        let signed = sign(u);
        assert_eq!(
            validate_moderation_event(&signed, &HashSet::new()),
            Err(ModerationEventError::ReportMissingP),
        );
    }

    #[test]
    fn warning_d_tag_requires_colon_format() {
        let u = UnsignedEvent {
            pubkey: admin_pk_hex(),
            created_at: 1_700_000_000,
            kind: KIND_WARNING,
            tags: vec![vec!["d".to_string(), target_pk()]],
            content: "r".to_string(),
        };
        let signed = sign(u);
        assert!(matches!(
            validate_moderation_event(&signed, &admin_set()),
            Err(ModerationEventError::InvalidDTag {
                kind: KIND_WARNING,
                ..
            }),
        ));
    }

    #[test]
    fn d_tag_of_works() {
        let u = build_ban(&admin_pk_hex(), &target_pk(), "x", 1);
        let expected = format!("{}:{}", admin_pk_hex(), target_pk());
        assert_eq!(d_tag_of(&u), Some(expected.as_str()));
    }

    #[test]
    fn unban_builds_and_validates() {
        let u = build_unban(&admin_pk_hex(), &target_pk(), "pardoned", 1_700_000_000);
        let signed = sign(u);
        assert_eq!(signed.kind, KIND_UNBAN);
        assert!(validate_moderation_event(&signed, &admin_set()).is_ok());
    }

    #[test]
    fn unmute_builds_and_validates() {
        let u = build_unmute(
            &admin_pk_hex(),
            &target_pk(),
            "cooldown over",
            1_700_000_000,
        );
        let signed = sign(u);
        assert_eq!(signed.kind, KIND_UNMUTE);
        assert!(validate_moderation_event(&signed, &admin_set()).is_ok());
    }
}
