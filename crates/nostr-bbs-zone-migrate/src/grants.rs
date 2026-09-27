//! Zone-key grants addressed to the migrator (`--fetch-grants`).
//!
//! An admin grants a zone key as a NIP-59 gift wrap (kind 1059, `#p` = the
//! recipient) around a seal (kind 13) around a rumor of kind
//! [`KIND_ZONE_KEY_GRANT`] whose content is
//! `{"zone","epoch","secret","pubkey","created_at"}`. These rules mirror the
//! forum client (`nostr-bbs-forum-client/src/zone_crypto/mod.rs`
//! `unwrap_any` and `validate_grant`) exactly:
//!
//! 1. the wrap is kind 1059 and decrypts with the migrator's key;
//! 2. the seal is kind 13 and its id and signature verify;
//! 3. the rumor's author equals the seal's author;
//! 4. the rumor is kind 21453 with well-formed content (zone non-empty,
//!    epoch ≥ 1, 64-hex secret and pubkey);
//! 5. the secret derives to the stated pubkey;
//! 6. the seal's author is a relay admin (`GET /api/check-whitelist`).
//!
//! Decryption uses core `nip44` and verification core
//! `verify_event_strict`; nothing here is hand-rolled. Core's `unwrap_gift`
//! is not used because it admits only kind-14 DM rumors.

use std::collections::HashMap;

use nostr_bbs_core::keys::SecretKey;
use nostr_bbs_core::{verify_event_strict, NostrEvent, UnsignedEvent};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use crate::keys::{is_hex64, KeyError, KeySource, ZoneKey};
use crate::relay::{fetch_all, Filter, Relay, RelayError};

/// NIP-59 rumor kind carrying a zone-key grant (forum client
/// `zone_crypto::KIND_ZONE_KEY_GRANT`).
pub const KIND_ZONE_KEY_GRANT: u64 = 21453;

const KIND_GIFT_WRAP: u64 = 1059;
const KIND_SEAL: u64 = 13;

/// Why a gift wrap did not yield a zone key.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GrantError {
    /// The wrap, seal or rumor could not be decrypted or parsed, or the seal
    /// did not verify, or the rumor's author is not the seal's author.
    #[error("not an openable gift wrap: {0}")]
    Unwrap(String),
    /// The rumor is not a zone-key grant (for example an ordinary DM).
    #[error("not a zone-key grant (rumor kind {0})")]
    WrongKind(u64),
    /// The grant content is not well formed.
    #[error("grant content is malformed")]
    Malformed,
    /// The grant's secret does not derive to its stated pubkey.
    #[error("grant secret does not derive to its stated pubkey")]
    SecretMismatch,
    /// The grant was sealed by a pubkey that is not a relay admin.
    #[error("grant was not sealed by an admin ({0})")]
    NotAdmin(String),
}

#[derive(Deserialize)]
struct GrantPayload {
    zone: String,
    epoch: u32,
    secret: String,
    pubkey: String,
    #[allow(dead_code)]
    created_at: u64,
}

impl Drop for GrantPayload {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Open a kind-1059 gift wrap addressed to `recipient` and return the
/// verified seal author and the rumor, whatever the rumor's kind.
pub fn open_gift_wrap(
    gift: &NostrEvent,
    recipient: &SecretKey,
) -> Result<(String, UnsignedEvent), GrantError> {
    let unwrap = |why: &str| GrantError::Unwrap(why.to_string());
    if gift.kind != KIND_GIFT_WRAP {
        return Err(GrantError::Unwrap(format!(
            "not a gift wrap (kind {})",
            gift.kind
        )));
    }
    let wrap_pk = hex32(&gift.pubkey).ok_or_else(|| unwrap("wrap pubkey is not 64 hex"))?;
    let seal_json = nostr_bbs_core::nip44::decrypt(recipient.as_bytes(), &wrap_pk, &gift.content)
        .map_err(|_| unwrap("wrap does not decrypt with this key"))?;
    let seal: NostrEvent =
        serde_json::from_str(&seal_json).map_err(|_| unwrap("seal is not an event"))?;
    if seal.kind != KIND_SEAL {
        return Err(GrantError::Unwrap(format!(
            "not a seal (kind {})",
            seal.kind
        )));
    }
    verify_event_strict(&seal).map_err(|_| unwrap("seal id or signature does not verify"))?;
    let seal_pk = hex32(&seal.pubkey).ok_or_else(|| unwrap("seal pubkey is not 64 hex"))?;
    let mut rumor_json =
        nostr_bbs_core::nip44::decrypt(recipient.as_bytes(), &seal_pk, &seal.content)
            .map_err(|_| unwrap("seal does not decrypt with this key"))?;
    let rumor: Result<UnsignedEvent, _> = serde_json::from_str(&rumor_json);
    rumor_json.zeroize();
    let rumor = rumor.map_err(|_| unwrap("rumor is not an event"))?;
    if rumor.pubkey != seal.pubkey {
        return Err(unwrap("rumor author does not match seal author"));
    }
    Ok((seal.pubkey, rumor))
}

/// Validate a decrypted grant rumor sealed by `sealer`.
///
/// `is_admin` is injected so the rule is testable; the migrator passes the
/// relay's `check-whitelist` answer for `sealer`.
pub fn validate_grant(
    rumor: &UnsignedEvent,
    sealer: &str,
    is_admin: bool,
) -> Result<ZoneKey, GrantError> {
    if rumor.kind != KIND_ZONE_KEY_GRANT {
        return Err(GrantError::WrongKind(rumor.kind));
    }
    let payload: GrantPayload =
        serde_json::from_str(&rumor.content).map_err(|_| GrantError::Malformed)?;
    if payload.zone.is_empty()
        || payload.epoch == 0
        || !is_hex64(&payload.pubkey)
        || !is_hex64(&payload.secret)
    {
        return Err(GrantError::Malformed);
    }
    let key = ZoneKey::new(
        &payload.zone,
        payload.epoch,
        &payload.secret,
        &payload.pubkey,
        KeySource::Grant {
            granted_by: sealer.to_ascii_lowercase(),
        },
    )
    .map_err(|e| match e {
        KeyError::SecretMismatch { .. } => GrantError::SecretMismatch,
        _ => GrantError::Malformed,
    })?;
    if !is_admin {
        return Err(GrantError::NotAdmin(sealer.to_string()));
    }
    Ok(key)
}

/// A gift wrap that carried a zone-key grant which was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RejectedGrant {
    /// Id of the kind-1059 wrap.
    pub wrap_id: String,
    /// Why it was refused.
    pub reason: String,
}

/// Outcome of [`fetch_grants`].
#[derive(Debug, Default)]
pub struct GrantHarvest {
    /// Accepted keys (not yet merged into a ring).
    pub keys: Vec<ZoneKey>,
    /// Grants that were refused, with reasons.
    pub rejected: Vec<RejectedGrant>,
    /// Wraps that were not zone-key grants (DMs) or could not be opened.
    pub ignored: usize,
}

/// Fetch every kind-1059 wrap addressed to `me` and keep the valid zone-key
/// grants. Each distinct sealer's admin status is asked once.
pub async fn fetch_grants<R: Relay>(
    relay: &mut R,
    me: &SecretKey,
) -> Result<GrantHarvest, RelayError> {
    let filter = Filter {
        kinds: Some(vec![KIND_GIFT_WRAP]),
        p_tags: Some(vec![me.public_key().to_hex()]),
        ..Filter::default()
    };
    let wraps = fetch_all(relay, &filter).await?.events;
    let mut harvest = GrantHarvest::default();
    let mut admin_cache: HashMap<String, bool> = HashMap::new();
    for wrap in &wraps {
        let Ok((sealer, mut rumor)) = open_gift_wrap(wrap, me) else {
            harvest.ignored += 1;
            continue;
        };
        if rumor.kind != KIND_ZONE_KEY_GRANT {
            rumor.content.zeroize();
            harvest.ignored += 1;
            continue;
        }
        let is_admin = match admin_cache.get(&sealer) {
            Some(v) => *v,
            None => {
                let v = relay.is_admin(&sealer).await?;
                admin_cache.insert(sealer.clone(), v);
                v
            }
        };
        let verdict = validate_grant(&rumor, &sealer, is_admin);
        // The rumor content carries the zone secret in hex.
        rumor.content.zeroize();
        match verdict {
            Ok(key) => harvest.keys.push(key),
            Err(e) => harvest.rejected.push(RejectedGrant {
                wrap_id: wrap.id.clone(),
                reason: e.to_string(),
            }),
        }
    }
    Ok(harvest)
}

fn hex32(s: &str) -> Option<[u8; 32]> {
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

    fn rumor(kind: u64, content: String) -> UnsignedEvent {
        UnsignedEvent {
            pubkey: "a".repeat(64),
            created_at: 1,
            kind,
            tags: vec![],
            content,
        }
    }

    fn payload(secret: &[u8; 32], pubkey: &str) -> String {
        format!(
            r#"{{"zone":"zone3","epoch":2,"secret":"{}","pubkey":"{pubkey}","created_at":1}}"#,
            hex::encode(secret)
        )
    }

    #[test]
    fn valid_grant_from_admin_is_accepted() {
        let pk = nostr_bbs_core::keys::pubkey_hex(&[0x33; 32]).unwrap();
        let key = validate_grant(
            &rumor(KIND_ZONE_KEY_GRANT, payload(&[0x33; 32], &pk)),
            &"A".repeat(64),
            true,
        )
        .unwrap();
        assert_eq!((key.zone(), key.epoch(), key.pubkey()), ("zone3", 2, &*pk));
        assert_eq!(
            key.source(),
            &KeySource::Grant {
                granted_by: "a".repeat(64)
            }
        );
    }

    #[test]
    fn grant_rules_reject_each_violation() {
        let pk = nostr_bbs_core::keys::pubkey_hex(&[0x33; 32]).unwrap();
        let other = nostr_bbs_core::keys::pubkey_hex(&[0x34; 32]).unwrap();
        let sealer = "b".repeat(64);
        assert_eq!(
            validate_grant(&rumor(14, payload(&[0x33; 32], &pk)), &sealer, true).unwrap_err(),
            GrantError::WrongKind(14)
        );
        assert_eq!(
            validate_grant(&rumor(KIND_ZONE_KEY_GRANT, "{}".into()), &sealer, true).unwrap_err(),
            GrantError::Malformed
        );
        assert_eq!(
            validate_grant(
                &rumor(
                    KIND_ZONE_KEY_GRANT,
                    payload(&[0x33; 32], &pk).replace("\"epoch\":2", "\"epoch\":0")
                ),
                &sealer,
                true
            )
            .unwrap_err(),
            GrantError::Malformed
        );
        assert_eq!(
            validate_grant(
                &rumor(KIND_ZONE_KEY_GRANT, payload(&[0x33; 32], &other)),
                &sealer,
                true
            )
            .unwrap_err(),
            GrantError::SecretMismatch
        );
        assert_eq!(
            validate_grant(
                &rumor(KIND_ZONE_KEY_GRANT, payload(&[0x33; 32], &pk)),
                &sealer,
                false
            )
            .unwrap_err(),
            GrantError::NotAdmin(sealer.clone())
        );
    }

    #[test]
    fn non_wrap_is_refused_before_any_decryption() {
        let me = SecretKey::from_bytes([0x22; 32]).unwrap();
        let ev = NostrEvent {
            id: String::new(),
            pubkey: "a".repeat(64),
            created_at: 0,
            kind: 4,
            tags: vec![],
            content: String::new(),
            sig: String::new(),
        };
        assert!(matches!(
            open_gift_wrap(&ev, &me).unwrap_err(),
            GrantError::Unwrap(_)
        ));
    }
}
