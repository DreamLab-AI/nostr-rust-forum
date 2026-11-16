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
//! A **kind-1014 NIP-171 epoch ticket** (ADR-2028 decision 2) is accepted
//! beside the 21453 grant. A ticket is a regular signed event inside the
//! rumor slot, so it keeps its `sig`; it is accepted only when its signer is
//! the group pubkey supplied for a zone with `--group-pubkey <zone>=<hex>`
//! (the CLI has no NIP-11 cache) and its `p` tag is the opening key's owner.
//! A relay admin check does not apply: the group identity is not an admin.
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

/// NIP-171 epoch ticket (signed `kind:1014`).
pub const KIND_EPOCH_TICKET: u64 = 1014;

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
    /// A ticket's signer is not bound to exactly one zone by `--group-pubkey`.
    #[error("ticket signer {0} is not bound to exactly one zone (--group-pubkey)")]
    NoGroupBinding(String),
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
    let (sealer, mut rumor_json) = open_gift_wrap_raw(gift, recipient)?;
    let rumor: Result<UnsignedEvent, _> = serde_json::from_str(&rumor_json);
    rumor_json.zeroize();
    let rumor = rumor.map_err(|_| GrantError::Unwrap("rumor is not an event".to_string()))?;
    if rumor.pubkey != sealer {
        return Err(GrantError::Unwrap(
            "rumor author does not match seal author".to_string(),
        ));
    }
    Ok((sealer, rumor))
}

/// The wrap and seal checks of [`open_gift_wrap`], returning the verified
/// seal author and the decrypted rumor JSON unparsed (a 1014 ticket needs its
/// `sig`, which `UnsignedEvent` drops). The caller zeroizes the string.
fn open_gift_wrap_raw(
    gift: &NostrEvent,
    recipient: &SecretKey,
) -> Result<(String, String), GrantError> {
    let unwrap = |why: &str| GrantError::Unwrap(why.to_string());
    if gift.kind != KIND_GIFT_WRAP {
        return Err(GrantError::Unwrap(format!(
            "not a gift wrap (kind {})",
            gift.kind
        )));
    }
    verify_event_strict(gift).map_err(|_| unwrap("wrap id or signature does not verify"))?;
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
    let rumor_json = nostr_bbs_core::nip44::decrypt(recipient.as_bytes(), &seal_pk, &seal.content)
        .map_err(|_| unwrap("seal does not decrypt with this key"))?;
    Ok((seal.pubkey, rumor_json))
}

/// A zone and the group identity pubkey the relay binds to it
/// (`--group-pubkey <zone>=<hex>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupBinding {
    /// Zone id.
    pub zone: String,
    /// Group identity pubkey, 64 lowercase hex.
    pub group: String,
}

impl std::str::FromStr for GroupBinding {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let (zone, group) = s
            .split_once('=')
            .ok_or_else(|| "expected <zone>=<64-hex group pubkey>".to_string())?;
        let group = group.to_ascii_lowercase();
        if zone.is_empty() || !is_hex64(&group) {
            return Err("expected <zone>=<64-hex group pubkey>".to_string());
        }
        Ok(Self {
            zone: zone.to_string(),
            group,
        })
    }
}

/// Validate a signed kind-1014 ticket found in a rumor slot.
///
/// `rumor_json` is the decrypted rumor, `sealer` the verified seal author,
/// `me` the member pubkeys a ticket may name (the identity, as in the forum
/// client; never the inbox key) and `groups` the supplied bindings. Rules,
/// all MUSTs of NIP-171: signed event with a verifying id and signature;
/// author equals the seal's author; exactly one `p` and one `epoch` tag
/// (plain decimal); content 64 lowercase hex and a valid scalar; the signer
/// is bound to exactly one supplied zone; the epoch is at least 1.
pub fn validate_ticket(
    rumor_json: &str,
    sealer: &str,
    me: &[String],
    groups: &[GroupBinding],
) -> Result<ZoneKey, GrantError> {
    let ev: NostrEvent = serde_json::from_str(rumor_json).map_err(|_| GrantError::Malformed)?;
    if ev.kind != KIND_EPOCH_TICKET {
        return Err(GrantError::WrongKind(ev.kind));
    }
    verify_event_strict(&ev).map_err(|_| GrantError::Malformed)?;
    if ev.pubkey != sealer {
        return Err(GrantError::Unwrap(
            "ticket author does not match seal author".to_string(),
        ));
    }
    let one = |name: &str| -> Option<String> {
        let mut it = ev
            .tags
            .iter()
            .filter(|t| t.first().is_some_and(|n| n == name));
        match (it.next(), it.next()) {
            (Some(t), None) if t.len() == 2 => Some(t[1].clone()),
            _ => None,
        }
    };
    let member = one("p").ok_or(GrantError::Malformed)?;
    let epoch = one("epoch").ok_or(GrantError::Malformed)?;
    let lower_hex64 = |s: &str| is_hex64(s) && !s.bytes().any(|b| b.is_ascii_uppercase());
    if !lower_hex64(&member) || !lower_hex64(&ev.content) {
        return Err(GrantError::Malformed);
    }
    if epoch.is_empty()
        || !epoch.bytes().all(|b| b.is_ascii_digit())
        || (epoch.len() > 1 && epoch.starts_with('0'))
    {
        return Err(GrantError::Malformed);
    }
    let epoch: u32 = epoch.parse().map_err(|_| GrantError::Malformed)?;
    if epoch == 0 || !me.contains(&member) {
        return Err(GrantError::Malformed);
    }
    let mut bound = groups.iter().filter(|g| g.group == ev.pubkey);
    let zone = match (bound.next(), bound.next()) {
        (Some(g), None) => g.zone.clone(),
        _ => return Err(GrantError::NoGroupBinding(ev.pubkey.clone())),
    };
    let secret = hex32(&ev.content).ok_or(GrantError::Malformed)?;
    let pubkey = nostr_bbs_core::keys::pubkey_hex(&secret).map_err(|_| GrantError::Malformed)?;
    ZoneKey::new(
        &zone,
        epoch,
        &ev.content,
        &pubkey,
        KeySource::Grant {
            granted_by: ev.pubkey.clone(),
        },
    )
    .map_err(|_| GrantError::Malformed)
}

/// Open a gift wrap with the first of `keys` that decrypts it. Callers pass
/// the inbox secret first and the identity secret second; the error from the
/// last key is returned when none opens the wrap.
pub fn open_gift_wrap_with(
    gift: &NostrEvent,
    keys: &[&SecretKey],
) -> Result<(String, UnsignedEvent), GrantError> {
    let mut last = GrantError::Unwrap("no key supplied".to_string());
    for key in keys {
        match open_gift_wrap(gift, key) {
            Ok(opened) => return Ok(opened),
            Err(e) => last = e,
        }
    }
    Err(last)
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

/// [`fetch_grants_with`] with no group bindings: kind-1014 tickets are then
/// all refused, as before they existed.
pub async fn fetch_grants<R: Relay>(
    relay: &mut R,
    me: &SecretKey,
    inbox: Option<&SecretKey>,
) -> Result<GrantHarvest, RelayError> {
    fetch_grants_with(relay, me, inbox, &[]).await
}

/// Fetch every kind-1059 wrap addressed to `me` (and to `inbox`, when the
/// admin has a registered inbox key) and keep the valid zone-key grants and
/// NIP-171 epoch tickets. The inbox secret is tried first, then the identity.
/// Each distinct sealer's admin status is asked once (grants only; a ticket's
/// sealer is a group identity checked against `groups`).
pub async fn fetch_grants_with<R: Relay>(
    relay: &mut R,
    me: &SecretKey,
    inbox: Option<&SecretKey>,
    groups: &[GroupBinding],
) -> Result<GrantHarvest, RelayError> {
    let mut p_tags = Vec::new();
    let mut openers: Vec<&SecretKey> = Vec::new();
    let mut owned: Vec<String> = Vec::new();
    if let Some(inbox) = inbox {
        p_tags.push(inbox.public_key().to_hex());
        openers.push(inbox);
    }
    p_tags.push(me.public_key().to_hex());
    openers.push(me);
    owned.push(me.public_key().to_hex());
    let filter = Filter {
        kinds: Some(vec![KIND_GIFT_WRAP]),
        p_tags: Some(p_tags),
        ..Filter::default()
    };
    let wraps = fetch_all(relay, &filter).await?.events;
    let mut harvest = GrantHarvest::default();
    let mut admin_cache: HashMap<String, bool> = HashMap::new();
    for wrap in &wraps {
        let Some((sealer, mut rumor_json)) = openers
            .iter()
            .find_map(|k| open_gift_wrap_raw(wrap, k).ok())
        else {
            harvest.ignored += 1;
            continue;
        };
        // The rumor carries the zone secret in hex either way.
        let kind = serde_json::from_str::<serde_json::Value>(&rumor_json)
            .ok()
            .and_then(|v| v["kind"].as_u64());
        let verdict = match kind {
            Some(KIND_EPOCH_TICKET) => validate_ticket(&rumor_json, &sealer, &owned, groups),
            Some(KIND_ZONE_KEY_GRANT) => {
                let rumor: Result<UnsignedEvent, _> = serde_json::from_str(&rumor_json);
                match rumor {
                    Ok(r) if r.pubkey == sealer => {
                        let is_admin = match admin_cache.get(&sealer) {
                            Some(v) => *v,
                            None => {
                                let v = relay.is_admin(&sealer).await?;
                                admin_cache.insert(sealer.clone(), v);
                                v
                            }
                        };
                        let out = validate_grant(&r, &sealer, is_admin);
                        let mut r = r;
                        r.content.zeroize();
                        out
                    }
                    _ => Err(GrantError::Unwrap(
                        "rumor author does not match seal author".to_string(),
                    )),
                }
            }
            _ => {
                rumor_json.zeroize();
                harvest.ignored += 1;
                continue;
            }
        };
        rumor_json.zeroize();
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
    fn tampered_wrap_is_refused_before_any_decryption() {
        let me = SecretKey::from_bytes([0x22; 32]).unwrap();
        let me_pk = nostr_bbs_core::keys::pubkey_hex(me.as_bytes()).unwrap();
        let sender = [0x44u8; 32];
        let sender_pk = nostr_bbs_core::keys::pubkey_hex(&sender).unwrap();
        let mut wrap = nostr_bbs_core::gift_wrap::gift_wrap_kind(
            &sender,
            &sender_pk,
            &me_pk,
            KIND_ZONE_KEY_GRANT,
            "{}",
        )
        .unwrap();
        assert!(open_gift_wrap(&wrap, &me).is_ok());
        wrap.sig = "00".repeat(64);
        match open_gift_wrap(&wrap, &me).unwrap_err() {
            GrantError::Unwrap(why) => assert!(why.contains("wrap id or signature"), "{why}"),
            other => panic!("expected Unwrap, got {other:?}"),
        }
    }

    #[test]
    fn inbox_key_is_tried_before_identity_and_either_opens() {
        let identity = SecretKey::from_bytes([0x22; 32]).unwrap();
        let inbox = SecretKey::from_bytes([0x23; 32]).unwrap();
        let sender = [0x44u8; 32];
        let sender_pk = nostr_bbs_core::keys::pubkey_hex(&sender).unwrap();
        let wrap_to = |sk: &SecretKey| {
            let pk = nostr_bbs_core::keys::pubkey_hex(sk.as_bytes()).unwrap();
            nostr_bbs_core::gift_wrap::gift_wrap_kind(
                &sender,
                &sender_pk,
                &pk,
                KIND_ZONE_KEY_GRANT,
                "{}",
            )
            .unwrap()
        };
        let keys = [&inbox, &identity];
        let (sealer, rumor) = open_gift_wrap_with(&wrap_to(&inbox), &keys).unwrap();
        assert_eq!(
            (sealer.as_str(), rumor.kind),
            (&*sender_pk, KIND_ZONE_KEY_GRANT)
        );
        assert!(open_gift_wrap_with(&wrap_to(&identity), &keys).is_ok());
        // Without the inbox key, a wrap to the inbox cannot be opened.
        assert!(matches!(
            open_gift_wrap_with(&wrap_to(&inbox), &[&identity]).unwrap_err(),
            GrantError::Unwrap(_)
        ));
        assert!(open_gift_wrap_with(&wrap_to(&inbox), &[]).is_err());
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
