//! NIP-26: Delegated Event Signing.
//!
//! Allows a delegator to grant a delegatee the authority to sign events on
//! their behalf, subject to optional conditions (event kind restriction and/or
//! created_at time window).
//!
//! Reference: <https://github.com/nostr-protocol/nostr/blob/master/nips/26.md>
//!
//! Wire format:
//!   delegation_tag = ["delegation", <delegator_pubkey_hex>, <conditions_str>, <sig_hex>]
//! where sig = Schnorr(delegator_sk, SHA-256("nostr:delegation:" || delegatee_pk || ":" || conditions_str))

use k256::schnorr::SigningKey;
use sha2::{Digest, Sha256};
use thiserror::Error;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum Nip26Error {
    #[error("invalid delegator secret key")]
    InvalidDelegatorKey,
    #[error("invalid pubkey hex: {0}")]
    InvalidPubkey(String),
    #[error("invalid condition: {0}")]
    InvalidCondition(String),
    #[error("invalid delegation signature")]
    InvalidSignature,
    #[error("malformed delegation tag")]
    MalformedTag,
    #[error("wrong delegation tag name")]
    WrongTagName,
    #[error("delegation conditions not satisfied: {0}")]
    ConditionsNotSatisfied(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("hex decode error: {0}")]
    HexError(String),
}

// ── Conditions ────────────────────────────────────────────────────────────────

/// Parsed delegation conditions.
///
/// Boundary semantics per NIP-26 spec:
/// - `created_at>T` means `created_at` must be strictly greater than T
/// - `created_at<T` means `created_at` must be strictly less than T
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Conditions {
    /// Permitted event kinds. Empty = any kind allowed.
    pub kinds: Vec<u64>,
    /// If `Some(ts)`, event `created_at` must be strictly greater than `ts`.
    pub created_after: Option<u64>,
    /// If `Some(ts)`, event `created_at` must be strictly less than `ts`.
    pub created_before: Option<u64>,
}

impl Conditions {
    /// Parse a conditions string such as `"kind=1&created_at>1700000000"`.
    ///
    /// Inherent method retained for direct call ergonomics; also exposed via
    /// `std::str::FromStr` for `.parse()` callers.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, Nip26Error> {
        let mut c = Conditions::default();
        if s.is_empty() {
            return Ok(c);
        }
        for part in s.split('&') {
            if part.is_empty() {
                continue;
            }
            if let Some(kind_str) = part.strip_prefix("kind=") {
                let k: u64 = kind_str.parse().map_err(|_| {
                    Nip26Error::InvalidCondition(format!("invalid kind: {kind_str}"))
                })?;
                c.kinds.push(k);
            } else if let Some(ts_str) = part.strip_prefix("created_at>") {
                let t: u64 = ts_str.parse().map_err(|_| {
                    Nip26Error::InvalidCondition(format!("invalid timestamp: {ts_str}"))
                })?;
                c.created_after = Some(t);
            } else if let Some(ts_str) = part.strip_prefix("created_at<") {
                let t: u64 = ts_str.parse().map_err(|_| {
                    Nip26Error::InvalidCondition(format!("invalid timestamp: {ts_str}"))
                })?;
                c.created_before = Some(t);
            } else {
                return Err(Nip26Error::InvalidCondition(format!(
                    "unknown condition: {part}"
                )));
            }
        }
        Ok(c)
    }

    /// Serialize to the canonical wire format.
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        let mut parts = Vec::new();
        for k in &self.kinds {
            parts.push(format!("kind={k}"));
        }
        if let Some(ts) = self.created_after {
            parts.push(format!("created_at>{ts}"));
        }
        if let Some(ts) = self.created_before {
            parts.push(format!("created_at<{ts}"));
        }
        parts.join("&")
    }

    /// Return `true` if the given kind and timestamp satisfy all conditions.
    pub fn permits(&self, kind: u64, created_at: u64) -> bool {
        if !self.kinds.is_empty() && !self.kinds.contains(&kind) {
            return false;
        }
        if let Some(after) = self.created_after {
            if !(after + 1..).contains(&created_at) {
                return false;
            }
        }
        if let Some(before) = self.created_before {
            if !(..before).contains(&created_at) {
                return false;
            }
        }
        true
    }
}

// ── DelegationToken ───────────────────────────────────────────────────────────

/// A signed NIP-26 delegation token.
pub struct DelegationToken {
    /// x-only pubkey hex of the delegator.
    pub delegator_pubkey: String,
    /// x-only pubkey hex of the delegatee.
    pub delegatee_pubkey: String,
    /// Raw conditions string (as signed).
    pub conditions_str: String,
    /// Parsed conditions.
    pub conditions: Conditions,
    /// 64-byte Schnorr signature (128 hex chars).
    pub sig: String,
}

impl DelegationToken {
    /// Create and sign a delegation token.
    pub fn create(
        delegator_sk: &[u8; 32],
        delegatee_pubkey: &str,
        conditions: &Conditions,
    ) -> Result<Self, Nip26Error> {
        let signing_key =
            SigningKey::from_bytes(delegator_sk).map_err(|_| Nip26Error::InvalidDelegatorKey)?;
        let delegator_pubkey = hex::encode(signing_key.verifying_key().to_bytes());

        let conditions_str = conditions.to_string();
        let hash = delegation_token_hash(delegatee_pubkey, &conditions_str);

        let mut aux = [0u8; 32];
        let _ = getrandom::getrandom(&mut aux);
        let signature = signing_key
            .sign_raw(&hash, &aux)
            .map_err(|e| Nip26Error::SigningFailed(e.to_string()))?;

        Ok(DelegationToken {
            delegator_pubkey,
            delegatee_pubkey: delegatee_pubkey.to_string(),
            conditions_str,
            conditions: conditions.clone(),
            sig: hex::encode(signature.to_bytes()),
        })
    }

    /// Verify the Schnorr signature.
    pub fn verify(&self) -> Result<(), Nip26Error> {
        let pk_bytes = decode_hex32(&self.delegator_pubkey)?;
        let verifying_key = k256::schnorr::VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| Nip26Error::InvalidPubkey(e.to_string()))?;

        let hash = delegation_token_hash(&self.delegatee_pubkey, &self.conditions_str);

        let sig_bytes = hex::decode(&self.sig).map_err(|e| Nip26Error::HexError(e.to_string()))?;
        let sig = k256::schnorr::Signature::try_from(sig_bytes.as_slice())
            .map_err(|_| Nip26Error::InvalidSignature)?;

        verifying_key
            .verify_raw(&hash, &sig)
            .map_err(|_| Nip26Error::InvalidSignature)
    }

    /// Parse from a [`DelegationTag`].
    ///
    /// If the tag has a 5th element (delegatee pubkey — added by `DelegationTag::from_token`),
    /// it is used to populate `delegatee_pubkey`; otherwise `delegatee_pubkey` is empty and
    /// the caller must fill it before calling `verify()`.
    pub fn from_tag(tag: &DelegationTag) -> Result<Self, Nip26Error> {
        if tag.0.len() < 4 {
            return Err(Nip26Error::MalformedTag);
        }
        if tag.0[0] != "delegation" {
            return Err(Nip26Error::WrongTagName);
        }
        let delegator_pubkey = tag.0[1].clone();
        let conditions_str = tag.0[2].clone();
        let sig = tag.0[3].clone();

        decode_hex32(&delegator_pubkey)?;
        let conditions = Conditions::from_str(&conditions_str)?;

        // Optional 5th element: delegatee pubkey (added by from_token for roundtrip support)
        let delegatee_pubkey = tag.0.get(4).cloned().unwrap_or_default();

        Ok(DelegationToken {
            delegator_pubkey,
            delegatee_pubkey,
            conditions_str,
            conditions,
            sig,
        })
    }
}

// ── DelegationTag ─────────────────────────────────────────────────────────────

/// A NIP-26 delegation tag array: `["delegation", delegator_pk, conditions, sig]`.
pub struct DelegationTag(pub Vec<String>);

impl DelegationTag {
    /// Construct a delegation tag from a [`DelegationToken`].
    ///
    /// Produces `["delegation", delegator_pk, conditions, sig, delegatee_pk]`.
    /// The 5th element (delegatee) is an extension to the standard 4-element NIP-26 wire
    /// format; it enables `DelegationToken::from_tag` → `verify()` roundtrips without
    /// needing out-of-band context. Standard clients ignore extra tag elements.
    pub fn from_token(token: &DelegationToken) -> Self {
        DelegationTag(vec![
            "delegation".to_string(),
            token.delegator_pubkey.clone(),
            token.conditions_str.clone(),
            token.sig.clone(),
            token.delegatee_pubkey.clone(),
        ])
    }
}

// ── validate_delegation_tag ───────────────────────────────────────────────────

/// Validate a delegation tag for a specific event context.
///
/// # Arguments
/// * `tag` - The delegation tag from the event
/// * `author_pubkey` - The event signer's pubkey (= delegatee)
/// * `kind` - The event kind
/// * `created_at` - The event timestamp
pub fn validate_delegation_tag(
    tag: &DelegationTag,
    author_pubkey: &str,
    kind: u64,
    created_at: u64,
) -> Result<(), Nip26Error> {
    let mut token = DelegationToken::from_tag(tag)?;
    token.delegatee_pubkey = author_pubkey.to_string();

    token.verify()?;

    if !token.conditions.permits(kind, created_at) {
        return Err(Nip26Error::ConditionsNotSatisfied(format!(
            "kind={kind} created_at={created_at} not permitted by '{}'",
            token.conditions_str
        )));
    }

    Ok(())
}

// ── Internal helpers ───────────────────────────────────────────────────────────

fn delegation_token_hash(delegatee_pubkey: &str, conditions_str: &str) -> [u8; 32] {
    let message = format!("nostr:delegation:{delegatee_pubkey}:{conditions_str}");
    Sha256::digest(message.as_bytes()).into()
}

fn decode_hex32(hex_str: &str) -> Result<[u8; 32], Nip26Error> {
    let bytes = hex::decode(hex_str).map_err(|e| Nip26Error::HexError(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(Nip26Error::InvalidPubkey(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_keypair;

    fn make_keypair() -> ([u8; 32], String) {
        let kp = generate_keypair().unwrap();
        let sk = *kp.secret.as_bytes();
        let pk = kp.public.to_hex();
        (sk, pk)
    }

    #[test]
    fn conditions_parse_empty() {
        let c = Conditions::from_str("").unwrap();
        assert_eq!(c, Conditions::default());
    }

    #[test]
    fn conditions_parse_multi_kind() {
        let c = Conditions::from_str("kind=1&kind=6").unwrap();
        assert_eq!(c.kinds, vec![1u64, 6u64]);
    }

    #[test]
    fn conditions_strict_boundary() {
        let c = Conditions::from_str("created_at>100&created_at<200").unwrap();
        assert!(!c.permits(1, 100));
        assert!(c.permits(1, 101));
        assert!(!c.permits(1, 200));
        assert!(c.permits(1, 199));
    }

    #[test]
    fn conditions_unknown_key_error() {
        assert!(Conditions::from_str("author=abc").is_err());
    }

    #[test]
    fn delegation_roundtrip() {
        let (delegator_sk, _) = make_keypair();
        let (_, delegatee_pk) = make_keypair();
        let conditions = Conditions::from_str("kind=1").unwrap();

        let token = DelegationToken::create(&delegator_sk, &delegatee_pk, &conditions).unwrap();
        assert_eq!(token.sig.len(), 128);
        token.verify().unwrap();
    }

    #[test]
    fn validate_valid_delegation() {
        let (delegator_sk, _) = make_keypair();
        let (_, delegatee_pk) = make_keypair();
        let conditions = Conditions::from_str("kind=1&created_at>0&created_at<9999999999").unwrap();

        let token = DelegationToken::create(&delegator_sk, &delegatee_pk, &conditions).unwrap();
        let tag = DelegationTag::from_token(&token);
        validate_delegation_tag(&tag, &delegatee_pk, 1, 1_000_000_000).unwrap();
    }

    #[test]
    fn validate_wrong_kind_fails() {
        let (delegator_sk, _) = make_keypair();
        let (_, delegatee_pk) = make_keypair();
        let conditions = Conditions::from_str("kind=1").unwrap();

        let token = DelegationToken::create(&delegator_sk, &delegatee_pk, &conditions).unwrap();
        let tag = DelegationTag::from_token(&token);
        let err = validate_delegation_tag(&tag, &delegatee_pk, 4, 0).unwrap_err();
        assert!(matches!(err, Nip26Error::ConditionsNotSatisfied(_)));
    }
}
