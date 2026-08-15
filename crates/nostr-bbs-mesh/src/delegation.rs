//! NIP-26 delegation — the universal trust pivot (ADR-074 §D8, PRD-010 G5/F8).
//!
//! A delegation token lets one key (the *delegator*) authorise another key (the
//! *delegatee*) to sign events on its behalf under bounded conditions. On the
//! mesh this is how a forum user authorises an agentbox agent or a VisionClaw
//! bridge to act for them without surrendering custody of their key.
//!
//! Wire form (ADR-074 §D8): a tag `["delegation", delegator_pk_hex,
//! conditions_str, sig_hex]` attached to the delegatee-signed event, mirrored
//! into the IS-Envelope `delegation` field (ADR-075 §D1) for in-band app logic.
//!
//! Signed bytes (ADR-074 §D8):
//!
//! ```text
//! sig = Schnorr_sign(delegator_sk, sha256("nostr:delegation:" || delegatee_pk_hex || ":" || conditions))
//! ```
//!
//! Conditions grammar: `kind=N&kind=M&created_at>T1&created_at<T2`
//! * multiple `kind=` clauses are **OR**'d,
//! * `created_at>T` and `created_at<T` are **AND**'d bounds (strict).
//!
//! # This kit has no `nip26` module
//!
//! The sibling `community-forum-rs` crate ships `nostr-core/src/nip26.rs`, but
//! *this* kit's `nostr-bbs-core` does not. Rather than take a cross-repo
//! dependency, this module implements the verifier directly on top of
//! `nostr-bbs-core`'s BIP-340 primitives (`PublicKey::verify`,
//! `Signature::from_bytes`).
//!
//! # Which event do the conditions bind?
//!
//! ADR-074 §D8 says conditions match "the event"; ADR-075 §D6 puts the tag on
//! the kind-13 seal, yet its Example 2 uses `kind=14` — the *rumor* kind.
//! Decision (documented): [`Conditions::check`] is applied against the **rumor**
//! (kind 14 and the rumor's true `created_at`), because that is the event whose
//! authorship the delegation actually attributes. The delegatee is the seal
//! signer (`seal.pubkey`), which is what [`DelegationToken::verify`] takes.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use nostr_bbs_core::keys::{PublicKey, Signature};

/// The `nostr:delegation:` message prefix from ADR-074 §D8.
pub const DELEGATION_MSG_PREFIX: &str = "nostr:delegation:";

/// A NIP-26 delegation token (ADR-074 §D8 / ADR-075 §D1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationToken {
    /// The delegator's identity. Accepted as bare 64-hex or `did:nostr:<hex>`;
    /// [`DelegationToken::delegator_hex`] normalises it for verification.
    pub delegator: String,
    /// The NIP-26 conditions query string, e.g. `kind=14&created_at<1763500000`.
    pub conditions: String,
    /// The delegator's 128-hex Schnorr signature over the delegation message.
    pub sig: String,
}

/// Errors from delegation parsing / verification.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DelegationError {
    /// Structural problem (empty field, wrong hex length, malformed conditions).
    #[error("delegation-invalid: {0}")]
    Malformed(String),
    /// The Schnorr signature did not verify against the delegator key.
    #[error("delegation-invalid: signature verification failed")]
    BadSignature,
    /// The delegated event violates the conditions (kind or timestamp bound).
    #[error("delegation-invalid: {0}")]
    ConditionsUnmet(String),
    /// The envelope's mirrored token disagrees with the seal's tag.
    #[error("delegation-invalid: envelope/seal token mismatch")]
    Mismatch,
}

impl DelegationToken {
    /// Construct a token from its three wire parts.
    pub fn new(delegator: impl Into<String>, conditions: impl Into<String>, sig: impl Into<String>) -> Self {
        DelegationToken {
            delegator: delegator.into(),
            conditions: conditions.into(),
            sig: sig.into(),
        }
    }

    /// Parse from a `["delegation", delegator, conditions, sig]` tag.
    pub fn from_tag(tag: &[String]) -> Option<Self> {
        if tag.len() >= 4 && tag[0] == "delegation" {
            Some(DelegationToken::new(&tag[1], &tag[2], &tag[3]))
        } else {
            None
        }
    }

    /// Render as a `["delegation", ...]` tag (bare-hex delegator form).
    pub fn to_tag(&self) -> Vec<String> {
        vec![
            "delegation".to_string(),
            self.delegator_hex(),
            self.conditions.clone(),
            self.sig.clone(),
        ]
    }

    /// The delegator's bare 64-hex pubkey (strips an optional `did:nostr:`).
    pub fn delegator_hex(&self) -> String {
        self.delegator
            .strip_prefix("did:nostr:")
            .unwrap_or(&self.delegator)
            .to_ascii_lowercase()
    }

    /// Structural validation only (no crypto): non-empty delegator/conditions
    /// and a 128-hex signature.
    pub fn validate_structure(&self) -> Result<(), DelegationError> {
        let dh = self.delegator_hex();
        if dh.len() != 64 || !is_hex(&dh) {
            return Err(DelegationError::Malformed("delegator must be 64-hex".into()));
        }
        if self.conditions.trim().is_empty() {
            return Err(DelegationError::Malformed("empty conditions".into()));
        }
        if self.sig.len() != 128 || !is_hex(&self.sig) {
            return Err(DelegationError::Malformed("sig must be 128-hex".into()));
        }
        // Conditions must parse.
        Conditions::parse(&self.conditions)?;
        Ok(())
    }

    /// The 32-byte SHA-256 message the delegator signs, for a given delegatee.
    pub fn signing_message(&self, delegatee_hex: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(DELEGATION_MSG_PREFIX.as_bytes());
        hasher.update(delegatee_hex.to_ascii_lowercase().as_bytes());
        hasher.update(b":");
        hasher.update(self.conditions.as_bytes());
        hasher.finalize().into()
    }

    /// Verify the delegator's signature authorises `delegatee_hex`, returning
    /// the parsed [`Conditions`] on success (ADR-074 §D8 steps 1–4).
    ///
    /// This does **not** apply the conditions to any event — call
    /// [`Conditions::check`] with the delegated event's kind and timestamp.
    pub fn verify(&self, delegatee_hex: &str) -> Result<Conditions, DelegationError> {
        self.validate_structure()?;
        let conditions = Conditions::parse(&self.conditions)?;

        let pk = PublicKey::from_hex(&self.delegator_hex())
            .map_err(|e| DelegationError::Malformed(format!("delegator key: {e}")))?;
        let sig_bytes = hex::decode(&self.sig)
            .map_err(|e| DelegationError::Malformed(format!("sig hex: {e}")))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| DelegationError::Malformed("sig must be 64 bytes".into()))?;
        let sig = Signature::from_bytes(sig_arr);

        let msg = self.signing_message(delegatee_hex);
        pk.verify(&msg, &sig).map_err(|_| DelegationError::BadSignature)?;
        Ok(conditions)
    }

    /// Full verification for a received message: verify the signature against
    /// the seal signer (`delegatee_hex`) and apply the conditions to the
    /// delegated (rumor) event's `kind` and `created_at`.
    pub fn verify_for_event(
        &self,
        delegatee_hex: &str,
        event_kind: u64,
        event_created_at: u64,
    ) -> Result<(), DelegationError> {
        let conditions = self.verify(delegatee_hex)?;
        conditions.check(event_kind, event_created_at)
    }
}

/// Parsed NIP-26 conditions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Conditions {
    /// Allowed event kinds (OR-semantics). Empty = any kind allowed.
    pub kinds: Vec<u64>,
    /// Strict lower bound on `created_at` (`created_at>T`).
    pub created_at_gt: Option<u64>,
    /// Strict upper bound on `created_at` (`created_at<T`).
    pub created_at_lt: Option<u64>,
}

impl Conditions {
    /// Parse the `kind=..&created_at>..&created_at<..` grammar (ADR-074 §D8).
    pub fn parse(s: &str) -> Result<Self, DelegationError> {
        let mut c = Conditions::default();
        for clause in s.split('&').map(str::trim).filter(|c| !c.is_empty()) {
            if let Some(rest) = clause.strip_prefix("kind=") {
                let k: u64 = rest
                    .parse()
                    .map_err(|_| DelegationError::Malformed(format!("bad kind clause: {clause}")))?;
                c.kinds.push(k);
            } else if let Some(rest) = clause.strip_prefix("created_at>") {
                c.created_at_gt = Some(
                    rest.parse()
                        .map_err(|_| DelegationError::Malformed(format!("bad created_at>: {clause}")))?,
                );
            } else if let Some(rest) = clause.strip_prefix("created_at<") {
                c.created_at_lt = Some(
                    rest.parse()
                        .map_err(|_| DelegationError::Malformed(format!("bad created_at<: {clause}")))?,
                );
            } else {
                return Err(DelegationError::Malformed(format!("unknown clause: {clause}")));
            }
        }
        if c.kinds.is_empty() && c.created_at_gt.is_none() && c.created_at_lt.is_none() {
            return Err(DelegationError::Malformed("no conditions parsed".into()));
        }
        Ok(c)
    }

    /// Apply the conditions to a delegated event (ADR-074 §D8 step 3).
    pub fn check(&self, kind: u64, created_at: u64) -> Result<(), DelegationError> {
        if !self.kinds.is_empty() && !self.kinds.contains(&kind) {
            return Err(DelegationError::ConditionsUnmet(format!(
                "kind {kind} not in delegated set {:?}",
                self.kinds
            )));
        }
        if let Some(gt) = self.created_at_gt {
            if !(created_at > gt) {
                return Err(DelegationError::ConditionsUnmet(format!(
                    "created_at {created_at} not > {gt}"
                )));
            }
        }
        if let Some(lt) = self.created_at_lt {
            if !(created_at < lt) {
                return Err(DelegationError::ConditionsUnmet(format!(
                    "created_at {created_at} not < {lt}"
                )));
            }
        }
        Ok(())
    }
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_bbs_core::keys::generate_keypair;

    /// Produce a valid token: delegator authorises delegatee for `conditions`.
    fn make_token(conditions: &str) -> (String, DelegationToken) {
        let delegator = generate_keypair().unwrap();
        let delegatee = generate_keypair().unwrap();
        let delegatee_hex = delegatee.public.to_hex();
        let token = DelegationToken::new(delegator.public.to_hex(), conditions, "00".repeat(64));
        let msg = token.signing_message(&delegatee_hex);
        let sig = delegator.secret.sign(&msg).unwrap();
        let token = DelegationToken::new(delegator.public.to_hex(), conditions, sig.to_hex());
        (delegatee_hex, token)
    }

    #[test]
    fn valid_delegation_verifies() {
        let (delegatee_hex, token) = make_token("kind=14&created_at<9999999999");
        let conditions = token.verify(&delegatee_hex).unwrap();
        assert_eq!(conditions.kinds, vec![14]);
        conditions.check(14, 1_000_000_000).unwrap();
    }

    #[test]
    fn tampered_conditions_fail_signature() {
        let (delegatee_hex, mut token) = make_token("kind=14");
        token.conditions = "kind=1059".to_string(); // sig no longer matches
        assert_eq!(token.verify(&delegatee_hex), Err(DelegationError::BadSignature));
    }

    #[test]
    fn wrong_delegatee_fails() {
        let (_delegatee_hex, token) = make_token("kind=14");
        let other = generate_keypair().unwrap().public.to_hex();
        assert_eq!(token.verify(&other), Err(DelegationError::BadSignature));
    }

    #[test]
    fn conditions_kind_or_semantics() {
        let c = Conditions::parse("kind=4&kind=14&kind=1059").unwrap();
        assert!(c.check(14, 1).is_ok());
        assert!(c.check(1, 1).is_err());
    }

    #[test]
    fn conditions_timestamp_bounds() {
        let c = Conditions::parse("created_at>100&created_at<200").unwrap();
        assert!(c.check(14, 150).is_ok());
        assert!(c.check(14, 100).is_err()); // strict >
        assert!(c.check(14, 200).is_err()); // strict <
    }

    #[test]
    fn tag_round_trip() {
        let (_d, token) = make_token("kind=14");
        let tag = token.to_tag();
        let back = DelegationToken::from_tag(&tag).unwrap();
        assert_eq!(back.conditions, token.conditions);
        assert_eq!(back.sig, token.sig);
    }
}
