//! NIP-26 delegation token verification endpoint (stub for W6).
//!
//! NIP-26 allows a delegator to sign a token that grants another pubkey
//! (the delegatee) the right to publish events on their behalf under specific
//! conditions.
//!
//! The delegation token is a Schnorr signature over:
//!   SHA-256("nostr:delegation:{delegatee_pubkey}:{conditions_string}")
//!
//! Because we never hold the user's private key server-side, we only provide a
//! *verification* endpoint: the client computes and signs the delegation
//! client-side, then calls this endpoint to confirm it is valid before
//! publishing the delegated events.
//!
//! Endpoint:
//!   POST /api/delegation/verify
//!   Auth: NIP-98 as the delegator pubkey
//!   Body: { delegation_tag: ["delegation", delegator_pubkey, conditions, token_hex] }
//!   Returns: { valid: true } or { valid: false, error: "reason" }

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use worker::{Env, Response, Result};

use crate::admin::{canonical_url, require_authed};
use crate::http::{error_json, json_response};

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

/// A NIP-26 delegation tag as sent by the client:
/// `["delegation", delegator_pubkey, conditions, sig_hex]`
#[derive(Deserialize)]
struct VerifyBody {
    /// Must be a 4-element array: `["delegation", <delegator>, <conditions>, <sig_hex>]`
    delegation_tag: Vec<String>,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// ---------------------------------------------------------------------------
// POST /api/delegation/verify
// ---------------------------------------------------------------------------

/// Verify a NIP-26 delegation token.
///
/// The caller authenticates via NIP-98 as the *delegator*. We confirm:
/// 1. The `delegation_tag[1]` (delegator pubkey) matches the NIP-98 signer.
/// 2. The Schnorr signature in `delegation_tag[3]` is valid over
///    SHA-256(`"nostr:delegation:{delegatee}:{conditions}"`).
pub async fn handle_verify(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
) -> Result<Response> {
    let url = canonical_url(env, "/api/delegation/verify");
    let caller_pubkey = match require_authed(auth_header, &url, "POST", Some(body_bytes), env).await
    {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let body: VerifyBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("Invalid JSON body: {e}"), 400),
    };

    // Validate tag structure.
    if body.delegation_tag.len() != 4 {
        let resp = VerifyResponse {
            valid: false,
            error: Some("delegation_tag must have exactly 4 elements".to_string()),
        };
        return json_response(env, &json!(resp), 400);
    }

    let tag_name = &body.delegation_tag[0];
    let delegator_pubkey = &body.delegation_tag[1];
    let conditions = &body.delegation_tag[2];
    let sig_hex = &body.delegation_tag[3];

    if tag_name != "delegation" {
        let resp = VerifyResponse {
            valid: false,
            error: Some("delegation_tag[0] must be \"delegation\"".to_string()),
        };
        return json_response(env, &json!(resp), 400);
    }

    // The NIP-98 caller must be the delegator.
    if *delegator_pubkey != caller_pubkey {
        let resp = VerifyResponse {
            valid: false,
            error: Some("NIP-98 signer does not match delegation_tag delegator pubkey".to_string()),
        };
        return json_response(env, &json!(resp), 403);
    }

    // Validate pubkey and sig formats before attempting crypto.
    if !is_hex64(delegator_pubkey) {
        let resp = VerifyResponse {
            valid: false,
            error: Some("delegator_pubkey is not 64-char hex".to_string()),
        };
        return json_response(env, &json!(resp), 400);
    }

    if sig_hex.len() != 128 || !sig_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        let resp = VerifyResponse {
            valid: false,
            error: Some("signature must be 128-char hex (64-byte Schnorr sig)".to_string()),
        };
        return json_response(env, &json!(resp), 400);
    }

    // We need the delegatee pubkey from the conditions or a separate field.
    // NIP-26 doesn't embed the delegatee in the tag; the delegatee is embedded
    // in the signed message string. The tag is:
    //   ["delegation", <delegator>, <conditions>, <sig_hex>]
    // The signed token covers: "nostr:delegation:{delegatee}:{conditions}"
    // But without the delegatee pubkey here we cannot reconstruct the message.
    //
    // Extended body: accept an optional delegatee_pubkey field alongside the
    // delegation_tag so the verifier can reconstruct the message.
    // We re-parse to get it.
    let ext: DelegationVerifyExt = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(_) => DelegationVerifyExt {
            delegatee_pubkey: None,
        },
    };

    let delegatee = match ext.delegatee_pubkey.as_deref() {
        Some(d) if is_hex64(d) => d.to_string(),
        Some(_) => {
            let resp = VerifyResponse {
                valid: false,
                error: Some("delegatee_pubkey must be 64-char hex".to_string()),
            };
            return json_response(env, &json!(resp), 400);
        }
        None => {
            // Without the delegatee we cannot verify the sig message.
            // Return an informative error rather than silently passing/failing.
            let resp = VerifyResponse {
                valid: false,
                error: Some(
                    "delegatee_pubkey required to reconstruct the NIP-26 signed token".to_string(),
                ),
            };
            return json_response(env, &json!(resp), 400);
        }
    };

    // Build the NIP-26 token message.
    let message = format!("nostr:delegation:{delegatee}:{conditions}");
    let message_hash = Sha256::digest(message.as_bytes());

    // Decode pubkey and signature bytes.
    let pubkey_bytes = match hex::decode(delegator_pubkey) {
        Ok(b) => b,
        Err(_) => {
            let resp = VerifyResponse {
                valid: false,
                error: Some("Failed to decode delegator pubkey".to_string()),
            };
            return json_response(env, &json!(resp), 400);
        }
    };

    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => {
            let resp = VerifyResponse {
                valid: false,
                error: Some("Failed to decode signature".to_string()),
            };
            return json_response(env, &json!(resp), 400);
        }
    };

    // Schnorr verification using k256.
    let valid = verify_schnorr(&pubkey_bytes, &message_hash, &sig_bytes);

    let resp = VerifyResponse {
        valid,
        error: if valid {
            None
        } else {
            Some("Schnorr signature verification failed".to_string())
        },
    };

    let status = if valid { 200 } else { 422 };
    json_response(env, &json!(resp), status)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DelegationVerifyExt {
    delegatee_pubkey: Option<String>,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Verify a Schnorr signature over `msg_hash` using the x-only `pubkey_bytes`.
///
/// Uses the k256 crate (same as the rest of the nostr-core stack). Returns
/// `true` only when the signature is cryptographically valid.
fn verify_schnorr(pubkey_bytes: &[u8], msg_hash: &[u8], sig_bytes: &[u8]) -> bool {
    use k256::schnorr::signature::Verifier;
    use k256::schnorr::{Signature, VerifyingKey};

    let vk = match VerifyingKey::from_bytes(pubkey_bytes) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let sig = match Signature::try_from(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify(msg_hash, &sig).is_ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::{signature::Signer, SigningKey};
    use sha2::{Digest, Sha256};

    fn make_key() -> SigningKey {
        SigningKey::from_bytes(&[0x03u8; 32]).unwrap()
    }

    #[test]
    fn schnorr_verify_roundtrip() {
        let sk = make_key();
        let vk = sk.verifying_key();
        let pubkey_bytes = vk.to_bytes();

        let msg = "nostr:delegation:ff".repeat(3);
        let hash = Sha256::digest(msg.as_bytes());

        // k256 Schnorr signing produces a 64-byte sig.
        let sig: k256::schnorr::Signature = sk.sign(&hash);
        let sig_bytes = sig.to_bytes();

        assert!(verify_schnorr(&pubkey_bytes, &hash, &sig_bytes));
    }

    #[test]
    fn schnorr_verify_wrong_msg_fails() {
        let sk = make_key();
        let vk = sk.verifying_key();
        let pubkey_bytes = vk.to_bytes();

        let msg = "nostr:delegation:correct";
        let hash = Sha256::digest(msg.as_bytes());
        let sig: k256::schnorr::Signature = sk.sign(&hash);
        let sig_bytes = sig.to_bytes();

        let wrong_hash = Sha256::digest(b"wrong message");
        assert!(!verify_schnorr(&pubkey_bytes, &wrong_hash, &sig_bytes));
    }

    #[test]
    fn is_hex64_accepts_valid() {
        assert!(is_hex64(&"a1".repeat(32)));
        assert!(!is_hex64(&"a1".repeat(31)));
        assert!(!is_hex64(&"zz".repeat(32)));
    }
}
