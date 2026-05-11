//! DID:nostr document serving (ADR-074 Tier-1).
//!
//! Serves W3C DID Core documents at `/.well-known/did/nostr/{pubkey}.json`.
//! Delegates document rendering to `nostr_bbs_core::did` (the canonical
//! single-source renderer) and handles only worker-specific concerns:
//! D1 existence gating, HTTP response building, and caching.

use nostr_bbs_core::did::{is_valid_hex_pubkey, render_did_document_tier1, NostrPubkey};
use serde_json::json;
use wasm_bindgen::JsValue;
use worker::*;

/// Handle a `GET /.well-known/did/nostr/{pubkey}.json` request.
///
/// 1. Validates the pubkey (64-char lowercase hex).
/// 2. Checks the `webauthn_credentials` D1 table to confirm the pubkey is
///    registered (returns 404 for unknown pubkeys).
/// 3. Builds a Tier-1 DID document via core's canonical renderer.
/// 4. Returns `application/did+json` with 5-minute cache.
pub async fn handle_did_document(pubkey: &str, env: &Env) -> Result<Response> {
    let pubkey_lower = pubkey.to_ascii_lowercase();

    if !is_valid_hex_pubkey(&pubkey_lower) {
        return did_error("Invalid pubkey: must be 64 lowercase hex characters", 400);
    }

    if !is_registered_pubkey(&pubkey_lower, env).await? {
        return did_error("Pubkey not registered", 404);
    }

    let pk = NostrPubkey::from_hex(&pubkey_lower)
        .map_err(|e| Error::RustError(e))?;
    let doc = render_did_document_tier1(&pk);
    let body = serde_json::to_string(&doc).map_err(|e| Error::RustError(e.to_string()))?;

    let headers = Headers::new();
    headers.set("Content-Type", "application/did+json")?;
    headers.set("Cache-Control", "public, max-age=300")?;

    Ok(Response::ok(body)?.with_headers(headers))
}

/// Check the D1 `webauthn_credentials` table for a row matching `pubkey`.
async fn is_registered_pubkey(pubkey: &str, env: &Env) -> Result<bool> {
    let db = env.d1("DB")?;
    let row = db
        .prepare("SELECT 1 AS found FROM webauthn_credentials WHERE pubkey = ?1 LIMIT 1")
        .bind(&[JsValue::from_str(pubkey)])?
        .first::<serde_json::Value>(None)
        .await?;
    Ok(row.is_some())
}

fn did_error(message: &str, status: u16) -> Result<Response> {
    let body = serde_json::to_string(&json!({ "error": message }))
        .map_err(|e| Error::RustError(e.to_string()))?;
    let headers = Headers::new();
    headers.set("Content-Type", "application/json")?;
    Ok(Response::ok(body)?.with_status(status).with_headers(headers))
}

#[cfg(test)]
mod tests {
    use nostr_bbs_core::did::{is_valid_hex_pubkey, render_did_document_tier1, NostrPubkey};

    const VALID_PUBKEY: &str = "611df01bfcf85c26ae65453b772d8f1dfd25c264621c0277e1fc1518686faef9";

    #[test]
    fn tier1_from_auth_worker_matches_core() {
        let pk = NostrPubkey::from_hex(VALID_PUBKEY).unwrap();
        let doc = render_did_document_tier1(&pk);
        assert_eq!(doc["id"], format!("did:nostr:{VALID_PUBKEY}"));
        assert!(doc["verificationMethod"][0]["publicKeyMultibase"]
            .as_str()
            .unwrap()
            .starts_with('z'));
        assert_eq!(doc["alsoKnownAs"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn pubkey_validation_delegates_to_core() {
        assert!(is_valid_hex_pubkey(VALID_PUBKEY));
        assert!(!is_valid_hex_pubkey("short"));
    }
}
