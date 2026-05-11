//! DID:nostr document serving (ADR-074 Tier-1).
//!
//! Serves W3C DID Core documents at `/.well-known/did/nostr/{pubkey}.json`.
//! Implements a Tier-1 (minimal) document with Schnorr secp256k1 verification
//! per ADR-074 rules D1-D4.

use serde_json::json;
use wasm_bindgen::JsValue;
use worker::*;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Handle a `GET /.well-known/did/nostr/{pubkey}.json` request.
///
/// 1. Validates the pubkey (64-char lowercase hex).
/// 2. Checks the `webauthn_credentials` D1 table to confirm the pubkey is
///    registered (returns 404 for unknown pubkeys).
/// 3. Builds a Tier-1 DID document per ADR-074 D1-D4.
/// 4. Returns `application/did+json` with 5-minute cache.
pub async fn handle_did_document(pubkey: &str, env: &Env) -> Result<Response> {
    // Normalise to lowercase so mixed-case URLs resolve correctly.
    let pubkey_lower = pubkey.to_ascii_lowercase();

    if !is_valid_hex_pubkey(&pubkey_lower) {
        return did_error("Invalid pubkey: must be 64 lowercase hex characters", 400);
    }

    // Gate on registration: only serve documents for known users.
    if !is_registered_pubkey(&pubkey_lower, env).await? {
        return did_error("Pubkey not registered", 404);
    }

    let doc = render_did_document(&pubkey_lower);
    let body = serde_json::to_string(&doc).map_err(|e| Error::RustError(e.to_string()))?;

    let headers = Headers::new();
    headers.set("Content-Type", "application/did+json")?;
    headers.set("Cache-Control", "public, max-age=300")?;

    Ok(Response::ok(body)?.with_headers(headers))
}

/// Build a Tier-1 DID document for the given **lowercase hex** pubkey.
///
/// The output conforms to ADR-074 D1-D4:
/// - Both required `@context` entries present (D4).
/// - `id` uses canonical `did:nostr:{lowercase_hex}` form (D1).
/// - Single `verificationMethod` with type `SchnorrSecp256k1VerificationKey2019` (D1).
/// - `controller` matches `document.id` (D2).
/// - `authentication` and `assertionMethod` reference the key (D3).
pub fn render_did_document(pubkey: &str) -> serde_json::Value {
    let did = format!("did:nostr:{pubkey}");
    let key_id = format!("{did}#nostr-schnorr");

    json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/secp256k1-2019/v1"
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "SchnorrSecp256k1VerificationKey2019",
                "controller": did,
                "publicKeyHex": pubkey
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id]
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A hex pubkey is valid when it is exactly 64 ASCII hex digits.
fn is_valid_hex_pubkey(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
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

/// Build a JSON error response with the given status code.
fn did_error(message: &str, status: u16) -> Result<Response> {
    let body = serde_json::to_string(&json!({ "error": message }))
        .map_err(|e| Error::RustError(e.to_string()))?;
    let headers = Headers::new();
    headers.set("Content-Type", "application/json")?;
    Ok(Response::ok(body)?.with_status(status).with_headers(headers))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_PUBKEY: &str = "611df01bfcf85c26ae65453b772d8f1dfd25c264621c0277e1fc1518686faef9";

    // ── pubkey validation ──────────────────────────────────────────────

    #[test]
    fn test_valid_pubkey_accepted() {
        assert!(is_valid_hex_pubkey(VALID_PUBKEY));
    }

    #[test]
    fn test_invalid_pubkey_too_short() {
        assert!(!is_valid_hex_pubkey("abcdef"));
    }

    #[test]
    fn test_invalid_pubkey_too_long() {
        let long = "a".repeat(65);
        assert!(!is_valid_hex_pubkey(&long));
    }

    #[test]
    fn test_invalid_pubkey_non_hex() {
        let bad = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert_eq!(bad.len(), 64);
        assert!(!is_valid_hex_pubkey(bad));
    }

    #[test]
    fn test_uppercase_hex_is_valid_hex() {
        // Uppercase hex passes is_valid_hex_pubkey because ASCII hex digits
        // include A-F. The handler normalises to lowercase before calling this.
        let upper = "611DF01BFCF85C26AE65453B772D8F1DFD25C264621C0277E1FC1518686FAEF9";
        assert!(is_valid_hex_pubkey(upper));
    }

    // ── DID document structure ─────────────────────────────────────────

    #[test]
    fn test_valid_pubkey_produces_correct_document() {
        let doc = render_did_document(VALID_PUBKEY);

        // id
        assert_eq!(
            doc["id"],
            format!("did:nostr:{VALID_PUBKEY}")
        );

        // verificationMethod
        let vm = &doc["verificationMethod"];
        assert!(vm.is_array());
        assert_eq!(vm.as_array().unwrap().len(), 1);

        let key = &vm[0];
        assert_eq!(
            key["id"],
            format!("did:nostr:{VALID_PUBKEY}#nostr-schnorr")
        );
        assert_eq!(key["type"], "SchnorrSecp256k1VerificationKey2019");
        assert_eq!(
            key["controller"],
            format!("did:nostr:{VALID_PUBKEY}")
        );
        assert_eq!(key["publicKeyHex"], VALID_PUBKEY);

        // authentication + assertionMethod
        assert_eq!(
            doc["authentication"][0],
            format!("did:nostr:{VALID_PUBKEY}#nostr-schnorr")
        );
        assert_eq!(
            doc["assertionMethod"][0],
            format!("did:nostr:{VALID_PUBKEY}#nostr-schnorr")
        );
    }

    #[test]
    fn test_context_fields_present() {
        let doc = render_did_document(VALID_PUBKEY);
        let ctx = doc["@context"].as_array().expect("@context must be array");
        assert_eq!(ctx.len(), 2);
        assert_eq!(ctx[0], "https://www.w3.org/ns/did/v1");
        assert_eq!(
            ctx[1],
            "https://w3id.org/security/suites/secp256k1-2019/v1"
        );
    }

    #[test]
    fn test_verification_method_type_is_2019() {
        let doc = render_did_document(VALID_PUBKEY);
        let vm_type = doc["verificationMethod"][0]["type"]
            .as_str()
            .expect("type must be string");
        assert_eq!(vm_type, "SchnorrSecp256k1VerificationKey2019");
        // Guard against drift to 2022 or 2024 variants
        assert_ne!(vm_type, "SchnorrSecp256k1VerificationKey2022");
        assert_ne!(vm_type, "NostrSchnorrKey2024");
    }

    #[test]
    fn test_controller_matches_document_id() {
        let doc = render_did_document(VALID_PUBKEY);
        assert_eq!(doc["id"], doc["verificationMethod"][0]["controller"]);
    }

    #[test]
    fn test_document_has_no_service_section() {
        // Tier-1 documents omit services (Tier-3 adds them).
        let doc = render_did_document(VALID_PUBKEY);
        assert!(doc.get("service").is_none());
    }
}
