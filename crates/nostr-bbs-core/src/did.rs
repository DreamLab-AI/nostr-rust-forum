//! `did:nostr` DID Document generation and verification.
//!
//! Thin wrapper over `solid_pod_rs::did_nostr_types` — the upstream
//! canonical module for DID:nostr types. This layer adds forum-specific
//! conveniences (Tier-1 `authentication`/`assertionMethod` arrays,
//! positional Tier-3 signature, uppercase-tolerant hex validation) while
//! delegating all document rendering and multibase encoding upstream.
//!
//! Both auth-worker and pod-worker import from here so there is exactly
//! one document schema per tier in the forum codebase.

use serde_json::{json, Value};
use solid_pod_rs::did_nostr_types as upstream;

// Re-export upstream types that don't depend on NostrPubkey.
pub use upstream::{format_multibase_schnorr, ServiceEntry};

// ---------------------------------------------------------------------------
// NostrPubkey — wraps upstream with String error for backward compat
// ---------------------------------------------------------------------------

/// A 32-byte x-only Schnorr (secp256k1) public key, as used by NIP-01.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NostrPubkey(pub [u8; 32]);

impl NostrPubkey {
    /// Parse a lowercase hex string of exactly 64 characters.
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let up = upstream::NostrPubkey::from_hex(s).map_err(|e| e.to_string())?;
        Ok(Self(up.0))
    }

    /// Lower-case hex encoding (64 chars).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    fn to_upstream(self) -> upstream::NostrPubkey {
        upstream::NostrPubkey(self.0)
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Format a `did:nostr:<hex>` URI for the given pubkey.
pub fn did_nostr_uri(pk: &NostrPubkey) -> String {
    upstream::did_nostr_uri(&pk.to_upstream())
}

/// Path at which the DID document should be served.
/// Mirrors JSS resolver convention: `<base>/<pubkey>.json`.
pub fn well_known_path(pk: &NostrPubkey) -> String {
    upstream::well_known_path(&pk.to_upstream())
}

/// Verify that `webid_uri` is controlled by `event_pubkey`.
///
/// Accepts:
/// - `did:nostr:<hex>` — hex must equal the event pubkey.
/// - `https://pods.example.com/<hex>/...` — hex in path must match.
pub fn verify_webid_tag(webid_uri: &str, event_pubkey: &str) -> bool {
    upstream::verify_webid_tag(webid_uri, event_pubkey)
}

/// A hex pubkey is valid when it is exactly 64 ASCII hex digits.
/// Accepts both upper and lower case (NIP-01 specifies lowercase, but
/// this is lenient for robustness).
pub fn is_valid_hex_pubkey(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------
// Document renderers
// ---------------------------------------------------------------------------

/// Render a Tier-1 (minimal) DID document.
///
/// Delegates to `solid_pod_rs::did_nostr_types::render_did_document_tier1`
/// and adds `authentication` + `assertionMethod` arrays (the forum
/// convention includes these even at Tier-1 for clients that check
/// authentication purpose before accepting signatures).
pub fn render_did_document_tier1(pk: &NostrPubkey) -> Value {
    let mut doc = upstream::render_did_document_tier1(&pk.to_upstream());
    let did = did_nostr_uri(pk);
    let vm_ref = format!("{did}#nostr-schnorr");
    doc["authentication"] = json!([&vm_ref]);
    doc["assertionMethod"] = json!([&vm_ref]);
    doc
}

/// Render a Tier-3 DID document enriched with WebID and service entries.
///
/// Convenience wrapper that constructs `ServiceEntry` values from
/// positional arguments and delegates to the upstream Tier-3 renderer.
pub fn render_did_document_tier3(
    pk: &NostrPubkey,
    webid: Option<&str>,
    pod_url: &str,
    relay_url: Option<&str>,
    name: Option<&str>,
) -> Value {
    let did = did_nostr_uri(pk);

    let mut services = vec![upstream::ServiceEntry {
        id: format!("{did}#solid-pod"),
        service_type: "SolidStorage".to_string(),
        service_endpoint: pod_url.to_string(),
        extra: None,
    }];

    if let Some(webid_url) = webid {
        services.push(upstream::ServiceEntry {
            id: format!("{did}#webid"),
            service_type: "SolidWebID".to_string(),
            service_endpoint: webid_url.to_string(),
            extra: None,
        });
    }

    if let Some(relay) = relay_url {
        services.push(upstream::ServiceEntry {
            id: format!("{did}#nostr-relay"),
            service_type: "NostrRelay".to_string(),
            service_endpoint: relay.to_string(),
            extra: None,
        });
    }

    let mut doc = upstream::render_did_document_tier3(&pk.to_upstream(), webid, &services);

    if let Some(n) = name {
        doc["profile"] = json!({ "name": n });
    }

    doc
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const PK_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const VALID_PUBKEY: &str = "611df01bfcf85c26ae65453b772d8f1dfd25c264621c0277e1fc1518686faef9";

    // ── NostrPubkey ───────────────────────────────────────────────────

    #[test]
    fn pubkey_roundtrip_hex() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        assert_eq!(pk.to_hex(), PK_HEX);
    }

    #[test]
    fn pubkey_rejects_short() {
        assert!(NostrPubkey::from_hex("abcd").is_err());
    }

    #[test]
    fn pubkey_rejects_non_hex() {
        assert!(NostrPubkey::from_hex(&"z".repeat(64)).is_err());
    }

    // ── URI helpers ───────────────────────────────────────────────────

    #[test]
    fn did_uri_format() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        assert_eq!(did_nostr_uri(&pk), format!("did:nostr:{PK_HEX}"));
    }

    #[test]
    fn well_known_path_format() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let p = well_known_path(&pk);
        assert_eq!(p, format!("/.well-known/did/nostr/{PK_HEX}.json"));
    }

    // ── pubkey validation ─────────────────────────────────────────────

    #[test]
    fn valid_pubkey_accepted() {
        assert!(is_valid_hex_pubkey(VALID_PUBKEY));
    }

    #[test]
    fn invalid_pubkey_too_short() {
        assert!(!is_valid_hex_pubkey("abcdef"));
    }

    #[test]
    fn invalid_pubkey_non_hex() {
        assert!(!is_valid_hex_pubkey(&"z".repeat(64)));
    }

    #[test]
    fn uppercase_hex_is_valid() {
        let upper = "611DF01BFCF85C26AE65453B772D8F1DFD25C264621C0277E1FC1518686FAEF9";
        assert!(is_valid_hex_pubkey(upper));
    }

    // ── Tier-1 document ───────────────────────────────────────────────

    #[test]
    fn tier1_has_required_fields() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let doc = render_did_document_tier1(&pk);
        assert_eq!(doc["id"], format!("did:nostr:{PK_HEX}"));
        assert_eq!(doc["@context"][0], "https://www.w3.org/ns/did/v1");
        assert_eq!(doc["alsoKnownAs"].as_array().unwrap().len(), 0);
        let vm = &doc["verificationMethod"][0];
        assert_eq!(vm["type"], "SchnorrSecp256k1VerificationKey2019");
        assert_eq!(vm["publicKeyHex"], PK_HEX);
        assert!(vm["publicKeyMultibase"].as_str().unwrap().starts_with('z'));
    }

    #[test]
    fn tier1_includes_authentication_and_assertion() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let doc = render_did_document_tier1(&pk);
        let expected_ref = format!("did:nostr:{PK_HEX}#nostr-schnorr");
        assert_eq!(doc["authentication"][0], expected_ref);
        assert_eq!(doc["assertionMethod"][0], expected_ref);
    }

    #[test]
    fn tier1_context_fields() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let doc = render_did_document_tier1(&pk);
        let ctx = doc["@context"].as_array().unwrap();
        assert_eq!(ctx.len(), 2);
        assert_eq!(ctx[0], "https://www.w3.org/ns/did/v1");
        assert_eq!(ctx[1], "https://w3id.org/security/suites/secp256k1-2019/v1");
    }

    #[test]
    fn tier1_verification_method_type_is_2019() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let doc = render_did_document_tier1(&pk);
        let vm_type = doc["verificationMethod"][0]["type"].as_str().unwrap();
        assert_eq!(vm_type, "SchnorrSecp256k1VerificationKey2019");
        assert_ne!(vm_type, "SchnorrSecp256k1VerificationKey2022");
        assert_ne!(vm_type, "NostrSchnorrKey2024");
    }

    #[test]
    fn tier1_controller_matches_id() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let doc = render_did_document_tier1(&pk);
        assert_eq!(doc["id"], doc["verificationMethod"][0]["controller"]);
    }

    #[test]
    fn tier1_has_no_service_section() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let doc = render_did_document_tier1(&pk);
        assert!(doc.get("service").is_none());
    }

    // ── Tier-3 document ───────────────────────────────────────────────

    #[test]
    fn tier3_carries_webid_and_relay() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let webid = "https://pods.example.com/0000.../profile/card#me";
        let pod = "https://pods.example.com/0000.../";
        let relay = "wss://relay.example.com";
        let doc = render_did_document_tier3(&pk, Some(webid), pod, Some(relay), Some("Alice"));
        assert_eq!(doc["alsoKnownAs"][0], webid);
        assert_eq!(doc["profile"]["name"], "Alice");
        let services = doc["service"].as_array().unwrap();
        let types: Vec<&str> = services
            .iter()
            .map(|s| s["type"].as_str().unwrap_or(""))
            .collect();
        assert!(types.contains(&"SolidStorage"));
        assert!(types.contains(&"SolidWebID"));
        assert!(types.contains(&"NostrRelay"));
    }

    #[test]
    fn tier3_without_relay_omits_it() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let doc = render_did_document_tier3(&pk, None, "https://pod.test/", None, None);
        let services = doc["service"].as_array().unwrap();
        assert_eq!(services.len(), 1);
    }

    // ── WebID verification ────────────────────────────────────────────

    #[test]
    fn verify_webid_tag_did_nostr() {
        let pk = "a".repeat(64);
        assert!(verify_webid_tag(&format!("did:nostr:{pk}"), &pk));
        assert!(!verify_webid_tag(
            &format!("did:nostr:{pk}"),
            &"b".repeat(64)
        ));
    }

    #[test]
    fn verify_webid_tag_pod_url() {
        let pk = "a".repeat(64);
        let uri = format!("https://pods.example.com/{pk}/profile/card#me");
        assert!(verify_webid_tag(&uri, &pk));
        assert!(!verify_webid_tag(&uri, &"b".repeat(64)));
    }

    // ── Multibase ─────────────────────────────────────────────────────

    #[test]
    fn multibase_is_deterministic_and_starts_z() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let a = format_multibase_schnorr(&pk.0);
        let b = format_multibase_schnorr(&pk.0);
        assert_eq!(a, b);
        assert!(a.starts_with('z'));
        assert!(a.len() > 10);
    }

    // ── Upstream parity ───────────────────────────────────────────────

    #[test]
    fn multibase_matches_upstream() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let local = format_multibase_schnorr(&pk.0);
        let up = upstream::format_multibase_schnorr(&pk.to_upstream().0);
        assert_eq!(local, up, "multibase encoding must match upstream");
    }

    #[test]
    fn tier1_superset_of_upstream() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let local = render_did_document_tier1(&pk);
        let up = upstream::render_did_document_tier1(&pk.to_upstream());
        assert_eq!(local["id"], up["id"]);
        assert_eq!(local["@context"], up["@context"]);
        assert_eq!(local["verificationMethod"], up["verificationMethod"]);
        assert_eq!(local["alsoKnownAs"], up["alsoKnownAs"]);
        // Forum adds authentication + assertionMethod at Tier-1
        assert!(local.get("authentication").is_some());
        assert!(up.get("authentication").is_none());
    }
}
