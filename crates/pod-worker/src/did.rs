//! `did:nostr` DID Document generation.
//!
//! Mirrors solid-pod-rs-nostr v0.4.0-alpha.2 `did` module logic, adapted
//! for WASM Workers (no tokio dependency). Logic is sourced from the forum's
//! own solid-pod-rs-nostr crate; this is the pod-worker thin adapter layer.
//!
//! Upstream: `solid-pod-rs-nostr/src/did.rs`
//! PARITY-CHECKLIST: rows 89, 90, 101, 132.

use serde_json::{json, Value};

/// A 32-byte x-only Schnorr (secp256k1) public key, as used by NIP-01.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NostrPubkey(pub [u8; 32]);

impl NostrPubkey {
    /// Parse a lowercase hex string of exactly 64 characters.
    pub fn from_hex(s: &str) -> Result<Self, String> {
        if s.len() != 64 {
            return Err(format!("expected 64 hex chars, got {}", s.len()));
        }
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Lower-case hex encoding (64 chars).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Format a `did:nostr:<hex>` URI for the given pubkey.
pub fn did_nostr_uri(pk: &NostrPubkey) -> String {
    format!("did:nostr:{}", pk.to_hex())
}

/// Path at which the DID document should be served.
/// Mirrors JSS resolver convention: `<base>/<pubkey>.json`.
pub fn well_known_path(pk: &NostrPubkey) -> String {
    format!("/.well-known/did/nostr/{}.json", pk.to_hex())
}

/// Verify that `webid_uri` is controlled by `event_pubkey`.
///
/// Accepts:
/// - `did:nostr:<hex>` — hex must equal the event pubkey.
/// - `https://pods.example.com/<hex>/...` — hex in path must match.
pub fn verify_webid_tag(webid_uri: &str, event_pubkey: &str) -> bool {
    if let Some(did_hex) = webid_uri.strip_prefix("did:nostr:") {
        return did_hex == event_pubkey;
    }
    // Pod WebID: https://pods.example.com/{pubkey}/profile/card#me
    if let Some(path) = webid_uri.strip_prefix("https://pods.example.com/") {
        let pubkey_from_path = path.split('/').next().unwrap_or("");
        return pubkey_from_path == event_pubkey;
    }
    false
}

/// Render a minimum-viable (Tier 1) DID document.
///
/// Contains W3C DID Core v1 context, the secp256k1-2019 security suite
/// context, `id`, empty `alsoKnownAs`, and a single
/// `SchnorrSecp256k1VerificationKey2019` verification method with both
/// `publicKeyHex` (JSS parity) and `publicKeyMultibase` (multibase z +
/// multicodec 0xe7).
///
/// Verification method type follows ADR-027: align with the W3C-registered
/// `SchnorrSecp256k1VerificationKey2019` cryptosuite rather than a custom
/// `NostrSchnorrKey2024` type, so generic DID resolvers can validate
/// signatures without forum-specific extensions.
///
/// Mirrors `solid_pod_rs_nostr::did::render_did_document_tier1`.
pub fn render_did_document_tier1(pk: &NostrPubkey) -> Value {
    let did = did_nostr_uri(pk);
    let vm_id = format!("{did}#nostr-schnorr");
    json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/secp256k1-2019/v1"
        ],
        "id": did,
        "alsoKnownAs": [],
        "verificationMethod": [{
            "id": vm_id,
            "type": "SchnorrSecp256k1VerificationKey2019",
            "controller": did,
            "publicKeyHex": pk.to_hex(),
            "publicKeyMultibase": format_multibase_schnorr(&pk.0)
        }],
        "authentication": [format!("{did}#nostr-schnorr")],
        "assertionMethod": [format!("{did}#nostr-schnorr")]
    })
}

/// Render a Tier-3 DID document enriched with WebID and service entries.
///
/// `webid` populates `alsoKnownAs`. Services surface federation endpoints
/// (SolidWebID, NostrRelay, etc.). Mirrors
/// `solid_pod_rs_nostr::did::render_did_document_tier3`.
pub fn render_did_document_tier3(
    pk: &NostrPubkey,
    webid: Option<&str>,
    pod_url: &str,
    relay_url: Option<&str>,
    name: Option<&str>,
) -> Value {
    let did = did_nostr_uri(pk);
    let vm_id = format!("{did}#nostr-schnorr");

    let also_known_as: Vec<Value> = webid.iter().map(|w| Value::String(w.to_string())).collect();

    let mut services: Vec<Value> = vec![json!({
        "id": format!("{did}#solid-pod"),
        "type": "SolidStorage",
        "serviceEndpoint": pod_url
    })];

    if let Some(webid_url) = webid {
        services.push(json!({
            "id": format!("{did}#webid"),
            "type": "SolidWebID",
            "serviceEndpoint": webid_url
        }));
    }

    if let Some(relay) = relay_url {
        services.push(json!({
            "id": format!("{did}#nostr-relay"),
            "type": "NostrRelay",
            "serviceEndpoint": relay
        }));
    }

    let mut doc = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/secp256k1-2019/v1"
        ],
        "id": did,
        "alsoKnownAs": also_known_as,
        "verificationMethod": [{
            "id": vm_id,
            "type": "SchnorrSecp256k1VerificationKey2019",
            "controller": did,
            "publicKeyHex": pk.to_hex(),
            "publicKeyMultibase": format_multibase_schnorr(&pk.0)
        }],
        "authentication": [format!("{did}#nostr-schnorr")],
        "assertionMethod": [format!("{did}#nostr-schnorr")],
        "service": services
    });

    if let Some(n) = name {
        doc["profile"] = json!({ "name": n });
    }

    doc
}

/// Build a `publicKeyMultibase` string for a secp256k1 x-only pubkey.
///
/// Layout: `'z' || base58btc( 0xe7 0x01 || pubkey )`.
/// Multicodec `0xe7` = secp256k1-pub; `0x01` is the varint continuation.
/// Mirrors `solid_pod_rs_nostr::did::format_multibase_schnorr`.
fn format_multibase_schnorr(pk: &[u8; 32]) -> String {
    let mut prefixed = Vec::with_capacity(34);
    prefixed.push(0xe7u8);
    prefixed.push(0x01u8);
    prefixed.extend_from_slice(pk);
    format!("z{}", base58_encode(&prefixed))
}

/// Minimal base58btc encoder (Bitcoin alphabet).
/// Avoids adding an extra dependency for a single use site.
/// Mirrors `solid_pod_rs_nostr::did::base58_encode`.
fn base58_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if input.is_empty() {
        return String::new();
    }

    let zeros = input.iter().take_while(|&&b| b == 0).count();

    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 2);
    for &byte in input {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat('1').take(zeros));
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const PK_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";

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
        assert!(p.starts_with("/.well-known/did/nostr/"));
        assert!(p.ends_with(".json"));
    }

    #[test]
    fn tier1_has_required_fields() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let doc = render_did_document_tier1(&pk);
        assert_eq!(doc["id"], format!("did:nostr:{PK_HEX}"));
        assert_eq!(doc["@context"][0], "https://www.w3.org/ns/did/v1");
        assert_eq!(doc["alsoKnownAs"].as_array().unwrap().len(), 0);
        let vm = &doc["verificationMethod"][0];
        assert_eq!(vm["type"], "SchnorrSecp256k1VerificationKey2019");
        // ADR-027: secp256k1-2019 security suite must be in @context for
        // generic DID resolvers to validate the verificationMethod.
        let ctx = doc["@context"].as_array().unwrap();
        assert!(ctx
            .iter()
            .any(|v| v == "https://w3id.org/security/suites/secp256k1-2019/v1"));
        assert_eq!(vm["publicKeyHex"], PK_HEX);
        assert!(vm["publicKeyMultibase"].as_str().unwrap().starts_with('z'));
    }

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

    #[test]
    fn multibase_is_deterministic_and_starts_z() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let a = format_multibase_schnorr(&pk.0);
        let b = format_multibase_schnorr(&pk.0);
        assert_eq!(a, b);
        assert!(a.starts_with('z'));
        assert!(a.len() > 10);
    }
}
