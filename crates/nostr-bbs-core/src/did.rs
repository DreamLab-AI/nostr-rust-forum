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
//!
//! ## Parity model
//!
//! Follows nostrcg/did-nostr#145 (closing #144). The `did:nostr` identifier
//! is the x-only key. A resolver that has only the identifier — every
//! `/.well-known/did/nostr/<hex>.json` route in the forum, which reads the
//! pubkey from D1 — emits `publicKeyMultibase: fe70102…` via
//! [`render_did_document_tier1`]. A controller that publishes its own
//! document from the full key may carry `fe70103…` when y is odd
//! ([`render_did_document_published`]). Decoders accept both and return the
//! same x ([`parse_multibase_schnorr`]); key arithmetic on a published
//! document starts from the point it carries ([`parse_multibase_sec1`]), and
//! with only the identifier from the `0x02` point
//! ([`NostrPubkey::to_even_public_key`]).

use serde_json::{json, Value};
use solid_pod_rs::did_nostr_types as upstream;

// Re-export upstream items that don't depend on NostrPubkey.
pub use upstream::{
    format_multibase_public_key, format_multibase_schnorr, render_did_document_published,
    ServiceEntry, MULTIKEY_LEN, MULTIKEY_PREFIX, MULTIKEY_PREFIX_ODD,
};

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

    /// The x-only identifier of a full secp256k1 public key (parity dropped).
    ///
    /// ```
    /// use nostr_bbs_core::did::NostrPubkey;
    ///
    /// let sk = k256::SecretKey::from_slice(&[0x11; 32]).unwrap();
    /// assert_eq!(NostrPubkey::from_public_key(&sk.public_key()).to_hex().len(), 64);
    /// ```
    pub fn from_public_key(pk: &k256::PublicKey) -> Self {
        Self(upstream::NostrPubkey::from_public_key(pk).0)
    }

    /// The `0x02` (even-y) point for this identifier — BIP-340 `lift_x`.
    ///
    /// The point to tweak when only the identifier is known; a holder whose
    /// secret gives the odd-y point uses `n − d` once so this point is theirs.
    ///
    /// # Errors
    ///
    /// Returns a message if `x` is not on secp256k1.
    pub fn to_even_public_key(&self) -> Result<k256::PublicKey, String> {
        self.to_upstream()
            .to_even_public_key()
            .map_err(|e| e.to_string())
    }

    fn to_upstream(self) -> upstream::NostrPubkey {
        upstream::NostrPubkey(self.0)
    }
}

// ---------------------------------------------------------------------------
// Multikey decoding / full-key encoding
// ---------------------------------------------------------------------------

/// Decode a `publicKeyMultibase` (`fe70102…` or `fe70103…`) to the x-only
/// `did:nostr` key.
///
/// Both parity prefixes are accepted and yield the same key — verifiers MUST
/// accept both (nostrcg/did-nostr#145; vectors `decode_even_parity` /
/// `decode_odd_parity`). Delegates to `solid_pod_rs`.
///
/// # Errors
///
/// Returns a message for a wrong prefix or multicodec, a length other than
/// [`MULTIKEY_LEN`], or uppercase / non-hex characters.
///
/// ```
/// use nostr_bbs_core::did::parse_multibase_schnorr;
///
/// let x = "124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2";
/// let even = parse_multibase_schnorr(&format!("fe70102{x}")).unwrap();
/// let odd = parse_multibase_schnorr(&format!("fe70103{x}")).unwrap();
/// assert_eq!(even, odd);
/// ```
pub fn parse_multibase_schnorr(s: &str) -> Result<NostrPubkey, String> {
    upstream::parse_multibase_schnorr(s)
        .map(|pk| NostrPubkey(pk.0))
        .map_err(|e| e.to_string())
}

/// Decode a `publicKeyMultibase` to the full point it carries, keeping its
/// parity — the point to tweak when doing key arithmetic on a published
/// document.
///
/// # Errors
///
/// Every error of [`parse_multibase_schnorr`], plus x not on secp256k1.
pub fn parse_multibase_sec1(s: &str) -> Result<k256::PublicKey, String> {
    upstream::parse_multibase_sec1(s).map_err(|e| e.to_string())
}

/// Build `publicKeyMultibase` from a controller's 33-byte SEC1-compressed
/// point, keeping its parity byte (`fe70102…` / `fe70103…`).
///
/// # Errors
///
/// Returns a message if `compressed` is not a valid 33-byte compressed
/// secp256k1 point.
pub fn format_multibase_sec1(compressed: &[u8]) -> Result<String, String> {
    upstream::format_multibase_sec1(compressed).map_err(|e| e.to_string())
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
/// Full delegation to `solid_pod_rs::did_nostr_types::render_did_document_tier1`
/// — the canonical create-agent / ADR-125 Multikey form. As of solid-pod-rs
/// 0.5.0-alpha.7 the upstream minimal document is fully aligned to the did:nostr
/// CG spec 0.1.1: `@context` is the three-context form (`did/v1` first, as
/// DID Core requires, then `cid/v1`, then the nostr context), and it
/// carries the canonical relative `authentication`/`assertionMethod`
/// (`["#key1"]`) and OMITS the optional members entirely — no empty `service: []`
/// (the pre-alignment shape) and no `alsoKnownAs`. The forum emits it verbatim —
/// no fragment re-pinning and no absolute-ref rewrite (the `did:nostr:<hex>`
/// string is unchanged, I1). `service`/`alsoKnownAs` appear only at Tier-3.
pub fn render_did_document_tier1(pk: &NostrPubkey) -> Value {
    upstream::render_did_document_tier1(&pk.to_upstream())
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
    governance_url: Option<&str>,
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

    if let Some(gov) = governance_url {
        services.push(upstream::ServiceEntry {
            id: format!("{did}#governance"),
            service_type: "AgentGovernance".to_string(),
            service_endpoint: gov.to_string(),
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
        // did:nostr CG 0.1.1: DID Core context leads.
        assert_eq!(doc["@context"][0], "https://www.w3.org/ns/did/v1");
        // ADR-125: canonical Multikey doc has no `alsoKnownAs` (the WebID link
        // lives in `service`, populated only at Tier-3).
        assert!(doc["alsoKnownAs"].is_null());
        let vm = &doc["verificationMethod"][0];
        // ADR-125: canonical Multikey form. publicKeyHex is dropped (D2 superseded).
        assert_eq!(vm["type"], "Multikey");
        assert!(vm.get("publicKeyHex").is_none());
        let mb = vm["publicKeyMultibase"].as_str().unwrap();
        // C1/C2/C3: f(base16-lower) + e701(secp256k1-pub) + 02(even-y) + 64-hex x-only.
        assert!(mb.starts_with("fe70102"));
        assert_eq!(mb.len(), 71);
        assert_eq!(mb, mb.to_ascii_lowercase());
        // I2 round-trip: multibase body equals the DID body equals the x-only hex.
        assert_eq!(&mb[7..], PK_HEX);
    }

    #[test]
    fn tier1_includes_authentication_and_assertion() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let doc = render_did_document_tier1(&pk);
        // ADR-125: canonical authentication/assertionMethod use the relative
        // fragment `#key1`; the VM id is the absolute `<did>#key1`.
        assert_eq!(doc["authentication"][0], "#key1");
        assert_eq!(doc["assertionMethod"][0], "#key1");
        let vm_id = doc["verificationMethod"][0]["id"].as_str().unwrap();
        assert!(vm_id.ends_with("#key1"));
    }

    #[test]
    fn tier1_context_fields() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let doc = render_did_document_tier1(&pk);
        let ctx = doc["@context"].as_array().unwrap();
        // ADR-125 §2 / did:nostr CG 0.1.1: canonical three-context form,
        // DID Core first (required by DID Core, aligned with DID 1.1).
        assert_eq!(ctx.len(), 3);
        assert_eq!(ctx[0], "https://www.w3.org/ns/did/v1");
        assert_eq!(ctx[1], "https://www.w3.org/ns/cid/v1");
        assert_eq!(ctx[2], "https://w3id.org/nostr/context");
    }

    #[test]
    fn tier1_verification_method_type_is_multikey() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let doc = render_did_document_tier1(&pk);
        let vm_type = doc["verificationMethod"][0]["type"].as_str().unwrap();
        // ADR-125: Multikey is canonical; the 2019/2022/2024 suites are superseded.
        assert_eq!(vm_type, "Multikey");
        assert_ne!(vm_type, "SchnorrSecp256k1VerificationKey2019");
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
    fn tier1_omits_service_section() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let doc = render_did_document_tier1(&pk);
        // solid-pod-rs 0.5.0-alpha.4 aligned the canonical minimal doc to the
        // did:nostr CG spec: the optional `service` member is OMITTED entirely
        // at Tier-1 (an empty `service: []` was the pre-alignment shape).
        // Entries are added only at Tier-3.
        assert!(
            doc.get("service").is_none(),
            "canonical minimal did:nostr doc must omit `service` (got {:?})",
            doc.get("service")
        );
    }

    // ── Tier-3 document ───────────────────────────────────────────────

    #[test]
    fn tier3_carries_webid_and_relay() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let webid = "https://pods.example.com/0000.../profile/card#me";
        let pod = "https://pods.example.com/0000.../";
        let relay = "wss://relay.example.com";
        let doc =
            render_did_document_tier3(&pk, Some(webid), pod, Some(relay), None, Some("Alice"));
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
        let doc = render_did_document_tier3(&pk, None, "https://pod.test/", None, None, None);
        let services = doc["service"].as_array().unwrap();
        assert_eq!(services.len(), 1);
    }

    #[test]
    fn tier3_with_governance_endpoint() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let gov = "https://auth.example.com/api/governance";
        let doc = render_did_document_tier3(&pk, None, "https://pod.test/", None, Some(gov), None);
        let services = doc["service"].as_array().unwrap();
        let types: Vec<&str> = services
            .iter()
            .map(|s| s["type"].as_str().unwrap_or(""))
            .collect();
        assert!(types.contains(&"SolidStorage"));
        assert!(types.contains(&"AgentGovernance"));
        assert_eq!(services.len(), 2);
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
    fn multibase_is_deterministic_and_canonical_multikey() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let a = format_multibase_schnorr(&pk.0);
        let b = format_multibase_schnorr(&pk.0);
        assert_eq!(a, b);
        // ADR-125 C1/C2/C3: fe70102 prefix, 71 chars, lowercase, body == x-only hex.
        assert!(a.starts_with("fe70102"));
        assert_eq!(a.len(), 71);
        assert_eq!(a, a.to_ascii_lowercase());
        assert_eq!(&a[7..], PK_HEX);
        // Missing-parity (fe701 + 64 hex, 67 chars) is the ship-bug form — must NOT match.
        assert_ne!(a.len(), 67);
    }

    // ── Parity model (nostrcg/did-nostr#145) ──────────────────────────

    /// Upstream nostrcg/did-nostr@4ea80d8,
    /// `test-vectors/test-vectors-generated.json` → `key_decoding`.
    const SPEC_X: &str = "124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2";
    const DECODE_EVEN_PARITY: &str =
        "fe70102124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2";
    const DECODE_ODD_PARITY: &str =
        "fe70103124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2";

    fn public_key_with_parity(tag: u8) -> k256::PublicKey {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        (1u8..=255)
            .map(|b| k256::SecretKey::from_slice(&[b; 32]).unwrap().public_key())
            .find(|pk| pk.to_encoded_point(true).as_bytes()[0] == tag)
            .unwrap()
    }

    #[test]
    fn decode_even_and_odd_parity_vectors() {
        for (input, parity) in [(DECODE_EVEN_PARITY, 0x02u8), (DECODE_ODD_PARITY, 0x03)] {
            assert_eq!(parse_multibase_schnorr(input).unwrap().to_hex(), SPEC_X);
            let point = parse_multibase_sec1(input).unwrap();
            use k256::elliptic_curve::sec1::ToEncodedPoint;
            assert_eq!(point.to_encoded_point(true).as_bytes()[0], parity);
            assert_eq!(format_multibase_public_key(&point), input);
        }
    }

    #[test]
    fn decoder_rejects_malformed_multikeys() {
        for bad in [
            "fe70104124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2",
            "f000102124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2",
            "FE70102124C0FA99407182ECE5A24FAD9B7F6674902FC422843D3128D38A0AFBEE0FDD2",
            "fe70102",
            "abc123",
        ] {
            assert!(parse_multibase_schnorr(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn identifier_only_document_emits_0x02_even_for_odd_key() {
        let pk = public_key_with_parity(0x03);
        let id = NostrPubkey::from_public_key(&pk);
        let doc = render_did_document_tier1(&id);
        let mb = doc["verificationMethod"][0]["publicKeyMultibase"]
            .as_str()
            .unwrap();
        assert_eq!(mb, format!("fe70102{}", id.to_hex()));
        assert_eq!(
            *id.to_even_public_key().unwrap().as_affine(),
            -*pk.as_affine()
        );
    }

    #[test]
    fn controller_published_document_carries_0x03_for_odd_key() {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let pk = public_key_with_parity(0x03);
        let id = NostrPubkey::from_public_key(&pk);
        let doc = render_did_document_published(&pk);
        assert_eq!(doc["id"], did_nostr_uri(&id));
        let mb = doc["verificationMethod"][0]["publicKeyMultibase"]
            .as_str()
            .unwrap();
        assert_eq!(mb, format!("fe70103{}", id.to_hex()));
        assert_eq!(mb.len(), MULTIKEY_LEN);
        assert_eq!(
            format_multibase_sec1(pk.to_encoded_point(true).as_bytes()).unwrap(),
            mb
        );
        assert_eq!(parse_multibase_schnorr(mb).unwrap(), id);
    }

    #[test]
    fn controller_published_document_matches_tier1_for_even_key() {
        let pk = public_key_with_parity(0x02);
        let id = NostrPubkey::from_public_key(&pk);
        assert_eq!(
            render_did_document_published(&pk),
            render_did_document_tier1(&id)
        );
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
    fn tier1_matches_upstream_canonical() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let local = render_did_document_tier1(&pk);
        let up = upstream::render_did_document_tier1(&pk.to_upstream());
        // Full delegation (alpha.4): the forum emits the upstream canonical
        // Multikey document verbatim — relative authentication/assertionMethod,
        // with the optional `service`/`alsoKnownAs` members omitted (spec-aligned
        // minimal form).
        assert_eq!(local, up);
        assert_eq!(local["authentication"][0], "#key1");
        assert!(
            local.get("service").is_none(),
            "canonical minimal did:nostr doc must omit `service`"
        );
    }
}
