//! Bundled JSON-LD context documents — served at runtime, no HTTP fetching.
//!
//! These contexts are embedded at compile time via `include_str!`. Any
//! Solid/RDF client that requests them via their canonical IRIs gets the
//! authoritative version baked into the binary, avoiding external round-trips
//! in the WASM Worker environment.

/// FOAF (Friend of a Friend) vocabulary context.
pub const CONTEXT_FOAF: &str = include_str!("../contexts/foaf.jsonld");

/// Solid terms + LDP + PIM space context.
pub const CONTEXT_SOLID: &str = include_str!("../contexts/solid.jsonld");

/// WAC (Web Access Control) ACL vocabulary context.
pub const CONTEXT_ACL: &str = include_str!("../contexts/acl.jsonld");

/// Canonical `did:nostr` JSON-LD context (ADR-125 §2 Multikey form).
///
/// This is the single context bundle the canonical DID document references
/// in its `@context` (`https://w3id.org/did` + `https://w3id.org/nostr/context`).
/// It defines only the canonical terms — `DIDNostr`, `Multikey`,
/// `publicKeyMultibase`, controller/VM/auth/assertion/service — and
/// deliberately does NOT define the superseded `SchnorrSecp256k1VerificationKey2019`
/// suite term or `publicKeyHex` (ADR-074 D2/D3 superseded; no dual-publish).
pub const CONTEXT_DID: &str = include_str!("../contexts/did-v1.jsonld");

/// Return the bundled context body for a well-known context IRI, if we host it.
///
/// Covers the most commonly fetched contexts that Solid clients dereference.
pub fn context_for_iri(iri: &str) -> Option<(&'static str, &'static str)> {
    match iri {
        "http://xmlns.com/foaf/0.1/" | "https://xmlns.com/foaf/0.1/" => {
            Some((CONTEXT_FOAF, "application/ld+json"))
        }

        "http://www.w3.org/ns/solid/terms#"
        | "https://www.w3.org/ns/solid/terms#"
        | "http://www.w3.org/ns/ldp#" => Some((CONTEXT_SOLID, "application/ld+json")),

        "http://www.w3.org/ns/auth/acl#" | "https://www.w3.org/ns/auth/acl#" => {
            Some((CONTEXT_ACL, "application/ld+json"))
        }

        // ADR-125 §2: the canonical did:nostr document references
        // `https://w3id.org/did` and `https://w3id.org/nostr/context`. Both
        // dereference to the bundled Multikey context. The legacy
        // `did/v1` / `secp256k1-2019/v1` IRIs remain dereferenceable as
        // back-compat aliases for old resolvers, but they now serve the
        // SAME canonical Multikey body (no 2019 suite, no publicKeyHex) — the
        // 2019 shape is superseded, not dual-published.
        "https://w3id.org/did"
        | "https://w3id.org/nostr/context"
        | "https://www.w3.org/ns/did/v1"
        | "https://w3id.org/security/suites/secp256k1-2019/v1" => {
            Some((CONTEXT_DID, "application/ld+json"))
        }

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foaf_context_is_valid_json() {
        serde_json::from_str::<serde_json::Value>(CONTEXT_FOAF).unwrap();
    }

    #[test]
    fn solid_context_is_valid_json() {
        serde_json::from_str::<serde_json::Value>(CONTEXT_SOLID).unwrap();
    }

    #[test]
    fn acl_context_is_valid_json() {
        serde_json::from_str::<serde_json::Value>(CONTEXT_ACL).unwrap();
    }

    #[test]
    fn did_context_is_valid_json() {
        serde_json::from_str::<serde_json::Value>(CONTEXT_DID).unwrap();
    }

    #[test]
    fn known_iris_resolve() {
        assert!(context_for_iri("http://xmlns.com/foaf/0.1/").is_some());
        assert!(context_for_iri("http://www.w3.org/ns/auth/acl#").is_some());
        assert!(context_for_iri("https://www.w3.org/ns/did/v1").is_some());
    }

    #[test]
    fn canonical_did_nostr_iris_resolve() {
        // ADR-125 §2: the canonical document references these two IRIs.
        assert!(context_for_iri("https://w3id.org/did").is_some());
        assert!(context_for_iri("https://w3id.org/nostr/context").is_some());
    }

    #[test]
    fn legacy_2019_iri_serves_canonical_body() {
        // Back-compat: the legacy IRI still dereferences, but to the SAME
        // canonical Multikey body — never a dual-published 2019 context.
        let (legacy, _) = context_for_iri("https://w3id.org/security/suites/secp256k1-2019/v1")
            .expect("legacy IRI must still resolve");
        let (canonical, _) =
            context_for_iri("https://w3id.org/nostr/context").expect("canonical IRI must resolve");
        assert_eq!(legacy, canonical);
    }

    #[test]
    fn did_context_drops_superseded_2019_terms() {
        // ADR-125 anti-drift: the served did:nostr context MUST NOT define the
        // superseded 2019 suite term or publicKeyHex (D2/D3 superseded; no
        // dual-publish). It MUST define the canonical Multikey terms.
        let ctx: serde_json::Value = serde_json::from_str(CONTEXT_DID).unwrap();
        let terms = ctx["@context"].as_object().unwrap();
        assert!(
            !terms.contains_key("SchnorrSecp256k1VerificationKey2019"),
            "did:nostr context must not carry the superseded 2019 suite term"
        );
        assert!(
            !terms.contains_key("publicKeyHex"),
            "did:nostr context must not carry publicKeyHex (D2 superseded)"
        );
        assert!(terms.contains_key("Multikey"), "must define Multikey term");
        assert!(
            terms.contains_key("publicKeyMultibase"),
            "must define publicKeyMultibase term"
        );
        assert!(terms.contains_key("DIDNostr"), "must define DIDNostr term");
    }

    #[test]
    fn unknown_iri_returns_none() {
        assert!(context_for_iri("https://unknown.example/context").is_none());
    }
}
