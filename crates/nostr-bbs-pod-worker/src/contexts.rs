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

/// W3C DID Core v1 context extended with did:nostr types.
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

        "https://www.w3.org/ns/did/v1" | "https://w3id.org/security/suites/secp256k1-2019/v1" => {
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
    fn unknown_iri_returns_none() {
        assert!(context_for_iri("https://unknown.example/context").is_none());
    }
}
