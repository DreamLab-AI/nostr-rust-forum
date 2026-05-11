//! `did:nostr` DID Document generation — pod-worker thin re-export layer.
//!
//! All document rendering and pubkey types live in `nostr_bbs_core::did`.
//! This module re-exports the public API so existing pod-worker call sites
//! (`use crate::did::*`) continue to compile unchanged.

pub use nostr_bbs_core::did::{render_did_document_tier3, verify_webid_tag, NostrPubkey};

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_bbs_core::did::render_did_document_tier1;

    const PK_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn reexported_tier1_matches_core() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let doc = render_did_document_tier1(&pk);
        assert_eq!(doc["id"], format!("did:nostr:{PK_HEX}"));
        assert!(doc["verificationMethod"][0]["publicKeyMultibase"]
            .as_str()
            .unwrap()
            .starts_with('z'));
    }

    #[test]
    fn reexported_tier3_matches_core() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let doc = render_did_document_tier3(&pk, None, "https://pod.test/", None, None);
        assert_eq!(doc["service"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn reexported_verify_webid_tag() {
        let pk = "a".repeat(64);
        assert!(verify_webid_tag(&format!("did:nostr:{pk}"), &pk));
    }
}
