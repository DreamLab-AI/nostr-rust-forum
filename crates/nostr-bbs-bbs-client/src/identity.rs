//! `did:nostr` identity + Solid pod / WebID URLs.
//!
//! Derived entirely from the kit's `nostr_bbs_core::did` (which delegates to the
//! canonical `solid_pod_rs` DID renderer) and `solid_pod_rs::webid`, so the BBS
//! surfaces the SAME identity + pod infrastructure as the main forum client —
//! no hand-rolled `did:`/pod URL formatting.

use nostr_bbs_core::{did_nostr_uri, is_valid_hex_pubkey, well_known_path, NostrPubkey};
use solid_pod_rs::webid::{pod_git_clone_url, webid_url};

/// A resolved viewer identity and its Solid pod surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// 64-char lowercase hex pubkey.
    pub pubkey_hex: String,
    /// `did:nostr:<hex>` URI.
    pub did: String,
    /// Solid WebID URL on the pod (`<pod>/<hex>/profile/card#me`-style).
    pub webid: String,
    /// `git clone`-able pod-git URL.
    pub git_clone: String,
    /// Path at which the DID document is served.
    pub did_doc_path: String,
}

impl Identity {
    /// Derive identity + pod URLs from a hex pubkey and the pod API base.
    /// Returns `None` for a malformed pubkey (fail closed — no partial identity).
    pub fn derive(pubkey_hex: &str, pod_api: &str) -> Option<Identity> {
        if !is_valid_hex_pubkey(pubkey_hex) {
            return None;
        }
        let pk = NostrPubkey::from_hex(pubkey_hex).ok()?;
        let hex = pubkey_hex.to_ascii_lowercase();
        Some(Identity {
            did: did_nostr_uri(&pk),
            webid: webid_url(pod_api, &hex),
            git_clone: pod_git_clone_url(pod_api, &hex),
            did_doc_path: well_known_path(&pk),
            pubkey_hex: hex,
        })
    }

    /// A short, BBS-friendly handle (`#abcd…wxyz`) for list rows.
    pub fn short(&self) -> String {
        let h = &self.pubkey_hex;
        if h.len() >= 12 {
            format!("#{}…{}", &h[..4], &h[h.len() - 4..])
        } else {
            format!("#{h}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn derive_rejects_bad_pubkey() {
        assert!(Identity::derive("not-hex", "https://pods.example.com").is_none());
        assert!(Identity::derive("abc", "https://pods.example.com").is_none());
    }

    #[test]
    fn derive_produces_did_and_pod_urls() {
        let id = Identity::derive(PK, "https://pods.example.com").expect("valid");
        assert!(id.did.starts_with("did:nostr:"));
        assert!(id.did.contains(PK));
        assert!(id.webid.contains(PK));
        assert!(id.git_clone.contains(PK));
    }

    #[test]
    fn short_handle_is_elided() {
        let id = Identity::derive(PK, "https://p").expect("valid");
        assert_eq!(id.short(), "#0000…0001");
    }
}
