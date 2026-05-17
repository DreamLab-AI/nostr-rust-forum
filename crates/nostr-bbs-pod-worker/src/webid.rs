//! WebID profile document generation + per-user pod URL builders.
//!
//! Phase 4 absorption (ADR-076/078): the WebID HTML+JSON-LD generator
//! lives in `solid-pod-rs::webid::generate_webid_html` and is wired in
//! via the `core` feature so this CF Workers crate compiles to wasm32
//! without dragging tokio/reqwest.
//!
//! This module is the **inheritance seam** for the nostr-bbs ecosystem:
//! anything URL-shaped that the relay/auth/pod workers and the
//! forum-client all need is re-exported from solid-pod-rs here so
//! downstream crates depend on `nostr-bbs-pod-worker::webid::*` rather
//! than reaching into solid-pod-rs themselves.

pub use solid_pod_rs::webid::{
    generate_webid_html,
    pod_git_clone_url,
    pod_root_url,
    webid_document_url,
    webid_url,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webid_contains_pubkey() {
        let html = generate_webid_html("abc123", None, "https://pods.example.com");
        assert!(html.contains("abc123"));
        assert!(html.contains("did:nostr:abc123") || html.contains("nostr:abc123"));
    }

    #[test]
    fn webid_uses_custom_name() {
        let html = generate_webid_html("abc123", Some("Alice"), "https://pods.example.com");
        assert!(html.contains("Alice"));
    }

    #[test]
    fn webid_is_valid_html() {
        let html = generate_webid_html("abc123", None, "https://pods.example.com");
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("</html>"));
        assert!(html.contains("application/ld+json"));
    }
}
