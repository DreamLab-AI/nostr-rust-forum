//! WebID profile document generation.
//!
//! Phase 4 absorption (ADR-076/078): the WebID HTML+JSON-LD generator
//! lives in `solid-pod-rs::webid::generate_webid_html` and is wired in
//! via the `core` feature so this CF Workers crate compiles to wasm32
//! without dragging tokio/reqwest. The local hand-roll (87 LOC) was
//! deleted in commit `<TBD>` of the Phase 4 chain.
//!
//! This module remains as a thin shim so existing call-sites
//! (`crate::webid::generate_webid_html`) keep working without churn.

pub use solid_pod_rs::webid::generate_webid_html;

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
