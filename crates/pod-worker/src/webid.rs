//! WebID profile document generation.
//!
//! Produces an HTML page with embedded JSON-LD that serves as a Solid
//! WebID profile for a Nostr BBS user identified by their Nostr pubkey.

/// Generate a WebID profile document as HTML with embedded JSON-LD.
///
/// The document conforms to the Solid WebID profile spec and links the
/// Nostr DID identity to the user's pod.
pub fn generate_webid_html(pubkey: &str, name: Option<&str>, pod_base: &str) -> String {
    let display_name = name.unwrap_or("Nostr BBS User");
    let pod_url = format!("{pod_base}/pods/{pubkey}/");
    let webid = format!("{pod_base}/pods/{pubkey}/profile/card#me");

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{display_name} - Nostr BBS</title>
  <script type="application/ld+json">
  {{
    "@context": {{
      "foaf": "http://xmlns.com/foaf/0.1/",
      "solid": "http://www.w3.org/ns/solid/terms#",
      "schema": "http://schema.org/"
    }},
    "@id": "{webid}",
    "@type": "foaf:Person",
    "foaf:name": "{display_name}",
    "solid:account": "{pod_url}",
    "solid:privateTypeIndex": "{pod_url}settings/privateTypeIndex",
    "solid:publicTypeIndex": "{pod_url}settings/publicTypeIndex",
    "schema:identifier": "did:nostr:{pubkey}"
  }}
  </script>
</head>
<body>
  <h1>{display_name}</h1>
  <p>WebID: <a href="{webid}">{webid}</a></p>
  <p>Pod: <a href="{pod_url}">{pod_url}</a></p>
</body>
</html>"#
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webid_contains_pubkey() {
        let html = generate_webid_html("abc123", None, "https://pods.example.com");
        assert!(html.contains("abc123"));
        assert!(html.contains("did:nostr:abc123"));
        assert!(html.contains("Nostr BBS User"));
    }

    #[test]
    fn webid_uses_custom_name() {
        let html = generate_webid_html("abc123", Some("Alice"), "https://pods.example.com");
        assert!(html.contains("Alice"));
        assert!(!html.contains("Nostr BBS User"));
    }

    #[test]
    fn webid_contains_solid_links() {
        let html = generate_webid_html("abc123", None, "https://pods.example.com");
        assert!(html.contains("solid:account"));
        assert!(html.contains("solid:privateTypeIndex"));
        assert!(html.contains("solid:publicTypeIndex"));
        assert!(html.contains("profile/card#me"));
    }

    #[test]
    fn webid_is_valid_html() {
        let html = generate_webid_html("abc123", None, "https://pods.example.com");
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("</html>"));
        assert!(html.contains("application/ld+json"));
    }
}
