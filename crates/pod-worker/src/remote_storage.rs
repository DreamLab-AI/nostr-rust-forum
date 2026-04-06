//! remoteStorage protocol compatibility layer.
//!
//! Maps remoteStorage requests to the existing Solid pod storage.
//! @see https://tools.ietf.org/html/draft-dejong-remotestorage-22

use serde_json::json;

/// Generate a WebFinger response for remoteStorage discovery.
/// Called when `GET /.well-known/webfinger?resource=acct:{pubkey}@{host}` is requested.
pub fn webfinger_response(pubkey: &str, host: &str, pod_base: &str) -> serde_json::Value {
    json!({
        "subject": format!("acct:{pubkey}@{host}"),
        "links": [
            {
                "rel": "http://tools.ietf.org/id/draft-dejong-remotestorage",
                "href": format!("{pod_base}/pods/{pubkey}/"),
                "type": "https://www.w3.org/ns/solid/terms#storage",
                "properties": {
                    "http://remotestorage.io/spec/version": "draft-dejong-remotestorage-22",
                    "http://tools.ietf.org/html/rfc6749#section-4.2": format!("{pod_base}/oauth/{pubkey}")
                }
            },
            {
                "rel": "http://www.w3.org/ns/solid/terms#storage",
                "href": format!("{pod_base}/pods/{pubkey}/")
            },
            {
                "rel": "self",
                "type": "application/activity+json",
                "href": format!("{pod_base}/pods/{pubkey}/profile/card")
            }
        ]
    })
}

/// Parse a WebFinger resource parameter to extract pubkey.
/// Accepts: `acct:{pubkey}@{host}` or `did:nostr:{pubkey}`
pub fn parse_webfinger_resource(resource: &str) -> Option<String> {
    if let Some(rest) = resource.strip_prefix("acct:") {
        // acct:pubkey@host
        rest.split('@')
            .next()
            .filter(|pk| pk.len() == 64 && pk.bytes().all(|b| b.is_ascii_hexdigit()))
            .map(|s| s.to_string())
    } else if let Some(pk) = resource.strip_prefix("did:nostr:") {
        if pk.len() == 64 && pk.bytes().all(|b| b.is_ascii_hexdigit()) {
            Some(pk.to_string())
        } else {
            None
        }
    } else {
        None
    }
}

/// Generate a Solid storage discovery document.
/// Response for `GET /.well-known/solid`
pub fn solid_discovery(pod_base: &str) -> serde_json::Value {
    json!({
        "@context": "http://www.w3.org/ns/solid/terms#",
        "server": "Nostr BBS Pod Worker",
        "version": "6.0.0",
        "runtime": "workers-rs",
        "features": [
            "ldp-basic-container",
            "wac",
            "json-patch",
            "conditional-requests",
            "range-requests",
            "quota",
            "webid",
            "content-negotiation",
            "remote-storage"
        ],
        "apiBase": format!("{pod_base}/pods/"),
        "spec": "https://solidproject.org/TR/protocol"
    })
}

/// Generate a Nostr-compatible `.well-known/nostr.json` for NIP-05 verification.
pub fn nostr_json(pubkey: &str, name: &str) -> serde_json::Value {
    json!({
        "names": {
            name: pubkey
        },
        "relays": {}
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_acct_resource() {
        let pk = "a".repeat(64);
        let resource = format!("acct:{pk}@your-domain.com");
        assert_eq!(parse_webfinger_resource(&resource), Some(pk));
    }

    #[test]
    fn parse_did_resource() {
        let pk = "b".repeat(64);
        let resource = format!("did:nostr:{pk}");
        assert_eq!(parse_webfinger_resource(&resource), Some(pk));
    }

    #[test]
    fn parse_invalid_resource() {
        assert_eq!(parse_webfinger_resource("mailto:user@example.com"), None);
        assert_eq!(parse_webfinger_resource("acct:short@host"), None);
        assert_eq!(parse_webfinger_resource(""), None);
    }

    #[test]
    fn parse_acct_missing_at_sign() {
        // acct: prefix but no @ — still extracts the first segment before @
        // In this case the whole remainder is the "pubkey" but it's not 64 hex chars
        assert_eq!(parse_webfinger_resource("acct:nohostpart"), None);
    }

    #[test]
    fn parse_did_wrong_length() {
        let pk = "a".repeat(32);
        let resource = format!("did:nostr:{pk}");
        assert_eq!(parse_webfinger_resource(&resource), None);
    }

    #[test]
    fn parse_did_non_hex() {
        let pk = "g".repeat(64);
        let resource = format!("did:nostr:{pk}");
        assert_eq!(parse_webfinger_resource(&resource), None);
    }

    #[test]
    fn webfinger_has_remote_storage_link() {
        let pk = "c".repeat(64);
        let resp = webfinger_response(&pk, "your-domain.com", "https://pods.example.com");
        let links = resp["links"].as_array().unwrap();
        assert!(links
            .iter()
            .any(|l| l["rel"] == "http://tools.ietf.org/id/draft-dejong-remotestorage"));
    }

    #[test]
    fn webfinger_has_solid_storage_link() {
        let pk = "d".repeat(64);
        let resp = webfinger_response(&pk, "your-domain.com", "https://pods.example.com");
        let links = resp["links"].as_array().unwrap();
        assert!(links
            .iter()
            .any(|l| l["rel"] == "http://www.w3.org/ns/solid/terms#storage"));
    }

    #[test]
    fn webfinger_has_activity_json_link() {
        let pk = "d".repeat(64);
        let resp = webfinger_response(&pk, "your-domain.com", "https://pods.example.com");
        let links = resp["links"].as_array().unwrap();
        assert!(links.iter().any(|l| l["rel"] == "self"
            && l["type"] == "application/activity+json"));
    }

    #[test]
    fn webfinger_subject_format() {
        let pk = "f".repeat(64);
        let resp = webfinger_response(&pk, "example.com", "https://pods.example.com");
        assert_eq!(resp["subject"], format!("acct:{pk}@example.com"));
    }

    #[test]
    fn solid_discovery_has_features() {
        let resp = solid_discovery("https://pods.example.com");
        let features = resp["features"].as_array().unwrap();
        assert!(features.len() >= 5);
        // Ensure remote-storage is listed
        assert!(features
            .iter()
            .any(|f| f.as_str() == Some("remote-storage")));
    }

    #[test]
    fn solid_discovery_has_api_base() {
        let resp = solid_discovery("https://pods.example.com");
        assert_eq!(
            resp["apiBase"],
            "https://pods.example.com/pods/"
        );
    }

    #[test]
    fn nostr_json_format() {
        let pk = "e".repeat(64);
        let resp = nostr_json(&pk, "alice");
        assert_eq!(resp["names"]["alice"], pk);
        assert!(resp["relays"].is_object());
    }
}
