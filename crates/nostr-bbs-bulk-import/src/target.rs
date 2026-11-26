//! The deployment target: the URLs that get EMBEDDED in signed data.
//!
//! `target.json`:
//!
//! ```json
//! {"name": "production", "pod": {"http": "https://pods.example.org"}}
//! ```
//!
//! Signed content embeds the pod URL of every image, and sealing freezes
//! it, so the target is chosen before the build and recorded in the state
//! directory ([`crate::d1::RunBinding`]); a build for another target into
//! the same state is refused. Relay hints in tags are always empty (the
//! client's own shape), so no relay URL is signed. Nothing here is ever
//! contacted: the tool makes no network calls.

use serde::{Deserialize, Serialize};

use crate::error::ImportError;

/// The pod part of a target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PodTarget {
    /// Pod worker base URL (`https://…`), no trailing slash.
    pub http: String,
}

/// `target.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// Lowercase name (`pilot`, `production`).
    pub name: String,
    /// Pod endpoint embedded in image URLs.
    pub pod: PodTarget,
}

impl Target {
    /// Parse and check `target.json`: a lowercase name, an `http(s)` pod
    /// URL without credentials, query or fragment.
    pub fn parse(bytes: &[u8]) -> Result<Self, ImportError> {
        let mut t: Target = serde_json::from_slice(bytes)
            .map_err(|e| ImportError::Format(format!("target.json: {e}")))?;
        if t.name.is_empty()
            || !t
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(ImportError::Format(
                "target.json: name must be [a-z0-9-]+".into(),
            ));
        }
        let u = url::Url::parse(&t.pod.http)
            .map_err(|e| ImportError::Format(format!("target.json pod.http: {e}")))?;
        if !matches!(u.scheme(), "http" | "https")
            || !u.username().is_empty()
            || u.password().is_some()
            || u.query().is_some()
            || u.fragment().is_some()
            || u.host_str().is_none()
        {
            return Err(ImportError::Format(
                "target.json pod.http must be a plain http(s) URL".into(),
            ));
        }
        t.pod.http = t.pod.http.trim_end_matches('/').to_string();
        Ok(t)
    }

    /// `<pod>/pods/<owner>/media/zones/<zone>/<name>`: where a zone image
    /// is served (pod zone ACL: members of the zone only).
    pub fn zone_media_url(&self, owner_pk: &str, zone: &str, name: &str) -> String {
        format!(
            "{}/pods/{owner_pk}/media/zones/{zone}/{name}",
            self.pod.http
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_refuses() {
        let t =
            Target::parse(br#"{"name":"prod","pod":{"http":"https://pod.example.org/"}}"#).unwrap();
        assert_eq!(
            t.zone_media_url("ab", "zone2", "x.webp"),
            "https://pod.example.org/pods/ab/media/zones/zone2/x.webp"
        );
        assert!(Target::parse(br#"{"name":"Prod","pod":{"http":"https://p"}}"#).is_err());
        assert!(Target::parse(br#"{"name":"p","pod":{"http":"https://u:pw@p"}}"#).is_err());
        assert!(Target::parse(br#"{"name":"p","pod":{"http":"ftp://p"}}"#).is_err());
        assert!(Target::parse(br#"{"name":"p","pod":{"http":"https://p"},"x":1}"#).is_err());
    }
}
