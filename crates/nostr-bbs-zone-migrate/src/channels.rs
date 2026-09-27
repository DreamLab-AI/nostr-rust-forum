//! The explicit channel → zone mapping (`--channels`), and the
//! `--print-channels` listing that helps an operator write it.
//!
//! The migrator never infers a zone from a channel's `section` tag: purge is
//! destructive, so every channel it touches must be named deliberately.
//!
//! ```json
//! [{"id": "<64-hex kind-40 channel id>", "zone": "zone3"},
//!  {"id": "<64-hex kind-40 channel id>", "zone": "zone4"}]
//! ```

use std::collections::HashSet;

use nostr_bbs_core::NostrEvent;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::keys::is_hex64;

/// One channel to migrate and the zone whose key seals it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelSpec {
    /// Kind-40 channel id, lowercase 64 hex.
    pub id: String,
    /// Zone id, such as `"zone3"`.
    pub zone: String,
}

/// Why a channels file was refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChannelsError {
    /// Not a JSON array of `{"id","zone"}` objects.
    #[error("channels file is not a JSON array of {{\"id\",\"zone\"}}: {0}")]
    Json(String),
    /// The array is empty.
    #[error("channels file lists no channels")]
    Empty,
    /// A channel id is not 64 hex characters.
    #[error("channel id {0:?} is not 64 hex")]
    BadId(String),
    /// A zone is empty.
    #[error("channel {0} has an empty zone")]
    EmptyZone(String),
    /// A channel is listed twice.
    #[error("channel {0} is listed more than once")]
    Duplicate(String),
}

/// Parse and validate a channels file. Ids are lowercased.
///
/// ```
/// use nostr_bbs_zone_migrate::channels::parse_channels;
/// let json = format!(r#"[{{"id":"{}","zone":"zone3"}}]"#, "AB".repeat(32));
/// let specs = parse_channels(&json).unwrap();
/// assert_eq!(specs[0].id, "ab".repeat(32));
/// ```
pub fn parse_channels(json: &str) -> Result<Vec<ChannelSpec>, ChannelsError> {
    let mut specs: Vec<ChannelSpec> =
        serde_json::from_str(json).map_err(|e| ChannelsError::Json(e.to_string()))?;
    if specs.is_empty() {
        return Err(ChannelsError::Empty);
    }
    let mut seen = HashSet::new();
    for spec in &mut specs {
        if !is_hex64(&spec.id) {
            return Err(ChannelsError::BadId(spec.id.clone()));
        }
        spec.id.make_ascii_lowercase();
        if spec.zone.trim().is_empty() {
            return Err(ChannelsError::EmptyZone(spec.id.clone()));
        }
        if !seen.insert(spec.id.clone()) {
            return Err(ChannelsError::Duplicate(spec.id.clone()));
        }
    }
    Ok(specs)
}

/// A kind-40 channel as listed by `--print-channels`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChannelListing {
    /// Channel id.
    pub id: String,
    /// `name` from the kind-40 content, or empty.
    pub name: String,
    /// Value of the first `section` tag, or empty. Only a hint for writing the
    /// channels file; the migrator never maps sections to zones itself.
    pub section: String,
    /// Channel creation time.
    pub created_at: u64,
}

/// Describe kind-40 channel-creation events, oldest first. Other kinds are
/// ignored; the section is read the same way the forum client reads it.
pub fn list_channels(events: &[NostrEvent]) -> Vec<ChannelListing> {
    let mut out: Vec<ChannelListing> = events
        .iter()
        .filter(|ev| ev.kind == 40)
        .map(|ev| ChannelListing {
            id: ev.id.clone(),
            name: serde_json::from_str::<serde_json::Value>(&ev.content)
                .ok()
                .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(str::to_string))
                .unwrap_or_default(),
            section: ev
                .tags
                .iter()
                .find(|t| t.len() >= 2 && t[0] == "section")
                .map(|t| t[1].clone())
                .unwrap_or_default(),
            created_at: ev.created_at,
        })
        .collect();
    out.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(id: &str, zone: &str) -> String {
        format!(r#"{{"id":"{id}","zone":"{zone}"}}"#)
    }

    #[test]
    fn rejects_every_malformed_shape() {
        let a = "a".repeat(64);
        assert!(matches!(
            parse_channels("{}").unwrap_err(),
            ChannelsError::Json(_)
        ));
        assert_eq!(parse_channels("[]").unwrap_err(), ChannelsError::Empty);
        assert_eq!(
            parse_channels(&format!("[{}]", spec("abc", "zone3"))).unwrap_err(),
            ChannelsError::BadId("abc".into())
        );
        assert_eq!(
            parse_channels(&format!("[{}]", spec(&a, " "))).unwrap_err(),
            ChannelsError::EmptyZone(a.clone())
        );
        assert_eq!(
            parse_channels(&format!(
                "[{},{}]",
                spec(&a, "zone3"),
                spec(&a.to_ascii_uppercase(), "zone4")
            ))
            .unwrap_err(),
            ChannelsError::Duplicate(a.clone())
        );
        // A section field is not accepted: zones are explicit.
        assert!(matches!(
            parse_channels(&format!(
                r#"[{{"id":"{a}","zone":"zone3","section":"family"}}]"#
            ))
            .unwrap_err(),
            ChannelsError::Json(_)
        ));
    }

    #[test]
    fn lists_kind40_with_name_and_section() {
        let ev = |id: &str, kind, created_at, tags: Vec<Vec<String>>, content: &str| NostrEvent {
            id: id.into(),
            pubkey: String::new(),
            created_at,
            kind,
            tags,
            content: content.into(),
            sig: String::new(),
        };
        let listed = list_channels(&[
            ev(
                "b",
                40,
                20,
                vec![vec!["section".into(), "family".into()]],
                r#"{"name":"Kitchen"}"#,
            ),
            ev("a", 40, 10, vec![], "not json"),
            ev("x", 41, 5, vec![], r#"{"name":"meta"}"#),
        ]);
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id, "a");
        assert_eq!(listed[0].name, "");
        assert_eq!(listed[1].name, "Kitchen");
        assert_eq!(listed[1].section, "family");
    }
}
