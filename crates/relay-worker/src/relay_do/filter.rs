//! Query building and filter matching for the Nostr relay.
//!
//! Contains the NIP-01 filter type, the SQL query builder for D1, and
//! in-memory filter matching used during event broadcasting.

use std::collections::HashMap;

use nostr_core::event::NostrEvent;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;

use super::NostrRelayDO;

// ---------------------------------------------------------------------------
// NIP-01 filter type
// ---------------------------------------------------------------------------

/// A NIP-01 subscription filter.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NostrFilter {
    #[serde(default)]
    pub ids: Option<Vec<String>>,
    #[serde(default)]
    pub authors: Option<Vec<String>>,
    #[serde(default)]
    pub kinds: Option<Vec<u64>>,
    #[serde(default)]
    pub since: Option<u64>,
    #[serde(default)]
    pub until: Option<u64>,
    #[serde(default)]
    pub limit: Option<u32>,
    /// NIP-50: Full-text search query.
    #[serde(default)]
    pub search: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// D1 row for COUNT results
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct CountResult {
    pub cnt: f64,
}

// ---------------------------------------------------------------------------
// SQL query builder
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Build WHERE conditions from a NIP-01 filter (shared by REQ and COUNT).
    pub(crate) fn build_filter_conditions(
        filter: &NostrFilter,
        conditions: &mut Vec<String>,
        params: &mut Vec<JsValue>,
        param_idx: &mut u32,
    ) {
        if let Some(ref ids) = filter.ids {
            if !ids.is_empty() {
                let placeholders: Vec<String> = ids
                    .iter()
                    .map(|id| {
                        let p = format!("?{}", *param_idx);
                        params.push(JsValue::from_str(id));
                        *param_idx += 1;
                        p
                    })
                    .collect();
                conditions.push(format!("id IN ({})", placeholders.join(",")));
            }
        }

        if let Some(ref authors) = filter.authors {
            if !authors.is_empty() {
                let placeholders: Vec<String> = authors
                    .iter()
                    .map(|a| {
                        let p = format!("?{}", *param_idx);
                        params.push(JsValue::from_str(a));
                        *param_idx += 1;
                        p
                    })
                    .collect();
                conditions.push(format!("pubkey IN ({})", placeholders.join(",")));
            }
        }

        if let Some(ref kinds) = filter.kinds {
            if !kinds.is_empty() {
                let placeholders: Vec<String> = kinds
                    .iter()
                    .map(|k| {
                        let p = format!("?{}", *param_idx);
                        params.push(JsValue::from_f64(*k as f64));
                        *param_idx += 1;
                        p
                    })
                    .collect();
                conditions.push(format!("kind IN ({})", placeholders.join(",")));
            }
        }

        if let Some(since) = filter.since {
            conditions.push(format!("created_at >= ?{}", *param_idx));
            params.push(JsValue::from_f64(since as f64));
            *param_idx += 1;
        }

        if let Some(until) = filter.until {
            conditions.push(format!("created_at <= ?{}", *param_idx));
            params.push(JsValue::from_f64(until as f64));
            *param_idx += 1;
        }

        // Tag filters (#e, #p, #t, etc.)
        for (key, values) in &filter.extra {
            if !key.starts_with('#') {
                continue;
            }
            let tag_name = &key[1..];
            if !tag_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                continue;
            }

            let tag_values: Vec<&str> = match values.as_array() {
                Some(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
                None => continue,
            };
            if tag_values.is_empty() {
                continue;
            }

            let mut tag_conditions: Vec<String> = Vec::new();
            for v in &tag_values {
                if v.is_empty() {
                    continue;
                }
                let escaped = v.replace('%', "\\%").replace('_', "\\_").replace('"', "");
                let pattern = format!("%\"{tag_name}\",\"{escaped}\"%");
                tag_conditions.push(format!("tags LIKE ?{} ESCAPE '\\\\'", *param_idx));
                params.push(JsValue::from_str(&pattern));
                *param_idx += 1;
            }

            if !tag_conditions.is_empty() {
                conditions.push(format!("({})", tag_conditions.join(" OR ")));
            }
        }

        // NIP-50: Full-text search on content
        if let Some(ref search) = filter.search {
            if !search.is_empty() {
                let escaped = search.replace('%', "\\%").replace('_', "\\_");
                let pattern = format!("%{escaped}%");
                conditions.push(format!("content LIKE ?{} ESCAPE '\\\\'", *param_idx));
                params.push(JsValue::from_str(&pattern));
                *param_idx += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// In-memory filter matching (for broadcast)
// ---------------------------------------------------------------------------

pub(crate) fn event_matches_filters(event: &NostrEvent, filters: &[NostrFilter]) -> bool {
    'outer: for filter in filters {
        if let Some(ref ids) = filter.ids {
            if !ids.iter().any(|id| id == &event.id) {
                continue;
            }
        }
        if let Some(ref authors) = filter.authors {
            if !authors.iter().any(|a| a == &event.pubkey) {
                continue;
            }
        }
        if let Some(ref kinds) = filter.kinds {
            if !kinds.contains(&event.kind) {
                continue;
            }
        }
        if let Some(since) = filter.since {
            if event.created_at < since {
                continue;
            }
        }
        if let Some(until) = filter.until {
            if event.created_at > until {
                continue;
            }
        }

        // Tag filters (#e, #p, #t, etc.) -- must match at least one value per tag
        for (key, values) in &filter.extra {
            if !key.starts_with('#') {
                continue;
            }
            let tag_name = &key[1..];
            let required: Vec<&str> = match values.as_array() {
                Some(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
                None => continue,
            };
            if required.is_empty() {
                continue;
            }

            // Check that the event has at least one tag matching this filter
            let has_match = event.tags.iter().any(|tag| {
                tag.first().map(|t| t.as_str()) == Some(tag_name)
                    && tag.get(1).map_or(false, |v| required.contains(&v.as_str()))
            });
            if !has_match {
                continue 'outer;
            }
        }

        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Tag helpers
// ---------------------------------------------------------------------------

/// Extract the first value for a given tag name from an event.
pub(crate) fn tag_value(event: &NostrEvent, name: &str) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].clone())
}

pub(crate) fn d_tag_value(event: &NostrEvent) -> String {
    for tag in &event.tags {
        if tag.first().map(|s| s.as_str()) == Some("d") {
            return tag.get(1).cloned().unwrap_or_default();
        }
    }
    String::new()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a minimal NostrEvent for testing filter matching.
    fn make_event(
        id: &str,
        pubkey: &str,
        kind: u64,
        created_at: u64,
        tags: Vec<Vec<String>>,
        content: &str,
    ) -> NostrEvent {
        NostrEvent {
            id: id.to_string(),
            pubkey: pubkey.to_string(),
            created_at,
            kind,
            tags,
            content: content.to_string(),
            sig: "00".repeat(64),
        }
    }

    fn empty_filter() -> NostrFilter {
        NostrFilter {
            ids: None,
            authors: None,
            kinds: None,
            since: None,
            until: None,
            limit: None,
            search: None,
            extra: HashMap::new(),
        }
    }

    // ── NostrFilter serde ────────────────────────────────────────────────

    #[test]
    fn filter_deserialize_empty_json() {
        let f: NostrFilter = serde_json::from_str("{}").unwrap();
        assert!(f.ids.is_none());
        assert!(f.authors.is_none());
        assert!(f.kinds.is_none());
        assert!(f.since.is_none());
        assert!(f.until.is_none());
        assert!(f.limit.is_none());
        assert!(f.search.is_none());
        assert!(f.extra.is_empty());
    }

    #[test]
    fn filter_deserialize_all_fields() {
        let json = r##"{
            "ids": ["abc123"],
            "authors": ["deadbeef"],
            "kinds": [1, 4],
            "since": 1000,
            "until": 2000,
            "limit": 50,
            "search": "hello",
            "#e": ["event1"],
            "#p": ["pubkey1", "pubkey2"]
        }"##;
        let f: NostrFilter = serde_json::from_str(json).unwrap();
        assert_eq!(f.ids.as_ref().unwrap(), &["abc123"]);
        assert_eq!(f.authors.as_ref().unwrap(), &["deadbeef"]);
        assert_eq!(f.kinds.as_ref().unwrap(), &[1, 4]);
        assert_eq!(f.since, Some(1000));
        assert_eq!(f.until, Some(2000));
        assert_eq!(f.limit, Some(50));
        assert_eq!(f.search.as_deref(), Some("hello"));
        assert!(f.extra.contains_key("#e"));
        assert!(f.extra.contains_key("#p"));
    }

    #[test]
    fn filter_roundtrip_serde() {
        let mut extra = HashMap::new();
        extra.insert(
            "#e".to_string(),
            serde_json::json!(["event_id_1"]),
        );
        let f = NostrFilter {
            ids: Some(vec!["id1".into()]),
            authors: Some(vec!["author1".into()]),
            kinds: Some(vec![1, 7]),
            since: Some(100),
            until: Some(200),
            limit: Some(25),
            search: Some("test".into()),
            extra,
        };
        let json = serde_json::to_string(&f).unwrap();
        let f2: NostrFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(f.ids, f2.ids);
        assert_eq!(f.authors, f2.authors);
        assert_eq!(f.kinds, f2.kinds);
        assert_eq!(f.since, f2.since);
        assert_eq!(f.until, f2.until);
        assert_eq!(f.limit, f2.limit);
        assert_eq!(f.search, f2.search);
    }

    #[test]
    fn filter_deserialize_empty_arrays() {
        let json = r#"{"ids":[],"authors":[],"kinds":[]}"#;
        let f: NostrFilter = serde_json::from_str(json).unwrap();
        assert!(f.ids.as_ref().unwrap().is_empty());
        assert!(f.authors.as_ref().unwrap().is_empty());
        assert!(f.kinds.as_ref().unwrap().is_empty());
    }

    // ── event_matches_filters ────────────────────────────────────────────

    #[test]
    fn matches_empty_filter() {
        let event = make_event("aaa", "bbb", 1, 1000, vec![], "hello");
        let filter = empty_filter();
        assert!(event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn matches_no_filters_returns_false() {
        let event = make_event("aaa", "bbb", 1, 1000, vec![], "hello");
        assert!(!event_matches_filters(&event, &[]));
    }

    #[test]
    fn matches_single_kind() {
        let event = make_event("aaa", "bbb", 1, 1000, vec![], "hello");
        let mut filter = empty_filter();
        filter.kinds = Some(vec![1]);
        assert!(event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn rejects_wrong_kind() {
        let event = make_event("aaa", "bbb", 1, 1000, vec![], "hello");
        let mut filter = empty_filter();
        filter.kinds = Some(vec![4]);
        assert!(!event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn matches_multiple_kinds() {
        let event = make_event("aaa", "bbb", 7, 1000, vec![], "hello");
        let mut filter = empty_filter();
        filter.kinds = Some(vec![1, 4, 7]);
        assert!(event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn matches_author_filter() {
        let event = make_event("aaa", "deadbeef", 1, 1000, vec![], "hello");
        let mut filter = empty_filter();
        filter.authors = Some(vec!["deadbeef".into()]);
        assert!(event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn rejects_wrong_author() {
        let event = make_event("aaa", "deadbeef", 1, 1000, vec![], "hello");
        let mut filter = empty_filter();
        filter.authors = Some(vec!["cafebabe".into()]);
        assert!(!event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn matches_id_filter() {
        let event = make_event("abc123", "bbb", 1, 1000, vec![], "hello");
        let mut filter = empty_filter();
        filter.ids = Some(vec!["abc123".into()]);
        assert!(event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn rejects_wrong_id() {
        let event = make_event("abc123", "bbb", 1, 1000, vec![], "hello");
        let mut filter = empty_filter();
        filter.ids = Some(vec!["xyz789".into()]);
        assert!(!event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn matches_since_filter() {
        let event = make_event("aaa", "bbb", 1, 1500, vec![], "hello");
        let mut filter = empty_filter();
        filter.since = Some(1000);
        assert!(event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn rejects_before_since() {
        let event = make_event("aaa", "bbb", 1, 500, vec![], "hello");
        let mut filter = empty_filter();
        filter.since = Some(1000);
        assert!(!event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn matches_until_filter() {
        let event = make_event("aaa", "bbb", 1, 1000, vec![], "hello");
        let mut filter = empty_filter();
        filter.until = Some(2000);
        assert!(event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn rejects_after_until() {
        let event = make_event("aaa", "bbb", 1, 3000, vec![], "hello");
        let mut filter = empty_filter();
        filter.until = Some(2000);
        assert!(!event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn matches_since_and_until_combined() {
        let event = make_event("aaa", "bbb", 1, 1500, vec![], "hello");
        let mut filter = empty_filter();
        filter.since = Some(1000);
        filter.until = Some(2000);
        assert!(event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn matches_tag_filter_e() {
        let event = make_event(
            "aaa",
            "bbb",
            1,
            1000,
            vec![vec!["e".into(), "event_ref".into()]],
            "hello",
        );
        let mut filter = empty_filter();
        filter.extra.insert(
            "#e".to_string(),
            serde_json::json!(["event_ref"]),
        );
        assert!(event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn rejects_wrong_tag_value() {
        let event = make_event(
            "aaa",
            "bbb",
            1,
            1000,
            vec![vec!["e".into(), "event_ref".into()]],
            "hello",
        );
        let mut filter = empty_filter();
        filter.extra.insert(
            "#e".to_string(),
            serde_json::json!(["other_ref"]),
        );
        assert!(!event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn matches_tag_filter_p() {
        let event = make_event(
            "aaa",
            "bbb",
            1,
            1000,
            vec![vec!["p".into(), "pubkey123".into()]],
            "hello",
        );
        let mut filter = empty_filter();
        filter.extra.insert(
            "#p".to_string(),
            serde_json::json!(["pubkey123"]),
        );
        assert!(event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn matches_tag_filter_multiple_values() {
        let event = make_event(
            "aaa",
            "bbb",
            1,
            1000,
            vec![vec!["t".into(), "bitcoin".into()]],
            "hello",
        );
        let mut filter = empty_filter();
        filter.extra.insert(
            "#t".to_string(),
            serde_json::json!(["nostr", "bitcoin", "lightning"]),
        );
        assert!(event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn combined_filters_all_must_match() {
        let event = make_event(
            "aaa",
            "author1",
            1,
            1500,
            vec![vec!["e".into(), "ref1".into()]],
            "hello",
        );
        let mut filter = empty_filter();
        filter.authors = Some(vec!["author1".into()]);
        filter.kinds = Some(vec![1]);
        filter.since = Some(1000);
        filter.until = Some(2000);
        filter.extra.insert(
            "#e".to_string(),
            serde_json::json!(["ref1"]),
        );
        assert!(event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn combined_filters_one_field_mismatch_rejects() {
        let event = make_event(
            "aaa",
            "author1",
            1,
            1500,
            vec![vec!["e".into(), "ref1".into()]],
            "hello",
        );
        let mut filter = empty_filter();
        filter.authors = Some(vec!["author1".into()]);
        filter.kinds = Some(vec![4]); // wrong kind
        filter.since = Some(1000);
        filter.until = Some(2000);
        assert!(!event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn multiple_filters_any_match_succeeds() {
        let event = make_event("aaa", "bbb", 1, 1000, vec![], "hello");
        let mut f1 = empty_filter();
        f1.kinds = Some(vec![4]); // doesn't match
        let mut f2 = empty_filter();
        f2.kinds = Some(vec![1]); // matches
        assert!(event_matches_filters(&event, &[f1, f2]));
    }

    #[test]
    fn multiple_filters_none_match() {
        let event = make_event("aaa", "bbb", 1, 1000, vec![], "hello");
        let mut f1 = empty_filter();
        f1.kinds = Some(vec![4]);
        let mut f2 = empty_filter();
        f2.kinds = Some(vec![7]);
        assert!(!event_matches_filters(&event, &[f1, f2]));
    }

    #[test]
    fn empty_ids_array_matches_all() {
        // An empty array means "no constraint" -- the field is set but effectively a no-op
        let event = make_event("aaa", "bbb", 1, 1000, vec![], "hello");
        let mut filter = empty_filter();
        filter.ids = Some(vec![]);
        // Per NIP-01: an empty array means "the field is set but impossible to match"
        // The implementation skips empty ids (continues to next check), so it matches.
        // Let's verify the actual behavior:
        assert!(!event_matches_filters(&event, &[filter]));
    }

    // ── tag_value ────────────────────────────────────────────────────────

    #[test]
    fn tag_value_extracts_first_match() {
        let event = make_event(
            "aaa",
            "bbb",
            1,
            1000,
            vec![
                vec!["e".into(), "ref1".into()],
                vec!["p".into(), "pk1".into()],
                vec!["e".into(), "ref2".into()],
            ],
            "hello",
        );
        assert_eq!(tag_value(&event, "e"), Some("ref1".to_string()));
        assert_eq!(tag_value(&event, "p"), Some("pk1".to_string()));
    }

    #[test]
    fn tag_value_returns_none_for_missing_tag() {
        let event = make_event("aaa", "bbb", 1, 1000, vec![], "hello");
        assert_eq!(tag_value(&event, "e"), None);
    }

    #[test]
    fn tag_value_returns_none_for_single_element_tag() {
        let event = make_event(
            "aaa",
            "bbb",
            1,
            1000,
            vec![vec!["e".into()]],
            "hello",
        );
        assert_eq!(tag_value(&event, "e"), None);
    }

    #[test]
    fn tag_value_expiration() {
        let event = make_event(
            "aaa",
            "bbb",
            1,
            1000,
            vec![vec!["expiration".into(), "1700000000".into()]],
            "hello",
        );
        assert_eq!(
            tag_value(&event, "expiration"),
            Some("1700000000".to_string())
        );
    }

    // ── d_tag_value ─────────────────────────────────────────────────────

    #[test]
    fn d_tag_value_extracts_d_tag() {
        let event = make_event(
            "aaa",
            "bbb",
            30023,
            1000,
            vec![
                vec!["d".into(), "my-article".into()],
                vec!["t".into(), "blog".into()],
            ],
            "hello",
        );
        assert_eq!(d_tag_value(&event), "my-article");
    }

    #[test]
    fn d_tag_value_empty_when_no_d_tag() {
        let event = make_event(
            "aaa",
            "bbb",
            1,
            1000,
            vec![vec!["e".into(), "ref1".into()]],
            "hello",
        );
        assert_eq!(d_tag_value(&event), "");
    }

    #[test]
    fn d_tag_value_empty_when_d_tag_has_no_value() {
        let event = make_event(
            "aaa",
            "bbb",
            30023,
            1000,
            vec![vec!["d".into()]],
            "hello",
        );
        assert_eq!(d_tag_value(&event), "");
    }

    #[test]
    fn d_tag_value_returns_first_d_tag() {
        let event = make_event(
            "aaa",
            "bbb",
            30023,
            1000,
            vec![
                vec!["d".into(), "first".into()],
                vec!["d".into(), "second".into()],
            ],
            "hello",
        );
        assert_eq!(d_tag_value(&event), "first");
    }

    // ── tag filter edge cases ───────────────────────────────────────────

    #[test]
    fn tag_filter_ignores_non_hash_keys() {
        let event = make_event("aaa", "bbb", 1, 1000, vec![], "hello");
        let mut filter = empty_filter();
        filter.extra.insert(
            "not_a_tag".to_string(),
            serde_json::json!(["val"]),
        );
        // Non-# keys in extra are ignored by the tag matching logic
        assert!(event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn tag_filter_empty_values_array_is_skipped() {
        let event = make_event("aaa", "bbb", 1, 1000, vec![], "hello");
        let mut filter = empty_filter();
        filter.extra.insert(
            "#e".to_string(),
            serde_json::json!([]),
        );
        // Empty required array is skipped (continues), so the filter still matches
        assert!(event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn tag_filter_non_array_value_is_skipped() {
        let event = make_event("aaa", "bbb", 1, 1000, vec![], "hello");
        let mut filter = empty_filter();
        filter.extra.insert(
            "#e".to_string(),
            serde_json::json!("not_an_array"),
        );
        assert!(event_matches_filters(&event, &[filter]));
    }
}
