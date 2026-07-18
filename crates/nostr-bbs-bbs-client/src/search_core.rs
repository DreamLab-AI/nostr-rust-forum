//! Pure logic for BBS global search (F11) — query parsing, request-body
//! building, response parsing, ranking, and match/formatting helpers.
//!
//! This module has NO Leptos / web-sys / wasm dependency (only `std`, `serde`
//! and `serde_json`) so it is unit-testable on the native target. The Leptos
//! search overlay in `search.rs` (`#[path = "search_core.rs"] pub mod core;`)
//! renders on top of these functions.
//!
//! Shape of the search-worker responses parsed here mirrors the forum client's
//! `utils/search_client.rs` / `components/global_search.rs` (origin: those two
//! files) — the worker replies `{"results":[{"id","score","content","label"}]}`.

use std::collections::HashSet;

use serde::Deserialize;

/// One raw hit as returned by the search-worker `/search` endpoint. Every field
/// is optional/defaulted so a partial or legacy response never fails parsing.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct RawHit {
    /// The matching event id (kind-42 message). May be empty in a malformed row.
    #[serde(default)]
    pub id: String,
    /// Similarity score in `[0,1]` for a semantic match; absent for a plain
    /// keyword match.
    #[serde(default)]
    pub score: Option<f64>,
    /// The message body, when the worker inlines it (otherwise hydrated later).
    #[serde(default)]
    pub content: Option<String>,
    /// The author label / pubkey, when present.
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Deserialize)]
struct RawResp {
    #[serde(default)]
    results: Vec<RawHit>,
}

/// Parse a search-worker `/search` JSON response into hits.
///
/// Returns a *friendly* error string (never a serde dump) on malformed JSON, so
/// callers can surface it verbatim in the phosphor overlay. Hits with an empty
/// id are dropped (they cannot be opened).
pub fn parse_results(json: &str) -> Result<Vec<RawHit>, String> {
    let resp: RawResp =
        serde_json::from_str(json).map_err(|_| "could not read search results".to_string())?;
    Ok(resp
        .results
        .into_iter()
        .filter(|h| !h.id.trim().is_empty())
        .collect())
}

/// Build the JSON request body for the worker `/search` endpoint. Uses
/// `serde_json` so the query is always correctly escaped.
pub fn build_search_body(query: &str, limit: usize) -> String {
    serde_json::json!({ "query": query.trim(), "limit": limit }).to_string()
}

/// Numeric sort key for a hit — an absent score ranks below any real score.
fn score_key(h: &RawHit) -> f64 {
    h.score.unwrap_or(-1.0)
}

/// Rank hits by descending score (unscored last, keeping their relative order)
/// and drop duplicate ids, keeping the first (highest-ranked) occurrence.
pub fn rank_and_dedup(mut hits: Vec<RawHit>) -> Vec<RawHit> {
    hits.sort_by(|a, b| {
        score_key(b)
            .partial_cmp(&score_key(a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut seen: HashSet<String> = HashSet::new();
    hits.into_iter()
        .filter(|h| !h.id.trim().is_empty() && seen.insert(h.id.clone()))
        .collect()
}

/// Format a `[0,1]` similarity score as a whole-percent chip, e.g. `83%`.
pub fn format_score(score: f64) -> String {
    format!("{:.0}%", score.clamp(0.0, 1.0) * 100.0)
}

/// Char-safe title truncation: never splits a multi-byte char (the forum
/// client's byte-slice `&content[..77]` can panic on UTF-8 — this cannot).
/// Collapses internal newlines to spaces so a title stays one line.
pub fn truncate_title(s: &str, max: usize) -> String {
    let one_line = s.trim().replace(['\n', '\r'], " ");
    let count = one_line.chars().count();
    if count <= max {
        return one_line;
    }
    let keep = max.saturating_sub(1).max(1);
    let head: String = one_line.chars().take(keep).collect();
    format!("{head}\u{2026}")
}

/// Case-insensitive substring match used for LOCAL board / member / message
/// filtering. An empty (or whitespace-only) query never matches.
pub fn name_matches(haystack: &str, query: &str) -> bool {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return false;
    }
    haystack.to_lowercase().contains(&q)
}

/// Recognise a `/search <q>` (or `find <q>`) command line (the leading `/` is
/// already stripped by the command line; tolerated here anyway). Returns the
/// trimmed query (possibly empty, meaning "open with no prefill"), or `None`
/// when the line is not a search command.
///
/// Kept pure + here so the shared `menu.rs` / `chrome.rs` command path (which
/// the integrator wires) reuses exactly one, tested, parser.
pub fn parse_search_command(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let trimmed = trimmed.strip_prefix('/').unwrap_or(trimmed);
    let mut it = trimmed.splitn(2, char::is_whitespace);
    let word = it.next()?.to_ascii_lowercase();
    if word == "search" || word == "find" {
        Some(it.next().unwrap_or("").trim().to_string())
    } else {
        None
    }
}

/// The friendly empty/failure copy for the overlay body — never a raw error.
/// `worker_ok` distinguishes "nothing matched" from "search service down".
pub fn empty_state_message(query: &str, worker_ok: bool) -> String {
    let q = query.trim();
    if q.is_empty() {
        return "Type to search boards, members and messages.".to_string();
    }
    if worker_ok {
        format!("No matches for \u{201c}{q}\u{201d} yet.")
    } else {
        format!(
            "No local matches for \u{201c}{q}\u{201d}. The search service is unreachable, so \
             deeper message search is offline."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_results_reads_full_and_partial_rows() {
        let json = r#"{"results":[
            {"id":"aaa","score":0.91,"content":"hello","label":"npub1"},
            {"id":"bbb"},
            {"id":"","score":0.5}
        ]}"#;
        let hits = parse_results(json).unwrap();
        // The empty-id row is dropped; the other two survive.
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].id, "aaa");
        assert_eq!(hits[0].score, Some(0.91));
        assert_eq!(hits[0].content.as_deref(), Some("hello"));
        assert_eq!(hits[1].id, "bbb");
        assert_eq!(hits[1].score, None);
        assert_eq!(hits[1].content, None);
    }

    #[test]
    fn parse_results_empty_and_malformed() {
        assert!(parse_results(r#"{"results":[]}"#).unwrap().is_empty());
        // Missing `results` key still parses to empty (serde default).
        assert!(parse_results(r#"{}"#).unwrap().is_empty());
        // Not JSON → friendly error, never a serde dump.
        let err = parse_results("<html>502</html>").unwrap_err();
        assert_eq!(err, "could not read search results");
    }

    #[test]
    fn build_search_body_escapes_query() {
        let body = build_search_body("  a\"b  ", 10);
        // Trimmed and quote-escaped by serde_json.
        assert!(body.contains(r#""query":"a\"b""#), "body was {body}");
        assert!(body.contains(r#""limit":10"#));
    }

    #[test]
    fn rank_and_dedup_orders_and_dedups() {
        let hits = vec![
            RawHit {
                id: "a".into(),
                score: Some(0.2),
                content: None,
                label: None,
            },
            RawHit {
                id: "b".into(),
                score: Some(0.9),
                content: None,
                label: None,
            },
            RawHit {
                id: "a".into(),
                score: Some(0.95),
                content: None,
                label: None,
            },
            RawHit {
                id: "c".into(),
                score: None,
                content: None,
                label: None,
            },
        ];
        let ranked = rank_and_dedup(hits);
        // Highest score first; unscored last; duplicate `a` collapsed to one,
        // keeping the higher-scored occurrence (0.95 sorts above b's 0.9).
        assert_eq!(ranked.len(), 3);
        assert_eq!(ranked[0].id, "a");
        assert_eq!(ranked[0].score, Some(0.95));
        assert_eq!(ranked[1].id, "b");
        assert_eq!(ranked[2].id, "c");
    }

    #[test]
    fn format_score_clamps_and_rounds() {
        assert_eq!(format_score(0.834), "83%");
        assert_eq!(format_score(1.5), "100%");
        assert_eq!(format_score(-0.2), "0%");
    }

    #[test]
    fn truncate_title_is_char_safe() {
        assert_eq!(truncate_title("  hello  ", 40), "hello");
        assert_eq!(truncate_title("line1\nline2", 40), "line1 line2");
        // Multi-byte: must not panic and must keep whole chars.
        let s = "café société généralité extra long text here";
        let t = truncate_title(s, 10);
        assert_eq!(t.chars().count(), 10);
        assert!(t.ends_with('\u{2026}'));
        // Pure ASCII truncation boundary.
        assert_eq!(truncate_title("abcdefghij", 5), "abcd\u{2026}");
    }

    #[test]
    fn name_matches_is_case_insensitive_and_rejects_empty() {
        assert!(name_matches("Fairfield Events", "fairfield"));
        assert!(name_matches("Fairfield Events", "EVENTS"));
        assert!(!name_matches("Fairfield Events", "sydney"));
        assert!(!name_matches("anything", "   "));
        assert!(!name_matches("anything", ""));
    }

    #[test]
    fn parse_search_command_variants() {
        assert_eq!(parse_search_command("search hello"), Some("hello".into()));
        assert_eq!(
            parse_search_command("/search  hello world "),
            Some("hello world".into())
        );
        assert_eq!(parse_search_command("FIND thing"), Some("thing".into()));
        assert_eq!(parse_search_command("search"), Some(String::new()));
        assert_eq!(parse_search_command("/search"), Some(String::new()));
        // Not a search command.
        assert_eq!(parse_search_command("boards"), None);
        assert_eq!(parse_search_command("s"), None);
        assert_eq!(parse_search_command(""), None);
        assert_eq!(parse_search_command("searchable"), None);
    }

    #[test]
    fn empty_state_message_distinguishes_offline() {
        assert_eq!(
            empty_state_message("", true),
            "Type to search boards, members and messages."
        );
        assert!(empty_state_message("qq", true).contains("No matches"));
        let off = empty_state_message("qq", false);
        assert!(off.contains("search service is unreachable"));
    }
}
