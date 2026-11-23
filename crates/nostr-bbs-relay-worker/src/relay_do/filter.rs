//! Query building and filter matching for the Nostr relay.
//!
//! Contains the NIP-01 filter type, the SQL query builder for D1, and
//! in-memory filter matching used during event broadcasting.

use std::collections::HashMap;

use nostr_bbs_core::event::NostrEvent;
use serde::{Deserialize, Serialize};

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
// SQL query builder
// ---------------------------------------------------------------------------

/// A value bound to one numbered `?N` placeholder of a [`FilterQuery`].
///
/// Kept free of `JsValue` so the exact SQL the relay sends to D1 can be run
/// against SQLite in native tests; `storage.rs` converts at the call site.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlParam {
    /// A TEXT value.
    Text(String),
    /// An INTEGER value (kinds, timestamps, limits).
    Int(i64),
}

/// One filter compiled to a single D1 statement: SQL with numbered
/// placeholders, and the values they bind in order (`?1` is `params[0]`).
#[derive(Debug, Clone, PartialEq)]
pub struct FilterQuery {
    /// The statement. Selects `id, pubkey, created_at, kind, tags, content,
    /// sig`, newest first, at most `limit` rows, never the same id twice.
    pub sql: String,
    /// Values for `?1..?N`.
    pub params: Vec<SqlParam>,
}

/// The most values of one tag filter answered as a `UNION ALL` of per-value
/// index walks. Above it the query falls back to a single `IN` driver, which
/// scans every match but keeps the statement small: SQLite caps compound
/// SELECTs at 500 terms and D1 a statement at 100 bound parameters.
pub const MAX_UNION_BRANCHES: usize = 32;

/// The selected columns, qualified: `event_tags` also has `created_at`, so an
/// unqualified name in a joined query is ambiguous.
const EVENT_COLUMNS: &str = "events.id AS id, events.pubkey AS pubkey, \
     events.created_at AS created_at, events.kind AS kind, events.tags AS tags, \
     events.content AS content, events.sig AS sig";

/// Numbered placeholders and their values, built up in order.
struct Binds {
    params: Vec<SqlParam>,
}

impl Binds {
    fn push(&mut self, p: SqlParam) -> String {
        self.params.push(p);
        format!("?{}", self.params.len())
    }

    fn text(&mut self, s: &str) -> String {
        self.push(SqlParam::Text(s.to_string()))
    }

    fn int(&mut self, n: i64) -> String {
        self.push(SqlParam::Int(n))
    }
}

/// Compile one NIP-01 filter, shared by REQ and COUNT, to one statement that
/// returns at most `limit` rows, newest first.
///
/// **Tag filters drive the query.** The first tag filter (in key order) is
/// read from `event_tags` through `idx_event_tags_time (name, value,
/// created_at, event_id)`, which hands rows over already in `created_at`
/// order. Each value gets its own branch, `CROSS JOIN`ed ahead of `events` so
/// SQLite walks the index newest-first, looks up each event by primary key,
/// applies the remaining conditions and stops after `limit` survivors. A
/// single-channel page therefore visits about `limit` rows whatever the
/// channel's size; the previous `SELECT DISTINCT event_id … IN (…)` driver
/// visited every match and sorted them in a temp B-tree before the LIMIT.
///
/// Several values become a `UNION ALL` of per-value branches, each limited,
/// under an outer `SELECT DISTINCT … ORDER BY … LIMIT`. SQLite cannot merge
/// per-value index order for an `IN` list, so this is what keeps a zone-wide
/// filter at about `values × limit` rows. The outer `DISTINCT` drops an event
/// that matches two values before the LIMIT, so such a page is never short:
/// every event in the true newest `limit` is among the newest `limit` of a
/// branch it matches. Within one branch an event appears once per identical
/// `(name, value)` tag row; the v3 writer inserts each distinct pair once and
/// migration 0015 removes older duplicates, so branches carry no repeats.
///
/// `since`/`until` bound the driver's `created_at` (inclusive, as before), so
/// they narrow the index range instead of filtering after it. That relies on
/// `event_tags.created_at` mirroring `events.created_at`, which the
/// `trg_event_tags_ai_v3` writer guarantees for new rows and migration 0015
/// backfills for old ones. Other tag filters become `EXISTS` probes.
///
/// Without a tag filter the query reads `events` directly; with a single kind
/// `idx_events_kind_time (kind, created_at)` serves the ORDER BY.
pub fn build_filter_query(filter: &NostrFilter, limit: u32) -> FilterQuery {
    let mut b = Binds { params: Vec::new() };
    let mut conds: Vec<String> = Vec::new();

    if let Some(ref ids) = filter.ids {
        if ids.is_empty() {
            conds.push("1 = 0".to_string());
        } else {
            let ph: Vec<String> = ids.iter().map(|id| b.text(id)).collect();
            conds.push(format!("events.id IN ({})", ph.join(",")));
        }
    }
    if let Some(ref authors) = filter.authors {
        if authors.is_empty() {
            conds.push("1 = 0".to_string());
        } else {
            let ph: Vec<String> = authors.iter().map(|a| b.text(a)).collect();
            conds.push(format!("events.pubkey IN ({})", ph.join(",")));
        }
    }
    if let Some(ref kinds) = filter.kinds {
        if kinds.is_empty() {
            conds.push("1 = 0".to_string());
        } else {
            let ph: Vec<String> = kinds.iter().map(|k| b.int(*k as i64)).collect();
            conds.push(format!("events.kind IN ({})", ph.join(",")));
        }
    }

    // Tag filters, in key order so the driver choice is deterministic.
    let mut keys: Vec<&String> = filter.extra.keys().collect();
    keys.sort();
    let mut driver: Option<(String, Vec<String>)> = None;
    for key in keys {
        let (tag_name, values) = match tag_filter_plan(key, &filter.extra[key]) {
            TagFilterPlan::Ignore => continue,
            TagFilterPlan::MatchNothing => {
                conds.push("1 = 0".to_string());
                continue;
            }
            TagFilterPlan::Values(name, values) => (name, values),
        };
        let name_ph = b.text(tag_name);
        let value_ph: Vec<String> = values.iter().map(|v| b.text(v)).collect();
        if driver.is_none() {
            driver = Some((name_ph, value_ph));
        } else {
            conds.push(format!(
                "EXISTS (SELECT 1 FROM event_tags x WHERE x.event_id = events.id \
                 AND x.name = {name_ph} AND x.value IN ({}))",
                value_ph.join(",")
            ));
        }
    }

    // NIP-50: full-text search on content.
    if let Some(search) = search_term(filter) {
        let ph = b.text(&like_pattern(search));
        conds.push(format!("events.content LIKE {ph} ESCAPE '\\'"));
    }

    let since = filter.since.map(|s| b.int(s as i64));
    let until = filter.until.map(|u| b.int(u as i64));
    let limit_ph = b.int(i64::from(limit));

    let sql = match driver {
        Some((name_ph, values)) if values.len() <= MAX_UNION_BRANCHES => {
            let mut where_tail = String::new();
            if let Some(s) = &since {
                where_tail.push_str(&format!(" AND d.created_at >= {s}"));
            }
            if let Some(u) = &until {
                where_tail.push_str(&format!(" AND d.created_at <= {u}"));
            }
            for c in &conds {
                where_tail.push_str(" AND ");
                where_tail.push_str(c);
            }
            let branches: Vec<String> = values
                .iter()
                .map(|v| {
                    format!(
                        "SELECT * FROM (SELECT {EVENT_COLUMNS} \
                         FROM event_tags d CROSS JOIN events ON events.id = d.event_id \
                         WHERE d.name = {name_ph} AND d.value = {v}{where_tail} \
                         ORDER BY d.created_at DESC, d.event_id DESC LIMIT {limit_ph})"
                    )
                })
                .collect();
            format!(
                "SELECT DISTINCT id, pubkey, created_at, kind, tags, content, sig \
                 FROM ({}) ORDER BY created_at DESC, id DESC LIMIT {limit_ph}",
                branches.join(" UNION ALL ")
            )
        }
        Some((name_ph, values)) => {
            // Too many values for a compound statement: one IN driver, as before.
            if let Some(s) = &since {
                conds.push(format!("events.created_at >= {s}"));
            }
            if let Some(u) = &until {
                conds.push(format!("events.created_at <= {u}"));
            }
            format!(
                "SELECT {EVENT_COLUMNS} FROM (SELECT DISTINCT event_id FROM event_tags \
                 WHERE name = {name_ph} AND value IN ({})) m \
                 CROSS JOIN events ON events.id = m.event_id{} \
                 ORDER BY events.created_at DESC, events.id DESC LIMIT {limit_ph}",
                values.join(","),
                where_clause(&conds)
            )
        }
        None => {
            if let Some(s) = &since {
                conds.push(format!("events.created_at >= {s}"));
            }
            if let Some(u) = &until {
                conds.push(format!("events.created_at <= {u}"));
            }
            format!(
                "SELECT {EVENT_COLUMNS} FROM events{} \
                 ORDER BY events.created_at DESC LIMIT {limit_ph}",
                where_clause(&conds)
            )
        }
    };

    FilterQuery {
        sql,
        params: b.params,
    }
}

/// The channel a channel-scoped kind-42 belongs to, in SQL over `events.tags`:
/// the same rule as [`channel_tag`] (the first `e` tag marked `root`, else the
/// first `e` tag), so a count can apply that channel's read gate exactly as
/// `authorize_event` does per event.
const SQL_CHANNEL_TAG: &str = "COALESCE(\
     (SELECT json_extract(j.value, '$[1]') FROM json_each(events.tags) j \
      WHERE json_type(j.value) = 'array' AND json_array_length(j.value) >= 2 \
        AND json_extract(j.value, '$[0]') = 'e' AND json_extract(j.value, '$[3]') = 'root' \
      ORDER BY j.key LIMIT 1), \
     (SELECT json_extract(j.value, '$[1]') FROM json_each(events.tags) j \
      WHERE json_type(j.value) = 'array' AND json_array_length(j.value) >= 2 \
        AND json_extract(j.value, '$[0]') = 'e' \
      ORDER BY j.key LIMIT 1))";

/// Whether the event carries any NIP-40 `expiration` tag, in SQL.
const SQL_HAS_EXPIRATION: &str = "EXISTS (SELECT 1 FROM json_each(events.tags) j \
     WHERE json_type(j.value) = 'array' AND json_array_length(j.value) >= 2 \
       AND json_extract(j.value, '$[0]') = 'expiration')";

/// The two statements of a channel message count (NIP-45 COUNT fast path for
/// `{"kinds":[42], "#e":[<channel>], since?, until?}`).
#[derive(Debug, Clone, PartialEq)]
pub struct ChannelCountQueries {
    /// `SELECT COUNT(*) AS n`: the plain case, kind-42s whose own channel
    /// ([`channel_tag`]) IS this channel and that carry no `expiration` tag.
    /// Every one of them gets the same read decision (this channel's zone
    /// gate), so the caller decides it once and adds `n` or nothing.
    pub plain: FilterQuery,
    /// Full rows of every other match (a different own channel, or an
    /// `expiration` tag): normally none. The caller runs the per-event path
    /// on them (NIP-40 expiry, then `authorize_event`), so the total equals
    /// what the generic COUNT path would return without its row cap.
    pub exceptions: FilterQuery,
}

/// Build the channel count statements. Both read `idx_event_tags_time` for
/// the channel and look up each event by primary key: about two rows read per
/// message, one statement, no rows shipped back for the plain case. The
/// generic COUNT path materialised every matching event (and was capped at
/// the filter's `limit`, default 500, so it could never report a large total).
pub fn build_channel_count(
    channel: &str,
    since: Option<u64>,
    until: Option<u64>,
) -> ChannelCountQueries {
    let mut b = Binds { params: Vec::new() };
    let ch = b.text(channel);
    let mut range = String::new();
    if let Some(s) = since {
        range.push_str(&format!(" AND d.created_at >= {}", b.int(s as i64)));
    }
    if let Some(u) = until {
        range.push_str(&format!(" AND d.created_at <= {}", b.int(u as i64)));
    }
    let from = format!(
        "FROM event_tags d CROSS JOIN events ON events.id = d.event_id \
         WHERE d.name = 'e' AND d.value = {ch} AND events.kind = 42{range}"
    );
    let plain_cond = format!("({SQL_CHANNEL_TAG}) = {ch} AND NOT {SQL_HAS_EXPIRATION}");
    let params = b.params;
    ChannelCountQueries {
        plain: FilterQuery {
            sql: format!("SELECT COUNT(*) AS n {from} AND {plain_cond}"),
            params: params.clone(),
        },
        exceptions: FilterQuery {
            sql: format!("SELECT {EVENT_COLUMNS} {from} AND NOT ({plain_cond})"),
            params,
        },
    }
}

/// The channel a COUNT filter set asks about, when it has the fast-path
/// shape: exactly one filter, `kinds` exactly `[42]`, exactly one `#e`
/// value, and nothing else but `since`/`until` (`limit` is ignored by COUNT).
pub fn channel_count_target(filters: &[NostrFilter]) -> Option<(String, Option<u64>, Option<u64>)> {
    let [f] = filters else {
        return None;
    };
    if f.ids.is_some() || f.authors.is_some() || search_term(f).is_some() {
        return None;
    }
    if f.kinds.as_deref() != Some(&[42][..]) {
        return None;
    }
    let mut channel = None;
    for (key, value) in &f.extra {
        match tag_filter_plan(key, value) {
            TagFilterPlan::Ignore => {}
            TagFilterPlan::Values(name, values)
                if name == "e" && values.len() == 1 && channel.is_none() =>
            {
                channel = Some(values[0].to_string());
            }
            _ => return None,
        }
    }
    channel.map(|c| (c, f.since, f.until))
}

fn where_clause(conds: &[String]) -> String {
    if conds.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conds.join(" AND "))
    }
}

// ---------------------------------------------------------------------------
// Filter semantics shared by the SQL builder and the live matcher
// ---------------------------------------------------------------------------

/// How one `#x` entry of a filter is to be applied. Both the SQL builder and
/// [`event_matches_filters`] decide through [`tag_filter_plan`], so a stored
/// read and a live broadcast cannot disagree about the same filter.
enum TagFilterPlan<'a> {
    /// Not a tag filter, an unusable tag name, or a non-array value: skipped.
    Ignore,
    /// An empty array, or one holding only empty strings: nothing can match.
    MatchNothing,
    /// The tag name and the non-empty string values, one of which must match.
    Values(&'a str, Vec<&'a str>),
}

fn tag_filter_plan<'a>(key: &'a str, values: &'a serde_json::Value) -> TagFilterPlan<'a> {
    let Some(tag_name) = key.strip_prefix('#') else {
        return TagFilterPlan::Ignore;
    };
    if !tag_name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return TagFilterPlan::Ignore;
    }
    // `probe` rows are kept out of `event_tags` (trg_event_tags_probe_blind), so
    // a stored `#probe` read returns nothing; the live path must agree.
    if tag_name == "probe" {
        return TagFilterPlan::MatchNothing;
    }
    let Some(arr) = values.as_array() else {
        return TagFilterPlan::Ignore;
    };
    let nonempty: Vec<&str> = arr
        .iter()
        .filter_map(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .collect();
    if nonempty.is_empty() {
        TagFilterPlan::MatchNothing
    } else {
        TagFilterPlan::Values(tag_name, nonempty)
    }
}

/// The NIP-50 term a filter applies, or `None` when absent or empty.
fn search_term(filter: &NostrFilter) -> Option<&str> {
    filter.search.as_deref().filter(|s| !s.is_empty())
}

/// SQL `LIKE` pattern for a search term, using `\` as the escape character.
/// The escape character itself is escaped first, otherwise a term containing a
/// backslash would match the character after it instead of the backslash.
fn like_pattern(term: &str) -> String {
    let escaped = term
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{escaped}%")
}

/// The live equivalent of `content LIKE like_pattern(term)`: a substring match
/// that is case-insensitive over ASCII only, as SQLite's default `LIKE` is.
fn content_matches_search(content: &str, term: &str) -> bool {
    content
        .to_ascii_lowercase()
        .contains(&term.to_ascii_lowercase())
}

// ---------------------------------------------------------------------------
// In-memory filter matching (for broadcast)
// ---------------------------------------------------------------------------

#[doc(hidden)]
pub fn event_matches_filters(event: &NostrEvent, filters: &[NostrFilter]) -> bool {
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

        // NIP-50: the live path honours `search` exactly as the SQL `LIKE` does.
        if let Some(term) = search_term(filter) {
            if !content_matches_search(&event.content, term) {
                continue;
            }
        }

        // Tag filters (#e, #p, #t, etc.) -- must match at least one value per
        // tag. The shared plan keeps this in step with the SQL builder.
        for (key, values) in &filter.extra {
            let (tag_name, required) = match tag_filter_plan(key, values) {
                TagFilterPlan::Ignore => continue,
                TagFilterPlan::MatchNothing => continue 'outer,
                TagFilterPlan::Values(name, values) => (name, values),
            };

            // Check that the event has at least one tag matching this filter
            let has_match = event.tags.iter().any(|tag| {
                tag.first().map(|t| t.as_str()) == Some(tag_name)
                    && tag.get(1).is_some_and(|v| required.contains(&v.as_str()))
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

/// The channel a kind-42 message belongs to: its `root`-marked `e` tag, else the
/// first `e` tag.
///
/// This is the same resolution the forum client uses to place a message in a
/// channel. The write and read gates previously took the FIRST `e` tag, so a
/// member could put a decoy first `e` naming a channel they may write to (or an
/// unscoped one) and a `root` `e` naming a zone-private channel: the relay
/// authorised the decoy while every client rendered the post in the private
/// thread. All three must agree on one answer.
pub fn channel_tag(event: &NostrEvent) -> Option<String> {
    let e_tags = || event.tags.iter().filter(|t| t.len() >= 2 && t[0] == "e");
    e_tags()
        .find(|t| t.get(3).map(String::as_str) == Some("root"))
        .or_else(|| e_tags().next())
        .map(|t| t[1].clone())
}

/// The channel whose zone governs reading `event`, if it is channel-scoped:
/// a kind-40 definition is its own channel; kind-41 metadata and kind-42
/// messages name theirs through [`channel_tag`].
#[doc(hidden)]
pub fn zone_channel_id(event: &NostrEvent) -> Option<String> {
    match event.kind {
        40 => Some(event.id.clone()),
        41 | 42 => channel_tag(event),
        _ => None,
    }
}

/// Split a NIP-33 `a` reference, `kind:pubkey:d-tag`, into its parts.
///
/// Only the first two colons separate fields: a d-tag may itself contain `:`,
/// and splitting on every colon truncated it so the deletion matched nothing.
#[doc(hidden)]
pub fn split_a_ref(a_ref: &str) -> Option<(f64, &str, &str)> {
    let mut parts = a_ref.splitn(3, ':');
    let kind: f64 = parts.next()?.parse().ok()?;
    let pubkey = parts.next()?;
    let d_tag = parts.next()?;
    Some((kind, pubkey, d_tag))
}

/// Extract the first value for a given tag name from an event.
#[doc(hidden)]
pub fn tag_value(event: &NostrEvent, name: &str) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].clone())
}

/// NIP-40 admission for an event's `expiration` tag at time `now`.
///
/// `Ok(())` when there is no tag or it names a future instant. NIP-40 values
/// are unix seconds; anything else is refused rather than ignored, because the
/// retention sweep (`cron.rs`) and any other relay would read it differently —
/// SQLite's `CAST('2026-10-06T…' AS INTEGER)` is 2026, so an RFC 3339 value used
/// to be accepted here and then deleted on the next cron run.
pub fn expiration_admission(event: &NostrEvent, now: u64) -> Result<(), &'static str> {
    let Some(raw) = tag_value(event, "expiration") else {
        return Ok(());
    };
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid: expiration must be unix seconds (NIP-40)");
    }
    match raw.parse::<u64>() {
        Ok(ts) if ts < now => Err("invalid: event expired"),
        Ok(_) => Ok(()),
        Err(_) => Err("invalid: expiration must be unix seconds (NIP-40)"),
    }
}

#[doc(hidden)]
pub fn d_tag_value(event: &NostrEvent) -> String {
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
        extra.insert("#e".to_string(), serde_json::json!(["event_id_1"]));
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
        filter
            .extra
            .insert("#e".to_string(), serde_json::json!(["event_ref"]));
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
        filter
            .extra
            .insert("#e".to_string(), serde_json::json!(["other_ref"]));
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
        filter
            .extra
            .insert("#p".to_string(), serde_json::json!(["pubkey123"]));
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
        filter
            .extra
            .insert("#e".to_string(), serde_json::json!(["ref1"]));
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

    // ── live matcher vs SQL semantics ────────────────────────────────────

    fn filter_from(json: serde_json::Value) -> NostrFilter {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn live_matcher_follows_sql_semantics_table() {
        let tagged = make_event(
            "i",
            "p",
            1,
            10,
            vec![
                vec!["t".into(), "rust".into()],
                vec!["probe".into(), "x".into()],
            ],
            "Hello 100% World_x back\\slash",
        );
        // (filter, expected live match). Each row's expectation is what the SQL
        // builder's conditions select for this event.
        let cases = [
            (serde_json::json!({"search": "hello"}), true),
            (serde_json::json!({"search": "WORLD"}), true),
            (serde_json::json!({"search": "absent"}), false),
            (serde_json::json!({"search": ""}), true),
            (serde_json::json!({"search": "100%"}), true),
            (serde_json::json!({"search": "d_x"}), true),
            (serde_json::json!({"search": "k\\s"}), true),
            (serde_json::json!({"search": "kxs"}), false),
            (serde_json::json!({"#t": []}), false),
            (serde_json::json!({"#t": [""]}), false),
            (serde_json::json!({"#t": [1, 2]}), false),
            (serde_json::json!({"#t": ["rust"]}), true),
            (serde_json::json!({"#t": ["go"]}), false),
            (serde_json::json!({"#t": "rust"}), true),
            (serde_json::json!({"#bad name": ["zzz"]}), true),
            (serde_json::json!({"#bad name": []}), true),
            // A bare "#" passes the SQL name check and then selects `name = ''`.
            (serde_json::json!({"#": ["zzz"]}), false),
            (serde_json::json!({"#t": ["rust"], "search": "nope"}), false),
            // Probe tags are never indexed, so SQL never matches them.
            (serde_json::json!({"#probe": ["x"]}), false),
        ];
        for (json, expected) in cases {
            let f = filter_from(json.clone());
            assert_eq!(
                event_matches_filters(&tagged, &[f]),
                expected,
                "filter {json}"
            );
        }
    }

    #[test]
    fn like_pattern_escapes_the_escape_character_first() {
        assert_eq!(like_pattern("a\\b"), "%a\\\\b%");
        assert_eq!(like_pattern("50%_"), "%50\\%\\_%");
    }

    #[test]
    fn split_a_ref_keeps_colons_inside_the_d_tag() {
        assert_eq!(
            split_a_ref("30023:abc:room:2026:notes"),
            Some((30023.0, "abc", "room:2026:notes"))
        );
        assert_eq!(split_a_ref("30023:abc:"), Some((30023.0, "abc", "")));
        assert_eq!(split_a_ref("30023:abc"), None);
        assert_eq!(split_a_ref("x:abc:d"), None);
    }

    // ── zone_channel_id ──────────────────────────────────────────────────

    #[test]
    fn zone_channel_id_maps_41_through_the_root_marker_not_the_first_e() {
        let tags = vec![
            vec!["e".into(), "public-decoy".into()],
            vec![
                "e".into(),
                "private-channel".into(),
                "".into(),
                "root".into(),
            ],
        ];
        for kind in [41, 42] {
            let event = make_event("id", "pk", kind, 1, tags.clone(), "x");
            assert_eq!(
                zone_channel_id(&event).as_deref(),
                Some("private-channel"),
                "kind {kind}"
            );
        }
        let def = make_event("chan-id", "pk", 40, 1, vec![], "{}");
        assert_eq!(zone_channel_id(&def).as_deref(), Some("chan-id"));
        assert_eq!(
            zone_channel_id(&make_event("i", "p", 1, 1, tags, "x")),
            None
        );
    }

    // ── tag_value ────────────────────────────────────────────────────────

    #[test]
    fn channel_tag_prefers_the_root_marker_over_a_decoy_first_e() {
        let event = make_event(
            "aaa",
            "bbb",
            42,
            1000,
            vec![
                vec!["e".into(), "public-decoy".into()],
                vec![
                    "e".into(),
                    "private-channel".into(),
                    "".into(),
                    "root".into(),
                ],
            ],
            "hi",
        );
        assert_eq!(channel_tag(&event).as_deref(), Some("private-channel"));
        // The old resolution would have authorised the decoy.
        assert_eq!(tag_value(&event, "e").as_deref(), Some("public-decoy"));
    }

    #[test]
    fn channel_tag_falls_back_to_the_first_e_without_a_root_marker() {
        let event = make_event(
            "a",
            "b",
            42,
            1,
            vec![
                vec!["e".into(), "chan".into()],
                vec!["e".into(), "other".into()],
            ],
            "x",
        );
        assert_eq!(channel_tag(&event).as_deref(), Some("chan"));
        assert_eq!(channel_tag(&make_event("a", "b", 42, 1, vec![], "x")), None);
        // A reply marker is not a root marker.
        let reply_first = make_event(
            "a",
            "b",
            42,
            1,
            vec![
                vec!["e".into(), "parent".into(), "".into(), "reply".into()],
                vec!["e".into(), "chan".into(), "".into(), "root".into()],
            ],
            "x",
        );
        assert_eq!(channel_tag(&reply_first).as_deref(), Some("chan"));
    }

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
        let event = make_event("aaa", "bbb", 1, 1000, vec![vec!["e".into()]], "hello");
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

    #[test]
    fn expiration_admission_accepts_absent_and_future_seconds() {
        let none = make_event("aaa", "bbb", 1, 1000, vec![], "x");
        assert_eq!(expiration_admission(&none, 1_000), Ok(()));
        let future = make_event(
            "aaa",
            "bbb",
            1,
            1000,
            vec![vec!["expiration".into(), "2000".into()]],
            "x",
        );
        assert_eq!(expiration_admission(&future, 1_000), Ok(()));
    }

    #[test]
    fn expiration_admission_refuses_past_and_non_numeric() {
        let past = make_event(
            "aaa",
            "bbb",
            1,
            1000,
            vec![vec!["expiration".into(), "999".into()]],
            "x",
        );
        assert_eq!(
            expiration_admission(&past, 1_000),
            Err("invalid: event expired")
        );
        // The a429e066 shape: RFC 3339 instead of unix seconds.
        for bad in ["2026-10-06T00:00:00Z", "", "12a", "-5", " 2000"] {
            let e = make_event(
                "aaa",
                "bbb",
                31402,
                1000,
                vec![vec!["expiration".into(), bad.into()]],
                "x",
            );
            assert_eq!(
                expiration_admission(&e, 1_000),
                Err("invalid: expiration must be unix seconds (NIP-40)"),
                "{bad:?}"
            );
        }
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
        let event = make_event("aaa", "bbb", 30023, 1000, vec![vec!["d".into()]], "hello");
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
        filter
            .extra
            .insert("not_a_tag".to_string(), serde_json::json!(["val"]));
        // Non-# keys in extra are ignored by the tag matching logic
        assert!(event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn tag_filter_empty_values_array_matches_nothing() {
        let event = make_event("aaa", "bbb", 1, 1000, vec![], "hello");
        let mut filter = empty_filter();
        filter.extra.insert("#e".to_string(), serde_json::json!([]));
        // The SQL builder emits `1 = 0` for an empty array; the live path agrees.
        assert!(!event_matches_filters(&event, &[filter]));
    }

    #[test]
    fn tag_filter_non_array_value_is_skipped() {
        let event = make_event("aaa", "bbb", 1, 1000, vec![], "hello");
        let mut filter = empty_filter();
        filter
            .extra
            .insert("#e".to_string(), serde_json::json!("not_an_array"));
        assert!(event_matches_filters(&event, &[filter]));
    }
}

#[cfg(test)]
mod query_builder_tests {
    //! The SQL `build_filter_query` emits, run against SQLite with the real
    //! schema (0009 + 0004 + the boot-time writer and indexes): same rows as
    //! the live matcher would select, newest first, no duplicates, `until`
    //! paging that loses nothing across equal timestamps, and a single-channel
    //! page that no longer visits the whole channel.
    use super::*;
    use rusqlite::{types::Value, Connection};

    const MIGRATION_0004: &str = include_str!("../../migrations/0004_event_tags.sql");

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(crate::EVENTS_CREATE_SQL).unwrap();
        c.execute_batch(MIGRATION_0004).unwrap();
        let _ = c.execute_batch(crate::EVENT_TAGS_TIME_COLUMN_SQL);
        for s in crate::PROBE_BLIND_STMTS {
            c.execute_batch(s).unwrap();
        }
        for s in crate::PAGING_INDEX_STMTS {
            c.execute_batch(s).unwrap();
        }
        c
    }

    fn ev(id: usize, kind: u64, created_at: u64, tags: Vec<Vec<&str>>) -> NostrEvent {
        NostrEvent {
            id: format!("{id:064x}"),
            pubkey: format!("{:064x}", id % 7),
            created_at,
            kind,
            tags: tags
                .into_iter()
                .map(|t| t.into_iter().map(String::from).collect())
                .collect(),
            content: format!("message {id}"),
            sig: "00".repeat(64),
        }
    }

    fn store(c: &Connection, events: &[NostrEvent]) {
        let mut s = c
            .prepare(
                "INSERT INTO events (id, pubkey, created_at, kind, tags, content, sig) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )
            .unwrap();
        for e in events {
            s.execute(rusqlite::params![
                e.id,
                e.pubkey,
                e.created_at as i64,
                e.kind as i64,
                serde_json::to_string(&e.tags).unwrap(),
                e.content,
                e.sig
            ])
            .unwrap();
        }
    }

    fn bind(params: &[SqlParam]) -> Vec<Value> {
        params
            .iter()
            .map(|p| match p {
                SqlParam::Text(s) => Value::Text(s.clone()),
                SqlParam::Int(n) => Value::Integer(*n),
            })
            .collect()
    }

    /// Run the compiled filter; returns `(id, created_at)` in result order and
    /// the statement's VM step count.
    fn run(c: &Connection, filter: &NostrFilter, limit: u32) -> (Vec<(String, u64)>, i32) {
        let q = build_filter_query(filter, limit);
        run_sql(c, &q.sql, &bind(&q.params))
    }

    fn run_sql(c: &Connection, sql: &str, params: &[Value]) -> (Vec<(String, u64)>, i32) {
        let mut s = c.prepare(sql).unwrap();
        let rows: Vec<(String, u64)> = s
            .query_map(rusqlite::params_from_iter(params.iter()), |r| {
                Ok((
                    r.get::<_, String>("id")?,
                    r.get::<_, i64>("created_at")? as u64,
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let steps = s.get_status(rusqlite::StatementStatus::VmStep);
        (rows, steps)
    }

    /// What the relay must return: every event the live matcher accepts,
    /// newest first, ties by id descending, at most `limit`.
    fn reference(events: &[NostrEvent], filter: &NostrFilter, limit: u32) -> Vec<(String, u64)> {
        let mut v: Vec<&NostrEvent> = events
            .iter()
            .filter(|e| event_matches_filters(e, std::slice::from_ref(filter)))
            .collect();
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));
        v.into_iter()
            .take(limit as usize)
            .map(|e| (e.id.clone(), e.created_at))
            .collect()
    }

    fn filter(json: serde_json::Value) -> NostrFilter {
        serde_json::from_value(json).unwrap()
    }

    /// Three channels; `a` is busy and has runs of up to 7 messages sharing a
    /// second (imported history keeps Keybase's one-second timestamps). Every
    /// 10th message of `a` also names `b`, and kind-7s and a kind-41 share the
    /// `e` values, so the kind condition is exercised inside the walk.
    fn fixture() -> Vec<NostrEvent> {
        let mut v = Vec::new();
        for i in 0..600 {
            let mut tags = vec![vec!["e", "a", "", "root"]];
            if i % 10 == 0 {
                tags.push(vec!["e", "b"]);
            }
            v.push(ev(i, 42, 1_000 + (i as u64 / 7), tags));
        }
        for i in 600..700 {
            v.push(ev(
                i,
                42,
                900 + i as u64,
                vec![vec!["e", "b", "", "root"], vec!["p", "bob"]],
            ));
        }
        for i in 700..720 {
            v.push(ev(i, 42, 1_050 + i as u64, vec![vec!["e", "c"]]));
        }
        for i in 720..760 {
            v.push(ev(i, 7, 1_020 + i as u64, vec![vec!["e", "a"]]));
        }
        v.push(ev(760, 41, 1_100, vec![vec!["e", "a"]]));
        v
    }

    #[test]
    fn a_single_channel_page_matches_the_live_matcher_exactly() {
        let c = db();
        let events = fixture();
        store(&c, &events);
        for f in [
            filter(serde_json::json!({"kinds": [42], "#e": ["a"], "limit": 50})),
            filter(serde_json::json!({"kinds": [42], "#e": ["a"], "until": 1_040, "limit": 100})),
            filter(
                serde_json::json!({"kinds": [42], "#e": ["a"], "since": 1_010, "until": 1_020, "limit": 1000}),
            ),
            filter(serde_json::json!({"kinds": [42, 7], "#e": ["a"], "limit": 30})),
            filter(serde_json::json!({"#e": ["a"], "limit": 1000})),
        ] {
            let limit = f.limit.unwrap();
            assert_eq!(run(&c, &f, limit).0, reference(&events, &f, limit), "{f:?}");
        }
    }

    #[test]
    fn since_and_until_stay_inclusive() {
        let c = db();
        let events = fixture();
        store(&c, &events);
        let f =
            filter(serde_json::json!({"kinds": [42], "#e": ["a"], "since": 1_010, "until": 1_010}));
        let rows = run(&c, &f, 500).0;
        assert_eq!(rows.len(), 7, "all seven messages of second 1010");
        assert!(rows.iter().all(|(_, t)| *t == 1_010));
    }

    #[test]
    fn several_values_union_without_duplicates_or_short_pages() {
        let c = db();
        let events = fixture();
        store(&c, &events);
        for f in [
            filter(serde_json::json!({"kinds": [42], "#e": ["a", "b", "c"], "limit": 100})),
            filter(
                serde_json::json!({"kinds": [42], "#e": ["b", "a"], "until": 1_030, "limit": 40}),
            ),
            filter(serde_json::json!({"kinds": [42], "#e": ["a", "b"], "limit": 1000})),
        ] {
            let limit = f.limit.unwrap();
            let got = run(&c, &f, limit).0;
            let ids: std::collections::HashSet<&String> = got.iter().map(|(id, _)| id).collect();
            assert_eq!(ids.len(), got.len(), "no event twice");
            assert_eq!(got, reference(&events, &f, limit), "{f:?}");
        }
    }

    #[test]
    fn a_second_tag_filter_is_applied_as_a_condition() {
        let c = db();
        let events = fixture();
        store(&c, &events);
        let f = filter(serde_json::json!({"kinds": [42], "#e": ["b"], "#p": ["bob"], "limit": 25}));
        assert_eq!(run(&c, &f, 25).0, reference(&events, &f, 25));
    }

    #[test]
    fn paging_by_inclusive_until_reaches_the_first_message_without_loss() {
        // The client's walk: page `until = oldest seen`, drop ids already
        // held, stop when a page is short. Runs of equal timestamps straddle
        // page boundaries (page 25, runs of 7).
        let c = db();
        let events = fixture();
        store(&c, &events);
        let mut held: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut until: Option<u64> = None;
        for _ in 0..1000 {
            let mut f = filter(serde_json::json!({"kinds": [42], "#e": ["a"], "limit": 25}));
            f.until = until;
            let page = run(&c, &f, 25).0;
            let oldest = page.iter().map(|(_, t)| *t).min();
            let fresh = page
                .iter()
                .filter(|(id, _)| held.insert(id.clone()))
                .count();
            if page.len() < 25 {
                break;
            }
            // A full page with nothing new would stall; step past the second.
            until = match (fresh, oldest) {
                (0, Some(t)) => Some(t - 1),
                (_, t) => t,
            };
        }
        let all: std::collections::HashSet<String> = events
            .iter()
            .filter(|e| e.kind == 42 && e.tags.iter().any(|t| t[0] == "e" && t[1] == "a"))
            .map(|e| e.id.clone())
            .collect();
        assert_eq!(held, all, "every message of the channel, once");
    }

    #[test]
    fn a_tagless_filter_reads_events_newest_first() {
        let c = db();
        let events = fixture();
        store(&c, &events);
        let f = filter(serde_json::json!({"kinds": [42], "limit": 60}));
        let got: Vec<u64> = run(&c, &f, 60).0.into_iter().map(|(_, t)| t).collect();
        let want: Vec<u64> = reference(&events, &f, 60)
            .into_iter()
            .map(|(_, t)| t)
            .collect();
        assert_eq!(got, want, "same timestamps in the same order");
    }

    #[test]
    fn too_many_values_fall_back_to_one_in_driver() {
        let c = db();
        let events = fixture();
        store(&c, &events);
        let mut values: Vec<String> = (0..MAX_UNION_BRANCHES + 5)
            .map(|i| format!("x{i}"))
            .collect();
        values.push("c".into());
        let f = filter(serde_json::json!({"kinds": [42], "#e": values, "limit": 10}));
        let q = build_filter_query(&f, 10);
        assert!(!q.sql.contains("UNION ALL"));
        assert_eq!(run(&c, &f, 10).0, reference(&events, &f, 10));
    }

    #[test]
    fn the_channel_count_splits_exactly_like_the_per_event_path() {
        let c = db();
        let mut events = fixture();
        // Edge cases the per-event path treats differently from the plain case:
        // a decoy first `e` with the root marker elsewhere, an `e` to the
        // channel that is not the event's own channel, and expiration tags.
        events.push(ev(
            800,
            42,
            1_200,
            vec![vec!["e", "decoy"], vec!["e", "a", "", "root"]],
        ));
        events.push(ev(
            801,
            42,
            1_201,
            vec![vec!["e", "b", "", "root"], vec!["e", "a"]],
        ));
        events.push(ev(
            802,
            42,
            1_202,
            vec![vec!["e", "a", "", "root"], vec!["expiration", "1"]],
        ));
        events.push(ev(
            803,
            42,
            1_203,
            vec![
                vec!["e", "a", "", "root"],
                vec!["expiration", "99999999999"],
            ],
        ));
        store(&c, &events);
        for (since, until) in [
            (None, None),
            (Some(1_010), None),
            (None, Some(1_050)),
            (Some(1_020), Some(1_202)),
        ] {
            let q = build_channel_count("a", since, until);
            let plain: i64 = c
                .query_row(
                    &q.plain.sql,
                    rusqlite::params_from_iter(bind(&q.plain.params).iter()),
                    |r| r.get(0),
                )
                .unwrap();
            let (mut exc, _) = run_sql(&c, &q.exceptions.sql, &bind(&q.exceptions.params));
            let in_range = |e: &&NostrEvent| {
                e.kind == 42
                    && e.tags
                        .iter()
                        .any(|t| t.len() >= 2 && t[0] == "e" && t[1] == "a")
                    && since.is_none_or(|s| e.created_at >= s)
                    && until.is_none_or(|u| e.created_at <= u)
            };
            let is_plain = |e: &&NostrEvent| {
                channel_tag(e).as_deref() == Some("a") && tag_value(e, "expiration").is_none()
            };
            let want_plain = events.iter().filter(in_range).filter(is_plain).count();
            let mut want_exc: Vec<(String, u64)> = events
                .iter()
                .filter(in_range)
                .filter(|e| !is_plain(e))
                .map(|e| (e.id.clone(), e.created_at))
                .collect();
            exc.sort();
            want_exc.sort();
            assert_eq!(plain as usize, want_plain, "plain {since:?}..{until:?}");
            assert_eq!(exc, want_exc, "exceptions {since:?}..{until:?}");
        }
    }

    #[test]
    fn only_the_single_channel_message_shape_takes_the_count_fast_path() {
        let f = |j: serde_json::Value| -> Vec<NostrFilter> { vec![filter(j)] };
        assert_eq!(
            channel_count_target(&f(
                serde_json::json!({"kinds": [42], "#e": ["a"], "since": 5, "limit": 1})
            )),
            Some(("a".to_string(), Some(5), None))
        );
        for j in [
            serde_json::json!({"kinds": [42, 7], "#e": ["a"]}),
            serde_json::json!({"#e": ["a"]}),
            serde_json::json!({"kinds": [42], "#e": ["a", "b"]}),
            serde_json::json!({"kinds": [42], "#e": ["a"], "#p": ["x"]}),
            serde_json::json!({"kinds": [42], "#e": ["a"], "authors": ["x"]}),
            serde_json::json!({"kinds": [42], "#e": ["a"], "search": "x"}),
            serde_json::json!({"kinds": [42], "#e": []}),
        ] {
            assert_eq!(channel_count_target(&f(j.clone())), None, "{j}");
        }
        let two = vec![filter(serde_json::json!({"kinds": [42], "#e": ["a"]})); 2];
        assert_eq!(channel_count_target(&two), None);
    }

    #[test]
    fn a_single_channel_page_walks_the_time_index_not_the_channel() {
        // 20k messages in one channel. The previous driver visited every one
        // of them and sorted them before the LIMIT; the time index stops
        // after the page. Measured as SQLite VM steps for the same page.
        let c = db();
        let events: Vec<NostrEvent> = (0..20_000)
            .map(|i| {
                ev(
                    i,
                    42,
                    1_000_000 + i as u64,
                    vec![vec!["e", "busy", "", "root"]],
                )
            })
            .collect();
        store(&c, &events);
        let f = filter(
            serde_json::json!({"kinds": [42], "#e": ["busy"], "until": 1_015_000, "limit": 100}),
        );
        let (rows, new_steps) = run(&c, &f, 100);
        assert_eq!(rows.len(), 100);
        assert_eq!(rows[0].1, 1_015_000);

        let legacy = "SELECT id, pubkey, created_at, kind, tags, content, sig \
             FROM (SELECT DISTINCT event_id FROM event_tags WHERE name = ?1 AND value IN (?2)) m \
             CROSS JOIN events ON events.id = m.event_id \
             WHERE events.kind IN (?3) AND events.created_at <= ?4 \
             ORDER BY events.created_at DESC LIMIT ?5";
        let (legacy_rows, legacy_steps) = run_sql(
            &c,
            legacy,
            &[
                Value::Text("e".into()),
                Value::Text("busy".into()),
                Value::Integer(42),
                Value::Integer(1_015_000),
                Value::Integer(100),
            ],
        );
        assert_eq!(rows, legacy_rows, "same page as the old query");
        assert!(
            new_steps * 50 < legacy_steps,
            "time-index walk took {new_steps} VM steps, legacy {legacy_steps}"
        );

        let plan: Vec<String> = c
            .prepare(&format!(
                "EXPLAIN QUERY PLAN {}",
                build_filter_query(&f, 100).sql
            ))
            .unwrap()
            .query_map(
                rusqlite::params_from_iter(bind(&build_filter_query(&f, 100).params).iter()),
                |r| r.get::<_, String>(3),
            )
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(
            plan.iter().any(|l| l.contains("idx_event_tags_time")),
            "plan: {plan:?}"
        );
    }
}
