//! Section stats (ADR-2038): the relay's one-frame answer listing every
//! marked topic root of a section with its last activity, last participant
//! and reply count, and how a board folds it in.
//!
//! The wire contract (see the relay's `relay_do/section_stats.rs`):
//!
//! ```text
//! client: ["SECTION-STATS", <id>, {"channel": "<64 lowercase hex>"}]
//! relay:  ["SECTION-STATS", <id>, {"channel", "as_of", "truncated", "fields", "topics"}]
//!     or: ["CLOSED", <id>, "<prefix>: <reason>"]
//! ```
//!
//! A client sends it only to a relay whose NIP-11 document advertises it
//! (`nostr_bbs.section_stats`, see [`advertised`]), so an old relay never
//! sees the verb. Any refusal, a timeout or a malformed answer is a failure,
//! after which the board behaves exactly as before ADR-2038.
//!
//! The answer's figures are exact for what the relay can see in tags and a
//! lower bound of what `classify_topics` derives, so they are folded in with
//! `max` ([`fold_section_stats`]): the relay never lowers a figure the
//! client already holds.

use std::collections::HashMap;

use super::board::{board_order, TopicSummary};

/// The frame verb.
pub const SECTION_STATS_VERB: &str = "SECTION-STATS";

/// The wire version this client speaks.
pub const SECTION_STATS_VERSION: u64 = 1;

/// How long a request waits for its answer before it counts as failed, in
/// milliseconds. Well under the board's 20 s freeze cap.
pub const SECTION_STATS_TIMEOUT_MS: i32 = 8_000;

/// The `NOTICE` an old relay sends for the verb, should it ever be sent one
/// (a stale NIP-11 answer). The client fails the request on it and does not
/// show it to the reader.
pub const SECTION_STATS_UNKNOWN_NOTICE: &str = "Unknown message type: SECTION-STATS";

/// Whether a relay's NIP-11 document advertises the request at a version
/// this client speaks.
pub fn advertised(nip11: &serde_json::Value) -> bool {
    let block = &nip11["nostr_bbs"]["section_stats"];
    block["verb"].as_str() == Some(SECTION_STATS_VERB)
        && block["version"]
            .as_u64()
            .is_some_and(|v| v >= SECTION_STATS_VERSION)
}

/// The request frame for `channel` under `id`.
pub fn section_stats_frame(id: &str, channel: &str) -> String {
    serde_json::json!([SECTION_STATS_VERB, id, { "channel": channel }]).to_string()
}

/// One topic of an answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TopicStat {
    /// The stored root id (a sealed root's envelope id).
    pub id: String,
    /// The root's creation time.
    pub created_at: u64,
    /// Newest activity (the root or its newest reply); `None` when the
    /// relay could not determine it.
    pub last_at: Option<u64>,
    /// Author of that activity; `None` when unknown or sealed.
    pub last_pubkey: Option<String>,
    /// Exact reply count; `None` past the relay's cap or budget.
    pub replies: Option<u32>,
    /// A sealed root's original id.
    pub original: Option<String>,
}

/// A parsed answer, indexed by every id a row may be listed under (the
/// stored id and a sealed root's original, lower-case).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SectionStats {
    /// The section.
    pub channel: String,
    /// The relay's clock when it computed the answer.
    pub as_of: u64,
    /// The section has more marked roots than the answer lists.
    pub truncated: bool,
    /// The topics, newest activity first.
    pub topics: Vec<TopicStat>,
    by_id: HashMap<String, usize>,
}

impl SectionStats {
    /// Parse an answer payload; `None` when it is not one. Fields are read
    /// by the names in its `fields` list, so added fields are ignored.
    pub fn parse(payload: &serde_json::Value) -> Option<Self> {
        let fields: Vec<&str> = payload["fields"]
            .as_array()?
            .iter()
            .map(|f| f.as_str())
            .collect::<Option<_>>()?;
        let at = |name: &str| fields.iter().position(|f| *f == name);
        let (i_id, i_created) = (at("id")?, at("created_at")?);
        let (i_last, i_pk, i_replies, i_orig) = (
            at("last_at"),
            at("last_pubkey"),
            at("replies"),
            at("original"),
        );
        let mut topics = Vec::new();
        for row in payload["topics"].as_array()? {
            let row = row.as_array()?;
            let get = |i: Option<usize>| i.and_then(|i| row.get(i));
            topics.push(TopicStat {
                id: row.get(i_id)?.as_str()?.to_string(),
                created_at: row.get(i_created)?.as_u64()?,
                last_at: get(i_last).and_then(|v| v.as_u64()),
                last_pubkey: get(i_pk).and_then(|v| v.as_str()).map(str::to_string),
                replies: get(i_replies)
                    .and_then(|v| v.as_u64())
                    .map(|n| n.min(u32::MAX as u64) as u32),
                original: get(i_orig).and_then(|v| v.as_str()).map(str::to_string),
            });
        }
        let mut by_id = HashMap::new();
        for (i, t) in topics.iter().enumerate() {
            by_id.insert(t.id.to_lowercase(), i);
            if let Some(o) = &t.original {
                by_id.entry(o.to_lowercase()).or_insert(i);
            }
        }
        Some(Self {
            channel: payload["channel"].as_str().unwrap_or("").to_string(),
            as_of: payload["as_of"].as_u64().unwrap_or(0),
            truncated: payload["truncated"].as_bool().unwrap_or(false),
            topics,
            by_id,
        })
    }

    /// The stats for a row listed under `id` (stored or original id).
    pub fn get(&self, id: &str) -> Option<&TopicStat> {
        self.by_id
            .get(&id.to_lowercase())
            .and_then(|&i| self.topics.get(i))
    }

    /// Whether the true last activity of the row listed under `id` is known.
    pub fn activity_known(&self, id: &str) -> bool {
        self.get(id).is_some_and(|t| t.last_at.is_some())
    }

    /// Whether the per-topic pump still has something to add for `id`: a
    /// reply count or a last activity this answer does not carry.
    pub fn needs_pump(&self, id: &str) -> bool {
        self.get(id)
            .is_none_or(|t| t.replies.is_none() || t.last_at.is_none())
    }
}

/// Where a section's stats request stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SectionStatsState {
    /// Asked, not answered yet.
    Pending,
    /// Answered.
    Answered(std::sync::Arc<SectionStats>),
    /// Refused, timed out, unsupported or malformed: the board behaves as
    /// it did before ADR-2038.
    Failed(String),
}

impl SectionStatsState {
    /// Answered or failed: nothing more is coming this visit.
    pub fn settled(&self) -> bool {
        !matches!(self, Self::Pending)
    }

    /// The state a request for `channel` settles in from the relay's
    /// reply: an answer for that channel, or a failure (a refusal, any
    /// `CLOSED` reason, a payload that does not parse or names another
    /// channel). A refusal is never an empty list (ADR-2034).
    pub fn from_answer(channel: &str, reply: Result<serde_json::Value, String>) -> Self {
        match reply {
            Ok(payload) => SectionStats::parse(&payload)
                .filter(|s| s.channel == channel)
                .map(|s| Self::Answered(std::sync::Arc::new(s)))
                .unwrap_or_else(|| Self::Failed("malformed answer".into())),
            Err(reason) => Self::Failed(reason),
        }
    }

    /// The answer, if there is one.
    pub fn stats(&self) -> Option<&std::sync::Arc<SectionStats>> {
        match self {
            Self::Answered(s) => Some(s),
            _ => None,
        }
    }
}

/// Fold an answer into classified topics: the newest activity and its
/// author when newer than what the topic has, the reply count when larger,
/// then re-sort by [`board_order`]. Topics the answer does not list (legacy
/// roots without the marker, past a truncation) keep their own figures.
pub fn fold_section_stats(
    mut topics: Vec<TopicSummary>,
    stats: Option<&SectionStats>,
) -> Vec<TopicSummary> {
    let Some(stats) = stats else {
        return topics;
    };
    for t in &mut topics {
        let Some(s) = stats.get(&t.id) else {
            continue;
        };
        if let Some(last) = s.last_at.filter(|l| *l > t.last_activity) {
            t.last_activity = last;
            if let Some(pk) = &s.last_pubkey {
                t.last_pubkey = pk.clone();
            }
        }
        if let Some(n) = s.replies {
            t.reply_count = t.reply_count.max(n);
        }
    }
    topics.sort_by(board_order);
    topics
}

/// Whether a board may freeze: once its history window has settled, its
/// root list has answered or failed and its section stats have answered or
/// failed, or once `capped` ([`super::board::FREEZE_CAP_MS`]).
pub fn freeze_ready(window: bool, roots: bool, section_stats: bool, capped: bool) -> bool {
    capped || (window && roots && section_stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(id: &str, created: u64, last: u64, replies: u32) -> TopicSummary {
        TopicSummary {
            id: id.into(),
            pubkey: "op".into(),
            content: id.into(),
            created_at: created,
            reply_count: replies,
            last_activity: last,
            last_pubkey: "op".into(),
        }
    }

    fn payload() -> serde_json::Value {
        serde_json::json!({
            "channel": "c",
            "as_of": 1_000,
            "truncated": false,
            "fields": ["id", "created_at", "last_at", "last_pubkey", "replies", "original"],
            "topics": [
                ["env", 5, 900, null, 3, "ORIG"],
                ["b", 10, 800, "bob", 7, null],
                ["c", 20, null, null, null, null]
            ]
        })
    }

    #[test]
    fn parses_by_field_name_and_indexes_sealed_originals() {
        let s = SectionStats::parse(&payload()).unwrap();
        assert_eq!(s.topics.len(), 3);
        assert_eq!(s.get("orig").map(|t| t.id.as_str()), Some("env"));
        assert_eq!(s.get("ENV").map(|t| t.replies), Some(Some(3)));
        assert!(s.activity_known("b"));
        assert!(!s.activity_known("c"));
        assert!(!s.activity_known("missing"));
        assert!(s.needs_pump("c") && s.needs_pump("missing") && !s.needs_pump("b"));
        // Reordered and extra fields read the same.
        let p = serde_json::json!({
            "fields": ["replies", "x", "id", "created_at"],
            "topics": [[4, "y", "a", 1]]
        });
        let s = SectionStats::parse(&p).unwrap();
        assert_eq!(
            (s.topics[0].id.as_str(), s.topics[0].replies),
            ("a", Some(4))
        );
        assert_eq!(s.topics[0].last_at, None);
        for bad in [
            serde_json::json!({}),
            serde_json::json!({"fields": ["id"], "topics": []}),
            serde_json::json!({"fields": ["id", "created_at"], "topics": [[1, 2]]}),
        ] {
            assert_eq!(SectionStats::parse(&bad), None, "{bad}");
        }
    }

    #[test]
    fn folding_only_raises_figures_and_resorts() {
        let s = SectionStats::parse(&payload()).unwrap();
        let topics = vec![
            summary("orig", 5, 5, 1),
            summary("b", 10, 850, 9),
            summary("c", 20, 20, 0),
            summary("legacy", 1, 950, 2),
        ];
        let out = fold_section_stats(topics, Some(&s));
        let order: Vec<&str> = out.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(order, ["legacy", "orig", "b", "c"]);
        let orig = &out[1];
        assert_eq!((orig.last_activity, orig.reply_count), (900, 3));
        assert_eq!(orig.last_pubkey, "op", "a sealed last author is unknown");
        let b = &out[2];
        assert_eq!((b.last_activity, b.reply_count), (850, 9), "never lowered");
        assert_eq!(
            fold_section_stats(vec![summary("x", 1, 2, 0)], None)[0].last_activity,
            2
        );
    }

    #[test]
    fn advertised_needs_the_verb_and_a_known_version() {
        let doc = |v: serde_json::Value| serde_json::json!({ "nostr_bbs": { "section_stats": v } });
        assert!(advertised(&doc(
            serde_json::json!({"verb": "SECTION-STATS", "version": 1})
        )));
        assert!(advertised(&doc(
            serde_json::json!({"verb": "SECTION-STATS", "version": 2})
        )));
        assert!(!advertised(&doc(
            serde_json::json!({"verb": "SECTION-STATS"})
        )));
        assert!(!advertised(&doc(
            serde_json::json!({"verb": "OTHER", "version": 1})
        )));
        assert!(
            !advertised(&serde_json::json!({ "supported_nips": [1] })),
            "an old relay"
        );
    }

    #[test]
    fn the_frame_names_the_channel() {
        assert_eq!(
            section_stats_frame("s1", "ab"),
            r#"["SECTION-STATS","s1",{"channel":"ab"}]"#
        );
    }

    #[test]
    fn freeze_waits_for_section_stats_or_the_cap() {
        assert!(!freeze_ready(true, true, false, false));
        assert!(freeze_ready(true, true, true, false));
        assert!(!freeze_ready(false, true, true, false));
        assert!(freeze_ready(false, false, false, true));
    }

    #[test]
    fn a_reply_settles_as_an_answer_only_for_its_channel() {
        let ok = SectionStatsState::from_answer("c", Ok(payload()));
        assert_eq!(ok.stats().map(|s| s.topics.len()), Some(3));
        let other = SectionStatsState::from_answer("d", Ok(payload()));
        assert_eq!(other, SectionStatsState::Failed("malformed answer".into()));
        let refused = SectionStatsState::from_answer("c", Err("auth-required: x".into()));
        assert_eq!(
            refused,
            SectionStatsState::Failed("auth-required: x".into())
        );
        assert!(
            refused.stats().is_none(),
            "a refusal is never an empty list"
        );
        let junk = SectionStatsState::from_answer("c", Ok(serde_json::json!({"count": 0})));
        assert!(matches!(junk, SectionStatsState::Failed(_)));
    }

    #[test]
    fn states_settle_on_answer_or_failure() {
        assert!(!SectionStatsState::Pending.settled());
        assert!(SectionStatsState::Failed("timeout".into()).settled());
        let a = SectionStatsState::Answered(std::sync::Arc::new(SectionStats::default()));
        assert!(a.settled() && a.stats().is_some());
    }
}
