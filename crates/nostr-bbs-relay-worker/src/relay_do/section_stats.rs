//! Section stats (ADR-2038): one request that returns, for one section
//! (kind-40 channel), every marked topic root with its last activity, its
//! last participant and its reply count, so a client can list the whole
//! section in true order at first paint instead of asking each topic.
//!
//! # Wire
//!
//! ```text
//! client: ["SECTION-STATS", <id>, {"channel": "<64 lowercase hex>"}]
//! relay:  ["SECTION-STATS", <id>, {"channel", "as_of", "truncated", "fields", "topics"}]
//!     or: ["CLOSED", <id>, "<prefix>: <reason>"]
//! ```
//!
//! `topics` holds one array per topic in [`FIELDS`] order, newest activity
//! first (ties by id), exactly the client's `board_order`.
//!
//! # Admission
//!
//! The aggregate covers the channel's kind-42 messages, so it is admitted
//! exactly as each of those messages would be on REQ or COUNT:
//! [`super::nip_handlers::channel_read_decision_for`]`(42, …)` on the zone
//! [`NostrRelayDO::cached_channel_zone`] resolves (the ADR-2037 pin first,
//! then the memo, then D1), for the viewer
//! [`NostrRelayDO::resolve_viewer_context`] builds. There is no second copy
//! of the rules here: [`admission`] only maps that decision to an answer.
//! A refused request gets `CLOSED`, never an empty list, and the refusal for
//! "gated and unreadable" is the same text as for "no such section", so a
//! refusal does not say which ids are gated channels.
//!
//! # What is counted
//!
//! The rules are `classify_topics` (client-core `topics::board`) restricted
//! to what the relay can see in tags:
//!
//! - a **topic root** is a stored kind-42 carrying the topic marker
//!   (`["t","topic"]`), whose `root`-marked `e` tag is the channel and which
//!   has no `reply`-marked `e` tag (sealed roots carry the same outer shape);
//! - a **reply** to root `R` is a stored kind-42 whose own channel (the
//!   `root`-marked `e` tag, else the first `e` tag) is the channel, whose first
//!   `reply`-marked `e` tag is `R`, and which is not an edit (no
//!   `edit`-marked `e` tag);
//! - NIP-40 expired events are neither; an honoured kind-5 deletion removes
//!   the row from `events`, so a deleted root or reply is never seen.
//!
//! A sealed root (ADR-2017) is reported under its envelope id with its
//! original's id in `original`, and replies naming either id count for it.
//! When the plaintext original is still stored beside its envelope, the
//! original is the topic and the envelope is not listed (`classify_topics`
//! shadowing); replies naming the envelope still count for it.
//!
//! # Cost
//!
//! See [`compute`]. The roots statement reads only this channel's topic
//! roots through migration 0017's partial index (until it is applied, a
//! walk of at most [`ROOTS_VISIT_CAP`] topic-marked rows that reports
//! `truncated` when it stops). One [`stats_sql`] statement per
//! [`STATS_BATCH`] ids gives each id its last activity (a walk of at most
//! [`ACTIVITY_WALK_ROWS`] `e`-tag rows) and, until [`COUNT_BUDGET`] count
//! rows have been visited, its reply count (a walk of at most
//! [`COUNT_VISIT_CAP`] rows; past it `null`). Every walk counts the rows it
//! visits, not only the ones that qualify, so reactions, quotes or crafted
//! references naming a topic cannot make an answer expensive. A section of
//! 300 topics costs 4 statements. Answers are memoised per channel for
//! [`MEMO_TTL_SECS`] (admission is decided before the memo is read), one
//! computation per channel runs at a time with every concurrent reader
//! waiting for it, and at most [`MAX_CONCURRENT`] run at once.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use serde::Deserialize;

use super::nip_handlers::{channel_read_decision_for, ReadDecision, ViewerContext};
use crate::trust::ZoneLookupError;
use crate::zone_config::ZoneConfig;

/// The frame verb, in both directions.
pub(crate) const VERB: &str = "SECTION-STATS";

/// Wire contract version, advertised in NIP-11 (`nostr_bbs.section_stats`).
pub(crate) const VERSION: u32 = 1;

/// Most topics one answer lists. More marked roots in the channel than this
/// sets `truncated`; the roots kept are the most recently created.
pub(crate) const MAX_TOPICS: usize = 1_000;

/// Most `e`-tag rows one root's last-activity walk visits (newest first). A
/// walk that meets this many rows naming the root without finding a reply
/// (reactions, edits, other channels' crafted references) reports the last
/// activity as unknown rather than reading further.
pub(crate) const ACTIVITY_WALK_ROWS: i64 = 256;

/// Most `e`-tag rows one id's count walk visits. A topic with more rows
/// naming it (replies, but also reactions, quotes, edits) reports its count
/// as unknown (`null`); the per-topic COUNT, snapshotted for big topics,
/// still supplies it.
pub(crate) const COUNT_VISIT_CAP: u64 = 1_000;

/// Count rows visited per answer, across topics, before counting stops (the
/// remaining batches report activity only). Checked between statements.
pub(crate) const COUNT_BUDGET: u64 = 20_000;

/// Ids per [`stats_sql`] statement (bound as one JSON array). One statement
/// visits at most `STATS_BATCH × (ACTIVITY_WALK_ROWS + 2 × COUNT_VISIT_CAP)`
/// index rows.
pub(crate) const STATS_BATCH: usize = 100;

/// Most section-stats computations running at once in this isolate, across
/// channels (one per channel by single flight).
pub(crate) const MAX_CONCURRENT: u32 = 2;

/// After the roots index is found missing, how long the relay goes straight
/// to the fallback walk before trying the index again, in seconds.
pub(crate) const INDEX_RETRY_SECS: u64 = 600;

/// Most topic-marked tag rows the fallback roots walk visits (used only
/// while migration 0017's index is absent); hitting it sets `truncated`.
pub(crate) const ROOTS_VISIT_CAP: usize = 20_000;

/// How long a computed answer is reused for the same channel, in seconds.
pub(crate) const MEMO_TTL_SECS: u64 = 30;

/// The answer's per-topic field order.
pub(crate) const FIELDS: [&str; 6] = [
    "id",
    "created_at",
    "last_at",
    "last_pubkey",
    "replies",
    "original",
];

/// Refusal for a request that is not authenticated (pre-AUTH, ADR-2034):
/// the client asks again after AUTH, and never reads this as "no topics".
pub(crate) const REFUSE_AUTH: &str = "auth-required: section stats need an authenticated reader";
/// Refusal for an authenticated reader who may not read the section, and for
/// a section that does not exist: deliberately the same text.
pub(crate) const REFUSE_RESTRICTED: &str = "restricted: section not readable";
/// D1 could not answer: try again later; not an absence.
pub(crate) const REFUSE_BUSY: &str = "error: section stats unavailable, try again";
/// The request itself is malformed.
pub(crate) const REFUSE_INVALID: &str =
    "invalid: expected {\"channel\": <64-character lowercase hex id>}";
/// The per-IP frame budget is spent.
pub(crate) const REFUSE_RATE: &str = "rate-limited: slow down";

/// The channel a request names, when it is a canonical event id.
pub(crate) fn requested_channel(body: &serde_json::Value) -> Option<String> {
    let c = body.get("channel")?.as_str()?;
    (c.len() == 64 && c.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .then(|| c.to_string())
}

/// The admission decision, from the shared channel read rule for the
/// channel's kind-42 messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    /// The reader may read every kind-42 of the channel.
    Admit,
    /// Refused with this `CLOSED` reason.
    Refuse(&'static str),
}

/// Map [`channel_read_decision_for`]`(42, …)` to an admission. The decision
/// is the REQ/COUNT rule itself (admin bypass, cohorts, public read, a pin,
/// a failed lookup withholding); only the refusal text is chosen here.
pub(crate) fn admission(
    lookup: &Result<Option<String>, ZoneLookupError>,
    zones: &ZoneConfig,
    ctx: &ViewerContext,
) -> Admission {
    match channel_read_decision_for(42, lookup, zones, ctx) {
        ReadDecision::Deliver | ReadDecision::DeliverAs(_) => Admission::Admit,
        ReadDecision::Withhold => Admission::Refuse(refusal_for(ctx)),
    }
}

/// The refusal for `ctx` (also used for a section that does not exist).
pub(crate) fn refusal_for(ctx: &ViewerContext) -> &'static str {
    if ctx.session_pubkey.is_some() {
        REFUSE_RESTRICTED
    } else {
        REFUSE_AUTH
    }
}

// ---------------------------------------------------------------------------
// SQL
// ---------------------------------------------------------------------------

/// The value of the first `e` tag of `alias.tags` whose marker (4th element)
/// is `marker`, in tag order.
#[cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, reason = "SQL is run through D1 only")
)]
fn marked_e(alias: &str, marker: &str) -> String {
    format!(
        "(SELECT json_extract(jt.value, '$[1]') FROM json_each({alias}.tags) jt \
          WHERE json_type(jt.value) = 'array' AND json_extract(jt.value, '$[0]') = 'e' \
            AND json_extract(jt.value, '$[3]') = '{marker}' ORDER BY jt.key LIMIT 1)"
    )
}

/// The channel an event is filed in: its first `root`-marked `e` tag, else
/// its first `e` tag (`filter::channel_tag`, `sealed::channel_of`).
#[cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, reason = "SQL is run through D1 only")
)]
fn own_channel(alias: &str) -> String {
    format!(
        "COALESCE({}, (SELECT json_extract(jt.value, '$[1]') FROM json_each({alias}.tags) jt \
          WHERE json_type(jt.value) = 'array' AND json_array_length(jt.value) >= 2 \
            AND json_extract(jt.value, '$[0]') = 'e' ORDER BY jt.key LIMIT 1))",
        marked_e(alias, "root")
    )
}

/// Whether the event is an edit (`["e", <target>, _, "edit"]`).
#[cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, reason = "SQL is run through D1 only")
)]
fn is_edit(alias: &str) -> String {
    format!(
        "EXISTS (SELECT 1 FROM json_each({alias}.tags) jt \
          WHERE json_type(jt.value) = 'array' AND json_extract(jt.value, '$[0]') = 'e' \
            AND json_extract(jt.value, '$[3]') = 'edit')"
    )
}

/// Whether the event carries any `sealed` tag (well formed or not).
#[cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, reason = "SQL is run through D1 only")
)]
fn has_sealed(alias: &str) -> String {
    format!(
        "EXISTS (SELECT 1 FROM json_each({alias}.tags) jt \
          WHERE json_type(jt.value) = 'array' AND json_extract(jt.value, '$[0]') = 'sealed')"
    )
}

/// Whether the event has expired at `now_ph` under NIP-40, exactly as the
/// REQ path decides (`storage::query_events_checked`: the first
/// `expiration` tag's value as `u64::parse` reads it, an optional `+` then
/// decimal digits with leading zeros allowed, strictly before now). Read from the row's own tags, like
/// `filter::SQL_HAS_EXPIRATION`: an `event_tags` probe on `name =
/// 'expiration'` let the planner walk every expiring row on the relay.
#[cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, reason = "SQL is run through D1 only")
)]
fn expired(alias: &str, now_ph: &str) -> String {
    // d: the digits after an optional '+'; z: d without leading zeros.
    let v = "json_extract(jt.value, '$[1]')";
    let d = format!("(CASE WHEN substr({v}, 1, 1) = '+' THEN substr({v}, 2) ELSE {v} END)");
    let z = format!("ltrim({d}, '0')");
    format!(
        "COALESCE((SELECT CASE WHEN json_type(jt.value, '$[1]') = 'text' \
             AND {d} <> '' AND {d} NOT GLOB '*[^0-9]*' AND length({z}) <= 18 \
             THEN CAST({z} AS INTEGER) < {now_ph} ELSE 0 END \
           FROM json_each({alias}.tags) jt \
           WHERE json_type(jt.value) = 'array' AND json_array_length(jt.value) >= 2 \
             AND json_extract(jt.value, '$[0]') = 'expiration' ORDER BY jt.key LIMIT 1), 0)"
    )
}

/// Whether `r` is a reply to `value` in channel `?1` at time `?2`.
#[cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, reason = "SQL is run through D1 only")
)]
fn qualifies(value: &str) -> String {
    format!(
        "r.kind = 42 AND {} = ?1 AND {} = {value} AND NOT {} AND NOT {}",
        own_channel("r"),
        marked_e("r", "reply"),
        is_edit("r"),
        expired("r", "?2"),
    )
}

#[cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, reason = "SQL is run through D1 only")
)]
/// The checks a candidate root row `ev` must pass for channel `?1` at `?2`.
fn root_shape() -> String {
    format!(
        "ev.kind = 42 AND {} = ?1 AND {} IS NULL AND NOT {}",
        marked_e("ev", "root"),
        marked_e("ev", "reply"),
        expired("ev", "?2"),
    )
}

/// The sealed-tags column of a root row (a JSON array of its `sealed` tags).
const SEALED_COLUMN: &str = "(SELECT json_group_array(json(js.value)) FROM json_each(ev.tags) js \
     WHERE json_type(js.value) = 'array' AND json_extract(js.value, '$[0]') = 'sealed') AS sealed";

/// The channel's topic roots through migration 0017's partial index (topic
/// roots only, keyed by the first tag's value): `?1` channel, `?2` now, `?3`
/// row limit. Reads this channel's roots and nothing else. Fails with "no
/// such index" while 0017 is not applied; [`compute`] then uses
/// [`roots_walk_sql`]. Columns `id`, `created_at`, `pubkey`, `sealed`,
/// `walked` (always NULL here).
#[cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, reason = "SQL is run through D1 only")
)]
pub(crate) fn roots_indexed_sql() -> String {
    format!(
        "SELECT ev.id AS id, ev.created_at AS created_at, ev.pubkey AS pubkey, {SEALED_COLUMN}, \
         NULL AS walked \
         FROM events ev INDEXED BY idx_events_topic_root_channel \
         WHERE ev.kind = 42 AND instr(ev.tags, '[\"t\",\"topic\"]') > 0 \
           AND json_extract(ev.tags, '$[0][1]') = ?1 AND {} \
         ORDER BY ev.created_at DESC, ev.id DESC LIMIT ?3",
        root_shape()
    )
}

/// The fallback without the index: the relay's topic-marked rows newest
/// first, at most `?4` of them ([`ROOTS_VISIT_CAP`]), kept when they are
/// this channel's roots: `?1` channel, `?2` now, `?3` row limit. Always one
/// row at least: `walked` (rows visited) on every row, and a row with a
/// NULL `id` when no root was found.
#[cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, reason = "SQL is run through D1 only")
)]
pub(crate) fn roots_walk_sql() -> String {
    let walk = "SELECT t.event_id AS eid, t.created_at AS tat FROM event_tags t \
                WHERE t.name = 't' AND t.value = 'topic' \
                ORDER BY t.created_at DESC, t.event_id DESC LIMIT ?4";
    format!(
        "SELECT rt.id AS id, rt.created_at AS created_at, rt.pubkey AS pubkey, rt.sealed AS sealed, \
         (SELECT COUNT(*) FROM ({walk})) AS walked \
         FROM (SELECT 1) one LEFT JOIN ( \
           SELECT ev.id AS id, ev.created_at AS created_at, ev.pubkey AS pubkey, {SEALED_COLUMN}, \
                  wk.tat AS tat \
           FROM ({walk}) wk CROSS JOIN events ev ON ev.id = wk.eid \
           WHERE EXISTS (SELECT 1 FROM event_tags c \
                         WHERE c.name = 'e' AND c.value = ?1 AND c.event_id = ev.id) \
             AND {} \
           ORDER BY wk.tat DESC, ev.id DESC LIMIT ?3) rt ON 1",
        root_shape()
    )
}

/// Each id's newest reply and, when `with_counts`, its reply count, in one
/// statement: `?1` channel, `?2` now, `?3` JSON array of ids, `?4` activity
/// walk limit ([`ACTIVITY_WALK_ROWS`]), `?5` count walk limit
/// ([`COUNT_VISIT_CAP`]). Every walk reads the `e`-tag rows naming the id
/// newest first on `idx_event_tags_time` and stops at its limit, so the rows
/// visited per id are bounded whatever else names it (reactions, quotes,
/// edits, crafted references). Columns: `v`; `last` (`[created_at, pubkey,
/// sealed]` of the newest reply within the activity walk, or NULL);
/// `walked` (activity rows visited, only when `last` is NULL); `n` (replies
/// within the count walk) and `visited` (count rows visited), NULL without
/// counts.
#[cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, reason = "SQL is run through D1 only")
)]
pub(crate) fn stats_sql(with_counts: bool) -> String {
    let walk = |v: &str, lim: &str| {
        format!(
            "SELECT w.event_id AS eid, w.created_at AS wat FROM event_tags w \
             WHERE w.name = 'e' AND w.value = {v} \
             ORDER BY w.created_at DESC, w.event_id DESC LIMIT {lim}"
        )
    };
    let counts = if with_counts {
        format!(
            "(SELECT COUNT(*) FROM ({}) y CROSS JOIN events r ON r.id = y.eid WHERE {}) AS n, \
             (SELECT COUNT(*) FROM ({})) AS visited",
            walk("jv.value", "?5"),
            qualifies("jv.value"),
            walk("jv.value", "?5"),
        )
    } else {
        // ?5 stays bound (D1 and SQLite refuse an unused binding).
        "NULL AS n, 0 * ?5 AS visited".to_string()
    };
    format!(
        "SELECT a.v AS v, a.last AS last, \
         CASE WHEN a.last IS NULL THEN (SELECT COUNT(*) FROM ({})) ELSE 0 END AS walked, \
         a.n AS n, a.visited AS visited \
         FROM (SELECT jv.value AS v, \
           (SELECT json_array(r.created_at, r.pubkey, {}) \
              FROM ({}) x CROSS JOIN events r ON r.id = x.eid \
              WHERE {} ORDER BY x.wat DESC, x.eid DESC LIMIT 1) AS last, \
           {counts} \
           FROM json_each(?3) jv) a",
        walk("a.v", "?4"),
        has_sealed("r"),
        walk("jv.value", "?4"),
        qualifies("jv.value"),
    )
}

/// Whether the section exists: a stored kind-40 or a creator row. `?1`.
#[cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, reason = "read through D1 only")
)]
pub(crate) const EXISTS_SQL: &str = "SELECT 1 AS x FROM events WHERE id = ?1 AND kind = 40 \
     UNION ALL SELECT 1 AS x FROM channel_creators WHERE channel_id = ?1 LIMIT 1";

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

/// One row of the roots statements.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RootRow {
    pub(crate) id: Option<String>,
    pub(crate) created_at: Option<f64>,
    pub(crate) pubkey: Option<String>,
    /// JSON array of the event's `sealed` tags.
    pub(crate) sealed: Option<String>,
    /// Topic-marked rows the fallback walk visited (NULL on the index path).
    pub(crate) walked: Option<f64>,
}

/// One row of [`stats_sql`].
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct StatsRow {
    pub(crate) v: String,
    pub(crate) last: Option<String>,
    pub(crate) walked: Option<f64>,
    pub(crate) n: Option<f64>,
    pub(crate) visited: Option<f64>,
}

/// The statements [`compute`] runs, so the pipeline is the same against D1
/// and against SQLite in tests.
#[allow(async_fn_in_trait)]
pub(crate) trait StatsDb {
    /// [`roots_indexed_sql`] when `indexed`, else [`roots_walk_sql`].
    async fn roots(
        &self,
        channel: &str,
        now: u64,
        limit: usize,
        indexed: bool,
    ) -> Result<Vec<RootRow>, String>;
    /// [`stats_sql`].
    async fn stats(
        &self,
        channel: &str,
        now: u64,
        ids: &[String],
        with_counts: bool,
    ) -> Result<Vec<StatsRow>, String>;
    /// [`EXISTS_SQL`]: whether the section exists.
    async fn exists(&self, channel: &str) -> Result<bool, String>;
}

/// One listed topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TopicStat {
    /// The stored root id (a sealed root's envelope id).
    pub(crate) id: String,
    /// The root's `created_at`.
    pub(crate) created_at: u64,
    /// Newest activity: the root or its newest reply. `None` when a walk
    /// ran out of rows before finding the newest reply (unknown).
    pub(crate) last_at: Option<u64>,
    /// Author of that newest activity; `None` when it is unknown or a
    /// sealed envelope (whose outer author is the migrator, not the poster).
    pub(crate) last_pubkey: Option<String>,
    /// Replies, exact; `None` past [`COUNT_VISIT_CAP`] or the budget.
    pub(crate) replies: Option<u64>,
    /// A sealed root's original id.
    pub(crate) original: Option<String>,
    /// Every id replies may name for this topic.
    keys: Vec<String>,
    root_pubkey: Option<String>,
}

/// A computed answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SectionAnswer {
    pub(crate) channel: String,
    pub(crate) as_of: u64,
    pub(crate) truncated: bool,
    pub(crate) topics: Vec<TopicStat>,
}

impl SectionAnswer {
    /// The frame payload.
    pub(crate) fn payload(&self) -> serde_json::Value {
        let topics: Vec<serde_json::Value> = self
            .topics
            .iter()
            .map(|t| {
                serde_json::json!([
                    t.id,
                    t.created_at,
                    t.last_at,
                    t.last_pubkey,
                    t.replies,
                    t.original
                ])
            })
            .collect();
        serde_json::json!({
            "channel": self.channel,
            "as_of": self.as_of,
            "truncated": self.truncated,
            "fields": FIELDS,
            "topics": topics,
        })
    }
}

/// A root row's fields, once it names a root.
struct Root {
    id: String,
    created_at: u64,
    pubkey: String,
    sealed: Option<String>,
}

/// The topics the root rows name: sealed originals read from their tags,
/// an envelope whose original is itself listed folded into the original.
fn plan_topics(rows: Vec<Root>) -> Vec<TopicStat> {
    let ids: HashSet<String> = rows.iter().map(|r| r.id.to_ascii_lowercase()).collect();
    let mut shadow: HashMap<String, String> = HashMap::new(); // original -> envelope
    let mut out: Vec<TopicStat> = Vec::new();
    for r in rows {
        let original = r
            .sealed
            .as_deref()
            .and_then(|s| serde_json::from_str::<Vec<Vec<String>>>(s).ok())
            .and_then(|tags| nostr_bbs_core::sealed::parse_sealed(&tags))
            .map(|s| s.inner_id);
        match original {
            Some(o) if ids.contains(&o) => {
                shadow.insert(o, r.id.clone());
            }
            Some(o) => out.push(TopicStat {
                keys: vec![r.id.clone(), o.clone()],
                id: r.id,
                created_at: r.created_at,
                last_at: None,
                last_pubkey: None,
                replies: None,
                original: Some(o),
                root_pubkey: None,
            }),
            None => out.push(TopicStat {
                keys: vec![r.id.clone()],
                id: r.id,
                created_at: r.created_at,
                last_at: None,
                last_pubkey: None,
                replies: None,
                original: None,
                root_pubkey: Some(r.pubkey),
            }),
        }
    }
    for t in &mut out {
        if let Some(env) = shadow.get(&t.id.to_ascii_lowercase()) {
            t.keys.push(env.clone());
        }
    }
    out
}

/// The client's `board_order`: newest activity first, ties by id. An
/// unknown last activity sorts by the root's creation (its lower bound).
fn board_order(a: &TopicStat, b: &TopicStat) -> std::cmp::Ordering {
    let ka = a.last_at.unwrap_or(a.created_at);
    let kb = b.last_at.unwrap_or(b.created_at);
    kb.cmp(&ka).then_with(|| a.id.cmp(&b.id))
}

/// A newest reply: (created_at, pubkey, sealed).
type Newest = (u64, String, bool);

/// A reply as [`stats_sql`] reports it.
fn parse_last(s: &str) -> Option<Newest> {
    let v: serde_json::Value = serde_json::from_str(s).ok()?;
    let ts = v.get(0)?.as_f64()?.max(0.0) as u64;
    let pk = v.get(1)?.as_str()?.to_string();
    let sealed = v.get(2).and_then(|x| x.as_i64()).unwrap_or(0) != 0;
    Some((ts, pk, sealed))
}

/// What one id's walks found.
struct Found {
    /// The activity walk ran out of rows without a reply.
    exhausted: bool,
    last: Option<Newest>,
    /// Replies, when counted and the count walk did not reach its cap.
    replies: Option<u64>,
    /// Count rows visited (0 without counts).
    visited: u64,
}

/// Whether a roots error means migration 0017's index is absent.
pub(crate) fn index_missing(err: &str) -> bool {
    err.contains("no such index")
}

/// Compute the answer for `channel` at `now`; `None` when the section does
/// not exist. `indexed`: try migration 0017's index first (the caller
/// remembers [`index_missing`] errors). Returns the answer and whether the
/// index was found missing.
///
/// Statements per uncached answer: one roots statement (a second, the
/// fallback walk, only when the index is missing), one [`stats_sql`] per
/// [`STATS_BATCH`] ids, and [`EXISTS_SQL`] only when no root was found. A
/// section of 300 topics costs 4. Rows visited: this channel's roots (index
/// path) or at most [`ROOTS_VISIT_CAP`] topic-marked rows (walk); per id at
/// most [`ACTIVITY_WALK_ROWS`] activity rows and, until [`COUNT_BUDGET`]
/// count rows have been visited, at most [`COUNT_VISIT_CAP`] count rows.
pub(crate) async fn compute<D: StatsDb>(
    db: &D,
    channel: &str,
    now: u64,
    indexed: bool,
) -> Result<(Option<SectionAnswer>, bool), String> {
    let mut index_absent = false;
    let rows = if indexed {
        match db.roots(channel, now, MAX_TOPICS + 1, true).await {
            Ok(rows) => rows,
            Err(e) if index_missing(&e) => {
                index_absent = true;
                db.roots(channel, now, MAX_TOPICS + 1, false).await?
            }
            Err(e) => return Err(e),
        }
    } else {
        db.roots(channel, now, MAX_TOPICS + 1, false).await?
    };
    let walk_capped = rows
        .iter()
        .filter_map(|r| r.walked)
        .any(|w| w as usize >= ROOTS_VISIT_CAP);
    let mut roots: Vec<Root> = rows
        .into_iter()
        .filter_map(|r| {
            Some(Root {
                id: r.id?,
                created_at: r.created_at.unwrap_or(0.0).max(0.0) as u64,
                pubkey: r.pubkey.unwrap_or_default(),
                sealed: r.sealed,
            })
        })
        .collect();
    let truncated = roots.len() > MAX_TOPICS || walk_capped;
    roots.truncate(MAX_TOPICS);
    if roots.is_empty() && !walk_capped && !db.exists(channel).await? {
        return Ok((None, index_absent));
    }
    let mut topics = plan_topics(roots);

    // Activity for every id, counts until the budget is spent.
    let mut found: HashMap<String, Found> = HashMap::new();
    let mut spent: u64 = 0;
    let mut start = 0;
    while start < topics.len() {
        let mut end = start;
        let mut ids: Vec<String> = Vec::new();
        while end < topics.len() && ids.len() + topics[end].keys.len() <= STATS_BATCH {
            ids.extend(topics[end].keys.iter().cloned());
            end += 1;
        }
        let with_counts = spent < COUNT_BUDGET;
        for row in db.stats(channel, now, &ids, with_counts).await? {
            let visited = row.visited.unwrap_or(0.0).max(0.0) as u64;
            spent += visited;
            found.insert(
                row.v,
                Found {
                    exhausted: row.walked.unwrap_or(0.0) as i64 >= ACTIVITY_WALK_ROWS,
                    last: row.last.as_deref().and_then(parse_last),
                    replies: row
                        .n
                        .filter(|_| with_counts && visited < COUNT_VISIT_CAP)
                        .map(|n| n.max(0.0) as u64),
                    visited,
                },
            );
        }
        start = end;
    }
    for t in &mut topics {
        let mut newest: Option<Newest> = None;
        let mut unknown = false;
        let mut replies: Option<u64> = Some(0);
        for k in &t.keys {
            match found.get(k) {
                Some(f) => {
                    match &f.last {
                        Some(l) => {
                            if newest.as_ref().is_none_or(|n| l.0 > n.0) {
                                newest = Some(l.clone());
                            }
                        }
                        // Walked its limit without a reply: the newest reply
                        // may be further back; the last activity is unknown.
                        None => unknown |= f.exhausted,
                    }
                    replies = replies.zip(f.replies).map(|(a, b)| a + b);
                    let _ = f.visited;
                }
                None => {
                    unknown = true;
                    replies = None;
                }
            }
        }
        t.replies = replies;
        if unknown {
            continue;
        }
        match newest {
            Some((ts, pk, sealed)) if ts > t.created_at => {
                t.last_at = Some(ts);
                t.last_pubkey = (!sealed).then_some(pk);
            }
            _ => {
                t.last_at = Some(t.created_at);
                t.last_pubkey = t.root_pubkey.clone();
            }
        }
    }
    topics.sort_by(board_order);

    Ok((
        Some(SectionAnswer {
            channel: channel.to_string(),
            as_of: now,
            truncated,
            topics,
        }),
        index_absent,
    ))
}

// ---------------------------------------------------------------------------
// Single flight
// ---------------------------------------------------------------------------

/// A shared answer: the payload, `None` for a section that does not exist,
/// or the error text.
pub(crate) type Shared = Result<Option<serde_json::Value>, String>;

/// One waiter's slot for the leader's answer.
pub(crate) struct Slot {
    value: RefCell<Option<Shared>>,
    waker: RefCell<Option<std::task::Waker>>,
}

impl Slot {
    fn new() -> Rc<Self> {
        Rc::new(Self {
            value: RefCell::new(None),
            waker: RefCell::new(None),
        })
    }

    fn fill(&self, v: Shared) {
        if self.value.borrow().is_none() {
            *self.value.borrow_mut() = Some(v);
            if let Some(w) = self.waker.borrow_mut().take() {
                w.wake();
            }
        }
    }

    /// The leader's answer, once it has one.
    pub(crate) async fn wait(self: &Rc<Self>) -> Shared {
        std::future::poll_fn(|cx| {
            if let Some(v) = self.value.borrow_mut().take() {
                return std::task::Poll::Ready(v);
            }
            *self.waker.borrow_mut() = Some(cx.waker().clone());
            std::task::Poll::Pending
        })
        .await
    }
}

/// Single flight per channel, and at most [`MAX_CONCURRENT`] computations
/// in the isolate across channels (the COUNT builder's
/// `InflightGuard`/`COUNT_FULL_MAX_CONCURRENT` pattern). Readers of a
/// channel already being computed wait for that one answer (each was
/// admitted on its own first); past the cap a new channel is refused busy.
#[derive(Default)]
pub(crate) struct SingleFlight {
    inflight: RefCell<HashMap<String, Vec<Rc<Slot>>>>,
    running: Cell<u32>,
}

/// What a request does: compute, wait for the computation running, or
/// refuse.
pub(crate) enum Role<'a> {
    /// Compute, then [`LeadGuard::finish`].
    Lead(LeadGuard<'a>),
    /// Wait for the leader's answer.
    Wait(Rc<Slot>),
    /// Too many computations running.
    Busy,
}

impl SingleFlight {
    /// The role of a request for `key`.
    pub(crate) fn begin(&self, key: &str) -> Role<'_> {
        if let Some(waiters) = self.inflight.borrow_mut().get_mut(key) {
            let slot = Slot::new();
            waiters.push(slot.clone());
            return Role::Wait(slot);
        }
        if self.running.get() >= MAX_CONCURRENT {
            return Role::Busy;
        }
        self.running.set(self.running.get() + 1);
        self.inflight
            .borrow_mut()
            .insert(key.to_string(), Vec::new());
        Role::Lead(LeadGuard {
            sf: self,
            key: key.to_string(),
        })
    }
}

/// The leader's hold on its key and on one concurrency slot, released on
/// drop; waiters not answered by then get an error.
pub(crate) struct LeadGuard<'a> {
    sf: &'a SingleFlight,
    key: String,
}

impl LeadGuard<'_> {
    /// Hand `answer` to every waiter and release the key.
    pub(crate) fn finish(self, answer: Shared) {
        self.release(answer);
    }

    fn release(&self, answer: Shared) {
        let waiters = self.sf.inflight.borrow_mut().remove(&self.key);
        for w in waiters.into_iter().flatten() {
            w.fill(answer.clone());
        }
    }
}

impl Drop for LeadGuard<'_> {
    fn drop(&mut self) {
        self.release(Err("section stats computation abandoned".into()));
        self.sf.running.set(self.sf.running.get().saturating_sub(1));
    }
}

// ---------------------------------------------------------------------------
// Durable Object
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
mod d1 {
    use super::*;
    use wasm_bindgen::JsValue;

    /// [`StatsDb`] over the relay's D1 binding.
    pub(crate) struct D1Stats<'a>(pub(crate) &'a worker::D1Database);

    impl D1Stats<'_> {
        async fn all<T: serde::de::DeserializeOwned>(
            &self,
            sql: &str,
            params: &[JsValue],
        ) -> Result<Vec<T>, String> {
            self.0
                .prepare(sql)
                .bind(params)
                .map_err(|e| e.to_string())?
                .all()
                .await
                .map_err(|e| e.to_string())?
                .results()
                .map_err(|e| e.to_string())
        }
    }

    fn ids_json(ids: &[String]) -> JsValue {
        JsValue::from_str(&serde_json::to_string(ids).unwrap_or_else(|_| "[]".into()))
    }

    impl StatsDb for D1Stats<'_> {
        async fn roots(
            &self,
            channel: &str,
            now: u64,
            limit: usize,
            indexed: bool,
        ) -> Result<Vec<RootRow>, String> {
            let mut params = vec![
                JsValue::from_str(channel),
                JsValue::from_f64(now as f64),
                JsValue::from_f64(limit as f64),
            ];
            if indexed {
                self.all(&roots_indexed_sql(), &params).await
            } else {
                params.push(JsValue::from_f64(ROOTS_VISIT_CAP as f64));
                self.all(&roots_walk_sql(), &params).await
            }
        }

        async fn stats(
            &self,
            channel: &str,
            now: u64,
            ids: &[String],
            with_counts: bool,
        ) -> Result<Vec<StatsRow>, String> {
            self.all(
                &stats_sql(with_counts),
                &[
                    JsValue::from_str(channel),
                    JsValue::from_f64(now as f64),
                    ids_json(ids),
                    JsValue::from_f64(ACTIVITY_WALK_ROWS as f64),
                    JsValue::from_f64(COUNT_VISIT_CAP as f64),
                ],
            )
            .await
        }

        async fn exists(&self, channel: &str) -> Result<bool, String> {
            #[derive(Deserialize)]
            struct Hit {
                #[allow(dead_code)]
                x: f64,
            }
            let hits: Vec<Hit> = self.all(EXISTS_SQL, &[JsValue::from_str(channel)]).await?;
            Ok(!hits.is_empty())
        }
    }
}

/// A native build's stand-in for D1: every statement fails.
#[cfg(not(target_arch = "wasm32"))]
struct NoD1;

#[cfg(not(target_arch = "wasm32"))]
impl StatsDb for NoD1 {
    async fn roots(&self, _: &str, _: u64, _: usize, _: bool) -> Result<Vec<RootRow>, String> {
        Err("no D1 binding in a native build".into())
    }
    async fn stats(&self, _: &str, _: u64, _: &[String], _: bool) -> Result<Vec<StatsRow>, String> {
        Err("no D1 binding in a native build".into())
    }
    async fn exists(&self, _: &str) -> Result<bool, String> {
        Err("no D1 binding in a native build".into())
    }
}

impl super::NostrRelayDO {
    /// Answer one `SECTION-STATS` frame (see the module docs). Never holds a
    /// subscription, so it does not count against the 20-subscription cap.
    pub(crate) async fn handle_section_stats(
        &self,
        session_id: u64,
        ip: &str,
        ws: &worker::WebSocket,
        id: &str,
        body: &serde_json::Value,
    ) {
        if !self.check_rate_limit(ip) {
            Self::send_closed(ws, id, REFUSE_RATE);
            return;
        }
        let Some(channel) = requested_channel(body) else {
            Self::send_closed(ws, id, REFUSE_INVALID);
            return;
        };
        let session_pubkey = self
            .sessions
            .borrow()
            .get(&session_id)
            .and_then(|s| s.authed_pubkey.clone());

        // Admission first, through the REQ/COUNT rule, before any cache or
        // shared computation.
        let zones = ZoneConfig::load(&self.env);
        let ctx = self.resolve_viewer_context(session_pubkey).await;
        let lookup = self.cached_channel_zone(&channel, &zones).await;
        if let Admission::Refuse(reason) = admission(&lookup, &zones, &ctx) {
            Self::send_closed(ws, id, reason);
            return;
        }

        let now = crate::auth::js_now_secs();
        if let Some(payload) = self.section_stats_cache.get(&channel, now) {
            Self::send_section_stats(ws, id, &payload);
            return;
        }
        let shared: Shared = match self.section_stats_flight.begin(&channel) {
            Role::Busy => Err("busy".into()),
            Role::Wait(slot) => slot.wait().await,
            Role::Lead(guard) => {
                let indexed = now >= self.section_stats_index_retry.get();
                let result = match self.compute_section_stats(&channel, now, indexed).await {
                    Ok((answer, index_absent)) => {
                        if index_absent {
                            self.section_stats_index_retry
                                .set(now.saturating_add(INDEX_RETRY_SECS));
                        }
                        Ok(answer.map(|a| a.payload()))
                    }
                    Err(e) => Err(e),
                };
                if let Ok(Some(payload)) = &result {
                    self.section_stats_cache
                        .insert(&channel, payload.clone(), now);
                }
                guard.finish(result.clone());
                result
            }
        };
        match shared {
            Ok(Some(payload)) => Self::send_section_stats(ws, id, &payload),
            // No such section: the same refusal as an unreadable one.
            Ok(None) => Self::send_closed(ws, id, refusal_for(&ctx)),
            Err(e) => {
                worker::console_error!("SECTION-STATS {id}: {e}");
                Self::send_closed(ws, id, REFUSE_BUSY);
            }
        }
    }

    /// The answer for an admitted request (`None`: no such section), and
    /// whether the roots index was found missing.
    #[cfg(target_arch = "wasm32")]
    async fn compute_section_stats(
        &self,
        channel: &str,
        now: u64,
        indexed: bool,
    ) -> Result<(Option<SectionAnswer>, bool), String> {
        let db = self.env.d1("DB").map_err(|e| e.to_string())?;
        compute(&d1::D1Stats(&db), channel, now, indexed).await
    }

    /// Native builds have no D1: the pipeline runs against [`NoD1`], so
    /// every request is answered busy.
    #[cfg(not(target_arch = "wasm32"))]
    async fn compute_section_stats(
        &self,
        channel: &str,
        now: u64,
        indexed: bool,
    ) -> Result<(Option<SectionAnswer>, bool), String> {
        compute(&NoD1, channel, now, indexed).await
    }

    fn send_section_stats(ws: &worker::WebSocket, id: &str, payload: &serde_json::Value) {
        Self::send(ws, &serde_json::json!([VERB, id, payload]));
    }
}

#[cfg(test)]
#[path = "section_stats_tests.rs"]
mod tests;
