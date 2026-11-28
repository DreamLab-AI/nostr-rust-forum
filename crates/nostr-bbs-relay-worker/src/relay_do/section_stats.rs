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
//! See [`compute`]: the root query walks the relay's marked roots
//! (`idx_event_tags_time` on `t = topic`), each root's last activity is an
//! index walk of at most [`ACTIVITY_WALK_ROWS`] tag rows newest first, and
//! reply counts are taken in activity order until [`COUNT_BUDGET`] replies
//! have been counted, each capped at [`REPLY_COUNT_CAP`]. Nothing scans a
//! channel's messages. The answer is memoised per channel for
//! [`MEMO_TTL_SECS`] (admission is decided before the memo is read).

use std::collections::{HashMap, HashSet};

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

/// Largest exact reply count reported. A topic with more replies reports
/// its count as unknown (`null`); the per-topic COUNT, which is snapshotted
/// for big topics, still supplies it.
pub(crate) const REPLY_COUNT_CAP: u64 = 1_000;

/// Replies counted per answer, across topics, before counting stops. Topics
/// are counted in activity order, so the top of the list has its figures.
pub(crate) const COUNT_BUDGET: u64 = 20_000;

/// Ids per activity statement (bound as one JSON array).
pub(crate) const BATCH: usize = 100;

/// Topics per count statement. The budget is checked between statements,
/// so one statement can overshoot it by at most this many capped counts.
pub(crate) const COUNT_BATCH: usize = 10;

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

/// Whether the event has expired at `now_ph` under NIP-40, as the REQ path
/// decides (`storage::query_events_checked`: the first `expiration` tag, a
/// decimal value strictly before now). Read from the row's own tags, like
/// `filter::SQL_HAS_EXPIRATION`: an `event_tags` probe on `name =
/// 'expiration'` let the planner walk every expiring row on the relay.
#[cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, reason = "SQL is run through D1 only")
)]
fn expired(alias: &str, now_ph: &str) -> String {
    format!(
        "COALESCE((SELECT CASE WHEN json_type(jt.value, '$[1]') = 'text' \
             AND json_extract(jt.value, '$[1]') <> '' \
             AND json_extract(jt.value, '$[1]') NOT GLOB '*[^0-9]*' \
             AND length(json_extract(jt.value, '$[1]')) <= 18 \
             THEN CAST(json_extract(jt.value, '$[1]') AS INTEGER) < {now_ph} ELSE 0 END \
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

/// The channel's topic roots: `?1` channel, `?2` now, `?3` row limit.
/// Columns `id`, `created_at`, `pubkey`, `sealed` (a JSON array of the
/// event's `sealed` tags). Driven from `t = topic` through
/// `idx_event_tags_time`, newest root first; each candidate is probed for
/// the channel through `idx_event_tags_lookup` and checked by its own tags.
#[cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, reason = "SQL is run through D1 only")
)]
pub(crate) fn roots_sql() -> String {
    format!(
        "SELECT ev.id AS id, ev.created_at AS created_at, ev.pubkey AS pubkey, \
         (SELECT json_group_array(json(js.value)) FROM json_each(ev.tags) js \
           WHERE json_type(js.value) = 'array' AND json_extract(js.value, '$[0]') = 'sealed') \
           AS sealed \
         FROM event_tags t CROSS JOIN events ev ON ev.id = t.event_id \
         WHERE t.name = 't' AND t.value = 'topic' AND ev.kind = 42 \
           AND EXISTS (SELECT 1 FROM event_tags c \
                       WHERE c.name = 'e' AND c.value = ?1 AND c.event_id = ev.id) \
           AND {} = ?1 AND {} IS NULL AND NOT {} \
         ORDER BY t.created_at DESC, t.event_id DESC LIMIT ?3",
        marked_e("ev", "root"),
        marked_e("ev", "reply"),
        expired("ev", "?2"),
    )
}

/// Each id's newest reply: `?1` channel, `?2` now, `?3` JSON array of ids,
/// `?4` walk limit ([`ACTIVITY_WALK_ROWS`]). Columns `v` (the id), `last`
/// (`[created_at, pubkey, sealed]` of the newest reply among the newest
/// `?4` tag rows naming the id, or NULL) and `walked` (only when `last` is
/// NULL: how many tag rows there were, at most `?4`, so the caller can tell
/// "no reply" from "walk ran out"). The walk reads `idx_event_tags_time`
/// newest first as a co-routine and stops at the first reply.
#[cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, reason = "SQL is run through D1 only")
)]
pub(crate) fn activity_sql() -> String {
    let walk = "SELECT w.event_id AS eid, w.created_at AS wat FROM event_tags w \
                WHERE w.name = 'e' AND w.value = a.v \
                ORDER BY w.created_at DESC, w.event_id DESC LIMIT ?4";
    format!(
        "SELECT a.v AS v, a.last AS last, \
         CASE WHEN a.last IS NULL THEN (SELECT COUNT(*) FROM ({walk})) ELSE 0 END AS walked \
         FROM (SELECT jv.value AS v, \
           (SELECT json_array(r.created_at, r.pubkey, {}) \
              FROM ({}) x CROSS JOIN events r ON r.id = x.eid \
              WHERE {} ORDER BY x.wat DESC, x.eid DESC LIMIT 1) AS last \
           FROM json_each(?3) jv) a",
        has_sealed("r"),
        walk.replace("a.v", "jv.value"),
        qualifies("jv.value"),
    )
}

/// Each id's reply count, capped: `?1` channel, `?2` now, `?3` JSON array of
/// ids, `?4` cap + 1. Columns `v` and `n` (at most `?4`).
#[cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, reason = "SQL is run through D1 only")
)]
pub(crate) fn counts_sql() -> String {
    format!(
        "SELECT jv.value AS v, \
         (SELECT COUNT(*) FROM (SELECT 1 FROM event_tags d CROSS JOIN events r \
            ON r.id = d.event_id WHERE d.name = 'e' AND d.value = jv.value AND {} \
            LIMIT ?4)) AS n \
         FROM json_each(?3) jv",
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

/// One row of [`roots_sql`].
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RootRow {
    pub(crate) id: String,
    pub(crate) created_at: f64,
    pub(crate) pubkey: String,
    /// JSON array of the event's `sealed` tags.
    pub(crate) sealed: Option<String>,
}

/// One row of [`activity_sql`].
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ActivityRow {
    pub(crate) v: String,
    pub(crate) walked: f64,
    pub(crate) last: Option<String>,
}

/// One row of [`counts_sql`].
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct CountRow {
    pub(crate) v: String,
    pub(crate) n: f64,
}

/// The statements [`compute`] runs, so the pipeline is the same against D1
/// and against SQLite in tests.
#[allow(async_fn_in_trait)]
pub(crate) trait StatsDb {
    /// [`roots_sql`].
    async fn roots(&self, channel: &str, now: u64, limit: usize) -> Result<Vec<RootRow>, String>;
    /// [`activity_sql`].
    async fn activity(
        &self,
        channel: &str,
        now: u64,
        ids: &[String],
    ) -> Result<Vec<ActivityRow>, String>;
    /// [`counts_sql`].
    async fn counts(
        &self,
        channel: &str,
        now: u64,
        ids: &[String],
    ) -> Result<Vec<CountRow>, String>;
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
    /// Replies, exact; `None` past [`REPLY_COUNT_CAP`] or the budget.
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

/// The topics the root rows name: sealed originals read from their tags,
/// an envelope whose original is itself listed folded into the original.
fn plan_topics(rows: Vec<RootRow>) -> Vec<TopicStat> {
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
        let created_at = r.created_at.max(0.0) as u64;
        match original {
            Some(o) if ids.contains(&o) => {
                shadow.insert(o, r.id.clone());
            }
            Some(o) => out.push(TopicStat {
                keys: vec![r.id.clone(), o.clone()],
                id: r.id,
                created_at,
                last_at: None,
                last_pubkey: None,
                replies: None,
                original: Some(o),
                root_pubkey: None,
            }),
            None => out.push(TopicStat {
                keys: vec![r.id.clone()],
                id: r.id,
                created_at,
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

/// A reply as [`activity_sql`] reports it.
fn parse_last(s: &str) -> Option<Newest> {
    let v: serde_json::Value = serde_json::from_str(s).ok()?;
    let ts = v.get(0)?.as_f64()?.max(0.0) as u64;
    let pk = v.get(1)?.as_str()?.to_string();
    let sealed = v.get(2).and_then(|x| x.as_i64()).unwrap_or(0) != 0;
    Some((ts, pk, sealed))
}

/// Compute the answer for `channel` at `now`.
///
/// Statements: one roots query (`MAX_TOPICS + 1` rows), one activity query
/// per [`BATCH`] ids, then count queries per [`COUNT_BATCH`] topics in
/// activity order until [`COUNT_BUDGET`] replies are counted. Rows visited:
/// the relay's marked roots walked by the driver (each probed once for the
/// channel), at most [`ACTIVITY_WALK_ROWS`] tag rows (and their events) per
/// listed id for activity, and at most `COUNT_BUDGET + COUNT_BATCH × 2 ×
/// (REPLY_COUNT_CAP + 1)` replies for counts, whatever the channel's size.
pub(crate) async fn compute<D: StatsDb>(
    db: &D,
    channel: &str,
    now: u64,
) -> Result<SectionAnswer, String> {
    let mut rows = db.roots(channel, now, MAX_TOPICS + 1).await?;
    let truncated = rows.len() > MAX_TOPICS;
    rows.truncate(MAX_TOPICS);
    let mut topics = plan_topics(rows);

    // Last activity for every id.
    let keys: Vec<String> = topics.iter().flat_map(|t| t.keys.clone()).collect();
    let mut activity: HashMap<String, (bool, Option<Newest>)> = HashMap::new();
    for chunk in keys.chunks(BATCH) {
        for row in db.activity(channel, now, chunk).await? {
            let exhausted = row.walked as i64 >= ACTIVITY_WALK_ROWS;
            let last = row.last.as_deref().and_then(parse_last);
            activity.insert(row.v, (exhausted, last));
        }
    }
    for t in &mut topics {
        let mut newest: Option<Newest> = None;
        let mut unknown = false;
        for k in &t.keys {
            match activity.get(k) {
                Some((_, Some(l))) => {
                    if newest.as_ref().is_none_or(|n| l.0 > n.0) {
                        newest = Some(l.clone());
                    }
                }
                // Walked its limit without a reply: the newest reply may be
                // further back; the last activity is not known.
                Some((true, None)) => unknown = true,
                Some((false, None)) => {}
                None => unknown = true,
            }
        }
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

    // Reply counts, top of the list first, within the budget.
    let mut spent: u64 = 0;
    let mut start = 0;
    while start < topics.len() && spent < COUNT_BUDGET {
        let end = (start + COUNT_BATCH).min(topics.len());
        let ids: Vec<String> = topics[start..end]
            .iter()
            .flat_map(|t| t.keys.clone())
            .collect();
        let counted: HashMap<String, u64> = db
            .counts(channel, now, &ids)
            .await?
            .into_iter()
            .map(|r| (r.v, r.n.max(0.0) as u64))
            .collect();
        for t in &mut topics[start..end] {
            let mut sum = 0u64;
            let mut capped = false;
            for k in &t.keys {
                let n = counted.get(k).copied().unwrap_or(0);
                spent += n;
                capped |= n > REPLY_COUNT_CAP;
                sum += n;
            }
            t.replies = (!capped && sum <= REPLY_COUNT_CAP).then_some(sum);
        }
        start = end;
    }

    Ok(SectionAnswer {
        channel: channel.to_string(),
        as_of: now,
        truncated,
        topics,
    })
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
        ) -> Result<Vec<RootRow>, String> {
            self.all(
                &roots_sql(),
                &[
                    JsValue::from_str(channel),
                    JsValue::from_f64(now as f64),
                    JsValue::from_f64(limit as f64),
                ],
            )
            .await
        }

        async fn activity(
            &self,
            channel: &str,
            now: u64,
            ids: &[String],
        ) -> Result<Vec<ActivityRow>, String> {
            self.all(
                &activity_sql(),
                &[
                    JsValue::from_str(channel),
                    JsValue::from_f64(now as f64),
                    ids_json(ids),
                    JsValue::from_f64(ACTIVITY_WALK_ROWS as f64),
                ],
            )
            .await
        }

        async fn counts(
            &self,
            channel: &str,
            now: u64,
            ids: &[String],
        ) -> Result<Vec<CountRow>, String> {
            self.all(
                &counts_sql(),
                &[
                    JsValue::from_str(channel),
                    JsValue::from_f64(now as f64),
                    ids_json(ids),
                    JsValue::from_f64((REPLY_COUNT_CAP + 1) as f64),
                ],
            )
            .await
        }
    }
}

/// A native build's stand-in for D1: every statement fails.
#[cfg(not(target_arch = "wasm32"))]
struct NoD1;

#[cfg(not(target_arch = "wasm32"))]
impl StatsDb for NoD1 {
    async fn roots(&self, _: &str, _: u64, _: usize) -> Result<Vec<RootRow>, String> {
        Err("no D1 binding in a native build".into())
    }
    async fn activity(&self, _: &str, _: u64, _: &[String]) -> Result<Vec<ActivityRow>, String> {
        Err("no D1 binding in a native build".into())
    }
    async fn counts(&self, _: &str, _: u64, _: &[String]) -> Result<Vec<CountRow>, String> {
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

        // Admission first, through the REQ/COUNT rule, before any cache.
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
        match self.compute_section_stats(&channel, now).await {
            Ok(Some(answer)) => {
                let payload = answer.payload();
                self.section_stats_cache
                    .insert(&channel, payload.clone(), now);
                Self::send_section_stats(ws, id, &payload);
            }
            // No such section: the same refusal as an unreadable one.
            Ok(None) => Self::send_closed(ws, id, refusal_for(&ctx)),
            Err(e) => {
                worker::console_error!("SECTION-STATS {id}: {e}");
                Self::send_closed(ws, id, REFUSE_BUSY);
            }
        }
    }

    /// The answer for an admitted request, or `None` when the section does
    /// not exist.
    #[cfg(target_arch = "wasm32")]
    async fn compute_section_stats(
        &self,
        channel: &str,
        now: u64,
    ) -> Result<Option<SectionAnswer>, String> {
        #[derive(Deserialize)]
        struct Hit {
            #[allow(dead_code)]
            x: f64,
        }
        let db = self.env.d1("DB").map_err(|e| e.to_string())?;
        let hits: Vec<Hit> = db
            .prepare(EXISTS_SQL)
            .bind(&[wasm_bindgen::JsValue::from_str(channel)])
            .map_err(|e| e.to_string())?
            .all()
            .await
            .map_err(|e| e.to_string())?
            .results()
            .map_err(|e| e.to_string())?;
        if hits.is_empty() {
            return Ok(None);
        }
        compute(&d1::D1Stats(&db), channel, now).await.map(Some)
    }

    /// Native builds have no D1: the pipeline runs against [`NoD1`], so
    /// every request is answered busy.
    #[cfg(not(target_arch = "wasm32"))]
    async fn compute_section_stats(
        &self,
        channel: &str,
        now: u64,
    ) -> Result<Option<SectionAnswer>, String> {
        compute(&NoD1, channel, now).await.map(Some)
    }

    fn send_section_stats(ws: &worker::WebSocket, id: &str, payload: &serde_json::Value) {
        Self::send(ws, &serde_json::json!([VERB, id, payload]));
    }
}

#[cfg(test)]
#[path = "section_stats_tests.rs"]
mod tests;
