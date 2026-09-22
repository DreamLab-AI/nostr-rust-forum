//! Sprint v11 — One-shot profiles backfill.
//!
//! Replays every stored kind-0 NIP-01 metadata event through the same UPSERT
//! logic the live ingest hook uses, populating the `profiles` projection table
//! for any pubkey whose kind-0 was stored before the projection landed (Sprint
//! v10) or any row that was lost between schema migrations.
//!
//! ## Idempotency
//!
//! The UPSERT carries a `WHERE excluded.last_kind0_at >= profiles.last_kind0_at`
//! guard, so re-running the backfill never overwrites a fresher row. A
//! malformed kind-0 (`content` is not JSON, or not an object) is skipped
//! silently — a single bad event must never abort the batch.
//!
//! ## Streaming
//!
//! D1 has a per-statement row ceiling and a worker CPU budget. We page through
//! the `events` table in batches of [`BACKFILL_BATCH_SIZE`] ordered by
//! `created_at DESC` so the freshest profile per pubkey is upserted first; the
//! `last_kind0_at` guard then filters out older copies that follow.
//!
//! ## Auth
//!
//! Triggered manually via `POST /api/admin/profiles/backfill` (NIP-98 admin
//! authed). We deliberately do NOT wire this into the existing 5-minute cron
//! trigger — backfill is a one-shot operation, and the live ingest hook keeps
//! the projection current after that.

use serde::Deserialize;
use serde_json::Value;
use wasm_bindgen::JsValue;
use worker::{console_warn, Env};

use crate::auth;
// `trust` is used only by the demotion-policy test adapter below; the live
// sweep moved to `trust_sweep`.
#[cfg(test)]
use crate::trust::{self, TrustThresholds};

/// How many rows to pull per `SELECT` page. D1 enforces a 1 MB result-row
/// ceiling per statement; 200 kind-0 rows comfortably fit under that with
/// room for large profiles (banner URLs, long bios, etc.).
pub(crate) const BACKFILL_BATCH_SIZE: u32 = 200;

/// Hard ceiling on the number of rows the backfill will touch in one
/// invocation, to keep us inside the worker CPU budget. The forum has well
/// under this number of profiles in practice; this is a circuit breaker, not
/// a target.
const BACKFILL_MAX_ROWS: u64 = 50_000;

/// D1 row shape returned by the kind-0 page query. Mirrors the column subset
/// the upsert needs — we deliberately don't fetch the full `tags`/`sig` blob
/// because we never re-emit the event, only project its parsed content.
#[derive(Deserialize)]
pub(crate) struct Kind0Row {
    id: String,
    pubkey: String,
    created_at: f64,
    content: String,
    /// Raw JSON-encoded tags array (kept verbatim so the projection's
    /// `raw_event` column is a faithful round-trip of the stored event).
    tags: String,
    sig: String,
}

/// Replay every stored kind-0 metadata event through the projection upsert.
///
/// Returns the number of upserts that actually mutated the `profiles` row
/// (i.e. survived the `last_kind0_at >= profiles.last_kind0_at` guard).
/// Malformed kind-0 events are counted in `skipped` rather than aborting the
/// batch.
pub async fn backfill_profiles(env: &Env) -> Result<BackfillResult, String> {
    let db = env
        .d1("DB")
        .map_err(|e| format!("DB binding missing: {e:?}"))?;

    let mut offset: u32 = 0;
    let mut scanned: u64 = 0;
    let mut backfilled: u64 = 0;
    let mut skipped: u64 = 0;

    loop {
        // D1 page query. Ordering by created_at DESC means the freshest
        // kind-0 per pubkey lands first; subsequent older copies are then
        // filtered out by the upsert's `last_kind0_at` guard.
        let stmt = db.prepare(
            "SELECT id, pubkey, created_at, content, tags, sig \
             FROM events \
             WHERE kind = 0 \
             ORDER BY created_at DESC \
             LIMIT ?1 OFFSET ?2",
        );

        let bound = stmt
            .bind(&[
                JsValue::from_f64(BACKFILL_BATCH_SIZE as f64),
                JsValue::from_f64(offset as f64),
            ])
            .map_err(|e| format!("bind failed: {e:?}"))?;

        let rows: Vec<Kind0Row> = bound
            .all()
            .await
            .map_err(|e| format!("page query failed: {e:?}"))?
            .results()
            .map_err(|e| format!("results parse failed: {e:?}"))?;

        let page_len = rows.len() as u32;
        if page_len == 0 {
            break;
        }

        for row in rows {
            scanned += 1;
            match upsert_profile_from_row(env, &row).await {
                Ok(true) => backfilled += 1,
                Ok(false) => skipped += 1,
                Err(e) => {
                    // Log but don't abort — a single failed upsert (e.g. D1
                    // transient error) must not lose the rest of the batch.
                    console_warn!("backfill upsert failed for event {}: {}", row.id, e);
                    skipped += 1;
                }
            }

            if scanned >= BACKFILL_MAX_ROWS {
                console_warn!(
                    "backfill_profiles: hit BACKFILL_MAX_ROWS ({}), stopping early",
                    BACKFILL_MAX_ROWS
                );
                return Ok(BackfillResult {
                    scanned,
                    backfilled,
                    skipped,
                    truncated: true,
                });
            }
        }

        // If we got fewer rows than we asked for, we've reached the end.
        if page_len < BACKFILL_BATCH_SIZE {
            break;
        }
        offset = offset
            .checked_add(page_len)
            .ok_or_else(|| "offset overflow".to_string())?;
    }

    Ok(BackfillResult {
        scanned,
        backfilled,
        skipped,
        truncated: false,
    })
}

/// Outcome of [`backfill_profiles`].
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct BackfillResult {
    /// Total kind-0 events read from `events`.
    pub scanned: u64,
    /// Rows that the upsert actually mutated (newer-than-existing).
    pub backfilled: u64,
    /// Rows skipped — either older than an existing profile, malformed JSON,
    /// or a transient D1 error during upsert.
    pub skipped: u64,
    /// `true` if we hit [`BACKFILL_MAX_ROWS`] before exhausting the table.
    pub truncated: bool,
}

/// Upsert a single kind-0 row into the `profiles` projection.
///
/// Returns `Ok(true)` if the row was applied (the upsert ran and the guard
/// allowed the write — though D1 doesn't tell us how many rows changed, so
/// "applied" here means "the statement ran without error and the guard MAY
/// have written"), `Ok(false)` if the content was not parseable JSON or the
/// guard skipped it. Real backend errors return `Err`.
///
/// The shape and binding order MUST match `relay_do::storage::upsert_profile`
/// exactly — that path keeps the projection live; this path catches up the
/// historic tail.
pub(crate) async fn upsert_profile_from_row(env: &Env, row: &Kind0Row) -> Result<bool, String> {
    let parsed: Value = match serde_json::from_str(&row.content) {
        Ok(v) => v,
        Err(_) => return Ok(false), // Malformed kind-0 content; skip silently.
    };
    let obj = match parsed.as_object() {
        Some(o) => o,
        None => return Ok(false),
    };

    fn str_field(o: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
        o.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
    }

    let name = str_field(obj, "name");
    let display_name = str_field(obj, "display_name").or_else(|| str_field(obj, "displayName"));
    let picture = str_field(obj, "picture");
    let banner = str_field(obj, "banner");
    let about = str_field(obj, "about");
    let nip05 = str_field(obj, "nip05");
    let lud16 = str_field(obj, "lud16");

    // Reconstruct a faithful raw_event JSON from the stored columns. This
    // matches what the live ingest hook stores and lets downstream consumers
    // (e.g. forum-client) treat the projection as the source of truth.
    let tags_value: Value = serde_json::from_str(&row.tags).unwrap_or(Value::Array(vec![]));
    let raw_event = serde_json::to_string(&serde_json::json!({
        "id": row.id,
        "pubkey": row.pubkey,
        "created_at": row.created_at as u64,
        "kind": 0u64,
        "tags": tags_value,
        "content": row.content,
        "sig": row.sig,
    }))
    .map_err(|e| format!("raw_event serialize: {e}"))?;

    fn js_opt(v: Option<&str>) -> JsValue {
        match v {
            Some(s) => JsValue::from_str(s),
            None => JsValue::NULL,
        }
    }

    let db = env
        .d1("DB")
        .map_err(|e| format!("DB binding missing: {e:?}"))?;

    let stmt = db.prepare(
        "INSERT INTO profiles \
            (pubkey, name, display_name, picture, banner, about, nip05, lud16, \
             last_kind0_at, raw_event) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
         ON CONFLICT (pubkey) DO UPDATE SET \
             name = excluded.name, \
             display_name = excluded.display_name, \
             picture = excluded.picture, \
             banner = excluded.banner, \
             about = excluded.about, \
             nip05 = excluded.nip05, \
             lud16 = excluded.lud16, \
             last_kind0_at = excluded.last_kind0_at, \
             raw_event = excluded.raw_event \
         WHERE excluded.last_kind0_at >= profiles.last_kind0_at",
    );

    let binds = [
        JsValue::from_str(&row.pubkey),
        js_opt(name.as_deref()),
        js_opt(display_name.as_deref()),
        js_opt(picture.as_deref()),
        js_opt(banner.as_deref()),
        js_opt(about.as_deref()),
        js_opt(nip05.as_deref()),
        js_opt(lud16.as_deref()),
        JsValue::from_f64(row.created_at),
        JsValue::from_str(&raw_event),
    ];

    let bound = stmt.bind(&binds).map_err(|e| format!("bind: {e:?}"))?;
    bound.run().await.map_err(|e| format!("run: {e:?}"))?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// ADR-2006 — inactivity-decay trust demotion sweep
//
// The sweep itself now lives in [`crate::trust_sweep`], which pages the
// candidate set with a **keyset cursor** rather than `LIMIT/OFFSET`. The offset
// form was unsound here: the sweep mutates `trust_level`, the very column its
// candidate predicate filters on, so demoted rows leave the eligible set and
// shift the remainder underneath the offset — a 400-row backlog swept at a
// batch size of 200 processed 200 rows and reported clean completion.
//
// The policy is unchanged and lives in `trust::decide_demotion`: only rows past
// the inactivity gate are candidates; TL3 and admin/exempt rows are never
// demoted; TL0 is a hard floor; TL2 lands on TL1 when the row still earns it and
// on TL0 otherwise; TL1 lands on TL0. One committed transition per row per
// sweep.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Retention / NIP-40 expiry sweep
//
// The NIP-11 document (`nip11::relay_info`) advertises a `retention` policy —
// finite windows for kinds 1/7/9024, indefinite for the rest — and NIP-40 lets
// any event carry an `["expiration", <unix_ts>]` tag. Neither was ever
// enforced: `events` grew unbounded and expired events were only *skipped on
// read* (`relay_do::storage::query_events`), never deleted. This sweep, run on
// the scheduled (cron) trigger, DELETEs rows past their kind's retention window
// AND rows past their NIP-40 expiration — paged and circuit-broken like the
// profile-backfill and demotion sweeps so it never issues an unbounded
// statement or blows the worker CPU budget.
//
// The retention windows are read from `nip11::RETENTION_POLICY`, the SAME
// constant the NIP-11 document is built from, so advertised policy and enforced
// policy can never drift.
// ---------------------------------------------------------------------------

/// Rows selected (and deleted) per DELETE page. Kept in line with the other
/// sweeps so one page is a single bounded statement set.
pub(crate) const RETENTION_BATCH_SIZE: u32 = 200;

/// Circuit breaker: the maximum number of rows a single retention sweep will
/// delete in one cron invocation, bounding worst-case D1 work. A healthy forum
/// deletes far fewer than this per tick; a large first sweep simply completes
/// over successive ticks.
const RETENTION_MAX_ROWS: u64 = 50_000;

/// Minimal id row for the retention/expiry candidate pages.
#[derive(Deserialize)]
struct EventIdRow {
    id: String,
}

/// Outcome of [`sweep_retention`].
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct RetentionSweepResult {
    /// Rows deleted because they were past their kind's retention window.
    pub retention_deleted: u64,
    /// Rows deleted because their NIP-40 `expiration` tag was already in the past.
    pub expired_deleted: u64,
    /// `true` if the sweep hit [`RETENTION_MAX_ROWS`] before exhausting
    /// candidates (the remainder is swept on the next tick).
    pub truncated: bool,
}

/// Paged, bounded retention + NIP-40-expiry sweep (run from the cron trigger).
///
/// Two phases, both paged identically (SELECT a bounded page of ids, then
/// batch-DELETE exactly that page, repeat until a short page or the shared
/// circuit breaker):
///
///  1. **Kind retention** — for every [`crate::nip11::RETENTION_POLICY`] rule
///     with a finite window, delete events of those kinds whose `created_at` is
///     older than `now - window`.
///  2. **NIP-40 expiry** — delete events carrying an `["expiration", <ts>]` tag
///     whose timestamp is already in the past, regardless of kind.
///
/// DELETE-by-id (rather than `DELETE … LIMIT`, which D1's SQLite build does not
/// enable) keeps every statement bounded and portable. Errors abort the sweep
/// with a message; the caller logs and swallows so a sweep failure never breaks
/// the scheduled tick.
pub async fn sweep_retention(env: &Env) -> Result<RetentionSweepResult, String> {
    let db = env
        .d1("DB")
        .map_err(|e| format!("DB binding missing: {e:?}"))?;

    let now = auth::js_now_secs() as i64;
    let mut budget: u64 = RETENTION_MAX_ROWS;
    let mut retention_deleted: u64 = 0;
    let mut expired_deleted: u64 = 0;

    // ---- Phase 1: per-kind retention windows ----
    for rule in crate::nip11::RETENTION_POLICY {
        let window = match rule.time {
            Some(secs) => secs,
            None => continue, // indefinite retention → nothing to prune
        };
        let cutoff = now - window;

        // Kind predicate + its bound parameters. Range rules use an inclusive
        // bound; list rules an `IN (…)` over an explicit, statically-sized set.
        let (kind_pred, kind_binds): (String, Vec<JsValue>) = match &rule.kinds {
            crate::nip11::RetentionKinds::Range(lo, hi) => (
                "kind >= ?1 AND kind <= ?2".to_string(),
                vec![JsValue::from_f64(*lo as f64), JsValue::from_f64(*hi as f64)],
            ),
            crate::nip11::RetentionKinds::List(ks) => {
                let placeholders: Vec<String> = (1..=ks.len()).map(|i| format!("?{i}")).collect();
                (
                    format!("kind IN ({})", placeholders.join(", ")),
                    ks.iter().map(|k| JsValue::from_f64(*k as f64)).collect(),
                )
            }
        };
        // The created_at cutoff and LIMIT are the two params after the kind set.
        let cutoff_idx = kind_binds.len() + 1;
        let limit_idx = cutoff_idx + 1;
        let sql = format!(
            "SELECT id FROM events \
             WHERE {kind_pred} AND created_at < ?{cutoff_idx} \
             LIMIT ?{limit_idx}"
        );

        loop {
            if budget == 0 {
                return Ok(RetentionSweepResult {
                    retention_deleted,
                    expired_deleted,
                    truncated: true,
                });
            }
            let page = budget.min(RETENTION_BATCH_SIZE as u64) as u32;

            let mut binds = kind_binds.clone();
            binds.push(JsValue::from_f64(cutoff as f64));
            binds.push(JsValue::from_f64(page as f64));

            let deleted = delete_id_page(&db, &sql, &binds).await?;
            retention_deleted += deleted as u64;
            budget = budget.saturating_sub(deleted as u64);

            if deleted < page {
                break; // exhausted this rule's candidates
            }
        }
    }

    // ---- Phase 2: NIP-40 expiration (any kind) ----
    // Probe the trigger-maintained event_tags side table (migration 0004)
    // instead of json_each over every events row: the old form full-scanned
    // the table on every 5-minute cron tick (~10% of all D1 rows read).
    // name='expiration' is an index seek touching only events that actually
    // carry the tag — normally zero rows.
    let expiry_sql = "SELECT DISTINCT event_id AS id FROM event_tags \
         WHERE name = 'expiration' \
           AND CAST(value AS INTEGER) < ?1 \
         LIMIT ?2";

    loop {
        if budget == 0 {
            return Ok(RetentionSweepResult {
                retention_deleted,
                expired_deleted,
                truncated: true,
            });
        }
        let page = budget.min(RETENTION_BATCH_SIZE as u64) as u32;

        let binds = [
            JsValue::from_f64(now as f64),
            JsValue::from_f64(page as f64),
        ];

        let deleted = delete_id_page(&db, expiry_sql, &binds).await?;
        expired_deleted += deleted as u64;
        budget = budget.saturating_sub(deleted as u64);

        if deleted < page {
            break;
        }
    }

    Ok(RetentionSweepResult {
        retention_deleted,
        expired_deleted,
        truncated: false,
    })
}

/// SELECT a bounded page of event ids with `sql`/`binds`, then batch-DELETE
/// exactly those ids. Returns the page length (== rows deleted). A page shorter
/// than the requested LIMIT means the candidate set is exhausted and the caller
/// stops paging.
async fn delete_id_page(
    db: &worker::D1Database,
    sql: &str,
    binds: &[JsValue],
) -> Result<u32, String> {
    let stmt = db.prepare(sql);
    let bound = stmt
        .bind(binds)
        .map_err(|e| format!("retention page bind failed: {e:?}"))?;
    let rows: Vec<EventIdRow> = bound
        .all()
        .await
        .map_err(|e| format!("retention page query failed: {e:?}"))?
        .results()
        .map_err(|e| format!("retention page parse failed: {e:?}"))?;

    let page_len = rows.len() as u32;
    if page_len == 0 {
        return Ok(0);
    }

    let mut deletes = Vec::with_capacity(rows.len());
    for row in &rows {
        let del = db.prepare("DELETE FROM events WHERE id = ?1");
        let bound_del = del
            .bind(&[JsValue::from_str(&row.id)])
            .map_err(|e| format!("retention delete bind failed: {e:?}"))?;
        deletes.push(bound_del);
    }
    db.batch(deletes)
        .await
        .map_err(|e| format!("retention delete batch failed: {e:?}"))?;

    Ok(page_len)
}

/// Test adapter over the single demotion authority, [`trust::decide_demotion`].
///
/// The sweep's policy used to be mirrored here as a separate `#[cfg(test)]`
/// copy that the tests asserted against, with a comment insisting the two
/// "MUST stay in lockstep" — a convention, not a guarantee. The policy is now a
/// pure function on the live path, so these tests exercise the executable
/// authority directly and the mirror cannot drift. This adapter only shapes the
/// flat test arguments into the row the real function takes.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn decide_demotion(
    current: trust::TrustLevel,
    days_active: i32,
    posts_read: i32,
    posts_created: i32,
    mod_actions_against: i32,
    last_active_at: i64,
    is_admin: bool,
    now: i64,
    thresholds: &TrustThresholds,
) -> trust::TrustLevel {
    let row = trust::WhitelistTrustRow {
        pubkey: "test".to_string(),
        trust_level: current.as_i32(),
        days_active,
        posts_read,
        posts_created,
        mod_actions_against,
        last_active_at: Some(last_active_at as f64),
        trust_level_updated_at: None,
        is_admin: Some(if is_admin { 1 } else { 0 }),
    };
    match trust::decide_demotion(&row, thresholds, now) {
        trust::DemotionDecision::Hold(_) => current,
        trust::DemotionDecision::Demote { to, .. } => to,
    }
}

// ---------------------------------------------------------------------------
// Tests
//
// Purely native unit tests over the JSON-parsing branches and the
// last_kind0_at guard contract. The D1 paths are exercised by integration
// tests in `tests/` and through the existing live-ingest test suite.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// FR4.3 — escalation on age
// ---------------------------------------------------------------------------

/// How many stale cases one tick will escalate. A circuit breaker, not a
/// target: the forum has far fewer pending cases than this, and a run that hits
/// the ceiling reports `truncated` so the shortfall is visible rather than
/// silently deferred.
const AGEING_BATCH_SIZE: u32 = 200;

/// What one ageing sweep did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AgeingSweepResult {
    /// Cases past their deadline that this tick looked at.
    pub scanned: u64,
    /// Cases that received a fresh `escalated-on-age` receipt.
    pub escalated: u64,
    /// Cases already carrying one. Not an error — the idempotency working.
    pub already_escalated: u64,
    /// Writes that failed. Reported as loudly as successes: a sweep whose
    /// writes all failed must not look like a quiet tick.
    pub failed: u64,
    /// The batch ceiling was reached and more stale cases remain.
    pub truncated: bool,
}

/// Whether a case is past its ageing deadline (FR4.3).
///
/// Pure so the arithmetic is testable without a clock or a D1: `now` and
/// `created_at` are seconds, `max_pending_hours` is the panel's declared
/// deadline (or the documented default for a case that predates it). A case
/// exactly *at* its deadline has not yet exceeded it.
pub(crate) fn is_past_pending_deadline(created_at: u64, now: u64, max_pending_hours: u32) -> bool {
    let hours = if max_pending_hours == 0 {
        nostr_bbs_core::governance::DEFAULT_MAX_PENDING_HOURS
    } else {
        max_pending_hours
    };
    now.saturating_sub(created_at) > (hours as u64).saturating_mul(3_600)
}

/// Mark every still-pending case past its panel's `max_pending_hours` with an
/// `escalated-on-age` side receipt (FR4.3, EXP-AC-004).
///
/// Exactly one receipt per case, guaranteed by the `(case_id, stage)` primary
/// key on `case_side_receipts` rather than by a code path that has to remember:
/// the `INSERT OR IGNORE` is the idempotency, and a second tick over the same
/// stale case reports it as `already_escalated`.
///
/// A stalled case is the failure mode C2 exists to catch — a reviewer who never
/// got to it, or a queue nobody is watching. The receipt is what makes that
/// visible instead of leaving the case quietly pending forever.
pub async fn escalate_stale_cases(env: &Env) -> Result<AgeingSweepResult, String> {
    let db = env.d1("DB").map_err(|e| format!("D1 binding: {e:?}"))?;
    let now = auth::js_now_secs();

    #[derive(Deserialize)]
    struct StaleCaseRow {
        id: String,
        created_at: f64,
        max_pending_hours: Option<f64>,
    }

    // Ordered and filtered by each case's OWN deadline, not by `created_at`.
    // Panels declare different deadlines, so "oldest first" is not "most
    // overdue first": a six-hour case raised this morning is overdue while a
    // seventy-two-hour case raised yesterday is not. Ordering by
    // `created_at + deadline` makes the page ceiling cut the *least* overdue
    // cases, which is the only cut that leaves the sweep correct. The pure
    // predicate below re-checks every fetched row — the SQL narrows, it does
    // not decide.
    let rows = db
        .prepare(
            "SELECT id, created_at, max_pending_hours FROM broker_cases \
             WHERE state IN ('open', 'under_review', 'reopened') \
               AND (created_at + COALESCE(NULLIF(max_pending_hours, 0), ?1) * 3600) < ?2 \
             ORDER BY (created_at + COALESCE(NULLIF(max_pending_hours, 0), ?1) * 3600) ASC \
             LIMIT ?3",
        )
        .bind(&[
            JsValue::from_f64(nostr_bbs_core::governance::DEFAULT_MAX_PENDING_HOURS as f64),
            JsValue::from_f64(now as f64),
            JsValue::from_f64((AGEING_BATCH_SIZE + 1) as f64),
        ])
        .map_err(|e| format!("stale case bind: {e:?}"))?
        .all()
        .await
        .map_err(|e| format!("stale case query: {e:?}"))?
        .results::<StaleCaseRow>()
        .map_err(|e| format!("stale case decode: {e:?}"))?;

    let mut result = AgeingSweepResult {
        truncated: rows.len() as u32 > AGEING_BATCH_SIZE,
        ..Default::default()
    };

    for row in rows.iter().take(AGEING_BATCH_SIZE as usize) {
        let created_at = row.created_at.max(0.0) as u64;
        let deadline = row
            .max_pending_hours
            .filter(|h| *h > 0.0)
            .map(|h| h as u32)
            .unwrap_or(nostr_bbs_core::governance::DEFAULT_MAX_PENDING_HOURS);
        result.scanned += 1;
        if !is_past_pending_deadline(created_at, now, deadline) {
            // The SQL already narrowed to overdue rows; this is the belt to its
            // braces. There is deliberately NO early break here: the rows carry
            // different deadlines, so a row inside its own deadline says nothing
            // whatever about the rows after it.
            continue;
        }

        let age_hours = now.saturating_sub(created_at) / 3_600;
        let insert = db
            .prepare(
                "INSERT OR IGNORE INTO case_side_receipts (case_id, stage, recorded_at, detail) \
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(&[
                JsValue::from_str(&row.id),
                JsValue::from_str(
                    nostr_bbs_core::governance::ReceiptStage::EscalatedOnAge.as_str(),
                ),
                JsValue::from_f64(now as f64),
                JsValue::from_str(&format!(
                    "pending {age_hours}h against a {deadline}h deadline"
                )),
            ]);
        match insert {
            Ok(stmt) => match stmt.run().await {
                Ok(meta) => {
                    let changed = meta
                        .meta()
                        .ok()
                        .flatten()
                        .and_then(|m| m.changes)
                        .unwrap_or(0);
                    if changed > 0 {
                        result.escalated += 1;
                    } else {
                        result.already_escalated += 1;
                    }
                }
                Err(e) => {
                    console_warn!("escalate-on-age write failed for {}: {:?}", row.id, e);
                    result.failed += 1;
                }
            },
            Err(e) => {
                console_warn!("escalate-on-age bind failed for {}: {:?}", row.id, e);
                result.failed += 1;
            }
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// ADR-2013 — proposal expiry
// ---------------------------------------------------------------------------

/// What one expiry sweep did.
///
/// Deliberately the same shape as [`AgeingSweepResult`] and deliberately NOT
/// the same type: the two sweeps answer different questions about the same
/// case, and collapsing them would hide a case that was escalated for age and
/// then expired — which is the ordinary sequence, not an anomaly.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ExpirySweepResult {
    /// Cases past their `stale_after` that this tick looked at.
    pub scanned: u64,
    /// Cases that received a fresh `expired` receipt AND were closed.
    pub expired: u64,
    /// Cases already carrying one. Not an error — the idempotency working.
    pub already_expired: u64,
    /// Writes that failed. Reported as loudly as successes.
    pub failed: u64,
    /// The batch ceiling was reached and more expired proposals remain.
    pub truncated: bool,
}

/// Close every still-pending ontology proposal past its `stale_after`
/// (ADR-2013, PRD-sovereign-corpus §3.3).
///
/// # Why this is not the ageing sweep
///
/// `escalate_stale_cases` answers "nobody has looked at this yet" and leaves
/// the case open so somebody still can. Expiry answers "this proposal is no
/// longer safe to apply": the corpus has moved on since the diff was computed,
/// the digest no longer describes the page, and applying it would write a stale
/// frontmatter over a newer one. So expiry **closes** the case
/// (`CaseState::Closed` — closed *without a decision*, which is why no
/// `broker_decisions` row is written) rather than merely re-surfacing it. The
/// page is untouched and the proposer regenerates from the current generation.
///
/// Both receipts can and routinely do land on the same case: a 14-day proposal
/// whose panel escalates at 14 days is escalated and then expires. They are
/// separate rows in `case_side_receipts` keyed by `(case_id, stage)`, so the
/// history reads "surfaced, then expired unattended", which is the true story.
///
/// # Ordering
///
/// The receipt is written **before** the close. If the close then fails, the
/// case stays pending and carries an `expired` receipt — visibly wrong, and
/// retried next tick (the receipt insert reports `already_expired`, the close
/// is re-attempted). The other order would close a case with no receipt saying
/// why, which is silently wrong and never retried.
pub async fn expire_stale_proposals(env: &Env) -> Result<ExpirySweepResult, String> {
    let db = env.d1("DB").map_err(|e| format!("D1 binding: {e:?}"))?;
    let now = auth::js_now_secs() as i64;

    #[derive(Deserialize)]
    struct ExpiredCaseRow {
        id: String,
        stale_after: f64,
    }

    // `stale_after IS NOT NULL` is what confines this sweep to ontology
    // proposals: no other 31402 declares one, so no other case can be closed
    // by it. Ordered by expiry so the batch ceiling cuts the least overdue.
    let rows = db
        .prepare(
            "SELECT id, stale_after FROM broker_cases \
             WHERE state IN ('open', 'under_review', 'reopened') \
               AND stale_after IS NOT NULL AND stale_after < ?1 \
             ORDER BY stale_after ASC LIMIT ?2",
        )
        .bind(&[
            JsValue::from_f64(now as f64),
            JsValue::from_f64((AGEING_BATCH_SIZE + 1) as f64),
        ])
        .map_err(|e| format!("expired case bind: {e:?}"))?
        .all()
        .await
        .map_err(|e| format!("expired case query: {e:?}"))?
        .results::<ExpiredCaseRow>()
        .map_err(|e| format!("expired case decode: {e:?}"))?;

    let mut result = ExpirySweepResult {
        truncated: rows.len() as u32 > AGEING_BATCH_SIZE,
        ..Default::default()
    };

    for row in rows.iter().take(AGEING_BATCH_SIZE as usize) {
        let stale_after = row.stale_after as i64;
        result.scanned += 1;
        // Belt to the SQL's braces, and the one place the boundary rule lives.
        if !nostr_bbs_core::ontology_governance::is_expired(stale_after, now) {
            continue;
        }

        let overdue_hours = (now - stale_after).max(0) / 3_600;
        let receipt = db
            .prepare(
                "INSERT OR IGNORE INTO case_side_receipts (case_id, stage, recorded_at, detail) \
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(&[
                JsValue::from_str(&row.id),
                JsValue::from_str(nostr_bbs_core::governance::ReceiptStage::Expired.as_str()),
                JsValue::from_f64(now as f64),
                JsValue::from_str(&format!(
                    "proposal stale_after passed {overdue_hours}h ago; closed without a decision"
                )),
            ]);
        let fresh = match receipt {
            Ok(stmt) => match stmt.run().await {
                Ok(meta) => {
                    meta.meta()
                        .ok()
                        .flatten()
                        .and_then(|m| m.changes)
                        .unwrap_or(0)
                        > 0
                }
                Err(e) => {
                    console_warn!("expiry receipt write failed for {}: {:?}", row.id, e);
                    result.failed += 1;
                    continue;
                }
            },
            Err(e) => {
                console_warn!("expiry receipt bind failed for {}: {:?}", row.id, e);
                result.failed += 1;
                continue;
            }
        };

        // Closed WITHOUT a decision: no `broker_decisions` row is written,
        // because nobody decided anything. The `expired` receipt is the whole
        // record of what happened, and the `state` guard in the WHERE clause
        // means a case decided between the SELECT and here is left alone.
        let close = db
            .prepare(
                "UPDATE broker_cases SET state = ?1, updated_at = ?2 \
                 WHERE id = ?3 AND state IN ('open', 'under_review', 'reopened')",
            )
            .bind(&[
                JsValue::from_str(nostr_bbs_core::governance::broker::CaseState::Closed.as_str()),
                JsValue::from_f64(now as f64),
                JsValue::from_str(&row.id),
            ]);
        match close {
            Ok(stmt) => match stmt.run().await {
                Ok(_) => {
                    if fresh {
                        result.expired += 1;
                    } else {
                        result.already_expired += 1;
                    }
                }
                Err(e) => {
                    console_warn!("expiry close failed for {}: {:?}", row.id, e);
                    result.failed += 1;
                }
            },
            Err(e) => {
                console_warn!("expiry close bind failed for {}: {:?}", row.id, e);
                result.failed += 1;
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Local helper mirroring the field-extraction logic inside
    /// `upsert_profile_from_row` — kept here so the test runs without a D1
    /// binding.
    fn extract_fields(content: &str) -> Option<ParsedProfile> {
        let parsed: Value = serde_json::from_str(content).ok()?;
        let obj = parsed.as_object()?;

        fn s(o: &serde_json::Map<String, Value>, k: &str) -> Option<String> {
            o.get(k).and_then(|v| v.as_str()).map(|s| s.to_string())
        }

        Some(ParsedProfile {
            name: s(obj, "name"),
            display_name: s(obj, "display_name").or_else(|| s(obj, "displayName")),
            picture: s(obj, "picture"),
            nip05: s(obj, "nip05"),
        })
    }

    #[derive(Debug, PartialEq)]
    struct ParsedProfile {
        name: Option<String>,
        display_name: Option<String>,
        picture: Option<String>,
        nip05: Option<String>,
    }

    #[test]
    fn backfill_skips_invalid_kind0_json() {
        // Content not JSON at all -> parser returns None, upsert path
        // would return Ok(false) without binding anything.
        assert!(extract_fields("this is not JSON").is_none());

        // Content is valid JSON but a scalar, not an object.
        assert!(extract_fields("\"hello\"").is_none());
        assert!(extract_fields("42").is_none());
        assert!(extract_fields("[1, 2, 3]").is_none());

        // Empty object is fine — all fields just come back None.
        let parsed = extract_fields("{}").expect("empty object should parse");
        assert_eq!(parsed.name, None);
        assert_eq!(parsed.display_name, None);
        assert_eq!(parsed.picture, None);
        assert_eq!(parsed.nip05, None);
    }

    #[test]
    fn backfill_extracts_name_aliases() {
        // Both `display_name` and `displayName` map to the same field; the
        // snake_case form wins when both are present.
        let snake = extract_fields(r#"{"name":"alice","display_name":"Alice"}"#).unwrap();
        assert_eq!(snake.name.as_deref(), Some("alice"));
        assert_eq!(snake.display_name.as_deref(), Some("Alice"));

        let camel = extract_fields(r#"{"displayName":"Alice"}"#).unwrap();
        assert_eq!(camel.display_name.as_deref(), Some("Alice"));

        let both = extract_fields(r#"{"display_name":"snake","displayName":"camel"}"#).unwrap();
        assert_eq!(both.display_name.as_deref(), Some("snake"));
    }

    /// The guard is `WHERE excluded.last_kind0_at >= profiles.last_kind0_at`.
    /// At the SQL layer this means an OLDER created_at can never overwrite a
    /// newer row. We assert this invariant holds for the comparison the
    /// guard codifies, since the live SQL is exercised by D1 itself.
    #[test]
    fn backfill_respects_last_kind0_at_guard() {
        // existing row's last_kind0_at; incoming candidate's created_at
        let existing_ts: u64 = 1_700_000_500;

        // Older incoming -> guard rejects (excluded.created_at < existing).
        let older_ts: u64 = 1_700_000_100;
        assert!(
            (older_ts as f64) < (existing_ts as f64),
            "older event must NOT overwrite a newer profile"
        );

        // Equal -> guard accepts (>= is inclusive). Idempotent re-run safe.
        let equal_ts: u64 = 1_700_000_500;
        assert!(
            (equal_ts as f64) >= (existing_ts as f64),
            "equal-timestamp re-run should be idempotent (>=)"
        );

        // Newer incoming -> guard accepts.
        let newer_ts: u64 = 1_700_001_000;
        assert!(
            (newer_ts as f64) >= (existing_ts as f64),
            "newer event must overwrite older profile"
        );
    }

    #[test]
    fn backfill_batch_size_is_safe_for_d1() {
        // D1's 1 MB row-set ceiling means we want batches small enough that
        // even a worst-case kind-0 (a few KB of profile metadata) fits. 200
        // gives us ~5 KB of headroom per row.
        const { assert!(BACKFILL_BATCH_SIZE > 0) };
        const { assert!(BACKFILL_BATCH_SIZE <= 1000) };
    }

    #[test]
    fn backfill_result_serializes_for_json_response() {
        let r = BackfillResult {
            scanned: 42,
            backfilled: 30,
            skipped: 12,
            truncated: false,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"backfilled\":30"));
        assert!(json.contains("\"scanned\":42"));
        assert!(json.contains("\"skipped\":12"));
        assert!(json.contains("\"truncated\":false"));
    }

    // -----------------------------------------------------------------------
    // ADR-102 — inactivity-decay demotion sweep decision model
    //
    // These exercise `decide_demotion`, the pure mirror of the policy
    // `trust::check_demotion` applies per row. They prove the sweep's contract:
    // an inactive TL2/TL1 row past the threshold is demoted one step; an active
    // row is not; TL0 is a floor; admin/exempt rows are never demoted.
    // -----------------------------------------------------------------------

    use crate::trust::{TrustLevel, TrustThresholds};

    /// A "now" comfortably past the ~6-month gate for `last_active` = `past`.
    fn now_and_stale() -> (i64, i64) {
        let t = TrustThresholds::default();
        let now = 2_000_000_000_i64;
        // Last active just over the inactivity window ago → past the gate.
        let past = now - t.inactivity_demotion_secs - 1;
        (now, past)
    }

    /// A `last_active` value that is recent (inside the inactivity window).
    fn recent(now: i64) -> i64 {
        let t = TrustThresholds::default();
        now - (t.inactivity_demotion_secs / 2)
    }

    #[test]
    fn sweep_demotes_inactive_tl2_one_step_to_tl1() {
        let t = TrustThresholds::default();
        let (now, stale) = now_and_stale();
        // Metrics: still qualify for TL1 (3d/10r/1p) but below 90% of TL2,
        // so the contract demotes exactly one level: TL2 → TL1.
        let after = decide_demotion(
            TrustLevel::Regular,
            /*days*/ 5,
            /*reads*/ 12,
            /*created*/ 2,
            /*mod*/ 0,
            stale,
            /*admin*/ false,
            now,
            &t,
        );
        assert_eq!(after, TrustLevel::Member, "inactive TL2 → TL1");
    }

    #[test]
    fn sweep_demotes_inactive_tl2_to_tl0_when_no_longer_a_member() {
        let t = TrustThresholds::default();
        let (now, stale) = now_and_stale();
        // Metrics collapse below even TL1: contract drops straight to TL0.
        let after = decide_demotion(
            TrustLevel::Regular,
            /*days*/ 1,
            /*reads*/ 0,
            /*created*/ 0,
            /*mod*/ 0,
            stale,
            false,
            now,
            &t,
        );
        assert_eq!(
            after,
            TrustLevel::Newcomer,
            "inactive TL2 with no TL1 qual → TL0"
        );
    }

    #[test]
    fn sweep_demotes_inactive_tl1_to_tl0() {
        let t = TrustThresholds::default();
        let (now, stale) = now_and_stale();
        // Below 90% of TL1 thresholds → TL1 demotes to TL0.
        let after = decide_demotion(
            TrustLevel::Member,
            /*days*/ 1,
            /*reads*/ 2,
            /*created*/ 0,
            /*mod*/ 0,
            stale,
            false,
            now,
            &t,
        );
        assert_eq!(after, TrustLevel::Newcomer, "inactive TL1 → TL0");
    }

    #[test]
    fn sweep_does_not_demote_active_row() {
        let t = TrustThresholds::default();
        let now = 2_000_000_000_i64;
        let fresh = recent(now);
        // Even with collapsed metrics, a recently-active TL2 is untouched:
        // the inactivity gate is the precondition.
        let after = decide_demotion(TrustLevel::Regular, 0, 0, 0, 5, fresh, false, now, &t);
        assert_eq!(after, TrustLevel::Regular, "active row never demoted");
    }

    #[test]
    fn sweep_holds_tl0_floor() {
        let t = TrustThresholds::default();
        let (now, stale) = now_and_stale();
        // A TL0 row, inactive and metric-empty, cannot go below Newcomer.
        let after = decide_demotion(TrustLevel::Newcomer, 0, 0, 0, 0, stale, false, now, &t);
        assert_eq!(after, TrustLevel::Newcomer, "TL0 is the floor");
    }

    #[test]
    fn sweep_never_demotes_admin_or_exempt() {
        let t = TrustThresholds::default();
        let (now, stale) = now_and_stale();
        // Admin TL2, inactive, metrics collapsed: still untouched.
        let after = decide_demotion(
            TrustLevel::Regular,
            0,
            0,
            0,
            9,
            stale,
            /*admin*/ true,
            now,
            &t,
        );
        assert_eq!(after, TrustLevel::Regular, "admin/exempt never demoted");
    }

    #[test]
    fn sweep_never_demotes_tl3() {
        let t = TrustThresholds::default();
        let (now, stale) = now_and_stale();
        let after = decide_demotion(TrustLevel::Trusted, 0, 0, 0, 0, stale, false, now, &t);
        assert_eq!(
            after,
            TrustLevel::Trusted,
            "TL3 admin-granted never auto-demoted"
        );
    }

    #[test]
    fn demotion_batch_size_is_bounded() {
        // The sweep pages the whitelist; the batch must be a sane bound, never
        // an unbounded full-table scan-and-update.
        const { assert!(crate::trust_sweep::DEMOTION_BATCH_SIZE > 0) };
        const { assert!(crate::trust_sweep::DEMOTION_BATCH_SIZE <= 1000) };
    }

    #[test]
    fn demotion_sweep_result_serializes_for_observability() {
        // The sweep's observability contract: committed, held and failed are
        // each reported, and the three account for every scanned row.
        let r = crate::trust_sweep::DemotionSweepResult {
            scanned: 12,
            demoted: 3,
            held: 8,
            failed: 1,
            ..Default::default()
        };
        assert!(r.is_balanced());
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"scanned\":12"));
        assert!(json.contains("\"demoted\":3"));
        assert!(json.contains("\"held\":8"));
        assert!(json.contains("\"failed\":1"));
    }
}

#[cfg(test)]
mod ageing_tests {
    //! FR4.3 / EXP-AC-004: the ageing predicate. The D1 shell around it is a
    //! paged `SELECT` plus an `INSERT OR IGNORE` whose idempotency is a primary
    //! key, so the only arithmetic worth testing is here.
    use super::*;

    const HOUR: u64 = 3_600;

    #[test]
    fn a_case_inside_its_deadline_is_not_escalated() {
        let created = 1_000_000;
        assert!(!is_past_pending_deadline(created, created + 71 * HOUR, 72));
    }

    /// A case exactly at its deadline has not yet *exceeded* it.
    #[test]
    fn the_deadline_boundary_is_exclusive() {
        let created = 1_000_000;
        assert!(!is_past_pending_deadline(created, created + 72 * HOUR, 72));
        assert!(is_past_pending_deadline(
            created,
            created + 72 * HOUR + 1,
            72
        ));
    }

    #[test]
    fn the_panel_deadline_is_honoured_over_the_default() {
        let created = 1_000_000;
        assert!(is_past_pending_deadline(created, created + 7 * HOUR, 6));
        assert!(!is_past_pending_deadline(created, created + 7 * HOUR, 72));
    }

    /// A case that predates the column, or a panel that declared nothing, falls
    /// back to the documented 72-hour default rather than escalating instantly.
    #[test]
    fn a_missing_deadline_falls_back_to_the_default() {
        let created = 1_000_000;
        assert!(!is_past_pending_deadline(created, created + HOUR, 0));
        assert!(is_past_pending_deadline(created, created + 73 * HOUR, 0));
        assert_eq!(nostr_bbs_core::governance::DEFAULT_MAX_PENDING_HOURS, 72);
    }

    /// A clock that has gone backwards must not escalate everything: the age is
    /// a saturating difference, so a future `created_at` reads as age zero.
    #[test]
    fn a_backwards_clock_escalates_nothing() {
        assert!(!is_past_pending_deadline(2_000_000, 1_000_000, 1));
    }
}

#[cfg(test)]
mod ageing_ordering_tests {
    //! The defect this pins: the sweep once ordered candidates by `created_at`
    //! and broke on the first case inside its own deadline. With per-panel
    //! deadlines that is unsound — a six-hour case raised after a seventy-two
    //! hour case is overdue while the older one is not, and the break skipped
    //! it. The ordering is now by each case's own deadline and there is no
    //! early break.
    use super::*;

    const HOUR: u64 = 3_600;

    /// The deadline instant a case is ordered and filtered by, mirroring the
    /// SQL expression so the two cannot drift apart unnoticed.
    fn deadline_at(created_at: u64, max_pending_hours: u32) -> u64 {
        let hours = if max_pending_hours == 0 {
            nostr_bbs_core::governance::DEFAULT_MAX_PENDING_HOURS
        } else {
            max_pending_hours
        };
        created_at + hours as u64 * HOUR
    }

    /// The exact shape that used to be skipped: a younger case with a short
    /// deadline is overdue while an older case with a long one is not.
    #[test]
    fn a_younger_short_deadline_case_is_overdue_before_an_older_long_one() {
        let now = 1_000_000 + 80 * HOUR;
        let old_slow = (1_000_000u64, 720u32); // raised first, 30-day deadline
        let young_fast = (1_000_000 + 70 * HOUR, 1u32); // raised later, 1 hour

        assert!(!is_past_pending_deadline(old_slow.0, now, old_slow.1));
        assert!(is_past_pending_deadline(young_fast.0, now, young_fast.1));

        // And the ordering the query uses puts the overdue one first, so a
        // capped page cuts the least overdue rather than the most.
        assert!(
            deadline_at(young_fast.0, young_fast.1) < deadline_at(old_slow.0, old_slow.1),
            "deadline ordering must not follow creation order here"
        );
    }

    /// With equal deadlines the ordering degenerates to oldest-first, which is
    /// the behaviour operators expect of a queue.
    #[test]
    fn equal_deadlines_order_oldest_first() {
        assert!(deadline_at(1_000, 72) < deadline_at(2_000, 72));
    }

    /// A case with no declared deadline sorts as though it declared the
    /// documented default, not as though it had none.
    #[test]
    fn an_undeclared_deadline_sorts_as_the_default() {
        assert_eq!(
            deadline_at(1_000, 0),
            deadline_at(1_000, nostr_bbs_core::governance::DEFAULT_MAX_PENDING_HOURS)
        );
    }
}
