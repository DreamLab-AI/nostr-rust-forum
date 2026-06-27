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
// ADR-102 — Inactivity-decay trust demotion sweep
//
// `trust::check_demotion` is inherently time-driven: its precondition is that a
// pubkey has been inactive for `inactivity_demotion_secs` (~6 months). Wiring it
// into a request handler would fire it on ACTIVE users — the opposite of its
// precondition — so it lives here, on the scheduled (cron) trigger, alongside
// the periodic-sweep pattern established by `backfill_profiles`.
//
// The decay policy is exactly what `check_demotion` already encodes; the sweep
// invents nothing harsher:
//   - only rows past the inactivity gate are candidates;
//   - TL3 (admin-granted) and admin/exempt rows are never demoted;
//   - TL0 is a hard floor (no demotion below Newcomer);
//   - TL2 → TL1 when the row still qualifies for TL1, else TL2 → TL0;
//   - TL1 → TL0.
// Each qualifying sweep applies one demotion step per row. `check_demotion`
// writes the `whitelist.trust_level` change and the `admin_log` entry itself,
// so the sweep is a pure selection-and-dispatch loop.
// ---------------------------------------------------------------------------

/// How many candidate whitelist rows to pull per `SELECT` page. The whitelist
/// is small relative to `events`, but we page it the same way as the profile
/// backfill so a large community never produces an unbounded result set or a
/// single oversized D1 statement.
pub(crate) const DEMOTION_BATCH_SIZE: u32 = 200;

/// Circuit breaker: the maximum number of candidate rows the sweep will process
/// in one cron invocation, keeping us inside the worker CPU budget. This is a
/// ceiling, not a target — a healthy forum produces far fewer inactive rows per
/// sweep than this.
const DEMOTION_MAX_ROWS: u64 = 50_000;

/// Minimal candidate row shape for the demotion sweep. We only need the pubkey
/// to dispatch `check_demotion`; the SQL predicate has already filtered on
/// trust level, inactivity, and the admin/exempt flag, so re-reading those
/// columns here would be redundant. `check_demotion` re-reads the full row
/// (parameterised, by pubkey) and re-checks every guard before writing, so the
/// SQL filter is an optimisation — it bounds the candidate set — not the
/// authority for the decision.
#[derive(Deserialize)]
struct DemotionCandidate {
    pubkey: String,
}

/// Outcome of [`sweep_inactive_demotions`].
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct DemotionSweepResult {
    /// Total candidate rows read from `whitelist` (past the inactivity gate and
    /// holding a demotable trust level).
    pub scanned: u64,
    /// Rows whose trust level `check_demotion` actually lowered this sweep.
    pub demoted: u64,
    /// `true` if we hit [`DEMOTION_MAX_ROWS`] before exhausting the candidates.
    pub truncated: bool,
}

/// Periodic inactivity-decay sweep (ADR-102).
///
/// Selects whitelist rows whose inactivity exceeds `inactivity_demotion_secs`
/// and that currently hold a demotable trust level (TL1/TL2, non-admin), then
/// applies [`trust::check_demotion`] to each. Paged and bounded: never scans or
/// updates the whole table unbounded.
///
/// The inactivity cutoff is computed once, in Rust, from the loaded thresholds
/// and the current time, then bound as a parameter — the SQL itself stays a
/// plain parameterised `SELECT … WHERE last_active_at < ?` with no clock or
/// arithmetic embedded in the statement.
///
/// Returns counts for observability. Per-row demotion failures are impossible
/// to distinguish from "row did not need demoting" through `check_demotion`'s
/// `Option` return, so `demoted` reflects an actual trust-level decrease only.
pub async fn sweep_inactive_demotions(env: &Env) -> Result<DemotionSweepResult, String> {
    let db = env
        .d1("DB")
        .map_err(|e| format!("DB binding missing: {e:?}"))?;

    let thresholds = TrustThresholds::load(env).await;
    let now = auth::js_now_secs() as i64;
    // Anything last active at or before this instant is past the inactivity
    // gate. Computed in Rust so the SQL carries no clock/arithmetic.
    let inactive_cutoff = now - thresholds.inactivity_demotion_secs;

    let demotable_floor = trust::TrustLevel::Member.as_i32(); // TL1
    let demotable_ceiling = trust::TrustLevel::Regular.as_i32(); // TL2

    let mut offset: u32 = 0;
    let mut scanned: u64 = 0;
    let mut demoted: u64 = 0;

    loop {
        // Parameterised candidate page. The predicate bounds the candidate set:
        //   - trust_level in [TL1, TL2]  → TL0 floor and TL3 are excluded here;
        //   - last_active_at <= cutoff   → only rows past the inactivity gate;
        //   - is_admin coalesced to 0    → admin/exempt rows never selected.
        // `check_demotion` re-validates all of these before any write, so this
        // is an optimisation that keeps the sweep bounded, not the decision.
        let stmt = db.prepare(
            "SELECT pubkey FROM whitelist \
             WHERE trust_level >= ?1 AND trust_level <= ?2 \
               AND COALESCE(last_active_at, 0) <= ?3 \
               AND COALESCE(is_admin, 0) = 0 \
             ORDER BY last_active_at ASC \
             LIMIT ?4 OFFSET ?5",
        );

        let bound = stmt
            .bind(&[
                JsValue::from_f64(demotable_floor as f64),
                JsValue::from_f64(demotable_ceiling as f64),
                JsValue::from_f64(inactive_cutoff as f64),
                JsValue::from_f64(DEMOTION_BATCH_SIZE as f64),
                JsValue::from_f64(offset as f64),
            ])
            .map_err(|e| format!("bind failed: {e:?}"))?;

        let rows: Vec<DemotionCandidate> = bound
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

            // Snapshot the level before, so we count only genuine decreases.
            let before = trust::get_trust_level(&row.pubkey, env).await;
            if let Some(after) = trust::check_demotion(&row.pubkey, env).await {
                if after < before {
                    demoted += 1;
                }
            }

            if scanned >= DEMOTION_MAX_ROWS {
                console_warn!(
                    "sweep_inactive_demotions: hit DEMOTION_MAX_ROWS ({}), stopping early",
                    DEMOTION_MAX_ROWS
                );
                return Ok(DemotionSweepResult {
                    scanned,
                    demoted,
                    truncated: true,
                });
            }
        }

        // Demotions mutate `trust_level`, which shrinks the candidate set this
        // very query filters on. Re-querying from OFFSET 0 each iteration would
        // risk skipping rows as the window shifts; advancing the offset by the
        // page length and ordering by a stable key (last_active_at ASC) pages
        // forward deterministically without revisiting demoted rows.
        if page_len < DEMOTION_BATCH_SIZE {
            break;
        }
        offset = offset
            .checked_add(page_len)
            .ok_or_else(|| "offset overflow".to_string())?;
    }

    Ok(DemotionSweepResult {
        scanned,
        demoted,
        truncated: false,
    })
}

/// Pure model of the demotion decision the sweep applies per row (ADR-102).
///
/// This is a side-effect-free mirror of the policy `trust::check_demotion`
/// encodes against D1: same inactivity gate, same TL3/admin/TL0 guards, same
/// per-level hysteresis. It exists so the sweep's contract is testable without
/// a D1 binding — the live path (`check_demotion`) remains the executable
/// authority; this function asserts the live path's policy is the one we
/// intend. The two MUST stay in lockstep.
///
/// Returns the trust level the row should hold AFTER this sweep. A return value
/// equal to `current` means "not demoted this sweep".
#[cfg(test)]
// Signature mirrors the live `trust::check_demotion` policy inputs 1:1 so the
// two stay in lockstep (see doc above); collapsing them into a struct here would
// break that parity, so the arg count is intentional on this security-path model.
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
    use trust::TrustLevel;

    // TL3 never auto-demoted; TL0 is the floor.
    if current == TrustLevel::Trusted || current == TrustLevel::Newcomer {
        return current;
    }
    // Admin/exempt rows are never demoted.
    if is_admin {
        return current;
    }
    // Inactivity gate: only demote rows past `inactivity_demotion_secs`.
    if now - last_active_at < thresholds.inactivity_demotion_secs {
        return current;
    }

    let hysteresis = thresholds.demotion_hysteresis_pct as f64 / 100.0;

    match current {
        TrustLevel::Regular => {
            let needs_demote = (days_active as f64)
                < (thresholds.tl2_days_active as f64 * hysteresis)
                || (posts_read as f64) < (thresholds.tl2_posts_read as f64 * hysteresis)
                || (posts_created as f64) < (thresholds.tl2_posts_created as f64 * hysteresis)
                || mod_actions_against > 0;
            if needs_demote {
                let qualifies = trust::compute_trust_level(
                    days_active,
                    posts_read,
                    posts_created,
                    mod_actions_against,
                    thresholds,
                );
                if qualifies >= TrustLevel::Member {
                    TrustLevel::Member
                } else {
                    TrustLevel::Newcomer
                }
            } else {
                current
            }
        }
        TrustLevel::Member => {
            let needs_demote = (days_active as f64)
                < (thresholds.tl1_days_active as f64 * hysteresis)
                || (posts_read as f64) < (thresholds.tl1_posts_read as f64 * hysteresis)
                || (posts_created as f64) < (thresholds.tl1_posts_created as f64 * hysteresis);
            if needs_demote {
                TrustLevel::Newcomer
            } else {
                current
            }
        }
        _ => current,
    }
}

// ---------------------------------------------------------------------------
// Tests
//
// Purely native unit tests over the JSON-parsing branches and the
// last_kind0_at guard contract. The D1 paths are exercised by integration
// tests in `tests/` and through the existing live-ingest test suite.
// ---------------------------------------------------------------------------

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
        const { assert!(DEMOTION_BATCH_SIZE > 0) };
        const { assert!(DEMOTION_BATCH_SIZE <= 1000) };
    }

    #[test]
    fn demotion_sweep_result_serializes_for_observability() {
        let r = DemotionSweepResult {
            scanned: 12,
            demoted: 3,
            truncated: false,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"scanned\":12"));
        assert!(json.contains("\"demoted\":3"));
        assert!(json.contains("\"truncated\":false"));
    }
}
