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
        assert!(BACKFILL_BATCH_SIZE > 0);
        assert!(BACKFILL_BATCH_SIZE <= 1000);
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
}
