//! Sprint v10 — `/api/profiles/{batch,search}` HTTP handlers.
//!
//! Reads from the `profiles` table maintained by the kind-0 ingest hook in
//! `relay_do::storage::save_event`. No auth required: profile metadata is
//! public per NIP-01.
//!
//! | Method | Path                         | Body / Query                | Limit |
//! |--------|------------------------------|-----------------------------|-------|
//! | POST   | /api/profiles/batch          | `{ "pubkeys": [hex, ...] }` | 200   |
//! | GET    | /api/profiles/search         | `?q=<prefix>&limit=20`      | 50    |

use serde::Deserialize;
use serde_json::json;
use wasm_bindgen::JsValue;
use worker::{D1Database, Env, Request, Response, Result};

use crate::cors::json_response as cors_json_response;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Hard ceiling on `/api/profiles/batch` request size. The forum-client cache
/// fetcher batches in 200-pubkey windows, so this cap matches the natural unit
/// of work and prevents accidental DOS via oversized batches.
const BATCH_MAX: usize = 200;

/// Hard ceiling on `/api/profiles/search` result count.
const SEARCH_MAX_LIMIT: u32 = 50;

/// Default `/api/profiles/search` result count.
const SEARCH_DEFAULT_LIMIT: u32 = 20;

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct BatchBody {
    pubkeys: Vec<String>,
}

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ProfileRow {
    pubkey: String,
    name: Option<String>,
    display_name: Option<String>,
    picture: Option<String>,
    nip05: Option<String>,
}

impl ProfileRow {
    fn into_json(self) -> serde_json::Value {
        json!({
            "pubkey": self.pubkey,
            "name": self.name,
            "display_name": self.display_name,
            "picture": self.picture,
            "nip05": self.nip05,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validate that `s` is a 64-char lowercase hex pubkey. Cheaper and safer
/// than dragging a regex into the WASM bundle.
fn is_valid_pubkey(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Build the SQL `LIKE` pattern for a (caller-lowercased) handle search query.
///
/// Returns a case-insensitive **substring** pattern (`%<needle>%`) after
/// stripping the literal `%`/`_` wildcards so the typeahead can't be coerced
/// into a full wildcard scan. Pairing this with `LOWER(<column>) LIKE ?1`
/// makes handle search case-insensitive in both directions and matches the
/// client's `MentionCandidate::matches` (`.contains`) semantics.
fn search_like_pattern(q_lower: &str) -> String {
    let needle = q_lower.replace(['%', '_'], "");
    format!("%{needle}%")
}

// ---------------------------------------------------------------------------
// POST /api/profiles/batch
// ---------------------------------------------------------------------------

pub async fn handle_batch(_req: &Request, body_bytes: &[u8], env: &Env) -> Result<Response> {
    let body: BatchBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(_) => {
            return cors_json_response(env, &json!({ "error": "Invalid JSON body" }), 400);
        }
    };

    // Dedupe + filter to valid hex pubkeys, capped at BATCH_MAX.
    let mut seen = std::collections::HashSet::with_capacity(body.pubkeys.len().min(BATCH_MAX));
    let mut clean: Vec<String> = Vec::with_capacity(body.pubkeys.len().min(BATCH_MAX));
    for pk in body.pubkeys {
        let pk = pk.to_lowercase();
        if !is_valid_pubkey(&pk) {
            continue;
        }
        if seen.insert(pk.clone()) {
            clean.push(pk);
            if clean.len() >= BATCH_MAX {
                break;
            }
        }
    }

    if clean.is_empty() {
        return cors_json_response(env, &json!({ "profiles": [] }), 200);
    }

    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return cors_json_response(env, &json!({ "error": "Database unavailable" }), 500),
    };

    // Build `WHERE pubkey IN (?1, ?2, ...)` with N placeholders.
    let placeholders: Vec<String> = (1..=clean.len()).map(|i| format!("?{i}")).collect();
    let sql = format!(
        "SELECT pubkey, name, display_name, picture, nip05 FROM profiles \
         WHERE pubkey IN ({})",
        placeholders.join(", ")
    );

    let binds: Vec<JsValue> = clean.iter().map(|p| JsValue::from_str(p)).collect();

    let stmt = match db.prepare(&sql).bind(&binds) {
        Ok(s) => s,
        Err(_) => return cors_json_response(env, &json!({ "error": "Bind failed" }), 500),
    };

    let result = match stmt.all().await {
        Ok(r) => r,
        Err(_) => return cors_json_response(env, &json!({ "error": "Query failed" }), 500),
    };

    let rows: Vec<ProfileRow> = result.results().unwrap_or_default();
    let mut profiles: Vec<serde_json::Value> = rows.into_iter().map(|r| r.into_json()).collect();

    // Task #7 — alias inheritance for DISPLAY. Any requested pubkey that has no
    // profile of its own but is aliased to a prior `old_pubkey` inherits the old
    // pubkey's profile so authorship renders under the prior handle. Events are
    // never re-signed; this is purely how the name resolves at read time.
    let resolved: std::collections::HashSet<String> = profiles
        .iter()
        .filter_map(|p| p.get("pubkey").and_then(|v| v.as_str()).map(String::from))
        .collect();
    let unresolved: Vec<String> = clean
        .iter()
        .filter(|pk| !resolved.contains(*pk))
        .cloned()
        .collect();
    if !unresolved.is_empty() {
        let inherited = resolve_aliased_profiles(&db, &unresolved).await;
        profiles.extend(inherited);
    }

    cors_json_response(env, &json!({ "profiles": profiles }), 200)
}

/// For each `new_pubkey` with a `pubkey_aliases` row, fetch the aliased
/// `old_pubkey`'s profile and return it keyed under the requested `new_pubkey`.
///
/// Best-effort: a missing alias or missing old profile simply yields no row for
/// that pubkey (the client then falls back to the shortened hex). The returned
/// JSON keeps the requested `new_pubkey` as `pubkey` so the client cache stores
/// the inherited name against the key the caller asked about.
async fn resolve_aliased_profiles(
    db: &D1Database,
    new_pubkeys: &[String],
) -> Vec<serde_json::Value> {
    if new_pubkeys.is_empty() {
        return Vec::new();
    }

    // Map each requested new_pubkey -> aliased old_pubkey.
    #[derive(Deserialize)]
    struct AliasPair {
        new_pubkey: String,
        old_pubkey: String,
    }

    let placeholders: Vec<String> = (1..=new_pubkeys.len()).map(|i| format!("?{i}")).collect();
    let alias_sql = format!(
        "SELECT new_pubkey, old_pubkey FROM pubkey_aliases WHERE new_pubkey IN ({})",
        placeholders.join(", ")
    );
    let binds: Vec<JsValue> = new_pubkeys.iter().map(|p| JsValue::from_str(p)).collect();
    let stmt = match db.prepare(&alias_sql).bind(&binds) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let pairs: Vec<AliasPair> = match stmt.all().await {
        Ok(r) => r.results().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    if pairs.is_empty() {
        return Vec::new();
    }

    // Fetch the old pubkeys' profiles in one query, then re-key under the new.
    let old_keys: Vec<String> = pairs.iter().map(|p| p.old_pubkey.clone()).collect();
    let old_placeholders: Vec<String> = (1..=old_keys.len()).map(|i| format!("?{i}")).collect();
    let prof_sql = format!(
        "SELECT pubkey, name, display_name, picture, nip05 FROM profiles WHERE pubkey IN ({})",
        old_placeholders.join(", ")
    );
    let old_binds: Vec<JsValue> = old_keys.iter().map(|p| JsValue::from_str(p)).collect();
    let prof_stmt = match db.prepare(&prof_sql).bind(&old_binds) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let old_rows: Vec<ProfileRow> = match prof_stmt.all().await {
        Ok(r) => r.results().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    let old_by_pk: std::collections::HashMap<String, &ProfileRow> =
        old_rows.iter().map(|r| (r.pubkey.clone(), r)).collect();

    let mut out = Vec::new();
    for pair in &pairs {
        if let Some(old) = old_by_pk.get(&pair.old_pubkey) {
            out.push(json!({
                "pubkey": pair.new_pubkey,
                "name": old.name,
                "display_name": old.display_name,
                "picture": old.picture,
                "nip05": old.nip05,
            }));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// GET /api/profiles/search
// ---------------------------------------------------------------------------

pub async fn handle_search(req: &Request, env: &Env) -> Result<Response> {
    let url = match req.url() {
        Ok(u) => u,
        Err(_) => return cors_json_response(env, &json!({ "error": "Bad request" }), 400),
    };

    let mut q = String::new();
    let mut limit: u32 = SEARCH_DEFAULT_LIMIT;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "q" => q = v.to_string(),
            "limit" => {
                if let Ok(n) = v.parse::<u32>() {
                    limit = n;
                }
            }
            _ => {}
        }
    }

    let q = q.to_lowercase();
    let limit = limit.clamp(1, SEARCH_MAX_LIMIT);

    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return cors_json_response(env, &json!({ "error": "Database unavailable" }), 500),
    };

    // Two query shapes:
    //
    //   * **Roster mode** (empty `q`): the composer opens the @mention dropdown on
    //     a bare `@` and must show real, recently-active members immediately —
    //     otherwise the only candidates are the hardcoded client-side seed bots
    //     ("I only see the house agents"). Return the most-recently-active
    //     profiles ordered by the indexed `last_kind0_at`, bounded by `limit`.
    //     This is NOT a wildcard scan: no `LIKE`, just an ordered LIMIT.
    //
    //   * **Filter mode** (non-empty `q`, any length ≥ 1): case-insensitive
    //     SUBSTRING match across every human-facing handle column (`name`,
    //     `display_name`, `nip05`). Both sides fold to lower-case — `q` is
    //     lowercased above and each column is wrapped in `LOWER(...)` — so
    //     "reddread" surfaces a stored "RedDreadTest1". Substring (not prefix)
    //     keeps parity with the client's `MentionCandidate::matches` (`.contains`)
    //     so a mid-handle fragment ("dread", "test") still finds the user. The
    //     literal `%`/`_` LIKE wildcards are stripped so the typeahead can't be
    //     coerced into a full wildcard scan. (Previously `q` shorter than 2 chars
    //     was rejected with 400; that hard floor is what left a
    //     bare `@` showing only the seed. A 1-char `LIKE %x%` is still bounded by
    //     LIMIT, so it is admitted.)
    let (sql, binds): (&str, Vec<JsValue>) = if q.is_empty() {
        (
            "SELECT pubkey, name, display_name, picture, nip05 FROM profiles \
             ORDER BY last_kind0_at DESC LIMIT ?1",
            vec![JsValue::from_f64(limit as f64)],
        )
    } else {
        let pattern = search_like_pattern(&q);
        (
            "SELECT pubkey, name, display_name, picture, nip05 FROM profiles \
             WHERE LOWER(name) LIKE ?1 \
                OR LOWER(display_name) LIKE ?1 \
                OR LOWER(nip05) LIKE ?1 \
             ORDER BY last_kind0_at DESC LIMIT ?2",
            vec![JsValue::from_str(&pattern), JsValue::from_f64(limit as f64)],
        )
    };

    let bound = match db.prepare(sql).bind(&binds) {
        Ok(s) => s,
        Err(_) => return cors_json_response(env, &json!({ "error": "Bind failed" }), 500),
    };

    let result = match bound.all().await {
        Ok(r) => r,
        Err(_) => return cors_json_response(env, &json!({ "error": "Query failed" }), 500),
    };

    let rows: Vec<ProfileRow> = result.results().unwrap_or_default();
    let profiles: Vec<serde_json::Value> = rows.into_iter().map(|r| r.into_json()).collect();

    cors_json_response(env, &serde_json::Value::Array(profiles), 200)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_valid_pubkey_accepts_64_char_hex() {
        let pk = "0".repeat(64);
        assert!(is_valid_pubkey(&pk));
        assert!(is_valid_pubkey(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        ));
    }

    #[test]
    fn is_valid_pubkey_rejects_wrong_length() {
        assert!(!is_valid_pubkey(""));
        assert!(!is_valid_pubkey(&"a".repeat(63)));
        assert!(!is_valid_pubkey(&"a".repeat(65)));
    }

    #[test]
    fn is_valid_pubkey_rejects_non_hex() {
        let mixed = format!("g{}", "0".repeat(63));
        assert!(!is_valid_pubkey(&mixed));
    }

    // Mirror SQLite's `LOWER(<column>) LIKE <pattern>` for an ASCII column so
    // the tests prove the matching contract without a live D1.
    fn sql_like_match(column_value: &str, pattern: &str) -> bool {
        let hay = column_value.to_lowercase();
        // The handler only ever builds `%<needle>%` patterns, so a plain
        // substring check is an exact stand-in for SQLite LIKE here.
        let needle = pattern.trim_matches('%');
        hay.contains(needle)
    }

    #[test]
    fn search_pattern_wraps_substring() {
        assert_eq!(search_like_pattern("reddread"), "%reddread%");
    }

    #[test]
    fn search_pattern_strips_like_wildcards() {
        // A user can't smuggle SQL LIKE wildcards into the typeahead.
        assert_eq!(search_like_pattern("a%b_c"), "%abc%");
        assert_eq!(search_like_pattern("%%__"), "%%");
    }

    #[test]
    fn search_matches_case_insensitively() {
        // Operator's case: typing "reddread" must surface "RedDreadTest1".
        let pattern = search_like_pattern(&"RedDread".to_lowercase());
        assert!(sql_like_match("RedDreadTest1", &pattern));
        // And the reverse casing on the query.
        let pattern = search_like_pattern(&"REDDREAD".to_lowercase());
        assert!(sql_like_match("reddreadtest1", &pattern));
    }

    #[test]
    fn search_matches_mid_handle_substring() {
        // Substring (not prefix): a fragment from the middle still matches.
        let pattern = search_like_pattern(&"dread".to_lowercase());
        assert!(sql_like_match("RedDreadTest1", &pattern));
        let pattern = search_like_pattern(&"test".to_lowercase());
        assert!(sql_like_match("RedDreadTest1", &pattern));
    }

    #[test]
    fn search_does_not_match_unrelated() {
        let pattern = search_like_pattern(&"alice".to_lowercase());
        assert!(!sql_like_match("RedDreadTest1", &pattern));
    }

    #[test]
    fn single_char_query_still_filters() {
        // A 1-char query is now admitted (was rejected with 400): the composer's
        // first typed char after `@` must already narrow the roster, not scan.
        let pattern = search_like_pattern(&"r".to_lowercase());
        assert_eq!(pattern, "%r%");
        assert!(sql_like_match("RedDread", &pattern));
        assert!(!sql_like_match("Bob", &pattern));
    }
}
