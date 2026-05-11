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
use worker::{Env, Request, Response, Result};

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

/// Minimum prefix length for typeahead. Prevents whole-table scans.
const SEARCH_MIN_PREFIX: usize = 2;

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
    let profiles: Vec<serde_json::Value> = rows.into_iter().map(|r| r.into_json()).collect();

    cors_json_response(env, &json!({ "profiles": profiles }), 200)
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

    // Lowercase + length guard.
    let q = q.to_lowercase();
    if q.chars().count() < SEARCH_MIN_PREFIX {
        return cors_json_response(
            env,
            &json!({ "error": format!("q must be at least {SEARCH_MIN_PREFIX} chars") }),
            400,
        );
    }

    let limit = limit.clamp(1, SEARCH_MAX_LIMIT);

    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return cors_json_response(env, &json!({ "error": "Database unavailable" }), 500),
    };

    // Case-insensitive prefix match on either column. We rely on
    // SQLite's default LIKE being case-insensitive for ASCII; the prefix
    // is already lowercased above for parity with stored values when the
    // column happens to carry mixed case.
    let pattern = format!("{}%", q.replace(['%', '_'], ""));

    let stmt = db.prepare(
        "SELECT pubkey, name, display_name, picture, nip05 FROM profiles \
         WHERE LOWER(name) LIKE ?1 OR LOWER(display_name) LIKE ?1 \
         ORDER BY last_kind0_at DESC LIMIT ?2",
    );

    let binds = [JsValue::from_str(&pattern), JsValue::from_f64(limit as f64)];

    let bound = match stmt.bind(&binds) {
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

// `_req` is kept on `handle_search` so future enhancements (e.g. per-Origin
// CORS branching) don't change the public signature again.
#[allow(dead_code)]
fn _ensure_request_arg_used(req: &Request) -> &Request {
    req
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
}
