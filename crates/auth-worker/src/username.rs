//! Sprint v10 — username (nickname) reservations.
//!
//! Provides a lightweight, server-enforced uniqueness layer on top of Nostr's
//! kind-0 metadata events. Nostr alone cannot guarantee a single owner for any
//! given `name` field (the protocol forbids enforcing uniqueness at the event
//! layer), so we maintain a side-table in D1 that maps `username -> pubkey`
//! atomically.
//!
//! On successful claim we ALSO write `POD_META.nip05:{username} -> pubkey`
//! so the pod-worker's `/.well-known/nostr.json` endpoint can serve NIP-05
//! verification without a second round-trip to D1.
//!
//! | Method | Path                        | Auth     | Purpose                            |
//! |--------|-----------------------------|----------|------------------------------------|
//! | GET    | /api/username/check?name=X  | open     | Is username available?             |
//! | POST   | /api/username/claim         | NIP-98   | Atomic claim; one per pubkey       |
//! | POST   | /api/username/release       | NIP-98   | Release caller's username          |

use serde::Deserialize;
use serde_json::json;
use wasm_bindgen::JsValue;
use worker::{Env, Response, Result};

use crate::admin::{canonical_url, now_secs, require_authed};
use crate::http::{error_json, json_response};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// In-memory representation of a `username_reservations` row.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsernameClaim {
    pub username: String,
    pub pubkey: String,
    pub created_at: u64,
}

/// Validation / claim error variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsernameError {
    /// Length out of bounds (must be 3..=30).
    InvalidLength,
    /// Disallowed character or layout (e.g. leading dash).
    InvalidCharset,
    /// Username is on the reserved-word list.
    Reserved,
    /// Database is unavailable / KV missing / etc.
    Backend(String),
    /// Username already taken by a different pubkey.
    UsernameTaken,
    /// Caller already owns a (different) username.
    PubkeyHasUsername,
}

impl UsernameError {
    fn http_status(&self) -> u16 {
        match self {
            UsernameError::InvalidLength
            | UsernameError::InvalidCharset
            | UsernameError::Reserved => 400,
            UsernameError::UsernameTaken | UsernameError::PubkeyHasUsername => 409,
            UsernameError::Backend(_) => 500,
        }
    }

    fn message(&self) -> String {
        match self {
            UsernameError::InvalidLength => "Username must be 3-30 characters".to_string(),
            UsernameError::InvalidCharset => {
                "Username may only contain a-z, 0-9, _ or -, and may not start with - or _"
                    .to_string()
            }
            UsernameError::Reserved => "Username is reserved".to_string(),
            UsernameError::UsernameTaken => "Username already taken".to_string(),
            UsernameError::PubkeyHasUsername => "This account already owns a username".to_string(),
            UsernameError::Backend(s) => format!("Backend error: {s}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Reserved words that cannot be claimed.
///
/// Kept in lockstep with the forum-client onboarding modal copy. New entries
/// here MUST be alphabetically sorted to keep diffs trivial.
const RESERVED: &[&str] = &[
    "admin",
    "anon",
    "help",
    "mod",
    "null",
    "official",
    "root",
    "support",
    "system",
    "undefined",
];

/// Validate a candidate username against the regex `^[a-z0-9][a-z0-9_-]{2,29}$`,
/// the reserved-word list and a leading-dash/underscore rule.
///
/// The implementation is hand-rolled to avoid pulling `regex` into the WASM
/// build; the regex above is simple enough that explicit byte checks are both
/// faster and produce a smaller bundle.
pub fn validate_username(s: &str) -> std::result::Result<(), UsernameError> {
    let len = s.len();
    if !(3..=30).contains(&len) {
        return Err(UsernameError::InvalidLength);
    }

    let bytes = s.as_bytes();

    // First char: a-z or 0-9 (no leading - or _)
    let first = bytes[0];
    let first_ok = first.is_ascii_lowercase() || first.is_ascii_digit();
    if !first_ok {
        return Err(UsernameError::InvalidCharset);
    }

    // Remaining chars: a-z, 0-9, _ or -.
    for &b in &bytes[1..] {
        let ok = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-';
        if !ok {
            return Err(UsernameError::InvalidCharset);
        }
    }

    if RESERVED.binary_search(&s).is_ok() {
        return Err(UsernameError::Reserved);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// D1 + KV helpers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct PubkeyRow {
    pubkey: String,
}

/// Look up the pubkey currently reserving `username`, if any.
///
/// Returns `Ok(None)` when the username is free, `Ok(Some(pk))` when it is
/// claimed, and `Err` only on hard backend failure.
pub async fn check(
    env: &Env,
    username: &str,
) -> std::result::Result<Option<String>, UsernameError> {
    validate_username(username)?;

    let db = env
        .d1("DB")
        .map_err(|e| UsernameError::Backend(format!("D1 unavailable: {e}")))?;

    let stmt = db
        .prepare(
            "SELECT pubkey FROM username_reservations WHERE username = ?1 AND status = 'active'",
        )
        .bind(&[JsValue::from_str(username)])
        .map_err(|e| UsernameError::Backend(format!("bind failed: {e}")))?;

    let row = stmt
        .first::<PubkeyRow>(None)
        .await
        .map_err(|e| UsernameError::Backend(format!("query failed: {e}")))?;

    Ok(row.map(|r| r.pubkey))
}

/// Atomically claim `username` for `pubkey`.
///
/// Returns `Err(UsernameTaken)` if the username already exists, or
/// `Err(PubkeyHasUsername)` if the pubkey already owns a (different) username.
/// On success, also writes `POD_META.nip05:{username} -> pubkey` so the
/// pod-worker's NIP-05 endpoint can resolve the handle without re-reading D1.
pub async fn claim(
    env: &Env,
    pubkey: &str,
    username: &str,
) -> std::result::Result<UsernameClaim, UsernameError> {
    validate_username(username)?;

    let db = env
        .d1("DB")
        .map_err(|e| UsernameError::Backend(format!("D1 unavailable: {e}")))?;

    let now = now_secs();

    // Atomic INSERT — relies on UNIQUE(username) and UNIQUE(pubkey) constraints
    // to surface conflicts. We let D1 raise the error and then disambiguate
    // afterwards via two cheap SELECTs.
    let insert = db
        .prepare(
            "INSERT INTO username_reservations (username, pubkey, created_at, status) \
             VALUES (?1, ?2, ?3, 'active')",
        )
        .bind(&[
            JsValue::from_str(username),
            JsValue::from_str(pubkey),
            JsValue::from_f64(now as f64),
        ])
        .map_err(|e| UsernameError::Backend(format!("bind failed: {e}")))?
        .run()
        .await;

    if let Err(_e) = insert {
        // Disambiguate the conflict.
        if let Ok(Some(existing_pk)) = check(env, username).await {
            if existing_pk == pubkey {
                // Idempotent re-claim of the same (username, pubkey) pair.
                // Treat as success so retries are safe.
                return Ok(UsernameClaim {
                    username: username.to_string(),
                    pubkey: pubkey.to_string(),
                    created_at: now,
                });
            }
            return Err(UsernameError::UsernameTaken);
        }
        if let Ok(Some(_)) = lookup_by_pubkey(env, pubkey).await {
            return Err(UsernameError::PubkeyHasUsername);
        }
        return Err(UsernameError::Backend("insert failed".to_string()));
    }

    // Mirror to KV for the pod-worker NIP-05 endpoint.
    if let Ok(kv) = env.kv("POD_META") {
        let key = format!("nip05:{username}");
        if let Ok(builder) = kv.put(&key, pubkey) {
            let _ = builder.execute().await;
        }
    }

    Ok(UsernameClaim {
        username: username.to_string(),
        pubkey: pubkey.to_string(),
        created_at: now,
    })
}

/// Find the username currently reserved by `pubkey`, if any.
pub async fn lookup_by_pubkey(
    env: &Env,
    pubkey: &str,
) -> std::result::Result<Option<String>, UsernameError> {
    let db = env
        .d1("DB")
        .map_err(|e| UsernameError::Backend(format!("D1 unavailable: {e}")))?;

    #[derive(Deserialize)]
    struct UsernameRow {
        username: String,
    }

    let stmt = db
        .prepare(
            "SELECT username FROM username_reservations \
             WHERE pubkey = ?1 AND status = 'active'",
        )
        .bind(&[JsValue::from_str(pubkey)])
        .map_err(|e| UsernameError::Backend(format!("bind failed: {e}")))?;

    let row = stmt
        .first::<UsernameRow>(None)
        .await
        .map_err(|e| UsernameError::Backend(format!("query failed: {e}")))?;

    Ok(row.map(|r| r.username))
}

/// Release the username currently reserved by `pubkey` (if any). Idempotent.
///
/// Also clears the `POD_META.nip05:{username}` KV mapping so subsequent
/// NIP-05 lookups return 404 immediately.
pub async fn release(
    env: &Env,
    pubkey: &str,
) -> std::result::Result<Option<String>, UsernameError> {
    let existing = lookup_by_pubkey(env, pubkey).await?;
    let Some(username) = existing else {
        return Ok(None);
    };

    let db = env
        .d1("DB")
        .map_err(|e| UsernameError::Backend(format!("D1 unavailable: {e}")))?;

    let _ = db
        .prepare("DELETE FROM username_reservations WHERE pubkey = ?1")
        .bind(&[JsValue::from_str(pubkey)])
        .map_err(|e| UsernameError::Backend(format!("bind failed: {e}")))?
        .run()
        .await;

    if let Ok(kv) = env.kv("POD_META") {
        let key = format!("nip05:{username}");
        let _ = kv.delete(&key).await;
    }

    Ok(Some(username))
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ClaimBody {
    username: String,
}

/// `GET /api/username/check?name=alice`
pub async fn handle_check(query: &[(String, String)], env: &Env) -> Result<Response> {
    let name = query
        .iter()
        .find(|(k, _)| k == "name")
        .map(|(_, v)| v.as_str())
        .unwrap_or("")
        .to_lowercase();

    if let Err(e) = validate_username(&name) {
        return json_response(
            env,
            &json!({
                "available": false,
                "error": e.message(),
            }),
            e.http_status(),
        );
    }

    match check(env, &name).await {
        Ok(None) => json_response(
            env,
            &json!({ "available": true, "claimed_by": serde_json::Value::Null }),
            200,
        ),
        Ok(Some(pk)) => json_response(env, &json!({ "available": false, "claimed_by": pk }), 200),
        Err(e) => error_json(env, &e.message(), e.http_status()),
    }
}

/// `POST /api/username/claim` -- NIP-98 authed.
pub async fn handle_claim(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
) -> Result<Response> {
    let url = canonical_url(env, "/api/username/claim");
    let pubkey = match require_authed(auth_header, &url, "POST", Some(body_bytes), env).await {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let body: ClaimBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(_) => return error_json(env, "Invalid JSON body", 400),
    };

    let username = body.username.to_lowercase();

    match claim(env, &pubkey, &username).await {
        Ok(claim) => json_response(
            env,
            &json!({
                "ok": true,
                "username": claim.username,
                "pubkey": claim.pubkey,
                "created_at": claim.created_at,
            }),
            200,
        ),
        Err(e) => error_json(env, &e.message(), e.http_status()),
    }
}

/// `POST /api/username/release` -- NIP-98 authed.
pub async fn handle_release(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
) -> Result<Response> {
    let url = canonical_url(env, "/api/username/release");
    let pubkey = match require_authed(auth_header, &url, "POST", Some(body_bytes), env).await {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    match release(env, &pubkey).await {
        Ok(Some(username)) => json_response(env, &json!({ "ok": true, "released": username }), 200),
        Ok(None) => json_response(
            env,
            &json!({ "ok": true, "released": serde_json::Value::Null }),
            200,
        ),
        Err(e) => error_json(env, &e.message(), e.http_status()),
    }
}

// ---------------------------------------------------------------------------
// Tests (pure validation — D1/KV paths are exercised in the integration suite)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_list_is_sorted() {
        // binary_search depends on the list being sorted; if a future PR adds
        // an entry without keeping the order this assertion will fail loudly.
        let mut sorted = RESERVED.to_vec();
        sorted.sort();
        assert_eq!(sorted, RESERVED.to_vec());
    }

    // ── accept ─────────────────────────────────────────────────────────

    #[test]
    fn accepts_basic_lowercase() {
        assert!(validate_username("alice").is_ok());
    }

    #[test]
    fn accepts_with_digits_and_dashes() {
        assert!(validate_username("alice_42").is_ok());
        assert!(validate_username("a-b-c").is_ok());
        assert!(validate_username("user1").is_ok());
    }

    #[test]
    fn accepts_min_length_three() {
        assert!(validate_username("abc").is_ok());
    }

    #[test]
    fn accepts_max_length_thirty() {
        assert!(validate_username(&"a".repeat(30)).is_ok());
    }

    // ── reject: length ────────────────────────────────────────────────

    #[test]
    fn rejects_too_short() {
        assert_eq!(validate_username("ab"), Err(UsernameError::InvalidLength));
        assert_eq!(validate_username(""), Err(UsernameError::InvalidLength));
    }

    #[test]
    fn rejects_too_long() {
        assert_eq!(
            validate_username(&"a".repeat(31)),
            Err(UsernameError::InvalidLength)
        );
    }

    // ── reject: charset ───────────────────────────────────────────────

    #[test]
    fn rejects_uppercase() {
        assert_eq!(
            validate_username("Alice"),
            Err(UsernameError::InvalidCharset)
        );
    }

    #[test]
    fn rejects_leading_dash() {
        assert_eq!(
            validate_username("-alice"),
            Err(UsernameError::InvalidCharset)
        );
    }

    #[test]
    fn rejects_leading_underscore() {
        assert_eq!(
            validate_username("_alice"),
            Err(UsernameError::InvalidCharset)
        );
    }

    #[test]
    fn rejects_special_chars() {
        for s in ["al ice", "al.ice", "al@ice", "al/ice", "alíce"] {
            assert_eq!(
                validate_username(s),
                Err(UsernameError::InvalidCharset),
                "expected invalid charset for {s:?}"
            );
        }
    }

    // ── reject: reserved ──────────────────────────────────────────────

    #[test]
    fn rejects_reserved_words() {
        for w in RESERVED.iter() {
            assert_eq!(
                validate_username(w),
                Err(UsernameError::Reserved),
                "expected reserved for {w}"
            );
        }
    }

    #[test]
    fn http_status_codes_are_stable() {
        assert_eq!(UsernameError::InvalidLength.http_status(), 400);
        assert_eq!(UsernameError::InvalidCharset.http_status(), 400);
        assert_eq!(UsernameError::Reserved.http_status(), 400);
        assert_eq!(UsernameError::UsernameTaken.http_status(), 409);
        assert_eq!(UsernameError::PubkeyHasUsername.http_status(), 409);
        assert_eq!(UsernameError::Backend("x".into()).http_status(), 500);
    }
}
