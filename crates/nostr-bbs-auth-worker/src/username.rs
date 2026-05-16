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
//! JSS Phase 1 (ADR-086) adds an explicit NIP-05 *resolution* surface:
//! `resolve()` consults D1 first, then optionally falls through to the
//! operator-configured pod's `/.well-known/nostr.json` over HTTP when
//! `NIP05_RESOLVER_MODE = "federated"`. This is distinct from `check()` and
//! `claim()` — both of which stay D1-only to preserve the trust root.
//!
//! | Method | Path                        | Auth     | Purpose                            |
//! |--------|-----------------------------|----------|------------------------------------|
//! | GET    | /api/username/check?name=X  | open     | Is username available?             |
//! | GET    | /api/username/resolve?name=X| open     | NIP-05 resolve (D1 → pod fallback) |
//! | POST   | /api/username/claim         | NIP-98   | Atomic claim; one per pubkey       |
//! | POST   | /api/username/release       | NIP-98   | Release caller's username          |

use serde::Deserialize;
use serde_json::json;
use wasm_bindgen::JsValue;
use worker::{Env, Fetch, Method, Request, Response, Result};

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
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/username/claim");
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
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/username/release");
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
// JSS Phase 1 — Federated NIP-05 resolution (ADR-086)
// ---------------------------------------------------------------------------

/// Operator-selected NIP-05 resolution policy. Mirrors the
/// `[nip05].resolver_mode` field defined in `nostr-bbs-config`. The
/// auth-worker reads the chosen value from the `NIP05_RESOLVER_MODE` env
/// var (operator's deploy script injects it from `forum.toml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverMode {
    /// D1+KV only; no pod fallback. Default — preserves legacy behaviour.
    D1,
    /// D1+KV first, then pod fallback on miss.
    Federated,
}

impl ResolverMode {
    /// Parse `NIP05_RESOLVER_MODE`. Unknown / empty values default to `D1`
    /// — the kit refuses to silently enable federation.
    pub fn from_env_str(s: Option<&str>) -> Self {
        match s.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
            Some("federated") => ResolverMode::Federated,
            _ => ResolverMode::D1,
        }
    }
}

/// Parse a NIP-05 response body (`{"names": {<name>: <pubkey-hex>}}`) and
/// return the 64-char lowercase hex pubkey for `name`, if present.
///
/// Returns `None` when the JSON is malformed, the `names` field is missing
/// or non-object, the requested name is absent, or the value is not a
/// 64-char lowercase hex string. This is the trust-boundary parser for
/// federated responses — be strict.
pub fn parse_nip05_pubkey(body: &[u8], name: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let pk = v.get("names")?.get(name)?.as_str()?;
    if pk.len() != 64 || !pk.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return None;
    }
    Some(pk.to_string())
}

/// Build the federation fetch URL for `name` against `pod_base_url`.
///
/// Strips any trailing slash on `pod_base_url` (validator should already
/// reject it, but defence-in-depth). Returns `None` when name is empty.
pub fn build_federated_url(pod_base_url: &str, name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    let base = pod_base_url.trim_end_matches('/');
    Some(format!("{base}/.well-known/nostr.json?name={name}"))
}

/// Federation-aware NIP-05 resolve. Pure D1 first (trust root); on miss in
/// `Federated` mode, fetches the operator's pod over HTTP and parses the
/// response. ADR-086 §3.
///
/// Failure modes per ADR-086 §5: pod offline → `None`; malformed JSON →
/// `None`; conflicting record never happens because D1 hit short-circuits
/// before the fetch.
pub async fn resolve(env: &Env, name: &str) -> std::result::Result<Option<String>, UsernameError> {
    validate_username(name)?;

    // Trust root: D1 first.
    if let Some(pk) = check(env, name).await? {
        return Ok(Some(pk));
    }

    // Mode + base URL gate.
    let mode_str = env.var("NIP05_RESOLVER_MODE").ok().map(|v| v.to_string());
    let mode = ResolverMode::from_env_str(mode_str.as_deref());
    if mode != ResolverMode::Federated {
        return Ok(None);
    }
    let pod_base = match env.var("POD_BASE_URL").ok().map(|v| v.to_string()) {
        Some(v) if !v.is_empty() => v,
        _ => return Ok(None), // No URL configured — silently degrade to D1-only.
    };

    let Some(url) = build_federated_url(&pod_base, name) else {
        return Ok(None);
    };

    // Short-timeout HTTP fetch. The CF Workers runtime does not expose a
    // direct timeout knob on `Fetch::Url`; the platform applies its own
    // hard ceiling (sub-second to a few seconds depending on plan) which
    // is acceptable for a verifier path.
    let request = match Request::new(&url, Method::Get) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    let mut resp = match Fetch::Request(request).send().await {
        Ok(r) => r,
        Err(_) => return Ok(None), // Pod offline / DNS / TLS — degrade silently.
    };
    if resp.status_code() != 200 {
        return Ok(None);
    }
    let body = match resp.bytes().await {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };
    Ok(parse_nip05_pubkey(&body, name))
}

/// `GET /api/username/resolve?name=alice` — ADR-086 federated NIP-05 resolve.
///
/// Response shape mirrors `handle_check` for client symmetry but
/// semantically returns NIP-05 resolution rather than availability:
///   200 `{"name": "alice", "pubkey": "<hex>"}` on hit (D1 or pod)
///   404 `{"error": "Not found"}` on miss
///   400 on invalid username
///   500 on backend failure
pub async fn handle_resolve(query: &[(String, String)], env: &Env) -> Result<Response> {
    let name = query
        .iter()
        .find(|(k, _)| k == "name")
        .map(|(_, v)| v.as_str())
        .unwrap_or("")
        .to_lowercase();

    if let Err(e) = validate_username(&name) {
        return json_response(env, &json!({ "error": e.message() }), e.http_status());
    }

    match resolve(env, &name).await {
        Ok(Some(pk)) => json_response(env, &json!({ "name": name, "pubkey": pk }), 200),
        Ok(None) => json_response(env, &json!({ "error": "Not found" }), 404),
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

    // ── ADR-086: ResolverMode parsing ─────────────────────────────────

    #[test]
    fn resolver_mode_defaults_to_d1_on_missing_env() {
        assert_eq!(ResolverMode::from_env_str(None), ResolverMode::D1);
    }

    #[test]
    fn resolver_mode_defaults_to_d1_on_empty_env() {
        assert_eq!(ResolverMode::from_env_str(Some("")), ResolverMode::D1);
        assert_eq!(ResolverMode::from_env_str(Some("   ")), ResolverMode::D1);
    }

    #[test]
    fn resolver_mode_parses_federated_case_insensitive() {
        assert_eq!(
            ResolverMode::from_env_str(Some("federated")),
            ResolverMode::Federated
        );
        assert_eq!(
            ResolverMode::from_env_str(Some("FEDERATED")),
            ResolverMode::Federated
        );
        assert_eq!(
            ResolverMode::from_env_str(Some(" Federated ")),
            ResolverMode::Federated
        );
    }

    #[test]
    fn resolver_mode_unknown_value_falls_back_to_d1() {
        // Refuse to silently enable federation on typo / future-mode names.
        assert_eq!(
            ResolverMode::from_env_str(Some("hybrid")),
            ResolverMode::D1
        );
        assert_eq!(
            ResolverMode::from_env_str(Some("d1")),
            ResolverMode::D1
        );
    }

    // ── ADR-086: build_federated_url ──────────────────────────────────

    #[test]
    fn build_federated_url_basic() {
        assert_eq!(
            build_federated_url("https://pods.example.com", "alice"),
            Some("https://pods.example.com/.well-known/nostr.json?name=alice".into())
        );
    }

    #[test]
    fn build_federated_url_strips_trailing_slash() {
        assert_eq!(
            build_federated_url("https://pods.example.com/", "alice"),
            Some("https://pods.example.com/.well-known/nostr.json?name=alice".into())
        );
    }

    #[test]
    fn build_federated_url_rejects_empty_name() {
        assert_eq!(build_federated_url("https://pods.example.com", ""), None);
    }

    // ── ADR-086: parse_nip05_pubkey (trust-boundary parser) ────────────

    #[test]
    fn parse_nip05_pubkey_happy_path() {
        let pk = "a".repeat(64);
        let body = format!(r#"{{"names":{{"alice":"{pk}"}}}}"#);
        assert_eq!(
            parse_nip05_pubkey(body.as_bytes(), "alice"),
            Some(pk)
        );
    }

    #[test]
    fn parse_nip05_pubkey_returns_none_for_unknown_name() {
        let pk = "a".repeat(64);
        let body = format!(r#"{{"names":{{"alice":"{pk}"}}}}"#);
        assert_eq!(parse_nip05_pubkey(body.as_bytes(), "bob"), None);
    }

    #[test]
    fn parse_nip05_pubkey_rejects_malformed_json() {
        assert_eq!(parse_nip05_pubkey(b"not json", "alice"), None);
        assert_eq!(parse_nip05_pubkey(b"", "alice"), None);
    }

    #[test]
    fn parse_nip05_pubkey_rejects_missing_names_field() {
        assert_eq!(parse_nip05_pubkey(br#"{"relays":{}}"#, "alice"), None);
    }

    #[test]
    fn parse_nip05_pubkey_rejects_non_string_pubkey() {
        assert_eq!(
            parse_nip05_pubkey(br#"{"names":{"alice":42}}"#, "alice"),
            None
        );
    }

    #[test]
    fn parse_nip05_pubkey_rejects_wrong_length() {
        // 63 chars
        let pk = "a".repeat(63);
        let body = format!(r#"{{"names":{{"alice":"{pk}"}}}}"#);
        assert_eq!(parse_nip05_pubkey(body.as_bytes(), "alice"), None);
        // 65 chars
        let pk = "a".repeat(65);
        let body = format!(r#"{{"names":{{"alice":"{pk}"}}}}"#);
        assert_eq!(parse_nip05_pubkey(body.as_bytes(), "alice"), None);
    }

    #[test]
    fn parse_nip05_pubkey_rejects_non_hex() {
        let body = r#"{"names":{"alice":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}}"#;
        assert_eq!(parse_nip05_pubkey(body.as_bytes(), "alice"), None);
    }

    #[test]
    fn parse_nip05_pubkey_rejects_uppercase_hex() {
        // NIP-05 mandates lowercase hex. Strict parsing prevents canonicalisation surprises.
        let pk = "A".repeat(64);
        let body = format!(r#"{{"names":{{"alice":"{pk}"}}}}"#);
        assert_eq!(parse_nip05_pubkey(body.as_bytes(), "alice"), None);
    }
}
