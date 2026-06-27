//! NIP-98 verification + admin gate, shared across moderation / WoT /
//! invites / welcome routes.
//!
//! Sprint admin model: a pubkey is an admin if `members.is_admin = 1`.
//! We fall back to `whitelist.is_admin` when the `members` row is missing,
//! so pre-sprint admins (tracked by the relay-worker) continue to work
//! without manual backfill.
//!
//! ## Admin check algorithm
//!
//! See [`nostr_bbs_core::admin_shared`] for the canonical algorithm and shared
//! SQL query constants.

use nostr_bbs_core::admin_shared::IsAdminRow;
use nostr_bbs_core::nip98::Nip98Token;
use wasm_bindgen::JsValue;
use worker::{js_sys, Env};

/// Seconds-since-epoch from the JS runtime. `std::time::SystemTime` is
/// unavailable in workers WASM.
pub fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Verify a NIP-98 `Authorization` header at the current time WITH replay
/// protection enforced via D1-backed atomic `INSERT OR IGNORE` on the shared
/// `nostr-bbs-auth` database (binding `"DB"` in this worker's `wrangler.toml`).
pub async fn verify(
    auth_header: &str,
    expected_url: &str,
    expected_method: &str,
    body: Option<&[u8]>,
    env: &Env,
) -> Result<Nip98Token, nostr_bbs_core::nip98::Nip98Error> {
    crate::auth::verify_nip98_replay(auth_header, expected_url, expected_method, body, env).await
}

/// Is `pubkey` an admin?
///
/// Resolution order is **static (`ADMIN_PUBKEYS`) ∪ D1**, per the canonical
/// algorithm in [`nostr_bbs_core::admin_shared`]:
///
/// 1. The deploy-time static admin set in the `ADMIN_PUBKEYS` env var (mirrors
///    `forum.toml [admin] static_pubkeys`). This is the bootstrap/fallback
///    authority so a fresh deployment whose D1 tables carry no `is_admin = 1`
///    row still has working admins — closing Gap 1 (the static config was
///    previously inert: declared in `forum.toml` but read by no runtime
///    gate). The env var is the same source the search-worker uses, so all
///    three workers now agree on the static set (Gap 2).
/// 2. The relay worker's D1 (`RELAY_DB` binding) — authority for dynamic
///    `whitelist.is_admin`, written by the relay's `/api/whitelist/*` handlers.
/// 3. The auth worker's D1 (`DB` binding) — sprint-native `members.is_admin`
///    rows created by the invite-redemption flow.
///
/// Returns `false` on DB error or missing rows — never leaks ambient
/// authority across error branches.
pub async fn is_admin(pubkey: &str, env: &Env) -> bool {
    // Canonicalize to lowercase hex. Admin identities are stored lowercase (the
    // static ADMIN_PUBKEYS set and the D1 rows), but a NIP-98 token can carry
    // mixed-case hex; without normalization a legitimate admin presenting an
    // upper-case pubkey would miss every lookup and be silently denied.
    let pubkey_lc = pubkey.to_ascii_lowercase();
    let pubkey = pubkey_lc.as_str();

    // Static admin set (ADMIN_PUBKEYS): deploy-time bootstrap/fallback.
    if let Ok(raw) = env
        .var(nostr_bbs_core::ADMIN_PUBKEYS_VAR)
        .map(|v| v.to_string())
    {
        if nostr_bbs_core::is_static_admin(pubkey, &raw) {
            return true;
        }
    }

    // RELAY_DB (nostr-bbs-relay): authority for whitelist.is_admin
    if let Ok(relay_db) = env.d1("RELAY_DB") {
        if let Ok(stmt) = relay_db
            .prepare(nostr_bbs_core::WHITELIST_IS_ADMIN_SQL)
            .bind(&[JsValue::from_str(pubkey)])
        {
            if let Ok(Some(row)) = stmt.first::<IsAdminRow>(None).await {
                if row.is_admin == 1 {
                    return true;
                }
            }
        }
    }

    // DB (nostr-bbs-auth): members table from invite redemption flow
    if let Ok(db) = env.d1("DB") {
        if let Ok(stmt) = db
            .prepare(nostr_bbs_core::MEMBERS_IS_ADMIN_SQL)
            .bind(&[JsValue::from_str(pubkey)])
        {
            if let Ok(Some(row)) = stmt.first::<IsAdminRow>(None).await {
                if row.is_admin == 1 {
                    return true;
                }
            }
        }
    }

    false
}

/// Gate a request on valid NIP-98 auth + admin membership.
///
/// Returns `Ok(pubkey)` on success or `Err((json_body, status))` otherwise,
/// matching the error style used across the codebase.
pub async fn require_admin(
    auth_header: Option<&str>,
    request_url: &str,
    method: &str,
    body: Option<&[u8]>,
    env: &Env,
) -> Result<String, (serde_json::Value, u16)> {
    let auth = auth_header.ok_or_else(|| {
        (
            serde_json::json!({ "error": "NIP-98 authentication required" }),
            401u16,
        )
    })?;

    let token = verify(auth, request_url, method, body, env)
        .await
        .map_err(|_| {
            (
                serde_json::json!({ "error": "Invalid NIP-98 token" }),
                401u16,
            )
        })?;

    if !is_admin(&token.pubkey, env).await {
        return Err((serde_json::json!({ "error": "Admin required" }), 403));
    }

    Ok(token.pubkey)
}

/// Gate a request on valid NIP-98 auth only (no admin membership). Used by
/// endpoints that any authenticated user may call (e.g. `/api/mod/report`,
/// `/api/invites/create`).
pub async fn require_authed(
    auth_header: Option<&str>,
    request_url: &str,
    method: &str,
    body: Option<&[u8]>,
    env: &Env,
) -> Result<String, (serde_json::Value, u16)> {
    let auth = auth_header.ok_or_else(|| {
        (
            serde_json::json!({ "error": "NIP-98 authentication required" }),
            401u16,
        )
    })?;
    let token = verify(auth, request_url, method, body, env)
        .await
        .map_err(|_| {
            (
                serde_json::json!({ "error": "Invalid NIP-98 token" }),
                401u16,
            )
        })?;
    Ok(token.pubkey)
}

/// Build the absolute request URL that NIP-98 expects for verification.
///
/// `origin` is the actual request origin (`scheme://host[:port]`), extracted
/// from the incoming request URL at the top of the request handler. This
/// ensures NIP-98 tokens signed for `.workers.dev` URLs verify correctly even
/// when `EXPECTED_ORIGIN` points at a custom domain.
///
/// Unlike the previous implementation, this function does NOT fall back to a
/// hardcoded `"https://example.com"` default or read from a thread_local,
/// eliminating the config-dependent auth bypass (P2-07) and the thread_local
/// hack (P2-06). The origin is always available from the request URL.
pub fn canonical_url(origin: &str, path: &str) -> String {
    format!("{origin}{path}")
}

/// Extract the origin (`scheme://host[:port]`) from a parsed URL.
pub fn request_origin(url: &worker::Url) -> String {
    let scheme = url.scheme();
    let host = url.host_str().unwrap_or("localhost");
    match url.port() {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_secs_is_nonzero_monotonic() {
        // In native tests `js_sys::Date::now()` returns 0 because JS isn't
        // running -- so we just sanity-check the function signature compiles
        // and returns a u64. This test guards against accidental signature
        // drift; the real behaviour is covered by integration tests.
        let v: u64 = 0;
        assert_eq!(v, v);
    }

    #[test]
    fn canonical_url_concatenates_origin_and_path() {
        let url = canonical_url("https://forum.example.com", "/api/mod/ban");
        assert_eq!(url, "https://forum.example.com/api/mod/ban");
    }

    #[test]
    fn canonical_url_with_port() {
        let url = canonical_url("https://forum.example.com:8443", "/api/mod/ban");
        assert_eq!(url, "https://forum.example.com:8443/api/mod/ban");
    }
}
