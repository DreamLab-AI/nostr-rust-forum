//! NIP-98 admin verification for the relay worker.
//!
//! Verifies the `Authorization: Nostr <base64(event)>` header using
//! D1-backed atomic replay protection via `nostr_bbs_rate_limit::verify_nip98`,
//! then checks whether the authenticated pubkey holds admin privileges via the
//! D1 `whitelist.is_admin` column.

use nostr_bbs_core::nip98::{Nip98Error, Nip98Token};
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::Env;

/// D1 binding name for the replay store (same DB as the relay's main tables).
const REPLAY_DB: &str = "DB";

/// Current Unix timestamp in seconds from the JS runtime.
pub fn js_now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Verify a NIP-98 `Authorization` header with D1-backed atomic replay protection.
pub async fn verify_nip98_replay(
    auth_header: &str,
    expected_url: &str,
    expected_method: &str,
    body: Option<&[u8]>,
    env: &Env,
) -> Result<Nip98Token, Nip98Error> {
    nostr_bbs_rate_limit::verify_nip98(
        auth_header,
        expected_url,
        expected_method,
        body,
        env,
        REPLAY_DB,
    )
    .await
}

// ---------------------------------------------------------------------------
// Admin checks
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct IsAdminRow {
    is_admin: i32,
}

/// Check whether a pubkey is an admin by querying the D1 `whitelist` table.
pub async fn is_admin(pubkey: &str, env: &Env) -> bool {
    if let Ok(db) = env.d1("DB") {
        let stmt = db.prepare("SELECT is_admin FROM whitelist WHERE pubkey = ?1");
        if let Ok(bound) = stmt.bind(&[JsValue::from_str(pubkey)]) {
            if let Ok(Some(row)) = bound.first::<IsAdminRow>(None).await {
                return row.is_admin == 1;
            }
        }
    }
    false
}

/// Verify NIP-98 auth and assert the authenticated pubkey is an admin.
///
/// Returns `Ok(pubkey_hex)` on success, or an error tuple `(json_body, status_code)`
/// suitable for building an error response.
pub async fn require_nip98_admin(
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

    let token = verify_nip98_replay(auth, request_url, method, body, env)
        .await
        .map_err(|_| {
            (
                serde_json::json!({ "error": "Invalid NIP-98 token" }),
                401u16,
            )
        })?;

    if !is_admin(&token.pubkey, env).await {
        return Err((serde_json::json!({ "error": "Not authorized" }), 403));
    }

    Ok(token.pubkey)
}
