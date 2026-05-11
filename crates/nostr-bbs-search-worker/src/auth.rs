//! NIP-98 authentication for the search worker.
//!
//! Ingest endpoint requires NIP-98 admin auth. Uses D1-backed atomic replay
//! protection via `nostr_bbs_rate_limit::verify_nip98`.

use nostr_bbs_core::nip98::{Nip98Error, Nip98Token};
use worker::Env;

/// D1 binding name for the replay store.
const REPLAY_DB: &str = "REPLAY_DB";

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

/// Synchronous, replay-FREE verification (legacy callers).
#[deprecated(
    since = "0.2.0",
    note = "Use verify_nip98_replay; this skips replay protection"
)]
pub fn verify_nip98(
    auth_header: &str,
    expected_url: &str,
    expected_method: &str,
    body: Option<&[u8]>,
) -> Result<Nip98Token, Nip98Error> {
    let now = (js_sys::Date::now() / 1000.0) as u64;
    nostr_bbs_core::verify_nip98_token_at(auth_header, expected_url, expected_method, body, now)
}

/// Return the list of admin pubkeys from the `ADMIN_PUBKEYS` environment variable.
pub fn admin_pubkeys(env: &Env) -> Vec<String> {
    env.var("ADMIN_PUBKEYS")
        .map(|v| v.to_string())
        .unwrap_or_default()
        .split(',')
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
        .collect()
}

/// Check whether a pubkey is listed in the `ADMIN_PUBKEYS` environment variable.
pub fn is_admin(pubkey: &str, env: &Env) -> bool {
    admin_pubkeys(env).iter().any(|k| k == pubkey)
}

/// Verify NIP-98 auth and assert the authenticated pubkey is an admin.
///
/// Returns `Ok(pubkey_hex)` on success, or an error tuple `(json_body, status_code)`.
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

    if !is_admin(&token.pubkey, env) {
        return Err((serde_json::json!({ "error": "Not authorized" }), 403));
    }

    Ok(token.pubkey)
}
