//! NIP-98 authentication for the search worker.
//!
//! Ingest endpoint requires NIP-98 admin auth. Uses D1-backed atomic replay
//! protection via `nostr_bbs_rate_limit::verify_nip98`.
//!
//! ## Admin check (`ADMIN_PUBKEYS` static set)
//!
//! Unlike the auth-worker and pod-worker, this worker does **not** have a D1
//! binding to the members/whitelist tables. Admin membership is determined by
//! the `ADMIN_PUBKEYS` environment variable (comma-separated hex pubkeys) —
//! the **static** half of the canonical `static ∪ D1` resolution order. The
//! auth-worker reads this same env var (its bootstrap/fallback set) plus D1, so
//! when the deploy pipeline injects `forum.toml [admin] static_pubkeys` into
//! `ADMIN_PUBKEYS` for both workers, the search-worker admin set is a subset of
//! the auth-worker set and no longer diverges (Gap 2).
//!
//! Parsing goes through [`nostr_bbs_core::admin_pubkeys_from_env_str`] — the
//! single canonical parser shared with the auth-worker — so the
//! comma/whitespace/empty semantics cannot drift between the two WASM targets.
//!
//! This is a deliberate tradeoff: the search worker's only admin-gated
//! endpoint is the ingest trigger, and adding a D1 binding would increase
//! cold-start latency for a single rarely-used route. If the search worker
//! grows endpoints that need the *dynamic* D1 admins, migrate it to the
//! D1-backed queries in [`nostr_bbs_core::admin_shared`].

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

/// Return the list of admin pubkeys from the `ADMIN_PUBKEYS` environment
/// variable, parsed through the canonical shared parser so the semantics match
/// the auth-worker exactly.
pub fn admin_pubkeys(env: &Env) -> Vec<String> {
    let raw = env
        .var(nostr_bbs_core::ADMIN_PUBKEYS_VAR)
        .map(|v| v.to_string())
        .unwrap_or_default();
    nostr_bbs_core::admin_pubkeys_from_env_str(&raw)
}

/// Check whether a pubkey is listed in the `ADMIN_PUBKEYS` environment variable.
pub fn is_admin(pubkey: &str, env: &Env) -> bool {
    let raw = env
        .var(nostr_bbs_core::ADMIN_PUBKEYS_VAR)
        .map(|v| v.to_string())
        .unwrap_or_default();
    nostr_bbs_core::is_static_admin(pubkey, &raw)
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
