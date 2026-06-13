//! NIP-98 admin verification for the relay worker.
//!
//! Verifies the `Authorization: Nostr <base64(event)>` header using
//! D1-backed atomic replay protection via `nostr_bbs_rate_limit::verify_nip98`,
//! then checks whether the authenticated pubkey holds admin privileges via the
//! D1 `whitelist.is_admin` column.
//!
//! ## Admin cache (P2-03)
//!
//! Every incoming EVENT previously triggered 1-3 D1 queries just for admin
//! checks. [`AdminCache`] provides an in-memory TTL cache (default 5 min)
//! keyed by pubkey, eliminating redundant D1 round-trips on the hot path.
//! The cache lives inside [`super::relay_do::NostrRelayDO`] and is safe to
//! use in the single-threaded V8 Durable Object isolate via `RefCell`.

use std::cell::RefCell;
use std::collections::HashMap;

use nostr_bbs_core::nip98::{Nip98Error, Nip98Token};
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::Env;

/// D1 binding name for the NIP-98 replay store. Points at the shared
/// auth-worker D1 database so cross-worker replay is detected.
///
/// P0-03 fix: previously this was "DB" which resolved to the relay's own
/// D1 database (nostr-bbs-relay), not the shared auth database
/// (nostr-bbs-auth). The nip98_replay table only exists in the auth DB,
/// so replay protection was silently skipped.
const REPLAY_DB: &str = "REPLAY_DB";

/// Admin-cache TTL in seconds (5 minutes).
const ADMIN_CACHE_TTL_SECS: u64 = 300;

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
// Admin cache (P2-03)
// ---------------------------------------------------------------------------

/// Cached admin-status entry: the boolean result and the timestamp at which
/// it was fetched from D1.
#[derive(Clone, Copy)]
struct AdminEntry {
    is_admin: bool,
    fetched_at: u64,
}

/// In-memory TTL cache for admin status lookups.
///
/// Designed for the single-threaded Cloudflare Workers Durable Object runtime.
/// All mutable access goes through interior `RefCell`, matching the pattern
/// used by `NostrRelayDO` for sessions and rate limits.
pub struct AdminCache {
    entries: RefCell<HashMap<String, AdminEntry>>,
}

impl AdminCache {
    pub fn new() -> Self {
        Self {
            entries: RefCell::new(HashMap::new()),
        }
    }

    /// Look up admin status for `pubkey`, using the cache when the entry is
    /// fresh (within `ADMIN_CACHE_TTL_SECS`). On a miss or expiry, queries
    /// D1 and stores the result.
    pub async fn is_admin(&self, pubkey: &str, env: &Env) -> bool {
        let now = js_now_secs();

        // Fast path: cache hit within TTL.
        {
            let entries = self.entries.borrow();
            if let Some(entry) = entries.get(pubkey) {
                if now.saturating_sub(entry.fetched_at) < ADMIN_CACHE_TTL_SECS {
                    return entry.is_admin;
                }
            }
        }

        // Cache miss or expired — query D1.
        let result = query_is_admin(pubkey, env).await;

        // Store result.
        {
            let mut entries = self.entries.borrow_mut();
            entries.insert(
                pubkey.to_string(),
                AdminEntry {
                    is_admin: result,
                    fetched_at: now,
                },
            );
        }

        result
    }

    /// Invalidate a single entry (e.g. after an admin status change).
    pub fn invalidate(&self, pubkey: &str) {
        self.entries.borrow_mut().remove(pubkey);
    }
}

// ---------------------------------------------------------------------------
// D1 admin query (extracted from former `is_admin`)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct IsAdminRow {
    is_admin: i32,
}

/// Query D1 to check whether a pubkey is an admin via the `members` and
/// `whitelist` tables, consistent with the auth-worker's admin model.
///
/// P0-02 fix: previously only `whitelist` was checked, which meant a user
/// added as admin via the `members` table would be rejected by the relay
/// for admin-gated NIP-29 events.
///
/// Task #7 fix (admin-resolution): resolution order is now
/// **`ADMIN_PUBKEYS` (static) ∪ D1**, matching the auth-worker
/// (`crate::admin::is_admin`). The static set is the deploy-time
/// bootstrap/fallback authority — it projects `dreamlab.toml [admin]
/// static_pubkeys` so a fresh deployment whose relay `whitelist`/`members`
/// tables carry no `is_admin = 1` row still has working admins. Without this,
/// the relay's admin-gated endpoints (`/api/whitelist/list`, etc.) 401/403 for
/// the operator and the admin panel renders empty, with no way to bootstrap an
/// admin (adding one requires being one). The var is read through the canonical
/// `nostr_bbs_core` helpers so the comma/whitespace/npub-or-hex semantics never
/// drift from the auth- and search-workers.
async fn query_is_admin(pubkey: &str, env: &Env) -> bool {
    // Static admin set (ADMIN_PUBKEYS): deploy-time bootstrap/fallback. Checked
    // before D1 so a no-seed deployment still authenticates the operator.
    if let Ok(raw) = env
        .var(nostr_bbs_core::ADMIN_PUBKEYS_VAR)
        .map(|v| v.to_string())
    {
        if nostr_bbs_core::is_static_admin(pubkey, &raw) {
            return true;
        }
    }

    if let Ok(db) = env.d1("DB") {
        let stmt = db.prepare("SELECT is_admin FROM members WHERE pubkey = ?1");
        if let Ok(bound) = stmt.bind(&[JsValue::from_str(pubkey)]) {
            if let Ok(Some(row)) = bound.first::<IsAdminRow>(None).await {
                if row.is_admin == 1 {
                    return true;
                }
            }
        }

        let stmt = db.prepare("SELECT is_admin FROM whitelist WHERE pubkey = ?1");
        if let Ok(bound) = stmt.bind(&[JsValue::from_str(pubkey)]) {
            if let Ok(Some(row)) = bound.first::<IsAdminRow>(None).await {
                return row.is_admin == 1;
            }
        }
    }
    false
}

/// Check whether a pubkey is an admin (uncached — queries D1 directly).
///
/// Kept for call sites outside the Durable Object (e.g. `require_nip98_admin`)
/// that don't have access to the `AdminCache` instance.
pub async fn is_admin(pubkey: &str, env: &Env) -> bool {
    query_is_admin(pubkey, env).await
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
