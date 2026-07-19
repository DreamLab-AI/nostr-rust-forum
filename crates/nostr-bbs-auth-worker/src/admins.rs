//! WI-8 Admin management API.
//!
//! Endpoints (all NIP-98 gated, caller must be admin):
//!
//! | Method | Path                | Purpose                                  |
//! |--------|---------------------|------------------------------------------|
//! | GET    | /api/admins         | List all is_admin=1 pubkeys              |
//! | POST   | /api/admins/add     | Grant admin; ensures whitelist row exists |
//! | POST   | /api/admins/remove  | Revoke admin (cannot remove yourself)    |
//!
//! The KV-cached admin list used elsewhere is invalidated on every mutation
//! so the next request re-populates from D1 (TTL = 60 s).

use serde::Deserialize;
use serde_json::json;
use wasm_bindgen::JsValue;
use worker::{Env, Response, Result};

use crate::admin::{canonical_url, now_secs, require_admin};
use crate::http::{error_json, json_response};

// Admin list KV cache key — shared with the get_admin_pubkeys helper.
pub(crate) const ADMIN_CACHE_KEY: &str = "admin_pubkeys_cache";

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct PubkeyBody {
    pubkey: String,
}

// ---------------------------------------------------------------------------
// D1 row types — use shared types from nostr_bbs_core (P2-01)
// ---------------------------------------------------------------------------

use nostr_bbs_core::admin_shared::PubkeyRow;

// ---------------------------------------------------------------------------
// KV-cached admin lookup (60-second TTL)
//
// Used by moderation.rs and admin.rs to avoid a D1 round-trip on every
// admin-gated request. The cache is busted by the add/remove handlers below.
// ---------------------------------------------------------------------------

/// Fetch the admin pubkey list, using KV as a 60-second cache.
///
/// On cache miss: queries D1 (both `members` and `whitelist` tables),
/// serialises to JSON, stores in KV with `expirationTtl = 60`.
/// On cache hit: deserialises and returns immediately.
pub async fn get_admin_pubkeys(env: &Env) -> Result<Vec<String>> {
    // Attempt KV cache read.
    let kv = env.kv("KV")?;
    if let Ok(Some(cached)) = kv.get(ADMIN_CACHE_KEY).text().await {
        if let Ok(list) = serde_json::from_str::<Vec<String>>(&cached) {
            return Ok(list);
        }
    }

    // Cache miss — resolve static (ADMIN_PUBKEYS) ∪ D1, matching the
    // canonical order in `admin::is_admin`. Check both RELAY_DB (relay's
    // whitelist, the source of truth for dynamic admin flags) and DB (auth's
    // members table, set by the invite-redemption flow).
    let mut pubkeys: Vec<String> = Vec::new();

    // Static admin set (ADMIN_PUBKEYS): deploy-time bootstrap/fallback, so a
    // fresh D1 still surfaces the operator's static admins here (Gap 1/2).
    if let Ok(raw) = env
        .var(nostr_bbs_core::ADMIN_PUBKEYS_VAR)
        .map(|v| v.to_string())
    {
        for k in nostr_bbs_core::admin_pubkeys_from_env_str(&raw) {
            if !pubkeys.contains(&k) {
                pubkeys.push(k);
            }
        }
    }

    // RELAY_DB: whitelist.is_admin (source of truth)
    if let Ok(relay_db) = env.d1("RELAY_DB") {
        let whitelist = relay_db
            .prepare(nostr_bbs_core::WHITELIST_ADMIN_LIST_SQL)
            .all()
            .await;
        if let Ok(result) = whitelist {
            if let Ok(rows) = result.results::<PubkeyRow>() {
                for r in rows {
                    if !pubkeys.contains(&r.pubkey) {
                        pubkeys.push(r.pubkey);
                    }
                }
            }
        }
    }

    // DB: members.is_admin (invite flow)
    if let Ok(db) = env.d1("DB") {
        let members = db
            .prepare(nostr_bbs_core::MEMBERS_ADMIN_LIST_SQL)
            .all()
            .await;
        if let Ok(result) = members {
            if let Ok(rows) = result.results::<PubkeyRow>() {
                for r in rows {
                    if !pubkeys.contains(&r.pubkey) {
                        pubkeys.push(r.pubkey);
                    }
                }
            }
        }
    }

    // Store in KV with 60-second TTL (best-effort; ignore errors).
    if let Ok(serialised) = serde_json::to_string(&pubkeys) {
        if let Ok(builder) = kv.put(ADMIN_CACHE_KEY, serialised) {
            let _ = builder.expiration_ttl(60).execute().await;
        }
    }

    Ok(pubkeys)
}

/// Invalidate the KV admin cache so the next request re-fetches from D1.
async fn bust_cache(env: &Env) {
    if let Ok(kv) = env.kv("KV") {
        let _ = kv.delete(ADMIN_CACHE_KEY).await;
    }
}

// ---------------------------------------------------------------------------
// GET /api/admins
// ---------------------------------------------------------------------------

pub async fn handle_list(auth_header: Option<&str>, env: &Env, origin: &str) -> Result<Response> {
    let url = canonical_url(origin, "/api/admins");
    if let Err((body, status)) = require_admin(auth_header, &url, "GET", None, env).await {
        return json_response(env, &body, status);
    }

    let pubkeys = match get_admin_pubkeys(env).await {
        Ok(p) => p,
        Err(e) => return error_json(env, &format!("Admin lookup failed: {e}"), 500),
    };

    json_response(env, &json!({ "admins": pubkeys }), 200)
}

// ---------------------------------------------------------------------------
// POST /api/admins/add
// ---------------------------------------------------------------------------

pub async fn handle_add(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/admins/add");
    if let Err((body, status)) =
        require_admin(auth_header, &url, "POST", Some(body_bytes), env).await
    {
        return json_response(env, &body, status);
    }

    let body: PubkeyBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("Invalid JSON body: {e}"), 400),
    };

    if body.pubkey.len() != 64 || !body.pubkey.bytes().all(|b| b.is_ascii_hexdigit()) {
        return error_json(env, "pubkey must be a 64-char hex string", 400);
    }

    let now = now_secs() as i64;

    // RELAY_DB (nostr-bbs-relay): the relay's whitelist is the source of
    // truth for admin flags. Write there so the relay DO and this worker's
    // is_admin() both see the change immediately.
    let relay_db = match env.d1("RELAY_DB") {
        Ok(db) => db,
        Err(_) => return error_json(env, "RELAY_DB unavailable", 500),
    };

    let upsert = relay_db
        .prepare(
            "INSERT INTO whitelist (pubkey, is_admin, cohorts, added_at) \
             VALUES (?1, 1, '[\"home\"]', ?2) \
             ON CONFLICT (pubkey) DO UPDATE SET is_admin = 1",
        )
        .bind(&[
            JsValue::from_str(&body.pubkey),
            JsValue::from_f64(now as f64),
        ])?
        .run()
        .await;

    if let Err(e) = upsert {
        return error_json(env, &format!("RELAY_DB error: {e}"), 500);
    }

    // DB (nostr-bbs-auth): also ensure a members row exists for the
    // invite-flow admin set.
    if let Ok(db) = env.d1("DB") {
        let _ = db
            .prepare(
                "INSERT INTO members (pubkey, is_admin, created_at) \
                 VALUES (?1, 1, ?2) \
                 ON CONFLICT (pubkey) DO UPDATE SET is_admin = 1",
            )
            .bind(&[
                JsValue::from_str(&body.pubkey),
                JsValue::from_f64(now as f64),
            ])?
            .run()
            .await;
    }

    bust_cache(env).await;

    json_response(
        env,
        &json!({ "ok": true, "pubkey": body.pubkey, "action": "admin_added" }),
        200,
    )
}

// ---------------------------------------------------------------------------
// POST /api/admins/remove
// ---------------------------------------------------------------------------

pub async fn handle_remove(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/admins/remove");
    let caller = match require_admin(auth_header, &url, "POST", Some(body_bytes), env).await {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let body: PubkeyBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("Invalid JSON body: {e}"), 400),
    };

    if body.pubkey.len() != 64 || !body.pubkey.bytes().all(|b| b.is_ascii_hexdigit()) {
        return error_json(env, "pubkey must be a 64-char hex string", 400);
    }

    // Prevent self-removal to avoid lockout.
    if body.pubkey == caller {
        return error_json(env, "Cannot remove your own admin rights", 403);
    }

    // RELAY_DB: source of truth for whitelist admin flags
    let relay_db = match env.d1("RELAY_DB") {
        Ok(db) => db,
        Err(_) => return error_json(env, "RELAY_DB unavailable", 500),
    };

    let update_whitelist = relay_db
        .prepare("UPDATE whitelist SET is_admin = 0 WHERE pubkey = ?1")
        .bind(&[JsValue::from_str(&body.pubkey)])?
        .run()
        .await;
    if let Err(e) = update_whitelist {
        return error_json(env, &format!("RELAY_DB error: {e}"), 500);
    }

    // DB: also clear members.is_admin
    if let Ok(db) = env.d1("DB") {
        let _ = db
            .prepare("UPDATE members SET is_admin = 0 WHERE pubkey = ?1")
            .bind(&[JsValue::from_str(&body.pubkey)])?
            .run()
            .await;
    }

    bust_cache(env).await;

    json_response(
        env,
        &json!({ "ok": true, "pubkey": body.pubkey, "action": "admin_removed" }),
        200,
    )
}

/// `POST /api/admins/delete-member` — NIP-98 admin only (Task #7).
///
/// Hard-deletes a user's **auth-side** records: the `members` row (invite/admin
/// state) and the `username_reservations` row (claimed handle + admin-only
/// `real_name`). This is the auth half of "delete user"; the relay half
/// (`POST /api/admin/user/delete` on the relay worker) removes the whitelist row
/// and optionally purges events. The client calls both so a deleted user leaves
/// no handle/real-name residue and cannot resolve to a stale display name.
///
/// Body: `{ "pubkey": "<hex>" }`. Self-deletion is refused to avoid lockout.
pub async fn handle_delete_member(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/admins/delete-member");
    let caller = match require_admin(auth_header, &url, "POST", Some(body_bytes), env).await {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let body: PubkeyBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("Invalid JSON body: {e}"), 400),
    };

    if body.pubkey.len() != 64 || !body.pubkey.bytes().all(|b| b.is_ascii_hexdigit()) {
        return error_json(env, "pubkey must be a 64-char hex string", 400);
    }

    // Prevent self-deletion to avoid lockout.
    if body.pubkey == caller {
        return error_json(env, "Cannot delete your own account", 403);
    }

    // DB (nostr-bbs-auth): drop the members row and the username reservation
    // (which carries the claimed handle and the admin-only real_name).
    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return error_json(env, "DB unavailable", 500),
    };

    let _ = db
        .prepare("DELETE FROM members WHERE pubkey = ?1")
        .bind(&[JsValue::from_str(&body.pubkey)])?
        .run()
        .await;
    let _ = db
        .prepare("DELETE FROM username_reservations WHERE pubkey = ?1")
        .bind(&[JsValue::from_str(&body.pubkey)])?
        .run()
        .await;

    // Bust the admin-list cache in case the deleted member held admin.
    bust_cache(env).await;

    json_response(
        env,
        &json!({ "ok": true, "pubkey": body.pubkey, "action": "member_deleted" }),
        200,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_cache_key_is_stable() {
        assert_eq!(ADMIN_CACHE_KEY, "admin_pubkeys_cache");
    }

    #[test]
    fn pubkey_hex_validation() {
        let valid = "a".repeat(64);
        assert!(valid.len() == 64 && valid.bytes().all(|b: u8| b.is_ascii_hexdigit()));
        let too_short = "a".repeat(63);
        assert!(too_short.len() != 64);
        let non_hex = "g".repeat(64);
        assert!(!non_hex.bytes().all(|b: u8| b.is_ascii_hexdigit()));
    }
}
