//! Whitelist management HTTP handlers.
//!
//! Provides public and admin-only endpoints for checking, listing, adding, and
//! updating whitelist entries in the D1 `whitelist` table.

use serde::Deserialize;
use serde_json::json;
use wasm_bindgen::JsValue;
use worker::{Env, Request, Response, Result};

use crate::audit;
use crate::auth;
use crate::cors::json_response;

// ---------------------------------------------------------------------------
// JsValue helpers
// ---------------------------------------------------------------------------

fn js_str(s: &str) -> JsValue {
    JsValue::from_str(s)
}

fn js_f64(v: f64) -> JsValue {
    JsValue::from_f64(v)
}

// ---------------------------------------------------------------------------
// D1 row types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CohortRow {
    cohorts: String,
    is_admin: Option<i32>,
}

#[derive(Deserialize)]
struct WhitelistRow {
    pubkey: String,
    cohorts: String,
    added_at: f64,
    added_by: Option<String>,
    profile_content: Option<String>,
    is_admin: Option<i32>,
}

#[derive(Deserialize)]
struct CountRow {
    count: f64,
}

// ---------------------------------------------------------------------------
// Request body types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct WhitelistAddBody {
    pubkey: Option<String>,
    cohorts: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct WhitelistUpdateCohortsBody {
    pubkey: Option<String>,
    cohorts: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct SetAdminBody {
    pubkey: Option<String>,
    is_admin: Option<bool>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/check-whitelist?pubkey=<hex>`
///
/// Returns the whitelist status for a given pubkey, including admin status and
/// cohort memberships. Public endpoint used by the community forum client.
pub async fn handle_check_whitelist(req: &Request, env: &Env) -> Result<Response> {
    let url = req.url()?;
    let pubkey = url
        .query_pairs()
        .find(|(k, _)| k == "pubkey")
        .map(|(_, v)| v.to_string())
        .unwrap_or_default();

    if pubkey.len() != 64 || !pubkey.bytes().all(|b| b.is_ascii_hexdigit()) {
        return json_response(env, &json!({ "error": "Invalid pubkey format" }), 400);
    }

    let db = env.d1("DB")?;
    let now = auth::js_now_secs();

    let stmt = db
        .prepare("SELECT cohorts, is_admin FROM whitelist WHERE pubkey = ?1 AND (expires_at IS NULL OR expires_at > ?2)")
        .bind(&[js_str(&pubkey), js_f64(now as f64)])?;

    let entry = stmt.first::<CohortRow>(None).await?;
    let is_admin_key = entry
        .as_ref()
        .map(|row| row.is_admin.unwrap_or(0) == 1)
        .unwrap_or(false);

    let cohorts: Vec<String> = entry
        .as_ref()
        .and_then(|row| serde_json::from_str(&row.cohorts).ok())
        .unwrap_or_default();

    // Compute 3-boolean access flags from legacy cohort values
    let has_home = is_admin_key
        || cohorts.iter().any(|c| matches!(c.as_str(), "home" | "lobby" | "approved" | "cross-access"));
    let has_members = is_admin_key
        || cohorts.iter().any(|c| matches!(c.as_str(),
            "members" | "business" | "business-only" | "trainers" | "trainees"
            | "ai-agents" | "agent" | "visionflow-full" | "cross-access"
        ));
    let has_private = is_admin_key
        || cohorts.iter().any(|c| matches!(c.as_str(),
            "private" | "private-only" | "private-business" | "cross-access"
        ));

    json_response(
        env,
        &json!({
            "isWhitelisted": entry.is_some() || is_admin_key,
            "isAdmin": is_admin_key,
            "cohorts": cohorts,
            "access": {
                "home": has_home,
                "members": has_members,
                "private": has_private,
            },
            "verifiedAt": js_sys::Date::now() as u64,
            "source": "relay",
        }),
        200,
    )
}

/// `GET /api/whitelist/list?limit=&offset=&cohort=`
///
/// Paginated whitelist with optional cohort filter. Joins with the events table
/// to extract `display_name` from the most recent kind-0 profile event.
pub async fn handle_whitelist_list(req: &Request, env: &Env) -> Result<Response> {
    let url = req.url()?;
    let params: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let limit: u32 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(20)
        .min(100);
    let offset: u32 = params
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let cohort = params.get("cohort").cloned();

    let db = env.d1("DB")?;
    let now = auth::js_now_secs();

    // Build count query
    let (count_sql, list_sql, bind_values) = if let Some(ref cohort_val) = cohort {
        // Escape LIKE wildcards and strip quotes to prevent pattern injection
        let escaped = cohort_val
            .replace('%', "\\%")
            .replace('_', "\\_")
            .replace('"', "");
        let like_pattern = format!("%\"{escaped}\"%");

        let count =
            "SELECT COUNT(*) as count FROM whitelist WHERE (expires_at IS NULL OR expires_at > ?1) AND cohorts LIKE ?2 ESCAPE '\\'".to_string();
        let list =
            "SELECT w.pubkey, w.cohorts, w.added_at, w.added_by, w.is_admin, \
             (SELECT e.content FROM events e WHERE e.pubkey = w.pubkey AND e.kind = 0 ORDER BY e.created_at DESC LIMIT 1) as profile_content \
             FROM whitelist w WHERE (w.expires_at IS NULL OR w.expires_at > ?1) AND w.cohorts LIKE ?2 ESCAPE '\\' \
             ORDER BY w.added_at DESC LIMIT ?3 OFFSET ?4".to_string();
        (
            count,
            list,
            vec![
                js_f64(now as f64),
                js_str(&like_pattern),
                js_f64(limit as f64),
                js_f64(offset as f64),
            ],
        )
    } else {
        let count =
            "SELECT COUNT(*) as count FROM whitelist WHERE (expires_at IS NULL OR expires_at > ?1)"
                .to_string();
        let list = "SELECT w.pubkey, w.cohorts, w.added_at, w.added_by, w.is_admin, \
             (SELECT e.content FROM events e WHERE e.pubkey = w.pubkey AND e.kind = 0 ORDER BY e.created_at DESC LIMIT 1) as profile_content \
             FROM whitelist w WHERE (w.expires_at IS NULL OR w.expires_at > ?1) \
             ORDER BY w.added_at DESC LIMIT ?2 OFFSET ?3".to_string();
        (
            count,
            list,
            vec![
                js_f64(now as f64),
                js_f64(limit as f64),
                js_f64(offset as f64),
            ],
        )
    };

    // Execute count query
    let count_binds: Vec<JsValue> = if cohort.is_some() {
        bind_values[..2].to_vec()
    } else {
        bind_values[..1].to_vec()
    };
    let count_result = db
        .prepare(&count_sql)
        .bind(&count_binds)?
        .first::<CountRow>(None)
        .await?;
    let total = count_result.map(|r| r.count as u64).unwrap_or(0);

    // Execute list query
    let list_result = db.prepare(&list_sql).bind(&bind_values)?.all().await?;

    let rows: Vec<WhitelistRow> = list_result.results()?;
    let users: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|row| {
            let display_name = row.profile_content.as_ref().and_then(|content| {
                serde_json::from_str::<serde_json::Value>(content)
                    .ok()
                    .and_then(|profile| {
                        profile
                            .get("display_name")
                            .or_else(|| profile.get("name"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    })
            });

            let cohorts: Vec<String> = serde_json::from_str(&row.cohorts).unwrap_or_default();

            json!({
                "pubkey": row.pubkey,
                "cohorts": cohorts,
                "addedAt": row.added_at as u64,
                "addedBy": row.added_by,
                "displayName": display_name,
                "isAdmin": row.is_admin.unwrap_or(0) == 1,
            })
        })
        .collect();

    json_response(
        env,
        &json!({ "users": users, "total": total, "limit": limit, "offset": offset }),
        200,
    )
}

/// `POST /api/whitelist/add` (NIP-98 admin only)
///
/// Adds or updates a pubkey in the whitelist. Request body:
/// `{ "pubkey": "<hex>", "cohorts": ["approved"] }`
pub async fn handle_whitelist_add(mut req: Request, env: &Env) -> Result<Response> {
    let url = req.url()?;
    let request_url = format!("{}{}", url.origin().ascii_serialization(), url.path());
    let auth_header = req.headers().get("Authorization").ok().flatten();
    let body_bytes = req.bytes().await?;

    let admin_pubkey = match auth::require_nip98_admin(
        auth_header.as_deref(),
        &request_url,
        "POST",
        Some(&body_bytes),
        env,
    )
    .await
    {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let body: WhitelistAddBody =
        serde_json::from_slice(&body_bytes).map_err(|e| worker::Error::RustError(e.to_string()))?;

    let pubkey = match body.pubkey {
        Some(ref pk) if pk.len() == 64 && pk.bytes().all(|b| b.is_ascii_hexdigit()) => pk.clone(),
        _ => return json_response(env, &json!({ "error": "Invalid or missing pubkey" }), 400),
    };

    let cohorts = body.cohorts.unwrap_or_else(|| vec!["home".to_string()]);
    let cohorts_json =
        serde_json::to_string(&cohorts).map_err(|e| worker::Error::RustError(e.to_string()))?;
    let now = auth::js_now_secs();

    let db = env.d1("DB")?;
    db.prepare(
        "INSERT INTO whitelist (pubkey, cohorts, added_at, added_by) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT (pubkey) DO UPDATE SET cohorts = excluded.cohorts, added_by = excluded.added_by",
    )
    .bind(&[
        js_str(&pubkey),
        js_str(&cohorts_json),
        js_f64(now as f64),
        js_str(&admin_pubkey),
    ])?
    .run()
    .await?;

    // Audit trail
    let _ = audit::log_admin_action(
        env,
        &admin_pubkey,
        "whitelist_add",
        Some(&pubkey),
        None,
        None,
        Some(&cohorts_json),
        None,
    )
    .await;

    json_response(env, &json!({ "success": true }), 200)
}

/// `POST /api/whitelist/set-admin` (NIP-98 admin only)
///
/// Promotes or demotes an admin. Request body:
/// `{ "pubkey": "<hex>", "is_admin": true }`
///
/// Safety: prevents demoting yourself if you're the last admin.
pub async fn handle_set_admin(mut req: Request, env: &Env) -> Result<Response> {
    let url = req.url()?;
    let request_url = format!("{}{}", url.origin().ascii_serialization(), url.path());
    let auth_header = req.headers().get("Authorization").ok().flatten();
    let body_bytes = req.bytes().await?;

    let admin_pubkey = match auth::require_nip98_admin(
        auth_header.as_deref(),
        &request_url,
        "POST",
        Some(&body_bytes),
        env,
    )
    .await
    {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let body: SetAdminBody =
        serde_json::from_slice(&body_bytes).map_err(|e| worker::Error::RustError(e.to_string()))?;

    let target_pubkey = match body.pubkey {
        Some(ref pk) if pk.len() == 64 && pk.bytes().all(|b| b.is_ascii_hexdigit()) => pk.clone(),
        _ => return json_response(env, &json!({ "error": "Invalid or missing pubkey" }), 400),
    };

    let new_admin_status = body.is_admin.unwrap_or(false);
    let db = env.d1("DB")?;

    // Safety: prevent demoting yourself if you're the last admin
    if !new_admin_status && target_pubkey == admin_pubkey {
        let count_stmt = db.prepare("SELECT COUNT(*) as count FROM whitelist WHERE is_admin = 1");
        if let Ok(Some(row)) = count_stmt.first::<CountRow>(None).await {
            if (row.count as u64) <= 1 {
                return json_response(
                    env,
                    &json!({ "error": "Cannot remove the last admin" }),
                    400,
                );
            }
        }
    }

    let admin_val = if new_admin_status { 1i32 } else { 0i32 };
    db.prepare("UPDATE whitelist SET is_admin = ?1 WHERE pubkey = ?2")
        .bind(&[js_f64(admin_val as f64), js_str(&target_pubkey)])?
        .run()
        .await?;

    // Audit trail
    let action = if new_admin_status {
        "admin_grant"
    } else {
        "admin_revoke"
    };
    let _ = audit::log_admin_action(
        env,
        &admin_pubkey,
        action,
        Some(&target_pubkey),
        None,
        Some(if new_admin_status { "0" } else { "1" }),
        Some(if new_admin_status { "1" } else { "0" }),
        None,
    )
    .await;

    json_response(env, &json!({ "success": true }), 200)
}

/// `GET /api/setup-status`
///
/// Public endpoint that returns whether the system needs initial admin setup.
/// Returns `{ "needsSetup": true }` when the whitelist has no admin users.
pub async fn handle_setup_status(_req: &Request, env: &Env) -> Result<Response> {
    let db = env.d1("DB")?;
    let stmt = db.prepare("SELECT COUNT(*) as count FROM whitelist WHERE is_admin = 1");
    let admin_count = match stmt.first::<CountRow>(None).await {
        Ok(Some(row)) => row.count as u64,
        _ => 0,
    };

    json_response(
        env,
        &json!({
            "needsSetup": admin_count == 0,
        }),
        200,
    )
}

/// `POST /api/admin/reset-db` (NIP-98 admin only)
///
/// Clears both the `whitelist` and `events` tables for a fresh start.
/// After reset the first user to register will become admin.
pub async fn handle_reset_db(mut req: Request, env: &Env) -> Result<Response> {
    let url = req.url()?;
    let request_url = format!("{}{}", url.origin().ascii_serialization(), url.path());
    let auth_header = req.headers().get("Authorization").ok().flatten();
    let body_bytes = req.bytes().await?;

    let _admin_pubkey = match auth::require_nip98_admin(
        auth_header.as_deref(),
        &request_url,
        "POST",
        Some(&body_bytes),
        env,
    )
    .await
    {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let db = env.d1("DB")?;
    let _ = db.prepare("DELETE FROM events").run().await;
    let _ = db.prepare("DELETE FROM whitelist").run().await;

    json_response(
        env,
        &json!({ "success": true, "message": "Database reset. First user to register will become admin." }),
        200,
    )
}

/// `POST /api/whitelist/update-cohorts` (NIP-98 admin only)
///
/// Updates the cohorts for an existing pubkey. Request body:
/// `{ "pubkey": "<hex>", "cohorts": ["approved", "premium"] }`
pub async fn handle_whitelist_update_cohorts(mut req: Request, env: &Env) -> Result<Response> {
    let url = req.url()?;
    let request_url = format!("{}{}", url.origin().ascii_serialization(), url.path());
    let auth_header = req.headers().get("Authorization").ok().flatten();
    let body_bytes = req.bytes().await?;

    let admin_pubkey = match auth::require_nip98_admin(
        auth_header.as_deref(),
        &request_url,
        "POST",
        Some(&body_bytes),
        env,
    )
    .await
    {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let body: WhitelistUpdateCohortsBody =
        serde_json::from_slice(&body_bytes).map_err(|e| worker::Error::RustError(e.to_string()))?;

    let pubkey = match &body.pubkey {
        Some(pk) if !pk.is_empty() => pk.clone(),
        _ => return json_response(env, &json!({ "error": "Missing pubkey or cohorts" }), 400),
    };
    let cohorts = match &body.cohorts {
        Some(c) => c.clone(),
        None => return json_response(env, &json!({ "error": "Missing pubkey or cohorts" }), 400),
    };

    let cohorts_json =
        serde_json::to_string(&cohorts).map_err(|e| worker::Error::RustError(e.to_string()))?;
    let now = auth::js_now_secs();

    let db = env.d1("DB")?;
    db.prepare(
        "INSERT INTO whitelist (pubkey, cohorts, added_at, added_by) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT (pubkey) DO UPDATE SET cohorts = excluded.cohorts, added_by = excluded.added_by",
    )
    .bind(&[
        js_str(&pubkey),
        js_str(&cohorts_json),
        js_f64(now as f64),
        js_str(&admin_pubkey),
    ])?
    .run()
    .await?;

    // Audit trail
    let _ = audit::log_admin_action(
        env,
        &admin_pubkey,
        "cohort_update",
        Some(&pubkey),
        None,
        None,
        Some(&cohorts_json),
        None,
    )
    .await;

    json_response(env, &json!({ "success": true }), 200)
}
