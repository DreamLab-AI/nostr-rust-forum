//! Admin audit trail -- append-only log of all admin actions.
//!
//! Provides `log_admin_action()` for recording admin mutations to the D1
//! `admin_log` table, and `handle_audit_log_list()` for querying the log via
//! NIP-98 authenticated admin endpoint.

use serde_json::json;
use wasm_bindgen::JsValue;
use worker::{Env, Request, Response, Result};

use crate::auth;
use crate::cors::json_response;

// ---------------------------------------------------------------------------
// JsValue helpers (local to module)
// ---------------------------------------------------------------------------

fn js_str(s: &str) -> JsValue {
    JsValue::from_str(s)
}

fn js_f64(v: f64) -> JsValue {
    JsValue::from_f64(v)
}

// ---------------------------------------------------------------------------
// Core audit logging
// ---------------------------------------------------------------------------

/// Log an admin action to the `admin_log` D1 table.
///
/// This is an append-only insert; the table has no UPDATE or DELETE operations.
/// Called from every admin-mutating handler in `whitelist.rs`, `moderation.rs`,
/// and the trust/settings endpoints.
pub async fn log_admin_action(
    env: &Env,
    actor_pubkey: &str,
    action: &str,
    target_pubkey: Option<&str>,
    target_id: Option<&str>,
    previous_value: Option<&str>,
    new_value: Option<&str>,
    reason: Option<&str>,
) -> Result<()> {
    let db = env.d1("DB")?;
    let now = auth::js_now_secs();

    db.prepare(
        "INSERT INTO admin_log (actor_pubkey, action, target_pubkey, target_id, previous_value, new_value, reason, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(&[
        js_str(actor_pubkey),
        js_str(action),
        target_pubkey.map(js_str).unwrap_or(JsValue::NULL),
        target_id.map(js_str).unwrap_or(JsValue::NULL),
        previous_value.map(js_str).unwrap_or(JsValue::NULL),
        new_value.map(js_str).unwrap_or(JsValue::NULL),
        reason.map(js_str).unwrap_or(JsValue::NULL),
        js_f64(now as f64),
    ])?
    .run()
    .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// D1 row type
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct AuditLogRow {
    id: f64,
    actor_pubkey: String,
    action: String,
    target_pubkey: Option<String>,
    target_id: Option<String>,
    previous_value: Option<String>,
    new_value: Option<String>,
    reason: Option<String>,
    created_at: f64,
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

/// `GET /api/admin/audit-log?action=&actor=&target=&since=&until=&limit=50`
///
/// Filterable, paginated admin audit log. NIP-98 admin-only.
pub async fn handle_audit_log_list(req: &Request, env: &Env) -> Result<Response> {
    // Authenticate admin via NIP-98
    let url = req.url()?;
    let request_url = format!("{}{}", url.origin().ascii_serialization(), url.path());
    let auth_header = req.headers().get("Authorization").ok().flatten();

    match auth::require_nip98_admin(auth_header.as_deref(), &request_url, "GET", None, env).await {
        Ok(_) => {}
        Err((body, status)) => return json_response(env, &body, status),
    }

    let params: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let limit: u32 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50)
        .min(200);
    let offset: u32 = params
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    // Build dynamic WHERE clauses
    let mut conditions: Vec<String> = Vec::new();
    let mut bind_values: Vec<JsValue> = Vec::new();
    let mut param_idx = 1u32;

    if let Some(action) = params.get("action") {
        if !action.is_empty() {
            conditions.push(format!("action = ?{param_idx}"));
            bind_values.push(js_str(action));
            param_idx += 1;
        }
    }

    if let Some(actor) = params.get("actor") {
        if actor.len() == 64 && actor.bytes().all(|b| b.is_ascii_hexdigit()) {
            conditions.push(format!("actor_pubkey = ?{param_idx}"));
            bind_values.push(js_str(actor));
            param_idx += 1;
        }
    }

    if let Some(target) = params.get("target") {
        if !target.is_empty() {
            conditions.push(format!(
                "(target_pubkey = ?{pi} OR target_id = ?{pi})",
                pi = param_idx
            ));
            bind_values.push(js_str(target));
            param_idx += 1;
        }
    }

    if let Some(since) = params.get("since").and_then(|v| v.parse::<u64>().ok()) {
        conditions.push(format!("created_at >= ?{param_idx}"));
        bind_values.push(js_f64(since as f64));
        param_idx += 1;
    }

    if let Some(until) = params.get("until").and_then(|v| v.parse::<u64>().ok()) {
        conditions.push(format!("created_at <= ?{param_idx}"));
        bind_values.push(js_f64(until as f64));
        param_idx += 1;
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let sql = format!(
        "SELECT id, actor_pubkey, action, target_pubkey, target_id, previous_value, new_value, reason, created_at \
         FROM admin_log {where_clause} ORDER BY created_at DESC LIMIT ?{param_idx} OFFSET ?{}",
        param_idx + 1
    );

    bind_values.push(js_f64(limit as f64));
    bind_values.push(js_f64(offset as f64));

    let db = env.d1("DB")?;
    let result = db.prepare(&sql).bind(&bind_values)?.all().await?;
    let rows: Vec<AuditLogRow> = result.results()?;

    let entries: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|row| {
            json!({
                "id": row.id as u64,
                "actorPubkey": row.actor_pubkey,
                "action": row.action,
                "targetPubkey": row.target_pubkey,
                "targetId": row.target_id,
                "previousValue": row.previous_value,
                "newValue": row.new_value,
                "reason": row.reason,
                "createdAt": row.created_at as u64,
            })
        })
        .collect();

    json_response(env, &json!({ "entries": entries, "limit": limit, "offset": offset }), 200)
}
