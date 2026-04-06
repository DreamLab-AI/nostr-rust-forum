//! NIP-56 moderation queue -- report lifecycle management.
//!
//! Provides HTTP handlers for listing and resolving reports, and a helper for
//! inserting NIP-56 (kind-1984) report events into the `reports` D1 table.
//! Auto-hide logic triggers when 3+ pending reports accumulate for the same
//! event from TL1+ reporters.

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
struct ReportRow {
    id: f64,
    report_event_id: String,
    reporter_pubkey: String,
    reported_event_id: String,
    reported_pubkey: String,
    reason: String,
    reason_text: Option<String>,
    status: String,
    resolved_by: Option<String>,
    resolution: Option<String>,
    resolved_at: Option<f64>,
    created_at: f64,
}

#[derive(Deserialize)]
struct CountRow {
    count: f64,
}

// ---------------------------------------------------------------------------
// Request body types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ResolveReportBody {
    report_id: Option<f64>,
    resolution: Option<String>,
    reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Report insertion (called from nip_handlers.rs for kind-1984)
// ---------------------------------------------------------------------------

/// Insert a NIP-56 report into the `reports` table.
///
/// Returns `true` if auto-hide threshold was reached (3+ pending reports
/// for the same reported event from TL1+ users).
pub async fn insert_report(
    env: &Env,
    report_event_id: &str,
    reporter_pubkey: &str,
    reported_event_id: &str,
    reported_pubkey: &str,
    reason: &str,
    reason_text: Option<&str>,
) -> Result<bool> {
    let db = env.d1("DB")?;
    let now = auth::js_now_secs();

    db.prepare(
        "INSERT INTO reports (report_event_id, reporter_pubkey, reported_event_id, reported_pubkey, reason, reason_text, status, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7) \
         ON CONFLICT (report_event_id) DO NOTHING",
    )
    .bind(&[
        js_str(report_event_id),
        js_str(reporter_pubkey),
        js_str(reported_event_id),
        js_str(reported_pubkey),
        js_str(reason),
        reason_text.map(js_str).unwrap_or(JsValue::NULL),
        js_f64(now as f64),
    ])?
    .run()
    .await?;

    // Check auto-hide threshold: 3+ pending reports for the same event
    let count_result = db
        .prepare(
            "SELECT COUNT(*) as count FROM reports WHERE reported_event_id = ?1 AND status = 'pending'",
        )
        .bind(&[js_str(reported_event_id)])?
        .first::<CountRow>(None)
        .await?;

    let pending_count = count_result.map(|r| r.count as u64).unwrap_or(0);

    if pending_count >= 3 {
        // Auto-hide: mark the reported event as hidden by inserting into hidden_events
        // or by deleting it. We use a soft-hide approach: store in hidden_events table
        // and log the auto-action.
        let _ = db
            .prepare(
                "INSERT INTO hidden_events (event_id, hidden_by, reason, created_at) \
                 VALUES (?1, 'auto-moderation', 'auto-hide: 3+ reports', ?2) \
                 ON CONFLICT (event_id) DO NOTHING",
            )
            .bind(&[js_str(reported_event_id), js_f64(now as f64)])?
            .run()
            .await;

        // Log the auto-hide action
        let _ = audit::log_admin_action(
            env,
            "system",
            "event_auto_hide",
            Some(reported_pubkey),
            Some(reported_event_id),
            None,
            Some("hidden"),
            Some("auto-hide: 3+ pending reports from TL1+ users"),
        )
        .await;

        return Ok(true);
    }

    Ok(false)
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

/// `GET /api/reports?status=pending|resolved|dismissed&limit=50&offset=0`
///
/// Paginated report queue. NIP-98 admin-only.
pub async fn handle_list_reports(req: &Request, env: &Env) -> Result<Response> {
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
    let status_filter = params.get("status").cloned();

    let db = env.d1("DB")?;

    let (sql, bind_values) = if let Some(ref status) = status_filter {
        // Validate status value
        let valid = matches!(status.as_str(), "pending" | "resolved_approve" | "resolved_dismiss");
        if !valid {
            return json_response(
                env,
                &json!({ "error": "Invalid status. Use: pending, resolved_approve, resolved_dismiss" }),
                400,
            );
        }
        (
            "SELECT id, report_event_id, reporter_pubkey, reported_event_id, reported_pubkey, \
             reason, reason_text, status, resolved_by, resolution, resolved_at, created_at \
             FROM reports WHERE status = ?1 ORDER BY created_at DESC LIMIT ?2 OFFSET ?3"
                .to_string(),
            vec![
                js_str(status),
                js_f64(limit as f64),
                js_f64(offset as f64),
            ],
        )
    } else {
        (
            "SELECT id, report_event_id, reporter_pubkey, reported_event_id, reported_pubkey, \
             reason, reason_text, status, resolved_by, resolution, resolved_at, created_at \
             FROM reports ORDER BY created_at DESC LIMIT ?1 OFFSET ?2"
                .to_string(),
            vec![js_f64(limit as f64), js_f64(offset as f64)],
        )
    };

    let result = db.prepare(&sql).bind(&bind_values)?.all().await?;
    let rows: Vec<ReportRow> = result.results()?;

    let reports: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|row| {
            json!({
                "id": row.id as u64,
                "reportEventId": row.report_event_id,
                "reporterPubkey": row.reporter_pubkey,
                "reportedEventId": row.reported_event_id,
                "reportedPubkey": row.reported_pubkey,
                "reason": row.reason,
                "reasonText": row.reason_text,
                "status": row.status,
                "resolvedBy": row.resolved_by,
                "resolution": row.resolution,
                "resolvedAt": row.resolved_at.map(|t| t as u64),
                "createdAt": row.created_at as u64,
            })
        })
        .collect();

    json_response(
        env,
        &json!({ "reports": reports, "limit": limit, "offset": offset }),
        200,
    )
}

/// `POST /api/reports/resolve`
///
/// Resolve a report. Body: `{ "report_id": 123, "resolution": "dismiss"|"hide"|"delete", "reason": "..." }`
/// NIP-98 admin-only.
pub async fn handle_resolve_report(mut req: Request, env: &Env) -> Result<Response> {
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

    let body: ResolveReportBody =
        serde_json::from_slice(&body_bytes).map_err(|e| worker::Error::RustError(e.to_string()))?;

    let report_id = match body.report_id {
        Some(id) => id,
        None => return json_response(env, &json!({ "error": "Missing report_id" }), 400),
    };

    let resolution = match body.resolution.as_deref() {
        Some(r @ ("dismiss" | "hide" | "delete")) => r.to_string(),
        _ => {
            return json_response(
                env,
                &json!({ "error": "Invalid resolution. Use: dismiss, hide, delete" }),
                400,
            )
        }
    };

    let reason = body.reason.unwrap_or_default();
    let db = env.d1("DB")?;
    let now = auth::js_now_secs();

    // Fetch the report to get target info
    let report = db
        .prepare("SELECT id, report_event_id, reporter_pubkey, reported_event_id, reported_pubkey, reason, reason_text, status, resolved_by, resolution, resolved_at, created_at FROM reports WHERE id = ?1")
        .bind(&[js_f64(report_id)])?
        .first::<ReportRow>(None)
        .await?;

    let report = match report {
        Some(r) => r,
        None => return json_response(env, &json!({ "error": "Report not found" }), 404),
    };

    if report.status != "pending" {
        return json_response(env, &json!({ "error": "Report already resolved" }), 400);
    }

    // Determine the new status based on resolution
    let new_status = match resolution.as_str() {
        "dismiss" => "resolved_dismiss",
        "hide" | "delete" => "resolved_approve",
        _ => unreachable!(),
    };

    // Update the report
    db.prepare(
        "UPDATE reports SET status = ?1, resolved_by = ?2, resolution = ?3, resolved_at = ?4 WHERE id = ?5",
    )
    .bind(&[
        js_str(new_status),
        js_str(&admin_pubkey),
        js_str(&resolution),
        js_f64(now as f64),
        js_f64(report_id),
    ])?
    .run()
    .await?;

    // Apply the resolution action on the reported event
    match resolution.as_str() {
        "hide" => {
            // Soft-hide the reported event
            let _ = db
                .prepare(
                    "INSERT INTO hidden_events (event_id, hidden_by, reason, created_at) \
                     VALUES (?1, ?2, ?3, ?4) \
                     ON CONFLICT (event_id) DO NOTHING",
                )
                .bind(&[
                    js_str(&report.reported_event_id),
                    js_str(&admin_pubkey),
                    js_str(&reason),
                    js_f64(now as f64),
                ])?
                .run()
                .await;
        }
        "delete" => {
            // Hard-delete the reported event from the events table (NIP-09 style)
            let _ = db
                .prepare("DELETE FROM events WHERE id = ?1")
                .bind(&[js_str(&report.reported_event_id)])?
                .run()
                .await;
        }
        _ => {
            // "dismiss" -- no action on the content
        }
    }

    // Log to admin audit trail
    let action = match resolution.as_str() {
        "dismiss" => "report_dismiss",
        _ => "report_resolve",
    };

    let _ = audit::log_admin_action(
        env,
        &admin_pubkey,
        action,
        Some(&report.reported_pubkey),
        Some(&format!("{}", report_id as u64)),
        Some("pending"),
        Some(new_status),
        if reason.is_empty() {
            None
        } else {
            Some(&reason)
        },
    )
    .await;

    json_response(env, &json!({ "success": true, "resolution": resolution }), 200)
}
