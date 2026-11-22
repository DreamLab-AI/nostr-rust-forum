//! NIP-56 moderation queue -- report lifecycle management.
//!
//! Provides HTTP handlers for listing and resolving reports, and a helper for
//! inserting NIP-56 (kind-1984) report events into the `reports` D1 table.
//! Auto-hide logic triggers when 3+ pending reports accumulate for the same
//! event from TL1+ reporters.

use nostr_bbs_core::d1_helpers::{js_f64, js_str};
use serde::Deserialize;
use serde_json::json;
use wasm_bindgen::JsValue;
use worker::{Env, Request, Response, Result};

use crate::audit;
use crate::auth;
use crate::cors::json_response;

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
    let request_url = url.to_string();
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
        let valid = matches!(
            status.as_str(),
            "pending" | "resolved_approve" | "resolved_dismiss"
        );
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
            vec![js_str(status), js_f64(limit as f64), js_f64(offset as f64)],
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
    let request_url = url.to_string();
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

    // What a "delete" actually removed, for the reply and the audit row.
    let mut deletion: Option<DeletionRecord> = None;

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
            // The target id is the reporter's first `e` tag and
            // `reported_pubkey` only their claim, so read what the row really
            // is before it goes; the admin sees what was removed. A failed read
            // is reported as nothing found and does not stop the deletion.
            let stored = match db
                .prepare("SELECT pubkey, kind FROM events WHERE id = ?1 LIMIT 1")
                .bind(&[js_str(&report.reported_event_id)])
            {
                Ok(stmt) => stmt.first::<StoredEventRow>(None).await.ok().flatten(),
                Err(_) => None,
            };
            // A moderator's decision that the content goes: tombstone it under
            // that real author, so it cannot be published again. Fails open.
            let tombstoned = crate::tombstone_before_delete(
                &db,
                crate::TombstoneTarget::Event(&report.reported_event_id),
                now,
            )
            .await;
            let run = db
                .prepare("DELETE FROM events WHERE id = ?1")
                .bind(&[js_str(&report.reported_event_id)])?
                .run()
                .await;
            // Claim a removal only when the DELETE ran.
            deletion = Some(DeletionRecord {
                event_id: report.reported_event_id.clone(),
                stored: stored.map(|r| (r.pubkey, r.kind as u64)),
                tombstoned,
                delete_error: run.err().map(|e| e.to_string()),
            });
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

    // A deletion names the real author where the row was found, and records
    // the reporter's claim beside it in the details.
    let details = deletion.as_ref().map(|d| {
        d.audit_details(new_status, &report.reported_pubkey)
            .to_string()
    });
    let audit_target = deletion
        .as_ref()
        .and_then(|d| d.stored.as_ref().map(|(author, _)| author.as_str()))
        .unwrap_or(&report.reported_pubkey);

    let _ = audit::log_admin_action(
        env,
        &admin_pubkey,
        action,
        Some(audit_target),
        Some(&format!("{}", report_id as u64)),
        Some("pending"),
        Some(details.as_deref().unwrap_or(new_status)),
        if reason.is_empty() {
            None
        } else {
            Some(&reason)
        },
    )
    .await;

    let mut body = json!({ "success": true, "resolution": resolution });
    if let (Some(d), Some(fields)) = (&deletion, body.as_object_mut()) {
        fields.extend(d.outcome_fields());
    }
    json_response(env, &body, 200)
}

#[derive(Deserialize)]
struct StoredEventRow {
    pubkey: String,
    kind: f64,
}

/// What a report resolved as "delete" did.
#[derive(Debug, Clone, PartialEq)]
struct DeletionRecord {
    /// The id the report named.
    event_id: String,
    /// The stored row's real `(author, kind)`, or `None` when no row was found.
    stored: Option<(String, u64)>,
    /// Whether every tombstone statement ran.
    tombstoned: bool,
    /// The DELETE's error, when it failed.
    delete_error: Option<String>,
}

impl DeletionRecord {
    /// `removed`: the row actually deleted, or `null` when no row was found or
    /// the DELETE failed.
    fn removed_json(&self) -> serde_json::Value {
        match (&self.stored, &self.delete_error) {
            (Some((author, kind)), None) => {
                json!({ "id": self.event_id, "author": author, "kind": kind })
            }
            _ => serde_json::Value::Null,
        }
    }

    /// The fields a deletion adds to the reply: `removed`, `tombstoned`, and
    /// `deleteError` when the DELETE failed.
    fn outcome_fields(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut fields = serde_json::Map::new();
        fields.insert("removed".into(), self.removed_json());
        fields.insert("tombstoned".into(), json!(self.tombstoned));
        if let Some(e) = &self.delete_error {
            fields.insert("deleteError".into(), json!(e));
        }
        fields
    }

    /// The `admin_log.new_value` details for a deletion: the reply's fields
    /// plus the resolution status and the reporter's claimed author.
    fn audit_details(&self, status: &str, reported_pubkey: &str) -> serde_json::Value {
        let mut fields = self.outcome_fields();
        fields.insert("status".into(), json!(status));
        fields.insert("reportedPubkey".into(), json!(reported_pubkey));
        serde_json::Value::Object(fields)
    }
}

#[cfg(test)]
mod deletion_record_tests {
    use super::*;

    #[test]
    fn a_found_row_reports_its_real_author_and_kind() {
        let d = DeletionRecord {
            event_id: "e1".into(),
            stored: Some(("real".into(), 30023)),
            tombstoned: true,
            delete_error: None,
        };
        assert_eq!(
            d.removed_json(),
            json!({ "id": "e1", "author": "real", "kind": 30023 })
        );
        assert_eq!(
            d.audit_details("resolved_approve", "claimed"),
            json!({
                "status": "resolved_approve",
                "removed": { "id": "e1", "author": "real", "kind": 30023 },
                "reportedPubkey": "claimed",
                "tombstoned": true,
            })
        );
    }

    #[test]
    fn a_missing_row_reports_nothing_removed() {
        let d = DeletionRecord {
            event_id: "e1".into(),
            stored: None,
            tombstoned: false,
            delete_error: None,
        };
        assert!(d.removed_json().is_null());
        assert_eq!(
            d.audit_details("resolved_approve", "claimed")["removed"],
            serde_json::Value::Null
        );
        assert!(!d.outcome_fields().contains_key("deleteError"));
    }

    #[test]
    fn a_failed_delete_claims_no_removal_and_says_why() {
        let d = DeletionRecord {
            event_id: "e1".into(),
            stored: Some(("real".into(), 1)),
            tombstoned: true,
            delete_error: Some("D1_ERROR: busy".into()),
        };
        assert!(d.removed_json().is_null());
        assert_eq!(
            serde_json::Value::Object(d.outcome_fields()),
            json!({ "removed": null, "tombstoned": true, "deleteError": "D1_ERROR: busy" })
        );
        let audit = d.audit_details("resolved_approve", "claimed");
        assert_eq!(audit["removed"], serde_json::Value::Null);
        assert_eq!(audit["deleteError"], "D1_ERROR: busy");
    }
}
