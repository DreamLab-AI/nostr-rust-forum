//! WI-2 Moderation API handlers.
//!
//! All endpoints are NIP-98 authenticated. Admin-only endpoints additionally
//! require `members.is_admin = 1` (or the legacy `whitelist.is_admin = 1`).
//!
//! Endpoints:
//!
//! | Method | Path                          | Auth        | Purpose                              |
//! |--------|-------------------------------|-------------|--------------------------------------|
//! | POST   | /api/mod/ban                  | admin       | Ban a pubkey (optional reason)       |
//! | POST   | /api/mod/mute                 | admin       | Mute a pubkey (optional expires_at)  |
//! | POST   | /api/mod/warn                 | admin       | Send a formal warning                |
//! | POST   | /api/mod/report               | authed      | File a report against an event       |
//! | GET    | /api/mod/actions              | admin       | List moderation actions (filterable) |
//! | GET    | /api/mod/reports              | admin       | List reports (status filter)         |
//! | POST   | /api/mod/reports/:id/action   | admin       | Mark a report actioned/dismissed     |
//!
//! The admin CLI builds and signs Nostr moderation events (kinds 30910-30914)
//! client-side and supplies them alongside structured payload fields. The
//! worker validates the event shape + signer and inserts a row into
//! `moderation_actions` / `mod_reports`. This keeps the signing key on the
//! admin's machine and uses D1 purely as a queryable mirror.

use nostr_bbs_core::d1_helpers::{js_i64, js_opt_i64, js_opt_str, js_str};
use nostr_bbs_core::{
    validate_moderation_event, NostrEvent, KIND_BAN, KIND_MUTE, KIND_REPORT, KIND_REPORT_NIP56,
    KIND_UNBAN, KIND_UNMUTE, KIND_WARNING, MOD_KINDS,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashSet;
use wasm_bindgen::JsValue;
use worker::{Env, Response, Result};

use crate::admin::{canonical_url, now_secs, require_admin, require_authed};
use crate::http::{error_json, json_response};

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

/// Body for `POST /api/mod/{ban|mute|warn}`.
///
/// The admin CLI pre-signs the Nostr moderation event and sends it along with
/// the structured action fields. We validate both, then persist.
#[derive(Deserialize)]
struct ActionBody {
    /// The signed Nostr moderation event (kind 30910/30911/30912).
    event: NostrEvent,
    /// Optional human-readable reason (duplicated from event.content for
    /// queryability; D1 stores this in `moderation_actions.reason`).
    reason: Option<String>,
    /// Optional expiry for mutes, unix-seconds. Ignored for bans and warnings.
    expires_at: Option<u64>,
    /// Internal row id (nanoid/ulid), duplicated into `moderation_actions.id`.
    /// If omitted, the worker derives one from `event.id`.
    id: Option<String>,
}

/// Body for `POST /api/mod/report` -- filed by any authed member.
#[derive(Deserialize)]
struct ReportBody {
    /// The signed kind-30913 report event.
    event: NostrEvent,
    /// Event id being reported.
    target_event_id: String,
    /// Pubkey that authored the reported event.
    target_pubkey: String,
    /// Short machine-readable reason tag (`spam`, `abuse`, etc.).
    reason: String,
    /// Optional row id; derived from event.id if missing.
    id: Option<String>,
}

/// Body for `POST /api/mod/reports/:id/action`.
#[derive(Deserialize)]
struct ReportActionBody {
    /// Either `"actioned"` or `"dismissed"`.
    status: String,
    /// Optional follow-up note stored alongside.
    note: Option<String>,
}

// ---------------------------------------------------------------------------
// D1 row types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ActionRow {
    id: String,
    action: String,
    target_pubkey: String,
    performed_by: String,
    reason: Option<String>,
    expires_at: Option<i64>,
    event_id: String,
    created_at: i64,
}

#[derive(Deserialize)]
struct ReportRow {
    id: String,
    reporter_pubkey: String,
    target_event_id: String,
    target_pubkey: String,
    reason: String,
    status: String,
    event_id: String,
    created_at: i64,
    actioned_by: Option<String>,
    actioned_at: Option<i64>,
}

#[derive(Deserialize)]
struct StatusOnly {
    status: String,
}

/// Load the admin set from D1. Used to validate that the Nostr event was
/// signed by an admin. Combines `members` and `whitelist` for compatibility.
async fn admin_set(env: &Env) -> HashSet<String> {
    use nostr_bbs_core::admin_shared::PubkeyRow;

    let mut set = HashSet::new();
    let Ok(db) = env.d1("DB") else {
        return set;
    };

    let members = db
        .prepare(nostr_bbs_core::MEMBERS_ADMIN_LIST_SQL)
        .all()
        .await;
    if let Ok(result) = members {
        if let Ok(rows) = result.results::<PubkeyRow>() {
            for r in rows {
                set.insert(r.pubkey);
            }
        }
    }

    let whitelist = db
        .prepare(nostr_bbs_core::WHITELIST_ADMIN_LIST_SQL)
        .all()
        .await;
    if let Ok(result) = whitelist {
        if let Ok(rows) = result.results::<PubkeyRow>() {
            for r in rows {
                set.insert(r.pubkey);
            }
        }
    }

    set
}

// ---------------------------------------------------------------------------
// POST /api/mod/{ban|mute|warn}
// ---------------------------------------------------------------------------

/// Map a moderation action path to its `(action_name, expected_kind)` pair.
///
/// P0-4: `unban`/`unmute` are the HTTP-side counterparts to the relay's
/// unban/unmute mirror. They flow through the identical admin/NIP-98 auth
/// and validate-then-persist path as `ban`/`mute`; the signed KIND_UNBAN
/// (30915) / KIND_UNMUTE (30916) events are built client-side via
/// `build_unban` / `build_unmute`.
fn action_for_path(path: &str) -> Option<(&'static str, u64)> {
    match path {
        "/api/mod/ban" => Some(("ban", KIND_BAN)),
        "/api/mod/mute" => Some(("mute", KIND_MUTE)),
        "/api/mod/warn" => Some(("warn", KIND_WARNING)),
        "/api/mod/unban" => Some(("unban", KIND_UNBAN)),
        "/api/mod/unmute" => Some(("unmute", KIND_UNMUTE)),
        _ => None,
    }
}

/// Handle an admin moderation action (ban / mute / warn / unban / unmute).
///
/// `expected_kind` constrains the event kind so clients can't mix actions.
pub async fn handle_action(
    path: &str,
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let (action_name, expected_kind) = match action_for_path(path) {
        Some(pair) => pair,
        None => return error_json(env, "Unknown moderation action path", 404),
    };

    let url = canonical_url(origin, path);
    let admin_pubkey = match require_admin(auth_header, &url, "POST", Some(body_bytes), env).await {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let body: ActionBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("Invalid JSON body: {e}"), 400),
    };

    // Event must be the requested kind.
    if body.event.kind != expected_kind {
        return error_json(
            env,
            &format!(
                "Event kind {} does not match action {} (expected {})",
                body.event.kind, action_name, expected_kind
            ),
            400,
        );
    }

    // Verify signer is an admin AND the Nostr event itself is well-formed.
    let admins = admin_set(env).await;
    if let Err(e) = validate_moderation_event(&body.event, &admins) {
        return error_json(env, &format!("Invalid moderation event: {e}"), 400);
    }

    // Extract the target pubkey (ban/mute) or pubkey:ts tuple (warn).
    let target_pubkey = first_tag(&body.event, "p")
        .ok_or_else(|| worker::Error::RustError("missing p tag".into()))
        .unwrap_or_default()
        .to_string();
    if target_pubkey.is_empty() {
        return error_json(env, "Event missing `p` tag (target pubkey)", 400);
    }

    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return error_json(env, "Database unavailable", 500),
    };

    let row_id = body.id.clone().unwrap_or_else(|| body.event.id.clone());
    let now = now_secs();
    let reason = body.reason.clone();
    let expires_at = if expected_kind == KIND_MUTE {
        body.expires_at.map(|v| v as i64)
    } else {
        None
    };

    let insert = db
        .prepare(
            "INSERT INTO moderation_actions \
             (id, action, target_pubkey, performed_by, reason, expires_at, event_id, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(&[
            js_str(&row_id),
            js_str(action_name),
            js_str(&target_pubkey),
            js_str(&admin_pubkey),
            js_opt_str(reason.as_deref()),
            js_opt_i64(expires_at),
            js_str(&body.event.id),
            js_i64(now as i64),
        ])?
        .run()
        .await;

    if let Err(e) = insert {
        return error_json(env, &format!("Insert failed: {e}"), 500);
    }

    json_response(
        env,
        &json!({
            "ok": true,
            "id": row_id,
            "action": action_name,
            "target_pubkey": target_pubkey,
            "expires_at": expires_at,
            "event_id": body.event.id,
        }),
        200,
    )
}

// ---------------------------------------------------------------------------
// POST /api/mod/report
// ---------------------------------------------------------------------------

/// File a report. Any authenticated member may call this.
pub async fn handle_report(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/mod/report");
    let reporter = match require_authed(auth_header, &url, "POST", Some(body_bytes), env).await {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let body: ReportBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("Invalid JSON body: {e}"), 400),
    };

    if body.event.kind != KIND_REPORT {
        return error_json(env, "Report event must be kind 30913", 400);
    }

    // Reports don't require admin signer -- validate using an empty admin set.
    if let Err(e) = validate_moderation_event(&body.event, &HashSet::new()) {
        return error_json(env, &format!("Invalid report event: {e}"), 400);
    }

    // The NIP-98 signer must match the event signer (no impersonation).
    if body.event.pubkey != reporter {
        return error_json(
            env,
            "Reporter pubkey in event does not match NIP-98 signer",
            403,
        );
    }

    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return error_json(env, "Database unavailable", 500),
    };

    let row_id = body.id.clone().unwrap_or_else(|| body.event.id.clone());
    let now = now_secs();

    let insert = db
        .prepare(
            "INSERT INTO mod_reports \
             (id, reporter_pubkey, target_event_id, target_pubkey, reason, status, event_id, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'open', ?6, ?7) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&[
            js_str(&row_id),
            js_str(&reporter),
            js_str(&body.target_event_id),
            js_str(&body.target_pubkey),
            js_str(&body.reason),
            js_str(&body.event.id),
            js_i64(now as i64),
        ])?
        .run()
        .await;

    if let Err(e) = insert {
        return error_json(env, &format!("Insert failed: {e}"), 500);
    }

    json_response(
        env,
        &json!({
            "ok": true,
            "id": row_id,
            "reporter": reporter,
            "target_event_id": body.target_event_id,
            "status": "open",
        }),
        200,
    )
}

// ---------------------------------------------------------------------------
// GET /api/mod/actions?target=<pubkey>&action=<ban|mute|warn>
// ---------------------------------------------------------------------------

pub async fn handle_list_actions(
    query: &[(String, String)],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/mod/actions");
    if let Err((body, status)) = require_admin(auth_header, &url, "GET", None, env).await {
        return json_response(env, &body, status);
    }

    let target: Option<&str> = query
        .iter()
        .find(|(k, _)| k == "target")
        .map(|(_, v)| v.as_str());
    let action: Option<&str> = query
        .iter()
        .find(|(k, _)| k == "action")
        .map(|(_, v)| v.as_str());

    if let Some(a) = action {
        if !matches!(a, "ban" | "mute" | "warn" | "unban" | "unmute") {
            return error_json(env, "Invalid action filter", 400);
        }
    }

    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return error_json(env, "Database unavailable", 500),
    };

    // Hand-rolled query builder -- only 4 valid shapes, easy to audit.
    let (sql, binds): (&str, Vec<JsValue>) = match (target, action) {
        (Some(t), Some(a)) => (
            "SELECT id, action, target_pubkey, performed_by, reason, expires_at, event_id, created_at \
             FROM moderation_actions \
             WHERE target_pubkey = ?1 AND action = ?2 \
             ORDER BY created_at DESC LIMIT 200",
            vec![js_str(t), js_str(a)],
        ),
        (Some(t), None) => (
            "SELECT id, action, target_pubkey, performed_by, reason, expires_at, event_id, created_at \
             FROM moderation_actions \
             WHERE target_pubkey = ?1 \
             ORDER BY created_at DESC LIMIT 200",
            vec![js_str(t)],
        ),
        (None, Some(a)) => (
            "SELECT id, action, target_pubkey, performed_by, reason, expires_at, event_id, created_at \
             FROM moderation_actions \
             WHERE action = ?1 \
             ORDER BY created_at DESC LIMIT 200",
            vec![js_str(a)],
        ),
        (None, None) => (
            "SELECT id, action, target_pubkey, performed_by, reason, expires_at, event_id, created_at \
             FROM moderation_actions \
             ORDER BY created_at DESC LIMIT 200",
            vec![],
        ),
    };

    let result = match db.prepare(sql).bind(&binds)?.all().await {
        Ok(r) => r,
        Err(e) => return error_json(env, &format!("Query failed: {e}"), 500),
    };
    let rows: Vec<ActionRow> = result.results().unwrap_or_default();

    let actions: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id,
                "action": r.action,
                "target_pubkey": r.target_pubkey,
                "performed_by": r.performed_by,
                "reason": r.reason,
                "expires_at": r.expires_at,
                "event_id": r.event_id,
                "created_at": r.created_at,
            })
        })
        .collect();

    json_response(env, &json!({ "actions": actions }), 200)
}

// ---------------------------------------------------------------------------
// GET /api/mod/reports?status=<open|actioned|dismissed>
// ---------------------------------------------------------------------------

pub async fn handle_list_reports(
    query: &[(String, String)],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/mod/reports");
    if let Err((body, status)) = require_admin(auth_header, &url, "GET", None, env).await {
        return json_response(env, &body, status);
    }

    let status_filter: Option<&str> = query
        .iter()
        .find(|(k, _)| k == "status")
        .map(|(_, v)| v.as_str());

    if let Some(s) = status_filter {
        if !matches!(s, "open" | "actioned" | "dismissed") {
            return error_json(env, "Invalid status filter", 400);
        }
    }

    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return error_json(env, "Database unavailable", 500),
    };

    let (sql, binds): (&str, Vec<JsValue>) = match status_filter {
        Some(s) => (
            "SELECT id, reporter_pubkey, target_event_id, target_pubkey, reason, status, event_id, created_at, actioned_by, actioned_at \
             FROM mod_reports WHERE status = ?1 ORDER BY created_at DESC LIMIT 200",
            vec![js_str(s)],
        ),
        None => (
            "SELECT id, reporter_pubkey, target_event_id, target_pubkey, reason, status, event_id, created_at, actioned_by, actioned_at \
             FROM mod_reports ORDER BY created_at DESC LIMIT 200",
            vec![],
        ),
    };

    let result = match db.prepare(sql).bind(&binds)?.all().await {
        Ok(r) => r,
        Err(e) => return error_json(env, &format!("Query failed: {e}"), 500),
    };
    let rows: Vec<ReportRow> = result.results().unwrap_or_default();

    let reports: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id,
                "reporter_pubkey": r.reporter_pubkey,
                "target_event_id": r.target_event_id,
                "target_pubkey": r.target_pubkey,
                "reason": r.reason,
                "status": r.status,
                "event_id": r.event_id,
                "created_at": r.created_at,
                "actioned_by": r.actioned_by,
                "actioned_at": r.actioned_at,
            })
        })
        .collect();

    json_response(env, &json!({ "reports": reports }), 200)
}

// ---------------------------------------------------------------------------
// POST /api/mod/reports/:id/action
// ---------------------------------------------------------------------------

pub async fn handle_report_action(
    report_id: &str,
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let path = format!("/api/mod/reports/{report_id}/action");
    let url = canonical_url(origin, &path);
    let admin = match require_admin(auth_header, &url, "POST", Some(body_bytes), env).await {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let body: ReportActionBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("Invalid JSON body: {e}"), 400),
    };

    if !matches!(body.status.as_str(), "actioned" | "dismissed") {
        return error_json(env, "status must be `actioned` or `dismissed`", 400);
    }

    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return error_json(env, "Database unavailable", 500),
    };

    // Fetch existing row first so we can 404 cleanly.
    let existing = db
        .prepare("SELECT status FROM mod_reports WHERE id = ?1")
        .bind(&[js_str(report_id)])?
        .first::<StatusOnly>(None)
        .await;
    match existing {
        Ok(Some(row)) if row.status != "open" => {
            return error_json(env, "Report is not open", 409);
        }
        Ok(Some(_)) => {}
        Ok(None) => return error_json(env, "Report not found", 404),
        Err(e) => return error_json(env, &format!("Query failed: {e}"), 500),
    }

    let now = now_secs();
    let _ = body.note; // Note currently captured by the moderation event, not persisted here.
    let update = db
        .prepare(
            "UPDATE mod_reports SET status = ?1, actioned_by = ?2, actioned_at = ?3 WHERE id = ?4",
        )
        .bind(&[
            js_str(&body.status),
            js_str(&admin),
            js_i64(now as i64),
            js_str(report_id),
        ])?
        .run()
        .await;

    if let Err(e) = update {
        return error_json(env, &format!("Update failed: {e}"), 500);
    }

    json_response(
        env,
        &json!({ "ok": true, "id": report_id, "status": body.status }),
        200,
    )
}

// ---------------------------------------------------------------------------
// GET /api/moderation/reports — NIP-1984 (kind-1984) standard report queue
// ---------------------------------------------------------------------------

/// D1 row for a stored kind-1984 event.
#[derive(Deserialize)]
struct Nip1984Row {
    event_id: String,
    pubkey: String,
    created_at: i64,
    content: String,
    tags_json: String,
}

/// Return the most recent 50 kind-1984 report events stored in D1.
///
/// These are standard NIP-56 report events submitted by any user via the
/// relay (kind 1984). The relay stores them as `Regular` events. This
/// endpoint surfaces them to admins for review.
///
/// The query reads from a `nip1984_reports` table populated by the relay-worker
/// when it receives kind-1984 events. This table is created by `ensure_schema`.
pub async fn handle_nip1984_reports(
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/moderation/reports");
    if let Err((body, status)) = require_admin(auth_header, &url, "GET", None, env).await {
        return json_response(env, &body, status);
    }

    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return error_json(env, "Database unavailable", 500),
    };

    let result = match db
        .prepare(
            "SELECT event_id, pubkey, created_at, content, tags_json \
             FROM nip1984_reports \
             ORDER BY created_at DESC \
             LIMIT 50",
        )
        .all()
        .await
    {
        Ok(r) => r,
        Err(e) => return error_json(env, &format!("Query failed: {e}"), 500),
    };

    let rows: Vec<Nip1984Row> = result.results().unwrap_or_default();

    let reports: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            // Parse tags_json back to a Value; fall back to empty array on error.
            let tags: serde_json::Value =
                serde_json::from_str(&r.tags_json).unwrap_or(serde_json::Value::Array(vec![]));
            json!({
                "kind": KIND_REPORT_NIP56,
                "id": r.event_id,
                "pubkey": r.pubkey,
                "created_at": r.created_at,
                "content": r.content,
                "tags": tags,
            })
        })
        .collect();

    json_response(
        env,
        &json!({ "reports": reports, "kind": KIND_REPORT_NIP56 }),
        200,
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the first single-letter tag value matching `name`, if present.
fn first_tag<'a>(event: &'a NostrEvent, name: &str) -> Option<&'a str> {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

// Reference the unused constant so clippy doesn't warn when route extensions
// (e.g. unban/unmute) land in a follow-up. The parent module keeps the star.
#[allow(dead_code)]
const _REF_MOD_KINDS: &[u64] = MOD_KINDS;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::SigningKey;
    use nostr_bbs_core::event::{sign_event_deterministic, UnsignedEvent};
    use nostr_bbs_core::{build_ban, build_mute, build_report, build_unban, build_unmute};

    fn admin_sk() -> SigningKey {
        SigningKey::from_bytes(&[0x02u8; 32]).unwrap()
    }
    fn admin_pk() -> String {
        hex::encode(admin_sk().verifying_key().to_bytes())
    }
    fn target_pk() -> String {
        "ff".repeat(32)
    }

    fn signed(u: UnsignedEvent) -> NostrEvent {
        sign_event_deterministic(u, &admin_sk()).unwrap()
    }

    #[test]
    fn action_body_parses_with_signed_ban() {
        let ev = signed(build_ban(&admin_pk(), &target_pk(), "spam", 1_700_000_000));
        let payload = json!({
            "event": ev,
            "reason": "spam",
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let body: ActionBody = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body.event.kind, KIND_BAN);
        assert_eq!(body.reason.as_deref(), Some("spam"));
    }

    #[test]
    fn action_body_rejects_missing_event() {
        let payload = json!({ "reason": "spam" });
        let bytes = serde_json::to_vec(&payload).unwrap();
        assert!(serde_json::from_slice::<ActionBody>(&bytes).is_err());
    }

    #[test]
    fn report_body_roundtrips() {
        let ev = signed(build_report(
            &admin_pk(),
            &"aa".repeat(32),
            &target_pk(),
            "spam",
            1_700_000_000,
        ));
        let payload = json!({
            "event": ev,
            "target_event_id": "aa".repeat(32),
            "target_pubkey": target_pk(),
            "reason": "spam",
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let body: ReportBody = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body.reason, "spam");
    }

    #[test]
    fn report_action_body_validates_status() {
        for s in ["actioned", "dismissed"] {
            let bytes = serde_json::to_vec(&json!({ "status": s })).unwrap();
            let parsed: ReportActionBody = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(parsed.status, s);
        }
    }

    #[test]
    fn mute_body_captures_expires_at() {
        let ev = signed(build_mute(
            &admin_pk(),
            &target_pk(),
            1_700_003_600,
            "cool down",
            1_700_000_000,
        ));
        let payload = json!({
            "event": ev,
            "expires_at": 1_700_003_600u64,
            "reason": "cool down",
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let body: ActionBody = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body.event.kind, KIND_MUTE);
        assert_eq!(body.expires_at, Some(1_700_003_600));
    }

    #[test]
    fn validate_rejects_non_admin_signer_for_ban() {
        let ev = signed(build_ban(&admin_pk(), &target_pk(), "spam", 1_700_000_000));
        let empty: HashSet<String> = HashSet::new();
        let err = validate_moderation_event(&ev, &empty).unwrap_err();
        assert!(matches!(
            err,
            nostr_bbs_core::ModerationEventError::NotAdmin { .. }
        ));
    }

    #[test]
    fn first_tag_finds_p_tag() {
        let ev = signed(build_ban(&admin_pk(), &target_pk(), "", 1_700_000_000));
        assert_eq!(first_tag(&ev, "p"), Some(target_pk().as_str()));
        assert_eq!(first_tag(&ev, "zz"), None);
    }

    // ── P0-4: unban / unmute routing ──────────────────────────────────

    #[test]
    fn action_for_path_routes_all_actions() {
        assert_eq!(action_for_path("/api/mod/ban"), Some(("ban", KIND_BAN)));
        assert_eq!(action_for_path("/api/mod/mute"), Some(("mute", KIND_MUTE)));
        assert_eq!(
            action_for_path("/api/mod/warn"),
            Some(("warn", KIND_WARNING))
        );
        // The two gap-filled routes must resolve to the unban/unmute kinds.
        assert_eq!(
            action_for_path("/api/mod/unban"),
            Some(("unban", KIND_UNBAN))
        );
        assert_eq!(
            action_for_path("/api/mod/unmute"),
            Some(("unmute", KIND_UNMUTE))
        );
        assert_eq!(action_for_path("/api/mod/nope"), None);
    }

    #[test]
    fn unban_event_routes_and_validates() {
        // The route resolves to KIND_UNBAN ...
        let (name, kind) = action_for_path("/api/mod/unban").unwrap();
        assert_eq!(name, "unban");
        assert_eq!(kind, KIND_UNBAN);

        // ... and an admin-signed unban event passes the same kind-match +
        // validate_moderation_event gate that handle_action applies.
        let ev = signed(build_unban(&admin_pk(), &target_pk(), "appeal granted", 1_700_000_000));
        assert_eq!(ev.kind, kind);
        let mut admins = HashSet::new();
        admins.insert(admin_pk());
        validate_moderation_event(&ev, &admins).expect("unban event must validate for admin signer");
        assert_eq!(first_tag(&ev, "p"), Some(target_pk().as_str()));
    }

    #[test]
    fn unmute_event_routes_and_validates() {
        let (name, kind) = action_for_path("/api/mod/unmute").unwrap();
        assert_eq!(name, "unmute");
        assert_eq!(kind, KIND_UNMUTE);

        let ev = signed(build_unmute(&admin_pk(), &target_pk(), "cooldown over", 1_700_000_000));
        assert_eq!(ev.kind, kind);
        let mut admins = HashSet::new();
        admins.insert(admin_pk());
        validate_moderation_event(&ev, &admins).expect("unmute event must validate for admin signer");
        assert_eq!(first_tag(&ev, "p"), Some(target_pk().as_str()));
    }
}
