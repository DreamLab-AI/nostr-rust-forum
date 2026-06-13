//! Admin user-management HTTP handlers (Task #7).
//!
//! These endpoints sit alongside `whitelist.rs` in the main worker (NOT the
//! Durable Object) and share the same `DB` D1 binding. Every mutating route is
//! NIP-98 admin-gated via [`auth::require_nip98_admin`] and writes an
//! `admin_log` audit row.
//!
//! | Method | Path                       | Purpose                                   |
//! |--------|----------------------------|-------------------------------------------|
//! | POST   | /api/admin/user/delete     | Remove from whitelist (+optional purge)   |
//! | POST   | /api/admin/suspend         | Set/clear `whitelist.suspended_until`     |
//! | POST   | /api/admin/silence         | Set/clear `whitelist.silenced`            |
//! | GET    | /api/admin/notes/:pubkey   | Read `whitelist.user_notes`               |
//! | POST   | /api/admin/notes           | Write `whitelist.user_notes`              |
//! | GET    | /api/admin/aliases         | List `pubkey_aliases` rows                |
//! | POST   | /api/admin/alias           | Link old_pubkey -> new_pubkey (+inherit)  |
//!
//! ## Alias inheritance (NOT event re-signing)
//!
//! Nostr events are bound to the signing key; an admin can never re-sign another
//! key's events. The realistic model is a `pubkey_aliases` map. When a newly
//! joining `new_pubkey` is linked to a prior `old_pubkey`, we (a) copy the old
//! pubkey's `cohorts` onto the new whitelist row (cohort inheritance), and (b)
//! persist the alias so the *display* layer can attribute the new pubkey's posts
//! under the prior handle. Authorship of historic events is unchanged — only how
//! we render/resolve it.

use nostr_bbs_core::d1_helpers::{js_f64, js_str};
use serde::Deserialize;
use serde_json::json;
use wasm_bindgen::JsValue;
use worker::{Env, Request, Response, Result};

use crate::audit;
use crate::auth;
use crate::cors::json_response;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validate a 64-char lowercase-or-upper hex pubkey.
fn valid_pubkey(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Build the canonical request URL (origin + path) for NIP-98 verification.
fn request_url(req: &Request) -> Result<String> {
    let url = req.url()?;
    Ok(format!(
        "{}{}",
        url.origin().ascii_serialization(),
        url.path()
    ))
}

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DeleteUserBody {
    pubkey: Option<String>,
    /// When true, also `DELETE FROM events WHERE pubkey = ?` — purges the
    /// user's posted messages. Defaults to false (whitelist removal only).
    #[serde(default)]
    delete_events: bool,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
struct SuspendBody {
    pubkey: Option<String>,
    /// `"1d" | "1w" | "1m" | "permanent"`, or `"clear"`/empty to lift.
    #[serde(default)]
    duration: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
struct SilenceBody {
    pubkey: Option<String>,
    #[serde(default)]
    silenced: bool,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
struct NotesBody {
    pubkey: Option<String>,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Deserialize)]
struct AliasBody {
    old_pubkey: Option<String>,
    new_pubkey: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    /// When true (default), copy the old pubkey's whitelist cohorts onto the
    /// new pubkey's whitelist row so the new key inherits zone access.
    #[serde(default = "default_true")]
    inherit_cohorts: bool,
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// D1 row types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CountRow {
    count: f64,
}

#[derive(Deserialize)]
struct NotesRow {
    user_notes: Option<String>,
}

#[derive(Deserialize)]
struct CohortsRow {
    cohorts: String,
}

#[derive(Deserialize)]
struct AliasRow {
    old_pubkey: String,
    new_pubkey: String,
    created_by: String,
    created_at: f64,
    reason: Option<String>,
}

// ---------------------------------------------------------------------------
// POST /api/admin/user/delete
// ---------------------------------------------------------------------------

/// Remove a user from the whitelist. Optionally purge all their stored events.
///
/// Body: `{ "pubkey": "<hex>", "delete_events": false, "reason": "..." }`
///
/// Safety: refuses to delete the last remaining admin.
pub async fn handle_delete_user(mut req: Request, env: &Env) -> Result<Response> {
    let request_url = request_url(&req)?;
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

    let body: DeleteUserBody =
        serde_json::from_slice(&body_bytes).map_err(|e| worker::Error::RustError(e.to_string()))?;

    let target = match body.pubkey {
        Some(ref pk) if valid_pubkey(pk) => pk.clone(),
        _ => return json_response(env, &json!({ "error": "Invalid or missing pubkey" }), 400),
    };

    let db = env.d1("DB")?;

    // Safety: never delete the last admin. If the target is an admin and is the
    // only one left, refuse.
    let target_is_admin = {
        let stmt = db
            .prepare("SELECT COUNT(*) as count FROM whitelist WHERE pubkey = ?1 AND is_admin = 1");
        let bound = stmt.bind(&[js_str(&target)])?;
        matches!(bound.first::<CountRow>(None).await, Ok(Some(r)) if r.count > 0.0)
    };
    if target_is_admin {
        let stmt = db.prepare("SELECT COUNT(*) as count FROM whitelist WHERE is_admin = 1");
        if let Ok(Some(row)) = stmt.first::<CountRow>(None).await {
            if (row.count as u64) <= 1 {
                return json_response(
                    env,
                    &json!({ "error": "Cannot delete the last admin" }),
                    400,
                );
            }
        }
    }

    // Remove the whitelist row (revokes all relay access).
    db.prepare("DELETE FROM whitelist WHERE pubkey = ?1")
        .bind(&[js_str(&target)])?
        .run()
        .await?;

    // Drop any alias rows referencing the deleted pubkey so stale attribution
    // cannot survive the user.
    let _ = db
        .prepare("DELETE FROM pubkey_aliases WHERE old_pubkey = ?1 OR new_pubkey = ?1")
        .bind(&[js_str(&target)])?
        .run()
        .await;

    let mut events_purged = false;
    if body.delete_events {
        // Purge the user's stored events AND their projected profile row. The
        // events table is the relay store; the profiles projection is derived.
        let _ = db
            .prepare("DELETE FROM events WHERE pubkey = ?1")
            .bind(&[js_str(&target)])?
            .run()
            .await;
        let _ = db
            .prepare("DELETE FROM profiles WHERE pubkey = ?1")
            .bind(&[js_str(&target)])?
            .run()
            .await;
        events_purged = true;
    }

    let _ = audit::log_admin_action(
        env,
        &admin_pubkey,
        if events_purged {
            "user_delete_with_events"
        } else {
            "user_delete"
        },
        Some(&target),
        None,
        None,
        None,
        body.reason.as_deref(),
    )
    .await;

    json_response(
        env,
        &json!({ "success": true, "pubkey": target, "events_purged": events_purged }),
        200,
    )
}

// ---------------------------------------------------------------------------
// POST /api/admin/suspend
// ---------------------------------------------------------------------------

/// Suspend (or lift suspension on) a user. Writes `whitelist.suspended_until`.
///
/// Body: `{ "pubkey": "<hex>", "duration": "1d|1w|1m|permanent|clear", "reason": "..." }`
pub async fn handle_suspend(mut req: Request, env: &Env) -> Result<Response> {
    let request_url = request_url(&req)?;
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

    let body: SuspendBody =
        serde_json::from_slice(&body_bytes).map_err(|e| worker::Error::RustError(e.to_string()))?;

    let target = match body.pubkey {
        Some(ref pk) if valid_pubkey(pk) => pk.clone(),
        _ => return json_response(env, &json!({ "error": "Invalid or missing pubkey" }), 400),
    };

    let now = auth::js_now_secs();
    // A duration string maps to an absolute `suspended_until` unix-seconds, or
    // NULL to lift. "permanent" parks the timestamp far in the future.
    let until: Option<u64> = match body.duration.as_deref().map(|s| s.trim()) {
        Some("1d") => Some(now + 86_400),
        Some("1w") => Some(now + 7 * 86_400),
        Some("1m") => Some(now + 30 * 86_400),
        Some("permanent") => Some(now + 100 * 365 * 86_400),
        Some("") | Some("clear") | None => None,
        Some(_) => return json_response(env, &json!({ "error": "Invalid duration" }), 400),
    };

    let db = env.d1("DB")?;
    let until_val = match until {
        Some(ts) => js_f64(ts as f64),
        None => JsValue::NULL,
    };
    db.prepare("UPDATE whitelist SET suspended_until = ?1 WHERE pubkey = ?2")
        .bind(&[until_val, js_str(&target)])?
        .run()
        .await?;

    let _ = audit::log_admin_action(
        env,
        &admin_pubkey,
        if until.is_some() {
            "user_suspend"
        } else {
            "user_unsuspend"
        },
        Some(&target),
        None,
        None,
        until.map(|ts| ts.to_string()).as_deref(),
        body.reason.as_deref(),
    )
    .await;

    json_response(
        env,
        &json!({ "success": true, "pubkey": target, "suspended_until": until }),
        200,
    )
}

// ---------------------------------------------------------------------------
// POST /api/admin/silence
// ---------------------------------------------------------------------------

/// Silence (read-only) or unsilence a user. Writes `whitelist.silenced`.
///
/// Body: `{ "pubkey": "<hex>", "silenced": true, "reason": "..." }`
pub async fn handle_silence(mut req: Request, env: &Env) -> Result<Response> {
    let request_url = request_url(&req)?;
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

    let body: SilenceBody =
        serde_json::from_slice(&body_bytes).map_err(|e| worker::Error::RustError(e.to_string()))?;

    let target = match body.pubkey {
        Some(ref pk) if valid_pubkey(pk) => pk.clone(),
        _ => return json_response(env, &json!({ "error": "Invalid or missing pubkey" }), 400),
    };

    let db = env.d1("DB")?;
    let val = if body.silenced { 1i32 } else { 0i32 };
    db.prepare("UPDATE whitelist SET silenced = ?1 WHERE pubkey = ?2")
        .bind(&[js_f64(val as f64), js_str(&target)])?
        .run()
        .await?;

    let _ = audit::log_admin_action(
        env,
        &admin_pubkey,
        if body.silenced {
            "user_silence"
        } else {
            "user_unsilence"
        },
        Some(&target),
        None,
        Some(if body.silenced { "0" } else { "1" }),
        Some(if body.silenced { "1" } else { "0" }),
        body.reason.as_deref(),
    )
    .await;

    json_response(
        env,
        &json!({ "success": true, "pubkey": target, "silenced": body.silenced }),
        200,
    )
}

// ---------------------------------------------------------------------------
// GET /api/admin/notes/:pubkey  and  POST /api/admin/notes
// ---------------------------------------------------------------------------

/// Read the private admin notes for a user. `pubkey` is the trailing path
/// segment after `/api/admin/notes/`.
pub async fn handle_notes_get(req: &Request, env: &Env, pubkey: &str) -> Result<Response> {
    let request_url = request_url(req)?;
    let auth_header = req.headers().get("Authorization").ok().flatten();

    if let Err((body, status)) =
        auth::require_nip98_admin(auth_header.as_deref(), &request_url, "GET", None, env).await
    {
        return json_response(env, &body, status);
    }

    if !valid_pubkey(pubkey) {
        return json_response(env, &json!({ "error": "Invalid pubkey" }), 400);
    }

    let db = env.d1("DB")?;
    let stmt = db.prepare("SELECT user_notes FROM whitelist WHERE pubkey = ?1");
    let bound = stmt.bind(&[js_str(pubkey)])?;
    let notes = match bound.first::<NotesRow>(None).await {
        Ok(Some(row)) => row.user_notes.unwrap_or_default(),
        _ => String::new(),
    };

    json_response(env, &json!({ "pubkey": pubkey, "notes": notes }), 200)
}

/// Write the private admin notes for a user.
///
/// Body: `{ "pubkey": "<hex>", "notes": "..." }`
pub async fn handle_notes_set(mut req: Request, env: &Env) -> Result<Response> {
    let request_url = request_url(&req)?;
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

    let body: NotesBody =
        serde_json::from_slice(&body_bytes).map_err(|e| worker::Error::RustError(e.to_string()))?;

    let target = match body.pubkey {
        Some(ref pk) if valid_pubkey(pk) => pk.clone(),
        _ => return json_response(env, &json!({ "error": "Invalid or missing pubkey" }), 400),
    };

    let notes = body.notes.unwrap_or_default();
    let db = env.d1("DB")?;
    let notes_val = if notes.is_empty() {
        JsValue::NULL
    } else {
        js_str(&notes)
    };
    db.prepare("UPDATE whitelist SET user_notes = ?1 WHERE pubkey = ?2")
        .bind(&[notes_val, js_str(&target)])?
        .run()
        .await?;

    let _ = audit::log_admin_action(
        env,
        &admin_pubkey,
        "user_notes_set",
        Some(&target),
        None,
        None,
        None,
        None,
    )
    .await;

    json_response(env, &json!({ "success": true, "pubkey": target }), 200)
}

// ---------------------------------------------------------------------------
// GET /api/admin/aliases  and  POST /api/admin/alias
// ---------------------------------------------------------------------------

/// List every pubkey alias (admin only).
pub async fn handle_aliases_list(req: &Request, env: &Env) -> Result<Response> {
    let request_url = request_url(req)?;
    let auth_header = req.headers().get("Authorization").ok().flatten();

    if let Err((body, status)) =
        auth::require_nip98_admin(auth_header.as_deref(), &request_url, "GET", None, env).await
    {
        return json_response(env, &body, status);
    }

    let db = env.d1("DB")?;
    let result = db
        .prepare(
            "SELECT old_pubkey, new_pubkey, created_by, created_at, reason \
             FROM pubkey_aliases ORDER BY created_at DESC",
        )
        .all()
        .await?;
    let rows: Vec<AliasRow> = result.results().unwrap_or_default();
    let aliases: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "old_pubkey": r.old_pubkey,
                "new_pubkey": r.new_pubkey,
                "created_by": r.created_by,
                "created_at": r.created_at as u64,
                "reason": r.reason,
            })
        })
        .collect();

    json_response(env, &json!({ "aliases": aliases }), 200)
}

/// Link `old_pubkey -> new_pubkey`. The new pubkey inherits the old pubkey's
/// cohorts (when `inherit_cohorts`, the default) and future display attribution
/// resolves the new pubkey under the old one. Events are never re-signed.
///
/// Body: `{ "old_pubkey": "<hex>", "new_pubkey": "<hex>", "reason": "...", "inherit_cohorts": true }`
pub async fn handle_alias_set(mut req: Request, env: &Env) -> Result<Response> {
    let request_url = request_url(&req)?;
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

    let body: AliasBody =
        serde_json::from_slice(&body_bytes).map_err(|e| worker::Error::RustError(e.to_string()))?;

    let old_pk = match body.old_pubkey {
        Some(ref pk) if valid_pubkey(pk) => pk.clone(),
        _ => {
            return json_response(
                env,
                &json!({ "error": "Invalid or missing old_pubkey" }),
                400,
            )
        }
    };
    let new_pk = match body.new_pubkey {
        Some(ref pk) if valid_pubkey(pk) => pk.clone(),
        _ => {
            return json_response(
                env,
                &json!({ "error": "Invalid or missing new_pubkey" }),
                400,
            )
        }
    };
    if old_pk == new_pk {
        return json_response(
            env,
            &json!({ "error": "old_pubkey and new_pubkey must differ" }),
            400,
        );
    }

    let now = auth::js_now_secs();
    let db = env.d1("DB")?;

    // Persist the alias (new_pubkey is the PK: a joining key maps to at most one
    // prior identity; re-linking overwrites).
    let reason_val = match body.reason.as_deref() {
        Some(r) if !r.is_empty() => js_str(r),
        _ => JsValue::NULL,
    };
    db.prepare(
        "INSERT INTO pubkey_aliases (new_pubkey, old_pubkey, created_by, created_at, reason) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT (new_pubkey) DO UPDATE SET \
            old_pubkey = excluded.old_pubkey, \
            created_by = excluded.created_by, \
            created_at = excluded.created_at, \
            reason = excluded.reason",
    )
    .bind(&[
        js_str(&new_pk),
        js_str(&old_pk),
        js_str(&admin_pubkey),
        js_f64(now as f64),
        reason_val,
    ])?
    .run()
    .await?;

    // Cohort inheritance: copy the old pubkey's cohorts onto the new pubkey's
    // whitelist row (creating it if absent). Access (which zones the new key can
    // read/write) is cohort-driven, so this is the realistic "inherit access".
    let mut inherited_cohorts: Option<String> = None;
    if body.inherit_cohorts {
        let stmt = db.prepare("SELECT cohorts FROM whitelist WHERE pubkey = ?1");
        let bound = stmt.bind(&[js_str(&old_pk)])?;
        if let Ok(Some(row)) = bound.first::<CohortsRow>(None).await {
            let cohorts_json = row.cohorts;
            db.prepare(
                "INSERT INTO whitelist (pubkey, cohorts, added_at, added_by) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT (pubkey) DO UPDATE SET cohorts = excluded.cohorts",
            )
            .bind(&[
                js_str(&new_pk),
                js_str(&cohorts_json),
                js_f64(now as f64),
                js_str(&admin_pubkey),
            ])?
            .run()
            .await?;
            inherited_cohorts = Some(cohorts_json);
        }
    }

    let _ = audit::log_admin_action(
        env,
        &admin_pubkey,
        "pubkey_alias_set",
        Some(&new_pk),
        Some(&old_pk),
        None,
        inherited_cohorts.as_deref(),
        body.reason.as_deref(),
    )
    .await;

    json_response(
        env,
        &json!({
            "success": true,
            "old_pubkey": old_pk,
            "new_pubkey": new_pk,
            "inherited_cohorts": inherited_cohorts,
        }),
        200,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_validation() {
        assert!(valid_pubkey(&"a".repeat(64)));
        assert!(valid_pubkey(
            "2de44d5622eef79519ac078f6e227a85aecbaefd561e4e50c5f51dfadbf916e9"
        ));
        assert!(!valid_pubkey(&"a".repeat(63)));
        assert!(!valid_pubkey(&"a".repeat(65)));
        assert!(!valid_pubkey(&format!("g{}", "a".repeat(63))));
        assert!(!valid_pubkey(""));
    }
}
