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
//! joining `new_pubkey` is linked to a prior `old_pubkey`, we (a) merge the old
//! pubkey's `cohorts` into the new whitelist row (cohort inheritance; cohorts
//! the new key already holds are kept, ADR-2014 D2), and (b)
//! persist the alias so the *display* layer can attribute the new pubkey's posts
//! under the prior handle. Authorship of historic events is unchanged — only how
//! we render/resolve it.

use nostr_bbs_core::d1_helpers::{js_f64, js_str};
use nostr_bbs_core::whitelist_sql::WHITELIST_GRANT_COHORTS_SQL;
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

/// Build the exact absolute request URL, including its query string, for
/// NIP-98 verification.
fn request_url(req: &Request) -> Result<String> {
    Ok(req.url()?.to_string())
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
    /// Alias an old key that is whitelisted in its own right (an account,
    /// not just a key that signed history). Refused without it.
    #[serde(default)]
    force: bool,
    /// Re-point an old key that already has a DIFFERENT successor. Refused
    /// without it (a silent overwrite moves someone's history and DMs).
    #[serde(default)]
    replace: bool,
    /// Also merge an `admin` cohort from the old key. Stripped without it.
    #[serde(default)]
    inherit_admin_cohort: bool,
}

/// What the alias guards know about the two keys (see [`alias_refusal`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AliasFacts {
    /// The old key is a static admin or a config-declared ingress (DM)
    /// recipient: a system identity, never aliased, even with force.
    pub old_is_system: bool,
    /// The old key is a live identity in its own right: a whitelist row, a
    /// registered device key (or device owner), an active agent.
    pub old_is_live: bool,
    /// The old key is itself someone's successor.
    pub old_is_a_successor: bool,
    /// The new key is itself replaced.
    pub new_is_replaced: bool,
    /// The old key's current successor, if any.
    pub old_current_successor: Option<String>,
}

/// Why an alias `old -> new` is refused, if it is. One hop only, so neither
/// end may already be in a chain: an old key that is itself someone's
/// successor would leave its own predecessors resolving to it, not to `new`;
/// a successor that is itself replaced would never be shown. Neither is
/// overridable. A system identity is never aliased. A live identity hands its
/// display identity and DMs to `new`, so that takes `force`; re-pointing an
/// old key already linked elsewhere takes `replace`.
pub(crate) fn alias_refusal(
    f: &AliasFacts,
    new_pk: &str,
    force: bool,
    replace: bool,
) -> Option<&'static str> {
    if f.old_is_system {
        return Some("old_pubkey is a static admin or ingress recipient: it cannot be aliased");
    }
    if f.old_is_a_successor {
        return Some(
            "old_pubkey is itself a successor of other keys: re-point those first (one hop only)",
        );
    }
    if f.new_is_replaced {
        return Some("new_pubkey is itself replaced by another key: link to its successor instead");
    }
    if f.old_is_live && !force {
        return Some("old_pubkey is a live identity in its own right (whitelist, device or agent): pass force=true to alias it");
    }
    if f.old_current_successor
        .as_deref()
        .is_some_and(|s| s != new_pk)
        && !replace
    {
        return Some(
            "old_pubkey already has a different successor: pass replace=true to re-point it",
        );
    }
    None
}

/// The cohorts inherited from the old key: its whitelist cohorts minus
/// `admin` unless explicitly allowed. `None` for unparseable JSON.
pub(crate) fn inheritable_cohorts(cohorts_json: &str, allow_admin: bool) -> Option<String> {
    let list: Vec<String> = serde_json::from_str(cohorts_json).ok()?;
    let kept: Vec<String> = list
        .into_iter()
        .filter(|c| allow_admin || c != "admin")
        .collect();
    serde_json::to_string(&kept).ok()
}

/// Insert or re-point an alias atomically with the chain guards, so two
/// concurrent calls cannot create a chain or loop between the guard reads
/// and the write: the row is written only if `old` is nobody's successor and
/// `new` is not replaced at write time. Binds: new, old, created_by,
/// created_at, reason.
pub(crate) const ALIAS_UPSERT_GUARDED_SQL: &str = "INSERT INTO pubkey_aliases \
     (new_pubkey, old_pubkey, created_by, created_at, reason) \
     SELECT ?1, ?2, ?3, ?4, ?5 \
     WHERE NOT EXISTS (SELECT 1 FROM pubkey_aliases WHERE new_pubkey = ?2) \
       AND NOT EXISTS (SELECT 1 FROM pubkey_aliases WHERE old_pubkey = ?1) \
     ON CONFLICT (old_pubkey) DO UPDATE SET \
        new_pubkey = excluded.new_pubkey, created_by = excluded.created_by, \
        created_at = excluded.created_at, reason = excluded.reason";

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
    // Reported, never acted on: a failed tombstone cannot be retried once the
    // rows are gone, so the admin must be told, but the purge still proceeds.
    // `None` when no purge was asked for: nothing was attempted, so the reply
    // and the audit row carry no `tombstoned` at all.
    let mut tombstoned: Option<bool> = None;
    if body.delete_events {
        // Purge the user's stored events AND their projected profile row. The
        // events table is the relay store; the profiles projection is derived.
        // Tombstone them first: the whitelist row is gone, so the ingest gate
        // refuses this author for now, but re-admission must not let anyone
        // re-publish what the admin chose to remove. Fails open.
        tombstoned = Some(
            crate::tombstone_before_delete(
                &db,
                crate::TombstoneTarget::Author(&target),
                auth::js_now_secs(),
            )
            .await,
        );
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
        tombstoned
            .map(|t| json!({ "tombstoned": t }).to_string())
            .as_deref(),
        body.reason.as_deref(),
    )
    .await;

    let mut reply = json!({
        "success": true,
        "pubkey": target,
        "events_purged": events_purged,
    });
    if let Some(t) = tombstoned {
        reply["tombstoned"] = json!(t);
    }
    json_response(env, &reply, 200)
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

    // Keys are stored lowercase: every reader and the client compare exactly
    // (review C1: a mixed-case key slipped past every guard).
    let old_pk = match body.old_pubkey {
        Some(ref pk) if valid_pubkey(pk) => pk.to_ascii_lowercase(),
        _ => {
            return json_response(
                env,
                &json!({ "error": "Invalid or missing old_pubkey" }),
                400,
            )
        }
    };
    let new_pk = match body.new_pubkey {
        Some(ref pk) if valid_pubkey(pk) => pk.to_ascii_lowercase(),
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

    // Guards (see alias_refusal). Lookup errors refuse (fail closed).
    #[derive(Deserialize)]
    struct N {
        n: f64,
    }
    let exists = |sql: &'static str, pk: String| {
        let db = &db;
        async move {
            db.prepare(sql)
                .bind(&[js_str(&pk)])?
                .first::<N>(None)
                .await
                .map(|r| r.map_or(0.0, |r| r.n) > 0.0)
        }
    };
    #[derive(Deserialize)]
    struct Succ {
        new_pubkey: String,
    }
    let static_admin = env
        .var(nostr_bbs_core::ADMIN_PUBKEYS_VAR)
        .map(|v| nostr_bbs_core::is_static_admin(&old_pk, &v.to_string()))
        .unwrap_or(false);
    let ingress = nostr_bbs_config::ingress::is_ingress_recipient(
        &crate::ingress::ingress_from_env(env),
        &old_pk,
    );
    let facts = match (
        exists("SELECT COUNT(*) AS n FROM whitelist WHERE pubkey = ?1", old_pk.clone()).await,
        exists(
            "SELECT COUNT(*) AS n FROM device_keys WHERE (device_pubkey = ?1 OR owner_pubkey = ?1) AND revoked = 0",
            old_pk.clone(),
        )
        .await,
        exists("SELECT COUNT(*) AS n FROM agent_registry WHERE pubkey = ?1 AND active = 1", old_pk.clone()).await,
        exists("SELECT COUNT(*) AS n FROM pubkey_aliases WHERE new_pubkey = ?1", old_pk.clone()).await,
        exists("SELECT COUNT(*) AS n FROM pubkey_aliases WHERE old_pubkey = ?1", new_pk.clone()).await,
        db.prepare("SELECT new_pubkey FROM pubkey_aliases WHERE old_pubkey = ?1")
            .bind(&[js_str(&old_pk)])?
            .first::<Succ>(None)
            .await,
    ) {
        (Ok(wl), dev, agent, Ok(succ), Ok(repl), Ok(cur)) => AliasFacts {
            old_is_system: static_admin || ingress,
            // device_keys / agent_registry may be absent on older deployments:
            // a failed lookup there counts as live (fail closed: needs force).
            old_is_live: wl || dev.unwrap_or(true) || agent.unwrap_or(true),
            old_is_a_successor: succ,
            new_is_replaced: repl,
            old_current_successor: cur.map(|c| c.new_pubkey),
        },
        _ => return json_response(env, &json!({ "error": "Alias lookup failed" }), 503),
    };
    if let Some(reason) = alias_refusal(&facts, &new_pk, body.force, body.replace) {
        return json_response(env, &json!({ "error": reason }), 409);
    }

    // Persist the alias, re-checking the chain guards in the same statement.
    let reason_val = match body.reason.as_deref() {
        Some(r) if !r.is_empty() => js_str(r),
        _ => JsValue::NULL,
    };
    let written = db
        .prepare(ALIAS_UPSERT_GUARDED_SQL)
        .bind(&[
            js_str(&new_pk),
            js_str(&old_pk),
            js_str(&admin_pubkey),
            js_f64(now as f64),
            reason_val,
        ])?
        .run()
        .await?
        .meta()
        .ok()
        .flatten()
        .and_then(|m| m.changes)
        .unwrap_or(0);
    if written == 0 {
        return json_response(
            env,
            &json!({ "error": "alias would create a chain (changed concurrently): retry" }),
            409,
        );
    }

    // Cohort inheritance: merge the old pubkey's cohorts (minus `admin`
    // unless inherit_admin_cohort) into the new pubkey's whitelist row. A
    // merge, not a copy: anything the new key was already granted survives.
    // Not reversed on unlink or re-point (documented).
    let mut inherited_cohorts: Option<String> = None;
    if body.inherit_cohorts {
        let stmt = db.prepare("SELECT cohorts FROM whitelist WHERE pubkey = ?1");
        let bound = stmt.bind(&[js_str(&old_pk)])?;
        if let Ok(Some(row)) = bound.first::<CohortsRow>(None).await {
            if let Some(cohorts_json) = inheritable_cohorts(&row.cohorts, body.inherit_admin_cohort)
            {
                db.prepare(WHITELIST_GRANT_COHORTS_SQL)
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
    }

    let audit_reason = format!(
        "{}{}{}",
        body.reason.as_deref().unwrap_or(""),
        if body.force { " [force]" } else { "" },
        if body.replace { " [replace]" } else { "" }
    );
    let _ = audit::log_admin_action(
        env,
        &admin_pubkey,
        "pubkey_alias_set",
        Some(&new_pk),
        Some(&old_pk),
        None,
        inherited_cohorts.as_deref(),
        Some(audit_reason.trim()),
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

#[derive(Deserialize)]
struct AliasDeleteBody {
    old_pubkey: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

/// Remove one alias: `old_pubkey` no longer resolves to a successor (review
/// C4: undoing a wrong link needed a re-point or a user delete). Cohorts the
/// successor inherited are NOT revoked (they may also have come from
/// elsewhere); revoke them explicitly if needed.
///
/// Body: `{ "old_pubkey": "<hex>", "reason": "..." }`
pub async fn handle_alias_delete(mut req: Request, env: &Env) -> Result<Response> {
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
    let body: AliasDeleteBody =
        serde_json::from_slice(&body_bytes).map_err(|e| worker::Error::RustError(e.to_string()))?;
    let old_pk = match body.old_pubkey {
        Some(ref pk) if valid_pubkey(pk) => pk.to_ascii_lowercase(),
        _ => {
            return json_response(
                env,
                &json!({ "error": "Invalid or missing old_pubkey" }),
                400,
            )
        }
    };
    let db = env.d1("DB")?;
    let removed = db
        .prepare("DELETE FROM pubkey_aliases WHERE old_pubkey = ?1")
        .bind(&[js_str(&old_pk)])?
        .run()
        .await?
        .meta()
        .ok()
        .flatten()
        .and_then(|m| m.changes)
        .unwrap_or(0);
    let _ = audit::log_admin_action(
        env,
        &admin_pubkey,
        "pubkey_alias_delete",
        None,
        Some(&old_pk),
        None,
        None,
        body.reason.as_deref(),
    )
    .await;
    json_response(
        env,
        &json!({ "success": true, "old_pubkey": old_pk, "removed": removed > 0 }),
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

#[cfg(test)]
mod alias_refusal_tests {
    use super::{alias_refusal, inheritable_cohorts, AliasFacts};

    #[test]
    fn chains_and_system_keys_are_refused_live_accounts_need_force() {
        let f = |g: fn(&mut AliasFacts)| {
            let mut x = AliasFacts::default();
            g(&mut x);
            x
        };
        assert_eq!(
            alias_refusal(&AliasFacts::default(), "new", false, false),
            None,
            "an archive key"
        );
        assert!(alias_refusal(&f(|x| x.old_is_a_successor = true), "new", true, true).is_some());
        assert!(alias_refusal(&f(|x| x.new_is_replaced = true), "new", true, true).is_some());
        assert!(
            alias_refusal(&f(|x| x.old_is_system = true), "new", true, true).is_some(),
            "static admin / ingress"
        );
        assert!(alias_refusal(&f(|x| x.old_is_live = true), "new", false, false).is_some());
        assert_eq!(
            alias_refusal(&f(|x| x.old_is_live = true), "new", true, false),
            None,
            "forced"
        );
        // Re-pointing to a different successor needs replace; same successor is idempotent.
        let linked = AliasFacts {
            old_current_successor: Some("other".into()),
            ..Default::default()
        };
        assert!(alias_refusal(&linked, "new", true, false).is_some());
        assert_eq!(alias_refusal(&linked, "new", false, true), None);
        let same = AliasFacts {
            old_current_successor: Some("new".into()),
            ..Default::default()
        };
        assert_eq!(alias_refusal(&same, "new", false, false), None);
    }

    #[test]
    fn the_admin_cohort_is_not_inherited_without_the_flag() {
        assert_eq!(
            inheritable_cohorts(r#"["members","admin","zone2"]"#, false).as_deref(),
            Some(r#"["members","zone2"]"#)
        );
        assert_eq!(
            inheritable_cohorts(r#"["admin"]"#, true).as_deref(),
            Some(r#"["admin"]"#)
        );
        assert_eq!(inheritable_cohorts("nope", false), None);
    }
}
