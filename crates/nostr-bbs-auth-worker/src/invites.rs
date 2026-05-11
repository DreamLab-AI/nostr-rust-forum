//! WI-4 Invite credits API.
//!
//! Members earn the right to mint invite codes once they have been active for
//! `instance_settings.min_days_active` days (measured from `members.first_seen_at`).
//! Each member may have up to `instance_settings.invites_per_user` non-revoked,
//! non-expired invites outstanding. Admins are exempt from tenure + count caps.
//!
//! Invite codes are random 16-char nanoid-style tokens (URL-safe alphabet).
//! They expire after `instance_settings.invite_expiry_hours` hours. Redemption
//! is idempotent: the same pubkey redeeming the same code twice returns the
//! original `members` row without error.
//!
//! | Method | Path                        | Auth   | Purpose                                |
//! |--------|-----------------------------|--------|----------------------------------------|
//! | POST   | /api/invites/create         | authed | Mint a new invite (tenure-gated)       |
//! | GET    | /api/invites/mine           | authed | List caller's invites                  |
//! | GET    | /api/invites/:code          | open   | Preview an invite (public landing)     |
//! | POST   | /api/invites/:code/redeem   | authed | Redeem an invite, become a member      |
//! | POST   | /api/invites/:id/revoke     | authed | Revoke an invite you issued (or admin) |

use nostr_bbs_core::d1_helpers::{js_i64, js_str};
use serde::Deserialize;
use serde_json::json;
use worker::{Env, Response, Result};

use crate::admin::{canonical_url, is_admin, now_secs, require_authed};
use crate::http::{error_json, json_response};

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct CreateBody {
    /// Optional max-uses override. Defaults to 1 (single-use invite). Admins
    /// may raise this; regular users are capped at 1 use per code.
    max_uses: Option<u32>,
}

// ---------------------------------------------------------------------------
// D1 row types
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Deserialize)]
struct InviteRow {
    id: String,
    code: String,
    issued_by: String,
    max_uses: i64,
    uses: i64,
    expires_at: i64,
    revoked_at: Option<i64>,
    revoked_by: Option<String>,
    created_at: i64,
}

#[derive(Deserialize)]
struct SettingsRow {
    min_days_active: i64,
    invites_per_user: i64,
    invite_expiry_hours: i64,
}

#[derive(Deserialize)]
struct MemberRow {
    #[allow(dead_code)]
    pubkey: String,
    first_seen_at: Option<i64>,
}

#[derive(Deserialize)]
struct CountRow {
    c: i64,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// nanoid-style 16-char code from the URL-safe alphabet. Cryptographically
/// random via `getrandom` (backed by `crypto.getRandomValues` on wasm).
///
/// Returns an error if the CSPRNG is unavailable rather than falling back to a
/// predictable source -- invite codes must be unpredictable.
fn generate_code(len: usize) -> std::result::Result<String, &'static str> {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-";
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| "CSPRNG unavailable: cannot generate secure invite code")?;
    Ok(bytes
        .into_iter()
        .map(|b| ALPHABET[(b as usize) % ALPHABET.len()] as char)
        .collect())
}

/// Load the effective settings row, falling back to sane defaults if the
/// table has not been seeded yet.
async fn load_settings(env: &Env) -> SettingsRow {
    if let Ok(db) = env.d1("DB") {
        if let Ok(Some(row)) = db
            .prepare(
                "SELECT min_days_active, invites_per_user, invite_expiry_hours \
                 FROM instance_settings WHERE id = 1",
            )
            .first::<SettingsRow>(None)
            .await
        {
            return row;
        }
    }
    SettingsRow {
        min_days_active: 7,
        invites_per_user: 3,
        invite_expiry_hours: 168,
    }
}

/// Look up the caller's `members` row, if any.
async fn load_member(pubkey: &str, env: &Env) -> Option<MemberRow> {
    let db = env.d1("DB").ok()?;
    db.prepare("SELECT pubkey, first_seen_at FROM members WHERE pubkey = ?1")
        .bind(&[js_str(pubkey)])
        .ok()?
        .first::<MemberRow>(None)
        .await
        .ok()
        .flatten()
}

/// Count active (non-revoked, non-expired, uses < max_uses) invites for a pubkey.
async fn active_invite_count(pubkey: &str, now: i64, env: &Env) -> i64 {
    let Ok(db) = env.d1("DB") else {
        return 0;
    };
    let Ok(stmt) = db
        .prepare(
            "SELECT COUNT(*) AS c FROM invitations \
             WHERE issued_by = ?1 AND revoked_at IS NULL AND expires_at > ?2 AND uses < max_uses",
        )
        .bind(&[js_str(pubkey), js_i64(now)])
    else {
        return 0;
    };
    stmt.first::<CountRow>(None)
        .await
        .ok()
        .flatten()
        .map(|r| r.c)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// POST /api/invites/create
// ---------------------------------------------------------------------------

pub async fn handle_create(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
) -> Result<Response> {
    let url = canonical_url(env, "/api/invites/create");
    let pubkey = match require_authed(auth_header, &url, "POST", Some(body_bytes), env).await {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let body: CreateBody = if body_bytes.is_empty() {
        CreateBody::default()
    } else {
        serde_json::from_slice(body_bytes).unwrap_or_default()
    };

    let settings = load_settings(env).await;
    let member = load_member(&pubkey, env).await;
    let caller_is_admin = is_admin(&pubkey, env).await;

    if !caller_is_admin {
        // Tenure gate: first_seen_at must be at least min_days_active days old.
        let Some(ref m) = member else {
            return error_json(env, "Only registered members can create invites", 403);
        };
        let first_seen = m.first_seen_at.unwrap_or(0);
        let days_active = (now_secs() as i64 - first_seen) / 86_400;
        if days_active < settings.min_days_active {
            return error_json(
                env,
                &format!(
                    "Account too new: {days_active}/{min} days active required",
                    min = settings.min_days_active
                ),
                403,
            );
        }

        // Cap: number of active invites
        let count = active_invite_count(&pubkey, now_secs() as i64, env).await;
        if count >= settings.invites_per_user {
            return error_json(
                env,
                &format!(
                    "Invite cap reached: {count}/{limit} active",
                    limit = settings.invites_per_user
                ),
                403,
            );
        }
    }

    let max_uses: i64 = if caller_is_admin {
        body.max_uses.unwrap_or(1) as i64
    } else {
        1 // regular users: single-use only
    };
    let max_uses = max_uses.clamp(1, 100);

    let id = match generate_code(8) {
        Ok(v) => v,
        Err(msg) => return error_json(env, msg, 500),
    };
    let code = match generate_code(16) {
        Ok(v) => v,
        Err(msg) => return error_json(env, msg, 500),
    };
    let now = now_secs() as i64;
    let expires_at = now + (settings.invite_expiry_hours * 3600);

    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return error_json(env, "Database unavailable", 500),
    };

    let insert = db
        .prepare(
            "INSERT INTO invitations (id, code, issued_by, max_uses, uses, expires_at, created_at) \
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6)",
        )
        .bind(&[
            js_str(&id),
            js_str(&code),
            js_str(&pubkey),
            js_i64(max_uses),
            js_i64(expires_at),
            js_i64(now),
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
            "id": id,
            "code": code,
            "expires_at": expires_at,
            "max_uses": max_uses,
            "issued_by": pubkey,
        }),
        200,
    )
}

// ---------------------------------------------------------------------------
// GET /api/invites/mine
// ---------------------------------------------------------------------------

pub async fn handle_list_mine(auth_header: Option<&str>, env: &Env) -> Result<Response> {
    let url = canonical_url(env, "/api/invites/mine");
    let pubkey = match require_authed(auth_header, &url, "GET", None, env).await {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return error_json(env, "Database unavailable", 500),
    };

    let result = db
        .prepare(
            "SELECT id, code, issued_by, max_uses, uses, expires_at, revoked_at, revoked_by, created_at \
             FROM invitations WHERE issued_by = ?1 ORDER BY created_at DESC LIMIT 100",
        )
        .bind(&[js_str(&pubkey)])?
        .all()
        .await;

    let rows: Vec<InviteRow> = match result {
        Ok(r) => r.results().unwrap_or_default(),
        Err(e) => return error_json(env, &format!("Query failed: {e}"), 500),
    };

    let now = now_secs() as i64;
    let invites: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            let state = classify(&r, now);
            json!({
                "id": r.id,
                "code": r.code,
                "max_uses": r.max_uses,
                "uses": r.uses,
                "expires_at": r.expires_at,
                "revoked_at": r.revoked_at,
                "revoked_by": r.revoked_by,
                "created_at": r.created_at,
                "state": state,
            })
        })
        .collect();

    json_response(env, &json!({ "invites": invites }), 200)
}

fn classify(r: &InviteRow, now: i64) -> &'static str {
    if r.revoked_at.is_some() {
        "revoked"
    } else if r.expires_at <= now {
        "expired"
    } else if r.uses >= r.max_uses {
        "used"
    } else {
        "active"
    }
}

// ---------------------------------------------------------------------------
// GET /api/invites/:code   (public preview -- no auth required)
// ---------------------------------------------------------------------------

pub async fn handle_preview(code: &str, env: &Env) -> Result<Response> {
    if !is_valid_code(code) {
        return error_json(env, "Invalid code", 400);
    }

    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return error_json(env, "Database unavailable", 500),
    };

    let row = db
        .prepare(
            "SELECT id, code, issued_by, max_uses, uses, expires_at, revoked_at, revoked_by, created_at \
             FROM invitations WHERE code = ?1",
        )
        .bind(&[js_str(code)])?
        .first::<InviteRow>(None)
        .await
        .ok()
        .flatten();

    let row = match row {
        Some(r) => r,
        None => return error_json(env, "Invite not found", 404),
    };

    let now = now_secs() as i64;
    let state = classify(&row, now);

    let status_code = if state == "revoked" {
        410 // Gone
    } else {
        200
    };

    // Public preview -- don't leak issuer pubkey fully; show a short prefix.
    let issuer_prefix: String = row.issued_by.chars().take(8).collect();

    json_response(
        env,
        &json!({
            "code": row.code,
            "max_uses": row.max_uses,
            "uses": row.uses,
            "expires_at": row.expires_at,
            "state": state,
            "issuer_prefix": issuer_prefix,
        }),
        status_code,
    )
}

fn is_valid_code(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

// ---------------------------------------------------------------------------
// POST /api/invites/:code/redeem
// ---------------------------------------------------------------------------

pub async fn handle_redeem(
    code: &str,
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
) -> Result<Response> {
    if !is_valid_code(code) {
        return error_json(env, "Invalid code", 400);
    }

    let url = canonical_url(env, &format!("/api/invites/{code}/redeem"));
    let redeemer = match require_authed(auth_header, &url, "POST", Some(body_bytes), env).await {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return error_json(env, "Database unavailable", 500),
    };

    let row = db
        .prepare(
            "SELECT id, code, issued_by, max_uses, uses, expires_at, revoked_at, revoked_by, created_at \
             FROM invitations WHERE code = ?1",
        )
        .bind(&[js_str(code)])?
        .first::<InviteRow>(None)
        .await
        .ok()
        .flatten();

    let row = match row {
        Some(r) => r,
        None => return error_json(env, "Invite not found", 404),
    };

    let now = now_secs() as i64;
    match classify(&row, now) {
        "revoked" => return error_json(env, "Invite has been revoked", 410),
        "expired" => return error_json(env, "Invite expired", 410),
        "used" => return error_json(env, "Invite is fully used", 409),
        _ => {}
    }

    if row.issued_by == redeemer {
        return error_json(env, "Cannot redeem your own invite", 400);
    }

    // Idempotent: if this pubkey has already redeemed this invite, succeed.
    let already = db
        .prepare("SELECT COUNT(*) AS c FROM invitation_redemptions WHERE invitation_id = ?1 AND pubkey = ?2")
        .bind(&[js_str(&row.id), js_str(&redeemer)])?
        .first::<CountRow>(None)
        .await
        .ok()
        .flatten()
        .map(|r| r.c)
        .unwrap_or(0);

    if already > 0 {
        return json_response(
            env,
            &json!({ "ok": true, "idempotent": true, "invitation_id": row.id }),
            200,
        );
    }

    // Atomic uses increment (filter by WHERE uses < max_uses so concurrent
    // redemptions don't over-increment).
    let update = db
        .prepare(
            "UPDATE invitations SET uses = uses + 1 \
             WHERE id = ?1 AND uses < max_uses AND revoked_at IS NULL AND expires_at > ?2",
        )
        .bind(&[js_str(&row.id), js_i64(now)])?
        .run()
        .await;
    let update = match update {
        Ok(result) => result,
        Err(e) => return error_json(env, &format!("Increment failed: {e}"), 500),
    };
    let changed = update
        .meta()
        .ok()
        .flatten()
        .and_then(|m| m.changes.or(m.rows_written))
        .unwrap_or(0);
    if changed != 1 {
        return error_json(env, "Invite is fully used", 409);
    }

    // Record redemption
    let _ = db
        .prepare(
            "INSERT INTO invitation_redemptions (invitation_id, pubkey, redeemed_at) \
             VALUES (?1, ?2, ?3)",
        )
        .bind(&[js_str(&row.id), js_str(&redeemer), js_i64(now)])?
        .run()
        .await;

    // Upsert member (first_seen_at set to now on first redemption)
    let _ = db
        .prepare(
            "INSERT INTO members (pubkey, is_admin, joined_via_invite_id, first_seen_at, created_at) \
             VALUES (?1, 0, ?2, ?3, ?3) \
             ON CONFLICT (pubkey) DO UPDATE SET joined_via_invite_id = excluded.joined_via_invite_id",
        )
        .bind(&[js_str(&redeemer), js_str(&row.id), js_i64(now)])?
        .run()
        .await;

    json_response(
        env,
        &json!({
            "ok": true,
            "invitation_id": row.id,
            "issuer": row.issued_by,
            "joined_at": now,
        }),
        200,
    )
}

// ---------------------------------------------------------------------------
// POST /api/invites/:id/revoke
// ---------------------------------------------------------------------------

pub async fn handle_revoke(
    invite_id: &str,
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
) -> Result<Response> {
    if !is_valid_code(invite_id) {
        return error_json(env, "Invalid invite id", 400);
    }

    let url = canonical_url(env, &format!("/api/invites/{invite_id}/revoke"));
    let caller = match require_authed(auth_header, &url, "POST", Some(body_bytes), env).await {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return error_json(env, "Database unavailable", 500),
    };

    let row = db
        .prepare("SELECT id, code, issued_by, max_uses, uses, expires_at, revoked_at, revoked_by, created_at FROM invitations WHERE id = ?1")
        .bind(&[js_str(invite_id)])?
        .first::<InviteRow>(None)
        .await
        .ok()
        .flatten();

    let row = match row {
        Some(r) => r,
        None => return error_json(env, "Invite not found", 404),
    };

    let caller_is_admin = is_admin(&caller, env).await;
    if row.issued_by != caller && !caller_is_admin {
        return error_json(env, "Not authorised to revoke this invite", 403);
    }

    if row.revoked_at.is_some() {
        return json_response(
            env,
            &json!({ "ok": true, "already_revoked": true, "id": row.id }),
            200,
        );
    }

    let now = now_secs() as i64;
    let update = db
        .prepare("UPDATE invitations SET revoked_at = ?1, revoked_by = ?2 WHERE id = ?3")
        .bind(&[js_i64(now), js_str(&caller), js_str(invite_id)])?
        .run()
        .await;
    if let Err(e) = update {
        return error_json(env, &format!("Revoke failed: {e}"), 500);
    }

    json_response(
        env,
        &json!({ "ok": true, "id": row.id, "revoked_at": now, "revoked_by": caller }),
        200,
    )
}

// ---------------------------------------------------------------------------
// Registration bypass: consume an invite code during WebAuthn register.
// ---------------------------------------------------------------------------

/// Atomically consume `code` on behalf of `redeemer` during WebAuthn
/// registration. Used by `webauthn::register_verify` when `wot_enabled = 1`
/// but the caller supplies a valid invite code.
///
/// Returns `Ok(())` if the code is active and was (or had already been)
/// redeemed for this pubkey. Returns `Err(reason)` otherwise.
pub async fn consume_for_registration(
    code: &str,
    redeemer: &str,
    env: &Env,
) -> std::result::Result<(), &'static str> {
    if !is_valid_code(code) {
        return Err("Invalid invite code");
    }
    let db = env.d1("DB").map_err(|_| "Database unavailable")?;

    let Ok(stmt) = db
        .prepare(
            "SELECT id, code, issued_by, max_uses, uses, expires_at, revoked_at, revoked_by, created_at \
             FROM invitations WHERE code = ?1",
        )
        .bind(&[js_str(code)])
    else {
        return Err("Database error");
    };
    let row = stmt
        .first::<InviteRow>(None)
        .await
        .ok()
        .flatten()
        .ok_or("Invite not found")?;

    let now = now_secs() as i64;
    match classify(&row, now) {
        "revoked" => return Err("Invite has been revoked"),
        "expired" => return Err("Invite expired"),
        "used" => return Err("Invite is fully used"),
        _ => {}
    }
    if row.issued_by == redeemer {
        return Err("Cannot redeem your own invite");
    }

    // Idempotent: same pubkey redeeming the same code twice succeeds.
    let Ok(dup_stmt) = db
        .prepare(
            "SELECT COUNT(*) AS c FROM invitation_redemptions \
             WHERE invitation_id = ?1 AND pubkey = ?2",
        )
        .bind(&[js_str(&row.id), js_str(redeemer)])
    else {
        return Err("Database error");
    };
    let already = dup_stmt
        .first::<CountRow>(None)
        .await
        .ok()
        .flatten()
        .map(|r| r.c)
        .unwrap_or(0);
    if already > 0 {
        return Ok(());
    }

    // Atomic use bump with WHERE gate to prevent over-redemption.
    let Ok(inc_stmt) = db
        .prepare(
            "UPDATE invitations SET uses = uses + 1 \
             WHERE id = ?1 AND uses < max_uses AND revoked_at IS NULL AND expires_at > ?2",
        )
        .bind(&[js_str(&row.id), js_i64(now)])
    else {
        return Err("Database error");
    };
    let inc = inc_stmt.run().await.map_err(|_| "Increment failed")?;
    let changed = inc
        .meta()
        .ok()
        .flatten()
        .and_then(|m| m.changes.or(m.rows_written))
        .unwrap_or(0);
    if changed != 1 {
        return Err("Invite is fully used");
    }

    let Ok(rec_stmt) = db
        .prepare(
            "INSERT INTO invitation_redemptions (invitation_id, pubkey, redeemed_at) \
             VALUES (?1, ?2, ?3)",
        )
        .bind(&[js_str(&row.id), js_str(redeemer), js_i64(now)])
    else {
        return Err("Database error");
    };
    let _ = rec_stmt.run().await;

    let Ok(mem_stmt) = db
        .prepare(
            "INSERT INTO members (pubkey, is_admin, joined_via_invite_id, first_seen_at, created_at) \
             VALUES (?1, 0, ?2, ?3, ?3) \
             ON CONFLICT (pubkey) DO UPDATE SET joined_via_invite_id = excluded.joined_via_invite_id",
        )
        .bind(&[js_str(redeemer), js_str(&row.id), js_i64(now)])
    else {
        return Err("Database error");
    };
    let _ = mem_stmt.run().await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_code_has_expected_length() {
        let c = generate_code(16).expect("getrandom should work in test");
        assert_eq!(c.len(), 16);
        assert!(c
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'));
    }

    #[test]
    fn generate_code_is_non_deterministic() {
        let a = generate_code(16).expect("getrandom should work in test");
        let b = generate_code(16).expect("getrandom should work in test");
        assert_ne!(a, b, "two consecutive codes should differ");
    }

    #[test]
    fn is_valid_code_accepts_urlsafe() {
        assert!(is_valid_code("abc123"));
        assert!(is_valid_code("ABC_def-12"));
    }

    #[test]
    fn is_valid_code_rejects_bad_input() {
        assert!(!is_valid_code(""));
        assert!(!is_valid_code("contains space"));
        assert!(!is_valid_code("contains/slash"));
        assert!(!is_valid_code(&"a".repeat(33)));
    }

    #[test]
    fn classify_active_when_fresh() {
        let r = InviteRow {
            id: "i".into(),
            code: "c".into(),
            issued_by: "p".into(),
            max_uses: 1,
            uses: 0,
            expires_at: 1_000_000,
            revoked_at: None,
            revoked_by: None,
            created_at: 0,
        };
        assert_eq!(classify(&r, 100), "active");
    }

    #[test]
    fn classify_expired_after_deadline() {
        let r = InviteRow {
            id: "i".into(),
            code: "c".into(),
            issued_by: "p".into(),
            max_uses: 1,
            uses: 0,
            expires_at: 50,
            revoked_at: None,
            revoked_by: None,
            created_at: 0,
        };
        assert_eq!(classify(&r, 100), "expired");
    }

    #[test]
    fn classify_used_when_max_reached() {
        let r = InviteRow {
            id: "i".into(),
            code: "c".into(),
            issued_by: "p".into(),
            max_uses: 1,
            uses: 1,
            expires_at: 1_000_000,
            revoked_at: None,
            revoked_by: None,
            created_at: 0,
        };
        assert_eq!(classify(&r, 100), "used");
    }

    #[test]
    fn classify_revoked_beats_other_states() {
        let r = InviteRow {
            id: "i".into(),
            code: "c".into(),
            issued_by: "p".into(),
            max_uses: 1,
            uses: 0,
            expires_at: 1_000_000,
            revoked_at: Some(10),
            revoked_by: Some("admin".into()),
            created_at: 0,
        };
        assert_eq!(classify(&r, 100), "revoked");
    }

    #[test]
    fn create_body_defaults_empty() {
        let body: CreateBody = serde_json::from_str("{}").unwrap();
        assert!(body.max_uses.is_none());
    }
}
