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

use nostr_bbs_core::d1_helpers::{js_i64, js_opt_str, js_str};
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
    /// Optional zone this invite grants access to (a `ZONE_CONFIG` zone id,
    /// e.g. `zone2`). When present the invite is *zone-bound*: redeeming it
    /// additionally grants the zone's `required_cohorts` to the redeemer.
    /// Minting a zone-bound invite is ADMIN-ONLY — a regular member must not
    /// be able to grant zone access. `None` ⇒ a plain member invite (existing
    /// member-can-mint behaviour).
    zone_id: Option<String>,
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
    /// Zone this invite grants (a `ZONE_CONFIG` id), or `None` for a plain
    /// member invite. The zone's `required_cohorts` are resolved from config
    /// at redeem time — only the id is frozen into the row.
    #[serde(default)]
    zone_id: Option<String>,
}

/// Whitelist cohort projection read back from the relay's shared D1 before a
/// merge-grant.
#[derive(Deserialize)]
struct WhitelistCohortsRow {
    cohorts: String,
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
// Zone resolution (pure) + grant (D1)
// ---------------------------------------------------------------------------

/// Minimal projection of a `ZONE_CONFIG` entry — only what zone-bound invites
/// need. Extra fields in the JSON are ignored.
#[derive(Debug, Clone, Deserialize)]
struct ZoneMeta {
    id: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    required_cohorts: Vec<String>,
}

/// Resolve a zone by id from a `ZONE_CONFIG` JSON string. Returns `None` when
/// the config is absent/malformed or when no zone carries that id. This is the
/// single source of truth for both "does this zone exist?" (create-time
/// validation) and "what cohorts does it grant?" (redeem-time resolution) — the
/// cohorts are never frozen into the invite row.
fn resolve_zone(zone_config: Option<&str>, zone_id: &str) -> Option<ZoneMeta> {
    let raw = zone_config?;
    let zones: Vec<ZoneMeta> = serde_json::from_str(raw.trim()).ok()?;
    zones.into_iter().find(|z| z.id == zone_id)
}

/// Merge `add` cohorts into an existing JSON cohort array string, de-duplicating
/// and preserving every existing cohort (never clobbers). The whitelist stores
/// cohorts as a JSON array string (see relay `whitelist.rs` / auth `username.rs`).
/// A malformed/empty existing value is treated as an empty set so the grant
/// still lands.
fn merge_cohorts_json(existing: &str, add: &[String]) -> String {
    let mut cohorts: Vec<String> = serde_json::from_str(existing.trim()).unwrap_or_default();
    for c in add {
        if !cohorts.contains(c) {
            cohorts.push(c.clone());
        }
    }
    serde_json::to_string(&cohorts).unwrap_or_else(|_| existing.to_string())
}

/// Grant `zone_cohorts` to `pubkey` on the relay's shared whitelist (RELAY_DB).
///
/// **Ensure-then-merge** (race-safe). The redeemer is frequently a brand-new
/// signup whose whitelist row is being created *concurrently* by the auth-worker
/// username-claim (`username.rs`). A naive SELECT-then-branch loses the grant:
/// if the SELECT sees no row but the claim's `INSERT ... members` lands before
/// this function's `INSERT ... members+zone ON CONFLICT DO NOTHING`, the conflict
/// silently drops the zone cohort. To close that window we:
///   1. INSERT a row seeded with `members` + the zone cohorts, `ON CONFLICT DO
///      NOTHING` — guarantees a row exists afterwards (ours, or the claim's).
///   2. Re-read the (now-guaranteed) row and UPDATE it with the zone cohorts
///      merged into whatever is there. The UPDATE is idempotent and correct
///      whether we or the claim won step 1, so a concurrent bare-`members`
///      insert can no longer clobber the grant.
/// Best-effort: any D1 error is a non-fatal no-op (the redeem still succeeds; an
/// admin can re-grant).
async fn grant_zone_cohorts(env: &Env, pubkey: &str, zone_cohorts: &[String]) {
    if zone_cohorts.is_empty() {
        return;
    }
    let Ok(db) = env.d1("RELAY_DB") else {
        return;
    };

    let now = now_secs() as i64;

    // 1. Ensure a row exists. If we win the insert it already carries the zone
    //    cohorts; if the username-claim wins, DO NOTHING and step 2 merges.
    let seeded = merge_cohorts_json(r#"["members"]"#, zone_cohorts);
    if let Ok(stmt) = db
        .prepare(
            "INSERT INTO whitelist (pubkey, cohorts, added_at, added_by, is_admin) \
             VALUES (?1, ?2, ?3, ?4, 0) ON CONFLICT (pubkey) DO NOTHING",
        )
        .bind(&[
            js_str(pubkey),
            js_str(&seeded),
            js_i64(now),
            js_str("invite-zone-grant"),
        ])
    {
        let _ = stmt.run().await;
    }

    // 2. Merge the zone cohorts into whatever row now exists. Covers the case
    //    where a concurrent claim-insert of ["members"] won step 1.
    let existing = match db
        .prepare("SELECT cohorts FROM whitelist WHERE pubkey = ?1")
        .bind(&[js_str(pubkey)])
    {
        Ok(stmt) => stmt.first::<WhitelistCohortsRow>(None).await.ok().flatten(),
        Err(_) => None,
    };
    if let Some(row) = existing {
        let merged = merge_cohorts_json(&row.cohorts, zone_cohorts);
        if merged != row.cohorts {
            if let Ok(stmt) = db
                .prepare("UPDATE whitelist SET cohorts = ?1 WHERE pubkey = ?2")
                .bind(&[js_str(&merged), js_str(pubkey)])
            {
                let _ = stmt.run().await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/invites/create
// ---------------------------------------------------------------------------

pub async fn handle_create(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/invites/create");
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

    // Zone binding: admin-only to mint, and the zone must exist in ZONE_CONFIG.
    // A plain member invite (`zone_id: None`) keeps the member-can-mint path.
    let zone_id: Option<String> = match body.zone_id.as_deref().map(str::trim) {
        Some(z) if !z.is_empty() => {
            if !caller_is_admin {
                return error_json(env, "Only admins can mint zone-bound invites", 403);
            }
            let zone_config = env.var("ZONE_CONFIG").ok().map(|v| v.to_string());
            if resolve_zone(zone_config.as_deref(), z).is_none() {
                return error_json(env, &format!("Unknown zone: {z}"), 400);
            }
            Some(z.to_string())
        }
        _ => None,
    };

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
            "INSERT INTO invitations (id, code, issued_by, max_uses, uses, expires_at, created_at, zone_id) \
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, ?7)",
        )
        .bind(&[
            js_str(&id),
            js_str(&code),
            js_str(&pubkey),
            js_i64(max_uses),
            js_i64(expires_at),
            js_i64(now),
            js_opt_str(zone_id.as_deref()),
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
            "zone_id": zone_id,
        }),
        200,
    )
}

// ---------------------------------------------------------------------------
// GET /api/invites/mine
// ---------------------------------------------------------------------------

pub async fn handle_list_mine(
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/invites/mine");
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
            "SELECT id, code, issued_by, max_uses, uses, expires_at, revoked_at, revoked_by, created_at, zone_id \
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
            "SELECT id, code, issued_by, max_uses, uses, expires_at, revoked_at, revoked_by, created_at, zone_id \
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

    // Zone-bound invites carry the human-readable zone name so the landing
    // page can render "You have been invited to <Zone>". Resolved from
    // ZONE_CONFIG at read time; falls back to the raw id if config is missing.
    let (zone_id, zone_display_name) = match row.zone_id.as_deref() {
        Some(zid) => {
            let zone_config = env.var("ZONE_CONFIG").ok().map(|v| v.to_string());
            let display = resolve_zone(zone_config.as_deref(), zid)
                .map(|z| z.display_name)
                .filter(|d| !d.is_empty())
                .unwrap_or_else(|| zid.to_string());
            (Some(zid.to_string()), Some(display))
        }
        None => (None, None),
    };

    json_response(
        env,
        &json!({
            "code": row.code,
            "max_uses": row.max_uses,
            "uses": row.uses,
            "expires_at": row.expires_at,
            "state": state,
            "issuer_prefix": issuer_prefix,
            "zone_id": zone_id,
            "zone_display_name": zone_display_name,
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
    origin: &str,
) -> Result<Response> {
    if !is_valid_code(code) {
        return error_json(env, "Invalid code", 400);
    }

    let url = canonical_url(origin, &format!("/api/invites/{code}/redeem"));
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
            "SELECT id, code, issued_by, max_uses, uses, expires_at, revoked_at, revoked_by, created_at, zone_id \
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

    // Zone-bound invite: additionally grant the zone's required_cohorts to the
    // redeemer's whitelist row (cohorts resolved from ZONE_CONFIG at redeem
    // time, never frozen into the invite). Best-effort — a grant failure does
    // not fail the redemption.
    let mut granted_cohorts: Vec<String> = Vec::new();
    if let Some(zid) = row.zone_id.as_deref() {
        let zone_config = env.var("ZONE_CONFIG").ok().map(|v| v.to_string());
        if let Some(zone) = resolve_zone(zone_config.as_deref(), zid) {
            grant_zone_cohorts(env, &redeemer, &zone.required_cohorts).await;
            granted_cohorts = zone.required_cohorts;
        }
    }

    json_response(
        env,
        &json!({
            "ok": true,
            "invitation_id": row.id,
            "issuer": row.issued_by,
            "joined_at": now,
            "zone_id": row.zone_id,
            "granted_cohorts": granted_cohorts,
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
    origin: &str,
) -> Result<Response> {
    if !is_valid_code(invite_id) {
        return error_json(env, "Invalid invite id", 400);
    }

    let url = canonical_url(origin, &format!("/api/invites/{invite_id}/revoke"));
    let caller = match require_authed(auth_header, &url, "POST", Some(body_bytes), env).await {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return error_json(env, "Database unavailable", 500),
    };

    let row = db
        .prepare("SELECT id, code, issued_by, max_uses, uses, expires_at, revoked_at, revoked_by, created_at, zone_id FROM invitations WHERE id = ?1")
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
            "SELECT id, code, issued_by, max_uses, uses, expires_at, revoked_at, revoked_by, created_at, zone_id \
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

    // Zone-bound invite consumed at WebAuthn registration: grant the zone's
    // required_cohorts (resolved from ZONE_CONFIG) on the whitelist, mirroring
    // the /redeem path so both invite-consumption routes are consistent.
    if let Some(zid) = row.zone_id.as_deref() {
        let zone_config = env.var("ZONE_CONFIG").ok().map(|v| v.to_string());
        if let Some(zone) = resolve_zone(zone_config.as_deref(), zid) {
            grant_zone_cohorts(env, redeemer, &zone.required_cohorts).await;
        }
    }

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
            zone_id: None,
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
            zone_id: None,
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
            zone_id: None,
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
            zone_id: None,
        };
        assert_eq!(classify(&r, 100), "revoked");
    }

    #[test]
    fn create_body_defaults_empty() {
        let body: CreateBody = serde_json::from_str("{}").unwrap();
        assert!(body.max_uses.is_none());
        assert!(body.zone_id.is_none());
    }

    #[test]
    fn create_body_parses_zone_id() {
        let body: CreateBody = serde_json::from_str(r#"{"zone_id":"zone2"}"#).unwrap();
        assert_eq!(body.zone_id.as_deref(), Some("zone2"));
    }

    // --- ZONE_CONFIG fixture mirrors the deployed dreamlab projection -------
    const ZC: &str = r#"[
        {"id":"zone1","slug":"welcome","display_name":"Welcome","required_cohorts":[],"visibility":"public"},
        {"id":"zone2","slug":"minimoonoir","display_name":"Minimoonoir","required_cohorts":["zone2"],"visibility":"locked"},
        {"id":"zone3","slug":"family","display_name":"Family","required_cohorts":["zone3"],"visibility":"locked"},
        {"id":"zone4","slug":"dreamlab","display_name":"DreamLab","required_cohorts":["zone4"],"visibility":"locked"}
    ]"#;

    #[test]
    fn resolve_zone_finds_locked_zone_and_cohorts() {
        let z = resolve_zone(Some(ZC), "zone3").expect("zone3 exists");
        assert_eq!(z.id, "zone3");
        assert_eq!(z.display_name, "Family");
        assert_eq!(z.required_cohorts, vec!["zone3".to_string()]);
    }

    #[test]
    fn resolve_zone_rejects_unknown_zone() {
        assert!(resolve_zone(Some(ZC), "zone9").is_none());
        assert!(resolve_zone(Some(ZC), "").is_none());
    }

    #[test]
    fn resolve_zone_handles_absent_or_malformed_config() {
        assert!(resolve_zone(None, "zone2").is_none());
        assert!(resolve_zone(Some("not json"), "zone2").is_none());
    }

    #[test]
    fn resolve_zone_public_zone_has_empty_cohorts() {
        let z = resolve_zone(Some(ZC), "zone1").expect("zone1 exists");
        assert!(z.required_cohorts.is_empty());
    }

    #[test]
    fn merge_cohorts_dedups_and_preserves_existing() {
        // Existing member with zone2 already; grant zone3 → both kept, no dupes.
        let merged = merge_cohorts_json(
            r#"["members","zone2"]"#,
            &["zone3".to_string(), "zone2".to_string()],
        );
        let parsed: Vec<String> = serde_json::from_str(&merged).unwrap();
        assert_eq!(parsed, vec!["members", "zone2", "zone3"]);
    }

    #[test]
    fn merge_cohorts_into_members_only_row() {
        let merged = merge_cohorts_json(r#"["members"]"#, &["zone4".to_string()]);
        let parsed: Vec<String> = serde_json::from_str(&merged).unwrap();
        assert_eq!(parsed, vec!["members", "zone4"]);
    }

    #[test]
    fn merge_cohorts_empty_grant_is_noop() {
        let merged = merge_cohorts_json(r#"["members","zone2"]"#, &[]);
        let parsed: Vec<String> = serde_json::from_str(&merged).unwrap();
        assert_eq!(parsed, vec!["members", "zone2"]);
    }

    #[test]
    fn merge_cohorts_tolerates_malformed_existing() {
        // Malformed existing value → treated as empty set so the grant still lands.
        let merged = merge_cohorts_json("garbage", &["zone2".to_string()]);
        let parsed: Vec<String> = serde_json::from_str(&merged).unwrap();
        assert_eq!(parsed, vec!["zone2"]);
    }
}
