//! Agent Control Surface governance API.
//!
//! Endpoints (all NIP-98 gated):
//!
//! | Method | Path                             | Gate  | Purpose                              |
//! |--------|----------------------------------|-------|--------------------------------------|
//! | GET    | /api/governance/agents           | any   | List registered agents               |
//! | POST   | /api/governance/agents/register  | admin | Register an agent pubkey             |
//! | POST   | /api/governance/agents/provision | admin | Whitelist + register in one op (ADR-097) |
//! | POST   | /api/governance/agents/revoke    | admin | Deactivate an agent                  |
//! | GET    | /api/governance/cases           | any   | List broker cases (optional ?state=)  |
//! | GET    | /api/governance/cases/:id       | any   | Get a single broker case             |
//! | POST   | /api/governance/roles/grant     | admin | Grant a broker role to a pubkey      |
//! | POST   | /api/governance/roles/revoke    | admin | Revoke a broker role from a pubkey   |
//! | GET    | /api/governance/roles           | any   | List broker role assignments         |

use serde::Deserialize;
use serde_json::json;
use wasm_bindgen::JsValue;
use worker::{Env, Response, Result};

use crate::admin::{canonical_url, now_secs, require_admin, require_authed};
use crate::http::{error_json, json_response};

/// Governance tables (agent_registry, broker_cases, broker_decisions,
/// broker_roles) live in the relay worker's D1 (`dreamlab-relay`), bound
/// as `RELAY_DB` in this worker. The relay DO reads these tables when
/// gating governance event kinds (31400-31405).
fn relay_db(env: &Env) -> Result<worker::D1Database> {
    env.d1("RELAY_DB")
}

// ── Request bodies ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterAgentBody {
    pubkey: String,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default = "default_rate_limit")]
    rate_limit_per_min: u32,
}

fn default_rate_limit() -> u32 {
    60
}

/// Consolidated agent-provisioning request (ADR-097).
///
/// One admin-authenticated body that drives BOTH the membership/cohort
/// allowlist write and the `agent_registry` upsert. The agent's own kind-0 +
/// NIP-65 events stay client-side — the caller signs those with the agent key;
/// this endpoint never sees the agent privkey.
#[derive(Deserialize)]
struct ProvisionAgentBody {
    pubkey: String,
    name: String,
    #[serde(default)]
    description: String,
    cohorts: Vec<String>,
    #[serde(default = "default_rate_limit")]
    rate_limit_per_min: u32,
}

/// Normalised, validated provisioning parameters. Splitting validation out of
/// the env-bound handler keeps it unit-testable without a D1 binding (ADR-097).
#[cfg_attr(test, derive(Debug))]
struct NormalizedProvision {
    pubkey: String,
    name: String,
    description: String,
    cohorts: Vec<String>,
    rate_limit_per_min: u32,
}

/// Pure validation/normalisation for [`ProvisionAgentBody`].
///
/// Rules:
/// - `pubkey` must be exactly 64 ASCII hex chars (BIP-340 x-only, lowercased).
/// - `name` must be non-empty after trimming.
/// - `cohorts` must be non-empty (provisioning without a cohort is a no-op
///   allowlist write and almost always a caller bug).
fn normalize_provision(
    body: ProvisionAgentBody,
) -> std::result::Result<NormalizedProvision, &'static str> {
    if body.pubkey.len() != 64 || !body.pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid pubkey: must be 64 hex chars");
    }
    if body.name.trim().is_empty() {
        return Err("name is required");
    }
    if body.cohorts.is_empty() {
        return Err("cohorts is required and must be non-empty");
    }
    Ok(NormalizedProvision {
        pubkey: body.pubkey.to_ascii_lowercase(),
        name: body.name,
        description: body.description,
        cohorts: body.cohorts,
        rate_limit_per_min: body.rate_limit_per_min,
    })
}

#[derive(Deserialize)]
struct RevokeAgentBody {
    pubkey: String,
}

#[derive(Deserialize)]
struct GrantRoleBody {
    pubkey: String,
    role: String,
}

#[derive(Deserialize)]
struct RevokeRoleBody {
    pubkey: String,
    role: String,
}

// ── D1 row types ────────────────────────────────────────────────────────────

#[derive(Deserialize, serde::Serialize)]
struct AgentRow {
    pubkey: String,
    name: String,
    description: String,
    registered_by: String,
    registered_at: f64,
    rate_limit_per_min: f64,
    active: f64,
}

#[derive(Deserialize, serde::Serialize)]
struct CaseRow {
    id: String,
    category: String,
    subject_kind: String,
    subject_id: String,
    title: String,
    summary: String,
    state: String,
    priority: f64,
    created_by: String,
    assigned_to: Option<String>,
    nostr_event_id: Option<String>,
    created_at: f64,
    updated_at: f64,
}

#[derive(Deserialize, serde::Serialize)]
struct RoleRow {
    pubkey: String,
    role: String,
    granted_by: String,
    granted_at: f64,
}

// ── Handlers ────────────────────────────────────────────────────────────────

pub async fn handle_list_agents(
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/governance/agents");
    if let Err((body, status)) = require_authed(auth_header, &url, "GET", None, env).await {
        return json_response(env, &body, status);
    }

    let db = relay_db(env)?;
    let result = db
        .prepare("SELECT * FROM agent_registry ORDER BY name")
        .all()
        .await?;
    let rows = result.results::<AgentRow>()?;

    json_response(env, &json!({ "agents": rows }), 200)
}

pub async fn handle_register_agent(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/governance/agents/register");
    let admin_pk = match require_admin(auth_header, &url, "POST", Some(body_bytes), env).await {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let body: RegisterAgentBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("bad body: {e}"), 400),
    };

    if body.pubkey.len() != 64 || !body.pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return error_json(env, "invalid pubkey: must be 64 hex chars", 400);
    }
    if body.name.trim().is_empty() {
        return error_json(env, "name is required", 400);
    }

    let db = relay_db(env)?;
    let now = now_secs();

    db.prepare(
        "INSERT OR REPLACE INTO agent_registry \
         (pubkey, name, description, registered_by, registered_at, rate_limit_per_min, active) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
    )
    .bind(&[
        JsValue::from_str(&body.pubkey),
        JsValue::from_str(&body.name),
        JsValue::from_str(&body.description),
        JsValue::from_str(&admin_pk),
        JsValue::from_f64(now as f64),
        JsValue::from_f64(body.rate_limit_per_min as f64),
    ])?
    .run()
    .await?;

    json_response(
        env,
        &json!({ "ok": true, "pubkey": body.pubkey, "name": body.name }),
        201,
    )
}

/// `POST /api/governance/agents/provision` (NIP-98 admin) — ADR-097.
///
/// Consolidates the admin-side half of bot-identity provisioning into ONE
/// idempotent authenticated call. It performs, atomically against the relay
/// D1 (`RELAY_DB` — the same database that holds both `whitelist` and
/// `agent_registry`):
///
/// 1. Allowlist upsert — adds/updates the pubkey in the `whitelist` cohort
///    table with the supplied cohorts. Mirrors the relay worker's
///    `/api/whitelist/add` SQL contract (`INSERT … ON CONFLICT … DO UPDATE`),
///    so the two paths converge on identical row shapes.
/// 2. Registry upsert — `INSERT OR REPLACE` into `agent_registry`, reusing the
///    exact column set written by [`handle_register_agent`].
///
/// Because both tables live in the same physical D1, the two writes are issued
/// as a single `db.batch(...)` — D1 batches run in one implicit transaction, so
/// provisioning is all-or-nothing. No cross-worker transaction is invented.
///
/// The agent's own kind-0 profile + NIP-65 relay list stay client-side: the
/// caller signs them with the agent key. This endpoint never receives the agent
/// privkey. Composes with ADR-094 subkey derivation (agents are commonly
/// derived keys) and ADR-096 pod delegation.
///
/// Idempotent: provisioning the same pubkey twice converges to the same end
/// state (cohorts replaced, registry row replaced & re-activated).
///
/// Returns `{ pubkey, cohorts, registered: true }`.
pub async fn handle_provision_agent(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/governance/agents/provision");
    let admin_pk = match require_admin(auth_header, &url, "POST", Some(body_bytes), env).await {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let body: ProvisionAgentBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("bad body: {e}"), 400),
    };

    let p = match normalize_provision(body) {
        Ok(p) => p,
        Err(msg) => return error_json(env, msg, 400),
    };

    let cohorts_json = match serde_json::to_string(&p.cohorts) {
        Ok(s) => s,
        Err(e) => return error_json(env, &format!("cohorts encode failed: {e}"), 400),
    };

    let db = relay_db(env)?;
    let now = now_secs();

    // Allowlist write — same SQL contract as the relay worker's
    // `/api/whitelist/add` (INSERT … ON CONFLICT DO UPDATE on cohorts/added_by).
    let whitelist_stmt = db
        .prepare(
            "INSERT INTO whitelist (pubkey, cohorts, added_at, added_by) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT (pubkey) DO UPDATE SET cohorts = excluded.cohorts, added_by = excluded.added_by",
        )
        .bind(&[
            JsValue::from_str(&p.pubkey),
            JsValue::from_str(&cohorts_json),
            JsValue::from_f64(now as f64),
            JsValue::from_str(&admin_pk),
        ])?;

    // Registry write — identical column set to handle_register_agent.
    let registry_stmt = db
        .prepare(
            "INSERT OR REPLACE INTO agent_registry \
             (pubkey, name, description, registered_by, registered_at, rate_limit_per_min, active) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
        )
        .bind(&[
            JsValue::from_str(&p.pubkey),
            JsValue::from_str(&p.name),
            JsValue::from_str(&p.description),
            JsValue::from_str(&admin_pk),
            JsValue::from_f64(now as f64),
            JsValue::from_f64(p.rate_limit_per_min as f64),
        ])?;

    // Same physical D1 → atomic batch. All-or-nothing; no partial state.
    db.batch(vec![whitelist_stmt, registry_stmt]).await?;

    json_response(
        env,
        &json!({
            "pubkey": p.pubkey,
            "cohorts": p.cohorts,
            "registered": true,
        }),
        200,
    )
}

pub async fn handle_revoke_agent(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/governance/agents/revoke");
    if let Err((body, status)) =
        require_admin(auth_header, &url, "POST", Some(body_bytes), env).await
    {
        return json_response(env, &body, status);
    }

    let body: RevokeAgentBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("bad body: {e}"), 400),
    };

    let db = relay_db(env)?;
    db.prepare("UPDATE agent_registry SET active = 0 WHERE pubkey = ?1")
        .bind(&[JsValue::from_str(&body.pubkey)])?
        .run()
        .await?;

    json_response(
        env,
        &json!({ "ok": true, "pubkey": body.pubkey, "active": false }),
        200,
    )
}

pub async fn handle_list_cases(
    query: &[(String, String)],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/governance/cases");
    if let Err((body, status)) = require_authed(auth_header, &url, "GET", None, env).await {
        return json_response(env, &body, status);
    }

    let db = relay_db(env)?;
    let state_filter = query
        .iter()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.as_str());

    let result = if let Some(state) = state_filter {
        db.prepare("SELECT * FROM broker_cases WHERE state = ?1 ORDER BY updated_at DESC LIMIT 100")
            .bind(&[JsValue::from_str(state)])?
            .all()
            .await?
    } else {
        db.prepare("SELECT * FROM broker_cases ORDER BY updated_at DESC LIMIT 100")
            .all()
            .await?
    };

    let rows = result.results::<CaseRow>()?;
    json_response(env, &json!({ "cases": rows }), 200)
}

pub async fn handle_get_case(
    case_id: &str,
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, &format!("/api/governance/cases/{case_id}"));
    if let Err((body, status)) = require_authed(auth_header, &url, "GET", None, env).await {
        return json_response(env, &body, status);
    }

    let db = relay_db(env)?;
    let case = db
        .prepare("SELECT * FROM broker_cases WHERE id = ?1")
        .bind(&[JsValue::from_str(case_id)])?
        .first::<CaseRow>(None)
        .await?;

    match case {
        Some(row) => json_response(env, &json!({ "case": row }), 200),
        None => error_json(env, "case not found", 404),
    }
}

pub async fn handle_grant_role(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/governance/roles/grant");
    let admin_pk = match require_admin(auth_header, &url, "POST", Some(body_bytes), env).await {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let body: GrantRoleBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("bad body: {e}"), 400),
    };

    if body.pubkey.len() != 64 || !body.pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return error_json(env, "invalid pubkey: must be 64 hex chars", 400);
    }

    let db = relay_db(env)?;
    let now = now_secs();

    db.prepare(
        "INSERT OR REPLACE INTO broker_roles (pubkey, role, granted_by, granted_at) \
         VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(&[
        JsValue::from_str(&body.pubkey),
        JsValue::from_str(&body.role),
        JsValue::from_str(&admin_pk),
        JsValue::from_f64(now as f64),
    ])?
    .run()
    .await?;

    json_response(
        env,
        &json!({ "ok": true, "pubkey": body.pubkey, "role": body.role }),
        201,
    )
}

pub async fn handle_list_roles(
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/governance/roles");
    if let Err((body, status)) = require_authed(auth_header, &url, "GET", None, env).await {
        return json_response(env, &body, status);
    }

    let db = relay_db(env)?;
    let result = db
        .prepare("SELECT * FROM broker_roles ORDER BY pubkey, role")
        .all()
        .await?;
    let rows = result.results::<RoleRow>()?;

    json_response(env, &json!({ "roles": rows }), 200)
}

pub async fn handle_revoke_role(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/governance/roles/revoke");
    if let Err((body, status)) =
        require_admin(auth_header, &url, "POST", Some(body_bytes), env).await
    {
        return json_response(env, &body, status);
    }

    let body: RevokeRoleBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("bad body: {e}"), 400),
    };

    let db = relay_db(env)?;
    db.prepare("DELETE FROM broker_roles WHERE pubkey = ?1 AND role = ?2")
        .bind(&[
            JsValue::from_str(&body.pubkey),
            JsValue::from_str(&body.role),
        ])?
        .run()
        .await?;

    json_response(
        env,
        &json!({ "ok": true, "pubkey": body.pubkey, "role": body.role, "revoked": true }),
        200,
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────
//
// These cover the pure request-body parsing + validation/normalisation for the
// consolidated provisioning operation (ADR-097). The handler itself is Env/D1
// bound (it needs the `RELAY_DB` binding to write `whitelist` + `agent_registry`
// atomically via `db.batch`), so its dispatch + atomic-write path is integration
// /env-bound and exercised end-to-end in the worker deploy, not in unit tests.
// Admin-auth gating is shared with the existing `/register` route via
// `require_admin` — the same gate is unit-tested for that path's helpers.
#[cfg(test)]
mod tests {
    use super::*;

    fn good_pubkey() -> String {
        "a".repeat(64)
    }

    fn body_json(cohorts: &str) -> String {
        format!(
            r#"{{"pubkey":"{}","name":"scribe-bot","description":"d","cohorts":{}}}"#,
            good_pubkey(),
            cohorts
        )
    }

    #[test]
    fn parses_valid_provision_body() {
        let raw = body_json(r#"["ai-agents","members"]"#);
        let body: ProvisionAgentBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        let p = normalize_provision(body).expect("valid body normalises");
        assert_eq!(p.pubkey, good_pubkey());
        assert_eq!(p.name, "scribe-bot");
        assert_eq!(
            p.cohorts,
            vec!["ai-agents".to_string(), "members".to_string()]
        );
        // rate_limit defaults when omitted.
        assert_eq!(p.rate_limit_per_min, 60);
    }

    #[test]
    fn rate_limit_override_is_honoured() {
        let raw = format!(
            r#"{{"pubkey":"{}","name":"n","cohorts":["agent"],"rate_limit_per_min":5}}"#,
            good_pubkey()
        );
        let body: ProvisionAgentBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        let p = normalize_provision(body).unwrap();
        assert_eq!(p.rate_limit_per_min, 5);
    }

    #[test]
    fn rejects_bad_pubkey_wrong_length() {
        let raw = format!(
            r#"{{"pubkey":"{}","name":"n","cohorts":["agent"]}}"#,
            "a".repeat(63)
        );
        let body: ProvisionAgentBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        assert!(normalize_provision(body).is_err());
    }

    #[test]
    fn rejects_bad_pubkey_non_hex() {
        let raw = format!(
            r#"{{"pubkey":"{}","name":"n","cohorts":["agent"]}}"#,
            "g".repeat(64)
        );
        let body: ProvisionAgentBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        assert!(normalize_provision(body).is_err());
    }

    #[test]
    fn rejects_empty_name() {
        let raw = format!(
            r#"{{"pubkey":"{}","name":"   ","cohorts":["agent"]}}"#,
            good_pubkey()
        );
        let body: ProvisionAgentBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        assert!(normalize_provision(body).is_err());
    }

    #[test]
    fn rejects_empty_cohorts() {
        let raw = body_json("[]");
        let body: ProvisionAgentBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        let err = normalize_provision(body).unwrap_err();
        assert!(err.contains("cohorts"));
    }

    #[test]
    fn missing_cohorts_field_fails_to_parse() {
        // cohorts has no serde default → required field; missing => parse error.
        let raw = format!(r#"{{"pubkey":"{}","name":"n"}}"#, good_pubkey());
        let parsed: std::result::Result<ProvisionAgentBody, _> =
            serde_json::from_slice(raw.as_bytes());
        assert!(parsed.is_err());
    }

    #[test]
    fn pubkey_is_lowercased_for_idempotent_keying() {
        // Upper-case hex is valid hex; normalisation lowercases so a re-provision
        // with differing case converges to the same primary-key row.
        let raw = format!(
            r#"{{"pubkey":"{}","name":"n","cohorts":["agent"]}}"#,
            "A".repeat(64)
        );
        let body: ProvisionAgentBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        let p = normalize_provision(body).unwrap();
        assert_eq!(p.pubkey, "a".repeat(64));
    }

    #[test]
    fn idempotent_normalisation_is_stable() {
        // Provisioning twice with the same input yields identical normalised
        // params → identical SQL binds → identical end state (PK-keyed upserts).
        let raw = body_json(r#"["agent"]"#);
        let p1 = normalize_provision(serde_json::from_slice(raw.as_bytes()).unwrap()).unwrap();
        let p2 = normalize_provision(serde_json::from_slice(raw.as_bytes()).unwrap()).unwrap();
        assert_eq!(p1.pubkey, p2.pubkey);
        assert_eq!(p1.cohorts, p2.cohorts);
        assert_eq!(p1.name, p2.name);
        assert_eq!(p1.rate_limit_per_min, p2.rate_limit_per_min);
    }
}
