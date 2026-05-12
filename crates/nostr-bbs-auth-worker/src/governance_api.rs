//! Agent Control Surface governance API.
//!
//! Endpoints (all NIP-98 gated):
//!
//! | Method | Path                            | Gate  | Purpose                              |
//! |--------|---------------------------------|-------|--------------------------------------|
//! | GET    | /api/governance/agents          | any   | List registered agents               |
//! | POST   | /api/governance/agents/register | admin | Register an agent pubkey             |
//! | POST   | /api/governance/agents/revoke   | admin | Deactivate an agent                  |
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

pub async fn handle_list_agents(auth_header: Option<&str>, env: &Env) -> Result<Response> {
    let url = canonical_url(env, "/api/governance/agents");
    if let Err((body, status)) = require_authed(auth_header, &url, "GET", None, env).await {
        return json_response(env, &body, status);
    }

    let db = env.d1("DB")?;
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
) -> Result<Response> {
    let url = canonical_url(env, "/api/governance/agents/register");
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

    let db = env.d1("DB")?;
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

pub async fn handle_revoke_agent(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
) -> Result<Response> {
    let url = canonical_url(env, "/api/governance/agents/revoke");
    if let Err((body, status)) =
        require_admin(auth_header, &url, "POST", Some(body_bytes), env).await
    {
        return json_response(env, &body, status);
    }

    let body: RevokeAgentBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("bad body: {e}"), 400),
    };

    let db = env.d1("DB")?;
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
) -> Result<Response> {
    let url = canonical_url(env, "/api/governance/cases");
    if let Err((body, status)) = require_authed(auth_header, &url, "GET", None, env).await {
        return json_response(env, &body, status);
    }

    let db = env.d1("DB")?;
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
) -> Result<Response> {
    let url = canonical_url(env, &format!("/api/governance/cases/{case_id}"));
    if let Err((body, status)) = require_authed(auth_header, &url, "GET", None, env).await {
        return json_response(env, &body, status);
    }

    let db = env.d1("DB")?;
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
) -> Result<Response> {
    let url = canonical_url(env, "/api/governance/roles/grant");
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

    let db = env.d1("DB")?;
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

pub async fn handle_list_roles(auth_header: Option<&str>, env: &Env) -> Result<Response> {
    let url = canonical_url(env, "/api/governance/roles");
    if let Err((body, status)) = require_authed(auth_header, &url, "GET", None, env).await {
        return json_response(env, &body, status);
    }

    let db = env.d1("DB")?;
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
) -> Result<Response> {
    let url = canonical_url(env, "/api/governance/roles/revoke");
    if let Err((body, status)) =
        require_admin(auth_header, &url, "POST", Some(body_bytes), env).await
    {
        return json_response(env, &body, status);
    }

    let body: RevokeRoleBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("bad body: {e}"), 400),
    };

    let db = env.d1("DB")?;
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
