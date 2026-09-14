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
//! | GET    | /api/governance/decisions       | any   | List broker decisions (?case_id=, paged) |
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
/// broker_roles) live in the relay worker's D1 (`nostr-bbs-relay`), bound
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

/// Shared pubkey/name validation for both the register and provision paths.
///
/// - `pubkey` must be exactly 64 ASCII hex chars (BIP-340 x-only).
/// - `name` must be non-empty after trimming.
///
/// Returns `Ok(())` so callers keep ownership of the body and decide their own
/// normalisation (register stores the pubkey as supplied; provision lowercases).
fn validate_agent_fields(pubkey: &str, name: &str) -> std::result::Result<(), &'static str> {
    if pubkey.len() != 64 || !pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid pubkey: must be 64 hex chars");
    }
    if name.trim().is_empty() {
        return Err("name is required");
    }
    Ok(())
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
    validate_agent_fields(&body.pubkey, &body.name)?;
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

/// One `broker_cases` row as the REST surface sees it.
///
/// `Deserialize` only: the wire shape goes through [`case_json`], because the
/// probe digest must not be re-served on an undecided case (DDD §6 invariant 7)
/// and a struct that serialises itself has no seam to enforce that at.
#[derive(Deserialize)]
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
    /// ADR-2011: the tier that governs this case. Absent on cases projected
    /// before migration 0006.
    #[serde(default)]
    effective_tier: Option<String>,
    /// The requesting agent's own declaration. Telemetry: declared-vs-effective
    /// divergence is how a habitually under-tiering agent becomes visible.
    #[serde(default)]
    declared_tier: Option<String>,
    #[serde(default)]
    tp_verifiability: Option<String>,
    #[serde(default)]
    tp_reversibility: Option<String>,
    #[serde(default)]
    tp_stakes: Option<String>,
    #[serde(default)]
    calibration_sample: Option<f64>,
    #[serde(default)]
    max_pending_hours: Option<f64>,
    /// Never serialised directly — see [`case_json`].
    #[serde(default)]
    probe_digest: Option<String>,
}

/// Whether a case has been decided, and so whether its probe may be revealed.
///
/// The legacy `resolved`/`rejected` strings the pre-orchestrator projection
/// wrote are decisions too (`CaseState::parse` treats them as `Decided`), so
/// they reveal as well — otherwise an old probe would stay hidden forever.
pub(crate) fn case_is_decided(state: &str) -> bool {
    matches!(
        state,
        "decided" | "resolved" | "rejected" | "superseded" | "closed" | "promoted" | "precedent"
    )
}

/// The probe digest as it may be served for a case in `state`.
///
/// DDD §6 invariant 7 — "probes are blind until decided": a reviewer who can
/// see that a request is a seeded probe is not being tested, they are being
/// told the answer, and the catch rate becomes meaningless. So the digest is
/// withheld from every projection of an undecided case and revealed once the
/// 31403 exists, which is when it becomes audit evidence instead of a hint.
pub(crate) fn redact_probe<'a>(state: &str, probe_digest: Option<&'a str>) -> Option<&'a str> {
    probe_digest.filter(|_| case_is_decided(state))
}

/// The wire shape of a case, with the probe redacted where it must be.
fn case_json(row: &CaseRow) -> serde_json::Value {
    json!({
        "id": row.id,
        "category": row.category,
        "subject_kind": row.subject_kind,
        "subject_id": row.subject_id,
        "title": row.title,
        "summary": row.summary,
        "state": row.state,
        "priority": row.priority,
        "created_by": row.created_by,
        "assigned_to": row.assigned_to,
        "nostr_event_id": row.nostr_event_id,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "effective_tier": row.effective_tier,
        "declared_tier": row.declared_tier,
        "task_properties": row.tp_verifiability.as_ref().map(|v| json!({
            "verifiability": v,
            "reversibility": row.tp_reversibility,
            "stakes": row.tp_stakes,
        })),
        "calibration_sample": row.calibration_sample.unwrap_or(0.0) >= 1.0,
        "max_pending_hours": row.max_pending_hours,
        "probe": redact_probe(&row.state, row.probe_digest.as_deref()),
    })
}

#[derive(Deserialize, serde::Serialize)]
struct RoleRow {
    pubkey: String,
    role: String,
    granted_by: String,
    granted_at: f64,
}

/// One `broker_decisions` row (COM-17 / F5). Carries the full audit shape,
/// including the non-binary `outcome_detail` (delegate target / pattern / scope
/// / diff), the `prior_decision_id` provenance link written by the relay's
/// orchestrator projection, and the F6 `superseded_by` marker (DDD §7a): the
/// decision id that supersedes this row, or `None` when this is the current
/// effective decision. Exposing it lets a decisions-API consumer render the
/// supersession chain without a second query.
#[derive(Deserialize, serde::Serialize)]
struct DecisionRow {
    decision_id: String,
    case_id: String,
    outcome: String,
    outcome_detail: Option<String>,
    broker_pubkey: String,
    reasoning: String,
    prior_decision_id: Option<String>,
    #[serde(default)]
    superseded_by: Option<String>,
    decided_at: f64,
}

/// Normalised pagination + filter for the decisions read API (COM-17 / F5).
#[cfg_attr(test, derive(Debug, PartialEq))]
struct DecisionsQuery {
    case_id: Option<String>,
    limit: u32,
    offset: u32,
}

const DECISIONS_DEFAULT_LIMIT: u32 = 100;
const DECISIONS_MAX_LIMIT: u32 = 200;

/// Pure query-string parser for `GET /api/governance/decisions`.
///
/// - `case_id` — optional exact-match filter (empty string is treated as absent).
/// - `limit` — page size, clamped to `1..=DECISIONS_MAX_LIMIT`, default 100.
/// - `offset` — page offset, default 0.
///
/// Split out so the pagination/clamp contract is unit-testable without a D1
/// binding (the handler itself is Env-bound), mirroring `normalize_provision`.
fn parse_decisions_query(query: &[(String, String)]) -> DecisionsQuery {
    let case_id = query
        .iter()
        .find(|(k, _)| k == "case_id")
        .map(|(_, v)| v.clone())
        .filter(|s| !s.is_empty());
    let limit = query
        .iter()
        .find(|(k, _)| k == "limit")
        .and_then(|(_, v)| v.parse::<u32>().ok())
        .unwrap_or(DECISIONS_DEFAULT_LIMIT)
        .clamp(1, DECISIONS_MAX_LIMIT);
    let offset = query
        .iter()
        .find(|(k, _)| k == "offset")
        .and_then(|(_, v)| v.parse::<u32>().ok())
        .unwrap_or(0);
    DecisionsQuery {
        case_id,
        limit,
        offset,
    }
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

    if let Err(msg) = validate_agent_fields(&body.pubkey, &body.name) {
        return error_json(env, msg, 400);
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
    let cases: Vec<serde_json::Value> = rows.iter().map(case_json).collect();
    json_response(env, &json!({ "cases": cases }), 200)
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
        Some(row) => json_response(env, &json!({ "case": case_json(&row) }), 200),
        None => error_json(env, "case not found", 404),
    }
}

/// `GET /api/governance/decisions` (NIP-98 authed) — COM-17 / F5.
///
/// The read side over `broker_decisions`: the append-only audit trail the
/// relay's orchestrator projection writes. Mirrors `handle_list_cases` (same
/// `require_authed` gate, same `relay_db` binding, newest-first), adding
/// pagination (`?limit=`, `?offset=`) and an optional `?case_id=` filter so an
/// operator can page a case's decision history. Returns each row's `outcome`,
/// `outcome_detail`, `reasoning` and `prior_decision_id`.
pub async fn handle_list_decisions(
    query: &[(String, String)],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/governance/decisions");
    if let Err((body, status)) = require_authed(auth_header, &url, "GET", None, env).await {
        return json_response(env, &body, status);
    }

    let q = parse_decisions_query(query);
    let db = relay_db(env)?;

    let result = if let Some(case_id) = &q.case_id {
        db.prepare(
            "SELECT * FROM broker_decisions WHERE case_id = ?1 \
             ORDER BY decided_at DESC LIMIT ?2 OFFSET ?3",
        )
        .bind(&[
            JsValue::from_str(case_id),
            JsValue::from_f64(q.limit as f64),
            JsValue::from_f64(q.offset as f64),
        ])?
        .all()
        .await?
    } else {
        db.prepare("SELECT * FROM broker_decisions ORDER BY decided_at DESC LIMIT ?1 OFFSET ?2")
            .bind(&[
                JsValue::from_f64(q.limit as f64),
                JsValue::from_f64(q.offset as f64),
            ])?
            .all()
            .await?
    };

    let rows = result.results::<DecisionRow>()?;
    json_response(
        env,
        &json!({ "decisions": rows, "limit": q.limit, "offset": q.offset }),
        200,
    )
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

    // ---- COM-17 / F5: decisions read-API pagination (pure parser) ----

    fn q(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn decisions_query_defaults_when_empty() {
        let parsed = parse_decisions_query(&q(&[]));
        assert_eq!(
            parsed,
            DecisionsQuery {
                case_id: None,
                limit: DECISIONS_DEFAULT_LIMIT,
                offset: 0,
            }
        );
    }

    #[test]
    fn decisions_query_reads_case_id_limit_offset() {
        let parsed = parse_decisions_query(&q(&[
            ("case_id", "case-42"),
            ("limit", "25"),
            ("offset", "50"),
        ]));
        assert_eq!(parsed.case_id.as_deref(), Some("case-42"));
        assert_eq!(parsed.limit, 25);
        assert_eq!(parsed.offset, 50);
    }

    #[test]
    fn decisions_query_clamps_limit_and_ignores_junk() {
        // Over-max clamps down; zero clamps up to 1; non-numeric falls back.
        assert_eq!(
            parse_decisions_query(&q(&[("limit", "9999")])).limit,
            DECISIONS_MAX_LIMIT
        );
        assert_eq!(parse_decisions_query(&q(&[("limit", "0")])).limit, 1);
        assert_eq!(
            parse_decisions_query(&q(&[("limit", "abc")])).limit,
            DECISIONS_DEFAULT_LIMIT
        );
        // Empty case_id is treated as absent (no filter).
        assert_eq!(parse_decisions_query(&q(&[("case_id", "")])).case_id, None);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FR4.1 — application receipts: closing the loop for the human who approved
// ═══════════════════════════════════════════════════════════════════════════

use nostr_bbs_core::governance::{can_advance_stage, ReceiptStage, StageAdvanceError};

/// `POST /api/governance/receipts/{response_event_id}/application` body.
#[derive(Deserialize)]
struct ApplicationBody {
    /// One of `consumer-received | applied | not-applied | applied-manually`.
    stage: String,
    /// The mutation owner's own words about what happened. Optional, and never
    /// synthesised: absence renders as absence (PRD non-functional rule 1).
    #[serde(default)]
    acknowledgement: Option<String>,
}

/// Why an application-stage advance was refused, and with what HTTP status.
///
/// Separated from the handler so the whole decision — who may report which
/// stage, against which case state, from which current stage — is a pure
/// function under test rather than a tangle of early returns around a D1 call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApplicationRefusal {
    /// The body named something that is not an application stage.
    UnknownStage,
    /// The caller is neither a registered agent nor an admin.
    NotAuthorised,
    /// `applied-manually` is an admin-only act (FR7.2).
    ManualRequiresAdmin,
    /// `applied-manually` presupposes a prior `Approve` (DDD §6 invariant 4).
    ManualRequiresApprovedCase,
    /// The ladder would move backwards or repeat (DDD §6 invariant 5).
    Regression(StageAdvanceError),
}

impl ApplicationRefusal {
    pub(crate) fn status(&self) -> u16 {
        match self {
            Self::UnknownStage => 400,
            Self::NotAuthorised | Self::ManualRequiresAdmin => 403,
            // A regression and a not-yet-approved case are both conflicts with
            // durable state, not authentication problems: 409, so a retrying
            // client can tell "you may not" from "not in that order".
            Self::ManualRequiresApprovedCase | Self::Regression(_) => 409,
        }
    }

    pub(crate) fn message(&self) -> String {
        match self {
            Self::UnknownStage => {
                "stage must be one of consumer-received, applied, not-applied, applied-manually"
                    .to_string()
            }
            Self::NotAuthorised => {
                "only a registered agent or an admin may report an application stage".to_string()
            }
            Self::ManualRequiresAdmin => {
                "applied-manually may only be reported by an admin".to_string()
            }
            Self::ManualRequiresApprovedCase => {
                "applied-manually requires a case already decided Approve".to_string()
            }
            Self::Regression(e) => format!("receipt stage would not advance: {e}"),
        }
    }
}

/// Who is asking, as far as this endpoint cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApplicationCaller {
    pub is_admin: bool,
    pub is_registered_agent: bool,
}

/// Decide whether one application-stage advance is permitted (FR4.1, FR7.2).
///
/// Pure over every input the decision depends on:
///
/// - `current` — the receipt's stage now.
/// - `requested` — the stage the caller wants to record.
/// - `caller` — admin and registered-agent flags, resolved from NIP-98.
/// - `case_state` / `latest_outcome` — the case's own row, needed only for the
///   `applied-manually` precondition.
///
/// The ordering of the checks is deliberate: authority first, then the
/// manual-continuation precondition, then monotonicity. A caller who may not
/// speak at all is told that, rather than being told their stage is out of
/// order — which would leak the receipt's state to an unauthorised caller.
pub(crate) fn plan_application_advance(
    current: ReceiptStage,
    requested: ReceiptStage,
    caller: ApplicationCaller,
    case_state: &str,
    latest_outcome: Option<&str>,
) -> std::result::Result<(), ApplicationRefusal> {
    if !requested.is_application_stage() {
        return Err(ApplicationRefusal::UnknownStage);
    }
    if !caller.is_admin && !caller.is_registered_agent {
        return Err(ApplicationRefusal::NotAuthorised);
    }
    if requested == ReceiptStage::AppliedManually {
        if !caller.is_admin {
            return Err(ApplicationRefusal::ManualRequiresAdmin);
        }
        // EXP-AC-007 counter-example: never for a rejected or still-open case.
        // A manual continuation *continues* something a human already approved;
        // anything else is a fresh decision wearing a receipt's clothes.
        let decided = matches!(case_state, "decided" | "resolved");
        if !decided || latest_outcome != Some("approve") {
            return Err(ApplicationRefusal::ManualRequiresApprovedCase);
        }
    }
    can_advance_stage(current, requested).map_err(ApplicationRefusal::Regression)
}

/// Whether `pubkey` is an active row in the relay's `agent_registry`.
async fn is_registered_agent(env: &Env, pubkey: &str) -> Result<bool> {
    #[derive(Deserialize)]
    struct ActiveRow {
        active: f64,
    }
    let found = relay_db(env)?
        .prepare("SELECT active FROM agent_registry WHERE pubkey = ?1 LIMIT 1")
        .bind(&[JsValue::from_str(pubkey)])?
        .first::<ActiveRow>(None)
        .await?;
    Ok(found.map(|r| r.active >= 1.0).unwrap_or(false))
}

/// `POST /api/governance/receipts/{response_event_id}/application` (NIP-98).
///
/// The mutation owner tells the forum what actually happened to a decision it
/// took delivery of. Until this endpoint existed, a human who approved
/// something learned only that the relay had stored their signature — the
/// approval could fail to apply and look identical to one that worked. That is
/// the gap FR4.1 closes: `consumer-received` says the owner has it, and exactly
/// one of `applied | not-applied | applied-manually` says what became of it.
///
/// Authority: a registered agent may report the first three; `applied-manually`
/// is admin-only and additionally requires a case already decided `Approve`
/// (FR7.2). Monotonic: a regression is 409 and leaves the row untouched.
pub async fn handle_receipt_application(
    response_event_id: &str,
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let path = format!("/api/governance/receipts/{response_event_id}/application");
    let url = canonical_url(origin, &path);
    let caller_pubkey = match require_authed(auth_header, &url, "POST", Some(body_bytes), env).await
    {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let body: ApplicationBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("bad body: {e}"), 400),
    };
    let Some(requested) = ReceiptStage::parse(&body.stage) else {
        let refusal = ApplicationRefusal::UnknownStage;
        return error_json(env, &refusal.message(), refusal.status());
    };

    let db = relay_db(env)?;

    #[derive(Deserialize)]
    struct ReceiptStageRow {
        stage: String,
        case_id: String,
    }
    let Some(receipt) = db
        .prepare("SELECT stage, case_id FROM governance_receipts WHERE event_id = ?1 LIMIT 1")
        .bind(&[JsValue::from_str(response_event_id)])?
        .first::<ReceiptStageRow>(None)
        .await?
    else {
        return error_json(env, "receipt not found", 404);
    };
    let Some(current) = ReceiptStage::parse(&receipt.stage) else {
        return error_json(env, "receipt carries an unknown stage", 500);
    };

    #[derive(Deserialize)]
    struct CaseOutcomeRow {
        state: String,
        outcome: Option<String>,
    }
    let case = db
        .prepare(
            "SELECT c.state AS state, \
             (SELECT d.outcome FROM broker_decisions d WHERE d.case_id = c.id \
              ORDER BY d.decided_at DESC, d.decision_id DESC LIMIT 1) AS outcome \
             FROM broker_cases c WHERE c.id = ?1 LIMIT 1",
        )
        .bind(&[JsValue::from_str(&receipt.case_id)])?
        .first::<CaseOutcomeRow>(None)
        .await?;

    let caller = ApplicationCaller {
        is_admin: crate::admin::is_admin(&caller_pubkey, env).await,
        is_registered_agent: is_registered_agent(env, &caller_pubkey).await.unwrap_or(false),
    };

    if let Err(refusal) = plan_application_advance(
        current,
        requested,
        caller,
        case.as_ref().map(|c| c.state.as_str()).unwrap_or(""),
        case.as_ref().and_then(|c| c.outcome.as_deref()),
    ) {
        return error_json(env, &refusal.message(), refusal.status());
    }

    // The `stage = ?5` guard makes the write a compare-and-swap: two consumers
    // racing to advance the same receipt cannot both win, and the loser sees a
    // 409 rather than silently overwriting the other's stage.
    let now = now_secs();
    let updated = db
        .prepare(
            "UPDATE governance_receipts \
             SET stage = ?1, applied_at = ?2, applied_by = ?3, acknowledgement = ?4 \
             WHERE event_id = ?5 AND stage = ?6",
        )
        .bind(&[
            JsValue::from_str(requested.as_str()),
            JsValue::from_f64(now as f64),
            JsValue::from_str(&caller_pubkey),
            match body.acknowledgement.as_deref() {
                Some(a) if !a.trim().is_empty() => JsValue::from_str(a),
                _ => JsValue::NULL,
            },
            JsValue::from_str(response_event_id),
            JsValue::from_str(current.as_str()),
        ])?
        .run()
        .await?;

    let changed = updated
        .meta()
        .ok()
        .flatten()
        .and_then(|m| m.changes)
        .unwrap_or(0);
    if changed == 0 {
        return error_json(
            env,
            "receipt stage changed concurrently; re-read and retry",
            409,
        );
    }

    json_response(
        env,
        &json!({
            "ok": true,
            "event_id": response_event_id,
            "case_id": receipt.case_id,
            "stage": requested.as_str(),
            "previous_stage": current.as_str(),
            "applied_at": now,
            "applied_by": caller_pubkey,
        }),
        200,
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// FR6.1 — reviewer telemetry: measuring the humans, not only the agents
// ═══════════════════════════════════════════════════════════════════════════

/// One decided case as the telemetry read model sees it.
///
/// Deliberately flat and owned by this module rather than being the D1 row
/// type: the aggregation below is pure over these, which is what makes the
/// whole read model testable without a database.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReviewerDecisionRow {
    pub broker_pubkey: String,
    pub decision_id: String,
    pub outcome: String,
    /// When the reviewer decided. Relay `accepted_at` where the receipt has it,
    /// else the signed `decided_at` (DDD §9 open issue 1: a skewed agent clock
    /// distorts time-to-decision, so relay time is preferred).
    pub decided_at_ms: i64,
    /// When the request arrived. Relay `accepted_at` for the 31402 where
    /// present, else the case's `created_at`.
    pub requested_at_ms: i64,
    pub calibration_sample: bool,
    pub is_probe: bool,
    pub superseded: bool,
}

/// Per-reviewer telemetry (EXP-AC-006).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub(crate) struct ReviewerStats {
    pub pubkey: String,
    pub decisions: u64,
    pub median_ttd_ms: i64,
    pub p90_ttd_ms: i64,
    /// Share of this reviewer's decisions whose outcome is not a plain
    /// `approve`. An agent that files a 31402 is asking for its action to
    /// proceed, so anything other than `approve` is the human departing from
    /// what the agent asked for. Rounded to four decimals.
    pub override_rate: f64,
    pub superseded: u64,
    /// Calibration-sampled cases in the corpus. The same for every reviewer:
    /// they share one queue, and nothing records who looked at what, so a
    /// per-reviewer "shown" would be an invention (PRD non-functional rule 1).
    pub calibration_shown: u64,
    /// Of those, the ones this reviewer decided.
    pub calibration_decided: u64,
    /// Probe cases in the corpus, on the same reasoning as `calibration_shown`.
    pub probes_seen: u64,
    /// Probes this reviewer rejected — the catch rate's numerator.
    pub probes_caught: u64,
}

/// The pth percentile of an already-sorted slice, by nearest-rank.
///
/// Nearest-rank rather than interpolation because the population is small and a
/// latency that no reviewer actually experienced is a worse answer than a real
/// one that is slightly off-centre.
fn percentile(sorted: &[i64], p: f64) -> i64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p * sorted.len() as f64).ceil() as usize).max(1);
    sorted[rank.min(sorted.len()) - 1]
}

fn median(sorted: &[i64]) -> i64 {
    if sorted.is_empty() {
        return 0;
    }
    let n = sorted.len();
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2
    }
}

/// Fold the decided-case rows into per-reviewer telemetry (FR6.1).
///
/// Pure, and the only place the definitions live: a change to what "override"
/// or "caught" means is a change here, with the tests that pin it.
pub(crate) fn aggregate_reviewers(rows: &[ReviewerDecisionRow]) -> Vec<ReviewerStats> {
    use std::collections::BTreeMap;

    // Corpus-wide denominators. Counted over distinct decisions' cases as they
    // appear here; a case decided twice contributes once per decision, which is
    // the honest reading of "how much sampled work passed through review".
    let calibration_shown = rows.iter().filter(|r| r.calibration_sample).count() as u64;
    let probes_seen = rows.iter().filter(|r| r.is_probe).count() as u64;

    let mut by_reviewer: BTreeMap<&str, Vec<&ReviewerDecisionRow>> = BTreeMap::new();
    for row in rows {
        by_reviewer
            .entry(row.broker_pubkey.as_str())
            .or_default()
            .push(row);
    }

    by_reviewer
        .into_iter()
        .map(|(pubkey, rows)| {
            let decisions = rows.len() as u64;
            let mut ttds: Vec<i64> = rows
                .iter()
                // A negative time-to-decision is a clock problem, not a
                // reviewer who answered before being asked: drop it rather than
                // let it drag the median below zero.
                .map(|r| r.decided_at_ms - r.requested_at_ms)
                .filter(|d| *d >= 0)
                .collect();
            ttds.sort_unstable();

            let overrides = rows.iter().filter(|r| r.outcome != "approve").count() as u64;
            let override_rate = if decisions == 0 {
                0.0
            } else {
                ((overrides as f64 / decisions as f64) * 10_000.0).round() / 10_000.0
            };

            ReviewerStats {
                pubkey: pubkey.to_string(),
                decisions,
                median_ttd_ms: median(&ttds),
                p90_ttd_ms: percentile(&ttds, 0.9),
                override_rate,
                superseded: rows.iter().filter(|r| r.superseded).count() as u64,
                calibration_shown,
                calibration_decided: rows.iter().filter(|r| r.calibration_sample).count() as u64,
                probes_seen,
                // A probe is a known-bad request: catching it is rejecting it.
                probes_caught: rows
                    .iter()
                    .filter(|r| r.is_probe && r.outcome == "reject")
                    .count() as u64,
            }
        })
        .collect()
}

/// `GET /api/governance/reviewers` (admin NIP-98) — FR6.1 / EXP-AC-006.
///
/// The read model over `broker_decisions × broker_cases × governance_receipts`.
/// C4 and C6 ask whether the humans doing the reviewing stay capable of it;
/// nothing in the estate could answer that before this endpoint, because
/// nothing counted their work. It is admin-gated because reviewer-level
/// telemetry is exactly the sort of thing that should not be readable by
/// everyone it measures.
pub async fn handle_list_reviewers(
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/governance/reviewers");
    if let Err((body, status)) = require_admin(auth_header, &url, "GET", None, env).await {
        return json_response(env, &body, status);
    }

    let db = relay_db(env)?;

    #[derive(Deserialize)]
    struct JoinedRow {
        broker_pubkey: String,
        decision_id: String,
        outcome: String,
        decided_at: f64,
        /// Relay acceptance time of the 31403, where a receipt has it.
        decision_accepted_at: Option<f64>,
        /// Relay acceptance time of the 31402, where a receipt has it.
        request_accepted_at: Option<f64>,
        case_created_at: f64,
        calibration_sample: Option<f64>,
        probe_digest: Option<String>,
        case_state: String,
    }

    // One join, aggregated in Rust: the definitions of "override", "caught" and
    // "superseded" belong in tested code, not in SQL nobody can exercise.
    let rows = db
        .prepare(
            "SELECT d.broker_pubkey AS broker_pubkey, \
                    d.decision_id AS decision_id, \
                    d.outcome AS outcome, \
                    d.decided_at AS decided_at, \
                    rd.accepted_at AS decision_accepted_at, \
                    rq.accepted_at AS request_accepted_at, \
                    c.created_at AS case_created_at, \
                    c.calibration_sample AS calibration_sample, \
                    c.probe_digest AS probe_digest, \
                    c.state AS case_state \
             FROM broker_decisions d \
             JOIN broker_cases c ON c.id = d.case_id \
             LEFT JOIN governance_receipts rd ON rd.decision_id = d.decision_id \
             LEFT JOIN governance_receipts rq ON rq.event_id = c.nostr_event_id \
             ORDER BY d.decided_at DESC LIMIT 5000",
        )
        .all()
        .await?
        .results::<JoinedRow>()?;

    let model: Vec<ReviewerDecisionRow> = rows
        .into_iter()
        .map(|r| ReviewerDecisionRow {
            broker_pubkey: r.broker_pubkey,
            decision_id: r.decision_id,
            outcome: r.outcome,
            decided_at_ms: (r.decision_accepted_at.unwrap_or(r.decided_at) * 1000.0) as i64,
            requested_at_ms: (r.request_accepted_at.unwrap_or(r.case_created_at) * 1000.0) as i64,
            calibration_sample: r.calibration_sample.unwrap_or(0.0) >= 1.0,
            is_probe: r.probe_digest.is_some(),
            superseded: r.case_state == "superseded",
        })
        .collect();

    let reviewers = aggregate_reviewers(&model);
    json_response(
        env,
        &json!({
            "reviewers": reviewers,
            "decisions_considered": model.len(),
        }),
        200,
    )
}

#[cfg(test)]
mod augmentation_api_tests {
    //! FR4.1 / FR6.1 / FR7.2: the pure seams behind the two new endpoints. The
    //! D1 shells around them are a `SELECT`, a guarded `UPDATE` and a join —
    //! every decision worth testing is in these two functions.
    use super::*;

    fn agent() -> ApplicationCaller {
        ApplicationCaller {
            is_admin: false,
            is_registered_agent: true,
        }
    }
    fn admin() -> ApplicationCaller {
        ApplicationCaller {
            is_admin: true,
            is_registered_agent: false,
        }
    }
    fn stranger() -> ApplicationCaller {
        ApplicationCaller {
            is_admin: false,
            is_registered_agent: false,
        }
    }

    // ── Authority ───────────────────────────────────────────────────────

    #[test]
    fn a_registered_agent_may_report_the_ordinary_stages() {
        for (current, requested) in [
            (ReceiptStage::ProjectionCommitted, ReceiptStage::ConsumerReceived),
            (ReceiptStage::ConsumerReceived, ReceiptStage::Applied),
            (ReceiptStage::ConsumerReceived, ReceiptStage::NotApplied),
        ] {
            assert_eq!(
                plan_application_advance(current, requested, agent(), "decided", Some("approve")),
                Ok(()),
                "{current:?} -> {requested:?}"
            );
        }
    }

    /// EXP-AC-004: a caller who is neither a registered agent nor an admin gets
    /// 403, and is told that rather than being told the receipt's state.
    #[test]
    fn a_stranger_is_refused_with_403() {
        let refusal = plan_application_advance(
            ReceiptStage::ProjectionCommitted,
            ReceiptStage::ConsumerReceived,
            stranger(),
            "decided",
            Some("approve"),
        )
        .expect_err("a stranger may not report an application stage");
        assert_eq!(refusal, ApplicationRefusal::NotAuthorised);
        assert_eq!(refusal.status(), 403);
    }

    /// EXP-AC-004: `applied-manually` from a non-admin returns 403.
    #[test]
    fn applied_manually_from_a_non_admin_is_403() {
        let refusal = plan_application_advance(
            ReceiptStage::ProjectionCommitted,
            ReceiptStage::AppliedManually,
            agent(),
            "decided",
            Some("approve"),
        )
        .expect_err("only an admin may record a manual continuation");
        assert_eq!(refusal, ApplicationRefusal::ManualRequiresAdmin);
        assert_eq!(refusal.status(), 403);
    }

    // ── The manual-continuation precondition (FR7.2) ────────────────────

    #[test]
    fn an_admin_may_record_a_manual_continuation_on_an_approved_case() {
        assert_eq!(
            plan_application_advance(
                ReceiptStage::ProjectionCommitted,
                ReceiptStage::AppliedManually,
                admin(),
                "decided",
                Some("approve"),
            ),
            Ok(())
        );
    }

    /// EXP-AC-007 counter-example: never for a rejected or still-open case.
    #[test]
    fn applied_manually_requires_a_prior_approve() {
        for (state, outcome) in [
            ("decided", Some("reject")),
            ("open", None),
            ("under_review", None),
            ("reopened", Some("approve")),
            ("decided", None),
        ] {
            let refusal = plan_application_advance(
                ReceiptStage::ProjectionCommitted,
                ReceiptStage::AppliedManually,
                admin(),
                state,
                outcome,
            )
            .expect_err("manual continuation presupposes an approve");
            assert_eq!(
                refusal,
                ApplicationRefusal::ManualRequiresApprovedCase,
                "state={state} outcome={outcome:?}"
            );
            assert_eq!(refusal.status(), 409);
        }
    }

    /// The legacy `resolved` state string means the same thing as `decided`
    /// (see `CaseState::parse`), so a manual continuation works against it too.
    #[test]
    fn the_legacy_resolved_state_still_admits_a_continuation() {
        assert_eq!(
            plan_application_advance(
                ReceiptStage::ProjectionCommitted,
                ReceiptStage::AppliedManually,
                admin(),
                "resolved",
                Some("approve"),
            ),
            Ok(())
        );
    }

    // ── Monotonicity ────────────────────────────────────────────────────

    /// EXP-AC-004: `applied` then `consumer-received` is 409 and changes
    /// nothing.
    #[test]
    fn a_regression_is_409() {
        let refusal = plan_application_advance(
            ReceiptStage::Applied,
            ReceiptStage::ConsumerReceived,
            agent(),
            "decided",
            Some("approve"),
        )
        .expect_err("the ladder never regresses");
        assert!(matches!(refusal, ApplicationRefusal::Regression(_)));
        assert_eq!(refusal.status(), 409);
    }

    #[test]
    fn a_repeat_of_the_same_terminal_stage_is_409() {
        let refusal = plan_application_advance(
            ReceiptStage::Applied,
            ReceiptStage::Applied,
            agent(),
            "decided",
            Some("approve"),
        )
        .unwrap_err();
        assert_eq!(refusal.status(), 409);
    }

    /// The counter-example EXP-AC-004 opens with: a decision that never
    /// committed cannot be reported as applied.
    #[test]
    fn an_uncommitted_decision_cannot_be_applied() {
        for current in [ReceiptStage::RelayAccepted, ReceiptStage::ProjectionFailed] {
            let refusal = plan_application_advance(
                current,
                ReceiptStage::ConsumerReceived,
                agent(),
                "decided",
                Some("approve"),
            )
            .unwrap_err();
            assert_eq!(
                refusal,
                ApplicationRefusal::Regression(StageAdvanceError::NotProjected)
            );
        }
    }

    #[test]
    fn a_side_receipt_is_not_an_application_stage() {
        for stage in [ReceiptStage::EscalatedOnAge, ReceiptStage::Expired] {
            let refusal = plan_application_advance(
                ReceiptStage::ProjectionCommitted,
                stage,
                admin(),
                "decided",
                Some("approve"),
            )
            .unwrap_err();
            assert_eq!(refusal, ApplicationRefusal::UnknownStage);
            assert_eq!(refusal.status(), 400);
        }
    }

    // ── Reviewer telemetry (FR6.1) ──────────────────────────────────────

    fn row(
        pubkey: &str,
        outcome: &str,
        ttd_secs: i64,
        calibration: bool,
        probe: bool,
    ) -> ReviewerDecisionRow {
        ReviewerDecisionRow {
            broker_pubkey: pubkey.into(),
            decision_id: format!("dec-{pubkey}-{outcome}-{ttd_secs}"),
            outcome: outcome.into(),
            requested_at_ms: 1_000_000,
            decided_at_ms: 1_000_000 + ttd_secs * 1000,
            calibration_sample: calibration,
            is_probe: probe,
            superseded: false,
        }
    }

    #[test]
    fn an_empty_corpus_yields_no_reviewers() {
        assert!(aggregate_reviewers(&[]).is_empty());
    }

    #[test]
    fn decisions_time_to_decision_and_override_rate() {
        let rows = vec![
            row("alice", "approve", 10, false, false),
            row("alice", "approve", 20, false, false),
            row("alice", "reject", 30, false, false),
            row("alice", "amend", 100, false, false),
            row("bob", "approve", 5, false, false),
        ];
        let stats = aggregate_reviewers(&rows);
        assert_eq!(stats.len(), 2);

        let alice = &stats[0];
        assert_eq!(alice.pubkey, "alice");
        assert_eq!(alice.decisions, 4);
        // Sorted TTDs 10s, 20s, 30s, 100s → median is the mean of 20s and 30s.
        assert_eq!(alice.median_ttd_ms, 25_000);
        // Nearest-rank p90 over four samples is the fourth.
        assert_eq!(alice.p90_ttd_ms, 100_000);
        // Two of four were not a plain approve.
        assert_eq!(alice.override_rate, 0.5);

        let bob = &stats[1];
        assert_eq!(bob.decisions, 1);
        assert_eq!(bob.override_rate, 0.0);
        assert_eq!(bob.median_ttd_ms, 5_000);
    }

    /// DDD §9 open issue 1 in practice: a skewed clock producing a decision
    /// that predates its own request must not drag the median below zero.
    #[test]
    fn a_negative_time_to_decision_is_discarded() {
        let mut skewed = row("alice", "approve", 0, false, false);
        skewed.decided_at_ms = skewed.requested_at_ms - 60_000;
        let stats = aggregate_reviewers(&[skewed, row("alice", "approve", 40, false, false)]);
        assert_eq!(stats[0].decisions, 2, "the decision still counts");
        assert_eq!(stats[0].median_ttd_ms, 40_000, "but its TTD does not");
    }

    /// EXP-AC-006: the calibration and probe columns, with the corpus-wide
    /// denominators shared across reviewers and the per-reviewer numerators
    /// counting only what that reviewer actually decided.
    #[test]
    fn calibration_and_probe_columns() {
        let rows = vec![
            row("alice", "reject", 10, false, true),   // probe caught
            row("alice", "approve", 10, false, true),  // probe missed
            row("alice", "approve", 10, true, false),  // calibration decided
            row("bob", "approve", 10, true, false),    // calibration decided
        ];
        let stats = aggregate_reviewers(&rows);
        let alice = &stats[0];
        let bob = &stats[1];

        assert_eq!(alice.probes_seen, 2);
        assert_eq!(bob.probes_seen, 2, "the corpus denominator is shared");
        assert_eq!(alice.probes_caught, 1);
        assert_eq!(bob.probes_caught, 0);

        assert_eq!(alice.calibration_shown, 2);
        assert_eq!(alice.calibration_decided, 1);
        assert_eq!(bob.calibration_decided, 1);
    }

    /// DDD §6 invariant 8: a superseded decision is counted so a reviewer whose
    /// calls keep being overturned is visible.
    #[test]
    fn superseded_decisions_are_counted() {
        let mut overturned = row("alice", "approve", 10, false, false);
        overturned.superseded = true;
        let stats = aggregate_reviewers(&[overturned, row("alice", "approve", 10, false, false)]);
        assert_eq!(stats[0].superseded, 1);
        assert_eq!(stats[0].decisions, 2);
    }

    // ── Probe blindness (DDD §6 invariant 7) ────────────────────────────

    /// EXP-AC-006 counter-example: the probe tag must not be visible on a
    /// pending card.
    #[test]
    fn a_probe_is_withheld_from_every_undecided_case() {
        for state in ["open", "under_review", "reopened", "delegated"] {
            assert_eq!(
                redact_probe(state, Some("deadbeef")),
                None,
                "{state} is undecided and must reveal nothing"
            );
        }
    }

    /// Once the 31403 exists the digest is audit evidence rather than a hint,
    /// so it is served.
    #[test]
    fn a_probe_is_revealed_once_the_case_is_decided() {
        for state in ["decided", "resolved", "rejected", "superseded", "closed"] {
            assert_eq!(redact_probe(state, Some("deadbeef")), Some("deadbeef"), "{state}");
        }
    }

    /// A case that never carried a probe reveals nothing whatever its state:
    /// absence renders as absence.
    #[test]
    fn a_case_without_a_probe_reveals_nothing() {
        assert_eq!(redact_probe("decided", None), None);
        assert_eq!(redact_probe("open", None), None);
    }

    #[test]
    fn percentile_and_median_are_total_on_an_empty_series() {
        assert_eq!(percentile(&[], 0.9), 0);
        assert_eq!(median(&[]), 0);
        assert_eq!(percentile(&[7], 0.9), 7);
        assert_eq!(median(&[7]), 7);
    }
}
