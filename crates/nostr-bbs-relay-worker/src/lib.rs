//! nostr-bbs Relay Worker (Rust)
//!
//! Cloudflare Workers-based private Nostr relay with:
//! - WebSocket NIP-01 protocol via Durable Objects
//! - D1-backed event storage + whitelist
//! - NIP-98 authenticated admin endpoints
//! - Whitelist/cohort management API
//! - NIP-11 relay information document
//! - NIP-16/33 replaceable events
//!
//! ## Architecture
//!
//! - `lib.rs` -- HTTP router, CORS, entry point
//! - `relay_do.rs` -- Durable Object: WebSocket relay, NIP-01 message handling
//! - `nip11.rs` -- NIP-11 relay information document
//! - `whitelist.rs` -- Whitelist management HTTP handlers
//! - `auth.rs` -- NIP-98 admin verification wrapper

mod agent_disclosure;
mod audit;
mod auth;
mod cron;
mod mesh;
mod moderation;
mod nip11;
mod profile_stats;
mod profiles;
mod relay_do;
mod trust;
mod trust_sweep;
mod user_admin;
mod whitelist;
mod zone_config;

/// Re-export so the `worker` crate runtime can discover the Durable Object.
pub use relay_do::NostrRelayDO;

// Test-only public API for integration tests (Sprint v9 Stream-E2).
// Activated by `--features test-exports` for tests in `tests/`.
#[cfg(feature = "test-exports")]
pub mod test_exports {
    pub use crate::relay_do::test_exports::*;
    pub use crate::trust::{compute_trust_level, TrustLevel, TrustThresholds};
}

use worker::*;

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

/// Build allowed origins list from `ALLOWED_ORIGINS` env var (comma-separated)
/// or fall back to the production domain.
fn allowed_origins(env: &Env) -> Vec<String> {
    env.var("ALLOWED_ORIGINS")
        .or_else(|_| env.var("ALLOWED_ORIGIN"))
        .map(|v| v.to_string())
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The `Access-Control-Allow-Origin` value for a request from `origin`: the
/// origin itself when it is allowed, else the first allowed origin (which a
/// browser then rejects, as it should).
fn select_origin(allowed: &[String], origin: &str) -> String {
    if allowed.iter().any(|o| o == origin) {
        origin.to_string()
    } else {
        allowed.first().cloned().unwrap_or_default()
    }
}

fn cors_origin(req: &Request, env: &Env) -> String {
    let origin = req
        .headers()
        .get("Origin")
        .ok()
        .flatten()
        .unwrap_or_default();
    select_origin(&allowed_origins(env), &origin)
}

/// Rewrite a response's `Access-Control-Allow-Origin` to the request's own
/// allowed origin.
///
/// Many handlers build their response through [`cors::json_response`], which
/// has no request and so can only name the first allowed origin; with more
/// than one allowed origin every other one was refused by the browser. The
/// entry point resolves the origin once and corrects the header here. A
/// response without the header (none was intended) is left alone.
fn with_request_origin(resp: Response, origin: &str) -> Response {
    if origin.is_empty()
        || !resp
            .headers()
            .has("Access-Control-Allow-Origin")
            .unwrap_or(false)
    {
        return resp;
    }
    let headers = Headers::new();
    for (k, v) in resp.headers().entries() {
        headers.append(&k, &v).ok();
    }
    headers.set("Access-Control-Allow-Origin", origin).ok();
    headers.set("Vary", "Origin").ok();
    resp.with_headers(headers)
}

fn cors_headers(req: &Request, env: &Env) -> Headers {
    let headers = Headers::new();
    headers
        .set("Access-Control-Allow-Origin", &cors_origin(req, env))
        .ok();
    headers
        .set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        .ok();
    headers
        .set(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, Accept",
        )
        .ok();
    headers.set("Access-Control-Max-Age", "86400").ok();
    headers.set("Vary", "Origin").ok();
    headers
}

fn default_origin(env: &Env) -> String {
    allowed_origins(env).into_iter().next().unwrap_or_default()
}

/// CORS utilities for submodules that lack direct access to the request.
pub(crate) mod cors {
    use worker::*;

    /// Create a JSON response with CORS headers attached.
    ///
    /// Used by whitelist handlers that receive `&Env` but not the original
    /// `&Request`. The origin is resolved from the env-based allowed origins.
    pub fn json_response(env: &Env, body: &serde_json::Value, status: u16) -> Result<Response> {
        let json_str = serde_json::to_string(body).map_err(|e| Error::RustError(e.to_string()))?;
        let headers = Headers::new();
        headers.set("Content-Type", "application/json").ok();

        let origin = super::default_origin(env);
        headers.set("Access-Control-Allow-Origin", &origin).ok();
        headers
            .set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            .ok();
        headers
            .set(
                "Access-Control-Allow-Headers",
                "Content-Type, Authorization, Accept",
            )
            .ok();
        headers.set("Access-Control-Max-Age", "86400").ok();
        headers.set("Vary", "Origin").ok();

        Ok(Response::ok(json_str)?
            .with_status(status)
            .with_headers(headers))
    }
}

/// Create a JSON response with CORS from the request's Origin header.
fn json_response(
    req: &Request,
    env: &Env,
    body: &serde_json::Value,
    status: u16,
) -> Result<Response> {
    let json_str = serde_json::to_string(body).map_err(|e| Error::RustError(e.to_string()))?;
    let headers = cors_headers(req, env);
    headers.set("Content-Type", "application/json").ok();
    Ok(Response::ok(json_str)?
        .with_status(status)
        .with_headers(headers))
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

// Invoked via wasm-bindgen by the Workers runtime; appears unused on native
// builds because there is no native caller of the `#[event(fetch)]` glue.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // Idempotent schema migrations (trust columns, new tables, etc.)
    ensure_schema(&env).await;
    nostr_bbs_rate_limit::ensure_replay_schema(&env, "REPLAY_DB").await;

    // CORS preflight
    if req.method() == Method::Options {
        return Ok(Response::empty()?
            .with_status(204)
            .with_headers(cors_headers(&req, &env)));
    }

    // WebSocket upgrade -> Durable Object
    if req.headers().get("Upgrade")?.as_deref() == Some("websocket") {
        let stub = env.durable_object("RELAY")?.get_by_name("main")?;
        return stub.fetch_with_request(req).await;
    }

    let url = req.url()?;
    let path = url.path();

    // NIP-11 relay info document
    if path == "/" && accepts_nostr_json(&req) {
        let info = nip11::relay_info(&env);
        let json_str = serde_json::to_string(&info).map_err(|e| Error::RustError(e.to_string()))?;
        let headers = Headers::new();
        headers.set("Content-Type", "application/nostr+json").ok();
        headers
            .set("Access-Control-Allow-Origin", &cors_origin(&req, &env))
            .ok();
        headers.set("Vary", "Origin").ok();
        return Ok(Response::ok(json_str)?.with_headers(headers));
    }

    // Route to handlers with error wrapping. The origin is resolved before
    // `req` moves into the router, then applied to whatever comes back.
    let request_origin = cors_origin(&req, &env);
    let result = route(req, &env, path).await;
    match result {
        Ok(resp) => Ok(with_request_origin(resp, &request_origin)),
        Err(e) => {
            console_error!("Relay worker error: {e}");
            let msg = e.to_string();
            let fallback_origin = request_origin;
            if msg.contains("JSON") || msg.contains("json") || msg.contains("Syntax") {
                let headers = Headers::new();
                headers.set("Content-Type", "application/json").ok();
                headers
                    .set("Access-Control-Allow-Origin", &fallback_origin)
                    .ok();
                headers.set("Vary", "Origin").ok();
                Ok(Response::ok(r#"{"error":"Invalid JSON"}"#)?
                    .with_status(400)
                    .with_headers(headers))
            } else {
                let headers = Headers::new();
                headers.set("Content-Type", "application/json").ok();
                headers
                    .set("Access-Control-Allow-Origin", &fallback_origin)
                    .ok();
                headers.set("Vary", "Origin").ok();
                Ok(Response::ok(r#"{"error":"Internal error"}"#)?
                    .with_status(500)
                    .with_headers(headers))
            }
        }
    }
}

/// Route incoming requests to the appropriate handler.
async fn route(req: Request, env: &Env, path: &str) -> Result<Response> {
    let method = req.method();

    // Health check
    if path == "/health" || path == "/" {
        return json_response(
            &req,
            env,
            &serde_json::json!({
                "status": "healthy",
                // ADR-103 §2.5: version reports derive from Cargo.toml, never a
                // hardcoded literal (R2 drift class). NIP-90 dropped — the DVM
                // module was removed in R4 (ADR-103 §2.3) and no DVM kinds are
                // handled, so advertising 90 would be a phantom capability claim.
                "version": env!("CARGO_PKG_VERSION"),
                "runtime": "workers-rs",
                "nips": [1, 9, 11, 16, 17, 29, 33, 40, 42, 45, 50, 59, 65, 98],
            }),
            200,
        );
    }

    // Setup status check (public -- returns whether initial admin setup is needed)
    if path == "/api/setup-status" && method == Method::Get {
        return whitelist::handle_setup_status(&req, env).await;
    }

    // Whitelist check (public)
    if path == "/api/check-whitelist" && method == Method::Get {
        return whitelist::handle_check_whitelist(&req, env).await;
    }

    // Whitelist list (public)
    if path == "/api/whitelist/list" && method == Method::Get {
        return whitelist::handle_whitelist_list(&req, env).await;
    }

    // Agent disclosure (public) — COM-13/F2, ADR-106 Decision 3.
    // Minimal active-agent set (pubkey, name, registered_by) for the client's
    // disclosure badge. Sources the authorising principal from the registry,
    // never from event content.
    if path == "/api/agents/disclosure" && method == Method::Get {
        return agent_disclosure::handle_agent_disclosure(env).await;
    }

    // ADR-2010 — governance receipt trail. Exposes the stage each signed
    // response actually reached, so a consumer can tell a denied action from an
    // approved one whose write failed, and can verify correlation itself rather
    // than trusting a relay OK or a forum badge.
    if path == "/api/governance/receipts" && method == Method::Get {
        return relay_do::receipts::handle_receipts_list(&req, env).await;
    }

    // Whitelist add (NIP-98 admin only)
    if path == "/api/whitelist/add" && method == Method::Post {
        return whitelist::handle_whitelist_add(req, env).await;
    }

    // Whitelist update cohorts (NIP-98 admin only)
    if path == "/api/whitelist/update-cohorts" && method == Method::Post {
        return whitelist::handle_whitelist_update_cohorts(req, env).await;
    }

    // Set admin status (NIP-98 admin only)
    if path == "/api/whitelist/set-admin" && method == Method::Post {
        return whitelist::handle_set_admin(req, env).await;
    }

    // Reset database (NIP-98 admin only)
    if path == "/api/admin/reset-db" && method == Method::Post {
        return whitelist::handle_reset_db(req, env).await;
    }

    // Channel -> zone mapping upsert (NIP-98 admin only). This is the sole
    // write path into the `channel_zones` table; zones themselves are declared
    // in config (ZONE_CONFIG), this binds a channel to one of them.
    if path == "/api/admin/channel-zone" && method == Method::Post {
        return handle_channel_zone_upsert(req, env).await;
    }

    // --- Moderation endpoints (NIP-98 admin only) ---

    // List reports
    if path == "/api/reports" && method == Method::Get {
        return moderation::handle_list_reports(&req, env).await;
    }

    // Resolve a report
    if path == "/api/reports/resolve" && method == Method::Post {
        return moderation::handle_resolve_report(req, env).await;
    }

    // --- Audit log endpoint (NIP-98 admin only) ---

    if path == "/api/admin/audit-log" && method == Method::Get {
        return audit::handle_audit_log_list(&req, env).await;
    }

    // --- Sprint v10: profiles (public, no auth) ---

    if path == "/api/profiles/batch" && method == Method::Post {
        let mut req = req;
        let body_bytes = req.bytes().await.unwrap_or_default();
        return profiles::handle_batch(&req, &body_bytes, env).await;
    }

    if path == "/api/profiles/search" && method == Method::Get {
        return profiles::handle_search(&req, env).await;
    }

    // Public old->new pubkey map (admin-set aliases), so clients can fold a
    // replaced key into its successor in pickers and DM routing.
    if path == "/api/profiles/successors" && method == Method::Get {
        return profile_stats::handle_successors(env).await;
    }

    // User-card activity stats, scoped to what the (optional NIP-98) viewer
    // may read — see profile_stats.rs.
    if path == "/api/profile-stats" && method == Method::Get {
        return profile_stats::handle_profile_stats(&req, env).await;
    }

    // --- Sprint v11: profiles backfill (NIP-98 admin only, one-shot) ---
    //
    // Manually-triggered replay of historic kind-0 events into the `profiles`
    // projection. Idempotent — the upsert's `last_kind0_at` guard means
    // re-running is always safe.
    if path == "/api/admin/profiles/backfill" && method == Method::Post {
        return handle_profiles_backfill(req, env).await;
    }

    // --- Task #7: admin user management (NIP-98 admin only) ---

    // Remove a user from the whitelist, optionally purging their events.
    if path == "/api/admin/user/delete" && method == Method::Post {
        return user_admin::handle_delete_user(req, env).await;
    }

    // Suspend / unsuspend (writes whitelist.suspended_until).
    if path == "/api/admin/suspend" && method == Method::Post {
        return user_admin::handle_suspend(req, env).await;
    }

    // Silence / unsilence (writes whitelist.silenced).
    if path == "/api/admin/silence" && method == Method::Post {
        return user_admin::handle_silence(req, env).await;
    }

    // Admin notes write (POST) — read is the parameterised GET below.
    if path == "/api/admin/notes" && method == Method::Post {
        return user_admin::handle_notes_set(req, env).await;
    }

    // GET /api/admin/notes/:pubkey — the pubkey is the trailing path segment.
    if let Some(rest) = path.strip_prefix("/api/admin/notes/") {
        if method == Method::Get && !rest.is_empty() && !rest.contains('/') {
            return user_admin::handle_notes_get(&req, env, rest).await;
        }
    }

    // Pubkey aliases — list (GET) and link old->new (POST).
    if path == "/api/admin/aliases" && method == Method::Get {
        return user_admin::handle_aliases_list(&req, env).await;
    }
    if path == "/api/admin/alias" && method == Method::Post {
        return user_admin::handle_alias_set(req, env).await;
    }

    json_response(&req, env, &serde_json::json!({ "error": "Not found" }), 404)
}

// ---------------------------------------------------------------------------
// Sprint v11: profiles backfill admin endpoint
// ---------------------------------------------------------------------------

/// `POST /api/admin/profiles/backfill` — NIP-98 admin only.
///
/// Replays every stored kind-0 event through the `profiles` projection upsert
/// (Sprint v10). Returns `{ scanned, backfilled, skipped, truncated }`.
async fn handle_profiles_backfill(mut req: Request, env: &Env) -> Result<Response> {
    let url = req.url()?;
    let request_url = url.to_string();
    let auth_header = req.headers().get("Authorization").ok().flatten();
    let body_bytes = req.bytes().await.unwrap_or_default();
    // Treat empty body as no body for NIP-98 payload-hash semantics; non-empty
    // is hashed and verified.
    let body_for_auth: Option<&[u8]> = if body_bytes.is_empty() {
        None
    } else {
        Some(&body_bytes)
    };

    let _admin_pubkey = match auth::require_nip98_admin(
        auth_header.as_deref(),
        &request_url,
        "POST",
        body_for_auth,
        env,
    )
    .await
    {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(&req, env, &body, status),
    };

    match cron::backfill_profiles(env).await {
        Ok(result) => {
            let body = serde_json::to_value(result).unwrap_or_else(|_| serde_json::json!({}));
            json_response(&req, env, &body, 200)
        }
        Err(e) => {
            console_error!("backfill_profiles failed: {e}");
            json_response(
                &req,
                env,
                &serde_json::json!({ "error": "backfill failed", "detail": e }),
                500,
            )
        }
    }
}

/// `POST /api/admin/channel-zone` — NIP-98 admin only.
///
/// Inserts or updates a row in `channel_zones`, binding a channel id to a zone
/// slug. Zones themselves are config-driven (declared via `ZONE_CONFIG`); this
/// endpoint is the only write path into the mapping table, mirroring the
/// whitelist admin handlers. Request body:
/// `{ "channel_id": "<hex>", "zone": "<slug>", "archived": false }`.
async fn handle_channel_zone_upsert(mut req: Request, env: &Env) -> Result<Response> {
    use nostr_bbs_core::d1_helpers::{js_f64, js_str};

    let url = req.url()?;
    let request_url = url.to_string();
    let auth_header = req.headers().get("Authorization").ok().flatten();
    let body_bytes = req.bytes().await.unwrap_or_default();
    let body_for_auth: Option<&[u8]> = if body_bytes.is_empty() {
        None
    } else {
        Some(&body_bytes)
    };

    let admin_pubkey = match auth::require_nip98_admin(
        auth_header.as_deref(),
        &request_url,
        "POST",
        body_for_auth,
        env,
    )
    .await
    {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(&req, env, &body, status),
    };

    #[derive(serde::Deserialize)]
    struct Body {
        channel_id: Option<String>,
        zone: Option<String>,
        #[serde(default)]
        archived: bool,
    }

    let body: Body = match serde_json::from_slice(&body_bytes) {
        Ok(b) => b,
        Err(e) => {
            return json_response(
                &req,
                env,
                &serde_json::json!({ "error": "invalid JSON", "detail": e.to_string() }),
                400,
            )
        }
    };

    let channel_id = match &body.channel_id {
        Some(c) if !c.is_empty() && c.len() <= 128 && c.bytes().all(|b| b.is_ascii_hexdigit()) => {
            c.clone()
        }
        _ => {
            return json_response(
                &req,
                env,
                &serde_json::json!({ "error": "missing or invalid channel_id (hex required)" }),
                400,
            )
        }
    };

    let zone = match &body.zone {
        Some(z)
            if !z.is_empty()
                && z.len() <= 64
                && z.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') =>
        {
            z.clone()
        }
        _ => {
            return json_response(
                &req,
                env,
                &serde_json::json!({ "error": "missing or invalid zone slug" }),
                400,
            )
        }
    };

    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => {
            return json_response(
                &req,
                env,
                &serde_json::json!({ "error": "DB unavailable" }),
                500,
            )
        }
    };

    let archived = if body.archived { 1.0 } else { 0.0 };
    let upsert = db
        .prepare(
            "INSERT INTO channel_zones (channel_id, zone, archived) \
             VALUES (?1, ?2, ?3) \
             ON CONFLICT (channel_id) DO UPDATE SET zone = excluded.zone, archived = excluded.archived",
        )
        .bind(&[js_str(&channel_id), js_str(&zone), js_f64(archived)]);

    match upsert {
        Ok(stmt) => match stmt.run().await {
            Ok(_) => {}
            Err(e) => {
                console_error!("channel_zone upsert failed: {e}");
                return json_response(
                    &req,
                    env,
                    &serde_json::json!({ "error": "upsert failed" }),
                    500,
                );
            }
        },
        Err(e) => {
            console_error!("channel_zone bind failed: {e}");
            return json_response(
                &req,
                env,
                &serde_json::json!({ "error": "bind failed" }),
                500,
            );
        }
    }

    // Audit trail, mirroring the whitelist admin handlers.
    let _ = audit::log_admin_action(
        env,
        &admin_pubkey,
        "channel_zone_set",
        None,
        Some(&channel_id),
        None,
        Some(&zone),
        None,
    )
    .await;

    json_response(
        &req,
        env,
        &serde_json::json!({ "success": true, "channel_id": channel_id, "zone": zone }),
        200,
    )
}

/// The statements that keep seeded probes out of `event_tags` (DDD §6
/// invariant 7, FR6.4), mirroring migration 0006.
///
/// `event_tags` backs every `#tag` REQ filter, so one `probe` row there lets any
/// client enumerate the seeded probes by subscription and destroys the catch
/// rate they exist to measure.
///
/// The blinding lives in the tag-WRITING trigger, not in a second trigger
/// watching it. `event_tags` is written only by `trg_event_tags_ai` (0004), an
/// `AFTER INSERT ON events`; in SQLite a trigger fired by a modification made
/// inside another trigger runs only under `PRAGMA recursive_triggers = ON`,
/// which defaults OFF and is set nowhere here. A watcher trigger therefore never
/// fired for the only path that writes probe rows: the control read as
/// enforcement and was inert. Filtering at the source needs no recursion.
///
/// Order matters: drop the old writer, create the filtering one, keep the
/// watcher for any other writer, then purge rows written before any of this
/// existed. The last statement is the one the original migration failed to
/// mirror here, so a deployed relay kept every probe row it had already indexed.
pub(crate) const PROBE_BLIND_STMTS: [&str; 4] = [
    "DROP TRIGGER IF EXISTS trg_event_tags_ai",
    "CREATE TRIGGER IF NOT EXISTS trg_event_tags_ai_v2 AFTER INSERT ON events \
     BEGIN \
       INSERT INTO event_tags (event_id, name, value) \
       SELECT NEW.id, json_extract(je.value, '$[0]'), \
              COALESCE(json_extract(je.value, '$[1]'), '') \
       FROM json_each(NEW.tags) je \
       WHERE json_type(je.value) = 'array' \
         AND json_extract(je.value, '$[0]') IS NOT NULL \
         AND json_extract(je.value, '$[0]') <> 'probe'; \
     END",
    "CREATE TRIGGER IF NOT EXISTS trg_event_tags_probe_blind \
     AFTER INSERT ON event_tags WHEN NEW.name = 'probe' \
     BEGIN DELETE FROM event_tags WHERE event_id = NEW.event_id AND name = 'probe'; END",
    "DELETE FROM event_tags WHERE name = 'probe'",
];

/// Idempotent schema migrations.
///
/// All statements use `IF NOT EXISTS` for tables or silently ignore errors
/// for `ALTER TABLE ADD COLUMN` (D1/SQLite raises an error if the column
/// already exists, which we swallow).
async fn ensure_schema(env: &Env) {
    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return,
    };

    // --- Whitelist columns (idempotent: errors ignored if column exists) ---
    let alter_stmts = [
        "ALTER TABLE whitelist ADD COLUMN is_admin INTEGER DEFAULT 0",
        "ALTER TABLE whitelist ADD COLUMN trust_level INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE whitelist ADD COLUMN days_active INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE whitelist ADD COLUMN posts_read INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE whitelist ADD COLUMN posts_created INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE whitelist ADD COLUMN mod_actions_against INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE whitelist ADD COLUMN last_active_at INTEGER",
        "ALTER TABLE whitelist ADD COLUMN trust_level_updated_at INTEGER",
        "ALTER TABLE whitelist ADD COLUMN suspended_until INTEGER",
        "ALTER TABLE whitelist ADD COLUMN silenced INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE whitelist ADD COLUMN user_notes TEXT",
        // F6 (DDD §7a): supersession marker on the append-only decision trail.
        // Idempotent for already-deployed DBs whose broker_decisions predates F6.
        "ALTER TABLE broker_decisions ADD COLUMN superseded_by TEXT",
        // ADR-2011 (migration 0006): the effective escalation boundary and the
        // operator-declared triple it derives from, the calibration mark, the
        // seeded-probe digest and the panel's ageing deadline. Mirrored here
        // because THIS function is the live schema path — a deployed DB is
        // provisioned from here, not from `wrangler d1 migrations apply`, so a
        // column that exists only in migrations/ would never exist in
        // production. SQLite has no `ADD COLUMN IF NOT EXISTS`; the error on a
        // duplicate column is discarded below, which is how every ALTER above
        // is already idempotent.
        "ALTER TABLE broker_cases ADD COLUMN declared_tier TEXT",
        "ALTER TABLE broker_cases ADD COLUMN effective_tier TEXT",
        "ALTER TABLE broker_cases ADD COLUMN tp_verifiability TEXT",
        "ALTER TABLE broker_cases ADD COLUMN tp_reversibility TEXT",
        "ALTER TABLE broker_cases ADD COLUMN tp_stakes TEXT",
        "ALTER TABLE broker_cases ADD COLUMN calibration_sample INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE broker_cases ADD COLUMN probe_digest TEXT",
        "ALTER TABLE broker_cases ADD COLUMN max_pending_hours INTEGER",
        // ADR-2013 (migration 0007): the ontology proposal's own expiry, copied
        // off the `PatchProposal` body at projection time so the expiry sweep
        // is an indexed scan rather than a JSON parse per pending row.
        "ALTER TABLE broker_cases ADD COLUMN stale_after INTEGER",
        // FR4.1: provenance of an application-stage advance — who claimed it,
        // when, and in whose words.
        "ALTER TABLE governance_receipts ADD COLUMN applied_at INTEGER",
        "ALTER TABLE governance_receipts ADD COLUMN applied_by TEXT",
        "ALTER TABLE governance_receipts ADD COLUMN acknowledgement TEXT",
    ];
    for stmt in alter_stmts {
        let _ = db.prepare(stmt).run().await;
    }

    // --- New tables (idempotent via IF NOT EXISTS) ---
    let create_stmts = [
        "CREATE TABLE IF NOT EXISTS channel_zones (\
            channel_id TEXT PRIMARY KEY, \
            zone TEXT NOT NULL DEFAULT 'home', \
            archived INTEGER NOT NULL DEFAULT 0\
        )",
        "CREATE TABLE IF NOT EXISTS admin_log (\
            id INTEGER PRIMARY KEY AUTOINCREMENT, \
            actor_pubkey TEXT NOT NULL, \
            action TEXT NOT NULL, \
            target_pubkey TEXT, \
            target_id TEXT, \
            previous_value TEXT, \
            new_value TEXT, \
            reason TEXT, \
            created_at INTEGER NOT NULL\
        )",
        "CREATE TABLE IF NOT EXISTS settings (\
            key TEXT PRIMARY KEY, \
            value TEXT NOT NULL, \
            type TEXT NOT NULL DEFAULT 'string', \
            category TEXT NOT NULL DEFAULT 'general'\
        )",
        "CREATE TABLE IF NOT EXISTS reports (\
            id INTEGER PRIMARY KEY AUTOINCREMENT, \
            report_event_id TEXT NOT NULL UNIQUE, \
            reporter_pubkey TEXT NOT NULL, \
            reporter_trust_level INTEGER NOT NULL DEFAULT 0, \
            reported_event_id TEXT NOT NULL, \
            reported_pubkey TEXT NOT NULL, \
            reason TEXT NOT NULL, \
            reason_text TEXT, \
            status TEXT NOT NULL DEFAULT 'pending', \
            resolved_by TEXT, \
            resolution TEXT, \
            created_at INTEGER NOT NULL, \
            resolved_at INTEGER\
        )",
        "CREATE TABLE IF NOT EXISTS hidden_events (\
            event_id TEXT PRIMARY KEY, \
            hidden_by TEXT NOT NULL, \
            reason TEXT, \
            created_at INTEGER NOT NULL\
        )",
        // WI-2: mirror of auth-worker's moderation_actions. Populated when
        // kind-30910/30911 Nostr events signed by an admin are saved here.
        // Consumed by the relay's ingress gate to block muted/banned authors.
        "CREATE TABLE IF NOT EXISTS moderation_actions (\
            id TEXT PRIMARY KEY, \
            action TEXT NOT NULL, \
            target_pubkey TEXT NOT NULL, \
            performed_by TEXT NOT NULL, \
            reason TEXT, \
            expires_at INTEGER, \
            event_id TEXT NOT NULL, \
            created_at INTEGER NOT NULL\
        )",
        // Sprint v10: projection of the most-recent kind-0 per pubkey, with
        // the JSON content fields parsed into typed columns. Maintained by
        // the kind-0 ingest hook in `relay_do::storage::save_event`.
        "CREATE TABLE IF NOT EXISTS profiles (\
            pubkey TEXT PRIMARY KEY NOT NULL, \
            name TEXT, \
            display_name TEXT, \
            picture TEXT, \
            banner TEXT, \
            about TEXT, \
            nip05 TEXT, \
            lud16 TEXT, \
            last_kind0_at INTEGER NOT NULL, \
            raw_event TEXT NOT NULL\
        )",
        // Agent Control Surface Protocol: registry of agents allowed to publish
        // governance events (kinds 31400-31405).
        "CREATE TABLE IF NOT EXISTS agent_registry (\
            pubkey TEXT PRIMARY KEY NOT NULL, \
            name TEXT NOT NULL, \
            description TEXT NOT NULL DEFAULT '', \
            registered_by TEXT NOT NULL, \
            registered_at INTEGER NOT NULL, \
            rate_limit_per_min INTEGER NOT NULL DEFAULT 60, \
            active INTEGER NOT NULL DEFAULT 1\
        )",
        // Broker case aggregate — human-in-the-loop governance decisions.
        "CREATE TABLE IF NOT EXISTS broker_cases (\
            id TEXT PRIMARY KEY NOT NULL, \
            category TEXT NOT NULL, \
            subject_kind TEXT NOT NULL, \
            subject_id TEXT NOT NULL, \
            title TEXT NOT NULL, \
            summary TEXT NOT NULL DEFAULT '', \
            state TEXT NOT NULL DEFAULT 'open', \
            priority INTEGER NOT NULL DEFAULT 50, \
            from_share_state TEXT, \
            to_share_state TEXT, \
            created_by TEXT NOT NULL, \
            assigned_to TEXT, \
            nostr_event_id TEXT, \
            created_at INTEGER NOT NULL, \
            updated_at INTEGER NOT NULL\
        )",
        // Individual decisions on broker cases (append-only audit trail).
        // F6 (DDD §7a): `superseded_by` names the decision that supersedes this
        // row (NULL = current/effective). It is a projection-derived column — the
        // superseding kind-31403 marks the prior row without ever mutating the
        // underlying Nostr event (Invariant 5).
        "CREATE TABLE IF NOT EXISTS broker_decisions (\
            decision_id TEXT PRIMARY KEY NOT NULL, \
            case_id TEXT NOT NULL REFERENCES broker_cases(id), \
            outcome TEXT NOT NULL, \
            outcome_detail TEXT, \
            broker_pubkey TEXT NOT NULL, \
            reasoning TEXT NOT NULL DEFAULT '', \
            prior_decision_id TEXT, \
            superseded_by TEXT, \
            decided_at INTEGER NOT NULL\
        )",
        // ADR-2010 — durable governance outcome receipts. One row per signed
        // governance event, keyed by the FULL event id, recording the stage the
        // response actually reached. Written at `relay-accepted` right after the
        // envelope is stored; transitions to `projection-committed` inside the
        // same batch as the decision row and case state, so the two can never
        // disagree. `replays` counts redeliveries without re-running the mutation.
        "CREATE TABLE IF NOT EXISTS governance_receipts (\
            event_id TEXT PRIMARY KEY NOT NULL, \
            kind INTEGER NOT NULL, \
            case_id TEXT NOT NULL, \
            request_event_id TEXT, \
            signer_pubkey TEXT NOT NULL, \
            decision_outcome TEXT, \
            target_operation TEXT, \
            supersedes_event_id TEXT, \
            stage TEXT NOT NULL, \
            stage_error TEXT, \
            decision_id TEXT, \
            signed_at INTEGER NOT NULL, \
            accepted_at INTEGER, \
            projected_at INTEGER, \
            replays INTEGER NOT NULL DEFAULT 0\
        )",
        // Role assignments for broker governance (which pubkeys can claim cases).
        "CREATE TABLE IF NOT EXISTS broker_roles (\
            pubkey TEXT NOT NULL, \
            role TEXT NOT NULL, \
            granted_by TEXT NOT NULL, \
            granted_at INTEGER NOT NULL, \
            PRIMARY KEY (pubkey, role)\
        )",
        // Task #7: pubkey alias map (old_pubkey -> new_pubkey). Nostr events are
        // bound to the signing key and can never be re-signed, so identity
        // inheritance is modelled as an alias: a newly-joining `new_pubkey` is
        // linked to a prior `old_pubkey` so the DISPLAY layer attributes the new
        // key's posts under the prior handle and cohorts can be inherited.
        // `new_pubkey` is the PK (a joining key maps to at most one prior id).
        "CREATE TABLE IF NOT EXISTS pubkey_aliases (\
            new_pubkey TEXT PRIMARY KEY NOT NULL, \
            old_pubkey TEXT NOT NULL, \
            created_by TEXT NOT NULL, \
            created_at INTEGER NOT NULL, \
            reason TEXT\
        )",
        // FR4.3 / FR4.5 (migration 0006): `escalated-on-age` and `expired` are
        // receipts about a CASE, not about a signed decision event, so they
        // cannot live in `governance_receipts` — every row there is keyed by a
        // full 64-hex signed event id. The (case_id, stage) primary key is what
        // makes the ageing cron idempotent: "exactly once per case" is a
        // constraint, not a code path that has to remember.
        "CREATE TABLE IF NOT EXISTS case_side_receipts (\
            case_id TEXT NOT NULL, \
            stage TEXT NOT NULL, \
            recorded_at INTEGER NOT NULL, \
            detail TEXT, \
            PRIMARY KEY (case_id, stage)\
        )",
        // FR6.2 (migration 0006): an admin's Delegate{to} projects one row
        // here and the 31403 admission gate consults it. A `reviewer`-role
        // pubkey is otherwise read-only; a row here admits it for EXACTLY the
        // named case, and `delegated_by` keeps the delegation attributable to
        // the admin who granted it.
        "CREATE TABLE IF NOT EXISTS case_delegations (\
            case_id TEXT NOT NULL, \
            delegate_pubkey TEXT NOT NULL, \
            delegated_by TEXT NOT NULL, \
            decision_id TEXT, \
            delegated_at INTEGER NOT NULL, \
            PRIMARY KEY (case_id, delegate_pubkey)\
        )",
    ];
    for stmt in create_stmts {
        let _ = db.prepare(stmt).run().await;
    }

    // DDD §6 invariant 7 — probe blinding. Ordered, so run as its own sequence
    // rather than folded into the unordered `create_stmts` above.
    for stmt in PROBE_BLIND_STMTS {
        let _ = db.prepare(stmt).run().await;
    }

    // --- Indexes (idempotent via IF NOT EXISTS) ---
    let index_stmts = [
        "CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)",
        "CREATE INDEX IF NOT EXISTS idx_reports_reported_event ON reports(reported_event_id)",
        "CREATE INDEX IF NOT EXISTS idx_reports_reported_pubkey ON reports(reported_pubkey)",
        "CREATE INDEX IF NOT EXISTS idx_admin_log_action ON admin_log(action)",
        "CREATE INDEX IF NOT EXISTS idx_admin_log_actor ON admin_log(actor_pubkey)",
        "CREATE INDEX IF NOT EXISTS idx_admin_log_target ON admin_log(target_pubkey)",
        "CREATE INDEX IF NOT EXISTS idx_admin_log_created ON admin_log(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_mod_actions_target ON moderation_actions(target_pubkey)",
        "CREATE INDEX IF NOT EXISTS idx_mod_actions_active ON moderation_actions(action, expires_at)",
        // NIP-59 (Sealed DMs, kind-1059): index on kind for efficient recipient delivery.
        // p-tag recipient filtering is applied via the tags LIKE pattern at query time;
        // this index narrows the scan to kind-1059 rows first.
        "CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind)",
        // Sprint v10: profiles indexes for batch lookup and prefix typeahead.
        "CREATE INDEX IF NOT EXISTS idx_profiles_name ON profiles(name)",
        "CREATE INDEX IF NOT EXISTS idx_profiles_display_name ON profiles(display_name)",
        "CREATE INDEX IF NOT EXISTS idx_profiles_last_kind0 ON profiles(last_kind0_at DESC)",
        // Agent Control Surface Protocol indexes.
        "CREATE INDEX IF NOT EXISTS idx_agent_registry_active ON agent_registry(active)",
        "CREATE INDEX IF NOT EXISTS idx_broker_cases_state ON broker_cases(state)",
        "CREATE INDEX IF NOT EXISTS idx_broker_cases_category ON broker_cases(category)",
        "CREATE INDEX IF NOT EXISTS idx_broker_cases_assigned ON broker_cases(assigned_to)",
        "CREATE INDEX IF NOT EXISTS idx_broker_decisions_case ON broker_decisions(case_id)",
        "CREATE INDEX IF NOT EXISTS idx_broker_roles_pubkey ON broker_roles(pubkey)",
        "CREATE INDEX IF NOT EXISTS idx_governance_receipts_case ON governance_receipts(case_id)",
        "CREATE INDEX IF NOT EXISTS idx_governance_receipts_stage ON governance_receipts(stage)",
        "CREATE INDEX IF NOT EXISTS idx_governance_receipts_request ON governance_receipts(request_event_id)",
        "CREATE INDEX IF NOT EXISTS idx_governance_receipts_signer ON governance_receipts(signer_pubkey)",
        // Task #7: reverse lookup old_pubkey -> new_pubkey for display/cohort
        // resolution (the forward new_pubkey lookup uses the PK).
        "CREATE INDEX IF NOT EXISTS idx_pubkey_aliases_old ON pubkey_aliases(old_pubkey)",
        // ADR-2011 (migration 0006). `idx_broker_cases_pending_age` serves the
        // ageing sweep's state filter; the sweep orders by a computed deadline
        // expression, which SQLite cannot index, so this narrows rather than
        // satisfies the ORDER BY.
        "CREATE INDEX IF NOT EXISTS idx_broker_cases_effective_tier ON broker_cases(effective_tier)",
        "CREATE INDEX IF NOT EXISTS idx_broker_cases_pending_age ON broker_cases(state, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_case_side_receipts_stage ON case_side_receipts(stage)",
        "CREATE INDEX IF NOT EXISTS idx_case_delegations_delegate ON case_delegations(delegate_pubkey)",
    ];
    for stmt in index_stmts {
        let _ = db.prepare(stmt).run().await;
    }
}

/// Check whether the request's Accept header includes `application/nostr+json`.
fn accepts_nostr_json(req: &Request) -> bool {
    req.headers()
        .get("Accept")
        .ok()
        .flatten()
        .map(|v| v.contains("application/nostr+json"))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Cron keep-warm
// ---------------------------------------------------------------------------

/// Cron handler: keep-warm plus the ADR-102 inactivity-decay trust sweep.
///
/// The `SELECT 1` touches D1 to keep the connection pool warm and prevent cold
/// starts. The demotion sweep (ADR-102) then selects whitelist rows past the
/// ~6-month inactivity gate and applies `trust::check_demotion` to each —
/// wiring the previously-dead demotion path onto the only trigger whose
/// semantics match its precondition (time-driven, not request-driven). The
/// sweep is paged and bounded; a sweep error is logged but never propagated, so
/// it cannot break the keep-warm tick.
// Invoked via wasm-bindgen by the Workers runtime; appears unused on native
// builds because there is no native caller of the `#[event(scheduled)]` glue.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return,
    };
    let _ = db
        .prepare("SELECT 1")
        .first::<serde_json::Value>(None)
        .await;

    match trust_sweep::sweep_inactive_demotions(&env).await {
        Ok(result) => {
            // ADR-2006: report the explicit outcomes, not just the happy count.
            // A sweep whose writes all failed must not look like a quiet tick,
            // so `failed` and `aborted` are as loud as `demoted`.
            if result.demoted > 0 || result.truncated || result.failed > 0 || result.aborted {
                console_log!(
                    "trust demotion sweep: scanned={} demoted={} held={} failed={} \
                     truncated={} aborted={}",
                    result.scanned,
                    result.demoted,
                    result.held,
                    result.failed,
                    result.truncated,
                    result.aborted
                );
            }
        }
        Err(e) => console_error!("trust demotion sweep failed: {e}"),
    }

    // Enforce the NIP-11 retention policy and NIP-40 expiration: DELETE rows
    // past their kind's retention window and past their expiration tag. Paged
    // and circuit-broken; a failure is logged but never breaks the tick.
    match cron::sweep_retention(&env).await {
        Ok(result) => {
            if result.retention_deleted > 0 || result.expired_deleted > 0 || result.truncated {
                console_log!(
                    "retention sweep: retention_deleted={} expired_deleted={} truncated={}",
                    result.retention_deleted,
                    result.expired_deleted,
                    result.truncated
                );
            }
        }
        Err(e) => console_error!("retention sweep failed: {e}"),
    }

    // FR4.3: a case nobody got to must age visibly rather than sit quietly
    // pending. One `escalated-on-age` receipt per case, ever — the idempotency
    // is the `(case_id, stage)` primary key, not this tick's memory.
    match cron::escalate_stale_cases(&env).await {
        Ok(result) => {
            if result.escalated > 0 || result.failed > 0 || result.truncated {
                console_log!(
                    "ageing sweep: scanned={} escalated={} already={} failed={} truncated={}",
                    result.scanned,
                    result.escalated,
                    result.already_escalated,
                    result.failed,
                    result.truncated
                );
            }
        }
        Err(e) => console_error!("ageing sweep failed: {e}"),
    }

    // ADR-2013: an ontology proposal past its `stale_after` is no longer safe
    // to apply — the corpus has moved on and its digest no longer describes the
    // page. It is closed WITHOUT a decision and receipted `expired`. This runs
    // after the ageing sweep so a case that is both overdue and expired accrues
    // the honest pair of receipts, in the order they became true.
    match cron::expire_stale_proposals(&env).await {
        Ok(result) => {
            if result.expired > 0 || result.failed > 0 || result.truncated {
                console_log!(
                    "expiry sweep: scanned={} expired={} already={} failed={} truncated={}",
                    result.scanned,
                    result.expired,
                    result.already_expired,
                    result.failed,
                    result.truncated
                );
            }
        }
        Err(e) => console_error!("expiry sweep failed: {e}"),
    }
}

#[cfg(test)]
mod cors_tests {
    #[test]
    fn cors_allows_every_configured_origin_not_just_the_first() {
        let allowed = vec![
            "https://dreamlab-ai.com".to_string(),
            "http://agentbox:8083".to_string(),
        ];
        assert_eq!(
            super::select_origin(&allowed, "https://dreamlab-ai.com"),
            "https://dreamlab-ai.com"
        );
        assert_eq!(
            super::select_origin(&allowed, "http://agentbox:8083"),
            "http://agentbox:8083"
        );
        // A foreign origin gets the first allowed one, which the browser refuses.
        assert_eq!(
            super::select_origin(&allowed, "https://evil.example"),
            "https://dreamlab-ai.com"
        );
        assert_eq!(
            super::select_origin(&allowed, ""),
            "https://dreamlab-ai.com"
        );
        assert_eq!(super::select_origin(&[], "https://dreamlab-ai.com"), "");
    }
}

#[cfg(test)]
mod probe_blinding_tests {

    use super::PROBE_BLIND_STMTS;

    const MIGRATION_0006: &str = include_str!("../migrations/0006_augmentation_conditions.sql");

    /// Whitespace-insensitive containment, so a line-continued Rust string and a
    /// formatted SQL file compare on content rather than on layout.
    fn squash(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn the_tag_writing_trigger_itself_excludes_probe() {
        // The defect this guards: blinding used to live in a SECOND trigger
        // watching `event_tags`. `event_tags` is written only from inside
        // another trigger, and SQLite runs trigger-inside-trigger only under
        // `PRAGMA recursive_triggers = ON` — off by default, set nowhere here.
        // The control read as enforcement and never fired. Filtering in the
        // writer needs no recursion.
        let writer = PROBE_BLIND_STMTS
            .iter()
            .find(|s| s.contains("trg_event_tags_ai_v2"))
            .expect("a replacement tag-writing trigger exists");
        let w = squash(writer);
        assert!(w.contains("AFTER INSERT ON events"));
        assert!(
            w.contains("json_extract(je.value, '$[0]') <> 'probe'"),
            "the writer must filter probe rows at the source"
        );
    }

    #[test]
    fn the_superseded_writer_trigger_is_dropped_first() {
        // 0004 created `trg_event_tags_ai` with IF NOT EXISTS, so on a deployed
        // relay it survives and would keep writing probe rows beside the new
        // one. It must be dropped, and dropped BEFORE the replacement exists so
        // the sequence never leaves the table unwritten.
        assert_eq!(
            PROBE_BLIND_STMTS[0], "DROP TRIGGER IF EXISTS trg_event_tags_ai",
            "the old writer must be dropped first"
        );
        assert!(PROBE_BLIND_STMTS[1].contains("trg_event_tags_ai_v2"));
    }

    #[test]
    fn existing_probe_rows_are_purged_on_the_live_path_too() {
        // The original migration purged pre-existing rows and `ensure_schema`
        // did not, contradicting the file's own "every statement below is
        // mirrored there" — so a deployed relay kept every probe row it had
        // already indexed and stayed enumerable.
        assert!(
            PROBE_BLIND_STMTS
                .iter()
                .any(|s| squash(s) == "DELETE FROM event_tags WHERE name = 'probe'"),
            "the live path must purge rows written before the blinding existed"
        );
    }

    #[test]
    fn every_live_statement_is_mirrored_in_migration_0006() {
        // The mirror claim is now checkable rather than asserted in a comment.
        let migration = squash(MIGRATION_0006);
        for stmt in PROBE_BLIND_STMTS {
            assert!(
                migration.contains(&squash(stmt)),
                "migration 0006 does not carry: {}",
                squash(stmt)
            );
        }
    }

    #[test]
    fn the_watcher_trigger_is_kept_but_is_not_the_only_control() {
        // Kept for any other writer of `event_tags`; it must not be the sole
        // blinder, which is what made the control inert.
        assert!(PROBE_BLIND_STMTS
            .iter()
            .any(|s| s.contains("trg_event_tags_probe_blind")));
        assert!(
            PROBE_BLIND_STMTS
                .iter()
                .filter(|s| s.contains("'probe'"))
                .count()
                >= 3,
            "blinding must be enforced at the writer, the watcher and the purge"
        );
    }
}
