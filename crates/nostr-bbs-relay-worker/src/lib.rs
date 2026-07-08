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

// Worker entry points are invoked via wasm-bindgen and appear unused in native builds.
#![allow(dead_code)]

mod agent_disclosure;
mod audit;
mod auth;
mod cron;
mod moderation;
mod nip11;
mod profiles;
mod relay_do;
mod trust;
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

fn cors_origin(req: &Request, env: &Env) -> String {
    let origins = allowed_origins(env);
    let origin = req
        .headers()
        .get("Origin")
        .ok()
        .flatten()
        .unwrap_or_default();
    if origins.iter().any(|o| o == &origin) {
        origin
    } else {
        origins.into_iter().next().unwrap_or_default()
    }
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

    // Route to handlers with error wrapping
    let result = route(req, &env, path).await;
    match result {
        Ok(resp) => Ok(resp),
        Err(e) => {
            console_error!("Relay worker error: {e}");
            let msg = e.to_string();
            let fallback_origin = default_origin(&env);
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
    let request_url = format!("{}{}", url.origin().ascii_serialization(), url.path());
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
    let request_url = format!("{}{}", url.origin().ascii_serialization(), url.path());
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
        "CREATE TABLE IF NOT EXISTS broker_decisions (\
            decision_id TEXT PRIMARY KEY NOT NULL, \
            case_id TEXT NOT NULL REFERENCES broker_cases(id), \
            outcome TEXT NOT NULL, \
            outcome_detail TEXT, \
            broker_pubkey TEXT NOT NULL, \
            reasoning TEXT NOT NULL DEFAULT '', \
            prior_decision_id TEXT, \
            decided_at INTEGER NOT NULL\
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
    ];
    for stmt in create_stmts {
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
        // Task #7: reverse lookup old_pubkey -> new_pubkey for display/cohort
        // resolution (the forward new_pubkey lookup uses the PK).
        "CREATE INDEX IF NOT EXISTS idx_pubkey_aliases_old ON pubkey_aliases(old_pubkey)",
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

    match cron::sweep_inactive_demotions(&env).await {
        Ok(result) => {
            if result.demoted > 0 || result.truncated {
                console_log!(
                    "trust demotion sweep: scanned={} demoted={} truncated={}",
                    result.scanned,
                    result.demoted,
                    result.truncated
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
}
