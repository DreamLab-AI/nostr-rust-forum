//! Nostr BBS Relay Worker (Rust)
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

mod audit;
mod auth;
mod moderation;
mod nip11;
mod relay_do;
mod trust;
mod whitelist;

/// Re-export so the `worker` crate runtime can discover the Durable Object.
pub use relay_do::NostrRelayDO;

use worker::*;

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

/// Build allowed origins list from `ALLOWED_ORIGINS` env var (comma-separated)
/// or fall back to the production domain.
fn allowed_origins(env: &Env) -> Vec<String> {
    env.var("ALLOWED_ORIGINS")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "https://example.com".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .collect()
}

/// Determine the allowed CORS origin for a request.
///
/// If the request's `Origin` header matches one of the allowed origins, that
/// origin is returned. Otherwise falls back to the first allowed origin.
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
        origins
            .into_iter()
            .next()
            .unwrap_or_else(|| "https://example.com".to_string())
    }
}

/// Build CORS response headers.
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

/// Return the default allowed origin from the env or the production domain.
fn default_origin(env: &Env) -> String {
    allowed_origins(env)
        .into_iter()
        .next()
        .unwrap_or_else(|| "https://example.com".to_string())
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
        let json_str =
            serde_json::to_string(&info).map_err(|e| Error::RustError(e.to_string()))?;
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
                "version": "3.0.0",
                "runtime": "workers-rs",
                "nips": [1, 9, 11, 16, 29, 33, 40, 42, 45, 50, 98],
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

    json_response(
        &req,
        env,
        &serde_json::json!({ "error": "Not found" }),
        404,
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

/// Cron handler: touch D1 to keep the connection pool warm and prevent cold starts.
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
}
