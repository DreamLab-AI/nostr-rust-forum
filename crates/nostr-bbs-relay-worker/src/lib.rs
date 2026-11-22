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

mod admin_events;
mod agent_disclosure;
mod audit;
mod auth;
mod cron;
mod ingress;
mod mesh;
mod moderation;
mod nip11;
mod profile_stats;
mod profiles;
mod push;
mod recipient_keys;
mod relay_do;
mod triage;
mod trust;
mod trust_sweep;
mod user_admin;
mod whitelist;
mod zone_config;
mod zone_groups;

/// Re-export so the `worker` crate runtime can discover the Durable Object.
pub use relay_do::NostrRelayDO;

// Test-only public API for integration tests (Sprint v9 Stream-E2).
// Activated by `--features test-exports` for tests in `tests/`.
#[cfg(feature = "test-exports")]
pub mod test_exports {
    pub use crate::relay_do::test_exports::*;
    pub use crate::trust::{compute_trust_level, TrustLevel, TrustThresholds};
}

use nostr_bbs_core::whitelist_sql::WHITELIST_CREATE_SQL;
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

thread_local! {
    /// Set once `ensure_schema` has completed in this isolate. A Worker isolate is
    /// single-threaded, so a thread-local `Cell` is the whole synchronisation.
    static SCHEMA_READY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Latch the once-per-isolate guard after a schema pass. A pass that reported a
/// failed CREATE leaves it open so the next request retries.
fn record_schema_pass(ok: bool) {
    if ok {
        SCHEMA_READY.with(|c| c.set(true));
    }
}

// Invoked via wasm-bindgen by the Workers runtime; appears unused on native
// builds because there is no native caller of the `#[event(fetch)]` glue.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // CORS preflight
    if req.method() == Method::Options {
        return Ok(Response::empty()?
            .with_status(204)
            .with_headers(cors_headers(&req, &env)));
    }

    // Idempotent schema migrations (trust columns, new tables, etc.). Once per
    // isolate, after the preflight short-circuit but BEFORE the WebSocket branch:
    // the Durable Object and `scheduled` never bootstrap the schema, so a
    // WebSocket-only isolate would otherwise never create it.
    if !SCHEMA_READY.with(|c| c.get()) {
        let ok = ensure_schema(&env).await;
        nostr_bbs_rate_limit::ensure_replay_schema(&env, "REPLAY_DB").await;
        record_schema_pass(ok);
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

    // Content-free Web Push (ADR-2023): subscribe, prefs, drain, config.
    if let Some(rest) = path.strip_prefix("/api/push/") {
        return push::handle(req, env, rest).await;
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

    // ADR-2017: silent delete of kind-42 rows by id (NIP-98 admin only). No
    // kind-5 and no broadcast: clients fold a kind-5 into their own tombstones,
    // hiding the id that a sealed original restores. The relay's D1 tombstone
    // is recorded (it is never served to clients). See `admin_events`.
    if path == "/api/admin/events/delete" && method == Method::Post {
        return admin_events::handle_delete_events(req, env).await;
    }

    // --- Moderation endpoints (NIP-98 admin only) ---

    // Jev option (NF-03-S1-01): advisory triage queue (NIP-98 admin only).
    if path == "/api/jev/triage" && method == Method::Get && triage::flag_on(env) {
        return triage::handle_list(&req, env).await;
    }

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

/// The `events` table, as `relay_do/storage.rs` writes it. `d_tag` and
/// `received_at` are inserted on every save, so a table without them fails every
/// write. Held identical to `migrations/0009_events.sql` by a test.
pub const EVENTS_CREATE_SQL: &str = "CREATE TABLE IF NOT EXISTS events (\
    id TEXT PRIMARY KEY, \
    pubkey TEXT NOT NULL, \
    created_at INTEGER NOT NULL, \
    kind INTEGER NOT NULL, \
    tags TEXT NOT NULL, \
    content TEXT NOT NULL, \
    sig TEXT NOT NULL, \
    d_tag TEXT NOT NULL DEFAULT '', \
    received_at INTEGER NOT NULL DEFAULT 0\
)";

/// The creator of each kind-40 channel, persisted when the channel is saved so
/// that a later kind-5 deletion of the kind-40 event cannot strip the creator's
/// kind-41 rights. Held identical to `migrations/0009_events.sql` by a test.
pub const CHANNEL_CREATORS_CREATE_SQL: &str = "CREATE TABLE IF NOT EXISTS channel_creators (\
    channel_id TEXT PRIMARY KEY, \
    pubkey TEXT NOT NULL, \
    created_at INTEGER NOT NULL\
)";

/// NIP-09 tombstones for deleted event ids. A deletion is honoured by deleting
/// the target row; without a record of it, anyone holding the original signed
/// event could publish it again and the relay would store it as new. One row per
/// `(id, author)`: an event id is a hash over the event, its author included, so
/// a row naming the wrong author blocks nothing.
pub const DELETED_EVENTS_CREATE_SQL: &str = "CREATE TABLE IF NOT EXISTS deleted_events (\
    id TEXT NOT NULL, \
    pubkey TEXT NOT NULL, \
    deleted_at INTEGER NOT NULL, \
    PRIMARY KEY (id, pubkey)\
)";

/// NIP-09 tombstones for deleted addresses (`a` refs, `kind:pubkey:d`): versions
/// created at or before `deleted_until` stay deleted; newer ones are accepted.
pub const DELETED_ADDRESSES_CREATE_SQL: &str = "CREATE TABLE IF NOT EXISTS deleted_addresses (\
    kind INTEGER NOT NULL, \
    pubkey TEXT NOT NULL, \
    d_tag TEXT NOT NULL, \
    deleted_until INTEGER NOT NULL, \
    PRIMARY KEY (kind, pubkey, d_tag)\
)";

/// Record an event-id tombstone (`?1` id, `?2` author, `?3` deletion time).
pub const DELETED_EVENT_INSERT_SQL: &str =
    "INSERT OR IGNORE INTO deleted_events (id, pubkey, deleted_at) VALUES (?1, ?2, ?3)";

/// Record an address tombstone, keeping the latest `deleted_until`
/// (`?1` kind, `?2` author, `?3` d-tag, `?4` deletion `created_at`).
pub const DELETED_ADDRESS_UPSERT_SQL: &str =
    "INSERT INTO deleted_addresses (kind, pubkey, d_tag, deleted_until) \
    VALUES (?1, ?2, ?3, ?4) \
    ON CONFLICT (kind, pubkey, d_tag) DO UPDATE SET deleted_until = excluded.deleted_until \
    WHERE excluded.deleted_until > deleted_addresses.deleted_until";

/// Whether a regular event is deleted (`?1` id, `?2` author): its id carries
/// the author's tombstone.
pub const IS_DELETED_ID_SQL: &str =
    "SELECT EXISTS (SELECT 1 FROM deleted_events WHERE id = ?1 AND pubkey = ?2) AS deleted";

/// Whether a (parameterised) replaceable event is deleted (`?1` id, `?2`
/// author, `?3` kind, `?4` d-tag, `?5` created_at): its id is tombstoned, or it
/// is a version no newer than its address's deletion. Only ever bound with a
/// real replaceable kind; regular events use [`IS_DELETED_ID_SQL`].
pub const IS_DELETED_ADDRESSABLE_SQL: &str = "SELECT \
    EXISTS (SELECT 1 FROM deleted_events WHERE id = ?1 AND pubkey = ?2) \
    OR EXISTS (SELECT 1 FROM deleted_addresses WHERE kind = ?3 AND pubkey = ?2 AND d_tag = ?4 AND deleted_until >= ?5) \
    AS deleted";

/// The kind-5 gate's one lookup for a member's `e` targets (`?1` a JSON array
/// of distinct canonical ids, `?2` the signer).
///
/// One row per target that is NOT a stored event of the signer's: either no
/// row (`pubkey` NULL) or another author's. A kind-5 carries up to 2,000 `e`
/// tags and D1 caps bound parameters near 100, so the ids travel as one JSON
/// value through `json_each`, not as an `IN (?, …)` list. `tags` comes back
/// only for kind 1059, the one kind whose foreign rows a member may still own
/// (a wrap to their recipient key), so 2,000 tag blobs never cross the wire.
///
/// Two flags, read only for an id with no row (a row that exists is judged by
/// its author, so neither can launder another author's stored event):
/// - `sealed`: a stored kind-42 names the id in a `sealed` tag (ADR-2017).
///   Deliberately looser than the moderator's envelope match
///   ([`SEALED_ENVELOPES_FOR_SQL`]): for a member it only ever refuses.
/// - `tombstoned`: `deleted_events` holds `(id, signer)`, so the signer's
///   deletion of it was accepted before (a retry, a second device, a
///   re-broadcast). `deleted_events`' primary key is `(id, pubkey)`, so the
///   join adds at most one row per target.
///
/// The `sealed` probe is served by the covering `idx_event_tags_lookup (name,
/// value, event_id)` index; the tombstone join by `deleted_events`' key.
pub const DELETION_TARGETS_CLASSIFY_SQL: &str = "SELECT j.value AS target, \
       e.pubkey AS pubkey, \
       e.kind AS kind, \
       CASE WHEN e.kind = 1059 THEN e.tags END AS tags, \
       CASE WHEN e.id IS NULL THEN EXISTS ( \
           SELECT 1 FROM event_tags t JOIN events s ON s.id = t.event_id \
           WHERE t.name = 'sealed' AND t.value = j.value AND s.kind = 42 \
       ) ELSE 0 END AS sealed, \
       CASE WHEN e.id IS NULL AND d.id IS NOT NULL THEN 1 ELSE 0 END AS tombstoned \
    FROM json_each(?1) j \
    LEFT JOIN events e ON e.id = j.value \
    LEFT JOIN deleted_events d ON d.id = j.value AND d.pubkey = ?2 \
    WHERE e.id IS NULL OR e.pubkey <> ?2";

/// The stored sealed-original envelopes (ADR-2017) that wrap any of the ids in
/// `?1` (a JSON array of lowercase ids), with their authors. A moderator's
/// kind-5 naming an original must remove these, or the original is hidden only
/// on clients that fold the kind-5 while the envelope keeps serving it to
/// everyone else.
///
/// Matched on the envelope's whole wire shape, not the `sealed` tag alone: a
/// `kind = 42` row carrying a well-formed `sealed` tag (64-char value, decimal
/// version) AND a `zk` tag. A kind-42 stored before the ADR-2017 ingest gate
/// could carry a stray `sealed` tag naming any id; without the shape check a
/// moderator deleting that id would take such a post with it. The caller
/// further keeps only rows whose author is an admin, as the ingest gate
/// requires of every envelope.
pub const SEALED_ENVELOPES_FOR_SQL: &str = "SELECT DISTINCT s.id AS id, s.pubkey AS pubkey \
    FROM json_each(?1) j \
    JOIN event_tags t ON t.name = 'sealed' AND t.value = j.value \
    JOIN events s ON s.id = t.event_id AND s.kind = 42 \
    WHERE EXISTS ( \
        SELECT 1 FROM json_each(s.tags) st \
        WHERE json_extract(st.value, '$[0]') = 'sealed' \
          AND json_extract(st.value, '$[1]') = j.value \
          AND json_type(st.value, '$[2]') = 'text' \
          AND json_extract(st.value, '$[2]') <> '' \
          AND json_extract(st.value, '$[2]') NOT GLOB '*[^0-9]*' \
    ) \
    AND EXISTS (SELECT 1 FROM event_tags z WHERE z.event_id = s.id AND z.name = 'zk')";

/// Delete one sealed envelope row (`?1`), and only while it is still kind 42.
pub const SEALED_ENVELOPE_DELETE_SQL: &str = "DELETE FROM events WHERE id = ?1 AND kind = 42";

// Tombstones taken from the stored rows themselves, for moderator and admin
// deletions of someone else's events: report resolution, the ADR-2017 purge, a
// user purge, and a moderator's kind-5 in `process_deletion`; an author's own
// kind-5 there takes the address statement scoped to the signer.
// Reading the author from the row inside the INSERT means the tombstone names
// the event's real author by construction, with no gap between read and write;
// an absent row records nothing. They must run before the row's DELETE.
// `deleted_until` is the deleted version's own `created_at`, clamped to now: an
// older signed version cannot come back as the current one, while the author's
// next version (newer by definition) is accepted. A plain replaceable kind (0,
// 3, 10000-19999) is replaced on `(kind, author)` alone, so its address is keyed
// with an empty d-tag whatever `d` tag the event carried ([`address_d_tag`]).

/// Tombstone the stored event `?1` under its own author (`?2` deletion time).
/// Only a well-formed id (64 lowercase hex) is recorded.
pub const TOMBSTONE_EVENT_ROW_SQL: &str =
    "INSERT OR IGNORE INTO deleted_events (id, pubkey, deleted_at) \
    SELECT id, pubkey, ?2 FROM events \
    WHERE id = ?1 AND length(id) = 64 AND id NOT GLOB '*[^0-9a-f]*'";

/// Address tombstone for the stored event `?1` when it is a (parameterised)
/// replaceable kind (`?2` now, the clamp). Regular kinds record nothing.
pub const TOMBSTONE_EVENT_ROW_ADDRESS_SQL: &str =
    "INSERT INTO deleted_addresses (kind, pubkey, d_tag, deleted_until) \
    SELECT kind, pubkey, CASE WHEN kind >= 30000 THEN d_tag ELSE '' END, MIN(created_at, ?2) FROM events \
    WHERE id = ?1 \
      AND (kind IN (0, 3) OR kind BETWEEN 10000 AND 19999 OR kind BETWEEN 30000 AND 39999) \
    ON CONFLICT (kind, pubkey, d_tag) DO UPDATE SET deleted_until = excluded.deleted_until \
    WHERE excluded.deleted_until > deleted_addresses.deleted_until";

/// [`TOMBSTONE_EVENT_ROW_ADDRESS_SQL`] for an author deleting their own event
/// (`?3` the signer): a row by anyone else records nothing, so a member's
/// kind-5 naming another author's replaceable event cannot tombstone its
/// address.
pub const TOMBSTONE_OWN_EVENT_ROW_ADDRESS_SQL: &str =
    "INSERT INTO deleted_addresses (kind, pubkey, d_tag, deleted_until) \
    SELECT kind, pubkey, CASE WHEN kind >= 30000 THEN d_tag ELSE '' END, MIN(created_at, ?2) FROM events \
    WHERE id = ?1 AND pubkey = ?3 \
      AND (kind IN (0, 3) OR kind BETWEEN 10000 AND 19999 OR kind BETWEEN 30000 AND 39999) \
    ON CONFLICT (kind, pubkey, d_tag) DO UPDATE SET deleted_until = excluded.deleted_until \
    WHERE excluded.deleted_until > deleted_addresses.deleted_until";

/// Tombstone every stored event by author `?1` (`?2` deletion time). Only
/// well-formed ids are recorded.
pub const TOMBSTONE_AUTHOR_ROWS_SQL: &str =
    "INSERT OR IGNORE INTO deleted_events (id, pubkey, deleted_at) \
    SELECT id, pubkey, ?2 FROM events \
    WHERE pubkey = ?1 AND length(id) = 64 AND id NOT GLOB '*[^0-9a-f]*'";

/// Address tombstones for every (parameterised) replaceable address author
/// `?1` holds (`?2` now, the clamp), at the newest stored version of each.
pub const TOMBSTONE_AUTHOR_ROWS_ADDRESS_SQL: &str =
    "INSERT INTO deleted_addresses (kind, pubkey, d_tag, deleted_until) \
    SELECT kind, pubkey, CASE WHEN kind >= 30000 THEN d_tag ELSE '' END AS addr_d, MIN(MAX(created_at), ?2) FROM events \
    WHERE pubkey = ?1 \
      AND (kind IN (0, 3) OR kind BETWEEN 10000 AND 19999 OR kind BETWEEN 30000 AND 39999) \
    GROUP BY kind, pubkey, addr_d \
    ON CONFLICT (kind, pubkey, d_tag) DO UPDATE SET deleted_until = excluded.deleted_until \
    WHERE excluded.deleted_until > deleted_addresses.deleted_until";

/// Backfill event-id tombstones from stored kind-5s, for deletions honoured
/// before the tombstone tables existed. Own-deletion semantics only (the
/// kind-5's author): a moderator's past deletion of someone else's event left
/// no record of that author. Idempotent.
pub const DELETED_EVENTS_BACKFILL_SQL: &str =
    "INSERT OR IGNORE INTO deleted_events (id, pubkey, deleted_at) \
    SELECT json_extract(t.value, '$[1]'), e.pubkey, e.created_at \
    FROM events e, json_each(e.tags) t \
    WHERE e.kind = 5 AND json_extract(t.value, '$[0]') = 'e' \
      AND length(json_extract(t.value, '$[1]')) = 64 \
      AND json_extract(t.value, '$[1]') NOT GLOB '*[^0-9a-f]*'";

/// Backfill address tombstones from stored kind-5s' `a` tags naming their own
/// author, for (parameterised) replaceable kinds only, with an empty d-tag for
/// plain replaceable kinds. Idempotent (keeps the latest deletion time).
pub const DELETED_ADDRESSES_BACKFILL_SQL: &str = "INSERT INTO deleted_addresses (kind, pubkey, d_tag, deleted_until) \
    SELECT CAST(substr(a, 1, instr(a, ':') - 1) AS INTEGER), \
           substr(rest, 1, instr(rest, ':') - 1), \
           CASE WHEN CAST(substr(a, 1, instr(a, ':') - 1) AS INTEGER) >= 30000 \
                THEN substr(rest, instr(rest, ':') + 1) ELSE '' END, \
           MIN(created_at, CAST(strftime('%s', 'now') AS INTEGER)) \
    FROM (SELECT json_extract(t.value, '$[1]') AS a, \
                 substr(json_extract(t.value, '$[1]'), instr(json_extract(t.value, '$[1]'), ':') + 1) AS rest, \
                 e.pubkey AS author, e.created_at AS created_at \
          FROM events e, json_each(e.tags) t \
          WHERE e.kind = 5 AND json_extract(t.value, '$[0]') = 'a') \
    WHERE instr(a, ':') > 1 AND instr(rest, ':') > 1 \
      AND substr(rest, 1, instr(rest, ':') - 1) = author \
      AND substr(a, 1, instr(a, ':') - 1) NOT GLOB '*[^0-9]*' \
      AND (CAST(substr(a, 1, instr(a, ':') - 1) AS INTEGER) IN (0, 3) \
           OR CAST(substr(a, 1, instr(a, ':') - 1) AS INTEGER) BETWEEN 10000 AND 19999 \
           OR CAST(substr(a, 1, instr(a, ':') - 1) AS INTEGER) BETWEEN 30000 AND 39999) \
    ON CONFLICT (kind, pubkey, d_tag) DO UPDATE SET deleted_until = excluded.deleted_until \
    WHERE excluded.deleted_until > deleted_addresses.deleted_until";

/// Re-key plain replaceable address tombstones recorded under a non-empty d-tag
/// (before [`address_d_tag`] existed) onto the empty d-tag, keeping the latest
/// deletion time. Run before [`DELETED_ADDRESSES_PRUNE_PLAIN_D_SQL`]; idempotent.
pub const DELETED_ADDRESSES_REKEY_PLAIN_SQL: &str =
    "INSERT INTO deleted_addresses (kind, pubkey, d_tag, deleted_until) \
    SELECT kind, pubkey, '', MAX(deleted_until) FROM deleted_addresses \
    WHERE kind < 30000 AND d_tag <> '' \
    GROUP BY kind, pubkey \
    ON CONFLICT (kind, pubkey, d_tag) DO UPDATE SET deleted_until = excluded.deleted_until \
    WHERE excluded.deleted_until > deleted_addresses.deleted_until";

/// Drop the plain replaceable rows [`DELETED_ADDRESSES_REKEY_PLAIN_SQL`] has
/// copied: no lookup reads them any more.
pub const DELETED_ADDRESSES_PRUNE_PLAIN_D_SQL: &str =
    "DELETE FROM deleted_addresses WHERE kind < 30000 AND d_tag <> ''";

/// The d-tag an address tombstone is keyed on: the event's own `d` for a
/// parameterised replaceable kind (30000-39999), empty for every other kind,
/// because a plain replaceable event is replaced on `(kind, author)` alone and an
/// old version carrying a different `d` tag must still be covered.
pub fn address_d_tag(kind: u64, d_tag: &str) -> &str {
    if (30_000..40_000).contains(&kind) {
        d_tag
    } else {
        ""
    }
}

/// `settings` key marking [`DELETED_ADDRESSES_REKEY_PLAIN_SQL`] done for this
/// database. Separate from [`TOMBSTONE_BACKFILL_SETTING`], which deployed
/// databases already carry.
pub const PLAIN_ADDRESS_REKEY_SETTING: &str = "nip09_plain_addresses_rekeyed";

/// `settings` key marking the tombstone backfill done for this database.
pub const TOMBSTONE_BACKFILL_SETTING: &str = "nip09_tombstones_backfilled";

/// Broker case aggregate (human-in-the-loop governance decisions). Created ahead
/// of the `ALTER TABLE broker_cases` block so a fresh D1 has a table to alter;
/// the ALTERs then add the ADR-2011 / ADR-2013 columns.
pub const BROKER_CASES_CREATE_SQL: &str = "CREATE TABLE IF NOT EXISTS broker_cases (\
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
        )";

/// Individual decisions on broker cases (append-only audit trail). F6 (DDD §7a):
/// `superseded_by` names the decision that supersedes this row (NULL =
/// current/effective). It is a projection-derived column: the superseding
/// kind-31403 marks the prior row without ever mutating the underlying Nostr
/// event (Invariant 5). Only `ensure_schema` creates it (migration 0002 predates
/// F6), so the SQLite tests build their schema from this constant.
pub const BROKER_DECISIONS_CREATE_SQL: &str = "CREATE TABLE IF NOT EXISTS broker_decisions (\
            decision_id TEXT PRIMARY KEY NOT NULL, \
            case_id TEXT NOT NULL REFERENCES broker_cases(id), \
            outcome TEXT NOT NULL, \
            outcome_detail TEXT, \
            broker_pubkey TEXT NOT NULL, \
            reasoning TEXT NOT NULL DEFAULT '', \
            prior_decision_id TEXT, \
            superseded_by TEXT, \
            decided_at INTEGER NOT NULL\
        )";

/// ADR-2010 durable governance outcome receipts. One row per signed governance
/// event, keyed by the FULL event id, recording the stage the response actually
/// reached. Written at `relay-accepted` right after the envelope is stored;
/// transitions to `projection-committed` inside the same batch as the decision
/// row and case state, so the two can never disagree. `replays` counts
/// redeliveries without re-running the mutation. Created ahead of the ALTERs.
pub const GOVERNANCE_RECEIPTS_CREATE_SQL: &str = "CREATE TABLE IF NOT EXISTS governance_receipts (\
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
            replays INTEGER NOT NULL DEFAULT 0, \
            applied_at INTEGER, \
            applied_by TEXT, \
            acknowledgement TEXT\
        )";

/// Idempotent schema migrations. Returns `true` only when every CREATE succeeded
/// (ALTER errors are expected duplicate-column noise and do not count), so the
/// caller retries on the next request after a transient D1 failure.
///
/// All statements use `IF NOT EXISTS` for tables or silently ignore errors
/// for `ALTER TABLE ADD COLUMN` (D1/SQLite raises an error if the column
/// already exists, which we swallow).
async fn ensure_schema(env: &Env) -> bool {
    let mut ok = true;
    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return false,
    };

    // --- Events table (migration 0009) ---
    // Must precede every ALTER and index below that touches `events`: on a fresh
    // D1 there is otherwise no table, and every save fails. A table created from
    // the older SETUP.md lacks `d_tag` and `received_at`; the ALTERs below add
    // them (errors on an existing column are ignored).
    if let Err(e) = db.prepare(EVENTS_CREATE_SQL).run().await {
        console_error!("ensure_schema: events create failed: {e}");
        ok = false;
    }
    if let Err(e) = db.prepare(CHANNEL_CREATORS_CREATE_SQL).run().await {
        console_error!("ensure_schema: channel_creators create failed: {e}");
        ok = false;
    }
    // NIP-09 tombstones, so a deleted event cannot be published again. The
    // one-time backfill from stored kind-5s runs at the end, once per database.
    // A failure here leaves ingest working, just without the re-insert refusal.
    for (what, sql) in [
        ("deleted_events create", DELETED_EVENTS_CREATE_SQL),
        ("deleted_addresses create", DELETED_ADDRESSES_CREATE_SQL),
    ] {
        if let Err(e) = db.prepare(sql).run().await {
            console_error!("ensure_schema: {what} failed: {e}");
        }
    }
    for stmt in [
        "ALTER TABLE events ADD COLUMN d_tag TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE events ADD COLUMN received_at INTEGER NOT NULL DEFAULT 0",
    ] {
        let _ = db.prepare(stmt).run().await;
    }

    // --- Whitelist table (ADR-2014 phase 1, migration 0008) ---
    // Must precede the ALTERs below: on a fresh D1 there is otherwise no table
    // for them to alter, and admission and every whitelist write fail.
    if let Err(e) = db.prepare(WHITELIST_CREATE_SQL).run().await {
        console_error!("ensure_schema: whitelist create failed: {e}");
        ok = false;
    }

    // --- Web Push tables (ADR-2023, migration 0010) ---
    // Only when the feature is on, so a default deploy pays nothing per request.
    if push::enabled(env) {
        for stmt in push::PUSH_SCHEMA_SQL {
            if let Err(e) = db.prepare(stmt).run().await {
                console_error!("ensure_schema: push table failed: {e}");
                ok = false;
            }
        }
        // A deployment that created the table before the DM budget columns.
        for stmt in push::PUSH_ALTER_SQL {
            let _ = db.prepare(stmt).run().await;
        }
    }

    // --- Recipient keys (Phase 2, migration 0012) ---
    // Only when the feature is on, so a default deploy pays nothing per request.
    let zone_groups_on = zone_groups::zone_groups_enabled_var(
        env.var(zone_groups::ZONE_GROUPS_ENABLED_VAR)
            .ok()
            .map(|v| v.to_string())
            .as_deref(),
    );
    // ZONE_GROUPS_ENABLED also needs the table: it holds the `epoch` rows.
    if zone_groups_on
        || recipient_keys::recipient_keys_enabled_var(
            env.var(recipient_keys::RECIPIENT_KEYS_ENABLED_VAR)
                .ok()
                .map(|v| v.to_string())
                .as_deref(),
        )
    {
        for stmt in [
            recipient_keys::RECIPIENT_KEYS_CREATE_SQL,
            recipient_keys::RECIPIENT_KEYS_INDEX_SQL,
        ] {
            if let Err(e) = db.prepare(stmt).run().await {
                console_error!("ensure_schema: recipient_keys create failed: {e}");
                ok = false;
            }
        }
        // Migration 0012: a database created before the `proof` column existed.
        // A duplicate-column error is the expected outcome everywhere else and
        // does not count against `ok`, like the other ALTERs in this function.
        let _ = db
            .prepare(recipient_keys::RECIPIENT_KEYS_ADD_PROOF_SQL)
            .run()
            .await;
    }

    // --- Zone epoch keys (Phase 4b, migration 0014) ---
    if zone_groups_on {
        if let Err(e) = db
            .prepare(zone_groups::ZONE_EPOCH_KEYS_CREATE_SQL)
            .run()
            .await
        {
            console_error!("ensure_schema: zone_epoch_keys create failed: {e}");
            ok = false;
        }
    }

    // --- Governance tables (broker_cases, governance_receipts) ---
    // Must precede the ALTERs below for the same reason as events/whitelist: on a
    // fresh D1 the ALTERs otherwise fail and the effective_tier index is skipped.
    for (name, sql) in [
        ("broker_cases", BROKER_CASES_CREATE_SQL),
        ("broker_decisions", BROKER_DECISIONS_CREATE_SQL),
        ("governance_receipts", GOVERNANCE_RECEIPTS_CREATE_SQL),
    ] {
        if let Err(e) = db.prepare(sql).run().await {
            console_error!("ensure_schema: {name} create failed: {e}");
            ok = false;
        }
    }

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
        // Read by admission (`expires_at IS NULL OR expires_at > now`) but, until
        // ADR-2014 phase 1, created by no DDL in the repository.
        "ALTER TABLE whitelist ADD COLUMN expires_at INTEGER",
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
        if let Err(e) = db.prepare(stmt).run().await {
            console_error!("ensure_schema: create failed: {e}");
            ok = false;
        }
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
        "CREATE INDEX IF NOT EXISTS idx_events_pubkey ON events(pubkey)",
        "CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_events_replaceable ON events(kind, pubkey, d_tag)",
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
    backfill_tombstones_once(&db).await;
    rekey_plain_addresses_once(&db).await;
    ok
}

/// Whether the one-off `settings` marker `key` is already set. A failed read
/// answers `true`, so a migration is skipped rather than run blind.
async fn setting_marked(db: &worker::D1Database, key: &str) -> bool {
    #[derive(serde::Deserialize)]
    struct Row {
        #[allow(dead_code)]
        value: String,
    }
    match db
        .prepare("SELECT value FROM settings WHERE key = ?1 LIMIT 1")
        .bind(&[key.into()])
    {
        Ok(s) => !matches!(s.first::<Row>(None).await, Ok(None)),
        Err(_) => true,
    }
}

/// Set the one-off `settings` marker `key`.
async fn mark_setting(db: &worker::D1Database, key: &str) {
    if let Ok(s) = db
        .prepare("INSERT OR IGNORE INTO settings (key, value, type, category) VALUES (?1, '1', 'string', 'system')")
        .bind(&[key.into()])
    {
        let _ = s.run().await;
    }
}

/// Re-key plain replaceable address tombstones onto the empty d-tag, once per
/// database: every write since keys them that way, so the scan is not worth
/// repeating on each cold isolate. The prune runs only after the re-key has
/// landed (or the rows would be lost), and the marker only after both.
async fn rekey_plain_addresses_once(db: &worker::D1Database) {
    if setting_marked(db, PLAIN_ADDRESS_REKEY_SETTING).await {
        return;
    }
    for (what, sql) in [
        (
            "deleted_addresses re-key",
            DELETED_ADDRESSES_REKEY_PLAIN_SQL,
        ),
        (
            "deleted_addresses prune",
            DELETED_ADDRESSES_PRUNE_PLAIN_D_SQL,
        ),
    ] {
        if let Err(e) = db.prepare(sql).run().await {
            console_error!("ensure_schema: {what} failed: {e}");
            return;
        }
    }
    mark_setting(db, PLAIN_ADDRESS_REKEY_SETTING).await;
}

/// Backfill NIP-09 tombstones from the kind-5s already stored, once per
/// database (marked in `settings`), so the scan is not repeated on every cold
/// isolate. The marker is written only after both statements succeed.
async fn backfill_tombstones_once(db: &worker::D1Database) {
    #[derive(serde::Deserialize)]
    struct Row {
        #[allow(dead_code)]
        value: String,
    }
    let marked = match db
        .prepare("SELECT value FROM settings WHERE key = ?1 LIMIT 1")
        .bind(&[TOMBSTONE_BACKFILL_SETTING.into()])
    {
        Ok(s) => matches!(s.first::<Row>(None).await, Ok(Some(_))),
        Err(_) => return,
    };
    if marked {
        return;
    }
    for (what, sql) in [
        ("deleted_events backfill", DELETED_EVENTS_BACKFILL_SQL),
        ("deleted_addresses backfill", DELETED_ADDRESSES_BACKFILL_SQL),
    ] {
        if let Err(e) = db.prepare(sql).run().await {
            console_error!("ensure_schema: {what} failed: {e}");
            return;
        }
    }
    if let Ok(s) = db
        .prepare("INSERT OR IGNORE INTO settings (key, value, type, category) VALUES (?1, '1', 'string', 'system')")
        .bind(&[TOMBSTONE_BACKFILL_SETTING.into()])
    {
        let _ = s.run().await;
    }
}

/// Stored rows a deletion route is about to remove.
#[derive(Debug, Clone, Copy)]
pub(crate) enum TombstoneTarget<'a> {
    /// One event, by id, of any kind.
    Event(&'a str),
    /// One event, by id, that the caller has already read as a regular kind:
    /// it has no address, so only the id statement runs (one D1 query, not two,
    /// which matters to a route deleting hundreds of ids per invocation).
    RegularEvent(&'a str),
    /// Every event by one author.
    Author(&'a str),
    /// The address of one event, by id, only if `author` wrote it: an
    /// author's own kind-5, whose id tombstone the caller has already written
    /// under the signer.
    OwnEventAddress {
        /// The event id.
        id: &'a str,
        /// The signer, who must be the stored row's author.
        author: &'a str,
    },
}

impl<'a> TombstoneTarget<'a> {
    /// The statements for this target, the key they bind as `?1` (`?2` is the
    /// deletion time), and the author they bind as `?3`, if any.
    fn statements(&self) -> (&'a str, &'static [&'static str], Option<&'a str>) {
        match *self {
            TombstoneTarget::Event(id) => (
                id,
                &[TOMBSTONE_EVENT_ROW_SQL, TOMBSTONE_EVENT_ROW_ADDRESS_SQL],
                None,
            ),
            TombstoneTarget::RegularEvent(id) => (id, &[TOMBSTONE_EVENT_ROW_SQL], None),
            TombstoneTarget::Author(pubkey) => (
                pubkey,
                &[TOMBSTONE_AUTHOR_ROWS_SQL, TOMBSTONE_AUTHOR_ROWS_ADDRESS_SQL],
                None,
            ),
            TombstoneTarget::OwnEventAddress { id, author } => {
                (id, &[TOMBSTONE_OWN_EVENT_ROW_ADDRESS_SQL], Some(author))
            }
        }
    }
}

/// Record NIP-09 tombstones for `target`'s stored rows, so deleted content
/// cannot be published again. Call it before the DELETE (it
/// reads the rows), and never in the same `batch` as the DELETE: D1 batches are
/// transactional, and a failed tombstone must not undo the deletion.
///
/// Returns whether every statement ran. Callers report it but never act on it:
/// the tombstone is a re-insert guard, so a failure must not block the deletion.
pub(crate) async fn tombstone_before_delete(
    db: &worker::D1Database,
    target: TombstoneTarget<'_>,
    now: u64,
) -> bool {
    let (key, statements, author) = target.statements();
    let mut binds = vec![key.into(), wasm_bindgen::JsValue::from_f64(now as f64)];
    binds.extend(author.map(wasm_bindgen::JsValue::from_str));
    let mut all_ran = true;
    for sql in statements {
        let bound = db.prepare(*sql).bind(&binds);
        match bound {
            Ok(stmt) => {
                if let Err(e) = stmt.run().await {
                    console_error!("tombstone for {target:?} failed: {e}");
                    all_ran = false;
                }
            }
            Err(e) => {
                console_error!("tombstone for {target:?} failed to bind: {e}");
                all_ran = false;
            }
        }
    }
    all_ran
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

    // ADR-2023: drop push subscriptions the app stopped refreshing.
    push::sweep_stale(&env).await;
    // ADR-2023: wake devices whose burst was throttled and never got its push.
    push::flush_pending(&env).await;

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

    // Jev option (NF-03-S1-01): advisory moderation triage of already-admitted
    // public posts. Off by default; a no-op without touching D1 when the flag
    // is off. Fail-open: it can never break the tick.
    triage::run_sweep(&env).await;
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
mod schema_order_tests {
    use super::{BROKER_CASES_CREATE_SQL, GOVERNANCE_RECEIPTS_CREATE_SQL, SCHEMA_READY};

    #[test]
    fn governance_tables_exist_for_the_alters_and_the_tier_index() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute(BROKER_CASES_CREATE_SQL, []).unwrap();
        conn.execute(GOVERNANCE_RECEIPTS_CREATE_SQL, []).unwrap();
        // Idempotent on a second pass.
        conn.execute(BROKER_CASES_CREATE_SQL, []).unwrap();
        // The statements that failed on a fresh D1 when the tables came later.
        conn.execute(
            "ALTER TABLE broker_cases ADD COLUMN effective_tier TEXT",
            [],
        )
        .unwrap();
        // The CREATE already carries the provenance columns, so the live ALTER is a
        // harmless duplicate-column error (discarded by ensure_schema).
        assert!(conn
            .execute(
                "ALTER TABLE governance_receipts ADD COLUMN applied_at INTEGER",
                []
            )
            .is_err());
        conn.prepare("SELECT applied_at, applied_by, acknowledgement FROM governance_receipts")
            .unwrap();
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_broker_cases_effective_tier ON broker_cases(effective_tier)",
            [],
        )
        .unwrap();
    }

    #[test]
    fn schema_guard_is_per_isolate_and_starts_unset() {
        assert!(!SCHEMA_READY.with(|c| c.get()));
        super::record_schema_pass(false);
        assert!(
            !SCHEMA_READY.with(|c| c.get()),
            "a failed pass must be retried"
        );
        super::record_schema_pass(true);
        assert!(SCHEMA_READY.with(|c| c.get()));
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

#[cfg(test)]
mod tombstone_tests {
    use super::*;
    use rusqlite::{params, Connection};

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const ID1: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(EVENTS_CREATE_SQL).unwrap();
        c.execute_batch(DELETED_EVENTS_CREATE_SQL).unwrap();
        c.execute_batch(DELETED_ADDRESSES_CREATE_SQL).unwrap();
        c
    }

    fn deleted(c: &Connection, id: &str, pk: &str, kind: i64, d: &str, at: i64) -> bool {
        // kind < 0 stands for "a regular event", as the relay routes it.
        let n: i64 = if kind < 0 {
            c.query_row(IS_DELETED_ID_SQL, params![id, pk], |r| r.get(0))
        } else {
            c.query_row(
                IS_DELETED_ADDRESSABLE_SQL,
                params![id, pk, kind, d, at],
                |r| r.get(0),
            )
        }
        .unwrap();
        n != 0
    }

    #[test]
    fn a_tombstoned_id_is_deleted_for_its_author_only() {
        let c = db();
        c.execute(DELETED_EVENT_INSERT_SQL, params![ID1, A, 100])
            .unwrap();
        assert!(deleted(&c, ID1, A, -1, "", 50));
        assert!(
            !deleted(&c, ID1, B, -1, "", 50),
            "a claim for another author blocks nothing"
        );
        assert!(!deleted(&c, &"2".repeat(64), A, -1, "", 50));
        c.execute(DELETED_EVENT_INSERT_SQL, params![ID1, A, 200])
            .unwrap();
    }

    #[test]
    fn an_address_tombstone_covers_versions_up_to_the_deletion() {
        let c = db();
        c.execute(DELETED_ADDRESS_UPSERT_SQL, params![30023, A, "post", 100])
            .unwrap();
        assert!(
            deleted(&c, ID1, A, 30023, "post", 100),
            "same second is deleted"
        );
        assert!(deleted(&c, ID1, A, 30023, "post", 99));
        assert!(
            !deleted(&c, ID1, A, 30023, "post", 101),
            "a newer version is accepted"
        );
        assert!(!deleted(&c, ID1, A, 30023, "other", 50));
        assert!(!deleted(&c, ID1, B, 30023, "post", 50));
        assert!(
            !deleted(&c, ID1, A, -1, "post", 50),
            "a regular event never matches an address"
        );
        // A later deletion extends it; an earlier one never shortens it.
        c.execute(DELETED_ADDRESS_UPSERT_SQL, params![30023, A, "post", 300])
            .unwrap();
        c.execute(DELETED_ADDRESS_UPSERT_SQL, params![30023, A, "post", 10])
            .unwrap();
        assert!(deleted(&c, ID1, A, 30023, "post", 250));
    }

    #[test]
    fn a_negative_kind_address_row_never_blocks_regular_events() {
        // The relay refuses such a-refs before recording, but even a stray
        // row cannot match: regular events are checked on (id, author) only.
        let c = db();
        c.execute(DELETED_ADDRESS_UPSERT_SQL, params![-1, A, "", 10_000])
            .unwrap();
        assert!(!deleted(&c, ID1, A, -1, "", 5));
    }

    #[test]
    fn the_address_upsert_only_moves_forward() {
        let c = db();
        c.execute(DELETED_ADDRESS_UPSERT_SQL, params![30023, A, "p", 100])
            .unwrap();
        c.execute(DELETED_ADDRESS_UPSERT_SQL, params![30023, A, "p", 50])
            .unwrap();
        let until: i64 = c
            .query_row("SELECT deleted_until FROM deleted_addresses", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(until, 100);
    }

    fn kind5(c: &Connection, id: &str, author: &str, at: i64, tags: &str) {
        c.execute(
            "INSERT INTO events (id, pubkey, created_at, kind, tags, content, sig) VALUES (?1, ?2, ?3, 5, ?4, '', 's')",
            params![id, author, at, tags],
        )
        .unwrap();
    }

    fn store(c: &Connection, id: &str, author: &str, kind: i64, d: &str, at: i64) {
        c.execute(
            "INSERT INTO events (id, pubkey, created_at, kind, tags, content, sig, d_tag) VALUES (?1, ?2, ?3, ?4, '[]', 'c', 's', ?5)",
            params![id, author, at, kind, d],
        )
        .unwrap();
    }

    /// `deleted_events` rows as `(id, author, deleted_at)`.
    type EventTombstones = Vec<(String, String, i64)>;
    /// `deleted_addresses` rows as `(kind, author, d_tag, deleted_until)`.
    type AddressTombstones = Vec<(i64, String, String, i64)>;

    fn tombstone_rows(c: &Connection) -> (EventTombstones, AddressTombstones) {
        let events = c
            .prepare("SELECT id, pubkey, deleted_at FROM deleted_events ORDER BY id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let addresses = c
            .prepare("SELECT kind, pubkey, d_tag, deleted_until FROM deleted_addresses ORDER BY kind, d_tag")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        (events, addresses)
    }

    /// What the deletion routes do: tombstone from the row, then delete it.
    fn tombstone_then_delete(c: &Connection, target: TombstoneTarget<'_>, now: i64) {
        let (key, statements, author) = target.statements();
        for sql in statements {
            match author {
                Some(author) => c.execute(sql, params![key, now, author]),
                None => c.execute(sql, params![key, now]),
            }
            .unwrap();
        }
        match target {
            TombstoneTarget::Event(_) | TombstoneTarget::RegularEvent(_) => {
                c.execute("DELETE FROM events WHERE id = ?1", params![key])
            }
            TombstoneTarget::Author(_) => {
                c.execute("DELETE FROM events WHERE pubkey = ?1", params![key])
            }
            // The member's own DELETE is scoped to their pubkey, as in
            // `process_deletion`.
            TombstoneTarget::OwnEventAddress { id, author } => c.execute(
                "DELETE FROM events WHERE id = ?1 AND pubkey = ?2",
                params![id, author],
            ),
        }
        .unwrap();
    }

    /// The ingest lookup as `is_deleted` binds it: the address d-tag, not the
    /// event's raw `d`.
    fn ingest_deleted(c: &Connection, id: &str, pk: &str, kind: u64, d: &str, at: i64) -> bool {
        deleted(c, id, pk, kind as i64, address_d_tag(kind, d), at)
    }

    #[test]
    fn the_address_d_tag_is_empty_below_the_parameterised_range() {
        for kind in [0, 3, 10_002, 19_999, 1, 42, 29_999, 40_000] {
            assert_eq!(address_d_tag(kind, "x"), "", "kind {kind}");
        }
        for kind in [30_000, 30_023, 39_999] {
            assert_eq!(address_d_tag(kind, "x"), "x", "kind {kind}");
        }
    }

    #[test]
    fn a_plain_replaceable_row_is_tombstoned_whatever_d_tag_it_carried() {
        let c = db();
        store(&c, ID1, A, 0, "stray", 500);
        tombstone_then_delete(&c, TombstoneTarget::Event(ID1), 1_000);
        let (_, addresses) = tombstone_rows(&c);
        assert_eq!(addresses, vec![(0, A.to_string(), String::new(), 500)]);
        let older = "2".repeat(64);
        assert!(
            ingest_deleted(&c, &older, A, 0, "", 400),
            "an older version without a d tag"
        );
        assert!(
            ingest_deleted(&c, &older, A, 0, "other", 400),
            "an older version with a different d tag"
        );
        assert!(!ingest_deleted(&c, &older, A, 0, "other", 501));
    }

    #[test]
    fn a_parameterised_replaceable_keeps_its_own_d_tag() {
        let c = db();
        store(&c, ID1, A, 30023, "post", 500);
        tombstone_then_delete(&c, TombstoneTarget::Event(ID1), 1_000);
        let older = "2".repeat(64);
        assert!(ingest_deleted(&c, &older, A, 30023, "post", 400));
        assert!(
            !ingest_deleted(&c, &older, A, 30023, "other", 400),
            "another address of the same kind is untouched"
        );
    }

    #[test]
    fn an_author_purge_folds_plain_replaceable_d_tags_into_one_address() {
        let c = db();
        store(&c, ID1, A, 10002, "", 100);
        store(&c, &"2".repeat(64), A, 10002, "stray", 300);
        tombstone_then_delete(&c, TombstoneTarget::Author(A), 1_000);
        let (_, addresses) = tombstone_rows(&c);
        assert_eq!(addresses, vec![(10002, A.to_string(), String::new(), 300)]);
    }

    #[test]
    fn a_regular_event_target_runs_the_id_statement_only() {
        let (key, statements, author) = TombstoneTarget::RegularEvent(ID1).statements();
        assert_eq!(
            (key, statements, author),
            (ID1, &[TOMBSTONE_EVENT_ROW_SQL][..], None)
        );
        let c = db();
        store(&c, ID1, B, 42, "", 50);
        tombstone_then_delete(&c, TombstoneTarget::RegularEvent(ID1), 1_000);
        assert_eq!(
            tombstone_rows(&c),
            (vec![(ID1.to_string(), B.to_string(), 1_000)], vec![])
        );
    }

    #[test]
    fn an_authors_own_deletion_tombstones_the_address_of_their_replaceable() {
        let c = db();
        store(&c, ID1, A, 30023, "post", 500);
        // The signer's id claim, as `process_deletion` writes it first.
        c.execute(DELETED_EVENT_INSERT_SQL, params![ID1, A, 1_000])
            .unwrap();
        tombstone_then_delete(
            &c,
            TombstoneTarget::OwnEventAddress { id: ID1, author: A },
            1_000,
        );
        let (_, addresses) = tombstone_rows(&c);
        assert_eq!(
            addresses,
            vec![(30023, A.to_string(), "post".to_string(), 500)]
        );
        let older = "2".repeat(64);
        assert!(
            ingest_deleted(&c, &older, A, 30023, "post", 400),
            "an older signed version cannot be stored again"
        );
        assert!(!ingest_deleted(&c, &older, A, 30023, "post", 501));
    }

    #[test]
    fn an_own_deletion_naming_another_authors_event_records_no_address() {
        let c = db();
        store(&c, ID1, B, 0, "", 500);
        tombstone_then_delete(
            &c,
            TombstoneTarget::OwnEventAddress { id: ID1, author: A },
            1_000,
        );
        assert_eq!(tombstone_rows(&c), (vec![], vec![]));
        let left: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 1, "and the row, not the signer's, stays");
    }

    #[test]
    fn backfill_keys_plain_replaceable_a_refs_on_an_empty_d_tag() {
        let c = db();
        let tags = format!(r#"[["a","0:{A}:stray"],["a","10002:{A}:"],["a","30023:{A}:post"]]"#);
        kind5(&c, &"5".repeat(64), A, 100, &tags);
        c.execute_batch(DELETED_ADDRESSES_BACKFILL_SQL).unwrap();
        let (_, addresses) = tombstone_rows(&c);
        assert_eq!(
            addresses,
            vec![
                (0, A.to_string(), String::new(), 100),
                (10002, A.to_string(), String::new(), 100),
                (30023, A.to_string(), "post".to_string(), 100),
            ]
        );
    }

    #[test]
    fn the_rekey_moves_plain_replaceable_rows_onto_the_empty_d_tag() {
        let c = db();
        for (kind, d, until) in [
            (0, "x", 50),
            (0, "y", 80),
            (0, "", 60),
            (3, "z", 20),
            (30023, "post", 10),
        ] {
            c.execute(DELETED_ADDRESS_UPSERT_SQL, params![kind, A, d, until])
                .unwrap();
        }
        for _ in 0..2 {
            c.execute_batch(DELETED_ADDRESSES_REKEY_PLAIN_SQL).unwrap();
            c.execute_batch(DELETED_ADDRESSES_PRUNE_PLAIN_D_SQL)
                .unwrap();
        }
        let (_, addresses) = tombstone_rows(&c);
        assert_eq!(
            addresses,
            vec![
                (0, A.to_string(), String::new(), 80),
                (3, A.to_string(), String::new(), 20),
                (30023, A.to_string(), "post".to_string(), 10),
            ],
            "latest deletion kept, parameterised rows untouched, idempotent"
        );
    }

    #[test]
    fn a_row_tombstone_names_the_stored_author_and_blocks_the_republish() {
        let c = db();
        store(&c, ID1, B, 42, "", 50);
        tombstone_then_delete(&c, TombstoneTarget::Event(ID1), 1_000);
        assert_eq!(
            tombstone_rows(&c),
            (vec![(ID1.to_string(), B.to_string(), 1_000)], vec![]),
            "the row's author, and no address for a regular kind"
        );
        assert!(deleted(&c, ID1, B, -1, "", 50));
        assert!(!deleted(&c, ID1, A, -1, "", 50));
    }

    #[test]
    fn a_row_tombstone_records_nothing_for_an_absent_or_malformed_id() {
        let c = db();
        let upper = ID1.replace('1', "F");
        store(&c, &upper, A, 1, "", 50);
        store(&c, "short", A, 1, "", 50);
        for id in [ID1, upper.as_str(), "short"] {
            tombstone_then_delete(&c, TombstoneTarget::Event(id), 1_000);
        }
        assert_eq!(tombstone_rows(&c), (vec![], vec![]));
        let left: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 0, "the deletion goes ahead regardless");
    }

    #[test]
    fn a_replaceable_row_also_tombstones_its_address_up_to_that_version() {
        let c = db();
        store(&c, ID1, A, 30023, "post", 500);
        tombstone_then_delete(&c, TombstoneTarget::Event(ID1), 1_000);
        let (_, addresses) = tombstone_rows(&c);
        assert_eq!(
            addresses,
            vec![(30023, A.to_string(), "post".to_string(), 500)]
        );
        let older = "2".repeat(64);
        assert!(
            deleted(&c, &older, A, 30023, "post", 400),
            "an older signed version cannot come back as the current one"
        );
        assert!(
            !deleted(&c, &older, A, 30023, "post", 501),
            "the author's next version is accepted"
        );
        assert!(deleted(&c, ID1, A, 30023, "post", 500));
    }

    #[test]
    fn a_future_dated_replaceable_row_clamps_its_address_to_now() {
        let c = db();
        store(&c, ID1, A, 0, "", 2_000);
        tombstone_then_delete(&c, TombstoneTarget::Event(ID1), 1_000);
        let (events, addresses) = tombstone_rows(&c);
        assert_eq!(addresses, vec![(0, A.to_string(), String::new(), 1_000)]);
        assert_eq!(events.len(), 1, "the exact version stays covered by its id");
        assert!(deleted(&c, ID1, A, 0, "", 2_000));
        assert!(!deleted(&c, &"2".repeat(64), A, 0, "", 1_500));
    }

    #[test]
    fn an_address_row_tombstone_never_shortens_a_later_deletion() {
        let c = db();
        c.execute(DELETED_ADDRESS_UPSERT_SQL, params![30023, A, "post", 900])
            .unwrap();
        store(&c, ID1, A, 30023, "post", 500);
        tombstone_then_delete(&c, TombstoneTarget::Event(ID1), 1_000);
        let (_, addresses) = tombstone_rows(&c);
        assert_eq!(
            addresses,
            vec![(30023, A.to_string(), "post".to_string(), 900)]
        );
    }

    #[test]
    fn an_author_purge_tombstones_every_row_of_that_author_only() {
        let c = db();
        let (id2, id3, id4) = ("2".repeat(64), "3".repeat(64), "4".repeat(64));
        store(&c, ID1, A, 1, "", 10);
        store(&c, &id2, A, 0, "", 20);
        store(&c, &id3, A, 30023, "post", 30);
        store(&c, "short", A, 1, "", 40);
        store(&c, &id4, B, 1, "", 50);
        tombstone_then_delete(&c, TombstoneTarget::Author(A), 1_000);
        let (events, addresses) = tombstone_rows(&c);
        let ids: Vec<&str> = events.iter().map(|(id, _, _)| id.as_str()).collect();
        assert_eq!(ids, vec![ID1, id2.as_str(), id3.as_str()]);
        assert!(events.iter().all(|(_, pk, at)| pk == A && *at == 1_000));
        assert_eq!(
            addresses,
            vec![
                (0, A.to_string(), String::new(), 20),
                (30023, A.to_string(), "post".to_string(), 30),
            ]
        );
        assert!(deleted(&c, ID1, A, -1, "", 10));
        assert!(
            !deleted(&c, &id4, B, -1, "", 50),
            "another author is untouched"
        );
        let left: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 1);
    }

    #[test]
    fn an_author_purge_takes_the_newest_version_per_address() {
        let c = db();
        // Supersession keeps one row per address, but a race can leave two.
        store(&c, ID1, A, 30023, "post", 100);
        store(&c, &"2".repeat(64), A, 30023, "post", 300);
        store(&c, &"3".repeat(64), A, 30023, "other", 5_000);
        tombstone_then_delete(&c, TombstoneTarget::Author(A), 1_000);
        let (_, addresses) = tombstone_rows(&c);
        assert_eq!(
            addresses,
            vec![
                (30023, A.to_string(), "other".to_string(), 1_000),
                (30023, A.to_string(), "post".to_string(), 300),
            ]
        );
    }

    #[test]
    fn backfill_records_own_deletions_from_stored_kind5s_and_is_idempotent() {
        let c = db();
        let upper = ID1.replace('1', "F");
        let tags = format!(
            r#"[["e","{ID1}"],["e","short"],["e","{upper}"],["k","1"],["a","30023:{A}:post"],["a","30023:{B}:theirs"],["a","1:{A}:"],["a","-1:{A}:"],["a","3x:{A}:"]]"#
        );
        kind5(&c, &"5".repeat(64), A, 100, &tags);
        for _ in 0..2 {
            c.execute_batch(DELETED_EVENTS_BACKFILL_SQL).unwrap();
            c.execute_batch(DELETED_ADDRESSES_BACKFILL_SQL).unwrap();
        }
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM deleted_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "only the well-formed lowercase-hex e tag, once");
        assert!(deleted(&c, ID1, A, -1, "", 1));
        let addrs: Vec<(i64, String, String, i64)> = c
            .prepare("SELECT kind, pubkey, d_tag, deleted_until FROM deleted_addresses")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            addrs,
            vec![(30023, A.to_string(), "post".to_string(), 100)],
            "own addressable refs only: not another author's, a regular kind, or a malformed kind"
        );
    }
}
