//! nostr-bbs Auth Worker (Rust)
//!
//! WebAuthn registration/authentication + NIP-98 verification + pod provisioning.
//! Port of `workers/auth-api/index.ts` (510 lines).
//!
//! ## Architecture
//!
//! - `lib.rs` -- Router, CORS, entry point
//! - `webauthn.rs` -- WebAuthn registration + authentication handlers
//! - `pod.rs` -- Pod provisioning and profile retrieval
//! - `auth.rs` -- NIP-98 verification wrapper

// Worker entry points are invoked via wasm-bindgen and appear unused in native builds.
#![allow(dead_code)]

mod admin;
mod admins;
mod auth;
mod crypto;
mod delegation;
mod did;
mod governance_api;
mod http;
mod invites;
mod moderation;
mod pod;
mod schema;
mod username;
mod webauthn;
mod welcome;
mod wot;

use worker::*;

/// Build CORS headers from the `EXPECTED_ORIGIN` env var.
fn cors_headers(env: &Env) -> Headers {
    let origin = env
        .var("EXPECTED_ORIGIN")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "https://example.com".to_string());

    let headers = Headers::new();
    headers.set("Access-Control-Allow-Origin", &origin).ok();
    headers
        .set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        .ok();
    headers
        .set(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization",
        )
        .ok();
    headers.set("Access-Control-Max-Age", "86400").ok();
    headers
}

/// Create a JSON error response that NEVER masks failures with an empty 200.
///
/// If the primary `Response::ok` builder fails (it never has in practice),
/// fall through to `Response::error(...)` and unwrap with `expect` so any
/// actual breakage is visible at the runtime layer instead of being silently
/// turned into a 200 with an empty body.
fn error_response(env: &Env, message: &str, status: u16) -> Response {
    let body = format!(r#"{{"error":"{}"}}"#, message.replace('"', r#"\""#));
    let cors = cors_headers(env);
    match Response::ok(&body) {
        Ok(resp) => {
            let resp = resp.with_status(status).with_headers(cors);
            resp.headers().set("Content-Type", "application/json").ok();
            resp
        }
        Err(_) => {
            // Hard error path. `Response::error` only fails if the static
            // string allocation fails, which would mean the worker is in a
            // worse state than this branch can reasonably recover from.
            Response::error("internal", 500).expect("static error response")
        }
    }
}

/// Create a JSON response with CORS headers.
fn json_response(env: &Env, body: &serde_json::Value, status: u16) -> Result<Response> {
    let json_str = serde_json::to_string(body).map_err(|e| Error::RustError(e.to_string()))?;
    let cors = cors_headers(env);
    let resp = Response::ok(json_str)?
        .with_status(status)
        .with_headers(cors);
    resp.headers().set("Content-Type", "application/json").ok();
    Ok(resp)
}

/// Attach CORS headers to an existing response.
fn with_cors(resp: Response, env: &Env) -> Response {
    let cors = cors_headers(env);
    resp.with_headers(cors)
}

// ---------------------------------------------------------------------------
// Typed route error (P2-05: replaces string-contains classification)
// ---------------------------------------------------------------------------

/// Typed error for route handler failures, mapping each variant to an HTTP
/// status code. Replaces the previous string-contains error classification
/// that matched on Debug representations of `worker::Error`.
#[derive(Debug)]
enum RouteError {
    /// Client sent an invalid request body (bad JSON, missing fields, etc.)
    BadRequest(String),
    /// Internal server error (DB failure, unexpected state, etc.)
    Internal(String),
}

impl RouteError {
    fn status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::Internal(_) => 500,
        }
    }

    fn user_message(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "Invalid request body",
            Self::Internal(_) => "Internal server error",
        }
    }
}

impl From<worker::Error> for RouteError {
    fn from(e: worker::Error) -> Self {
        match &e {
            Error::SerdeJsonError(_) | Error::BadEncoding => Self::BadRequest(format!("{e:?}")),
            Error::RustError(msg) if is_client_error(msg) => Self::BadRequest(format!("{e:?}")),
            _ => Self::Internal(format!("{e:?}")),
        }
    }
}

/// Heuristic check for whether a RustError message represents a client error.
fn is_client_error(msg: &str) -> bool {
    msg.starts_with("Invalid JSON")
        || msg.starts_with("Invalid request")
        || msg.starts_with("parse:")
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // Wrap the entire handler so NO errors ever leak to the workers-rs framework.
    // The framework formats leaked errors as raw Debug text (e.g. SerializationError(...))
    // which is not valid JSON and confuses clients.
    match handle_request(req, &env).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            console_error!("Unhandled worker error: {e:?}");
            Ok(error_response(&env, "Internal server error", 500))
        }
    }
}

/// Inner request handler. All errors are caught by the outer `fetch` wrapper.
async fn handle_request(mut req: Request, env: &Env) -> Result<Response> {
    // Apply the idempotent schema bootstrap on every cold start so newly
    // added tables (moderation_actions, mod_reports, wot_entries, members,
    // invitations, invitation_redemptions, instance_settings) exist before
    // any handler tries to use them. Failures are swallowed inside.
    schema::ensure_schema(env).await;
    nostr_bbs_rate_limit::ensure_replay_schema(env, "DB").await;

    // CORS preflight
    if req.method() == Method::Options {
        return Ok(Response::empty()?
            .with_status(204)
            .with_headers(cors_headers(env)));
    }

    // Rate limit: 20 requests per 60 seconds per IP
    let ip = nostr_bbs_rate_limit::client_ip(&req);
    if !nostr_bbs_rate_limit::check_rate_limit(env, "SESSIONS", &ip, 20, 60).await {
        return json_response(
            env,
            &serde_json::json!({ "error": "Too many requests" }),
            429,
        );
    }

    let url = req.url()?;
    let path = url.path();
    let method = req.method();

    // Extract the actual request origin for NIP-98 verification. This ensures
    // tokens signed for .workers.dev URLs verify correctly even when
    // EXPECTED_ORIGIN points at a custom domain. The origin is threaded
    // through the route functions rather than stored in a thread_local (P2-06).
    let origin = admin::request_origin(&url);

    // Read body bytes BEFORE routing so they are available for both NIP-98
    // payload hash verification and route handler consumption.
    let body_bytes: Vec<u8> = match method {
        Method::Post | Method::Put | Method::Patch => req.bytes().await.unwrap_or_default(),
        _ => Vec::new(),
    };

    let result = route(&req, env, path, &method, &body_bytes, &origin).await;

    match result {
        Ok(resp) => Ok(with_cors(resp, env)),
        Err(e) => {
            let route_err = RouteError::from(e);
            console_error!("Route error: {:?}", route_err);
            Ok(error_response(
                env,
                route_err.user_message(),
                route_err.status(),
            ))
        }
    }
}

/// Route an incoming request to the appropriate handler.
///
/// `body_bytes` contains the pre-read request body (non-empty for POST/PUT/PATCH).
/// This allows NIP-98 payload hash verification BEFORE dispatching to handlers,
/// and avoids double-consumption of the request stream.
async fn route(
    req: &Request,
    env: &Env,
    path: &str,
    method: &Method,
    body_bytes: &[u8],
    origin: &str,
) -> Result<Response> {
    // DID document serving (public, no auth required)
    if let Some(rest) = path.strip_prefix("/.well-known/did/nostr/") {
        if let Some(pubkey) = rest.strip_suffix(".json") {
            return did::handle_did_document(pubkey, env).await;
        }
    }

    // Health check
    if path == "/health" {
        return json_response(
            env,
            &serde_json::json!({
                "status": "ok",
                "service": "auth-api",
                "runtime": "workers-rs"
            }),
            200,
        );
    }

    // WebAuthn Registration -- Generate options
    if path == "/auth/register/options" && *method == Method::Post {
        return webauthn::register_options(body_bytes, env).await;
    }

    // WebAuthn Registration -- Verify
    if path == "/auth/register/verify" && *method == Method::Post {
        let cf_country = req.headers().get("CF-IPCountry").ok().flatten();
        return webauthn::register_verify(body_bytes, cf_country.as_deref(), env).await;
    }

    // WebAuthn Authentication -- Generate options
    if path == "/auth/login/options" && *method == Method::Post {
        return webauthn::login_options(body_bytes, env).await;
    }

    // WebAuthn Authentication -- Verify
    if path == "/auth/login/verify" && *method == Method::Post {
        return webauthn::login_verify(req, body_bytes, env).await;
    }

    // Credential lookup (for discoverable login)
    if path == "/auth/lookup" && *method == Method::Post {
        return webauthn::credential_lookup(body_bytes, env).await;
    }

    // NIP-98 protected endpoints
    if path.starts_with("/api/") {
        let auth_header_opt = req.headers().get("Authorization").ok().flatten();

        // --- Sprint endpoints: moderation / WoT / invites / welcome ------
        //
        // These modules perform their own NIP-98 verification + admin/member
        // gating via `admin::require_admin` / `require_authed` so we dispatch
        // before the legacy `auth::verify_nip98` branch below.
        if let Some(resp) = route_sprint_api(
            req,
            env,
            path,
            method,
            body_bytes,
            auth_header_opt.as_deref(),
            origin,
        )
        .await?
        {
            return Ok(resp);
        }

        let auth_header = match auth_header_opt {
            Some(h) => h,
            None => {
                return json_response(
                    env,
                    &serde_json::json!({ "error": "Authorization required" }),
                    401,
                )
            }
        };

        let request_url = admin::canonical_url(origin, path);

        // Pass body bytes to NIP-98 for payload hash verification on POST/PUT.
        // For GET/HEAD/DELETE the body is empty, so we pass None.
        let body_for_nip98: Option<&[u8]> = match method {
            Method::Post | Method::Put | Method::Patch => Some(body_bytes),
            _ => None,
        };

        let result = auth::verify_nip98_replay(
            &auth_header,
            &request_url,
            method_str(method),
            body_for_nip98,
            env,
        )
        .await;

        match result {
            Ok(token) => {
                // Route authenticated requests
                if path == "/api/profile" && *method == Method::Get {
                    let cors = cors_headers(env);
                    return pod::handle_profile(&token.pubkey, env, cors).await;
                }
            }
            Err(_) => {
                return json_response(
                    env,
                    &serde_json::json!({ "error": "Invalid NIP-98 token" }),
                    401,
                )
            }
        }
    }

    json_response(env, &serde_json::json!({ "error": "Not found" }), 404)
}

/// Dispatch to the Obelisk-polish sprint endpoints (moderation / WoT /
/// invites / welcome). Returns `Ok(Some(resp))` if handled, `Ok(None)`
/// otherwise so the caller can fall through to the legacy `/api/profile`
/// handler.
async fn route_sprint_api(
    req: &Request,
    env: &Env,
    path: &str,
    method: &Method,
    body_bytes: &[u8],
    auth_header: Option<&str>,
    origin: &str,
) -> Result<Option<Response>> {
    // Collect query pairs once for GET endpoints.
    let query: Vec<(String, String)> = req
        .url()
        .map(|u| {
            u.query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // -- Moderation (WI-2) ----------------------------------------------
    if matches!(path, "/api/mod/ban" | "/api/mod/mute" | "/api/mod/warn") && *method == Method::Post
    {
        let resp = moderation::handle_action(path, body_bytes, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    if path == "/api/mod/report" && *method == Method::Post {
        let resp = moderation::handle_report(body_bytes, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    if path == "/api/mod/actions" && *method == Method::Get {
        let resp = moderation::handle_list_actions(&query, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    if path == "/api/mod/reports" && *method == Method::Get {
        let resp = moderation::handle_list_reports(&query, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    // POST /api/mod/reports/:id/action
    if let Some(rest) = path.strip_prefix("/api/mod/reports/") {
        if let Some(report_id) = rest.strip_suffix("/action") {
            if *method == Method::Post && !report_id.is_empty() && !report_id.contains('/') {
                let resp = moderation::handle_report_action(
                    report_id,
                    body_bytes,
                    auth_header,
                    env,
                    origin,
                )
                .await?;
                return Ok(Some(resp));
            }
        }
    }

    // -- Web-of-Trust (WI-3) --------------------------------------------
    if path == "/api/wot/status" && *method == Method::Get {
        let resp = wot::handle_status(auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    if path == "/api/wot/set-referente" && *method == Method::Post {
        let resp = wot::handle_set_referente(body_bytes, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    if path == "/api/wot/refresh" && *method == Method::Post {
        let resp = wot::handle_refresh(body_bytes, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    if matches!(path, "/api/wot/override/add" | "/api/wot/override/remove")
        && *method == Method::Post
    {
        let resp = wot::handle_override(path, body_bytes, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }

    // -- Invites (WI-4) -------------------------------------------------
    if path == "/api/invites/create" && *method == Method::Post {
        let resp = invites::handle_create(body_bytes, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    if path == "/api/invites/mine" && *method == Method::Get {
        let resp = invites::handle_list_mine(auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    // POST /api/invites/:id/revoke (must be checked before the generic preview)
    if let Some(rest) = path.strip_prefix("/api/invites/") {
        if let Some(invite_id) = rest.strip_suffix("/revoke") {
            if *method == Method::Post && !invite_id.is_empty() && !invite_id.contains('/') {
                let resp =
                    invites::handle_revoke(invite_id, body_bytes, auth_header, env, origin).await?;
                return Ok(Some(resp));
            }
        }
        // POST /api/invites/:code/redeem
        if let Some(code) = rest.strip_suffix("/redeem") {
            if *method == Method::Post && !code.is_empty() && !code.contains('/') {
                let resp =
                    invites::handle_redeem(code, body_bytes, auth_header, env, origin).await?;
                return Ok(Some(resp));
            }
        }
        // GET /api/invites/:code (public preview, no auth)
        if *method == Method::Get
            && !rest.is_empty()
            && !rest.contains('/')
            && rest != "create"
            && rest != "mine"
        {
            let resp = invites::handle_preview(rest, env).await?;
            return Ok(Some(resp));
        }
    }

    // -- Welcome bot (WI-5) --------------------------------------------
    if path == "/api/welcome/config" && *method == Method::Get {
        let resp = welcome::handle_get_config(auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    if path == "/api/welcome/configure" && *method == Method::Post {
        let resp = welcome::handle_configure(body_bytes, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    if path == "/api/welcome/set-bot-key" && *method == Method::Post {
        let resp = welcome::handle_set_bot_key(body_bytes, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    if path == "/api/welcome/test" && *method == Method::Post {
        let resp = welcome::handle_test(body_bytes, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }

    // -- Admin management (WI-8) ----------------------------------------
    if path == "/api/admins" && *method == Method::Get {
        let resp = admins::handle_list(auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    if path == "/api/admins/add" && *method == Method::Post {
        let resp = admins::handle_add(body_bytes, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    if path == "/api/admins/remove" && *method == Method::Post {
        let resp = admins::handle_remove(body_bytes, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }

    // -- Governance (Agent Control Surface) --------------------------------
    if path == "/api/governance/agents" && *method == Method::Get {
        let resp = governance_api::handle_list_agents(auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    if path == "/api/governance/agents/register" && *method == Method::Post {
        let resp =
            governance_api::handle_register_agent(body_bytes, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    if path == "/api/governance/agents/revoke" && *method == Method::Post {
        let resp =
            governance_api::handle_revoke_agent(body_bytes, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    if path == "/api/governance/cases" && *method == Method::Get {
        let resp = governance_api::handle_list_cases(&query, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    if let Some(case_id) = path.strip_prefix("/api/governance/cases/") {
        if *method == Method::Get && !case_id.is_empty() && !case_id.contains('/') {
            let resp = governance_api::handle_get_case(case_id, auth_header, env, origin).await?;
            return Ok(Some(resp));
        }
    }
    if path == "/api/governance/roles/grant" && *method == Method::Post {
        let resp = governance_api::handle_grant_role(body_bytes, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    if path == "/api/governance/roles/revoke" && *method == Method::Post {
        let resp = governance_api::handle_revoke_role(body_bytes, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    if path == "/api/governance/roles" && *method == Method::Get {
        let resp = governance_api::handle_list_roles(auth_header, env, origin).await?;
        return Ok(Some(resp));
    }

    // -- NIP-1984 standard report queue (admin view) --------------------
    if path == "/api/moderation/reports" && *method == Method::Get {
        let resp = moderation::handle_nip1984_reports(auth_header, env, origin).await?;
        return Ok(Some(resp));
    }

    // -- NIP-26 Delegation verification (stub for W6) -------------------
    if path == "/api/delegation/verify" && *method == Method::Post {
        let resp = delegation::handle_verify(body_bytes, auth_header, env).await?;
        return Ok(Some(resp));
    }

    // -- Native pod provisioning ----------------------------------------
    if path == "/api/native-pod/provision" && *method == Method::Post {
        let resp =
            handle_native_pod_provision(body_bytes, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }

    // -- Sprint v10: username reservations ------------------------------
    if path == "/api/username/check" && *method == Method::Get {
        let resp = username::handle_check(&query, env).await?;
        return Ok(Some(resp));
    }
    // JSS Phase 1 (ADR-086) — federated NIP-05 resolve.
    if path == "/api/username/resolve" && *method == Method::Get {
        let resp = username::handle_resolve(&query, env).await?;
        return Ok(Some(resp));
    }
    if path == "/api/username/claim" && *method == Method::Post {
        let resp = username::handle_claim(body_bytes, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }
    if path == "/api/username/release" && *method == Method::Post {
        let resp = username::handle_release(body_bytes, auth_header, env, origin).await?;
        return Ok(Some(resp));
    }

    Ok(None)
}

/// POST /api/native-pod/provision
///
/// Admin NIP-98 required. Validates the supplied pubkey, then forwards a
/// provisioning request to the native solid-pod-rs server using the PSK header.
///
/// Env bindings required:
/// - `NATIVE_POD_URL`      — Base URL of the native server
/// - `NATIVE_POD_ADMIN_KEY` — Pre-shared key sent as `X-Pod-Admin-Key`
async fn handle_native_pod_provision(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    // Require admin NIP-98 auth.
    let auth_header = match auth_header {
        Some(h) => h,
        None => {
            return json_response(
                env,
                &serde_json::json!({ "error": "Authorization required" }),
                401,
            );
        }
    };
    let request_url = admin::canonical_url(origin, "/api/native-pod/provision");
    let token = match crate::auth::verify_nip98_replay(
        auth_header,
        &request_url,
        "POST",
        Some(body_bytes),
        env,
    )
    .await
    {
        Ok(t) => t,
        Err(_) => {
            return json_response(
                env,
                &serde_json::json!({ "error": "Invalid NIP-98 token" }),
                401,
            );
        }
    };
    if !admin::is_admin(&token.pubkey, env).await {
        return json_response(
            env,
            &serde_json::json!({ "error": "Admin access required" }),
            403,
        );
    }

    // Parse request body: { "pubkey": "<hex>" }
    let body: serde_json::Value = match serde_json::from_slice(body_bytes) {
        Ok(v) => v,
        Err(_) => {
            return json_response(
                env,
                &serde_json::json!({ "error": "Invalid request body" }),
                400,
            );
        }
    };
    let pubkey = match body.get("pubkey").and_then(|v| v.as_str()) {
        Some(pk) => pk.to_string(),
        None => {
            return json_response(
                env,
                &serde_json::json!({ "error": "Missing pubkey field" }),
                400,
            );
        }
    };
    if pubkey.len() != 64 || !pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return json_response(
            env,
            &serde_json::json!({ "error": "pubkey must be 64 hex characters" }),
            400,
        );
    }

    // Read env bindings.
    let native_pod_url = match env.var("NATIVE_POD_URL") {
        Ok(v) => v.to_string(),
        Err(_) => {
            return json_response(
                env,
                &serde_json::json!({ "error": "native pod not configured" }),
                503,
            );
        }
    };
    let native_pod_admin_key = match env.var("NATIVE_POD_ADMIN_KEY") {
        Ok(v) => v.to_string(),
        Err(_) => {
            return json_response(
                env,
                &serde_json::json!({ "error": "native pod not configured" }),
                503,
            );
        }
    };

    // Forward to native server: POST {NATIVE_POD_URL}/_admin/provision/{pubkey}
    let provision_url = format!(
        "{}/_admin/provision/{}",
        native_pod_url.trim_end_matches('/'),
        pubkey
    );

    let headers = Headers::new();
    headers
        .set("X-Pod-Admin-Key", &native_pod_admin_key)
        .map_err(|e| Error::RustError(format!("Headers::set: {e:?}")))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| Error::RustError(format!("Headers::set: {e:?}")))?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_headers(headers);

    let upstream_req = Request::new_with_init(&provision_url, &init)?;
    let mut upstream_resp = Fetch::Request(upstream_req).send().await?;
    let status = upstream_resp.status_code();
    let body_text = upstream_resp.text().await.unwrap_or_default();

    let resp = Response::ok(body_text)?.with_status(status);
    Ok(resp)
}

/// Map a `worker::Method` enum to its string name.
fn method_str(m: &Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Head => "HEAD",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
        Method::Options => "OPTIONS",
        Method::Patch => "PATCH",
        Method::Connect => "CONNECT",
        Method::Trace => "TRACE",
        _ => "GET",
    }
}

// ---------------------------------------------------------------------------
// Tests — pure function coverage (no Worker runtime required)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── method_str ──────────────────────────────────────────────────────

    #[test]
    fn method_str_get() {
        assert_eq!(method_str(&Method::Get), "GET");
    }

    #[test]
    fn method_str_post() {
        assert_eq!(method_str(&Method::Post), "POST");
    }

    #[test]
    fn method_str_put() {
        assert_eq!(method_str(&Method::Put), "PUT");
    }

    #[test]
    fn method_str_delete() {
        assert_eq!(method_str(&Method::Delete), "DELETE");
    }

    #[test]
    fn method_str_head() {
        assert_eq!(method_str(&Method::Head), "HEAD");
    }

    #[test]
    fn method_str_options() {
        assert_eq!(method_str(&Method::Options), "OPTIONS");
    }

    #[test]
    fn method_str_patch() {
        assert_eq!(method_str(&Method::Patch), "PATCH");
    }

    #[test]
    fn method_str_connect() {
        assert_eq!(method_str(&Method::Connect), "CONNECT");
    }

    #[test]
    fn method_str_trace() {
        assert_eq!(method_str(&Method::Trace), "TRACE");
    }
}

/// Cron keep-warm: prevents cold starts by pinging D1.
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) -> () {
    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return,
    };
    let _ = db
        .prepare("SELECT 1")
        .first::<serde_json::Value>(None)
        .await;
}
