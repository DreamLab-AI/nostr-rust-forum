//! Nostr BBS auth-api Worker (Rust)
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

mod auth;
mod pod;
mod rate_limit;
mod webauthn;

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

/// Create a JSON error response that NEVER fails.
/// Falls back to plain text if JSON serialization somehow fails.
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
            // Absolute fallback — should never happen
            Response::error(message, status).unwrap_or_else(|_| Response::empty().unwrap())
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
    // CORS preflight
    if req.method() == Method::Options {
        return Ok(Response::empty()?
            .with_status(204)
            .with_headers(cors_headers(env)));
    }

    // Rate limit: 20 requests per 60 seconds per IP
    let ip = rate_limit::client_ip(&req);
    if !rate_limit::check_rate_limit(env, &ip, 20, 60).await {
        return json_response(
            env,
            &serde_json::json!({ "error": "Too many requests" }),
            429,
        );
    }

    let url = req.url()?;
    let path = url.path();
    let method = req.method();

    // Read body bytes BEFORE routing so they are available for both NIP-98
    // payload hash verification and route handler consumption.
    let body_bytes: Vec<u8> = match method {
        Method::Post | Method::Put | Method::Patch => {
            req.bytes().await.unwrap_or_default()
        }
        _ => Vec::new(),
    };

    let result = route(&req, env, path, &method, &body_bytes).await;

    match result {
        Ok(resp) => Ok(with_cors(resp, env)),
        Err(e) => {
            console_error!("Route error: {e:?}");
            let msg = format!("{e:?}");
            let status = if msg.contains("Serialization")
                || msg.contains("JSON")
                || msg.contains("json")
                || msg.contains("missing field")
                || msg.contains("parsing")
                || msg.contains("Invalid")
            {
                400u16
            } else {
                500u16
            };
            let user_msg = if status == 400 {
                "Invalid request body"
            } else {
                "Internal server error"
            };
            Ok(error_response(env, user_msg, status))
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
) -> Result<Response> {
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
        return webauthn::register_verify(body_bytes, env).await;
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
        let auth_header = match req.headers().get("Authorization").ok().flatten() {
            Some(h) => h,
            None => {
                return json_response(
                    env,
                    &serde_json::json!({ "error": "Authorization required" }),
                    401,
                )
            }
        };

        let expected_origin = env
            .var("EXPECTED_ORIGIN")
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "https://example.com".to_string());
        let request_url = format!("{expected_origin}{path}");

        // Pass body bytes to NIP-98 for payload hash verification on POST/PUT.
        // For GET/HEAD/DELETE the body is empty, so we pass None.
        let body_for_nip98: Option<&[u8]> = match method {
            Method::Post | Method::Put | Method::Patch => Some(body_bytes),
            _ => None,
        };

        let result = auth::verify_nip98(
            &auth_header,
            &request_url,
            method_str(method),
            body_for_nip98,
        );

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
