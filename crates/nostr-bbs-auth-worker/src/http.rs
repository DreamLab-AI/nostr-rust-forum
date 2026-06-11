//! Shared HTTP response helpers, lifted out of `lib.rs` so feature modules
//! (moderation / WoT / invites / welcome) can use them without circular
//! imports.

use worker::{Env, Headers, Response, Result};

/// Build CORS headers from the `EXPECTED_ORIGIN` env var.
///
/// Fail-closed (Gap 5): when `EXPECTED_ORIGIN` is unset or empty we emit **no**
/// `Access-Control-Allow-Origin` header rather than falling back to a
/// `https://example.com` placeholder. A placeholder default silently CORS-grants
/// an unrelated origin on a misconfigured deploy; omitting the header makes the
/// browser refuse the cross-origin response instead. This mirrors the
/// `expected_origin_required()` fail-closed pattern already used in the
/// WebAuthn ceremony path (`webauthn.rs`).
///
/// This is the single canonical CORS builder for the auth-worker; `lib.rs`
/// re-exports it so both response paths share identical fail-closed behaviour.
pub fn cors_headers(env: &Env) -> Headers {
    let headers = Headers::new();

    match env.var("EXPECTED_ORIGIN").map(|v| v.to_string()) {
        Ok(origin) if !origin.trim().is_empty() => {
            headers.set("Access-Control-Allow-Origin", &origin).ok();
        }
        // Misconfigured deploy: no allowed origin. Omit ACAO entirely so the
        // browser's same-origin policy blocks the response — never grant a
        // placeholder origin.
        _ => {}
    }

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

/// Serialize a JSON body and build a CORS-wrapped response with `status`.
pub fn json_response(env: &Env, body: &serde_json::Value, status: u16) -> Result<Response> {
    let json_str =
        serde_json::to_string(body).map_err(|e| worker::Error::RustError(e.to_string()))?;
    let resp = Response::ok(json_str)?
        .with_status(status)
        .with_headers(cors_headers(env));
    resp.headers().set("Content-Type", "application/json").ok();
    Ok(resp)
}

/// Convenience: build `{"error": msg}` at `status`.
pub fn error_json(env: &Env, msg: &str, status: u16) -> Result<Response> {
    json_response(env, &serde_json::json!({ "error": msg }), status)
}
