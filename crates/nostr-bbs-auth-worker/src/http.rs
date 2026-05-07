//! Shared HTTP response helpers, lifted out of `lib.rs` so feature modules
//! (moderation / WoT / invites / welcome) can use them without circular
//! imports.

use worker::{Env, Headers, Response, Result};

/// Build CORS headers from the `EXPECTED_ORIGIN` env var.
pub fn cors_headers(env: &Env) -> Headers {
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
