//! Git HTTP protocol detection and CF-aware stub responses.
//!
//! `solid-pod-rs-git` implements the full git HTTP backend (spawns
//! `git-http-backend` CGI). CF Workers cannot spawn subprocesses, so on
//! the Cloudflare deployment these routes return `501 Not Implemented`
//! with a machine-readable `X-Git-Unavailable: cf-workers` header.
//!
//! On native/agentbox deployments the pod-worker can be rebuilt to wire
//! `solid_pod_rs_git::GitHttpService` here instead — the detection logic
//! stays the same.
//!
//! ## Security
//!
//! Direct access to `.git/` internals (e.g. `/.git/config`) is blocked
//! with 403 regardless of backend, mirroring JSS `src/handlers/git.js`
//! lines 52-68 which explicitly reject such paths before any auth check.
//!
//! ## JSS parity
//!
//! Mirrors the git-request detection from JSS `isGitRequest`:
//! ```text
//! function isGitRequest(urlPath) {
//!   return urlPath.includes('/info/refs') ||
//!     urlPath.includes('/git-upload-pack') ||
//!     urlPath.includes('/git-receive-pack');
//! }
//! ```
//! We also handle `OPTIONS` pre-flight and the bare `HEAD` file served
//! by `git-http-backend` (used by `PodBrowserPage`'s git-init probe).

use worker::Response;

/// Returns `true` if `resource_path` is a git smart-HTTP protocol URL.
///
/// Covers the four request patterns `git-http-backend` responds to:
/// - `…/info/refs?service=git-{upload,receive}-pack` — protocol discovery
/// - `…/git-upload-pack` — fetch/clone data transfer
/// - `…/git-receive-pack` — push data transfer
///
/// Note: the bare `/HEAD` probe used by the pod browser is NOT included
/// here — it returns 404 from the LDP layer on CF, which the client
/// interprets correctly as "git not enabled on this deployment".
#[inline]
pub fn is_git_request(resource_path: &str) -> bool {
    resource_path.contains("/info/refs")
        || resource_path.contains("/git-upload-pack")
        || resource_path.contains("/git-receive-pack")
}

/// Returns `true` if `resource_path` is a direct request for `.git/`
/// directory internals — always blocked for security.
#[inline]
pub fn is_dot_git_path(resource_path: &str) -> bool {
    resource_path.starts_with("/.git/") || resource_path == "/.git"
}

/// Build a `403 Forbidden` response for direct `.git/` access.
pub fn git_dir_forbidden() -> worker::Result<Response> {
    let json = serde_json::to_string(&serde_json::json!({
        "error": "Direct access to .git directory contents is forbidden"
    }))
    .map_err(|e| worker::Error::RustError(e.to_string()))?;
    let resp = Response::ok(json)?.with_status(403);
    resp.headers().set("Content-Type", "application/json").ok();
    resp.headers().set("Access-Control-Allow-Origin", "*").ok();
    Ok(resp)
}

/// Build a `501 Not Implemented` response for git protocol requests on
/// the Cloudflare Workers deployment.
///
/// The `X-Git-Unavailable: cf-workers` header is machine-readable so
/// client tooling (e.g. `pod_browser.rs`'s git probe) can distinguish
/// "CF limitation" from "git not enabled by operator" without parsing
/// error text.
pub fn git_not_implemented() -> worker::Result<Response> {
    let json = serde_json::to_string(&serde_json::json!({
        "error": "Git HTTP protocol is not available on the Cloudflare Workers deployment",
        "reason": "cf-workers-cannot-subprocess",
        "docs": "https://github.com/DreamLab-AI/nostr-rust-forum/blob/main/docs/adr/ADR-089-git-pods-cf-workers-limitation.md"
    }))
    .map_err(|e| worker::Error::RustError(e.to_string()))?;
    let resp = Response::ok(json)?.with_status(501);
    resp.headers().set("Content-Type", "application/json").ok();
    resp.headers().set("Access-Control-Allow-Origin", "*").ok();
    resp.headers().set("X-Git-Unavailable", "cf-workers").ok();
    Ok(resp)
}
