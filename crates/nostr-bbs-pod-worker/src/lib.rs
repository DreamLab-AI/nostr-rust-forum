//! nostr-bbs Pod Worker (Rust)
//!
//! Per-user Solid pod storage backed by R2 + KV, with NIP-98 authentication,
//! WAC (Web Access Control) enforcement, LDP container support, ACL CRUD,
//! pod provisioning, WebID profile management, remoteStorage compatibility,
//! Solid Notifications (webhooks), HTTP 402 payments (Web Ledgers spec),
//! and `did:nostr` DID document resolution.
//!
//! Payments: `/pay/` routes provide balance queries, multi-chain TXO deposits,
//! and metered resource access via `did:nostr:<pubkey>` identities. Users and
//! agents are indistinguishable at the protocol level.
//!
//! Port of `workers/pod-api/index.ts`.

mod acl;
mod auth;
mod conditional;
mod container;
mod content_negotiation;
mod contexts;
mod did;
mod git;
// Native-only pod-git identity + gitmark/blocktrails anchoring (ADR-124 §5.4,
// ADR-089). Structurally absent from the CF Workers (`wasm32-unknown-unknown`)
// build: CF cannot spawn `git` subprocesses, so the trail anchors only on the
// native/agentbox deployment of the externally-pullable forum pod. On CF the
// `git` module above keeps returning the 501 / `X-Git-Unavailable: cf-workers`
// stub.
mod notifications;
mod patch;
mod payments;
#[cfg(not(target_arch = "wasm32"))]
mod pod_git_anchor;
mod provision;
mod quota;
mod remote_storage;
mod webid;

// JSS Phase 1 staging (ADR-086/087): inert re-export shim for the upstream
// `export-jsonld` feature. Compiles to an empty surface today; activation is
// gated on the `solid-pod-rs-phase1` feature. See `docs/consumer-surface-map.md`.
//
// The `provision-keys` and `nip05-endpoint` shims were removed at closeout
// (2026-07-03): CF-native equivalents already serve those paths (`provision.rs`
// and the `/.well-known/nostr.json` handler below), so the parked shims only
// advertised upstream parity the wasm32 CF Workers target cannot link (ADR-087).
mod export;

use acl::{
    coerce_required_mode_for_acl, evaluate_access, find_effective_acl, wac_allow_header, AccessMode,
};
use base64::Engine as _;
use worker::*;

/// Maximum request body size: 50 MB.
const MAX_BODY_SIZE: u64 = 50 * 1024 * 1024;

/// Defense-in-depth path-traversal guard for pod resource paths (P2).
///
/// The `r2_key` is built as `pods/{owner}{resource_path}`. ACL scoping plus
/// WHATWG URL normalization already contain most traversal, but this helper
/// adds an explicit decode-then-validate rejection so a crafted path can never
/// escape the `pods/{owner}/` prefix. Rejects, before any R2 key is built:
///   - literal `..` parent-directory segments;
///   - percent-encoded dots (`%2e`/`%2E`) that decode to `.` (re-encoded
///     traversal such as `%2e%2e%2f`);
///   - percent-encoded slashes (`%2f`/`%2F`) that decode to `/` (smuggled path
///     separators the prefix check would otherwise miss);
///   - backslashes (`\`), which some clients/proxies treat as separators;
///   - NUL bytes (`%00` or raw `\0`), a classic truncation vector.
///
/// Returns `true` when the path is safe to use in an `r2_key`.
fn is_safe_resource_path(resource_path: &str) -> bool {
    // Raw forbidden bytes.
    if resource_path.contains('\\') || resource_path.contains('\0') {
        return false;
    }
    if resource_path.contains("..") {
        return false;
    }

    // Inspect percent-encodings WITHOUT a full decode (we cannot fully decode
    // here without pulling in a decoder, and a single-pass lowercase scan is
    // sufficient to catch the encoded dot/slash/NUL forms).
    let lower = resource_path.to_ascii_lowercase();
    if lower.contains("%2e") // encoded '.'
        || lower.contains("%2f") // encoded '/'
        || lower.contains("%5c") // encoded '\'
        || lower.contains("%00")
    // encoded NUL
    {
        return false;
    }

    true
}

/// Regex-equivalent pattern for pod routes: `/pods/{64 hex chars}{optional path}`.
/// We parse manually instead of pulling in `regex` to keep the WASM binary small.
fn parse_pod_route(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/pods/")?;
    if rest.len() < 64 {
        return None;
    }
    let (pubkey, remainder) = rest.split_at(64);
    // Validate hex characters
    if !pubkey.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    // Remainder must be empty or start with '/'
    if !remainder.is_empty() && !remainder.starts_with('/') {
        return None;
    }
    let resource_path = if remainder.is_empty() { "/" } else { remainder };
    // Defense-in-depth: reject traversal/encoded-separator paths before any
    // caller can build an `r2_key` from this value (P2).
    if !is_safe_resource_path(resource_path) {
        return None;
    }
    Some((pubkey, resource_path))
}

/// Check whether a resource path targets an `.acl` sidecar document.
fn is_acl_path(path: &str) -> bool {
    path.ends_with(".acl")
}

/// Check whether a resource path targets the pod provisioning endpoint.
fn is_provision_path(path: &str) -> bool {
    path == "/.provision"
}

/// Forum Worker pod names are Nostr x-only pubkeys.
///
/// Native solid-pod-rs can create named pods through `POST /.pods`; this
/// Worker maps that surface onto the existing `/pods/{pubkey}/` storage model
/// so the authenticated creator and ACL owner remain the same identity.
fn is_valid_worker_pod_name(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())
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

/// Build CORS headers from the `EXPECTED_ORIGIN` env var.
///
/// Uses the canonical [`nostr_bbs_core::POD_CORS_HEADERS`] constant for the
/// extended method/header set required by the Solid/LDP protocol.
fn cors_headers(env: &Env) -> Headers {
    let origin = env
        .var("EXPECTED_ORIGIN")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "*".to_string());
    let wildcard = origin == "*";

    let headers = Headers::new();
    headers.set("Access-Control-Allow-Origin", &origin).ok();
    for (name, value) in nostr_bbs_core::POD_CORS_HEADERS {
        // Per the Fetch/CORS spec, `Access-Control-Allow-Credentials: true` is
        // invalid alongside a wildcard `Allow-Origin` (browsers reject the
        // combination). When no concrete `EXPECTED_ORIGIN` is configured we fall
        // back to `*`, so we must NOT also advertise credentialed access — emit a
        // spec-valid header set instead of a self-contradicting one.
        if wildcard && *name == "Access-Control-Allow-Credentials" {
            continue;
        }
        headers.set(name, value).ok();
    }
    // Defense-in-depth against MIME-sniffing of stored pod content into an
    // executable type (stored-XSS). Applied to every response that uses this
    // shared builder.
    headers.set("X-Content-Type-Options", "nosniff").ok();
    headers
}

/// Neutralize active content for resources served as HTML.
///
/// Pod resources are *data*, not applications. A party who can store HTML in a
/// world-readable container (e.g. `public/`, or a poisoned `/profile/card`)
/// could otherwise execute script on the pod's web origin — a stored-XSS that,
/// on a shared app/pod origin, can read another user's persisted key material.
/// `Content-Security-Policy: sandbox` (without `allow-scripts`) runs the
/// document with scripting disabled; `default-src 'none'` blocks subresource
/// loads. JSON-LD (`application/ld+json`) WebID data is unaffected — browsers
/// and RDF consumers parse it rather than execute it.
fn add_html_safety_headers(headers: &Headers, content_type: &str) {
    if content_type.starts_with("text/html") {
        headers
            .set("Content-Security-Policy", "default-src 'none'; sandbox")
            .ok();
    }
}

/// Recover an image `Content-Type` from a resource path extension when the
/// stored type is the generic `application/octet-stream`.
///
/// The old upload client PUT every blob as `application/octet-stream`, so images
/// stored before the client fix carry that type. Combined with `nosniff` (set on
/// every response above) browsers refuse to render them in `<img>`, and the
/// image→ASCII transform below is gated on an `image/*` type, so the BBS shows
/// "image unavailable". Deriving the real type from the extension lets those
/// already-stored avatars and photos render without a re-upload. Only overrides
/// the generic/empty stored type — a real stored type is always respected.
fn refine_image_content_type(path: &str, stored: String) -> String {
    if !stored.is_empty() && stored != "application/octet-stream" {
        return stored;
    }
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg".to_string(),
        "png" => "image/png".to_string(),
        "webp" => "image/webp".to_string(),
        "gif" => "image/gif".to_string(),
        "avif" => "image/avif".to_string(),
        "svg" => "image/svg+xml".to_string(),
        "bmp" => "image/bmp".to_string(),
        _ => stored,
    }
}

/// True when an `Accept` request header opts in to server-side ASCII rendering
/// by listing the `text/x-ascii-art` media type (case-insensitive match).
fn accept_wants_ascii(accept_header: Option<&str>) -> bool {
    accept_header
        .map(|h| h.to_ascii_lowercase().contains("text/x-ascii-art"))
        .unwrap_or(false)
}

/// Whether a pod resource GET opts in to server-side image→ASCII rendering.
///
/// Two equivalent opt-ins are honoured: a `?format=ascii` query param (the
/// `format_param` value, case-insensitive) OR an `Accept` header that lists
/// `text/x-ascii-art`. This decides *intent only*; the caller still gates the
/// transform on an `image/*` content type AND on access control having already
/// passed — ASCII rendering never exposes bytes the caller could not GET.
fn ascii_requested(format_param: Option<&str>, accept_header: Option<&str>) -> bool {
    format_param
        .map(|f| f.eq_ignore_ascii_case("ascii"))
        .unwrap_or(false)
        || accept_wants_ascii(accept_header)
}

/// Append LDP Link headers and ACL link to a response.
///
/// For non-`.acl` resources, includes `Link: <{path}.acl>; rel="acl"`.
fn add_ldp_headers(headers: &Headers, is_container: bool, resource_path: &str) {
    let mut link_parts = Vec::new();

    if is_container {
        link_parts.push("<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"".to_string());
        link_parts.push("<http://www.w3.org/ns/ldp#Resource>; rel=\"type\"".to_string());
    } else {
        link_parts.push("<http://www.w3.org/ns/ldp#Resource>; rel=\"type\"".to_string());
    }

    // Add rel="acl" link for non-.acl resources
    if !is_acl_path(resource_path) {
        let acl_link = format!("<{resource_path}.acl>; rel=\"acl\"");
        link_parts.push(acl_link);
    }

    headers.set("Link", &link_parts.join(", ")).ok();
    headers.set("Accept-Ranges", "bytes").ok();
    headers
        .set("Updates-Via", &format!("{resource_path}.notifications"))
        .ok();
}

/// Add WAC-Allow header to a response.
fn add_wac_allow(
    headers: &Headers,
    acl_doc: Option<&acl::AclDocument>,
    agent_uri: Option<&str>,
    resource_path: &str,
) {
    let value = wac_allow_header(acl_doc, agent_uri, resource_path);
    headers.set("WAC-Allow", &value).ok();
}

/// Add Cache-Control header to a response based on resource path.
///
/// Media paths under `/media/` are treated as content-addressed and immutable
/// (1-year cache, immutable directive). All other resources use a short
/// `max-age=300` with `must-revalidate` since they are mutable Solid pod
/// resources (profile cards, ACLs, type indexes, etc.).
fn add_cache_control(headers: &Headers, resource_path: &str) {
    let value = if resource_path.starts_with("/media/") {
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=300, must-revalidate"
    };
    headers.set("Cache-Control", value).ok();
}

/// Extract the origin (`scheme://host[:port]`) from a parsed URL.
///
/// Used to construct NIP-98 verification URLs from the actual request origin
/// rather than the `EXPECTED_ORIGIN` env var. Workers may be accessed via
/// their `.workers.dev` subdomain or a custom domain — the NIP-98 `u` tag
/// must match whichever origin the client actually used.
fn request_origin(url: &worker::Url) -> String {
    let scheme = url.scheme();
    let host = url.host_str().unwrap_or("localhost");
    match url.port() {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    }
}

/// Public pod base URL used in WebID, Location, and podUri values.
///
/// This is intentionally separate from `EXPECTED_ORIGIN`, which is the browser
/// CORS origin for the forum frontend. A typical deployment serves the frontend
/// at `example.com` and the pod worker at `pods.example.com`, so using one
/// variable for both produces broken WebID URLs.
fn public_pod_base_url(env: &Env, fallback_origin: &str) -> String {
    env.var("POD_BASE_URL")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| fallback_origin.to_string())
        .trim_end_matches('/')
        .to_string()
}

/// Create a JSON error response with CORS headers.
fn json_error(env: &Env, message: &str, status: u16) -> Result<Response> {
    let body = serde_json::json!({ "error": message });
    let json_str = serde_json::to_string(&body).map_err(|e| Error::RustError(e.to_string()))?;
    let cors = cors_headers(env);
    let resp = Response::ok(json_str)?
        .with_status(status)
        .with_headers(cors);
    resp.headers().set("Content-Type", "application/json").ok();
    if status == 401 {
        resp.headers()
            .set(
                "WWW-Authenticate",
                "DPoP realm=\"Solid\", Bearer realm=\"Solid\"",
            )
            .ok();
    }
    Ok(resp)
}

/// Sprint v10: lightweight token-bucket rate limit for `/.well-known/nostr.json`.
///
/// Counts requests per IP per 60-second bucket. Returns `true` if the request
/// is allowed, `false` if the bucket is full. KV failures fail-open (we'd
/// rather serve a few extra hits than silently 429 every legitimate client
/// when KV is degraded).
const NIP05_RL_LIMIT: u32 = 60;
const NIP05_RL_WINDOW_SECS: u64 = 60;

async fn rl_nostr_json(kv: &worker::kv::KvStore, ip: &str) -> bool {
    let bucket = (js_sys::Date::now() as u64) / (NIP05_RL_WINDOW_SECS * 1000);
    let key = format!("rl:nostr_json:{ip}:{bucket}");

    let current: u32 = match kv.get(&key).text().await {
        Ok(Some(val)) => val.parse().unwrap_or(0),
        _ => 0,
    };
    if current >= NIP05_RL_LIMIT {
        return false;
    }

    let next = (current + 1).to_string();
    if let Ok(builder) = kv.put(&key, &next) {
        let _ = builder.expiration_ttl(NIP05_RL_WINDOW_SECS).execute().await;
    }
    true
}

/// Build a did:nostr DID document (Tier 3) for the given x-only pubkey hex.
///
/// Delegates to `crate::did::render_did_document_tier3`, which calls through
/// to the canonical `solid_pod_rs::did_nostr_types` module (upstream since
/// v0.4.0-alpha.8).
fn build_did_nostr_document(pubkey_hex: &str, pod_base: &str) -> serde_json::Value {
    match did::NostrPubkey::from_hex(pubkey_hex) {
        Ok(pk) => {
            let pod_url = format!("{pod_base}/pods/{pubkey_hex}/");
            let webid_url = format!("{pod_url}profile/card#me");
            did::render_did_document_tier3(
                &pk,
                Some(&webid_url),
                &pod_url,
                None, // relay URL: not included at Tier 3 without lookup
                None, // governance URL: set at instance config level
                None, // display name: not known at DID resolution time
            )
        }
        Err(_) => serde_json::json!({ "error": "invalid pubkey" }),
    }
}

/// Create a JSON success response with CORS headers.
fn json_ok(env: &Env, body: &serde_json::Value, status: u16) -> Result<Response> {
    let json_str = serde_json::to_string(body).map_err(|e| Error::RustError(e.to_string()))?;
    let cors = cors_headers(env);
    let resp = Response::ok(json_str)?
        .with_status(status)
        .with_headers(cors);
    resp.headers().set("Content-Type", "application/json").ok();
    Ok(resp)
}

// Invoked via wasm-bindgen as the worker's wasm entry point; on native builds
// nothing calls it directly, so it would otherwise be flagged dead-code there.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[event(fetch)]
async fn fetch(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
    nostr_bbs_rate_limit::ensure_replay_schema(&env, "REPLAY_DB").await;
    payments::ensure_payment_schema(&env, "REPLAY_DB").await;

    // CORS preflight
    if req.method() == Method::Options {
        return Ok(Response::empty()?
            .with_status(204)
            .with_headers(cors_headers(&env)));
    }

    let url = req.url()?;
    let path = url.path();

    // Health check
    if path == "/health" {
        return json_ok(
            &env,
            &serde_json::json!({
                "status": "ok",
                "service": "pod-api",
                "runtime": "workers-rs",
                // ADR-103 §2.5: derive from Cargo.toml, never a hardcoded literal.
                "version": env!("CARGO_PKG_VERSION"),
                "features": [
                    "ldp-containers",
                    "conditional-requests",
                    "quota",
                    "webid",
                    "acl-crud",
                    "pod-provisioning",
                    "wac-allow",
                    "jsonld-native",
                    "content-negotiation",
                    "remote-storage",
                    "solid-notifications",
                    "webfinger",
                    "nip-05",
                    "payments"
                ]
            }),
            200,
        );
    }

    // -------------------------------------------------------------------
    // .well-known discovery endpoints (federation-ready, Stream 12)
    // -------------------------------------------------------------------

    // WebFinger: remoteStorage + Solid + ActivityPub discovery
    if path == "/.well-known/webfinger" {
        let resource = url
            .query_pairs()
            .find(|(k, _)| k == "resource")
            .map(|(_, v)| v.to_string())
            .unwrap_or_default();
        if let Some(pk) = remote_storage::parse_webfinger_resource(&resource) {
            let host = url.host_str().unwrap_or("example.test");
            let pod_base = format!("https://{host}");
            let body = remote_storage::webfinger_response(&pk, host, &pod_base);
            let json_str =
                serde_json::to_string(&body).map_err(|e| Error::RustError(e.to_string()))?;
            let cors = cors_headers(&env);
            let resp = Response::ok(json_str)?.with_headers(cors);
            resp.headers()
                .set("Content-Type", "application/jrd+json")
                .ok();
            return Ok(resp);
        }
        return json_error(&env, "Invalid resource parameter", 400);
    }

    // Solid discovery metadata
    if path == "/.well-known/solid" {
        let host = url.host_str().unwrap_or("example.test");
        let body = remote_storage::solid_discovery(&format!("https://{host}"));
        let json_str = serde_json::to_string(&body).map_err(|e| Error::RustError(e.to_string()))?;
        let cors = cors_headers(&env);
        let resp = Response::ok(json_str)?.with_headers(cors);
        resp.headers().set("Content-Type", "application/json").ok();
        return Ok(resp);
    }

    // NIP-05 verification
    if path == "/.well-known/nostr.json" {
        // Sprint v10: rate-limit at 60 req/min per IP via POD_META KV. The
        // endpoint is otherwise unauthenticated and trivially scrape-able,
        // so without a budget here a single client could enumerate the
        // entire username table.
        let kv = env.kv("POD_META")?;
        let ip = req
            .headers()
            .get("CF-Connecting-IP")
            .ok()
            .flatten()
            .unwrap_or_else(|| "unknown".to_string());
        if !rl_nostr_json(&kv, &ip).await {
            let cors = cors_headers(&env);
            let resp = Response::ok(r#"{"error":"Too many requests"}"#)?
                .with_status(429)
                .with_headers(cors);
            resp.headers().set("Content-Type", "application/json").ok();
            resp.headers().set("Retry-After", "60").ok();
            return Ok(resp);
        }

        let name = url
            .query_pairs()
            .find(|(k, _)| k == "name")
            .map(|(_, v)| v.to_string())
            .unwrap_or_default();
        if name.is_empty() {
            return json_error(&env, "Missing name parameter", 400);
        }
        // Look up pubkey from KV: nip05:{name} -> pubkey
        let key = format!("nip05:{name}");
        let pubkey = kv.get(&key).text().await.ok().flatten();
        if let Some(pk) = pubkey {
            let body = remote_storage::nostr_json(&pk, &name);
            let json_str =
                serde_json::to_string(&body).map_err(|e| Error::RustError(e.to_string()))?;
            let cors = cors_headers(&env);
            let resp = Response::ok(json_str)?.with_headers(cors);
            resp.headers().set("Content-Type", "application/json").ok();
            resp.headers().set("Access-Control-Allow-Origin", "*").ok();
            // This public endpoint forces a wildcard origin; a wildcard origin
            // with `Allow-Credentials: true` is an invalid (browser-rejected)
            // combination and NIP-05 lookups are unauthenticated, so strip the
            // inherited credentials header to emit a spec-valid header set.
            resp.headers()
                .delete("Access-Control-Allow-Credentials")
                .ok();
            return Ok(resp);
        }
        return json_error(&env, "Name not found", 404);
    }

    // DID document: GET /.well-known/did/nostr/{pubkey}.json
    // Returns a did:nostr DID document for any 64-char hex pubkey known to this pod.
    // Tier1 (public, no auth) — anyone can resolve. Tier3 (extended) not yet gated.
    if let Some(rest) = path.strip_prefix("/.well-known/did/nostr/") {
        if let Some(pk) = rest.strip_suffix(".json") {
            // Validate: must be exactly 64 lowercase hex chars
            if pk.len() == 64 && pk.bytes().all(|b| b.is_ascii_hexdigit()) {
                let host = url.host_str().unwrap_or("example.test");
                let pod_base = format!("https://{host}");
                let did_doc = build_did_nostr_document(pk, &pod_base);
                let json_str =
                    serde_json::to_string(&did_doc).map_err(|e| Error::RustError(e.to_string()))?;
                let cors = cors_headers(&env);
                let resp = Response::ok(json_str)?.with_headers(cors);
                resp.headers()
                    .set("Content-Type", "application/did+json")
                    .ok();
                return Ok(resp);
            }
            return json_error(&env, "Invalid pubkey in DID path", 400);
        }
    }

    // Web Ledgers discovery
    if path == "/.well-known/webledgers/webledgers.json" {
        let host = url.host_str().unwrap_or("example.test");
        let body = payments::webledgers_discovery(&format!("https://{host}"));
        return json_ok(&env, &body, 200);
    }

    // JSS-compatible pod creation surface: POST /.pods {"name":"<pubkey>"}.
    //
    // Unlike the native server's anonymous development path, the Worker keeps
    // creation authenticated and bound to the signing pubkey because its ACLs
    // and DID identities are keyed by did:nostr:<pubkey>.
    if path == "/.pods" {
        if req.method() != Method::Post {
            return json_error(&env, "Method not allowed; use POST", 405);
        }

        let body = req.bytes().await.unwrap_or_default();
        let parsed: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| Error::RustError(format!("Invalid JSON body: {e}")))?;
        let name = parsed
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !is_valid_worker_pod_name(name) {
            return json_error(&env, "Pod name must be a 64-character Nostr pubkey", 400);
        }

        let auth_header = req.headers().get("Authorization").ok().flatten();
        let request_url = format!("{}{}", request_origin(&url), path);
        let requester_pubkey = match auth_header.as_deref() {
            Some(header) => {
                auth::verify_nip98_replay(header, &request_url, "POST", Some(&body), &env)
                    .await
                    .ok()
                    .map(|token| token.pubkey)
            }
            None => None,
        };
        if requester_pubkey.as_deref() != Some(name) {
            return json_error(&env, "Authentication required for this pod name", 401);
        }

        let kv = env.kv("POD_META")?;
        let bucket = env.bucket("PODS")?;
        if provision::pod_exists(&bucket, name).await {
            return json_error(&env, "Pod already provisioned", 409);
        }

        let pod_base = public_pod_base_url(&env, &request_origin(&url));
        provision::provision_pod(&bucket, &kv, name, &pod_base, None).await?;

        let pod_uri = format!("{pod_base}/pods/{name}/");
        let web_id = format!("{pod_uri}profile/card#me");
        let resp = json_ok(
            &env,
            &serde_json::json!({
                "name": name,
                "webId": web_id,
                "podUri": pod_uri,
            }),
            201,
        )?;
        resp.headers().set("Location", &pod_uri).ok();
        return Ok(resp);
    }

    // -------------------------------------------------------------------
    // /pay/ routes (HTTP 402 payment system — Web Ledgers spec)
    // -------------------------------------------------------------------
    if path.starts_with("/pay/") {
        let pay_config = load_pay_config(&env);
        if pay_config.enabled {
            let method = req.method();
            let pay_auth_header = req.headers().get("Authorization").ok().flatten();

            let pay_body: Option<Vec<u8>> = if method == Method::Post {
                req.bytes().await.ok()
            } else {
                None
            };

            let pay_nip98_origin = request_origin(&url);
            let request_url = format!("{pay_nip98_origin}{path}");
            let requester_pubkey: Option<String> = if let Some(ref header) = pay_auth_header {
                let method_name = method_str(&method);
                let body_ref = pay_body.as_deref();
                auth::verify_nip98_replay(header, &request_url, method_name, body_ref, &env)
                    .await
                    .ok()
                    .map(|t| t.pubkey)
            } else {
                None
            };

            let pay_cors_origin = env
                .var("EXPECTED_ORIGIN")
                .map(|v| v.to_string())
                .unwrap_or_else(|_| pay_nip98_origin.clone());
            let pay_db = env
                .d1("REPLAY_DB")
                .map_err(|e| Error::RustError(format!("REPLAY_DB D1 binding missing: {e}")))?;
            if let Some(result) = payments::handle_pay_route(
                path,
                &method,
                requester_pubkey.as_deref(),
                pay_body.as_deref(),
                &pay_db,
                &env,
                &pay_config,
            )
            .await
            {
                let resp = result?;
                resp.headers()
                    .set("Access-Control-Allow-Origin", &pay_cors_origin)
                    .ok();
                return Ok(resp);
            }
        }
        return json_error(&env, "Not found", 404);
    }

    // Route: /pods/{pubkey}/...
    let (owner_pubkey, resource_path) = match parse_pod_route(path) {
        Some(parsed) => parsed,
        None => return json_error(&env, "Not found", 404),
    };

    // --- Git HTTP protocol guard (ADR-089, JSS parity) -------------------
    // Block direct .git/ access unconditionally (security).
    if git::is_dot_git_path(resource_path) {
        return git::git_dir_forbidden();
    }
    // Git smart-HTTP protocol: 501 on CF Workers (no subprocess support).
    // On native/agentbox deployments, wire solid-pod-rs-git::GitHttpService
    // here instead. The forum-client pod_browser already handles 501 +
    // the X-Git-Unavailable header by displaying "not enabled on this deployment".
    if git::is_git_request(resource_path) {
        return git::git_not_implemented();
    }

    // We need owned copies before we borrow `req` mutably for the body
    let owner_pubkey = owner_pubkey.to_string();
    let resource_path = resource_path.to_string();
    let method = req.method();
    let req_headers = req.headers().clone();
    let auth_header = req_headers.get("Authorization").ok().flatten();
    let slug_header = req_headers.get("Slug").ok().flatten();
    let accept_header = req_headers.get("Accept").ok().flatten();
    let content_type = req_headers
        .get("Content-Type")
        .ok()
        .flatten()
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let content_length: u64 = req_headers
        .get("Content-Length")
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Read body early so we can use it for both NIP-98 payload verification and R2 upload
    let body_bytes: Option<Vec<u8>> = match method {
        Method::Put | Method::Post | Method::Patch => req.bytes().await.ok(),
        _ => None,
    };

    // Authenticate via NIP-98
    let nip98_origin = request_origin(&url);
    let expected_origin = env
        .var("EXPECTED_ORIGIN")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| nip98_origin.clone());
    let request_url = format!("{nip98_origin}{path}");

    let requester_pubkey: Option<String> = if let Some(ref header) = auth_header {
        let method_name = method_str(&method);
        let body_ref = body_bytes.as_deref();
        match auth::verify_nip98_replay(header, &request_url, method_name, body_ref, &env).await {
            Ok(token) => {
                // If the event carries a `["webid", uri]` tag, verify the URI
                // is controlled by the signing pubkey. Reject tokens where the
                // webid tag references a different identity.
                if let Some(webid_uri) = extract_webid_tag_from_header(header) {
                    if !did::verify_webid_tag(&webid_uri, &token.pubkey) {
                        return json_error(&env, "NIP-98 webid tag identity mismatch", 401);
                    }
                }
                Some(token.pubkey)
            }
            Err(_) => None,
        }
    } else {
        None
    };

    let kv = env.kv("POD_META")?;
    let bucket = env.bucket("PODS")?;
    let quota_db = env
        .d1("REPLAY_DB")
        .map_err(|e| Error::RustError(format!("REPLAY_DB D1 binding missing: {e}")))?;

    // Build the WAC agent URI from the (NIP-98-verified) requester pubkey. Fail
    // CLOSED on a malformed pubkey: rather than constructing an unvalidated
    // `did:nostr:{pk}` identity that could be matched by an ACL grant, drop the
    // agent identity entirely so deny-by-default WAC treats it as anonymous.
    let agent_uri = requester_pubkey.as_ref().and_then(|pk| {
        did::NostrPubkey::from_hex(pk)
            .map(|p| nostr_bbs_core::did_nostr_uri(&p))
            .ok()
    });

    // -----------------------------------------------------------------------
    // Provisioning endpoint: POST /pods/{pubkey}/.provision
    // -----------------------------------------------------------------------
    if is_provision_path(&resource_path) {
        if method != Method::Post {
            return json_error(&env, "Method not allowed; use POST", 405);
        }

        // Require authentication
        let req_pk = match requester_pubkey.as_ref() {
            Some(pk) => pk.clone(),
            None => return json_error(&env, "Authentication required", 401),
        };

        // Only the pod owner or an admin can provision
        let is_owner = req_pk == owner_pubkey;
        let is_admin = is_admin_user(&env, &req_pk).await;
        if !is_owner && !is_admin {
            return json_error(&env, "Only the pod owner or admin can provision", 403);
        }

        // Check if pod already exists
        if provision::pod_exists(&bucket, &owner_pubkey).await {
            return json_error(&env, "Pod already provisioned", 409);
        }

        // Extract optional display_name from body
        let display_name: Option<String> = body_bytes
            .as_deref()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
            .and_then(|v| {
                v.get("display_name")
                    .and_then(|n| n.as_str())
                    .map(String::from)
            });

        let pod_base = public_pod_base_url(&env, &nip98_origin);
        provision::provision_pod(
            &bucket,
            &kv,
            &owner_pubkey,
            &pod_base,
            display_name.as_deref(),
        )
        .await?;

        let pod_url = format!("{pod_base}/pods/{owner_pubkey}/");
        let webid_url = format!("{pod_url}profile/card#me");
        return json_ok(
            &env,
            &serde_json::json!({
                "status": "provisioned",
                "podUrl": pod_url,
                "webId": webid_url,
                "didNostr": did::NostrPubkey::from_hex(&owner_pubkey)
                    .map(|pk| nostr_bbs_core::did_nostr_uri(&pk))
                    .unwrap_or_else(|_| format!("did:nostr:{owner_pubkey}")),
                "containers": ["profile/", "public/", "private/", "inbox/", "settings/", "media/", "media/public/"]
            }),
            201,
        );
    }

    // -----------------------------------------------------------------------
    // ACL CRUD: paths ending with .acl
    // -----------------------------------------------------------------------
    if is_acl_path(&resource_path) {
        return handle_acl_request(
            &env,
            &bucket,
            &kv,
            &owner_pubkey,
            &resource_path,
            &method,
            &req_headers,
            body_bytes,
            content_length,
            requester_pubkey.as_deref(),
            agent_uri.as_deref(),
        )
        .await;
    }

    // -----------------------------------------------------------------------
    // Standard resource ACL check
    // -----------------------------------------------------------------------
    // For `.acl` sidecars we coerce write-class methods up to acl:Control so
    // a principal with mere acl:Write cannot escalate by overwriting the
    // sidecar (audit C3). Non-acl resources retain the standard mapping.
    let required_mode = coerce_required_mode_for_acl(&resource_path, method_str(&method));
    let acl_doc = find_effective_acl(&bucket, &kv, &owner_pubkey, &resource_path).await;

    let has_access = evaluate_access(
        acl_doc.as_ref(),
        agent_uri.as_deref(),
        &resource_path,
        required_mode,
    );

    if !has_access {
        return if requester_pubkey.is_some() {
            json_error(&env, "Forbidden", 403)
        } else {
            json_error(&env, "Authentication required", 401)
        };
    }

    // Detect container vs resource
    let is_container_path = container::is_container(&resource_path);

    // R2 operations
    let r2_key = format!("pods/{owner_pubkey}{resource_path}");

    match method {
        Method::Get | Method::Head => {
            // Container listing
            if is_container_path {
                let listing =
                    container::list_container(&bucket, &owner_pubkey, &resource_path).await?;
                let json_str =
                    serde_json::to_string(&listing).map_err(|e| Error::RustError(e.to_string()))?;
                let cors = cors_headers(&env);
                let resp = Response::ok(json_str)?.with_headers(cors);
                resp.headers()
                    .set("Content-Type", "application/ld+json")
                    .ok();
                add_ldp_headers(resp.headers(), true, &resource_path);
                add_wac_allow(
                    resp.headers(),
                    acl_doc.as_ref(),
                    agent_uri.as_deref(),
                    &resource_path,
                );
                add_cache_control(resp.headers(), &resource_path);
                return Ok(resp);
            }

            // WebID profile document (special path): serve from R2 if stored,
            // otherwise generate dynamically.
            if resource_path == "/profile/card" {
                let html = match bucket.get(&r2_key).execute().await? {
                    Some(obj) => {
                        let body = obj
                            .body()
                            .ok_or_else(|| Error::RustError("R2 object has no body".into()))?;
                        let bytes = body.bytes().await?;
                        String::from_utf8(bytes).unwrap_or_else(|_| {
                            webid::generate_webid_html(&owner_pubkey, None, &expected_origin)
                        })
                    }
                    None => webid::generate_webid_html(&owner_pubkey, None, &expected_origin),
                };
                let cors = cors_headers(&env);
                let resp = Response::ok(html)?.with_headers(cors);
                resp.headers().set("Content-Type", "text/html").ok();
                // WebID cards are world-readable; sandbox them so a poisoned
                // card cannot run script on the pod origin (validate_webid_html
                // checks for a JSON-LD block but does not sanitize surrounding
                // markup).
                add_html_safety_headers(resp.headers(), "text/html");
                add_ldp_headers(resp.headers(), false, &resource_path);
                add_wac_allow(
                    resp.headers(),
                    acl_doc.as_ref(),
                    agent_uri.as_deref(),
                    &resource_path,
                );
                add_cache_control(resp.headers(), &resource_path);
                return Ok(resp);
            }

            // Regular resource GET
            let object = match bucket.get(&r2_key).execute().await? {
                Some(obj) => obj,
                None => return json_error(&env, "Not found", 404),
            };

            let stored_content_type = object
                .http_metadata()
                .content_type
                .unwrap_or_else(|| "application/octet-stream".to_string());
            // Recover a real image type for legacy octet-stream uploads so they
            // render in `<img>` (nosniff) and reach the image→ASCII transform.
            let stored_content_type =
                refine_image_content_type(&resource_path, stored_content_type);
            let obj_content_type = match content_negotiation::negotiate(
                accept_header.as_deref(),
                &stored_content_type,
            ) {
                content_negotiation::Negotiated::ContentType(ct) => ct,
                content_negotiation::Negotiated::NotAcceptable => {
                    // e.g. `Accept: text/turtle` against a JSON-LD-stored RDF
                    // resource: this crate has no Turtle serializer, so
                    // silently substituting JSON-LD would violate content
                    // negotiation and break Turtle-only Solid/LDP clients.
                    let resp = json_error(&env, "Not Acceptable", 406)?;
                    resp.headers().set("Vary", "Accept").ok();
                    return Ok(resp);
                }
            };
            let etag = object.etag();
            let cors = cors_headers(&env);

            // Conditional request check
            if let Some(status) = conditional::check_preconditions(&req_headers, &etag) {
                let resp = Response::empty()?.with_status(status).with_headers(cors);
                resp.headers().set("ETag", &format!("\"{etag}\"")).ok();
                add_ldp_headers(resp.headers(), false, &resource_path);
                add_wac_allow(
                    resp.headers(),
                    acl_doc.as_ref(),
                    agent_uri.as_deref(),
                    &resource_path,
                );
                return Ok(resp);
            }

            if method == Method::Head {
                let resp = Response::empty()?.with_headers(cors);
                resp.headers().set("Content-Type", &obj_content_type).ok();
                resp.headers().set("ETag", &format!("\"{etag}\"")).ok();
                resp.headers().set("Vary", "Accept").ok();
                add_ldp_headers(resp.headers(), false, &resource_path);
                add_wac_allow(
                    resp.headers(),
                    acl_doc.as_ref(),
                    agent_uri.as_deref(),
                    &resource_path,
                );
                add_cache_control(resp.headers(), &resource_path);
                return Ok(resp);
            }

            let body = object
                .body()
                .ok_or_else(|| Error::RustError("R2 object has no body".to_string()))?;
            let bytes = body.bytes().await?;

            // ── Server-side image→ASCII rendering ───────────────────────────
            // Presentation transform applied STRICTLY AFTER the WAC/WebID gate
            // above (control only reaches here once `has_access` held), so we
            // never render bytes the caller could not already GET. A caller opts
            // in via `?format=ascii` or `Accept: text/x-ascii-art`, and only
            // `image/*` resources are transformed. `cols`/`ramp`/`invert` query
            // params tune the output. Any decode failure falls through to serve
            // the original bytes unchanged; absent the opt-in, behaviour below
            // is identical to before.
            if obj_content_type.starts_with("image/") {
                let mut format_param: Option<String> = None;
                let mut opts = nostr_bbs_ascii::RenderOptions::default();
                for (k, v) in url.query_pairs() {
                    match k.as_ref() {
                        "format" => format_param = Some(v.into_owned()),
                        "cols" => {
                            if let Some(c) = v.parse::<u32>().ok().filter(|c| *c > 0) {
                                opts.cols = c;
                            }
                        }
                        "ramp" => {
                            let trimmed = v.trim();
                            if !trimmed.is_empty() {
                                opts.ramp = nostr_bbs_ascii::GlyphRamp::parse(trimmed);
                            }
                        }
                        "invert" => {
                            opts.invert = matches!(v.as_ref(), "1" | "true" | "yes" | "on");
                        }
                        _ => {}
                    }
                }

                if ascii_requested(format_param.as_deref(), accept_header.as_deref()) {
                    if let Ok(art) = nostr_bbs_ascii::render_bytes(&bytes, &opts) {
                        // We are now emitting HTML built from pod bytes, so apply
                        // the same active-content neutralization the worker uses
                        // for any served HTML (`add_html_safety_headers`); the
                        // shared `cors` builder already sets `nosniff`.
                        let resp = Response::ok(art.to_html())?.with_headers(cors);
                        resp.headers()
                            .set("Content-Type", "text/html; charset=utf-8")
                            .ok();
                        resp.headers().set("ETag", &format!("\"{etag}\"")).ok();
                        resp.headers().set("Vary", "Accept").ok();
                        add_html_safety_headers(resp.headers(), "text/html; charset=utf-8");
                        add_ldp_headers(resp.headers(), false, &resource_path);
                        add_wac_allow(
                            resp.headers(),
                            acl_doc.as_ref(),
                            agent_uri.as_deref(),
                            &resource_path,
                        );
                        add_cache_control(resp.headers(), &resource_path);
                        return Ok(resp);
                    }
                    // Decode failed → fall through and serve the original bytes.
                }
            }

            // Range request support
            if let Some((start, end)) = conditional::parse_range(&req_headers, bytes.len() as u64) {
                let slice = &bytes[start as usize..=end as usize];
                let resp = Response::from_bytes(slice.to_vec())?
                    .with_status(206)
                    .with_headers(cors);
                resp.headers().set("Content-Type", &obj_content_type).ok();
                resp.headers().set("ETag", &format!("\"{etag}\"")).ok();
                resp.headers()
                    .set(
                        "Content-Range",
                        &format!("bytes {start}-{end}/{}", bytes.len()),
                    )
                    .ok();
                add_html_safety_headers(resp.headers(), &obj_content_type);
                add_ldp_headers(resp.headers(), false, &resource_path);
                add_wac_allow(
                    resp.headers(),
                    acl_doc.as_ref(),
                    agent_uri.as_deref(),
                    &resource_path,
                );
                add_cache_control(resp.headers(), &resource_path);
                return Ok(resp);
            }

            let resp = Response::from_bytes(bytes)?.with_headers(cors);
            resp.headers().set("Content-Type", &obj_content_type).ok();
            resp.headers().set("ETag", &format!("\"{etag}\"")).ok();
            resp.headers().set("Vary", "Accept").ok();
            add_html_safety_headers(resp.headers(), &obj_content_type);
            add_ldp_headers(resp.headers(), false, &resource_path);
            add_wac_allow(
                resp.headers(),
                acl_doc.as_ref(),
                agent_uri.as_deref(),
                &resource_path,
            );
            add_cache_control(resp.headers(), &resource_path);
            Ok(resp)
        }

        Method::Put => {
            // PUT replaces a resource (not valid on containers)
            if is_container_path {
                return json_error(&env, "Cannot PUT to a container; use POST", 405);
            }

            if content_length > MAX_BODY_SIZE {
                return json_error(
                    &env,
                    &format!("Body exceeds {} byte limit", MAX_BODY_SIZE),
                    413,
                );
            }

            let data = body_bytes.unwrap_or_default();
            let data_len = data.len() as u64;
            if data_len > MAX_BODY_SIZE {
                return json_error(
                    &env,
                    &format!("Body exceeds {} byte limit", MAX_BODY_SIZE),
                    413,
                );
            }

            // Conditional check: If-Match for safe overwrites
            if let Ok(Some(existing)) = bucket.get(&r2_key).execute().await {
                let etag = existing.etag();
                if let Some(status) = conditional::check_preconditions(&req_headers, &etag) {
                    return json_error(
                        &env,
                        if status == 412 {
                            "Precondition failed"
                        } else {
                            "Not modified"
                        },
                        status,
                    );
                }
            }

            // Atomic quota check + reserve (D1)
            if let Err(e) = quota::check_and_reserve_d1(&quota_db, &owner_pubkey, data_len).await {
                return json_error(&env, &e.to_string(), 413);
            }

            // WebID profile: validate HTML with JSON-LD before storing
            if resource_path == "/profile/card" {
                if let Err(msg) = validate_webid_html(&data) {
                    return json_error(&env, &msg, 422);
                }
            }

            bucket
                .put(&r2_key, data)
                .http_metadata(HttpMetadata {
                    content_type: Some(content_type),
                    ..Default::default()
                })
                .execute()
                .await?;

            // Fire notification webhooks (non-blocking)
            notifications::notify_change(&kv, &owner_pubkey, &resource_path, "Update").await;

            let resp_body = serde_json::json!({ "status": "ok" });
            let resp = json_ok(&env, &resp_body, 201)?;
            add_ldp_headers(resp.headers(), false, &resource_path);
            add_wac_allow(
                resp.headers(),
                acl_doc.as_ref(),
                agent_uri.as_deref(),
                &resource_path,
            );
            Ok(resp)
        }

        Method::Post => {
            // POST to a container creates a child resource
            if !is_container_path {
                // POST to a non-container: treat as regular write (backwards compat)
                if content_length > MAX_BODY_SIZE {
                    return json_error(
                        &env,
                        &format!("Body exceeds {} byte limit", MAX_BODY_SIZE),
                        413,
                    );
                }

                let data = body_bytes.unwrap_or_default();
                let data_len = data.len() as u64;
                if data_len > MAX_BODY_SIZE {
                    return json_error(
                        &env,
                        &format!("Body exceeds {} byte limit", MAX_BODY_SIZE),
                        413,
                    );
                }

                if let Err(e) =
                    quota::check_and_reserve_d1(&quota_db, &owner_pubkey, data_len).await
                {
                    return json_error(&env, &e.to_string(), 413);
                }

                bucket
                    .put(&r2_key, data)
                    .http_metadata(HttpMetadata {
                        content_type: Some(content_type),
                        ..Default::default()
                    })
                    .execute()
                    .await?;

                // Fire notification webhooks (non-blocking)
                notifications::notify_change(&kv, &owner_pubkey, &resource_path, "Update").await;

                let resp_body = serde_json::json!({ "status": "ok" });
                let resp = json_ok(&env, &resp_body, 201)?;
                add_ldp_headers(resp.headers(), false, &resource_path);
                add_wac_allow(
                    resp.headers(),
                    acl_doc.as_ref(),
                    agent_uri.as_deref(),
                    &resource_path,
                );
                return Ok(resp);
            }

            // Container POST: create child resource
            if content_length > MAX_BODY_SIZE {
                return json_error(
                    &env,
                    &format!("Body exceeds {} byte limit", MAX_BODY_SIZE),
                    413,
                );
            }

            let data = body_bytes.unwrap_or_default();
            let data_len = data.len() as u64;
            if data_len > MAX_BODY_SIZE {
                return json_error(
                    &env,
                    &format!("Body exceeds {} byte limit", MAX_BODY_SIZE),
                    413,
                );
            }

            if let Err(e) = quota::check_and_reserve_d1(&quota_db, &owner_pubkey, data_len).await {
                return json_error(&env, &e.to_string(), 413);
            }

            let child_path = container::resolve_slug(&resource_path, slug_header.as_deref());
            // Defense-in-depth (P2): the child path is derived from the
            // attacker-controlled `Slug` header, so re-validate before building
            // the r2_key — `parse_pod_route`'s guard only covers the URL path.
            if !is_safe_resource_path(&child_path) {
                return json_error(&env, "Invalid resource path", 400);
            }
            let child_r2_key = format!("pods/{owner_pubkey}{child_path}");

            bucket
                .put(&child_r2_key, data)
                .http_metadata(HttpMetadata {
                    content_type: Some(content_type),
                    ..Default::default()
                })
                .execute()
                .await?;

            // Fire notification webhooks (non-blocking)
            notifications::notify_change(&kv, &owner_pubkey, &child_path, "Create").await;

            let location = format!("/pods/{owner_pubkey}{child_path}");
            let resp_body = serde_json::json!({
                "status": "created",
                "path": child_path,
                "location": location,
            });
            let resp = json_ok(&env, &resp_body, 201)?;
            resp.headers().set("Location", &location).ok();
            add_ldp_headers(resp.headers(), false, &resource_path);
            add_wac_allow(
                resp.headers(),
                acl_doc.as_ref(),
                agent_uri.as_deref(),
                &resource_path,
            );
            Ok(resp)
        }

        Method::Patch => {
            // PATCH applies JSON Patch (RFC 6902) to a resource
            if is_container_path {
                return json_error(&env, "Cannot PATCH a container", 405);
            }

            let patch_data = body_bytes.unwrap_or_default();

            // Parse patch operations
            let operations: Vec<patch::PatchOperation> = serde_json::from_slice(&patch_data)
                .map_err(|e| Error::RustError(format!("Invalid JSON Patch: {e}")))?;

            // Read current document
            let current_bytes = match bucket.get(&r2_key).execute().await? {
                Some(obj) => {
                    let body = obj
                        .body()
                        .ok_or_else(|| Error::RustError("R2 object has no body".into()))?;
                    body.bytes().await?
                }
                None => return json_error(&env, "Not found", 404),
            };

            let mut document: serde_json::Value = serde_json::from_slice(&current_bytes)
                .map_err(|e| Error::RustError(format!("Resource is not JSON: {e}")))?;

            // Apply patches
            patch::apply_patches(&mut document, &operations)
                .map_err(|e| Error::RustError(format!("Patch failed: {e}")))?;

            let updated =
                serde_json::to_vec(&document).map_err(|e| Error::RustError(e.to_string()))?;
            let updated_len = updated.len() as u64;

            // Atomic quota check for size increase
            let size_delta = updated_len as i64 - current_bytes.len() as i64;
            if size_delta > 0 {
                if let Err(e) =
                    quota::check_and_reserve_d1(&quota_db, &owner_pubkey, size_delta as u64).await
                {
                    return json_error(&env, &e.to_string(), 413);
                }
            }

            // WebID profile: validate after patching
            if resource_path == "/profile/card" {
                if let Err(msg) = validate_webid_html(&updated) {
                    return json_error(&env, &msg, 422);
                }
            }

            bucket
                .put(&r2_key, updated)
                .http_metadata(HttpMetadata {
                    content_type: Some("application/ld+json".into()),
                    ..Default::default()
                })
                .execute()
                .await?;

            // Release quota for shrinkage
            if size_delta < 0 {
                quota::update_usage_d1(&quota_db, &owner_pubkey, size_delta)
                    .await
                    .ok();
            }

            // Fire notification webhooks (non-blocking)
            notifications::notify_change(&kv, &owner_pubkey, &resource_path, "Update").await;

            let resp_body = serde_json::json!({ "status": "ok" });
            let resp = json_ok(&env, &resp_body, 200)?;
            add_ldp_headers(resp.headers(), false, &resource_path);
            add_wac_allow(
                resp.headers(),
                acl_doc.as_ref(),
                agent_uri.as_deref(),
                &resource_path,
            );
            Ok(resp)
        }

        Method::Delete => {
            // Estimate size of deleted resource for quota tracking
            let deleted_size: u64 = match bucket.get(&r2_key).execute().await? {
                Some(obj) => obj.size(),
                None => return json_error(&env, "Not found", 404),
            };

            bucket.delete(&r2_key).await?;

            // Release quota (negative delta, D1 atomic)
            quota::update_usage_d1(&quota_db, &owner_pubkey, -(deleted_size as i64))
                .await
                .ok();

            // Fire notification webhooks (non-blocking)
            notifications::notify_change(&kv, &owner_pubkey, &resource_path, "Delete").await;

            let resp_body = serde_json::json!({ "status": "deleted" });
            let resp = json_ok(&env, &resp_body, 200)?;
            add_ldp_headers(resp.headers(), false, &resource_path);
            add_wac_allow(
                resp.headers(),
                acl_doc.as_ref(),
                agent_uri.as_deref(),
                &resource_path,
            );
            Ok(resp)
        }

        _ => json_error(&env, "Method not allowed", 405),
    }
}

// ---------------------------------------------------------------------------
// ACL request handler
// ---------------------------------------------------------------------------

/// Handle GET/PUT/DELETE on `.acl` sidecar resources.
///
/// ACL documents are stored in R2 alongside the resources they protect.
/// Writing an ACL requires `acl:Control` on the parent resource.
#[allow(clippy::too_many_arguments)]
async fn handle_acl_request(
    env: &Env,
    bucket: &Bucket,
    kv: &kv::KvStore,
    owner_pubkey: &str,
    acl_path: &str,
    method: &Method,
    req_headers: &Headers,
    body_bytes: Option<Vec<u8>>,
    content_length: u64,
    requester_pubkey: Option<&str>,
    agent_uri: Option<&str>,
) -> Result<Response> {
    let r2_key = format!("pods/{owner_pubkey}{acl_path}");

    // Derive the protected resource this `.acl`/`.meta` sidecar governs AND
    // the AccessMode the WAC check must run against, via the SHARED
    // sidecar-elevation decision `acl::effective_acl_target`
    // (`solid_pod_rs::wac::effective_acl_target`) — the single source of truth
    // co-owned with solid-pod-rs' native server. For any sidecar path this
    // returns `(protected_resource, AccessMode::Control)`: reading OR writing
    // an `.acl`/`.meta` discloses/rewrites the full authorization graph of the
    // protected resource, which WAC §4.3.5 gates on `acl:Control` of that
    // resource — never `acl:Read` of the sidecar. Deriving it here (rather
    // than re-stripping `.acl` locally) keeps the forum on the shared policy
    // and covers `.meta` sidecars identically.
    let (protected_resource, acl_required_mode) =
        acl::effective_acl_target(acl_path, AccessMode::Read);
    let parent_path: &str = &protected_resource;

    // Resolve effective ACL for the protected resource to determine access.
    let parent_acl = find_effective_acl(bucket, kv, owner_pubkey, parent_path).await;

    match *method {
        Method::Get | Method::Head => {
            // P2-1 FIX: reading an `.acl`/`.meta` sidecar requires
            // `acl:Control` on the PROTECTED resource — never mere `acl:Read`.
            // The previous `evaluate_access(Read) || evaluate_access(Control)`
            // shortcut let ANY Read-holder (including anonymous on a
            // public-readable container) fetch the sidecar and read off the
            // entire authorization graph — who-can-do-what — an information-
            // disclosure leak. `acl_required_mode` is the shared decision
            // (`AccessMode::Control` for every sidecar path), so the read gate
            // now matches the write gate: a single `Control` check.
            let can_read = evaluate_access(
                parent_acl.as_ref(),
                agent_uri,
                parent_path,
                acl_required_mode,
            );

            if !can_read {
                return if requester_pubkey.is_some() {
                    json_error(env, "Forbidden", 403)
                } else {
                    json_error(env, "Authentication required", 401)
                };
            }

            let object = match bucket.get(&r2_key).execute().await? {
                Some(obj) => obj,
                None => return json_error(env, "No ACL document found", 404),
            };

            let etag = object.etag();
            let cors = cors_headers(env);

            if let Some(status) = conditional::check_preconditions(req_headers, &etag) {
                let resp = Response::empty()?.with_status(status).with_headers(cors);
                resp.headers().set("ETag", &format!("\"{etag}\"")).ok();
                return Ok(resp);
            }

            if *method == Method::Head {
                let resp = Response::empty()?.with_headers(cors);
                resp.headers()
                    .set("Content-Type", "application/ld+json")
                    .ok();
                resp.headers().set("ETag", &format!("\"{etag}\"")).ok();
                add_cache_control(resp.headers(), acl_path);
                return Ok(resp);
            }

            let body = object
                .body()
                .ok_or_else(|| Error::RustError("R2 object has no body".into()))?;
            let bytes = body.bytes().await?;
            let resp = Response::from_bytes(bytes)?.with_headers(cors);
            resp.headers()
                .set("Content-Type", "application/ld+json")
                .ok();
            resp.headers().set("ETag", &format!("\"{etag}\"")).ok();
            add_wac_allow(resp.headers(), parent_acl.as_ref(), agent_uri, parent_path);
            add_cache_control(resp.headers(), acl_path);
            Ok(resp)
        }

        Method::Put => {
            // Writing an ACL requires acl:Control on the parent resource
            let has_control = evaluate_access(
                parent_acl.as_ref(),
                agent_uri,
                parent_path,
                AccessMode::Control,
            );

            if !has_control {
                return if requester_pubkey.is_some() {
                    json_error(env, "acl:Control required to modify ACL", 403)
                } else {
                    json_error(env, "Authentication required", 401)
                };
            }

            if content_length > MAX_BODY_SIZE {
                return json_error(
                    env,
                    &format!("Body exceeds {} byte limit", MAX_BODY_SIZE),
                    413,
                );
            }

            let mut data = body_bytes.unwrap_or_default();

            // ── Delegation shortcut (ADR-096) ──────────────────────────
            //
            // An `acl:Control` holder (verified above) may grant another
            // `did:nostr` agent Read/Write on this container WITHOUT
            // hand-authoring JSON-LD by PUTting a structured grant:
            //
            //   { "@delegation": { "agent": "did:nostr:<hex>",
            //                      "modes": ["acl:Read", "acl:Write"] } }
            //
            // to the container sidecar `<container>/.acl`. The worker
            // serialises the canonical ACL via `build_delegation_acl`,
            // which ALWAYS re-emits the owner's full `acl:Control` so the
            // owner can never be locked out, and never confers Control on
            // the grantee. `acl:Append` is accepted as a synonym for the
            // append mode. Any other body falls through to raw JSON-LD.
            if let Ok(envelope) = serde_json::from_slice::<serde_json::Value>(&data) {
                if let Some(grant) = envelope.get("@delegation") {
                    let agent_did = grant.get("agent").and_then(|v| v.as_str());
                    let Some(agent_did) = agent_did else {
                        return json_error(
                            env,
                            "Invalid delegation: @delegation.agent (did:nostr) required",
                            422,
                        );
                    };
                    if !agent_did.starts_with("did:nostr:") {
                        return json_error(
                            env,
                            "Invalid delegation: agent must be a did:nostr identifier",
                            422,
                        );
                    }
                    let mut modes: Vec<AccessMode> = Vec::new();
                    if let Some(arr) = grant.get("modes").and_then(|v| v.as_array()) {
                        for m in arr {
                            match m.as_str() {
                                Some("acl:Read") => modes.push(AccessMode::Read),
                                Some("acl:Write") => modes.push(AccessMode::Write),
                                Some("acl:Append") => modes.push(AccessMode::Append),
                                // acl:Control is intentionally ignored here:
                                // build_delegation_acl never delegates Control.
                                Some("acl:Control") => {}
                                _ => {
                                    return json_error(
                                        env,
                                        "Invalid delegation: modes must be acl:Read/Write/Append",
                                        422,
                                    );
                                }
                            }
                        }
                    }
                    let owner_did = did::NostrPubkey::from_hex(owner_pubkey)
                        .map(|pk| nostr_bbs_core::did_nostr_uri(&pk))
                        .unwrap_or_else(|_| format!("did:nostr:{owner_pubkey}"));
                    // The container the ACL governs is the parent of the
                    // `.acl` sidecar, normalised to a container path.
                    let container = if parent_path.ends_with('/') {
                        parent_path.to_string()
                    } else {
                        format!("{parent_path}/")
                    };
                    let doc = acl::build_delegation_acl(&owner_did, agent_did, &container, &modes);
                    data = serde_json::to_vec(&doc).map_err(|e| Error::RustError(e.to_string()))?;
                }
            }

            // Validate that the body is a valid ACL document (parseable JSON-LD)
            if serde_json::from_slice::<acl::AclDocument>(&data).is_err() {
                return json_error(
                    env,
                    "Invalid ACL document: must be valid JSON-LD with @graph",
                    422,
                );
            }

            bucket
                .put(&r2_key, data)
                .http_metadata(HttpMetadata {
                    content_type: Some("application/ld+json".into()),
                    ..Default::default()
                })
                .execute()
                .await?;

            let resp_body = serde_json::json!({ "status": "ok" });
            json_ok(env, &resp_body, 201)
        }

        Method::Delete => {
            // Deleting an ACL requires acl:Control on the parent resource
            let has_control = evaluate_access(
                parent_acl.as_ref(),
                agent_uri,
                parent_path,
                AccessMode::Control,
            );

            if !has_control {
                return if requester_pubkey.is_some() {
                    json_error(env, "acl:Control required to delete ACL", 403)
                } else {
                    json_error(env, "Authentication required", 401)
                };
            }

            // Check it exists
            if bucket.get(&r2_key).execute().await?.is_none() {
                return json_error(env, "ACL document not found", 404);
            }

            bucket.delete(&r2_key).await?;

            let resp_body = serde_json::json!({ "status": "deleted" });
            json_ok(env, &resp_body, 200)
        }

        _ => json_error(env, "Method not allowed on ACL resource", 405),
    }
}

// ---------------------------------------------------------------------------
// WebID validation
// ---------------------------------------------------------------------------

/// Validate that a byte slice is a valid WebID profile document.
///
/// Checks that the content is valid UTF-8 and contains embedded JSON-LD
/// (a `<script type="application/ld+json">` block).
fn validate_webid_html(data: &[u8]) -> Result<(), String> {
    let text =
        std::str::from_utf8(data).map_err(|_| "WebID profile must be valid UTF-8".to_string())?;

    if !text.contains("application/ld+json") {
        return Err(
            "WebID profile must contain a <script type=\"application/ld+json\"> block".to_string(),
        );
    }

    // Extract the JSON-LD content and verify it parses
    if let Some(start) = text.find("application/ld+json") {
        // Find the closing > of the script tag
        if let Some(tag_end) = text[start..].find('>') {
            let json_start = start + tag_end + 1;
            if let Some(script_end) = text[json_start..].find("</script>") {
                let json_str = text[json_start..json_start + script_end].trim();
                serde_json::from_str::<serde_json::Value>(json_str)
                    .map_err(|e| format!("Invalid JSON-LD in WebID profile: {e}"))?;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// NIP-98 webid tag extractor
// ---------------------------------------------------------------------------

/// Extract the value of the `["webid", uri]` tag from a raw NIP-98
/// `Authorization: Nostr <base64>` header, if present.
///
/// The NIP-98 spec allows extension tags. When a client sends a `webid`
/// tag, we verify that the URI refers to the same identity as the signing
/// pubkey (via `did::verify_webid_tag`).
///
/// Returns `None` if the header is malformed, the event has no webid tag,
/// or base64 decoding fails — non-fatal; auth proceeds without webid check.
fn extract_webid_tag_from_header(auth_header: &str) -> Option<String> {
    let b64 = auth_header.strip_prefix("Nostr ")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let event: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let tags = event.get("tags")?.as_array()?;
    for tag in tags {
        let arr = tag.as_array()?;
        if arr.first()?.as_str() == Some("webid") {
            if let Some(uri) = arr.get(1).and_then(|v| v.as_str()) {
                return Some(uri.to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Payment config loader
// ---------------------------------------------------------------------------

fn load_pay_config(env: &Env) -> payments::PayConfig {
    let enabled = env
        .var("PAY_ENABLED")
        .map(|v| {
            let s = v.to_string();
            s == "true" || s == "1"
        })
        .unwrap_or(false);
    let cost_sats = env
        .var("PAY_COST_SATS")
        .ok()
        .and_then(|v| v.to_string().parse().ok())
        .unwrap_or(1);

    let token = env.var("PAY_TOKEN_TICKER").ok().map(|ticker_var| {
        let ticker = ticker_var.to_string();
        let rate = env
            .var("PAY_TOKEN_RATE")
            .ok()
            .and_then(|v| v.to_string().parse().ok())
            .unwrap_or(10);
        let supply = env
            .var("PAY_TOKEN_SUPPLY")
            .ok()
            .and_then(|v| v.to_string().parse().ok())
            .unwrap_or(1_000_000);
        let issuer = env
            .var("PAY_TOKEN_ISSUER")
            .ok()
            .map(|v| v.to_string())
            .unwrap_or_default();
        payments::TokenConfig {
            ticker,
            rate,
            supply,
            issuer,
        }
    });

    payments::PayConfig {
        enabled,
        cost_sats,
        token,
        chains: vec![
            payments::ChainConfig::bitcoin_mainnet(),
            payments::ChainConfig::bitcoin_testnet4(),
            payments::ChainConfig::bitcoin_signet(),
        ],
    }
}

// ---------------------------------------------------------------------------
// Admin check helper
// ---------------------------------------------------------------------------

/// Check if a pubkey is an admin user via the shared D1 database.
///
/// Queries `members.is_admin` then falls back to `whitelist.is_admin`,
/// matching the auth-worker's `admin::is_admin` logic. Uses the `REPLAY_DB`
/// binding which points at the same D1 database as the auth-worker's `DB`.
///
/// Uses shared SQL constants and row types from [`nostr_bbs_core::admin_shared`]
/// to prevent structural drift between workers (P2-01).
async fn is_admin_user(env: &Env, pubkey: &str) -> bool {
    use nostr_bbs_core::admin_shared::IsAdminRow;

    let db = match env.d1("REPLAY_DB") {
        Ok(db) => db,
        Err(_) => return false,
    };

    if let Ok(stmt) = db
        .prepare(nostr_bbs_core::MEMBERS_IS_ADMIN_SQL)
        .bind(&[wasm_bindgen::JsValue::from_str(pubkey)])
    {
        if let Ok(Some(row)) = stmt.first::<IsAdminRow>(None).await {
            if row.is_admin == 1 {
                return true;
            }
        }
    }

    if let Ok(stmt) = db
        .prepare(nostr_bbs_core::WHITELIST_IS_ADMIN_SQL)
        .bind(&[wasm_bindgen::JsValue::from_str(pubkey)])
    {
        if let Ok(Some(row)) = stmt.first::<IsAdminRow>(None).await {
            return row.is_admin == 1;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Unit tests (route parsing only -- full integration requires wasm-bindgen)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refine_image_content_type_recovers_from_octet_stream() {
        // Legacy uploads stored as octet-stream recover their real image type
        // from the path extension so they render and reach the ASCII transform.
        for (path, want) in [
            ("/media/public/moomaa1.jpg", "image/jpeg"),
            ("/media/public/x.jpeg", "image/jpeg"),
            ("/media/public/x.PNG", "image/png"),
            ("/media/public/x.webp", "image/webp"),
            ("/media/public/x.gif", "image/gif"),
            ("/media/public/x.svg", "image/svg+xml"),
        ] {
            assert_eq!(
                refine_image_content_type(path, "application/octet-stream".to_string()),
                want,
                "path {path}"
            );
        }
    }

    #[test]
    fn refine_image_content_type_respects_real_stored_type() {
        // A real stored content-type is never overridden by the extension.
        assert_eq!(
            refine_image_content_type("/media/public/x.jpg", "image/png".to_string()),
            "image/png"
        );
        // Non-image extensions keep the generic type.
        assert_eq!(
            refine_image_content_type(
                "/media/public/notes.txt",
                "application/octet-stream".to_string()
            ),
            "application/octet-stream"
        );
    }

    #[test]
    fn parse_pod_route_valid() {
        let pubkey = "a".repeat(64);
        let path = format!("/pods/{pubkey}/profile/card");
        let (pk, rp) = parse_pod_route(&path).unwrap();
        assert_eq!(pk, pubkey);
        assert_eq!(rp, "/profile/card");
    }

    #[test]
    fn parse_pod_route_root() {
        let pubkey = "b".repeat(64);
        let path = format!("/pods/{pubkey}");
        let (pk, rp) = parse_pod_route(&path).unwrap();
        assert_eq!(pk, pubkey);
        assert_eq!(rp, "/");
    }

    #[test]
    fn parse_pod_route_with_trailing_slash() {
        let pubkey = "c".repeat(64);
        let path = format!("/pods/{pubkey}/");
        let (pk, rp) = parse_pod_route(&path).unwrap();
        assert_eq!(pk, pubkey);
        assert_eq!(rp, "/");
    }

    #[test]
    fn parse_pod_route_invalid_hex() {
        let path = format!("/pods/{}/file", "x".repeat(64));
        assert!(parse_pod_route(&path).is_none());
    }

    #[test]
    fn parse_pod_route_short_pubkey() {
        assert!(parse_pod_route("/pods/abc/file").is_none());
    }

    #[test]
    fn parse_pod_route_wrong_prefix() {
        assert!(parse_pod_route("/api/something").is_none());
    }

    #[test]
    fn parse_pod_route_no_slash_after_pubkey() {
        let pubkey = "d".repeat(64);
        let path = format!("/pods/{pubkey}extra");
        assert!(parse_pod_route(&path).is_none());
    }

    #[test]
    fn parse_pod_route_container_path() {
        let pubkey = "e".repeat(64);
        let path = format!("/pods/{pubkey}/media/");
        let (pk, rp) = parse_pod_route(&path).unwrap();
        assert_eq!(pk, pubkey);
        assert_eq!(rp, "/media/");
    }

    // ── P2: resource-path traversal guard ──────────────────────────────

    #[test]
    fn is_safe_resource_path_allows_normal_nested() {
        assert!(is_safe_resource_path("/"));
        assert!(is_safe_resource_path("/media/"));
        assert!(is_safe_resource_path("/profile/card"));
        assert!(is_safe_resource_path("/public/sub/dir/file.json"));
        assert!(is_safe_resource_path("/notes/2026-06-07.md"));
    }

    #[test]
    fn is_safe_resource_path_rejects_dotdot() {
        assert!(!is_safe_resource_path("/../etc/passwd"));
        assert!(!is_safe_resource_path("/media/../../secret"));
        assert!(!is_safe_resource_path("/a/../b"));
    }

    #[test]
    fn is_safe_resource_path_rejects_encoded_dot() {
        // %2e / %2E decode to '.'  → re-encoded traversal.
        assert!(!is_safe_resource_path("/%2e%2e%2f"));
        assert!(!is_safe_resource_path("/media/%2E%2E/secret"));
        assert!(!is_safe_resource_path("/%2efoo"));
    }

    #[test]
    fn is_safe_resource_path_rejects_encoded_slash() {
        // %2f / %2F decode to '/'  → smuggled separator.
        assert!(!is_safe_resource_path("/media%2f..%2fsecret"));
        assert!(!is_safe_resource_path("/a%2Fb"));
    }

    #[test]
    fn is_safe_resource_path_rejects_backslash_and_nul() {
        assert!(!is_safe_resource_path("/media\\..\\secret"));
        assert!(!is_safe_resource_path("/a%5cb")); // encoded backslash
        assert!(!is_safe_resource_path("/a\0b")); // raw NUL
        assert!(!is_safe_resource_path("/a%00b")); // encoded NUL
    }

    #[test]
    fn parse_pod_route_rejects_traversal() {
        let pubkey = "f".repeat(64);
        // URL-path traversal and encoded forms are rejected at route parse.
        assert!(parse_pod_route(&format!("/pods/{pubkey}/../etc")).is_none());
        assert!(parse_pod_route(&format!("/pods/{pubkey}/%2e%2e%2fsecret")).is_none());
        assert!(parse_pod_route(&format!("/pods/{pubkey}/a%2fb")).is_none());
        assert!(parse_pod_route(&format!("/pods/{pubkey}/a\\b")).is_none());
        // A normal nested path still parses.
        let normal_path = format!("/pods/{pubkey}/public/file");
        let (pk, rp) = parse_pod_route(&normal_path).unwrap();
        assert_eq!(pk, pubkey);
        assert_eq!(rp, "/public/file");
    }

    #[test]
    fn is_acl_path_detects_acl_suffix() {
        assert!(is_acl_path("/public/.acl"));
        assert!(is_acl_path("/.acl"));
        assert!(is_acl_path("/profile/card.acl"));
        assert!(!is_acl_path("/public/"));
        assert!(!is_acl_path("/profile/card"));
        assert!(!is_acl_path("/acl/resource"));
    }

    #[test]
    fn is_provision_path_detects_endpoint() {
        assert!(is_provision_path("/.provision"));
        assert!(!is_provision_path("/provision"));
        assert!(!is_provision_path("/.provision/extra"));
        assert!(!is_provision_path("/public/.provision"));
    }

    #[test]
    fn worker_pod_names_are_nostr_pubkeys() {
        assert!(is_valid_worker_pod_name(&"a".repeat(64)));
        assert!(is_valid_worker_pod_name(&"ABCDEF0123456789".repeat(4)));
        assert!(!is_valid_worker_pod_name("alice"));
        assert!(!is_valid_worker_pod_name(&"g".repeat(64)));
        assert!(!is_valid_worker_pod_name(&"a".repeat(63)));
    }

    #[test]
    fn pod_uri_uses_trimmed_public_base() {
        let base = "https://pods.example.com/".trim_end_matches('/');
        let pubkey = "a".repeat(64);
        let pod_uri = format!("{base}/pods/{pubkey}/");
        assert_eq!(pod_uri, format!("https://pods.example.com/pods/{pubkey}/"));
        assert_eq!(
            format!("{pod_uri}profile/card#me"),
            format!("https://pods.example.com/pods/{pubkey}/profile/card#me")
        );
    }

    #[test]
    fn validate_webid_html_accepts_valid() {
        let html = r##"<!DOCTYPE html>
<html>
<head>
  <script type="application/ld+json">
  {"@context": {"foaf": "http://xmlns.com/foaf/0.1/"}, "@id": "#me", "@type": "foaf:Person"}
  </script>
</head>
<body></body>
</html>"##;
        assert!(validate_webid_html(html.as_bytes()).is_ok());
    }

    #[test]
    fn validate_webid_html_rejects_no_jsonld() {
        let html = "<!DOCTYPE html><html><body>No JSON-LD here</body></html>";
        assert!(validate_webid_html(html.as_bytes()).is_err());
    }

    #[test]
    fn validate_webid_html_rejects_invalid_utf8() {
        let bad_bytes: &[u8] = &[0xff, 0xfe, 0xfd];
        assert!(validate_webid_html(bad_bytes).is_err());
    }

    #[test]
    fn validate_webid_html_rejects_invalid_jsonld() {
        let html = r##"<!DOCTYPE html>
<html>
<head>
  <script type="application/ld+json">
  {not valid json}
  </script>
</head>
<body></body>
</html>"##;
        assert!(validate_webid_html(html.as_bytes()).is_err());
    }

    // ── server-side image→ASCII opt-in detection ────────────────────────
    // The opt-in is a presentation directive only; the resource GET handler
    // still gates the actual transform on an `image/*` content type and on the
    // WAC/WebID access check having already passed.

    #[test]
    fn accept_wants_ascii_detects_media_type() {
        assert!(accept_wants_ascii(Some("text/x-ascii-art")));
        // Among a normal browser-style Accept list, with a quality value.
        assert!(accept_wants_ascii(Some(
            "text/html,application/xhtml+xml,text/x-ascii-art;q=0.9,*/*;q=0.1"
        )));
        // Case-insensitive.
        assert!(accept_wants_ascii(Some("TEXT/X-ASCII-ART")));
    }

    #[test]
    fn accept_wants_ascii_absent_or_unrelated() {
        assert!(!accept_wants_ascii(None));
        assert!(!accept_wants_ascii(Some("image/png")));
        assert!(!accept_wants_ascii(Some("text/html, */*")));
    }

    #[test]
    fn ascii_requested_via_query_format() {
        assert!(ascii_requested(Some("ascii"), None));
        assert!(ascii_requested(Some("ASCII"), None)); // case-insensitive
        assert!(!ascii_requested(Some("json"), None));
        assert!(!ascii_requested(None, None));
    }

    #[test]
    fn ascii_requested_via_accept_header() {
        assert!(ascii_requested(None, Some("text/x-ascii-art")));
        assert!(ascii_requested(
            None,
            Some("text/html, text/x-ascii-art;q=0.8")
        ));
        // Neither signal present → not requested; a raw image GET is unchanged.
        assert!(!ascii_requested(None, Some("image/png, */*")));
        assert!(!ascii_requested(Some("raw"), Some("*/*")));
    }
}
