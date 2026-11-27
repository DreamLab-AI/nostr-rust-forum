//! nostr-bbs link-preview-api Worker (Rust port)
//!
//! Proxies requests to fetch OpenGraph metadata, bypassing CORS.
//! Replaces the TypeScript Cloudflare Workers implementation.
//!
//! ## Module structure
//!
//! - `ssrf` -- SSRF protection (private/internal URL blocking)
//! - `parse` -- OpenGraph metadata extraction, HTML entity decoding
//! - `oembed` -- Twitter/X oEmbed detection and fetching
//! ## Endpoints
//!
//!   GET /preview?url=...  -- fetch OG metadata or Twitter oEmbed
//!   GET /ascii?url=...    -- render a remote image to phosphor ASCII-art HTML
//!   GET /health           -- health check
//!   GET /stats            -- cache statistics (CF Cache API)
//!   OPTIONS               -- CORS preflight

mod oembed;
mod parse;
mod ssrf;

use serde::Serialize;
use worker::*;

use nostr_bbs_ascii::{render_bytes, AsciiError, GlyphRamp, RenderOptions};
use oembed::TwitterCachePayload;
use parse::OgCachePayload;

// ── Constants ────────────────────────────────────────────────────────────────

const CACHE_TTL_OG: u32 = 10 * 24 * 60 * 60; // 10 days (seconds)
const CACHE_TTL_TWITTER: u32 = 24 * 60 * 60; // 1 day  (seconds)
const CACHE_TTL_ASCII: u32 = 7 * 24 * 60 * 60; // 7 days (seconds) — ASCII of an image is deterministic

// ── Response types ───────────────────────────────────────────────────────────

#[derive(Serialize)]
struct OgPreviewResponse {
    r#type: &'static str,
    url: String,
    domain: String,
    favicon: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    image: Option<String>,
    #[serde(rename = "siteName", skip_serializing_if = "Option::is_none")]
    site_name: Option<String>,
    cached: bool,
}

#[derive(Serialize)]
struct TwitterEmbedResponse {
    r#type: &'static str,
    url: String,
    html: String,
    author_name: String,
    author_url: String,
    provider_name: String,
    cached: bool,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    runtime: &'static str,
}

#[derive(Serialize)]
struct StatsResponse {
    cache: &'static str,
    note: &'static str,
}

/// Unified cache payload for serialization/deserialization.
#[derive(Serialize, serde::Deserialize)]
#[serde(untagged)]
enum CachePayload {
    Twitter(TwitterCachePayload),
    Og(OgCachePayload),
}

// ── CORS ─────────────────────────────────────────────────────────────────────

fn allowed_origin(env: &Env) -> String {
    env.var("ALLOWED_ORIGIN")
        .map(|v| v.to_string())
        .unwrap_or_default()
}

fn cors_headers(env: &Env) -> Headers {
    let headers = Headers::new();
    let _ = headers.set("Access-Control-Allow-Origin", &allowed_origin(env));
    let _ = headers.set("Access-Control-Allow-Methods", "GET, OPTIONS");
    let _ = headers.set("Access-Control-Allow-Headers", "Content-Type");
    let _ = headers.set("Access-Control-Max-Age", "86400");
    headers
}

fn json_response(body: &impl Serialize, status: u16, env: &Env) -> Result<Response> {
    json_response_extra(body, status, env, None)
}

fn json_response_extra(
    body: &impl Serialize,
    status: u16,
    env: &Env,
    extra_headers: Option<(&str, &str)>,
) -> Result<Response> {
    let json = serde_json::to_string(body).map_err(|e| Error::RustError(e.to_string()))?;
    let headers = cors_headers(env);
    let _ = headers.set("Content-Type", "application/json");
    if let Some((key, value)) = extra_headers {
        let _ = headers.set(key, value);
    }
    Ok(Response::from_body(ResponseBody::Body(json.into_bytes()))?
        .with_headers(headers)
        .with_status(status))
}

// ── Percent encoding (inline to avoid extra crate) ───────────────────────────

pub(crate) fn percent_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}

// ── Cache helpers (CF Cache API) ─────────────────────────────────────────────

fn cache_key(target_url: &str) -> String {
    format!(
        "https://link-preview-cache.internal/v1?url={}",
        percent_encode(target_url)
    )
}

async fn get_from_cache(target_url: &str) -> Option<Response> {
    let cache = Cache::default();
    let key = cache_key(target_url);
    cache.get(&key, false).await.ok().flatten()
}

async fn put_to_cache(target_url: &str, payload: &CachePayload, ttl: u32, env: &Env) {
    let cache = Cache::default();
    let key = cache_key(target_url);

    let body = match serde_json::to_string(payload) {
        Ok(b) => b,
        Err(_) => return,
    };

    let headers = cors_headers(env);
    let _ = headers.set("Content-Type", "application/json");
    let _ = headers.set("Cache-Control", &format!("public, max-age={}", ttl));

    if let Ok(response) =
        Response::from_body(ResponseBody::Body(body.into_bytes())).map(|r| r.with_headers(headers))
    {
        let _ = cache.put(&key, response).await;
    }
}

// ── ASCII cache helpers (HTML payload, distinct key namespace) ───────────────

/// Canonical, stable name for a glyph ramp — used in the ASCII cache key so two
/// requests that normalise to the same ramp (e.g. `ramp=block` and
/// `ramp=blocks`) share a cache entry.
fn ramp_name(ramp: GlyphRamp) -> &'static str {
    match ramp {
        GlyphRamp::Standard => "standard",
        GlyphRamp::Blocks => "blocks",
        GlyphRamp::Dense => "dense",
    }
}

/// Synthetic CF Cache API key for a rendered ASCII image. Deterministic in the
/// full render input (url + cols + ramp + invert) and kept in a separate
/// `/ascii/v1` path namespace so it can never collide with the JSON preview
/// cache (`/v1`).
fn ascii_cache_key(target_url: &str, cols: u32, ramp: &str, invert: bool) -> String {
    format!(
        "https://link-preview-cache.internal/ascii/v1?url={}&cols={}&ramp={}&invert={}",
        percent_encode(target_url),
        cols,
        ramp,
        invert as u8
    )
}

async fn get_ascii_from_cache(key: &str) -> Option<Response> {
    let cache = Cache::default();
    cache.get(key, false).await.ok().flatten()
}

async fn put_ascii_to_cache(key: &str, html: &str, env: &Env) {
    let cache = Cache::default();
    let headers = cors_headers(env);
    let _ = headers.set("Content-Type", "text/html; charset=utf-8");
    let _ = headers.set(
        "Cache-Control",
        &format!("public, max-age={}", CACHE_TTL_ASCII),
    );
    if let Ok(response) = Response::from_body(ResponseBody::Body(html.as_bytes().to_vec()))
        .map(|r| r.with_headers(headers))
    {
        let _ = cache.put(key, response).await;
    }
}

/// Build a `text/html` response with the worker's CORS headers and an
/// `X-Cache` state header (`HIT`/`MISS`).
fn html_response(html: String, status: u16, env: &Env, cache_state: &str) -> Result<Response> {
    let headers = cors_headers(env);
    let _ = headers.set("Content-Type", "text/html; charset=utf-8");
    let _ = headers.set("X-Cache", cache_state);
    Ok(Response::from_body(ResponseBody::Body(html.into_bytes()))?
        .with_headers(headers)
        .with_status(status))
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn handle_preview(req: &Request, env: &Env) -> Result<Response> {
    let url = req.url()?;
    let target_url = url
        .query_pairs()
        .find(|(k, _)| k == "url")
        .map(|(_, v)| v.to_string());

    let target_url = match target_url {
        Some(u) => u,
        None => {
            return json_response(
                &ErrorResponse {
                    error: "Missing url parameter".to_string(),
                },
                400,
                env,
            )
        }
    };

    // Validate URL
    if Url::parse(&target_url).is_err() {
        return json_response(
            &ErrorResponse {
                error: "Invalid URL".to_string(),
            },
            400,
            env,
        );
    }

    // SSRF check: say which rule refused (allow-list or internal address).
    if let Some(refusal) = ssrf::refusal(&target_url) {
        return json_response(
            &ErrorResponse {
                error: refusal.message().to_string(),
            },
            400,
            env,
        );
    }

    let is_twitter = oembed::is_twitter_url(&target_url);

    // Check CF Cache API
    if let Some(mut cached) = get_from_cache(&target_url).await {
        if let Ok(text) = cached.text().await {
            if let Ok(mut data) = serde_json::from_str::<serde_json::Value>(&text) {
                data["cached"] = serde_json::Value::Bool(true);
                return json_response_extra(&data, 200, env, Some(("X-Cache", "HIT")));
            }
        }
    }

    if is_twitter {
        match oembed::fetch_twitter_embed(&target_url).await {
            Ok(data) => {
                let cache_payload = CachePayload::Twitter(data.clone());
                put_to_cache(&target_url, &cache_payload, CACHE_TTL_TWITTER, env).await;

                let response = TwitterEmbedResponse {
                    r#type: "twitter",
                    url: data.url,
                    html: data.html,
                    author_name: data.author_name,
                    author_url: data.author_url,
                    provider_name: data.provider_name,
                    cached: false,
                };
                json_response_extra(&response, 200, env, Some(("X-Cache", "MISS")))
            }
            Err(e) => json_response(
                &ErrorResponse {
                    error: e.to_string(),
                },
                500,
                env,
            ),
        }
    } else {
        match parse::fetch_open_graph_data(&target_url).await {
            Ok(data) => {
                let cache_payload = CachePayload::Og(data.clone());
                put_to_cache(&target_url, &cache_payload, CACHE_TTL_OG, env).await;

                let response = OgPreviewResponse {
                    r#type: "opengraph",
                    url: data.url,
                    domain: data.domain,
                    favicon: data.favicon,
                    title: data.title,
                    description: data.description,
                    image: data.image,
                    site_name: data.site_name,
                    cached: false,
                };
                json_response_extra(&response, 200, env, Some(("X-Cache", "MISS")))
            }
            Err(e) => json_response(
                &ErrorResponse {
                    error: e.to_string(),
                },
                500,
                env,
            ),
        }
    }
}

async fn handle_ascii(req: &Request, env: &Env) -> Result<Response> {
    let url = req.url()?;

    // Parse query params: required `url`; optional `cols`/`ramp`/`invert`.
    let mut target_url: Option<String> = None;
    let mut cols: Option<u32> = None;
    let mut ramp_raw: Option<String> = None;
    let mut invert = false;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "url" => target_url = Some(v.into_owned()),
            "cols" => cols = v.parse::<u32>().ok(),
            "ramp" => ramp_raw = Some(v.into_owned()),
            "invert" => invert = matches!(v.as_ref(), "1" | "true"),
            _ => {}
        }
    }

    let target_url = match target_url {
        Some(u) => u,
        None => {
            return json_response(
                &ErrorResponse {
                    error: "Missing url parameter".to_string(),
                },
                400,
                env,
            )
        }
    };

    // Validate URL
    if Url::parse(&target_url).is_err() {
        return json_response(
            &ErrorResponse {
                error: "Invalid URL".to_string(),
            },
            400,
            env,
        );
    }

    // SSRF check: say which rule refused (allow-list or internal address).
    if let Some(refusal) = ssrf::refusal(&target_url) {
        return json_response(
            &ErrorResponse {
                error: refusal.message().to_string(),
            },
            400,
            env,
        );
    }

    // Build render options. `cols` defaults to the crate's 80; the crate clamps
    // out-of-range values internally.
    let ramp = GlyphRamp::parse(ramp_raw.as_deref().unwrap_or(""));
    let mut opts = RenderOptions::default();
    if let Some(c) = cols {
        opts.cols = c;
    }
    opts.ramp = ramp;
    opts.invert = invert;

    let key = ascii_cache_key(&target_url, opts.cols, ramp_name(ramp), invert);

    // Check CF Cache API (HTML payload).
    if let Some(mut cached) = get_ascii_from_cache(&key).await {
        if let Ok(html) = cached.text().await {
            return html_response(html, 200, env, "HIT");
        }
    }

    // Miss: fetch the image bytes (through a service binding for the
    // deployment's own Workers, SSRF-checked on every hop otherwise), then
    // render. The upstream answer is checked before anything is decoded, so
    // an error page is reported as what it is rather than as a corrupt image.
    let headers = Headers::new();
    let _ = headers.set("Accept", "image/*");
    let _ = headers.set("User-Agent", "LinkPreviewAPI/1.0 (ASCII Render Bot)");

    let bindings = env
        .var(SERVICE_BINDINGS_VAR)
        .map(|v| v.to_string())
        .unwrap_or_default();
    let host = Url::parse(&target_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_default();
    let fetched = match service_binding_for(&bindings, &host) {
        Some(binding) => fetch_via_binding(env, &binding, &target_url, &headers).await,
        None => ssrf::ssrf_fetch_with_redirects(&target_url, &headers)
            .await
            .map_err(|e| e.to_string()),
    };
    let response = match fetched {
        Ok(r) => r,
        Err(error) => return json_response(&ErrorResponse { error }, 502, env),
    };

    let content_type = response.headers().get("Content-Type").ok().flatten();
    if let Some((status, error)) = upstream_problem(response.status_code(), content_type.as_deref())
    {
        return json_response(&ErrorResponse { error }, status, env);
    }

    let bytes = match ssrf::read_bytes_capped(response, ssrf::MAX_IMAGE_BYTES).await {
        Ok(b) => b,
        Err(ssrf::SsrfFetchError::BodyTooLarge) => {
            return json_response(
                &ErrorResponse {
                    error: format!(
                        "image too large: over {} MB",
                        ssrf::MAX_IMAGE_BYTES / (1024 * 1024)
                    ),
                },
                413,
                env,
            )
        }
        Err(e) => {
            return json_response(
                &ErrorResponse {
                    error: e.to_string(),
                },
                502,
                env,
            )
        }
    };

    match render_bytes(&bytes, &opts) {
        Ok(art) => {
            let html = art.to_html();
            put_ascii_to_cache(&key, &html, env).await;
            html_response(html, 200, env, "MISS")
        }
        Err(e) => json_response(
            &ErrorResponse {
                error: e.to_string(),
            },
            ascii_error_status(e),
            env,
        ),
    }
}

/// Worker variable naming the service bindings `/ascii` fetches through:
/// `"host=BINDING, host2=BINDING2"`. A Worker cannot `fetch()` another Worker
/// on the same Cloudflare zone (the `*.workers.dev` subdomain counts) over the
/// public internet: the runtime answers with an error page instead (error
/// 1042). Images on the deployment's own pod Workers therefore need a
/// `[[services]]` binding in `wrangler.toml` and an entry here. The host must
/// still pass the egress allow-list.
const SERVICE_BINDINGS_VAR: &str = "PREVIEW_SERVICE_BINDINGS";

/// The service binding configured for `host` in a [`SERVICE_BINDINGS_VAR`]
/// value, if any (host compared case-insensitively; malformed entries are
/// ignored).
fn service_binding_for(spec: &str, host: &str) -> Option<String> {
    if host.is_empty() {
        return None;
    }
    spec.split([',', ';', '\n'])
        .filter_map(|entry| entry.split_once('='))
        .map(|(h, b)| (h.trim().to_ascii_lowercase(), b.trim()))
        .find(|(h, b)| h == host && !b.is_empty())
        .map(|(_, b)| b.to_string())
}

/// GET `url` through the service binding `binding`: one hop, no redirects
/// (a redirect out of our own Worker is refused rather than followed outside
/// the SSRF checks).
async fn fetch_via_binding(
    env: &Env,
    binding: &str,
    url: &str,
    headers: &Headers,
) -> std::result::Result<Response, String> {
    let fetcher = env
        .service(binding)
        .map_err(|e| format!("service binding {binding} unavailable: {e}"))?;
    let req = ssrf::build_request(url, headers, Method::Get).map_err(|e| e.to_string())?;
    let response = fetcher
        .fetch_request(req)
        .await
        .map_err(|e| format!("service binding {binding} fetch failed: {e}"))?;
    if (300..400).contains(&response.status_code()) {
        return Err("redirect via service binding refused".to_string());
    }
    Ok(response)
}

/// Why an upstream answer cannot be an image, as the `/ascii` status and
/// message: a non-2xx status (502, naming it), or a declared non-image
/// content type (415). A missing or generic binary type passes; the bytes are
/// sniffed when decoded.
fn upstream_problem(status: u16, content_type: Option<&str>) -> Option<(u16, String)> {
    if !(200..300).contains(&status) {
        return Some((502, format!("upstream answered HTTP {status}")));
    }
    let media = content_type
        .and_then(|c| c.split(';').next())
        .map(|m| m.trim().to_ascii_lowercase())
        .filter(|m| !m.is_empty())?;
    let binary = matches!(
        media.as_str(),
        "application/octet-stream" | "binary/octet-stream"
    );
    if media.starts_with("image/") || binary {
        None
    } else {
        Some((415, format!("not an image: upstream sent {media}")))
    }
}

/// HTTP status for a render failure: 415 not an image, 413 too large, 422
/// corrupt (and any failure a later crate version adds).
fn ascii_error_status(e: AsciiError) -> u16 {
    match e {
        AsciiError::NotAnImage => 415,
        AsciiError::TooLarge => 413,
        _ => 422,
    }
}

fn handle_health(env: &Env) -> Result<Response> {
    json_response(
        &HealthResponse {
            status: "ok",
            service: "link-preview-api",
            runtime: "workers-rs",
        },
        200,
        env,
    )
}

fn handle_stats(env: &Env) -> Result<Response> {
    json_response(
        &StatsResponse {
            cache: "cf-cache-api",
            note: "Per-key hit stats are available in Cloudflare Analytics dashboard",
        },
        200,
        env,
    )
}

// ── Router ───────────────────────────────────────────────────────────────────

/// Body of the 503 returned by `/preview` and `/ascii` while the egress policy
/// is closed (no `PREVIEW_ALLOWED_HOSTS`, no development opt-out).
const EGRESS_CLOSED_ERROR: &str =
    "Link previews are disabled: PREVIEW_ALLOWED_HOSTS is not configured";

// wasm-bindgen registers this as the fetch handler; it is invoked only from the
// generated glue on the wasm32 target and appears unused to native `cargo check`.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // CORS preflight
    if req.method() == Method::Options {
        let headers = cors_headers(&env);
        return Ok(Response::empty()?.with_headers(headers).with_status(204));
    }

    // Install the egress policy from the JS `Env` on every request. The lazy
    // `std::env` fallback in `ssrf` is inert under the CF Workers WASM runtime
    // (vars arrive via this `Env`, not the process environment). Unset or blank
    // `PREVIEW_ALLOWED_HOSTS` fails closed unless the development opt-out
    // `PREVIEW_ALLOW_ANY_HOST = "true"` is present; see `ssrf` module docs.
    let var = |name: &str| env.var(name).ok().map(|v| v.to_string());
    let policy = ssrf::EgressPolicy::from_vars(
        var(ssrf::ALLOWED_HOSTS_VAR).as_deref(),
        var(ssrf::ALLOW_ANY_HOST_VAR).as_deref(),
    );
    let egress_closed = policy.is_closed();
    ssrf::set_policy(policy);

    // Rate limit: 30 requests per 60 seconds per IP
    let ip = nostr_bbs_rate_limit::client_ip(&req);
    if !nostr_bbs_rate_limit::check_rate_limit(&env, "RATE_LIMIT", &ip, 30, 60).await {
        return json_response(
            &ErrorResponse {
                error: "Too many requests".to_string(),
            },
            429,
            &env,
        );
    }

    let url = req.url()?;
    let path = url.path();

    let result = match (req.method(), path) {
        (Method::Get, "/preview" | "/ascii") if egress_closed => json_response(
            &ErrorResponse {
                error: EGRESS_CLOSED_ERROR.to_string(),
            },
            503,
            &env,
        ),
        (Method::Get, "/preview") => handle_preview(&req, &env).await,
        (Method::Get, "/ascii") => handle_ascii(&req, &env).await,
        (Method::Get, "/health") => handle_health(&env),
        (Method::Get, "/stats") => handle_stats(&env),
        _ => json_response(
            &ErrorResponse {
                error: "Not found".to_string(),
            },
            404,
            &env,
        ),
    };

    match result {
        Ok(resp) => Ok(resp),
        Err(e) => {
            console_error!("Worker error: {}", e);
            json_response(
                &ErrorResponse {
                    error: e.to_string(),
                },
                500,
                &env,
            )
        }
    }
}

// Cron keep-warm: prevents cold starts by running periodically
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, _env: Env, _ctx: ScheduleContext) {
    // No persistent storage to touch -- the cron itself keeps the isolate warm
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_errors_are_named_before_decoding() {
        assert_eq!(
            upstream_problem(404, Some("text/html")),
            Some((502, "upstream answered HTTP 404".to_string()))
        );
        assert_eq!(
            upstream_problem(401, Some("application/json")).map(|p| p.0),
            Some(502)
        );
        assert_eq!(
            upstream_problem(200, Some("text/html; charset=UTF-8")),
            Some((415, "not an image: upstream sent text/html".to_string()))
        );
        assert_eq!(upstream_problem(200, Some("image/jpeg")), None);
        assert_eq!(upstream_problem(200, Some("IMAGE/WEBP")), None);
        assert_eq!(
            upstream_problem(200, Some("application/octet-stream")),
            None
        );
        assert_eq!(upstream_problem(200, None), None);
    }

    #[test]
    fn render_failures_have_distinct_statuses() {
        assert_eq!(ascii_error_status(AsciiError::NotAnImage), 415);
        assert_eq!(ascii_error_status(AsciiError::TooLarge), 413);
        assert_eq!(ascii_error_status(AsciiError::Decode), 422);
    }

    #[test]
    fn service_bindings_are_matched_by_host() {
        let spec =
            "Pods.Example.workers.dev = POD_V2, old-pods.example.workers.dev=POD_V1;bad, empty=";
        assert_eq!(
            service_binding_for(spec, "pods.example.workers.dev").as_deref(),
            Some("POD_V2")
        );
        assert_eq!(
            service_binding_for(spec, "old-pods.example.workers.dev").as_deref(),
            Some("POD_V1")
        );
        assert_eq!(service_binding_for(spec, "empty"), None);
        assert_eq!(service_binding_for(spec, "cdn.example.com"), None);
        assert_eq!(service_binding_for("", "pods.example.workers.dev"), None);
        assert_eq!(service_binding_for(spec, ""), None);
    }

    // Cache key tests
    #[test]
    fn cache_key_is_deterministic() {
        let key1 = cache_key("https://example.com/page");
        let key2 = cache_key("https://example.com/page");
        assert_eq!(key1, key2);
        assert!(key1.starts_with("https://link-preview-cache.internal/v1?url="));
    }

    #[test]
    fn cache_keys_differ_for_different_urls() {
        let key1 = cache_key("https://example.com/a");
        let key2 = cache_key("https://example.com/b");
        assert_ne!(key1, key2);
    }

    // Percent encoding tests
    #[test]
    fn encodes_special_chars() {
        assert_eq!(percent_encode("hello world"), "hello%20world");
        assert_eq!(percent_encode("a=b&c=d"), "a%3Db%26c%3Dd");
    }

    #[test]
    fn preserves_unreserved_chars() {
        assert_eq!(percent_encode("abc-_.~"), "abc-_.~");
        assert_eq!(percent_encode("ABC123"), "ABC123");
    }

    // ── ASCII cache-key tests ──────────────────────────────────────────────
    #[test]
    fn ascii_cache_key_is_deterministic() {
        let k1 = ascii_cache_key("https://example.com/cat.png", 80, "standard", false);
        let k2 = ascii_cache_key("https://example.com/cat.png", 80, "standard", false);
        assert_eq!(k1, k2);
        assert!(k1.starts_with("https://link-preview-cache.internal/ascii/v1?url="));
    }

    #[test]
    fn ascii_cache_key_varies_with_render_params() {
        let base = ascii_cache_key("https://example.com/cat.png", 80, "standard", false);
        // Each render parameter must change the key independently.
        assert_ne!(
            base,
            ascii_cache_key("https://example.com/cat.png", 120, "standard", false)
        );
        assert_ne!(
            base,
            ascii_cache_key("https://example.com/cat.png", 80, "blocks", false)
        );
        assert_ne!(
            base,
            ascii_cache_key("https://example.com/cat.png", 80, "standard", true)
        );
        assert_ne!(
            base,
            ascii_cache_key("https://example.com/other.png", 80, "standard", false)
        );
    }

    #[test]
    fn ascii_cache_key_namespace_disjoint_from_preview() {
        // The ASCII (`/ascii/v1`) and JSON preview (`/v1`) caches must never
        // collide for the same target URL.
        let ascii = ascii_cache_key("https://example.com/x.png", 80, "standard", false);
        let preview = cache_key("https://example.com/x.png");
        assert_ne!(ascii, preview);
        assert!(ascii.contains("/ascii/v1?"));
        assert!(preview.contains("/v1?"));
    }

    // ── Ramp normalisation ─────────────────────────────────────────────────
    #[test]
    fn ramp_name_is_canonical_across_aliases() {
        // Aliased query strings normalise to the same canonical cache token, so
        // `ramp=block` and `ramp=blocks` share a cache entry.
        assert_eq!(ramp_name(GlyphRamp::parse("block")), "blocks");
        assert_eq!(ramp_name(GlyphRamp::parse("blocks")), "blocks");
        assert_eq!(ramp_name(GlyphRamp::parse("fine")), "dense");
        assert_eq!(ramp_name(GlyphRamp::parse("dense")), "dense");
        // Unknown values fall back to the standard ramp.
        assert_eq!(ramp_name(GlyphRamp::parse("nonsense")), "standard");
        assert_eq!(ramp_name(GlyphRamp::parse("")), "standard");
    }

    #[test]
    fn ascii_ttl_is_a_week() {
        const { assert!(CACHE_TTL_ASCII == 7 * 24 * 60 * 60) };
    }
}
