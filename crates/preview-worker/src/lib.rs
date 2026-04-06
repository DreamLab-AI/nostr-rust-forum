//! Nostr BBS link-preview-api Worker (Rust port)
//!
//! Proxies requests to fetch OpenGraph metadata, bypassing CORS.
//! Replaces the TypeScript Cloudflare Workers implementation.
//!
//! ## Module structure
//!
//! - `ssrf` -- SSRF protection (private/internal URL blocking)
//! - `parse` -- OpenGraph metadata extraction, HTML entity decoding
//! - `oembed` -- Twitter/X oEmbed detection and fetching
//! - `rate_limit` -- Application-layer rate limiting via KV
//!
//! ## Endpoints
//!
//!   GET /preview?url=...  -- fetch OG metadata or Twitter oEmbed
//!   GET /health           -- health check
//!   GET /stats            -- cache statistics (CF Cache API)
//!   OPTIONS               -- CORS preflight

mod oembed;
mod parse;
mod rate_limit;
mod ssrf;

use serde::Serialize;
use worker::*;

use oembed::TwitterCachePayload;
use parse::OgCachePayload;

// ── Constants ────────────────────────────────────────────────────────────────

const CACHE_TTL_OG: u32 = 10 * 24 * 60 * 60; // 10 days (seconds)
const CACHE_TTL_TWITTER: u32 = 24 * 60 * 60; // 1 day  (seconds)

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
        .unwrap_or_else(|_| "https://example.com".to_string())
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

    // SSRF check
    if ssrf::is_private_url(&target_url) {
        return json_response(
            &ErrorResponse {
                error: "URL not allowed (private or internal address)".to_string(),
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

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // CORS preflight
    if req.method() == Method::Options {
        let headers = cors_headers(&env);
        return Ok(Response::empty()?.with_headers(headers).with_status(204));
    }

    // Rate limit: 30 requests per 60 seconds per IP
    let ip = rate_limit::client_ip(&req);
    if !rate_limit::check_rate_limit(&env, &ip, 30, 60).await {
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
        (Method::Get, "/preview") => handle_preview(&req, &env).await,
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
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, _env: Env, _ctx: ScheduleContext) {
    // No persistent storage to touch -- the cron itself keeps the isolate warm
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
}
