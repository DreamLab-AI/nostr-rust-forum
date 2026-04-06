//! Nostr BBS Search Worker (Rust)
//!
//! Cloudflare Workers-based vector search with:
//! - In-memory cosine k-NN over 384-dim embeddings
//! - RVF binary format persistence to R2
//! - id↔label mapping in KV
//! - NIP-98 authenticated ingest
//! - Hash-based fallback embedding generation
//!
//! ## Architecture
//!
//! - `lib.rs`   -- HTTP router, CORS, entry point
//! - `store.rs` -- In-memory vector store, RVF serialization
//! - `embed.rs` -- Hash-based embedding generator
//! - `auth.rs`  -- NIP-98 admin verification

mod auth;
mod embed;
mod rate_limit;
mod store;

use embed::DIM;
use serde::Deserialize;
use store::VectorStore;
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
        origins.into_iter().next().unwrap_or_else(|| "https://example.com".to_string())
    }
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
            "Content-Type, Authorization",
        )
        .ok();
    headers.set("Access-Control-Max-Age", "86400").ok();
    headers.set("Vary", "Origin").ok();
    headers
}

fn json_response(req: &Request, env: &Env, body: &serde_json::Value, status: u16) -> Result<Response> {
    let json_str = serde_json::to_string(body).map_err(|e| Error::RustError(e.to_string()))?;
    let headers = cors_headers(req, env);
    headers.set("Content-Type", "application/json").ok();
    Ok(Response::ok(json_str)?
        .with_status(status)
        .with_headers(headers))
}

// ---------------------------------------------------------------------------
// Request/Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SearchRequest {
    embedding: Vec<f32>,
    #[serde(default = "default_k")]
    k: usize,
    #[serde(default, rename = "minScore")]
    min_score: f32,
}

fn default_k() -> usize {
    10
}

#[derive(Deserialize)]
struct IngestEntry {
    id: String,
    embedding: Vec<f32>,
}

#[derive(Deserialize)]
struct IngestRequest {
    entries: Vec<IngestEntry>,
}

#[derive(Deserialize)]
struct EmbedRequest {
    text: Option<String>,
    texts: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Store lifecycle (R2 + KV)
// ---------------------------------------------------------------------------

/// Load the vector store from R2, or create empty if none exists.
async fn load_store(env: &Env) -> Result<VectorStore> {
    let store_key = env
        .var("RVF_STORE_KEY")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "forum.rvf".to_string());

    let bucket = env.bucket("VECTORS")?;
    let obj = bucket.get(&store_key).execute().await?;

    if let Some(obj) = obj {
        let bytes = obj.body().unwrap().bytes().await?;
        if let Some(store) = VectorStore::from_rvf_bytes(&bytes) {
            return Ok(store);
        }
    }

    Ok(VectorStore::new())
}

/// Persist the vector store to R2 as RVF binary + mapping to KV.
async fn persist_store(
    store: &VectorStore,
    id_to_label: &std::collections::HashMap<String, u64>,
    next_label: u64,
    env: &Env,
) -> Result<()> {
    let store_key = env
        .var("RVF_STORE_KEY")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "forum.rvf".to_string());

    // Persist RVF bytes to R2
    let rvf_bytes = store.to_rvf_bytes();
    let bucket = env.bucket("VECTORS")?;
    bucket.put(&store_key, rvf_bytes).execute().await?;

    // Persist id↔label mapping to KV
    let kv = env.kv("SEARCH_CONFIG")?;
    let pairs: Vec<(&str, u64)> = id_to_label.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    let mapping = serde_json::json!({
        "pairs": pairs,
        "next": next_label,
    });
    kv.put(
        &format!("{store_key}:mapping"),
        serde_json::to_string(&mapping).map_err(|e| Error::RustError(e.to_string()))?,
    )?
    .execute()
    .await?;

    Ok(())
}

/// Load id↔label mapping from KV.
async fn load_mapping(
    env: &Env,
) -> Result<(std::collections::HashMap<String, u64>, std::collections::HashMap<u64, String>, u64)>
{
    let store_key = env
        .var("RVF_STORE_KEY")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "forum.rvf".to_string());

    let kv = env.kv("SEARCH_CONFIG")?;
    let mapping_key = format!("{store_key}:mapping");

    if let Some(json_str) = kv.get(&mapping_key).text().await? {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
            let next = val["next"].as_u64().unwrap_or(1);
            let mut id_to_label = std::collections::HashMap::new();
            let mut label_to_id = std::collections::HashMap::new();

            if let Some(pairs) = val["pairs"].as_array() {
                for pair in pairs {
                    if let (Some(id), Some(label)) = (pair[0].as_str(), pair[1].as_u64()) {
                        id_to_label.insert(id.to_string(), label);
                        label_to_id.insert(label, id.to_string());
                    }
                }
            }

            return Ok((id_to_label, label_to_id, next));
        }
    }

    Ok((
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
        1,
    ))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_search(req: &Request, env: &Env) -> Result<Response> {
    let mut req_clone = req.clone()?;
    let body: SearchRequest = req_clone.json().await?;

    if body.embedding.len() != DIM {
        return json_response(
            req,
            env,
            &serde_json::json!({ "error": format!("Expected {DIM}-dim embedding") }),
            400,
        );
    }

    let store = load_store(env).await?;
    let k = body.k.clamp(1, 100);

    if store.count() == 0 {
        return json_response(
            req,
            env,
            &serde_json::json!({ "results": [], "totalVectors": 0 }),
            200,
        );
    }

    let (_, label_to_id, _) = load_mapping(env).await?;
    let results = store.search(&body.embedding, k, body.min_score);

    let results_json: Vec<serde_json::Value> = results
        .iter()
        .map(|(label, score)| {
            let id = label_to_id
                .get(label)
                .cloned()
                .unwrap_or_else(|| label.to_string());
            serde_json::json!({
                "id": id,
                "distance": 1.0 - score,
                "score": score,
            })
        })
        .collect();

    json_response(
        req,
        env,
        &serde_json::json!({
            "results": results_json,
            "totalVectors": store.count(),
            "engine": "rvf-rust",
            "dimensions": DIM,
        }),
        200,
    )
}

async fn handle_embed(req: &Request, env: &Env) -> Result<Response> {
    let mut req_clone = req.clone()?;
    let body: EmbedRequest = req_clone.json().await?;

    let texts: Vec<String> = match (body.texts, body.text) {
        (Some(texts), _) => texts,
        (None, Some(text)) => vec![text],
        (None, None) => {
            return json_response(
                req,
                env,
                &serde_json::json!({ "error": "Missing text or texts field" }),
                400,
            );
        }
    };

    if texts.is_empty() {
        return json_response(
            req,
            env,
            &serde_json::json!({ "error": "Missing text or texts field" }),
            400,
        );
    }
    if texts.len() > 100 {
        return json_response(
            req,
            env,
            &serde_json::json!({ "error": "Maximum 100 texts per request" }),
            400,
        );
    }

    let embeddings: Vec<Vec<f32>> = texts.iter().map(|t| embed::generate_embedding(t)).collect();

    json_response(
        req,
        env,
        &serde_json::json!({
            "embeddings": embeddings,
            "dimensions": DIM,
            "model": "hash-fallback-v1",
            "note": "Hash-based fallback embedding. Replace with ONNX WASM model for semantic quality.",
        }),
        200,
    )
}

async fn handle_ingest(req: &Request, env: &Env) -> Result<Response> {
    // NIP-98 admin auth
    let url = req.url()?;
    let request_url = format!("{}{}", url.origin().ascii_serialization(), url.path());
    let auth_header = req.headers().get("Authorization")?;
    let mut req_clone = req.clone()?;
    let raw_body = req_clone.bytes().await?;

    if let Err((err_body, status)) = auth::require_nip98_admin(
        auth_header.as_deref(),
        &request_url,
        "POST",
        Some(&raw_body),
        env,
    ) {
        return json_response(req, env, &err_body, status);
    }

    let body: IngestRequest =
        serde_json::from_slice(&raw_body).map_err(|e| Error::RustError(e.to_string()))?;

    if body.entries.is_empty() {
        return json_response(
            req,
            env,
            &serde_json::json!({ "error": "Missing entries array" }),
            400,
        );
    }

    let mut store = load_store(env).await?;
    let (mut id_to_label, _, mut next_label) = load_mapping(env).await?;

    let mut accepted = 0u32;
    let mut rejected = 0u32;

    for entry in &body.entries {
        if entry.id.is_empty() || entry.embedding.len() != DIM {
            rejected += 1;
            continue;
        }

        let label = *id_to_label.entry(entry.id.clone()).or_insert_with(|| {
            let l = next_label;
            next_label += 1;
            l
        });

        store.insert(label, &entry.embedding);
        accepted += 1;
    }

    // Persist to R2 + KV
    persist_store(&store, &id_to_label, next_label, env).await?;

    json_response(
        req,
        env,
        &serde_json::json!({
            "accepted": accepted,
            "rejected": rejected,
            "totalVectors": store.count(),
            "engine": "rvf-rust",
        }),
        200,
    )
}

async fn handle_status(req: &Request, env: &Env) -> Result<Response> {
    let store = load_store(env).await?;

    json_response(
        req,
        env,
        &serde_json::json!({
            "status": "healthy",
            "totalVectors": store.count(),
            "dimensions": DIM,
            "metric": "cosine",
            "model": "all-MiniLM-L6-v2",
            "engine": "rvf-rust",
            "runtime": "workers-rs",
            "format": "rvf-v1",
        }),
        200,
    )
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // CORS preflight
    if req.method() == Method::Options {
        return Ok(Response::empty()?
            .with_status(204)
            .with_headers(cors_headers(&req, &env)));
    }

    // Rate limit: 100 requests per 60 seconds per IP
    let ip = rate_limit::client_ip(&req);
    if !rate_limit::check_rate_limit(&env, &ip, 100, 60).await {
        return json_response(
            &req,
            &env,
            &serde_json::json!({ "error": "Too many requests" }),
            429,
        );
    }

    let url = req.url()?;
    let path = url.path();

    let result = route(&req, &env, path).await;
    match result {
        Ok(resp) => Ok(resp),
        Err(e) => {
            console_error!("Search worker error: {e}");
            let msg = e.to_string();
            if msg.contains("JSON") || msg.contains("json") || msg.contains("Syntax") {
                json_response(
                    &req,
                    &env,
                    &serde_json::json!({ "error": "Invalid JSON body" }),
                    400,
                )
            } else {
                json_response(
                    &req,
                    &env,
                    &serde_json::json!({ "error": "Internal error" }),
                    500,
                )
            }
        }
    }
}

async fn route(req: &Request, env: &Env, path: &str) -> Result<Response> {
    let method = req.method();

    // Health / status
    if (path == "/health" || path == "/status" || path == "/") && method == Method::Get {
        return handle_status(req, env).await;
    }

    // Search
    if path == "/search" && method == Method::Post {
        return handle_search(req, env).await;
    }

    // Embed
    if path == "/embed" && method == Method::Post {
        return handle_embed(req, env).await;
    }

    // Ingest (NIP-98 admin only)
    if path == "/ingest" && method == Method::Post {
        return handle_ingest(req, env).await;
    }

    json_response(req, env, &serde_json::json!({ "error": "Not found" }), 404)
}

// ---------------------------------------------------------------------------
// Cron keep-warm
// ---------------------------------------------------------------------------

#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    // Touch R2 to keep the connection warm
    let _ = load_store(&env).await;
}
