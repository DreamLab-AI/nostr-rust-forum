//! RuVector semantic search client for the Nostr BBS forum.
//!
//! Talks to the search-api Cloudflare Worker for embedding generation,
//! k-NN vector search, and message ingestion (NIP-98 authenticated).

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

const SEARCH_API: &str = match option_env!("VITE_SEARCH_API_URL") {
    Some(u) => u,
    None => "https://search.example.com",
};

// ── Public types ──

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SearchResult {
    pub id: String,
    pub score: f64,
    #[serde(default)]
    pub distance: f64,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SearchStats {
    #[serde(rename = "totalVectors", default)]
    pub total_vectors: u32,
    #[serde(default)]
    pub dimensions: u32,
    #[serde(default)]
    pub engine: String,
}

// ── Public API ──

/// Generate embedding via search-api /embed endpoint (hash-based fallback).
pub async fn embed_query(text: &str) -> Result<Vec<f64>, String> {
    let url = format!("{}/embed", SEARCH_API);
    let body = serde_json::json!({ "text": text });

    let response = fetch_json_post(&url, &body.to_string(), None).await?;

    #[derive(serde::Deserialize)]
    struct EmbedResponse {
        embeddings: Vec<Vec<f64>>,
    }

    let data: EmbedResponse =
        serde_json::from_str(&response).map_err(|e| format!("Parse error: {}", e))?;

    data.embeddings
        .into_iter()
        .next()
        .ok_or_else(|| "No embedding returned".to_string())
}

/// Search for similar content via search-api /search endpoint.
pub async fn search_similar(
    query: &str,
    k: u32,
    min_score: f64,
    channel: Option<&str>,
) -> Result<Vec<SearchResult>, String> {
    let embedding = embed_query(query).await?;

    let url = format!("{}/search", SEARCH_API);
    let mut body = serde_json::json!({
        "embedding": embedding,
        "k": k,
        "minScore": min_score,
    });

    if let Some(ch) = channel {
        body["channel"] = serde_json::json!(ch);
    }

    let response = fetch_json_post(&url, &body.to_string(), None).await?;

    #[derive(serde::Deserialize)]
    struct SearchResponse {
        results: Vec<SearchResult>,
    }

    let data: SearchResponse =
        serde_json::from_str(&response).map_err(|e| format!("Parse error: {}", e))?;

    Ok(data.results)
}

/// Index a new message for semantic search (NIP-98 authenticated).
pub async fn ingest_message(
    event_id: &str,
    content: &str,
    channel: Option<&str>,
    secret_key: &[u8; 32],
) -> Result<bool, String> {
    let embedding = embed_query(content).await?;

    let url = format!("{}/ingest", SEARCH_API);
    let body = serde_json::json!({
        "entries": [{
            "id": event_id,
            "embedding": embedding,
            "channel": channel,
            "timestamp": (js_sys::Date::now() / 1000.0) as u64,
        }]
    });
    let body_str = body.to_string();

    // Create NIP-98 auth token
    let token = crate::auth::nip98::create_nip98_token(
        secret_key,
        &url,
        "POST",
        Some(body_str.as_bytes()),
    )
    .map_err(|e| format!("NIP-98 error: {}", e))?;

    let response = fetch_json_post(&url, &body_str, Some(&token)).await?;

    #[derive(serde::Deserialize)]
    struct IngestResponse {
        #[serde(default)]
        accepted: u32,
    }

    let data: IngestResponse =
        serde_json::from_str(&response).map_err(|e| format!("Parse error: {}", e))?;

    Ok(data.accepted > 0)
}

/// Get search API status.
pub async fn get_search_status() -> Result<SearchStats, String> {
    let url = format!("{}/status", SEARCH_API);
    let response = fetch_get(&url).await?;
    serde_json::from_str(&response).map_err(|e| format!("Parse error: {}", e))
}

/// Cosine similarity between two vectors.
#[allow(dead_code)]
pub fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    if a.len() != b.len() {
        return 0.0;
    }
    let mut dot = 0.0;
    let mut norm_a = 0.0;
    let mut norm_b = 0.0;
    for i in 0..a.len() {
        dot += a[i] * b[i];
        norm_a += a[i] * a[i];
        norm_b += b[i] * b[i];
    }
    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom > 0.0 {
        dot / denom
    } else {
        0.0
    }
}

// ── HTTP helpers ──

async fn fetch_json_post(
    url: &str,
    body: &str,
    auth_token: Option<&str>,
) -> Result<String, String> {
    let opts = web_sys::RequestInit::new();
    opts.set_method("POST");
    opts.set_body(&JsValue::from_str(body));

    let headers =
        web_sys::Headers::new().map_err(|_| "Headers error".to_string())?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|_| "Header set error".to_string())?;
    if let Some(token) = auth_token {
        headers
            .set("Authorization", &format!("Nostr {}", token))
            .map_err(|_| "Auth header error".to_string())?;
    }
    opts.set_headers(&headers);

    let request = web_sys::Request::new_with_str_and_init(url, &opts)
        .map_err(|_| "Request create error".to_string())?;

    let window = web_sys::window().ok_or("No window")?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("Fetch error: {:?}", e))?;

    let resp: web_sys::Response = resp_value
        .dyn_into()
        .map_err(|_| "Response cast error".to_string())?;

    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let text = JsFuture::from(
        resp.text().map_err(|_| "Text error".to_string())?,
    )
    .await
    .map_err(|e| format!("Text read error: {:?}", e))?;

    text.as_string()
        .ok_or_else(|| "Non-string response".to_string())
}

async fn fetch_get(url: &str) -> Result<String, String> {
    let window = web_sys::window().ok_or("No window")?;
    let resp_value = JsFuture::from(window.fetch_with_str(url))
        .await
        .map_err(|e| format!("Fetch error: {:?}", e))?;

    let resp: web_sys::Response = resp_value
        .dyn_into()
        .map_err(|_| "Response cast error".to_string())?;

    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let text = JsFuture::from(
        resp.text().map_err(|_| "Text error".to_string())?,
    )
    .await
    .map_err(|e| format!("Text read error: {:?}", e))?;

    text.as_string()
        .ok_or_else(|| "Non-string response".to_string())
}
