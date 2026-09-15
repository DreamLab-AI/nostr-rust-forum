//! RuVector semantic search client for the nostr-bbs forum.
//!
//! Talks to the search-api Cloudflare Worker for embedding generation,
//! k-NN vector search, and message ingestion (NIP-98 authenticated).
//!
//! ## Base-URL resolution (single source of truth)
//!
//! This module owns the ONE resolver for the search-worker base URL
//! ([`search_api_base`]); [`crate::components::global_search`] calls it rather
//! than keeping a second copy. Before this was unified the two sites disagreed:
//! the overlay defaulted to the real deployed worker while this module defaulted
//! to `https://search.example.com` — `example.com` is IANA-reserved and resolves
//! to nothing, so `get_search_status()` and `search_similar()` could never
//! succeed in any build that had not set the compile-time variable.
//!
//! Resolution order is runtime-first, mirroring
//! `nostr-bbs-bbs-client/src/config.rs` (which reads `SEARCH_API` /
//! `SEARCH_URL` / `SEARCH_BASE_URL` off `window.__ENV__`) and this crate's own
//! `utils::relay_url`:
//!
//! 1. `window.__ENV__.{SEARCH_API, SEARCH_URL, SEARCH_BASE_URL, SEARCH_API_URL,
//!    VITE_SEARCH_API_URL}` — injected by the operator's deploy at *runtime*, so
//!    one built artefact can be pointed at a different worker without a rebuild.
//! 2. The compile-time `VITE_SEARCH_API_URL`, else `SEARCH_API_URL`. Both names
//!    are accepted because `SETUP.md` documents `SEARCH_API_URL` while the code
//!    historically read only `VITE_SEARCH_API_URL`; honouring both means neither
//!    the docs nor existing build scripts are silently wrong.
//! 3. The kit's deployed worker, as a last resort — a reachable default beats an
//!    unresolvable placeholder.

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// `window.__ENV__` keys consulted, in priority order, for the search base URL.
///
/// The first trio matches the BBS client's `config.rs` exactly so an operator
/// injects one set of names for both clients. The last two exist so the
/// documented (`SEARCH_API_URL`) and historical (`VITE_SEARCH_API_URL`) spellings
/// also work at runtime, not just at compile time.
const SEARCH_ENV_KEYS: &[&str] = &[
    "SEARCH_API",
    "SEARCH_URL",
    "SEARCH_BASE_URL",
    "SEARCH_API_URL",
    "VITE_SEARCH_API_URL",
];

/// Compile-time base URL, accepting either documented spelling.
///
/// `option_env!` is evaluated in const context, so this costs nothing at
/// runtime and simply records which (if either) variable the build was given.
const SEARCH_API_COMPILE_TIME: Option<&str> = match option_env!("VITE_SEARCH_API_URL") {
    Some(u) => Some(u),
    None => option_env!("SEARCH_API_URL"),
};

/// Last-resort default: the kit's deployed search worker.
///
/// Deliberately a *reachable* host. The previous `https://search.example.com`
/// default could never work (RFC 2606 reserved domain), which turned a missing
/// build variable into a silent, permanent search outage instead of a
/// degraded-but-working default.
const SEARCH_API_FALLBACK: &str = "https://members-search-api.solitary-paper-764d.workers.dev";

/// Pure base-URL resolution: runtime override, else compile-time, else fallback.
///
/// Kept free of `web_sys` so it is unit-testable on the host target (the wasm
/// `window.__ENV__` read happens in [`runtime_search_base`] and is injected
/// here as a plain `Option<&str>`). Blank/whitespace-only values are treated as
/// absent — an operator template that emits `SEARCH_API: ""` must fall through
/// rather than produce the URL `"/search"`. The trailing slash is stripped so
/// callers can uniformly `format!("{base}/search")` without doubling it.
pub fn resolve_search_base(runtime: Option<&str>, compile_time: Option<&str>) -> String {
    [runtime, compile_time]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|s| !s.is_empty())
        .unwrap_or(SEARCH_API_FALLBACK)
        .trim_end_matches('/')
        .to_string()
}

/// Read the first non-empty search base URL from the live `window.__ENV__`.
///
/// Mirrors `utils::relay_url::env_override`; kept local so this module has no
/// dependency edge on a file outside the search feature.
fn runtime_search_base() -> Option<String> {
    let window = web_sys::window()?;
    let env = js_sys::Reflect::get(&window, &"__ENV__".into()).ok()?;
    if env.is_undefined() || env.is_null() {
        return None;
    }
    SEARCH_ENV_KEYS.iter().find_map(|key| {
        let val = js_sys::Reflect::get(&env, &(*key).into()).ok()?;
        let s = val.as_string()?;
        if s.trim().is_empty() {
            None
        } else {
            Some(s)
        }
    })
}

/// The search-worker base URL for this session, without a trailing slash.
///
/// Resolved on every call (not cached in a `const`) precisely so the runtime
/// `window.__ENV__` value wins over anything baked in at build time.
pub fn search_api_base() -> String {
    resolve_search_base(
        runtime_search_base().as_deref(),
        SEARCH_API_COMPILE_TIME,
    )
}

// ── Wire-body builders (pure, host-testable) ──

/// Build the `POST /search` body for a caller-supplied embedding.
///
/// The worker's `SearchRequest` (search-worker `lib.rs`) deserialises exactly
/// `embedding` / `query` / `k` / `minScore` / `model`. Anything else is dropped
/// by serde, so the field name must be `k` — a `limit` key looks plausible,
/// serialises fine, and is silently ignored, leaving the worker's `default_k()`
/// in charge. Building the body here (rather than inline at the fetch site)
/// keeps that contract in one unit-tested place.
pub fn build_embedding_search_body(embedding: &[f64], k: u32, min_score: f64) -> String {
    serde_json::json!({
        "embedding": embedding,
        "k": k,
        "minScore": min_score,
    })
    .to_string()
}

/// Build the `POST /search` body for a text query the worker will embed itself.
///
/// The query is trimmed client-side as well as worker-side: a whitespace-only
/// query embeds to an all-zero vector, which scores `0.0` against every stored
/// vector and — with the default `minScore` of `0.0` and a `>=` comparison —
/// would return the entire index as "matches". Both ends trim so neither a stale
/// client nor a stale worker can reintroduce that.
pub fn build_query_search_body(query: &str, k: u32) -> String {
    serde_json::json!({
        "query": query.trim(),
        "k": k,
    })
    .to_string()
}

// ── Public types ──

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SearchResult {
    pub id: String,
    /// Similarity score in `[0,1]`.
    ///
    /// `#[serde(default)]` because the field is not guaranteed: a legacy or
    /// partial worker response that omits `score` on even one row used to fail
    /// the *whole* `SearchResponse` parse, turning a cosmetic gap into "search
    /// is broken". Defaulting to `0.0` degrades that row's ranking instead of
    /// discarding every result.
    #[serde(default)]
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
    let url = format!("{}/embed", search_api_base());
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
///
/// # No channel filter
///
/// This function used to accept a `channel: Option<&str>` and, when set, add a
/// `"channel"` key to the request body. That was a **silent no-op**: the
/// worker's `SearchRequest` has no `channel` field, so serde discarded the key
/// and every "filtered" search quietly returned global results. Rather than
/// leave a parameter that lies about what it does, the filter is removed
/// client-side and the limitation documented here and in `SETUP.md`.
///
/// It is removed rather than implemented worker-side because the worker's index
/// is a flat `(label, vector)` store with no per-vector channel metadata — the
/// KV mapping holds only `id -> label` plus the public-visibility set. Adding a
/// real filter means a schema change to the persisted RVF/KV mapping and a
/// re-ingest of every vector, which is a feature, not a bug fix. Callers that
/// need per-channel results should filter the returned ids after relay
/// hydration (the ids carry their channel tag), which is what the global-search
/// overlay already does.
pub async fn search_similar(
    query: &str,
    k: u32,
    min_score: f64,
) -> Result<Vec<SearchResult>, String> {
    let embedding = embed_query(query).await?;

    let url = format!("{}/search", search_api_base());
    let body = build_embedding_search_body(&embedding, k, min_score);

    let response = fetch_json_post(&url, &body, None).await?;

    #[derive(serde::Deserialize)]
    struct SearchResponse {
        results: Vec<SearchResult>,
    }

    let data: SearchResponse =
        serde_json::from_str(&response).map_err(|e| format!("Parse error: {}", e))?;

    Ok(data.results)
}

/// Index a new message for semantic search (Signer-based NIP-98 auth).
///
/// # `public` decides whether the message is ever findable
///
/// The worker records `public` into its `publicLabels` set and `/search`
/// filters every hit through it (fail-closed: a missing or `false` flag means
/// "never return this to an anonymous searcher"). Passing `false` therefore
/// indexes a vector that *no search can ever reach* — it costs storage and
/// returns nothing. Callers indexing a message posted to an open, publicly
/// readable channel must pass `true`; `false` is correct only for a message in
/// a private/gated channel, where the vector exists so that a future
/// authorised-search path can use it.
///
/// `channel` is sent as metadata for forward compatibility only; the worker
/// does not currently read it (see [`search_similar`] for why there is no
/// channel filter).
pub async fn ingest_message_signer(
    event_id: &str,
    content: &str,
    channel: Option<&str>,
    public: bool,
    signer: &dyn nostr_bbs_core::signer::Signer,
) -> Result<bool, String> {
    let embedding = embed_query(content).await?;

    let url = format!("{}/ingest", search_api_base());
    let body = serde_json::json!({
        "entries": [{
            "id": event_id,
            "embedding": embedding,
            "channel": channel,
            "timestamp": (js_sys::Date::now() / 1000.0) as u64,
            "public": public,
        }]
    });
    let body_str = body.to_string();

    let token = crate::auth::nip98::create_nip98_token_with_signer(
        signer,
        &url,
        "POST",
        Some(body_str.as_bytes()),
    )
    .await
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
    let url = format!("{}/status", search_api_base());
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

    let headers = web_sys::Headers::new().map_err(|_| "Headers error".to_string())?;
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

    let text = JsFuture::from(resp.text().map_err(|_| "Text error".to_string())?)
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

    let text = JsFuture::from(resp.text().map_err(|_| "Text error".to_string())?)
        .await
        .map_err(|e| format!("Text read error: {:?}", e))?;

    text.as_string()
        .ok_or_else(|| "Non-string response".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: every test here is deliberately pure — no `web_sys` / `js_sys`
    // call is on the path. wasm-bindgen imports compile on the host target but
    // panic when called, so the runtime `window.__ENV__` read is isolated in
    // `runtime_search_base` and injected into `resolve_search_base` as a plain
    // `Option<&str>`, which is what these tests exercise.

    #[test]
    fn runtime_env_wins_over_compile_time_and_fallback() {
        // The whole point of reading `window.__ENV__` at runtime: one built
        // artefact, repointable by the operator without a rebuild.
        let base = resolve_search_base(Some("https://s.example.org"), Some("https://baked.in"));
        assert_eq!(base, "https://s.example.org");
    }

    #[test]
    fn compile_time_used_when_no_runtime_value() {
        assert_eq!(
            resolve_search_base(None, Some("https://baked.in")),
            "https://baked.in"
        );
    }

    #[test]
    fn blank_values_fall_through_to_the_reachable_default() {
        // A deploy template that emits `SEARCH_API: ""` must NOT yield a base of
        // "" (which would make every request a same-origin "/search").
        assert_eq!(resolve_search_base(Some("   "), None), SEARCH_API_FALLBACK);
        assert_eq!(resolve_search_base(None, Some("")), SEARCH_API_FALLBACK);
        assert_eq!(resolve_search_base(None, None), SEARCH_API_FALLBACK);
        // And the default must be reachable, not the old IANA-reserved
        // `example.com` placeholder that could never resolve.
        assert!(!SEARCH_API_FALLBACK.contains("example.com"));
    }

    #[test]
    fn trailing_slash_is_stripped_so_paths_never_double_up() {
        let base = resolve_search_base(Some("https://s.example.org/"), None);
        assert_eq!(base, "https://s.example.org");
        assert_eq!(format!("{base}/search"), "https://s.example.org/search");
    }

    #[test]
    fn env_keys_cover_both_documented_spellings() {
        // SETUP.md documents SEARCH_API_URL; the code historically read
        // VITE_SEARCH_API_URL; bbs-client's config.rs reads the SEARCH_* trio.
        // All five must be honoured or one of those three is silently wrong.
        for key in [
            "SEARCH_API",
            "SEARCH_URL",
            "SEARCH_BASE_URL",
            "SEARCH_API_URL",
            "VITE_SEARCH_API_URL",
        ] {
            assert!(SEARCH_ENV_KEYS.contains(&key), "{key} not consulted");
        }
    }

    #[test]
    fn embedding_search_body_uses_k_not_limit() {
        // The worker's SearchRequest has `k`; a `limit` key deserialises to
        // nothing and leaves the worker's default_k() silently in charge.
        let body = build_embedding_search_body(&[0.5, -0.25], 7, 0.3);
        assert!(body.contains(r#""k":7"#), "body was {body}");
        assert!(body.contains(r#""minScore":0.3"#), "body was {body}");
        assert!(body.contains(r#""embedding":[0.5,-0.25]"#), "body was {body}");
        assert!(!body.contains("limit"), "stale `limit` key in {body}");
    }

    #[test]
    fn query_search_body_uses_k_and_trims() {
        let body = build_query_search_body("  hello \"world\"  ", 10);
        assert!(body.contains(r#""k":10"#), "body was {body}");
        // Trimmed (a whitespace-only query would otherwise embed to an all-zero
        // vector and match the entire index at score 0.0) and quote-escaped.
        assert!(body.contains(r#""query":"hello \"world\"""#), "body was {body}");
        assert!(!body.contains("limit"), "stale `limit` key in {body}");
    }

    #[test]
    fn search_body_carries_no_channel_key() {
        // The channel filter was a silent no-op (the worker has no such field);
        // it must not creep back in and pretend to filter.
        let body = build_embedding_search_body(&[0.1], 5, 0.0);
        assert!(!body.contains("channel"), "body was {body}");
    }

    #[test]
    fn search_result_parses_without_a_score_field() {
        // A response row missing `score` used to fail the WHOLE parse, so one
        // cosmetic gap read to the user as "search is broken".
        let parsed: SearchResult = serde_json::from_str(r#"{"id":"abc"}"#)
            .expect("a score-less row must still parse");
        assert_eq!(parsed.id, "abc");
        assert_eq!(parsed.score, 0.0);
        assert_eq!(parsed.distance, 0.0);
        assert!(parsed.content.is_none());
    }

    #[test]
    fn search_result_still_reads_a_full_row() {
        let parsed: SearchResult = serde_json::from_str(
            r#"{"id":"abc","score":0.91,"distance":0.09,"content":"hi","label":"npub1"}"#,
        )
        .unwrap();
        assert_eq!(parsed.score, 0.91);
        assert_eq!(parsed.content.as_deref(), Some("hi"));
        assert_eq!(parsed.label.as_deref(), Some("npub1"));
    }
}
