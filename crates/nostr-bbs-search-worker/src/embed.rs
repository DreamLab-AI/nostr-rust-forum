//! Semantic embedding generation with hash fallback.
//!
//! Backends, in order of precedence:
//!
//! 1. **OpenAI-compatible endpoint (opt-in).** When the `EMBED_URL` var is set
//!    (for example a self-hosted Xinference at `http://host:9997/v1`), texts
//!    are POSTed to `{EMBED_URL}/embeddings` as `{"model": EMBED_MODEL,
//!    "input": [...]}`. This exists so a local pilot can run real semantic
//!    search without a Cloudflare account; it is never enabled by default.
//!    Its vectors are labelled with `EMBED_MODEL_LABEL` (default
//!    `"<EMBED_MODEL>@openai-compat"`), deliberately *not* the Workers AI
//!    label: the same model served by another runtime may pool differently
//!    (Workers AI documents mean pooling by default, sentence-transformers'
//!    bge config uses CLS), so the index's model guard must not treat the two
//!    as interchangeable unless the operator says so explicitly.
//! 2. **Cloudflare Workers AI** `@cf/baai/bge-small-en-v1.5` (384-dim,
//!    L2-normalized) via the `worker` crate's `Ai` binding.
//! 3. **Hash fallback**: deterministic multi-pass char hashing into 384-dim,
//!    used only when neither backend is configured (or both fail) so the
//!    worker degrades gracefully instead of hard-failing.

use serde::{Deserialize, Serialize};
use worker::{Env, Result};

/// Embedding dimension. BGE-small-en-v1.5 outputs exactly 384 dimensions,
/// which matches the store's fixed `[f32; 384]` layout and the legacy
/// all-MiniLM-L6-v2 hash fallback. Do not change without re-indexing.
pub const DIM: usize = 384;

/// Cloudflare Workers AI model id. Outputs 384-dim float vectors.
pub const BGE_MODEL: &str = "@cf/baai/bge-small-en-v1.5";

/// Binding name for the Workers AI runtime (see `wrangler.toml` `[ai]`).
pub const AI_BINDING: &str = "AI";

/// Model label reported by `/status` and `/embed` when the real model is live.
pub const MODEL_LABEL_SEMANTIC: &str = "bge-small-en-v1.5";

/// Model label reported when the worker falls back to hash embeddings.
pub const MODEL_LABEL_FALLBACK: &str = "hash-fallback-v1";

/// Var naming the base URL of an OpenAI-compatible embeddings API (opt-in).
pub const EMBED_URL_VAR: &str = "EMBED_URL";
/// Var naming the model to request from `EMBED_URL`.
pub const EMBED_MODEL_VAR: &str = "EMBED_MODEL";
/// Optional var overriding the label recorded for `EMBED_URL` vectors.
pub const EMBED_MODEL_LABEL_VAR: &str = "EMBED_MODEL_LABEL";
/// Optional secret (or var) sent as `Authorization: Bearer` to `EMBED_URL`.
pub const EMBED_API_KEY_VAR: &str = "EMBED_API_KEY";
/// Model requested from `EMBED_URL` when `EMBED_MODEL` is unset.
pub const DEFAULT_EMBED_MODEL: &str = "bge-small-en-v1.5";
/// Per-text character cap for the `EMBED_URL` backend. The model truncates at
/// 512 tokens anyway; this only bounds the request body.
pub const EMBED_URL_MAX_CHARS: usize = 8192;

/// Configuration of the opt-in OpenAI-compatible backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiEmbedConfig {
    /// `{base}/embeddings` endpoint.
    pub endpoint: String,
    /// Model name sent in the request body.
    pub model: String,
    /// Label recorded with vectors from this backend.
    pub label: String,
}

impl OpenAiEmbedConfig {
    /// Build from raw var values. `None` when `url` is unset or blank.
    pub fn from_vars(url: Option<&str>, model: Option<&str>, label: Option<&str>) -> Option<Self> {
        let base = url.map(str::trim).filter(|u| !u.is_empty())?;
        let model = model
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .unwrap_or(DEFAULT_EMBED_MODEL)
            .to_string();
        let label = label
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("{model}@openai-compat"));
        let base = base.trim_end_matches('/');
        let endpoint = if base.ends_with("/embeddings") {
            base.to_string()
        } else {
            format!("{base}/embeddings")
        };
        Some(Self {
            endpoint,
            model,
            label,
        })
    }
}

fn var_str(env: &Env, name: &str) -> Option<String> {
    env.var(name).ok().map(|v| v.to_string())
}

/// The opt-in OpenAI-compatible backend, if `EMBED_URL` is configured.
pub fn openai_config(env: &Env) -> Option<OpenAiEmbedConfig> {
    OpenAiEmbedConfig::from_vars(
        var_str(env, EMBED_URL_VAR).as_deref(),
        var_str(env, EMBED_MODEL_VAR).as_deref(),
        var_str(env, EMBED_MODEL_LABEL_VAR).as_deref(),
    )
}

/// Label of the backend `embed_texts` would try first in this environment.
pub fn active_model_label(env: &Env) -> String {
    if let Some(cfg) = openai_config(env) {
        cfg.label
    } else if ai_binding_available(env) {
        MODEL_LABEL_SEMANTIC.to_string()
    } else {
        MODEL_LABEL_FALLBACK.to_string()
    }
}

/// Build the OpenAI-compatible request body, capping each text.
pub fn openai_request_body(model: &str, texts: &[String]) -> serde_json::Value {
    let input: Vec<String> = texts
        .iter()
        .map(|t| t.chars().take(EMBED_URL_MAX_CHARS).collect())
        .collect();
    serde_json::json!({ "model": model, "input": input })
}

#[derive(Deserialize)]
struct OpenAiItem {
    #[serde(default)]
    index: Option<usize>,
    embedding: Vec<f32>,
}

#[derive(Deserialize)]
struct OpenAiResponse {
    data: Vec<OpenAiItem>,
}

/// Parse an OpenAI-compatible embeddings response for `n` inputs.
///
/// Orders by `index` (falling back to position when absent), requires exactly
/// one vector per input with no gaps or duplicates, checks every vector is
/// [`DIM`]-dimensional, and L2-normalizes each one.
pub fn parse_openai_embeddings(body: &str, n: usize) -> std::result::Result<Vec<Vec<f32>>, String> {
    let resp: OpenAiResponse =
        serde_json::from_str(body).map_err(|e| format!("bad embeddings JSON: {e}"))?;
    if resp.data.len() != n {
        return Err(format!("{} vectors for {n} inputs", resp.data.len()));
    }
    let mut slots: Vec<Option<Vec<f32>>> = vec![None; n];
    for (pos, item) in resp.data.into_iter().enumerate() {
        let idx = item.index.unwrap_or(pos);
        if idx >= n {
            return Err(format!("index {idx} out of range for {n} inputs"));
        }
        if item.embedding.len() != DIM {
            return Err(format!(
                "{}-dim vector, expected {DIM}",
                item.embedding.len()
            ));
        }
        if slots[idx].is_some() {
            return Err(format!("duplicate index {idx}"));
        }
        let mut v = item.embedding;
        l2_normalize(&mut v);
        slots[idx] = Some(v);
    }
    // len == n and no duplicates within range, so every slot is filled.
    Ok(slots.into_iter().flatten().collect())
}

async fn run_openai(env: &Env, cfg: &OpenAiEmbedConfig, texts: &[String]) -> Result<Vec<Vec<f32>>> {
    use worker::{Fetch, Headers, Method, Request, RequestInit};
    let headers = Headers::new();
    headers.set("Content-Type", "application/json")?;
    let key = var_str(env, EMBED_API_KEY_VAR)
        .or_else(|| env.secret(EMBED_API_KEY_VAR).ok().map(|s| s.to_string()))
        .filter(|k| !k.trim().is_empty());
    if let Some(k) = key {
        headers.set("Authorization", &format!("Bearer {}", k.trim()))?;
    }
    let body = openai_request_body(&cfg.model, texts).to_string();
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(body.into()));
    let req = Request::new_with_init(&cfg.endpoint, &init)?;
    let mut resp = Fetch::Request(req).send().await?;
    let status = resp.status_code();
    let text = resp.text().await?;
    if !(200..300).contains(&status) {
        return Err(worker::Error::RustError(format!(
            "embeddings endpoint returned HTTP {status}"
        )));
    }
    parse_openai_embeddings(&text, texts.len()).map_err(worker::Error::RustError)
}

// --- Workers AI request/response shapes ---------------------------------

#[derive(Serialize)]
struct BgeRequest<'a> {
    text: &'a [String],
}

#[derive(Deserialize)]
struct BgeResponse {
    /// One f32 vector per input text.
    ///
    /// The Workers AI BGE schema also returns a `shape: [batch, dim]` field;
    /// it is not captured here (serde ignores unknown fields by default) since
    /// nothing reads it — `data.len()` and each vector's `.len()` are checked
    /// directly in `run_bge`.
    data: Vec<Vec<f32>>,
}

/// True if the Workers AI `AI` binding is configured in this environment.
pub fn ai_binding_available(env: &Env) -> bool {
    env.ai(AI_BINDING).is_ok()
}

/// L2-normalize a vector in place to match the store's cosine convention.
fn l2_normalize(v: &mut [f32]) {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm = if norm == 0.0 { 1.0 } else { norm };
    for x in v.iter_mut() {
        *x /= norm;
    }
}

/// Embed a batch of texts.
///
/// Tries the opt-in `EMBED_URL` backend first when configured, then Workers AI
/// BGE-small. If neither is available, or a call fails / returns a malformed
/// shape, falls back to the deterministic hash embedder so the request never
/// hard-fails (the index's model guard then refuses to mix the spaces).
///
/// Returns the per-text embeddings and the label of the backend that actually
/// produced them.
pub async fn embed_texts(env: &Env, texts: &[String]) -> (Vec<Vec<f32>>, String) {
    if let Some(cfg) = openai_config(env) {
        match run_openai(env, &cfg, texts).await {
            Ok(embeddings) => return (embeddings, cfg.label),
            Err(e) => {
                worker::console_warn!("EMBED_URL embedding failed ({e}); trying the next backend");
            }
        }
    }
    if let Ok(ai) = env.ai(AI_BINDING) {
        match run_bge(&ai, texts).await {
            Ok(embeddings) => return (embeddings, MODEL_LABEL_SEMANTIC.to_string()),
            Err(e) => {
                worker::console_warn!(
                    "Workers AI embedding failed ({e}); falling back to hash embedder"
                );
            }
        }
    }
    let fallback = texts.iter().map(|t| generate_embedding(t)).collect();
    (fallback, MODEL_LABEL_FALLBACK.to_string())
}

async fn run_bge(ai: &worker::Ai, texts: &[String]) -> Result<Vec<Vec<f32>>> {
    let req = BgeRequest { text: texts };
    let resp: BgeResponse = ai.run(BGE_MODEL, req).await?;

    if resp.data.len() != texts.len() {
        return Err(worker::Error::RustError(format!(
            "Workers AI returned {} vectors for {} inputs",
            resp.data.len(),
            texts.len()
        )));
    }

    let mut out = Vec::with_capacity(resp.data.len());
    for mut vec in resp.data {
        if vec.len() != DIM {
            return Err(worker::Error::RustError(format!(
                "Workers AI returned {}-dim vector, expected {DIM}",
                vec.len()
            )));
        }
        l2_normalize(&mut vec);
        out.push(vec);
    }
    Ok(out)
}

/// Generate a deterministic hash-based embedding for the given text.
///
/// Uses 3-pass character hashing for distribution, then L2-normalizes.
/// Identical to the TS `generateEmbedding()` in `workers/search-api/index.ts`.
/// NOT semantic — only used as a graceful fallback when Workers AI is absent.
pub fn generate_embedding(text: &str) -> Vec<f32> {
    let mut vector = vec![0.0f32; DIM];
    let normalized = text.to_lowercase();
    let normalized = normalized.trim();

    // Multi-pass hash for better distribution
    for pass in 0u32..3 {
        for (i, ch) in normalized.chars().enumerate() {
            let code = ch as u32;
            let idx = ((code * (i as u32 + 1) * (pass + 1) + pass * 127) % DIM as u32) as usize;
            vector[idx] += code as f32 / (255.0 * (pass + 1) as f32);
        }
    }

    l2_normalize(&mut vector);
    vector
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedding_has_correct_dim() {
        let emb = generate_embedding("hello world");
        assert_eq!(emb.len(), DIM);
    }

    #[test]
    fn embedding_is_normalized() {
        let emb = generate_embedding("test input");
        let norm: f32 = emb.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5);
    }

    #[test]
    fn embedding_is_deterministic() {
        let a = generate_embedding("same text");
        let b = generate_embedding("same text");
        assert_eq!(a, b);
    }

    #[test]
    fn empty_text_produces_zero_norm_fallback() {
        let emb = generate_embedding("");
        // All zeros, normalized to all zeros / 1.0 = all zeros
        assert!(emb.iter().all(|v| *v == 0.0));
    }

    fn vec_json(seed: f32) -> String {
        let v: Vec<String> = (0..DIM).map(|i| format!("{}", seed + i as f32)).collect();
        format!("[{}]", v.join(","))
    }

    #[test]
    fn openai_config_requires_url() {
        assert_eq!(OpenAiEmbedConfig::from_vars(None, None, None), None);
        assert_eq!(
            OpenAiEmbedConfig::from_vars(Some("  "), Some("m"), None),
            None
        );
    }

    #[test]
    fn openai_config_defaults_and_endpoint() {
        let c = OpenAiEmbedConfig::from_vars(Some("http://h:9997/v1/"), None, None).unwrap();
        assert_eq!(c.endpoint, "http://h:9997/v1/embeddings");
        assert_eq!(c.model, DEFAULT_EMBED_MODEL);
        // Never the Workers AI label by default: pooling may differ.
        assert_eq!(c.label, "bge-small-en-v1.5@openai-compat");
        assert_ne!(c.label, MODEL_LABEL_SEMANTIC);
        let c =
            OpenAiEmbedConfig::from_vars(Some("http://h/v1/embeddings"), Some("x"), Some("lbl"))
                .unwrap();
        assert_eq!(c.endpoint, "http://h/v1/embeddings");
        assert_eq!(c.model, "x");
        assert_eq!(c.label, "lbl");
    }

    #[test]
    fn openai_body_caps_each_text() {
        let long = "é".repeat(EMBED_URL_MAX_CHARS + 10);
        let b = openai_request_body("m", &["a".into(), long]);
        assert_eq!(b["model"], "m");
        assert_eq!(b["input"][0], "a");
        assert_eq!(
            b["input"][1].as_str().unwrap().chars().count(),
            EMBED_URL_MAX_CHARS
        );
    }

    #[test]
    fn openai_parse_orders_by_index_and_normalizes() {
        let body = format!(
            r#"{{"data":[{{"index":1,"embedding":{}}},{{"index":0,"embedding":{}}}]}}"#,
            vec_json(100.0),
            vec_json(1.0)
        );
        let out = parse_openai_embeddings(&body, 2).unwrap();
        assert_eq!(out.len(), 2);
        for v in &out {
            let n: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
            assert!((n - 1.0).abs() < 1e-4);
        }
        // index 0 came from seed 1.0: its first component is the smaller share.
        assert!(out[0][0] < out[1][0]);
    }

    #[test]
    fn openai_parse_positional_when_index_absent() {
        let body = format!(r#"{{"data":[{{"embedding":{}}}]}}"#, vec_json(1.0));
        assert_eq!(parse_openai_embeddings(&body, 1).unwrap().len(), 1);
    }

    #[test]
    fn openai_parse_rejects_bad_shapes() {
        let one = format!(r#"{{"index":0,"embedding":{}}}"#, vec_json(1.0));
        // count mismatch
        assert!(parse_openai_embeddings(&format!(r#"{{"data":[{one}]}}"#), 2).is_err());
        // duplicate index
        assert!(parse_openai_embeddings(&format!(r#"{{"data":[{one},{one}]}}"#), 2).is_err());
        // out of range
        let oor = format!(
            r#"{{"data":[{{"index":5,"embedding":{}}}]}}"#,
            vec_json(1.0)
        );
        assert!(parse_openai_embeddings(&oor, 1).is_err());
        // wrong dim
        assert!(
            parse_openai_embeddings(r#"{"data":[{"index":0,"embedding":[1,2,3]}]}"#, 1).is_err()
        );
        // not JSON
        assert!(parse_openai_embeddings("nope", 1).is_err());
    }

    #[test]
    fn bge_model_dim_matches_store_dim() {
        // BGE-small-en-v1.5 emits 384-dim vectors; the store is fixed at DIM.
        assert_eq!(DIM, 384);
    }
}
