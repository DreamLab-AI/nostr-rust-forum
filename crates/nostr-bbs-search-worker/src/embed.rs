//! Semantic embedding generation with hash fallback.
//!
//! Primary path: Cloudflare Workers AI `@cf/baai/bge-small-en-v1.5`
//! (384-dim, L2-normalized) via the `worker` crate's `Ai` binding.
//! Fallback path: deterministic multi-pass char hashing into 384-dim,
//! used only when the `AI` binding is absent (local dev / misconfigured
//! deployment) so the worker degrades gracefully instead of hard-failing.

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

// --- Workers AI request/response shapes ---------------------------------

#[derive(Serialize)]
struct BgeRequest<'a> {
    text: &'a [String],
}

#[derive(Deserialize)]
struct BgeResponse {
    /// `[batch, dim]` per Workers AI BGE schema.
    #[serde(default)]
    #[allow(dead_code)]
    shape: Vec<usize>,
    /// One f32 vector per input text.
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
/// Default path: Workers AI BGE-small. If the `AI` binding is unavailable,
/// or if the inference call fails / returns a malformed shape, falls back to
/// the deterministic hash embedder so the request never hard-fails.
///
/// Returns the per-text embeddings and the model label that actually produced
/// them (`bge-small-en-v1.5` or `hash-fallback-v1`).
pub async fn embed_texts(env: &Env, texts: &[String]) -> (Vec<Vec<f32>>, &'static str) {
    if let Ok(ai) = env.ai(AI_BINDING) {
        match run_bge(&ai, texts).await {
            Ok(embeddings) => return (embeddings, MODEL_LABEL_SEMANTIC),
            Err(e) => {
                worker::console_warn!(
                    "Workers AI embedding failed ({e}); falling back to hash embedder"
                );
            }
        }
    }
    let fallback = texts.iter().map(|t| generate_embedding(t)).collect();
    (fallback, MODEL_LABEL_FALLBACK)
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

    #[test]
    fn bge_model_dim_matches_store_dim() {
        // BGE-small-en-v1.5 emits 384-dim vectors; the store is fixed at DIM.
        assert_eq!(DIM, 384);
    }
}
