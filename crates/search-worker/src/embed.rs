//! Hash-based fallback embedding generator.
//!
//! Deterministic multi-pass hash producing 384-dim L2-normalized vectors.
//! NOT semantic — provides stable vectors for testing and graceful degradation.
//! Will be replaced by quantized MiniLM ONNX model running in WASM.

/// Embedding dimension (all-MiniLM-L6-v2 compatible).
pub const DIM: usize = 384;

/// Generate a deterministic hash-based embedding for the given text.
///
/// Uses 3-pass character hashing for distribution, then L2-normalizes.
/// Identical to the TS `generateEmbedding()` in `workers/search-api/index.ts`.
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

    // L2 normalize
    let norm = vector.iter().map(|v| v * v).sum::<f32>().sqrt();
    let norm = if norm == 0.0 { 1.0 } else { norm };
    for v in &mut vector {
        *v /= norm;
    }

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
}
