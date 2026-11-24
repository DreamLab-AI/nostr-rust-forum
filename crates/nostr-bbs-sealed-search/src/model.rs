//! bge-small-en-v1.5 sentence embeddings with candle: CLS pooling, L2
//! normalisation (the checkpoint's `1_Pooling` config), 384 dims.
//!
//! One forward pass, two weight forms:
//! - **FP32**, loaded from the original PyTorch checkpoint (builder, native);
//! - **Q8_0**, every Linear weight quantised with GGML Q8_0 and stored with
//!   the F32 LayerNorms and biases in one GGUF file (browser worker). Word
//!   embeddings are stored Q8_0 and dequantised once at load.
//!
//! [`to_gguf_q8`] converts the FP32 checkpoint into the Q8 file.

#[cfg(not(target_arch = "wasm32"))]
use std::collections::HashMap;
use std::io::Cursor;

#[cfg(not(target_arch = "wasm32"))]
use candle_core::quantized::GgmlDType;
use candle_core::quantized::{gguf_file, QMatMul, QTensor};
#[cfg(not(target_arch = "wasm32"))]
use candle_core::DType;
use candle_core::{Device, Module, Tensor};

use crate::wordpiece::WordPiece;

/// Embedding dimension.
pub const DIM: usize = 384;
const LAYERS: usize = 12;
const HEADS: usize = 12;
const HEAD_DIM: usize = DIM / HEADS;
const EPS: f64 = 1e-12;

type Res<T> = Result<T, String>;
fn e<E: std::fmt::Display>(x: E) -> String {
    x.to_string()
}

enum Lin {
    /// FP32 weight + bias (builder, native only).
    #[cfg(not(target_arch = "wasm32"))]
    F(Tensor, Tensor),
    Q(QMatMul, Tensor),
}

impl Lin {
    fn fwd(&self, x: &Tensor) -> candle_core::Result<Tensor> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Lin::F(w, b) => x.broadcast_matmul(&w.t()?)?.broadcast_add(b),
            Lin::Q(m, b) => m.forward(x)?.broadcast_add(b),
        }
    }
}

struct Norm(Tensor, Tensor);
impl Norm {
    fn fwd(&self, x: &Tensor) -> candle_core::Result<Tensor> {
        candle_nn::ops::layer_norm(x, &self.0, &self.1, EPS as f32)
    }
}

struct Layer {
    q: Lin,
    k: Lin,
    v: Lin,
    o: Lin,
    ln1: Norm,
    up: Lin,
    down: Lin,
    ln2: Norm,
}

/// A loaded bge-small model plus its tokeniser.
pub struct Bge {
    word: Tensor,
    pos: Tensor,
    tok_type: Tensor,
    ln: Norm,
    layers: Vec<Layer>,
    tok: WordPiece,
    dev: Device,
}

fn layer_names(i: usize) -> [String; 8] {
    let p = format!("encoder.layer.{i}");
    [
        format!("{p}.attention.self.query"),
        format!("{p}.attention.self.key"),
        format!("{p}.attention.self.value"),
        format!("{p}.attention.output.dense"),
        format!("{p}.attention.output.LayerNorm"),
        format!("{p}.intermediate.dense"),
        format!("{p}.output.dense"),
        format!("{p}.output.LayerNorm"),
    ]
}

impl Bge {
    fn build(
        mut get_f: impl FnMut(&str) -> Res<Tensor>,
        mut get_lin: impl FnMut(&str) -> Res<Lin>,
        tok: WordPiece,
    ) -> Res<Self> {
        let word = get_f("embeddings.word_embeddings.weight")?;
        let pos = get_f("embeddings.position_embeddings.weight")?;
        let tok_type = get_f("embeddings.token_type_embeddings.weight")?;
        let ln = Norm(get_f("embeddings.LayerNorm.weight")?, get_f("embeddings.LayerNorm.bias")?);
        let mut layers = Vec::with_capacity(LAYERS);
        for i in 0..LAYERS {
            let n = layer_names(i);
            let norm = |s: &str, g: &mut dyn FnMut(&str) -> Res<Tensor>| -> Res<Norm> {
                Ok(Norm(g(&format!("{s}.weight"))?, g(&format!("{s}.bias"))?))
            };
            layers.push(Layer {
                q: get_lin(&n[0])?,
                k: get_lin(&n[1])?,
                v: get_lin(&n[2])?,
                o: get_lin(&n[3])?,
                ln1: norm(&n[4], &mut get_f)?,
                up: get_lin(&n[5])?,
                down: get_lin(&n[6])?,
                ln2: norm(&n[7], &mut get_f)?,
            });
        }
        Ok(Self { word, pos, tok_type, ln, layers, tok, dev: Device::Cpu })
    }

    /// FP32 model from the original checkpoint directory (`pytorch_model.bin`,
    /// `vocab.txt`). Native only (reads files).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn load_fp32_dir(dir: &std::path::Path) -> Res<Self> {
        let tensors: HashMap<String, Tensor> = candle_core::pickle::read_all(dir.join("pytorch_model.bin"))
            .map_err(e)?
            .into_iter()
            .collect();
        let tok = WordPiece::from_vocab_txt(&std::fs::read_to_string(dir.join("vocab.txt")).map_err(e)?)?;
        let f = |n: &str| -> Res<Tensor> {
            tensors.get(n).cloned().ok_or_else(|| format!("missing {n}"))?.to_dtype(DType::F32).map_err(e)
        };
        Self::build(f, |n: &str| Ok(Lin::F(f(&format!("{n}.weight"))?, f(&format!("{n}.bias"))?)), tok)
    }

    /// Q8 model from GGUF bytes (written by [`to_gguf_q8`]) and `vocab.txt`.
    pub fn load_gguf_q8(gguf: &[u8], vocab_txt: &str) -> Res<Self> {
        let dev = Device::Cpu;
        let cur = std::cell::RefCell::new(Cursor::new(gguf));
        let content = gguf_file::Content::read(&mut *cur.borrow_mut()).map_err(e)?;
        let qt = |n: &str| -> Res<QTensor> {
            if !content.tensor_infos.contains_key(n) {
                return Err(format!("missing {n}"));
            }
            content.tensor(&mut *cur.borrow_mut(), n, &dev).map_err(e)
        };
        let f = |n: &str| -> Res<Tensor> { qt(n)?.dequantize(&dev).map_err(e) };
        let lin = |n: &str| -> Res<Lin> {
            let w = qt(&format!("{n}.weight"))?;
            Ok(Lin::Q(QMatMul::from_qtensor(w).map_err(e)?, f(&format!("{n}.bias"))?))
        };
        Self::build(f, lin, WordPiece::from_vocab_txt(vocab_txt)?)
    }

    /// Token ids for a text.
    pub fn encode(&self, text: &str) -> Vec<u32> {
        self.tok.encode(text)
    }

    /// Embed a batch of token-id sequences (padded internally) → unit vectors.
    pub fn embed_ids(&self, batch: &[Vec<u32>]) -> Res<Vec<[f32; DIM]>> {
        if batch.is_empty() {
            return Ok(Vec::new());
        }
        let b = batch.len();
        let t = batch.iter().map(Vec::len).max().unwrap_or(1);
        let mut ids = vec![0u32; b * t];
        let mut mask = vec![0f32; b * t];
        for (i, s) in batch.iter().enumerate() {
            for (j, &id) in s.iter().enumerate() {
                ids[i * t + j] = id;
                mask[i * t + j] = 1.0;
            }
        }
        let out = self.forward(&ids, &mask, b, t).map_err(e)?;
        let v: Vec<Vec<f32>> = out.to_vec2().map_err(e)?;
        Ok(v.into_iter()
            .map(|row| {
                let mut a = [0f32; DIM];
                a.copy_from_slice(&row);
                let n = a.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-12);
                a.iter_mut().for_each(|x| *x /= n);
                a
            })
            .collect())
    }

    /// Embed texts (no instruction prefix; matches the document side).
    pub fn embed(&self, texts: &[&str]) -> Res<Vec<[f32; DIM]>> {
        let ids: Vec<Vec<u32>> = texts.iter().map(|t| self.encode(t)).collect();
        self.embed_ids(&ids)
    }

    fn forward(&self, ids: &[u32], mask: &[f32], b: usize, t: usize) -> candle_core::Result<Tensor> {
        let ids_t = Tensor::from_slice(ids, (b * t,), &self.dev)?;
        let x = self.word.index_select(&ids_t, 0)?.reshape((b, t, DIM))?;
        let x = x.broadcast_add(&self.pos.narrow(0, 0, t)?)?;
        let x = x.broadcast_add(&self.tok_type.narrow(0, 0, 1)?)?;
        let mut x = self.ln.fwd(&x)?;
        // Additive mask (b, 1, 1, t): 0 for tokens, a large negative for padding.
        let m = Tensor::from_slice(mask, (b, 1, 1, t), &self.dev)?;
        let m = ((m - 1.0)? * 1e9)?;
        let scale = 1.0 / (HEAD_DIM as f64).sqrt();
        for l in &self.layers {
            let heads = |y: Tensor| y.reshape((b, t, HEADS, HEAD_DIM))?.transpose(1, 2)?.contiguous();
            let q = heads(l.q.fwd(&x)?)?;
            let k = heads(l.k.fwd(&x)?)?;
            let v = heads(l.v.fwd(&x)?)?;
            let att = (q.matmul(&k.t()?.contiguous()?)? * scale)?.broadcast_add(&m)?;
            let att = candle_nn::ops::softmax_last_dim(&att)?;
            let ctx = att.matmul(&v)?.transpose(1, 2)?.contiguous()?.reshape((b, t, DIM))?;
            let h = l.ln1.fwd(&(l.o.fwd(&ctx)? + &x)?)?;
            let ff = l.down.fwd(&l.up.fwd(&h)?.gelu_erf()?)?;
            x = l.ln2.fwd(&(ff + h)?)?;
        }
        // CLS pooling.
        x.narrow(1, 0, 1)?.squeeze(1)?.contiguous()
    }
}

/// Convert the FP32 checkpoint directory into the Q8 GGUF file the browser
/// worker loads: Linear weights and word embeddings Q8_0, everything else F32.
#[cfg(not(target_arch = "wasm32"))]
pub fn to_gguf_q8(dir: &std::path::Path) -> Res<Vec<u8>> {
    let tensors = candle_core::pickle::read_all(dir.join("pytorch_model.bin")).map_err(e)?;
    let mut q: Vec<(String, QTensor)> = Vec::new();
    for (name, t) in tensors {
        if name.starts_with("pooler.") || name.ends_with("position_ids") {
            continue;
        }
        let t = t.to_dtype(DType::F32).map_err(e)?;
        let is_lin_w = name.ends_with(".weight") && t.rank() == 2 && !name.contains("LayerNorm") && !name.contains("position_embeddings") && !name.contains("token_type");
        let dt = if is_lin_w { GgmlDType::Q8_0 } else { GgmlDType::F32 };
        q.push((name, QTensor::quantize(&t, dt).map_err(e)?));
    }
    q.sort_by(|a, b| a.0.cmp(&b.0));
    let refs: Vec<(&str, &QTensor)> = q.iter().map(|(n, t)| (n.as_str(), t)).collect();
    let meta = gguf_file::Value::String("bge-small-en-v1.5 q8_0 (nostr-bbs-sealed-search)".into());
    let mut out = Cursor::new(Vec::new());
    gguf_file::write(&mut out, &[("general.name", &meta)], &refs).map_err(e)?;
    Ok(out.into_inner())
}
