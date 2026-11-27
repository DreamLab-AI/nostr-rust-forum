//! Document embeddings: bge-small-en-v1.5 in FP32 with candle on the CPU,
//! computed on this machine (review M6: no remote embedder ever sees zone
//! text).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use nostr_bbs_sealed_search::model::{Bge, DIM};

/// Something that embeds texts as unit vectors (the real model, or a test
/// stand-in).
pub trait Embedder {
    /// One vector per text, in order.
    ///
    /// # Errors
    ///
    /// When the model cannot be loaded or a forward pass fails. Messages
    /// never include the texts.
    fn embed(&mut self, texts: &[&str]) -> Result<Vec<[f32; DIM]>, String>;
}

/// The FP32 checkpoint, loaded on first use (a run with nothing new to
/// index never loads it), embedding length-sorted batches on several threads.
pub struct BgeEmbedder {
    dir: PathBuf,
    model: Option<Bge>,
    batch: usize,
    workers: usize,
}

impl BgeEmbedder {
    /// An embedder over the checkpoint in `dir` (`pytorch_model.bin`,
    /// `vocab.txt`), `batch` texts per forward pass on `workers` threads.
    pub fn new(dir: &Path, batch: usize, workers: usize) -> Self {
        Self {
            dir: dir.to_path_buf(),
            model: None,
            batch: batch.max(1),
            workers: workers.max(1),
        }
    }
}

impl Embedder for BgeEmbedder {
    fn embed(&mut self, texts: &[&str]) -> Result<Vec<[f32; DIM]>, String> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        if self.model.is_none() {
            self.model = Some(Bge::load_fp32_dir(&self.dir)?);
        }
        let model = self.model.as_ref().expect("model loaded above");
        let mut order: Vec<(usize, Vec<u32>)> = texts
            .iter()
            .enumerate()
            .map(|(i, t)| (i, model.encode(t)))
            .collect();
        // Length-sorted batches on several workers: the per-op overhead of
        // small GEMMs dominates one forward pass, so concurrency is what
        // scales.
        order.sort_by_key(|x| x.1.len());
        let batches: Vec<&[(usize, Vec<u32>)]> = order.chunks(self.batch).collect();
        let next = AtomicUsize::new(0);
        let results: Mutex<Vec<(usize, [f32; DIM])>> = Mutex::new(Vec::with_capacity(texts.len()));
        let failure: Mutex<Option<String>> = Mutex::new(None);
        std::thread::scope(|sc| {
            for _ in 0..self.workers {
                sc.spawn(|| loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(chunk) = batches.get(i) else { break };
                    let ids: Vec<Vec<u32>> = chunk.iter().map(|x| x.1.clone()).collect();
                    match model.embed_ids(&ids) {
                        Ok(vs) => {
                            let mut r = results.lock().expect("results lock poisoned");
                            for (j, v) in vs.into_iter().enumerate() {
                                r.push((chunk[j].0, v));
                            }
                        }
                        Err(e) => {
                            *failure.lock().expect("failure lock poisoned") = Some(e);
                            break;
                        }
                    }
                });
            }
        });
        if let Some(e) = failure.into_inner().expect("failure lock poisoned") {
            return Err(e);
        }
        let mut out = vec![[0f32; DIM]; texts.len()];
        for (i, v) in results.into_inner().expect("results lock poisoned") {
            out[i] = v;
        }
        Ok(out)
    }
}
