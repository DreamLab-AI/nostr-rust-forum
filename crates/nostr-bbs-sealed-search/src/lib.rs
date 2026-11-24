//! Sealed per-zone search for end-to-end-encrypted forum zones.
//!
//! Members download a zone's search index sealed to the zone key (age, with
//! an X25519 identity derived by HKDF from the zone epoch secret), and search
//! it in a browser Web Worker: the query is embedded on the device, so no
//! plaintext, vector or query ever reaches a server. See
//! `keybase-port/analysis/SEALED-SEARCH-DESIGN.md`.
//!
//! - [`wordpiece`]: BERT-uncased tokeniser (bge-small `vocab.txt`).
//! - [`model`]: bge-small-en-v1.5 embeddings in candle, FP32 or GGUF Q8_0.
//! - [`quant`]: sign codes + lookup-table scoring, int8 rescoring rows.
//! - [`format`]: authenticated object header and layers.
//! - [`kdf`]: HKDF derivation of the per-(zone, epoch) search key (no age; the main thread links only this).
//! - [`seal`]: age X25519 identity from that key, seal/open, chunk random access.
//! - [`manifest`]: the signed (NIP-01) index manifest and its acceptance rules.
//! - [`search`]: the resident index (first stage, chunked rescoring, decoys).

#[cfg(feature = "seal")]
pub mod build;
pub mod format;
pub mod kdf;
pub mod manifest;
#[cfg(feature = "model")]
pub mod model;
pub mod quant;
#[cfg(feature = "seal")]
pub mod search;
#[cfg(feature = "seal")]
pub mod seal;
#[cfg(feature = "model")]
pub mod wordpiece;

/// Embedding dimension (bge-small-en-v1.5).
pub const DIM: usize = 384;
