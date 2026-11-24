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
//! - [`seal`]: HKDF → age X25519 identity, seal/open, chunk random access.
//! - [`manifest`]: the signed (NIP-01) index manifest and its acceptance rules.
//! - [`search`]: the resident index (first stage, chunked rescoring, decoys).

pub mod build;
pub mod format;
pub mod manifest;
pub mod model;
pub mod quant;
pub mod search;
pub mod seal;
pub mod wordpiece;
