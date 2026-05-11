//! Storage adapter layer for the pod-worker.
//!
//! Wraps Cloudflare R2 (object store) and KV in an ergonomic adapter that
//! the rest of the worker interacts with. This is the thin adapter prescribed
//! by the solid-pod-rs-first strategy: pod-worker delegates all persistence
//! to Cloudflare primitives, not to solid-pod-rs's Storage trait (which pulls
//! tokio and is incompatible with WASM Workers).

pub mod cf_backend;
