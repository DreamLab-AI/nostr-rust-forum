//! Pod export bundle re-export shim (JSS Phase 1).
//!
//! Re-exports the upstream `solid_pod_rs::export::*` surface so the
//! pod-worker can serve `GET /api/exports/all` as a time-chain ordered
//! JSON-LD bundle without re-implementing canonicalisation locally.
//!
//! Surface (alpha.11): `PodExportBundle`, `PodExportEntry`, `ExportOptions`,
//! `export_pod_jsonld`, plus the `EXPORT_*` and `PRIVATE_*` const paths.
//!
//! Activation: requires the `solid-pod-rs-phase1` cargo feature on
//! `nostr-bbs-pod-worker`. Note that upstream gates `export-jsonld` on
//! `tokio-runtime`, so this surface is only reachable on native (server)
//! builds, not the wasm32 CF Workers target.
//!
//! See `docs/consumer-surface-map.md` and ADR-086.

#[cfg(feature = "solid-pod-rs-phase1")]
#[allow(unused_imports)]
pub use solid_pod_rs::export::*;
