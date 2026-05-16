//! Pod-resident NIP-05 endpoint shim (JSS Phase 1, deferred).
//!
//! **Verification (2026-05-16, alpha.11):** the upstream `nip05-endpoint`
//! feature manifests as `solid_pod_rs_server::handle_well_known_nip05`, a
//! private `async fn` returning `actix_web::HttpResponse`. It is NOT a
//! publicly re-exportable symbol, and its actix-web binding is unsuitable
//! for the CF Workers `worker::Response` runtime the pod-worker uses.
//!
//! Therefore the re-export stays parked. The pod-worker's existing
//! `/.well-known/nostr.json?name=<local>` handler (in `src/lib.rs`, around
//! line 359) keeps serving the route using its KV-backed `nip05:{name}`
//! lookup. ADR-086's federation path is unaffected — the auth-worker
//! fetches NIP-05 from the pod over HTTP regardless of which server
//! framework implements the endpoint on the other end.
//!
//! When a CF-Workers-portable extraction of the upstream handler ships,
//! revisit this module to wire it in. Tracked as Phase 1 follow-up.
//!
//! See `docs/consumer-surface-map.md` and ADR-086.

#[cfg(feature = "solid-pod-rs-phase1")]
// Surface is actix-web-only in `solid-pod-rs-server`; not portable to the
// `worker::Response` runtime. Leave commented until an upstream extraction
// or a CF-Workers-native helper exists.
// pub use solid_pod_rs_server::nip05_endpoint::*;
const _: () = ();
