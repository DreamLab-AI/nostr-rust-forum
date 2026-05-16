//! Key provisioning re-export shim (JSS Phase 1, deferred).
//!
//! **Verification (2026-05-16, alpha.11):** the `key_provisioning` module
//! ships at `solid_pod_rs_idp::key_provisioning` (sibling workspace crate
//! `solid-pod-rs-idp`), NOT at `solid_pod_rs::idp::key_provisioning`. The
//! kit does not depend on `solid-pod-rs-idp`. Upstream feature
//! `provision-keys = ["tokio-runtime"]` is incompatible with the kit's
//! `default-features = false, features = ["core"]` workspace pin and with
//! the wasm32 CF Workers target.
//!
//! Therefore the re-export stays parked. The pod-worker has its own
//! provisioning path in `src/provision.rs` (CF Workers-native: R2/KV/D1
//! storage, no tokio). Adopting the upstream helper requires either
//! (a) a CF Workers port of `key_provisioning` upstream, or (b) a native
//! server-side variant of the pod-worker. Tracked as Phase 1 follow-up.
//!
//! See `docs/consumer-surface-map.md` and ADR-086.

#[cfg(feature = "solid-pod-rs-phase1")]
// Surface lives in the `solid-pod-rs-idp` sibling crate, not re-exported by
// the core `solid-pod-rs` crate. Add `solid-pod-rs-idp` as an optional dep
// gated behind `solid-pod-rs-phase1` and uncomment the line below to wire
// it through once a CF-Workers-compatible variant is available.
// pub use solid_pod_rs_idp::key_provisioning::*;
const _: () = ();
