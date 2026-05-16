# NRF → solid-pod-rs Consumer Surface Map

**Generated:** 2026-05-16 (mega-sprint Phase 1 staging)
**Pin:** `solid-pod-rs = "0.4.0-alpha.10"` (workspace, `default-features = false, features = ["core"]`)
**Purpose:** Track every NRF call into `solid_pod_rs::*` so the Phase 1 alpha.11
bump can be audited at a glance. Re-export shims are surfaces NRF re-publishes
verbatim per the ADR-076/078 absorption; internal uses are call sites the kit
consumes but does not re-export.

## Current consumer surface (alpha.10)

| NRF file (crate / path) | solid-pod-rs symbol | Role |
| --- | --- | --- |
| `nostr-bbs-pod-worker/src/acl.rs:22` | `solid_pod_rs::wac::{method_to_mode, wac_allow_header, AccessMode, AclDocument}` | Re-export shim (public API) |
| `nostr-bbs-pod-worker/src/acl.rs:45` | `solid_pod_rs::wac::evaluate_access` | Internal use (delegated call) |
| `nostr-bbs-pod-worker/src/acl.rs:181` (test) | `solid_pod_rs::wac::{mode_name, AclAuthorization, IdOrIds, IdRef}` | Internal use (unit tests only) |
| `nostr-bbs-pod-worker/src/webid.rs:12` | `solid_pod_rs::webid::generate_webid_html` | Re-export shim (public API) |
| `nostr-bbs-pod-worker/src/payments.rs:31` | `solid_pod_rs::payments::{balance_response, parse_txo_uri, pay_info, payment_required_body, pubkey_to_did, webledgers_discovery, ChainConfig, PayConfig, PaymentError, PaymentStore, TokenConfig, WebLedger}` | Re-export shim (public API) |
| `nostr-bbs-core/src/did.rs:13` | `solid_pod_rs::did_nostr_types` (aliased `upstream`) | Internal wrapper (kit adds adapters on top) |
| `nostr-bbs-pod-worker/src/provision.rs` (docs only) | mirrors `solid_pod_rs::provision::*` constants/paths | Documentation reference (no `use` line — kit re-implements equivalents) |

## Staged Phase 1 consumer surface (alpha.11, currently inert)

The following stub modules are wired in `nostr-bbs-pod-worker/src/lib.rs` behind
the inert `solid-pod-rs-phase1` cargo feature. Bodies stay commented until the
workspace bumps `solid-pod-rs` to `0.4.0-alpha.11`.

| NRF stub file | Anticipated solid-pod-rs symbol | Role on activation |
| --- | --- | --- |
| `nostr-bbs-pod-worker/src/key_provisioning.rs` | `solid_pod_rs::idp::key_provisioning::*` | Re-export shim (public API) for the Schnorr keypair signup helper |
| `nostr-bbs-pod-worker/src/export.rs` | `solid_pod_rs::export::PodExportBundle` (+ helpers) | Re-export shim (public API) for the time-chain JSON-LD export bundle |
| `nostr-bbs-pod-worker/src/nip05_endpoint.rs` | `solid_pod_rs::nip05::endpoint::*` (handler helpers) | Re-export shim (public API) for the pod-resident `/.well-known/nostr.json` route. Distinct from the existing `verify_nip05` builder. |

## Notes

- The `core` feature is the only feature enabled today; Phase 1 introduces three
  additional default-off features upstream (`provision-keys`, `nip05-endpoint`,
  `export-jsonld`). The kit groups them under one NRF-facing alias,
  `solid-pod-rs-phase1`, defined in `nostr-bbs-pod-worker/Cargo.toml`.
- No call sites in `nostr-bbs-auth-worker` use `solid_pod_rs::*` today. The NIP-05
  federation path lands there post-Phase-1 (see ADR-086).
