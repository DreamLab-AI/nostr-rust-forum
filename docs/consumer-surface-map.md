# NRF → solid-pod-rs Consumer Surface Map

**Generated:** 2026-05-17 (1.0.0-beta.2 / git control panel + JSS #464 + native pod tier); pins refreshed 2026-07-18 for kit 1.0.0-beta.5
**Pin:** `solid-pod-rs` `=0.5.0-alpha.4` from crates.io (`default-features = false, features = ["core"]`; superseded git revs `4ac7670` alpha.14 / `8668792`)
**Purpose:** Track every NRF call into `solid_pod_rs::*` so upstream Solid/JSS
parity bumps can be audited at a glance. Re-export shims are surfaces NRF
re-publishes verbatim per the ADR-076/078 absorption; internal uses are call
sites the kit consumes but does not re-export.

## Current consumer surface

| NRF file (crate / path) | solid-pod-rs symbol | Role |
| --- | --- | --- |
| `nostr-bbs-pod-worker/src/acl.rs:22` | `solid_pod_rs::wac::{method_to_mode, wac_allow_header, AccessMode, AclDocument}` | Re-export shim (public API). The kit-local `find_effective_acl` resolver (ADR-096) now probes the per-container sidecar `<dir>/.acl` at every walk-up level and sets `AclDocument::inherited` per level; `build_delegation_acl` emits a canonical owner-Control + agent-minus-Control merged doc that round-trips through this parser. |
| `nostr-bbs-pod-worker/src/acl.rs:45` | `solid_pod_rs::wac::evaluate_access` | Internal use (delegated call) |
| `nostr-bbs-pod-worker/src/acl.rs:181` (test) | `solid_pod_rs::wac::{mode_name, AclAuthorization, IdOrIds, IdRef}` | Internal use (unit tests only) |
| `nostr-bbs-pod-worker/src/webid.rs:12` | `solid_pod_rs::webid::generate_webid_html` | Re-export shim (public API) |
| `nostr-bbs-pod-worker/src/payments.rs:31` | `solid_pod_rs::payments::{balance_response, parse_txo_uri, pay_info, payment_required_body, pubkey_to_did, webledgers_discovery, ChainConfig, PayConfig, PaymentError, PaymentStore, TokenConfig, WebLedger}` | Re-export shim (public API) |
| `nostr-bbs-core/src/did.rs:13` | `solid_pod_rs::did_nostr_types` (aliased `upstream`) | Internal wrapper (kit adds adapters on top) |
| `nostr-bbs-forum-client/src/pages/{signup,pod_browser,settings}.rs` | `solid_pod_rs::webid::{webid_url, pod_git_clone_url}` | Internal URL builder use; avoids hand-rolled pod/WebID/git URL strings in user-facing WASM |
| `nostr-bbs-forum-client/src/components/git_panel.rs` | `/_git/{pk}/*` REST API (solid-pod-rs-server, feature `git`) + `/.well-known/apps` (JSS #464) | Forum git control panel calls server-side endpoints; no direct `solid_pod_rs::` import (REST boundary); only available on native server deployments (ADR-089) |
| `nostr-bbs-pod-worker/src/provision.rs` (docs only) | mirrors `solid_pod_rs::provision::*` constants/paths | Documentation reference (no `use` line — kit re-implements equivalents) |

## Worker-local mirrors

The Cloudflare Worker target cannot link the native actix/tokio server surfaces,
so these routes intentionally mirror the upstream behavior with Worker-native
storage and response types:

| NRF surface | Upstream reference | Worker disposition |
| --- | --- | --- |
| `nostr-bbs-core::POD_CORS_HEADERS` | `solid-pod-rs-server` JSS-compatible CORS middleware | Mirrors method/header/expose envelope, including `DPoP`, `Updates-Via`, WAC, and payment headers |
| `nostr-bbs-pod-worker::json_error(401)` | JSS-compatible Solid auth challenge | Emits `WWW-Authenticate: DPoP realm="Solid", Bearer realm="Solid"` |
| `POST /.pods` | `solid-pod-rs-server` pod creation route | Authenticated alias that provisions `/pods/{pubkey}/` and returns `{ name, webId, podUri }` |
| LDP response headers | `Updates-Via: .../.notifications` | Emits resource sidecar notification discovery (`{resource}.notifications`) for the Worker webhook implementation |

## Staged Phase 1 consumer surface

The following stub modules are wired in `nostr-bbs-pod-worker/src/lib.rs` behind
the `solid-pod-rs-phase1` cargo feature. They remain Worker-portability markers
because the native upstream implementations are not directly linkable in
`wasm32-unknown-unknown`.

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
