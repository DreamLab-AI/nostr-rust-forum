# JSS Phase 1 Impact Assessment — NRF Forum Primitive

**Date:** 2026-05-16
**Scope:** Kit crates only (`nostr-bbs-{auth-worker, pod-worker, relay-worker,
preview-worker, search-worker, forum-client, core, config, mesh, rate-limit}`).
The `dreamlab-ai-website` operator overlay is out of scope.
**Trigger:** `solid-pod-rs` bumped 0.4.0-alpha.10 → 0.4.0-alpha.11 (commit
874524f, task #6 closed). Phase 1 features `provision-keys`, `nip05-endpoint`,
`export-jsonld` are now reachable from the workspace.

## 1. Per-crate findings

### 1.1 `nostr-bbs-auth-worker`

| Surface | Phase 1 primitive? | Redundant? | New capability? | Disposition |
| --- | --- | --- | --- | --- |
| `username.rs::check` (D1 lookup) | Partial | No | Federated NIP-05 lookup unlocks D1 → pod-HTTP fallback per ADR-086 | **Required** |
| `username.rs::claim` (D1 + KV mirror) | Yes (writes `POD_META.nip05:{name}`) | No (trust root) | None | No-op |
| `pod.rs` (provisioning) | Yes — provisions Solid pod | Not redundant; upstream `solid_pod_rs_idp::key_provisioning` is tokio-only and lives in a sibling crate the kit doesn't depend on. The CF Workers runtime cannot link it. | Pod-resident Schnorr signup if upstream extracts a CF-portable variant | **Deferred** (upstream blocker) |
| `webauthn.rs` (passkey registration) | No | No | NIP-46 remote-signing-to-pod alt-flow theoretically possible but requires (a) pod-resident key, (b) NIP-46 signer running on the pod. Both are upstream-blocked. | **Deferred** (depends on pod-resident signup) |
| `pod.rs:10` `POD_BASE_URL` constant | Placeholder `https://pods.example.com` — wired to no config source | Yes — federation needs operator-supplied URL | None new, but cleanup required | **Nice-to-have, paired with federation work** |

**Required action:** Add a `resolve()` function in `username.rs` that does D1 →
KV → optional pod-HTTP fallback, gated on `NIP05_RESOLVER_MODE` (set from the
operator's `[nip05].resolver_mode` field). Expose via `GET
/api/username/resolve?name=<X>`. Existing `check()`/`claim()` paths untouched
to preserve the trust-root invariant.

### 1.2 `nostr-bbs-pod-worker`

| Surface | Phase 1 primitive? | Redundant? | New capability? | Disposition |
| --- | --- | --- | --- | --- |
| `src/provision.rs` (CF-Workers-native pod provisioning) | Yes | No — upstream `provision-keys` lives in `solid-pod-rs-idp` (tokio-only, separate crate). Pod-worker's R2/KV/D1 path is non-portable in the other direction. | Could optionally write `nostr:pubkey` triple into the WebID profile/card so pod-resident NIP-05 can serve from it later. | **Nice-to-have** (decouples from federation work; can land next sprint without blocking the federation path) |
| `src/lib.rs` `/.well-known/nostr.json` route | Yes — KV-backed handler | No — alpha.11 upstream handler is actix-web in `solid-pod-rs-server`, not portable to `worker::Response`. ADR-086 §8 records this. | Pod-resident WebID-sourced NIP-05 would be a net new feature but requires the upstream port. | **Deferred** |
| `src/webid.rs` `generate_webid_html` re-export | Yes | No | Could grow `nostr:pubkey` triple emission (small) | **Nice-to-have**, sequenced after pod-worker provision optionally writes the privkey/triple |
| `src/payments.rs`, `src/acl.rs`, `src/did.rs` | Unaffected by Phase 1 | No | None | No-op |
| `src/export.rs` (new shim, alpha.11) | Surface is live (`solid_pod_rs::export::*`) | No | Upstream `export-jsonld = ["tokio-runtime"]` — the underlying `export_pod_jsonld` async fn requires tokio + a `Storage` impl. CF Workers can't run it. | **Deferred** (upstream blocker for the worker target) |

**Required action:** None for this pass. All Phase 1 pod-worker work needs an
upstream CF-Workers-portable extraction first.

### 1.3 `nostr-bbs-config`

| Surface | Phase 1 primitive? | Redundant? | New capability? | Disposition |
| --- | --- | --- | --- | --- |
| `src/schema.rs` (TOML schema) | No `[nip05]` block today | No | Adding `[nip05] { resolver_mode, pod_base_url }` gives the kit first-class typed config (currently lives in the operator overlay as an additive `toml::Value` extraction). | **Required** (per brief constraint) |

**Required action:** Add `Nip05` struct + optional `nip05` field on
`ForumConfig`, with `serde(default)` and conservative defaults (`resolver_mode
= "d1"`). Add validator for `pod_base_url` (must be https). Tests for round-trip.

### 1.4 `nostr-bbs-forum-client` (Leptos)

| Surface | Phase 1 primitive? | Redundant? | New capability? | Disposition |
| --- | --- | --- | --- | --- |
| Registration page | Brings own key (NIP-07) | No | "Generate keys on my pod" requires pod-resident signup (deferred per §1.1) | **Deferred** |
| `/settings/export` page | Not present today | No | GDPR-style "Download my data" against pod's `/api/exports/all` | **Deferred** (the pod-worker doesn't expose this route yet; export logic upstream is tokio-only) |
| Profile NIP-05 verification badge | Not present today | No | Renders `✓ verified` if pod NIP-05 responds with matching pubkey | **Nice-to-have**; small, fully client-side; defer to keep this sprint focused on the federation path |

**Required action:** None for this pass.

### 1.5 `nostr-bbs-relay-worker`

| Surface | Phase 1 primitive? | Redundant? | New capability? | Disposition |
| --- | --- | --- | --- | --- |
| NIP-42 AUTH gate | Schnorr verification path | No | None — pod-provisioned keys are also Schnorr; AUTH is signature-agnostic about origin | **No-op** (verified by reading `src/auth.rs` — accepts any 64-hex pubkey) |

### 1.6 `nostr-bbs-core`, `nostr-bbs-mesh`, `nostr-bbs-rate-limit`, `nostr-bbs-preview-worker`, `nostr-bbs-search-worker`

No Phase 1-relevant primitives. Type re-exports for `solid-pod-rs` already
in place via `nostr-bbs-pod-worker`. **No-op.**

## 2. Implementation manifest for this pass

In priority order:

1. **(REQUIRED) `[nip05]` config schema.** Extend
   `nostr-bbs-config/src/schema.rs` additively. Default: `resolver_mode =
   "d1"`. Round-trip + validator tests.
2. **(REQUIRED) Federated `resolve()` in auth-worker.** New function +
   `GET /api/username/resolve?name=<X>` route. Reads `NIP05_RESOLVER_MODE`
   env var (operator deploy injects from `forum.toml`). On `"federated"` and
   D1 miss: fetch `${POD_BASE_URL}/.well-known/nostr.json?name=<local>`,
   parse, return pubkey. Tests for both modes + pod-offline + malformed-JSON
   + conflicting-record (D1-wins-by-construction). Move
   `pod.rs:10::POD_BASE_URL` to env-driven config in the same patch.
3. **(STATUS) Update ADR-086 from `Accepted` to `Implemented`** once item 2
   lands and tests pass.

## 3. Explicitly deferred (with rationale)

| Feature | Brief priority | Blocker |
| --- | --- | --- |
| Pod-resident signup (provision-keys) | 2 | Upstream `key_provisioning` is tokio-only and lives in `solid-pod-rs-idp`. CF Workers target cannot link. Track via Phase 1 follow-up upstream. |
| Data export UX (export-jsonld) | 3 | Upstream `export_pod_jsonld` is tokio + `Storage` trait. CF Workers can't run it. Pod-worker has no `/api/exports/all` route to call. |
| Profile NIP-05 badge | 4 | Genuinely nice-to-have; cuts client-side scope from this commit. File a follow-up. Implementation is ~50 lines of Leptos once the federation path is verified. |
| Optional `nostr:pubkey` triple emission in `webid.rs` | n/a | Pairs better with pod-resident signup; isolated change otherwise has no consumer until then. |

## 4. Open questions for follow-up ADRs

- **Account-recovery / key-loss policy** when (and if) pod-resident signup
  lands. Today the user owns the key locally; with pod-resident keys, what
  happens when the user loses pod access? Worth its own ADR.
- **Per-user external pod registration.** ADR-086 currently assumes a single
  operator-wide `pod_base_url`. If users want to bring their own pod, the
  schema needs a per-user mapping and `derive_pod_base_url(name)` needs to
  consult it. Track as ADR-NNN if/when there's user demand.
- **Upstream `solid-pod-rs` CF-Workers portability.** Three of the four Phase
  1 features hit the tokio/actix-web wall on wasm32. A follow-up issue on
  `solid-pod-rs` to extract CF-Workers-portable cores (no tokio, no actix)
  would unblock real consumer work in the kit.
