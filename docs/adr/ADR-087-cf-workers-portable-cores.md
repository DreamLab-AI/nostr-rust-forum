# ADR-087 — CF-Workers-portable cores for solid-pod-rs Phase 1 surfaces

- **Status:** Draft — decision deferred (closeout 2026-07-03). No option (a/b/c)
  has been selected; the three Phase-1 surfaces (`provision-keys`,
  `nip05-endpoint`, `export-jsonld`) remain structurally unreachable from the
  wasm32 CF Workers target, so ADR-086's pod-federation fallback is degenerate
  (pod returns the same data D1 already holds). This is a genuine open spec
  decision, not implemented work — it awaits a champion for the upstream split.
- **Date:** 2026-05-16
- **Owners:** Cross-stack — NRF consumer (`nostr-bbs-pod-worker`) and upstream
  `solid-pod-rs`. Authored by `nrf-aligner` following Phase 1 impact
  assessment; awaiting a champion before flipping to Proposed.
- **Related:** ADR-076 (Phase 4 absorption — `core` feature precedent),
  ADR-086 §8 (NIP-05 federation; records `key_provisioning` and
  `nip05-endpoint` deferral), `docs/phase1-impact-assessment.md` §3 (data
  export UX deferral on same basis).

## 1. Context

JSS Phase 1 ports three default-off feature flags into `solid-pod-rs`
v0.4.0-alpha.11:

| Upstream feature   | Module path                                      | Hard dep             |
| ------------------ | ------------------------------------------------ | -------------------- |
| `provision-keys`   | `solid_pod_rs_idp::key_provisioning`             | `tokio-runtime`      |
| `nip05-endpoint`   | `solid_pod_rs_server::handle_well_known_nip05`   | `tokio-runtime` + actix-web |
| `export-jsonld`    | `solid_pod_rs::export::export_pod_jsonld`        | `tokio-runtime` + `Storage` trait |

NRF's deployable consumer surface is **`nostr-bbs-pod-worker`**, a
Cloudflare Workers crate compiled to `wasm32-unknown-unknown`. CF Workers
has no Tokio runtime, no native sockets, no synchronous filesystem. The
three Phase 1 surfaces are therefore unreachable from the kit's primary
deployment target. ADR-086 §8 records the immediate consequence: the stub
re-exports in `nostr-bbs-pod-worker::{key_provisioning, nip05_endpoint}`
stay commented; only `export` was wired (and it too is gated since
`export-jsonld = ["tokio-runtime"]`).

The `core` feature precedent (ADR-076 / `solid-pod-rs` 0.4.0-alpha.3)
already shows the kit can absorb large surfaces if upstream offers a
no-tokio split. The Phase 1 ports did not extend the same split.

## 2. Decision (deferred)

This ADR enumerates options without picking one. It exists to pin the
finding before context evaporates.

### Option (a) — Upstream PR: CF-Workers-portable cores [recommended]

Extract `core`-style minimal surfaces for each Phase 1 feature:

- `key_provisioning`: pure-transform helpers that produce the JSON-LD body
  for `/private/privkey.jsonld` and its WAC ACL, with no Storage trait.
  Caller (CF Workers in our case, server runtimes elsewhere) is responsible
  for persisting the bytes. Mirrors the `core` precedent.
- `nip05-endpoint`: a request/response shape extractor (`name` → `Option<Pubkey>`)
  plus a response-body builder. No framework binding. CF Workers' existing
  `/.well-known/nostr.json` handler in `nostr-bbs-pod-worker/src/lib.rs`
  can call into it.
- `export-jsonld`: a streaming-iterator API parameterised over an async
  source. Caller provides the iterator; library does the canonicalisation
  + framing. Removes the hard `Storage`-trait dependency.

Wins: benefits NRF + every future wasm32/no-tokio consumer of solid-pod-rs
(other CF Workers shops, embedded WASM, browser-side experiments).
Aligns with the `core` precedent the project already invested in. Cost:
single upstream PR; scope is bounded since the impl logic already exists.

### Option (b) — NRF reimplements to wire-shape parity

Drop in NRF-owned implementations in CF Workers Rust:

- `/private/privkey.jsonld` writer (already partially there in
  `nostr-bbs-pod-worker/src/provision.rs`; just extend to the Phase 1 shape).
- `/.well-known/nostr.json` handler reads pubkey from WebID profile/card
  Turtle (need a CF-portable Turtle parser — solid-pod-rs ships one, but
  it lives behind the same wasm32 wall).
- Time-chain JSON-LD export bundle: walk the user's R2 prefix, frame each
  resource into the bundle envelope per the spec.

Wins: zero coordination with upstream; lands when we want. Cost: every
spec drift downstream means a re-port; duplicates effort across all wasm32
consumers; CF Workers becomes a divergent shadow stack. Wire compatibility
is real but only on a best-effort basis.

### Option (c) — Defer indefinitely

Accept that NRF's Phase 1 capabilities are bounded by what CF Workers can
do without upstream help. Means:

- Pod-resident signup (`provision-keys`) never lands in the kit.
- Data export UX (`export-jsonld`) never lands.
- Pod-resident NIP-05 (`nip05-endpoint`) never lands; the kit's KV-backed
  handler remains the only source.

Wins: zero work. Cost: the federation contract in ADR-086 is degenerate
for the foreseeable future (pod fallback returns the same data D1 already
returns); the kit can never offer the user-visible Phase 1 capabilities.

## 3. Recommendation

**Option (a).** The cost is bounded (one upstream PR; impl already exists,
just needs splitting), the precedent (`core`) is well-trodden, and it
unlocks every future wasm32 consumer — not just NRF. Status flips to
Proposed when a champion picks up the upstream work.

## 4. Out of scope

- Picking the option.
- Drafting the upstream PR.
- Re-evaluating ADR-086's "operator-wide single `pod_base_url`" simplifying
  assumption (that's a separate per-user-pod federation question).

## 5. Migration / impact

None today. Status is Draft. ADR-086 and the impact assessment continue
to defer the affected NRF features under their existing rationale.

## 6. References

- ADR-086 §8 (Implementation note: the deferral that surfaced this gap).
- `docs/phase1-impact-assessment.md` §3.
- `docs/consumer-surface-map.md` (staged Phase 1 consumer surface section).
- Upstream: https://github.com/melvincarvalho/solid-pod-rs commit
  `d8a1c81` (v0.4.0-alpha.11).
