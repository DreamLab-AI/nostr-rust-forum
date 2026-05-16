# ADR-086 — NIP-05 Pod Federation

- **Status:** Implemented
- **Date:** 2026-05-16
- **Owners:** nostr-rust-forum (NRF) consumer surface; cooperates with
  `dreamlab-overlay`'s `dreamlab.toml` schema work and the `solid-porter`
  Phase 1 ports in `solid-pod-rs`.
- **Related:** ADR-076 (D5 module absorption), ADR-078 (Shape A absorption
  follow-up), ADR-085 (forum.toml as single configuration source),
  `dreamlab-overlay` operator surface ADR (TBD — being authored by that team
  in parallel; field name `[nip05].resolver_mode`).

## 1. Context

NRF currently treats NIP-05 as a centrally-administered registry, written to
two backing stores at username-claim time:

- **D1** (forum DB): `username_reservations(username, pubkey, created_at)`
  rows — written by `nostr-bbs-auth-worker/src/username.rs::claim()` under a
  pubkey-uniqueness invariant.
- **KV** (`POD_META` binding): `nip05:{username} -> pubkey` — written
  alongside the D1 row so the pod-worker's `/.well-known/nostr.json?name=…`
  route in `nostr-bbs-pod-worker/src/lib.rs` (~line 359) can serve verifier
  queries without hopping to D1.

Two consequences follow:

1. The auth-worker is the **trust root** for `name → pubkey` resolution on
   this forum. D1 is the authoritative side; the KV row is a read-replica.
2. Users with their own Solid pod cannot today serve NIP-05 for themselves —
   the forum's KV must be the answering hop, even when the pod is online and
   reachable.

JSS Phase 1 is adding a `nip05-endpoint` feature to `solid-pod-rs` that ships
a pod-resident `/.well-known/nostr.json` handler backed by the WebID
profile/card's `nostr:` triple. Once that ports land in `solid-pod-rs`
`0.4.0-alpha.11`, the pod-worker can re-export the handler via the staged
`nostr-bbs-pod-worker::nip05_endpoint` shim, and downstream forums can choose
to federate lookups: D1 first (cached, fast, authoritative for forum-issued
names), pod-fallback on miss (authoritative for pod-owned names that the
forum has never seen).

## 2. Decision

Adopt a **D1-cache-first, pod-fallback-on-miss** federation pattern for
NIP-05 resolution, gated by an operator opt-in flag.

- **D1 cache first.** The auth-worker's claim flow keeps writing
  `username_reservations` and the mirrored KV row. Lookups (`GET
  /.well-known/nostr.json?name=…` served by the auth-worker or pod-worker)
  consult KV → D1 in the existing order. D1 remains the trust root for
  forum-issued names.
- **Pod fallback on miss.** When both KV and D1 return no row, and the
  operator has enabled federated resolution, the auth-worker issues a
  short-timeout HTTP `GET` to the pod's `/.well-known/nostr.json?name=<local>`
  endpoint, parses the JSON response per NIP-05, and returns the pod's
  answer to the verifier without persisting it.
- **No write-back.** Pod answers are never copied into D1/KV. The forum's
  trust boundary remains "names the auth-worker has claimed"; pod-resident
  names stay owned by the pod.

This ADR is **design-only**. Implementation lands after `solid-pod-rs`
`0.4.0-alpha.11` ships and the workspace bumps the dep.

## 3. Implementation outline

All code paths below are deferred until alpha.11.

1. **Workspace bump.** Update the `solid-pod-rs` pin in the root `Cargo.toml`
   from `0.4.0-alpha.10` to `0.4.0-alpha.11`. Drop the
   `# TODO(phase1)` comment.
2. **Activate the feature alias.** Enable
   `nostr-bbs-pod-worker/solid-pod-rs-phase1` in the worker's deploy
   manifest. The three stub modules (`key_provisioning`, `export`,
   `nip05_endpoint`) un-comment their `pub use` re-exports.
3. **Wire the pod-worker route.** Replace the inline KV-only NIP-05 handler
   in `nostr-bbs-pod-worker/src/lib.rs` with a call into
   `crate::nip05_endpoint::*`, keeping the existing CORS / rate-limit
   wrapping.
4. **Auth-worker fallback.** Extend
   `nostr-bbs-auth-worker/src/username.rs` (or a new
   `username_resolve.rs`) with a `fn resolve_with_pod_fallback(name,
   resolver_mode) -> Option<String>` helper. Pseudocode:

   ```text
   if let Some(pk) = kv_lookup(name) { return Some(pk); }
   if let Some(pk) = d1_lookup(name) { return Some(pk); }
   if resolver_mode == ResolverMode::Federated {
       let pod_url = derive_pod_base_url(name)?;
       let url = format!("{pod_url}/.well-known/nostr.json?name={local}");
       let resp = fetch_with_timeout(url, Duration::from_millis(750)).await.ok()?;
       parse_nip05_response(resp).ok()
   } else {
       None
   }
   ```

   `derive_pod_base_url` must consult `forum.toml`/`dreamlab.toml` for the
   federation-allowlist (per ADR-085 single-source config). Names without a
   resolvable pod URL fall through to `None`.

5. **Test fixtures.** Add NIP-05 federation cases to
   `tests/fixtures/` (ADR-082 shared-fixture protocol) so VisionClaw,
   agentbox, and the dreamlab-ai-website downstream consumer can replay the
   same lookup matrix.

## 4. Cooperation with operator overlay

The `dreamlab-overlay` team owns the `dreamlab.toml` operator surface. The
field that gates this federation pattern is:

```toml
[nip05]
# "d1"        → legacy behaviour: D1+KV only, no pod fallback.
# "federated" → D1+KV first, then pod fallback on miss.
resolver_mode = "d1"                       # safe default; "federated" requires alpha.11
pod_base_url  = "https://pods.dreamlab-ai.com"
```

Confirmed verbatim with `dreamlab-overlay` (2026-05-16): both field names
and the `"d1" | "federated"` value set are locked. Defaults to `"d1"` so
existing deployments remain bit-for-bit identical. Operators who want pod
federation opt in by flipping `resolver_mode` to `"federated"`; the
`pod_base_url` is the host root the fallback HTTP fetch builds against,
i.e. `${pod_base_url}/.well-known/nostr.json?name=<local>`.

Parsing lives in `dreamlab-overlay`'s `src/phase1.rs::Nip05Config` (extracts
via `toml::Value`, additive — no `nostr-bbs-config` schema bump required).
NRF consumers reach the parsed values through the overlay's existing
config surface; no NRF-side parser work is needed.

## 5. Failure modes

| Mode | Symptom | Disposition |
| --- | --- | --- |
| Pod offline | Fallback HTTP fetch times out (>750 ms) | Treat as miss; return `404 Name not found`. Do not retry. |
| Malformed pod response | Pod returns non-JSON or schema-invalid `nostr.json` | Treat as miss; log at `warn`. Do not retry. |
| Conflicting records (D1 has `alice → pk_A`, pod replies `alice → pk_B`) | Two answers disagree | **D1 wins.** The forum's claim ledger is the trust root for names the forum has issued; the pod is only consulted when the forum has no record. The conflict scenario is therefore unreachable by construction (D1 hit short-circuits the pod fetch). |
| Pod returns a name the forum has explicitly **released** (per `username::release`) | Stale pod data | Acceptable: the release path removes the D1+KV rows, so the next lookup falls through to the pod. The pod's record is the user's own; the forum no longer asserts ownership. |
| Federation enabled but `resolver_mode` parser missing the field | Mis-configured deploy | Default to `"d1"`. Never federate without an explicit opt-in. |
| DoS via pod-fetch amplification | Adversary spams unknown names to force pod fetches | Rate-limit the fallback path at the auth-worker (re-use `nostr-bbs-rate-limit`); cache negative results in KV for 60 s. |

## 6. Out of scope

- Bidirectional sync between pods and the forum registry. This ADR is
  read-only fallback.
- Migrating existing D1 records into pods. Owners can do this manually via
  the Phase 1 `export-jsonld` bundle.
- Cross-forum federation (forum A consulting forum B's D1). Same trust-root
  argument — declined.

## 7. Migration

No migration is required to *adopt* this ADR (the federation path stays
behind `resolver_mode = "federated"`). Operators who want it on flip the
config flag after the alpha.11 bump and validate against the shared
fixtures.

## 8. Implementation note (2026-05-16)

- Workspace bump landed: `solid-pod-rs = "0.4.0-alpha.10"` → `"0.4.0-alpha.11"`,
  with a temporary `[patch.crates-io]` git-tag pin (`v0.4.0-alpha.11`,
  commit `d8a1c81`) until upstream `cargo publish` runs. The patch block
  is marked `TODO(phase1):` for removal.
- `nostr-bbs-pod-worker` `[features] solid-pod-rs-phase1` is now populated
  with the three upstream features (`provision-keys`, `nip05-endpoint`,
  `export-jsonld`) and `cargo check` is clean both default and gated.
- Stub re-exports activated where possible:
  - `src/export.rs` — `pub use solid_pod_rs::export::*;` (live).
  - `src/key_provisioning.rs` — **deferred**. Upstream surface is
    `solid_pod_rs_idp::key_provisioning` (sibling crate, not depended on)
    and requires `tokio-runtime`; not reachable from the wasm32 CF Workers
    target. Pod-worker keeps its own provisioning in `src/provision.rs`.
  - `src/nip05_endpoint.rs` — **deferred**. Upstream handler is an
    actix-web `async fn` private to `solid-pod-rs-server`; not portable
    to the CF Workers `worker::Response` runtime. Pod-worker keeps its
    existing KV-backed `/.well-known/nostr.json` handler in `src/lib.rs`.
- The federation fallback (auth-worker → pod HTTP) is unaffected: it
  fetches NIP-05 over HTTP regardless of which framework serves the
  endpoint on the other side. Auth-worker implementation lands in the
  follow-up impact-assessment task (see task #5).

## 9. Implementation note (2026-05-16, task #5)

- `nostr-bbs-config` schema absorbs `[nip05]` first-class:
  - `Nip05 { resolver_mode: ResolverMode, pod_base_url: Option<String> }`
  - `ResolverMode::{D1, Federated}` with `#[serde(rename_all = "lowercase")]`
    and `D1` as the conservative default.
  - Validators enforce HTTPS (or `http://localhost`), reject trailing
    slash, and reject `Federated` without a `pod_base_url`.
- `nostr-bbs-auth-worker::username` adds the federation path:
  - `ResolverMode::from_env_str` parses `NIP05_RESOLVER_MODE` (defaults to
    `D1` on missing/unknown values — no silent federation).
  - `parse_nip05_pubkey` is the trust-boundary parser: strict 64-char
    lowercase-hex check on the JSON response body.
  - `build_federated_url` constructs `${pod_base}/.well-known/nostr.json?name=<X>`.
  - `resolve(env, name) -> Option<String>` does D1 → optional pod-HTTP
    fallback.
  - `GET /api/username/resolve?name=<X>` exposes the resolver.
  - Existing `check()`/`claim()` paths untouched — they keep the
    D1-only invariant.
- 10 new pure-logic tests covering: mode parsing (5), URL construction (3),
  JSON parsing (7) including malformed JSON, missing `names`, non-string
  pubkey, wrong length, non-hex, uppercase hex.
- The pod-offline failure mode is degrade-silently (returns `None`); the
  endpoint responds 404 to the caller. D1-wins-by-construction makes the
  conflicting-record scenario unreachable.
