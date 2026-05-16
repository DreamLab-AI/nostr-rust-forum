# ADR-089 — git-pods unavailability on Cloudflare Workers deployments

- **Status:** Draft
- **Date:** 2026-05-16
- **Owners:** Cross-stack — NRF consumer (`nostr-bbs-pod-worker`) and upstream
  `solid-pod-rs` git-pods initiative (JSS #471, alpha.12). Authored by
  `nrf-git-ui` following the git-pods mesh sprint.
- **Related:** ADR-087 (CF-Workers-portable cores — same underlying
  wasm32/Tokio gap); ADR-032 (embed solid-pod-rs library); JSS #471
  (solid-pod-rs git-auto-init at pod provisioning); agentbox sister-task
  surfacing git HTTP route for non-CF deployments.

## 1. Context

`solid-pod-rs` v0.4.0-alpha.12 (JSS #471) ships **git-auto-init**: at pod
provisioning time the library runs `git init -b main` against the pod's
storage root and exposes the resulting repository over an HTTP smart
transport, so users can `git clone https://pods.<host>/<user>/` and treat
their pod as a versioned working tree. The feature is gated behind a
`git` cargo feature that pulls in `git2`/`gix` plus a `tokio::process`
subprocess fallback for `git init`.

NRF's deployable pod surface is **`nostr-bbs-pod-worker`**, a Cloudflare
Workers crate compiled to `wasm32-unknown-unknown`. CF Workers has:

- no process-spawning capability (no `tokio::process`, no `std::process::Command`,
  no syscall surface that could host a `git init` subprocess);
- no native filesystem (pod storage is R2 + KV, accessed only via the
  workers-rs bindings);
- no Tokio runtime — the same wasm32 wall that ADR-087 documents for
  Phase 1 surfaces.

Consequently the alpha.12 `git` feature is **structurally unreachable**
from `nostr-bbs-pod-worker`. Adding `solid-pod-rs` with `features = ["git"]`
to the worker's `Cargo.toml` would not just fail to function — it would
fail to compile, because `tokio::process` has no wasm32 target.

Sister-stack `agentbox` (a non-CF deployment of the kit's pod surface,
built on a server Tokio runtime) **can** consume the `git` feature and is
doing so in a parallel sprint task. The result is a deployment-tier
divergence: pods provisioned by agentbox are git repositories; pods
provisioned by the CF Workers tier are plain LDP+R2 prefixes with no
git history.

## 2. Decision (deferred)

This ADR enumerates options without picking one. The shipping behaviour
for the CF Workers tier is option (a) by default — git-pods are simply
absent there until a champion lands (b) or (c).

### Option (a) — Defer indefinitely on CF Workers [shipping default]

CF-Workers-hosted pods are not git repositories. Users who want git
access to their pod must use a non-CF deployment of the kit (agentbox,
self-hosted server, etc.). The forum-client UI surfaces a clone URL on a
best-effort basis with a caveat: the URL only resolves on deployments
where the operator has enabled git-init at provisioning time.

Wins: zero engineering cost; honest about the limitation; no risk of
shipping a broken `git clone` experience to CF tenants. Cost: a
user-visible capability gap between deployment tiers.

### Option (b) — WASM-native git via pure-Rust `gix`

`gitoxide` (`gix`) ships a pure-Rust git implementation with no process
spawning. In principle it can target wasm32; in practice the R2-backed
"filesystem" needs adapting (gix expects a `std::fs`-shaped backend, and
the kit would need to provide a shim that translates gix's repository
I/O into R2/KV `put`/`get` calls).

Wins: closes the deployment-tier capability gap; pure-Rust path keeps the
worker dependency tree wasm-friendly. Cost: substantial research effort
(R2-backed storage shim, packfile semantics under CF Workers' 30s CPU
budget, smart-HTTP transport over Workers fetch handlers). Unknown
whether gix's wasm32 story is mature enough to be production-grade in
2026. No champion identified.

### Option (c) — External git-init sidecar service

Run a non-CF sidecar (e.g. small Fly.io / Hetzner container) that
subscribes to pod-creation events from the CF tier and runs
`git init` against the R2 bucket via the S3-compatible API. The CF worker
remains the request path; only provisioning crosses tiers.

Wins: minimal CF-side change; reuses the upstream `git` feature
unmodified. Cost: introduces a non-CF infrastructure component into a
deployment story whose value proposition is "CF Workers only"; operators
who picked the CF tier specifically to avoid running containers will not
want to operate this sidecar; event ordering / failure semantics need
thought.

## 3. Recommendation

**Option (a) for the v3.0 line.** Ship the forum-client clone-URL UI
surface unconditionally — it is value-add on agentbox and other non-CF
deployments today, and a soft signal of an absent capability on the CF
tier. Revisit (b) if `gix`'s wasm32 story matures or if user demand
materialises; revisit (c) only if a specific operator funds the sidecar
work.

## 4. Out of scope

- Picking between (b) and (c).
- The `solid-pod-rs` git-feature design itself (owned upstream by JSS
  #471 and agentbox).
- Operator configuration UX for the clone URL host (covered by the
  existing `[pod].base_url` plumbing in `nostr-bbs-config`).

## 5. Migration / impact

- **`nostr-bbs-pod-worker`**: no Cargo dependency change. A doc comment
  in `src/provision.rs` records the divergence so the next reader does
  not look for a missing git-init call.
- **`nostr-bbs-forum-client`**: settings page gains a "Pod git
  repository" section displaying `git clone <pod_base_url>/<pubkey>`
  with a copy button and a caveat that the URL only resolves on
  git-init-enabled deployments. Pod base URL flows from
  `[pod].base_url` via the existing `VITE_POD_API_URL` env override
  (mirrors `pages/pod_browser.rs`).
- **`dreamlab-ai-website`**: operator overlay keeps `[git].enabled =
  false` for the Cloudflare deployment recipe; agentbox recipe sets it
  to `true`.
- **README**: Phase 1 (May 2026) section gains a "Phase 1 extension:
  git-pods (2026-05-16)" paragraph cross-referencing this ADR.

## 6. References

- ADR-087 (same wasm32/Tokio gap, Phase 1 surfaces).
- ADR-032 (embed solid-pod-rs library — the dependency-direction
  precedent).
- JSS #471 — solid-pod-rs git-auto-init at pod provisioning.
- Upstream: `solid-pod-rs` v0.4.0-alpha.12 (git feature, default-off).
- Sister sprint task: agentbox wires the same upstream feature on a
  server Tokio runtime and exposes the git HTTP route.
