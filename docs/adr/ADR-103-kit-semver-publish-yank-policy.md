# ADR-103 — Kit semver, crates.io publish, and yank policy

- **Status:** Accepted
- **Date:** 2026-06-11
- **Owners:** the `nostr-bbs-*` kit crates (publishable surface), release operators.
- **Related:** [ADR-087](ADR-087-cf-workers-portable-cores.md) (portable cores —
  what the kit *is*); the anomaly register R2/R4
  ([docs/diagrams/00-anomaly-register.md](../diagrams/00-anomaly-register.md)) —
  the version-drift and NIP-26-removal findings that motivate a stated policy.

---

## 1. Context

The audit sweep (anomaly register R2, R4) surfaced two release-discipline gaps:

- **Version drift.** README claimed `v3.0.0-rc11`, SECURITY listed rc7/rc6, and the
  relay served `"3.0.0"` in NIP-11 — three different versions for one codebase.
  Normalised to **`1.0.0-beta.2`** (`nip11.rs` now reads `env!("CARGO_PKG_VERSION")`
  so it can never drift again).
- **An API-breaking removal with no stated semver consequence.** R4 deleted the
  NIP-26 implementation + tests and the NIP-90 DVM module — the `!` commits removing
  `pub mod nip26` / `pub mod nip90`. The register flagged this as
  "**API-breaking for next publish → 1.0.0-beta.3**" but no policy document defined
  what "API-breaking" means for a beta line, what the next version should be, or how
  downstream consumers are protected.

The kit publishes to crates.io and is consumed downstream (notably by SHA-pinned
operator overlays), so it needs an explicit, written contract.

## 2. Decision

### 2.1 What counts as API-breaking

For the publishable `nostr-bbs-*` crates, a change is **API-breaking** if it alters
the public Rust surface in a way that can fail a downstream compile or change
observed behaviour of a stable item. Specifically:

- **Removing or renaming any `pub` item** — module, type, fn, trait, variant,
  field. The R4 removals of `pub mod nip26` and `pub mod nip90` are the canonical
  example: deleting a public module is breaking even if we believe it had no users,
  because crates.io semver is about the *contract*, not the observed call graph.
- Changing a public fn signature, a public trait's required methods, or a public
  type's layout in a way that breaks callers.
- Changing the **wire/protocol contract** a consumer relies on (e.g. the served
  NIP-11 shape, an admission rule, an HTTP route contract).

Non-breaking: adding new `pub` items, adding enum variants to `#[non_exhaustive]`
enums, internal refactors, doc changes, and additive feature-gated code that is
off by default.

### 2.2 Beta-line semantics

The kit is on a **`1.0.0-beta.N`** pre-release line. While on the beta line:

- The `1.0.0` **API is not yet frozen.** Breaking changes are permitted between
  beta increments — that is what a beta line is *for*. Each breaking change bumps
  the beta counter (`beta.2` → `beta.3`), it does **not** force `2.0.0`.
- Cargo treats `1.0.0-beta.N` pre-releases as **not** semver-compatible with each
  other by default: a dependant on `=1.0.0-beta.2` does not silently get `beta.3`.
  This is the safety property the beta line buys us — breaking moves cannot
  auto-upgrade a consumer.
- On `1.0.0` final, the surface freezes and normal semver applies (breaking →
  major).

### 2.3 The next publish

The next published version is **`1.0.0-beta.3`**, carrying the R4 API-breaking
removals (NIP-26, NIP-90) plus the R2 version-drift normalisation and the
ADR-094..101/104 additions. The beta counter increments because the change set is
API-breaking under §2.1; it stays on the `1.0.0-beta` line under §2.2.

### 2.4 Yank policy

`cargo yank` is reserved for **defect containment**, not history rewriting:

- **Yank** a published version when it is **broken or unsafe** to depend on — a
  security defect, a build-breaking packaging error, or a published-by-mistake
  artifact. Yanking prevents *new* dependants from selecting it; it does **not**
  delete it and does not break existing `Cargo.lock` pins.
- **Do not yank** merely because a newer version exists or to discourage use of an
  old API — that is what version selection is for.
- A yank is always accompanied by a CHANGELOG note stating the reason and the fixed
  version to move to.
- Yanks are not un-published; the crate content is immutable on crates.io by design.

### 2.5 Downstream-consumer contract

- **Operator overlays pin by SHA**, not by a crates.io version range. The git/SHA
  pin is the authoritative downstream coupling: a breaking kit change cannot reach
  an overlay until that overlay deliberately bumps the pinned SHA and adapts. This
  is the primary protection — the beta-line semver (§2.2) is a second line of
  defence for crates.io-range consumers.
- A breaking change therefore has a two-step propagation: publish `beta.N+1` →
  each SHA-pinned consumer bumps and adapts on its own
  schedule. The kit does **not** assume consumers track `HEAD`.
- Version sources of truth: `Cargo.toml` `version` is canonical; anything that
  *reports* a version (NIP-11, README badges, SECURITY) MUST derive from it
  (`env!("CARGO_PKG_VERSION")` where code can, a single documented bump checklist
  where it cannot) — R2 must not recur.

## 3. Consequences

- **Positive.** "API-breaking" is now defined, so the beta counter bumps for a
  stated reason. SHA-pinned downstreams are insulated from kit churn by
  construction. The version-drift class (R2) is structurally prevented at the one
  place code reports a version.
- **Negative / accepted.** The beta line means consumers using crates.io ranges
  must opt in to each beta explicitly (pre-releases don't auto-match) — slightly
  more friction, deliberately, until `1.0.0` freezes the surface.
- **Operational.** Every publish updates the CHANGELOG with the version and whether
  it is API-breaking; every yank states its reason and the fixed version.

## 4. Addendum — residue reconciliation (2026-07-03, closeout)

The §2.5 "everything that reports a version derives from it" rule was stated but
not fully enforced: the closeout audit found four version reports still hardcoded
after the beta.2 normalisation. These were reconciled on 2026-07-03:

- `relay-worker/src/lib.rs` `/health` — was `"3.0.0"`, now `env!("CARGO_PKG_VERSION")`.
- `pod-worker/src/lib.rs` `/health` and `pod-worker/src/remote_storage.rs`
  `/.well-known/solid` — were `"6.0.0"`, now `env!("CARGO_PKG_VERSION")`.
- `README.md` release badge and `SECURITY.md` supported-version table — the two
  markdown surfaces code cannot reach — bumped `beta.2` → `beta.3`. These stay on
  the **manual bump checklist** (§2.5, "a single documented bump checklist where
  it cannot"): update both in the same commit that bumps `Cargo.toml`.

The same sweep dropped the **phantom NIP-90 advertisement** (relay `/health`,
`nip11.rs` `supported_nips`, and the README NIP-coverage table). NIP-90's module
was removed in R4 (§2.3) and no DVM kinds are handled, so advertising 90 was a
false capability claim, not a semver concern. With these fixes the R2 drift class
is closed at every version-reporting surface, not just `nip11.rs`.
