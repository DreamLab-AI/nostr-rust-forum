---
id: ADR-2004
title: Gate revocable device keys default-off behind exact `DEVICE_KEYS_ENABLED == "true"`, checked in both workers
date: 2026-08-31
decision_status: accepted
implementation_status: complete
activation_status: live
supersedes: []
superseded_by: []
verified_commit: 7795af5
owner: jjohare
review_trigger: DEVICE_KEYS_ENABLED flipped on in a real deployment, or ADR-099 phase-2 multi-device DM scheduled
repo: nostr-rust-forum
domain: IDENTITY-keys-and-trust.md
lineage: distils legacy ADR-099 (revocable device keys) and ADR-100 (key lifecycle); relies on ADR-2003's derivation
---

# ADR-2004 — Gate revocable device keys default-off behind exact `DEVICE_KEYS_ENABLED == "true"`, checked in both workers

## External review qualification — 2026-11-02

The [dated source reconciliation](external-review-2026-11-02.md) records the current
implementation evidence, open acceptance gaps and limits of the external review.
It supplements this decision without changing its adoption or activation status.

## Producer repair — 2026-11-03

The [external-review repair receipt](external-fixes-2026-11-03.md) records the
implemented ceremony, authority, concurrency and consumer-contract changes relevant
to this decision, with their migration and deployment limits. These changes do not
promote the whole decision's implementation or activation status.

## Context

Revocable device keys let a device onboard without the master key, and revocation must
be honoured at NIP-42 AUTH time. This adds an attribution-rewriting surface (device→owner
remap) to the hot admission path. The registry could live in the auth worker's D1 next to
NIP-05 reservations; the gate could be a truthy check; it could default on.

## Decision

The whole feature is **default-off** behind a single Worker var `DEVICE_KEYS_ENABLED`,
enabled only on the **exact** string `"true"` (any unset/empty/other value → off), and the
identical exact-match gate is duplicated **independently in both the auth worker and the
relay worker** rather than shared. The `device_keys` row lives in the **relay worker's
D1** (`RELAY_DB`), not the auth worker's, so the relay DO reads the registry at AUTH with
no cross-worker round-trip. With the gate off, a known device→owner mapping is ignored and
the author key is used as-is.

## Consequences

- Forecloses "enabled by default" and any loose/truthy parse: a looser check widens the
  auth surface (Invariant 3); a default-on rollout would rewrite attribution silently.
- The device story (ADR-099/100) is dormant in every default deployment — revocation has
  no effect until the var is set, which is the intended safe posture.
- Duplicated gate logic in two crates must be kept in lockstep; a fix to one must be
  mirrored, the accepted cost of not sharing a helper across worker boundaries.
- Splitting the registry into `RELAY_DB` couples device-key schema ownership to the relay
  worker, away from the auth worker that mints identities.

## Verification

- Exact `"true"`, default-off, auth worker: `crates/nostr-bbs-auth-worker/src/devices.rs:88-96`.
- Independent gate, relay worker: `crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:1626-1665`;
  off-path ignores mapping at `nip_handlers.rs:531,3010`.
- Row in relay D1 with `revoked` flag: `devices.rs:81-110`.
- Established at `verified_commit` 7795af5 (`git rev-parse --short HEAD`).

## Closeout extension — 2026-09-04

Work packages: CP-04/08. Accountable owner: the existing owner above, with forum release/identity maintainers for cross-service acceptance. Historical verification and activation declarations are preserved; this review does not re-certify a live deployment.

Both inspected workers independently require the exact string true. Default-off policy is implemented; that fact does not establish a deployed device registry or revocation journey.

**Acceptance condition:** Exercise unset/false/TRUE/true and mismatched worker configuration, active/revoked/missing mappings, reconnect and cached sessions. Record owner attribution and denial after revocation in the actual deployment profile.

Dependencies: CP-01 release identity and the relevant identity, governance and recovery journeys. Reopen when the governed source, dependency, deployment profile or consumer contract changes. See the [estate forum review](../../../VisionFlow/docs/estate-review/forum-decisions.md) and [current source/test receipt](../../../VisionFlow/docs/estate-review/evidence/forum-closeout-snapshot.json).

## Acceptance progress — 2026-09-05

**Implemented.** The gate is `DEVICE_KEYS_ENABLED`, read independently by the auth worker
(`crates/nostr-bbs-auth-worker/src/devices.rs`, guarding device register/list/revoke) and the relay worker
(`crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs`, guarding the device→owner rebind at NIP-42
AUTH and the write-gate allowlist check). Both now delegate to one shared predicate in
`crates/nostr-bbs-core/src/feature_gate.rs`. The two gate *checks* stay independent — each worker reads its
own binding, with no cross-worker call, as this ADR requires — but the *rule* is shared, so "kept in
lockstep" becomes a compile-time fact rather than a convention. There is no behavioural change: both already
implemented exact-match `== "true"`.

A real defect was found and fixed. The auth worker's only gate test,
`devices.rs::tests::gate_default_off_semantics`, asserted against a locally re-declared closure
(`let enables = |v: &str| v == "true";`) rather than the production code. It tested the closure. It would
have passed unchanged against a truthy-on-any-value parse or a default-on gate — so the auth half of the
gate was, in effect, untested. It now calls the production seam and covers the unset case the closure could
not express.

**Variant table** (24 asserted in all three crates). `"true"` → enabled. Everything else → disabled: unset,
`""`, `false`, `False`, `FALSE`, `TRUE`, `True`, `tRuE`, `0`, `1`, `yes`, `no`, `on`, `off`, `" true"`,
`"true "`, `"\ttrue\n"`, `"\"true\""`, `true1`, `truthy`, `enabled`, `not-a-bool`. Note that **`"TRUE"` is
off**: this ADR's Decision specifies the exact string `"true"` and explicitly forecloses a loose or truthy
parse, so exact match was implemented in preference to the case-insensitive reading.

**Mismatched-worker behaviour.** Auth on / relay off → `AuthOnlyFailsClosed`: registration and revocation are
live, but the relay ignores the registry, so a registered device resolves to itself, is not whitelisted, and
is denied by the write gate — it **fails closed**. Relay on / auth off → `RelayOnlyUnrevocable`: existing
mappings are honoured and attribution rewriting is live, while register, list **and revoke** all 404, so an
existing mapping cannot be withdrawn through the API. That asymmetry **fails open on revocation** and is
precisely the hazard this ADR's lockstep requirement exists to prevent; it is now named and asserted rather
than latent. `"true"` versus `"TRUE"` collapses to the fail-closed posture.

**Tests and results.** All exit 0: `cargo test -p nostr-bbs-core --lib` 345 passed (8 gate tests);
`cargo test -p nostr-bbs-core --doc feature_gate` 1 passed; `cargo test -p nostr-bbs-auth-worker` 215 passed
(7 gate tests); `cargo test -p nostr-bbs-relay-worker --features test-exports --test device_gate_tests` 10
passed. `cargo clippy` across the three crates raised no new warnings. Active, revoked and missing mapping
resolution through `effective_principal` is covered.

**Browser receipts.** None. The forum client's device UI is gated on `window.__ENV__`, not a Worker var, and
is outside this decision's scope.

**Remaining.** The client parses the same flag name loosely (trim, lowercase, accepts `"1"` or a JS
boolean), so `"TRUE"` or `"1"` would show device UI that both workers 404 — a cosmetic divergence, left
unfixed and recorded here. The deployment half of the acceptance condition — reconnect, cached sessions, real
D1 rows, denial after revocation in a live profile — remains unexercised; nothing here re-certifies a
deployment.

**Governed paths changed:** `crates/nostr-bbs-core/src/feature_gate.rs` (new),
`crates/nostr-bbs-core/src/lib.rs`, `crates/nostr-bbs-auth-worker/src/devices.rs`,
`crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs`,
`crates/nostr-bbs-relay-worker/src/relay_do/mod.rs`,
`crates/nostr-bbs-relay-worker/tests/device_gate_tests.rs` (new). Receipt:
[`docs/estate-closeout/2026-09-05/adr-2004-device-gate.json`](../estate-closeout/2026-09-05/adr-2004-device-gate.json).

## Source qualification — 2026-09-07

The exact-string, default-off contract and independent worker enforcement remain supported. The Decision's literal “rather than shared” describes the older implementation, not the current helper structure: `crates/nostr-bbs-auth-worker/src/devices.rs:36,91-104` and `crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:14,1649-1663` independently obtain their worker setting and call the common `core_device_keys_enabled` predicate from `nostr-bbs-core/src/feature_gate.rs`. Sharing that pure predicate does not remove either worker's gate.

The 2026-09-05 acceptance progress already records this extraction. This qualification makes the current decision reading explicit: one exact-value policy, enforced at both entrypoints. Client loose parsing, live revocation/reconnect, cached session and deployment acceptance remain distinct and unclosed; no activation status is changed. The [2026-09-07 audit](../../../VisionFlow/docs/estate-review/2026-09-07-federation-audit.md) records the source identity and native-test scope.
