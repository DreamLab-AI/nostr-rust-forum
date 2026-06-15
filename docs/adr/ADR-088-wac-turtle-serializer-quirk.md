# ADR-088 — WAC Turtle serializer bare-path IRI quirk

- **Status:** Draft
- **Date:** 2026-05-16
- **Owners:** Cross-stack — NRF consumer (`nostr-bbs-pod-worker::acl`) and
  upstream `solid-pod-rs::wac::serializer`. Authored by `nrf-aligner`
  following Phase 1 implementation findings reported by `solid-porter`;
  awaiting a champion before flipping to Proposed.
- **Related:** ADR-086 (NIP-05 pod federation; mentions ACL adjacency),
  ADR-076 (Phase 4 absorption; established the WAC re-export shim in
  `nostr-bbs-pod-worker::acl`), `docs/consumer-surface-map.md`.

## 1. Context

While implementing `provision-keys` in `solid-pod-rs` v0.4.0-alpha.11,
`solid-porter` discovered a latent quirk in
`solid_pod_rs::wac::serializer::emit_pairs`: it only wraps strings prefixed
with `http` in `<>` IRI delimiters. Bare-path IRIs such as
`/private/privkey.jsonld` are emitted without delimiters, which means a
Turtle round-trip (`serialize → parse`) silently corrupts the value (the
parser reads it as a literal, not an IRI).

Solid-porter's workaround upstream: emit the ACL for the privkey.jsonld
file as JSON-LD instead of Turtle. The bug remains latent in
`emit_pairs` for any caller that does want Turtle output.

### Why this is currently fine for NRF

The kit's WAC consumer surface (per `docs/consumer-surface-map.md`) is:

- `nostr-bbs-pod-worker/src/acl.rs:22` — re-exports `method_to_mode`,
  `wac_allow_header`, `AccessMode`, `AclDocument` from
  `solid_pod_rs::wac`.
- `nostr-bbs-pod-worker/src/acl.rs:45` — calls
  `solid_pod_rs::wac::evaluate_access` (in-memory `AclDocument`).
- `nostr-bbs-pod-worker/src/acl.rs:181` — test-only use of `mode_name`,
  `AclAuthorization`, `IdOrIds`, `IdRef`.

None of these touch `wac::serializer`. The pod-worker writes ACL bytes
to R2/KV directly without going through a serializer, and access checks
operate on the in-memory `AclDocument` struct. The Turtle parser path is
also unreached today.

The quirk therefore has **no live impact** on the kit. The risk is
forward-looking: if a future change has the kit round-trip ACL through
`serialize_turtle_acl → parse_turtle_acl` (e.g. caching ACL bytes in KV
then reloading them for evaluation), bare-path IRIs would silently
corrupt.

## 2. Decision (deferred)

This ADR enumerates options without picking one. Status: Draft.

### Option (a) — Upstream fix in `wac::serializer::emit_pairs`

Wrap any IRI-typed value in `<>` regardless of prefix. Add upstream test
cases for bare-path IRIs (`/private/privkey.jsonld`,
`./relative/path.ttl`, etc.) round-tripping through serialize/parse.

Cost: small, well-bounded upstream PR. Benefits every Turtle-emitting
consumer.

### Option (b) — NRF: restrict to JSON-LD ACL bodies

Document the constraint formally in NRF: ACL bodies in
`nostr-bbs-pod-worker` use JSON-LD framing only. The kit's existing R2/KV
write path already does this de facto; making it policy prevents future
contributors from accidentally introducing a Turtle round-trip.

Cost: documentation + a guard in the WAC re-export shim doc-comments. No
upstream coordination.

### Option (c) — Defensive unit test in `nostr-bbs-pod-worker::acl`

Add a unit test asserting that the pod-worker does not invoke any
`wac::serializer` function on a code path under test. The test acts as a
canary — if a future PR adds a Turtle round-trip, the assertion fails
loud.

Cost: ~15 lines of test code. Independent of upstream.

## 3. Recommendation

**Option (a) upstream fix + Option (c) defensive test in the kit.** Both
are tiny. Option (a) eliminates the root cause for every consumer;
Option (c) gives the kit a local canary independent of upstream release
cadence. Option (b) is implicit once (a) lands (no constraint needed if
Turtle round-trips work).

Status flips to Proposed when (a) is championed upstream or (c) is
scheduled into a kit sprint.

## 4. Out of scope

- Picking the option.
- Drafting the upstream fix.
- Auditing other `wac::serializer` callers in solid-pod-rs (out of NRF's
  concern; upstream maintainers' call).

## 5. Migration / impact

None today. The quirk has zero live impact on the kit. ADR exists to
prevent the knowledge from evaporating into commit-message archaeology.

## 6. References

- ADR-076 (Phase 4 absorption; WAC re-export shim provenance).
- `docs/consumer-surface-map.md` — section "Current consumer surface" rows
  for `acl.rs:22`, `acl.rs:45`, `acl.rs:181`.
- Solid-porter's task #4 implementation notes (2026-05-16, alpha.11
  publish): "the `provision-keys`-written ACL file is JSON-LD (not
  Turtle) because of a latent bug in `wac::serializer::emit_pairs`."
- Upstream: https://github.com/melvincarvalho/solid-pod-rs commit
  `d8a1c81` (v0.4.0-alpha.11).
