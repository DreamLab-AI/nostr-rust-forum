---
id: ADR-2003
title: Derive purpose-scoped subkeys with raw HMAC-SHA256, not HKDF, for byte-for-byte JS parity
date: 2026-08-31
decision_status: accepted
implementation_status: complete
activation_status: live
supersedes: []
superseded_by: []
verified_commit: 7795af5
owner: jjohare
review_trigger: any change to the agentbox JS mirror-key derivation, or a move to per-subkey compromise isolation
repo: nostr-rust-forum
domain: IDENTITY-keys-and-trust.md
lineage: distils legacy ADR-094 (deterministic subkey derivation) and the ADR-100 key-lifecycle rotation model
---

# ADR-2003 — Derive purpose-scoped subkeys with raw HMAC-SHA256, not HKDF, for byte-for-byte JS parity

## External review qualification — 2026-11-02

The [dated source reconciliation](external-review-2026-11-02.md) records the current
implementation evidence, open acceptance gaps and limits of the external review.
It supplements this decision without changing its adoption or activation status.

## Context

`derive_subkey(root, tag)` produces a purpose-scoped child secret shared across the
Rust forum and agentbox's JavaScript. HKDF-SHA256 (Extract+Expand) is the textbook
choice and is already used by the sibling `derive_from_prf`. But agentbox's mirror-key
derivation is a single `crypto.createHmac('sha256', root).update(tag).digest()`.

## Decision

`derive_subkey` is a single raw **HMAC-SHA-256** keyed by the root's 32 secret bytes with
the UTF-8 tag as the message — deliberately **not** HKDF, with no Extract/Expand step —
so the Rust output equals the JS output byte-for-byte for a given `(root, tag)`. This
cross-stack equality is the contract; the construction may not be "upgraded" to HKDF
without forking every derived identity on both stacks. Rotation is by tag suffix
(`-v1`→`-v2`), and the accepted, documented cost is that a derived subkey is
**recoverable from the root** — domain separation, not compromise isolation.

## Consequences

- Forecloses HKDF and any keyed-hash variant: the "more correct" KDF would silently
  diverge from the JS mirror, breaking the shared-identity guarantee.
- A leaked root exposes every child; no design may assume a compromised subkey is
  contained — root rotation is the only boundary (ties Invariant 6).
- Binds a Rust security primitive to an external JS implementation's exact bytes, pinned
  by a known-answer JS-parity test that must never be deleted.

## Verification

- Raw HMAC construction, explicitly "not HKDF": `crates/nostr-bbs-core/src/keys.rs:251-256`.
- Root-recoverability disclaimer is load-bearing doc: `keys.rs:238-243`.
- Distinct from the HKDF `derive_from_prf`: `keys.rs:196-205`.
- JS-parity known-answer vector guards it: `keys.rs:478-486`.
- Established at `verified_commit` 7795af5 (`git rev-parse --short HEAD`).

## Closeout extension — 2026-09-04

Work packages: CP-04. Accountable owner: the existing owner above, with forum release/identity maintainers for cross-service acceptance. Historical verification and activation declarations are preserved; this review does not re-certify a live deployment.

Source retains raw HMAC-SHA256 over the UTF-8 tag. The native keys suite passes 22 tests, including the known-answer JS-parity fixture; this is not an execution of the current agentbox JS implementation.

**Acceptance condition:** Run both current implementations over a shared versioned vector set, including tag rotation and invalid input handling. Bind identity migration and revocation expectations to the consumer release manifest; retain the root-recoverability limitation.

Dependencies: CP-01 release identity and the relevant identity, governance and recovery journeys. Reopen when the governed source, dependency, deployment profile or consumer contract changes. See the [estate forum review](../../../VisionFlow/docs/estate-review/forum-decisions.md) and [current source/test receipt](../../../VisionFlow/docs/estate-review/evidence/forum-closeout-snapshot.json).

## Acceptance progress — 2026-09-05

**Implemented.** A versioned, shared vector set now executes against both stacks.
`crates/nostr-bbs-core/tests/vectors/identity-subkey-vectors.v1.json` pins `version: 1`, the algorithm id
`agentbox-subkey-hmac-sha256-v1`, the curve order, and an explicit `not_hkdf` clause. It is consumed by a
Rust runner (`crates/nostr-bbs-core/tests/identity_subkey_vectors.rs`) and a Node 22 runner
(`scripts/identity-vector-parity.mjs`, built-in `crypto` only, no new dependencies).

Thirteen vectors plus three invalid roots. Coverage: the canonical live tags (`agentbox-mirror-v1`,
`agentbox-gateway-v1`, `agentbox-agent-v1`); rotation `-v1` → `-v2` for two tags, asserting the same root
yields a distinct child; empty, single-byte and 519-byte tags (past the SHA-256 block size); non-ASCII tags
spanning two-, three- and four-byte UTF-8; a combining-accent tag, proving neither side NFC-normalises; a
whitespace-significant tag, proving neither side trims; one tag under two roots; and a root at n−1. The
invalid roots — all-zero, all-0xff, and exactly the curve order — must be rejected. Each vector also carries
`tag_utf8_bytes`, asserted on both sides, so a re-encoding editor cannot silently corrupt a tag.

Both runners additionally assert the construction is **not** HKDF: each computes HKDF-Expand over the same
inputs and requires it to differ, so the "upgrade" this ADR forecloses fails immediately on both stacks. The
existing inline known-answer test in `keys.rs` is untouched, as this ADR requires; the fixture's
`canonical-mirror-v1` vector reproduces its known answer.

**JS provenance.** The agentbox derivation is *mirrored, not imported*, because none of the three call sites
exports it: `config/hooks/nostr-live-mirror.cjs` keeps `deriveChildKey()` module-private, and both
`config/nostr-gateway/nostr-send.cjs` and `gateway.cjs` execute side effects (a `process.exit`, a socket
bind) at require time. The Node runner therefore re-executes the identical expression **and pins the
sources**: it reads each agentbox file, records its sha256, asserts the exact HMAC expression is still
present and that no `hkdf` appears. If agentbox changes its derivation the runner fails rather than passing
against a stale mirror.

**Tests and results.** `cargo test -p nostr-bbs-core` — 474 passed, 0 failed, 2 pre-existing ignores; the
new target alone is 5 passed. `node scripts/identity-vector-parity.mjs` — exit 0, 13/13 vectors, 3/3 invalid
roots rejected, 18/18 checks. Negative verification was performed and reverted: corrupting one expected value
fails the Rust runner with the vector named and exits the Node runner non-zero; deleting the fixture panics
the Rust runner rather than skipping.

**Browser receipts.** None; this is a library primitive with no browser surface.

**Remaining.** The agentbox source hashes are checked only when a runner is invoked, so wiring
`node scripts/identity-vector-parity.mjs` into CI is what makes the drift guard live. A genuine asymmetry
surfaced: Rust validates the derived child as a secp256k1 scalar via `SecretKey::from_bytes`, the JS side
does not, so agentbox would accept an out-of-range child in production. The runner adds that check itself so
the vectors cover it, but the production asymmetry stands and is worth an explicit decision.

**Governed paths changed:** `crates/nostr-bbs-core/tests/vectors/identity-subkey-vectors.v1.json` (new),
`crates/nostr-bbs-core/tests/identity_subkey_vectors.rs` (new), `scripts/identity-vector-parity.mjs` (new).
No change to `keys.rs` — the construction is unaltered. Receipt:
[`docs/estate-closeout/2026-09-05/adr-2003-vector-parity.json`](../estate-closeout/2026-09-05/adr-2003-vector-parity.json).
