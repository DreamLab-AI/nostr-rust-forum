# Changelog

All notable changes to this project will be documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project tracks the spec home at [VisionClaw monorepo](https://github.com/DreamLab-AI/VisionClaw)
(`docs/specs/` + `docs/adr/`) for cross-substrate normative decisions.

## [Unreleased]

## [Security Audit Sprint] - 2026-05-11

DreamLab ecosystem-wide security audit. 12 fixes applied to nostr-rust-forum
covering P0 critical, P1 high, P2 medium, and P3 housekeeping findings.

### Security

- **P0-01**: PRF salt is now server-derived in webauthn.rs, preventing
  client-controlled salt injection in passkey registration flows
- **P0-02**: Admin model checks both members and whitelist in relay auth.rs,
  closing a privilege-escalation path where non-whitelisted members could
  bypass admin gates
- **P0-03**: Replay DB binding corrected to REPLAY_DB in relay wrangler.toml;
  the previous binding name silently created a second empty D1 database,
  leaving the replay cache ineffective
- **R2-P0-01**: /pay/.cleanup endpoint now requires NIP-98 auth guard in
  payments.rs, preventing unauthenticated callers from triggering cleanup

### Fixed

- **P1-18**: Job settle/cancel operations are now atomic via
  UPDATE...WHERE in payments.rs, eliminating TOCTOU races between
  concurrent settle and cancel on the same job
- **P1-19**: Job IDs generated via CSPRNG (getrandom) in payments.rs,
  replacing the previous sequential/predictable scheme
- **P1-20**: Deterministic invite code fallback removed in invites.rs;
  all invite codes are now CSPRNG-generated with no weak fallback path
- **P2-01**: DID pubkey validated as 64-character lowercase hex in
  payments.rs, rejecting malformed did:nostr identifiers at the boundary
- **P2-02**: NIP-26 delegation handler returns 501 Not Implemented in
  delegation.rs instead of silently accepting unverified delegations
- **P2-03**: Admin cache uses 5-minute TTL in relay auth.rs, bounding
  stale-admin-list exposure after revocation
- **P3-02**: Job expiry column added to payments schema, with orphan
  recovery sweep and /pay/.cleanup endpoint for operator-initiated GC

### Removed

- **P3-01**: KvPaymentStore dead code removed from payments.rs; the KV
  backend was superseded by D1 but never cleaned up

## [3.0.0-rc6] -- 2026-05-11

Payments, security hardening, and upstream alignment.

### Added

- **HTTP 402 payments** (`/pay/` routes in pod-worker). Web Ledgers spec
  implementation: `.info`, `.balance`, `.deposit`, metered resource access,
  multi-chain TXO verification, `/.well-known/webledgers/webledgers.json`
  discovery. All identities are `did:nostr:<pubkey>` — users and agents
  are indistinguishable at the protocol level.
- **`Nip98Token.event_id`** field: canonical event ID (recomputed by
  `verify_event_strict`) carried through to replay caches. Eliminates the
  redundant `compute_event_id_from_header` re-parse.
- **Wrangler.toml KV bindings**: `ADMIN_KV`, `ADMIN_KV_RO`, `NIP98_REPLAY`
  provisioned across all 4 workers.
- **`PAY_ENABLED` / `PAY_COST_SATS`** env vars in pod-worker wrangler.toml.

### Fixed

- **NIP-98 URL matching** (JSS alignment): removed trailing-slash
  normalisation; exact match only, per JSS source of truth.
- **Quota overflow**: `check_quota` uses `checked_add()` to prevent
  arithmetic overflow on projected usage.
- **admins.rs KV cache write**: `.execute().await` was missing — the
  future was dropped without awaiting. Cache writes now persist.
- **Whitelist `update_cohorts`**: added 64-char hex validation on pubkey
  input (was only checking non-empty).
- **NIP-19 proptest relay generator**: simplified to avoid generating
  invalid IDN labels (`xn--` prefixes). All 13 proptests pass.

### Changed

- **solid-pod-rs**: upgraded to 0.4.0-alpha.7 (payments, LWS-CID, CID v1
  WebID terms, NIP-98 WebID elevation).
- **`d1_helpers`** extracted to `nostr-bbs-core` (shared by auth-worker
  and relay-worker). Gated on `cfg(target_arch = "wasm32")`.

## [3.0-rc1] -- 2026-05-07

Phase 2 kit-extraction import. Brings critical security fixes, the F26 upstream
canary crate, L1 reference-vector test scaffolds, and Phase-1 substrate scripts
across from the legacy `dreamlab-ai-website/community-forum-rs` fork (where
they were authored during the mega-sprint Phase 0 + Phase 1 windows).

### Fixed (Critical)

- **C1 -- NIP-44 v2 conversation-key interop bug** in `crates/nostr-core/src/nip44.rs`.
  The previous implementation chained `HKDF-Extract -> HKDF-Expand` and produced
  `HMAC(PRK, 0x01)` instead of the PRK itself, breaking interoperability with
  every reference NIP-44 v2 implementation. Replaced with direct
  `HMAC-SHA256(salt="nip44-v2", ikm=shared_x)`. Validated against
  `paulmillr/nip44` test vectors (`docs/specs/fixtures/nip44-v2.json` in
  VisionClaw monorepo). Refs: ADR-076 D5, mega-sprint Phase 0.

- **C5 -- NIP-42 AUTH challenge CSPRNG** in
  `crates/relay-worker/src/relay_do/session.rs`. Replaced
  `js_sys::Math::random()` (non-cryptographic PRNG) with `getrandom::getrandom`,
  which on the Cloudflare Workers runtime delegates to `crypto.getRandomValues`
  (a CSPRNG). Predictable challenges allow a network attacker to forge an AUTH
  response, so this is the entire security property of the handshake. Added
  `getrandom = { workspace = true }` to `crates/relay-worker/Cargo.toml`.
  Refs: ADR-082, mega-sprint Phase 0.

### Added

- **F26 -- `nostr-upstream-canary` crate** (`crates/nostr-upstream-canary/`).
  Smoke-tests the upstream `nostr` 0.44.2 crate (without `nostr-sdk`) on the
  forum's WASM/Cloudflare Workers build matrix. Three smokes: keypair
  round-trip, NIP-44 v2 conversation-key derivation against
  `paulmillr/nip44` vector 0, NIP-19 npub bech32 round-trip. PASS unblocks
  ADR-076 D5 module absorption (Shape A); FAIL records a Shape C
  patch-in-place fallback. Crate is `publish = false` and not linked into the
  forum binary. Refs: ADR-076 D5, PRD-009.

- **L1 -- reference-vector test scaffolds**
  (`crates/nostr-core/tests/upstream_vectors/`). Loader at `mod.rs` resolves
  fixtures from `tests/fixtures/` (or `VISIONCLAW_FIXTURE_ROOT` env var) and
  asserts metadata blocks. `all_fixtures.rs` wires one test per fixture across
  13 files: NIP-01/04/19/26/44-v2/59/98, BIP-340, RFC 8785, multibase, DID-Doc
  conformance, IS-envelope v1, mesh-federation. Tests skip cleanly when the
  fixture is absent so the bring-up window stays green. Run
  `scripts/sync-fixtures.sh` first to populate. Refs: ADR-082 D5.

- **Phase-1 substrate scripts**:
  - `scripts/sync-fixtures.sh` -- pulls cross-substrate fixtures from VisionClaw's
    `docs/specs/fixtures/` into `tests/fixtures/`, writes `CHECKSUM.txt` for CI
    drift detection. Supports `--verify` mode for CI gates and
    `VISIONCLAW_FIXTURES_PATH` for offline / local-monorepo dev.
  - `scripts/anti-drift-lint.sh` -- ADR-077 P3 anti-drift lint. Rejects
    DreamLab-only Schnorr verification suite identifiers
    (`NostrSchnorrKey2024`, `SchnorrSecp256k1VerificationKey2022`/`2025`/`2026`)
    in favour of the canonical `SchnorrSecp256k1VerificationKey2019`. Rejects
    hand-rolled DID-Document emitters outside `crates/pod-worker/src/did.rs`
    and `crates/nostr-core/`. Exit non-zero on drift.

### Changed

- **`Cargo.toml` workspace members** -- added `crates/nostr-upstream-canary` so
  the canary participates in `cargo check --workspace` runs.

### Notes

- This release does **not** include the full Sprint v9-v11 feature set authored
  in the legacy fork (NIP-98 replay store, profiles backfill, username
  reservations, mesh service-list, Tailwind CDN replacement, etc.). Those land
  incrementally in Phase 3+.
- Crate renaming to a `nostr-bbs-*` prefix and the new `nostr-bbs-config`,
  `nostr-bbs-mesh`, `nostr-bbs-setup-skill` crates remain deferred.
- The `admin-cli` crate is DreamLab-specific and stays in the legacy fork.

### Provenance

- Charter: RuVector key
  `project-state/mega-sprint-phase-2-kit-extraction-charter`.
- Final report: RuVector key
  `mega-sprint-2026-05-07/phase-2-kit-extraction-final-report`.
- Prior sprint reports: `mega-sprint-2026-05-07/phase-0-final-report`,
  `mega-sprint-2026-05-07/phase-1-final-report`.

## [2.0] -- 2026-04-06

Complete Rust rewrite (pre-existing kit baseline, see commit `ab4b403`).

[Unreleased]: https://github.com/DreamLab-AI/nostr-rust-forum/compare/v3.0-rc1...HEAD
[3.0-rc1]: https://github.com/DreamLab-AI/nostr-rust-forum/compare/v2.0...v3.0-rc1
[2.0]: https://github.com/DreamLab-AI/nostr-rust-forum/releases/tag/v2.0
