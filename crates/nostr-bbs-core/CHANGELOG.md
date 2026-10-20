# Changelog

All notable changes to `nostr-bbs-core` are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-beta.20] - 2026-10-20

### Added

- `gift_wrap_rumor_with_signer` and `gift_wrap_rumor_pair_with_signer`: wrap a caller-built
  unsigned rumor (any NIP-17 kind, with its own tags, so reactions, deletions, replies and
  `imeta` can travel) through the same ADR-2025 envelope as `gift_wrap_with_signer`. The rumor's
  `pubkey` must equal the signer's key, enforced at runtime. Callers remain responsible for the
  rumor's `p` and `e` tags; the forum client restricts `p` to {recipient, self}.

## [1.0.0-beta.19] - 2026-10-20

### Added

- `gift_wrap::RumorKind` (`Chat` 14, `Reaction` 7, `Deletion` 5, `File` 15) and
  `UnwrappedGift::rumor_kind()`.

### Changed

- `unwrap_gift` and `unwrap_gift_with_signer` accept the four NIP-17 rumor kinds
  instead of only kind 14 (ADR-2027). Any other kind is still refused with the
  same `InvalidKind { expected: 14, .. }` error, which never echoes decrypted
  content. `unwrap_gift_kind` / `unwrap_gift_with_signer_kind` still match
  exactly one caller-chosen kind. Callers that treated "unwrap succeeded" as
  "this is a chat message" must now check `rumor_kind()`.

## [1.0.0-beta.18] - 2026-10-19

### Licence (applies from 1.0.0-beta.18, merged 2026-10-20)

### Changed

- **Licence changed to `MIT OR Apache-2.0`** from `1.0.0-beta.18` onward. Every
  line of this crate was written by DreamLab AI and its agents (94 commits,
  no outside contributor; provenance checked 2026-10-12), so the change is
  the rights holder's. Versions `<= 1.0.0-beta.17` remain `AGPL-3.0-only` as
  published (beta.16 and beta.17 shipped under AGPL before this merge); nothing already released changes licence. The rest of the
  `nostr-rust-forum` workspace (workers, clients, server) stays AGPL-3.0-only.
- **`did` module is now behind an off-by-default `did` feature.** It wraps
  `solid_pod_rs::did_nostr_types`, and `solid-pod-rs` is AGPL-3.0-only; a
  build with `did` enabled is therefore AGPL as a combined work and must be
  treated as such. Default features pull no copyleft dependency. In-workspace
  dependants (`bbs-client`, `pod-worker`, `auth-worker`) enable the feature
  explicitly and are unchanged in behaviour.

### Why

- Lets permissive consumers (the Ontomark toolchain's governance verbs,
  Agentbox, the Obsidian plugin) depend on the Nostr primitives directly
  without inheriting AGPL, while keeping the DID path and the forum itself
  copyleft.


### Changed

- **`unwrap_gift*` and `unwrap_gift_with_signer*` verify the outer kind-1059 before decrypting**
  (ADR-2025). A wrap whose own id or signature does not verify is refused as the new
  `GiftWrapError::WrapVerification` / `SignerGiftWrapError::WrapVerification`. The wrap key is a
  throwaway, so this is a shape check; seal verification and the `rumor.pubkey == seal.pubkey`
  binding are unchanged. Every wrap a relay running `verify_event_strict` on ingest has stored
  already passes. **API note:** both enums gain a variant and are not `#[non_exhaustive]`, so an
  exhaustive `match` outside this workspace needs a new arm.
- **Unwrap errors are fixed strings.** `Decryption`, `ParseError` and `Serialization` payloads
  name the layer (`gift wrap layer`, `seal layer`, `seal JSON malformed`, `rumor JSON malformed`,
  `NIP-04 layer`) instead of carrying serde's or the cipher's message; serde quotes offending values, so
  the old text could echo decrypted bytes into a caller's log. `Signer` still carries the
  backend's text. A rumor carrying a `sig` is still accepted and the field ignored, on purpose:
  see ADR-2025 for why refusing it would risk stored DMs.

## [1.0.0-beta.17] - 2026-10-18

### Changed

- **`solid-pod-rs` is a caret range, now `0.5.0-alpha.14`.** beta.16 pinned
  `=0.5.0-alpha.13`, so a consumer could not take a newer solid-pod-rs alpha,
  including a security release, without a new nostr-bbs-core. The range lets
  the consumer's `cargo update` move it (estate register ER-35). alpha.14
  carries the MCP skill pay-per-read fix, hardened git spawns, Solid-OIDC
  `aud`/`kid` binding and case-folded path guards.

## [1.0.0-beta.4] - 2026-07-03 (closeout — did-doc canonicalisation gate)

### Changed

- **DID:nostr conformance re-canonicalised to ADR-125.** The
  `did-doc-conformance.json` fixture and its JSON Schema were replaced with the
  byte-identical canonical Multikey document, matching the upstream
  `solid-pod-rs` CID v1.0 migration. The superseded 2019-suite / `publicKeyHex`
  vectors are dropped and the `did_doc_load_and_validate` reference-vector gate
  minimum is aligned from 9 to 7 vectors, so the gate now matches the
  canonical fixture rather than failing on the retired vectors. Fixture
  checksums were regenerated and the sync manifest repointed.
- **`solid-pod-rs` dependency advanced `0.5.0-alpha.3` -> `0.5.0-alpha.4`**
  (workspace pin) — the closeout security release. The `core`-feature surface
  consumed by this crate (`did_nostr_types`, WebID/DID rendering) is unchanged
  between the two upstream versions; the bump carries the hardened upstream
  through to the forum.

### Notes

- Publishing `1.0.0-beta.4` requires `solid-pod-rs 0.5.0-alpha.4` to be live on
  crates.io first (it is published as part of the same closeout release train).
