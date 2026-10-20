# Changelog

All notable changes to `nostr-bbs-core` are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-beta.18] - 2026-10-19

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
