# Changelog

All notable changes to `nostr-bbs-core` are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
