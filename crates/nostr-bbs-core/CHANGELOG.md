# Changelog

All notable changes to `nostr-bbs-core` are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-beta.16] - 2026-10-12 (licence: MIT OR Apache-2.0)

### Changed

- **Licence changed to `MIT OR Apache-2.0`** from this version onward. Every
  line of this crate was written by DreamLab AI and its agents (94 commits,
  no outside contributor; provenance checked 2026-10-12), so the change is
  the rights holder's. Versions `<= 1.0.0-beta.15` remain `AGPL-3.0-only` as
  published; nothing already released changes licence. The rest of the
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
