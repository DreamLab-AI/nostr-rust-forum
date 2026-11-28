---
id: ADR-2037
title: Pin an existing section to a zone from zone config
date: 2026-11-28
decision_status: accepted
implementation_status: complete
activation_status: staged
supersedes: []
superseded_by: []
verified_commit: branch feat/zone-channel-pin (WP1 a2773ae and 8892963, WP2 642445e, WP3 d354a6d, WP4 ef7ce23, WP5 505fda9), built on main 416534e
verified_paths: [crates/nostr-bbs-relay-worker/src/zone_config.rs, crates/nostr-bbs-relay-worker/src/trust.rs, crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs, crates/nostr-bbs-relay-worker/src/profile_stats.rs, crates/nostr-bbs-relay-worker/src/triage.rs, crates/nostr-bbs-config/src/schema.rs, crates/nostr-bbs-config/src/validate.rs, crates/nostr-bbs-config/tests/zone_projection.rs, crates/nostr-bbs-client-core/src/stores/zones.rs, crates/nostr-bbs-client-core/src/stores/channels.rs, crates/nostr-bbs-client-core/src/zone_crypto/store.rs, crates/nostr-bbs-forum-client/src/pages/admin.rs, crates/nostr-bbs-forum-client/src/admin/mod.rs, crates/nostr-bbs-forum-client/src/pages/channel.rs, crates/nostr-bbs-forum-client/src/pages/category.rs, crates/nostr-bbs-search-build/src/harvest.rs, forum.example.toml]
owner: jjohare
review_trigger: the first deployment that configures a pin; any new reader of channel_zones or of the relay's channel→zone memo; any new place a client derives a channel's zone from the kind-40 section tag rather than ChannelMeta::section
repo: nostr-rust-forum
domain: BASELINE-architecture.md
evidence_class: source+test
acceptance_boundary: Established by unit and integration tests on the branch (relay pin resolution including D1 errors and double pins, read and write decisions for a pinned channel by viewer class, the foreign-zk refusal, profile stats and triage overlays; config validation and byte-identical ZONE_CONFIG projections from fixtures captured before the change; client effective section, cache healing on pin removal and from pre-change caches, key choice, the empty-cohort membership rule, bind refusal; search-build skip and exclusion), plus cargo fmt, clippy -D warnings, the wasm32 workspace check, the workspace test suite, rustdoc -D warnings and the ADR checks. Not established - behaviour against a deployed relay, D1 or Durable Object (including whether a redeploy evicts DO memory, which the design no longer depends on), in a browser, in the BBS, or with an old client build; those are rollout checks.
---

# ADR-2037 — Pin an existing section to a zone from zone config

## Context

A section is a kind-40 channel. The relay decides its zone from the D1 `channel_zones` row, written only by `POST /api/admin/channel-zone`; the clients decide it from the signed kind-40 `section` tag. An operator who wants an existing section to become "admin eyes only" has no clean move: re-signing the kind-40 makes a new channel and strands the posts; rebinding the D1 row is invisible to clients, which keep choosing the old zone's key, and the admin "Bind to zone" button would bind it back. A zone (ADR-2016) is already the unit of read gate, write gate, visibility and encryption key, so a hidden, encrypted zone with an admin-only cohort is exactly "admin eyes only"; what was missing is a way to move a channel into one without rewriting stored data.

## Decision

1. **A zone may pin channels.** `[[zones]] channels = [<kind-40 id>, …]` (64-char lowercase hex). It is projected into `ZONE_CONFIG`, which the relay and both clients already read, and omitted from the projection when empty (`skip_serializing_if`), so a config without pins projects byte-for-byte as before (`nostr-bbs-config/tests/zone_projection.rs`, fixtures captured before the change). Validation refuses a malformed id, a channel listed twice, a channel pinned by two zones, and a pinning zone whose id is `<other zone id>-…` (`validate.rs:456`), because client media routing takes the first prefix match.
2. **The relay consults the pin before D1, everywhere.** `ZoneConfig::pinned_zone` (`zone_config.rs:171`) returns `Unpinned`, `Pinned(zone)` or `Conflict`, comparing ids case-insensitively and skipping entries that are not 64 hex digits. `trust::resolve_channel_zone` (`trust.rs:595`) answers a pinned channel without calling the D1 lookup, so a pinned channel resolves while D1 is down; a `Conflict` is a `ZoneLookupError` (reads withheld from everyone, writes refused). `get_channel_zone` and `cached_channel_zone` (`relay_do/nip_handlers.rs:2858`, pin checked ahead of both 60 s memos, from the `ZoneConfig` snapshot the caller already holds) go through it, and every gate resolves through `cached_channel_zone`: the kind-42 write gate and its ciphertext check, the reference-kind gates, REQ, COUNT, live broadcast, push fan-out and kind-40/41 visibility. The two direct SQL readers outside that path apply the pin themselves: `/api/profile-stats` (`profile_stats.rs:366`, D1 asked only about unpinned channels) and the Jev triage candidate query (`triage.rs:207`). A kind-42 into a pinned channel whose `zk` names another zone is refused (`zone_config.rs:322`), so a client that does not know the pin cannot store old-zone ciphertext even when the pinned zone is unencrypted.
3. **Clients route a pinned channel by its pinned zone.** `ChannelMeta.section_tag` holds the raw signed tag; `ChannelMeta.section` is `zones::effective_section` (`client-core/src/stores/zones.rs:347`): the pinning zone's id, used verbatim so it resolves by exact match, unless the tag already names that zone. It is set at both kind-40 ingest sites and recomputed on every cache load (`heal_cached_sections`, `channels.rs:73`), and the cache stores the raw tag in `section`, so caches from before the field, a removed pin and an older build all route correctly. Every resolver (key choice, navigation, media target, search, BBS) reads `ChannelMeta::section` and follows with no change of its own. The admin rename modal still mirrors the raw tag onto kind-41.
4. **A pinned channel is never bound in D1.** "Bind to zone" and bind-on-create decide through `zones::bind_zone_for`, which returns nothing for a pinned channel; the admin page shows the pin instead. A row written while pinned would outlive the pin.
5. **Clients follow the relay's empty-cohort rule.** `Zone::is_member` (`zones.rs:173`) now treats empty `required_cohorts` as open only on a `Public` zone, so an admin-only zone with no cohort no longer shows as an open tile. Every caller already ORs with `Public` visibility or admin, or pre-filters non-empty cohorts; no zone with cohorts, and no public zone, changes.
6. **Sealed search keeps pinned channels out of other zones' indexes.** `nostr-bbs-search-build --zone-config <file>` skips posts whose channel is pinned to another zone and excludes their already-indexed rows (`harvest.rs:648`).

No new cryptography, no change to stored event formats, no D1 schema or data change, no new endpoint.

## Consequences

**What a pin protects.** Relay reads of the channel, including its kind-40/41 metadata when the pinned zone is hidden, its existence in profile stats, live delivery and push; and decryption of everything posted after the move, because clients encrypt new posts to the pinned zone's key, which members of the old zone never receive.

**What it does not protect.**
- History already synced or decryptable under the old zone's key stays so: members who fetched the channel's posts before the move keep their copies and the key that opens them, and the posts remain stored under the old zone's key (an export of D1 or a forwarded copy is readable by any holder of that key). Re-sealing history would rewrite data and still miss synced copies; it is not done.
- The zone config, including the pinned channel id and the new zone's existence, is public: it ships in the page source.
- Images already uploaded stay under the old zone's media path and readable to its members; only new uploads go to the pinned zone.
- Kind-42 posts e-tagged by a slug rather than the channel id (pre-id legacy) were never zone-gated by the relay, pin or not.
- Sealed-search rows already in an old zone's index leave it only after a reconcile (`update --since 0`) or a full rebuild run with `--zone-config`.

**Behaviour with old builds.** An old relay ignores `channels`: the pin silently does nothing, so the deployed relay must be checked to be at or after this change before a pin is relied on. An old client against a new relay: a member of the old zone gets nothing from the relay for the channel (definition, posts, counts), drops the cached channel on its next authenticated EOSE, and has every post refused (no write access to the pinned zone); an admin still reads, decrypts old posts with the old key and new posts if it holds the pinned zone's key, but every post it writes is encrypted to the old zone and refused (`zk` mismatch), and its "Bind to zone" would write a D1 row the pin overrides. Nothing leaks; old clients fail closed.

**Costs.** Several channels pinned to one zone share one section card on the forum index (they all route by the zone id). A pinned channel's zone cannot be shown nested inside its old zone's tile. A channel lookup scans the zones' pin lists in the caller's `ZONE_CONFIG` snapshot; no extra parse, JS call or D1 read per event (ADR-2018), and only a D1 miss re-reads the config. The client derives `section` at ingest and on cache load only; a pin change takes effect on the next page load.

## Verification

At the commits in `verified_commit`, from the worktree root:

- `cargo test -p nostr-bbs-relay-worker --lib` (pin tests in `zone_config`, `trust`, `relay_do::nip_handlers::channel_pin_gate_tests`, `profile_stats`, `triage`), `cargo test -p nostr-bbs-config` (validation tests and `tests/zone_projection.rs`, whose fixtures passed against the schema before the field was added), `cargo test -p nostr-bbs-client-core --lib` (`stores::zones` and `stores::channels` pin tests), `cargo test -p nostr-bbs-search-build` (harvest unit tests and three `incremental_e2e` cases).
- `cargo test --workspace --all-targets --all-features`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo fmt --all -- --check`, `cargo check --workspace --target wasm32-unknown-unknown`, `RUSTDOCFLAGS="-D warnings -D rustdoc::broken-intra-doc-links" cargo doc --workspace --no-deps`.
- Readers of `channel_zones` and of the relay memo were enumerated by `grep -rn "channel_zones\|get_channel_zone\|cached_channel_zone\|channel_zone_cache"`; the gates all go through `cached_channel_zone`, and the two SQL readers outside it (profile stats, triage) apply the pin. The offline tools `nostr-bbs-bulk-import` and `nostr-bbs-zone-migrate` read `channel_zones` from an export and are not gates; a pinned channel migrated with them under its old zone is refused by the relay's `zk` check.

Not verified here: anything against a deployed relay, D1, Durable Object or browser. Rollout checks: the deployed relay sha includes this change; as a member of the old zone (forum and BBS), the section is gone after reload, a deep link is refused, `REQ {"kinds":[40,41,42],"ids"/"#e":[id]}` and COUNT return nothing, and profile stats show no channel name; as an admin, old posts decrypt and a new post carries the pinned zone's `zk`; signed out, nothing; and a count of the channel's kind-42 posts whose root `e` is not the channel id (legacy slug tags, ungated).
