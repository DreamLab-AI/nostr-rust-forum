# Dependency advisory exceptions

These exceptions cover transitive dependencies that cannot be replaced within
this workspace. The security maintainers own the list. It must be reviewed by
**2026-11-20** and whenever the direct parent dependency is upgraded.

| Advisory | Dependency path / rationale | Removal target |
|---|---|---|
| RUSTSEC-2025-0141 | `bincode 1.3.3` through `gloo-worker`; unmaintained, with no known vulnerability. Browser-only serialization path. | Remove when Gloo replaces bincode or the client moves off `gloo-worker`. |
| RUSTSEC-2024-0384 | `instant 0.1.13` is target-specific legacy browser timing code; unmaintained, with no known vulnerability. | Remove when its transitive parent releases without `instant`. |
| RUSTSEC-2024-0436 | `paste 1.0.15` is a compile-time macro dependency of Leptos; unmaintained and absent at runtime. | Remove with the next Leptos upgrade that drops it. |
| RUSTSEC-2026-0173 | `proc-macro-error2 2.0.1` is a compile-time Leptos macro dependency; unmaintained and absent at runtime. | Remove with the next Leptos upgrade that drops it. |
| RUSTSEC-2026-0097 | `rand 0.8/0.9` is affected only with a custom logger invoking RNG recursively; this workspace defines no such logger. | Remove once all parent crates resolve a patched Rand release. |
| RUSTSEC-2026-0221 | `event-listener 5.4.1` enters through Leptos reactive state. The reported cross-thread `!Send` issue is not reachable in the single-threaded browser WASM client. | Remove with a Leptos/reactive-graph release using a fixed event-listener. |

Exceptions suppress CI warnings, not vulnerabilities in application-owned
code. A newly published vulnerability or a change in deployment target must
trigger immediate reassessment rather than waiting for the review date.

## Advisory drift and the watch list

The advisory database is fetched live by `cargo audit` and `cargo deny`, so a
lockfile that has not changed can turn red when a new advisory is published
(2026-10-14: `rustls 0.23.45` and `quinn-proto 0.11.15`). `ci.yml` only runs
`cargo deny` on push and pull request, so drift could first appear at release
time. `audit.yml` therefore also runs `cargo deny check advisories` on its weekly
schedule (Monday 06:17 UTC), alongside `cargo audit`.

`scripts/ci/dep-watchlist.sh` reads the crates listed in
`scripts/ci/dep-watchlist.txt` (currently `rustls`, `quinn-proto`), prints each
locked version from `Cargo.lock` and compares it with the latest crates.io
release. It runs as a non-blocking step, emits a `::warning::` annotation when a
crate is behind, and fails open (exit 0 with a warning) when crates.io is
unreachable. Add a crate to the list after any advisory that hits a TLS or
transport dependency; a lockfile bump is the usual fix.

