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
