# Architecture Decision Records — index

This directory is the **canonical register** of Architecture Decision Records for
`nostr-rust-forum`. Each ADR captures one decision: its context, the decision, and
its consequences. This index closes register gap **G6** (no ADR index existed).

## Numbering authority

- ADR numbers are **sequential and unique**. A number is allocated once and never
  reused, even if an ADR is later superseded or rejected.
- **This directory (`docs/adr/`) is canonical** for ADR numbering and content.
- A small number of ADRs are **sprint-resident** (see below) — they live under a
  sprint folder because they were authored inline with that sprint's work and are
  referenced directly by code. They are listed here so the register is complete;
  reconciling them into this directory (or formally leaving them sprint-resident
  with a stub here) is in-flight. Until then, **this index is the authority on what
  number maps to what decision**.
- ADRs **001–085** are the **upstream / historical kit record** and are **not filed
  in this directory**. They belong to the broader VisionClaw / kit decision history
  tracked upstream; they are intentionally out of scope for this register. This
  directory begins at ADR-086.

## Register — ADR-086 onward

| ADR | Title | Status | Location |
|-----|-------|--------|----------|
| 086 | NIP-05 Pod Federation | Accepted | `ADR-086-nip05-pod-federation.md` |
| 087 | CF-Workers-portable cores for solid-pod-rs Phase 1 surfaces | Accepted | `ADR-087-cf-workers-portable-cores.md` |
| 088 | WAC Turtle serializer bare-path IRI quirk | Accepted | `ADR-088-wac-turtle-serializer-quirk.md` |
| 089 | git-pods unavailability on Cloudflare Workers deployments | Accepted | `ADR-089-git-pods-cf-workers-limitation.md` |
| 090 | Path discipline at the FORUM_BASE boundary | Accepted | **sprint-resident** — `../sprint/2026-05-17-ux-audit/ADR-090-forum-base-path-discipline.md` |
| 091 | Channel post counts must be derived, not accumulated | Accepted | **sprint-resident** — `../sprint/2026-05-17-ux-audit/ADR-091-channel-counts-derived-from-events.md` |
| 092 | Deep-link entry must self-bootstrap | Accepted | **sprint-resident** — `../sprint/2026-05-17-ux-audit/ADR-092-deeplink-self-bootstrap.md` |
| 093 | Native pod mesh: hybrid CF Workers + agentbox two-tier architecture | Accepted | `ADR-093-native-pod-mesh.md` |
| 094 | Deterministic purpose-scoped subkey derivation | Accepted | `ADR-094-deterministic-subkey-derivation.md` |
| 095 | Recovery & device-onboarding sheet | Accepted | `ADR-095-recovery-device-onboarding-sheet.md` |
| 096 | ACL container resolution + per-container delegation | Accepted | `ADR-096-acl-container-resolution-and-delegation.md` |
| 097 | Consolidated agent identity provisioning | Accepted | `ADR-097-agent-identity-provisioning.md` |
| 098 | `/connect` magic-link onboarding | Accepted | `ADR-098-connect-magic-link-onboarding.md` |
| 099 | Revocable device keys | Accepted (gated `DEVICE_KEYS_ENABLED`, default off) | `ADR-099-revocable-device-keys.md` |
| 100 | Key lifecycle: root rotation, subkey re-derivation, device revocation | Accepted | `ADR-100-key-lifecycle.md` |
| 101 | Multi-device NIP-17 DM delivery | Accepted (implementation deferred — ADR-099 phase 2) | `ADR-101-multi-device-dm-delivery.md` |
| 102 | Trust demotion (relay activity) | _Incoming_ — owned by concurrent trust-demotion work; see anomaly O1 | `ADR-102-*` (pending) |
| 103 | Kit semver, crates.io publish, and yank policy | Accepted | `ADR-103-kit-semver-publish-yank-policy.md` |
| 104 | NIP-59 gift-wrap recipient admission and relay gating | Accepted | `ADR-104-gift-wrap-recipient-admission.md` |
| 105 | BBS door-games framework, auth-optional surfaces, and the M2 write-path | Accepted (write-path deferred) | `ADR-105-bbs-door-games-and-write-architecture.md` |

> **ADR-102** is reserved for the trust-demotion decision being authored alongside
> the `relay-worker/src/trust.rs` demotion wiring (anomaly register O1 —
> `check_demotion` / `increment_posts_read` currently unreachable). It is listed
> here so the sequence is unbroken; its record lands with that work.

## Sprint-resident ADRs

Three ADRs from the **2026-05-17 UX audit** sprint live under
`../sprint/2026-05-17-ux-audit/` rather than in this directory. They are
code-referenced (the forum client's path/count/deep-link invariants cite them
directly) and are reproduced in the register above:

- **ADR-090** — Path discipline at the FORUM_BASE boundary
- **ADR-091** — Channel post counts must be derived, not accumulated
- **ADR-092** — Deep-link entry must self-bootstrap

They remain in the sprint folder for now; their numbers are reserved in this
canonical register and reconciliation into `docs/adr/` is a tracked follow-up.

## Companion maps

The diagram-driven audit ground-truth lives in
[`../diagrams/`](../diagrams/00-anomaly-register.md); ADRs 099–104 in particular are
cross-referenced against `relay-event-admission.md`.
