# ADR-106: Gap-Close Forum Governance Surfaces

**Status:** Proposed
**Date:** 2026-07-08
**Decision Owners:** nostr-rust-forum maintainers (DreamLab AI)
**Related:** [PRD Gap-Close Forum](../prd/prd-gap-close-forum.md), [DDD Gap-Close Forum Context](../ddd/ddd-gap-close-forum-context.md), [Meta-PRD Gap-Close Sprint](../../../VisionFlow/docs/PRD-gap-close-sprint.md), [ADR-004 Gap-Close Sprint Governance](../../../VisionFlow/docs/ADR-004-gap-close-sprint-governance.md), [ADR-002 Ecosystem Alignment Governance](../../../VisionFlow/docs/ADR-002-ecosystem-alignment-governance.md), [ADR-097 Agent Identity Provisioning](ADR-097-agent-identity-provisioning.md), [ADR-104 Gift-Wrap Recipient Admission](ADR-104-gift-wrap-recipient-admission.md), [ADR-125 did:nostr Multikey (VisionClaw)]

## Context

The forum's gap-close slice closes the decision surface. Nine register gaps (F1–F9) and three commitments (COM-13, COM-16, COM-17) touch code that already exists in nearly every case: a tested escalation orchestrator with no callers, an ack-capable publish path the governance page bypasses, nine roster endpoints no client calls, an agent registry no badge reads. The slice forces decisions the PRD does not settle: which branch to build on, how to split the member read path from the admin write path, where the disclosure principal comes from, whether to consume or re-implement the orchestrator, and how to treat two claims (NIP-42, federation) that verification shows are already in a defined state.

Two upstream decisions constrain the answers. ADR-002 keeps repository-local docs authoritative for implementation while the canon owns the cross-repo view. ADR-004 requires code-verified closure at a stated tier, a liveness canary per loop-closing item, and conformist typing against the Judgment Broker context. This ADR records the decisions this slice forces under those constraints.

## Decision 1 — Base the sprint branch on `did-nostr-cidv1`, not `main`

`gap-close/2026-07` is cut from `did-nostr-cidv1` at `6ef842b`, not from `main` at `a149da4`.

Verification. `did-nostr-cidv1` is `main` plus three commits (`3734b60`, `6370d71`, `6ef842b`): did-doc cid/v1 fixture convergence, full-shape spec alignment, and a security-audit remediation batch. A diff of the two branches over the governance and agent-control surfaces (`app.rs`, `pages/governance.rs`, `stores/panel_registry.rs`, `nostr-bbs-core/src/governance.rs`, `governance_api.rs`, `panel_registry.rs`) shows them byte-identical. The branch's only touch to `nip_handlers.rs` is a per-IP rate-limit gate on `handle_req`/`handle_count` (`+17` lines), in different functions from the 31403 governance projection this slice wires. So choosing the richer base introduces no rebase conflict on any file this slice edits.

The meta-PRD's hypothesis was that COM-13/COM-14 depend on the branch's `did:nostr` work. Verification narrows that: COM-14 (keying actor nodes by `did:nostr`) is VisionClaw's item, not the forum's, and COM-13's disclosure badge reads `agent_registry.registered_by`, a principal string on `main`, not a rendered `did:nostr` document. The badge does not depend on `did.rs`.

The real reason to take the branch is the P0 floor. ADR-004's P0 wave is correctness and security preconditions, and the forum's REC-1 share sits in it. The three branch commits carry exactly that class of fix: REQ/COUNT per-IP rate-limit gates, `.acl` GET narrowed to Control-only through the shared `solid_pod_rs::wac::effective_acl_target`, gift-wrap admission hardening (`gift_wrap.rs`, `+158`), moderation signature verification (`moderation_events.rs`, `+49`), a retention-sweep cron, and the `nip11.rs` retention single-source refactor that this slice's WP-6 reconciles. Building the P1 governance surfaces on a base that lacks the P0 floor would invert the wave order. Taking the branch also means the canonical `did:nostr` Tier-1 rendering (ADR-125 Multikey, `did.rs`) is present for any later principal-verification the disclosure or supersession surfaces sign against.

Alternatives:

| Alternative | Verdict | Rationale |
|---|---|---|
| Base on `main` (recon's recommendation) | Rejected | The recon's argument is merge-safety: it worried that concurrent workstreams landing on `main` could clobber `acl.rs`/`gift_wrap.rs`. Basing on `did-nostr-cidv1` eliminates that risk instead of running into it, because this slice edits none of those files and now sits atop them. Building on `main` would leave the P1 surfaces without the P0 security floor until the branch merges. |
| Wait for `did-nostr-cidv1` to merge to `main`, then branch | Rejected | Serialises the sprint on an unrelated branch's merge review. The governance surfaces are identical on both, so waiting buys nothing and delays P0 disclosure. |
| Base on `did-nostr-cidv1` | **Accepted** | Zero conflict on edited files, inherits the P0 security floor and the ADR-125 identity form, and turns the clobber risk into a superset relationship: `did-nostr-cidv1` can merge to `main` first and `gap-close/2026-07` carries its own governance delta on top. |

Consequence: when `did-nostr-cidv1` merges to `main`, `gap-close/2026-07` rebases to a delta of governance commits only. The maintainers coordinate merge order so the branch merges before or together with the gap-close surfaces.

## Decision 2 — Split the member read path from the admin write path by route, not by conditional rendering

F1 is closed by adding an `AuthGated` (auth-only, non-admin) read-only governance route and repointing `/governance` at it for non-admins, while the Approve/Reject controls stay behind `AdminGatedGovernance` at a distinct admin route (for example `/governance/admin`).

Alternative considered: keep a single `GovernancePage` and hide the write buttons behind an `is_admin` guard in the view. Rejected. A single page that conditionally renders controls still mounts the publish handlers in the component tree and ships the write code to every member's client; a bug or a signal misfire could expose a path to publish a 31403. Splitting by route means the member read component never compiles in a write handler. It also matches the existing `auth_gated!` macro pattern (`app.rs:1090-1098`), so the read variant is a small, well-worn addition rather than a new gating mechanism.

## Decision 3 — The disclosure badge sources the authorising principal from the registry, never from event content

COM-13's badge reads the active agent set and the `registered_by` principal from `agent_registry` (via `GET /api/governance/agents` or a lighter public read), and renders that principal. It does not trust a self-declared "I am an agent" tag or a content field on the event.

Alternative considered: agents self-disclose by including a tag or content flag in their events, and the client badges on that. Rejected. A self-claim is spoofable in both directions: a human can claim agent status, and an agent can omit the claim to pass as human, which is the exact failure F2 names. The server-side registry is the trust root already used by the relay's registered-agent gate (`nip_handlers.rs:341-355`). Reading the badge from the same source keeps disclosure honest and consistent with the write gate.

Consequence: the badge needs the active registry client-side. This slice caches the active pubkey set from the registry read and invalidates on a bounded interval; a revoked agent (`active = 0`) loses its badge on the next refresh.

## Decision 4 — Consume the existing `DecisionOrchestrator`; assign risk tier at the panel, suppress at the member Memo

COM-16 wires the relay's 31403 projection (`nip_handlers.rs`) to route a parsed non-binary action through `broker::DecisionOrchestrator::decide` (`nostr-bbs-core/src/governance.rs:577`) and persist the outcome to `broker_decisions`. The client stays thin. The `risk_tier` is declared by the agent on the 31402 ActionRequest/PanelDefinition; the member panel Memo suppresses low-risk panels.

Two alternatives:

| Alternative | Verdict | Rationale |
|---|---|---|
| Re-implement the escalation state machine in the forum client | Rejected | Duplicates tested domain logic that already lives in `nostr-bbs-core` (`governance.rs:488-602`, tests at `:832-1164`) and invites drift between the client's reading and the core's. ADR-002 keeps one implementation authoritative; the core already is. |
| Compute `risk_tier` at the relay from the action content | Rejected for the default | The relay cannot infer an action's risk without a policy the sprint has not defined (that policy is REC-6, agentbox-owned). Having the agent declare the tier on the 31402 is honest about where the judgment comes from and lets REC-6 later override or validate it. The relay and client trust-but-verify the declared tier. |
| Agent declares `risk_tier`, client suppresses low tier | **Accepted** | Keeps the domain logic single-sourced, makes the risk judgment legible at its origin, and gives F7 (approval fatigue) a concrete mechanism: the member surface shows only panels a tier says warrant attention. |

Consequence: the approval-fatigue response (F7) is the suppression itself, not a separate feature. If REC-6 later supplies a relay-side default, it overrides the agent-declared tier; until then the agent's declaration stands and is labelled as such.

## Decision 5 — Replace optimistic send with `publish_with_ack`; add a tenth governance route for decision reads

COM-17 swaps the governance path's `relay.publish(&signed)` at `pages/governance.rs:209` and `:319` for `relay.publish_with_ack` (`relay.rs:464-478`) with an on-OK callback that flips the sent state only on relay acceptance and raises a rejection state on `accepted = false`. `GET /api/governance/decisions` is added as the tenth governance route, reading `broker_decisions` and mirroring `handle_list_cases`.

Alternative considered: keep optimistic send and reconcile later by polling `broker_decisions` for the persisted outcome. Rejected. Polling adds latency and a race: the UI would still show "Sent" in the window before the poll returns, which is the F4 defect, and a relay rejection would surface late or not at all. The ack machinery is already `integrated` on seven other write paths (`thread.rs`, `settings.rs`, `category.rs`, `section.rs`, `admin/mod.rs`, `rsvp_buttons.rs`, `create_event_modal.rs`); the governance path is the outlier, so this is consistency, not new machinery.

Consequence: the panel schema gains `confidence` and `risk_tier` fields (`ActionEntry`, `stores/panel_registry.rs:23-27`), displayed at decision time so a human sees the agent's stated confidence before responding (F5).

## Decision 6 — Implement F6 supersession to a canon specification; declare the dependency, do not invent semantics

The forum does not define supersession, appeal or revoke semantics for a published decision locally. The VisionFlow canon owns that specification (into `DDD-judgment-broker-context`, meta-PRD VisionFlow work package). This slice waits for it, then implements `DecisionOutcome::Supersede { prior_decision_id }` and `CaseState::Reopened` behind an admin-gated `POST /api/governance/decisions/:id/supersede`.

Alternative considered: define supersession semantics in the forum now and let the canon conform later. Rejected. The decision lifecycle is a Judgment Broker aggregate (`BrokerCase`, `DecisionOutcome`), and DDD Gap-Close types the forum as conformist to that context (Relationship Types). A locally invented supersede would risk a semantics the canon then has to unpick, reproducing the drift ADR-002 exists to catch. F6 stays `planned` until the canon spec lands; the slice cites the spec by document and section when it implements.

Consequence: F6 is P2 and dependency-gated. Its canary is registered now and is not expected to fire this wave.

## Decision 7 — Ratify the existing NIP-42 reconciliation at the canon; make no redundant write-model change

Verification shows the NIP-42 claim is already reconciled in shipped code: `nip11.rs` advertises `auth_required: false` with an explicit `nostr_bbs.write_policy` block (`model: "whitelist"`, `nip42_challenge_sent: true`, `nip42_required_for_write: false`), the relay sends a NIP-42 challenge on connect, and the write gate is `is_whitelisted(pubkey)`, independent of AUTH. `CLOSEOUT-SECURITY-AUDIT.md` records the same. The forum's REC-1 action is to align the canon's wording to this mechanism, not to change the mechanism.

Alternative considered: make writes require a completed NIP-42 AUTH round-trip so the canon's stronger claim becomes literally true. Rejected. That changes the shipped, documented whitelist-gated write model, a real behavioural change ADR-004 does not mandate and that would break the reconciliation the relay already advertises to API consumers. The honest close is to match the canon's wording to the code, which is a canon-side documentation act this slice flags, not a forum code change.

## Decision 8 — Federation stays planned; build no `MeshTransport` this sprint

F9 is parked standalone-first (ecosystem-map G2, meta-PRD Non-Goals). This slice builds no transport. The allow-list gate (`is_federated_kind_allowed`, `is_mesh_peer`, `nip_handlers.rs:1379-1429`) already exists and is inert under the shipped `MESH_MODE = "standalone"` default; `nostr-bbs-mesh` is a 123-line trait-only crate with no implementation.

Alternative considered: implement a `MeshTransport` (the crate README names libp2p, HTTP3 and Tailscale as candidates) and stand up one federated pair now. Rejected for this sprint. The meta-PRD scopes federation to a single P2 rescope-or-build fork whose default is rescope; building it would export a governance-replication trust boundary the security audit records as unenforced. The item stays `planned`; if the canon fork resolves to build, it moves `scaffolded → integrated` on live replication evidence.

## What this ADR does not decide

- The implementation of any work package. The PRD's falsification statements and acceptance criteria bound them; the code lands under those.
- The severity or type of any gap. The register's judges fixed those (DDD Gap-Close, Invariant against re-rating).
- The supersession lifecycle semantics (Decision 6 defers them to the canon) or the escalation-default schema (Decision 4 defers the relay-side default to REC-6/agentbox).

## Consequences

Positive. The four loop-closing P0/P1 surfaces (disclosure, member read, escalation, decision integrity, roster) each carry a canary and a pre-authored falsification statement, so a design accepted and abandoned registers as open, not as a documentation success (ADR-004 Risk). Consuming the existing orchestrator and ack path means most closures are integration, not new domain code, which the recon sizes down from greenfield. Basing on `did-nostr-cidv1` puts the P0 security floor under the P1 surfaces.

Tradeoffs. Splitting the governance route (Decision 2) adds a route and a component variant rather than a conditional. Basing on an in-flight branch (Decision 1) couples the sprint branch to that branch's merge; the mitigation is the superset relationship and a coordinated merge order.

Risks. Risk-tiering (Decision 4) and the escalation-default projection are greenfield; the recon sizes them L, not M. F6, F9, REC-6 and REC-10 are dependency-gated on the canon, agentbox and VisionClaw; their canaries stay unfired until the upstream lands, and the maturity summary labels them below `integrated` so a gated item cannot read as closed.

## Reconciliation

Each closed item updates `../../../VisionFlow/docs/architecture/compatibility-matrix.md` at the tier its evidence supports, per ADR-002. Wave promotion is ratified at the canon when the P0 canaries (`forum-canary-agent-badge`, `forum-canary-nip42-conformance`) are green. This ADR is revisited only on a structural change; item-level movement is a canon-register edit, not an ADR revision (ADR-004 Governance Cadence).
