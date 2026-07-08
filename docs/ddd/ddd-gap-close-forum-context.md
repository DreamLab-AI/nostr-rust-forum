# DDD: Gap-Close Forum Context

**Status:** Living document
**Date:** 2026-07-08
**Scope:** The nostr-rust-forum slice of the four-surface gap-close sprint
**Governed by:** [PRD Gap-Close Forum](../prd/prd-gap-close-forum.md), [ADR-106 Gap-Close Forum Governance Surfaces](../adr/ADR-106-gap-close-forum-governance-surfaces.md)
**Conformist to:** [DDD Gap-Close Context](../../../VisionFlow/docs/DDD-gap-close-context.md), [DDD Judgment Broker Context](../../../VisionFlow/docs/DDD-judgment-broker-context.md), [DDD Ecosystem Alignment Context](../../../VisionFlow/docs/DDD-ecosystem-alignment-context.md)
**Local context:** [DDD BBS Bounded Contexts](ddd-bbs-bounded-contexts.md)

---

## 1. Bounded context

The Forum Governance Surface is where a decision is taken by a human. It renders panels an agent declares (31400 PanelDefinition), presents an agent's request for a decision (31402 ActionRequest), and carries the human's answer back (31403 ActionResponse). The gap register found this surface built and half-wired: the display works, the escalation lifecycle behind it does not reach the wire, the ack behind the send is bypassed, and the roster behind the agents is unmanageable from any screen.

This context is downstream and conformist. It adds no aggregate to the Judgment Broker context (`BrokerCase`, `DecisionOutcome`); it projects those aggregates onto a surface. It adds no maturity vocabulary to the Ecosystem Alignment context; it uses the seven tiers verbatim. It consumes the Gap-Close context's closure protocol (falsification, receipt, canary) without redefining it.

---

## 2. Context map

| Context | Relationship | Notes |
|---|---|---|
| **Forum Governance Surface** (this context) | Projects the decision loop onto the forum client and relay | Owns the panel projection, disclosure, member read path, roster admin |
| **Judgment Broker** ([DDD](../../../VisionFlow/docs/DDD-judgment-broker-context.md), [ADR-003](../../../VisionFlow/docs/ADR-003-judgment-broker-distributed-architecture.md)) | Upstream, conformist | Owns `BrokerCase`, `DecisionOutcome`, `CaseState`, `DecisionOrchestrator`. This context consumes them; it does not re-model them. |
| **Ecosystem Alignment** ([ADR-002](../../../VisionFlow/docs/ADR-002-ecosystem-alignment-governance.md)) | Upstream, conformist | Supplies the maturity vocabulary and the compatibility matrix this slice reconciles into. |
| **Gap-Close Sprint** ([DDD](../../../VisionFlow/docs/DDD-gap-close-context.md), [ADR-004](../../../VisionFlow/docs/ADR-004-gap-close-sprint-governance.md)) | Upstream, customer/supplier | Defines the closure protocol; this slice supplies its `RepoWorkPackage` and evidence. |
| **Agent Runtime (agentbox)** | Upstream (Supplier), dependency-gated | Owns the escalation-default schema (REC-6) this slice projects and the `did:nostr`-at-spawn principal it displays. |
| **VisionFlow canon** | Upstream, conformist | Owns the supersession-authority specification (F6) and the federation rescope-or-build fork (F9). |

### Relationship types

- **Judgment Broker → Forum Governance Surface:** Conformist. A decision this surface records is a `DecisionOutcome` persisted to `broker_decisions` through `DecisionOrchestrator::decide`, not a parallel forum-local decision model. `CaseState` transitions follow the broker's, not a forum invention.
- **Ecosystem Alignment → Forum Governance Surface:** Conformist. Maturity is claimed in the seven tiers and reconciled into the compatibility matrix.
- **agentbox / canon → Forum Governance Surface:** Customer/Supplier, dependency-gated. This slice waits for the escalation-default schema (REC-6), the supersession spec (F6) and the federation fork (F9) before those items pass `planned`.

---

## 3. Aggregates

| Aggregate | Root | Description |
|---|---|---|
| `GovernancePanelProjection` | Yes (this context) | The client-side and relay-side projection of a governance panel: a 31400 PanelDefinition, its 31402 ActionRequests, and the 31403 ActionResponses. Consistency boundary: a panel's actions and their responses render and publish together. Owns the member read path (F1), the disclosure badge (COM-13), the risk-tier suppression (F7), and the ack-confirmed publish (F4). |
| `AgentRegistration` | Yes | One row of `agent_registry` (`pubkey`, `name`, `description`, `registered_by`, `registered_at`, `rate_limit_per_min`, `active`). The authorising-principal source (`registered_by`) for the disclosure badge and the roster admin surface (F8). Immutable identity is `pubkey`; `active` is the lifecycle flag. |
| `BrokerCase` | No (owned by Judgment Broker) | Consumed, not owned. A case moves through `CaseState` and receives `DecisionOutcome`s. This context projects it and, via `DecisionOrchestrator`, persists outcomes; it does not define the case lifecycle. |
| `DecisionOutcome` | No (owned by Judgment Broker) | `Approve`, `Reject`, `Amend`, `Delegate`, `Promote`, `Precedent`, and the canon-specified `Supersede` (F6, pending). Persisted to `broker_decisions`. |

---

## 4. Entities

| Entity | Identity | Owner |
|---|---|---|
| `PanelDefinition` (31400) | `d` tag | Agent (publisher); projected by this context |
| `ActionRequest` (31402) | `d` tag + `e` tag | Agent (publisher); projected by this context |
| `ActionResponse` (31403) | signer pubkey + `e` tag | Human (publisher); published by this context |
| `AgentRegistration` | `pubkey` | Relay (`agent_registry`) |
| `BrokerDecision` | `decision_id` | Relay (`broker_decisions`); written via `DecisionOrchestrator` |
| `MemberSession` | authed pubkey + `ZoneAccess` | Forum client (`use_auth`, `is_admin`) |

---

## 5. Value objects

| Value object | Fields | Notes |
|---|---|---|
| `RiskTier` | low, medium, high, critical | New. Declared by the agent on the 31402 ActionRequest; the member panel Memo suppresses `low`. Greenfield (`planned`) — no symbol exists in the tree today. |
| `Confidence` | `Option<f32>` on the ActionRequest | New. Displayed at decision time (F5). Absent from `ActionEntry` today. |
| `AuthorisingPrincipal` | `registered_by` pubkey | The principal the disclosure badge names (COM-13). Read from the registry, never from event content (ADR-106 Decision 3). |
| `MaturityTier` | historical, planned, scaffolded, standalone, integrated, federation-verified, released | ADR-002 vocabulary, verbatim. |
| `PublishOutcome` | Sent (ack), Rejected (`OK false`), Pending | Replaces the optimistic boolean that flips on sign (F4). |
| `FalsificationStatement` | Predicate whose truth means not done | One per work package, authored before the code. |

---

## 6. Domain events

| Event | Trigger | Publisher | Consumer |
|---|---|---|---|
| `WorkPackageMinted` | This slice's child PRD/ADR/DDD authored | nostr-rust-forum | Gap-Close context |
| `PanelProjectedToMember` | A non-admin member renders a read-only panel (F1) | Forum client | `forum-canary-member-panel` |
| `AgentDisclosed` | An agent-authored item renders a badge naming its principal (COM-13) | Forum client | `forum-canary-agent-badge` |
| `EscalationOutcomeRecorded` | A non-binary 31403 routes through `DecisionOrchestrator::decide` and persists to `broker_decisions` (COM-16) | Relay (`nip_handlers.rs`) | `forum-canary-escalation-outcome`, `broker_decisions` |
| `DecisionRejectedByRelay` | A 31403 returns `OK false`; the UI leaves "Sent" (F4) | Relay → forum client | `forum-canary-ack-reject` |
| `DecisionHistoryQueried` | `GET /api/governance/decisions` returns a persisted row (F5) | auth-worker | `forum-canary-decisions-read` |
| `RosterMutated` | An admin register/revoke round-trips through one of the nine endpoints (F8) | Forum client → auth-worker | `forum-canary-roster-roundtrip` |
| `Nip42ClaimConformant` | Advertised `write_policy` equals the enforced gate (REC-1) | Relay | `forum-canary-nip42-conformance` |
| `DecisionSuperseded` | A supersede persists a revoking decision and reopens the case (F6) | Relay | `forum-canary-supersede` (deferred, canon-gated) |
| `GovernanceKindReplicated` | A governance kind replicates to a federated peer (F9) | `MeshTransport` | `forum-canary-federation-replicate` (deferred) |

---

## 7. Invariants

Local invariants this slice holds, in addition to the Gap-Close context invariants it inherits.

1. **The member read path publishes nothing.** The read-only member route (F1) mounts no code path capable of publishing a 31403. Write controls exist only behind the admin gate. Splitting by route, not by conditional render, enforces this (ADR-106 Decision 2).

2. **Disclosure trusts the registry, not the event.** The badge's `AuthorisingPrincipal` is read from `agent_registry.registered_by`, never from event content. A self-claimed agent status carries no badge; a registry-active agent always carries one (ADR-106 Decision 3).

3. **A decision is recorded through the broker, not around it.** A non-binary outcome reaches `broker_decisions` only via `DecisionOrchestrator::decide`. This context never writes a decision row that bypasses the orchestrator, so `CaseState` and `DecisionOutcome` stay consistent with the Judgment Broker context.

4. **Sent means acknowledged.** The publish state advances to Sent only on a relay OK. A signed-but-unacknowledged 31403 is `Pending`; a rejected one is `Rejected`. The state never advances on sign alone (F4).

5. **A gated item stays below `integrated`.** F6, F9, REC-6 and REC-10 depend on the canon, agentbox or VisionClaw. Each stays at `planned` (or, for the F9 allow-list gate, `scaffolded`) until its upstream lands, and never reads as closed (DDD Gap-Close, Invariant 6).

6. **Supersession semantics come from the canon.** This context adds `DecisionOutcome::Supersede` and `CaseState::Reopened` only to a canon specification, never inventing the lifecycle locally (ADR-106 Decision 6, conformist to the Judgment Broker context).

---

## 8. Ubiquitous language (slice additions)

| Term | Meaning |
|---|---|
| **Panel projection** | The forum's rendering of a governance panel: the 31400 definition, its 31402 requests, and the 31403 responses, on the client and relay. |
| **Member read path** | The non-admin, auth-only route that renders panels read-only, with no write control (F1). |
| **Disclosure badge** | The marker on an agent-authored item naming its authorising principal from `agent_registry.registered_by` (COM-13). |
| **Authorising principal** | The `registered_by` pubkey that provisioned an agent; the identity the badge names. |
| **Escalation outcome** | A non-binary `DecisionOutcome` (delegate, promote, precedent) recorded through `DecisionOrchestrator` (COM-16). |
| **Risk tier** | An agent-declared tier on a 31402 that governs whether the member surface shows the panel; the design answer to approval fatigue (F7). |
| **Ack-confirmed publish** | A 31403 whose UI state advances only on relay acceptance, via `publish_with_ack` (F4). |
| **Decision-audit read** | `GET /api/governance/decisions`, the read side over `broker_decisions` (F5). |
| **Reconciled claim** | A canon assertion (NIP-42) aligned to the shipped mechanism rather than the mechanism changed to fit the claim (REC-1). |

---

## 9. Services

| Service | Responsibility | Owner | Status |
|---|---|---|---|
| `MemberGovernanceView` | Renders read-only panels to a non-admin member | Forum client | `planned` → `integrated` (F1) |
| `AgentBadgeResolver` | Resolves the active agent set and authorising principal from the registry, caches, invalidates on revoke | Forum client | `planned` → `integrated` (COM-13) |
| `EscalationProjector` | Routes a non-binary 31403 through `DecisionOrchestrator::decide`, persists to `broker_decisions` | Relay (`nip_handlers.rs`) | `scaffolded` (orchestrator) → `integrated` (COM-16) |
| `AckedGovernancePublisher` | Publishes a 31403 via `publish_with_ack`, tracking `PublishOutcome` | Forum client | `planned` → `integrated` (F4) |
| `DecisionReadApi` | `GET /api/governance/decisions` over `broker_decisions` | auth-worker | `planned` → `integrated` (F5) |
| `RosterAdminTab` | Calls the nine roster endpoints via NIP-98-signed fetch | Forum client | `planned` → `integrated` (F8) |
| `Nip42Reconciler` | Keeps the advertised `write_policy` equal to the enforced gate | Relay (`nip11.rs`) | `integrated`, canon wording pending (REC-1) |
| `SupersessionAuthority` | Adds `Supersede`/`Reopened` to a canon spec | Relay + auth-worker | `planned`, canon-gated (F6) |
| `MeshGovernanceTransport` | Replicates governance kinds to a peer | `nostr-bbs-mesh` | `planned` (trait-only), no build this sprint (F9) |
| `EscalationDefaultProjection` | Projects agentbox's escalation-default schema on the relay | Relay | `planned`, agentbox-gated (REC-6) |
| `DiscoveryAdvertiser` | Advertises a NIP-89-style discovery kind | Relay | `planned`, upstream-gated (REC-10) |

---

## 10. Liveness canaries

Each loop-closing service registers a canary against the VisionClaw harness (RES-a). A loop item with no fired canary is `Open`, not closed (DDD Gap-Close, Invariant 4).

| Canary | Wire observed | Firing means | Wave |
|---|---|---|---|
| `forum-canary-member-panel` | A non-admin session GET-renders a `PanelCard` with no write control in the DOM | The member read path carries live panel data to an ordinary member | P1 |
| `forum-canary-agent-badge` | An agent-authored item (author ∈ active `agent_registry`) renders a badge naming `registered_by` | The disclosure wire carries the authorising principal | P0 |
| `forum-canary-escalation-outcome` | A non-binary 31403 reaches `DecisionOrchestrator::decide` and persists a matching `broker_decisions` row | The escalation lifecycle is no longer dead code | P1 |
| `forum-canary-ack-reject` | A relay-rejected 31403 flips the UI out of "Sent" via the `publish_with_ack` callback | The optimistic-send illusion is closed | P1 |
| `forum-canary-decisions-read` | `GET /api/governance/decisions` returns a persisted `broker_decisions` row to an authed operator | The decision-audit read API is live | P1 |
| `forum-canary-roster-roundtrip` | The Agents tab issues a NIP-98-signed call to one of the nine endpoints and the roster reflects the mutation | The roster admin UI reaches the server | P1 |
| `forum-canary-nip42-conformance` | Advertised `write_policy` equals the enforced write gate | Advertised claim and enforced mechanism agree (conformance probe) | P0 |
| `forum-canary-supersede` | A supersede persists a revoking decision and reopens the case | Supersession authority is live (deferred, canon-gated) | P2 |
| `forum-canary-federation-replicate` | A governance kind signed on relay A appears on relay B via a live `MeshTransport` | Federation carries governance traffic (deferred, no build this sprint) | P2 |
| `forum-canary-escalation-default-projection` | The relay projects agentbox's escalation-default schema | The escalation-default projection is live (deferred, agentbox-gated) | P1/P2 |
| `forum-canary-discovery-surface` | A NIP-89-style discovery kind is fetchable from `agent_registry`/NIP-11 | The discovery surface is live (deferred, upstream-gated) | P2 |

---

## 11. Ownership summary

| Owns in this context | Does not own |
|---|---|
| The panel projection, the member read path, the disclosure badge, the escalation projection into `broker_decisions`, the ack-confirmed publish, the decision-audit read API, the roster admin surface, the NIP-42 conformance | The `BrokerCase`/`DecisionOutcome`/`CaseState` model (Judgment Broker canon), the supersession specification (VisionFlow canon), the escalation-default schema (agentbox), the discovery contract (VisionClaw/agentbox), the `did:nostr` actor-node keying (VisionClaw), embodiment, agent runtime, pod persistence |

---

## 12. Open issues

1. **Canary durability for the escalation projection.** `forum-canary-escalation-outcome` feeds the Augmentation Ratio and Trust Variance measures (meta-PRD Measurement Commitments), which imply a standing monitor rather than one-shot firing. Resolve in the ADR whether this canary must stay green or firing once suffices (DDD Gap-Close, Open Issue 2).
2. **REC-6 override versus agent-declared tier.** Decision 4 has the agent declare `risk_tier` on the 31402; REC-6 later supplies a relay-side default. The precedence (agent-declared, relay-override, or relay-validated) is fixed when the agentbox authority model lands.
3. **F6 sub-item boundary with the canon.** The supersession spec is canon-owned; the boundary between the canon's semantics and this slice's projection (route, gate, persistence) is fixed in the canon's F6 document, not here (DDD Gap-Close, Open Issue 3).
