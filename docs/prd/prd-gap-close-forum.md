# PRD: Gap-Close Sprint — nostr-rust-forum slice

**Owner:** nostr-rust-forum maintainers (DreamLab AI)
**Status:** Proposed
**Date:** 2026-07-08
**Wave entry:** P0 (COM-13/F2 disclosure, REC-1 NIP-42), then P1 (F1, COM-16, COM-17, F8), P2 (F6, F9)
**Governed by:** [Meta-PRD Gap-Close Sprint](../../../VisionFlow/docs/PRD-gap-close-sprint.md), [ADR-004 Gap-Close Sprint Governance](../../../VisionFlow/docs/ADR-004-gap-close-sprint-governance.md), [DDD Gap-Close Context](../../../VisionFlow/docs/DDD-gap-close-context.md)
**Child decisions:** [ADR-106 Gap-Close Forum Governance Surfaces](../adr/ADR-106-gap-close-forum-governance-surfaces.md)
**Child context:** [DDD Gap-Close Forum Context](../ddd/ddd-gap-close-forum-context.md)
**Base branch:** `gap-close/2026-07`, cut from `did-nostr-cidv1` at `6ef842b` (rationale: ADR-106 Decision 1)

## TL;DR

The forum owns the decision surface, and the register found it half-built. A governance plane rejects a forged approval yet admits only one operator (F1). Agents post beside humans with nothing marking them as agents (COM-13/F2). A tested escalation orchestrator sits in `nostr-bbs-core` with zero callers, so every case decides binary Approve or Reject (COM-16/F3). A rejected decision reads as sent, because the client fires the 31403 event and flips its own UI without waiting for a relay OK (COM-17/F4). Nine agent-roster endpoints exist server-side and no client screen calls any of them (F8). This slice wires those loops and states, before writing a line of implementation, the condition under which each is judged not done.

Nine of the twenty-eight register gaps (F1–F9) and three roadmap commitments (COM-13, COM-16, COM-17) land here, plus a share of REC-1 (the NIP-42 claim), REC-6 (relay projection of escalation defaults) and REC-10 (a discovery surface). The concentration is structural: the forum is one of two repositories the meta-PRD names as owning 26 of 28 gaps, because it owns the surface where a decision is taken.

## Scope and ownership

Owned register items: F1, F3, F4, F5, F6, F7, F8, F9, and F2 (subsumed by COM-13). Owned commitments: COM-13, COM-16, COM-17. Shared: REC-1 (NIP-42 sub-item), REC-6 (escalation-default relay projection), REC-10 (discovery-surface share).

Not owned by this slice: embodiment, the agent runtime, pod persistence (DDD Gap-Close, Ownership Summary). The `did:nostr` keying of actor nodes (COM-14) belongs to VisionClaw; the forum consumes `did:nostr` only as an authorising-principal string it displays, never as a node key.

## Work packages

Each package states current and target maturity in the ADR-002 seven-tier vocabulary (`historical`, `planned`, `scaffolded`, `standalone`, `integrated`, `federation-verified`, `released`), acceptance criteria as observable predicates, a falsification statement authored now, and a named liveness canary where the package closes a loop.

### WP-1 — Member surface (F1)

Current maturity: `planned`. The admin governance view is `integrated` and works: `/governance` routes to `AdminGatedGovernance` (`crates/nostr-bbs-forum-client/src/app.rs:581`), which requires auth and `ZoneAccess::is_admin`, bouncing non-admins to `/forums` with a toast (`app.rs:1133-1141`). The read-only member variant does not exist: the `auth_gated!` macro (`app.rs:1090-1098`) produces auth-only pages for other routes but none for governance, and the Approve/Reject controls in `pages/governance.rs` gate on `is_admin`. There is no route a non-admin member can reach to view a panel.

Target maturity: `integrated`. A non-admin authenticated member reaches a read-only governance route that renders `PanelCard`/`ActionRow` without the Approve/Reject buttons; the admin write controls move behind a distinct admin route so the read path never mounts a write handler (ADR-106 Decision 2).

Acceptance criteria:
- An authenticated non-admin loads the member governance route and sees at least one live `PanelCard`; the DOM carries no Approve, Reject or panel-action button.
- The same member on the admin route is still bounced, and an admin still sees the full write controls.
- The read route mounts no code path that can publish a 31403 ActionResponse.

Falsification statement: *WP-1 is falsified if a non-admin authenticated member still cannot open any governance panel, or if the member read route renders a control that can publish a 31403 event.*

Canary: `forum-canary-member-panel` — observes a non-admin session GET-rendering a `PanelCard` with no write control in the DOM. Firing means the member read path carries live panel data to an ordinary member.

### WP-2 — Disclosure badge (COM-13/F2)

Current maturity: `planned`. The `agent_registry` table is `integrated` as a data source (`crates/nostr-bbs-relay-worker/src/lib.rs:673-681`: `pubkey`, `name`, `description`, `registered_by`, `registered_at`, `rate_limit_per_min`, `active`), and `GET /api/governance/agents` lists it. No client component reads it: a search of `crates/nostr-bbs-forum-client/src/` for `AgentBadge`, `is_agent` or disclosure returns nothing. `PanelCard` (`pages/governance.rs:119-176`) shows an `agent_name` resolved through the profile cache, indistinguishable from a human display name.

Target maturity: `integrated`. A component reads the active agent set from the registry and renders a badge naming the authorising principal (`registered_by`) wherever an agent pubkey is displayed: post author and panel `agent_name`. The badge sources trust from the server-side registry, never from an event self-claim (ADR-106 Decision 3).

Acceptance criteria:
- An item authored by a pubkey in `agent_registry` where `active = 1` renders a visible agent badge naming its `registered_by` principal.
- An item authored by a human (pubkey absent from the active registry) renders no badge.
- The badge's principal matches the `registered_by` column, verified against a registry row, not against the event content.

Falsification statement: *WP-2 is falsified if any agent-authored item (author pubkey active in `agent_registry`) renders without a badge, if a human item renders a badge, or if the badge's principal is read from event content rather than the registry.*

Canary: `forum-canary-agent-badge` — observes an agent-authored item (author ∈ active `agent_registry`) rendering an `AgentBadge` that names `registered_by`. Firing means the disclosure wire carries the authorising principal to the reader.

### WP-3 — Decision integrity (COM-17/F4/F5)

Current maturity: `planned`. `relay.publish_with_ack` exists (`crates/nostr-bbs-forum-client/src/relay.rs:464-478`, with `PendingPublish`/`PublishCallback` at lines 69-73) and is `integrated` on other write paths (`thread.rs:501,601`; `settings.rs:1437`; `category.rs:522`; `section.rs:542`; `admin/mod.rs:663`; `rsvp_buttons.rs:72`; `create_event_modal.rs:176`). The governance path does not use it: `pages/governance.rs:209` and `:319` call plain `relay.publish(&signed)` and then set `sent.set(true)` / `response_sent.set(true)` on the very next line, so the UI reports "Sent" the moment the event signs, not when the relay accepts it. `GET /api/governance/decisions` does not exist: the nine documented governance routes (`crates/nostr-bbs-auth-worker/src/governance_api.rs:7-15`, `crates/nostr-bbs-auth-worker/src/lib.rs:492-529`) carry no decisions route, though the `broker_decisions` table with `outcome`, `reasoning` and `prior_decision_id` columns is `integrated` server-side (`relay-worker/src/lib.rs:701-710`). `ActionEntry` (`stores/panel_registry.rs:23-27`) carries `reasoning: Option<String>` and no `confidence` or `risk_tier` field.

Target maturity: `integrated`. The governance publish path uses `publish_with_ack` with an on-OK callback that flips the sent state only on relay acceptance and raises a rejection state on `accepted = false`. A tenth governance route, `GET /api/governance/decisions`, reads `broker_decisions` (mirroring `handle_list_cases`). The panel schema gains `confidence` and `risk_tier` fields displayed at decision time (ADR-106 Decision 5).

Acceptance criteria:
- A relay-rejected 31403 (`OK false`) flips the client from optimistic "Sent" to a visible rejection state; the state never advances on sign alone.
- `GET /api/governance/decisions` returns a persisted `broker_decisions` row to an authed operator, with `outcome`, `reasoning` and `prior_decision_id`.
- A panel displays the agent's `confidence` and `risk_tier` at decision time, sourced from the 31402 ActionRequest.

Falsification statement: *WP-3 is falsified if a relay-rejected decision still reads as "Sent", if `publish` is still called fire-and-forget on the governance path, if the decisions read route is absent while `broker_decisions` holds rows, or if the panel shows no confidence at decision time.*

Canaries:
- `forum-canary-ack-reject` — observes a relay-rejected 31403 flipping the UI out of "Sent" through the `publish_with_ack` callback. Firing means the optimistic-send illusion is closed.
- `forum-canary-decisions-read` — observes `GET /api/governance/decisions` returning a persisted `broker_decisions` row to an authed operator. Firing means the decision-audit read API is live.

### WP-4 — Graduated escalation (COM-16/F3/F7)

Current maturity: `scaffolded` for the orchestrator, `planned` for risk-tiering and the approval-fatigue response. `broker::DecisionOrchestrator` (`crates/nostr-bbs-core/src/governance.rs:574-602`) implements `decide()` over `DecisionOutcome::{Approve, Reject, Amend, Delegate, Promote, Precedent}` (`governance.rs:357-364`) and `CaseState::{Open, UnderReview, Decided, Delegated, Promoted, Precedent, Closed}` (`governance.rs:333-341`), with `record_decision` fully tested (`governance.rs:832-1164`). It has zero consumers: a search outside `nostr-bbs-core` returns nothing. The 31403 projection publishes only `{"action", "reasoning"}` for whatever action the panel declared (`pages/governance.rs:188-192,296-300`), so `delegate`/`promote`/`precedent` are dead code from the application's view. No `risk_tier` or escalation-suppression symbol exists anywhere in the repository; risk-tiering is greenfield, not partial.

Target maturity: `integrated`. The relay's 31403 projection (`relay_do/nip_handlers.rs`) routes a parsed non-binary action through `DecisionOrchestrator::decide` and persists the outcome to `broker_decisions`. A `risk_tier` field on the 31402 PanelDefinition/ActionRequest lets the panel Memo suppress low-risk panels from the member surface, which is this slice's design answer to approval fatigue (F7): a member sees only the panels a risk tier says warrant attention (ADR-106 Decision 4).

Acceptance criteria:
- A 31403 carrying `delegate`, `promote` or `precedent` reaches `DecisionOrchestrator::decide` and persists a `broker_decisions` row whose `outcome` matches, moving the case to the matching `CaseState`.
- At least three distinct decision outcomes (beyond Approve/Reject) are reachable end to end.
- A panel tagged low risk is suppressed from the member panel Memo; a documented risk tier drives the suppression.

Falsification statement: *WP-4 is falsified if a non-binary action still parks a case in `under_review` forever, if `DecisionOrchestrator` still has zero callers outside `nostr-bbs-core`, or if no risk tier suppresses any low-risk panel.*

Canary: `forum-canary-escalation-outcome` — observes a 31403 carrying a non-binary outcome reaching `DecisionOrchestrator::decide` and persisting a matching `broker_decisions` row. Firing means the escalation lifecycle is no longer dead code.

### WP-5 — Roster admin (F8)

Current maturity: `planned`. Exactly nine agent-roster endpoints exist and are `integrated` server-side (`crates/nostr-bbs-auth-worker/src/lib.rs:492-529`): `GET agents`, `POST agents/register`, `POST agents/provision`, `POST agents/revoke`, `GET cases`, `GET cases/:id`, `POST roles/grant`, `POST roles/revoke`, `GET roles`, documented at `governance_api.rs:7-15`. No client calls any of them: a search of both client crates for `api/governance` returns zero hits, and no Agents tab exists under `forum-client/src/pages/` or `/admin/`.

Target maturity: `integrated`. An Agents admin tab (mirroring `admin/section_requests.rs`) calls the nine endpoints via NIP-98-signed fetch, mounted inside `AdminGatedGovernance` or a sibling admin route.

Acceptance criteria:
- The Agents tab lists the current roster from `GET /api/governance/agents`.
- An admin register or revoke action round-trips through the matching endpoint and the roster list reflects the change without a manual reload of a different tool.
- Each call carries a valid NIP-98 signature; an unsigned or non-admin call is rejected server-side.

Falsification statement: *WP-5 is falsified if roster administration still requires an out-of-band tool, if the client issues no call to any of the nine endpoints, or if a roster mutation is not reflected in the tab after it returns.*

Canary: `forum-canary-roster-roundtrip` — observes the Agents tab issuing a NIP-98-signed call to one of the nine endpoints and the roster list reflecting the mutation. Firing means the roster admin UI reaches the server.

### WP-6 — NIP-42 reconciliation (REC-1 sub-item)

Current maturity: `integrated`, already reconciled. NIP-11 advertises `auth_required: false` deliberately (`crates/nostr-bbs-relay-worker/src/nip11.rs:126,133-149`) with a namespaced `nostr_bbs.write_policy` block (`model: "whitelist"`, `nip42_challenge_sent: true`, `nip42_required_for_write: false`) that documents the mechanism for API consumers. The relay does send a NIP-42 AUTH challenge on connect and tracks an authed pubkey (`relay_do/mod.rs:149,242`; `session.rs:24-26,283-287`), but the write gate is `is_whitelisted(pubkey)`, independent of the AUTH round-trip. This is an intentional, documented reconciliation present in git history and unmodified by the base branch. `CLOSEOUT-SECURITY-AUDIT.md` records the same finding.

Target maturity: `integrated`, with the canon wording aligned. No forum code change is warranted. The action is to ratify the shipped reconciliation at the VisionFlow canon so the canon no longer implies a completed AUTH round-trip gates writes (ADR-106 Decision 7). Performing a redundant AUTH-gated-write change would alter the shipped whitelist model, which ADR-004 does not mandate.

Acceptance criteria:
- The canon's NIP-42 wording states the enforced mechanism (whitelist-gated writes, AUTH challenge sent but not required for write), matching `nip11.rs`.
- The forum introduces no behavioural change to the write gate under this item.

Falsification statement: *WP-6 is falsified if the canon still claims an authenticated signer gates writes while the relay advertises `nip42_required_for_write: false`, or if this slice silently changes the shipped write model to force the claim true.*

Canary: `forum-canary-nip42-conformance` — a conformance probe, not a live-traffic canary: it observes that the advertised `write_policy` equals the enforced gate (`is_whitelisted`, independent of AUTH state). Firing means advertised claim and enforced mechanism agree.

### WP-7 — Supersession authority (F6), canon-dependent

Current maturity: `planned`. No supersede, appeal or revoke concept exists for a published decision: a search across `governance.rs`, `governance_api.rs` and `relay-worker/src/lib.rs` returns nothing. `CaseState` has no `Reopened`/`Superseded` variant. `broker_decisions` is effectively append-only with a `prior_decision_id` link that `record_decision` populates but no path consumes to express supersession. The only `revoke` in the tree is `agents/revoke`, which deactivates an agent pubkey and is unrelated to a decision's lifecycle.

Target maturity for this sprint: `scaffolded`, dependency-gated. The VisionFlow canon owns the supersession-authority specification (meta-PRD, VisionFlow work package, into `DDD-judgment-broker-context`). This slice implements to that specification and does not invent the lifecycle semantics locally (ADR-106 Decision 6). Until the canon spec lands, F6 stays `planned`; on the spec, this slice adds `DecisionOutcome::Supersede { prior_decision_id }` and `CaseState::Reopened` behind an admin-gated `POST /api/governance/decisions/:id/supersede`. It reaches `integrated` only with the canon spec cited and the canary fired. F6 is a P2 item.

Acceptance criteria (activate only on the canon specification):
- A supersede persists a new `broker_decisions` row citing the `prior_decision_id` it revokes and moves the case to `Reopened`.
- The route is admin-gated, matching the existing governance-response admin gate.
- The implementation cites the canon supersession spec by document and section.

Falsification statement: *WP-7 is falsified if this slice defines supersession semantics locally without the canon specification, or if it is claimed closed while `CaseState` still carries no `Reopened`/`Superseded` variant.*

Canary: `forum-canary-supersede` — deferred, dependency-gated. Observes a supersede persisting a revoking `broker_decisions` row and flipping the case to `Reopened`. Registered now; not expected to fire until the canon spec exists.

### WP-8 — Federation (F9), standalone-first, no build this sprint

Current maturity: `planned` for transport, `scaffolded` for the allow-list gate. `wrangler.toml` sets `MESH_MODE = "standalone"`, an empty `MESH_PEER_RELAYS`, and `MESH_FEDERATED_KINDS` covering 31400–31405 plus 38000/38100 (`relay-worker/wrangler.toml:23-26`). `is_federated_kind_allowed` and `is_mesh_peer` are wired into the incoming-event path (`nip_handlers.rs:213,1379-1429`), but `is_mesh_peer` always returns false under the shipped `standalone` default with no configured peers. `nostr-bbs-mesh` defines only the `MeshTransport` trait (`src/lib.rs:84`, 123 lines, no implementation); `CLOSEOUT-SECURITY-AUDIT.md:254` records it as an unshipped scaffold with no cross-instance AUTH trust boundary enforced.

Target maturity: stays `planned`. Federation is parked standalone-first per ecosystem-map G2 and the meta-PRD Non-Goals. This slice builds no `MeshTransport` unless the canon's P2 rescope-or-build fork resolves to build (ADR-106 Decision 8). If it does, the item moves `scaffolded → integrated` on live replication evidence.

Acceptance criteria (activate only on a canon build decision):
- A `MeshTransport` implementation replicates a signed governance kind from one relay to a federated peer, verified live.
- `MESH_MODE`, `MESH_PEER_RELAYS` and `MESH_ALLOWED_REMOTE_DIDS` are set for at least one federated pair.

Falsification statement: *WP-8 is falsified if this slice claims federation `integrated` while `MeshTransport` remains trait-only and `MESH_MODE` stays `standalone`, or if it builds a transport before the canon fork resolves to build.*

Canary: `forum-canary-federation-replicate` — deferred. Observes a governance kind signed on relay A appearing on relay B through a live `MeshTransport`. Registered now; stays unfired under the standalone-first freeze.

### WP-9 — Escalation-default projection (REC-6 share), agentbox-dependent

Current maturity: `planned`. No relay-side projection of escalation defaults exists: a search for `risk_tier`/`escalation_default`/`default_escalation` across all crates returns nothing, and no config surface (`forum.example.toml`, `wrangler.toml`) expresses a default authority-boundary posture.

Target maturity: `scaffolded`, dependency-gated. REC-6's primary owner is agentbox. This slice's share exposes whatever escalation-default schema agentbox settles on as a relay-side NIP-11 `nostr_bbs` block field or a new governance event kind, projected the way governance kinds are gated today (`nip_handlers.rs:341-355`). It stays `planned` until agentbox's authority model lands.

Acceptance criteria (activate on the agentbox schema):
- The relay projects the agentbox escalation-default schema in a NIP-11 `nostr_bbs` block or a governance kind.
- The projection is gated identically to the existing governance kinds.

Falsification statement: *WP-9 is falsified if this slice invents an escalation-default schema divergent from agentbox's, or claims closed while no relay surface projects it.*

Canary: `forum-canary-escalation-default-projection` — deferred. Observes the relay projecting agentbox's escalation-default schema. Registered now; unfired pending the agentbox authority model.

### WP-10 — Discovery surface (REC-10 share), upstream-dependent

Current maturity: `planned`. No agent-discovery surface exists: a search for discovery across crates and docs returns only unrelated storage-backend hits in `pod-worker`. NIP-89 is absent from the supported NIPs (`nip11.rs:126`: `[1,9,11,16,29,33,40,42,45,50,56,59,65,98]`).

Target maturity: `planned`, dependency-gated. REC-10's discovery contract is defined by VisionClaw and agentbox (Insight Ingestion Loop v1). This slice's likely share is a NIP-89-style kind advertised via `agent_registry`/NIP-11 once that contract exists. It is not sized further until the contract lands.

Acceptance criteria (activate on the Insight Loop v1 contract):
- A NIP-89-style discovery kind advertised from `agent_registry`/NIP-11 is fetchable by a mesh consumer.

Falsification statement: *WP-10 is falsified if this slice ships a discovery kind before the Insight Loop v1 contract defines it, or claims closed while no discovery surface exists.*

Canary: `forum-canary-discovery-surface` — deferred. Observes a NIP-89-style discovery kind fetchable from `agent_registry`/NIP-11. Registered now; unfired pending the contract.

## Maturity summary

| Item | Current | Target (this sprint) | Wave | Loop-closing |
|---|---|---|---|---|
| F1 member read-only view | planned | integrated | P1 | yes |
| COM-13/F2 disclosure badge | planned | integrated | P0 | yes |
| COM-16/F3/F7 escalation + risk-tiering | scaffolded (orchestrator) / planned (tiering) | integrated | P1 | yes |
| COM-17/F4 publish_with_ack | planned | integrated | P1 | yes |
| COM-17/F5 decisions read API + schema | planned | integrated | P1 | yes |
| F8 roster admin tab | planned | integrated | P1 | yes |
| REC-1 NIP-42 | integrated (reconciled) | integrated (canon aligned) | P0 | conformance |
| F6 supersession | planned | scaffolded (canon-gated) | P2 | deferred |
| F9 federation | planned / scaffolded (gate) | planned (no build) | P2 | deferred |
| REC-6 escalation-default projection | planned | scaffolded (agentbox-gated) | P1/P2 | deferred |
| REC-10 discovery surface | planned | planned (upstream-gated) | P2 | deferred |

No item is claimed above the tier its evidence supports. Risk-tiering (WP-4) and the escalation-default projection (WP-9) are greenfield and labelled `planned`, not folded into a closed parent. F6, F9, REC-6 and REC-10 are dependency-gated and stay below `integrated` until their upstream lands.

## Evidence and verification

Closure carries an execution receipt (command, raw output, timestamp, git SHA) per ADR-004 Decision 2. The canonical commands (CONTRIBUTING.md):
- `cargo test --workspace` — full suite.
- `cargo test -p nostr-bbs-core governance` — exercises `DecisionOrchestrator`/`CaseState` directly (WP-4 domain floor).
- `cargo check --target wasm32-unknown-unknown -p nostr-bbs-forum-client` — client check (a local secp256k1 toolchain issue is clean in CI; native `cargo check` also passes).

Verification is anti-fox (ADR-004 Decision 6): the party confirming a closure is not the one that produced it and sits on a different model family, running at least one counter-example probe per the falsification statements above. A green canary is the difference between `integrated` and a claim (ADR-004 Decision 3).

## Wave gating

WP-2 (COM-13) and WP-6 (NIP-42) sit in P0 and gate nothing above them until their canaries are green. WP-1, WP-3, WP-4, WP-5 are P1 and open only when P0's canaries fire. WP-7, WP-8 are P2. WP-9 and WP-10 are dependency-gated and enter their wave only when the upstream contract exists (DDD Gap-Close, Invariant 7).

## Cross-reference

- Governance kinds: 31400 PanelDefinition, 31401 PanelState, 31402 ActionRequest, 31403 ActionResponse, 31404 PanelUpdate, 31405 PanelRetired/AuditLog (`nostr-bbs-core/src/governance.rs:27-34,203`).
- Federation kinds: 38000, 38100 (allow-listed, inert; `wrangler.toml:23-26`).
- Identity: `did:nostr:<hex-pubkey>`, ADR-125 Multikey form, canonicalised upstream in `did.rs` (consumed as a principal string only).
- Tables: `agent_registry` (`relay-worker/src/lib.rs:673-681`), `broker_cases`, `broker_decisions` (`:701-710`), `broker_roles`.
