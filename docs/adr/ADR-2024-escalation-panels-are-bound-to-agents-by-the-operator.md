---
id: ADR-2024
title: Escalation panels are bound to agents by the operator, never selected by the request
date: 2026-10-19
decision_status: proposed
implementation_status: none
activation_status: inactive
supersedes: []
superseded_by: []
verified_commit:
owner: DreamLab-AI/nostr-rust-forum maintainers
review_trigger: Before any deployment sets GOVERNANCE_PANEL_BINDING=enforce; or when a second operator deploys [governance]
repo: nostr-rust-forum
---

# ADR-2024 — Escalation panels are bound to agents by the operator, never selected by the request

## Context
- ADR-2011 Decision 2 says a declared `risk_tier` carries no authority alone; the escalation boundary comes from operator-held task properties on a panel (31400).
- The requesting agent chooses which panel a 31402 cites (`a` tag, `nip_handlers.rs` resolve_panel_tags ~L2391-2443), and the fallback uses the agent's own latest panel, which it can republish looser at any time (NIP-33).
- An agent that cites no panel keeps its own declared tier: `governance.rs` effective_tier ~L527 `(Some(declared), None) => declared`. An allow-list of panels cannot close this, because the escape is citing nothing.
- Appeals have the same shape flaw: `project_appeal` takes the case from the `d` tag (~L3088), so a requester's appeal with `d = case_id` replaces its own signed 31402, against ADR-2010's verifiable signed history. No producer emits appeals today.
- DreamLab's JunkieJarvis authors the dream-machine 31400 and raises the 31402s (`forum-config/dreamlab.toml` [governance]), so under this ADR its panel cannot be its own binding.

## Decision
1. An agent's escalation panel is the one an admin binds to it at registration (`agent_registry.panel_address`, migration 0011 and `ensure_schema`). The auth-worker register endpoint accepts the binding and refuses a panel whose author pubkey is the agent's own. A panel is never authored by the agent it governs.
2. Request `a`/panel tags are ignored for tiering. `resolve_panel_tags` reads the binding.
3. With no bound panel, the operator's advertised default tier is a floor: `effective_tier` returns `max(advertised_default, result)`. Agent inputs can only raise a tier, never lower it.
4. Rollout is two-phase, by the relay var `GOVERNANCE_PANEL_BINDING`: `warn` computes both the legacy and the bound answer, stores the legacy one and logs divergence; `enforce` stores the bound one. Decision 3 cannot sit behind the flag (effective_tier is a pure function shared with the client's compute_boundary), so it ships only with `enforce`.
5. Appeal wire shape: an appeal-marked 31402 carries a fresh `d`, a `["case", <case_id>]` tag and `["e", <decision>, "", "appeal"]`. An appeal whose `d` equals its case, or with no `case` tag, is refused at ingest (`blocked: appeal_shape`). The client treats an appeal-marked 31402 as a case event, not a new pending case.
6. Standing: only the case's requester of record (`broker_cases.created_by`) may appeal, citing a decision on that same case while the case is in a terminal state. Deciders and admins supersede instead (ADR-2010 §7a).

## Consequences
- Closes the self-chosen escalation boundary. An agent can no longer declare a `low` case away from member review by citing nothing or by republishing a looser panel.
- **Breaks DreamLab as configured.** With `ESCALATION_DEFAULT_TIER=medium`, JunkieJarvis's low cases stop being member-suppressed until an operator key publishes the panel and an admin binds it. The agentbox panel publisher moves to the operator key. Rollout: `warn` first, then `enforce` with Decision 3.
- Before `enforce`, check whether the live dream-machine 31400 carries `tp-*` tags; if not, Decision 3 alone moves JunkieJarvis's low cases to medium on the next kit pin.
- Appeal receipts (decision_id NULL) reach the client reducer (`stores/receipts.rs` ~L106) and `GET /api/governance/receipts`; `reduce_case` must tolerate a non-31403 row.
- Amends ADR-2011 Decisions 2 and 3 (related, not superseded). ADR-2010's known-findings rows for the appeal and supersession paths move from "not receipt-wired" to wired once the companion code lands.
- Out of scope, shipped as code-only under ADR-2010 §7a before this ADR is accepted: supersession case binding and atomic commit; appeal standing check and the `appeal_shape` ingest refusal (Decision 5's refusal half). Until this ADR lands, a `d = case` appeal is refused rather than allowed to overwrite the original request; nothing is lost because nothing produces appeals.

## Verification
- `governance.rs` task_property_tests: `declared_low_without_panel_folds_up_to_advertised_default` (the existing `(Some(d), None)` table rows flip; intended).
- `nip_handlers.rs` augmentation_boundary_tests: `request_a_tag_cannot_select_a_looser_panel_than_the_binding`, `unbound_agent_cannot_tier_below_advertised_default`; auth-worker: `self_authored_panel_binding_is_refused`.
- A `warn`-phase deployment log showing zero divergence on DreamLab's live cases before `enforce` is set.
