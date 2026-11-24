---
id: ADR-2024
title: Escalation panels are bound to agents by the operator, never selected by the request
date: 2026-10-19
decision_status: proposed
implementation_status: partial
activation_status: inactive
supersedes: []
superseded_by: []
verified_commit: 4a9b4ff
owner: DreamLab-AI/nostr-rust-forum maintainers
review_trigger: Before any deployment sets GOVERNANCE_PANEL_BINDING=enforce; or when a second operator deploys [governance]
repo: nostr-rust-forum
evidence_class: source
acceptance_boundary: Established at 4a9b4ff, by reading the cited lines and running the rg commands under Verification - Decisions 1 to 4 and the client half of Decision 5 are not built; Decision 5's ingest refusal and Decision 6's standing check are built (ec33b96, merged 6216145). No test or build was run for this record. Not established - the live dream-machine 31400's tags, and the ESCALATION_DEFAULT_TIER that DreamLab's deployed relay runs with.
---

# ADR-2024 — Escalation panels are bound to agents by the operator, never selected by the request

## Context
- ADR-2011 Decision 2 says a declared `risk_tier` carries no authority alone; the escalation boundary comes from operator-held task properties on a panel (31400).
- The requester chooses which panel a 31402 cites. `resolve_panel_tags` (`nip_handlers.rs:3925-3986`) honours an `a` address naming any author's 31400 (:3940), then a `panel` tag (:3948), then the requester's own latest panel (:3966), which it can republish looser at any time (NIP-33).
- A requester that cites no panel keeps its own declared tier: `governance.rs` `effective_tier` (:564) has `(Some(d), None) => d` (:576). An allow-list of panels cannot close this, because the escape is citing nothing.
- Appeals. Commit ec33b96 (merged 6216145, 2026-10-19, after this record was first written) fixed the shape flaw this record described. An appeal-marked 31402 whose `case` tag is missing or equals its `d` is refused at ingest (`appeal_shape_refused` :845, gate :1436-1445). `project_appeal` (:4699) reads the case from the `case` tag (:4717-4718). `plan_appeal` (:817-838) limits standing to the requester of record (KF-12). Still open: the receipt is keyed on the appeal's own `d` (`receipts.rs:337-339`), and the client lists an appeal as a new pending case (`panel_registry.rs:268-323` does not check the marker). At 4a9b4ff nothing in this repository or agentbox emits an appeal.
- Since PR #103 (4a9b4ff) a member's kanban 31402 is exempt from the agent-registry gate (:1358-1362). It still projects through `project_action_request` and `resolve_panel_tags` (:1754-1766, :4010), so requesters are no longer only registered agents. The kanban approval gate (KF-36, `kanban_gate.rs`) reads raw events and does not use tiers. KF-37: kanban decisions never join their case.
- `response_admission` admits any admin for any case (:308-323, called at :1388). DreamLab's requesting agents hold the admin flag (KF-12), so an operator binding constrains them only after the admin key split (dreamlab-ai-website ADR-2012 activation step 2(a)).
- DreamLab's JunkieJarvis authors the dream-machine 31400 and raises the 31402s (dreamlab-ai-website `forum-config/dreamlab.toml:280-284` at 63c9fd9e), so under this ADR its panel cannot be its own binding.

## Decision
1. An agent's escalation panel is the one an admin binds to it at registration (`agent_registry.panel_address`, added by a new relay migration and `ensure_schema`). The auth-worker register endpoint accepts the binding and refuses a panel whose author pubkey is the agent's own. A panel is never authored by the agent it governs.
2. Request `a`/panel tags are ignored for tiering. `resolve_panel_tags` reads the binding.
3. With no bound panel, the operator's advertised default tier is a floor: `effective_tier` returns `max(advertised_default, result)`. Agent inputs can only raise a tier, never lower it.
4. Rollout is two-phase, by the relay var `GOVERNANCE_PANEL_BINDING`: `warn` computes both the legacy and the bound answer, stores the legacy one and logs divergence; `enforce` stores the bound one. Decision 3 cannot sit behind the flag (effective_tier is a pure function shared with the client's compute_boundary), so it ships only with `enforce`.
5. Appeal wire shape: an appeal-marked 31402 carries a fresh `d`, a `["case", <case_id>]` tag and `["e", <decision>, "", "appeal"]`. An appeal whose `d` equals its case, or with no `case` tag, is refused at ingest (`blocked: appeal_shape`). The client treats an appeal-marked 31402 as a case event, not a new pending case.
6. Standing: only the case's requester of record (`broker_cases.created_by`) may appeal, citing a decision on that same case while the case is in a terminal state. Deciders and admins supersede instead (ADR-2010 §7a).

## Consequences
- Closes the self-chosen escalation boundary. An agent can no longer declare a `low` case away from member review by citing nothing or by republishing a looser panel.
- Member kanban requests have no binding, so Decision 3's floor governs them. ADR-2035 Decision 4 relies on that floor.
- **Breaks DreamLab as configured.** With `ESCALATION_DEFAULT_TIER=medium` (the kit default, `wrangler.toml:78`), JunkieJarvis's low cases stop being member-suppressed until an operator key publishes the panel and an admin binds it. The agentbox panel publisher moves to the operator key. Rollout: `warn` first, then `enforce` with Decision 3. The kanban approval gate uses the same warn/enforce pattern (`KANBAN_APPROVAL_GATE`, `wrangler.toml:25`) under a separate var.
- Before `enforce`, check whether the live dream-machine 31400 carries `tp-*` tags; if not, Decision 3 alone moves JunkieJarvis's low cases to medium on the next kit pin.
- Appeal receipts (decision_id NULL) reach `GET /api/governance/receipts` and the client reducer (`stores/receipts.rs` `reduce_case` :199, not yet wired, `#[allow(dead_code)]`); `reduce_case` must tolerate a non-31403 row.
- Amends ADR-2011 Decisions 2 and 3 (related, not superseded). ADR-2010's known-findings rows for the appeal and supersession paths move from "not receipt-wired" to wired once the companion code lands.
- Shipped as code-only under ADR-2010 §7a before this ADR is accepted (ec33b96, merged 6216145): supersession case binding and atomic commit; Decision 6's standing check; Decision 5's `appeal_shape` ingest refusal. A `d = case` appeal is therefore refused rather than allowed to overwrite the original request.

## Verification
At 4a9b4ff:
- Not built: `rg -n 'GOVERNANCE_PANEL_BINDING|panel_binding' crates` finds nothing. `agent_registry` has no `panel_address` column (`relay-worker/src/lib.rs:1323-1331`, `migrations/0002_governance.sql:5-13`). The `(Some(d), None) => d` arm stands (`governance.rs:576`). `resolve_panel_tags` still reads request tags (:3940, :3948).
- Built: `rg -n 'fn appeal_shape_refused|fn plan_appeal|blocked: appeal_shape' crates` gives `nip_handlers.rs:817`, `:845` and `:1443`. Tests: `appeal_projection_tests` (:5653) and the shape assertions at :5823-5834.
- Decision 4's premise holds: the client's `compute_boundary` (`governance_view.rs:227`) calls core `effective_tier` (:242).
- Existing test whose rows Decision 3 flips: `effective_tier_table_holds_for_every_triple_and_tier` (`governance.rs:3301`).
- Planned tests, not yet written: `governance.rs` task_property_tests `declared_low_without_panel_folds_up_to_advertised_default`; `nip_handlers.rs` augmentation_boundary_tests `request_a_tag_cannot_select_a_looser_panel_than_the_binding` and `unbound_agent_cannot_tier_below_advertised_default`; auth-worker `self_authored_panel_binding_is_refused`.
- Before `enforce`: a `warn`-phase deployment log showing zero divergence on DreamLab's live cases.
