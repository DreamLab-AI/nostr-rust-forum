---
id: ADR-2035
title: A kanban agent column dispatches its cards to a registered agent, and the agent's result returns as a governed case
date: 2026-11-23
decision_status: proposed
implementation_status: partial
activation_status: inactive
supersedes: []
superseded_by: []
verified_commit: c8b8c4e
owner: jjohare
review_trigger: ADR-2024 reaching `enforce`; the relay approval-column finding (FORUM-KANBAN-APPROVAL-COL-CLIENT-ONLY) closing; the first deployment that sets agentbox `[sovereign_mesh.relay].intent_command`
repo: nostr-rust-forum
evidence_class:
acceptance_boundary:
---

# ADR-2035 — A kanban agent column dispatches its cards to a registered agent, and the agent's result returns as a governed case

## Context
- The parts of a shared agent workflow already exist: zone boards and cards (30301/30302, `kanban.rs`), approval columns that turn a move into a kanban-tagged 31402 (`APPROVAL_COL_TAG`, `kanban.rs:72`), and a 38000 agent intent (`create_agent_intent_signer`, `kanban.rs:802`).
- Dispatch is manual and runs one way. "Send to agent" asks for a pasted 64-hex pubkey (`board.rs:1316`) although the registry is listed at `GET /api/governance/agents` (`auth-worker/src/lib.rs:511`). Nothing in agentbox reads or writes 30302, so a result never reaches the card.
- The intent carries no `actor` tag, so agentbox's `resolveActorRef` takes the actor from the `a` coordinate, which is the card's own d-tag (`agentbox mcp/nostr-bridge/default-intent-spec.js:45`). This is filed as finding AB-INTENT-ACTOR-FROM-CARD-DTAG.
- The approval-column gate exists only in the client. The relay exempts kanban 31402s from the agent-registry gate (`nip_handlers.rs:1349`) but never checks that a card version naming an approval column carries an approved move. This is filed as finding FORUM-KANBAN-APPROVAL-COL-CLIENT-ONLY.
- Industry guidance on shared agent workflows (recurring, verifiable, cheaply reversible work run as a shared system with scrutiny) matches the broker that the forum's 31400–31405 surface already provides: tiers from task properties, calibration sampling, seeded probes and receipts. What is missing is the loop that connects the board to that broker.
- A qualitative field study of 58 companies adopting AI (Anthropic Economics, "Working with AI", 23 November 2026) found that reviewing AI output was the recurring bottleneck: "Without the proper scaffolding in place, that bottleneck is immediate." An agent column can dispatch faster than people decide its cases, so review capacity has to be visible.
- ADR-2024, cited below, is proposed and not on main: it lives on branch `docs/adr-2024-panel-binding`, verified only at `a76c3233`. The rules this record takes from it hold only once it lands.

## Decision
1. **Agent column.** A board may declare `["agent_col", <col-id>, <agent-pubkey>, <prompt-ref>]`. `<prompt-ref>` is an `https` URL plus `#sha256=<hex>` naming a prompt version held in a pod (solid-pod-rs ADR-2012). The tag is honoured only when the board's author is a board maintainer who is not `<agent-pubkey>`, and `<agent-pubkey>` is an active row in `agent_registry`. The ADR-2024 rule applies: an agent never configures its own dispatch.
2. **Dispatch.** When a card enters an agent column, the client of the person who moved it signs the 38000 intent. The intent carries `p` = agent, `["actor", <agent-pubkey>]`, `a` = card coordinate and `["prompt", <prompt-ref>]`. The person who started a run is therefore its signer of record. Manual "Send to agent" stays, but picks from the registry instead of taking a pasted key.
3. **Return path.** An agent column must be followed directly by an approval column (`approval_col`), and the board is refused at validation otherwise. The agent finishes by republishing the card into that column with `["result", <url>#sha256=<hex>]` and `["run", <run-record-url>]`, which raises the existing kanban-tagged 31402. Every agent output therefore becomes a case. The `pending_move` flow is reused unchanged.
4. **Tier.** The case's task properties come from `tp-*` tags that the maintainer places on the board for that approval column, never from the agent. With none present, the operator's advertised default is the floor (ADR-2024 Decision 3). Calibration sampling, seeded probes, rationale and receipts apply as for any 31402.
5. **Activation order.** A deployment enables agent columns only after AB-INTENT-ACTOR-FROM-CARD-DTAG and FORUM-KANBAN-APPROVAL-COL-CLIENT-ONLY are closed and ADR-2024 runs at `enforce`. The board feature stays default-off behind `[features].kanban_agent_columns`.
6. **Review measurement.** The board shows, for each approval column, the number of open undecided cases and the median decision time over its last 30 decided cases. Decision time is the deciding 31403's `created_at` minus its 31402's `created_at`. Both are already signed, so this adds no tag and no event kind. The figures are visible to board maintainers and to the operator, and they are the input to any later throughput rule.

## Consequences
- Boards become shared, reviewable agent workflows without a second governance system. The broker's existing tiers, probes and receipts govern agent output.
- Each run leaves a trail: a human-signed intent, an agent-signed card version naming its result and run record, a signed 31403 and an `applied` receipt.
- Costs: board validation in core and the client; a registry picker; relay enforcement of approval columns (the linked finding); an agentbox responder that republishes 30302 (agentbox work, outside this repository).
- Dispatch is emitted by the client. A move made from a third-party client that does not implement this ADR raises no intent. An agent-side subscription to its own columns is the fallback if that proves material, and would need its own record.
- Prompt versions and evals live in pods (solid-pod-rs ADR-2012), not in new Nostr kinds. This repository adds no event kind.
- Open question, not decided here: review backpressure (holding dispatch while an approval column's backlog is high). Dispatch is client-signed, so a client-side limit would be a courtesy, not a guarantee, and would repeat the weakness filed as FORUM-KANBAN-APPROVAL-COL-CLIENT-ONLY. It gets its own record, enforced by the relay or the agent, only if Decision 6's figures show a backlog forming.
- Proposed, so it does not change BASELINE-architecture.md. The invariants are written there on acceptance.

## Verification
- At `c8b8c4e`: `rg -n "approval_col|pending_move|column_needs_approval" crates --glob '!**/kanban.rs' --glob '!**/forum-client/**'` returns only the core re-export (`nostr-bbs-core/src/lib.rs:116`), so the relay holds no approval-column check.
- From `988873b`, `create_agent_intent_signer` (`kanban.rs`) builds the intent tags `p`, `actor` (= the agent key), `a`, `board` and `card_d`; a unit test pins `actor` equal to `p` and never the card d-tag, which closes AB-INTENT-ACTOR-FROM-CARD-DTAG on the producer side. The `prompt` tag is not built. `board.rs:1316` accepts only a 64-character key.
- `rg -n "30302|kanban" agentbox/mcp/nostr-bridge` returns nothing at agentbox `59b1aca1c`, so there is no return path.
- `implementation_status: partial`: nothing in the Decision is built.
