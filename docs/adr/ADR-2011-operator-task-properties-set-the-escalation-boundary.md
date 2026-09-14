---
id: ADR-2011
title: Operator-declared task properties set the escalation boundary, not the requesting agent's self-tier
date: 2026-09-14
decision_status: accepted
implementation_status: partial
activation_status: inactive
supersedes: []
superseded_by: []
verified_commit: 81aa0d9
owner: jjohare
review_trigger: nostr-bbs-core publishing TaskProperties to crates.io, or a probe-blindness scheme that survives raw-event inspection
repo: nostr-rust-forum
---

# ADR-2011 — Operator-declared task properties set the escalation boundary, not the requesting agent's self-tier

## Context

A 31402 `ActionRequest` carried one boundary signal, `risk_tier`, declared by the requesting agent, with the doc comment "the agent's declaration stands". No relay or human path re-tiered it. The relay advertised `ESCALATION_DEFAULT_TIER=medium` and `ESCALATION_DEFAULT_POSTURE=escalate_to_human` in NIP-11 (`wrangler.toml:48-49`) and enforced neither. The party with the strongest incentive to under-tier was the only party that tiered. arXiv 2609.12482 sets the human–agent boundary by three properties of the *task* — verifiability, reversibility, stakes — not by the actor's self-assessment. This ADR is the forum's implementation of canon [VisionFlow ADR-2011](https://github.com/DreamLab-AI/VisionFlow) and the FR3/FR4/FR6/FR7 substrate work of PRD-augmentation-conditions. It builds on [ADR-2010](ADR-2010-durable-governance-outcome-receipts.md), whose receipt ladder it extends past `projection-committed`.

## Decision

1. **`nostr-bbs-core` owns the triple.** `TaskProperties { verifiability: Inspectable|Partial|Opaque, reversibility: Reversible|Compensable|Irreversible, stakes: Bounded|Significant|Critical }`, carried as tags `tp-verifiability` / `tp-reversibility` / `tp-stakes` on a 31400 `PanelDefinition` (the operator's declaration) and optionally on a 31402 (the agent's restatement). `TaskProperties::merge` is a per-axis `max` over enums whose declaration order **is** the tightness order, so "a request may tighten but never loosen" is structural rather than a rule that has to be remembered.
2. **`effective_tier(panel_props, request_props, declared, advertised_default)` is pure and total.** `Irreversible` reversibility or `Critical` stakes floors the case at `High`; `Opaque` verifiability floors it at `Medium` and forbids member suppression outright; a request that declares nothing at all folds to the relay's advertised default rather than to an accidental `Medium`. `risk_tier` survives as the agent's declaration for telemetry and carries no authority alone.
3. **The relay computes the boundary once and stores it.** `project_action_request` resolves the request's panel, computes the tier, and writes `broker_cases.effective_tier` together with the merged triple and the declared tier. Every consumer reads that column; there is nowhere else to look for a suppression or routing decision.
4. **A high or critical case is resolved only by a human, who must say why.** `plan_action_response` refuses a 31403 whose `decided_by` names a `system:` actor when the case's effective tier is `High` or `Critical`. The same tier threshold carries FR2.2: a 31403 with outcome `approve | reject | amend | delegate` on such a case must carry a rationale of at least `MIN_HUMAN_RATIONALE_CHARS` (20) Unicode scalars after trimming, refused **before `save_event`** with the token `rationale_required`. This is a relay rule rather than a client one because a 31403 is a signed event any script can publish directly; a rationale requirement that lives only in the forum UI does not deliver "a human formed this judgement". Nothing fills a rationale in — absence is refused.
5. **The receipt ladder extends past projection.** `ReceiptStage` moves into `nostr-bbs-core` and gains `consumer-received`, `applied`, `not-applied`, `applied-manually`, plus `escalated-on-age` and `expired` as side receipts that never advance the ladder. `can_advance_stage` enforces monotonicity; `applied-manually` is exempt from the `consumer-received` precondition because the outage path it serves has no consumer by construction.
6. **Delegation is scoped, sampling is deterministic, probes are withheld.** A `reviewer`-role pubkey decides exactly the cases an admin `Delegate`d to it, via a `case_delegations` row. A panel's `calibration-sample-rate` (default 0.1) selects otherwise-suppressible cases by `HMAC-SHA256(relay_selection_key, request_id)` and never by the clock. The key is load-bearing, not incidental: the request id is the 31402's `d` tag, which the requesting agent chooses freely, so an unkeyed hash against a published rate would let an agent grind `d` tags until it found one sampling never selects — ADR-2011's own thesis defeated one level down. The key is a Cloudflare secret (`CALIBRATION_SELECTION_KEY`), never a `wrangler.toml` var. A `probe` tag is honoured only from the panel's registered probe agent, is kept out of `event_tags` so no client can enumerate probes by subscription, and is withheld from every REST projection of an undecided case.

## Consequences

- The relay gains a small amount of policy — one pure function and one default — which this ADR records as required by ADR-2006 (canon owns the cross-repo view, substrates own implementation). The schema stays owned by `nostr-bbs-core`.
- Legacy panels and requests keep working: absent `tp-*` tags parse to `None` (distinct from a declared-loosest triple), and a case projected before migration 0006 has no effective tier and is not retro-gated on one.
- Operators must now declare the triple when publishing a panel to get any benefit from it. A panel that declares nothing behaves as before except that its unlabelled requests fold to the advertised default rather than to `medium` by accident.
- Agents that habitually under-tier become measurable: declared-versus-effective divergence is now two columns on the same row.
- **Probe blindness is partial, and this is the reason `implementation_status` is `partial`.** The `probe` tag is removed from the tag index and never re-served in the D1 projection of an undecided case, so no client can query for probes and no governance API response reveals one. The tag nevertheless remains on the raw signed 31402 served over REQ, because removing it would invalidate the signature that both clients verify strictly (`verify_event_strict`) and the probe would vanish entirely rather than render blind. A scheme that survives raw-event inspection — committing to the probe out of band, or encrypting the marker to the relay — is follow-on work and is this ADR's `review_trigger`.
- `reviewer` became a privilege-granting role, which made the pre-existing stale-privilege defect in role revocation material; role grant/revoke now normalise pubkey casing and a revocation that matched no row returns 404 instead of reporting success.

## Implementation notes

### Client (`nostr-bbs-forum-client`)

The forum client is the surface the six conditions are actually experienced on,
and it is where FR2, the FR4.1/FR4.3 display half, and the FR6.2/6.3/6.4 display
half land. The rules live in pure functions with host-target tests rather than in
`view!` macros, so what a reviewer is shown and when they may act is asserted by
`cargo test`, not by reading markup.

- **Pure view logic** — `crates/nostr-bbs-forum-client/src/utils/governance_view.rs`.
  `compute_boundary` (:225) mirrors the relay's `plan_request_boundary` in
  everything **except calibration selection**: the effective tier, the merged
  triple and the probe recognition come from the same `nostr-bbs-core` functions
  over the same signed events, so the client reads a tier it computes
  identically rather than one it guesses. Calibration is the exception and is
  **relay-authoritative**, passed in rather than derived — selection became
  `HMAC-SHA256(selection_key, request_id)` under a secret only the relay holds
  (Decision 6 as amended), precisely because the request id is the 31402's `d`
  tag and its publisher chooses it freely; a key shipped to a browser to let the
  client recompute the flag would be a published key and would restore the hole.
  The flag is read from `broker_cases.calibration_sample` over
  `GET /api/governance/cases` by
  `src/stores/case_projection.rs`, which is `require_authed` (any NIP-98 signer,
  not admin) — as it must be, since calibration samples exist to be shown to the
  member surface. A case the relay has said nothing about is not a sample.
  `rationale_satisfied` (:57) is the FR2.2 gate; `decision_content` (:77) writes
  the reviewer's bytes untrimmed and has no template branch; `visible_probe` (:292)
  is the only path a probe digest can take to the DOM; `card_sections` (:445) makes
  the FR2.1 ordering data; `is_decidable_by` (:399) is the scoped-delegation view
  gate; `relative_age_label` (:304) and `is_overdue` (:328) are FR4.3.
- **Decision card** — `src/pages/governance.rs`. `ActionCardData` (:446) resolves
  each request's panel, boundary and decidability once per render; `card_body_parts`
  (:480) builds every region *except* the controls and `assemble_card` (:652)
  orders them by `card_sections`, which is how the agent's tier and confidence come
  to sit **below** Approve. `ActionRow` (:695) carries the rationale textarea and
  Approve / Reject / Amend / Delegate; `ReadOnlyActionRow` (:1028) renders the same
  context with no signer, relay handle or publish path.
- **Decidability replaces the pure route split.** ADR-106 Decision 2 split the
  surface by route so an ordinary member mounted no publish path. FR6.2 makes "who
  may decide" a per-case question, so `GovernancePage` (:87) mounts `ActionRow`
  exactly where `is_decidable_by` admits the viewer — an admin, or the delegatee an
  admin named on that one case — and `ReadOnlyActionRow` everywhere else. The
  property ADR-106 protected is unchanged: a viewer who may not decide a case
  mounts nothing that could. The relay's scoped-delegation admission enforces the
  same gate independently.
- **Receipt ladder** — `src/stores/receipts.rs`. `parse_receipts` (:62) and
  `reduce_case` (:106) reduce `GET /api/governance/receipts`, keeping
  `escalated-on-age` and `expired` as side receipts that never become a decision's
  stage; `stage_label` (:132) gives each stage a distinct honest label so a denied
  action and an approved action whose write failed never read alike.
  `DecisionChainRow` (:1117) renders the stage beside its decision.
- **Store** — `src/stores/panel_registry.rs` now carries the raw 31400 and 31402
  tags (:28, :63) so the triple, the panel policy and a probe tag are readable,
  `context_url` (:60) so the proposal's context can be linked, and `delegate_to`
  (:121) so a delegation names its delegatee in the chain. `resolve_panel_for`
  (:356) mirrors the relay's panel-resolution order.

### Out-of-scope security fixes carried on this change

`deepsec-gate --diff` scans the blast radius of a change, not only its lines. It surfaced two `HIGH` auth bypasses in the relay's REQ read path that this ADR's work did not introduce and does not otherwise touch — the feature diff has no hunk between `nip_handlers.rs` old lines 202 and 1750, where both live. They are recorded here rather than dropped, because they block the gate for this branch and they ship with it.

1. **The REQ subscription was stored before it was authorised, and stored raw** (`crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:1288-1331`). `handle_req` inserted `filters.clone()` — the client's un-gated filter — into `session.subscriptions` and persisted it *before* `nip42::protected_read_blocked` and `Self::gate_kind_1059_filters` ran, keeping the gated filters in a shadowed local used only for the immediate `query_events`. A subscription refused with `CLOSED` therefore stayed in the session, and `broadcast.rs` matched every later event against the raw filter: the historical read was refused and the live stream was delivered anyway. Both gates now precede the insert (`:1296`, `:1308`) and the stored value is the rebound, `#p`-rewritten filter (`:1319-1331`). Tests: `nip_handlers.rs:4144` `req_gate_ordering_tests`.

2. **A `kinds`-absent filter bypassed both protected-read gates** (`crates/nostr-bbs-relay-worker/src/relay_do/nip42.rs:85-108`, called from `nip_handlers.rs:1655-1675`). Both gates decide from the kinds a filter *names*, and a Nostr filter omitting `kinds` matches every kind while naming none — `build_filter_conditions` adds no `kind IN (...)` predicate for it — so `REQ ["sub", {}]` returned sealed DMs, encrypted DMs and moderation events to an anonymous socket. `nip42::protected_read_permitted` is now consulted from `authorize_event`, which already guards the historical, COUNT and broadcast paths; a per-event decision cannot be dodged by declining to mention the kind. Correspondence (4/13/14/1059) requires an authenticated author or `p`-tagged recipient and is mode-independent, with no admin exemption; moderation kinds (30910-30916) require only authentication and only in `Nip42` mode, so legacy `Allowlist` deployments keep their read behaviour. Tests: `nip42.rs:383` `protected_read_permitted_tests`, 8 cases.

Findings that are pre-existing and **not** contained enough to fix here are listed in `docs/security/known-findings.md` with an owner, not silently carried.

### Known limits (client)

0. The calibration flag arrives on a separate authenticated read, so a
   logged-out viewer of the member surface sees calibration samples suppressed
   by tier rather than shown. That is the conservative failure: a sample not
   shown loses a calibration opportunity, whereas a sample shown on the client's
   own guess would be a claim the relay never made.
1. `GET /api/governance/receipts` is NIP-98 **admin**, so a member or a delegated
   reviewer sees the decision chain without application stages. The store records
   that as unavailable and never as `not-applied`; the ageing badge those viewers
   do get is the client's own clock reading and is labelled as advisory against
   the relay's `escalated-on-age` receipt.
2. Receipts are fetched per case on demand, not subscribed; a stage that advances
   after the fetch appears on the next load of the surface.
3. **The client publishes no 31400.** There is no panel-authoring UI in this
   crate, so there is no publish form in which to prompt for the task-property
   triple. The triple is declared by whatever publishes the panel — today
   agentbox — and the requirement is documented for those publishers in
   `README.md` (governance tags) rather than implemented as a form that does not
   exist. A panel-authoring UI, when one is built, must collect
   `tp-verifiability` / `tp-reversibility` / `tp-stakes` at publish time.
4. Probe blindness in the client is complete for *rendering* (`visible_probe` is
   the only path, and it is tested against a fixture 31402 carrying the tag), but
   the raw signed event still carries the tag over REQ, exactly as this ADR's
   `Consequences` records. A reader of the browser's WebSocket frames can still
   see it.

## Verification

Established at `verified_commit` by executed commands, recorded with raw output in `.claude/evidence/EXP-AC-003.evidence.md`, `EXP-AC-004.evidence.md`, `EXP-AC-006.evidence.md` and `EXP-AC-007.evidence.md`:

- `cargo test -p nostr-bbs-core --lib governance::task_property_tests` — the 729-pair exhaustive tightening-only property and the effective-tier table over the whole triple space crossed with every declared tier.
- `cargo test -p nostr-bbs-core --lib governance::calibration_tests governance::receipt_stage_tests` — the deterministic sampling band (80..=120 of 1,000 at rate 0.1), the keyed-selection property that defeats `d`-tag grinding, and every stage pair checked for regression.
- `cargo test -p nostr-bbs-relay-worker --lib augmentation_boundary_tests ageing` — panel-tightened projection, advertised-default folding, delegation admission, the human-resolution guard, and the ageing predicate and its deadline ordering.
- `cargo test -p nostr-bbs-auth-worker --lib augmentation_api_tests` — application-stage authority (including the case-ownership bind), the manual-continuation precondition, monotonicity and its 409s, probe redaction, and the reviewer read model.
- `cargo test -p nostr-bbs-core --lib rationale_tests` and `cargo test -p nostr-bbs-relay-worker --lib rationale_gate` — the FR2.2 relay-side rationale gate: 19 scalars padded with spaces refused, 20 astral scalars (80 bytes) accepted, low tier unchanged, `delegate` on critical without a rationale refused.
- `cargo test -p nostr-bbs-relay-worker --lib req_gate_ordering_tests protected_read_permitted_tests` — the two out-of-scope security fixes recorded under Consequences.
- `cargo test --workspace --exclude nostr-bbs-forum-client` — whole-workspace regression: 1589 passed, 0 failed at `verified_commit`.
- `scripts/deepsec-gate.sh --diff main` — security gate. **It does not pass.** The verdict is computed from `deepsec export --project-id`, an export of the persistent store under `.deepsec-gate/data/`, which accumulates and never retires a fixed finding; both blocking `HIGH` entries are fixed on this branch in commits predating the run that still reports them. The receipts record the exit code and the analysis, and claim nothing further. Pre-existing findings that were not fixed are owned in `docs/security/known-findings.md`.

Client half, recorded in `.claude/evidence/EXP-AC-002.client.evidence.md`,
`EXP-AC-004.client.evidence.md` and `EXP-AC-006.client.evidence.md`:

- `cargo test -p nostr-bbs-forum-client` — 393 tests, of which 42 in
  `utils::governance_view`, 9 in `stores::receipts`, 3 new in
  `stores::panel_registry` and 3 in `utils` are new: the rationale gate
  and its whitespace counter-example, byte-for-byte reasoning, the absence of any
  rationale template (asserted over the sources that build a 31403), the
  tightening-only boundary, deterministic clock-free sampling, probe blindness
  against a fixture event carrying the tag, the ageing labels and deadline,
  scoped delegation including withdrawal by supersession, control-before-framing
  ordering, untruncated proposal rendering, the receipt-stage reduction with its
  side-receipt rule, and the security fixes below.
- `trunk build --release` in `crates/nostr-bbs-forum-client` — the WASM bundle the
  forum actually ships.
- `scripts/deepsec-gate.sh --diff feat/augmentation-conditions` over the client
  worktree — **BLOCK, exit 1**, run three times as the branch changed. It found
  and this branch fixed: stored XSS through an unvalidated `context_url` bound
  into an `href` (the governance subscription carries no `authors` filter, so
  that field is attacker-controlled); a byte-slicing panic on non-ASCII
  identifiers, which in WASM blanks the whole client; panels keyed by `d` tag
  alone, which let one registered agent replace another operator's panel and so
  **lower their escalation boundary**; 31405 retirement with no ownership check;
  and an unscoped decision chain, where a 31403 with a colliding `d` tag could
  make a case read as decided (revealing its probe) or offer a stranger the
  controls. The two HIGH entries on the final receipt are the first run's,
  fixed and absent from runs 2 and 3; the gate's blocking list is cumulative.
  Remaining findings and why they are open are triaged in
  `.claude/evidence/EXP-AC-002.client.evidence.md`.

`activation_status` stays `inactive`: nothing here has been deployed and `nostr-bbs-core` 1.0.0-beta.11 has not been published. It moves to `staged` on publication and to `live` on edge deploy with the probe suite run (PRD milestone M4).
