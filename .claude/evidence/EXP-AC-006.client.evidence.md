---
expectation_id: EXP-AC-006
scope: nostr-bbs-forum-client (FR6.2/6.3/6.4 display and gating halves only)
git_sha: ef0c9aa207ba16618cb4a09195546ef317823ba8
branch: feat/augmentation-conditions-client
produced_by: agent:claude-opus
produced_at: 2026-09-14T20:02:22Z
audited_by:
---

# Evidence — EXP-AC-006 (forum client)

Covers the client's share: that a delegated reviewer is offered the controls for
exactly the case delegated to them, that calibration samples are shown rather
than suppressed, and that a probe is never rendered before its 31403 exists.
`GET /api/governance/reviewers`, the relay's delegation admission gate, the
deterministic sampling band over 1,000 requests, VisionClaw's `CaseView` and the
dream-ledger schema are other components' halves.

## Scenario 1 — delegation is scoped (DDD §6 invariant 6)

```
$ cargo test -p nostr-bbs-forum-client utils::governance_view
```

```
test utils::governance_view::tests::an_admin_may_decide_an_open_case_and_a_stranger_may_not ... ok
test utils::governance_view::tests::a_delegatee_may_decide_only_the_delegated_case ... ok
test utils::governance_view::tests::a_delegation_is_not_itself_a_decision ... ok
test utils::governance_view::tests::a_superseded_delegation_withdraws_the_reviewers_authority ... ok
test utils::governance_view::tests::a_decided_case_offers_controls_to_nobody ... ok
test utils::governance_view::tests::delegate_target_must_be_hex64 ... ok
```

`a_delegatee_may_decide_only_the_delegated_case` is EXP-AC-006's counter-example
"A reviewer deciding a case not delegated to them": the same reviewer pubkey is
admitted on the delegated case and refused on another. `is_decidable_by`
(`src/utils/governance_view.rs:389`) drives which component mounts, so a
non-delegated viewer mounts `ReadOnlyActionRow` — no signer, no relay handle,
no publish path. Delegation itself is an **admin** control; a delegatee cannot
re-delegate. A delegation superseded by a later one withdraws the first
delegatee's authority.

This is a **view** gate mirroring the relay's admission gate, not a replacement
for it: the relay rejects an unauthorised 31403 regardless. Its job is that a
reviewer is shown the controls exactly when using them will work.

## Scenario 2 — calibration samples are shown, marked, and clock-free

```
test utils::governance_view::tests::a_plain_low_case_is_member_suppressed_unless_sampled ... ok
test utils::governance_view::tests::calibration_sampling_is_deterministic_and_clock_free ... ok
test utils::governance_view::tests::opaque_work_is_never_member_suppressed ... ok
test utils::governance_view::tests::an_irreversible_panel_floors_a_low_declaring_agent_at_high ... ok
test stores::panel_registry::tests::suppression_reads_the_effective_tier_not_the_agents_declaration ... ok
```

`calibration_sampling_is_deterministic_and_clock_free` is the counter-example
"Sampling that depends on wall-clock time": the same request id yields the same
answer across repeated calls, because the client calls the same
`nostr-bbs-core::is_calibration_sample` (a hash of the request id) the relay
does. A sample renders with a small "calibration" marker and is **never**
suppressed. Suppression reads the **effective** tier, never the agent's
`risk_tier` (invariant 3) — `suppression_reads_the_effective_tier_not_the_agents_declaration`
shows an agent declaring `low` against an operator panel declaring the work
irreversible, and the case stays visible at effective tier `high`.

## Scenario 3 — probes are blind until decided (invariant 7)

```
test utils::governance_view::tests::a_probe_is_hidden_until_the_case_is_decided ... ok
test utils::governance_view::tests::a_probe_tag_on_a_pending_fixture_event_never_reaches_the_view ... ok
test utils::governance_view::tests::a_probe_tag_from_an_unregistered_agent_is_not_a_probe ... ok
```

`a_probe_tag_on_a_pending_fixture_event_never_reaches_the_view` is the
counter-example "Probe tag visible on a pending card", tested against a fixture
31402 that **does** carry `probe=<sha>` — which is how it arrives over REQ,
because the relay cannot strip it without invalidating the signature this client
verifies strictly. The digest is recognised (it is from the panel's registered
probe agent) and still yields `None` from `visible_probe` while the case is
undecided; once a 31403 exists it renders. `visible_probe`
(`src/utils/governance_view.rs:282`) is the only path a digest can take to the
DOM.

A related hardening landed here under the security gate: the decision chain on a
card is now scoped to the decisions **bound to that request's event id**
(`bind_to_request`, `src/stores/panel_registry.rs`). Without it, a 31403
carrying a colliding `d` tag would land on a victim case's chain, where a
forged `approve` would make the case read as decided and **reveal its probe**,
and a forged `delegate` would offer a stranger the controls. Tested by
`a_decision_on_another_case_never_lands_on_this_cards_chain`.

## Whole suite and bundle

```
$ cargo test -p nostr-bbs-forum-client
```

```
test result: ok. 393 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

**Verdict: PASS**, for the client halves of FR6.2, FR6.3 and FR6.4 only.

## Honest limits

1. **Probe blindness is rendering-only.** The tag remains on the raw signed
   31402 over REQ, exactly as ADR-2011's `Consequences` records. A reader of
   the browser's WebSocket frames still sees it. This is that ADR's
   `review_trigger`, not something this branch closes.
2. **No reviewer telemetry UI.** `GET /api/governance/reviewers` is not
   consumed by this client; EXP-AC-006 puts reviewer scoring and ranking UI out
   of scope, and nothing here displays it.
3. **No browser run.** Every assertion is a host-target unit test plus a release
   `trunk build`; nothing here claims the rendered page was observed, and no
   probe was seeded against a live relay.

## Security gate

```
$ /home/devuser/.claude/skills/build-with-quality/scripts/deepsec-gate.sh --diff feat/augmentation-conditions
```

Run three times as the branch changed. The receipts are kept in full under
`.deepsec-gate/reports/`.

| Run | Receipt | Exit | New findings |
|---|---|---|---|
| 1 | `20260914T194300Z` | 1 | HIGH x2, MEDIUM x1, BUG x1 |
| 2 | `20260914T195646Z` | 1 | MEDIUM x4, HIGH_BUG x1, BUG x2 |
| 3 | `20260914T201424Z` | 1 | MEDIUM x2 |

**Final result: BLOCK, exit 1. Not a pass, and not recorded as one.**

The gate's `blocking` list is cumulative across runs, so the two HIGH entries on
the final receipt are run 1's, both **fixed in this tree** and absent from runs 2
and 3:

- *Stored XSS via unvalidated `ActionRequest.context_url` rendered into href*
  and its ingest-side twin. Real, and mine: the governance subscription carries
  no `authors` filter, so `context_url` is attacker-controlled, and I had bound
  it straight into an `<a href>`. Fixed by `safe_context_url`
  (`src/utils/governance_view.rs`), applied at **both** the store ingest and the
  render, allowing only `http`/`https` with a case-insensitive scheme match and
  rejecting any string carrying an ASCII control character (a browser strips
  embedded tabs before resolving a scheme, so `java\tscript:` is a
  `javascript:` URI in disguise). Tests:
  `only_http_and_https_context_urls_survive`,
  `a_script_bearing_context_url_never_reaches_an_href`,
  `control_characters_are_rejected_rather_than_trimmed_out`.

Also fixed in this branch, from runs 1 and 2:

- *`shorten_pubkey` byte-slices at fixed offsets and can panic* — a panic in
  WASM aborts the whole reactive render. Fixed by character-slicing, in
  `utils/mod.rs` and in the new `governance_view::short_id` used by the decision
  chain, where a hostile 31403's `delegate_to` is an arbitrary string.
- *Panels keyed by `d` tag alone let one agent clobber another agent's panel*
  and *`KIND_PANEL_RETIRED` removes any panel by `d` tag with no ownership
  check*. Material to this change specifically: since ADR-2011 a panel carries
  the operator's task-property declaration, so a `d`-tag collision was a way to
  **lower another operator's escalation boundary**. Fixed by keying panels and
  panel states by the NIP-33 address (`panel_address`), which makes retirement
  ownership-safe for free.
- *Decision chain computed with no scoping, so a colliding `d` tag injects into
  a victim case's chain*. Fixed by binding the chain to the request's event id
  (`bind_to_request`); a forged `approve` can no longer make a case read as
  decided (which would reveal its probe) and a forged `delegate` can no longer
  offer a stranger the controls.

**Left open, with reasons:**

- *Probe blindness is only enforced at the DOM; digests are readable on the
  wire* (MEDIUM, run 3). Correct, and already this branch's stated position:
  the relay cannot strip the tag from a signed event without invalidating the
  signature. It is ADR-2011's `implementation_status: partial` and its
  `review_trigger`. Not closable in the client.
- *Action requests appended and deduped by `event_id`, ignoring NIP-33
  replaceable semantics* (BUG). Pre-existing behaviour, unchanged by this
  branch; each 31402 is treated as a distinct case, which is what the relay's
  own `broker_cases` projection does. Untriaged beyond that.
- Four findings in `nostr-bbs-relay-worker` and `nostr-bbs-core`
  (device-key moderation bypass, `governance_rank` pubkey casing, 31405 defined
  twice, 64-bit decision ids). **Not this branch's code** — they belong to the
  backend half on `feat/augmentation-conditions` and are recorded here only so
  they are not lost.

## Iteration after merge — calibration became relay-authoritative

Scenario 2 above was written against a client that **computed** the calibration
flag itself, with `is_calibration_sample(request_id, rate)` as an unkeyed hash.
Before the merge into `feat/augmentation-conditions`, the backend closed a
finding that invalidates that design: the request id is the 31402's `d` tag, and
on a NIP-33 parameterized-replaceable event the **requesting agent chooses it
freely**. An agent could grind `d` tags offline until it found one selection
never picks, and opt itself out of the oversight FR6.3 exists to impose — this
ADR's own thesis defeated one level down. Selection is now
`HMAC-SHA256(selection_key, request_id)` under a Cloudflare secret the relay
holds (forum commit `67d0d71`).

The client therefore **must not** compute the flag: it has no key, and a key
shipped in a WASM bundle is a published key that restores the hole exactly. So
this branch's `compute_boundary` no longer derives it. Calibration is read from
`broker_cases.calibration_sample` over `GET /api/governance/cases`
(`src/stores/case_projection.rs`). That endpoint is `require_authed` — any
NIP-98 signer, not admin — which is what FR6.3 needs, since calibration samples
exist to be shown to the member surface; **no auth-worker change was required**.
A case the relay has said nothing about is not a sample.

```
$ cargo test -p nostr-bbs-forum-client
```

```
test utils::governance_view::tests::a_plain_low_case_is_suppressed_unless_the_relay_says_it_is_a_sample ... ok
test utils::governance_view::tests::a_legacy_case_the_relay_says_nothing_about_is_not_a_sample ... ok
test utils::governance_view::tests::the_client_never_derives_the_calibration_flag_from_anything_it_holds ... ok
test stores::case_projection::tests::parses_the_case_projection_envelope ... ok
test stores::case_projection::tests::a_legacy_row_without_the_flag_is_not_a_calibration_sample ... ok
test stores::case_projection::tests::malformed_rows_are_skipped_and_a_bad_body_yields_nothing ... ok
test stores::case_projection::tests::an_unknown_case_is_never_reported_as_a_calibration_sample ... ok
test result: ok. 398 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

`a_plain_low_case_is_suppressed_unless_the_relay_says_it_is_a_sample` is the
flag-present/flag-absent pair the merge asked for: same request, same panel,
same effective tier, and only the relay's answer changes whether the member
surface shows it. `a_legacy_case_the_relay_says_nothing_about_is_not_a_sample`
covers a case projected before migration 0006 — suppressed per effective tier,
and, where the tier would not suppress it anyway, still shown; absence of the
flag suppresses nothing on its own.
`the_client_never_derives_the_calibration_flag_from_anything_it_holds` is the
regression guard: a panel rate of `1.0`, which under the old unkeyed scheme
sampled everything, now selects nothing client-side, and no source in this crate
calls the core selection function at all (the needle is assembled at runtime so
the assertion does not match itself).

**What this costs, stated:** the flag arrives on a separate authenticated read,
so a logged-out viewer of the member surface sees calibration samples suppressed
by tier rather than shown. That is the conservative failure — a sample not shown
loses a calibration opportunity, whereas a sample shown on the client's own guess
would be a claim the relay never made.

### Post-merge verification

```
$ cargo test --workspace
```

```
1990 tests passed, 0 failed (398 of them nostr-bbs-forum-client)
```

```
$ cd crates/nostr-bbs-forum-client && trunk build --release
$ cargo clippy -p nostr-bbs-forum-client --target wasm32-unknown-unknown
```

Build: `INFO success`. Clippy: clean across every file this branch owns; the two
remaining warnings are pre-existing `Option<AgentDisclosureCache>` clones in
`pages/knowledge.rs`, untouched here.

The security gate was **not** re-run after the merge — the last recorded run is
the pre-merge `20260914T201424Z` (BLOCK, exit 1) documented above, and this
iteration adds a read-only projection fetch and removes a computation. That is a
gap, not a pass: a gate run against the merged tree is still owed.
