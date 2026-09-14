---
expectation_id: EXP-AC-002
scope: nostr-bbs-forum-client (forum half; the VisionClaw half is another repo's)
git_sha: aa438f3ea79ad9688c37119783b398d609680778
branch: feat/augmentation-conditions-client
produced_by: agent:claude-opus
produced_at: 2026-09-14T20:02:22Z
audited_by:
---

# Evidence — EXP-AC-002 (forum client)

Executed in the worktree `nostr-rust-forum-client` on branch
`feat/augmentation-conditions-client`, whose parent is `aa438f3ea79ad9688c37119783b398d609680778`
(`feat/augmentation-conditions`). Every command below was run; the output is
this run's, trimmed to the assertion lines. Uncommitted at capture time — the
tree is the change under test.

## Scenario 1 — the rationale is the human's, and there is no template left

```
$ cargo test -p nostr-bbs-forum-client utils::governance_view
```

```
test utils::governance_view::tests::low_and_medium_never_require_a_rationale ... ok
test utils::governance_view::tests::high_and_critical_require_twenty_trimmed_characters ... ok
test utils::governance_view::tests::whitespace_does_not_satisfy_a_mandatory_rationale ... ok
test utils::governance_view::tests::rationale_remaining_counts_down_to_zero ... ok
test utils::governance_view::tests::published_reasoning_is_the_typed_text_byte_for_byte ... ok
test utils::governance_view::tests::an_empty_rationale_publishes_an_empty_reasoning_not_a_template ... ok
test utils::governance_view::tests::decision_content_round_trips_through_the_core_parser ... ok
test utils::governance_view::tests::no_decision_surface_carries_a_rationale_template ... ok
test result: ok. 42 passed; 0 failed; 0 ignored; 0 measured; 349 filtered out; finished in 0.00s
```

Both EXP-AC-002 counter-examples are named tests.
`whitespace_does_not_satisfy_a_mandatory_rationale` is "Approve button enabled
on a `critical` case with an empty rationale" — fifty spaces do not open the
gate, because the length test is on the trimmed text.
`published_reasoning_is_the_typed_text_byte_for_byte` is "`reasoning`
containing text the human did not type" — it asserts equality against a string
with leading whitespace, a newline and an em-dash, so trimming or normalising
would fail it.

`no_decision_surface_carries_a_rationale_template` is the removal receipt: it
`include_str!`s `pages/governance.rs`, `stores/panel_registry.rs` and
`stores/receipts.rs` and asserts neither `"via governance UI"` nor the shape
`"Human {"` appears in any of them. Confirmed independently:

```
$ grep -rn "via governance UI" crates/ | sed 's/:.*//' | sort -u
```

```
crates/nostr-bbs-forum-client/src/utils/governance_view.rs
```

The single remaining occurrence is prose in the module that removed it, naming
the template so the next reader knows what was removed and why. It is not in a
code path, which is why that file is excluded from the guard by construction —
stated here rather than hidden by a narrower grep.

**Verdict: PASS.**

## Scenario 2 — the proposal is in view, and the agent's framing is below the controls

```
$ cargo test -p nostr-bbs-forum-client utils::governance_view
```

```
test utils::governance_view::tests::reviewer_controls_always_precede_the_agents_framing ... ok
test utils::governance_view::tests::the_proposal_precedes_the_controls_so_it_is_in_view_when_judging ... ok
test utils::governance_view::tests::absent_optional_sections_are_omitted_not_emptied ... ok
test utils::governance_view::tests::fields_are_pretty_printed_in_full_without_truncation ... ok
test utils::governance_view::tests::a_bare_string_payload_prints_as_itself ... ok
test utils::governance_view::tests::a_null_payload_is_absent_rather_than_the_word_null ... ok
```

The ordering rule is **data**, not markup: `card_sections()`
(`src/utils/governance_view.rs:435`) returns the ordered section list and
`assemble_card()` (`src/pages/governance.rs:652`) renders in exactly that
order, so the counter-example "Tier/confidence rendered above the controls"
is a compiled assertion over all four
(has_context_url x has_agent_reasoning) combinations rather than a claim about a
`view!` macro.

`fields_are_pretty_printed_in_full_without_truncation` builds a 200-element
payload and asserts both the first and the **last** element survive and that no
ellipsis appears — EXP-AC-002's "`fields` of arbitrary JSON shape rendered
(pretty-printed) without truncation".

**Verdict: PASS.**

## Scenario 3 — the whole client suite, and the shipped bundle

```
$ cargo test -p nostr-bbs-forum-client
```

```
test result: ok. 391 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

334 of those pre-date this change; 57 are new. The client is a WASM binary, so
the suite runs on the **host** target: every rule above lives in a pure module
with no `web_sys`/`js_sys`/Leptos-signal dependency precisely so that it can.
The WASM bundle the forum ships is built separately:

```
$ cd crates/nostr-bbs-forum-client && trunk build --release
```

```
    Finished `release` profile [optimized] target(s) in 0.50s
wasm-opt: /home/devuser/workspace/nostr-rust-forum-client/dist/.stage/nostr-bbs-forum-client-*_bg.wasm
2026-09-14T19:56:46Z  INFO applying new distribution
2026-09-14T19:56:46Z  INFO success
```

Environment note: the sandbox mounts `~/.cache` `noexec`, so trunk's cached
`wasm-bindgen` could not be executed and the first build failed with
`Permission denied (os error 13)`. Resolved by copying the identical binary
(`wasm-bindgen 0.2.125`) to `$CARGO_HOME/bin`, which is on PATH and
executable. This is an environment fact, not a code change.

**Verdict: PASS.**

## Not covered here

- FR2.3 and FR2.4 (VisionClaw `AcspCaseQueue`, the hardcoded
  `confidence: 0.5`) are another repository's half of this expectation and are
  **not** evidenced by this receipt.
- No browser run. Every assertion above is a host-target unit test plus a
  release build; nothing here claims the rendered page was observed.

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
