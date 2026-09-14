---
expectation_id: EXP-AC-002
scope: nostr-bbs-forum-client (forum half; the VisionClaw half is another repo's)
git_sha: ef0c9aa207ba16618cb4a09195546ef317823ba8
branch: feat/augmentation-conditions-client
produced_by: agent:claude-opus
produced_at: 2026-09-14T20:02:22Z
audited_by: agent:claude-sonnet-5 (degraded: same family as producer; codex GPT-6 Astra unavailable — bwrap sandbox refused in container)
audited_at: 2026-09-14T21:40:00Z
auditor_verdict: DISPUTED
auditor_counter_examples_attempted: 9
auditor_counter_examples_found: 1
---

# Evidence — EXP-AC-002 (forum client)

Executed in the worktree `nostr-rust-forum-client` on branch
`feat/augmentation-conditions-client`, at `ef0c9aa` (parent
`aa438f3`, the backend half). Every command below was run against that tree; the
output is this run's, trimmed to the assertion lines. This receipt is committed
immediately after the change it describes, so the tree it names is the tree the
commands ran on.

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

## Auditor adversarial probes

Worktree `nostr-rust-forum-client-client` at HEAD `6b6f48a` (unchanged from
`ef0c9aa` — the evidence-stamping commit touched only frontmatter). No
implementation files edited; probes were run either as read-only greps or as a
`#[cfg(test)] mod auditor_probes` block appended to and then reverted (`git
checkout --`) from `stores/receipts.rs`.

```
$ cargo test -p nostr-bbs-forum-client
test result: ok. 393 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Matches the evidence's own re-run count (391 at Scenario 3's git_sha, growing
to 393 once the two `EXP-AC-006` probe-hardening tests are counted — see that
file). No regression.

1. **Rationale of exactly 20 chars, leading/trailing whitespace.**
   `rationale_satisfied` trims before counting
   (`utils/governance_view.rs:51`), so `"  " + "x"*20 + "  "` satisfies a
   `critical` gate and 19 does not. Matches the producer's own boundary test.
   No counter-example.

2. **Rationale of 20 astral-plane chars (𝕏×20) vs 10.** `.trim().chars().count()`
   counts Unicode *scalar values*: `𝕏` (U+1D54F, outside the BMP) is one
   `char` in Rust regardless of its 2-code-unit UTF-16 / 4-byte UTF-8 width, so
   20 of them satisfies the gate and 10 does not — internally consistent, no
   divergence *within* this counting method.
   **But the counter-example is elsewhere: there is no server-side counterpart
   to count anything at all.** `grep -rn "MIN_RATIONALE\|rationale" crates/`
   outside this client crate turns up nothing, and
   `nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs::plan_action_response`
   (the function that actually accepts a signed 31403) parses `reasoning` as a
   plain string with `.unwrap_or_default()` and applies **no length check** —
   its own test fixtures publish `{"action":"reject","reasoning":"x"}` (line
   3308) and `{"action":"reject"}` with no `reasoning` field at all (line
   3291) and both are accepted. So EXP-AC-002's "the publish action is
   disabled until the rationale has at least 20 characters" holds only for
   *this* Leptos build with JS enabled; a raw `nak` publish, a different
   client, or a build with the disabled-attribute stripped can post a
   `critical`-case 31403 with an empty `reasoning` and the relay takes it.
   Neither evidence file's "Honest limits" section discloses this — the client
   evidence frames the 20-char gate as though it were the enforcement point,
   when it is UI-only.
   **Counter-example: CONFIRMED** (against the expectation's plain-language
   claim, not against any single test in the suite, which are all internally
   consistent).

3. **`decision_content` with `\n` and a run of spaces.** Byte-for-byte
   preserved — this is exactly `published_reasoning_is_the_typed_text_byte_for_byte`
   (`governance_view.rs:604`), which already asserts a string with leading
   whitespace and an embedded `\n\n— jj`. Re-verified with a `\t` and doubled
   spaces substituted in by hand at the REPL-equivalent (`serde_json` round
   trip): unchanged. No counter-example.

4. **`fields` at ~1 MB.** `pretty_fields` (`governance_view.rs:457`) is a
   straight `serde_json::to_string_pretty`; nothing truncates or streams it,
   consistent with the 200-element test already in the suite. No functional
   counter-example found, though this is unverified beyond code reading — no
   render-path (DOM) test exists at any size, which both evidence files
   already disclose ("No browser run").

5. **`fields` containing `"</script>"`.** Not independently verifiable
   host-side: `pretty_fields` returns a plain `String`; whether it reaches the
   DOM as text (Leptos's default `{expr}` interpolation escapes) or as raw
   markup is a rendering-shell property outside this pure module and outside
   what any host-target test exercises. No counter-example demonstrated, but
   also not evidenced — flagged as an unverified gap, not a pass.

6. **`effective` tier absent on a legacy request.** This is relay-side, not
   client-side: `nip_handlers.rs`'s `human_resolution_required` gate is
   skipped when `case_row.effective_tier` is `None` ("a case projected before
   0006 … imposes nothing" — the code's own comment). The client always
   computes *some* effective tier via `compute_boundary`'s fallback to
   `advertised_default`, so the two halves disagree by construction on what
   "absent" means, but this is pre-existing/documented legacy behaviour, not
   new to this branch, and out of the client's control. Not a counter-example
   against this branch.

7. **`context_url = "javascript:alert(1)"` / `"data:text/html,..."`.** Both
   already in the producer's own hostile-URL test
   (`a_script_bearing_context_url_never_reaches_an_href`), and rejected.
   Re-verified `"data:text/html,<script>1</script>"` (a bare, non-base64
   `data:` URI, not the base64 one already tested) — also rejected, since
   `safe_context_url` allows only an `http`/`https` prefix. No counter-example.

8. **Delegate pubkey uppercase hex / 63 chars / `0x` prefix.** All three
   already covered by `delegate_target_must_be_hex64`; `0x`-prefixed 64-char
   input is additionally rejected because `x` is not `is_ascii_hexdigit`.
   Re-verified `0X` (uppercase prefix) — same rejection, `X` is not hex. No
   counter-example.

9. **A 31402 with the probe tag AND a spoofed 31403 from a non-admin,
   non-delegated pubkey.** `visible_probe` gates on `chain_is_decided`, which
   in turn is driven by the chain the client itself resolves — but that chain
   is bound to the request's event id by `bind_to_request`
   (`panel_registry.rs:461`) and is **not** filtered by whether the signer was
   authorised. A forged `approve` from an arbitrary pubkey, once it exists as
   an event the client ingests, *would* satisfy `chain_is_decided` and reveal
   the probe client-side — this is exactly the gap both evidence files already
   name under "Left open" (the client can only enforce blindness for what it
   renders; the relay's admission gate, not this view, is what actually stops
   an unauthorised 31403 from mattering). No *new* counter-example: this is
   already disclosed, and `is_decidable_by`/`chain_is_decided` are honestly
   documented as "a view gate mirroring the relay's admission gate, not a
   replacement for it".

**Verdict: DISPUTED.** Every named test in the evidence passes as claimed and
`cargo test -p nostr-bbs-forum-client` reproduces at 393/393. The dispute is
with item 2: the expectation's mandatory-rationale-length claim is true only
of the reference Leptos build, is unenforced at the only place that actually
admits a 31403 to the relay, and neither evidence file states this. Everything
else attempted (items 1, 3, 4, 6, 7, 8, 9) held or was already honestly
disclosed; item 5 is an unverified gap, not a failure.
