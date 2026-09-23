# Ontology promotion — operator runbook

**What this is:** the human side of the corpus governance loop. Everything below
happens on the `ontology-governance` panel in the forum; you are the single
human signer (`PRD-sovereign-corpus` §2 Q7).

**Records:** forum [ADR-2013](../adr/ADR-2013-ontology-governance-panel-promote-demote-expiry.md),
[ADR-2011](../adr/ADR-2011-operator-task-properties-set-the-escalation-boundary.md)
(tiering), [ADR-2010](../adr/ADR-2010-durable-governance-outcome-receipts.md)
(receipts), agentbox ADR-2109 (apply), VisionClaw ADR-2116 (what this replaced),
VisionFlow `PRD-sovereign-corpus` §3.3 (the state machine).

---

## The state machine

```
Draft Concept                          working/, status: draft, unverified
      │
      │  vault propose <iri> --level content|schema
      │  ├─ Whelk inconsistency ────────┐
      │  ├─ SUBCLASS_CYCLE              ├─ BLOCKERS. Nothing is posted. Not
      │  ├─ RELATION_CONTRADICTION      │  your decision to make: a proposal
      │  └─ vocabulary violation ───────┘  with blockers never reaches you.
      ▼
machine-confirmed          verified: [process:vault/<ver>]
      │                    31402 ActionRequest on the ontology-governance panel
      │                    tier = panel properties ⊔ level ⊔ agent declaration
      │                    level: schema|demotion  ⇒  stakes critical  ⇒  HIGH
      │
      ├─ you sign 31403 Promote{iri} ──► status: stable, verified += human:<npub>
      │                                  ledger entry, case → promoted
      ├─ you sign 31403 Reject ────────► receipt `rejected`. Nothing is written.
      ├─ you sign 31403 Demote{iri} ───► status: deprecated. Case → decided.
      │
      └─ 14 d unattended ─────────────► `escalated-on-age` receipt, then
         (panel deadline = stale_after)     `expired` receipt: case CLOSED without
                                            a decision. Page untouched.
stable ──► a conflict or a passed stale_after proposes its own demotion, which
           comes back to you as a `level: demotion` case, floored HIGH.
```

Exposure-level changes inside Loom (manifest, salience, budgets, ranking
weights) never reach this panel. They self-evolve under ADR-140 D6's paired-eval
gate with auto-revert and are ledgered, not signed. If one appears in your
queue, that is a bug — report it rather than deciding it.

---

## What you see, and what each field is for

A case in the `ontology-governance` inbox carries eight fields. They exist
because a signature you cannot justify is worse than no signature.

| Field | What it is | What to do with it |
|---|---|---|
| **Subject IRI** (`context_url`) | `urn:ngm:class:…` — the page's OKF `resource` | The subject of your decision. The apply path resolves it to a page by re-slugifying candidates; if two pages claim it, the write **stops** rather than guessing. |
| **Vault page** | the `knowledge/pages/…` id | Open it in Obsidian before you sign. |
| **Level** | `content` \| `schema` \| `demotion` | `schema` and `demotion` are floored at tier **High**: they change what every other page means. |
| **Hypothesis** | the proposer's one-sentence claim | The thing you are agreeing or disagreeing with. If it is vague, reject — a hypothesis you cannot falsify is not a proposal. |
| **Frontmatter diff** | unified diff of the proposed frontmatter | The whole change. Nothing outside this diff is written. |
| **Content digest** | `sha256:…` of the proposed frontmatter | Correlates the decision to the ledger entry. Also the case id and the 31402's `d` tag — one value, three names. |
| **Generation** | `visionGraph@<sha>` | Which build the diff was computed against. If it is far behind `main`, the diff may no longer apply — that is what expiry exists to catch. |
| **Expires** (`stale_after`) | 14 days from proposal | After this the case closes itself. |

**Rationale is mandatory on a High case** and is enforced by the relay before
the event is stored, not by the UI: at least 20 characters after trimming
(ADR-2011 §4). A 31403 without one is refused with `rationale_required`. This
applies to a script publishing directly as much as to you in the forum.

---

## What each decision does

### Approve → `Promote{iri}`

The forum publishes a kind-31403 whose content is
`{"action":"promote","iri":"<iri>","reasoning":"…"}`. The IRI is in **your**
signed bytes, redundantly with the request's `context_url`, so a later edit to
the request cannot repoint your decision at a different page.

agentbox's `handleGovernanceDecision` then runs, in order:

```
vault edit <page> \
  --set status=stable \
  --set 'verified+={"by":"human:<your npub>","at":"<your 31403 created_at, ISO>"}' \
  --expect docs=1,blocks=1 --json
POST http://loom:8080/loom/attest  {case_id, digest, outcome, signer, at}
```

- `verified+=` **appends**. Your signature joins the machine's attestation; it
  does not replace it.
- `--expect docs=1,blocks=1` is the blast-radius guard. One decision, one page.
  If the vault disagrees the edit fails and **nothing is written** — the right
  outcome when the page moved under your decision.
- The timestamp is when *you* decided, not when agentbox got round to it.
- The ledger call is **fail-open**. A 404 or an unreachable Loom is logged and
  the write still counts, because the page has in fact changed.

### Reject

Receipt `rejected`. No `vault` call, no ledger entry, no write. The proposal is
dead; the proposer regenerates if it still believes the hypothesis.

### Demote → `Demote{iri}`

```
vault edit <page> --set status=deprecated --expect docs=1,blocks=1 --json
```

No `verified` stamp is appended. Stamping "a human vouches for this" onto a page
you have just deprecated would say the opposite of what happened. A demotion is
the only decision that may be raised about an already-stable page.

### Do nothing

Two different things happen, and they are **not** the same, though on this
panel they fall due together:

1. **336 hours** (the panel's `max_pending_hours`, 14 days): an
   `escalated-on-age` side receipt. On its own it leaves the case **open**: it
   says "nobody has looked at this yet" and is a prompt, not a verdict.
2. **14 days** (`stale_after`): an `expired` side receipt and the case is
   **closed without a decision** — no `broker_decisions` row, because nobody
   decided anything. The page is untouched. This says "this diff no longer
   describes the page": the corpus has moved on, the digest no longer matches,
   and applying it would write stale frontmatter over newer.

The panel deadline is set to match `stale_after` on purpose (forum ADR-2013), so
both sweeps land on the same five-minute cron tick rather than a day either side
of each other. Both receipts land on the same case, and that is the honest
history: *surfaced, then expired unattended*. If you want an earlier nudge than
fourteen days, it has to come from outside the panel: shortening
`max_pending_hours` alone would re-open the gap ADR-2013 closed. An expired proposal is not a
rejection — nothing was judged. The proposer regenerates from the current
generation.

---

## The receipt ladder, and how it correlates with Loom's ledger

Every decision accrues receipts (ADR-2010). Four are the relay's; four are the
mutation owner's. Two are side receipts that never advance the ladder.

| Stage | Who writes it | What it certifies |
|---|---|---|
| `signed` | relay | valid signature, correlates to a case |
| `relay-accepted` | relay | the envelope is **stored**. That is all a relay `OK` means. |
| `projection-committed` | relay | decision row, case state and receipt committed together |
| `projection-failed` | relay | terminal until a reconciliation retry supersedes it |
| `consumer-received` | agentbox | it has read the decision. It has not acted. |
| `applied` | agentbox | `vault edit` ran and took effect |
| `not-applied` | agentbox | it did not run the act, and says so |
| `applied-manually` | operator | you did it by hand during an outage |
| `escalated-on-age` | cron | *side*: past the panel deadline, still open |
| `expired` | cron | *side*: past `stale_after`, closed without a decision |

**Reading them correctly.** The first four rungs each imply the ones before.
The three application outcomes do **not**: `applied`, `not-applied` and
`applied-manually` are mutually exclusive claims about the world, exactly one of
which is true. Never reduce them with `max()` — treat them as a set, and if you
ever see more than one on a decision, surface it as the contradiction it is
rather than resolving it.

**Correlation with Loom.** One value ties the three systems together: the
content digest. It is the 31402's `d` tag, the `broker_cases.id`, the `case_id`
on every receipt, and the `digest` in the Loom `/loom/attest` body. To audit one
decision end to end:

```
forum   GET /api/governance/cases/<digest>          state + effective_tier + receipts
forum   GET /api/governance/decisions?case=<digest> the signed outcome and your rationale
loom    GET /loom/ledger?case=<digest>              the chain-hashed attestation
vault   frontmatter `verified: [{by: human:<npub>, at: …}]`  the page's own record
```

If Loom has no entry but the page carries your attestation, the ledger call
failed open — that is by design, not corruption. Re-attest; the page is correct.

If Loom **has** an entry and the page does **not** carry your attestation, that
is the serious one: a write was reported that did not land. Check the
`not-applied` receipt and the agentbox log for the `vault edit` refusal, most
likely `--expect` failing because the page changed.

---

## Failure modes worth recognising

| Symptom | Cause | What to do |
|---|---|---|
| A proposal you expected never appears | It had blockers (Whelk inconsistency, subclass cycle, relation contradiction, vocabulary violation). Blocked proposals are never posted. | Read `vault conflicts` / `vault gate` output. This is correct behaviour — an inconsistent ontology is not yours to approve. |
| A case shows `medium` when you expected `high` | The 31402's `level` tag is missing or misspelled. An unrecognised level falls back to `content`, the loosest. | Reject it. A schema change that arrived mistyped is a proposal you cannot trust the tiering of. |
| A promote returns `attested: false` | Loom's `/loom/attest` 404'd or was unreachable. Fail-open by design. | The page **is** written. Re-attest when Loom is back. |
| A promote fails with an `--expect` error | The page has more docs or blocks than the decision assumed — it changed under you. | Do not widen the guard. Have the proposer regenerate against the current generation. |
| Two pages claim one IRI | Corpus conflict. The apply stops rather than choosing. | `vault conflicts --severity high`. Fix the duplicate before re-deciding. |
| A `system:` actor tried to resolve a High case | A reasoner attempted to close a case reserved for a person. Refused by the relay. | Expected. Nothing to do; it is the floor working. |

---

## Verifying the loop without touching the corpus

```sh
cd nostr-rust-forum
scripts/e2e-ontology-promotion.sh          # 29 assertions, stub vault
E2E_REAL_VAULT=1 scripts/e2e-ontology-promotion.sh   # once WS-C's binary exists
```

It signs real 31402/31403 events, asserts the `High` floor, runs the relay's own
projection and expiry SQL against SQLite loaded from this repository's
migrations, and drives agentbox's apply path — asserting the exact `vault edit`
argv, including the blast-radius guard and that the attestation instant is the
31403's `created_at` rather than wall clock.
