# WIP status — feat/augmentation-conditions (paused by operator)

## Done

- **FR3 / ADR-2011** `TaskProperties`, tightening-only `merge`, pure
  `effective_tier`, `PanelPolicy`, deterministic calibration sampling, and the
  extended `ReceiptStage` ladder in `nostr-bbs-core`.
- **Relay** migration 0006 **and** its mirror in `ensure_schema` (the live
  schema path), effective tier stamped at 31402 projection, scoped delegation
  admission, human-resolution guard on high/critical, ageing cron, application
  stages on the receipts read API.
- **Auth worker** `POST /api/governance/receipts/{id}/application` and
  `GET /api/governance/reviewers`, both with pure tested decision seams.
- **Docs** ADR-2011 (partial/inactive, honest), BASELINE section, README tag and
  receipt-ladder tables, CHANGELOG, `nostr-bbs-core` + `nostr-bbs-mesh`
  1.0.0-beta.11 (NOT published), ADR index regenerated.
- **Evidence** four EDD receipts in `.claude/evidence/`, `audited_by` empty.
- **Fixed under the gate** cross-tenant receipt reporting, the ageing sweep's
  unsound early break, silent revocation, pubkey case normalisation, and two
  pre-existing relay read-auth bypasses (see CHANGELOG).

## Not done

1. **deepsec-gate is BLOCK, not PASS.** Final run: exit `1`, 43 findings,
   2 at/above HIGH, receipt `.deepsec-gate/reports/20260914T194052Z/`.
   Both blocking `HIGH` findings
   are **triaged and fixed**: each is purely pre-existing blast radius (the
   feature diff has no hunk in `nip_handlers.rs` between old lines 202 and 1750,
   where both live), each is contained, and each is fixed with tests —
   `a14b2b7` (`nip_handlers.rs:1288-1331`) and `12a10da` (`nip42.rs:85-108`).
   Full triage, with exploit paths, in each evidence receipt and in ADR-2011's
   Consequences.
   They still appear in the verdict because it is computed from
   `deepsec export --project-id`, an export of the persistent store under
   `.deepsec-gate/data/`, which accumulates and never retires a fixed finding:
   the total grew 5, 8, 13, 18, 25, 30, 32 across runs while each run's net-new
   count stayed small, and the same issues recur verbatim.
   **Still needs the gate owner:** reset or re-verify the store for a truthful
   current-state verdict. Clearing a security ledger is not this agent's call;
   an attempt to set the store aside was denied by policy and not worked around.
   Pre-existing findings that were *not* fixed now have an owner in
   `docs/security/known-findings.md` (KF-1..KF-6), including one `HIGH_BUG`.

2. **Probe blindness is PARTIAL.** The `probe` tag is absent from `event_tags`
   and from every D1/REST projection of an undecided case, but remains on the
   raw signed 31402 served over REQ: stripping it invalidates the signature both
   clients verify strictly. ADR-2011 is `implementation_status: partial` for
   this and it is that ADR's `review_trigger`.
3. **Nothing deployed, nothing published.** `activation_status: inactive`.
4. **Not mine, still open:** FR2 forum-client rendering (incl. hiding the probe
   tag and reading only `effective_tier`), and the agentbox / VisionClaw clauses
   of EXP-AC-004, 006 and 007.
5. `docs/dream-cycle/LEDGER.md` carried four uncommitted dream-cycle rows from
   main into the first commit. Someone else's work, kept rather than discarded.

## Environment note — a stale `target/` can fake a total build failure

Midway through this work `cargo test --workspace --exclude nostr-bbs-forum-client`
went from 1589 passing to *nothing compiling*, with ~150 errors of the form
`the trait bound NostrEvent: serde::Serialize is not satisfied`, after a commit
that touched **only Markdown**.

It is not a code defect. The tell is buried in the note attached to the first
error: `there are multiple different versions of crate serde_core in the
dependency graph`. `Cargo.lock` pins exactly one `serde 1.0.228` /
`serde_core 1.0.228`, and `cargo tree -i serde_core` shows one version — so the
duplication was two incompatible rlibs of the *same* version left in `target/`
by earlier builds under different `-p` selections and feature unification. A
derive from one copy does not satisfy a bound from the other, so every
`#[derive(Serialize)]` in the workspace appears not to exist.

Repair, and it is cheap:

```
cargo clean -p serde_core -p serde -p serde_json   # removed 425 files, 260 MiB
cargo test --workspace --exclude nostr-bbs-forum-client
```

Back to 1589 passing, 0 failing, with no source change. If you see mass
`Serialize`/`Deserialize` bound failures in a tree whose `git status` is clean,
check for that `multiple different versions` note before you start editing code.
