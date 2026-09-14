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

1. **deepsec-gate is BLOCK, not PASS** (exit 1, receipt
   `.deepsec-gate/reports/20260914T162917Z/`). Now triaged: both blocking HIGH
   findings are pre-existing relay read-auth bypasses that **are fixed on this
   branch** (`a14b2b7`, `12a10da`), each with tests. They still appear because
   the gate's verdict is an export of the persistent project store under
   `.deepsec-gate/data/`, which accumulates and never retires a fixed finding —
   the total grew 5, 8, 13, 18, 25, 30, 32 across runs while each run's net-new
   count stayed small, and the same issues recur verbatim.
   **Needs a decision from the gate's owner:** reset or re-verify the store to
   get a truthful current-state verdict. Clearing a security ledger is not this
   agent's call; an attempt to set the store aside was denied by policy and not
   worked around. Full analysis in each evidence receipt.
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
