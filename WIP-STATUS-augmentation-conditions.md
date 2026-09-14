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
   `.deepsec-gate/reports/20260914T162917Z/`). 2 HIGH remain, both pre-existing
   and outside this feature. Untriaged at pause. The evidence receipts say so.
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
