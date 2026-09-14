-- ADR-2011 / PRD-augmentation-conditions FR3, FR4.3, FR6.2: the effective
-- escalation boundary, the calibration/probe marks, per-case delegation, and
-- the side receipts a case can accrue without a decision.
--
-- Additive only. Every column is nullable or carries a default, so a legacy
-- row keeps working and a legacy writer that never sets them is still correct:
-- an absent `effective_tier` reads as "this case predates ADR-2011", which is
-- exactly what it is.
--
-- NOTE ON IDEMPOTENCY: unlike 0001-0005 this migration uses `ALTER TABLE ADD
-- COLUMN`, which SQLite has no `IF NOT EXISTS` form for. It is applied once by
-- `wrangler d1 migrations apply`, which records what it has run; re-running the
-- file by hand will error on the first duplicate column and change nothing.
--
-- NOTE ON THE LIVE PATH: this file is the readable record. The schema a deployed
-- relay actually gets comes from `ensure_schema()` in `src/lib.rs`, which the
-- worker runs at startup and which discards the duplicate-column error. Every
-- statement below is mirrored there. **The two move together** — a column added
-- here and not there simply does not exist in production.

-- ── Effective tier and the properties it derives from (ADR-2011) ────────────

-- The requesting agent's own `risk_tier`. Telemetry only from here on: kept so
-- declared-vs-effective divergence is measurable per agent.
ALTER TABLE broker_cases ADD COLUMN declared_tier TEXT;
-- The tier that actually governs the case. The ONLY tier a consumer reads for
-- suppression or routing (DDD §6 invariant 3).
ALTER TABLE broker_cases ADD COLUMN effective_tier TEXT;
-- The merged (panel-tightened) task-property triple the tier derives from,
-- stored so a reviewer and an auditor can see *why* the tier is what it is.
ALTER TABLE broker_cases ADD COLUMN tp_verifiability TEXT;
ALTER TABLE broker_cases ADD COLUMN tp_reversibility TEXT;
ALTER TABLE broker_cases ADD COLUMN tp_stakes TEXT;

-- ── Calibration sampling and seeded probes (FR6.3, FR6.4) ──────────────────

-- 1 when the deterministic hash of the request id fell below the panel's
-- calibration rate: the case is shown to reviewers rather than suppressed.
ALTER TABLE broker_cases ADD COLUMN calibration_sample INTEGER NOT NULL DEFAULT 0;
-- The seeded-probe digest, present only when the panel's REGISTERED probe
-- agent published it. Held here and NOT re-served on an undecided case: DDD §6
-- invariant 7 requires a probe to be blind until its 31403 exists.
ALTER TABLE broker_cases ADD COLUMN probe_digest TEXT;

-- ── Ageing (FR4.3) ─────────────────────────────────────────────────────────

-- The panel's `max_pending_hours` at the time the case was opened, copied onto
-- the case so the ageing cron is a single indexed scan rather than a panel
-- lookup per row.
ALTER TABLE broker_cases ADD COLUMN max_pending_hours INTEGER;

CREATE INDEX IF NOT EXISTS idx_broker_cases_effective_tier
    ON broker_cases(effective_tier);
CREATE INDEX IF NOT EXISTS idx_broker_cases_pending_age
    ON broker_cases(state, created_at);

-- ── Side receipts (FR4.3, FR4.5) ───────────────────────────────────────────

-- `escalated-on-age` and `expired` are receipts about a CASE, not about a
-- signed decision event, so they cannot live in `governance_receipts` — that
-- table is keyed by a full 64-hex signed event id and every row there certifies
-- a signature. Keying this table on (case_id, stage) is what makes the cron
-- idempotent by construction: "exactly once per case" is a primary key, not a
-- code path that has to remember.
CREATE TABLE IF NOT EXISTS case_side_receipts (
    case_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    detail TEXT,
    PRIMARY KEY (case_id, stage)
);
CREATE INDEX IF NOT EXISTS idx_case_side_receipts_stage ON case_side_receipts(stage);

-- ── Application receipts (FR4.1) ───────────────────────────────────────────

-- The mutation owner's own words about what happened, and who said it. The
-- stage itself advances the existing `governance_receipts.stage` column; these
-- record the provenance of that advance so an auditor can see who claimed it.
ALTER TABLE governance_receipts ADD COLUMN applied_at INTEGER;
ALTER TABLE governance_receipts ADD COLUMN applied_by TEXT;
ALTER TABLE governance_receipts ADD COLUMN acknowledgement TEXT;

-- ── Scoped delegation (FR6.2, DDD §6 invariant 6) ──────────────────────────

-- An admin's `Delegate{to}` on a case projects one row here; the 31403
-- admission gate consults it. A `reviewer`-role pubkey is otherwise read-only,
-- and a row here admits it for EXACTLY the named case — the delegation is
-- scoped, and the admin who granted it stays attributable.
CREATE TABLE IF NOT EXISTS case_delegations (
    case_id TEXT NOT NULL,
    delegate_pubkey TEXT NOT NULL,
    delegated_by TEXT NOT NULL,
    decision_id TEXT,
    delegated_at INTEGER NOT NULL,
    PRIMARY KEY (case_id, delegate_pubkey)
);
CREATE INDEX IF NOT EXISTS idx_case_delegations_delegate ON case_delegations(delegate_pubkey);

-- ── Probe blindness in the tag index (DDD §6 invariant 7) ──────────────────

-- `event_tags` (0004) is trigger-maintained and backs every `#tag` REQ filter.
-- A `probe` row there would let any client enumerate the seeded probes by
-- subscription, which destroys the catch rate the probes exist to measure. The
-- trigger below removes those rows as they are written, so no probe is ever
-- queryable by tag. The tag remains on the signed envelope, which is
-- unavoidable: stripping a tag from a signed event breaks the signature that
-- the forum client verifies strictly (`verify_event_strict`). Blindness on the
-- rendered surface is the client's own responsibility (FR6.4), and blindness in
-- the relay's D1 projection is enforced in `broker_cases`, which never re-serves
-- `probe_digest` for an undecided case.
--
-- The blinding is done in the tag-writing trigger ITSELF, not in a second
-- trigger that watches it. `event_tags` is written only by
-- `trg_event_tags_ai` (0004), an AFTER INSERT ON events; in SQLite a trigger
-- fired by a modification made INSIDE another trigger runs only when
-- `PRAGMA recursive_triggers = ON`, which defaults OFF and is set nowhere in
-- this worker (and is not on by default in D1). A watcher trigger therefore
-- never fired for the only path that writes probe rows, and the control was
-- inert while reading as enforcement. Filtering at the source needs no
-- recursion and cannot be switched off by a pragma.
--
-- 0004 created `trg_event_tags_ai` with IF NOT EXISTS, so it survives on a
-- deployed relay and must be dropped rather than redefined. The replacement
-- carries a new name so that the live `ensure_schema` path can drop the old
-- one idempotently without ever dropping the trigger currently in force.
DROP TRIGGER IF EXISTS trg_event_tags_ai;

CREATE TRIGGER IF NOT EXISTS trg_event_tags_ai_v2 AFTER INSERT ON events
BEGIN
  INSERT INTO event_tags (event_id, name, value)
  SELECT NEW.id,
         json_extract(je.value, '$[0]'),
         COALESCE(json_extract(je.value, '$[1]'), '')
  FROM json_each(NEW.tags) je
  WHERE json_type(je.value) = 'array'
    AND json_extract(je.value, '$[0]') IS NOT NULL
    AND json_extract(je.value, '$[0]') <> 'probe';
END;

-- Belt and braces: kept so that any other writer of `event_tags` (a backfill, a
-- future ingest path) is still blinded. It is not the primary control.
CREATE TRIGGER IF NOT EXISTS trg_event_tags_probe_blind AFTER INSERT ON event_tags
WHEN NEW.name = 'probe'
BEGIN
  DELETE FROM event_tags WHERE event_id = NEW.event_id AND name = 'probe';
END;

-- Purge rows written before the blinding existed. Mirrored in `ensure_schema`,
-- unlike the original, which was not — so a deployed relay kept every probe row
-- it had already indexed.
DELETE FROM event_tags WHERE name = 'probe';
