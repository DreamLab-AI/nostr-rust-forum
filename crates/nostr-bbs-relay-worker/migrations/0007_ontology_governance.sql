-- ADR-2013 / PRD-sovereign-corpus §3.3: proposal expiry for the
-- `ontology-governance` panel.
--
-- Additive and nullable. A case that is not an ontology proposal has a NULL
-- `stale_after` and is invisible to the expiry sweep, which is exactly right:
-- expiry is a property of a PatchProposal, not of governance in general.
--
-- The value is copied off the 31402's `PatchProposal` body at projection time
-- rather than parsed out of `summary` on every sweep, for the same reason
-- `max_pending_hours` is copied in 0006: the cron must be one indexed scan.
--
-- NOTE ON IDEMPOTENCY and NOTE ON THE LIVE PATH: as 0006. `ensure_schema()` in
-- `src/lib.rs` mirrors this statement and is what a deployed relay actually
-- runs. The two move together.

ALTER TABLE broker_cases ADD COLUMN stale_after INTEGER;

-- The sweep's access path: still-pending cases with a declared expiry, oldest
-- expiry first. Partial on `stale_after IS NOT NULL` so the index carries only
-- the ontology cases rather than every case the forum has ever opened.
CREATE INDEX IF NOT EXISTS idx_broker_cases_stale_after
    ON broker_cases(stale_after) WHERE stale_after IS NOT NULL;
