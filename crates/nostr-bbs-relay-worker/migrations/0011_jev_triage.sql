-- Jev option (NF-03-S1-01): advisory moderation-triage annotations.
--
-- Written only by the opt-in `JEV_TRIAGE` cron sweep, AFTER an event has been
-- admitted and stored by the normal pipeline. A row never hides, deletes,
-- bans or rejects anything and is never read by admission, auth, trust or the
-- `reports` auto-hide. It is a queue for human moderators.
-- As with 0006 to 0010, the live schema comes from `ensure_schema()` in src/lib.rs,
-- which runs this same statement.

CREATE TABLE IF NOT EXISTS jev_triage (
    event_id TEXT PRIMARY KEY,
    channel_id TEXT NOT NULL,
    zone TEXT NOT NULL,
    spam REAL NOT NULL,
    abuse REAL NOT NULL,
    harm REAL NOT NULL,
    severity REAL NOT NULL,
    severity_confidence REAL NOT NULL,
    queued INTEGER NOT NULL,
    model TEXT NOT NULL,
    question_set TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_jev_triage_queue ON jev_triage(queued, created_at);
