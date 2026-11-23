-- 0015: one-off backfill of event_tags.created_at (paged history reads).
--
-- Why: a tag-filtered REQ (`#e:[channel]`, `limit`, `until`) used to drive from
-- `SELECT DISTINCT event_id FROM event_tags …`, which no index can return in
-- time order, so D1 visited and sorted EVERY message of the channel before the
-- LIMIT (about 90k rows read for a 100-row page of a 30k-message channel). The
-- relay now walks `idx_event_tags_time (name, value, created_at, event_id)`
-- newest-first and stops after `limit` rows, which needs the event's
-- timestamp on its tag rows.
--
-- What the relay already does at boot (`ensure_schema`, every deployment, so
-- this file does NOT repeat it):
--   * ALTER TABLE event_tags ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0
--   * replaces the tag writer with `trg_event_tags_ai_v3`, which copies
--     NEW.created_at and writes each distinct (name, value) of an event once
--   * CREATE INDEX idx_event_tags_time ON event_tags(name, value, created_at, event_id)
--   * CREATE INDEX idx_events_kind_time ON events(kind, created_at)
--
-- What only this file does, once per existing database:
--   1. copy events.created_at onto tag rows written before v3 (created_at = 0);
--   2. drop duplicate (event_id, name, value) rows that older writers produced
--      for an event repeating a tag, so a per-value page never counts one
--      event twice against its LIMIT.
--
-- Order: deploy the relay, let it boot once (any HTTP request runs
-- ensure_schema), THEN apply this file. On a database whose relay has not
-- booted yet the column does not exist and this file fails harmlessly with
-- "no such column"; apply it after the boot. On a fresh database there is
-- nothing to backfill and it can be skipped. Until it runs, tag rows of older
-- events carry created_at = 0: a tag-filtered read sorts them after every
-- newer event and a `since` bound drops them, so run it straight after the
-- deploy.
--
-- Idempotent: both statements only touch rows that still need it, so a
-- second run reads the table and changes nothing.

UPDATE event_tags
SET created_at = (SELECT e.created_at FROM events e WHERE e.id = event_tags.event_id)
WHERE created_at = 0
  AND EXISTS (SELECT 1 FROM events e WHERE e.id = event_tags.event_id AND e.created_at <> 0);

DELETE FROM event_tags
WHERE rowid NOT IN (
  SELECT MIN(rowid) FROM event_tags GROUP BY event_id, name, value
);
