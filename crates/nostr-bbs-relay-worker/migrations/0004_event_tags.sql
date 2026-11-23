-- 0004: indexed tag lookups (kills the instr() full-kind scans).
--
-- Why: every tag-filtered REQ (#e/#p/#t…) compiled to `instr(tags, ?) > 0`,
-- which cannot use an index — D1 walked every row of the kind on every
-- subscription. With a 15s keep-warm poller that was ~80% of all D1 rows
-- read (3–4.5M/day against a 730-row table). The NIP-40 expiry sweep's
-- `json_each` full scan (every 5 min cron) was second at ~10%.
--
-- Design: a side table `event_tags` maintained by TRIGGERS, not Rust code —
-- the relay deletes events from seven different code paths (retention cron,
-- NIP-09, moderation, user purge, replaceable-event supersede, admin wipe),
-- and a trigger is the only way to guarantee the side table can never drift.
-- All tag names are indexed (not just single-letter): the table is tiny and
-- it lets the expiry sweep use the same index via name='expiration'.

-- `created_at` (the event's time, for paged reads) is added to deployed
-- databases by the relay's `ensure_schema`; a fresh database gets it here so
-- the boot-time writer `trg_event_tags_ai_v3` never meets a table without it.
CREATE TABLE IF NOT EXISTS event_tags (
  event_id   TEXT NOT NULL,
  name       TEXT NOT NULL,
  value      TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL DEFAULT 0
);

-- (name, value, event_id) serves tag-filter EXISTS probes; covering, so the
-- probe never touches the base table. (event_id) serves the delete trigger.
CREATE INDEX IF NOT EXISTS idx_event_tags_lookup ON event_tags(name, value, event_id);
CREATE INDEX IF NOT EXISTS idx_event_tags_event  ON event_tags(event_id);

CREATE TRIGGER IF NOT EXISTS trg_event_tags_ai AFTER INSERT ON events
BEGIN
  INSERT INTO event_tags (event_id, name, value)
  SELECT NEW.id,
         json_extract(je.value, '$[0]'),
         COALESCE(json_extract(je.value, '$[1]'), '')
  FROM json_each(NEW.tags) je
  WHERE json_type(je.value) = 'array'
    AND json_extract(je.value, '$[0]') IS NOT NULL;
END;

CREATE TRIGGER IF NOT EXISTS trg_event_tags_ad AFTER DELETE ON events
BEGIN
  DELETE FROM event_tags WHERE event_id = OLD.id;
END;

-- Backfill existing rows (idempotent: wipe-and-rebuild).
DELETE FROM event_tags;
INSERT INTO event_tags (event_id, name, value)
SELECT e.id,
       json_extract(je.value, '$[0]'),
       COALESCE(json_extract(je.value, '$[1]'), '')
FROM events e, json_each(e.tags) je
WHERE json_type(je.value) = 'array'
  AND json_extract(je.value, '$[0]') IS NOT NULL;
