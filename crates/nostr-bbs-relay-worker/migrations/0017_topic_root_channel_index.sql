-- 0017: find one section's topic roots without walking the whole relay's (ADR-2038).
--
-- Why: SECTION-STATS lists a section's topic roots (kind-42 carrying the
-- ["t","topic"] marker). Through event_tags the only seekable key is
-- (name='t', value='topic'), which is every topic root on the relay, so a
-- small section on a large relay paid for every topic elsewhere (PR #134
-- review). This partial expression index holds topic roots only, keyed by
-- their first tag's value, which is the channel for every root the forum and
-- the sealed-original migrator write (topic_root_tags / seal_original put
-- ["e", <channel>, "", "root"] first). A root shaped otherwise is simply not
-- found through it (the relay's answer is a lower bound, never wrong).
--
-- Additive and idempotent: one new index, no table or column change, no data
-- rewritten. Write cost: the partial predicate is evaluated on each insert
-- (an instr() over the tags text); only topic roots add an index entry.
-- Build cost: one pass over `events` when created. The relay works without it
-- (a bounded walk that reports `truncated`), and uses it once it exists.
--
-- Rollback: DROP INDEX IF EXISTS idx_events_topic_root_channel;
-- (the relay falls back to the bounded walk on the next request).

CREATE INDEX IF NOT EXISTS idx_events_topic_root_channel
  ON events (json_extract(tags, '$[0][1]'), created_at)
  WHERE kind = 42 AND instr(tags, '["t","topic"]') > 0;
