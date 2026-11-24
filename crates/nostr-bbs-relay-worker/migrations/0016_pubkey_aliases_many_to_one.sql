-- Migration 0016: pubkey_aliases keyed by old_pubkey (many predecessors -> one successor)
--
-- 0003 made `new_pubkey` the primary key, so a successor could replace only
-- ONE old key: linking a second silently overwrote the first. A person with
-- several old keys (or archive keys) needs all of them to resolve to their
-- one live key. Now `old_pubkey` is the primary key (a replaced key has
-- exactly one successor) and `new_pubkey` is indexed (a successor's
-- predecessors). Successors still resolve ONE hop.
--
-- Data is kept: rows are copied oldest first with REPLACE, so an old key the
-- earlier shape linked to several successors keeps its latest link.
--
-- The relay's ensure_schema performs the same rebuild at boot when it finds
-- the earlier shape (PUBKEY_ALIASES_UPGRADE_STMTS), so a deployment upgrades
-- whether or not this file is applied. Idempotent: on the new shape it
-- rebuilds the same rows.

DROP TABLE IF EXISTS pubkey_aliases_v2;
CREATE TABLE pubkey_aliases_v2 (
    old_pubkey  TEXT PRIMARY KEY NOT NULL,
    new_pubkey  TEXT NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    reason      TEXT
);
INSERT OR REPLACE INTO pubkey_aliases_v2 (old_pubkey, new_pubkey, created_by, created_at, reason)
    SELECT old_pubkey, new_pubkey, created_by, created_at, reason FROM pubkey_aliases
    ORDER BY created_at ASC, rowid ASC;
DROP TABLE pubkey_aliases;
ALTER TABLE pubkey_aliases_v2 RENAME TO pubkey_aliases;
CREATE INDEX IF NOT EXISTS idx_pubkey_aliases_new ON pubkey_aliases(new_pubkey);
