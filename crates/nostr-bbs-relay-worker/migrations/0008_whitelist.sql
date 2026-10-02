-- ADR-2014 phase 1: the relay `whitelist` table, checked in.
--
-- Until now no DDL in the repository created this table. `SETUP.md` told an
-- operator to create the five base columns by hand, `ensure_schema()` in
-- `src/lib.rs` added ten more by `ALTER TABLE`, and `expires_at`, which
-- admission reads (`expires_at IS NULL OR expires_at > now`), was created by
-- nothing at all. A fresh instance that skipped the SETUP step had no table, so
-- every admission and every whitelist write failed.
--
-- This is the whole table as the workers use it. Column types repeat the
-- `ALTER` statements in `ensure_schema()` exactly, so a table created here and
-- one grown column by column are the same shape.
--
-- NOTE ON THE LIVE PATH: as 0006 and 0007, this file is the readable record and
-- the schema a deployed relay gets comes from `ensure_schema()`. That function
-- runs this same statement first (`nostr_bbs_core::whitelist_sql::
-- WHITELIST_CREATE_SQL`, which a test holds identical to this file) and then
-- the `ALTER TABLE whitelist ADD COLUMN` list, which now includes `expires_at`.
-- On an existing table the CREATE is a no-op and each ALTER either adds a
-- missing column or fails harmlessly on a duplicate. **The two move together.**
--
-- NOTE ON IDEMPOTENCY: `IF NOT EXISTS` makes this file safe to re-run. It adds
-- no column to an existing table; that is the ALTER list's job, for the reason
-- 0006 gives (SQLite has no `ADD COLUMN IF NOT EXISTS`).
--
-- Cohorts are a JSON array of strings. Every write to them goes through
-- `WHITELIST_GRANT_COHORTS_SQL` (merge) or `WHITELIST_REVOKE_COHORTS_SQL`
-- (named removal); nothing replaces the set (ADR-2014 D2).

CREATE TABLE IF NOT EXISTS whitelist (
    pubkey TEXT PRIMARY KEY,
    cohorts TEXT NOT NULL DEFAULT '["members"]',
    added_at INTEGER NOT NULL,
    added_by TEXT NOT NULL DEFAULT 'auto-registration',
    is_admin INTEGER NOT NULL DEFAULT 0,
    trust_level INTEGER NOT NULL DEFAULT 0,
    days_active INTEGER NOT NULL DEFAULT 0,
    posts_read INTEGER NOT NULL DEFAULT 0,
    posts_created INTEGER NOT NULL DEFAULT 0,
    mod_actions_against INTEGER NOT NULL DEFAULT 0,
    last_active_at INTEGER,
    trust_level_updated_at INTEGER,
    suspended_until INTEGER,
    silenced INTEGER NOT NULL DEFAULT 0,
    user_notes TEXT,
    expires_at INTEGER
);
