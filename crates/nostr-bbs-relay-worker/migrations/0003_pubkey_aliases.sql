-- Migration 0003: Pubkey alias map (Task #7 — identity inheritance)
--
-- Nostr events are signed and bound to a pubkey; an admin can NEVER re-sign
-- another key's events. Identity inheritance is therefore modelled as an alias
-- map rather than by rewriting authorship: a newly-joining `new_pubkey` is
-- linked to a prior `old_pubkey` so that
--   * the DISPLAY layer attributes the new key's posts under the prior handle,
--   * cohort/access can be INHERITED (the new whitelist row copies the old
--     pubkey's cohorts at link time — see /api/admin/alias).
--
-- `new_pubkey` is the PRIMARY KEY: a joining key maps to at most one prior
-- identity; re-linking overwrites. Set/listed via the NIP-98 admin endpoints
-- POST /api/admin/alias and GET /api/admin/aliases.
--
-- Idempotently re-applied at worker cold start via `ensure_schema` in lib.rs.

-- UP:
CREATE TABLE IF NOT EXISTS pubkey_aliases (
    new_pubkey  TEXT PRIMARY KEY NOT NULL,
    old_pubkey  TEXT NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    reason      TEXT
);
-- DOWN: DROP TABLE pubkey_aliases;

CREATE INDEX IF NOT EXISTS idx_pubkey_aliases_old
    ON pubkey_aliases(old_pubkey);
-- DOWN: DROP INDEX idx_pubkey_aliases_old;
