-- Migration 0003: Username reservations (Sprint v10)
--
-- Server-enforced uniqueness layer on top of Nostr kind-0 metadata. Required
-- because Nostr cannot guarantee a single owner for any given `name` at the
-- protocol level. The forum-client onboarding modal calls
-- /api/username/{check,claim,release} against this table.
--
-- Applied idempotently at worker cold-start via `schema::ensure_schema`.

-- UP:
CREATE TABLE IF NOT EXISTS username_reservations (
    username   TEXT PRIMARY KEY NOT NULL
               CHECK (length(username) BETWEEN 3 AND 30),
    pubkey     TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    status     TEXT NOT NULL DEFAULT 'active'
);
-- DOWN: DROP TABLE username_reservations;

CREATE INDEX IF NOT EXISTS idx_username_reservations_pubkey
    ON username_reservations(pubkey);
-- DOWN: DROP INDEX idx_username_reservations_pubkey;
