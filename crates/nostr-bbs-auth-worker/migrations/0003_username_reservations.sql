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

-- Real-name redesign: OPTIONAL admin-only legal/provisioning name.
-- NEVER published to the relay or kind-0 (both public). Returned only on
-- admin-gated read routes and the owner's own authed read. Co-located with
-- the username reservation (one row per pubkey) so the admin registration
-- view is a single-table read. ALTER is idempotent in `schema::ensure_schema`
-- (the duplicate-column error is swallowed); raw migration apply runs once.
-- UP:
ALTER TABLE username_reservations ADD COLUMN real_name TEXT;
-- DOWN: ALTER TABLE username_reservations DROP COLUMN real_name;
