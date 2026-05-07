-- Migration 0001: Profiles projection (Sprint v10)
--
-- The relay stores raw kind-0 NIP-01 metadata events in the `events` table.
-- This `profiles` table is a projection of the most recent kind-0 per pubkey,
-- with the JSON content fields parsed into typed columns. It is maintained by
-- the kind-0 ingest hook in `relay_do::storage::save_event`.
--
-- Consumers:
--   * /api/profiles/batch  -- bulk lookup (forum-client name resolution)
--   * /api/profiles/search -- prefix typeahead for @mention autocomplete
--
-- Idempotently re-applied at worker cold start via `ensure_schema` in lib.rs.

-- UP:
CREATE TABLE IF NOT EXISTS profiles (
    pubkey        TEXT PRIMARY KEY NOT NULL,
    name          TEXT,
    display_name  TEXT,
    picture       TEXT,
    banner        TEXT,
    about         TEXT,
    nip05         TEXT,
    lud16         TEXT,
    last_kind0_at INTEGER NOT NULL,
    raw_event     TEXT NOT NULL
);
-- DOWN: DROP TABLE profiles;

CREATE INDEX IF NOT EXISTS idx_profiles_name
    ON profiles(name);
-- DOWN: DROP INDEX idx_profiles_name;

CREATE INDEX IF NOT EXISTS idx_profiles_display_name
    ON profiles(display_name);
-- DOWN: DROP INDEX idx_profiles_display_name;

CREATE INDEX IF NOT EXISTS idx_profiles_last_kind0
    ON profiles(last_kind0_at DESC);
-- DOWN: DROP INDEX idx_profiles_last_kind0;
