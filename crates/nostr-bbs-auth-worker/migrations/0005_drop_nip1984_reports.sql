-- Migration 0005: drop the never-populated `nip1984_reports` table.
--
-- Nothing ever wrote to it. Kind-1984 (NIP-56) reports are stored by the
-- relay worker in the `reports` table of its own D1, which the auth worker
-- reads through its `RELAY_DB` binding for GET /api/moderation/reports.
-- The auth worker's own `mod_reports` (kind-30913) is unaffected.

-- UP:
DROP INDEX IF EXISTS idx_nip1984_reports_created;
DROP TABLE IF EXISTS nip1984_reports;
-- DOWN: CREATE TABLE IF NOT EXISTS nip1984_reports (event_id TEXT PRIMARY KEY, pubkey TEXT NOT NULL, created_at INTEGER NOT NULL, content TEXT NOT NULL DEFAULT '', tags_json TEXT NOT NULL DEFAULT '[]'); CREATE INDEX IF NOT EXISTS idx_nip1984_reports_created ON nip1984_reports(created_at DESC);
