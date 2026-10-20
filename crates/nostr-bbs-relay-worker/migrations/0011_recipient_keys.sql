-- Phase 2 (ADR-2027 decision 2): private recipient keys.
--
-- A member registers a random inbox key so zone-key grants and session-mirror
-- wraps are addressed to a key their other NIP-17 clients cannot decrypt. The
-- row is private: a public event would link identity and inbox key. The relay
-- reads it only behind the RECIPIENT_KEYS_ENABLED wrangler var (default off),
-- and never uses it to authenticate: a recipient key can receive wraps, it can
-- not act as its owner. `role = 'epoch'` is reserved for Phase 4.
--
-- Held identical to RECIPIENT_KEYS_CREATE_SQL in src/recipient_keys.rs by a test.
CREATE TABLE IF NOT EXISTS recipient_keys (
    key          TEXT PRIMARY KEY,
    owner_pubkey TEXT NOT NULL,
    zone         TEXT,
    role         TEXT NOT NULL CHECK(role IN ('inbox','epoch')),
    created_at   INTEGER NOT NULL,
    revoked      INTEGER NOT NULL DEFAULT 0,
    proof        TEXT
);

CREATE INDEX IF NOT EXISTS idx_recipient_keys_owner ON recipient_keys(owner_pubkey);
