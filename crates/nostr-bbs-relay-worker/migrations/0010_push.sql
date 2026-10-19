-- ADR-2023: content-free Web Push.
--
-- One row per installed browser/app instance that granted notification
-- permission. `endpoint` is the push service URL (SSRF-checked at the door);
-- `token_hash` is SHA-256 of the bearer token the service worker presents to
-- /api/push/drain; the token itself is never stored. The pending_* counters
-- and link_* deep links are the only "content" a notification ever carries,
-- and they are fetched by the service worker over HTTPS after the empty push
-- wakes it, not sent through the push service.
CREATE TABLE IF NOT EXISTS push_subscriptions (
    id             TEXT PRIMARY KEY,
    pubkey         TEXT NOT NULL,
    endpoint       TEXT NOT NULL,
    token_hash     TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    refreshed_at   INTEGER NOT NULL,
    last_push_at   INTEGER NOT NULL DEFAULT 0,
    failures       INTEGER NOT NULL DEFAULT 0,
    pending_dm     INTEGER NOT NULL DEFAULT 0,
    pending_reply  INTEGER NOT NULL DEFAULT 0,
    pending_topic  INTEGER NOT NULL DEFAULT 0,
    pending_post   INTEGER NOT NULL DEFAULT 0,
    link_reply     TEXT,
    link_topic     TEXT,
    link_post      TEXT
);
CREATE INDEX IF NOT EXISTS idx_push_subscriptions_pubkey ON push_subscriptions(pubkey);

-- Per-member alert preferences, shared by all of that member's devices.
-- Defaults: replies and DMs on; new topics and new posts are opt-in.
CREATE TABLE IF NOT EXISTS push_prefs (
    pubkey          TEXT PRIMARY KEY,
    replies         INTEGER NOT NULL DEFAULT 1,
    dms             INTEGER NOT NULL DEFAULT 1,
    new_topics      INTEGER NOT NULL DEFAULT 0,
    new_posts       INTEGER NOT NULL DEFAULT 0,
    muted_channels  TEXT NOT NULL DEFAULT '[]',
    quiet_start     INTEGER,
    quiet_end       INTEGER,
    tz_offset       INTEGER NOT NULL DEFAULT 0,
    updated_at      INTEGER NOT NULL DEFAULT 0
);
