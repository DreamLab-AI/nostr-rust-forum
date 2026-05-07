-- Migration 002: Moderation, Web-of-Trust, Invite credits, Welcome bot
--
-- Combined migration for the Obelisk-Polish sprint (WI-2, WI-3, WI-4, WI-5).
-- Applied idempotently at worker start-up via `schema::ensure_schema`.
--
-- `DOWN` notes are provided alongside each UP statement. To revert this
-- migration run the statements in the "-- DOWN:" blocks in reverse order.

-- ---------------------------------------------------------------------------
-- WI-2: Moderation
-- ---------------------------------------------------------------------------

-- UP:
CREATE TABLE IF NOT EXISTS moderation_actions (
    id TEXT PRIMARY KEY,              -- uuid / nanoid
    action TEXT NOT NULL,             -- ban|mute|warn|unban|unmute
    target_pubkey TEXT NOT NULL,
    performed_by TEXT NOT NULL,
    reason TEXT,
    expires_at INTEGER,               -- null for permanent
    event_id TEXT NOT NULL,           -- Nostr event id of the authoritative event
    created_at INTEGER NOT NULL
);
-- DOWN: DROP TABLE moderation_actions;

CREATE INDEX IF NOT EXISTS idx_mod_actions_target ON moderation_actions(target_pubkey);
CREATE INDEX IF NOT EXISTS idx_mod_actions_active ON moderation_actions(action, expires_at);
-- DOWN: DROP INDEX idx_mod_actions_target; DROP INDEX idx_mod_actions_active;

-- Drop-and-recreate pattern is unsafe in D1; instead we create a namespaced
-- copy. The relay-worker also owns a `reports` table (different shape) -- we
-- reuse the relay-worker's table when the DB is shared.
CREATE TABLE IF NOT EXISTS mod_reports (
    id TEXT PRIMARY KEY,
    reporter_pubkey TEXT NOT NULL,
    target_event_id TEXT NOT NULL,
    target_pubkey TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',  -- open|actioned|dismissed
    event_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    actioned_by TEXT,
    actioned_at INTEGER
);
-- DOWN: DROP TABLE mod_reports;

CREATE INDEX IF NOT EXISTS idx_mod_reports_status ON mod_reports(status);
CREATE INDEX IF NOT EXISTS idx_mod_reports_target ON mod_reports(target_pubkey);
-- DOWN: DROP INDEX idx_mod_reports_status; DROP INDEX idx_mod_reports_target;

-- ---------------------------------------------------------------------------
-- WI-3: Web-of-Trust
-- ---------------------------------------------------------------------------

-- UP: see schema::ensure_schema for the ALTER TABLE instance_settings adds:
--   wot_enabled, wot_referente_pubkey, wot_last_fetched_at, wot_follow_count.

CREATE TABLE IF NOT EXISTS wot_entries (
    pubkey TEXT PRIMARY KEY,
    added_at INTEGER NOT NULL,
    source TEXT NOT NULL              -- 'referente' | 'manual_override'
);
-- DOWN: DROP TABLE wot_entries;

CREATE INDEX IF NOT EXISTS idx_wot_source ON wot_entries(source);
-- DOWN: DROP INDEX idx_wot_source;

-- ---------------------------------------------------------------------------
-- WI-4: Invite credits
-- ---------------------------------------------------------------------------

-- UP: ALTERs on instance_settings: min_days_active, invites_per_user, invite_expiry_hours.
-- UP: ALTERs on members: joined_via_invite_id, first_seen_at.

CREATE TABLE IF NOT EXISTS members (
    pubkey TEXT PRIMARY KEY,
    is_admin INTEGER NOT NULL DEFAULT 0,
    joined_via_invite_id TEXT,
    first_seen_at INTEGER,
    created_at INTEGER NOT NULL
);
-- DOWN: DROP TABLE members;

CREATE TABLE IF NOT EXISTS invitations (
    id TEXT PRIMARY KEY,              -- nanoid 8
    code TEXT UNIQUE NOT NULL,        -- nanoid 16
    issued_by TEXT NOT NULL,          -- pubkey
    max_uses INTEGER NOT NULL DEFAULT 1,
    uses INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revoked_by TEXT,
    created_at INTEGER NOT NULL
);
-- DOWN: DROP TABLE invitations;

CREATE INDEX IF NOT EXISTS idx_invitations_code ON invitations(code);
CREATE INDEX IF NOT EXISTS idx_invitations_issuer ON invitations(issued_by);
-- DOWN: DROP INDEX idx_invitations_code; DROP INDEX idx_invitations_issuer;

CREATE TABLE IF NOT EXISTS invitation_redemptions (
    invitation_id TEXT NOT NULL,
    pubkey TEXT NOT NULL,
    redeemed_at INTEGER NOT NULL,
    PRIMARY KEY (invitation_id, pubkey),
    FOREIGN KEY (invitation_id) REFERENCES invitations(id)
);
-- DOWN: DROP TABLE invitation_redemptions;

-- ---------------------------------------------------------------------------
-- Shared: instance_settings (one-row config table, key-value style)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS instance_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    -- WI-3 WoT
    wot_enabled INTEGER NOT NULL DEFAULT 0,
    wot_referente_pubkey TEXT,
    wot_last_fetched_at INTEGER,
    wot_follow_count INTEGER,
    -- WI-4 invites
    min_days_active INTEGER NOT NULL DEFAULT 7,
    invites_per_user INTEGER NOT NULL DEFAULT 3,
    invite_expiry_hours INTEGER NOT NULL DEFAULT 168,
    -- WI-5 welcome bot
    welcome_enabled INTEGER NOT NULL DEFAULT 0,
    welcome_channel_id TEXT,
    welcome_message_en TEXT,
    welcome_message_es TEXT,
    welcome_bot_pubkey TEXT,
    welcome_bot_nsec_encrypted TEXT
);
-- DOWN: DROP TABLE instance_settings;

-- Seed the single row if it doesn't exist.
INSERT OR IGNORE INTO instance_settings (id) VALUES (1);
