-- The relay `events` table and the `channel_creators` projection, checked in.
--
-- Until now no migration created `events`. `ensure_schema()` in `src/lib.rs`
-- only indexed it, and the SQL in `SETUP.md` listed seven columns, omitting
-- `d_tag` and `received_at`, which `relay_do/storage.rs` inserts on every save.
-- A deploy that followed the docs therefore failed every write.
--
-- NOTE ON THE LIVE PATH: as 0006 to 0008, this file is the readable record and
-- the schema a deployed relay gets comes from `ensure_schema()`. That function
-- runs these same two statements (`EVENTS_CREATE_SQL`, `CHANNEL_CREATORS_CREATE_SQL`,
-- which `tests/events_schema.rs` holds identical to this file) and then adds
-- `d_tag` and `received_at` by `ALTER TABLE` to a table created from the older
-- SETUP.md. SQLite has no `ADD COLUMN IF NOT EXISTS`, so this file adds no column
-- to an existing table; apply these two by hand on such a database:
--
--   ALTER TABLE events ADD COLUMN d_tag TEXT NOT NULL DEFAULT '';
--   ALTER TABLE events ADD COLUMN received_at INTEGER NOT NULL DEFAULT 0;
--
-- `d_tag` is the first `d` tag value (empty when absent), used by the
-- parameterised-replaceable delete in `save_event`. `received_at` is the relay's
-- own clock at save time, in seconds.

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    pubkey TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    kind INTEGER NOT NULL,
    tags TEXT NOT NULL,
    content TEXT NOT NULL,
    sig TEXT NOT NULL,
    d_tag TEXT NOT NULL DEFAULT '',
    received_at INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_pubkey ON events(pubkey);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
CREATE INDEX IF NOT EXISTS idx_events_replaceable ON events(kind, pubkey, d_tag);

-- The creator of each kind-40 channel, written when the channel is saved. The
-- creator was previously re-resolved from the kind-40 event, so a kind-5
-- deletion of that event stripped a TL2 creator's kind-41 rights.

CREATE TABLE IF NOT EXISTS channel_creators (
    channel_id TEXT PRIMARY KEY,
    pubkey TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
