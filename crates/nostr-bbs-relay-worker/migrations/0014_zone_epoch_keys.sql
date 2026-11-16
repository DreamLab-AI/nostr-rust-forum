-- Phase 4b (ADR-2028 decision 6): one key per zone and epoch.
--
-- The relay is the single authority. The first `zk` pubkey seen for a
-- (zone, epoch) is stored; a later write naming a different pubkey is refused.
-- Read and written only behind the ZONE_GROUPS_ENABLED wrangler var (default
-- off). Held identical to ZONE_EPOCH_KEYS_CREATE_SQL in src/zone_groups.rs by a test.
CREATE TABLE IF NOT EXISTS zone_epoch_keys (
    zone       TEXT NOT NULL,
    epoch      INTEGER NOT NULL,
    pubkey     TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    PRIMARY KEY (zone, epoch)
);
