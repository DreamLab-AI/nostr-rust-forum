//! Idempotent schema bootstrap for the auth-worker D1 database.
//!
//! Mirrors the `migrations/002_mod_wot_invites_welcome.sql` file so the
//! worker can self-apply the schema on cold start without requiring
//! `wrangler d1 migrations apply` to run first. All statements are safe
//! to re-run: tables use `CREATE TABLE IF NOT EXISTS`, indexes use
//! `CREATE INDEX IF NOT EXISTS`, and `ALTER TABLE ADD COLUMN` errors
//! are silently swallowed when the column already exists.

use worker::Env;

/// Apply the moderation / WoT / invites / welcome schema idempotently.
///
/// Called from the top of every `fetch` handler in `lib.rs`. Failure to
/// create a table is logged but does not short-circuit the request:
/// most handlers will return a useful error when they later hit the
/// missing table, and swallowing the error here keeps unrelated endpoints
/// (e.g. `/health`) working during a partial-provisioning state.
pub async fn ensure_schema(env: &Env) {
    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return,
    };

    // --- Base tables that webauthn.rs depends on (existed pre-sprint) ----
    let base_stmts = [
        "CREATE TABLE IF NOT EXISTS challenges (\
            pubkey TEXT NOT NULL, \
            challenge TEXT NOT NULL, \
            created_at INTEGER NOT NULL\
        )",
        "CREATE TABLE IF NOT EXISTS webauthn_credentials (\
            pubkey TEXT NOT NULL, \
            credential_id TEXT NOT NULL, \
            public_key TEXT NOT NULL, \
            counter INTEGER NOT NULL DEFAULT 0, \
            prf_salt TEXT, \
            created_at INTEGER NOT NULL\
        )",
    ];
    for stmt in base_stmts {
        let _ = db.prepare(stmt).run().await;
    }

    // --- NIP-1984 standard report events (kind-1984) --------------------
    // Populated by the relay-worker when it stores kind-1984 events.
    // The auth-worker reads from this table at GET /api/moderation/reports.
    let _ = db
        .prepare(
            "CREATE TABLE IF NOT EXISTS nip1984_reports (\
                event_id TEXT PRIMARY KEY, \
                pubkey TEXT NOT NULL, \
                created_at INTEGER NOT NULL, \
                content TEXT NOT NULL DEFAULT '', \
                tags_json TEXT NOT NULL DEFAULT '[]'\
            )",
        )
        .run()
        .await;
    let _ = db
        .prepare(
            "CREATE INDEX IF NOT EXISTS idx_nip1984_reports_created \
             ON nip1984_reports(created_at DESC)",
        )
        .run()
        .await;

    // --- WI-2: moderation tables + indexes ------------------------------
    let mod_stmts = [
        "CREATE TABLE IF NOT EXISTS moderation_actions (\
            id TEXT PRIMARY KEY, \
            action TEXT NOT NULL, \
            target_pubkey TEXT NOT NULL, \
            performed_by TEXT NOT NULL, \
            reason TEXT, \
            expires_at INTEGER, \
            event_id TEXT NOT NULL, \
            created_at INTEGER NOT NULL\
        )",
        "CREATE INDEX IF NOT EXISTS idx_mod_actions_target ON moderation_actions(target_pubkey)",
        "CREATE INDEX IF NOT EXISTS idx_mod_actions_active ON moderation_actions(action, expires_at)",
        "CREATE TABLE IF NOT EXISTS mod_reports (\
            id TEXT PRIMARY KEY, \
            reporter_pubkey TEXT NOT NULL, \
            target_event_id TEXT NOT NULL, \
            target_pubkey TEXT NOT NULL, \
            reason TEXT NOT NULL, \
            status TEXT NOT NULL DEFAULT 'open', \
            event_id TEXT NOT NULL, \
            created_at INTEGER NOT NULL, \
            actioned_by TEXT, \
            actioned_at INTEGER\
        )",
        "CREATE INDEX IF NOT EXISTS idx_mod_reports_status ON mod_reports(status)",
        "CREATE INDEX IF NOT EXISTS idx_mod_reports_target ON mod_reports(target_pubkey)",
    ];
    for stmt in mod_stmts {
        let _ = db.prepare(stmt).run().await;
    }

    // --- WI-3: WoT table + instance_settings extensions -----------------
    let wot_stmts = [
        "CREATE TABLE IF NOT EXISTS wot_entries (\
            pubkey TEXT PRIMARY KEY, \
            added_at INTEGER NOT NULL, \
            source TEXT NOT NULL\
        )",
        "CREATE INDEX IF NOT EXISTS idx_wot_source ON wot_entries(source)",
    ];
    for stmt in wot_stmts {
        let _ = db.prepare(stmt).run().await;
    }

    // --- WI-4: members + invitations tables -----------------------------
    let invite_stmts = [
        "CREATE TABLE IF NOT EXISTS members (\
            pubkey TEXT PRIMARY KEY, \
            is_admin INTEGER NOT NULL DEFAULT 0, \
            joined_via_invite_id TEXT, \
            first_seen_at INTEGER, \
            created_at INTEGER NOT NULL\
        )",
        "CREATE TABLE IF NOT EXISTS invitations (\
            id TEXT PRIMARY KEY, \
            code TEXT UNIQUE NOT NULL, \
            issued_by TEXT NOT NULL, \
            max_uses INTEGER NOT NULL DEFAULT 1, \
            uses INTEGER NOT NULL DEFAULT 0, \
            expires_at INTEGER NOT NULL, \
            revoked_at INTEGER, \
            revoked_by TEXT, \
            created_at INTEGER NOT NULL\
        )",
        "CREATE INDEX IF NOT EXISTS idx_invitations_code ON invitations(code)",
        "CREATE INDEX IF NOT EXISTS idx_invitations_issuer ON invitations(issued_by)",
        "CREATE TABLE IF NOT EXISTS invitation_redemptions (\
            invitation_id TEXT NOT NULL, \
            pubkey TEXT NOT NULL, \
            redeemed_at INTEGER NOT NULL, \
            PRIMARY KEY (invitation_id, pubkey), \
            FOREIGN KEY (invitation_id) REFERENCES invitations(id)\
        )",
    ];
    for stmt in invite_stmts {
        let _ = db.prepare(stmt).run().await;
    }

    // --- WI-5: welcome-bot outbox --------------------------------------
    let welcome_stmts = [
        "CREATE TABLE IF NOT EXISTS welcome_messages (\
            event_id TEXT PRIMARY KEY, \
            target_pubkey TEXT NOT NULL, \
            locale TEXT NOT NULL, \
            signed_json TEXT NOT NULL, \
            sent_at INTEGER, \
            created_at INTEGER NOT NULL\
        )",
        "CREATE INDEX IF NOT EXISTS idx_welcome_messages_pending \
         ON welcome_messages(sent_at) WHERE sent_at IS NULL",
    ];
    for stmt in welcome_stmts {
        let _ = db.prepare(stmt).run().await;
    }

    // --- Shared: instance_settings (single-row config) ------------------
    let _ = db
        .prepare(
            "CREATE TABLE IF NOT EXISTS instance_settings (\
                id INTEGER PRIMARY KEY CHECK (id = 1), \
                wot_enabled INTEGER NOT NULL DEFAULT 0, \
                wot_referente_pubkey TEXT, \
                wot_last_fetched_at INTEGER, \
                wot_follow_count INTEGER, \
                min_days_active INTEGER NOT NULL DEFAULT 7, \
                invites_per_user INTEGER NOT NULL DEFAULT 3, \
                invite_expiry_hours INTEGER NOT NULL DEFAULT 168, \
                welcome_enabled INTEGER NOT NULL DEFAULT 0, \
                welcome_channel_id TEXT, \
                welcome_message_en TEXT, \
                welcome_message_es TEXT, \
                welcome_bot_pubkey TEXT, \
                welcome_bot_nsec_encrypted TEXT\
            )",
        )
        .run()
        .await;
    let _ = db
        .prepare("INSERT OR IGNORE INTO instance_settings (id) VALUES (1)")
        .run()
        .await;

    // --- Sprint v10: username reservations (idempotent) -----------------
    let username_stmts = [
        "CREATE TABLE IF NOT EXISTS username_reservations (\
            username TEXT PRIMARY KEY NOT NULL \
                CHECK (length(username) BETWEEN 3 AND 30), \
            pubkey TEXT NOT NULL UNIQUE, \
            created_at INTEGER NOT NULL DEFAULT (unixepoch()), \
            status TEXT NOT NULL DEFAULT 'active'\
        )",
        "CREATE INDEX IF NOT EXISTS idx_username_reservations_pubkey \
         ON username_reservations(pubkey)",
    ];
    for stmt in username_stmts {
        let _ = db.prepare(stmt).run().await;
    }

    // Agent Control Surface Protocol tables (agent_registry, broker_cases,
    // broker_decisions, broker_roles) live in the relay worker's D1
    // (dreamlab-relay, bound as RELAY_DB). They are NOT created here.
    // The relay-worker's ensure_tables_exist() manages their schema.
    // The governance_api.rs handlers read/write via the RELAY_DB binding.
}
