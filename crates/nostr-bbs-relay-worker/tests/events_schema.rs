//! TODO-unified S-2 guards over the `events` table and `channel_creators`.
//!
//! The relay Worker runs on D1, which is SQLite, so the migration and the DDL
//! `ensure_schema()` runs can be exercised against a real SQLite here:
//!
//! - the checked-in migration and the DDL constants are the same statements;
//! - the `INSERT` in `relay_do/storage.rs` succeeds against the created table
//!   (the regression: SETUP.md once omitted `d_tag` and `received_at`);
//! - a table created from the older SETUP.md gains the missing columns;
//! - the channel creator outlives a deletion of its kind-40 event.

use std::fs;
use std::path::Path;

use nostr_bbs_relay_worker::{CHANNEL_CREATORS_CREATE_SQL, EVENTS_CREATE_SQL};
use rusqlite::Connection;

fn read(rel: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)).expect(rel)
}

fn normalise_sql(sql: &str) -> String {
    let stripped: String = sql
        .lines()
        .map(|l| l.split("--").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ");
    stripped
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("( ", "(")
        .replace(" )", ")")
}

/// The first `CREATE TABLE IF NOT EXISTS <name>` statement in the migration.
fn migration_statement(name: &str) -> String {
    let sql = read("migrations/0009_events.sql");
    let start = sql
        .find(&format!("CREATE TABLE IF NOT EXISTS {name}"))
        .unwrap_or_else(|| panic!("0009 creates {name}"));
    let end = start + sql[start..].find(';').expect("statement terminator");
    normalise_sql(&sql[start..end])
}

/// The `INSERT INTO events` literal in `save_event`, joined across its `\` continuations.
fn storage_insert() -> String {
    let src = read("src/relay_do/storage.rs");
    let start = src.find("INSERT INTO events").expect("save_event INSERT");
    let end = start + src[start..].find('"').expect("closing quote");
    src[start..end]
        .replace("\\\n", " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn fresh() -> Connection {
    let db = Connection::open_in_memory().expect("sqlite");
    db.execute_batch(&read("migrations/0009_events.sql"))
        .expect("0009 applies");
    db
}

#[test]
fn migration_0009_matches_the_ddl_ensure_schema_runs() {
    assert_eq!(
        migration_statement("events"),
        normalise_sql(EVENTS_CREATE_SQL)
    );
    assert_eq!(
        migration_statement("channel_creators"),
        normalise_sql(CHANNEL_CREATORS_CREATE_SQL)
    );
}

#[test]
fn migration_is_idempotent() {
    let db = fresh();
    db.execute_batch(&read("migrations/0009_events.sql"))
        .expect("a second run is a no-op");
}

#[test]
fn save_event_insert_succeeds_against_the_migrated_table() {
    let db = fresh();
    let insert = storage_insert();
    assert!(insert.contains("d_tag") && insert.contains("received_at"));
    db.execute(
        &insert,
        rusqlite::params!["id1", "pk", 1_i64, 40_i64, "[]", "c", "sig", "", 2_i64],
    )
    .expect("INSERT matches the table");
    // Re-delivery of the same id is ignored, not an error (ON CONFLICT DO NOTHING).
    db.execute(
        &insert,
        rusqlite::params!["id1", "pk", 1_i64, 40_i64, "[]", "c", "sig", "", 2_i64],
    )
    .expect("duplicate id is a no-op");
    let n: i64 = db
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);
}

#[test]
fn the_setup_md_seven_column_table_is_the_failure_the_migration_fixes() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "CREATE TABLE events (id TEXT PRIMARY KEY, pubkey TEXT NOT NULL, kind INTEGER NOT NULL, \
         created_at INTEGER NOT NULL, content TEXT NOT NULL, tags TEXT NOT NULL, sig TEXT NOT NULL);",
    )
    .unwrap();
    let insert = storage_insert();
    let params = rusqlite::params!["id1", "pk", 1_i64, 40_i64, "[]", "c", "sig", "", 2_i64];
    assert!(
        db.execute(&insert, params).is_err(),
        "the old table rejects every write"
    );

    // What ensure_schema() adds to such a table.
    for alter in [
        "ALTER TABLE events ADD COLUMN d_tag TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE events ADD COLUMN received_at INTEGER NOT NULL DEFAULT 0",
    ] {
        let lib = read("src/lib.rs");
        assert!(
            lib.contains(&format!("\"{alter}\"")),
            "ensure_schema runs: {alter}"
        );
        db.execute(alter, []).expect("alter");
    }
    db.execute(&insert, params)
        .expect("writes succeed once altered");
}

#[test]
fn ensure_schema_creates_events_before_altering_or_indexing_it() {
    let lib = read("src/lib.rs");
    let create = lib.find("db.prepare(EVENTS_CREATE_SQL)").expect("create");
    let alter = lib
        .find("ALTER TABLE events ADD COLUMN d_tag")
        .expect("alter");
    let index = lib.find("idx_events_replaceable").expect("index");
    assert!(create < alter && alter < index);
}

#[test]
fn channel_creator_survives_deletion_of_the_kind_40_event() {
    let db = fresh();
    let insert = storage_insert();
    db.execute(
        &insert,
        rusqlite::params!["chan1", "creator", 1_i64, 40_i64, "[]", "{}", "sig", "", 2_i64],
    )
    .unwrap();
    // The statement save_event runs for a stored kind-40.
    let src = read("src/relay_do/storage.rs");
    assert!(src.contains("INSERT INTO channel_creators (channel_id, pubkey, created_at)"));
    db.execute(
        "INSERT INTO channel_creators (channel_id, pubkey, created_at) VALUES (?1, ?2, ?3) \
         ON CONFLICT (channel_id) DO NOTHING",
        rusqlite::params!["chan1", "creator", 1_i64],
    )
    .unwrap();
    db.execute("DELETE FROM events WHERE id = 'chan1'", [])
        .unwrap(); // kind-5 deletion

    let creator = |sql: &str| -> Option<String> { db.query_row(sql, ["chan1"], |r| r.get(0)).ok() };
    assert_eq!(
        creator("SELECT pubkey FROM channel_creators WHERE channel_id = ?1").as_deref(),
        Some("creator")
    );
    assert_eq!(
        creator("SELECT pubkey FROM events WHERE id = ?1 AND kind = 40"),
        None,
        "the old lookup lost the creator"
    );
}

#[test]
fn the_members_table_is_no_longer_queried() {
    assert!(!read("src/auth.rs").contains("FROM members"));
}
