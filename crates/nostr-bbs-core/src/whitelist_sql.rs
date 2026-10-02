//! SQL for the relay `whitelist` table, shared by every worker that writes it.
//!
//! The relay worker (`DB`) and the auth worker (`RELAY_DB`) both write the
//! same physical D1 table. Before ADR-2014 phase 1 each writer carried its own
//! copy of an upsert that **replaced** the member's cohort list, so granting
//! one cohort silently revoked every other. This module is the single
//! definition both workers bind, and its contract is the ADR-2014 D2 rule:
//!
//! - every grant is a **merge**: cohorts already held are kept, new ones are
//!   appended in order, nothing is duplicated;
//! - the only removal is an explicit revoke of named cohorts
//!   ([`WHITELIST_REVOKE_COHORTS_SQL`]);
//! - no statement here replaces the set wholesale.
//!
//! The merge runs inside SQLite (D1) as one statement, so two admins granting
//! different cohorts to the same member at once cannot lose either grant, which
//! a read-modify-write in the worker could.
//!
//! [`WHITELIST_CREATE_SQL`] is the table's DDL. It is mirrored verbatim by the
//! relay's `migrations/0008_whitelist.sql` and is the first statement of the
//! relay's `ensure_schema()`, which is the live schema path for a deployed
//! relay.
//!
//! ```
//! use nostr_bbs_core::whitelist_sql::{WHITELIST_GRANT_COHORTS_SQL, WHITELIST_REVOKE_COHORTS_SQL};
//!
//! // Bind order for a grant: pubkey, cohorts JSON array, added_at, added_by.
//! assert!(WHITELIST_GRANT_COHORTS_SQL.contains("?4"));
//! // Bind order for a revoke: pubkey, JSON array of cohorts to remove.
//! assert!(WHITELIST_REVOKE_COHORTS_SQL.contains("?2"));
//! ```

/// DDL for the relay `whitelist` table, with every column the workers read or
/// write.
///
/// The base columns match the table `SETUP.md` has historically told operators
/// to create; the rest were added over time by `ALTER TABLE` in the relay's
/// `ensure_schema()`, whose column types this repeats exactly so a fresh table
/// and an upgraded one are the same shape. `expires_at` is read by admission
/// (`expires_at IS NULL OR expires_at > now`) and was previously created by no
/// DDL in the repository.
pub const WHITELIST_CREATE_SQL: &str = "CREATE TABLE IF NOT EXISTS whitelist (\
    pubkey TEXT PRIMARY KEY, \
    cohorts TEXT NOT NULL DEFAULT '[\"members\"]', \
    added_at INTEGER NOT NULL, \
    added_by TEXT NOT NULL DEFAULT 'auto-registration', \
    is_admin INTEGER NOT NULL DEFAULT 0, \
    trust_level INTEGER NOT NULL DEFAULT 0, \
    days_active INTEGER NOT NULL DEFAULT 0, \
    posts_read INTEGER NOT NULL DEFAULT 0, \
    posts_created INTEGER NOT NULL DEFAULT 0, \
    mod_actions_against INTEGER NOT NULL DEFAULT 0, \
    last_active_at INTEGER, \
    trust_level_updated_at INTEGER, \
    suspended_until INTEGER, \
    silenced INTEGER NOT NULL DEFAULT 0, \
    user_notes TEXT, \
    expires_at INTEGER\
)";

/// Grant cohorts to a member, creating the row if it does not exist.
///
/// Binds: `?1` pubkey, `?2` the cohorts to grant as a JSON array of strings,
/// `?3` `added_at` (used only when the row is new), `?4` `added_by`.
///
/// On a new pubkey the row is inserted with exactly `?2`. On an existing one
/// the stored cohorts are kept in their order and every granted cohort not
/// already held is appended, so a grant never removes a cohort. `added_at` is
/// kept; `added_by` records the latest granter. If the stored value is not a
/// JSON array (no writer produces one, but D1 does not enforce it) it carries
/// no readable cohorts, and the grant becomes the row's value rather than the
/// statement failing.
pub const WHITELIST_GRANT_COHORTS_SQL: &str =
    "INSERT INTO whitelist (pubkey, cohorts, added_at, added_by) \
     VALUES (?1, ?2, ?3, ?4) \
     ON CONFLICT (pubkey) DO UPDATE SET \
       cohorts = CASE \
         WHEN json_valid(whitelist.cohorts) AND json_type(whitelist.cohorts) = 'array' THEN \
           (SELECT json_group_array(value) FROM ( \
              SELECT value FROM json_each(whitelist.cohorts) \
              UNION ALL \
              SELECT value FROM json_each(excluded.cohorts) \
               WHERE value NOT IN (SELECT value FROM json_each(whitelist.cohorts)))) \
         ELSE excluded.cohorts \
       END, \
       added_by = excluded.added_by";

/// Revoke named cohorts from a member.
///
/// Binds: `?1` pubkey, `?2` the cohorts to remove as a JSON array of strings.
///
/// Removes every occurrence of each named cohort and keeps the rest in order.
/// A cohort the member does not hold is ignored, and a pubkey with no row is
/// left without one: revoking never creates access. A row whose stored value
/// is not a JSON array is left untouched.
pub const WHITELIST_REVOKE_COHORTS_SQL: &str = "UPDATE whitelist SET cohorts = \
       (SELECT json_group_array(value) FROM json_each(whitelist.cohorts) \
         WHERE value NOT IN (SELECT value FROM json_each(?2))) \
     WHERE pubkey = ?1 \
       AND json_valid(cohorts) AND json_type(cohorts) = 'array'";

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    //! These run the statements against a real SQLite, the engine D1 is built
    //! on, rather than asserting on SQL text: the defect was in what the SQL
    //! does, not in how it reads.

    use super::*;
    use rusqlite::{params, Connection};

    const PK: &str = "aa00000000000000000000000000000000000000000000000000000000000001";

    fn db() -> Connection {
        let conn = Connection::open_in_memory().expect("open sqlite");
        conn.execute(WHITELIST_CREATE_SQL, [])
            .expect("create whitelist");
        conn
    }

    fn grant(conn: &Connection, pubkey: &str, cohorts: &[&str], at: i64, by: &str) {
        let json = serde_json::to_string(cohorts).unwrap();
        conn.execute(WHITELIST_GRANT_COHORTS_SQL, params![pubkey, json, at, by])
            .expect("grant");
    }

    fn revoke(conn: &Connection, pubkey: &str, cohorts: &[&str]) {
        let json = serde_json::to_string(cohorts).unwrap();
        conn.execute(WHITELIST_REVOKE_COHORTS_SQL, params![pubkey, json])
            .expect("revoke");
    }

    fn cohorts(conn: &Connection, pubkey: &str) -> Option<Vec<String>> {
        conn.query_row(
            "SELECT cohorts FROM whitelist WHERE pubkey = ?1",
            [pubkey],
            |r| r.get::<_, String>(0),
        )
        .ok()
        .map(|s| serde_json::from_str(&s).expect("cohorts is a JSON array"))
    }

    fn row_meta(conn: &Connection, pubkey: &str) -> (i64, String) {
        conn.query_row(
            "SELECT added_at, added_by FROM whitelist WHERE pubkey = ?1",
            [pubkey],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    }

    #[test]
    fn grant_creates_a_row_with_exactly_the_granted_cohorts() {
        let conn = db();
        grant(&conn, PK, &["home", "zone2"], 100, "admin");
        assert_eq!(cohorts(&conn, PK).unwrap(), ["home", "zone2"]);
        assert_eq!(row_meta(&conn, PK), (100, "admin".to_string()));
    }

    #[test]
    fn grant_never_removes_an_existing_cohort() {
        let conn = db();
        grant(&conn, PK, &["home", "zone2"], 100, "first");
        grant(&conn, PK, &["agent"], 200, "second");
        assert_eq!(cohorts(&conn, PK).unwrap(), ["home", "zone2", "agent"]);
    }

    #[test]
    fn grant_does_not_duplicate_a_held_cohort() {
        let conn = db();
        grant(&conn, PK, &["home", "zone2"], 100, "first");
        grant(&conn, PK, &["zone2", "home", "zone3"], 200, "second");
        assert_eq!(cohorts(&conn, PK).unwrap(), ["home", "zone2", "zone3"]);
    }

    #[test]
    fn empty_grant_leaves_cohorts_unchanged() {
        let conn = db();
        grant(&conn, PK, &["home"], 100, "first");
        grant(&conn, PK, &[], 200, "second");
        assert_eq!(cohorts(&conn, PK).unwrap(), ["home"]);
    }

    #[test]
    fn grant_keeps_added_at_and_records_the_latest_granter() {
        let conn = db();
        grant(&conn, PK, &["home"], 100, "first");
        grant(&conn, PK, &["zone2"], 200, "second");
        assert_eq!(row_meta(&conn, PK), (100, "second".to_string()));
    }

    #[test]
    fn grant_over_a_non_array_value_writes_the_grant() {
        let conn = db();
        conn.execute(
            "INSERT INTO whitelist (pubkey, cohorts, added_at) VALUES (?1, 'not json', 1)",
            [PK],
        )
        .unwrap();
        grant(&conn, PK, &["home"], 200, "admin");
        assert_eq!(cohorts(&conn, PK).unwrap(), ["home"]);
    }

    #[test]
    fn grant_leaves_other_columns_alone() {
        let conn = db();
        grant(&conn, PK, &["home"], 100, "first");
        conn.execute(
            "UPDATE whitelist SET is_admin = 1, trust_level = 2, silenced = 1, \
             suspended_until = 999, user_notes = 'n' WHERE pubkey = ?1",
            [PK],
        )
        .unwrap();
        grant(&conn, PK, &["zone2"], 200, "second");
        let row: (i64, i64, i64, i64, String) = conn
            .query_row(
                "SELECT is_admin, trust_level, silenced, suspended_until, user_notes \
                 FROM whitelist WHERE pubkey = ?1",
                [PK],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(row, (1, 2, 1, 999, "n".to_string()));
    }

    #[test]
    fn revoke_removes_only_the_named_cohorts() {
        let conn = db();
        grant(&conn, PK, &["home", "zone2", "agent"], 100, "admin");
        revoke(&conn, PK, &["zone2", "not-held"]);
        assert_eq!(cohorts(&conn, PK).unwrap(), ["home", "agent"]);
    }

    #[test]
    fn revoke_of_every_cohort_leaves_an_empty_array() {
        let conn = db();
        grant(&conn, PK, &["home"], 100, "admin");
        revoke(&conn, PK, &["home"]);
        assert_eq!(cohorts(&conn, PK).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn revoke_never_creates_a_row() {
        let conn = db();
        revoke(&conn, PK, &["home"]);
        assert_eq!(cohorts(&conn, PK), None);
    }

    #[test]
    fn revoke_leaves_a_non_array_value_untouched() {
        let conn = db();
        conn.execute(
            "INSERT INTO whitelist (pubkey, cohorts, added_at) VALUES (?1, 'not json', 1)",
            [PK],
        )
        .unwrap();
        revoke(&conn, PK, &["home"]);
        let raw: String = conn
            .query_row(
                "SELECT cohorts FROM whitelist WHERE pubkey = ?1",
                [PK],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(raw, "not json");
    }

    #[test]
    fn create_is_idempotent_and_defaults_match_the_legacy_table() {
        let conn = db();
        conn.execute(WHITELIST_CREATE_SQL, [])
            .expect("second create");
        conn.execute(
            "INSERT INTO whitelist (pubkey, added_at) VALUES (?1, 1)",
            [PK],
        )
        .unwrap();
        let row: (String, String, i64, i64, Option<i64>) = conn
            .query_row(
                "SELECT cohorts, added_by, is_admin, silenced, expires_at \
                 FROM whitelist WHERE pubkey = ?1",
                [PK],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(
            row,
            (
                r#"["members"]"#.to_string(),
                "auto-registration".to_string(),
                0,
                0,
                None
            )
        );
    }
}
