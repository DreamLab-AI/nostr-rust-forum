//! Shared admin-check primitives consumed by all worker crates.
//!
//! Workers are separate `cdylib` WASM targets and cannot import functions from
//! each other. This module provides the **canonical** SQL query strings,
//! deserialization types, and documentation of the admin-check algorithm so
//! every worker implements the same logic without structural drift.
//!
//! ## Canonical admin-check algorithm
//!
//! A pubkey is considered an admin if **either** of these D1 queries returns
//! `is_admin = 1`:
//!
//! 1. `SELECT is_admin FROM whitelist WHERE pubkey = ?1` (RELAY_DB binding —
//!    the relay worker's whitelist, source of truth for admin flags written by
//!    the `/api/whitelist/*` management handlers).
//!
//! 2. `SELECT is_admin FROM members WHERE pubkey = ?1` (DB / REPLAY_DB binding
//!    — the auth worker's members table, populated by the invite-redemption
//!    flow).
//!
//! On DB error or missing rows, the check returns `false` — never leaking
//! ambient authority across error branches.
//!
//! ## Listing all admin pubkeys
//!
//! To list all admins (e.g. for the `/api/admins` endpoint or KV cache
//! population), query both tables:
//!
//! - `SELECT pubkey FROM whitelist WHERE is_admin = 1`
//! - `SELECT pubkey FROM members WHERE is_admin = 1`
//!
//! Deduplicate the union.

use serde::Deserialize;

/// Row type for single-pubkey admin checks.
///
/// Used with [`WHITELIST_IS_ADMIN_SQL`] and [`MEMBERS_IS_ADMIN_SQL`].
/// The `is_admin` column is `INTEGER` in D1 (SQLite); `1` = admin, `0` = not.
#[derive(Debug, Clone, Deserialize)]
pub struct IsAdminRow {
    pub is_admin: i32,
}

/// Row type for listing admin pubkeys.
///
/// Used with [`WHITELIST_ADMIN_LIST_SQL`] and [`MEMBERS_ADMIN_LIST_SQL`].
#[derive(Debug, Clone, Deserialize)]
pub struct PubkeyRow {
    pub pubkey: String,
}

// ---------------------------------------------------------------------------
// Canonical SQL query strings — use these in every worker.
// ---------------------------------------------------------------------------

/// Check if a pubkey is admin in the relay's whitelist table.
/// Bind parameter: `?1` = pubkey (hex string).
pub const WHITELIST_IS_ADMIN_SQL: &str = "SELECT is_admin FROM whitelist WHERE pubkey = ?1";

/// Check if a pubkey is admin in the auth/members table.
/// Bind parameter: `?1` = pubkey (hex string).
pub const MEMBERS_IS_ADMIN_SQL: &str = "SELECT is_admin FROM members WHERE pubkey = ?1";

/// List all admin pubkeys from the relay's whitelist table.
pub const WHITELIST_ADMIN_LIST_SQL: &str = "SELECT pubkey FROM whitelist WHERE is_admin = 1";

/// List all admin pubkeys from the auth/members table.
pub const MEMBERS_ADMIN_LIST_SQL: &str = "SELECT pubkey FROM members WHERE is_admin = 1";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_admin_row_deserialises() {
        let json = r#"{"is_admin": 1}"#;
        let row: IsAdminRow = serde_json::from_str(json).unwrap();
        assert_eq!(row.is_admin, 1);
    }

    #[test]
    fn is_admin_row_deserialises_zero() {
        let json = r#"{"is_admin": 0}"#;
        let row: IsAdminRow = serde_json::from_str(json).unwrap();
        assert_eq!(row.is_admin, 0);
    }

    #[test]
    fn pubkey_row_deserialises() {
        let json = r#"{"pubkey": "aabbccdd"}"#;
        let row: PubkeyRow = serde_json::from_str(json).unwrap();
        assert_eq!(row.pubkey, "aabbccdd");
    }

    #[test]
    fn sql_constants_are_stable() {
        assert!(WHITELIST_IS_ADMIN_SQL.contains("?1"));
        assert!(MEMBERS_IS_ADMIN_SQL.contains("?1"));
        assert!(WHITELIST_ADMIN_LIST_SQL.contains("is_admin = 1"));
        assert!(MEMBERS_ADMIN_LIST_SQL.contains("is_admin = 1"));
    }
}
