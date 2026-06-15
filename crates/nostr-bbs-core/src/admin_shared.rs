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
//! ## Static admin bootstrap (`ADMIN_PUBKEYS`)
//!
//! In addition to the two D1 sources, a deploy-time **static** admin set may be
//! injected via the `ADMIN_PUBKEYS` env var (comma-separated hex pubkeys). This
//! mirrors `forum.toml [admin] static_pubkeys` and is the bootstrap/fallback
//! authority: a fresh deployment whose D1 `whitelist`/`members` tables carry no
//! `is_admin = 1` row still has working admins so the operator can seed D1.
//!
//! The canonical resolution order is **`ADMIN_PUBKEYS` (static) ∪ D1**. Every
//! worker parses the env var through [`admin_pubkeys_from_env_str`] so the
//! comma/whitespace/empty-filter semantics never drift between crates (workers
//! are separate WASM targets and cannot share a function at link time).
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
// Static admin set (`ADMIN_PUBKEYS` env var)
// ---------------------------------------------------------------------------

/// Env var carrying the deploy-time static admin set, comma-separated hex
/// pubkeys. Mirrors `forum.toml [admin] static_pubkeys` (injected at deploy
/// time, following the `POD_BASE_URL` mirroring convention).
pub const ADMIN_PUBKEYS_VAR: &str = "ADMIN_PUBKEYS";

/// Parse a raw `ADMIN_PUBKEYS` value into the static admin pubkey set.
///
/// Splits on `,`, trims each entry, and drops empties — so an unset/empty var
/// yields an empty `Vec` (no ambient admins), and trailing commas or stray
/// whitespace are tolerated. This is the single canonical parser; every worker
/// calls it so the comma/whitespace/empty semantics stay identical across the
/// separately-compiled WASM targets.
pub fn admin_pubkeys_from_env_str(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
        .collect()
}

/// Whether `pubkey` is present in the static `ADMIN_PUBKEYS` set parsed from
/// `raw`. Constant-shape membership test over [`admin_pubkeys_from_env_str`].
pub fn is_static_admin(pubkey: &str, raw: &str) -> bool {
    admin_pubkeys_from_env_str(raw).iter().any(|k| k == pubkey)
}

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

    #[test]
    fn static_admin_parse_empty_is_no_admins() {
        assert!(admin_pubkeys_from_env_str("").is_empty());
        assert!(admin_pubkeys_from_env_str("   ").is_empty());
        assert!(admin_pubkeys_from_env_str(",, ,").is_empty());
    }

    #[test]
    fn static_admin_parse_trims_and_filters() {
        let keys = admin_pubkeys_from_env_str(" aabb , ccdd ,,eeff ");
        assert_eq!(keys, vec!["aabb", "ccdd", "eeff"]);
    }

    #[test]
    fn static_admin_membership() {
        let raw = "6407eed8,5d80b5fa";
        assert!(is_static_admin("6407eed8", raw));
        assert!(is_static_admin("5d80b5fa", raw));
        assert!(!is_static_admin("deadbeef", raw));
        assert!(!is_static_admin("6407eed8", ""));
    }
}
