//! Registered gift-wrap recipient keys (Phase 2, ADR-2027 decision 2).
//!
//! A member can register a random *inbox key* with the auth-worker. Zone-key
//! grants and session-mirror wraps are then addressed to that key instead of the
//! member's identity pubkey, so a second NIP-17 client holding only the identity
//! key cannot open them. The registration is a private D1 row (`recipient_keys`),
//! never a public event.
//!
//! The relay consults the table only when the `RECIPIENT_KEYS_ENABLED` worker
//! var is exactly `"true"`; with it absent every path here is a no-op and the
//! relay behaves as before. This module holds the pure rules (admission route,
//! read set, wrap ownership), the SQL as constants, and the two D1 lookups.
//!
//! Only `role = 'inbox'` rows are honoured here. `epoch` rows are Phase 4.

use wasm_bindgen::JsValue;
use worker::D1Database;

/// Name of the worker var that switches the feature on.
pub(crate) const RECIPIENT_KEYS_ENABLED_VAR: &str = "RECIPIENT_KEYS_ENABLED";

/// Refusal for a recipient with no registration that is not whitelisted itself.
pub(crate) const REASON_NOT_REGISTERED: &str = "blocked: gift-wrap recipient not registered";
/// Refusal for a registered key that is revoked, or whose owner is not a member.
pub(crate) const REASON_INELIGIBLE: &str = "blocked: gift-wrap recipient key not eligible";
/// Refusal when the feature is off: the historical string, unchanged.
pub(crate) const REASON_NOT_WHITELISTED: &str = "blocked: gift-wrap recipient not whitelisted";

/// The `recipient_keys` table. Held identical to
/// `migrations/0011_recipient_keys.sql` by a test.
pub(crate) const RECIPIENT_KEYS_CREATE_SQL: &str = "CREATE TABLE IF NOT EXISTS recipient_keys (\
    key          TEXT PRIMARY KEY, \
    owner_pubkey TEXT NOT NULL, \
    zone         TEXT, \
    role         TEXT NOT NULL CHECK(role IN ('inbox','epoch')), \
    created_at   INTEGER NOT NULL, \
    revoked      INTEGER NOT NULL DEFAULT 0\
)";

/// Owner lookup index, created alongside the table.
pub(crate) const RECIPIENT_KEYS_INDEX_SQL: &str =
    "CREATE INDEX IF NOT EXISTS idx_recipient_keys_owner ON recipient_keys(owner_pubkey)";

/// Row for one inbox key, revoked or not. Deliberately no `revoked = 0`
/// filter: a revoked key must be recognisable as registered, or it would fall
/// through to the plain whitelist rule.
pub(crate) const LOOKUP_OWNER_SQL: &str = "SELECT owner_pubkey, revoked FROM recipient_keys \
    WHERE key = ?1 AND role = 'inbox' LIMIT 1";

/// Unrevoked inbox keys of one owner.
pub(crate) const KEYS_FOR_OWNER_SQL: &str = "SELECT key FROM recipient_keys \
    WHERE owner_pubkey = ?1 AND role = 'inbox' AND revoked = 0";

/// Whether the feature is on. Exact match on `"true"`, like the device-key gate.
pub(crate) fn recipient_keys_enabled_var(raw: Option<&str>) -> bool {
    raw == Some("true")
}

/// A registration as the relay sees it: `(owner_pubkey, revoked)`.
pub(crate) type KeyRow = (String, bool);

/// Next step of the gift-wrap recipient gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Route {
    /// Admit without further checks (declared ingress recipient).
    Accept,
    /// Admit iff this owner pubkey is whitelisted.
    OwnerMustBeMember(String),
    /// No registration: the recipient itself must be whitelisted.
    RecipientMustBeMember,
    /// Refuse now, with this reason.
    Refuse(&'static str),
}

/// First stage of the recipient gate, from what needs no whitelist read.
///
/// Order: ingress accepts; a registered key is judged by its owner (a revoked
/// one is refused outright); anything else must itself be whitelisted.
pub(crate) fn route(ingress: bool, row: Option<&KeyRow>) -> Route {
    if ingress {
        return Route::Accept;
    }
    match row {
        Some((_, true)) => Route::Refuse(REASON_INELIGIBLE),
        Some((owner, false)) => Route::OwnerMustBeMember(owner.clone()),
        None => Route::RecipientMustBeMember,
    }
}

/// Second stage: `member` is the whitelist verdict for whoever `route` named.
pub(crate) fn verdict(route: &Route, member: bool) -> Result<(), &'static str> {
    match route {
        Route::Accept => Ok(()),
        Route::Refuse(r) => Err(r),
        Route::OwnerMustBeMember(_) if member => Ok(()),
        Route::OwnerMustBeMember(_) => Err(REASON_INELIGIBLE),
        Route::RecipientMustBeMember if member => Ok(()),
        Route::RecipientMustBeMember => Err(REASON_NOT_REGISTERED),
    }
}

/// Set A: the authed pubkey plus its registered inbox keys, lowercase, unique.
pub(crate) fn read_set(authed: &str, extra: &[String]) -> Vec<String> {
    let mut out = vec![authed.to_ascii_lowercase()];
    for k in extra {
        let k = k.to_ascii_lowercase();
        if !out.contains(&k) {
            out.push(k);
        }
    }
    out
}

/// Whether `key` is in `set`, ignoring hex case.
pub(crate) fn set_contains(set: &[String], key: &str) -> bool {
    set.iter().any(|k| k.eq_ignore_ascii_case(key))
}

#[cfg(test)]
/// Narrow a requested `#p` list to set A; `None` (absent or not an array)
/// yields all of A. An empty result matches nothing downstream.
pub(crate) fn narrow_p(requested: Option<&serde_json::Value>, set: &[String]) -> Vec<String> {
    match requested.and_then(|v| v.as_array()) {
        Some(arr) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .filter(|p| set_contains(set, p))
            .map(str::to_ascii_lowercase)
            .collect(),
        None => set.to_vec(),
    }
}

/// First `p` tag value of a JSON-encoded tag array, as stored in `events.tags`.
pub(crate) fn first_p_of_tags(tags_json: &str) -> Option<String> {
    let tags: Vec<Vec<String>> = serde_json::from_str(tags_json).ok()?;
    tags.into_iter()
        .find(|t| t.len() >= 2 && t[0] == "p" && !t[1].is_empty())
        .map(|t| t[1].clone())
}

/// Whether a stored event is a kind-1059 wrap whose FIRST `p` is in `set`.
/// First `p` only, as everywhere else: a second `p` added by a sender must not
/// let another party delete the wrap.
pub(crate) fn wrap_addressed_to(kind: u64, tags_json: &str, set: &[String]) -> bool {
    kind == 1059 && first_p_of_tags(tags_json).is_some_and(|p| set_contains(set, &p))
}

/// Registration for `key` (revoked rows included). D1 failure reads as
/// unregistered, which falls back to the plain whitelist rule.
pub(crate) async fn lookup_owner(db: &D1Database, key: &str) -> Option<KeyRow> {
    #[derive(serde::Deserialize)]
    struct Row {
        owner_pubkey: String,
        revoked: f64,
    }
    let key = key.to_ascii_lowercase();
    let stmt = db
        .prepare(LOOKUP_OWNER_SQL)
        .bind(&[JsValue::from_str(&key)])
        .ok()?;
    match stmt.first::<Row>(None).await {
        Ok(Some(r)) => Some((r.owner_pubkey, r.revoked != 0.0)),
        _ => None,
    }
}

/// Unrevoked inbox keys registered by `owner`. D1 failure yields none.
pub(crate) async fn keys_for_owner(db: &D1Database, owner: &str) -> Vec<String> {
    #[derive(serde::Deserialize)]
    struct Row {
        key: String,
    }
    let owner = owner.to_ascii_lowercase();
    let Ok(stmt) = db
        .prepare(KEYS_FOR_OWNER_SQL)
        .bind(&[JsValue::from_str(&owner)])
    else {
        return Vec::new();
    };
    match stmt.all().await.and_then(|r| r.results::<Row>()) {
        Ok(rows) => rows
            .into_iter()
            .map(|r| r.key.to_ascii_lowercase())
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};

    const OWNER: &str = "0a";
    const INBOX: &str = "1b";

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute(RECIPIENT_KEYS_CREATE_SQL, []).unwrap();
        c.execute(RECIPIENT_KEYS_INDEX_SQL, []).unwrap();
        c
    }

    fn add(c: &Connection, key: &str, owner: &str, role: &str, revoked: i64) {
        c.execute(
            "INSERT INTO recipient_keys (key, owner_pubkey, zone, role, created_at, revoked) \
             VALUES (?1, ?2, NULL, ?3, 1, ?4)",
            params![key, owner, role, revoked],
        )
        .unwrap();
    }

    fn lookup(c: &Connection, key: &str) -> Option<KeyRow> {
        c.query_row(LOOKUP_OWNER_SQL, params![key], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0))
        })
        .ok()
    }

    fn keys(c: &Connection, owner: &str) -> Vec<String> {
        let mut s = c.prepare(KEYS_FOR_OWNER_SQL).unwrap();
        let rows = s
            .query_map(params![owner], |r| r.get::<_, String>(0))
            .unwrap();
        rows.map(Result::unwrap).collect()
    }

    /// The whole gate for one wrap, with whitelist verdicts supplied.
    fn admit(
        c: &Connection,
        ingress: bool,
        p: &str,
        owner_member: bool,
        p_member: bool,
    ) -> Result<(), &'static str> {
        let row = lookup(c, p);
        let r = route(ingress, row.as_ref());
        let member = match &r {
            Route::OwnerMustBeMember(_) => owner_member,
            _ => p_member,
        };
        verdict(&r, member)
    }

    #[test]
    fn flag_is_exact_true_only() {
        assert!(recipient_keys_enabled_var(Some("true")));
        for v in [
            None,
            Some(""),
            Some("false"),
            Some("TRUE"),
            Some(" true"),
            Some("1"),
        ] {
            assert!(!recipient_keys_enabled_var(v), "{v:?}");
        }
    }

    #[test]
    fn migration_matches_the_create_constants() {
        let sql = include_str!("../migrations/0011_recipient_keys.sql");
        let squash = |s: &str| s.split_whitespace().collect::<Vec<_>>().join("");
        assert!(squash(sql).contains(&squash(RECIPIENT_KEYS_CREATE_SQL)));
        assert!(squash(sql).contains(&squash(RECIPIENT_KEYS_INDEX_SQL)));
    }

    #[test]
    fn registered_inbox_key_of_a_member_is_accepted() {
        let c = db();
        add(&c, INBOX, OWNER, "inbox", 0);
        assert_eq!(admit(&c, false, INBOX, true, false), Ok(()));
    }

    #[test]
    fn revoked_key_is_refused_even_if_it_is_itself_whitelisted() {
        let c = db();
        add(&c, INBOX, OWNER, "inbox", 1);
        assert_eq!(admit(&c, false, INBOX, true, true), Err(REASON_INELIGIBLE));
    }

    #[test]
    fn key_whose_owner_is_not_a_member_is_refused() {
        let c = db();
        add(&c, INBOX, OWNER, "inbox", 0);
        assert_eq!(admit(&c, false, INBOX, false, true), Err(REASON_INELIGIBLE));
    }

    #[test]
    fn unregistered_non_member_gets_the_new_reason() {
        let c = db();
        assert_eq!(
            admit(&c, false, "ff", false, false),
            Err(REASON_NOT_REGISTERED)
        );
        assert_ne!(REASON_NOT_REGISTERED, REASON_NOT_WHITELISTED);
    }

    #[test]
    fn unregistered_member_and_ingress_are_accepted() {
        let c = db();
        assert_eq!(admit(&c, false, "ff", false, true), Ok(()));
        assert_eq!(admit(&c, true, "ff", false, false), Ok(()));
    }

    #[test]
    fn ingress_wins_over_a_revoked_row() {
        let c = db();
        add(&c, INBOX, OWNER, "inbox", 1);
        assert_eq!(admit(&c, true, INBOX, false, false), Ok(()));
    }

    #[test]
    fn epoch_rows_are_not_inbox_keys() {
        let c = db();
        add(&c, "ee", OWNER, "epoch", 0);
        assert_eq!(lookup(&c, "ee"), None);
        assert!(keys(&c, OWNER).is_empty());
    }

    #[test]
    fn keys_for_owner_lists_unrevoked_only() {
        let c = db();
        add(&c, "aa", OWNER, "inbox", 0);
        add(&c, "bb", OWNER, "inbox", 1);
        add(&c, "cc", "other", "inbox", 0);
        assert_eq!(keys(&c, OWNER), vec!["aa".to_string()]);
    }

    #[test]
    fn role_check_constraint_rejects_unknown_roles() {
        let c = db();
        assert!(c
            .execute(
                "INSERT INTO recipient_keys (key, owner_pubkey, role, created_at) VALUES ('x','y','admin',1)",
                [],
            )
            .is_err());
    }

    #[test]
    fn read_set_is_authed_plus_keys_lowercase_unique() {
        let a = read_set("AA", &["BB".into(), "bb".into(), "aa".into()]);
        assert_eq!(a, vec!["aa".to_string(), "bb".to_string()]);
    }

    #[test]
    fn narrow_p_intersects_or_defaults_to_the_set() {
        let a = read_set("aa", &["bb".into()]);
        let req = serde_json::json!(["BB", "zz"]);
        assert_eq!(narrow_p(Some(&req), &a), vec!["bb".to_string()]);
        assert_eq!(narrow_p(None, &a), a);
        let foreign = serde_json::json!(["zz"]);
        assert!(narrow_p(Some(&foreign), &a).is_empty());
    }

    #[test]
    fn wrap_ownership_uses_the_first_p_only() {
        let a = read_set("aa", &["bb".into()]);
        assert!(wrap_addressed_to(1059, r#"[["p","bb"]]"#, &a));
        assert!(!wrap_addressed_to(1059, r#"[["p","zz"],["p","bb"]]"#, &a));
        assert!(!wrap_addressed_to(1, r#"[["p","bb"]]"#, &a));
        assert!(!wrap_addressed_to(1059, "not json", &a));
        assert!(!wrap_addressed_to(1059, "[]", &a));
    }
}
