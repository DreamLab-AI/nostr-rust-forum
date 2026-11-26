//! Per-user storage quota management.
//!
//! Two backends:
//! - KV (legacy, non-atomic): `get_quota`, `update_usage`, `check_quota`
//! - D1 (atomic): `update_usage_d1`, `check_and_reserve_d1`
//!
//! The D1 path uses single SQL statements with arithmetic in the WHERE clause,
//! eliminating the read-modify-write race window that allows concurrent writers
//! to bypass quota.
//!
//! Quota state is persisted in the `quota_usage` table (created by
//! `payments::ensure_payment_schema`).

use nostr_bbs_core::d1_helpers::{js_i64, js_str};
use worker::*;

/// Built-in per-pod quota when `POD_QUOTA_MB` is unset or invalid: 50 MiB.
const DEFAULT_QUOTA: u64 = 50 * 1024 * 1024;

/// Upper bound accepted for `POD_QUOTA_MB` and for an admin-set limit: 1 TiB.
pub const MAX_QUOTA: u64 = 1024 * 1024 * 1024 * 1024;

/// The per-pod default from `POD_QUOTA_MB` (whole MiB, 1..=1 TiB), else
/// [`DEFAULT_QUOTA`]. Applies to every pod without an admin-set limit.
pub fn default_quota_from(var: Option<&str>) -> u64 {
    var.and_then(|v| v.trim().parse::<u64>().ok())
        .and_then(|mb| mb.checked_mul(1024 * 1024))
        .filter(|b| *b > 0 && *b <= MAX_QUOTA)
        .unwrap_or(DEFAULT_QUOTA)
}

/// [`default_quota_from`] over the worker env.
pub fn default_quota(env: &Env) -> u64 {
    default_quota_from(
        env.var("POD_QUOTA_MB")
            .ok()
            .map(|v| v.to_string())
            .as_deref(),
    )
}

/// The limit a row enforces: its own `limit_bytes` when an admin set it
/// (`limit_explicit = 1`), else the larger of its stored limit and the
/// current default. Mirrors the SQL in [`RESERVE_SQL`].
pub fn effective_limit(limit_bytes: u64, limit_explicit: bool, default: u64) -> u64 {
    if limit_explicit {
        limit_bytes
    } else {
        limit_bytes.max(default)
    }
}

/// Atomic reserve: adds `?2` bytes only if the total stays within the
/// effective limit ([`effective_limit`]; `?4` = current default for this
/// account). Binds: pubkey, bytes, now, default.
pub(crate) const RESERVE_SQL: &str = "UPDATE quota_usage \
     SET used_bytes = used_bytes + ?2, updated_at = ?3 \
     WHERE pubkey = ?1 AND (used_bytes + ?2) <= \
       CASE WHEN limit_explicit = 1 THEN limit_bytes \
            ELSE MAX(limit_bytes, ?4) END";

/// Total capacity reserved for authenticated third-party appends to one pod's
/// inbox. It is deliberately separate from the owner's general storage quota,
/// so inbox spam cannot block the owner's own writes.
pub const INBOX_QUOTA: u64 = 5 * 1024 * 1024;

/// Select the quota account and limit for a write.
/// The inbox account is always capped at [`INBOX_QUOTA`]; the owner's
/// account at `owner_default` (the configured default, [`default_quota`]).
pub fn reservation_account(
    owner_pubkey: &str,
    _requester_pubkey: Option<&str>,
    resource_path: &str,
    owner_default: u64,
) -> (String, u64) {
    if resource_path.starts_with("/inbox/") {
        (format!("inbox:{owner_pubkey}"), INBOX_QUOTA)
    } else {
        (owner_pubkey.to_string(), owner_default)
    }
}

/// Quota information for a pod.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct QuotaInfo {
    pub limit: u64,
    pub used: u64,
}

impl Default for QuotaInfo {
    fn default() -> Self {
        Self {
            limit: DEFAULT_QUOTA,
            used: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// D1 atomic quota operations
// ---------------------------------------------------------------------------

/// Atomically update quota usage in D1.
///
/// Uses a single UPDATE with arithmetic in SQL, or INSERT for new rows.
/// Positive delta = write (add bytes), negative delta = delete (subtract bytes).
/// Usage is clamped to zero on negative overflow.
pub async fn update_usage_d1(
    db: &D1Database,
    pubkey: &str,
    delta: i64,
    default: u64,
) -> Result<()> {
    let now = (js_sys::Date::now() / 1000.0) as i64;

    if delta >= 0 {
        // Upsert: create row with usage = delta, or add delta to existing
        db.prepare(
            "INSERT INTO quota_usage (pubkey, limit_bytes, used_bytes, updated_at) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(pubkey) DO UPDATE SET \
               used_bytes = used_bytes + ?3, \
               updated_at = ?4",
        )
        .bind(&[
            js_str(pubkey),
            js_i64(default as i64),
            js_i64(delta),
            js_i64(now),
        ])
        .map_err(|e| Error::RustError(format!("d1 bind usage+: {e:?}")))?
        .run()
        .await
        .map_err(|e| Error::RustError(format!("d1 run usage+: {e:?}")))?;
    } else {
        // Subtract: clamp to zero using MAX(0, used_bytes + delta)
        let abs_delta = delta.unsigned_abs() as i64;
        db.prepare(
            "UPDATE quota_usage \
             SET used_bytes = MAX(0, used_bytes - ?2), updated_at = ?3 \
             WHERE pubkey = ?1",
        )
        .bind(&[js_str(pubkey), js_i64(abs_delta), js_i64(now)])
        .map_err(|e| Error::RustError(format!("d1 bind usage-: {e:?}")))?
        .run()
        .await
        .map_err(|e| Error::RustError(format!("d1 run usage-: {e:?}")))?;
    }
    Ok(())
}

/// Atomically check and reserve quota in a single D1 statement.
///
/// Attempts to add `bytes` to `used_bytes` only if the result would not
/// exceed `limit_bytes`. Returns `Ok(())` if the reservation succeeded,
/// or `Err` if the quota would be exceeded.
///
/// The WHERE clause `(used_bytes + ?2) <= limit_bytes` makes this atomic —
/// concurrent writers cannot all pass the check before any records usage.
pub async fn check_and_reserve_d1(
    db: &D1Database,
    pubkey: &str,
    bytes: u64,
    default: u64,
) -> Result<()> {
    check_and_reserve_with_limit_d1(db, pubkey, bytes, default).await
}

/// Atomically reserve bytes against an explicitly bounded quota account.
pub async fn check_and_reserve_with_limit_d1(
    db: &D1Database,
    pubkey: &str,
    bytes: u64,
    limit: u64,
) -> Result<()> {
    let now = (js_sys::Date::now() / 1000.0) as i64;

    // First ensure the row exists (idempotent upsert with zero delta)
    db.prepare(
        "INSERT INTO quota_usage (pubkey, limit_bytes, used_bytes, updated_at) \
         VALUES (?1, ?2, 0, ?3) \
         ON CONFLICT(pubkey) DO NOTHING",
    )
    .bind(&[js_str(pubkey), js_i64(limit as i64), js_i64(now)])
    .map_err(|e| Error::RustError(format!("d1 bind quota init: {e:?}")))?
    .run()
    .await
    .map_err(|e| Error::RustError(format!("d1 run quota init: {e:?}")))?;

    // Atomic check-and-reserve: only updates if the new total fits the
    // effective limit (an admin-set limit, else max(stored, current default)).
    let result = db
        .prepare(RESERVE_SQL)
        .bind(&[
            js_str(pubkey),
            js_i64(bytes as i64),
            js_i64(now),
            js_i64(limit as i64),
        ])
        .map_err(|e| Error::RustError(format!("d1 bind reserve: {e:?}")))?
        .run()
        .await
        .map_err(|e| Error::RustError(format!("d1 run reserve: {e:?}")))?;

    let rows_written = result
        .meta()
        .ok()
        .flatten()
        .and_then(|m| m.rows_written)
        .unwrap_or(0);

    if rows_written == 0 {
        // Read actual values for the error message
        let info = get_quota_d1(db, pubkey, limit).await;
        return Err(Error::RustError(format!(
            "Storage quota exceeded: {}/{} bytes (need {} more)",
            info.used, info.limit, bytes
        )));
    }
    Ok(())
}

/// Read quota info from D1.
/// Read quota info from D1, reporting the EFFECTIVE limit (see
/// [`effective_limit`]) given the account's current `default`.
pub async fn get_quota_d1(db: &D1Database, pubkey: &str, default: u64) -> QuotaInfo {
    let fallback = QuotaInfo {
        limit: default,
        used: 0,
    };
    let stmt = match db
        .prepare(
            "SELECT limit_bytes, used_bytes, limit_explicit FROM quota_usage WHERE pubkey = ?1",
        )
        .bind(&[js_str(pubkey)])
    {
        Ok(s) => s,
        Err(_) => return fallback,
    };
    match stmt.first::<serde_json::Value>(None).await {
        Ok(Some(row)) => {
            let stored = row
                .get("limit_bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(default);
            let explicit = row.get("limit_explicit").and_then(|v| v.as_u64()) == Some(1);
            let used = row.get("used_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
            QuotaInfo {
                limit: effective_limit(stored, explicit, default),
                used,
            }
        }
        _ => fallback,
    }
}

/// How a failed quota reservation should be answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveFailure {
    /// The write would exceed the limit: 413.
    OverQuota,
    /// D1 was busy or locked (`SQLITE_BUSY`, "database is locked"): a
    /// transient condition under load, answered 503 + Retry-After so the
    /// client retries instead of reporting a quota error.
    Busy,
    /// Any other D1 failure (binding, statement): 503, also retryable.
    Unavailable,
}

/// Classify a [`check_and_reserve_with_limit_d1`] error by its message: only
/// the explicit over-limit refusal is a quota error.
pub fn classify_reserve_error(message: &str) -> ReserveFailure {
    let m = message.to_ascii_lowercase();
    if m.contains("quota exceeded") {
        ReserveFailure::OverQuota
    } else if m.contains("sqlite_busy")
        || m.contains("database is locked")
        || m.contains("sqlite_locked")
    {
        ReserveFailure::Busy
    } else {
        ReserveFailure::Unavailable
    }
}

/// Set (`Some`) or clear (`None`: follow the default again) an admin limit
/// for one pod's owner account (`POST /.quota`, admin NIP-98). An explicit
/// limit may be below the default (to restrict a pod) or above it.
pub async fn set_quota_d1(
    db: &D1Database,
    pubkey: &str,
    limit: Option<u64>,
    default: u64,
) -> Result<QuotaInfo> {
    let now = (js_sys::Date::now() / 1000.0) as i64;
    let (bytes, explicit) = match limit {
        Some(b) => (b, 1),
        None => (default, 0),
    };
    db.prepare(
        "INSERT INTO quota_usage (pubkey, limit_bytes, used_bytes, updated_at, limit_explicit) \
         VALUES (?1, ?2, 0, ?3, ?4) \
         ON CONFLICT(pubkey) DO UPDATE SET limit_bytes = ?2, updated_at = ?3, limit_explicit = ?4",
    )
    .bind(&[
        js_str(pubkey),
        js_i64(bytes as i64),
        js_i64(now),
        js_i64(explicit),
    ])
    .map_err(|e| Error::RustError(format!("d1 bind set_quota: {e:?}")))?
    .run()
    .await
    .map_err(|e| Error::RustError(format!("d1 run set_quota: {e:?}")))?;

    Ok(get_quota_d1(db, pubkey, default).await)
}

// ---------------------------------------------------------------------------
// KV-backed quota operations (DEPRECATED — non-atomic)
// ---------------------------------------------------------------------------

/// Get quota info from KV.
#[deprecated(note = "Use get_quota_d1 for atomic quota operations")]
pub async fn get_quota(kv: &kv::KvStore, pubkey: &str) -> Result<QuotaInfo> {
    let key = format!("quota:{pubkey}");
    match kv.get(&key).text().await? {
        Some(json) => {
            serde_json::from_str(&json).map_err(|e| Error::RustError(format!("quota parse: {e}")))
        }
        None => Ok(QuotaInfo::default()),
    }
}

/// Update quota usage after a write (positive delta) or delete (negative delta).
#[deprecated(note = "Use update_usage_d1 for atomic quota operations")]
pub async fn update_usage(kv: &kv::KvStore, pubkey: &str, delta: i64) -> Result<()> {
    // SECURITY: This KV read-modify-write counter is non-atomic. Use
    // update_usage_d1 for authoritative quota tracking under concurrent writes.
    #[allow(deprecated)]
    let mut info = get_quota(kv, pubkey).await?;
    if delta > 0 {
        info.used = info.used.saturating_add(delta as u64);
    } else {
        info.used = info.used.saturating_sub((-delta) as u64);
    }
    let key = format!("quota:{pubkey}");
    let json = serde_json::to_string(&info)
        .map_err(|e| Error::RustError(format!("quota serialize: {e}")))?;
    kv.put(&key, &json)?.execute().await?;
    Ok(())
}

// `set_quota` and `check_quota` (deprecated, KV-backed legacy path) were
// removed here: both were already marked `#[deprecated]` in favour of the
// atomic D1 path, had zero callers anywhere in the crate (production or
// test), and are genuinely dead on every build target — see
// `set_quota_d1`/`check_and_reserve_d1` for the current atomic equivalents.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_quota_is_50mb() {
        let q = QuotaInfo::default();
        assert_eq!(q.limit, 50 * 1024 * 1024);
        assert_eq!(q.used, 0);
    }

    #[test]
    fn quota_serialization_round_trip() {
        let q = QuotaInfo {
            limit: 100,
            used: 42,
        };
        let json = serde_json::to_string(&q).unwrap();
        let q2: QuotaInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(q2.limit, 100);
        assert_eq!(q2.used, 42);
    }

    #[test]
    fn third_party_inbox_writes_use_an_isolated_bounded_account() {
        let owner = "aa";
        let big = 2048 * 1024 * 1024;
        assert_eq!(
            reservation_account(owner, Some("bb"), "/inbox/", big),
            ("inbox:aa".to_string(), INBOX_QUOTA),
            "the inbox stays capped whatever the owner default"
        );
        assert_eq!(
            reservation_account(owner, Some(owner), "/inbox/", big),
            ("inbox:aa".to_string(), INBOX_QUOTA)
        );
        assert_eq!(
            reservation_account(owner, Some("bb"), "/private/note", big),
            (owner.to_string(), big)
        );
    }

    #[test]
    fn only_a_real_overflow_is_a_quota_error() {
        assert_eq!(
            classify_reserve_error("Quota exceeded: 2147483648 of 2147483648 bytes used, need 10"),
            ReserveFailure::OverQuota
        );
        assert_eq!(
            classify_reserve_error(
                "d1 run quota init: JsValue(Error: D1_ERROR: database is locked: SQLITE_BUSY)"
            ),
            ReserveFailure::Busy
        );
        assert_eq!(
            classify_reserve_error("d1 bind reserve: SQLITE_LOCKED"),
            ReserveFailure::Busy
        );
        assert_eq!(
            classify_reserve_error("d1 run reserve: network"),
            ReserveFailure::Unavailable
        );
    }

    #[test]
    fn the_default_comes_from_pod_quota_mb() {
        assert_eq!(default_quota_from(None), DEFAULT_QUOTA);
        assert_eq!(default_quota_from(Some("2048")), 2048 * 1024 * 1024);
        assert_eq!(default_quota_from(Some(" 100 ")), 100 * 1024 * 1024);
        for bad in ["0", "-5", "abc", "", "99999999999999"] {
            assert_eq!(default_quota_from(Some(bad)), DEFAULT_QUOTA, "{bad:?}");
        }
    }

    #[test]
    fn rows_follow_the_current_default_unless_an_admin_set_them() {
        let def = 2048;
        assert_eq!(
            effective_limit(50, false, def),
            2048,
            "old default row is raised"
        );
        assert_eq!(effective_limit(4096, false, def), 4096, "never lowered");
        assert_eq!(
            effective_limit(10, true, def),
            10,
            "explicit restriction holds"
        );
        assert_eq!(
            effective_limit(9000, true, def),
            9000,
            "explicit raise holds"
        );
    }

    #[test]
    fn the_reserve_sql_enforces_the_effective_limit() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        for ddl in crate::pay_ledger::SCHEMA {
            let _ = c.execute(ddl, []);
        }
        // An old row created at the 50 MiB default, an admin-restricted row.
        c.execute_batch(
            "INSERT INTO quota_usage (pubkey, limit_bytes, used_bytes, updated_at) VALUES ('old', 50, 40, 0);
             INSERT INTO quota_usage (pubkey, limit_bytes, used_bytes, updated_at, limit_explicit) VALUES ('capped', 50, 40, 0, 1);",
        )
        .unwrap();
        let reserve = |pk: &str, bytes: i64, default: i64| {
            c.execute(RESERVE_SQL, rusqlite::params![pk, bytes, 1, default])
                .unwrap()
        };
        assert_eq!(
            reserve("old", 20, 50),
            0,
            "at the old default 60 > 50 refuses"
        );
        assert_eq!(reserve("old", 20, 2048), 1, "the raised default admits it");
        assert_eq!(
            reserve("capped", 20, 2048),
            0,
            "an explicit limit ignores the default"
        );
    }
}
