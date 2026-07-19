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

/// Default per-pod quota: 50 MB.
const DEFAULT_QUOTA: u64 = 50 * 1024 * 1024;

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
pub async fn update_usage_d1(db: &D1Database, pubkey: &str, delta: i64) -> Result<()> {
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
            js_i64(DEFAULT_QUOTA as i64),
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
pub async fn check_and_reserve_d1(db: &D1Database, pubkey: &str, bytes: u64) -> Result<()> {
    let now = (js_sys::Date::now() / 1000.0) as i64;

    // First ensure the row exists (idempotent upsert with zero delta)
    db.prepare(
        "INSERT INTO quota_usage (pubkey, limit_bytes, used_bytes, updated_at) \
         VALUES (?1, ?2, 0, ?3) \
         ON CONFLICT(pubkey) DO NOTHING",
    )
    .bind(&[js_str(pubkey), js_i64(DEFAULT_QUOTA as i64), js_i64(now)])
    .map_err(|e| Error::RustError(format!("d1 bind quota init: {e:?}")))?
    .run()
    .await
    .map_err(|e| Error::RustError(format!("d1 run quota init: {e:?}")))?;

    // Atomic check-and-reserve: only updates if the new total fits
    let result = db
        .prepare(
            "UPDATE quota_usage \
             SET used_bytes = used_bytes + ?2, updated_at = ?3 \
             WHERE pubkey = ?1 AND (used_bytes + ?2) <= limit_bytes",
        )
        .bind(&[js_str(pubkey), js_i64(bytes as i64), js_i64(now)])
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
        let info = get_quota_d1(db, pubkey).await;
        return Err(Error::RustError(format!(
            "Storage quota exceeded: {}/{} bytes (need {} more)",
            info.used, info.limit, bytes
        )));
    }
    Ok(())
}

/// Read quota info from D1.
pub async fn get_quota_d1(db: &D1Database, pubkey: &str) -> QuotaInfo {
    let stmt = match db
        .prepare("SELECT limit_bytes, used_bytes FROM quota_usage WHERE pubkey = ?1")
        .bind(&[js_str(pubkey)])
    {
        Ok(s) => s,
        Err(_) => return QuotaInfo::default(),
    };
    match stmt.first::<serde_json::Value>(None).await {
        Ok(Some(row)) => {
            let limit = row
                .get("limit_bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(DEFAULT_QUOTA);
            let used = row.get("used_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
            QuotaInfo { limit, used }
        }
        _ => QuotaInfo::default(),
    }
}

/// Set the quota limit for a user in D1. Used by admin endpoints.
///
/// No admin HTTP route calls this yet in this crate — reserved for that
/// future endpoint (unlike `set_quota`/`check_quota` below, which are the
/// deprecated *legacy* KV path and have been removed as genuinely dead).
#[allow(dead_code)]
pub async fn set_quota_d1(db: &D1Database, pubkey: &str, limit: u64) -> Result<QuotaInfo> {
    let now = (js_sys::Date::now() / 1000.0) as i64;
    db.prepare(
        "INSERT INTO quota_usage (pubkey, limit_bytes, used_bytes, updated_at) \
         VALUES (?1, ?2, 0, ?3) \
         ON CONFLICT(pubkey) DO UPDATE SET limit_bytes = ?2, updated_at = ?3",
    )
    .bind(&[js_str(pubkey), js_i64(limit as i64), js_i64(now)])
    .map_err(|e| Error::RustError(format!("d1 bind set_quota: {e:?}")))?
    .run()
    .await
    .map_err(|e| Error::RustError(format!("d1 run set_quota: {e:?}")))?;

    Ok(get_quota_d1(db, pubkey).await)
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
}
