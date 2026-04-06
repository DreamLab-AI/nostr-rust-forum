//! Per-user storage quota management.
//!
//! Quota state is persisted in KV under the key `quota:{pubkey}` as a
//! JSON-serialized `QuotaInfo`.  Every write updates usage; every delete
//! decrements it.

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

/// Get quota info from KV.
pub async fn get_quota(kv: &kv::KvStore, pubkey: &str) -> Result<QuotaInfo> {
    let key = format!("quota:{pubkey}");
    match kv.get(&key).text().await? {
        Some(json) => serde_json::from_str(&json)
            .map_err(|e| Error::RustError(format!("quota parse: {e}"))),
        None => Ok(QuotaInfo::default()),
    }
}

/// Update quota usage after a write (positive delta) or delete (negative delta).
pub async fn update_usage(kv: &kv::KvStore, pubkey: &str, delta: i64) -> Result<()> {
    let mut info = get_quota(kv, pubkey).await?;
    if delta > 0 {
        info.used = info.used.saturating_add(delta as u64);
    } else {
        info.used = info.used.saturating_sub((-delta) as u64);
    }
    let key = format!("quota:{pubkey}");
    let json =
        serde_json::to_string(&info).map_err(|e| Error::RustError(format!("quota serialize: {e}")))?;
    kv.put(&key, &json)?.execute().await?;
    Ok(())
}

/// Set the quota limit for a user.  Used by admin endpoints.
pub async fn set_quota(kv: &kv::KvStore, pubkey: &str, limit: u64) -> Result<QuotaInfo> {
    let mut info = get_quota(kv, pubkey).await?;
    info.limit = limit;
    let key = format!("quota:{pubkey}");
    let json =
        serde_json::to_string(&info).map_err(|e| Error::RustError(format!("quota serialize: {e}")))?;
    kv.put(&key, &json)?.execute().await?;
    Ok(info)
}

/// Check if a write of `additional_bytes` would exceed the user's quota.
///
/// Returns `Ok(())` if the write is permitted, or `Err` with a descriptive
/// message if the quota would be exceeded.
pub async fn check_quota(kv: &kv::KvStore, pubkey: &str, additional_bytes: u64) -> Result<()> {
    let info = get_quota(kv, pubkey).await?;
    if info.used + additional_bytes > info.limit {
        Err(Error::RustError(format!(
            "Storage quota exceeded: {}/{} bytes (need {} more)",
            info.used, info.limit, additional_bytes
        )))
    } else {
        Ok(())
    }
}

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
