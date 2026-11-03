//! D1-backed NIP-98 replay protection.
//!
//! Replaces the non-atomic KV get+put pattern with `INSERT OR IGNORE` on a
//! `UNIQUE` event_id column, giving true atomic first-seen semantics.

use async_trait::async_trait;
use nostr_bbs_core::nip98::{Nip98Error, Nip98ReplayStore, Nip98Token};
use solid_pod_rs::auth::replay_store::{ReplayError, ReplayStore};
use wasm_bindgen::JsValue;
use worker::{D1Database, Env};

const SQL_RECORD_NONCE: &str =
    "INSERT OR IGNORE INTO nip98_replay (event_id, expires_at) VALUES (?1, ?2)";

/// D1-backed replay store using `INSERT OR IGNORE` for atomic first-seen check.
///
/// The `nip98_replay` table schema: `event_id TEXT PRIMARY KEY, expires_at INTEGER`.
/// `INSERT OR IGNORE` returns `rows_written == 0` when the key already exists.
pub struct D1ReplayStore<'a> {
    pub db: &'a D1Database,
    pub ttl_secs: u64,
}

impl D1ReplayStore<'_> {
    async fn record(&self, event_id: &str) -> Result<bool, String> {
        let expires_at = (js_sys::Date::now() / 1000.0) as i64 + self.ttl_secs as i64;

        let result = self
            .db
            .prepare(SQL_RECORD_NONCE)
            .bind(&[
                JsValue::from_str(event_id),
                JsValue::from_f64(expires_at as f64),
            ])
            .map_err(|e| format!("d1 bind: {e:?}"))?
            .run()
            .await
            .map_err(|e| format!("d1 run: {e:?}"))?;

        match result.meta() {
            Ok(Some(meta)) => first_seen_from_metadata(meta.changes, meta.rows_written),
            _ => Err("D1 replay metadata unavailable".into()),
        }
    }
}

fn first_seen_from_metadata(
    changes: Option<usize>,
    rows_written: Option<usize>,
) -> Result<bool, String> {
    changes
        .or(rows_written)
        .map(|n| n > 0)
        .ok_or_else(|| "D1 replay metadata omitted changed-row count".into())
}

#[cfg(test)]
#[test]
fn replay_metadata_never_treats_an_unknown_write_as_first_seen() {
    assert!(first_seen_from_metadata(Some(1), None).unwrap());
    assert!(!first_seen_from_metadata(Some(0), Some(1)).unwrap());
    assert!(first_seen_from_metadata(None, None).is_err());
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[test]
fn duplicate_nonce_is_refused_without_refreshing_its_expiry() {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute_batch(
        "CREATE TABLE nip98_replay(event_id TEXT PRIMARY KEY,expires_at INTEGER NOT NULL)",
    )
    .unwrap();
    let first = db
        .execute(SQL_RECORD_NONCE, rusqlite::params!["signed-id", 100])
        .unwrap();
    let replay = db
        .execute(SQL_RECORD_NONCE, rusqlite::params!["signed-id", 500])
        .unwrap();
    assert!(first_seen_from_metadata(Some(first), None).unwrap());
    assert!(!first_seen_from_metadata(Some(replay), None).unwrap());
    let expiry: i64 = db
        .query_row("SELECT expires_at FROM nip98_replay", [], |r| r.get(0))
        .unwrap();
    assert_eq!(expiry, 100, "replays cannot extend a nonce lifetime");
}

#[async_trait]
impl ReplayStore for D1ReplayStore<'_> {
    async fn check_and_record(&self, event_id: &str) -> Result<(), ReplayError> {
        // worker-rs owns the single-threaded Workers future bridge; no local unsafe marker.
        worker::send::SendFuture::new(async {
            match self.record(event_id).await {
                Ok(true) => Ok(()),
                Ok(false) => Err(ReplayError::Replayed {
                    ttl: std::time::Duration::from_secs(self.ttl_secs),
                }),
                Err(detail) => Err(ReplayError::Unavailable { detail }),
            }
        })
        .await
    }
}

#[async_trait(?Send)]
impl Nip98ReplayStore for D1ReplayStore<'_> {
    async fn seen_or_record(&self, event_id: &str) -> Result<bool, String> {
        match self.check_and_record(event_id).await {
            Ok(()) => Ok(true),
            Err(ReplayError::Replayed { .. }) => Ok(false),
            Err(error) => Err(error.to_string()),
        }
    }
}

/// Create the `nip98_replay` table if it doesn't exist.
///
/// Call once during worker startup (idempotent via `IF NOT EXISTS`).
/// Also prunes expired entries to keep the table bounded.
pub async fn ensure_replay_schema(env: &Env, db_binding: &str) {
    let db = match env.d1(db_binding) {
        Ok(db) => db,
        Err(_) => return,
    };
    let _ = db
        .prepare(
            "CREATE TABLE IF NOT EXISTS nip98_replay (\
                event_id TEXT PRIMARY KEY, \
                expires_at INTEGER NOT NULL\
            )",
        )
        .run()
        .await;
    let now = (js_sys::Date::now() / 1000.0) as i64;
    if let Ok(stmt) = db
        .prepare("DELETE FROM nip98_replay WHERE expires_at < ?1")
        .bind(&[JsValue::from_f64(now as f64)])
    {
        let _ = stmt.run().await;
    }
}

/// Verify a NIP-98 `Authorization` header with D1-backed atomic replay protection.
///
/// This is the single entry point all workers should use. It:
/// 1. Extracts the current timestamp from the JS runtime
/// 2. Looks up the D1 database binding
/// 3. Delegates to `nostr_bbs_core::verify_nip98_token_at_with_replay`
pub async fn verify_nip98(
    auth_header: &str,
    expected_url: &str,
    expected_method: &str,
    body: Option<&[u8]>,
    env: &Env,
    db_binding: &str,
) -> Result<Nip98Token, Nip98Error> {
    let now = (js_sys::Date::now() / 1000.0) as u64;
    let db = env
        .d1(db_binding)
        .map_err(|_| Nip98Error::ReplayBackend(format!("{db_binding} D1 binding missing")))?;
    let ttl = nostr_bbs_core::REPLAY_CACHE_TTL_SECS;
    let store = D1ReplayStore {
        db: &db,
        ttl_secs: ttl,
    };
    nostr_bbs_core::verify_nip98_token_at_with_replay(
        auth_header,
        expected_url,
        expected_method,
        body,
        now,
        &store,
    )
    .await
}

/// Compute the SHA-256 hex digest of a byte slice.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}
