//! D1-backed NIP-98 replay protection.
//!
//! Replaces the non-atomic KV get+put pattern with `INSERT OR IGNORE` on a
//! `UNIQUE` event_id column, giving true atomic first-seen semantics.

use async_trait::async_trait;
use nostr_bbs_core::nip98::{Nip98Error, Nip98ReplayStore, Nip98Token};
use wasm_bindgen::JsValue;
use worker::{D1Database, Env};

/// D1-backed replay store using `INSERT OR IGNORE` for atomic first-seen check.
///
/// The `nip98_replay` table schema: `event_id TEXT PRIMARY KEY, expires_at INTEGER`.
/// `INSERT OR IGNORE` returns `rows_written == 0` when the key already exists.
pub struct D1ReplayStore<'a> {
    pub db: &'a D1Database,
    pub ttl_secs: u64,
}

#[async_trait(?Send)]
impl<'a> Nip98ReplayStore for D1ReplayStore<'a> {
    async fn seen_or_record(&self, event_id: &str) -> Result<bool, String> {
        let expires_at = (js_sys::Date::now() / 1000.0) as i64 + self.ttl_secs as i64;

        let result = self
            .db
            .prepare("INSERT OR IGNORE INTO nip98_replay (event_id, expires_at) VALUES (?1, ?2)")
            .bind(&[
                JsValue::from_str(event_id),
                JsValue::from_f64(expires_at as f64),
            ])
            .map_err(|e| format!("d1 bind: {e:?}"))?
            .run()
            .await
            .map_err(|e| format!("d1 run: {e:?}"))?;

        match result.meta() {
            Ok(Some(meta)) => Ok(meta.rows_written.unwrap_or(0) > 0),
            _ => Ok(true),
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
