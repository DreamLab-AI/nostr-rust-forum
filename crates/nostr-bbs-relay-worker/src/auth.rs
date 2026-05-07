//! NIP-98 admin verification for the relay worker.
//!
//! Verifies the `Authorization: Nostr <base64(event)>` header using
//! `nostr_bbs_core::verify_nip98_token_at`, then checks whether the authenticated
//! pubkey holds admin privileges via the D1 `whitelist.is_admin` column.

use async_trait::async_trait;
use nostr_bbs_core::nip98::{Nip98Error, Nip98ReplayStore, Nip98Token};
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::{kv::KvStore, Env};

// ---------------------------------------------------------------------------
// NIP-98 verification
// ---------------------------------------------------------------------------

/// KV-backed NIP-98 replay store (TTL = 2 * tolerance window).
pub struct KvReplayStore<'a> {
    pub kv: &'a KvStore,
    pub ttl_secs: u64,
}

#[async_trait(?Send)]
impl<'a> Nip98ReplayStore for KvReplayStore<'a> {
    async fn seen_or_record(&self, event_id: &str) -> Result<bool, String> {
        let key = format!("nip98:{event_id}");
        match self.kv.get(&key).text().await {
            Ok(Some(_)) => return Ok(false),
            Ok(None) => {}
            Err(e) => return Err(format!("kv get failed: {e:?}")),
        }
        let put = self
            .kv
            .put(&key, "1")
            .map_err(|e| format!("kv put builder: {e:?}"))?;
        put.expiration_ttl(self.ttl_secs)
            .execute()
            .await
            .map_err(|e| format!("kv put exec: {e:?}"))?;
        Ok(true)
    }
}

struct AlwaysFreshStore;
#[async_trait(?Send)]
impl Nip98ReplayStore for AlwaysFreshStore {
    async fn seen_or_record(&self, _event_id: &str) -> Result<bool, String> {
        Ok(true)
    }
}

/// Verify a NIP-98 `Authorization` header WITH replay protection.
pub async fn verify_nip98_replay(
    auth_header: &str,
    expected_url: &str,
    expected_method: &str,
    body: Option<&[u8]>,
    env: &Env,
) -> Result<Nip98Token, Nip98Error> {
    let now = js_now_secs();
    let ttl = nostr_bbs_core::REPLAY_CACHE_TTL_SECS;
    if let Ok(kv) = env.kv("NIP98_REPLAY") {
        let store = KvReplayStore {
            kv: &kv,
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
    } else {
        worker::console_warn!(
            "NIP98_REPLAY KV binding missing; replay protection disabled (relay-worker)"
        );
        nostr_bbs_core::verify_nip98_token_at_with_replay(
            auth_header,
            expected_url,
            expected_method,
            body,
            now,
            &AlwaysFreshStore,
        )
        .await
    }
}

/// Synchronous, replay-FREE verification (legacy callers).
#[deprecated(
    since = "0.2.0",
    note = "Use verify_nip98_replay; this skips replay protection"
)]
pub fn verify_nip98(
    auth_header: &str,
    expected_url: &str,
    expected_method: &str,
    body: Option<&[u8]>,
) -> Result<Nip98Token, Nip98Error> {
    let now = js_now_secs();
    nostr_bbs_core::verify_nip98_token_at(auth_header, expected_url, expected_method, body, now)
}

/// Get the current Unix timestamp in seconds from the JS runtime.
pub fn js_now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

// ---------------------------------------------------------------------------
// Admin checks
// ---------------------------------------------------------------------------

/// D1 row type for admin status queries.
#[derive(Deserialize)]
struct IsAdminRow {
    is_admin: i32,
}

/// Check whether a pubkey is an admin by querying the D1 `whitelist` table.
pub async fn is_admin(pubkey: &str, env: &Env) -> bool {
    if let Ok(db) = env.d1("DB") {
        let stmt = db.prepare("SELECT is_admin FROM whitelist WHERE pubkey = ?1");
        if let Ok(bound) = stmt.bind(&[JsValue::from_str(pubkey)]) {
            if let Ok(Some(row)) = bound.first::<IsAdminRow>(None).await {
                return row.is_admin == 1;
            }
        }
    }
    false
}

/// Verify NIP-98 auth and assert the authenticated pubkey is an admin.
///
/// Returns `Ok(pubkey_hex)` on success, or an error tuple `(json_body, status_code)`
/// suitable for building an error response.
pub async fn require_nip98_admin(
    auth_header: Option<&str>,
    request_url: &str,
    method: &str,
    body: Option<&[u8]>,
    env: &Env,
) -> Result<String, (serde_json::Value, u16)> {
    let auth = auth_header.ok_or_else(|| {
        (
            serde_json::json!({ "error": "NIP-98 authentication required" }),
            401u16,
        )
    })?;

    let token = verify_nip98_replay(auth, request_url, method, body, env)
        .await
        .map_err(|_| {
            (
                serde_json::json!({ "error": "Invalid NIP-98 token" }),
                401u16,
            )
        })?;

    if !is_admin(&token.pubkey, env).await {
        return Err((serde_json::json!({ "error": "Not authorized" }), 403));
    }

    Ok(token.pubkey)
}
