//! NIP-98 verification wrapper for the pod worker.
//!
//! Delegates to `nostr_bbs_core::verify_nip98_token_at` for cryptographic
//! verification and adds the worker-specific glue: extracting the
//! `Authorization` header, reading the request body for payload hash
//! verification, and obtaining the current timestamp via `Date.now()`.

use async_trait::async_trait;
use nostr_bbs_core::nip98::{Nip98Error, Nip98ReplayStore, Nip98Token};
use sha2::{Digest, Sha256};
use worker::{js_sys, kv::KvStore, Env};

/// KV-backed replay store. The KV value is irrelevant; presence of the key
/// signals "seen", and the TTL bounds entry lifetime.
pub struct KvReplayStore<'a> {
    pub kv: &'a KvStore,
    pub ttl_secs: u64,
}

#[async_trait(?Send)]
impl<'a> Nip98ReplayStore for KvReplayStore<'a> {
    async fn seen_or_record(&self, event_id: &str) -> Result<bool, String> {
        let key = format!("nip98:{event_id}");
        // SECURITY TODO: Cloudflare KV get+put is not atomic. Missing bindings
        // now fail closed, but concurrent replay races remain possible until
        // this store moves to a Durable Object or D1 UNIQUE insert.
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

/// Verify the NIP-98 `Authorization` header WITH replay protection.
///
/// Reads/writes the `NIP98_REPLAY` KV namespace (TTL = 2 * tolerance window).
/// If the binding is missing the function fails closed.
pub async fn verify_nip98_replay(
    auth_header: &str,
    expected_url: &str,
    expected_method: &str,
    body: Option<&[u8]>,
    env: &Env,
) -> Result<Nip98Token, Nip98Error> {
    let now = js_now_secs();
    let ttl = nostr_bbs_core::REPLAY_CACHE_TTL_SECS;
    let kv = env
        .kv("NIP98_REPLAY")
        .map_err(|_| Nip98Error::ReplayBackend("NIP98_REPLAY KV binding missing".into()))?;
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
}

/// Synchronous, replay-FREE verification. Use [`verify_nip98_replay`] for
/// new callers — this is kept only for legacy paths without `Env` access.
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

/// Compute the SHA-256 hex digest of a byte slice.
///
/// Used externally when the caller needs to pre-compute a payload hash.
#[allow(dead_code)]
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Get the current Unix timestamp in seconds from the JS runtime.
///
/// Workers do not have access to `std::time::SystemTime`, so we call
/// `Date.now()` via `js_sys` and convert milliseconds to seconds.
fn js_now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}
