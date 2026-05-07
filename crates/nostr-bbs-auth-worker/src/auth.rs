//! NIP-98 verification wrapper for the auth worker.
//!
//! Delegates to `nostr_bbs_core::verify_nip98_token_at_with_replay` for
//! cryptographic verification AND replay protection, and adds the
//! worker-specific glue: extracting the `Authorization` header, reading the
//! request body for payload hash verification, and obtaining the current
//! timestamp via `Date.now()`.
//!
//! The replay store is backed by the `NIP98_REPLAY` KV namespace with TTL =
//! [`nostr_bbs_core::REPLAY_CACHE_TTL_SECS`] (= 2x tolerance window). Workers
//! that lack the KV binding (e.g. local dev without the binding wired) fall
//! back to a permissive in-memory store; production deployments MUST bind
//! `NIP98_REPLAY` to enforce replay protection.

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
        // Probe first.
        match self.kv.get(&key).text().await {
            Ok(Some(_)) => return Ok(false),
            Ok(None) => {} // first observation
            Err(e) => return Err(format!("kv get failed: {e:?}")),
        }
        // Record with TTL.
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

/// Permissive fallback when KV is unavailable. NEVER use this in production.
struct AlwaysFreshStore;
#[async_trait(?Send)]
impl Nip98ReplayStore for AlwaysFreshStore {
    async fn seen_or_record(&self, _event_id: &str) -> Result<bool, String> {
        Ok(true)
    }
}

/// Verify the NIP-98 `Authorization` header from an incoming request,
/// enforcing replay protection via the `NIP98_REPLAY` KV namespace.
///
/// # Arguments
/// * `auth_header` - The raw `Authorization` header value
/// * `expected_url` - The canonical URL the token should authorize
/// * `expected_method` - The HTTP method the token should authorize
/// * `body` - Optional request body bytes for payload hash verification
/// * `env`  - Worker environment (for KV binding lookup)
pub async fn verify_nip98_replay(
    auth_header: &str,
    expected_url: &str,
    expected_method: &str,
    body: Option<&[u8]>,
    env: &Env,
) -> Result<Nip98Token, Nip98Error> {
    let now = js_now_secs();
    let kv = env.kv("NIP98_REPLAY").ok();
    let ttl = nostr_bbs_core::REPLAY_CACHE_TTL_SECS;
    if let Some(kv) = kv {
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
        // No binding -> log + fall back. Replay protection is best-effort
        // until ops finishes wrangler.toml provisioning.
        worker::console_warn!(
            "NIP98_REPLAY KV binding missing; replay protection disabled (auth-worker)"
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

/// Synchronous, replay-FREE verification kept for legacy call sites that do
/// not have access to `Env` (e.g. test helpers). Workers should prefer
/// [`verify_nip98_replay`].
#[deprecated(
    since = "0.2.0",
    note = "Use verify_nip98_replay for replay protection. \
            This API is kept only for legacy call sites without Env access."
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
