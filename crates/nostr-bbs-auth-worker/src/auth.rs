//! NIP-98 verification wrapper for the auth worker.
//!
//! Delegates to `nostr_bbs_rate_limit::verify_nip98` for cryptographic
//! verification AND D1-backed atomic replay protection.

use nostr_bbs_core::nip98::{Nip98Error, Nip98Token};
use worker::Env;

/// D1 binding name for the replay store. All workers share the same database
/// so cross-worker replay is detected.
const REPLAY_DB: &str = "DB";

/// Verify the NIP-98 `Authorization` header from an incoming request,
/// enforcing D1-backed atomic replay protection.
pub async fn verify_nip98_replay(
    auth_header: &str,
    expected_url: &str,
    expected_method: &str,
    body: Option<&[u8]>,
    env: &Env,
) -> Result<Nip98Token, Nip98Error> {
    nostr_bbs_rate_limit::verify_nip98(
        auth_header,
        expected_url,
        expected_method,
        body,
        env,
        REPLAY_DB,
    )
    .await
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
    nostr_bbs_rate_limit::sha256_hex(data)
}

fn js_now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}
