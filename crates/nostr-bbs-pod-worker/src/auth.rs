//! NIP-98 verification wrapper for the pod worker.
//!
//! Delegates to `nostr_bbs_rate_limit::verify_nip98` for cryptographic
//! verification AND D1-backed atomic replay protection.

use nostr_bbs_core::nip98::{Nip98Error, Nip98Token};
use worker::Env;

/// D1 binding name for the replay store.
const REPLAY_DB: &str = "REPLAY_DB";

/// Verify the NIP-98 `Authorization` header with D1-backed atomic replay protection.
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
    let now = (js_sys::Date::now() / 1000.0) as u64;
    nostr_bbs_core::verify_nip98_token_at(auth_header, expected_url, expected_method, body, now)
}

#[allow(dead_code)]
pub fn sha256_hex(data: &[u8]) -> String {
    nostr_bbs_rate_limit::sha256_hex(data)
}
