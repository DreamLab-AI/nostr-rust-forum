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
