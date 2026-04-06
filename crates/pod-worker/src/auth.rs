//! NIP-98 verification wrapper for the pod worker.
//!
//! Delegates to `nostr_core::verify_nip98_token_at` for cryptographic
//! verification and adds the worker-specific glue: extracting the
//! `Authorization` header, reading the request body for payload hash
//! verification, and obtaining the current timestamp via `Date.now()`.

use nostr_core::nip98::{Nip98Error, Nip98Token};
use sha2::{Digest, Sha256};
use worker::js_sys;

/// Verify the NIP-98 `Authorization` header from an incoming request.
///
/// Returns `Ok(Some(token))` on success, `Ok(None)` if no `Authorization`
/// header is present, or `Err` if verification fails.
///
/// # Arguments
/// * `auth_header` - The raw `Authorization` header value
/// * `expected_url` - The canonical URL the token should authorize
/// * `expected_method` - The HTTP method the token should authorize
/// * `body` - Optional request body bytes for payload hash verification
pub fn verify_nip98(
    auth_header: &str,
    expected_url: &str,
    expected_method: &str,
    body: Option<&[u8]>,
) -> Result<Nip98Token, Nip98Error> {
    let now = js_now_secs();
    nostr_core::verify_nip98_token_at(auth_header, expected_url, expected_method, body, now)
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
