//! NIP-98: HTTP Auth via Nostr events (kind 27235).
//!
//! **Canonical Rust implementation for the DreamLab ecosystem.**
//!
//! This module is the single source of truth for NIP-98 verification across
//! nostr-rust-forum, solid-pod-rs, VisionClaw, and any future Rust consumers.
//! All verification paths converge here; downstream crates should depend on
//! `nostr_bbs_core::nip98` rather than rolling their own.
//!
//! Wire format: `Authorization: Nostr base64(json(signed_event))`
//!
//! ## Verification checks (in order)
//!
//! 1. Strip `Nostr ` prefix from the Authorization header
//! 2. Size-gate the encoded token (max 64 KiB)
//! 3. Base64-decode and JSON-parse into a [`NostrEvent`]
//! 4. Assert `kind == 27235`
//! 5. Validate pubkey format (64 hex chars)
//! 6. Check timestamp freshness within `max_age_secs` (default 60s)
//! 7. Recompute event ID from canonical NIP-01 serialisation and verify
//!    the BIP-340 Schnorr signature (never trusts the client-provided id)
//! 8. Match the `u` tag against the expected URL
//! 9. Match the `method` tag against the expected HTTP method (case-insensitive)
//! 10. If a request body is provided, verify the `payload` tag contains its SHA-256
//!
//! ## Replay protection
//!
//! The [`Nip98ReplayStore`] trait abstracts the storage backend for replay
//! detection. The `nostr-bbs-rate-limit` crate provides a D1-backed
//! implementation; tests use an in-memory map. Replay checking is performed
//! **after** all cryptographic checks pass so that the store is never
//! polluted by forged or expired events.
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use nostr_bbs_core::nip98::{verify_nip98, Nip98Token, Nip98Error};
//!
//! // Stateless verification (no replay protection)
//! let token: Nip98Token = verify_nip98(
//!     auth_header,    // "Nostr base64..."
//!     expected_url,   // "https://api.example.com/endpoint"
//!     expected_method,// "POST"
//!     None,           // max_age_secs — defaults to 60
//! )?;
//! println!("Authenticated pubkey: {}", token.pubkey);
//! ```
//!
//! [`Nip98Token`] carries the validated `event_id` (recomputed by
//! `verify_event_strict`, never trusted from the client), enabling
//! callers to key replay caches on the canonical ID.

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use k256::schnorr::SigningKey;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::event::{sign_event, verify_event, NostrEvent, UnsignedEvent};

/// NIP-98 event kind.
const HTTP_AUTH_KIND: u64 = 27235;

/// Maximum allowed clock skew in seconds.
pub const TIMESTAMP_TOLERANCE: u64 = 60;

/// Recommended replay-cache TTL: 2x the timestamp tolerance window.
///
/// Stores accepting older event IDs only need to outlive the tolerance, so
/// `2 * TIMESTAMP_TOLERANCE` is a safe upper bound for replay-cache entries.
pub const REPLAY_CACHE_TTL_SECS: u64 = 2 * TIMESTAMP_TOLERANCE;

/// Maximum encoded event size in bytes (64 KiB, matching TS implementation).
const MAX_EVENT_SIZE: usize = 64 * 1024;

/// Authorization header prefix.
const NOSTR_PREFIX: &str = "Nostr ";

/// Replay-cache abstraction for NIP-98 event IDs.
///
/// Implementations record-and-check whether a NIP-98 event id has been seen
/// within the tolerance window. Workers wire this to KV with TTL =
/// [`REPLAY_CACHE_TTL_SECS`]; tests use an in-memory map.
///
/// Semantics: [`Nip98ReplayStore::seen_or_record`] MUST be atomic from the
/// caller's point of view — it returns `Ok(true)` on first observation and
/// records the id, returning `Ok(false)` on subsequent observations within
/// the TTL. A storage error is surfaced as `Err`.
#[async_trait(?Send)]
pub trait Nip98ReplayStore {
    /// Record `event_id` if absent and return `true` on first observation.
    /// Return `false` if `event_id` was already recorded within the TTL.
    async fn seen_or_record(&self, event_id: &str) -> Result<bool, String>;
}

/// A verified NIP-98 token with extracted fields.
///
/// Returned by all `verify_*` functions ([`verify_nip98`], [`verify_token`],
/// [`verify_token_at`], [`verify_token_full`], [`verify_token_at_with_replay`],
/// [`verify_nip98_with_replay`]) after successful verification of an
/// `Authorization: Nostr <base64(event)>` header.
///
/// The `event_id` field contains the **canonical** event ID recomputed from
/// the NIP-01 serialisation — it is never taken from the client-provided
/// payload. This makes it safe to use as a replay-cache key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Nip98Token {
    /// Canonical event ID (validated via `verify_event_strict` before population).
    pub event_id: String,
    /// Hex-encoded x-only public key of the signer.
    pub pubkey: String,
    /// The URL this token authorizes.
    pub url: String,
    /// The HTTP method this token authorizes.
    pub method: String,
    /// SHA-256 hex hash of the request body, if present.
    pub payload_hash: Option<String>,
    /// Unix timestamp when the token was created.
    pub created_at: u64,
}

/// Errors that can occur during NIP-98 token creation or verification.
#[derive(Debug, Error)]
pub enum Nip98Error {
    #[error("invalid secret key: {0}")]
    InvalidKey(#[from] k256::schnorr::Error),

    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("missing 'Nostr ' prefix in Authorization header")]
    MissingPrefix,

    #[error("event exceeds maximum size ({MAX_EVENT_SIZE} bytes)")]
    EventTooLarge,

    #[error("wrong event kind: expected {HTTP_AUTH_KIND}, got {0}")]
    WrongKind(u64),

    #[error("invalid pubkey: expected 64 hex chars")]
    InvalidPubkey,

    #[error(
        "timestamp expired: event created_at {event_ts} is more than {tolerance}s from now ({now})"
    )]
    TimestampExpired {
        event_ts: u64,
        now: u64,
        tolerance: u64,
    },

    #[error("missing required tag: {0}")]
    MissingTag(String),

    #[error("URL mismatch: token={token_url}, expected={expected_url}")]
    UrlMismatch {
        token_url: String,
        expected_url: String,
    },

    #[error("method mismatch: token={token_method}, expected={expected_method}")]
    MethodMismatch {
        token_method: String,
        expected_method: String,
    },

    #[error("payload hash mismatch")]
    PayloadMismatch,

    #[error("body present but no payload tag in signed event")]
    MissingPayloadTag,

    #[error("event signature verification failed")]
    InvalidSignature,

    #[error("replay detected: event id has already been seen within the tolerance window")]
    Replayed,

    #[error("replay store backend error: {0}")]
    ReplayBackend(String),
}

/// Create a NIP-98 authorization token for an HTTP request.
///
/// Returns a base64-encoded JSON string suitable for the `Authorization: Nostr <token>` header.
///
/// # Arguments
/// * `secret_key` - 32-byte secp256k1 secret key
/// * `url` - The full request URL
/// * `method` - HTTP method (GET, POST, etc.)
/// * `body` - Optional request body (will be SHA-256 hashed for the payload tag)
pub fn create_token(
    secret_key: &[u8; 32],
    url: &str,
    method: &str,
    body: Option<&[u8]>,
) -> Result<String, Nip98Error> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs();
    create_token_at(secret_key, url, method, body, now)
}

/// Like [`create_token`] but accepts an explicit Unix timestamp.
///
/// Use this variant in WASM environments where `SystemTime::now()` is unavailable.
/// The caller is responsible for providing a current timestamp (e.g., from `Date.now() / 1000`).
pub fn create_token_at(
    secret_key: &[u8; 32],
    url: &str,
    method: &str,
    body: Option<&[u8]>,
    created_at: u64,
) -> Result<String, Nip98Error> {
    let sk = SigningKey::from_bytes(secret_key)?;
    let pubkey = hex::encode(sk.verifying_key().to_bytes());

    let mut tags = vec![
        vec!["u".to_string(), url.to_string()],
        vec!["method".to_string(), method.to_string()],
    ];

    if let Some(body_bytes) = body {
        let hash = Sha256::digest(body_bytes);
        tags.push(vec!["payload".to_string(), hex::encode(hash)]);
    }

    let unsigned = UnsignedEvent {
        pubkey,
        created_at,
        kind: HTTP_AUTH_KIND,
        tags,
        content: String::new(),
    };

    // Safety: pubkey is derived from sk above, so sign_event cannot fail with PubkeyMismatch
    let signed = sign_event(unsigned, &sk)
        .expect("pubkey derived from same signing key — mismatch impossible");
    let json = serde_json::to_string(&signed)?;
    Ok(BASE64.encode(json.as_bytes()))
}

// ── Canonical verification API ─────────────────────────────────────────────
//
// The public API is layered for ergonomics and backward compatibility:
//
//   verify_nip98()                — canonical entry point (system clock, configurable tolerance)
//   verify_token()               — legacy alias using default tolerance + system clock
//   verify_token_at()            — explicit timestamp, default tolerance
//   verify_token_full()          — full control: explicit timestamp + custom tolerance
//   verify_token_at_with_replay()— full control + async replay protection
//
// All paths converge on `verify_token_full`.

/// **Canonical NIP-98 verification entry point.**
///
/// Verifies the `Authorization: Nostr <base64(event)>` header against the
/// expected URL and HTTP method. Uses the system clock for timestamp checking.
///
/// This is the recommended function for all new code across the DreamLab
/// ecosystem. It performs every check specified by NIP-98:
///
/// - Kind == 27235
/// - URL tag matches `expected_url`
/// - Method tag matches `expected_method` (case-insensitive)
/// - Timestamp within `max_age_secs` of the current time
/// - BIP-340 Schnorr signature over the canonical NIP-01 event hash
/// - Optional payload SHA-256 verification (when a request body is present)
///
/// # Arguments
///
/// * `auth_header` - The full `Authorization` header value (e.g. `"Nostr base64..."`)
/// * `expected_url` - The URL that should appear in the `u` tag
/// * `expected_method` - The HTTP method that should appear in the `method` tag
/// * `max_age_secs` - Maximum allowed clock skew in seconds. Pass `None` to use
///   the default [`TIMESTAMP_TOLERANCE`] (60 seconds).
///
/// # Returns
///
/// A [`Nip98Token`] containing the verified pubkey, URL, method, payload hash,
/// and canonical event ID (safe to use as a replay-cache key).
///
/// # Errors
///
/// Returns [`Nip98Error`] on any verification failure. The error variants are
/// specific enough for callers to distinguish authentication failures (401)
/// from authorisation failures (403) and replay attacks.
///
/// # Example
///
/// ```rust,ignore
/// use nostr_bbs_core::nip98::{verify_nip98, Nip98Token};
///
/// let token = verify_nip98(
///     "Nostr eyJpZC...",
///     "https://api.example.com/v1/data",
///     "POST",
///     None, // use default 60s tolerance
/// )?;
/// println!("Authenticated: {}", token.pubkey);
/// ```
pub fn verify_nip98(
    auth_header: &str,
    expected_url: &str,
    expected_method: &str,
    max_age_secs: Option<u64>,
) -> Result<Nip98Token, Nip98Error> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs();
    let tolerance = max_age_secs.unwrap_or(TIMESTAMP_TOLERANCE);
    verify_token_full(
        auth_header,
        expected_url,
        expected_method,
        None,
        now,
        tolerance,
    )
}

/// Verify a NIP-98 `Authorization` header value using the system clock
/// and the default [`TIMESTAMP_TOLERANCE`].
///
/// Delegates to [`verify_token_full`] with `tolerance = TIMESTAMP_TOLERANCE`.
/// For new code, prefer [`verify_nip98`] which exposes the tolerance parameter.
///
/// # Arguments
/// * `auth_header` - The full `Authorization` header value (e.g. `"Nostr base64..."`)
/// * `expected_url` - The URL that should appear in the `u` tag
/// * `expected_method` - The HTTP method that should appear in the `method` tag
/// * `body` - Optional request body bytes to verify against the `payload` tag
pub fn verify_token(
    auth_header: &str,
    expected_url: &str,
    expected_method: &str,
    body: Option<&[u8]>,
) -> Result<Nip98Token, Nip98Error> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs();
    verify_token_full(
        auth_header,
        expected_url,
        expected_method,
        body,
        now,
        TIMESTAMP_TOLERANCE,
    )
}

/// Verify a NIP-98 `Authorization` header value against an explicit timestamp
/// using the default [`TIMESTAMP_TOLERANCE`].
///
/// Use this variant in tests or worker environments where you want
/// deterministic timestamp validation instead of relying on `SystemTime::now()`.
///
/// # Arguments
/// * `auth_header` - The full `Authorization` header value (e.g. `"Nostr base64..."`)
/// * `expected_url` - The URL that should appear in the `u` tag
/// * `expected_method` - The HTTP method that should appear in the `method` tag
/// * `body` - Optional request body bytes to verify against the `payload` tag
/// * `now` - The current Unix timestamp (seconds) used for tolerance checking
pub fn verify_token_at(
    auth_header: &str,
    expected_url: &str,
    expected_method: &str,
    body: Option<&[u8]>,
    now: u64,
) -> Result<Nip98Token, Nip98Error> {
    verify_token_full(
        auth_header,
        expected_url,
        expected_method,
        body,
        now,
        TIMESTAMP_TOLERANCE,
    )
}

/// Full-control NIP-98 verification with explicit timestamp and tolerance.
///
/// This is the core verification function that all other `verify_*` functions
/// delegate to. It performs every check listed in the module-level documentation.
///
/// # Arguments
/// * `auth_header` - The full `Authorization` header value (e.g. `"Nostr base64..."`)
/// * `expected_url` - The URL that should appear in the `u` tag
/// * `expected_method` - The HTTP method that should appear in the `method` tag
/// * `body` - Optional request body bytes to verify against the `payload` tag
/// * `now` - The current Unix timestamp (seconds) used for tolerance checking
/// * `max_age_secs` - Maximum allowed absolute difference between `now` and the
///   event's `created_at` timestamp. Use [`TIMESTAMP_TOLERANCE`] for the default.
pub fn verify_token_full(
    auth_header: &str,
    expected_url: &str,
    expected_method: &str,
    body: Option<&[u8]>,
    now: u64,
    max_age_secs: u64,
) -> Result<Nip98Token, Nip98Error> {
    // 1. Strip "Nostr " prefix
    let token = auth_header
        .strip_prefix(NOSTR_PREFIX)
        .ok_or(Nip98Error::MissingPrefix)?
        .trim();

    // 2. Size check on encoded token
    if token.len() > MAX_EVENT_SIZE {
        return Err(Nip98Error::EventTooLarge);
    }

    // 3. Base64 decode and parse JSON
    let json_bytes = BASE64.decode(token)?;
    if json_bytes.len() > MAX_EVENT_SIZE {
        return Err(Nip98Error::EventTooLarge);
    }
    let event: NostrEvent = serde_json::from_slice(&json_bytes)?;

    // 4. Check kind
    if event.kind != HTTP_AUTH_KIND {
        return Err(Nip98Error::WrongKind(event.kind));
    }

    // 5. Check pubkey format
    if event.pubkey.len() != 64 || hex::decode(&event.pubkey).is_err() {
        return Err(Nip98Error::InvalidPubkey);
    }

    // 6. Timestamp within tolerance
    if now.abs_diff(event.created_at) > max_age_secs {
        return Err(Nip98Error::TimestampExpired {
            event_ts: event.created_at,
            now,
            tolerance: max_age_secs,
        });
    }

    // 7. Verify event integrity (recomputes ID from scratch + Schnorr sig check)
    if !verify_event(&event) {
        return Err(Nip98Error::InvalidSignature);
    }

    // 8. Extract and verify URL tag
    let token_url = get_tag(&event, "u").ok_or_else(|| Nip98Error::MissingTag("u".into()))?;
    if token_url != expected_url {
        return Err(Nip98Error::UrlMismatch {
            token_url: token_url.clone(),
            expected_url: expected_url.to_string(),
        });
    }

    // 9. Extract and verify method tag
    let token_method =
        get_tag(&event, "method").ok_or_else(|| Nip98Error::MissingTag("method".into()))?;
    if token_method.to_uppercase() != expected_method.to_uppercase() {
        return Err(Nip98Error::MethodMismatch {
            token_method,
            expected_method: expected_method.to_string(),
        });
    }

    // 10. Payload hash verification
    let payload_tag = get_tag(&event, "payload");

    let verified_payload_hash = if let Some(body_bytes) = body {
        if !body_bytes.is_empty() {
            // Body present — payload tag MUST exist
            let expected_hash = payload_tag.as_ref().ok_or(Nip98Error::MissingPayloadTag)?;
            let actual_hash = hex::encode(Sha256::digest(body_bytes));
            if expected_hash.to_lowercase() != actual_hash.to_lowercase() {
                return Err(Nip98Error::PayloadMismatch);
            }
            Some(expected_hash.clone())
        } else {
            payload_tag
        }
    } else {
        payload_tag
    };

    Ok(Nip98Token {
        event_id: event.id,
        pubkey: event.pubkey,
        url: token_url,
        method: token_method,
        payload_hash: verified_payload_hash,
        created_at: event.created_at,
    })
}

/// Verify a NIP-98 token AND enforce replay protection via [`Nip98ReplayStore`].
///
/// This is the recommended verification path for all worker endpoints. The
/// store is consulted only AFTER the cryptographic checks pass — replay
/// recording is a side effect of a structurally-valid event, never of a
/// forged or expired one. If the event id has already been seen within the
/// store's TTL, returns [`Nip98Error::Replayed`].
///
/// Uses the default [`TIMESTAMP_TOLERANCE`]. For custom tolerance, use
/// [`verify_nip98_with_replay`].
///
/// # Arguments
/// As [`verify_token_at`], plus `replay_store` — a store keyed by the
/// 32-byte hex event id with a TTL of at least [`REPLAY_CACHE_TTL_SECS`].
pub async fn verify_token_at_with_replay(
    auth_header: &str,
    expected_url: &str,
    expected_method: &str,
    body: Option<&[u8]>,
    now: u64,
    replay_store: &dyn Nip98ReplayStore,
) -> Result<Nip98Token, Nip98Error> {
    verify_nip98_with_replay(
        auth_header,
        expected_url,
        expected_method,
        body,
        now,
        TIMESTAMP_TOLERANCE,
        replay_store,
    )
    .await
}

/// Full-control NIP-98 verification with replay protection.
///
/// Combines [`verify_token_full`] with async replay detection. The replay
/// store is only consulted after all stateless cryptographic checks pass,
/// so the store is never polluted by forged or expired events.
///
/// # Arguments
///
/// * `auth_header` - Full `Authorization` header value
/// * `expected_url` - URL that should appear in the `u` tag
/// * `expected_method` - HTTP method that should appear in the `method` tag
/// * `body` - Optional request body for payload hash verification
/// * `now` - Current Unix timestamp (seconds)
/// * `max_age_secs` - Maximum allowed timestamp skew
/// * `replay_store` - Backend for atomic replay detection (D1, KV, in-memory, etc.)
pub async fn verify_nip98_with_replay(
    auth_header: &str,
    expected_url: &str,
    expected_method: &str,
    body: Option<&[u8]>,
    now: u64,
    max_age_secs: u64,
    replay_store: &dyn Nip98ReplayStore,
) -> Result<Nip98Token, Nip98Error> {
    // Run all stateless cryptographic + structural checks first.
    // verify_token_full recomputes and validates the event ID, so
    // token.event_id is the canonical ID — not client-supplied.
    let token = verify_token_full(
        auth_header,
        expected_url,
        expected_method,
        body,
        now,
        max_age_secs,
    )?;

    let first_seen = replay_store
        .seen_or_record(&token.event_id)
        .await
        .map_err(Nip98Error::ReplayBackend)?;
    if !first_seen {
        return Err(Nip98Error::Replayed);
    }

    Ok(token)
}

/// Helper: extract the first value for a tag name from an event's tags.
fn get_tag(event: &NostrEvent, name: &str) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.first().map(|s| s.as_str()) == Some(name))
        .and_then(|t| t.get(1).cloned())
}

/// Build a full `Authorization` header value from a token string.
pub fn authorization_header(token: &str) -> String {
    format!("{NOSTR_PREFIX}{token}")
}

/// Build a ready-to-send `Authorization: Nostr <base64>` header value for
/// an outbound HTTP request.
///
/// Convenience wrapper for CLI/worker clients that need the full header
/// value in one call. Reuses [`create_token`] internally — the signing
/// logic lives in a single place.
///
/// # Arguments
/// * `secret_key` - 32-byte secp256k1 secret key
/// * `url` - The full request URL
/// * `method` - HTTP method (GET, POST, etc.)
/// * `body` - Optional request body (hashed into the payload tag if present)
pub fn sign_request_header(
    secret_key: &[u8; 32],
    url: &str,
    method: &str,
    body: Option<&[u8]>,
) -> Result<String, Nip98Error> {
    let token = create_token(secret_key, url, method, body)?;
    Ok(authorization_header(&token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::SigningKey;

    fn test_secret_key() -> [u8; 32] {
        // Deterministic key for tests
        let mut key = [0u8; 32];
        key[0] = 0x01;
        key[31] = 0x01;
        key
    }

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&test_secret_key()).unwrap()
    }

    // ── Roundtrip ──────────────────────────────────────────────────────

    #[test]
    fn nip98_create_verify_roundtrip_no_body() {
        let sk = test_secret_key();
        let url = "https://api.example.com/upload";
        let method = "GET";

        let token = create_token(&sk, url, method, None).unwrap();
        let header = authorization_header(&token);
        let result = verify_token(&header, url, method, None).unwrap();

        let expected_pubkey = hex::encode(test_signing_key().verifying_key().to_bytes());
        assert_eq!(result.pubkey, expected_pubkey);
        assert_eq!(result.url, url);
        assert_eq!(result.method, method);
        assert!(result.payload_hash.is_none());
    }

    #[test]
    fn nip98_create_verify_roundtrip_with_body() {
        let sk = test_secret_key();
        let url = "https://api.example.com/data";
        let method = "POST";
        let body = b"hello world";

        let token = create_token(&sk, url, method, Some(body)).unwrap();
        let header = authorization_header(&token);
        let result = verify_token(&header, url, method, Some(body)).unwrap();

        assert_eq!(result.method, method);
        assert!(result.payload_hash.is_some());

        // Verify the payload hash matches SHA-256 of body
        let expected_hash = hex::encode(Sha256::digest(body));
        assert_eq!(result.payload_hash.unwrap(), expected_hash);
    }

    // ── Rejection tests ────────────────────────────────────────────────

    #[test]
    fn nip98_reject_wrong_url() {
        let sk = test_secret_key();
        let token = create_token(&sk, "https://good.com/api", "GET", None).unwrap();
        let header = authorization_header(&token);

        let err = verify_token(&header, "https://evil.com/api", "GET", None).unwrap_err();
        assert!(matches!(err, Nip98Error::UrlMismatch { .. }));
    }

    #[test]
    fn nip98_reject_wrong_method() {
        let sk = test_secret_key();
        let token = create_token(&sk, "https://api.example.com/x", "GET", None).unwrap();
        let header = authorization_header(&token);

        let err = verify_token(&header, "https://api.example.com/x", "POST", None).unwrap_err();
        assert!(matches!(err, Nip98Error::MethodMismatch { .. }));
    }

    #[test]
    fn nip98_reject_missing_prefix() {
        let err = verify_token("Bearer abc123", "https://x.com", "GET", None).unwrap_err();
        assert!(matches!(err, Nip98Error::MissingPrefix));
    }

    #[test]
    fn nip98_reject_invalid_base64() {
        let err = verify_token("Nostr !!!not-base64!!!", "https://x.com", "GET", None).unwrap_err();
        // Could be base64 decode error or JSON parse error
        assert!(
            matches!(err, Nip98Error::Base64(_)) || matches!(err, Nip98Error::Json(_)),
            "expected Base64 or Json error, got: {err}"
        );
    }

    #[test]
    fn nip98_reject_tampered_signature() {
        let sk = test_secret_key();
        let url = "https://api.example.com/test";
        let token_b64 = create_token(&sk, url, "GET", None).unwrap();

        // Decode, tamper with sig, re-encode
        let json_bytes = BASE64.decode(&token_b64).unwrap();
        let mut event: NostrEvent = serde_json::from_slice(&json_bytes).unwrap();
        // Flip a byte in the signature
        let mut sig_bytes = hex::decode(&event.sig).unwrap();
        sig_bytes[0] ^= 0xFF;
        event.sig = hex::encode(&sig_bytes);

        let tampered_json = serde_json::to_string(&event).unwrap();
        let tampered_b64 = BASE64.encode(tampered_json.as_bytes());
        let header = authorization_header(&tampered_b64);

        let err = verify_token(&header, url, "GET", None).unwrap_err();
        assert!(matches!(err, Nip98Error::InvalidSignature));
    }

    #[test]
    fn nip98_reject_payload_mismatch() {
        let sk = test_secret_key();
        let url = "https://api.example.com/upload";
        let original_body = b"original content";
        let tampered_body = b"tampered content";

        let token = create_token(&sk, url, "POST", Some(original_body)).unwrap();
        let header = authorization_header(&token);

        let err = verify_token(&header, url, "POST", Some(tampered_body)).unwrap_err();
        assert!(matches!(err, Nip98Error::PayloadMismatch));
    }

    #[test]
    fn nip98_reject_body_without_payload_tag() {
        let sk = test_secret_key();
        let url = "https://api.example.com/upload";

        // Create token WITHOUT body (no payload tag)
        let token = create_token(&sk, url, "POST", None).unwrap();
        let header = authorization_header(&token);

        // Verify WITH body — should reject because payload tag is missing
        let err = verify_token(&header, url, "POST", Some(b"sneaky body")).unwrap_err();
        assert!(matches!(err, Nip98Error::MissingPayloadTag));
    }

    #[test]
    fn nip98_reject_expired_timestamp() {
        let signing_key = test_signing_key();
        let pubkey = hex::encode(signing_key.verifying_key().to_bytes());
        let url = "https://api.example.com/old";

        // Manually create an event with an old timestamp
        let old_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 120; // 2 minutes ago, beyond 60s tolerance

        let unsigned = UnsignedEvent {
            pubkey,
            created_at: old_time,
            kind: HTTP_AUTH_KIND,
            tags: vec![
                vec!["u".to_string(), url.to_string()],
                vec!["method".to_string(), "GET".to_string()],
            ],
            content: String::new(),
        };

        let signed = sign_event(unsigned, &signing_key).expect("pubkey derived from same key");
        let json = serde_json::to_string(&signed).unwrap();
        let b64 = BASE64.encode(json.as_bytes());
        let header = authorization_header(&b64);

        let err = verify_token(&header, url, "GET", None).unwrap_err();
        assert!(matches!(err, Nip98Error::TimestampExpired { .. }));
    }

    // ── verify_token_at tests ─────────────────────────────────────────

    #[test]
    fn nip98_verify_token_at_accepts_matching_timestamp() {
        let sk = test_secret_key();
        let url = "https://api.example.com/at";
        let created_at = 1_700_000_000u64;

        let token = create_token_at(&sk, url, "GET", None, created_at).unwrap();
        let header = authorization_header(&token);

        // Verify at the same timestamp
        let result = verify_token_at(&header, url, "GET", None, created_at).unwrap();
        assert_eq!(result.created_at, created_at);
    }

    #[test]
    fn nip98_verify_token_at_accepts_within_tolerance() {
        let sk = test_secret_key();
        let url = "https://api.example.com/at";
        let created_at = 1_700_000_000u64;

        let token = create_token_at(&sk, url, "POST", Some(b"body"), created_at).unwrap();
        let header = authorization_header(&token);

        // 30 seconds later -- within the 60s tolerance
        let result = verify_token_at(&header, url, "POST", Some(b"body"), created_at + 30).unwrap();
        assert_eq!(result.created_at, created_at);
    }

    #[test]
    fn nip98_verify_token_at_rejects_beyond_tolerance() {
        let sk = test_secret_key();
        let url = "https://api.example.com/at";
        let created_at = 1_700_000_000u64;

        let token = create_token_at(&sk, url, "GET", None, created_at).unwrap();
        let header = authorization_header(&token);

        // 120 seconds later -- beyond the 60s tolerance
        let err = verify_token_at(&header, url, "GET", None, created_at + 120).unwrap_err();
        assert!(matches!(err, Nip98Error::TimestampExpired { .. }));
    }

    #[test]
    fn nip98_verify_token_at_rejects_future_beyond_tolerance() {
        let sk = test_secret_key();
        let url = "https://api.example.com/at";
        let created_at = 1_700_000_100u64;

        let token = create_token_at(&sk, url, "GET", None, created_at).unwrap();
        let header = authorization_header(&token);

        // Verify at a time 120s BEFORE the event -- future event beyond tolerance
        let err = verify_token_at(&header, url, "GET", None, created_at - 120).unwrap_err();
        assert!(matches!(err, Nip98Error::TimestampExpired { .. }));
    }

    // ── Edge cases ─────────────────────────────────────────────────────

    #[test]
    fn nip98_url_trailing_slash_mismatch_rejected() {
        let sk = test_secret_key();
        let url_with_slash = "https://api.example.com/path/";
        let url_without_slash = "https://api.example.com/path";

        let token = create_token(&sk, url_with_slash, "GET", None).unwrap();
        let header = authorization_header(&token);

        let err = verify_token(&header, url_without_slash, "GET", None).unwrap_err();
        assert!(matches!(err, Nip98Error::UrlMismatch { .. }));
    }

    #[test]
    fn nip98_method_case_insensitive() {
        let sk = test_secret_key();
        let url = "https://api.example.com/test";

        let token = create_token(&sk, url, "post", None).unwrap();
        let header = authorization_header(&token);

        // Should succeed: method comparison is case-insensitive
        let result = verify_token(&header, url, "POST", None).unwrap();
        assert_eq!(result.method, "post");
    }

    #[test]
    fn nip98_empty_body_no_payload_tag_required() {
        let sk = test_secret_key();
        let url = "https://api.example.com/get";

        let token = create_token(&sk, url, "GET", None).unwrap();
        let header = authorization_header(&token);

        // No body on verify side either — should pass
        let result = verify_token(&header, url, "GET", None).unwrap();
        assert!(result.payload_hash.is_none());
    }

    #[test]
    fn nip98_authorization_header_format() {
        let token = "abc123";
        let header = authorization_header(token);
        assert_eq!(header, "Nostr abc123");
    }

    // ── Additional edge-case tests ──────────────────────────────────────

    #[test]
    fn nip98_reject_wrong_kind() {
        let sk = test_signing_key();
        let pubkey = hex::encode(sk.verifying_key().to_bytes());
        let url = "https://api.example.com/test";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Manually create an event with wrong kind (kind 1 instead of 27235)
        let unsigned = UnsignedEvent {
            pubkey,
            created_at: now,
            kind: 1, // wrong kind
            tags: vec![
                vec!["u".to_string(), url.to_string()],
                vec!["method".to_string(), "GET".to_string()],
            ],
            content: String::new(),
        };
        let signed = sign_event(unsigned, &sk).unwrap();
        let json = serde_json::to_string(&signed).unwrap();
        let b64 = BASE64.encode(json.as_bytes());
        let header = authorization_header(&b64);

        let err = verify_token(&header, url, "GET", None).unwrap_err();
        assert!(matches!(err, Nip98Error::WrongKind(1)));
    }

    #[test]
    fn nip98_reject_missing_url_tag() {
        let sk = test_signing_key();
        let pubkey = hex::encode(sk.verifying_key().to_bytes());
        let url = "https://api.example.com/test";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Event with method tag but no u tag
        let unsigned = UnsignedEvent {
            pubkey,
            created_at: now,
            kind: HTTP_AUTH_KIND,
            tags: vec![vec!["method".to_string(), "GET".to_string()]],
            content: String::new(),
        };
        let signed = sign_event(unsigned, &sk).unwrap();
        let json = serde_json::to_string(&signed).unwrap();
        let b64 = BASE64.encode(json.as_bytes());
        let header = authorization_header(&b64);

        let err = verify_token(&header, url, "GET", None).unwrap_err();
        assert!(matches!(err, Nip98Error::MissingTag(_)));
    }

    #[test]
    fn nip98_reject_missing_method_tag() {
        let sk = test_signing_key();
        let pubkey = hex::encode(sk.verifying_key().to_bytes());
        let url = "https://api.example.com/test";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Event with u tag but no method tag
        let unsigned = UnsignedEvent {
            pubkey,
            created_at: now,
            kind: HTTP_AUTH_KIND,
            tags: vec![vec!["u".to_string(), url.to_string()]],
            content: String::new(),
        };
        let signed = sign_event(unsigned, &sk).unwrap();
        let json = serde_json::to_string(&signed).unwrap();
        let b64 = BASE64.encode(json.as_bytes());
        let header = authorization_header(&b64);

        let err = verify_token(&header, url, "GET", None).unwrap_err();
        assert!(matches!(err, Nip98Error::MissingTag(_)));
    }

    #[test]
    fn nip98_empty_body_with_body_bytes_passes() {
        let sk = test_secret_key();
        let url = "https://api.example.com/test";

        // Create token without body
        let token = create_token(&sk, url, "POST", None).unwrap();
        let header = authorization_header(&token);

        // Verify with empty body slice (not None) -- should pass since body is empty
        let result = verify_token(&header, url, "POST", Some(b"")).unwrap();
        assert!(result.payload_hash.is_none());
    }

    #[test]
    fn nip98_get_tag_returns_none_for_missing() {
        let event = NostrEvent {
            id: "00".repeat(32),
            pubkey: "aa".repeat(32),
            created_at: 0,
            kind: 1,
            tags: vec![vec!["e".into(), "ref1".into()]],
            content: String::new(),
            sig: "00".repeat(64),
        };
        assert!(get_tag(&event, "u").is_none());
        assert_eq!(get_tag(&event, "e"), Some("ref1".to_string()));
    }

    // ── verify_nip98 (canonical API) ─────────────────────────────────────

    #[test]
    fn nip98_verify_nip98_default_tolerance() {
        let sk = test_secret_key();
        let url = "https://api.example.com/canonical";
        let token = create_token(&sk, url, "GET", None).unwrap();
        let header = authorization_header(&token);

        // None means default 60s tolerance — token was just created, so it's fresh.
        let result = verify_nip98(&header, url, "GET", None).unwrap();
        assert_eq!(result.url, url);
        assert_eq!(result.method, "GET");
    }

    #[test]
    fn nip98_verify_nip98_custom_tolerance() {
        let sk = test_secret_key();
        let url = "https://api.example.com/custom";
        let created_at = 1_700_000_000u64;

        let token = create_token_at(&sk, url, "POST", None, created_at).unwrap();
        let header = authorization_header(&token);

        // 90-second offset should fail with default 60s tolerance
        let err = verify_token_at(&header, url, "POST", None, created_at + 90).unwrap_err();
        assert!(matches!(err, Nip98Error::TimestampExpired { .. }));

        // But should succeed with a 120s tolerance via verify_token_full
        let result = verify_token_full(&header, url, "POST", None, created_at + 90, 120).unwrap();
        assert_eq!(result.url, url);
        assert_eq!(result.created_at, created_at);
    }

    #[test]
    fn nip98_verify_token_full_strict_tolerance() {
        let sk = test_secret_key();
        let url = "https://api.example.com/strict";
        let created_at = 1_700_000_000u64;

        let token = create_token_at(&sk, url, "GET", None, created_at).unwrap();
        let header = authorization_header(&token);

        // 10-second tolerance: 5s offset should pass
        let result = verify_token_full(&header, url, "GET", None, created_at + 5, 10).unwrap();
        assert_eq!(result.created_at, created_at);

        // 10-second tolerance: 15s offset should fail
        let err = verify_token_full(&header, url, "GET", None, created_at + 15, 10).unwrap_err();
        assert!(matches!(
            err,
            Nip98Error::TimestampExpired { tolerance: 10, .. }
        ));
    }

    #[test]
    fn nip98_timestamp_expired_error_includes_tolerance() {
        let sk = test_secret_key();
        let url = "https://api.example.com/err";
        let created_at = 1_700_000_000u64;

        let token = create_token_at(&sk, url, "GET", None, created_at).unwrap();
        let header = authorization_header(&token);

        let err = verify_token_full(&header, url, "GET", None, created_at + 200, 30).unwrap_err();
        match err {
            Nip98Error::TimestampExpired {
                event_ts,
                now,
                tolerance,
            } => {
                assert_eq!(event_ts, created_at);
                assert_eq!(now, created_at + 200);
                assert_eq!(tolerance, 30);
            }
            other => panic!("expected TimestampExpired, got: {other}"),
        }
    }

    // ── Replay protection ──────────────────────────────────────────────
    //
    // In-memory replay store for unit tests. The trait is `?Send` so it
    // works in both native and wasm32; the cell is a single-threaded
    // `RefCell` which is fine here.

    use std::cell::RefCell;
    use std::collections::HashSet;

    struct InMemoryReplayStore {
        seen: RefCell<HashSet<String>>,
    }

    impl InMemoryReplayStore {
        fn new() -> Self {
            Self {
                seen: RefCell::new(HashSet::new()),
            }
        }
    }

    #[async_trait::async_trait(?Send)]
    impl Nip98ReplayStore for InMemoryReplayStore {
        async fn seen_or_record(&self, event_id: &str) -> Result<bool, String> {
            let mut g = self.seen.borrow_mut();
            if g.contains(event_id) {
                Ok(false)
            } else {
                g.insert(event_id.to_string());
                Ok(true)
            }
        }
    }

    /// Tiny block_on for unit tests (the replay store futures resolve immediately).
    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn noop_clone(p: *const ()) -> RawWaker {
            RawWaker::new(p, &VTAB)
        }
        fn noop(_: *const ()) {}
        static VTAB: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);
        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTAB)) };
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Box::pin(f);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => continue, // not used here, but safe
            }
        }
    }

    #[test]
    fn nip98_replay_first_use_succeeds() {
        let sk = test_secret_key();
        let url = "https://api.example.com/replay";
        let ts = 1_700_000_000u64;
        let token = create_token_at(&sk, url, "POST", Some(b"x"), ts).unwrap();
        let header = authorization_header(&token);

        let store = InMemoryReplayStore::new();
        let result = block_on(verify_token_at_with_replay(
            &header,
            url,
            "POST",
            Some(b"x"),
            ts,
            &store,
        ));
        assert!(result.is_ok(), "first use must succeed");
    }

    #[test]
    fn nip98_replay_second_use_rejected() {
        let sk = test_secret_key();
        let url = "https://api.example.com/replay";
        let ts = 1_700_000_000u64;
        let token = create_token_at(&sk, url, "POST", Some(b"y"), ts).unwrap();
        let header = authorization_header(&token);

        let store = InMemoryReplayStore::new();

        // First use records the id.
        let _ = block_on(verify_token_at_with_replay(
            &header,
            url,
            "POST",
            Some(b"y"),
            ts,
            &store,
        ))
        .unwrap();

        // Second use of the SAME header (within tolerance) MUST be rejected.
        let err = block_on(verify_token_at_with_replay(
            &header,
            url,
            "POST",
            Some(b"y"),
            ts,
            &store,
        ))
        .unwrap_err();
        assert!(
            matches!(err, Nip98Error::Replayed),
            "second use must be Replayed, got {err}"
        );
    }

    #[test]
    fn nip98_replay_different_events_independent() {
        let sk = test_secret_key();
        let url = "https://api.example.com/replay";
        let ts = 1_700_000_000u64;
        let t1 = create_token_at(&sk, url, "POST", Some(b"a"), ts).unwrap();
        let t2 = create_token_at(&sk, url, "POST", Some(b"b"), ts).unwrap();
        let h1 = authorization_header(&t1);
        let h2 = authorization_header(&t2);

        let store = InMemoryReplayStore::new();
        assert!(block_on(verify_token_at_with_replay(
            &h1,
            url,
            "POST",
            Some(b"a"),
            ts,
            &store,
        ))
        .is_ok());
        // Different body -> different event id -> independent record.
        assert!(block_on(verify_token_at_with_replay(
            &h2,
            url,
            "POST",
            Some(b"b"),
            ts,
            &store,
        ))
        .is_ok());
    }

    #[test]
    fn nip98_create_token_at_deterministic() {
        let sk = test_secret_key();
        let url = "https://api.example.com/test";
        let ts = 1_700_000_000u64;

        // Two tokens created at the same timestamp for same inputs
        let t1 = create_token_at(&sk, url, "GET", None, ts).unwrap();
        let t2 = create_token_at(&sk, url, "GET", None, ts).unwrap();

        // Decode both and check they have the same pubkey, url, method, created_at
        let b1 = BASE64.decode(&t1).unwrap();
        let e1: NostrEvent = serde_json::from_slice(&b1).unwrap();
        let b2 = BASE64.decode(&t2).unwrap();
        let e2: NostrEvent = serde_json::from_slice(&b2).unwrap();

        assert_eq!(e1.pubkey, e2.pubkey);
        assert_eq!(e1.created_at, e2.created_at);
        assert_eq!(e1.kind, e2.kind);
        assert_eq!(e1.tags, e2.tags);
    }
}

// ── Property-based tests (native only, proptest not available in wasm32) ─

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn test_secret_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = 0x01;
        key[31] = 0x01;
        key
    }

    proptest! {
        #[test]
        fn nip98_roundtrip_arbitrary_url(
            path in "[a-z]{1,20}(/[a-z0-9]{1,10}){0,5}"
        ) {
            let sk = test_secret_key();
            let url = format!("https://api.example.com/{path}");
            let ts = 1_700_000_000u64;

            let token = create_token_at(&sk, &url, "GET", None, ts).unwrap();
            let header = authorization_header(&token);
            let result = verify_token_at(&header, &url, "GET", None, ts);
            prop_assert!(result.is_ok(), "Failed for URL: {url}");
            let verified = result.unwrap();
            prop_assert_eq!(verified.url, url);
        }

        #[test]
        fn nip98_roundtrip_arbitrary_method(
            method in "(GET|POST|PUT|DELETE|PATCH|HEAD)"
        ) {
            let sk = test_secret_key();
            let url = "https://api.example.com/test";
            let ts = 1_700_000_000u64;

            let token = create_token_at(&sk, url, &method, None, ts).unwrap();
            let header = authorization_header(&token);
            let result = verify_token_at(&header, url, &method, None, ts);
            prop_assert!(result.is_ok());
        }

        #[test]
        fn nip98_roundtrip_arbitrary_body(
            body in prop::collection::vec(any::<u8>(), 1..200)
        ) {
            let sk = test_secret_key();
            let url = "https://api.example.com/upload";
            let ts = 1_700_000_000u64;

            let token = create_token_at(&sk, url, "POST", Some(&body), ts).unwrap();
            let header = authorization_header(&token);
            let result = verify_token_at(&header, url, "POST", Some(&body), ts);
            prop_assert!(result.is_ok());
        }

        #[test]
        fn nip98_timestamp_within_tolerance_always_passes(
            offset in 0u64..=60
        ) {
            let sk = test_secret_key();
            let url = "https://api.example.com/time";
            let created_at = 1_700_000_000u64;

            let token = create_token_at(&sk, url, "GET", None, created_at).unwrap();
            let header = authorization_header(&token);

            // Verify at created_at + offset (within 60s tolerance)
            let result = verify_token_at(&header, url, "GET", None, created_at + offset);
            prop_assert!(result.is_ok(), "Failed at offset {offset}s");
        }

        #[test]
        fn nip98_timestamp_beyond_tolerance_always_fails(
            offset in 61u64..=600
        ) {
            let sk = test_secret_key();
            let url = "https://api.example.com/time";
            let created_at = 1_700_000_000u64;

            let token = create_token_at(&sk, url, "GET", None, created_at).unwrap();
            let header = authorization_header(&token);

            // Verify at created_at + offset (beyond 60s tolerance)
            let result = verify_token_at(&header, url, "GET", None, created_at + offset);
            prop_assert!(result.is_err(), "Should fail at offset {offset}s");
        }
    }
}
