//! NIP-98: HTTP Auth via Nostr events (kind 27235).
//!
//! Implements token creation and verification matching the TypeScript
//! implementation in `workers/shared/nip98.ts` and `packages/nip98/`.
//!
//! Wire format: `Authorization: Nostr base64(json(signed_event))`

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use k256::schnorr::SigningKey;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::event::{sign_event, verify_event, NostrEvent, UnsignedEvent};

/// NIP-98 event kind.
const HTTP_AUTH_KIND: u64 = 27235;

/// Maximum allowed clock skew in seconds.
const TIMESTAMP_TOLERANCE: u64 = 60;

/// Maximum encoded event size in bytes (64 KiB, matching TS implementation).
const MAX_EVENT_SIZE: usize = 64 * 1024;

/// Authorization header prefix.
const NOSTR_PREFIX: &str = "Nostr ";

/// A verified NIP-98 token with extracted fields.
///
/// Returned by [`verify_token`] and [`verify_token_at`] after successful
/// verification of an `Authorization: Nostr <base64(event)>` header.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Nip98Token {
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

    #[error("timestamp expired: event created_at {event_ts} is more than {TIMESTAMP_TOLERANCE}s from now ({now})")]
    TimestampExpired { event_ts: u64, now: u64 },

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

/// Verify a NIP-98 `Authorization` header value using the system clock.
///
/// Delegates to [`verify_token_at`] with the current Unix timestamp from
/// `SystemTime::now()`. Prefer [`verify_token_at`] in tests or environments
/// where you want deterministic timestamp control.
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
    verify_token_at(auth_header, expected_url, expected_method, body, now)
}

/// Verify a NIP-98 `Authorization` header value against an explicit timestamp.
///
/// Decodes the base64 token, recomputes the event ID from canonical form
/// (never trusts the provided id), verifies the Schnorr signature, and
/// checks URL, method, timestamp tolerance, and optional payload hash.
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
    if now.abs_diff(event.created_at) > TIMESTAMP_TOLERANCE {
        return Err(Nip98Error::TimestampExpired {
            event_ts: event.created_at,
            now,
        });
    }

    // 7. Verify event integrity (recomputes ID from scratch + Schnorr sig check)
    if !verify_event(&event) {
        return Err(Nip98Error::InvalidSignature);
    }

    // 8. Extract and verify URL tag
    let token_url = get_tag(&event, "u").ok_or_else(|| Nip98Error::MissingTag("u".into()))?;
    let normalized_token = token_url.trim_end_matches('/');
    let normalized_expected = expected_url.trim_end_matches('/');
    if normalized_token != normalized_expected {
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
        pubkey: event.pubkey,
        url: token_url,
        method: token_method,
        payload_hash: verified_payload_hash,
        created_at: event.created_at,
    })
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
    fn nip98_url_trailing_slash_normalization() {
        let sk = test_secret_key();
        let url_with_slash = "https://api.example.com/path/";
        let url_without_slash = "https://api.example.com/path";

        let token = create_token(&sk, url_with_slash, "GET", None).unwrap();
        let header = authorization_header(&token);

        // Should succeed: trailing slash is normalized away
        let result = verify_token(&header, url_without_slash, "GET", None).unwrap();
        assert_eq!(result.url, url_with_slash);
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
            tags: vec![
                vec!["method".to_string(), "GET".to_string()],
            ],
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
            tags: vec![
                vec!["u".to_string(), url.to_string()],
            ],
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
