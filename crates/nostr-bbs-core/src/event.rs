//! Nostr event types and NIP-01 canonical serialization.
//!
//! Phase 5 absorption (ADR-076/078): this module preserves the kit's
//! hex-string `NostrEvent` / `UnsignedEvent` public surface for ABI
//! stability with downstream consumers. Conversion helpers
//! (`to_upstream` / `from_upstream`) bridge to `nostr::Event` so that
//! higher-level NIP modules can delegate protocol logic to rust-nostr.

use k256::schnorr::{SigningKey, VerifyingKey};
use nostr::JsonUtil;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors returned by event operations.
#[derive(Debug, Error)]
pub enum EventError {
    /// The recomputed event ID does not match the `id` field.
    #[error("event ID mismatch: expected {expected}, got {actual}")]
    IdMismatch {
        /// The event's declared ID.
        actual: String,
        /// The ID recomputed from canonical serialization.
        expected: String,
    },

    /// The pubkey field is not a valid 32-byte hex string.
    #[error("invalid pubkey: expected 64 hex chars")]
    InvalidPubkey,

    /// The pubkey bytes are not a valid secp256k1 x-coordinate.
    #[error("pubkey is not a valid secp256k1 point")]
    InvalidPubkeyPoint,

    /// The signature field is not a valid 64-byte hex string.
    #[error("invalid signature: expected 128 hex chars")]
    InvalidSignature,

    /// The Schnorr signature does not verify against the pubkey and event ID.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// Conversion to/from upstream `nostr::Event` failed.
    #[error("upstream conversion: {0}")]
    Upstream(String),
}

/// A fully signed Nostr event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

/// An unsigned event template, ready for ID computation and signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedEvent {
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

/// Compute the NIP-01 event ID: SHA-256 of the canonical JSON serialization.
///
/// Canonical form: `[0, <pubkey>, <created_at>, <kind>, <tags>, <content>]`
///
/// Uses a tuple-of-references to serialize directly into the hasher, avoiding
/// the intermediate `serde_json::Value` DOM tree that the `json!()` macro
/// would create. This matters when verifying batches of 1K+ events: no
/// intermediate heap allocations per event, no GC stutter in WASM.
pub fn compute_event_id(event: &UnsignedEvent) -> [u8; 32] {
    let canonical = (
        0u8,
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    );
    let serialized = serde_json::to_string(&canonical).expect("canonical JSON serialization");
    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    hasher.finalize().into()
}

/// Compute the event ID from a raw [`NostrEvent`] (for verification — recomputes from scratch).
pub fn recompute_event_id(event: &NostrEvent) -> [u8; 32] {
    let unsigned = UnsignedEvent {
        pubkey: event.pubkey.clone(),
        created_at: event.created_at,
        kind: event.kind,
        tags: event.tags.clone(),
        content: event.content.clone(),
    };
    compute_event_id(&unsigned)
}

/// Error returned when the pubkey in an [`UnsignedEvent`] does not match the signing key.
#[derive(Debug, Error)]
#[error("pubkey mismatch: event has {event_pubkey}, signing key derives {derived_pubkey}")]
pub struct PubkeyMismatch {
    pub event_pubkey: String,
    pub derived_pubkey: String,
}

/// Sign an unsigned event, producing a fully signed [`NostrEvent`].
///
/// **Pubkey safety:** The `pubkey` field in `event` is validated against the
/// signing key's derived public key. If they don't match, this function returns
/// an error rather than producing a self-invalid event.
///
/// **Aux randomness:** Uses `getrandom` for the BIP-340 auxiliary randomness
/// nonce, providing side-channel hardening in production. For deterministic
/// signing (tests, reproducibility), use [`sign_event_deterministic`].
pub fn sign_event(
    event: UnsignedEvent,
    signing_key: &SigningKey,
) -> Result<NostrEvent, PubkeyMismatch> {
    let derived_pubkey = hex::encode(signing_key.verifying_key().to_bytes());
    if event.pubkey != derived_pubkey {
        return Err(PubkeyMismatch {
            event_pubkey: event.pubkey,
            derived_pubkey,
        });
    }

    let id_bytes = compute_event_id(&event);
    let id_hex = hex::encode(id_bytes);

    let mut aux_rand = [0u8; 32];
    getrandom::getrandom(&mut aux_rand).expect("getrandom for aux_rand");
    let signature = signing_key
        .sign_raw(&id_bytes, &aux_rand)
        .expect("schnorr sign");
    let sig_hex = hex::encode(signature.to_bytes());

    Ok(NostrEvent {
        id: id_hex,
        pubkey: event.pubkey,
        created_at: event.created_at,
        kind: event.kind,
        tags: event.tags,
        content: event.content,
        sig: sig_hex,
    })
}

/// Sign an unsigned event with deterministic (zero) auxiliary randomness.
///
/// Same pubkey validation as [`sign_event`], but uses all-zero aux bytes for
/// the BIP-340 nonce. Useful for tests and reproducible signatures. **Not
/// recommended for production** — prefer [`sign_event`] which uses random aux.
pub fn sign_event_deterministic(
    event: UnsignedEvent,
    signing_key: &SigningKey,
) -> Result<NostrEvent, PubkeyMismatch> {
    let derived_pubkey = hex::encode(signing_key.verifying_key().to_bytes());
    if event.pubkey != derived_pubkey {
        return Err(PubkeyMismatch {
            event_pubkey: event.pubkey,
            derived_pubkey,
        });
    }

    let id_bytes = compute_event_id(&event);
    let id_hex = hex::encode(id_bytes);

    let aux_rand = [0u8; 32];
    let signature = signing_key
        .sign_raw(&id_bytes, &aux_rand)
        .expect("schnorr sign");
    let sig_hex = hex::encode(signature.to_bytes());

    Ok(NostrEvent {
        id: id_hex,
        pubkey: event.pubkey,
        created_at: event.created_at,
        kind: event.kind,
        tags: event.tags,
        content: event.content,
        sig: sig_hex,
    })
}

/// Verify a signed event: recompute ID from canonical form, then verify Schnorr signature.
///
/// Returns `true` if the event ID matches the canonical serialization AND the
/// signature is valid against the pubkey. For richer error information, use
/// [`verify_event_strict`] instead.
pub fn verify_event(event: &NostrEvent) -> bool {
    verify_event_strict(event).is_ok()
}

/// Verify a signed event with detailed error reporting.
///
/// Same checks as [`verify_event`] but returns a typed [`EventError`] on failure
/// instead of a bare `false`, making it easier to log or propagate the reason.
pub fn verify_event_strict(event: &NostrEvent) -> Result<(), EventError> {
    // Recompute ID — never trust the provided id field
    let expected_id = recompute_event_id(event);
    let expected_id_hex = hex::encode(expected_id);

    if event.id != expected_id_hex {
        return Err(EventError::IdMismatch {
            actual: event.id.clone(),
            expected: expected_id_hex,
        });
    }

    // Decode pubkey
    let pubkey_bytes = hex::decode(&event.pubkey)
        .ok()
        .filter(|b| b.len() == 32)
        .ok_or(EventError::InvalidPubkey)?;

    let verifying_key =
        VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| EventError::InvalidPubkeyPoint)?;

    // Decode signature
    let sig_bytes = hex::decode(&event.sig)
        .ok()
        .filter(|b| b.len() == 64)
        .ok_or(EventError::InvalidSignature)?;

    let signature = k256::schnorr::Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| EventError::InvalidSignature)?;

    // Verify Schnorr signature over the event ID bytes
    verifying_key
        .verify_raw(&expected_id, &signature)
        .map_err(|_| EventError::SignatureInvalid)
}

/// Verify multiple events, returning a result for each.
///
/// Useful in relay and worker contexts that receive batches of events
/// (e.g. `EVENT` messages on a WebSocket connection). Each event is
/// verified independently; a failure in one does not affect the others.
pub fn verify_events_batch(events: &[NostrEvent]) -> Vec<Result<(), EventError>> {
    events.iter().map(verify_event_strict).collect()
}

// ── Upstream conversion layer (ADR-076/078) ─────────────────────────────────
//
// Bridges between the kit's hex-string `NostrEvent` and rust-nostr 0.44's
// typed `nostr::Event`. Both serialize to NIP-01 JSON, so serde round-trip
// is the natural conversion — correct by construction with zero field-mapping
// risk.

impl NostrEvent {
    /// Convert to upstream `nostr::Event` via NIP-01 JSON round-trip.
    pub fn to_upstream(&self) -> Result<nostr::Event, EventError> {
        let json = serde_json::to_string(self).expect("NostrEvent always serializes");
        nostr::Event::from_json(&json).map_err(|e| EventError::Upstream(e.to_string()))
    }

    /// Convert from upstream `nostr::Event` via NIP-01 JSON round-trip.
    pub fn from_upstream(event: &nostr::Event) -> Self {
        let json = event.as_json();
        serde_json::from_str(&json).expect("upstream Event produces valid NIP-01 JSON")
    }
}

impl UnsignedEvent {
    /// Convert to an upstream `EventBuilder` for signing via rust-nostr.
    pub fn to_upstream_builder(&self) -> nostr::EventBuilder {
        let tags: Vec<nostr::Tag> = self
            .tags
            .iter()
            .filter_map(|t| {
                if t.is_empty() {
                    return None;
                }
                Some(nostr::Tag::parse(t.clone()).unwrap_or_else(|_| {
                    nostr::Tag::custom(
                        nostr::TagKind::custom(t[0].clone()),
                        t[1..].iter().cloned().collect::<Vec<_>>(),
                    )
                }))
            })
            .collect();
        nostr::EventBuilder::new(nostr::Kind::from(self.kind as u16), &self.content)
            .tags(tags)
            .custom_created_at(nostr::Timestamp::from(self.created_at))
    }
}

/// Convert a `k256::schnorr::SigningKey` to upstream `nostr::Keys`.
pub fn signing_key_to_upstream(sk: &SigningKey) -> Result<nostr::Keys, EventError> {
    let sk_hex = hex::encode(sk.to_bytes());
    nostr::Keys::parse(&sk_hex).map_err(|e| EventError::Upstream(e.to_string()))
}

/// Sign an `UnsignedEvent` via upstream rust-nostr, returning a `NostrEvent`.
///
/// Same pubkey safety guarantee as [`sign_event`]: validates that the
/// unsigned event's `pubkey` matches the signing key.
pub fn sign_event_upstream(
    event: UnsignedEvent,
    signing_key: &SigningKey,
) -> Result<NostrEvent, PubkeyMismatch> {
    let derived_pubkey = hex::encode(signing_key.verifying_key().to_bytes());
    if event.pubkey != derived_pubkey {
        return Err(PubkeyMismatch {
            event_pubkey: event.pubkey,
            derived_pubkey,
        });
    }
    let keys = signing_key_to_upstream(signing_key)
        .expect("valid SigningKey converts to valid Keys");
    let builder = event.to_upstream_builder();
    let upstream_event = builder
        .sign_with_keys(&keys)
        .expect("signing with valid keys succeeds");
    Ok(NostrEvent::from_upstream(&upstream_event))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signing_key() -> SigningKey {
        let secret = [0x01u8; 32];
        SigningKey::from_bytes(&secret).unwrap()
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = test_signing_key();
        let pubkey = hex::encode(sk.verifying_key().to_bytes());

        let unsigned = UnsignedEvent {
            pubkey,
            created_at: 1700000000,
            kind: 1,
            tags: vec![],
            content: "hello".to_string(),
        };

        let signed = sign_event_deterministic(unsigned, &sk).unwrap();
        assert!(verify_event(&signed));
    }

    #[test]
    fn sign_event_rejects_wrong_pubkey() {
        let sk = test_signing_key();

        let unsigned = UnsignedEvent {
            pubkey: "aa".repeat(32), // wrong pubkey
            created_at: 1700000000,
            kind: 1,
            tags: vec![],
            content: "hello".to_string(),
        };

        let result = sign_event_deterministic(unsigned, &sk);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("pubkey mismatch"));
    }

    #[test]
    fn sign_event_randomized_produces_valid_event() {
        let sk = test_signing_key();
        let pubkey = hex::encode(sk.verifying_key().to_bytes());

        let unsigned = UnsignedEvent {
            pubkey,
            created_at: 1700000000,
            kind: 1,
            tags: vec![],
            content: "randomized".to_string(),
        };

        let signed = sign_event(unsigned, &sk).unwrap();
        assert!(verify_event(&signed));
    }

    #[test]
    fn tampered_content_fails_verification() {
        let sk = test_signing_key();
        let pubkey = hex::encode(sk.verifying_key().to_bytes());

        let unsigned = UnsignedEvent {
            pubkey,
            created_at: 1700000000,
            kind: 1,
            tags: vec![],
            content: "hello".to_string(),
        };

        let mut signed = sign_event_deterministic(unsigned, &sk).unwrap();
        signed.content = "tampered".to_string();
        assert!(!verify_event(&signed));
    }

    #[test]
    fn tampered_id_fails_verification() {
        let sk = test_signing_key();
        let pubkey = hex::encode(sk.verifying_key().to_bytes());

        let unsigned = UnsignedEvent {
            pubkey,
            created_at: 1700000000,
            kind: 1,
            tags: vec![],
            content: "hello".to_string(),
        };

        let mut signed = sign_event_deterministic(unsigned, &sk).unwrap();
        signed.id = "00".repeat(32);
        assert!(!verify_event(&signed));
    }

    #[test]
    fn verify_event_strict_returns_id_mismatch() {
        let sk = test_signing_key();
        let pubkey = hex::encode(sk.verifying_key().to_bytes());

        let unsigned = UnsignedEvent {
            pubkey,
            created_at: 1700000000,
            kind: 1,
            tags: vec![],
            content: "hello".to_string(),
        };

        let mut signed = sign_event_deterministic(unsigned, &sk).unwrap();
        signed.id = "00".repeat(32);
        let err = verify_event_strict(&signed).unwrap_err();
        assert!(matches!(err, EventError::IdMismatch { .. }));
    }

    #[test]
    fn verify_event_strict_returns_signature_invalid() {
        let sk = test_signing_key();
        let pubkey = hex::encode(sk.verifying_key().to_bytes());

        let unsigned = UnsignedEvent {
            pubkey,
            created_at: 1700000000,
            kind: 1,
            tags: vec![],
            content: "hello".to_string(),
        };

        let mut signed = sign_event_deterministic(unsigned, &sk).unwrap();
        let mut sig_bytes = hex::decode(&signed.sig).unwrap();
        sig_bytes[0] ^= 0xFF;
        signed.sig = hex::encode(&sig_bytes);
        let err = verify_event_strict(&signed).unwrap_err();
        assert!(matches!(err, EventError::SignatureInvalid));
    }

    #[test]
    fn verify_events_batch_mixed_results() {
        let sk = test_signing_key();
        let pubkey = hex::encode(sk.verifying_key().to_bytes());

        let good = sign_event_deterministic(
            UnsignedEvent {
                pubkey: pubkey.clone(),
                created_at: 1700000000,
                kind: 1,
                tags: vec![],
                content: "valid".to_string(),
            },
            &sk,
        )
        .unwrap();

        let mut bad = sign_event_deterministic(
            UnsignedEvent {
                pubkey,
                created_at: 1700000001,
                kind: 1,
                tags: vec![],
                content: "tampered".to_string(),
            },
            &sk,
        )
        .unwrap();
        bad.content = "modified".to_string();

        let results = verify_events_batch(&[good, bad]);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(results[1].is_err());
    }

    #[test]
    fn verify_events_batch_all_valid() {
        let sk = test_signing_key();
        let pubkey = hex::encode(sk.verifying_key().to_bytes());

        let events: Vec<NostrEvent> = (0..5)
            .map(|i| {
                sign_event_deterministic(
                    UnsignedEvent {
                        pubkey: pubkey.clone(),
                        created_at: 1700000000 + i,
                        kind: 1,
                        tags: vec![],
                        content: format!("msg {i}"),
                    },
                    &sk,
                )
                .unwrap()
            })
            .collect();

        let results = verify_events_batch(&events);
        assert!(results.iter().all(|r| r.is_ok()));
    }

    #[test]
    fn verify_events_batch_empty() {
        let results = verify_events_batch(&[]);
        assert!(results.is_empty());
    }

    // ── Upstream conversion layer tests ─────────────────────────────────

    #[test]
    fn nostr_event_to_upstream_roundtrip() {
        let sk = test_signing_key();
        let pubkey = hex::encode(sk.verifying_key().to_bytes());
        let signed = sign_event_deterministic(
            UnsignedEvent {
                pubkey,
                created_at: 1700000000,
                kind: 1,
                tags: vec![vec!["p".into(), "aa".repeat(32)]],
                content: "hello upstream".to_string(),
            },
            &sk,
        )
        .unwrap();

        let upstream = signed.to_upstream().expect("to_upstream succeeds");
        upstream.verify().expect("upstream verify passes");
        let back = NostrEvent::from_upstream(&upstream);
        assert_eq!(back.id, signed.id);
        assert_eq!(back.pubkey, signed.pubkey);
        assert_eq!(back.content, signed.content);
        assert_eq!(back.kind, signed.kind);
        assert_eq!(back.sig, signed.sig);
    }

    #[test]
    fn unsigned_to_upstream_builder_preserves_fields() {
        let unsigned = UnsignedEvent {
            pubkey: "aa".repeat(32),
            created_at: 1700000000,
            kind: 30023,
            tags: vec![
                vec!["d".into(), "test-article".into()],
                vec!["t".into(), "rust".into()],
            ],
            content: "long form content".to_string(),
        };
        let builder = unsigned.to_upstream_builder();
        let keys = nostr::Keys::generate();
        let event = builder.sign_with_keys(&keys).unwrap();
        assert_eq!(event.created_at.as_u64(), 1700000000);
        assert_eq!(event.kind.as_u16(), 30023);
        assert_eq!(event.content, "long form content");
    }

    #[test]
    fn sign_event_upstream_matches_kit_verify() {
        let sk = test_signing_key();
        let pubkey = hex::encode(sk.verifying_key().to_bytes());
        let unsigned = UnsignedEvent {
            pubkey,
            created_at: 1700000000,
            kind: 1,
            tags: vec![],
            content: "upstream-signed".to_string(),
        };
        let signed = sign_event_upstream(unsigned, &sk).unwrap();
        assert!(verify_event(&signed), "kit verify must accept upstream-signed event");
    }

    #[test]
    fn sign_event_upstream_rejects_wrong_pubkey() {
        let sk = test_signing_key();
        let unsigned = UnsignedEvent {
            pubkey: "bb".repeat(32),
            created_at: 1700000000,
            kind: 1,
            tags: vec![],
            content: "wrong pk".to_string(),
        };
        assert!(sign_event_upstream(unsigned, &sk).is_err());
    }
}
