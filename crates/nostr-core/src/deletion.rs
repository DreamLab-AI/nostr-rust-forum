//! NIP-09: Event Deletion — kind 5 deletion request events.
//!
//! A deletion event targets one or more events by their IDs, signaling to relays
//! and clients that the author wishes those events to be removed. Only the original
//! author's deletion events are honored.

use k256::schnorr::SigningKey;
use thiserror::Error;

use crate::event::{sign_event, NostrEvent, UnsignedEvent};

/// Kind for NIP-09 deletion events.
const KIND_DELETION: u64 = 5;

/// Errors specific to NIP-09 deletion event creation.
#[derive(Debug, Error)]
pub enum DeletionError {
    /// No target event IDs were provided.
    #[error("at least one target event ID is required")]
    NoTargets,

    /// A target event ID is not a valid 64-character hex string.
    #[error("invalid target event ID: {0}")]
    InvalidTargetId(String),

    /// The signing key is invalid.
    #[error("invalid signing key: {0}")]
    InvalidKey(String),

    /// Signing the deletion event failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),
}

/// Create a kind-5 deletion event targeting one or more events.
///
/// Per NIP-09, the deletion event contains `["e", "<event-id>"]` tags for each
/// target. An optional `reason` string is placed in the `content` field.
///
/// # Arguments
/// * `privkey` - 32-byte secp256k1 secret key of the event author
/// * `target_ids` - Hex-encoded event IDs to request deletion of
/// * `reason` - Optional human-readable reason for the deletion
///
/// # Errors
/// Returns `DeletionError` if no targets are provided, any target ID is
/// invalid, or signing fails.
pub fn create_deletion_event(
    privkey: &[u8; 32],
    target_ids: &[String],
    reason: Option<&str>,
) -> Result<NostrEvent, DeletionError> {
    if target_ids.is_empty() {
        return Err(DeletionError::NoTargets);
    }

    // Validate all target IDs are 64-char hex
    for id in target_ids {
        if id.len() != 64 || hex::decode(id).is_err() {
            return Err(DeletionError::InvalidTargetId(id.clone()));
        }
    }

    let signing_key = SigningKey::from_bytes(privkey)
        .map_err(|e| DeletionError::InvalidKey(e.to_string()))?;
    let pubkey = hex::encode(signing_key.verifying_key().to_bytes());

    let tags: Vec<Vec<String>> = target_ids
        .iter()
        .map(|id| vec!["e".to_string(), id.clone()])
        .collect();

    let now = now_secs();

    let unsigned = UnsignedEvent {
        pubkey,
        created_at: now,
        kind: KIND_DELETION,
        tags,
        content: reason.unwrap_or("").to_string(),
    };

    sign_event(unsigned, &signing_key)
        .map_err(|e| DeletionError::SigningFailed(e.to_string()))
}

/// Get current Unix timestamp, platform-aware.
fn now_secs() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0) as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::verify_event;
    use k256::schnorr::SigningKey;

    fn test_signing_key() -> (SigningKey, [u8; 32]) {
        let secret = [0x01u8; 32];
        let sk = SigningKey::from_bytes(&secret).unwrap();
        (sk, secret)
    }

    #[test]
    fn create_deletion_single_target() {
        let (sk, privkey) = test_signing_key();
        let pubkey = hex::encode(sk.verifying_key().to_bytes());
        let target = "aa".repeat(32);

        let event = create_deletion_event(&privkey, &[target.clone()], None).unwrap();

        assert_eq!(event.kind, 5);
        assert_eq!(event.pubkey, pubkey);
        assert_eq!(event.content, "");
        assert_eq!(event.tags.len(), 1);
        assert_eq!(event.tags[0], vec!["e", &target]);
        assert!(verify_event(&event));
    }

    #[test]
    fn create_deletion_multiple_targets_with_reason() {
        let (_, privkey) = test_signing_key();
        let targets = vec!["bb".repeat(32), "cc".repeat(32), "dd".repeat(32)];
        let reason = "spam cleanup";

        let event = create_deletion_event(&privkey, &targets, Some(reason)).unwrap();

        assert_eq!(event.kind, 5);
        assert_eq!(event.content, reason);
        assert_eq!(event.tags.len(), 3);
        for (i, target) in targets.iter().enumerate() {
            assert_eq!(event.tags[i][0], "e");
            assert_eq!(event.tags[i][1], *target);
        }
        assert!(verify_event(&event));
    }

    #[test]
    fn create_deletion_no_targets_rejected() {
        let (_, privkey) = test_signing_key();
        let result = create_deletion_event(&privkey, &[], None);
        assert!(matches!(result, Err(DeletionError::NoTargets)));
    }

    #[test]
    fn create_deletion_invalid_target_id_rejected() {
        let (_, privkey) = test_signing_key();
        let result = create_deletion_event(&privkey, &["not-hex".to_string()], None);
        assert!(matches!(result, Err(DeletionError::InvalidTargetId(_))));
    }

    #[test]
    fn create_deletion_short_target_id_rejected() {
        let (_, privkey) = test_signing_key();
        let result = create_deletion_event(&privkey, &["aabb".to_string()], None);
        assert!(matches!(result, Err(DeletionError::InvalidTargetId(_))));
    }

    #[test]
    fn create_deletion_verifies_signature() {
        let (_, privkey) = test_signing_key();
        let target = "ee".repeat(32);
        let event =
            create_deletion_event(&privkey, &[target], Some("test reason")).unwrap();
        assert!(verify_event(&event));
    }

    #[test]
    fn create_deletion_empty_reason_is_empty_content() {
        let (_, privkey) = test_signing_key();
        let target = "ff".repeat(32);
        let event = create_deletion_event(&privkey, &[target], None).unwrap();
        assert_eq!(event.content, "");
    }
}
