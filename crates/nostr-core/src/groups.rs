//! NIP-29: Relay-based Groups — group event constructors.
//!
//! NIP-29 defines relay-based groups where the relay manages membership and
//! access control. All group events carry an `["h", "<group-id>"]` tag.
//!
//! Event kinds:
//! - 9: Group chat message
//! - 9000: Add user to group
//! - 9001: Remove user from group
//! - 9005: Delete event from group
//! - 9021: Join request
//! - 9024: Registration request
//! - 39000: Group metadata (name, about, picture)
//! - 39002: Members list (read-only, relay-published)

use k256::schnorr::SigningKey;
use thiserror::Error;

use crate::event::{sign_event, NostrEvent, UnsignedEvent};

// -- Kind constants -----------------------------------------------------------

const KIND_GROUP_MESSAGE: u64 = 9;
const KIND_ADD_USER: u64 = 9000;
const KIND_REMOVE_USER: u64 = 9001;
const KIND_GROUP_DELETE: u64 = 9005;
const KIND_JOIN_REQUEST: u64 = 9021;
const KIND_REGISTRATION_REQUEST: u64 = 9024;
const KIND_GROUP_METADATA: u64 = 39000;

// -- Error type ---------------------------------------------------------------

/// Errors specific to NIP-29 group event creation.
#[derive(Debug, Error)]
pub enum GroupError {
    /// The group ID is empty.
    #[error("group_id must not be empty")]
    EmptyGroupId,

    /// A pubkey argument is not valid 64-character hex.
    #[error("invalid pubkey hex: {0}")]
    InvalidPubkey(String),

    /// An event ID argument is not valid 64-character hex.
    #[error("invalid event ID hex: {0}")]
    InvalidEventId(String),

    /// The signing key is invalid.
    #[error("invalid signing key: {0}")]
    InvalidKey(String),

    /// Signing the event failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),
}

// -- Helpers ------------------------------------------------------------------

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

fn validate_group_id(group_id: &str) -> Result<(), GroupError> {
    if group_id.is_empty() {
        return Err(GroupError::EmptyGroupId);
    }
    Ok(())
}

fn validate_hex_pubkey(pk: &str) -> Result<(), GroupError> {
    if pk.len() != 64 || hex::decode(pk).is_err() {
        return Err(GroupError::InvalidPubkey(pk.to_string()));
    }
    Ok(())
}

fn validate_hex_event_id(id: &str) -> Result<(), GroupError> {
    if id.len() != 64 || hex::decode(id).is_err() {
        return Err(GroupError::InvalidEventId(id.to_string()));
    }
    Ok(())
}

fn build_and_sign(
    privkey: &[u8; 32],
    kind: u64,
    tags: Vec<Vec<String>>,
    content: String,
) -> Result<NostrEvent, GroupError> {
    let signing_key =
        SigningKey::from_bytes(privkey).map_err(|e| GroupError::InvalidKey(e.to_string()))?;
    let pubkey = hex::encode(signing_key.verifying_key().to_bytes());

    let unsigned = UnsignedEvent {
        pubkey,
        created_at: now_secs(),
        kind,
        tags,
        content,
    };

    sign_event(unsigned, &signing_key).map_err(|e| GroupError::SigningFailed(e.to_string()))
}

// -- Public constructors ------------------------------------------------------

/// Create a group chat message (kind 9).
///
/// Content is the message text. Tags: `["h", group_id]`.
pub fn create_group_message(
    privkey: &[u8; 32],
    group_id: &str,
    content: &str,
) -> Result<NostrEvent, GroupError> {
    validate_group_id(group_id)?;
    let tags = vec![vec!["h".to_string(), group_id.to_string()]];
    build_and_sign(privkey, KIND_GROUP_MESSAGE, tags, content.to_string())
}

/// Create group metadata (kind 39000).
///
/// Tags: `["h", group_id]`, `["name", name]`, `["about", about]`, `["picture", picture]`.
pub fn create_group_metadata(
    privkey: &[u8; 32],
    group_id: &str,
    name: &str,
    about: &str,
    picture: &str,
) -> Result<NostrEvent, GroupError> {
    validate_group_id(group_id)?;
    let tags = vec![
        vec!["h".to_string(), group_id.to_string()],
        vec!["name".to_string(), name.to_string()],
        vec!["about".to_string(), about.to_string()],
        vec!["picture".to_string(), picture.to_string()],
    ];
    build_and_sign(privkey, KIND_GROUP_METADATA, tags, String::new())
}

/// Create an add-user event (kind 9000).
///
/// Tags: `["h", group_id]`, `["p", user_pubkey]`.
pub fn create_add_user(
    privkey: &[u8; 32],
    group_id: &str,
    user_pubkey: &str,
) -> Result<NostrEvent, GroupError> {
    validate_group_id(group_id)?;
    validate_hex_pubkey(user_pubkey)?;
    let tags = vec![
        vec!["h".to_string(), group_id.to_string()],
        vec!["p".to_string(), user_pubkey.to_string()],
    ];
    build_and_sign(privkey, KIND_ADD_USER, tags, String::new())
}

/// Create a remove-user event (kind 9001).
///
/// Tags: `["h", group_id]`, `["p", user_pubkey]`.
pub fn create_remove_user(
    privkey: &[u8; 32],
    group_id: &str,
    user_pubkey: &str,
) -> Result<NostrEvent, GroupError> {
    validate_group_id(group_id)?;
    validate_hex_pubkey(user_pubkey)?;
    let tags = vec![
        vec!["h".to_string(), group_id.to_string()],
        vec!["p".to_string(), user_pubkey.to_string()],
    ];
    build_and_sign(privkey, KIND_REMOVE_USER, tags, String::new())
}

/// Create a group-delete event (kind 9005) to request deletion of an event within a group.
///
/// Tags: `["h", group_id]`, `["e", event_id]`.
pub fn create_group_delete(
    privkey: &[u8; 32],
    group_id: &str,
    event_id: &str,
) -> Result<NostrEvent, GroupError> {
    validate_group_id(group_id)?;
    validate_hex_event_id(event_id)?;
    let tags = vec![
        vec!["h".to_string(), group_id.to_string()],
        vec!["e".to_string(), event_id.to_string()],
    ];
    build_and_sign(privkey, KIND_GROUP_DELETE, tags, String::new())
}

/// Create a join request (kind 9021).
///
/// Tags: `["h", group_id]`. Optional message in content.
pub fn create_join_request(
    privkey: &[u8; 32],
    group_id: &str,
    message: Option<&str>,
) -> Result<NostrEvent, GroupError> {
    validate_group_id(group_id)?;
    let tags = vec![vec!["h".to_string(), group_id.to_string()]];
    build_and_sign(
        privkey,
        KIND_JOIN_REQUEST,
        tags,
        message.unwrap_or("").to_string(),
    )
}

/// Create a registration request (kind 9024).
///
/// Tags: `["h", group_id]`. Metadata in content (e.g. JSON profile data).
pub fn create_registration_request(
    privkey: &[u8; 32],
    group_id: &str,
    metadata: &str,
) -> Result<NostrEvent, GroupError> {
    validate_group_id(group_id)?;
    let tags = vec![vec!["h".to_string(), group_id.to_string()]];
    build_and_sign(
        privkey,
        KIND_REGISTRATION_REQUEST,
        tags,
        metadata.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::verify_event;
    use k256::schnorr::SigningKey;

    fn test_key() -> [u8; 32] {
        [0x01u8; 32]
    }

    fn test_pubkey_hex() -> String {
        let sk = SigningKey::from_bytes(&test_key()).unwrap();
        hex::encode(sk.verifying_key().to_bytes())
    }

    // -- Group message (kind 9) -----------------------------------------------

    #[test]
    fn group_message_has_correct_kind_and_h_tag() {
        let event = create_group_message(&test_key(), "general", "hello group").unwrap();
        assert_eq!(event.kind, 9);
        assert_eq!(event.tags[0], vec!["h", "general"]);
        assert_eq!(event.content, "hello group");
        assert!(verify_event(&event));
    }

    #[test]
    fn group_message_empty_group_id_rejected() {
        let result = create_group_message(&test_key(), "", "msg");
        assert!(matches!(result, Err(GroupError::EmptyGroupId)));
    }

    #[test]
    fn group_message_signature_valid() {
        let event = create_group_message(&test_key(), "test-group", "test").unwrap();
        assert!(verify_event(&event));
    }

    // -- Group metadata (kind 39000) ------------------------------------------

    #[test]
    fn group_metadata_has_correct_tags() {
        let event = create_group_metadata(
            &test_key(),
            "dev",
            "Developers",
            "A group for devs",
            "https://example.com/pic.png",
        )
        .unwrap();

        assert_eq!(event.kind, 39000);
        assert_eq!(event.tags[0], vec!["h", "dev"]);
        assert_eq!(event.tags[1], vec!["name", "Developers"]);
        assert_eq!(event.tags[2], vec!["about", "A group for devs"]);
        assert_eq!(event.tags[3], vec!["picture", "https://example.com/pic.png"]);
        assert_eq!(event.content, "");
        assert!(verify_event(&event));
    }

    #[test]
    fn group_metadata_empty_group_rejected() {
        let result = create_group_metadata(&test_key(), "", "n", "a", "p");
        assert!(matches!(result, Err(GroupError::EmptyGroupId)));
    }

    #[test]
    fn group_metadata_pubkey_matches() {
        let event = create_group_metadata(&test_key(), "g", "n", "a", "p").unwrap();
        assert_eq!(event.pubkey, test_pubkey_hex());
    }

    // -- Add user (kind 9000) -------------------------------------------------

    #[test]
    fn add_user_has_correct_kind_and_tags() {
        let user_pk = "aa".repeat(32);
        let event = create_add_user(&test_key(), "moderators", &user_pk).unwrap();

        assert_eq!(event.kind, 9000);
        assert_eq!(event.tags[0], vec!["h", "moderators"]);
        assert_eq!(event.tags[1], vec!["p", &user_pk]);
        assert!(verify_event(&event));
    }

    #[test]
    fn add_user_invalid_pubkey_rejected() {
        let result = create_add_user(&test_key(), "group", "bad-hex");
        assert!(matches!(result, Err(GroupError::InvalidPubkey(_))));
    }

    #[test]
    fn add_user_short_pubkey_rejected() {
        let result = create_add_user(&test_key(), "group", "aabb");
        assert!(matches!(result, Err(GroupError::InvalidPubkey(_))));
    }

    // -- Remove user (kind 9001) ----------------------------------------------

    #[test]
    fn remove_user_has_correct_kind_and_tags() {
        let user_pk = "bb".repeat(32);
        let event = create_remove_user(&test_key(), "members", &user_pk).unwrap();

        assert_eq!(event.kind, 9001);
        assert_eq!(event.tags[0], vec!["h", "members"]);
        assert_eq!(event.tags[1], vec!["p", &user_pk]);
        assert!(verify_event(&event));
    }

    #[test]
    fn remove_user_invalid_pubkey_rejected() {
        let result = create_remove_user(&test_key(), "group", "xyz");
        assert!(matches!(result, Err(GroupError::InvalidPubkey(_))));
    }

    #[test]
    fn remove_user_empty_group_rejected() {
        let result = create_remove_user(&test_key(), "", &"cc".repeat(32));
        assert!(matches!(result, Err(GroupError::EmptyGroupId)));
    }

    // -- Group delete (kind 9005) ---------------------------------------------

    #[test]
    fn group_delete_has_correct_kind_and_tags() {
        let event_id = "dd".repeat(32);
        let event = create_group_delete(&test_key(), "general", &event_id).unwrap();

        assert_eq!(event.kind, 9005);
        assert_eq!(event.tags[0], vec!["h", "general"]);
        assert_eq!(event.tags[1], vec!["e", &event_id]);
        assert!(verify_event(&event));
    }

    #[test]
    fn group_delete_invalid_event_id_rejected() {
        let result = create_group_delete(&test_key(), "group", "short");
        assert!(matches!(result, Err(GroupError::InvalidEventId(_))));
    }

    #[test]
    fn group_delete_signature_valid() {
        let event_id = "ee".repeat(32);
        let event = create_group_delete(&test_key(), "g", &event_id).unwrap();
        assert!(verify_event(&event));
    }

    // -- Join request (kind 9021) ---------------------------------------------

    #[test]
    fn join_request_with_message() {
        let event =
            create_join_request(&test_key(), "newcomers", Some("Please let me in")).unwrap();

        assert_eq!(event.kind, 9021);
        assert_eq!(event.tags[0], vec!["h", "newcomers"]);
        assert_eq!(event.content, "Please let me in");
        assert!(verify_event(&event));
    }

    #[test]
    fn join_request_without_message() {
        let event = create_join_request(&test_key(), "open-group", None).unwrap();

        assert_eq!(event.kind, 9021);
        assert_eq!(event.content, "");
        assert!(verify_event(&event));
    }

    #[test]
    fn join_request_empty_group_rejected() {
        let result = create_join_request(&test_key(), "", None);
        assert!(matches!(result, Err(GroupError::EmptyGroupId)));
    }

    // -- Registration request (kind 9024) -------------------------------------

    #[test]
    fn registration_request_with_metadata() {
        let metadata = r#"{"name":"Alice","bio":"Developer"}"#;
        let event =
            create_registration_request(&test_key(), "verified-group", metadata).unwrap();

        assert_eq!(event.kind, 9024);
        assert_eq!(event.tags[0], vec!["h", "verified-group"]);
        assert_eq!(event.content, metadata);
        assert!(verify_event(&event));
    }

    #[test]
    fn registration_request_empty_group_rejected() {
        let result = create_registration_request(&test_key(), "", "{}");
        assert!(matches!(result, Err(GroupError::EmptyGroupId)));
    }

    #[test]
    fn registration_request_signature_valid() {
        let event = create_registration_request(&test_key(), "g", "data").unwrap();
        assert!(verify_event(&event));
    }
}
