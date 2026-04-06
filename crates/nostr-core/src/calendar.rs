//! NIP-52: Calendar Events — time-based and date-based calendar events with RSVPs.
//!
//! Implements:
//! - Kind 31923: Time-based calendar event (parameterized replaceable via `d` tag)
//! - Kind 31925: Calendar RSVP (parameterized replaceable via `d` tag)

use k256::schnorr::SigningKey;
use thiserror::Error;

use crate::event::{sign_event, NostrEvent, UnsignedEvent};

// -- Kind constants -----------------------------------------------------------

const KIND_CALENDAR_EVENT: u64 = 31923;
const KIND_CALENDAR_RSVP: u64 = 31925;

// -- Types --------------------------------------------------------------------

/// RSVP status for a calendar event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsvpStatus {
    /// The user accepts the invitation.
    Accept,
    /// The user declines the invitation.
    Decline,
    /// The user is tentatively accepting.
    Tentative,
}

impl RsvpStatus {
    /// Wire-format string per NIP-52.
    pub fn as_str(&self) -> &'static str {
        match self {
            RsvpStatus::Accept => "accepted",
            RsvpStatus::Decline => "declined",
            RsvpStatus::Tentative => "tentative",
        }
    }
}

// -- Error type ---------------------------------------------------------------

/// Errors specific to NIP-52 calendar event creation.
#[derive(Debug, Error)]
pub enum CalendarError {
    /// The title is empty.
    #[error("title must not be empty")]
    EmptyTitle,

    /// Start timestamp is zero.
    #[error("start_timestamp must be > 0")]
    InvalidStartTime,

    /// End timestamp is before start timestamp.
    #[error("end_timestamp ({end}) must be >= start_timestamp ({start})")]
    EndBeforeStart { start: u64, end: u64 },

    /// The referenced event ID is not valid 64-character hex.
    #[error("invalid event ID: {0}")]
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

/// Generate a simple UUID-like identifier from random bytes.
fn random_d_tag() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("getrandom for d-tag");
    hex::encode(bytes)
}

// -- Public constructors ------------------------------------------------------

/// Create a time-based calendar event (kind 31923).
///
/// This is a parameterized replaceable event (NIP-33) identified by the `d` tag.
/// A random `d` tag is generated automatically.
///
/// # Tags
/// - `["d", "<random-id>"]` — unique identifier
/// - `["title", "<title>"]` — event title
/// - `["start", "<unix-timestamp>"]` — start time
/// - `["end", "<unix-timestamp>"]` — end time (optional)
/// - `["location", "<location>"]` — location (optional)
/// - `["t", "calendar-event"]` — hashtag for discoverability
///
/// # Arguments
/// * `privkey` - 32-byte secp256k1 secret key
/// * `title` - Event title (required, non-empty)
/// * `start_timestamp` - Unix seconds for the event start
/// * `end_timestamp` - Optional Unix seconds for the event end
/// * `location` - Optional location string
/// * `description` - Optional description (placed in content)
/// * `max_attendees` - Optional maximum number of attendees
pub fn create_calendar_event(
    privkey: &[u8; 32],
    title: &str,
    start_timestamp: u64,
    end_timestamp: Option<u64>,
    location: Option<&str>,
    description: Option<&str>,
    max_attendees: Option<u32>,
) -> Result<NostrEvent, CalendarError> {
    if title.is_empty() {
        return Err(CalendarError::EmptyTitle);
    }
    if start_timestamp == 0 {
        return Err(CalendarError::InvalidStartTime);
    }
    if let Some(end) = end_timestamp {
        if end < start_timestamp {
            return Err(CalendarError::EndBeforeStart {
                start: start_timestamp,
                end,
            });
        }
    }

    let signing_key =
        SigningKey::from_bytes(privkey).map_err(|e| CalendarError::InvalidKey(e.to_string()))?;
    let pubkey = hex::encode(signing_key.verifying_key().to_bytes());

    let d_tag = random_d_tag();
    let mut tags = vec![
        vec!["d".to_string(), d_tag],
        vec!["title".to_string(), title.to_string()],
        vec!["start".to_string(), start_timestamp.to_string()],
    ];

    if let Some(end) = end_timestamp {
        tags.push(vec!["end".to_string(), end.to_string()]);
    }

    if let Some(loc) = location {
        tags.push(vec!["location".to_string(), loc.to_string()]);
    }

    if let Some(max) = max_attendees {
        tags.push(vec!["max_attendees".to_string(), max.to_string()]);
    }

    tags.push(vec!["t".to_string(), "calendar-event".to_string()]);

    let unsigned = UnsignedEvent {
        pubkey,
        created_at: now_secs(),
        kind: KIND_CALENDAR_EVENT,
        tags,
        content: description.unwrap_or("").to_string(),
    };

    sign_event(unsigned, &signing_key).map_err(|e| CalendarError::SigningFailed(e.to_string()))
}

/// Create a calendar RSVP (kind 31925).
///
/// This is a parameterized replaceable event. The `d` tag uses the referenced
/// event ID so that a user's RSVP can be updated by publishing a new event
/// with the same `d` value.
///
/// # Tags
/// - `["d", "<event-id>"]` — the calendar event being responded to
/// - `["e", "<event-id>"]` — reference to the calendar event
/// - `["status", "accepted"|"declined"|"tentative"]` — RSVP status
///
/// # Arguments
/// * `privkey` - 32-byte secp256k1 secret key
/// * `event_id` - 64-character hex ID of the calendar event
/// * `status` - RSVP status (Accept, Decline, Tentative)
pub fn create_rsvp(
    privkey: &[u8; 32],
    event_id: &str,
    status: RsvpStatus,
) -> Result<NostrEvent, CalendarError> {
    if event_id.len() != 64 || hex::decode(event_id).is_err() {
        return Err(CalendarError::InvalidEventId(event_id.to_string()));
    }

    let signing_key =
        SigningKey::from_bytes(privkey).map_err(|e| CalendarError::InvalidKey(e.to_string()))?;
    let pubkey = hex::encode(signing_key.verifying_key().to_bytes());

    let tags = vec![
        vec!["d".to_string(), event_id.to_string()],
        vec!["e".to_string(), event_id.to_string()],
        vec!["status".to_string(), status.as_str().to_string()],
    ];

    let unsigned = UnsignedEvent {
        pubkey,
        created_at: now_secs(),
        kind: KIND_CALENDAR_RSVP,
        tags,
        content: String::new(),
    };

    sign_event(unsigned, &signing_key).map_err(|e| CalendarError::SigningFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::verify_event;

    fn test_key() -> [u8; 32] {
        [0x01u8; 32]
    }

    // -- Calendar event (kind 31923) ------------------------------------------

    #[test]
    fn calendar_event_basic() {
        let event = create_calendar_event(
            &test_key(),
            "Rust Meetup",
            1700000000,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(event.kind, 31923);
        // Should have d, title, start, and t tags
        let tag_names: Vec<&str> = event.tags.iter().map(|t| t[0].as_str()).collect();
        assert!(tag_names.contains(&"d"));
        assert!(tag_names.contains(&"title"));
        assert!(tag_names.contains(&"start"));
        assert!(tag_names.contains(&"t"));
        // Title tag value
        let title_tag = event.tags.iter().find(|t| t[0] == "title").unwrap();
        assert_eq!(title_tag[1], "Rust Meetup");
        // Start tag value
        let start_tag = event.tags.iter().find(|t| t[0] == "start").unwrap();
        assert_eq!(start_tag[1], "1700000000");
        assert!(verify_event(&event));
    }

    #[test]
    fn calendar_event_with_all_options() {
        let event = create_calendar_event(
            &test_key(),
            "Workshop",
            1700000000,
            Some(1700003600),
            Some("London"),
            Some("A great workshop"),
            Some(50),
        )
        .unwrap();

        assert_eq!(event.kind, 31923);
        assert_eq!(event.content, "A great workshop");

        let end_tag = event.tags.iter().find(|t| t[0] == "end").unwrap();
        assert_eq!(end_tag[1], "1700003600");

        let loc_tag = event.tags.iter().find(|t| t[0] == "location").unwrap();
        assert_eq!(loc_tag[1], "London");

        let max_tag = event.tags.iter().find(|t| t[0] == "max_attendees").unwrap();
        assert_eq!(max_tag[1], "50");

        assert!(verify_event(&event));
    }

    #[test]
    fn calendar_event_empty_title_rejected() {
        let result = create_calendar_event(&test_key(), "", 1700000000, None, None, None, None);
        assert!(matches!(result, Err(CalendarError::EmptyTitle)));
    }

    #[test]
    fn calendar_event_zero_start_rejected() {
        let result = create_calendar_event(&test_key(), "Title", 0, None, None, None, None);
        assert!(matches!(result, Err(CalendarError::InvalidStartTime)));
    }

    #[test]
    fn calendar_event_end_before_start_rejected() {
        let result = create_calendar_event(
            &test_key(),
            "Title",
            1700000000,
            Some(1699999999),
            None,
            None,
            None,
        );
        assert!(matches!(result, Err(CalendarError::EndBeforeStart { .. })));
    }

    #[test]
    fn calendar_event_d_tag_is_unique() {
        let e1 = create_calendar_event(&test_key(), "A", 1700000000, None, None, None, None)
            .unwrap();
        let e2 = create_calendar_event(&test_key(), "B", 1700000000, None, None, None, None)
            .unwrap();
        let d1 = &e1.tags.iter().find(|t| t[0] == "d").unwrap()[1];
        let d2 = &e2.tags.iter().find(|t| t[0] == "d").unwrap()[1];
        assert_ne!(d1, d2);
    }

    // -- RSVP (kind 31925) ----------------------------------------------------

    #[test]
    fn rsvp_accept() {
        let event_id = "aa".repeat(32);
        let event = create_rsvp(&test_key(), &event_id, RsvpStatus::Accept).unwrap();

        assert_eq!(event.kind, 31925);
        assert_eq!(event.tags[0], vec!["d", &event_id]);
        assert_eq!(event.tags[1], vec!["e", &event_id]);
        assert_eq!(event.tags[2], vec!["status", "accepted"]);
        assert_eq!(event.content, "");
        assert!(verify_event(&event));
    }

    #[test]
    fn rsvp_decline() {
        let event_id = "bb".repeat(32);
        let event = create_rsvp(&test_key(), &event_id, RsvpStatus::Decline).unwrap();

        let status_tag = event.tags.iter().find(|t| t[0] == "status").unwrap();
        assert_eq!(status_tag[1], "declined");
        assert!(verify_event(&event));
    }

    #[test]
    fn rsvp_tentative() {
        let event_id = "cc".repeat(32);
        let event = create_rsvp(&test_key(), &event_id, RsvpStatus::Tentative).unwrap();

        let status_tag = event.tags.iter().find(|t| t[0] == "status").unwrap();
        assert_eq!(status_tag[1], "tentative");
        assert!(verify_event(&event));
    }

    #[test]
    fn rsvp_invalid_event_id_rejected() {
        let result = create_rsvp(&test_key(), "not-valid-hex", RsvpStatus::Accept);
        assert!(matches!(result, Err(CalendarError::InvalidEventId(_))));
    }

    #[test]
    fn rsvp_short_event_id_rejected() {
        let result = create_rsvp(&test_key(), "aabb", RsvpStatus::Accept);
        assert!(matches!(result, Err(CalendarError::InvalidEventId(_))));
    }

    #[test]
    fn rsvp_d_tag_matches_event_id() {
        let event_id = "dd".repeat(32);
        let event = create_rsvp(&test_key(), &event_id, RsvpStatus::Accept).unwrap();
        let d_tag = event.tags.iter().find(|t| t[0] == "d").unwrap();
        assert_eq!(d_tag[1], event_id);
    }
}
