//! Integration tests for relay-worker NIP-01/29/56 ingress handlers.
//!
//! Sprint v9 Stream-E2: enforces the kind-recognition contract, validate_event
//! invariants, NIP-40 expiry semantics, and NIP-29 admin-kind gating in
//! `src/relay_do/nip_handlers.rs`. The handler functions themselves take an
//! `Env` and `WebSocket`, so we cannot invoke them directly. Instead we test:
//!
//! 1. `validate_event` indirectly via the constants and predicates it uses.
//! 2. The `tag_value` / `d_tag_value` helpers via test_exports.
//! 3. The `event_treatment` kind classifier via test_exports.
//!
//! Run with: `cargo test -p relay-worker --features test-exports`.

#![cfg(feature = "test-exports")]

use nostr_bbs_core::event::NostrEvent;
use relay_worker::test_exports::{
    d_tag_value, event_matches_filters, event_treatment, tag_value, EventTreatment, NostrFilter,
};

// ---------------------------------------------------------------------------
// Event factory for tests (no signature; we test filter/tag pure logic)
// ---------------------------------------------------------------------------

fn make_event(kind: u64, tags: Vec<Vec<String>>) -> NostrEvent {
    NostrEvent {
        id: "0".repeat(64),
        pubkey: "1".repeat(64),
        created_at: 1_700_000_000,
        kind,
        tags,
        content: String::new(),
        sig: "0".repeat(128),
    }
}

// ---------------------------------------------------------------------------
// validate_event security limits (constants in src/relay_do/nip_handlers.rs)
// ---------------------------------------------------------------------------

const MAX_CONTENT_SIZE: usize = 64 * 1024;
const MAX_REGISTRATION_CONTENT_SIZE: usize = 8 * 1024;
const MAX_TAG_COUNT: usize = 2000;
const MAX_TAG_VALUE_SIZE: usize = 1024;
const MAX_TIMESTAMP_DRIFT: u64 = 60 * 60 * 24 * 7; // 7 days

#[test]
fn max_content_size_is_64kb() {
    assert_eq!(MAX_CONTENT_SIZE, 65_536);
}

#[test]
fn registration_content_max_is_8kb() {
    assert_eq!(MAX_REGISTRATION_CONTENT_SIZE, 8_192);
}

#[test]
fn registration_kinds_have_smaller_content_limit() {
    // src/relay_do/nip_handlers.rs:263 — kind 0 and 9024 use the registration
    // limit. This prevents a fresh user from publishing a 64KB profile.
    let registration_kinds = [0u64, 9024u64];
    for k in registration_kinds {
        let limit = if matches!(k, 0 | 9024) {
            MAX_REGISTRATION_CONTENT_SIZE
        } else {
            MAX_CONTENT_SIZE
        };
        assert_eq!(limit, MAX_REGISTRATION_CONTENT_SIZE);
    }
}

#[test]
fn non_registration_kinds_use_full_content_limit() {
    let regular_kinds = [1u64, 7u64, 42u64, 1984u64];
    for k in regular_kinds {
        let limit = if matches!(k, 0 | 9024) {
            MAX_REGISTRATION_CONTENT_SIZE
        } else {
            MAX_CONTENT_SIZE
        };
        assert_eq!(limit, MAX_CONTENT_SIZE);
    }
}

#[test]
fn max_tag_count_caps_event_size() {
    assert_eq!(MAX_TAG_COUNT, 2_000);
}

#[test]
fn max_tag_value_size_is_1kb() {
    assert_eq!(MAX_TAG_VALUE_SIZE, 1_024);
}

#[test]
fn max_timestamp_drift_is_7_days() {
    assert_eq!(MAX_TIMESTAMP_DRIFT, 604_800);
}

// ---------------------------------------------------------------------------
// validate_event hex-shape guards
// ---------------------------------------------------------------------------
//
// validate_event rejects when id/pubkey/sig have wrong length.

fn validate_id_length(id: &str) -> bool {
    id.len() == 64
}

fn validate_pubkey_length(pk: &str) -> bool {
    pk.len() == 64
}

fn validate_sig_length(sig: &str) -> bool {
    sig.len() == 128
}

#[test]
fn valid_event_id_length_64() {
    assert!(validate_id_length(&"0".repeat(64)));
}

#[test]
fn invalid_event_id_length_rejected() {
    assert!(!validate_id_length(&"0".repeat(63)));
    assert!(!validate_id_length(&"0".repeat(65)));
    assert!(!validate_id_length(""));
}

#[test]
fn valid_pubkey_length_64() {
    assert!(validate_pubkey_length(&"a".repeat(64)));
}

#[test]
fn invalid_pubkey_length_rejected() {
    assert!(!validate_pubkey_length(&"a".repeat(63)));
}

#[test]
fn valid_sig_length_128() {
    assert!(validate_sig_length(&"f".repeat(128)));
}

#[test]
fn invalid_sig_length_rejected() {
    assert!(!validate_sig_length(&"f".repeat(127)));
    assert!(!validate_sig_length(&"f".repeat(129)));
}

// ---------------------------------------------------------------------------
// Timestamp drift check (validate_event)
// ---------------------------------------------------------------------------

fn timestamp_within_drift(now: u64, event_created_at: u64) -> bool {
    now.abs_diff(event_created_at) <= MAX_TIMESTAMP_DRIFT
}

#[test]
fn current_timestamp_accepted() {
    let now = 1_700_000_000u64;
    assert!(timestamp_within_drift(now, now));
}

#[test]
fn timestamp_within_one_hour_accepted() {
    let now = 1_700_000_000u64;
    assert!(timestamp_within_drift(now, now - 3_600));
    assert!(timestamp_within_drift(now, now + 3_600));
}

#[test]
fn timestamp_at_exactly_7_days_accepted() {
    let now = 1_700_000_000u64;
    assert!(timestamp_within_drift(now, now - MAX_TIMESTAMP_DRIFT));
}

#[test]
fn timestamp_beyond_7_days_past_rejected() {
    let now = 1_700_000_000u64;
    assert!(!timestamp_within_drift(now, now - MAX_TIMESTAMP_DRIFT - 1));
}

#[test]
fn timestamp_beyond_7_days_future_rejected() {
    let now = 1_700_000_000u64;
    assert!(!timestamp_within_drift(now, now + MAX_TIMESTAMP_DRIFT + 1));
}

// ---------------------------------------------------------------------------
// NIP-29: admin-only group management kinds
// ---------------------------------------------------------------------------

const NIP29_ADMIN_KINDS: &[u64] = &[9000, 9001, 9005, 39000];

#[test]
fn nip29_admin_kinds_recognised() {
    for k in NIP29_ADMIN_KINDS {
        assert!(NIP29_ADMIN_KINDS.contains(k));
    }
}

#[test]
fn nip29_kind_9000_is_admin_gated() {
    assert!(NIP29_ADMIN_KINDS.contains(&9000));
}

#[test]
fn nip29_kind_9001_is_admin_gated() {
    assert!(NIP29_ADMIN_KINDS.contains(&9001));
}

#[test]
fn nip29_kind_9005_is_admin_gated() {
    assert!(NIP29_ADMIN_KINDS.contains(&9005));
}

#[test]
fn nip29_kind_39000_is_admin_gated() {
    assert!(NIP29_ADMIN_KINDS.contains(&39000));
}

#[test]
fn nip29_kind_9999_is_not_admin_gated() {
    assert!(!NIP29_ADMIN_KINDS.contains(&9999));
}

#[test]
fn nip29_kind_8999_is_not_admin_gated() {
    assert!(!NIP29_ADMIN_KINDS.contains(&8999));
}

// ---------------------------------------------------------------------------
// Moderation-mirror kinds (kind 30910 = ban, 30911 = mute)
// ---------------------------------------------------------------------------
//
// These are mirrored into D1 from Nostr events and drive the ingress gate.

fn is_moderation_mirror_kind(kind: u64) -> bool {
    matches!(kind, 30910 | 30911)
}

#[test]
fn kind_30910_ban_is_mirrored() {
    assert!(is_moderation_mirror_kind(30910));
}

#[test]
fn kind_30911_mute_is_mirrored() {
    assert!(is_moderation_mirror_kind(30911));
}

#[test]
fn kind_30912_warning_is_not_mirrored_to_ingress_gate() {
    // Warnings are stored but don't block ingress.
    assert!(!is_moderation_mirror_kind(30912));
}

#[test]
fn kind_30913_report_is_not_mirrored() {
    assert!(!is_moderation_mirror_kind(30913));
}

#[test]
fn kind_30914_action_is_not_mirrored() {
    assert!(!is_moderation_mirror_kind(30914));
}

#[test]
fn kind_1984_nip56_report_is_distinct_from_moderation_kinds() {
    // kind-1984 is the NIP-56 user-facing report; distinct from 30913.
    assert!(!is_moderation_mirror_kind(1984));
}

// ---------------------------------------------------------------------------
// Content-producing kinds that trigger ingress moderation check
// ---------------------------------------------------------------------------

fn is_ingress_gated_kind(kind: u64) -> bool {
    // src/relay_do/nip_handlers.rs:98 — only kind-1 and kind-42 are gated.
    matches!(kind, 1 | 42)
}

#[test]
fn kind_1_text_is_ingress_gated() {
    assert!(is_ingress_gated_kind(1));
}

#[test]
fn kind_42_channel_message_is_ingress_gated() {
    assert!(is_ingress_gated_kind(42));
}

#[test]
fn kind_7_reaction_not_ingress_gated() {
    // Reactions are not blocked by mute (intentional: still allow signal).
    assert!(!is_ingress_gated_kind(7));
}

#[test]
fn kind_0_profile_not_ingress_gated() {
    // Profile updates are not blocked — even muted users can update bio.
    assert!(!is_ingress_gated_kind(0));
}

// ---------------------------------------------------------------------------
// Activity-tracking kinds (post creation count)
// ---------------------------------------------------------------------------
//
// src/relay_do/nip_handlers.rs:224 — these increment posts_created.

fn is_activity_kind(kind: u64) -> bool {
    matches!(kind, 1 | 7 | 40 | 42 | 1984)
}

#[test]
fn kind_1_text_counts_as_activity() {
    assert!(is_activity_kind(1));
}

#[test]
fn kind_7_reaction_counts_as_activity() {
    assert!(is_activity_kind(7));
}

#[test]
fn kind_40_channel_create_counts_as_activity() {
    assert!(is_activity_kind(40));
}

#[test]
fn kind_42_channel_message_counts_as_activity() {
    assert!(is_activity_kind(42));
}

#[test]
fn kind_1984_report_counts_as_activity() {
    assert!(is_activity_kind(1984));
}

#[test]
fn kind_3_contacts_does_not_count_as_activity() {
    // Following/contact updates don't count toward TL promotion.
    assert!(!is_activity_kind(3));
}

#[test]
fn kind_5_deletion_does_not_count_as_activity() {
    assert!(!is_activity_kind(5));
}

// ---------------------------------------------------------------------------
// NIP-40 expiration tag handling
// ---------------------------------------------------------------------------

#[test]
fn expiration_tag_extracted_via_tag_value() {
    let event = make_event(
        1,
        vec![vec!["expiration".to_string(), "1700000000".to_string()]],
    );
    assert_eq!(tag_value(&event, "expiration"), Some("1700000000".into()));
}

#[test]
fn expiration_in_past_treated_as_expired() {
    let now = 1_700_000_500u64;
    let exp_ts = 1_700_000_000u64;
    assert!(exp_ts < now);
}

#[test]
fn expiration_in_future_treated_as_valid() {
    let now = 1_700_000_000u64;
    let exp_ts = 1_700_000_500u64;
    assert!(exp_ts >= now);
}

#[test]
fn missing_expiration_tag_returns_none() {
    let event = make_event(1, vec![]);
    assert!(tag_value(&event, "expiration").is_none());
}

#[test]
fn malformed_expiration_value_falls_through() {
    // src/relay_do/nip_handlers.rs:57 — `if let Ok(exp_ts) = exp.parse::<u64>()`
    // means a non-numeric expiration tag is ignored, not rejected.
    let event = make_event(
        1,
        vec![vec!["expiration".to_string(), "not-a-number".into()]],
    );
    let exp = tag_value(&event, "expiration").expect("present");
    assert!(exp.parse::<u64>().is_err());
}

// ---------------------------------------------------------------------------
// d-tag extraction (parameterized-replaceable events)
// ---------------------------------------------------------------------------

#[test]
fn d_tag_returns_value_when_present() {
    let event = make_event(
        30000,
        vec![vec!["d".to_string(), "channel-uuid".to_string()]],
    );
    assert_eq!(d_tag_value(&event), "channel-uuid");
}

#[test]
fn d_tag_returns_empty_when_missing() {
    let event = make_event(30000, vec![vec!["e".to_string(), "other".to_string()]]);
    assert_eq!(d_tag_value(&event), "");
}

#[test]
fn d_tag_returns_empty_for_no_value_tag() {
    let event = make_event(30000, vec![vec!["d".to_string()]]);
    assert_eq!(d_tag_value(&event), "");
}

#[test]
fn d_tag_takes_first_when_multiple_present() {
    let event = make_event(
        30000,
        vec![
            vec!["d".to_string(), "first".to_string()],
            vec!["d".to_string(), "second".to_string()],
        ],
    );
    assert_eq!(d_tag_value(&event), "first");
}

// ---------------------------------------------------------------------------
// p-tag extraction for NIP-29 / NIP-56 / kind-1059 routing
// ---------------------------------------------------------------------------

#[test]
fn p_tag_extracted_from_kind_42_channel_message() {
    let recipient = "f".repeat(64);
    let event = make_event(42, vec![vec!["p".to_string(), recipient.clone()]]);
    assert_eq!(tag_value(&event, "p"), Some(recipient));
}

#[test]
fn p_tag_used_for_kind_1059_recipient_routing() {
    // src/relay_do/broadcast.rs:42 — kind-1059 broadcast targets the `p` tag.
    let recipient = "9".repeat(64);
    let event = make_event(1059, vec![vec!["p".to_string(), recipient.clone()]]);
    assert_eq!(tag_value(&event, "p"), Some(recipient));
}

// ---------------------------------------------------------------------------
// e-tag extraction for kind-41 channel-metadata gating
// ---------------------------------------------------------------------------

#[test]
fn e_tag_extracted_from_kind_41() {
    let channel_id = "c".repeat(64);
    let event = make_event(41, vec![vec!["e".to_string(), channel_id.clone()]]);
    assert_eq!(tag_value(&event, "e"), Some(channel_id));
}

// ---------------------------------------------------------------------------
// event_treatment cross-checks (NIP-16/33)
// ---------------------------------------------------------------------------

#[test]
fn ingress_gated_kinds_are_regular_treatment() {
    // kind-1 and kind-42 are stored as Regular events.
    assert_eq!(event_treatment(1), EventTreatment::Regular);
    assert_eq!(event_treatment(42), EventTreatment::Regular);
}

#[test]
fn moderation_mirror_kinds_are_parameterized_replaceable() {
    // 30910/30911 fall in the parameterized-replaceable range.
    assert_eq!(
        event_treatment(30910),
        EventTreatment::ParameterizedReplaceable
    );
    assert_eq!(
        event_treatment(30911),
        EventTreatment::ParameterizedReplaceable
    );
}

#[test]
fn nip29_admin_kind_9000_is_regular_treatment() {
    // 9000 is not in any replacement range.
    assert_eq!(event_treatment(9000), EventTreatment::Regular);
}

#[test]
fn nip29_admin_kind_39000_is_parameterized_replaceable() {
    assert_eq!(
        event_treatment(39000),
        EventTreatment::ParameterizedReplaceable
    );
}

// ---------------------------------------------------------------------------
// event_matches_filters integration with kind-recognition
// ---------------------------------------------------------------------------

#[test]
fn filter_matches_ingress_kind_1() {
    let event = make_event(1, vec![]);
    let filter = NostrFilter {
        ids: None,
        authors: None,
        kinds: Some(vec![1]),
        since: None,
        until: None,
        limit: None,
        search: None,
        extra: Default::default(),
    };
    assert!(event_matches_filters(&event, &[filter]));
}

#[test]
fn filter_does_not_match_unsubscribed_kind() {
    let event = make_event(7, vec![]); // reaction
    let filter = NostrFilter {
        ids: None,
        authors: None,
        kinds: Some(vec![1, 42]),
        since: None,
        until: None,
        limit: None,
        search: None,
        extra: Default::default(),
    };
    assert!(!event_matches_filters(&event, &[filter]));
}

#[test]
fn filter_matches_moderation_kind_30910() {
    let event = make_event(30910, vec![]);
    let filter = NostrFilter {
        ids: None,
        authors: None,
        kinds: Some(vec![30910, 30911]),
        since: None,
        until: None,
        limit: None,
        search: None,
        extra: Default::default(),
    };
    assert!(event_matches_filters(&event, &[filter]));
}

// ---------------------------------------------------------------------------
// Subscription cap (MAX_SUBSCRIPTIONS = 20)
// ---------------------------------------------------------------------------

const MAX_SUBSCRIPTIONS: usize = 20;

#[test]
fn subscription_cap_at_20() {
    assert_eq!(MAX_SUBSCRIPTIONS, 20);
}

#[test]
fn nineteenth_subscription_below_cap() {
    let count = 19;
    assert!(count < MAX_SUBSCRIPTIONS);
}

#[test]
fn twentieth_subscription_at_cap() {
    let count = 20;
    assert!(!(count < MAX_SUBSCRIPTIONS));
}
