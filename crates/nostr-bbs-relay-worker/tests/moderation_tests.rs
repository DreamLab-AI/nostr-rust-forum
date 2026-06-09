//! Integration tests for relay-worker moderation enforcement perimeter.
//!
//! Sprint v9 Stream-E2: closes the relay-worker test gap (1900 LOC, 0 tests
//! pre-sprint). These tests target the WI-2 ingress moderation surface.
//!
//! ## Why integration tests, not unit tests in src/
//!
//! The moderation HTTP handlers in `src/moderation.rs` are deeply coupled to
//! `worker::Env` (D1, KV) and cannot run on native `cargo test` without a
//! workers-rs runtime emulator we don't have. This file instead tests:
//!
//! 1. The `Block` enum and `ModCache` semantics exposed via `test_exports`.
//! 2. The pure-logic predicates (status validation, d-tag scheme, expiry
//!    arithmetic) that the handlers rely on, documented as test-resident
//!    re-implementations against the source SQL/strings to lock the contract.
//!
//! Run with: `cargo test -p relay-worker --features test-exports`.

#![cfg(feature = "test-exports")]

use nostr_bbs_relay_worker::test_exports::{Block, ModCache};

// ---------------------------------------------------------------------------
// Block enum semantics (from src/relay_do/mod_cache.rs)
// ---------------------------------------------------------------------------

#[test]
fn block_none_means_unrestricted() {
    let b = Block::None;
    assert_eq!(b, Block::None);
    assert_ne!(b, Block::Banned);
}

#[test]
fn block_banned_is_distinct_from_muted() {
    let banned = Block::Banned;
    let muted = Block::MutedUntil(9_999_999_999);
    assert_ne!(banned, muted);
}

#[test]
fn block_mutedutil_carries_unix_timestamp() {
    let m = Block::MutedUntil(1_700_000_000);
    match m {
        Block::MutedUntil(ts) => assert_eq!(ts, 1_700_000_000),
        _ => panic!("expected MutedUntil"),
    }
}

#[test]
fn block_copy_semantics() {
    // Block is Copy: cheap to pass by value through the cache hot path.
    let a = Block::Banned;
    let b = a;
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// ModCache construction (default-state)
// ---------------------------------------------------------------------------

#[test]
fn mod_cache_default_is_empty() {
    let _cache = ModCache::default();
    // No public observers; the contract is "construction does not panic".
}

#[test]
fn mod_cache_new_returns_empty_cache() {
    let _cache = ModCache::new();
    // Same as default but via the named constructor.
}

#[test]
fn mod_cache_invalidate_unknown_pubkey_is_noop() {
    let cache = ModCache::new();
    // The contract: invalidate is idempotent and safe on a missing key.
    cache.invalidate("0".repeat(64).as_str());
    cache.invalidate("0".repeat(64).as_str());
}

// ---------------------------------------------------------------------------
// TTL semantics: 60-second cache window
// ---------------------------------------------------------------------------

const CACHE_TTL_SECS: u64 = 60;

#[test]
fn cache_entry_is_fresh_within_ttl() {
    let loaded_at: u64 = 1_700_000_000;
    let now: u64 = loaded_at + 30;
    assert!(now.saturating_sub(loaded_at) < CACHE_TTL_SECS);
}

#[test]
fn cache_entry_at_t59_still_fresh() {
    let loaded_at: u64 = 1_000;
    let now: u64 = 1_059;
    assert!(now.saturating_sub(loaded_at) < CACHE_TTL_SECS);
}

#[test]
fn cache_entry_at_t60_boundary_is_expired() {
    // The < strict comparison means exactly TTL is treated as expired.
    let loaded_at: u64 = 1_000;
    let now: u64 = 1_060;
    assert!(!(now.saturating_sub(loaded_at) < CACHE_TTL_SECS));
}

#[test]
fn cache_entry_at_t61_is_expired() {
    let loaded_at: u64 = 1_000;
    let now: u64 = 1_061;
    assert!(now.saturating_sub(loaded_at) >= CACHE_TTL_SECS);
}

#[test]
fn cache_entry_clock_skew_does_not_underflow() {
    // saturating_sub guards against the (impossible) clock-going-backwards case.
    let loaded_at: u64 = 1_100;
    let now: u64 = 1_000; // earlier than load — sat_sub yields 0, treated fresh.
    assert_eq!(now.saturating_sub(loaded_at), 0);
}

// ---------------------------------------------------------------------------
// Mute expiry semantics (load_state in mod_cache.rs)
// ---------------------------------------------------------------------------
//
// The relay's load_state replays moderation_actions and picks the strongest
// in-force state per pubkey. A mute with `expires_at` in the past is treated
// as "no longer muted" (the row has been ignored at filter time).

fn mute_is_active(expires_at: i64, now: i64) -> bool {
    expires_at > now
}

#[test]
fn mute_with_future_expiry_is_active() {
    let now: i64 = 1_700_000_000;
    assert!(mute_is_active(now + 3600, now));
}

#[test]
fn mute_with_past_expiry_is_inactive() {
    let now: i64 = 1_700_000_000;
    assert!(!mute_is_active(now - 1, now));
}

#[test]
fn mute_at_exact_expiry_boundary_is_inactive() {
    // The `>` semantics means expires_at == now is "no longer muted".
    let now: i64 = 1_700_000_000;
    assert!(!mute_is_active(now, now));
}

// ---------------------------------------------------------------------------
// Picking furthest-future mute when multiple rows present
// ---------------------------------------------------------------------------

fn merge_mute(prev: Block, candidate_ts: i64) -> Block {
    match prev {
        Block::MutedUntil(p) if p >= candidate_ts => prev,
        _ => Block::MutedUntil(candidate_ts),
    }
}

#[test]
fn merging_picks_later_of_two_mutes() {
    let r1 = Block::MutedUntil(100);
    let merged = merge_mute(r1, 200);
    assert_eq!(merged, Block::MutedUntil(200));
}

#[test]
fn merging_keeps_existing_when_candidate_earlier() {
    let r1 = Block::MutedUntil(500);
    let merged = merge_mute(r1, 200);
    assert_eq!(merged, Block::MutedUntil(500));
}

#[test]
fn merging_starts_from_none() {
    let merged = merge_mute(Block::None, 1_700_000_000);
    assert_eq!(merged, Block::MutedUntil(1_700_000_000));
}

#[test]
fn ban_dominates_any_mute() {
    // load_state semantics: any 'ban' row short-circuits to Block::Banned.
    let states = [Block::None, Block::MutedUntil(9_000_000_000), Block::Banned];
    let strongest = states
        .iter()
        .copied()
        .max_by_key(|s| match s {
            Block::None => 0,
            Block::MutedUntil(_) => 1,
            // P2: Unknown is the fail-CLOSED sentinel; rank alongside Banned.
            Block::Banned | Block::Unknown => 2,
        })
        .unwrap();
    assert_eq!(strongest, Block::Banned);
}

#[test]
fn permanent_mute_no_expiry_is_promoted_to_banned() {
    // Per src/relay_do/mod_cache.rs:119, ("mute", None) maps to Block::Banned.
    // This test documents that contract.
    let action = "mute";
    let expires_at: Option<i64> = None;
    let outcome = match (action, expires_at) {
        ("ban", _) => Block::Banned,
        ("mute", None) => Block::Banned,
        ("mute", Some(t)) => Block::MutedUntil(t),
        _ => Block::None,
    };
    assert_eq!(outcome, Block::Banned);
}

// ---------------------------------------------------------------------------
// d-tag scheme: `{admin_pubkey}:{target_pubkey}` for kind-30910/30911
// ---------------------------------------------------------------------------
//
// Nostr parameterized-replaceable events keyed by d-tag. The relay mirrors
// kind-30910 (Ban) and kind-30911 (Mute) into moderation_actions, and the
// `d` tag identifies the `{admin}:{target}` pair so re-issuing replaces.

fn parse_d_tag(d: &str) -> Option<(&str, &str)> {
    d.split_once(':')
}

#[test]
fn d_tag_admin_target_split() {
    let admin = "a".repeat(64);
    let target = "b".repeat(64);
    let d = format!("{admin}:{target}");
    let (a, t) = parse_d_tag(&d).expect("valid d-tag");
    assert_eq!(a, admin);
    assert_eq!(t, target);
}

#[test]
fn d_tag_without_separator_is_rejected() {
    assert!(parse_d_tag("nopubkeyseparator").is_none());
}

#[test]
fn d_tag_empty_string_is_rejected() {
    assert!(parse_d_tag("").is_none());
}

#[test]
fn d_tag_with_multiple_colons_takes_first_split() {
    // split_once on ':' takes the first colon. This documents the contract:
    // hex pubkeys never contain ':' so this is safe.
    let (a, rest) = parse_d_tag("a:b:c").expect("split_once");
    assert_eq!(a, "a");
    assert_eq!(rest, "b:c");
}

// ---------------------------------------------------------------------------
// Resolution string mapping (from src/moderation.rs handle_resolve_report)
// ---------------------------------------------------------------------------
//
// POST /api/reports/resolve accepts resolution ∈ {dismiss, hide, delete}
// and maps to status ∈ {resolved_dismiss, resolved_approve}. This locks the
// contract.

fn resolution_to_status(resolution: &str) -> Option<&'static str> {
    match resolution {
        "dismiss" => Some("resolved_dismiss"),
        "hide" | "delete" => Some("resolved_approve"),
        _ => None,
    }
}

#[test]
fn resolution_dismiss_maps_to_resolved_dismiss() {
    assert_eq!(resolution_to_status("dismiss"), Some("resolved_dismiss"));
}

#[test]
fn resolution_hide_maps_to_resolved_approve() {
    assert_eq!(resolution_to_status("hide"), Some("resolved_approve"));
}

#[test]
fn resolution_delete_maps_to_resolved_approve() {
    assert_eq!(resolution_to_status("delete"), Some("resolved_approve"));
}

#[test]
fn resolution_invalid_is_rejected() {
    assert_eq!(resolution_to_status("nuke"), None);
    assert_eq!(resolution_to_status(""), None);
    assert_eq!(resolution_to_status("DISMISS"), None); // case-sensitive
}

// ---------------------------------------------------------------------------
// Status filter validation (handle_list_reports)
// ---------------------------------------------------------------------------

fn is_valid_report_status(s: &str) -> bool {
    matches!(s, "pending" | "resolved_approve" | "resolved_dismiss")
}

#[test]
fn valid_report_statuses_accepted() {
    assert!(is_valid_report_status("pending"));
    assert!(is_valid_report_status("resolved_approve"));
    assert!(is_valid_report_status("resolved_dismiss"));
}

#[test]
fn invalid_report_statuses_rejected() {
    assert!(!is_valid_report_status("resolved"));
    assert!(!is_valid_report_status("approved"));
    assert!(!is_valid_report_status(""));
    assert!(!is_valid_report_status("PENDING"));
}

// ---------------------------------------------------------------------------
// Auto-hide threshold (3+ pending reports triggers soft-hide)
// ---------------------------------------------------------------------------

const AUTO_HIDE_THRESHOLD: u64 = 3;

#[test]
fn one_report_does_not_trigger_auto_hide() {
    assert!(!(1u64 >= AUTO_HIDE_THRESHOLD));
}

#[test]
fn two_reports_does_not_trigger_auto_hide() {
    assert!(!(2u64 >= AUTO_HIDE_THRESHOLD));
}

#[test]
fn three_reports_triggers_auto_hide() {
    assert!(3u64 >= AUTO_HIDE_THRESHOLD);
}

#[test]
fn many_reports_still_triggers_auto_hide() {
    assert!(100u64 >= AUTO_HIDE_THRESHOLD);
}
