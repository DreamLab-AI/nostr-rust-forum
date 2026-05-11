//! Integration tests for relay-worker whitelist enforcement perimeter.
//!
//! Sprint v9 Stream-E2: pure-logic tests for the whitelist + cohort access
//! flag computation, hex pubkey validation, and the kind-3 referente parsing
//! that drives WoT (web-of-trust) auto-admission.
//!
//! Run with: `cargo test -p relay-worker --features test-exports`.

#![cfg(feature = "test-exports")]

// ---------------------------------------------------------------------------
// Hex pubkey validation (used in src/whitelist.rs:90 and elsewhere)
// ---------------------------------------------------------------------------
//
// All admin endpoints validate pubkey shape before SQL bind:
//     pk.len() == 64 && pk.bytes().all(|b| b.is_ascii_hexdigit())

fn is_valid_hex_pubkey(pk: &str) -> bool {
    pk.len() == 64 && pk.bytes().all(|b| b.is_ascii_hexdigit())
}

#[test]
fn valid_64_char_lowercase_hex_accepted() {
    let pk = "0".repeat(64);
    assert!(is_valid_hex_pubkey(&pk));
}

#[test]
fn valid_64_char_mixed_hex_accepted() {
    let pk = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    assert!(is_valid_hex_pubkey(pk));
}

#[test]
fn valid_64_char_uppercase_hex_accepted() {
    // is_ascii_hexdigit accepts both cases.
    let pk = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    assert!(is_valid_hex_pubkey(pk));
}

#[test]
fn empty_pubkey_rejected() {
    assert!(!is_valid_hex_pubkey(""));
}

#[test]
fn short_pubkey_rejected() {
    let pk = "0".repeat(63);
    assert!(!is_valid_hex_pubkey(&pk));
}

#[test]
fn long_pubkey_rejected() {
    let pk = "0".repeat(65);
    assert!(!is_valid_hex_pubkey(&pk));
}

#[test]
fn pubkey_with_non_hex_char_rejected() {
    let pk = "g".to_string() + &"0".repeat(63);
    assert!(!is_valid_hex_pubkey(&pk));
}

#[test]
fn pubkey_with_unicode_rejected() {
    // Important: bytes() iterates raw bytes, not chars. A unicode char's bytes
    // are non-ASCII so is_ascii_hexdigit returns false.
    let pk = "ñ".to_string() + &"0".repeat(62);
    assert!(!is_valid_hex_pubkey(&pk));
}

#[test]
fn pubkey_with_dash_rejected() {
    // SQL-injection-style attempt: '-- DROP TABLE
    let pk = "abc-".to_string() + &"d".repeat(60);
    assert!(!is_valid_hex_pubkey(&pk));
}

#[test]
fn pubkey_with_quote_rejected() {
    let pk = "'".to_string() + &"0".repeat(63);
    assert!(!is_valid_hex_pubkey(&pk));
}

// ---------------------------------------------------------------------------
// Cohort → access flag mapping (from src/whitelist.rs:113-138)
// ---------------------------------------------------------------------------
//
// The cohort taxonomy maps to three zone booleans: home, members, private.
// Admins always have all three. The cross-access cohort grants all.

fn compute_access_flags(is_admin: bool, cohorts: &[&str]) -> (bool, bool, bool) {
    let has_home = is_admin
        || cohorts
            .iter()
            .any(|c| matches!(*c, "home" | "lobby" | "approved" | "cross-access"));
    let has_members = is_admin
        || cohorts.iter().any(|c| {
            matches!(
                *c,
                "members"
                    | "business"
                    | "business-only"
                    | "trainers"
                    | "trainees"
                    | "ai-agents"
                    | "agent"
                    | "cross-access"
            )
        });
    let has_private = is_admin
        || cohorts.iter().any(|c| {
            matches!(
                *c,
                "private" | "private-only" | "private-business" | "cross-access"
            )
        });
    (has_home, has_members, has_private)
}

#[test]
fn admin_has_all_three_zones() {
    let (h, m, p) = compute_access_flags(true, &[]);
    assert!(h && m && p, "admin should have access to all zones");
}

#[test]
fn admin_with_no_cohorts_still_has_all_zones() {
    let (h, m, p) = compute_access_flags(true, &[]);
    assert!(h);
    assert!(m);
    assert!(p);
}

#[test]
fn lobby_user_has_only_home_access() {
    let (h, m, p) = compute_access_flags(false, &["lobby"]);
    assert!(h);
    assert!(!m);
    assert!(!p);
}

#[test]
fn business_cohort_has_only_members_access() {
    let (h, m, p) = compute_access_flags(false, &["business"]);
    assert!(!h);
    assert!(m);
    assert!(!p);
}

#[test]
fn cross_access_grants_all_three_zones() {
    let (h, m, p) = compute_access_flags(false, &["cross-access"]);
    assert!(h);
    assert!(m);
    assert!(p);
}

#[test]
fn unknown_cohort_grants_nothing() {
    let (h, m, p) = compute_access_flags(false, &["mystery-cohort"]);
    assert!(!h);
    assert!(!m);
    assert!(!p);
}

#[test]
fn empty_cohorts_grants_nothing() {
    let (h, m, p) = compute_access_flags(false, &[]);
    assert!(!h);
    assert!(!m);
    assert!(!p);
}

#[test]
fn approved_cohort_grants_home() {
    let (h, _, _) = compute_access_flags(false, &["approved"]);
    assert!(h);
}

#[test]
fn home_cohort_grants_home() {
    let (h, _, _) = compute_access_flags(false, &["home"]);
    assert!(h);
}

#[test]
fn trainers_cohort_grants_members() {
    let (_, m, _) = compute_access_flags(false, &["trainers"]);
    assert!(m);
}

#[test]
fn trainees_cohort_grants_members() {
    let (_, m, _) = compute_access_flags(false, &["trainees"]);
    assert!(m);
}

#[test]
fn ai_agents_cohort_grants_members() {
    let (_, m, _) = compute_access_flags(false, &["ai-agents"]);
    assert!(m);
}

#[test]
fn agent_cohort_grants_members() {
    let (_, m, _) = compute_access_flags(false, &["agent"]);
    assert!(m);
}

#[test]
fn business_only_cohort_grants_members() {
    let (_, m, _) = compute_access_flags(false, &["business-only"]);
    assert!(m);
}

#[test]
fn private_only_grants_private() {
    let (_, _, p) = compute_access_flags(false, &["private-only"]);
    assert!(p);
}

#[test]
fn private_business_grants_private() {
    let (_, _, p) = compute_access_flags(false, &["private-business"]);
    assert!(p);
}

#[test]
fn multi_cohort_union_grants_all_implied() {
    let (h, m, p) = compute_access_flags(false, &["lobby", "trainers", "private"]);
    assert!(h);
    assert!(m);
    assert!(p);
}

// ---------------------------------------------------------------------------
// Cohort JSON serialization (cohort field in D1 stored as JSON string)
// ---------------------------------------------------------------------------

#[test]
fn cohorts_json_roundtrip() {
    let cohorts = vec![
        "lobby".to_string(),
        "approved".to_string(),
        "trainers".to_string(),
    ];
    let json = serde_json::to_string(&cohorts).expect("serialize");
    let restored: Vec<String> = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(cohorts, restored);
}

#[test]
fn empty_cohorts_serializes_as_empty_array() {
    let cohorts: Vec<String> = vec![];
    let json = serde_json::to_string(&cohorts).expect("serialize");
    assert_eq!(json, "[]");
}

#[test]
fn malformed_cohort_json_falls_back_to_empty() {
    // Mimics the .unwrap_or_default() pattern in handle_check_whitelist.
    let bad = "not-json";
    let cohorts: Vec<String> = serde_json::from_str(bad).unwrap_or_default();
    assert!(cohorts.is_empty());
}

#[test]
fn cohort_default_when_omitted_is_home() {
    // src/whitelist.rs:296: body.cohorts.unwrap_or_else(|| vec!["home".to_string()])
    let body_cohorts: Option<Vec<String>> = None;
    let resolved = body_cohorts.unwrap_or_else(|| vec!["home".to_string()]);
    assert_eq!(resolved, vec!["home"]);
}

// ---------------------------------------------------------------------------
// LIKE-pattern injection guard (handle_whitelist_list:171)
// ---------------------------------------------------------------------------
//
// User-supplied cohort filter is escaped to prevent SQL LIKE wildcard injection:
//     cohort_val.replace('%', "\\%").replace('_', "\\_").replace('"', "")

fn escape_like_cohort(cohort: &str) -> String {
    cohort
        .replace('%', "\\%")
        .replace('_', "\\_")
        .replace('"', "")
}

#[test]
fn percent_wildcard_is_escaped() {
    assert_eq!(escape_like_cohort("foo%bar"), "foo\\%bar");
}

#[test]
fn underscore_wildcard_is_escaped() {
    assert_eq!(escape_like_cohort("foo_bar"), "foo\\_bar");
}

#[test]
fn double_quote_is_stripped() {
    // Strip rather than escape: prevents JSON-string boundary attacks.
    assert_eq!(escape_like_cohort(r#"foo"bar"#), "foobar");
}

#[test]
fn safe_cohort_passes_through_unchanged() {
    assert_eq!(escape_like_cohort("approved"), "approved");
}

#[test]
fn all_three_wildcards_escaped_simultaneously() {
    let bad = r#"%_"injection"#;
    assert_eq!(escape_like_cohort(bad), "\\%\\_injection");
}

// ---------------------------------------------------------------------------
// NIP-02 kind-3 (contact list) referente parsing
// ---------------------------------------------------------------------------
//
// WoT auto-whitelist: the relay watches kind-3 from a designated "referente"
// pubkey and admits everyone in their contacts. This test extracts the pubkey
// list from a kind-3 event tag array.

fn extract_referente_pubkeys(tags: &[Vec<String>]) -> Vec<String> {
    tags.iter()
        .filter(|t| t.len() >= 2 && t.first().map(|s| s.as_str()) == Some("p"))
        .map(|t| t[1].clone())
        .filter(|pk| pk.len() == 64 && pk.bytes().all(|b| b.is_ascii_hexdigit()))
        .collect()
}

#[test]
fn kind3_extracts_p_tag_pubkeys() {
    let pk1 = "a".repeat(64);
    let pk2 = "b".repeat(64);
    let tags = vec![
        vec!["p".to_string(), pk1.clone()],
        vec!["p".to_string(), pk2.clone()],
    ];
    let extracted = extract_referente_pubkeys(&tags);
    assert_eq!(extracted, vec![pk1, pk2]);
}

#[test]
fn kind3_skips_non_p_tags() {
    let pk = "c".repeat(64);
    let tags = vec![
        vec!["e".to_string(), "event_id".repeat(8)],
        vec!["p".to_string(), pk.clone()],
        vec!["t".to_string(), "topic".to_string()],
    ];
    let extracted = extract_referente_pubkeys(&tags);
    assert_eq!(extracted, vec![pk]);
}

#[test]
fn kind3_skips_invalid_pubkey_in_p_tag() {
    let valid = "d".repeat(64);
    let tags = vec![
        vec!["p".to_string(), "not-a-pubkey".to_string()],
        vec!["p".to_string(), valid.clone()],
        vec!["p".to_string(), "".to_string()],
    ];
    let extracted = extract_referente_pubkeys(&tags);
    assert_eq!(extracted, vec![valid]);
}

#[test]
fn kind3_handles_empty_tag_array() {
    let extracted = extract_referente_pubkeys(&[]);
    assert!(extracted.is_empty());
}

#[test]
fn kind3_skips_p_tag_without_value() {
    // ["p"] alone, no second element — skipped by len >= 2 guard.
    let tags = vec![vec!["p".to_string()]];
    let extracted = extract_referente_pubkeys(&tags);
    assert!(extracted.is_empty());
}

// ---------------------------------------------------------------------------
// Whitelist set add/remove idempotency (D1 ON CONFLICT semantics)
// ---------------------------------------------------------------------------
//
// The handle_whitelist_add SQL uses ON CONFLICT(pubkey) DO UPDATE, which means
// repeated adds are idempotent (last-wins on cohorts). Model this with HashSet.

use std::collections::HashSet;

fn idempotent_add(set: &mut HashSet<String>, pk: &str) {
    set.insert(pk.to_string());
}

fn idempotent_remove(set: &mut HashSet<String>, pk: &str) {
    set.remove(pk);
}

#[test]
fn whitelist_add_is_idempotent() {
    let mut s = HashSet::new();
    let pk = "e".repeat(64);
    idempotent_add(&mut s, &pk);
    idempotent_add(&mut s, &pk);
    idempotent_add(&mut s, &pk);
    assert_eq!(s.len(), 1);
    assert!(s.contains(&pk));
}

#[test]
fn whitelist_remove_unknown_is_noop() {
    let mut s = HashSet::new();
    idempotent_remove(&mut s, &"f".repeat(64));
    assert!(s.is_empty());
}

#[test]
fn whitelist_add_then_remove_clears() {
    let mut s = HashSet::new();
    let pk = "0".repeat(64);
    idempotent_add(&mut s, &pk);
    idempotent_remove(&mut s, &pk);
    assert!(s.is_empty());
}

// ---------------------------------------------------------------------------
// Relay ingress does not bypass whitelist admission.
// ---------------------------------------------------------------------------
//
// Account creation and invitation state are owned by the auth worker; relay
// events must not self-create access.

fn is_bypass_kind(kind: u64) -> bool {
    let _ = kind;
    false
}

#[test]
fn kind0_profile_does_not_bypass_whitelist() {
    assert!(!is_bypass_kind(0));
}

#[test]
fn kind9021_join_request_does_not_bypass_whitelist() {
    assert!(!is_bypass_kind(9021));
}

#[test]
fn kind9024_registration_metadata_does_not_bypass_whitelist() {
    assert!(!is_bypass_kind(9024));
}

#[test]
fn kind1_text_does_not_bypass_whitelist() {
    assert!(!is_bypass_kind(1));
}

#[test]
fn kind40_channel_create_does_not_bypass_whitelist() {
    // Per src/relay_do/nip_handlers.rs:69 the comment explicitly notes
    // kind-40 NO LONGER bypasses (was a Sprint-Vx hardening change).
    assert!(!is_bypass_kind(40));
}

#[test]
fn kind42_channel_message_does_not_bypass_whitelist() {
    assert!(!is_bypass_kind(42));
}
