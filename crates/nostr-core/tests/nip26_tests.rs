//! Tests for NIP-26: Delegated Event Signing.
//!
//! These tests exercise the public API that W1 will implement in
//! `crates/nostr-core/src/nip26.rs`.
//!
//! Wire format summary:
//!   delegation_tag = ["delegation", <delegator_pubkey_hex>, <conditions_str>, <sig_hex>]
//!   where sig = Schnorr(delegator_sk, SHA-256("nostr:delegation:" || delegatee_pk || ":" || conditions_str))
//!
//! Conditions string grammar (from NIP-26):
//!   conditions = condition ("&" condition)*
//!   condition  = "kind=" INT | "created_at>" INT | "created_at<" INT
//!
//! Test categories:
//!   - Conditions parsing: well-formed strings, edge cases, error paths
//!   - Conditions permissions: in/out-of-window events
//!   - Token creation and verification (roundtrip)
//!   - Delegation tag encoding / decoding
//!   - Signature verification (valid, tampered, wrong delegatee)

use nostr_core::nip26::{
    validate_delegation_tag, Conditions, DelegationTag, DelegationToken, Nip26Error,
};

// ── Helper keys (small valid scalars) ─────────────────────────────────────────

fn sk_scalar(n: u8) -> [u8; 32] {
    let mut sk = [0u8; 32];
    sk[31] = n;
    sk
}

fn pk_hex_for_scalar(n: u8) -> String {
    use k256::schnorr::SigningKey;
    let sk_bytes = sk_scalar(n);
    let sk = SigningKey::from_bytes(&sk_bytes).unwrap();
    hex::encode(sk.verifying_key().to_bytes())
}

// ── Conditions parsing ────────────────────────────────────────────────────────

#[test]
fn conditions_parse_kind_only() {
    let c = Conditions::from_str("kind=1").expect("must parse 'kind=1'");
    assert_eq!(c.kinds, vec![1u64]);
    assert!(c.created_after.is_none());
    assert!(c.created_before.is_none());
}

#[test]
fn conditions_parse_multiple_kinds() {
    // NIP-26 allows multiple kind= entries
    let c = Conditions::from_str("kind=1&kind=6").expect("must parse multiple kinds");
    assert!(c.kinds.contains(&1u64));
    assert!(c.kinds.contains(&6u64));
}

#[test]
fn conditions_parse_created_at_range() {
    let c = Conditions::from_str("kind=1&created_at>1674777689&created_at<1675721813")
        .expect("must parse full conditions string");
    assert_eq!(c.kinds, vec![1u64]);
    assert_eq!(c.created_after, Some(1674777689u64));
    assert_eq!(c.created_before, Some(1675721813u64));
}

#[test]
fn conditions_parse_time_without_kind() {
    let c = Conditions::from_str("created_at>100&created_at<200")
        .expect("must allow conditions without kind");
    assert!(c.kinds.is_empty());
    assert_eq!(c.created_after, Some(100u64));
    assert_eq!(c.created_before, Some(200u64));
}

#[test]
fn conditions_parse_empty_string() {
    // Empty conditions = any event allowed
    let c = Conditions::from_str("").expect("empty conditions must parse");
    assert!(c.kinds.is_empty());
    assert!(c.created_after.is_none());
    assert!(c.created_before.is_none());
}

#[test]
fn conditions_parse_invalid_kind_value_returns_error() {
    let result = Conditions::from_str("kind=notanumber");
    assert!(
        matches!(result, Err(Nip26Error::InvalidCondition(_))),
        "non-numeric kind must return InvalidCondition"
    );
}

#[test]
fn conditions_parse_unknown_key_returns_error() {
    // Unrecognised condition keys should be rejected
    let result = Conditions::from_str("author=abc");
    assert!(
        result.is_err(),
        "unknown condition key must return an error"
    );
}

#[test]
fn conditions_parse_malformed_key_returns_error() {
    // Missing operator/value
    let result = Conditions::from_str("kind");
    assert!(
        result.is_err(),
        "condition with no operator must return error"
    );
}

// ── Conditions::permits ───────────────────────────────────────────────────────

#[test]
fn conditions_permits_matching_kind_and_time() {
    let c = Conditions::from_str("kind=1&created_at>100&created_at<200").unwrap();
    assert!(c.permits(1, 150), "kind=1 ts=150 must be permitted");
}

#[test]
fn conditions_permits_rejects_wrong_kind() {
    let c = Conditions::from_str("kind=1&created_at>100&created_at<200").unwrap();
    assert!(
        !c.permits(2, 150),
        "kind=2 must be rejected when only kind=1 allowed"
    );
}

#[test]
fn conditions_permits_rejects_before_window() {
    let c = Conditions::from_str("kind=1&created_at>100&created_at<200").unwrap();
    assert!(!c.permits(1, 50), "ts=50 is before created_at>100 window");
}

#[test]
fn conditions_permits_rejects_after_window() {
    let c = Conditions::from_str("kind=1&created_at>100&created_at<200").unwrap();
    assert!(!c.permits(1, 250), "ts=250 is after created_at<200 window");
}

#[test]
fn conditions_permits_boundary_at_created_after() {
    // created_at> is strictly greater-than per NIP-26 spec
    let c = Conditions::from_str("created_at>100").unwrap();
    assert!(
        !c.permits(1, 100),
        "ts=100 is NOT strictly greater than 100"
    );
    assert!(c.permits(1, 101), "ts=101 is strictly greater than 100");
}

#[test]
fn conditions_permits_boundary_at_created_before() {
    // created_at< is strictly less-than
    let c = Conditions::from_str("created_at<200").unwrap();
    assert!(!c.permits(1, 200), "ts=200 is NOT strictly less than 200");
    assert!(c.permits(1, 199), "ts=199 is strictly less than 200");
}

#[test]
fn conditions_permits_no_constraints_allows_anything() {
    let c = Conditions::from_str("").unwrap();
    assert!(
        c.permits(0, 0),
        "no constraints: kind=0 ts=0 must be allowed"
    );
    assert!(
        c.permits(999, u64::MAX),
        "no constraints: any kind/ts allowed"
    );
}

#[test]
fn conditions_permits_multiple_kinds() {
    let c = Conditions::from_str("kind=1&kind=6").unwrap();
    assert!(c.permits(1, 0), "kind=1 must be permitted");
    assert!(c.permits(6, 0), "kind=6 must be permitted");
    assert!(!c.permits(4, 0), "kind=4 must be rejected");
}

#[test]
fn conditions_serialise_roundtrip() {
    // parse → to_string → parse must be idempotent
    let original = "kind=1&created_at>1674777689&created_at<1675721813";
    let c = Conditions::from_str(original).unwrap();
    let serialised = c.to_string();
    let c2 = Conditions::from_str(&serialised).unwrap();
    assert_eq!(c.kinds, c2.kinds);
    assert_eq!(c.created_after, c2.created_after);
    assert_eq!(c.created_before, c2.created_before);
}

// ── DelegationToken creation and verification ─────────────────────────────────

#[test]
fn delegation_token_roundtrip_kind_only() {
    let delegator_sk = sk_scalar(1);
    let delegatee_pk = pk_hex_for_scalar(2);
    let conditions = Conditions::from_str("kind=1").unwrap();

    let token = DelegationToken::create(&delegator_sk, &delegatee_pk, &conditions)
        .expect("create must succeed");

    token
        .verify()
        .expect("verify must succeed on a freshly-created token");
}

#[test]
fn delegation_token_roundtrip_with_time_bounds() {
    let delegator_sk = sk_scalar(3);
    let delegatee_pk = pk_hex_for_scalar(4);
    let conditions = Conditions::from_str("kind=1&created_at>1000&created_at<9999999999").unwrap();

    let token = DelegationToken::create(&delegator_sk, &delegatee_pk, &conditions).unwrap();
    token
        .verify()
        .expect("verify with time bounds must succeed");
}

#[test]
fn delegation_token_roundtrip_no_conditions() {
    let delegator_sk = sk_scalar(5);
    let delegatee_pk = pk_hex_for_scalar(6);
    let conditions = Conditions::from_str("").unwrap();

    let token = DelegationToken::create(&delegator_sk, &delegatee_pk, &conditions).unwrap();
    token
        .verify()
        .expect("verify with empty conditions must succeed");
}

#[test]
fn delegation_token_verify_tampered_sig_fails() {
    let delegator_sk = sk_scalar(1);
    let delegatee_pk = pk_hex_for_scalar(2);
    let conditions = Conditions::from_str("kind=1").unwrap();

    let mut token = DelegationToken::create(&delegator_sk, &delegatee_pk, &conditions).unwrap();
    // Corrupt one byte of the signature
    let mut sig_bytes = hex::decode(&token.sig).unwrap();
    sig_bytes[0] ^= 0xFF;
    token.sig = hex::encode(&sig_bytes);

    let result = token.verify();
    assert!(
        matches!(result, Err(Nip26Error::InvalidSignature)),
        "tampered signature must fail verification, got: {result:?}"
    );
}

#[test]
fn delegation_token_verify_wrong_delegatee_fails() {
    let delegator_sk = sk_scalar(1);
    let delegatee_pk = pk_hex_for_scalar(2);
    let wrong_pk = pk_hex_for_scalar(3);
    let conditions = Conditions::from_str("kind=1").unwrap();

    let mut token = DelegationToken::create(&delegator_sk, &delegatee_pk, &conditions).unwrap();
    // Substitute a different delegatee pubkey — sig was computed over original
    token.delegatee_pubkey = wrong_pk;

    let result = token.verify();
    assert!(
        result.is_err(),
        "wrong delegatee pubkey must fail verification"
    );
}

#[test]
fn delegation_token_verify_wrong_conditions_fails() {
    let delegator_sk = sk_scalar(1);
    let delegatee_pk = pk_hex_for_scalar(2);
    let conditions = Conditions::from_str("kind=1").unwrap();

    let mut token = DelegationToken::create(&delegator_sk, &delegatee_pk, &conditions).unwrap();
    // Change the conditions string — sig was computed over original
    token.conditions_str = "kind=4".to_string();

    let result = token.verify();
    assert!(
        result.is_err(),
        "tampered conditions string must fail verification"
    );
}

// ── DelegationTag encode / decode ─────────────────────────────────────────────

#[test]
fn delegation_tag_roundtrip() {
    let delegator_sk = sk_scalar(1);
    let delegatee_pk = pk_hex_for_scalar(2);
    let conditions = Conditions::from_str("kind=1").unwrap();

    let token = DelegationToken::create(&delegator_sk, &delegatee_pk, &conditions).unwrap();
    let tag = DelegationTag::from_token(&token);

    // Tag must follow NIP-26 wire format:
    //   ["delegation", <delegator_pubkey>, <conditions>, <sig>]
    assert_eq!(tag.0[0], "delegation", "first element must be 'delegation'");
    assert_eq!(tag.0[1].len(), 64, "delegator pubkey must be 64 hex chars");
    // conditions string is at index 2
    assert!(!tag.0[2].is_empty() || conditions.to_string().is_empty());
    assert_eq!(tag.0[3].len(), 128, "signature must be 128 hex chars");

    // Round-trip: parse tag back into a token and verify
    let recovered = DelegationToken::from_tag(&tag).expect("from_tag must succeed");
    recovered
        .verify()
        .expect("recovered token must pass verification");
}

#[test]
fn delegation_tag_from_malformed_tag_returns_error() {
    // Too few elements
    let bad_tag = DelegationTag(vec!["delegation".into(), "pubkey".into()]);
    let result = DelegationToken::from_tag(&bad_tag);
    assert!(
        result.is_err(),
        "tag with too few elements must return error"
    );
}

#[test]
fn delegation_tag_wrong_first_element_returns_error() {
    let bad_tag = DelegationTag(vec![
        "notdelegation".into(),
        "a".repeat(64),
        "kind=1".into(),
        "b".repeat(128),
    ]);
    let result = DelegationToken::from_tag(&bad_tag);
    assert!(
        result.is_err(),
        "tag with wrong first element must return error"
    );
}

// ── validate_delegation_tag (event-level helper) ──────────────────────────────

#[test]
fn validate_delegation_tag_accepts_matching_event() {
    let delegator_sk = sk_scalar(1);
    let delegatee_pk = pk_hex_for_scalar(2);
    let conditions = Conditions::from_str("kind=1&created_at>0&created_at<9999999999").unwrap();

    let token = DelegationToken::create(&delegator_sk, &delegatee_pk, &conditions).unwrap();
    let tag = DelegationTag::from_token(&token);

    let result = validate_delegation_tag(
        &tag,
        &delegatee_pk, // event author
        1,             // kind
        1_000_000_000, // created_at — within window
    );
    assert!(
        result.is_ok(),
        "valid event must pass delegation validation"
    );
}

#[test]
fn validate_delegation_tag_rejects_wrong_author() {
    let delegator_sk = sk_scalar(1);
    let delegatee_pk = pk_hex_for_scalar(2);
    let wrong_author = pk_hex_for_scalar(3);
    let conditions = Conditions::from_str("kind=1").unwrap();

    let token = DelegationToken::create(&delegator_sk, &delegatee_pk, &conditions).unwrap();
    let tag = DelegationTag::from_token(&token);

    let result = validate_delegation_tag(&tag, &wrong_author, 1, 0);
    assert!(
        result.is_err(),
        "wrong event author must fail delegation validation"
    );
}

#[test]
fn validate_delegation_tag_rejects_wrong_kind() {
    let delegator_sk = sk_scalar(1);
    let delegatee_pk = pk_hex_for_scalar(2);
    let conditions = Conditions::from_str("kind=1").unwrap();

    let token = DelegationToken::create(&delegator_sk, &delegatee_pk, &conditions).unwrap();
    let tag = DelegationTag::from_token(&token);

    let result = validate_delegation_tag(&tag, &delegatee_pk, 4, 0); // kind 4 not authorised
    assert!(
        result.is_err(),
        "kind=4 must fail when delegation only authorises kind=1"
    );
}

#[test]
fn validate_delegation_tag_rejects_expired_time() {
    let delegator_sk = sk_scalar(1);
    let delegatee_pk = pk_hex_for_scalar(2);
    let conditions = Conditions::from_str("created_at>100&created_at<200").unwrap();

    let token = DelegationToken::create(&delegator_sk, &delegatee_pk, &conditions).unwrap();
    let tag = DelegationTag::from_token(&token);

    // created_at=300 is outside the [101, 199] allowed window
    let result = validate_delegation_tag(&tag, &delegatee_pk, 1, 300);
    assert!(
        result.is_err(),
        "timestamp outside window must fail delegation validation"
    );
}

// ── Known-vector: signature hash pre-image ────────────────────────────────────

#[test]
fn delegation_sig_hash_preimage_format() {
    // NIP-26 specifies the sig covers:
    //   SHA-256("nostr:delegation:" || delegatee_pk || ":" || conditions_str)
    // This test verifies the token's signature field is 64 hex bytes (128 chars).
    let delegator_sk = sk_scalar(1);
    let delegatee_pk = pk_hex_for_scalar(2);
    let conditions = Conditions::from_str("kind=1").unwrap();
    let token = DelegationToken::create(&delegator_sk, &delegatee_pk, &conditions).unwrap();

    assert_eq!(
        token.sig.len(),
        128,
        "Schnorr sig must be 64 bytes = 128 hex chars"
    );
    assert!(
        token.sig.chars().all(|c: char| c.is_ascii_hexdigit()),
        "sig must be lowercase hex"
    );
}
