// TEMPORARY auditor scratch test — deleted after the audit run, not committed.
use nostr_bbs_core::governance::{
    can_advance_stage, effective_tier, is_calibration_sample, is_member_suppressed_effective,
    Reversibility, RiskTier, Stakes, TaskProperties, Verifiability,
};

#[test]
fn probe_merge_request_looser_than_panel_on_all_three_axes() {
    let panel = TaskProperties::new(Verifiability::Opaque, Reversibility::Irreversible, Stakes::Critical);
    let request = TaskProperties::new(Verifiability::Inspectable, Reversibility::Reversible, Stakes::Bounded);
    let merged = TaskProperties::merge(panel, request);
    assert_eq!(merged.verifiability, Verifiability::Opaque, "request loosened verifiability");
    assert_eq!(merged.reversibility, Reversibility::Irreversible, "request loosened reversibility");
    assert_eq!(merged.stakes, Stakes::Critical, "request loosened stakes");
}

#[test]
fn probe_opaque_plus_declared_low_is_at_least_medium_not_suppressed() {
    let props = TaskProperties::new(Verifiability::Opaque, Reversibility::Reversible, Stakes::Bounded);
    let tier = effective_tier(Some(&props), None, Some(RiskTier::Low), RiskTier::Medium);
    assert!(tier >= RiskTier::Medium, "Opaque was suppressed to below Medium: {:?}", tier);
    assert!(!is_member_suppressed_effective(Some(&props), tier, false));
}

#[test]
fn probe_irreversible_plus_declared_low_is_at_least_high() {
    let props = TaskProperties::new(Verifiability::Inspectable, Reversibility::Irreversible, Stakes::Bounded);
    let tier = effective_tier(Some(&props), None, Some(RiskTier::Low), RiskTier::Medium);
    assert!(tier >= RiskTier::High, "Irreversible was not floored at High: declared Low -> {:?}", tier);
}

#[test]
fn probe_critical_stakes_plus_declared_low_is_at_least_high() {
    let props = TaskProperties::new(Verifiability::Inspectable, Reversibility::Reversible, Stakes::Critical);
    let tier = effective_tier(Some(&props), None, Some(RiskTier::Low), RiskTier::Medium);
    assert!(tier >= RiskTier::High, "Critical stakes was not floored at High: declared Low -> {:?}", tier);
}

#[test]
fn probe_unlabelled_request_folds_to_env_absent_default() {
    // "what if env var absent?" -- caller must supply *some* RiskTier; there is
    // no way to construct effective_tier without one. Probe: does an entirely
    // absent panel/request/declared collapse to Medium (the historical
    // accidental default) instead of exactly the advertised default?
    for advertised in [RiskTier::Low, RiskTier::Medium, RiskTier::High, RiskTier::Critical] {
        let tier = effective_tier(None, None, None, advertised);
        assert_eq!(tier, advertised, "unlabelled request did not fold to advertised default {:?}, got {:?}", advertised, tier);
    }
}

#[test]
fn probe_receipt_regression_applied_to_consumer_received_is_rejected() {
    use nostr_bbs_core::governance::ReceiptStage;
    let result = can_advance_stage(ReceiptStage::Applied, ReceiptStage::ConsumerReceived);
    assert!(result.is_err(), "regression Applied -> ConsumerReceived was permitted");
}

#[test]
fn probe_applied_manually_from_relay_accepted_is_not_projected() {
    use nostr_bbs_core::governance::ReceiptStage;
    let result = can_advance_stage(ReceiptStage::RelayAccepted, ReceiptStage::AppliedManually);
    assert!(result.is_err(), "AppliedManually admitted from RelayAccepted (never committed)");
}

#[test]
fn probe_calibration_sampling_determinism_same_id_same_result() {
    let id = "audit-probe-request-id-0001";
    let first = is_calibration_sample(id, 0.1);
    for _ in 0..20 {
        assert_eq!(is_calibration_sample(id, 0.1), first, "sampling flipped for the same request id");
    }
}

#[test]
fn probe_calibration_rate_zero_selects_none_rate_one_selects_all() {
    for id in ["a", "b", "c", "deadbeef", "0000000000000000000000000000000000000000000000000000000000000000"] {
        assert!(!is_calibration_sample(id, 0.0), "rate 0 sampled {id}");
        assert!(is_calibration_sample(id, 1.0), "rate 1 did not sample {id}");
    }
}

#[test]
fn probe_calibration_negative_and_nan_rate_sample_nothing() {
    assert!(!is_calibration_sample("x", -0.5));
    assert!(!is_calibration_sample("x", f32::NAN));
}
