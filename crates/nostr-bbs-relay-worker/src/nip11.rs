//! NIP-11 Relay Information Document.
//!
//! Returns a JSON document describing relay capabilities, limits, and retention
//! policies per <https://github.com/nostr-protocol/nips/blob/master/11.md>.

use nostr_bbs_core::governance::{
    RiskTier, KIND_ACTION_REQUEST, KIND_ACTION_RESPONSE, KIND_PANEL_DEFINITION, KIND_PANEL_RETIRED,
    KIND_PANEL_STATE, KIND_PANEL_UPDATE,
};
use serde_json::json;
use worker::Env;

/// Default escalation tier when `ESCALATION_DEFAULT_TIER` is unset (REC-6).
const DEFAULT_ESCALATION_TIER: &str = "medium";
/// Default authority posture when `ESCALATION_DEFAULT_POSTURE` is unset (REC-6).
const DEFAULT_ESCALATION_POSTURE: &str = "escalate_to_human";

/// Forum-side projection of the agent authority-boundary default (REC-6 share,
/// WP-9). REC-6's authoritative schema is owned by agentbox; this relay reflects
/// the shipped forum default so a NIP-11-reading agent can discover the boundary
/// posture the surface currently assumes. It is a SCAFFOLD and labelled as such:
/// `status` is `scaffolded` and `schema_owner` names agentbox, so a reader does
/// not mistake it for the finalised authority model. When agentbox's REC-6
/// schema lands, this field shape aligns to it (ADR-106 Decision 4 consequence;
/// PRD WP-9).
///
/// `default_escalation_tier` is the [`RiskTier`] at (or above) which an agent
/// action requires a human decision rather than acting autonomously. The shipped
/// forum default escalates at `medium` and above — only `low` acts autonomously,
/// which is exactly the tier the member surface suppresses
/// ([`RiskTier::is_member_suppressed`]), so the projected default and the
/// enforced view filter stay consistent. An unrecognised configured tier is
/// normalised through [`RiskTier::parse`] so the relay can never advertise a tier
/// the forum does not model.
pub(crate) fn escalation_defaults_block(default_tier: &str, posture: &str) -> serde_json::Value {
    let tier = RiskTier::parse(default_tier).as_str();
    let risk_tiers: Vec<&'static str> = [
        RiskTier::Low,
        RiskTier::Medium,
        RiskTier::High,
        RiskTier::Critical,
    ]
    .iter()
    .map(|t| t.as_str())
    .collect();
    json!({
        "status": "scaffolded",
        "schema_owner": "agentbox:REC-6",
        "registry_gated": true,
        "default_escalation_tier": tier,
        "autonomous_below_default": true,
        "default_posture": posture,
        "risk_tiers": risk_tiers,
        "note": "Forum-side reflection of the agent authority-boundary default. \
                 The authoritative escalation-default schema is owned by agentbox \
                 (REC-6); until it lands this projects the shipped forum default \
                 (escalate at or above the default tier; only 'low' acts \
                 autonomously). When REC-6 promotes this to a governance event \
                 kind it is gated identically to kinds 31400-31405 via the \
                 agent_registry.",
    })
}

/// One NIP-11 retention rule: a set of event kinds and how long they are kept.
///
/// This is the SINGLE SOURCE OF TRUTH shared by the advertised NIP-11
/// `retention` document (built in [`relay_info`]) and the cron DELETE sweep
/// ([`crate::cron::sweep_retention`]). Because both read the same
/// [`RETENTION_POLICY`], the relay can only advertise a window it actually
/// enforces — the two can never drift.
pub(crate) struct RetentionRule {
    pub kinds: RetentionKinds,
    /// Retention window in seconds. `None` = retained indefinitely (never swept).
    pub time: Option<i64>,
}

/// The set of event kinds a [`RetentionRule`] applies to.
pub(crate) enum RetentionKinds {
    /// Explicit kind numbers, e.g. `[1]` or `[0, 3]`.
    List(&'static [u64]),
    /// Inclusive kind range, serialised in NIP-11's nested-pair form
    /// (`[[lo, hi]]`).
    Range(u64, u64),
}

impl RetentionKinds {
    /// The NIP-11 JSON form of the `kinds` field for this rule.
    fn to_json(&self) -> serde_json::Value {
        match self {
            RetentionKinds::List(ks) => json!(ks),
            RetentionKinds::Range(lo, hi) => json!([[lo, hi]]),
        }
    }
}

/// Canonical per-kind retention policy. Drives BOTH the NIP-11 document and the
/// cron retention sweep. Kinds with `time: None` are retained forever.
pub(crate) const RETENTION_POLICY: &[RetentionRule] = &[
    RetentionRule {
        kinds: RetentionKinds::List(&[0]),
        time: None,
    },
    RetentionRule {
        kinds: RetentionKinds::List(&[3]),
        time: None,
    },
    RetentionRule {
        kinds: RetentionKinds::List(&[1]),
        time: Some(7_776_000),
    },
    RetentionRule {
        kinds: RetentionKinds::List(&[7]),
        time: Some(2_592_000),
    },
    RetentionRule {
        kinds: RetentionKinds::List(&[9024]),
        time: Some(86_400),
    },
    RetentionRule {
        kinds: RetentionKinds::Range(10_000, 19_999),
        time: None,
    },
    RetentionRule {
        kinds: RetentionKinds::Range(30_000, 39_999),
        time: None,
    },
];

/// Build the NIP-11 relay information JSON value.
///
/// The relay name is taken from the `RELAY_NAME` env var (falling back to
/// "nostr-bbs Relay"). The pubkey and contact fields are left empty since
/// admin status is now dynamic (stored in D1).
pub fn relay_info(env: &Env) -> serde_json::Value {
    let relay_name = env
        .var("RELAY_NAME")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "nostr-bbs Relay".to_string());

    let admin_pubkey = String::new();
    let contact = String::new();

    // REC-6 (WP-9): the default authority-boundary posture, sourced from config
    // so an operator sets it without a code change. Falls back to a conservative
    // default (escalate at/above medium; only `low` is autonomous).
    let escalation_default_tier = env
        .var("ESCALATION_DEFAULT_TIER")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| DEFAULT_ESCALATION_TIER.to_string());
    let escalation_posture = env
        .var("ESCALATION_DEFAULT_POSTURE")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| DEFAULT_ESCALATION_POSTURE.to_string());

    // Built from the shared `RETENTION_POLICY` so the advertised windows and the
    // cron sweep (`crate::cron::sweep_retention`) can never diverge.
    let retention: Vec<serde_json::Value> = RETENTION_POLICY
        .iter()
        .map(|r| {
            json!({
                "kinds": r.kinds.to_json(),
                "time": match r.time {
                    Some(secs) => json!(secs),
                    None => serde_json::Value::Null,
                },
            })
        })
        .collect();

    json!({
        "name": relay_name,
        "description": "Private whitelist-only Nostr relay (nostr-bbs).",
        "pubkey": admin_pubkey,
        "contact": contact,
        // NIP-56 (kind-1984 reports) is enforced relay-side: trust-gated
        // submission, report projection, and auto-hide moderation all run in
        // `nip_handlers`. It was previously implemented but unadvertised; add
        // it so the info document accurately reflects relay capability.
        //
        // NIP-17 (private direct messages) is NOT advertised. The relay
        // accepts and recipient-gates kind-1059 gift wraps (NIP-59), but
        // NIP-17 additionally requires inbox routing: kind-14 chat messages
        // delivered to the recipient's declared DM relays (kind-10050). No
        // such inbox routing exists here, so advertising NIP-17 would
        // overstate capability — only the NIP-59 transport is implemented.
        // NIP-90 (DVM) is likewise NOT advertised: the `nip90` module was
        // removed in the R4 sweep (ADR-103 §2.3) and no DVM kinds are handled,
        // so listing 90 would be a phantom capability claim.
        "supported_nips": [1, 9, 11, 16, 29, 33, 40, 42, 45, 50, 56, 59, 65, 98],
        "software": "https://github.com/DreamLab-AI/nostr-rust-forum",
        "version": env!("CARGO_PKG_VERSION"),
        "limitation": {
            "max_message_length": 65536,
            "max_content_length": 65536,
            "max_event_tags": 2000,
            "max_subscriptions": 20,
            "max_filters": 10,
            "max_limit": 1000,
            "max_subid_length": 64,
            // Gap 7 (truthful relay-info): the relay sends a NIP-42 AUTH
            // challenge on connect and lists 42 in supported_nips, but writes
            // are NOT gated on completing the AUTH handshake — the gate is on
            // the *signed event's pubkey* being whitelisted (see
            // nip_handlers::handle_event `is_whitelisted`). So `auth_required`
            // is false in the strict NIP-42 sense (no AUTH round-trip is
            // forced before EVENT), but writes are still trust-gated. The
            // `restricted_writes` flag plus the `nostr_bbs.write_policy` block
            // below describe the actual model so a standard client does not
            // mistake this for an open relay.
            "auth_required": false,
            "payment_required": false,
            "restricted_writes": true,
        },
        // Enforced by `crate::cron::sweep_retention`; sourced from
        // `RETENTION_POLICY` above so the advertised policy is the swept policy.
        "retention": retention,
        // nostr-bbs kit namespaced extension: the Agent Control Surface Protocol.
        // This relay gates governance kinds 31400-31405 behind the
        // `agent_registry` table (only registered `did:nostr` agent pubkeys may
        // publish PanelDefinition/ActionRequest/etc.; humans respond via 31403).
        // A NIP-11-reading agent uses this block to discover that the relay
        // speaks the mesh governance protocol and which kinds it enforces.
        // Kind numbers are sourced from the canonical `governance` constants to
        // prevent drift. Namespaced under `nostr_bbs` so it never collides with
        // standard NIP-11 fields.
        "nostr_bbs": {
            // Gap 7: make the whitelist-gated write model explicit. Standard
            // NIP-11 only has the boolean `restricted_writes`; this block says
            // *how* writes are restricted so a client knows a rejection is not
            // a NIP-42 AUTH failure but a trust/whitelist decision keyed on the
            // signed event's pubkey. `auth_method: "whitelist"` (not "nip42")
            // is the truthful description: the EVENT itself proves identity,
            // and admission is decided against the relay's whitelist + trust
            // levels, not against a completed AUTH session.
            "write_policy": {
                "model": "whitelist",
                "auth_method": "whitelist",
                "nip42_challenge_sent": true,
                "nip42_required_for_write": false,
                "rejection_message": "blocked: pubkey not whitelisted",
            },
            "agent_control_surface": {
                "enabled": true,
                "registry_gated": true,
                "panel_definition_kind": KIND_PANEL_DEFINITION,
                "panel_state_kind": KIND_PANEL_STATE,
                "action_request_kind": KIND_ACTION_REQUEST,
                "action_response_kind": KIND_ACTION_RESPONSE,
                "panel_update_kind": KIND_PANEL_UPDATE,
                "panel_retired_kind": KIND_PANEL_RETIRED,
                "agent_auth": "nip98",
                "agent_identity": "did:nostr",
            },
            // REC-6 share (WP-9): forum-side reflection of the agentbox
            // authority-boundary default. Scaffolded and schema-owned by
            // agentbox — see `escalation_defaults_block`.
            "escalation_defaults": escalation_defaults_block(
                &escalation_default_tier,
                &escalation_posture,
            ),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalation_block_reflects_config_and_lists_all_risk_tiers() {
        let block = escalation_defaults_block("high", "escalate_to_human");
        assert_eq!(block["status"], "scaffolded");
        assert_eq!(block["schema_owner"], "agentbox:REC-6");
        assert_eq!(block["registry_gated"], true);
        assert_eq!(block["default_escalation_tier"], "high");
        assert_eq!(block["default_posture"], "escalate_to_human");
        let tiers = block["risk_tiers"].as_array().expect("risk_tiers array");
        assert_eq!(tiers.len(), 4);
        assert_eq!(tiers[0], "low");
        assert_eq!(tiers[3], "critical");
    }

    #[test]
    fn escalation_block_normalises_unknown_tier_to_default() {
        // A junk configured tier must not advertise an unmodelled tier; parse
        // folds it to the medium default.
        let block = escalation_defaults_block("bananas", "escalate_to_human");
        assert_eq!(block["default_escalation_tier"], "medium");
    }

    #[test]
    fn projected_default_matches_member_suppression_boundary() {
        // The shipped default (medium) means only `low` acts autonomously — the
        // exact tier the member surface suppresses. This keeps the advertised
        // default consistent with the enforced view filter (RiskTier::is_member_suppressed).
        let block = escalation_defaults_block(DEFAULT_ESCALATION_TIER, DEFAULT_ESCALATION_POSTURE);
        let tier = block["default_escalation_tier"]
            .as_str()
            .expect("tier string");
        assert!(RiskTier::Low.is_member_suppressed());
        assert!(!RiskTier::parse(tier).is_member_suppressed());
    }
}
