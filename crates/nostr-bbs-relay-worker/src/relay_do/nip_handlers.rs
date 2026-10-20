//! NIP-specific protocol handlers for the Nostr relay.
//!
//! - NIP-01: EVENT, REQ, CLOSE
//! - NIP-09: Deletion processing
//! - NIP-42: AUTH challenge/response
//! - NIP-45: COUNT
//! - Event validation.
//! - Trust-level gating (TL0-TL3) for event kinds.
//! - Zone enforcement on EVENT and REQ.
//! - F11 (PRD-010): Federated kind allowlist filtering for mesh peers.

use nostr_bbs_core::event::NostrEvent;
use nostr_bbs_core::feature_gate::{
    device_keys_enabled as core_device_keys_enabled, DEVICE_KEYS_ENABLED_VAR,
};
use nostr_bbs_core::governance::{self, RiskTier, TaskProperties};
use nostr_bbs_core::ontology_governance;
use nostr_bbs_core::{KIND_BAN, KIND_MUTE, KIND_REPORT_NIP56, KIND_UNBAN, KIND_UNMUTE};
use wasm_bindgen::JsValue;
use worker::*;

use crate::auth;
use crate::moderation;
use crate::trust::{self, TrustLevel};
use crate::zone_config::ZoneConfig;

use super::broadcast::{event_treatment, EventTreatment};
use super::calendar_projection;
use super::filter::{self, NostrFilter};
use super::nip42::{self, AuthMode};
use super::receipts::{self, ReceiptOutcome, ReceiptStore};
use super::NostrRelayDO;

use nostr_bbs_core::KIND_CALENDAR_RSVP;

// ---------------------------------------------------------------------------
// Security limits
// ---------------------------------------------------------------------------

const MAX_CONTENT_SIZE: usize = 64 * 1024;
const MAX_REGISTRATION_CONTENT_SIZE: usize = 8 * 1024;
const MAX_TAG_COUNT: usize = 2000;
const MAX_TAG_VALUE_SIZE: usize = 1024;
const MAX_TIMESTAMP_DRIFT: u64 = 60 * 60 * 24 * 7;
const MAX_SUBSCRIPTIONS: usize = 20;

/// NIP-59: gift-wrap event kind. Signed by a fresh ephemeral key per message;
/// recipient-gated via the first `["p", <hex>]` tag rather than the author.
const GIFT_WRAP_KIND: u64 = 1059;

/// NIP-29: Admin-only group management/moderation kinds.
fn is_nip29_admin_kind(kind: u64) -> bool {
    (9000..=9020).contains(&kind) || (39000..=39002).contains(&kind)
}

/// WI-2: content-bearing kinds a banned or muted author must NOT publish.
///
/// The moderation ingress gate (`ModCache::is_blocked`) previously fired only
/// for kinds 1 and 42, so a banned user could still publish reactions (7),
/// deletions (5), reports (1984), long-form articles (30023), channel
/// create/metadata (40/41) and NIP-52 calendar events + RSVPs (31922/31923/
/// 31925). This enumerates every user-authored content kind the ban must cover.
/// Admins bypass at the call site. Gift wraps (1059) are intentionally excluded:
/// each is signed by a throwaway ephemeral key, so an author-keyed ban cannot
/// apply — those are bounded by the recipient-whitelist gate instead.
///
/// Pure predicate so the gate scope is unit-testable without an `Env`.
pub fn is_ban_gated_kind(kind: u64) -> bool {
    matches!(
        kind,
        1 | 5 | 7 | 9 | 40 | 41 | 42 | 30023 | KIND_COMMUNITY_DEFINITION
    ) || kind == KIND_REPORT_NIP56
        || kind == nostr_bbs_core::KIND_CALENDAR_DATE_EVENT
        || kind == nostr_bbs_core::KIND_CALENDAR_EVENT
        || kind == KIND_CALENDAR_RSVP
        || nostr_bbs_core::is_kanban_kind(kind)
        || kind == nostr_bbs_core::KIND_AGENT_INTENT
}

/// NIP-72 community definition (kind 34550): content-bearing, so a banned author
/// must not publish one (ADR-2029 room dialect).
const KIND_COMMUNITY_DEFINITION: u64 = 34550;

/// Content kinds that bump the author's `posts_created` trust counter: kind-1
/// text, kind-9 chat, kind-7 reaction, kind-40 channel create, kind-42 channel
/// message and kind-1984 report. Pure so the scope is unit-testable.
pub fn counts_as_post(kind: u64) -> bool {
    matches!(kind, 1 | 7 | 9 | 40 | 42 | KIND_REPORT_NIP56)
}

/// Phase C (write side): whether an RSVP (kind 31925) is permitted to be written,
/// given the AUTHOR's resolved projection tier for the RSVP's TARGET event.
///
/// An RSVP attaches its author to a target event. If the author can only see that
/// target as free/busy (`FreeBusy`) or not at all (`Omit`), accepting the RSVP is a
/// privacy/integrity leak. Only a `Full` tier (which already covers admins/owners
/// via `project_tier`'s short-circuit) is write-permitted.
///
/// Pure predicate over the already-resolved tier so the gate decision is
/// unit-testable without a `worker::Env` / D1. The caller resolves the target
/// zone/venue from D1 and computes the tier via
/// [`calendar_projection::project_tier`].
pub fn rsvp_write_permitted(tier: &calendar_projection::Projection) -> bool {
    matches!(tier, calendar_projection::Projection::Full)
}

/// Phase C (write side): whether a zone-tagged calendar event (31922/31923) is
/// permitted to be written. A zone-tagged event requires the author to hold write
/// access to that zone; an untagged event is unscoped and always permitted here.
///
/// `has_write` is the already-resolved
/// [`trust::has_zone_write_access`](crate::trust::has_zone_write_access) result.
/// Pure predicate so the decision is unit-testable without a `worker::Env`.
pub fn calendar_write_permitted(zone: Option<&str>, has_write: bool) -> bool {
    match zone {
        Some(_) => has_write,
        None => true,
    }
}

/// The keys a sanction (suspension, silence, ban, mute) is checked against: the
/// raw signing key, plus its owner when that differs (a registered device key).
pub fn sanction_subjects<'a>(raw: &'a str, principal: &'a str) -> Vec<&'a str> {
    let mut subjects = vec![raw];
    if principal != raw {
        subjects.push(principal);
    }
    subjects
}

/// Whether a stored channel creator is any of `subjects`. `channel_creators`
/// records the RAW signing key (a device key for a channel made from a device),
/// older rows included, so the owner alone can never be enough.
pub fn creator_matches(creator: &str, subjects: &[&str]) -> bool {
    subjects.contains(&creator)
}

/// Whether the device-owner lookup is worth making for an event of `kind`:
/// never for gift wraps, whose author is a fresh one-time key.
pub fn needs_owner_lookup(kind: u64) -> bool {
    kind != GIFT_WRAP_KIND
}

/// NIP-59: extract the gift-wrap (kind-1059) RECIPIENT pubkey from the first
/// `["p", <hex>]` tag. Returns `None` when the event is not a gift wrap, or when
/// no non-empty `p` tag is present. The recipient — not the ephemeral author —
/// is the principal the membership gate is applied to.
///
/// Pure over the event so the routing decision is unit-testable without an
/// `is_whitelisted` D1 lookup / `worker::Env`.
pub fn gift_wrap_recipient(event: &NostrEvent) -> Option<String> {
    if event.kind != GIFT_WRAP_KIND {
        return None;
    }
    match filter::tag_value(event, "p") {
        Some(pk) if !pk.is_empty() => Some(pk),
        _ => None,
    }
}

/// Whether `event` may be shown to a session authenticated as `session_pubkey`.
///
/// Only kind-1059 gift wraps are restricted: a wrap is readable solely by its
/// recipient (`p` tag). The REQ/COUNT filter gate keys on the filter's `kinds`,
/// so a filter with no `kinds` (or an empty list) reaches wraps without ever
/// being seen as a wrap read; this per-event check closes that on the shared
/// read path, whatever the filter said. Every other kind passes unchanged
/// (zone and cohort rules are applied separately by `authorize_event`).
pub fn gift_wrap_readable_by(event: &NostrEvent, session_pubkey: Option<&str>) -> bool {
    if event.kind != GIFT_WRAP_KIND {
        return true;
    }
    match (gift_wrap_recipient(event), session_pubkey) {
        (Some(recipient), Some(viewer)) => recipient.eq_ignore_ascii_case(viewer),
        _ => false,
    }
}

/// [`gift_wrap_readable_by`] for a viewer holding several recipient keys
/// (Phase 2, set A: identity pubkey plus registered inbox keys). Same rule:
/// only the FIRST `p` is the recipient, matched case-insensitively.
pub fn gift_wrap_readable_by_any(event: &NostrEvent, viewer_keys: &[String]) -> bool {
    if event.kind != GIFT_WRAP_KIND {
        return true;
    }
    gift_wrap_recipient(event).is_some_and(|r| crate::recipient_keys::set_contains(viewer_keys, &r))
}

// ── ADR-2011: the effective escalation boundary ─────────────────────────────

/// Who resolved a case — a human, or a system actor acting on its behalf.
///
/// DDD §6 invariant 8: `system:whelk-gate` and its kind are not humans, and an
/// effective `High`/`Critical` case is not theirs to close (invariant 4). The
/// distinction is carried on the 31403's optional `decided_by` field, which a
/// reasoner stamps and a human client never does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Resolver {
    /// A human `did:nostr`, identified by the signing pubkey.
    Human(String),
    /// A named non-human actor, e.g. `system:whelk-gate`.
    System(String),
}

impl Resolver {
    pub(crate) fn is_human(&self) -> bool {
        matches!(self, Resolver::Human(_))
    }
}

/// Read the resolver from a signed 31403's content.
///
/// A response with no `decided_by`, or one naming the signer, is a human
/// decision — the overwhelmingly common case and the safe default, because the
/// 31403 admission gate has already established that the signer is an admin or
/// a delegated reviewer. A `decided_by` of the form `system:<actor>` marks the
/// outcome as machine-produced.
pub(crate) fn parse_resolver(content: &str, signer: &str) -> Resolver {
    let declared = serde_json::from_str::<serde_json::Value>(content)
        .ok()
        .and_then(|v| {
            v.get("decided_by")
                .and_then(|d| d.as_str())
                .map(str::to_string)
        });
    match declared {
        Some(actor) if actor.starts_with("system:") => Resolver::System(actor),
        _ => Resolver::Human(signer.to_string()),
    }
}

/// DDD §6 invariant 4: an effective `High` or `Critical` case reaches `Decided`
/// only through a human 31403.
pub(crate) fn human_resolution_required(effective: RiskTier) -> bool {
    matches!(effective, RiskTier::High | RiskTier::Critical)
}

/// The action and human rationale carried by a signed 31403's content.
///
/// Parsed once, here, so the rationale gate and the projection cannot disagree
/// about what the event said. A malformed body yields `None` for the action,
/// which the gate treats as "not a gated outcome" — a body that does not parse
/// is rejected further down by `plan_action_response`, and refusing it here for
/// the wrong reason would tell the publisher something untrue.
pub(crate) fn response_action_and_reasoning(content: &str) -> (Option<String>, Option<String>) {
    let action = governance::broker::DecisionOutcome::from_response_content(content)
        .map(|o| o.action_str().to_string());
    let reasoning = serde_json::from_str::<serde_json::Value>(content)
        .ok()
        .and_then(|v| {
            v.get("reasoning")
                .and_then(|r| r.as_str())
                .map(str::to_string)
        });
    (action, reasoning)
}

/// The outcome of the 31403 admission gate (P1-6 extended by FR6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseAdmission {
    /// The signer may decide this case.
    Admit,
    /// The signer is neither an admin nor a reviewer: decisions are not theirs.
    BlockedNotAuthorised,
    /// The signer holds the `reviewer` role but this case was never delegated
    /// to them. Reviewers are read-only except on cases an admin hands them.
    BlockedNotDelegated,
}

impl ResponseAdmission {
    pub fn is_admitted(self) -> bool {
        matches!(self, ResponseAdmission::Admit)
    }

    /// The relay `OK` message for a refusal.
    pub fn reason(self) -> &'static str {
        match self {
            ResponseAdmission::Admit => "",
            ResponseAdmission::BlockedNotAuthorised => {
                "blocked: admin-only governance action response"
            }
            ResponseAdmission::BlockedNotDelegated => {
                "blocked: case not delegated to this reviewer"
            }
        }
    }
}

/// Decide whether a kind-31403 may be admitted (FR6.2, DDD §6 invariant 6).
///
/// An admin may decide any case, as before. A `reviewer`-role pubkey may decide
/// **exactly** the cases an admin has delegated to it — the mechanism that lets
/// a junior reviewer do substantive review work without being handed the whole
/// surface. Everyone else is refused.
///
/// Pure so the gate is unit-testable without a `worker::Env`; the relay supplies
/// the three booleans from `broker_roles`, its admin list, and `case_delegations`.
pub fn response_admission(
    is_admin: bool,
    is_reviewer: bool,
    delegated_for_this_case: bool,
) -> ResponseAdmission {
    if is_admin {
        return ResponseAdmission::Admit;
    }
    if !is_reviewer {
        return ResponseAdmission::BlockedNotAuthorised;
    }
    if delegated_for_this_case {
        ResponseAdmission::Admit
    } else {
        ResponseAdmission::BlockedNotDelegated
    }
}

/// Everything the relay derives about a 31402's escalation boundary at
/// projection time (ADR-2011, FR6.3, FR6.4, FR4.3).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RequestBoundary {
    /// The agent's own declaration. Telemetry: kept so declared-vs-effective
    /// divergence is measurable per agent.
    pub declared: Option<RiskTier>,
    /// The tier that governs the case. The only tier a consumer reads.
    pub effective: RiskTier,
    /// The merged, panel-tightened triple the tier derives from.
    pub props: Option<TaskProperties>,
    /// Whether this otherwise-suppressible case is shown anyway (FR6.3).
    pub calibration_sample: bool,
    /// The seeded-probe digest, kept only when the panel's REGISTERED probe
    /// agent published it.
    pub probe_digest: Option<String>,
    /// The panel's pending-case deadline, copied onto the case for the cron.
    pub max_pending_hours: u32,
    /// The proposal's own expiry instant, read out of the `PatchProposal` body
    /// (ADR-2013). `None` for every request that is not an ontology proposal,
    /// and for one whose `stale_after` this relay will not vouch for.
    pub stale_after: Option<i64>,
}

/// The agent's declared tier, read from the `risk-tier` tag first and the
/// `ActionRequest` content second.
///
/// A tag is cheaper for the relay and is what agentbox stamps; the content
/// field is what the forum client's own `ActionRequest` carries. Reading both
/// means neither publisher has to change to be understood, and an absent
/// declaration stays `None` rather than becoming an accidental `Medium`.
fn declared_tier(tags: &[Vec<String>], content: &str) -> Option<RiskTier> {
    if let Some(t) = governance::extract_tag(tags, "risk-tier") {
        return Some(RiskTier::parse(t));
    }
    serde_json::from_str::<serde_json::Value>(content)
        .ok()
        .and_then(|v| {
            v.get("risk_tier")
                .and_then(|t| t.as_str())
                .map(RiskTier::parse)
        })
}

/// Derive the whole boundary for one 31402 (ADR-2011).
///
/// `panel_tags` are the tags of the 31400 this request belongs to, where the
/// relay could resolve one. A request whose panel cannot be resolved is not
/// refused — it simply has no operator declaration to be tightened by, and
/// falls back to its own declaration and the relay's advertised default.
///
/// Pure over its inputs so the whole boundary computation is unit-testable
/// without a live D1; the env-bound shell in `project_action_request` only
/// supplies the panel row.
///
/// `calibration_key` is the relay's secret selection key. It is an input rather
/// than a constant because the whole point is that the requesting agent cannot
/// predict the sampling outcome: the agent chooses its own `d` tag, so an
/// unkeyed hash of it would let the agent grind its way out of oversight.
pub(crate) fn plan_request_boundary(
    case_id: &str,
    request_pubkey: &str,
    request_tags: &[Vec<String>],
    request_content: &str,
    panel_tags: Option<&[Vec<String>]>,
    advertised_default: RiskTier,
    calibration_key: &[u8],
) -> RequestBoundary {
    let panel_props = panel_tags.and_then(TaskProperties::from_tags);
    // ADR-2013: an ontology proposal's `level` tag contributes a property floor
    // of its own — `schema` and `demotion` carry `stakes: critical`, whose
    // tier floor is `High`. It is folded in on the REQUEST side, where the
    // tightening-only merge can only ever raise the boundary: a proposer that
    // omits or misspells `level` loses the floor rather than escaping the
    // panel's. Expressing the rule as a property rather than a tier is what
    // puts the reason in `broker_cases.tp_stakes` for the reviewer to read.
    let request_props = TaskProperties::merge_opt(
        TaskProperties::from_tags(request_tags).as_ref(),
        ontology_governance::level_property_floor(request_tags).as_ref(),
    );
    let merged = TaskProperties::merge_opt(panel_props.as_ref(), request_props.as_ref());
    let declared = declared_tier(request_tags, request_content);
    let effective = governance::effective_tier(
        panel_props.as_ref(),
        request_props.as_ref(),
        declared,
        advertised_default,
    );

    let policy = panel_tags
        .map(governance::PanelPolicy::from_tags)
        .unwrap_or_default();

    // Only a case the member surface would otherwise hide is worth sampling:
    // sampling a case that is already shown changes nothing and would inflate
    // the `calibration_shown` denominator with cases nobody chose to show.
    let suppressible =
        governance::is_member_suppressed_effective(merged.as_ref(), effective, false);
    let calibration_sample = suppressible
        && governance::is_calibration_sample(
            calibration_key,
            case_id,
            policy.calibration_sample_rate,
        );

    // A `probe` tag is honoured ONLY from the panel's registered probe agent
    // (FR6.4). From anyone else it is noise that would corrupt the catch rate,
    // so it is dropped rather than recorded.
    let probe_digest = governance::extract_tag(request_tags, governance::TAG_PROBE)
        .filter(|_| policy.is_probe_agent(request_pubkey))
        .map(str::to_string);

    RequestBoundary {
        declared,
        effective,
        props: merged,
        calibration_sample,
        probe_digest,
        max_pending_hours: policy.max_pending_hours,
        // Only an ontology proposal has an expiry, and only one that declared a
        // `level` is an ontology proposal: reading `stale_after` off any 31402
        // would let an unrelated agent give its own case a self-serving
        // deadline.
        stale_after: ontology_governance::ProposalLevel::from_tags(request_tags)
            .and_then(|_| ontology_governance::stale_after_from_content(request_content)),
    }
}

/// The `broker_cases` columns the 31403 projection reads to hydrate a case
/// aggregate (COM-16). Deserialised straight from a D1 row.
#[derive(serde::Deserialize)]
pub(crate) struct BrokerCaseRow {
    pub category: String,
    pub state: String,
    /// The ADR-2011 effective tier, absent on cases projected before 0006.
    /// An absent tier imposes no human-resolution requirement of its own —
    /// the case predates the boundary rather than opting out of it.
    #[serde(default)]
    pub effective_tier: Option<String>,
    pub nostr_event_id: Option<String>,
    pub created_by: String,
    pub from_share_state: Option<String>,
    pub to_share_state: Option<String>,
}

/// The persistable result of projecting a 31403 onto a case: the row to append
/// to `broker_decisions` and the new `broker_cases.state`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResponseProjection {
    pub decision_id: String,
    /// `broker_decisions.outcome` — the canonical action string.
    pub outcome: String,
    /// `broker_decisions.outcome_detail` — delegate target / pattern id /
    /// precedent scope / amend diff; `None` for approve/reject.
    pub outcome_detail: Option<String>,
    pub prior_decision_id: Option<String>,
    /// `broker_cases.state` after the decision — never `under_review` for a
    /// well-formed outcome.
    pub new_state: governance::broker::CaseState,
    pub reasoning: String,
}

/// Plan the 31403 ActionResponse projection (COM-16 / F3).
///
/// This is the relay's consumer of the tested escalation state machine: it
/// hydrates a `BrokerCase` from the case's D1 row (a missing request remains
/// unresolved until a later redelivery) and
/// routes the parsed outcome through **`DecisionOrchestrator::decide`**, so a
/// `delegate`/`promote`/`precedent` outcome reaches the matching `CaseState`
/// instead of the former fixed `under_review` fallback. The `Env`/D1 read + write
/// stay in [`NostrRelayDO::project_action_response`]; this pure seam is what makes
/// the lifecycle unit-testable in the worker crate without a live D1.
///
/// ADR-2011 / DDD §6 invariants 4 and 8: a case whose **effective** tier is
/// `High` or `Critical` reaches `Decided` only through a *human* 31403. The
/// resolver is read from the response's own `decided_by` field, so a reasoner
/// stamping `system:whelk-gate` cannot close a case the boundary reserves for a
/// person. This is the assertion path EXP-AC-003 requires: the admission gate
/// already establishes that the signer is an admin or a delegated reviewer, and
/// this establishes that the *outcome* is a human's.
pub(crate) fn plan_action_response(
    case_id: &str,
    case_row: Option<&BrokerCaseRow>,
    event_id: &str,
    content: &str,
    responder_pubkey: &str,
    latest_decision_id: Option<String>,
    now: u64,
) -> std::result::Result<ResponseProjection, governance::broker::OrchestrationError> {
    use governance::broker::{
        CaseCategory, CaseSnapshot, CaseState, DecisionOrchestrator, DecisionOutcome, ShareState,
    };

    // Parse the typed outcome from the signed 31403 content; a malformed or
    // unknown action is rejected (the case is left untouched, never parked).
    let outcome = DecisionOutcome::from_response_content(content).ok_or_else(|| {
        governance::broker::OrchestrationError::ShareTransitionRejected(
            "unrecognised or malformed 31403 action response".to_string(),
        )
    })?;
    let reasoning = serde_json::from_str::<serde_json::Value>(content)
        .ok()
        .and_then(|v| {
            v.get("reasoning")
                .and_then(|r| r.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    let decision_id = format!("dec-{}", &event_id[..16.min(event_id.len())]);

    // Invariant 4: only a human closes a high/critical case. An absent
    // `effective_tier` is a case projected before 0006 and imposes nothing.
    let effective = case_row
        .and_then(|r| r.effective_tier.as_deref())
        .map(RiskTier::parse);
    if let Some(tier) = effective {
        let resolver = parse_resolver(content, responder_pubkey);
        if human_resolution_required(tier) && !resolver.is_human() {
            return Err(
                governance::broker::OrchestrationError::ShareTransitionRejected(format!(
                    "effective tier {} requires a human 31403; {:?} may not resolve it",
                    tier.as_str(),
                    resolver
                )),
            );
        }
    }

    if let Some(row) = case_row {
        if !matches!(
            row.state.as_str(),
            "open"
                | "under_review"
                | "reopened"
                | "decided"
                | "resolved"
                | "rejected"
                | "delegated"
                | "promoted"
                | "precedent"
                | "closed"
                | "superseded"
        ) {
            return Err(
                governance::broker::OrchestrationError::ShareTransitionRejected(
                    "unknown persisted case state; repair before deciding".into(),
                ),
            );
        }
    }
    let snapshot = match case_row {
        Some(row) => CaseSnapshot {
            id: case_id.to_string(),
            category: CaseCategory::parse(&row.category),
            created_by: row.created_by.clone(),
            state: CaseState::parse(&row.state),
            from_state: row.from_share_state.as_deref().and_then(ShareState::parse),
            to_state: row.to_share_state.as_deref().and_then(ShareState::parse),
            latest_decision_id,
        },
        None => {
            return Err(
                governance::broker::OrchestrationError::ShareTransitionRejected(
                    "request case has not projected; retry after request".to_string(),
                ),
            )
        }
    };

    // Hydrate the aggregate and route through the tested orchestrator.
    let mut case = snapshot.hydrate(now);
    let orch = DecisionOrchestrator;
    let report = orch.decide(
        &mut case,
        decision_id.clone(),
        outcome.clone(),
        responder_pubkey,
        reasoning.clone(),
        now,
    )?;

    Ok(ResponseProjection {
        decision_id,
        outcome: outcome.action_str().to_string(),
        outcome_detail: outcome.detail().map(str::to_string),
        prior_decision_id: report.entry.prior_decision_id.clone(),
        new_state: case.state,
        reasoning,
    })
}

/// F6 (DDD §7a): the derived decision id the relay assigns a governance event.
///
/// The 31403 projection keys `broker_decisions.decision_id` as `dec-<first 16
/// hex of the event id>`. Supersession references a *prior decision event* by
/// `e`-tag; resolving that event id to its decision id is this same deterministic
/// derivation, so the superseded row can be located without a second lookup.
pub(crate) fn decision_id_for_event(event_id: &str) -> String {
    format!("dec-{}", &event_id[..16.min(event_id.len())])
}

/// The persistable result of projecting a *superseding* 31403 onto a case
/// (F6, `DDD-judgment-broker-context.md` §7a). Distinct from
/// [`ResponseProjection`]: it also names the decision it supersedes, so the
/// projection can mark that prior row `superseded_by` (retained, auditable —
/// never mutated) while appending this one and moving the case to `Superseded`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SupersessionProjection {
    /// `broker_decisions.decision_id` of the superseding decision.
    pub decision_id: String,
    /// The decision id this supersedes: the superseding row's
    /// `prior_decision_id` AND the value written to the superseded row's
    /// `superseded_by` column.
    pub superseded_decision_id: String,
    pub outcome: String,
    pub outcome_detail: Option<String>,
    pub reasoning: String,
    /// `broker_cases.state` after the supersession — always `Superseded` for a
    /// well-formed, authorised supersede.
    pub new_state: governance::broker::CaseState,
}

/// Why a superseding 31403 was rejected at the projection (F6, DDD §7a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SupersessionError {
    /// The superseder is neither the original signer nor a higher governance
    /// role (§7a.1). The `RelayGovernanceGate` rejects this on ingest.
    Unauthorised { superseder: String },
    /// The superseding content carried no recognised `DecisionOutcome`.
    MalformedOutcome,
    /// No stated reason (§7a.2 point 3).
    MissingReason,
    /// The `supersedes` `e`-tag did not resolve to a prior decision.
    MissingSupersededDecision,
    /// The superseded decision belongs to a different case than the one the
    /// superseding event names in its `d` tag. Without this, a signer who may
    /// supersede on case B could mark case A's decision `superseded_by`.
    CaseMismatch,
    /// The superseded decision already has a successor; only the current
    /// effective decision of a case may be superseded.
    TargetAlreadySuperseded,
    /// The case's persisted state does not admit a supersession (an `open` or
    /// `under_review` case gets a first-order decision, not a supersession).
    StateNotSupersedable(String),
    /// The case named by the `d` tag has no row. Refused, not treated as a case
    /// created by the empty string.
    CaseMissing,
    /// The case's effective tier is `high` or `critical` and the superseding
    /// decision is machine-produced (ADR-2011 §4, DDD §6 invariant 4).
    HumanRequired,
    /// The superseder created the case (the aggregate's self-review guard).
    SelfReview,
}

impl SupersessionError {
    /// The wire token: `blocked: <token>` at ingest, or `stage_error` once the
    /// receipt exists.
    pub(crate) fn token(&self) -> String {
        match self {
            Self::Unauthorised { .. } => "supersession_unauthorised".into(),
            Self::MalformedOutcome => "supersession_outcome_malformed".into(),
            Self::MissingReason => "supersession_reason_missing".into(),
            Self::MissingSupersededDecision => "supersession_target_missing".into(),
            Self::CaseMismatch => "supersession_case_mismatch".into(),
            Self::TargetAlreadySuperseded => "supersession_target_already_superseded".into(),
            Self::StateNotSupersedable(state) => {
                format!("supersession_state_not_supersedable:{state}")
            }
            Self::CaseMissing => "supersession_case_missing".into(),
            Self::HumanRequired => "supersession_human_required".into(),
            Self::SelfReview => "self_review".into(),
        }
    }
}

/// What the relay read from D1 about the case a supersession targets, so the
/// plan can check the decision chain and the case state before the aggregate is
/// asked anything (the published aggregate's `supersede` never reads its state).
#[derive(Clone, Copy)]
pub(crate) struct SupersessionContext<'a> {
    /// The case named by the superseding event's own `d` tag.
    pub case_id: &'a str,
    /// The case the superseded decision row belongs to.
    pub superseded_case_id: &'a str,
    /// The superseded decision's `superseded_by`; `Some` means it is not effective.
    pub superseded_by: Option<&'a str>,
    /// The `d`-tag case's row; `None` when the case does not exist.
    pub case_row: Option<&'a BrokerCaseRow>,
}

/// Case states a supersession may act on, held with the batch SQL in `receipts`.
fn state_supersedable(state: &str) -> bool {
    receipts::SUPERSEDABLE_STATES.contains(&state)
}

/// The superseded decision row, as read at ingest and at projection.
#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct SupersededDecisionRow {
    /// Who signed the decision being superseded.
    pub broker_pubkey: String,
    /// The case the decision belongs to.
    pub case_id: String,
    /// Its successor, if it has been superseded already.
    #[serde(default)]
    pub superseded_by: Option<String>,
}

/// Why a superseding 31403 is refused at ingest, before it is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SupersessionRefusal {
    /// The `supersedes` `e` tag names no known decision.
    TargetMissing,
    /// The decision belongs to another case than the event's `d` tag.
    CaseMismatch,
    /// The decision already has a successor.
    TargetAlreadySuperseded,
    /// The signer is neither the original signer nor a higher governance role.
    Unauthorised,
}

impl SupersessionRefusal {
    /// The `OK false` reason sent to the signer.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::TargetMissing => "blocked: supersession_target_missing",
            Self::CaseMismatch => "blocked: supersession_case_mismatch",
            Self::TargetAlreadySuperseded => "blocked: supersession_target_already_superseded",
            Self::Unauthorised => "blocked: supersession_unauthorised",
        }
    }
}

/// The pure part of the ingest gate: the decision must exist, belong to the case
/// the event names, and still be effective. Authority is checked after, because
/// it needs the role ranks.
pub(crate) fn supersession_ingest_refusal(
    event_id: &str,
    case_id: &str,
    target: Option<&SupersededDecisionRow>,
) -> std::result::Result<(), SupersessionRefusal> {
    let target = target.ok_or(SupersessionRefusal::TargetMissing)?;
    if target.case_id != case_id {
        return Err(SupersessionRefusal::CaseMismatch);
    }
    // A redelivery of the very event that already superseded the target must
    // pass: NIP-01 wants a duplicate accepted (`OK true`), and the projection
    // reports it as `DuplicateIgnored`. Only a *different* successor refuses.
    match target.superseded_by.as_deref() {
        Some(by) if by != decision_id_for_event(event_id) => {
            Err(SupersessionRefusal::TargetAlreadySuperseded)
        }
        _ => Ok(()),
    }
}

/// Why an appeal is refused (stage error `projection-failed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AppealRefusal {
    /// The appellant is not the case's requester of record.
    NoStanding,
    /// The appeal cites no known decision.
    TargetMissing,
    /// The cited decision belongs to another case.
    TargetMismatch,
    /// The case is not in a terminal state; carries the state.
    NotAppealable(String),
    /// The named case has no row.
    CaseMissing,
}

impl AppealRefusal {
    /// The `stage_error` token.
    pub(crate) fn token(&self) -> String {
        match self {
            Self::NoStanding => "appeal_no_standing".into(),
            Self::TargetMissing => "appeal_target_missing".into(),
            Self::TargetMismatch => "appeal_target_mismatch".into(),
            Self::NotAppealable(state) => format!("case_not_appealable:{state}"),
            Self::CaseMissing => "case_missing".into(),
        }
    }
}

/// Plan an appeal: only the case's requester of record (`created_by`, compared
/// case-insensitively per KF-6) may appeal, the appeal must cite a decision on
/// that same case, and the case must be in an appealable terminal state.
///
/// The signer of the decision does not appeal, they supersede under §7a.1;
/// admins and other agents have no standing here. `APPEAL_REOPEN_SQL` repeats
/// the same three conditions so a case that moves between this read and the
/// batch changes nothing.
pub(crate) fn plan_appeal(
    appellant: &str,
    case_id: &str,
    case_row: Option<&BrokerCaseRow>,
    cited_decision_case_id: Option<&str>,
) -> std::result::Result<(), AppealRefusal> {
    let row = case_row.ok_or(AppealRefusal::CaseMissing)?;
    if !row.created_by.eq_ignore_ascii_case(appellant) {
        return Err(AppealRefusal::NoStanding);
    }
    let cited = cited_decision_case_id.ok_or(AppealRefusal::TargetMissing)?;
    if cited != case_id {
        return Err(AppealRefusal::TargetMismatch);
    }
    if !matches!(
        row.state.as_str(),
        "decided" | "delegated" | "promoted" | "precedent" | "superseded"
    ) {
        return Err(AppealRefusal::NotAppealable(row.state.clone()));
    }
    Ok(())
}

/// Ingest shape check for an appeal-marked 31402. The appeal must name its case
/// in a `case` tag, and its `d` tag (the replaceable key, NIP-33) must differ
/// from it: an appeal with `d` equal to the case id would replace the requester's
/// own original signed request, against ADR-2010's "preserve verifiable signed
/// decision history". `true` means the shape is refused.
pub(crate) fn appeal_shape_refused(event: &NostrEvent) -> bool {
    let d = governance::extract_d_tag(&event.tags).unwrap_or("");
    match filter::tag_value(event, "case") {
        Some(case) => case.is_empty() || d.is_empty() || case == d,
        None => true,
    }
}

/// Plan the *supersession* projection for a superseding kind-31403 (F6,
/// `DDD-judgment-broker-context.md` §7a).
///
/// Pure seam behind the async [`NostrRelayDO::project_supersession`] and the
/// ingest-time authority gate, mirroring how [`plan_action_response`] is the pure
/// seam over `DecisionOrchestrator::decide`. It:
///
/// 1. computes the §7a.1 authority (`supersede_authority`) from the original
///    signer + role ranks the relay supplies;
/// 2. routes the superseding decision through the single-sourced aggregate
///    `BrokerCase::supersede`, which enforces authority, a stated reason and
///    outcome-detail completeness, appends the superseding decision **without
///    mutating the prior one**, and moves the case to `Superseded`.
///
/// An unauthorised superseder yields `Err(Unauthorised)` — the testable rejection
/// the canon requires (§7a.4). `superseded_event_id` is the `e`-tag target;
/// `original_signer`/`original_rank`/`superseder_rank` and the
/// [`SupersessionContext`] are read from D1 by the async caller.
///
/// Before the aggregate is consulted the plan refuses (in this order): a missing
/// case, a superseded decision from another case, a decision that is no longer
/// effective, a case state that does not admit supersession, and a machine
/// decider on a high or critical case. These guards live here and in the batch
/// SQL, not in core: the published `BrokerCase::supersede` never reads its state.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_supersession(
    superseding_event_id: &str,
    superseded_event_id: Option<&str>,
    content: &str,
    superseder_pubkey: &str,
    original_signer: &str,
    original_rank: u8,
    superseder_rank: u8,
    ctx: &SupersessionContext<'_>,
    now: u64,
) -> std::result::Result<SupersessionProjection, SupersessionError> {
    use governance::broker::{
        supersede_authority, CaseCategory, CaseSnapshot, CaseState, DecisionOutcome,
    };

    let superseded_event_id =
        superseded_event_id.ok_or(SupersessionError::MissingSupersededDecision)?;
    if superseded_event_id.is_empty() {
        return Err(SupersessionError::MissingSupersededDecision);
    }
    let superseded_decision_id = decision_id_for_event(superseded_event_id);

    let outcome = DecisionOutcome::from_response_content(content)
        .ok_or(SupersessionError::MalformedOutcome)?;
    let reasoning = serde_json::from_str::<serde_json::Value>(content)
        .ok()
        .and_then(|v| {
            v.get("reasoning")
                .and_then(|r| r.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();

    let Some(row) = ctx.case_row else {
        return Err(SupersessionError::CaseMissing);
    };
    if ctx.superseded_case_id != ctx.case_id {
        return Err(SupersessionError::CaseMismatch);
    }
    if ctx.superseded_by.is_some() {
        return Err(SupersessionError::TargetAlreadySuperseded);
    }
    if !state_supersedable(&row.state) {
        return Err(SupersessionError::StateNotSupersedable(row.state.clone()));
    }
    if let Some(tier) = row.effective_tier.as_deref().map(RiskTier::parse) {
        if human_resolution_required(tier) && !parse_resolver(content, superseder_pubkey).is_human()
        {
            return Err(SupersessionError::HumanRequired);
        }
    }

    let authority = supersede_authority(
        original_signer,
        superseder_pubkey,
        original_rank,
        superseder_rank,
    );

    // Route through the single-sourced aggregate, hydrated with the case's real
    // persisted state. The snapshot's created_by preserves the self-review guard.
    let snapshot = CaseSnapshot {
        id: ctx.case_id.to_string(),
        category: CaseCategory::parse(&row.category),
        created_by: row.created_by.clone(),
        state: CaseState::parse(&row.state),
        from_state: None,
        to_state: None,
        latest_decision_id: Some(superseded_decision_id.clone()),
    };
    let mut case = snapshot.hydrate(now);
    let superseding_decision_id = decision_id_for_event(superseding_event_id);

    case.supersede(
        superseding_decision_id.clone(),
        superseded_decision_id.clone(),
        outcome.clone(),
        superseder_pubkey,
        reasoning.clone(),
        authority,
        now,
    )
    .map_err(|e| match e {
        governance::broker::CaseError::UnauthorisedSupersession { superseder } => {
            SupersessionError::Unauthorised { superseder }
        }
        governance::broker::CaseError::MissingSupersessionReason => {
            SupersessionError::MissingReason
        }
        governance::broker::CaseError::SelfReview { .. } => SupersessionError::SelfReview,
        _ => SupersessionError::MalformedOutcome,
    })?;

    Ok(SupersessionProjection {
        decision_id: superseding_decision_id,
        superseded_decision_id,
        outcome: outcome.action_str().to_string(),
        outcome_detail: outcome.detail().map(str::to_string),
        reasoning,
        new_state: case.state,
    })
}

/// ADR-099: resolve the EFFECTIVE principal a session's access derives from.
///
/// When device keys are enabled and the authing `pubkey` is a registered,
/// non-revoked device key, its session "acts as" the OWNER for READ scope and
/// the OWNER is the principal the write-gate allowlist is checked against. The
/// device's own signature is verified UNCHANGED upstream — this only rebinds
/// *who is treated as the principal* for access, never the event's pubkey/sig.
///
/// `device_owner` is the already-resolved `device_owner(pubkey)` D1 lookup
/// (`Some(owner)` for a non-revoked device row, `None` otherwise). `enabled` is
/// `DEVICE_KEYS_ENABLED == "true"`.
///
/// Gate-off (`enabled == false`) ⇒ identity passthrough: returns `pubkey`
/// verbatim, so a device key is just an unknown pubkey and every existing gate
/// behaves exactly as before. Gate-on with no device row ⇒ also passthrough.
///
/// Pure over its inputs so the resolution is unit-testable without a
/// `worker::Env` / D1.
/// Pure seam over [`NostrRelayDO::device_keys_enabled`]: the same decision,
/// taken on the raw `DEVICE_KEYS_ENABLED` value instead of a `worker::Env`, so
/// the relay's half of the ADR-2004 dual-worker gate is unit-testable natively.
/// Delegates to the shared rule — this crate defines no parse of its own.
pub fn device_keys_enabled_var(raw: Option<&str>) -> bool {
    core_device_keys_enabled(raw)
}

pub fn effective_principal(pubkey: &str, device_owner: Option<&str>, enabled: bool) -> String {
    if enabled {
        if let Some(owner) = device_owner {
            return owner.to_string();
        }
    }
    pubkey.to_string()
}

// ---------------------------------------------------------------------------
// NIP-01: EVENT handling
// ---------------------------------------------------------------------------

/// Project a 31402 into `broker_cases`, keyed by its `d` tag.
///
/// A case is created once, but it must follow the request the relay currently
/// holds: 31402 is parameterised-replaceable, so a re-post with the same `d`
/// replaces the stored event, and a 31403 is only projected when it cites the
/// case's `nostr_event_id` (`receipts.rs`). With `INSERT OR IGNORE` a re-post
/// left the case on the replaced (or swept) event, and every decision on the
/// live one was stored but never applied (2026-10-05: a429e066 → 16fd671f).
///
/// The update is narrow: same author, still undecided, and strictly newer than
/// the event the case points at (a missing event counts as oldest). It keeps
/// `created_at` (case age and ageing stay honest), `created_by`, the
/// calibration mark and the probe digest, so a re-post cannot reset the clock
/// or re-roll sampling.
pub(crate) const CASE_UPSERT_SQL: &str = "INSERT INTO broker_cases \
     (id, category, subject_kind, subject_id, title, summary, state, priority, \
      created_by, nostr_event_id, created_at, updated_at, \
      declared_tier, effective_tier, tp_verifiability, tp_reversibility, tp_stakes, \
      calibration_sample, probe_digest, max_pending_hours, stale_after) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'open', ?7, ?8, ?9, ?10, ?10, \
             ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19) \
     ON CONFLICT (id) DO UPDATE SET \
       category = excluded.category, subject_kind = excluded.subject_kind, \
       subject_id = excluded.subject_id, title = excluded.title, \
       summary = excluded.summary, priority = excluded.priority, \
       nostr_event_id = excluded.nostr_event_id, updated_at = excluded.updated_at, \
       declared_tier = excluded.declared_tier, effective_tier = excluded.effective_tier, \
       tp_verifiability = excluded.tp_verifiability, \
       tp_reversibility = excluded.tp_reversibility, tp_stakes = excluded.tp_stakes, \
       max_pending_hours = excluded.max_pending_hours, stale_after = excluded.stale_after \
     WHERE broker_cases.created_by = excluded.created_by \
       AND broker_cases.state IN ('open', 'under_review', 'reopened') \
       AND broker_cases.nostr_event_id <> excluded.nostr_event_id \
       AND excluded.updated_at > COALESCE( \
             (SELECT e.created_at FROM events e WHERE e.id = broker_cases.nostr_event_id), 0)";

impl NostrRelayDO {
    /// Resolve the configured NIP-42 enforcement mode (`AUTH_MODE`). Absent or
    /// unrecognised ⇒ the secure default (`nip42`). Reads a JS-boundary env var,
    /// so callers cache the result within a single handler invocation.
    pub(crate) fn auth_mode(&self) -> AuthMode {
        nip42::parse_auth_mode(
            self.env
                .var("AUTH_MODE")
                .ok()
                .map(|v| v.to_string())
                .as_deref(),
        )
    }

    /// The relay's own canonical URL (`RELAY_URL`), used to verify a client's
    /// NIP-42 `["relay", …]` tag. Returns `None` when unset/blank, which makes
    /// `evaluate_auth_event` skip the relay-tag check (fail-open on that
    /// defence-in-depth check only; the per-session challenge still applies).
    pub(crate) fn own_relay_url(&self) -> Option<String> {
        self.env
            .var("RELAY_URL")
            .ok()
            .map(|v| v.to_string())
            .filter(|s| !s.trim().is_empty())
    }

    pub(crate) async fn handle_event(
        &self,
        session_id: u64,
        ws: &WebSocket,
        ip: &str,
        event: NostrEvent,
    ) {
        // Rate limit
        if !self.check_rate_limit(ip) {
            Self::send_notice(ws, "rate limit exceeded");
            return;
        }

        // Validate event structure
        if !Self::validate_event(&event) {
            Self::send_ok(ws, &event.id, false, "invalid: event validation failed");
            return;
        }

        // NIP-40: refuse an expired `expiration` tag, and a malformed one — the
        // retention sweep would otherwise delete an accepted event silently.
        if let Err(reason) = filter::expiration_admission(&event, auth::js_now_secs()) {
            Self::send_ok(ws, &event.id, false, reason);
            return;
        }

        // Verify event ID and Schnorr signature before any side effects
        // including admission state changes or activity tracking.
        if nostr_bbs_core::verify_event_strict(&event).is_err() {
            Self::send_ok(
                ws,
                &event.id,
                false,
                "invalid: event id or signature verification failed",
            );
            return;
        }

        // PRD-010 G4: NIP-42 AUTH is the universal write gate. Resolve the mode
        // and whether THIS session completed the AUTH handshake ONCE, then reuse
        // both below (the mode read crosses the JS env boundary). In `nip42`
        // mode an unauthenticated session may not publish ANY event — including
        // gift wraps, which are still published over the sender's authenticated
        // socket even though the wrap itself is signed by an ephemeral key. The
        // allowlist check further down then applies as AUTHORISATION on the
        // authenticated identity (see `allowlist_denial_reason`).
        let auth_mode = self.auth_mode();
        let session_authed = self
            .sessions
            .borrow()
            .get(&session_id)
            .map(|s| s.authed_pubkey.is_some())
            .unwrap_or(false);
        if let Err(reason) = nip42::write_auth_ok(auth_mode, session_authed) {
            Self::send_ok(ws, &event.id, false, reason);
            return;
        }

        // ADR-099: resolve the effective principal ONCE, and only now: the
        // lookup costs a D1 read and a cache entry per distinct key, so it must
        // not run for events that fail verification or the write gate, nor for
        // gift wraps (a fresh one-time key each, never a device). A registered
        // device key acts for its owner for ALLOWLIST, TRUST LEVEL and ZONE WRITE
        // only; SANCTIONS (suspension, silence, ban) apply to the key AND the
        // owner; ADMIN status stays the raw signing key's own, so a device key
        // never inherits admin powers. Gate-off / non-device ⇒ `principal ==
        // event.pubkey`. The RSVP cohort check, the posts_created counter, the
        // activity stamp and the delete-any trust level below also use the
        // principal, so they agree with the trust level and zone-write path that
        // resolve through the owner; the mesh-peer, agent, reviewer, delegation
        // and supersession checks, NIP-09 own-event scope and moderation
        // mirroring stay on the raw signing key.
        let principal = if needs_owner_lookup(event.kind) {
            self.effective_pubkey(&event.pubkey).await
        } else {
            event.pubkey.clone()
        };
        let sanction_subjects = sanction_subjects(&event.pubkey, &principal);

        // NIP-59 gift wraps (kind-1059) are signed by a fresh ephemeral key per
        // message, so the author is intentionally NOT a member and the standard
        // author-membership check would always reject them. Instead, gate on the
        // RECIPIENT carried in the first `["p", <hex>]` tag: accept only if that
        // recipient is a whitelisted member. This bounds gift-wrap acceptance to
        // messages addressed to existing members (no spam to non-members) while
        // permitting the ephemeral author.
        if event.kind == GIFT_WRAP_KIND {
            // A recipient declared in config (`INGRESS_RECIPIENTS`) is admitted
            // without a D1 row, so an operator reset cannot silence it. Every
            // other recipient still has to be whitelisted.
            let ingress = crate::ingress::ingress_from_env(&self.env);
            let is_ingress = gift_wrap_recipient(&event)
                .is_some_and(|pk| nostr_bbs_config::ingress::is_ingress_recipient(&ingress, &pk));
            if let Err(refusal) = self.gift_wrap_recipient_verdict(&event, is_ingress).await {
                Self::send_ok(ws, &event.id, false, refusal);
                return;
            }
        } else {
            // ADR-099: a device-authored event is admitted under its OWNER's
            // allowlist. `effective_pubkey` returns the owner for a registered
            // non-revoked device key when DEVICE_KEYS_ENABLED, else the author
            // pubkey verbatim (gate-off / non-device ⇒ unchanged behaviour). The
            // event's signature was already verified strictly above against the
            // device's own key; we only rebind WHO the allowlist is checked for.
            if !self.is_whitelisted(&principal).await {
                // NIP-42 semantics: a denial AFTER a completed AUTH is
                // `restricted:` (authenticated but not authorised), distinct
                // from `auth-required:`. Legacy `allowlist` mode keeps the
                // historical `blocked:` message.
                let reason = nip42::allowlist_denial_reason(auth_mode, session_authed);
                Self::send_ok(ws, &event.id, false, reason);
                return;
            }
        }

        // F11 (PRD-010): When mesh federation is active, events arriving from
        // a recognised mesh peer (listed in MESH_ALLOWED_REMOTE_DIDS) are
        // filtered against the federated_kinds allowlist. Local clients whose
        // pubkey is NOT in the remote DIDs list bypass this check entirely.
        if self.is_mesh_peer(&event.pubkey) && !self.is_federated_kind_allowed(event.kind) {
            Self::send_ok(
                ws,
                &event.id,
                false,
                "blocked: event kind not in federated_kinds allowlist",
            );
            return;
        }

        // Suspension and silence check: the device key OR its owner being
        // sanctioned blocks the event.
        for subject in &sanction_subjects {
            let (suspended, silenced) = trust::check_suspension(subject, &self.env).await;
            if suspended {
                Self::send_ok(ws, &event.id, false, "blocked: account suspended");
                return;
            }
            if silenced {
                Self::send_ok(
                    ws,
                    &event.id,
                    false,
                    "blocked: account silenced (read-only)",
                );
                return;
            }
        }

        // WI-2: moderation ingress check against moderation_actions (60s DO
        // cache). Applies to EVERY user-authored content kind a banned/muted
        // author must not publish (see `is_ban_gated_kind`) — not just kind-1
        // and kind-42, which let bans leak through reactions, deletions,
        // reports, articles and calendar events. Admins bypass so they can e.g.
        // publish warnings even while under moderation for other reasons.
        //
        // P2-03: use admin_cache to avoid redundant D1 queries on every event.
        if is_ban_gated_kind(event.kind)
            && !self.admin_cache.is_admin(&event.pubkey, &self.env).await
        {
            for subject in &sanction_subjects {
                if self.mod_cache.is_blocked(subject, &self.env).await {
                    Self::send_ok(ws, &event.id, false, "blocked: author is banned or muted");
                    return;
                }
            }
        }

        // Trust-level gating for specific event kinds
        // P2-03: cached lookup — same TTL entry reused from above if still fresh.
        let is_admin = self.admin_cache.is_admin(&event.pubkey, &self.env).await;
        if !is_admin {
            let trust_level = trust::get_trust_level(&principal, &self.env).await;

            // kind-40 (channel creation): TL2+ required
            if event.kind == 40 && trust_level < TrustLevel::Regular {
                Self::send_ok(
                    ws,
                    &event.id,
                    false,
                    "restricted: TL2+ required for channel creation",
                );
                return;
            }

            // kind-41 (channel metadata/pin): TL2+ for own channel, TL3+ for any
            if event.kind == 41 {
                let Some(channel_id) = filter::channel_tag(&event) else {
                    Self::send_ok(ws, &event.id, false, "invalid: missing channel tag");
                    return;
                };
                if trust_level < TrustLevel::Regular {
                    Self::send_ok(
                        ws,
                        &event.id,
                        false,
                        "restricted: TL2+ required for channel metadata",
                    );
                    return;
                }
                // If TL2 (not TL3), verify they are the channel creator
                if trust_level < TrustLevel::Trusted
                    && !self
                        .is_channel_creator(&sanction_subjects, &channel_id)
                        .await
                {
                    Self::send_ok(
                        ws,
                        &event.id,
                        false,
                        "restricted: TL3+ required to modify others' channels",
                    );
                    return;
                }
            }

            // kind-1984 (report): TL1+ required
            if event.kind == KIND_REPORT_NIP56 && trust_level < TrustLevel::Member {
                Self::send_ok(
                    ws,
                    &event.id,
                    false,
                    "restricted: TL1+ required to report content",
                );
                return;
            }

            // kind-5 (deletion): own events always allowed; others' events require TL3+
            if event.kind == 5 {
                let targets_others = self.deletion_targets_others(&event).await;
                if targets_others && trust_level < TrustLevel::Trusted {
                    Self::send_ok(
                        ws,
                        &event.id,
                        false,
                        "restricted: TL3+ required to delete others' events",
                    );
                    return;
                }
            }
        }

        // NIP-29: Admin-only group management kinds
        if is_nip29_admin_kind(event.kind) {
            // NIP-29 TODO: This enforces the h-tag/admin gate, but full group
            // metadata should be relay-key-generated rather than accepted from
            // arbitrary clients.
            if filter::tag_value(&event, "h").is_none() {
                Self::send_ok(ws, &event.id, false, "invalid: missing group tag");
                return;
            }
            if !is_admin {
                Self::send_ok(ws, &event.id, false, "blocked: admin-only group action");
                return;
            }
        }

        // Agent Control Surface Protocol: governance kinds (31400-31405) are
        // only accepted from pubkeys registered in the agent_registry table.
        // Human responses (kind 31403, approve/reject of agent action requests)
        // are exempt from the agent-registry gate but, per P1-6, MUST come from
        // an admin -- they are privileged decisions, not generic member actions.
        //
        // Kanban exception: a kanban approval request (31402 tagged `k=30302`)
        // is a MEMBER-initiated ask — "may this card enter the approval-gated
        // column?" — so it is admitted from any whitelisted author (whitelist
        // admission already ran above). Decisions stay admin-only 31403; every
        // other 31402 remains agent-registry-gated.
        if governance::is_governance_kind(event.kind)
            && event.kind != governance::KIND_ACTION_RESPONSE
            && !nostr_bbs_core::is_kanban_approval_request(&event)
            && !self.is_registered_agent(&event.pubkey).await
        {
            Self::send_ok(
                ws,
                &event.id,
                false,
                "blocked: pubkey not in agent registry",
            );
            return;
        }

        // P1-6 + FR6.2: kind-31403 ActionResponse is admin-only, EXCEPT for a
        // `reviewer`-role pubkey deciding a case an admin explicitly delegated
        // to it. That exception is what lets a junior reviewer do substantive
        // review work (C5) without being handed the whole governance surface:
        // the delegation is scoped to one case and the delegating admin stays
        // on the row. Everyone else is refused exactly as before.
        if event.kind == governance::KIND_ACTION_RESPONSE {
            let case_id = governance::extract_d_tag(&event.tags).unwrap_or_default();
            let (is_reviewer, delegated) = if is_admin || case_id.is_empty() {
                (false, false)
            } else {
                (
                    self.is_reviewer(&event.pubkey).await,
                    self.is_delegated_for_case(case_id, &event.pubkey).await,
                )
            };
            let admission = response_admission(is_admin, is_reviewer, delegated);
            if !admission.is_admitted() {
                Self::send_ok(ws, &event.id, false, admission.reason());
                return;
            }

            // FR2.2: a decision on a consequential case must carry the human's
            // own words. Enforced HERE, before `save_event`, because a 31403 is
            // a signed event any client or script can publish straight to the
            // relay — a rule that lives only in the forum UI is a suggestion,
            // and the point of FR2.2 is that a signed decision represents a
            // judgement a human actually formed. A refusal never fills the
            // rationale in; absence is refused, not papered over.
            if !case_id.is_empty() {
                if let Some(effective) = self.case_effective_tier(case_id).await {
                    let (action, reasoning) = response_action_and_reasoning(&event.content);
                    if let Some(action) = action {
                        if let Err(e) =
                            governance::check_rationale(effective, &action, reasoning.as_deref())
                        {
                            Self::send_ok(ws, &event.id, false, e.reason());
                            return;
                        }
                    }
                }
            }
        }

        // F6 (DDD §7a.1): a *superseding* kind-31403 — one carrying an `e`-tag
        // with the `supersedes` marker — is additionally authority-gated. Only
        // the original decision's signer, or a human of a strictly higher
        // governance role, may supersede a published decision. The
        // `RelayGovernanceGate` rejects any other superseder here, exactly as it
        // rejects an orphan response under Invariant 2 — before the event is
        // saved or projected.
        if event.kind == governance::KIND_ACTION_RESPONSE {
            if let Some(superseded_event_id) = governance::extract_supersedes_target(&event.tags) {
                let case_id = governance::extract_d_tag(&event.tags).unwrap_or("");
                if let Err(refusal) = self
                    .supersession_authorised(&event.pubkey, &event.id, case_id, superseded_event_id)
                    .await
                {
                    Self::send_ok(ws, &event.id, false, refusal.reason());
                    return;
                }
            }
        }

        // Appeal standing (DDD §7a.2): an appeal-marked 31402 must name its case in
        // a `case` tag distinct from its `d` tag, or it would replace the
        // requester's own signed request. Refused before storage, so no receipt.
        if event.kind == governance::KIND_ACTION_REQUEST
            && governance::extract_appeal_target(&event.tags).is_some()
            && appeal_shape_refused(&event)
        {
            Self::send_ok(ws, &event.id, false, "blocked: appeal_shape");
            return;
        }

        // Zone enforcement for channel messages (kind-42)
        if event.kind == 42 {
            let Some(channel_id) = filter::channel_tag(&event) else {
                Self::send_ok(ws, &event.id, false, "invalid: missing channel tag");
                return;
            };
            // Only a channel EXPLICITLY bound to a zone (a `channel_zones` row,
            // written solely by the admin-only /api/admin/channel-zone endpoint)
            // is write-gated. An undeclared channel is UNSCOPED: it belongs to no
            // private zone, so any whitelisted member (already gated above) may
            // post to it.
            //
            // Finding-5 fix: this previously defaulted an undeclared channel to
            // the "home" zone. Absent a matching ZONE_CONFIG entry (the four-zone
            // model ships public/friends/family/business, no "home"), the write
            // gate then denied ALL non-admins — silently write-locking every
            // freshly-created channel to admins until an admin bound it. Since
            // channel creation never writes `channel_zones`, that lockout was
            // permanent for non-admin-created channels, including the creator's
            // own new channel. Writes route through the write gate
            // (write_cohorts ?? required_cohorts) so a public zone can still be
            // read-by-all yet write-restricted.
            let zone = self.cached_channel_zone(&channel_id).await;
            // ADR-2017: sealed originals are admin-only and belong to encrypted
            // zones. They are exempt from the drift check in `validate_event`,
            // so this gate must reject every other shape, including a sealed
            // envelope into an unscoped channel from an admin.
            let sealed = nostr_bbs_core::sealed::has_sealed_tag(&event.tags);
            if sealed {
                let zone_encrypted = zone
                    .as_deref()
                    .map(|z| ZoneConfig::load(&self.env).is_encrypted(z));
                if let Some(reason) = sealed_write_rejection(sealed, is_admin, zone_encrypted) {
                    Self::send_ok(ws, &event.id, false, reason);
                    return;
                }
            }
            if let Some(zone) = zone {
                if !is_admin && !trust::has_zone_write_access(&principal, &zone, &self.env).await {
                    Self::send_ok(ws, &event.id, false, "zone access denied");
                    return;
                }
                // Encrypted zones store no readable text — for anyone, admins
                // included. Shape check only; the relay holds no zone key.
                if crate::zone_config::ZoneConfig::load(&self.env).is_encrypted(&zone)
                    && !crate::zone_config::is_zone_ciphertext(&zone, &event.tags, &event.content)
                {
                    Self::send_ok(
                        ws,
                        &event.id,
                        false,
                        "blocked: encrypted zone requires zone-key ciphertext",
                    );
                    return;
                }
            }
        }

        // Phase C (write side): NIP-52 calendar kinds carry their access binding
        // natively, not via a channel-id lookup. The READ path projects them
        // per-tier; the WRITE path must validate the author against the SAME
        // data-tier rules so a lower-tier author cannot inject an RSVP into, or a
        // calendar event onto, a zone they cannot fully see/write.
        //
        //   - 31925 RSVP: an RSVP attaches the author to a target event. If the
        //     author can only see that target as free/busy (or not at all), the
        //     RSVP is a privacy/integrity leak — it surfaces participation in an
        //     event the author isn't a full participant of. We resolve the TARGET
        //     from D1 (never an author-mirrored tag, which is spoofable) and
        //     compute the AUTHOR's projection tier for it; accept only on Full.
        //     Admins/owners are inherently Full. An unresolvable target denies for
        //     non-admins (deny-by-default: blocks pre-publishing RSVPs to a target
        //     that isn't visible yet).
        //
        //   - 31922/31923 calendar events: a zone-tagged event must come from an
        //     author with write access to that zone (mirrors kind-42). Untagged
        //     calendar events are unscoped and keep prior behaviour.
        if event.kind == KIND_CALENDAR_RSVP && !is_admin {
            let permitted = match self.resolve_rsvp_target(&event).await {
                Some((zone, venue)) => {
                    // `is_owner=false`: a non-admin author is never the relay owner.
                    // `project_tier` short-circuits admins/owners to Full anyway;
                    // here we ask the author's own tier for the TARGET's real zone.
                    let (author_cohorts, author_cohort_admin) =
                        self.cached_viewer_cohorts(&principal).await;
                    let tier = calendar_projection::project_tier(
                        &author_cohorts,
                        &zone,
                        venue.as_deref(),
                        false,
                        author_cohort_admin,
                    );
                    rsvp_write_permitted(&tier)
                }
                // Target not resolvable: deny by default for non-admins. Prevents
                // pre-publishing an RSVP to an event that is not yet visible.
                None => false,
            };
            if !permitted {
                Self::send_ok(ws, &event.id, false, "blocked: rsvp not permitted");
                return;
            }
        } else if (matches!(
            event.kind,
            nostr_bbs_core::KIND_CALENDAR_DATE_EVENT | nostr_bbs_core::KIND_CALENDAR_EVENT
        ) || nostr_bbs_core::is_kanban_kind(event.kind))
            && !is_admin
        {
            // Only zone-tagged calendar/kanban events are write-gated; untagged
            // events are unscoped and retain prior behaviour. Kanban boards and
            // cards (30301/30302) carry the same zone-binding tag as calendar
            // events and follow the identical rule: writing into a zone requires
            // that zone's effective write cohorts.
            let zone = nostr_bbs_core::read_zone_tag(&event);
            let has_write = match zone {
                Some(z) => trust::has_zone_write_access(&principal, z, &self.env).await,
                None => false,
            };
            if !calendar_write_permitted(zone, has_write) {
                Self::send_ok(ws, &event.id, false, "blocked: zone access denied");
                return;
            }
        }

        // NIP-16 event treatment
        let treatment = event_treatment(event.kind);

        if treatment == EventTreatment::Ephemeral {
            Self::send_ok(ws, &event.id, true, "");
            self.broadcast_event(&event).await;
            return;
        }

        // ADR-2023: `save_event` answers `true` for an id it already holds, so
        // note a repeat submission now (before the insert) and let it not alert
        // anyone a second time.
        let push_repeat = self.push_event_known(&event).await;

        // Save to D1
        if self.save_event(&event, treatment).await {
            Self::send_ok(ws, &event.id, true, "");
            self.broadcast_event(&event).await;
            // Activity tracking: increment posts_created and update last_active
            // for content-producing event kinds (kind-1 text, kind-9 chat, kind-42 channel msg,
            // kind-40 channel create, kind-7 reaction, kind-1984 report).
            if counts_as_post(event.kind) {
                trust::increment_posts_created(&principal, &self.env).await;
            }
            // ADR-2018: the `last_active_at` stamp and promotion check are
            // coalesced to one flush per pubkey per window; `posts_created`
            // above stays exact because it is the promotion counter itself.
            self.note_write_activity(&principal).await;

            // NIP-09: Process deletion events. Same-author targets always
            // delete; admins and TL3+ (Trusted) may delete anyone's events —
            // the moderation privilege the earlier kind-5 gate admits. The
            // flag is re-derived here because `trust_level` is scoped to the
            // non-admin gating block above (admins skip it entirely).
            if event.kind == 5 {
                let can_delete_any = is_admin
                    || trust::get_trust_level(&principal, &self.env).await >= TrustLevel::Trusted;
                self.process_deletion(&event, can_delete_any).await;
            }

            // NIP-56: Process report events -- insert into reports table and check auto-hide
            if event.kind == KIND_REPORT_NIP56 {
                self.process_report(&event).await;
            }

            // WI-2 + P0-4(a): mirror moderation-action Nostr events (kind 30910
            // ban, 30911 mute, 30915 unban, 30916 unmute) into the local
            // `moderation_actions` table so the ingress gate can reject content
            // from muted/banned authors AND so a lifted ban/mute stops being
            // enforced. Only respected when the signer is an admin on this relay.
            if matches!(event.kind, KIND_BAN | KIND_MUTE | KIND_UNBAN | KIND_UNMUTE) && is_admin {
                self.mirror_moderation_action(&event).await;
                if let Some(target) = filter::tag_value(&event, "p") {
                    self.mod_cache.invalidate(&target);
                }
            }

            // Agent Control Surface: project ActionRequest events (31402)
            // into the broker_cases table for D1-queryable governance inbox.
            // F6 (DDD §7a.2): an ActionRequest carrying an `appeal` `e`-tag
            // marker is an *appeal* — it reopens the cited case rather than
            // opening a fresh one.
            if event.kind == governance::KIND_ACTION_REQUEST {
                if governance::extract_appeal_target(&event.tags).is_some() {
                    let receipt = self.project_appeal(&event).await;
                    if !receipt.is_applied() {
                        console_warn!(
                            "governance appeal {} accepted but not applied: {:?}",
                            &event.id,
                            receipt
                        );
                    }
                } else {
                    self.project_action_request(&event).await;
                }
            }

            // Agent Control Surface: project ActionResponse events (31403)
            // into broker_decisions and update the broker_cases state. F6 (DDD
            // §7a): a *superseding* response (with a `supersedes` `e`-tag) marks
            // the superseded decision `Superseded` and chains forward, rather
            // than recording a first-order decision.
            if event.kind == governance::KIND_ACTION_RESPONSE {
                if governance::extract_supersedes_target(&event.tags).is_some() {
                    let receipt = self.project_supersession(&event).await;
                    if !receipt.is_applied() {
                        console_warn!(
                            "governance supersession {} accepted but not applied: {:?}",
                            &event.id,
                            receipt
                        );
                    }
                } else {
                    // ADR-2010: the OK above certified storage only. If the
                    // decision did not reach `projection-committed`, the
                    // response is accepted but NOT applied — say so, rather
                    // than letting the relay's OK stand as the last word.
                    let receipt = self.project_action_response(&event).await;
                    if !receipt.is_applied() {
                        console_warn!(
                            "governance response {} accepted but not applied: {:?}",
                            &event.id,
                            receipt
                        );
                    }
                }
            }

            // ADR-2023: wake members whose app is closed. Last, so the DO's
            // own bookkeeping above never queues behind recipient lookups;
            // the sender already has their OK, and the pushes themselves go
            // out under `wait_until`.
            if !push_repeat {
                let submitter = self
                    .sessions
                    .borrow()
                    .get(&session_id)
                    .and_then(|s| s.authed_pubkey.clone());
                self.push_fanout(&event, submitter).await;
            }
        } else {
            Self::send_ok(ws, &event.id, false, "error: failed to save event");
        }
    }

    fn validate_event(event: &NostrEvent) -> bool {
        if event.id.len() != 64 || event.pubkey.len() != 64 || event.sig.len() != 128 {
            return false;
        }

        let is_reg = event.kind == 0 || event.kind == 9024;
        let max_content = if is_reg {
            MAX_REGISTRATION_CONTENT_SIZE
        } else {
            MAX_CONTENT_SIZE
        };
        if event.content.len() > max_content {
            return false;
        }

        if event.tags.len() > MAX_TAG_COUNT {
            return false;
        }
        for tag in &event.tags {
            for v in tag {
                if v.len() > MAX_TAG_VALUE_SIZE {
                    return false;
                }
            }
        }

        timestamp_drift_ok(event, auth::js_now_secs())
    }
}

// ---------------------------------------------------------------------------
// ADR-2017: sealed originals — pure relay decisions
// ---------------------------------------------------------------------------

/// Reject text for a sealed original from a non-admin author (ADR-2017).
pub(crate) const SEALED_ADMIN_ONLY: &str = "blocked: sealed originals are admin-only";

/// Reject text for a sealed original outside an encrypted zone (ADR-2017).
pub(crate) const SEALED_ENCRYPTED_ZONES_ONLY: &str =
    "blocked: sealed originals belong to encrypted zones";

/// Whether `event` is exempt from the [`MAX_TIMESTAMP_DRIFT`] check because it
/// is a sealed-original envelope (ADR-2017).
///
/// An envelope keeps its original's `created_at` so relay pagination and
/// ordering and clients' unread logic stay correct; migrated history is
/// usually far older than seven days. `validate_event` runs before admin
/// status is known, so the exemption is keyed on the tag alone and is safe
/// only because [`sealed_write_rejection`] then refuses the event unless the
/// author is an admin writing into an encrypted zone.
///
/// The exemption needs a **well-formed** marker
/// ([`nostr_bbs_core::sealed::parse_sealed`]) while the write gate fires on
/// **any** `sealed` tag ([`nostr_bbs_core::sealed::has_sealed_tag`]), so a
/// malformed marker can never buy the exemption without also hitting the gate.
pub(crate) fn sealed_drift_exempt(event: &NostrEvent) -> bool {
    event.kind == 42 && nostr_bbs_core::sealed::parse_sealed(&event.tags).is_some()
}

/// The `created_at` bound of `validate_event`, at wall-clock time `now`.
///
/// Every event must lie within [`MAX_TIMESTAMP_DRIFT`] of `now`. A sealed
/// original ([`sealed_drift_exempt`]) is exempt only from the *past* bound:
/// it re-publishes an event the relay once accepted, so its `created_at` can
/// be old but never further in the future than a live post's.
pub(crate) fn timestamp_drift_ok(event: &NostrEvent, now: u64) -> bool {
    if event.created_at <= now && sealed_drift_exempt(event) {
        return true;
    }
    now.abs_diff(event.created_at) <= MAX_TIMESTAMP_DRIFT
}

/// The ADR-2017 write rule for a kind-42 into a channel, or `None` to fall
/// through to the ordinary zone gate.
///
/// - `sealed`: the event carries any `sealed` tag, well formed or not
///   ([`nostr_bbs_core::sealed::has_sealed_tag`]).
/// - `is_admin`: the author is a relay admin.
/// - `zone_encrypted`: `None` when the channel is unscoped (no
///   `channel_zones` row), else whether its zone is encrypted.
///
/// Order matters: an unscoped channel otherwise lets any member post, so the
/// encrypted-zone rule must reject a sealed envelope there even from an
/// admin. The ADR-2016 ciphertext rule (`zone_config::is_zone_ciphertext`)
/// still applies afterwards, so an accepted envelope always carries a
/// well-formed `zk` tag and NIP-44 v2-shaped content.
pub(crate) fn sealed_write_rejection(
    sealed: bool,
    is_admin: bool,
    zone_encrypted: Option<bool>,
) -> Option<&'static str> {
    if !sealed {
        return None;
    }
    if !is_admin {
        return Some(SEALED_ADMIN_ONLY);
    }
    if zone_encrypted != Some(true) {
        return Some(SEALED_ENCRYPTED_ZONES_ONLY);
    }
    None
}

// ---------------------------------------------------------------------------
// NIP-01: REQ / CLOSE handling
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    pub(crate) async fn handle_req(
        &self,
        session_id: u64,
        ip: &str,
        sub_id: &str,
        filters: Vec<NostrFilter>,
    ) {
        let ws = {
            let sessions = self.sessions.borrow();
            match sessions.get(&session_id) {
                Some(s) => s.ws.clone(),
                None => return,
            }
        };

        // Per-IP rate limit, consistent with the EVENT path. REQ was previously
        // ungated, letting one IP drive unbounded D1 scans; gate it identically.
        if !self.check_rate_limit(ip) {
            Self::send_notice(&ws, "rate limit exceeded");
            return;
        }

        // Check subscription limit
        {
            let sessions = self.sessions.borrow();
            if let Some(session) = sessions.get(&session_id) {
                if session.subscriptions.len() >= MAX_SUBSCRIPTIONS {
                    Self::send_notice(&ws, "too many subscriptions");
                    return;
                }
            }
        }

        // Determine the requesting session's pubkey and zone access for filtering
        let session_pubkey = {
            let sessions = self.sessions.borrow();
            sessions
                .get(&session_id)
                .and_then(|s| s.authed_pubkey.clone())
        };

        // PRD-010 G4: protected-kind reads ({4,13,14,1059,30910-30916}) require
        // an authenticated session in nip42 mode. Reject the whole subscription
        // with CLOSED (NIP-42 semantics) before any D1 query. Public kinds stay
        // open to unauthenticated sockets. kind-1059's own gate + mandatory #p
        // rewrite still runs below in BOTH modes, so DM privacy never depends on
        // AUTH_MODE.
        //
        // ORDERING IS LOAD-BEARING (auth-bypass, found by deepsec-gate). Both
        // gates run BEFORE the subscription is stored, and what is stored is the
        // GATED filter, never the client's raw one. The previous order stored
        // `filters.clone()` first and shadowed the gated filters into a local
        // used only for the immediate `query_events`: a rejected subscription
        // stayed in `session.subscriptions`, and `broadcast_event` then matched
        // live events against the un-gated filter. The historical read was
        // refused and every subsequent matching event was delivered anyway.
        if nip42::protected_read_blocked(&filters, session_pubkey.is_some(), self.auth_mode()) {
            Self::send_closed(
                &ws,
                sub_id,
                "auth-required: authentication required to read protected kinds",
            );
            return;
        }

        // NIP-59: kind-1059 (Sealed DM) read gate + mandatory #p rewrite. Shared
        // with the COUNT path so both reject unauthenticated kind-1059 reads and
        // bind results to the authed recipient identically.
        let read_set = self.recipient_read_set(&session_pubkey).await;
        let filters = match Self::gate_kind_1059_filters_with(
            filters,
            &session_pubkey,
            read_set.as_deref(),
        ) {
            Some(f) => f,
            None => {
                Self::send_notice(
                    &ws,
                    "auth-required: must authenticate to receive kind-1059 DMs",
                );
                return;
            }
        };

        // Store the AUTHORISED subscription — never the raw client filter — so
        // the live broadcast path matches against exactly what the gates above
        // permitted.
        {
            let mut sessions = self.sessions.borrow_mut();
            if let Some(session) = sessions.get_mut(&session_id) {
                session
                    .subscriptions
                    .insert(sub_id.to_string(), filters.clone());
            }
        }

        // Persist subscriptions to DO storage so they survive hibernation
        self.save_subscriptions(session_id).await;

        // Query D1 for matching events
        let events = self.query_events(&filters).await;

        // Resolve the viewer's effective read scope once (ADR-099 device→owner
        // rebinding, admin status, calendar cohorts), then apply the SHARED
        // per-event zone/cohort/NIP-52-calendar gate (`authorize_event`). The
        // exact same gate runs on the COUNT and live-broadcast paths, so the
        // three read paths can never diverge on what a viewer may read.
        let zones = ZoneConfig::load(&self.env);
        let ctx = self.resolve_viewer_context(session_pubkey.clone()).await;

        // Count events actually DELIVERED to the reader this REQ (post-gate). An
        // event withheld by zone access was never read, so we tally survivors and
        // batch a single `posts_read` increment at EOSE for the TL0→TL1 promotion.
        let mut delivered: i32 = 0;
        for event in &events {
            let readable = match &read_set {
                Some(set) => gift_wrap_readable_by_any(event, set),
                None => gift_wrap_readable_by(event, session_pubkey.as_deref()),
            };
            if !readable {
                continue;
            }
            match self.authorize_event(event, &ctx, &zones).await {
                ReadDecision::Deliver => {
                    Self::send_event(&ws, sub_id, event);
                    delivered += 1;
                }
                ReadDecision::DeliverAs(out) => {
                    Self::send_event(&ws, sub_id, &out);
                    delivered += 1;
                }
                ReadDecision::Withhold => {}
            }
        }
        Self::send_eose(&ws, sub_id);

        // O1: count this REQ's reads toward TL0→TL1 promotion. Gate on an
        // authenticated session and at least one delivered event; the
        // `increment_posts_read_by` UPDATE is whitelist-scoped, so a
        // non-member authed pubkey is a harmless no-op. We charge the read to
        // the literal session pubkey (the identity that subscribed), not the
        // device→owner `access_pubkey` rebinding used for zone reads. After the
        // batched increment, run the same `check_promotion` the EVENT path uses
        // so a reader can cross the threshold without needing to also write.
        //
        // ADR-2018: the increment, the `last_active_at` stamp (ADR-102: a
        // delivered read is activity, so a read-only member's inactivity clock
        // resets) and the promotion check are coalesced by `ActivityLedger`
        // into one flush per pubkey per window instead of three D1 writes per
        // frame. The UPDATEs are whitelist-scoped, so a non-member authed
        // pubkey is a harmless no-op.
        if delivered > 0 {
            if let Some(pk) = &session_pubkey {
                self.note_read_activity(pk, delivered).await;
            }
        }
    }

    /// Phase C: project a single NIP-52 calendar event for one viewer.
    ///
    /// The projector is the COMPLETE access decision — there is no upstream zone
    /// read-gate for calendar kinds. A live probe proved a gate-then-project
    /// ordering wrong: the gate omitted any event in a zone the viewer was not a
    /// member of, so the FreeBusy / cross-zone-Full tiers never ran. The pure
    /// projector applies the operator-approved matrix end to end
    /// (full / free-busy-redacted / omit), deny-by-default for unknown zones.
    ///
    /// For RSVPs (kind 31925) the target event's zone AND venue are resolved from
    /// the STORED referenced event (never from an author-mirrored tag on the RSVP,
    /// which is spoofable with the gate removed). The RSVP is served only when the
    /// viewer's tier for the target is `Full` — an RSVP leaks participants, so a
    /// free/busy tier omits it. If the target cannot be resolved, the RSVP is
    /// served only to admin or the RSVP's owner (deny-by-default).
    async fn project_calendar_for_viewer(
        &self,
        event: &NostrEvent,
        session_pubkey: &Option<String>,
        viewer_cohorts: &[String],
        viewer_is_admin: bool,
        _zones: &ZoneConfig,
    ) -> Option<NostrEvent> {
        let is_owner = session_pubkey
            .as_deref()
            .map(|pk| pk == event.pubkey)
            .unwrap_or(false);

        // RSVPs: the TARGET event's tier decides. Resolve zone + venue from the
        // stored referenced event (spoof-resistant). Serve only on a Full tier;
        // a FreeBusy/Omit tier would leak the participant list.
        if event.kind == KIND_CALENDAR_RSVP {
            let Some((zone, venue)) = self.resolve_rsvp_target(event).await else {
                // Target unresolvable: deny by default, admin/owner only.
                return if viewer_is_admin || is_owner {
                    Some(event.clone())
                } else {
                    None
                };
            };
            let tier = calendar_projection::project_tier(
                viewer_cohorts,
                &zone,
                venue.as_deref(),
                is_owner,
                viewer_is_admin,
            );
            return match tier {
                calendar_projection::Projection::Full => Some(event.clone()),
                // FreeBusy or Omit ⇒ withhold the RSVP entirely (it would leak
                // participation in an event the viewer only sees as a busy block,
                // or not at all).
                _ => None,
            };
        }

        // Calendar events (31922/31923): the projector decides everything.
        calendar_projection::project_calendar_event(
            viewer_cohorts,
            event,
            is_owner,
            viewer_is_admin,
        )
    }

    /// Resolve the owning zone slug AND venue of a calendar RSVP's TARGET event by
    /// reading the referenced event's stored `zone`/`venue` tags from D1. The RSVP
    /// references its target via an `e` (event id) tag.
    ///
    /// SECURITY: the target's zone/venue are read from the STORED event, never
    /// from any tag the RSVP author mirrored onto the RSVP itself — with the read
    /// gate removed, an author-mirrored `zone=public` on an RSVP targeting a
    /// family event would otherwise leak that event. Returns `None` when the
    /// target cannot be resolved.
    async fn resolve_rsvp_target(&self, rsvp: &NostrEvent) -> Option<(String, Option<String>)> {
        let db = self.env.d1("DB").ok()?;

        #[derive(serde::Deserialize)]
        struct TagsRow {
            tags: String,
        }

        // Look up the referenced calendar event and read its zone + venue tags.
        let target_id = filter::tag_value(rsvp, "e")?;
        let stmt = db.prepare("SELECT tags FROM events WHERE id = ?1 LIMIT 1");
        let row = stmt
            .bind(&[JsValue::from_str(&target_id)])
            .ok()?
            .first::<TagsRow>(None)
            .await
            .ok()??;
        let tags: Vec<Vec<String>> = serde_json::from_str(&row.tags).ok()?;
        let zone = tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == nostr_bbs_core::ZONE_TAG)
            .map(|t| t[1].clone())?;
        let venue = tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == nostr_bbs_core::VENUE_TAG)
            .map(|t| t[1].clone());
        Some((zone, venue))
    }

    pub(crate) async fn handle_close(&self, session_id: u64, sub_id: &str) {
        {
            let mut sessions = self.sessions.borrow_mut();
            if let Some(session) = sessions.get_mut(&session_id) {
                session.subscriptions.remove(sub_id);
            }
        }

        // Persist updated subscriptions to DO storage
        self.save_subscriptions(session_id).await;
    }
}

// ---------------------------------------------------------------------------
// NIP-42: AUTH challenge/response
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Handle an AUTH response from a client (kind 22242 event).
    ///
    /// Verification (kind, Schnorr signature, challenge match, relay-URL match,
    /// created_at skew) is delegated to the pure [`nip42::evaluate_auth_event`]
    /// so the full verdict table is unit-testable without a DO; this method only
    /// performs the side effects (mark session authed + persist for hibernation).
    pub(crate) async fn handle_auth(&self, session_id: u64, ws: &WebSocket, event: NostrEvent) {
        // The exact challenge THIS session was issued (None if the session is
        // gone — which can never match, so verification rejects).
        let expected_challenge = {
            let sessions = self.sessions.borrow();
            sessions.get(&session_id).map(|s| s.challenge.clone())
        };
        let own_relay_url = self.own_relay_url();
        nip42::warn_if_relay_url_unconfigured(self.auth_mode(), own_relay_url.as_deref());
        let now = auth::js_now_secs();

        match nip42::evaluate_auth_event(
            &event,
            expected_challenge.as_deref(),
            own_relay_url.as_deref(),
            now,
            nip42::AUTH_MAX_SKEW_SECS,
        ) {
            nip42::AuthVerdict::Ok(pubkey) => {
                // Mark session as authenticated.
                {
                    let mut sessions = self.sessions.borrow_mut();
                    if let Some(session) = sessions.get_mut(&session_id) {
                        session.authed_pubkey = Some(pubkey.clone());
                    }
                }
                // Persist auth state to DO storage so it survives hibernation.
                self.save_auth(session_id, &pubkey).await;
                Self::send_ok(ws, &event.id, true, "");
            }
            nip42::AuthVerdict::Rejected(reason) => {
                Self::send_ok(ws, &event.id, false, reason);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shared read-authorization (REQ / COUNT / live broadcast)
// ---------------------------------------------------------------------------

/// Resolved read scope for one viewer (session). Computed once per REQ/COUNT,
/// or once per candidate session on the broadcast path, then reused for every
/// event so the three read paths apply identical zone/cohort gating.
pub(crate) struct ViewerContext {
    pub session_pubkey: Option<String>,
    pub access_pubkey: Option<String>,
    pub is_admin: bool,
    pub viewer_cohorts: Vec<String>,
    pub viewer_is_admin: bool,
    /// Phase 2: the session's registered inbox keys (empty when the feature is
    /// off). Lets a kind-1059 addressed to one of them pass the protected-kind
    /// gate for the owner's session.
    pub recipient_keys: Vec<String>,
}

/// Per-event read decision shared by every read path.
pub(crate) enum ReadDecision {
    /// Deliver the event verbatim.
    Deliver,
    /// Deliver this calendar-projected / redacted replacement instead.
    DeliverAs(NostrEvent),
    /// Withhold the event from this viewer (zone/cohort/projection denial).
    Withhold,
}

/// Zone read rule shared by the REQ, COUNT and broadcast gates (ADR-2018).
///
/// Mirrors `trust::has_zone_access` without the D1 read: a public-read zone is
/// open to everyone (including an unauthenticated viewer, whose cohorts are
/// empty); otherwise the viewer needs the whitelist admin flag or one of the
/// zone's required cohorts. Unknown zones deny, as `cohorts_can_read` does.
pub(crate) fn zone_read_permitted(zones: &ZoneConfig, zone: &str, ctx: &ViewerContext) -> bool {
    zones.is_public_read(zone)
        || ctx.viewer_is_admin
        || zones.cohorts_can_read(zone, &ctx.viewer_cohorts)
}

impl NostrRelayDO {
    /// NIP-59 kind-1059 (Sealed DM) read gate + mandatory `#p` rewrite.
    ///
    /// If any filter requests kind-1059, the session must be authenticated; each
    /// such filter is rewritten to require `#p == authed pubkey`, preventing a
    /// client from reading another user's sealed DMs. Returns `None` when the
    /// request must be rejected (kind-1059 requested by an unauthenticated
    /// session). Shared by REQ and COUNT so neither can leak DMs.
    #[cfg(test)]
    fn gate_kind_1059_filters(
        filters: Vec<NostrFilter>,
        session_pubkey: &Option<String>,
    ) -> Option<Vec<NostrFilter>> {
        Self::gate_kind_1059_filters_with(filters, session_pubkey, None)
    }

    /// [`Self::gate_kind_1059_filters`] with the recipient-keys switch (Phase 2).
    /// `recipient_keys_on == false` overwrites `#p` with the authed pubkey,
    /// exactly as before. `true` stores the filter as the client sent it: the
    /// stored (and live-broadcast) filter must not depend on a key list that can
    /// be stale or empty at subscribe time, or a key registered a moment later
    /// would sit behind a dead subscription. Isolation is the per-event check
    /// (`gift_wrap_readable_by_any`, first `p` against set A at delivery time).
    fn gate_kind_1059_filters_with(
        filters: Vec<NostrFilter>,
        session_pubkey: &Option<String>,
        read_set: Option<&[String]>,
    ) -> Option<Vec<NostrFilter>> {
        let needs_kind_1059 = filters
            .iter()
            .any(|f| f.kinds.as_ref().is_some_and(|k| k.contains(&1059)));
        if !needs_kind_1059 {
            return Some(filters);
        }
        session_pubkey.as_ref().map(|authed_pk| {
            filters
                .into_iter()
                .map(|mut f| {
                    if f.kinds.as_ref().is_some_and(|k| k.contains(&1059)) {
                        match read_set {
                            None => {
                                f.extra
                                    .insert("#p".to_string(), serde_json::json!([authed_pk]));
                            }
                            // A client-sent `#p` is stored as sent. Without one,
                            // bind to A so the SQL `LIMIT` cannot be spent on
                            // other members' wraps.
                            Some(set) => {
                                f.extra
                                    .entry("#p".to_string())
                                    .or_insert_with(|| serde_json::json!(set));
                            }
                        }
                    }
                    f
                })
                .collect::<Vec<_>>()
        })
    }

    /// Resolve a viewer's effective read scope (ADR-099 device→owner rebinding,
    /// admin status, calendar cohorts). The kind-1059 DM `#p` filter is bound to
    /// the literal `session_pubkey` upstream and deliberately NOT rebound here —
    /// only cohort/zone READ scope is rebound to the owner.
    pub(crate) async fn resolve_viewer_context(
        &self,
        session_pubkey: Option<String>,
    ) -> ViewerContext {
        let access_pubkey: Option<String> = match &session_pubkey {
            Some(pk) => Some(self.effective_pubkey(pk).await),
            None => None,
        };
        let is_admin = match &access_pubkey {
            Some(pk) => self.admin_cache.is_admin(pk, &self.env).await,
            None => false,
        };
        let (viewer_cohorts, cohort_admin) = match &access_pubkey {
            Some(pk) => self.cached_viewer_cohorts(pk).await,
            None => (Vec::new(), false),
        };
        let viewer_is_admin = is_admin || cohort_admin;
        let recipient_keys = match &session_pubkey {
            Some(pk) => self.cached_recipient_keys(pk).await,
            None => Vec::new(),
        };
        ViewerContext {
            session_pubkey,
            access_pubkey,
            is_admin,
            viewer_cohorts,
            viewer_is_admin,
            recipient_keys,
        }
    }

    // -----------------------------------------------------------------------
    // ADR-2018: memoised lookups and coalesced activity writes
    // -----------------------------------------------------------------------

    /// `channel_zones` lookup through the 60s per-DO memo. Only a bound zone is
    /// remembered: an unbound channel goes back to D1 every time, so a channel
    /// bound moments after its first read is never served as unscoped.
    pub(crate) async fn cached_channel_zone(&self, channel_id: &str) -> Option<String> {
        let now = auth::js_now_secs();
        if let Some(zone) = self.channel_zone_cache.get(channel_id, now) {
            return Some(zone);
        }
        let zone = trust::get_channel_zone(channel_id, &self.env).await?;
        self.channel_zone_cache
            .insert(channel_id, zone.clone(), now);
        Some(zone)
    }

    /// Whitelist `(cohorts, is_admin)` through the 60s per-DO memo. A missing
    /// row is cached as `(vec![], false)` exactly as the D1 path reports it,
    /// so a non-member costs one read a minute rather than one per frame.
    pub(crate) async fn cached_viewer_cohorts(&self, pubkey: &str) -> (Vec<String>, bool) {
        let now = auth::js_now_secs();
        if let Some(hit) = self.cohort_cache.get(pubkey, now) {
            return hit;
        }
        let fresh = trust::get_viewer_cohorts(pubkey, &self.env).await;
        self.cohort_cache.insert(pubkey, fresh.clone(), now);
        fresh
    }

    /// `device_keys` owner lookup through the 60s per-DO memo. Both outcomes
    /// are cached: a non-device pubkey is the common case and must not cost a
    /// read per frame.
    pub(crate) async fn cached_device_owner(&self, pubkey: &str) -> Option<String> {
        let now = auth::js_now_secs();
        if let Some(hit) = self.device_owner_cache.get(pubkey, now) {
            return hit;
        }
        let fresh = self.device_owner(pubkey).await;
        self.device_owner_cache.insert(pubkey, fresh.clone(), now);
        fresh
    }

    /// The gift-wrap recipient gate. Feature off: `is_ingress`, else the
    /// recipient must be whitelisted, with the historical refusal. Feature on:
    /// ingress, else a registered inbox key judged by its owner's membership,
    /// else the key itself must be a member.
    async fn gift_wrap_recipient_verdict(
        &self,
        event: &NostrEvent,
        is_ingress: bool,
    ) -> std::result::Result<(), &'static str> {
        use crate::recipient_keys::{route, verdict, Route, REASON_NOT_WHITELISTED};
        let Some(pk) = gift_wrap_recipient(event) else {
            return Err(REASON_NOT_WHITELISTED);
        };
        if !self.recipient_keys_enabled() {
            return if is_ingress || self.is_whitelisted(&pk).await {
                Ok(())
            } else {
                Err(REASON_NOT_WHITELISTED)
            };
        }
        let row = if is_ingress {
            None
        } else {
            self.cached_recipient_row(&pk).await
        };
        let route = route(is_ingress, row.as_ref());
        let member = match &route {
            Route::OwnerMustBeMember(owner) => self.is_whitelisted(owner).await,
            Route::RecipientMustBeMember => self.is_whitelisted(&pk).await,
            _ => false,
        };
        verdict(&route, member)
    }

    /// Phase 2: whether registered recipient keys are honoured. Only the exact
    /// string `"true"` in `RECIPIENT_KEYS_ENABLED` enables; absent ⇒ off.
    pub(crate) fn recipient_keys_enabled(&self) -> bool {
        crate::recipient_keys::recipient_keys_enabled_var(
            self.env
                .var(crate::recipient_keys::RECIPIENT_KEYS_ENABLED_VAR)
                .ok()
                .map(|v| v.to_string())
                .as_deref(),
        )
    }

    /// `recipient_keys` registration for `key` through the 60s memo. Both
    /// outcomes are cached; a revoked row is returned as such.
    pub(crate) async fn cached_recipient_row(&self, key: &str) -> Option<(String, bool)> {
        let key = key.to_ascii_lowercase();
        let now = auth::js_now_secs();
        if let Some(hit) = self.recipient_row_cache.get(&key, now) {
            return hit;
        }
        let fresh = match self.env.d1("DB") {
            Ok(db) => crate::recipient_keys::lookup_owner(&db, &key).await,
            Err(_) => None,
        };
        // Cache hits only. A cached miss would keep a key that was registered
        // a moment later on the Unregistered route for up to the TTL, judged
        // by its own whitelist status instead of its owner's. A miss is one
        // indexed D1 read, which is what every unregistered recipient cost
        // before this feature existed.
        if fresh.is_some() {
            self.recipient_row_cache.insert(&key, fresh.clone(), now);
        }
        fresh
    }

    /// `owner`'s unrevoked inbox keys through the 60s memo. Empty when the
    /// feature is off (no D1 read at all).
    pub(crate) async fn cached_recipient_keys(&self, owner: &str) -> Vec<String> {
        if !self.recipient_keys_enabled() {
            return Vec::new();
        }
        let owner = owner.to_ascii_lowercase();
        let now = auth::js_now_secs();
        if let Some(hit) = self.recipient_keys_cache.get(&owner, now) {
            return hit;
        }
        let fresh = match self.env.d1("DB") {
            Ok(db) => crate::recipient_keys::keys_for_owner(&db, &owner).await,
            Err(_) => Vec::new(),
        };
        // Cache non-empty lists only, so a key registered after an empty
        // lookup is readable on the next call, not after the TTL.
        if !fresh.is_empty() {
            self.recipient_keys_cache.insert(&owner, fresh.clone(), now);
        }
        fresh
    }

    /// Set A for a session: its pubkey plus registered inbox keys. `None` when
    /// the feature is off or the session is unauthenticated, so callers keep
    /// today's single-pubkey rule.
    pub(crate) async fn recipient_read_set(
        &self,
        session_pubkey: &Option<String>,
    ) -> Option<Vec<String>> {
        if !self.recipient_keys_enabled() {
            return None;
        }
        let pk = session_pubkey.as_ref()?;
        let extra = self.cached_recipient_keys(pk).await;
        Some(crate::recipient_keys::read_set(pk, &extra))
    }

    /// Record `delivered` reads for an authed reader and flush the trust ledger
    /// when the [`ActivityLedger`] says the window is due.
    pub(crate) async fn note_read_activity(&self, pubkey: &str, delivered: i32) {
        let now = auth::js_now_secs();
        if let Some(flush) = self.activity.record_read(pubkey, delivered, now) {
            self.flush_activity(pubkey, flush.reads).await;
        }
    }

    /// Record an accepted EVENT from `pubkey` and flush the trust ledger when
    /// the window is due. `posts_created` is incremented by the caller
    /// unconditionally; only the stamp and promotion check are throttled.
    pub(crate) async fn note_write_activity(&self, pubkey: &str) {
        let now = auth::js_now_secs();
        if let Some(flush) = self.activity.record_write(pubkey, now) {
            self.flush_activity(pubkey, flush.reads).await;
        }
    }

    async fn flush_activity(&self, pubkey: &str, reads: i32) {
        trust::increment_posts_read_by(pubkey, reads, &self.env).await;
        trust::update_last_active(pubkey, &self.env).await;
        let _ = trust::check_promotion(pubkey, &self.env).await;
    }

    /// Apply the zone / cohort / NIP-52-calendar read gate to a single event for
    /// one resolved viewer. THE single source of truth for read authorization,
    /// shared by REQ, COUNT, and live broadcast.
    ///
    /// Decision matrix for a NON-member (non-admin), per zone visibility:
    ///   Public : defs + content served to everyone (incl. unauth).
    ///   Locked : defs served (tile renders) but content withheld.
    ///   Hidden : defs AND content omitted.
    /// Members (cohort match) and admins always receive both. NIP-52 calendar
    /// kinds are decided entirely by `project_calendar_for_viewer` (the per-tier
    /// projection IS the access decision), deny-by-default for unknown zones.
    pub(crate) async fn authorize_event(
        &self,
        event: &NostrEvent,
        ctx: &ViewerContext,
        zones: &ZoneConfig,
    ) -> ReadDecision {
        // Protected kinds first, and per EVENT rather than per filter. The
        // filter-level gates in `handle_req` decide from the kinds a filter
        // NAMES; a filter that omits `kinds` matches every kind while naming
        // none, and so passed both of them. This branch cannot be dodged that
        // way — the kind is a property of the event in hand.
        if nip42::is_protected_read_kind(event.kind) {
            let recipients: Vec<String> = event
                .tags
                .iter()
                .filter(|t| t.len() >= 2 && t[0] == "p")
                .map(|t| t[1].clone())
                .collect();
            if !nip42::protected_read_permitted_with_keys(
                event.kind,
                &event.pubkey,
                &recipients,
                ctx.session_pubkey.as_deref(),
                &ctx.recipient_keys,
                self.auth_mode(),
            ) {
                return ReadDecision::Withhold;
            }
        }

        if calendar_projection::is_projected_calendar_kind(event.kind) {
            return match self
                .project_calendar_for_viewer(
                    event,
                    &ctx.session_pubkey,
                    &ctx.viewer_cohorts,
                    ctx.viewer_is_admin,
                    zones,
                )
                .await
            {
                Some(out) => ReadDecision::DeliverAs(out),
                None => ReadDecision::Withhold,
            };
        }

        // Kanban boards/cards (30301/30302): binary zone read gate — no
        // free/busy tier. An untagged board is unscoped (served as-is, the
        // calendar posture); a zone-tagged one is served only to the author,
        // admins, and zone members (cohort match or public-read zone).
        // Deny-by-default for unknown zones, exactly like the projector.
        if nostr_bbs_core::is_kanban_kind(event.kind) {
            let Some(zone) = nostr_bbs_core::read_zone_tag(event) else {
                return ReadDecision::Deliver;
            };
            let is_owner = ctx
                .access_pubkey
                .as_deref()
                .map(|pk| pk == event.pubkey)
                .unwrap_or(false);
            let is_member =
                zones.is_public_read(zone) || zones.cohorts_can_read(zone, &ctx.viewer_cohorts);
            return if ctx.viewer_is_admin || is_owner || is_member {
                ReadDecision::Deliver
            } else {
                ReadDecision::Withhold
            };
        }

        // Zone-scoped channel kinds: kind-40 defs (channel id == event id),
        // kind-41 metadata and kind-42 content (channel id == root/first `e` tag).
        let channel_id: Option<String> = filter::zone_channel_id(event);

        if let Some(cid) = channel_id {
            // Only a channel EXPLICITLY bound to a zone is read-gated. An
            // undeclared channel is UNSCOPED (public read), mirroring the write
            // path that lets any whitelisted member post to it — a channel you
            // may post to, you (and everyone) may read. Finding-5 fix: defaulting
            // an undeclared channel to a private "home" zone previously hid every
            // new channel's tile AND messages from all non-admins, including the
            // channel's own author, since "home" is not a configured zone and an
            // unknown zone denies by default.
            //
            // ADR-2018: the zone comes from the per-DO memo and membership is
            // decided from the cohorts already resolved into `ctx` — no D1
            // round-trips per event. `zone_read_permitted` is the same rule
            // `trust::has_zone_access` applies (public read, or whitelist
            // admin, or a required cohort); `ctx.viewer_is_admin` carries the
            // whitelist admin flag that function used to re-read.
            if let Some(zone) = self.cached_channel_zone(&cid).await {
                if !ctx.is_admin {
                    let is_member = zone_read_permitted(zones, &zone, ctx);
                    if !is_member {
                        if matches!(event.kind, 40 | 41) {
                            // Channel definition or its metadata update (a rename
                            // must agree with the definition the tile shows):
                            // served only if the zone is not Hidden
                            // (Locked/Public tiles render).
                            if !zones.defs_visible_to_nonmember(&zone) {
                                return ReadDecision::Withhold;
                            }
                        } else {
                            // Channel content (kind-42): withheld from non-members
                            // of Locked/Hidden zones.
                            return ReadDecision::Withhold;
                        }
                    }
                }
            }
        }

        ReadDecision::Deliver
    }
}

// ---------------------------------------------------------------------------
// NIP-45: COUNT
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Handle a COUNT request: return the number of matching events the session
    /// is AUTHORIZED to read.
    ///
    /// Applies the same read authorization as REQ (kind-1059 auth gate + `#p`
    /// rewrite, then the per-event zone/cohort/calendar gate). Without this,
    /// COUNT is an existence/count oracle that leaks how many sealed DMs a pubkey
    /// has received and message counts for Locked/Hidden zones and gated calendar
    /// events — all of which REQ correctly withholds.
    pub(crate) async fn handle_count(
        &self,
        session_id: u64,
        ip: &str,
        ws: &WebSocket,
        sub_id: &str,
        filters: Vec<NostrFilter>,
    ) {
        // Per-IP rate limit, consistent with the EVENT/REQ paths. COUNT was
        // previously ungated and is an equally cheap way to force unbounded D1
        // scans; gate it identically.
        if !self.check_rate_limit(ip) {
            Self::send_notice(ws, "rate limit exceeded");
            return;
        }

        let session_pubkey = {
            let sessions = self.sessions.borrow();
            sessions
                .get(&session_id)
                .and_then(|s| s.authed_pubkey.clone())
        };

        // PRD-010 G4: protected-kind reads require auth (nip42 mode). A COUNT is
        // an existence/count oracle, so an unauthenticated protected-kind COUNT
        // returns 0 rather than a real tally — mirroring the REQ CLOSED
        // rejection so the two read paths never diverge on what leaks.
        if nip42::protected_read_blocked(&filters, session_pubkey.is_some(), self.auth_mode()) {
            Self::send_count(ws, sub_id, 0);
            return;
        }

        // kind-1059 gate identical to REQ; deny-by-default → count 0 on reject.
        let read_set = self.recipient_read_set(&session_pubkey).await;
        let filters = match Self::gate_kind_1059_filters_with(
            filters,
            &session_pubkey,
            read_set.as_deref(),
        ) {
            Some(f) => f,
            None => {
                Self::send_count(ws, sub_id, 0);
                return;
            }
        };

        let events = self.query_events(&filters).await;
        let zones = ZoneConfig::load(&self.env);
        let ctx = self.resolve_viewer_context(session_pubkey.clone()).await;

        let mut count: u64 = 0;
        for event in &events {
            let readable = match &read_set {
                Some(set) => gift_wrap_readable_by_any(event, set),
                None => gift_wrap_readable_by(event, session_pubkey.as_deref()),
            };
            if !readable {
                continue;
            }
            match self.authorize_event(event, &ctx, &zones).await {
                ReadDecision::Deliver | ReadDecision::DeliverAs(_) => count += 1,
                ReadDecision::Withhold => {}
            }
        }
        Self::send_count(ws, sub_id, count);
    }
}

// ---------------------------------------------------------------------------
// NIP-09: Deletion processing
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Process a kind-5 deletion event: delete targeted events by the same
    /// author, or — when `can_delete_any` (admin / TL3+, mirroring the EVENT
    /// gate) — anyone's. Without the flag the SQL keeps the author constraint,
    /// so a gate regression can never widen deletion via this path alone.
    pub(crate) async fn process_deletion(&self, deletion_event: &NostrEvent, can_delete_any: bool) {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return,
        };

        // Collect "e" tags (direct event ID targets)
        let target_ids: Vec<&str> = deletion_event
            .tags
            .iter()
            .filter(|t| t.len() >= 2 && t[0] == "e")
            .map(|t| t[1].as_str())
            .collect();

        let mut own_keys: Option<Vec<String>> = None;
        for target_id in &target_ids {
            let result = if can_delete_any {
                let stmt = db.prepare("DELETE FROM events WHERE id = ?1");
                match stmt.bind(&[JsValue::from_str(target_id)]) {
                    Ok(s) => s.run().await,
                    Err(_) => continue,
                }
            } else {
                let stmt = db.prepare("DELETE FROM events WHERE id = ?1 AND pubkey = ?2");
                match stmt.bind(&[
                    JsValue::from_str(target_id),
                    JsValue::from_str(&deletion_event.pubkey),
                ]) {
                    Ok(s) => s.run().await,
                    Err(_) => continue,
                }
            };
            let _ = result;

            // Phase 2 recipient branch, kind 1059 only: the wrap's first `p`
            // must be one of the signer's own recipient keys (decided in Rust
            // on the first `p`, never by an any-`p` SQL match).
            if !can_delete_any && self.recipient_keys_enabled() {
                if own_keys.is_none() {
                    own_keys = self
                        .recipient_read_set(&Some(deletion_event.pubkey.clone()))
                        .await;
                }
                let Some(set) = own_keys.as_ref() else {
                    continue;
                };
                #[derive(serde::Deserialize)]
                struct WrapRow {
                    kind: f64,
                    tags: String,
                }
                let Ok(sel) = db
                    .prepare("SELECT kind, tags FROM events WHERE id = ?1 AND kind = 1059 LIMIT 1")
                    .bind(&[JsValue::from_str(target_id)])
                else {
                    continue;
                };
                if let Ok(Some(row)) = sel.first::<WrapRow>(None).await {
                    if crate::recipient_keys::wrap_addressed_to(row.kind as u64, &row.tags, set) {
                        if let Ok(del) = db
                            .prepare("DELETE FROM events WHERE id = ?1 AND kind = 1059")
                            .bind(&[JsValue::from_str(target_id)])
                        {
                            let _ = del.run().await;
                        }
                    }
                }
            }
        }

        // Collect "a" tags (parameterized replaceable targets: "kind:pubkey:d-tag")
        let a_targets: Vec<&str> = deletion_event
            .tags
            .iter()
            .filter(|t| t.len() >= 2 && t[0] == "a")
            .map(|t| t[1].as_str())
            .collect();

        for a_ref in &a_targets {
            let Some((kind, pubkey, d_tag)) = filter::split_a_ref(a_ref) else {
                continue;
            };

            // Own events only, unless the author holds delete-any privilege
            // (the a-ref names its owner, so the SQL below stays scoped to
            // exactly that pubkey's replaceable event either way).
            if !can_delete_any && pubkey != deletion_event.pubkey {
                continue;
            }

            let stmt =
                db.prepare("DELETE FROM events WHERE kind = ?1 AND pubkey = ?2 AND d_tag = ?3");
            let _ = match stmt.bind(&[
                JsValue::from_f64(kind),
                JsValue::from_str(pubkey),
                JsValue::from_str(d_tag),
            ]) {
                Ok(s) => s.run().await,
                Err(_) => continue,
            };
        }
    }
}

// ---------------------------------------------------------------------------
// Trust / zone helper methods
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Check whether a pubkey is the creator of a channel.
    ///
    /// Reads the `channel_creators` row persisted when the kind-40 event was
    /// saved, so deleting that event (kind-5) does not change the answer. A
    /// channel created before the table existed has no row; it falls back to the
    /// kind-40 event, which is the best evidence left.
    pub(crate) async fn is_channel_creator(&self, subjects: &[&str], channel_id: &str) -> bool {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return false,
        };

        #[derive(serde::Deserialize)]
        struct ChannelCreatorRow {
            pubkey: String,
        }

        for sql in [
            "SELECT pubkey FROM channel_creators WHERE channel_id = ?1 LIMIT 1",
            "SELECT pubkey FROM events WHERE id = ?1 AND kind = 40 LIMIT 1",
        ] {
            let Ok(bound) = db.prepare(sql).bind(&[JsValue::from_str(channel_id)]) else {
                continue;
            };
            if let Ok(Some(row)) = bound.first::<ChannelCreatorRow>(None).await {
                return creator_matches(&row.pubkey, subjects);
            }
        }
        false
    }

    /// ADR-099: whether device-key honouring is enabled. Reads the
    /// `DEVICE_KEYS_ENABLED` Worker var; only the exact string `"true"` enables
    /// the feature. Absent/empty/any-other value ⇒ disabled (default off).
    ///
    /// ADR-2004 keeps this check **independent** of the auth worker's — the
    /// relay reads its own binding and decides alone, never calling across.
    /// Only the parse *rule* is shared ([`nostr_bbs_core::feature_gate`]) so the
    /// two gates cannot drift on what `"true"` means, which is precisely the
    /// "kept in lockstep" obligation the ADR records as the cost of duplication.
    pub(crate) fn device_keys_enabled(&self) -> bool {
        device_keys_enabled_var(
            self.env
                .var(DEVICE_KEYS_ENABLED_VAR)
                .ok()
                .map(|v| v.to_string())
                .as_deref(),
        )
    }

    /// ADR-099 (read-only here; the auth-worker owns writes): resolve the OWNER
    /// account for a registered, non-revoked device key.
    ///
    /// Returns `Some(owner_pubkey)` for a `device_keys` row whose `revoked = 0`,
    /// else `None`. Fail-safe: a missing `device_keys` table (not provisioned
    /// yet) or any D1 error yields `None` — a device key then resolves to no
    /// owner and is treated as an ordinary unknown pubkey.
    pub(crate) async fn device_owner(&self, pubkey: &str) -> Option<String> {
        let db = self.env.d1("DB").ok()?;

        #[derive(serde::Deserialize)]
        struct OwnerRow {
            owner_pubkey: String,
        }

        let stmt = db.prepare(
            "SELECT owner_pubkey FROM device_keys WHERE device_pubkey = ?1 AND revoked = 0 LIMIT 1",
        );
        // A missing table surfaces as a prepare/bind/exec error; `.ok()?` maps it
        // to `None` (fail-safe), so the relay behaves as if no device exists.
        let bound = stmt.bind(&[JsValue::from_str(pubkey)]).ok()?;
        match bound.first::<OwnerRow>(None).await {
            Ok(Some(row)) => Some(row.owner_pubkey),
            _ => None,
        }
    }

    /// ADR-099: resolve the EFFECTIVE principal for `pubkey`, applied to read
    /// scope (cohorts/zone access) and the write-gate allowlist check.
    ///
    /// Gated by `DEVICE_KEYS_ENABLED`. When off, this is a pure identity
    /// passthrough (no D1 read at all) — guaranteeing zero behaviour change. When
    /// on, a registered non-revoked device key resolves to its OWNER; otherwise
    /// the input pubkey is returned unchanged.
    pub(crate) async fn effective_pubkey(&self, pubkey: &str) -> String {
        if !self.device_keys_enabled() {
            return pubkey.to_string();
        }
        let owner = self.cached_device_owner(pubkey).await;
        effective_principal(pubkey, owner.as_deref(), true)
    }

    pub(crate) async fn is_registered_agent(&self, pubkey: &str) -> bool {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return false,
        };

        #[derive(serde::Deserialize)]
        struct AgentActiveRow {
            active: u32,
        }

        let stmt = db.prepare("SELECT active FROM agent_registry WHERE pubkey = ?1 LIMIT 1");
        match stmt.bind(&[JsValue::from_str(pubkey)]) {
            Ok(s) => match s.first::<AgentActiveRow>(None).await {
                Ok(Some(row)) => row.active == 1,
                _ => false,
            },
            Err(_) => false,
        }
    }

    /// The relay's advertised `ESCALATION_DEFAULT_TIER` (NIP-11), as a tier.
    ///
    /// ADR-2011 §3 makes the advertisement load-bearing rather than decorative:
    /// an unlabelled 31402 folds to exactly this. Reading it here, from the same
    /// var `nip11.rs` advertises, is what stops the claim and the behaviour
    /// drifting apart.
    pub(crate) fn advertised_default_tier(&self) -> RiskTier {
        self.env
            .var("ESCALATION_DEFAULT_TIER")
            .map(|v| RiskTier::parse(&v.to_string()))
            .unwrap_or_default()
    }

    /// The relay's calibration selection key (FR6.3).
    ///
    /// Secret, and never advertised in NIP-11: its secrecy is the only thing
    /// stopping a requesting agent from grinding `d` tags until it finds one
    /// that sampling never selects.
    pub(crate) fn calibration_selection_key(&self) -> Vec<u8> {
        self.env
            .var(governance::ENV_CALIBRATION_SELECTION_KEY)
            .map(|v| v.to_string().into_bytes())
            .unwrap_or_default()
    }

    /// The tags of the 31400 panel a 31402 belongs to, where one can be resolved.
    ///
    /// Resolution order: the NIP-33 `a` tag (`31400:<pubkey>:<d>`), then a plain
    /// `panel` tag naming the panel's `d`, then the most recent panel the same
    /// agent published. A request whose panel cannot be resolved is not refused —
    /// it simply has no operator declaration to be tightened by.
    pub(crate) async fn resolve_panel_tags(&self, event: &NostrEvent) -> Option<Vec<Vec<String>>> {
        let db = self.env.d1("DB").ok()?;

        #[derive(serde::Deserialize)]
        struct TagsRow {
            tags: String,
        }

        // `a` is `<kind>:<pubkey>:<d>`; we only honour a 31400 address.
        let addressed = governance::extract_tag(&event.tags, "a").and_then(|a| {
            let mut parts = a.splitn(3, ':');
            let kind = parts.next()?;
            let pubkey = parts.next()?;
            let d = parts.next()?;
            (kind.parse::<u64>().ok() == Some(governance::KIND_PANEL_DEFINITION))
                .then(|| (pubkey.to_string(), d.to_string()))
        });
        let named = governance::extract_tag(&event.tags, "panel")
            .map(|d| (event.pubkey.clone(), d.to_string()));

        let row = if let Some((pubkey, d)) = addressed.or(named) {
            db.prepare(
                "SELECT tags FROM events WHERE kind = ?1 AND pubkey = ?2 AND d_tag = ?3 \
                 ORDER BY created_at DESC LIMIT 1",
            )
            .bind(&[
                JsValue::from_f64(governance::KIND_PANEL_DEFINITION as f64),
                JsValue::from_str(&pubkey),
                JsValue::from_str(&d),
            ])
            .ok()?
            .first::<TagsRow>(None)
            .await
            .ok()
            .flatten()
        } else {
            db.prepare(
                "SELECT tags FROM events WHERE kind = ?1 AND pubkey = ?2 \
                 ORDER BY created_at DESC LIMIT 1",
            )
            .bind(&[
                JsValue::from_f64(governance::KIND_PANEL_DEFINITION as f64),
                JsValue::from_str(&event.pubkey),
            ])
            .ok()?
            .first::<TagsRow>(None)
            .await
            .ok()
            .flatten()
        }?;

        serde_json::from_str::<Vec<Vec<String>>>(&row.tags).ok()
    }

    /// Project a 31402 ActionRequest into `broker_cases`, stamping the ADR-2011
    /// effective tier, the triple it derives from, the calibration mark and the
    /// panel's ageing deadline.
    ///
    /// The tier is computed here, once, at projection time — not read from the
    /// request by each consumer. That is what makes the boundary the operator's
    /// rather than the requesting agent's: every downstream surface reads
    /// `broker_cases.effective_tier` and there is nowhere else to look.
    pub(crate) async fn project_action_request(&self, event: &NostrEvent) {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return,
        };

        let d_tag = governance::extract_d_tag(&event.tags).unwrap_or(&event.id);
        let category =
            governance::extract_tag(&event.tags, "category").unwrap_or("manual_submission");
        let subject_kind = governance::extract_tag(&event.tags, "subject-kind").unwrap_or("opaque");
        let subject_id = governance::extract_tag(&event.tags, "subject-id").unwrap_or("");
        let title = governance::extract_tag(&event.tags, "title").unwrap_or("Untitled");
        let priority: u32 = governance::extract_tag(&event.tags, "priority")
            .and_then(|p| p.parse().ok())
            .unwrap_or(50);

        let panel_tags = self.resolve_panel_tags(event).await;
        let calibration_key = self.calibration_selection_key();
        if calibration_key.is_empty() {
            // Reported, not silently tolerated: without a key the selection is
            // an unkeyed hash of an agent-chosen `d` tag, which the agent can
            // grind to escape sampling. Sampling still runs, because silently
            // disabling oversight is the worse of the two failures.
            console_warn!(
                "{} is unset: calibration sampling is predictable by the requesting agent",
                governance::ENV_CALIBRATION_SELECTION_KEY
            );
        }
        let boundary = plan_request_boundary(
            d_tag,
            &event.pubkey,
            &event.tags,
            &event.content,
            panel_tags.as_deref(),
            self.advertised_default_tier(),
            &calibration_key,
        );

        let stmt = db.prepare(CASE_UPSERT_SQL);
        if let Ok(bound) = stmt.bind(&[
            JsValue::from_str(d_tag),
            JsValue::from_str(category),
            JsValue::from_str(subject_kind),
            JsValue::from_str(subject_id),
            JsValue::from_str(title),
            JsValue::from_str(&event.content),
            JsValue::from_f64(priority as f64),
            JsValue::from_str(&event.pubkey),
            JsValue::from_str(&event.id),
            JsValue::from_f64(event.created_at as f64),
            match boundary.declared {
                Some(t) => JsValue::from_str(t.as_str()),
                None => JsValue::NULL,
            },
            JsValue::from_str(boundary.effective.as_str()),
            match &boundary.props {
                Some(p) => JsValue::from_str(p.verifiability.as_str()),
                None => JsValue::NULL,
            },
            match &boundary.props {
                Some(p) => JsValue::from_str(p.reversibility.as_str()),
                None => JsValue::NULL,
            },
            match &boundary.props {
                Some(p) => JsValue::from_str(p.stakes.as_str()),
                None => JsValue::NULL,
            },
            JsValue::from_f64(u8::from(boundary.calibration_sample) as f64),
            match &boundary.probe_digest {
                Some(d) => JsValue::from_str(d),
                None => JsValue::NULL,
            },
            JsValue::from_f64(boundary.max_pending_hours as f64),
            match boundary.stale_after {
                Some(t) => JsValue::from_f64(t as f64),
                None => JsValue::NULL,
            },
        ]) {
            let _ = bound.run().await;
        }
    }

    /// The effective tier stored on a case, or `None` for a case projected
    /// before migration 0006 (which is not retro-gated on a tier nobody
    /// computed) or a case id the relay has never seen.
    pub(crate) async fn case_effective_tier(&self, case_id: &str) -> Option<RiskTier> {
        let db = self.env.d1("DB").ok()?;
        #[derive(serde::Deserialize)]
        struct TierRow {
            effective_tier: Option<String>,
        }
        db.prepare("SELECT effective_tier FROM broker_cases WHERE id = ?1 LIMIT 1")
            .bind(&[JsValue::from_str(case_id)])
            .ok()?
            .first::<TierRow>(None)
            .await
            .ok()
            .flatten()
            .and_then(|r| r.effective_tier)
            .map(|t| RiskTier::parse(&t))
    }

    /// Whether `pubkey` holds the `reviewer` governance role (FR6.2).
    pub(crate) async fn is_reviewer(&self, pubkey: &str) -> bool {
        let Ok(db) = self.env.d1("DB") else {
            return false;
        };
        let Ok(stmt) = db
            .prepare("SELECT role FROM broker_roles WHERE lower(pubkey) = ?1 AND role = ?2 LIMIT 1")
            .bind(&[
                JsValue::from_str(&pubkey.to_ascii_lowercase()),
                JsValue::from_str(governance::ROLE_REVIEWER),
            ])
        else {
            return false;
        };
        stmt.first::<serde_json::Value>(None)
            .await
            .ok()
            .flatten()
            .is_some()
    }

    /// Whether an admin has delegated `case_id` to `pubkey` (FR6.2).
    ///
    /// The delegation is scoped to exactly one case: this returns false for
    /// every other case the same reviewer might try to decide.
    pub(crate) async fn is_delegated_for_case(&self, case_id: &str, pubkey: &str) -> bool {
        let Ok(db) = self.env.d1("DB") else {
            return false;
        };
        let Ok(stmt) = db
            .prepare(
                "SELECT case_id FROM case_delegations \
                 WHERE case_id = ?1 AND lower(delegate_pubkey) = ?2 LIMIT 1",
            )
            .bind(&[
                JsValue::from_str(case_id),
                JsValue::from_str(&pubkey.to_ascii_lowercase()),
            ])
        else {
            return false;
        };
        stmt.first::<serde_json::Value>(None)
            .await
            .ok()
            .flatten()
            .is_some()
    }

    /// Record an admin's `Delegate{to}` so the 31403 gate will admit the
    /// delegatee for this one case (FR6.2, DDD §6 invariant 6).
    ///
    /// The delegating admin is kept on the row, so the delegation stays
    /// attributable to them even though the decision will be the delegatee's.
    pub(crate) async fn record_case_delegation(
        &self,
        case_id: &str,
        delegate_pubkey: &str,
        delegated_by: &str,
        decision_id: &str,
        at: u64,
    ) {
        let Ok(db) = self.env.d1("DB") else {
            return;
        };
        if let Ok(stmt) = db
            .prepare(
                "INSERT OR IGNORE INTO case_delegations \
                 (case_id, delegate_pubkey, delegated_by, decision_id, delegated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .bind(&[
                JsValue::from_str(case_id),
                // Normalised on write as well as on read: the gate compares a
                // lowercased form, so a delegation stored in another casing
                // would silently never admit its delegatee.
                JsValue::from_str(&delegate_pubkey.to_ascii_lowercase()),
                JsValue::from_str(delegated_by),
                JsValue::from_str(decision_id),
                JsValue::from_f64(at as f64),
            ])
        {
            let _ = stmt.run().await;
        }
    }

    /// Project a signed 31403 ActionResponse onto `broker_decisions` and the
    /// case's state (COM-16 / F3).
    ///
    /// The parsed outcome — including the non-binary `delegate`/`promote`/
    /// `precedent` forms — is routed through the tested `DecisionOrchestrator`
    /// (via [`plan_action_response`], which calls `DecisionOrchestrator::decide`),
    /// so the resulting `CaseState` matches the outcome instead of the former
    /// projection's fixed `under_review` fallback. A malformed, terminal or
    /// self-review response yields an error and persists nothing — the case is
    /// left unchanged, never parked.
    /// Project a 31403 ActionResponse, recording a durable receipt of the stage
    /// the response actually reached (ADR-2010).
    ///
    /// The relay has already stored the envelope and sent `OK` by the time this
    /// runs, so the acknowledgement the client saw certifies storage and nothing
    /// more. What happens next is now recorded rather than assumed: a receipt is
    /// written at `relay-accepted`, and the decision row, the case state and the
    /// receipt's transition to `projection-committed` are submitted as a single
    /// D1 batch — one implicit transaction, so a half-applied projection cannot
    /// occur. A redelivery of the same signed event is recognised by its full
    /// event id and never re-runs the mutation.
    pub(crate) async fn project_action_response(&self, event: &NostrEvent) -> ReceiptOutcome {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => {
                return ReceiptOutcome::NotRecorded {
                    error: "DB binding missing".to_string(),
                }
            }
        };

        // Correlation first: an event we cannot join to a case gets no receipt
        // and no projection. ADR-2010 keeps an uncorrelated request unresolved
        // rather than absorbing it into a fallback case.
        let correlation = match receipts::correlate(event) {
            Some(c) => c,
            None => return ReceiptOutcome::Uncorrelated,
        };
        let case_id = correlation.case_id.clone();
        // Check completed receipts before hydrating a now-terminal case. A
        // legitimate redelivery must report the prior result, not fail planning.
        #[derive(serde::Deserialize)]
        struct PriorReceipt {
            stage: String,
        }
        let prior = match db
            .prepare("SELECT stage FROM governance_receipts WHERE event_id = ?1")
            .bind(&[JsValue::from_str(&event.id)])
        {
            Ok(stmt) => stmt.first::<PriorReceipt>(None).await,
            Err(error) => {
                return ReceiptOutcome::NotRecorded {
                    error: format!("receipt lookup bind: {error:?}"),
                }
            }
        };
        match prior {
            Ok(Some(row)) if row.stage == "projection-committed" => {
                let store = receipts::D1ReceiptStore::new(db);
                return match store
                    .record_accepted(&correlation, auth::js_now_secs())
                    .await
                {
                    Ok(receipts::AcceptOutcome::Replay { replays, .. }) => {
                        ReceiptOutcome::DuplicateIgnored { replays }
                    }
                    Ok(_) => ReceiptOutcome::NotRecorded {
                        error: "committed receipt vanished".into(),
                    },
                    Err(error) => ReceiptOutcome::NotRecorded { error },
                };
            }
            Err(error) => {
                return ReceiptOutcome::NotRecorded {
                    error: format!("receipt lookup: {error:?}"),
                }
            }
            _ => {}
        }

        // Hydrate the case aggregate from its D1 projection: the orchestrator
        // reads category/state/created_by/share-states, and the latest decision
        // id links the provenance chain.
        let case_row = db
            .prepare(
                "SELECT category, state, effective_tier, nostr_event_id, created_by, \
                 from_share_state, to_share_state \
                 FROM broker_cases WHERE id = ?1 LIMIT 1",
            )
            .bind(&[JsValue::from_str(&case_id)])
            .ok();
        let case_row = match case_row {
            Some(stmt) => stmt.first::<BrokerCaseRow>(None).await.ok().flatten(),
            None => None,
        };

        #[derive(serde::Deserialize)]
        struct LatestDecisionRow {
            decision_id: String,
        }
        let latest_stmt = db
            .prepare(
                "SELECT decision_id FROM broker_decisions \
                 WHERE case_id = ?1 ORDER BY decided_at DESC, decision_id DESC LIMIT 1",
            )
            .bind(&[JsValue::from_str(&case_id)])
            .ok();
        let latest_decision_id = match latest_stmt {
            Some(stmt) => stmt
                .first::<LatestDecisionRow>(None)
                .await
                .ok()
                .flatten()
                .map(|r| r.decision_id),
            None => None,
        };

        let proj = match plan_action_response(
            &case_id,
            case_row.as_ref(),
            &event.id,
            &event.content,
            &event.pubkey,
            latest_decision_id,
            event.created_at,
        ) {
            Ok(proj) => proj,
            Err(e) => {
                // A malformed or unroutable response is a rejection, not a
                // silent drop: the receipt records that it never projected.
                let store = receipts::D1ReceiptStore::new(db);
                let now = auth::js_now_secs();
                let _ = store.record_accepted(&correlation, now).await;
                let _ = store
                    .mark_projection_failed(&event.id, &format!("{e:?}"), now)
                    .await;
                return ReceiptOutcome::ProjectionFailed {
                    error: format!("{e:?}"),
                };
            }
        };

        // Captured before `proj` is consumed: an admin's `Delegate{to}` has to
        // project a `case_delegations` row, which is what later admits the
        // delegatee's own 31403 for this one case (FR6.2).
        let delegate_target = if proj.outcome == "delegate" {
            proj.outcome_detail.clone()
        } else {
            None
        };
        let delegating_decision_id = proj.decision_id.clone();
        let delegated_case_id = case_id.clone();

        let commit = receipts::ProjectionCommit {
            event_id: event.id.clone(),
            case_id,
            request_event_id: case_row
                .as_ref()
                .and_then(|r| r.nostr_event_id.clone())
                .unwrap_or_default(),
            expected_state: case_row
                .as_ref()
                .map(|r| r.state.clone())
                .unwrap_or_default(),
            decision_id: proj.decision_id,
            outcome: proj.outcome,
            outcome_detail: proj.outcome_detail,
            prior_decision_id: proj.prior_decision_id,
            reasoning: proj.reasoning,
            broker_pubkey: event.pubkey.clone(),
            new_state: proj.new_state.as_str().to_string(),
            decided_at: event.created_at,
        };

        let store = receipts::D1ReceiptStore::new(db);
        let outcome = receipts::apply_with_receipt(
            &store,
            &correlation,
            receipts::Commit::Response(&commit),
            auth::js_now_secs(),
        )
        .await;

        // FR6.2: only a delegation that actually COMMITTED opens the gate. A
        // projection that failed leaves no delegation behind, so a reviewer can
        // never be admitted on the strength of a decision that did not land.
        if outcome.is_applied() {
            if let Some(delegate) = delegate_target.as_deref().filter(|d| !d.trim().is_empty()) {
                self.record_case_delegation(
                    &delegated_case_id,
                    delegate,
                    &event.pubkey,
                    &delegating_decision_id,
                    event.created_at,
                )
                .await;
            }
        }

        match &outcome {
            ReceiptOutcome::ProjectionFailed { error } => {
                console_warn!(
                    "governance receipt {}: projection failed: {}",
                    &event.id,
                    error
                );
            }
            ReceiptOutcome::NotRecorded { error } => {
                console_warn!(
                    "governance receipt {}: could not be recorded: {}",
                    &event.id,
                    error
                );
            }
            _ => {}
        }
        outcome
    }

    /// F6 (DDD §7a.1): the governance-role rank of a pubkey for the
    /// supersession-authority gradient.
    ///
    /// Combines the relay's own admin status (a whitelist admin ranks at least
    /// `admin`) with any explicit `broker_roles` grant (e.g. `owner`), taking the
    /// maximum. The absolute number is meaningless; only the ordering matters
    /// (`governance::broker::governance_role_rank`).
    pub(crate) async fn governance_rank(&self, pubkey: &str) -> u8 {
        use governance::broker::governance_role_rank;
        let mut rank = 0u8;
        if self.admin_cache.is_admin(pubkey, &self.env).await {
            rank = rank.max(governance_role_rank("admin"));
        }
        if let Ok(db) = self.env.d1("DB") {
            #[derive(serde::Deserialize)]
            struct RoleRow {
                role: String,
            }
            if let Ok(stmt) = db
                .prepare("SELECT role FROM broker_roles WHERE pubkey = ?1")
                .bind(&[JsValue::from_str(pubkey)])
            {
                if let Ok(result) = stmt.all().await {
                    if let Ok(rows) = result.results::<RoleRow>() {
                        for row in rows {
                            rank = rank.max(governance_role_rank(&row.role));
                        }
                    }
                }
            }
        }
        rank
    }

    /// F6 (DDD §7a.1): whether `superseder` may supersede the decision published
    /// on `superseded_event_id`, on the case named by the superseding event's own
    /// `d` tag (`case_id`).
    ///
    /// Deny-by-default: if the superseded decision cannot be located (so its
    /// original signer is unknown), authority cannot be established and the
    /// supersession is refused. The decision must belong to `case_id` and still be
    /// effective (`superseded_by IS NULL`); otherwise the pure
    /// `governance::broker::supersede_authority` decides from the two role ranks.
    pub(crate) async fn supersession_authorised(
        &self,
        superseder: &str,
        event_id: &str,
        case_id: &str,
        superseded_event_id: &str,
    ) -> std::result::Result<(), SupersessionRefusal> {
        let db = self
            .env
            .d1("DB")
            .map_err(|_| SupersessionRefusal::TargetMissing)?;
        let target = Self::load_superseded_decision(&db, superseded_event_id).await;
        supersession_ingest_refusal(event_id, case_id, target.as_ref())?;
        let target = target.ok_or(SupersessionRefusal::TargetMissing)?;

        let original_rank = self.governance_rank(&target.broker_pubkey).await;
        let superseder_rank = self.governance_rank(superseder).await;
        if governance::broker::supersede_authority(
            &target.broker_pubkey,
            superseder,
            original_rank,
            superseder_rank,
        )
        .is_authorised()
        {
            Ok(())
        } else {
            Err(SupersessionRefusal::Unauthorised)
        }
    }

    /// The decision row a `supersedes` `e`-tag names, by its derived decision id.
    async fn load_superseded_decision(
        db: &worker::D1Database,
        superseded_event_id: &str,
    ) -> Option<SupersededDecisionRow> {
        db.prepare(
            "SELECT broker_pubkey, case_id, superseded_by FROM broker_decisions \
             WHERE decision_id = ?1 LIMIT 1",
        )
        .bind(&[JsValue::from_str(&decision_id_for_event(
            superseded_event_id,
        ))])
        .ok()?
        .first::<SupersededDecisionRow>(None)
        .await
        .ok()
        .flatten()
    }

    /// Replay check shared by the governance projections: a receipt already at
    /// `projection-committed` is a duplicate, counted and never re-run.
    async fn committed_replay(
        env: &Env,
        db: &worker::D1Database,
        correlation: &receipts::ReceiptCorrelation,
    ) -> Option<ReceiptOutcome> {
        #[derive(serde::Deserialize)]
        struct PriorReceipt {
            stage: String,
        }
        let prior = match db
            .prepare("SELECT stage FROM governance_receipts WHERE event_id = ?1")
            .bind(&[JsValue::from_str(&correlation.event_id)])
        {
            Ok(stmt) => stmt.first::<PriorReceipt>(None).await,
            Err(error) => {
                return Some(ReceiptOutcome::NotRecorded {
                    error: format!("receipt lookup bind: {error:?}"),
                })
            }
        };
        match prior {
            Ok(Some(row)) if row.stage == "projection-committed" => {
                let store = receipts::D1ReceiptStore::new(match env.d1("DB") {
                    Ok(d) => d,
                    Err(e) => {
                        return Some(ReceiptOutcome::NotRecorded {
                            error: format!("DB binding: {e}"),
                        })
                    }
                });
                Some(
                    match store
                        .record_accepted(correlation, auth::js_now_secs())
                        .await
                    {
                        Ok(receipts::AcceptOutcome::Replay { replays, .. }) => {
                            ReceiptOutcome::DuplicateIgnored { replays }
                        }
                        Ok(_) => ReceiptOutcome::NotRecorded {
                            error: "committed receipt vanished".into(),
                        },
                        Err(error) => ReceiptOutcome::NotRecorded { error },
                    },
                )
            }
            Err(error) => Some(ReceiptOutcome::NotRecorded {
                error: format!("receipt lookup: {error:?}"),
            }),
            _ => None,
        }
    }

    /// Record the acceptance and park the receipt at `projection-failed` with a
    /// wire `token`: the event is durably held, the mutation did not happen.
    async fn refuse_projection(
        env: &Env,
        correlation: &receipts::ReceiptCorrelation,
        token: String,
    ) -> ReceiptOutcome {
        let Ok(store_db) = env.d1("DB") else {
            return ReceiptOutcome::NotRecorded {
                error: "DB binding missing".into(),
            };
        };
        let store = receipts::D1ReceiptStore::new(store_db);
        let now = auth::js_now_secs();
        let _ = store.record_accepted(correlation, now).await;
        let _ = store
            .mark_projection_failed(&correlation.event_id, &token, now)
            .await;
        ReceiptOutcome::ProjectionFailed { error: token }
    }

    /// Log a governance receipt outcome that did not apply, in the same words
    /// for every projection.
    fn log_receipt_outcome(event_id: &str, outcome: &ReceiptOutcome) {
        match outcome {
            ReceiptOutcome::ProjectionFailed { error } => {
                console_warn!(
                    "governance receipt {}: projection failed: {}",
                    event_id,
                    error
                );
            }
            ReceiptOutcome::NotRecorded { error } => {
                console_warn!(
                    "governance receipt {}: could not be recorded: {}",
                    event_id,
                    error
                );
            }
            _ => {}
        }
    }

    /// Project a *superseding* kind-31403 onto `broker_decisions` and the case
    /// (F6, `DDD-judgment-broker-context.md` §7a), through the ADR-2010 stage
    /// machine.
    ///
    /// The authority was already enforced at ingest (`supersession_authorised`);
    /// this re-derives it and adds the state checks of [`plan_supersession`]. A
    /// refused plan leaves the receipt at `projection-failed` with a token and
    /// writes nothing: the prior decision stands, unmutated. A good plan commits
    /// the superseding decision row, the `superseded_by` mark, the case's move to
    /// `superseded` and the receipt together, in one batch whose every statement
    /// must change exactly one row (the Nostr event itself is never touched,
    /// Invariant 5).
    pub(crate) async fn project_supersession(&self, event: &NostrEvent) -> ReceiptOutcome {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => {
                return ReceiptOutcome::NotRecorded {
                    error: "DB binding missing".to_string(),
                }
            }
        };
        let Some(correlation) = receipts::correlate(event) else {
            return ReceiptOutcome::Uncorrelated;
        };
        let Some(superseded_event_id) = governance::extract_supersedes_target(&event.tags) else {
            return ReceiptOutcome::Uncorrelated;
        };
        if let Some(done) = Self::committed_replay(&self.env, &db, &correlation).await {
            return done;
        }
        let case_id = correlation.case_id.clone();

        let Some(target) = Self::load_superseded_decision(&db, superseded_event_id).await else {
            return Self::refuse_projection(
                &self.env,
                &correlation,
                SupersessionError::MissingSupersededDecision.token(),
            )
            .await;
        };
        let case_row = match db
            .prepare(
                "SELECT category, state, effective_tier, nostr_event_id, created_by, \
                 from_share_state, to_share_state \
                 FROM broker_cases WHERE id = ?1 LIMIT 1",
            )
            .bind(&[JsValue::from_str(&case_id)])
        {
            Ok(stmt) => stmt.first::<BrokerCaseRow>(None).await.ok().flatten(),
            Err(_) => None,
        };

        let original_rank = self.governance_rank(&target.broker_pubkey).await;
        let superseder_rank = self.governance_rank(&event.pubkey).await;
        let ctx = SupersessionContext {
            case_id: &case_id,
            superseded_case_id: &target.case_id,
            superseded_by: target.superseded_by.as_deref(),
            case_row: case_row.as_ref(),
        };
        let proj = match plan_supersession(
            &event.id,
            Some(superseded_event_id),
            &event.content,
            &event.pubkey,
            &target.broker_pubkey,
            original_rank,
            superseder_rank,
            &ctx,
            event.created_at,
        ) {
            Ok(proj) => proj,
            Err(e) => return Self::refuse_projection(&self.env, &correlation, e.token()).await,
        };

        let commit = receipts::SupersessionCommit {
            event_id: event.id.clone(),
            case_id,
            superseded_event_id: superseded_event_id.to_string(),
            superseded_decision_id: proj.superseded_decision_id,
            expected_state: case_row.map(|r| r.state).unwrap_or_default(),
            decision_id: proj.decision_id,
            outcome: proj.outcome,
            outcome_detail: proj.outcome_detail,
            reasoning: proj.reasoning,
            broker_pubkey: event.pubkey.clone(),
            decided_at: event.created_at,
        };
        let store = receipts::D1ReceiptStore::new(db);
        let outcome = receipts::apply_with_receipt(
            &store,
            &correlation,
            receipts::Commit::Supersession(&commit),
            auth::js_now_secs(),
        )
        .await;
        Self::log_receipt_outcome(&event.id, &outcome);
        outcome
    }

    /// Project an *appeal* kind-31402 (F6, `DDD-judgment-broker-context.md`
    /// §7a.2/§7a.3): reopen the cited case for a fresh human decision.
    ///
    /// An appeal reopens; it does not overturn. Standing is the case's requester
    /// of record (`created_by`, case-insensitive) and the appeal must cite a
    /// decision on that same case, which must be in a terminal state
    /// ([`plan_appeal`]). A refusal parks the receipt at `projection-failed` with
    /// a token; it is never a silent no-op. The overturning, if any, is a
    /// subsequent authorised kind-31403 on the now-`reopened` case.
    pub(crate) async fn project_appeal(&self, event: &NostrEvent) -> ReceiptOutcome {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => {
                return ReceiptOutcome::NotRecorded {
                    error: "DB binding missing".to_string(),
                }
            }
        };
        let Some(correlation) = receipts::correlate(event) else {
            return ReceiptOutcome::Uncorrelated;
        };
        let Some(cited_event_id) = governance::extract_appeal_target(&event.tags) else {
            return ReceiptOutcome::Uncorrelated;
        };
        if let Some(done) = Self::committed_replay(&self.env, &db, &correlation).await {
            return done;
        }
        // Ingest guarantees a `case` tag distinct from `d` (`appeal_shape_refusal`).
        let case_id = filter::tag_value(event, "case").unwrap_or_default();
        let cited_decision_id = decision_id_for_event(cited_event_id);

        let case_row = match db
            .prepare(
                "SELECT category, state, effective_tier, nostr_event_id, created_by, \
                 from_share_state, to_share_state \
                 FROM broker_cases WHERE id = ?1 LIMIT 1",
            )
            .bind(&[JsValue::from_str(&case_id)])
        {
            Ok(stmt) => stmt.first::<BrokerCaseRow>(None).await.ok().flatten(),
            Err(_) => None,
        };
        #[derive(serde::Deserialize)]
        struct CitedRow {
            case_id: String,
        }
        let cited_case = match db
            .prepare("SELECT case_id FROM broker_decisions WHERE decision_id = ?1 LIMIT 1")
            .bind(&[JsValue::from_str(&cited_decision_id)])
        {
            Ok(stmt) => stmt
                .first::<CitedRow>(None)
                .await
                .ok()
                .flatten()
                .map(|r| r.case_id),
            Err(_) => None,
        };

        if let Err(refusal) = plan_appeal(
            &event.pubkey,
            &case_id,
            case_row.as_ref(),
            cited_case.as_deref(),
        ) {
            let outcome = Self::refuse_projection(&self.env, &correlation, refusal.token()).await;
            Self::log_receipt_outcome(&event.id, &outcome);
            return outcome;
        }

        let commit = receipts::AppealCommit {
            event_id: event.id.clone(),
            case_id,
            appellant: event.pubkey.clone(),
            cited_event_id: cited_event_id.to_string(),
            cited_decision_id,
            at: event.created_at,
        };
        let store = receipts::D1ReceiptStore::new(db);
        let outcome = receipts::apply_with_receipt(
            &store,
            &correlation,
            receipts::Commit::Appeal(&commit),
            auth::js_now_secs(),
        )
        .await;
        Self::log_receipt_outcome(&event.id, &outcome);
        outcome
    }

    /// Check whether a kind-5 deletion event targets events by other authors.
    ///
    /// Returns `true` if any `e` tag references an event not authored by the
    /// deletion event's pubkey.
    pub(crate) async fn deletion_targets_others(&self, event: &NostrEvent) -> bool {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return false,
        };

        #[derive(serde::Deserialize)]
        struct EventPubkeyRow {
            pubkey: String,
            kind: f64,
            tags: String,
        }

        let target_ids: Vec<&str> = event
            .tags
            .iter()
            .filter(|t| t.len() >= 2 && t[0] == "e")
            .map(|t| t[1].as_str())
            .collect();

        // Phase 2: a wrap addressed to one of the deleter's own recipient keys is
        // theirs to remove. Looked up lazily, once, on the raw signer.
        let mut own_keys: Option<Vec<String>> = None;

        for target_id in &target_ids {
            let stmt = db.prepare("SELECT pubkey, kind, tags FROM events WHERE id = ?1 LIMIT 1");
            match stmt.bind(&[JsValue::from_str(target_id)]) {
                Ok(s) => {
                    if let Ok(Some(row)) = s.first::<EventPubkeyRow>(None).await {
                        if row.pubkey != event.pubkey {
                            if row.kind as u64 == GIFT_WRAP_KIND && self.recipient_keys_enabled() {
                                if own_keys.is_none() {
                                    own_keys =
                                        self.recipient_read_set(&Some(event.pubkey.clone())).await;
                                }
                                if own_keys.as_ref().is_some_and(|set| {
                                    crate::recipient_keys::wrap_addressed_to(
                                        row.kind as u64,
                                        &row.tags,
                                        set,
                                    )
                                }) {
                                    continue;
                                }
                            }
                            return true;
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        false
    }
}

// ---------------------------------------------------------------------------
// F11 (PRD-010): Federated kind allowlist helpers
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Check whether the event's pubkey belongs to a known mesh peer.
    ///
    /// Returns `true` when:
    ///   1. `MESH_MODE` is set to a value other than `"standalone"` (or empty), AND
    ///   2. `MESH_ALLOWED_REMOTE_DIDS` contains the pubkey.
    ///
    /// When `MESH_MODE` is `"standalone"` (the default) or the env var is absent,
    /// this always returns `false` — all events are treated as local.
    pub(crate) fn is_mesh_peer(&self, pubkey: &str) -> bool {
        let mesh_mode = match self.env.var("MESH_MODE") {
            Ok(val) => val.to_string(),
            Err(_) => return false,
        };

        if mesh_mode.is_empty() || mesh_mode == "standalone" {
            return false;
        }

        let allowed_dids = match self.env.var("MESH_ALLOWED_REMOTE_DIDS") {
            Ok(val) => val.to_string(),
            Err(_) => return false,
        };

        if allowed_dids.is_empty() {
            return false;
        }

        allowed_dids.split(',').any(|did| did.trim() == pubkey)
    }

    /// Check whether a given event kind is in the `MESH_FEDERATED_KINDS`
    /// allowlist.
    ///
    /// Reads `MESH_FEDERATED_KINDS` from the Worker env (comma-separated list
    /// of u64 values). When the env var is absent or empty, returns `false`
    /// (fail-closed: no kinds allowed from peers by default).
    pub(crate) fn is_federated_kind_allowed(&self, kind: u64) -> bool {
        let kinds_str = match self.env.var("MESH_FEDERATED_KINDS") {
            Ok(val) => val.to_string(),
            Err(_) => return false,
        };

        if kinds_str.is_empty() {
            return false;
        }

        kinds_str
            .split(',')
            .filter_map(|s| s.trim().parse::<u64>().ok())
            .any(|k| k == kind)
    }
}

// ---------------------------------------------------------------------------
// NIP-56: Report processing
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Process a kind-1984 report event.
    ///
    /// Extracts the `e` tag (reported event), `p` tag (reported pubkey), and
    /// reason from the `report` tag or content. Inserts into the `reports`
    /// table and triggers auto-hide if the threshold is reached.
    pub(crate) async fn process_report(&self, report_event: &NostrEvent) {
        // Extract the reported event ID from the `e` tag
        let reported_event_id = match filter::tag_value(report_event, "e") {
            Some(id) => id,
            None => return, // Invalid report: no `e` tag
        };

        // Extract the reported pubkey from the `p` tag
        let reported_pubkey = match filter::tag_value(report_event, "p") {
            Some(pk) => pk,
            None => return, // Invalid report: no `p` tag
        };

        // Extract reason from `report` tag first, fall back to content
        let reason = filter::tag_value(report_event, "report").unwrap_or_else(|| {
            if report_event.content.is_empty() {
                "other".to_string()
            } else {
                report_event.content.clone()
            }
        });

        // Separate structured reason from free-text
        let (reason_code, reason_text) = match reason.as_str() {
            r @ ("nudity" | "profanity" | "illegal" | "spam" | "impersonation") => {
                // Structured reason; content may hold additional free-text
                let text = if report_event.content.is_empty() {
                    None
                } else {
                    Some(report_event.content.as_str())
                };
                (r.to_string(), text)
            }
            _ => {
                // Free-text reason
                ("other".to_string(), Some(reason.as_str()))
            }
        };

        let _ = moderation::insert_report(
            &self.env,
            &report_event.id,
            &report_event.pubkey,
            &reported_event_id,
            &reported_pubkey,
            &reason_code,
            reason_text,
        )
        .await;
    }

    /// WI-2 + P0-4(a): mirror a kind-30910 (ban), 30911 (mute), 30915 (unban),
    /// or 30916 (unmute) event into the local `moderation_actions` table.
    /// Idempotent via `event_id` dedup -- re-receiving the same event is a
    /// no-op. Missing target pubkey (no `p` tag) silently drops the mirror.
    /// Unban/unmute rows are written as their own action rows (preserving
    /// signer + target + created_at) so `load_state` can apply latest-wins and
    /// cancel a prior ban/mute.
    pub(crate) async fn mirror_moderation_action(&self, event: &NostrEvent) {
        let action = match event.kind {
            KIND_BAN => "ban",
            KIND_MUTE => "mute",
            KIND_UNBAN => "unban",
            KIND_UNMUTE => "unmute",
            _ => return,
        };

        let Some(target) = filter::tag_value(event, "p") else {
            return;
        };

        // expires_at: mutes may carry a NIP-40 style `expiration` tag. Bans,
        // unbans and unmutes never expire; we persist NULL.
        let expires_at: Option<i64> = if action == "mute" {
            filter::tag_value(event, "expiration").and_then(|s| s.parse::<i64>().ok())
        } else {
            None
        };

        let reason: Option<&str> = if event.content.is_empty() {
            None
        } else {
            Some(event.content.as_str())
        };

        let Ok(db) = self.env.d1("DB") else {
            return;
        };

        let row_id = format!("mirror:{}", event.id);
        // P0-4(a): persist the event's signed `created_at` (not receipt time) so
        // `load_state` latest-wins ordering between ban/unban (and mute/unmute)
        // follows the admin's intended sequence even under out-of-order delivery.
        let created_at = event.created_at;

        let sql = "INSERT INTO moderation_actions \
             (id, action, target_pubkey, performed_by, reason, expires_at, event_id, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
             ON CONFLICT (id) DO NOTHING";
        let Ok(stmt) = db.prepare(sql).bind(&[
            JsValue::from_str(&row_id),
            JsValue::from_str(action),
            JsValue::from_str(&target),
            JsValue::from_str(&event.pubkey),
            reason.map(JsValue::from_str).unwrap_or(JsValue::NULL),
            expires_at
                .map(|v| JsValue::from_f64(v as f64))
                .unwrap_or(JsValue::NULL),
            JsValue::from_str(&event.id),
            JsValue::from_f64(created_at as f64),
        ]) else {
            return;
        };
        let _ = stmt.run().await;
    }
}

// ---------------------------------------------------------------------------
// Phase C (write side): data-tier write validation tests
// ---------------------------------------------------------------------------
//
// The EVENT (write) gate for calendar kinds mirrors the READ projection. These
// tests drive the same decision the handler executes: the AUTHOR's projection
// tier for an RSVP's TARGET (resolved zone/venue from D1) feeds `project_tier`,
// then `rsvp_write_permitted` accepts only `Full`; a zone-tagged calendar event
// feeds `calendar_write_permitted` with the author's resolved write access. The
// D1 lookups themselves are exercised by integration tests; here we pin the
// pure decision boundary that those lookups feed into.
#[cfg(test)]
mod count_auth_tests {
    //! Read-authorization gate shared by REQ and COUNT. COUNT previously called
    //! `query_events` directly with no gating, leaking existence/counts of sealed
    //! DMs and zone-private content; it now routes through this same gate.
    use super::*;

    fn filter(json: serde_json::Value) -> NostrFilter {
        serde_json::from_value(json).expect("valid filter")
    }

    fn wrap(recipient: &str) -> NostrEvent {
        serde_json::from_value(serde_json::json!({
            "id": "0".repeat(64), "pubkey": "e".repeat(64), "created_at": 1, "kind": 1059,
            "tags": [["p", recipient]], "content": "x", "sig": "0".repeat(128)
        }))
        .expect("valid event")
    }

    #[test]
    fn wrap_is_readable_only_by_its_recipient() {
        let ev = wrap(&"a".repeat(64));
        assert!(gift_wrap_readable_by(&ev, Some(&"a".repeat(64))));
        assert!(
            gift_wrap_readable_by(&ev, Some(&"A".repeat(64))),
            "case-insensitive"
        );
    }

    #[test]
    fn counter_example_other_viewers_and_anonymous_cannot_read_a_wrap() {
        let ev = wrap(&"a".repeat(64));
        assert!(!gift_wrap_readable_by(&ev, Some(&"b".repeat(64))));
        assert!(!gift_wrap_readable_by(&ev, None));
    }

    #[test]
    fn counter_example_wrap_without_a_recipient_is_unreadable() {
        let mut ev = wrap(&"a".repeat(64));
        ev.tags.clear();
        assert!(!gift_wrap_readable_by(&ev, Some(&"a".repeat(64))));
    }

    #[test]
    fn non_wrap_kinds_are_unaffected() {
        let mut ev = wrap(&"a".repeat(64));
        ev.kind = 1;
        assert!(gift_wrap_readable_by(&ev, None));
        assert!(gift_wrap_readable_by(&ev, Some(&"b".repeat(64))));
    }

    #[test]
    fn a_kindless_filter_is_not_stopped_by_the_filter_gate_so_the_event_check_must_hold() {
        // Documents the gap this check closes: the filter gate passes it through.
        let filters = vec![filter(serde_json::json!({ "authors": ["e".repeat(64)] }))];
        assert!(NostrRelayDO::gate_kind_1059_filters(filters, &None).is_some());
        assert!(!gift_wrap_readable_by(&wrap(&"a".repeat(64)), None));
    }

    #[test]
    fn non_dm_filter_passes_through_unauthenticated() {
        let filters = vec![filter(serde_json::json!({ "kinds": [1] }))];
        assert!(NostrRelayDO::gate_kind_1059_filters(filters, &None).is_some());
    }

    #[test]
    fn kind_1059_rejected_when_unauthenticated() {
        let filters = vec![filter(serde_json::json!({ "kinds": [1059] }))];
        // Deny-by-default: an unauthenticated COUNT/REQ for sealed DMs is rejected.
        assert!(NostrRelayDO::gate_kind_1059_filters(filters, &None).is_none());
    }

    #[test]
    fn kind_1059_injects_p_tag_for_authed_pubkey() {
        let pk = "a".repeat(64);
        let filters = vec![filter(serde_json::json!({ "kinds": [1059] }))];
        let out = NostrRelayDO::gate_kind_1059_filters(filters, &Some(pk.clone()))
            .expect("authed kind-1059 read allowed");
        assert_eq!(out[0].extra.get("#p"), Some(&serde_json::json!([pk])));
    }

    #[test]
    fn kind_1059_overrides_client_supplied_p_tag() {
        let pk = "a".repeat(64);
        let attacker_target = "b".repeat(64);
        let filters = vec![filter(
            serde_json::json!({ "kinds": [1059], "#p": [attacker_target] }),
        )];
        let out = NostrRelayDO::gate_kind_1059_filters(filters, &Some(pk.clone()))
            .expect("authed kind-1059 read allowed");
        // The #p constraint must be rebound to the authed pubkey so a client
        // cannot count/read another user's sealed DMs.
        assert_eq!(out[0].extra.get("#p"), Some(&serde_json::json!([pk])));
    }
}

#[cfg(test)]
mod governance_projection_tests {
    //! COM-16 / F3: the 31403 ActionResponse projection routes non-binary
    //! outcomes through the tested `DecisionOrchestrator`. These exercise the
    //! pure `plan_action_response` seam — the worker-side assembly of a
    //! `CaseSnapshot` from a D1 row plus the orchestrator call — without a live
    //! D1. The env-bound read/write in `project_action_response` is a thin shell
    //! over this.
    use super::*;
    use nostr_bbs_core::governance::broker::{CaseState, OrchestrationError};

    fn open_case_row() -> BrokerCaseRow {
        BrokerCaseRow {
            category: "manual_submission".into(),
            state: "open".into(),
            effective_tier: None,
            nostr_event_id: Some("r".repeat(64)),
            created_by: "agent-alice".into(),
            from_share_state: None,
            to_share_state: None,
        }
    }

    #[test]
    fn delegate_response_reaches_delegated_not_under_review() {
        let row = open_case_row();
        let proj = plan_action_response(
            "case-1",
            Some(&row),
            &"e".repeat(64),
            r#"{"action":"delegate","delegate_to":"human-carol","reasoning":"reassign"}"#,
            "human-bob",
            None,
            2_000,
        )
        .expect("delegate projects");
        assert_eq!(proj.outcome, "delegate");
        assert_eq!(proj.outcome_detail.as_deref(), Some("human-carol"));
        assert_eq!(proj.new_state, CaseState::Delegated);
        // The falsification target for WP-4.
        assert_ne!(proj.new_state, CaseState::UnderReview);
    }

    #[test]
    fn promote_and_precedent_reach_matching_states() {
        let row = open_case_row();
        let promote = plan_action_response(
            "case-1",
            Some(&row),
            &"a".repeat(64),
            r#"{"action":"promote","iri":"urn:ngm:class:knowledge-graph"}"#,
            "human-bob",
            None,
            2_000,
        )
        .expect("promote projects");
        assert_eq!(promote.new_state, CaseState::Promoted);

        let precedent = plan_action_response(
            "case-1",
            Some(&open_case_row()),
            &"b".repeat(64),
            r#"{"action":"precedent","scope":"org-wide"}"#,
            "human-bob",
            None,
            2_000,
        )
        .expect("precedent projects");
        assert_eq!(precedent.new_state, CaseState::Precedent);
    }

    #[test]
    fn binary_outcomes_reach_decided_with_no_detail() {
        let proj = plan_action_response(
            "case-1",
            Some(&open_case_row()),
            &"c".repeat(64),
            r#"{"action":"approve","reasoning":"ok"}"#,
            "human-bob",
            None,
            2_000,
        )
        .expect("approve projects");
        assert_eq!(proj.new_state, CaseState::Decided);
        assert_eq!(proj.outcome_detail, None);
    }

    #[test]
    fn absent_case_row_stays_unresolved_until_request_projects() {
        // An early response must not invent a request case.
        let proj = plan_action_response(
            "case-unknown",
            None,
            &"d".repeat(64),
            r#"{"action":"reject","reasoning":"no"}"#,
            "human-bob",
            None,
            2_000,
        )
        .expect_err("missing request cannot project");
        assert!(matches!(
            proj,
            OrchestrationError::ShareTransitionRejected(_)
        ));
    }

    #[test]
    fn unknown_persisted_state_cannot_default_to_open() {
        let mut row = open_case_row();
        row.state = "corrupt".into();
        assert!(plan_action_response(
            "case-1",
            Some(&row),
            &"c".repeat(64),
            r#"{"action":"approve"}"#,
            "human-bob",
            None,
            2000
        )
        .is_err());
    }

    #[test]
    fn terminal_case_row_rejects_second_response() {
        let mut row = open_case_row();
        row.state = "decided".into();
        let err = plan_action_response(
            "case-1",
            Some(&row),
            &"f".repeat(64),
            r#"{"action":"approve","reasoning":"again"}"#,
            "human-bob",
            None,
            2_000,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            OrchestrationError::Case(
                nostr_bbs_core::governance::broker::CaseError::AlreadyTerminal(_)
            )
        ));
    }

    #[test]
    fn malformed_response_is_rejected() {
        let err = plan_action_response(
            "case-1",
            Some(&open_case_row()),
            &"0".repeat(64),
            r#"{"action":"escalate"}"#,
            "human-bob",
            None,
            2_000,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            OrchestrationError::ShareTransitionRejected(_)
        ));
    }

    // ── F6: supersession-authority projection (DDD §7a) ──────────────────
    //
    // These exercise the pure `plan_supersession` seam — the worker-side
    // authority computation + aggregate supersede — that the env-bound
    // `project_supersession` shell wraps. The ingest-time gate
    // (`supersession_authorised`) is the same `supersede_authority` call over the
    // same ranks, so an unauthorised supersession is rejected here exactly as the
    // relay rejects it before save (canon §7a.4: "an unauthorised supersede
    // rejected by RelayGovernanceGate").

    /// admin-rank = 3 (`governance_role_rank("admin")`); owner-rank = 4.
    const ADMIN_RANK: u8 = 3;
    const OWNER_RANK: u8 = 4;

    /// A `decided` case created by `agent-alice`, the shape most tests act on.
    fn decided_row() -> BrokerCaseRow {
        BrokerCaseRow {
            state: "decided".into(),
            ..open_case_row()
        }
    }

    /// The context for a supersession of an effective decision on `row`'s own
    /// case, `case-1`.
    fn ctx(row: &BrokerCaseRow) -> SupersessionContext<'_> {
        SupersessionContext {
            case_id: "case-1",
            superseded_case_id: "case-1",
            superseded_by: None,
            case_row: Some(row),
        }
    }

    /// Plan bob superseding his own decision with a reasoned reject.
    fn plan_bob(
        content: &str,
        ctx: &SupersessionContext<'_>,
    ) -> std::result::Result<SupersessionProjection, SupersessionError> {
        plan_supersession(
            &"b".repeat(64),
            Some(&"a".repeat(64)),
            content,
            "human-bob",
            "human-bob",
            ADMIN_RANK,
            ADMIN_RANK,
            ctx,
            3_000,
        )
    }

    const REASONED: &str = r#"{"action":"reject","reasoning":"revoked"}"#;

    #[test]
    fn supersede_citing_decision_on_other_case_is_refused() {
        let row = decided_row();
        let mut c = ctx(&row);
        c.superseded_case_id = "case-other";
        assert_eq!(plan_bob(REASONED, &c), Err(SupersessionError::CaseMismatch));
    }

    #[test]
    fn supersede_of_already_superseded_decision_is_refused() {
        let row = decided_row();
        let mut c = ctx(&row);
        c.superseded_by = Some("dec-later");
        assert_eq!(
            plan_bob(REASONED, &c),
            Err(SupersessionError::TargetAlreadySuperseded)
        );
    }

    #[test]
    fn supersede_of_open_or_under_review_case_is_refused() {
        for state in ["open", "under_review"] {
            let row = BrokerCaseRow {
                state: state.into(),
                ..open_case_row()
            };
            assert_eq!(
                plan_bob(REASONED, &ctx(&row)),
                Err(SupersessionError::StateNotSupersedable(state.into())),
                "{state}"
            );
        }
    }

    #[test]
    fn supersede_of_reopened_case_by_authorised_signer_is_accepted() {
        // Canon §7a.3: Reopened --(new 31403)--> Superseded, the appeal-then-overturn path.
        let row = BrokerCaseRow {
            state: "reopened".into(),
            ..open_case_row()
        };
        let proj = plan_bob(REASONED, &ctx(&row)).expect("reopened is supersedable");
        assert_eq!(proj.new_state, CaseState::Superseded);
    }

    #[test]
    fn every_supersedable_state_is_accepted() {
        for state in receipts::SUPERSEDABLE_STATES {
            let row = BrokerCaseRow {
                state: state.into(),
                ..open_case_row()
            };
            assert!(plan_bob(REASONED, &ctx(&row)).is_ok(), "{state}");
        }
    }

    #[test]
    fn system_supersession_of_high_tier_case_is_refused() {
        let system = r#"{"action":"reject","reasoning":"auto","decided_by":"system:whelk-gate"}"#;
        for tier in ["high", "critical"] {
            let row = BrokerCaseRow {
                effective_tier: Some(tier.into()),
                ..decided_row()
            };
            assert_eq!(
                plan_bob(system, &ctx(&row)),
                Err(SupersessionError::HumanRequired),
                "{tier}"
            );
        }
        // A human signer on a high case, and a machine on a medium case, pass.
        let high = BrokerCaseRow {
            effective_tier: Some("high".into()),
            ..decided_row()
        };
        assert!(plan_bob(REASONED, &ctx(&high)).is_ok());
        let medium = BrokerCaseRow {
            effective_tier: Some("medium".into()),
            ..decided_row()
        };
        assert!(plan_bob(system, &ctx(&medium)).is_ok());
    }

    #[test]
    fn supersede_with_missing_case_row_is_refused_not_creator_blank() {
        let row = decided_row();
        let c = SupersessionContext {
            case_row: None,
            ..ctx(&row)
        };
        assert_eq!(plan_bob(REASONED, &c), Err(SupersessionError::CaseMissing));
    }

    #[test]
    fn the_superseder_who_created_the_case_is_refused_as_self_review() {
        let row = BrokerCaseRow {
            created_by: "human-bob".into(),
            ..decided_row()
        };
        assert_eq!(
            plan_bob(REASONED, &ctx(&row)),
            Err(SupersessionError::SelfReview)
        );
    }

    #[test]
    fn supersession_tokens_are_the_documented_wire_strings() {
        let t = |e: SupersessionError| e.token();
        assert_eq!(
            t(SupersessionError::CaseMismatch),
            "supersession_case_mismatch"
        );
        assert_eq!(
            t(SupersessionError::StateNotSupersedable("open".into())),
            "supersession_state_not_supersedable:open"
        );
        assert_eq!(
            t(SupersessionError::CaseMissing),
            "supersession_case_missing"
        );
        assert_eq!(
            t(SupersessionError::HumanRequired),
            "supersession_human_required"
        );
        assert_eq!(t(SupersessionError::SelfReview), "self_review");
        assert_eq!(
            t(SupersessionError::TargetAlreadySuperseded),
            "supersession_target_already_superseded"
        );
        assert_eq!(
            SupersessionRefusal::Unauthorised.reason(),
            "blocked: supersession_unauthorised"
        );
    }

    const EV: &str = "ev-new";

    #[test]
    fn redelivered_superseding_event_passes_ingest() {
        let done = SupersededDecisionRow {
            broker_pubkey: "human-bob".into(),
            case_id: "case-1".into(),
            superseded_by: Some(decision_id_for_event(EV)),
        };
        // The same signed event again: accepted, projection ignores the duplicate.
        assert_eq!(
            supersession_ingest_refusal(EV, "case-1", Some(&done)),
            Ok(())
        );
        // A different event racing for the same target is still refused.
        assert_eq!(
            supersession_ingest_refusal("ev-other", "case-1", Some(&done)),
            Err(SupersessionRefusal::TargetAlreadySuperseded)
        );
    }

    #[test]
    fn ingest_refuses_a_missing_foreign_or_spent_target() {
        let row = |case: &str, by: Option<&str>| SupersededDecisionRow {
            broker_pubkey: "human-bob".into(),
            case_id: case.into(),
            superseded_by: by.map(str::to_string),
        };
        assert_eq!(
            supersession_ingest_refusal(EV, "case-1", None),
            Err(SupersessionRefusal::TargetMissing)
        );
        assert_eq!(
            supersession_ingest_refusal(EV, "case-1", Some(&row("case-2", None))),
            Err(SupersessionRefusal::CaseMismatch)
        );
        assert_eq!(
            supersession_ingest_refusal(EV, "case-1", Some(&row("case-1", Some("dec-x")))),
            Err(SupersessionRefusal::TargetAlreadySuperseded)
        );
        assert_eq!(
            supersession_ingest_refusal(EV, "case-1", Some(&row("case-1", None))),
            Ok(())
        );
    }

    #[test]
    fn authorised_supersede_by_original_signer_accepted() {
        let superseded_event = "a".repeat(64);
        let superseding_event = "b".repeat(64);
        // bob (the original signer) revokes his own prior Approve with a Reject.
        let proj = plan_supersession(
            &superseding_event,
            Some(&superseded_event),
            r#"{"action":"reject","reasoning":"revoked: grant no longer holds"}"#,
            "human-bob", // superseder
            "human-bob", // original signer — same ⇒ OriginalSigner authority
            ADMIN_RANK,  // original rank
            ADMIN_RANK,  // superseder rank
            &ctx(&decided_row()),
            3_000,
        )
        .expect("original signer may supersede");
        assert_eq!(proj.outcome, "reject");
        // The superseding decision references the one it supersedes (§7a.2).
        assert_eq!(
            proj.superseded_decision_id,
            decision_id_for_event(&superseded_event)
        );
        assert_eq!(proj.decision_id, decision_id_for_event(&superseding_event));
        // The case moves to Superseded (§7a.3).
        assert_eq!(proj.new_state, CaseState::Superseded);
    }

    #[test]
    fn authorised_supersede_by_higher_role_accepted() {
        let superseded_event = "a".repeat(64);
        let superseding_event = "c".repeat(64);
        // carol (owner, rank 4) supersedes bob's (admin, rank 3) decision.
        let proj = plan_supersession(
            &superseding_event,
            Some(&superseded_event),
            r#"{"action":"reject","reasoning":"overridden by governance"}"#,
            "human-carol",
            "human-bob",
            ADMIN_RANK,
            OWNER_RANK,
            &ctx(&decided_row()),
            3_000,
        )
        .expect("higher role may supersede");
        assert_eq!(proj.new_state, CaseState::Superseded);
    }

    #[test]
    fn unauthorised_supersede_by_equal_role_rejected() {
        let superseded_event = "a".repeat(64);
        let superseding_event = "d".repeat(64);
        // mallory (a different admin, equal rank) may NOT supersede bob's
        // decision — the authority gradient is not collapsed (§7a.1).
        let err = plan_supersession(
            &superseding_event,
            Some(&superseded_event),
            r#"{"action":"reject","reasoning":"I disagree"}"#,
            "human-mallory",
            "human-bob",
            ADMIN_RANK,
            ADMIN_RANK,
            &ctx(&decided_row()),
            3_000,
        )
        .unwrap_err();
        assert_eq!(
            err,
            SupersessionError::Unauthorised {
                superseder: "human-mallory".into()
            }
        );
    }

    #[test]
    fn unauthorised_supersede_by_lower_role_rejected() {
        let superseded_event = "a".repeat(64);
        let superseding_event = "e".repeat(64);
        // A lower-rank different signer is rejected.
        let err = plan_supersession(
            &superseding_event,
            Some(&superseded_event),
            r#"{"action":"reject","reasoning":"nope"}"#,
            "human-dave",
            "human-carol",
            OWNER_RANK, // original outranks superseder
            ADMIN_RANK,
            &ctx(&decided_row()),
            3_000,
        )
        .unwrap_err();
        assert!(matches!(err, SupersessionError::Unauthorised { .. }));
    }

    #[test]
    fn supersede_without_reason_rejected() {
        let superseded_event = "a".repeat(64);
        let superseding_event = "f".repeat(64);
        let err = plan_supersession(
            &superseding_event,
            Some(&superseded_event),
            r#"{"action":"reject"}"#, // no reasoning field
            "human-bob",
            "human-bob",
            ADMIN_RANK,
            ADMIN_RANK,
            &ctx(&decided_row()),
            3_000,
        )
        .unwrap_err();
        assert_eq!(err, SupersessionError::MissingReason);
    }

    #[test]
    fn supersede_without_referenced_event_rejected() {
        let err = plan_supersession(
            &"b".repeat(64),
            None, // no supersedes e-tag target
            r#"{"action":"reject","reasoning":"x"}"#,
            "human-bob",
            "human-bob",
            ADMIN_RANK,
            ADMIN_RANK,
            &ctx(&decided_row()),
            3_000,
        )
        .unwrap_err();
        assert_eq!(err, SupersessionError::MissingSupersededDecision);
    }

    #[test]
    fn supersession_chain_renders_effective_and_superseded_decisions() {
        // Two supersessions chained: dec(A) --superseded_by--> dec(B)
        // --superseded_by--> dec(C). The projection expresses the chain via the
        // superseding row's prior_decision_id link + the superseded row's
        // superseded_by mark; the client renders the newest as effective and the
        // earlier ones as history. Here we assert the projection produces the
        // chain data a renderer consumes.
        let ev_a = "a".repeat(64);
        let ev_b = "b".repeat(64);
        let ev_c = "c".repeat(64);
        let dec_a = decision_id_for_event(&ev_a);
        let dec_b = decision_id_for_event(&ev_b);
        let dec_c = decision_id_for_event(&ev_c);

        // B supersedes A (original signer bob).
        let first = plan_supersession(
            &ev_b,
            Some(&ev_a),
            r#"{"action":"reject","reasoning":"revoke"}"#,
            "human-bob",
            "human-bob",
            ADMIN_RANK,
            ADMIN_RANK,
            &ctx(&decided_row()),
            3_000,
        )
        .expect("B supersedes A");
        assert_eq!(first.decision_id, dec_b);
        assert_eq!(first.superseded_decision_id, dec_a);
        assert_eq!(first.new_state, CaseState::Superseded);

        // C supersedes B (higher-role owner carol) — forward-chaining (§7a.3).
        let second = plan_supersession(
            &ev_c,
            Some(&ev_b),
            r#"{"action":"approve","reasoning":"re-granted on review"}"#,
            "human-carol",
            "human-bob",
            ADMIN_RANK,
            OWNER_RANK,
            &ctx(&decided_row()),
            3_100,
        )
        .expect("C supersedes B");
        assert_eq!(second.decision_id, dec_c);
        assert_eq!(second.superseded_decision_id, dec_b);
        // The effective decision is the newest (C); A and B are retained history.
        assert_eq!(second.new_state, CaseState::Superseded);
        assert_eq!(second.outcome, "approve");
    }
}

#[cfg(test)]
mod appeal_projection_tests {
    //! Appeal standing (DDD §7a.2). The pure `plan_appeal` seam and the
    //! `APPEAL_REOPEN_SQL` statement, run against SQLite built from the DDL
    //! `ensure_schema` applies.
    use super::receipts::test_support::{governance_db, seed_case, seed_decision};
    use super::receipts::APPEAL_REOPEN_SQL;
    use super::*;

    fn row(state: &str, created_by: &str) -> BrokerCaseRow {
        BrokerCaseRow {
            category: "manual_submission".into(),
            state: state.into(),
            effective_tier: None,
            nostr_event_id: Some("r".repeat(64)),
            created_by: created_by.into(),
            from_share_state: None,
            to_share_state: None,
        }
    }

    #[test]
    fn plan_appeal_refuses_non_requester() {
        let r = row("decided", "agent-alice");
        assert_eq!(
            plan_appeal("agent-mallory", "case-1", Some(&r), Some("case-1")),
            Err(AppealRefusal::NoStanding)
        );
    }

    #[test]
    fn plan_appeal_accepts_the_requester_case_insensitively() {
        let r = row("decided", "AGENT-Alice");
        assert_eq!(
            plan_appeal("agent-alice", "case-1", Some(&r), Some("case-1")),
            Ok(())
        );
    }

    #[test]
    fn plan_appeal_refuses_decision_from_another_case() {
        let r = row("decided", "agent-alice");
        assert_eq!(
            plan_appeal("agent-alice", "case-1", Some(&r), Some("case-2")),
            Err(AppealRefusal::TargetMismatch)
        );
        assert_eq!(
            plan_appeal("agent-alice", "case-1", Some(&r), None),
            Err(AppealRefusal::TargetMissing)
        );
    }

    #[test]
    fn plan_appeal_refuses_open_case() {
        let r = row("open", "agent-alice");
        let err = plan_appeal("agent-alice", "case-1", Some(&r), Some("case-1")).unwrap_err();
        assert_eq!(err, AppealRefusal::NotAppealable("open".into()));
        assert_eq!(err.token(), "case_not_appealable:open");
    }

    #[test]
    fn plan_appeal_refuses_a_missing_case() {
        assert_eq!(
            plan_appeal("agent-alice", "case-1", None, Some("case-1")),
            Err(AppealRefusal::CaseMissing)
        );
    }

    #[test]
    fn appeal_tokens_are_the_documented_wire_strings() {
        assert_eq!(AppealRefusal::NoStanding.token(), "appeal_no_standing");
        assert_eq!(
            AppealRefusal::TargetMissing.token(),
            "appeal_target_missing"
        );
        assert_eq!(
            AppealRefusal::TargetMismatch.token(),
            "appeal_target_mismatch"
        );
        assert_eq!(AppealRefusal::CaseMissing.token(), "case_missing");
    }

    fn reopen(conn: &rusqlite::Connection, appellant: &str, decision: &str) -> usize {
        conn.execute(
            APPEAL_REOPEN_SQL,
            rusqlite::params![5_000, "case-1", appellant, decision],
        )
        .unwrap()
    }

    fn state(conn: &rusqlite::Connection) -> String {
        conn.query_row(
            "SELECT state FROM broker_cases WHERE id = 'case-1'",
            [],
            |r| r.get(0),
        )
        .unwrap()
    }

    fn decided() -> rusqlite::Connection {
        let conn = governance_db();
        seed_case(&conn, "case-1", "decided", "agent-alice", None);
        seed_decision(&conn, "dec-1", "case-1", "human-bob");
        conn
    }

    #[test]
    fn appeal_sql_reopens_decided_case_for_requester() {
        let conn = decided();
        assert_eq!(reopen(&conn, "agent-alice", "dec-1"), 1);
        assert_eq!(state(&conn), "reopened");
        // Case-insensitive on the requester, as plan_appeal.
        let conn = decided();
        assert_eq!(reopen(&conn, "AGENT-ALICE", "dec-1"), 1);
    }

    #[test]
    fn appeal_sql_leaves_case_untouched_for_other_appellant() {
        let conn = decided();
        assert_eq!(reopen(&conn, "agent-mallory", "dec-1"), 0);
        assert_eq!(state(&conn), "decided");
    }

    #[test]
    fn appeal_sql_requires_cited_decision_on_same_case() {
        let conn = decided();
        seed_case(&conn, "case-2", "decided", "agent-alice", None);
        seed_decision(&conn, "dec-2", "case-2", "human-bob");
        assert_eq!(
            reopen(&conn, "agent-alice", "dec-2"),
            0,
            "decision of case-2"
        );
        assert_eq!(
            reopen(&conn, "agent-alice", "dec-none"),
            0,
            "no such decision"
        );
        assert_eq!(state(&conn), "decided");
    }

    #[test]
    fn appeal_sql_does_not_reopen_a_non_terminal_case() {
        let conn = governance_db();
        seed_case(&conn, "case-1", "open", "agent-alice", None);
        seed_decision(&conn, "dec-1", "case-1", "human-bob");
        assert_eq!(reopen(&conn, "agent-alice", "dec-1"), 0);
        assert_eq!(state(&conn), "open");
    }

    fn appeal(tags: Vec<Vec<String>>) -> NostrEvent {
        NostrEvent {
            id: "e".repeat(64),
            pubkey: "p".repeat(64),
            created_at: 1,
            kind: governance::KIND_ACTION_REQUEST,
            tags,
            content: String::new(),
            sig: "s".repeat(128),
        }
    }

    fn tag(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| p.to_string()).collect()
    }

    #[test]
    fn appeal_with_d_equal_case_is_refused_at_ingest() {
        let target = "a".repeat(64);
        let marked = tag(&["e", &target, "", "appeal"]);
        // d == case: would replace the requester's own request (NIP-33).
        assert!(appeal_shape_refused(&appeal(vec![
            tag(&["d", "case-1"]),
            tag(&["case", "case-1"]),
            marked.clone()
        ])));
        // No case tag at all.
        assert!(appeal_shape_refused(&appeal(vec![
            tag(&["d", "case-1"]),
            marked.clone()
        ])));
        // A fresh appeal id and a named case is well-shaped.
        assert!(!appeal_shape_refused(&appeal(vec![
            tag(&["d", "appeal-9"]),
            tag(&["case", "case-1"]),
            marked
        ])));
    }
}

#[cfg(test)]
mod write_gate_tests {
    use super::super::calendar_projection::{
        project_tier, Projection, COHORT_BUSINESS, COHORT_FAMILY, COHORT_FRIENDS, ZONE_BUSINESS,
        ZONE_FAMILY,
    };
    use super::*;

    fn cohorts(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// Helper: compute the author's RSVP write decision exactly as `handle_event`
    /// does — resolved target (zone, venue) + author cohorts → tier → permitted.
    fn rsvp_decision(
        author_cohorts: &[String],
        author_cohort_admin: bool,
        target_zone: &str,
        target_venue: Option<&str>,
    ) -> bool {
        let tier = project_tier(
            author_cohorts,
            target_zone,
            target_venue,
            false,
            author_cohort_admin,
        );
        rsvp_write_permitted(&tier)
    }

    // ---- RSVP write gate (kind 31925) --------------------------------------

    #[test]
    fn friends_author_rsvp_to_business_venue_target_rejected() {
        // EVIDENCE replay: a friends-cohort author RSVPs to a business-zone event
        // she only sees as free/busy (business@primary venue). Author tier =
        // FreeBusy ⇒ write rejected.
        assert!(
            !rsvp_decision(
                &cohorts(&[COHORT_FRIENDS]),
                false,
                ZONE_BUSINESS,
                Some("primary"),
            ),
            "friends author must not RSVP to a business target she only sees as free/busy"
        );
        // Off-site business target (no shared venue): friends tier = Omit ⇒ reject.
        assert!(!rsvp_decision(
            &cohorts(&[COHORT_FRIENDS]),
            false,
            ZONE_BUSINESS,
            None
        ));
    }

    #[test]
    fn family_author_rsvp_to_business_target_accepted() {
        // family tier is Full on every zone, including business ⇒ RSVP permitted.
        assert!(rsvp_decision(
            &cohorts(&[COHORT_FAMILY]),
            false,
            ZONE_BUSINESS,
            Some("primary"),
        ));
        assert!(rsvp_decision(
            &cohorts(&[COHORT_FAMILY]),
            false,
            ZONE_BUSINESS,
            None
        ));
    }

    #[test]
    fn owner_admin_author_rsvp_accepted() {
        // Admin author (cohort_admin flag) → project_tier short-circuits to Full,
        // regardless of target zone ⇒ permitted. (A non-cohort author flagged
        // admin in the handler bypasses this gate entirely; this asserts the tier
        // short-circuit for the cohort-admin path.)
        assert!(rsvp_decision(&[], true, ZONE_FAMILY, None));
        assert!(rsvp_decision(&[], true, ZONE_BUSINESS, Some("primary")));
    }

    #[test]
    fn business_author_rsvp_to_own_business_zone_accepted() {
        // A business author RSVPing to a business-zone target sees it Full ⇒ ok.
        assert!(rsvp_decision(
            &cohorts(&[COHORT_BUSINESS]),
            false,
            ZONE_BUSINESS,
            None
        ));
        // ...but a business author RSVPing to a FAMILY target sees Omit ⇒ reject.
        assert!(!rsvp_decision(
            &cohorts(&[COHORT_BUSINESS]),
            false,
            ZONE_FAMILY,
            None
        ));
    }

    #[test]
    fn rsvp_write_permitted_only_on_full_tier() {
        assert!(rsvp_write_permitted(&Projection::Full));
        assert!(!rsvp_write_permitted(&Projection::FreeBusy));
        assert!(!rsvp_write_permitted(&Projection::Omit));
    }

    // ---- Calendar event write gate (kind 31922/31923) ----------------------

    #[test]
    fn calendar_write_into_non_member_zone_rejected() {
        // Zone-tagged event, author lacks write access ⇒ rejected.
        assert!(!calendar_write_permitted(Some(ZONE_BUSINESS), false));
    }

    #[test]
    fn calendar_write_into_member_zone_accepted() {
        // Zone-tagged event, author holds write access ⇒ accepted.
        assert!(calendar_write_permitted(Some(ZONE_BUSINESS), true));
    }

    #[test]
    fn untagged_calendar_event_keeps_prior_behaviour() {
        // No zone tag → unscoped → permitted regardless of zone-write resolution.
        assert!(calendar_write_permitted(None, false));
        assert!(calendar_write_permitted(None, true));
    }

    // ---- Kanban gates (kinds 30301/30302, kanban-scoped 31402) --------------

    #[test]
    fn case_upsert_follows_a_repost_only_within_its_guards() {
        // Behaviour is exercised against SQLite with the relay migrations
        // (re-post after sweep, older re-post, other author, decided case);
        // these pin the guards so none is dropped silently.
        let sql = super::CASE_UPSERT_SQL;
        assert!(sql.contains("ON CONFLICT (id) DO UPDATE SET"));
        assert!(sql.contains("nostr_event_id = excluded.nostr_event_id"));
        assert!(sql.contains("broker_cases.created_by = excluded.created_by"));
        assert!(sql.contains("broker_cases.state IN ('open', 'under_review', 'reopened')"));
        assert!(sql.contains("COALESCE"));
        for frozen in [
            "created_at = excluded",
            "created_by = excluded.created_by,",
            "calibration_sample = excluded",
            "probe_digest = excluded",
        ] {
            assert!(!sql.contains(frozen), "{frozen} must not be updated");
        }
    }

    #[test]
    fn kind_9_and_34550_are_ban_gated() {
        assert!(is_ban_gated_kind(9));
        assert!(is_ban_gated_kind(34550));
        // NIP-29 admin kinds are gated separately, not by the ban predicate.
        assert!(!is_ban_gated_kind(9000));
    }

    #[test]
    fn kind_9_counts_as_a_post() {
        for k in [1, 7, 9, 40, 42, KIND_REPORT_NIP56] {
            assert!(counts_as_post(k), "kind {k} must count");
        }
        assert!(!counts_as_post(41));
        assert!(!counts_as_post(1059));
    }

    #[test]
    fn kanban_kinds_are_ban_and_write_gated() {
        // Kanban boards/cards and agent intents are content-bearing: a banned
        // author must not publish them.
        assert!(is_ban_gated_kind(nostr_bbs_core::KIND_KANBAN_BOARD));
        assert!(is_ban_gated_kind(nostr_bbs_core::KIND_KANBAN_CARD));
        assert!(is_ban_gated_kind(nostr_bbs_core::KIND_AGENT_INTENT));
        // The write path reuses the calendar zone predicate: zone-tagged needs
        // write access, untagged is unscoped.
        assert!(!calendar_write_permitted(Some("family"), false));
        assert!(calendar_write_permitted(Some("family"), true));
        assert!(calendar_write_permitted(None, false));
    }

    #[test]
    fn kanban_approval_request_exempt_from_agent_registry_gate() {
        // A 31402 tagged `k=30302` is the member-initiated kanban approval ask
        // — exempt from the agent-registry gate. Any other 31402 stays gated.
        let kanban_req = mk_event(
            31402,
            vec![
                vec!["d".into(), "x".into()],
                vec!["k".into(), "30302".into()],
            ],
        );
        assert!(nostr_bbs_core::is_kanban_approval_request(&kanban_req));

        let plain_req = mk_event(31402, vec![vec!["d".into(), "x".into()]]);
        assert!(!nostr_bbs_core::is_kanban_approval_request(&plain_req));
        // Wrong k value is not kanban either.
        let wrong_k = mk_event(
            31402,
            vec![vec!["d".into(), "x".into()], vec!["k".into(), "1".into()]],
        );
        assert!(!nostr_bbs_core::is_kanban_approval_request(&wrong_k));
        // A 31403 response never matches (admin-only path unchanged).
        let response = mk_event(31403, vec![vec!["k".into(), "30302".into()]]);
        assert!(!nostr_bbs_core::is_kanban_approval_request(&response));
    }

    // ---- NIP-59 gift-wrap (kind 1059) recipient routing --------------------
    //
    // The handler's recipient gate is `is_whitelisted(recipient)`, which needs a
    // `worker::Env` / D1 and so cannot run in isolation. These tests pin the PURE
    // decision the handler feeds into that lookup: `gift_wrap_recipient` resolves
    // the principal the membership check is applied to. `Some(pk)` ⇒ the gate runs
    // against `pk` (admitted iff whitelisted); `None` ⇒ fail-closed reject; for a
    // normal kind ⇒ `None`, so the author `is_whitelisted` branch runs as before.

    fn mk_event(kind: u64, tags: Vec<Vec<String>>) -> NostrEvent {
        NostrEvent {
            id: "00".repeat(32),
            pubkey: "ab".repeat(32),
            created_at: 0,
            kind,
            tags,
            content: String::new(),
            sig: "cd".repeat(64),
        }
    }

    fn p(hex: &str) -> Vec<String> {
        vec!["p".to_string(), hex.to_string()]
    }

    #[test]
    fn gift_wrap_with_p_tag_routes_membership_to_recipient() {
        // kind-1059 carrying a #p recipient ⇒ gate that recipient (not the
        // ephemeral author). The handler then admits iff that recipient is
        // whitelisted; here we pin the recipient resolution + the boolean gate.
        let recipient = "11".repeat(32);
        let ev = mk_event(GIFT_WRAP_KIND, vec![p(&recipient)]);
        assert_eq!(
            gift_wrap_recipient(&ev).as_deref(),
            Some(recipient.as_str())
        );
        // Whitelisted recipient ⇒ admitted; non-whitelisted ⇒ rejected.
        let admitted = |whitelisted: bool| gift_wrap_recipient(&ev).is_some() && whitelisted;
        assert!(admitted(true));
        assert!(!admitted(false));
    }

    #[test]
    fn gift_wrap_without_or_empty_p_tag_rejected() {
        // No #p tag ⇒ no resolvable recipient ⇒ fail-closed reject.
        let ev_missing = mk_event(GIFT_WRAP_KIND, vec![vec!["e".to_string(), "ff".repeat(32)]]);
        assert_eq!(gift_wrap_recipient(&ev_missing), None);
        // Empty #p value ⇒ treated as absent ⇒ reject.
        let ev_empty = mk_event(GIFT_WRAP_KIND, vec![p("")]);
        assert_eq!(gift_wrap_recipient(&ev_empty), None);
    }

    #[test]
    fn normal_kind_does_not_route_to_recipient_gate() {
        // A normal kind (e.g. kind-1) with a #p tag is NOT recipient-gated; the
        // author `is_whitelisted` branch still applies (gift_wrap_recipient → None).
        let ev = mk_event(1, vec![p(&"22".repeat(32))]);
        assert_eq!(gift_wrap_recipient(&ev), None);
    }
}

// ---------------------------------------------------------------------------
// ADR-099: revocable device-key access resolution tests
// ---------------------------------------------------------------------------
//
// The async `device_owner` / `effective_pubkey` / `is_whitelisted` methods need
// a `worker::Env` / D1 and cannot run in isolation. These tests pin the PURE
// decision the handler feeds those lookups into:
//   - `effective_principal` resolves the principal access derives from (the
//     device→owner mapping, gated). This is the exact function the async
//     `effective_pubkey` calls after resolving `device_owner(pubkey)` from D1.
//   - `access_admitted` replays the write-gate boolean the handler computes:
//     `is_whitelisted(effective_principal(author, owner, enabled))`.
// The D1 `device_owner` query (missing-table → None) and the env gate read are
// exercised by integration tests against a real D1; here we pin the resolution
// and the access boundary those feed.
#[cfg(test)]
mod device_key_tests {
    use super::*;

    #[test]
    fn sanctions_cover_the_device_key_and_its_owner() {
        assert_eq!(sanction_subjects("d", "o"), vec!["d", "o"]);
        assert_eq!(sanction_subjects("d", "d"), vec!["d"]);
    }

    #[test]
    fn creator_recorded_as_the_device_key_still_matches_via_the_raw_key() {
        let subjects = sanction_subjects("device", "owner");
        assert!(creator_matches("device", &subjects));
        assert!(creator_matches("owner", &subjects));
        assert!(!creator_matches("someone-else", &subjects));
    }

    #[test]
    fn gift_wraps_skip_the_owner_lookup() {
        assert!(!needs_owner_lookup(GIFT_WRAP_KIND));
        assert!(needs_owner_lookup(1));
        assert!(needs_owner_lookup(30910));
    }

    const DEVICE: &str = "de";
    const OWNER: &str = "01";
    const OTHER: &str = "99";

    fn dev() -> String {
        DEVICE.repeat(32)
    }
    fn owner() -> String {
        OWNER.repeat(32)
    }

    // ---- pure resolution: effective_principal -----------------------------

    #[test]
    fn device_resolves_to_owner_when_enabled() {
        // Registered, non-revoked device row (device_owner → Some(owner)) and the
        // feature on ⇒ the session acts as the OWNER for access.
        assert_eq!(
            effective_principal(&dev(), Some(&owner()), true),
            owner(),
            "an enabled, registered device key must resolve to its owner"
        );
    }

    #[test]
    fn revoked_or_unknown_device_resolves_to_self() {
        // `device_owner` returns `None` for a revoked row (the query filters
        // `revoked = 0`) AND for an unknown pubkey AND for a missing table
        // (fail-safe). All three reach here as `None` ⇒ identity passthrough.
        assert_eq!(effective_principal(&dev(), None, true), dev());
    }

    #[test]
    fn gate_off_is_identity_passthrough() {
        // DEVICE_KEYS_ENABLED off ⇒ even a known device→owner mapping is ignored;
        // the device key is just an unknown pubkey, current behaviour unchanged.
        assert_eq!(effective_principal(&dev(), Some(&owner()), false), dev());
        // And a non-device pubkey is of course unchanged too.
        assert_eq!(effective_principal(&dev(), None, false), dev());
    }

    // ---- access decision: write-gate allowlist replay ---------------------
    //
    // The handler admits a (non-gift-wrap) event iff
    // `is_whitelisted(effective_pubkey(author))`. We model `is_whitelisted` as a
    // membership set and replay the exact composition.

    /// Replay of the handler's write-gate: admit iff the EFFECTIVE principal is
    /// whitelisted. `whitelisted` models the `is_whitelisted` D1 set.
    fn access_admitted(
        author: &str,
        device_owner: Option<&str>,
        enabled: bool,
        whitelisted: &[String],
    ) -> bool {
        let principal = effective_principal(author, device_owner, enabled);
        whitelisted.contains(&principal)
    }

    #[test]
    fn device_event_admitted_iff_owner_whitelisted() {
        // Owner IS whitelisted, device is NOT ⇒ enabled device event admitted
        // under the owner's allowlist.
        let wl = vec![owner()];
        assert!(
            access_admitted(&dev(), Some(&owner()), true, &wl),
            "device-authored event must be admitted when its owner is whitelisted"
        );
    }

    #[test]
    fn device_event_rejected_when_owner_not_whitelisted() {
        // Owner NOT whitelisted ⇒ rejected even though it is a valid device row.
        let wl = vec![OTHER.repeat(32)];
        assert!(!access_admitted(&dev(), Some(&owner()), true, &wl));
    }

    #[test]
    fn device_event_rejected_when_gate_off_even_if_owner_whitelisted() {
        // Gate off ⇒ the device pubkey itself is checked. Owner whitelisted but
        // device not ⇒ rejected. This is the "fully inert" guarantee: a device
        // key is just an unknown pubkey.
        let wl = vec![owner()];
        assert!(!access_admitted(&dev(), Some(&owner()), false, &wl));
    }

    #[test]
    fn revoked_device_rejected_even_when_enabled() {
        // Revoked ⇒ `device_owner` is None ⇒ the device pubkey is checked, not
        // the owner ⇒ rejected (owner whitelisted but device not).
        let wl = vec![owner()];
        assert!(!access_admitted(&dev(), None, true, &wl));
    }

    #[test]
    fn non_device_author_unchanged() {
        // An ordinary author (no device row) is checked against itself in both
        // gate states — no behaviour change for the common path.
        let author = "ab".repeat(32);
        let wl = vec![author.clone()];
        assert!(access_admitted(&author, None, true, &wl));
        assert!(access_admitted(&author, None, false, &wl));
        // ...and a non-whitelisted ordinary author is rejected, gate on or off.
        let wl_empty: Vec<String> = vec![];
        assert!(!access_admitted(&author, None, true, &wl_empty));
        assert!(!access_admitted(&author, None, false, &wl_empty));
    }
}

#[cfg(test)]
mod augmentation_boundary_tests {
    //! ADR-2011 / EXP-AC-003, EXP-AC-006: the relay's own share of the
    //! augmentation-conditions work — the effective tier it stamps on a case,
    //! the default it folds an unlabelled request to, the delegation admission
    //! gate, and the human-resolution guard on a high/critical case. All of it
    //! sits behind pure seams so it is exercised without a live D1, exactly as
    //! `governance_projection_tests` does for the decision projection.
    use super::*;
    use nostr_bbs_core::governance::{Reversibility, Stakes, Verifiability};

    /// Stands in for the relay operator's `CALIBRATION_SELECTION_KEY`. Sampling
    /// is keyed precisely so a requesting agent cannot predict it from the `d`
    /// tag it chose.
    const KEY: &[u8] = b"relay-selection-secret";

    fn tag(name: &str, value: &str) -> Vec<String> {
        vec![name.to_string(), value.to_string()]
    }

    fn panel_tags(v: &str, r: &str, s: &str) -> Vec<Vec<String>> {
        vec![
            tag("d", "panel-1"),
            tag(governance::TAG_TP_VERIFIABILITY, v),
            tag(governance::TAG_TP_REVERSIBILITY, r),
            tag(governance::TAG_TP_STAKES, s),
        ]
    }

    // ── Effective tier at projection time ───────────────────────────────

    /// EXP-AC-003: an unlabelled 31402 projects with the NIP-11 advertised
    /// default tier, not with the accidental `Medium` of an absent tag.
    #[test]
    fn unlabelled_request_projects_with_the_advertised_default() {
        for default in [RiskTier::Low, RiskTier::Medium, RiskTier::High] {
            let boundary = plan_request_boundary(
                "case-1",
                "agent",
                &[tag("d", "case-1")],
                "{}",
                None,
                default,
                KEY,
            );
            assert_eq!(boundary.effective, default);
            assert_eq!(boundary.declared, None);
            assert_eq!(boundary.props, None);
        }
    }

    /// The counter-example: a request claiming `reversible` against a panel
    /// declaring `irreversible` does not lower the boundary.
    #[test]
    fn request_tag_cannot_loosen_the_panel_declaration() {
        let panel = panel_tags("inspectable", "irreversible", "bounded");
        let request = vec![
            tag("d", "case-1"),
            tag(governance::TAG_TP_REVERSIBILITY, "reversible"),
            tag("risk-tier", "low"),
        ];
        let boundary = plan_request_boundary(
            "case-1",
            "agent",
            &request,
            "{}",
            Some(&panel),
            RiskTier::Medium,
            KEY,
        );
        assert_eq!(
            boundary.props.unwrap().reversibility,
            Reversibility::Irreversible
        );
        assert_eq!(boundary.effective, RiskTier::High);
        assert_eq!(boundary.declared, Some(RiskTier::Low), "still telemetry");
    }

    /// A request may *tighten*: that is the whole point of allowing it to
    /// declare at all.
    #[test]
    fn request_tag_may_tighten_the_panel_declaration() {
        let panel = panel_tags("inspectable", "reversible", "bounded");
        let request = vec![
            tag("d", "case-1"),
            tag(governance::TAG_TP_STAKES, "critical"),
        ];
        let boundary = plan_request_boundary(
            "case-1",
            "agent",
            &request,
            "{}",
            Some(&panel),
            RiskTier::Low,
            KEY,
        );
        assert_eq!(boundary.props.unwrap().stakes, Stakes::Critical);
        assert_eq!(boundary.effective, RiskTier::High);
    }

    /// The declared tier is read from the `risk-tier` tag OR the request
    /// content, so neither publisher has to change to be understood.
    #[test]
    fn declared_tier_reads_from_tag_or_content() {
        let from_tag = plan_request_boundary(
            "c",
            "agent",
            &[tag("risk-tier", "critical")],
            "{}",
            None,
            RiskTier::Low,
            KEY,
        );
        assert_eq!(from_tag.declared, Some(RiskTier::Critical));
        assert_eq!(from_tag.effective, RiskTier::Critical);

        let from_content = plan_request_boundary(
            "c",
            "agent",
            &[],
            r#"{"fields":{},"risk_tier":"high"}"#,
            None,
            RiskTier::Low,
            KEY,
        );
        assert_eq!(from_content.declared, Some(RiskTier::High));
        assert_eq!(from_content.effective, RiskTier::High);
    }

    /// `Opaque` work floors at `Medium` and is never member-suppressed.
    #[test]
    fn opaque_work_floors_at_medium_and_is_shown() {
        let panel = panel_tags("opaque", "reversible", "bounded");
        let boundary = plan_request_boundary(
            "case-1",
            "agent",
            &[tag("risk-tier", "low")],
            "{}",
            Some(&panel),
            RiskTier::Low,
            KEY,
        );
        assert_eq!(boundary.effective, RiskTier::Medium);
        assert!(!governance::is_member_suppressed_effective(
            boundary.props.as_ref(),
            boundary.effective,
            boundary.calibration_sample
        ));
        assert_eq!(boundary.props.unwrap().verifiability, Verifiability::Opaque);
    }

    // ── Calibration sampling and probes ─────────────────────────────────

    /// Sampling only ever applies to a case the member surface would otherwise
    /// hide: marking a case that is already shown would inflate the
    /// `calibration_shown` denominator with cases nobody chose to show.
    #[test]
    fn only_suppressible_cases_are_sampled() {
        let panel = vec![
            tag("d", "p"),
            tag(governance::TAG_CALIBRATION_SAMPLE_RATE, "1.0"),
        ];
        let low = plan_request_boundary(
            "case-low",
            "agent",
            &[tag("risk-tier", "low")],
            "{}",
            Some(&panel),
            RiskTier::Low,
            KEY,
        );
        assert!(low.calibration_sample, "a low case is suppressible");

        let high = plan_request_boundary(
            "case-high",
            "agent",
            &[tag("risk-tier", "high")],
            "{}",
            Some(&panel),
            RiskTier::Low,
            KEY,
        );
        assert!(!high.calibration_sample, "a high case is already shown");
    }

    /// The evasion this closes: the `d` tag IS the case id, and the requesting
    /// agent chooses it. If sampling were an unkeyed hash of that, an agent
    /// could grind `d` tags offline against the panel's published rate until it
    /// found one that is never sampled. Keyed, the same id resolves differently
    /// under different relay keys, so there is nothing to grind towards.
    #[test]
    fn an_agent_cannot_grind_its_case_id_out_of_sampling() {
        let panel = vec![
            tag("d", "p"),
            tag(governance::TAG_CALIBRATION_SAMPLE_RATE, "0.5"),
        ];
        let sampled_under = |key: &[u8], case_id: &str| {
            plan_request_boundary(
                case_id,
                "agent",
                &[tag("risk-tier", "low")],
                "{}",
                Some(&panel),
                RiskTier::Low,
                key,
            )
            .calibration_sample
        };

        // An agent grinds offline and finds an id unsampled under the key it
        // guessed at.
        let evader = (0..10_000)
            .map(|i| format!("agent-chosen-{i}"))
            .find(|id| !sampled_under(b"guessed-key", id))
            .expect("an unsampled id exists at rate 0.5");

        // Against the relay's real key, the grinding bought nothing.
        assert!(
            (0..64u32).any(|n| sampled_under(format!("real-key-{n}").as_bytes(), &evader)),
            "an id ground against one key evaded every key: sampling is predictable"
        );
    }

    /// A calibration sample is shown rather than suppressed — the mechanism
    /// that keeps reviewers exposed to routine agent output (C5/C6).
    #[test]
    fn a_calibration_sample_is_not_suppressed() {
        let panel = vec![
            tag("d", "p"),
            tag(governance::TAG_CALIBRATION_SAMPLE_RATE, "1.0"),
        ];
        let b = plan_request_boundary(
            "case-low",
            "agent",
            &[tag("risk-tier", "low")],
            "{}",
            Some(&panel),
            RiskTier::Low,
            KEY,
        );
        assert_eq!(b.effective, RiskTier::Low);
        assert!(!governance::is_member_suppressed_effective(
            b.props.as_ref(),
            b.effective,
            b.calibration_sample
        ));
    }

    /// EXP-AC-006: a `probe` tag is honoured only from the panel's REGISTERED
    /// probe agent. From anyone else it is noise that would corrupt the catch
    /// rate, so it is dropped rather than recorded.
    #[test]
    fn probe_is_honoured_only_from_the_registered_probe_agent() {
        let prober = "a".repeat(64);
        let panel = vec![tag("d", "p"), tag(governance::TAG_PROBE_AGENT, &prober)];
        let request = vec![tag(governance::TAG_PROBE, "deadbeef")];

        let registered = plan_request_boundary(
            "c",
            &prober,
            &request,
            "{}",
            Some(&panel),
            RiskTier::Medium,
            KEY,
        );
        assert_eq!(registered.probe_digest.as_deref(), Some("deadbeef"));

        let impostor = plan_request_boundary(
            "c",
            &"b".repeat(64),
            &request,
            "{}",
            Some(&panel),
            RiskTier::Medium,
            KEY,
        );
        assert_eq!(impostor.probe_digest, None);

        // And a panel with no registered probe agent honours none at all.
        let unregistered = plan_request_boundary(
            "c",
            &prober,
            &request,
            "{}",
            Some(&[tag("d", "p")]),
            RiskTier::Medium,
            KEY,
        );
        assert_eq!(unregistered.probe_digest, None);
    }

    /// The panel's ageing deadline travels onto the case so the cron is a
    /// single indexed scan, and falls back to the documented default.
    #[test]
    fn max_pending_hours_comes_from_the_panel_or_the_default() {
        let panel = vec![tag("d", "p"), tag(governance::TAG_MAX_PENDING_HOURS, "6")];
        assert_eq!(
            plan_request_boundary("c", "a", &[], "{}", Some(&panel), RiskTier::Medium, KEY,)
                .max_pending_hours,
            6
        );
        assert_eq!(
            plan_request_boundary("c", "a", &[], "{}", None, RiskTier::Medium, KEY,)
                .max_pending_hours,
            governance::DEFAULT_MAX_PENDING_HOURS
        );
    }

    // ── Delegation admission (FR6.2) ────────────────────────────────────

    #[test]
    fn admin_decides_any_case() {
        assert_eq!(
            response_admission(true, false, false),
            ResponseAdmission::Admit
        );
    }

    /// EXP-AC-006 counter-example: a reviewer deciding a case not delegated to
    /// them is refused.
    #[test]
    fn reviewer_without_a_delegation_is_refused() {
        assert_eq!(
            response_admission(false, true, false),
            ResponseAdmission::BlockedNotDelegated
        );
    }

    #[test]
    fn reviewer_with_a_delegation_is_admitted() {
        assert_eq!(
            response_admission(false, true, true),
            ResponseAdmission::Admit
        );
    }

    /// A delegation row for a non-reviewer does not make them a decider: both
    /// halves are required, so a stale row cannot promote an ordinary member.
    #[test]
    fn a_delegation_alone_does_not_admit_a_non_reviewer() {
        assert_eq!(
            response_admission(false, false, true),
            ResponseAdmission::BlockedNotAuthorised
        );
        assert_eq!(
            response_admission(false, false, false),
            ResponseAdmission::BlockedNotAuthorised
        );
    }

    // ── Human resolution of a high/critical case (invariants 4 and 8) ────

    fn case_row_at_tier(tier: &str) -> BrokerCaseRow {
        BrokerCaseRow {
            category: "manual_submission".into(),
            state: "open".into(),
            effective_tier: Some(tier.into()),
            nostr_event_id: Some("r".repeat(64)),
            created_by: "agent-alice".into(),
            from_share_state: None,
            to_share_state: None,
        }
    }

    #[test]
    fn high_and_critical_require_a_human() {
        assert!(human_resolution_required(RiskTier::High));
        assert!(human_resolution_required(RiskTier::Critical));
        assert!(!human_resolution_required(RiskTier::Medium));
        assert!(!human_resolution_required(RiskTier::Low));
    }

    #[test]
    fn resolver_defaults_to_the_human_signer() {
        assert_eq!(
            parse_resolver(r#"{"action":"approve"}"#, "human-bob"),
            Resolver::Human("human-bob".into())
        );
        assert_eq!(
            parse_resolver(
                r#"{"action":"approve","decided_by":"system:whelk-gate"}"#,
                "relay-key"
            ),
            Resolver::System("system:whelk-gate".into())
        );
    }

    /// EXP-AC-003: a case with effective `High`/`Critical` cannot reach
    /// `Decided` through any non-human path.
    #[test]
    fn a_system_actor_cannot_decide_a_high_or_critical_case() {
        for tier in ["high", "critical"] {
            let row = case_row_at_tier(tier);
            let err = plan_action_response(
                "case-1",
                Some(&row),
                &"e".repeat(64),
                r#"{"action":"approve","decided_by":"system:whelk-gate"}"#,
                "relay-key",
                None,
                2_000,
            )
            .expect_err("a system actor must not resolve a high/critical case");
            let message = format!("{err:?}");
            assert!(
                message.contains("requires a human 31403"),
                "unexpected refusal: {message}"
            );
        }
    }

    #[test]
    fn a_human_decides_a_high_case_normally() {
        let row = case_row_at_tier("high");
        let proj = plan_action_response(
            "case-1",
            Some(&row),
            &"e".repeat(64),
            r#"{"action":"approve","reasoning":"checked the diff line by line"}"#,
            "human-bob",
            None,
            2_000,
        )
        .expect("a human resolves a high case");
        assert_eq!(proj.outcome, "approve");
    }

    /// A system actor may still resolve a case the boundary does not reserve —
    /// the guard is about the tier, not about disliking automation.
    #[test]
    fn a_system_actor_may_decide_a_medium_case() {
        let row = case_row_at_tier("medium");
        assert!(plan_action_response(
            "case-1",
            Some(&row),
            &"e".repeat(64),
            r#"{"action":"approve","decided_by":"system:whelk-gate"}"#,
            "relay-key",
            None,
            2_000,
        )
        .is_ok());
    }

    /// A case projected before migration 0006 has no effective tier. It keeps
    /// its prior behaviour rather than being retro-gated on a tier nobody
    /// computed.
    #[test]
    fn a_legacy_case_without_an_effective_tier_is_unaffected() {
        let row = open_legacy_case_row();
        assert!(plan_action_response(
            "case-1",
            Some(&row),
            &"e".repeat(64),
            r#"{"action":"approve","decided_by":"system:whelk-gate"}"#,
            "relay-key",
            None,
            2_000,
        )
        .is_ok());
    }

    fn open_legacy_case_row() -> BrokerCaseRow {
        BrokerCaseRow {
            category: "manual_submission".into(),
            state: "open".into(),
            effective_tier: None,
            nostr_event_id: Some("r".repeat(64)),
            created_by: "agent-alice".into(),
            from_share_state: None,
            to_share_state: None,
        }
    }
}

#[cfg(test)]
mod ontology_governance_boundary_tests {
    //! ADR-2013: the `ontology-governance` profile's share of the boundary —
    //! the `level` tag's tier floor and the proposal expiry the relay copies
    //! onto the case. Pure seams, no live D1, as `augmentation_boundary_tests`.
    use super::*;
    use nostr_bbs_core::governance::broker::CaseState;
    use nostr_bbs_core::governance::Stakes;
    use nostr_bbs_core::ontology_governance::{self as og, ProposalLevel};

    const KEY: &[u8] = b"relay-selection-secret";

    fn tag(name: &str, value: &str) -> Vec<String> {
        vec![name.to_string(), value.to_string()]
    }

    /// The panel an operator actually publishes, rendered to the tags a 31400
    /// carries. Tests run against the real thing so a change to the panel's
    /// declaration is caught here rather than in production.
    fn ontology_panel_tags() -> Vec<Vec<String>> {
        let panel = og::ontology_governance_panel();
        let mut tags = vec![tag("d", og::PANEL_ONTOLOGY_GOVERNANCE)];
        tags.extend(panel.task_properties.unwrap().to_tags());
        tags.extend(panel.policy().to_tags());
        tags
    }

    fn proposal(level: &str, stale_after: &str) -> (Vec<Vec<String>>, String) {
        let tags = vec![
            tag("d", "case-onto-1"),
            tag(og::TAG_CONTEXT_URL, "urn:ngm:class:knowledge-graph"),
            tag(og::TAG_LEVEL, level),
            tag("risk-tier", "low"),
        ];
        let content = format!(
            r#"{{"level":"{level}","iri":"urn:ngm:class:knowledge-graph",
                 "page":"Knowledge Graph","hypothesis":"h","diff":"d",
                 "digest":"sha256:abc","blockers":[],
                 "proposer":"process:vault/1.0","generation":"visionGraph@deadbee",
                 "stale_after":"{stale_after}"}}"#
        );
        (tags, content)
    }

    fn boundary_for(level: &str, stale_after: &str) -> RequestBoundary {
        let (tags, content) = proposal(level, stale_after);
        plan_request_boundary(
            "case-onto-1",
            "agent",
            &tags,
            &content,
            Some(&ontology_panel_tags()),
            RiskTier::Medium,
            KEY,
        )
    }

    // ── The `level` tier floor (PRD §2 Q7) ──────────────────────────────

    /// The headline rule: a schema-level proposal is `High` even though the
    /// proposing agent declared `low` and the panel declares only
    /// `significant` stakes.
    #[test]
    fn a_schema_proposal_is_floored_at_high() {
        let boundary = boundary_for("schema", "2026-10-06T00:00:00Z");
        assert_eq!(boundary.effective, RiskTier::High);
        assert_eq!(boundary.props.unwrap().stakes, Stakes::Critical);
        assert_eq!(
            boundary.declared,
            Some(RiskTier::Low),
            "the agent's own claim survives as telemetry, not as the boundary"
        );
    }

    /// A demotion reaches as far as a schema change, so it is tiered the same.
    #[test]
    fn a_demotion_proposal_is_floored_at_high() {
        assert_eq!(
            boundary_for("demotion", "2026-10-06T00:00:00Z").effective,
            RiskTier::High
        );
    }

    /// The falsification target: if every ontology case were `High`, the rule
    /// above would be testing nothing. A content proposal is not floored.
    #[test]
    fn a_content_proposal_is_not_floored_at_high() {
        let boundary = boundary_for("content", "2026-10-06T00:00:00Z");
        assert_ne!(boundary.effective, RiskTier::High);
        assert_eq!(boundary.props.unwrap().stakes, Stakes::Significant);
    }

    /// A non-ontology 31402 on some other panel is untouched by this profile.
    #[test]
    fn a_request_without_a_level_tag_gains_no_floor_and_no_expiry() {
        let boundary = plan_request_boundary(
            "case-1",
            "agent",
            &[tag("d", "case-1")],
            r#"{"stale_after":"2020-01-01T00:00:00Z"}"#,
            None,
            RiskTier::Medium,
            KEY,
        );
        assert_eq!(boundary.effective, RiskTier::Medium);
        assert_eq!(
            boundary.stale_after, None,
            "a `stale_after` on a request that is not an ontology proposal is \
             not this relay's business to honour"
        );
    }

    // ── Expiry carried onto the case ────────────────────────────────────

    #[test]
    fn the_proposal_expiry_is_copied_onto_the_case() {
        let boundary = boundary_for("content", "2026-10-06T00:00:00Z");
        assert_eq!(boundary.stale_after, Some(1_791_244_800));
        assert!(og::is_expired(1_791_244_800, 1_791_244_801));
        assert!(!og::is_expired(1_791_244_800, 1_791_244_800));
    }

    #[test]
    fn an_unreadable_expiry_leaves_the_case_out_of_the_sweep() {
        let (tags, _) = proposal("content", "");
        let boundary = plan_request_boundary(
            "case-onto-1",
            "agent",
            &tags,
            r#"{"level":"content","stale_after":"whenever"}"#,
            Some(&ontology_panel_tags()),
            RiskTier::Medium,
            KEY,
        );
        assert_eq!(boundary.stale_after, None);
        // …but the case is still tiered and still ages, so it is not lost.
        assert_eq!(boundary.max_pending_hours, og::STALE_AFTER_DEFAULT_HOURS);
    }

    // ── Promote / Demote parsing off the signed 31403 ───────────────────

    /// A schema-level ontology case as the relay projected it: `high`, because
    /// that is what [`a_schema_proposal_is_floored_at_high`] proves it becomes.
    fn schema_case_row() -> BrokerCaseRow {
        BrokerCaseRow {
            category: "knowledge_enrichment".into(),
            state: "open".into(),
            effective_tier: Some(RiskTier::High.as_str().to_string()),
            nostr_event_id: Some("r".repeat(64)),
            created_by: "agent-vault".into(),
            from_share_state: None,
            to_share_state: None,
        }
    }

    #[test]
    fn promote_and_demote_project_with_the_iri_they_signed() {
        let row = schema_case_row();
        let promote = plan_action_response(
            "case-onto-1",
            Some(&row),
            &"a".repeat(64),
            r#"{"action":"promote","iri":"urn:ngm:class:knowledge-graph"}"#,
            "human-bob",
            None,
            2_000,
        )
        .expect("promote projects");
        assert_eq!(promote.outcome, "promote");
        assert_eq!(
            promote.outcome_detail.as_deref(),
            Some("urn:ngm:class:knowledge-graph")
        );
        assert_eq!(promote.new_state, CaseState::Promoted);

        let demote = plan_action_response(
            "case-onto-1",
            Some(&schema_case_row()),
            &"b".repeat(64),
            r#"{"action":"demote","iri":"urn:ngm:class:knowledge-graph"}"#,
            "human-bob",
            None,
            2_000,
        )
        .expect("demote projects");
        assert_eq!(demote.outcome, "demote");
        assert_eq!(
            demote.outcome_detail.as_deref(),
            Some("urn:ngm:class:knowledge-graph")
        );
        // A demotion is a resolved decision; it gets no state of its own.
        assert_eq!(demote.new_state, CaseState::Decided);
    }

    /// A promote or demote settles an ontology case exactly as approve does:
    /// the projected state is terminal, so the cron sweeps and the projection
    /// guard (`state IN ('open', 'under_review', 'reopened')`) leave it alone,
    /// and a second response on it is refused.
    #[test]
    fn promote_and_demote_settle_the_case_like_approve() {
        for (content, persisted) in [
            (r#"{"action":"approve"}"#, "decided"),
            (
                r#"{"action":"promote","iri":"urn:ngm:class:knowledge-graph"}"#,
                "promoted",
            ),
            (
                r#"{"action":"demote","iri":"urn:ngm:class:knowledge-graph"}"#,
                "decided",
            ),
        ] {
            let proj = plan_action_response(
                "case-onto-1",
                Some(&schema_case_row()),
                &"e".repeat(64),
                content,
                "human-bob",
                None,
                2_000,
            )
            .expect("a human decision projects");
            assert!(proj.new_state.is_terminal(), "{content} settles the case");
            assert_eq!(proj.new_state.as_str(), persisted);
            assert!(!matches!(persisted, "open" | "under_review" | "reopened"));

            let mut settled = schema_case_row();
            settled.state = persisted.into();
            assert!(
                matches!(
                    plan_action_response(
                        "case-onto-1",
                        Some(&settled),
                        &"f".repeat(64),
                        r#"{"action":"approve"}"#,
                        "human-bob",
                        Some(proj.decision_id.clone()),
                        2_001,
                    ),
                    Err(governance::broker::OrchestrationError::Case(
                        governance::broker::CaseError::AlreadyTerminal(_)
                    ))
                ),
                "a {persisted} case refuses a second response"
            );
        }
    }

    /// A `promote`/`demote` with no `iri` is refused rather than parked: the
    /// apply path has nothing to act on, and inventing a subject for it is the
    /// one mistake that writes to the wrong page.
    #[test]
    fn a_subjectless_promote_or_demote_is_refused() {
        for content in [r#"{"action":"promote"}"#, r#"{"action":"demote"}"#] {
            assert!(
                nostr_bbs_core::governance::broker::DecisionOutcome::from_response_content(content)
                    .is_none(),
                "{content} must not parse"
            );
        }
    }

    /// The point of flooring a schema proposal at `High`: the corpus write is
    /// then reserved for a person. A reasoner stamping `system:whelk-gate`
    /// cannot promote a page, however well its gate ran.
    #[test]
    fn a_reasoner_may_not_promote_a_schema_level_page() {
        let refused = plan_action_response(
            "case-onto-1",
            Some(&schema_case_row()),
            &"c".repeat(64),
            r#"{"action":"promote","iri":"urn:ngm:class:knowledge-graph",
                "decided_by":"system:whelk-gate"}"#,
            "agent-vault",
            None,
            2_000,
        );
        assert!(
            refused.is_err(),
            "a system resolver must not close a High case"
        );

        // The same body from a human signer, with no `decided_by`, projects.
        assert!(plan_action_response(
            "case-onto-1",
            Some(&schema_case_row()),
            &"d".repeat(64),
            r#"{"action":"promote","iri":"urn:ngm:class:knowledge-graph"}"#,
            "human-bob",
            None,
            2_000,
        )
        .is_ok());
    }

    #[test]
    fn the_level_a_proposal_declares_round_trips() {
        for (s, level) in [
            ("content", ProposalLevel::Content),
            ("schema", ProposalLevel::Schema),
            ("demotion", ProposalLevel::Demotion),
        ] {
            assert_eq!(ProposalLevel::parse(s), level);
            assert_eq!(level.as_str(), s);
        }
    }
}

#[cfg(test)]
mod req_gate_ordering_tests {
    //! The auth-bypass deepsec-gate found in `handle_req`: the subscription was
    //! stored before the read gates ran, and what was stored was the client's
    //! RAW filter while the gated one was a shadowed local used only for the
    //! immediate `query_events`. A refused subscription therefore stayed in
    //! `session.subscriptions`, and `broadcast_event` matched every later event
    //! against the un-gated filter — the historical read was refused and the
    //! live stream was delivered anyway.
    //!
    //! `handle_req` needs a live WebSocket and Durable Object, so the ordering
    //! itself cannot be driven from a unit test. What is pinned here is the
    //! property that makes the ordering matter: the gated filter is not the same
    //! object as the raw one, so storing the wrong one is a real difference and
    //! not a distinction without one.
    use super::*;

    fn dm_filter() -> Vec<NostrFilter> {
        vec![serde_json::from_value(serde_json::json!({ "kinds": [1059] })).expect("valid filter")]
    }

    /// An unauthenticated session cannot subscribe to sealed DMs at all, so
    /// there is nothing legitimate to store.
    #[test]
    fn an_unauthenticated_sealed_dm_subscription_yields_no_filter_to_store() {
        assert!(NostrRelayDO::gate_kind_1059_filters(dm_filter(), &None).is_none());
    }

    /// An authenticated session's stored filter must be the REWRITTEN one: it
    /// carries a `#p` binding the client never sent. Storing the raw filter
    /// would leave the subscription unbound to any recipient, which is exactly
    /// what the live broadcast path then honoured.
    #[test]
    fn the_gated_filter_differs_from_the_raw_one_and_binds_the_recipient() {
        let pk = "a".repeat(64);
        let raw = dm_filter();
        assert!(
            !raw[0].extra.contains_key("#p"),
            "the client sent no recipient binding"
        );

        let gated = NostrRelayDO::gate_kind_1059_filters(raw.clone(), &Some(pk.clone()))
            .expect("an authed session may read its own sealed DMs");
        assert_eq!(
            gated[0].extra.get("#p"),
            Some(&serde_json::json!([pk])),
            "the stored filter must bind to the authed recipient"
        );
        assert_ne!(
            gated[0].extra.get("#p"),
            raw[0].extra.get("#p"),
            "raw and gated must not be interchangeable"
        );
    }
}

#[cfg(test)]
mod rationale_gate_tests {
    //! FR2.2 relay-side: a 31403 on an effective high/critical case must carry
    //! a human rationale of at least 20 Unicode scalars, refused before
    //! `save_event` with the token `rationale_required`.
    //!
    //! The auditor's counter-example (client evidence `53ca2e2`) was that the
    //! relay accepted `reasoning: "x"` and accepted no reasoning at all, which
    //! made FR2.2 a forum-UI convention rather than a protocol rule — and a
    //! 31403 is a signed event any script can publish straight at the relay.
    //!
    //! `handle_event` needs a live WebSocket and D1, so these exercise the two
    //! pure seams the gate is built from: the content parse, and
    //! `governance::check_rationale`. The env-bound half is one `SELECT` of
    //! `broker_cases.effective_tier`.
    use super::*;
    use nostr_bbs_core::governance::{check_rationale, RationaleError};

    fn approve(reasoning: &str) -> String {
        serde_json::json!({ "action": "approve", "reasoning": reasoning }).to_string()
    }

    // ── The content parse ───────────────────────────────────────────────

    #[test]
    fn the_action_and_reasoning_are_read_off_the_signed_content() {
        let (action, reasoning) = response_action_and_reasoning(&approve("checked the diff"));
        assert_eq!(action.as_deref(), Some("approve"));
        assert_eq!(reasoning.as_deref(), Some("checked the diff"));
    }

    #[test]
    fn an_absent_reasoning_field_reads_as_absent() {
        let (action, reasoning) = response_action_and_reasoning(r#"{"action":"approve"}"#);
        assert_eq!(action.as_deref(), Some("approve"));
        assert_eq!(reasoning, None, "absence must not become an empty string");
    }

    /// A body that does not parse is not refused *for want of a rationale* —
    /// it is rejected further down for being malformed. Refusing it here would
    /// tell the publisher something untrue about why.
    #[test]
    fn a_malformed_body_yields_no_action_and_so_no_rationale_refusal() {
        let (action, _) = response_action_and_reasoning("not json at all");
        assert_eq!(action, None);
    }

    // ── The rule, over the parsed content ───────────────────────────────

    /// The auditor's two fixtures, by name: `reasoning: "x"` and no reasoning.
    #[test]
    fn the_auditor_counter_examples_are_now_refused() {
        for content in [approve("x"), r#"{"action":"approve"}"#.to_string()] {
            let (action, reasoning) = response_action_and_reasoning(&content);
            let err = check_rationale(
                RiskTier::Critical,
                action.as_deref().unwrap(),
                reasoning.as_deref(),
            )
            .expect_err("a critical case must not accept this");
            assert_eq!(err.reason(), "rationale_required");
        }
    }

    /// 19 scalars padded with spaces is 19 scalars.
    #[test]
    fn nineteen_characters_with_padding_is_refused() {
        let content = approve("                   abcdefghijklmnopqrs   ");
        let (action, reasoning) = response_action_and_reasoning(&content);
        assert_eq!(
            check_rationale(
                RiskTier::High,
                action.as_deref().unwrap(),
                reasoning.as_deref()
            ),
            Err(RationaleError::TooShort { chars: 19 })
        );
    }

    /// 20 astral scalars (80 bytes) is 20 characters and is accepted — the
    /// test fails if anyone counts bytes.
    #[test]
    fn twenty_astral_characters_are_accepted_through_the_json_round_trip() {
        let rationale = "\u{1D11E}".repeat(20);
        let content = approve(&rationale);
        let (action, reasoning) = response_action_and_reasoning(&content);
        assert_eq!(reasoning.as_ref().unwrap().chars().count(), 20);
        assert_eq!(reasoning.as_ref().unwrap().len(), 80);
        assert_eq!(
            check_rationale(
                RiskTier::High,
                action.as_deref().unwrap(),
                reasoning.as_deref()
            ),
            Ok(())
        );
    }

    /// Low and medium tiers are untouched: the gate is about consequence.
    #[test]
    fn a_low_tier_case_still_accepts_a_bare_decision() {
        let (action, reasoning) = response_action_and_reasoning(r#"{"action":"approve"}"#);
        for tier in [RiskTier::Low, RiskTier::Medium] {
            assert_eq!(
                check_rationale(tier, action.as_deref().unwrap(), reasoning.as_deref()),
                Ok(())
            );
        }
    }

    #[test]
    fn delegate_on_a_critical_case_without_a_rationale_is_refused() {
        let content =
            serde_json::json!({ "action": "delegate", "delegate_to": "human-carol" }).to_string();
        let (action, reasoning) = response_action_and_reasoning(&content);
        assert_eq!(action.as_deref(), Some("delegate"));
        assert_eq!(
            check_rationale(
                RiskTier::Critical,
                action.as_deref().unwrap(),
                reasoning.as_deref()
            ),
            Err(RationaleError::Missing)
        );
    }

    /// A case projected before migration 0006 has no effective tier, so the
    /// gate does not run at all — legacy behaviour, unchanged.
    #[test]
    fn a_legacy_untiered_case_is_not_gated() {
        // `case_effective_tier` returns None for such a case, and the gate is
        // inside `if let Some(effective)`. The parse still works, and nothing
        // downstream refuses it.
        let (action, reasoning) = response_action_and_reasoning(r#"{"action":"approve"}"#);
        assert_eq!(action.as_deref(), Some("approve"));
        assert_eq!(reasoning, None);
    }
}

#[cfg(test)]
mod sealed_original_tests {
    //! ADR-2017: the drift exemption and the write rule for sealed originals.
    //! The handler feeds these pure decisions from `validate_event` and from
    //! the kind-42 channel/zone gate; the D1 lookups behind `is_admin` and the
    //! channel's zone are exercised elsewhere.
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const OLD: u64 = NOW - 400 * 24 * 60 * 60;

    fn event(kind: u64, created_at: u64, tags: Vec<Vec<String>>) -> NostrEvent {
        NostrEvent {
            id: "1".repeat(64),
            pubkey: "2".repeat(64),
            created_at,
            kind,
            tags,
            content: String::new(),
            sig: "3".repeat(128),
        }
    }

    fn tag(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn envelope_tags(sealed: Vec<String>) -> Vec<Vec<String>> {
        let chan = "c".repeat(64);
        vec![
            tag(&["e", &chan, "", "root"]),
            tag(&["zk", "zone3", "1", &"d".repeat(64)]),
            sealed,
        ]
    }

    fn well_formed() -> Vec<String> {
        tag(&["sealed", &"a".repeat(64), "1"])
    }

    #[test]
    fn reject_strings_match_adr_2017_verbatim() {
        assert_eq!(
            SEALED_ADMIN_ONLY,
            "blocked: sealed originals are admin-only"
        );
        assert_eq!(
            SEALED_ENCRYPTED_ZONES_ONLY,
            "blocked: sealed originals belong to encrypted zones"
        );
    }

    #[test]
    fn well_formed_sealed_kind_42_is_drift_exempt() {
        let ev = event(42, OLD, envelope_tags(well_formed()));
        assert!(sealed_drift_exempt(&ev));
        assert!(timestamp_drift_ok(&ev, NOW));
    }

    #[test]
    fn exemption_is_kind_42_only() {
        for kind in [1, 7, 40, 41, 1059] {
            let ev = event(kind, OLD, envelope_tags(well_formed()));
            assert!(!sealed_drift_exempt(&ev), "kind {kind}");
            assert!(!timestamp_drift_ok(&ev, NOW), "kind {kind}");
        }
    }

    #[test]
    fn malformed_marker_buys_no_exemption() {
        for bad in [
            tag(&["sealed"]),
            tag(&["sealed", &"a".repeat(64)]),
            tag(&["sealed", "not-hex", "1"]),
            tag(&["sealed", &"a".repeat(63), "1"]),
            tag(&["sealed", &"a".repeat(64), "v1"]),
        ] {
            let ev = event(42, OLD, envelope_tags(bad.clone()));
            assert!(!sealed_drift_exempt(&ev), "{bad:?}");
            assert!(!timestamp_drift_ok(&ev, NOW), "{bad:?}");
            // ...but the write gate still sees it and refuses a non-admin.
            assert!(nostr_bbs_core::sealed::has_sealed_tag(&ev.tags));
            assert_eq!(
                sealed_write_rejection(true, false, Some(true)),
                Some(SEALED_ADMIN_ONLY)
            );
        }
    }

    #[test]
    fn plain_kind_42_keeps_the_drift_check() {
        let chan = "c".repeat(64);
        let tags = vec![tag(&["e", &chan, "", "root"])];
        assert!(!timestamp_drift_ok(&event(42, OLD, tags.clone()), NOW));
        assert!(timestamp_drift_ok(&event(42, NOW - 60, tags.clone()), NOW));
        assert!(timestamp_drift_ok(
            &event(42, NOW - MAX_TIMESTAMP_DRIFT, tags.clone()),
            NOW
        ));
        assert!(!timestamp_drift_ok(
            &event(42, NOW - MAX_TIMESTAMP_DRIFT - 1, tags),
            NOW
        ));
    }

    #[test]
    fn sealed_envelope_is_not_exempt_into_the_future() {
        let tags = envelope_tags(well_formed());
        assert!(timestamp_drift_ok(
            &event(42, NOW + MAX_TIMESTAMP_DRIFT, tags.clone()),
            NOW
        ));
        assert!(!timestamp_drift_ok(
            &event(42, NOW + MAX_TIMESTAMP_DRIFT + 1, tags),
            NOW
        ));
    }

    #[test]
    fn unsealed_events_fall_through_to_the_zone_gate() {
        for is_admin in [false, true] {
            for zone in [None, Some(false), Some(true)] {
                assert_eq!(sealed_write_rejection(false, is_admin, zone), None);
            }
        }
    }

    #[test]
    fn sealed_from_non_admin_is_refused_everywhere() {
        for zone in [None, Some(false), Some(true)] {
            assert_eq!(
                sealed_write_rejection(true, false, zone),
                Some(SEALED_ADMIN_ONLY)
            );
        }
    }

    #[test]
    fn sealed_from_admin_needs_an_encrypted_zone() {
        // Unscoped channel: members may post there, so the envelope must be
        // refused even though the author is an admin.
        assert_eq!(
            sealed_write_rejection(true, true, None),
            Some(SEALED_ENCRYPTED_ZONES_ONLY)
        );
        assert_eq!(
            sealed_write_rejection(true, true, Some(false)),
            Some(SEALED_ENCRYPTED_ZONES_ONLY)
        );
        assert_eq!(sealed_write_rejection(true, true, Some(true)), None);
    }

    #[test]
    fn real_envelope_passes_the_ciphertext_rule() {
        use nostr_bbs_core::keys::SecretKey;
        use nostr_bbs_core::sealed::seal_original;
        use nostr_bbs_core::{sign_event, UnsignedEvent};

        let author = SecretKey::from_bytes([0x11; 32]).unwrap();
        let migrator = SecretKey::from_bytes([0x22; 32]).unwrap();
        let zone = SecretKey::from_bytes([0x33; 32]).unwrap();
        let chan = "c".repeat(64);
        let signing_key = nostr_bbs_core::keys::signing_key_from_bytes(author.as_bytes()).unwrap();
        let original = sign_event(
            UnsignedEvent {
                pubkey: author.public_key().to_hex(),
                created_at: OLD,
                kind: 42,
                tags: vec![tag(&["e", &chan, "", "root"])],
                content: "from before encryption".into(),
            },
            &signing_key,
        )
        .unwrap();
        let env = seal_original(
            &original,
            "zone3",
            1,
            &zone.public_key().to_hex(),
            &migrator,
        )
        .unwrap();

        assert!(timestamp_drift_ok(&env, NOW));
        assert_eq!(sealed_write_rejection(true, true, Some(true)), None);
        assert!(crate::zone_config::is_zone_ciphertext(
            "zone3",
            &env.tags,
            &env.content
        ));
        // The gate keys on the channel `e` tag, which is the envelope's first.
        assert_eq!(filter::tag_value(&env, "e").as_deref(), Some(chan.as_str()));
    }
}

#[cfg(test)]
mod zone_read_rule_tests {
    //! ADR-2018: the D1-free zone read rule must match `trust::has_zone_access`
    //! (public read, or whitelist admin, or a required cohort; unknown denies).
    use super::{zone_read_permitted, ViewerContext};
    use crate::zone_config::ZoneConfig;

    fn zones() -> ZoneConfig {
        ZoneConfig::from_json(
            r#"[{"id":"public","required_cohorts":[],"visibility":"public"},
                {"id":"zone2","required_cohorts":["friends"],"visibility":"locked"}]"#,
        )
    }

    fn ctx(cohorts: &[&str], admin: bool) -> ViewerContext {
        ViewerContext {
            session_pubkey: Some("s".into()),
            access_pubkey: Some("s".into()),
            is_admin: false,
            viewer_cohorts: cohorts.iter().map(|c| c.to_string()).collect(),
            viewer_is_admin: admin,
            recipient_keys: vec![],
        }
    }

    #[test]
    fn public_zone_is_readable_by_anyone_including_unauthenticated() {
        let anon = ViewerContext {
            session_pubkey: None,
            access_pubkey: None,
            is_admin: false,
            viewer_cohorts: vec![],
            viewer_is_admin: false,
            recipient_keys: vec![],
        };
        assert!(zone_read_permitted(&zones(), "public", &anon));
        assert!(zone_read_permitted(&zones(), "public", &ctx(&[], false)));
    }

    #[test]
    fn locked_zone_needs_a_required_cohort_or_the_whitelist_admin_flag() {
        assert!(!zone_read_permitted(&zones(), "zone2", &ctx(&[], false)));
        assert!(!zone_read_permitted(
            &zones(),
            "zone2",
            &ctx(&["family"], false)
        ));
        assert!(zone_read_permitted(
            &zones(),
            "zone2",
            &ctx(&["friends"], false)
        ));
        assert!(zone_read_permitted(&zones(), "zone2", &ctx(&[], true)));
    }

    #[test]
    fn unknown_zone_denies_even_with_cohorts() {
        assert!(!zone_read_permitted(
            &zones(),
            "zone9",
            &ctx(&["friends"], false)
        ));
        assert!(
            zone_read_permitted(&zones(), "zone9", &ctx(&[], true)),
            "admins bypass"
        );
    }
}

#[cfg(test)]
mod recipient_key_read_tests {
    //! Phase 2: reads and deletion with registered inbox keys. The chain below
    //! composes the same predicates the REQ/COUNT/broadcast paths run, in order:
    //! the `#p` rewrite, `gift_wrap_readable_by_any`, then the protected-kind gate.
    use super::*;
    use crate::recipient_keys::{read_set, wrap_addressed_to};

    const OWNER: &str = "aa";
    const INBOX: &str = "bb";
    const OTHER: &str = "cc";

    fn wrap_to(recipient: &str) -> NostrEvent {
        serde_json::from_value(serde_json::json!({
            "id": "0".repeat(64), "pubkey": "e".repeat(64), "created_at": 1, "kind": 1059,
            "tags": [["p", recipient]], "content": "x", "sig": "0".repeat(128)
        }))
        .expect("valid event")
    }

    fn req(v: serde_json::Value) -> Vec<NostrFilter> {
        vec![serde_json::from_value(v).expect("filter")]
    }

    /// Would `session` (with inbox keys `keys`) be shown `event` by a REQ asking `filter`?
    fn delivered(
        session: &str,
        keys: &[&str],
        filter: serde_json::Value,
        event: &NostrEvent,
    ) -> bool {
        let extra: Vec<String> = keys.iter().map(|k| k.to_string()).collect();
        let set = read_set(session, &extra);
        let f = NostrRelayDO::gate_kind_1059_filters_with(
            req(filter),
            &Some(session.to_string()),
            Some(&set),
        )
        .expect("authed");
        // The stored filter is the client's own; an absent `#p` constrains nothing.
        let sql_matches = match f[0].extra.get("#p").and_then(|v| v.as_array()) {
            None => true,
            Some(p) => event
                .tags
                .iter()
                .any(|t| t[0] == "p" && p.iter().any(|v| v.as_str() == Some(t[1].as_str()))),
        };
        let recipients: Vec<String> = event.tags.iter().map(|t| t[1].clone()).collect();
        sql_matches
            && gift_wrap_readable_by_any(event, &set)
            && nip42::protected_read_permitted_with_keys(
                event.kind,
                &event.pubkey,
                &recipients,
                Some(session),
                &extra,
                AuthMode::Nip42,
            )
    }

    #[test]
    fn req_with_p_inbox_key_returns_to_the_owner_only() {
        let ev = wrap_to(INBOX);
        let f = serde_json::json!({ "kinds": [1059], "#p": [INBOX] });
        assert!(delivered(OWNER, &[INBOX], f.clone(), &ev));
        assert!(
            !delivered(OTHER, &[], f, &ev),
            "another session sees nothing"
        );
    }

    #[test]
    fn req_without_p_defaults_to_the_whole_set() {
        let f = serde_json::json!({ "kinds": [1059] });
        assert!(delivered(OWNER, &[INBOX], f.clone(), &wrap_to(INBOX)));
        assert!(delivered(OWNER, &[INBOX], f, &wrap_to(OWNER)));
    }

    #[test]
    fn count_gate_is_the_same_chain() {
        // COUNT shares gate_kind_1059_filters_with and the per-event predicates.
        let f = serde_json::json!({ "kinds": [1059], "#p": [INBOX, OTHER] });
        assert!(delivered(OWNER, &[INBOX], f.clone(), &wrap_to(INBOX)));
        assert!(!delivered(OWNER, &[INBOX], f, &wrap_to(OTHER)));
    }

    #[test]
    fn no_p_is_bound_to_set_a_and_a_sent_p_is_kept() {
        let set = read_set(OWNER, &[INBOX.into()]);
        let out = NostrRelayDO::gate_kind_1059_filters_with(
            req(serde_json::json!({ "kinds": [1059] })),
            &Some(OWNER.into()),
            Some(&set),
        )
        .unwrap();
        assert_eq!(out[0].extra.get("#p"), Some(&serde_json::json!(set)));
        let out = NostrRelayDO::gate_kind_1059_filters_with(
            req(serde_json::json!({ "kinds": [1059], "#p": [INBOX] })),
            &Some(OWNER.into()),
            Some(&set),
        )
        .unwrap();
        assert_eq!(out[0].extra.get("#p"), Some(&serde_json::json!([INBOX])));
    }

    #[test]
    fn foreign_p_is_stored_as_sent_and_the_event_check_withholds() {
        let out = NostrRelayDO::gate_kind_1059_filters_with(
            req(serde_json::json!({ "kinds": [1059], "#p": [OTHER] })),
            &Some(OWNER.into()),
            Some(&read_set(OWNER, &[INBOX.into()])),
        )
        .unwrap();
        assert_eq!(out[0].extra.get("#p"), Some(&serde_json::json!([OTHER])));
        assert!(!delivered(
            OWNER,
            &[INBOX],
            serde_json::json!({ "kinds": [1059], "#p": [OTHER] }),
            &wrap_to(OTHER)
        ));
    }

    #[test]
    fn inbox_req_after_an_empty_cached_key_list_is_stored_intact_and_delivers_once_refreshed() {
        // Identity REQ ran first and saw no keys; registration lands afterwards.
        let f = serde_json::json!({ "kinds": [1059], "#p": [INBOX] });
        let stored = NostrRelayDO::gate_kind_1059_filters_with(
            req(f.clone()),
            &Some(OWNER.into()),
            Some(&read_set(OWNER, &[])),
        )
        .unwrap();
        assert_eq!(stored[0].extra.get("#p"), Some(&serde_json::json!([INBOX])));
        let ev = wrap_to(INBOX);
        assert!(!delivered(OWNER, &[], f.clone(), &ev), "list still empty");
        assert!(delivered(OWNER, &[INBOX], f, &ev), "list refreshed");
    }

    #[test]
    fn a_second_p_does_not_make_a_wrap_readable_by_its_holder() {
        let mut ev = wrap_to(OTHER);
        ev.tags.push(vec!["p".into(), INBOX.into()]);
        assert!(!gift_wrap_readable_by_any(
            &ev,
            &read_set(OWNER, &[INBOX.into()])
        ));
    }

    #[test]
    fn feature_off_keeps_the_overwrite_and_the_single_key_rule() {
        let out = NostrRelayDO::gate_kind_1059_filters(
            req(serde_json::json!({ "kinds": [1059], "#p": [OTHER] })),
            &Some(OWNER.into()),
        )
        .unwrap();
        assert_eq!(out[0].extra.get("#p"), Some(&serde_json::json!([OWNER])));
        assert!(!nip42::protected_read_permitted(
            1059,
            &"e".repeat(64),
            &[INBOX.to_string()],
            Some(OWNER),
            AuthMode::Nip42
        ));
    }

    #[test]
    fn inbox_keys_open_only_kind_1059_in_the_protected_gate() {
        let keys = [INBOX.to_string()];
        assert!(!nip42::protected_read_permitted_with_keys(
            14,
            "e",
            &[INBOX.to_string()],
            Some(OWNER),
            &keys,
            AuthMode::Nip42
        ));
    }

    // ── deletion lane ──────────────────────────────────────────────────────

    #[test]
    fn member_deletes_a_wrap_to_their_inbox_key_but_not_to_another_member() {
        use rusqlite::{params, Connection};
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(crate::EVENTS_CREATE_SQL).unwrap();
        for (id, p) in [("w1", INBOX), ("w2", OTHER)] {
            c.execute(
                "INSERT INTO events (id,pubkey,created_at,kind,tags,content,sig) VALUES (?1,'eph',1,1059,?2,'x','s')",
                params![id, serde_json::json!([["p", p]]).to_string()],
            )
            .unwrap();
        }
        let set = read_set(OWNER, &[INBOX.into()]);
        let mut deleted = vec![];
        for id in ["w1", "w2"] {
            let (kind, tags): (i64, String) = c
                .query_row(
                    "SELECT kind, tags FROM events WHERE id = ?1",
                    params![id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            // deletion_targets_others: not "others" iff addressed to the signer's set.
            if wrap_addressed_to(kind as u64, &tags, &set) {
                c.execute(
                    "DELETE FROM events WHERE id = ?1 AND kind = 1059",
                    params![id],
                )
                .unwrap();
                deleted.push(id);
            }
        }
        assert_eq!(deleted, vec!["w1"]);
        let left: i64 = c
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 1, "the wrap to another member survives");
    }
}
