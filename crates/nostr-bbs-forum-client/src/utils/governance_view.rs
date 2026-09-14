//! Pure view logic for the Agent Control Surface decision card (PRD
//! *Augmentation Conditions* FR2, FR4, FR6; ADR-2011).
//!
//! Everything in this module is a total function over plain data. Nothing here
//! touches `web_sys`, `js_sys` or a Leptos signal, so the rules that decide
//! **what a reviewer is shown and when they are allowed to act** are unit-tested
//! on the host target rather than asserted by eye in a WASM bundle. The Leptos
//! components in [`crate::pages::governance`] are a rendering shell over these
//! functions: they choose no ordering, no gate and no label of their own.
//!
//! The rules, and the invariants they discharge (DDD §6):
//!
//! - **Invariant 1 — no fabricated judgement.** [`decision_content`] writes the
//!   reviewer's typed text and nothing else. There is no template anywhere in
//!   this crate; an empty rationale publishes an empty `reasoning`.
//! - **Invariant 3 — effective tier is authoritative.** [`compute_boundary`]
//!   mirrors the relay's `plan_request_boundary` exactly (same `nostr-bbs-core`
//!   functions, same inputs), so suppression and gating read the effective tier
//!   and never the agent's `risk_tier`.
//! - **Invariant 6 — delegation is scoped.** [`is_decidable_by`] admits a
//!   non-admin only for the one case an admin delegated to them.
//! - **Invariant 7 — probes are blind until decided.** [`visible_probe`] is the
//!   only path by which a probe digest may reach the DOM, and it yields `None`
//!   for every undecided case.

use nostr_bbs_core::governance::{
    self, broker::DecisionOutcome, PanelPolicy, RiskTier, TaskProperties,
};

// ── Rationale gate (FR2.2, EXP-AC-002) ──────────────────────────────────────

/// Minimum trimmed rationale length before a `high`/`critical` case may be
/// decided (PRD FR2.2).
pub const MIN_RATIONALE_LEN: usize = 20;

/// Whether the effective tier makes a typed rationale mandatory.
///
/// `high` and `critical` only. A `low`/`medium` case still *collects* a
/// rationale — it simply does not withhold the controls for one.
pub fn rationale_required(effective: RiskTier) -> bool {
    matches!(effective, RiskTier::High | RiskTier::Critical)
}

/// Whether the reviewer's controls (Approve / Reject / Amend / Delegate) are
/// enabled for this tier and this rationale text.
///
/// The length test is on the **trimmed** text so a reviewer cannot satisfy a
/// `critical` gate with twenty spaces; what gets published is the untrimmed
/// text ([`decision_content`]), because the reviewer's bytes are the record.
pub fn rationale_satisfied(effective: RiskTier, typed: &str) -> bool {
    !rationale_required(effective) || typed.trim().chars().count() >= MIN_RATIONALE_LEN
}

/// Characters still needed before a mandatory rationale satisfies the gate.
/// `0` when the gate is already satisfied or does not apply.
pub fn rationale_remaining(effective: RiskTier, typed: &str) -> usize {
    if !rationale_required(effective) {
        return 0;
    }
    MIN_RATIONALE_LEN.saturating_sub(typed.trim().chars().count())
}

/// The signed 31403 content for a decision.
///
/// The outcome is serialised by `nostr-bbs-core` (internally tagged on
/// `action`), then the reviewer's text is attached **verbatim and untrimmed**
/// as `reasoning`. DDD §6 invariant 1: this function has no fallback, no
/// template and no default — if the reviewer typed nothing, `reasoning` is the
/// empty string, which is the honest record of "they gave no reason".
pub fn decision_content(outcome: &DecisionOutcome, typed_rationale: &str) -> String {
    let mut value = serde_json::to_value(outcome).unwrap_or_else(|_| {
        serde_json::json!({ "action": outcome.action_str() })
    });
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "reasoning".to_string(),
            serde_json::Value::String(typed_rationale.to_string()),
        );
    }
    value.to_string()
}

// ── Panel resolution + boundary (FR3.2, invariant 3) ────────────────────────

/// How a 31402 names the 31400 whose operator declaration governs it.
///
/// Mirrors the relay's `resolve_panel_tags` resolution order exactly, so the
/// client and the relay agree on which panel bounds a request: the NIP-33 `a`
/// tag, then a plain `panel` tag naming the `d`, then the most recent panel the
/// same agent published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PanelRef {
    /// `a` = `31400:<pubkey>:<d>`.
    Addressed { pubkey: String, d_tag: String },
    /// `panel` = `<d>`, on the requesting agent's own panels.
    Named { pubkey: String, d_tag: String },
    /// Neither tag: the newest panel published by the requesting agent.
    LatestFromAgent { pubkey: String },
}

/// Resolve the panel a request belongs to from its tags.
pub fn resolve_panel_ref(request_tags: &[Vec<String>], request_pubkey: &str) -> PanelRef {
    if let Some(a) = governance::extract_tag(request_tags, "a") {
        let mut parts = a.splitn(3, ':');
        if let (Some(kind), Some(pubkey), Some(d)) = (parts.next(), parts.next(), parts.next()) {
            if kind.parse::<u64>().ok() == Some(governance::KIND_PANEL_DEFINITION) {
                return PanelRef::Addressed {
                    pubkey: pubkey.to_string(),
                    d_tag: d.to_string(),
                };
            }
        }
    }
    if let Some(d) = governance::extract_tag(request_tags, "panel") {
        return PanelRef::Named {
            pubkey: request_pubkey.to_string(),
            d_tag: d.to_string(),
        };
    }
    PanelRef::LatestFromAgent {
        pubkey: request_pubkey.to_string(),
    }
}

/// The operator declaration a panel contributes to a request's boundary.
///
/// A panel publisher may carry the triple and the policy either on the 31400's
/// **tags** (what agentbox stamps and what the relay reads) or inside the
/// `PanelDefinition` **content** (what this client's own types carry). Reading
/// both means neither publisher has to change to be understood; tags win where
/// both are present, matching the relay.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PanelContext {
    pub task_properties: Option<TaskProperties>,
    pub policy: PanelPolicy,
}

impl PanelContext {
    /// Build the context from a 31400's tags and its parsed definition.
    pub fn from_panel(
        tags: &[Vec<String>],
        definition: Option<&governance::PanelDefinition>,
    ) -> Self {
        let from_tags = TaskProperties::from_tags(tags);
        let from_content = definition.and_then(|d| d.task_properties);
        // Tag declaration wins; where only the content declares, use it. Where
        // both do, they are merged tightening-only rather than one silently
        // overriding the other — two declarations by the same operator can only
        // raise the boundary between them.
        let task_properties = match (from_tags, from_content) {
            (Some(t), Some(c)) => Some(TaskProperties::merge(t, c)),
            (Some(t), None) => Some(t),
            (None, Some(c)) => Some(c),
            (None, None) => None,
        };
        // A tag-declared policy wins for the same reason; otherwise the
        // definition's own optional fields, each falling back independently.
        let tag_policy = PanelPolicy::from_tags(tags);
        let policy = if tags_declare_policy(tags) {
            tag_policy
        } else {
            definition.map(|d| d.policy()).unwrap_or_default()
        };
        Self {
            task_properties,
            policy,
        }
    }
}

fn tags_declare_policy(tags: &[Vec<String>]) -> bool {
    [
        governance::TAG_CALIBRATION_SAMPLE_RATE,
        governance::TAG_MAX_PENDING_HOURS,
        governance::TAG_PROBE_AGENT,
    ]
    .iter()
    .any(|t| governance::extract_tag(tags, t).is_some())
}

/// The whole boundary for one 31402, as the client sees it.
///
/// Field-for-field the relay's `RequestBoundary`. The client computes it rather
/// than reading it back because the member surface has no authenticated read
/// API — and because `nostr-bbs-core::effective_tier` is pure, both sides
/// necessarily agree on the same inputs.
#[derive(Debug, Clone, PartialEq)]
pub struct CaseBoundary {
    /// The agent's own declaration. Telemetry only — never used for gating.
    pub declared: Option<RiskTier>,
    /// The tier that governs the case. The only tier rendered or gated on.
    pub effective: RiskTier,
    /// The merged operator/agent triple, where anything was declared.
    pub props: Option<TaskProperties>,
    /// Deterministically selected to be shown despite being suppressible.
    pub calibration_sample: bool,
    /// The seeded-probe digest, honoured only from the panel's probe agent.
    /// Holding it is not rendering it — see [`visible_probe`].
    pub probe_digest: Option<String>,
    /// Hours past which the case is escalated on age.
    pub max_pending_hours: u32,
}

/// Compute a request's boundary (ADR-2011 §2).
///
/// `case_id` is the request's `d`-tag, which is what the relay keys the case on
/// and therefore what calibration sampling must hash — sampling the event id
/// instead would disagree with the relay on every case.
pub fn compute_boundary(
    case_id: &str,
    request_pubkey: &str,
    request_tags: &[Vec<String>],
    request: &governance::ActionRequest,
    panel: Option<&PanelContext>,
    advertised_default: RiskTier,
) -> CaseBoundary {
    let panel_props = panel.and_then(|p| p.task_properties);
    // The triple may ride tags (agentbox) or the request body (this client).
    let request_props = TaskProperties::from_tags(request_tags).or(request.task_properties);
    let merged = TaskProperties::merge_opt(panel_props.as_ref(), request_props.as_ref());
    let declared = governance::extract_tag(request_tags, "risk-tier")
        .map(RiskTier::parse)
        .or(request.risk_tier);
    let effective = governance::effective_tier(
        panel_props.as_ref(),
        request_props.as_ref(),
        declared,
        advertised_default,
    );

    let policy = panel.map(|p| p.policy.clone()).unwrap_or_default();

    // Only a case the member surface would otherwise hide is worth sampling;
    // sampling an already-visible case would inflate the shown denominator.
    let suppressible = governance::is_member_suppressed_effective(merged.as_ref(), effective, false);
    let calibration_sample =
        suppressible && governance::is_calibration_sample(case_id, policy.calibration_sample_rate);

    // A `probe` tag is honoured ONLY from the panel's registered probe agent
    // (FR6.4); from anyone else it is noise that would corrupt the catch rate.
    let probe_digest = governance::extract_tag(request_tags, governance::TAG_PROBE)
        .map(str::to_string)
        .or_else(|| request.probe.clone())
        .filter(|_| policy.is_probe_agent(request_pubkey));

    CaseBoundary {
        declared,
        effective,
        props: merged,
        calibration_sample,
        probe_digest,
        max_pending_hours: policy.max_pending_hours,
    }
}

impl CaseBoundary {
    /// Whether the member surface shows this case (FR3.2, FR6.3).
    ///
    /// Reads the **effective** tier, never `declared`. A calibration sample is
    /// shown by construction: it exists precisely to be seen.
    pub fn is_member_visible(&self) -> bool {
        !governance::is_member_suppressed_effective(
            self.props.as_ref(),
            self.effective,
            self.calibration_sample,
        )
    }
}

// ── Probe blindness (FR6.4, invariant 7) ────────────────────────────────────

/// The probe digest as it may be rendered for a case.
///
/// DDD §6 invariant 7: a reviewer who can see that a request is a seeded probe
/// is not being tested, they are being told the answer. The digest is withheld
/// from every undecided case and revealed once a 31403 exists, at which point
/// it is audit evidence rather than a hint.
///
/// The raw signed 31402 still carries the tag — stripping it would invalidate
/// the signature this client verifies strictly — so blindness is this client's
/// job, and this function is the only place the client may take it.
pub fn visible_probe<'a>(decided: bool, probe_digest: Option<&'a str>) -> Option<&'a str> {
    probe_digest.filter(|_| decided)
}

// ── Ageing (FR4.3) ──────────────────────────────────────────────────────────

/// A coarse relative age label for a pending case, from the case's `created_at`
/// (or the relay's `accepted_at` where a caller has one) and the current time.
///
/// Pure over both timestamps so the label is testable; the caller supplies
/// `now`. A `created_at` in the future (clock skew between the publishing agent
/// and this browser) reads as "just now" rather than a negative age.
pub fn relative_age_label(created_at: u64, now: u64) -> String {
    if created_at == 0 {
        return "age unknown".to_string();
    }
    let secs = now.saturating_sub(created_at);
    if secs < 60 {
        return "just now".to_string();
    }
    if secs < 3600 {
        return format!("{}m old", secs / 60);
    }
    if secs < 86_400 {
        return format!("{}h old", secs / 3600);
    }
    format!("{}d old", secs / 86_400)
}

/// Whether a still-pending case has passed the panel's `max_pending_hours`.
///
/// This is the client's own reading of the clock, shown so a member without an
/// authenticated receipts read still sees a stalled case as stalled. It is
/// advisory: the authoritative statement is the relay's `escalated-on-age`
/// receipt ([`crate::stores::receipts`]), which is what the badge cites when it
/// is available.
pub fn is_overdue(created_at: u64, now: u64, max_pending_hours: u32) -> bool {
    if created_at == 0 || max_pending_hours == 0 {
        return false;
    }
    now.saturating_sub(created_at) >= (max_pending_hours as u64) * 3600
}

// ── Delegation (FR6.2, invariant 6) ─────────────────────────────────────────

/// A 64-character lowercase hex pubkey, or `None`.
///
/// The Delegate control will not publish anything else: a mistyped target would
/// mint a delegation to a pubkey nobody holds, which the relay would accept as
/// a well-formed 31403 and which would park the case in `Delegated` with no
/// delegatee able to move it.
pub fn normalise_delegate_pubkey(input: &str) -> Option<String> {
    let t = input.trim();
    (t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit())).then(|| t.to_ascii_lowercase())
}

/// One observed decision, reduced to what the view rules need.
///
/// Mirrors `stores::panel_registry::DecisionEntry` but owns no store types, so
/// the delegation and decided-ness rules are testable in isolation.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainStep {
    pub event_id: String,
    pub signer_pubkey: String,
    pub outcome: String,
    /// `Delegate { delegate_to }`'s target, where the outcome was a delegation.
    pub delegate_to: Option<String>,
    pub superseded: bool,
    pub effective: bool,
}

/// Whether a case has reached a decision — used both to reveal a probe and to
/// stop offering controls on a closed case.
///
/// A delegation is *not* a decision: it hands the case to someone else, and the
/// case stays open until that delegatee decides it. Only a non-superseded,
/// non-delegation outcome closes a case.
pub fn chain_is_decided(chain: &[ChainStep]) -> bool {
    chain
        .iter()
        .any(|s| !s.superseded && s.outcome != "delegate")
}

/// The pubkey an admin delegated this case to, if the delegation still stands.
///
/// Only the *effective* (non-superseded) delegation counts: an admin who
/// supersedes their own delegation has withdrawn it, and the delegatee loses
/// the case with it.
pub fn delegated_to(chain: &[ChainStep]) -> Option<&str> {
    chain
        .iter()
        .rev()
        .find(|s| !s.superseded && s.outcome == "delegate")
        .and_then(|s| s.delegate_to.as_deref())
}

/// Whether `viewer` may publish a 31403 on this case from this client.
///
/// Admins always may. A non-admin may only when an admin's standing delegation
/// names them — invariant 6, "a delegatee may decide only the delegated case".
/// Nobody may decide a case that already carries an effective decision; the
/// supersession path is a separate, admin-only affordance.
///
/// This is a *view* gate mirroring the relay's admission gate, not a
/// replacement for it: the relay rejects an unauthorised 31403 regardless. Its
/// job is that a reviewer is shown the controls exactly when using them will
/// work.
pub fn is_decidable_by(chain: &[ChainStep], viewer_pubkey: Option<&str>, is_admin: bool) -> bool {
    if chain_is_decided(chain) {
        return false;
    }
    let Some(viewer) = viewer_pubkey else {
        return false;
    };
    if is_admin {
        return true;
    }
    delegated_to(chain).is_some_and(|d| d.eq_ignore_ascii_case(viewer))
}

// ── Card section order (FR2.1, EXP-AC-002) ──────────────────────────────────

/// One rendered region of a decision card, in the order it appears.
///
/// The ordering rule is the whole point of FR2.1 and is a *counter-example* in
/// EXP-AC-002 ("Tier/confidence rendered above the controls"): the reviewer
/// must meet the proposal and form a judgement before they meet the agent's
/// framing of it. Making the order data means the rule is asserted by a test
/// instead of by reading a `view!` macro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardSection {
    /// Title, requesting agent, ageing badges, calibration marker.
    Header,
    /// The agent's own `reasoning` prose, verbatim.
    AgentReasoning,
    /// `ActionRequest.fields`, pretty-printed in full.
    Proposal,
    /// `ActionRequest.context_url` as a link.
    ContextLink,
    /// Rationale textarea + Approve / Reject / Amend / Delegate.
    ReviewerControls,
    /// The agent's declared tier, its confidence, and the effective tier.
    AgentFraming,
    /// Receipt-stage decision chain.
    DecisionChain,
}

/// The section order for a decision card.
///
/// `ReviewerControls` precedes `AgentFraming` unconditionally. `ContextLink` is
/// omitted where the request carried no `context_url`, and `AgentReasoning`
/// where the agent wrote none — absence renders as absence (PRD NFR), never as
/// an empty box or a stand-in.
pub fn card_sections(has_context_url: bool, has_agent_reasoning: bool) -> Vec<CardSection> {
    let mut v = vec![CardSection::Header];
    if has_agent_reasoning {
        v.push(CardSection::AgentReasoning);
    }
    v.push(CardSection::Proposal);
    if has_context_url {
        v.push(CardSection::ContextLink);
    }
    v.push(CardSection::ReviewerControls);
    v.push(CardSection::AgentFraming);
    v.push(CardSection::DecisionChain);
    v
}

/// Pretty-print `ActionRequest.fields` for display, in full and untruncated.
///
/// EXP-AC-002 scopes "`fields` of arbitrary JSON shape rendered (pretty-printed)
/// without truncation" — the reviewer is judging this payload, so eliding any
/// of it reintroduces exactly the vacuous verification the PRD is about. The
/// card scrolls; the text does not shorten. A `fields` that is a bare string
/// prints as that string rather than as a quoted JSON scalar.
pub fn pretty_fields(fields: &serde_json::Value) -> String {
    match fields {
        serde_json::Value::Null => String::new(),
        serde_json::Value::String(s) => s.clone(),
        other => serde_json::to_string_pretty(other).unwrap_or_else(|_| other.to_string()),
    }
}

/// The `context_url` of a request, as it may safely be bound into an `href`.
///
/// `ActionRequest.context_url` is **attacker-controlled**: the governance
/// subscription carries no `authors` filter, so any event the relay delivers on
/// kinds 31400–31405 lands in the panel registry, and a `javascript:` or
/// `data:` URI bound into an anchor is stored XSS against every reviewer —
/// including the admins whose keys decide cases. Leptos escapes the attribute
/// value but does not restrict the scheme, and `target="_blank"` does not make
/// a `javascript:` URI inert.
///
/// So only `http://` and `https://` survive, the scheme matched
/// case-insensitively (`JaVaScRiPt:` is a scheme too), and any string carrying
/// an ASCII control character is rejected outright rather than trimmed —
/// browsers strip embedded tabs and newlines before resolving a scheme, so
/// `java\tscript:alert(1)` is a `javascript:` URI wearing a disguise, and the
/// honest answer to a URL with control characters in it is "no".
///
/// Applied at BOTH ends: the store never keeps an unsafe value, and the view
/// re-checks before binding. Either alone would be enough; both means a future
/// ingest path cannot reopen the sink.
pub fn safe_context_url(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() || t.chars().any(|c| c.is_control()) {
        return None;
    }
    let lower = t.to_ascii_lowercase();
    (lower.starts_with("http://") || lower.starts_with("https://")).then(|| t.to_string())
}

/// Shorten an identifier for display without ever slicing mid-character.
///
/// A pubkey or event id from a hostile event is only guaranteed to be a string:
/// the relay checks a 31403's signature, not that every field it carries is
/// ASCII hex. Byte-slicing one at a fixed offset panics on a multi-byte
/// boundary, and a panic in WASM aborts the whole reactive render — the entire
/// forum goes blank. Character-slicing cannot.
pub fn short_id(id: &str) -> String {
    let chars: Vec<char> = id.chars().collect();
    if chars.len() <= 12 {
        return id.to_string();
    }
    let head: String = chars[..8].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

/// Whether there is a proposal to render at all.
pub fn has_proposal(fields: &serde_json::Value) -> bool {
    !matches!(fields, serde_json::Value::Null) && !pretty_fields(fields).is_empty()
}

/// The relay's advertised `ESCALATION_DEFAULT_TIER` as this client understands
/// it: a runtime `window.__ENV__` override, else `RiskTier`'s own default —
/// which is what an unconfigured relay also falls back to, so the two agree.
#[cfg(target_arch = "wasm32")]
pub fn advertised_default_tier() -> RiskTier {
    crate::utils::relay_url::env_override("ESCALATION_DEFAULT_TIER")
        .map(|v| RiskTier::parse(&v))
        .unwrap_or_default()
}

#[cfg(not(target_arch = "wasm32"))]
pub fn advertised_default_tier() -> RiskTier {
    RiskTier::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_bbs_core::governance::{Reversibility, Stakes, Verifiability};

    fn tag(k: &str, v: &str) -> Vec<String> {
        vec![k.to_string(), v.to_string()]
    }

    fn request(fields: serde_json::Value) -> governance::ActionRequest {
        governance::ActionRequest {
            fields,
            reasoning: None,
            context_url: None,
            risk_tier: None,
            confidence: None,
            task_properties: None,
            probe: None,
        }
    }

    fn step(id: &str, outcome: &str, to: Option<&str>, superseded: bool) -> ChainStep {
        ChainStep {
            event_id: id.into(),
            signer_pubkey: "admin".into(),
            outcome: outcome.into(),
            delegate_to: to.map(str::to_string),
            superseded,
            effective: !superseded,
        }
    }

    // ── Rationale gate ──────────────────────────────────────────────────

    #[test]
    fn low_and_medium_never_require_a_rationale() {
        for tier in [RiskTier::Low, RiskTier::Medium] {
            assert!(!rationale_required(tier));
            assert!(rationale_satisfied(tier, ""));
            assert_eq!(rationale_remaining(tier, ""), 0);
        }
    }

    #[test]
    fn high_and_critical_require_twenty_trimmed_characters() {
        for tier in [RiskTier::High, RiskTier::Critical] {
            assert!(rationale_required(tier));
            assert!(!rationale_satisfied(tier, ""));
            assert!(!rationale_satisfied(tier, "too short"));
            // Nineteen characters is still short; twenty passes.
            assert!(!rationale_satisfied(tier, &"x".repeat(19)));
            assert!(rationale_satisfied(tier, &"x".repeat(20)));
        }
    }

    #[test]
    fn whitespace_does_not_satisfy_a_mandatory_rationale() {
        // EXP-AC-002 counter-example: "Approve button enabled on a `critical`
        // case with an empty rationale" — padding is empty.
        assert!(!rationale_satisfied(RiskTier::Critical, &" ".repeat(50)));
        assert_eq!(rationale_remaining(RiskTier::Critical, "   "), 20);
    }

    #[test]
    fn rationale_remaining_counts_down_to_zero() {
        assert_eq!(rationale_remaining(RiskTier::High, "abc"), 17);
        assert_eq!(rationale_remaining(RiskTier::High, &"x".repeat(25)), 0);
    }

    // ── Verbatim reasoning ──────────────────────────────────────────────

    #[test]
    fn published_reasoning_is_the_typed_text_byte_for_byte() {
        let typed = "  I checked the diff against the migration and it is reversible.\n\n— jj  ";
        let content = decision_content(&DecisionOutcome::Approve, typed);
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v["reasoning"].as_str().unwrap(), typed);
        assert_eq!(v["action"].as_str().unwrap(), "approve");
    }

    #[test]
    fn an_empty_rationale_publishes_an_empty_reasoning_not_a_template() {
        // DDD §6 invariant 1. The removed template was
        // `format!("Human {action} via governance UI")`; absence must render
        // and publish as absence.
        let content = decision_content(&DecisionOutcome::Reject, "");
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v["reasoning"].as_str().unwrap(), "");
        assert!(!content.contains("via governance UI"));
        assert!(!content.to_lowercase().contains("human reject"));
    }

    #[test]
    fn decision_content_round_trips_through_the_core_parser() {
        for (outcome, detail) in [
            (DecisionOutcome::Approve, None),
            (DecisionOutcome::Reject, None),
            (
                DecisionOutcome::Amend {
                    diff: "-a\n+b".into(),
                },
                Some("-a\n+b"),
            ),
            (
                DecisionOutcome::Delegate {
                    delegate_to: "f".repeat(64),
                },
                Some("f".repeat(64)).as_deref(),
            ),
        ] {
            let content = decision_content(&outcome, "reviewed carefully enough");
            let parsed = DecisionOutcome::from_response_content(&content)
                .expect("core must parse what the client publishes");
            assert_eq!(parsed, outcome);
            assert_eq!(parsed.detail(), detail);
        }
    }

    #[test]
    fn no_decision_surface_carries_a_rationale_template() {
        // EXP-AC-002: the string `"Human {action} via governance UI"` and any
        // equivalent template no longer exist. Asserted over the sources that
        // build a 31403 rather than left to a reviewer's grep, because a
        // template is exactly the kind of thing that grows back.
        //
        // This module is excluded by construction: it names the removed
        // template in prose so the next reader knows what was removed and why.
        for (name, src) in [
            ("pages/governance.rs", include_str!("../pages/governance.rs")),
            (
                "stores/panel_registry.rs",
                include_str!("../stores/panel_registry.rs"),
            ),
            ("stores/receipts.rs", include_str!("../stores/receipts.rs")),
        ] {
            assert!(
                !src.contains("via governance UI"),
                "{name} still carries the fabricated rationale template"
            );
            // The shape, not just that one string: nothing there may build a
            // `reasoning` value out of the action name.
            assert!(
                !src.contains("Human {"),
                "{name} builds a rationale from the action name"
            );
        }
    }

    // ── Panel resolution ────────────────────────────────────────────────

    #[test]
    fn panel_ref_prefers_the_addressed_a_tag() {
        let tags = vec![tag("a", "31400:aaa:panel-1"), tag("panel", "panel-2")];
        assert_eq!(
            resolve_panel_ref(&tags, "agent"),
            PanelRef::Addressed {
                pubkey: "aaa".into(),
                d_tag: "panel-1".into()
            }
        );
    }

    #[test]
    fn panel_ref_ignores_an_a_tag_for_another_kind() {
        let tags = vec![tag("a", "30023:aaa:article"), tag("panel", "panel-2")];
        assert_eq!(
            resolve_panel_ref(&tags, "agent"),
            PanelRef::Named {
                pubkey: "agent".into(),
                d_tag: "panel-2".into()
            }
        );
    }

    #[test]
    fn panel_ref_falls_back_to_the_agents_latest_panel() {
        assert_eq!(
            resolve_panel_ref(&[], "agent"),
            PanelRef::LatestFromAgent {
                pubkey: "agent".into()
            }
        );
    }

    // ── Boundary (invariant 3) ──────────────────────────────────────────

    #[test]
    fn an_unlabelled_request_folds_to_the_advertised_default() {
        let b = compute_boundary("case-1", "agent", &[], &request(serde_json::json!({})), None, RiskTier::Medium);
        assert_eq!(b.declared, None);
        assert_eq!(b.effective, RiskTier::Medium);
        assert_eq!(b.props, None);
    }

    #[test]
    fn an_irreversible_panel_floors_a_low_declaring_agent_at_high() {
        // The whole point of ADR-2011: the party with the strongest incentive
        // to under-tier its own work cannot lower the boundary.
        let panel = PanelContext {
            task_properties: Some(TaskProperties::new(
                Verifiability::Inspectable,
                Reversibility::Irreversible,
                Stakes::Bounded,
            )),
            policy: PanelPolicy::default(),
        };
        let mut req = request(serde_json::json!({"drop": "table"}));
        req.risk_tier = Some(RiskTier::Low);
        let b = compute_boundary("case-1", "agent", &[], &req, Some(&panel), RiskTier::Low);
        assert_eq!(b.declared, Some(RiskTier::Low));
        assert_eq!(b.effective, RiskTier::High);
        // And the effective tier — not the declaration — drives the gate.
        assert!(rationale_required(b.effective));
        assert!(b.is_member_visible());
    }

    #[test]
    fn a_request_may_tighten_but_never_loosen_the_panel() {
        let panel = PanelContext {
            task_properties: Some(TaskProperties::new(
                Verifiability::Opaque,
                Reversibility::Compensable,
                Stakes::Significant,
            )),
            policy: PanelPolicy::default(),
        };
        // The agent claims the loosest triple on every leg.
        let tags = vec![
            tag("tp-verifiability", "inspectable"),
            tag("tp-reversibility", "reversible"),
            tag("tp-stakes", "bounded"),
        ];
        let b = compute_boundary(
            "case-1",
            "agent",
            &tags,
            &request(serde_json::json!({})),
            Some(&panel),
            RiskTier::Low,
        );
        let props = b.props.expect("a declared triple survives");
        assert_eq!(props.verifiability, Verifiability::Opaque);
        assert_eq!(props.reversibility, Reversibility::Compensable);
        assert_eq!(props.stakes, Stakes::Significant);
    }

    #[test]
    fn a_tag_declared_risk_tier_is_read_like_the_relay_reads_it() {
        let tags = vec![tag("risk-tier", "critical")];
        let b = compute_boundary(
            "case-1",
            "agent",
            &tags,
            &request(serde_json::json!({})),
            None,
            RiskTier::Low,
        );
        assert_eq!(b.effective, RiskTier::Critical);
    }

    #[test]
    fn opaque_work_is_never_member_suppressed() {
        let panel = PanelContext {
            task_properties: Some(TaskProperties::new(
                Verifiability::Opaque,
                Reversibility::Reversible,
                Stakes::Bounded,
            )),
            policy: PanelPolicy::default(),
        };
        let mut req = request(serde_json::json!({}));
        req.risk_tier = Some(RiskTier::Low);
        let b = compute_boundary("case-1", "agent", &[], &req, Some(&panel), RiskTier::Low);
        assert!(b.is_member_visible());
    }

    #[test]
    fn a_plain_low_case_is_member_suppressed_unless_sampled() {
        let mut req = request(serde_json::json!({}));
        req.risk_tier = Some(RiskTier::Low);
        // Rate 0 samples nothing.
        let panel_none = PanelContext {
            task_properties: None,
            policy: PanelPolicy {
                calibration_sample_rate: 0.0,
                max_pending_hours: 72,
                probe_agent: None,
            },
        };
        let b = compute_boundary("case-1", "agent", &[], &req, Some(&panel_none), RiskTier::Low);
        assert!(!b.calibration_sample);
        assert!(!b.is_member_visible());

        // Rate 1 samples everything, and a sample is always shown (FR6.3).
        let panel_all = PanelContext {
            task_properties: None,
            policy: PanelPolicy {
                calibration_sample_rate: 1.0,
                max_pending_hours: 72,
                probe_agent: None,
            },
        };
        let b = compute_boundary("case-1", "agent", &[], &req, Some(&panel_all), RiskTier::Low);
        assert!(b.calibration_sample);
        assert!(b.is_member_visible());
    }

    #[test]
    fn calibration_sampling_is_deterministic_and_clock_free() {
        // EXP-AC-006 counter-example: "Sampling that depends on wall-clock
        // time". Same id, same answer, every time.
        let mut req = request(serde_json::json!({}));
        req.risk_tier = Some(RiskTier::Low);
        let panel = PanelContext {
            task_properties: None,
            policy: PanelPolicy {
                calibration_sample_rate: 0.1,
                max_pending_hours: 72,
                probe_agent: None,
            },
        };
        let first = compute_boundary("case-abc", "agent", &[], &req, Some(&panel), RiskTier::Low);
        for _ in 0..8 {
            let again =
                compute_boundary("case-abc", "agent", &[], &req, Some(&panel), RiskTier::Low);
            assert_eq!(first.calibration_sample, again.calibration_sample);
        }
    }

    #[test]
    fn panel_context_reads_the_triple_from_tags_or_from_content() {
        let from_tags = PanelContext::from_panel(
            &[
                tag("tp-verifiability", "opaque"),
                tag("max-pending-hours", "12"),
            ],
            None,
        );
        assert_eq!(
            from_tags.task_properties.unwrap().verifiability,
            Verifiability::Opaque
        );
        assert_eq!(from_tags.policy.max_pending_hours, 12);

        // No tags at all: the policy is the documented default.
        let bare = PanelContext::from_panel(&[], None);
        assert!(bare.task_properties.is_none());
        assert_eq!(bare.policy.max_pending_hours, governance::DEFAULT_MAX_PENDING_HOURS);
    }

    // ── Probe blindness (invariant 7) ───────────────────────────────────

    #[test]
    fn a_probe_is_hidden_until_the_case_is_decided() {
        // EXP-AC-006 counter-example: "Probe tag visible on a pending card".
        assert_eq!(visible_probe(false, Some("deadbeef")), None);
        assert_eq!(visible_probe(true, Some("deadbeef")), Some("deadbeef"));
        assert_eq!(visible_probe(true, None), None);
    }

    #[test]
    fn a_probe_tag_on_a_pending_fixture_event_never_reaches_the_view() {
        // The fixture is a real 31402 carrying the tag, exactly as it arrives
        // over REQ: the relay cannot strip it without invalidating the
        // signature, so blindness is this client's job.
        let probe_tags = vec![
            tag("d", "case-probe-1"),
            tag("probe", &"ab".repeat(32)),
            tag("risk-tier", "low"),
        ];
        let probe_agent = "c".repeat(64);
        let panel = PanelContext {
            task_properties: None,
            policy: PanelPolicy {
                calibration_sample_rate: 0.0,
                max_pending_hours: 72,
                probe_agent: Some(probe_agent.clone()),
            },
        };
        let b = compute_boundary(
            "case-probe-1",
            &probe_agent,
            &probe_tags,
            &request(serde_json::json!({"x": 1})),
            Some(&panel),
            RiskTier::Low,
        );
        // The digest is recognised (it is from the registered probe agent) …
        assert_eq!(b.probe_digest.as_deref(), Some(&*"ab".repeat(32)));
        // … and still not renderable while the case is undecided.
        let chain: Vec<ChainStep> = Vec::new();
        assert!(!chain_is_decided(&chain));
        assert_eq!(
            visible_probe(chain_is_decided(&chain), b.probe_digest.as_deref()),
            None
        );
        // Once a 31403 exists it may be shown.
        let decided = vec![step("dec-1", "approve", None, false)];
        assert_eq!(
            visible_probe(chain_is_decided(&decided), b.probe_digest.as_deref()),
            Some(&*"ab".repeat(32))
        );
    }

    #[test]
    fn a_probe_tag_from_an_unregistered_agent_is_not_a_probe() {
        let tags = vec![tag("probe", "deadbeef")];
        let panel = PanelContext {
            task_properties: None,
            policy: PanelPolicy {
                calibration_sample_rate: 0.0,
                max_pending_hours: 72,
                probe_agent: Some("c".repeat(64)),
            },
        };
        let b = compute_boundary(
            "case-1",
            "someone-else",
            &tags,
            &request(serde_json::json!({})),
            Some(&panel),
            RiskTier::Low,
        );
        assert_eq!(b.probe_digest, None);
    }

    // ── Ageing (FR4.3) ──────────────────────────────────────────────────

    #[test]
    fn relative_age_labels_read_in_the_largest_whole_unit() {
        assert_eq!(relative_age_label(1_000, 1_030), "just now");
        assert_eq!(relative_age_label(1_000, 1_000 + 300), "5m old");
        assert_eq!(relative_age_label(1_000, 1_000 + 7_200), "2h old");
        assert_eq!(relative_age_label(1_000, 1_000 + 259_200), "3d old");
    }

    #[test]
    fn a_future_created_at_reads_as_just_now_not_as_a_negative_age() {
        assert_eq!(relative_age_label(9_000, 1_000), "just now");
    }

    #[test]
    fn a_missing_created_at_says_so_rather_than_claiming_an_age() {
        assert_eq!(relative_age_label(0, 1_000), "age unknown");
        assert!(!is_overdue(0, 10_000_000, 72));
    }

    #[test]
    fn overdue_trips_exactly_at_the_panel_deadline() {
        let created = 1_000_000u64;
        let deadline = created + 72 * 3600;
        assert!(!is_overdue(created, deadline - 1, 72));
        assert!(is_overdue(created, deadline, 72));
        // A tighter panel deadline trips sooner.
        assert!(is_overdue(created, created + 12 * 3600, 12));
    }

    // ── Delegation (invariant 6) ────────────────────────────────────────

    #[test]
    fn delegate_target_must_be_hex64() {
        assert_eq!(normalise_delegate_pubkey(&"A".repeat(64)), Some("a".repeat(64)));
        assert_eq!(
            normalise_delegate_pubkey(&format!("  {}  ", "b".repeat(64))),
            Some("b".repeat(64))
        );
        assert_eq!(normalise_delegate_pubkey(""), None);
        assert_eq!(normalise_delegate_pubkey(&"a".repeat(63)), None);
        assert_eq!(normalise_delegate_pubkey(&"a".repeat(65)), None);
        assert_eq!(normalise_delegate_pubkey(&"z".repeat(64)), None);
        assert_eq!(normalise_delegate_pubkey("npub1abc"), None);
    }

    #[test]
    fn an_admin_may_decide_an_open_case_and_a_stranger_may_not() {
        let chain: Vec<ChainStep> = Vec::new();
        assert!(is_decidable_by(&chain, Some("admin"), true));
        assert!(!is_decidable_by(&chain, Some("stranger"), false));
        // Logged out: nothing to sign with.
        assert!(!is_decidable_by(&chain, None, true));
    }

    #[test]
    fn a_delegatee_may_decide_only_the_delegated_case() {
        // EXP-AC-006 counter-example: "A reviewer deciding a case not
        // delegated to them".
        let reviewer = "d".repeat(64);
        let delegated = vec![step("dec-1", "delegate", Some(&reviewer), false)];
        assert!(is_decidable_by(&delegated, Some(&reviewer), false));
        assert!(!is_decidable_by(&delegated, Some(&"e".repeat(64)), false));
        // A different case, with no delegation, stays read-only for them.
        assert!(!is_decidable_by(&[], Some(&reviewer), false));
    }

    #[test]
    fn a_delegation_is_not_itself_a_decision() {
        let reviewer = "d".repeat(64);
        let chain = vec![step("dec-1", "delegate", Some(&reviewer), false)];
        assert!(!chain_is_decided(&chain));
        assert_eq!(delegated_to(&chain), Some(&*reviewer));
    }

    #[test]
    fn a_superseded_delegation_withdraws_the_reviewers_authority() {
        let reviewer = "d".repeat(64);
        let chain = vec![
            step("dec-1", "delegate", Some(&reviewer), true),
            step("dec-2", "delegate", Some(&"e".repeat(64)), false),
        ];
        assert_eq!(delegated_to(&chain), Some(&*"e".repeat(64)));
        assert!(!is_decidable_by(&chain, Some(&reviewer), false));
    }

    #[test]
    fn a_decided_case_offers_controls_to_nobody() {
        let chain = vec![step("dec-1", "approve", None, false)];
        assert!(!is_decidable_by(&chain, Some("admin"), true));
    }

    // ── Card order (FR2.1) ──────────────────────────────────────────────

    #[test]
    fn reviewer_controls_always_precede_the_agents_framing() {
        for (ctx, reasoning) in [(false, false), (true, false), (false, true), (true, true)] {
            let s = card_sections(ctx, reasoning);
            let controls = s.iter().position(|x| *x == CardSection::ReviewerControls);
            let framing = s.iter().position(|x| *x == CardSection::AgentFraming);
            assert!(
                controls < framing,
                "tier/confidence must never render above Approve (sections: {s:?})"
            );
        }
    }

    #[test]
    fn the_proposal_precedes_the_controls_so_it_is_in_view_when_judging() {
        let s = card_sections(true, true);
        let proposal = s.iter().position(|x| *x == CardSection::Proposal).unwrap();
        let controls = s
            .iter()
            .position(|x| *x == CardSection::ReviewerControls)
            .unwrap();
        assert!(proposal < controls);
    }

    #[test]
    fn absent_optional_sections_are_omitted_not_emptied() {
        let s = card_sections(false, false);
        assert!(!s.contains(&CardSection::ContextLink));
        assert!(!s.contains(&CardSection::AgentReasoning));
        assert!(s.contains(&CardSection::Proposal));
    }

    // ── Proposal rendering ──────────────────────────────────────────────

    #[test]
    fn fields_are_pretty_printed_in_full_without_truncation() {
        let big: serde_json::Value = serde_json::json!({
            "migration": "0007_drop_legacy",
            "statements": (0..200).map(|i| format!("DROP TABLE legacy_{i}")).collect::<Vec<_>>(),
        });
        let out = pretty_fields(&big);
        assert!(out.contains("DROP TABLE legacy_0"));
        assert!(out.contains("DROP TABLE legacy_199"), "no truncation");
        assert!(!out.contains('…'));
        assert!(out.contains('\n'), "pretty-printed, not minified");
    }

    #[test]
    fn a_bare_string_payload_prints_as_itself() {
        assert_eq!(
            pretty_fields(&serde_json::json!("rm -rf /var/lib/pods")),
            "rm -rf /var/lib/pods"
        );
    }

    // ── href safety ─────────────────────────────────────────────────────

    #[test]
    fn only_http_and_https_context_urls_survive() {
        assert_eq!(
            safe_context_url("https://example.org/pr/1"),
            Some("https://example.org/pr/1".to_string())
        );
        assert_eq!(
            safe_context_url("  http://example.org/x  "),
            Some("http://example.org/x".to_string())
        );
        // Scheme matching is case-insensitive in both directions.
        assert_eq!(
            safe_context_url("HTTPS://example.org"),
            Some("HTTPS://example.org".to_string())
        );
    }

    #[test]
    fn a_script_bearing_context_url_never_reaches_an_href() {
        for hostile in [
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "  javascript:alert(1)",
            "data:text/html;base64,PHNjcmlwdD4=",
            "vbscript:msgbox(1)",
            "file:///etc/passwd",
            "//evil.example/x",
            "",
            "   ",
        ] {
            assert_eq!(safe_context_url(hostile), None, "accepted {hostile:?}");
        }
    }

    #[test]
    fn control_characters_are_rejected_rather_than_trimmed_out() {
        // Browsers strip embedded tabs and newlines before resolving a scheme,
        // so this is a `javascript:` URI in disguise.
        assert_eq!(safe_context_url("java\tscript:alert(1)"), None);
        assert_eq!(safe_context_url("java\nscript:alert(1)"), None);
        assert_eq!(safe_context_url("https://example.org/\u{0}x"), None);
    }

    #[test]
    fn short_id_never_slices_mid_character() {
        // A hostile 31403 can carry any string as a delegate target; a
        // byte-slice at a fixed offset would panic and blank the whole client.
        assert_eq!(short_id("abcdefghijklmnop"), "abcdefgh…mnop");
        assert_eq!(short_id("short"), "short");
        // Multi-byte characters straddling byte offsets 6, 8 and len-4.
        let multi = "日本語テキストの長い文字列です";
        let out = short_id(multi);
        assert!(out.contains('…'));
        assert!(out.starts_with("日本語テキストの"));
        // Emoji (4-byte) at every boundary.
        let emoji = "😀😀😀😀😀😀😀😀😀😀😀😀😀😀";
        assert_eq!(short_id(emoji), "😀😀😀😀😀😀😀😀…😀😀😀😀");
    }

    #[test]
    fn a_null_payload_is_absent_rather_than_the_word_null() {
        assert_eq!(pretty_fields(&serde_json::Value::Null), "");
        assert!(!has_proposal(&serde_json::Value::Null));
        assert!(has_proposal(&serde_json::json!({"a": 1})));
    }
}
