//! Agent Control Surface Protocol — governance types for the nostr-bbs relay.
//!
//! Defines the domain model for agent-published control panels rendered by the
//! forum client, and the broker case aggregate for human-in-the-loop governance
//! decisions.
//!
//! ## Nostr Event Kinds
//!
//! | Kind  | Name              | Publisher | Purpose                                   |
//! |-------|-------------------|-----------|-------------------------------------------|
//! | 31400 | PanelDefinition   | Agent     | Declare a control panel (schema, actions)  |
//! | 31401 | PanelState        | Agent     | Publish current panel data snapshot        |
//! | 31402 | ActionRequest     | Agent     | Request human decision                     |
//! | 31403 | ActionResponse    | Human     | Respond to an action request               |
//! | 31404 | PanelUpdate       | Agent     | Incremental state diff                     |
//! | 31405 | PanelRetired      | Agent     | Retire a control panel                     |
//!
//! All events use `d`-tag addressing (NIP-33 parameterized replaceable).

use crate::event::NostrEvent;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

// ── Event kind constants ────────────────────────────────────────────────────

pub const KIND_PANEL_DEFINITION: u64 = 31400;
pub const KIND_PANEL_STATE: u64 = 31401;
pub const KIND_ACTION_REQUEST: u64 = 31402;
pub const KIND_ACTION_RESPONSE: u64 = 31403;
pub const KIND_PANEL_UPDATE: u64 = 31404;
pub const KIND_PANEL_RETIRED: u64 = 31405;

pub const GOVERNANCE_KIND_RANGE: std::ops::RangeInclusive<u64> = 31400..=31405;

// ── Panel Definition ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PanelSchema {
    ActionInbox,
    Dashboard,
    ConfigForm,
    StatusBoard,
    ChatBridge,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PanelCapability {
    BulkAction,
    Filter,
    Search,
    Sort,
    Export,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FieldType {
    String,
    Int,
    Float,
    Bool,
    Json,
    Enum,
    Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldDef {
    pub name: String,
    pub field_type: FieldType,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ActionStyle {
    Primary,
    Secondary,
    Destructive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionDef {
    pub id: String,
    pub label: String,
    pub style: ActionStyle,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LayoutHint {
    InboxTable,
    Kanban,
    CardGrid,
    SplitDetail,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PanelDefinition {
    pub title: String,
    pub description: String,
    #[serde(default = "default_version")]
    pub version: String,
    pub schema: PanelSchema,
    pub fields: Vec<FieldDef>,
    pub actions: Vec<ActionDef>,
    pub layout: LayoutHint,
    #[serde(default)]
    pub capabilities: Vec<PanelCapability>,
    #[serde(default = "default_refresh")]
    pub refresh_secs: u32,
}

fn default_version() -> String {
    "1.0.0".into()
}

fn default_refresh() -> u32 {
    30
}

// ── Action Request / Response ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionPriority {
    Critical,
    High,
    Medium,
    Low,
}

/// Agent-declared risk tier for a governance action request (F7).
///
/// Declared by the agent on the 31402 ActionRequest. It is the design answer to
/// approval fatigue: the member surface suppresses `Low`-tier requests so a
/// member sees only the requests a tier says warrant attention. Suppression is
/// a view filter — the underlying 31403/31402 events still exist and remain
/// auditable through the admin surface and the decisions read API (ADR-106
/// Decision 4). If REC-6 later supplies a relay-side default it overrides this
/// agent-declared tier; until then the agent's declaration stands.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskTier {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskTier::Low => "low",
            RiskTier::Medium => "medium",
            RiskTier::High => "high",
            RiskTier::Critical => "critical",
        }
    }

    /// Parse a persisted/tag risk-tier string. Unrecognised values fall back to
    /// `Medium` so an unlabelled request is shown (fail-open on visibility).
    pub fn parse(s: &str) -> RiskTier {
        match s {
            "low" => RiskTier::Low,
            "high" => RiskTier::High,
            "critical" => RiskTier::Critical,
            _ => RiskTier::Medium,
        }
    }

    /// Whether the member surface suppresses a request at this tier (F7).
    ///
    /// Only `Low` is suppressed; medium and above always warrant member
    /// attention. An absent tier is treated as `Medium` (shown) by callers.
    pub fn is_member_suppressed(self) -> bool {
        matches!(self, RiskTier::Low)
    }
}

impl Default for RiskTier {
    fn default() -> Self {
        RiskTier::Medium
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    pub fields: serde_json::Value,
    pub reasoning: Option<String>,
    pub context_url: Option<String>,
    /// Agent-declared risk tier (F7). Absent on legacy requests → treated as
    /// `Medium` (shown) by the member surface.
    #[serde(default)]
    pub risk_tier: Option<RiskTier>,
    /// Agent-declared confidence in the requested action, `0.0..=1.0` (F5).
    /// Displayed at decision time so a human sees the agent's stated confidence
    /// before responding. Absent on legacy requests.
    #[serde(default)]
    pub confidence: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResponse {
    pub action: String,
    pub reasoning: String,
}

// ── Tag extraction helpers ──────────────────────────────────────────────────

pub fn is_governance_kind(kind: u64) -> bool {
    GOVERNANCE_KIND_RANGE.contains(&kind)
}

pub fn extract_d_tag(tags: &[Vec<String>]) -> Option<&str> {
    tags.iter()
        .find(|t| t.first().map(|s| s.as_str()) == Some("d"))
        .and_then(|t| t.get(1))
        .map(|s| s.as_str())
}

pub fn extract_tag<'a>(tags: &'a [Vec<String>], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|t| t.first().map(|s| s.as_str()) == Some(name))
        .and_then(|t| t.get(1))
        .map(|s| s.as_str())
}

// ── Governance event validation (P2: authz / append-only audit log) ──────────

/// Reasons a governance control-surface event can fail validation.
///
/// Mirrors the structure/style of
/// [`crate::moderation_events::ModerationEventError`] so callers can adopt the
/// same handling pattern.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GovernanceEventError {
    /// The event kind is outside the governance range (31400-31405).
    #[error("kind {0} is not a governance event kind")]
    UnknownKind(u64),

    /// The `d` tag required by parameterized-replaceable semantics is missing.
    #[error("missing `d` tag")]
    MissingDTag,

    /// The `d` tag is present but empty.
    #[error("`d` tag is empty")]
    EmptyDTag,

    /// A 31405 audit-log entry reused a `d` tag that was already recorded.
    ///
    /// Audit logs are append-only and tamper-evident: each entry MUST carry a
    /// unique audit-entry id in its `d` tag. A repeated `d` is a replay /
    /// overwrite attempt and is rejected rather than silently replacing the
    /// existing entry.
    #[error("duplicate audit-log `d` tag `{0}`: audit entries are append-only")]
    DuplicateAuditEntry(String),
}

/// The 31405 GovernanceAuditLog kind. Audit-log entries are append-only: each
/// uses a unique-per-entry `d` tag (audit-entry id) so a same-`d` replay is
/// rejected as a duplicate instead of overwriting the prior entry.
pub const KIND_GOVERNANCE_AUDIT_LOG: u64 = 31405;

/// Validate that `event` is a well-formed governance control-surface event.
///
/// `seen_audit_ids` is the set of audit-entry `d` tags already recorded by the
/// caller. For 31405 audit-log events this enforces append-only semantics: a
/// `d` tag already present in the set is a replay/overwrite and is rejected.
/// Callers should insert each accepted audit-entry `d` into the set after a
/// successful validation. For non-audit kinds the set is ignored.
pub fn validate_governance_event(
    event: &NostrEvent,
    seen_audit_ids: &HashSet<String>,
) -> Result<(), GovernanceEventError> {
    // (a) kind must be in the governance range.
    if !is_governance_kind(event.kind) {
        return Err(GovernanceEventError::UnknownKind(event.kind));
    }

    // All governance kinds are NIP-33 parameterized-replaceable: require a
    // non-empty `d` tag.
    let d = extract_d_tag(&event.tags).ok_or(GovernanceEventError::MissingDTag)?;
    if d.is_empty() {
        return Err(GovernanceEventError::EmptyDTag);
    }

    // (b) 31405 audit-log entries are append-only: the `d` tag must be a unique
    // audit-entry id never seen before. A reused `d` is a duplicate.
    if event.kind == KIND_GOVERNANCE_AUDIT_LOG && seen_audit_ids.contains(d) {
        return Err(GovernanceEventError::DuplicateAuditEntry(d.to_string()));
    }

    Ok(())
}

// ── Agent Registry ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredAgent {
    pub pubkey: String,
    pub name: String,
    pub description: String,
    pub registered_by: String,
    pub registered_at: u64,
    pub rate_limit_per_min: u32,
    pub active: bool,
}

// ═══════════════════════════════════════════════════════════════════════════
// Broker Case Domain Model (ported from VisionClaw ADR-041/057)
// ═══════════════════════════════════════════════════════════════════════════

pub mod broker {
    use super::*;
    use thiserror::Error;

    // ── Errors ──────────────────────────────────────────────────────────

    #[derive(Debug, Error, PartialEq, Eq)]
    pub enum CaseError {
        #[error("self-review forbidden: broker {broker} is the case creator")]
        SelfReview { broker: String },

        #[error("case already terminal in state {0:?}; no further decisions allowed")]
        AlreadyTerminal(CaseState),

        #[error("invalid transition from {from:?} to {to:?}")]
        InvalidTransition { from: CaseState, to: CaseState },

        #[error("amendment outcome requires a non-empty diff")]
        MissingAmendmentDiff,

        #[error("delegation outcome requires a non-empty delegate pubkey")]
        MissingDelegateTarget,
    }

    // ── Value Objects ───────────────────────────────────────────────────

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum CaseCategory {
        ContributorMeshShare,
        WorkflowReview,
        PolicyException,
        TrustAlert,
        ManualSubmission,
        KnowledgeEnrichment,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum SubjectKind {
        WorkArtifact,
        SkillPackage,
        AutomationProposal,
        PolicyException,
        Opaque,
    }

    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
    #[serde(rename_all = "snake_case")]
    pub enum ShareState {
        Private,
        Team,
        Mesh,
    }

    impl ShareState {
        pub fn can_advance_to(self, next: ShareState) -> bool {
            matches!(
                (self, next),
                (ShareState::Private, ShareState::Team)
                    | (ShareState::Team, ShareState::Mesh)
                    | (ShareState::Private, ShareState::Mesh)
            )
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase")]
    pub struct SubjectRef {
        pub kind: SubjectKind,
        pub id: String,
        #[serde(default)]
        pub from_state: Option<ShareState>,
        #[serde(default)]
        pub to_state: Option<ShareState>,
    }

    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum CaseState {
        Open,
        UnderReview,
        Decided,
        Delegated,
        Promoted,
        Precedent,
        Closed,
    }

    impl CaseState {
        pub fn is_terminal(self) -> bool {
            matches!(
                self,
                CaseState::Decided
                    | CaseState::Delegated
                    | CaseState::Promoted
                    | CaseState::Precedent
                    | CaseState::Closed
            )
        }

        /// Canonical persisted string for the `broker_cases.state` column.
        pub fn as_str(self) -> &'static str {
            match self {
                CaseState::Open => "open",
                CaseState::UnderReview => "under_review",
                CaseState::Decided => "decided",
                CaseState::Delegated => "delegated",
                CaseState::Promoted => "promoted",
                CaseState::Precedent => "precedent",
                CaseState::Closed => "closed",
            }
        }

        /// Parse a persisted `broker_cases.state` string.
        ///
        /// Lenient by design. The pre-orchestrator projection wrote ad-hoc
        /// strings (`resolved`/`rejected`) that are not `CaseState` variants;
        /// those map to `Decided` (both are terminal decisions). An unrecognised
        /// value falls back to `Open` so a case is never left unreachable.
        pub fn parse(s: &str) -> CaseState {
            match s {
                "under_review" => CaseState::UnderReview,
                "decided" | "resolved" | "rejected" => CaseState::Decided,
                "delegated" => CaseState::Delegated,
                "promoted" => CaseState::Promoted,
                "precedent" => CaseState::Precedent,
                "closed" => CaseState::Closed,
                _ => CaseState::Open,
            }
        }
    }

    impl CaseCategory {
        /// Parse a persisted `broker_cases.category` string; unknown values fall
        /// back to `ManualSubmission` (the projection default).
        pub fn parse(s: &str) -> CaseCategory {
            match s {
                "contributor_mesh_share" => CaseCategory::ContributorMeshShare,
                "workflow_review" => CaseCategory::WorkflowReview,
                "policy_exception" => CaseCategory::PolicyException,
                "trust_alert" => CaseCategory::TrustAlert,
                "knowledge_enrichment" => CaseCategory::KnowledgeEnrichment,
                _ => CaseCategory::ManualSubmission,
            }
        }
    }

    impl ShareState {
        /// Parse a persisted share-state string; `None` when absent/unrecognised.
        pub fn parse(s: &str) -> Option<ShareState> {
            match s {
                "private" => Some(ShareState::Private),
                "team" => Some(ShareState::Team),
                "mesh" => Some(ShareState::Mesh),
                _ => None,
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(tag = "action", rename_all = "snake_case")]
    pub enum DecisionOutcome {
        Approve,
        Reject,
        Amend { diff: String },
        Delegate { delegate_to: String },
        Promote { pattern_id: String },
        Precedent { scope: String },
    }

    impl DecisionOutcome {
        pub fn action_str(&self) -> &'static str {
            match self {
                DecisionOutcome::Approve => "approve",
                DecisionOutcome::Reject => "reject",
                DecisionOutcome::Amend { .. } => "amend",
                DecisionOutcome::Delegate { .. } => "delegate",
                DecisionOutcome::Promote { .. } => "promote",
                DecisionOutcome::Precedent { .. } => "precedent",
            }
        }

        /// Parse a decision outcome from a signed 31403 ActionResponse content
        /// payload.
        ///
        /// The content is the internally-tagged `DecisionOutcome` JSON:
        /// `{"action":"delegate","delegate_to":"<pubkey>", ...}`. The binary
        /// forms carry no detail (`{"action":"approve"}`); the non-binary forms
        /// carry the typed detail field their variant requires (`delegate_to`,
        /// `pattern_id`, `scope`, `diff`). Extra fields — notably the human's
        /// free-text `reasoning` — are ignored. Returns `None` when the action is
        /// unrecognised or a required detail field is missing, so a malformed
        /// response is rejected rather than silently parked.
        pub fn from_response_content(content: &str) -> Option<Self> {
            serde_json::from_str::<Self>(content).ok()
        }

        /// The typed detail payload for the `broker_decisions.outcome_detail`
        /// column: the delegate target, promoted pattern id, precedent scope, or
        /// amendment diff. `None` for the binary approve/reject outcomes.
        pub fn detail(&self) -> Option<&str> {
            match self {
                DecisionOutcome::Approve | DecisionOutcome::Reject => None,
                DecisionOutcome::Amend { diff } => Some(diff.as_str()),
                DecisionOutcome::Delegate { delegate_to } => Some(delegate_to.as_str()),
                DecisionOutcome::Promote { pattern_id } => Some(pattern_id.as_str()),
                DecisionOutcome::Precedent { scope } => Some(scope.as_str()),
            }
        }
    }

    // ── Aggregate: Decision History Entry ────────────────────────────────

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase")]
    pub struct DecisionHistoryEntry {
        pub decision_id: String,
        pub outcome: DecisionOutcome,
        pub broker_pubkey: String,
        pub decided_at: u64,
        pub prior_decision_id: Option<String>,
        pub reasoning: String,
    }

    // ── Aggregate Root: BrokerCase ──────────────────────────────────────

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct BrokerCase {
        pub id: String,
        pub category: CaseCategory,
        pub subject: SubjectRef,
        pub title: String,
        pub summary: String,
        pub state: CaseState,
        pub priority: u8,
        pub created_by: String,
        pub created_at: u64,
        pub updated_at: u64,
        pub assigned_to: Option<String>,
        pub history: Vec<DecisionHistoryEntry>,
        #[serde(default)]
        pub metadata: HashMap<String, String>,
        pub nostr_event_id: Option<String>,
    }

    impl BrokerCase {
        #[allow(clippy::too_many_arguments)]
        pub fn new(
            id: impl Into<String>,
            category: CaseCategory,
            subject: SubjectRef,
            title: impl Into<String>,
            summary: impl Into<String>,
            created_by: impl Into<String>,
            priority: u8,
            now: u64,
        ) -> Self {
            Self {
                id: id.into(),
                category,
                subject,
                title: title.into(),
                summary: summary.into(),
                state: CaseState::Open,
                priority,
                created_by: created_by.into(),
                created_at: now,
                updated_at: now,
                assigned_to: None,
                history: Vec::new(),
                metadata: HashMap::new(),
                nostr_event_id: None,
            }
        }

        pub fn claim(
            &mut self,
            broker_pubkey: impl Into<String>,
            now: u64,
        ) -> Result<(), CaseError> {
            let b = broker_pubkey.into();
            if b == self.created_by {
                return Err(CaseError::SelfReview { broker: b });
            }
            match self.state {
                CaseState::Open => {
                    self.state = CaseState::UnderReview;
                    self.assigned_to = Some(b);
                    self.updated_at = now;
                    Ok(())
                }
                CaseState::UnderReview => {
                    if self.assigned_to.as_deref() == Some(b.as_str()) {
                        Ok(())
                    } else {
                        Err(CaseError::InvalidTransition {
                            from: self.state,
                            to: CaseState::UnderReview,
                        })
                    }
                }
                other => Err(CaseError::AlreadyTerminal(other)),
            }
        }

        pub fn release(&mut self, now: u64) -> Result<(), CaseError> {
            if self.state != CaseState::UnderReview {
                return Err(CaseError::InvalidTransition {
                    from: self.state,
                    to: CaseState::Open,
                });
            }
            self.state = CaseState::Open;
            self.assigned_to = None;
            self.updated_at = now;
            Ok(())
        }

        pub fn record_decision(
            &mut self,
            decision_id: impl Into<String>,
            outcome: DecisionOutcome,
            broker_pubkey: impl Into<String>,
            reasoning: impl Into<String>,
            now: u64,
        ) -> Result<&DecisionHistoryEntry, CaseError> {
            let broker = broker_pubkey.into();

            if broker == self.created_by {
                return Err(CaseError::SelfReview { broker });
            }

            if self.state.is_terminal() {
                return Err(CaseError::AlreadyTerminal(self.state));
            }

            match &outcome {
                DecisionOutcome::Amend { diff } if diff.trim().is_empty() => {
                    return Err(CaseError::MissingAmendmentDiff);
                }
                DecisionOutcome::Delegate { delegate_to } if delegate_to.trim().is_empty() => {
                    return Err(CaseError::MissingDelegateTarget);
                }
                _ => {}
            }

            let prior_decision_id = self.history.last().map(|e| e.decision_id.clone());
            let entry = DecisionHistoryEntry {
                decision_id: decision_id.into(),
                outcome: outcome.clone(),
                broker_pubkey: broker,
                decided_at: now,
                prior_decision_id,
                reasoning: reasoning.into(),
            };

            self.history.push(entry);

            self.state = match outcome {
                DecisionOutcome::Approve
                | DecisionOutcome::Reject
                | DecisionOutcome::Amend { .. } => CaseState::Decided,
                DecisionOutcome::Delegate { .. } => CaseState::Delegated,
                DecisionOutcome::Promote { .. } => CaseState::Promoted,
                DecisionOutcome::Precedent { .. } => CaseState::Precedent,
            };
            self.updated_at = now;

            Ok(self.history.last().expect("just pushed"))
        }

        pub fn latest_decision_id(&self) -> Option<&str> {
            self.history.last().map(|e| e.decision_id.as_str())
        }
    }

    // ── Decision Orchestrator ───────────────────────────────────────────

    #[derive(Debug, Clone)]
    pub struct ShareTransitionPlan {
        pub case_id: String,
        pub subject: SubjectRef,
        pub from: ShareState,
        pub to: ShareState,
        pub approved_by: String,
    }

    #[derive(Debug, Clone)]
    pub struct DecisionReport {
        pub case_id: String,
        pub entry: DecisionHistoryEntry,
        pub share_plan: Option<ShareTransitionPlan>,
    }

    #[derive(Debug, Error)]
    pub enum OrchestrationError {
        #[error(transparent)]
        Case(#[from] CaseError),

        #[error("share transition rejected: {0}")]
        ShareTransitionRejected(String),
    }

    #[derive(Debug, Default, Clone)]
    pub struct DecisionOrchestrator;

    impl DecisionOrchestrator {
        pub fn decide(
            &self,
            case: &mut BrokerCase,
            decision_id: impl Into<String>,
            outcome: DecisionOutcome,
            broker_pubkey: impl Into<String>,
            reasoning: impl Into<String>,
            now: u64,
        ) -> Result<DecisionReport, OrchestrationError> {
            let broker_pubkey_s = broker_pubkey.into();
            let outcome_clone = outcome.clone();

            let entry = case
                .record_decision(decision_id, outcome, &broker_pubkey_s, reasoning, now)?
                .clone();

            let share_plan = match (&case.category, &outcome_clone) {
                (
                    CaseCategory::ContributorMeshShare,
                    DecisionOutcome::Approve | DecisionOutcome::Promote { .. },
                ) => build_share_plan(case, &broker_pubkey_s)?,
                _ => None,
            };

            Ok(DecisionReport {
                case_id: case.id.clone(),
                entry,
                share_plan,
            })
        }
    }

    fn build_share_plan(
        case: &BrokerCase,
        approved_by: &str,
    ) -> Result<Option<ShareTransitionPlan>, OrchestrationError> {
        let (Some(from), Some(to)) = (case.subject.from_state, case.subject.to_state) else {
            return Ok(None);
        };
        if !from.can_advance_to(to) {
            return Err(OrchestrationError::ShareTransitionRejected(format!(
                "{from:?} -> {to:?} is not a forward transition"
            )));
        }
        Ok(Some(ShareTransitionPlan {
            case_id: case.id.clone(),
            subject: case.subject.clone(),
            from,
            to,
            approved_by: approved_by.to_string(),
        }))
    }

    // ── 31403 ActionResponse projection (COM-16 / F3) ───────────────────────

    /// The orchestrator-load-bearing fields of a persisted broker case.
    ///
    /// The relay stores a case as a flat `broker_cases` row; this is the subset
    /// the [`DecisionOrchestrator`] reads when applying the next decision
    /// (category and share-states drive the share plan; `state` gates the
    /// terminal check; `created_by` gates self-review; `latest_decision_id`
    /// links the provenance chain). The cosmetic fields (title/summary/priority)
    /// are irrelevant to the transition and are not carried here.
    #[derive(Debug, Clone)]
    pub struct CaseSnapshot {
        pub id: String,
        pub category: CaseCategory,
        pub created_by: String,
        pub state: CaseState,
        pub from_state: Option<ShareState>,
        pub to_state: Option<ShareState>,
        pub latest_decision_id: Option<String>,
    }

    impl CaseSnapshot {
        /// Rebuild a [`BrokerCase`] aggregate from its flat D1 projection so a
        /// caller (the relay worker's 31403 projection) can apply the next
        /// decision through [`DecisionOrchestrator::decide`].
        ///
        /// Only the orchestrator-read fields are load-bearing; the cosmetic
        /// fields are defaulted. The latest decision id is seeded as a single
        /// history entry so a follow-on decision links its predecessor — only
        /// that entry's `decision_id` matters for the provenance chain.
        pub fn hydrate(&self, now: u64) -> BrokerCase {
            let mut case = BrokerCase::new(
                self.id.clone(),
                self.category.clone(),
                SubjectRef {
                    kind: SubjectKind::Opaque,
                    id: String::new(),
                    from_state: self.from_state,
                    to_state: self.to_state,
                },
                String::new(),
                String::new(),
                self.created_by.clone(),
                50,
                now,
            );
            case.state = self.state;
            if let Some(prior) = &self.latest_decision_id {
                case.history.push(DecisionHistoryEntry {
                    decision_id: prior.clone(),
                    outcome: DecisionOutcome::Approve,
                    broker_pubkey: String::new(),
                    decided_at: 0,
                    prior_decision_id: None,
                    reasoning: String::new(),
                });
            }
            case
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::broker::*;
    use super::*;

    #[test]
    fn governance_kind_range() {
        assert!(is_governance_kind(31400));
        assert!(is_governance_kind(31405));
        assert!(!is_governance_kind(31399));
        assert!(!is_governance_kind(31406));
    }

    // ---- P2: governance event authz / append-only audit log ----

    fn gov_event(kind: u64, d: &str) -> NostrEvent {
        NostrEvent {
            id: "00".repeat(32),
            pubkey: "11".repeat(32),
            created_at: 1_700_000_000,
            kind,
            tags: vec![vec!["d".to_string(), d.to_string()]],
            content: String::new(),
            sig: String::new(),
        }
    }

    #[test]
    fn governance_validator_rejects_out_of_range_kind() {
        let ev = gov_event(31399, "x");
        assert_eq!(
            validate_governance_event(&ev, &HashSet::new()),
            Err(GovernanceEventError::UnknownKind(31399)),
        );
        let ev2 = gov_event(31406, "x");
        assert_eq!(
            validate_governance_event(&ev2, &HashSet::new()),
            Err(GovernanceEventError::UnknownKind(31406)),
        );
    }

    #[test]
    fn governance_validator_accepts_in_range_kind() {
        let ev = gov_event(KIND_PANEL_DEFINITION, "panel-1");
        assert!(validate_governance_event(&ev, &HashSet::new()).is_ok());
    }

    #[test]
    fn governance_validator_requires_non_empty_d_tag() {
        let mut ev = gov_event(KIND_PANEL_STATE, "x");
        ev.tags.clear();
        assert_eq!(
            validate_governance_event(&ev, &HashSet::new()),
            Err(GovernanceEventError::MissingDTag),
        );
        let ev_empty = gov_event(KIND_PANEL_STATE, "");
        assert_eq!(
            validate_governance_event(&ev_empty, &HashSet::new()),
            Err(GovernanceEventError::EmptyDTag),
        );
    }

    #[test]
    fn audit_log_duplicate_d_tag_rejected() {
        // First audit entry with a fresh id validates.
        let ev = gov_event(KIND_GOVERNANCE_AUDIT_LOG, "audit-entry-1");
        let mut seen: HashSet<String> = HashSet::new();
        assert!(validate_governance_event(&ev, &seen).is_ok());

        // Caller records the accepted entry id, making it append-only.
        seen.insert("audit-entry-1".to_string());

        // A replay/overwrite with the SAME `d` is rejected as a duplicate.
        let replay = gov_event(KIND_GOVERNANCE_AUDIT_LOG, "audit-entry-1");
        assert_eq!(
            validate_governance_event(&replay, &seen),
            Err(GovernanceEventError::DuplicateAuditEntry(
                "audit-entry-1".to_string()
            )),
        );

        // A distinct audit-entry id is still accepted (append-only, not frozen).
        let next = gov_event(KIND_GOVERNANCE_AUDIT_LOG, "audit-entry-2");
        assert!(validate_governance_event(&next, &seen).is_ok());
    }

    #[test]
    fn non_audit_kind_ignores_seen_set() {
        // Replaceable non-audit kinds may legitimately reuse a `d` tag; the
        // duplicate check only applies to the 31405 audit log.
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert("panel-1".to_string());
        let ev = gov_event(KIND_PANEL_DEFINITION, "panel-1");
        assert!(validate_governance_event(&ev, &seen).is_ok());
    }

    #[test]
    fn extract_d_tag_from_tags() {
        let tags = vec![
            vec!["e".into(), "abc".into()],
            vec!["d".into(), "my-panel".into()],
            vec!["p".into(), "deadbeef".into()],
        ];
        assert_eq!(extract_d_tag(&tags), Some("my-panel"));
    }

    #[test]
    fn panel_definition_roundtrip() {
        let panel = PanelDefinition {
            title: "Test Panel".into(),
            description: "A test".into(),
            version: "1.0.0".into(),
            schema: PanelSchema::ActionInbox,
            fields: vec![FieldDef {
                name: "entity".into(),
                field_type: FieldType::String,
                label: "Entity URN".into(),
            }],
            actions: vec![ActionDef {
                id: "approve".into(),
                label: "Approve".into(),
                style: ActionStyle::Primary,
            }],
            layout: LayoutHint::InboxTable,
            capabilities: vec![PanelCapability::BulkAction, PanelCapability::Filter],
            refresh_secs: 30,
        };
        let json = serde_json::to_string(&panel).unwrap();
        let parsed: PanelDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.title, "Test Panel");
        assert_eq!(parsed.schema, PanelSchema::ActionInbox);
        assert_eq!(parsed.actions.len(), 1);
        assert_eq!(parsed.capabilities.len(), 2);
    }

    #[test]
    fn new_case_is_open() {
        let c = BrokerCase::new(
            "case-1",
            CaseCategory::ManualSubmission,
            SubjectRef {
                kind: SubjectKind::Opaque,
                id: "sub-1".into(),
                from_state: None,
                to_state: None,
            },
            "Test case",
            "Summary",
            "alice",
            50,
            1000,
        );
        assert_eq!(c.state, CaseState::Open);
        assert!(c.history.is_empty());
    }

    #[test]
    fn self_review_rejected_on_claim() {
        let mut c = BrokerCase::new(
            "case-1",
            CaseCategory::ManualSubmission,
            SubjectRef {
                kind: SubjectKind::Opaque,
                id: "sub-1".into(),
                from_state: None,
                to_state: None,
            },
            "Test",
            "Summary",
            "alice",
            50,
            1000,
        );
        let err = c.claim("alice", 1001).unwrap_err();
        assert!(matches!(err, CaseError::SelfReview { .. }));
    }

    #[test]
    fn self_review_rejected_on_decide() {
        let mut c = BrokerCase::new(
            "case-1",
            CaseCategory::ManualSubmission,
            SubjectRef {
                kind: SubjectKind::Opaque,
                id: "sub-1".into(),
                from_state: None,
                to_state: None,
            },
            "Test",
            "Summary",
            "alice",
            50,
            1000,
        );
        c.state = CaseState::UnderReview;
        c.assigned_to = Some("alice".into());
        let err = c
            .record_decision("dec-1", DecisionOutcome::Approve, "alice", "ok", 1002)
            .unwrap_err();
        assert!(matches!(err, CaseError::SelfReview { .. }));
    }

    #[test]
    fn approval_flow() {
        let mut c = BrokerCase::new(
            "case-1",
            CaseCategory::ManualSubmission,
            SubjectRef {
                kind: SubjectKind::Opaque,
                id: "sub-1".into(),
                from_state: None,
                to_state: None,
            },
            "Test",
            "Summary",
            "alice",
            50,
            1000,
        );
        c.claim("bob", 1001).unwrap();
        assert_eq!(c.state, CaseState::UnderReview);

        let entry = c
            .record_decision("dec-1", DecisionOutcome::Approve, "bob", "looks good", 1002)
            .unwrap()
            .clone();
        assert_eq!(entry.decision_id, "dec-1");
        assert_eq!(c.state, CaseState::Decided);
        assert_eq!(c.history.len(), 1);
        assert_eq!(c.latest_decision_id(), Some("dec-1"));
    }

    #[test]
    fn terminal_state_rejects_further_decisions() {
        let mut c = BrokerCase::new(
            "case-1",
            CaseCategory::ManualSubmission,
            SubjectRef {
                kind: SubjectKind::Opaque,
                id: "sub-1".into(),
                from_state: None,
                to_state: None,
            },
            "Test",
            "Summary",
            "alice",
            50,
            1000,
        );
        c.claim("bob", 1001).unwrap();
        c.record_decision("dec-1", DecisionOutcome::Approve, "bob", "ok", 1002)
            .unwrap();
        let err = c
            .record_decision(
                "dec-2",
                DecisionOutcome::Reject,
                "bob",
                "changed mind",
                1003,
            )
            .unwrap_err();
        assert!(matches!(err, CaseError::AlreadyTerminal(_)));
    }

    #[test]
    fn amend_requires_diff() {
        let mut c = BrokerCase::new(
            "case-1",
            CaseCategory::ManualSubmission,
            SubjectRef {
                kind: SubjectKind::Opaque,
                id: "sub-1".into(),
                from_state: None,
                to_state: None,
            },
            "Test",
            "Summary",
            "alice",
            50,
            1000,
        );
        c.claim("bob", 1001).unwrap();
        let err = c
            .record_decision(
                "dec-1",
                DecisionOutcome::Amend { diff: "   ".into() },
                "bob",
                "fix",
                1002,
            )
            .unwrap_err();
        assert_eq!(err, CaseError::MissingAmendmentDiff);
    }

    #[test]
    fn delegate_requires_target() {
        let mut c = BrokerCase::new(
            "case-1",
            CaseCategory::ManualSubmission,
            SubjectRef {
                kind: SubjectKind::Opaque,
                id: "sub-1".into(),
                from_state: None,
                to_state: None,
            },
            "Test",
            "Summary",
            "alice",
            50,
            1000,
        );
        c.claim("bob", 1001).unwrap();
        let err = c
            .record_decision(
                "dec-1",
                DecisionOutcome::Delegate {
                    delegate_to: "".into(),
                },
                "bob",
                "reassign",
                1002,
            )
            .unwrap_err();
        assert_eq!(err, CaseError::MissingDelegateTarget);
    }

    #[test]
    fn share_state_monotonic() {
        assert!(ShareState::Private.can_advance_to(ShareState::Team));
        assert!(ShareState::Team.can_advance_to(ShareState::Mesh));
        assert!(ShareState::Private.can_advance_to(ShareState::Mesh));
        assert!(!ShareState::Team.can_advance_to(ShareState::Private));
        assert!(!ShareState::Mesh.can_advance_to(ShareState::Team));
    }

    #[test]
    fn orchestrator_approve_with_share_plan() {
        let mut c = BrokerCase::new(
            "case-1",
            CaseCategory::ContributorMeshShare,
            SubjectRef {
                kind: SubjectKind::WorkArtifact,
                id: "art-1".into(),
                from_state: Some(ShareState::Private),
                to_state: Some(ShareState::Team),
            },
            "Promote artifact",
            "Move to team pod",
            "alice",
            50,
            1000,
        );
        c.claim("bob", 1001).unwrap();

        let orch = DecisionOrchestrator;
        let report = orch
            .decide(&mut c, "dec-1", DecisionOutcome::Approve, "bob", "ok", 1002)
            .unwrap();

        let plan = report.share_plan.expect("plan required");
        assert_eq!(plan.from, ShareState::Private);
        assert_eq!(plan.to, ShareState::Team);
        assert_eq!(plan.approved_by, "bob");
    }

    #[test]
    fn orchestrator_reject_no_share_plan() {
        let mut c = BrokerCase::new(
            "case-1",
            CaseCategory::ContributorMeshShare,
            SubjectRef {
                kind: SubjectKind::WorkArtifact,
                id: "art-1".into(),
                from_state: Some(ShareState::Private),
                to_state: Some(ShareState::Team),
            },
            "Promote artifact",
            "Move to team pod",
            "alice",
            50,
            1000,
        );
        c.claim("bob", 1001).unwrap();

        let orch = DecisionOrchestrator;
        let report = orch
            .decide(
                &mut c,
                "dec-1",
                DecisionOutcome::Reject,
                "bob",
                "nope",
                1002,
            )
            .unwrap();
        assert!(report.share_plan.is_none());
    }

    #[test]
    fn invalid_share_transition_rejected() {
        let mut c = BrokerCase::new(
            "case-1",
            CaseCategory::ContributorMeshShare,
            SubjectRef {
                kind: SubjectKind::WorkArtifact,
                id: "art-1".into(),
                from_state: Some(ShareState::Mesh),
                to_state: Some(ShareState::Private),
            },
            "Demote artifact",
            "Backward transition",
            "alice",
            50,
            1000,
        );
        c.claim("bob", 1001).unwrap();

        let orch = DecisionOrchestrator;
        let err = orch
            .decide(&mut c, "dec-1", DecisionOutcome::Approve, "bob", "ok", 1002)
            .unwrap_err();
        assert!(matches!(
            err,
            OrchestrationError::ShareTransitionRejected(_)
        ));
    }

    #[test]
    fn delegate_transitions_state() {
        let mut c = BrokerCase::new(
            "case-1",
            CaseCategory::ManualSubmission,
            SubjectRef {
                kind: SubjectKind::Opaque,
                id: "sub-1".into(),
                from_state: None,
                to_state: None,
            },
            "Test",
            "Summary",
            "alice",
            50,
            1000,
        );
        c.claim("bob", 1001).unwrap();
        c.record_decision(
            "dec-1",
            DecisionOutcome::Delegate {
                delegate_to: "carol".into(),
            },
            "bob",
            "reassign",
            1002,
        )
        .unwrap();
        assert_eq!(c.state, CaseState::Delegated);
    }

    #[test]
    fn provenance_chain_links() {
        let mut c = BrokerCase::new(
            "case-1",
            CaseCategory::ManualSubmission,
            SubjectRef {
                kind: SubjectKind::Opaque,
                id: "sub-1".into(),
                from_state: None,
                to_state: None,
            },
            "Test",
            "Summary",
            "alice",
            50,
            1000,
        );
        c.claim("bob", 1001).unwrap();
        c.record_decision(
            "dec-1",
            DecisionOutcome::Delegate {
                delegate_to: "carol".into(),
            },
            "bob",
            "handoff",
            1002,
        )
        .unwrap();
        // Simulate re-opening after delegation
        c.state = CaseState::UnderReview;
        c.assigned_to = Some("carol".into());
        c.record_decision("dec-2", DecisionOutcome::Approve, "carol", "ok", 1003)
            .unwrap();
        assert_eq!(c.history[1].prior_decision_id.as_deref(), Some("dec-1"));
    }

    #[test]
    fn action_response_roundtrip() {
        let resp = ActionResponse {
            action: "approve".into(),
            reasoning: "Looks correct".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: ActionResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.action, "approve");
    }

    #[test]
    fn all_six_outcomes_stable_action_str() {
        assert_eq!(DecisionOutcome::Approve.action_str(), "approve");
        assert_eq!(DecisionOutcome::Reject.action_str(), "reject");
        assert_eq!(
            DecisionOutcome::Amend { diff: "x".into() }.action_str(),
            "amend"
        );
        assert_eq!(
            DecisionOutcome::Delegate {
                delegate_to: "x".into()
            }
            .action_str(),
            "delegate"
        );
        assert_eq!(
            DecisionOutcome::Promote {
                pattern_id: "x".into()
            }
            .action_str(),
            "promote"
        );
        assert_eq!(
            DecisionOutcome::Precedent { scope: "x".into() }.action_str(),
            "precedent"
        );
    }

    // ---- COM-17 / F5: risk tier + confidence on the ActionRequest ----

    #[test]
    fn action_request_carries_risk_tier_and_confidence() {
        let raw = r#"{"fields":{},"reasoning":"please review","context_url":null,
                      "risk_tier":"high","confidence":0.82}"#;
        let req: ActionRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.risk_tier, Some(RiskTier::High));
        assert_eq!(req.confidence, Some(0.82));
    }

    #[test]
    fn legacy_action_request_defaults_tier_and_confidence_to_none() {
        // A pre-slice 31402 carries neither field; #[serde(default)] admits it.
        let raw = r#"{"fields":{},"reasoning":"x","context_url":null}"#;
        let req: ActionRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.risk_tier, None);
        assert_eq!(req.confidence, None);
    }

    // ---- COM-16 / F7: risk-tier member suppression (view filter) ----

    #[test]
    fn only_low_risk_is_member_suppressed() {
        assert!(RiskTier::Low.is_member_suppressed());
        assert!(!RiskTier::Medium.is_member_suppressed());
        assert!(!RiskTier::High.is_member_suppressed());
        assert!(!RiskTier::Critical.is_member_suppressed());
    }

    #[test]
    fn risk_tier_parse_fails_open_to_medium() {
        assert_eq!(RiskTier::parse("low"), RiskTier::Low);
        assert_eq!(RiskTier::parse("critical"), RiskTier::Critical);
        // Unknown / unlabelled → Medium (shown), never silently suppressed.
        assert_eq!(RiskTier::parse("weird"), RiskTier::Medium);
        assert!(!RiskTier::parse("weird").is_member_suppressed());
    }

    // ---- COM-16 / F3: 31403 → DecisionOutcome parsing ----

    #[test]
    fn binary_response_parses_ignoring_reasoning() {
        let approve =
            DecisionOutcome::from_response_content(r#"{"action":"approve","reasoning":"ok"}"#);
        assert_eq!(approve, Some(DecisionOutcome::Approve));
        let reject =
            DecisionOutcome::from_response_content(r#"{"action":"reject","reasoning":"no"}"#);
        assert_eq!(reject, Some(DecisionOutcome::Reject));
    }

    #[test]
    fn non_binary_responses_parse_with_typed_detail() {
        let del = DecisionOutcome::from_response_content(
            r#"{"action":"delegate","delegate_to":"carol","reasoning":"handoff"}"#,
        )
        .unwrap();
        assert_eq!(del.detail(), Some("carol"));
        let prom = DecisionOutcome::from_response_content(
            r#"{"action":"promote","pattern_id":"pat-9"}"#,
        )
        .unwrap();
        assert_eq!(prom.detail(), Some("pat-9"));
        let prec = DecisionOutcome::from_response_content(
            r#"{"action":"precedent","scope":"org-wide"}"#,
        )
        .unwrap();
        assert_eq!(prec.detail(), Some("org-wide"));
    }

    #[test]
    fn unknown_or_detail_missing_response_is_rejected_not_parked() {
        // Unknown action → None (caller persists nothing; case is not parked).
        assert_eq!(
            DecisionOutcome::from_response_content(r#"{"action":"escalate"}"#),
            None
        );
        // delegate without its required target → None (record_decision would
        // have rejected MissingDelegateTarget anyway).
        assert_eq!(
            DecisionOutcome::from_response_content(r#"{"action":"delegate"}"#),
            None
        );
    }

    // ---- COM-16 / F3: hydrate a case + decide through the orchestrator ----
    //
    // This mirrors, at the domain floor, exactly what the relay worker's 31403
    // projection does: hydrate a `BrokerCase` from its `CaseSnapshot` and route
    // the parsed outcome through `DecisionOrchestrator::decide`. The worker crate
    // holds the equivalent end-to-end assertion against `plan_action_response`.

    fn snapshot(state: CaseState) -> CaseSnapshot {
        CaseSnapshot {
            id: "case-1".into(),
            category: CaseCategory::ManualSubmission,
            created_by: "agent-alice".into(),
            state,
            from_state: None,
            to_state: None,
            latest_decision_id: None,
        }
    }

    /// Domain-floor helper: hydrate + decide, returning the persistable shape.
    #[allow(clippy::type_complexity)]
    fn decide(
        snap: &CaseSnapshot,
        event_id: &str,
        content: &str,
        responder: &str,
        now: u64,
    ) -> Result<(String, Option<String>, CaseState, Option<String>), OrchestrationError> {
        let outcome = DecisionOutcome::from_response_content(content).ok_or_else(|| {
            OrchestrationError::ShareTransitionRejected("malformed response".into())
        })?;
        let decision_id = format!("dec-{}", &event_id[..16.min(event_id.len())]);
        let mut case = snap.hydrate(now);
        let orch = DecisionOrchestrator;
        let report = orch.decide(
            &mut case,
            decision_id,
            outcome.clone(),
            responder,
            "",
            now,
        )?;
        Ok((
            outcome.action_str().to_string(),
            outcome.detail().map(str::to_string),
            case.state,
            report.entry.prior_decision_id.clone(),
        ))
    }

    #[test]
    fn hydrate_decide_delegate_moves_case_to_delegated() {
        let (action, detail, state, _prior) = decide(
            &snapshot(CaseState::Open),
            &"e".repeat(64),
            r#"{"action":"delegate","delegate_to":"carol","reasoning":"reassign"}"#,
            "human-bob",
            2000,
        )
        .unwrap();
        assert_eq!(action, "delegate");
        assert_eq!(detail.as_deref(), Some("carol"));
        assert_eq!(state, CaseState::Delegated);
        // The falsification target: a non-binary action never parks in review.
        assert_ne!(state, CaseState::UnderReview);
    }

    #[test]
    fn hydrate_decide_promote_and_precedent_reach_matching_states() {
        let (_, detail, state, _) = decide(
            &snapshot(CaseState::Open),
            &"a".repeat(64),
            r#"{"action":"promote","pattern_id":"pat-9"}"#,
            "human-bob",
            2000,
        )
        .unwrap();
        assert_eq!(state, CaseState::Promoted);
        assert_eq!(detail.as_deref(), Some("pat-9"));

        let (_, detail, state, _) = decide(
            &snapshot(CaseState::Open),
            &"b".repeat(64),
            r#"{"action":"precedent","scope":"org-wide"}"#,
            "human-bob",
            2000,
        )
        .unwrap();
        assert_eq!(state, CaseState::Precedent);
        assert_eq!(detail.as_deref(), Some("org-wide"));
    }

    #[test]
    fn hydrate_decide_binary_outcomes_reach_decided() {
        for (content, expect) in [
            (r#"{"action":"approve","reasoning":"ok"}"#, "approve"),
            (r#"{"action":"reject","reasoning":"no"}"#, "reject"),
        ] {
            let (action, detail, state, _) =
                decide(&snapshot(CaseState::Open), &"c".repeat(64), content, "human-bob", 2000)
                    .unwrap();
            assert_eq!(action, expect);
            assert_eq!(state, CaseState::Decided);
            assert_eq!(detail, None);
        }
    }

    #[test]
    fn hydrate_decide_links_prior_decision_id() {
        let mut snap = snapshot(CaseState::Open);
        snap.latest_decision_id = Some("dec-earlier".into());
        let (_, _, _, prior) = decide(
            &snap,
            &"d".repeat(64),
            r#"{"action":"approve","reasoning":"ok"}"#,
            "human-bob",
            2000,
        )
        .unwrap();
        assert_eq!(prior.as_deref(), Some("dec-earlier"));
    }

    #[test]
    fn hydrate_decide_rejects_terminal_case() {
        // A second response on an already-decided case is rejected — the state
        // machine's terminal guard holds through the hydrate/decide path.
        let err = decide(
            &snapshot(CaseState::Decided),
            &"f".repeat(64),
            r#"{"action":"approve","reasoning":"again"}"#,
            "human-bob",
            2000,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            OrchestrationError::Case(CaseError::AlreadyTerminal(_))
        ));
    }

    #[test]
    fn hydrate_decide_rejects_malformed_response() {
        let err = decide(
            &snapshot(CaseState::Open),
            &"0".repeat(64),
            r#"{"action":"escalate"}"#,
            "human-bob",
            2000,
        )
        .unwrap_err();
        assert!(matches!(err, OrchestrationError::ShareTransitionRejected(_)));
    }

    #[test]
    fn case_state_str_roundtrips_the_canonical_variants() {
        for st in [
            CaseState::Open,
            CaseState::UnderReview,
            CaseState::Decided,
            CaseState::Delegated,
            CaseState::Promoted,
            CaseState::Precedent,
            CaseState::Closed,
        ] {
            assert_eq!(CaseState::parse(st.as_str()), st);
        }
        // Legacy projection strings map onto the domain's terminal decided state.
        assert_eq!(CaseState::parse("resolved"), CaseState::Decided);
        assert_eq!(CaseState::parse("rejected"), CaseState::Decided);
    }
}
