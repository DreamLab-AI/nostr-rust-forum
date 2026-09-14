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
    /// Operator-declared task-property triple for every action this panel
    /// raises (ADR-2011). Absent on legacy panels, which constrain nothing.
    #[serde(default)]
    pub task_properties: Option<TaskProperties>,
    /// Share of otherwise-suppressible requests shown anyway (FR6.3). `None`
    /// means [`DEFAULT_CALIBRATION_SAMPLE_RATE`].
    #[serde(default)]
    pub calibration_sample_rate: Option<f32>,
    /// Age in hours past which a pending case is escalated (FR4.3). `None`
    /// means [`DEFAULT_MAX_PENDING_HOURS`].
    #[serde(default)]
    pub max_pending_hours: Option<u32>,
    /// The one agent pubkey whose `probe`-tagged requests count as probes
    /// (FR6.4). `None` means this panel honours no probes.
    #[serde(default)]
    pub probe_agent: Option<String>,
}

impl PanelDefinition {
    /// The panel's effective calibration/ageing/probe policy, with each field
    /// falling back to its documented default independently.
    pub fn policy(&self) -> PanelPolicy {
        PanelPolicy {
            calibration_sample_rate: self
                .calibration_sample_rate
                .filter(|r| r.is_finite())
                .map(|r| r.clamp(0.0, 1.0))
                .unwrap_or(DEFAULT_CALIBRATION_SAMPLE_RATE),
            max_pending_hours: self
                .max_pending_hours
                .filter(|h| *h > 0)
                .unwrap_or(DEFAULT_MAX_PENDING_HOURS),
            probe_agent: self.probe_agent.clone(),
        }
    }
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
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    /// Default tier: an unlabelled or unrecognised request is shown to members
    /// (fail-open on visibility).
    #[default]
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


// ── Task properties: the operator-declared human–agent boundary (ADR-2011) ──

/// How far an outcome can be checked after the fact.
///
/// The first leg of the task-property triple (arXiv 2609.12482, ADR-2011).
/// Ordering is *tightness*: `Inspectable` is the loosest, `Opaque` the
/// tightest. A request may move a property up this ordering and never down.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Verifiability {
    /// The result can be read back and checked directly.
    #[default]
    Inspectable,
    /// Some of the result is checkable; some is not.
    Partial,
    /// Nothing about the result can be checked from outside.
    Opaque,
}

/// Whether the act can be undone.
///
/// Second leg of the triple. Tightness order: `Reversible` < `Compensable` <
/// `Irreversible`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    /// The act can be undone, restoring the prior state exactly.
    #[default]
    Reversible,
    /// The act cannot be undone but its harm can be paid back or repaired.
    Compensable,
    /// Once done, done.
    Irreversible,
}

/// What is at risk if the act is wrong.
///
/// Third leg of the triple. Tightness order: `Bounded` < `Significant` <
/// `Critical`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Stakes {
    /// A loss the operator has already accepted as a cost of doing business.
    #[default]
    Bounded,
    /// A loss that would need explaining.
    Significant,
    /// A loss the operator cannot absorb.
    Critical,
}

impl Verifiability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inspectable => "inspectable",
            Self::Partial => "partial",
            Self::Opaque => "opaque",
        }
    }
    /// Parse a tag value. An unrecognised value falls back to the **loosest**
    /// variant, because an unrecognised string must never silently *lower* a
    /// panel's declared property through the tightening-only merge: it is the
    /// merge that raises, and a loose fallback simply defers to the other side.
    pub fn parse(s: &str) -> Self {
        match s {
            "partial" => Self::Partial,
            "opaque" => Self::Opaque,
            _ => Self::Inspectable,
        }
    }
}

impl Reversibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reversible => "reversible",
            Self::Compensable => "compensable",
            Self::Irreversible => "irreversible",
        }
    }
    /// See [`Verifiability::parse`] for why an unknown value is the loosest.
    pub fn parse(s: &str) -> Self {
        match s {
            "compensable" => Self::Compensable,
            "irreversible" => Self::Irreversible,
            _ => Self::Reversible,
        }
    }
}

impl Stakes {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bounded => "bounded",
            Self::Significant => "significant",
            Self::Critical => "critical",
        }
    }
    /// See [`Verifiability::parse`] for why an unknown value is the loosest.
    pub fn parse(s: &str) -> Self {
        match s {
            "significant" => Self::Significant,
            "critical" => Self::Critical,
            _ => Self::Bounded,
        }
    }
}

/// Tag name carrying [`Verifiability`] on a 31400 panel or 31402 request.
pub const TAG_TP_VERIFIABILITY: &str = "tp-verifiability";
/// Tag name carrying [`Reversibility`].
pub const TAG_TP_REVERSIBILITY: &str = "tp-reversibility";
/// Tag name carrying [`Stakes`].
pub const TAG_TP_STAKES: &str = "tp-stakes";
/// Tag name carrying the panel's calibration sample rate (31400).
pub const TAG_CALIBRATION_SAMPLE_RATE: &str = "calibration-sample-rate";
/// Tag name carrying the panel's pending-case deadline in hours (31400).
pub const TAG_MAX_PENDING_HOURS: &str = "max-pending-hours";
/// Tag name carrying the panel's registered probe-agent pubkey (31400).
pub const TAG_PROBE_AGENT: &str = "probe-agent";
/// Tag name carrying a seeded probe's digest on a 31402 request.
///
/// Invariant 7 (DDD §6) asks that this tag never be rendered before the case is
/// decided. **What the relay actually enforces is narrower than that, and this
/// comment says so rather than restating the aspiration as fact:**
///
/// - the tag is deleted from the `event_tags` index, so no client can find a
///   probe by subscribing to `#probe`;
/// - `broker_cases.probe_digest` is withheld from every REST projection of an
///   undecided case;
/// - a `probe` tag from any pubkey other than the panel's registered probe
///   agent is discarded rather than recorded, so it cannot corrupt the catch
///   rate.
///
/// The tag nevertheless **remains on the raw signed 31402** served over REQ.
/// Removing it would invalidate the signature that the forum and BBS clients
/// both verify strictly (`verify_event_strict`), so the probe would disappear
/// from the queue rather than render blind — the opposite of what the feature
/// needs. Blindness on the rendered surface is therefore the client's
/// responsibility, and the catch rate assumes reviewers read that surface
/// rather than raw relay events. Closing this properly means keeping the digest
/// off the signed event altogether; that is ADR-2011's `review_trigger`.
pub const TAG_PROBE: &str = "probe";

/// Default share of `Low`/`Reversible` requests shown rather than suppressed,
/// so reviewers keep exposure to routine agent output (C5/C6, FR6.3).
pub const DEFAULT_CALIBRATION_SAMPLE_RATE: f32 = 0.1;

/// Default age at which a still-pending case is escalated (FR4.3).
pub const DEFAULT_MAX_PENDING_HOURS: u32 = 72;

/// The governance role that may decide a case only when an admin has delegated
/// that specific case to it (FR6.2, DDD §6 invariant 6).
pub const ROLE_REVIEWER: &str = "reviewer";

/// The operator-declared properties of the *task*, which set the human–agent
/// boundary (ADR-2011).
///
/// Declared on a [`PanelDefinition`] (31400) by the operator who publishes the
/// panel, and optionally restated on an [`ActionRequest`] (31402) by the
/// requesting agent — where it may only **tighten**, never loosen, the panel's
/// declaration. This is the whole point: the party with the strongest incentive
/// to under-tier its own work cannot lower the boundary.
///
/// `Default` is the loosest triple, which is the correct reading of *absence*:
/// a panel that declared nothing constrains nothing, and the request's own
/// declaration (or the relay's advertised default) decides.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskProperties {
    #[serde(default)]
    pub verifiability: Verifiability,
    #[serde(default)]
    pub reversibility: Reversibility,
    #[serde(default)]
    pub stakes: Stakes,
}

impl TaskProperties {
    pub fn new(verifiability: Verifiability, reversibility: Reversibility, stakes: Stakes) -> Self {
        Self {
            verifiability,
            reversibility,
            stakes,
        }
    }

    /// Read the triple from an event's tags.
    ///
    /// Returns `None` when **no** `tp-*` tag is present — the honest reading of
    /// a legacy event that declared nothing, distinct from one that declared
    /// the loosest triple. When at least one leg is present the missing legs
    /// take their loosest value, which is safe under [`Self::merge`]: a loose
    /// leg can only ever defer to the other side, never lower it.
    pub fn from_tags(tags: &[Vec<String>]) -> Option<Self> {
        let v = extract_tag(tags, TAG_TP_VERIFIABILITY);
        let r = extract_tag(tags, TAG_TP_REVERSIBILITY);
        let s = extract_tag(tags, TAG_TP_STAKES);
        if v.is_none() && r.is_none() && s.is_none() {
            return None;
        }
        Some(Self {
            verifiability: v.map(Verifiability::parse).unwrap_or_default(),
            reversibility: r.map(Reversibility::parse).unwrap_or_default(),
            stakes: s.map(Stakes::parse).unwrap_or_default(),
        })
    }

    /// The three tags a publisher stamps on a 31400/31402 to declare this triple.
    pub fn to_tags(self) -> Vec<Vec<String>> {
        vec![
            vec![
                TAG_TP_VERIFIABILITY.to_string(),
                self.verifiability.as_str().to_string(),
            ],
            vec![
                TAG_TP_REVERSIBILITY.to_string(),
                self.reversibility.as_str().to_string(),
            ],
            vec![TAG_TP_STAKES.to_string(), self.stakes.as_str().to_string()],
        ]
    }

    /// Combine the panel's declaration with the request's, taking the **tighter**
    /// value on every leg independently.
    ///
    /// DDD §6 invariant 2 ("tightening only"): the result is never looser than
    /// `panel` on any leg, whatever the request claims. A request declaring
    /// `Reversible` against a panel declaring `Irreversible` does not lower the
    /// boundary — it is simply ignored on that leg.
    pub fn merge(panel: TaskProperties, request: TaskProperties) -> TaskProperties {
        TaskProperties {
            verifiability: panel.verifiability.max(request.verifiability),
            reversibility: panel.reversibility.max(request.reversibility),
            stakes: panel.stakes.max(request.stakes),
        }
    }

    /// Merge where either side may be absent. `None` on both sides means
    /// nothing was declared anywhere, which stays `None` rather than collapsing
    /// to the loosest triple — the caller needs that distinction to decide
    /// whether to fall back to the relay's advertised default.
    pub fn merge_opt(
        panel: Option<&TaskProperties>,
        request: Option<&TaskProperties>,
    ) -> Option<TaskProperties> {
        match (panel, request) {
            (None, None) => None,
            (Some(p), None) => Some(*p),
            (None, Some(r)) => Some(*r),
            (Some(p), Some(r)) => Some(Self::merge(*p, *r)),
        }
    }

    /// The lowest [`RiskTier`] this triple permits (ADR-2011 §2).
    ///
    /// `Irreversible` reversibility or `Critical` stakes floors the case at
    /// `High`; `Opaque` verifiability floors it at `Medium`. Anything else
    /// imposes no floor of its own (`Low`) and defers to the declared tier and
    /// the relay's advertised default.
    pub fn tier_floor(self) -> RiskTier {
        if self.reversibility == Reversibility::Irreversible || self.stakes == Stakes::Critical {
            RiskTier::High
        } else if self.verifiability == Verifiability::Opaque {
            RiskTier::Medium
        } else {
            RiskTier::Low
        }
    }

    /// Whether this triple forbids member-surface suppression outright.
    ///
    /// `Opaque` work is the case the paper singles out: nobody downstream can
    /// check it, so it is never hidden from the people who could.
    pub fn forbids_suppression(self) -> bool {
        self.verifiability == Verifiability::Opaque
            || self.reversibility == Reversibility::Irreversible
            || self.stakes == Stakes::Critical
    }
}

/// The tier that actually governs a case (ADR-2011 §2) — the only tier stored,
/// rendered, or used for suppression.
///
/// - `panel_props` — the operator's declaration on the 31400.
/// - `request_props` — the agent's optional restatement on the 31402; merged
///   tightening-only.
/// - `declared` — the agent's own `risk_tier`. Telemetry from here on: it can
///   raise the effective tier but never lower it below the properties' floor.
/// - `advertised_default` — the relay's `ESCALATION_DEFAULT_TIER`, as advertised
///   in NIP-11. An entirely unlabelled request folds to exactly this.
///
/// Total and pure: every combination of inputs yields a tier, and the same
/// inputs always yield the same tier.
pub fn effective_tier(
    panel_props: Option<&TaskProperties>,
    request_props: Option<&TaskProperties>,
    declared: Option<RiskTier>,
    advertised_default: RiskTier,
) -> RiskTier {
    let merged = TaskProperties::merge_opt(panel_props, request_props);
    match (declared, merged) {
        // Nothing declared anywhere: the relay's advertised posture applies,
        // rather than the accidental `Medium` of an absent tag (ADR-2011 §3).
        (None, None) => advertised_default,
        // A tier but no properties: the agent's declaration stands on its own.
        (Some(d), None) => d,
        // Properties but no tier: the floor, but never below what the relay
        // advertises it escalates at.
        (None, Some(p)) => advertised_default.max(p.tier_floor()),
        // Both: the tighter of the two.
        (Some(d), Some(p)) => d.max(p.tier_floor()),
    }
}

/// Whether the member surface may suppress this case (FR3.2, DDD §6).
///
/// Suppression is a view filter over the *effective* tier, with two overrides
/// that the tier alone cannot express: a triple that forbids suppression
/// outright, and a calibration sample, which exists precisely to be seen.
pub fn is_member_suppressed_effective(
    props: Option<&TaskProperties>,
    effective: RiskTier,
    calibration_sample: bool,
) -> bool {
    if calibration_sample {
        return false;
    }
    if props.map(|p| p.forbids_suppression()).unwrap_or(false) {
        return false;
    }
    effective.is_member_suppressed()
}

/// Whether a request is a deterministically-selected calibration sample
/// (FR6.3, DDD §3).
///
/// The first 8 bytes of `sha256(request_id)` read as a big-endian `u64`,
/// divided by `u64::MAX`, compared against `rate`. Deterministic by
/// construction: the same request id always gives the same answer on every
/// node, and nothing about the wall clock enters — the counter-example
/// EXP-AC-006 names explicitly.
///
/// A rate at or below zero samples nothing; a rate at or above one samples
/// everything.
pub fn is_calibration_sample(request_id: &str, rate: f32) -> bool {
    // NaN is handled explicitly rather than by inverting `>`: a rate that is
    // not a number samples nothing, which is the conservative reading.
    if rate.is_nan() || rate <= 0.0 {
        return false;
    }
    if rate >= 1.0 {
        return true;
    }
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(request_id.as_bytes());
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest[..8]);
    let position = u64::from_be_bytes(head) as f64 / u64::MAX as f64;
    position < rate as f64
}

/// The calibration/ageing/probe policy an operator declares on a panel
/// (FR6.3, FR6.4, FR4.3).
///
/// Read from 31400 tags so it travels with the panel rather than living in
/// relay configuration: the operator who declares what the panel does also
/// declares how its cases are sampled, when they go stale, and who is allowed
/// to seed probes into them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PanelPolicy {
    /// Share of otherwise-suppressible requests shown to reviewers anyway.
    pub calibration_sample_rate: f32,
    /// Age in hours past which a still-pending case is escalated.
    pub max_pending_hours: u32,
    /// The one pubkey whose `probe`-tagged requests are honoured as probes.
    pub probe_agent: Option<String>,
}

impl Default for PanelPolicy {
    fn default() -> Self {
        Self {
            calibration_sample_rate: DEFAULT_CALIBRATION_SAMPLE_RATE,
            max_pending_hours: DEFAULT_MAX_PENDING_HOURS,
            probe_agent: None,
        }
    }
}

impl PanelPolicy {
    /// Read the policy from a 31400's tags, defaulting each field independently
    /// so a panel that declares only one of them keeps the defaults for the
    /// rest. An out-of-range rate is clamped to `0.0..=1.0` and a zero deadline
    /// is rejected in favour of the default, because "escalate everything
    /// immediately" is far more likely a typo than an intent.
    pub fn from_tags(tags: &[Vec<String>]) -> Self {
        let rate = extract_tag(tags, TAG_CALIBRATION_SAMPLE_RATE)
            .and_then(|v| v.parse::<f32>().ok())
            .filter(|v| v.is_finite())
            .map(|v| v.clamp(0.0, 1.0))
            .unwrap_or(DEFAULT_CALIBRATION_SAMPLE_RATE);
        let hours = extract_tag(tags, TAG_MAX_PENDING_HOURS)
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_MAX_PENDING_HOURS);
        let probe_agent = extract_tag(tags, TAG_PROBE_AGENT)
            .filter(|v| v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit()))
            .map(|v| v.to_ascii_lowercase());
        Self {
            calibration_sample_rate: rate,
            max_pending_hours: hours,
            probe_agent,
        }
    }

    /// The tags a panel publisher stamps to declare this policy.
    pub fn to_tags(&self) -> Vec<Vec<String>> {
        let mut tags = vec![
            vec![
                TAG_CALIBRATION_SAMPLE_RATE.to_string(),
                self.calibration_sample_rate.to_string(),
            ],
            vec![
                TAG_MAX_PENDING_HOURS.to_string(),
                self.max_pending_hours.to_string(),
            ],
        ];
        if let Some(agent) = &self.probe_agent {
            tags.push(vec![TAG_PROBE_AGENT.to_string(), agent.clone()]);
        }
        tags
    }

    /// Whether `pubkey` is this panel's registered probe agent (FR6.4).
    ///
    /// A panel with no registered probe agent honours no probes at all: a
    /// `probe` tag from an arbitrary agent is not a probe, it is noise that
    /// would corrupt the catch rate.
    pub fn is_probe_agent(&self, pubkey: &str) -> bool {
        self.probe_agent
            .as_deref()
            .is_some_and(|a| a.eq_ignore_ascii_case(pubkey))
    }
}

// ── Receipt stage ladder (ADR-2010 + FR4) ───────────────────────────────────

/// How far a governance decision has actually got — from the signature through
/// to whether the approved act took effect in the world.
///
/// The first four stages are the relay's (ADR-2010): they certify storage and
/// projection. The **application** stages are the mutation owner's (FR4.1):
/// only the system that performed the act can say whether it happened, and it
/// says so by advancing this ladder through the receipts endpoint. That is what
/// closes the loop for the human who approved it.
///
/// Two stages are *side receipts* ([`Self::is_side_receipt`]): they record
/// something that happened to a case without advancing it toward application,
/// and so never overwrite a ladder stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptStage {
    /// The event carries a valid signature and correlates to a case.
    Signed,
    /// The signed envelope is durably stored by the relay. This is what a relay
    /// `OK` actually certifies — and all it certifies.
    RelayAccepted,
    /// The decision row, the case state and this receipt committed together.
    ProjectionCommitted,
    /// Projection was attempted and did not commit. Terminal until a
    /// reconciliation retry supersedes it.
    ProjectionFailed,
    /// The mutation owner has read the decision. It has not acted yet.
    ConsumerReceived,
    /// The mutation owner performed the approved act and it took effect.
    Applied,
    /// The mutation owner did not perform the act, and says so. A denied action
    /// and an approved action whose write failed must never look the same.
    NotApplied,
    /// An operator executed the approved act by hand during an outage (FR7).
    AppliedManually,
    /// Side receipt: the case exceeded the panel's `max_pending_hours` while
    /// still pending (FR4.3).
    EscalatedOnAge,
    /// Side receipt: the case passed its open-case TTL without a decision.
    Expired,
}

impl ReceiptStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signed => "signed",
            Self::RelayAccepted => "relay-accepted",
            Self::ProjectionCommitted => "projection-committed",
            Self::ProjectionFailed => "projection-failed",
            Self::ConsumerReceived => "consumer-received",
            Self::Applied => "applied",
            Self::NotApplied => "not-applied",
            Self::AppliedManually => "applied-manually",
            Self::EscalatedOnAge => "escalated-on-age",
            Self::Expired => "expired",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "signed" => Some(Self::Signed),
            "relay-accepted" => Some(Self::RelayAccepted),
            "projection-committed" => Some(Self::ProjectionCommitted),
            "projection-failed" => Some(Self::ProjectionFailed),
            "consumer-received" => Some(Self::ConsumerReceived),
            "applied" => Some(Self::Applied),
            "not-applied" => Some(Self::NotApplied),
            "applied-manually" => Some(Self::AppliedManually),
            "escalated-on-age" => Some(Self::EscalatedOnAge),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }

    /// Position on the monotonic ladder, or `None` for a stage that is not on
    /// it (the two side receipts, and the `projection-failed` error state).
    pub fn ladder_rank(self) -> Option<u8> {
        match self {
            Self::Signed => Some(0),
            Self::RelayAccepted => Some(1),
            Self::ProjectionCommitted => Some(2),
            Self::ConsumerReceived => Some(3),
            Self::Applied | Self::NotApplied | Self::AppliedManually => Some(4),
            Self::ProjectionFailed | Self::EscalatedOnAge | Self::Expired => None,
        }
    }

    /// A record about a case that does not advance it toward application
    /// (DDD §6 invariant 5).
    pub fn is_side_receipt(self) -> bool {
        matches!(self, Self::EscalatedOnAge | Self::Expired)
    }

    /// One of the four stages the mutation owner reports through the receipts
    /// endpoint (FR4.1).
    pub fn is_application_stage(self) -> bool {
        matches!(
            self,
            Self::ConsumerReceived | Self::Applied | Self::NotApplied | Self::AppliedManually
        )
    }

    /// A terminal application stage: the mutation owner has said what happened.
    pub fn is_terminal_application(self) -> bool {
        matches!(self, Self::Applied | Self::NotApplied | Self::AppliedManually)
    }

    /// Whether this stage represents a mutation that actually took effect.
    pub fn is_applied(self) -> bool {
        matches!(
            self,
            Self::ProjectionCommitted | Self::Applied | Self::AppliedManually
        )
    }

    /// Whether a further projection attempt is warranted.
    pub fn awaits_projection(self) -> bool {
        matches!(self, Self::Signed | Self::RelayAccepted | Self::ProjectionFailed)
    }
}

/// Why an application-stage advance was refused (FR4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StageAdvanceError {
    /// The requested stage is not one the mutation owner may report.
    #[error("stage is not an application stage")]
    NotAnApplicationStage,
    /// The receipt has not yet reached `projection-committed`, so there is no
    /// committed decision for a consumer to have received.
    #[error("receipt has not reached projection-committed")]
    NotProjected,
    /// The ladder would move backwards, or sideways within the same rank.
    /// DDD §6 invariant 5: a stage never regresses.
    #[error("stage would regress or repeat")]
    Regression,
    /// `applied | not-applied` must follow an explicit `consumer-received`:
    /// the consumer says it has the decision before it says what it did with it.
    #[error("terminal application stage requires consumer-received first")]
    MissingConsumerReceived,
}

/// Whether a receipt at `current` may advance to `next` (DDD §6 invariant 5).
///
/// Monotonic: `next` must sit strictly higher on the ladder than `current`.
/// `applied` and `not-applied` additionally require an explicit
/// `consumer-received` beforehand, so "the consumer never saw it" and "the
/// consumer saw it and declined" stay distinguishable.
///
/// `applied-manually` is deliberately exempt from that second rule: it is the
/// outage path (FR7), where by construction no consumer received anything —
/// an operator acted by hand on a decision that reached `projection-committed`.
pub fn can_advance_stage(
    current: ReceiptStage,
    next: ReceiptStage,
) -> Result<(), StageAdvanceError> {
    if !next.is_application_stage() {
        return Err(StageAdvanceError::NotAnApplicationStage);
    }
    let current_rank = match current.ladder_rank() {
        // A side receipt or a failed projection is not a ladder position, so
        // there is nothing to advance from.
        None => return Err(StageAdvanceError::NotProjected),
        Some(r) => r,
    };
    if current_rank < ReceiptStage::ProjectionCommitted.ladder_rank().unwrap_or(2) {
        return Err(StageAdvanceError::NotProjected);
    }
    let next_rank = next.ladder_rank().unwrap_or(0);
    if next_rank <= current_rank {
        return Err(StageAdvanceError::Regression);
    }
    if matches!(next, ReceiptStage::Applied | ReceiptStage::NotApplied)
        && current != ReceiptStage::ConsumerReceived
    {
        return Err(StageAdvanceError::MissingConsumerReceived);
    }
    Ok(())
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
    /// The agent's optional restatement of the panel's task-property triple
    /// (ADR-2011). Merged tightening-only: it can raise the boundary for this
    /// one request and can never lower the panel's.
    #[serde(default)]
    pub task_properties: Option<TaskProperties>,
    /// Seeded-probe digest (FR6.4). Honoured only from the panel's registered
    /// probe agent, and never rendered before the case is decided (DDD §6
    /// invariant 7).
    #[serde(default)]
    pub probe: Option<String>,
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

/// The referenced event id of an `e`-tag carrying a given NIP-10 marker.
///
/// A NIP-10 `e`-tag is `["e", <event_id>, <relay_url>, <marker>]`; the marker is
/// the fourth element. Returns the event id (second element) of the first `e`-tag
/// whose marker matches. This is the reference-integrity mechanism the Judgment
/// Broker canon (`DDD-judgment-broker-context.md` §7a.2) requires for a
/// supersession (`supersedes` marker) and an appeal (`appeal` marker): a
/// superseding kind-31403 / appealing kind-31402 references the prior decision
/// event by `e`-tag, disambiguated from the ordinary request-referencing `e`-tag
/// by its marker.
pub fn extract_e_tag_with_marker<'a>(tags: &'a [Vec<String>], marker: &str) -> Option<&'a str> {
    tags.iter()
        .find(|t| {
            t.first().map(|s| s.as_str()) == Some("e")
                && t.get(3).map(|s| s.as_str()) == Some(marker)
        })
        .and_then(|t| t.get(1))
        .map(|s| s.as_str())
}

/// The superseded decision event id referenced by a superseding kind-31403
/// (`DDD-judgment-broker-context.md` §7a.2 — `supersedes` marker).
pub fn extract_supersedes_target(tags: &[Vec<String>]) -> Option<&str> {
    extract_e_tag_with_marker(tags, "supersedes")
}

/// The prior decision event id an appealing kind-31402 cites to reopen a case
/// (`DDD-judgment-broker-context.md` §7a.2 — `appeal` marker).
pub fn extract_appeal_target(tags: &[Vec<String>]) -> Option<&str> {
    extract_e_tag_with_marker(tags, "appeal")
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

        /// A superseding kind-31403 was signed by a party who is neither the
        /// original decision's signer nor a higher governance role
        /// (`DDD-judgment-broker-context.md` §7a.1, F6). The authority gradient
        /// the governance plane exists to hold is not collapsed by supersession.
        #[error("unauthorised supersession: {superseder} is neither the original signer nor a higher governance role")]
        UnauthorisedSupersession { superseder: String },

        /// A supersession carried no stated reason
        /// (`DDD-judgment-broker-context.md` §7a.2 point 3, F6).
        #[error("supersession requires a stated reason")]
        MissingSupersessionReason,
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
        /// A published decision on this case has been referenced and replaced by
        /// a newer authorised kind-31403 (`DDD-judgment-broker-context.md`
        /// §7a.3, F6). Terminal *for the superseded event* — the event is never
        /// mutated — but the case is not: an appeal can reopen it, and a further
        /// authorised supersession can chain forward.
        Superseded,
        /// A resolved/rejected/superseded case is under human review again after
        /// an appeal (`DDD-judgment-broker-context.md` §7a.3, F6). Non-terminal:
        /// a new kind-31403 decision resolves it.
        Reopened,
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
                    // `Superseded` is terminal for the *event*: a plain
                    // `record_decision` will not touch it. The only paths out are
                    // an authorised `supersede` (which explicitly acts on a
                    // superseded/decided case) or a `reopen` via appeal.
                    | CaseState::Superseded
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
                CaseState::Superseded => "superseded",
                CaseState::Reopened => "reopened",
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
                "superseded" => CaseState::Superseded,
                "reopened" => CaseState::Reopened,
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

    // ── Supersession authority (F6, DDD §7a.1) ──────────────────────────

    /// Governance-role rank for the supersession-authority gradient
    /// (`DDD-judgment-broker-context.md` §7a.1). Higher rank = more authority.
    ///
    /// The free-form `broker_roles.role` strings map here; the relay combines
    /// this with its own whitelist admin/owner status (an owner/admin outranks a
    /// moderator/member — the canon's worked example). An unrecognised role is
    /// rank 0 (member-equivalent). The absolute numbers are meaningless; only the
    /// *ordering* is load-bearing — supersession by a different signer requires a
    /// strictly greater rank than the original signer's.
    pub fn governance_role_rank(role: &str) -> u8 {
        match role {
            "owner" => 4,
            "admin" => 3,
            "moderator" => 2,
            "reviewer" => 1,
            _ => 0,
        }
    }

    /// The outcome of the §7a.1 authority check for a superseding kind-31403.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SupersedeAuthority {
        /// The superseder is the `did:nostr` that signed the original decision,
        /// acting on their own decision.
        OriginalSigner,
        /// The superseder holds a governance role strictly above the original
        /// signer's role at the time of supersession.
        HigherRole,
        /// Neither — the supersession must be rejected (§7a.1).
        Unauthorised,
    }

    impl SupersedeAuthority {
        pub fn is_authorised(self) -> bool {
            !matches!(self, SupersedeAuthority::Unauthorised)
        }
    }

    /// Decide whether a superseder may supersede a decision the `original_signer`
    /// published, per `DDD-judgment-broker-context.md` §7a.1.
    ///
    /// Authorised iff the superseder IS the original signer, or holds a role rank
    /// *strictly greater* than the original signer's. An equal- or lower-rank
    /// different signer is `Unauthorised`: the authority gradient is not collapsed
    /// by supersession. Pure over its inputs; the relay supplies the ranks from
    /// its role/admin tables.
    pub fn supersede_authority(
        original_signer: &str,
        superseder: &str,
        original_rank: u8,
        superseder_rank: u8,
    ) -> SupersedeAuthority {
        if superseder == original_signer {
            SupersedeAuthority::OriginalSigner
        } else if superseder_rank > original_rank {
            SupersedeAuthority::HigherRole
        } else {
            SupersedeAuthority::Unauthorised
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

        /// Supersede a prior published decision on this case
        /// (`DDD-judgment-broker-context.md` §7a, F6).
        ///
        /// Supersession is a *new* authorised decision that references the prior
        /// one; the prior decision is never mutated — it stays in `history` as the
        /// audit record and the case moves to `Superseded`. Per §7a.2 the
        /// superseding decision carries the superseder's own `DecisionOutcome`
        /// (e.g. a `Reject` that revokes a prior `Approve` — a "Revoke"), a
        /// reference to the superseded decision, and a stated reason.
        ///
        /// Authority-gated (§7a.1): the caller passes the pre-computed
        /// [`SupersedeAuthority`] (the relay derives it from the original signer +
        /// role ranks). An `Unauthorised` authority is rejected here with a
        /// testable error, exactly as the relay `RelayGovernanceGate` rejects it
        /// on ingest — this method is the pure, unit-testable seam behind that
        /// gate. A missing reason is rejected (§7a.2 point 3).
        ///
        /// Unlike [`Self::record_decision`], this deliberately does NOT reject a
        /// terminal (`Decided`/`Superseded`) case — superseding a *resolved*
        /// decision is the whole point (§7a.3: `Resolved/Rejected/Superseded
        /// --(superseding 31403)--> Superseded`). The self-review guard still
        /// applies: a superseder may not be the case creator.
        #[allow(clippy::too_many_arguments)]
        pub fn supersede(
            &mut self,
            superseding_decision_id: impl Into<String>,
            superseded_decision_id: impl Into<String>,
            outcome: DecisionOutcome,
            superseder_pubkey: impl Into<String>,
            reason: impl Into<String>,
            authority: SupersedeAuthority,
            now: u64,
        ) -> Result<&DecisionHistoryEntry, CaseError> {
            let superseder = superseder_pubkey.into();

            if !authority.is_authorised() {
                return Err(CaseError::UnauthorisedSupersession { superseder });
            }

            let reason = reason.into();
            if reason.trim().is_empty() {
                return Err(CaseError::MissingSupersessionReason);
            }

            if superseder == self.created_by {
                return Err(CaseError::SelfReview { broker: superseder });
            }

            // The superseding decision's own outcome is validated with the same
            // detail-completeness rules as a first-order decision.
            match &outcome {
                DecisionOutcome::Amend { diff } if diff.trim().is_empty() => {
                    return Err(CaseError::MissingAmendmentDiff);
                }
                DecisionOutcome::Delegate { delegate_to } if delegate_to.trim().is_empty() => {
                    return Err(CaseError::MissingDelegateTarget);
                }
                _ => {}
            }

            let entry = DecisionHistoryEntry {
                decision_id: superseding_decision_id.into(),
                outcome,
                broker_pubkey: superseder,
                decided_at: now,
                // The provenance link points at the decision this one supersedes,
                // not merely the chronologically prior one — the reference the
                // canon (§7a.2) requires.
                prior_decision_id: Some(superseded_decision_id.into()),
                reasoning: reason,
            };
            self.history.push(entry);
            self.state = CaseState::Superseded;
            self.updated_at = now;

            Ok(self.history.last().expect("just pushed"))
        }

        /// Reopen a resolved/rejected/superseded case for a fresh human decision
        /// after an appeal (`DDD-judgment-broker-context.md` §7a.3, F6).
        ///
        /// An appeal is a fresh kind-31402 (`ActionRequest`) citing the prior
        /// decision; it *reopens* the case (→ `Reopened`) but does not itself
        /// overturn anything. The overturning, if any, is a subsequent kind-31403
        /// under §7a.1 authority applied to the now-`Reopened` case. Rejects a
        /// case that is not in an appealable terminal state.
        pub fn reopen(&mut self, now: u64) -> Result<(), CaseError> {
            match self.state {
                CaseState::Decided
                | CaseState::Delegated
                | CaseState::Promoted
                | CaseState::Precedent
                | CaseState::Superseded => {
                    self.state = CaseState::Reopened;
                    self.updated_at = now;
                    Ok(())
                }
                other => Err(CaseError::InvalidTransition {
                    from: other,
                    to: CaseState::Reopened,
                }),
            }
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
            task_properties: Some(TaskProperties::new(
                Verifiability::Partial,
                Reversibility::Compensable,
                Stakes::Significant,
            )),
            calibration_sample_rate: Some(0.2),
            max_pending_hours: Some(24),
            probe_agent: Some("f".repeat(64)),
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
        let prom =
            DecisionOutcome::from_response_content(r#"{"action":"promote","pattern_id":"pat-9"}"#)
                .unwrap();
        assert_eq!(prom.detail(), Some("pat-9"));
        let prec =
            DecisionOutcome::from_response_content(r#"{"action":"precedent","scope":"org-wide"}"#)
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
        let report = orch.decide(&mut case, decision_id, outcome.clone(), responder, "", now)?;
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
            let (action, detail, state, _) = decide(
                &snapshot(CaseState::Open),
                &"c".repeat(64),
                content,
                "human-bob",
                2000,
            )
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
        assert!(matches!(
            err,
            OrchestrationError::ShareTransitionRejected(_)
        ));
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
            // F6 (DDD §7a.3): the supersession lifecycle states.
            CaseState::Superseded,
            CaseState::Reopened,
        ] {
            assert_eq!(CaseState::parse(st.as_str()), st);
        }
        // Legacy projection strings map onto the domain's terminal decided state.
        assert_eq!(CaseState::parse("resolved"), CaseState::Decided);
        assert_eq!(CaseState::parse("rejected"), CaseState::Decided);
    }

    // ── F6: supersession authority + lifecycle (DDD §7a) ─────────────────

    fn supersedable_case() -> BrokerCase {
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
        c.record_decision("dec-1", DecisionOutcome::Approve, "bob", "granted", 1002)
            .unwrap();
        assert_eq!(c.state, CaseState::Decided);
        c
    }

    #[test]
    fn governance_role_rank_orders_admin_above_moderator_above_member() {
        // The canon's worked example: an admin/owner outranks a moderator/member.
        assert!(governance_role_rank("owner") > governance_role_rank("admin"));
        assert!(governance_role_rank("admin") > governance_role_rank("moderator"));
        assert!(governance_role_rank("moderator") > governance_role_rank("reviewer"));
        assert!(governance_role_rank("reviewer") > governance_role_rank("member"));
        // An unrecognised role is member-equivalent (rank 0), never elevated.
        assert_eq!(governance_role_rank("nonsense"), 0);
        assert_eq!(governance_role_rank("member"), 0);
    }

    #[test]
    fn supersede_authority_gradient() {
        // Original signer may always supersede their own decision.
        assert_eq!(
            supersede_authority("alice", "alice", 3, 3),
            SupersedeAuthority::OriginalSigner
        );
        // A strictly higher role may supersede a different signer's decision.
        assert_eq!(
            supersede_authority("alice", "carol", 2, 3),
            SupersedeAuthority::HigherRole
        );
        // Equal role, different signer ⇒ unauthorised (gradient not collapsed).
        assert_eq!(
            supersede_authority("alice", "carol", 3, 3),
            SupersedeAuthority::Unauthorised
        );
        // Lower role, different signer ⇒ unauthorised.
        assert_eq!(
            supersede_authority("alice", "carol", 3, 2),
            SupersedeAuthority::Unauthorised
        );
        assert!(SupersedeAuthority::OriginalSigner.is_authorised());
        assert!(SupersedeAuthority::HigherRole.is_authorised());
        assert!(!SupersedeAuthority::Unauthorised.is_authorised());
    }

    #[test]
    fn supersede_by_original_signer_accepted_and_retains_history() {
        let mut c = supersedable_case();
        // The original signer (bob) revokes their own prior Approve with a Reject.
        let entry = c
            .supersede(
                "dec-2",
                "dec-1",
                DecisionOutcome::Reject,
                "bob",
                "revoked: grant no longer holds",
                SupersedeAuthority::OriginalSigner,
                1003,
            )
            .unwrap()
            .clone();
        // The superseding decision references the one it supersedes (§7a.2).
        assert_eq!(entry.prior_decision_id.as_deref(), Some("dec-1"));
        assert_eq!(entry.outcome, DecisionOutcome::Reject);
        // The case moves to Superseded (§7a.3).
        assert_eq!(c.state, CaseState::Superseded);
        // The prior decision is RETAINED — never mutated (Invariant 5): both the
        // original Approve and the superseding Reject are in the audit history.
        assert_eq!(c.history.len(), 2);
        assert_eq!(c.history[0].decision_id, "dec-1");
        assert_eq!(c.history[0].outcome, DecisionOutcome::Approve);
        assert_eq!(c.history[1].decision_id, "dec-2");
        // The effective decision is the most recent authorised one.
        assert_eq!(c.latest_decision_id(), Some("dec-2"));
    }

    #[test]
    fn supersede_by_higher_role_accepted() {
        let mut c = supersedable_case();
        // A different, higher-role signer (carol, admin over bob) may supersede.
        c.supersede(
            "dec-2",
            "dec-1",
            DecisionOutcome::Reject,
            "carol",
            "overridden by governance",
            SupersedeAuthority::HigherRole,
            1003,
        )
        .unwrap();
        assert_eq!(c.state, CaseState::Superseded);
    }

    #[test]
    fn supersede_by_unauthorised_signer_rejected() {
        let mut c = supersedable_case();
        let err = c
            .supersede(
                "dec-2",
                "dec-1",
                DecisionOutcome::Reject,
                "mallory",
                "I disagree",
                SupersedeAuthority::Unauthorised,
                1003,
            )
            .unwrap_err();
        assert!(matches!(err, CaseError::UnauthorisedSupersession { .. }));
        // Nothing changed: the original decision stands, no row appended.
        assert_eq!(c.state, CaseState::Decided);
        assert_eq!(c.history.len(), 1);
    }

    #[test]
    fn supersede_requires_a_stated_reason() {
        let mut c = supersedable_case();
        let err = c
            .supersede(
                "dec-2",
                "dec-1",
                DecisionOutcome::Reject,
                "bob",
                "   ",
                SupersedeAuthority::OriginalSigner,
                1003,
            )
            .unwrap_err();
        assert_eq!(err, CaseError::MissingSupersessionReason);
        assert_eq!(c.state, CaseState::Decided);
        assert_eq!(c.history.len(), 1);
    }

    #[test]
    fn supersession_chain_then_appeal_then_redecide() {
        // Full §7a.3 lifecycle: Decided → Superseded → (chain) → Reopened → Decided.
        let mut c = supersedable_case();

        // Chain a second supersession onto the first (forward-chaining, §7a.3).
        c.supersede(
            "dec-2",
            "dec-1",
            DecisionOutcome::Reject,
            "bob",
            "revoke",
            SupersedeAuthority::OriginalSigner,
            1003,
        )
        .unwrap();
        c.supersede(
            "dec-3",
            "dec-2",
            DecisionOutcome::Approve,
            "carol",
            "re-granted on appeal-review",
            SupersedeAuthority::HigherRole,
            1004,
        )
        .unwrap();
        assert_eq!(c.state, CaseState::Superseded);
        // The effective (current) decision is the newest in the chain.
        assert_eq!(c.latest_decision_id(), Some("dec-3"));
        // Every decision is retained as history — the chain is auditable.
        assert_eq!(c.history.len(), 3);
        assert_eq!(c.history[2].prior_decision_id.as_deref(), Some("dec-2"));

        // An appeal reopens the (superseded) case for a fresh decision (§7a.3).
        c.reopen(1005).unwrap();
        assert_eq!(c.state, CaseState::Reopened);

        // A new decision on the reopened case resolves it (Reopened → Decided).
        c.record_decision("dec-4", DecisionOutcome::Reject, "carol", "final", 1006)
            .unwrap();
        assert_eq!(c.state, CaseState::Decided);
        assert_eq!(c.history.len(), 4);
    }

    #[test]
    fn reopen_rejects_a_non_terminal_case() {
        // An Open case has nothing to appeal.
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
        let err = c.reopen(1001).unwrap_err();
        assert!(matches!(err, CaseError::InvalidTransition { .. }));
    }

    #[test]
    fn extract_supersedes_and_appeal_targets_by_marker() {
        let tags = vec![
            vec!["d".into(), "case-1".into()],
            // Ordinary request-referencing e-tag (no marker) is NOT a supersede.
            vec!["e".into(), "req-event".into()],
            vec![
                "e".into(),
                "prior-decision-event".into(),
                "".into(),
                "supersedes".into(),
            ],
        ];
        assert_eq!(
            extract_supersedes_target(&tags),
            Some("prior-decision-event")
        );
        // No appeal marker present.
        assert_eq!(extract_appeal_target(&tags), None);

        let appeal_tags = vec![
            vec!["d".into(), "case-1".into()],
            vec![
                "e".into(),
                "reviewed-decision".into(),
                "".into(),
                "appeal".into(),
            ],
        ];
        assert_eq!(
            extract_appeal_target(&appeal_tags),
            Some("reviewed-decision")
        );
        assert_eq!(extract_supersedes_target(&appeal_tags), None);
    }
}

// ── ADR-2011 / EXP-AC-003: task properties and the effective tier ───────────

#[cfg(test)]
mod task_property_tests {
    use super::*;

    const VERIFIABILITIES: [Verifiability; 3] = [
        Verifiability::Inspectable,
        Verifiability::Partial,
        Verifiability::Opaque,
    ];
    const REVERSIBILITIES: [Reversibility; 3] = [
        Reversibility::Reversible,
        Reversibility::Compensable,
        Reversibility::Irreversible,
    ];
    const STAKES: [Stakes; 3] = [Stakes::Bounded, Stakes::Significant, Stakes::Critical];

    /// All 27 triples, in a fixed order so a failure names a reproducible case.
    fn all_triples() -> Vec<TaskProperties> {
        let mut out = Vec::with_capacity(27);
        for v in VERIFIABILITIES {
            for r in REVERSIBILITIES {
                for s in STAKES {
                    out.push(TaskProperties::new(v, r, s));
                }
            }
        }
        out
    }

    /// DDD §6 invariant 2, exhaustively: over every one of the 27×27 =: 729
    /// (panel, request) pairs the merge is never looser than the panel on any
    /// leg. This is the property the whole ADR rests on — an agent cannot lower
    /// the boundary its operator set — so it is checked by enumeration rather
    /// than by sampling.
    #[test]
    fn merge_is_tightening_only_over_all_729_pairs() {
        let triples = all_triples();
        assert_eq!(triples.len(), 27, "the triple space is 3x3x3");
        let mut checked = 0usize;
        for panel in &triples {
            for request in &triples {
                let merged = TaskProperties::merge(*panel, *request);
                assert!(
                    merged.verifiability >= panel.verifiability,
                    "verifiability loosened: panel={panel:?} request={request:?} merged={merged:?}"
                );
                assert!(
                    merged.reversibility >= panel.reversibility,
                    "reversibility loosened: panel={panel:?} request={request:?} merged={merged:?}"
                );
                assert!(
                    merged.stakes >= panel.stakes,
                    "stakes loosened: panel={panel:?} request={request:?} merged={merged:?}"
                );
                // Tightening only in the other direction too: the request's own
                // declaration is honoured where it is the tighter of the two.
                assert!(merged.verifiability >= request.verifiability);
                assert!(merged.reversibility >= request.reversibility);
                assert!(merged.stakes >= request.stakes);
                // And the merge never invents tightness neither side declared.
                assert_eq!(
                    merged,
                    TaskProperties::new(
                        panel.verifiability.max(request.verifiability),
                        panel.reversibility.max(request.reversibility),
                        panel.stakes.max(request.stakes),
                    )
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 729);
    }

    /// The counter-example EXP-AC-003 names: a request tag claiming
    /// `Reversible` against an `Irreversible` panel.
    #[test]
    fn request_cannot_lower_irreversible_to_reversible() {
        let panel = TaskProperties::new(
            Verifiability::Inspectable,
            Reversibility::Irreversible,
            Stakes::Bounded,
        );
        let request = TaskProperties::default();
        let merged = TaskProperties::merge(panel, request);
        assert_eq!(merged.reversibility, Reversibility::Irreversible);
        assert_eq!(
            effective_tier(Some(&panel), Some(&request), Some(RiskTier::Low), RiskTier::Medium),
            RiskTier::High,
            "an irreversible panel floors the case at high whatever the request says"
        );
    }

    /// The effective-tier table from PRD FR3.2 / ADR-2011 §2, over the whole
    /// triple space crossed with every declared tier.
    #[test]
    fn effective_tier_table_holds_for_every_triple_and_tier() {
        let tiers = [
            None,
            Some(RiskTier::Low),
            Some(RiskTier::Medium),
            Some(RiskTier::High),
            Some(RiskTier::Critical),
        ];
        for props in all_triples() {
            for declared in tiers {
                let tier = effective_tier(Some(&props), None, declared, RiskTier::Medium);

                if props.reversibility == Reversibility::Irreversible
                    || props.stakes == Stakes::Critical
                {
                    assert!(
                        tier >= RiskTier::High,
                        "irreversible/critical must floor at high: {props:?} declared={declared:?} => {tier:?}"
                    );
                } else if props.verifiability == Verifiability::Opaque {
                    assert!(
                        tier >= RiskTier::Medium,
                        "opaque must floor at medium: {props:?} declared={declared:?} => {tier:?}"
                    );
                    assert!(
                        !is_member_suppressed_effective(Some(&props), tier, false),
                        "opaque work is never member-suppressed: {props:?}"
                    );
                } else {
                    // No floor of its own: the declared tier stands, and an
                    // undeclared tier folds to the advertised default.
                    assert_eq!(tier, declared.unwrap_or(RiskTier::Medium));
                }

                // The declared tier can only ever raise the result.
                if let Some(d) = declared {
                    assert!(tier >= d, "declared tier was lowered: {d:?} => {tier:?}");
                }
            }
        }
    }

    /// FR3.3: an entirely unlabelled request folds to exactly the relay's
    /// advertised default, not to the accidental `Medium` of an absent tag.
    #[test]
    fn unlabelled_request_folds_to_advertised_default() {
        for default in [RiskTier::Low, RiskTier::Medium, RiskTier::High, RiskTier::Critical] {
            assert_eq!(effective_tier(None, None, None, default), default);
        }
    }

    /// A tier declared without any properties stands on its own — the
    /// advertised default is what an *unlabelled* request folds to, not a floor
    /// under every request (ADR-2011 §3).
    #[test]
    fn declared_tier_without_properties_stands_alone() {
        assert_eq!(
            effective_tier(None, None, Some(RiskTier::Low), RiskTier::Medium),
            RiskTier::Low
        );
        assert_eq!(
            effective_tier(None, None, Some(RiskTier::Critical), RiskTier::Low),
            RiskTier::Critical
        );
    }

    /// Properties without a declared tier still never sit below what the relay
    /// advertises it escalates at.
    #[test]
    fn properties_without_tier_respect_advertised_default() {
        let loose = TaskProperties::default();
        assert_eq!(
            effective_tier(Some(&loose), None, None, RiskTier::High),
            RiskTier::High
        );
    }

    /// The second counter-example: a `Critical`-stakes request is never
    /// suppressed from the member surface.
    #[test]
    fn critical_stakes_is_never_member_suppressed() {
        let props = TaskProperties::new(
            Verifiability::Inspectable,
            Reversibility::Reversible,
            Stakes::Critical,
        );
        let tier = effective_tier(Some(&props), None, Some(RiskTier::Low), RiskTier::Medium);
        assert_eq!(tier, RiskTier::High);
        assert!(!is_member_suppressed_effective(Some(&props), tier, false));
    }

    /// A calibration sample is shown even when its effective tier is `Low` —
    /// that is the entire mechanism (FR6.3).
    #[test]
    fn calibration_sample_overrides_suppression() {
        let loose = TaskProperties::default();
        assert!(is_member_suppressed_effective(
            Some(&loose),
            RiskTier::Low,
            false
        ));
        assert!(!is_member_suppressed_effective(
            Some(&loose),
            RiskTier::Low,
            true
        ));
    }

    #[test]
    fn tags_round_trip() {
        let props = TaskProperties::new(
            Verifiability::Opaque,
            Reversibility::Compensable,
            Stakes::Significant,
        );
        let tags = props.to_tags();
        assert_eq!(TaskProperties::from_tags(&tags), Some(props));
    }

    /// Legacy events carry no `tp-*` tag at all; that must stay distinguishable
    /// from a declared-loosest triple, because only the former falls back to the
    /// advertised default.
    #[test]
    fn absent_tags_parse_to_none_not_loosest() {
        let legacy = vec![vec!["d".to_string(), "case-1".to_string()]];
        assert_eq!(TaskProperties::from_tags(&legacy), None);
    }

    /// A partially-tagged request keeps the loosest value on the legs it did
    /// not declare, which under the tightening merge simply defers to the panel.
    #[test]
    fn partial_tags_default_the_missing_legs() {
        let tags = vec![vec![TAG_TP_STAKES.to_string(), "critical".to_string()]];
        let parsed = TaskProperties::from_tags(&tags).expect("one tp tag is enough");
        assert_eq!(parsed.stakes, Stakes::Critical);
        assert_eq!(parsed.verifiability, Verifiability::Inspectable);
        assert_eq!(parsed.reversibility, Reversibility::Reversible);

        let panel = TaskProperties::new(
            Verifiability::Opaque,
            Reversibility::Irreversible,
            Stakes::Bounded,
        );
        let merged = TaskProperties::merge(panel, parsed);
        assert_eq!(merged.verifiability, Verifiability::Opaque);
        assert_eq!(merged.reversibility, Reversibility::Irreversible);
        assert_eq!(merged.stakes, Stakes::Critical);
    }

    /// An unrecognised tag value must not loosen a declared property; it falls
    /// back to the loosest value, which the merge then discards in favour of
    /// whatever the other side declared.
    #[test]
    fn unknown_tag_value_cannot_loosen() {
        let tags = vec![vec![
            TAG_TP_REVERSIBILITY.to_string(),
            "totally-fine-honest".to_string(),
        ]];
        let parsed = TaskProperties::from_tags(&tags).unwrap();
        assert_eq!(parsed.reversibility, Reversibility::Reversible);
        let panel = TaskProperties::new(
            Verifiability::Inspectable,
            Reversibility::Irreversible,
            Stakes::Bounded,
        );
        assert_eq!(
            TaskProperties::merge(panel, parsed).reversibility,
            Reversibility::Irreversible
        );
    }
}

// ── EXP-AC-006: deterministic calibration sampling ──────────────────────────

#[cfg(test)]
mod calibration_tests {
    use super::*;

    /// EXP-AC-006: with a rate of 0.1, between 80 and 120 of 1,000 requests are
    /// sampled. The bound is on the hash's uniformity, not on luck: the ids are
    /// fixed, so this test is deterministic and will fail identically forever if
    /// the selection function changes.
    #[test]
    fn sampling_rate_lands_within_the_expected_band() {
        let sampled = (0..1000)
            .filter(|i| is_calibration_sample(&format!("req-{i:04}"), 0.1))
            .count();
        assert!(
            (80..=120).contains(&sampled),
            "expected 80..=120 of 1000 sampled at rate 0.1, got {sampled}"
        );
    }

    /// The counter-example EXP-AC-006 names: sampling must not depend on the
    /// wall clock. Determinism is the observable form of that — the same id
    /// gives the same answer every time it is asked.
    #[test]
    fn sampling_is_deterministic_per_request_id() {
        for i in 0..200 {
            let id = format!("req-{i}");
            let first = is_calibration_sample(&id, 0.1);
            for _ in 0..5 {
                assert_eq!(is_calibration_sample(&id, 0.1), first, "unstable for {id}");
            }
        }
    }

    #[test]
    fn degenerate_rates_are_total() {
        assert!(!is_calibration_sample("anything", 0.0));
        assert!(!is_calibration_sample("anything", -1.0));
        assert!(is_calibration_sample("anything", 1.0));
        assert!(is_calibration_sample("anything", 2.0));
    }

    /// A higher rate samples a superset: the selection is a threshold on one
    /// fixed per-id position, not a fresh draw.
    #[test]
    fn higher_rate_is_a_superset() {
        for i in 0..300 {
            let id = format!("req-{i}");
            if is_calibration_sample(&id, 0.1) {
                assert!(is_calibration_sample(&id, 0.5), "{id} dropped out at 0.5");
            }
        }
    }

    #[test]
    fn panel_policy_defaults_and_overrides() {
        assert_eq!(
            PanelPolicy::from_tags(&[]),
            PanelPolicy {
                calibration_sample_rate: DEFAULT_CALIBRATION_SAMPLE_RATE,
                max_pending_hours: DEFAULT_MAX_PENDING_HOURS,
                probe_agent: None,
            }
        );
        let probe = "b".repeat(64);
        let tags = vec![
            vec![TAG_CALIBRATION_SAMPLE_RATE.to_string(), "0.25".to_string()],
            vec![TAG_MAX_PENDING_HOURS.to_string(), "12".to_string()],
            vec![TAG_PROBE_AGENT.to_string(), probe.clone()],
        ];
        let policy = PanelPolicy::from_tags(&tags);
        assert_eq!(policy.calibration_sample_rate, 0.25);
        assert_eq!(policy.max_pending_hours, 12);
        assert!(policy.is_probe_agent(&probe));
        assert!(!policy.is_probe_agent(&"c".repeat(64)));
    }

    /// A nonsense rate or a zero deadline is far more likely a typo than an
    /// intent, so the policy keeps its documented default rather than sampling
    /// nothing or escalating everything.
    #[test]
    fn out_of_range_policy_values_fall_back() {
        let tags = vec![
            vec![TAG_CALIBRATION_SAMPLE_RATE.to_string(), "7".to_string()],
            vec![TAG_MAX_PENDING_HOURS.to_string(), "0".to_string()],
            vec![TAG_PROBE_AGENT.to_string(), "not-a-pubkey".to_string()],
        ];
        let policy = PanelPolicy::from_tags(&tags);
        assert_eq!(policy.calibration_sample_rate, 1.0, "clamped, not discarded");
        assert_eq!(policy.max_pending_hours, DEFAULT_MAX_PENDING_HOURS);
        assert_eq!(policy.probe_agent, None);
    }

    /// A panel with no registered probe agent honours no probes: a `probe` tag
    /// from an arbitrary agent is noise that would corrupt the catch rate.
    #[test]
    fn panel_without_probe_agent_honours_no_probe() {
        assert!(!PanelPolicy::default().is_probe_agent(&"a".repeat(64)));
    }
}

// ── EXP-AC-004: the receipt stage ladder ────────────────────────────────────

#[cfg(test)]
mod receipt_stage_tests {
    use super::*;

    const ALL: [ReceiptStage; 10] = [
        ReceiptStage::Signed,
        ReceiptStage::RelayAccepted,
        ReceiptStage::ProjectionCommitted,
        ReceiptStage::ProjectionFailed,
        ReceiptStage::ConsumerReceived,
        ReceiptStage::Applied,
        ReceiptStage::NotApplied,
        ReceiptStage::AppliedManually,
        ReceiptStage::EscalatedOnAge,
        ReceiptStage::Expired,
    ];

    #[test]
    fn every_stage_round_trips_through_its_wire_string() {
        for stage in ALL {
            assert_eq!(ReceiptStage::parse(stage.as_str()), Some(stage));
        }
        assert_eq!(ReceiptStage::parse("not-a-stage"), None);
    }

    /// The happy path EXP-AC-004 specifies: `projection-committed` →
    /// `consumer-received` → exactly one terminal stage.
    #[test]
    fn ladder_advances_committed_to_received_to_terminal() {
        assert!(can_advance_stage(
            ReceiptStage::ProjectionCommitted,
            ReceiptStage::ConsumerReceived
        )
        .is_ok());
        for terminal in [ReceiptStage::Applied, ReceiptStage::NotApplied] {
            assert!(
                can_advance_stage(ReceiptStage::ConsumerReceived, terminal).is_ok(),
                "{terminal:?} must follow consumer-received"
            );
        }
    }

    /// DDD §6 invariant 5, exhaustively: no pair of stages permits a regression
    /// or a sideways move at the same rank.
    #[test]
    fn no_stage_pair_permits_a_regression() {
        for current in ALL {
            for next in ALL {
                let Ok(()) = can_advance_stage(current, next) else {
                    continue;
                };
                let (c, n) = (
                    current.ladder_rank().expect("advance from a ladder stage"),
                    next.ladder_rank().expect("advance to a ladder stage"),
                );
                assert!(n > c, "{current:?} -> {next:?} is not an advance");
                assert!(next.is_application_stage());
            }
        }
    }

    /// The EXP-AC-004 regression case, by name: `applied` then
    /// `consumer-received` is refused.
    #[test]
    fn applied_then_consumer_received_is_a_regression() {
        assert_eq!(
            can_advance_stage(ReceiptStage::Applied, ReceiptStage::ConsumerReceived),
            Err(StageAdvanceError::Regression)
        );
        assert_eq!(
            can_advance_stage(ReceiptStage::Applied, ReceiptStage::Applied),
            Err(StageAdvanceError::Regression)
        );
    }

    /// A consumer cannot report an outcome for a decision that never committed.
    #[test]
    fn application_stages_require_a_committed_projection() {
        for current in [
            ReceiptStage::Signed,
            ReceiptStage::RelayAccepted,
            ReceiptStage::ProjectionFailed,
            ReceiptStage::EscalatedOnAge,
            ReceiptStage::Expired,
        ] {
            assert_eq!(
                can_advance_stage(current, ReceiptStage::ConsumerReceived),
                Err(StageAdvanceError::NotProjected),
                "{current:?} is not a committed projection"
            );
        }
    }

    /// "The consumer never saw it" and "the consumer saw it and declined" must
    /// stay distinguishable, so a terminal stage needs an explicit
    /// `consumer-received` first.
    #[test]
    fn applied_requires_consumer_received_first() {
        assert_eq!(
            can_advance_stage(ReceiptStage::ProjectionCommitted, ReceiptStage::Applied),
            Err(StageAdvanceError::MissingConsumerReceived)
        );
        assert_eq!(
            can_advance_stage(ReceiptStage::ProjectionCommitted, ReceiptStage::NotApplied),
            Err(StageAdvanceError::MissingConsumerReceived)
        );
    }

    /// FR7: manual continuation is the outage path, where by construction no
    /// consumer received anything — so it is exempt from that one rule and
    /// nothing else.
    #[test]
    fn applied_manually_may_follow_a_committed_projection_directly() {
        assert!(can_advance_stage(
            ReceiptStage::ProjectionCommitted,
            ReceiptStage::AppliedManually
        )
        .is_ok());
        assert_eq!(
            can_advance_stage(ReceiptStage::RelayAccepted, ReceiptStage::AppliedManually),
            Err(StageAdvanceError::NotProjected)
        );
    }

    /// Side receipts never advance the ladder and are never a target of it.
    #[test]
    fn side_receipts_are_off_the_ladder() {
        for side in [ReceiptStage::EscalatedOnAge, ReceiptStage::Expired] {
            assert!(side.is_side_receipt());
            assert_eq!(side.ladder_rank(), None);
            assert_eq!(
                can_advance_stage(ReceiptStage::ConsumerReceived, side),
                Err(StageAdvanceError::NotAnApplicationStage)
            );
        }
    }

    /// A denied action and an approved action whose write failed must never
    /// look the same.
    #[test]
    fn not_applied_is_not_applied() {
        assert!(!ReceiptStage::NotApplied.is_applied());
        assert!(ReceiptStage::Applied.is_applied());
        assert!(ReceiptStage::AppliedManually.is_applied());
        assert!(!ReceiptStage::ConsumerReceived.is_applied());
    }
}
