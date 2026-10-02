//! ADR-2011 M4 probe suite: the pure half.
//!
//! PRD-augmentation-conditions milestone M4 is "probe suite run against the
//! live edge forum (relay, auth API)", exited by "receipt of each probe; deploy
//! status recorded honestly". This crate is that suite. The library holds
//! everything that decides *what* is sent and *whether* the answer passes:
//! probe identities, unsigned event builders, and one verdict function per
//! probe. The binary (`src/main.rs`, native only) holds the sockets.
//!
//! # Probes are identifiable as probes
//!
//! ADR-2011 Decision 6 honours a `probe` tag only from the panel's registered
//! probe agent. Every event this suite publishes therefore lives on its own
//! panel ([`PANEL_D`]), whose 31400 names the signing agent as `probe-agent`,
//! carries the topic tag [`PROBE_TOPIC`], and titles each case
//! `M4 PROBE · …`. Nothing is published to an operator's real panel, and the
//! suite never needs the owner's key: it signs as a registered agent and
//! *expects* the relay to refuse that agent wherever ADR-2011 reserves a
//! decision for a human.
//!
//! # What the suite asserts
//!
//! | Probe | Surface | ADR-2011 clause |
//! |---|---|---|
//! | P01 | relay NIP-11 | §3 advertised default tier and posture |
//! | P02 | `GET /api/governance/reviewers` | FR6.1 route deployed; unsigned read refused |
//! | P03 | `POST /api/governance/receipts/{id}/application` | §5 / FR4.1 route deployed, stage parsed |
//! | P04 | 31400 probe panel | §1 operator triple, §6 probe agent |
//! | P05 | 31402 probe request (declared `low`) | §1 request accepted under the panel |
//! | P06 | `GET /api/governance/cases/{id}` | §2/§3 `effective_tier` stamped `high`; §6 probe withheld |
//! | P07 | REQ `#probe` | §6 probe tag absent from the tag index |
//! | P08 | 31403, no rationale | §4 refused before storage (`rationale_required`, or admission) |
//! | P09 | 31403, `system:` decider with a rationale | §4 a non-human outcome cannot close a high case |
//! | P10 | `GET /api/governance/cases/{id}` | §4 neither response changed the case |
//! | P11 | kind-5 withdrawal | clean-up: the probe request and any stored response leave the panel |
//!
//! P08 and P09 are meaningful whatever the signer's role. A non-admin agent is
//! refused at admission; an admin agent is admitted and must then be stopped
//! by the rationale gate (P08) and by the projection's human-resolution guard
//! (P09, asserted by P10). The suite never sends a 31403 that ADR-2011 would
//! accept as a human decision.
//!
//! A verdict is [`Verdict::Pass`], [`Verdict::Fail`] or [`Verdict::NotRun`].
//! `NotRun` is never counted as a pass: a suite with any `NotRun` is not a
//! green M4 run.

use nostr_bbs_core::governance::{
    ActionRequest, LayoutHint, PanelCapability, PanelDefinition, PanelPolicy, PanelSchema,
    Reversibility, RiskTier, Stakes, TaskProperties, Verifiability, KIND_ACTION_REQUEST,
    KIND_ACTION_RESPONSE, KIND_PANEL_DEFINITION, TAG_PROBE,
};
use nostr_bbs_core::UnsignedEvent;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// `d` tag of the probe panel. Never an operator's panel.
pub const PANEL_D: &str = "adr-2011-m4-probe";
/// Topic tag carried by every event the suite publishes.
pub const PROBE_TOPIC: &str = "adr-2011-m4-probe";
/// Prefix of every probe case title, so a human reading the panel sees a probe.
pub const TITLE_PREFIX: &str = "M4 PROBE";
/// `decided_by` the suite stamps on its refused 31403.
pub const PROBE_DECIDER: &str = "system:adr-2011-m4-probe";
/// NIP-09 deletion kind.
pub const KIND_DELETION: u64 = 5;
/// Ageing deadline the probe panel declares (hours).
pub const PROBE_MAX_PENDING_HOURS: u32 = 24;

/// The operator triple the probe panel declares: an irreversible task floors
/// every request on it at `high`, whatever the requesting agent declares.
pub fn probe_panel_properties() -> TaskProperties {
    TaskProperties::new(
        Verifiability::Inspectable,
        Reversibility::Irreversible,
        Stakes::Significant,
    )
}

/// The tier the probe request declares — deliberately the loosest, so a
/// projected `high` can only have come from the panel.
pub const DECLARED_TIER: RiskTier = RiskTier::Low;

/// One run of the suite. Every case id and probe digest derives from it, so
/// two runs never collide and a run's events can be found again from its id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeRun {
    run_id: String,
}

/// A run id that is not 1..=40 characters of `[a-z0-9-]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadRunId(pub String);

impl std::fmt::Display for BadRunId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "run id {:?} must be 1-40 chars of [a-z0-9-]", self.0)
    }
}

impl std::error::Error for BadRunId {}

impl ProbeRun {
    /// A run named `run_id` (1..=40 characters of `[a-z0-9-]`).
    pub fn new(run_id: &str) -> Result<Self, BadRunId> {
        let ok = !run_id.is_empty()
            && run_id.len() <= 40
            && run_id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if ok {
            Ok(Self {
                run_id: run_id.to_string(),
            })
        } else {
            Err(BadRunId(run_id.to_string()))
        }
    }

    /// The run id.
    pub fn id(&self) -> &str {
        &self.run_id
    }

    /// `d` tag (and `broker_cases.id`) of this run's probe case.
    pub fn case_d(&self) -> String {
        format!("m4-probe-{}", self.run_id)
    }

    /// The seeded-probe digest: SHA-256 of a domain-separated run label.
    pub fn probe_digest(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"adr-2011-m4-probe:");
        h.update(self.run_id.as_bytes());
        hex::encode(h.finalize())
    }
}

/// `31400:<pubkey>:<PANEL_D>` — the probe panel's NIP-33 coordinate.
pub fn panel_coordinate(pubkey: &str) -> String {
    format!("{KIND_PANEL_DEFINITION}:{pubkey}:{PANEL_D}")
}

/// `31402:<pubkey>:<case d>` — the probe request's NIP-33 coordinate.
pub fn request_coordinate(pubkey: &str, run: &ProbeRun) -> String {
    format!("{KIND_ACTION_REQUEST}:{pubkey}:{}", run.case_d())
}

/// The probe panel's definition (31400 content).
pub fn panel_definition(probe_agent: &str) -> PanelDefinition {
    PanelDefinition {
        title: format!("{TITLE_PREFIX} · ADR-2011 escalation boundary"),
        description: "Automated ADR-2011 M4 probe panel. Every case here is a probe that \
                      verifies the relay's escalation boundary; none is a real decision. \
                      Cases are withdrawn by the suite when it finishes."
            .into(),
        version: "1.0.0".into(),
        schema: PanelSchema::ActionInbox,
        fields: Vec::new(),
        actions: Vec::new(),
        layout: LayoutHint::InboxTable,
        capabilities: vec![PanelCapability::Filter],
        refresh_secs: 300,
        task_properties: Some(probe_panel_properties()),
        calibration_sample_rate: None,
        max_pending_hours: Some(PROBE_MAX_PENDING_HOURS),
        probe_agent: Some(probe_agent.to_string()),
    }
}

/// Unsigned 31400 for the probe panel, signed by `pubkey`, which it also names
/// as the panel's registered probe agent.
pub fn panel_event(pubkey: &str, created_at: u64) -> UnsignedEvent {
    let mut tags = vec![vec!["d".to_string(), PANEL_D.to_string()]];
    tags.extend(probe_panel_properties().to_tags());
    tags.extend(
        PanelPolicy {
            max_pending_hours: PROBE_MAX_PENDING_HOURS,
            probe_agent: Some(pubkey.to_string()),
            ..PanelPolicy::default()
        }
        .to_tags(),
    );
    tags.push(vec!["t".into(), PROBE_TOPIC.into()]);
    UnsignedEvent {
        pubkey: pubkey.to_string(),
        created_at,
        kind: KIND_PANEL_DEFINITION,
        tags,
        content: serde_json::to_string(&panel_definition(pubkey)).unwrap_or_default(),
    }
}

/// Unsigned 31402 probe request on the probe panel. It declares the loosest
/// tier and carries no task properties of its own, so any tightening the relay
/// stamps is the panel's.
pub fn request_event(pubkey: &str, run: &ProbeRun, created_at: u64) -> UnsignedEvent {
    let request = ActionRequest {
        fields: json!({
            "probe_run": run.id(),
            "note": "Automated ADR-2011 M4 probe. Not a real decision; do not act on it.",
        }),
        reasoning: Some(
            "M4 probe: declares risk tier low on a panel whose operator declared the task \
             irreversible. The relay must stamp effective tier high and refuse any \
             non-human resolution."
                .into(),
        ),
        context_url: None,
        risk_tier: Some(DECLARED_TIER),
        confidence: None,
        task_properties: None,
        // The digest rides the tag only (ADR-2011 §6); it is not repeated in
        // content, where every REST and REQ reader would see it.
        probe: None,
    };
    UnsignedEvent {
        pubkey: pubkey.to_string(),
        created_at,
        kind: KIND_ACTION_REQUEST,
        tags: vec![
            vec!["d".into(), run.case_d()],
            vec!["a".into(), panel_coordinate(pubkey)],
            vec!["panel".into(), PANEL_D.into()],
            vec!["priority".into(), "low".into()],
            vec!["risk-tier".into(), DECLARED_TIER.as_str().into()],
            vec!["category".into(), "workflow_review".into()],
            vec!["subject-kind".into(), "m4-probe".into()],
            vec!["subject-id".into(), run.id().into()],
            vec![
                "title".into(),
                format!(
                    "{TITLE_PREFIX} · boundary probe {} · not a real decision",
                    run.id()
                ),
            ],
            vec!["t".into(), PROBE_TOPIC.into()],
            vec![TAG_PROBE.into(), run.probe_digest()],
        ],
        content: serde_json::to_string(&request).unwrap_or_default(),
    }
}

/// Unsigned 31403 by the probe agent approving its own probe case with a
/// `system:` decider and no rationale — every property ADR-2011 §4 refuses on
/// a high case. The suite expects the relay to refuse it.
pub fn response_event(
    pubkey: &str,
    run: &ProbeRun,
    request_event_id: &str,
    created_at: u64,
) -> UnsignedEvent {
    UnsignedEvent {
        pubkey: pubkey.to_string(),
        created_at,
        kind: KIND_ACTION_RESPONSE,
        tags: vec![
            vec!["d".into(), run.case_d()],
            vec!["e".into(), request_event_id.into()],
            vec!["a".into(), request_coordinate(pubkey, run)],
            vec!["t".into(), PROBE_TOPIC.into()],
        ],
        content: json!({
            "action": "approve",
            "reasoning": "",
            "decided_by": PROBE_DECIDER,
        })
        .to_string(),
    }
}

/// The rationale P09 carries: long enough for the FR2.2 gate, so the only
/// thing left to refuse it is the `system:` decider.
pub const SYSTEM_RATIONALE: &str =
    "ADR-2011 M4 probe: a non-human resolver must not close a high-tier case.";

/// Unsigned 31403 by the probe agent approving its probe case with a rationale
/// that satisfies FR2.2 but a `system:` decider. If admitted and stored, the
/// relay's projection must refuse to close the case (ADR-2011 §4).
pub fn system_response_event(
    pubkey: &str,
    run: &ProbeRun,
    request_event_id: &str,
    created_at: u64,
) -> UnsignedEvent {
    let mut ev = response_event(pubkey, run, request_event_id, created_at);
    ev.content = json!({
        "action": "approve",
        "reasoning": SYSTEM_RATIONALE,
        "decided_by": PROBE_DECIDER,
    })
    .to_string();
    ev
}

/// Unsigned NIP-09 kind-5 withdrawing this run's probe request.
///
/// `stored_responses` are ids of this run's 31403s the relay stored (P09 on an
/// admin signer); they are withdrawn with the request.
pub fn withdrawal_event(
    pubkey: &str,
    run: &ProbeRun,
    request_event_id: &str,
    stored_responses: &[String],
    created_at: u64,
) -> UnsignedEvent {
    let mut tags = vec![vec!["e".into(), request_event_id.into()]];
    tags.extend(
        stored_responses
            .iter()
            .map(|id| vec!["e".into(), id.clone()]),
    );
    tags.push(vec!["a".into(), request_coordinate(pubkey, run)]);
    tags.push(vec!["k".into(), KIND_ACTION_REQUEST.to_string()]);
    if !stored_responses.is_empty() {
        tags.push(vec!["k".into(), KIND_ACTION_RESPONSE.to_string()]);
    }
    UnsignedEvent {
        pubkey: pubkey.to_string(),
        created_at,
        kind: KIND_DELETION,
        tags,
        content: format!("withdrawn: ADR-2011 M4 probe run {} complete", run.id()),
    }
}

/// The outcome of one probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", content = "why", rename_all = "kebab-case")]
pub enum Verdict {
    /// The live surface did what ADR-2011 says it does.
    Pass,
    /// The live surface answered, and the answer contradicts ADR-2011.
    Fail(String),
    /// The probe could not be run; never counted as a pass.
    NotRun(String),
}

impl Verdict {
    /// Whether this is a pass.
    pub fn is_pass(&self) -> bool {
        matches!(self, Verdict::Pass)
    }

    fn check(ok: bool, why: impl FnOnce() -> String) -> Self {
        if ok {
            Verdict::Pass
        } else {
            Verdict::Fail(why())
        }
    }
}

/// One probe's receipt, written to `<out>/<id>.json`.
///
/// `request` records what was sent: the URL and body, or the signed event
/// (public by construction). A NIP-98 `Authorization` header is a bearer
/// token and is never recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeReceipt {
    /// Probe id, e.g. `P06`.
    pub id: String,
    /// What the probe asserts.
    pub title: String,
    /// The ADR-2011 clause it exercises.
    pub clause: String,
    /// UTC time the probe was sent, RFC 3339.
    pub at: String,
    /// What was sent.
    pub request: Value,
    /// What came back.
    pub response: Value,
    /// Ids of events published or observed by this probe.
    pub event_ids: Vec<String>,
    /// The outcome.
    pub verdict: Verdict,
}

/// Overall result of a suite run.
pub fn suite_passed(receipts: &[ProbeReceipt]) -> bool {
    !receipts.is_empty() && receipts.iter().all(|r| r.verdict.is_pass())
}

/// P01: NIP-11 advertises a valid default tier and the escalate-to-human
/// posture, with the agent control surface enabled.
pub fn judge_nip11(doc: &Value) -> Verdict {
    let nb = &doc["nostr_bbs"];
    let esc = &nb["escalation_defaults"];
    let tier = esc["default_escalation_tier"].as_str().unwrap_or("");
    let tiers: Vec<&str> = esc["risk_tiers"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let posture = esc["default_posture"].as_str().unwrap_or("");
    let enabled = nb["agent_control_surface"]["enabled"].as_bool() == Some(true);
    Verdict::check(
        !tier.is_empty() && tiers.contains(&tier) && posture == "escalate_to_human" && enabled,
        || format!("tier={tier:?} tiers={tiers:?} posture={posture:?} surface_enabled={enabled}"),
    )
}

/// P02: the reviewers route is deployed and gated. An unsigned read must be
/// refused with 401; a signed read must reach the handler — 403 for a
/// non-admin signer, or 200 with a `reviewers` array for an admin one. A 404
/// on the signed read means the route is not deployed.
pub fn judge_reviewers_route(
    unsigned_status: u16,
    signed_status: u16,
    signed_body: &Value,
) -> Verdict {
    if unsigned_status != 401 {
        return Verdict::Fail(format!("unsigned read answered {unsigned_status}, not 401"));
    }
    match signed_status {
        403 => Verdict::Pass,
        200 if signed_body["reviewers"].is_array() => Verdict::Pass,
        200 => Verdict::Fail(format!("200 without a reviewers array: {signed_body}")),
        404 => Verdict::Fail(format!("route not deployed: 404 {signed_body}")),
        401 => Verdict::Fail(format!("NIP-98 token not accepted: 401 {signed_body}")),
        s => Verdict::Fail(format!("unexpected {s} {signed_body}")),
    }
}

/// The exact refusal the auth worker returns for an unparseable stage
/// (`ApplicationRefusal::UnknownStage`). It exists only in ADR-2011 builds.
pub const UNKNOWN_STAGE_MESSAGE: &str =
    "stage must be one of consumer-received, applied, not-applied, applied-manually";

/// P03: posting an unknown stage to the application route is refused with
/// the ADR-2011 stage vocabulary, proving the route and its parser are live.
pub fn judge_application_unknown_stage(status: u16, body: &Value) -> Verdict {
    let msg = body["error"].as_str().unwrap_or("");
    Verdict::check(status == 400 && msg == UNKNOWN_STAGE_MESSAGE, || {
        format!("expected 400 {UNKNOWN_STAGE_MESSAGE:?}, got {status} {body}")
    })
}

/// P04/P05/P11: the relay accepted a publish.
pub fn judge_accepted(accepted: bool, message: &str) -> Verdict {
    Verdict::check(accepted, || format!("relay refused: {message:?}"))
}

/// P06: the probe case is projected with the operator's boundary, not the
/// agent's: effective `high` over a declared `low`, the irreversible triple
/// stored, still open, created by the probe agent, and no probe digest served.
pub fn judge_case_projection(case: &Value, run: &ProbeRun, agent_pubkey: &str) -> Verdict {
    let mut wrong = Vec::new();
    let want = |field: &str, got: &Value, expected: &str, wrong: &mut Vec<String>| {
        if got.as_str() != Some(expected) {
            wrong.push(format!("{field}={got} (want {expected:?})"));
        }
    };
    want("id", &case["id"], &run.case_d(), &mut wrong);
    want(
        "effective_tier",
        &case["effective_tier"],
        "high",
        &mut wrong,
    );
    want(
        "declared_tier",
        &case["declared_tier"],
        DECLARED_TIER.as_str(),
        &mut wrong,
    );
    want("state", &case["state"], "open", &mut wrong);
    want(
        "task_properties.reversibility",
        &case["task_properties"]["reversibility"],
        "irreversible",
        &mut wrong,
    );
    let created_by = case["created_by"].as_str().unwrap_or("");
    if !created_by.eq_ignore_ascii_case(agent_pubkey) {
        wrong.push(format!("created_by={created_by:?}"));
    }
    if !case["probe"].is_null() {
        wrong.push(format!(
            "probe served on an undecided case: {}",
            case["probe"]
        ));
    }
    if case.to_string().contains(&run.probe_digest()) {
        wrong.push("probe digest appears in the case projection".into());
    }
    Verdict::check(wrong.is_empty(), || wrong.join("; "))
}

/// P07: a `#probe` REQ finds nothing while a `#d` REQ for the same request
/// finds it — the probe is withheld from the tag index, not merely absent.
pub fn judge_probe_not_indexed(by_probe: usize, by_d: usize) -> Verdict {
    Verdict::check(by_probe == 0 && by_d >= 1, || {
        format!("#probe returned {by_probe} event(s); #d control returned {by_d}")
    })
}

/// P08: the agent's rationale-less 31403 on a high case is refused before
/// storage: `blocked:` (admission, non-admin signer) or `rationale_required`
/// (FR2.2 gate, admin signer).
pub fn judge_agent_response_refused(accepted: bool, message: &str) -> Verdict {
    if accepted {
        return Verdict::Fail(format!(
            "relay accepted a non-human 31403 on a high case: {message:?}"
        ));
    }
    Verdict::check(
        message.starts_with("blocked:") || message.contains("rationale_required"),
        || format!("refused for an unrelated reason: {message:?}"),
    )
}

/// P09: the `system:`-decider response is either refused outright or stored
/// for the projection to refuse; P10 asserts the projection did refuse it.
/// Any other refusal means the probe did not reach the rule it targets.
pub fn judge_system_response(accepted: bool, message: &str) -> Verdict {
    Verdict::check(
        accepted || message.starts_with("blocked:") || message.contains("rationale_required"),
        || format!("refused for an unrelated reason: {message:?}"),
    )
}

/// P10: after both responses the case is still open and undecided.
pub fn judge_case_unchanged(case: &Value) -> Verdict {
    Verdict::check(
        case["state"].as_str() == Some("open") && case["probe"].is_null(),
        || format!("state={} probe={}", case["state"], case["probe"]),
    )
}

/// RFC 3339 UTC timestamp for `secs` since the Unix epoch.
pub fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_bbs_core::governance::{effective_tier, extract_tag, is_governance_kind};

    const PK: &str = "6d6f636b6d6f636b6d6f636b6d6f636b6d6f636b6d6f636b6d6f636b6d6f636b";

    fn run() -> ProbeRun {
        ProbeRun::new("20261002t131500z").unwrap()
    }

    #[test]
    fn run_ids_are_constrained() {
        assert!(ProbeRun::new("").is_err());
        assert!(ProbeRun::new("UPPER").is_err());
        assert!(ProbeRun::new("has space").is_err());
        assert!(ProbeRun::new(&"a".repeat(41)).is_err());
        assert!(ProbeRun::new(&"a".repeat(40)).is_ok());
    }

    #[test]
    fn probe_digest_is_stable_hex_and_run_scoped() {
        let a = run().probe_digest();
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(a, run().probe_digest());
        assert_ne!(a, ProbeRun::new("other").unwrap().probe_digest());
    }

    #[test]
    fn panel_declares_the_triple_and_names_the_probe_agent() {
        let ev = panel_event(PK, 1);
        assert_eq!(ev.kind, KIND_PANEL_DEFINITION);
        assert_eq!(extract_tag(&ev.tags, "d"), Some(PANEL_D));
        assert_eq!(
            TaskProperties::from_tags(&ev.tags),
            Some(probe_panel_properties())
        );
        let policy = PanelPolicy::from_tags(&ev.tags);
        assert!(policy.is_probe_agent(PK));
        assert_eq!(policy.max_pending_hours, PROBE_MAX_PENDING_HOURS);
        assert_eq!(extract_tag(&ev.tags, "t"), Some(PROBE_TOPIC));
        let def: PanelDefinition = serde_json::from_str(&ev.content).unwrap();
        assert!(def.title.starts_with(TITLE_PREFIX));
    }

    #[test]
    fn panel_triple_floors_a_low_request_at_high() {
        let panel = probe_panel_properties();
        let req = request_event(PK, &run(), 1);
        let tier = effective_tier(
            Some(&panel),
            TaskProperties::from_tags(&req.tags).as_ref(),
            Some(DECLARED_TIER),
            RiskTier::Medium,
        );
        assert_eq!(tier, RiskTier::High);
    }

    #[test]
    fn request_is_identifiable_and_addressed_to_the_probe_panel() {
        let r = run();
        let ev = request_event(PK, &r, 1);
        assert_eq!(ev.kind, KIND_ACTION_REQUEST);
        assert!(is_governance_kind(ev.kind));
        assert_eq!(extract_tag(&ev.tags, "d"), Some(r.case_d().as_str()));
        assert_eq!(
            extract_tag(&ev.tags, "a"),
            Some(panel_coordinate(PK).as_str())
        );
        assert_eq!(
            extract_tag(&ev.tags, TAG_PROBE),
            Some(r.probe_digest().as_str())
        );
        assert_eq!(extract_tag(&ev.tags, "risk-tier"), Some("low"));
        assert!(extract_tag(&ev.tags, "title")
            .unwrap()
            .starts_with(TITLE_PREFIX));
        // No triple on the request: any tightening must come from the panel.
        assert_eq!(TaskProperties::from_tags(&ev.tags), None);
        // The digest is not echoed into content.
        assert!(!ev.content.contains(&r.probe_digest()));
        let req: ActionRequest = serde_json::from_str(&ev.content).unwrap();
        assert_eq!(req.risk_tier, Some(RiskTier::Low));
    }

    #[test]
    fn response_carries_every_property_section_4_refuses() {
        let r = run();
        let ev = response_event(PK, &r, &"e".repeat(64), 2);
        assert_eq!(ev.kind, KIND_ACTION_RESPONSE);
        assert_eq!(extract_tag(&ev.tags, "d"), Some(r.case_d().as_str()));
        let v: Value = serde_json::from_str(&ev.content).unwrap();
        assert_eq!(v["action"], "approve");
        assert_eq!(v["reasoning"], "");
        assert!(v["decided_by"].as_str().unwrap().starts_with("system:"));
    }

    #[test]
    fn withdrawal_targets_only_this_runs_request() {
        let r = run();
        let ev = withdrawal_event(PK, &r, &"e".repeat(64), &[], 3);
        assert_eq!(ev.kind, KIND_DELETION);
        assert_eq!(extract_tag(&ev.tags, "e"), Some("e".repeat(64).as_str()));
        let with = withdrawal_event(PK, &r, &"e".repeat(64), &["f".repeat(64)], 3);
        let es: Vec<&str> = with
            .tags
            .iter()
            .filter(|t| t[0] == "e")
            .map(|t| t[1].as_str())
            .collect();
        assert_eq!(es, vec!["e".repeat(64), "f".repeat(64)]);
        assert!(with.tags.iter().any(|t| t[0] == "k" && t[1] == "31403"));
        assert_eq!(
            extract_tag(&ev.tags, "a"),
            Some(request_coordinate(PK, &r).as_str())
        );
        assert_eq!(extract_tag(&ev.tags, "k"), Some("31402"));
    }

    #[test]
    fn nip11_judgement() {
        let good = json!({"nostr_bbs": {
            "agent_control_surface": {"enabled": true},
            "escalation_defaults": {"default_escalation_tier": "medium",
                "default_posture": "escalate_to_human",
                "risk_tiers": ["low","medium","high","critical"]}}});
        assert!(judge_nip11(&good).is_pass());
        let mut bad = good.clone();
        bad["nostr_bbs"]["escalation_defaults"]["default_escalation_tier"] = json!("bogus");
        assert!(!judge_nip11(&bad).is_pass());
        assert!(!judge_nip11(&json!({})).is_pass());
    }

    #[test]
    fn reviewers_judgement_distinguishes_absent_from_gated() {
        let rows = json!({"reviewers": [], "decisions_considered": 0});
        assert!(judge_reviewers_route(401, 403, &json!({})).is_pass());
        assert!(judge_reviewers_route(401, 200, &rows).is_pass());
        assert!(matches!(
            judge_reviewers_route(401, 404, &json!({})),
            Verdict::Fail(w) if w.contains("not deployed")
        ));
        // An ungated route fails even if the signed read looks right.
        assert!(!judge_reviewers_route(200, 200, &rows).is_pass());
        assert!(!judge_reviewers_route(401, 200, &json!({})).is_pass());
        assert!(!judge_reviewers_route(401, 401, &json!({})).is_pass());
    }

    #[test]
    fn system_response_passes_fr2_2_and_names_a_system_decider() {
        let r = run();
        let ev = system_response_event(PK, &r, &"e".repeat(64), 2);
        let v: Value = serde_json::from_str(&ev.content).unwrap();
        assert!(v["reasoning"].as_str().unwrap().trim().chars().count() >= 20);
        assert!(v["decided_by"].as_str().unwrap().starts_with("system:"));
        assert!(judge_system_response(true, "").is_pass());
        assert!(
            judge_system_response(false, "blocked: admin-only governance action response")
                .is_pass()
        );
        assert!(!judge_system_response(false, "error: failed to save event").is_pass());
    }

    #[test]
    fn application_judgement_requires_the_exact_stage_refusal() {
        assert!(
            judge_application_unknown_stage(400, &json!({"error": UNKNOWN_STAGE_MESSAGE}))
                .is_pass()
        );
        assert!(!judge_application_unknown_stage(404, &json!({"error": "not found"})).is_pass());
        assert!(!judge_application_unknown_stage(400, &json!({"error": "bad body"})).is_pass());
    }

    fn projected(r: &ProbeRun) -> Value {
        json!({"id": r.case_d(), "state": "open", "created_by": PK,
               "effective_tier": "high", "declared_tier": "low",
               "task_properties": {"verifiability": "inspectable",
                   "reversibility": "irreversible", "stakes": "significant"},
               "probe": null})
    }

    #[test]
    fn case_projection_judgement() {
        let r = run();
        assert!(judge_case_projection(&projected(&r), &r, PK).is_pass());
        assert!(judge_case_projection(&projected(&r), &r, &PK.to_uppercase()).is_pass());

        let mut agent_tier = projected(&r);
        agent_tier["effective_tier"] = json!("low");
        assert!(!judge_case_projection(&agent_tier, &r, PK).is_pass());

        let mut pre_0006 = projected(&r);
        pre_0006["effective_tier"] = Value::Null;
        assert!(!judge_case_projection(&pre_0006, &r, PK).is_pass());

        let mut leaked = projected(&r);
        leaked["probe"] = json!(r.probe_digest());
        assert!(!judge_case_projection(&leaked, &r, PK).is_pass());

        let mut leaked_elsewhere = projected(&r);
        leaked_elsewhere["summary"] = json!(r.probe_digest());
        assert!(!judge_case_projection(&leaked_elsewhere, &r, PK).is_pass());
    }

    #[test]
    fn probe_index_judgement_needs_the_control() {
        assert!(judge_probe_not_indexed(0, 1).is_pass());
        assert!(!judge_probe_not_indexed(1, 1).is_pass());
        // An empty control means the query proved nothing.
        assert!(!judge_probe_not_indexed(0, 0).is_pass());
    }

    #[test]
    fn agent_response_judgement() {
        assert!(judge_agent_response_refused(
            false,
            "blocked: admin-only governance action response"
        )
        .is_pass());
        assert!(judge_agent_response_refused(false, "rationale_required: …").is_pass());
        assert!(!judge_agent_response_refused(true, "").is_pass());
        assert!(!judge_agent_response_refused(false, "rate-limited").is_pass());
    }

    #[test]
    fn unchanged_judgement() {
        let r = run();
        assert!(judge_case_unchanged(&projected(&r)).is_pass());
        let mut decided = projected(&r);
        decided["state"] = json!("decided");
        assert!(!judge_case_unchanged(&decided).is_pass());
    }

    #[test]
    fn not_run_is_never_green() {
        let rec = |v: Verdict| ProbeReceipt {
            id: "P".into(),
            title: String::new(),
            clause: String::new(),
            at: String::new(),
            request: Value::Null,
            response: Value::Null,
            event_ids: vec![],
            verdict: v,
        };
        assert!(suite_passed(&[rec(Verdict::Pass)]));
        assert!(!suite_passed(&[
            rec(Verdict::Pass),
            rec(Verdict::NotRun("x".into()))
        ]));
        assert!(!suite_passed(&[]));
    }

    #[test]
    fn rfc3339_matches_known_instants() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_790_946_611), "2026-10-02T13:10:11Z");
    }

    #[test]
    fn verdict_serialises_tagged() {
        assert_eq!(
            serde_json::to_value(Verdict::Fail("x".into())).unwrap(),
            json!({"verdict": "fail", "why": "x"})
        );
        assert_eq!(
            serde_json::to_value(Verdict::Pass).unwrap(),
            json!({"verdict": "pass"})
        );
    }
}
