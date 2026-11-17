//! Golden-file contract for the governance event kinds 31400-31405.
//!
//! This crate is the single author of the governance wire contract. The files
//! under `contracts/governance/v1/` at the repository root are that contract
//! rendered as data, for consumers that cannot link this crate (agentbox is
//! JavaScript). This test builds one fully populated, deterministic example of
//! each kind with the crate's own types, validates it with the crate's own
//! validator, and compares it byte-for-byte with the checked-in file.
//!
//! * A stale or missing file fails the test.
//! * `UPDATE_GOVERNANCE_CONTRACT=1 cargo test -p nostr-bbs-core --test governance_contract_golden`
//!   regenerates every file.
//!
//! Keys and timestamps are fixed and signatures use zero aux randomness, so the
//! output is reproducible and a diff shows only what really changed.

use nostr_bbs_core::event::{sign_event_deterministic, verify_event, NostrEvent, UnsignedEvent};
use nostr_bbs_core::governance::broker::{CaseCategory, DecisionOutcome, SubjectKind};
use nostr_bbs_core::governance::{
    self, check_rationale, extract_d_tag, extract_tag, outcome_requires_rationale,
    validate_governance_event, ActionDef, ActionPriority, ActionRequest, ActionStyle, FieldDef,
    FieldType, LayoutHint, PanelCapability, PanelDefinition, PanelSchema, ReceiptStage,
    Reversibility, RiskTier, Stakes, TaskProperties, Verifiability,
};
use nostr_bbs_core::keys::signing_key_from_bytes;
use serde::Serialize;
use serde_json::{json, Value};
use std::path::PathBuf;

/// The agent key used by the crate's own fixtures (all-`0x11`).
const AGENT_SECRET: [u8; 32] = [0x11; 32];
/// The human key used by the crate's own fixtures (all-`0x22`).
const HUMAN_SECRET: [u8; 32] = [0x22; 32];
/// 2026-09-22T12:00:00Z, the instant the crate's own fixtures use.
const NOW: u64 = 1_790_078_400;

const PANEL_ID: &str = "ontology-governance";
const CASE_ID: &str = "urn:agentbox:thing:golden:proposal-0123456789ab";
const IRI: &str = "urn:ngm:class:golden-example";
const HUMAN_RATIONALE: &str =
    "The definition matches the cited sources and the diff is limited to the stated page.";

fn contract_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/governance/v1")
        .components()
        .collect()
}

fn signed(
    secret: [u8; 32],
    kind: u64,
    created_at: u64,
    tags: Vec<Vec<String>>,
    content: String,
) -> NostrEvent {
    let sk = signing_key_from_bytes(&secret).expect("valid fixture secret");
    let pubkey = hex::encode(sk.verifying_key().to_bytes());
    let event = sign_event_deterministic(
        UnsignedEvent {
            pubkey,
            created_at,
            kind,
            tags,
            content,
        },
        &sk,
    )
    .expect("key matches pubkey");
    assert!(verify_event(&event), "kind {kind} fixture must verify");
    validate_governance_event(&event).expect("kind {kind} fixture must pass the crate validator");
    event
}

fn tag(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

fn to_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("serialisable")
}

fn pubkey_of(secret: [u8; 32]) -> String {
    let sk = signing_key_from_bytes(&secret).unwrap();
    hex::encode(sk.verifying_key().to_bytes())
}

fn task_properties() -> TaskProperties {
    TaskProperties::new(
        Verifiability::Partial,
        Reversibility::Compensable,
        Stakes::Significant,
    )
}

fn panel_definition() -> NostrEvent {
    let panel = PanelDefinition {
        title: "Ontology governance".into(),
        description: "Human decisions on proposed changes to the shared ontology.".into(),
        version: "1.0.0".into(),
        schema: PanelSchema::ActionInbox,
        fields: vec![
            FieldDef {
                name: "term".into(),
                field_type: FieldType::String,
                label: "Term".into(),
            },
            FieldDef {
                name: "score".into(),
                field_type: FieldType::Float,
                label: "Score".into(),
            },
        ],
        actions: vec![
            ActionDef {
                id: "promote".into(),
                label: "Promote".into(),
                style: ActionStyle::Primary,
            },
            ActionDef {
                id: "reject".into(),
                label: "Reject".into(),
                style: ActionStyle::Destructive,
            },
        ],
        layout: LayoutHint::InboxTable,
        capabilities: vec![PanelCapability::Filter, PanelCapability::Search],
        refresh_secs: 30,
        task_properties: Some(task_properties()),
        calibration_sample_rate: Some(0.25),
        max_pending_hours: Some(48),
        probe_agent: Some(pubkey_of(AGENT_SECRET)),
    };
    let mut tags = vec![tag(&["d", PANEL_ID])];
    tags.extend(task_properties().to_tags());
    tags.extend(panel.policy().to_tags());
    signed(
        AGENT_SECRET,
        governance::KIND_PANEL_DEFINITION,
        NOW,
        tags,
        to_json(&panel),
    )
}

fn panel_state() -> NostrEvent {
    let state = canonical(
        &json!({ "open_cases": 1, "decided_cases": 0, "last_scan": "2026-09-22T11:59:00Z" }),
    );
    signed(
        AGENT_SECRET,
        governance::KIND_PANEL_STATE,
        NOW + 1,
        vec![tag(&["d", PANEL_ID])],
        state.to_string(),
    )
}

fn action_request() -> NostrEvent {
    let request = ActionRequest {
        fields: canonical(&json!({
            "term": "Golden example",
            "score": 0.92,
            "proposal_urn": CASE_ID,
            "propose_iri": IRI,
        })),
        reasoning: Some("Three independent notes define the term identically.".into()),
        context_url: Some(IRI.into()),
        risk_tier: Some(RiskTier::High),
        confidence: Some(0.75),
        task_properties: Some(task_properties()),
        probe: None,
    };
    let mut tags = vec![
        tag(&["d", CASE_ID]),
        tag(&[
            "a",
            &format!("31400:{}:{PANEL_ID}", pubkey_of(AGENT_SECRET)),
        ]),
        tag(&["priority", "high"]),
        tag(&["category", "knowledge_enrichment"]),
        tag(&["subject-kind", "opaque"]),
        tag(&["subject-id", IRI]),
        tag(&["title", "Promote Golden example"]),
        tag(&["risk-tier", "high"]),
        tag(&["context_url", IRI]),
    ];
    tags.extend(task_properties().to_tags());
    signed(
        AGENT_SECRET,
        governance::KIND_ACTION_REQUEST,
        NOW + 2,
        tags,
        to_json(&request),
    )
}

fn action_response(request_id: &str) -> NostrEvent {
    // The signed human decision names its subject and carries the human's own
    // words; `DecisionOutcome` is internally tagged and ignores the extras.
    let mut content = serde_json::to_value(DecisionOutcome::Promote { iri: IRI.into() }).unwrap();
    let map = content.as_object_mut().unwrap();
    map.insert("case_id".into(), json!(CASE_ID));
    map.insert("reasoning".into(), json!(HUMAN_RATIONALE));
    let content = canonical(&content).to_string();

    // The same rules the relay applies, run over what the fixture contains.
    let parsed = DecisionOutcome::from_response_content(&content).expect("outcome parses");
    assert_eq!(parsed.action_str(), "promote");
    assert!(outcome_requires_rationale(parsed.action_str()));
    check_rationale(RiskTier::High, parsed.action_str(), Some(HUMAN_RATIONALE))
        .expect("fixture rationale satisfies the minimum");

    signed(
        HUMAN_SECRET,
        governance::KIND_ACTION_RESPONSE,
        NOW + 60,
        vec![tag(&["d", CASE_ID]), tag(&["e", request_id])],
        content,
    )
}

fn panel_update() -> NostrEvent {
    let diff = canonical(&json!({ "open_cases": 0, "decided_cases": 1 }));
    signed(
        AGENT_SECRET,
        governance::KIND_PANEL_UPDATE,
        NOW + 120,
        vec![tag(&["d", PANEL_ID])],
        diff.to_string(),
    )
}

fn panel_retired() -> NostrEvent {
    signed(
        AGENT_SECRET,
        governance::KIND_PANEL_RETIRED,
        NOW + 180,
        vec![tag(&["d", PANEL_ID])],
        String::new(),
    )
}

/// Rebuild a JSON value with every object's keys in sorted order.
///
/// `serde_json` keeps object keys sorted by default, but any crate in the same
/// build that turns on its `preserve_order` feature switches every `Map` to
/// insertion order. Cargo unifies features across a workspace, so a
/// `--workspace` test run would otherwise produce differently ordered files
/// from a `-p nostr-bbs-core` run. Sorting here makes the golden text the same
/// in every build.
fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), canonical(&map[k]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

/// Render an event as the golden file's text: pretty JSON with sorted keys,
/// trailing newline.
fn render(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(&canonical(value)).expect("serialisable");
    text.push('\n');
    text
}

fn strings<T, F: Fn(&T) -> String>(items: &[T], f: F) -> Vec<String> {
    items.iter().map(f).collect()
}

fn serde_name<T: Serialize>(v: &T) -> String {
    match serde_json::to_value(v).expect("serialisable") {
        Value::String(s) => s,
        other => other.to_string(),
    }
}

fn manifest(files: &[(u64, &str, &str)]) -> Value {
    let kinds: Vec<Value> = files
        .iter()
        .map(|(kind, name, publisher)| {
            let (required_tags, optional_tags, content_required, content_optional): (
                Vec<&str>,
                Vec<&str>,
                Vec<&str>,
                Vec<&str>,
            ) = match *kind {
                governance::KIND_PANEL_DEFINITION => (
                    vec!["d"],
                    vec![
                        "tp-verifiability",
                        "tp-reversibility",
                        "tp-stakes",
                        "calibration-sample-rate",
                        "max-pending-hours",
                        "probe-agent",
                    ],
                    vec![
                        "title",
                        "description",
                        "schema",
                        "fields",
                        "actions",
                        "layout",
                    ],
                    vec![
                        "version",
                        "capabilities",
                        "refresh_secs",
                        "task_properties",
                        "calibration_sample_rate",
                        "max_pending_hours",
                        "probe_agent",
                    ],
                ),
                governance::KIND_ACTION_REQUEST => (
                    vec!["d"],
                    vec![
                        "a",
                        "priority",
                        "category",
                        "subject-kind",
                        "subject-id",
                        "title",
                        "risk-tier",
                        "context_url",
                        "tp-verifiability",
                        "tp-reversibility",
                        "tp-stakes",
                        "probe",
                    ],
                    vec!["fields"],
                    vec![
                        "reasoning",
                        "context_url",
                        "risk_tier",
                        "confidence",
                        "task_properties",
                        "probe",
                    ],
                ),
                governance::KIND_ACTION_RESPONSE => (
                    vec!["d", "e"],
                    vec![],
                    vec!["action"],
                    vec![
                        "reasoning",
                        "case_id",
                        "iri",
                        "diff",
                        "delegate_to",
                        "scope",
                    ],
                ),
                governance::KIND_PANEL_STATE | governance::KIND_PANEL_UPDATE => {
                    (vec!["d"], vec![], vec![], vec![])
                }
                _ => (vec!["d"], vec![], vec![], vec![]),
            };
            json!({
                "kind": kind,
                "name": name,
                "publisher": publisher,
                "file": format!("{kind}-{name}.json"),
                "required_tags": required_tags,
                "optional_tags": optional_tags,
                "content_required": content_required,
                "content_optional": content_optional,
            })
        })
        .collect();

    let outcomes = [
        DecisionOutcome::Approve,
        DecisionOutcome::Reject,
        DecisionOutcome::Amend {
            diff: String::new(),
        },
        DecisionOutcome::Delegate {
            delegate_to: String::new(),
        },
        DecisionOutcome::Promote { iri: String::new() },
        DecisionOutcome::Demote { iri: String::new() },
        DecisionOutcome::Precedent {
            scope: String::new(),
        },
    ];
    let decision_actions: Vec<&str> = outcomes.iter().map(|o| o.action_str()).collect();
    let rationale_actions: Vec<&str> = decision_actions
        .iter()
        .copied()
        .filter(|a| outcome_requires_rationale(a))
        .collect();

    json!({
        "contract": "governance",
        "version": 1,
        "kind_range": { "min": *governance::GOVERNANCE_KIND_RANGE.start(), "max": *governance::GOVERNANCE_KIND_RANGE.end() },
        "kinds": kinds,
        "enums": {
            "panel_schemas": strings(&[PanelSchema::ActionInbox, PanelSchema::Dashboard, PanelSchema::ConfigForm, PanelSchema::StatusBoard, PanelSchema::ChatBridge], serde_name),
            "panel_capabilities": strings(&[PanelCapability::BulkAction, PanelCapability::Filter, PanelCapability::Search, PanelCapability::Sort, PanelCapability::Export], serde_name),
            "field_types": strings(&[FieldType::String, FieldType::Int, FieldType::Float, FieldType::Bool, FieldType::Json, FieldType::Enum, FieldType::Timestamp], serde_name),
            "action_styles": strings(&[ActionStyle::Primary, ActionStyle::Secondary, ActionStyle::Destructive], serde_name),
            "layout_hints": strings(&[LayoutHint::InboxTable, LayoutHint::Kanban, LayoutHint::CardGrid, LayoutHint::SplitDetail], serde_name),
            "action_priorities": strings(&[ActionPriority::Critical, ActionPriority::High, ActionPriority::Medium, ActionPriority::Low], serde_name),
            "risk_tiers": ([RiskTier::Low, RiskTier::Medium, RiskTier::High, RiskTier::Critical].map(RiskTier::as_str)),
            "verifiability": ([Verifiability::Inspectable, Verifiability::Partial, Verifiability::Opaque].map(Verifiability::as_str)),
            "reversibility": ([Reversibility::Reversible, Reversibility::Compensable, Reversibility::Irreversible].map(Reversibility::as_str)),
            "stakes": ([Stakes::Bounded, Stakes::Significant, Stakes::Critical].map(Stakes::as_str)),
            "decision_actions": decision_actions,
            "case_categories": strings(&[CaseCategory::ContributorMeshShare, CaseCategory::WorkflowReview, CaseCategory::PolicyException, CaseCategory::TrustAlert, CaseCategory::ManualSubmission, CaseCategory::KnowledgeEnrichment], serde_name),
            "subject_kinds": strings(&[SubjectKind::WorkArtifact, SubjectKind::SkillPackage, SubjectKind::AutomationProposal, SubjectKind::PolicyException, SubjectKind::Opaque], serde_name),
            "receipt_stages": ([
                ReceiptStage::Signed, ReceiptStage::RelayAccepted, ReceiptStage::ProjectionCommitted,
                ReceiptStage::ProjectionFailed, ReceiptStage::ConsumerReceived, ReceiptStage::Applied,
                ReceiptStage::NotApplied, ReceiptStage::AppliedManually, ReceiptStage::EscalatedOnAge,
                ReceiptStage::Expired,
            ].map(ReceiptStage::as_str)),
        },
        "rules": {
            "min_human_rationale_chars": governance::MIN_HUMAN_RATIONALE_CHARS,
            "rationale_required_tiers": ["high", "critical"],
            "rationale_required_actions": rationale_actions,
            "default_calibration_sample_rate": governance::DEFAULT_CALIBRATION_SAMPLE_RATE.to_string().parse::<f64>().unwrap(),
            "default_max_pending_hours": governance::DEFAULT_MAX_PENDING_HOURS,
            "d_tag_required_non_empty": true,
            "response_binds_request_by": "e tag carrying the 31402 event id; d tag equals the 31402 d tag (the case id)",
        },
        "tag_names": {
            "task_verifiability": governance::TAG_TP_VERIFIABILITY,
            "task_reversibility": governance::TAG_TP_REVERSIBILITY,
            "task_stakes": governance::TAG_TP_STAKES,
            "calibration_sample_rate": governance::TAG_CALIBRATION_SAMPLE_RATE,
            "max_pending_hours": governance::TAG_MAX_PENDING_HOURS,
            "probe_agent": governance::TAG_PROBE_AGENT,
            "probe": governance::TAG_PROBE,
        },
        "fixture_keys": {
            "agent_pubkey": pubkey_of(AGENT_SECRET),
            "human_pubkey": pubkey_of(HUMAN_SECRET),
        },
    })
}

/// Every governance kind with a deterministic example, as `(kind, name, publisher, event)`.
fn examples() -> Vec<(u64, &'static str, &'static str, NostrEvent)> {
    let request = action_request();
    let response = action_response(&request.id);
    // The response must bind to the request exactly as the apply path checks.
    assert_eq!(extract_tag(&response.tags, "e"), Some(request.id.as_str()));
    assert_eq!(extract_d_tag(&response.tags), extract_d_tag(&request.tags));
    vec![
        (
            governance::KIND_PANEL_DEFINITION,
            "panel-definition",
            "agent",
            panel_definition(),
        ),
        (
            governance::KIND_PANEL_STATE,
            "panel-state",
            "agent",
            panel_state(),
        ),
        (
            governance::KIND_ACTION_REQUEST,
            "action-request",
            "agent",
            request,
        ),
        (
            governance::KIND_ACTION_RESPONSE,
            "action-response",
            "human",
            response,
        ),
        (
            governance::KIND_PANEL_UPDATE,
            "panel-update",
            "agent",
            panel_update(),
        ),
        (
            governance::KIND_PANEL_RETIRED,
            "panel-retired",
            "agent",
            panel_retired(),
        ),
    ]
}

#[test]
fn governance_golden_files_match_the_crate() {
    let update = std::env::var("UPDATE_GOVERNANCE_CONTRACT").map_or(false, |v| v == "1");
    let dir = contract_dir();
    let examples = examples();

    let mut expected: Vec<(String, String)> = examples
        .iter()
        .map(|(kind, name, _, event)| {
            let value = serde_json::to_value(event).expect("event serialises");
            (format!("{kind}-{name}.json"), render(&value))
        })
        .collect();
    let index: Vec<(u64, &str, &str)> = examples.iter().map(|(k, n, p, _)| (*k, *n, *p)).collect();
    expected.push(("manifest.json".into(), render(&manifest(&index))));

    if update {
        std::fs::create_dir_all(&dir).expect("create contracts dir");
        for (file, text) in &expected {
            std::fs::write(dir.join(file), text).expect("write golden file");
        }
        return;
    }

    let mut stale = Vec::new();
    for (file, text) in &expected {
        match std::fs::read_to_string(dir.join(file)) {
            Ok(on_disk) if on_disk == *text => {}
            Ok(_) => stale.push(format!("{file}: differs from the crate")),
            Err(e) => stale.push(format!("{file}: unreadable ({e})")),
        }
    }
    assert!(
        stale.is_empty(),
        "governance contract golden files are stale; run with UPDATE_GOVERNANCE_CONTRACT=1 to regenerate:\n{}",
        stale.join("\n")
    );
}

#[test]
fn governance_examples_cover_every_kind_exactly_once() {
    let kinds: Vec<u64> = examples().iter().map(|(k, _, _, _)| *k).collect();
    let expected: Vec<u64> = governance::GOVERNANCE_KIND_RANGE.collect();
    assert_eq!(kinds, expected);
}

#[test]
fn governance_response_rationale_is_at_least_the_minimum() {
    assert!(HUMAN_RATIONALE.chars().count() >= governance::MIN_HUMAN_RATIONALE_CHARS);
    assert!(check_rationale(RiskTier::High, "promote", Some("too short")).is_err());
}
