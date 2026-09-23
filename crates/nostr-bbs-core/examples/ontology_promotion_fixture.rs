//! Emit the signed events the ontology-promotion loop is exercised with
//! (ADR-2013), as one JSON document on stdout.
//!
//! This is the *driver* for `scripts/e2e-ontology-promotion.sh`: it is the one
//! place a real BIP-340 signature is produced, and it computes the effective
//! tier with the same `governance::effective_tier` the relay calls, so the
//! script never has to reimplement a rule in order to assert it.
//!
//! The keys are deterministic all-`0x11`/all-`0x22` secrets and the signatures
//! use zero aux randomness, so the whole fixture is byte-reproducible: a
//! reviewer can diff two runs and see only what actually changed.
//!
//! ```sh
//! cargo run -q -p nostr-bbs-core --example ontology_promotion_fixture
//! ```
//!
//! # `--from-request <file>`: decide a REAL proposal
//!
//! Given a file holding `vault propose --dry-run --json` output (or a bare
//! 31402 event), the example instead verifies that 31402's BIP-340 signature,
//! computes its effective tier from ITS OWN tags against the canonical panel,
//! and signs one human 31403 per decision — `promote`, `demote`, `reject` —
//! bound to the request's `d` tag (the case id) and event id. This is how the
//! e2e script's real-vault mode drives the apply path with a decision about a
//! proposal the real `vault` built, rather than about a hand-written one.
//!
//! ```sh
//! cargo run -q -p nostr-bbs-core --example ontology_promotion_fixture -- \
//!     --from-request proposal.json
//! ```

use k256::schnorr::SigningKey;
use nostr_bbs_core::event::{sign_event_deterministic, verify_event, UnsignedEvent};
use nostr_bbs_core::governance::{self, RiskTier, TaskProperties};
use nostr_bbs_core::keys::signing_key_from_bytes;
use nostr_bbs_core::ontology_governance as og;

/// The test IRI. Deliberately namespaced `test` so it can never collide with a
/// real corpus page even if a fixture escapes into a live relay.
const TEST_IRI: &str = "urn:ngm:class:test-e2e-promotion";
const TEST_PAGE: &str = "Test E2E Promotion";

/// The agent that proposes. In production this is `process:vault/1.0`.
const AGENT_SECRET: [u8; 32] = [0x11; 32];
/// The human who signs the decision.
const HUMAN_SECRET: [u8; 32] = [0x22; 32];

/// A fixed instant so the fixture is reproducible: 2026-09-22T12:00:00Z.
const NOW: u64 = 1_790_078_400;

fn key(secret: [u8; 32]) -> (SigningKey, String) {
    let sk = signing_key_from_bytes(&secret).expect("valid test secret");
    let pk = hex::encode(sk.verifying_key().to_bytes());
    (sk, pk)
}

fn patch_proposal(level: &str, stale_after: &str) -> String {
    serde_json::json!({
        "level": level,
        "iri": TEST_IRI,
        "page": TEST_PAGE,
        "hypothesis": "The e2e fixture page is stable enough to publish.",
        "diff": "-status: draft\n+status: stable\n",
        "digest": "sha256:e2e0000000000000000000000000000000000000000000000000000000000000",
        "blockers": [],
        "proposer": "process:vault/1.0",
        "generation": "visionGraph@e2efixture",
        "stale_after": stale_after,
    })
    .to_string()
}

/// The 31400 the operator publishes, as tags.
fn panel_tags() -> Vec<Vec<String>> {
    let panel = og::ontology_governance_panel();
    let mut tags = vec![vec!["d".into(), og::PANEL_ONTOLOGY_GOVERNANCE.into()]];
    tags.extend(panel.task_properties.unwrap().to_tags());
    tags.extend(panel.policy().to_tags());
    tags
}

/// A 31402 ActionRequest carrying a `PatchProposal` (contract C4/C5).
fn action_request(
    sk: &SigningKey,
    pubkey: &str,
    case_id: &str,
    level: &str,
    stale_after: &str,
) -> nostr_bbs_core::event::NostrEvent {
    let unsigned = UnsignedEvent {
        pubkey: pubkey.to_string(),
        created_at: NOW,
        kind: governance::KIND_ACTION_REQUEST,
        tags: vec![
            // C5: the `d` tag IS the case id and the proposal digest.
            vec!["d".into(), case_id.into()],
            vec![
                "a".into(),
                format!("31400:{pubkey}:{}", og::PANEL_ONTOLOGY_GOVERNANCE),
            ],
            vec![og::TAG_CONTEXT_URL.into(), TEST_IRI.into()],
            vec![og::TAG_LEVEL.into(), level.into()],
            vec!["category".into(), "knowledge_enrichment".into()],
            vec!["subject-kind".into(), "opaque".into()],
            vec!["subject-id".into(), TEST_IRI.into()],
            vec!["title".into(), format!("Promote {TEST_PAGE}")],
            // The agent under-declares on purpose: the whole point of the
            // tiering rule is that this cannot lower the boundary.
            vec!["risk-tier".into(), "low".into()],
        ],
        content: patch_proposal(level, stale_after),
    };
    sign_event_deterministic(unsigned, sk).expect("agent key matches pubkey")
}

/// A 31403 ActionResponse: the human's signed decision.
fn action_response(
    sk: &SigningKey,
    pubkey: &str,
    case_id: &str,
    request_id: &str,
    outcome: serde_json::Value,
) -> nostr_bbs_core::event::NostrEvent {
    let unsigned = UnsignedEvent {
        pubkey: pubkey.to_string(),
        created_at: NOW + 60,
        kind: governance::KIND_ACTION_RESPONSE,
        tags: vec![
            vec!["d".into(), case_id.into()],
            vec!["e".into(), request_id.into()],
        ],
        content: outcome.to_string(),
    };
    sign_event_deterministic(unsigned, sk).expect("human key matches pubkey")
}

/// The effective tier of a 31402 as the relay computes it: the canonical
/// panel's properties, merged tightening-only with the request's own
/// properties and its `level` floor, against the agent's declared tier.
fn tier_of(request_tags: &[Vec<String>]) -> RiskTier {
    let panel = panel_tags();
    let panel_props = TaskProperties::from_tags(&panel);
    let request_props = TaskProperties::merge_opt(
        TaskProperties::from_tags(request_tags).as_ref(),
        og::level_property_floor(request_tags).as_ref(),
    );
    let declared = governance::extract_tag(request_tags, "risk-tier").map(RiskTier::parse);
    governance::effective_tier(
        panel_props.as_ref(),
        request_props.as_ref(),
        declared,
        RiskTier::Medium,
    )
}

/// `--from-request`: verify a real 31402 and sign the human's decisions on it.
fn decide_real_request(path: &str) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    let doc: serde_json::Value = serde_json::from_str(&text).expect("request file is JSON");
    // `vault propose --json` wraps the event beside the proposal; accept both.
    let event_json = doc.get("event").cloned().unwrap_or(doc);
    let request: nostr_bbs_core::event::NostrEvent =
        serde_json::from_value(event_json).expect("a Nostr event");

    let verified = verify_event(&request);
    let case_id = governance::extract_tag(&request.tags, "d")
        .expect("a 31402 carries its case id as the d tag")
        .to_string();
    let iri = governance::extract_tag(&request.tags, og::TAG_CONTEXT_URL)
        .unwrap_or(TEST_IRI)
        .to_string();
    let level = og::ProposalLevel::from_tags(&request.tags).map(|l| l.as_str());

    let (human_sk, human_pk) = key(HUMAN_SECRET);
    let decide = |outcome: serde_json::Value| {
        let e = action_response(&human_sk, &human_pk, &case_id, &request.id, outcome);
        assert!(verify_event(&e), "signed 31403 {} must verify", e.id);
        e
    };
    let promote = decide(serde_json::json!({
        "action": "promote", "iri": iri, "case_id": case_id,
        "reasoning": "e2e: the real proposal's diff matches its hypothesis.",
    }));
    let demote = decide(serde_json::json!({
        "action": "demote", "iri": iri, "case_id": case_id,
        "reasoning": "e2e: demotion of the same subject.",
    }));
    let reject = decide(serde_json::json!({
        "action": "reject", "case_id": case_id,
        "reasoning": "e2e: rejected; nothing may be written.",
    }));

    let out = serde_json::json!({
        "request_id": request.id,
        "request_kind": request.kind,
        "request_verified": verified,
        "case_id": case_id,
        "iri": iri,
        "level": level,
        "effective_tier": tier_of(&request.tags).as_str(),
        "human_pubkey": human_pk,
        "promote": promote,
        "demote": demote,
        "reject": reject,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&out).expect("serialisable")
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--from-request") {
        let path = args.get(i + 1).expect("--from-request <file>");
        decide_real_request(path);
        return;
    }

    let (agent_sk, agent_pk) = key(AGENT_SECRET);
    let (human_sk, human_pk) = key(HUMAN_SECRET);

    let panel = panel_tags();
    let panel_props = TaskProperties::from_tags(&panel);

    // ── The schema-level proposal that must be tiered High ──────────────
    let schema_case = "sha256:e2e-schema-case";
    let schema_request = action_request(
        &agent_sk,
        &agent_pk,
        schema_case,
        "schema",
        "2026-10-06T12:00:00Z",
    );
    let schema_props = TaskProperties::merge_opt(
        TaskProperties::from_tags(&schema_request.tags).as_ref(),
        og::level_property_floor(&schema_request.tags).as_ref(),
    );
    let schema_tier = governance::effective_tier(
        panel_props.as_ref(),
        schema_props.as_ref(),
        Some(RiskTier::Low),
        RiskTier::Medium,
    );

    // The human promotes it, naming the IRI in their own signed bytes.
    let promote = action_response(
        &human_sk,
        &human_pk,
        schema_case,
        &schema_request.id,
        serde_json::json!({
            "action": "promote",
            "iri": TEST_IRI,
            "case_id": schema_case,
            "reasoning": "Closure checked by hand; the diff matches the hypothesis.",
        }),
    );

    // ── The already-expired proposal ────────────────────────────────────
    let expired_case = "sha256:e2e-expired-case";
    let expired_request = action_request(
        &agent_sk,
        &agent_pk,
        expired_case,
        "content",
        "2020-01-01T00:00:00Z",
    );
    let expired_stale_after = og::stale_after_from_content(&expired_request.content)
        .expect("the fixture declares a readable stale_after");

    for e in [&schema_request, &promote, &expired_request] {
        assert!(verify_event(e), "fixture event {} must verify", e.id);
    }

    let out = serde_json::json!({
        "now": NOW,
        "iri": TEST_IRI,
        "page": TEST_PAGE,
        "agent_pubkey": agent_pk,
        "human_pubkey": human_pk,
        "panel": { "d": og::PANEL_ONTOLOGY_GOVERNANCE, "tags": panel },
        "schema": {
            "case_id": schema_case,
            "request": schema_request,
            "response": promote,
            "effective_tier": schema_tier.as_str(),
            "declared_tier": "low",
            "max_pending_hours": og::STALE_AFTER_DEFAULT_HOURS,
            "stale_after": og::stale_after_from_content(&schema_request.content),
        },
        "expired": {
            "case_id": expired_case,
            "request": expired_request,
            "stale_after": expired_stale_after,
            "is_expired_now": og::is_expired(expired_stale_after, NOW as i64),
        },
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&out).expect("serialisable")
    );
}
