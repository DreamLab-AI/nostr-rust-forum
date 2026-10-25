//! Jev option (NF-06-S1-01): advisory rationale/evidence-quality check for
//! governance decision cards (agent control surface, kinds 31400-31405).
//!
//! A reviewer can ask "does my draft rationale actually cover this case?"
//! before signing. The answer is **advice shown next to the card**. It never
//! feeds `rationale_required`/`rationale_satisfied`, tier assignment, 31403
//! signing, promotion/demotion, request correlation or seeded-probe handling;
//! none of those code paths read it.
//!
//! Data class: case titles/summaries and a reviewer's draft are not known to
//! be public, so this consumer is **local-only**: it resolves only a
//! declared-local backend (`JEV_LOCAL=1` with an explicit endpoint, or the
//! agentbox loopback with `AGENTBOX_SYSTEM_ONE_BACKEND_LOCAL=1`) and refuses
//! the vendor endpoint. What leaves the Worker: case title, summary, effective
//! tier, typed task properties and the draft rationale. Never keys, pubkeys or
//! the probe digest.
//!
//! Rubric: [`QUESTION_SET_VERSION`]. The estate is meant to share one
//! versioned governance evidence-quality rubric (ES-05, agentbox); until that
//! exists this is a local rubric with its own version string, to be aligned.

use nostr_bbs_jev::{ask, Answer, Fallback, JevConfig, JevTransport, Question};
use serde::Deserialize;
use serde_json::json;
use wasm_bindgen::JsValue;
use worker::{console_log, Env, Response, Result};

use crate::admin::{canonical_url, require_authed};
use crate::http::{error_json, json_response};

/// Flag variable (default off).
pub const FLAG: &str = "JEV_RATIONALE_CHECK";
/// Local rubric version (align with the estate ES-05 rubric when published).
pub const QUESTION_SET_VERSION: &str = "forum-governance-evidence-quality/1-local";
/// Max characters of each free-text field sent.
pub const TEXT_MAX_CHARS: usize = 2000;
/// A flag is raised when its probability is at/above this. Unfitted.
pub const FLAG_THRESHOLD: f64 = 0.5;
/// Minimum confidence of the urgency score before it is shown.
pub const MIN_URGENCY_CONFIDENCE: f64 = 0.5;

/// Whether the flag is on (resolver is not consulted otherwise).
pub fn flag_on(env: &Env) -> bool {
    env.var(FLAG)
        .map(|v| matches!(v.to_string().trim(), "1" | "true"))
        .unwrap_or(false)
}

/// What the check looks at.
#[derive(Debug, Clone, PartialEq)]
pub struct CaseView {
    /// Case title.
    pub title: String,
    /// Case summary.
    pub summary: String,
    /// Effective risk tier.
    pub tier: Option<String>,
    /// Typed task properties `(verifiability, reversibility, stakes)`.
    pub task_properties: Option<(String, Option<String>, Option<String>)>,
}

/// One raised flag.
#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceFlag {
    /// Stable id.
    pub id: &'static str,
    /// Human label.
    pub label: &'static str,
    /// P(flag applies).
    pub probability: f64,
}

/// The advisory annotation.
#[derive(Debug, Clone, PartialEq)]
pub struct Annotation {
    /// Raised flags only (probability >= threshold).
    pub flags: Vec<EvidenceFlag>,
    /// Review urgency 0..=3, if confident enough to show.
    pub urgency: Option<f64>,
}

const FLAGS: [(&str, &str); 3] = [
    (
        "unsupported_claim",
        "The rationale asserts something the case does not support",
    ),
    (
        "unaddressed_obligation",
        "The rationale does not address the case's stakes or reversibility",
    ),
    (
        "no_reason_given",
        "The rationale gives no actual reason for the decision",
    ),
];

fn clip(s: &str) -> String {
    s.chars().take(TEXT_MAX_CHARS).collect()
}

fn questions() -> Vec<(&'static str, Question)> {
    vec![
        (
            "unsupported_claim",
            Question::Noul {
                instructions:
                    "Does `draft_rationale` assert any fact, outcome or justification that \
                               is not supported by `case` (its title, summary, tier or task \
                               properties)? Reasonable judgement calls that do not claim new facts \
                               are not unsupported claims."
                        .into(),
            },
        ),
        (
            "unaddressed_obligation",
            Question::Noul {
                instructions: "The case carries `case.task_properties` (verifiability, \
                               reversibility, stakes) and a `case.tier`. Does `draft_rationale` \
                               fail to address an obligation that these make important, such as \
                               explaining why an irreversible or high-stakes action is acceptable? \
                               If the tier is low and nothing is irreversible, answer no."
                    .into(),
            },
        ),
        (
            "no_reason_given",
            Question::Noul {
                instructions:
                    "Is `draft_rationale` empty, boilerplate or a bare restatement of the \
                               decision (for example just 'approved' or 'looks fine'), giving no \
                               reason a later auditor could use?"
                        .into(),
            },
        ),
        (
            "urgency",
            Question::Score {
                instructions: "How urgently should a human re-read the case before signing, given \
                               gaps between `case` and `draft_rationale`?"
                    .into(),
                criteria: vec![
                    "None: the rationale covers the case".into(),
                    "Low: small gaps, fine to sign".into(),
                    "Medium: reread the case first".into(),
                    "High: do not sign until the gaps are closed".into(),
                ],
            },
        ),
    ]
}

/// Run the check. `Err` means "show nothing extra".
pub async fn check<T: JevTransport + ?Sized>(
    transport: &T,
    cfg: &JevConfig,
    case: &CaseView,
    rationale: &str,
) -> std::result::Result<Annotation, Fallback> {
    let state = json!({
        "case": {
            "title": clip(&case.title),
            "summary": clip(&case.summary),
            "tier": case.tier,
            "task_properties": case.task_properties.as_ref().map(|(v, r, s)| json!({
                "verifiability": v, "reversibility": r, "stakes": s,
            })),
        },
        "draft_rationale": clip(rationale),
    });
    let qs = questions();
    let a = ask(transport, cfg, &state, &qs).await?;
    let mut flags = Vec::new();
    for (id, label) in FLAGS {
        match a.get(id) {
            Some(Answer::Noul(p)) => {
                if *p >= FLAG_THRESHOLD {
                    flags.push(EvidenceFlag {
                        id,
                        label,
                        probability: *p,
                    });
                }
            }
            _ => return Err(Fallback::Malformed),
        }
    }
    let urgency = match a.get("urgency") {
        Some(Answer::Score { score, confidence }) => {
            (*confidence >= MIN_URGENCY_CONFIDENCE).then_some(*score)
        }
        _ => return Err(Fallback::Malformed),
    };
    Ok(Annotation { flags, urgency })
}

/// Wire form of the annotation.
pub fn annotation_json(a: &Annotation) -> serde_json::Value {
    json!({
        "advisory": true,
        "available": true,
        "questionSet": QUESTION_SET_VERSION,
        "flags": a.flags.iter().map(|f| json!({
            "id": f.id, "label": f.label, "probability": f.probability,
        })).collect::<Vec<_>>(),
        "urgency": a.urgency,
    })
}

/// Wire form when no advice is available (any fallback). Carries no reason
/// detail beyond the stable token, and the card behaves exactly as before.
pub fn unavailable_json(why: &Fallback) -> serde_json::Value {
    json!({ "advisory": true, "available": false, "reason": why.tag() })
}

#[derive(Deserialize)]
struct Body {
    #[serde(default)]
    rationale: String,
}

#[derive(Deserialize)]
struct Row {
    title: String,
    summary: String,
    effective_tier: Option<String>,
    tp_verifiability: Option<String>,
    tp_reversibility: Option<String>,
    tp_stakes: Option<String>,
}

/// `POST /api/governance/cases/:id/rationale-check` (NIP-98 authed, flag-gated).
///
/// Body `{"rationale": "<draft>"}`. Always `200` with an advisory body once the
/// caller is authenticated and the case exists; `available:false` on any
/// fallback. Read-only: it writes nothing.
pub async fn handle_check(
    case_id: &str,
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(
        origin,
        &format!("/api/governance/cases/{case_id}/rationale-check"),
    );
    if let Err((body, status)) =
        require_authed(auth_header, &url, "POST", Some(body_bytes), env).await
    {
        return json_response(env, &body, status);
    }
    let Ok(body) = serde_json::from_slice::<Body>(body_bytes) else {
        return error_json(env, "invalid body", 400);
    };
    let db = crate::governance_api::relay_db(env)?;
    let row = db
        .prepare(
            "SELECT title, summary, effective_tier, tp_verifiability, tp_reversibility, tp_stakes \\
             FROM broker_cases WHERE id = ?1",
        )
        .bind(&[JsValue::from_str(case_id)])?
        .first::<Row>(None)
        .await?;
    let Some(row) = row else {
        return error_json(env, "case not found", 404);
    };
    let case = CaseView {
        title: row.title,
        summary: row.summary,
        tier: row.effective_tier,
        task_properties: row
            .tp_verifiability
            .map(|v| (v, row.tp_reversibility, row.tp_stakes)),
    };

    let lookup = nostr_bbs_jev::fetch::env_lookup(env);
    // local_only = true: this data class is not known to be public.
    let out = match nostr_bbs_jev::resolve(&lookup, FLAG, true) {
        Ok(cfg) => {
            check(
                &nostr_bbs_jev::fetch::WorkersFetch,
                &cfg,
                &case,
                &body.rationale,
            )
            .await
        }
        Err(why) => Err(why),
    };
    match out {
        Ok(a) => json_response(env, &annotation_json(&a), 200),
        Err(why) => {
            console_log!("jev rationale-check fallback: {}", why.tag());
            json_response(env, &unavailable_json(&why), 200)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_bbs_jev::testutil::{block_on, Mock};
    use nostr_bbs_jev::TransportError;

    fn cfg() -> JevConfig {
        JevConfig {
            endpoint: "http://local".into(),
            model: "m".into(),
            bearer: None,
            deadline_ms: 10,
        }
    }
    fn case() -> CaseView {
        CaseView {
            title: "Delete staging bucket".into(),
            summary: "Agent requests deletion of the staging bucket".into(),
            tier: Some("high".into()),
            task_properties: Some((
                "low".into(),
                Some("irreversible".into()),
                Some("high".into()),
            )),
        }
    }
    fn reply(u: f64, i: f64, n: f64, urg: f64, conf: f64) -> String {
        json!({"model":"m","answers":{
            "unsupported_claim":{"type":"noul","noul":u},
            "unaddressed_obligation":{"type":"noul","noul":i},
            "no_reason_given":{"type":"noul","noul":n},
            "urgency":{"type":"score","score":urg,"confidence":conf,"legend":{}}},
            "usage":{"input_tokens":1,"output_tokens":1}})
        .to_string()
    }

    #[test]
    fn accept_path_raises_only_flags_over_threshold() {
        let m = Mock::new(Ok((200, reply(0.1, 0.9, 0.2, 2.4, 0.8))));
        let a = block_on(check(&m, &cfg(), &case(), "ok")).unwrap();
        assert_eq!(a.flags.len(), 1);
        assert_eq!(a.flags[0].id, "unaddressed_obligation");
        assert_eq!(a.urgency, Some(2.4));
        let j = annotation_json(&a);
        assert_eq!(j["advisory"], true);
        assert_eq!(j["questionSet"], QUESTION_SET_VERSION);
    }

    #[test]
    fn low_confidence_urgency_is_withheld_not_a_fallback() {
        let m = Mock::new(Ok((200, reply(0.1, 0.1, 0.1, 3.0, 0.1))));
        let a = block_on(check(&m, &cfg(), &case(), "x")).unwrap();
        assert_eq!(a.urgency, None);
        assert!(a.flags.is_empty());
    }

    #[test]
    fn wire_shape_and_no_identifiers_leave() {
        let m = Mock::new(Ok((200, reply(0.1, 0.1, 0.1, 0.0, 0.9))));
        block_on(check(&m, &cfg(), &case(), "my reasons")).unwrap();
        let body: serde_json::Value = serde_json::from_str(&m.requests.borrow()[0].2).unwrap();
        assert_eq!(body["state"]["draft_rationale"], "my reasons");
        assert_eq!(
            body["state"]["case"]["task_properties"]["reversibility"],
            "irreversible"
        );
        assert!(body["questions"]["urgency"]["criteria"].is_array());
        for k in [
            "unsupported_claim",
            "unaddressed_obligation",
            "no_reason_given",
        ] {
            assert_eq!(body["questions"][k]["type"], "noul");
        }
        let s = body.to_string();
        assert!(!s.contains("pubkey") && !s.contains("probe"));
    }

    #[test]
    fn every_fallback_yields_unavailable_and_never_an_error() {
        let cases = vec![
            (Err(TransportError::Timeout), "timeout"),
            (Err(TransportError::Other), "http-0"),
            (Ok((500, String::new())), "http-500"),
            (Ok((200, "bad".into())), "malformed"),
            (Ok((200, r#"{"answers":{}}"#.into())), "malformed"),
        ];
        for (rep, tag) in cases {
            let why = block_on(check(&Mock::new(rep), &cfg(), &case(), "x")).unwrap_err();
            let j = unavailable_json(&why);
            assert_eq!(j["available"], false);
            assert_eq!(j["reason"], tag);
            assert!(j.get("flags").is_none());
        }
    }

    #[test]
    fn local_only_refuses_the_vendor_endpoint() {
        let env = |k: &str| match k {
            "JEV_RATIONALE_CHECK" => Some("1".to_string()),
            "TYPESAFE_API_KEY" => Some("k".to_string()),
            _ => None,
        };
        assert_eq!(
            nostr_bbs_jev::resolve(&env, FLAG, true),
            Err(Fallback::NoEndpoint)
        );
    }
}
