//! Jev option (NF-06-S1-01): advisory rationale/evidence-quality check for
//! governance decision cards (agent control surface, kinds 31400-31405).
//!
//! A reviewer can ask "does my draft rationale actually cover this case?"
//! before signing. The answer is **advice shown next to the card**. It never
//! feeds `rationale_required`/`rationale_satisfied`, tier assignment, 31403
//! signing, promotion/demotion, request correlation or seeded-probe handling;
//! none of those code paths read it.
//!
//! Data class: case content and a reviewer's draft are not known to be public,
//! so this consumer is **local-only**: it resolves only a declared-local
//! backend (`JEV_LOCAL=1` with an explicit endpoint, or the agentbox loopback
//! with `AGENTBOX_SYSTEM_ONE_BACKEND_LOCAL=1`) and refuses the vendor
//! endpoint. What leaves the Worker: case title, subject kind and id, summary,
//! effective tier, typed task properties and the draft rationale. Never keys,
//! pubkeys or the probe digest.
//!
//! Rubric: the estate-shared ES-05 `governance-evidence-quality` v1 question
//! set, vendored byte-for-byte from agentbox
//! (`management-api/lib/rubrics/governance-evidence-quality.v1.json`, branch
//! `feat/jev-option-p1-b`). Its canonical-JSON sha256 is pinned in
//! [`RUBRIC_SHA256`] and checked by a test, so drift breaks loudly. The
//! rubric's optional request-digest binding is not recorded here: this route
//! reads a case row, not the unsigned event content/tags the digest is over.

use nostr_bbs_jev::{ask, Answer, Fallback, JevConfig, JevTransport, Question};
use serde::Deserialize;
use serde_json::{json, Value};
use wasm_bindgen::JsValue;
use worker::{console_log, Env, Response, Result};

use crate::admin::{canonical_url, require_authed};
use crate::http::{error_json, json_response};

/// Flag variable (default off).
pub const FLAG: &str = "JEV_RATIONALE_CHECK";
/// Shared rubric id/version (ES-05).
pub const QUESTION_SET_VERSION: &str = "governance-evidence-quality/1";
/// Vendored copy of the shared rubric.
pub const RUBRIC_JSON: &str = include_str!("rubrics/governance-evidence-quality.v1.json");
/// Pinned sha256 of the rubric's canonical JSON (keys sorted, compact).
pub const RUBRIC_SHA256: &str = "3a338a77939ffec84e03413186619b6e58ad59f8d098543a9e127987fc9a6910";
/// Max characters of each free-text field sent.
pub const TEXT_MAX_CHARS: usize = 2000;
/// A Noul signal below this (probability of yes) raises a flag. Unfitted.
pub const FLAG_BELOW: f64 = 0.5;
/// Minimum confidence of the completeness score before it is shown.
pub const MIN_SCORE_CONFIDENCE: f64 = 0.5;

/// Whether the flag is on (resolver is not consulted otherwise).
pub fn flag_on(env: &Env) -> bool {
    env.var(FLAG)
        .map(|v| matches!(v.to_string().trim(), "1" | "true"))
        .unwrap_or(false)
}

/// What the check looks at.
#[derive(Debug, Clone, PartialEq)]
pub struct CaseView {
    /// Case title (rubric `title`).
    pub title: String,
    /// Subject kind (rubric `subject.kind`).
    pub subject_kind: String,
    /// Subject id (rubric `subject.id`).
    pub subject_id: String,
    /// Case summary (part of rubric `evidence`).
    pub summary: String,
    /// Effective risk tier (part of `evidence`).
    pub tier: Option<String>,
    /// Typed task properties `(verifiability, reversibility, stakes)`
    /// (part of `evidence`).
    pub task_properties: Option<(String, Option<String>, Option<String>)>,
}

/// One raised flag.
#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceFlag {
    /// Rubric question id.
    pub id: String,
    /// P(yes) for that question; below [`FLAG_BELOW`].
    pub probability: f64,
}

/// The advisory annotation.
#[derive(Debug, Clone, PartialEq)]
pub struct Annotation {
    /// Every rubric signal in `[0,1]` (Noul = P(yes); Score = score/(levels-1)),
    /// keyed by question id, only for questions that were answered.
    pub signals: Vec<(String, f64)>,
    /// Noul questions whose P(yes) fell below [`FLAG_BELOW`].
    pub flags: Vec<EvidenceFlag>,
    /// Completeness 0..=1, if the score was confident enough to show.
    pub completeness: Option<f64>,
}

fn clip(s: &str) -> String {
    s.chars().take(TEXT_MAX_CHARS).collect()
}

/// Canonical JSON: object keys sorted recursively, compact. Test-only: the
/// worker itself hashes the vendored rubric bytes, not a re-serialisation.
#[cfg(test)]
pub fn canonical_json(v: &Value) -> String {
    fn sorted(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for k in keys {
                    out.insert(k.clone(), sorted(&m[k]));
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    sorted(v).to_string()
}

/// Parse the vendored rubric's questions into the adapter's types, in a
/// stable (id-sorted) order. `None` only if the vendored file is corrupt.
pub fn rubric_questions() -> Option<Vec<(String, Question)>> {
    let v: Value = serde_json::from_str(RUBRIC_JSON).ok()?;
    let qs = v.get("questions")?.as_object()?;
    let mut out = Vec::new();
    for (id, q) in qs {
        let instructions = q.get("instructions")?.as_str()?.to_string();
        let question = match q.get("type")?.as_str()? {
            "noul" => Question::Noul { instructions },
            "score" => Question::Score {
                instructions,
                criteria: q
                    .get("criteria")?
                    .as_array()?
                    .iter()
                    .map(|c| c.as_str().map(str::to_string))
                    .collect::<Option<Vec<_>>>()?,
            },
            _ => return None,
        };
        out.push((id.clone(), question));
    }
    Some(out)
}

/// Rubric `state` for a case plus the reviewer's draft rationale.
pub fn rubric_state(case: &CaseView, rationale: &str) -> Value {
    let rationale = rationale.trim();
    json!({
        "title": clip(&case.title),
        "subject": { "kind": case.subject_kind, "id": case.subject_id },
        "rationale": if rationale.is_empty() { Value::Null } else { json!(clip(rationale)) },
        "evidence": {
            "summary": clip(&case.summary),
            "tier": case.tier,
            "task_properties": case.task_properties.as_ref().map(|(v, r, s)| json!({
                "verifiability": v, "reversibility": r, "stakes": s,
            })),
        },
        // The forum case row carries no context link.
        "context_url": Value::Null,
    })
}

/// Run the check. `Err` means "show nothing extra".
pub async fn check<T: JevTransport + ?Sized>(
    transport: &T,
    cfg: &JevConfig,
    case: &CaseView,
    rationale: &str,
) -> std::result::Result<Annotation, Fallback> {
    let owned = rubric_questions().ok_or(Fallback::Malformed)?;
    let qs: Vec<(&str, Question)> = owned.iter().map(|(k, q)| (k.as_str(), q.clone())).collect();
    let a = ask(transport, cfg, &rubric_state(case, rationale), &qs).await?;
    let mut signals = Vec::new();
    let mut flags = Vec::new();
    let mut completeness = None;
    for (id, q) in &owned {
        match (q, a.get(id)) {
            (Question::Noul { .. }, Some(Answer::Noul(p))) => {
                signals.push((id.clone(), *p));
                if *p < FLAG_BELOW {
                    flags.push(EvidenceFlag {
                        id: id.clone(),
                        probability: *p,
                    });
                }
            }
            (Question::Score { criteria, .. }, Some(Answer::Score { score, confidence })) => {
                let levels = criteria.len().max(2);
                let norm = (score / (levels - 1) as f64).clamp(0.0, 1.0);
                if *confidence >= MIN_SCORE_CONFIDENCE {
                    signals.push((id.clone(), norm));
                    completeness = Some(norm);
                }
            }
            _ => return Err(Fallback::Malformed),
        }
    }
    Ok(Annotation {
        signals,
        flags,
        completeness,
    })
}

/// Wire form of the annotation.
pub fn annotation_json(a: &Annotation) -> Value {
    json!({
        "advisory": true,
        "available": true,
        "authority": "none",
        "rubric": { "id": "governance-evidence-quality", "version": "1", "sha256": RUBRIC_SHA256 },
        "questionSet": QUESTION_SET_VERSION,
        "signals": a.signals.iter().map(|(k, v)| (k.clone(), json!(v)))
            .collect::<serde_json::Map<_, _>>(),
        "flags": a.flags.iter().map(|f| json!({
            "id": f.id, "probability": f.probability,
        })).collect::<Vec<_>>(),
        "completeness": a.completeness,
    })
}

/// Wire form when no advice is available (any fallback). Carries no reason
/// detail beyond the stable token, and the card behaves exactly as before.
pub fn unavailable_json(why: &Fallback) -> Value {
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
    subject_kind: String,
    subject_id: String,
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
            "SELECT title, subject_kind, subject_id, summary, effective_tier, \
             tp_verifiability, tp_reversibility, tp_stakes \
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
        subject_kind: row.subject_kind,
        subject_id: row.subject_id,
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
            let r = check(
                &nostr_bbs_jev::fetch::WorkersFetch,
                &cfg,
                &case,
                &body.rationale,
            )
            .await;
            if r.is_ok() {
                console_log!(
                    "jev rationale-check accepted: question_set={} model={}",
                    QUESTION_SET_VERSION,
                    cfg.model
                );
            }
            r
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
    use sha2::{Digest, Sha256};

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
            subject_kind: "bucket".into(),
            subject_id: "staging-1".into(),
            summary: "Agent requests deletion of the staging bucket".into(),
            tier: Some("high".into()),
            task_properties: Some((
                "low".into(),
                Some("irreversible".into()),
                Some("high".into()),
            )),
        }
    }
    fn reply(expl: f64, supp: f64, scope: f64, score: f64, conf: f64) -> String {
        json!({"model":"m","answers":{
            "rationale_explains_action":{"type":"noul","noul":expl},
            "evidence_supports_claim":{"type":"noul","noul":supp},
            "scope_matches_title":{"type":"noul","noul":scope},
            "review_completeness":{"type":"score","score":score,"confidence":conf,"legend":{}}},
            "usage":{"input_tokens":1,"output_tokens":1}})
        .to_string()
    }

    #[test]
    fn vendored_rubric_matches_the_pinned_digest() {
        let v: Value = serde_json::from_str(RUBRIC_JSON).unwrap();
        let digest = hex::encode(Sha256::digest(canonical_json(&v).as_bytes()));
        assert_eq!(
            digest, RUBRIC_SHA256,
            "rubric drifted from the agentbox ES-05 v1 pin"
        );
        assert_eq!(v["id"], "governance-evidence-quality");
        assert_eq!(v["version"], "1");
        assert_eq!(v["authority"], "none");
        assert_eq!(rubric_questions().unwrap().len(), 4);
    }

    #[test]
    fn accept_path_flags_low_probability_signals() {
        let m = Mock::new(Ok((200, reply(0.9, 0.1, 0.8, 2.0, 0.8))));
        let a = block_on(check(&m, &cfg(), &case(), "reasons")).unwrap();
        assert_eq!(a.flags.len(), 1);
        assert_eq!(a.flags[0].id, "evidence_supports_claim");
        assert!((a.completeness.unwrap() - 2.0 / 3.0).abs() < 1e-9);
        let j = annotation_json(&a);
        assert_eq!(j["advisory"], true);
        assert_eq!(j["authority"], "none");
        assert_eq!(j["rubric"]["sha256"], RUBRIC_SHA256);
        assert_eq!(j["questionSet"], QUESTION_SET_VERSION);
        assert!(j["signals"]["scope_matches_title"].is_number());
    }

    #[test]
    fn low_confidence_score_is_withheld_not_a_fallback() {
        let m = Mock::new(Ok((200, reply(0.9, 0.9, 0.9, 3.0, 0.1))));
        let a = block_on(check(&m, &cfg(), &case(), "x")).unwrap();
        assert_eq!(a.completeness, None);
        assert!(a.flags.is_empty());
    }

    #[test]
    fn wire_shape_maps_the_card_onto_the_rubric_state() {
        let m = Mock::new(Ok((200, reply(0.9, 0.9, 0.9, 3.0, 0.9))));
        block_on(check(&m, &cfg(), &case(), "my reasons")).unwrap();
        let body: Value = serde_json::from_str(&m.requests.borrow()[0].2).unwrap();
        let st = &body["state"];
        assert_eq!(st["title"], "Delete staging bucket");
        assert_eq!(st["subject"]["kind"], "bucket");
        assert_eq!(st["rationale"], "my reasons");
        assert_eq!(
            st["evidence"]["task_properties"]["reversibility"],
            "irreversible"
        );
        assert!(st["context_url"].is_null());
        for k in [
            "rationale_explains_action",
            "evidence_supports_claim",
            "scope_matches_title",
        ] {
            assert_eq!(body["questions"][k]["type"], "noul");
        }
        assert_eq!(
            body["questions"]["review_completeness"]["criteria"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        let s = body.to_string();
        assert!(!s.contains("pubkey") && !s.contains("probe"));
    }

    #[test]
    fn empty_draft_is_sent_as_null_rationale() {
        assert!(rubric_state(&case(), "   ")["rationale"].is_null());
    }

    #[test]
    fn every_fallback_yields_unavailable_and_never_an_error() {
        let cases = vec![
            (Err(TransportError::Timeout), "timeout"),
            (Err(TransportError::Other), "transport"),
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
