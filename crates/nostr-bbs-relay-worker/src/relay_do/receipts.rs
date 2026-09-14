//! ADR-2010 — durable governance outcome receipts.
//!
//! A signed governance response used to disappear into a gap. `handle_event`
//! sent `OK` and broadcast the moment `save_event` returned, then projected the
//! decision into the case tables as a separate, unchecked step: a `broker_decisions`
//! `INSERT` followed by a `broker_cases` `UPDATE`, each with its result discarded.
//! Three failure shapes followed from that:
//!
//! 1. **A relay `OK` that means nothing downstream.** The client shows
//!    "Response sent" on an acknowledgement that certifies only that the
//!    envelope was stored — not that the decision took effect.
//! 2. **Half-applied projections.** The decision row could land while the case
//!    state update did not, leaving a case whose recorded decision and
//!    displayed state disagree, with nothing recording that it happened.
//! 3. **No replay identity.** A re-delivered event re-ran the whole projection.
//!
//! This module supplies the missing spine: a durable, per-event receipt that
//! records which **stage** a response actually reached, correlated to every
//! identifier a downstream consumer needs to verify authority independently.
//!
//! ## Stages
//!
//! `signed → relay-accepted → projection-committed`, with `projection-failed`
//! as the terminal error state. Each stage certifies **only itself**: a receipt
//! at `relay-accepted` says the relay durably holds the signed envelope and
//! nothing more. A timeout or an interrupted delivery leaves the receipt where
//! it was, so a pending response is visibly pending rather than implicitly
//! approved. Nothing in this module ever reports success for a mutation that
//! did not commit.
//!
//! ## Atomicity
//!
//! D1 cannot span the event-envelope write and the projection in one
//! transaction — `save_event` has already committed by the time a projection is
//! planned. ADR-2010 anticipates exactly this and permits the alternative:
//! *"retain a durable replay record with idempotent reconciliation"*. The
//! receipt row written at `relay-accepted` **is** that record. The projection
//! itself is then genuinely atomic: the decision `INSERT`, the case `UPDATE` and
//! the receipt's stage transition are submitted as a single D1 `batch`, which
//! Cloudflare executes in one implicit transaction. The half-applied projection
//! is therefore not merely unlikely, it is unrepresentable.
//!
//! ## Idempotency
//!
//! The receipt is keyed by the full 64-hex signed event id. A replayed event
//! finds its receipt already present:
//!
//! - already `projection-committed` → the replay is counted and **no mutation
//!   is re-run**;
//! - still `relay-accepted`, or `projection-failed` → the replay is a
//!   *reconciliation* opportunity and the projection is retried. That retry is
//!   safe because the decision insert is `INSERT OR IGNORE` on a deterministic
//!   decision id derived from the event id, and the case update is a state
//!   assignment rather than an increment.
//!
//! Retrying the same signed event can therefore never duplicate the mutation.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;

use nostr_bbs_core::governance;
use nostr_bbs_core::NostrEvent;

// ---------------------------------------------------------------------------
// Stages
// ---------------------------------------------------------------------------

/// The receipt stage ladder, owned by `nostr-bbs-core` (ADR-2010 + FR4).
///
/// It moved out of this module when FR4.1 added the **application** stages
/// (`consumer-received`, `applied`, `not-applied`, `applied-manually`) and the
/// `escalated-on-age` / `expired` side receipts: the auth worker's receipts
/// endpoint and this projection path both have to agree on the ladder and its
/// monotonicity rule, and they share no code but the core crate. Re-exported
/// here so every existing `receipts::ReceiptStage` path keeps working.
pub use nostr_bbs_core::governance::ReceiptStage;

// ---------------------------------------------------------------------------
// Correlation
// ---------------------------------------------------------------------------

/// Everything a receipt binds a decision to.
///
/// ADR-2010 requires a receipt to carry the full signed event id, the request
/// event id, the case id, the signer, the decision outcome, the target
/// operation and any supersession — so a consumer can verify authority and
/// correlation for itself rather than trusting a forum badge or a relay `OK`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptCorrelation {
    /// The **full** 64-hex signed event id. Never truncated: the shortened
    /// `decision_id` is a projection key, not an identity.
    pub event_id: String,
    pub kind: u64,
    pub case_id: String,
    /// The 31402 ActionRequest this responds to, where the response cites one.
    pub request_event_id: Option<String>,
    pub signer_pubkey: String,
    /// The canonical action string, once parsed.
    pub decision_outcome: Option<String>,
    /// The operation the decision authorises, where the response names one.
    pub target_operation: Option<String>,
    /// The decision event this response supersedes, if any.
    pub supersedes_event_id: Option<String>,
    /// `event.created_at` — when the signer signed.
    pub signed_at: u64,
}

/// Build the correlation record for a governance event.
///
/// Returns `None` for an event that cannot be correlated at all — no `d` tag,
/// so no case. ADR-2010 is explicit that an uncorrelated request stays
/// unresolved rather than being absorbed by a fallback: we decline to mint a
/// receipt we could not later join to anything.
pub fn correlate(event: &NostrEvent) -> Option<ReceiptCorrelation> {
    let case_id = governance::extract_d_tag(&event.tags)?;
    if case_id.is_empty() {
        return None;
    }

    // The `e` tag marked `request` cites the originating 31402; an unmarked
    // `e` tag on a response is treated the same way, which matches how the
    // existing projection resolves its request linkage.
    let request_event_id = tag_with_marker(event, "e", "request")
        .or_else(|| governance::extract_appeal_target(&event.tags).map(str::to_string));

    Some(ReceiptCorrelation {
        event_id: event.id.clone(),
        kind: event.kind,
        case_id: case_id.to_string(),
        request_event_id,
        signer_pubkey: event.pubkey.clone(),
        decision_outcome: governance::broker::DecisionOutcome::from_response_content(
            &event.content,
        )
        .map(|o| o.action_str().to_string()),
        target_operation: tag_value(event, "op"),
        supersedes_event_id: governance::extract_supersedes_target(&event.tags).map(str::to_string),
        signed_at: event.created_at,
    })
}

/// First value of a single-valued tag.
fn tag_value(event: &NostrEvent, name: &str) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].clone())
}

/// First value of a tag carrying the given NIP-01 marker in position 3.
fn tag_with_marker(event: &NostrEvent, name: &str, marker: &str) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 4 && t[0] == name && t[3] == marker)
        .map(|t| t[1].clone())
}

// ---------------------------------------------------------------------------
// Projection payload
// ---------------------------------------------------------------------------

/// The complete set of writes one committed projection performs, carried
/// together because they must commit together.
// Each following statement is conditional on its predecessor changing one row.
// D1 batch serialises these statements in one transaction. The first statement
// checks request identity, legal-state snapshot, latest decision and receipt.
const PROJECTION_DECISION_SQL: &str = r#"INSERT INTO broker_decisions
 (decision_id, case_id, outcome, outcome_detail, broker_pubkey, reasoning, prior_decision_id, decided_at)
 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8
 WHERE EXISTS (SELECT 1 FROM broker_cases WHERE id = ?2 AND state = ?9 AND nostr_event_id = ?10 AND state IN ('open', 'under_review', 'reopened'))
 AND (SELECT decision_id FROM broker_decisions WHERE case_id = ?2 ORDER BY decided_at DESC, decision_id DESC LIMIT 1) IS ?7
 AND EXISTS (SELECT 1 FROM governance_receipts WHERE event_id = ?11 AND case_id = ?2
 AND request_event_id = ?10 AND stage IN ('relay-accepted', 'projection-failed'))"#;
const PROJECTION_CASE_SQL: &str = r#"UPDATE broker_cases SET state = ?1, assigned_to = ?2, updated_at = ?3
 WHERE id = ?4 AND changes() = 1"#;
const PROJECTION_RECEIPT_SQL: &str = r#"UPDATE governance_receipts
 SET stage = ?1, projected_at = ?2, decision_id = ?3, stage_error = NULL
 WHERE event_id = ?4 AND changes() = 1"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionCommit {
    pub event_id: String,
    pub case_id: String,
    pub request_event_id: String,
    pub expected_state: String,
    pub decision_id: String,
    pub outcome: String,
    pub outcome_detail: Option<String>,
    pub prior_decision_id: Option<String>,
    pub reasoning: String,
    pub broker_pubkey: String,
    /// `broker_cases.state` after the decision.
    pub new_state: String,
    pub decided_at: u64,
}

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

/// What recording an acceptance found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptOutcome {
    /// No receipt existed; one was created at `relay-accepted`.
    Fresh,
    /// A receipt already existed. `stage` is the stage it had reached and the
    /// replay has been counted.
    Replay { stage: ReceiptStage, replays: u32 },
}

/// The terminal result of handling one governance response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "result", rename_all = "kebab-case")]
pub enum ReceiptOutcome {
    /// Projection committed; the mutation took effect.
    Committed { stage: ReceiptStage },
    /// This exact signed event had already been projected. Counted, and
    /// **no mutation was re-run**.
    DuplicateIgnored { replays: u32 },
    /// A previously incomplete receipt was retried and has now committed.
    Reconciled { replays: u32 },
    /// The envelope is durably held but the projection did not commit. The
    /// receipt sits at `projection-failed` and is retryable.
    ProjectionFailed { error: String },
    /// The receipt itself could not be written, so the relay cannot promise
    /// even a replay record.
    NotRecorded { error: String },
    /// The event could not be correlated to a case, so no receipt was minted.
    Uncorrelated,
}

impl ReceiptOutcome {
    /// Whether the governed mutation is now in effect. Only a committed
    /// projection — or a duplicate of one — counts.
    pub fn is_applied(&self) -> bool {
        matches!(
            self,
            Self::Committed { .. } | Self::Reconciled { .. } | Self::DuplicateIgnored { .. }
        )
    }
}

// ---------------------------------------------------------------------------
// Storage seam
// ---------------------------------------------------------------------------

/// The receipt operations the flow needs, abstracted so the stage machine can
/// be exercised — including under injected failure — without a live D1.
#[async_trait(?Send)]
pub trait ReceiptStore {
    /// Record the accepted envelope at `relay-accepted`, or report that this
    /// event id already has a receipt (counting the replay).
    async fn record_accepted(
        &self,
        correlation: &ReceiptCorrelation,
        accepted_at: u64,
    ) -> Result<AcceptOutcome, String>;

    /// Commit the decision row, the case state and the receipt's transition to
    /// `projection-committed` **as one transaction**.
    async fn commit_projection(&self, commit: &ProjectionCommit) -> Result<(), String>;

    /// Move the receipt to `projection-failed`, recording why.
    async fn mark_projection_failed(
        &self,
        event_id: &str,
        error: &str,
        at: u64,
    ) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// The stage machine
// ---------------------------------------------------------------------------

/// Take one signed governance response from acceptance through projection,
/// recording the stage actually reached at every step.
///
/// The caller has already stored the envelope, so the relay's `OK` is honest as
/// far as it goes. This function decides what happens *after* that `OK` and
/// leaves behind a receipt saying exactly how far the response got.
pub async fn apply_with_receipt<S>(
    store: &S,
    correlation: &ReceiptCorrelation,
    commit: &ProjectionCommit,
    now: u64,
) -> ReceiptOutcome
where
    S: ReceiptStore + ?Sized,
{
    // Refuse a caller assembling a plan from a different signed response or
    // request. An incomplete receipt never certifies an external operation.
    if correlation.event_id != commit.event_id
        || correlation.case_id != commit.case_id
        || correlation.signer_pubkey != commit.broker_pubkey
        || correlation.request_event_id.as_deref() != Some(commit.request_event_id.as_str())
        || correlation.decision_outcome.as_deref() != Some(commit.outcome.as_str())
    {
        return ReceiptOutcome::Uncorrelated;
    }
    let accept = match store.record_accepted(correlation, now).await {
        Ok(a) => a,
        Err(e) => return ReceiptOutcome::NotRecorded { error: e },
    };

    let replays = match accept {
        AcceptOutcome::Fresh => 0,
        AcceptOutcome::Replay { stage, replays } => {
            // A response already projected is done. Re-running it is exactly
            // the duplicate mutation ADR-2010 forbids, so we stop here — the
            // replay is recorded, nothing is written twice.
            if !stage.awaits_projection() {
                return ReceiptOutcome::DuplicateIgnored { replays };
            }
            // Otherwise the earlier attempt left the receipt short of
            // `projection-committed`: this delivery is a reconciliation.
            replays
        }
    };

    match store.commit_projection(commit).await {
        Ok(()) => {
            if replays > 0 {
                ReceiptOutcome::Reconciled { replays }
            } else {
                ReceiptOutcome::Committed {
                    stage: ReceiptStage::ProjectionCommitted,
                }
            }
        }
        Err(e) => {
            // Best-effort transition to the failed stage. If even that write
            // fails the receipt stays at `relay-accepted`, which is still
            // correct: it claims only what is true, and remains retryable.
            let _ = store
                .mark_projection_failed(&commit.event_id, &e, now)
                .await;
            ReceiptOutcome::ProjectionFailed { error: e }
        }
    }
}

// ---------------------------------------------------------------------------
// D1-backed store
// ---------------------------------------------------------------------------

/// Row shape for reading a receipt back.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReceiptRow {
    pub event_id: String,
    pub kind: i64,
    pub case_id: String,
    pub request_event_id: Option<String>,
    pub signer_pubkey: String,
    pub decision_outcome: Option<String>,
    pub target_operation: Option<String>,
    pub supersedes_event_id: Option<String>,
    pub stage: String,
    pub stage_error: Option<String>,
    pub decision_id: Option<String>,
    pub signed_at: i64,
    pub accepted_at: Option<i64>,
    pub projected_at: Option<i64>,
    pub replays: i64,
    /// FR4.1 provenance: when the mutation owner reported an application stage,
    /// who reported it, and in whose words. Absent until one is reported.
    #[serde(default)]
    pub applied_at: Option<i64>,
    #[serde(default)]
    pub applied_by: Option<String>,
    #[serde(default)]
    pub acknowledgement: Option<String>,
}

/// D1 implementation of [`ReceiptStore`].
pub struct D1ReceiptStore {
    db: worker::D1Database,
}

impl D1ReceiptStore {
    pub fn new(db: worker::D1Database) -> Self {
        Self { db }
    }
}

fn js_opt(v: Option<&str>) -> JsValue {
    match v {
        Some(s) => JsValue::from_str(s),
        None => JsValue::NULL,
    }
}

#[async_trait(?Send)]
impl ReceiptStore for D1ReceiptStore {
    async fn record_accepted(
        &self,
        c: &ReceiptCorrelation,
        accepted_at: u64,
    ) -> Result<AcceptOutcome, String> {
        // `INSERT OR IGNORE` keyed on the full signed event id: the first
        // delivery creates the receipt, every later one is a no-op here and is
        // detected by the read below.
        let insert = self
            .db
            .prepare(
                "INSERT OR IGNORE INTO governance_receipts \
                 (event_id, kind, case_id, request_event_id, signer_pubkey, decision_outcome, \
                  target_operation, supersedes_event_id, stage, signed_at, accepted_at, replays) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0)",
            )
            .bind(&[
                JsValue::from_str(&c.event_id),
                JsValue::from_f64(c.kind as f64),
                JsValue::from_str(&c.case_id),
                js_opt(c.request_event_id.as_deref()),
                JsValue::from_str(&c.signer_pubkey),
                js_opt(c.decision_outcome.as_deref()),
                js_opt(c.target_operation.as_deref()),
                js_opt(c.supersedes_event_id.as_deref()),
                JsValue::from_str(ReceiptStage::RelayAccepted.as_str()),
                JsValue::from_f64(c.signed_at as f64),
                JsValue::from_f64(accepted_at as f64),
            ])
            .map_err(|e| format!("receipt insert bind: {e:?}"))?;

        let inserted = insert
            .run()
            .await
            .map_err(|e| format!("receipt insert: {e:?}"))?;
        let created = inserted
            .meta()
            .ok()
            .flatten()
            .and_then(|m| m.changes)
            .map(|c| c > 0)
            .unwrap_or(false);

        if created {
            return Ok(AcceptOutcome::Fresh);
        }

        // Already present: count the replay and report the stage reached.
        #[derive(Deserialize)]
        struct StageRow {
            stage: String,
            replays: i64,
        }
        let bumped = self
            .db
            .prepare(
                "UPDATE governance_receipts SET replays = replays + 1 WHERE event_id = ?1 \
                 RETURNING stage, replays",
            )
            .bind(&[JsValue::from_str(&c.event_id)])
            .map_err(|e| format!("replay bump bind: {e:?}"))?
            .first::<StageRow>(None)
            .await
            .map_err(|e| format!("replay bump: {e:?}"))?
            .ok_or_else(|| "receipt vanished between insert and update".to_string())?;

        let stage = ReceiptStage::parse(&bumped.stage)
            .ok_or_else(|| format!("unknown receipt stage {:?}", bumped.stage))?;
        Ok(AcceptOutcome::Replay {
            stage,
            replays: bumped.replays.max(0) as u32,
        })
    }

    async fn commit_projection(&self, c: &ProjectionCommit) -> Result<(), String> {
        let decision = self
            .db
            .prepare(PROJECTION_DECISION_SQL)
            .bind(&[
                JsValue::from_str(&c.decision_id),
                JsValue::from_str(&c.case_id),
                JsValue::from_str(&c.outcome),
                js_opt(c.outcome_detail.as_deref()),
                JsValue::from_str(&c.broker_pubkey),
                JsValue::from_str(&c.reasoning),
                js_opt(c.prior_decision_id.as_deref()),
                JsValue::from_f64(c.decided_at as f64),
                JsValue::from_str(&c.expected_state),
                JsValue::from_str(&c.request_event_id),
                JsValue::from_str(&c.event_id),
            ])
            .map_err(|e| format!("decision bind: {e:?}"))?;

        let case = self
            .db
            .prepare(PROJECTION_CASE_SQL)
            .bind(&[
                JsValue::from_str(&c.new_state),
                JsValue::from_str(&c.broker_pubkey),
                JsValue::from_f64(c.decided_at as f64),
                JsValue::from_str(&c.case_id),
            ])
            .map_err(|e| format!("case bind: {e:?}"))?;

        let receipt = self
            .db
            .prepare(PROJECTION_RECEIPT_SQL)
            .bind(&[
                JsValue::from_str(ReceiptStage::ProjectionCommitted.as_str()),
                JsValue::from_f64(c.decided_at as f64),
                JsValue::from_str(&c.decision_id),
                JsValue::from_str(&c.event_id),
            ])
            .map_err(|e| format!("receipt transition bind: {e:?}"))?;

        // One batch, one implicit transaction: the decision, the case state and
        // the receipt either all land or none do. This is what makes a
        // half-applied projection unrepresentable rather than merely unlikely.
        let results = self
            .db
            .batch(vec![decision, case, receipt])
            .await
            .map_err(|e| format!("projection batch failed: {e:?}"))?;

        if results.len() != 3 {
            return Err("projection batch returned an incomplete result".to_string());
        }
        for r in &results {
            if !r.success() {
                return Err(format!(
                    "projection batch reported failure: {}",
                    r.error().unwrap_or_else(|| "unknown".to_string())
                ));
            }
        }
        for r in &results {
            if r.meta().ok().flatten().and_then(|m| m.changes) != Some(1) {
                return Err(
                    "projection conflict: case/request/state changed or receipt incomplete"
                        .to_string(),
                );
            }
        }
        Ok(())
    }

    async fn mark_projection_failed(
        &self,
        event_id: &str,
        error: &str,
        at: u64,
    ) -> Result<(), String> {
        // Never regress a committed receipt: the guard on `stage` means a late
        // failure report from a superseded attempt cannot un-commit a decision.
        self.db
            .prepare(
                "UPDATE governance_receipts SET stage = ?1, stage_error = ?2, accepted_at = \
                 COALESCE(accepted_at, ?3) WHERE event_id = ?4 AND stage != ?5",
            )
            .bind(&[
                JsValue::from_str(ReceiptStage::ProjectionFailed.as_str()),
                JsValue::from_str(error),
                JsValue::from_f64(at as f64),
                JsValue::from_str(event_id),
                JsValue::from_str(ReceiptStage::ProjectionCommitted.as_str()),
            ])
            .map_err(|e| format!("failure transition bind: {e:?}"))?
            .run()
            .await
            .map_err(|e| format!("failure transition: {e:?}"))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Read API — GET /api/governance/receipts
// ---------------------------------------------------------------------------

/// Serialise a receipt row for the wire, adding the derived flags a consumer
/// needs rather than making every client re-implement the stage semantics.
fn receipt_json(row: &ReceiptRow) -> serde_json::Value {
    let stage = ReceiptStage::parse(&row.stage);
    serde_json::json!({
        // Correlation — everything ADR-2010 requires a consumer to check for
        // itself before acting on a decision.
        "eventId": row.event_id,
        "kind": row.kind,
        "caseId": row.case_id,
        "requestEventId": row.request_event_id,
        "signerPubkey": row.signer_pubkey,
        "decisionOutcome": row.decision_outcome,
        "targetOperation": row.target_operation,
        "supersedesEventId": row.supersedes_event_id,
        "decisionId": row.decision_id,
        // Stage reached, and what it does and does not certify.
        "stage": row.stage,
        "stageError": row.stage_error,
        // `applied` is the distinction an operator acts on: an approved
        // decision whose write failed is NOT applied, and is not a denial
        // either.
        "applied": stage.map(ReceiptStage::is_applied).unwrap_or(false),
        "awaitsProjection": stage.map(ReceiptStage::awaits_projection).unwrap_or(false),
        // FR4.1: the stages past projection, and who claimed them. This is
        // what the human who approved something reads to learn whether it
        // actually happened — the loop ADR-2010 left open.
        "isApplicationStage": stage.map(ReceiptStage::is_application_stage).unwrap_or(false),
        "appliedAt": row.applied_at,
        "appliedBy": row.applied_by,
        "acknowledgement": row.acknowledgement,
        "signedAt": row.signed_at,
        "acceptedAt": row.accepted_at,
        "projectedAt": row.projected_at,
        "replays": row.replays,
    })
}

/// `GET /api/governance/receipts` — the receipt trail.
///
/// Filters: `case` (case id), `event` (full signed event id), `stage`, plus
/// `limit`/`offset`. Ordered by `signed_at DESC`.
///
/// NIP-98 admin authenticated. ADR-2010's history-consumer extension leaves
/// cross-case read authority for CP-04/05/08/09 to ratify, so this read is
/// scoped to the relay's existing administrative authority rather than
/// inventing a broader one.
pub async fn handle_receipts_list(
    req: &worker::Request,
    env: &worker::Env,
) -> worker::Result<worker::Response> {
    use crate::cors::json_response;

    let url = req.url()?;
    let request_url = url.to_string();
    let auth_header = req.headers().get("Authorization").ok().flatten();
    match crate::auth::require_nip98_admin(auth_header.as_deref(), &request_url, "GET", None, env)
        .await
    {
        Ok(_) => {}
        Err((body, status)) => return json_response(env, &body, status),
    }

    let params: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let limit: u32 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50)
        .min(200);
    let offset: u32 = params
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let db = env.d1("DB")?;

    // Build the filter from whichever selectors were supplied. Every value is
    // bound, never interpolated.
    let mut predicates: Vec<String> = Vec::new();
    let mut binds: Vec<JsValue> = Vec::new();
    for (param, column) in [
        ("case", "case_id"),
        ("event", "event_id"),
        ("stage", "stage"),
        ("signer", "signer_pubkey"),
    ] {
        if let Some(v) = params.get(param).filter(|v| !v.is_empty()) {
            binds.push(JsValue::from_str(v));
            predicates.push(format!("{column} = ?{}", binds.len()));
        }
    }
    let where_clause = if predicates.is_empty() {
        String::new()
    } else {
        format!("WHERE {} ", predicates.join(" AND "))
    };
    let limit_idx = binds.len() + 1;
    let offset_idx = binds.len() + 2;
    binds.push(JsValue::from_f64(limit as f64));
    binds.push(JsValue::from_f64(offset as f64));

    let sql = format!(
        "SELECT event_id, kind, case_id, request_event_id, signer_pubkey, decision_outcome, \
         target_operation, supersedes_event_id, stage, stage_error, decision_id, signed_at, \
         accepted_at, projected_at, replays \
         FROM governance_receipts {where_clause}\
         ORDER BY signed_at DESC LIMIT ?{limit_idx} OFFSET ?{offset_idx}"
    );

    let rows = db
        .prepare(sql)
        .bind(&binds)?
        .all()
        .await?
        .results::<ReceiptRow>()?;

    let receipts: Vec<serde_json::Value> = rows.iter().map(receipt_json).collect();
    json_response(
        env,
        &serde_json::json!({
            "receipts": receipts,
            "limit": limit,
            "offset": offset,
        }),
        200,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// See `trust_sweep::tests::block_on` — the workspace carries no async
    /// runtime and none is needed: the in-memory store never yields.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        let mut fut = Box::pin(fut);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(v) => v,
            std::task::Poll::Pending => panic!("test future parked"),
        }
    }

    #[derive(Default)]
    struct Applied {
        decisions: Vec<String>,
        case_states: HashMap<String, String>,
    }

    /// One row of the fake receipt table, keyed by event id:
    /// `(stage, replays, last projection error)`. These are the only three
    /// receipt columns the projection path reads back, so the fake models them
    /// as a tuple rather than mirroring the full D1 schema.
    type FakeReceiptRow = (ReceiptStage, u32, Option<String>);

    /// In-memory model of the receipt table plus the projection tables, with
    /// the batch's all-or-nothing semantics reproduced faithfully: an injected
    /// failure leaves the decision row, the case state AND the receipt stage
    /// all untouched.
    struct FakeStore {
        receipts: RefCell<HashMap<String, FakeReceiptRow>>,
        applied: RefCell<Applied>,
        /// Fail `record_accepted` — the relay cannot even mint a replay record.
        fail_accept: Option<String>,
        /// Fail `commit_projection` this many times before succeeding. Models
        /// "failure injected after save, before projection completes".
        fail_commit_times: RefCell<u32>,
        commit_calls: RefCell<u32>,
    }

    impl FakeStore {
        fn new() -> Self {
            Self {
                receipts: RefCell::new(HashMap::new()),
                applied: RefCell::new(Applied::default()),
                fail_accept: None,
                fail_commit_times: RefCell::new(0),
                commit_calls: RefCell::new(0),
            }
        }
        fn failing_accept(mut self, msg: &str) -> Self {
            self.fail_accept = Some(msg.to_string());
            self
        }
        fn failing_commits(self, n: u32) -> Self {
            *self.fail_commit_times.borrow_mut() = n;
            self
        }
        fn stage_of(&self, id: &str) -> Option<ReceiptStage> {
            self.receipts.borrow().get(id).map(|r| r.0)
        }
        fn error_of(&self, id: &str) -> Option<String> {
            self.receipts.borrow().get(id).and_then(|r| r.2.clone())
        }
        fn decision_count(&self) -> usize {
            self.applied.borrow().decisions.len()
        }
        fn case_state(&self, case: &str) -> Option<String> {
            self.applied.borrow().case_states.get(case).cloned()
        }
    }

    #[async_trait(?Send)]
    impl ReceiptStore for FakeStore {
        async fn record_accepted(
            &self,
            c: &ReceiptCorrelation,
            _at: u64,
        ) -> Result<AcceptOutcome, String> {
            if let Some(e) = &self.fail_accept {
                return Err(e.clone());
            }
            let mut r = self.receipts.borrow_mut();
            match r.get_mut(&c.event_id) {
                None => {
                    r.insert(c.event_id.clone(), (ReceiptStage::RelayAccepted, 0, None));
                    Ok(AcceptOutcome::Fresh)
                }
                Some(entry) => {
                    entry.1 += 1;
                    Ok(AcceptOutcome::Replay {
                        stage: entry.0,
                        replays: entry.1,
                    })
                }
            }
        }

        async fn commit_projection(&self, c: &ProjectionCommit) -> Result<(), String> {
            *self.commit_calls.borrow_mut() += 1;
            {
                let mut left = self.fail_commit_times.borrow_mut();
                if *left > 0 {
                    *left -= 1;
                    // The batch is atomic: nothing at all is written.
                    return Err("D1_ERROR: projection batch aborted".to_string());
                }
            }
            let mut applied = self.applied.borrow_mut();
            // `INSERT OR IGNORE` on a deterministic decision id.
            if !applied.decisions.contains(&c.decision_id) {
                applied.decisions.push(c.decision_id.clone());
            }
            applied
                .case_states
                .insert(c.case_id.clone(), c.new_state.clone());
            let mut receipts = self.receipts.borrow_mut();
            let replays = receipts.get(&c.event_id).map(|r| r.1).unwrap_or(0);
            receipts.insert(
                c.event_id.clone(),
                (ReceiptStage::ProjectionCommitted, replays, None),
            );
            Ok(())
        }

        async fn mark_projection_failed(
            &self,
            event_id: &str,
            error: &str,
            _at: u64,
        ) -> Result<(), String> {
            let mut r = self.receipts.borrow_mut();
            if let Some(entry) = r.get_mut(event_id) {
                // Never regress a committed receipt.
                if entry.0 != ReceiptStage::ProjectionCommitted {
                    entry.0 = ReceiptStage::ProjectionFailed;
                    entry.2 = Some(error.to_string());
                }
            }
            Ok(())
        }
    }

    fn correlation() -> ReceiptCorrelation {
        ReceiptCorrelation {
            event_id: "e".repeat(64),
            kind: 31403,
            case_id: "case-1".to_string(),
            request_event_id: Some("r".repeat(64)),
            signer_pubkey: "a".repeat(64),
            decision_outcome: Some("approve".to_string()),
            target_operation: Some("publish".to_string()),
            supersedes_event_id: None,
            signed_at: 1_700_000_000,
        }
    }

    fn commit_plan() -> ProjectionCommit {
        ProjectionCommit {
            event_id: "e".repeat(64),
            case_id: "case-1".to_string(),
            request_event_id: "r".repeat(64),
            expected_state: "open".to_string(),
            decision_id: "dec-eeeeeeeeeeeeeeee".to_string(),
            outcome: "approve".to_string(),
            outcome_detail: None,
            prior_decision_id: None,
            reasoning: "reviewed and approved".to_string(),
            broker_pubkey: "a".repeat(64),
            new_state: "approved".to_string(),
            decided_at: 1_700_000_000,
        }
    }

    #[test]
    fn mismatched_signed_correlation_cannot_apply_a_plan() {
        for mismatch in [
            "event",
            "case",
            "request",
            "signer",
            "outcome",
            "missing-request",
        ] {
            let store = FakeStore::new();
            let mut c = correlation();
            match mismatch {
                "event" => c.event_id = "other".into(),
                "case" => c.case_id = "other".into(),
                "request" => c.request_event_id = Some("other".into()),
                "signer" => c.signer_pubkey = "other".into(),
                "outcome" => c.decision_outcome = Some("reject".into()),
                _ => c.request_event_id = None,
            }
            assert!(matches!(
                block_on(apply_with_receipt(&store, &c, &commit_plan(), 1)),
                ReceiptOutcome::Uncorrelated
            ));
        }
    }

    // -- Happy path --------------------------------------------------------

    #[test]
    fn first_delivery_commits_and_records_the_stage() {
        let store = FakeStore::new();
        let out = block_on(apply_with_receipt(
            &store,
            &correlation(),
            &commit_plan(),
            1_700_000_001,
        ));

        assert_eq!(
            out,
            ReceiptOutcome::Committed {
                stage: ReceiptStage::ProjectionCommitted
            }
        );
        assert!(out.is_applied());
        assert_eq!(
            store.stage_of(&"e".repeat(64)),
            Some(ReceiptStage::ProjectionCommitted)
        );
        assert_eq!(store.decision_count(), 1);
        assert_eq!(store.case_state("case-1").as_deref(), Some("approved"));
    }

    // -- Duplicate replay --------------------------------------------------

    #[test]
    fn replaying_a_committed_event_does_not_duplicate_the_mutation() {
        let store = FakeStore::new();
        let c = correlation();
        let plan = commit_plan();

        let first = block_on(apply_with_receipt(&store, &c, &plan, 1));
        assert!(matches!(first, ReceiptOutcome::Committed { .. }));

        // Same signed event delivered twice more.
        let second = block_on(apply_with_receipt(&store, &c, &plan, 2));
        let third = block_on(apply_with_receipt(&store, &c, &plan, 3));

        assert_eq!(second, ReceiptOutcome::DuplicateIgnored { replays: 1 });
        assert_eq!(third, ReceiptOutcome::DuplicateIgnored { replays: 2 });
        // The mutation ran exactly once.
        assert_eq!(store.decision_count(), 1);
        assert_eq!(
            *store.commit_calls.borrow(),
            1,
            "a committed receipt must short-circuit before any further write"
        );
        // A duplicate of an applied decision still reports the effect as applied.
        assert!(second.is_applied());
    }

    // -- Failure injected after save, before projection --------------------

    #[test]
    fn projection_failure_leaves_a_retryable_receipt_and_no_partial_write() {
        // The envelope is stored (the relay already sent OK), then the
        // projection batch aborts. Nothing may be half-applied, and the
        // response must not read as approved-and-applied.
        let store = FakeStore::new().failing_commits(1);
        let out = block_on(apply_with_receipt(
            &store,
            &correlation(),
            &commit_plan(),
            5,
        ));

        match &out {
            ReceiptOutcome::ProjectionFailed { error } => {
                assert!(error.contains("projection batch aborted"))
            }
            other => panic!("expected ProjectionFailed, got {other:?}"),
        }
        assert!(
            !out.is_applied(),
            "a failed write must never read as applied"
        );
        assert_eq!(store.decision_count(), 0, "no decision row");
        assert_eq!(store.case_state("case-1"), None, "no case state change");
        assert_eq!(
            store.stage_of(&"e".repeat(64)),
            Some(ReceiptStage::ProjectionFailed)
        );
        assert!(
            store.error_of(&"e".repeat(64)).is_some(),
            "the reason is retained"
        );
    }

    #[test]
    fn redelivery_after_a_failed_projection_reconciles_exactly_once() {
        // Restart recovery: the first attempt failed, the relay retains the
        // durable replay record, and the next delivery of the same signed event
        // completes the projection — once.
        let store = FakeStore::new().failing_commits(1);
        let c = correlation();
        let plan = commit_plan();

        let first = block_on(apply_with_receipt(&store, &c, &plan, 5));
        assert!(matches!(first, ReceiptOutcome::ProjectionFailed { .. }));

        let second = block_on(apply_with_receipt(&store, &c, &plan, 6));
        assert_eq!(second, ReceiptOutcome::Reconciled { replays: 1 });
        assert_eq!(store.decision_count(), 1);
        assert_eq!(store.case_state("case-1").as_deref(), Some("approved"));
        assert_eq!(
            store.stage_of(&"e".repeat(64)),
            Some(ReceiptStage::ProjectionCommitted)
        );

        // A third delivery is now a plain duplicate.
        let third = block_on(apply_with_receipt(&store, &c, &plan, 7));
        assert!(matches!(third, ReceiptOutcome::DuplicateIgnored { .. }));
        assert_eq!(store.decision_count(), 1, "still exactly one mutation");
    }

    #[test]
    fn repeated_projection_failures_never_apply_the_mutation() {
        let store = FakeStore::new().failing_commits(3);
        let c = correlation();
        let plan = commit_plan();
        for _ in 0..3 {
            let out = block_on(apply_with_receipt(&store, &c, &plan, 9));
            assert!(!out.is_applied());
        }
        assert_eq!(store.decision_count(), 0);
        assert_eq!(
            store.stage_of(&"e".repeat(64)),
            Some(ReceiptStage::ProjectionFailed)
        );
        // The fourth succeeds once the injected failures are exhausted.
        let ok = block_on(apply_with_receipt(&store, &c, &plan, 10));
        assert!(ok.is_applied());
        assert_eq!(store.decision_count(), 1);
    }

    #[test]
    fn a_receipt_that_cannot_be_written_is_reported_not_swallowed() {
        let store = FakeStore::new().failing_accept("D1_ERROR: receipts unavailable");
        let out = block_on(apply_with_receipt(
            &store,
            &correlation(),
            &commit_plan(),
            1,
        ));
        match &out {
            ReceiptOutcome::NotRecorded { error } => assert!(error.contains("unavailable")),
            other => panic!("expected NotRecorded, got {other:?}"),
        }
        assert!(!out.is_applied());
        assert_eq!(store.decision_count(), 0);
    }

    // -- Stage semantics ---------------------------------------------------

    #[test]
    fn only_a_committed_projection_counts_as_applied() {
        assert!(!ReceiptStage::Signed.is_applied());
        assert!(
            !ReceiptStage::RelayAccepted.is_applied(),
            "a relay OK certifies storage, never effect"
        );
        assert!(ReceiptStage::ProjectionCommitted.is_applied());
        assert!(
            !ReceiptStage::ProjectionFailed.is_applied(),
            "an approved decision whose write failed is not a denial and not an application"
        );
    }

    #[test]
    fn stages_round_trip_through_their_wire_form() {
        for s in [
            ReceiptStage::Signed,
            ReceiptStage::RelayAccepted,
            ReceiptStage::ProjectionCommitted,
            ReceiptStage::ProjectionFailed,
        ] {
            assert_eq!(ReceiptStage::parse(s.as_str()), Some(s));
        }
        assert_eq!(ReceiptStage::parse("nonsense"), None);
    }

    #[test]
    fn stage_ordering_never_regresses() {
        assert!(ReceiptStage::Signed < ReceiptStage::RelayAccepted);
        assert!(ReceiptStage::RelayAccepted < ReceiptStage::ProjectionCommitted);
    }

    // -- Correlation -------------------------------------------------------

    fn event(tags: Vec<Vec<String>>, content: &str) -> NostrEvent {
        NostrEvent {
            id: "e".repeat(64),
            pubkey: "a".repeat(64),
            created_at: 1_700_000_000,
            kind: 31403,
            tags,
            content: content.to_string(),
            sig: "0".repeat(128),
        }
    }

    fn t(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn correlation_binds_the_full_event_id_not_a_truncation() {
        let ev = event(
            vec![t(&["d", "case-9"])],
            r#"{"action":"approve","reasoning":"ok"}"#,
        );
        let c = correlate(&ev).expect("correlates");
        assert_eq!(c.event_id.len(), 64, "the full signed id is the identity");
        assert_eq!(c.event_id, ev.id);
        assert_eq!(c.case_id, "case-9");
        assert_eq!(c.signer_pubkey, ev.pubkey);
        assert_eq!(c.signed_at, ev.created_at);
    }

    #[test]
    fn correlation_captures_request_and_supersession_links() {
        let req = "b".repeat(64);
        let sup = "c".repeat(64);
        let ev = event(
            vec![
                t(&["d", "case-9"]),
                t(&["e", &req, "", "request"]),
                t(&["e", &sup, "", "supersedes"]),
                t(&["op", "publish-vault"]),
            ],
            r#"{"action":"approve"}"#,
        );
        let c = correlate(&ev).expect("correlates");
        assert_eq!(c.request_event_id.as_deref(), Some(req.as_str()));
        assert_eq!(c.supersedes_event_id.as_deref(), Some(sup.as_str()));
        assert_eq!(c.target_operation.as_deref(), Some("publish-vault"));
    }

    // -- Wire projection ---------------------------------------------------

    fn row(stage: ReceiptStage, error: Option<&str>) -> ReceiptRow {
        ReceiptRow {
            event_id: "e".repeat(64),
            kind: 31403,
            case_id: "case-1".to_string(),
            request_event_id: Some("r".repeat(64)),
            signer_pubkey: "a".repeat(64),
            decision_outcome: Some("approve".to_string()),
            target_operation: Some("publish".to_string()),
            supersedes_event_id: None,
            stage: stage.as_str().to_string(),
            stage_error: error.map(str::to_string),
            decision_id: Some("dec-eeeeeeeeeeeeeeee".to_string()),
            signed_at: 1_700_000_000,
            accepted_at: Some(1_700_000_001),
            projected_at: None,
            replays: 0,
            applied_at: None,
            applied_by: None,
            acknowledgement: None,
        }
    }

    #[test]
    fn wire_form_distinguishes_a_failed_write_from_a_denial() {
        // The operator-facing distinction ADR-2010 turns on: an approved
        // decision whose projection failed must not read as applied, and must
        // not read as a rejection either.
        let failed = receipt_json(&row(
            ReceiptStage::ProjectionFailed,
            Some("D1_ERROR: batch aborted"),
        ));
        assert_eq!(failed["applied"], serde_json::json!(false));
        assert_eq!(failed["decisionOutcome"], serde_json::json!("approve"));
        assert_eq!(
            failed["stageError"],
            serde_json::json!("D1_ERROR: batch aborted")
        );
        assert_eq!(failed["awaitsProjection"], serde_json::json!(true));

        let accepted = receipt_json(&row(ReceiptStage::RelayAccepted, None));
        assert_eq!(
            accepted["applied"],
            serde_json::json!(false),
            "a relay OK is not an application"
        );

        let committed = receipt_json(&row(ReceiptStage::ProjectionCommitted, None));
        assert_eq!(committed["applied"], serde_json::json!(true));
        assert_eq!(committed["awaitsProjection"], serde_json::json!(false));
    }

    #[test]
    fn wire_form_carries_the_full_correlation_set() {
        let j = receipt_json(&row(ReceiptStage::ProjectionCommitted, None));
        for field in [
            "eventId",
            "caseId",
            "requestEventId",
            "signerPubkey",
            "decisionOutcome",
            "targetOperation",
            "decisionId",
            "stage",
            "signedAt",
            "replays",
        ] {
            assert!(!j[field].is_null(), "{field} must be present on the wire");
        }
        assert_eq!(
            j["eventId"].as_str().unwrap().len(),
            64,
            "consumers correlate on the full event id"
        );
    }

    #[test]
    fn an_uncorrelated_event_mints_no_receipt() {
        // ADR-2010: an unknown request stays unresolved until correlated. We
        // decline to mint a receipt we could never join to a case.
        let ev = event(vec![t(&["op", "publish"])], r#"{"action":"approve"}"#);
        assert!(correlate(&ev).is_none());
        let ev = event(vec![t(&["d", ""])], r#"{"action":"approve"}"#);
        assert!(correlate(&ev).is_none());
    }
}

#[cfg(test)]
mod application_stage_wire_tests {
    //! FR4.1: the read API must speak the extended ladder, or the human who
    //! approved something still cannot see whether it happened.
    use super::*;

    fn applied_row() -> ReceiptRow {
        ReceiptRow {
            event_id: "e".repeat(64),
            kind: 31403,
            case_id: "case-1".to_string(),
            request_event_id: Some("r".repeat(64)),
            signer_pubkey: "a".repeat(64),
            decision_outcome: Some("approve".to_string()),
            target_operation: Some("publish".to_string()),
            supersedes_event_id: None,
            stage: ReceiptStage::Applied.as_str().to_string(),
            stage_error: None,
            decision_id: Some("dec-eeeeeeeeeeeeeeee".to_string()),
            signed_at: 1_700_000_000,
            accepted_at: Some(1_700_000_001),
            projected_at: Some(1_700_000_002),
            replays: 0,
            applied_at: Some(1_700_000_099),
            applied_by: Some("b".repeat(64)),
            acknowledgement: Some("published to the mesh, 3 records written".to_string()),
        }
    }

    #[test]
    fn an_applied_receipt_serialises_its_provenance() {
        let json = receipt_json(&applied_row());
        assert_eq!(json["stage"], "applied");
        assert_eq!(json["applied"], true);
        assert_eq!(json["isApplicationStage"], true);
        assert_eq!(json["appliedAt"], 1_700_000_099i64);
        assert_eq!(json["appliedBy"], "b".repeat(64));
        assert_eq!(
            json["acknowledgement"],
            "published to the mesh, 3 records written"
        );
    }

    /// The distinction the whole receipt ladder exists for: a decision the
    /// owner declined to apply is not applied, and is not a denial either.
    #[test]
    fn a_not_applied_receipt_is_not_applied() {
        let mut row = applied_row();
        row.stage = ReceiptStage::NotApplied.as_str().to_string();
        row.acknowledgement = Some("target branch was deleted upstream".to_string());
        let json = receipt_json(&row);
        assert_eq!(json["applied"], false);
        assert_eq!(json["isApplicationStage"], true);
        assert_eq!(json["awaitsProjection"], false);
    }

    /// A receipt nobody has reported on yet says so by absence, not by a
    /// fabricated default (PRD non-functional rule 1).
    #[test]
    fn an_unreported_receipt_carries_null_provenance() {
        let mut row = applied_row();
        row.stage = ReceiptStage::ProjectionCommitted.as_str().to_string();
        row.applied_at = None;
        row.applied_by = None;
        row.acknowledgement = None;
        let json = receipt_json(&row);
        assert_eq!(json["isApplicationStage"], false);
        assert!(json["appliedAt"].is_null());
        assert!(json["appliedBy"].is_null());
        assert!(json["acknowledgement"].is_null());
        // Still applied in the relay's sense: the projection committed.
        assert_eq!(json["applied"], true);
    }
}
