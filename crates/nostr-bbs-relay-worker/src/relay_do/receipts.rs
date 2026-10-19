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

    // The `e` tag marked `request` cites the originating 31402; failing that an
    // appeal's target; failing that the first UNMARKED `e` tag, which is the
    // shape every 31403 producer in the estate actually emits (the forum
    // client signs `["e", <request id>]`). A tag with any other marker —
    // `supersedes`, `appeal` — is never read as the request. Reading the
    // unmarked tag cannot bind a decision to the wrong case: the projection
    // still requires this id to equal the case's own `nostr_event_id`.
    let request_event_id = tag_with_marker(event, "e", "request")
        .or_else(|| governance::extract_appeal_target(&event.tags).map(str::to_string))
        .or_else(|| unmarked_tag(event, "e"));

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

/// First value of a `name` tag that carries no NIP-01 marker (fewer than four
/// elements, or an empty marker).
fn unmarked_tag(event: &NostrEvent, name: &str) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == name && t.get(3).is_none_or(|m| m.is_empty()))
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

/// Case states a supersession may act on (DDD §7a.3). `reopened` is the
/// appeal-then-overturn path; an `open` or `under_review` case gets a first-order
/// decision instead. Held identical to the `IN (...)` list in
/// [`SUPERSESSION_DECISION_SQL`] by a test.
pub const SUPERSEDABLE_STATES: [&str; 6] = [
    "decided",
    "delegated",
    "promoted",
    "precedent",
    "superseded",
    "reopened",
];

// Supersession batch (ADR-2010 / DDD §7a). Four statements, each conditional on
// its predecessor having changed exactly one row, so a stale snapshot writes
// nothing at all. S1 appends the superseding decision only if the case is still
// in the state the plan saw (and that state is supersedable), the superseded
// decision still belongs to this case and is still effective, and the event's
// own receipt is awaiting projection.
const SUPERSESSION_DECISION_SQL: &str = r#"INSERT INTO broker_decisions
 (decision_id, case_id, outcome, outcome_detail, broker_pubkey, reasoning, prior_decision_id, decided_at)
 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8
 WHERE EXISTS (SELECT 1 FROM broker_cases WHERE id = ?2 AND state = ?9
 AND state IN ('decided', 'delegated', 'promoted', 'precedent', 'superseded', 'reopened'))
 AND EXISTS (SELECT 1 FROM broker_decisions WHERE decision_id = ?7 AND case_id = ?2 AND superseded_by IS NULL)
 AND EXISTS (SELECT 1 FROM governance_receipts WHERE event_id = ?10 AND case_id = ?2
 AND stage IN ('relay-accepted', 'projection-failed'))"#;
const SUPERSESSION_MARK_SQL: &str = r#"UPDATE broker_decisions SET superseded_by = ?1
 WHERE decision_id = ?2 AND superseded_by IS NULL AND changes() = 1"#;
const SUPERSESSION_CASE_SQL: &str = r#"UPDATE broker_cases
 SET state = 'superseded', assigned_to = ?1, updated_at = ?2
 WHERE id = ?3 AND changes() = 1"#;

/// The complete set of writes one committed supersession performs. Carried
/// together because they must commit together: the superseding decision row, the
/// `superseded_by` mark on the decision it replaces, the case's move to
/// `superseded`, and the receipt's transition to `projection-committed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupersessionCommit {
    /// Full signed id of the superseding 31403.
    pub event_id: String,
    /// The case named by the superseding event's own `d` tag.
    pub case_id: String,
    /// Full event id of the decision being superseded (the `supersedes` `e` tag).
    pub superseded_event_id: String,
    /// `broker_decisions.decision_id` of the decision being superseded.
    pub superseded_decision_id: String,
    /// The case state the plan was made against.
    pub expected_state: String,
    /// `broker_decisions.decision_id` of the superseding decision.
    pub decision_id: String,
    /// Canonical action string.
    pub outcome: String,
    /// Delegate target, amend diff and so on.
    pub outcome_detail: Option<String>,
    /// The stated reason (§7a.2).
    pub reasoning: String,
    /// The superseder's pubkey.
    pub broker_pubkey: String,
    /// `event.created_at`.
    pub decided_at: u64,
}

/// Reopen a terminal case for its requester of record (appeal standing, DDD
/// §7a.2). `?1` now, `?2` case, `?3` appellant, `?4` the cited decision id. One
/// row changes only if the appellant is the case's `created_by` (compared
/// case-insensitively, KF-6), the case is in a terminal state, and the cited
/// decision belongs to this very case; anything else changes nothing.
pub const APPEAL_REOPEN_SQL: &str = "UPDATE broker_cases SET state = 'reopened', updated_at = ?1 \
 WHERE id = ?2 AND lower(created_by) = lower(?3) \
 AND state IN ('decided', 'delegated', 'promoted', 'precedent', 'superseded') \
 AND EXISTS (SELECT 1 FROM broker_decisions WHERE decision_id = ?4 AND case_id = ?2)";

/// The writes one committed appeal performs: the case reopening and the
/// receipt's transition, as one batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppealCommit {
    /// Full signed id of the appeal 31402.
    pub event_id: String,
    /// The case being reopened (the appeal's `case` tag).
    pub case_id: String,
    /// The appellant's pubkey.
    pub appellant: String,
    /// Full event id of the cited decision (the `appeal`-marked `e` tag).
    pub cited_event_id: String,
    /// `broker_decisions.decision_id` derived from the cited event.
    pub cited_decision_id: String,
    /// `event.created_at`.
    pub at: u64,
}

/// What one stage-machine run commits: a first-order response or a supersession.
#[derive(Debug, Clone, Copy)]
pub enum Commit<'a> {
    /// A first-order decision (`request`-correlated).
    Response(&'a ProjectionCommit),
    /// A superseding decision (`supersedes`-correlated; carries no request id).
    Supersession(&'a SupersessionCommit),
    /// An appeal reopening a case (`appeal`-correlated).
    Appeal(&'a AppealCommit),
}

impl Commit<'_> {
    /// Whether `correlation` describes the same signed event this plan was
    /// assembled from. An incomplete receipt never certifies a different one.
    fn matches(&self, correlation: &ReceiptCorrelation) -> bool {
        match self {
            Commit::Response(c) => {
                correlation.event_id == c.event_id
                    && correlation.case_id == c.case_id
                    && correlation.signer_pubkey == c.broker_pubkey
                    && correlation.request_event_id.as_deref() == Some(c.request_event_id.as_str())
                    && correlation.decision_outcome.as_deref() == Some(c.outcome.as_str())
            }
            Commit::Supersession(c) => {
                correlation.event_id == c.event_id
                    && correlation.case_id == c.case_id
                    && correlation.signer_pubkey == c.broker_pubkey
                    && correlation.supersedes_event_id.as_deref()
                        == Some(c.superseded_event_id.as_str())
                    && correlation.decision_outcome.as_deref() == Some(c.outcome.as_str())
            }
            // The receipt's `case_id` is the appeal's `d` tag until ADR-2024 gives
            // the appeal its own `case` correlation, so only the signed event,
            // the appellant and the cited decision are bound here.
            Commit::Appeal(c) => {
                correlation.event_id == c.event_id
                    && correlation.signer_pubkey == c.appellant
                    && correlation.request_event_id.as_deref() == Some(c.cited_event_id.as_str())
            }
        }
    }

    fn event_id(&self) -> &str {
        match self {
            Commit::Response(c) => &c.event_id,
            Commit::Supersession(c) => &c.event_id,
            Commit::Appeal(c) => &c.event_id,
        }
    }
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
#[allow(clippy::double_must_use)] // async_trait's own must_use; see nostr-bbs-core signer.rs
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

    /// Commit a supersession: the superseding decision row, the `superseded_by`
    /// mark, the case's move to `superseded` and the receipt's transition, **as
    /// one transaction**, each statement required to change exactly one row.
    async fn commit_supersession(&self, commit: &SupersessionCommit) -> Result<(), String>;

    /// Commit an appeal: reopen the case and move the receipt to
    /// `projection-committed` as one transaction.
    async fn commit_appeal(&self, commit: &AppealCommit) -> Result<(), String>;

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
    commit: Commit<'_>,
    now: u64,
) -> ReceiptOutcome
where
    S: ReceiptStore + ?Sized,
{
    // Refuse a caller assembling a plan from a different signed response or
    // request. An incomplete receipt never certifies an external operation.
    if !commit.matches(correlation) {
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

    let committed = match commit {
        Commit::Response(c) => store.commit_projection(c).await,
        Commit::Supersession(c) => store.commit_supersession(c).await,
        Commit::Appeal(c) => store.commit_appeal(c).await,
    };
    match committed {
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
                .mark_projection_failed(commit.event_id(), &e, now)
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

    /// Run `stmts` as one D1 batch and require every statement to have
    /// succeeded and changed exactly one row (a zero is a TOCTOU conflict: the
    /// snapshot the plan was made against has moved).
    async fn run_batch(&self, stmts: Vec<worker::D1PreparedStatement>) -> Result<(), String> {
        let expected = stmts.len();
        let results = self
            .db
            .batch(stmts)
            .await
            .map_err(|e| format!("projection batch failed: {e:?}"))?;

        if results.len() != expected {
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
        self.run_batch(vec![decision, case, receipt]).await
    }

    async fn commit_supersession(&self, c: &SupersessionCommit) -> Result<(), String> {
        let decision = self
            .db
            .prepare(SUPERSESSION_DECISION_SQL)
            .bind(&[
                JsValue::from_str(&c.decision_id),
                JsValue::from_str(&c.case_id),
                JsValue::from_str(&c.outcome),
                js_opt(c.outcome_detail.as_deref()),
                JsValue::from_str(&c.broker_pubkey),
                JsValue::from_str(&c.reasoning),
                JsValue::from_str(&c.superseded_decision_id),
                JsValue::from_f64(c.decided_at as f64),
                JsValue::from_str(&c.expected_state),
                JsValue::from_str(&c.event_id),
            ])
            .map_err(|e| format!("supersession decision bind: {e:?}"))?;
        let mark = self
            .db
            .prepare(SUPERSESSION_MARK_SQL)
            .bind(&[
                JsValue::from_str(&c.decision_id),
                JsValue::from_str(&c.superseded_decision_id),
            ])
            .map_err(|e| format!("supersession mark bind: {e:?}"))?;
        let case = self
            .db
            .prepare(SUPERSESSION_CASE_SQL)
            .bind(&[
                JsValue::from_str(&c.broker_pubkey),
                JsValue::from_f64(c.decided_at as f64),
                JsValue::from_str(&c.case_id),
            ])
            .map_err(|e| format!("supersession case bind: {e:?}"))?;
        let receipt = self
            .db
            .prepare(PROJECTION_RECEIPT_SQL)
            .bind(&[
                JsValue::from_str(ReceiptStage::ProjectionCommitted.as_str()),
                JsValue::from_f64(c.decided_at as f64),
                JsValue::from_str(&c.decision_id),
                JsValue::from_str(&c.event_id),
            ])
            .map_err(|e| format!("supersession receipt bind: {e:?}"))?;
        self.run_batch(vec![decision, mark, case, receipt]).await
    }

    async fn commit_appeal(&self, c: &AppealCommit) -> Result<(), String> {
        let reopen = self
            .db
            .prepare(APPEAL_REOPEN_SQL)
            .bind(&[
                JsValue::from_f64(c.at as f64),
                JsValue::from_str(&c.case_id),
                JsValue::from_str(&c.appellant),
                JsValue::from_str(&c.cited_decision_id),
            ])
            .map_err(|e| format!("appeal reopen bind: {e:?}"))?;
        let receipt = self
            .db
            .prepare(PROJECTION_RECEIPT_SQL)
            .bind(&[
                JsValue::from_str(ReceiptStage::ProjectionCommitted.as_str()),
                JsValue::from_f64(c.at as f64),
                JsValue::NULL,
                JsValue::from_str(&c.event_id),
            ])
            .map_err(|e| format!("appeal receipt bind: {e:?}"))?;
        self.run_batch(vec![reopen, receipt]).await
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

/// SQLite fixtures for the governance projection SQL, shared by the receipt and
/// appeal tests. The DDL comes from the constants `ensure_schema` applies, not
/// from `migrations/`: the live schema path is what deploys, and migration 0002
/// lacks `broker_decisions.superseded_by`, which only `ensure_schema` adds.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::{
        BROKER_CASES_CREATE_SQL, BROKER_DECISIONS_CREATE_SQL, GOVERNANCE_RECEIPTS_CREATE_SQL,
    };

    /// An in-memory database with the three governance tables as `ensure_schema`
    /// leaves them (including the ADR-2011 `effective_tier` column).
    pub(crate) fn governance_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        for ddl in [
            BROKER_CASES_CREATE_SQL,
            BROKER_DECISIONS_CREATE_SQL,
            GOVERNANCE_RECEIPTS_CREATE_SQL,
            "ALTER TABLE broker_cases ADD COLUMN effective_tier TEXT",
        ] {
            conn.execute(ddl, []).unwrap();
        }
        conn
    }

    /// Insert a case in `state`.
    pub(crate) fn seed_case(
        conn: &rusqlite::Connection,
        id: &str,
        state: &str,
        created_by: &str,
        effective_tier: Option<&str>,
    ) {
        conn.execute(
            "INSERT INTO broker_cases (id, category, subject_kind, subject_id, title, state, \
             created_by, nostr_event_id, created_at, updated_at, effective_tier) \
             VALUES (?1, 'manual_submission', 'x', 'x', 't', ?2, ?3, ?4, 1, 1, ?5)",
            rusqlite::params![id, state, created_by, format!("req-{id}"), effective_tier],
        )
        .unwrap();
    }

    /// Insert an effective (not superseded) decision.
    pub(crate) fn seed_decision(
        conn: &rusqlite::Connection,
        decision_id: &str,
        case_id: &str,
        signer: &str,
    ) {
        conn.execute(
            "INSERT INTO broker_decisions (decision_id, case_id, outcome, broker_pubkey, decided_at) \
             VALUES (?1, ?2, 'approve', ?3, 1)",
            rusqlite::params![decision_id, case_id, signer],
        )
        .unwrap();
    }

    /// Insert a receipt at `stage`.
    pub(crate) fn seed_receipt(
        conn: &rusqlite::Connection,
        event_id: &str,
        case_id: &str,
        stage: &str,
    ) {
        conn.execute(
            "INSERT INTO governance_receipts (event_id, kind, case_id, signer_pubkey, stage, \
             signed_at) VALUES (?1, 31403, ?2, 'human-bob', ?3, 1)",
            rusqlite::params![event_id, case_id, stage],
        )
        .unwrap();
    }
}

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

        async fn commit_appeal(&self, c: &AppealCommit) -> Result<(), String> {
            *self.commit_calls.borrow_mut() += 1;
            self.applied
                .borrow_mut()
                .case_states
                .insert(c.case_id.clone(), "reopened".to_string());
            let mut receipts = self.receipts.borrow_mut();
            let replays = receipts.get(&c.event_id).map(|r| r.1).unwrap_or(0);
            receipts.insert(
                c.event_id.clone(),
                (ReceiptStage::ProjectionCommitted, replays, None),
            );
            Ok(())
        }

        async fn commit_supersession(&self, c: &SupersessionCommit) -> Result<(), String> {
            *self.commit_calls.borrow_mut() += 1;
            {
                let mut left = self.fail_commit_times.borrow_mut();
                if *left > 0 {
                    *left -= 1;
                    return Err("D1_ERROR: projection batch aborted".to_string());
                }
            }
            let mut applied = self.applied.borrow_mut();
            if !applied.decisions.contains(&c.decision_id) {
                applied.decisions.push(c.decision_id.clone());
            }
            applied
                .case_states
                .insert(c.case_id.clone(), "superseded".to_string());
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
                block_on(apply_with_receipt(
                    &store,
                    &c,
                    Commit::Response(&commit_plan()),
                    1
                )),
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
            Commit::Response(&commit_plan()),
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

        let first = block_on(apply_with_receipt(&store, &c, Commit::Response(&plan), 1));
        assert!(matches!(first, ReceiptOutcome::Committed { .. }));

        // Same signed event delivered twice more.
        let second = block_on(apply_with_receipt(&store, &c, Commit::Response(&plan), 2));
        let third = block_on(apply_with_receipt(&store, &c, Commit::Response(&plan), 3));

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
            Commit::Response(&commit_plan()),
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

        let first = block_on(apply_with_receipt(&store, &c, Commit::Response(&plan), 5));
        assert!(matches!(first, ReceiptOutcome::ProjectionFailed { .. }));

        let second = block_on(apply_with_receipt(&store, &c, Commit::Response(&plan), 6));
        assert_eq!(second, ReceiptOutcome::Reconciled { replays: 1 });
        assert_eq!(store.decision_count(), 1);
        assert_eq!(store.case_state("case-1").as_deref(), Some("approved"));
        assert_eq!(
            store.stage_of(&"e".repeat(64)),
            Some(ReceiptStage::ProjectionCommitted)
        );

        // A third delivery is now a plain duplicate.
        let third = block_on(apply_with_receipt(&store, &c, Commit::Response(&plan), 7));
        assert!(matches!(third, ReceiptOutcome::DuplicateIgnored { .. }));
        assert_eq!(store.decision_count(), 1, "still exactly one mutation");
    }

    #[test]
    fn repeated_projection_failures_never_apply_the_mutation() {
        let store = FakeStore::new().failing_commits(3);
        let c = correlation();
        let plan = commit_plan();
        for _ in 0..3 {
            let out = block_on(apply_with_receipt(&store, &c, Commit::Response(&plan), 9));
            assert!(!out.is_applied());
        }
        assert_eq!(store.decision_count(), 0);
        assert_eq!(
            store.stage_of(&"e".repeat(64)),
            Some(ReceiptStage::ProjectionFailed)
        );
        // The fourth succeeds once the injected failures are exhausted.
        let ok = block_on(apply_with_receipt(&store, &c, Commit::Response(&plan), 10));
        assert!(ok.is_applied());
        assert_eq!(store.decision_count(), 1);
    }

    #[test]
    fn a_receipt_that_cannot_be_written_is_reported_not_swallowed() {
        let store = FakeStore::new().failing_accept("D1_ERROR: receipts unavailable");
        let out = block_on(apply_with_receipt(
            &store,
            &correlation(),
            Commit::Response(&commit_plan()),
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

    /// The forum client signs a 31403 as `[["d", case], ["e", request]]` with
    /// no marker. Before this was read, every decision taken in the forum UI
    /// correlated with no request, `apply_with_receipt` returned
    /// `Uncorrelated`, and the decision never reached `broker_decisions` while
    /// the relay's OK said it was accepted.
    #[test]
    fn the_forum_clients_unmarked_request_tag_correlates() {
        let req = "b".repeat(64);
        let ev = event(
            vec![t(&["d", "case-9"]), t(&["e", &req])],
            r#"{"action":"approve","reasoning":"I have read the diff and it is right."}"#,
        );
        let c = correlate(&ev).expect("correlates");
        assert_eq!(c.request_event_id.as_deref(), Some(req.as_str()));
        // An explicitly empty marker is still unmarked.
        let ev = event(vec![t(&["d", "case-9"]), t(&["e", &req, "", ""])], "{}");
        assert_eq!(
            correlate(&ev).unwrap().request_event_id.as_deref(),
            Some(req.as_str())
        );
    }

    #[test]
    fn a_marked_request_wins_and_other_markers_are_never_the_request() {
        let req = "b".repeat(64);
        let other = "d".repeat(64);
        let sup = "c".repeat(64);
        let ev = event(
            vec![
                t(&["d", "case-9"]),
                t(&["e", &other]),
                t(&["e", &req, "", "request"]),
            ],
            "{}",
        );
        assert_eq!(
            correlate(&ev).unwrap().request_event_id.as_deref(),
            Some(req.as_str())
        );
        let ev = event(
            vec![t(&["d", "case-9"]), t(&["e", &sup, "", "supersedes"])],
            "{}",
        );
        let c = correlate(&ev).unwrap();
        assert_eq!(c.request_event_id, None);
        assert_eq!(c.supersedes_event_id.as_deref(), Some(sup.as_str()));
    }

    /// End to end through the receipt store: a response in the client's
    /// shape now reaches `projection-committed` and writes its decision.
    #[test]
    fn an_unmarked_response_now_commits_its_projection() {
        let ev = event(
            vec![t(&["d", "case-1"]), t(&["e", &"r".repeat(64)])],
            r#"{"action":"approve"}"#,
        );
        let c = correlate(&ev).unwrap();
        let store = FakeStore::new();
        let out = block_on(apply_with_receipt(
            &store,
            &c,
            Commit::Response(&commit_plan()),
            1,
        ));
        assert_eq!(
            out,
            ReceiptOutcome::Committed {
                stage: ReceiptStage::ProjectionCommitted
            }
        );
        assert_eq!(store.decision_count(), 1);

        // The same response with the request tag pointing elsewhere still
        // cannot commit against this case.
        let ev = event(
            vec![t(&["d", "case-1"]), t(&["e", &"x".repeat(64)])],
            r#"{"action":"approve"}"#,
        );
        let c = correlate(&ev).unwrap();
        let store = FakeStore::new();
        let out = block_on(apply_with_receipt(
            &store,
            &c,
            Commit::Response(&commit_plan()),
            1,
        ));
        assert_eq!(out, ReceiptOutcome::Uncorrelated);
        assert_eq!(store.decision_count(), 0);
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

    fn supersession_event(tags: Vec<Vec<String>>) -> NostrEvent {
        event(tags, r#"{"action":"reject","reasoning":"revoked"}"#)
    }

    fn supersession_correlation() -> ReceiptCorrelation {
        ReceiptCorrelation {
            event_id: "s".repeat(64),
            kind: 31403,
            case_id: "case-1".into(),
            request_event_id: None,
            signer_pubkey: "human-bob".into(),
            decision_outcome: Some("reject".into()),
            target_operation: None,
            supersedes_event_id: Some("a".repeat(64)),
            signed_at: 10,
        }
    }

    fn supersession_plan() -> SupersessionCommit {
        SupersessionCommit {
            event_id: "s".repeat(64),
            case_id: "case-1".into(),
            superseded_event_id: "a".repeat(64),
            superseded_decision_id: format!("dec-{}", "a".repeat(16)),
            expected_state: "decided".into(),
            decision_id: format!("dec-{}", "s".repeat(16)),
            outcome: "reject".into(),
            outcome_detail: None,
            reasoning: "revoked".into(),
            broker_pubkey: "human-bob".into(),
            decided_at: 10,
        }
    }

    #[test]
    fn supersession_correlation_uses_supersedes_tag_not_request() {
        // A supersedes-only 31403 carries no request id; the `supersedes` marked
        // `e` tag must never be read as the request.
        let target = "a".repeat(64);
        let c = correlate(&supersession_event(vec![
            t(&["d", "case-1"]),
            t(&["e", &target, "", "supersedes"]),
        ]))
        .expect("correlates");
        assert_eq!(c.request_event_id, None);
        assert_eq!(c.supersedes_event_id.as_deref(), Some(target.as_str()));
        assert_eq!(c.decision_outcome.as_deref(), Some("reject"));
    }

    #[test]
    fn supersession_commits_through_the_stage_machine_without_a_request_id() {
        let store = FakeStore::new();
        let out = block_on(apply_with_receipt(
            &store,
            &supersession_correlation(),
            Commit::Supersession(&supersession_plan()),
            10,
        ));
        assert!(matches!(out, ReceiptOutcome::Committed { .. }), "{out:?}");
        assert_eq!(store.case_state("case-1").as_deref(), Some("superseded"));
        assert_eq!(
            store.stage_of(&"s".repeat(64)),
            Some(ReceiptStage::ProjectionCommitted)
        );
    }

    #[test]
    fn supersession_redelivery_is_duplicate_ignored() {
        let store = FakeStore::new();
        let c = supersession_correlation();
        let plan = supersession_plan();
        let first = block_on(apply_with_receipt(
            &store,
            &c,
            Commit::Supersession(&plan),
            10,
        ));
        let second = block_on(apply_with_receipt(
            &store,
            &c,
            Commit::Supersession(&plan),
            11,
        ));
        assert!(matches!(first, ReceiptOutcome::Committed { .. }));
        assert_eq!(second, ReceiptOutcome::DuplicateIgnored { replays: 1 });
        assert_eq!(store.decision_count(), 1);
        assert_eq!(*store.commit_calls.borrow(), 1, "no second mutation");
    }

    #[test]
    fn a_supersession_plan_for_another_target_is_uncorrelated() {
        let store = FakeStore::new();
        let mut plan = supersession_plan();
        plan.superseded_event_id = "b".repeat(64);
        let out = block_on(apply_with_receipt(
            &store,
            &supersession_correlation(),
            Commit::Supersession(&plan),
            10,
        ));
        assert_eq!(out, ReceiptOutcome::Uncorrelated);
        assert_eq!(store.decision_count(), 0);
    }

    #[test]
    fn supersedable_states_match_the_batch_sql() {
        for state in SUPERSEDABLE_STATES {
            assert!(
                SUPERSESSION_DECISION_SQL.contains(&format!("'{state}'")),
                "{state} missing from the SQL"
            );
        }
        assert!(!SUPERSESSION_DECISION_SQL.contains("'open'"));
        assert!(!SUPERSESSION_DECISION_SQL.contains("'under_review'"));
    }

    #[test]
    fn an_appeal_commits_through_the_stage_machine_and_redelivery_is_ignored() {
        let cited = "a".repeat(64);
        let correlation = ReceiptCorrelation {
            event_id: "p".repeat(64),
            kind: 31402,
            case_id: "appeal-9".into(),
            request_event_id: Some(cited.clone()),
            signer_pubkey: "agent-alice".into(),
            decision_outcome: None,
            target_operation: None,
            supersedes_event_id: None,
            signed_at: 5,
        };
        let plan = AppealCommit {
            event_id: "p".repeat(64),
            case_id: "case-1".into(),
            appellant: "agent-alice".into(),
            cited_event_id: cited.clone(),
            cited_decision_id: format!("dec-{}", &cited[..16]),
            at: 5,
        };
        let store = FakeStore::new();
        let first = block_on(apply_with_receipt(
            &store,
            &correlation,
            Commit::Appeal(&plan),
            5,
        ));
        let second = block_on(apply_with_receipt(
            &store,
            &correlation,
            Commit::Appeal(&plan),
            6,
        ));
        assert!(
            matches!(first, ReceiptOutcome::Committed { .. }),
            "{first:?}"
        );
        assert_eq!(second, ReceiptOutcome::DuplicateIgnored { replays: 1 });
        assert_eq!(store.case_state("case-1").as_deref(), Some("reopened"));

        let mut other = plan.clone();
        other.cited_event_id = "b".repeat(64);
        assert_eq!(
            block_on(apply_with_receipt(
                &FakeStore::new(),
                &correlation,
                Commit::Appeal(&other),
                5
            )),
            ReceiptOutcome::Uncorrelated
        );
    }

    // -- The supersession batch, run against SQLite (the engine D1 is built on) --

    use super::test_support::*;

    /// Run the four supersession statements in order inside one transaction and
    /// return rows changed by each, as D1's `batch` reports them.
    fn run_supersession(conn: &mut rusqlite::Connection, c: &SupersessionCommit) -> Vec<usize> {
        let tx = conn.transaction().unwrap();
        let changes = vec![
            tx.execute(
                SUPERSESSION_DECISION_SQL,
                rusqlite::params![
                    c.decision_id,
                    c.case_id,
                    c.outcome,
                    c.outcome_detail,
                    c.broker_pubkey,
                    c.reasoning,
                    c.superseded_decision_id,
                    c.decided_at as i64,
                    c.expected_state,
                    c.event_id
                ],
            )
            .unwrap(),
            tx.execute(
                SUPERSESSION_MARK_SQL,
                rusqlite::params![c.decision_id, c.superseded_decision_id],
            )
            .unwrap(),
            tx.execute(
                SUPERSESSION_CASE_SQL,
                rusqlite::params![c.broker_pubkey, c.decided_at as i64, c.case_id],
            )
            .unwrap(),
            tx.execute(
                PROJECTION_RECEIPT_SQL,
                rusqlite::params![
                    ReceiptStage::ProjectionCommitted.as_str(),
                    c.decided_at as i64,
                    c.decision_id,
                    c.event_id
                ],
            )
            .unwrap(),
        ];
        tx.commit().unwrap();
        changes
    }

    fn seeded(state: &str) -> (rusqlite::Connection, SupersessionCommit) {
        let plan = supersession_plan();
        let conn = governance_db();
        seed_case(&conn, &plan.case_id, state, "agent-alice", None);
        seed_decision(
            &conn,
            &plan.superseded_decision_id,
            &plan.case_id,
            "human-bob",
        );
        seed_receipt(&conn, &plan.event_id, &plan.case_id, "relay-accepted");
        (conn, plan)
    }

    fn one(conn: &rusqlite::Connection, sql: &str) -> Option<String> {
        use rusqlite::types::Value;
        match conn.query_row(sql, [], |r| r.get::<_, Value>(0)).unwrap() {
            Value::Null => None,
            Value::Integer(n) => Some(n.to_string()),
            Value::Text(t) => Some(t),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn supersession_batch_commits_all_four_together() {
        let (mut conn, plan) = seeded("decided");
        assert_eq!(run_supersession(&mut conn, &plan), vec![1, 1, 1, 1]);
        assert_eq!(
            one(&conn, "SELECT state FROM broker_cases").as_deref(),
            Some("superseded")
        );
        assert_eq!(
            one(
                &conn,
                &format!(
                    "SELECT superseded_by FROM broker_decisions WHERE decision_id = '{}'",
                    plan.superseded_decision_id
                )
            )
            .as_deref(),
            Some(plan.decision_id.as_str())
        );
        assert_eq!(
            one(
                &conn,
                &format!(
                    "SELECT prior_decision_id FROM broker_decisions WHERE decision_id = '{}'",
                    plan.decision_id
                )
            )
            .as_deref(),
            Some(plan.superseded_decision_id.as_str())
        );
        assert_eq!(
            one(&conn, "SELECT stage FROM governance_receipts").as_deref(),
            Some("projection-committed")
        );
    }

    #[test]
    fn supersession_batch_commits_from_a_reopened_case() {
        let (mut conn, plan) = seeded("reopened");
        let mut plan = plan;
        plan.expected_state = "reopened".into();
        assert_eq!(run_supersession(&mut conn, &plan), vec![1, 1, 1, 1]);
    }

    #[test]
    fn supersession_batch_writes_nothing_when_case_moved() {
        // The plan saw `decided`; the case has since moved on.
        let (mut conn, plan) = seeded("reopened");
        assert_eq!(run_supersession(&mut conn, &plan), vec![0, 0, 0, 0]);
        assert_eq!(
            one(&conn, "SELECT state FROM broker_cases").as_deref(),
            Some("reopened")
        );
        assert_eq!(
            one(&conn, "SELECT superseded_by FROM broker_decisions"),
            None,
            "prior decision unmutated"
        );
        assert_eq!(
            one(&conn, "SELECT count(*) FROM broker_decisions").as_deref(),
            Some("1")
        );
        assert_eq!(
            one(&conn, "SELECT stage FROM governance_receipts").as_deref(),
            Some("relay-accepted")
        );
    }

    #[test]
    fn supersession_batch_refuses_an_open_case_even_if_the_snapshot_says_so() {
        let (mut conn, mut plan) = seeded("open");
        plan.expected_state = "open".into();
        assert_eq!(run_supersession(&mut conn, &plan), vec![0, 0, 0, 0]);
        assert_eq!(
            one(&conn, "SELECT state FROM broker_cases").as_deref(),
            Some("open")
        );
    }

    #[test]
    fn supersession_batch_refuses_an_already_superseded_target() {
        let (mut conn, plan) = seeded("decided");
        conn.execute(
            "UPDATE broker_decisions SET superseded_by = 'dec-other'",
            [],
        )
        .unwrap();
        assert_eq!(run_supersession(&mut conn, &plan), vec![0, 0, 0, 0]);
        assert_eq!(
            one(&conn, "SELECT superseded_by FROM broker_decisions").as_deref(),
            Some("dec-other")
        );
    }

    #[test]
    fn supersession_batch_refuses_a_decision_from_another_case() {
        let plan = supersession_plan();
        let mut conn = governance_db();
        seed_case(&conn, "case-1", "decided", "agent-alice", None);
        seed_case(&conn, "case-b", "decided", "agent-alice", None);
        seed_decision(&conn, &plan.superseded_decision_id, "case-b", "human-bob");
        seed_receipt(&conn, &plan.event_id, "case-1", "relay-accepted");
        assert_eq!(run_supersession(&mut conn, &plan), vec![0, 0, 0, 0]);
        assert_eq!(
            one(&conn, "SELECT superseded_by FROM broker_decisions"),
            None
        );
    }

    #[test]
    fn supersession_batch_needs_a_receipt_awaiting_projection() {
        let (mut conn, plan) = seeded("decided");
        conn.execute(
            "UPDATE governance_receipts SET stage = 'projection-committed'",
            [],
        )
        .unwrap();
        assert_eq!(run_supersession(&mut conn, &plan), vec![0, 0, 0, 0]);
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
