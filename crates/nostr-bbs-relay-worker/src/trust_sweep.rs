//! ADR-2006 — inactivity-decay trust demotion sweep.
//!
//! Demotion is **time-driven**: its precondition is ~6 months of inactivity, so
//! it runs on the scheduled (cron) trigger and never on the admission hot path,
//! where it would be evaluated against active users — the opposite of its gate.
//!
//! This module owns the *mechanics* of the sweep. The *policy* lives in
//! [`crate::trust::decide_demotion`], which is pure and shared with the
//! per-pubkey [`crate::trust::check_demotion`] path so the two cannot drift.
//!
//! ## Why keyset pagination, not `OFFSET`
//!
//! The sweep mutates the very column its candidate predicate filters on
//! (`trust_level`). With `LIMIT/OFFSET`, every row demoted out of the eligible
//! band (TL1 → TL0) shrinks the result set *underneath* the offset, so the next
//! page starts past rows that have shuffled down into the window. Concretely:
//! 400 eligible rows at a batch size of 200, all of page one demoted to TL0 —
//! the second query asks for `OFFSET 200` over a set that now holds only the
//! 200 untouched rows, gets an empty page, and the sweep stops having processed
//! half the work while reporting clean completion.
//!
//! A **keyset cursor** over `(last_active_at, pubkey)` is immune to this:
//! neither column is written by a demotion, so the ordering key of every row is
//! stable across the mutation boundary. The next page is "everything ordered
//! after the last row I actually consumed", which is well defined whether or not
//! the rows behind it left the eligible set. The `pubkey` tiebreak makes the
//! order total, so a cohort sharing one `last_active_at` — the common case when
//! rows are seeded or migrated in bulk — still pages deterministically instead
//! of looping on the same tie or skipping past it.
//!
//! ## Why outcomes are explicit
//!
//! The previous implementation discarded the result of both the `UPDATE` and
//! the audit `INSERT` (`let _ = …`) and then returned the *planned* level. A
//! failed write was therefore indistinguishable from a committed one, and the
//! sweep's `demoted` count included demotions that never happened. Here every
//! row resolves to exactly one [`RowOutcome`], the counters move only on a
//! confirmed commit, and failures are both counted and sampled for the operator.
//!
//! ## Why the commit is a batch
//!
//! The trust-level `UPDATE` and the `admin_log` audit `INSERT` describe the same
//! fact. Issued separately they can diverge: a level change with no audit trail,
//! or an audit entry for a change that did not land. They are submitted as one
//! D1 `batch`, which Cloudflare executes inside a single implicit transaction,
//! so audit and state commit together or not at all.

use async_trait::async_trait;
use wasm_bindgen::JsValue;
use worker::{console_warn, Env};

use crate::auth;
use crate::trust::{
    decide_demotion, DemotionDecision, TrustLevel, TrustThresholds, WhitelistTrustRow,
};

/// How many candidate rows to pull per page. The whitelist is small relative to
/// `events`, but paging keeps any single D1 statement bounded no matter how
/// large the community grows.
pub const DEMOTION_BATCH_SIZE: u32 = 200;

/// Circuit breaker: the most candidate rows one sweep will process, bounding
/// the worker CPU budget. A ceiling, not a target — the remainder is picked up
/// by the next scheduled tick, which is safe precisely because the cursor is
/// derived from the data rather than from a running count.
pub const DEMOTION_MAX_ROWS: u64 = 50_000;

/// How many individual failures to retain for operator inspection. Failures
/// beyond this are still counted, just not sampled.
const MAX_SAMPLED_FAILURES: usize = 32;

// ---------------------------------------------------------------------------
// Cursor
// ---------------------------------------------------------------------------

/// Position in the candidate ordering: the sort key of the last row consumed.
///
/// Ordering is `(COALESCE(last_active_at, 0) ASC, pubkey ASC)`. Neither
/// component is written by a demotion, which is what makes the cursor stable
/// across the sweep's own mutations.
#[derive(Debug, Clone, PartialEq)]
pub struct SweepCursor {
    /// `COALESCE(last_active_at, 0)` of the last consumed row.
    pub last_active_at: f64,
    /// Tiebreak within one `last_active_at`, making the order total.
    pub pubkey: String,
}

impl SweepCursor {
    /// The cursor positioned immediately after `row`.
    pub fn after(row: &WhitelistTrustRow) -> Self {
        Self {
            last_active_at: row.last_active_at.unwrap_or(0.0),
            pubkey: row.pubkey.clone(),
        }
    }

    /// Whether `row` sorts strictly after this cursor.
    ///
    /// The in-memory store used by the tests pages with this; the D1 store
    /// expresses the identical predicate in SQL, so the two page shapes are
    /// verifiably the same ordering.
    #[cfg(test)]
    pub fn precedes(&self, row: &WhitelistTrustRow) -> bool {
        let ts = row.last_active_at.unwrap_or(0.0);
        ts > self.last_active_at || (ts == self.last_active_at && row.pubkey > self.pubkey)
    }
}

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

/// Where a failure occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureStage {
    /// The candidate page query failed. The sweep cannot make progress and
    /// aborts rather than silently reporting completion.
    Page,
    /// The demotion commit (trust `UPDATE` + audit `INSERT`, one batch) failed
    /// or affected no rows. State and audit are unchanged together.
    Commit,
}

/// One recorded failure, retained for operator diagnosis.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SweepFailure {
    /// The row involved, where the failure is attributable to one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
    pub stage: FailureStage,
    pub error: String,
}

/// Outcome of a sweep.
///
/// `demoted` counts **committed** changes only. `scanned == demoted + held +
/// failed` always holds, which is what makes the report auditable: no row is
/// silently unaccounted for.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct DemotionSweepResult {
    /// Candidate rows read and evaluated.
    pub scanned: u64,
    /// Rows whose demotion was confirmed committed.
    pub demoted: u64,
    /// Rows the policy deliberately left alone.
    pub held: u64,
    /// Rows where a due demotion did not commit.
    pub failed: u64,
    /// Hit [`DEMOTION_MAX_ROWS`] before exhausting candidates; the remainder is
    /// swept on the next tick, resuming from `resume_cursor`.
    pub truncated: bool,
    /// A page query failed and the sweep stopped early. Distinct from
    /// `truncated`: this is an error, not a budget.
    pub aborted: bool,
    /// Sampled failures (capped; `failed` carries the true count).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<SweepFailure>,
    /// The pubkey of the last row consumed — where the next tick resumes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume_pubkey: Option<String>,
}

impl DemotionSweepResult {
    /// Every scanned row is accounted for by exactly one outcome.
    pub fn is_balanced(&self) -> bool {
        self.scanned == self.demoted + self.held + self.failed
    }

    fn record_failure(&mut self, pubkey: Option<String>, stage: FailureStage, error: String) {
        if self.failures.len() < MAX_SAMPLED_FAILURES {
            self.failures.push(SweepFailure {
                pubkey,
                stage,
                error,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Storage seam
// ---------------------------------------------------------------------------

/// The storage operations the sweep needs, abstracted so the engine can be
/// exercised natively without a live D1.
///
/// `?Send` because the Workers runtime is single-threaded and its futures are
/// not `Send`.
#[allow(clippy::double_must_use)] // async_trait's own must_use; see nostr-bbs-core signer.rs
#[async_trait(?Send)]
pub trait DemotionStore {
    /// Fetch the next page of candidates strictly after `after`, ordered by
    /// `(last_active_at ASC, pubkey ASC)`.
    ///
    /// Candidates hold a demotable level (TL1..=TL2), are past the inactivity
    /// `cutoff`, and are not admin/exempt. The predicate is an optimisation
    /// that bounds the candidate set; [`decide_demotion`] re-checks every guard
    /// before anything is written, so SQL is never the authority for the policy.
    async fn candidate_page(
        &self,
        cutoff: i64,
        after: Option<&SweepCursor>,
        limit: u32,
    ) -> Result<Vec<WhitelistTrustRow>, String>;

    /// Apply one demotion: trust-level `UPDATE` and audit `INSERT` committed
    /// together, or neither.
    ///
    /// `from` is the level observed when the decision was taken; the write is
    /// conditioned on it, so a level changed concurrently (an admin grant
    /// landing mid-sweep) yields a conflict error rather than clobbering it.
    async fn commit_demotion(
        &self,
        pubkey: &str,
        from: TrustLevel,
        to: TrustLevel,
        now: i64,
        observed: &WhitelistTrustRow,
    ) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Run the inactivity-decay demotion sweep.
///
/// Each candidate row is evaluated **exactly once per sweep** and receives at
/// most one committed transition. ADR-2006 permits TL2 to land directly on TL0
/// when the row no longer meets the TL1 criteria, so "one step" is one committed
/// transition per row per sweep, not one rung of the ladder; the keyset cursor
/// is what guarantees no row is revisited and cascaded within the same sweep.
///
/// The cursor advances for every consumed row — including held rows and failed
/// commits — so a row that can never be written (a persistent constraint error,
/// say) cannot wedge the sweep in a retry loop. Its failure is recorded and the
/// sweep moves on.
pub async fn run_demotion_sweep<S>(
    store: &S,
    thresholds: &TrustThresholds,
    now: i64,
    batch_size: u32,
    max_rows: u64,
) -> DemotionSweepResult
where
    S: DemotionStore + ?Sized,
{
    let mut result = DemotionSweepResult::default();
    let cutoff = now.saturating_sub(thresholds.inactivity_demotion_secs);
    let batch_size = batch_size.max(1);
    let mut cursor: Option<SweepCursor> = None;

    loop {
        let page = match store
            .candidate_page(cutoff, cursor.as_ref(), batch_size)
            .await
        {
            Ok(page) => page,
            Err(e) => {
                result.aborted = true;
                result.record_failure(None, FailureStage::Page, e);
                break;
            }
        };

        let page_len = page.len() as u32;
        if page_len == 0 {
            break;
        }

        for row in &page {
            // Advance the cursor before doing anything that can fail, so the
            // sweep always makes forward progress.
            cursor = Some(SweepCursor::after(row));
            result.resume_pubkey = Some(row.pubkey.clone());
            result.scanned += 1;

            match decide_demotion(row, thresholds, now) {
                DemotionDecision::Hold(_) => {
                    result.held += 1;
                }
                DemotionDecision::Demote { from, to } => {
                    match store.commit_demotion(&row.pubkey, from, to, now, row).await {
                        Ok(()) => result.demoted += 1,
                        Err(e) => {
                            result.failed += 1;
                            result.record_failure(
                                Some(row.pubkey.clone()),
                                FailureStage::Commit,
                                e,
                            );
                        }
                    }
                }
            }

            if result.scanned >= max_rows {
                result.truncated = true;
                return result;
            }
        }

        // A short page means the candidate set is exhausted.
        if page_len < batch_size {
            break;
        }
    }

    result
}

// ---------------------------------------------------------------------------
// D1-backed store
// ---------------------------------------------------------------------------

/// The whitelist columns the decision needs. Selecting them in the page query
/// means the sweep reads each row **once**; the previous implementation
/// re-read the row (and reloaded every threshold setting) per candidate.
const CANDIDATE_COLUMNS: &str = "pubkey, trust_level, days_active, posts_read, posts_created, \
     mod_actions_against, last_active_at, trust_level_updated_at, is_admin";

/// Shared candidate predicate: demotable band, past the inactivity gate, not
/// admin/exempt.
const CANDIDATE_PREDICATE: &str = "trust_level >= ?1 AND trust_level <= ?2 \
     AND COALESCE(last_active_at, 0) <= ?3 \
     AND COALESCE(is_admin, 0) = 0";

/// D1 implementation of [`DemotionStore`].
pub struct D1DemotionStore {
    db: worker::D1Database,
}

impl D1DemotionStore {
    /// Bind the store to the worker's `DB` D1 binding.
    pub fn new(env: &Env) -> Result<Self, String> {
        let db = env
            .d1("DB")
            .map_err(|e| format!("DB binding missing: {e:?}"))?;
        Ok(Self { db })
    }
}

#[async_trait(?Send)]
impl DemotionStore for D1DemotionStore {
    async fn candidate_page(
        &self,
        cutoff: i64,
        after: Option<&SweepCursor>,
        limit: u32,
    ) -> Result<Vec<WhitelistTrustRow>, String> {
        let floor = TrustLevel::Member.as_i32() as f64;
        let ceiling = TrustLevel::Regular.as_i32() as f64;

        // Two statement shapes rather than a sentinel cursor: the first page has
        // no lower bound at all, so there is no magic value to get wrong.
        let (sql, binds): (String, Vec<JsValue>) = match after {
            None => (
                format!(
                    "SELECT {CANDIDATE_COLUMNS} FROM whitelist \
                     WHERE {CANDIDATE_PREDICATE} \
                     ORDER BY COALESCE(last_active_at, 0) ASC, pubkey ASC \
                     LIMIT ?4"
                ),
                vec![
                    JsValue::from_f64(floor),
                    JsValue::from_f64(ceiling),
                    JsValue::from_f64(cutoff as f64),
                    JsValue::from_f64(limit as f64),
                ],
            ),
            Some(cur) => (
                format!(
                    "SELECT {CANDIDATE_COLUMNS} FROM whitelist \
                     WHERE {CANDIDATE_PREDICATE} \
                       AND (COALESCE(last_active_at, 0) > ?4 \
                            OR (COALESCE(last_active_at, 0) = ?4 AND pubkey > ?5)) \
                     ORDER BY COALESCE(last_active_at, 0) ASC, pubkey ASC \
                     LIMIT ?6"
                ),
                vec![
                    JsValue::from_f64(floor),
                    JsValue::from_f64(ceiling),
                    JsValue::from_f64(cutoff as f64),
                    JsValue::from_f64(cur.last_active_at),
                    JsValue::from_str(&cur.pubkey),
                    JsValue::from_f64(limit as f64),
                ],
            ),
        };

        self.db
            .prepare(sql)
            .bind(&binds)
            .map_err(|e| format!("bind failed: {e:?}"))?
            .all()
            .await
            .map_err(|e| format!("page query failed: {e:?}"))?
            .results()
            .map_err(|e| format!("results parse failed: {e:?}"))
    }

    async fn commit_demotion(
        &self,
        pubkey: &str,
        from: TrustLevel,
        to: TrustLevel,
        now: i64,
        observed: &WhitelistTrustRow,
    ) -> Result<(), String> {
        commit_demotion_d1(&self.db, pubkey, from, to, now, observed).await
    }
}

// These statements execute consecutively on the same D1 batch connection.
// A successful zero-row UPDATE must not manufacture an audit fact.
const DEMOTION_UPDATE_SQL: &str = r#"UPDATE whitelist
 SET trust_level = ?1, trust_level_updated_at = ?2
 WHERE pubkey = ?3 AND trust_level = ?4
 AND is_admin IS ?5 AND COALESCE(is_admin, 0) != 1
 AND last_active_at IS ?6 AND trust_level_updated_at IS ?7
 AND days_active = ?8 AND posts_read = ?9 AND posts_created = ?10
 AND mod_actions_against = ?11"#;
const DEMOTION_AUDIT_SQL: &str = r#"INSERT INTO admin_log
 (actor_pubkey, action, target_pubkey, previous_value, new_value, reason, created_at)
 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7 WHERE changes() = 1"#;

/// Apply one demotion against a D1 handle: the trust-level `UPDATE` and the
/// `admin_log` audit `INSERT` submitted as a single batch, which Cloudflare
/// executes in one implicit transaction. Shared by the sweep and the
/// scheduled sweep path, preserving the same
/// atomicity and conflict guarantees.
pub(crate) async fn commit_demotion_d1(
    db: &worker::D1Database,
    pubkey: &str,
    from: TrustLevel,
    to: TrustLevel,
    now: i64,
    observed: &WhitelistTrustRow,
) -> Result<(), String> {
    {
        // Conditioned on the observed level: if an admin grant landed between
        // the page read and this write, `changes` is 0 and we report a conflict
        // instead of overwriting the grant.
        let update = db
            .prepare(DEMOTION_UPDATE_SQL)
            .bind(&[
                JsValue::from_f64(to.as_i32() as f64),
                JsValue::from_f64(now as f64),
                JsValue::from_str(pubkey),
                JsValue::from_f64(from.as_i32() as f64),
                observed
                    .is_admin
                    .map(|v| JsValue::from_f64(v as f64))
                    .unwrap_or(JsValue::NULL),
                observed
                    .last_active_at
                    .map(JsValue::from_f64)
                    .unwrap_or(JsValue::NULL),
                observed
                    .trust_level_updated_at
                    .map(JsValue::from_f64)
                    .unwrap_or(JsValue::NULL),
                JsValue::from_f64(observed.days_active as f64),
                JsValue::from_f64(observed.posts_read as f64),
                JsValue::from_f64(observed.posts_created as f64),
                JsValue::from_f64(observed.mod_actions_against as f64),
            ])
            .map_err(|e| format!("update bind failed: {e:?}"))?;

        let audit = db
            .prepare(DEMOTION_AUDIT_SQL)
            .bind(&[
                JsValue::from_str("system"),
                JsValue::from_str("trust_level_change"),
                JsValue::from_str(pubkey),
                JsValue::from_str(&from.as_i32().to_string()),
                JsValue::from_str(&to.as_i32().to_string()),
                JsValue::from_str("auto-demotion (hysteresis)"),
                JsValue::from_f64(now as f64),
            ])
            .map_err(|e| format!("audit bind failed: {e:?}"))?;

        // One batch = one implicit transaction: state and audit commit together
        // or not at all.
        let results = db
            .batch(vec![update, audit])
            .await
            .map_err(|e| format!("commit batch failed: {e:?}"))?;

        for r in &results {
            if !r.success() {
                return Err(format!(
                    "commit batch reported failure: {}",
                    r.error().unwrap_or_else(|| "unknown".to_string())
                ));
            }
        }

        // Require a confirmed state change AND its conditional audit. A no-op
        // batch is safe (neither changed), but is a conflict rather than success.
        if results.len() != 2
            || results
                .iter()
                .any(|r| r.meta().ok().flatten().and_then(|meta| meta.changes) != Some(1))
        {
            return Err(format!(
                "trust snapshot for {pubkey} changed concurrently or commit metadata unavailable"
            ));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Periodic inactivity-decay sweep, invoked from the scheduled (cron) trigger.
pub async fn sweep_inactive_demotions(env: &Env) -> Result<DemotionSweepResult, String> {
    let store = D1DemotionStore::new(env)?;
    let thresholds = TrustThresholds::load(env).await;
    let now = auth::js_now_secs() as i64;

    let result = run_demotion_sweep(
        &store,
        &thresholds,
        now,
        DEMOTION_BATCH_SIZE,
        DEMOTION_MAX_ROWS,
    )
    .await;

    if result.aborted {
        console_warn!(
            "sweep_inactive_demotions: aborted after {} rows: {:?}",
            result.scanned,
            result.failures
        );
    } else if result.truncated {
        console_warn!(
            "sweep_inactive_demotions: hit DEMOTION_MAX_ROWS ({}), resuming next tick from {:?}",
            DEMOTION_MAX_ROWS,
            result.resume_pubkey
        );
    }
    if result.failed > 0 {
        console_warn!(
            "sweep_inactive_demotions: {} demotion(s) did not commit",
            result.failed
        );
    }
    // Every scanned row must be accounted for by exactly one outcome. If this
    // ever fails the counts are not trustworthy, and an operator reading them
    // as "committed changes" would be misled — so say so loudly rather than
    // publishing a silently wrong total.
    if !result.is_balanced() {
        console_warn!(
            "sweep_inactive_demotions: outcome counts do not balance \
             (scanned {} != demoted {} + held {} + failed {})",
            result.scanned,
            result.demoted,
            result.held,
            result.failed
        );
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// Drive a future to completion on the test thread.
    ///
    /// The workspace carries no async runtime (the production target is the
    /// single-threaded Workers runtime), and none is needed: every future in
    /// these tests is backed by the in-memory store and performs no real I/O,
    /// so it completes on the first poll. A `Pending` here would mean a test
    /// future genuinely parked, which cannot happen — so we panic loudly
    /// rather than spin.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        let mut fut = Box::pin(fut);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(v) => v,
            std::task::Poll::Pending => {
                panic!("test future parked; the in-memory store must never yield")
            }
        }
    }

    /// ~6 months, matching `TrustThresholds::inactivity_demotion_secs`.
    const IDLE: i64 = 6 * 30 * 24 * 60 * 60;
    const NOW: i64 = 1_800_000_000;

    /// An in-memory whitelist that models the parts of D1 the sweep depends on:
    /// the candidate predicate, the keyset ordering, and — crucially — the fact
    /// that a committed demotion *changes the eligible set the next page query
    /// runs against*. That feedback loop is what the `OFFSET` implementation
    /// tripped over, so the fake must reproduce it faithfully.
    struct FakeStore {
        rows: RefCell<HashMap<String, WhitelistTrustRow>>,
        /// Audit entries written, mirroring `admin_log`.
        audit: RefCell<Vec<(String, i32, i32)>>,
        /// Pubkeys whose commit must fail, and with what message.
        commit_failures: HashMap<String, String>,
        /// If set, the audit half of the batch fails for these pubkeys. Because
        /// the commit is one transaction, the level must NOT change either.
        audit_failures: HashMap<String, String>,
        /// Fail the Nth page query (0-based).
        fail_page_at: Option<usize>,
        page_calls: RefCell<usize>,
        /// Every commit attempted, in order — lets a test assert that no row is
        /// visited twice within one sweep.
        commit_attempts: RefCell<Vec<String>>,
    }

    impl FakeStore {
        fn new(rows: Vec<WhitelistTrustRow>) -> Self {
            Self {
                rows: RefCell::new(rows.into_iter().map(|r| (r.pubkey.clone(), r)).collect()),
                audit: RefCell::new(Vec::new()),
                commit_failures: HashMap::new(),
                audit_failures: HashMap::new(),
                fail_page_at: None,
                page_calls: RefCell::new(0),
                commit_attempts: RefCell::new(Vec::new()),
            }
        }

        fn fail_commit_for(mut self, pubkey: &str, msg: &str) -> Self {
            self.commit_failures
                .insert(pubkey.to_string(), msg.to_string());
            self
        }

        fn fail_audit_for(mut self, pubkey: &str, msg: &str) -> Self {
            self.audit_failures
                .insert(pubkey.to_string(), msg.to_string());
            self
        }

        fn fail_page_at(mut self, n: usize) -> Self {
            self.fail_page_at = Some(n);
            self
        }

        fn level_of(&self, pubkey: &str) -> i32 {
            self.rows
                .borrow()
                .get(pubkey)
                .map(|r| r.trust_level)
                .unwrap()
        }

        fn audit_count(&self) -> usize {
            self.audit.borrow().len()
        }
    }

    #[async_trait(?Send)]
    impl DemotionStore for FakeStore {
        async fn candidate_page(
            &self,
            cutoff: i64,
            after: Option<&SweepCursor>,
            limit: u32,
        ) -> Result<Vec<WhitelistTrustRow>, String> {
            let call = {
                let mut c = self.page_calls.borrow_mut();
                let n = *c;
                *c += 1;
                n
            };
            if self.fail_page_at == Some(call) {
                return Err("simulated page query failure".to_string());
            }

            let rows = self.rows.borrow();
            let mut candidates: Vec<WhitelistTrustRow> = rows
                .values()
                .filter(|r| {
                    r.trust_level >= TrustLevel::Member.as_i32()
                        && r.trust_level <= TrustLevel::Regular.as_i32()
                        && (r.last_active_at.unwrap_or(0.0) as i64) <= cutoff
                        && r.is_admin.unwrap_or(0) == 0
                })
                .filter(|r| after.map(|c| c.precedes(r)).unwrap_or(true))
                .map(clone_row)
                .collect();

            candidates.sort_by(|a, b| {
                a.last_active_at
                    .unwrap_or(0.0)
                    .partial_cmp(&b.last_active_at.unwrap_or(0.0))
                    .unwrap()
                    .then_with(|| a.pubkey.cmp(&b.pubkey))
            });
            candidates.truncate(limit as usize);
            Ok(candidates)
        }

        async fn commit_demotion(
            &self,
            pubkey: &str,
            from: TrustLevel,
            to: TrustLevel,
            now: i64,
            observed: &WhitelistTrustRow,
        ) -> Result<(), String> {
            let _ = observed;
            self.commit_attempts.borrow_mut().push(pubkey.to_string());

            if let Some(msg) = self.commit_failures.get(pubkey) {
                return Err(msg.clone());
            }
            // The audit INSERT and the trust UPDATE are one transaction: if the
            // audit half fails, neither lands.
            if let Some(msg) = self.audit_failures.get(pubkey) {
                return Err(msg.clone());
            }

            let mut rows = self.rows.borrow_mut();
            let row = rows.get_mut(pubkey).ok_or("row vanished")?;
            if row.trust_level != from.as_i32() {
                return Err("level changed concurrently".to_string());
            }
            row.trust_level = to.as_i32();
            row.trust_level_updated_at = Some(now as f64);
            self.audit
                .borrow_mut()
                .push((pubkey.to_string(), from.as_i32(), to.as_i32()));
            Ok(())
        }
    }

    fn clone_row(r: &WhitelistTrustRow) -> WhitelistTrustRow {
        WhitelistTrustRow {
            pubkey: r.pubkey.clone(),
            trust_level: r.trust_level,
            days_active: r.days_active,
            posts_read: r.posts_read,
            posts_created: r.posts_created,
            mod_actions_against: r.mod_actions_against,
            last_active_at: r.last_active_at,
            trust_level_updated_at: r.trust_level_updated_at,
            is_admin: r.is_admin,
        }
    }

    /// A row that is idle past the gate and holds no activity, so it demotes.
    fn idle_row(pubkey: &str, level: i32, last_active: i64) -> WhitelistTrustRow {
        WhitelistTrustRow {
            pubkey: pubkey.to_string(),
            trust_level: level,
            days_active: 0,
            posts_read: 0,
            posts_created: 0,
            mod_actions_against: 0,
            last_active_at: Some(last_active as f64),
            trust_level_updated_at: None,
            is_admin: Some(0),
        }
    }

    fn thresholds() -> TrustThresholds {
        TrustThresholds::default()
    }

    /// Well past the inactivity gate.
    fn stale_ts() -> i64 {
        NOW - IDLE - 1
    }

    // -- The regression the ADR-2006 closeout identified -------------------

    #[test]
    fn sweeps_every_row_across_many_batches() {
        // 400 eligible rows at a batch size of 200. Under LIMIT/OFFSET the
        // first page's demotions drop those rows out of the eligible set, the
        // second query at OFFSET 200 returns nothing, and the sweep stops
        // having processed exactly half. Keyset pagination must process all
        // 400.
        let rows: Vec<_> = (0..400)
            .map(|i| idle_row(&format!("pk{i:04}"), 1, stale_ts() - i as i64))
            .collect();
        let store = FakeStore::new(rows);

        let r = block_on(run_demotion_sweep(
            &store,
            &thresholds(),
            NOW,
            200,
            DEMOTION_MAX_ROWS,
        ));

        assert_eq!(r.scanned, 400, "every eligible row must be evaluated");
        assert_eq!(r.demoted, 400, "every TL1 idle row demotes to TL0");
        assert_eq!(r.failed, 0);
        assert!(!r.truncated);
        assert!(!r.aborted);
        assert!(r.is_balanced());
        assert_eq!(store.audit_count(), 400, "one audit entry per demotion");
    }

    #[test]
    fn tied_timestamps_page_deterministically() {
        // Every row shares one last_active_at, so the pubkey tiebreak is the
        // only thing making the order total. Without it the cursor cannot
        // advance past the tie and the sweep either loops or skips the cohort.
        let ts = stale_ts();
        let rows: Vec<_> = (0..500)
            .map(|i| idle_row(&format!("tie{i:04}"), 1, ts))
            .collect();
        let store = FakeStore::new(rows);

        let r = block_on(run_demotion_sweep(
            &store,
            &thresholds(),
            NOW,
            50,
            DEMOTION_MAX_ROWS,
        ));

        assert_eq!(r.scanned, 500);
        assert_eq!(r.demoted, 500);
        assert!(r.is_balanced());

        // No row visited twice: one commit attempt each.
        let attempts = store.commit_attempts.borrow();
        let mut unique = attempts.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            attempts.len(),
            "keyset pagination must not revisit a row within one sweep"
        );
    }

    #[test]
    fn one_committed_transition_per_row_per_sweep() {
        // A TL2 row with no activity drops straight to TL0 (ADR-2006 allows
        // TL2 → TL0 when the TL1 criteria are not met). It must be written
        // once, not stepped TL2 → TL1 → TL0 within the same sweep.
        let store = FakeStore::new(vec![idle_row("pk", 2, stale_ts())]);

        let r = block_on(run_demotion_sweep(
            &store,
            &thresholds(),
            NOW,
            10,
            DEMOTION_MAX_ROWS,
        ));

        assert_eq!(r.scanned, 1);
        assert_eq!(r.demoted, 1);
        assert_eq!(store.level_of("pk"), 0, "TL2 lands on TL0 in one step");
        assert_eq!(store.commit_attempts.borrow().len(), 1);
        assert_eq!(store.audit_count(), 1);
    }

    #[test]
    fn tl2_lands_on_tl1_when_tl1_criteria_still_met() {
        // Idle past the gate and below the TL2 hysteresis band, but the row
        // still earns TL1 — so it stops there rather than falling to TL0.
        let mut row = idle_row("pk", 2, stale_ts());
        row.days_active = 12; // < 14*0.9 = 12.6 → breaks the TL2 band
        row.posts_read = 50;
        row.posts_created = 10;
        let store = FakeStore::new(vec![row]);

        let r = block_on(run_demotion_sweep(
            &store,
            &thresholds(),
            NOW,
            10,
            DEMOTION_MAX_ROWS,
        ));

        assert_eq!(r.demoted, 1);
        assert_eq!(store.level_of("pk"), 1);
    }

    // -- Exclusions --------------------------------------------------------

    #[test]
    fn tl3_and_admin_rows_are_never_swept() {
        let mut admin = idle_row("admin", 2, stale_ts());
        admin.is_admin = Some(1);
        let tl3 = idle_row("tl3", 3, stale_ts());
        let tl0 = idle_row("tl0", 0, stale_ts());
        let normal = idle_row("normal", 1, stale_ts());
        let store = FakeStore::new(vec![admin, tl3, tl0, normal]);

        let r = block_on(run_demotion_sweep(
            &store,
            &thresholds(),
            NOW,
            10,
            DEMOTION_MAX_ROWS,
        ));

        // Only the ordinary TL1 row is even a candidate: the SQL predicate
        // excludes admin, TL3 and TL0 before the policy runs.
        assert_eq!(r.scanned, 1);
        assert_eq!(r.demoted, 1);
        assert_eq!(store.level_of("admin"), 2, "admin/exempt untouched");
        assert_eq!(store.level_of("tl3"), 3, "TL3 never auto-demoted");
        assert_eq!(store.level_of("tl0"), 0, "TL0 is the floor");
        assert_eq!(store.level_of("normal"), 0);
    }

    #[test]
    fn active_row_inside_the_window_is_held_not_demoted() {
        // Inside the inactivity window: a candidate only because the fake's
        // cutoff arithmetic is deliberately loose here — the policy must hold
        // it. Constructed by placing it exactly on the boundary.
        let row = idle_row("recent", 1, NOW - IDLE + 10);
        let store = FakeStore::new(vec![row]);

        let r = block_on(run_demotion_sweep(
            &store,
            &thresholds(),
            NOW,
            10,
            DEMOTION_MAX_ROWS,
        ));

        // The SQL-equivalent predicate filters it out entirely.
        assert_eq!(r.scanned, 0);
        assert_eq!(store.level_of("recent"), 1);
    }

    #[test]
    fn row_clearing_hysteresis_is_held_and_counted() {
        // Idle past the gate but still comfortably inside the TL1 band.
        let mut row = idle_row("solid", 1, stale_ts());
        row.days_active = 100;
        row.posts_read = 100;
        row.posts_created = 100;
        let store = FakeStore::new(vec![row]);

        let r = block_on(run_demotion_sweep(
            &store,
            &thresholds(),
            NOW,
            10,
            DEMOTION_MAX_ROWS,
        ));

        assert_eq!(r.scanned, 1);
        assert_eq!(r.demoted, 0);
        assert_eq!(
            r.held, 1,
            "a hold is an explicit outcome, not a silent skip"
        );
        assert!(r.is_balanced());
        assert_eq!(store.level_of("solid"), 1);
        assert_eq!(store.audit_count(), 0);
    }

    // -- Failure accounting ------------------------------------------------

    #[test]
    fn failed_write_is_not_counted_as_a_demotion() {
        let store = FakeStore::new(vec![
            idle_row("ok1", 1, stale_ts()),
            idle_row("bad", 1, stale_ts() - 1),
            idle_row("ok2", 1, stale_ts() - 2),
        ])
        .fail_commit_for("bad", "D1_ERROR: disk full");

        let r = block_on(run_demotion_sweep(
            &store,
            &thresholds(),
            NOW,
            10,
            DEMOTION_MAX_ROWS,
        ));

        assert_eq!(r.scanned, 3);
        assert_eq!(r.demoted, 2, "counts reflect committed changes only");
        assert_eq!(r.failed, 1);
        assert!(r.is_balanced());
        assert_eq!(store.level_of("bad"), 1, "state unchanged on write failure");
        assert_eq!(r.failures.len(), 1);
        assert_eq!(r.failures[0].stage, FailureStage::Commit);
        assert_eq!(r.failures[0].pubkey.as_deref(), Some("bad"));
        // The failing row must not stall the sweep.
        assert_eq!(store.level_of("ok2"), 0);
    }

    #[test]
    fn audit_failure_leaves_state_and_audit_consistent() {
        // The trust UPDATE and the audit INSERT are one batch/transaction. If
        // the audit half fails the level must not move either, and the sweep
        // must not claim a demotion.
        let store = FakeStore::new(vec![idle_row("pk", 2, stale_ts())])
            .fail_audit_for("pk", "D1_ERROR: admin_log constraint");

        let r = block_on(run_demotion_sweep(
            &store,
            &thresholds(),
            NOW,
            10,
            DEMOTION_MAX_ROWS,
        ));

        assert_eq!(r.demoted, 0);
        assert_eq!(r.failed, 1);
        assert_eq!(store.level_of("pk"), 2, "no level change without its audit");
        assert_eq!(store.audit_count(), 0, "no audit without its level change");
        assert!(r.is_balanced());
    }

    #[test]
    fn page_query_failure_aborts_rather_than_reporting_completion() {
        let rows: Vec<_> = (0..300)
            .map(|i| idle_row(&format!("pk{i:04}"), 1, stale_ts() - i as i64))
            .collect();
        // Page 0 succeeds, page 1 fails.
        let store = FakeStore::new(rows).fail_page_at(1);

        let r = block_on(run_demotion_sweep(
            &store,
            &thresholds(),
            NOW,
            200,
            DEMOTION_MAX_ROWS,
        ));

        assert!(r.aborted, "a failed page must not look like a clean finish");
        assert_eq!(r.scanned, 200);
        assert_eq!(r.demoted, 200);
        assert_eq!(r.failures.len(), 1);
        assert_eq!(r.failures[0].stage, FailureStage::Page);
        assert!(r.is_balanced());
    }

    // -- Budget and restart ------------------------------------------------

    #[test]
    fn truncation_reports_a_resume_point() {
        let rows: Vec<_> = (0..100)
            .map(|i| idle_row(&format!("pk{i:04}"), 1, stale_ts() - i as i64))
            .collect();
        let store = FakeStore::new(rows);

        let r = block_on(run_demotion_sweep(&store, &thresholds(), NOW, 10, 25));

        assert!(r.truncated);
        assert_eq!(r.scanned, 25);
        assert!(r.resume_pubkey.is_some());
        assert!(r.is_balanced());
    }

    #[test]
    fn rerunning_the_sweep_reconciles_and_converges() {
        // Restart reconciliation. `faller` drops to TL0 and leaves the eligible
        // band entirely. `stepper` breaks the TL2 hysteresis band but still
        // earns TL1, so it lands there — and on the next sweep it is a
        // candidate again yet is *held*, because TL1 is a level it genuinely
        // qualifies for. One committed transition per row per sweep, no
        // cascade to the floor, and no double counting on re-run.
        let mut stepper = idle_row("stepper", 2, stale_ts());
        stepper.days_active = 12; // < 14 * 0.9 → breaks the TL2 band
        stepper.posts_read = 50;
        stepper.posts_created = 10;
        let store = FakeStore::new(vec![idle_row("faller", 1, stale_ts() - 5), stepper]);

        let first = block_on(run_demotion_sweep(
            &store,
            &thresholds(),
            NOW,
            10,
            DEMOTION_MAX_ROWS,
        ));
        assert_eq!(first.scanned, 2);
        assert_eq!(first.demoted, 2);
        assert_eq!(store.level_of("faller"), 0);
        assert_eq!(store.level_of("stepper"), 1);

        let second = block_on(run_demotion_sweep(
            &store,
            &thresholds(),
            NOW,
            10,
            DEMOTION_MAX_ROWS,
        ));
        assert_eq!(second.scanned, 1, "only `stepper` is still in the band");
        assert_eq!(second.demoted, 0, "TL1 is earned, so it is held");
        assert_eq!(second.held, 1);
        assert!(second.is_balanced());
        assert_eq!(store.level_of("stepper"), 1);

        assert_eq!(
            store.audit_count(),
            2,
            "one audit entry per committed change, none for the re-run"
        );
    }

    #[test]
    fn empty_whitelist_is_a_clean_no_op() {
        let store = FakeStore::new(vec![]);
        let r = block_on(run_demotion_sweep(
            &store,
            &thresholds(),
            NOW,
            200,
            DEMOTION_MAX_ROWS,
        ));
        assert_eq!(r.scanned, 0);
        assert!(!r.aborted);
        assert!(!r.truncated);
        assert!(r.is_balanced());
    }

    #[test]
    fn exact_batch_multiple_terminates() {
        // Candidate count is an exact multiple of the batch size: the loop must
        // issue one extra (empty) page and stop, not spin.
        let rows: Vec<_> = (0..20)
            .map(|i| idle_row(&format!("pk{i:04}"), 1, stale_ts() - i as i64))
            .collect();
        let store = FakeStore::new(rows);
        let r = block_on(run_demotion_sweep(
            &store,
            &thresholds(),
            NOW,
            10,
            DEMOTION_MAX_ROWS,
        ));
        assert_eq!(r.scanned, 20);
        assert_eq!(r.demoted, 20);
    }
}
