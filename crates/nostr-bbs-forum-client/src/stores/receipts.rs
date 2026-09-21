//! Governance receipt store — the client half of the FR4.1 receipt ladder.
//!
//! ADR-2010 established that a relay `OK` certifies storage and nothing more.
//! FR4.1 extends the ladder past projection into **application**: only the
//! system that performed the approved act can say whether it happened, and it
//! says so by advancing `governance_receipts` through the auth worker's
//! `POST /api/governance/receipts/{id}/application`. This store reads the other
//! end of that — `GET /api/governance/receipts` on the relay worker — so the
//! human who approved something learns whether it took effect.
//!
//! Two deliberate limits, stated rather than papered over:
//!
//! 1. The read is **NIP-98 admin** (the relay scopes cross-case receipt reads to
//!    its existing administrative authority). A member or a delegated reviewer
//!    therefore sees the decision chain without stages. The ageing badge they
//!    do get is the client's own clock reading
//!    ([`crate::utils::governance_view::is_overdue`]), labelled as such.
//! 2. Receipts are fetched per case on demand, not subscribed. A stage that
//!    advances after the fetch shows on the next load of the surface.
//!
//! The parsing and reduction below are pure and unit-tested; only
//! `ReceiptStore::load_case` touches the network (WASM-only, so it does not
//! appear in host-target rustdoc).

use std::collections::HashMap;

use leptos::prelude::*;
use nostr_bbs_core::governance::ReceiptStage;

/// One `governance_receipts` row, reduced to what the decision chain renders.
// Unwired: the pure, unit-tested half of a governance surface that is not yet
// rendered. Kept because the tests assert a documented invariant; the `allow`
// is scoped to the item so new dead code in this module is still reported.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptView {
    /// The 31403 event this receipt tracks.
    pub event_id: String,
    pub case_id: String,
    pub stage: ReceiptStage,
    /// Set when projection failed; the human is told why, not just that.
    pub stage_error: Option<String>,
    /// Who claimed an application stage (the mutation owner, or the operator
    /// who executed it by hand).
    pub applied_by: Option<String>,
    /// The mutation owner's own words about what it did.
    pub acknowledgement: Option<String>,
    pub applied_at: Option<u64>,
}

/// What one decision's receipts amount to, for display.
///
/// The split exists because the stage ladder has two halves with different
/// algebra. The rungs up to `consumer-received` are genuinely **ordered** —
/// each implies the ones before it, so "furthest wins" is correct and reading
/// them through `Ord` is right. The application outcomes are a **set of
/// mutually exclusive claims**, where "largest wins" is meaningless: two of
/// them is not progress, it is a contradiction, and resolving it by picking one
/// invents an answer the receipts do not contain.
// Unwired: the pure, unit-tested half of a governance surface that is not yet
// rendered. Kept because the tests assert a documented invariant; the `allow`
// is scoped to the item so new dead code in this module is still reported.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageView {
    /// The furthest ladder rung reached; no application outcome reported yet.
    Ladder(ReceiptStage),
    /// Exactly one application outcome. The loop FR4.1 exists to close.
    Terminal(ReceiptStage),
    /// Two or more DIFFERENT application outcomes for one decision, held as
    /// what they are. Never resolved by choosing one: only the mutation owner
    /// knows which is true, and a client that guessed would be fabricating the
    /// very thing this whole context forbids.
    Conflicting(Vec<ReceiptStage>),
}

impl StageView {
    /// The human-facing label.
    pub fn label(&self) -> String {
        match self {
            StageView::Ladder(s) | StageView::Terminal(s) => stage_label(*s).to_string(),
            StageView::Conflicting(stages) => {
                let names: Vec<&str> = stages.iter().map(|s| stage_label(*s)).collect();
                format!("conflicting receipts: {}", names.join(" and "))
            }
        }
    }

    /// Badge classes. A conflict reads as a failure, because it is one: nobody
    /// can say whether the approved act happened, which is exactly the state an
    /// operator must act on.
    pub fn class(&self) -> &'static str {
        match self {
            StageView::Ladder(s) | StageView::Terminal(s) => stage_class(*s),
            StageView::Conflicting(_) => "bg-red-500/10 text-red-400 border-red-500/30",
        }
    }
}

/// One decision's reduced receipt: the stage view plus the row that carried the
/// most informative claim (the terminal outcome where there is one, else the
/// furthest rung).
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionReceipt {
    pub stage: StageView,
    /// Who claimed an application stage.
    pub applied_by: Option<String>,
    /// The mutation owner's own words about what it did.
    pub acknowledgement: Option<String>,
    /// Set when projection failed; the human is told why, not just that.
    pub stage_error: Option<String>,
}

/// What a case's receipts say, reduced for display.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CaseReceipts {
    /// Per 31403 event id. Side receipts never appear here (DDD §6
    /// invariant 5).
    pub by_decision: HashMap<String, DecisionReceipt>,
    /// The case exceeded its panel's `max_pending_hours` (FR4.3). This is the
    /// authoritative statement, as against the client's own clock reading.
    pub escalated_on_age: bool,
    /// The case passed its open-case TTL without a decision.
    pub expired: bool,
}

/// Parse `GET /api/governance/receipts` into rows, ignoring anything malformed
/// rather than failing the whole read: a receipt trail with one unreadable row
/// is still worth showing.
// Unwired: the pure, unit-tested half of a governance surface that is not yet
// rendered. Kept because the tests assert a documented invariant; the `allow`
// is scoped to the item so new dead code in this module is still reported.
#[allow(dead_code)]
pub fn parse_receipts(body: &str) -> Vec<ReceiptView> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let Some(rows) = v.get("receipts").and_then(|r| r.as_array()) else {
        return Vec::new();
    };
    rows.iter()
        .filter_map(|r| {
            let stage = ReceiptStage::parse(r.get("stage")?.as_str()?)?;
            Some(ReceiptView {
                event_id: r.get("eventId")?.as_str()?.to_string(),
                case_id: r
                    .get("caseId")
                    .and_then(|c| c.as_str())
                    .unwrap_or_default()
                    .to_string(),
                stage,
                stage_error: r
                    .get("stageError")
                    .and_then(|e| e.as_str())
                    .map(str::to_string),
                applied_by: r
                    .get("appliedBy")
                    .and_then(|e| e.as_str())
                    .map(str::to_string),
                acknowledgement: r
                    .get("acknowledgement")
                    .and_then(|e| e.as_str())
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
                applied_at: r.get("appliedAt").and_then(|e| e.as_u64()),
            })
        })
        .collect()
}

/// Reduce a case's receipt rows for display.
///
/// Three rules, each for its own reason:
///
/// 1. **Side receipts set flags, never stages.** DDD §6 invariant 5:
///    `escalated-on-age` and `expired` record something that happened *to* a
///    case without advancing it toward application.
/// 2. **Ladder rungs reduce by `Ord`.** `signed → relay-accepted →
///    projection-committed → consumer-received` each imply the ones before, so
///    the furthest is the whole truth and rows may arrive in any order.
/// 3. **Application outcomes reduce as a SET.** `applied`, `not-applied` and
///    `applied-manually` are mutually exclusive claims about the world. One of
///    them is the answer and outranks every rung; two *different* ones are a
///    contradiction, held as [`StageView::Conflicting`] rather than resolved.
///    Only the mutation owner knows which is true, and a client that picked the
///    larger under a derived `Ord` would be displaying a successful application
///    as a failure — which is precisely the counter-example FR4.1 names, in the
///    opposite direction.
///
/// Known limit, stated: `projection-failed` is treated as a ladder rung, so a
/// failure followed by a successful reconciliation retry still shows the
/// failure (it outranks `projection-committed`). These rows carry no ordering
/// this reducer reads, and showing a stale failure is the safe direction —
/// an operator looks again, rather than being told all is well.
// Unwired: the pure, unit-tested half of a governance surface that is not yet
// rendered. Kept because the tests assert a documented invariant; the `allow`
// is scoped to the item so new dead code in this module is still reported.
#[allow(dead_code)]
pub fn reduce_case(rows: Vec<ReceiptView>) -> CaseReceipts {
    let mut out = CaseReceipts::default();
    // Per decision: the furthest ladder rung, the DISTINCT terminal outcomes in
    // arrival order, and the row worth quoting.
    let mut ladder: HashMap<String, ReceiptStage> = HashMap::new();
    let mut terminals: HashMap<String, Vec<ReceiptStage>> = HashMap::new();
    let mut detail: HashMap<String, ReceiptView> = HashMap::new();

    for row in rows {
        if row.stage == ReceiptStage::EscalatedOnAge {
            out.escalated_on_age = true;
            continue;
        }
        if row.stage == ReceiptStage::Expired {
            out.expired = true;
            continue;
        }

        if row.stage.is_terminal_application() {
            let seen = terminals.entry(row.event_id.clone()).or_default();
            // A repeated claim — a replayed post — is one claim, not a conflict.
            if !seen.contains(&row.stage) {
                seen.push(row.stage);
            }
            // A terminal row always carries the most informative detail.
            detail.insert(row.event_id.clone(), row);
            continue;
        }

        let rung = ladder.entry(row.event_id.clone()).or_insert(row.stage);
        if row.stage > *rung {
            *rung = row.stage;
        }
        // Keep a ladder row's detail only while no terminal row has spoken.
        if !terminals.contains_key(&row.event_id) {
            match detail.get(&row.event_id) {
                Some(existing) if existing.stage >= row.stage => {}
                _ => {
                    detail.insert(row.event_id.clone(), row);
                }
            }
        }
    }

    let ids: std::collections::BTreeSet<String> =
        ladder.keys().chain(terminals.keys()).cloned().collect();
    for id in ids {
        let stage = match terminals.get(&id).map(Vec::as_slice) {
            Some([]) | None => match ladder.get(&id) {
                Some(rung) => StageView::Ladder(*rung),
                // Unreachable in practice: an id is here because it appeared in
                // one map or the other.
                None => continue,
            },
            Some([one]) => StageView::Terminal(*one),
            Some(many) => StageView::Conflicting(many.to_vec()),
        };
        let row = detail.get(&id);
        out.by_decision.insert(
            id,
            DecisionReceipt {
                stage,
                applied_by: row.and_then(|r| r.applied_by.clone()),
                acknowledgement: row.and_then(|r| r.acknowledgement.clone()),
                stage_error: row.and_then(|r| r.stage_error.clone()),
            },
        );
    }
    out
}

/// The human-facing label for a stage, and what it does and does not certify.
///
/// Every string here is a statement about the world the relay or the mutation
/// owner actually made. "Approved" is never one of them — that is the decision,
/// not its fate.
pub fn stage_label(stage: ReceiptStage) -> &'static str {
    match stage {
        ReceiptStage::Signed => "signed",
        ReceiptStage::RelayAccepted => "stored by relay",
        ReceiptStage::ProjectionCommitted => "recorded",
        ReceiptStage::ProjectionFailed => "recording failed",
        ReceiptStage::ConsumerReceived => "read by the agent",
        ReceiptStage::Applied => "applied",
        ReceiptStage::NotApplied => "NOT applied",
        ReceiptStage::AppliedManually => "applied manually",
        ReceiptStage::EscalatedOnAge => "escalated on age",
        ReceiptStage::Expired => "expired",
    }
}

/// Tailwind classes for a stage badge. `not-applied` and `recording failed` are
/// the two an operator must act on, so they read as failures rather than as
/// another shade of progress — an approved action whose write failed and a
/// denied action must never look the same (FR4.1).
pub fn stage_class(stage: ReceiptStage) -> &'static str {
    match stage {
        ReceiptStage::Applied | ReceiptStage::AppliedManually => {
            "bg-green-500/10 text-green-400 border-green-500/20"
        }
        ReceiptStage::NotApplied | ReceiptStage::ProjectionFailed => {
            "bg-red-500/10 text-red-400 border-red-500/30"
        }
        ReceiptStage::EscalatedOnAge | ReceiptStage::Expired => {
            "bg-amber-500/10 text-amber-400 border-amber-500/30"
        }
        _ => "bg-gray-700/60 text-gray-400 border-gray-600/50",
    }
}

// ── Reactive store ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReceiptStoreState {
    /// Per case `d`-tag. A case present with an empty [`CaseReceipts`] has been
    /// fetched and had nothing; a case absent has not been fetched.
    pub cases: HashMap<String, CaseReceipts>,
    /// Cases with a fetch in flight, so a re-render does not re-request.
    pub in_flight: HashMap<String, ()>,
    /// Set when the read is unavailable to this viewer (non-admin, or the relay
    /// refused). Surfaces as "stages unavailable", never as "not applied".
    pub unavailable: bool,
}

#[derive(Clone, Copy)]
pub struct ReceiptStore {
    pub state: RwSignal<ReceiptStoreState>,
}

pub fn provide_receipt_store() {
    provide_context(ReceiptStore {
        state: RwSignal::new(ReceiptStoreState::default()),
    });
}

pub fn use_receipt_store() -> ReceiptStore {
    expect_context::<ReceiptStore>()
}

impl ReceiptStore {
    /// The receipts already loaded for a case.
    pub fn case(&self, d_tag: &str) -> Option<CaseReceipts> {
        self.state.read().cases.get(d_tag).cloned()
    }

    /// Whether this case still needs a fetch. Read only by the WASM-only
    /// `load_case`, which is `cfg`-gated out of host-target rustdoc.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    pub fn needs_load(&self, d_tag: &str) -> bool {
        let s = self.state.read();
        !s.unavailable && !s.cases.contains_key(d_tag) && !s.in_flight.contains_key(d_tag)
    }

    /// Fetch one case's receipt trail (NIP-98 admin).
    ///
    /// A 401/403 sets `unavailable` once and stops further attempts for the
    /// session: a member surface must not hammer an endpoint it is not
    /// entitled to read.
    #[cfg(target_arch = "wasm32")]
    pub fn load_case(&self, d_tag: &str, signer: std::rc::Rc<dyn nostr_bbs_core::signer::Signer>) {
        use wasm_bindgen_futures::spawn_local;

        if !self.needs_load(d_tag) {
            return;
        }
        let key = d_tag.to_string();
        let store = *self;
        store.state.update(|s| {
            s.in_flight.insert(key.clone(), ());
        });
        spawn_local(async move {
            let url = format!(
                "{}/api/governance/receipts?case={}&limit=200",
                crate::utils::relay_url::relay_api_base(),
                js_sys::encode_uri_component(&key)
            );
            let result =
                crate::auth::nip98::fetch_with_nip98_get_signer(&url, signer.as_ref()).await;
            store.state.update(|s| {
                s.in_flight.remove(&key);
                match result {
                    Ok(body) => {
                        let rows: Vec<ReceiptView> = parse_receipts(&body)
                            .into_iter()
                            .filter(|r| r.case_id.is_empty() || r.case_id == key)
                            .collect();
                        s.cases.insert(key.clone(), reduce_case(rows));
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        // Not entitled to read: say so once, never retry, and
                        // never let the absence read as "not applied".
                        if msg.contains("401") || msg.contains("403") {
                            s.unavailable = true;
                        }
                        web_sys::console::warn_1(
                            &format!("[governance] receipt read failed: {msg}").into(),
                        );
                    }
                }
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(event_id: &str, stage: ReceiptStage) -> ReceiptView {
        ReceiptView {
            event_id: event_id.into(),
            case_id: "case-1".into(),
            stage,
            stage_error: None,
            applied_by: None,
            acknowledgement: None,
            applied_at: None,
        }
    }

    #[test]
    fn parses_the_relay_receipt_envelope() {
        let body = r#"{"receipts":[
            {"eventId":"dec-1","caseId":"case-1","stage":"applied","stageError":null,
             "appliedBy":"agent-x","acknowledgement":"migration 0007 ran","appliedAt":1700000000},
            {"eventId":"dec-1","caseId":"case-1","stage":"projection-committed"}
        ],"limit":50,"offset":0}"#;
        let rows = parse_receipts(body);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].stage, ReceiptStage::Applied);
        assert_eq!(
            rows[0].acknowledgement.as_deref(),
            Some("migration 0007 ran")
        );
        assert_eq!(rows[0].applied_by.as_deref(), Some("agent-x"));
        assert_eq!(rows[1].stage, ReceiptStage::ProjectionCommitted);
    }

    #[test]
    fn malformed_rows_are_skipped_not_fatal() {
        let body = r#"{"receipts":[{"eventId":"a","stage":"not-a-stage"},{"stage":"applied"},
                       {"eventId":"b","caseId":"case-1","stage":"applied"}]}"#;
        let rows = parse_receipts(body);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_id, "b");
    }

    #[test]
    fn a_non_receipt_body_yields_nothing_rather_than_panicking() {
        assert!(parse_receipts("").is_empty());
        assert!(parse_receipts("not json").is_empty());
        assert!(parse_receipts(r#"{"error":"forbidden"}"#).is_empty());
    }

    #[test]
    fn two_terminal_outcomes_are_a_conflict_never_a_winner() {
        // Auditor counter-example: `applied` and `not-applied` are mutually
        // exclusive CLAIMS about the world, not rungs. Picking the larger under
        // the derived `Ord` displayed a successful application as a failure.
        for pair in [
            [ReceiptStage::Applied, ReceiptStage::NotApplied],
            [ReceiptStage::NotApplied, ReceiptStage::Applied],
            [ReceiptStage::AppliedManually, ReceiptStage::Applied],
            [ReceiptStage::Applied, ReceiptStage::AppliedManually],
            [ReceiptStage::NotApplied, ReceiptStage::AppliedManually],
        ] {
            let r = reduce_case(vec![row("dec-1", pair[0]), row("dec-1", pair[1])]);
            let view = &r.by_decision["dec-1"].stage;
            match view {
                StageView::Conflicting(stages) => {
                    assert!(stages.contains(&pair[0]) && stages.contains(&pair[1]));
                }
                other => panic!("{pair:?} reduced to {other:?} instead of a conflict"),
            }
            assert!(view.label().contains("conflict"));
            assert!(view.class().contains("red"), "a conflict is not progress");
        }
    }

    #[test]
    fn a_conflict_survives_an_intervening_ladder_row() {
        let r = reduce_case(vec![
            row("dec-1", ReceiptStage::Applied),
            row("dec-1", ReceiptStage::ConsumerReceived),
            row("dec-1", ReceiptStage::NotApplied),
        ]);
        assert!(matches!(
            r.by_decision["dec-1"].stage,
            StageView::Conflicting(_)
        ));
    }

    #[test]
    fn a_repeated_terminal_outcome_is_not_a_conflict() {
        // The same claim twice — a replayed post — is one claim.
        for stage in [
            ReceiptStage::Applied,
            ReceiptStage::NotApplied,
            ReceiptStage::AppliedManually,
        ] {
            let r = reduce_case(vec![row("dec-1", stage), row("dec-1", stage)]);
            assert_eq!(r.by_decision["dec-1"].stage, StageView::Terminal(stage));
        }
    }

    #[test]
    fn one_terminal_outcome_wins_over_every_ladder_rung() {
        let r = reduce_case(vec![
            row("dec-1", ReceiptStage::Signed),
            row("dec-1", ReceiptStage::NotApplied),
            row("dec-1", ReceiptStage::RelayAccepted),
            row("dec-1", ReceiptStage::ConsumerReceived),
        ]);
        assert_eq!(
            r.by_decision["dec-1"].stage,
            StageView::Terminal(ReceiptStage::NotApplied)
        );
    }

    #[test]
    fn a_conflict_on_one_decision_does_not_infect_another() {
        let r = reduce_case(vec![
            row("dec-1", ReceiptStage::Applied),
            row("dec-1", ReceiptStage::NotApplied),
            row("dec-2", ReceiptStage::Applied),
        ]);
        assert!(matches!(
            r.by_decision["dec-1"].stage,
            StageView::Conflicting(_)
        ));
        assert_eq!(
            r.by_decision["dec-2"].stage,
            StageView::Terminal(ReceiptStage::Applied)
        );
    }

    #[test]
    fn out_of_order_ladder_rows_still_reduce_to_the_furthest_rung() {
        // Ladder rungs ARE ordered, and keep using that order.
        let r = reduce_case(vec![
            row("dec-1", ReceiptStage::ConsumerReceived),
            row("dec-1", ReceiptStage::Signed),
            row("dec-1", ReceiptStage::ProjectionCommitted),
            row("dec-1", ReceiptStage::RelayAccepted),
        ]);
        assert_eq!(
            r.by_decision["dec-1"].stage,
            StageView::Ladder(ReceiptStage::ConsumerReceived)
        );
    }

    #[test]
    fn the_terminal_outcome_wins_over_the_ladder_it_completes() {
        let r = reduce_case(vec![
            row("dec-1", ReceiptStage::ProjectionCommitted),
            row("dec-1", ReceiptStage::ConsumerReceived),
            row("dec-1", ReceiptStage::Applied),
        ]);
        assert_eq!(
            r.by_decision["dec-1"].stage,
            StageView::Terminal(ReceiptStage::Applied)
        );
    }

    #[test]
    fn an_out_of_order_row_never_regresses_a_decision() {
        let r = reduce_case(vec![
            row("dec-1", ReceiptStage::Applied),
            row("dec-1", ReceiptStage::ConsumerReceived),
        ]);
        assert_eq!(
            r.by_decision["dec-1"].stage,
            StageView::Terminal(ReceiptStage::Applied)
        );
    }

    #[test]
    fn side_receipts_flag_the_case_and_never_become_a_stage() {
        // DDD §6 invariant 5.
        let r = reduce_case(vec![
            row("dec-1", ReceiptStage::ConsumerReceived),
            row("dec-1", ReceiptStage::EscalatedOnAge),
            row("dec-1", ReceiptStage::Expired),
        ]);
        assert!(r.escalated_on_age);
        assert!(r.expired);
        assert_eq!(
            r.by_decision["dec-1"].stage,
            StageView::Ladder(ReceiptStage::ConsumerReceived)
        );
    }

    #[test]
    fn an_escalated_on_age_receipt_on_an_undecided_case_still_flags_it() {
        let r = reduce_case(vec![row("req-1", ReceiptStage::EscalatedOnAge)]);
        assert!(r.escalated_on_age);
        assert!(r.by_decision.is_empty());
    }

    #[test]
    fn the_application_stages_each_have_a_distinct_honest_label() {
        // FR4.1: "a denied action and an approved action whose write failed
        // must never look the same".
        assert_eq!(stage_label(ReceiptStage::Applied), "applied");
        assert_eq!(stage_label(ReceiptStage::NotApplied), "NOT applied");
        assert_eq!(
            stage_label(ReceiptStage::AppliedManually),
            "applied manually"
        );
        assert_eq!(
            stage_label(ReceiptStage::ConsumerReceived),
            "read by the agent"
        );
        assert_eq!(
            stage_label(ReceiptStage::EscalatedOnAge),
            "escalated on age"
        );
        let labels = [
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
        ]
        .map(stage_label);
        let mut uniq: Vec<&str> = labels.to_vec();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), labels.len(), "every stage reads distinctly");
    }

    #[test]
    fn a_failed_application_reads_as_a_failure_not_as_progress() {
        assert!(stage_class(ReceiptStage::NotApplied).contains("red"));
        assert!(stage_class(ReceiptStage::ProjectionFailed).contains("red"));
        assert!(stage_class(ReceiptStage::Applied).contains("green"));
        assert!(stage_class(ReceiptStage::EscalatedOnAge).contains("amber"));
    }
}
