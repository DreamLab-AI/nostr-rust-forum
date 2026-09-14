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
//! [`ReceiptStore::load_case`] touches the network.

use std::collections::HashMap;

use leptos::prelude::*;
use nostr_bbs_core::governance::ReceiptStage;

/// One `governance_receipts` row, reduced to what the decision chain renders.
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

/// What a case's receipts say, reduced for display.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CaseReceipts {
    /// The furthest **ladder** stage per 31403 event id. Side receipts never
    /// appear here (DDD §6 invariant 5).
    pub by_decision: HashMap<String, ReceiptView>,
    /// The case exceeded its panel's `max_pending_hours` (FR4.3). This is the
    /// authoritative statement, as against the client's own clock reading.
    pub escalated_on_age: bool,
    /// The case passed its open-case TTL without a decision.
    pub expired: bool,
}

/// Parse `GET /api/governance/receipts` into rows, ignoring anything malformed
/// rather than failing the whole read: a receipt trail with one unreadable row
/// is still worth showing.
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
/// DDD §6 invariant 5 — receipts are monotonic, and `escalated-on-age` /
/// `expired` are **side receipts that do not advance the ladder**. So a side
/// receipt sets its own flag and never becomes a decision's stage, and where
/// several ladder rows exist for one decision (a replayed projection, then an
/// application) the furthest one wins.
pub fn reduce_case(rows: Vec<ReceiptView>) -> CaseReceipts {
    let mut out = CaseReceipts::default();
    for row in rows {
        if row.stage == ReceiptStage::EscalatedOnAge {
            out.escalated_on_age = true;
            continue;
        }
        if row.stage == ReceiptStage::Expired {
            out.expired = true;
            continue;
        }
        match out.by_decision.get(&row.event_id) {
            Some(existing) if existing.stage >= row.stage => {}
            _ => {
                out.by_decision.insert(row.event_id.clone(), row);
            }
        }
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
    /// [`Self::load_case`].
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
        assert_eq!(rows[0].acknowledgement.as_deref(), Some("migration 0007 ran"));
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
    fn the_furthest_ladder_stage_wins_per_decision() {
        let r = reduce_case(vec![
            row("dec-1", ReceiptStage::ProjectionCommitted),
            row("dec-1", ReceiptStage::ConsumerReceived),
            row("dec-1", ReceiptStage::Applied),
        ]);
        assert_eq!(r.by_decision["dec-1"].stage, ReceiptStage::Applied);
    }

    #[test]
    fn an_out_of_order_row_never_regresses_a_decision() {
        let r = reduce_case(vec![
            row("dec-1", ReceiptStage::Applied),
            row("dec-1", ReceiptStage::ConsumerReceived),
        ]);
        assert_eq!(r.by_decision["dec-1"].stage, ReceiptStage::Applied);
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
        assert_eq!(r.by_decision["dec-1"].stage, ReceiptStage::ConsumerReceived);
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
        assert_eq!(stage_label(ReceiptStage::AppliedManually), "applied manually");
        assert_eq!(stage_label(ReceiptStage::ConsumerReceived), "read by the agent");
        assert_eq!(stage_label(ReceiptStage::EscalatedOnAge), "escalated on age");
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
