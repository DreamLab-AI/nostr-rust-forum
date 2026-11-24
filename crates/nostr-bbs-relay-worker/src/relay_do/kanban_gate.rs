//! Relay-side enforcement of kanban approval columns.
//!
//! A board (kind 30301) may mark columns as approval columns. Until this gate
//! existed only the forum client honoured that: any zone writer could publish a
//! card version (kind 30302) straight into one. The gate admits a non-admin
//! card version that *enters* an approval column only when the card's prior
//! version carries a `pending_move=(<column>, <31402 id>)` naming a stored
//! kanban approval request, an admin has approved it, the decider is not the
//! requester, and the approval has not been spent before.
//!
//! The decision is read from the raw stored 31402/31403 events, not from the
//! governance projection: a kanban 31403 carries a random `d`, so it never
//! joins the request's case (known finding KF-37), and broadcast runs before
//! projection. Spent approvals are recorded in `kanban_move_approvals`
//! (migration `0015`).
//!
//! The pure rules live in `nostr_bbs_core::kanban`; this module gathers the
//! facts from D1 and owns the rollout switch. Everything that can be tested
//! without a Durable Object is a pure function or a SQL constant, so the
//! rusqlite tests below run the very statements the Worker sends to D1.
//!
//! Rollout: `KANBAN_APPROVAL_GATE` is `warn` (the default, also for an unset or
//! unrecognised value) or `enforce`. In `warn` the gate evaluates and logs what
//! it would refuse, stores the event as before, and still writes the claim row
//! for admitted entries so the switch to `enforce` starts consistent.

use nostr_bbs_core::event::NostrEvent;
use nostr_bbs_core::{
    check_approved_entry, entry_requires_approval_at, parse_approval_decision, parse_coord,
    ApprovalFacts, ApprovalRefusal, ApprovedEntry, DecisionFacts, KanbanBoard, KanbanCard,
    KIND_KANBAN_BOARD, KIND_KANBAN_CARD,
};
use std::sync::atomic::{AtomicBool, Ordering};

use wasm_bindgen::JsValue;
use worker::*;

use super::storage::EventRow;
use super::NostrRelayDO;
use crate::auth;

/// Name of the relay var that selects the rollout mode.
pub(crate) const KANBAN_APPROVAL_GATE_VAR: &str = "KANBAN_APPROVAL_GATE";

/// Table of spent approvals. Held identical to `migrations/0015` by a test.
pub(crate) const KANBAN_MOVE_APPROVALS_CREATE_SQL: &str =
    "CREATE TABLE IF NOT EXISTS kanban_move_approvals (\
    request_event_id TEXT PRIMARY KEY NOT NULL, \
    board TEXT NOT NULL, \
    card_d TEXT NOT NULL, \
    target_col TEXT NOT NULL, \
    decision_event_id TEXT NOT NULL, \
    card_event_id TEXT NOT NULL, \
    gate_mode TEXT NOT NULL, \
    consumed_at INTEGER NOT NULL\
)";

/// Index over the card a spent approval belongs to. Held identical to `0015`.
pub(crate) const KANBAN_MOVE_APPROVALS_INDEX_SQL: &str =
    "CREATE INDEX IF NOT EXISTS idx_kanban_move_approvals_card \
    ON kanban_move_approvals(board, card_d)";

/// The board version at the exact coordinate named by the card's `a` tag.
pub(crate) const SELECT_BOARD_SQL: &str =
    "SELECT id, pubkey, created_at, kind, tags, content, sig FROM events WHERE kind = 30301 \
    AND pubkey = ?1 AND d_tag = ?2 ORDER BY created_at DESC LIMIT 1";

/// Stored versions of one card across authors, latest first, ties to the
/// lowest id, newest 20 (the true latest is always inside the limit, since
/// the order is the fold order). `?3` excludes the incoming event. Re-checked in Rust against the
/// card's board, because `d_tag` alone is not unique across boards.
pub(crate) const SELECT_PRIOR_CARD_SQL: &str = "SELECT e.id, e.pubkey, e.created_at, e.kind, e.tags, e.content, e.sig FROM events e \
    WHERE e.kind = 30302 AND e.d_tag = ?2 AND e.id <> ?3 \
    AND EXISTS (SELECT 1 FROM event_tags t WHERE t.event_id = e.id AND t.name = 'a' AND t.value = ?1) \
    ORDER BY e.created_at DESC, e.id ASC LIMIT 20";

/// The stored kanban approval request, by id.
pub(crate) const SELECT_REQUEST_SQL: &str =
    "SELECT id, pubkey, created_at, kind, tags, content, sig FROM events \
    WHERE id = ?1 AND kind = 31402";

/// The newest 50 stored 31403s whose `e` tag names a request. Narrowed to admin-signed,
/// request-bound, parseable decisions in Rust.
pub(crate) const SELECT_DECISIONS_SQL: &str = "SELECT e.id, e.pubkey, e.created_at, e.kind, e.tags, e.content, e.sig FROM events e \
    WHERE e.kind = 31403 \
    AND EXISTS (SELECT 1 FROM event_tags t WHERE t.event_id = e.id AND t.name = 'e' AND t.value = ?1) \
    ORDER BY e.created_at DESC, e.id ASC LIMIT 50";

/// Whether the incoming event id is already stored (a redelivery).
pub(crate) const SELECT_EVENT_KNOWN_SQL: &str = "SELECT id FROM events WHERE id = ?1 LIMIT 1";

/// Spend an approval. A concurrent or repeated claimant loses silently and is
/// then judged by [`SELECT_CONSUMPTION_SQL`].
pub(crate) const INSERT_CLAIM_SQL: &str = "INSERT INTO kanban_move_approvals \
    (request_event_id, board, card_d, target_col, decision_event_id, card_event_id, \
     gate_mode, consumed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
    ON CONFLICT(request_event_id) DO NOTHING";

/// The card event that spent a request, if any.
pub(crate) const SELECT_CONSUMPTION_SQL: &str =
    "SELECT card_event_id FROM kanban_move_approvals WHERE request_event_id = ?1";

/// Give a claim back when the card event could not be stored.
pub(crate) const DELETE_CLAIM_SQL: &str =
    "DELETE FROM kanban_move_approvals WHERE request_event_id = ?1 AND card_event_id = ?2";

/// Judge a claim from the row [`SELECT_CONSUMPTION_SQL`] returns after the
/// insert: the same card event is a repeat (fine), another is a lost race, and
/// no row (or a read error) cannot be verified.
pub(crate) fn claim_verdict(
    winner: std::result::Result<Option<String>, ()>,
    card_event_id: &str,
) -> std::result::Result<(), ApprovalRefusal> {
    match winner {
        Ok(Some(w)) if w == card_event_id => Ok(()),
        Ok(Some(_)) => Err(ApprovalRefusal::Consumed),
        Ok(None) | Err(()) => Err(ApprovalRefusal::Unverifiable),
    }
}

/// Name of the relay var that sets how long an approval stays usable.
pub(crate) const KANBAN_APPROVAL_TTL_VAR: &str = "KANBAN_APPROVAL_TTL_SECS";

/// Default approval lifetime: 7 days, counted from the decision's `created_at`.
pub(crate) const DEFAULT_APPROVAL_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Set once the mode has been logged in this isolate.
static MODE_LOGGED: AtomicBool = AtomicBool::new(false);

/// Parse `KANBAN_APPROVAL_TTL_SECS`. Unset, empty, non-numeric and zero values
/// give [`DEFAULT_APPROVAL_TTL_SECS`] (a zero lifetime would refuse every move).
pub(crate) fn kanban_approval_ttl_var(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_APPROVAL_TTL_SECS)
}

/// Whether a claim should be given back after `save_event` answered `false`.
/// `stored_after` is whether the card event is now in the table: a duplicate
/// copy of an event that another delivery stored keeps the claim, because the
/// claim belongs to the stored event. Unknown (`None`) keeps it too: a leaked
/// claim costs a new request, a wrongly released one re-arms the approval.
pub(crate) fn should_release_claim(stored_after: Option<bool>) -> bool {
    stored_after == Some(false)
}

/// Rollout mode of the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateMode {
    /// Evaluate and log, never refuse.
    Warn,
    /// Refuse with `blocked: <token>`.
    Enforce,
}

impl GateMode {
    /// The value stored in `kanban_move_approvals.gate_mode`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            GateMode::Warn => "warn",
            GateMode::Enforce => "enforce",
        }
    }
}

/// Parse the `KANBAN_APPROVAL_GATE` var. Only the exact string `enforce`
/// enforces; unset, empty and unrecognised values are `warn`.
pub(crate) fn kanban_approval_gate_mode_var(raw: Option<&str>) -> GateMode {
    if raw == Some("enforce") {
        GateMode::Enforce
    } else {
        GateMode::Warn
    }
}

/// Whether the gate is consulted at all: only for card versions from
/// non-admins. Admins keep the same bypass they have in the client and in the
/// zone write gate.
pub(crate) fn kanban_gate_applies(kind: u64, is_admin: bool) -> bool {
    kind == KIND_KANBAN_CARD && !is_admin
}

/// Outcome of evaluating one card version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KanbanGate {
    /// Not an entry into an approval column (or the board is unknown).
    NotGated,
    /// An entry with a valid approval; the approval is to be claimed.
    Admitted(ApprovedEntry),
    /// An entry the gate would refuse.
    Refused(ApprovalRefusal),
}

/// A stored 31403 with its signer's admin standing resolved by the caller.
#[derive(Debug, Clone)]
pub(crate) struct DecisionCandidate {
    /// The stored decision event.
    pub event: NostrEvent,
    /// Whether the signer is a current admin.
    pub signer_is_admin: bool,
}

/// The latest decision that may bind `request_id`: admin-signed, citing the
/// request through the kanban link rule (`decision_request_link`: an `e` tag
/// marked `request`, else the first unmarked one; `supersedes` and `appeal`
/// markers never bind, so there is no appeal fallback here), and parseable as
/// Approve or Reject.
/// Latest `created_at` wins, ties to the lowest id. Returns the event and
/// whether it approves.
///
/// An unparseable 31403 is invisible, not a denial.
pub(crate) fn latest_eligible_decision<'a>(
    request_id: &str,
    candidates: &'a [DecisionCandidate],
) -> Option<(&'a NostrEvent, bool)> {
    candidates
        .iter()
        .filter(|c| c.signer_is_admin)
        .filter_map(|c| parse_approval_decision(&c.event).map(|d| (&c.event, d)))
        .filter(|(_, d)| d.request_id == request_id)
        .map(|(ev, d)| (ev, d.approved))
        .min_by(|(a, _), (b, _)| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.cmp(&b.id))
        })
}

/// The first row that is a card version of `board_coord`, given rows in
/// latest-first order.
pub(crate) fn first_card_of_board(rows: Vec<NostrEvent>, board_coord: &str) -> Option<KanbanCard> {
    rows.iter()
        .filter_map(KanbanCard::from_event)
        .find(|c| c.board == board_coord)
}

impl NostrRelayDO {
    /// The rollout mode from `KANBAN_APPROVAL_GATE`. The first call in an
    /// isolate logs the mode, and an unrecognised value loudly.
    pub(crate) fn kanban_approval_gate_mode(&self) -> GateMode {
        let raw = self
            .env
            .var(KANBAN_APPROVAL_GATE_VAR)
            .ok()
            .map(|v| v.to_string());
        let mode = kanban_approval_gate_mode_var(raw.as_deref());
        if !MODE_LOGGED.swap(true, Ordering::Relaxed) {
            match raw.as_deref() {
                None | Some("warn") | Some("enforce") => {
                    console_log!("kanban approval gate: mode {}", mode.as_str());
                }
                Some(other) => console_error!(
                    "kanban approval gate: {KANBAN_APPROVAL_GATE_VAR}={other:?} is not \
                     \"warn\" or \"enforce\"; running in warn"
                ),
            }
        }
        mode
    }

    /// The approval lifetime from `KANBAN_APPROVAL_TTL_SECS`.
    pub(crate) fn kanban_approval_ttl_secs(&self) -> u64 {
        kanban_approval_ttl_var(
            self.env
                .var(KANBAN_APPROVAL_TTL_VAR)
                .ok()
                .map(|v| v.to_string())
                .as_deref(),
        )
    }

    /// Run a query that returns stored events. `Err` is a D1 failure.
    async fn kanban_query_events(
        &self,
        sql: &str,
        params: &[JsValue],
    ) -> std::result::Result<Vec<NostrEvent>, ()> {
        let db = self.env.d1("DB").map_err(|_| ())?;
        let stmt = db.prepare(sql).bind(params).map_err(|_| ())?;
        let rows: Vec<EventRow> = stmt
            .all()
            .await
            .map_err(|_| ())?
            .results()
            .map_err(|_| ())?;
        Ok(rows
            .into_iter()
            .filter_map(EventRow::into_nostr_event)
            .collect())
    }

    /// Evaluate a card version from a non-admin. Fast-path order: board read,
    /// then the prior-version read, then (only for a real entry) the request,
    /// decision, principal and consumption reads.
    ///
    /// A D1 failure before the entry is known to be gated fails open (the
    /// board cannot be rendered by clients either); after that it is
    /// [`ApprovalRefusal::Unverifiable`], which fails closed in `enforce`.
    pub(crate) async fn kanban_approval_gate(&self, event: &NostrEvent) -> KanbanGate {
        let Some(incoming) = KanbanCard::from_event(event) else {
            return KanbanGate::NotGated;
        };
        let Some((kind, board_pk, board_d)) = parse_coord(&incoming.board) else {
            return KanbanGate::NotGated;
        };
        if kind != KIND_KANBAN_BOARD {
            return KanbanGate::NotGated;
        }

        let board = match self
            .kanban_query_events(
                SELECT_BOARD_SQL,
                &[JsValue::from_str(board_pk), JsValue::from_str(board_d)],
            )
            .await
        {
            Ok(rows) => rows.first().and_then(KanbanBoard::from_event),
            Err(()) => {
                console_warn!("kanban approval gate: board read failed for {}", event.id);
                return KanbanGate::NotGated;
            }
        };
        let Some(board) = board else {
            return KanbanGate::NotGated;
        };
        if !board.column_needs_approval(&incoming.column) {
            return KanbanGate::NotGated;
        }

        // Known to be gated from here on: storage errors fail closed.
        let prior_rows = match self
            .kanban_query_events(
                SELECT_PRIOR_CARD_SQL,
                &[
                    JsValue::from_str(&incoming.board),
                    JsValue::from_str(&incoming.d_tag),
                    JsValue::from_str(&event.id),
                ],
            )
            .await
        {
            Ok(rows) => rows,
            Err(()) => return KanbanGate::Refused(ApprovalRefusal::Unverifiable),
        };
        let prior = first_card_of_board(prior_rows, &incoming.board);
        let now = auth::js_now_secs();
        if !entry_requires_approval_at(Some(&board), prior.as_ref(), &incoming, now) {
            return KanbanGate::NotGated;
        }

        // A redelivery of an event the relay already holds changes nothing:
        // the replaceable save has typically removed the prior version.
        match self.kanban_event_known(&event.id).await {
            Some(true) => return KanbanGate::NotGated,
            Some(false) => {}
            None => return KanbanGate::Refused(ApprovalRefusal::Unverifiable),
        }

        let ttl_secs = self.kanban_approval_ttl_secs();
        let request_id = prior
            .as_ref()
            .and_then(|p| p.pending_move.as_ref())
            .map(|(_, r)| r.clone());
        let Some(request_id) = request_id else {
            return self.kanban_check(&incoming, prior.as_ref(), None, now, ttl_secs);
        };

        let request = match self
            .kanban_query_events(SELECT_REQUEST_SQL, &[JsValue::from_str(&request_id)])
            .await
        {
            Ok(mut rows) => rows.pop(),
            Err(()) => return KanbanGate::Refused(ApprovalRefusal::Unverifiable),
        };
        let Some(request) = request else {
            return self.kanban_check(&incoming, prior.as_ref(), None, now, ttl_secs);
        };

        let decision_rows = match self
            .kanban_query_events(SELECT_DECISIONS_SQL, &[JsValue::from_str(&request_id)])
            .await
        {
            Ok(rows) => rows,
            Err(()) => return KanbanGate::Refused(ApprovalRefusal::Unverifiable),
        };
        let mut candidates = Vec::with_capacity(decision_rows.len());
        for ev in decision_rows {
            let signer_is_admin = self.admin_cache.is_admin(&ev.pubkey, &self.env).await;
            candidates.push(DecisionCandidate {
                event: ev,
                signer_is_admin,
            });
        }
        let decision = latest_eligible_decision(&request_id, &candidates);
        let decider_principal = match decision {
            Some((ev, _)) => Some(self.effective_pubkey(&ev.pubkey).await.to_ascii_lowercase()),
            None => None,
        };
        let requester_principal = self
            .effective_pubkey(&request.pubkey)
            .await
            .to_ascii_lowercase();
        let consumed_by = match self.kanban_consumed_by(&request_id).await {
            Ok(c) => c,
            Err(()) => return KanbanGate::Refused(ApprovalRefusal::Unverifiable),
        };

        let facts = ApprovalFacts {
            incoming: &incoming,
            prior: prior.as_ref(),
            request: Some(&request),
            requester_principal: Some(&requester_principal),
            decision: decision.map(|(ev, approved)| DecisionFacts {
                event_id: &ev.id,
                approved,
                decider_principal: decider_principal.as_deref().unwrap_or(&ev.pubkey),
                signed_at: ev.created_at,
            }),
            consumed_by: consumed_by.as_deref(),
            now,
            ttl_secs,
        };
        match check_approved_entry(&facts) {
            Ok(entry) => KanbanGate::Admitted(entry),
            Err(r) => KanbanGate::Refused(r),
        }
    }

    /// `check_approved_entry` over the facts known when the request could not
    /// be found: it fails before reading any of the missing ones.
    fn kanban_check(
        &self,
        incoming: &KanbanCard,
        prior: Option<&KanbanCard>,
        request: Option<&NostrEvent>,
        now: u64,
        ttl_secs: u64,
    ) -> KanbanGate {
        match check_approved_entry(&ApprovalFacts {
            incoming,
            prior,
            request,
            requester_principal: None,
            decision: None,
            consumed_by: None,
            now,
            ttl_secs,
        }) {
            Ok(entry) => KanbanGate::Admitted(entry),
            Err(r) => KanbanGate::Refused(r),
        }
    }

    /// Whether an event id is already stored. `None` on a D1 failure.
    pub(crate) async fn kanban_event_known(&self, id: &str) -> Option<bool> {
        let db = self.env.d1("DB").ok()?;
        let stmt = db
            .prepare(SELECT_EVENT_KNOWN_SQL)
            .bind(&[JsValue::from_str(id)])
            .ok()?;
        let row = stmt.first::<serde_json::Value>(None).await.ok()?;
        Some(row.is_some())
    }

    /// The card event that already spent `request_id`, if any.
    async fn kanban_consumed_by(
        &self,
        request_id: &str,
    ) -> std::result::Result<Option<String>, ()> {
        let db = self.env.d1("DB").map_err(|_| ())?;
        let stmt = db
            .prepare(SELECT_CONSUMPTION_SQL)
            .bind(&[JsValue::from_str(request_id)])
            .map_err(|_| ())?;
        let row = stmt
            .first::<serde_json::Value>(None)
            .await
            .map_err(|_| ())?;
        Ok(row.and_then(|v| {
            v.get("card_event_id")
                .and_then(|c| c.as_str())
                .map(str::to_string)
        }))
    }

    /// Spend `entry`'s approval on `card_event_id`. A repeat by the same card
    /// event is fine (a redelivery); a different card event gets
    /// [`ApprovalRefusal::Consumed`]. Runs in every mode, so `enforce` starts
    /// from a consistent table.
    pub(crate) async fn claim_kanban_approval(
        &self,
        entry: &ApprovedEntry,
        card_event_id: &str,
        mode: GateMode,
    ) -> std::result::Result<(), ApprovalRefusal> {
        let unverifiable = ApprovalRefusal::Unverifiable;
        let db = self.env.d1("DB").map_err(|_| unverifiable)?;
        db.prepare(INSERT_CLAIM_SQL)
            .bind(&[
                JsValue::from_str(&entry.request_id),
                JsValue::from_str(&entry.board),
                JsValue::from_str(&entry.card_d),
                JsValue::from_str(&entry.target_col),
                JsValue::from_str(&entry.decision_id),
                JsValue::from_str(card_event_id),
                JsValue::from_str(mode.as_str()),
                JsValue::from_f64(auth::js_now_secs() as f64),
            ])
            .map_err(|_| unverifiable)?
            .run()
            .await
            .map_err(|_| unverifiable)?;
        claim_verdict(
            self.kanban_consumed_by(&entry.request_id).await,
            card_event_id,
        )
    }

    /// Give a claim back after the card event failed to store, so the
    /// approval is not spent on nothing. Only the row this event wrote goes.
    pub(crate) async fn release_kanban_approval(&self, request_id: &str, card_event_id: &str) {
        let Ok(db) = self.env.d1("DB") else {
            return;
        };
        if let Ok(stmt) = db.prepare(DELETE_CLAIM_SQL).bind(&[
            JsValue::from_str(request_id),
            JsValue::from_str(card_event_id),
        ]) {
            let _ = stmt.run().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_do::receipts::correlate;
    use rusqlite::{params, Connection};

    // -- Fixtures ----------------------------------------------------------------

    const BOARD_PK: &str = "aa";
    const BOARD_COORD: &str = "30301:aa:board1";

    fn norm(sql: &str) -> String {
        let stripped: String = sql
            .lines()
            .map(|l| l.split("--").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join(" ");
        stripped
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .replace("( ", "(")
            .replace(" )", ")")
            .replace(" ;", ";")
    }

    /// `events` + the trigger-maintained `event_tags` + the new table, built
    /// from the same DDL the Worker and the migrations carry.
    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(crate::EVENTS_CREATE_SQL, []).unwrap();
        conn.execute_batch(include_str!("../../migrations/0004_event_tags.sql"))
            .unwrap();
        for stmt in crate::PROBE_BLIND_STMTS {
            conn.execute(stmt, []).unwrap();
        }
        conn.execute_batch(include_str!(
            "../../migrations/0015_kanban_move_approvals.sql"
        ))
        .unwrap();
        conn
    }

    fn tag(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn ev(
        id: &str,
        pubkey: &str,
        created_at: u64,
        kind: u64,
        tags: Vec<Vec<String>>,
    ) -> NostrEvent {
        NostrEvent {
            id: id.into(),
            pubkey: pubkey.into(),
            created_at,
            kind,
            tags,
            content: r#"{"action":"approve"}"#.into(),
            sig: "s".into(),
        }
    }

    fn insert(conn: &Connection, e: &NostrEvent) {
        let d = e
            .tags
            .iter()
            .find(|t| t[0] == "d")
            .map(|t| t[1].clone())
            .unwrap_or_default();
        conn.execute(
            "INSERT INTO events (id, pubkey, created_at, kind, tags, content, sig, d_tag, \
             received_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
            params![
                e.id,
                e.pubkey,
                e.created_at as i64,
                e.kind as i64,
                serde_json::to_string(&e.tags).unwrap(),
                e.content,
                e.sig,
                d
            ],
        )
        .unwrap();
    }

    fn board_event(id: &str, pubkey: &str, d: &str, approval: &[&str]) -> NostrEvent {
        let mut tags = vec![
            tag(&["d", d]),
            tag(&["title", "B"]),
            tag(&["col", "todo", "To do", "0"]),
            tag(&["col", "done", "Done", "1"]),
        ];
        for c in approval {
            tags.push(tag(&["approval_col", c]));
        }
        ev(id, pubkey, 1, 30301, tags)
    }

    fn card_event(id: &str, pubkey: &str, at: u64, board: &str, col: &str) -> NostrEvent {
        ev(
            id,
            pubkey,
            at,
            30302,
            vec![tag(&["d", "card1"]), tag(&["a", board]), tag(&["s", col])],
        )
    }

    fn rows(conn: &Connection, sql: &str, params: &[&dyn rusqlite::ToSql]) -> Vec<String> {
        let mut stmt = conn.prepare(sql).unwrap();
        stmt.query_map(params, |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    fn claim(conn: &Connection, request: &str, card: &str, mode: &str) -> usize {
        conn.execute(
            INSERT_CLAIM_SQL,
            params![request, BOARD_COORD, "card1", "done", "dec", card, mode, 1],
        )
        .unwrap()
    }

    fn consumed(conn: &Connection, request: &str) -> Option<String> {
        rows(conn, SELECT_CONSUMPTION_SQL, &[&request])
            .into_iter()
            .next()
    }

    // -- Schema ------------------------------------------------------------------

    #[test]
    fn migration_0015_matches_the_ensure_schema_constants() {
        let migration = norm(include_str!(
            "../../migrations/0015_kanban_move_approvals.sql"
        ));
        let consts = format!(
            "{}; {};",
            norm(KANBAN_MOVE_APPROVALS_CREATE_SQL),
            norm(KANBAN_MOVE_APPROVALS_INDEX_SQL)
        );
        assert_eq!(migration, consts);
    }

    // -- 16: board republished by a non-maintainer --------------------------------

    #[test]
    fn sibling_board_at_another_coordinate_does_not_replace_the_real_one() {
        let conn = db();
        insert(&conn, &board_event("b-real", BOARD_PK, "board1", &["done"]));
        // A zone writer's sibling: same d, no approval column, newer.
        let mut sibling = board_event("b-fake", "ff", "board1", &[]);
        sibling.created_at = 99;
        insert(&conn, &sibling);

        let ids = rows(&conn, SELECT_BOARD_SQL, &[&BOARD_PK, &"board1"]);
        assert_eq!(ids, vec!["b-real"]);
        let real = KanbanBoard::from_event(&ev(
            "b-real",
            BOARD_PK,
            1,
            30301,
            board_event("x", BOARD_PK, "board1", &["done"]).tags,
        ))
        .unwrap();
        assert!(real.column_needs_approval("done"));

        // A card whose `a` points at the sibling is a different card key.
        insert(&conn, &card_event("c-real", "cc", 5, BOARD_COORD, "todo"));
        insert(
            &conn,
            &card_event("c-fake", "cc", 6, "30301:ff:board1", "todo"),
        );
        let prior = rows(
            &conn,
            SELECT_PRIOR_CARD_SQL,
            &[&BOARD_COORD, &"card1", &"incoming"],
        );
        assert_eq!(prior, vec!["c-real"]);
    }

    // -- 17: prior-version SQL ----------------------------------------------------

    #[test]
    fn prior_version_is_latest_across_authors_with_lowest_id_tie_break() {
        let conn = db();
        insert(&conn, &card_event("old", "c1", 5, BOARD_COORD, "todo"));
        insert(&conn, &card_event("b-tie", "c2", 9, BOARD_COORD, "todo"));
        insert(&conn, &card_event("a-tie", "c3", 9, BOARD_COORD, "doing"));
        insert(
            &conn,
            &card_event("incoming", "c4", 20, BOARD_COORD, "done"),
        );

        let ids = rows(
            &conn,
            SELECT_PRIOR_CARD_SQL,
            &[&BOARD_COORD, &"card1", &"incoming"],
        );
        assert_eq!(ids, vec!["a-tie", "b-tie", "old"], "incoming id excluded");

        let events: Vec<NostrEvent> = ids
            .iter()
            .map(|id| card_event(id, "x", 1, BOARD_COORD, "todo"))
            .collect();
        let first = first_card_of_board(events, BOARD_COORD).unwrap();
        assert_eq!(first.id, "a-tie");
    }

    // -- 18: claim idempotency ----------------------------------------------------

    #[test]
    fn claim_is_idempotent_for_one_card_and_refuses_another() {
        let conn = db();
        assert_eq!(claim(&conn, "r1", "card-a", "enforce"), 1);
        // Same card event again: the insert is a no-op and the winner is us.
        assert_eq!(claim(&conn, "r1", "card-a", "enforce"), 0);
        assert_eq!(consumed(&conn, "r1").as_deref(), Some("card-a"));
        // A different card event loses and sees the winner.
        assert_eq!(claim(&conn, "r1", "card-b", "enforce"), 0);
        assert_eq!(consumed(&conn, "r1").as_deref(), Some("card-a"));
    }

    #[test]
    fn release_deletes_only_the_matching_row() {
        let conn = db();
        claim(&conn, "r1", "card-a", "enforce");
        claim(&conn, "r2", "card-b", "enforce");
        // Wrong card event: nothing goes.
        let n = conn
            .execute(DELETE_CLAIM_SQL, params!["r1", "card-b"])
            .unwrap();
        assert_eq!(n, 0);
        let n = conn
            .execute(DELETE_CLAIM_SQL, params!["r1", "card-a"])
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(consumed(&conn, "r1"), None);
        assert_eq!(consumed(&conn, "r2").as_deref(), Some("card-b"));
    }

    // -- 19: decision filtering ---------------------------------------------------

    fn decision(
        id: &str,
        signer: &str,
        at: u64,
        tags: Vec<Vec<String>>,
        content: &str,
    ) -> NostrEvent {
        let mut e = ev(id, signer, at, 31403, tags);
        e.content = content.into();
        e
    }

    fn plain_tags(request: &str) -> Vec<Vec<String>> {
        vec![
            tag(&["d", &format!("rand-{request}")]),
            tag(&["e", request]),
        ]
    }

    fn cand(event: NostrEvent, signer_is_admin: bool) -> DecisionCandidate {
        DecisionCandidate {
            event,
            signer_is_admin,
        }
    }

    #[test]
    fn decision_by_a_non_admin_is_ignored() {
        let c = [cand(
            decision(
                "d1",
                "reviewer",
                10,
                plain_tags("r1"),
                r#"{"action":"approve"}"#,
            ),
            false,
        )];
        assert!(latest_eligible_decision("r1", &c).is_none());
    }

    #[test]
    fn decision_whose_only_link_is_a_supersedes_marker_is_ignored() {
        // SQL picks it up (its `e` tag names r1) but correlate() reads a
        // supersedes-marked tag as no request at all.
        let conn = db();
        let tags = vec![tag(&["d", "rand"]), tag(&["e", "r1", "", "supersedes"])];
        let sup = decision("d-sup", "admin", 10, tags, r#"{"action":"approve"}"#);
        insert(&conn, &sup);
        assert_eq!(rows(&conn, SELECT_DECISIONS_SQL, &[&"r1"]), vec!["d-sup"]);
        assert!(latest_eligible_decision("r1", &[cand(sup, true)]).is_none());
    }

    #[test]
    fn unparseable_decision_is_invisible_not_a_denial() {
        let junk = decision("d1", "admin", 10, plain_tags("r1"), "not json");
        assert!(latest_eligible_decision("r1", &[cand(junk, true)]).is_none());
    }

    #[test]
    fn decision_for_another_request_is_ignored() {
        let other = decision(
            "d1",
            "admin",
            10,
            plain_tags("r2"),
            r#"{"action":"approve"}"#,
        );
        assert!(latest_eligible_decision("r1", &[cand(other, true)]).is_none());
    }

    #[test]
    fn latest_eligible_decision_wins_so_a_later_reject_denies() {
        let approve = decision(
            "d-a",
            "admin",
            10,
            plain_tags("r1"),
            r#"{"action":"approve"}"#,
        );
        let reject = decision(
            "d-r",
            "admin",
            20,
            plain_tags("r1"),
            r#"{"action":"reject"}"#,
        );
        let c = [cand(approve.clone(), true), cand(reject.clone(), true)];
        let (ev, approved) = latest_eligible_decision("r1", &c).unwrap();
        assert_eq!((ev.id.as_str(), approved), ("d-r", false));
        // Order of the candidates does not matter.
        let c = [cand(reject, true), cand(approve, true)];
        assert!(!latest_eligible_decision("r1", &c).unwrap().1);
    }

    #[test]
    fn decision_tie_breaks_to_the_lowest_id() {
        let a = decision(
            "d-a",
            "admin",
            10,
            plain_tags("r1"),
            r#"{"action":"approve"}"#,
        );
        let b = decision(
            "d-b",
            "admin",
            10,
            plain_tags("r1"),
            r#"{"action":"reject"}"#,
        );
        let both = [cand(b, true), cand(a, true)];
        let (ev, _) = latest_eligible_decision("r1", &both).unwrap();
        assert_eq!(ev.id, "d-a");
    }

    // -- 20 / 21: mode and admin exemption ----------------------------------------

    #[test]
    fn mode_var_defaults_to_warn() {
        assert_eq!(kanban_approval_gate_mode_var(None), GateMode::Warn);
        assert_eq!(kanban_approval_gate_mode_var(Some("")), GateMode::Warn);
        assert_eq!(kanban_approval_gate_mode_var(Some("junk")), GateMode::Warn);
        assert_eq!(
            kanban_approval_gate_mode_var(Some("Enforce")),
            GateMode::Warn
        );
        assert_eq!(kanban_approval_gate_mode_var(Some("warn")), GateMode::Warn);
        assert_eq!(
            kanban_approval_gate_mode_var(Some("enforce")),
            GateMode::Enforce
        );
    }

    #[test]
    fn gate_is_not_consulted_for_admins_or_other_kinds() {
        assert!(kanban_gate_applies(30302, false));
        assert!(!kanban_gate_applies(30302, true));
        assert!(!kanban_gate_applies(30301, false));
        assert!(!kanban_gate_applies(1, false));
    }

    #[test]
    fn claim_verdict_has_three_arms() {
        assert_eq!(claim_verdict(Ok(Some("c1".into())), "c1"), Ok(()));
        assert_eq!(
            claim_verdict(Ok(Some("c1".into())), "c2"),
            Err(ApprovalRefusal::Consumed)
        );
        assert_eq!(
            claim_verdict(Ok(None), "c1"),
            Err(ApprovalRefusal::Unverifiable)
        );
        assert_eq!(
            claim_verdict(Err(()), "c1"),
            Err(ApprovalRefusal::Unverifiable)
        );
    }

    #[test]
    fn appeal_marked_admin_approval_citing_the_request_is_not_eligible() {
        // The case projection falls back to the appeal target, but a kanban
        // decision binds only through a `request`-marked or unmarked `e` tag.
        let tags = vec![tag(&["d", "rand"]), tag(&["e", "r1", "", "appeal"])];
        let appeal = decision("d-app", "admin", 10, tags, r#"{"action":"approve"}"#);
        assert!(latest_eligible_decision("r1", &[cand(appeal, true)]).is_none());
        // A `request`-marked tag does bind.
        let tags = vec![tag(&["d", "rand"]), tag(&["e", "r1", "", "request"])];
        let marked = decision("d-req", "admin", 10, tags, r#"{"action":"approve"}"#);
        assert!(latest_eligible_decision("r1", &[cand(marked, true)]).is_some());
    }

    #[test]
    fn ttl_var_defaults_to_seven_days() {
        assert_eq!(kanban_approval_ttl_var(None), 604_800);
        assert_eq!(kanban_approval_ttl_var(Some("")), 604_800);
        assert_eq!(kanban_approval_ttl_var(Some("junk")), 604_800);
        assert_eq!(kanban_approval_ttl_var(Some("0")), 604_800);
        assert_eq!(kanban_approval_ttl_var(Some(" 3600 ")), 3600);
    }

    #[test]
    fn duplicate_a_tags_do_not_multiply_prior_rows_and_the_limit_keeps_the_latest() {
        let conn = db();
        // One card version with the board's `a` tag repeated 30 times.
        let mut dup = card_event("dup", "c1", 50, BOARD_COORD, "todo");
        for _ in 0..30 {
            dup.tags.push(tag(&["a", BOARD_COORD]));
        }
        insert(&conn, &dup);
        let ids = rows(
            &conn,
            SELECT_PRIOR_CARD_SQL,
            &[&BOARD_COORD, &"card1", &"incoming"],
        );
        assert_eq!(ids, vec!["dup"], "one row per event, not per tag");

        // Far more versions than the limit: the newest is still first.
        for i in 0..40u64 {
            insert(
                &conn,
                &card_event(
                    &format!("v{i:02}"),
                    &format!("w{i}"),
                    i,
                    BOARD_COORD,
                    "todo",
                ),
            );
        }
        let ids = rows(
            &conn,
            SELECT_PRIOR_CARD_SQL,
            &[&BOARD_COORD, &"card1", &"incoming"],
        );
        assert_eq!(ids.len(), 20);
        assert_eq!(ids[0], "dup", "created_at 50 beats every v*");
    }

    #[test]
    fn decision_query_is_bounded_and_newest_first() {
        let conn = db();
        for i in 0..80u64 {
            insert(
                &conn,
                &decision(
                    &format!("d{i:02}"),
                    "admin",
                    i,
                    plain_tags("r1"),
                    r#"{"action":"approve"}"#,
                ),
            );
        }
        let ids = rows(&conn, SELECT_DECISIONS_SQL, &[&"r1"]);
        assert_eq!(ids.len(), 50);
        assert_eq!(ids[0], "d79");
    }

    #[test]
    fn a_duplicate_save_keeps_the_claim_of_the_stored_event() {
        // M4: copies 1 and 2 of finalising event F both claim R (the second is
        // a no-op, same card id). Copy 1 stores F; copy 2's save answers
        // false. Releasing on copy 2's false would delete copy 1's claim.
        let conn = db();
        assert_eq!(claim(&conn, "r1", "F", "enforce"), 1);
        assert_eq!(claim(&conn, "r1", "F", "enforce"), 0);
        insert(&conn, &card_event("F", "c1", 20, BOARD_COORD, "done"));
        let stored_after = Some(!rows(&conn, SELECT_EVENT_KNOWN_SQL, &[&"F"]).is_empty());
        assert!(!should_release_claim(stored_after));
        assert_eq!(consumed(&conn, "r1").as_deref(), Some("F"));

        // A save that really failed (event absent) does release.
        assert_eq!(claim(&conn, "r2", "G", "enforce"), 1);
        let stored_after = Some(!rows(&conn, SELECT_EVENT_KNOWN_SQL, &[&"G"]).is_empty());
        assert!(should_release_claim(stored_after));
        conn.execute(DELETE_CLAIM_SQL, params!["r2", "G"]).unwrap();
        assert_eq!(consumed(&conn, "r2"), None);

        // An unreadable table keeps the claim.
        assert!(!should_release_claim(None));
    }

    // -- 22: warn mode still claims -----------------------------------------------

    #[test]
    fn warn_mode_still_writes_the_claim_row() {
        let conn = db();
        assert_eq!(claim(&conn, "r1", "card-a", GateMode::Warn.as_str()), 1);
        let mode = rows(
            &conn,
            "SELECT gate_mode FROM kanban_move_approvals WHERE request_event_id = ?1",
            &[&"r1"],
        );
        assert_eq!(mode, vec!["warn"]);
    }

    // -- Decision lookup through the covering index --------------------------------

    #[test]
    fn decisions_are_found_through_event_tags_and_other_kinds_are_not() {
        let conn = db();
        insert(
            &conn,
            &decision(
                "d1",
                "admin",
                10,
                plain_tags("r1"),
                r#"{"action":"approve"}"#,
            ),
        );
        // A non-31403 event that cites the same id is not returned.
        insert(&conn, &ev("n1", "x", 10, 1, vec![tag(&["e", "r1"])]));
        assert_eq!(rows(&conn, SELECT_DECISIONS_SQL, &[&"r1"]), vec!["d1"]);
    }

    #[test]
    fn request_lookup_requires_kind_31402() {
        let conn = db();
        insert(
            &conn,
            &ev(
                "r1",
                "dd",
                5,
                31402,
                vec![tag(&["d", "q"]), tag(&["k", "30302"])],
            ),
        );
        insert(&conn, &ev("r2", "dd", 5, 1, vec![]));
        assert_eq!(rows(&conn, SELECT_REQUEST_SQL, &[&"r1"]), vec!["r1"]);
        assert!(rows(&conn, SELECT_REQUEST_SQL, &[&"r2"]).is_empty());
    }

    // -- KF-37: kanban decisions never join their request's case -------------------

    /// Minimal executor for the I/O-free `PrfSigner` futures.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn noop(_: *const ()) {}
        fn clone(p: *const ()) -> RawWaker {
            RawWaker::new(p, &VTAB)
        }
        static VTAB: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTAB)) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = std::pin::pin!(fut);
        loop {
            if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
        }
    }

    fn prf_signer(seed: u8) -> nostr_bbs_core::PrfSigner {
        let secret = nostr_bbs_core::keys::SecretKey::from_bytes([seed; 32]).unwrap();
        let public = secret.public_key();
        nostr_bbs_core::PrfSigner::new(nostr_bbs_core::keys::Keypair { secret, public })
    }

    /// KNOWN BUG (KF-37, docs/security/known-findings.md). This test documents
    /// today's behaviour and is written to FAIL when someone fixes it.
    ///
    /// `create_card_approval_response_signer` gives the 31403 a fresh random `d`,
    /// `receipts::correlate` uses that `d` as the case id, and the kanban 31402
    /// projects a case keyed by its OWN `d`. So the decision cites the right
    /// request but joins no case: every kanban case stays `open`, no decision
    /// reaches `broker_decisions`, and the receipt stops at `projection-failed`
    /// ("request case has not projected; retry after request").
    ///
    /// The fix is a wire change (the 31403 must carry the request's `d`) and
    /// needs its own ADR. When it lands, delete this test and replace it with
    /// one asserting the join.
    #[test]
    fn known_bug_kf37_kanban_decision_never_joins_the_request_case() {
        use super::super::nip_handlers::{plan_action_response, CASE_UPSERT_SQL};
        use super::super::receipts::test_support::governance_db;

        let requester = prf_signer(0x02);
        let admin = prf_signer(0x03);
        let card = KanbanCard {
            id: "c1".into(),
            pubkey: requester.public_key().to_string(),
            d_tag: "card1".into(),
            board: BOARD_COORD.into(),
            title: "Fix the gate".into(),
            description: String::new(),
            column: "doing".into(),
            rank: 0,
            assignees: vec![],
            due: None,
            zone: Some("family".into()),
            pending_move: None,
            deleted: false,
            created_at: 1,
        };
        use nostr_bbs_core::Signer;
        let request = block_on(nostr_bbs_core::create_card_approval_request_signer(
            &requester, &card, "done", "ready",
        ))
        .unwrap();
        assert!(nostr_bbs_core::is_kanban_approval_request(&request));

        // Project the 31402 with the case id `project_action_request` uses: the
        // request's own `d`. (The tier columns are fixed, not planned.)
        let request_d = nostr_bbs_core::governance::extract_d_tag(&request.tags)
            .unwrap()
            .to_string();
        let conn = governance_db();
        // The columns `ensure_schema` adds after the CREATE (`effective_tier`
        // is already there).
        for alter in [
            "ALTER TABLE broker_cases ADD COLUMN declared_tier TEXT",
            "ALTER TABLE broker_cases ADD COLUMN tp_verifiability TEXT",
            "ALTER TABLE broker_cases ADD COLUMN tp_reversibility TEXT",
            "ALTER TABLE broker_cases ADD COLUMN tp_stakes TEXT",
            "ALTER TABLE broker_cases ADD COLUMN calibration_sample INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE broker_cases ADD COLUMN probe_digest TEXT",
            "ALTER TABLE broker_cases ADD COLUMN max_pending_hours INTEGER",
            "ALTER TABLE broker_cases ADD COLUMN stale_after INTEGER",
        ] {
            conn.execute(alter, []).unwrap();
        }
        // The upsert's conflict guard reads `events`.
        conn.execute(crate::EVENTS_CREATE_SQL, []).unwrap();
        conn.execute(
            CASE_UPSERT_SQL,
            params![
                request_d,
                "manual_submission",
                "opaque",
                "",
                "Untitled",
                request.content,
                0,
                request.pubkey,
                request.id,
                request.created_at as i64,
                None::<String>,
                "medium",
                None::<String>,
                None::<String>,
                None::<String>,
                0,
                None::<String>,
                0,
                None::<i64>,
            ],
        )
        .unwrap();
        let open_cases = rows(
            &conn,
            "SELECT id FROM broker_cases WHERE state = 'open'",
            &[],
        );
        assert_eq!(open_cases, vec![request_d.clone()], "the 31402 projects");

        // The client-shaped 31403 cites the request but carries a random `d`.
        let response = block_on(nostr_bbs_core::create_card_approval_response_signer(
            &admin, &request, true,
        ))
        .unwrap();
        let corr = correlate(&response).expect("a 31403 with a d tag correlates");
        assert_eq!(
            corr.request_event_id.as_deref(),
            Some(request.id.as_str()),
            "the decision names the right request"
        );
        // BUG: the case id is the 31403's own random `d`, not the request's.
        assert_ne!(
            corr.case_id, request_d,
            "KF-37: decision does not join its case"
        );
        let joined = rows(
            &conn,
            "SELECT id FROM broker_cases WHERE id = ?1",
            &[&corr.case_id],
        );
        assert!(joined.is_empty(), "KF-37: no case row for the decision");

        // So the projection plans against no case and refuses.
        let err = plan_action_response(
            &corr.case_id,
            None,
            &response.id,
            &response.content,
            &response.pubkey,
            None,
            response.created_at,
        )
        .unwrap_err();
        assert!(
            format!("{err:?}").contains("request case has not projected"),
            "KF-37: {err:?}"
        );
        // And the request's case is still open, with no decision recorded.
        assert_eq!(
            rows(&conn, "SELECT decision_id FROM broker_decisions", &[]),
            Vec::<String>::new()
        );
    }
}
