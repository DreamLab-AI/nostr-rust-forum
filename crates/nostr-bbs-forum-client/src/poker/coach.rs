//! The practice table's coach: each time it is the member's turn, the table
//! DMs the coach agent (`[poker] coach_pubkey`) the decision in front of them
//! and shows the reply under the table.
//!
//! The transport is the forum's ordinary DM: a kind-14 rumor, gift-wrapped to
//! the coach and sent through the DM store over the primary relay. The agent
//! answers any member's DM, so nothing changes on its side. Both directions
//! carry a tag at the start of the text ([`REQUEST_TAG`], [`REPLY_TAG`]) so
//! the DM pages can leave the exchange out of the member's inbox
//! ([`is_coach_content`]).
//!
//! This module is the pure half: the prompt, built from the member's own
//! [`SeatView`] and never from the hand itself, so the bot's hole cards and the
//! deck cannot reach it; and the [`Ledger`] that pairs replies with requests.
//! The box on the page is [`crate::components::poker_coach`].

use std::collections::{HashSet, VecDeque};
use std::fmt::Write as _;

use nostr_bbs_poker::engine::{card_name, LogEntry, STREETS};

use super::{Legal, SeatView};
use crate::dm::DMMessage;

/// The first line of every request the table sends the coach.
pub const REQUEST_TAG: &str = "[poker-coach]";
/// What the coach is asked to start every reply with.
pub const REPLY_TAG: &str = "[coach]";
/// How long the member's turn must hold before the coach is asked, so a
/// state that flickers past is never sent.
pub const DEBOUNCE_MS: i32 = 300;
/// How long the box waits for a reply before saying none came.
pub const REPLY_TIMEOUT_MS: i32 = 30_000;
/// How long a request may wait for its reply, in seconds, before it stops
/// claiming one. Longer than [`REPLY_TIMEOUT_MS`] (the agent answers, or
/// apologises, within its own 25 s), so a slow reply still pairs with the
/// request that asked for it rather than with the next one.
pub const PENDING_TTL_SECS: u64 = 45;
/// How far a reply's timestamp may sit before its request's, in seconds: the
/// agent's clock and the member's need not agree to the second.
pub const CLOCK_SLACK_SECS: u64 = 5;

/// Whether a DM's text is one half of a coach exchange, and so belongs to the
/// table rather than the inbox.
pub fn is_coach_content(content: &str) -> bool {
    let t = content.trim_start();
    t.starts_with(REQUEST_TAG) || t.starts_with(REPLY_TAG)
}

/// The text to show for a reply: the tag taken off, line breaks kept.
pub fn reply_text(content: &str) -> String {
    let t = content.trim();
    t.strip_prefix(REPLY_TAG).unwrap_or(t).trim().to_string()
}

/// The decision the member faces, as a key that changes whenever the decision
/// does: the hand (its seed) and how far its log has run. `None` unless it is
/// the viewer's turn.
pub fn decision_key(
    view: &SeatView,
    legal: &Legal,
    seed_hex: &str,
    log_len: usize,
) -> Option<String> {
    hero_to_act(view, legal).then(|| format!("{seed_hex}:{log_len}"))
}

/// Whether the hand is live and the viewing seat is the one to act.
fn hero_to_act(view: &SeatView, legal: &Legal) -> bool {
    view.phase == "act" && view.to_act == view.seat as i32 && legal.seat == view.seat
}

fn cards(list: &[u8]) -> String {
    list.iter()
        .map(|&c| card_name(c))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The legal actions, priced: `fold`, `call 10`, `raise to 40`.
fn priced_actions(legal: &Legal) -> String {
    legal
        .actions
        .iter()
        .map(|a| match a.as_str() {
            "call" => format!("call {}", legal.call_amount),
            "bet" => format!("bet {}", legal.min_raise_to),
            "raise" => format!("raise to {}", legal.min_raise_to),
            other => other.to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// This hand's betting, a line per street, in the member's words ("me",
/// "opponent"). The log names seats and amounts only; it never carries hole
/// cards.
fn betting(log: &[LogEntry], hero: u32) -> String {
    let who = |seat: Option<u32>| if seat == Some(hero) { "me" } else { "opponent" };
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::from("Preflop:");
    let mut any = false;
    for e in log {
        let step = match e.ev.as_str() {
            "sb" => format!("{} small blind {}", who(e.seat), e.amount.unwrap_or(0)),
            "bb" => format!("{} big blind {}", who(e.seat), e.amount.unwrap_or(0)),
            "ante" => format!("{} ante {}", who(e.seat), e.amount.unwrap_or(0)),
            "fold" => format!("{} folds", who(e.seat)),
            "check" => format!("{} checks", who(e.seat)),
            "call" => format!("{} calls {}", who(e.seat), e.amount.unwrap_or(0)),
            "bet" => format!("{} bets {}", who(e.seat), e.to.unwrap_or(0)),
            "raise" => format!("{} raises to {}", who(e.seat), e.to.unwrap_or(0)),
            "street" => {
                lines.push(std::mem::take(&mut current));
                let name = e.street.as_deref().unwrap_or("next street");
                let mut head = capitalised(name);
                if let Some(b) = e.board.as_deref() {
                    let _ = write!(head, " ({})", cards(b));
                }
                current = format!("{head}:");
                any = false;
                continue;
            }
            _ => continue,
        };
        current.push_str(if any { ", " } else { " " });
        current.push_str(&step);
        any = true;
    }
    if !any {
        current.push_str(" no action yet");
    }
    lines.push(current);
    lines.join("\n")
}

fn capitalised(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// The request for the decision in front of the viewer, or `None` when it is
/// not their turn (so nothing is sent at a showdown or on the bot's turn).
///
/// Built from the viewer's [`SeatView`], its legal envelope and the hand log
/// only. The viewer's cards come from [`SeatView::hole`]; the other seats'
/// `hole` fields are never read, so a view that carries them (a showdown)
/// still cannot leak them. `limit_cap` is the engine's bets-per-street cap
/// (a bet and its raises).
pub fn build_prompt(
    view: &SeatView,
    legal: &Legal,
    log: &[LogEntry],
    limit_cap: u32,
) -> Option<String> {
    if !hero_to_act(view, legal) {
        return None;
    }
    let hero = view.seat;
    let me = view.seats.get(hero as usize)?;
    let opp = view
        .seats
        .iter()
        .enumerate()
        .find(|(i, s)| *i != hero as usize && !s.out)
        .map(|(_, s)| s)?;
    let (sb, bb) = (view.sb, view.bb);
    let big = bb.saturating_mul(2);
    let raises = limit_cap.saturating_sub(1);

    let mut p = String::new();
    let _ = writeln!(p, "{REQUEST_TAG}");
    let _ = writeln!(
        p,
        "I am a beginner playing practice chips (worth nothing) against a bot. The game is heads-up \
         fixed-limit Texas hold'em: two players; the button posts the small blind ({sb}) and the \
         other player the big blind ({bb}). Each player has two private hole cards, and five shared \
         board cards come in three streets: the flop (three cards), the turn (one) and the river \
         (one). Bets are fixed: on the preflop and flop every bet or raise is the small bet ({bb}); \
         on the turn and river it is the big bet ({big}). A street allows at most {limit_cap} bets \
         (a bet and {raises} raises; preflop the big blind counts as the first). The button acts \
         first preflop and last on every later street. At a showdown the best five-card hand from \
         your two cards and the board wins the pot."
    );
    let _ = writeln!(p);
    let _ = writeln!(p, "Stakes: {sb}/{bb} (small bet {bb}, big bet {big}).");
    let _ = writeln!(
        p,
        "My stack: {}. Opponent's stack: {}.",
        me.stack, opp.stack
    );
    let _ = writeln!(
        p,
        "Button: {}.",
        if view.button == hero {
            "me (I posted the small blind)"
        } else {
            "the opponent (I posted the big blind)"
        }
    );
    let street = STREETS
        .iter()
        .find(|s| **s == view.street)
        .copied()
        .unwrap_or(view.street.as_str());
    let _ = writeln!(p, "Street: {street}.");
    let hole = view.hole.as_deref().unwrap_or_default();
    let _ = writeln!(
        p,
        "My hole cards: {}.",
        if hole.is_empty() {
            "unknown".into()
        } else {
            cards(hole)
        }
    );
    let _ = writeln!(
        p,
        "Board: {}.",
        if view.board.is_empty() {
            "none yet".to_string()
        } else {
            cards(&view.board)
        }
    );
    let _ = writeln!(p, "Pot: {}.", view.pot);
    let _ = writeln!(p, "To call: {}.", legal.call_amount);
    let _ = writeln!(p, "Legal actions: {}.", priced_actions(legal));
    let _ = writeln!(p, "Betting so far this hand:");
    let _ = writeln!(p, "{}", betting(log, hero));
    let _ = writeln!(p);
    let _ = write!(
        p,
        "Give detail. Reply in under 600 characters, plain text, starting with {REPLY_TAG}. \
         1) Recommended action (one of the legal actions). 2) Why, in one or two sentences a \
         beginner can follow. 3) One short general tip."
    );
    Some(p)
}

/// A request the coach has not answered yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// The table's request id, one per decision asked about.
    pub id: u64,
    /// The decision it asked about ([`decision_key`]).
    pub decision: String,
    /// When it was sent, in Unix seconds.
    pub sent_at: u64,
}

/// Pairs the coach's replies with the requests that asked for them.
///
/// The agent answers each DM in turn and its replies name nothing, so replies
/// are paired first in, first out: each new message from the coach answers
/// the oldest request still waiting. A slow reply to an earlier decision
/// therefore lands on that decision (and is dropped as stale) instead of
/// being shown as advice for the next one.
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    pending: VecDeque<Pending>,
    seen: HashSet<String>,
}

impl Ledger {
    /// Record a request just sent.
    pub fn sent(&mut self, id: u64, decision: String, sent_at: u64) {
        self.pending.push_back(Pending {
            id,
            decision,
            sent_at,
        });
    }

    /// Take in the store's messages, `now` in Unix seconds, and return each
    /// newly answered request with its reply text. Messages already seen,
    /// messages the member sent, messages from anyone but `coach`, and
    /// messages older than the oldest waiting request are passed over (the
    /// DM subscription replays two days of history). Requests that have
    /// waited past [`PENDING_TTL_SECS`] stop waiting first.
    pub fn absorb(
        &mut self,
        coach: &str,
        messages: &[DMMessage],
        now: u64,
    ) -> Vec<(Pending, String)> {
        self.pending
            .retain(|p| now.saturating_sub(p.sent_at) <= PENDING_TTL_SECS);
        let mut fresh: Vec<&DMMessage> = messages
            .iter()
            .filter(|m| !m.is_sent && m.sender_pubkey.eq_ignore_ascii_case(coach))
            .filter(|m| !self.seen.contains(&m.id))
            .collect();
        fresh.sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then_with(|| a.id.cmp(&b.id)));
        let mut answered = Vec::new();
        for m in fresh {
            self.seen.insert(m.id.clone());
            let Some(oldest) = self.pending.front() else {
                continue;
            };
            if m.timestamp.saturating_add(CLOCK_SLACK_SECS) < oldest.sent_at {
                continue;
            }
            if let Some(p) = self.pending.pop_front() {
                answered.push((p, reply_text(&m.content)));
            }
        }
        answered
    }
}

/// The reply to show, if any: an answered request's text when it is the
/// current request and its decision is still the one in front of the member.
/// A reply to a decision already taken (the next street, the hand over) is
/// dropped.
pub fn reply_for_current(
    answered: &[(Pending, String)],
    current_request: u64,
    current_decision: Option<&str>,
) -> Option<String> {
    answered
        .iter()
        .find(|(p, _)| p.id == current_request && Some(p.decision.as_str()) == current_decision)
        .map(|(_, text)| text.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_bbs_poker::engine::{card_of_code, ViewSeat};

    fn c(code: &str) -> u8 {
        card_of_code(code).unwrap()
    }

    fn seat(name: &str, stack: u64, hole: Option<Vec<u8>>) -> ViewSeat {
        ViewSeat {
            name: name.into(),
            stack,
            folded: false,
            all_in: false,
            out: false,
            street_commit: 0,
            hand_commit: 0,
            hole,
        }
    }

    /// The member (seat 0) on the button, to act on the flop facing a bet.
    fn flop_view(villain_hole: Option<Vec<u8>>) -> (SeatView, Legal, Vec<LogEntry>) {
        let board = vec![c("Ah"), c("7d"), c("2c")];
        let view = SeatView {
            seat: 0,
            street: "flop".into(),
            board: board.clone(),
            phase: "act".into(),
            to_act: 0,
            current_bet: 10,
            min_raise_to: Some(20),
            button: 0,
            sb: 5,
            bb: 10,
            hole: Some(vec![c("As"), c("Kh")]),
            pot: 30,
            seats: vec![
                seat("You", 980, Some(vec![c("As"), c("Kh")])),
                seat("Bot", 970, villain_hole),
            ],
            result: None,
        };
        let legal = Legal {
            seat: 0,
            actions: vec!["fold".into(), "call".into(), "raise".into()],
            call_amount: 10,
            min_raise_to: 20,
            max_raise_to: 20,
            current_bet: 10,
        };
        let log = vec![
            LogEntry {
                seat: Some(0),
                amount: Some(5),
                ..ev("sb")
            },
            LogEntry {
                seat: Some(1),
                amount: Some(10),
                ..ev("bb")
            },
            LogEntry {
                sb: Some(0),
                bb: Some(1),
                ..ev("deal")
            },
            LogEntry {
                seat: Some(0),
                amount: Some(5),
                ..ev("call")
            },
            LogEntry {
                seat: Some(1),
                ..ev("check")
            },
            LogEntry {
                street: Some("flop".into()),
                board: Some(board),
                ..ev("street")
            },
            LogEntry {
                seat: Some(1),
                to: Some(10),
                ..ev("bet")
            },
        ];
        (view, legal, log)
    }

    fn ev(name: &str) -> LogEntry {
        LogEntry {
            ev: name.into(),
            ..LogEntry::default()
        }
    }

    #[test]
    fn prompt_carries_the_decision() {
        let (view, legal, log) = flop_view(None);
        let p = build_prompt(&view, &legal, &log, 4).unwrap();
        assert!(p.starts_with("[poker-coach]\n"), "{p}");
        for want in [
            "heads-up fixed-limit Texas hold'em",
            "at most 4 bets (a bet and 3 raises",
            "Stakes: 5/10 (small bet 10, big bet 20).",
            "My stack: 980. Opponent's stack: 970.",
            "Button: me (I posted the small blind).",
            "Street: flop.",
            "My hole cards: A♠ K♥.",
            "Board: A♥ 7♦ 2♣.",
            "Pot: 30.",
            "To call: 10.",
            "Preflop: me small blind 5, opponent big blind 10, me calls 5, opponent checks",
            "Flop (A♥ 7♦ 2♣): opponent bets 10",
            "starting with [coach]",
            "under 600 characters",
        ] {
            assert!(p.contains(want), "missing {want:?} in\n{p}");
        }
    }

    #[test]
    fn prompt_lists_exactly_the_legal_actions_priced() {
        let (view, mut legal, log) = flop_view(None);
        let p = build_prompt(&view, &legal, &log, 4).unwrap();
        assert!(
            p.contains("Legal actions: fold, call 10, raise to 20."),
            "{p}"
        );

        // capped street: no raise offered, none mentioned
        legal.actions = vec!["fold".into(), "call".into()];
        let p = build_prompt(&view, &legal, &log, 4).unwrap();
        assert!(p.contains("Legal actions: fold, call 10."), "{p}");
        assert!(!p.contains("raise to 20"), "{p}");

        // nothing to call: check or bet
        legal.actions = vec!["fold".into(), "check".into(), "bet".into()];
        legal.call_amount = 0;
        legal.min_raise_to = 10;
        let p = build_prompt(&view, &legal, &log, 4).unwrap();
        assert!(p.contains("Legal actions: fold, check, bet 10."), "{p}");
    }

    #[test]
    fn prompt_never_carries_the_villains_hole_cards() {
        // the view carries the bot's cards (as one does at a showdown)
        let villain = vec![c("Qd"), c("Jc")];
        let (view, legal, log) = flop_view(Some(villain.clone()));
        let p = build_prompt(&view, &legal, &log, 4).unwrap();
        for card in &villain {
            assert!(
                !p.contains(&card_name(*card)),
                "leaked {} in\n{p}",
                card_name(*card)
            );
        }

        // and at the showdown itself nothing is built, so nothing is sent
        let mut done = view.clone();
        done.phase = "done".into();
        done.to_act = -1;
        assert!(build_prompt(&done, &legal, &log, 4).is_none());
    }

    #[test]
    fn nothing_is_built_off_the_heros_turn() {
        let (mut view, mut legal, log) = flop_view(None);
        view.to_act = 1;
        legal.seat = 1;
        assert!(build_prompt(&view, &legal, &log, 4).is_none());
        assert!(decision_key(&view, &legal, "ab", 7).is_none());
    }

    #[test]
    fn decision_key_moves_with_the_log() {
        let (view, legal, _) = flop_view(None);
        let a = decision_key(&view, &legal, "seed", 7).unwrap();
        let b = decision_key(&view, &legal, "seed", 9).unwrap();
        assert_ne!(a, b);
        assert_eq!(Some(a), decision_key(&view, &legal, "seed", 7));
    }

    #[test]
    fn coach_content_is_recognised_by_its_tag() {
        assert!(is_coach_content("[poker-coach]\nI am a beginner"));
        assert!(is_coach_content("  [coach] Call: you have top pair."));
        assert!(!is_coach_content("hello [coach]"));
        assert!(!is_coach_content("Coach me later?"));
        assert_eq!(
            reply_text("[coach] Call.\nTip: position."),
            "Call.\nTip: position."
        );
        assert_eq!(
            reply_text("Sorry, I could not answer."),
            "Sorry, I could not answer."
        );
    }

    const COACH: &str = "2de44d5622eef79519ac078f6e227a85aecbaefd561e4e50c5f51dfadbf916e9";

    fn msg(id: &str, from: &str, ts: u64, text: &str) -> DMMessage {
        DMMessage {
            id: id.into(),
            sender_pubkey: from.into(),
            recipient_pubkey: "me".into(),
            content: text.into(),
            timestamp: ts,
            is_sent: false,
            is_read: false,
        }
    }

    #[test]
    fn replies_older_than_the_request_are_ignored() {
        let mut l = Ledger::default();
        l.sent(1, "s:7".into(), 1_000);
        // history streamed in by the two-day lookback
        let old = [msg("h", COACH, 900, "[coach] Fold.")];
        assert!(l.absorb(COACH, &old, 1_001).is_empty());
        assert_eq!(l.pending.len(), 1);
        // the real reply
        let mut all = old.to_vec();
        all.push(msg("r", COACH, 1_004, "[coach] Raise."));
        let got = l.absorb(COACH, &all, 1_005);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.id, 1);
        assert_eq!(got[0].1, "Raise.");
        // seen once only
        assert!(l.absorb(COACH, &all, 1_006).is_empty());
    }

    #[test]
    fn replies_from_other_senders_and_our_own_are_ignored() {
        let mut l = Ledger::default();
        l.sent(1, "s:7".into(), 1_000);
        let mut mine = msg("m", "me", 1_001, "[poker-coach]\n…");
        mine.is_sent = true;
        let other = msg("o", &"ab".repeat(32), 1_002, "[coach] Fold, trust me.");
        assert!(l.absorb(COACH, &[mine, other], 1_003).is_empty());
        assert_eq!(l.pending.len(), 1);
        // the coach key matches case-insensitively
        let upper = msg("u", &COACH.to_ascii_uppercase(), 1_004, "[coach] Call.");
        assert_eq!(l.absorb(COACH, &[upper], 1_005).len(), 1);
    }

    #[test]
    fn a_reply_to_a_decision_already_taken_is_dropped() {
        let mut l = Ledger::default();
        l.sent(1, "s:7".into(), 1_000); // flop decision
        l.sent(2, "s:11".into(), 1_002); // the member acted; turn decision asked
                                         // the flop's slow reply arrives first, then the turn's
        let first = [msg("a", COACH, 1_003, "[coach] Call the flop.")];
        let got = l.absorb(COACH, &first, 1_003);
        assert_eq!(got[0].0.id, 1, "the first reply answers the first request");
        assert_eq!(reply_for_current(&got, 2, Some("s:11")), None);

        let mut both = first.to_vec();
        both.push(msg("b", COACH, 1_006, "[coach] Bet the turn."));
        let got = l.absorb(COACH, &both, 1_006);
        assert_eq!(
            reply_for_current(&got, 2, Some("s:11")).as_deref(),
            Some("Bet the turn.")
        );
        // and once the decision moves on (hand over), it is dropped too
        assert_eq!(reply_for_current(&got, 2, None), None);
        assert_eq!(reply_for_current(&got, 2, Some("s:13")), None);
    }

    #[test]
    fn an_unanswered_request_stops_waiting() {
        let mut l = Ledger::default();
        l.sent(1, "s:7".into(), 1_000);
        l.sent(2, "s:9".into(), 1_100);
        let r = [msg("r", COACH, 1_101, "[coach] Check.")];
        let got = l.absorb(COACH, &r, 1_101);
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].0.id, 2,
            "the expired request no longer claims a reply"
        );
    }
}
