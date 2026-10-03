//! From an engine hand to a Libre Poker `Hand` record (HAND.md v0), the
//! document a settlement's `hand:<root>` memo commits to.
//!
//! The record carries what a verifier needs and nothing the engine keeps for
//! itself: the seed, every seat's start stack and hole cards, the board, the
//! action log with street markers, and the result. Hole cards are written as
//! HAND.md names (`Kd`), not the engine's glyphs. The engine's bookkeeping
//! entries (blinds, refunds, run-outs, wins) are not actions and are left
//! out; a verifier re-derives them by replay.

use crate::engine::{card_code, Hand};
use crate::rules::{Act, HandAction, HandRecord, HandResult, HandSeat, Street, Variant, Winner};

/// The JSON-LD context HAND.md names.
pub const CONTEXT: &str = "https://librepoker.org/context.jsonld";

/// The record of a finished hand, or `None` while it is still in play.
///
/// `names` replaces the engine's seat names (the house seat may be dealt
/// under a character's name but recorded under the member's and the
/// citizen's identities); `None` keeps the engine's.
pub fn record_of(h: &Hand, names: Option<&[String]>) -> Option<HandRecord> {
    let result = h.result.as_ref()?;
    let seats = h
        .seats
        .iter()
        .enumerate()
        .map(|(i, s)| HandSeat {
            name: names
                .and_then(|n| n.get(i).cloned())
                .unwrap_or_else(|| s.name.clone()),
            start_stack: s.start_stack,
            hole: s
                .hole
                .as_ref()
                .map(|cards| cards.iter().map(|&c| card_code(c)).collect()),
            agent: None,
        })
        .collect();
    let mut actions = Vec::new();
    for e in &h.log {
        match e.ev.as_str() {
            "fold" | "check" | "call" | "bet" | "raise" => {
                let act = match e.ev.as_str() {
                    "fold" => Act::Fold,
                    "check" => Act::Check,
                    "call" => Act::Call,
                    "bet" => Act::Bet,
                    _ => Act::Raise,
                };
                actions.push(HandAction::Act {
                    seat: e.seat.unwrap_or(0),
                    act,
                    to: e.to,
                    amount: e.amount,
                });
            }
            "street" => {
                let street = match e.street.as_deref() {
                    Some("flop") => Street::Flop,
                    Some("turn") => Street::Turn,
                    Some("river") => Street::River,
                    _ => continue,
                };
                actions.push(HandAction::Street { street });
            }
            _ => {}
        }
    }
    Some(HandRecord {
        context: Some(CONTEXT.to_string()),
        kind: "Hand".to_string(),
        v: 0,
        variant: if h.limit {
            Variant::HoldemLimit
        } else {
            Variant::HoldemNoLimit
        },
        seed: h.seed_hex.clone(),
        sb: h.sb,
        bb: h.bb,
        ante: h.ante,
        button: h.button,
        seats,
        board: h.board.iter().map(|&c| card_code(c)).collect(),
        actions,
        result: HandResult {
            showdown: result.showdown,
            pot: result.pots.iter().map(|p| p.amount).sum(),
            winners: result
                .winners
                .iter()
                .map(|w| Winner {
                    seat: w.seat,
                    amount: w.amount,
                })
                .collect(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{act, new_hand, Action, HandConfig, SeatConfig};

    fn play_fold() -> Hand {
        let h = new_hand(&HandConfig {
            seats: vec![
                SeatConfig {
                    name: "You".into(),
                    stack: 2000,
                },
                SeatConfig {
                    name: "First Mate Wren".into(),
                    stack: 2000,
                },
            ],
            button: 0,
            sb: 10,
            bb: 20,
            ante: 0,
            seed_hex: "9b".repeat(32),
            limit: true,
        })
        .unwrap();
        act(
            &h,
            &Action {
                seat: 0,
                action: "fold".into(),
                amount: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn no_record_while_in_play() {
        let mut h = play_fold();
        h.phase = "act".into();
        h.result = None;
        assert!(record_of(&h, None).is_none());
    }

    #[test]
    fn a_folded_hand_records_the_fold_and_the_pot() {
        let h = play_fold();
        let names = ["hero".to_string(), "citizen".to_string()];
        let r = record_of(&h, Some(&names)).unwrap();
        assert_eq!(r.kind, "Hand");
        assert_eq!(r.variant, Variant::HoldemLimit);
        assert_eq!(r.seats[0].name, "hero");
        assert_eq!(r.seats[1].name, "citizen");
        assert_eq!(r.seats[0].start_stack, 2000);
        assert_eq!(r.seats[0].hole.as_ref().unwrap().len(), 2);
        assert!(r.seats[0].hole.as_ref().unwrap()[0]
            .chars()
            .nth(1)
            .is_some_and(|s| "cdhs".contains(s)));
        assert_eq!(
            r.actions,
            [HandAction::Act {
                seat: 0,
                act: Act::Fold,
                to: None,
                amount: None
            }]
        );
        assert!(!r.result.showdown);
        assert_eq!(r.result.pot, 20);
        assert_eq!(
            r.result.winners,
            [Winner {
                seat: 1,
                amount: 20
            }]
        );
        // the root is stable and the record round-trips through JSON
        let json = serde_json::to_string(&r).unwrap();
        let back: HandRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.root().unwrap(), r.root().unwrap());
        assert_eq!(crate::rules::hand_root(&json).unwrap(), r.root().unwrap());
    }
}
