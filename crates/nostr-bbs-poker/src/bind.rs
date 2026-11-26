//! Binding a hand's payment to the replay that was verified.
//!
//! The house's `Done` message carries a settlement (who pays, how much), a
//! root, a buy-in and an opponent. A member's wallet signs a real transfer
//! on the strength of them, so none may be taken on the house's word: each
//! is checked against the hand [`verify`](crate::verify::verify) replayed
//! from the revealed secret, and the amount and the payee returned are
//! derived from that replay, not copied from the message.

use crate::engine::Hand;
use serde::{Deserialize, Serialize};

use crate::rules::{self, HandRecord, Settlement, Side, Variant};

/// What the member agreed to when they sat or answered a challenge, kept
/// by commitment on their side. The house's record is checked against
/// this, never against its own numbers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Agreed {
    /// Whether the hand is against the house bot (reached by `Sit`) or
    /// against a member (reached by `Challenge` or `Accept`).
    pub house: bool,
    /// The other player: the pinned citizen for a house hand, the member
    /// challenged or the challenger accepted otherwise.
    pub opponent: String,
    /// The big blind of the table chosen.
    pub bb: u64,
    /// The small blind of that table.
    pub sb: u64,
    /// The buy-in of that table, base units.
    pub buyin: u64,
}

/// What the house's `Done` message claims about a hand, from one member's
/// seat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reported<'a> {
    /// The member's seat, as the message names it.
    pub seat: u32,
    /// The other player's pubkey, as the message names it.
    pub opponent: &'a str,
    /// Whether the other player is the house bot.
    pub house: bool,
    /// The buy-in, base units.
    pub buyin: u64,
    /// The record's root, which the payment's memo carries.
    pub root: &'a str,
    /// The settlement, from this member's side: [`Side::Hero`] pays.
    pub settlement: Option<Settlement>,
}

/// What a member may pay, derived from the replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    /// The record's root, for the `hand:<root>` memo.
    pub root: String,
    /// The buy-in both seats sat with.
    pub buyin: u64,
    /// What the hand settles, from this member's side.
    pub settlement: Option<Settlement>,
    /// The pubkey to pay, when the member owes: the opponent.
    pub payee: Option<String>,
}

/// Why a payment does not match the verified hand.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BindError {
    /// The hand does not have two seats, or the seat is not one of them.
    #[error("the hand does not seat two players with a seat {0}")]
    Seats(u32),
    /// The record does not seat this member where the message says.
    #[error("the record does not seat you in seat {0}")]
    NotMe(u32),
    /// The record's other seat, or the message's opponent, is not who was
    /// agreed to play.
    #[error("the opponent is not the one agreed to")]
    Opponent,
    /// The hand is against the house, or is not, against what was agreed.
    #[error("the hand is not the kind (house or member) agreed to")]
    HouseClaim,
    /// The variant, blinds or ante are not the table's.
    #[error("the variant or blinds are not those of the table chosen")]
    Stakes,
    /// The root the message names is not the record's.
    #[error("the root named is not the record's root")]
    Root,
    /// The buy-in named is not what both seats sat with.
    #[error("the buy-in is not the one agreed to")]
    Buyin,
    /// The hand's stacks cannot be settled.
    #[error("the replayed hand cannot be settled: {0}")]
    Unsettleable(String),
    /// The settlement named is not the one the replay gives.
    #[error("the settlement named does not match the replay (the replay gives {expected})")]
    Settlement {
        /// What the replay gives, in words.
        expected: String,
    },
}

fn describe(s: &Option<Settlement>) -> String {
    match s {
        None => "nothing moves".to_string(),
        Some(Settlement {
            from: Side::Hero,
            amount,
            ..
        }) => format!("you pay {amount}"),
        Some(Settlement { amount, .. }) => format!("you are paid {amount}"),
    }
}

/// Check what the house reported against what the member agreed to and the
/// verified `replayed` hand and its `record`, and derive the payment from
/// them.
///
/// `me` is this member's pubkey and `citizen` the house's, as pinned by the
/// forum's configuration rather than by the message. `agreed` is what the
/// member chose when they sat or answered a challenge. The record's seat
/// names are not covered by the replay, so the opponent, the kind of hand,
/// the blinds and the buy-in are all held to `agreed`: a house that names
/// another payee, inflates a stack or changes the table is refused.
///
/// # Errors
///
/// A [`BindError`] naming the first claim that does not hold; the member
/// pays nothing then.
pub fn bind_settlement(
    replayed: &Hand,
    record: &HandRecord,
    me: &str,
    citizen: &str,
    agreed: &Agreed,
    reported: &Reported<'_>,
) -> Result<Bound, BindError> {
    let seat = reported.seat as usize;
    if seat > 1 || record.seats.len() != 2 || replayed.seats.len() != 2 {
        return Err(BindError::Seats(reported.seat));
    }
    if record.seats[seat].name != me {
        return Err(BindError::NotMe(reported.seat));
    }
    if reported.house != agreed.house {
        return Err(BindError::HouseClaim);
    }
    // a house hand is against the pinned citizen; a member's never is, and
    // never against oneself
    if agreed.house != (agreed.opponent == citizen) || agreed.opponent == me {
        return Err(BindError::HouseClaim);
    }
    if reported.opponent != agreed.opponent || record.seats[1 - seat].name != agreed.opponent {
        return Err(BindError::Opponent);
    }
    match record.root() {
        Ok(r) if r == reported.root => {}
        _ => return Err(BindError::Root),
    }
    // the tables deal fixed-limit; another variant is not what was offered
    if record.variant != Variant::HoldemLimit
        || record.bb != agreed.bb
        || record.sb != agreed.sb
        || record.ante != 0
    {
        return Err(BindError::Stakes);
    }
    let buyin = agreed.buyin;
    if record.seats.iter().any(|s| s.start_stack != buyin) || reported.buyin != buyin {
        return Err(BindError::Buyin);
    }
    let expected = rules::settlement(!replayed.in_play(), replayed.seats[seat].stack, buyin)
        .map_err(|e| BindError::Unsettleable(e.to_string()))?;
    if reported.settlement != expected {
        return Err(BindError::Settlement {
            expected: describe(&expected),
        });
    }
    let payee = matches!(
        expected,
        Some(Settlement {
            from: Side::Hero,
            ..
        })
    )
    .then(|| agreed.opponent.clone());
    Ok(Bound {
        root: reported.root.to_string(),
        buyin,
        settlement: expected,
        payee,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{self, Action, HandConfig, SeatConfig};
    use crate::record::record_of;

    const ME: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HOUSE: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const ATTACKER: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    /// A hand of `stack` each in which `loser` folds on their first turn.
    fn hand_lost_by(loser: u32) -> (Hand, HandRecord) {
        hand_of(loser, 2_000, [ME, HOUSE], 10, 20)
    }

    fn hand_of(loser: u32, stack: u64, names: [&str; 2], sb: u64, bb: u64) -> (Hand, HandRecord) {
        let cfg = HandConfig {
            seats: names
                .iter()
                .map(|n| SeatConfig {
                    name: n.to_string(),
                    stack,
                })
                .collect(),
            button: 0,
            sb,
            bb,
            ante: 0,
            seed_hex: "ab".repeat(32),
            limit: true,
        };
        let mut h = engine::new_hand(&cfg).unwrap();
        while h.in_play() {
            let seat = h.to_act as u32;
            let l = engine::legal(&h).unwrap();
            let action = if seat == loser {
                "fold"
            } else if l.allows("check") {
                "check"
            } else {
                "call"
            };
            h = engine::act(
                &h,
                &Action {
                    seat,
                    action: action.into(),
                    amount: None,
                },
            )
            .unwrap();
        }
        let names = [names[0].to_string(), names[1].to_string()];
        let rec = record_of(&h, Some(&names)).unwrap();
        (h, rec)
    }

    fn house_hand() -> Agreed {
        Agreed {
            house: true,
            opponent: HOUSE.into(),
            bb: 20,
            sb: 10,
            buyin: 2_000,
        }
    }

    fn honest<'a>(h: &Hand, root: &'a str) -> Reported<'a> {
        Reported {
            seat: 0,
            opponent: HOUSE,
            house: true,
            buyin: 2_000,
            root,
            settlement: rules::settlement(true, h.seats[0].stack, 2_000).unwrap(),
        }
    }

    #[test]
    fn an_honest_report_binds_and_names_the_opponent_as_payee_when_we_owe() {
        let (h, rec) = hand_lost_by(0);
        let root = rec.root().unwrap();
        let b = bind_settlement(&h, &rec, ME, HOUSE, &house_hand(), &honest(&h, &root)).unwrap();
        let s = b.settlement.expect("the folder pays");
        assert_eq!(s.from, Side::Hero);
        assert!(s.amount > 0 && s.amount <= 2_000);
        assert_eq!(b.payee.as_deref(), Some(HOUSE));
        assert_eq!(b.root, root);
        // the winner pays nobody
        let (h, rec) = hand_lost_by(1);
        let root = rec.root().unwrap();
        let b = bind_settlement(&h, &rec, ME, HOUSE, &house_hand(), &honest(&h, &root)).unwrap();
        assert_eq!(b.payee, None);
        assert_eq!(b.settlement.unwrap().from, Side::Citizen);
    }

    #[test]
    fn a_tampered_amount_is_refused() {
        let (h, rec) = hand_lost_by(0);
        let root = rec.root().unwrap();
        let ag = house_hand();
        for delta in [-1i64, 1, 1_000] {
            let mut r = honest(&h, &root);
            let s = r.settlement.as_mut().unwrap();
            s.amount = s.amount.checked_add_signed(delta).unwrap();
            assert!(
                matches!(
                    bind_settlement(&h, &rec, ME, HOUSE, &ag, &r),
                    Err(BindError::Settlement { .. })
                ),
                "amount off by {delta}"
            );
        }
        let mut r = honest(&h, &root);
        r.settlement = None;
        assert!(bind_settlement(&h, &rec, ME, HOUSE, &ag, &r).is_err());
        let mut r = honest(&h, &root);
        r.settlement.as_mut().unwrap().from = Side::Citizen;
        assert!(bind_settlement(&h, &rec, ME, HOUSE, &ag, &r).is_err());
    }

    #[test]
    fn a_tampered_destination_is_refused() {
        let (h, rec) = hand_lost_by(0);
        let root = rec.root().unwrap();
        let ag = house_hand();
        let mut r = honest(&h, &root);
        r.opponent = ATTACKER;
        assert_eq!(
            bind_settlement(&h, &rec, ME, HOUSE, &ag, &r),
            Err(BindError::Opponent)
        );
        // the record itself seats the attacker, and the message agrees
        let (h2, forged) = hand_of(0, 2_000, [ME, ATTACKER], 10, 20);
        let froot = forged.root().unwrap();
        let mut r = honest(&h2, &froot);
        r.opponent = ATTACKER;
        assert_eq!(
            bind_settlement(&h2, &forged, ME, HOUSE, &ag, &r),
            Err(BindError::Opponent)
        );
        // someone else's pubkey pinned as the citizen
        assert_eq!(
            bind_settlement(&h, &rec, ME, ATTACKER, &ag, &honest(&h, &root)),
            Err(BindError::HouseClaim)
        );
    }

    #[test]
    fn a_member_hand_cannot_be_turned_into_a_payee_the_member_did_not_agree_to() {
        // the member challenged FRIEND; the house's record seats the
        // attacker in that seat, and its message says so
        let friend = "f".repeat(64);
        let ag = Agreed {
            house: false,
            opponent: friend.clone(),
            ..house_hand()
        };
        let (h, forged) = hand_of(0, 2_000, [ME, ATTACKER], 10, 20);
        let root = forged.root().unwrap();
        let mut r = honest(&h, &root);
        r.opponent = ATTACKER;
        r.house = false;
        assert_eq!(
            bind_settlement(&h, &forged, ME, HOUSE, &ag, &r),
            Err(BindError::Opponent)
        );
        // the honest record against the friend binds, and pays the friend
        let (h, rec) = hand_of(0, 2_000, [ME, &friend], 10, 20);
        let root = rec.root().unwrap();
        let mut r = honest(&h, &root);
        r.opponent = &friend;
        r.house = false;
        let b = bind_settlement(&h, &rec, ME, HOUSE, &ag, &r).unwrap();
        assert_eq!(b.payee.as_deref(), Some(friend.as_str()));
    }

    #[test]
    fn a_house_hand_reported_as_a_member_hand_and_back_is_refused() {
        let (h, rec) = hand_lost_by(0);
        let root = rec.root().unwrap();
        // sat against the house (sit), reported as a member hand
        let mut r = honest(&h, &root);
        r.house = false;
        assert_eq!(
            bind_settlement(&h, &rec, ME, HOUSE, &house_hand(), &r),
            Err(BindError::HouseClaim)
        );
        // challenged a member, reported as the house's hand
        let ag = Agreed {
            house: false,
            opponent: "f".repeat(64),
            ..house_hand()
        };
        assert_eq!(
            bind_settlement(&h, &rec, ME, HOUSE, &ag, &honest(&h, &root)),
            Err(BindError::HouseClaim)
        );
        // a member hand against the house's own key is never one
        let ag = Agreed {
            house: false,
            opponent: HOUSE.into(),
            ..house_hand()
        };
        let mut r = honest(&h, &root);
        r.house = false;
        assert_eq!(
            bind_settlement(&h, &rec, ME, HOUSE, &ag, &r),
            Err(BindError::HouseClaim)
        );
    }

    #[test]
    fn an_inflated_stack_or_changed_blinds_are_refused() {
        // the member chose a 2 000 buy-in at 10/20; the house dealt 4 000
        let (h, rec) = hand_of(0, 4_000, [ME, HOUSE], 10, 20);
        let root = rec.root().unwrap();
        let mut r = honest(&h, &root);
        r.buyin = 4_000;
        r.settlement = rules::settlement(true, h.seats[0].stack, 4_000).unwrap();
        assert_eq!(
            bind_settlement(&h, &rec, ME, HOUSE, &house_hand(), &r),
            Err(BindError::Buyin)
        );
        // stacks unequal in the record
        let (h, mut rec) = hand_lost_by(0);
        rec.seats[1].start_stack = 2_500;
        let root = rec.root().unwrap();
        assert_eq!(
            bind_settlement(&h, &rec, ME, HOUSE, &house_hand(), &honest(&h, &root)),
            Err(BindError::Buyin)
        );
        // another variant: a no-limit record of a limit table
        let (h, mut rec) = hand_lost_by(0);
        rec.variant = Variant::HoldemNoLimit;
        let root = rec.root().unwrap();
        assert_eq!(
            bind_settlement(&h, &rec, ME, HOUSE, &house_hand(), &honest(&h, &root)),
            Err(BindError::Stakes)
        );
        // other blinds
        let (h, rec) = hand_of(0, 2_000, [ME, HOUSE], 100, 200);
        let root = rec.root().unwrap();
        assert_eq!(
            bind_settlement(&h, &rec, ME, HOUSE, &house_hand(), &honest(&h, &root)),
            Err(BindError::Stakes)
        );
    }

    #[test]
    fn a_wrong_seat_root_or_buyin_is_refused() {
        let (h, rec) = hand_lost_by(0);
        let root = rec.root().unwrap();
        let ag = house_hand();
        let mut r = honest(&h, &root);
        r.seat = 1;
        assert_eq!(
            bind_settlement(&h, &rec, ME, HOUSE, &ag, &r),
            Err(BindError::NotMe(1))
        );
        r.seat = 2;
        assert_eq!(
            bind_settlement(&h, &rec, ME, HOUSE, &ag, &r),
            Err(BindError::Seats(2))
        );
        let other = "0".repeat(64);
        let mut r = honest(&h, &root);
        r.root = &other;
        assert_eq!(
            bind_settlement(&h, &rec, ME, HOUSE, &ag, &r),
            Err(BindError::Root)
        );
        let mut r = honest(&h, &root);
        r.buyin = 1_000;
        assert_eq!(
            bind_settlement(&h, &rec, ME, HOUSE, &ag, &r),
            Err(BindError::Buyin)
        );
        // a hand that is still being played settles nothing
        let mut live = h.clone();
        live.phase = "act".into();
        assert!(matches!(
            bind_settlement(&live, &rec, ME, HOUSE, &ag, &honest(&h, &root)),
            Err(BindError::Unsettleable(_))
        ));
        assert_eq!(
            bind_settlement(&h, &rec, ATTACKER, HOUSE, &ag, &honest(&h, &root)),
            Err(BindError::NotMe(0))
        );
    }
}
