//! Replay verification: did the house deal what it committed to and play by
//! the book?
//!
//! Given what a hand's [`Done`](crate::protocol::ToHero::Done) message
//! carries, a verifier checks, in order, that the revealed secret matches
//! the commitment shown before the deal, that the seed is the one both
//! contributions fix, that dealing from that seed with the recorded seats
//! and applying the recorded actions reproduces the record's hole cards,
//! board and result, and that every action by the house seat is exactly
//! what [`crate::bots::decide`] gives from that seat's view under
//! [`crate::fair::bot_seed`]. A hand that passes was dealt fairly and played
//! without the house knowing the hero's cards; a hand that fails names the
//! first check that did not hold. A hand between two members that the house
//! only dealt has no house seat; the replay then checks the deal and the
//! result alone, and each member's own actions are their own.
//!
//! The engine is abstract ([`Engine`]) so a browser can verify with its own
//! JavaScript bindings while the house seat verifies with the Rust engine;
//! [`RustEngine`] is the in-crate implementation.

use crate::bots;
use crate::engine::{self, Action, Hand, HandConfig, Legal, SeatConfig, SeatView};
use crate::fair;
use crate::rules::{Act, HandAction, HandRecord};

/// An engine a verifier replays with.
pub trait Engine {
    /// Deal a hand.
    fn new_hand(&self, cfg: &HandConfig) -> Result<Hand, String>;
    /// The legal envelope, `None` once the hand is over.
    fn legal(&self, h: &Hand) -> Result<Option<Legal>, String>;
    /// Apply an action.
    fn act(&self, h: &Hand, action: &Action) -> Result<Hand, String>;
    /// What a seat may see.
    fn seat_view(&self, h: &Hand, seat: u32) -> Result<SeatView, String>;
    /// A bot's decision for a seat under a seed.
    fn bot_decide(
        &self,
        h: &Hand,
        seat: u32,
        profile: &str,
        seed_hex: &str,
    ) -> Result<Action, String>;
}

/// The crate's own engine.
#[derive(Debug, Clone, Copy, Default)]
pub struct RustEngine;

impl Engine for RustEngine {
    fn new_hand(&self, cfg: &HandConfig) -> Result<Hand, String> {
        engine::new_hand(cfg).map_err(|e| e.0)
    }

    fn legal(&self, h: &Hand) -> Result<Option<Legal>, String> {
        Ok(engine::legal(h))
    }

    fn act(&self, h: &Hand, action: &Action) -> Result<Hand, String> {
        engine::act(h, action).map_err(|e| e.0)
    }

    fn seat_view(&self, h: &Hand, seat: u32) -> Result<SeatView, String> {
        Ok(engine::seat_view(h, seat))
    }

    fn bot_decide(
        &self,
        h: &Hand,
        seat: u32,
        profile: &str,
        seed_hex: &str,
    ) -> Result<Action, String> {
        let l = engine::legal(h).ok_or_else(|| "hand is over".to_string())?;
        let view = engine::seat_view(h, seat);
        let mut rng = engine::Rng::from_seed(seed_hex).map_err(|e| e.0)?;
        Ok(bots::decide(&view, &l, profile, &mut rng))
    }
}

/// What a verifier is given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim<'a> {
    /// The commitment shown before the deal.
    pub commit: &'a str,
    /// The secret revealed after it.
    pub secret: &'a str,
    /// The players' nonces, in seat order (one for a hand against the house).
    pub nonces: Vec<String>,
    /// The seed the hand was said to be dealt from.
    pub seed: &'a str,
    /// The hand record.
    pub record: &'a HandRecord,
    /// The house bot's seat, or `None` for a hand between two members that
    /// the house only dealt.
    pub house_seat: Option<u32>,
    /// The house bot's profile.
    pub profile: &'a str,
}

/// Why a hand does not verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// The revealed secret is not what was committed to.
    #[error("the revealed secret does not match the commitment shown before the deal")]
    Commitment,
    /// The seed is not `sha256(secret ‖ nonce)`.
    #[error("the seed is not the one the secret and the nonce fix")]
    Seed,
    /// The record's seed is not the claimed one.
    #[error("the record names a different seed")]
    RecordSeed,
    /// The engine refused to replay.
    #[error("replay failed: {0}")]
    Engine(String),
    /// The record's action log cannot be applied: an action out of turn,
    /// illegal, or a street marker where none falls.
    #[error("action {index} cannot be applied: {why}")]
    Action {
        /// The index into the record's actions.
        index: usize,
        /// The engine's reason.
        why: String,
    },
    /// The house seat's recorded action is not the bot's decision.
    #[error("action {index}: the house played {played} but the book says {expected}")]
    HousePlay {
        /// The index into the record's actions.
        index: usize,
        /// What the record says the house did.
        played: String,
        /// What `decide` gives.
        expected: String,
    },
    /// The hand did not end where the record says.
    #[error("the record ends before the hand does")]
    Unfinished,
    /// The replayed hand differs from the record.
    #[error("the replay differs from the record: {0}")]
    Mismatch(String),
}

fn describe(a: &Action) -> String {
    match a.amount {
        Some(n) => format!("{} {n}", a.action),
        None => a.action.clone(),
    }
}

/// Verify a hand. `Ok` carries the replayed final hand.
pub fn verify(engine: &dyn Engine, claim: &Claim<'_>) -> Result<Hand, VerifyError> {
    if !fair::check_commit(claim.secret, claim.commit) {
        return Err(VerifyError::Commitment);
    }
    let nonces: Vec<&str> = claim.nonces.iter().map(String::as_str).collect();
    if fair::seed_of_many(claim.secret, &nonces) != claim.seed {
        return Err(VerifyError::Seed);
    }
    let r = claim.record;
    if r.seed != claim.seed {
        return Err(VerifyError::RecordSeed);
    }
    let cfg = HandConfig {
        seats: r
            .seats
            .iter()
            .map(|s| SeatConfig {
                name: s.name.clone(),
                stack: s.start_stack,
            })
            .collect(),
        button: r.button,
        sb: r.sb,
        bb: r.bb,
        ante: r.ante,
        seed_hex: r.seed.clone(),
        limit: matches!(r.variant, crate::rules::Variant::HoldemLimit),
    };
    let mut h = engine.new_hand(&cfg).map_err(VerifyError::Engine)?;
    let mut expected_street: u8 = 0;
    for (index, entry) in r.actions.iter().enumerate() {
        match entry {
            HandAction::Street { street } => {
                // a marker is a reader's convenience: it must fall where the
                // replay dealt that street
                let want = match street {
                    crate::rules::Street::Flop => 1,
                    crate::rules::Street::Turn => 2,
                    crate::rules::Street::River => 3,
                };
                if h.street < want || want != expected_street + 1 {
                    return Err(VerifyError::Action {
                        index,
                        why: format!(
                            "street marker {street:?} does not fall where the replay dealt it"
                        ),
                    });
                }
                expected_street = want;
            }
            HandAction::Act {
                seat,
                act,
                to,
                amount: _,
            } => {
                if !h.in_play() {
                    return Err(VerifyError::Action {
                        index,
                        why: "the hand is already over".into(),
                    });
                }
                // the replay must have reached the street the markers say
                if h.street != expected_street {
                    return Err(VerifyError::Action {
                        index,
                        why: "a street was dealt without its marker".into(),
                    });
                }
                let action = Action {
                    seat: *seat,
                    action: match act {
                        Act::Fold => "fold",
                        Act::Check => "check",
                        Act::Call => "call",
                        Act::Bet => "bet",
                        Act::Raise => "raise",
                    }
                    .to_string(),
                    amount: match act {
                        Act::Bet | Act::Raise => *to,
                        _ => None,
                    },
                };
                if Some(*seat) == claim.house_seat {
                    let seed = fair::bot_seed(claim.seed, h.log.len());
                    let expected = engine
                        .bot_decide(&h, *seat, claim.profile, &seed)
                        .map_err(VerifyError::Engine)?;
                    if expected != action {
                        return Err(VerifyError::HousePlay {
                            index,
                            played: describe(&action),
                            expected: describe(&expected),
                        });
                    }
                }
                h = engine
                    .act(&h, &action)
                    .map_err(|why| VerifyError::Action { index, why })?;
            }
        }
    }
    if h.in_play() {
        return Err(VerifyError::Unfinished);
    }
    let replayed = crate::record::record_of(&h, None).ok_or(VerifyError::Unfinished)?;
    // the record's names are the identities, the replay's are the config's:
    // compare everything else
    let strip = |mut rec: HandRecord| {
        for s in &mut rec.seats {
            s.name.clear();
        }
        rec.context = None;
        rec
    };
    let (a, b) = (strip(replayed), strip(r.clone()));
    if a.seats != b.seats {
        return Err(VerifyError::Mismatch("hole cards or start stacks".into()));
    }
    if a.board != b.board {
        return Err(VerifyError::Mismatch("board".into()));
    }
    if a.result != b.result {
        return Err(VerifyError::Mismatch("result".into()));
    }
    if a.actions != b.actions {
        return Err(VerifyError::Mismatch("actions".into()));
    }
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{self as eng, HandConfig, SeatConfig};
    use crate::record::record_of;

    /// Play a hand as the citizen would: seat 1 is the house, seat 0 folds
    /// or calls down by a fixed script.
    fn play(secret: &str, nonce: &str, hero_script: &[&str]) -> (Hand, String) {
        let seed = fair::seed_of(secret, nonce);
        let cfg = HandConfig {
            seats: vec![
                SeatConfig {
                    name: "You".into(),
                    stack: 2000,
                },
                SeatConfig {
                    name: "House".into(),
                    stack: 2000,
                },
            ],
            button: 0,
            sb: 10,
            bb: 20,
            ante: 0,
            seed_hex: seed.clone(),
            limit: true,
        };
        let mut h = eng::new_hand(&cfg).unwrap();
        let mut script = hero_script.iter();
        while h.in_play() {
            let l = eng::legal(&h).unwrap();
            let a = if l.seat == 1 {
                let mut rng = eng::Rng::from_seed(&fair::bot_seed(&seed, h.log.len())).unwrap();
                bots::decide(&eng::seat_view(&h, 1), &l, "tag", &mut rng)
            } else {
                let want = script.next().copied().unwrap_or("call");
                let want = if l.allows(want) {
                    want
                } else if l.allows("check") {
                    "check"
                } else {
                    "call"
                };
                Action {
                    seat: 0,
                    action: want.into(),
                    amount: if want == "raise" || want == "bet" {
                        Some(l.min_raise_to)
                    } else {
                        None
                    },
                }
            };
            h = eng::act(&h, &a).unwrap();
        }
        (h, seed)
    }

    #[test]
    fn an_honest_hand_verifies_and_a_tampered_one_does_not() {
        let secret = "11".repeat(32);
        let nonce = "22".repeat(32);
        let commit = fair::commit(&secret);
        let (h, seed) = play(
            &secret,
            &nonce,
            &["call", "check", "check", "check", "check"],
        );
        let record = record_of(&h, None).unwrap();
        let claim = Claim {
            commit: &commit,
            secret: &secret,
            nonces: vec![nonce.clone()],
            seed: &seed,
            record: &record,
            house_seat: Some(1),
            profile: "tag",
        };
        let replayed = verify(&RustEngine, &claim).unwrap();
        assert_eq!(replayed.result, h.result);

        // wrong secret
        let bad = Claim {
            secret: &"13".repeat(32),
            ..claim.clone()
        };
        assert_eq!(verify(&RustEngine, &bad), Err(VerifyError::Commitment));
        // wrong nonce
        let bad = Claim {
            nonces: vec!["23".repeat(32)],
            ..claim.clone()
        };
        assert_eq!(verify(&RustEngine, &bad), Err(VerifyError::Seed));
        // a different profile: the house's play no longer matches the book
        // (unless this seed's hand had no house decision, which the script
        // guarantees against: the house acts preflop at least)
        let other = Claim {
            profile: "station",
            ..claim.clone()
        };
        let outcome = verify(&RustEngine, &other);
        assert!(
            matches!(outcome, Err(VerifyError::HousePlay { .. })) || outcome.is_ok(),
            "{outcome:?}"
        );
        // a doctored result
        let mut doctored = record.clone();
        doctored.result.pot += 1;
        let bad = Claim {
            record: &doctored,
            ..claim.clone()
        };
        assert_eq!(
            verify(&RustEngine, &bad),
            Err(VerifyError::Mismatch("result".into()))
        );
        // a doctored hole card
        let mut doctored = record.clone();
        doctored.seats[1].hole = Some(vec!["As".into(), "Ah".into()]);
        let bad = Claim {
            record: &doctored,
            ..claim.clone()
        };
        assert_eq!(
            verify(&RustEngine, &bad),
            Err(VerifyError::Mismatch("hole cards or start stacks".into()))
        );
        // an action the engine refuses
        let mut doctored = record.clone();
        doctored.actions.insert(
            0,
            HandAction::Act {
                seat: 1,
                act: Act::Check,
                to: None,
                amount: None,
            },
        );
        let bad = Claim {
            record: &doctored,
            ..claim.clone()
        };
        assert!(matches!(
            verify(&RustEngine, &bad),
            Err(VerifyError::Action { index: 0, .. })
                | Err(VerifyError::HousePlay { index: 0, .. })
        ));
        // a record cut short
        let mut doctored = record.clone();
        doctored.actions.pop();
        let bad = Claim {
            record: &doctored,
            ..claim.clone()
        };
        let outcome = verify(&RustEngine, &bad);
        assert!(
            matches!(
                outcome,
                Err(VerifyError::Unfinished) | Err(VerifyError::Mismatch(_))
            ),
            "{outcome:?}"
        );
    }

    #[test]
    fn a_house_that_deviates_from_the_book_is_caught() {
        let secret = "31".repeat(32);
        let nonce = "32".repeat(32);
        let commit = fair::commit(&secret);
        let (h, seed) = play(
            &secret,
            &nonce,
            &["call", "check", "check", "check", "check"],
        );
        let mut record = record_of(&h, None).unwrap();
        // flip the house's first action to a fold (always legal), and fix up
        // nothing else: the verifier must stop at that action
        let idx = record
            .actions
            .iter()
            .position(|a| matches!(a, HandAction::Act { seat: 1, .. }))
            .expect("the house acted");
        record.actions[idx] = HandAction::Act {
            seat: 1,
            act: Act::Fold,
            to: None,
            amount: None,
        };
        let claim = Claim {
            commit: &commit,
            secret: &secret,
            nonces: vec![nonce.clone()],
            seed: &seed,
            record: &record,
            house_seat: Some(1),
            profile: "tag",
        };
        // dealt-only: the house's play is not checked, so the doctored
        // action is caught only by the replay's result
        let dealt_only = Claim {
            house_seat: None,
            ..claim.clone()
        };
        assert!(verify(&RustEngine, &dealt_only).is_err());
        match verify(&RustEngine, &claim) {
            Err(VerifyError::HousePlay { index, .. }) => assert_eq!(index, idx),
            other => panic!("{other:?}"),
        }
    }
}
