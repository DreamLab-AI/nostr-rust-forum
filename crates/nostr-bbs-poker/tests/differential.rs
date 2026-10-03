//! The Rust engine and bots against the JavaScript originals, on recorded
//! hands (`tests/fixtures/hands.json`, made by `tools/gen-fixtures.mjs`).
//!
//! Every comparison is on parsed JSON, so key order is free but every value
//! must agree: the hand after the deal, each legal envelope, each action the
//! house bot chose, each hand after an action, and both seat views.

use nostr_bbs_poker::bots::{self, PROFILES};
use nostr_bbs_poker::engine::{self, Action, Hand, HandConfig, Legal, Rng};
use nostr_bbs_poker::fair;
use serde_json::Value;

const FIXTURES: &str = include_str!("fixtures/hands.json");

fn fixtures() -> Value {
    serde_json::from_str(FIXTURES).expect("fixtures parse")
}

fn to_value<T: serde::Serialize>(t: &T) -> Value {
    serde_json::to_value(t).unwrap()
}

#[test]
fn rng_draws_match() {
    for r in fixtures()["rngs"].as_array().unwrap() {
        let mut rng = Rng::from_seed(r["seed"].as_str().unwrap()).unwrap();
        for (i, want) in r["draws"].as_array().unwrap().iter().enumerate() {
            let got = rng.draw();
            assert_eq!(got, want.as_f64().unwrap(), "seed {} draw {i}", r["seed"]);
        }
    }
}

#[test]
fn roster_and_profiles_match() {
    let f = fixtures();
    assert_eq!(to_value(&bots::roster()), f["roster"]);
    for (name, p) in PROFILES {
        let want = &f["profiles"][name];
        assert_eq!(p.vpip, want["vpip"].as_f64().unwrap(), "{name}");
        assert_eq!(p.aggro, want["aggro"].as_f64().unwrap(), "{name}");
        assert_eq!(p.bluff, want["bluff"].as_f64().unwrap(), "{name}");
        assert_eq!(p.cap, want["cap"].as_f64().unwrap(), "{name}");
    }
}

#[test]
fn evaluator_matches_on_400_random_sets() {
    let f = fixtures();
    let mut checked = 0;
    for e in f["evals"].as_array().unwrap() {
        let cards: Vec<u8> = serde_json::from_value(e["cards"].clone()).unwrap();
        let want = &e["eval"];
        if want["score"].is_null() {
            // six cards, three pairs: the original scores it NaN (see
            // `evaluate`); not a state a hand can reach
            continue;
        }
        let got = engine::evaluate(&cards);
        assert_eq!(to_value(&got), *want, "cards {cards:?}");
        assert_eq!(engine::hand_name(&got), e["name"].as_str().unwrap());
        assert_eq!(to_value(&engine::best_five(&cards)), e["best"]);
        checked += 1;
    }
    assert!(checked >= 390, "{checked}");
}

#[test]
fn chen_and_equity_match() {
    let f = fixtures();
    for c in f["chens"].as_array().unwrap() {
        let hole: Vec<u8> = serde_json::from_value(c["hole"].clone()).unwrap();
        assert_eq!(bots::chen(&hole), c["chen"].as_f64().unwrap(), "{hole:?}");
    }
    for e in f["equities"].as_array().unwrap() {
        let hole: Vec<u8> = serde_json::from_value(e["hole"].clone()).unwrap();
        let board: Vec<u8> = serde_json::from_value(e["board"].clone()).unwrap();
        let mut rng = Rng::from_seed(e["rngSeed"].as_str().unwrap()).unwrap();
        let got = bots::equity_mc(&hole, &board, 1, &mut rng, 60);
        assert_eq!(got, e["equity"].as_f64().unwrap(), "{hole:?} {board:?}");
    }
}

#[test]
fn every_recorded_hand_replays_identically() {
    let f = fixtures();
    let hands = f["hands"].as_array().unwrap();
    assert_eq!(hands.len(), 160);
    let mut steps = 0;
    let mut bot_steps = 0;
    for (n, hand) in hands.iter().enumerate() {
        let cfg: HandConfig = serde_json::from_value(hand["cfg"].clone()).unwrap();
        let profile = hand["profile"].as_str().unwrap();
        let mut h: Hand = engine::new_hand(&cfg).unwrap();
        assert_eq!(to_value(&h), hand["dealt"], "hand {n}: deal");
        for (i, step) in hand["steps"].as_array().unwrap().iter().enumerate() {
            let l: Legal = engine::legal(&h).expect("in play");
            assert_eq!(to_value(&l), step["legal"], "hand {n} step {i}: legal");
            let recorded: Action = serde_json::from_value(step["action"].clone()).unwrap();
            if h.to_act == 1 {
                let seed = fair::bot_seed(&cfg.seed_hex, h.log.len());
                let view = engine::seat_view(&h, 1);
                assert_eq!(
                    to_value(&view),
                    step["viewBefore"],
                    "hand {n} step {i}: bot view"
                );
                let mut rng = Rng::from_seed(&seed).unwrap();
                let decided = bots::decide(&view, &l, profile, &mut rng);
                assert_eq!(
                    decided, recorded,
                    "hand {n} step {i}: bot decision ({profile})"
                );
                bot_steps += 1;
            }
            h = engine::act(&h, &recorded).unwrap();
            assert_eq!(to_value(&h), step["after"], "hand {n} step {i}: after");
            assert_eq!(
                to_value(&engine::seat_view(&h, 0)),
                step["view0"],
                "hand {n} step {i}: view0"
            );
            assert_eq!(
                to_value(&engine::seat_view(&h, 1)),
                step["view1"],
                "hand {n} step {i}: view1"
            );
            steps += 1;
        }
        assert!(!h.in_play(), "hand {n} did not finish");
        assert_eq!(to_value(&h), hand["final"], "hand {n}: final");
        assert_eq!(
            to_value(&engine::seat_view(&h, 0)),
            hand["view0"],
            "hand {n}: final view0"
        );
        assert_eq!(
            to_value(&engine::seat_view(&h, 1)),
            hand["view1"],
            "hand {n}: final view1"
        );
    }
    assert_eq!(steps, 378);
    assert!(bot_steps > 150, "{bot_steps}");
}
