//! The table's characters: a Rust port of Libre Poker's `bots.js`.
//!
//! A bot sees only its [`SeatView`] (the same envelope a remote human gets)
//! plus the legal-action envelope, and returns a serialisable [`Action`].
//! Decisions are deterministic given the random generator, so a hand replays
//! exactly from its seed: the house seat decides with
//! [`crate::fair::bot_seed`] at every step, and a member's client can check,
//! after the hand, that every house action was the one this function gives.
//!
//! The floating-point arithmetic follows the original operation for
//! operation (the Chen score, the Monte-Carlo equity, the jittered
//! thresholds), and `tests/differential.rs` holds the port to the JavaScript
//! on recorded hands.

use crate::engine::{evaluate, rank_of, suit_of, Action, Legal, Rng, SeatView};

/// A playing style.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Profile {
    /// Voluntarily-put-in-pot: how many hands it plays.
    pub vpip: f64,
    /// How often it bets or raises when it may.
    pub aggro: f64,
    /// How often it bets with nothing.
    pub bluff: f64,
    /// How readily it piles in with a monster.
    pub cap: f64,
}

/// The five named profiles, in the original's order.
pub const PROFILES: [(&str, Profile); 5] = [
    (
        "rock",
        Profile {
            vpip: 0.13,
            aggro: 0.45,
            bluff: 0.03,
            cap: 0.75,
        },
    ),
    (
        "tag",
        Profile {
            vpip: 0.21,
            aggro: 0.75,
            bluff: 0.09,
            cap: 0.95,
        },
    ),
    (
        "lag",
        Profile {
            vpip: 0.32,
            aggro: 0.85,
            bluff: 0.16,
            cap: 1.00,
        },
    ),
    (
        "station",
        Profile {
            vpip: 0.44,
            aggro: 0.22,
            bluff: 0.02,
            cap: 0.60,
        },
    ),
    (
        "maniac",
        Profile {
            vpip: 0.55,
            aggro: 0.95,
            bluff: 0.24,
            cap: 1.00,
        },
    ),
];

/// The profile for a name, or `tag` for an unknown one, as the original
/// falls back.
pub fn profile(name: &str) -> Profile {
    PROFILES
        .iter()
        .find(|(n, _)| *n == name)
        .or_else(|| PROFILES.iter().find(|(n, _)| *n == "tag"))
        .map(|(_, p)| *p)
        .expect("tag profile exists")
}

/// One of the wardroom's characters: name, style, glyph and a line.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RosterEntry {
    /// Display name.
    pub name: String,
    /// The profile it plays.
    pub profile: String,
    /// A glyph for the seat.
    pub emoji: String,
    /// One line of character.
    pub blurb: String,
}

/// The wardroom's characters (`ROSTER`).
pub fn roster() -> Vec<RosterEntry> {
    let entry = |name: &str, profile: &str, emoji: &str, blurb: &str| RosterEntry {
        name: name.into(),
        profile: profile.into(),
        emoji: emoji.into(),
        blurb: blurb.into(),
    };
    vec![
        entry("Cmdr. Sterling", "rock", "🎖", "waits for the navy"),
        entry("First Mate Wren", "tag", "🪶", "tight, then ruthless"),
        entry("Gunner Halloway", "lag", "💣", "pressure from any two"),
        entry("Cook Barnacle", "station", "🍲", "never folds a stew"),
        entry("Ensign Puffin", "maniac", "🐧", "all sail, no anchor"),
    ]
}

/// The house character for a profile: the first roster entry playing it,
/// else `tag`'s, else the first.
pub fn pick_bot(profile: &str) -> RosterEntry {
    let r = roster();
    r.iter()
        .find(|e| e.profile == profile)
        .or_else(|| r.iter().find(|e| e.profile == "tag"))
        .or_else(|| r.first())
        .cloned()
        .expect("roster is not empty")
}

/// The Chen formula, halved to roughly `0..1` (`chen`): AA scores 1.0.
pub fn chen(hole: &[u8]) -> f64 {
    let mut r: Vec<u8> = hole.iter().map(|&c| rank_of(c)).collect();
    r.sort_by(|a, b| b.cmp(a));
    let suited = hole.len() >= 2 && suit_of(hole[0]) == suit_of(hole[1]);
    let pts = |rank: u8| -> f64 {
        match rank {
            12 => 10.0,
            11 => 8.0,
            10 => 7.0,
            9 => 6.0,
            r => (f64::from(r) + 2.0) / 2.0,
        }
    };
    let (r0, r1) = (r[0], r[1]);
    let score = if r0 == r1 {
        (pts(r0) * 2.0).max(5.0)
    } else {
        let mut score = pts(r0);
        if suited {
            score += 2.0;
        }
        let gap = i32::from(r0) - i32::from(r1) - 1;
        if gap == 1 {
            score -= 1.0;
        } else if gap == 2 {
            score -= 2.0;
        } else if gap == 3 {
            score -= 4.0;
        } else if gap >= 4 {
            score -= 5.0;
        }
        if gap <= 1 && r0 <= 9 {
            score += 1.0; // small connectors can straighten
        }
        score
    };
    (score / 20.0).max(0.0)
}

/// Monte-Carlo equity against `opps` unknown hands (`equityMC`), deterministic
/// under `rng`.
pub fn equity_mc(hole: &[u8], board: &[u8], opps: usize, rng: &mut Rng, rollouts: usize) -> f64 {
    let pool: Vec<u8> = (0..52u8)
        .filter(|c| !hole.contains(c) && !board.contains(c))
        .collect();
    let mut win = 0.0f64;
    for _ in 0..rollouts {
        // partial Fisher-Yates over a copy
        let mut p = pool.clone();
        let draws = opps * 2 + (5 - board.len());
        for i in 0..draws {
            let j = i + rng.below(p.len() - i);
            p.swap(i, j);
        }
        let mut k = 0usize;
        let mut full_board = board.to_vec();
        while full_board.len() < 5 {
            full_board.push(p[k]);
            k += 1;
        }
        let mut mine_cards = hole.to_vec();
        mine_cards.extend_from_slice(&full_board);
        let mine = evaluate(&mine_cards).score;
        let mut best = true;
        let mut tie = 1.0f64;
        for _ in 0..opps {
            let mut theirs_cards = vec![p[k], p[k + 1]];
            theirs_cards.extend_from_slice(&full_board);
            let theirs = evaluate(&theirs_cards).score;
            k += 2;
            if theirs > mine {
                best = false;
                break;
            }
            if theirs == mine {
                tie += 1.0;
            }
        }
        if best {
            win += 1.0 / tie;
        }
    }
    win / rollouts as f64
}

/// ECMAScript `Math.round`: halves round towards positive infinity.
fn js_round(x: f64) -> f64 {
    let f = x.floor();
    if x - f >= 0.5 {
        f + 1.0
    } else {
        f
    }
}

fn action(seat: u32, action: &str, amount: Option<u64>) -> Action {
    Action {
        seat,
        action: action.to_string(),
        amount,
    }
}

/// A bot's decision (`decide`): the strategy's choice, netted to something
/// legal (raise → call → check → fold) so it never asks for an illegal action.
pub fn decide(view: &SeatView, l: &Legal, profile_name: &str, rng: &mut Rng) -> Action {
    decide_with(view, l, profile_name, rng, 60)
}

/// [`decide`] with a chosen number of equity roll-outs.
pub fn decide_with(
    view: &SeatView,
    l: &Legal,
    profile_name: &str,
    rng: &mut Rng,
    rollouts: usize,
) -> Action {
    let raw = decide_raw(view, l, profile_name, rng, rollouts);
    if l.allows(&raw.action) {
        return raw;
    }
    let order: &[&str] = if raw.action == "fold" {
        &["check", "fold"]
    } else {
        &["call", "check", "bet", "raise", "fold"]
    };
    for a in order {
        if !l.allows(a) {
            continue;
        }
        if *a == "bet" || *a == "raise" {
            return action(view.seat, a, Some(l.min_raise_to));
        }
        return action(view.seat, a, None);
    }
    action(view.seat, "fold", None)
}

fn decide_raw(
    view: &SeatView,
    l: &Legal,
    profile_name: &str,
    rng: &mut Rng,
    rollouts: usize,
) -> Action {
    let p = profile(profile_name);
    let seat = view.seat;
    let Some(me) = view.seats.get(seat as usize) else {
        return action(seat, "fold", None);
    };
    let hole: Vec<u8> = view.hole.clone().unwrap_or_default();
    if hole.len() < 2 {
        return action(seat, "fold", None);
    }
    let pot = view.pot as f64;
    let call = l.call_amount as f64;
    let bb = view.bb as f64;
    let stack_bb = me.stack as f64 / bb;
    let opps = view
        .seats
        .iter()
        .enumerate()
        .filter(|(i, s)| *i != seat as usize && !s.folded && !s.out)
        .count();
    let pot_odds = if call > 0.0 { call / (pot + call) } else { 0.0 };
    let street_commit = me.street_commit as f64;

    let raise_to = |frac: f64| -> u64 {
        // bet ~frac of pot, clamped to the legal envelope, chip-rounded
        let target = js_round((pot * frac + call + street_commit) / bb) * bb;
        let clamped = (l.min_raise_to as f64).max((l.max_raise_to as f64).min(target));
        clamped as u64
    };
    let aggressive = |amount: u64| -> Action {
        let a = if l.allows("bet") { "bet" } else { "raise" };
        action(seat, a, Some(amount))
    };
    let jitter = |x: f64, rng: &mut Rng| x * (0.92 + rng.draw() * 0.16);

    // ---- preflop: chart poker + short-stack push/fold
    if view.street == "preflop" {
        let s = jitter(chen(&hole), rng);
        let open_threshold = 0.30 - p.vpip * 0.35; // rock .25, station .15
        let facing_raise = view.current_bet as f64 > bb;
        if stack_bb <= 10.0 {
            // push/fold regime
            let shove_at = if facing_raise {
                0.42
            } else {
                0.33 - p.vpip * 0.15
            };
            if s >= shove_at {
                let a = if l.allows("raise") { "raise" } else { "call" };
                return action(seat, a, Some(l.max_raise_to));
            }
            if l.allows("check") {
                return action(seat, "check", None);
            }
            if call <= bb && s >= 0.2 {
                return action(seat, "call", None);
            }
            return action(seat, "fold", None);
        }
        if !facing_raise {
            // the draw happens only when the first test fails and the second
            // holds, as the original's short-circuit does
            if (s >= open_threshold + 0.12 || (s >= open_threshold && rng.draw() < p.aggro))
                && (l.allows("raise") || l.allows("bet"))
            {
                let a = if l.allows("raise") { "raise" } else { "bet" };
                return action(seat, a, Some(raise_to(1.0)));
            }
            if l.allows("check") {
                return action(seat, "check", None);
            }
            if (s >= open_threshold - 0.02 || call <= bb) && call / (pot + call) < s * 0.9 {
                return action(seat, "call", None);
            }
            if rng.draw() < p.bluff && l.allows("raise") {
                return action(seat, "raise", Some(raise_to(1.0)));
            }
            return action(seat, "fold", None);
        }
        // facing a raise
        if s >= 0.62 && l.allows("raise") {
            return action(seat, "raise", Some(raise_to(1.2)));
        }
        if s >= 0.34 && pot_odds < s * 0.8 {
            return action(seat, "call", None);
        }
        if l.allows("check") {
            return action(seat, "check", None);
        }
        if rng.draw() < p.bluff * 0.5 && l.allows("raise") {
            return action(seat, "raise", Some(raise_to(1.2)));
        }
        return action(seat, "fold", None);
    }

    // ---- postflop: equity vs pot odds, coloured by personality
    let eq = {
        let e = equity_mc(&hole, &view.board, opps, rng, rollouts);
        jitter(e, rng)
    };
    let strong = eq > 0.5 + 0.12 / (opps.max(1) as f64);
    let monster = eq > 0.78;

    if call == 0.0 {
        if (strong && rng.draw() < p.aggro) || monster {
            let frac = if monster { 0.85 } else { 0.6 };
            if l.allows("bet") || l.allows("raise") {
                return aggressive(raise_to(frac));
            }
        }
        if rng.draw() < p.bluff && (l.allows("bet") || l.allows("raise")) {
            return aggressive(raise_to(0.55));
        }
        return action(seat, "check", None);
    }
    // facing a bet
    let margin = 0.04 * (1.0 - p.vpip); // stations call thinner
    if monster && l.allows("raise") && rng.draw() < p.aggro * p.cap {
        return action(seat, "raise", Some(raise_to(1.0)));
    }
    if eq > pot_odds + margin {
        if strong && l.allows("raise") && rng.draw() < p.aggro * 0.4 {
            return action(seat, "raise", Some(raise_to(0.8)));
        }
        return action(seat, "call", None);
    }
    if rng.draw() < p.bluff * 0.35 && l.allows("raise") && call < pot * 0.6 {
        return action(seat, "raise", Some(raise_to(0.9)));
    }
    action(seat, "fold", None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chen_anchors() {
        // AA = 20 points → 1.0; 72o is the worst
        assert_eq!(chen(&[12, 12 + 13]), 1.0);
        let worst = chen(&[5, 13]);
        assert!(worst < 0.1, "{worst}");
        // suited connectors get the suited and small-connector bonuses
        let suited = chen(&[6, 5]);
        let off = chen(&[6, 5 + 13]);
        assert!(suited > off);
    }

    #[test]
    fn js_round_halves_up() {
        assert_eq!(js_round(2.5), 3.0);
        assert_eq!(js_round(2.4999), 2.0);
        assert_eq!(js_round(0.499_999_999_999_999_94), 0.0);
    }

    #[test]
    fn unknown_profile_is_tag_and_roster_picks_by_profile() {
        assert_eq!(profile("nope"), profile("tag"));
        assert_eq!(pick_bot("maniac").name, "Ensign Puffin");
        assert_eq!(pick_bot("nope").profile, "tag");
    }
}
