//! The hand engine: a Rust port of Libre Poker's `poker.js` (the Wardroom's
//! pure engine) — cards, the seeded shuffle, the evaluator, and the Texas
//! hold'em hand state machine driven by serialisable actions.
//!
//! The port is behaviour-for-behaviour, including the two places amateur
//! engines go wrong and this one does by the book: min-raise rules (an
//! under-raise all-in does **not** reopen the betting for seats that already
//! acted) and side pots cut from capped commitments after the uncalled tail of
//! a bet is refunded. It serialises to the **same JSON** as the JavaScript
//! engine, so a seat view produced here reads in any client written against
//! `poker.js`, and `tests/differential.rs` holds it to that: every state of
//! 160 recorded hands must match the JavaScript byte for byte once parsed.
//!
//! Numbers follow ECMAScript where it matters: the xorshift128 generator works
//! in 32-bit lanes, `(x * n) | 0` truncates, and `Math.round` rounds halves
//! up. Nothing here reads a clock, the network or the DOM.
//!
//! Cards are `0..52`: `rank = card % 13` (`0` = deuce … `12` = ace) and
//! `suit = card / 13` in the order clubs, diamonds, hearts, spades.

use serde::{Deserialize, Serialize};

/// The 13 ranks, deuce to ace.
pub const RANKS: &[u8; 13] = b"23456789TJQKA";
/// The four suit glyphs, in suit order (clubs, diamonds, hearts, spades).
pub const SUITS: [char; 4] = ['♣', '♦', '♥', '♠'];
/// The four suit letters HAND.md uses in card names, in suit order.
pub const SUIT_LETTERS: [char; 4] = ['c', 'd', 'h', 's'];
/// The streets, in order.
pub const STREETS: [&str; 4] = ["preflop", "flop", "turn", "river"];
/// Spoken category names, index = category.
pub const CAT_NAMES: [&str; 9] = [
    "high card",
    "a pair",
    "two pair",
    "three of a kind",
    "a straight",
    "a flush",
    "a full house",
    "four of a kind",
    "a straight flush",
];
const RANK_WORDS: [&str; 13] = [
    "deuce", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "jack", "queen",
    "king", "ace",
];

/// A card's rank, `0` (deuce) to `12` (ace).
pub fn rank_of(card: u8) -> u8 {
    card % 13
}

/// A card's suit, `0` to `3`.
pub fn suit_of(card: u8) -> u8 {
    card / 13
}

/// A card's short name with a suit glyph, as the engine prints it: `A♠`, `T♥`.
pub fn card_name(card: u8) -> String {
    format!(
        "{}{}",
        RANKS[rank_of(card) as usize] as char,
        SUITS[suit_of(card) as usize]
    )
}

/// A card's name as HAND.md writes it: rank then suit letter, `As`, `Th`.
pub fn card_code(card: u8) -> String {
    format!(
        "{}{}",
        RANKS[rank_of(card) as usize] as char,
        SUIT_LETTERS[suit_of(card) as usize]
    )
}

/// The card a HAND.md name denotes (`Kd` → 24), if well-formed.
pub fn card_of_code(code: &str) -> Option<u8> {
    let mut chars = code.chars();
    let rank = chars.next()?;
    let suit = chars.next()?;
    if chars.next().is_some() {
        return None;
    }
    let r = RANKS.iter().position(|&c| c as char == rank)?;
    let s = SUIT_LETTERS.iter().position(|&c| c == suit)?;
    Some((s * 13 + r) as u8)
}

// ── Random numbers ────────────────────────────────────────────────────────────

/// xorshift128 seeded from a 64-hex string: the fleet's shuffle (`rngFromSeed`).
///
/// Each draw is a double in `[0, 1)`, exactly the JavaScript sequence for the
/// same seed.
#[derive(Debug, Clone)]
pub struct Rng {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
}

impl Rng {
    /// Seed from 64 lowercase hex characters; only the first 32 are used, as
    /// in the original.
    pub fn from_seed(seed_hex: &str) -> Result<Self, EngineError> {
        if seed_hex.len() != 64 || !seed_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(EngineError("seed must be 64 hex chars".into()));
        }
        let lane = |i: usize| u32::from_str_radix(&seed_hex[i * 8..i * 8 + 8], 16).unwrap_or(0);
        let (mut a, b, c, d) = (lane(0), lane(1), lane(2), lane(3));
        if a | b | c | d == 0 {
            a = 0x9e37_79b9;
        }
        Ok(Self { a, b, c, d })
    }

    /// The next draw in `[0, 1)`.
    pub fn draw(&mut self) -> f64 {
        let t = self.a ^ (self.a << 11);
        self.a = self.b;
        self.b = self.c;
        self.c = self.d;
        self.d = (self.d ^ (self.d >> 19)) ^ (t ^ (t >> 8));
        f64::from(self.d) / 4_294_967_296.0
    }

    /// `(rng() * n) | 0`: a draw truncated to an index below `n`.
    pub fn below(&mut self, n: usize) -> usize {
        (self.draw() * n as f64) as usize
    }
}

/// The 52-card deck shuffled from a seed (`shuffledDeck`).
pub fn shuffled_deck(seed_hex: &str) -> Result<Vec<u8>, EngineError> {
    let mut rng = Rng::from_seed(seed_hex)?;
    let mut deck: Vec<u8> = (0..52).collect();
    for i in (1..52).rev() {
        let j = rng.below(i + 1);
        deck.swap(i, j);
    }
    Ok(deck)
}

// ── Evaluator ─────────────────────────────────────────────────────────────────

/// A hand's strength: category, category-specific tie-break ranks (high to
/// low) and a score that compares as an integer, higher winning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Eval {
    /// Category, `0` (high card) to `8` (straight flush).
    pub cat: u8,
    /// Tie-break ranks for the category, high to low, unpadded.
    pub kick: Vec<u8>,
    /// `cat`, then each of five kick ranks (zero-padded) in base 16.
    pub score: u64,
}

fn score(cat: u8, kick: Vec<u8>) -> Eval {
    let mut s = u64::from(cat);
    for i in 0..5 {
        s = s * 16 + u64::from(kick.get(i).copied().unwrap_or(0));
    }
    Eval {
        cat,
        kick,
        score: s,
    }
}

/// The high rank of the best straight in a rank set, `None` for none; the
/// wheel (A-2-3-4-5) is a five-high straight.
fn straight_high(set: &[bool; 13]) -> Option<u8> {
    let mut run = 0u8;
    for r in (0..13).rev() {
        run = if set[r] { run + 1 } else { 0 };
        if run == 5 {
            return Some(r as u8 + 4);
        }
    }
    if set[12] && set[0] && set[1] && set[2] && set[3] {
        return Some(3);
    }
    None
}

/// Best five of up to seven cards (`evaluate`).
///
/// A set with no single card beside its pairs (possible only with six cards)
/// has no kicker; the original scores it as `NaN`. Such a set never reaches
/// a showdown (seven cards always leave a single), and this port scores it
/// with a zero kicker.
pub fn evaluate(cards: &[u8]) -> Eval {
    let mut by_rank = [0u8; 13];
    let mut by_suit: [Vec<u8>; 4] = Default::default();
    for &c in cards {
        by_rank[rank_of(c) as usize] += 1;
        by_suit[suit_of(c) as usize].push(rank_of(c));
    }
    for suit in &by_suit {
        if suit.len() >= 5 {
            let mut set = [false; 13];
            for &r in suit {
                set[r as usize] = true;
            }
            if let Some(hi) = straight_high(&set) {
                return score(8, vec![hi]);
            }
        }
    }
    // (count, rank), highest count first, then highest rank
    let mut groups: Vec<(u8, u8)> = (0..13u8)
        .rev()
        .filter(|&r| by_rank[r as usize] > 0)
        .map(|r| (by_rank[r as usize], r))
        .collect();
    groups.sort_by(|x, y| y.0.cmp(&x.0).then(y.1.cmp(&x.1)));
    let top = groups[0];
    let ranks_desc = |g: &[(u8, u8)]| -> Vec<u8> {
        let mut v: Vec<u8> = g.iter().map(|g| g.1).collect();
        v.sort_by(|a, b| b.cmp(a));
        v
    };
    if top.0 == 4 {
        let others: Vec<(u8, u8)> = groups.iter().copied().filter(|g| g.1 != top.1).collect();
        let kicker = ranks_desc(&others).first().copied().unwrap_or(0);
        return score(7, vec![top.1, kicker]);
    }
    if top.0 == 3 && groups.get(1).is_some_and(|g| g.0 >= 2) {
        return score(6, vec![top.1, groups[1].1]);
    }
    for suit in &by_suit {
        if suit.len() >= 5 {
            let mut top5 = suit.clone();
            top5.sort_by(|a, b| b.cmp(a));
            top5.truncate(5);
            return score(5, top5);
        }
    }
    {
        let mut set = [false; 13];
        for (r, &n) in by_rank.iter().enumerate() {
            set[r] = n > 0;
        }
        if let Some(hi) = straight_high(&set) {
            return score(4, vec![hi]);
        }
    }
    if top.0 == 3 {
        let mut kickers = ranks_desc(&groups[1..]);
        kickers.truncate(2);
        let mut kick = vec![top.1];
        kick.extend(kickers);
        return score(3, kick);
    }
    if top.0 == 2 && groups.get(1).is_some_and(|g| g.0 == 2) {
        let pairs: Vec<(u8, u8)> = groups.iter().copied().filter(|g| g.0 == 2).collect();
        let pairs = ranks_desc(&pairs);
        let singles: Vec<(u8, u8)> = groups.iter().copied().filter(|g| g.0 == 1).collect();
        let kicker = ranks_desc(&singles).first().copied().unwrap_or(0);
        return score(2, vec![pairs[0], pairs[1], kicker]);
    }
    if top.0 == 2 {
        let mut kickers = ranks_desc(&groups[1..]);
        kickers.truncate(3);
        let mut kick = vec![top.1];
        kick.extend(kickers);
        return score(1, kick);
    }
    let mut kick: Vec<u8> = groups.iter().map(|g| g.1).collect();
    kick.truncate(5);
    score(0, kick)
}

/// The five cards a hand actually plays: the first maximal five-card subset
/// in combination order (`bestFive`).
pub fn best_five(cards: &[u8]) -> Vec<u8> {
    if cards.len() <= 5 {
        return cards.to_vec();
    }
    let n = cards.len();
    let mut best: Vec<u8> = Vec::new();
    let mut best_score: i128 = -1;
    for a in 0..n - 4 {
        for b in a + 1..n - 3 {
            for c in b + 1..n - 2 {
                for d in c + 1..n - 1 {
                    for e in d + 1..n {
                        let five = [cards[a], cards[b], cards[c], cards[d], cards[e]];
                        let sc = i128::from(evaluate(&five).score);
                        if sc > best_score {
                            best_score = sc;
                            best = five.to_vec();
                        }
                    }
                }
            }
        }
    }
    best
}

fn plural(r: u8) -> String {
    if r == 4 {
        "sixes".to_string()
    } else {
        format!("{}s", RANK_WORDS[r as usize])
    }
}

/// A speakable name: "two pair, kings and nines", "a flush, ace high"
/// (`handName`).
pub fn hand_name(ev: &Eval) -> String {
    let k = |i: usize| ev.kick.get(i).copied().unwrap_or(0);
    let word = |r: u8| RANK_WORDS[r as usize];
    match ev.cat {
        8 if k(0) == 12 => "a royal flush".to_string(),
        8 => format!("a straight flush, {} high", word(k(0))),
        7 => format!("four {}", plural(k(0))),
        6 => format!("a full house, {} over {}", plural(k(0)), plural(k(1))),
        5 => format!("a flush, {} high", word(k(0))),
        4 => format!("a straight, {} high", word(k(0))),
        3 => format!("three {}", plural(k(0))),
        2 => format!("two pair, {} and {}", plural(k(0)), plural(k(1))),
        1 => format!("a pair of {}", plural(k(0))),
        _ => format!("{} high", word(k(0))),
    }
}

// ── The hand ─────────────────────────────────────────────────────────────────

/// An engine refusal: a bad seed, an illegal action, a hand that is over.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct EngineError(pub String);

/// A seat as the engine keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Seat {
    /// Display name.
    pub name: String,
    /// Stack when the hand was dealt.
    pub start_stack: u64,
    /// Chips behind.
    pub stack: u64,
    /// The two hole cards, once dealt.
    pub hole: Option<Vec<u8>>,
    /// Folded this hand.
    pub folded: bool,
    /// Every chip committed.
    pub all_in: bool,
    /// Sitting out (dealt in with no chips).
    pub out: bool,
    /// Committed on the current street.
    pub street_commit: u64,
    /// Committed over the whole hand.
    pub hand_commit: u64,
    /// May still raise on this street.
    pub can_raise: bool,
    /// Has acted on this street since the last full raise.
    pub acted: bool,
}

/// One entry of the hand log. The engine writes a different subset of fields
/// for each event; absent ones are left out of the JSON, as the original does.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// `deal`, `ante`, `sb`, `bb`, `fold`, `check`, `call`, `bet`, `raise`,
    /// `street`, `runout`, `refund`, `win` or `showdown`.
    pub ev: String,
    /// The seat the event concerns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seat: Option<u32>,
    /// Chips moved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    /// The total a bet or raise went to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<u64>,
    /// The street dealt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub street: Option<String>,
    /// The board after a street or a run-out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub board: Option<Vec<u8>>,
    /// The small-blind seat, on `deal`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sb: Option<u32>,
    /// The big-blind seat, on `deal`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bb: Option<u32>,
    /// `false` on a fold-out `win`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub showdown: Option<bool>,
    /// Who collected what, on `showdown`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub winners: Option<Vec<Winner>>,
}

impl LogEntry {
    fn ev(ev: &str) -> Self {
        Self {
            ev: ev.to_string(),
            ..Self::default()
        }
    }
}

/// A pot and who could win it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pot {
    /// Chips in it.
    pub amount: u64,
    /// Seats eligible for it.
    pub contenders: Vec<u32>,
    /// Seats that won it.
    pub winners: Vec<u32>,
}

/// A shown hand at showdown: its evaluation and spoken name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedEval {
    /// Category.
    pub cat: u8,
    /// Tie-break ranks.
    pub kick: Vec<u8>,
    /// Comparable score.
    pub score: u64,
    /// Spoken name.
    pub name: String,
}

/// Chips a seat collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Winner {
    /// The seat.
    pub seat: u32,
    /// Chips collected, the seat's own commitment included.
    pub amount: u64,
}

/// How a finished hand came out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandResult {
    /// Cards were shown (false when everyone else folded).
    pub showdown: bool,
    /// The pots after side-pot slicing.
    pub pots: Vec<Pot>,
    /// Shown hands by seat, only at a showdown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evals: Option<std::collections::BTreeMap<String, NamedEval>>,
    /// Who collected what, by seat.
    pub winners: Vec<Winner>,
}

/// A seat in a new hand's configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeatConfig {
    /// Display name.
    pub name: String,
    /// Starting stack; zero sits the seat out.
    pub stack: u64,
}

/// Everything a new hand needs (`newHand`'s argument).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandConfig {
    /// The seats, in seat order.
    pub seats: Vec<SeatConfig>,
    /// The dealer button's seat.
    pub button: u32,
    /// Small blind.
    pub sb: u64,
    /// Big blind.
    pub bb: u64,
    /// Ante, zero for none.
    #[serde(default)]
    pub ante: u64,
    /// The 64-hex shuffle seed.
    pub seed_hex: String,
    /// Fixed-limit betting.
    #[serde(default)]
    pub limit: bool,
}

/// An action message: what a seat does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    /// The acting seat.
    pub seat: u32,
    /// `fold`, `check`, `call`, `bet` or `raise`.
    pub action: String,
    /// The total a bet or raise goes to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
}

/// The actions open to the seat to act (`legal`). In fixed-limit the raise
/// total is one fixed number (`min_raise_to == max_raise_to`) and the street
/// caps out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Legal {
    /// The seat to act.
    pub seat: u32,
    /// Some of `fold`, `check`, `call`, `bet`, `raise`.
    pub actions: Vec<String>,
    /// Chips needed to call.
    pub call_amount: u64,
    /// The smallest total a bet or raise may go to.
    pub min_raise_to: u64,
    /// The largest total a bet or raise may go to.
    pub max_raise_to: u64,
    /// The bet to match on this street.
    pub current_bet: u64,
}

impl Legal {
    /// Whether `action` is open.
    pub fn allows(&self, action: &str) -> bool {
        self.actions.iter().any(|a| a == action)
    }
}

/// A seat as another seat sees it (`seatView`'s seats).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewSeat {
    /// Display name.
    pub name: String,
    /// Chips behind.
    pub stack: u64,
    /// Folded this hand.
    pub folded: bool,
    /// All chips committed.
    pub all_in: bool,
    /// Sitting out.
    pub out: bool,
    /// Committed on the current street.
    pub street_commit: u64,
    /// Committed over the whole hand.
    pub hand_commit: u64,
    /// Hole cards: the viewer's own, and hands shown down.
    pub hole: Option<Vec<u8>>,
}

/// What one seat may see of the hand (`seatView`): the multiplayer seam. A
/// remote player gets exactly this and nothing more.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeatView {
    /// The viewing seat.
    pub seat: u32,
    /// `preflop`, `flop`, `turn` or `river`.
    pub street: String,
    /// Community cards dealt so far.
    pub board: Vec<u8>,
    /// `act` or `done`.
    pub phase: String,
    /// The seat to act, or `-1`.
    pub to_act: i32,
    /// The bet to match on this street.
    pub current_bet: u64,
    /// The smallest raise total, when the viewer is to act.
    pub min_raise_to: Option<u64>,
    /// The dealer button's seat.
    pub button: u32,
    /// Small blind.
    pub sb: u64,
    /// Big blind.
    pub bb: u64,
    /// The viewer's hole cards.
    pub hole: Option<Vec<u8>>,
    /// Every chip committed this hand.
    pub pot: u64,
    /// All seats, masked for the viewer.
    pub seats: Vec<ViewSeat>,
    /// Set once the hand is over.
    pub result: Option<HandResult>,
}

/// The whole hand state, as `newHand` builds it and `act` advances it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hand {
    /// Number of seats.
    pub n: u32,
    /// The dealer button's seat.
    pub button: u32,
    /// Small blind.
    pub sb: u64,
    /// Big blind.
    pub bb: u64,
    /// Ante.
    pub ante: u64,
    /// The shuffle seed.
    pub seed_hex: String,
    /// The shuffled deck.
    pub deck: Vec<u8>,
    /// Cards dealt from the deck so far.
    pub deck_pos: usize,
    /// Community cards.
    pub board: Vec<u8>,
    /// `0` preflop … `3` river.
    pub street: u8,
    /// The seats.
    pub seats: Vec<Seat>,
    /// The bet to match on this street.
    pub current_bet: u64,
    /// The size of the last full raise, the smallest allowed next.
    pub min_raise_size: u64,
    /// Fixed-limit betting.
    pub limit: bool,
    /// Bets and raises allowed per street in fixed-limit.
    pub limit_cap: u32,
    /// Bets and raises so far this street (the big blind counts preflop).
    pub street_raises: u32,
    /// The seat to act, or `-1`.
    pub to_act: i32,
    /// `act` or `done`.
    pub phase: String,
    /// Everything that happened, in order.
    pub log: Vec<LogEntry>,
    /// Set once the hand is over.
    pub result: Option<HandResult>,
    /// Two live seats at the deal.
    pub heads_up: bool,
    /// Small-blind seat.
    pub sb_seat: u32,
    /// Big-blind seat.
    pub bb_seat: u32,
}

impl Hand {
    /// Whether the hand is still being played.
    pub fn in_play(&self) -> bool {
        self.phase == "act"
    }

    fn order(&self, from: i64) -> Vec<usize> {
        let n = i64::from(self.n);
        (0..n)
            .map(|k| (((from + k) % n + n) % n) as usize)
            .collect()
    }

    fn commit(&mut self, i: usize, amount: u64, why: Option<&str>) -> u64 {
        let s = &mut self.seats[i];
        let put = amount.min(s.stack);
        s.stack -= put;
        s.street_commit += put;
        s.hand_commit += put;
        if s.stack == 0 {
            s.all_in = true;
        }
        if let Some(why) = why {
            self.log.push(LogEntry {
                seat: Some(i as u32),
                amount: Some(put),
                ..LogEntry::ev(why)
            });
        }
        put
    }

    fn in_hand(&self, i: usize) -> bool {
        !self.seats[i].out && !self.seats[i].folded
    }

    fn can_act(&self, i: usize) -> bool {
        self.in_hand(i) && !self.seats[i].all_in
    }

    fn next_actor(&self, from: i64) -> i32 {
        self.order(from)
            .into_iter()
            .find(|&i| self.can_act(i))
            .map_or(-1, |i| i as i32)
    }

    fn live_seats(&self) -> Vec<usize> {
        (0..self.seats.len()).filter(|&i| self.in_hand(i)).collect()
    }

    fn deal_card(&mut self) -> u8 {
        let c = self.deck[self.deck_pos];
        self.deck_pos += 1;
        c
    }

    fn advance(&mut self) {
        let live = self.live_seats();
        if live.len() == 1 {
            return self.finish();
        }
        let actors: Vec<usize> = live.iter().copied().filter(|&i| self.can_act(i)).collect();
        let settled = actors
            .iter()
            .all(|&i| self.seats[i].acted && self.seats[i].street_commit == self.current_bet);
        if !settled {
            self.to_act = self.next_actor(i64::from(self.to_act) + 1);
            if self.to_act == -1 {
                return self.run_out();
            }
            return;
        }
        if actors.len() <= 1 {
            return self.run_out();
        }
        if self.street == 3 {
            return self.finish();
        }
        self.next_street();
    }

    fn deal_street_cards(&mut self) {
        if self.street == 1 {
            for _ in 0..3 {
                let c = self.deal_card();
                self.board.push(c);
            }
        } else {
            let c = self.deal_card();
            self.board.push(c);
        }
    }

    fn next_street(&mut self) {
        self.street += 1;
        for s in &mut self.seats {
            s.street_commit = 0;
            s.acted = false;
            s.can_raise = true;
        }
        self.current_bet = 0;
        self.min_raise_size = self.bb;
        self.street_raises = 0;
        self.deal_street_cards();
        self.log.push(LogEntry {
            street: Some(STREETS[self.street as usize].to_string()),
            board: Some(self.board.clone()),
            ..LogEntry::ev("street")
        });
        self.to_act = self.next_actor(i64::from(self.button) + 1);
        if self.to_act == -1 {
            return self.run_out();
        }
        if self.heads_up {
            let button = self.button as usize;
            if let Some(nb) = self.live_seats().into_iter().find(|&i| i != button) {
                if self.can_act(nb) {
                    self.to_act = nb as i32;
                }
            }
        }
    }

    fn run_out(&mut self) {
        while self.street < 3 {
            self.street += 1;
            self.deal_street_cards();
        }
        self.log.push(LogEntry {
            board: Some(self.board.clone()),
            ..LogEntry::ev("runout")
        });
        self.finish();
    }

    fn finish(&mut self) {
        self.phase = "done".to_string();
        self.to_act = -1;
        let live = self.live_seats();

        // refund the uncalled tail of the highest commitment (to a live seat
        // only; a folded seat's chips are dead money and flow into the pots)
        let commits: Vec<u64> = self.seats.iter().map(|s| s.hand_commit).collect();
        let mut sorted = commits.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        if sorted.len() > 1 && sorted[0] > sorted[1] {
            let top = commits.iter().position(|&c| c == sorted[0]).unwrap_or(0);
            if self.in_hand(top) {
                let refund = sorted[0] - sorted[1];
                self.seats[top].stack += refund;
                self.seats[top].hand_commit -= refund;
                if refund > 0 {
                    self.log.push(LogEntry {
                        seat: Some(top as u32),
                        amount: Some(refund),
                        ..LogEntry::ev("refund")
                    });
                }
            }
        }

        // fold-out: a single live seat scoops without showdown
        if live.len() == 1 {
            let total: u64 = self.seats.iter().map(|s| s.hand_commit).sum();
            let w = live[0];
            self.seats[w].stack += total;
            let live32: Vec<u32> = vec![w as u32];
            self.result = Some(HandResult {
                showdown: false,
                pots: vec![Pot {
                    amount: total,
                    contenders: live32.clone(),
                    winners: live32,
                }],
                evals: None,
                winners: vec![Winner {
                    seat: w as u32,
                    amount: total,
                }],
            });
            self.log.push(LogEntry {
                seat: Some(w as u32),
                amount: Some(total),
                showdown: Some(false),
                ..LogEntry::ev("win")
            });
            return;
        }

        // side pots from capped live commitments
        let mut levels: Vec<u64> = live
            .iter()
            .map(|&i| self.seats[i].hand_commit)
            .filter(|&c| c > 0)
            .collect();
        levels.sort_unstable();
        levels.dedup();
        let mut pots: Vec<(u64, Vec<usize>)> = Vec::new();
        let mut prev = 0u64;
        let mut sliced = 0u64;
        for lv in levels {
            let amount: u64 = self
                .seats
                .iter()
                .map(|s| s.hand_commit.min(lv).saturating_sub(prev))
                .sum();
            let contenders: Vec<usize> = live
                .iter()
                .copied()
                .filter(|&i| self.seats[i].hand_commit >= lv)
                .collect();
            if !contenders.is_empty() && amount > 0 {
                pots.push((amount, contenders));
                sliced += amount;
            }
            prev = lv;
        }
        let total: u64 = self.seats.iter().map(|s| s.hand_commit).sum();
        let leftover = total - sliced;
        if leftover > 0 {
            if let Some(last) = pots.last_mut() {
                last.0 += leftover;
            }
        }
        let mut merged: Vec<(u64, Vec<usize>)> = Vec::new();
        for p in pots {
            match merged.last_mut() {
                Some(last) if last.1 == p.1 => last.0 += p.0,
                _ => merged.push(p),
            }
        }

        let mut evals: std::collections::BTreeMap<usize, Eval> = Default::default();
        for &i in &live {
            let mut cards = self.seats[i].hole.clone().unwrap_or_default();
            cards.extend_from_slice(&self.board);
            evals.insert(i, evaluate(&cards));
        }
        let mut winners_total: std::collections::BTreeMap<usize, u64> = Default::default();
        let mut out_pots = Vec::new();
        for (amount, contenders) in merged {
            let best = contenders.iter().map(|i| evals[i].score).max().unwrap_or(0);
            let winners: Vec<usize> = contenders
                .iter()
                .copied()
                .filter(|i| evals[i].score == best)
                .collect();
            let share = amount / winners.len() as u64;
            let mut remainder = amount - share * winners.len() as u64;
            // odd chips go first to the earliest winner left of the button
            let clockwise: Vec<usize> = self
                .order(i64::from(self.button) + 1)
                .into_iter()
                .filter(|i| winners.contains(i))
                .collect();
            for i in clockwise {
                let extra = u64::from(remainder > 0);
                let got = share + extra;
                remainder -= extra;
                self.seats[i].stack += got;
                *winners_total.entry(i).or_default() += got;
            }
            out_pots.push(Pot {
                amount,
                contenders: contenders.iter().map(|&i| i as u32).collect(),
                winners: winners.iter().map(|&i| i as u32).collect(),
            });
        }
        let named: std::collections::BTreeMap<String, NamedEval> = evals
            .into_iter()
            .map(|(i, e)| {
                let name = hand_name(&e);
                (
                    i.to_string(),
                    NamedEval {
                        cat: e.cat,
                        kick: e.kick,
                        score: e.score,
                        name,
                    },
                )
            })
            .collect();
        let winners: Vec<Winner> = winners_total
            .into_iter()
            .map(|(seat, amount)| Winner {
                seat: seat as u32,
                amount,
            })
            .collect();
        self.log.push(LogEntry {
            winners: Some(winners.clone()),
            ..LogEntry::ev("showdown")
        });
        self.result = Some(HandResult {
            showdown: true,
            pots: out_pots,
            evals: Some(named),
            winners,
        });
    }
}

/// Deal a hand (`newHand`): shuffle from the seed, post antes and blinds, deal
/// two cards to every seat with chips, and name the first to act.
pub fn new_hand(cfg: &HandConfig) -> Result<Hand, EngineError> {
    let deck = shuffled_deck(&cfg.seed_hex)?;
    let n = cfg.seats.len() as u32;
    let mut h = Hand {
        n,
        button: cfg.button,
        sb: cfg.sb,
        bb: cfg.bb,
        ante: cfg.ante,
        seed_hex: cfg.seed_hex.clone(),
        deck,
        deck_pos: 0,
        board: Vec::new(),
        street: 0,
        seats: cfg
            .seats
            .iter()
            .map(|s| Seat {
                name: s.name.clone(),
                start_stack: s.stack,
                stack: s.stack,
                hole: None,
                folded: false,
                all_in: false,
                out: s.stack == 0,
                street_commit: 0,
                hand_commit: 0,
                can_raise: true,
                acted: false,
            })
            .collect(),
        current_bet: 0,
        min_raise_size: cfg.bb,
        limit: cfg.limit,
        limit_cap: 4,
        street_raises: u32::from(cfg.limit),
        to_act: -1,
        phase: "act".to_string(),
        log: Vec::new(),
        result: None,
        heads_up: false,
        sb_seat: 0,
        bb_seat: 0,
    };
    let live: Vec<usize> = h
        .order(i64::from(cfg.button) + 1)
        .into_iter()
        .filter(|&i| !h.seats[i].out)
        .collect();
    if live.len() < 2 {
        return Err(EngineError("need two players".into()));
    }
    if cfg.ante > 0 {
        for &i in &live {
            let put = cfg.ante.min(h.seats[i].stack);
            h.commit(i, put, Some("ante"));
        }
    }
    let heads_up = live.len() == 2;
    let button = cfg.button as usize;
    let sb_seat = if heads_up { button } else { live[0] };
    let bb_seat = if heads_up {
        live.iter()
            .copied()
            .find(|&i| i != button)
            .unwrap_or(live[1])
    } else {
        live[1]
    };
    let sb_put = cfg.sb.min(h.seats[sb_seat].stack);
    h.commit(sb_seat, sb_put, Some("sb"));
    let bb_put = cfg.bb.min(h.seats[bb_seat].stack);
    h.commit(bb_seat, bb_put, Some("bb"));
    h.current_bet = h.seats.iter().map(|s| s.street_commit).max().unwrap_or(0);
    h.min_raise_size = cfg.bb;

    for _round in 0..2 {
        for i in h.order(i64::from(cfg.button) + 1) {
            if h.seats[i].out {
                continue;
            }
            let c = h.deal_card();
            h.seats[i].hole.get_or_insert_with(Vec::new).push(c);
        }
    }
    h.to_act = if heads_up {
        sb_seat as i32
    } else {
        h.next_actor(bb_seat as i64 + 1)
    };
    h.heads_up = heads_up;
    h.sb_seat = sb_seat as u32;
    h.bb_seat = bb_seat as u32;
    h.log.push(LogEntry {
        sb: Some(sb_seat as u32),
        bb: Some(bb_seat as u32),
        ..LogEntry::ev("deal")
    });
    // the blinds may have put everyone all-in before any action
    let actors = h.live_seats().into_iter().filter(|&i| h.can_act(i)).count();
    if actors == 0 {
        h.run_out();
    }
    Ok(h)
}

/// The legal envelope for the seat to act, `None` once the hand is over.
pub fn legal(h: &Hand) -> Option<Legal> {
    if !h.in_play() {
        return None;
    }
    let i = h.to_act as usize;
    let s = &h.seats[i];
    let call_amt = (h.current_bet.saturating_sub(s.street_commit)).min(s.stack);
    let mut acts = vec!["fold".to_string()];
    acts.push(if call_amt == 0 { "check" } else { "call" }.to_string());
    let mut max_to = s.street_commit + s.stack;
    let mut min_to = h.current_bet + h.min_raise_size;
    let mut may_raise = max_to > h.current_bet && s.can_raise;
    if h.limit {
        let bet_size = if h.street <= 1 { h.bb } else { h.bb * 2 };
        if h.street_raises >= h.limit_cap {
            may_raise = false;
        }
        min_to = (h.current_bet + bet_size).min(s.street_commit + s.stack);
        max_to = if may_raise {
            min_to
        } else {
            s.street_commit + s.stack
        };
    }
    if may_raise {
        acts.push(if h.current_bet == 0 { "bet" } else { "raise" }.to_string());
        if min_to > max_to {
            min_to = max_to; // all-in for less than a min-raise
        }
    }
    Some(Legal {
        seat: i as u32,
        actions: acts,
        call_amount: call_amt,
        min_raise_to: min_to,
        max_raise_to: max_to,
        current_bet: h.current_bet,
    })
}

/// Apply an action (`act`), returning the advanced hand.
pub fn act(h: &Hand, action: &Action) -> Result<Hand, EngineError> {
    if !h.in_play() {
        return Err(EngineError("hand is over".into()));
    }
    if i64::from(action.seat) != i64::from(h.to_act) {
        return Err(EngineError(format!("not seat {}'s turn", action.seat)));
    }
    let l = legal(h).ok_or_else(|| EngineError("hand is over".into()))?;
    if !l.allows(&action.action) {
        return Err(EngineError(format!(
            "illegal {} (legal: {})",
            action.action,
            l.actions.join(",")
        )));
    }
    let mut h = h.clone();
    let seat = action.seat as usize;
    match action.action.as_str() {
        "fold" => {
            h.seats[seat].folded = true;
            h.log.push(LogEntry {
                seat: Some(action.seat),
                ..LogEntry::ev("fold")
            });
        }
        "check" => {
            h.log.push(LogEntry {
                seat: Some(action.seat),
                ..LogEntry::ev("check")
            });
        }
        "call" => {
            h.commit(seat, l.call_amount, None);
            h.log.push(LogEntry {
                seat: Some(action.seat),
                amount: Some(l.call_amount),
                ..LogEntry::ev("call")
            });
        }
        _ => {
            let amount = match action.amount {
                Some(a) if a >= l.min_raise_to && a <= l.max_raise_to => a,
                Some(a) => {
                    return Err(EngineError(format!(
                        "raise to {a} outside [{}, {}]",
                        l.min_raise_to, l.max_raise_to
                    )))
                }
                None => {
                    return Err(EngineError(format!(
                        "raise to undefined outside [{}, {}]",
                        l.min_raise_to, l.max_raise_to
                    )))
                }
            };
            let raise_size = amount.saturating_sub(h.current_bet);
            let full_raise = raise_size >= h.min_raise_size;
            h.street_raises += 1;
            let put = amount.saturating_sub(h.seats[seat].street_commit);
            h.commit(seat, put, None);
            let ev = if h.current_bet == 0 { "bet" } else { "raise" };
            h.log.push(LogEntry {
                seat: Some(action.seat),
                to: Some(amount),
                ..LogEntry::ev(ev)
            });
            h.current_bet = amount;
            if full_raise {
                h.min_raise_size = raise_size;
                for (k, s) in h.seats.iter_mut().enumerate() {
                    if k != seat {
                        s.can_raise = true;
                        s.acted = false;
                    }
                }
            } else {
                // under-raise all-in: seats that already acted may call but
                // not re-raise
                for (k, s) in h.seats.iter_mut().enumerate() {
                    if k != seat && s.acted {
                        s.can_raise = false;
                    }
                }
            }
        }
    }
    h.seats[seat].acted = true;
    h.advance();
    Ok(h)
}

/// What `seat` may see of the hand (`seatView`): its own hole cards, the
/// board, every stack and commitment, and other seats' hole cards only once
/// they were shown down.
pub fn seat_view(h: &Hand, seat: u32) -> SeatView {
    let min_raise_to = if h.in_play() && h.to_act == seat as i32 {
        legal(h).map(|l| l.min_raise_to)
    } else {
        None
    };
    let shown = |i: usize, s: &Seat| -> bool {
        i == seat as usize
            || (!h.in_play()
                && h.result.as_ref().is_some_and(|r| r.showdown)
                && !s.folded
                && !s.out)
    };
    SeatView {
        seat,
        street: STREETS[h.street as usize].to_string(),
        board: h.board.clone(),
        phase: h.phase.clone(),
        to_act: h.to_act,
        current_bet: h.current_bet,
        min_raise_to,
        button: h.button,
        sb: h.sb,
        bb: h.bb,
        hole: h.seats.get(seat as usize).and_then(|s| s.hole.clone()),
        pot: h.seats.iter().map(|s| s.hand_commit).sum(),
        seats: h
            .seats
            .iter()
            .enumerate()
            .map(|(i, s)| ViewSeat {
                name: s.name.clone(),
                stack: s.stack,
                folded: s.folded,
                all_in: s.all_in,
                out: s.out,
                street_commit: s.street_commit,
                hand_commit: s.hand_commit,
                hole: if shown(i, s) { s.hole.clone() } else { None },
            })
            .collect(),
        result: if h.in_play() { None } else { h.result.clone() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(seed: &str, limit: bool) -> HandConfig {
        HandConfig {
            seats: vec![
                SeatConfig {
                    name: "You".into(),
                    stack: 2000,
                },
                SeatConfig {
                    name: "Bot".into(),
                    stack: 2000,
                },
            ],
            button: 0,
            sb: 10,
            bb: 20,
            ante: 0,
            seed_hex: seed.into(),
            limit,
        }
    }

    #[test]
    fn a_bad_seed_is_refused() {
        assert_eq!(
            Rng::from_seed("abc").unwrap_err().0,
            "seed must be 64 hex chars"
        );
        assert!(new_hand(&cfg("zz", true)).is_err());
    }

    #[test]
    fn the_zero_seed_falls_back_to_the_golden_ratio_lane() {
        let mut z = Rng::from_seed(&"0".repeat(64)).unwrap();
        let mut g = Rng {
            a: 0x9e37_79b9,
            b: 0,
            c: 0,
            d: 0,
        };
        assert_eq!(z.draw(), g.draw());
    }

    #[test]
    fn heads_up_the_button_posts_the_small_blind_and_acts_first() {
        let h = new_hand(&cfg(&"ab".repeat(32), true)).unwrap();
        assert_eq!(h.sb_seat, 0);
        assert_eq!(h.bb_seat, 1);
        assert_eq!(h.to_act, 0);
        assert_eq!(h.seats[0].street_commit, 10);
        assert_eq!(h.seats[1].street_commit, 20);
        assert_eq!(h.current_bet, 20);
        assert_eq!(h.deck_pos, 4);
        assert_eq!(h.log[0].ev, "sb");
        assert_eq!(h.log[2].ev, "deal");
    }

    #[test]
    fn limit_raise_is_one_fixed_number_and_caps_at_four() {
        let h = new_hand(&cfg(&"cd".repeat(32), true)).unwrap();
        let l = legal(&h).unwrap();
        assert_eq!(l.actions, ["fold", "call", "raise"]);
        assert_eq!((l.min_raise_to, l.max_raise_to), (40, 40));
        let raise = |h: &Hand| {
            let l = legal(h).unwrap();
            act(
                h,
                &Action {
                    seat: l.seat,
                    action: "raise".into(),
                    amount: Some(l.min_raise_to),
                },
            )
            .unwrap()
        };
        let h = raise(&h); // 2 raises (bb counted as the first)
        let h = raise(&h); // 3
        let h = raise(&h); // 4: capped
        let l = legal(&h).unwrap();
        assert_eq!(l.actions, ["fold", "call"]);
        assert_eq!(h.street_raises, 4);
    }

    #[test]
    fn a_fold_ends_the_hand_without_showdown() {
        let h = new_hand(&cfg(&"ef".repeat(32), true)).unwrap();
        let h = act(
            &h,
            &Action {
                seat: 0,
                action: "fold".into(),
                amount: None,
            },
        )
        .unwrap();
        assert!(!h.in_play());
        let r = h.result.unwrap();
        assert!(!r.showdown);
        assert_eq!(
            r.winners,
            [Winner {
                seat: 1,
                amount: 20
            }]
        );
        assert!(r.evals.is_none());
        assert_eq!(h.seats[1].stack, 2010);
        assert_eq!(h.seats[0].stack, 1990);
    }

    #[test]
    fn acting_out_of_turn_or_illegally_is_refused() {
        let h = new_hand(&cfg(&"01".repeat(32), true)).unwrap();
        let e = act(
            &h,
            &Action {
                seat: 1,
                action: "fold".into(),
                amount: None,
            },
        )
        .unwrap_err();
        assert_eq!(e.0, "not seat 1's turn");
        let e = act(
            &h,
            &Action {
                seat: 0,
                action: "check".into(),
                amount: None,
            },
        )
        .unwrap_err();
        assert_eq!(e.0, "illegal check (legal: fold,call,raise)");
        let e = act(
            &h,
            &Action {
                seat: 0,
                action: "raise".into(),
                amount: Some(41),
            },
        )
        .unwrap_err();
        assert_eq!(e.0, "raise to 41 outside [40, 40]");
    }

    #[test]
    fn the_view_hides_the_other_hole_cards_until_a_showdown() {
        let h = new_hand(&cfg(&"23".repeat(32), true)).unwrap();
        let v = seat_view(&h, 0);
        assert!(v.seats[0].hole.is_some());
        assert!(v.seats[1].hole.is_none());
        assert_eq!(v.hole, h.seats[0].hole);
        assert_eq!(v.min_raise_to, Some(40));
        assert_eq!(seat_view(&h, 1).min_raise_to, None);
        assert_eq!(v.pot, 30);
    }

    #[test]
    fn evaluator_categories() {
        // A♠ K♠ Q♠ J♠ T♠ = royal flush
        let royal = [12 + 39, 11 + 39, 10 + 39, 9 + 39, 8 + 39];
        let e = evaluate(&royal);
        assert_eq!((e.cat, e.kick.clone()), (8, vec![12]));
        assert_eq!(hand_name(&e), "a royal flush");
        // wheel: A 2 3 4 5 off-suit
        let wheel = [12, 13, 1 + 26, 2 + 39, 3];
        let e = evaluate(&wheel);
        assert_eq!((e.cat, e.kick.clone()), (4, vec![3]));
        assert_eq!(hand_name(&e), "a straight, five high");
        // two pair kings and nines, ace kicker
        let tp = [11, 11 + 13, 7, 7 + 26, 12 + 39];
        let e = evaluate(&tp);
        assert_eq!((e.cat, e.kick.clone()), (2, vec![11, 7, 12]));
        assert_eq!(hand_name(&e), "two pair, kings and nines");
        assert_eq!(
            hand_name(&evaluate(&[4, 4 + 13, 0, 1 + 26, 9])),
            "a pair of sixes"
        );
        assert_eq!(best_five(&[1, 2, 3]), vec![1, 2, 3]);
    }

    #[test]
    fn card_codes_round_trip() {
        for c in 0..52u8 {
            assert_eq!(card_of_code(&card_code(c)), Some(c));
        }
        assert_eq!(card_code(24), "Kd");
        assert_eq!(card_name(24), "K♦");
        assert_eq!(card_of_code("Kx"), None);
        assert_eq!(card_of_code("K"), None);
    }
}
