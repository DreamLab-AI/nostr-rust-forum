//! Settlement rules for heads-up poker hands played for an issued asset
//! (DREAM on `sidestr:dreamlab`): the money phase of the forum's table.
//!
//! The money model is deliberately small. Each hand is played for a fixed
//! **buy-in**: both seats — the member (the *hero*) and the house seat (the
//! *citizen*) — must cover it before the deal, and both start the hand with
//! exactly that stack. When the hand ends, the loser owes the winner exactly
//! the hero's stack delta, `hero_stack_after − buyin`; a positive delta is
//! paid by the citizen to the hero, a negative one by the hero to the citizen,
//! and a split pot moves nothing. Because every chip in the hand came out of
//! the two buy-ins, a delta beyond `±buyin` is impossible in an honest hand
//! and is refused rather than paid.
//!
//! Stakes are a unit of the big blind: the small blind is half the big blind
//! and the buy-in a fixed number of big blinds ([`stakes_of`]), so a limit
//! hand at 100/200 owes exactly ten times the same hand at 10/20.
//!
//! A settlement transfer is tied to the hand it pays for by a memo,
//! `hand:<root>` ([`hand_memo`], [`parse_hand_memo`]), where the root is the
//! SHA-256 of the hand record's RFC 8785 (JCS) canonical bytes
//! ([`hand_root`], [`HandRecord::root`]). The root commits to the whole hand —
//! seed, seats, actions and result — rather than to the seed alone, so two
//! parties holding the same record derive the same memo, and a payer can
//! never attach a settlement to a different hand dealt from the same seed.
//!
//! Everything here is pure: no DOM, no network, no clock, so it is tested
//! natively and compiles unchanged for `wasm32-unknown-unknown`. It was first
//! written in the forum client (`wallet::poker`) and moved here so the house
//! seat and the member's browser settle by one copy of the rules.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The big blinds a table may run at, in DREAM base units: 1/2, 5/10, 10/20,
/// 50/100 and 100/200.
pub const STAKES_BB: [u64; 5] = [2, 10, 20, 100, 200];

/// The memo prefix that marks a transfer as the settlement of one hand.
pub const HAND_PREFIX: &str = "hand:";

/// One table size: blinds, buy-in and the label the picker shows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stakes {
    /// The big blind, in base units.
    pub bb: u64,
    /// The small blind: always half the big blind.
    pub sb: u64,
    /// The buy-in each seat covers for every hand: a whole number of big
    /// blinds.
    pub buyin: u64,
    /// The human label, `"<sb>/<bb>"` (for example `"10/20"`).
    pub label: String,
}

/// The stakes for a big blind of `bb` and a buy-in of `buyin_bb` big blinds.
///
/// `None` when the big blind is zero or odd (the small blind must be a whole
/// unit), when the buy-in is zero big blinds, or when the buy-in overflows.
pub fn stakes_of(bb: u64, buyin_bb: u64) -> Option<Stakes> {
    if bb == 0 || bb % 2 != 0 || buyin_bb == 0 {
        return None;
    }
    let sb = bb / 2;
    let buyin = buyin_bb.checked_mul(bb)?;
    Some(Stakes {
        bb,
        sb,
        buyin,
        label: format!("{sb}/{bb}"),
    })
}

/// The stakes for each big blind in `stakes_bb`, in order, each with a buy-in
/// of `buyin_bb` big blinds. Sizes [`stakes_of`] refuses, and repeats of an
/// earlier size, are left out.
pub fn stakes_table(stakes_bb: &[u64], buyin_bb: u64) -> Vec<Stakes> {
    let mut table: Vec<Stakes> = Vec::with_capacity(stakes_bb.len());
    for &bb in stakes_bb {
        if table.iter().any(|s| s.bb == bb) {
            continue;
        }
        if let Some(s) = stakes_of(bb, buyin_bb) {
            table.push(s);
        }
    }
    table
}

/// A seat at a heads-up table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Side {
    /// The member playing the hand.
    Hero,
    /// The house seat the member plays against.
    Citizen,
}

/// What a finished hand owes: one transfer from the loser to the winner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settlement {
    /// The seat that pays (the loser).
    pub from: Side,
    /// The seat that is paid (the winner).
    pub to: Side,
    /// The amount in base units: never zero, never more than the buy-in.
    pub amount: u64,
}

/// Why a hand could not be settled or its record could not be rooted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PokerError {
    /// The hand is still being played.
    HandNotOver,
    /// The hero's stack moved by more than the buy-in, which no honest hand
    /// can do.
    ExceedsBuyin {
        /// The hero's stack delta, `hero_stack_after − buyin`.
        delta: i128,
        /// The buy-in the hand was played for.
        buyin: u64,
    },
    /// The stakes cannot carry a hand (for example a zero buy-in).
    BadStakes(String),
    /// The hand record is not JSON that RFC 8785 can canonicalise.
    Canonical(String),
}

impl fmt::Display for PokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HandNotOver => f.write_str("the hand is not over"),
            Self::ExceedsBuyin { delta, buyin } => write!(
                f,
                "a hand cannot move more than its buy-in (delta {delta}, buy-in {buyin})"
            ),
            Self::BadStakes(why) => write!(f, "bad stakes: {why}"),
            Self::Canonical(why) => write!(f, "cannot canonicalise the hand record: {why}"),
        }
    }
}

impl std::error::Error for PokerError {}

/// What a hand owes once it is over: the transfer the loser makes, or
/// `Ok(None)` for a split pot.
///
/// `hero_stack_after` is the hero's stack when the hand ended; the hand
/// started with both stacks at `buyin`.
pub fn settlement(
    hand_over: bool,
    hero_stack_after: u64,
    buyin: u64,
) -> Result<Option<Settlement>, PokerError> {
    if !hand_over {
        return Err(PokerError::HandNotOver);
    }
    if buyin == 0 {
        return Err(PokerError::BadStakes("the buy-in is zero".into()));
    }
    let delta = i128::from(hero_stack_after) - i128::from(buyin);
    if delta.unsigned_abs() > u128::from(buyin) {
        return Err(PokerError::ExceedsBuyin { delta, buyin });
    }
    // |delta| <= buyin, a u64, so the cast is lossless.
    let amount = delta.unsigned_abs() as u64;
    Ok(match delta.signum() {
        0 => None,
        1 => Some(Settlement {
            from: Side::Citizen,
            to: Side::Hero,
            amount,
        }),
        _ => Some(Settlement {
            from: Side::Hero,
            to: Side::Citizen,
            amount,
        }),
    })
}

/// The memo that ties a settlement transfer to its hand: `hand:<root>`.
///
/// `root` should be a [`hand_root`]; anything else yields a memo
/// [`parse_hand_memo`] refuses.
pub fn hand_memo(root: &str) -> String {
    format!("{HAND_PREFIX}{root}")
}

/// The hand root a settlement memo names, if `memo` is exactly `hand:`
/// followed by 64 lowercase hex digits.
pub fn parse_hand_memo(memo: &str) -> Option<&str> {
    let root = memo.strip_prefix(HAND_PREFIX)?;
    (root.len() == 64 && root.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .then_some(root)
}

/// The root of a hand record: lowercase hex SHA-256 of the RFC 8785 (JCS)
/// canonical bytes of the JSON document `record_json`.
///
/// The top-level `annotations` array, which HAND.md makes advisory, is left
/// out, so annotating a hand never changes its root. Everything else is
/// committed as given, so key order and whitespace do not matter but every
/// field does.
pub fn hand_root(record_json: &str) -> Result<String, PokerError> {
    let mut value: Value =
        serde_json::from_str(record_json).map_err(|e| PokerError::Canonical(e.to_string()))?;
    if let Value::Object(map) = &mut value {
        map.remove("annotations");
    }
    root_of(&value)
}

fn root_of(value: &Value) -> Result<String, PokerError> {
    let canonical = canonicalize(value)?;
    Ok(hex::encode(Sha256::digest(canonical.as_bytes())))
}

/// RFC 8785 canonical JSON of `value`: object members sorted by the UTF-16
/// code units of their names, no insignificant whitespace, strings escaped as
/// ECMAScript `JSON.stringify` does, and numbers in ECMAScript
/// `Number.prototype.toString` form.
///
/// Integers beyond ±(2⁵³ − 1) are refused: I-JSON, which JCS is defined
/// over, cannot carry them exactly.
pub fn canonicalize(value: &Value) -> Result<String, PokerError> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut String) -> Result<(), PokerError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&jcs_number(n)?),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            members.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, (key, item)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_canonical(item, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// A JSON string as `JSON.stringify` writes it: `"` and `\` escaped, the
/// controls below U+0020 as `\b \t \n \f \r` or lowercase `\u00xx`, and
/// everything else (including `/`, DEL and non-ASCII) literal.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The largest integer I-JSON carries exactly, 2⁵³ − 1.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

fn jcs_number(n: &serde_json::Number) -> Result<String, PokerError> {
    if let Some(u) = n.as_u64() {
        return if u <= MAX_SAFE_INTEGER {
            Ok(u.to_string())
        } else {
            Err(PokerError::Canonical(format!("{u} is beyond 2^53 - 1")))
        };
    }
    if let Some(i) = n.as_i64() {
        return if i.unsigned_abs() <= MAX_SAFE_INTEGER {
            Ok(i.to_string())
        } else {
            Err(PokerError::Canonical(format!("{i} is beyond -(2^53 - 1)")))
        };
    }
    let f = n
        .as_f64()
        .ok_or_else(|| PokerError::Canonical(format!("{n} is not a number")))?;
    es_number(f)
}

/// ECMAScript `Number.prototype.toString(10)` for a finite double (ECMA-262
/// § Number::toString), from Rust's shortest round-trip digits.
fn es_number(f: f64) -> Result<String, PokerError> {
    if !f.is_finite() {
        return Err(PokerError::Canonical(format!("{f} is not finite")));
    }
    if f == 0.0 {
        return Ok("0".into()); // -0 too
    }
    let sign = if f < 0.0 { "-" } else { "" };
    let (digits, exp) = es_digits(f.abs())?;
    let k = digits.len() as i32;
    // The value is 0.<digits> × 10^n.
    let n = exp + 1;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let e_sign = if e < 0 { '-' } else { '+' };
        let (head, tail) = digits.split_at(1);
        if tail.is_empty() {
            format!("{head}e{e_sign}{}", e.abs())
        } else {
            format!("{head}.{tail}e{e_sign}{}", e.abs())
        }
    };
    Ok(format!("{sign}{body}"))
}

/// Split Rust's scientific form `d[.ddd]e<exp>` into its digits and exponent.
fn split_sci(sci: &str) -> Result<(String, i32), PokerError> {
    let bad = || PokerError::Canonical(format!("unexpected float form {sci}"));
    let (mantissa, exp) = sci.split_once('e').ok_or_else(bad)?;
    let exp = exp.parse().map_err(|_| bad())?;
    Ok((mantissa.chars().filter(|c| *c != '.').collect(), exp))
}

/// The ECMAScript significand digits and decimal exponent of a positive
/// finite double: the shortest digits that round-trip and, of those, the
/// closest — and when two are equally close, the one with an even last digit.
///
/// Rust's `{:e}` gives the shortest closest digits but breaks an exact tie
/// upwards (`0x43143ff3c1cb0959` is exactly `…206.25`; Rust writes `…206.3`,
/// ECMAScript `…206.2`), so a tie is detected from the exact decimal
/// expansion and settled the ECMAScript way.
fn es_digits(f: f64) -> Result<(String, i32), PokerError> {
    let (digits, exp) = split_sci(&format!("{f:e}"))?;
    let k = digits.len();
    // Every double has a finite decimal expansion of at most 767 significant
    // digits, so 800 places is exact.
    let (exact, exact_exp) = split_sci(&format!("{f:.800e}"))?;
    let exact = exact.trim_end_matches('0');
    if exact_exp != exp || exact.len() != k + 1 || !exact.ends_with('5') {
        return Ok((digits, exp));
    }
    // A tie between truncating and rounding up at k digits.
    let low = exact[..k].to_string();
    let high = increment_decimal(&low);
    let round_trips = |d: &str| {
        d.len() == k && format!("{}.{}e{exp}", &d[..1], &d[1..]).parse::<f64>().ok() == Some(f)
    };
    let even = |d: &str| d.bytes().last().is_some_and(|b| (b - b'0') % 2 == 0);
    let chosen = [low, high]
        .into_iter()
        .filter(|d| round_trips(d))
        .min_by_key(|d| !even(d));
    Ok((chosen.unwrap_or(digits), exp))
}

/// A decimal digit string plus one in its last place (may grow by a digit).
fn increment_decimal(d: &str) -> String {
    let mut bytes = d.as_bytes().to_vec();
    for b in bytes.iter_mut().rev() {
        if *b == b'9' {
            *b = b'0';
        } else {
            *b += 1;
            return String::from_utf8(bytes).unwrap_or_default();
        }
    }
    let mut grown = String::from("1");
    grown.push_str(&String::from_utf8(bytes).unwrap_or_default());
    grown
}

/// The poker variant a hand was dealt under; it governs betting legality on
/// replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Variant {
    /// Fixed-limit Texas hold'em (`"holdem-limit"`).
    #[serde(rename = "holdem-limit")]
    HoldemLimit,
    /// No-limit Texas hold'em (`"holdem-nolimit"`).
    #[serde(rename = "holdem-nolimit")]
    HoldemNoLimit,
}

/// One seat of a hand record, in engine seat order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandSeat {
    /// The display name the seat played under.
    pub name: String,
    /// The seat's stack when the hand was dealt.
    pub start_stack: u64,
    /// The two hole cards (`lp:Card`, for example `"Kd"`), or `None` (JSON
    /// `null`) for a seat dealt out.
    pub hole: Option<Vec<String>>,
    /// The draft Agent marker for a declared machine, carried verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<Value>,
}

/// A betting street, as a log's street markers name it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Street {
    /// Three board cards dealt.
    Flop,
    /// The fourth board card dealt.
    Turn,
    /// The fifth board card dealt.
    River,
}

/// What a seat did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Act {
    /// Gave up the hand.
    Fold,
    /// Passed with nothing to call.
    Check,
    /// Matched the current bet.
    Call,
    /// Opened the betting on a street.
    Bet,
    /// Increased the current bet.
    Raise,
}

/// One entry of a hand's action log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HandAction {
    /// A seat acted.
    Act {
        /// The acting seat's index.
        seat: u32,
        /// The action.
        act: Act,
        /// For a bet or raise, the total the seat's street commitment is
        /// raised to.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to: Option<u64>,
        /// For a call, the chips added.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        amount: Option<u64>,
    },
    /// A street boundary: a reader's convenience, checked against the rules
    /// by a verifier.
    Street {
        /// The street that begins.
        street: Street,
    },
}

/// One share of the pot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Winner {
    /// The winning seat's index.
    pub seat: u32,
    /// The chips that seat collected.
    pub amount: u64,
}

/// How the chips moved: derivable from the replay, carried so light readers
/// can trust but verify.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandResult {
    /// Whether the hand reached a showdown.
    pub showdown: bool,
    /// The total pot.
    pub pot: u64,
    /// Who collected what.
    pub winners: Vec<Winner>,
}

/// A Libre Poker `Hand` record, v0 (HAND.md): the fields its root commits
/// to. The advisory `annotations` block is not part of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandRecord {
    /// The JSON-LD context, `"https://librepoker.org/context.jsonld"`.
    #[serde(rename = "@context", default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// The document type, `"Hand"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The format version, `0`.
    pub v: u32,
    /// The variant the hand was dealt under.
    pub variant: Variant,
    /// The 64-hex shuffle seed the deck regenerates from.
    pub seed: String,
    /// The small blind.
    pub sb: u64,
    /// The big blind.
    pub bb: u64,
    /// The ante (zero in heads-up limit).
    pub ante: u64,
    /// The dealer button's seat index.
    pub button: u32,
    /// The seats, in engine order.
    pub seats: Vec<HandSeat>,
    /// The board cards dealt, in order.
    pub board: Vec<String>,
    /// The action log, in order.
    pub actions: Vec<HandAction>,
    /// How the chips moved.
    pub result: HandResult,
}

impl HandRecord {
    /// The record's root, as [`hand_root`] computes it over this record's
    /// JSON. For a document holding only the fields this type carries, it
    /// equals `hand_root` of the original text.
    pub fn root(&self) -> Result<String, PokerError> {
        let value = serde_json::to_value(self).map_err(|e| PokerError::Canonical(e.to_string()))?;
        root_of(&value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HAND.md's example, `examples/hand-001.json`, verbatim.
    const HAND_001: &str = r#"{
  "@context": "https://librepoker.org/context.jsonld",
  "type": "Hand",
  "v": 0,
  "variant": "holdem-limit",
  "seed": "9b1f6c1f3d2a4e5b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b",
  "sb": 10, "bb": 20, "ante": 0,
  "button": 0,
  "seats": [
    { "name": "Gunner Halloway", "startStack": 1480, "hole": ["Qc", "7s"] },
    { "name": "You", "startStack": 1520, "hole": ["Kd", "6s"] }
  ],
  "board": ["8c", "4d", "4h", "8h", "9h"],
  "actions": [
    { "seat": 0, "act": "raise", "to": 40 },
    { "seat": 1, "act": "call", "amount": 20 },
    { "street": "flop" },
    { "seat": 1, "act": "bet", "to": 20 },
    { "seat": 0, "act": "call", "amount": 20 },
    { "street": "turn" },
    { "seat": 1, "act": "bet", "to": 40 },
    { "seat": 0, "act": "call", "amount": 40 },
    { "street": "river" },
    { "seat": 1, "act": "check" },
    { "seat": 0, "act": "check" }
  ],
  "result": {
    "showdown": true,
    "pot": 200,
    "winners": [ { "seat": 1, "amount": 200 } ]
  },
  "annotations": [
    { "action": 9, "mix": { "check": 0.01, "bet": 0.99 }, "evLossBb": 0.16, "exact": true }
  ]
}"#;

    fn ten_twenty() -> Stakes {
        stakes_of(20, 100).unwrap()
    }

    // --- settlement (sats-test.mjs) ---

    #[test]
    fn a_hand_still_being_played_has_no_settlement() {
        assert_eq!(
            settlement(false, 2_000, 2_000),
            Err(PokerError::HandNotOver)
        );
        assert_eq!(
            settlement(false, 1_990, 2_000),
            Err(PokerError::HandNotOver)
        );
    }

    #[test]
    fn a_split_pot_moves_nothing() {
        assert_eq!(settlement(true, 2_000, 2_000), Ok(None));
    }

    #[test]
    fn hero_folds_the_small_blind_and_owes_it() {
        let s = ten_twenty();
        assert_eq!(
            settlement(true, s.buyin - s.sb, s.buyin),
            Ok(Some(Settlement {
                from: Side::Hero,
                to: Side::Citizen,
                amount: 10
            }))
        );
    }

    #[test]
    fn hero_calls_then_folds_to_a_raise_and_owes_the_big_blind() {
        let s = ten_twenty();
        assert_eq!(
            settlement(true, s.buyin - s.bb, s.buyin),
            Ok(Some(Settlement {
                from: Side::Hero,
                to: Side::Citizen,
                amount: 20
            }))
        );
    }

    #[test]
    fn citizen_folds_to_a_three_bet_and_pays_the_hero() {
        assert_eq!(
            settlement(true, 2_040, 2_000),
            Ok(Some(Settlement {
                from: Side::Citizen,
                to: Side::Hero,
                amount: 40
            }))
        );
    }

    #[test]
    fn exactly_the_buy_in_either_way_is_allowed() {
        assert_eq!(
            settlement(true, 4_000, 2_000),
            Ok(Some(Settlement {
                from: Side::Citizen,
                to: Side::Hero,
                amount: 2_000
            }))
        );
        assert_eq!(
            settlement(true, 0, 2_000),
            Ok(Some(Settlement {
                from: Side::Hero,
                to: Side::Citizen,
                amount: 2_000
            }))
        );
    }

    #[test]
    fn beyond_the_buy_in_is_refused() {
        assert_eq!(
            settlement(true, 4_001, 2_000),
            Err(PokerError::ExceedsBuyin {
                delta: 2_001,
                buyin: 2_000
            })
        );
        assert!(matches!(
            settlement(true, u64::MAX, u64::MAX / 2),
            Err(PokerError::ExceedsBuyin { .. })
        ));
    }

    #[test]
    fn a_zero_buy_in_is_bad_stakes() {
        assert!(matches!(
            settlement(true, 0, 0),
            Err(PokerError::BadStakes(_))
        ));
    }

    #[test]
    fn at_100_200_the_folded_small_blind_owes_100() {
        let hi = stakes_of(200, 100).unwrap();
        assert_eq!(hi.buyin, 20_000);
        assert_eq!(
            settlement(true, hi.buyin - hi.sb, hi.buyin),
            Ok(Some(Settlement {
                from: Side::Hero,
                to: Side::Citizen,
                amount: 100
            }))
        );
    }

    #[test]
    fn errors_read_as_sentences() {
        assert_eq!(PokerError::HandNotOver.to_string(), "the hand is not over");
        assert!(PokerError::ExceedsBuyin {
            delta: -2_001,
            buyin: 2_000
        }
        .to_string()
        .contains("delta -2001"));
    }

    // --- stakes ---

    #[test]
    fn every_listed_size_is_half_and_a_hundred_big_blinds() {
        let labels = ["1/2", "5/10", "10/20", "50/100", "100/200"];
        for (bb, label) in STAKES_BB.iter().zip(labels) {
            let s = stakes_of(*bb, 100).unwrap();
            assert_eq!(s.bb, *bb);
            assert_eq!(s.sb * 2, *bb);
            assert_eq!(s.buyin, 100 * bb);
            assert_eq!(s.label, label);
        }
    }

    #[test]
    fn bogus_sizes_are_refused() {
        assert_eq!(stakes_of(7, 100), None);
        assert_eq!(stakes_of(0, 100), None);
        assert_eq!(stakes_of(20, 0), None);
        assert_eq!(stakes_of(u64::MAX - 1, 100), None);
    }

    #[test]
    fn the_table_keeps_order_and_drops_bad_and_repeated_sizes() {
        let t = stakes_table(&[20, 7, 2, 20, 0, 200], 50);
        let bbs: Vec<u64> = t.iter().map(|s| s.bb).collect();
        assert_eq!(bbs, [20, 2, 200]);
        assert_eq!(t[0].buyin, 1_000);
        assert_eq!(stakes_table(&STAKES_BB, 100).len(), STAKES_BB.len());
    }

    // --- memos ---

    #[test]
    fn a_memo_round_trips() {
        let root = hand_root(HAND_001).unwrap();
        let memo = hand_memo(&root);
        assert!(memo.starts_with(HAND_PREFIX));
        assert_eq!(parse_hand_memo(&memo), Some(root.as_str()));
    }

    #[test]
    fn malformed_memos_are_refused() {
        let ok = "0f".repeat(32);
        assert_eq!(parse_hand_memo(&ok), None, "no prefix");
        assert_eq!(parse_hand_memo(&format!("Hand:{ok}")), None, "prefix case");
        assert_eq!(parse_hand_memo(&format!("hand: {ok}")), None, "space");
        assert_eq!(parse_hand_memo(&format!("hand:{ok}0")), None, "65 digits");
        assert_eq!(parse_hand_memo(&format!("hand:{}", &ok[1..])), None, "63");
        assert_eq!(parse_hand_memo(&hand_memo(&"0F".repeat(32))), None, "upper");
        assert_eq!(
            parse_hand_memo(&hand_memo(&"0g".repeat(32))),
            None,
            "non-hex"
        );
        assert_eq!(parse_hand_memo("hand:"), None);
        assert_eq!(parse_hand_memo(""), None);
    }

    // --- roots ---

    #[test]
    fn the_root_is_deterministic_and_ignores_key_order_and_whitespace() {
        let a = hand_root(HAND_001).unwrap();
        // Pinned from an independent JavaScript computation (sorted-key
        // JSON.stringify of hand-001.json without annotations, then sha256).
        assert_eq!(
            a,
            "514301d45de5abe59e0185dc40864189e37db8540f703404b615b559e786b3c3"
        );
        assert_eq!(a, hand_root(HAND_001).unwrap());
        let reordered = r#"{"result":{"winners":[{"amount":200,"seat":1}],"pot":200,"showdown":true},
          "actions":[{"to":40,"act":"raise","seat":0},{"amount":20,"act":"call","seat":1},{"street":"flop"},
          {"to":20,"act":"bet","seat":1},{"amount":20,"act":"call","seat":0},{"street":"turn"},
          {"to":40,"act":"bet","seat":1},{"amount":40,"act":"call","seat":0},{"street":"river"},
          {"act":"check","seat":1},{"act":"check","seat":0}],
          "board":["8c","4d","4h","8h","9h"],"button":0,"ante":0,"bb":20,"sb":10,
          "seats":[{"hole":["Qc","7s"],"startStack":1480,"name":"Gunner Halloway"},
                   {"hole":["Kd","6s"],"startStack":1520,"name":"You"}],
          "seed":"9b1f6c1f3d2a4e5b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b",
          "variant":"holdem-limit","v":0,"type":"Hand","@context":"https://librepoker.org/context.jsonld"}"#;
        assert_eq!(a, hand_root(reordered).unwrap());
    }

    #[test]
    fn annotations_do_not_move_the_root_but_every_field_does() {
        let mut v: Value = serde_json::from_str(HAND_001).unwrap();
        let a = hand_root(HAND_001).unwrap();
        v.as_object_mut().unwrap().remove("annotations");
        assert_eq!(a, hand_root(&v.to_string()).unwrap());
        v["result"]["pot"] = 201.into();
        assert_ne!(a, hand_root(&v.to_string()).unwrap());
    }

    #[test]
    fn the_typed_record_roots_the_same_as_the_document() {
        let rec: HandRecord = serde_json::from_str(HAND_001).unwrap();
        assert_eq!(rec.variant, Variant::HoldemLimit);
        assert_eq!(rec.actions.len(), 11);
        assert_eq!(
            rec.actions[2],
            HandAction::Street {
                street: Street::Flop
            }
        );
        assert_eq!(rec.root().unwrap(), hand_root(HAND_001).unwrap());
    }

    #[test]
    fn a_non_json_record_is_refused() {
        assert!(matches!(hand_root("{"), Err(PokerError::Canonical(_))));
        assert!(matches!(
            hand_root(r#"{"pot": 9007199254740992}"#),
            Err(PokerError::Canonical(_))
        ));
        assert!(hand_root(r#"{"pot": 9007199254740991}"#).is_ok());
    }

    // --- RFC 8785 test vectors ---

    #[test]
    fn rfc8785_appendix_b_numbers() {
        let vectors: [(u64, &str); 23] = [
            (0x0000000000000000, "0"),
            (0x8000000000000000, "0"),
            (0x0000000000000001, "5e-324"),
            (0x8000000000000001, "-5e-324"),
            (0x7fefffffffffffff, "1.7976931348623157e+308"),
            (0xffefffffffffffff, "-1.7976931348623157e+308"),
            (0x4340000000000000, "9007199254740992"),
            (0xc340000000000000, "-9007199254740992"),
            (0x4430000000000000, "295147905179352830000"),
            (0x44b52d02c7e14af5, "9.999999999999997e+22"),
            (0x44b52d02c7e14af6, "1e+23"),
            (0x44b52d02c7e14af7, "1.0000000000000001e+23"),
            (0x444b1ae4d6e2ef4e, "999999999999999700000"),
            (0x444b1ae4d6e2ef4f, "999999999999999900000"),
            (0x444b1ae4d6e2ef50, "1e+21"),
            (0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"),
            (0x3eb0c6f7a0b5ed8d, "0.000001"),
            (0x41b3de4355555553, "333333333.3333332"),
            (0x41b3de4355555554, "333333333.33333325"),
            (0x41b3de4355555555, "333333333.3333333"),
            (0x41b3de4355555556, "333333333.3333334"),
            (0x41b3de4355555557, "333333333.33333343"),
            (0xbecbf647612f3696, "-0.0000033333333333333333"),
        ];
        for (bits, want) in vectors {
            assert_eq!(
                es_number(f64::from_bits(bits)).unwrap(),
                want,
                "{bits:#018x}"
            );
        }
        assert_eq!(
            es_number(f64::from_bits(0x43143ff3c1cb0959)).unwrap(),
            "1424953923781206.2"
        );
        assert!(es_number(f64::NAN).is_err());
        assert!(es_number(f64::INFINITY).is_err());
    }

    #[test]
    fn rfc8785_section_3_2_2_sample() {
        let input = r#"{
          "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
          "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
          "literals": [null, true, false]
        }"#;
        let v: Value = serde_json::from_str(input).unwrap();
        assert_eq!(
            canonicalize(&v).unwrap(),
            "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
        );
    }

    #[test]
    fn rfc8785_section_3_2_3_sorting() {
        let input = r#"{
          "\u20ac": "Euro Sign",
          "\r": "Carriage Return",
          "\ufb33": "Hebrew Letter Dalet With Dagesh",
          "1": "One",
          "\ud83d\ude00": "Emoji: Grinning Face",
          "\u0080": "Control",
          "\u00f6": "Latin Small Letter O With Diaeresis"
        }"#;
        let v: Value = serde_json::from_str(input).unwrap();
        assert_eq!(
            canonicalize(&v).unwrap(),
            "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\
             \"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\
             \"\u{1f600}\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}"
        );
    }

    #[test]
    fn rfc8785_escapes_controls_in_lowercase_and_leaves_the_rest() {
        let v = Value::String("\u{1}\u{8}\u{1f}\u{7f}/".into());
        assert_eq!(canonicalize(&v).unwrap(), "\"\\u0001\\b\\u001f\u{7f}/\"");
    }
}
