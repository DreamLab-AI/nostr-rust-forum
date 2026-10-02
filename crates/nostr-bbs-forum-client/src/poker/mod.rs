//! The practice poker table: its gates, its configuration, and the typed seam
//! to the vendored Libre Poker engine (`js/librepoker`, AGPL-3.0).
//!
//! Three things must all hold before the table shows anywhere, nav item or
//! route: the operator set `window.__ENV__.POKER = "on"`, the member wallet is
//! on (`window.__ENV__.SIDESTR_WALLET`), and the member ticked "Poker table" in
//! Settings → Games. The table plays practice chips only; nothing here reads
//! the wallet store or sends anything anywhere.
//!
//! The engine runs in JS behind `js/poker-table.js`, whose exports take and
//! return JSON strings. The hand state lives here between calls as
//! [`HandState`]: the engine's own JSON (passed back verbatim on the next call,
//! so no engine field is ever lost) beside a typed [`Hand`] parsed from it.
//! What the page draws comes from [`SeatView`] — the engine's view for the
//! hero's seat — so the bot's hole cards stay hidden until a showdown.

use std::collections::BTreeMap;

use leptos::prelude::*;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

use crate::stores::preferences::use_preferences;
use crate::utils::relay_url::env_override;

// -- JS interop with the engine ----------------------------------------------
//
// wasm-bindgen ships a local snippet as the text of that one file: it does not
// follow the file's own `import`s. The shim imports `./librepoker/poker.js` and
// `./librepoker/bots.js`, so each of those is also declared here, which makes
// wasm-bindgen write it to `snippets/<crate>-<hash>/js/librepoker/` beside the
// shim, where the shim's relative imports find it. The declarations below are
// the ones the table really uses from each file.

#[wasm_bindgen(module = "/js/librepoker/poker.js")]
extern "C" {
    #[wasm_bindgen(js_name = cardName)]
    fn js_card_name(card: u32) -> String;
}

#[wasm_bindgen(module = "/js/librepoker/bots.js")]
extern "C" {
    #[wasm_bindgen(thread_local_v2, js_name = ROSTER)]
    static BOT_ROSTER: JsValue;
}

#[wasm_bindgen(module = "/js/poker-table.js")]
extern "C" {
    #[wasm_bindgen(js_name = pokerNewHand)]
    fn js_new_hand(cfg_json: &str) -> String;

    #[wasm_bindgen(js_name = pokerLegal)]
    fn js_legal(hand_json: &str) -> String;

    #[wasm_bindgen(js_name = pokerAct)]
    fn js_act(hand_json: &str, action_json: &str) -> String;

    #[wasm_bindgen(js_name = pokerBotDecide)]
    fn js_bot_decide(hand_json: &str, seat: u32, profile: &str, seed_hex: &str) -> String;

    #[wasm_bindgen(js_name = pokerSeatView)]
    fn js_seat_view(hand_json: &str, seat: u32) -> String;

    #[wasm_bindgen(js_name = pokerHandName)]
    fn js_hand_name(cards_json: &str) -> String;
}

// -- Gates --------------------------------------------------------------------

/// Whether an operator flag value switches a feature on: `on`, `true` or `1`,
/// surrounding whitespace ignored — the matcher [`crate::wallet::enabled`] uses.
pub fn flag_on(value: Option<&str>) -> bool {
    matches!(value.map(str::trim), Some("on" | "true" | "1"))
}

/// The table's triple gate: the operator flag, the member wallet, and the
/// member's own preference must all be on.
pub fn table_enabled(operator: bool, wallet: bool, user: bool) -> bool {
    operator && wallet && user
}

/// Whether the deployment switched the poker table on (`window.__ENV__.POKER`).
pub fn operator_enabled() -> bool {
    flag_on(env_override("POKER").as_deref())
}

/// Whether this deployment offers the table at all: the operator flag and the
/// member wallet. Settings shows the Games section only when this holds.
pub fn site_enabled() -> bool {
    table_enabled(operator_enabled(), crate::wallet::enabled(), true)
}

/// The full triple gate as a reactive value, for the nav and the route.
///
/// Reads the preferences signal provided at the app root, so ticking the box
/// in Settings shows the nav item at once, with no reload. Call it in a
/// component body (it looks up context), not inside an event handler.
pub fn use_table_enabled() -> Memo<bool> {
    let prefs = use_preferences();
    let operator = operator_enabled();
    let wallet = crate::wallet::enabled();
    Memo::new(move |_| table_enabled(operator, wallet, prefs.with(|p| p.poker_table)))
}

// -- Configuration ------------------------------------------------------------

/// The big blinds offered when the operator lists none.
pub const DEFAULT_STAKES_BB: [u64; 5] = [2, 10, 20, 100, 200];
/// The buy-in, in big blinds, when the operator sets none.
pub const DEFAULT_BUYIN_BB: u64 = 100;
/// The house bot's style when the operator names none (tight-aggressive).
pub const DEFAULT_BOT_PROFILE: &str = "tag";

/// The table parameters the client reads from `window.__ENV__.POKER_CONFIG`
/// (projected from the operator's `[poker]` section). Keys it does not use,
/// such as the settlement assets, are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct PokerConfig {
    /// Big-blind sizes of the tables offered, in lobby order.
    pub stakes_bb: Vec<u64>,
    /// Buy-in measured in big blinds of the chosen table.
    pub buyin_bb: u64,
    /// The house bot's profile name (`rock`, `tag`, `lag`, `station`, `maniac`).
    pub bot_profile: String,
}

impl Default for PokerConfig {
    fn default() -> Self {
        Self {
            stakes_bb: DEFAULT_STAKES_BB.to_vec(),
            buyin_bb: DEFAULT_BUYIN_BB,
            bot_profile: DEFAULT_BOT_PROFILE.to_string(),
        }
    }
}

/// One table's blinds and buy-in, in chips.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stake {
    /// Big blind.
    pub bb: u64,
    /// Small blind: half the big blind.
    pub sb: u64,
    /// The stack both seats start every hand with.
    pub buyin: u64,
}

impl PokerConfig {
    /// Parse the `POKER_CONFIG` JSON, falling back to the defaults on anything
    /// unreadable.
    pub fn from_json(json: &str) -> Self {
        serde_json::from_str(json).unwrap_or_default()
    }

    /// Read `window.__ENV__.POKER_CONFIG`, supplied either as a JSON string or
    /// as an already-parsed object.
    pub fn load() -> Self {
        env_json("POKER_CONFIG")
            .map(|j| Self::from_json(&j))
            .unwrap_or_default()
    }

    /// The tables on offer: every distinct big blind of at least 2 (so the
    /// small blind is a whole chip), in the operator's order. Falls back to the
    /// default list when none survive.
    pub fn stakes(&self) -> Vec<Stake> {
        let buyin_bb = if self.buyin_bb == 0 {
            DEFAULT_BUYIN_BB
        } else {
            self.buyin_bb
        };
        let mut seen = Vec::new();
        for &bb in &self.stakes_bb {
            if bb >= 2 && !seen.contains(&bb) {
                seen.push(bb);
            }
        }
        if seen.is_empty() {
            seen = DEFAULT_STAKES_BB.to_vec();
        }
        seen.into_iter()
            .map(|bb| Stake {
                bb,
                sb: bb / 2,
                buyin: bb.saturating_mul(buyin_bb),
            })
            .collect()
    }
}

/// A `window.__ENV__` value as JSON text, whether the deployment injected a
/// string or an object.
fn env_json(key: &str) -> Option<String> {
    let window = web_sys::window()?;
    let env = js_sys::Reflect::get(&window, &"__ENV__".into()).ok()?;
    if env.is_undefined() || env.is_null() {
        return None;
    }
    let val = js_sys::Reflect::get(&env, &key.into()).ok()?;
    if let Some(s) = val.as_string() {
        return (!s.trim().is_empty()).then_some(s);
    }
    if val.is_object() {
        return js_sys::JSON::stringify(&val).ok()?.as_string();
    }
    None
}

// -- Engine types -------------------------------------------------------------

/// Whether a hand is still being played.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// A seat is to act.
    Act,
    /// The hand is over and `result` is set. Also the reading of a hand whose
    /// phase is missing, so a malformed state never offers actions.
    #[default]
    Done,
}

/// A seat in the engine's full hand state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HandSeat {
    /// Display name.
    pub name: String,
    /// Stack at the start of the hand.
    pub start_stack: u64,
    /// Chips behind.
    pub stack: u64,
    /// The two hole cards (card indices 0–51).
    pub hole: Option<Vec<u8>>,
    /// Folded this hand.
    pub folded: bool,
    /// All chips committed.
    pub all_in: bool,
    /// Sitting out (no chips).
    pub out: bool,
    /// Committed on the current street.
    pub street_commit: u64,
    /// Committed over the whole hand.
    pub hand_commit: u64,
}

/// One entry of the engine's hand log (`ev` names the event).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct LogEntry {
    /// Event kind: `sb`, `bb`, `deal`, `fold`, `check`, `call`, `bet`,
    /// `raise`, `street`, `runout`, `refund`, `win`, `showdown`.
    pub ev: String,
    /// The seat the event concerns, where there is one.
    pub seat: Option<u32>,
    /// Chips moved (blinds, calls, refunds, wins).
    pub amount: Option<u64>,
    /// The total a bet or raise went to.
    pub to: Option<u64>,
    /// The street dealt (`flop`, `turn`, `river`).
    pub street: Option<String>,
}

/// A pot and who could win it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Pot {
    /// Chips in the pot.
    pub amount: u64,
    /// Seats eligible for it.
    pub contenders: Vec<u32>,
    /// Seats that won it.
    pub winners: Vec<u32>,
}

/// A seat's shown hand at showdown.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Eval {
    /// Category, 0 (high card) to 8 (straight flush).
    pub cat: u8,
    /// Tie-break ranks, high to low.
    pub kick: Vec<u8>,
    /// Comparable score: higher wins.
    pub score: u64,
    /// Spoken name, e.g. "two pair, kings and nines".
    pub name: String,
}

/// Chips a seat collected.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Winner {
    /// The seat.
    pub seat: u32,
    /// Chips collected (its own commitment included).
    pub amount: u64,
}

/// How a finished hand came out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct HandResult {
    /// Cards were shown (false when everyone else folded).
    pub showdown: bool,
    /// The pots, after side-pot slicing.
    pub pots: Vec<Pot>,
    /// Shown hands by seat number (as a string key, the engine's JSON shape);
    /// empty when there was no showdown.
    pub evals: BTreeMap<String, Eval>,
    /// Who collected what.
    pub winners: Vec<Winner>,
}

/// The engine's full hand state (`newHand`/`act` in `poker.js`). Fields the
/// table does not read, such as the deck, are left in the raw JSON.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Hand {
    /// Number of seats.
    pub n: u32,
    /// The dealer button's seat (heads-up it posts the small blind).
    pub button: u32,
    /// Small blind.
    pub sb: u64,
    /// Big blind.
    pub bb: u64,
    /// The 64-hex shuffle seed.
    pub seed_hex: String,
    /// Community cards dealt so far.
    pub board: Vec<u8>,
    /// 0 preflop, 1 flop, 2 turn, 3 river.
    pub street: u8,
    /// The seats.
    pub seats: Vec<HandSeat>,
    /// The bet to match on this street.
    pub current_bet: u64,
    /// The seat to act, or -1 when nobody is.
    pub to_act: i32,
    /// Still playing or finished.
    pub phase: Phase,
    /// Everything that happened, in order.
    pub log: Vec<LogEntry>,
    /// Set once the hand is over.
    pub result: Option<HandResult>,
    /// Small-blind seat.
    pub sb_seat: u32,
    /// Big-blind seat.
    pub bb_seat: u32,
}

/// A hand in play: the engine's JSON, passed back verbatim on every call, and
/// the typed reading of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandState {
    /// The engine's own serialisation.
    pub raw: String,
    /// Parsed from `raw`.
    pub hand: Hand,
}

impl HandState {
    /// Read an engine reply, turning an `{"error": …}` reply into `Err`.
    pub fn from_json(raw: String) -> Result<Self, String> {
        let hand = decode::<Hand>(&raw)?;
        Ok(Self { raw, hand })
    }
}

/// A seat as another seat sees it: hole cards only when they may be seen.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
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
    /// Hole cards, present for the viewer's own seat and for hands shown down.
    pub hole: Option<Vec<u8>>,
}

/// What one seat may see of the hand (`seatView` in `poker.js`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SeatView {
    /// The viewing seat.
    pub seat: u32,
    /// `preflop`, `flop`, `turn` or `river`.
    pub street: String,
    /// Community cards dealt so far.
    pub board: Vec<u8>,
    /// Still playing or finished.
    pub phase: Phase,
    /// The seat to act, or -1.
    pub to_act: i32,
    /// The bet to match on this street.
    pub current_bet: u64,
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

/// The actions open to the seat to act (`legal` in `poker.js`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Legal {
    /// The seat to act.
    pub seat: u32,
    /// Some of `fold`, `check`, `call`, `bet`, `raise`.
    pub actions: Vec<String>,
    /// Chips needed to call.
    pub call_amount: u64,
    /// The smallest total a bet or raise may go to (in limit, the only one).
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

/// An action message for the engine.
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

/// One of the engine's bot characters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct RosterEntry {
    /// Display name.
    pub name: String,
    /// The profile it plays (`rock`, `tag`, …).
    pub profile: String,
    /// A glyph for the seat.
    pub emoji: String,
    /// One line of character.
    pub blurb: String,
}

/// A seat in a new hand's configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SeatConfig {
    /// Display name.
    pub name: String,
    /// Starting stack.
    pub stack: u64,
}

/// Everything `newHand` needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    /// The committed 64-hex shuffle seed.
    pub seed_hex: String,
    /// Fixed-limit betting.
    pub limit: bool,
}

/// Parse an engine reply, surfacing an `{"error": …}` reply as `Err`.
fn decode<T: DeserializeOwned>(json: &str) -> Result<T, String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("engine reply unreadable: {e}"))?;
    if let Some(err) = value.get("error").and_then(|e| e.as_str()) {
        return Err(err.to_string());
    }
    serde_json::from_value(value).map_err(|e| format!("engine reply unexpected: {e}"))
}

// -- Engine calls (browser only) ----------------------------------------------

/// Deal a new hand.
pub fn new_hand(cfg: &HandConfig) -> Result<HandState, String> {
    let cfg = serde_json::to_string(cfg).map_err(|e| e.to_string())?;
    HandState::from_json(js_new_hand(&cfg))
}

/// The actions open to the seat to act; `None` once the hand is over.
pub fn legal(h: &HandState) -> Result<Option<Legal>, String> {
    decode(&js_legal(&h.raw))
}

/// Apply an action, returning the advanced hand.
pub fn act(h: &HandState, action: &Action) -> Result<HandState, String> {
    let action = serde_json::to_string(action).map_err(|e| e.to_string())?;
    HandState::from_json(js_act(&h.raw, &action))
}

/// A bot's decision for `seat`, made from that seat's view alone and
/// deterministic in `seed_hex`.
pub fn bot_decide(
    h: &HandState,
    seat: u32,
    profile: &str,
    seed_hex: &str,
) -> Result<Action, String> {
    decode(&js_bot_decide(&h.raw, seat, profile, seed_hex))
}

/// What `seat` may see of the hand.
pub fn seat_view(h: &HandState, seat: u32) -> Result<SeatView, String> {
    decode(&js_seat_view(&h.raw, seat))
}

/// The engine's bot characters.
pub fn roster() -> Vec<RosterEntry> {
    BOT_ROSTER.with(|r| serde_wasm_bindgen::from_value(r.clone()).unwrap_or_default())
}

/// A card's short name, e.g. `A♠` or `T♥`.
pub fn card_name(card: u8) -> String {
    js_card_name(u32::from(card))
}

/// The spoken name of the best hand in `cards`, e.g. "a flush, ace high".
pub fn hand_name(cards: &[u8]) -> String {
    serde_json::to_string(cards)
        .map(|j| js_hand_name(&j))
        .unwrap_or_default()
}

/// 32 bytes from the browser's CSPRNG as 64 lowercase hex: a shuffle seed.
pub fn fresh_seed() -> Option<String> {
    let crypto = web_sys::window()?.crypto().ok()?;
    let mut buf = [0u8; 32];
    crypto.get_random_values_with_u8_array(&mut buf).ok()?;
    Some(hex::encode(buf))
}

// -- Pure helpers -------------------------------------------------------------

/// The commitment published before a deal: SHA-256 of the seed's 64-character
/// hex text, so `printf %s <seed> | sha256sum` checks it.
pub fn seed_commit(seed_hex: &str) -> String {
    hex::encode(Sha256::digest(seed_hex.as_bytes()))
}

/// The bot's per-decision randomness, derived from the hand's seed and how far
/// the hand has gone, so a revealed seed replays the bot's play exactly.
pub fn bot_seed(seed_hex: &str, step: usize) -> String {
    hex::encode(Sha256::digest(format!("{seed_hex}:bot:{step}").as_bytes()))
}

/// The house bot for a profile: the first roster character playing it, else
/// the default profile's character, else the first character.
pub fn pick_bot(roster: &[RosterEntry], profile: &str) -> RosterEntry {
    roster
        .iter()
        .find(|r| r.profile == profile)
        .or_else(|| roster.iter().find(|r| r.profile == DEFAULT_BOT_PROFILE))
        .or_else(|| roster.first())
        .cloned()
        .unwrap_or_else(|| RosterEntry {
            name: "House".into(),
            profile: DEFAULT_BOT_PROFILE.into(),
            emoji: "♠".into(),
            blurb: String::new(),
        })
}

/// The three choices of the action bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// Fold.
    Fold,
    /// Check, or call when there is a bet.
    Passive,
    /// Bet, or raise when there is a bet.
    Aggressive,
}

/// The engine action for a choice, if it is open.
pub fn action_for(legal: &Legal, choice: Choice) -> Option<Action> {
    let (action, amount) = match choice {
        Choice::Fold => ("fold", None),
        Choice::Passive if legal.allows("check") => ("check", None),
        Choice::Passive => ("call", None),
        Choice::Aggressive if legal.allows("bet") => ("bet", Some(legal.min_raise_to)),
        Choice::Aggressive => ("raise", Some(legal.min_raise_to)),
    };
    legal.allows(action).then(|| Action {
        seat: legal.seat,
        action: action.to_string(),
        amount,
    })
}

/// The action bar's label for a choice, if it is open: `FOLD`, `CHECK`,
/// `CALL 2`, `BET 4`, `RAISE TO 8`.
pub fn choice_label(legal: &Legal, choice: Choice) -> Option<String> {
    let a = action_for(legal, choice)?;
    Some(match a.action.as_str() {
        "fold" => "FOLD".to_string(),
        "check" => "CHECK".to_string(),
        "call" => format!("CALL {}", legal.call_amount),
        "bet" => format!("BET {}", a.amount.unwrap_or_default()),
        _ => format!("RAISE TO {}", a.amount.unwrap_or_default()),
    })
}

/// A card name split for display: rank (`T` shown as `10`), suit glyph, and
/// whether the suit is red.
pub fn card_parts(name: &str) -> (String, String, bool) {
    let mut chars = name.chars();
    let suit = chars.next_back().map(String::from).unwrap_or_default();
    let rank = match chars.as_str() {
        "T" => "10".to_string(),
        r => r.to_string(),
    };
    let red = suit == "♥" || suit == "♦";
    (rank, suit, red)
}

/// A stack in big blinds: `100 BB`, `99.5 BB`.
pub fn bb_count(stack: u64, bb: u64) -> String {
    if bb == 0 {
        return String::new();
    }
    let tenths = stack * 10 / bb;
    if tenths % 10 == 0 {
        format!("{} BB", tenths / 10)
    } else {
        format!("{}.{} BB", tenths / 10, tenths % 10)
    }
}

/// A signed chip count: `+4`, `−2`, `0`.
pub fn signed(n: i64) -> String {
    match n {
        n if n > 0 => format!("+{n}"),
        n if n < 0 => format!("\u{2212}{}", n.unsigned_abs()),
        _ => "0".to_string(),
    }
}

/// A finished hand, told from the hero's side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandOutcome {
    /// Chips the hero won (positive) or lost (negative) this hand.
    pub hero_net: i64,
    /// One sentence: who won, with what, how many chips.
    pub text: String,
}

/// One line of the hand history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRow {
    /// Hand number this session.
    pub number: u32,
    /// The outcome sentence.
    pub text: String,
    /// The hero's net for the hand.
    pub net: i64,
}

fn net_of(seat: &HandSeat) -> i64 {
    seat.stack as i64 - seat.start_stack as i64
}

/// Tell a finished hand from `hero`'s side. `name_hand` names the best hand in
/// a set of cards (the engine's evaluator in the browser); `None` while the
/// hand is still in play.
pub fn summarise(
    hand: &Hand,
    hero: usize,
    name_hand: impl Fn(&[u8]) -> String,
) -> Option<HandOutcome> {
    let result = hand.result.as_ref()?;
    let hero_net = net_of(hand.seats.get(hero)?);
    let who = |i: usize| -> (String, &'static str) {
        let name = hand
            .seats
            .get(i)
            .map(|s| s.name.clone())
            .unwrap_or_default();
        if i == hero {
            ("You".to_string(), "win")
        } else {
            (name, "wins")
        }
    };
    let shown = |i: usize| -> String {
        let named = hand
            .seats
            .get(i)
            .and_then(|s| s.hole.clone())
            .map(|mut cards| {
                cards.extend_from_slice(&hand.board);
                name_hand(&cards)
            })
            .unwrap_or_default();
        if named.is_empty() {
            result
                .evals
                .get(&i.to_string())
                .map(|e| e.name.clone())
                .unwrap_or_default()
        } else {
            named
        }
    };

    let text = if result.winners.len() > 1 {
        let hand_text = result
            .winners
            .first()
            .map(|w| shown(w.seat as usize))
            .unwrap_or_default();
        format!("Split pot: both play {hand_text}.")
    } else if let Some(w) = result.winners.first() {
        let wi = w.seat as usize;
        let won = hand
            .seats
            .get(wi)
            .map(net_of)
            .unwrap_or_default()
            .max(0)
            .unsigned_abs();
        let (name, verb) = who(wi);
        let loser = (0..hand.seats.len()).find(|&i| i != wi);
        if result.showdown {
            let against = loser
                .map(|l| format!(" against {}", shown(l)))
                .unwrap_or_default();
            format!("{name} {verb} {} with {}{against}.", chips(won), shown(wi))
        } else {
            let folded = loser
                .map(|l| {
                    let (n, _) = who(l);
                    let n = if l == hero { "you".to_string() } else { n };
                    format!(" — {n} folded")
                })
                .unwrap_or_default();
            format!("{name} {verb} {}{folded}.", chips(won))
        }
    } else {
        "No winner recorded.".to_string()
    };
    Some(HandOutcome { hero_net, text })
}

/// `1 chip`, `4 chips`.
pub fn chips(n: u64) -> String {
    if n == 1 {
        "1 chip".to_string()
    } else {
        format!("{n} chips")
    }
}

/// A log entry in words, e.g. "First Mate Wren raises to 4" or, for the
/// `hero` seat, "You call 1"; `None` for bookkeeping entries the table does
/// not narrate.
pub fn describe(entry: &LogEntry, names: &[String], hero: u32) -> Option<String> {
    let you = entry.seat == Some(hero);
    let name = if you {
        "You".to_string()
    } else {
        entry
            .seat
            .and_then(|s| names.get(s as usize))
            .cloned()
            .unwrap_or_default()
    };
    let verb = |second: &str, third: &str| {
        if you {
            second.to_string()
        } else {
            third.to_string()
        }
    };
    let amount = entry.amount.unwrap_or_default();
    let to = entry.to.unwrap_or_default();
    Some(match entry.ev.as_str() {
        "sb" => format!(
            "{name} {} the small blind ({amount})",
            verb("post", "posts")
        ),
        "bb" => format!("{name} {} the big blind ({amount})", verb("post", "posts")),
        "fold" => format!("{name} {}", verb("fold", "folds")),
        "check" => format!("{name} {}", verb("check", "checks")),
        "call" => format!("{name} {} {amount}", verb("call", "calls")),
        "bet" => format!("{name} {} {to}", verb("bet", "bets")),
        "raise" => format!("{name} {} to {to}", verb("raise", "raises")),
        "street" => format!("— {} —", entry.street.clone().unwrap_or_default()),
        "runout" => "— board run out —".to_string(),
        "refund" => format!(
            "{} uncalled returned to {}",
            chips(amount),
            if you { "you" } else { name.as_str() }
        ),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stores::preferences::Preferences;

    const HAND_NEW: &str = include_str!("testdata/hand_new.json");
    const HAND_SHOWDOWN: &str = include_str!("testdata/hand_showdown.json");
    const HAND_FOLD: &str = include_str!("testdata/hand_fold.json");
    const LEGAL_NEW: &str = include_str!("testdata/legal_new.json");
    const LEGAL_DONE: &str = include_str!("testdata/legal_done.json");
    const VIEW_NEW: &str = include_str!("testdata/view_new.json");
    const VIEW_SHOWDOWN: &str = include_str!("testdata/view_showdown.json");
    const ROSTER: &str = include_str!("testdata/roster.json");
    const ERROR: &str = include_str!("testdata/error.json");

    fn eval_names(hand: &Hand) -> impl Fn(&[u8]) -> String + '_ {
        // Natively there is no JS evaluator; name by the engine's own evals.
        move |cards: &[u8]| {
            hand.seats
                .iter()
                .position(|s| s.hole.as_deref().is_some_and(|h| cards.starts_with(h)))
                .and_then(|i| hand.result.as_ref()?.evals.get(&i.to_string()))
                .map(|e| e.name.clone())
                .unwrap_or_default()
        }
    }

    #[test]
    fn preference_defaults_off_and_round_trips() {
        assert!(!Preferences::default().poker_table);
        // A store saved before the field existed still loads, with it off.
        let mut old = serde_json::to_value(Preferences::default()).unwrap();
        old.as_object_mut().unwrap().remove("poker_table");
        let loaded: Preferences = serde_json::from_value(old).unwrap();
        assert!(!loaded.poker_table);
        let on = Preferences {
            poker_table: true,
            ..Preferences::default()
        };
        let back: Preferences = serde_json::from_str(&serde_json::to_string(&on).unwrap()).unwrap();
        assert!(back.poker_table);
    }

    #[test]
    fn gate_needs_all_three() {
        assert!(table_enabled(true, true, true));
        for (o, w, u) in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
            (false, false, false),
        ] {
            assert!(!table_enabled(o, w, u));
        }
    }

    #[test]
    fn flag_matches_the_wallet_matcher() {
        for on in ["on", "true", "1", " on "] {
            assert!(flag_on(Some(on)), "{on}");
        }
        for off in ["off", "false", "0", "", "yes", "ON"] {
            assert!(!flag_on(Some(off)), "{off}");
        }
        assert!(!flag_on(None));
    }

    #[test]
    fn config_defaults_and_stakes() {
        let c = PokerConfig::from_json(
            r#"{"stakes_bb":[2,10,20,100,200],"buyin_bb":100,"assets":["sats","dream"],"bot_profile":"tag","citizen_pubkey":null}"#,
        );
        assert_eq!(c, PokerConfig::default());
        let s = c.stakes();
        assert_eq!(s.len(), 5);
        assert_eq!(
            s[0],
            Stake {
                bb: 2,
                sb: 1,
                buyin: 200
            }
        );
        assert_eq!(
            s[4],
            Stake {
                bb: 200,
                sb: 100,
                buyin: 20_000
            }
        );

        let odd = PokerConfig::from_json(
            r#"{"stakes_bb":[1,0,10,10,40],"buyin_bb":0,"bot_profile":"lag"}"#,
        );
        assert_eq!(odd.bot_profile, "lag");
        let s = odd.stakes();
        assert_eq!(s.iter().map(|s| s.bb).collect::<Vec<_>>(), vec![10, 40]);
        assert_eq!(s[0].buyin, 1_000);

        assert_eq!(PokerConfig::from_json("not json"), PokerConfig::default());
        assert_eq!(
            PokerConfig::from_json(r#"{"stakes_bb":[]}"#).stakes().len(),
            DEFAULT_STAKES_BB.len()
        );
    }

    #[test]
    fn new_hand_fixture_deserialises() {
        let h = HandState::from_json(HAND_NEW.trim().to_string()).unwrap();
        let hand = &h.hand;
        assert_eq!(hand.phase, Phase::Act);
        assert_eq!((hand.n, hand.button, hand.sb, hand.bb), (2, 0, 1, 2));
        assert_eq!(hand.seed_hex, "a".repeat(64));
        assert_eq!(hand.to_act, 0);
        assert_eq!((hand.sb_seat, hand.bb_seat), (0, 1));
        assert!(hand.board.is_empty());
        assert_eq!(hand.seats[0].hole.as_deref(), Some(&[8u8, 26][..]));
        assert_eq!(hand.seats[1].street_commit, 2);
        assert_eq!(hand.seats[0].stack, 199);
        assert!(hand.result.is_none());
        assert_eq!(hand.log.len(), 3);
        assert_eq!(h.raw, HAND_NEW.trim());
    }

    #[test]
    fn showdown_fixture_deserialises_and_summarises() {
        let h = HandState::from_json(HAND_SHOWDOWN.trim().to_string()).unwrap();
        let hand = &h.hand;
        assert_eq!(hand.phase, Phase::Done);
        assert_eq!(hand.to_act, -1);
        assert_eq!(hand.board.len(), 5);
        let r = hand.result.as_ref().unwrap();
        assert!(r.showdown);
        assert_eq!(r.winners, vec![Winner { seat: 1, amount: 4 }]);
        assert_eq!(r.evals["0"].name, "a pair of aces");
        assert_eq!(r.pots[0].contenders, vec![0, 1]);

        let o = summarise(hand, 0, eval_names(hand)).unwrap();
        assert_eq!(o.hero_net, -2);
        assert_eq!(
            o.text,
            "First Mate Wren wins 2 chips with a pair of aces against a pair of aces."
        );
        assert!(summarise(
            &HandState::from_json(HAND_NEW.into()).unwrap().hand,
            0,
            |_| String::new()
        )
        .is_none());
    }

    #[test]
    fn fold_fixture_summarises() {
        let hand = HandState::from_json(HAND_FOLD.trim().to_string())
            .unwrap()
            .hand;
        let o = summarise(&hand, 0, |_| String::new()).unwrap();
        assert_eq!(o.hero_net, -1);
        assert_eq!(o.text, "First Mate Wren wins 1 chip — you folded.");
        let names = ["You".to_string(), "First Mate Wren".to_string()];
        let said: Vec<String> = hand
            .log
            .iter()
            .filter_map(|e| describe(e, &names, 0))
            .collect();
        assert_eq!(
            said,
            vec![
                "You post the small blind (1)",
                "First Mate Wren posts the big blind (2)",
                "You fold",
                "1 chip uncalled returned to First Mate Wren",
            ]
        );
    }

    #[test]
    fn legal_and_views_deserialise() {
        let l: Option<Legal> = decode(LEGAL_NEW).unwrap();
        let l = l.unwrap();
        assert_eq!(l.actions, vec!["fold", "call", "raise"]);
        assert_eq!((l.call_amount, l.min_raise_to, l.max_raise_to), (1, 4, 4));
        assert_eq!(decode::<Option<Legal>>(LEGAL_DONE).unwrap(), None);

        let v: SeatView = decode(VIEW_NEW).unwrap();
        assert_eq!(v.street, "preflop");
        assert_eq!(v.pot, 3);
        assert_eq!(v.hole.as_deref(), Some(&[8u8, 26][..]));
        assert!(v.seats[1].hole.is_none(), "bot cards hidden mid-hand");

        let v: SeatView = decode(VIEW_SHOWDOWN).unwrap();
        assert_eq!(v.phase, Phase::Done);
        assert_eq!(
            v.seats[1].hole.as_deref(),
            Some(&[6u8, 9][..]),
            "shown at showdown"
        );
        assert!(v.result.is_some());
    }

    #[test]
    fn engine_error_is_an_err() {
        assert_eq!(
            HandState::from_json(ERROR.trim().to_string()).unwrap_err(),
            "not seat 1's turn"
        );
        assert!(decode::<Legal>("{").is_err());
    }

    #[test]
    fn roster_and_bot_choice() {
        let roster: Vec<RosterEntry> = decode(ROSTER).unwrap();
        assert_eq!(roster.len(), 5);
        assert_eq!(pick_bot(&roster, "tag").name, "First Mate Wren");
        assert_eq!(pick_bot(&roster, "maniac").emoji, "🐧");
        assert_eq!(pick_bot(&roster, "nobody").profile, "tag");
        assert_eq!(pick_bot(&[], "tag").name, "House");
    }

    #[test]
    fn action_bar() {
        let l: Legal = decode::<Option<Legal>>(LEGAL_NEW).unwrap().unwrap();
        assert_eq!(choice_label(&l, Choice::Fold).as_deref(), Some("FOLD"));
        assert_eq!(choice_label(&l, Choice::Passive).as_deref(), Some("CALL 1"));
        assert_eq!(
            choice_label(&l, Choice::Aggressive).as_deref(),
            Some("RAISE TO 4")
        );
        assert_eq!(
            action_for(&l, Choice::Aggressive),
            Some(Action {
                seat: 0,
                action: "raise".into(),
                amount: Some(4)
            })
        );
        assert_eq!(
            serde_json::to_string(&action_for(&l, Choice::Passive).unwrap()).unwrap(),
            r#"{"seat":0,"action":"call"}"#
        );

        let open = Legal {
            seat: 1,
            actions: vec!["fold".into(), "check".into(), "bet".into()],
            min_raise_to: 2,
            max_raise_to: 2,
            ..Legal::default()
        };
        assert_eq!(
            choice_label(&open, Choice::Passive).as_deref(),
            Some("CHECK")
        );
        assert_eq!(
            choice_label(&open, Choice::Aggressive).as_deref(),
            Some("BET 2")
        );

        let capped = Legal {
            actions: vec!["fold".into(), "call".into()],
            call_amount: 4,
            ..Legal::default()
        };
        assert_eq!(choice_label(&capped, Choice::Aggressive), None);
    }

    #[test]
    fn hand_config_serialises_for_the_shim() {
        let cfg = HandConfig {
            seats: vec![SeatConfig {
                name: "You".into(),
                stack: 200,
            }],
            button: 0,
            sb: 1,
            bb: 2,
            seed_hex: "ab".into(),
            limit: true,
        };
        assert_eq!(
            serde_json::to_string(&cfg).unwrap(),
            r#"{"seats":[{"name":"You","stack":200}],"button":0,"sb":1,"bb":2,"seedHex":"ab","limit":true}"#
        );
    }

    #[test]
    fn commit_and_bot_seed() {
        // SHA-256("abc"), FIPS 180-2 appendix B.1.
        assert_eq!(
            seed_commit("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let s = bot_seed(&"a".repeat(64), 3);
        assert_eq!(s.len(), 64);
        assert!(s
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_ne!(s, bot_seed(&"a".repeat(64), 4));
    }

    #[test]
    fn display_helpers() {
        assert_eq!(card_parts("A♠"), ("A".into(), "♠".into(), false));
        assert_eq!(card_parts("T♥"), ("10".into(), "♥".into(), true));
        assert_eq!(card_parts("2♦"), ("2".into(), "♦".into(), true));
        assert_eq!(card_parts(""), (String::new(), String::new(), false));
        assert_eq!(bb_count(200, 2), "100 BB");
        assert_eq!(bb_count(199, 2), "99.5 BB");
        assert_eq!(bb_count(5, 0), "");
        assert_eq!(signed(4), "+4");
        assert_eq!(signed(-2), "\u{2212}2");
        assert_eq!(signed(0), "0");
        assert_eq!(chips(1), "1 chip");
        assert_eq!(chips(0), "0 chips");
    }
}
