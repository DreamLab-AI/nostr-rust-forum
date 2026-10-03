//! The poker table: its gates, its configuration, the typed seam to the
//! vendored Libre Poker engine (`js/librepoker`, AGPL-3.0) for the practice
//! table, and the live session with the forum's house seat ([`live`]).
//!
//! Three things must all hold before the table shows anywhere, nav item or
//! route: the operator set `window.__ENV__.POKER = "on"`, the member wallet is
//! on (`window.__ENV__.SIDESTR_WALLET`), and the member ticked "Poker table" in
//! Settings → Games. The practice table plays chips that are worth nothing;
//! the DREAM table ([`money_enabled`]) needs the operator to name a house seat
//! (`POKER_CONFIG.citizen_pubkey`) and settles each hand on the chain.
//!
//! The engine types are [`nostr_bbs_poker::engine`]'s, shared with the house
//! seat; they serialise to the JavaScript engine's JSON, so the practice table
//! passes the engine's own state back verbatim ([`HandState`]) and the live
//! table reads the house's seat views unchanged.

use leptos::prelude::*;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::stores::preferences::use_preferences;
use crate::utils::relay_url::env_override;

pub mod live;

pub use nostr_bbs_poker::bots::RosterEntry;
pub use nostr_bbs_poker::engine::{
    Action, Hand, HandConfig, Legal, LogEntry, Seat as HandSeat, SeatConfig, SeatView,
};
pub use nostr_bbs_poker::fair::{bot_seed, commit as seed_commit};

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
    /// The house seat's pubkey (64 lowercase hex), once the operator runs one;
    /// `None` leaves only the practice table.
    pub citizen_pubkey: Option<String>,
}

impl Default for PokerConfig {
    fn default() -> Self {
        Self {
            stakes_bb: DEFAULT_STAKES_BB.to_vec(),
            buyin_bb: DEFAULT_BUYIN_BB,
            bot_profile: DEFAULT_BOT_PROFILE.to_string(),
            citizen_pubkey: None,
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

    /// The house seat's pubkey, when it is a well-formed one.
    pub fn citizen(&self) -> Option<String> {
        self.citizen_pubkey
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .filter(|pk| nostr_bbs_poker::fair::is_hex64(pk))
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

/// Whether this deployment runs a house seat: the DREAM table is offered.
pub fn money_enabled() -> bool {
    PokerConfig::load().citizen().is_some()
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

// -- Engine state -------------------------------------------------------------

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

/// 32 bytes from the browser's CSPRNG as 64 lowercase hex: a shuffle seed or
/// a nonce.
pub fn fresh_seed() -> Option<String> {
    let crypto = web_sys::window()?.crypto().ok()?;
    let mut buf = [0u8; 32];
    crypto.get_random_values_with_u8_array(&mut buf).ok()?;
    Some(hex::encode(buf))
}

/// The JavaScript engine behind [`nostr_bbs_poker::verify::Engine`], so a
/// finished DREAM hand is replayed in the browser with the same engine the
/// practice table plays.
pub struct JsEngine;

impl nostr_bbs_poker::verify::Engine for JsEngine {
    fn new_hand(&self, cfg: &HandConfig) -> Result<Hand, String> {
        new_hand(cfg).map(|h| h.hand)
    }

    fn legal(&self, h: &Hand) -> Result<Option<Legal>, String> {
        legal(&raw_of(h)?)
    }

    fn act(&self, h: &Hand, action: &Action) -> Result<Hand, String> {
        act(&raw_of(h)?, action).map(|h| h.hand)
    }

    fn seat_view(&self, h: &Hand, seat: u32) -> Result<SeatView, String> {
        seat_view(&raw_of(h)?, seat)
    }

    fn bot_decide(
        &self,
        h: &Hand,
        seat: u32,
        profile: &str,
        seed_hex: &str,
    ) -> Result<Action, String> {
        bot_decide(&raw_of(h)?, seat, profile, seed_hex)
    }
}

/// The engine's JSON for a typed hand: the types serialise to the engine's
/// own shape, so a replayed hand goes back to JavaScript whole.
fn raw_of(h: &Hand) -> Result<HandState, String> {
    let raw = serde_json::to_string(h).map_err(|e| e.to_string())?;
    Ok(HandState {
        raw,
        hand: h.clone(),
    })
}

// -- Pure helpers -------------------------------------------------------------

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

/// The legal envelope a seat view implies for its own seat, when it is to
/// act: what the house's view lets the member choose from. Fixed-limit: the
/// raise total is the view's `min_raise_to`.
pub fn legal_of_view(v: &SeatView) -> Option<Legal> {
    if v.phase != "act" || v.to_act != v.seat as i32 {
        return None;
    }
    let me = v.seats.get(v.seat as usize)?;
    let call = v.current_bet.saturating_sub(me.street_commit).min(me.stack);
    let mut actions = vec!["fold".to_string()];
    actions.push(if call == 0 { "check" } else { "call" }.to_string());
    let (min_to, max_to) = match v.min_raise_to {
        Some(to) if to > v.current_bet => {
            actions.push(if v.current_bet == 0 { "bet" } else { "raise" }.to_string());
            (to, to)
        }
        _ => (v.current_bet, me.street_commit + me.stack),
    };
    Some(Legal {
        seat: v.seat,
        actions,
        call_amount: call,
        min_raise_to: min_to,
        max_raise_to: max_to,
        current_bet: v.current_bet,
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
/// hand is still in play. `names` replaces the seats' names for display.
pub fn summarise(
    hand: &Hand,
    hero: usize,
    name_hand: impl Fn(&[u8]) -> String,
) -> Option<HandOutcome> {
    let names: Vec<String> = hand.seats.iter().map(|s| s.name.clone()).collect();
    summarise_named(hand, hero, &names, name_hand)
}

/// [`summarise`] with display names for the seats.
pub fn summarise_named(
    hand: &Hand,
    hero: usize,
    names: &[String],
    name_hand: impl Fn(&[u8]) -> String,
) -> Option<HandOutcome> {
    let result = hand.result.as_ref()?;
    let hero_net = net_of(hand.seats.get(hero)?);
    let who = |i: usize| -> (String, &'static str) {
        let name = names.get(i).cloned().unwrap_or_default();
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
                .as_ref()
                .and_then(|e| e.get(&i.to_string()))
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
    use nostr_bbs_poker::engine::Winner;

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
                .and_then(|i| hand.result.as_ref()?.evals.as_ref()?.get(&i.to_string()))
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
    fn config_defaults_stakes_and_the_house_seat() {
        let c = PokerConfig::from_json(
            r#"{"stakes_bb":[2,10,20,100,200],"buyin_bb":100,"assets":["sats","dream"],"bot_profile":"tag","citizen_pubkey":null}"#,
        );
        assert_eq!(c, PokerConfig::default());
        assert_eq!(c.citizen(), None);
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
        let housed =
            PokerConfig::from_json(&format!(r#"{{"citizen_pubkey":" {} "}}"#, "AB".repeat(32)));
        assert_eq!(housed.citizen().as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(
            PokerConfig::from_json(r#"{"citizen_pubkey":"nope"}"#).citizen(),
            None
        );
    }

    #[test]
    fn new_hand_fixture_deserialises() {
        let h = HandState::from_json(HAND_NEW.trim().to_string()).unwrap();
        let hand = &h.hand;
        assert!(hand.in_play());
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
        // the typed hand serialises back to the engine's shape
        let back: serde_json::Value = serde_json::from_str(&raw_of(hand).unwrap().raw).unwrap();
        let orig: serde_json::Value = serde_json::from_str(HAND_NEW).unwrap();
        assert_eq!(back, orig);
    }

    #[test]
    fn showdown_fixture_deserialises_and_summarises() {
        let h = HandState::from_json(HAND_SHOWDOWN.trim().to_string()).unwrap();
        let hand = &h.hand;
        assert!(!hand.in_play());
        assert_eq!(hand.to_act, -1);
        assert_eq!(hand.board.len(), 5);
        let r = hand.result.as_ref().unwrap();
        assert!(r.showdown);
        assert_eq!(r.winners, vec![Winner { seat: 1, amount: 4 }]);
        assert_eq!(r.evals.as_ref().unwrap()["0"].name, "a pair of aces");
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
        let named =
            summarise_named(hand, 0, &["You".into(), "Alice".into()], eval_names(hand)).unwrap();
        assert!(named.text.starts_with("Alice wins"));
    }

    #[test]
    fn fold_fixture_summarises() {
        let hand = HandState::from_json(HAND_FOLD.trim().to_string())
            .unwrap()
            .hand;
        let o = summarise(&hand, 0, |_| String::new()).unwrap();
        assert_eq!(o.hero_net, -1);
        assert_eq!(o.text, "First Mate Wren wins 1 chip — you folded.");
        assert!(hand.result.as_ref().unwrap().evals.is_none());
    }

    #[test]
    fn legal_and_view_fixtures_and_the_action_bar() {
        let l: Legal = decode(LEGAL_NEW).unwrap();
        assert_eq!(l.seat, 0);
        assert!(l.allows("call") && l.allows("raise") && !l.allows("check"));
        assert_eq!(action_for(&l, Choice::Passive).unwrap().action, "call");
        assert_eq!(choice_label(&l, Choice::Passive).as_deref(), Some("CALL 1"));
        assert_eq!(
            choice_label(&l, Choice::Aggressive).as_deref(),
            Some("RAISE TO 4")
        );
        assert_eq!(choice_label(&l, Choice::Fold).as_deref(), Some("FOLD"));
        let done: Option<Legal> = decode(LEGAL_DONE).unwrap();
        assert!(done.is_none());

        let v: SeatView = decode(VIEW_NEW).unwrap();
        assert_eq!(v.seat, 0);
        assert!(v.seats[1].hole.is_none());
        assert!(v.hole.is_some());
        // the view implies the same envelope the engine gave
        let implied = legal_of_view(&v).unwrap();
        assert_eq!(implied.actions, l.actions);
        assert_eq!(implied.call_amount, l.call_amount);
        assert_eq!(implied.min_raise_to, l.min_raise_to);
        let sv: SeatView = decode(VIEW_SHOWDOWN).unwrap();
        assert!(sv.seats[1].hole.is_some());
        assert!(legal_of_view(&sv).is_none());

        let roster: Vec<RosterEntry> = serde_json::from_str(ROSTER).unwrap();
        assert_eq!(pick_bot(&roster, "maniac").name, "Ensign Puffin");
        assert_eq!(pick_bot(&roster, "nope").profile, "tag");
        assert_eq!(pick_bot(&[], "tag").name, "House");
        assert_eq!(decode::<Legal>(ERROR).unwrap_err(), "not seat 1's turn");
    }

    #[test]
    fn helpers() {
        assert_eq!(card_parts("T♥"), ("10".into(), "♥".into(), true));
        assert_eq!(card_parts("A♠"), ("A".into(), "♠".into(), false));
        assert_eq!(bb_count(199, 2), "99.5 BB");
        assert_eq!(bb_count(200, 2), "100 BB");
        assert_eq!(bb_count(5, 0), "");
        assert_eq!(signed(4), "+4");
        assert_eq!(signed(-2), "\u{2212}2");
        assert_eq!(signed(0), "0");
        assert_eq!(chips(1), "1 chip");
        let names = vec!["You".to_string(), "Wren".to_string()];
        let e = |ev: &str, seat: u32, amount: Option<u64>, to: Option<u64>| LogEntry {
            ev: ev.into(),
            seat: Some(seat),
            amount,
            to,
            ..LogEntry::default()
        };
        assert_eq!(
            describe(&e("raise", 1, None, Some(4)), &names, 0).as_deref(),
            Some("Wren raises to 4")
        );
        assert_eq!(
            describe(&e("call", 0, Some(1), None), &names, 0).as_deref(),
            Some("You call 1")
        );
        assert_eq!(describe(&e("deal", 0, None, None), &names, 0), None);
        assert_eq!(seed_commit(&"ab".repeat(32)).len(), 64);
        assert_ne!(bot_seed("s", 1), bot_seed("s", 2));
    }
}
