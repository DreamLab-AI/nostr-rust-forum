//! The house seat as a state machine: messages in, messages and effects out,
//! no clock, no network, no randomness of its own (the secret source is
//! injected), so the whole money path is tested natively.
//!
//! One [`Citizen`] serves every member at once. A member plays the house
//! bot, or challenges another member present at the table to a hand the
//! house deals but takes no seat in. Either way the house holds the whole
//! hand and each player receives only their own seat view. The runner feeds
//! it decoded [`ToCitizen`] messages with the balances it read from the
//! chain, and carries out the [`Effect`]s: send a message, take the bot's
//! turn after a pause, pay a settlement, save the ledger.

use std::collections::HashMap;

use nostr_bbs_poker::bots;
use nostr_bbs_poker::engine::{self, Action, Hand, HandConfig, SeatConfig};
use nostr_bbs_poker::fair;
use nostr_bbs_poker::protocol::{Asset, Debt, TableOffer, ToCitizen, ToHero, VERSION};
use nostr_bbs_poker::record::record_of;
use nostr_bbs_poker::rules::{self, Settlement, Side};

use crate::ledger::{Ledger, Owed, Owing};

/// The member's seat in a hand against the house.
pub const HERO: u32 = 0;
/// The house's seat in a hand against the house.
pub const HOUSE: u32 = 1;
/// A member counts as present this long after their last hello, seconds.
pub const PRESENCE_TTL: u64 = 180;
/// A challenge lapses after this long, seconds.
pub const CHALLENGE_TTL: u64 = 120;

/// The table's parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Big blinds on offer, in base units, lobby order.
    pub stakes_bb: Vec<u64>,
    /// The buy-in in big blinds.
    pub buyin_bb: u64,
    /// The house bot's profile.
    pub profile: String,
    /// The most the house pays out per day, base units.
    pub daily_cap: u64,
    /// How long a member's payment claim is trusted before the chain must
    /// show it, seconds.
    pub claim_grace_secs: u64,
    /// The table's asset as members read it (`DREAM`, `BLAKES7`).
    pub ticker: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            stakes_bb: rules::STAKES_BB.to_vec(),
            buyin_bb: 100,
            profile: "tag".into(),
            daily_cap: 20_000,
            claim_grace_secs: 30 * 60,
            ticker: "DREAM".into(),
        }
    }
}

/// Who the house is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct House {
    /// The house's pubkey, 64 hex.
    pub pubkey: String,
    /// Its receive script, hex.
    pub script_hex: String,
}

/// What the runner must do.
// `Send` carries a whole protocol message; effects are transient.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    /// Send a message to a member.
    Send(String, ToHero),
    /// Take the house's turn in the hand named by its commitment, after a
    /// short pause.
    BotTurn(String),
    /// Pay a settlement the house owes.
    Pay {
        /// The member.
        hero: String,
        /// The hand's root.
        root: String,
        /// Base units.
        amount: u64,
    },
    /// The ledger changed; save it.
    Persist,
}

/// Balances the runner read from the chain for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Balances {
    /// Units of the table's asset the sender holds.
    pub hero_asset: u64,
    /// Units of the table's asset the house holds.
    pub house_asset: u64,
}

/// A hand in play, keyed by its commitment.
#[derive(Debug, Clone)]
struct Live {
    /// The players' pubkeys in seat order; seat 1 is the house's for a
    /// house hand.
    seats: [String; 2],
    house: bool,
    secret: String,
    nonces: Vec<String>,
    seed: String,
    buyin: u64,
    hand: Hand,
}

/// A challenge waiting for its opponent.
#[derive(Debug, Clone)]
struct Challenge {
    from: String,
    to: String,
    bb: u64,
    nonce: String,
    secret: String,
    expires: u64,
}

/// One member's standing with the house.
#[derive(Debug, Clone, Default)]
struct Session {
    /// The secret and commitment offered for the next house hand.
    offer: Option<(String, String)>,
    /// The commitment of the hand the member is in.
    live: Option<String>,
    /// Who has the button next against the house.
    next_button: u32,
    /// Last hello, unix seconds.
    seen: u64,
}

/// The house seat.
pub struct Citizen {
    cfg: Config,
    house: House,
    bot: bots::RosterEntry,
    sessions: HashMap<String, Session>,
    hands: HashMap<String, Live>,
    challenges: HashMap<String, Challenge>,
    /// The book.
    pub ledger: Ledger,
    secrets: Box<dyn FnMut() -> [u8; 32]>,
}

impl std::fmt::Debug for Citizen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Citizen")
            .field("house", &self.house)
            .field("sessions", &self.sessions.len())
            .field("hands", &self.hands.len())
            .field("ledger", &self.ledger)
            .finish_non_exhaustive()
    }
}

fn err(to: &str, commit: Option<&str>, message: impl Into<String>) -> Vec<Effect> {
    vec![Effect::Send(
        to.to_string(),
        ToHero::Error {
            commit: commit.map(str::to_string),
            message: message.into(),
        },
    )]
}

impl Citizen {
    /// A house seat with `secrets` as its source of 32 random bytes per hand.
    pub fn new(
        cfg: Config,
        house: House,
        ledger: Ledger,
        secrets: Box<dyn FnMut() -> [u8; 32]>,
    ) -> Self {
        let bot = bots::pick_bot(&cfg.profile);
        Self {
            cfg,
            house,
            bot,
            sessions: HashMap::new(),
            hands: HashMap::new(),
            challenges: HashMap::new(),
            ledger,
            secrets,
        }
    }

    /// The tables on offer.
    pub fn tables(&self) -> Vec<TableOffer> {
        rules::stakes_table(&self.cfg.stakes_bb, self.cfg.buyin_bb)
            .into_iter()
            .map(|s| TableOffer {
                bb: s.bb,
                sb: s.sb,
                buyin: s.buyin,
                label: s.label,
            })
            .collect()
    }

    /// The house character.
    pub fn bot(&self) -> &bots::RosterEntry {
        &self.bot
    }

    /// Whether `member` is in a hand.
    pub fn in_hand(&self, member: &str) -> bool {
        self.sessions
            .get(member)
            .and_then(|s| s.live.as_ref())
            .and_then(|c| self.hands.get(c))
            .is_some_and(|l| l.hand.in_play())
    }

    fn cap_left(&self, now: u64) -> u64 {
        self.cfg
            .daily_cap
            .saturating_sub(self.ledger.paid_today(now))
    }

    fn fresh_secret(&mut self) -> (String, String) {
        let secret = hex::encode((self.secrets)());
        let commit = fair::commit(&secret);
        (secret, commit)
    }

    fn stake_for(&self, bb: u64) -> Option<rules::Stakes> {
        rules::stakes_table(&self.cfg.stakes_bb, self.cfg.buyin_bb)
            .into_iter()
            .find(|s| s.bb == bb)
    }

    /// Members present now, other than `except`, not in a hand.
    fn present(&self, except: &str, now: u64) -> Vec<String> {
        let mut v: Vec<String> = self
            .sessions
            .iter()
            .filter(|(pk, s)| {
                pk.as_str() != except
                    && now.saturating_sub(s.seen) <= PRESENCE_TTL
                    && !self.in_hand(pk)
            })
            .map(|(pk, _)| pk.clone())
            .collect();
        v.sort();
        v
    }

    /// Why `member` may not sit for a hand at `buyin`, if anything.
    fn refusal(&self, member: &str, buyin: u64, held: u64, now: u64) -> Option<String> {
        for o in self.ledger.owed.iter().filter(|o| o.hero == member) {
            let overdue = match &o.claimed {
                None => true,
                Some(c) => now.saturating_sub(c.at) > self.cfg.claim_grace_secs,
            };
            if overdue {
                let why = if o.claimed.is_some() {
                    "the chain has not shown your payment"
                } else {
                    "it has not been paid"
                };
                return Some(format!(
                    "You still owe {} {} for hand {}…: {why}. Pay it and sit again.",
                    o.amount,
                    self.cfg.ticker,
                    &o.root[..12]
                ));
            }
        }
        if held < buyin {
            return Some(format!(
                "You hold {held} {}; this table's buy-in is {buyin}.",
                self.cfg.ticker
            ));
        }
        None
    }

    fn offer(&mut self, member: &str, now: u64) -> ToHero {
        let (secret, commit) = self.fresh_secret();
        let present = self.present(member, now);
        let session = self.sessions.entry(member.to_string()).or_default();
        session.offer = Some((secret, commit.clone()));
        let owed = self
            .ledger
            .owed
            .iter()
            .filter(|o| o.hero == member)
            .map(|o| Debt {
                root: o.root.clone(),
                amount: o.amount,
                since: o.since,
            })
            .collect();
        let owing = self
            .ledger
            .owing
            .iter()
            .filter(|o| o.hero == member)
            .map(|o| Debt {
                root: o.root.clone(),
                amount: o.amount,
                since: o.since,
            })
            .collect();
        ToHero::Offer {
            v: VERSION,
            citizen: self.house.pubkey.clone(),
            script: self.house.script_hex.clone(),
            name: self.bot.name.clone(),
            profile: self.bot.profile.clone(),
            assets: vec![Asset::Dream],
            tables: self.tables(),
            commit,
            owed,
            owing,
            daily_cap_left: self.cap_left(now),
            present,
        }
    }

    fn seat_of(live: &Live, member: &str) -> Option<u32> {
        live.seats
            .iter()
            .position(|s| s == member)
            .map(|i| i as u32)
    }

    fn state_for(commit: &str, live: &Live, seat: u32) -> ToHero {
        let other = live.seats[1 - seat as usize].clone();
        ToHero::State {
            commit: commit.to_string(),
            seat,
            opponent: other,
            house: live.house,
            view: engine::seat_view(&live.hand, seat),
            log: live.hand.log.clone(),
        }
    }

    /// Handle a message from `from`.
    pub fn handle(
        &mut self,
        from: &str,
        msg: ToCitizen,
        now: u64,
        balances: Balances,
    ) -> Vec<Effect> {
        match msg {
            ToCitizen::Hello { v } => {
                if v != VERSION {
                    return err(
                        from,
                        None,
                        format!("This table speaks protocol {VERSION}, not {v}."),
                    );
                }
                self.sessions.entry(from.to_string()).or_default().seen = now;
                let live = self
                    .sessions
                    .get(from)
                    .and_then(|s| s.live.clone())
                    .and_then(|c| self.hands.get(&c).map(|l| (c, l.clone())));
                if let Some((commit, live)) = live {
                    if live.hand.in_play() {
                        // a reload mid-hand: show the hand again
                        let seat = Self::seat_of(&live, from).unwrap_or(HERO);
                        let mut out = vec![Effect::Send(
                            from.to_string(),
                            Self::state_for(&commit, &live, seat),
                        )];
                        if live.house && live.hand.to_act == HOUSE as i32 {
                            out.push(Effect::BotTurn(commit));
                        }
                        return out;
                    }
                }
                let offer = self.offer(from, now);
                vec![Effect::Send(from.to_string(), offer)]
            }
            ToCitizen::Sit {
                v,
                commit,
                asset,
                bb,
                nonce,
            } => self.sit(from, v, &commit, asset, bb, &nonce, now, balances),
            ToCitizen::Act { commit, action } => self.member_act(from, &commit, action, now),
            ToCitizen::Paid { root, txid } => {
                if !fair::is_hex64(&root) || txid.len() != 64 {
                    return Vec::new();
                }
                if self.ledger.claim(from, &root, &txid, now) {
                    vec![Effect::Persist]
                } else {
                    Vec::new()
                }
            }
            ToCitizen::Leave { commit } => {
                let mut out = Vec::new();
                let mine = commit.filter(|c| {
                    self.in_hand(from)
                        && self.sessions.get(from).and_then(|s| s.live.as_deref())
                            == Some(c.as_str())
                });
                if let Some(c) = mine {
                    // leaving a hand is folding it, on one's own turn; off
                    // turn the hand simply waits for the player to come back
                    if let Some(live) = self.hands.get(&c) {
                        let seat = Self::seat_of(live, from).unwrap_or(HERO);
                        if live.hand.to_act == seat as i32 {
                            let fold = Action {
                                seat,
                                action: "fold".into(),
                                amount: None,
                            };
                            out = self.member_act(from, &c, fold, now);
                        }
                    }
                }
                if let Some(s) = self.sessions.get_mut(from) {
                    s.offer = None;
                    s.seen = 0;
                }
                out
            }
            ToCitizen::Challenge {
                v,
                opponent,
                bb,
                nonce,
            } => self.challenge(from, v, &opponent, bb, &nonce, now, balances),
            ToCitizen::Accept { commit, nonce } => {
                self.accept(from, &commit, &nonce, now, balances)
            }
            ToCitizen::Decline { commit } => {
                let Some(ch) = self.challenges.get(&commit) else {
                    return Vec::new();
                };
                if ch.to != from {
                    return Vec::new();
                }
                let ch = self.challenges.remove(&commit).expect("present");
                vec![Effect::Send(
                    ch.from,
                    ToHero::Declined {
                        commit,
                        by: from.to_string(),
                    },
                )]
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn sit(
        &mut self,
        member: &str,
        v: u32,
        commit: &str,
        asset: Asset,
        bb: u64,
        nonce: &str,
        now: u64,
        balances: Balances,
    ) -> Vec<Effect> {
        if v != VERSION {
            return err(
                member,
                Some(commit),
                format!("This table speaks protocol {VERSION}, not {v}."),
            );
        }
        let Asset::Dream = asset;
        if !fair::is_hex64(nonce) {
            return err(
                member,
                Some(commit),
                "Your nonce must be 64 lowercase hex characters.",
            );
        }
        let Some(stake) = self.stake_for(bb) else {
            return err(
                member,
                Some(commit),
                format!("No table at a big blind of {bb}."),
            );
        };
        if self.in_hand(member) {
            return err(member, Some(commit), "You are already in a hand.");
        }
        let session = self.sessions.entry(member.to_string()).or_default();
        session.seen = now;
        let Some((secret, offered)) = session.offer.take() else {
            return err(member, Some(commit), "Ask for an offer first.");
        };
        if offered != commit {
            // give the member a fresh offer rather than leave them stuck
            let offer = self.offer(member, now);
            return vec![
                Effect::Send(
                    member.to_string(),
                    ToHero::Error {
                        commit: Some(commit.to_string()),
                        message: "That offer has expired; here is a new one.".into(),
                    },
                ),
                Effect::Send(member.to_string(), offer),
            ];
        }
        if let Some(why) = self.refusal(member, stake.buyin, balances.hero_asset, now) {
            return err(member, Some(commit), why);
        }
        let house_free = balances
            .house_asset
            .saturating_sub(self.ledger.owing_total());
        if house_free < stake.buyin {
            return err(
                member,
                Some(commit),
                "The house cannot cover this buy-in right now.",
            );
        }
        if self.cap_left(now) < stake.buyin {
            return err(
                member,
                Some(commit),
                "The house has paid out its daily limit; the table reopens tomorrow.",
            );
        }
        let seed = fair::seed_of(&secret, nonce);
        let session = self.sessions.entry(member.to_string()).or_default();
        let button = session.next_button;
        session.next_button = if button == HERO { HOUSE } else { HERO };
        let seats = [member.to_string(), self.house.pubkey.clone()];
        self.deal(
            commit,
            seats,
            true,
            secret,
            vec![nonce.to_string()],
            seed,
            &stake,
            button,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn deal(
        &mut self,
        commit: &str,
        seats: [String; 2],
        house: bool,
        secret: String,
        nonces: Vec<String>,
        seed: String,
        stake: &rules::Stakes,
        button: u32,
        now: u64,
    ) -> Vec<Effect> {
        let cfg = HandConfig {
            seats: seats
                .iter()
                .map(|pk| SeatConfig {
                    name: pk.clone(),
                    stack: stake.buyin,
                })
                .collect(),
            button,
            sb: stake.sb,
            bb: stake.bb,
            ante: 0,
            seed_hex: seed.clone(),
            limit: true,
        };
        let hand = match engine::new_hand(&cfg) {
            Ok(h) => h,
            Err(e) => return err(&seats[0], Some(commit), format!("The deal failed: {e}")),
        };
        for pk in seats
            .iter()
            .filter(|pk| !house || pk.as_str() != self.house.pubkey)
        {
            self.sessions.entry(pk.clone()).or_default().live = Some(commit.to_string());
        }
        self.hands.insert(
            commit.to_string(),
            Live {
                seats,
                house,
                secret,
                nonces,
                seed,
                buyin: stake.buyin,
                hand,
            },
        );
        self.after_change(commit, now)
    }

    #[allow(clippy::too_many_arguments)]
    fn challenge(
        &mut self,
        from: &str,
        v: u32,
        opponent: &str,
        bb: u64,
        nonce: &str,
        now: u64,
        balances: Balances,
    ) -> Vec<Effect> {
        if v != VERSION {
            return err(
                from,
                None,
                format!("This table speaks protocol {VERSION}, not {v}."),
            );
        }
        if !fair::is_hex64(nonce) {
            return err(
                from,
                None,
                "Your nonce must be 64 lowercase hex characters.",
            );
        }
        if opponent == from || opponent == self.house.pubkey {
            return err(
                from,
                None,
                "Challenge another member; the house deals this hand.",
            );
        }
        let Some(stake) = self.stake_for(bb) else {
            return err(from, None, format!("No table at a big blind of {bb}."));
        };
        if self.in_hand(from) {
            return err(from, None, "You are already in a hand.");
        }
        self.sessions.entry(from.to_string()).or_default().seen = now;
        if !self.present(from, now).iter().any(|p| p == opponent) {
            return err(from, None, "That member is not at the table right now.");
        }
        if let Some(why) = self.refusal(from, stake.buyin, balances.hero_asset, now) {
            return err(from, None, why);
        }
        if self
            .challenges
            .values()
            .any(|c| c.from == from && c.expires > now)
        {
            return err(from, None, "Your last challenge is still waiting.");
        }
        let (secret, commit) = self.fresh_secret();
        let expires = now + CHALLENGE_TTL;
        self.challenges.insert(
            commit.clone(),
            Challenge {
                from: from.to_string(),
                to: opponent.to_string(),
                bb,
                nonce: nonce.to_string(),
                secret,
                expires,
            },
        );
        vec![
            Effect::Send(
                opponent.to_string(),
                ToHero::Challenged {
                    commit: commit.clone(),
                    from: from.to_string(),
                    bb,
                    buyin: stake.buyin,
                    expires,
                },
            ),
            Effect::Send(
                from.to_string(),
                ToHero::Waiting {
                    commit,
                    opponent: opponent.to_string(),
                    expires,
                },
            ),
        ]
    }

    fn accept(
        &mut self,
        from: &str,
        commit: &str,
        nonce: &str,
        now: u64,
        balances: Balances,
    ) -> Vec<Effect> {
        let Some(ch) = self.challenges.get(commit).cloned() else {
            return err(from, Some(commit), "That challenge is no longer open.");
        };
        if ch.to != from {
            return err(from, Some(commit), "That challenge is not yours to accept.");
        }
        if ch.expires < now {
            self.challenges.remove(commit);
            return vec![
                Effect::Send(
                    from.to_string(),
                    ToHero::Error {
                        commit: Some(commit.to_string()),
                        message: "That challenge has lapsed.".into(),
                    },
                ),
                Effect::Send(
                    ch.from,
                    ToHero::Declined {
                        commit: commit.to_string(),
                        by: self.house.pubkey.clone(),
                    },
                ),
            ];
        }
        if !fair::is_hex64(nonce) {
            return err(
                from,
                Some(commit),
                "Your nonce must be 64 lowercase hex characters.",
            );
        }
        let Some(stake) = self.stake_for(ch.bb) else {
            return err(from, Some(commit), "That table is no longer offered.");
        };
        if self.in_hand(from) || self.in_hand(&ch.from) {
            return err(from, Some(commit), "One of you is already in a hand.");
        }
        self.sessions.entry(from.to_string()).or_default().seen = now;
        if let Some(why) = self.refusal(from, stake.buyin, balances.hero_asset, now) {
            return err(from, Some(commit), why);
        }
        self.challenges.remove(commit);
        let seed = fair::seed_of_many(&ch.secret, &[&ch.nonce, nonce]);
        let seats = [ch.from.clone(), from.to_string()];
        // the challenger has the button
        self.deal(
            commit,
            seats,
            false,
            ch.secret,
            vec![ch.nonce, nonce.to_string()],
            seed,
            &stake,
            0,
            now,
        )
    }

    fn member_act(&mut self, from: &str, commit: &str, action: Action, now: u64) -> Vec<Effect> {
        let Some(live) = self.hands.get_mut(commit) else {
            return err(from, Some(commit), "That is not a hand in play.");
        };
        let Some(seat) = Self::seat_of(live, from) else {
            return err(from, Some(commit), "You are not in that hand.");
        };
        if action.seat != seat {
            return err(from, Some(commit), "You may only act for your own seat.");
        }
        if !live.hand.in_play() || live.hand.to_act != seat as i32 {
            return err(from, Some(commit), "It is not your turn.");
        }
        match engine::act(&live.hand, &action) {
            Ok(h) => live.hand = h,
            Err(e) => return err(from, Some(commit), e.0),
        }
        self.after_change(commit, now)
    }

    /// The house's turn in the hand named by `commit`, if it is its turn.
    pub fn bot_turn(&mut self, commit: &str, now: u64) -> Vec<Effect> {
        let Some(live) = self.hands.get_mut(commit) else {
            return Vec::new();
        };
        if !live.house || !live.hand.in_play() || live.hand.to_act != HOUSE as i32 {
            return Vec::new();
        }
        let Some(l) = engine::legal(&live.hand) else {
            return Vec::new();
        };
        let view = engine::seat_view(&live.hand, HOUSE);
        let step = live.hand.log.len();
        let action = match engine::Rng::from_seed(&fair::bot_seed(&live.seed, step)) {
            Ok(mut rng) => bots::decide(&view, &l, &self.bot.profile, &mut rng),
            Err(_) => Action {
                seat: HOUSE,
                action: if l.allows("check") { "check" } else { "fold" }.into(),
                amount: None,
            },
        };
        match engine::act(&live.hand, &action) {
            Ok(h) => live.hand = h,
            Err(e) => {
                let member = live.seats[0].clone();
                return err(
                    &member,
                    Some(commit),
                    format!("The house could not act: {e}"),
                );
            }
        }
        self.after_change(commit, now)
    }

    /// After the hand moved: tell the players, queue the house's turn, or
    /// settle.
    fn after_change(&mut self, commit: &str, now: u64) -> Vec<Effect> {
        let Some(live) = self.hands.get(commit) else {
            return Vec::new();
        };
        if live.hand.in_play() {
            let mut out = Vec::new();
            for (i, pk) in live.seats.iter().enumerate() {
                if live.house && i == HOUSE as usize {
                    continue;
                }
                out.push(Effect::Send(
                    pk.clone(),
                    Self::state_for(commit, live, i as u32),
                ));
            }
            if live.house && live.hand.to_act == HOUSE as i32 {
                out.push(Effect::BotTurn(commit.to_string()));
            }
            return out;
        }
        self.settle(commit, now)
    }

    fn settle(&mut self, commit: &str, now: u64) -> Vec<Effect> {
        let Some(live) = self.hands.remove(commit) else {
            return Vec::new();
        };
        for pk in &live.seats {
            if let Some(s) = self.sessions.get_mut(pk) {
                if s.live.as_deref() == Some(commit) {
                    s.live = None;
                }
            }
        }
        let Some(record) = record_of(&live.hand, Some(&live.seats)) else {
            return err(
                &live.seats[0],
                Some(commit),
                "The hand ended without a result.",
            );
        };
        let root = match record.root() {
            Ok(r) => r,
            Err(e) => {
                return err(
                    &live.seats[0],
                    Some(commit),
                    format!("The record cannot be rooted: {e}"),
                )
            }
        };
        let mut out = Vec::new();
        // each player's side of the settlement
        for (i, pk) in live.seats.iter().enumerate() {
            if live.house && i == HOUSE as usize {
                continue;
            }
            let after = live.hand.seats[i].stack;
            let settlement = match rules::settlement(true, after, live.buyin) {
                Ok(s) => s,
                Err(e) => return err(pk, Some(commit), format!("The hand cannot be settled: {e}")),
            };
            out.push(Effect::Send(
                pk.clone(),
                ToHero::Done {
                    commit: commit.to_string(),
                    seat: i as u32,
                    opponent: live.seats[1 - i].clone(),
                    house: live.house,
                    view: engine::seat_view(&live.hand, i as u32),
                    log: live.hand.log.clone(),
                    secret: live.secret.clone(),
                    nonces: live.nonces.clone(),
                    seed: live.seed.clone(),
                    record: record.clone(),
                    root: root.clone(),
                    buyin: live.buyin,
                    settlement,
                },
            ));
        }
        // the book, from seat 0's side
        let seat0 = &live.seats[0];
        let net0 = live.hand.seats[0].stack as i64 - live.buyin as i64;
        self.ledger.settled(seat0, &root, net0, now);
        match rules::settlement(true, live.hand.seats[0].stack, live.buyin) {
            Ok(Some(Settlement {
                from: Side::Hero,
                amount,
                ..
            })) => {
                // seat 0 owes seat 1 (the house, or the other member)
                self.ledger.owed.push(Owed {
                    hero: seat0.clone(),
                    to: live.seats[1].clone(),
                    root: root.clone(),
                    amount,
                    since: now,
                    claimed: None,
                });
            }
            Ok(Some(Settlement {
                from: Side::Citizen,
                amount,
                ..
            })) => {
                if live.house {
                    self.ledger.owing.push(Owing {
                        hero: seat0.clone(),
                        root: root.clone(),
                        amount,
                        since: now,
                        attempts: 0,
                        last_attempt: 0,
                        last_error: None,
                    });
                    if self.cap_left(now) >= amount {
                        out.push(Effect::Pay {
                            hero: seat0.clone(),
                            root: root.clone(),
                            amount,
                        });
                    }
                } else {
                    // seat 1, a member, owes seat 0
                    self.ledger.owed.push(Owed {
                        hero: live.seats[1].clone(),
                        to: seat0.clone(),
                        root: root.clone(),
                        amount,
                        since: now,
                        claimed: None,
                    });
                }
            }
            _ => {}
        }
        out.push(Effect::Persist);
        for (i, pk) in live.seats.iter().enumerate() {
            if live.house && i == HOUSE as usize {
                continue;
            }
            let offer = self.offer(pk, now);
            out.push(Effect::Send(pk.clone(), offer));
        }
        out
    }

    /// The chain shows `hand:<root>` transfers (root → recipient pubkey →
    /// base units): clear the debts they pay.
    pub fn payments_seen(
        &mut self,
        paid: &std::collections::BTreeMap<String, std::collections::BTreeMap<String, u64>>,
    ) -> Vec<Effect> {
        let cleared = self.ledger.payments_seen(paid);
        if cleared.is_empty() {
            Vec::new()
        } else {
            vec![Effect::Persist]
        }
    }

    /// The house's transfer for a hand was accepted by the producer.
    pub fn house_paid(&mut self, hero: &str, root: &str, txid: &str, now: u64) -> Vec<Effect> {
        if self.ledger.house_paid(root, txid, now).is_none() {
            return Vec::new();
        }
        vec![
            Effect::Send(
                hero.to_string(),
                ToHero::Paid {
                    root: root.to_string(),
                    txid: txid.to_string(),
                },
            ),
            Effect::Persist,
        ]
    }

    /// The house's transfer for a hand failed; it stays owed.
    pub fn house_pay_failed(&mut self, root: &str, why: &str, now: u64) -> Vec<Effect> {
        self.ledger.house_pay_failed(root, why, now);
        vec![Effect::Persist]
    }

    /// Settlements the house owes and may pay now: within the daily cap and
    /// not attempted in the last `retry_after` seconds.
    pub fn payable(&self, now: u64, retry_after: u64) -> Vec<Effect> {
        let mut left = self.cap_left(now);
        let mut out = Vec::new();
        for o in &self.ledger.owing {
            if o.amount > left || now.saturating_sub(o.last_attempt) < retry_after {
                continue;
            }
            left -= o.amount;
            out.push(Effect::Pay {
                hero: o.hero.clone(),
                root: o.root.clone(),
                amount: o.amount,
            });
        }
        out
    }

    /// Time passes: lapse old challenges (telling the challenger) and forget
    /// stale sessions.
    pub fn tick(&mut self, now: u64) -> Vec<Effect> {
        let lapsed: Vec<(String, Challenge)> = self
            .challenges
            .iter()
            .filter(|(_, c)| c.expires < now)
            .map(|(k, c)| (k.clone(), c.clone()))
            .collect();
        let mut out = Vec::new();
        for (commit, ch) in lapsed {
            self.challenges.remove(&commit);
            out.push(Effect::Send(
                ch.from,
                ToHero::Declined {
                    commit,
                    by: self.house.pubkey.clone(),
                },
            ));
        }
        self.sessions
            .retain(|_, s| s.live.is_some() || now.saturating_sub(s.seen) <= PRESENCE_TTL * 10);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_bbs_poker::verify::{verify, Claim, RustEngine};

    fn citizen() -> Citizen {
        let mut n = 0u8;
        Citizen::new(
            Config {
                stakes_bb: vec![2, 20],
                buyin_bb: 100,
                profile: "tag".into(),
                daily_cap: 5_000,
                claim_grace_secs: 600,
                // a BLAKES7 house seat: every member-facing figure names it
                ticker: "BLAKES7".into(),
            },
            House {
                pubkey: "c".repeat(64),
                script_hex: format!("5120{}", "c".repeat(64)),
            },
            Ledger::default(),
            Box::new(move || {
                n = n.wrapping_add(1);
                [n; 32]
            }),
        )
    }

    const HERO_PK: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER_PK: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const RICH: Balances = Balances {
        hero_asset: 10_000,
        house_asset: 10_000,
    };

    fn offer_commit(effects: &[Effect]) -> String {
        effects
            .iter()
            .find_map(|e| match e {
                Effect::Send(_, ToHero::Offer { commit, .. }) => Some(commit.clone()),
                _ => None,
            })
            .expect("an offer")
    }

    fn hello(c: &mut Citizen, who: &str, now: u64) -> Vec<Effect> {
        c.handle(who, ToCitizen::Hello { v: VERSION }, now, RICH)
    }

    fn sit(c: &mut Citizen, commit: &str, bb: u64, nonce: &str, bal: Balances) -> Vec<Effect> {
        c.handle(
            HERO_PK,
            ToCitizen::Sit {
                v: VERSION,
                commit: commit.into(),
                asset: Asset::Dream,
                bb,
                nonce: nonce.into(),
            },
            1_000,
            bal,
        )
    }

    fn challenge(c: &mut Citizen, from: &str, to: &str, bb: u64, now: u64) -> Vec<Effect> {
        c.handle(
            from,
            ToCitizen::Challenge {
                v: VERSION,
                opponent: to.into(),
                bb,
                nonce: "11".repeat(32),
            },
            now,
            RICH,
        )
    }

    /// Drive effects to quiescence: bot turns run, and every member to act
    /// calls or checks.
    fn drive(c: &mut Citizen, mut effects: Vec<Effect>, bal: Balances) -> Vec<Effect> {
        let mut all = Vec::new();
        let mut guard = 0;
        loop {
            guard += 1;
            assert!(guard < 200);
            let mut next = Vec::new();
            for e in effects.drain(..) {
                match &e {
                    Effect::BotTurn(commit) => next.extend(c.bot_turn(commit, 1_001)),
                    Effect::Send(
                        to,
                        ToHero::State {
                            commit, seat, view, ..
                        },
                    ) if view.to_act == *seat as i32 => {
                        let l = engine::legal(&c.hands[commit].hand).unwrap();
                        let a = if l.allows("check") { "check" } else { "call" };
                        next.extend(c.handle(
                            to,
                            ToCitizen::Act {
                                commit: commit.clone(),
                                action: Action {
                                    seat: *seat,
                                    action: a.into(),
                                    amount: None,
                                },
                            },
                            1_002,
                            bal,
                        ));
                        all.push(e.clone());
                    }
                    _ => all.push(e.clone()),
                }
            }
            if next.is_empty() {
                break;
            }
            effects = next;
        }
        all
    }

    fn done_for<'a>(all: &'a [Effect], who: &str) -> &'a ToHero {
        all.iter()
            .find_map(|e| match e {
                Effect::Send(to, d @ ToHero::Done { .. }) if to == who => Some(d),
                _ => None,
            })
            .expect("a done message")
    }

    #[test]
    fn hello_offers_tables_a_commitment_and_who_is_present() {
        let mut c = citizen();
        let out = hello(&mut c, HERO_PK, 1_000);
        match &out[0] {
            Effect::Send(
                to,
                ToHero::Offer {
                    tables,
                    commit,
                    citizen,
                    daily_cap_left,
                    present,
                    ..
                },
            ) => {
                assert_eq!(to, HERO_PK);
                assert_eq!(tables.len(), 2);
                assert_eq!(tables[1].buyin, 2_000);
                assert!(fair::is_hex64(commit));
                assert_eq!(citizen, &"c".repeat(64));
                assert_eq!(*daily_cap_left, 5_000);
                assert!(present.is_empty());
            }
            other => panic!("{other:?}"),
        }
        let out = hello(&mut c, OTHER_PK, 1_010);
        if let Effect::Send(_, ToHero::Offer { present, .. }) = &out[0] {
            assert_eq!(present, &[HERO_PK.to_string()]);
        } else {
            panic!("{out:?}");
        }
        // presence lapses
        let out = hello(&mut c, OTHER_PK, 1_010 + PRESENCE_TTL + 1);
        if let Effect::Send(_, ToHero::Offer { present, .. }) = &out[0] {
            assert!(present.is_empty());
        }
        let wrong = c.handle(HERO_PK, ToCitizen::Hello { v: 9 }, 1_000, RICH);
        assert!(matches!(&wrong[0], Effect::Send(_, ToHero::Error { .. })));
    }

    #[test]
    fn sit_is_refused_without_funds_or_with_a_stale_offer() {
        let mut c = citizen();
        let commit = offer_commit(&hello(&mut c, HERO_PK, 1_000));
        let poor = Balances {
            hero_asset: 1_999,
            house_asset: 10_000,
        };
        let out = sit(&mut c, &commit, 20, &"ab".repeat(32), poor);
        assert!(
            matches!(&out[0], Effect::Send(_, ToHero::Error { message, .. }) if message.contains("BLAKES7; this table's buy-in is 2000"))
        );
        // the offer was consumed by the refused sit: a new one is needed
        let out = sit(&mut c, &commit, 20, &"ab".repeat(32), RICH);
        assert!(
            matches!(&out[0], Effect::Send(_, ToHero::Error { message, .. }) if message.contains("offer first"))
        );
        let _ = offer_commit(&hello(&mut c, HERO_PK, 1_000));
        let out = sit(&mut c, &"0".repeat(64), 20, &"ab".repeat(32), RICH);
        assert!(
            matches!(&out[0], Effect::Send(_, ToHero::Error { message, .. }) if message.contains("expired"))
        );
        assert!(matches!(&out[1], Effect::Send(_, ToHero::Offer { .. })));
        let fresh = offer_commit(&hello(&mut c, HERO_PK, 1_000));
        let out = sit(&mut c, &fresh, 7, &"ab".repeat(32), RICH);
        assert!(
            matches!(&out[0], Effect::Send(_, ToHero::Error { message, .. }) if message.contains("No table"))
        );
        let broke_house = Balances {
            hero_asset: 10_000,
            house_asset: 100,
        };
        let fresh = offer_commit(&hello(&mut c, HERO_PK, 1_000));
        let out = sit(&mut c, &fresh, 20, &"ab".repeat(32), broke_house);
        assert!(
            matches!(&out[0], Effect::Send(_, ToHero::Error { message, .. }) if message.contains("house cannot cover"))
        );
    }

    #[test]
    fn a_house_hand_plays_to_a_verifiable_record_and_settles() {
        let mut c = citizen();
        let commit = offer_commit(&hello(&mut c, HERO_PK, 1_000));
        let seated = sit(&mut c, &commit, 20, &"ab".repeat(32), RICH);
        let all = drive(&mut c, seated, RICH);
        let ToHero::Done {
            commit,
            secret,
            nonces,
            seed,
            record,
            root,
            buyin,
            settlement,
            view,
            seat,
            opponent,
            house,
            ..
        } = done_for(&all, HERO_PK).clone()
        else {
            unreachable!()
        };
        assert_eq!((seat, house), (HERO, true));
        assert_eq!(opponent, "c".repeat(64));
        assert_eq!(buyin, 2_000);
        assert!(fair::check_commit(&secret, &commit));
        assert_eq!(nonces, ["ab".repeat(32)]);
        assert_eq!(seed, fair::seed_of(&secret, &nonces[0]));
        assert_eq!(record.root().unwrap(), root);
        assert_eq!(record.seats[0].name, HERO_PK);
        assert_eq!(record.seats[1].name, "c".repeat(64));
        let claim = Claim {
            commit: &commit,
            secret: &secret,
            nonces: nonces.clone(),
            seed: &seed,
            record: &record,
            house_seat: Some(HOUSE),
            profile: "tag",
        };
        verify(&RustEngine, &claim).unwrap();
        let hero_after = view.seats[0].stack;
        assert_eq!(
            settlement,
            rules::settlement(true, hero_after, buyin).unwrap()
        );
        assert_eq!(c.ledger.hands, 1);
        assert!(all.iter().any(|e| matches!(e, Effect::Persist)));
        assert!(matches!(
            all.last(),
            Some(Effect::Send(_, ToHero::Offer { .. }))
        ));
        match settlement {
            Some(Settlement {
                from: Side::Hero,
                amount,
                ..
            }) => {
                assert_eq!(c.ledger.owed[0].amount, amount);
                assert_eq!(c.ledger.owed[0].to, "c".repeat(64));
                assert!(c.ledger.owing.is_empty());
            }
            Some(Settlement {
                from: Side::Citizen,
                amount,
                ..
            }) => {
                assert_eq!(c.ledger.owing[0].amount, amount);
                assert!(all
                    .iter()
                    .any(|e| matches!(e, Effect::Pay { amount: a, .. } if *a == amount)));
            }
            None => assert!(c.ledger.owed.is_empty() && c.ledger.owing.is_empty()),
        }
        for e in &all {
            if let Effect::Send(_, ToHero::State { view, .. }) = e {
                assert!(view.seats[1].hole.is_none(), "house cards leaked mid-hand");
            }
        }
        // the house never received a message
        assert!(!all
            .iter()
            .any(|e| matches!(e, Effect::Send(to, _) if to == &"c".repeat(64))));
    }

    #[test]
    fn two_members_play_a_dealt_hand_and_the_loser_owes_the_winner() {
        let mut c = citizen();
        hello(&mut c, HERO_PK, 1_000);
        hello(&mut c, OTHER_PK, 1_000);
        let out = challenge(&mut c, HERO_PK, OTHER_PK, 20, 1_000);
        let commit = match &out[0] {
            Effect::Send(
                to,
                ToHero::Challenged {
                    commit,
                    from,
                    buyin,
                    ..
                },
            ) => {
                assert_eq!(to, OTHER_PK);
                assert_eq!(from, HERO_PK);
                assert_eq!(*buyin, 2_000);
                commit.clone()
            }
            other => panic!("{other:?}"),
        };
        assert!(matches!(&out[1], Effect::Send(to, ToHero::Waiting { .. }) if to == HERO_PK));
        // a second challenge while one waits is refused
        let again = challenge(&mut c, HERO_PK, OTHER_PK, 20, 1_001);
        assert!(
            matches!(&again[0], Effect::Send(_, ToHero::Error { message, .. }) if message.contains("still waiting"))
        );
        // only the opponent may accept
        let wrong = c.handle(
            HERO_PK,
            ToCitizen::Accept {
                commit: commit.clone(),
                nonce: "22".repeat(32),
            },
            1_001,
            RICH,
        );
        assert!(matches!(&wrong[0], Effect::Send(_, ToHero::Error { .. })));
        let accepted = c.handle(
            OTHER_PK,
            ToCitizen::Accept {
                commit: commit.clone(),
                nonce: "22".repeat(32),
            },
            1_001,
            RICH,
        );
        // both get a state; no bot turn
        assert_eq!(
            accepted
                .iter()
                .filter(|e| matches!(e, Effect::Send(_, ToHero::State { .. })))
                .count(),
            2
        );
        assert!(!accepted.iter().any(|e| matches!(e, Effect::BotTurn(_))));
        assert!(c.in_hand(HERO_PK) && c.in_hand(OTHER_PK));
        let all = drive(&mut c, accepted, RICH);
        let ToHero::Done {
            seat,
            house,
            opponent,
            nonces,
            seed,
            secret,
            record,
            settlement,
            ..
        } = done_for(&all, HERO_PK).clone()
        else {
            unreachable!()
        };
        assert_eq!((seat, house), (0, false));
        assert_eq!(opponent, OTHER_PK);
        assert_eq!(nonces, ["11".repeat(32), "22".repeat(32)]);
        assert_eq!(
            seed,
            fair::seed_of_many(
                &secret,
                &["11".repeat(32).as_str(), "22".repeat(32).as_str()]
            )
        );
        let claim = Claim {
            commit: &commit,
            secret: &secret,
            nonces: nonces.clone(),
            seed: &seed,
            record: &record,
            house_seat: None,
            profile: "tag",
        };
        verify(&RustEngine, &claim).unwrap();
        let ToHero::Done {
            seat: oseat,
            opponent: oopp,
            settlement: osett,
            ..
        } = done_for(&all, OTHER_PK).clone()
        else {
            unreachable!()
        };
        assert_eq!((oseat, oopp.as_str()), (1, HERO_PK));
        // the two settlements mirror each other
        match (settlement, osett) {
            (None, None) => {}
            (Some(a), Some(b)) => {
                assert_eq!(a.amount, b.amount);
                assert_ne!(a.from, b.from);
            }
            other => panic!("{other:?}"),
        }
        // the loser, if any, owes the winner, never the house
        for o in &c.ledger.owed {
            assert_ne!(o.to, "c".repeat(64));
            assert!(o.hero == HERO_PK || o.hero == OTHER_PK);
        }
        assert!(c.ledger.owing.is_empty());
        // both got fresh offers
        assert_eq!(
            all.iter()
                .filter(|e| matches!(e, Effect::Send(_, ToHero::Offer { .. })))
                .count(),
            2
        );
    }

    #[test]
    fn a_challenge_can_be_declined_or_lapse() {
        let mut c = citizen();
        hello(&mut c, HERO_PK, 1_000);
        hello(&mut c, OTHER_PK, 1_000);
        let out = challenge(&mut c, HERO_PK, OTHER_PK, 2, 1_000);
        let Effect::Send(_, ToHero::Challenged { commit, .. }) = &out[0] else {
            panic!()
        };
        let commit = commit.clone();
        let declined = c.handle(
            OTHER_PK,
            ToCitizen::Decline {
                commit: commit.clone(),
            },
            1_001,
            RICH,
        );
        assert!(
            matches!(&declined[0], Effect::Send(to, ToHero::Declined { by, .. }) if to == HERO_PK && by == OTHER_PK)
        );
        // a lapse
        let out = challenge(&mut c, HERO_PK, OTHER_PK, 2, 1_002);
        let Effect::Send(_, ToHero::Challenged { commit, .. }) = &out[0] else {
            panic!()
        };
        let commit = commit.clone();
        assert!(c.tick(1_003).is_empty());
        let lapsed = c.tick(1_002 + CHALLENGE_TTL + 1);
        assert!(
            matches!(&lapsed[0], Effect::Send(to, ToHero::Declined { by, .. }) if to == HERO_PK && by == &"c".repeat(64))
        );
        let late = c.handle(
            OTHER_PK,
            ToCitizen::Accept {
                commit,
                nonce: "22".repeat(32),
            },
            1_002 + CHALLENGE_TTL + 2,
            RICH,
        );
        assert!(
            matches!(&late[0], Effect::Send(_, ToHero::Error { message, .. }) if message.contains("no longer open"))
        );
        // a challenge to someone not present
        let gone = challenge(
            &mut c,
            HERO_PK,
            &"d".repeat(64),
            2,
            1_002 + CHALLENGE_TTL + 2,
        );
        assert!(
            matches!(&gone[0], Effect::Send(_, ToHero::Error { message, .. }) if message.contains("not at the table"))
        );
    }

    #[test]
    fn a_debtor_is_refused_until_the_chain_shows_the_payment() {
        let mut c = citizen();
        c.ledger.owed.push(Owed {
            hero: HERO_PK.into(),
            to: "c".repeat(64),
            root: "1".repeat(64),
            amount: 40,
            since: 900,
            claimed: None,
        });
        let out = hello(&mut c, HERO_PK, 1_000);
        if let Effect::Send(_, ToHero::Offer { owed, .. }) = &out[0] {
            assert_eq!(owed.len(), 1);
        } else {
            panic!("{out:?}");
        }
        let commit = offer_commit(&out);
        let out = sit(&mut c, &commit, 20, &"ab".repeat(32), RICH);
        assert!(
            matches!(&out[0], Effect::Send(_, ToHero::Error { message, .. }) if message.contains("BLAKES7 for hand") && message.contains("has not been paid"))
        );
        let claimed = c.handle(
            HERO_PK,
            ToCitizen::Paid {
                root: "1".repeat(64),
                txid: "2".repeat(64),
            },
            1_000,
            RICH,
        );
        assert_eq!(claimed, [Effect::Persist]);
        let commit = offer_commit(&hello(&mut c, HERO_PK, 1_000));
        let out = sit(&mut c, &commit, 20, &"ab".repeat(32), RICH);
        assert!(
            matches!(&out[0], Effect::Send(_, ToHero::State { .. })),
            "{out:?}"
        );
        // leave on one's own turn: the hand is folded and settled
        let out = c.handle(
            HERO_PK,
            ToCitizen::Leave {
                commit: Some(commit.clone()),
            },
            1_003,
            RICH,
        );
        assert!(out
            .iter()
            .any(|e| matches!(e, Effect::Send(_, ToHero::Done { .. }))));
        assert!(!c.in_hand(HERO_PK));
        // the grace runs out without the chain showing it
        let commit = offer_commit(&hello(&mut c, HERO_PK, 2_000));
        let out = c.handle(
            HERO_PK,
            ToCitizen::Sit {
                v: VERSION,
                commit,
                asset: Asset::Dream,
                bb: 20,
                nonce: "ab".repeat(32),
            },
            2_000,
            RICH,
        );
        assert!(
            matches!(&out[0], Effect::Send(_, ToHero::Error { message, .. }) if message.contains("chain has not shown"))
        );
        // the chain shows it, to the right recipient
        let mut paid = std::collections::BTreeMap::new();
        let mut to = std::collections::BTreeMap::new();
        to.insert("c".repeat(64), 40u64);
        paid.insert("1".repeat(64), to);
        assert_eq!(c.payments_seen(&paid), [Effect::Persist]);
        assert!(c.ledger.owed.iter().all(|o| o.root != "1".repeat(64)));
    }

    #[test]
    fn payouts_respect_the_daily_cap_and_retry() {
        let mut c = citizen();
        for root in ["3", "4"] {
            c.ledger.owing.push(Owing {
                hero: HERO_PK.into(),
                root: root.repeat(64),
                amount: 4_000,
                since: 100,
                attempts: 0,
                last_attempt: 0,
                last_error: None,
            });
        }
        assert_eq!(c.payable(1_000, 60).len(), 1);
        let out = c.house_paid(HERO_PK, &"3".repeat(64), &"5".repeat(64), 1_000);
        assert!(matches!(&out[0], Effect::Send(_, ToHero::Paid { .. })));
        assert_eq!(c.ledger.paid_today(1_000), 4_000);
        assert!(c.payable(1_000, 60).is_empty());
        assert_eq!(c.payable(90_000, 60).len(), 1);
        c.house_pay_failed(&"4".repeat(64), "no coins", 90_000);
        assert!(c.payable(90_010, 60).is_empty());
        assert_eq!(c.payable(90_100, 60).len(), 1);
        let out = hello(&mut c, HERO_PK, 90_100);
        if let Effect::Send(
            _,
            ToHero::Offer {
                owing,
                daily_cap_left,
                ..
            },
        ) = &out[0]
        {
            assert_eq!(owing.len(), 1);
            assert_eq!(*daily_cap_left, 5_000);
        } else {
            panic!("{out:?}");
        }
    }

    #[test]
    fn acting_out_of_turn_or_for_the_house_is_refused() {
        let mut c = citizen();
        let commit = offer_commit(&hello(&mut c, HERO_PK, 1_000));
        let out = sit(&mut c, &commit, 2, &"ab".repeat(32), RICH);
        assert!(matches!(&out[0], Effect::Send(_, ToHero::State { .. })));
        let fold = |seat| Action {
            seat,
            action: "fold".into(),
            amount: None,
        };
        let bad = c.handle(
            HERO_PK,
            ToCitizen::Act {
                commit: commit.clone(),
                action: fold(HOUSE),
            },
            1_001,
            RICH,
        );
        assert!(
            matches!(&bad[0], Effect::Send(_, ToHero::Error { message, .. }) if message.contains("own seat"))
        );
        let bad = c.handle(
            HERO_PK,
            ToCitizen::Act {
                commit: "9".repeat(64),
                action: fold(HERO),
            },
            1_001,
            RICH,
        );
        assert!(
            matches!(&bad[0], Effect::Send(_, ToHero::Error { message, .. }) if message.contains("not a hand"))
        );
        let bad = c.handle(
            OTHER_PK,
            ToCitizen::Act {
                commit: commit.clone(),
                action: fold(HERO),
            },
            1_001,
            RICH,
        );
        assert!(
            matches!(&bad[0], Effect::Send(_, ToHero::Error { message, .. }) if message.contains("not in that hand"))
        );
        let again = hello(&mut c, HERO_PK, 1_002);
        assert!(matches!(&again[0], Effect::Send(_, ToHero::State { .. })));
    }
}
