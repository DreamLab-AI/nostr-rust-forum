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

use crate::ledger::{Cause, Ledger, Owed, Owing, Pending, Replaced, REFUSALS_PER_ALERT};
use crate::state::{SavedHand, SeenEntry, State};

/// The member's seat in a hand against the house.
pub const HERO: u32 = 0;
/// The house's seat in a hand against the house.
pub const HOUSE: u32 = 1;
/// A member counts as present this long after their last hello, seconds.
pub const PRESENCE_TTL: u64 = 180;
/// A challenge lapses after this long, seconds.
pub const CHALLENGE_TTL: u64 = 120;
/// A member who has not acted for this long on their own turn folds the
/// hand, seconds. Without it an abandoned hand would hold the house's
/// buy-in back from the bankroll and the daily cap for ever.
pub const HAND_IDLE_SECS: u64 = 30 * 60;

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
        /// The payout already signed for this hand, if any: it is sent
        /// again as it is, or replaced only when the chain shows its coins
        /// went elsewhere ([`Pending::resume`]).
        pending: Option<Pending>,
    },
    /// The ledger changed; save it.
    Persist,
    /// Something an operator must look at: say it loudly.
    Alert(String),
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
    /// When the hand last moved (or was recovered), unix seconds.
    updated: u64,
}

/// What a voided hand shows of its deal.
struct Reveal {
    secret: String,
    nonces: Vec<String>,
    seed: String,
    log: Vec<engine::LogEntry>,
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
    /// State a saved copy does not yet show.
    dirty: bool,
}

/// What came back from a saved state.
#[derive(Debug, Clone, PartialEq)]
pub struct Recovered {
    /// What to do now: the house's turn in each recovered hand that waits
    /// on it.
    pub effects: Vec<Effect>,
    /// Hands resumed, by commitment.
    pub resumed: Vec<String>,
    /// Hands that could not be trusted and were voided, by commitment, with
    /// why. A void moves no funds: a hand's stakes are notional until it
    /// settles.
    pub voided: Vec<(String, String)>,
    /// Messages already processed.
    pub seen: Vec<SeenEntry>,
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
            dirty: false,
        }
    }

    /// A house seat carrying on from `state`.
    ///
    /// Every hand in the state is resumed where it stood, provided it still
    /// proves itself: the secret must match the commitment, the seed must be
    /// the one the secret and nonces fix, and replaying the saved actions
    /// from the deal must reproduce the saved hand exactly. A hand that does
    /// not is voided (see [`Recovered::voided`]), never played on. `now`
    /// restarts each resumed hand's idle clock, so downtime is not held
    /// against the member.
    pub fn restore(
        cfg: Config,
        house: House,
        state: State,
        secrets: Box<dyn FnMut() -> [u8; 32]>,
        now: u64,
    ) -> (Self, Recovered) {
        let State { ledger, live, seen } = state;
        let mut c = Self::new(cfg, house, ledger, secrets);
        let mut effects = Vec::new();
        let mut resumed = Vec::new();
        let mut voided = Vec::new();
        for saved in live {
            let commit = saved.commit.clone();
            let (saved_seats, saved_house) = (saved.seats.clone(), saved.house);
            let (saved_secret, saved_nonces) = (saved.secret.clone(), saved.nonces.clone());
            let (saved_seed, saved_log) = (saved.seed.clone(), saved.hand.log.clone());
            match c.resume(saved, now) {
                Ok(()) => {
                    if c.hands[&commit].house && c.hands[&commit].hand.to_act == HOUSE as i32 {
                        effects.push(Effect::BotTurn(commit.clone()));
                    }
                    resumed.push(commit);
                }
                Err(why) => {
                    // the member is told, with the deal revealed so it can
                    // be checked, and the book records it
                    effects.extend(c.void(
                        &commit,
                        &saved_seats,
                        saved_house,
                        Reveal {
                            secret: saved_secret,
                            nonces: saved_nonces,
                            seed: saved_seed,
                            log: saved_log,
                        },
                        &why,
                        now,
                    ));
                    voided.push((commit, why));
                }
            }
        }
        if !voided.is_empty() {
            c.dirty = true;
        }
        (
            c,
            Recovered {
                effects,
                resumed,
                voided,
                seen,
            },
        )
    }

    /// End a hand the house cannot carry on. No funds move: a hand's stakes
    /// are notional until it settles, so nothing is owed either way. Each
    /// member is told why and given the deal to check, the book records it,
    /// and each gets a fresh offer.
    fn void(
        &mut self,
        commit: &str,
        seats: &[String; 2],
        house: bool,
        reveal: Reveal,
        why: &str,
        now: u64,
    ) -> Vec<Effect> {
        self.dirty = true;
        let mut out = Vec::new();
        for (i, pk) in seats.iter().enumerate() {
            if house && i == HOUSE as usize {
                continue;
            }
            if let Some(s) = self.sessions.get_mut(pk) {
                if s.live.as_deref() == Some(commit) {
                    s.live = None;
                }
            }
            self.ledger.voided(pk, commit, why, now);
            out.push(Effect::Send(
                pk.clone(),
                ToHero::Voided {
                    commit: commit.to_string(),
                    why: why.to_string(),
                    secret: reveal.secret.clone(),
                    nonces: reveal.nonces.clone(),
                    seed: reveal.seed.clone(),
                    log: reveal.log.clone(),
                },
            ));
            let offer = self.offer(pk, now);
            out.push(Effect::Send(pk.clone(), offer));
        }
        out
    }

    /// The coins of every payout signed and not yet shown on the chain, as
    /// `txid:vout`: held back from the bankroll and from coin selection. A
    /// payout's coins stay held as long as its debt does, whether or not the
    /// producer has accepted it, and are free again only when the debt
    /// clears (the chain shows the payment) or its signed transfer is
    /// dropped (the chain shows its coins went elsewhere).
    pub fn held_outpoints(&self) -> Vec<String> {
        self.ledger
            .owing
            .iter()
            .filter_map(|o| o.pending.as_ref())
            .flat_map(|p| p.outpoints.iter())
            .cloned()
            .collect()
    }

    /// Whether the house holds a session for `member`: they have said hello,
    /// or are in a hand.
    pub fn has_standing(&self, member: &str) -> bool {
        self.sessions.contains_key(member)
    }

    fn resume(&mut self, saved: SavedHand, now: u64) -> Result<(), String> {
        let hand = self.rebuild(&saved)?;
        if self.hands.contains_key(&saved.commit) {
            return Err("the commitment is already in play".into());
        }
        for pk in &saved.seats {
            if self.sessions.get(pk).is_some_and(|s| s.live.is_some()) {
                return Err(format!("{}… is already in another hand", &pk[..8]));
            }
        }
        for (i, pk) in saved.seats.iter().enumerate() {
            if saved.house && i == HOUSE as usize {
                continue;
            }
            self.sessions.entry(pk.clone()).or_default().live = Some(saved.commit.clone());
        }
        self.hands.insert(
            saved.commit,
            Live {
                seats: saved.seats,
                house: saved.house,
                secret: saved.secret,
                nonces: saved.nonces,
                seed: saved.seed,
                buyin: saved.buyin,
                hand,
                updated: now,
            },
        );
        Ok(())
    }

    /// The saved hand, if it proves itself: see [`Citizen::restore`].
    fn rebuild(&self, s: &SavedHand) -> Result<Hand, String> {
        if !fair::is_hex64(&s.commit) || !fair::check_commit(&s.secret, &s.commit) {
            return Err("the secret does not match the commitment".into());
        }
        let nonces: Vec<&str> = s.nonces.iter().map(String::as_str).collect();
        if nonces.len() != if s.house { 1 } else { 2 }
            || fair::seed_of_many(&s.secret, &nonces) != s.seed
        {
            return Err("the seed is not the one the secret and nonces fix".into());
        }
        let house = &self.house.pubkey;
        let seats_ok = s.seats.iter().enumerate().all(|(i, pk)| {
            if s.house && i == HOUSE as usize {
                pk == house
            } else {
                fair::is_hex64(pk) && pk != house
            }
        }) && s.seats[0] != s.seats[1];
        if !seats_ok {
            return Err("the seats are not a member and the house, or two members".into());
        }
        if s.buyin == 0 {
            return Err("the buy-in is zero".into());
        }
        let saved = &s.hand;
        let cfg = HandConfig {
            seats: s
                .seats
                .iter()
                .map(|pk| SeatConfig {
                    name: pk.clone(),
                    stack: s.buyin,
                })
                .collect(),
            button: saved.button,
            sb: saved.sb,
            bb: saved.bb,
            ante: saved.ante,
            seed_hex: s.seed.clone(),
            limit: saved.limit,
        };
        let mut hand = engine::new_hand(&cfg).map_err(|e| format!("the deal failed: {e}"))?;
        for entry in &saved.log {
            if !matches!(
                entry.ev.as_str(),
                "fold" | "check" | "call" | "bet" | "raise"
            ) {
                continue;
            }
            let Some(seat) = entry.seat else {
                return Err("an action in the log has no seat".into());
            };
            let action = Action {
                seat,
                action: entry.ev.clone(),
                amount: entry.to,
            };
            hand = engine::act(&hand, &action).map_err(|e| format!("replay: {}", e.0))?;
        }
        if hand != *saved {
            return Err("replaying the saved actions does not give the saved hand".into());
        }
        if !hand.in_play() {
            return Err("the hand is already over".into());
        }
        Ok(hand)
    }

    /// Everything that must survive a restart, for the runner to save:
    /// the book, the hands in play and `seen`, the relay events already
    /// acted on. Hands are ordered by commitment, so equal states give
    /// equal files.
    pub fn state(&self, seen: Vec<SeenEntry>) -> State {
        let mut live: Vec<SavedHand> = self
            .hands
            .iter()
            .map(|(commit, l)| SavedHand {
                commit: commit.clone(),
                seats: l.seats.clone(),
                house: l.house,
                secret: l.secret.clone(),
                nonces: l.nonces.clone(),
                seed: l.seed.clone(),
                buyin: l.buyin,
                hand: l.hand.clone(),
            })
            .collect();
        live.sort_by(|a, b| a.commit.cmp(&b.commit));
        State {
            ledger: self.ledger.clone(),
            live,
            seen,
        }
    }

    /// Save what changed, through `save`. The runner calls this after every
    /// step of the table and sends nothing the step produced unless it
    /// returns `Ok`: a hand's cards, a settlement's secret and a payout
    /// must never leave on the strength of a change a restart would forget.
    /// On `Err` the state stays dirty, so the next call tries again.
    ///
    /// # Errors
    ///
    /// Whatever `save` reports.
    pub fn checkpoint(
        &mut self,
        seen: Vec<SeenEntry>,
        save: impl FnOnce(&State) -> Result<(), String>,
    ) -> Result<(), String> {
        if !self.dirty {
            return Ok(());
        }
        save(&self.state(seen))?;
        self.dirty = false;
        Ok(())
    }

    /// Whether the table has changes not yet saved.
    pub fn is_dirty(&self) -> bool {
        self.dirty
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

    /// Base units the house stands behind in the hands it is playing: the
    /// most it can lose in a hand is the buy-in, so each house hand holds
    /// one back from the bankroll and the daily cap until it settles.
    /// Hands between two members hold nothing: the house moves no funds.
    pub fn reserved(&self) -> u64 {
        self.hands
            .values()
            .filter(|l| l.house)
            .fold(0u64, |sum, l| sum.saturating_add(l.buyin))
    }

    /// Everything the house is already bound to pay: hands in play and
    /// settled hands not yet paid.
    fn committed(&self) -> u64 {
        self.reserved().saturating_add(self.ledger.owing_total())
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
            ToCitizen::Act {
                commit,
                action,
                log_len,
            } => self.member_act(from, &commit, action, log_len, now),
            ToCitizen::Paid { root, txid } => {
                if !fair::is_hex64(&root) || txid.len() != 64 {
                    return Vec::new();
                }
                if self.ledger.claim(from, &root, &txid, now) {
                    self.dirty = true;
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
                            out = self.member_act(from, &c, fold, None, now);
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
        // Acceptance reserves the buy-in: the house may lose all of it, so
        // it is set against the bankroll and the day's cap together with
        // every hand already dealt and every payout already owed. All of it
        // is derived from the state this `&mut self` call holds, so two
        // sits answered from one chain read cannot both claim the same
        // coins.
        let committed = self.committed();
        if balances.house_asset < committed.saturating_add(stake.buyin) {
            return err(
                member,
                Some(commit),
                "The house cannot cover this buy-in right now.",
            );
        }
        if self.cap_left(now) < committed.saturating_add(stake.buyin) {
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
                updated: now,
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

    fn member_act(
        &mut self,
        from: &str,
        commit: &str,
        action: Action,
        log_len: Option<usize>,
        now: u64,
    ) -> Vec<Effect> {
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
        if log_len.is_some_and(|n| n != live.hand.log.len()) {
            return err(
                from,
                Some(commit),
                "That action answers an earlier state of the hand.",
            );
        }
        match engine::act(&live.hand, &action) {
            Ok(h) => {
                live.hand = h;
                live.updated = now;
            }
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
            Ok(h) => {
                live.hand = h;
                live.updated = now;
            }
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
        self.dirty = true;
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
                        pending: None,
                        accepted_at: None,
                        rebuilds: 0,
                        invalid_rebuilds: 0,
                        refusals: 0,
                        halted: None,
                    });
                    if self.cap_left(now) >= amount {
                        out.push(Effect::Pay {
                            hero: seat0.clone(),
                            root: root.clone(),
                            amount,
                            pending: None,
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
        now: u64,
    ) -> Vec<Effect> {
        let cleared = self.ledger.payments_seen(paid, now);
        if cleared.is_empty() {
            Vec::new()
        } else {
            self.dirty = true;
            vec![Effect::Persist]
        }
    }

    /// The house's transfer for a hand was accepted by the producer.
    pub fn house_paid(&mut self, hero: &str, root: &str, txid: &str, now: u64) -> Vec<Effect> {
        // the debt stays, with its signed transfer and the coins it spends,
        // until the chain shows the payment
        if self.ledger.house_paid(root, txid, now).is_none() {
            return Vec::new();
        }
        self.dirty = true;
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
        self.dirty = true;
        vec![Effect::Persist]
    }

    /// The house has signed its payout for `root` and is about to send it.
    /// Kept with the debt, and saved by the runner first, so that a lost
    /// response, a retry or a crash between the producer accepting it and
    /// the ledger learning of it all send these same bytes and never a
    /// second transfer for the hand. `false` when `root` is no longer owed:
    /// send nothing.
    pub fn pay_prepared(&mut self, root: &str, pending: Pending, now: u64) -> bool {
        if !self.ledger.pay_prepared(root, pending, now) {
            return false;
        }
        self.dirty = true;
        true
    }

    /// The signed payout kept for `root`, if any.
    pub fn pending_of(&self, root: &str) -> Option<Pending> {
        self.ledger.pending_of(root).cloned()
    }

    /// Replace the signed payout for `root`: the chain shows its coins went
    /// elsewhere, or that it was included and rejected. Nothing is signed
    /// here; the debt comes up again through [`Citizen::payable`], and so
    /// through the daily-cap check. A debt replaced after rejection more
    /// than once, or replaced too often, is halted and an alert is raised.
    pub fn replace_payout(&mut self, root: &str, cause: Cause, now: u64) -> Vec<Effect> {
        let Some(replaced) = self.ledger.rebuild(root, cause, now) else {
            return Vec::new();
        };
        self.dirty = true;
        let mut out = vec![Effect::Persist];
        if replaced == Replaced::Halted {
            out.push(Effect::Alert(format!(
                "HALTED hand {}…: {}",
                &root[..root.len().min(12)],
                self.ledger.halted(root).unwrap_or("replaced too often")
            )));
        }
        out
    }

    /// Debts no payout is signed for until an operator looks: hand root and
    /// why.
    pub fn halted(&self) -> Vec<(String, String)> {
        self.ledger
            .owing
            .iter()
            .filter_map(|o| Some((o.root.clone(), o.halted.clone()?)))
            .collect()
    }

    /// Whether the debt for `root` is halted.
    pub fn is_halted(&self, root: &str) -> bool {
        self.ledger.halted(root).is_some()
    }

    /// The producer definitely refused the payout for `root` (as opposed to
    /// not being reached). The same bytes are tried again later and no
    /// replacement is signed; every [`REFUSALS_PER_ALERT`] refusals an
    /// alert is raised for an operator.
    pub fn house_pay_refused(&mut self, root: &str, why: &str, now: u64) -> Vec<Effect> {
        let n = self.ledger.pay_refused(root, why, now);
        self.dirty = true;
        let mut out = vec![Effect::Persist];
        if n > 0 && n % REFUSALS_PER_ALERT == 0 {
            out.push(Effect::Alert(format!(
                "the producer has refused the payout for hand {}… {n} times: {why}",
                &root[..root.len().min(12)]
            )));
        }
        out
    }

    /// Settlements the house owes and may pay now: within the daily cap and
    /// not attempted in the last `retry_after` seconds.
    pub fn payable(&self, now: u64, retry_after: u64) -> Vec<Effect> {
        let mut left = self.cap_left(now);
        let mut out = Vec::new();
        for o in &self.ledger.owing {
            if o.halted.is_some() || now.saturating_sub(o.last_attempt) < retry_after {
                continue;
            }
            // a payout the producer accepted is already counted against the
            // day; one not yet sent must fit what is left of it
            if o.accepted_at.is_none() {
                if o.amount > left {
                    continue;
                }
                left -= o.amount;
            }
            out.push(Effect::Pay {
                hero: o.hero.clone(),
                root: o.root.clone(),
                amount: o.amount,
                pending: o.pending.clone(),
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
        // a member who left a hand waiting on them folds it, so it settles
        // and releases what it holds
        let mut idle: Vec<(String, String, u32)> = self
            .hands
            .iter()
            .filter(|(_, l)| {
                l.hand.in_play()
                    && now.saturating_sub(l.updated) > HAND_IDLE_SECS
                    && !(l.house && l.hand.to_act == HOUSE as i32)
            })
            .filter_map(|(commit, l)| {
                let seat = u32::try_from(l.hand.to_act).ok()?;
                Some((commit.clone(), l.seats.get(seat as usize)?.clone(), seat))
            })
            .collect();
        idle.sort();
        // a house turn that cannot be taken must not hold its reservation
        // for ever
        let mut stuck: Vec<String> = self
            .hands
            .iter()
            .filter(|(_, l)| {
                l.house
                    && l.hand.in_play()
                    && l.hand.to_act == HOUSE as i32
                    && now.saturating_sub(l.updated) > HAND_IDLE_SECS
            })
            .map(|(c, _)| c.clone())
            .collect();
        stuck.sort();
        for commit in stuck {
            if let Some(l) = self.hands.remove(&commit) {
                out.extend(self.void(
                    &commit,
                    &l.seats,
                    l.house,
                    Reveal {
                        secret: l.secret,
                        nonces: l.nonces,
                        seed: l.seed,
                        log: l.hand.log,
                    },
                    "the house could not take its turn",
                    now,
                ));
            }
        }
        for (commit, member, seat) in idle {
            let fold = Action {
                seat,
                action: "fold".into(),
                amount: None,
            };
            out.extend(self.member_act(&member, &commit, fold, None, now));
        }
        self.sessions
            .retain(|_, s| s.live.is_some() || now.saturating_sub(s.seen) <= PRESENCE_TTL * 10);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{Resume, TxOnChain};
    use nostr_bbs_poker::verify::{verify, Claim, RustEngine};

    fn config() -> Config {
        Config {
            stakes_bb: vec![2, 20],
            buyin_bb: 100,
            profile: "tag".into(),
            daily_cap: 5_000,
            claim_grace_secs: 600,
            // a BLAKES7 house seat: every member-facing figure names it
            ticker: "BLAKES7".into(),
        }
    }

    fn house() -> House {
        House {
            pubkey: "c".repeat(64),
            script_hex: format!("5120{}", "c".repeat(64)),
        }
    }

    fn citizen() -> Citizen {
        let mut n = 0u8;
        Citizen::new(
            config(),
            house(),
            Ledger::default(),
            Box::new(move || {
                n = n.wrapping_add(1);
                [n; 32]
            }),
        )
    }

    /// The house after a restart: what it saved, read back from the file.
    fn restarted(c: &Citizen, now: u64) -> (Citizen, Recovered) {
        let saved = c
            .state(vec![SeenEntry {
                sender: HERO_PK.into(),
                key: "e1".into(),
                at: 7,
            }])
            .to_json();
        let state = State::parse(&saved).expect("the saved state reads back");
        Citizen::restore(config(), house(), state, Box::new(|| [0x77; 32]), now)
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
                                log_len: None,
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

    /// A distinct member key, 64 lowercase hex.
    fn member(n: u64) -> String {
        format!("{n:064x}")
    }

    /// Sit `who` at the 20-big-blind table, as the runner would: every
    /// request in one poll reads the same chain balances.
    fn sit_member(c: &mut Citizen, who: &str, bal: Balances, now: u64) -> Vec<Effect> {
        let commit = offer_commit(&c.handle(who, ToCitizen::Hello { v: VERSION }, now, bal));
        c.handle(
            who,
            ToCitizen::Sit {
                v: VERSION,
                commit,
                asset: Asset::Dream,
                bb: 20,
                nonce: "ab".repeat(32),
            },
            now,
            bal,
        )
    }

    /// Play `who`'s hand against the house to its end, checking or calling.
    fn play_out(c: &mut Citizen, who: &str, bal: Balances) -> Vec<Effect> {
        let commit = c.sessions[who].live.clone().expect("in a hand");
        let mut all = Vec::new();
        for _ in 0..200 {
            let Some(live) = c.hands.get(&commit) else {
                break;
            };
            let effects = if live.hand.to_act == HERO as i32 {
                let l = engine::legal(&live.hand).expect("in play");
                let a = if l.allows("check") { "check" } else { "call" };
                c.handle(
                    who,
                    ToCitizen::Act {
                        log_len: None,
                        commit: commit.clone(),
                        action: Action {
                            seat: HERO,
                            action: a.into(),
                            amount: None,
                        },
                    },
                    1_002,
                    bal,
                )
            } else {
                c.bot_turn(&commit, 1_002)
            };
            all.extend(effects);
        }
        all
    }

    fn seated(out: &[Effect]) -> bool {
        out.iter()
            .any(|e| matches!(e, Effect::Send(_, ToHero::State { .. })))
    }

    fn refused_with(out: &[Effect], needle: &str) -> bool {
        out.iter().any(
            |e| matches!(e, Effect::Send(_, ToHero::Error { message, .. }) if message.contains(needle)),
        )
    }

    #[test]
    fn concurrent_buy_ins_cannot_overdraw_the_house_bankroll() {
        let mut c = citizen();
        // the chain shows the house with exactly three buy-ins (2 000 each)
        // of free coins; the daily cap is out of the way
        c.cfg.daily_cap = 1_000_000;
        let bal = Balances {
            hero_asset: 10_000,
            house_asset: 6_000,
        };
        let mut accepted = 0;
        for n in 1..=6 {
            let out = sit_member(&mut c, &member(n), bal, 1_000);
            if seated(&out) {
                accepted += 1;
            } else {
                assert!(refused_with(&out, "house cannot cover"), "{out:?}");
            }
        }
        assert_eq!(accepted, 3, "the house can stand behind three buy-ins");
        assert_eq!(c.reserved(), 6_000);
    }

    #[test]
    fn concurrent_buy_ins_cannot_exceed_the_daily_cap() {
        let mut c = citizen(); // cap 5 000, buy-in 2 000
        let mut accepted = 0;
        for n in 1..=4 {
            let out = sit_member(&mut c, &member(n), RICH, 1_000);
            if seated(&out) {
                accepted += 1;
            } else {
                assert!(refused_with(&out, "daily limit"), "{out:?}");
            }
        }
        assert_eq!(
            accepted, 2,
            "two buy-ins fit under a 5 000 cap, three do not"
        );
        assert!(c.reserved() <= c.cfg.daily_cap);
    }

    #[test]
    fn what_the_house_already_owes_counts_against_new_buy_ins() {
        let mut c = citizen();
        c.cfg.daily_cap = 1_000_000;
        c.ledger.owing.push(Owing {
            hero: member(9),
            root: "7".repeat(64),
            amount: 1_500,
            since: 900,
            attempts: 0,
            last_attempt: 0,
            last_error: None,
            pending: None,
            accepted_at: None,
            rebuilds: 0,
            invalid_rebuilds: 0,
            refusals: 0,
            halted: None,
        });
        let bal = Balances {
            hero_asset: 10_000,
            house_asset: 3_400,
        };
        // 3 400 - 1 500 owed = 1 900 free: not enough for a 2 000 buy-in
        let out = sit_member(&mut c, &member(1), bal, 1_000);
        assert!(refused_with(&out, "house cannot cover"), "{out:?}");
    }

    #[test]
    fn settlement_releases_the_reservation() {
        let mut c = citizen();
        c.cfg.daily_cap = 1_000_000;
        let bal = Balances {
            hero_asset: 10_000,
            house_asset: 2_000,
        };
        let out = sit_member(&mut c, HERO_PK, bal, 1_000);
        assert!(seated(&out));
        assert_eq!(c.reserved(), 2_000);
        // a second member is refused while the first hand holds the bankroll
        let out = sit_member(&mut c, OTHER_PK, bal, 1_001);
        assert!(refused_with(&out, "house cannot cover"), "{out:?}");
        play_out(&mut c, HERO_PK, bal);
        assert!(!c.in_hand(HERO_PK), "the hand ran to its end");
        assert_eq!(c.reserved(), 0, "settled hands hold nothing back");
    }

    #[test]
    fn member_versus_member_hands_reserve_nothing() {
        let mut c = citizen();
        hello(&mut c, HERO_PK, 1_000);
        hello(&mut c, OTHER_PK, 1_000);
        let out = challenge(&mut c, HERO_PK, OTHER_PK, 20, 1_000);
        let Effect::Send(_, ToHero::Challenged { commit, .. }) = &out[0] else {
            panic!("{out:?}")
        };
        let accepted = c.handle(
            OTHER_PK,
            ToCitizen::Accept {
                commit: commit.clone(),
                nonce: "22".repeat(32),
            },
            1_001,
            RICH,
        );
        assert!(seated(&accepted));
        assert_eq!(c.reserved(), 0, "the house stands behind neither stack");
    }

    /// One move in `who`'s house hand: theirs if it is their turn, else
    /// the house's.
    fn step(c: &mut Citizen, who: &str, bal: Balances, now: u64) -> Vec<Effect> {
        let commit = c.sessions[who].live.clone().expect("in a hand");
        let live = &c.hands[&commit];
        if live.hand.to_act == HERO as i32 {
            let l = engine::legal(&live.hand).expect("in play");
            let a = if l.allows("check") { "check" } else { "call" };
            c.handle(
                who,
                ToCitizen::Act {
                    log_len: None,
                    commit,
                    action: Action {
                        seat: HERO,
                        action: a.into(),
                        amount: None,
                    },
                },
                now,
                bal,
            )
        } else {
            c.bot_turn(&commit, now)
        }
    }

    /// What a hand left on the books, whoever ran it.
    fn books(c: &Citizen) -> (Vec<Owed>, Vec<Owing>, u64, u64) {
        (
            c.ledger.owed.clone(),
            c.ledger.owing.clone(),
            c.ledger.hands,
            c.reserved(),
        )
    }

    #[test]
    fn a_restart_mid_hand_resumes_it_and_no_funds_are_lost_or_counted_twice() {
        for moves in 0..3 {
            let mut live = citizen();
            let mut twin = citizen();
            for c in [&mut live, &mut twin] {
                assert!(seated(&sit_member(c, HERO_PK, RICH, 1_000)));
            }
            for _ in 0..moves {
                step(&mut live, HERO_PK, RICH, 1_001);
                step(&mut twin, HERO_PK, RICH, 1_001);
            }
            assert!(live.in_hand(HERO_PK), "{moves} moves in, the hand is open");
            // the twin never stops; `live` is killed and restarted
            let (mut live, rec) = restarted(&live, 5_000);
            assert_eq!(rec.resumed.len(), 1);
            assert!(rec.voided.is_empty(), "{:?}", rec.voided);
            assert_eq!(rec.seen.len(), 1);
            assert_eq!(rec.seen[0].key, "e1");
            assert!(live.in_hand(HERO_PK));
            assert_eq!(live.reserved(), twin.reserved(), "the buy-in is still held");
            // the member's reload shows the hand exactly as it stood
            let before = hello(&mut twin, HERO_PK, 1_002);
            let after = hello(&mut live, HERO_PK, 5_001);
            assert_eq!(before, after);
            // both play on to the end
            let a = play_out(&mut twin, HERO_PK, RICH);
            let b = play_out(&mut live, HERO_PK, RICH);
            assert_eq!(done_for(&a, HERO_PK), done_for(&b, HERO_PK));
            assert_eq!(books(&twin), books(&live));
            assert_eq!(live.reserved(), 0);
            assert_eq!(live.ledger.hands, 1, "one hand, counted once");
            let ToHero::Done {
                settlement, buyin, ..
            } = done_for(&b, HERO_PK)
            else {
                unreachable!()
            };
            let owed: u64 = live.ledger.owed.iter().map(|o| o.amount).sum();
            let owing: u64 = live.ledger.owing.iter().map(|o| o.amount).sum();
            match settlement {
                Some(Settlement {
                    from: Side::Hero,
                    amount,
                    ..
                }) => assert_eq!((owed, owing), (*amount, 0)),
                Some(Settlement { amount, .. }) => assert_eq!((owed, owing), (0, *amount)),
                None => assert_eq!((owed, owing), (0, 0)),
            }
            assert!(owed <= *buyin && owing <= *buyin);
        }
    }

    #[test]
    fn a_restart_between_the_deal_and_the_first_message_loses_nothing() {
        // the state is saved when sit returns, before its effects are sent
        let mut c = citizen();
        let out = sit_member(&mut c, HERO_PK, RICH, 1_000);
        assert!(seated(&out));
        assert!(c.is_dirty(), "a deal is a change to save");
        c.checkpoint(Vec::new(), |_| Ok(())).unwrap();
        assert!(!c.is_dirty());
        let (mut r, rec) = restarted(&c, 2_000);
        assert_eq!(rec.resumed.len(), 1);
        let shown = hello(&mut r, HERO_PK, 2_001);
        assert!(matches!(&shown[0], Effect::Send(_, ToHero::State { .. })));
        let all = play_out(&mut r, HERO_PK, RICH);
        let ToHero::Done {
            commit,
            secret,
            nonces,
            seed,
            record,
            ..
        } = done_for(&all, HERO_PK)
        else {
            unreachable!()
        };
        // the resumed hand still verifies against the commitment shown
        // before the restart
        let claim = Claim {
            commit,
            secret,
            nonces: nonces.clone(),
            seed,
            record,
            house_seat: Some(HOUSE),
            profile: "tag",
        };
        verify(&RustEngine, &claim).unwrap();
    }

    #[test]
    fn a_hand_between_two_members_survives_a_restart() {
        let mut c = citizen();
        hello(&mut c, HERO_PK, 1_000);
        hello(&mut c, OTHER_PK, 1_000);
        let out = challenge(&mut c, HERO_PK, OTHER_PK, 20, 1_000);
        let Effect::Send(_, ToHero::Challenged { commit, .. }) = &out[0] else {
            panic!("{out:?}")
        };
        let commit = commit.clone();
        c.handle(
            OTHER_PK,
            ToCitizen::Accept {
                commit: commit.clone(),
                nonce: "22".repeat(32),
            },
            1_001,
            RICH,
        );
        let (r, rec) = restarted(&c, 2_000);
        assert_eq!(rec.resumed, [commit]);
        assert!(r.in_hand(HERO_PK) && r.in_hand(OTHER_PK));
        assert_eq!(r.reserved(), 0);
    }

    #[test]
    fn a_saved_hand_that_does_not_prove_itself_is_voided_and_moves_no_funds() {
        let mut c = citizen();
        assert!(seated(&sit_member(&mut c, HERO_PK, RICH, 1_000)));
        c.checkpoint(Vec::new(), |_| Ok(())).unwrap();
        let good = c.state(Vec::new());
        let mut cases: Vec<(&str, State)> = Vec::new();
        let mut s = good.clone();
        s.live[0].hand.seats[0].stack += 1;
        cases.push(("a stack altered", s));
        let mut s = good.clone();
        s.live[0].secret = "9".repeat(64);
        cases.push(("another secret", s));
        let mut s = good.clone();
        s.live[0].seed = "8".repeat(64);
        cases.push(("another seed", s));
        let mut s = good.clone();
        s.live[0].hand.log.truncate(2);
        cases.push(("a log cut short", s));
        let mut s = good.clone();
        s.live[0].seats[1] = "d".repeat(64);
        cases.push(("another house", s));
        let mut s = good.clone();
        s.live[0].buyin = 0;
        cases.push(("no buy-in", s));
        for (what, state) in cases {
            let ledger = state.ledger.clone();
            let (mut r, rec) =
                Citizen::restore(config(), house(), state, Box::new(|| [1; 32]), 2_000);
            assert_eq!(rec.voided.len(), 1, "{what}");
            assert!(rec.resumed.is_empty(), "{what}");
            assert!(!r.in_hand(HERO_PK), "{what}");
            assert_eq!(r.reserved(), 0, "{what}");
            assert_eq!(
                (&r.ledger.owed, &r.ledger.owing, r.ledger.hands),
                (&ledger.owed, &ledger.owing, ledger.hands),
                "{what}: a void owes nothing either way"
            );
            assert!(
                r.ledger.history[0]
                    .txid
                    .as_deref()
                    .is_some_and(|t| t.starts_with("voided")),
                "{what}: the void is on the record"
            );
            assert!(
                rec.effects.iter().any(|e| matches!(
                    e,
                    Effect::Send(to, ToHero::Voided { why, secret, .. })
                        if to == HERO_PK && !why.is_empty() && !secret.is_empty()
                )),
                "{what}: {:?}",
                rec.effects
            );
            assert!(r.is_dirty(), "{what}: the void is to be saved");
            // the member simply gets a fresh offer
            let out = hello(&mut r, HERO_PK, 2_001);
            assert!(
                matches!(&out[0], Effect::Send(_, ToHero::Offer { .. })),
                "{what}"
            );
        }
    }

    #[test]
    fn a_recovered_hand_waiting_on_the_house_queues_its_turn() {
        let mut c = citizen();
        // the house has the button, so it acts first
        c.sessions.entry(HERO_PK.into()).or_default().next_button = HOUSE;
        let out = sit_member(&mut c, HERO_PK, RICH, 1_000);
        assert!(
            out.iter().any(|e| matches!(e, Effect::BotTurn(_))),
            "{out:?}"
        );
        let (_, rec) = restarted(&c, 2_000);
        let commit = c.sessions[HERO_PK].live.clone().unwrap();
        assert_eq!(rec.effects, [Effect::BotTurn(commit)]);
    }

    #[test]
    fn a_member_who_walks_away_folds_after_the_idle_limit_and_releases_the_bankroll() {
        let mut c = citizen();
        assert!(seated(&sit_member(&mut c, HERO_PK, RICH, 1_000)));
        assert_eq!(c.reserved(), 2_000);
        assert!(c.tick(1_000 + HAND_IDLE_SECS).is_empty(), "not yet");
        assert!(c.in_hand(HERO_PK));
        let out = c.tick(1_000 + HAND_IDLE_SECS + 1);
        assert!(out
            .iter()
            .any(|e| matches!(e, Effect::Send(to, ToHero::Done { .. }) if to == HERO_PK)));
        assert!(!c.in_hand(HERO_PK));
        assert_eq!(c.reserved(), 0);
        assert_eq!(c.ledger.hands, 1);
        assert_eq!(c.ledger.owed.len() + c.ledger.owing.len(), 1);
    }

    #[test]
    fn downtime_is_not_held_against_a_member() {
        let mut c = citizen();
        assert!(seated(&sit_member(&mut c, HERO_PK, RICH, 1_000)));
        let (mut r, _) = restarted(&c, 1_000 + 10 * HAND_IDLE_SECS);
        assert!(r.tick(1_000 + 10 * HAND_IDLE_SECS + 1).is_empty());
        assert!(r.in_hand(HERO_PK));
    }

    fn owing_for(c: &mut Citizen, root: &str, amount: u64) {
        c.ledger.owing.push(Owing {
            hero: HERO_PK.into(),
            root: root.into(),
            amount,
            since: 100,
            attempts: 0,
            last_attempt: 0,
            last_error: None,
            pending: None,
            accepted_at: None,
            rebuilds: 0,
            invalid_rebuilds: 0,
            refusals: 0,
            halted: None,
        });
    }

    fn signed(txid: &str) -> Pending {
        Pending {
            hex: format!("0200{txid}"),
            txid: txid.into(),
            outpoints: vec![format!("{}:1", "e".repeat(64))],
        }
    }

    fn pay_effect(effects: &[Effect]) -> Pending {
        match effects {
            [Effect::Pay {
                pending: Some(p), ..
            }] => p.clone(),
            other => panic!("one payout with its signed transfer: {other:?}"),
        }
    }

    #[test]
    fn a_retry_with_no_chain_evidence_sends_the_same_signed_payout() {
        let root = "3".repeat(64);
        let mut c = citizen();
        owing_for(&mut c, &root, 100);
        assert!(matches!(
            c.payable(1_000, 120).as_slice(),
            [Effect::Pay { pending: None, .. }]
        ));
        let first = signed("aa");
        assert!(c.pay_prepared(&root, first.clone(), 1_000));
        // the response was lost: before the interval, nothing; after it,
        // t+121 s with the chain silent, the very same bytes
        assert!(c.payable(1_119, 120).is_empty());
        assert_eq!(pay_effect(&c.payable(1_121, 120)), first);
        // and across a restart (killed after the producer accepted it)
        let (r, _) = restarted(&c, 1_010);
        assert!(r.payable(1_010, 120).is_empty());
        assert_eq!(pay_effect(&r.payable(1_121, 120)), first);
        // its coins are not the house's to spend or count while it is out
        assert_eq!(r.held_outpoints(), first.outpoints);
        // the chain shows the payment: cleared, never paid again
        let mut r = r;
        let mut paid = std::collections::BTreeMap::new();
        paid.insert(
            root.clone(),
            std::collections::BTreeMap::from([(HERO_PK.to_string(), 100u64)]),
        );
        assert_eq!(r.payments_seen(&paid, 1_200), [Effect::Persist]);
        assert!(r.payable(9_999, 120).is_empty());
    }

    type Paid = std::collections::BTreeMap<String, std::collections::BTreeMap<String, u64>>;

    fn chain_pays(root: &str, hero: &str, amount: u64) -> Paid {
        Paid::from([(
            root.to_string(),
            std::collections::BTreeMap::from([(hero.to_string(), amount)]),
        )])
    }

    #[test]
    fn an_accepted_payout_stays_a_debt_until_the_chain_shows_it() {
        let root = "3".repeat(64);
        let mut c = citizen();
        owing_for(&mut c, &root, 100);
        let p = signed("bb");
        assert!(c.pay_prepared(&root, p.clone(), 1_000));
        // the producer accepts it; the member is told
        let told = c.house_paid(HERO_PK, &root, &p.txid, 1_001);
        assert!(matches!(&told[0], Effect::Send(_, ToHero::Paid { .. })));
        // the debt, its signed transfer and its coins all stay
        assert_eq!(c.ledger.owing.len(), 1);
        assert_eq!(c.pending_of(&root), Some(p.clone()));
        assert_eq!(c.held_outpoints(), p.outpoints);
        assert_eq!(c.ledger.paid_today(1_001), 100, "counted against the day");
        assert!(
            c.house_paid(HERO_PK, &root, &p.txid, 1_002).is_empty(),
            "once"
        );
        // the transfer never appears on the chain: long past any holding
        // period nothing is lost, and the same bytes are sent again
        let much_later = 1_001 + 24 * 3_600;
        assert_eq!(pay_effect(&c.payable(much_later, 120)), p);
        let (r, _) = restarted(&c, much_later);
        assert_eq!(r.ledger.owing.len(), 1);
        assert_eq!(r.held_outpoints(), p.outpoints, "still not free bankroll");
        assert_eq!(pay_effect(&r.payable(much_later, 120)), p);
        // the chain shows the coins went elsewhere and no transfer of ours:
        // a new one is signed for the same debt, and the day's count is
        // given back
        let mut r = r;
        assert_eq!(p.resume(TxOnChain::NotSeen, false), Resume::Rebuild);
        r.replace_payout(&root, Cause::SpentElsewhere, much_later);
        assert!(r.held_outpoints().is_empty());
        assert_eq!(r.ledger.paid_today(1_001), 0);
        assert!(matches!(
            r.payable(much_later + 121, 120).as_slice(),
            [Effect::Pay {
                pending: None,
                amount: 100,
                ..
            }]
        ));
        // and when it does land, the debt clears exactly once
        let second = signed("cc");
        assert!(r.pay_prepared(&root, second.clone(), much_later));
        r.house_paid(HERO_PK, &root, &second.txid, much_later + 1);
        assert_eq!(
            r.payments_seen(&chain_pays(&root, HERO_PK, 100), much_later + 60),
            [Effect::Persist]
        );
        assert!(r.ledger.owing.is_empty() && r.held_outpoints().is_empty());
        assert_eq!(r.ledger.paid_today(much_later), 100, "paid once, not twice");
        assert!(r.payable(much_later + 999, 120).is_empty());
    }

    /// A debt of `amount` whose payout was signed, accepted and sits on the
    /// books as paid out.
    fn accepted_debt(c: &mut Citizen, root: &str, amount: u64, txid: &str, now: u64) -> Pending {
        let p = signed(txid);
        if c.ledger.owing.iter().all(|o| o.root != root) {
            owing_for(c, root, amount);
        }
        assert!(c.pay_prepared(root, p.clone(), now));
        c.house_paid(HERO_PK, root, txid, now + 1);
        p
    }

    fn alerts(effects: &[Effect]) -> Vec<&String> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::Alert(a) => Some(a),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_rejected_payout_is_replaced_once_through_the_cap_and_then_the_debt_halts() {
        let root = "3".repeat(64);
        let mut c = citizen(); // daily cap 5 000
        let t0 = 1_000;
        accepted_debt(&mut c, &root, 3_000, "aa", t0);
        assert_eq!(c.ledger.paid_today(t0), 3_000);
        // the chain includes it and the assets rule rejects it: the coins
        // were really spent, so the day's count is NOT given back
        let out = c.replace_payout(&root, Cause::Invalid, t0 + 200);
        assert!(alerts(&out).is_empty(), "the first replacement is routine");
        assert_eq!(c.ledger.paid_today(t0), 3_000);
        assert!(c.pending_of(&root).is_none() && c.held_outpoints().is_empty());
        // nothing is signed here, and the replacement goes through the cap:
        // 3 000 spent leaves 2 000, which does not cover 3 000
        assert!(c.payable(t0 + 400, 120).is_empty(), "the cap is respected");
        // tomorrow it fits, and exactly one replacement is asked for
        let tomorrow = t0 + 86_400;
        assert!(matches!(
            c.payable(tomorrow, 120).as_slice(),
            [Effect::Pay {
                pending: None,
                amount: 3_000,
                ..
            }]
        ));
        accepted_debt(&mut c, &root, 3_000, "bb", tomorrow);
        assert_eq!(c.ledger.paid_today(tomorrow), 3_000);
        // the same thing happens again: systematic, so halt for an operator
        let out = c.replace_payout(&root, Cause::Invalid, tomorrow + 200);
        assert_eq!(alerts(&out).len(), 1, "{out:?}");
        assert!(c.is_halted(&root));
        assert_eq!(c.halted().len(), 1);
        assert_eq!(c.ledger.paid_today(tomorrow), 3_000, "still not refunded");
        // no more automatic signing, on any day, and the debt stays
        for day in 2..6 {
            assert!(c.payable(t0 + day * 86_400, 120).is_empty());
        }
        assert!(!c.pay_prepared(&root, signed("cc"), t0 + 9 * 86_400));
        assert_eq!(c.ledger.owing.len(), 1, "the debt stays visible");
        // and a restart does not forget it
        let (r, _) = restarted(&c, t0 + 9 * 86_400);
        assert!(r.is_halted(&root));
        assert!(r.payable(t0 + 10 * 86_400, 120).is_empty());
        let offer = {
            let mut r = r;
            hello(&mut r, HERO_PK, t0 + 10 * 86_400)
        };
        assert!(matches!(
            &offer[0],
            Effect::Send(_, ToHero::Offer { owing, .. }) if owing.len() == 1
        ));
    }

    #[test]
    fn a_systematic_rejection_makes_at_most_one_replacement() {
        let root = "3".repeat(64);
        let mut c = citizen();
        let mut signed_payouts = 0;
        let mut now = 1_000;
        // every payout the house signs is rejected by the chain; the
        // supervisor polls every 120 s for a week
        for _ in 0..(7 * 86_400 / 120) {
            now += 120;
            if c.ledger.owing.is_empty() {
                owing_for(&mut c, &root, 100);
            }
            if let Some(p) = c.pending_of(&root) {
                // on the chain, rejected
                let _ = p;
                c.replace_payout(&root, Cause::Invalid, now);
                continue;
            }
            for e in c.payable(now, 120) {
                if let Effect::Pay { root: r, .. } = e {
                    signed_payouts += 1;
                    let p = accepted_debt(&mut c, &r, 100, &format!("tx{signed_payouts}"), now);
                    let _ = p;
                }
            }
        }
        assert_eq!(signed_payouts, 2, "the first, and one replacement");
        assert!(c.is_halted(&root));
    }

    #[test]
    fn a_replacement_after_coins_spent_elsewhere_also_goes_through_the_cap() {
        let root = "3".repeat(64);
        let mut c = citizen(); // cap 5 000
        let t0 = 1_000;
        // 3 000 already paid to others today
        c.ledger.paid.insert(crate::ledger::day_of(t0), 3_000);
        accepted_debt(&mut c, &root, 3_000, "aa", t0);
        // a payout that never landed gives its count back: 3 000 paid, 2 000
        // left, which does not cover the 3 000 debt
        let out = c.replace_payout(&root, Cause::SpentElsewhere, t0 + 200);
        assert!(alerts(&out).is_empty());
        assert_eq!(c.ledger.paid_today(t0), 3_000);
        assert!(c.payable(t0 + 400, 120).is_empty(), "the cap is checked");
        // with room, it is asked for through `payable`, not signed inline
        c.ledger.paid.insert(crate::ledger::day_of(t0), 0);
        assert!(matches!(
            c.payable(t0 + 400, 120).as_slice(),
            [Effect::Pay { pending: None, .. }]
        ));
        // being spent elsewhere again and again also ends in a halt
        for i in 0..3u64 {
            accepted_debt(&mut c, &root, 3_000, &format!("x{i}"), t0 + 500 + i * 10);
            c.replace_payout(&root, Cause::SpentElsewhere, t0 + 505 + i * 10);
        }
        assert!(c.is_halted(&root));
    }

    #[test]
    fn repeated_refusals_of_the_same_bytes_alert_an_operator_and_never_rebuild() {
        let root = "3".repeat(64);
        let mut c = citizen();
        owing_for(&mut c, &root, 100);
        let p = signed("aa");
        assert!(c.pay_prepared(&root, p.clone(), 1_000));
        let mut raised = Vec::new();
        for i in 1..=REFUSALS_PER_ALERT * 2 {
            let out = c.house_pay_refused(&root, "the producer refused: bad fee", 1_000 + i as u64);
            raised.push((i, alerts(&out).len()));
        }
        let at: Vec<u32> = raised
            .iter()
            .filter(|(_, n)| *n > 0)
            .map(|(i, _)| *i)
            .collect();
        assert_eq!(at, [REFUSALS_PER_ALERT, REFUSALS_PER_ALERT * 2]);
        // the same bytes remain; no replacement, no halt
        assert_eq!(c.pending_of(&root), Some(p));
        assert!(!c.is_halted(&root));
        // a refusal of a payout already accepted is the producer
        // recognising it, not a failure
        c.house_paid(HERO_PK, &root, "aa", 2_000);
        let out = c.house_pay_refused(&root, "already known", 2_100);
        assert!(alerts(&out).is_empty());
        assert_eq!(c.ledger.owing[0].refusals, REFUSALS_PER_ALERT * 2);
    }

    #[test]
    fn a_payout_is_prepared_only_for_a_hand_still_owed() {
        let root = "3".repeat(64);
        let mut c = citizen();
        owing_for(&mut c, &root, 100);
        assert!(c.pay_prepared(&root, signed("cc"), 1_000));
        c.house_paid(HERO_PK, &root, "cc", 1_001);
        assert!(
            c.pay_prepared(&root, signed("cc"), 1_200),
            "unconfirmed is still owed"
        );
        c.payments_seen(&chain_pays(&root, HERO_PK, 100), 1_300);
        assert!(!c.pay_prepared(&root, signed("dd"), 1_400), "already paid");
        assert!(c.pending_of(&root).is_none());
    }

    #[test]
    fn only_a_member_the_house_holds_a_session_for_has_standing() {
        let mut c = citizen();
        assert!(!c.has_standing(HERO_PK));
        hello(&mut c, HERO_PK, 1_000);
        assert!(c.has_standing(HERO_PK));
        assert!(!c.has_standing(OTHER_PK));
    }

    #[test]
    fn a_failed_save_keeps_the_table_dirty_and_is_retried() {
        let mut c = citizen();
        assert!(seated(&sit_member(&mut c, HERO_PK, RICH, 1_000)));
        assert!(c.is_dirty());
        let failed = c.checkpoint(Vec::new(), |_| Err("disk full".into()));
        assert_eq!(failed, Err("disk full".to_string()));
        assert!(c.is_dirty(), "the change is still unsaved");
        let mut saved = None;
        c.checkpoint(Vec::new(), |s| {
            saved = Some(s.clone());
            Ok(())
        })
        .unwrap();
        assert!(!c.is_dirty());
        assert_eq!(
            saved.unwrap().live.len(),
            1,
            "the hand is in what was saved"
        );
        // nothing to save is not a write
        c.checkpoint(Vec::new(), |_| Err("must not be called".into()))
            .unwrap();
    }

    #[test]
    fn a_stale_or_replayed_act_is_refused_by_the_log_length_it_answers() {
        let mut c = citizen();
        let out = sit_member(&mut c, HERO_PK, RICH, 1_000);
        assert!(seated(&out));
        let commit = c.sessions[HERO_PK].live.clone().unwrap();
        let len = c.hands[&commit].hand.log.len();
        let act = |c: &mut Citizen, log_len: Option<usize>| {
            let l = engine::legal(&c.hands[&commit].hand).unwrap();
            let a = if l.allows("check") { "check" } else { "call" };
            c.handle(
                HERO_PK,
                ToCitizen::Act {
                    commit: commit.clone(),
                    action: Action {
                        seat: HERO,
                        action: a.into(),
                        amount: None,
                    },
                    log_len,
                },
                1_001,
                RICH,
            )
        };
        let wrong = act(&mut c, Some(len + 3));
        assert!(refused_with(&wrong, "earlier state"), "{wrong:?}");
        assert_eq!(c.hands[&commit].hand.log.len(), len, "nothing applied");
        let ok = act(&mut c, Some(len));
        assert!(!refused_with(&ok, "earlier state"));
        assert!(c.hands[&commit].hand.log.len() > len);
        // the same message again, a turn later, is a copy of the past
        while c.in_hand(HERO_PK) && c.hands[&commit].hand.to_act != HERO as i32 {
            c.bot_turn(&commit, 1_002);
        }
        if c.in_hand(HERO_PK) {
            let again = act(&mut c, Some(len));
            assert!(refused_with(&again, "earlier state"), "{again:?}");
        }
    }

    #[test]
    fn a_house_turn_that_cannot_be_taken_is_voided_and_releases_the_bankroll() {
        let mut c = citizen();
        c.sessions.entry(HERO_PK.into()).or_default().next_button = HOUSE;
        assert!(seated(&sit_member(&mut c, HERO_PK, RICH, 1_000)));
        assert_eq!(c.reserved(), 2_000);
        // the BotTurn is never run
        assert!(c.tick(1_000 + HAND_IDLE_SECS).is_empty());
        let out = c.tick(1_000 + HAND_IDLE_SECS + 1);
        assert!(out
            .iter()
            .any(|e| matches!(e, Effect::Send(to, ToHero::Voided { .. }) if to == HERO_PK)));
        assert_eq!(c.reserved(), 0);
        assert!(!c.in_hand(HERO_PK));
        assert!(c.ledger.owed.is_empty() && c.ledger.owing.is_empty());
        assert_eq!(c.ledger.hands, 0);
    }

    #[test]
    fn a_restart_replays_a_members_raise() {
        let mut c = citizen();
        assert!(seated(&sit_member(&mut c, HERO_PK, RICH, 1_000)));
        let commit = c.sessions[HERO_PK].live.clone().unwrap();
        let l = engine::legal(&c.hands[&commit].hand).unwrap();
        assert!(l.allows("raise"), "the button may raise: {l:?}");
        let out = c.handle(
            HERO_PK,
            ToCitizen::Act {
                commit: commit.clone(),
                action: Action {
                    seat: HERO,
                    action: "raise".into(),
                    amount: Some(l.min_raise_to),
                },
                log_len: None,
            },
            1_001,
            RICH,
        );
        assert!(
            !out.iter()
                .any(|e| matches!(e, Effect::Send(_, ToHero::Error { .. }))),
            "{out:?}"
        );
        assert!(c.hands[&commit]
            .hand
            .log
            .iter()
            .any(|e| e.ev == "raise" || e.ev == "bet"));
        let (r, rec) = restarted(&c, 2_000);
        assert!(rec.voided.is_empty(), "{:?}", rec.voided);
        assert_eq!(r.hands[&commit].hand, c.hands[&commit].hand);
    }

    #[test]
    fn a_done_the_house_sent_binds_to_its_replay_and_a_tampered_one_does_not() {
        use nostr_bbs_poker::bind::{bind_settlement, Agreed, BindError, Reported};
        let mut c = citizen();
        let commit = offer_commit(&hello(&mut c, HERO_PK, 1_000));
        assert!(seated(&sit(&mut c, &commit, 20, &"ab".repeat(32), RICH)));
        // the member folds on their turn: they owe the house
        let out = c.handle(
            HERO_PK,
            ToCitizen::Leave {
                commit: Some(commit.clone()),
            },
            1_003,
            RICH,
        );
        let ToHero::Done {
            seat,
            opponent,
            house,
            secret,
            nonces,
            seed,
            record,
            root,
            buyin,
            settlement,
            ..
        } = done_for(&out, HERO_PK).clone()
        else {
            unreachable!()
        };
        let owed = c.ledger.owed[0].amount;
        let claim = Claim {
            commit: &commit,
            secret: &secret,
            nonces,
            seed: &seed,
            record: &record,
            house_seat: Some(HOUSE),
            profile: "tag",
        };
        let replayed = verify(&RustEngine, &claim).unwrap();
        let agreed = Agreed {
            house: true,
            opponent: "c".repeat(64),
            bb: 20,
            sb: 10,
            buyin,
        };
        let honest = Reported {
            seat,
            opponent: &opponent,
            house,
            buyin,
            root: &root,
            settlement,
        };
        let house_pk = "c".repeat(64);
        let bound =
            bind_settlement(&replayed, &record, HERO_PK, &house_pk, &agreed, &honest).unwrap();
        assert_eq!(bound.settlement.map(|s| s.amount), Some(owed));
        assert_eq!(bound.payee.as_deref(), Some(house_pk.as_str()));
        // the amount raised by one unit, or paid to another key
        let mut greedy = honest.clone();
        greedy.settlement.as_mut().unwrap().amount += 1;
        assert!(matches!(
            bind_settlement(&replayed, &record, HERO_PK, &house_pk, &agreed, &greedy),
            Err(BindError::Settlement { .. })
        ));
        let thief = "d".repeat(64);
        let mut elsewhere = honest.clone();
        elsewhere.opponent = &thief;
        assert!(
            bind_settlement(&replayed, &record, HERO_PK, &house_pk, &agreed, &elsewhere).is_err()
        );
        // a house that is not the pinned one
        assert!(bind_settlement(&replayed, &record, HERO_PK, &thief, &agreed, &honest).is_err());
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
        assert_eq!(c.payments_seen(&paid, 2_001), [Effect::Persist]);
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
                pending: None,
                accepted_at: None,
                rebuilds: 0,
                invalid_rebuilds: 0,
                refusals: 0,
                halted: None,
            });
        }
        assert_eq!(c.payable(1_000, 60).len(), 1);
        let out = c.house_paid(HERO_PK, &"3".repeat(64), &"5".repeat(64), 1_000);
        assert!(matches!(&out[0], Effect::Send(_, ToHero::Paid { .. })));
        assert_eq!(c.ledger.paid_today(1_000), 4_000);
        assert!(c.payable(1_000, 60).is_empty());
        // the chain shows the first payout; the second may go out tomorrow
        c.payments_seen(&chain_pays(&"3".repeat(64), HERO_PK, 4_000), 50_000);
        assert_eq!(c.ledger.paid_today(1_000), 4_000, "counted once");
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
                log_len: None,
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
                log_len: None,
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
                log_len: None,
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
