//! The live table: a member's session with the forum's house seat
//! (`nostr-bbs-poker-citizen`), over NIP-59 gift wraps of kind
//! [`RUMOR_KIND`] on the forum relay.
//!
//! The house holds the hand; this store holds what the house showed us (our
//! seat view, the log), what it offered (tables, who is present), who has
//! challenged us, and the last finished hand with its verification and
//! settlement. When a hand ends the store replays it with the browser's own
//! engine ([`super::JsEngine`]) against the revealed secret and record
//! ([`nostr_bbs_poker::verify`]); a hand we lost is paid from the wallet at
//! once (`hand:<root>` beside the DREAM), a hand we won is marked paid when
//! the house says so or the chain shows the opponent's transfer.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use leptos::prelude::*;
use nostr_bbs_core::gift_wrap::{gift_wrap_with_signer_kind, unwrap_gift_with_signer_kind};
use nostr_bbs_core::signer::Signer;
use nostr_bbs_core::NostrEvent;
use nostr_bbs_poker::protocol::{Asset, Debt, TableOffer, ToCitizen, ToHero, RUMOR_KIND, VERSION};
use nostr_bbs_poker::rules::{HandRecord, Settlement, Side};
use nostr_bbs_poker::verify::{verify, Claim};
use send_wrapper::SendWrapper;

use super::{
    action_for, fresh_seed, hand_name, legal_of_view, summarise_named, Choice, HandOutcome,
    HistoryRow, JsEngine, LogEntry, SeatView,
};
use crate::auth::AuthStore;
use crate::relay::{EventCallback, Filter, RelayConnection};
use crate::wallet::{chain, WalletStore};

/// How far back the inbox subscription looks, covering NIP-59's timestamp
/// jitter.
const LOOKBACK_SECS: u64 = 2 * 24 * 60 * 60 + 3_600;
/// Hands kept in the history card.
const HISTORY_LEN: usize = 20;

/// What the house offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// The house's pubkey.
    pub citizen: String,
    /// The house's receive script, hex.
    pub script: String,
    /// The house character's name.
    pub name: String,
    /// Its profile.
    pub profile: String,
    /// Tables on offer.
    pub tables: Vec<TableOffer>,
    /// The commitment for the next house hand.
    pub commit: String,
    /// What we still owe.
    pub owed: Vec<Debt>,
    /// What the house still owes us.
    pub owing: Vec<Debt>,
    /// What the house may still pay out today.
    pub daily_cap_left: u64,
    /// Other members at the table.
    pub present: Vec<String>,
}

/// A hand in play, as the house shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveHand {
    /// The hand.
    pub commit: String,
    /// Our seat.
    pub seat: u32,
    /// The opponent's pubkey.
    pub opponent: String,
    /// Whether the opponent is the house bot.
    pub house: bool,
    /// Our view.
    pub view: SeatView,
    /// The log so far.
    pub log: Vec<LogEntry>,
}

/// A challenge another member sent us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incoming {
    /// The challenge.
    pub commit: String,
    /// Who.
    pub from: String,
    /// The big blind.
    pub bb: u64,
    /// The buy-in.
    pub buyin: u64,
    /// When it lapses, unix seconds.
    pub expires: u64,
}

/// Our challenge waiting for its opponent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Waiting {
    /// The challenge.
    pub commit: String,
    /// The opponent.
    pub opponent: String,
    /// When it lapses.
    pub expires: u64,
}

/// Where a finished hand's settlement stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pay {
    /// We owe; not sent yet (or the wallet could not sign).
    Owed {
        /// The winner's script, hex.
        to_script: String,
        /// Base units.
        amount: u64,
        /// Why the last attempt failed, if it did.
        error: Option<String>,
    },
    /// We paid.
    Sent(String),
    /// The opponent owes us; the chain has not shown it yet.
    Awaiting {
        /// Base units.
        amount: u64,
    },
    /// The opponent paid.
    Received(String),
    /// A split pot: nothing moves.
    Split,
}

/// The last finished hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    /// The hand.
    pub commit: String,
    /// Our seat.
    pub seat: u32,
    /// The opponent.
    pub opponent: String,
    /// Whether the opponent was the house bot.
    pub house: bool,
    /// The final view.
    pub view: SeatView,
    /// The log.
    pub log: Vec<LogEntry>,
    /// Our net, base units.
    pub net: i64,
    /// One sentence about it.
    pub text: String,
    /// The record's root.
    pub root: String,
    /// The revealed seed.
    pub seed: String,
    /// The buy-in.
    pub buyin: u64,
    /// `Ok` when the replay matched and the house played by the book.
    pub verified: Result<(), String>,
    /// The settlement.
    pub pay: Pay,
}

/// The session with the house seat, provided to the table page.
#[derive(Clone, Copy)]
pub struct LiveStore {
    /// The house's offer.
    pub offer: RwSignal<Option<Offer>>,
    /// The hand in play.
    pub hand: RwSignal<Option<LiveHand>>,
    /// The last finished hand.
    pub finished: RwSignal<Option<Finished>>,
    /// Challenges waiting for our answer.
    pub challenges: RwSignal<Vec<Incoming>>,
    /// Our challenge waiting for its opponent.
    pub waiting: RwSignal<Option<Waiting>>,
    /// Something the house said no to.
    pub error: RwSignal<Option<String>>,
    /// A passing remark (a declined challenge, a payment seen).
    pub notice: RwSignal<Option<String>>,
    /// Waiting for the house to answer.
    pub busy: RwSignal<bool>,
    /// Hands finished this session.
    pub history: RwSignal<Vec<HistoryRow>>,
    /// Net over the session.
    pub session_net: RwSignal<i64>,
    /// Hands this session.
    pub hands_played: RwSignal<u32>,
    /// The big blind chosen.
    pub stake_bb: RwSignal<u64>,
    citizen: StoredValue<String>,
    me: StoredValue<String>,
    relay: StoredValue<RelayConnection>,
    signer: StoredValue<SendWrapper<Rc<dyn Signer>>>,
    auth: StoredValue<AuthStore>,
    wallet: StoredValue<Option<WalletStore>>,
    sub: StoredValue<Option<String>>,
    seen: StoredValue<HashSet<String>>,
    nonces: StoredValue<HashMap<String, String>>,
}

/// What [`LiveStore::send`] carries into its task, read while the store is
/// alive. Generic only so tests can stand in for the relay and the signer,
/// which need a browser.
struct Outbox<S = SendWrapper<Rc<dyn Signer>>, R = RelayConnection> {
    citizen: String,
    signer: S,
    relay: R,
}

impl<S, R> Outbox<S, R>
where
    S: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
{
    /// Read the three values now: `None` once their owner is disposed (the
    /// table has closed), where a plain read would panic.
    fn read(
        citizen: StoredValue<String>,
        signer: StoredValue<S>,
        relay: StoredValue<R>,
    ) -> Option<Self> {
        Some(Self {
            citizen: citizen.try_get_value()?,
            signer: signer.try_get_value()?,
            relay: relay.try_get_value()?,
        })
    }
}

impl LiveStore {
    /// A session as `me` with the house `citizen`.
    pub fn new(
        relay: RelayConnection,
        signer: Rc<dyn Signer>,
        auth: AuthStore,
        wallet: Option<WalletStore>,
        me: &str,
        citizen: &str,
    ) -> Self {
        Self {
            offer: RwSignal::new(None),
            hand: RwSignal::new(None),
            finished: RwSignal::new(None),
            challenges: RwSignal::new(Vec::new()),
            waiting: RwSignal::new(None),
            error: RwSignal::new(None),
            notice: RwSignal::new(None),
            busy: RwSignal::new(false),
            history: RwSignal::new(Vec::new()),
            session_net: RwSignal::new(0),
            hands_played: RwSignal::new(0),
            stake_bb: RwSignal::new(0),
            citizen: StoredValue::new(citizen.to_string()),
            me: StoredValue::new(me.to_string()),
            relay: StoredValue::new(relay),
            signer: StoredValue::new(SendWrapper::new(signer)),
            auth: StoredValue::new(auth),
            wallet: StoredValue::new(wallet),
            sub: StoredValue::new(None),
            seen: StoredValue::new(HashSet::new()),
            nonces: StoredValue::new(HashMap::new()),
        }
    }

    /// The house's pubkey.
    pub fn citizen(&self) -> String {
        self.citizen.get_value()
    }

    /// Our pubkey.
    pub fn me(&self) -> String {
        self.me.get_value()
    }

    fn now() -> u64 {
        (js_sys::Date::now() / 1000.0) as u64
    }

    /// Open the inbox and say hello.
    pub fn start(&self) {
        if self.sub.get_value().is_some() {
            return;
        }
        let store = *self;
        let on_event: EventCallback = Rc::new(move |event: NostrEvent| {
            wasm_bindgen_futures::spawn_local(async move {
                store.process(event).await;
            });
        });
        let filter = Filter {
            kinds: Some(vec![1059]),
            p_tags: Some(vec![self.me()]),
            since: Some(Self::now().saturating_sub(LOOKBACK_SECS)),
            ..Default::default()
        };
        let id = self
            .relay
            .with_value(|r| r.subscribe(vec![filter], on_event, None));
        self.sub.set_value(Some(id));
        self.hello();
    }

    /// Close the inbox and leave the table.
    pub fn stop(&self) {
        let commit = self.hand.get_untracked().map(|h| h.commit);
        self.send(ToCitizen::Leave { commit });
        if let Some(id) = self.sub.get_value() {
            self.relay.with_value(|r| r.unsubscribe(&id));
            self.sub.set_value(None);
        }
    }

    /// What a message to the house needs, read now: `None` once the table
    /// that owns this store is gone.
    fn outbox(&self) -> Option<Outbox> {
        Outbox::read(self.citizen, self.signer, self.relay)
    }

    fn send(&self, msg: ToCitizen) {
        // Read everything before the task: it runs after this call returns,
        // and the Leave sent from the table's cleanup runs after the store
        // is disposed, when reading it would panic.
        let Some(out) = self.outbox() else {
            return;
        };
        let error = self.error;
        wasm_bindgen_futures::spawn_local(async move {
            let json = msg.to_json();
            match gift_wrap_with_signer_kind(out.signer.as_ref(), &out.citizen, RUMOR_KIND, &json)
                .await
            {
                Ok(ev) => out.relay.publish(&ev),
                Err(e) => {
                    error.try_set(Some(format!("Could not reach the house: {e}")));
                }
            }
        });
    }

    /// Ask for an offer (also resumes a hand in play after a reload).
    pub fn hello(&self) {
        self.busy.set(true);
        self.send(ToCitizen::Hello { v: VERSION });
    }

    /// Sit for one hand against the house at the chosen big blind.
    pub fn sit(&self) {
        let Some(offer) = self.offer.get_untracked() else {
            return;
        };
        let bb = self.stake_bb.get_untracked();
        let Some(nonce) = fresh_seed() else {
            self.error.set(Some(
                "This browser offers no secure random source, so no shuffle can be committed."
                    .into(),
            ));
            return;
        };
        self.nonces.update_value(|n| {
            n.insert(offer.commit.clone(), nonce.clone());
        });
        self.error.set(None);
        self.busy.set(true);
        self.send(ToCitizen::Sit {
            v: VERSION,
            commit: offer.commit,
            asset: Asset::Dream,
            bb,
            nonce,
        });
    }

    /// Act on our turn.
    pub fn act(&self, choice: Choice) {
        let Some(h) = self.hand.get_untracked() else {
            return;
        };
        let Some(l) = legal_of_view(&h.view) else {
            return;
        };
        let Some(action) = action_for(&l, choice) else {
            return;
        };
        self.busy.set(true);
        self.send(ToCitizen::Act {
            commit: h.commit,
            action,
        });
    }

    /// Challenge a member present at the table.
    pub fn challenge(&self, opponent: &str) {
        let bb = self.stake_bb.get_untracked();
        let Some(nonce) = fresh_seed() else {
            return;
        };
        // the commitment is not known until the house answers: remember the
        // nonce by opponent until the Waiting message names the hand
        self.nonces.update_value(|n| {
            n.insert(format!("challenge:{opponent}"), nonce.clone());
        });
        self.error.set(None);
        self.send(ToCitizen::Challenge {
            v: VERSION,
            opponent: opponent.to_string(),
            bb,
            nonce,
        });
    }

    /// Accept a challenge.
    pub fn accept(&self, commit: &str) {
        let Some(nonce) = fresh_seed() else {
            return;
        };
        self.nonces.update_value(|n| {
            n.insert(commit.to_string(), nonce.clone());
        });
        self.challenges.update(|c| c.retain(|i| i.commit != commit));
        self.error.set(None);
        self.busy.set(true);
        self.send(ToCitizen::Accept {
            commit: commit.to_string(),
            nonce,
        });
    }

    /// Decline a challenge.
    pub fn decline(&self, commit: &str) {
        self.challenges.update(|c| c.retain(|i| i.commit != commit));
        self.send(ToCitizen::Decline {
            commit: commit.to_string(),
        });
    }

    /// Fold out of the hand in play.
    pub fn leave_hand(&self) {
        if let Some(h) = self.hand.get_untracked() {
            self.send(ToCitizen::Leave {
                commit: Some(h.commit),
            });
        }
    }

    /// Pay (again) what the last hand owes.
    pub fn pay_now(&self) {
        let Some(f) = self.finished.get_untracked() else {
            return;
        };
        let Pay::Owed {
            to_script, amount, ..
        } = f.pay
        else {
            return;
        };
        let store = *self;
        wasm_bindgen_futures::spawn_local(async move {
            store.pay(&f.root, &to_script, amount).await;
        });
    }

    async fn pay(&self, root: &str, to_script: &str, amount: u64) {
        // the table may have closed before this task ran
        let (Some(wallet), Some(auth)) = (self.wallet.try_get_value(), self.auth.try_get_value())
        else {
            return;
        };
        let outcome = match (wallet, chain::script_of_hex(to_script)) {
            (Some(w), Some(to)) => w.send_asset_for_hand(&auth, to, amount, root).await,
            (None, _) => Err("The wallet is switched off.".into()),
            (_, None) => Err("The winner's script is not readable.".into()),
        };
        let root = root.to_string();
        self.finished.update(|f| {
            if let Some(f) = f.as_mut().filter(|f| f.root == root) {
                f.pay = match &outcome {
                    Ok(txid) => Pay::Sent(txid.clone()),
                    Err(e) => Pay::Owed {
                        to_script: to_script.to_string(),
                        amount,
                        error: Some(e.clone()),
                    },
                };
            }
        });
        if let Ok(txid) = outcome {
            self.send(ToCitizen::Paid { root, txid });
        }
    }

    /// The chain shows the opponent's transfer for the last hand.
    pub fn received(&self, root: &str, txid: &str) {
        self.finished.update(|f| {
            if let Some(f) = f
                .as_mut()
                .filter(|f| f.root == root && matches!(f.pay, Pay::Awaiting { .. }))
            {
                f.pay = Pay::Received(txid.to_string());
            }
        });
    }

    async fn process(&self, event: NostrEvent) {
        let fresh = self.seen.try_update_value(|s| s.insert(event.id.clone()));
        if fresh != Some(true) {
            return;
        }
        // an event already in flight when the table closed finds the store
        // gone, before or after the unwrap: drop it
        let Some(signer) = self.signer.try_get_value() else {
            return;
        };
        let unwrapped = unwrap_gift_with_signer_kind(&event, signer.as_ref(), RUMOR_KIND).await;
        let Ok(unwrapped) = unwrapped else {
            return; // a DM or a zone-key grant: not ours
        };
        let Some(citizen) = self.citizen.try_get_value() else {
            return;
        };
        if unwrapped.sender_pubkey != citizen {
            return;
        }
        // the relay re-streams history: anything older than a hand's
        // possible life is stale
        if Self::now().saturating_sub(unwrapped.rumor.created_at) > 600 {
            return;
        }
        let msg = match ToHero::parse(&unwrapped.rumor.content) {
            Ok(m) => m,
            Err(e) => {
                web_sys::console::warn_1(&format!("[table] {e}").into());
                return;
            }
        };
        self.on_message(msg);
    }

    fn on_message(&self, msg: ToHero) {
        match msg {
            ToHero::Offer {
                v,
                citizen,
                script,
                name,
                profile,
                tables,
                commit,
                owed,
                owing,
                daily_cap_left,
                present,
                ..
            } => {
                if v != VERSION {
                    self.error.set(Some(format!(
                        "The house speaks protocol {v}; this page speaks {VERSION}. Reload."
                    )));
                    return;
                }
                if self.stake_bb.get_untracked() == 0 {
                    if let Some(t) = tables.first() {
                        self.stake_bb.set(t.bb);
                    }
                }
                self.offer.set(Some(Offer {
                    citizen,
                    script,
                    name,
                    profile,
                    tables,
                    commit,
                    owed,
                    owing,
                    daily_cap_left,
                    present,
                }));
                self.busy.set(false);
            }
            ToHero::Challenged {
                commit,
                from,
                bb,
                buyin,
                expires,
            } => {
                self.challenges.update(|c| {
                    c.retain(|i| i.commit != commit);
                    c.push(Incoming {
                        commit,
                        from,
                        bb,
                        buyin,
                        expires,
                    });
                });
            }
            ToHero::Waiting {
                commit,
                opponent,
                expires,
            } => {
                // the nonce we sent now belongs to this commitment
                self.nonces.update_value(|n| {
                    if let Some(nonce) = n.remove(&format!("challenge:{opponent}")) {
                        n.insert(commit.clone(), nonce);
                    }
                });
                self.waiting.set(Some(Waiting {
                    commit,
                    opponent,
                    expires,
                }));
            }
            ToHero::Declined { commit, by } => {
                let citizen = self.citizen();
                if self
                    .waiting
                    .get_untracked()
                    .is_some_and(|w| w.commit == commit)
                {
                    self.waiting.set(None);
                    self.notice.set(Some(if by == citizen {
                        "Your challenge lapsed unanswered.".into()
                    } else {
                        "Your challenge was declined.".into()
                    }));
                }
                self.challenges.update(|c| c.retain(|i| i.commit != commit));
            }
            ToHero::State {
                commit,
                seat,
                opponent,
                house,
                view,
                log,
            } => {
                self.waiting.set(None);
                self.finished.set(None);
                self.error.set(None);
                self.hand.set(Some(LiveHand {
                    commit,
                    seat,
                    opponent,
                    house,
                    view,
                    log,
                }));
                self.busy.set(false);
            }
            ToHero::Done {
                commit,
                seat,
                opponent,
                house,
                view,
                log,
                secret,
                nonces,
                seed,
                record,
                root,
                buyin,
                settlement,
            } => {
                self.finish(
                    commit, seat, opponent, house, view, log, secret, nonces, seed, record, root,
                    buyin, settlement,
                );
            }
            ToHero::Paid { root, txid } => {
                self.finished.update(|f| {
                    if let Some(f) = f.as_mut().filter(|f| f.root == root) {
                        f.pay = Pay::Received(txid);
                    }
                });
            }
            ToHero::Error { message, .. } => {
                self.error.set(Some(message));
                self.busy.set(false);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finish(
        &self,
        commit: String,
        seat: u32,
        opponent: String,
        house: bool,
        view: SeatView,
        log: Vec<LogEntry>,
        secret: String,
        nonces: Vec<String>,
        seed: String,
        record: HandRecord,
        root: String,
        buyin: u64,
        settlement: Option<Settlement>,
    ) {
        let profile = self
            .offer
            .get_untracked()
            .map(|o| o.profile)
            .unwrap_or_else(|| "tag".to_string());
        // our nonce must be the one the house used for our seat
        let ours = self.nonces.with_value(|n| n.get(&commit).cloned());
        let nonce_ok = ours
            .as_deref()
            .is_some_and(|n| nonces.get(seat as usize).map(String::as_str) == Some(n));
        let claim = Claim {
            commit: &commit,
            secret: &secret,
            nonces: nonces.clone(),
            seed: &seed,
            record: &record,
            house_seat: house.then_some(1 - seat),
            profile: &profile,
        };
        let replay = verify(&JsEngine, &claim);
        let verified = match (&replay, nonce_ok) {
            (Ok(_), true) => Ok(()),
            (Ok(_), false) => Err("the house did not deal from your nonce".to_string()),
            (Err(e), _) => Err(e.to_string()),
        };
        // the house plays under its character's name; a member under the
        // display name the forum already knows for their pubkey
        let other_name = if house {
            self.offer
                .get_untracked()
                .map(|o| o.name)
                .unwrap_or_else(|| "The house".to_string())
        } else {
            crate::components::user_display::use_display_name(&opponent)
        };
        let names: Vec<String> = (0..2)
            .map(|i| {
                if i == seat {
                    "You".to_string()
                } else {
                    other_name.clone()
                }
            })
            .collect();
        let outcome: HandOutcome = match &replay {
            Ok(hand) => {
                summarise_named(hand, seat as usize, &names, hand_name).unwrap_or(HandOutcome {
                    hero_net: 0,
                    text: "The hand ended.".into(),
                })
            }
            Err(_) => {
                let net = view
                    .seats
                    .get(seat as usize)
                    .map(|s| s.stack as i64 - buyin as i64)
                    .unwrap_or(0);
                HandOutcome {
                    hero_net: net,
                    text: "The hand ended, but its record did not verify.".into(),
                }
            }
        };
        let pay = match settlement {
            None => Pay::Split,
            Some(Settlement {
                from: Side::Hero,
                amount,
                ..
            }) => {
                let to_script = if house {
                    self.offer
                        .get_untracked()
                        .map(|o| o.script)
                        .unwrap_or_default()
                } else {
                    chain::script_of(&opponent)
                        .map(|s| s.to_hex_string())
                        .unwrap_or_default()
                };
                Pay::Owed {
                    to_script,
                    amount,
                    error: None,
                }
            }
            Some(Settlement { amount, .. }) => Pay::Awaiting { amount },
        };
        let n = self.hands_played.get_untracked() + 1;
        self.hands_played.set(n);
        self.session_net.update(|v| *v += outcome.hero_net);
        self.history.update(|rows| {
            rows.insert(
                0,
                HistoryRow {
                    number: n,
                    text: outcome.text.clone(),
                    net: outcome.hero_net,
                },
            );
            rows.truncate(HISTORY_LEN);
        });
        let owed = matches!(pay, Pay::Owed { .. });
        let (root_c, to_c, amount_c) = match &pay {
            Pay::Owed {
                to_script, amount, ..
            } => (root.clone(), to_script.clone(), *amount),
            _ => (String::new(), String::new(), 0),
        };
        self.hand.set(None);
        self.finished.set(Some(Finished {
            commit,
            seat,
            opponent,
            house,
            view,
            log,
            net: outcome.hero_net,
            text: outcome.text,
            root,
            seed,
            buyin,
            verified: verified.clone(),
            pay,
        }));
        self.busy.set(false);
        self.nonces.update_value(|n| {
            n.retain(|k, _| !k.starts_with("challenge:"));
        });
        // pay what we owe at once; a hand that did not verify is still ours
        // to pay (we played it), but say so beside the button
        if owed && verified.is_ok() {
            let store = *self;
            wasm_bindgen_futures::spawn_local(async move {
                store.pay(&root_c, &to_c, amount_c).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_outbox_reads_a_live_table() {
        let owner = Owner::new();
        owner.with(|| {
            let out = Outbox::read(
                StoredValue::new("ab".repeat(32)),
                StoredValue::new("signer".to_string()),
                StoredValue::new(7u8),
            )
            .expect("alive");
            assert_eq!(out.citizen, "ab".repeat(32));
            assert_eq!(out.signer, "signer");
            assert_eq!(out.relay, 7);
        });
    }

    #[test]
    fn the_outbox_of_a_closed_table_is_empty_not_a_panic() {
        // the DREAM table's cleanup sends a Leave whose task ran once the
        // table, and so the store, was gone: switching to the practice table
        // panicked ("a reactive value that has already been disposed").
        // `send` now reads through `Outbox::read` before it spawns, and
        // sends nothing once the owner is disposed.
        let owner = Owner::new();
        let (c, s, r) = owner.with(|| {
            (
                StoredValue::new("ab".repeat(32)),
                StoredValue::new("signer".to_string()),
                StoredValue::new(7u8),
            )
        });
        owner.cleanup();
        assert!(c.try_get_value().is_none(), "the owner disposed its values");
        assert!(Outbox::read(c, s, r).is_none());
    }
}
