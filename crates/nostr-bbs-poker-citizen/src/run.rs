//! The runner: the command line, the clock, the relay, the producer, and the
//! loop that joins them to the table ([`crate::table::Citizen`]).

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::time::Duration;

use bitcoin::{OutPoint, Txid};
use clap::Parser;
use nostr_bbs_core::gift_wrap::{gift_wrap_kind, unwrap_gift_kind};
use nostr_bbs_poker::protocol::{ToCitizen, ToHero, RUMOR_KIND};
use sidestr_agent::AgentKey;
use sidestr_core::document::ChainDocument;
use tokio::time::{sleep, Instant};
use zeroize::Zeroizing;

use nostr_bbs_poker_citizen::chain::{self, Facts};
use nostr_bbs_poker_citizen::ledger::Ledger;
use nostr_bbs_poker_citizen::net::{now_secs, publish_once, Frame, Relay};
use nostr_bbs_poker_citizen::table::{Balances, Citizen, Config, Effect, House};

/// The house seat of the nostr-bbs poker table.
#[derive(Parser, Debug)]
#[command(
    name = "nostr-bbs-poker-citizen",
    version,
    about = "The house seat: deals committed hands over the forum relay, plays the house bot, settles each hand in one chain's asset (DREAM on sidestr:dreamlab by default; BLAKES7 on sidestr:dreamlab-txbt4).",
    after_help = "The house key is read from --key-file (64 hex or nsec1…), never from a flag's value. One instance serves one chain, with its own key and --state file. Testnet only: coins on these chains carry no value."
)]
pub struct Cli {
    /// The pinned chain this house seat settles on: sidestr:dreamlab or sidestr:dreamlab-txbt4.
    #[arg(
        long,
        env = "POKER_CITIZEN_CHAIN",
        default_value = "sidestr:dreamlab",
        value_name = "ID"
    )]
    chain_id: String,
    /// The asset the table settles in, by its issue's txid (64 hex). Defaults to DREAM on sidestr:dreamlab; required on any other chain.
    #[arg(long, env = "POKER_CITIZEN_ASSET", value_name = "TXID")]
    asset_id: Option<String>,
    /// The asset's ticker, as members read it. Defaults to DREAM on sidestr:dreamlab; required on any other chain.
    #[arg(long, env = "POKER_CITIZEN_TICKER", value_name = "TICKER")]
    ticker: Option<String>,
    /// The house's key file (64 hex characters or an nsec1…).
    #[arg(long, env = "POKER_CITIZEN_KEY_FILE", value_name = "PATH")]
    key_file: PathBuf,
    /// The forum relay (wss://…) the table is played over.
    #[arg(long, env = "POKER_CITIZEN_RELAY", value_name = "URL")]
    relay: String,
    /// The chain's producer (`/chain.json`, `/blocks.dat`, `POST /tx`): 3450 serves sidestr:dreamlab, 3451 sidestr:dreamlab-txbt4 on the estate's box.
    #[arg(
        long,
        env = "SIDESTR_URL",
        default_value = "http://127.0.0.1:3450",
        value_name = "URL"
    )]
    producer: String,
    /// Public relays the producer follows, for the kind-23500 events, comma-separated.
    #[arg(
        long,
        env = "SIDESTR_RELAYS",
        default_value = "wss://nos.lol,wss://relay.damus.io,wss://relay.primal.net,wss://nostr.mom,wss://nostr.oxtr.dev",
        value_name = "URLS"
    )]
    sidestr_relays: String,
    /// Where the ledger is kept.
    #[arg(long, env = "POKER_CITIZEN_STATE", value_name = "PATH")]
    state: PathBuf,
    /// Big blinds on offer, in base units of the table's asset, comma-separated.
    #[arg(
        long,
        env = "POKER_STAKES_BB",
        default_value = "2,10,20,100,200",
        value_name = "LIST"
    )]
    stakes_bb: String,
    /// The buy-in in big blinds.
    #[arg(long, env = "POKER_BUYIN_BB", default_value_t = 100)]
    buyin_bb: u64,
    /// The house bot's profile: rock, tag, lag, station or maniac.
    #[arg(long, env = "POKER_BOT_PROFILE", default_value = "tag")]
    profile: String,
    /// The most the house pays out per day, in base units of the table's asset.
    #[arg(long, env = "POKER_DAILY_CAP", default_value_t = 20_000)]
    daily_cap: u64,
    /// How long a member's own report of a payment is trusted before the chain must show it, seconds.
    #[arg(long, default_value_t = 1_800)]
    claim_grace_secs: u64,
    /// How often the chain is re-read, seconds.
    #[arg(long, default_value_t = 15)]
    poll_secs: u64,
    /// How long the house "thinks" before acting, milliseconds.
    #[arg(long, default_value_t = 600)]
    bot_delay_ms: u64,
}

/// A transfer the producer accepted but the chain has not shown yet: its
/// coins are held back from the next build.
struct Held {
    txid: String,
    outpoints: Vec<OutPoint>,
    at: u64,
}

/// Held coins are released after this long if the chain never shows them.
const HELD_TTL: u64 = 30 * 60;
/// A failed payout is retried after this long.
const PAY_RETRY_SECS: u64 = 120;
/// The inbox looks back this far, covering NIP-59's timestamp jitter.
const INBOX_LOOKBACK: u64 = 2 * 24 * 60 * 60 + 3_600;
/// Event ids remembered for de-duplication.
const SEEN_CAP: usize = 4_096;

struct Runner {
    cli: Cli,
    key: AgentKey,
    sk: Zeroizing<[u8; 32]>,
    pubkey: String,
    citizen: Citizen,
    doc: ChainDocument,
    asset: Txid,
    ticker: String,
    facts: Option<Facts>,
    held: Vec<Held>,
    http: reqwest::Client,
    bot_turns: VecDeque<(Instant, String)>,
    seen: HashSet<String>,
    seen_order: VecDeque<String>,
}

fn read_key(path: &PathBuf) -> Result<(AgentKey, Zeroizing<[u8; 32]>), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let key = AgentKey::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let t = text.trim();
    let hex_text = if t.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("nsec1")) {
        nostr_bbs_core::nip19::decode_nsec(t).map_err(|e| e.to_string())?
    } else {
        t.to_string()
    };
    let bytes = hex::decode(hex_text).map_err(|_| "the key file is not hex".to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "the key is not 32 bytes".to_string())?;
    Ok((key, Zeroizing::new(arr)))
}

/// Run the house until the process is stopped.
pub async fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let served = chain::select(
        &cli.chain_id,
        cli.asset_id.as_deref(),
        cli.ticker.as_deref(),
    )?;
    let (key, sk) = read_key(&cli.key_file)?;
    let pubkey = hex::encode(key.pubkey().serialize());
    let stakes_bb: Vec<u64> = cli
        .stakes_bb
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    if stakes_bb.is_empty() {
        return Err("--stakes-bb lists no big blind".into());
    }
    let ledger = match std::fs::read_to_string(&cli.state) {
        Ok(json) => Ledger::parse(&json)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ledger::default(),
        Err(e) => return Err(format!("{}: {e}", cli.state.display())),
    };
    let cfg = Config {
        stakes_bb,
        buyin_bb: cli.buyin_bb,
        profile: cli.profile.clone(),
        daily_cap: cli.daily_cap,
        claim_grace_secs: cli.claim_grace_secs,
        ticker: served.ticker.clone(),
    };
    let house = House {
        pubkey: pubkey.clone(),
        script_hex: key.script().to_hex_string(),
    };
    let citizen = Citizen::new(
        cfg,
        house,
        ledger,
        Box::new(|| {
            let mut b = [0u8; 32];
            getrandom::getrandom(&mut b).expect("the OS random source");
            b
        }),
    );
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!(
            "nostr-bbs-poker-citizen/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .map_err(|e| e.to_string())?;
    let doc_json = http
        .get(format!("{}/chain.json", cli.producer.trim_end_matches('/')))
        .send()
        .await
        .map_err(|e| format!("producer: {e}"))?
        .text()
        .await
        .map_err(|e| e.to_string())?;
    let doc = chain::check_document(served.pin, &doc_json)?;
    eprintln!(
        "citizen {pubkey} ({}) on {} · {} {} ({}) · producer {} · tables {}",
        citizen.bot().name,
        cli.relay,
        served.pin.id,
        served.ticker,
        served.asset,
        cli.producer,
        citizen
            .tables()
            .iter()
            .map(|t| t.label.clone())
            .collect::<Vec<_>>()
            .join(" ")
    );
    let mut runner = Runner {
        cli,
        key,
        sk,
        pubkey,
        citizen,
        doc,
        asset: served.asset,
        ticker: served.ticker,
        facts: None,
        held: Vec::new(),
        http,
        bot_turns: VecDeque::new(),
        seen: HashSet::new(),
        seen_order: VecDeque::new(),
    };
    runner.refresh_chain().await;
    runner.persist();
    let mut backoff = 2u64;
    loop {
        match Relay::connect(&runner.cli.relay, &runner.sk, &runner.pubkey).await {
            Ok(mut relay) => {
                backoff = 2;
                if !relay.authenticated() {
                    eprintln!("relay did not challenge for AUTH; the inbox may be refused");
                }
                if let Err(e) = relay
                    .subscribe_inbox(now_secs().saturating_sub(INBOX_LOOKBACK))
                    .await
                {
                    eprintln!("relay: REQ failed: {e}");
                    sleep(Duration::from_secs(backoff)).await;
                    continue;
                }
                eprintln!("relay: inbox open");
                runner.serve(&mut relay).await;
                eprintln!("relay: connection lost; reconnecting in {backoff}s");
            }
            Err(e) => {
                eprintln!("relay: {e}; retrying in {backoff}s");
            }
        }
        sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(60);
    }
}

impl Runner {
    fn persist(&self) {
        let tmp = self.cli.state.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp, self.citizen.ledger.to_json())
            .and_then(|()| std::fs::rename(&tmp, &self.cli.state))
        {
            eprintln!("ledger: could not save {}: {e}", self.cli.state.display());
        }
    }

    fn remember(&mut self, id: &str) -> bool {
        if !self.seen.insert(id.to_string()) {
            return false;
        }
        self.seen_order.push_back(id.to_string());
        while self.seen_order.len() > SEEN_CAP {
            if let Some(old) = self.seen_order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }

    async fn refresh_chain(&mut self) {
        let url = format!(
            "{}/blocks.dat?t={}",
            self.cli.producer.trim_end_matches('/'),
            now_secs() / 15
        );
        let dat = match self.http.get(&url).send().await {
            Ok(r) => match r.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("producer: {e}");
                    return;
                }
            },
            Err(e) => {
                eprintln!("producer: {e}");
                return;
            }
        };
        match chain::scan(self.doc.clone(), self.asset, &dat, Some(now_secs() as u32)) {
            Ok(facts) => {
                if !facts.asset_issued() && self.facts.is_none() {
                    eprintln!(
                        "chain: {} at height {} does not show {}'s issue {}; members cannot buy in until it does",
                        self.doc.id,
                        facts.height(),
                        self.ticker,
                        self.asset
                    );
                }
                let now = now_secs();
                self.held.retain(|h| {
                    !facts.txids.contains(&h.txid) && now.saturating_sub(h.at) < HELD_TTL
                });
                self.facts = Some(facts);
            }
            Err(e) => eprintln!("chain: {e}"),
        }
    }

    fn balances_for(&self, hero: &str) -> Balances {
        let Some(f) = &self.facts else {
            return Balances::default();
        };
        let held: Vec<OutPoint> = self.held.iter().flat_map(|h| h.outpoints.clone()).collect();
        Balances {
            hero_asset: f.units_of(hero),
            house_asset: f.units_of_script(&self.key.script(), &held),
        }
    }

    async fn send(&mut self, relay: &mut Relay, to: &str, msg: &ToHero) {
        let wrap = match gift_wrap_kind(&self.sk, &self.pubkey, to, RUMOR_KIND, &msg.to_json()) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("wrap to {}…: {e}", &to[..8]);
                return;
            }
        };
        if let Err(e) = relay.publish(&wrap).await {
            eprintln!("publish to {}…: {e}", &to[..8]);
        }
    }

    /// Pay a settlement; the effects that follow (the `Paid` message, the
    /// ledger save) are returned for the caller's queue.
    async fn pay(&mut self, hero: &str, root: &str, amount: u64) -> Vec<Effect> {
        let now = now_secs();
        let Some(facts) = &self.facts else {
            return self
                .citizen
                .house_pay_failed(root, "the chain is not loaded", now);
        };
        let held: Vec<OutPoint> = self.held.iter().flat_map(|h| h.outpoints.clone()).collect();
        let payment = match chain::build_payment(&self.key, facts, &held, hero, amount, root, now) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "pay {amount} {} to {}… for {}…: {e}",
                    self.ticker,
                    &hero[..8],
                    &root[..8]
                );
                return self.citizen.house_pay_failed(root, &e, now);
            }
        };
        let txid = payment.spend.txid.to_string();
        let post = self
            .http
            .post(format!("{}/tx", self.cli.producer.trim_end_matches('/')))
            .body(payment.spend.hex.clone())
            .send()
            .await;
        let accepted = match post {
            Ok(r) => {
                let text = r.text().await.unwrap_or_default();
                match sidestr_wallet::deliver::parse_tx_response(&text) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(format!("the producer refused: {e}")),
                }
            }
            Err(e) => Err(format!("producer: {e}")),
        };
        match accepted {
            Ok(()) => {
                eprintln!(
                    "paid {amount} {} to {}… for hand {}…: {txid}",
                    self.ticker,
                    &hero[..8],
                    &root[..8]
                );
                self.held.push(Held {
                    txid: txid.clone(),
                    outpoints: payment
                        .spend
                        .tx
                        .input
                        .iter()
                        .map(|i| i.previous_output)
                        .collect(),
                    at: now,
                });
                // the producer follows the public relays too: let them see it
                if let Ok(json) = serde_json::to_string(&payment.event) {
                    let id = payment.event.id.clone();
                    let relays: Vec<String> = self
                        .cli
                        .sidestr_relays
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| s.starts_with("wss://"))
                        .collect();
                    tokio::spawn(async move {
                        for r in relays {
                            publish_once(&r, &json, &id).await;
                        }
                    });
                }
                self.citizen.house_paid(hero, root, &txid, now)
            }
            Err(e) => {
                eprintln!("pay for hand {}…: {e}", &root[..8]);
                self.citizen.house_pay_failed(root, &e, now)
            }
        }
    }

    async fn run_effects(&mut self, relay: &mut Relay, effects: Vec<Effect>) {
        let mut queue: VecDeque<Effect> = effects.into();
        while let Some(e) = queue.pop_front() {
            match e {
                Effect::Send(to, msg) => self.send(relay, &to, &msg).await,
                Effect::BotTurn(commit) => {
                    let at = Instant::now() + Duration::from_millis(self.cli.bot_delay_ms);
                    self.bot_turns.push_back((at, commit));
                }
                Effect::Pay { hero, root, amount } => {
                    // what follows a payment goes ahead of the rest of the queue
                    let follow = self.pay(&hero, &root, amount).await;
                    for (i, f) in follow.into_iter().enumerate() {
                        queue.insert(i, f);
                    }
                }
                Effect::Persist => self.persist(),
            }
        }
    }

    async fn on_event(&mut self, relay: &mut Relay, ev: nostr_bbs_core::NostrEvent) {
        if !self.remember(&ev.id) {
            return;
        }
        let unwrapped = match unwrap_gift_kind(&ev, &self.sk, RUMOR_KIND) {
            Ok(u) => u,
            Err(_) => return, // a DM or someone else's wrap: not for the table
        };
        let hero = unwrapped.sender_pubkey;
        let msg = match ToCitizen::parse(&unwrapped.rumor.content) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("{}…: {e}", &hero[..8]);
                return;
            }
        };
        // a stale replay of the inbox (the relay re-streams history) must
        // not re-play old actions: anything older than the hand's possible
        // life is dropped
        let now = now_secs();
        if now.saturating_sub(unwrapped.rumor.created_at) > 600 {
            return;
        }
        let balances = self.balances_for(&hero);
        let effects = self.citizen.handle(&hero, msg, now, balances);
        self.run_effects(relay, effects).await;
    }

    async fn serve(&mut self, relay: &mut Relay) {
        let mut poll = tokio::time::interval(Duration::from_secs(self.cli.poll_secs.max(5)));
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let next_bot = self.bot_turns.front().map(|(at, _)| *at);
            tokio::select! {
                frame = relay.next() => match frame {
                    Frame::Event(ev) => self.on_event(relay, ev).await,
                    Frame::Ok { id, accepted, message } => {
                        if !accepted {
                            eprintln!("relay refused {}…: {message}", &id[..8]);
                        }
                    }
                    Frame::Eose => {}
                    Frame::Notice(n) => eprintln!("relay notice: {n}"),
                    Frame::Closed(why) => {
                        eprintln!("relay closed the inbox: {why}");
                        return;
                    }
                    Frame::Disconnected => return,
                    Frame::Other => {}
                },
                _ = async {
                    match next_bot {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    if let Some((_, commit)) = self.bot_turns.pop_front() {
                        let effects = self.citizen.bot_turn(&commit, now_secs());
                        self.run_effects(relay, effects).await;
                    }
                },
                _ = poll.tick() => {
                    self.refresh_chain().await;
                    let now = now_secs();
                    let mut effects = self.citizen.tick(now);
                    if let Some(f) = &self.facts {
                        effects.extend(self.citizen.payments_seen(&f.hand_payments));
                    }
                    effects.extend(self.citizen.payable(now, PAY_RETRY_SECS));
                    self.run_effects(relay, effects).await;
                },
            }
        }
    }
}
