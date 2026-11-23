//! The runner: the command line, the clock, the relay, the producer, and the
//! loop that joins them to the table ([`crate::table::Citizen`]).

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Duration;

use bitcoin::{OutPoint, Txid};
use clap::Parser;
use nostr_bbs_core::event::compute_event_id;
use nostr_bbs_core::gift_wrap::{gift_wrap, gift_wrap_kind, unwrap_gift_kind};
use nostr_bbs_poker::protocol::{ToCitizen, ToHero, RUMOR_KIND};
use sidestr_agent::AgentKey;
use sidestr_core::document::ChainDocument;
use tokio::time::{sleep, Instant};
use zeroize::Zeroizing;

use nostr_bbs_poker_citizen::alert::{Alert, Alerter};
use nostr_bbs_poker_citizen::chain::{self, Facts};
use nostr_bbs_poker_citizen::ledger::{Cause, Pending, Resume, TxOnChain};
use nostr_bbs_poker_citizen::net::{now_secs, publish_once, Frame, Relay};
use nostr_bbs_poker_citizen::state::{self, Seen, State};
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
    /// Where the house keeps its state: the ledger, the hands in play and the events acted on (private to its owner).
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
    /// An operator's pubkey (64 hex, or npub1…) to send alerts to as a gift-wrapped direct message on the forum relay: halted payout debts and a producer that keeps refusing. Each debt and cause is sent once per window. The relay must admit this key as a gift-wrap recipient (whitelisted, e.g. the operator's forum account) or it refuses the DM. Unset, alerts go to stderr only.
    #[arg(long, env = "POKER_CITIZEN_ALERT_PUBKEY", value_name = "PUBKEY")]
    alert_pubkey: Option<String>,
    /// How often the chain is re-read, seconds.
    #[arg(long, default_value_t = 15)]
    poll_secs: u64,
    /// How long the house "thinks" before acting, milliseconds.
    #[arg(long, default_value_t = 600)]
    bot_delay_ms: u64,
}

/// A failed payout is retried after this long.
const PAY_RETRY_SECS: u64 = 120;
/// The inbox looks back this far, covering NIP-59's timestamp jitter.
const INBOX_LOOKBACK: u64 = 2 * 24 * 60 * 60 + 3_600;

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
    /// The producer's `/tip` hash at the last full scan; an unchanged tip skips the re-download and replay.
    scanned_tip: Option<String>,
    /// What the house said it would do on its first connection: tell members of hands it voided.
    startup: Vec<Effect>,
    http: reqwest::Client,
    bot_turns: VecDeque<(Instant, String)>,
    seen: Seen,
    /// Where alerts beyond stderr go, and how often.
    alerter: Alerter,
}

/// The alert recipient as 64 hex: hex as given, or an `npub1…`; an empty value is none.
fn parse_alert_pubkey(text: Option<&str>) -> Result<Option<String>, String> {
    let Some(t) = text.map(str::trim).filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    let hex_text = if t.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("npub1")) {
        nostr_bbs_core::nip19::decode_npub(t).map_err(|e| format!("--alert-pubkey: {e}"))?
    } else {
        t.to_ascii_lowercase()
    };
    if hex_text.len() == 64 && hex_text.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(Some(hex_text))
    } else {
        Err("--alert-pubkey is not 64 hex characters or an npub1…".into())
    }
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
    let alert_to = parse_alert_pubkey(cli.alert_pubkey.as_deref())?;
    let pubkey = hex::encode(key.pubkey().serialize());
    let stakes_bb: Vec<u64> = cli
        .stakes_bb
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    if stakes_bb.is_empty() {
        return Err("--stakes-bb lists no big blind".into());
    }
    let state = match std::fs::read_to_string(&cli.state) {
        Ok(json) => State::parse(&json)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
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
    // Hands in play when the house stopped are resumed where they stood
    // (see `Citizen::restore`); one that no longer proves itself is voided.
    let (citizen, recovered) = Citizen::restore(
        cfg,
        house,
        state,
        Box::new(|| {
            let mut b = [0u8; 32];
            getrandom::getrandom(&mut b).expect("the OS random source");
            b
        }),
        now_secs(),
    );
    for (root, why) in citizen.halted() {
        eprintln!(
            "HALTED debt for hand {}…: {why}",
            &root[..12.min(root.len())]
        );
    }
    let startup_summary = Alert::summary(&citizen.halted());
    for commit in &recovered.resumed {
        eprintln!("recovered hand {}…", &commit[..12]);
    }
    for (commit, why) in &recovered.voided {
        eprintln!("voided hand {}…: {why}", &commit[..12.min(commit.len())]);
    }
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
        scanned_tip: None,
        startup: Vec::new(),
        http,
        bot_turns: VecDeque::new(),
        seen: Seen::from_entries(recovered.seen),
        alerter: Alerter::new(alert_to),
    };
    if !runner.alerter.is_configured() {
        eprintln!("alerts: no --alert-pubkey; alerts go to stderr only");
    }
    // one summary of the debts that are halted, said on the first connection
    if let Some(summary) = startup_summary {
        runner.startup.push(Effect::Alert(summary));
    }
    for e in recovered.effects {
        if let Effect::BotTurn(commit) = e {
            let at = Instant::now() + Duration::from_millis(runner.cli.bot_delay_ms);
            runner.bot_turns.push_back((at, commit));
        } else {
            runner.startup.push(e);
        }
    }
    runner.refresh_chain().await;
    runner.checkpoint();
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
    /// Save what changed. Called after every step of the table and before
    /// its effects are carried out, so nothing is sent or paid on the
    /// strength of a change a restart would forget. If the state cannot be
    /// saved the house stops: the process restarts from the last good file,
    /// which no member has been told anything beyond.
    fn checkpoint(&mut self) {
        let path = self.cli.state.clone();
        let seen = self.seen.to_entries();
        let saved = self
            .citizen
            .checkpoint(seen, |st| state::save(&path, st).map_err(|e| e.to_string()));
        if let Err(e) = saved {
            eprintln!(
                "state: could not save {}: {e}; stopping rather than act on unsaved state",
                path.display()
            );
            std::process::exit(1);
        }
    }

    /// The coins held back from the house's balance and coin selection:
    /// those of payouts sent and of payouts signed and about to be.
    fn held_outpoints(&self) -> Vec<OutPoint> {
        self.citizen
            .held_outpoints()
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect()
    }

    /// The producer's tip hash, or `None` when `/tip` cannot be read (then the chain is rescanned in full).
    async fn producer_tip(&self) -> Option<String> {
        let url = format!("{}/tip", self.cli.producer.trim_end_matches('/'));
        let body = self.http.get(&url).send().await.ok()?.bytes().await.ok()?;
        let v: serde_json::Value = serde_json::from_slice(&body).ok()?;
        v.get("hash")?.as_str().map(str::to_owned)
    }

    async fn refresh_chain(&mut self) {
        // blocks.dat is append-only and a scan is a pure function of it, so while the tip is the one
        // already scanned there is nothing new to learn: skip the full download and replay.
        let tip = self.producer_tip().await;
        if self.facts.is_some() && tip.is_some() && tip == self.scanned_tip {
            return;
        }
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
                self.facts = Some(facts);
                self.scanned_tip = tip;
            }
            Err(e) => eprintln!("chain: {e}"),
        }
    }

    fn balances_for(&self, hero: &str) -> Balances {
        let Some(f) = &self.facts else {
            return Balances::default();
        };
        let held = self.held_outpoints();
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

    /// Send the operator a NIP-17 direct message, gift-wrapped (NIP-59).
    async fn send_dm(&mut self, relay: &mut Relay, to: &str, text: &str) {
        let wrap = match gift_wrap(&self.sk, &self.pubkey, to, text) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("alert DM: wrap: {e}");
                return;
            }
        };
        if let Err(e) = relay.publish(&wrap).await {
            eprintln!("alert DM: publish: {e}");
        }
    }

    /// Sign the house's payout for a hand.
    fn sign_payout(
        &self,
        hero: &str,
        root: &str,
        amount: u64,
        now: u64,
    ) -> Result<(Pending, sidestr_nostr::event::Event), String> {
        let facts = self.facts.as_ref().ok_or("the chain is not loaded")?;
        let held = self.held_outpoints();
        let payment = chain::build_payment(&self.key, facts, &held, hero, amount, root, now)?;
        let pending = Pending {
            hex: payment.spend.hex.clone(),
            txid: payment.spend.txid.to_string(),
            outpoints: payment
                .spend
                .tx
                .input
                .iter()
                .map(|i| i.previous_output.to_string())
                .collect(),
        };
        Ok((pending, payment.event))
    }

    /// Pay a settlement; the effects that follow (the `Paid` message, the
    /// ledger save) are returned for the caller's queue.
    ///
    /// A transfer is signed once per hand and kept with the debt (saved
    /// before it is sent); every retry sends those same bytes. A new one is
    /// signed only when the chain shows the old one's coins spent by
    /// something else and the old one nowhere.
    async fn pay(&mut self, hero: &str, root: &str, amount: u64) -> Vec<Effect> {
        let now = now_secs();
        if self.citizen.is_halted(root) {
            return Vec::new(); // waiting for an operator
        }
        // the signed transfer is the ledger's, read now, not a copy that
        // travelled in an effect
        let (pending, event) = match self.citizen.pending_of(root) {
            Some(p) => {
                let (on_chain, unspent) = match &self.facts {
                    Some(f) => (
                        f.tx_state(&p.txid),
                        f.all_unspent(&self.key.script(), &p.outpoints),
                    ),
                    None => (TxOnChain::NotSeen, true),
                };
                match p.resume(on_chain, unspent) {
                    Resume::OnChain => return Vec::new(),
                    Resume::Resend => (p, None),
                    Resume::Rebuild => {
                        // never signed here: the debt goes back to being
                        // unsent and comes up again through `payable`,
                        // which holds it to the daily cap; a second
                        // rejection halts it for an operator
                        let cause = if on_chain == TxOnChain::Invalid {
                            eprintln!(
                                "PAYOUT REJECTED: transfer {} for hand {}… is on the chain but the assets rule rejected it; its coins are spent and {amount} {} did not move.",
                                p.txid,
                                &root[..8],
                                self.ticker
                            );
                            Cause::Invalid
                        } else {
                            eprintln!(
                                "pay for hand {}…: the coins of {} were spent by something else and it never landed",
                                &root[..8],
                                p.txid
                            );
                            Cause::SpentElsewhere
                        };
                        let follow = self.citizen.replace_payout(root, cause, now);
                        self.checkpoint();
                        return follow;
                    }
                }
            }
            None => match self.sign_payout(hero, root, amount, now) {
                Ok((p, ev)) => (p, Some(ev)),
                Err(e) => {
                    eprintln!(
                        "pay {amount} {} to {}… for {}…: {e}",
                        self.ticker,
                        &hero[..8],
                        &root[..8]
                    );
                    return self.citizen.house_pay_failed(root, &e, now);
                }
            },
        };
        let txid = pending.txid.clone();
        // kept and saved before the transfer leaves: see `Citizen::pay_prepared`
        if !self.citizen.pay_prepared(root, pending.clone(), now) {
            return Vec::new(); // no longer owed: send nothing
        }
        self.checkpoint();
        let post = self
            .http
            .post(format!("{}/tx", self.cli.producer.trim_end_matches('/')))
            .body(pending.hex.clone())
            .send()
            .await;
        // the flag is true for the producer's own refusal, false for not
        // having reached it
        let accepted = match post {
            Ok(r) => {
                let text = r.text().await.unwrap_or_default();
                match sidestr_wallet::deliver::parse_tx_response(&text) {
                    Ok(_) => Ok(()),
                    Err(e) => Err((true, format!("the producer refused: {e}"))),
                }
            }
            Err(e) => Err((false, format!("producer: {e}"))),
        };
        match accepted {
            Ok(()) => {
                eprintln!(
                    "paid {amount} {} to {}… for hand {}…: {txid}",
                    self.ticker,
                    &hero[..8],
                    &root[..8]
                );
                // the producer follows the public relays too: let them see it
                if let Some(event) = event {
                    if let Ok(json) = serde_json::to_string(&event) {
                        let id = event.id.clone();
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
                }
                let follow = self.citizen.house_paid(hero, root, &txid, now);
                self.checkpoint();
                follow
            }
            Err((refused, e)) => {
                eprintln!("pay for hand {}…: {e}", &root[..8]);
                let follow = if refused {
                    self.citizen.house_pay_refused(root, &e, now)
                } else {
                    self.citizen.house_pay_failed(root, &e, now)
                };
                self.checkpoint();
                follow
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
                Effect::Pay {
                    hero, root, amount, ..
                } => {
                    // what follows a payment goes ahead of the rest of the queue
                    let follow = self.pay(&hero, &root, amount).await;
                    for (i, f) in follow.into_iter().enumerate() {
                        queue.insert(i, f);
                    }
                }
                Effect::Persist => self.checkpoint(),
                Effect::Alert(alert) => {
                    eprintln!("ALERT: {}", alert.text);
                    // a due DM goes ahead of the rest of the queue
                    if let Some(dm) = self.alerter.route(&alert, now_secs()) {
                        queue.push_front(dm);
                    }
                }
                Effect::Dm { to, text } => self.send_dm(relay, &to, &text).await,
            }
        }
    }

    async fn on_event(&mut self, relay: &mut Relay, ev: nostr_bbs_core::NostrEvent) {
        let unwrapped = match unwrap_gift_kind(&ev, &self.sk, RUMOR_KIND) {
            Ok(u) => u,
            Err(_) => return, // a DM or someone else's wrap: not for the table
        };
        // the relay re-streams history: a message too old, or dated ahead of
        // the clock, is dropped unread
        let now = now_secs();
        let at = unwrapped.rumor.created_at;
        if !state::fresh(at, now) {
            return;
        }
        // de-duplicate on what only a member can make (their key and the
        // rumor's id), after a wrap has opened and its content parsed; what
        // is remembered is forgotten by age, a sender's share is bounded,
        // and only senders the house holds a session for are remembered at
        // all, so junk cannot grow the set or what is saved
        let hero = unwrapped.sender_pubkey;
        let key = hex::encode(compute_event_id(&unwrapped.rumor));
        self.seen.expire(now);
        if self.seen.contains(&hero, &key) {
            return;
        }
        let msg = match ToCitizen::parse(&unwrapped.rumor.content) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("{}…: {e}", &hero[..8]);
                return;
            }
        };
        let balances = self.balances_for(&hero);
        let effects = self.citizen.handle(&hero, msg, now, balances);
        // a message that changed the table is saved with its id before
        // anything it produced is sent; one that changed nothing writes
        // nothing, and is remembered in memory only
        let changed = self.citizen.is_dirty();
        if self.citizen.has_standing(&hero) {
            self.seen.remember(&hero, &key, at, changed);
        }
        self.checkpoint();
        self.run_effects(relay, effects).await;
    }

    async fn serve(&mut self, relay: &mut Relay) {
        let startup = std::mem::take(&mut self.startup);
        self.run_effects(relay, startup).await;
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
                        self.checkpoint();
                        self.run_effects(relay, effects).await;
                    }
                },
                _ = poll.tick() => {
                    self.refresh_chain().await;
                    let now = now_secs();
                    let mut effects = self.citizen.tick(now);
                    if let Some(f) = &self.facts {
                        effects.extend(self.citizen.payments_seen(&f.hand_payments, now));
                    }
                    effects.extend(self.citizen.payable(now, PAY_RETRY_SECS));
                    self.checkpoint();
                    self.run_effects(relay, effects).await;
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_alert_pubkey;

    #[test]
    fn the_alert_pubkey_is_hex_an_npub_or_nothing() {
        let hex = "ab".repeat(32);
        assert_eq!(parse_alert_pubkey(None), Ok(None));
        assert_eq!(parse_alert_pubkey(Some("  ")), Ok(None));
        assert_eq!(parse_alert_pubkey(Some(&hex)), Ok(Some(hex.clone())));
        assert_eq!(
            parse_alert_pubkey(Some(&hex.to_uppercase())),
            Ok(Some(hex.clone()))
        );
        let npub = nostr_bbs_core::nip19::encode_npub(&hex).unwrap();
        assert_eq!(parse_alert_pubkey(Some(&npub)), Ok(Some(hex)));
        assert!(parse_alert_pubkey(Some("abcd")).is_err());
        assert!(parse_alert_pubkey(Some(&"zz".repeat(32))).is_err());
    }
}
