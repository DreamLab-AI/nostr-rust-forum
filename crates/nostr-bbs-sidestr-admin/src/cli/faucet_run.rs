//! `faucet`: answer kind-23501 requests on the relays, one grant at a time.
//!
//! Each relay is followed on its own task and reconnected with backoff;
//! requests reach one queue and are answered in order. A request is judged
//! against the ledger first (cheap), then against a fresh replay of the
//! producer's blocks, so the faucet never pays from a coin the chain has
//! already spent. The coins a grant spends are held back until the chain
//! shows them gone, or half an hour passes and the grant is taken to have
//! been dropped. A grant goes to the producer (`POST /tx`) and, as a signed
//! kind-23500 event, to the relays; either taking it is enough.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use bitcoin::OutPoint;
use futures_util::{SinkExt, StreamExt};
use nostr_bbs_poker_citizen::net::publish_once;
use nostr_bbs_sidestr_admin::faucet::{build_grant, Ledger, Policy};
use nostr_bbs_sidestr_admin::resolve_asset;
use serde_json::{json, Value};
use sidestr_agent::AgentKey;
use sidestr_nostr::event::Event;
use sidestr_nostr::kinds::KIND_FAUCET_REQUEST;
use sidestr_nostr::tx::{parse_faucet_request, sign_transaction_event};
use sidestr_wallet::spend::resolve_to;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_tungstenite::{connect_async, tungstenite::Message};

use super::{now_secs, Producer};

/// How far back a (re)connected relay is asked for requests.
const LOOKBACK_SECS: u64 = 120;
/// How long a grant's coins are held back if the chain never shows them.
const HELD_SECS: u64 = 1_800;
/// How long a request id is remembered, so a relay re-serving it is quiet.
const SEEN_SECS: u64 = 3_600;

/// What the subcommand was given.
pub struct Settings {
    /// The chain the producer must serve.
    pub chain_id: String,
    /// The asset to grant beside the sats (id or ticker), and units.
    pub asset: Option<(String, u64)>,
    /// Plain sats per grant.
    pub sats: u64,
    /// Hours before one script may be paid again.
    pub per_address_hours: u64,
    /// Grants per hour, all scripts together.
    pub per_hour: usize,
    /// The grant ledger.
    pub state: PathBuf,
    /// Relays to follow and publish to.
    pub relays: Vec<String>,
}

fn log(msg: impl AsRef<str>) {
    eprintln!("{} faucet: {}", now_secs(), msg.as_ref());
}

fn load(path: &PathBuf) -> Result<Ledger, String> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ledger::parse(&t).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Ledger::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn save(path: &PathBuf, l: &Ledger) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, l.to_json())?;
    std::fs::rename(tmp, path)
}

/// Run the faucet until every relay task has ended (they do not, on their
/// own: each reconnects).
pub async fn run(producer: &Producer, key: &AgentKey, s: Settings) -> Result<(), String> {
    let first = producer.replayed(&s.chain_id).await?;
    let doc = first.state.document().clone();
    let asset = match &s.asset {
        Some((a, units)) => Some((resolve_asset(&first, a)?, *units)),
        None => None,
    };
    let policy = Policy {
        sats: s.sats,
        asset,
        per_address_secs: s.per_address_hours.saturating_mul(3_600),
        per_hour: s.per_hour,
    };
    let me = key.script();
    let mut ledger = load(&s.state)?;
    log(format!(
        "{} on {} at height {}: {} sats{} per grant, one per script per {} h, {}/h; key {}…; relays {}",
        if asset.is_some() { "sats and asset" } else { "sats" },
        doc.id,
        first.state.height(),
        policy.sats,
        asset.map_or(String::new(), |(a, n)| format!(" + {n} of {}…", &a.to_string()[..12])),
        s.per_address_hours,
        policy.per_hour,
        &key.pubkey().to_string()[..12],
        s.relays.join(",")
    ));
    drop(first);

    let (tx, mut rx) = mpsc::channel::<(String, Event)>(256);
    for relay in &s.relays {
        tokio::spawn(follow(relay.clone(), tx.clone()));
    }
    drop(tx);

    let mut held: HashMap<OutPoint, u64> = HashMap::new();
    let mut seen: HashMap<String, u64> = HashMap::new();
    while let Some((relay, ev)) = rx.recv().await {
        let now = now_secs();
        seen.retain(|_, t| now.saturating_sub(*t) < SEEN_SECS);
        if seen.insert(ev.id.clone(), now).is_some() {
            continue;
        }
        if ev.verify().is_err() {
            continue;
        }
        let Ok(req) = parse_faucet_request(&ev, Some(&doc.id)) else {
            continue; // another chain's request
        };
        let short = &ev.id[..12.min(ev.id.len())];
        let to = match resolve_to(&req.destination, &doc.address_prefix) {
            Ok(r) => r.script,
            Err(e) => {
                log(format!("request {short}…: {e}"));
                continue;
            }
        };
        if to == me || to.is_op_return() {
            log(format!(
                "request {short}…: not a destination the faucet pays"
            ));
            continue;
        }
        let script_hex = to.to_hex_string();
        if let Err(why) = ledger.judge(&script_hex, now, &policy) {
            log(format!("{}… {why}; skipped", &script_hex[..16]));
            if let Err(e) = save(&s.state, &ledger) {
                log(format!("ledger not saved: {e}"));
            }
            continue;
        }
        let r = match producer.replayed(&s.chain_id).await {
            Ok(r) => r,
            Err(e) => {
                log(format!("request {short}…: {e}"));
                continue;
            }
        };
        let coins = r.state.coins(&me);
        held.retain(|op, t| {
            coins.iter().any(|c| c.outpoint == *op) && now.saturating_sub(*t) < HELD_SECS
        });
        let free: Vec<_> = coins
            .into_iter()
            .filter(|c| !held.contains_key(&c.outpoint))
            .collect();
        let spend = match build_grant(key, &r, &free, &to, &policy) {
            Ok(s) => s,
            Err(e) => {
                log(format!("request {short}…: {e}"));
                continue;
            }
        };
        let posted = producer.post(&spend).await;
        let mut relays_took = 0usize;
        match sign_transaction_event(&key.event_signer(), &doc.id, &spend.hex, now) {
            Ok(event) => {
                let json = serde_json::to_string(&event).unwrap_or_default();
                for url in &s.relays {
                    if publish_once(url, &json, &event.id).await {
                        relays_took += 1;
                    }
                }
            }
            Err(e) => log(format!("kind-23500 not signed: {e}")),
        }
        if let Err(e) = &posted {
            if relays_took == 0 {
                log(format!("request {short}…: nothing took the grant: {e}"));
                continue;
            }
        }
        for i in &spend.tx.input {
            held.insert(i.previous_output, now);
        }
        ledger.record(&script_hex, now);
        if let Err(e) = save(&s.state, &ledger) {
            log(format!("ledger not saved: {e}"));
        }
        log(format!(
            "paid {}… {} sats{} in {} (fee {}; producer {}, {relays_took} relays) (asked on {relay})",
            &script_hex[..16],
            policy.sats,
            asset.map_or(String::new(), |(_, n)| format!(" + {n} units")),
            spend.txid,
            spend.fee,
            if posted.is_ok() { "took it" } else { "refused" },
        ));
    }
    Err("every relay task ended".into())
}

/// Follow one relay for kind-23501, reconnecting with backoff.
async fn follow(url: String, tx: mpsc::Sender<(String, Event)>) {
    let mut backoff = 2u64;
    loop {
        match connect_async(url.as_str()).await {
            Ok((mut ws, _)) => {
                backoff = 2;
                let req = json!([
                    "REQ",
                    "faucet",
                    { "kinds": [KIND_FAUCET_REQUEST], "since": now_secs().saturating_sub(LOOKBACK_SECS) }
                ]);
                if ws.send(Message::Text(req.to_string())).await.is_err() {
                    sleep(Duration::from_secs(backoff)).await;
                    continue;
                }
                while let Some(msg) = ws.next().await {
                    let text = match msg {
                        Ok(Message::Text(t)) => t,
                        Ok(Message::Ping(p)) => {
                            let _ = ws.send(Message::Pong(p)).await;
                            continue;
                        }
                        Ok(Message::Close(_)) | Err(_) => break,
                        Ok(_) => continue,
                    };
                    let Ok(Value::Array(frame)) = serde_json::from_str::<Value>(&text) else {
                        continue;
                    };
                    match frame.first().and_then(Value::as_str) {
                        Some("EVENT") => {
                            if let Some(ev) = frame
                                .get(2)
                                .and_then(|v| serde_json::from_value::<Event>(v.clone()).ok())
                            {
                                if tx.send((url.clone(), ev)).await.is_err() {
                                    return; // the faucet has stopped
                                }
                            }
                        }
                        Some("CLOSED") => break,
                        _ => {}
                    }
                }
                log(format!(
                    "{url}: connection closed; reconnecting in {backoff}s"
                ));
            }
            Err(e) => log(format!("{url}: {e}; retrying in {backoff}s")),
        }
        sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(120);
    }
}
