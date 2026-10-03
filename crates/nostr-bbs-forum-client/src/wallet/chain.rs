//! The chain half of the member wallet, pure and natively testable: the
//! compiled-in chain locks, the replay of a mirror's block file into a
//! snapshot, and what the UI reads from a snapshot (balances, a member's
//! activity, the asset tipped on each post).
//!
//! **The locks (ADR-2015, ADR-2021).** The wallet knows exactly two chains,
//! both sealed documents compiled in ([`PINS`]):
//!
//! - [`DREAMLAB`], `sidestr:dreamlab` beside Bitcoin testnet4
//!   (`parent: tbtc4`), whose asset DREAM was issued at [`DREAM_ASSET_ID`];
//! - [`DREAMLAB_TXBT4`], `sidestr:dreamlab-txbt4` beside BLAKE2b testnet4
//!   (`parent: txbt4`), whose blocks carry Knots' v2 header and whose asset
//!   (BLAKES7) has no compiled-in id: the deployment names it once issued.
//!
//! Runtime config can switch the wallet on, choose which of the two chains
//! it offers, and point each at another mirror, other relays or another asset
//! id ([`super::profile`]); it cannot point it at a third chain, and a
//! document that differs from its pin in id, parent or genesis is refused
//! ([`check_document`]). A mirror is never trusted: every block it serves is
//! validated against the pinned document under the header family its parent
//! hands down ([`sidestr_core::mirror`]), so a bad mirror can be stale or
//! empty but cannot invent a balance.

use std::collections::HashMap;

use bitcoin::{OutPoint, Script, ScriptBuf, Txid};
use sidestr_core::assets::{AssetView, Issued};
use sidestr_core::block::{HeaderFamily, SidestrBlock};
use sidestr_core::document::ChainDocument;
use sidestr_core::records::records_of;
use sidestr_core::rules::Utxo;
use sidestr_core::{Family, State, StateOf, Stock};
use sidestr_header::Blake2bV2;
use sidestr_wallet::coins::Coin;

/// The sealed chain document of `sidestr:dreamlab`, byte for byte as the
/// mirror serves it (`chain.json`).
pub const CHAIN_JSON: &str = include_str!("sidestr-dreamlab.chain.json");
/// The chain id.
pub const CHAIN_ID: &str = "sidestr:dreamlab";
/// The parent: Bitcoin testnet4. The wallet refuses any other.
pub const PARENT: &str = "tbtc4";
/// The genesis the document seals.
pub const GENESIS_HASH: &str = "4db37517728bd509c0cb96ee5a2e3e2a77f9e965a092e9f67948b413d453dbc0";
/// DREAM: `issue:DREAM:0` at block 372, supply 1,000,000, by the DreamLab
/// treasury key.
pub const DREAM_ASSET_ID: &str = "608005d32a927de46e92f01b7948feac3469411cc0fbcfb1336e4eff49b978a9";
/// The ticker shown.
pub const DREAM: &str = "DREAM";
/// The default mirror: GitHub Pages, open CORS (SPEC 11).
pub const DEFAULT_MIRROR: &str = "https://dreamlab-ai.github.io/sidestr-dreamlab";

/// The sealed chain document of `sidestr:dreamlab-txbt4`, byte for byte as
/// its producer serves it (`chain.json`).
pub const TXBT4_CHAIN_JSON: &str = include_str!("sidestr-dreamlab-txbt4.chain.json");
/// The second chain's id.
pub const TXBT4_CHAIN_ID: &str = "sidestr:dreamlab-txbt4";
/// Its parent: BLAKE2b testnet4. The wallet refuses any other.
pub const TXBT4_PARENT: &str = "txbt4";
/// The genesis its document seals.
pub const TXBT4_GENESIS_HASH: &str =
    "1009aa2984d5c699fe61ef1e5905afe472a49d67551542045726828c8b82d108";
/// Its default mirror: its own GitHub Pages repository.
pub const TXBT4_DEFAULT_MIRROR: &str = "https://dreamlab-ai.github.io/sidestr-dreamlab-txbt4";

/// The relays the producers and the faucets follow (siding's five defaults).
pub const DEFAULT_RELAYS: [&str; 5] = [
    "wss://nos.lol",
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://nostr.mom",
    "wss://nostr.oxtr.dev",
];
/// The memo a tip carries beside its tally: `tip:nostr:<event id>`.
pub const TIP_PREFIX: &str = "tip:nostr:";

/// One compiled-in chain lock: the sealed document and what the wallet shows
/// for it before any runtime config.
#[derive(Debug, PartialEq, Eq)]
pub struct Pin {
    /// The chain id.
    pub id: &'static str,
    /// The parent alias the document must name.
    pub parent: &'static str,
    /// The parent in words.
    pub parent_name: &'static str,
    /// The genesis the document must seal.
    pub genesis_hash: &'static str,
    /// The address prefix the document sets (checked by the tests).
    pub address_prefix: &'static str,
    /// The sealed document.
    pub json: &'static str,
    /// The default name of the chain's asset, for headings.
    pub label: &'static str,
    /// The default ticker.
    pub ticker: &'static str,
    /// The asset's compiled-in id, when it was issued before this build.
    pub asset_id: Option<&'static str>,
    /// The default mirror.
    pub mirror: &'static str,
}

/// `sidestr:dreamlab`, DREAM.
pub const DREAMLAB: Pin = Pin {
    id: CHAIN_ID,
    parent: PARENT,
    parent_name: "testnet4",
    genesis_hash: GENESIS_HASH,
    address_prefix: "drm",
    json: CHAIN_JSON,
    label: DREAM,
    ticker: DREAM,
    asset_id: Some(DREAM_ASSET_ID),
    mirror: DEFAULT_MIRROR,
};

/// `sidestr:dreamlab-txbt4`, BLAKES7 (id named at runtime once issued).
pub const DREAMLAB_TXBT4: Pin = Pin {
    id: TXBT4_CHAIN_ID,
    parent: TXBT4_PARENT,
    parent_name: "BLAKE2b testnet4",
    genesis_hash: TXBT4_GENESIS_HASH,
    address_prefix: "drt",
    json: TXBT4_CHAIN_JSON,
    label: "BLAKES7",
    ticker: "BLAKES7",
    asset_id: None,
    mirror: TXBT4_DEFAULT_MIRROR,
};

/// Every chain the wallet will touch.
pub const PINS: [&Pin; 2] = [&DREAMLAB, &DREAMLAB_TXBT4];

/// The pin of a chain id, if it is one of [`PINS`].
pub fn pin(id: &str) -> Option<&'static Pin> {
    PINS.into_iter().find(|p| p.id == id)
}

/// Whether `s` is 64 hex digits (a txid, a pubkey, an event id).
pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A chain document, accepted only if it is exactly the chain `pin` locks:
/// same id, same parent, same genesis.
pub fn check_document(pin: &Pin, json: &str) -> Result<ChainDocument, String> {
    let doc = ChainDocument::from_json(json).map_err(|e| format!("chain document: {e}"))?;
    if doc.id != pin.id || doc.parent != pin.parent {
        return Err(format!(
            "the chain is {} beside {}, not {} beside {}",
            doc.id, doc.parent, pin.id, pin.parent
        ));
    }
    if doc.genesis_hash.as_deref() != Some(pin.genesis_hash) {
        return Err(format!("{}'s genesis is not the locked one", pin.id));
    }
    Ok(doc)
}

impl Pin {
    /// The pinned document, checked against the lock.
    pub fn document(&self) -> Result<ChainDocument, String> {
        check_document(self, self.json)
    }
}

/// The script a Nostr key's coins pay: `OP_1 <x-only key>`. The same on
/// every sidestr chain, so one key is one wallet on both.
pub fn script_of(pubkey_hex: &str) -> Option<ScriptBuf> {
    let pk = pubkey_hex.trim().to_ascii_lowercase();
    if !is_hex64(&pk) {
        return None;
    }
    ScriptBuf::from_hex(&format!("5120{pk}")).ok()
}

/// A script from its hex.
pub fn script_of_hex(hex_script: &str) -> Option<ScriptBuf> {
    ScriptBuf::from_hex(hex_script).ok()
}

/// The Nostr key a `5120<key>` script pays, if it is one.
pub fn pubkey_of_script(script: &Script) -> Option<String> {
    let b = script.as_bytes();
    (b.len() == 34 && b[0] == 0x51 && b[1] == 0x20).then(|| hex::encode(&b[2..]))
}

/// The validated chain state, under whichever header family the chain's
/// parent hands down: stock headers beside testnet4, Knots' 164-byte v2
/// headers beside BLAKE2b testnet4.
pub enum ChainState {
    /// A chain beside a stock parent.
    Stock(State),
    /// A chain beside a BLAKE2b parent.
    Blake2b(StateOf<Blake2bV2>),
}

impl ChainState {
    /// The document the chain was validated against.
    pub fn document(&self) -> &ChainDocument {
        match self {
            Self::Stock(s) => s.document(),
            Self::Blake2b(s) => s.document(),
        }
    }

    /// The tip height.
    pub fn height(&self) -> u32 {
        match self {
            Self::Stock(s) => s.height(),
            Self::Blake2b(s) => s.height(),
        }
    }

    /// The tip block's time.
    pub fn tip_time(&self) -> u32 {
        match self {
            Self::Stock(s) => s.tip().time,
            Self::Blake2b(s) => s.tip().time,
        }
    }

    /// The unspent outputs.
    pub fn utxo(&self) -> &Utxo {
        match self {
            Self::Stock(s) => s.utxo(),
            Self::Blake2b(s) => s.utxo(),
        }
    }

    /// The coins a script holds at the tip.
    pub fn coins(&self, script: &Script) -> Vec<Coin> {
        match self {
            Self::Stock(s) => sidestr_wallet::coins::from_state(s, script),
            Self::Blake2b(s) => sidestr_wallet::coins::from_state(s, script),
        }
    }
}

/// One side of a transaction as a wallet reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leg {
    /// The script, hex.
    pub script: String,
    /// Sats.
    pub sats: u64,
    /// Units of the chain's asset carried (DREAM on `sidestr:dreamlab`).
    pub asset: u64,
}

/// A transaction summarised for activity lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxSummary {
    /// Its id, hex.
    pub txid: String,
    /// The block it is in.
    pub height: u32,
    /// The block's time, unix seconds.
    pub time: u32,
    /// What it spent (the coinbase has none).
    pub ins: Vec<Leg>,
    /// What it paid (records left out).
    pub outs: Vec<Leg>,
    /// The post a tip names, when it carries `tip:nostr:<event id>`.
    pub tip_event: Option<String>,
    /// The poker hand it settles, when it carries `hand:<root>`.
    pub hand_root: Option<String>,
    /// Set when the assets rule reads it as broken: an asset it touched is gone.
    pub broken: Option<String>,
    /// A block's coinbase: a peg-in claim or the producer's fees.
    pub coinbase: bool,
}

/// Tips on one post.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TipTotal {
    /// Units of the chain's asset tipped.
    pub asset: u64,
    /// How many tips.
    pub count: u32,
}

/// The chain as one replay of the mirror left it.
pub struct Snapshot {
    /// The validated chain.
    pub state: ChainState,
    /// What each unspent output carries, under the SPEC 12 assets rule.
    pub assets: AssetView,
    /// The asset this wallet reads, when the chain has one configured.
    pub asset: Option<Txid>,
    /// Every transaction, oldest first.
    pub txs: Vec<TxSummary>,
    /// The asset tipped per post, by event id.
    pub tips: HashMap<String, TipTotal>,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("chain", &self.state.document().id)
            .field("height", &self.height())
            .field("txs", &self.txs.len())
            .finish_non_exhaustive()
    }
}

/// What one family's replay produced, before it is wrapped in a [`ChainState`].
struct Replayed<F: HeaderFamily> {
    state: StateOf<F>,
    assets: AssetView,
    txs: Vec<TxSummary>,
    tips: HashMap<String, TipTotal>,
}

/// Units of `asset` an output's carry holds.
fn units(carry: Option<&sidestr_core::assets::Carry>, asset: Option<&Txid>) -> u64 {
    match (carry, asset) {
        (Some(c), Some(a)) => c.get(a).copied().unwrap_or(0),
        _ => 0,
    }
}

/// Replay a mirror's `blocks.dat` against `pin`'s sealed document, reading
/// `asset` (if any) under the assets rule. `now` is the clock for the
/// future-time rule.
pub fn replay(
    pin: &Pin,
    asset: Option<Txid>,
    dat: &[u8],
    now: Option<u32>,
) -> Result<Snapshot, String> {
    let doc = pin.document()?;
    let family = doc.family().map_err(|e| format!("chain document: {e}"))?;
    Ok(match family {
        Family::Stock => {
            let r = replay_in::<Stock>(doc, asset, dat, now)?;
            Snapshot {
                state: ChainState::Stock(r.state),
                assets: r.assets,
                asset,
                txs: r.txs,
                tips: r.tips,
            }
        }
        Family::Blake2b => {
            let r = replay_in::<Blake2bV2>(doc, asset, dat, now)?;
            Snapshot {
                state: ChainState::Blake2b(r.state),
                assets: r.assets,
                asset,
                txs: r.txs,
                tips: r.tips,
            }
        }
    })
}

fn replay_in<F: HeaderFamily>(
    doc: ChainDocument,
    asset: Option<Txid>,
    dat: &[u8],
    now: Option<u32>,
) -> Result<Replayed<F>, String> {
    let family = F::default();
    let asset = asset.as_ref();
    let mut assets = AssetView::new();
    let mut txs = Vec::new();
    let mut tips: HashMap<String, TipTotal> = HashMap::new();
    let state = StateOf::<F>::replay_with(doc, dat, now, |before, height, block| {
        let time = family.time(block.header());
        let txdata = block.txdata();
        // inputs are read before the block is applied (afterwards they are
        // gone); one that spends an output of an earlier transaction in the
        // same block is resolved from that transaction once the block is read
        let mut spent: Vec<Vec<Option<Leg>>> = txdata
            .iter()
            .map(|tx| {
                tx.input
                    .iter()
                    .map(|i| {
                        let c = before?.utxo().get(&i.previous_output)?;
                        Some(Leg {
                            script: c.output.script_pubkey.to_hex_string(),
                            sats: c.output.value.to_sat(),
                            asset: units(assets.carried(&i.previous_output), asset),
                        })
                    })
                    .collect()
            })
            .collect();
        let outcomes = assets.apply_transactions(txdata, height);
        let ids: Vec<Txid> = txdata.iter().map(|t| t.compute_txid()).collect();
        for (ti, tx) in txdata.iter().enumerate() {
            for (ii, inp) in tx.input.iter().enumerate() {
                if spent[ti][ii].is_some() {
                    continue;
                }
                let op = inp.previous_output;
                let Some(src) = ids[..ti].iter().position(|t| *t == op.txid) else {
                    continue;
                };
                let Some(o) = txdata[src].output.get(op.vout as usize) else {
                    continue;
                };
                let carried = units(
                    outcomes
                        .iter()
                        .find(|oc| oc.txid == op.txid)
                        .and_then(|oc| oc.carried_out.get(&op.vout)),
                    asset,
                );
                spent[ti][ii] = Some(Leg {
                    script: o.script_pubkey.to_hex_string(),
                    sats: o.value.to_sat(),
                    asset: carried,
                });
            }
        }
        let spent: Vec<Vec<Leg>> = spent
            .into_iter()
            .map(|v| v.into_iter().flatten().collect())
            .collect();
        for (i, tx) in txdata.iter().enumerate() {
            let txid = ids[i];
            let coinbase = i == 0 && tx.is_coinbase();
            let outcome = outcomes.iter().find(|o| o.txid == txid);
            let broken = outcome.and_then(|o| o.error.clone());
            let outs: Vec<Leg> = tx
                .output
                .iter()
                .enumerate()
                .filter(|(_, o)| !o.script_pubkey.is_op_return())
                .map(|(v, o)| Leg {
                    script: o.script_pubkey.to_hex_string(),
                    sats: o.value.to_sat(),
                    asset: units(
                        outcome.and_then(|oc| oc.carried_out.get(&(v as u32))),
                        asset,
                    ),
                })
                .collect();
            let records = records_of(tx);
            let tip_event = records.iter().find_map(|(_, t)| {
                t.strip_prefix(TIP_PREFIX)
                    .filter(|id| is_hex64(id))
                    .map(str::to_ascii_lowercase)
            });
            let hand_root = records
                .iter()
                .find_map(|(_, t)| nostr_bbs_poker::rules::parse_hand_memo(t).map(str::to_string));
            // a tip counts what output 0 carries of the asset, when the rule held
            if let (Some(ev), None) = (&tip_event, &broken) {
                let n = outs.first().map(|l| l.asset).unwrap_or(0);
                if n > 0 {
                    let t = tips.entry(ev.clone()).or_default();
                    t.asset += n;
                    t.count += 1;
                }
            }
            txs.push(TxSummary {
                txid: txid.to_string(),
                height,
                time,
                ins: spent[i].clone(),
                outs,
                tip_event,
                hand_root,
                broken,
                coinbase,
            });
        }
    })
    .map_err(|e| format!("the mirror's blocks do not validate: {e}"))?;
    Ok(Replayed {
        state,
        assets,
        txs,
        tips,
    })
}

/// A member's balances.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Balances {
    /// Units of the chain's asset held.
    pub asset: u64,
    /// Sats on coins that carry nothing: what pays fees.
    pub plain: u64,
    /// Sats riding on asset carriers (any asset: none of them pay fees).
    pub carrier_sats: u64,
}

impl Snapshot {
    /// The tip height.
    pub fn height(&self) -> u32 {
        self.state.height()
    }

    /// The tip block's time.
    pub fn tip_time(&self) -> u32 {
        self.state.tip_time()
    }

    /// Coins a script holds, less any `held` (spent by a transaction not yet
    /// mined).
    pub fn coins(&self, script: &Script, held: &[OutPoint]) -> Vec<Coin> {
        self.state
            .coins(script)
            .into_iter()
            .filter(|c| !held.contains(&c.outpoint))
            .collect()
    }

    /// What a script holds.
    pub fn balances(&self, script: &Script, held: &[OutPoint]) -> Balances {
        let mut b = Balances::default();
        for c in self.coins(script, held) {
            match self.assets.carried(&c.outpoint) {
                None => b.plain += c.value,
                Some(m) => {
                    b.asset += units(Some(m), self.asset.as_ref());
                    b.carrier_sats += c.value;
                }
            }
        }
        b
    }

    /// The issue of the asset this wallet reads, once the chain shows it.
    pub fn issued(&self) -> Option<&Issued> {
        self.asset.and_then(|a| self.assets.issued().get(&a))
    }

    /// Transactions touching a script, newest first.
    pub fn history(&self, script_hex: &str) -> Vec<&TxSummary> {
        self.txs
            .iter()
            .rev()
            .filter(|t| {
                t.ins.iter().any(|l| l.script == script_hex)
                    || t.outs.iter().any(|l| l.script == script_hex)
            })
            .collect()
    }

    /// Whether a transaction is in the chain.
    pub fn contains(&self, txid: &str) -> bool {
        self.txs.iter().any(|t| t.txid == txid)
    }

    /// Whether an outpoint is still unspent.
    pub fn unspent(&self, op: &OutPoint) -> bool {
        self.state.utxo().contains_key(op)
    }
}

/// How one transaction reads from one member's side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Movement {
    /// The asset in (positive) or out (negative), net of change.
    pub asset: i64,
    /// Sats in or out, net of change and including the fee when sending.
    pub sats: i64,
    /// The other side: the first script paid that is not mine (sending) or
    /// the first script spent that is not mine (receiving).
    pub counterparty: Option<String>,
}

impl TxSummary {
    /// The net effect on `me` (a script hex).
    pub fn movement(&self, me: &str) -> Movement {
        let sum = |legs: &[Leg], f: fn(&Leg) -> u64| -> i64 {
            legs.iter().filter(|l| l.script == me).map(f).sum::<u64>() as i64
        };
        let asset = sum(&self.outs, |l| l.asset) - sum(&self.ins, |l| l.asset);
        let sats = sum(&self.outs, |l| l.sats) - sum(&self.ins, |l| l.sats);
        let sending = self.ins.iter().any(|l| l.script == me);
        let counterparty = if sending {
            self.outs
                .iter()
                .find(|l| l.script != me)
                .map(|l| l.script.clone())
        } else {
            self.ins
                .iter()
                .find(|l| l.script != me)
                .map(|l| l.script.clone())
        };
        Movement {
            asset,
            sats,
            counterparty,
        }
    }
}

/// Where a payment on `pin`'s chain goes, from what a member typed or picked:
/// an npub, a `did:nostr:`, 64-hex key, or an address. An address pays its
/// script whatever its prefix (sidestr-wallet's rule, `resolve_to`); a key's
/// script is the same on every chain, so another chain's address of a member
/// (`drm1…` on `sidestr:dreamlab-txbt4`) pays that member here. Secret-shaped
/// text is refused before anything else, without being echoed.
pub fn destination_script(pin: &Pin, text: &str) -> Result<ScriptBuf, String> {
    let t = sidestr_agent::refuse_secret(text.trim()).map_err(|e| e.to_string())?;
    let dest = sidestr_agent::destination(t).map_err(|e| e.to_string())?;
    sidestr_wallet::spend::resolve_to(&dest, pin.address_prefix)
        .map(|r| r.script)
        .map_err(|e| e.to_string())
}

/// A Nostr key's address on `pin`'s chain (`drm1…`, `drt1…`).
pub fn address_of(pin: &Pin, pubkey_hex: &str) -> Option<String> {
    let pk = sidestr_agent::parse_pubkey(pubkey_hex).ok()?;
    sidestr_agent::identity(&pk, pin.address_prefix).map(|i| i.address)
}

/// Why a provision could not be built.
#[derive(Debug)]
pub enum ProvisionError {
    /// The wallet refused (not enough, dust, …).
    Wallet(sidestr_wallet::Error),
    /// Nothing to give, or a record that would not encode.
    Plain(String),
}

/// A starter pack in one transaction: `units` of the snapshot's asset on a
/// carrier to `to` (with the change on a carrier back), then `sats` to `to`
/// as plain coins for their fees. Asset carriers are the required inputs;
/// plain coins pay the sats and the fee. Checked against the assets view
/// before it is returned. `ticker` names the asset in errors.
pub fn build_provision(
    snap: &Snapshot,
    coins: &[Coin],
    signer: &dyn sidestr_wallet::SpendSigner,
    to: &ScriptBuf,
    units: u64,
    sats: u64,
    ticker: &str,
) -> Result<sidestr_wallet::spend::Spend, ProvisionError> {
    use sidestr_wallet::asset::{sort_coins, CARRIER};
    use sidestr_wallet::compose::{build_outputs, OutputsRequest};
    let me = signer.script();
    let id = match (snap.asset, units) {
        (Some(id), _) => Some(id),
        (None, 0) => None,
        (None, _) => {
            return Err(ProvisionError::Plain(format!(
                "This chain has no {ticker} yet; give sats only."
            )))
        }
    };
    let sorted = sort_coins(coins, &snap.assets, id.as_ref());
    let mut required = Vec::new();
    let mut have = 0u64;
    if units > 0 {
        let mut carriers = sorted.carriers.clone();
        carriers.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        for (c, n) in carriers {
            if have >= units {
                break;
            }
            have += n;
            required.push(c);
        }
        if have < units {
            return Err(ProvisionError::Plain(format!(
                "Not enough {ticker}: you hold {have}, the pack gives {units}."
            )));
        }
    }
    let mut outputs = Vec::new();
    let mut records = Vec::new();
    if units > 0 {
        outputs.push((to.clone(), CARRIER));
        let mut assigns = vec![(0u32, units)];
        if have > units {
            outputs.push((me.clone(), CARRIER));
            assigns.push((1, have - units));
        }
        records.push(
            sidestr_core::records::tally_text(id.as_ref(), &assigns)
                .map_err(|e| ProvisionError::Plain(e.to_string()))?,
        );
    }
    if sats > 0 {
        outputs.push((to.clone(), sats));
    }
    if outputs.is_empty() {
        return Err(ProvisionError::Plain(format!(
            "Choose some {ticker} or sats to give."
        )));
    }
    let spend = build_outputs(
        &OutputsRequest {
            chain: snap.state.document(),
            coins: &sorted.plain,
            required: &required,
            tip_height: snap.height(),
            outputs: &outputs,
            records: &records,
            fee: None,
        },
        signer,
        &sidestr_wallet::Permissive,
    )
    .map_err(ProvisionError::Wallet)?;
    let mut carried_in = Default::default();
    snap.assets
        .check(&spend.tx, &mut carried_in)
        .map_err(|e| ProvisionError::Plain(format!("the pack would break the assets rule: {e}")))?;
    Ok(spend)
}

/// The outputs `tx` spends, in input order, read from the member's own
/// coins (every coin pays `me`): the prevouts a browser signer's answer is
/// verified against. A spend of a coin not in `coins` is refused, since
/// the page did not build it.
pub fn prevouts_for(
    tx: &bitcoin::Transaction,
    coins: &[Coin],
    me: &ScriptBuf,
) -> Result<Vec<bitcoin::TxOut>, String> {
    tx.input
        .iter()
        .map(|i| {
            coins
                .iter()
                .find(|c| c.outpoint == i.previous_output)
                .map(|c| bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(c.value),
                    script_pubkey: me.clone(),
                })
                .ok_or_else(|| {
                    format!(
                        "the transfer spends {}, which is not one of your coins",
                        i.previous_output
                    )
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &str = "11ed64225dd5e2c5e18f61ad43d5ad9272d08739d3a20dd25886197b0738663c";

    fn dream() -> Txid {
        DREAM_ASSET_ID.parse().unwrap()
    }

    fn dreamlab_snap() -> Snapshot {
        replay(
            &DREAMLAB,
            Some(dream()),
            include_bytes!("testdata/blocks.dat"),
            None,
        )
        .unwrap()
    }

    #[test]
    fn each_lock_holds_its_pinned_document() {
        for pin in PINS {
            let doc = pin.document().unwrap();
            assert_eq!(doc.id, pin.id);
            assert_eq!(doc.parent, pin.parent);
            assert_eq!(doc.genesis_hash.as_deref(), Some(pin.genesis_hash));
            assert_eq!(doc.address_prefix, pin.address_prefix);
            assert_eq!(super::pin(pin.id), Some(pin));
        }
        assert_eq!(
            DREAMLAB.document().unwrap().family().unwrap(),
            Family::Stock
        );
        assert_eq!(
            DREAMLAB_TXBT4.document().unwrap().family().unwrap(),
            Family::Blake2b
        );
        assert_eq!(dream().to_string(), DREAM_ASSET_ID);
        assert_eq!(DREAMLAB.asset_id, Some(DREAM_ASSET_ID));
        assert_eq!(DREAMLAB_TXBT4.asset_id, None, "BLAKES7 is named at runtime");
        assert_eq!(super::pin("sidestr:other"), None);
    }

    /// The txbt4 document with any one locked field changed is refused.
    #[test]
    fn a_txbt4_document_that_is_not_the_pinned_one_is_refused() {
        let wrong_genesis = TXBT4_CHAIN_JSON.replace(TXBT4_GENESIS_HASH, &"00".repeat(32));
        assert_ne!(wrong_genesis, TXBT4_CHAIN_JSON);
        let e = check_document(&DREAMLAB_TXBT4, &wrong_genesis).unwrap_err();
        assert!(e.contains("genesis"), "{e}");
        let wrong_parent = TXBT4_CHAIN_JSON.replace(r#""parent":"txbt4""#, r#""parent":"tbtc4""#);
        assert_ne!(wrong_parent, TXBT4_CHAIN_JSON);
        assert!(check_document(&DREAMLAB_TXBT4, &wrong_parent).is_err());
        let wrong_id = TXBT4_CHAIN_JSON.replace(
            r#""id":"sidestr:dreamlab-txbt4""#,
            r#""id":"sidestr:dreamlab-txbt5""#,
        );
        assert_ne!(wrong_id, TXBT4_CHAIN_JSON);
        assert!(check_document(&DREAMLAB_TXBT4, &wrong_id).is_err());
        // and neither pinned document passes for the other chain
        assert!(check_document(&DREAMLAB_TXBT4, CHAIN_JSON).is_err());
        assert!(check_document(&DREAMLAB, TXBT4_CHAIN_JSON).is_err());
    }

    #[test]
    fn scripts_and_keys_round_trip() {
        let s = script_of(PK).unwrap();
        assert_eq!(pubkey_of_script(&s).as_deref(), Some(PK));
        assert!(script_of("nope").is_none());
        assert!(address_of(&DREAMLAB, PK).unwrap().starts_with("drm1p"));
        assert_eq!(
            destination_script(&DREAMLAB, &format!("did:nostr:{PK}")).unwrap(),
            s
        );
        assert_eq!(
            destination_script(&DREAMLAB, &address_of(&DREAMLAB, PK).unwrap()).unwrap(),
            s
        );
    }

    /// One key, one script, two addresses: each chain writes its own prefix,
    /// and either address pays the same script on either chain.
    #[test]
    fn one_key_has_an_address_on_each_chain_and_one_script() {
        let s = script_of(PK).unwrap();
        let drm = address_of(&DREAMLAB, PK).unwrap();
        let drt = address_of(&DREAMLAB_TXBT4, PK).unwrap();
        assert!(drt.starts_with("drt1p"), "{drt}");
        assert_ne!(drm, drt);
        for pin in PINS {
            assert_eq!(destination_script(pin, &drm).unwrap(), s);
            assert_eq!(destination_script(pin, &drt).unwrap(), s);
        }
        let npub = sidestr_agent::npub(&sidestr_agent::parse_pubkey(PK).unwrap());
        assert_eq!(destination_script(&DREAMLAB_TXBT4, &npub).unwrap(), s);
    }

    #[test]
    fn a_secret_is_never_a_destination() {
        for pin in PINS {
            let e = destination_script(
                pin,
                "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5",
            )
            .unwrap_err();
            assert!(!e.contains("vl029"), "the secret is echoed: {e}");
        }
    }

    #[test]
    fn an_empty_or_foreign_block_file_is_refused() {
        for pin in PINS {
            assert!(replay(pin, None, &[], None).is_err());
            assert!(replay(pin, None, &[0u8; 12], None).is_err());
        }
    }

    /// The live chain as the producer served it after DREAM was issued
    /// (block 372) and the treasury funded: the whole replay, the lock, the
    /// supply where it was minted.
    #[test]
    fn the_live_chain_replays_with_dream_at_the_treasury() {
        let snap = dreamlab_snap();
        assert!(matches!(snap.state, ChainState::Stock(_)));
        assert!(snap.height() >= 372);
        let issued = snap.issued().unwrap();
        assert_eq!(
            (issued.ticker.as_str(), issued.supply, issued.height),
            ("DREAM", 1_000_000, 372)
        );
        let treasury =
            script_of("f6b84686a2323a233e99c60ed79a59d3ec45289fec58a4c359997e551b0326b0").unwrap();
        let b = snap.balances(&treasury, &[]);
        assert!(b.asset > 0 && b.asset <= 1_000_000);
        let hist = snap.history(&treasury.to_hex_string());
        let issue = hist.iter().find(|t| t.txid == DREAM_ASSET_ID).unwrap();
        assert_eq!(issue.movement(&treasury.to_hex_string()).asset, 1_000_000);
        assert!(snap.txs.iter().all(|t| t.broken.is_none()));
        // with no asset named the same chain reads sats only
        let bare = replay(&DREAMLAB, None, include_bytes!("testdata/blocks.dat"), None).unwrap();
        let b = bare.balances(&treasury, &[]);
        assert_eq!(b.asset, 0);
        assert!(b.carrier_sats > 0, "the carriers are still counted apart");
        assert!(bare.issued().is_none() && bare.tips.is_empty());
    }

    /// `sidestr:dreamlab-txbt4` as its producer served it at the seal: the
    /// BLAKE2b genesis alone, validated under the Knots v2 header family.
    #[test]
    fn the_txbt4_genesis_replays_under_the_blake2b_family() {
        let dat = include_bytes!("testdata/txbt4-genesis.dat");
        let snap = replay(&DREAMLAB_TXBT4, None, dat, None).unwrap();
        assert!(matches!(snap.state, ChainState::Blake2b(_)));
        assert_eq!(snap.height(), 0);
        assert_eq!(snap.state.document().id, TXBT4_CHAIN_ID);
        assert_eq!(
            snap.balances(&script_of(PK).unwrap(), &[]),
            Balances::default()
        );
        // each chain's blocks fail the other's lock
        assert!(replay(&DREAMLAB, Some(dream()), dat, None).is_err());
        assert!(replay(
            &DREAMLAB_TXBT4,
            None,
            include_bytes!("testdata/blocks.dat"),
            None
        )
        .is_err());
    }

    #[test]
    fn a_pack_of_an_asset_the_chain_lacks_is_refused() {
        let snap = replay(
            &DREAMLAB_TXBT4,
            None,
            include_bytes!("testdata/txbt4-genesis.dat"),
            None,
        )
        .unwrap();
        let k = sidestr_agent::AgentKey::from_secret_bytes(&[0x42; 32]).unwrap();
        let e = build_provision(
            &snap,
            &[],
            &k.spend_signer(),
            &script_of(PK).unwrap(),
            10,
            0,
            "BLAKES7",
        )
        .unwrap_err();
        assert!(matches!(e, ProvisionError::Plain(m) if m.contains("no BLAKES7")));
    }

    mod browser_signer {
        use super::super::*;
        use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
        use bitcoin::hashes::Hash;
        use bitcoin::secp256k1::{Keypair, Message, SecretKey};
        use bitcoin::{Transaction, Witness};
        use sidestr_core::block::secp;
        use sidestr_core::sighash::{key_path_sighash, SighashRules};
        use sidestr_wallet::external::{accept_signed, unsigned_hex, ExternalSigner};
        use sidestr_wallet::SpendSigner;

        fn snap() -> Snapshot {
            replay(
                &DREAMLAB,
                DREAM_ASSET_ID.parse().ok(),
                include_bytes!("testdata/blocks.dat"),
                None,
            )
            .unwrap()
        }
        fn kp() -> Keypair {
            Keypair::from_secret_key(secp(), &SecretKey::from_slice(&[0x42; 32]).unwrap())
        }
        /// Two plain coins of the test key, so a pack spends both.
        fn coins() -> Vec<Coin> {
            (1..=2u8)
                .map(|i| Coin {
                    outpoint: OutPoint {
                        txid: Txid::from_byte_array([i; 32]),
                        vout: 0,
                    },
                    value: 1_500,
                    height: 1,
                    coinbase: false,
                })
                .collect()
        }
        fn them() -> ScriptBuf {
            script_of("11ed64225dd5e2c5e18f61ad43d5ad9272d08739d3a20dd25886197b0738663c").unwrap()
        }
        /// What the extension does: its own sighash, its own key.
        fn sign(tx: &Transaction, prevouts: &[bitcoin::TxOut], k: &Keypair) -> Transaction {
            let mut t = tx.clone();
            for i in 0..t.input.len() {
                let (m, ht) = key_path_sighash(&t, i, prevouts, SighashRules::Bip341).unwrap();
                let sig = secp().sign_schnorr_with_aux_rand(&Message::from_digest(m), k, &[0; 32]);
                t.input[i].witness =
                    Witness::from_slice(&[[sig.serialize().as_slice(), &[ht]].concat()]);
            }
            t
        }
        fn built() -> (Snapshot, ExternalSigner, sidestr_wallet::spend::Spend) {
            let s = snap();
            let ext = ExternalSigner::new(kp().x_only_public_key().0);
            let spend = build_provision(&s, &coins(), &ext, &them(), 0, 2_000, DREAM)
                .unwrap_or_else(|_| panic!("the pack builds"));
            (s, ext, spend)
        }

        /// The treasury's own DREAM pack, from its public key alone: the
        /// carriers are found and laid out, and nothing is signed.
        #[test]
        fn a_dream_pack_builds_unsigned_from_a_public_key() {
            let s = snap();
            let treasury = sidestr_agent::parse_pubkey(
                "f6b84686a2323a233e99c60ed79a59d3ec45289fec58a4c359997e551b0326b0",
            )
            .unwrap();
            let ext = ExternalSigner::new(treasury);
            let coins = s.coins(&ext.script(), &[]);
            let spend = build_provision(&s, &coins, &ext, &them(), 100, 1_000, DREAM)
                .unwrap_or_else(|_| panic!("the treasury pack builds"));
            let bare: Transaction = deserialize_hex(&unsigned_hex(&spend.tx)).unwrap();
            assert!(bare.input.iter().all(|i| i.witness.is_empty()));
            assert_eq!(bare.compute_txid(), spend.txid);
            let prevouts = prevouts_for(&spend.tx, &coins, &ext.script()).unwrap();
            assert_eq!(prevouts.len(), spend.tx.input.len());
            let doc = DREAMLAB.document().unwrap();
            // an answer that is still unsigned is refused
            assert!(accept_signed(&spend, &unsigned_hex(&spend.tx), &prevouts, &doc).is_err());
        }

        #[test]
        fn a_validly_signed_answer_is_accepted() {
            let (_, ext, spend) = built();
            assert_eq!(spend.tx.input.len(), 2);
            let prevouts = prevouts_for(&spend.tx, &coins(), &ext.script()).unwrap();
            let answer = serialize_hex(&sign(&spend.tx, &prevouts, &kp()));
            let signed =
                accept_signed(&spend, &answer, &prevouts, &DREAMLAB.document().unwrap()).unwrap();
            assert_eq!(signed.txid, spend.txid);
            assert_eq!(
                signed.vsize, spend.vsize,
                "the placeholder sized it exactly"
            );
        }

        #[test]
        fn swapped_signatures_are_refused() {
            let (_, ext, spend) = built();
            let prevouts = prevouts_for(&spend.tx, &coins(), &ext.script()).unwrap();
            let mut t = sign(&spend.tx, &prevouts, &kp());
            // same inputs in the same order, each carrying the other's signature
            let w0 = t.input[0].witness.clone();
            t.input[0].witness = t.input[1].witness.clone();
            t.input[1].witness = w0;
            assert!(accept_signed(
                &spend,
                &serialize_hex(&t),
                &prevouts,
                &DREAMLAB.document().unwrap()
            )
            .is_err());
        }

        #[test]
        fn another_keys_signature_is_refused() {
            let (_, ext, spend) = built();
            let prevouts = prevouts_for(&spend.tx, &coins(), &ext.script()).unwrap();
            let other =
                Keypair::from_secret_key(secp(), &SecretKey::from_slice(&[0x43; 32]).unwrap());
            let answer = serialize_hex(&sign(&spend.tx, &prevouts, &other));
            assert!(
                accept_signed(&spend, &answer, &prevouts, &DREAMLAB.document().unwrap()).is_err()
            );
        }

        #[test]
        fn a_different_transaction_is_refused_even_if_signed() {
            let (_, ext, spend) = built();
            let prevouts = prevouts_for(&spend.tx, &coins(), &ext.script()).unwrap();
            let mut other = spend.tx.clone();
            other.output[0].script_pubkey = ext.script(); // pays itself instead
            let answer = serialize_hex(&sign(&other, &prevouts, &kp()));
            let e = accept_signed(&spend, &answer, &prevouts, &DREAMLAB.document().unwrap())
                .unwrap_err();
            assert!(e.to_string().contains("different transaction"), "{e}");
        }

        #[test]
        fn a_coin_that_is_not_mine_has_no_prevout() {
            let (_, ext, spend) = built();
            assert!(prevouts_for(&spend.tx, &coins()[..1], &ext.script()).is_err());
        }
    }

    #[test]
    fn movement_nets_change_and_counts_the_fee() {
        let me = "5120".to_string() + &"aa".repeat(32);
        let them = "5120".to_string() + &"bb".repeat(32);
        let t = TxSummary {
            txid: "x".into(),
            height: 1,
            time: 0,
            ins: vec![Leg {
                script: me.clone(),
                sats: 1000,
                asset: 100,
            }],
            outs: vec![
                Leg {
                    script: them.clone(),
                    sats: 330,
                    asset: 40,
                },
                Leg {
                    script: me.clone(),
                    sats: 330,
                    asset: 60,
                },
                Leg {
                    script: me.clone(),
                    sats: 140,
                    asset: 0,
                },
            ],
            tip_event: None,
            hand_root: None,
            broken: None,
            coinbase: false,
        };
        let m = t.movement(&me);
        assert_eq!(m.asset, -40);
        assert_eq!(m.sats, -530);
        assert_eq!(m.counterparty.as_deref(), Some(them.as_str()));
        let r = t.movement(&them);
        assert_eq!((r.asset, r.sats), (40, 330));
        assert_eq!(r.counterparty.as_deref(), Some(me.as_str()));
    }
}
