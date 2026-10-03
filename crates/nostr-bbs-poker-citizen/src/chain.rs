//! The chain half of the house: replay the producer's block file into a
//! validated view, read balances of the table's asset, spot `hand:<root>`
//! transfers, and build the house's own settlement transfers.
//!
//! The locks are the forum client's (ADR-2015, ADR-2021): two chains, both
//! sealed documents compiled in ([`PINS`]) — `sidestr:dreamlab` beside
//! testnet4, whose asset is DREAM, and `sidestr:dreamlab-txbt4` beside
//! BLAKE2b testnet4, whose asset (BLAKES7) the operator names by id. One
//! house seat serves one chain and one asset, chosen at start
//! (`--chain-id`, `--asset-id`). The producer's `chain.json` is accepted
//! only if it is exactly that chain's pinned document ([`check_document`]),
//! and every block is replayed against the compiled copy under the header
//! family its parent hands down.

use std::collections::{BTreeMap, HashSet};

use bitcoin::{OutPoint, Script, ScriptBuf, Txid};
use sidestr_agent::AgentKey;
use sidestr_core::assets::AssetView;
use sidestr_core::block::{HeaderFamily, SidestrBlock};
use sidestr_core::document::ChainDocument;
use sidestr_core::records::records_of;
use sidestr_core::{Family, State, StateOf, Stock};
use sidestr_header::Blake2bV2;
use sidestr_nostr::tx::sign_transaction_event;
use sidestr_wallet::asset::{build_transfer, TransferRequest};
use sidestr_wallet::coins::Coin;
use sidestr_wallet::spend::Spend;
use sidestr_wallet::Permissive;

/// The first chain's id.
pub const CHAIN_ID: &str = "sidestr:dreamlab";
/// Its parent: Bitcoin testnet4.
pub const PARENT: &str = "tbtc4";
/// The genesis its document seals.
pub const GENESIS_HASH: &str = "4db37517728bd509c0cb96ee5a2e3e2a77f9e965a092e9f67948b413d453dbc0";
/// DREAM: `issue:DREAM:0` at block 372, supply 1,000,000.
pub const DREAM_ASSET_ID: &str = "608005d32a927de46e92f01b7948feac3469411cc0fbcfb1336e4eff49b978a9";

/// The second chain's id.
pub const TXBT4_CHAIN_ID: &str = "sidestr:dreamlab-txbt4";
/// Its parent: BLAKE2b testnet4.
pub const TXBT4_PARENT: &str = "txbt4";
/// The genesis its document seals.
pub const TXBT4_GENESIS_HASH: &str =
    "1009aa2984d5c699fe61ef1e5905afe472a49d67551542045726828c8b82d108";

/// One compiled-in chain lock.
#[derive(Debug, PartialEq, Eq)]
pub struct Pin {
    /// The chain id.
    pub id: &'static str,
    /// The parent alias the document must name.
    pub parent: &'static str,
    /// The genesis the document must seal.
    pub genesis_hash: &'static str,
    /// The sealed document, as the producer serves it.
    pub json: &'static str,
    /// The asset's id when it was issued before this build (`--asset-id`
    /// defaults to it).
    pub asset_id: Option<&'static str>,
    /// The asset's ticker when the id is compiled in (`--ticker` defaults to it).
    pub ticker: Option<&'static str>,
}

/// `sidestr:dreamlab`, DREAM.
pub const DREAMLAB: Pin = Pin {
    id: CHAIN_ID,
    parent: PARENT,
    genesis_hash: GENESIS_HASH,
    json: include_str!("sidestr-dreamlab.chain.json"),
    asset_id: Some(DREAM_ASSET_ID),
    ticker: Some("DREAM"),
};

/// `sidestr:dreamlab-txbt4`, whose asset is named at start.
pub const DREAMLAB_TXBT4: Pin = Pin {
    id: TXBT4_CHAIN_ID,
    parent: TXBT4_PARENT,
    genesis_hash: TXBT4_GENESIS_HASH,
    json: include_str!("sidestr-dreamlab-txbt4.chain.json"),
    asset_id: None,
    ticker: None,
};

/// Every chain a house seat will serve.
pub const PINS: [&Pin; 2] = [&DREAMLAB, &DREAMLAB_TXBT4];

/// The pin of a chain id, if it is one of [`PINS`].
pub fn pin(id: &str) -> Option<&'static Pin> {
    PINS.into_iter().find(|p| p.id == id)
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// An asset id from its hex (64 hex digits, any case).
pub fn parse_asset(hex_id: &str) -> Result<Txid, String> {
    let t = hex_id.trim();
    if !is_hex64(t) {
        return Err(format!("{t:?} is not an asset id (64 hex digits)"));
    }
    t.to_ascii_lowercase()
        .parse()
        .map_err(|e| format!("{t:?} is not an asset id: {e}"))
}

/// What one house seat serves: a pinned chain, its asset, and the ticker
/// members read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Served {
    /// The chain's lock.
    pub pin: &'static Pin,
    /// The asset the table settles in.
    pub asset: Txid,
    /// The asset's ticker.
    pub ticker: String,
}

/// The chain, asset and ticker a house seat serves, from `--chain-id`,
/// `--asset-id` and `--ticker`: the chain must be pinned; the asset id and
/// ticker default to the pin's (DREAM on `sidestr:dreamlab`) and are
/// required where the pin has none.
pub fn select(
    chain_id: &str,
    asset_id: Option<&str>,
    ticker: Option<&str>,
) -> Result<Served, String> {
    let chain_id = chain_id.trim();
    let pin = pin(chain_id).ok_or_else(|| {
        format!(
            "--chain-id {chain_id:?} is not a pinned chain (one of {})",
            PINS.map(|p| p.id).join(", ")
        )
    })?;
    let asset = match asset_id.or(pin.asset_id) {
        Some(a) => parse_asset(a).map_err(|e| format!("--asset-id: {e}"))?,
        None => return Err(format!("--asset-id is required on {}", pin.id)),
    };
    let ticker = match ticker.map(str::trim).or(pin.ticker) {
        Some(t) if (1..=16).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_alphanumeric()) => {
            t.to_string()
        }
        Some(t) => return Err(format!("--ticker {t:?} is not 1-16 letters and digits")),
        None => return Err(format!("--ticker is required on {}", pin.id)),
    };
    Ok(Served { pin, asset, ticker })
}

impl Pin {
    /// The compiled document, checked against the lock.
    pub fn document(&self) -> Result<ChainDocument, String> {
        lock(self, self.json)
    }
}

/// A document parsed and held to `pin`'s id, parent and genesis.
fn lock(pin: &Pin, json: &str) -> Result<ChainDocument, String> {
    let doc = ChainDocument::from_json(json).map_err(|e| format!("chain document: {e}"))?;
    if doc.id != pin.id || doc.parent != pin.parent {
        return Err(format!(
            "the producer serves {} beside {}, not {} beside {}",
            doc.id, doc.parent, pin.id, pin.parent
        ));
    }
    if doc.genesis_hash.as_deref() != Some(pin.genesis_hash) {
        return Err(format!(
            "the producer's chain does not seal {}'s locked genesis",
            pin.id
        ));
    }
    Ok(doc)
}

/// The producer's chain document, accepted only if it is `pin`'s chain (id,
/// parent, genesis) and, field for field, the sealed document compiled in.
/// What is returned is the compiled copy.
pub fn check_document(pin: &Pin, json: &str) -> Result<ChainDocument, String> {
    let served = lock(pin, json)?;
    let sealed = pin.document()?;
    if served != sealed {
        return Err(format!(
            "the producer's {} document differs from the sealed one",
            pin.id
        ));
    }
    Ok(sealed)
}

/// The script a Nostr key's coins pay: `OP_1 <x-only key>`.
pub fn script_of(pubkey_hex: &str) -> Option<ScriptBuf> {
    let pk = pubkey_hex.trim().to_ascii_lowercase();
    if !is_hex64(&pk) {
        return None;
    }
    ScriptBuf::from_hex(&format!("5120{pk}")).ok()
}

/// The validated chain state, under the header family its parent hands down.
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

    /// The coins a script holds at the tip.
    pub fn coins(&self, script: &Script) -> Vec<Coin> {
        match self {
            Self::Stock(s) => sidestr_wallet::coins::from_state(s, script),
            Self::Blake2b(s) => sidestr_wallet::coins::from_state(s, script),
        }
    }
}

/// The chain as one replay left it, plus what the house reads from it.
pub struct Facts {
    /// The validated chain.
    pub state: ChainState,
    /// What each unspent output carries.
    pub assets: AssetView,
    /// The asset the table settles in.
    pub asset: Txid,
    /// The asset paid with a `hand:<root>` record: root → recipient pubkey →
    /// units. Recipients are members and the house alike, so a hand two
    /// members played is seen settled too.
    pub hand_payments: BTreeMap<String, BTreeMap<String, u64>>,
    /// Every transaction id on the chain.
    pub txids: HashSet<String>,
}

impl std::fmt::Debug for Facts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Facts")
            .field("chain", &self.state.document().id)
            .field("height", &self.height())
            .field("hand_payments", &self.hand_payments.len())
            .finish_non_exhaustive()
    }
}

/// The Nostr key a `5120<key>` script pays, if it is one.
pub fn pubkey_of_script(script: &Script) -> Option<String> {
    let b = script.as_bytes();
    (b.len() == 34 && b[0] == 0x51 && b[1] == 0x20).then(|| hex::encode(&b[2..]))
}

/// Replay a block file against `doc` (one of the pinned documents), reading
/// every `hand:<root>` payment of `asset`. `now` is the clock for the
/// future-time rule.
pub fn scan(
    doc: ChainDocument,
    asset: Txid,
    dat: &[u8],
    now: Option<u32>,
) -> Result<Facts, String> {
    let family = doc.family().map_err(|e| format!("chain document: {e}"))?;
    let (state, assets, hand_payments, txids) = match family {
        Family::Stock => {
            let (s, a, h, t) = scan_in::<Stock>(doc, &asset, dat, now)?;
            (ChainState::Stock(s), a, h, t)
        }
        Family::Blake2b => {
            let (s, a, h, t) = scan_in::<Blake2bV2>(doc, &asset, dat, now)?;
            (ChainState::Blake2b(s), a, h, t)
        }
    };
    Ok(Facts {
        state,
        assets,
        asset,
        hand_payments,
        txids,
    })
}

type Scanned<F> = (
    StateOf<F>,
    AssetView,
    BTreeMap<String, BTreeMap<String, u64>>,
    HashSet<String>,
);

fn scan_in<F: HeaderFamily>(
    doc: ChainDocument,
    asset: &Txid,
    dat: &[u8],
    now: Option<u32>,
) -> Result<Scanned<F>, String> {
    let mut assets = AssetView::new();
    let mut hand_payments: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    let mut txids = HashSet::new();
    let state = StateOf::<F>::replay_with(doc, dat, now, |_, height, block| {
        let txdata = block.txdata();
        let outcomes = assets.apply_transactions(txdata, height);
        for tx in txdata {
            let txid = tx.compute_txid();
            txids.insert(txid.to_string());
            let Some(root) = records_of(tx)
                .into_iter()
                .find_map(|(_, t)| nostr_bbs_poker::rules::parse_hand_memo(&t).map(str::to_string))
            else {
                continue;
            };
            let Some(outcome) = outcomes.iter().find(|o| o.txid == txid) else {
                continue;
            };
            if outcome.error.is_some() {
                continue;
            }
            let carried = |v: usize| {
                outcome
                    .carried_out
                    .get(&(v as u32))
                    .and_then(|c| c.get(asset))
                    .copied()
                    .unwrap_or(0)
            };
            // output 0 is the recipient's carrier (the transfer builder's
            // shape); any later output to a different key is change, so
            // only the first carrier of each key counts
            let payer: Option<String> = tx
                .output
                .iter()
                .enumerate()
                .skip(1)
                .find(|(v, _)| carried(*v) > 0)
                .and_then(|(_, o)| pubkey_of_script(&o.script_pubkey));
            for (v, o) in tx.output.iter().enumerate() {
                let units = carried(v);
                let Some(to) = pubkey_of_script(&o.script_pubkey) else {
                    continue;
                };
                if units == 0 || Some(&to) == payer.as_ref() && v > 0 {
                    continue;
                }
                *hand_payments
                    .entry(root.clone())
                    .or_default()
                    .entry(to)
                    .or_default() += units;
            }
        }
    })
    .map_err(|e| format!("the producer's blocks do not validate: {e}"))?;
    Ok((state, assets, hand_payments, txids))
}

impl Facts {
    /// Units of the table's asset a key holds.
    pub fn units_of(&self, pubkey_hex: &str) -> u64 {
        script_of(pubkey_hex)
            .map(|s| self.units_of_script(&s, &[]))
            .unwrap_or(0)
    }

    /// Units of the table's asset a script holds, less coins `held` by
    /// transfers not yet mined.
    pub fn units_of_script(&self, script: &Script, held: &[OutPoint]) -> u64 {
        self.state
            .coins(script)
            .iter()
            .filter(|c| !held.contains(&c.outpoint))
            .filter_map(|c| self.assets.carried(&c.outpoint))
            .filter_map(|carry| carry.get(&self.asset))
            .sum()
    }

    /// Whether the chain shows the asset's issue.
    pub fn asset_issued(&self) -> bool {
        self.assets.issued().contains_key(&self.asset)
    }

    /// The tip height.
    pub fn height(&self) -> u32 {
        self.state.height()
    }
}

/// A settlement transfer, signed, and the event that carries it.
#[derive(Debug, Clone)]
pub struct Payment {
    /// The signed spend: output 0 is the member's carrier.
    pub spend: Spend,
    /// The kind-23500 event, signed by the house key.
    pub event: sidestr_nostr::event::Event,
}

/// Build the house's transfer of `amount` units of the table's asset to
/// `to_pubkey` for the hand `root`, from the house's coins less `held`
/// (spent by transfers the chain has not shown yet). Checked against the
/// assets view before it is signed.
pub fn build_payment(
    key: &AgentKey,
    facts: &Facts,
    held: &[OutPoint],
    to_pubkey: &str,
    amount: u64,
    root: &str,
    now: u64,
) -> Result<Payment, String> {
    let to = script_of(to_pubkey).ok_or("the member's pubkey is not 64 hex characters")?;
    let me = key.script();
    if to == me {
        return Err("the house would pay itself".into());
    }
    let coins: Vec<Coin> = facts
        .state
        .coins(&me)
        .into_iter()
        .filter(|c| !held.contains(&c.outpoint))
        .collect();
    let chain = facts.state.document();
    let memos = vec![nostr_bbs_poker::rules::hand_memo(root)];
    let t = build_transfer(
        &TransferRequest {
            chain,
            coins: &coins,
            view: &facts.assets,
            tip_height: facts.height(),
            asset: facts.asset,
            to: &to.to_hex_string(),
            amount,
            memos: &memos,
            fee: None,
        },
        &key.spend_signer(),
        &Permissive,
    )
    .map_err(|e| e.to_string())?;
    let mut carried_in = Default::default();
    facts
        .assets
        .check(&t.spend.tx, &mut carried_in)
        .map_err(|e| format!("the transfer would break the assets rule: {e}"))?;
    let event = sign_transaction_event(&key.event_signer(), &chain.id, &t.spend.hex, now)
        .map_err(|e| e.to_string())?;
    Ok(Payment {
        spend: t.spend,
        event,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DREAMLAB_BLOCKS: &[u8] = include_bytes!("testdata/dreamlab-blocks.dat");
    const TXBT4_BLOCKS: &[u8] = include_bytes!("testdata/txbt4-blocks.dat");

    #[test]
    fn scripts_and_the_locks() {
        let pk = "a".repeat(64);
        assert_eq!(script_of(&pk).unwrap().to_hex_string(), format!("5120{pk}"));
        assert_eq!(
            pubkey_of_script(&script_of(&pk).unwrap()).as_deref(),
            Some(pk.as_str())
        );
        assert!(script_of("abc").is_none());
        assert_eq!(
            parse_asset(DREAM_ASSET_ID).unwrap().to_string(),
            DREAM_ASSET_ID
        );
        assert!(parse_asset("xyz").is_err());
        for p in PINS {
            let doc = p.document().unwrap();
            assert_eq!((doc.id.as_str(), doc.parent.as_str()), (p.id, p.parent));
            assert_eq!(pin(p.id), Some(p));
            // the producer serving the sealed document is accepted
            assert_eq!(check_document(p, p.json).unwrap(), doc);
        }
        assert_eq!(pin("sidestr:other"), None);
        let other = r#"{"id":"sidestr:other","name":"other","parent":"tbtc4","challenge":"5120aa","powLimit":"7f","addressPrefix":"oth","pegConfirmations":6,"refundBlocks":10,"pegoutBlocks":1,"pegoutMin":1,"minFeeRate":1,"genesisHash":"00"}"#;
        let e = check_document(&DREAMLAB, other).unwrap_err();
        assert!(
            e.contains("sidestr:other") || e.contains("chain document"),
            "{e}"
        );
    }

    #[test]
    fn the_flags_choose_a_pinned_chain_and_its_asset() {
        // the defaults are today's house seat
        let d = select(CHAIN_ID, None, None).unwrap();
        assert_eq!(
            (d.pin, d.asset.to_string().as_str(), d.ticker.as_str()),
            (&DREAMLAB, DREAM_ASSET_ID, "DREAM")
        );
        // the second chain needs both, and takes them
        let id = "07".repeat(32);
        assert!(select(TXBT4_CHAIN_ID, None, Some("BLAKES7"))
            .unwrap_err()
            .contains("--asset-id is required"));
        assert!(select(TXBT4_CHAIN_ID, Some(&id), None)
            .unwrap_err()
            .contains("--ticker is required"));
        let t = select(
            TXBT4_CHAIN_ID,
            Some(&id.to_ascii_uppercase()),
            Some("BLAKES7"),
        )
        .unwrap();
        assert_eq!(
            (t.pin, t.asset.to_string(), t.ticker.as_str()),
            (&DREAMLAB_TXBT4, id.clone(), "BLAKES7")
        );
        // nothing unpinned, nothing malformed
        assert!(select("sidestr:melchain", Some(&id), Some("X"))
            .unwrap_err()
            .contains("not a pinned chain"));
        assert!(select(CHAIN_ID, Some("nope"), None).is_err());
        assert!(select(CHAIN_ID, None, Some("DRE AM")).is_err());
    }

    /// A producer serving the other chain, or the right chain with any field
    /// changed, is refused.
    #[test]
    fn a_producer_document_that_is_not_the_sealed_one_is_refused() {
        assert!(check_document(&DREAMLAB, DREAMLAB_TXBT4.json).is_err());
        assert!(check_document(&DREAMLAB_TXBT4, DREAMLAB.json).is_err());
        let genesis = DREAMLAB_TXBT4
            .json
            .replace(TXBT4_GENESIS_HASH, &"00".repeat(32));
        assert!(check_document(&DREAMLAB_TXBT4, &genesis)
            .unwrap_err()
            .contains("genesis"));
        // same id, parent and genesis, another fee rule: not the sealed chain
        let fee = DREAMLAB_TXBT4
            .json
            .replace(r#""minFeeRate":1"#, r#""minFeeRate":2"#);
        assert_ne!(fee, DREAMLAB_TXBT4.json);
        assert!(check_document(&DREAMLAB_TXBT4, &fee)
            .unwrap_err()
            .contains("differs"));
    }

    #[test]
    fn each_chain_scans_under_its_own_family() {
        let dream = parse_asset(DREAM_ASSET_ID).unwrap();
        let facts = scan(DREAMLAB.document().unwrap(), dream, DREAMLAB_BLOCKS, None).unwrap();
        assert!(matches!(facts.state, ChainState::Stock(_)));
        assert!(facts.height() >= 372 && facts.asset_issued());
        assert!(
            facts.units_of("f6b84686a2323a233e99c60ed79a59d3ec45289fec58a4c359997e551b0326b0") > 0
        );
        let blakes7 = parse_asset(&"07".repeat(32)).unwrap();
        let facts = scan(
            DREAMLAB_TXBT4.document().unwrap(),
            blakes7,
            TXBT4_BLOCKS,
            None,
        )
        .unwrap();
        assert!(matches!(facts.state, ChainState::Blake2b(_)));
        assert!(facts.height() >= 26);
        assert!(!facts.asset_issued());
        // each chain's blocks fail the other's document
        assert!(scan(DREAMLAB.document().unwrap(), dream, TXBT4_BLOCKS, None).is_err());
        assert!(scan(
            DREAMLAB_TXBT4.document().unwrap(),
            blakes7,
            DREAMLAB_BLOCKS,
            None
        )
        .is_err());
    }
}
