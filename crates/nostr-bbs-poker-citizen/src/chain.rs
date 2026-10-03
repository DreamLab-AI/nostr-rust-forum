//! The chain half of the house: replay the producer's block file into a
//! validated view, read DREAM balances, spot `hand:<root>` transfers paid to
//! the house, and build the house's own settlement transfers.
//!
//! The lock is the forum client's (ADR-2015): one chain, `sidestr:dreamlab`
//! beside testnet4, and one asset, DREAM. The producer's `chain.json` is
//! accepted only if it names them.

use std::collections::{BTreeMap, HashSet};

use bitcoin::{OutPoint, Script, ScriptBuf, Txid};
use sidestr_agent::{AgentKey, ChainView};
use sidestr_core::assets::AssetView;
use sidestr_core::document::ChainDocument;
use sidestr_core::records::records_of;
use sidestr_core::state::State;
use sidestr_nostr::tx::sign_transaction_event;
use sidestr_wallet::asset::{build_transfer, TransferRequest};
use sidestr_wallet::coins::Coin;
use sidestr_wallet::spend::Spend;
use sidestr_wallet::Permissive;

/// The chain id.
pub const CHAIN_ID: &str = "sidestr:dreamlab";
/// The parent: Bitcoin testnet4.
pub const PARENT: &str = "tbtc4";
/// The genesis the document seals.
pub const GENESIS_HASH: &str = "4db37517728bd509c0cb96ee5a2e3e2a77f9e965a092e9f67948b413d453dbc0";
/// DREAM: `issue:DREAM:0` at block 372, supply 1,000,000.
pub const DREAM_ASSET_ID: &str = "608005d32a927de46e92f01b7948feac3469411cc0fbcfb1336e4eff49b978a9";

/// DREAM's asset id.
pub fn dream_id() -> Txid {
    DREAM_ASSET_ID
        .parse()
        .expect("the pinned DREAM id is a txid")
}

/// The script a Nostr key's coins pay: `OP_1 <x-only key>`.
pub fn script_of(pubkey_hex: &str) -> Option<ScriptBuf> {
    let pk = pubkey_hex.trim().to_ascii_lowercase();
    if pk.len() != 64 || !pk.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    ScriptBuf::from_hex(&format!("5120{pk}")).ok()
}

/// The chain document, checked against the lock.
pub fn check_document(json: &str) -> Result<ChainDocument, String> {
    let doc = ChainDocument::from_json(json).map_err(|e| format!("chain document: {e}"))?;
    if doc.id != CHAIN_ID || doc.parent != PARENT {
        return Err(format!(
            "the producer serves {} beside {}, not {CHAIN_ID} beside {PARENT}",
            doc.id, doc.parent
        ));
    }
    if doc.genesis_hash.as_deref() != Some(GENESIS_HASH) {
        return Err("the producer's chain does not seal the locked genesis".into());
    }
    Ok(doc)
}

/// The chain as one replay left it, plus what the house reads from it.
pub struct Facts {
    /// The validated chain and its assets view.
    pub view: ChainView,
    /// DREAM paid with a `hand:<root>` record: root → recipient pubkey →
    /// units. Recipients are members and the house alike, so a hand two
    /// members played is seen settled too.
    pub hand_payments: BTreeMap<String, BTreeMap<String, u64>>,
    /// Every transaction id on the chain.
    pub txids: HashSet<String>,
}

impl std::fmt::Debug for Facts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Facts")
            .field("height", &self.view.state.height())
            .field("hand_payments", &self.hand_payments.len())
            .finish_non_exhaustive()
    }
}

/// The Nostr key a `5120<key>` script pays, if it is one.
pub fn pubkey_of_script(script: &Script) -> Option<String> {
    let b = script.as_bytes();
    (b.len() == 34 && b[0] == 0x51 && b[1] == 0x20).then(|| hex::encode(&b[2..]))
}

/// Replay a block file against `doc`, reading every `hand:<root>` payment.
/// `now` is the clock for the future-time rule.
pub fn scan(doc: ChainDocument, dat: &[u8], now: Option<u32>) -> Result<Facts, String> {
    let dream = dream_id();
    let mut assets = AssetView::new();
    let mut hand_payments: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    let mut txids = HashSet::new();
    let state = State::replay_with(doc, dat, now, |_, height, block| {
        let outcomes = assets.apply_transactions(&block.txdata, height);
        for tx in &block.txdata {
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
            // output 0 is the recipient's carrier (the transfer builder's
            // shape); any later output to a different key is change, so
            // only the first carrier of each key counts
            let payer: Option<String> = tx.output.iter().enumerate().skip(1).find_map(|(v, o)| {
                outcome
                    .carried_out
                    .get(&(v as u32))
                    .and_then(|c| c.get(&dream))
                    .filter(|&&n| n > 0)
                    .and_then(|_| pubkey_of_script(&o.script_pubkey))
            });
            for (v, o) in tx.output.iter().enumerate() {
                let units = outcome
                    .carried_out
                    .get(&(v as u32))
                    .and_then(|c| c.get(&dream))
                    .copied()
                    .unwrap_or(0);
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
    Ok(Facts {
        view: ChainView { state, assets },
        hand_payments,
        txids,
    })
}

impl Facts {
    /// DREAM a key holds.
    pub fn dream_of(&self, pubkey_hex: &str) -> u64 {
        script_of(pubkey_hex)
            .map(|s| self.view.asset_balance(&s, &dream_id()))
            .unwrap_or(0)
    }

    /// DREAM a script holds, less coins `held` by transfers not yet mined.
    pub fn dream_of_script(&self, script: &Script, held: &[OutPoint]) -> u64 {
        let dream = dream_id();
        self.view
            .coins(script)
            .iter()
            .filter(|c| !held.contains(&c.outpoint))
            .filter_map(|c| self.view.assets.carried(&c.outpoint))
            .filter_map(|carry| carry.get(&dream))
            .sum()
    }

    /// The tip height.
    pub fn height(&self) -> u32 {
        self.view.state.height()
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

/// Build the house's transfer of `amount` DREAM to `to_pubkey` for the hand
/// `root`, from the house's coins less `held` (spent by transfers the chain
/// has not shown yet). Checked against the assets view before it is signed.
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
        .view
        .coins(&me)
        .into_iter()
        .filter(|c| !held.contains(&c.outpoint))
        .collect();
    let chain = facts.view.state.document();
    let memos = vec![nostr_bbs_poker::rules::hand_memo(root)];
    let t = build_transfer(
        &TransferRequest {
            chain,
            coins: &coins,
            view: &facts.view.assets,
            tip_height: facts.height(),
            asset: dream_id(),
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
        .view
        .assets
        .check(&t.spend.tx, &mut carried_in)
        .map_err(|e| format!("the transfer would break the DREAM rule: {e}"))?;
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

    #[test]
    fn scripts_and_the_lock() {
        let pk = "a".repeat(64);
        assert_eq!(script_of(&pk).unwrap().to_hex_string(), format!("5120{pk}"));
        assert_eq!(
            pubkey_of_script(&script_of(&pk).unwrap()).as_deref(),
            Some(pk.as_str())
        );
        assert!(script_of("abc").is_none());
        assert_eq!(dream_id().to_string(), DREAM_ASSET_ID);
        let other = r#"{"id":"sidestr:other","name":"other","parent":"tbtc4","challenge":"5120aa","powLimit":"7f","addressPrefix":"oth","pegConfirmations":6,"refundBlocks":10,"pegoutBlocks":1,"pegoutMin":1,"minFeeRate":1,"genesisHash":"00"}"#;
        let e = check_document(other).unwrap_err();
        assert!(
            e.contains("sidestr:other") || e.contains("chain document"),
            "{e}"
        );
    }
}
