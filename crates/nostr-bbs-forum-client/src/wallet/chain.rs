//! The chain half of the member wallet, pure and natively testable: the
//! compiled-in chain lock, the replay of a mirror's block file into a
//! snapshot, and what the UI reads from a snapshot (balances, a member's
//! activity, the DREAM tipped on each post).
//!
//! **The lock (ADR-2015).** The wallet knows exactly one chain and one
//! asset, both compiled in: `sidestr:dreamlab`, beside Bitcoin testnet4
//! (`parent: tbtc4`), and DREAM, the asset issued on it at
//! [`DREAM_ASSET_ID`]. Runtime config can switch the wallet on and point it
//! at another mirror or other relays; it cannot point it at another chain.
//! A mirror is never trusted: every block it serves is validated against the
//! pinned document ([`sidestr_core::mirror`]), so a bad mirror can be stale
//! or empty but cannot invent a balance.

use std::collections::HashMap;

use bitcoin::{OutPoint, Script, ScriptBuf, Txid};
use sidestr_agent::ChainView;
use sidestr_core::assets::AssetView;
use sidestr_core::document::ChainDocument;
use sidestr_core::records::records_of;
use sidestr_core::state::State;
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
/// The relays the producer and the faucet follow (siding's five defaults).
pub const DEFAULT_RELAYS: [&str; 5] = [
    "wss://nos.lol",
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://nostr.mom",
    "wss://nostr.oxtr.dev",
];
/// The memo a tip carries beside its tally: `tip:nostr:<event id>`.
pub const TIP_PREFIX: &str = "tip:nostr:";

/// The pinned chain document, checked against the lock.
pub fn document() -> Result<ChainDocument, String> {
    let doc = ChainDocument::from_json(CHAIN_JSON).map_err(|e| format!("chain document: {e}"))?;
    if doc.id != CHAIN_ID || doc.parent != PARENT {
        return Err("the pinned chain is not sidestr:dreamlab beside testnet4".into());
    }
    if doc.genesis_hash.as_deref() != Some(GENESIS_HASH) {
        return Err("the pinned chain's genesis is not the locked one".into());
    }
    Ok(doc)
}

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

/// A script from its hex.
pub fn script_of_hex(hex_script: &str) -> Option<ScriptBuf> {
    ScriptBuf::from_hex(hex_script).ok()
}

/// The Nostr key a `5120<key>` script pays, if it is one.
pub fn pubkey_of_script(script: &Script) -> Option<String> {
    let b = script.as_bytes();
    (b.len() == 34 && b[0] == 0x51 && b[1] == 0x20).then(|| hex::encode(&b[2..]))
}

/// One side of a transaction as a wallet reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leg {
    /// The script, hex.
    pub script: String,
    /// Sats.
    pub sats: u64,
    /// DREAM carried.
    pub dream: u64,
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
    /// Set when the assets rule reads it as broken: DREAM it touched is gone.
    pub broken: Option<String>,
    /// A block's coinbase: a peg-in claim or the producer's fees.
    pub coinbase: bool,
}

/// Tips on one post.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TipTotal {
    /// DREAM tipped.
    pub dream: u64,
    /// How many tips.
    pub count: u32,
}

/// The chain as one replay of the mirror left it.
pub struct Snapshot {
    /// The validated chain and its assets view.
    pub view: ChainView,
    /// Every transaction, oldest first.
    pub txs: Vec<TxSummary>,
    /// DREAM tipped per post, by event id.
    pub tips: HashMap<String, TipTotal>,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("height", &self.height())
            .field("txs", &self.txs.len())
            .finish_non_exhaustive()
    }
}

fn leg_of(view: &AssetView, op: &OutPoint, script: &Script, sats: u64, dream: &Txid) -> Leg {
    Leg {
        script: script.to_hex_string(),
        sats,
        dream: view
            .carried(op)
            .and_then(|c| c.get(dream))
            .copied()
            .unwrap_or(0),
    }
}

/// Replay a mirror's `blocks.dat` against the pinned document. `now` is the
/// clock for the future-time rule.
pub fn replay(dat: &[u8], now: Option<u32>) -> Result<Snapshot, String> {
    let doc = document()?;
    let dream = dream_id();
    let mut assets = AssetView::new();
    let mut txs = Vec::new();
    let mut tips: HashMap<String, TipTotal> = HashMap::new();
    let state = State::replay_with(doc, dat, now, |before, height, block| {
        let time = block.header.time;
        // inputs are read before the block is applied (afterwards they are
        // gone); one that spends an output of an earlier transaction in the
        // same block is resolved from that transaction once the block is read
        let mut spent: Vec<Vec<Option<Leg>>> = block
            .txdata
            .iter()
            .map(|tx| {
                tx.input
                    .iter()
                    .map(|i| {
                        let c = before?.utxo().get(&i.previous_output)?;
                        Some(leg_of(
                            &assets,
                            &i.previous_output,
                            &c.output.script_pubkey,
                            c.output.value.to_sat(),
                            &dream,
                        ))
                    })
                    .collect()
            })
            .collect();
        let outcomes = assets.apply_transactions(&block.txdata, height);
        let ids: Vec<Txid> = block.txdata.iter().map(|t| t.compute_txid()).collect();
        for (ti, tx) in block.txdata.iter().enumerate() {
            for (ii, inp) in tx.input.iter().enumerate() {
                if spent[ti][ii].is_some() {
                    continue;
                }
                let op = inp.previous_output;
                let Some(src) = ids[..ti].iter().position(|t| *t == op.txid) else {
                    continue;
                };
                let Some(o) = block.txdata[src].output.get(op.vout as usize) else {
                    continue;
                };
                let carried = outcomes
                    .iter()
                    .find(|oc| oc.txid == op.txid)
                    .and_then(|oc| oc.carried_out.get(&op.vout))
                    .and_then(|c| c.get(&dream))
                    .copied()
                    .unwrap_or(0);
                spent[ti][ii] = Some(Leg {
                    script: o.script_pubkey.to_hex_string(),
                    sats: o.value.to_sat(),
                    dream: carried,
                });
            }
        }
        let spent: Vec<Vec<Leg>> = spent
            .into_iter()
            .map(|v| v.into_iter().flatten().collect())
            .collect();
        for (i, tx) in block.txdata.iter().enumerate() {
            let txid = tx.compute_txid();
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
                    dream: outcome
                        .and_then(|oc| oc.carried_out.get(&(v as u32)))
                        .and_then(|c| c.get(&dream))
                        .copied()
                        .unwrap_or(0),
                })
                .collect();
            let tip_event = records_of(tx).into_iter().find_map(|(_, t)| {
                t.strip_prefix(TIP_PREFIX)
                    .filter(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
                    .map(str::to_ascii_lowercase)
            });
            // a tip counts what output 0 carries of DREAM, when the rule held
            if let (Some(ev), None) = (&tip_event, &broken) {
                let n = outs.first().map(|l| l.dream).unwrap_or(0);
                if n > 0 {
                    let t = tips.entry(ev.clone()).or_default();
                    t.dream += n;
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
                broken,
                coinbase,
            });
        }
    })
    .map_err(|e| format!("the mirror's blocks do not validate: {e}"))?;
    Ok(Snapshot {
        view: ChainView { state, assets },
        txs,
        tips,
    })
}

/// A member's balances.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Balances {
    /// DREAM held.
    pub dream: u64,
    /// Sats on coins that carry nothing: what pays fees.
    pub plain: u64,
    /// Sats riding on DREAM carriers.
    pub carrier_sats: u64,
}

impl Snapshot {
    /// The tip height.
    pub fn height(&self) -> u32 {
        self.view.state.height()
    }

    /// The tip block's time.
    pub fn tip_time(&self) -> u32 {
        self.view.state.tip().time
    }

    /// Coins a script holds, less any `held` (spent by a transaction not yet
    /// mined).
    pub fn coins(&self, script: &Script, held: &[OutPoint]) -> Vec<Coin> {
        self.view
            .coins(script)
            .into_iter()
            .filter(|c| !held.contains(&c.outpoint))
            .collect()
    }

    /// What a script holds.
    pub fn balances(&self, script: &Script, held: &[OutPoint]) -> Balances {
        let dream = dream_id();
        let mut b = Balances::default();
        for c in self.coins(script, held) {
            match self.view.assets.carried(&c.outpoint) {
                None => b.plain += c.value,
                Some(m) => {
                    b.dream += m.get(&dream).copied().unwrap_or(0);
                    b.carrier_sats += c.value;
                }
            }
        }
        b
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
        self.view.state.utxo().contains_key(op)
    }
}

/// How one transaction reads from one member's side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Movement {
    /// DREAM in (positive) or out (negative), net of change.
    pub dream: i64,
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
        let dream = sum(&self.outs, |l| l.dream) - sum(&self.ins, |l| l.dream);
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
            dream,
            sats,
            counterparty,
        }
    }
}

/// Where a payment goes, from what a member typed or picked: an npub, a
/// `did:nostr:`, 64-hex key, or a `drm1…` address. Secret-shaped text is
/// refused before anything else, without being echoed.
pub fn destination_script(text: &str) -> Result<ScriptBuf, String> {
    let t = sidestr_agent::refuse_secret(text.trim()).map_err(|e| e.to_string())?;
    let dest = sidestr_agent::destination(t).map_err(|e| e.to_string())?;
    let doc = document()?;
    sidestr_wallet::spend::resolve_to(&dest, &doc.address_prefix)
        .map(|r| r.script)
        .map_err(|e| e.to_string())
}

/// The `drm1…` address of a Nostr key.
pub fn address_of(pubkey_hex: &str) -> Option<String> {
    let doc = document().ok()?;
    let pk = sidestr_agent::parse_pubkey(pubkey_hex).ok()?;
    sidestr_agent::identity(&pk, &doc.address_prefix).map(|i| i.address)
}

/// Why a provision could not be built.
#[derive(Debug)]
pub enum ProvisionError {
    /// The wallet refused (not enough, dust, …).
    Wallet(sidestr_wallet::Error),
    /// Nothing to give, or a record that would not encode.
    Plain(String),
}

/// A starter pack in one transaction: `dream` on a carrier to `to` (with the
/// DREAM change on a carrier back), then `sats` to `to` as plain coins for
/// their fees. DREAM carriers are the required inputs; plain coins pay the
/// sats and the fee. Checked against the assets view before it is returned.
pub fn build_provision(
    snap: &Snapshot,
    coins: &[Coin],
    signer: &dyn sidestr_wallet::SpendSigner,
    to: &ScriptBuf,
    dream: u64,
    sats: u64,
) -> Result<sidestr_wallet::spend::Spend, ProvisionError> {
    use sidestr_wallet::asset::{sort_coins, CARRIER};
    use sidestr_wallet::compose::{build_outputs, OutputsRequest};
    let me = signer.script();
    let id = dream_id();
    let sorted = sort_coins(coins, &snap.view.assets, Some(&id));
    let mut required = Vec::new();
    let mut have = 0u64;
    if dream > 0 {
        let mut carriers = sorted.carriers.clone();
        carriers.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        for (c, n) in carriers {
            if have >= dream {
                break;
            }
            have += n;
            required.push(c);
        }
        if have < dream {
            return Err(ProvisionError::Plain(format!(
                "Not enough DREAM: you hold {have}, the pack gives {dream}."
            )));
        }
    }
    let mut outputs = Vec::new();
    let mut records = Vec::new();
    if dream > 0 {
        outputs.push((to.clone(), CARRIER));
        let mut assigns = vec![(0u32, dream)];
        if have > dream {
            outputs.push((me.clone(), CARRIER));
            assigns.push((1, have - dream));
        }
        records.push(
            sidestr_core::records::tally_text(Some(&id), &assigns)
                .map_err(|e| ProvisionError::Plain(e.to_string()))?,
        );
    }
    if sats > 0 {
        outputs.push((to.clone(), sats));
    }
    if outputs.is_empty() {
        return Err(ProvisionError::Plain(
            "Choose some DREAM or sats to give.".into(),
        ));
    }
    let spend = build_outputs(
        &OutputsRequest {
            chain: snap.view.state.document(),
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
    snap.view
        .assets
        .check(&spend.tx, &mut carried_in)
        .map_err(|e| ProvisionError::Plain(format!("the pack would break the DREAM rule: {e}")))?;
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

    #[test]
    fn the_lock_holds_the_pinned_document() {
        let doc = document().unwrap();
        assert_eq!(doc.id, CHAIN_ID);
        assert_eq!(doc.address_prefix, "drm");
        assert_eq!(dream_id().to_string(), DREAM_ASSET_ID);
    }

    #[test]
    fn scripts_and_keys_round_trip() {
        let pk = "11ed64225dd5e2c5e18f61ad43d5ad9272d08739d3a20dd25886197b0738663c";
        let s = script_of(pk).unwrap();
        assert_eq!(pubkey_of_script(&s).as_deref(), Some(pk));
        assert!(script_of("nope").is_none());
        assert!(address_of(pk).unwrap().starts_with("drm1p"));
        assert_eq!(destination_script(&format!("did:nostr:{pk}")).unwrap(), s);
        assert_eq!(destination_script(&address_of(pk).unwrap()).unwrap(), s);
    }

    #[test]
    fn a_secret_is_never_a_destination() {
        let e =
            destination_script("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5")
                .unwrap_err();
        assert!(!e.contains("vl029"), "the secret is echoed: {e}");
    }

    #[test]
    fn an_empty_or_foreign_block_file_is_refused() {
        assert!(replay(&[], None).is_err());
        assert!(replay(&[0u8; 12], None).is_err());
    }

    /// The live chain as the producer served it after DREAM was issued
    /// (block 372) and the treasury funded: the whole replay, the lock, the
    /// supply where it was minted.
    #[test]
    fn the_live_chain_replays_with_dream_at_the_treasury() {
        let snap = replay(include_bytes!("testdata/blocks.dat"), None).unwrap();
        assert!(snap.height() >= 372);
        let issued = &snap.view.assets.issued()[&dream_id()];
        assert_eq!(
            (issued.ticker.as_str(), issued.supply, issued.height),
            ("DREAM", 1_000_000, 372)
        );
        let treasury =
            script_of("f6b84686a2323a233e99c60ed79a59d3ec45289fec58a4c359997e551b0326b0").unwrap();
        let b = snap.balances(&treasury, &[]);
        assert!(b.dream > 0 && b.dream <= 1_000_000);
        let hist = snap.history(&treasury.to_hex_string());
        let issue = hist.iter().find(|t| t.txid == DREAM_ASSET_ID).unwrap();
        assert_eq!(issue.movement(&treasury.to_hex_string()).dream, 1_000_000);
        assert!(snap.txs.iter().all(|t| t.broken.is_none()));
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
            replay(include_bytes!("testdata/blocks.dat"), None).unwrap()
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
            let spend = build_provision(&s, &coins(), &ext, &them(), 0, 2_000)
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
            let spend = build_provision(&s, &coins, &ext, &them(), 100, 1_000)
                .unwrap_or_else(|_| panic!("the treasury pack builds"));
            let bare: Transaction = deserialize_hex(&unsigned_hex(&spend.tx)).unwrap();
            assert!(bare.input.iter().all(|i| i.witness.is_empty()));
            assert_eq!(bare.compute_txid(), spend.txid);
            let prevouts = prevouts_for(&spend.tx, &coins, &ext.script()).unwrap();
            assert_eq!(prevouts.len(), spend.tx.input.len());
            let doc = document().unwrap();
            // an answer that is still unsigned is refused
            assert!(accept_signed(&spend, &unsigned_hex(&spend.tx), &prevouts, &doc).is_err());
        }

        #[test]
        fn a_validly_signed_answer_is_accepted() {
            let (_, ext, spend) = built();
            assert_eq!(spend.tx.input.len(), 2);
            let prevouts = prevouts_for(&spend.tx, &coins(), &ext.script()).unwrap();
            let answer = serialize_hex(&sign(&spend.tx, &prevouts, &kp()));
            let signed = accept_signed(&spend, &answer, &prevouts, &document().unwrap()).unwrap();
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
            assert!(
                accept_signed(&spend, &serialize_hex(&t), &prevouts, &document().unwrap()).is_err()
            );
        }

        #[test]
        fn another_keys_signature_is_refused() {
            let (_, ext, spend) = built();
            let prevouts = prevouts_for(&spend.tx, &coins(), &ext.script()).unwrap();
            let other =
                Keypair::from_secret_key(secp(), &SecretKey::from_slice(&[0x43; 32]).unwrap());
            let answer = serialize_hex(&sign(&spend.tx, &prevouts, &other));
            assert!(accept_signed(&spend, &answer, &prevouts, &document().unwrap()).is_err());
        }

        #[test]
        fn a_different_transaction_is_refused_even_if_signed() {
            let (_, ext, spend) = built();
            let prevouts = prevouts_for(&spend.tx, &coins(), &ext.script()).unwrap();
            let mut other = spend.tx.clone();
            other.output[0].script_pubkey = ext.script(); // pays itself instead
            let answer = serialize_hex(&sign(&other, &prevouts, &kp()));
            let e = accept_signed(&spend, &answer, &prevouts, &document().unwrap()).unwrap_err();
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
                dream: 100,
            }],
            outs: vec![
                Leg {
                    script: them.clone(),
                    sats: 330,
                    dream: 40,
                },
                Leg {
                    script: me.clone(),
                    sats: 330,
                    dream: 60,
                },
                Leg {
                    script: me.clone(),
                    sats: 140,
                    dream: 0,
                },
            ],
            tip_event: None,
            broken: None,
            coinbase: false,
        };
        let m = t.movement(&me);
        assert_eq!(m.dream, -40);
        assert_eq!(m.sats, -530);
        assert_eq!(m.counterparty.as_deref(), Some(them.as_str()));
        let r = t.movement(&them);
        assert_eq!((r.dream, r.sats), (40, 330));
        assert_eq!(r.counterparty.as_deref(), Some(me.as_str()));
    }
}
