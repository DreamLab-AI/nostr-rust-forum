//! The identity key's coins on BLAKE2b testnet4 (`txbt4`), shown read-only (ADR-2019).
//!
//! A member's x-only key is already a `txbt4` address: bitcoin-blake/blaketest
//! uses the key itself as the taproot witness program (`OP_1 <x-only key>`, no
//! BIP-341 tweak), so the npub and the `tb1p…` address are one key. This
//! module derives that address from the session's *public* key, asks the
//! Esplora-shaped backend the operator names in `BLAKE_TESTNET_API` what it
//! holds, and reads the backend's answer. Nothing here is validated in the
//! browser, nothing is signed and no coin is moved: spending happens in
//! blaketest or a Knots BLAKE2b wallet. ADR-2015's one-chain, one-asset lock
//! is untouched; this is not a second chain in it.
//!
//! Mined coins wait: a payment spending a coinbase output younger than
//! [`COINBASE_MATURITY`] confirmations is refused by every upgraded testnet4
//! node, so the confirmed figure is split into what can be spent now and what
//! is still maturing ([`Maturity`]) whenever the backend says which coins were
//! mined and how high its chain is; otherwise the page says the figure may
//! include immature mined coins.
//!
//! With `BLAKE_TESTNET_API` unset (or not `https://`), [`api_base`] is `None`
//! and the wallet page makes no request to any BLAKE backend.

use bitcoin::key::TweakedPublicKey;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{Address, KnownHrp};
use serde::Deserialize;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use crate::utils::relay_url::env_override;

/// How the page names the chain, so nobody mistakes the figure for value.
pub const LABEL: &str = "BLAKE2b testnet4 (no value)";
/// The chain's alias in sidestr/spec and blaketestnode.
pub const ALIAS: &str = "txbt4";
/// The stock testnet4 branch it forked from, as the pair view names it.
pub const PAIR_ALIAS: &str = "tbtc4";
/// Confirmations a mined (coinbase) coin needs before a payment spending it
/// leaves the node that relays it. Testnet4 since Knots 29.4.2: the mempool of
/// every upgraded node asks 6,705 of every reward, whatever its height (a
/// 123-deep reward was refused `bad-txns-premature-spend-of-coinbase` on
/// 2026-10-02). Source: Reef `2bd3cb8`, `lib/wallet.mjs` `COINBASE_MATURITY`;
/// counted as Reef's `isMature` does: `tip + 1 - height >= COINBASE_MATURITY`.
pub const COINBASE_MATURITY: u32 = 6705;
/// The wallet that moves `txbt4` coins: the forum never does.
pub const BLAKETEST_URL: &str = "https://bitcoin-blake.github.io/blaketest/";

/// The backend base URL from a raw `BLAKE_TESTNET_API` value: `https://` only,
/// without a trailing slash; anything else means the view is off.
pub fn api_base_from(raw: Option<&str>) -> Option<String> {
    let base = raw?.trim().trim_end_matches('/');
    (base.starts_with("https://") && base.len() > "https://".len()).then(|| base.to_string())
}

/// The backend this deployment names, or `None` (nothing shown, nothing fetched).
pub fn api_base() -> Option<String> {
    api_base_from(env_override("BLAKE_TESTNET_API").as_deref())
}

/// The `tb1p…` address of a Nostr key on `txbt4`: the x-only key as the
/// witness-v1 program, untweaked, bech32m-encoded by the `bitcoin` crate.
/// `None` unless `pubkey_hex` is a valid x-only point.
pub fn address_of(pubkey_hex: &str) -> Option<String> {
    let key: XOnlyPublicKey = pubkey_hex.trim().parse().ok()?;
    // blaketest skips the BIP-341 tweak: the output key *is* the identity key.
    let program = TweakedPublicKey::dangerous_assume_tweaked(key);
    Some(Address::p2tr_tweaked(program, KnownHrp::Testnets).to_string())
}

/// blaketest, pointed at the same backend, for moving coins.
pub fn blaketest_link(base: &str) -> String {
    format!("{BLAKETEST_URL}?api={}", percent_encode(base))
}

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[derive(Deserialize)]
struct Stats {
    funded_txo_sum: u64,
    spent_txo_sum: u64,
}

#[derive(Deserialize)]
struct AddressAnswer {
    address: String,
    chain_stats: Stats,
    mempool_stats: Stats,
}

#[derive(Deserialize)]
struct UtxoStatus {
    confirmed: bool,
    #[serde(default)]
    block_height: Option<u32>,
}

/// One entry of an Esplora `/address/:a/utxo` answer. Esplora and
/// blaketestnode do not send `coinbase`; a backend that does lets the
/// confirmed figure be split by maturity.
#[derive(Deserialize)]
struct Utxo {
    value: u64,
    status: UtxoStatus,
    #[serde(default)]
    coinbase: Option<bool>,
}

/// How much of the confirmed figure a payment could spend now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Maturity {
    /// The backend said which coins were mined and how high its chain is.
    Split {
        /// Confirmed sats a payment could spend now.
        spendable: u64,
        /// Mined sats younger than [`COINBASE_MATURITY`] confirmations.
        immature: u64,
    },
    /// The backend gave no `coinbase` flag, no tip height, or answers that do
    /// not add up: the confirmed figure may include immature mined coins.
    Unknown,
}

/// What the backend says an address holds, in sats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParentBalance {
    /// Confirmed: `chain_stats` funded minus spent.
    pub confirmed: u64,
    /// The mempool's net change: `mempool_stats` funded minus spent (may be negative).
    pub unconfirmed: i64,
    /// The confirmed figure split by coinbase maturity, when the backend allows it.
    pub maturity: Maturity,
}

/// Split `confirmed` by coinbase maturity from an `/address/:a/utxo` answer
/// and the backend's tip height. [`Maturity::Unknown`] unless both are given,
/// every confirmed coin carries a `coinbase` flag and a height, and the mined
/// coins still maturing fit inside `confirmed`. A coin above `tip` (the tip
/// was read after the coins) counts as zero confirmations.
pub fn split_maturity(confirmed: u64, utxo: Option<&str>, tip: Option<u32>) -> Maturity {
    let (Some(body), Some(tip)) = (utxo, tip) else {
        return Maturity::Unknown;
    };
    let Ok(coins) = serde_json::from_str::<Vec<Utxo>>(body) else {
        return Maturity::Unknown;
    };
    let mut immature: u64 = 0;
    for c in coins.iter().filter(|c| c.status.confirmed) {
        let (Some(coinbase), Some(height)) = (c.coinbase, c.status.block_height) else {
            return Maturity::Unknown;
        };
        let confirmations = tip.saturating_add(1).saturating_sub(height);
        if coinbase && confirmations < COINBASE_MATURITY {
            let Some(sum) = immature.checked_add(c.value) else {
                return Maturity::Unknown;
            };
            immature = sum;
        }
    }
    match confirmed.checked_sub(immature) {
        Some(spendable) => Maturity::Split {
            spendable,
            immature,
        },
        None => Maturity::Unknown,
    }
}

/// Read an Esplora `/address/:a` answer for `address`, and split its confirmed
/// figure by coinbase maturity from the `/address/:a/utxo` answer and tip
/// height, where the backend gives them ([`split_maturity`]). An answer about
/// any other address is refused.
pub fn parse_balance(
    address: &str,
    body: &str,
    utxo: Option<&str>,
    tip: Option<u32>,
) -> Result<ParentBalance, String> {
    let a: AddressAnswer =
        serde_json::from_str(body).map_err(|_| "the backend's answer is not Esplora-shaped")?;
    if a.address != address {
        return Err("the backend answered about another address".into());
    }
    let confirmed = a
        .chain_stats
        .funded_txo_sum
        .checked_sub(a.chain_stats.spent_txo_sum)
        .ok_or("the backend's confirmed figures do not add up")?;
    let unconfirmed = a.mempool_stats.funded_txo_sum as i64 - a.mempool_stats.spent_txo_sum as i64;
    Ok(ParentBalance {
        confirmed,
        unconfirmed,
        maturity: split_maturity(confirmed, utxo, tip),
    })
}

#[derive(Deserialize)]
struct Only {
    value: u64,
}

#[derive(Deserialize)]
struct Side {
    only: Only,
}

#[derive(Deserialize)]
struct Coin {
    value: u64,
}

/// One address across both branches of the fork, as blaketestnode's
/// `/address/:a/pair` reports it (confirmed coins only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairSplit {
    /// Sats only on BLAKE2b testnet4.
    pub only_blake: u64,
    /// Sats only on stock testnet4.
    pub only_stock: u64,
    /// Sats unspent on both, spendable on either (a spend without `SIGHASH_UNIFIED` is valid on each).
    pub both: u64,
}

/// Read a blaketestnode `/address/:a/pair` answer for `address`.
pub fn parse_pair(address: &str, body: &str) -> Result<PairSplit, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|_| "the pair answer is not JSON")?;
    if v.get("address").and_then(|a| a.as_str()) != Some(address) {
        return Err("the pair answer is about another address".into());
    }
    let side = |alias: &str| -> Result<u64, String> {
        let s: Side = serde_json::from_value(v.get(alias).cloned().unwrap_or_default())
            .map_err(|_| format!("the pair answer has no {alias} side"))?;
        Ok(s.only.value)
    };
    let both: Vec<Coin> = serde_json::from_value(v.get("both").cloned().unwrap_or_default())
        .map_err(|_| "the pair answer has no coins on both")?;
    Ok(PairSplit {
        only_blake: side(ALIAS)?,
        only_stock: side(PAIR_ALIAS)?,
        both: both.iter().map(|c| c.value).sum(),
    })
}

/// What the page shows for the parent coin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentView {
    /// The backend's balance.
    pub balance: ParentBalance,
    /// The split across both branches, when the backend runs with `--pair-api`.
    pub pair: Option<PairSplit>,
}

/// GET `url` as text; `Ok(None)` on a 404.
async fn fetch_text(url: &str) -> Result<Option<String>, String> {
    let win = web_sys::window().ok_or("no window")?;
    let init = web_sys::RequestInit::new();
    init.set_method("GET");
    init.set_cache(web_sys::RequestCache::NoStore);
    let req = web_sys::Request::new_with_str_and_init(url, &init)
        .map_err(|_| "could not build the request".to_string())?;
    let resp: web_sys::Response = JsFuture::from(win.fetch_with_request(&req))
        .await
        .map_err(|_| "the BLAKE2b testnet4 backend could not be reached".to_string())?
        .dyn_into()
        .map_err(|_| "bad response".to_string())?;
    if resp.status() == 404 {
        return Ok(None);
    }
    if !resp.ok() {
        return Err(format!(
            "the BLAKE2b testnet4 backend answered {}",
            resp.status()
        ));
    }
    let text = JsFuture::from(resp.text().map_err(|_| "no body".to_string())?)
        .await
        .map_err(|_| "the answer was cut short".to_string())?;
    Ok(text.as_string())
}

/// Ask `base` what `address` holds, how much of it is still-maturing mined
/// coin, and how it splits across the fork, as far as the backend knows.
/// Read-only GETs, nothing sent but the address. The coins are read before the
/// tip, so a tip that moved in between only makes coins older, never younger
/// than they are.
pub async fn load(base: &str, address: &str) -> Result<ParentView, String> {
    let body = fetch_text(&format!("{base}/address/{address}"))
        .await?
        .ok_or("the backend does not serve /address (run blaketestnode with --address-index)")?;
    // Optional: without them the figure is labelled as possibly including immature mined coins.
    let utxo = fetch_text(&format!("{base}/address/{address}/utxo"))
        .await
        .ok()
        .flatten();
    let tip = match utxo {
        Some(_) => fetch_text(&format!("{base}/blocks/tip/height"))
            .await
            .ok()
            .flatten()
            .and_then(|t| t.trim().parse::<u32>().ok()),
        None => None,
    };
    let balance = parse_balance(address, &body, utxo.as_deref(), tip)?;
    // A backend without --pair-api answers 404 here; a split it cannot give is simply not shown.
    let pair = match fetch_text(&format!("{base}/address/{address}/pair")).await {
        Ok(Some(body)) => parse_pair(address, &body).ok(),
        _ => None,
    };
    Ok(ParentView { balance, pair })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors from bitcoin-blake/blaketest `bitcoin.js` (gh-pages df14e48),
    // `getTaprootAddress` on secret keys 1 and 3.
    const G: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const G_ADDR: &str = "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47zagq";
    const K3: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    const K3_ADDR: &str = "tb1plycg5qvjtrp3qjf5f7zl382j9x6nrjz9sdhenvyxq8c3808qxmuswq2wgh";

    #[test]
    fn the_address_matches_blaketest() {
        assert_eq!(address_of(G).as_deref(), Some(G_ADDR));
        assert_eq!(address_of(K3).as_deref(), Some(K3_ADDR));
        assert_eq!(address_of(&G.to_ascii_uppercase()).as_deref(), Some(G_ADDR));
    }

    #[test]
    fn the_address_pays_the_same_script_as_the_sidestr_wallet() {
        let addr: Address<bitcoin::address::NetworkUnchecked> =
            address_of(K3).unwrap().parse().unwrap();
        let script = addr.assume_checked().script_pubkey();
        assert_eq!(Some(script), super::super::chain::script_of(K3));
    }

    #[test]
    fn a_bad_key_has_no_address() {
        assert!(address_of("nope").is_none());
        assert!(address_of(&"00".repeat(32)).is_none()); // not on the curve
        assert!(address_of(&G[..62]).is_none());
    }

    #[test]
    fn unset_or_insecure_means_off() {
        assert_eq!(api_base_from(None), None);
        assert_eq!(api_base_from(Some("")), None);
        assert_eq!(api_base_from(Some("  ")), None);
        assert_eq!(api_base_from(Some("https://")), None);
        assert_eq!(api_base_from(Some("http://10.0.0.1:3006/api")), None);
        assert_eq!(
            api_base_from(Some(" https://blake.example/api/ ")).as_deref(),
            Some("https://blake.example/api")
        );
    }

    #[test]
    fn blaketest_is_pointed_at_the_same_backend() {
        assert_eq!(
            blaketest_link("https://blake.example/api"),
            "https://bitcoin-blake.github.io/blaketest/?api=https%3A%2F%2Fblake.example%2Fapi"
        );
    }

    #[test]
    fn an_esplora_answer_reads_as_a_balance() {
        let body = format!(
            r#"{{"address":"{G_ADDR}","scriptPubKey":"5120{G}",
            "chain_stats":{{"funded_txo_count":2,"funded_txo_sum":150000,"spent_txo_count":1,"spent_txo_sum":50000,"tx_count":null}},
            "mempool_stats":{{"funded_txo_count":0,"funded_txo_sum":0,"spent_txo_count":1,"spent_txo_sum":20000,"tx_count":null}}}}"#
        );
        assert_eq!(
            parse_balance(G_ADDR, &body, None, None).unwrap(),
            ParentBalance {
                confirmed: 100_000,
                unconfirmed: -20_000,
                maturity: Maturity::Unknown,
            }
        );
        assert!(parse_balance(K3_ADDR, &body, None, None).is_err());
        assert!(parse_balance(G_ADDR, "<html>", None, None).is_err());
    }

    #[test]
    fn coinbase_maturity_is_reefs() {
        // Reef 2bd3cb8 lib/wallet.mjs: `export const COINBASE_MATURITY = 6705;`
        assert_eq!(COINBASE_MATURITY, 6705);
    }

    const TIP: u32 = 160_000;

    fn address_body(confirmed: u64) -> String {
        format!(
            r#"{{"address":"{G_ADDR}","scriptPubKey":"5120{G}",
            "chain_stats":{{"funded_txo_count":2,"funded_txo_sum":{confirmed},"spent_txo_count":0,"spent_txo_sum":0,"tx_count":null}},
            "mempool_stats":{{"funded_txo_count":0,"funded_txo_sum":0,"spent_txo_count":0,"spent_txo_sum":0,"tx_count":null}}}}"#
        )
    }

    fn utxo(value: u64, height: u32, coinbase: Option<bool>) -> String {
        let flag = coinbase
            .map(|c| format!(r#","coinbase":{c}"#))
            .unwrap_or_default();
        format!(
            r#"{{"txid":"{t}","vout":0,"value":{value},"status":{{"confirmed":true,"block_height":{height},"block_hash":"00","block_time":1}}{flag}}}"#,
            t = "bb".repeat(32)
        )
    }

    #[test]
    fn a_fifty_deep_mined_coin_is_immature_and_an_ordinary_one_spendable() {
        // 50 confirmations: tip + 1 - height = 50.
        let mined = utxo(5_000_000_000, TIP + 1 - 50, Some(true));
        let paid = utxo(30_000, TIP - 10, Some(false));
        let unconfirmed = r#"{"txid":"cc","vout":1,"value":7,"status":{"confirmed":false}}"#;
        let list = format!("[{mined},{paid},{unconfirmed}]");
        let b =
            parse_balance(G_ADDR, &address_body(5_000_030_000), Some(&list), Some(TIP)).unwrap();
        assert_eq!(
            b.maturity,
            Maturity::Split {
                spendable: 30_000,
                immature: 5_000_000_000
            }
        );
        assert_eq!(b.confirmed, 5_000_030_000);
    }

    #[test]
    fn maturity_is_counted_as_reef_counts_it() {
        let at = |conf: u32| {
            let list = format!("[{}]", utxo(1_000, TIP + 1 - conf, Some(true)));
            split_maturity(1_000, Some(&list), Some(TIP))
        };
        assert_eq!(
            at(COINBASE_MATURITY - 1),
            Maturity::Split {
                spendable: 0,
                immature: 1_000
            }
        );
        assert_eq!(
            at(COINBASE_MATURITY),
            Maturity::Split {
                spendable: 1_000,
                immature: 0
            }
        );
        // A coin above the tip (tip read late or behind) is not yet confirmed enough.
        let above = format!("[{}]", utxo(1_000, TIP + 3, Some(true)));
        assert_eq!(
            split_maturity(1_000, Some(&above), Some(TIP)),
            Maturity::Split {
                spendable: 0,
                immature: 1_000
            }
        );
    }

    #[test]
    fn without_a_flag_or_a_tip_the_split_is_unknown() {
        let unflagged = format!(
            "[{},{}]",
            utxo(5_000, TIP - 60, None),
            utxo(1, TIP - 9_000, Some(false))
        );
        // Esplora and blaketestnode's /utxo carry no coinbase flag.
        assert_eq!(
            split_maturity(5_001, Some(&unflagged), Some(TIP)),
            Maturity::Unknown
        );
        let flagged = format!("[{}]", utxo(5_000, TIP - 60, Some(false)));
        assert_eq!(
            split_maturity(5_000, Some(&flagged), None),
            Maturity::Unknown
        );
        assert_eq!(split_maturity(5_000, None, Some(TIP)), Maturity::Unknown);
        assert_eq!(
            split_maturity(5_000, Some("<html>"), Some(TIP)),
            Maturity::Unknown
        );
        // Immature mined coins beyond the confirmed figure: the answers disagree.
        let more = format!("[{}]", utxo(9_000, TIP - 60, Some(true)));
        assert_eq!(
            split_maturity(5_000, Some(&more), Some(TIP)),
            Maturity::Unknown
        );
    }

    #[test]
    fn the_output_key_is_the_bare_x_key() {
        // sidestr/spec keys.mjs rule (spec.md, "bare x-only key"): an npub is the
        // even-y point 02 + x, and the address pays OP_1 <x> with no tweak (rawtr, not tr).
        for (x, addr) in [(G, G_ADDR), (K3, K3_ADDR)] {
            assert_eq!(address_of(x).as_deref(), Some(addr));
            let parsed: Address<bitcoin::address::NetworkUnchecked> = addr.parse().unwrap();
            let script = parsed.assume_checked().script_pubkey();
            assert_eq!(script.to_hex_string(), format!("5120{x}"));
        }
    }

    #[test]
    fn a_pair_answer_splits_across_the_fork() {
        let body = format!(
            r#"{{"address":"{G_ADDR}","fork":{{"height":150308,"base":{{"height":150307,"hash":"00"}}}},
            "txbt4":{{"coins":2,"value":7000,"only":{{"coins":1,"value":2000}}}},
            "tbtc4":{{"coins":2,"value":9000,"only":{{"coins":1,"value":4000}}}},
            "both":[{{"txid":"{aa}","vout":0,"value":5000,"height":100}}],
            "utxo":{{"txbt4":[],"tbtc4":[]}}}}"#,
            aa = "aa".repeat(32)
        );
        assert_eq!(
            parse_pair(G_ADDR, &body).unwrap(),
            PairSplit {
                only_blake: 2000,
                only_stock: 4000,
                both: 5000
            }
        );
        assert!(parse_pair(K3_ADDR, &body).is_err());
    }
}
