//! `nostr-bbs-sidestr-admin` — the operator's wallet for a kit deployment's
//! pinned sidestr chains.
//!
//! The kit pins two chains ([`nostr_bbs_poker_citizen::chain::PINS`]):
//! `sidestr:dreamlab` beside testnet4 (stock headers) and
//! `sidestr:dreamlab-txbt4` beside the BLAKE2b testnet4 fork, whose parent
//! hands down [`sidestr_header::Blake2bV2`](https://docs.rs/sidestr-header)
//! headers. A wallet that assumes one header family cannot replay the other,
//! so this crate replays the producer's block file with
//! [`nostr_bbs_poker_citizen::chain::replay`], the house seat's own
//! two-family replay, and builds every transaction against the validated
//! state and assets view it leaves.
//!
//! | Item | Does |
//! |---|---|
//! | [`parse_key`] | A key file's text (64 hex or `nsec1…`) to a signing key; never echoes it |
//! | [`parse_recipient`] | A hex pubkey or `npub1…` to the hex key whose `OP_1 <key>` script is paid |
//! | [`holdings`] | A script's plain sats and every asset it holds |
//! | [`resolve_asset`] | An asset id or a ticker to the asset's id |
//! | [`build_issue`] | SPEC 12 issue: the whole supply on one carrier to the issuer |
//! | [`build_asset_transfer`] | Move units of an asset, fee from plain coins |
//! | [`build_send`] | Pay plain sats, spending only coins that carry nothing |
//! | [`faucet`] | The faucet: its grant ledger and the grant, for `faucet` in the binary |
//!
//! The builders take the coins to spend explicitly (the binary passes the
//! key's coins at the tip, [`Replayed`]'s `state.coins`), sign with the key
//! the way the house signs its settlements (`AgentKey::spend_signer`), and
//! re-check the result against the assets view before returning it.
//!
//! The binary (native only) fetches `/chain.json` and `/blocks.dat` from the
//! producer, holds the document to the pin, and prints or posts; its
//! `faucet` subcommand answers members' kind-23501 requests on the relays.
//! Run it with `--help`. Coins on these chains carry no value.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use bitcoin::{Script, Txid};
use nostr_bbs_poker_citizen::chain::{script_of, Replayed};
use sidestr_agent::AgentKey;
use sidestr_wallet::asset::{plain_coins, IssueRequest, Transfer, TransferRequest};
use sidestr_wallet::coins::Coin;
use sidestr_wallet::spend::{build_spend, Spend, SpendRequest};
use sidestr_wallet::Permissive;

pub use nostr_bbs_poker_citizen::chain::{check_document, pin, replay, Pin, PINS};

pub mod faucet;

/// A signing key from a key file's text: 64 hex characters or a NIP-19
/// `nsec1…`, surrounding whitespace ignored. The error never echoes the
/// text, which may be a secret.
///
/// ```
/// // NIP-19's published vector: this nsec is this hex secret
/// let a = nostr_bbs_sidestr_admin::parse_key(
///     "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5",
/// ).unwrap();
/// let b = nostr_bbs_sidestr_admin::parse_key(
///     "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa\n",
/// ).unwrap();
/// assert_eq!(a.pubkey(), b.pubkey());
/// assert!(nostr_bbs_sidestr_admin::parse_key("not a key").is_err());
/// ```
pub fn parse_key(text: &str) -> Result<AgentKey, String> {
    AgentKey::parse(text)
        .map_err(|_| "the key file holds neither 64 hex characters nor an nsec1…".to_string())
}

/// A recipient as the 64-hex x-only key its coins pay: a hex pubkey (any
/// case) or a NIP-19 `npub1…`.
///
/// ```
/// use nostr_bbs_sidestr_admin::parse_recipient;
/// // NIP-19's published vector
/// let hex = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";
/// assert_eq!(
///     parse_recipient("npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg").unwrap(),
///     hex
/// );
/// assert_eq!(parse_recipient(&hex.to_ascii_uppercase()).unwrap(), hex);
/// assert!(parse_recipient("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5").is_err());
/// ```
pub fn parse_recipient(text: &str) -> Result<String, String> {
    let t = text.trim();
    let hex_key = if t.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("npub1")) {
        nostr_bbs_core::nip19::decode_npub(&t.to_ascii_lowercase())
            .map_err(|e| format!("{t:?} is not an npub: {e}"))?
    } else {
        t.to_ascii_lowercase()
    };
    if script_of(&hex_key).is_none() {
        return Err(format!(
            "{t:?} is neither a 64-hex pubkey nor an npub1… (a secret key is never a recipient)"
        ));
    }
    // a hex string that is not a curve point would make an unspendable output
    bitcoin::XOnlyPublicKey::from_slice(
        &hex::decode(&hex_key).map_err(|_| format!("{t:?} is not hex"))?,
    )
    .map_err(|_| format!("{t:?} is not a valid x-only public key"))?;
    Ok(hex_key)
}

/// One asset a script holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holding {
    /// The asset's id: its issue's txid.
    pub id: Txid,
    /// Its ticker, as issued.
    pub ticker: String,
    /// Display decimals, as issued.
    pub decimals: u8,
    /// Units held at the tip.
    pub held: u64,
}

/// A script's holdings at the tip.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Holdings {
    /// Sats on coins that carry nothing and are mature: what a send or a fee
    /// may spend.
    pub plain_sats: u64,
    /// How many such coins.
    pub plain_coins: usize,
    /// Sats on plain coinbase coins not yet mature.
    pub immature_sats: u64,
    /// Sats locked on carriers (coins carrying an asset).
    pub carrier_sats: u64,
    /// Every asset the script holds, by id.
    pub assets: Vec<Holding>,
}

/// The holdings of `script` at the replayed tip.
pub fn holdings(r: &Replayed, script: &Script) -> Holdings {
    let tip = r.state.height();
    let coins = r.state.coins(script);
    let mut h = Holdings::default();
    for c in plain_coins(&coins, &r.assets) {
        if c.is_mature(tip) {
            h.plain_sats += c.value;
            h.plain_coins += 1;
        } else {
            h.immature_sats += c.value;
        }
    }
    let mut held: std::collections::BTreeMap<Txid, u64> = Default::default();
    for c in &coins {
        if let Some(carry) = r.assets.carried(&c.outpoint) {
            h.carrier_sats += c.value;
            for (id, n) in carry {
                *held.entry(*id).or_default() += n;
            }
        }
    }
    let issued = r.assets.issued();
    h.assets = held
        .into_iter()
        .filter(|(_, n)| *n > 0)
        .map(|(id, n)| {
            let (ticker, decimals) = issued
                .get(&id)
                .map_or((String::from("?"), 0), |i| (i.ticker.clone(), i.decimals));
            Holding {
                id,
                ticker,
                decimals,
                held: n,
            }
        })
        .collect();
    h
}

/// An asset by its id (64 hex) or its ticker (case-insensitive). The asset
/// must be issued on the replayed chain; a ticker that names more than one
/// asset is refused with their ids.
pub fn resolve_asset(r: &Replayed, text: &str) -> Result<Txid, String> {
    let t = text.trim();
    let issued = r.assets.issued();
    if t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
        let id = nostr_bbs_poker_citizen::chain::parse_asset(t)?;
        return if issued.contains_key(&id) {
            Ok(id)
        } else {
            Err(format!("asset {id} is not issued on this chain"))
        };
    }
    let found: Vec<Txid> = issued
        .iter()
        .filter(|(_, i)| i.ticker.eq_ignore_ascii_case(t))
        .map(|(id, _)| *id)
        .collect();
    match found.as_slice() {
        [id] => Ok(*id),
        [] => Err(format!(
            "no asset with ticker {t:?} is issued on this chain"
        )),
        many => Err(format!(
            "ticker {t:?} names {} assets; give the id: {}",
            many.len(),
            many.iter()
                .map(Txid::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// Issue `supply` units of a new asset `ticker` (1 to 8 of `A-Z0-9`) with
/// `decimals` (0 to 8): output 0 carries the whole supply to the issuer, then
/// the `issue:` and `tally:self:0=<supply>` records (SPEC 12). The fee comes
/// from plain mature `coins`. The asset's id is the returned spend's txid.
pub fn build_issue(
    key: &AgentKey,
    r: &Replayed,
    coins: &[Coin],
    ticker: &str,
    supply: u64,
    decimals: u8,
) -> Result<Spend, String> {
    if r.assets
        .issued()
        .values()
        .any(|i| i.ticker.eq_ignore_ascii_case(ticker))
    {
        return Err(format!(
            "an asset with ticker {ticker} is already issued on this chain"
        ));
    }
    sidestr_wallet::asset::build_issue(
        &IssueRequest {
            chain: r.state.document(),
            coins,
            view: &r.assets,
            tip_height: r.state.height(),
            ticker,
            decimals,
            supply,
            to: None,
            fee: None,
        },
        &key.spend_signer(),
        &Permissive,
    )
    .map_err(|e| e.to_string())
}

/// Move `units` of `asset` to `to_pubkey` (64 hex), with an optional memo
/// record. Output 0 is the recipient's carrier; asset change returns to the
/// signer on output 1; the fee comes from plain `coins`.
pub fn build_asset_transfer(
    key: &AgentKey,
    r: &Replayed,
    coins: &[Coin],
    asset: Txid,
    to_pubkey: &str,
    units: u64,
    memo: Option<&str>,
) -> Result<Transfer, String> {
    let to = script_of(to_pubkey).ok_or("the recipient is not a 64-hex pubkey")?;
    let memos: Vec<String> = memo.map(str::to_string).into_iter().collect();
    let t = sidestr_wallet::asset::build_transfer(
        &TransferRequest {
            chain: r.state.document(),
            coins,
            view: &r.assets,
            tip_height: r.state.height(),
            asset,
            to: &to.to_hex_string(),
            amount: units,
            memos: &memos,
            fee: None,
        },
        &key.spend_signer(),
        &Permissive,
    )
    .map_err(|e| e.to_string())?;
    let mut carried_in = Default::default();
    r.assets
        .check(&t.spend.tx, &mut carried_in)
        .map_err(|e| format!("the transfer would break the assets rule: {e}"))?;
    Ok(t)
}

/// Pay `sats` plain sats to `to_pubkey` (64 hex). Only `coins` that carry
/// nothing are spent, so no asset is ever destroyed; the built spend is
/// re-checked against the assets view to prove it.
pub fn build_send(
    key: &AgentKey,
    r: &Replayed,
    coins: &[Coin],
    to_pubkey: &str,
    sats: u64,
) -> Result<Spend, String> {
    let to = script_of(to_pubkey).ok_or("the recipient is not a 64-hex pubkey")?;
    let plain = plain_coins(coins, &r.assets);
    let spend = build_spend(
        &SpendRequest {
            chain: r.state.document(),
            coins: &plain,
            tip_height: r.state.height(),
            to: &to.to_hex_string(),
            amount: sats,
            fee: None,
        },
        &key.spend_signer(),
        &Permissive,
    )
    .map_err(|e| e.to_string())?;
    let mut carried_in = Default::default();
    r.assets
        .check(&spend.tx, &mut carried_in)
        .map_err(|e| format!("the send would break the assets rule: {e}"))?;
    if !carried_in.is_empty() {
        return Err("the send would spend a coin carrying an asset".into());
    }
    Ok(spend)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::OutPoint;
    use nostr_bbs_poker_citizen::chain::{ChainState, DREAMLAB, DREAMLAB_TXBT4, DREAM_ASSET_ID};

    /// The house seat's fixtures: real producer block files, one per family.
    const DREAMLAB_BLOCKS: &[u8] =
        include_bytes!("../../nostr-bbs-poker-citizen/src/testdata/dreamlab-blocks.dat");
    const TXBT4_BLOCKS: &[u8] =
        include_bytes!("../../nostr-bbs-poker-citizen/src/testdata/txbt4-blocks.dat");

    /// A DREAM holder in the dreamlab fixture (the house seat's test key).
    const DREAM_HOLDER: &str = "f6b84686a2323a233e99c60ed79a59d3ec45289fec58a4c359997e551b0326b0";

    fn key(byte: u8) -> AgentKey {
        parse_key(&hex::encode([byte; 32])).unwrap()
    }

    fn pubkey_hex(k: &AgentKey) -> String {
        k.pubkey().to_string()
    }

    /// A synthetic plain coin for `k`: the fixture keys' secrets are not
    /// ours, so builders are exercised against the real replayed document
    /// and view with a coin the test key owns.
    fn coin(seed: u8, value: u64) -> Coin {
        Coin {
            outpoint: format!("{}:0", hex::encode([seed; 32])).parse().unwrap(),
            value,
            height: 1,
            coinbase: false,
        }
    }

    fn replayed(p: &Pin, dat: &[u8]) -> Replayed {
        replay(p.document().unwrap(), dat, None).unwrap()
    }

    #[test]
    fn keys_parse_and_never_echo() {
        let hex_secret = "11".repeat(32);
        let k = parse_key(&format!("  {hex_secret}\n")).unwrap();
        assert_eq!(pubkey_hex(&k).len(), 64);
        let e = parse_key("deadbeef-not-a-secret").unwrap_err();
        assert!(!e.contains("deadbeef"), "{e}");
        // an npub is a public key, not a key file
        assert!(
            parse_key("npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg").is_err()
        );
    }

    #[test]
    fn recipients_are_hex_or_npub() {
        let k = key(0x22);
        let hex_pk = pubkey_hex(&k);
        assert_eq!(parse_recipient(&hex_pk).unwrap(), hex_pk);
        assert_eq!(
            parse_recipient(&format!(" {} ", hex_pk.to_ascii_uppercase())).unwrap(),
            hex_pk
        );
        let npub = nostr_bbs_core::nip19::encode_npub(&hex_pk).unwrap();
        assert_eq!(parse_recipient(&npub).unwrap(), hex_pk);
        assert!(parse_recipient("abc").is_err());
        assert!(parse_recipient(&"zz".repeat(32)).is_err());
        // 64 hex digits that are not a curve point
        assert!(parse_recipient(&"ff".repeat(32)).is_err());
        // a broken checksum
        let mut bad = npub.clone();
        bad.pop();
        bad.push(if npub.ends_with('q') { 'p' } else { 'q' });
        assert!(parse_recipient(&bad).is_err());
    }

    /// Both families replay through the shared helper, and the holdings read
    /// the fixture's DREAM.
    #[test]
    fn each_family_replays_and_reads_holdings() {
        let r = replayed(&DREAMLAB, DREAMLAB_BLOCKS);
        assert!(matches!(r.state, ChainState::Stock(_)));
        let dream: Txid = DREAM_ASSET_ID.parse().unwrap();
        let h = holdings(&r, &script_of(DREAM_HOLDER).unwrap());
        let d = h.assets.iter().find(|a| a.id == dream).unwrap();
        assert_eq!(d.ticker, "DREAM");
        assert!(d.held > 0 && h.carrier_sats > 0);
        assert_eq!(resolve_asset(&r, "dream").unwrap(), dream);
        assert_eq!(resolve_asset(&r, DREAM_ASSET_ID).unwrap(), dream);
        assert!(resolve_asset(&r, "NOPE").is_err());
        assert!(resolve_asset(&r, &"07".repeat(32))
            .unwrap_err()
            .contains("not issued"));
        // a stranger holds nothing
        assert_eq!(holdings(&r, &key(0x33).script()), Holdings::default());

        let r = replayed(&DREAMLAB_TXBT4, TXBT4_BLOCKS);
        assert!(matches!(r.state, ChainState::Blake2b(_)));
        assert!(r.state.height() >= 26);
        assert!(r.assets.issued().is_empty());
        assert!(resolve_asset(&r, "DREAM").is_err());
        // the other chain's blocks fail each document
        assert!(replay(DREAMLAB.document().unwrap(), TXBT4_BLOCKS, None).is_err());
        assert!(replay(DREAMLAB_TXBT4.document().unwrap(), DREAMLAB_BLOCKS, None).is_err());
    }

    /// An issue builds under each family's document and signature, reads
    /// back as the whole supply on output 0, and the issued asset then
    /// transfers, with its change and fee where the builder puts them.
    #[test]
    fn issue_then_transfer_on_each_family() {
        for (p, dat) in [
            (&DREAMLAB, DREAMLAB_BLOCKS),
            (&DREAMLAB_TXBT4, TXBT4_BLOCKS),
        ] {
            let r = replayed(p, dat);
            let k = key(0x44);
            let coins = vec![coin(0xab, 50_000)];
            let issue = build_issue(&k, &r, &coins, "BLAKES7", 10_000_000, 0).unwrap();
            assert_eq!(issue.tx.output[0].script_pubkey, k.script());
            assert_eq!(issue.tx.input.len(), 1);
            assert!(issue.fee > 0 && issue.change > 0, "{}", p.id);
            // the view reads the whole supply on output 0
            let mut view = r.assets.clone();
            let height = r.state.height() + 1;
            view.apply_transactions(std::slice::from_ref(&issue.tx), height);
            let id = issue.txid;
            assert_eq!(view.issued()[&id].supply, 10_000_000);
            assert_eq!(view.issued()[&id].ticker, "BLAKES7");
            assert_eq!(
                view.carried(&OutPoint { txid: id, vout: 0 }).unwrap()[&id],
                10_000_000
            );
            // transfer from the issue's outputs: the carrier and the change
            let mine: Vec<Coin> = issue
                .tx
                .output
                .iter()
                .enumerate()
                .filter(|(_, o)| o.script_pubkey == k.script())
                .map(|(v, o)| Coin {
                    outpoint: OutPoint {
                        txid: id,
                        vout: v as u32,
                    },
                    value: o.value.to_sat(),
                    height,
                    coinbase: false,
                })
                .collect();
            let after = Replayed {
                state: replayed(p, dat).state,
                assets: view,
            };
            let to = pubkey_hex(&key(0x55));
            let t = build_asset_transfer(&k, &after, &mine, id, &to, 2_500, Some("grant:test"))
                .unwrap();
            assert_eq!(t.asset_change, 10_000_000 - 2_500);
            assert_eq!(t.spend.tx.output[0].script_pubkey, script_of(&to).unwrap());
            // more than held is refused; an assets record as memo too
            assert!(build_asset_transfer(&k, &after, &mine, id, &to, 10_000_001, None).is_err());
            assert!(build_asset_transfer(&k, &after, &mine, id, &to, 1, Some("tally:x")).is_err());
            // a plain send never spends the carrier
            let s = build_send(&k, &after, &mine, &to, 1_000).unwrap();
            assert!(s
                .tx
                .input
                .iter()
                .all(|i| i.previous_output != OutPoint { txid: id, vout: 0 }));
        }
    }

    #[test]
    fn issues_and_sends_refuse_what_they_cannot_build() {
        let r = replayed(&DREAMLAB_TXBT4, TXBT4_BLOCKS);
        let k = key(0x44);
        let to = pubkey_hex(&key(0x55));
        // no coins, no fee
        assert!(build_issue(&k, &r, &[], "BLAKES7", 1, 0).is_err());
        // bad tickers and decimals
        let coins = vec![coin(0xab, 50_000)];
        assert!(build_issue(&k, &r, &coins, "TOOLONGTICKER", 1, 0).is_err());
        assert!(build_issue(&k, &r, &coins, "lower", 1, 0).is_err());
        assert!(build_issue(&k, &r, &coins, "OK", 1, 9).is_err());
        assert!(build_issue(&k, &r, &coins, "OK", 0, 0).is_err());
        // a ticker already on the chain is refused
        let d = replayed(&DREAMLAB, DREAMLAB_BLOCKS);
        assert!(build_issue(&k, &d, &coins, "DREAM", 1, 0)
            .unwrap_err()
            .contains("already issued"));
        // sends: under the coins, zero, and a recipient that is no key
        assert!(build_send(&k, &r, &coins, &to, 60_000).is_err());
        assert!(build_send(&k, &r, &coins, &to, 0).is_err());
        assert!(build_send(&k, &r, &coins, "nope", 1_000).is_err());
        let s = build_send(&k, &r, &coins, &to, 10_000).unwrap();
        assert_eq!(s.amount, 10_000);
        assert_eq!(s.tx.output[0].script_pubkey, script_of(&to).unwrap());
    }
}
