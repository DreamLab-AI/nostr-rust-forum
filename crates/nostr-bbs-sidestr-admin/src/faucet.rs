//! The faucet's pure half: who may be paid, and the grant itself.
//!
//! A member's wallet asks for coins with a kind-23501 event (SPEC 11) on the
//! public relays: a `chain` tag and, as content, the address to pay. The
//! faucet pays plain sats and, when it is given an asset, units of it on a
//! carrier, one grant per destination script per window and at most so many
//! grants an hour. [`Ledger`] keeps both limits; it reads and writes the same
//! JSON as `sidestr-agent faucet`, so a chain moved from that faucet to this
//! one keeps its grant history. [`build_grant`] builds the grant against the
//! replayed chain, from coins the caller has not already spent.
//!
//! Each request is judged against a fresh replay, as the crates.io faucet
//! does; this one replays under either header family
//! ([`crate::replay`]), which is why it exists.

use std::collections::{BTreeMap, VecDeque};

use bitcoin::{ScriptBuf, Txid};
use nostr_bbs_poker_citizen::chain::Replayed;
use serde::{Deserialize, Serialize};
use sidestr_agent::AgentKey;
use sidestr_core::records::tally_text;
use sidestr_wallet::asset::{sort_coins, CARRIER};
use sidestr_wallet::coins::Coin;
use sidestr_wallet::compose::{build_outputs, OutputsRequest};
use sidestr_wallet::spend::Spend;
use sidestr_wallet::Permissive;

/// One grant, and how often.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Plain sats per grant.
    pub sats: u64,
    /// The asset granted beside the sats, and how many units, if any.
    pub asset: Option<(Txid, u64)>,
    /// Seconds before one destination script may be paid again.
    pub per_address_secs: u64,
    /// Grants per hour, all scripts together.
    pub per_hour: usize,
}

/// Who was paid and when: the faucet's memory across restarts. The JSON is
/// `sidestr-agent faucet`'s: `paid` maps a destination script's hex to the
/// unix time it was last paid; `recent` lists recent grant times, oldest
/// first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    /// Destination script hex → when it was last paid.
    #[serde(default)]
    pub paid: BTreeMap<String, u64>,
    /// When recent grants were made, oldest first.
    #[serde(default)]
    pub recent: VecDeque<u64>,
}

/// Why a request is not paid now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// This script was paid within the window.
    PaidWithinWindow,
    /// The hourly limit is spent.
    HourlyLimit,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Refusal::PaidWithinWindow => "paid within the window",
            Refusal::HourlyLimit => "hourly limit reached",
        })
    }
}

impl Ledger {
    /// Parse a saved ledger. An unreadable one is an error, never a silent
    /// empty ledger: forgetting grants would pay everyone again.
    pub fn parse(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("the faucet ledger is not readable: {e}"))
    }

    /// The ledger as JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }

    /// Whether `script_hex` may be paid at `now` under `policy`. Drops grant
    /// times older than an hour as it goes.
    pub fn judge(&mut self, script_hex: &str, now: u64, policy: &Policy) -> Result<(), Refusal> {
        if let Some(t) = self.paid.get(script_hex) {
            if now.saturating_sub(*t) < policy.per_address_secs {
                return Err(Refusal::PaidWithinWindow);
            }
        }
        while self
            .recent
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= 3_600)
        {
            self.recent.pop_front();
        }
        if self.recent.len() >= policy.per_hour {
            return Err(Refusal::HourlyLimit);
        }
        Ok(())
    }

    /// Record a grant to `script_hex` at `now`.
    pub fn record(&mut self, script_hex: &str, now: u64) {
        self.paid.insert(script_hex.to_string(), now);
        self.recent.push_back(now);
    }
}

/// Build one grant to `to` from `coins` (the faucet key's coins at the tip,
/// less any a grant in flight has spent): output 0 a carrier with the
/// asset's units when the policy names one (asset change back to the key on
/// output 1), then the plain sats, then the tally record. The fee comes from
/// plain coins. The result is re-checked against the assets view.
pub fn build_grant(
    key: &AgentKey,
    r: &Replayed,
    coins: &[Coin],
    to: &ScriptBuf,
    policy: &Policy,
) -> Result<Spend, String> {
    let me = key.script();
    if to.is_op_return() || *to == me {
        return Err("not a destination the faucet pays".into());
    }
    if policy.sats == 0 && policy.asset.is_none() {
        return Err("the grant is empty: no sats and no asset".into());
    }
    let sorted = sort_coins(coins, &r.assets, policy.asset.as_ref().map(|(a, _)| a));
    let mut outputs = Vec::new();
    let mut records = Vec::new();
    let mut required = Vec::new();
    if let Some((asset, units)) = policy.asset {
        if units == 0 {
            return Err("an asset grant of 0 units".into());
        }
        let mut carriers = sorted.carriers.clone();
        carriers.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        let mut have = 0u64;
        for (c, n) in carriers {
            if have >= units {
                break;
            }
            have += n;
            required.push(c);
        }
        if have < units {
            return Err(format!("holds {have} of the asset, a grant is {units}"));
        }
        outputs.push((to.clone(), CARRIER));
        let mut assigns = vec![(0u32, units)];
        if have > units {
            outputs.push((me.clone(), CARRIER));
            assigns.push((1, have - units));
        }
        records.push(tally_text(Some(&asset), &assigns).map_err(|e| e.to_string())?);
    }
    if policy.sats > 0 {
        outputs.push((to.clone(), policy.sats));
    }
    let spend = build_outputs(
        &OutputsRequest {
            chain: r.state.document(),
            coins: &sorted.plain,
            required: &required,
            tip_height: r.state.height(),
            outputs: &outputs,
            records: &records,
            fee: None,
        },
        &key.spend_signer(),
        &Permissive,
    )
    .map_err(|e| e.to_string())?;
    let mut carried_in = Default::default();
    r.assets
        .check(&spend.tx, &mut carried_in)
        .map_err(|e| format!("the grant would break the assets rule: {e}"))?;
    Ok(spend)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_key, replay};
    use bitcoin::OutPoint;
    use nostr_bbs_poker_citizen::chain::{script_of, DREAMLAB_TXBT4};

    const TXBT4_BLOCKS: &[u8] =
        include_bytes!("../../nostr-bbs-poker-citizen/src/testdata/txbt4-blocks.dat");

    fn key(byte: u8) -> AgentKey {
        parse_key(&hex::encode([byte; 32])).unwrap()
    }

    fn coin(seed: u8, value: u64) -> Coin {
        Coin {
            outpoint: format!("{}:0", hex::encode([seed; 32])).parse().unwrap(),
            value,
            height: 1,
            coinbase: false,
        }
    }

    fn policy(sats: u64, asset: Option<(Txid, u64)>) -> Policy {
        Policy {
            sats,
            asset,
            per_address_secs: 24 * 3_600,
            per_hour: 2,
        }
    }

    #[test]
    fn the_ledger_reads_sidestr_agents_json() {
        let saved = r#"{"paid":{"5120ab":1758700000},"recent":[1758700000]}"#;
        let l = Ledger::parse(saved).unwrap();
        assert_eq!(l.paid["5120ab"], 1_758_700_000);
        assert_eq!(l.recent, VecDeque::from([1_758_700_000]));
        assert_eq!(Ledger::parse(&l.to_json()).unwrap(), l);
        assert_eq!(Ledger::parse("{}").unwrap(), Ledger::default());
        assert!(Ledger::parse("not json").is_err());
    }

    #[test]
    fn one_grant_per_script_per_window_and_so_many_an_hour() {
        let p = policy(1_000, None);
        let mut l = Ledger::default();
        let t = 1_000_000;
        assert_eq!(l.judge("a", t, &p), Ok(()));
        l.record("a", t);
        assert_eq!(l.judge("a", t + 60, &p), Err(Refusal::PaidWithinWindow));
        assert_eq!(l.judge("b", t + 60, &p), Ok(()));
        l.record("b", t + 60);
        assert_eq!(l.judge("c", t + 120, &p), Err(Refusal::HourlyLimit));
        // an hour on, the first grant no longer counts
        assert_eq!(l.judge("c", t + 3_600, &p), Ok(()));
        assert_eq!(l.recent.len(), 1);
        // a day on, "a" may be paid again
        assert_eq!(l.judge("a", t + 24 * 3_600, &p), Ok(()));
    }

    #[test]
    fn a_sats_grant_builds_on_the_blake2b_chain() {
        let r = replay(DREAMLAB_TXBT4.document().unwrap(), TXBT4_BLOCKS, None).unwrap();
        let k = key(0x44);
        let to = script_of(&key(0x55).pubkey().to_string()).unwrap();
        let s = build_grant(&k, &r, &[coin(0xab, 50_000)], &to, &policy(1_000, None)).unwrap();
        assert_eq!(s.tx.output[0].script_pubkey, to);
        assert_eq!(s.tx.output[0].value.to_sat(), 1_000);
        assert!(s.fee > 0);
        // short of coins, to itself, to nobody, or for nothing: refused
        assert!(build_grant(&k, &r, &[coin(0xab, 500)], &to, &policy(1_000, None)).is_err());
        assert!(build_grant(
            &k,
            &r,
            &[coin(0xab, 50_000)],
            &k.script(),
            &policy(1_000, None)
        )
        .unwrap_err()
        .contains("not a destination"));
        assert!(build_grant(&k, &r, &[coin(0xab, 50_000)], &to, &policy(0, None)).is_err());
        let burn = ScriptBuf::new_op_return([0u8; 4]);
        assert!(build_grant(&k, &r, &[coin(0xab, 50_000)], &burn, &policy(1_000, None)).is_err());
    }

    /// Issue an asset to the faucet key, then grant units of it with sats:
    /// output 0 carries the units to the member, output 1 the asset change.
    #[test]
    fn an_asset_grant_moves_units_and_returns_change() {
        let base = replay(DREAMLAB_TXBT4.document().unwrap(), TXBT4_BLOCKS, None).unwrap();
        let k = key(0x44);
        let issue =
            crate::build_issue(&k, &base, &[coin(0xab, 80_000)], "BLAKES7", 1_000, 0).unwrap();
        let id = issue.txid;
        let height = base.state.height() + 1;
        let mut view = base.assets.clone();
        view.apply_transactions(std::slice::from_ref(&issue.tx), height);
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
        let r = Replayed {
            state: replay(DREAMLAB_TXBT4.document().unwrap(), TXBT4_BLOCKS, None)
                .unwrap()
                .state,
            assets: view,
        };
        let to = script_of(&key(0x55).pubkey().to_string()).unwrap();
        let s = build_grant(&k, &r, &mine, &to, &policy(1_000, Some((id, 100)))).unwrap();
        assert_eq!(s.tx.output[0].script_pubkey, to);
        assert_eq!(s.tx.output[0].value.to_sat(), CARRIER);
        assert_eq!(s.tx.output[1].script_pubkey, k.script());
        assert_eq!(s.tx.output[2].script_pubkey, to);
        assert_eq!(s.tx.output[2].value.to_sat(), 1_000);
        let mut after = r.assets.clone();
        after.apply_transactions(std::slice::from_ref(&s.tx), height + 1);
        let got = after
            .carried(&OutPoint {
                txid: s.txid,
                vout: 0,
            })
            .unwrap();
        assert_eq!(got[&id], 100);
        let back = after
            .carried(&OutPoint {
                txid: s.txid,
                vout: 1,
            })
            .unwrap();
        assert_eq!(back[&id], 900);
        // more than held is refused
        assert!(build_grant(&k, &r, &mine, &to, &policy(1_000, Some((id, 1_001)))).is_err());
    }
}
