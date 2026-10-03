//! The house's book: what members owe it, what it owes members, and what it
//! paid out today. Saved as JSON after every change, so a restart forgets
//! nothing that money depends on.
//!
//! A debt is a settled hand's transfer not yet seen on the chain. One the
//! member owes is *claimed* once the member reports a transfer id and
//! *cleared* once the chain shows a `hand:<root>` transfer of at least the
//! amount to the house's script. One the house owes is cleared when the
//! house's own transfer is accepted by the producer.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The ledger's file format version.
pub const VERSION: u32 = 1;
/// Settled hands kept for the record.
const HISTORY_CAP: usize = 500;

/// A member's report that a transfer was sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    /// The transfer's id as the member reported it.
    pub txid: String,
    /// When it was reported, unix seconds.
    pub at: u64,
}

/// A settled hand the member has not yet paid for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owed {
    /// The member's pubkey, 64 hex.
    pub hero: String,
    /// Who is owed: the house's pubkey, or the other member's for a hand
    /// the house only dealt.
    pub to: String,
    /// The hand's root.
    pub root: String,
    /// Base units owed.
    pub amount: u64,
    /// When the hand ended, unix seconds.
    pub since: u64,
    /// The member's report, once made.
    #[serde(default)]
    pub claimed: Option<Claim>,
}

/// A settled hand the house has not yet paid for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owing {
    /// The member's pubkey, 64 hex.
    pub hero: String,
    /// The hand's root.
    pub root: String,
    /// Base units owed.
    pub amount: u64,
    /// When the hand ended, unix seconds.
    pub since: u64,
    /// Payment attempts so far.
    #[serde(default)]
    pub attempts: u32,
    /// When the last attempt was made, unix seconds.
    #[serde(default)]
    pub last_attempt: u64,
    /// Why the last attempt failed.
    #[serde(default)]
    pub last_error: Option<String>,
}

/// A hand that was settled, for the record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settled {
    /// The member.
    pub hero: String,
    /// The hand's root.
    pub root: String,
    /// The hero's net, positive when the house paid.
    pub hero_net: i64,
    /// The transfer that settled it, once known.
    #[serde(default)]
    pub txid: Option<String>,
    /// When the hand ended.
    pub at: u64,
}

/// The book.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    /// File format version.
    pub version: u32,
    /// Hands members owe for.
    #[serde(default)]
    pub owed: Vec<Owed>,
    /// Hands the house owes for.
    #[serde(default)]
    pub owing: Vec<Owing>,
    /// Base units the house paid out, by day number (unix seconds / 86 400).
    #[serde(default)]
    pub paid: BTreeMap<u64, u64>,
    /// Hands dealt.
    #[serde(default)]
    pub hands: u64,
    /// Settled hands, newest first, capped.
    #[serde(default)]
    pub history: Vec<Settled>,
}

impl Default for Ledger {
    fn default() -> Self {
        Self {
            version: VERSION,
            owed: Vec::new(),
            owing: Vec::new(),
            paid: BTreeMap::new(),
            hands: 0,
            history: Vec::new(),
        }
    }
}

/// The day number of a unix time.
pub fn day_of(now: u64) -> u64 {
    now / 86_400
}

impl Ledger {
    /// Parse a saved ledger.
    pub fn parse(json: &str) -> Result<Self, String> {
        let l: Self = serde_json::from_str(json).map_err(|e| format!("ledger: {e}"))?;
        if l.version != VERSION {
            return Err(format!("ledger version {} is not {VERSION}", l.version));
        }
        Ok(l)
    }

    /// The ledger as JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("ledger serialises")
    }

    /// Base units paid out on the day of `now`.
    pub fn paid_today(&self, now: u64) -> u64 {
        self.paid.get(&day_of(now)).copied().unwrap_or(0)
    }

    /// What the house owes in all, cleared or not.
    pub fn owing_total(&self) -> u64 {
        self.owing.iter().map(|o| o.amount).sum()
    }

    /// Record a settled hand.
    pub fn settled(&mut self, hero: &str, root: &str, hero_net: i64, at: u64) {
        self.hands += 1;
        self.history.insert(
            0,
            Settled {
                hero: hero.to_string(),
                root: root.to_string(),
                hero_net,
                txid: None,
                at,
            },
        );
        self.history.truncate(HISTORY_CAP);
    }

    fn note_txid(&mut self, root: &str, txid: &str) {
        if let Some(s) = self.history.iter_mut().find(|s| s.root == root) {
            s.txid = Some(txid.to_string());
        }
    }

    /// The member reported paying for a hand.
    pub fn claim(&mut self, hero: &str, root: &str, txid: &str, now: u64) -> bool {
        match self
            .owed
            .iter_mut()
            .find(|o| o.hero == hero && o.root == root)
        {
            Some(o) => {
                o.claimed = Some(Claim {
                    txid: txid.to_string(),
                    at: now,
                });
                true
            }
            None => false,
        }
    }

    /// The chain shows `hand:<root>` transfers (root → recipient pubkey →
    /// base units): clear what they pay for. Returns the roots cleared.
    pub fn payments_seen(&mut self, paid: &BTreeMap<String, BTreeMap<String, u64>>) -> Vec<String> {
        let mut cleared = Vec::new();
        self.owed.retain(|o| {
            let done = paid
                .get(&o.root)
                .and_then(|by_to| by_to.get(&o.to))
                .is_some_and(|&n| n >= o.amount);
            if done {
                cleared.push(o.root.clone());
            }
            !done
        });
        for root in &cleared {
            let txid = self
                .history
                .iter()
                .find(|s| &s.root == root)
                .and_then(|s| s.txid.clone());
            if txid.is_none() {
                self.note_txid(root, "seen on chain");
            }
        }
        cleared
    }

    /// The house's transfer for a hand was accepted.
    pub fn house_paid(&mut self, root: &str, txid: &str, now: u64) -> Option<u64> {
        let i = self.owing.iter().position(|o| o.root == root)?;
        let o = self.owing.remove(i);
        *self.paid.entry(day_of(now)).or_default() += o.amount;
        self.note_txid(root, txid);
        Some(o.amount)
    }

    /// The house's transfer for a hand failed; keep owing, remember why.
    pub fn house_pay_failed(&mut self, root: &str, why: &str, now: u64) {
        if let Some(o) = self.owing.iter_mut().find(|o| o.root == root) {
            o.attempts += 1;
            o.last_attempt = now;
            o.last_error = Some(why.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_refuses_another_version() {
        let mut l = Ledger::default();
        l.settled("h", "r", -5, 100);
        l.owed.push(Owed {
            hero: "h".into(),
            to: "c".into(),
            root: "r".into(),
            amount: 5,
            since: 100,
            claimed: None,
        });
        let back = Ledger::parse(&l.to_json()).unwrap();
        assert_eq!(back, l);
        let other = l.to_json().replace("\"version\": 1", "\"version\": 2");
        assert!(Ledger::parse(&other).is_err());
    }

    #[test]
    fn claims_clear_on_chain_and_payouts_count_against_the_day() {
        let mut l = Ledger::default();
        l.settled("h", "r1", -5, 100);
        l.owed.push(Owed {
            hero: "h".into(),
            to: "c".into(),
            root: "r1".into(),
            amount: 5,
            since: 100,
            claimed: None,
        });
        assert!(l.claim("h", "r1", "tx", 120));
        assert!(!l.claim("h", "nope", "tx", 120));
        assert_eq!(l.owed[0].claimed.as_ref().unwrap().txid, "tx");
        // an underpayment, or a payment to someone else, does not clear
        let mut paid: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        paid.entry("r1".into()).or_default().insert("c".into(), 4);
        assert!(l.payments_seen(&paid).is_empty());
        paid.entry("r1".into()).or_default().insert("x".into(), 5);
        assert!(l.payments_seen(&paid).is_empty());
        paid.entry("r1".into()).or_default().insert("c".into(), 5);
        assert_eq!(l.payments_seen(&paid), ["r1"]);
        assert!(l.owed.is_empty());

        l.settled("h", "r2", 7, 200);
        l.owing.push(Owing {
            hero: "h".into(),
            root: "r2".into(),
            amount: 7,
            since: 200,
            attempts: 0,
            last_attempt: 0,
            last_error: None,
        });
        l.house_pay_failed("r2", "no fee coins", 210);
        assert_eq!(l.owing[0].attempts, 1);
        assert_eq!(l.house_paid("r2", "txb", 86_400 + 5), Some(7));
        assert_eq!(l.paid_today(86_400 + 5), 7);
        assert_eq!(l.paid_today(5), 0);
        assert!(l.owing.is_empty());
        assert_eq!(l.history[0].txid.as_deref(), Some("txb"));
        assert_eq!(l.hands, 2);
    }
}
