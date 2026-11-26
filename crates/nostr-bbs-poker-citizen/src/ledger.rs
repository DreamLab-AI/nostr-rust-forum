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

/// A payout transfer the house has signed for a hand: kept with the debt so
/// every retry sends these same bytes, never a second transfer for the same
/// hand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    /// The signed transaction, hex.
    pub hex: String,
    /// Its id.
    pub txid: String,
    /// The coins it spends, `txid:vout`.
    pub outpoints: Vec<String>,
}

/// Why a signed payout is being replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    /// The chain shows its coins spent by something else and the transfer
    /// never landed: nothing of ours was spent.
    SpentElsewhere,
    /// The chain includes it and the assets rule rejected it: its coins
    /// were really spent and the asset did not move.
    Invalid,
}

/// What became of a debt whose payout is being replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replaced {
    /// It will be paid again, through the same checks as any payout.
    Queued,
    /// It has been replaced too often to trust automatically: the debt
    /// stays, and no payout is signed for it until an operator looks.
    Halted,
}

/// A transfer the assets rule rejects may be replaced once; a second
/// rejection means the cause is systematic and each retry would burn
/// another payout.
pub const MAX_INVALID_REBUILDS: u32 = 1;
/// Replacements of any cause, per debt.
pub const MAX_REBUILDS: u32 = 3;
/// Definite refusals of the same bytes between operator alerts.
pub const REFUSALS_PER_ALERT: u32 = 5;

/// What the chain shows of a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxOnChain {
    /// Not in any block.
    NotSeen,
    /// In a block, and the assets rule accepted it.
    Valid,
    /// In a block, but the assets rule rejected it: the coins it spent are
    /// gone and the asset it meant to move did not move.
    Invalid,
}

/// What to do about a payout already signed for a hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resume {
    /// The chain shows the transfer and accepted it: nothing to send; the
    /// debt clears when the payment is seen.
    OnChain,
    /// Send the same bytes again.
    Resend,
    /// Its coins were spent by something else and it never landed, or it
    /// landed and the assets rule rejected it: sign a new transfer.
    Rebuild,
}

impl Pending {
    /// What to do with this payout given what the chain shows: whether it
    /// holds the transfer, and whether every coin the transfer spends is
    /// still unspent. Only proof that the coins went elsewhere, or that the
    /// transfer was included and rejected, permits a new transfer; a quiet
    /// chain, a lost response or a slow block are all answered by the same
    /// bytes.
    pub fn resume(&self, on_chain: TxOnChain, inputs_unspent: bool) -> Resume {
        match on_chain {
            TxOnChain::Valid => Resume::OnChain,
            TxOnChain::Invalid => Resume::Rebuild,
            TxOnChain::NotSeen if inputs_unspent => Resume::Resend,
            TxOnChain::NotSeen => Resume::Rebuild,
        }
    }
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
    /// The signed payout, once one has been built.
    #[serde(default)]
    pub pending: Option<Pending>,
    /// Replacements of the signed payout so far.
    #[serde(default)]
    pub rebuilds: u32,
    /// Of those, replacements after the assets rule rejected the transfer.
    #[serde(default)]
    pub invalid_rebuilds: u32,
    /// Times the producer has definitely refused the current bytes.
    #[serde(default)]
    pub refusals: u32,
    /// Why no payout is signed for this debt any more, if so: it waits
    /// for an operator.
    #[serde(default)]
    pub halted: Option<String>,
    /// When the producer accepted the payout, unix seconds. The debt stays
    /// until the chain shows the payment, but from here the amount counts
    /// as paid out against the day, not as owed.
    #[serde(default)]
    pub accepted_at: Option<u64>,
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

    /// What the house still has to pay out: debts whose payout the producer
    /// has not accepted (those it has are counted in `paid`).
    pub fn owing_total(&self) -> u64 {
        self.owing
            .iter()
            .filter(|o| o.accepted_at.is_none())
            .fold(0u64, |sum, o| sum.saturating_add(o.amount))
    }

    /// Record a settled hand.
    pub fn settled(&mut self, hero: &str, root: &str, hero_net: i64, at: u64) {
        self.hands = self.hands.saturating_add(1);
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
    /// base units): clear what they pay for. What a member owes clears when
    /// the house's script was paid; what the house owes clears when the
    /// member was paid, which is how a payout accepted by the producer but
    /// not recorded before a crash is found already made, rather than made
    /// twice. Such a payout counts against the day of `now`. Returns the
    /// roots cleared.
    pub fn payments_seen(
        &mut self,
        paid: &BTreeMap<String, BTreeMap<String, u64>>,
        now: u64,
    ) -> Vec<String> {
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
        let mut paid_out = 0u64;
        self.owing.retain(|o| {
            let done = paid
                .get(&o.root)
                .and_then(|by_to| by_to.get(&o.hero))
                .is_some_and(|&n| n >= o.amount);
            if done {
                cleared.push(o.root.clone());
                if o.accepted_at.is_none() {
                    paid_out = paid_out.saturating_add(o.amount);
                }
            }
            !done
        });
        if paid_out > 0 {
            self.add_paid(now, paid_out);
        }
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

    /// The producer accepted the house's transfer for a hand. The debt
    /// stays, with its signed transfer, until the chain shows the payment
    /// ([`Ledger::payments_seen`]): acceptance is a promise, not a block.
    /// From here the amount counts against the day's payouts. Returns the
    /// amount the first time, `None` when the hand is not owed or this was
    /// already recorded.
    pub fn house_paid(&mut self, root: &str, txid: &str, now: u64) -> Option<u64> {
        let o = self.owing.iter_mut().find(|o| o.root == root)?;
        if o.accepted_at.is_some() {
            return None;
        }
        o.accepted_at = Some(now);
        o.last_attempt = now;
        let amount = o.amount;
        self.add_paid(now, amount);
        self.note_txid(root, txid);
        Some(amount)
    }

    /// The house's transfer for a hand failed; keep owing, remember why.
    pub fn house_pay_failed(&mut self, root: &str, why: &str, now: u64) {
        if let Some(o) = self.owing.iter_mut().find(|o| o.root == root) {
            o.attempts = o.attempts.saturating_add(1);
            o.last_attempt = now;
            o.last_error = Some(why.to_string());
        }
    }

    fn add_paid(&mut self, now: u64, amount: u64) {
        let day = self.paid.entry(day_of(now)).or_default();
        *day = day.saturating_add(amount);
    }

    /// The house has signed its payout for `root`: keep it with the debt,
    /// before it is sent, so retries and a restarted house send the same
    /// transfer. `false` when `root` is no longer owed, in which case
    /// nothing may be sent.
    pub fn pay_prepared(&mut self, root: &str, pending: Pending, now: u64) -> bool {
        let Some(o) = self
            .owing
            .iter_mut()
            .find(|o| o.root == root && o.halted.is_none())
        else {
            return false;
        };
        o.attempts = o.attempts.saturating_add(1);
        o.last_attempt = now;
        o.last_error = Some("sent; not yet shown on the chain".into());
        o.pending = Some(pending);
        true
    }

    /// The signed payout kept for `root`, if any.
    pub fn pending_of(&self, root: &str) -> Option<&Pending> {
        self.owing
            .iter()
            .find(|o| o.root == root)
            .and_then(|o| o.pending.as_ref())
    }

    /// Replace the signed payout for `root`: drop it, owe the debt as
    /// unsent again, and leave the new transfer to be signed when the debt
    /// next comes up for payment, through the daily-cap check like any
    /// other. Nothing is signed here.
    ///
    /// After [`Cause::SpentElsewhere`] the payout never landed, so what it
    /// counted against the day is given back. After [`Cause::Invalid`] its
    /// coins were really spent and it stays counted. A debt replaced more
    /// than [`MAX_INVALID_REBUILDS`] times for rejection, or
    /// [`MAX_REBUILDS`] times in all, is halted.
    pub fn rebuild(&mut self, root: &str, cause: Cause, now: u64) -> Option<Replaced> {
        let o = self.owing.iter_mut().find(|o| o.root == root)?;
        let was = o.pending.take().map(|p| p.txid);
        let credit = o.accepted_at.take().map(|at| (at, o.amount));
        o.last_attempt = now;
        o.refusals = 0;
        o.rebuilds = o.rebuilds.saturating_add(1);
        if cause == Cause::Invalid {
            o.invalid_rebuilds = o.invalid_rebuilds.saturating_add(1);
        }
        let too_often = o.invalid_rebuilds > MAX_INVALID_REBUILDS || o.rebuilds > MAX_REBUILDS;
        let replaced = if too_often {
            o.halted = Some(format!(
                "payout {} replaced {} times ({} rejected by the assets rule); waiting for an operator",
                was.as_deref().unwrap_or("?"),
                o.rebuilds,
                o.invalid_rebuilds
            ));
            Replaced::Halted
        } else {
            Replaced::Queued
        };
        if cause == Cause::SpentElsewhere {
            if let Some((at, amount)) = credit {
                if let Some(day) = self.paid.get_mut(&day_of(at)) {
                    *day = day.saturating_sub(amount);
                }
            }
        }
        Some(replaced)
    }

    /// Why `root` is halted, if it is.
    pub fn halted(&self, root: &str) -> Option<&str> {
        self.owing
            .iter()
            .find(|o| o.root == root)
            .and_then(|o| o.halted.as_deref())
    }

    /// The producer definitely refused the house's payout for `root`.
    /// Returns how many times it now has, counting only a payout it has not
    /// accepted (a refusal of one already accepted is the producer
    /// recognising it).
    pub fn pay_refused(&mut self, root: &str, why: &str, now: u64) -> u32 {
        self.house_pay_failed(root, why, now);
        match self
            .owing
            .iter_mut()
            .find(|o| o.root == root && o.accepted_at.is_none())
        {
            Some(o) => {
                o.refusals = o.refusals.saturating_add(1);
                o.refusals
            }
            None => 0,
        }
    }

    /// Record a hand that was voided, for the record. It moves no funds and
    /// is not a hand dealt to a conclusion, so it is not counted in
    /// [`Ledger::hands`]; `commit` stands where a root would.
    pub fn voided(&mut self, hero: &str, commit: &str, why: &str, at: u64) {
        self.history.insert(
            0,
            Settled {
                hero: hero.to_string(),
                root: commit.to_string(),
                hero_net: 0,
                txid: Some(format!("voided: {why}")),
                at,
            },
        );
        self.history.truncate(HISTORY_CAP);
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
        assert!(l.payments_seen(&paid, 130).is_empty());
        paid.entry("r1".into()).or_default().insert("x".into(), 5);
        assert!(l.payments_seen(&paid, 130).is_empty());
        paid.entry("r1".into()).or_default().insert("c".into(), 5);
        assert_eq!(l.payments_seen(&paid, 130), ["r1"]);
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
            pending: None,
            accepted_at: None,
            rebuilds: 0,
            invalid_rebuilds: 0,
            refusals: 0,
            halted: None,
        });
        l.house_pay_failed("r2", "no fee coins", 210);
        assert_eq!(l.owing[0].attempts, 1);
        assert_eq!(l.house_paid("r2", "txb", 86_400 + 5), Some(7));
        assert_eq!(l.paid_today(86_400 + 5), 7);
        assert_eq!(l.paid_today(5), 0);
        // accepted is not confirmed: the debt stays until the chain shows it,
        // counted as paid out and no longer as owed
        assert_eq!(l.owing.len(), 1);
        assert_eq!(l.owing_total(), 0);
        assert_eq!(l.house_paid("r2", "txb", 86_400 + 9), None, "once");
        assert_eq!(l.history[0].txid.as_deref(), Some("txb"));
        assert_eq!(l.hands, 2);
    }

    #[test]
    fn a_payout_the_chain_already_shows_is_cleared_not_paid_twice() {
        let mut l = Ledger::default();
        l.settled("h", "r2", 7, 200);
        l.owing.push(Owing {
            hero: "h".into(),
            root: "r2".into(),
            amount: 7,
            since: 200,
            attempts: 1,
            last_attempt: 210,
            last_error: None,
            pending: None,
            accepted_at: None,
            rebuilds: 0,
            invalid_rebuilds: 0,
            refusals: 0,
            halted: None,
        });
        let mut paid: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        // a short payment, or one to someone else, clears nothing
        paid.entry("r2".into()).or_default().insert("h".into(), 6);
        paid.entry("r2".into()).or_default().insert("x".into(), 7);
        assert!(l.payments_seen(&paid, 86_400 + 9).is_empty());
        assert_eq!(l.owing.len(), 1);
        paid.entry("r2".into()).or_default().insert("h".into(), 7);
        assert_eq!(l.payments_seen(&paid, 86_400 + 9), ["r2"]);
        assert!(l.owing.is_empty());
        assert_eq!(l.paid_today(86_400 + 9), 7, "it counts against the day");
        assert_eq!(l.history[0].txid.as_deref(), Some("seen on chain"));
    }

    fn pending(txid: &str) -> Pending {
        Pending {
            hex: format!("hex-{txid}"),
            txid: txid.into(),
            outpoints: vec![format!("{}:0", "e".repeat(64))],
        }
    }

    #[test]
    fn a_signed_payout_is_resent_until_the_chain_proves_its_coins_went_elsewhere() {
        use TxOnChain::{Invalid, NotSeen, Valid};
        let p = pending("t1");
        // no evidence either way: the same bytes again
        assert_eq!(p.resume(NotSeen, true), Resume::Resend);
        // on the chain and accepted: nothing to send
        assert_eq!(p.resume(Valid, true), Resume::OnChain);
        assert_eq!(p.resume(Valid, false), Resume::OnChain);
        // coins spent by something else and the transfer never landed
        assert_eq!(p.resume(NotSeen, false), Resume::Rebuild);
        // on the chain but rejected by the assets rule: the debt must not
        // wait on a transfer that can never pay it
        assert_eq!(p.resume(Invalid, false), Resume::Rebuild);
        assert_eq!(p.resume(Invalid, true), Resume::Rebuild);
    }

    #[test]
    fn a_payout_is_prepared_only_for_a_hand_still_owed() {
        let mut l = Ledger::default();
        assert!(!l.pay_prepared("r", pending("t1"), 10), "nothing owed");
        l.owing.push(Owing {
            hero: "h".into(),
            root: "r".into(),
            amount: 7,
            since: 1,
            attempts: 0,
            last_attempt: 0,
            last_error: None,
            pending: None,
            accepted_at: None,
            rebuilds: 0,
            invalid_rebuilds: 0,
            refusals: 0,
            halted: None,
        });
        assert!(l.pay_prepared("r", pending("t1"), 10));
        assert_eq!(l.pending_of("r").unwrap().txid, "t1");
        assert_eq!((l.owing[0].attempts, l.owing[0].last_attempt), (1, 10));
        // a failure keeps the signed transfer
        l.house_pay_failed("r", "producer down", 20);
        assert_eq!(l.pending_of("r").unwrap().txid, "t1");
        l.rebuild("r", Cause::SpentElsewhere, 25);
        assert!(l.pending_of("r").is_none());
        assert!(l.pay_prepared("r", pending("t1"), 30));
        l.house_paid("r", "t1", 30);
        // accepted but unconfirmed is still owed: the same bytes may go again
        assert!(l.pay_prepared("r", pending("t1"), 40));
        // until the chain shows it
        let mut paid = BTreeMap::new();
        paid.insert("r".to_string(), BTreeMap::from([("h".to_string(), 7u64)]));
        assert_eq!(l.payments_seen(&paid, 50), ["r"]);
        assert!(!l.pay_prepared("r", pending("t2"), 60), "already paid");
        assert_eq!(l.paid_today(50), 7, "counted once, at acceptance");
    }

    #[test]
    fn a_void_is_recorded_without_counting_a_hand_or_moving_funds() {
        let mut l = Ledger::default();
        l.voided("h", "commit", "restart", 5);
        assert_eq!(l.hands, 0);
        assert_eq!(l.history[0].hero_net, 0);
        assert_eq!(l.history[0].txid.as_deref(), Some("voided: restart"));
        assert!(l.owed.is_empty() && l.owing.is_empty());
    }

    #[test]
    fn totals_saturate_rather_than_wrap() {
        let mut l = Ledger::default();
        for r in ["a", "b"] {
            l.owing.push(Owing {
                hero: "h".into(),
                root: r.into(),
                amount: u64::MAX,
                since: 1,
                attempts: u32::MAX,
                last_attempt: 0,
                last_error: None,
                pending: None,
                accepted_at: None,
                rebuilds: 0,
                invalid_rebuilds: 0,
                refusals: 0,
                halted: None,
            });
        }
        assert_eq!(l.owing_total(), u64::MAX);
        l.house_pay_failed("a", "x", 1);
        assert_eq!(l.owing[0].attempts, u32::MAX);
    }

    #[test]
    fn a_payout_that_never_lands_is_owed_again_and_no_longer_counted_as_paid() {
        let mut l = Ledger::default();
        l.owing.push(Owing {
            hero: "h".into(),
            root: "r".into(),
            amount: 7,
            since: 1,
            attempts: 0,
            last_attempt: 0,
            last_error: None,
            pending: None,
            accepted_at: None,
            rebuilds: 0,
            invalid_rebuilds: 0,
            refusals: 0,
            halted: None,
        });
        assert!(l.pay_prepared("r", pending("t1"), 100));
        l.house_paid("r", "t1", 100);
        assert_eq!((l.owing_total(), l.paid_today(100)), (0, 7));
        l.rebuild("r", Cause::SpentElsewhere, 101);
        assert_eq!((l.owing_total(), l.paid_today(100)), (7, 0));
    }
}
