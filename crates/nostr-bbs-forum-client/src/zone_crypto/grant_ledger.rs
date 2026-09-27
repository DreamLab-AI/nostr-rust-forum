//! "Granted from this device" ledger for zone-key grants (ADR-2016).
//!
//! The Encryption tab records each member a grant reached, per
//! `(zone, epoch)`, so "Grant to members missing it" skips them. Relay acks for
//! one batch arrive together, and the previous read → add one → write against
//! IndexedDB let concurrent records overwrite each other, silently dropping a
//! random subset of members who did get the key.
//!
//! Here the in-memory set is authoritative: a record mutates it without
//! awaiting in between, then persists a snapshot of the whole set and re-writes
//! until the stored snapshot matches memory. Whichever write completes last is
//! followed by that check, so storage ends equal to memory whatever order the
//! writes finish in.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Mutex;

/// `zone_kv` id prefix: `grants_sent:<zone>:<epoch>`.
pub const KV_GRANTS_SENT: &str = "grants_sent";

/// Storage id for the `(zone, epoch)` grant set.
pub fn ledger_id(zone: &str, epoch: u32) -> String {
    format!("{KV_GRANTS_SENT}:{zone}:{epoch}")
}

/// Async key/value storage behind the ledger (IndexedDB in the browser).
/// Failures are swallowed by implementations: the ledger is a convenience
/// record, and a lost write is repaired by the next record for that set.
#[allow(async_fn_in_trait)]
pub trait GrantKv {
    /// Stored JSON for `id`, or `None` when absent or unreadable.
    async fn get(&self, id: &str) -> Option<String>;
    /// Store `json` under `id`; returns whether the write succeeded.
    async fn put(&self, id: &str, json: &str) -> bool;
}

#[derive(Default)]
struct Inner {
    sets: HashMap<String, BTreeSet<String>>,
    loaded: HashSet<String>,
}

/// Per-device record of which members each `(zone, epoch)` was granted to.
#[derive(Default)]
pub struct GrantLedger {
    inner: Mutex<Inner>,
}

/// Upper bound on persist rounds for one record: each extra round is caused by
/// a concurrent record, so this only trips under a pathological flood.
const MAX_PERSIST_ROUNDS: usize = 16;

impl GrantLedger {
    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        // Never held across an await, so a poisoned lock can only follow a
        // panic inside `f`; recover the data rather than lose the ledger.
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut g)
    }

    async fn ensure_loaded<K: GrantKv>(&self, kv: &K, id: &str) {
        if self.with(|i| i.loaded.contains(id)) {
            return;
        }
        let stored: Vec<String> = kv
            .get(id)
            .await
            .and_then(|j| serde_json::from_str(&j).ok())
            .unwrap_or_default();
        // Union, not replace: records made while this load was in flight are
        // already in memory and must survive it.
        self.with(|i| {
            i.sets.entry(id.to_string()).or_default().extend(stored);
            i.loaded.insert(id.to_string());
        });
    }

    fn snapshot(&self, id: &str) -> BTreeSet<String> {
        self.with(|i| i.sets.get(id).cloned().unwrap_or_default())
    }

    /// Members `(zone, epoch)` was granted to from this device.
    pub async fn sent<K: GrantKv>(&self, kv: &K, zone: &str, epoch: u32) -> HashSet<String> {
        let id = ledger_id(zone, epoch);
        self.ensure_loaded(kv, &id).await;
        self.snapshot(&id).into_iter().collect()
    }

    /// Record that `(zone, epoch)` reached `recipients`, and persist the set.
    pub async fn record<K: GrantKv>(&self, kv: &K, zone: &str, epoch: u32, recipients: &[String]) {
        let id = ledger_id(zone, epoch);
        self.ensure_loaded(kv, &id).await;
        self.with(|i| {
            i.sets
                .entry(id.clone())
                .or_default()
                .extend(recipients.iter().cloned());
        });
        for _ in 0..MAX_PERSIST_ROUNDS {
            let snap = self.snapshot(&id);
            let Ok(json) = serde_json::to_string(&snap) else {
                return;
            };
            if !kv.put(&id, &json).await {
                return;
            }
            // The set only grows, so an equal length means an equal set.
            if self.with(|i| i.sets.get(&id).map_or(0, BTreeSet::len)) == snap.len() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// Pending for `n` polls, so concurrent tasks interleave at every await.
    struct YieldN(u32);
    impl Future for YieldN {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.0 == 0 {
                return Poll::Ready(());
            }
            self.0 -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    /// In-memory KV whose reads and writes take a varying number of polls, so
    /// writes started in one order can land in another.
    #[derive(Default)]
    struct SlowKv {
        data: RefCell<HashMap<String, String>>,
        calls: Cell<u32>,
    }
    impl SlowKv {
        fn delay(&self) -> u32 {
            let n = self.calls.get();
            self.calls.set(n + 1);
            (n * 7 + 3) % 5
        }
        fn stored(&self, id: &str) -> BTreeSet<String> {
            self.data
                .borrow()
                .get(id)
                .map(|j| serde_json::from_str(j).unwrap())
                .unwrap_or_default()
        }
    }
    impl GrantKv for SlowKv {
        async fn get(&self, id: &str) -> Option<String> {
            YieldN(self.delay()).await;
            self.data.borrow().get(id).cloned()
        }
        async fn put(&self, id: &str, json: &str) -> bool {
            YieldN(self.delay()).await;
            self.data
                .borrow_mut()
                .insert(id.to_string(), json.to_string());
            true
        }
    }

    fn pks(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("{i:064x}")).collect()
    }

    /// The previous algorithm: read, add one, write back — with no ledger.
    async fn naive_record(kv: &SlowKv, id: &str, pk: &str) {
        let mut all: BTreeSet<String> = kv
            .get(id)
            .await
            .and_then(|j| serde_json::from_str(&j).ok())
            .unwrap_or_default();
        all.insert(pk.to_string());
        kv.put(id, &serde_json::to_string(&all).unwrap()).await;
    }

    #[test]
    fn naive_read_modify_write_loses_concurrent_records() {
        // Guards the test harness: it must actually interleave, or the
        // concurrent test below would pass vacuously.
        let kv = SlowKv::default();
        let id = ledger_id("zone2", 1);
        let all = pks(8);
        futures::executor::block_on(futures::future::join_all(
            all.iter().map(|pk| naive_record(&kv, &id, pk)),
        ));
        assert!(
            kv.stored(&id).len() < all.len(),
            "harness did not interleave"
        );
    }

    #[test]
    fn concurrent_records_all_persist() {
        let kv = SlowKv::default();
        let ledger = GrantLedger::default();
        let all = pks(8);
        futures::executor::block_on(futures::future::join_all(
            all.iter()
                .map(|pk| ledger.record(&kv, "zone2", 1, std::slice::from_ref(pk))),
        ));
        let want: BTreeSet<String> = all.iter().cloned().collect();
        assert_eq!(kv.stored(&ledger_id("zone2", 1)), want);
        let sent = futures::executor::block_on(ledger.sent(&kv, "zone2", 1));
        assert_eq!(sent.len(), 8);
    }

    #[test]
    fn load_unions_with_records_made_meanwhile() {
        let kv = SlowKv::default();
        let id = ledger_id("zone3", 1);
        kv.data
            .borrow_mut()
            .insert(id.clone(), serde_json::to_string(&pks(2)).unwrap());
        let ledger = GrantLedger::default();
        let extra = format!("{:064x}", 99);
        let (sent, ()) = futures::executor::block_on(futures::future::join(
            ledger.sent(&kv, "zone3", 1),
            ledger.record(&kv, "zone3", 1, std::slice::from_ref(&extra)),
        ));
        assert!(sent.len() >= 2);
        let stored = kv.stored(&id);
        assert_eq!(stored.len(), 3);
        assert!(stored.contains(&extra));
    }

    #[test]
    fn sets_are_per_zone_and_epoch() {
        let kv = SlowKv::default();
        let ledger = GrantLedger::default();
        let a = "ab".repeat(32);
        futures::executor::block_on(async {
            ledger
                .record(&kv, "zone2", 1, std::slice::from_ref(&a))
                .await;
            ledger.record(&kv, "zone2", 2, &pks(1)).await;
        });
        let e1 = futures::executor::block_on(ledger.sent(&kv, "zone2", 1));
        assert_eq!(e1, HashSet::from([a]));
        assert_eq!(kv.stored(&ledger_id("zone2", 2)).len(), 1);
        assert!(kv.stored(&ledger_id("zone3", 1)).is_empty());
    }

    #[test]
    fn failed_write_stops_without_looping() {
        struct FailKv;
        impl GrantKv for FailKv {
            async fn get(&self, _: &str) -> Option<String> {
                None
            }
            async fn put(&self, _: &str, _: &str) -> bool {
                false
            }
        }
        let ledger = GrantLedger::default();
        futures::executor::block_on(ledger.record(&FailKv, "zone4", 1, &pks(3)));
        // Memory still holds the record for this session.
        assert_eq!(
            futures::executor::block_on(ledger.sent(&FailKv, "zone4", 1)).len(),
            3
        );
    }
}
