//! What a member chose for each hand, kept across a reload.
//!
//! A finished hand's payment is held to what the member agreed to when they
//! sat or answered a challenge ([`Agreed`]), and the house's deal is checked
//! against the nonce they contributed. Both live only in memory while the
//! table is open; a reload mid-hand would lose them and the member could
//! not pay for a hand they had played. They are kept here, in the browser's
//! `localStorage`, keyed by the member's pubkey and by the hand's
//! commitment, for a day, and dropped once the hand is paid or voided.
//!
//! Storage sits behind [`KeyValue`] so the logic is tested without a
//! browser.

use std::collections::{BTreeMap, HashMap};

use nostr_bbs_poker::bind::Agreed;
use serde::{Deserialize, Serialize};

/// A hand's choices are kept this long, seconds: well past the ten minutes
/// a hand's messages stay acceptable.
pub const KEEP_SECS: u64 = 24 * 60 * 60;

/// A place to keep a string under a key.
pub trait KeyValue {
    /// Read `key`.
    ///
    /// # Errors
    ///
    /// A message when the store cannot be read.
    fn get(&self, key: &str) -> Result<Option<String>, String>;
    /// Write `key`.
    ///
    /// # Errors
    ///
    /// A message when the store cannot be written (private browsing, a full
    /// quota, storage switched off).
    fn set(&self, key: &str, value: &str) -> Result<(), String>;
}

/// The browser's `localStorage`.
#[derive(Debug, Clone, Copy, Default)]
pub struct BrowserStorage;

fn local() -> Result<web_sys::Storage, String> {
    web_sys::window()
        .ok_or_else(|| "no window".to_string())?
        .local_storage()
        .map_err(|_| "local storage is not allowed here".to_string())?
        .ok_or_else(|| "local storage is not available".to_string())
}

impl KeyValue for BrowserStorage {
    fn get(&self, key: &str) -> Result<Option<String>, String> {
        local()?
            .get_item(key)
            .map_err(|_| "local storage could not be read".to_string())
    }

    fn set(&self, key: &str, value: &str) -> Result<(), String> {
        local()?
            .set_item(key, value)
            .map_err(|_| "local storage is full or switched off".to_string())
    }
}

/// One hand's choices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The nonce we contributed to the shuffle.
    #[serde(default)]
    pub nonce: Option<String>,
    /// The table, opponent and kind of hand we agreed to.
    #[serde(default)]
    pub agreed: Option<Agreed>,
    /// When it was first kept, unix seconds.
    pub at: u64,
}

/// What a member chose, by hand commitment (or `challenge:<opponent>` until
/// the house names the hand).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Choices {
    entries: BTreeMap<String, Entry>,
}

impl Choices {
    /// The storage key for `me`'s choices.
    pub fn key(me: &str) -> String {
        format!("nostr-bbs:poker:choices:{me}")
    }

    /// Read `me`'s choices, dropping what is older than [`KEEP_SECS`]. A
    /// member with nothing kept gets an empty set.
    ///
    /// # Errors
    ///
    /// A message when storage cannot be read or holds something unreadable.
    pub fn load(store: &dyn KeyValue, me: &str, now: u64) -> Result<Self, String> {
        let Some(text) = store.get(&Self::key(me))? else {
            return Ok(Self::default());
        };
        let mut c: Self =
            serde_json::from_str(&text).map_err(|e| format!("kept choices unreadable: {e}"))?;
        c.prune(now);
        Ok(c)
    }

    /// Keep `me`'s choices.
    ///
    /// # Errors
    ///
    /// A message when storage cannot be written.
    pub fn save(&self, store: &dyn KeyValue, me: &str) -> Result<(), String> {
        let json = serde_json::to_string(self).map_err(|e| e.to_string())?;
        store.set(&Self::key(me), &json)
    }

    /// Fold what this table holds into what is kept: every commitment in
    /// either map is stored (keeping its first-seen time), `removed` ones
    /// are dropped, and what is too old goes. Entries this table does not
    /// hold are left alone: they may be another tab's hands, and a tab
    /// that never heard of a hand must not delete it.
    pub fn sync(
        &mut self,
        nonces: &HashMap<String, String>,
        agreed: &HashMap<String, Agreed>,
        removed: &[&str],
        now: u64,
    ) {
        for k in removed {
            self.entries.remove(*k);
        }
        let keys: Vec<&String> = nonces.keys().chain(agreed.keys()).collect();
        for k in keys {
            let e = self.entries.entry(k.clone()).or_insert(Entry {
                nonce: None,
                agreed: None,
                at: now,
            });
            e.nonce = nonces.get(k).cloned();
            e.agreed = agreed.get(k).cloned();
        }
        self.prune(now);
    }

    /// The kept nonces and agreements, to seed a reloaded table.
    pub fn maps(&self) -> (HashMap<String, String>, HashMap<String, Agreed>) {
        let mut nonces = HashMap::new();
        let mut agreed = HashMap::new();
        for (k, e) in &self.entries {
            if let Some(n) = &e.nonce {
                nonces.insert(k.clone(), n.clone());
            }
            if let Some(a) = &e.agreed {
                agreed.insert(k.clone(), a.clone());
            }
        }
        (nonces, agreed)
    }

    fn prune(&mut self, now: u64) {
        self.entries
            .retain(|_, e| e.at.saturating_add(KEEP_SECS) >= now);
    }

    /// How many hands are kept.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether none are.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    #[derive(Default)]
    struct Mem(RefCell<HashMap<String, String>>);

    impl KeyValue for Mem {
        fn get(&self, key: &str) -> Result<Option<String>, String> {
            Ok(self.0.borrow().get(key).cloned())
        }
        fn set(&self, key: &str, value: &str) -> Result<(), String> {
            self.0.borrow_mut().insert(key.into(), value.into());
            Ok(())
        }
    }

    struct Off;

    impl KeyValue for Off {
        fn get(&self, _: &str) -> Result<Option<String>, String> {
            Err("local storage is not available".into())
        }
        fn set(&self, _: &str, _: &str) -> Result<(), String> {
            Err("local storage is full or switched off".into())
        }
    }

    fn agreed() -> Agreed {
        Agreed {
            house: true,
            opponent: "c".repeat(64),
            bb: 20,
            sb: 10,
            buyin: 2_000,
        }
    }

    fn maps(commit: &str) -> (HashMap<String, String>, HashMap<String, Agreed>) {
        (
            HashMap::from([(commit.to_string(), "ab".repeat(32))]),
            HashMap::from([(commit.to_string(), agreed())]),
        )
    }

    #[test]
    fn a_reload_mid_hand_gets_back_the_nonce_and_the_agreement() {
        let store = Mem::default();
        let me = "a".repeat(64);
        let commit = "1".repeat(64);
        let (n, a) = maps(&commit);
        let mut c = Choices::default();
        c.sync(&n, &a, &[], 1_000);
        c.save(&store, &me).unwrap();
        // the page reloads: a new table reads what was kept
        let back = Choices::load(&store, &me, 1_300).unwrap();
        assert_eq!(back.maps(), (n, a));
        // another member of the same browser sees none of it
        assert!(Choices::load(&store, &"b".repeat(64), 1_300)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn what_is_paid_or_voided_is_dropped_and_what_is_old_expires() {
        let mut c = Choices::default();
        let (n, a) = maps(&"1".repeat(64));
        c.sync(&n, &a, &[], 1_000);
        assert_eq!(c.len(), 1);
        // the table paid or voided the hand: it says so, and storage drops it
        c.sync(
            &HashMap::new(),
            &HashMap::new(),
            &["1".repeat(64).as_str()],
            1_100,
        );
        assert!(c.is_empty());
        // an entry survives a day and no more
        c.sync(&n, &a, &[], 1_000);
        c.sync(&n, &a, &[], 1_000 + KEEP_SECS);
        assert_eq!(c.len(), 1);
        c.sync(&n, &a, &[], 1_000 + KEEP_SECS + 1);
        assert!(c.is_empty());
    }

    #[test]
    fn two_tabs_do_not_delete_each_others_hands() {
        let store = Mem::default();
        let me = "a".repeat(64);
        let (c1, c2) = ("1".repeat(64), "2".repeat(64));
        let save = |commit: &str, removed: &[&str], now: u64| {
            // each save reads what is kept first, as the table does
            let mut kept = Choices::load(&store, &me, now).unwrap_or_default();
            let (n, a) = if removed.is_empty() {
                maps(commit)
            } else {
                Default::default()
            };
            kept.sync(&n, &a, removed, now);
            kept.save(&store, &me).unwrap();
        };
        save(&c1, &[], 1_000); // tab one sits
        save(&c2, &[], 1_010); // tab two, which never heard of the first
        let both = Choices::load(&store, &me, 1_020).unwrap();
        assert_eq!(both.len(), 2, "neither deleted the other's");
        save(&c1, &[c1.as_str()], 1_030); // tab one's hand is paid
        let left = Choices::load(&store, &me, 1_040).unwrap();
        assert_eq!(left.len(), 1);
        assert!(left.maps().1.contains_key(&c2));
    }

    #[test]
    fn unavailable_storage_is_an_error_to_report_not_a_silent_loss() {
        let me = "a".repeat(64);
        let mut c = Choices::default();
        let (n, a) = maps(&"1".repeat(64));
        c.sync(&n, &a, &[], 1_000);
        assert!(c.save(&Off, &me).unwrap_err().contains("switched off"));
        assert!(Choices::load(&Off, &me, 1_000)
            .unwrap_err()
            .contains("not available"));
        // unreadable contents are reported too, not trusted
        let store = Mem::default();
        store.set(&Choices::key(&me), "{not json").unwrap();
        assert!(Choices::load(&store, &me, 1_000)
            .unwrap_err()
            .contains("unreadable"));
    }
}
