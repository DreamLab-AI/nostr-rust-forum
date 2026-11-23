//! What the house saves between runs: the book, the hands in play, and the
//! relay events it has already acted on, in one JSON document.
//!
//! One document, written whole by one atomic rename, so a restart sees the
//! hands and the ledger from the same instant: a hand is either still in
//! play (and its settlement not yet booked) or settled (and booked), never
//! both and never neither. The ledger's own fields sit at the top level, so
//! a file written before hands were saved loads as a state with none, and
//! an older build reading a newer file ignores what it does not know.
//!
//! A saved hand holds the deck's secret: the file is the house's private
//! state and the runner writes it readable by its owner alone.

use std::collections::BTreeMap;

use nostr_bbs_poker::engine::Hand;
use serde::{Deserialize, Serialize};

use crate::ledger::Ledger;

/// A relay message older than this, by its own timestamp, is dropped
/// unread: the longest a hand's message can usefully wait, seconds.
pub const STALE_SECS: u64 = 600;
/// A message timestamped further ahead than this is dropped: a future
/// date would outlive its place in the de-duplication window, seconds.
pub const FUTURE_SKEW_SECS: u64 = 60;
/// A processed message is remembered until it is too old to be accepted
/// again, with a margin, seconds. Memory is by age, never by count: a
/// flood of other messages cannot push a live one out.
pub const SEEN_KEEP_SECS: u64 = STALE_SECS + FUTURE_SKEW_SECS + 60;

/// One hand in play, with what the house needs to carry on dealing it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SavedHand {
    /// The hand's commitment, its key.
    pub commit: String,
    /// The players' pubkeys in seat order; seat 1 is the house's for a
    /// house hand.
    pub seats: [String; 2],
    /// Whether the house holds seat 1.
    pub house: bool,
    /// The revealed-at-the-end secret the deck was committed to.
    pub secret: String,
    /// The players' nonces, in seat order.
    pub nonces: Vec<String>,
    /// The shuffle seed.
    pub seed: String,
    /// The buy-in each seat sat with, base units.
    pub buyin: u64,
    /// The hand as it stands.
    pub hand: Hand,
}

/// The house's saved state.
///
/// On disk the ledger's own fields sit at the top level beside `live`,
/// `held` and `seen`. (`#[serde(flatten)]` is not used: it buffers the
/// document and can no longer read the ledger's day-numbered `paid` map,
/// whose keys are JSON strings.)
#[derive(Debug, Clone, PartialEq)]
pub struct State {
    /// The book.
    pub ledger: Ledger,
    /// Hands in play, ordered by commitment.
    pub live: Vec<SavedHand>,
    /// Messages already processed, by sender and rumor id, with the time
    /// each carries.
    pub seen: Vec<SeenEntry>,
}

impl Default for State {
    fn default() -> Self {
        Self::from(Ledger::default())
    }
}

impl From<Ledger> for State {
    fn from(ledger: Ledger) -> Self {
        Self {
            ledger,
            live: Vec::new(),
            seen: Vec::new(),
        }
    }
}

impl State {
    /// Parse a saved state, or a ledger saved before hands were kept.
    ///
    /// # Errors
    ///
    /// Returns a message when the text is not a state, or is a ledger of a
    /// version this build does not read.
    pub fn parse(json: &str) -> Result<Self, String> {
        use serde_json::Value;

        let mut doc: Value = serde_json::from_str(json).map_err(|e| format!("state: {e}"))?;
        let obj = doc
            .as_object_mut()
            .ok_or("state: not a JSON object".to_string())?;
        let mut take = |key: &str| obj.remove(key).unwrap_or_else(|| Value::Array(Vec::new()));
        let live = serde_json::from_value(take("live")).map_err(|e| format!("state: live: {e}"))?;
        let seen = serde_json::from_value(take("seen")).map_err(|e| format!("state: seen: {e}"))?;
        let ledger: Ledger = serde_json::from_value(doc).map_err(|e| format!("ledger: {e}"))?;
        if ledger.version != crate::ledger::VERSION {
            return Err(format!(
                "ledger version {} is not {}",
                ledger.version,
                crate::ledger::VERSION
            ));
        }
        Ok(Self { ledger, live, seen })
    }

    /// The state as JSON.
    pub fn to_json(&self) -> String {
        use serde_json::Value;

        let mut doc = serde_json::to_value(&self.ledger).expect("ledger serialises");
        let obj = doc.as_object_mut().expect("a ledger is an object");
        obj.insert(
            "live".into(),
            serde_json::to_value(&self.live).expect("hands serialise"),
        );
        obj.insert(
            "seen".into(),
            serde_json::to_value(&self.seen).expect("seen serialises"),
        );
        serde_json::to_string_pretty(&Value::Object(std::mem::take(obj))).expect("state serialises")
    }
}

/// A processed message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeenEntry {
    /// The sender's pubkey.
    pub sender: String,
    /// The rumor's id.
    pub key: String,
    /// The rumor's own timestamp, unix seconds.
    pub at: u64,
}

/// The most messages remembered for one sender. A sender can only fill its
/// own share: a flood from one key (or from none that parses) cannot push
/// another sender's messages out, and an overflowing sender forgets its own
/// oldest.
pub const SEEN_PER_SENDER: usize = 64;

/// Messages processed, forgotten once too old to be accepted again, and at
/// most [`SEEN_PER_SENDER`] per sender.
///
/// Only messages that parsed, from a sender the house holds a session for,
/// are put here; and only those that changed the table are saved
/// ([`Seen::to_entries`]), so what is written to disk is bounded by real
/// play, not by what the relay carries.
#[derive(Debug, Clone, Default)]
pub struct Seen {
    by_key: BTreeMap<(String, String), Noted>,
}

#[derive(Debug, Clone)]
struct Noted {
    at: u64,
    saved: bool,
}

impl Seen {
    /// A set holding `entries`.
    pub fn from_entries(entries: Vec<SeenEntry>) -> Self {
        let mut s = Self::default();
        for e in entries {
            s.remember(&e.sender, &e.key, e.at, true);
        }
        s
    }

    /// Whether the message has been processed.
    pub fn contains(&self, sender: &str, key: &str) -> bool {
        self.by_key
            .contains_key(&(sender.to_string(), key.to_string()))
    }

    /// Note a message from `sender`; `saved` marks one that changed the
    /// table, which is kept across a restart. `false` when it was already
    /// noted.
    pub fn remember(&mut self, sender: &str, key: &str, at: u64, saved: bool) -> bool {
        let k = (sender.to_string(), key.to_string());
        if let Some(n) = self.by_key.get_mut(&k) {
            n.saved |= saved;
            return false;
        }
        self.by_key.insert(k, Noted { at, saved });
        // keys sort by sender, so one sender's entries are one range
        let mine: Vec<(u64, String)> = self
            .by_key
            .range((sender.to_string(), String::new())..)
            .take_while(|((s, _), _)| s == sender)
            .map(|((_, id), n)| (n.at, id.clone()))
            .collect();
        if mine.len() > SEEN_PER_SENDER {
            if let Some((_, oldest)) = mine.into_iter().min() {
                self.by_key.remove(&(sender.to_string(), oldest));
            }
        }
        true
    }

    /// Forget what is too old to be accepted again.
    pub fn expire(&mut self, now: u64) {
        self.by_key
            .retain(|_, n| n.at.saturating_add(SEEN_KEEP_SECS) >= now);
    }

    /// The entries worth saving: those that changed the table.
    pub fn to_entries(&self) -> Vec<SeenEntry> {
        self.by_key
            .iter()
            .filter(|(_, n)| n.saved)
            .map(|((sender, key), n)| SeenEntry {
                sender: sender.clone(),
                key: key.clone(),
                at: n.at,
            })
            .collect()
    }

    /// How many messages are remembered.
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// Whether none are.
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

/// Whether a message stamped `at` may be acted on at `now`: not stale and
/// not from the future.
pub fn fresh(at: u64, now: u64) -> bool {
    now.saturating_sub(at) <= STALE_SECS && at <= now.saturating_add(FUTURE_SKEW_SECS)
}

/// Save `state` to `path`: a private temporary written whole, synced, renamed
/// into place, and the directory synced, so a crash leaves the old file or
/// the new one and a returned `Ok` means the new one is on disk. The file
/// holds each live deck's secret and is readable by its owner alone; a
/// stale temporary left by a crash is removed first so its permissions are
/// never inherited.
///
/// # Errors
///
/// Any failure to write, sync or rename. The caller must treat the state as
/// not saved.
#[cfg(not(target_arch = "wasm32"))]
pub fn save(path: &std::path::Path, state: &State) -> std::io::Result<()> {
    use std::io::Write;

    let tmp = path.with_extension("json.tmp");
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(state.to_json().as_bytes())?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        let dir = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => std::path::Path::new("."),
        };
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ledger_saved_before_hands_were_kept_still_loads() {
        let mut l = Ledger::default();
        l.settled("h", "r", -5, 100);
        let s = State::parse(&l.to_json()).unwrap();
        assert_eq!(s.ledger, l);
        assert!(s.live.is_empty() && s.seen.is_empty());
        // and the new document is still a ledger to a reader of the old one
        assert_eq!(Ledger::parse(&s.to_json()).unwrap(), l);
        let other = s.to_json().replace("\"version\": 1", "\"version\": 2");
        assert!(State::parse(&other).is_err());
    }

    #[test]
    fn a_ledger_with_a_payout_day_survives_the_state_file() {
        let mut l = Ledger::default();
        l.settled("h", "r", 7, 100);
        l.paid.insert(19_000, 7);
        l.paid.insert(19_001, 9);
        let st = State::from(l);
        let back = State::parse(&st.to_json()).unwrap();
        assert_eq!(back, st);
        assert_eq!(back.ledger.paid.len(), 2);
    }

    #[test]
    fn seen_is_forgotten_by_age_and_a_sender_can_only_fill_its_own_share() {
        let mut s = Seen::default();
        assert!(s.remember("alice", "a", 1_000, true));
        assert!(!s.remember("alice", "a", 1_000, false));
        // a flood from one key stays inside that key's share and cannot
        // evict anyone else's message
        for i in 0..100_000u64 {
            s.remember("mallory", &format!("junk{i}"), 1_000 + i % 5, false);
        }
        assert!(s.len() <= 1 + SEEN_PER_SENDER);
        assert!(s.contains("alice", "a"));
        // junk is never written; only what changed the table is
        assert_eq!(s.to_entries().len(), 1);
        assert!(s.to_entries().len() <= 1 + SEEN_PER_SENDER);
        s.expire(1_000 + SEEN_KEEP_SECS);
        assert!(s.contains("alice", "a"));
        s.expire(1_000 + SEEN_KEEP_SECS + 10);
        assert!(s.is_empty(), "too old to be accepted again anyway");
        let mut s = Seen::default();
        s.remember("alice", "a", 5, true);
        let back = Seen::from_entries(s.to_entries());
        assert_eq!(back.to_entries(), s.to_entries());
    }

    #[test]
    fn what_is_saved_is_bounded_by_play_not_by_traffic() {
        let mut s = Seen::default();
        // a thousand senders each flooding unsaved messages save nothing
        for who in 0..1_000u64 {
            for i in 0..200u64 {
                s.remember(&format!("{who:064x}"), &format!("m{i}"), 100 + i, false);
            }
        }
        assert!(s.to_entries().is_empty());
        let json = State::from(Ledger::default()).to_json();
        assert!(json.len() < 4_096);
    }

    #[test]
    fn what_is_forgotten_is_never_fresh_again() {
        let at = 5_000;
        // forgotten when `at + SEEN_KEEP_SECS < now`; by then it is stale
        assert!(!fresh(at, at + SEEN_KEEP_SECS + 1));
        assert!(fresh(at, at + STALE_SECS));
        assert!(!fresh(at, at + STALE_SECS + 1));
        // the future is refused beyond a small skew
        assert!(fresh(at + FUTURE_SKEW_SECS, at));
        assert!(!fresh(at + FUTURE_SKEW_SECS + 1, at));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn saving_is_private_whole_and_reports_failure() {
        let dir = std::env::temp_dir().join(format!("poker-state-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        // a stale temporary with open permissions is not inherited
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, "stale").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let mut st = State::default();
        st.ledger.settled("h", "r", 5, 1);
        save(&path, &st).unwrap();
        assert_eq!(
            State::parse(&std::fs::read_to_string(&path).unwrap()).unwrap(),
            st
        );
        assert!(!tmp.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // a failed write is an error, not a silent skip
        let missing = dir.join("no-such-dir").join("state.json");
        assert!(save(&missing, &st).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
