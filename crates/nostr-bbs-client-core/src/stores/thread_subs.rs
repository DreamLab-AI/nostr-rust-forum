//! Thread (topic) subscriptions: the topics a member follows, how many posts
//! in each they have not seen, and a private copy that follows them across
//! devices.
//!
//! ## Model
//!
//! - **Subscriptions** are keyed by topic root id (lower-case hex) and carry
//!   the root's channel id, its zone id, whether the subscription is on, and
//!   when it last changed (`at`, milliseconds). Switching one off keeps a
//!   *tombstone* (`on: false`) for [`TOMBSTONE_TTL_MS`], so a merge with an
//!   older copy that still has it on converges on "off" rather than reviving
//!   it.
//! - **Read markers**, one per subscribed topic: the newest post time
//!   (seconds) the member has seen there. A marker never moves backwards. It
//!   is set to "now" on subscribe, so the first count never walks the whole
//!   topic, and advanced by [`ThreadSubsStore::mark_read`] when a view shows
//!   the thread.
//! - **Unseen posts** are held in memory only, per topic: ids (with their
//!   time) of posts newer than the marker, by someone else, that are not
//!   edits. They come from a one-off backlog pass after NIP-42 AUTH (and
//!   again after a reconnect) and, while the app is open, from the channel
//!   store's inserted-message hook ([`ChannelStore::on_inserted`]). No
//!   polling, and no extra open subscription.
//!
//! **Topic titles are never stored**, here or in the synced copy: a title in
//! an encrypted zone is private to the zone's members, and localStorage and
//! the relay copy are readable without the zone key. Titles are resolved at
//! runtime from the root events the channel store holds (fetched by id when
//! needed, and decrypted through the zone-key store).
//!
//! ## Storage
//!
//! The working copy lives in localStorage under
//! `nostrbbs:thread_subs:v1:<pubkey>` (per account, shared by the forum and
//! the BBS on the same origin), is merged on every write with what another
//! tab stored, is reloaded when another tab writes it, and is removed at
//! sign-out ([`clear_persisted_for_logout`]). The cross-device copy is a
//! NIP-44 self-encrypted kind-30078 event: see
//! [`thread_subs_sync`](crate::stores::thread_subs_sync).
//!
//! ## Use
//!
//! Provide once at the app root with [`provide_thread_subs`], after the relay
//! connection, the channel store and the zone-key store are provided, then
//! read it anywhere with [`use_thread_subs`].

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::rc::Rc;

use gloo::storage::{LocalStorage, Storage};
use leptos::prelude::*;
use nostr_bbs_core::NostrEvent;
use serde::{Deserialize, Serialize};

use crate::auth::{use_auth, AuthStore};
use crate::relay::{Filter, RelayConnection};
use crate::stores::channels::{
    roots_key, topic_key, use_channel_store, ChannelStore, InsertedMessage, PAGE_TIMEOUT_MS,
    RELAY_MAX_FILTERS,
};
use crate::stores::thread_subs_sync::{self as sync, LocalOnlyReason, SyncStatus};
use crate::zone_crypto::store::ZoneKeyStore;

// -- Constants ----------------------------------------------------------------

/// Prefix of the per-account localStorage key; the signed-in pubkey (hex) is
/// appended.
pub const STORAGE_KEY_PREFIX: &str = "nostrbbs:thread_subs:v1:";

/// The most topics one member can follow at once. Keeps the synced copy well
/// under the relay's 64 KiB content cap; [`ThreadSubsStore::subscribe`]
/// refuses with [`SubscribeError::LimitReached`] beyond it.
pub const MAX_ACTIVE_SUBSCRIPTIONS: usize = 150;

/// Unread counts above this are shown as "99+" by the views; see
/// [`UnreadCount::capped`].
pub const UNREAD_DISPLAY_CAP: usize = 99;

/// How long a tombstone (a subscription switched off) is kept, in
/// milliseconds: long enough for every device to see it before it is
/// dropped. A device last synced before that may bring the subscription back.
pub const TOMBSTONE_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// The most tombstones kept locally (the newest).
pub(crate) const MAX_TOMBSTONES: usize = 300;

/// Posts asked for per topic by the backlog pass (`limit` of each filter).
pub(crate) const BACKLOG_LIMIT: u64 = 100;

/// Filters per backlog REQ: one under the relay's cap, as the other paced
/// passes leave room.
pub(crate) const BACKLOG_FILTERS_PER_REQ: usize = RELAY_MAX_FILTERS - 1;

/// Root ids asked for per title-fetch REQ. Each id is bound twice (by `ids`
/// and by `#sealed`), well inside the relay database's bound-parameter limit.
pub(crate) const ROOT_FETCH_BATCH: usize = 20;

/// Longest zone id accepted from storage or the synced copy.
pub(crate) const MAX_ZONE_LEN: usize = 64;

/// Pause before re-sending a backlog or title batch the relay refused,
/// milliseconds.
const RETRY_DELAY_MS: i32 = 3_000;

/// The localStorage key of `owner`'s subscriptions.
pub fn storage_key(owner: &str) -> String {
    format!("{STORAGE_KEY_PREFIX}{owner}")
}

// -- Public types -------------------------------------------------------------

/// How many posts in a topic (or across all followed topics) the member has
/// not seen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnreadCount {
    /// Unseen posts counted.
    pub count: usize,
    /// Show the count as at least this much: either it exceeds
    /// [`UNREAD_DISPLAY_CAP`] (show "99+"), or the backlog pass hit its
    /// per-topic limit so there may be more than `count` (show "`count`+").
    pub capped: bool,
}

/// One followed topic, ready for a subscriptions panel to render.
///
/// Carries the ids both clients need to link to the topic, not a URL:
/// the forum builds
/// [`topic_path`](crate::utils::section_url::topic_path)`(zone_slug, channel, root)`,
/// the BBS its `Thread { zone, channel_id, root_id }` route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscribedTopic {
    /// Topic root event id (lower-case hex).
    pub root: String,
    /// Channel (section) id the topic is in.
    pub channel: String,
    /// Zone id of the channel: resolved from the current zone configuration
    /// when the channel is known, else the zone recorded at subscribe time
    /// (empty when neither is known).
    pub zone: String,
    /// The zone's URL segment (its slug, or its id when it has none), for the
    /// forum's canonical topic path; `None` while the channel or zones are
    /// unknown.
    pub zone_slug: Option<String>,
    /// The topic title (first line of the root post), or `None` while the
    /// root is not held, or is held but cannot be read (encrypted zone without
    /// the key). Never stored.
    pub title: Option<String>,
    /// Unseen posts in the topic.
    pub unread: usize,
    /// See [`UnreadCount::capped`].
    pub capped: bool,
}

/// Why [`ThreadSubsStore::subscribe`] refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubscribeError {
    /// No member is signed in.
    NotSignedIn,
    /// The member already follows [`MAX_ACTIVE_SUBSCRIPTIONS`] topics.
    LimitReached {
        /// The limit that was reached.
        limit: usize,
    },
    /// The topic id or the channel id is not a 64-character hex event id.
    InvalidTopic,
}

impl std::fmt::Display for SubscribeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscribeError::NotSignedIn => f.write_str("Sign in to subscribe to topics."),
            SubscribeError::LimitReached { limit } => write!(
                f,
                "You can subscribe to at most {limit} topics. Unsubscribe from one to add another."
            ),
            SubscribeError::InvalidTopic => f.write_str("This topic cannot be subscribed to."),
        }
    }
}

impl std::error::Error for SubscribeError {}

// -- Pure model ---------------------------------------------------------------

/// One subscription as stored and synced. Short field names keep the synced
/// copy small. A tombstone carries no channel or zone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Entry {
    /// Topic root id, lower-case hex.
    pub r: String,
    /// Channel id.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub c: String,
    /// Zone id.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub z: String,
    /// On (subscribed) or off (tombstone).
    pub on: bool,
    /// When this entry last changed, unix milliseconds.
    pub at: u64,
}

impl Entry {
    /// Total order used by the merge: later `at` wins; at equal `at`, off
    /// beats on; then the channel and zone strings decide, so two copies
    /// always pick the same winner.
    fn outranks(&self, other: &Entry) -> bool {
        (self.at, !self.on, &self.c, &self.z) > (other.at, !other.on, &other.c, &other.z)
    }
}

/// One subscription in the stored and synced shape: an [`Entry`] plus its
/// read marker (`rd`, seconds) inline. Inline rather than in a separate
/// `{root: ts}` map, which would repeat every 64-character root and push a
/// full list past the synced copy's size budget.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DocEntry {
    #[serde(flatten)]
    pub entry: Entry,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rd: Option<u64>,
}

/// The stored and synced shape: `{"subs":[{r,c,z,on,at,rd}]}`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SubsDoc {
    #[serde(default)]
    pub subs: Vec<DocEntry>,
}

/// Subscriptions and read markers, keyed by lower-case root id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Subs {
    pub entries: BTreeMap<String, Entry>,
    pub read: BTreeMap<String, u64>,
}

/// Whether `s` is a 64-character hex id.
fn is_hex_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Subs {
    /// Rebuild from the stored shape, dropping malformed entries (an id that
    /// is not 64 hex, an over-long channel or zone) and resolving duplicate
    /// roots by the merge order.
    pub fn from_doc(doc: SubsDoc) -> Self {
        let mut out = Subs::default();
        for DocEntry { entry: mut e, rd } in doc.subs {
            e.r = e.r.to_ascii_lowercase();
            e.c = e.c.to_ascii_lowercase();
            if !is_hex_id(&e.r) || e.z.len() > MAX_ZONE_LEN {
                continue;
            }
            // A subscription names its channel (a kind-40 event id); a
            // tombstone names none.
            if (e.on && !is_hex_id(&e.c)) || (!e.on && !e.c.is_empty()) {
                continue;
            }
            if let Some(ts) = rd {
                let m = out.read.entry(e.r.clone()).or_insert(0);
                *m = (*m).max(ts);
            }
            out.put(e);
        }
        out
    }

    /// The stored shape, roots in order. A marker is written only with a
    /// followed topic.
    pub fn to_doc(&self) -> SubsDoc {
        SubsDoc {
            subs: self
                .entries
                .values()
                .map(|e| DocEntry {
                    rd: if e.on {
                        self.read.get(&e.r).copied()
                    } else {
                        None
                    },
                    entry: e.clone(),
                })
                .collect(),
        }
    }

    /// Insert `e` unless an entry for the same root outranks it.
    fn put(&mut self, e: Entry) {
        match self.entries.get(&e.r) {
            Some(cur) if !e.outranks(cur) => {}
            _ => {
                self.entries.insert(e.r.clone(), e);
            }
        }
    }

    /// Entry-wise merge: for each root the higher-ranked entry wins (later
    /// `at`, then off before on); read markers take the larger value. A
    /// join: commutative, associative and idempotent, so copies merged in
    /// any order converge. Markers are kept for every root here; dropping the
    /// ones of topics no longer followed is [`Self::prune`]'s job.
    pub fn join(&self, other: &Subs) -> Subs {
        let mut out = self.clone();
        for e in other.entries.values() {
            out.put(e.clone());
        }
        for (root, ts) in &other.read {
            let m = out.read.entry(root.clone()).or_insert(0);
            *m = (*m).max(*ts);
        }
        out
    }

    /// Drop tombstones older than [`TOMBSTONE_TTL_MS`] and all but the newest
    /// [`MAX_TOMBSTONES`], and the read markers of topics not followed.
    pub fn prune(&mut self, now_ms: u64) {
        let floor = now_ms.saturating_sub(TOMBSTONE_TTL_MS);
        self.entries.retain(|_, e| e.on || e.at >= floor);
        let mut tombs: Vec<(u64, String)> = self
            .entries
            .values()
            .filter(|e| !e.on)
            .map(|e| (e.at, e.r.clone()))
            .collect();
        if tombs.len() > MAX_TOMBSTONES {
            tombs.sort();
            let excess = tombs.len() - MAX_TOMBSTONES;
            for (_, r) in tombs.into_iter().take(excess) {
                self.entries.remove(&r);
            }
        }
        let entries = &self.entries;
        self.read
            .retain(|r, _| entries.get(r).is_some_and(|e| e.on));
    }

    /// Whether `root` (any case) is followed.
    pub fn is_active(&self, root: &str) -> bool {
        self.entries
            .get(&root.to_ascii_lowercase())
            .is_some_and(|e| e.on)
    }

    /// Number of followed topics.
    pub fn active_count(&self) -> usize {
        self.entries.values().filter(|e| e.on).count()
    }

    /// Followed topics, in root order.
    pub fn active(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values().filter(|e| e.on)
    }

    /// The read marker of followed topic `root` (seconds): its stored marker,
    /// or, for a subscription that arrived without one, the moment it was
    /// made. `None` when `root` is not followed.
    pub fn read_at(&self, root: &str) -> Option<u64> {
        let root = root.to_ascii_lowercase();
        let e = self.entries.get(&root).filter(|e| e.on)?;
        Some(self.read.get(&root).copied().unwrap_or(e.at / 1000))
    }

    /// Follow `root` in `channel` (zone `zone`). The marker is set to
    /// `now_secs` (never moved back). Returns whether anything changed.
    pub fn subscribe(
        &mut self,
        root: &str,
        channel: &str,
        zone: &str,
        now_ms: u64,
        now_secs: u64,
    ) -> Result<bool, SubscribeError> {
        let root = root.to_ascii_lowercase();
        let channel = channel.to_ascii_lowercase();
        let channel = channel.as_str();
        if !is_hex_id(&root) || !is_hex_id(channel) || zone.len() > MAX_ZONE_LEN {
            return Err(SubscribeError::InvalidTopic);
        }
        let prev = self.entries.get(&root);
        if let Some(e) = prev.filter(|e| e.on) {
            if e.c == channel && (zone.is_empty() || e.z == zone) {
                return Ok(false);
            }
        } else if self.active_count() >= MAX_ACTIVE_SUBSCRIPTIONS {
            return Err(SubscribeError::LimitReached {
                limit: MAX_ACTIVE_SUBSCRIPTIONS,
            });
        }
        let at = next_at(prev, now_ms);
        let was_on = prev.is_some_and(|e| e.on);
        let zone = if zone.is_empty() {
            prev.map(|e| e.z.clone()).unwrap_or_default()
        } else {
            zone.to_string()
        };
        self.entries.insert(
            root.clone(),
            Entry {
                r: root.clone(),
                c: channel.to_string(),
                z: zone,
                on: true,
                at,
            },
        );
        if !was_on {
            let m = self.read.entry(root).or_insert(0);
            *m = (*m).max(now_secs);
        }
        Ok(true)
    }

    /// Stop following `root`, leaving a tombstone. Returns whether it was
    /// followed.
    pub fn unsubscribe(&mut self, root: &str, now_ms: u64) -> bool {
        let root = root.to_ascii_lowercase();
        let Some(prev) = self.entries.get(&root).filter(|e| e.on) else {
            return false;
        };
        let at = next_at(Some(prev), now_ms);
        self.entries.insert(
            root.clone(),
            Entry {
                r: root.clone(),
                c: String::new(),
                z: String::new(),
                on: false,
                at,
            },
        );
        self.read.remove(&root);
        true
    }

    /// Advance followed topic `root`'s marker to `upto` (seconds). Never
    /// moves it back; a topic not followed is left alone. Returns whether it
    /// moved.
    pub fn mark_read(&mut self, root: &str, upto: u64) -> bool {
        let root = root.to_ascii_lowercase();
        let Some(cur) = self.read_at(&root) else {
            return false;
        };
        if upto <= cur && self.read.contains_key(&root) {
            return false;
        }
        self.read.insert(root, upto.max(cur));
        true
    }
}

/// The `at` for a new version of an entry: now, but always after the
/// previous version, so a local change always outranks what it replaces.
fn next_at(prev: Option<&Entry>, now_ms: u64) -> u64 {
    prev.map_or(now_ms, |p| now_ms.max(p.at + 1))
}

/// Unseen post ids per followed topic, with their `created_at`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Unseen {
    by_root: HashMap<String, HashMap<String, u64>>,
    /// Topics whose backlog answer was full ([`BACKLOG_LIMIT`]): there may
    /// be more unseen posts than counted.
    saturated: HashSet<String>,
}

impl Unseen {
    /// Record unseen post `id` in `root`. Returns whether it was new.
    pub fn note(&mut self, root: &str, id: &str, created_at: u64) -> bool {
        self.by_root
            .entry(root.to_string())
            .or_default()
            .insert(id.to_ascii_lowercase(), created_at)
            .is_none()
    }

    /// Mark `root`'s count as possibly incomplete.
    pub fn saturate(&mut self, root: &str) {
        self.saturated.insert(root.to_string());
    }

    /// Bring the sets in line with `subs`: forget topics not followed, and
    /// posts at or before each topic's marker. A topic whose set empties is
    /// no longer saturated.
    pub fn reconcile(&mut self, subs: &Subs) {
        self.by_root.retain(|root, ids| match subs.read_at(root) {
            Some(read) => {
                ids.retain(|_, ts| *ts > read);
                true
            }
            None => false,
        });
        let by_root = &self.by_root;
        self.saturated
            .retain(|r| subs.is_active(r) && by_root.get(r).is_some_and(|ids| !ids.is_empty()));
        self.by_root.retain(|_, ids| !ids.is_empty());
    }

    /// The newest unseen post time in `root`, if any.
    pub fn newest(&self, root: &str) -> Option<u64> {
        self.by_root.get(root)?.values().copied().max()
    }

    /// `root`'s unread count.
    pub fn count(&self, root: &str) -> UnreadCount {
        let count = self.by_root.get(root).map_or(0, HashMap::len);
        UnreadCount {
            count,
            capped: count > UNREAD_DISPLAY_CAP || self.saturated.contains(root),
        }
    }

    /// The count across every topic.
    pub fn total(&self) -> UnreadCount {
        let count = self.by_root.values().map(HashMap::len).sum();
        UnreadCount {
            count,
            capped: count > UNREAD_DISPLAY_CAP || !self.saturated.is_empty(),
        }
    }
}

/// The followed topic an inserted or fetched post counts as unseen in, if
/// any: a reply (not an edit) to a followed topic, by someone other than
/// `me`, newer than the topic's marker.
pub(crate) fn unseen_root<'a>(
    msg: &'a InsertedMessage,
    subs: &Subs,
    me: Option<&str>,
) -> Option<&'a str> {
    if msg.edit {
        return None;
    }
    if me.is_some_and(|m| m.eq_ignore_ascii_case(&msg.pubkey)) {
        return None;
    }
    let root = msg.reply_root.as_deref()?;
    let read = subs.read_at(root)?;
    (msg.created_at > read).then_some(root)
}

/// The backlog filter for topic `root` read up to `read_at`:
/// `{"kinds":[42], "#e":[root], "since": read_at + 1, "limit": 100}`.
pub(crate) fn backlog_filter(root: &str, read_at: u64) -> Filter {
    Filter {
        kinds: Some(vec![42]),
        e_tags: Some(vec![root.to_string()]),
        since: Some(read_at.saturating_add(1)),
        limit: Some(BACKLOG_LIMIT),
        ..Default::default()
    }
}

/// `(root, read_at)` pairs split into REQs of at most
/// [`BACKLOG_FILTERS_PER_REQ`] filters each.
pub(crate) fn backlog_batches(items: &[(String, u64)]) -> Vec<Vec<Filter>> {
    items
        .chunks(BACKLOG_FILTERS_PER_REQ)
        .map(|chunk| chunk.iter().map(|(r, t)| backlog_filter(r, *t)).collect())
        .collect()
}

/// The two filters fetching root ids `ids` (at most [`ROOT_FETCH_BATCH`]): a
/// live event by `ids`, a sealed one by the inner id in its `sealed` tag.
pub(crate) fn root_fetch_filters(ids: &[String]) -> Vec<Filter> {
    let n = ids.len() as u64;
    vec![
        Filter {
            ids: Some(ids.to_vec()),
            limit: Some(n),
            ..Default::default()
        },
        Filter {
            kinds: Some(vec![42]),
            sealed_tags: Some(ids.to_vec()),
            limit: Some(n),
            ..Default::default()
        },
    ]
}

/// A readable title for root `ev`: `None` for the missing-key and
/// undecryptable placeholders.
pub(crate) fn readable_title(ev: &NostrEvent) -> Option<String> {
    if ev.content == crate::zone_crypto::PLACEHOLDER_MISSING_KEY
        || ev.content == crate::zone_crypto::PLACEHOLDER_UNDECRYPTABLE
    {
        return None;
    }
    Some(crate::topics::board::topic_title(&ev.content))
}

/// Resolve the titles of `wanted` `(root, channel)` pairs from the stored
/// lists: each root is looked for in its channel's root list, its channel's
/// history window and its own topic list, nowhere else.
pub(crate) fn resolve_titles(
    lists: &HashMap<String, Vec<NostrEvent>>,
    wanted: &[(String, String)],
) -> HashMap<String, Option<String>> {
    let mut by_channel: HashMap<&str, HashSet<&str>> = HashMap::new();
    for (root, channel) in wanted {
        by_channel
            .entry(channel.as_str())
            .or_default()
            .insert(root.as_str());
    }
    let mut out: HashMap<String, Option<String>> = HashMap::new();
    let scan = |list: &str, roots: &HashSet<&str>, out: &mut HashMap<String, Option<String>>| {
        let Some(events) = lists.get(list) else {
            return;
        };
        for ev in events {
            if ev.kind != 42 || ev.id.len() != 64 {
                continue;
            }
            // Ids arrive lower-case; only an odd one pays for the copy.
            let id = if ev.id.bytes().any(|b| b.is_ascii_uppercase()) {
                ev.id.to_ascii_lowercase()
            } else if roots.contains(ev.id.as_str()) {
                ev.id.clone()
            } else {
                continue;
            };
            if !roots.contains(id.as_str()) {
                continue;
            }
            let title = readable_title(ev);
            let slot = out.entry(id).or_insert(None);
            if slot.is_none() {
                *slot = title;
            }
        }
    };
    for (channel, roots) in &by_channel {
        scan(&roots_key(channel), roots, &mut out);
        scan(channel, roots, &mut out);
    }
    for (root, _) in wanted {
        let one: HashSet<&str> = std::iter::once(root.as_str()).collect();
        scan(&topic_key(root), &one, &mut out);
    }
    for (root, _) in wanted {
        out.entry(root.clone()).or_insert(None);
    }
    out
}

/// The items of a refused batch to send again: those not already re-sent
/// once (recorded in `retried`), so a refusal is retried once and never loops.
pub(crate) fn requeue_once<T>(
    batch: Vec<T>,
    key: impl Fn(&T) -> &str,
    retried: &mut HashSet<String>,
) -> Vec<T> {
    batch
        .into_iter()
        .filter(|item| retried.insert(key(item).to_string()))
        .collect()
}

/// Whether any list of `channels` holds event `id` (from `created_at`).
/// Untracked; the same check the channel store makes before dropping the
/// decrypt state of an event it fetched for another purpose.
fn held_anywhere(channels: ChannelStore, id: &str, created_at: u64) -> bool {
    channels.channel_messages.with_untracked(|m| {
        m.values().any(|v| {
            let at = v.partition_point(|e| e.created_at < created_at);
            v[at..]
                .iter()
                .take_while(|e| e.created_at == created_at)
                .any(|e| e.id == id)
        })
    })
}

/// Whether root `root` of `channel` is held in one of the lists
/// [`resolve_titles`] looks in (readable or not).
pub(crate) fn root_held(
    lists: &HashMap<String, Vec<NostrEvent>>,
    root: &str,
    channel: &str,
) -> bool {
    [roots_key(channel), channel.to_string(), topic_key(root)]
        .iter()
        .any(|k| {
            lists
                .get(k)
                .is_some_and(|v| v.iter().any(|e| e.id.eq_ignore_ascii_case(root)))
        })
}

/// Sort for the panel: alphabetical by title, case-insensitive, ties by root
/// id; topics with no title yet last, by root id. Stable and total, so a row
/// moves only when its own title arrives.
pub(crate) fn sort_topics(topics: &mut [SubscribedTopic]) {
    topics.sort_by_cached_key(|t| {
        (
            t.title.is_none(),
            t.title
                .as_deref()
                .map(str::to_lowercase)
                .unwrap_or_default(),
            t.root.clone(),
        )
    });
}

// -- Persistence --------------------------------------------------------------

/// `owner`'s stored subscriptions; empty when absent or unreadable.
fn load_subs(owner: &str) -> Subs {
    LocalStorage::get::<SubsDoc>(storage_key(owner))
        .map(Subs::from_doc)
        .unwrap_or_default()
}

/// Remove `pubkey`'s stored subscriptions at sign-out, so the next account on
/// this browser does not see them. The synced relay copy, if any, is kept:
/// it is encrypted to the member and restores the list at their next
/// sign-in.
pub fn clear_persisted_for_logout(pubkey: Option<&str>) {
    if let Some(pk) = pubkey {
        LocalStorage::delete(storage_key(pk));
    }
}

fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

// -- Reactive store -----------------------------------------------------------

/// The account a set of subscriptions belongs to, held with them in one
/// signal so the two can never disagree.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Owned {
    owner: Option<String>,
    subs: Subs,
}

/// The backlog pass: topics already asked this connection, those queued, and
/// the REQ in flight (one at a time).
#[derive(Default)]
struct PumpState {
    done: HashSet<String>,
    queue: VecDeque<(String, u64)>,
    /// The batch the REQ in flight asks for, re-queued once if refused.
    inflight: Vec<(String, u64)>,
    /// Topics already re-queued once after a refusal on this connection.
    retried: HashSet<String>,
    sub: Option<String>,
    /// Bumped whenever the pass is abandoned (disconnect, account switch),
    /// so answers to an abandoned REQ are ignored.
    gen: u64,
}

/// Root fetches for titles: roots already asked this session, those queued,
/// and the REQ in flight (one at a time).
#[derive(Default)]
struct FetchState {
    asked: HashSet<String>,
    queue: VecDeque<String>,
    /// The roots the REQ in flight asks for, re-queued once if refused.
    inflight: Vec<String>,
    /// Roots already re-queued once after a refusal this session.
    retried: HashSet<String>,
    sub: Option<String>,
    gen: u64,
}

/// State of the cross-device copy for the current account.
#[derive(Clone, Debug, Default)]
struct SyncCtl {
    /// This account's first fetch-and-merge succeeded: publishing is allowed.
    fetched: bool,
    /// Local-only for the rest of the session (unreadable relay copy, no
    /// NIP-44, no signer).
    disabled: bool,
    busy: bool,
    /// Local changes the relay copy may lack.
    dirty: bool,
    /// Counts local changes, so a publish started before a change does not
    /// clear `dirty`.
    seq: u64,
    last_publish_ms: u64,
    timer_armed: bool,
    /// The newest relay copy seen: its id, `created_at` and contents.
    remote_id: Option<String>,
    remote_created_at: u64,
    remote: Option<Subs>,
}

/// What the store needs from elsewhere, captured once at the app root.
#[derive(Clone)]
struct Deps {
    auth: AuthStore,
    relay: RelayConnection,
    channels: ChannelStore,
    zone_keys: Option<ZoneKeyStore>,
}

/// Delay before a publish once changes settle, milliseconds.
const PUBLISH_SETTLE_MS: u64 = 2_000;
/// At most one publish per this many milliseconds.
const PUBLISH_INTERVAL_MS: u64 = 60_000;

/// Reactive thread-subscription store, provided via context
/// ([`provide_thread_subs`], [`use_thread_subs`]). `Copy`; every reading
/// method is reactive.
#[derive(Clone, Copy)]
pub struct ThreadSubsStore {
    owned: RwSignal<Owned>,
    unseen: RwSignal<Unseen>,
    pubkey: Memo<Option<String>>,
    generation: StoredValue<u64>,
    topics: Memo<Vec<SubscribedTopic>>,
    total: Memo<UnreadCount>,
    sync_status: RwSignal<SyncStatus>,
    pump: StoredValue<PumpState, leptos::prelude::LocalStorage>,
    fetch: StoredValue<FetchState, leptos::prelude::LocalStorage>,
    sync: StoredValue<SyncCtl>,
    deps: StoredValue<Deps, leptos::prelude::LocalStorage>,
}

impl ThreadSubsStore {
    fn new(deps: Deps) -> Self {
        let owned = RwSignal::new(Owned::default());
        let unseen = RwSignal::new(Unseen::default());
        let pubkey = deps.auth.pubkey();
        let channels = deps.channels;

        // The followed topics of the signed-in account; empty for a moment
        // after an account switch until the switch has loaded the new list.
        let current = move || -> Vec<Entry> {
            let pk = pubkey.get();
            owned.with(|o| {
                if o.owner == pk {
                    o.subs.active().cloned().collect()
                } else {
                    Vec::new()
                }
            })
        };
        let titles = Memo::new(move |_| {
            let wanted: Vec<(String, String)> = current().into_iter().map(|e| (e.r, e.c)).collect();
            channels
                .channel_messages
                .with(|m| resolve_titles(m, &wanted))
        });
        let topics = Memo::new(move |_| {
            let entries = current();
            let titles = titles.get();
            let zones = crate::stores::zones::load_zones();
            let metas: HashMap<String, crate::stores::channels::ChannelMeta> =
                channels.channels.with(|list| {
                    list.iter()
                        .filter(|c| entries.iter().any(|e| e.c == c.id))
                        .map(|c| (c.id.clone(), c.clone()))
                        .collect()
                });
            let mut out: Vec<SubscribedTopic> = unseen.with(|u| {
                entries
                    .iter()
                    .map(|e| {
                        let meta = metas.get(&e.c);
                        let zone = meta
                            .and_then(|m| {
                                crate::stores::zones::section_to_zone(
                                    crate::utils::section_url::effective_section_tag(m, &zones),
                                    &zones,
                                )
                            })
                            .unwrap_or_else(|| e.z.clone());
                        let zone_slug = meta
                            .and_then(|m| crate::utils::section_url::channel_zone_slug(m, &zones));
                        let count = u.count(&e.r);
                        SubscribedTopic {
                            root: e.r.clone(),
                            channel: e.c.clone(),
                            zone,
                            zone_slug,
                            title: titles.get(&e.r).cloned().flatten(),
                            unread: count.count,
                            capped: count.capped,
                        }
                    })
                    .collect()
            });
            sort_topics(&mut out);
            out
        });
        let total = Memo::new(move |_| {
            let pk = pubkey.get();
            if owned.with(|o| o.owner != pk) {
                return UnreadCount::default();
            }
            unseen.with(Unseen::total)
        });

        Self {
            owned,
            unseen,
            pubkey,
            generation: StoredValue::new(0),
            topics,
            total,
            sync_status: RwSignal::new(SyncStatus::Idle),
            pump: StoredValue::new_local(PumpState::default()),
            fetch: StoredValue::new_local(FetchState::default()),
            sync: StoredValue::new(SyncCtl::default()),
            deps: StoredValue::new_local(deps),
        }
    }

    // -- Reading (reactive) ---------------------------------------------------

    /// Run `f` on the signed-in account's subscriptions (tracked). Before an
    /// account switch has loaded the new account's list, `f` sees none.
    fn with_current<R>(&self, f: impl FnOnce(&Subs) -> R) -> R {
        let pk = self.pubkey.get();
        self.owned.with(|o| {
            if o.owner == pk {
                f(&o.subs)
            } else {
                f(&Subs::default())
            }
        })
    }

    /// Whether the member follows topic `root`. Reactive.
    pub fn is_subscribed(&self, root: &str) -> bool {
        self.with_current(|s| s.is_active(root))
    }

    /// How many topics the member follows. Reactive.
    pub fn active_count(&self) -> usize {
        self.with_current(Subs::active_count)
    }

    /// Whether the member follows [`MAX_ACTIVE_SUBSCRIPTIONS`] topics, so a
    /// further [`Self::subscribe`] would be refused. Reactive.
    pub fn at_limit(&self) -> bool {
        self.active_count() >= MAX_ACTIVE_SUBSCRIPTIONS
    }

    /// Unseen posts in followed topic `root` (zero when not followed).
    /// Reactive.
    pub fn unread(&self, root: &str) -> UnreadCount {
        let pk = self.pubkey.get();
        if self.owned.with(|o| o.owner != pk) {
            return UnreadCount::default();
        }
        let root = root.to_ascii_lowercase();
        self.unseen.with(|u| u.count(&root))
    }

    /// The followed topics with titles and unread counts, sorted for display
    /// (alphabetical by title, case-insensitive; topics with no title yet
    /// last, by id). A memo: rows change only when their data does.
    pub fn topics(&self) -> Memo<Vec<SubscribedTopic>> {
        self.topics
    }

    /// Unseen posts across every followed topic. A memo.
    pub fn total_unread(&self) -> Memo<UnreadCount> {
        self.total
    }

    /// State of the cross-device copy. Reactive.
    pub fn sync_status(&self) -> SyncStatus {
        self.sync_status.get()
    }

    /// Read markers of the followed topics, by lower-case root id (tracked).
    /// For the notification producer.
    pub(crate) fn followed_markers(&self) -> HashMap<String, u64> {
        self.with_current(|s| {
            s.active()
                .filter_map(|e| s.read_at(&e.r).map(|t| (e.r.clone(), t)))
                .collect()
        })
    }

    // -- Changing -------------------------------------------------------------

    /// Follow topic `root` (a topic root event id) in channel `channel`.
    /// The topic's read marker starts at now, so only posts from now on count
    /// as unread. Idempotent.
    pub fn subscribe(&self, root: &str, channel: &str) -> Result<(), SubscribeError> {
        self.ensure_owner();
        if self.owned.with_untracked(|o| o.owner.is_none()) {
            return Err(SubscribeError::NotSignedIn);
        }
        let zone = self.deps.with_value(|d| {
            crate::zone_crypto::store::channel_zone(d.channels, channel)
                .map(|(z, _, _)| z)
                .unwrap_or_default()
        });
        let (now_ms, now_secs) = (now_ms(), now_secs());
        let mut result = Ok(false);
        self.owned.update(|o| {
            result = o.subs.subscribe(root, channel, &zone, now_ms, now_secs);
        });
        if result? {
            self.after_change();
        }
        Ok(())
    }

    /// Stop following topic `root`. Its unread count goes with it.
    pub fn unsubscribe(&self, root: &str) {
        self.ensure_owner();
        let now = now_ms();
        let mut changed = false;
        self.owned.update(|o| {
            if o.owner.is_some() {
                changed = o.subs.unsubscribe(root, now);
            }
        });
        if changed {
            self.after_change();
        }
    }

    /// [`Self::unsubscribe`] when followed, else [`Self::subscribe`].
    /// Returns whether the topic is followed afterwards.
    pub fn toggle(&self, root: &str, channel: &str) -> Result<bool, SubscribeError> {
        self.ensure_owner();
        let on = self.owned.with_untracked(|o| o.subs.is_active(root));
        if on {
            self.unsubscribe(root);
            Ok(false)
        } else {
            self.subscribe(root, channel).map(|()| true)
        }
    }

    /// The member has seen followed topic `root` up to `upto` (unix seconds):
    /// pass the `created_at` of the newest post the view shows. Posts at or
    /// before it stop counting as unread. Never moves the marker back; a
    /// topic not followed is ignored.
    pub fn mark_read(&self, root: &str, upto: u64) {
        self.ensure_owner();
        let mut changed = false;
        self.owned.update(|o| {
            changed = o.subs.mark_read(root, upto);
        });
        if changed {
            self.after_change();
        }
    }

    /// Mark every followed topic read: each marker moves to now, or to the
    /// newest unseen post if that is later (a post dated in the future).
    pub fn mark_all_read(&self) {
        self.ensure_owner();
        let now = now_secs();
        let targets: Vec<(String, u64)> = self.owned.with_untracked(|o| {
            self.unseen.with_untracked(|u| {
                o.subs
                    .active()
                    .map(|e| (e.r.clone(), u.newest(&e.r).unwrap_or(0).max(now)))
                    .collect()
            })
        });
        let mut changed = false;
        self.owned.update(|o| {
            for (root, upto) in &targets {
                changed |= o.subs.mark_read(root, *upto);
            }
        });
        if changed {
            self.after_change();
        }
    }

    /// After any local change: drop what no longer counts, save (merging with
    /// what another tab saved), and schedule the relay copy.
    fn after_change(&self) {
        self.reconcile_unseen();
        self.persist();
        self.sync.update_value(|c| {
            c.dirty = true;
            c.seq += 1;
        });
        self.sync_kick();
    }

    fn reconcile_unseen(&self) {
        let subs = self.owned.with_untracked(|o| o.subs.clone());
        let mut next = self.unseen.get_untracked();
        next.reconcile(&subs);
        if self.unseen.with_untracked(|u| *u != next) {
            self.unseen.set(next);
        }
    }

    /// Save to the owner's key, merged with what is stored (another tab may
    /// have written since), and adopt the merge.
    fn persist(&self) {
        let Some(owner) = self.owned.with_untracked(|o| o.owner.clone()) else {
            return;
        };
        let memory = self.owned.with_untracked(|o| o.subs.clone());
        let mut merged = memory.join(&load_subs(&owner));
        merged.prune(now_ms());
        let _ = LocalStorage::set(storage_key(&owner), merged.to_doc());
        if merged != memory {
            self.owned.update(|o| o.subs = merged);
            self.reconcile_unseen();
        }
    }

    /// Load-only reload after another tab wrote a subscriptions key: merge
    /// what is stored for the current owner into memory. Never writes.
    fn reload_from_storage(&self) {
        let Some(owner) = self.owned.with_untracked(|o| o.owner.clone()) else {
            return;
        };
        let memory = self.owned.with_untracked(|o| o.subs.clone());
        let merged = memory.join(&load_subs(&owner));
        if merged != memory {
            self.owned.update(|o| o.subs = merged);
            self.reconcile_unseen();
        }
    }

    // -- Account switching ----------------------------------------------------

    /// Make the loaded list the signed-in account's, in one step: the owner
    /// and its subscriptions change together, and everything belonging to
    /// the previous account (unseen sets, the backlog pass, title fetches,
    /// the relay copy's state) is dropped. In-flight work for the previous
    /// account sees a new generation and discards its answers.
    fn ensure_owner(&self) {
        let pk = self.pubkey.get_untracked();
        if self.owned.with_untracked(|o| o.owner == pk) {
            return;
        }
        let subs = pk.as_deref().map(load_subs).unwrap_or_default();
        self.generation.update_value(|g| *g += 1);
        self.stop_pump();
        self.stop_fetch();
        self.fetch.update_value(|f| f.asked.clear());
        self.sync.set_value(SyncCtl::default());
        self.sync_status.set(SyncStatus::Idle);
        self.unseen.set(Unseen::default());
        self.owned.set(Owned { owner: pk, subs });
    }

    fn generation(&self) -> u64 {
        self.generation.try_get_value().unwrap_or(u64::MAX)
    }

    fn me(&self) -> Option<String> {
        self.owned.with_untracked(|o| o.owner.clone())
    }

    // -- Live counts ----------------------------------------------------------

    /// The channel store inserted `batch`: count replies in followed topics.
    fn on_inserted(&self, batch: &[InsertedMessage]) {
        let pk = self.pubkey.get_untracked();
        let fresh: Vec<(String, String, u64)> = self.owned.with_untracked(|o| {
            if o.owner.is_none() || o.owner != pk {
                return Vec::new();
            }
            batch
                .iter()
                .filter_map(|m| {
                    unseen_root(m, &o.subs, o.owner.as_deref())
                        .map(|r| (r.to_string(), m.id.clone(), m.created_at))
                })
                .collect()
        });
        if fresh.is_empty() {
            return;
        }
        self.unseen.update(|u| {
            for (root, id, ts) in &fresh {
                u.note(root, id, *ts);
            }
        });
    }

    // -- Backlog pass ---------------------------------------------------------

    /// Abandon the backlog pass: close the REQ in flight and forget what was
    /// asked, so the next connection asks again.
    fn stop_pump(&self) {
        let sub = self
            .pump
            .try_update_value(|p| {
                p.gen += 1;
                p.done.clear();
                p.queue.clear();
                p.inflight.clear();
                p.retried.clear();
                p.sub.take()
            })
            .flatten();
        if let Some(id) = sub.filter(|s| !s.is_empty()) {
            self.deps.with_value(|d| d.relay.unsubscribe(&id));
        }
    }

    /// Queue the followed topics not yet asked on this connection.
    fn enqueue_backlog(&self, wanted: Vec<(String, u64)>) {
        let added = self
            .pump
            .try_update_value(|p| {
                let mut added = false;
                for (root, read) in wanted {
                    if p.done.insert(root.clone()) {
                        p.queue.push_back((root, read));
                        added = true;
                    }
                }
                added
            })
            .unwrap_or(false);
        if added {
            self.pump_next();
        }
    }

    /// Send the next backlog REQ unless one is in flight: up to
    /// [`BACKLOG_FILTERS_PER_REQ`] topics, closed on its answer (or a CLOSED,
    /// or a timeout), then the next.
    fn pump_next(&self) {
        let next = self
            .pump
            .try_update_value(|p| {
                if p.sub.is_some() || p.queue.is_empty() {
                    return None;
                }
                let n = p.queue.len().min(BACKLOG_FILTERS_PER_REQ);
                let batch: Vec<(String, u64)> = p.queue.drain(..n).collect();
                p.inflight = batch.clone();
                // Reserve the slot before subscribing; the real id replaces
                // it once `subscribe` returns.
                p.sub = Some(String::new());
                Some((batch, p.gen))
            })
            .flatten();
        let Some((batch, gen)) = next else {
            return;
        };
        let Some(deps) = self.deps.try_with_value(Clone::clone) else {
            return;
        };
        let store = *self;
        let wanted: HashSet<String> = batch.iter().map(|(r, _)| r.clone()).collect();
        let delivered: Rc<RefCell<HashMap<String, u64>>> = Rc::default();
        let filters = backlog_batches(&batch)
            .into_iter()
            .next()
            .unwrap_or_default();

        let on_event = {
            let delivered = delivered.clone();
            let deps = deps.clone();
            Rc::new(move |ev: NostrEvent| {
                if store.pump.try_with_value(|p| p.gen) != Some(gen) {
                    return;
                }
                store.on_backlog_event(&deps, &wanted, &delivered, ev);
            })
        };
        let done = Rc::new(Cell::new(false));
        // `refused`: the relay answered CLOSED (e.g. its per-connection
        // subscription cap, likely right after AUTH): re-queue the batch once,
        // after a pause.
        let finish: Rc<dyn Fn(bool)> = {
            let relay = deps.relay.clone();
            Rc::new(move |refused: bool| {
                if done.replace(true) {
                    return;
                }
                let current = store.pump.try_with_value(|p| p.gen) == Some(gen);
                if !current {
                    return;
                }
                let (sub, retry) = store
                    .pump
                    .try_update_value(|p| {
                        let inflight = std::mem::take(&mut p.inflight);
                        let again = if refused {
                            requeue_once(inflight, |(r, _)| r.as_str(), &mut p.retried)
                        } else {
                            Vec::new()
                        };
                        let retry = !again.is_empty();
                        p.queue.extend(again);
                        (p.sub.take(), retry)
                    })
                    .unwrap_or((None, false));
                if let Some(id) = sub.filter(|s| !s.is_empty()) {
                    relay.unsubscribe(&id);
                }
                let full: Vec<String> = delivered
                    .borrow()
                    .iter()
                    .filter(|(_, n)| **n >= BACKLOG_LIMIT)
                    .map(|(r, _)| r.clone())
                    .collect();
                if !full.is_empty() {
                    store.unseen.update(|u| {
                        for r in &full {
                            u.saturate(r);
                        }
                    });
                }
                if retry {
                    crate::utils::set_timeout_once(move || store.pump_next(), RETRY_DELAY_MS);
                } else {
                    store.pump_next();
                }
            })
        };
        let on_receipt = {
            let finish = finish.clone();
            Rc::new(move |authed: bool| {
                if authed {
                    finish(false);
                }
            })
        };
        let on_closed = {
            let finish = finish.clone();
            Rc::new(move |_reason: String| finish(true))
        };
        let id = deps
            .relay
            .subscribe_with_receipt_or_closed(filters, on_event, on_receipt, on_closed);
        let still = self
            .pump
            .try_update_value(|p| {
                if p.gen == gen && p.sub.as_deref() == Some("") {
                    p.sub = Some(id.clone());
                    true
                } else {
                    false
                }
            })
            .unwrap_or(false);
        if !still {
            // Abandoned (or already answered) while subscribing: the slot
            // held a placeholder, so close the real subscription here.
            deps.relay.unsubscribe(&id);
            return;
        }
        crate::utils::set_timeout_once(move || finish(false), PAGE_TIMEOUT_MS as i32);
    }

    /// One backlog delivery: admitted and decrypted exactly as the store's
    /// other read paths do (so an edit or the author is judged on the post
    /// itself, not a sealed envelope), counted if it is unseen, and its
    /// decrypt state dropped unless a list holds it.
    fn on_backlog_event(
        &self,
        deps: &Deps,
        wanted: &HashSet<String>,
        delivered: &Rc<RefCell<HashMap<String, u64>>>,
        ev: NostrEvent,
    ) {
        let Some((list, ev)) = deps.channels.ingest(deps.zone_keys, ev, "") else {
            return;
        };
        let msg = InsertedMessage::of(&list, &ev);
        if let Some(root) = msg.reply_root.as_deref().filter(|r| wanted.contains(*r)) {
            *delivered.borrow_mut().entry(root.to_string()).or_insert(0) += 1;
            let me = self.me();
            let counted = self
                .owned
                .with_untracked(|o| unseen_root(&msg, &o.subs, me.as_deref()).map(str::to_string));
            if let Some(root) = counted {
                self.unseen.update(|u| {
                    u.note(&root, &msg.id, msg.created_at);
                });
            }
        }
        if !held_anywhere(deps.channels, &ev.id, ev.created_at) {
            if let Some(z) = deps.zone_keys {
                z.forget(std::slice::from_ref(&ev.id));
            }
        }
    }

    // -- Title fetches --------------------------------------------------------

    fn stop_fetch(&self) {
        let sub = self
            .fetch
            .try_update_value(|f| {
                f.gen += 1;
                // Roots dropped before an answer may be asked again.
                for root in f.queue.drain(..).chain(f.inflight.drain(..)) {
                    f.asked.remove(&root);
                }
                f.retried.clear();
                f.sub.take()
            })
            .flatten();
        if let Some(id) = sub.filter(|s| !s.is_empty()) {
            self.deps.with_value(|d| d.relay.unsubscribe(&id));
        }
    }

    /// Queue the followed roots the channel store does not hold and that were
    /// not asked for this session.
    fn enqueue_root_fetches(&self, wanted: Vec<(String, String)>) {
        let channels = self.deps.with_value(|d| d.channels);
        let added = self
            .fetch
            .try_update_value(|f| {
                let mut added = false;
                for (root, channel) in wanted {
                    if f.asked.contains(&root) {
                        continue;
                    }
                    let held = channels
                        .channel_messages
                        .with_untracked(|m| root_held(m, &root, &channel));
                    f.asked.insert(root.clone());
                    if !held {
                        f.queue.push_back(root);
                        added = true;
                    }
                }
                added
            })
            .unwrap_or(false);
        if added {
            self.fetch_next();
        }
    }

    /// Send the next root fetch unless one is in flight: up to
    /// [`ROOT_FETCH_BATCH`] ids, closed on its answer. Each root enters the
    /// channel store's root list for its channel through the usual admission
    /// and decrypt path, so a root still locked becomes readable when its
    /// zone key arrives.
    fn fetch_next(&self) {
        let next = self
            .fetch
            .try_update_value(|f| {
                if f.sub.is_some() || f.queue.is_empty() {
                    return None;
                }
                let n = f.queue.len().min(ROOT_FETCH_BATCH);
                let batch: Vec<String> = f.queue.drain(..n).collect();
                f.inflight = batch.clone();
                f.sub = Some(String::new());
                Some((batch, f.gen))
            })
            .flatten();
        let Some((batch, gen)) = next else {
            return;
        };
        let Some(deps) = self.deps.try_with_value(Clone::clone) else {
            return;
        };
        let store = *self;
        let wanted: HashSet<String> = batch.iter().cloned().collect();
        let on_event = {
            let deps = deps.clone();
            Rc::new(move |ev: NostrEvent| {
                if store.fetch.try_with_value(|f| f.gen) != Some(gen) {
                    return;
                }
                accept_root(&deps, &wanted, ev);
            })
        };
        let done = Rc::new(Cell::new(false));
        // As in `pump_next`: a refused batch is re-queued once, after a pause.
        let finish: Rc<dyn Fn(bool)> = {
            let relay = deps.relay.clone();
            Rc::new(move |refused: bool| {
                if done.replace(true) || store.fetch.try_with_value(|f| f.gen) != Some(gen) {
                    return;
                }
                let (sub, retry) = store
                    .fetch
                    .try_update_value(|f| {
                        let inflight = std::mem::take(&mut f.inflight);
                        let again = if refused {
                            requeue_once(inflight, String::as_str, &mut f.retried)
                        } else {
                            Vec::new()
                        };
                        let retry = !again.is_empty();
                        f.queue.extend(again);
                        (f.sub.take(), retry)
                    })
                    .unwrap_or((None, false));
                if let Some(id) = sub.filter(|s| !s.is_empty()) {
                    relay.unsubscribe(&id);
                }
                if retry {
                    crate::utils::set_timeout_once(move || store.fetch_next(), RETRY_DELAY_MS);
                } else {
                    store.fetch_next();
                }
            })
        };
        let on_receipt = {
            let finish = finish.clone();
            Rc::new(move |authed: bool| {
                if authed {
                    finish(false);
                }
            })
        };
        let on_closed = {
            let finish = finish.clone();
            Rc::new(move |_reason: String| finish(true))
        };
        let id = deps.relay.subscribe_with_receipt_or_closed(
            root_fetch_filters(&batch),
            on_event,
            on_receipt,
            on_closed,
        );
        let still = self
            .fetch
            .try_update_value(|f| {
                if f.gen == gen && f.sub.as_deref() == Some("") {
                    f.sub = Some(id.clone());
                    true
                } else {
                    false
                }
            })
            .unwrap_or(false);
        if !still {
            // As in `pump_next`: close the real subscription.
            deps.relay.unsubscribe(&id);
            return;
        }
        crate::utils::set_timeout_once(move || finish(false), PAGE_TIMEOUT_MS as i32);
    }

    // -- Cross-device copy ----------------------------------------------------

    /// Start or schedule the relay copy's work when it can run: signed in, the
    /// relay session authenticated, not local-only, nothing in flight. The
    /// first run for an account fetches and merges; later runs publish
    /// pending changes, at most once per [`PUBLISH_INTERVAL_MS`].
    fn sync_kick(&self) {
        let ready = self
            .deps
            .with_value(|d| d.relay.authenticated().get_untracked())
            && self.owned.with_untracked(|o| o.owner.is_some())
            && self
                .owned
                .with_untracked(|o| o.owner == self.pubkey.get_untracked());
        if !ready {
            return;
        }
        let ctl = self.sync.get_value();
        if ctl.disabled || ctl.busy {
            return;
        }
        if !ctl.fetched {
            self.spawn_sync();
        } else if ctl.dirty {
            self.schedule_publish();
        }
    }

    fn schedule_publish(&self) {
        let ctl = self.sync.get_value();
        if ctl.timer_armed {
            return;
        }
        self.sync.update_value(|c| c.timer_armed = true);
        let earliest = ctl.last_publish_ms.saturating_add(PUBLISH_INTERVAL_MS);
        let delay = earliest.saturating_sub(now_ms()).max(PUBLISH_SETTLE_MS);
        let gen = self.generation();
        let store = *self;
        crate::utils::set_timeout_once(
            move || {
                if store.generation() != gen {
                    return;
                }
                store.sync.update_value(|c| c.timer_armed = false);
                let ctl = store.sync.get_value();
                if ctl.dirty && !ctl.busy && !ctl.disabled {
                    store.spawn_sync();
                }
            },
            delay.min(i32::MAX as u64) as i32,
        );
    }

    fn spawn_sync(&self) {
        let store = *self;
        let gen = self.generation();
        self.sync.update_value(|c| c.busy = true);
        self.sync_status.set(SyncStatus::Syncing);
        leptos::task::spawn_local(async move {
            let outcome = store.sync_once(gen).await;
            if store.generation() != gen {
                return;
            }
            store.sync.update_value(|c| c.busy = false);
            match outcome {
                Ok(()) => {
                    store.sync_status.set(SyncStatus::Synced);
                    if store.sync.get_value().dirty {
                        store.schedule_publish();
                    }
                }
                Err(reason) => {
                    if reason.ends_session() {
                        store.sync.update_value(|c| c.disabled = true);
                    }
                    store.sync_status.set(SyncStatus::LocalOnly(reason));
                }
            }
        });
    }

    /// The signer for the relay copy, when it can encrypt to itself.
    fn sync_signer(&self) -> Result<Rc<dyn nostr_bbs_core::signer::Signer>, LocalOnlyReason> {
        let auth = self.deps.with_value(|d| d.auth);
        let signer = auth.get_signer().ok_or(LocalOnlyReason::NoSigner)?;
        let nip07 = auth.state().with_untracked(|s| s.is_nip07);
        if nip07 && !crate::auth::nip07::nip07_has_nip44() {
            return Err(LocalOnlyReason::NoNip44);
        }
        if Some(signer.public_key()) != self.me().as_deref() {
            return Err(LocalOnlyReason::NoSigner);
        }
        Ok(signer)
    }

    /// Fetch the relay copy, merge it into the local list, and publish the
    /// merge when the relay copy lacks something. Never publishes before a
    /// successful fetch, nor over a copy it cannot read.
    async fn sync_once(&self, gen: u64) -> Result<(), LocalOnlyReason> {
        let signer = self.sync_signer()?;
        let owner = signer.public_key().to_string();
        let relay = self.deps.with_value(|d| d.relay.clone());
        let seq0 = self.sync.get_value().seq;

        let remote_ev = sync::fetch_latest(&relay, &owner).await?;
        if self.generation() != gen {
            return Ok(());
        }
        let known = self.sync.get_value();
        let remote: Option<Subs> = match &remote_ev {
            Some(ev) if known.remote_id.as_deref() == Some(ev.id.as_str()) => known.remote,
            Some(ev) => Some(sync::open(&*signer, ev).await?),
            None => None,
        };
        if self.generation() != gen {
            return Ok(());
        }
        let remote_created_at = remote_ev.as_ref().map_or(0, |e| e.created_at);
        if let Some(r) = &remote {
            self.adopt_remote(r);
        }
        self.sync.update_value(|c| {
            c.fetched = true;
            c.remote_id = remote_ev.as_ref().map(|e| e.id.clone());
            c.remote_created_at = c.remote_created_at.max(remote_created_at);
            c.remote = remote.clone();
        });

        let now = now_ms();
        let local = self.owned.with_untracked(|o| {
            let mut s = o.subs.clone();
            s.prune(now);
            s
        });
        let needed = match remote {
            None => !local.entries.is_empty(),
            Some(mut r) => {
                r.prune(now);
                r != local
            }
        };
        if needed {
            let created_at = now_secs().max(self.sync.get_value().remote_created_at + 1);
            let ev = sync::seal(&*signer, &local, created_at).await?;
            if self.generation() != gen {
                return Ok(());
            }
            sync::publish(&relay, &ev).await?;
            if self.generation() != gen {
                return Ok(());
            }
            self.sync.update_value(|c| {
                c.last_publish_ms = now_ms();
                c.remote_id = Some(ev.id.clone());
                c.remote_created_at = ev.created_at;
                c.remote = Some(local.clone());
            });
        }
        self.sync.update_value(|c| {
            if c.seq == seq0 {
                c.dirty = false;
            }
        });
        Ok(())
    }

    /// Merge the relay copy `remote` into the local list and save.
    fn adopt_remote(&self, remote: &Subs) {
        let memory = self.owned.with_untracked(|o| o.subs.clone());
        let merged = memory.join(remote);
        if merged != memory {
            self.owned.update(|o| o.subs = merged);
        }
        self.persist();
        self.reconcile_unseen();
    }

    /// On `pagehide`, publish pending changes if that can finish without
    /// waiting: a local-key or passkey signer (a NIP-07 extension cannot
    /// answer while the page unloads), after this session's first merge.
    ///
    /// **The one exception to fetch-then-merge before publishing**: a fetch
    /// cannot complete while the page unloads, so the copy published is the
    /// local list, which holds the last relay copy this session saw. A change
    /// another device published since that fetch is overwritten on the relay;
    /// it comes back when that device next merges and publishes (its local
    /// copy still has it), unless that device has signed out since, which
    /// removed its local copy. Best effort: the frame may not leave before the
    /// page goes, in which case the change is published at the next session's
    /// first merge.
    fn flush_on_pagehide(&self) {
        let ctl = self.sync.get_value();
        if !ctl.dirty || !ctl.fetched || ctl.disabled || ctl.busy {
            return;
        }
        let nip07 = self
            .deps
            .with_value(|d| d.auth.state().with_untracked(|s| s.is_nip07));
        if nip07 {
            return;
        }
        let Ok(signer) = self.sync_signer() else {
            return;
        };
        let local = self.owned.with_untracked(|o| o.subs.clone());
        let created_at = now_secs().max(ctl.remote_created_at + 1);
        let relay = self.deps.with_value(|d| d.relay.clone());
        let store = *self;
        let gen = self.generation();
        leptos::task::spawn_local(async move {
            if let Ok(ev) = sync::seal(&*signer, &local, created_at).await {
                if store.generation() != gen {
                    return;
                }
                relay.publish(&ev);
                // `dirty` stays set: if the page is kept (back/forward cache)
                // or the frame never left, the normal path publishes again,
                // fetching and merging first.
                store.sync.update_value(|c| {
                    c.last_publish_ms = now_ms();
                    c.remote_id = Some(ev.id.clone());
                    c.remote_created_at = ev.created_at;
                    c.remote = Some(local);
                });
            }
        });
    }

    // -- Wiring ---------------------------------------------------------------

    /// Attach the effects and listeners. Called once by
    /// [`provide_thread_subs`].
    fn start(&self) {
        let store = *self;
        let (relay, channels) = self.deps.with_value(|d| (d.relay.clone(), d.channels));
        let authed = relay.authenticated();
        let pubkey = self.pubkey;
        let owned = self.owned;

        // Account switches: load the new account's list in the same step as
        // the owner changes.
        Effect::new(move |_| {
            let _ = pubkey.get();
            store.ensure_owner();
        });

        // Live counts from the channel store's inserted-message hook.
        channels.on_inserted(Rc::new(move |batch: &[InsertedMessage]| {
            store.on_inserted(batch);
        }));

        // Backlog pass and title fetches: after AUTH settles, again after a
        // reconnect (AUTH drops and returns), and for topics that become
        // followed meanwhile (here or merged from another device or tab).
        Effect::new(move |_| {
            let is_authed = authed.get();
            let pk = pubkey.get();
            let (owner_ok, backlog, roots) = owned.with(|o| {
                let ok = o.owner.is_some() && o.owner == pk;
                let backlog: Vec<(String, u64)> = o
                    .subs
                    .active()
                    .filter_map(|e| o.subs.read_at(&e.r).map(|t| (e.r.clone(), t)))
                    .collect();
                let roots: Vec<(String, String)> = o
                    .subs
                    .active()
                    .map(|e| (e.r.clone(), e.c.clone()))
                    .collect();
                (ok, backlog, roots)
            });
            if !is_authed || !owner_ok {
                store.stop_pump();
                store.stop_fetch();
                return;
            }
            store.enqueue_backlog(backlog);
            store.enqueue_root_fetches(roots);
        });

        // Relay copy: first merge once AUTH settles for the account; retried
        // after a reconnect if it failed.
        let owner_memo = Memo::new(move |_| owned.with(|o| o.owner.clone()));
        Effect::new(move |_| {
            let is_authed = authed.get();
            let _ = owner_memo.get();
            if is_authed {
                store.sync_kick();
            }
        });

        // Another tab wrote a subscriptions key (any account: the reload reads
        // only the current owner's).
        crate::utils::on_cross_tab_storage_prefix_write(STORAGE_KEY_PREFIX, move || {
            store.reload_from_storage();
        });

        // Last chance to publish pending changes.
        let listener =
            gloo::events::EventListener::new(&gloo::utils::window(), "pagehide", move |_| {
                store.flush_on_pagehide();
            });
        listener.forget();
    }
}

/// Take a fetched root into the channel store's root list for its channel if
/// it is one of `wanted` and shaped as a topic root (or a still-locked sealed
/// root carrying the topic marker); otherwise drop its decrypt state.
fn accept_root(deps: &Deps, wanted: &HashSet<String>, ev: NostrEvent) {
    let inner = nostr_bbs_core::sealed::parse_sealed(&ev.tags).map(|s| s.inner_id);
    let Some((cid, ev)) = deps.channels.ingest(deps.zone_keys, ev, "") else {
        return;
    };
    let id = ev.id.to_ascii_lowercase();
    let named = wanted.contains(&id) || inner.as_ref().is_some_and(|i| wanted.contains(i));
    let sealed = nostr_bbs_core::sealed::parse_sealed(&ev.tags).is_some();
    let marked = sealed
        && ev
            .tags
            .iter()
            .any(|t| t.len() == 2 && t[0] == "t" && t[1] == nostr_bbs_core::sealed::TOPIC_MARKER);
    let rooty = nostr_bbs_core::sealed::is_topic_root(&ev) || marked;
    if named && rooty {
        deps.channels.apply_page(vec![(roots_key(&cid), ev)]);
    } else if let Some(z) = deps.zone_keys {
        z.forget(std::slice::from_ref(&ev.id));
    }
}

// -- Context ------------------------------------------------------------------

/// Provide the thread-subscription store and start it. Call once at the app
/// root, after the auth store, the relay connection, the channel store and
/// the zone-key store are provided, and before the notification store's
/// `init_sync` runs (it reads this store for subscribed-topic notices).
pub fn provide_thread_subs() -> ThreadSubsStore {
    let deps = Deps {
        auth: use_auth(),
        relay: expect_context::<RelayConnection>(),
        channels: use_channel_store(),
        zone_keys: crate::zone_crypto::store::try_use_zone_key_store(),
    };
    let store = ThreadSubsStore::new(deps);
    provide_context(store);
    store.start();
    store
}

/// The thread-subscription store from context. Panics if
/// [`provide_thread_subs`] has not run.
pub fn use_thread_subs() -> ThreadSubsStore {
    expect_context::<ThreadSubsStore>()
}

/// The thread-subscription store from context, if provided.
pub fn try_use_thread_subs() -> Option<ThreadSubsStore> {
    use_context::<ThreadSubsStore>()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW_MS: u64 = 1_800_000_000_000;
    const NOW: u64 = NOW_MS / 1000;

    fn id(n: u32) -> String {
        format!("{n:064x}")
    }

    fn chan(n: u32) -> String {
        format!("{:064x}", 0xc000_0000u64 + n as u64)
    }

    fn entry(root: &str, on: bool, at: u64) -> Entry {
        Entry {
            r: root.to_string(),
            c: if on { chan(1) } else { String::new() },
            z: if on { "zone1".into() } else { String::new() },
            on,
            at,
        }
    }

    fn subs_of(entries: &[Entry], read: &[(&str, u64)]) -> Subs {
        let mut s = Subs::default();
        for e in entries {
            s.put(e.clone());
        }
        for (r, t) in read {
            s.read.insert(r.to_string(), *t);
        }
        s
    }

    fn msg(
        root: Option<&str>,
        pubkey: &str,
        created_at: u64,
        edit: bool,
        n: u32,
    ) -> InsertedMessage {
        InsertedMessage {
            list: chan(1),
            id: id(10_000 + n),
            pubkey: pubkey.to_string(),
            created_at,
            reply_root: root.map(str::to_string),
            edit,
        }
    }

    // -- serde --

    #[test]
    fn doc_round_trips_and_uses_the_compact_shape() {
        let mut s = Subs::default();
        s.subscribe(&id(1), &chan(1), "zone1", NOW_MS, NOW).unwrap();
        s.subscribe(&id(2), &chan(2), "", NOW_MS, NOW).unwrap();
        s.unsubscribe(&id(2), NOW_MS + 5);
        let json = serde_json::to_string(&s.to_doc()).unwrap();
        assert_eq!(
            json,
            format!(
                "{{\"subs\":[{{\"r\":\"{}\",\"c\":\"{}\",\"z\":\"zone1\",\"on\":true,\"at\":{NOW_MS},\"rd\":{NOW}}},\
                 {{\"r\":\"{}\",\"on\":false,\"at\":{}}}]}}",
                id(1),
                chan(1),
                id(2),
                NOW_MS + 5
            )
        );
        let back = Subs::from_doc(serde_json::from_str(&json).unwrap());
        assert_eq!(back, s);
    }

    #[test]
    fn malformed_entries_are_dropped_on_load() {
        let doc: SubsDoc = serde_json::from_value(serde_json::json!({
            "subs": [
                {"r": "not-hex", "c": "x", "on": true, "at": 1, "rd": 5},
                {"r": id(3).to_uppercase(), "c": chan(1), "z": "z", "on": true, "at": 2, "rd": 9},
                {"r": id(4), "c": "", "on": true, "at": 3},
                {"r": id(5), "c": "c".repeat(200), "on": true, "at": 3},
            ]
        }))
        .unwrap();
        let s = Subs::from_doc(doc);
        assert_eq!(s.entries.len(), 1);
        assert!(s.is_active(&id(3)));
        assert_eq!(s.read_at(&id(3)), Some(9));
    }

    #[test]
    fn a_missing_field_or_extra_field_still_loads() {
        let doc: SubsDoc = serde_json::from_str(r#"{"subs":[],"extra":1}"#).unwrap();
        assert_eq!(Subs::from_doc(doc), Subs::default());
        let doc: SubsDoc = serde_json::from_str("{}").unwrap();
        assert_eq!(Subs::from_doc(doc), Subs::default());
    }

    // -- markers --

    #[test]
    fn subscribe_sets_the_marker_to_now_and_markers_never_go_back() {
        let mut s = Subs::default();
        s.subscribe(&id(1), &chan(1), "", NOW_MS, NOW).unwrap();
        assert_eq!(s.read_at(&id(1)), Some(NOW));
        assert!(s.mark_read(&id(1), NOW + 10));
        assert!(!s.mark_read(&id(1), NOW + 5));
        assert_eq!(s.read_at(&id(1)), Some(NOW + 10));
        // Re-subscribing an active topic leaves the marker alone.
        s.subscribe(&id(1), &chan(1), "", NOW_MS + 1, NOW + 1)
            .unwrap();
        assert_eq!(s.read_at(&id(1)), Some(NOW + 10));
        // A topic not followed is ignored.
        assert!(!s.mark_read(&id(9), NOW));
        assert_eq!(s.read_at(&id(9)), None);
    }

    #[test]
    fn a_synced_subscription_without_a_marker_reads_from_when_it_was_made() {
        let s = subs_of(&[entry(&id(1), true, NOW_MS)], &[]);
        assert_eq!(s.read_at(&id(1)), Some(NOW));
    }

    #[test]
    fn roots_are_case_insensitive() {
        let mut s = Subs::default();
        s.subscribe(&id(0xabc).to_uppercase(), &chan(1), "", NOW_MS, NOW)
            .unwrap();
        assert!(s.is_active(&id(0xabc)));
        assert!(s.unsubscribe(&id(0xabc).to_uppercase(), NOW_MS + 1));
        assert!(!s.is_active(&id(0xabc)));
    }

    // -- cap --

    #[test]
    fn the_active_cap_refuses_with_a_clear_error_and_frees_on_unsubscribe() {
        let mut s = Subs::default();
        for n in 0..MAX_ACTIVE_SUBSCRIPTIONS as u32 {
            s.subscribe(&id(n), &chan(1), "", NOW_MS, NOW).unwrap();
        }
        let err = s
            .subscribe(&id(9999), &chan(1), "", NOW_MS, NOW)
            .unwrap_err();
        assert_eq!(
            err,
            SubscribeError::LimitReached {
                limit: MAX_ACTIVE_SUBSCRIPTIONS
            }
        );
        assert!(err.to_string().contains("150"));
        // An already-followed topic is not refused.
        assert_eq!(s.subscribe(&id(0), &chan(1), "", NOW_MS, NOW), Ok(false));
        s.unsubscribe(&id(0), NOW_MS + 1);
        assert_eq!(
            s.subscribe(&id(9999), &chan(1), "", NOW_MS + 2, NOW),
            Ok(true)
        );
    }

    #[test]
    fn invalid_ids_are_refused() {
        let mut s = Subs::default();
        assert_eq!(
            s.subscribe("abc", &chan(1), "", NOW_MS, NOW),
            Err(SubscribeError::InvalidTopic)
        );
        assert_eq!(
            s.subscribe(&id(1), "", "", NOW_MS, NOW),
            Err(SubscribeError::InvalidTopic)
        );
        assert_eq!(
            s.subscribe(&id(1), "general", "", NOW_MS, NOW),
            Err(SubscribeError::InvalidTopic),
            "a channel is a kind-40 event id, not a slug"
        );
        assert_eq!(
            s.subscribe(&id(1), &chan(1), &"z".repeat(MAX_ZONE_LEN + 1), NOW_MS, NOW),
            Err(SubscribeError::InvalidTopic)
        );
    }

    // -- merge --

    #[test]
    fn newer_entry_wins_and_tombstones_beat_older_subscriptions() {
        let a = subs_of(&[entry(&id(1), true, 100)], &[(&id(1), 50)]);
        let b = subs_of(&[entry(&id(1), false, 200)], &[]);
        let m = a.join(&b);
        assert!(!m.is_active(&id(1)));
        assert_eq!(m, b.join(&a));
        // A re-subscription after the tombstone wins in turn.
        let c = subs_of(&[entry(&id(1), true, 300)], &[(&id(1), 70)]);
        assert!(m.join(&c).is_active(&id(1)));
    }

    #[test]
    fn equal_times_break_ties_the_same_way_on_every_device() {
        let on = entry(&id(1), true, 100);
        let off = entry(&id(1), false, 100);
        let a = subs_of(std::slice::from_ref(&on), &[]);
        let b = subs_of(std::slice::from_ref(&off), &[]);
        assert_eq!(a.join(&b), b.join(&a));
        assert!(!a.join(&b).is_active(&id(1)), "off wins a tie");
        let mut other = on.clone();
        other.c = chan(2);
        let c = subs_of(&[other], &[]);
        assert_eq!(a.join(&c), c.join(&a));
    }

    #[test]
    fn read_markers_take_the_maximum() {
        let a = subs_of(&[entry(&id(1), true, 100)], &[(&id(1), 50)]);
        let b = subs_of(&[entry(&id(1), true, 90)], &[(&id(1), 80)]);
        assert_eq!(a.join(&b).read_at(&id(1)), Some(80));
    }

    #[test]
    fn merge_is_commutative_associative_and_idempotent() {
        let a = subs_of(
            &[entry(&id(1), true, 100), entry(&id(2), false, 400)],
            &[(&id(1), 10)],
        );
        let b = subs_of(
            &[entry(&id(1), false, 200), entry(&id(3), true, 50)],
            &[(&id(3), 7)],
        );
        let c = subs_of(
            &[entry(&id(1), true, 300), entry(&id(2), true, 300)],
            &[(&id(1), 20), (&id(2), 5)],
        );
        assert_eq!(a.join(&b), b.join(&a));
        assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)));
        assert_eq!(a.join(&a), a);
        let all = a.join(&b).join(&c);
        assert!(all.is_active(&id(1)));
        assert!(!all.is_active(&id(2)));
        assert!(all.is_active(&id(3)));
    }

    #[test]
    fn a_local_change_always_outranks_what_it_replaces() {
        let mut s = subs_of(&[entry(&id(1), true, NOW_MS + 10_000)], &[]);
        // The local clock is behind the stored entry.
        assert!(s.unsubscribe(&id(1), NOW_MS));
        assert_eq!(s.entries[&id(1)].at, NOW_MS + 10_001);
        let stale = subs_of(&[entry(&id(1), true, NOW_MS + 10_000)], &[]);
        assert!(!s.join(&stale).is_active(&id(1)));
    }

    // -- tombstones --

    #[test]
    fn tombstones_expire_and_are_bounded() {
        let mut s = subs_of(
            &[
                entry(&id(1), false, NOW_MS - TOMBSTONE_TTL_MS - 1),
                entry(&id(2), false, NOW_MS - 1),
                entry(&id(3), true, 1),
            ],
            &[(&id(2), 5), (&id(3), 6)],
        );
        s.prune(NOW_MS);
        assert!(!s.entries.contains_key(&id(1)), "expired tombstone dropped");
        assert!(s.entries.contains_key(&id(2)), "recent tombstone kept");
        assert!(s.is_active(&id(3)), "an old subscription is never pruned");
        assert!(
            !s.read.contains_key(&id(2)),
            "markers only for followed topics"
        );

        let many: Vec<Entry> = (0..(MAX_TOMBSTONES as u32 + 20))
            .map(|n| entry(&id(n), false, NOW_MS - 1000 + n as u64))
            .collect();
        let mut s = subs_of(&many, &[]);
        s.prune(NOW_MS);
        assert_eq!(s.entries.len(), MAX_TOMBSTONES);
        assert!(!s.entries.contains_key(&id(0)), "oldest go first");
        assert!(s.entries.contains_key(&id(MAX_TOMBSTONES as u32 + 19)));
    }

    // -- counting --

    #[test]
    fn counting_skips_edits_own_posts_read_posts_and_other_topics() {
        let me = "aa".repeat(32);
        let other = "bb".repeat(32);
        let mut s = Subs::default();
        s.subscribe(&id(1), &chan(1), "", NOW_MS, NOW).unwrap();
        let r = id(1);
        assert_eq!(
            unseen_root(&msg(Some(&r), &other, NOW + 1, false, 1), &s, Some(&me)),
            Some(r.as_str())
        );
        assert_eq!(
            unseen_root(&msg(Some(&r), &other, NOW + 1, true, 2), &s, Some(&me)),
            None
        );
        assert_eq!(
            unseen_root(
                &msg(Some(&r), &me.to_uppercase(), NOW + 1, false, 3),
                &s,
                Some(&me)
            ),
            None
        );
        assert_eq!(
            unseen_root(&msg(Some(&r), &other, NOW, false, 4), &s, Some(&me)),
            None
        );
        assert_eq!(
            unseen_root(&msg(Some(&id(2)), &other, NOW + 1, false, 5), &s, Some(&me)),
            None
        );
        assert_eq!(
            unseen_root(&msg(None, &other, NOW + 1, false, 6), &s, Some(&me)),
            None
        );
    }

    #[test]
    fn unseen_ids_are_deduplicated_and_reset_by_the_marker() {
        let mut s = Subs::default();
        s.subscribe(&id(1), &chan(1), "", NOW_MS, NOW).unwrap();
        let r = id(1);
        let mut u = Unseen::default();
        assert!(u.note(&r, &id(100), NOW + 1));
        assert!(
            !u.note(&r, &id(100).to_uppercase(), NOW + 1),
            "same id once"
        );
        u.note(&r, &id(101), NOW + 5);
        assert_eq!(
            u.count(&r),
            UnreadCount {
                count: 2,
                capped: false
            }
        );
        s.mark_read(&r, NOW + 1);
        u.reconcile(&s);
        assert_eq!(u.count(&r).count, 1);
        s.unsubscribe(&r, NOW_MS + 1);
        u.reconcile(&s);
        assert_eq!(u.count(&r).count, 0);
        assert_eq!(u.total().count, 0);
    }

    #[test]
    fn counts_cap_for_display_and_saturate_on_a_full_backlog() {
        let mut s = Subs::default();
        s.subscribe(&id(1), &chan(1), "", NOW_MS, NOW).unwrap();
        let r = id(1);
        let mut u = Unseen::default();
        for n in 0..=UNREAD_DISPLAY_CAP as u32 {
            u.note(&r, &id(500 + n), NOW + 1);
        }
        assert_eq!(u.count(&r).count, UNREAD_DISPLAY_CAP + 1);
        assert!(u.count(&r).capped);
        let mut u = Unseen::default();
        u.note(&r, &id(1), NOW + 1);
        u.saturate(&r);
        assert_eq!(
            u.count(&r),
            UnreadCount {
                count: 1,
                capped: true
            }
        );
        assert!(u.total().capped);
        s.mark_read(&r, NOW + 2);
        u.reconcile(&s);
        assert_eq!(u.count(&r), UnreadCount::default());
    }

    // -- retries --

    #[test]
    fn a_refused_batch_is_requeued_once_and_never_loops() {
        let mut retried = HashSet::new();
        let batch = vec![(id(1), 5u64), (id(2), 6)];
        let again = requeue_once(batch.clone(), |(r, _)| r.as_str(), &mut retried);
        assert_eq!(again, batch);
        let again = requeue_once(batch, |(r, _)| r.as_str(), &mut retried);
        assert!(again.is_empty());
        let mixed = vec![(id(2), 6u64), (id(3), 7)];
        let again = requeue_once(mixed, |(r, _)| r.as_str(), &mut retried);
        assert_eq!(again, vec![(id(3), 7)]);
    }

    // -- filters --

    #[test]
    fn backlog_requests_hold_at_most_nine_filters_with_since_after_the_marker() {
        let items: Vec<(String, u64)> = (0..40).map(|n| (id(n), 1000 + n as u64)).collect();
        let reqs = backlog_batches(&items);
        assert_eq!(reqs.len(), 5);
        assert!(reqs
            .iter()
            .all(|r| r.len() <= 9 && r.len() < RELAY_MAX_FILTERS));
        assert_eq!(reqs.iter().map(Vec::len).sum::<usize>(), 40);
        let f = serde_json::to_value(&reqs[0][0]).unwrap();
        assert_eq!(
            f,
            serde_json::json!({"kinds": [42], "#e": [id(0)], "since": 1001, "limit": 100})
        );
    }

    #[test]
    fn root_fetches_ask_by_id_and_by_sealed_inner_id() {
        let ids: Vec<String> = (0..3).map(id).collect();
        let f = root_fetch_filters(&ids);
        assert_eq!(f.len(), 2);
        let a = serde_json::to_value(&f[0]).unwrap();
        let b = serde_json::to_value(&f[1]).unwrap();
        assert_eq!(a["ids"].as_array().unwrap().len(), 3);
        assert_eq!(b["#sealed"].as_array().unwrap().len(), 3);
        assert_eq!(b["kinds"], serde_json::json!([42]));
        const {
            assert!(
                ROOT_FETCH_BATCH * 2 < 100,
                "inside the bound-parameter limit"
            )
        };
    }

    // -- titles and order --

    fn root_event(id_: &str, content: &str) -> NostrEvent {
        NostrEvent {
            id: id_.to_string(),
            pubkey: "aa".repeat(32),
            created_at: 1,
            kind: 42,
            tags: vec![vec!["e".into(), chan(1), "".into(), "root".into()]],
            content: content.to_string(),
            sig: String::new(),
        }
    }

    #[test]
    fn titles_come_from_the_topics_own_lists_and_placeholders_are_unknown() {
        let mut lists: HashMap<String, Vec<NostrEvent>> = HashMap::new();
        lists.insert(
            roots_key(&chan(1)),
            vec![root_event(&id(1), "Hello\nworld")],
        );
        lists.insert(
            chan(1),
            vec![root_event(
                &id(2),
                crate::zone_crypto::PLACEHOLDER_MISSING_KEY,
            )],
        );
        // Held, but in another channel's list: not looked at.
        lists.insert(chan(9), vec![root_event(&id(3), "Elsewhere")]);
        let wanted = vec![(id(1), chan(1)), (id(2), chan(1)), (id(3), chan(1))];
        let t = resolve_titles(&lists, &wanted);
        assert_eq!(t[&id(1)].as_deref(), Some("Hello"));
        assert_eq!(t[&id(2)], None);
        assert_eq!(t[&id(3)], None);
    }

    fn topic(root: &str, title: Option<&str>) -> SubscribedTopic {
        SubscribedTopic {
            root: root.to_string(),
            channel: chan(1),
            zone: String::new(),
            zone_slug: None,
            title: title.map(str::to_string),
            unread: 0,
            capped: false,
        }
    }

    #[test]
    fn panel_order_is_alphabetical_case_insensitive_unknown_last_and_stable() {
        let mut v = vec![
            topic(&id(5), None),
            topic(&id(4), Some("banana")),
            topic(&id(3), Some("Apple")),
            topic(&id(2), None),
            topic(&id(1), Some("apple")),
        ];
        sort_topics(&mut v);
        let order: Vec<&str> = v.iter().map(|t| t.root.as_str()).collect();
        assert_eq!(
            order,
            vec![
                id(1).as_str(),
                id(3).as_str(),
                id(4).as_str(),
                id(2).as_str(),
                id(5).as_str()
            ]
        );
        let again = {
            let mut w = v.clone();
            w.reverse();
            sort_topics(&mut w);
            w
        };
        assert_eq!(again, v);
    }

    #[test]
    fn storage_keys_are_per_account() {
        assert_eq!(storage_key("ab"), "nostrbbs:thread_subs:v1:ab".to_string());
        assert_ne!(storage_key(&"a".repeat(64)), storage_key(&"b".repeat(64)));
    }
}
