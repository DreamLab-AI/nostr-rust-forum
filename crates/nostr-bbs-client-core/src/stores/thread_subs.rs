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
//!   (seconds) the member has seen there. A marker never moves backwards and
//!   never runs ahead of this device's clock: a post's `created_at` is chosen
//!   by its author (the relay accepts up to seven days ahead), so every marker
//!   is clamped to local now wherever it is set or merged. On subscribe it
//!   starts at the newest reply already held for the topic (or the relay's
//!   newest, else now), so the first count never walks the whole topic and a
//!   fast local clock cannot hide the next posts. It is advanced by
//!   [`ThreadSubsStore::mark_read`] when a view shows the thread.
//! - **Unseen posts** are held in memory only, per topic: ids of posts newer
//!   than the marker, by someone else, that are not edits and not still-locked
//!   sealed envelopes (whose author is unknown until they open). They come
//!   from a backlog pass after NIP-42 AUTH and, while the app is open, from
//!   the channel store's inserted-message hook
//!   ([`ChannelStore::on_inserted`]). After a reconnect the pass asks only
//!   from each topic's in-session high-water mark. A post deleted later
//!   (kind 5) stops counting. No polling, and no extra open subscription.
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
//! the BBS on the same origin), with the last relay copy seen. It is merged
//! on every write with what another tab stored, reloaded when another tab
//! writes it, and removed at sign-out ([`clear_persisted_for_logout`]) after
//! a bounded last publish. The cross-device copy is a NIP-44 self-encrypted
//! kind-30078 event: see
//! [`thread_subs_sync`](crate::stores::thread_subs_sync), which also says who
//! can see what.
//!
//! ## Use
//!
//! Provide once at the app root with [`provide_thread_subs`], after the relay
//! connection, the channel store and the zone-key store are provided, then
//! read it anywhere with [`use_thread_subs`].

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;

use gloo::storage::{LocalStorage, Storage};
use leptos::prelude::*;
use nostr_bbs_core::NostrEvent;
use serde::{Deserialize, Serialize};

use crate::auth::{use_auth, AuthStore};
use crate::relay::{Filter, RelayConnection};
use crate::stores::channels::{
    followed_roots_key, roots_key, topic_key, use_channel_store, ChannelStore, InsertedMessage,
    PAGE_TIMEOUT_MS, RELAY_MAX_FILTERS,
};
use crate::stores::thread_subs_sync::{
    self as sync, LocalOnlyReason, Plan, PlanInput, RemoteSeen, SyncStatus, Trigger,
};
use crate::stores::zones::Zone;
use crate::zone_crypto::store::ZoneKeyStore;

// -- Constants ----------------------------------------------------------------

/// Prefix of the per-account localStorage key; the signed-in pubkey (hex) is
/// appended.
pub const STORAGE_KEY_PREFIX: &str = "nostrbbs:thread_subs:v1:";

/// Prefix of the per-account publish lock (one tab publishes at a time).
const LOCK_KEY_PREFIX: &str = "nostrbbs:thread_subs_lock:v1:";

/// How long a signer call made for the relay copy (encrypt, decrypt, sign)
/// may take before it is abandoned, milliseconds: a NIP-07 prompt left open
/// must not stall the copy for the session.
const SIGNER_TIMEOUT_MS: u32 = 120_000;

/// How long a tab's publish lock lasts, milliseconds: longer than a signer
/// call may take, so a lock held across an open prompt does not expire under
/// it (it is taken again just before publishing, too).
const LOCK_MS: u64 = SIGNER_TIMEOUT_MS as u64 + 30_000;

/// The most topics one member can follow at once. Keeps the synced copy under
/// the relay's 64 KiB content cap; [`ThreadSubsStore::subscribe`] refuses with
/// [`SubscribeError::LimitReached`] beyond it.
pub const MAX_ACTIVE_SUBSCRIPTIONS: usize = 150;

/// Unread counts above this are shown as "99+" by the views; see
/// [`UnreadCount::capped`].
pub const UNREAD_DISPLAY_CAP: usize = 99;

/// How long a tombstone (a subscription switched off) is kept, in
/// milliseconds: a year, so a device unused for months still sees it before
/// it is dropped. A tombstone is about 100 bytes and at most
/// 300 are kept.
pub const TOMBSTONE_TTL_MS: u64 = 365 * 24 * 60 * 60 * 1000;

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

/// First pause before re-sending a batch the relay refused, milliseconds;
/// doubled per attempt up to [`RETRY_MAX_MS`].
const RETRY_BASE_MS: u64 = 3_000;
/// Longest pause between re-sends, milliseconds.
const RETRY_MAX_MS: u64 = 60_000;
/// Re-sends per topic per connection before giving up until the next one.
const MAX_RETRIES: u32 = 6;

/// Still-locked sealed posts held to count once they open.
const MAX_PENDING_LOCKED: usize = 500;

/// Most bytes of not-held sealed envelopes kept to decrypt again later.
const MAX_PENDING_BYTES: usize = 256 * 1024;

/// Allowance subtracted from a topic's high-water mark (seconds): a post
/// dated up to five minutes before the newest one seen (a slow clock, a
/// late relay write) is still asked for after a reconnect.
const BACKDATE_ALLOWANCE_SECS: u64 = 300;

/// Delay before a scheduled publish once changes settle, milliseconds.
const PUBLISH_SETTLE_MS: u64 = 2_000;

/// How long sign-out waits for a last publish, milliseconds.
pub(crate) const SIGN_OUT_FLUSH_MS: u32 = 3_000;

/// Delay between re-checks of counted posts against deletions, milliseconds.
const DELETION_RECHECK_MS: i32 = 2_000;

/// The localStorage key of `owner`'s subscriptions.
pub fn storage_key(owner: &str) -> String {
    format!("{STORAGE_KEY_PREFIX}{owner}")
}

fn lock_key(owner: &str) -> String {
    format!("{LOCK_KEY_PREFIX}{owner}")
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

impl SubscribedTopic {
    /// The forum's canonical path to the topic (inside the router base), or
    /// `None` while the zone is unknown. The BBS links with its own
    /// `Thread { zone, channel_id: channel, root_id: root }` route instead.
    pub fn forum_path(&self) -> Option<String> {
        self.zone_slug
            .as_deref()
            .map(|z| crate::utils::section_url::topic_path(z, &self.channel, &self.root))
    }
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

/// The synced shape (and the subscriptions part of the stored one):
/// `{"subs":[{r,c,z,on,at,rd}]}`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SubsDoc {
    #[serde(default)]
    pub subs: Vec<DocEntry>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// The stored shape: the subscriptions plus, never published, the last relay
/// copy seen and when this browser last published.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LocalDoc {
    #[serde(flatten)]
    pub doc: SubsDoc,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<RemoteSeen>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub published_ms: u64,
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
    /// is not 64 hex, an over-long zone) and resolving duplicate roots by the
    /// merge order. Markers are clamped to `now_secs`.
    pub fn from_doc(doc: SubsDoc, now_secs: u64) -> Self {
        let mut out = Subs::default();
        for DocEntry { entry: mut e, rd } in doc.subs {
            e.r = e.r.to_ascii_lowercase();
            e.c = e.c.to_ascii_lowercase();
            // A change cannot be dated after this device's clock.
            e.at = e.at.min(now_secs.saturating_mul(1000).saturating_add(999));
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
                *m = (*m).max(ts.min(now_secs));
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

    /// The same list without read markers (what the membership digest
    /// covers).
    pub fn membership(&self) -> Subs {
        Subs {
            entries: self.entries.clone(),
            read: BTreeMap::new(),
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
    /// `at`, then off before on); read markers take the larger value, clamped
    /// to `now_secs`. For a fixed `now_secs` a join (commutative, associative,
    /// idempotent), so copies merged in any order converge. Markers are kept
    /// for every root here; dropping the ones of topics no longer followed is
    /// [`Self::prune`]'s job.
    pub fn join(&self, other: &Subs, now_secs: u64) -> Subs {
        let mut out = self.clone();
        for e in other.entries.values() {
            out.put(e.clone());
        }
        for (root, ts) in &other.read {
            let m = out.read.entry(root.clone()).or_insert(0);
            *m = (*m).max(*ts);
        }
        for m in out.read.values_mut() {
            *m = (*m).min(now_secs);
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

    /// Follow `root` in `channel` (zone `zone`) with read marker `start_secs`
    /// (see [`start_marker`]; never moved back). Returns whether anything
    /// changed.
    pub fn subscribe(
        &mut self,
        root: &str,
        channel: &str,
        zone: &str,
        start_secs: u64,
        now_ms: u64,
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
            *m = (*m).max(start_secs);
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

    /// Advance followed topic `root`'s marker to `upto` (seconds), clamped to
    /// `now_secs`. Never moves it back; a topic not followed is left alone.
    /// Returns whether it moved.
    pub fn mark_read(&mut self, root: &str, upto: u64, now_secs: u64) -> bool {
        let root = root.to_ascii_lowercase();
        let upto = upto.min(now_secs);
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
    prev.map_or(now_ms, |p| now_ms.max(p.at.saturating_add(1)))
}

/// Apply `f` to `sig`, notifying subscribers **only** if `f` reports a
/// change. `RwSignal::update` notifies whatever happened; an Effect that
/// reads a signal and calls a method which `update`s it unconditionally
/// re-runs itself for ever (the thread page's mark-read effect did, freezing
/// the page). Every write to the store's state goes through here.
pub(crate) fn write_if<T: Send + Sync + 'static>(
    sig: RwSignal<T>,
    f: impl FnOnce(&mut T) -> bool,
) -> bool {
    let mut changed = false;
    sig.maybe_update(|v| {
        changed = f(v);
        changed
    });
    changed
}

/// The read marker a new subscription starts at: the newest reply already
/// held for the topic or the relay's newest reply (`topic_latest`),
/// whichever is later, clamped to `now_secs`; `now_secs` when neither is
/// known. Starting from what the relay already has, rather than the local
/// clock, means a fast local clock cannot hide the next posts.
pub(crate) fn start_marker(
    held_newest: Option<u64>,
    relay_latest: Option<u64>,
    now_secs: u64,
) -> u64 {
    held_newest
        .into_iter()
        .chain(relay_latest)
        .max()
        .map_or(now_secs, |t| t.min(now_secs))
}

/// One counted post.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnseenPost {
    pub created_at: u64,
    pub pubkey: String,
}

/// Unseen posts per followed topic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Unseen {
    by_root: HashMap<String, HashMap<String, UnseenPost>>,
    /// Topics whose backlog answer was full ([`BACKLOG_LIMIT`]): there may
    /// be more unseen posts than counted.
    saturated: HashSet<String>,
    /// Posts the member marked read this session. A post dated in the future
    /// stays above the (clamped) marker, so it is dismissed by id instead and
    /// never counted again this session.
    dismissed: HashSet<String>,
}

impl Unseen {
    /// Record unseen post `id` in `root`. Returns whether it was new.
    pub fn note(&mut self, root: &str, id: &str, created_at: u64, pubkey: &str) -> bool {
        let id = id.to_ascii_lowercase();
        if self.dismissed.contains(&id) {
            return false;
        }
        self.by_root
            .entry(root.to_string())
            .or_default()
            .insert(
                id,
                UnseenPost {
                    created_at,
                    pubkey: pubkey.to_string(),
                },
            )
            .is_none()
    }

    /// Mark `root`'s count as possibly incomplete.
    pub fn saturate(&mut self, root: &str) {
        self.saturated.insert(root.to_string());
    }

    /// The member saw `root` up to `upto` (unclamped): those posts go, and
    /// stay gone this session. Returns their ids.
    pub fn dismiss_upto(&mut self, root: &str, upto: u64) -> Vec<String> {
        let mut gone: Vec<String> = Vec::new();
        if let Some(ids) = self.by_root.get_mut(root) {
            gone = ids
                .iter()
                .filter(|(_, p)| p.created_at <= upto)
                .map(|(id, _)| id.clone())
                .collect();
            for id in &gone {
                ids.remove(id);
                self.dismissed.insert(id.clone());
            }
        }
        self.tidy();
        gone
    }

    /// Whether [`Self::dismiss_upto`] would remove anything.
    pub fn would_dismiss(&self, root: &str, upto: u64) -> bool {
        self.by_root
            .get(root)
            .is_some_and(|ids| ids.values().any(|p| p.created_at <= upto))
    }

    /// Every post of `root` goes, and stays gone this session. Returns their
    /// ids.
    pub fn dismiss_root(&mut self, root: &str) -> Vec<String> {
        let mut gone = Vec::new();
        if let Some(ids) = self.by_root.remove(root) {
            gone = ids.into_keys().collect();
            self.dismissed.extend(gone.iter().cloned());
        }
        self.tidy();
        gone
    }

    /// Forget posts `ids` (deleted).
    pub fn remove_ids(&mut self, ids: &HashSet<String>) {
        for posts in self.by_root.values_mut() {
            posts.retain(|id, _| !ids.contains(id));
        }
        self.tidy();
    }

    /// Bring the sets in line with `subs`: forget topics not followed, and
    /// posts at or before each topic's marker.
    pub fn reconcile(&mut self, subs: &Subs) {
        self.by_root.retain(|root, ids| match subs.read_at(root) {
            Some(read) => {
                ids.retain(|_, p| p.created_at > read);
                true
            }
            None => false,
        });
        self.saturated.retain(|r| subs.is_active(r));
        self.tidy();
    }

    /// Drop empty topics; a topic with nothing counted is not saturated.
    fn tidy(&mut self) {
        self.by_root.retain(|_, ids| !ids.is_empty());
        let by_root = &self.by_root;
        self.saturated.retain(|r| by_root.contains_key(r));
    }

    /// Every counted post as `(id, post)`.
    pub fn posts(&self) -> Vec<(String, UnseenPost)> {
        self.by_root
            .values()
            .flat_map(|ids| ids.iter().map(|(id, p)| (id.clone(), p.clone())))
            .collect()
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
/// `me`, newer than the topic's marker, and not a still-locked sealed
/// envelope (its author is the migrator until it opens).
pub(crate) fn unseen_root<'a>(
    msg: &'a InsertedMessage,
    subs: &Subs,
    me: Option<&str>,
) -> Option<&'a str> {
    if msg.edit || msg.sealed_inner.is_some() {
        return None;
    }
    if me.is_some_and(|m| m.eq_ignore_ascii_case(&msg.pubkey)) {
        return None;
    }
    let root = msg.reply_root.as_deref()?;
    let read = subs.read_at(root)?;
    (msg.created_at > read).then_some(root)
}

/// The `since` of a topic's backlog filter: just after its read marker, or,
/// once a backlog answer this session has delivered posts up to `high`, from
/// `high` less [`BACKDATE_ALLOWANCE_SECS`] (a post dated a little earlier
/// may arrive later; duplicates are dropped by id). So a reconnect asks only for what is
/// newer than what was already seen, not the whole span again.
pub(crate) fn backlog_since(read_at: u64, high: Option<u64>) -> u64 {
    read_at
        .saturating_add(1)
        .max(high.map_or(0, |h| h.saturating_sub(BACKDATE_ALLOWANCE_SECS)))
}

/// The backlog filter for topic `root` from `since`:
/// `{"kinds":[42], "#e":[root], "since": since, "limit": 100}`.
pub(crate) fn backlog_filter(root: &str, since: u64) -> Filter {
    Filter {
        kinds: Some(vec![42]),
        e_tags: Some(vec![root.to_string()]),
        since: Some(since),
        limit: Some(BACKLOG_LIMIT),
        ..Default::default()
    }
}

/// `(root, since)` pairs split into REQs of at most
/// [`BACKLOG_FILTERS_PER_REQ`] filters each.
pub(crate) fn backlog_batches(items: &[(String, u64)]) -> Vec<Vec<Filter>> {
    items
        .chunks(BACKLOG_FILTERS_PER_REQ)
        .map(|chunk| chunk.iter().map(|(r, t)| backlog_filter(r, *t)).collect())
        .collect()
}

/// Pause before re-send `attempt` (0-based) of a refused batch: doubling
/// from [`RETRY_BASE_MS`] to at most [`RETRY_MAX_MS`]; `None` after
/// [`MAX_RETRIES`] (the next connection tries again).
pub(crate) fn retry_delay_ms(attempt: u32) -> Option<u64> {
    (attempt < MAX_RETRIES).then(|| (RETRY_BASE_MS << attempt.min(16)).min(RETRY_MAX_MS))
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
        scan(&followed_roots_key(channel), roots, &mut out);
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

/// The newest reply to `root` held in `lists` `keys`, at or before `now_secs`.
pub(crate) fn newest_held_reply(
    lists: &HashMap<String, Vec<NostrEvent>>,
    keys: &[String],
    root: &str,
    now_secs: u64,
) -> Option<u64> {
    keys.iter()
        .filter_map(|k| lists.get(k))
        .flat_map(|v| v.iter())
        .filter(|e| {
            e.created_at <= now_secs
                && nostr_bbs_core::sealed::reply_root_of(e)
                    .is_some_and(|r| r.eq_ignore_ascii_case(root))
        })
        .map(|e| e.created_at)
        .max()
}

/// Ids of replies to `root` held in list `key`, at or before `upto`.
pub(crate) fn replies_upto(
    lists: &HashMap<String, Vec<NostrEvent>>,
    key: &str,
    root: &str,
    upto: u64,
) -> Vec<String> {
    lists
        .get(key)
        .into_iter()
        .flat_map(|v| v.iter())
        .filter(|e| {
            e.created_at <= upto
                && nostr_bbs_core::sealed::reply_root_of(e)
                    .is_some_and(|r| r.eq_ignore_ascii_case(root))
        })
        .map(|e| e.id.to_ascii_lowercase())
        .collect()
}

/// Mark the bell notices of posts `ids` read (`post:<id>`).
fn clear_post_notices(ids: &[String]) {
    if ids.is_empty() {
        return;
    }
    if let Some(n) = crate::stores::notifications::global_notification_store() {
        let keys: HashSet<String> = ids
            .iter()
            .map(|id| format!("post:{}", id.to_ascii_lowercase()))
            .collect();
        n.mark_read_ids(&keys);
    }
}

/// The held event `id` (from `created_at`) and the list holding it.
fn find_held(channels: ChannelStore, id: &str, created_at: u64) -> Option<(String, NostrEvent)> {
    channels.channel_messages.with_untracked(|m| {
        m.iter().find_map(|(list, v)| {
            let at = v.partition_point(|e| e.created_at < created_at);
            v[at..]
                .iter()
                .take_while(|e| e.created_at == created_at)
                .find(|e| e.id.eq_ignore_ascii_case(id))
                .map(|e| (list.clone(), e.clone()))
        })
    })
}

/// Whether any list of `channels` holds event `id` (from `created_at`).
/// Untracked; the same check the channel store makes before dropping the
/// decrypt state of an event it fetched for another purpose.
fn held_anywhere(channels: ChannelStore, id: &str, created_at: u64) -> bool {
    find_held(channels, id, created_at).is_some()
}

/// Whether root `root` of `channel` is held in one of the lists
/// [`resolve_titles`] looks in (readable or not).
pub(crate) fn root_held(
    lists: &HashMap<String, Vec<NostrEvent>>,
    root: &str,
    channel: &str,
) -> bool {
    [
        roots_key(channel),
        followed_roots_key(channel),
        channel.to_string(),
        topic_key(root),
    ]
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

/// Whether the subscriptions of `owner` may be written: only while the
/// browser's stored session (`session`) is that account's.
pub(crate) fn persist_allowed(session: Option<&str>, owner: &str) -> bool {
    session.is_some_and(|s| s.eq_ignore_ascii_case(owner))
}

/// `owner`'s stored copy; empty when absent or unreadable.
fn load_local(owner: &str, now_secs: u64) -> (Subs, Option<RemoteSeen>, u64) {
    match LocalStorage::get::<LocalDoc>(storage_key(owner)) {
        Ok(d) => (Subs::from_doc(d.doc, now_secs), d.remote, d.published_ms),
        Err(_) => (Subs::default(), None, 0),
    }
}

/// Remove `pubkey`'s stored subscriptions (and its publish lock) at sign-out,
/// so the next account on this browser does not see them. The synced relay
/// copy, if any, is kept: it is encrypted to the member and restores the list
/// at their next sign-in. Sign-out first gives pending changes a bounded
/// chance to reach it.
pub fn clear_persisted_for_logout(pubkey: Option<&str>) {
    if let Some(pk) = pubkey {
        LocalStorage::delete(storage_key(pk));
        LocalStorage::delete(lock_key(pk));
    }
}

fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

// -- Reactive store -----------------------------------------------------------

/// The account a set of subscriptions belongs to, held with them (and the
/// last relay copy seen) in one signal so they can never disagree.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Owned {
    owner: Option<String>,
    subs: Subs,
    remote: Option<RemoteSeen>,
    published_ms: u64,
}

/// The backlog pass: topics already asked this connection, those queued,
/// the REQ in flight (one at a time), refusal retries, and each topic's
/// high-water mark (kept across reconnects, dropped on an account switch).
#[derive(Default)]
struct PumpState {
    done: HashSet<String>,
    queue: VecDeque<String>,
    inflight: Vec<String>,
    retries: HashMap<String, u32>,
    high: HashMap<String, u64>,
    sub: Option<String>,
    /// Bumped whenever the pass is abandoned (disconnect, account switch),
    /// so answers to an abandoned REQ are ignored.
    gen: u64,
}

/// Root fetches for titles: roots already asked this session, those queued,
/// the REQ in flight (one at a time) and refusal retries.
#[derive(Default)]
struct FetchState {
    asked: HashSet<String>,
    queue: VecDeque<String>,
    inflight: Vec<String>,
    retries: HashMap<String, u32>,
    sub: Option<String>,
    gen: u64,
}

/// A reply in a followed topic that arrived as a still-locked sealed
/// envelope: counted once it opens. `raw` is the envelope when no list holds
/// it (a backlog delivery), to decrypt again when a zone key arrives.
#[derive(Clone)]
struct PendingLocked {
    root: String,
    inner_id: String,
    created_at: u64,
    raw: Option<NostrEvent>,
}

/// State of the cross-device copy for the current account, this session.
#[derive(Clone, Debug, Default)]
struct SyncCtl {
    /// This account's first fetch-and-merge succeeded: publishing is allowed.
    fetched: bool,
    /// Local-only for the rest of the session, and why (unreadable relay
    /// copy, no NIP-44, a refused signature — the last is lifted by an
    /// explicit subscribe or unsubscribe).
    disabled: Option<LocalOnlyReason>,
    busy: bool,
    last_fetch_ms: Option<u64>,
    timer_at: Option<u64>,
    /// Failed attempts in a row, and the time before which none is retried.
    failures: u32,
    not_before_ms: u64,
    /// Another tab holds the publish lock until then.
    lock_wait_until: u64,
}

/// What the store needs from elsewhere, captured once at the app root.
#[derive(Clone)]
struct Deps {
    auth: AuthStore,
    relay: RelayConnection,
    channels: ChannelStore,
    zone_keys: Option<ZoneKeyStore>,
    /// The zone configuration, read once (it does not change while the page
    /// is open).
    zones: Vec<Zone>,
}

/// How a REQ of the backlog pass or the title fetch ended.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Answered,
    /// CLOSED, or no answer in time: re-sent with backoff.
    Refused,
}

/// Reactive thread-subscription store, provided via context
/// ([`provide_thread_subs`], [`use_thread_subs`]). `Copy`; every reading
/// method is reactive.
#[derive(Clone, Copy)]
pub struct ThreadSubsStore {
    owned: RwSignal<Owned>,
    unseen: RwSignal<Unseen>,
    /// Bumped when a followed topic's root is inserted, so titles are
    /// re-resolved then (and on zone-key changes), not on every insert.
    titles_rev: RwSignal<u64>,
    /// Sealed envelope id → original id, from every sealed post the channel
    /// store inserts (lower-case).
    aliases: StoredValue<HashMap<String, String>>,
    /// Bumped when an alias is learnt, so `is_subscribed` re-evaluates.
    aliases_rev: RwSignal<u64>,
    pubkey: Memo<Option<String>>,
    generation: StoredValue<u64>,
    topics: Memo<Vec<SubscribedTopic>>,
    total: Memo<UnreadCount>,
    sync_status: RwSignal<SyncStatus>,
    pump: StoredValue<PumpState, leptos::prelude::LocalStorage>,
    fetch: StoredValue<FetchState, leptos::prelude::LocalStorage>,
    pending: StoredValue<HashMap<String, PendingLocked>, leptos::prelude::LocalStorage>,
    recheck_armed: StoredValue<bool>,
    sync: StoredValue<SyncCtl>,
    tab_id: StoredValue<String>,
    deps: StoredValue<Deps, leptos::prelude::LocalStorage>,
}

impl ThreadSubsStore {
    fn new(deps: Deps) -> Self {
        let owned = RwSignal::new(Owned::default());
        let unseen = RwSignal::new(Unseen::default());
        let titles_rev = RwSignal::new(0u64);
        let pubkey = deps.auth.pubkey();
        let channels = deps.channels;
        let zone_rev = deps.zone_keys.map(|z| z.revision);
        let zones = std::sync::Arc::new(deps.zones.clone());

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
        // Memos over the followed entries only: a read-marker change leaves
        // them equal, so neither titles nor the panel list recompute.
        let active = Memo::new(move |_| current());
        let pairs = Memo::new(move |_| {
            active.with(|v| {
                v.iter()
                    .map(|e| (e.r.clone(), e.c.clone()))
                    .collect::<Vec<_>>()
            })
        });
        let titles = Memo::new(move |_| {
            let wanted = pairs.get();
            titles_rev.track();
            if let Some(r) = zone_rev {
                r.track();
            }
            channels
                .channel_messages
                .with_untracked(|m| resolve_titles(m, &wanted))
        });
        let topics = Memo::new(move |_| {
            let entries = active.get();
            let titles = titles.get();
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
        let tab_id = format!("{:016x}", (js_sys::Math::random() * u64::MAX as f64) as u64);

        Self {
            owned,
            unseen,
            titles_rev,
            aliases: StoredValue::new(HashMap::new()),
            aliases_rev: RwSignal::new(0),
            pubkey,
            generation: StoredValue::new(0),
            topics,
            total,
            sync_status: RwSignal::new(SyncStatus::Idle),
            pump: StoredValue::new_local(PumpState::default()),
            fetch: StoredValue::new_local(FetchState::default()),
            pending: StoredValue::new_local(HashMap::new()),
            recheck_armed: StoredValue::new(false),
            sync: StoredValue::new(SyncCtl::default()),
            tab_id: StoredValue::new(tab_id),
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

    /// Whether the member follows topic `root`. Reactive. A sealed root's
    /// envelope id and its original's id answer alike.
    pub fn is_subscribed(&self, root: &str) -> bool {
        self.aliases_rev.track();
        let canonical = self.canonical_root(root);
        self.with_current(|s| s.is_active(&canonical) || s.is_active(root))
    }

    /// The id a topic is followed under: a still-locked sealed root's
    /// envelope id maps to the original's id (which its replies name);
    /// any other id is itself (lower-case).
    fn canonical_root(&self, root: &str) -> String {
        let root = root.to_ascii_lowercase();
        self.aliases
            .try_with_value(|a| a.get(&root).cloned())
            .flatten()
            .unwrap_or(root)
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
        self.aliases_rev.track();
        let root = self.canonical_root(root);
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

    /// Follow topic `root` (a topic root event id) in channel `channel` (its
    /// kind-40 id). The topic's read marker starts at the newest reply already
    /// known for it (see the module notes), so only later posts count as
    /// unread. Idempotent.
    ///
    /// **Ship [`Self::mark_read`] with this.** A view that offers a subscribe
    /// control must, in the same release, call `mark_read` when it shows a
    /// subscribed thread; otherwise counts and subscribed-topic notices never
    /// reset when the member reads the thread.
    pub fn subscribe(&self, root: &str, channel: &str) -> Result<(), SubscribeError> {
        self.ensure_owner();
        if self.owned.with_untracked(|o| o.owner.is_none()) {
            return Err(SubscribeError::NotSignedIn);
        }
        let now = now_secs();
        let root_l = root.to_ascii_lowercase();
        let (zone, start) = self.deps.with_value(|d| {
            let zone = crate::zone_crypto::store::channel_zone(d.channels, channel)
                .map(|(z, _, _)| z)
                .unwrap_or_default();
            let keys = [topic_key(&root_l), channel.to_ascii_lowercase()];
            let held = d
                .channels
                .channel_messages
                .with_untracked(|m| newest_held_reply(m, &keys, &root_l, now));
            let latest = d.channels.topic_latest(&root_l).map(|(t, _)| t);
            (zone, start_marker(held, latest, now))
        });
        let mut result = Ok(false);
        let at = now_ms();
        // A still-locked sealed root is listed under its envelope's id, but
        // its replies name the original's: subscribe under the original, and
        // fold an earlier envelope-id entry into it.
        let canonical = self.canonical_root(root);
        let envelope = root.to_ascii_lowercase();
        write_if(self.owned, |o| {
            let mut changed = false;
            if envelope != canonical {
                changed |= o.subs.unsubscribe(&envelope, at);
            }
            match o.subs.subscribe(&canonical, channel, &zone, start, at) {
                Ok(c) => {
                    result = Ok(c || changed);
                    c || changed
                }
                Err(e) => {
                    result = Err(e);
                    changed
                }
            }
        });
        if result? {
            self.lift_refusal();
            self.after_change();
        }
        Ok(())
    }

    /// An explicit subscribe or unsubscribe lifts a session's refused
    /// signature, so the next publish asks the signer again.
    fn lift_refusal(&self) {
        self.sync.update_value(|c| {
            if c.disabled == Some(LocalOnlyReason::SignerRefused) {
                c.disabled = None;
                c.failures = 0;
                c.not_before_ms = 0;
            }
        });
    }

    /// Stop following topic `root`. Its unread count goes with it.
    pub fn unsubscribe(&self, root: &str) {
        self.ensure_owner();
        let now = now_ms();
        let canonical = self.canonical_root(root);
        let given = root.to_ascii_lowercase();
        let changed = write_if(self.owned, |o| {
            if o.owner.is_none() {
                return false;
            }
            // Both ids: an entry stored under a sealed root's envelope id
            // goes too.
            let a = o.subs.unsubscribe(&canonical, now);
            let b = given != canonical && o.subs.unsubscribe(&given, now);
            a || b
        });
        if changed {
            self.lift_refusal();
            self.after_change();
        }
    }

    /// [`Self::unsubscribe`] when followed, else [`Self::subscribe`].
    /// Returns whether the topic is followed afterwards.
    pub fn toggle(&self, root: &str, channel: &str) -> Result<bool, SubscribeError> {
        self.ensure_owner();
        let canonical = self.canonical_root(root);
        let on = self
            .owned
            .with_untracked(|o| o.subs.is_active(&canonical) || o.subs.is_active(root));
        if on {
            self.unsubscribe(root);
            Ok(false)
        } else {
            self.subscribe(root, channel).map(|()| true)
        }
    }

    /// The member has seen followed topic `root` up to `upto` (unix seconds):
    /// pass the `created_at` of the newest post the view shows. Posts at or
    /// before it stop counting as unread. The stored marker never moves back
    /// and never past this device's clock (a post can be dated in the future);
    /// the posts shown are dismissed for the session either way. A topic not
    /// followed is ignored.
    pub fn mark_read(&self, root: &str, upto: u64) {
        self.ensure_owner();
        let root = self.canonical_root(root);
        let now = now_secs();
        if !self.owned.with_untracked(|o| o.subs.is_active(&root)) {
            return;
        }
        // Notifies only when the marker actually moves: this runs from the
        // thread page's effect, which reads the same signal.
        let changed = write_if(self.owned, |o| o.subs.mark_read(&root, upto, now));
        let mut seen: Vec<String> = Vec::new();
        if self.unseen.with_untracked(|u| u.would_dismiss(&root, upto)) {
            self.unseen.update(|u| seen = u.dismiss_upto(&root, upto));
        }
        // The bell notices for the same posts clear with the count.
        let held = self.deps.with_value(|d| {
            d.channels
                .channel_messages
                .with_untracked(|m| replies_upto(m, &topic_key(&root), &root, upto))
        });
        seen.extend(held);
        clear_post_notices(&seen);
        if changed {
            self.after_change();
        }
    }

    /// While a view shows a thread, keep its read marker at the newest post
    /// shown: call once when the thread view mounts. `root` and `newest`
    /// (the newest shown post's `created_at`) are read reactively; whenever
    /// either changes and the topic is followed, [`Self::mark_read`] runs, so
    /// the panel count and the matching bell notices clear (and the change
    /// reaches other tabs and devices through the usual save and sync).
    pub fn mark_read_while_viewing(
        &self,
        root: impl Fn() -> Option<String> + 'static,
        newest: impl Fn() -> Option<u64> + 'static,
    ) {
        self.mark_read_while_viewing_ids(move || root().into_iter().collect(), newest);
    }

    /// [`Self::mark_read_while_viewing`] for a thread known by more than one
    /// id (a sealed root: the envelope's id and the original's): every listed
    /// id that is followed is marked.
    pub fn mark_read_while_viewing_ids(
        &self,
        roots: impl Fn() -> Vec<String> + 'static,
        newest: impl Fn() -> Option<u64> + 'static,
    ) {
        let store = *self;
        Effect::new(move |_| {
            let roots = roots();
            let Some(newest) = newest() else {
                return;
            };
            for root in roots {
                if store.is_subscribed(&root) {
                    store.mark_read(&root, newest);
                }
            }
        });
    }

    /// Whether a member is signed in, so the subscribe controls and the panel
    /// may be shown. Reactive.
    pub fn available(&self) -> bool {
        self.pubkey.get().is_some()
    }

    /// Mark every followed topic read: each marker moves to now and every
    /// counted post is dismissed (including any dated in the future).
    pub fn mark_all_read(&self) {
        self.ensure_owner();
        let now = now_secs();
        let roots: Vec<String> = self
            .owned
            .with_untracked(|o| o.subs.active().map(|e| e.r.clone()).collect());
        let changed = write_if(self.owned, |o| {
            let mut changed = false;
            for root in &roots {
                changed |= o.subs.mark_read(root, now, now);
            }
            changed
        });
        let mut seen: Vec<String> = Vec::new();
        write_if(self.unseen, |u| {
            for root in &roots {
                seen.extend(u.dismiss_root(root));
            }
            !seen.is_empty()
        });
        clear_post_notices(&seen);
        if changed {
            self.after_change();
        }
    }

    /// After any local change: drop what no longer counts, save (merging with
    /// what another tab saved), and schedule the relay copy.
    fn after_change(&self) {
        self.reconcile_unseen();
        self.persist();
        self.schedule_sync();
    }

    fn reconcile_unseen(&self) {
        let subs = self.owned.with_untracked(|o| o.subs.clone());
        let mut next = self.unseen.get_untracked();
        next.reconcile(&subs);
        if self.unseen.with_untracked(|u| *u != next) {
            self.unseen.set(next);
        }
    }

    /// Merge `memory` with what is stored for its owner.
    fn merged_with_stored(memory: &Owned, owner: &str) -> Owned {
        let now = now_ms();
        let (subs, remote, published_ms) = load_local(owner, now / 1000);
        let mut merged = memory.subs.join(&subs, now / 1000);
        merged.prune(now);
        Owned {
            owner: memory.owner.clone(),
            subs: merged,
            remote: RemoteSeen::newer(memory.remote.clone(), remote),
            published_ms: memory.published_ms.max(published_ms),
        }
    }

    /// Save to the owner's key, merged with what is stored (another tab may
    /// have written since), and adopt the merge. Nothing is written once the
    /// browser's stored session no longer names the owner: another tab has
    /// signed the account out, and its subscriptions must not reappear.
    fn persist(&self) {
        let memory = self.owned.get_untracked();
        let Some(owner) = memory.owner.clone() else {
            return;
        };
        if !persist_allowed(crate::auth::persisted_session_pubkey().as_deref(), &owner) {
            return;
        }
        let next = Self::merged_with_stored(&memory, &owner);
        let _ = LocalStorage::set(
            storage_key(&owner),
            LocalDoc {
                doc: next.subs.to_doc(),
                remote: next.remote.clone(),
                published_ms: next.published_ms,
            },
        );
        if next != memory {
            self.owned.set(next);
            self.reconcile_unseen();
        }
    }

    /// Drop the last-relay-copy record here and in storage (a merge with
    /// what is stored would bring it back).
    fn forget_remote(&self) {
        write_if(self.owned, |o| {
            let had = o.remote.is_some();
            o.remote = None;
            had
        });
        let Some(owner) = self.me() else {
            return;
        };
        if !persist_allowed(crate::auth::persisted_session_pubkey().as_deref(), &owner) {
            return;
        }
        if let Ok(mut doc) = LocalStorage::get::<LocalDoc>(storage_key(&owner)) {
            doc.remote = None;
            let _ = LocalStorage::set(storage_key(&owner), doc);
        }
    }

    /// Load-only reload after another tab wrote a subscriptions key: merge
    /// what is stored for the current owner into memory. Never writes, never
    /// schedules a publish (the tab that made the change does that).
    fn reload_from_storage(&self) {
        let memory = self.owned.get_untracked();
        let Some(owner) = memory.owner.clone() else {
            return;
        };
        let next = Self::merged_with_stored(&memory, &owner);
        if next != memory {
            self.owned.set(next);
            self.reconcile_unseen();
        }
    }

    // -- Account switching ----------------------------------------------------

    /// Make the loaded list the signed-in account's, in one step: the owner
    /// and its subscriptions change together, and everything belonging to
    /// the previous account (unseen sets, the backlog pass and its high-water
    /// marks, title fetches, pending sealed posts, the relay copy's state) is
    /// dropped. In-flight work for the previous account sees a new generation
    /// and discards its answers.
    fn ensure_owner(&self) {
        let pk = self.pubkey.get_untracked();
        if self.owned.with_untracked(|o| o.owner == pk) {
            return;
        }
        let (subs, remote, published_ms) = pk
            .as_deref()
            .map(|p| load_local(p, now_secs()))
            .unwrap_or_default();
        self.generation.update_value(|g| *g += 1);
        self.stop_pump();
        self.pump.update_value(|p| p.high.clear());
        self.stop_fetch();
        self.fetch.update_value(|f| f.asked.clear());
        self.pending.update_value(HashMap::clear);
        self.sync.set_value(SyncCtl::default());
        self.sync_status.set(SyncStatus::Idle);
        self.unseen.set(Unseen::default());
        self.owned.set(Owned {
            owner: pk,
            subs,
            remote,
            published_ms,
        });
    }

    fn generation(&self) -> u64 {
        self.generation.try_get_value().unwrap_or(u64::MAX)
    }

    fn me(&self) -> Option<String> {
        self.owned.with_untracked(|o| o.owner.clone())
    }

    fn owner_ready(&self) -> bool {
        let pk = self.pubkey.get_untracked();
        self.owned
            .with_untracked(|o| o.owner.is_some() && o.owner == pk)
    }

    // -- Live counts ----------------------------------------------------------

    /// The channel store inserted `batch`: count replies in followed topics,
    /// hold still-locked sealed ones until they open, and re-resolve titles
    /// when a followed root arrived.
    fn on_inserted(&self, batch: &[InsertedMessage]) {
        let learnt = self
            .aliases
            .try_update_value(|a| {
                let mut learnt = false;
                for m in batch {
                    if let Some(inner) = &m.sealed_inner {
                        let env = m.id.to_ascii_lowercase();
                        learnt |= a.insert(env, inner.to_ascii_lowercase()).is_none();
                    }
                }
                learnt
            })
            .unwrap_or(false);
        if learnt {
            self.aliases_rev.update(|r| *r += 1);
        }
        if !self.owner_ready() {
            return;
        }
        let (fresh, locked, root_arrived) = self.owned.with_untracked(|o| {
            let mut fresh = Vec::new();
            let mut locked = Vec::new();
            let mut root_arrived = false;
            for m in batch {
                let id = m.id.to_ascii_lowercase();
                if o.subs.is_active(&id)
                    || m.sealed_inner
                        .as_deref()
                        .is_some_and(|i| o.subs.is_active(i))
                {
                    root_arrived = true;
                }
                if let (Some(inner), Some(root)) = (&m.sealed_inner, &m.reply_root) {
                    if o.subs.read_at(root).is_some_and(|r| m.created_at > r) {
                        locked.push((
                            m.id.clone(),
                            PendingLocked {
                                root: root.clone(),
                                inner_id: inner.clone(),
                                created_at: m.created_at,
                                raw: None,
                            },
                        ));
                    }
                } else if let Some(root) = unseen_root(m, &o.subs, o.owner.as_deref()) {
                    fresh.push((root.to_string(), m.clone()));
                }
            }
            (fresh, locked, root_arrived)
        });
        if root_arrived {
            self.titles_rev.update(|r| *r += 1);
        }
        self.hold_locked(locked);
        if !fresh.is_empty() {
            self.unseen.update(|u| {
                for (root, m) in &fresh {
                    u.note(root, &m.id, m.created_at, &m.pubkey);
                }
            });
        }
    }

    fn hold_locked(&self, locked: Vec<(String, PendingLocked)>) {
        if locked.is_empty() {
            return;
        }
        let size = |e: &NostrEvent| {
            e.content.len() + e.tags.iter().flatten().map(String::len).sum::<usize>() + 256
        };
        self.pending.update_value(|p| {
            let mut bytes: usize = p.values().filter_map(|i| i.raw.as_ref()).map(size).sum();
            for (env, item) in locked {
                if p.len() >= MAX_PENDING_LOCKED {
                    break;
                }
                let add = item.raw.as_ref().map_or(0, size);
                if bytes + add > MAX_PENDING_BYTES {
                    continue;
                }
                if let std::collections::hash_map::Entry::Vacant(slot) = p.entry(env) {
                    bytes += add;
                    slot.insert(item);
                }
            }
        });
    }

    /// A zone key changed: count the sealed posts that have now opened.
    /// A held envelope is found under its original id once the store has
    /// re-decrypted it; one no list holds is decrypted again here. Counted by
    /// the original id only, so the id change cannot count it twice.
    fn resolve_pending(&self) {
        let Some(deps) = self.deps.try_with_value(Clone::clone) else {
            return;
        };
        let items: Vec<(String, PendingLocked)> = self
            .pending
            .try_with_value(|p| p.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        if items.is_empty() || !self.owner_ready() {
            return;
        }
        let me = self.me();
        let mut done: Vec<String> = Vec::new();
        let mut counted: Vec<(String, InsertedMessage)> = Vec::new();
        for (env, item) in items {
            let still = self.owned.with_untracked(|o| {
                o.subs
                    .read_at(&item.root)
                    .is_some_and(|r| item.created_at > r)
            });
            if !still {
                done.push(env);
                continue;
            }
            let opened = match &item.raw {
                None => find_held(deps.channels, &item.inner_id, item.created_at),
                Some(raw) => deps.zone_keys.and_then(|z| {
                    let ev = z.prepare_incoming(raw.clone());
                    let open = nostr_bbs_core::sealed::parse_sealed(&ev.tags).is_none();
                    if !held_anywhere(deps.channels, &ev.id, ev.created_at) {
                        z.forget(std::slice::from_ref(&ev.id));
                    }
                    open.then(|| (String::new(), ev))
                }),
            };
            if let Some((list, ev)) = opened {
                let msg = InsertedMessage::of(&list, &ev);
                let root = self.owned.with_untracked(|o| {
                    unseen_root(&msg, &o.subs, me.as_deref()).map(str::to_string)
                });
                if let Some(root) = root {
                    counted.push((root, msg));
                }
                done.push(env);
            }
        }
        self.pending.update_value(|p| {
            for env in &done {
                p.remove(env);
            }
        });
        if !counted.is_empty() {
            self.unseen.update(|u| {
                for (root, m) in &counted {
                    u.note(root, &m.id, m.created_at, &m.pubkey);
                }
            });
        }
    }

    /// Re-check counted posts against deletions, at most every
    /// [`DELETION_RECHECK_MS`]: a post a kind 5 has removed stops counting.
    fn arm_deletion_recheck(&self) {
        if self.recheck_armed.get_value() {
            return;
        }
        self.recheck_armed.set_value(true);
        let store = *self;
        crate::utils::set_timeout_once(
            move || {
                if store.recheck_armed.try_set_value(false).is_some() {
                    return;
                }
                store.recheck_deleted();
            },
            DELETION_RECHECK_MS,
        );
    }

    fn recheck_deleted(&self) {
        let Some(deps) = self.deps.try_with_value(Clone::clone) else {
            return;
        };
        let posts = self.unseen.with_untracked(Unseen::posts);
        if posts.is_empty() {
            return;
        }
        let gone: HashSet<String> = posts
            .into_iter()
            .filter(|(id, p)| {
                let stub = NostrEvent {
                    id: id.clone(),
                    pubkey: p.pubkey.clone(),
                    created_at: p.created_at,
                    kind: 42,
                    tags: Vec::new(),
                    content: String::new(),
                    sig: String::new(),
                };
                !deps.channels.admits_message(deps.zone_keys, &stub)
            })
            .map(|(id, _)| id)
            .collect();
        if !gone.is_empty() {
            self.unseen.update(|u| u.remove_ids(&gone));
        }
    }

    // -- Backlog pass ---------------------------------------------------------

    /// Abandon the backlog pass: close the REQ in flight and forget what was
    /// asked, so the next connection asks again (from each topic's high-water
    /// mark, which is kept).
    fn stop_pump(&self) {
        let sub = self
            .pump
            .try_update_value(|p| {
                p.gen += 1;
                p.done.clear();
                p.queue.clear();
                p.inflight.clear();
                p.retries.clear();
                p.sub.take()
            })
            .flatten();
        if let Some(id) = sub.filter(|s| !s.is_empty()) {
            self.deps.with_value(|d| d.relay.unsubscribe(&id));
        }
    }

    /// Queue the followed topics not yet asked on this connection.
    fn enqueue_backlog(&self, roots: Vec<String>) {
        let added = self
            .pump
            .try_update_value(|p| {
                let mut added = false;
                for root in roots {
                    if p.done.insert(root.clone()) {
                        p.queue.push_back(root);
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
    /// [`BACKLOG_FILTERS_PER_REQ`] topics, each from [`backlog_since`], closed
    /// on its answer; refused or unanswered batches are re-sent with backoff.
    fn pump_next(&self) {
        let next = self
            .pump
            .try_update_value(|p| {
                if p.sub.is_some() || p.queue.is_empty() {
                    return None;
                }
                let n = p.queue.len().min(BACKLOG_FILTERS_PER_REQ);
                let batch: Vec<String> = p.queue.drain(..n).collect();
                p.inflight = batch.clone();
                // Reserve the slot before subscribing; the real id replaces
                // it once `subscribe` returns.
                p.sub = Some(String::new());
                let items: Vec<(String, Option<u64>)> = batch
                    .into_iter()
                    .map(|r| {
                        let high = p.high.get(&r).copied();
                        (r, high)
                    })
                    .collect();
                Some((items, p.gen))
            })
            .flatten();
        let Some((items, gen)) = next else {
            return;
        };
        let Some(deps) = self.deps.try_with_value(Clone::clone) else {
            return;
        };
        // Since: from the marker (read now, so it is current) and the
        // high-water mark. Topics no longer followed are skipped.
        let items: Vec<(String, u64)> = self.owned.with_untracked(|o| {
            items
                .into_iter()
                .filter_map(|(r, high)| o.subs.read_at(&r).map(|t| (r, backlog_since(t, high))))
                .collect()
        });
        if items.is_empty() {
            self.pump.update_value(|p| {
                p.sub = None;
                p.inflight.clear();
            });
            self.pump_next();
            return;
        }
        let store = *self;
        let wanted: HashSet<String> = items.iter().map(|(r, _)| r.clone()).collect();
        // Per topic: posts delivered and the newest `created_at` seen.
        let delivered: Rc<RefCell<HashMap<String, (u64, u64)>>> = Rc::default();
        let filters = backlog_batches(&items)
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
        let finish: Rc<dyn Fn(Outcome)> = {
            let relay = deps.relay.clone();
            Rc::new(move |outcome: Outcome| {
                if done.replace(true) || store.pump.try_with_value(|p| p.gen) != Some(gen) {
                    return;
                }
                let delivered = delivered.borrow().clone();
                let (sub, retry_in) = store
                    .pump
                    .try_update_value(|p| {
                        let inflight = std::mem::take(&mut p.inflight);
                        let mut retry_in: Option<u64> = None;
                        for root in inflight {
                            match outcome {
                                Outcome::Answered => {
                                    p.retries.remove(&root);
                                    if let Some((_, newest)) = delivered.get(&root) {
                                        let h = p.high.entry(root).or_insert(0);
                                        *h = (*h).max(*newest);
                                    }
                                }
                                Outcome::Refused => {
                                    let n = p.retries.entry(root.clone()).or_insert(0);
                                    if let Some(d) = retry_delay_ms(*n) {
                                        *n += 1;
                                        p.queue.push_back(root);
                                        retry_in = Some(retry_in.map_or(d, |x| x.max(d)));
                                    }
                                }
                            }
                        }
                        (p.sub.take(), retry_in)
                    })
                    .unwrap_or((None, None));
                if let Some(id) = sub.filter(|s| !s.is_empty()) {
                    relay.unsubscribe(&id);
                }
                if outcome == Outcome::Answered {
                    let full: Vec<String> = delivered
                        .iter()
                        .filter(|(_, (n, _))| *n >= BACKLOG_LIMIT)
                        .map(|(r, _)| r.clone())
                        .collect();
                    if !full.is_empty() {
                        store.unseen.update(|u| {
                            for r in &full {
                                u.saturate(r);
                            }
                        });
                    }
                }
                match retry_in {
                    Some(ms) => crate::utils::set_timeout_once(
                        move || {
                            if store.pump.try_with_value(|p| p.gen) == Some(gen) {
                                store.pump_next();
                            }
                        },
                        ms as i32,
                    ),
                    None => store.pump_next(),
                }
            })
        };
        let on_receipt = {
            let finish = finish.clone();
            Rc::new(move |authed: bool| {
                if authed {
                    finish(Outcome::Answered);
                }
            })
        };
        let on_closed = {
            let finish = finish.clone();
            Rc::new(move |_reason: String| finish(Outcome::Refused))
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
        crate::utils::set_timeout_once(move || finish(Outcome::Refused), PAGE_TIMEOUT_MS as i32);
    }

    /// One backlog delivery: admitted and decrypted exactly as the store's
    /// other read paths do (so an edit or the author is judged on the post
    /// itself), counted if it is unseen, held if it is a still-locked sealed
    /// post, and its decrypt state dropped unless a list holds it.
    fn on_backlog_event(
        &self,
        deps: &Deps,
        wanted: &HashSet<String>,
        delivered: &Rc<RefCell<HashMap<String, (u64, u64)>>>,
        raw: NostrEvent,
    ) {
        let raw_copy = nostr_bbs_core::sealed::parse_sealed(&raw.tags)
            .is_some()
            .then(|| raw.clone());
        let Some((list, ev)) = deps.channels.ingest(deps.zone_keys, raw, "") else {
            return;
        };
        let msg = InsertedMessage::of(&list, &ev);
        if let Some(root) = msg.reply_root.as_deref().filter(|r| wanted.contains(*r)) {
            {
                let mut d = delivered.borrow_mut();
                let slot = d.entry(root.to_string()).or_insert((0, 0));
                slot.0 += 1;
                // Never let a post dated in the future raise the mark.
                slot.1 = slot.1.max(msg.created_at.min(now_secs()));
            }
            let me = self.me();
            let (counted, still_locked) = self.owned.with_untracked(|o| {
                let counted = unseen_root(&msg, &o.subs, me.as_deref()).map(str::to_string);
                let locked = msg.sealed_inner.is_some()
                    && o.subs.read_at(root).is_some_and(|r| msg.created_at > r);
                (counted, locked)
            });
            if let Some(root) = counted {
                self.unseen.update(|u| {
                    u.note(&root, &msg.id, msg.created_at, &msg.pubkey);
                });
            }
            if still_locked {
                if let Some(inner) = msg.sealed_inner.clone() {
                    self.hold_locked(vec![(
                        msg.id.clone(),
                        PendingLocked {
                            root: root.to_string(),
                            inner_id: inner,
                            created_at: msg.created_at,
                            raw: raw_copy,
                        },
                    )]);
                }
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
                f.retries.clear();
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
    /// [`ROOT_FETCH_BATCH`] ids, closed on its answer, re-sent with backoff if
    /// refused. Each root enters the channel store's subscribed-roots list for its
    /// channel through the usual admission and decrypt path, so a root still
    /// locked becomes readable when its zone key arrives.
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
        let finish: Rc<dyn Fn(Outcome)> = {
            let relay = deps.relay.clone();
            Rc::new(move |outcome: Outcome| {
                if done.replace(true) || store.fetch.try_with_value(|f| f.gen) != Some(gen) {
                    return;
                }
                let (sub, retry_in) = store
                    .fetch
                    .try_update_value(|f| {
                        let inflight = std::mem::take(&mut f.inflight);
                        let mut retry_in: Option<u64> = None;
                        for root in inflight {
                            if outcome == Outcome::Answered {
                                f.retries.remove(&root);
                                continue;
                            }
                            let n = f.retries.entry(root.clone()).or_insert(0);
                            if let Some(d) = retry_delay_ms(*n) {
                                *n += 1;
                                f.queue.push_back(root);
                                retry_in = Some(retry_in.map_or(d, |x| x.max(d)));
                            } else {
                                // Given up: may be asked again next session
                                // step (reconnect).
                                f.asked.remove(&root);
                            }
                        }
                        (f.sub.take(), retry_in)
                    })
                    .unwrap_or((None, None));
                if let Some(id) = sub.filter(|s| !s.is_empty()) {
                    relay.unsubscribe(&id);
                }
                match retry_in {
                    Some(ms) => crate::utils::set_timeout_once(
                        move || {
                            if store.fetch.try_with_value(|f| f.gen) == Some(gen) {
                                store.fetch_next();
                            }
                        },
                        ms as i32,
                    ),
                    None => store.fetch_next(),
                }
            })
        };
        let on_receipt = {
            let finish = finish.clone();
            Rc::new(move |authed: bool| {
                if authed {
                    finish(Outcome::Answered);
                }
            })
        };
        let on_closed = {
            let finish = finish.clone();
            Rc::new(move |_reason: String| finish(Outcome::Refused))
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
        crate::utils::set_timeout_once(move || finish(Outcome::Refused), PAGE_TIMEOUT_MS as i32);
    }

    // -- Cross-device copy ----------------------------------------------------

    fn is_extension(&self) -> bool {
        self.deps
            .with_value(|d| d.auth.state().with_untracked(|s| s.is_nip07))
    }

    fn relay_ready(&self) -> bool {
        self.deps
            .with_value(|d| d.relay.authenticated().get_untracked())
            && self.owner_ready()
    }

    /// The publish decision for `trigger` from the current state.
    fn plan_now(&self, trigger: Trigger) -> Plan {
        let now = now_ms();
        let (mut subs, remote, published_ms) = self
            .owned
            .with_untracked(|o| (o.subs.clone(), o.remote.clone(), o.published_ms));
        subs.prune(now);
        let local = sync::digests(&subs).ok();
        let ctl = self.sync.get_value();
        sync::plan(&PlanInput {
            fetched: ctl.fetched,
            disabled: ctl.disabled.is_some(),
            local: local.as_ref(),
            local_empty: subs.entries.is_empty(),
            remote: remote.as_ref(),
            extension: self.is_extension(),
            trigger,
            now_ms: now,
            last_fetch_ms: ctl.last_fetch_ms,
            published_ms,
            not_before_ms: ctl.not_before_ms,
        })
    }

    /// After a change, a reconnect or a sync: start the first sync for the
    /// account (one fetch per session; a reconnect fetches again only when
    /// something is pending), or arm the timer for the next publish the plan
    /// allows.
    fn schedule_sync(&self) {
        if !self.relay_ready() {
            return;
        }
        let ctl = self.sync.get_value();
        if ctl.disabled.is_some() || ctl.busy {
            return;
        }
        if !ctl.fetched {
            if now_ms() >= ctl.not_before_ms {
                self.spawn_sync(Trigger::Scheduled);
            } else {
                self.arm_timer(ctl.not_before_ms);
            }
            return;
        }
        match self.plan_now(Trigger::Scheduled) {
            Plan::Wait { until_ms } => self.arm_timer(until_ms.max(ctl.lock_wait_until)),
            Plan::Publish | Plan::Refetch => {
                self.arm_timer((now_ms() + PUBLISH_SETTLE_MS).max(ctl.lock_wait_until))
            }
            Plan::TooLarge => self
                .sync_status
                .set(SyncStatus::LocalOnly(LocalOnlyReason::TooLarge)),
            Plan::Nothing => self.sync_status.set(SyncStatus::Synced),
            Plan::Blocked => {}
        }
    }

    fn arm_timer(&self, at_ms: u64) {
        let ctl = self.sync.get_value();
        if ctl.timer_at.is_some_and(|t| t <= at_ms) {
            return;
        }
        self.sync.update_value(|c| c.timer_at = Some(at_ms));
        let gen = self.generation();
        let store = *self;
        let delay = at_ms.saturating_sub(now_ms()).min(i32::MAX as u64) as i32;
        crate::utils::set_timeout_once(
            move || {
                if store.generation() != gen {
                    return;
                }
                store.sync.update_value(|c| {
                    if c.timer_at == Some(at_ms) {
                        c.timer_at = None;
                    }
                });
                store.schedule_or_run();
            },
            delay,
        );
    }

    /// A timer fired: run the sync if the plan says so now, else re-arm.
    fn schedule_or_run(&self) {
        let ctl = self.sync.get_value();
        if ctl.busy || ctl.disabled.is_some() || !self.relay_ready() {
            return;
        }
        if !ctl.fetched {
            self.schedule_sync();
            return;
        }
        let now = now_ms();
        match self.plan_now(Trigger::Scheduled) {
            Plan::Publish | Plan::Refetch if now >= ctl.lock_wait_until => {
                self.spawn_sync(Trigger::Scheduled)
            }
            Plan::Publish | Plan::Refetch => self.arm_timer(ctl.lock_wait_until),
            Plan::Wait { until_ms } => self.arm_timer(until_ms.max(ctl.lock_wait_until)),
            _ => {}
        }
    }

    fn spawn_sync(&self, trigger: Trigger) {
        let store = *self;
        let gen = self.generation();
        self.sync.update_value(|c| c.busy = true);
        self.sync_status.set(SyncStatus::Syncing);
        leptos::task::spawn_local(async move {
            let outcome = store.sync_once(gen, trigger).await;
            if store.generation() != gen {
                return;
            }
            store.sync.update_value(|c| c.busy = false);
            match outcome {
                Ok(()) => {
                    store.sync.update_value(|c| {
                        c.failures = 0;
                        c.not_before_ms = 0;
                    });
                    store.schedule_sync();
                }
                Err(reason) => {
                    let now = now_ms();
                    store.sync.update_value(|c| {
                        if reason.ends_session() {
                            c.disabled = Some(reason);
                        } else {
                            // Rate-limited on the attempt, not the last
                            // success: back off before trying again.
                            c.failures += 1;
                            c.not_before_ms = now + sync::failure_backoff_ms(c.failures);
                        }
                    });
                    store.sync_status.set(SyncStatus::LocalOnly(reason));
                    // Retried with backoff: one timer (deduplicated by
                    // `arm_timer`, dropped on an account switch by the
                    // generation check), not on every change.
                    let ctl = store.sync.get_value();
                    if ctl.disabled.is_none() {
                        store.arm_timer(ctl.not_before_ms);
                    }
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

    /// Fetch the relay copy (one REQ, closed on its answer) and merge it in.
    /// A copy whose id is the one last seen (kept with the local copy, so
    /// across reloads too) is not decrypted again.
    async fn fetch_and_merge(
        &self,
        signer: &dyn nostr_bbs_core::signer::Signer,
        relay: &RelayConnection,
        gen: u64,
    ) -> Result<(), LocalOnlyReason> {
        let owner = signer.public_key().to_string();
        let latest = sync::fetch_latest(relay, &owner).await?;
        if self.generation() != gen {
            return Ok(());
        }
        self.sync.update_value(|c| c.last_fetch_ms = Some(now_ms()));
        let known = self.owned.with_untracked(|o| o.remote.clone());
        if latest.is_none() && known.is_some() {
            // The relay answered and holds no copy (it was deleted or lost):
            // forget the record, so the plan republishes the local list.
            self.forget_remote();
        }
        if let Some(ev) = latest.filter(|ev| sync::remote_changed(known.as_ref(), ev)) {
            let mut remote = timed(sync::open(signer, &ev, now_secs()), SIGNER_TIMEOUT_MS).await?;
            if self.generation() != gen {
                return Ok(());
            }
            let now = now_ms();
            let local = self.owned.with_untracked(|o| o.subs.clone());
            let merged = local.join(&remote, now / 1000);
            remote.prune(now);
            let d = sync::digests(&remote).unwrap_or(sync::Digests {
                full: String::new(),
                entries: String::new(),
            });
            self.owned.update(|o| {
                o.subs = merged;
                o.remote = Some(RemoteSeen {
                    id: ev.id.clone(),
                    created_at: ev.created_at,
                    digest: d.full,
                    entries_digest: d.entries,
                });
            });
            self.persist();
            self.reconcile_unseen();
        }
        self.sync.update_value(|c| c.fetched = true);
        Ok(())
    }

    /// Fetch, merge and, if the plan says so, publish. Re-fetches when the
    /// fetch has gone stale by the time the copy is sealed (a NIP-07 prompt
    /// can take minutes), and starts over if the relay copy changed
    /// meanwhile. Never publishes before a successful fetch, nor over a copy
    /// it cannot read (that fails the fetch with `Unreadable`). When another
    /// tab holds the publish lock it waits for that lock's expiry (or for the
    /// other tab's write, which shows nothing is pending).
    async fn sync_once(&self, gen: u64, trigger: Trigger) -> Result<(), LocalOnlyReason> {
        let signer = self.sync_signer()?;
        let relay = self.deps.with_value(|d| d.relay.clone());
        for _ in 0..3 {
            self.fetch_and_merge(&*signer, &relay, gen).await?;
            if self.generation() != gen {
                return Ok(());
            }
            match self.plan_now(trigger) {
                Plan::Publish => {}
                Plan::Refetch => continue,
                Plan::TooLarge => return Err(LocalOnlyReason::TooLarge),
                Plan::Wait { .. } | Plan::Nothing | Plan::Blocked => return Ok(()),
            }
            if let Err(until) = self.acquire_lock() {
                self.sync.update_value(|c| c.lock_wait_until = until);
                return Ok(());
            }
            let result = self.seal_and_publish(&*signer, &relay, gen).await;
            self.release_lock();
            match result {
                Ok(true) => return Ok(()),
                Ok(false) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Seal the local list and publish it unless the relay copy changed while
    /// sealing. `Ok(false)`: it changed; fetch, merge and seal again.
    async fn seal_and_publish(
        &self,
        signer: &dyn nostr_bbs_core::signer::Signer,
        relay: &RelayConnection,
        gen: u64,
    ) -> Result<bool, LocalOnlyReason> {
        let now = now_ms();
        let (mut snapshot, remote) = self
            .owned
            .with_untracked(|o| (o.subs.clone(), o.remote.clone()));
        snapshot.prune(now);
        let d = sync::digests(&snapshot)?;
        let created_at = now_secs().max(remote.as_ref().map_or(0, |r| r.created_at + 1));
        let ev = timed(sync::seal(signer, &snapshot, created_at), SIGNER_TIMEOUT_MS).await?;
        if self.generation() != gen {
            return Ok(true);
        }
        let fetched_at = self.sync.get_value().last_fetch_ms.unwrap_or(0);
        if now_ms().saturating_sub(fetched_at) > sync::FRESH_FETCH_MS {
            let latest = sync::fetch_latest(relay, signer.public_key()).await?;
            if self.generation() != gen {
                return Ok(true);
            }
            self.sync.update_value(|c| c.last_fetch_ms = Some(now_ms()));
            if latest.is_some_and(|l| sync::remote_changed(remote.as_ref(), &l)) {
                return Ok(false);
            }
        }
        // Extend the lock across the publish (the prompt may have used most
        // of it).
        if let Err(until) = self.acquire_lock() {
            self.sync.update_value(|c| c.lock_wait_until = until);
            return Ok(true);
        }
        sync::publish(relay, &ev).await?;
        if self.generation() != gen {
            return Ok(true);
        }
        self.owned.update(|o| {
            o.remote = Some(RemoteSeen {
                id: ev.id.clone(),
                created_at: ev.created_at,
                digest: d.full,
                entries_digest: d.entries,
            });
            o.published_ms = now_ms();
        });
        self.persist();
        Ok(true)
    }

    /// Take (or extend) the per-account publish lock unless another tab holds
    /// a live one; `Err(until)` gives that lock's expiry.
    fn acquire_lock(&self) -> Result<(), u64> {
        let Some(owner) = self.me() else {
            return Err(now_ms() + LOCK_MS);
        };
        let mine = self.tab_id.get_value();
        let key = lock_key(&owner);
        let now = now_ms();
        if let Ok(v) = LocalStorage::get::<(String, u64)>(&key) {
            if v.0 != mine && v.1 > now {
                return Err(v.1);
            }
        }
        let until = now + LOCK_MS;
        let _ = LocalStorage::set(&key, (mine.clone(), until));
        match LocalStorage::get::<(String, u64)>(&key) {
            Ok(v) if v.0 == mine => {
                self.sync.update_value(|c| c.lock_wait_until = 0);
                Ok(())
            }
            Ok(v) => Err(v.1),
            Err(_) => Err(until),
        }
    }

    fn release_lock(&self) {
        let Some(owner) = self.me() else {
            return;
        };
        let key = lock_key(&owner);
        if LocalStorage::get::<(String, u64)>(&key).is_ok_and(|v| v.0 == self.tab_id.get_value()) {
            LocalStorage::delete(key);
        }
    }

    /// The page was hidden: publish pending changes now, fetching and merging
    /// first (the page can still wait while hidden), within the plan's
    /// limits.
    fn flush_on_hidden(&self) {
        let ctl = self.sync.get_value();
        if ctl.busy || ctl.disabled.is_some() || !ctl.fetched || !self.relay_ready() {
            return;
        }
        if now_ms() < ctl.lock_wait_until {
            return;
        }
        if matches!(
            self.plan_now(Trigger::Hidden),
            Plan::Publish | Plan::Refetch
        ) {
            self.spawn_sync(Trigger::Hidden);
        }
    }

    /// The page is going: publish pending changes only if that needs no
    /// waiting (a local-key or passkey signer) and the last fetch is recent
    /// enough ([`sync::PAGEHIDE_FRESH_MS`]) that no relay copy can have been
    /// missed. Best effort; the last relay copy seen is not updated, so the
    /// next session checks what actually arrived.
    fn flush_on_pagehide(&self) {
        let ctl = self.sync.get_value();
        if ctl.busy || !self.relay_ready() || now_ms() < ctl.lock_wait_until {
            return;
        }
        if self.plan_now(Trigger::PageHide) != Plan::Publish {
            return;
        }
        let Ok(signer) = self.sync_signer() else {
            return;
        };
        let now = now_ms();
        let (mut local, remote) = self
            .owned
            .with_untracked(|o| (o.subs.clone(), o.remote.clone()));
        local.prune(now);
        let created_at = now_secs().max(remote.as_ref().map_or(0, |r| r.created_at + 1));
        let relay = self.deps.with_value(|d| d.relay.clone());
        leptos::task::spawn_local(async move {
            if let Ok(ev) = sync::seal(&*signer, &local, created_at).await {
                relay.publish(&ev);
            }
        });
    }

    /// A last publish for sign-out, built from what is in memory **now**
    /// (signer, list, last relay copy seen), so it runs after the session is
    /// cleared and writes nothing to storage. `None` when nothing is pending
    /// or allowed, and always for a NIP-07 extension (it would prompt).
    fn sign_out_job(&self) -> Option<Pin<Box<dyn Future<Output = ()>>>> {
        self.ensure_owner();
        if self.is_extension() {
            return None;
        }
        let ctl = self.sync.get_value();
        if ctl.disabled.is_some() || !ctl.fetched || !self.relay_ready() {
            return None;
        }
        if !matches!(
            self.plan_now(Trigger::SignOut),
            Plan::Publish | Plan::Refetch
        ) {
            return None;
        }
        let signer = self.sync_signer().ok()?;
        let relay = self.deps.with_value(|d| d.relay.clone());
        let (mut local, remote) = self
            .owned
            .with_untracked(|o| (o.subs.clone(), o.remote.clone()));
        local.prune(now_ms());
        Some(Box::pin(async move {
            let _ = sign_out_publish(&*signer, &relay, local, remote).await;
        }))
    }

    // -- Wiring ---------------------------------------------------------------

    /// Attach the effects and listeners. Called once by
    /// [`provide_thread_subs`].
    fn start(&self) {
        let store = *self;
        let (relay, channels, zone_keys) = self
            .deps
            .with_value(|d| (d.relay.clone(), d.channels, d.zone_keys));
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
        // reconnect (AUTH drops and returns; the pass then asks from each
        // topic's high-water mark), and for topics that become followed
        // meanwhile (here or merged from another device or tab).
        Effect::new(move |_| {
            let is_authed = authed.get();
            let pk = pubkey.get();
            let (owner_ok, roots) = owned.with(|o| {
                let ok = o.owner.is_some() && o.owner == pk;
                let roots: Vec<(String, String)> = o
                    .subs
                    .active()
                    .map(|e| (e.r.clone(), e.c.clone()))
                    .collect();
                (ok, roots)
            });
            if !is_authed || !owner_ok {
                store.stop_pump();
                store.stop_fetch();
                return;
            }
            store.enqueue_backlog(roots.iter().map(|(r, _)| r.clone()).collect());
            store.enqueue_root_fetches(roots);
        });

        // Relay copy: first merge once AUTH settles for the account; retried
        // after a reconnect if it failed.
        let owner_memo = Memo::new(move |_| owned.with(|o| o.owner.clone()));
        Effect::new(move |_| {
            let is_authed = authed.get();
            let _ = owner_memo.get();
            if is_authed {
                store.schedule_sync();
            }
        });

        // Sealed posts that open when a zone key arrives.
        if let Some(z) = zone_keys {
            let revision = z.revision;
            Effect::new(move |_| {
                revision.track();
                store.resolve_pending();
            });
        }

        // Deletions: the channel store's lists change when a kind 5 lands.
        Effect::new(move |_| {
            channels.channel_messages.track();
            store.arm_deletion_recheck();
        });

        // Another tab wrote a subscriptions key (any account: the reload reads
        // only the current owner's).
        crate::utils::on_cross_tab_storage_prefix_write(STORAGE_KEY_PREFIX, move || {
            store.reload_from_storage();
        });

        // Hidden: the page can still wait, so fetch, merge and publish.
        let hidden = gloo::events::EventListener::new(
            &gloo::utils::document(),
            "visibilitychange",
            move |_| {
                if gloo::utils::document().hidden() {
                    store.flush_on_hidden();
                }
            },
        );
        hidden.forget();

        // Going: publish only what needs no waiting.
        let going =
            gloo::events::EventListener::new(&gloo::utils::window(), "pagehide", move |_| {
                store.flush_on_pagehide();
            });
        going.forget();
    }
}

/// Take a fetched root into the channel store's subscribed-roots list for its
/// channel ([`followed_roots_key`], never the section's root list) if
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
        // Never into the section's root list: the topic board must not see it.
        deps.channels
            .apply_page(vec![(followed_roots_key(&cid), ev)]);
    } else if let Some(z) = deps.zone_keys {
        z.forget(std::slice::from_ref(&ev.id));
    }
}

// -- Sign-out -----------------------------------------------------------------

/// Run `fut`, giving up with [`LocalOnlyReason::RelayError`] after `ms`
/// milliseconds (a NIP-07 prompt left open never answers).
async fn timed<T>(
    fut: impl Future<Output = Result<T, LocalOnlyReason>>,
    ms: u32,
) -> Result<T, LocalOnlyReason> {
    let slot: Rc<crate::relay::OneShot<()>> = crate::relay::OneShot::new();
    let late = slot.clone();
    let _timer = gloo::timers::callback::Timeout::new(ms, move || late.fill(()));
    let timeout = Box::pin(async move { slot.wait().await });
    match futures_util::future::select(Box::pin(fut), timeout).await {
        futures_util::future::Either::Left((r, _)) => r,
        futures_util::future::Either::Right(_) => Err(LocalOnlyReason::RelayError),
    }
}

/// The sign-out publish: fetch, merge in memory, publish if the relay copy
/// lacks something. Uses only what it was given; touches no store or
/// storage, so it is safe after the session has been cleared.
async fn sign_out_publish(
    signer: &dyn nostr_bbs_core::signer::Signer,
    relay: &RelayConnection,
    mut local: Subs,
    mut remote: Option<RemoteSeen>,
) -> Result<(), LocalOnlyReason> {
    let owner = signer.public_key().to_string();
    let latest = sync::fetch_latest(relay, &owner).await?;
    if let Some(ev) = latest.filter(|ev| sync::remote_changed(remote.as_ref(), ev)) {
        let r = sync::open(signer, &ev, now_secs()).await?;
        local = local.join(&r, now_secs());
        let d = sync::digests(&r)?;
        remote = Some(RemoteSeen {
            id: ev.id.clone(),
            created_at: ev.created_at,
            digest: d.full,
            entries_digest: d.entries,
        });
    }
    local.prune(now_ms());
    let d = sync::digests(&local)?;
    if remote.as_ref().is_some_and(|r| r.digest == d.full) {
        return Ok(());
    }
    let created_at = now_secs().max(remote.as_ref().map_or(0, |r| r.created_at + 1));
    let ev = sync::seal(signer, &local, created_at).await?;
    sync::publish(relay, &ev).await
}

thread_local! {
    /// The store, for sign-out (which runs outside any reactive owner).
    static GLOBAL: Cell<Option<ThreadSubsStore>> = const { Cell::new(None) };
}

/// The store, for code outside a reactive owner (the notification centre's
/// "Mark all read"). `None` before [`provide_thread_subs`].
pub(crate) fn global_thread_subs() -> Option<ThreadSubsStore> {
    GLOBAL.with(Cell::get)
}

/// A bounded last publish to run before sign-out removes the local copy:
/// `Some` when pending changes can be published (the first fetch this
/// session succeeded, the relay session is authenticated, the signer is still
/// there). The caller waits at most [`SIGN_OUT_FLUSH_MS`] via [`within`]
/// before signing out regardless; changes made on this device since its last
/// successful publish are then lost with the local copy.
pub(crate) fn sign_out_flush() -> Option<Pin<Box<dyn Future<Output = ()>>>> {
    GLOBAL.with(Cell::get)?.sign_out_job()
}

/// Run `job` for at most `ms` milliseconds; the job is dropped (with the
/// signer it holds) if the time runs out.
pub(crate) async fn within(job: Pin<Box<dyn Future<Output = ()>>>, ms: u32) {
    let slot: Rc<crate::relay::OneShot<()>> = crate::relay::OneShot::new();
    let late = slot.clone();
    let _timer = gloo::timers::callback::Timeout::new(ms, move || late.fill(()));
    let timeout = Box::pin(async move { slot.wait().await });
    let _ = futures_util::future::select(job, timeout).await;
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
        zones: crate::stores::zones::load_zones(),
    };
    let store = ThreadSubsStore::new(deps);
    provide_context(store);
    GLOBAL.with(|g| g.set(Some(store)));
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
            sealed_inner: None,
        }
    }

    // -- serde --

    #[test]
    fn doc_round_trips_and_uses_the_compact_shape() {
        let mut s = Subs::default();
        s.subscribe(&id(1), &chan(1), "zone1", NOW, NOW_MS).unwrap();
        s.subscribe(&id(2), &chan(2), "", NOW, NOW_MS).unwrap();
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
        let back = Subs::from_doc(serde_json::from_str(&json).unwrap(), NOW);
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
        let s = Subs::from_doc(doc, NOW);
        assert_eq!(s.entries.len(), 1);
        assert!(s.is_active(&id(3)));
        assert_eq!(s.read_at(&id(3)), Some(9));
    }

    #[test]
    fn a_missing_field_or_extra_field_still_loads() {
        let doc: SubsDoc = serde_json::from_str(r#"{"subs":[],"extra":1}"#).unwrap();
        assert_eq!(Subs::from_doc(doc, NOW), Subs::default());
        let doc: SubsDoc = serde_json::from_str("{}").unwrap();
        assert_eq!(Subs::from_doc(doc, NOW), Subs::default());
    }

    // -- markers --

    #[test]
    fn subscribe_sets_the_marker_to_now_and_markers_never_go_back() {
        let mut s = Subs::default();
        s.subscribe(&id(1), &chan(1), "", NOW, NOW_MS).unwrap();
        assert_eq!(s.read_at(&id(1)), Some(NOW));
        assert!(s.mark_read(&id(1), NOW + 10, NOW + 1_000_000));
        assert!(!s.mark_read(&id(1), NOW + 5, NOW + 1_000_000));
        assert_eq!(s.read_at(&id(1)), Some(NOW + 10));
        // Re-subscribing an active topic leaves the marker alone.
        s.subscribe(&id(1), &chan(1), "", NOW + 1, NOW_MS + 1)
            .unwrap();
        assert_eq!(s.read_at(&id(1)), Some(NOW + 10));
        // A topic not followed is ignored.
        assert!(!s.mark_read(&id(9), NOW, NOW + 1_000_000));
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
        s.subscribe(&id(0xabc).to_uppercase(), &chan(1), "", NOW, NOW_MS)
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
            s.subscribe(&id(n), &chan(1), "", NOW, NOW_MS).unwrap();
        }
        let err = s
            .subscribe(&id(9999), &chan(1), "", NOW, NOW_MS)
            .unwrap_err();
        assert_eq!(
            err,
            SubscribeError::LimitReached {
                limit: MAX_ACTIVE_SUBSCRIPTIONS
            }
        );
        assert!(err.to_string().contains("150"));
        // An already-followed topic is not refused.
        assert_eq!(s.subscribe(&id(0), &chan(1), "", NOW, NOW_MS), Ok(false));
        s.unsubscribe(&id(0), NOW_MS + 1);
        assert_eq!(
            s.subscribe(&id(9999), &chan(1), "", NOW, NOW_MS + 2),
            Ok(true)
        );
    }

    #[test]
    fn invalid_ids_are_refused() {
        let mut s = Subs::default();
        assert_eq!(
            s.subscribe("abc", &chan(1), "", NOW, NOW_MS),
            Err(SubscribeError::InvalidTopic)
        );
        assert_eq!(
            s.subscribe(&id(1), "", "", NOW, NOW_MS),
            Err(SubscribeError::InvalidTopic)
        );
        assert_eq!(
            s.subscribe(&id(1), "general", "", NOW, NOW_MS),
            Err(SubscribeError::InvalidTopic),
            "a channel is a kind-40 event id, not a slug"
        );
        assert_eq!(
            s.subscribe(&id(1), &chan(1), &"z".repeat(MAX_ZONE_LEN + 1), NOW, NOW_MS),
            Err(SubscribeError::InvalidTopic)
        );
    }

    // -- merge --

    #[test]
    fn newer_entry_wins_and_tombstones_beat_older_subscriptions() {
        let a = subs_of(&[entry(&id(1), true, 100)], &[(&id(1), 50)]);
        let b = subs_of(&[entry(&id(1), false, 200)], &[]);
        let m = a.join(&b, NOW);
        assert!(!m.is_active(&id(1)));
        assert_eq!(m, b.join(&a, NOW));
        // A re-subscription after the tombstone wins in turn.
        let c = subs_of(&[entry(&id(1), true, 300)], &[(&id(1), 70)]);
        assert!(m.join(&c, NOW).is_active(&id(1)));
    }

    #[test]
    fn equal_times_break_ties_the_same_way_on_every_device() {
        let on = entry(&id(1), true, 100);
        let off = entry(&id(1), false, 100);
        let a = subs_of(std::slice::from_ref(&on), &[]);
        let b = subs_of(std::slice::from_ref(&off), &[]);
        assert_eq!(a.join(&b, NOW), b.join(&a, NOW));
        assert!(!a.join(&b, NOW).is_active(&id(1)), "off wins a tie");
        let mut other = on.clone();
        other.c = chan(2);
        let c = subs_of(&[other], &[]);
        assert_eq!(a.join(&c, NOW), c.join(&a, NOW));
    }

    #[test]
    fn read_markers_take_the_maximum() {
        let a = subs_of(&[entry(&id(1), true, 100)], &[(&id(1), 50)]);
        let b = subs_of(&[entry(&id(1), true, 90)], &[(&id(1), 80)]);
        assert_eq!(a.join(&b, NOW).read_at(&id(1)), Some(80));
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
        assert_eq!(a.join(&b, NOW), b.join(&a, NOW));
        assert_eq!(a.join(&b, NOW).join(&c, NOW), a.join(&b.join(&c, NOW), NOW));
        assert_eq!(a.join(&a, NOW), a);
        let all = a.join(&b, NOW).join(&c, NOW);
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
        assert!(!s.join(&stale, NOW).is_active(&id(1)));
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
        s.subscribe(&id(1), &chan(1), "", NOW, NOW_MS).unwrap();
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
        s.subscribe(&id(1), &chan(1), "", NOW, NOW_MS).unwrap();
        let r = id(1);
        let mut u = Unseen::default();
        assert!(u.note(&r, &id(100), NOW + 1, "bb"));
        assert!(
            !u.note(&r, &id(100).to_uppercase(), NOW + 1, "bb"),
            "same id once"
        );
        u.note(&r, &id(101), NOW + 5, "bb");
        assert_eq!(
            u.count(&r),
            UnreadCount {
                count: 2,
                capped: false
            }
        );
        s.mark_read(&r, NOW + 1, NOW + 1_000_000);
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
        s.subscribe(&id(1), &chan(1), "", NOW, NOW_MS).unwrap();
        let r = id(1);
        let mut u = Unseen::default();
        for n in 0..=UNREAD_DISPLAY_CAP as u32 {
            u.note(&r, &id(500 + n), NOW + 1, "bb");
        }
        assert_eq!(u.count(&r).count, UNREAD_DISPLAY_CAP + 1);
        assert!(u.count(&r).capped);
        let mut u = Unseen::default();
        u.note(&r, &id(1), NOW + 1, "bb");
        u.saturate(&r);
        assert_eq!(
            u.count(&r),
            UnreadCount {
                count: 1,
                capped: true
            }
        );
        assert!(u.total().capped);
        s.mark_read(&r, NOW + 2, NOW + 1_000_000);
        u.reconcile(&s);
        assert_eq!(u.count(&r), UnreadCount::default());
    }

    // -- retries --

    #[test]
    fn a_refused_batch_backs_off_and_gives_up_after_a_bound() {
        let delays: Vec<Option<u64>> = (0..8).map(retry_delay_ms).collect();
        assert_eq!(delays[0], Some(3_000));
        assert_eq!(delays[1], Some(6_000));
        assert_eq!(delays[2], Some(12_000));
        assert_eq!(delays[5], Some(60_000), "capped");
        assert_eq!(delays[6], None, "bounded: the next connection tries again");
        assert!(delays.iter().flatten().all(|d| *d <= 60_000));
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
            serde_json::json!({"kinds": [42], "#e": [id(0)], "since": 1000, "limit": 100})
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

    // -- clamps (future-dated posts) --

    #[test]
    fn markers_never_run_ahead_of_the_local_clock() {
        let mut s = Subs::default();
        s.subscribe(&id(1), &chan(1), "", NOW, NOW_MS).unwrap();
        // A post dated a week ahead must not mute the topic for a week.
        assert!(s.mark_read(&id(1), NOW + 604_800, NOW + 10));
        assert_eq!(s.read_at(&id(1)), Some(NOW + 10));
        // Loaded or synced markers are clamped too.
        let doc: SubsDoc = serde_json::from_value(serde_json::json!({"subs": [
            {"r": id(2), "c": chan(1), "on": true, "at": NOW_MS, "rd": NOW + 604_800}
        ]}))
        .unwrap();
        assert_eq!(Subs::from_doc(doc, NOW).read_at(&id(2)), Some(NOW));
        // And merging cannot carry a future marker in.
        let mut future = subs_of(&[entry(&id(3), true, NOW_MS)], &[]);
        future.read.insert(id(3), NOW + 604_800);
        let here = subs_of(&[entry(&id(3), true, NOW_MS)], &[(&id(3), NOW - 5)]);
        assert_eq!(here.join(&future, NOW).read_at(&id(3)), Some(NOW));
        assert_eq!(future.join(&here, NOW).read_at(&id(3)), Some(NOW));
    }

    #[test]
    fn a_new_subscription_starts_from_what_the_relay_has_not_the_clock() {
        // A fast local clock: now is an hour ahead of the topic's newest
        // reply; the marker starts at the reply, so the next post counts.
        assert_eq!(start_marker(Some(NOW - 3600), None, NOW), NOW - 3600);
        assert_eq!(
            start_marker(Some(NOW - 3600), Some(NOW - 60), NOW),
            NOW - 60
        );
        assert_eq!(start_marker(None, Some(NOW + 999), NOW), NOW, "clamped");
        assert_eq!(start_marker(None, None, NOW), NOW);
    }

    #[test]
    fn the_newest_held_reply_ignores_the_root_other_topics_and_the_future() {
        let mut lists: HashMap<String, Vec<NostrEvent>> = HashMap::new();
        let reply = |n: u32, root: &str, at: u64| NostrEvent {
            id: id(700 + n),
            pubkey: "bb".repeat(32),
            created_at: at,
            kind: 42,
            tags: vec![
                vec!["e".into(), chan(1), "".into(), "root".into()],
                vec!["e".into(), root.to_string(), "".into(), "reply".into()],
            ],
            content: String::new(),
            sig: String::new(),
        };
        lists.insert(
            chan(1),
            vec![
                root_event(&id(1), "Title"),
                reply(1, &id(1), NOW - 50),
                reply(2, &id(2), NOW - 10),
                reply(3, &id(1), NOW + 500),
            ],
        );
        let keys = [topic_key(&id(1)), chan(1)];
        assert_eq!(
            newest_held_reply(&lists, &keys, &id(1), NOW),
            Some(NOW - 50)
        );
        assert_eq!(newest_held_reply(&lists, &keys, &id(9), NOW), None);
    }

    // -- high-water mark --

    #[test]
    fn after_a_reconnect_the_backlog_asks_only_from_the_high_water_mark() {
        // First pass: just after the marker.
        assert_eq!(backlog_since(1_000, None), 1_001);
        // A previous answer delivered posts up to 5_000: ask from there,
        // less the backdating allowance, not from the marker again.
        assert_eq!(
            backlog_since(1_000, Some(5_000)),
            5_000 - BACKDATE_ALLOWANCE_SECS
        );
        assert_eq!(
            backlog_since(1_000, Some(1_100)),
            1_001,
            "never before the marker"
        );
        // A marker moved past the mark wins.
        assert_eq!(backlog_since(9_000, Some(5_000)), 9_001);
    }

    // -- dismissal, deletion, sealed posts --

    #[test]
    fn marking_read_dismisses_posts_dated_in_the_future_for_the_session() {
        let mut s = Subs::default();
        s.subscribe(&id(1), &chan(1), "", NOW, NOW_MS).unwrap();
        let r = id(1);
        let mut u = Unseen::default();
        u.note(&r, &id(100), NOW + 604_800, "bb");
        u.note(&r, &id(101), NOW + 5, "bb");
        s.mark_read(&r, NOW + 604_800, NOW + 10);
        u.reconcile(&s);
        // The marker is clamped, so reconcile alone keeps the future post…
        assert_eq!(u.count(&r).count, 1);
        // …but dismissing by what was shown removes it, and it stays gone.
        u.dismiss_upto(&r, NOW + 604_800);
        assert_eq!(u.count(&r).count, 0);
        assert!(!u.note(&r, &id(100), NOW + 604_800, "bb"));
        u.note(&r, &id(102), NOW + 20, "bb");
        u.dismiss_root(&r);
        assert_eq!(u.total().count, 0);
    }

    #[test]
    fn a_deleted_post_stops_counting() {
        let mut u = Unseen::default();
        let r = id(1);
        u.note(&r, &id(100), NOW + 1, "bb");
        u.note(&r, &id(101), NOW + 2, "bb");
        u.saturate(&r);
        let gone: HashSet<String> = [id(100)].into_iter().collect();
        u.remove_ids(&gone);
        assert_eq!(u.count(&r).count, 1);
        u.remove_ids(&[id(101)].into_iter().collect());
        assert_eq!(
            u.count(&r),
            UnreadCount::default(),
            "empty is not saturated"
        );
    }

    #[test]
    fn a_still_locked_sealed_post_is_not_counted_until_it_opens() {
        let mut s = Subs::default();
        s.subscribe(&id(1), &chan(1), "", NOW, NOW_MS).unwrap();
        let other = "bb".repeat(32);
        let mut locked = msg(Some(&id(1)), &other, NOW + 1, false, 1);
        locked.sealed_inner = Some(id(555));
        assert_eq!(unseen_root(&locked, &s, None), None);
        // Opened: counted under the original's id, once.
        let mut opened = msg(Some(&id(1)), &other, NOW + 1, false, 1);
        opened.id = id(555);
        assert_eq!(unseen_root(&opened, &s, None), Some(id(1).as_str()));
        let mut u = Unseen::default();
        assert!(u.note(&id(1), &opened.id, NOW + 1, &other));
        assert!(!u.note(&id(1), &opened.id, NOW + 1, &other));
        assert_eq!(u.count(&id(1)).count, 1);
    }

    #[test]
    fn tombstones_last_a_year() {
        let mut s = subs_of(
            &[
                entry(&id(1), false, NOW_MS - 200 * 24 * 3600 * 1000),
                entry(&id(2), false, NOW_MS - 400 * 24 * 3600 * 1000),
            ],
            &[],
        );
        s.prune(NOW_MS);
        assert!(s.entries.contains_key(&id(1)), "200 days: kept");
        assert!(!s.entries.contains_key(&id(2)), "400 days: dropped");
    }

    #[test]
    fn the_local_copy_round_trips_with_the_relay_record() {
        let mut s = Subs::default();
        s.subscribe(&id(1), &chan(1), "", NOW, NOW_MS).unwrap();
        let doc = LocalDoc {
            doc: s.to_doc(),
            remote: Some(RemoteSeen {
                id: id(9),
                created_at: 5,
                digest: "d".into(),
                entries_digest: "e".into(),
            }),
            published_ms: 7,
        };
        let json = serde_json::to_string(&doc).unwrap();
        let back: LocalDoc = serde_json::from_str(&json).unwrap();
        assert_eq!(back, doc);
        // The synced shape never carries the local record.
        let synced: SubsDoc = serde_json::from_str(&json).unwrap();
        assert!(!serde_json::to_string(&synced).unwrap().contains("remote"));
        // A copy stored before the record existed still loads.
        let old: LocalDoc =
            serde_json::from_str(&serde_json::to_string(&s.to_doc()).unwrap()).unwrap();
        assert_eq!(old.remote, None);
    }

    #[test]
    fn subscriptions_are_written_only_while_the_session_is_the_owners() {
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        assert!(persist_allowed(Some(&a), &a));
        assert!(persist_allowed(Some(&a.to_uppercase()), &a));
        assert!(!persist_allowed(None, &a), "signed out in another tab");
        assert!(!persist_allowed(Some(&b), &a), "another account signed in");
    }

    #[test]
    fn reading_a_thread_finds_the_held_replies_whose_notices_clear() {
        let reply = |n: u32, root: &str, at: u64| NostrEvent {
            id: id(900 + n).to_uppercase(),
            pubkey: "bb".repeat(32),
            created_at: at,
            kind: 42,
            tags: vec![
                vec!["e".into(), chan(1), "".into(), "root".into()],
                vec!["e".into(), root.to_string(), "".into(), "reply".into()],
            ],
            content: String::new(),
            sig: String::new(),
        };
        let mut lists: HashMap<String, Vec<NostrEvent>> = HashMap::new();
        lists.insert(
            topic_key(&id(1)),
            vec![
                reply(1, &id(1), 10),
                reply(2, &id(1), 30),
                reply(3, &id(2), 5),
            ],
        );
        let got = replies_upto(&lists, &topic_key(&id(1)), &id(1), 20);
        assert_eq!(
            got,
            vec![id(901)],
            "lower-cased, only this topic, only up to the mark"
        );
    }

    #[test]
    fn a_write_that_changes_nothing_does_not_wake_readers() {
        // The page freeze: the thread page's effect read the subscriptions
        // signal and called `mark_read`, which `update`d it unconditionally,
        // so the effect re-ran for ever. `write_if` notifies only on change.
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let owner = Owner::new();
        owner.with(|| {
            let mut subs = Subs::default();
            subs.subscribe(&id(1), &chan(1), "", NOW, NOW_MS).unwrap();
            let sig = RwSignal::new(subs);
            let runs = Arc::new(AtomicUsize::new(0));
            let counter = runs.clone();
            let reader = Memo::new(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                sig.with(|s| s.read_at(&id(1)))
            });
            assert_eq!(reader.get(), Some(NOW));
            assert_eq!(runs.load(Ordering::SeqCst), 1);
            // Marking read at or before the marker: nothing changes, nothing
            // is woken (as on every re-run of the viewing effect).
            assert!(!write_if(sig, |s| s.mark_read(&id(1), NOW, NOW + 10)));
            assert_eq!(reader.get(), Some(NOW));
            assert_eq!(runs.load(Ordering::SeqCst), 1, "no recompute: no loop");
            // A real move wakes it once.
            assert!(write_if(sig, |s| s.mark_read(&id(1), NOW + 5, NOW + 10)));
            assert_eq!(reader.get(), Some(NOW + 5));
            assert_eq!(runs.load(Ordering::SeqCst), 2);
            // And the next identical call is quiet again.
            assert!(!write_if(sig, |s| s.mark_read(&id(1), NOW + 5, NOW + 10)));
            assert_eq!(reader.get(), Some(NOW + 5));
            assert_eq!(runs.load(Ordering::SeqCst), 2);
        });
    }

    #[test]
    fn a_change_from_the_future_is_clamped_on_load() {
        let doc: SubsDoc = serde_json::from_value(serde_json::json!({"subs": [
            {"r": id(1), "c": chan(1), "on": true, "at": u64::MAX}
        ]}))
        .unwrap();
        let s = Subs::from_doc(doc, NOW);
        assert!(s.entries[&id(1)].at <= NOW * 1000 + 999);
        assert_eq!(
            next_at(Some(&entry(&id(1), true, u64::MAX)), NOW_MS),
            u64::MAX
        );
    }
}
