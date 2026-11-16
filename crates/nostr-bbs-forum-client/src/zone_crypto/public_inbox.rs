//! The `public_inbox` opt-in (ADR-2027 decision 1), behind `RECIPIENT_KEYS_ENABLED`.
//!
//! With the opt-in on, the member's kind 10050 (DM relays) and kind 10002
//! (relay list) are published to the public Nostr indexers, so anyone on Nostr
//! can find where to send them a direct message. Turning it off publishes the
//! same two kinds with no relay for us in them: both kinds are replaceable, so
//! the newer event supersedes the old one on every indexer that accepts it. A
//! copy that was already taken stays taken, which the settings page says.
//!
//! Everything decided here is a plain function of its arguments (flag,
//! registration, sweep state), so the rules are tested natively; only the
//! IndexedDB and WebSocket plumbing at the bottom needs a browser.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::rc::Rc;
use std::task::{Poll, Waker};

use nostr_bbs_core::signer::Signer;
use nostr_bbs_core::{NostrEvent, UnsignedEvent};
use serde::{Deserialize, Serialize};

use super::inbox_key::{local_id, LocalInbox};

/// Public indexers that receive the member's 10050 and 10002. One edit here
/// changes where the opt-in publishes.
pub const INDEXERS: &[&str] = &[
    "wss://purplepag.es",
    "wss://indexer.coracle.social",
    "wss://relay.nos.social",
];

/// Kind of the NIP-17 DM relay list.
pub const KIND_DM_RELAYS: u64 = 10050;
/// Kind of the NIP-65 relay list.
pub const KIND_RELAY_LIST: u64 = 10002;

/// Seconds to wait for one indexer to answer.
const INDEXER_WAIT_MS: u32 = 8_000;

/// `zone_kv` id of the member's choice.
pub fn opt_in_id(owner: &str) -> String {
    format!("public_inbox:v1:{owner}")
}

/// `zone_kv` id of the `created_at` of the last indexer publication.
pub fn last_published_id(owner: &str) -> String {
    format!("public_inbox_ts:v1:{owner}")
}

/// `zone_kv` id of the "old-grant cleanup finished" flag.
pub fn cleanup_id(owner: &str) -> String {
    format!("grant_cleanup_finished:v1:{owner}")
}

// -- The toggle ----------------------------------------------------------------

/// Why the toggle cannot be used yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blocked {
    /// No registered inbox key on this device.
    NoInboxKey,
    /// The old-grant cleanup has not finished.
    CleanupPending,
}

impl Blocked {
    /// The line shown beside the disabled toggle.
    pub fn explanation(self) -> &'static str {
        match self {
            Self::NoInboxKey => {
                "Not available yet: this device has no registered inbox key. It is created \
                 the next time you sign in with private inboxes switched on."
            }
            Self::CleanupPending => {
                "Not available yet: your older zone-key messages are still being cleared \
                 from the relay. This finishes by itself the next time you are signed in."
            }
        }
    }
}

/// What the settings section shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToggleState {
    /// `RECIPIENT_KEYS_ENABLED` is off: nothing is rendered.
    Hidden,
    /// Rendered but disabled, for this reason.
    Disabled(Blocked),
    /// The member may switch it.
    Enabled,
}

/// The toggle's state. Turning the opt-in OFF is always allowed, so a member
/// whose key state later regresses can still retract; only switching ON needs
/// both preconditions.
pub fn toggle_state(
    flag_on: bool,
    opted_in: bool,
    inbox_registered: bool,
    cleanup_finished: bool,
) -> ToggleState {
    if !flag_on {
        return ToggleState::Hidden;
    }
    if opted_in {
        return ToggleState::Enabled;
    }
    if !inbox_registered {
        return ToggleState::Disabled(Blocked::NoInboxKey);
    }
    if !cleanup_finished {
        return ToggleState::Disabled(Blocked::CleanupPending);
    }
    ToggleState::Enabled
}

/// The cleanup flag as stored. With the sweep switched off the cleanup cannot
/// be trusted to have run, so it counts as NOT finished whatever is stored.
pub fn cleanup_finished_from(sweep_enabled: bool, stored: Option<&str>) -> bool {
    sweep_enabled && stored == Some("1")
}

// -- What goes to the indexers --------------------------------------------------

/// Publish or retract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Opt-in on: add our relay to the member's existing lists.
    Publish,
    /// Opt-in off: take our relay out of the member's existing lists.
    Retract,
}

/// One event to sign and send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    /// Event kind.
    pub kind: u64,
    /// Event tags.
    pub tags: Vec<Vec<String>>,
    /// `created_at`: strictly after the list this one replaces.
    pub created_at: u64,
}

/// The member's current lists as found on the indexers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Existing {
    /// Newest valid kind 10050, if any.
    pub dm: Option<NostrEvent>,
    /// Newest valid kind 10002, if any.
    pub list: Option<NostrEvent>,
}

impl PartialEq for Existing {
    /// Equal when both name the same events (ids commit to the content).
    fn eq(&self, other: &Self) -> bool {
        let id = |e: &Option<NostrEvent>| e.as_ref().map(|e| e.id.clone());
        id(&self.dm) == id(&other.dm) && id(&self.list) == id(&other.list)
    }
}

/// The newest valid event of `kind` authored by `author`: id and signature
/// verified, so a forged or foreign list is never merged into the member's own.
pub fn newest_valid<'a>(
    events: &'a [NostrEvent],
    author: &str,
    kind: u64,
) -> Option<&'a NostrEvent> {
    events
        .iter()
        .filter(|e| e.kind == kind && e.pubkey == author)
        .filter(|e| nostr_bbs_core::verify_event_strict(e).is_ok())
        .max_by_key(|e| e.created_at)
}

fn to_upstream(ev: &NostrEvent) -> Option<nostr::Event> {
    use nostr::JsonUtil;
    nostr::Event::from_json(serde_json::to_string(ev).ok()?).ok()
}

/// Relays named by a kind 10050, parsed by the `nostr` crate.
fn dm_relays(ev: Option<&NostrEvent>) -> Vec<nostr::RelayUrl> {
    ev.and_then(to_upstream)
        .map(|e| {
            nostr::nips::nip17::extract_relay_list(&e)
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// Relays named by a kind 10002 with their markers, parsed by the `nostr` crate.
fn list_relays(
    ev: Option<&NostrEvent>,
) -> Vec<(nostr::RelayUrl, Option<nostr::nips::nip65::RelayMetadata>)> {
    ev.and_then(to_upstream)
        .map(|e| {
            nostr::nips::nip65::extract_relay_list(&e)
                .map(|(u, m)| (u.clone(), *m))
                .collect()
        })
        .unwrap_or_default()
}

fn url_str(u: &nostr::RelayUrl) -> String {
    u.as_str_without_trailing_slash().to_string()
}

/// NIP-65 tags for `entries`, built by the `nostr` crate rather than by hand.
fn relay_list_tags(
    entries: Vec<(nostr::RelayUrl, Option<nostr::nips::nip65::RelayMetadata>)>,
) -> Vec<Vec<String>> {
    // Any key serves: only the tags are read back.
    let author = nostr::PublicKey::from_byte_array([1u8; 32]);
    let built = nostr::EventBuilder::relay_list(entries).build(author);
    built.tags.iter().map(|t| t.as_slice().to_vec()).collect()
}

/// The two events for `mode`, merged over what the member already has.
///
/// Publishing keeps every foreign relay and names ours (unmarked in the 10002,
/// so it is a read and a write relay). Retracting removes only ours, from both lists
/// entirely: even a write-only entry would keep naming this relay. The
/// empty-tag form appears only when nothing else is left.
pub fn plan(
    mode: Mode,
    relay_url: &str,
    existing: &Existing,
    keep: Option<&Existing>,
    now: u64,
    last_published: Option<u64>,
) -> Vec<Planned> {
    let ours = nostr::RelayUrl::parse(relay_url).ok();
    let is_ours = |u: &nostr::RelayUrl| ours.as_ref() == Some(u);

    let mut dm = dm_relays(existing.dm.as_ref());
    let mut list = list_relays(existing.list.as_ref());
    // "Keep them": the relays of the local baseline that the indexers no longer
    // show are carried over, before our own relay is added or removed.
    if let Some(k) = keep {
        for u in dm_relays(k.dm.as_ref()) {
            if !dm.contains(&u) {
                dm.push(u);
            }
        }
        for (u, m) in list_relays(k.list.as_ref()) {
            if !list.iter().any(|(x, _)| *x == u) {
                list.push((u, m));
            }
        }
    }
    match mode {
        Mode::Publish => {
            if let Some(o) = &ours {
                if !dm.iter().any(is_ours) {
                    dm.push(o.clone());
                }
                list.retain(|(u, _)| !is_ours(u));
                list.push((o.clone(), None));
            }
        }
        Mode::Retract => {
            dm.retain(|u| !is_ours(u));
            // Removed outright: any entry naming us, even write-only, keeps
            // membership of this board public.
            list.retain(|(u, _)| !is_ours(u));
        }
    }
    let stamp = |ev: &Option<NostrEvent>| {
        let prev = ev.as_ref().map(|e| e.created_at).max(last_published);
        next_created_at(now, prev)
    };
    vec![
        Planned {
            kind: KIND_DM_RELAYS,
            tags: dm
                .iter()
                .map(|u| vec!["relay".to_string(), url_str(u)])
                .collect(),
            created_at: stamp(&existing.dm),
        },
        Planned {
            kind: KIND_RELAY_LIST,
            tags: relay_list_tags(list),
            created_at: stamp(&existing.list),
        },
    ]
}

/// `created_at` for the next publication: strictly after the last one. Equal
/// timestamps resolve by event id under NIP-01, so a retraction made within the
/// same second as the publication could otherwise lose to it.
pub fn next_created_at(now: u64, last: Option<u64>) -> u64 {
    match last {
        Some(l) => now.max(l.saturating_add(1)),
        None => now,
    }
}

/// Somewhere to read from and send to. The live implementation opens a short
/// connection per call; tests record.
#[allow(async_fn_in_trait)]
pub trait IndexerSink {
    /// Send `events` to the relay at `url` over one connection; true when it
    /// answered OK true to every one.
    async fn send(&self, url: &str, events: &[NostrEvent]) -> bool;
    /// The member's 10050 and 10002 events held by the relay at `url`. `None`
    /// means it could not be read (timeout, refusal), which is not the same as
    /// holding nothing.
    async fn fetch(&self, url: &str, author: &str) -> Option<Vec<NostrEvent>>;
}

/// How a publication went.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// Indexers that accepted every event.
    pub accepted: Vec<String>,
    /// Indexers that refused or did not answer.
    pub failed: Vec<String>,
    /// The lists to keep as the local baseline: the ones just published if any
    /// indexer accepted them, otherwise the baseline that went in.
    pub baseline: Existing,
    /// Highest `created_at` signed in this publication (0 if none was).
    pub created_at: u64,
}

impl Report {
    /// Whether enough indexers accepted the lists for the change to count as
    /// published. Below this the change stays owed and is retried.
    pub fn quorum_met(&self) -> bool {
        self.accepted.len() >= MIN_ANSWERS
    }
}

/// How to treat a list that looks older than the one the member published
/// before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Stop and ask.
    Ask,
    /// Carry the relays of the local baseline over.
    KeepThem,
    /// Publish what the indexers show, dropping the difference.
    Anyway,
}

/// Why nothing was published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    /// Too few indexers answered to trust the current lists, so publishing
    /// could overwrite them. Retry later.
    Unreadable,
    /// The newest list found has fewer relays than one published before from
    /// this browser; publishing would remove `removed`. Needs a decision.
    Shrunk {
        /// Relays the publication would drop.
        removed: Vec<String>,
    },
    /// Signing failed.
    Sign(String),
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable => f.write_str("the indexers could not be read"),
            Self::Shrunk { removed } => write!(f, "this would remove {}", removed.join(", ")),
            Self::Sign(e) => write!(f, "signing failed: {e}"),
        }
    }
}

/// Indexers that must answer before their lists are trusted on their own.
const MIN_ANSWERS: usize = 2;

/// Relay URLs of an event's lists other than `ours`, normalised.
fn foreign_set(
    dm: Option<&NostrEvent>,
    list: Option<&NostrEvent>,
    ours: Option<&nostr::RelayUrl>,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let keep = |u: &nostr::RelayUrl| ours != Some(u);
    (
        dm_relays(dm)
            .iter()
            .filter(|u| keep(u))
            .map(url_str)
            .collect(),
        list_relays(list)
            .iter()
            .map(|(u, _)| u)
            .filter(|u| keep(u))
            .map(url_str)
            .collect(),
    )
}

/// Newest of two optional events by `created_at`.
fn newer(a: Option<NostrEvent>, b: Option<NostrEvent>) -> Option<NostrEvent> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if y.created_at > x.created_at { y } else { x }),
        (x, None) => x,
        (None, y) => y,
    }
}

/// Read the member's current lists from `indexers`, merge `mode` over the
/// newest of what they show and the local `baseline` (the newest lists this
/// browser has seen or published), sign once and send to every indexer.
///
/// Authorship is not freshness: a stale indexer can serve an old but validly
/// signed list. So nothing is published unless two indexers answered, or one
/// answered and agrees with the baseline; and if the newest list is missing
/// relays the baseline has, the caller must decide ([`Resolution`]).
#[allow(clippy::too_many_arguments)]
pub async fn publish_merged<S: IndexerSink>(
    sink: &S,
    signer: &dyn Signer,
    indexers: &[&str],
    mode: Mode,
    relay_url: &str,
    baseline: &Existing,
    resolution: Resolution,
    now: u64,
    last_published: Option<u64>,
) -> Result<Report, PublishError> {
    let owner = signer.public_key().to_string();
    let ours = nostr::RelayUrl::parse(relay_url).ok();
    let mut found: Vec<NostrEvent> = Vec::new();
    let mut answers = 0usize;
    for url in indexers {
        if let Some(events) = sink.fetch(url, &owner).await {
            answers += 1;
            found.extend(events);
        }
    }
    let seen = Existing {
        dm: newest_valid(&found, &owner, KIND_DM_RELAYS).cloned(),
        list: newest_valid(&found, &owner, KIND_RELAY_LIST).cloned(),
    };
    let has_baseline = baseline.dm.is_some() || baseline.list.is_some();
    let agrees = has_baseline
        && foreign_set(seen.dm.as_ref(), seen.list.as_ref(), ours.as_ref())
            == foreign_set(baseline.dm.as_ref(), baseline.list.as_ref(), ours.as_ref());
    if answers == 0 || (answers < MIN_ANSWERS && !agrees) {
        return Err(PublishError::Unreadable);
    }
    let existing = Existing {
        dm: newer(seen.dm, baseline.dm.clone()),
        list: newer(seen.list, baseline.list.clone()),
    };
    // Relays the baseline has that the newest list lacks.
    let (cand_dm, cand_list) =
        foreign_set(existing.dm.as_ref(), existing.list.as_ref(), ours.as_ref());
    let (base_dm, base_list) =
        foreign_set(baseline.dm.as_ref(), baseline.list.as_ref(), ours.as_ref());
    let removed: Vec<String> = base_dm
        .difference(&cand_dm)
        .chain(base_list.difference(&cand_list))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if !removed.is_empty() && resolution == Resolution::Ask {
        return Err(PublishError::Shrunk { removed });
    }
    let keep = (resolution == Resolution::KeepThem).then_some(baseline);
    let planned = plan(mode, relay_url, &existing, keep, now, last_published);
    let mut events = Vec::with_capacity(planned.len());
    for p in &planned {
        let unsigned = UnsignedEvent {
            pubkey: owner.clone(),
            created_at: p.created_at,
            kind: p.kind,
            tags: p.tags.clone(),
            content: String::new(),
        };
        events.push(
            signer
                .sign_event(unsigned)
                .await
                .map_err(|e| PublishError::Sign(e.to_string()))?,
        );
    }
    let mut report = Report {
        accepted: Vec::new(),
        failed: Vec::new(),
        baseline: baseline.clone(),
        created_at: events.iter().map(|e| e.created_at).max().unwrap_or(0),
    };
    for url in indexers {
        if sink.send(url, &events).await {
            report.accepted.push((*url).to_string());
        } else {
            report.failed.push((*url).to_string());
        }
    }
    // The baseline moves forward only once someone accepted the new lists.
    if !report.accepted.is_empty() {
        report.baseline = Existing {
            dm: events.iter().find(|e| e.kind == KIND_DM_RELAYS).cloned(),
            list: events.iter().find(|e| e.kind == KIND_RELAY_LIST).cloned(),
        };
    }
    Ok(report)
}

// -- Cleanup tracking -------------------------------------------------------------

/// Decides when the old-grant sweep has "nothing left to delete".
///
/// A subscription stream has no natural end, so the verdict is taken at the
/// stored-events marker (EOSE) once every wrap received so far has been
/// handled: finished if none of them was an identity-addressed grant that is
/// still waiting for its replacement key.
#[derive(Debug, Default)]
pub struct SweepTracker {
    in_flight: usize,
    eose: bool,
    left: bool,
    decided: bool,
}

impl SweepTracker {
    /// A wrap has started processing.
    pub fn started(&mut self) {
        self.in_flight += 1;
    }

    /// An identity-addressed grant was seen that the sweep did not delete.
    pub fn grant_left(&mut self) {
        self.left = true;
    }

    /// A wrap finished processing. `Some(verdict)` once the backlog is settled.
    pub fn done(&mut self) -> Option<bool> {
        self.in_flight = self.in_flight.saturating_sub(1);
        self.verdict()
    }

    /// The relay reported the end of stored events.
    pub fn eose(&mut self) -> Option<bool> {
        self.eose = true;
        self.verdict()
    }

    fn verdict(&mut self) -> Option<bool> {
        if self.decided || !self.eose || self.in_flight > 0 {
            return None;
        }
        self.decided = true;
        Some(!self.left)
    }
}

/// Whether one identity-addressed grant keeps the cleanup from being finished.
///
/// A grant the sweep deleted does not. A grant that was REFUSED (not from an
/// admin, stale) is never deleted by the sweep and never will be, so it must
/// not hold the cleanup open: anyone could otherwise wrap a fake grant to a
/// member and keep their toggle disabled for good. A valid grant whose
/// replacement key has not arrived yet does hold it open, and so does an admin
/// check that could not be answered, which may be temporary.
pub fn grant_blocks_cleanup(admin_known: bool, valid: bool, deleted: bool) -> bool {
    !admin_known || (valid && !deleted)
}

/// The value to store for a verdict: "finished" only if the sweep was on, so a
/// session that examined nothing cannot leave a stale "finished" behind.
pub fn finished_to_store(sweep_enabled: bool, verdict: bool) -> bool {
    sweep_enabled && verdict
}

thread_local! {
    static TRACKER: RefCell<SweepTracker> = RefCell::new(SweepTracker::default());
    static TOPPED_UP: Cell<bool> = const { Cell::new(false) };
}

/// Sweep hook: a wrap began processing.
pub fn sweep_wrap_started() {
    TRACKER.with(|t| t.borrow_mut().started());
}

/// Sweep hook: an identity-addressed grant remains undeleted.
pub fn sweep_grant_left(owner: &str) {
    TRACKER.with(|t| t.borrow_mut().grant_left());
    // A grant that is still waiting means cleanup is not finished, now.
    set_cleanup_finished(owner, false);
}

/// Sweep hook: a wrap finished processing.
pub fn sweep_wrap_done(owner: &str) {
    if let Some(v) = TRACKER.with(|t| t.borrow_mut().done()) {
        set_cleanup_finished(
            owner,
            finished_to_store(super::inbox_key::grant_sweep_enabled(), v),
        );
    }
}

/// Sweep hook: the grant subscription reached the end of stored events.
pub fn sweep_eose(owner: &str) {
    if let Some(v) = TRACKER.with(|t| t.borrow_mut().eose()) {
        set_cleanup_finished(
            owner,
            finished_to_store(super::inbox_key::grant_sweep_enabled(), v),
        );
    }
}

// -- Browser plumbing ---------------------------------------------------------------

async fn kv_get(id: &str) -> Option<String> {
    crate::stores::indexed_db::ForumDb::open()
        .await
        .ok()?
        .get_zone_kv(id)
        .await
        .ok()
        .flatten()
}

async fn kv_put(id: &str, value: &str) -> bool {
    match crate::stores::indexed_db::ForumDb::open().await {
        Ok(db) => db.put_zone_kv(id, value).await.is_ok(),
        Err(_) => false,
    }
}

/// Whether the old-grant cleanup has finished for `owner` (sweep on, flag set).
pub async fn cleanup_finished(owner: &str) -> bool {
    let stored = kv_get(&cleanup_id(owner)).await;
    cleanup_finished_from(super::inbox_key::grant_sweep_enabled(), stored.as_deref())
}

fn set_cleanup_finished(owner: &str, finished: bool) {
    let id = cleanup_id(owner);
    wasm_bindgen_futures::spawn_local(async move {
        kv_put(&id, if finished { "1" } else { "0" }).await;
    });
}

/// Whether `owner` has a registered inbox key on this device.
pub async fn inbox_registered(owner: &str) -> bool {
    kv_get(&local_id(owner))
        .await
        .and_then(|j| serde_json::from_str::<LocalInbox>(&j).ok())
        .is_some_and(|s| s.registered)
}

/// The member's stored choice; off when nothing is stored.
pub async fn opted_in(owner: &str) -> bool {
    kv_get(&opt_in_id(owner)).await.as_deref() == Some("1")
}

struct Slot<T> {
    value: RefCell<Option<T>>,
    waker: RefCell<Option<Waker>>,
}

impl<T> Slot<T> {
    fn fill(&self, v: T) {
        if self.value.borrow().is_none() {
            *self.value.borrow_mut() = Some(v);
            if let Some(w) = self.waker.borrow_mut().take() {
                w.wake();
            }
        }
    }
    async fn wait(&self) -> T {
        std::future::poll_fn(|cx| {
            if let Some(v) = self.value.borrow_mut().take() {
                return Poll::Ready(v);
            }
            *self.waker.borrow_mut() = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }
}

/// Short-lived WebSocket to one indexer: connect, send, wait for the OK,
/// close. It is deliberately not a [`crate::relay::RelayConnection`]: an
/// indexer never asks for NIP-42 AUTH, and the shared connection holds writes
/// back until AUTH completes, so they would never leave.
pub struct LiveSink;

impl IndexerSink for LiveSink {
    async fn fetch(&self, url: &str, author: &str) -> Option<Vec<NostrEvent>> {
        live_fetch(url, author).await
    }

    async fn send(&self, url: &str, events: &[NostrEvent]) -> bool {
        use wasm_bindgen::closure::Closure;
        use wasm_bindgen::JsCast;

        let Ok(ws) = web_sys::WebSocket::new(url) else {
            return false;
        };
        let slot: Rc<Slot<bool>> = Rc::new(Slot {
            value: RefCell::new(None),
            waker: RefCell::new(None),
        });
        let frames: Vec<String> = events
            .iter()
            .map(|e| serde_json::json!(["EVENT", e]).to_string())
            .collect();
        let pending: Rc<RefCell<std::collections::HashSet<String>>> =
            Rc::new(RefCell::new(events.iter().map(|e| e.id.clone()).collect()));

        let ws_open = ws.clone();
        let on_open = Closure::<dyn FnMut()>::new(move || {
            for f in &frames {
                let _ = ws_open.send_with_str(f);
            }
        });
        let done = slot.clone();
        let on_message =
            Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
                let Some(text) = e.data().as_string() else {
                    return;
                };
                let Ok(serde_json::Value::Array(a)) = serde_json::from_str(&text) else {
                    return;
                };
                if a.first().and_then(|v| v.as_str()) != Some("OK") {
                    return;
                }
                let Some(id) = a.get(1).and_then(|v| v.as_str()) else {
                    return;
                };
                if !pending.borrow().contains(id) {
                    return;
                }
                if a.get(2).and_then(|v| v.as_bool()) == Some(true) {
                    pending.borrow_mut().remove(id);
                    if pending.borrow().is_empty() {
                        done.fill(true);
                    }
                } else {
                    done.fill(false);
                }
            });
        let failed = slot.clone();
        let on_error = Closure::<dyn FnMut()>::new(move || failed.fill(false));
        let closed = slot.clone();
        let on_close = Closure::<dyn FnMut()>::new(move || closed.fill(false));
        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
        ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));
        ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));
        let late = slot.clone();
        let _timer =
            gloo::timers::callback::Timeout::new(INDEXER_WAIT_MS, move || late.fill(false));

        let ok = slot.wait().await;
        ws.set_onopen(None);
        ws.set_onmessage(None);
        ws.set_onerror(None);
        ws.set_onclose(None);
        let _ = ws.close();
        drop((on_open, on_message, on_error, on_close));
        ok
    }
}

/// Ask one indexer for the member's 10050 and 10002; `None` when it does not
/// finish (EOSE) within the wait.
pub(crate) async fn live_fetch(url: &str, author: &str) -> Option<Vec<NostrEvent>> {
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::JsCast;

    let ws = web_sys::WebSocket::new(url).ok()?;
    let slot: Rc<Slot<bool>> = Rc::new(Slot {
        value: RefCell::new(None),
        waker: RefCell::new(None),
    });
    let found: Rc<RefCell<Vec<NostrEvent>>> = Rc::default();
    let req = serde_json::json!([
        "REQ",
        "pubinbox",
        { "authors": [author], "kinds": [KIND_DM_RELAYS, KIND_RELAY_LIST] }
    ])
    .to_string();
    let ws_open = ws.clone();
    let on_open = Closure::<dyn FnMut()>::new(move || {
        let _ = ws_open.send_with_str(&req);
    });
    let (done, sink) = (slot.clone(), found.clone());
    let on_message =
        Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
            let Some(text) = e.data().as_string() else {
                return;
            };
            let Ok(serde_json::Value::Array(a)) = serde_json::from_str(&text) else {
                return;
            };
            match a.first().and_then(|v| v.as_str()) {
                Some("EVENT") => {
                    if let Some(ev) = a
                        .get(2)
                        .and_then(|v| serde_json::from_value::<NostrEvent>(v.clone()).ok())
                    {
                        sink.borrow_mut().push(ev);
                    }
                }
                Some("EOSE") => done.fill(true),
                _ => {}
            }
        });
    let failed = slot.clone();
    let on_error = Closure::<dyn FnMut()>::new(move || failed.fill(false));
    let closed = slot.clone();
    let on_close = Closure::<dyn FnMut()>::new(move || closed.fill(false));
    ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
    ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));
    ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));
    let late = slot.clone();
    let _timer = gloo::timers::callback::Timeout::new(INDEXER_WAIT_MS, move || late.fill(false));
    let finished = slot.wait().await;
    ws.set_onopen(None);
    ws.set_onmessage(None);
    ws.set_onerror(None);
    ws.set_onclose(None);
    let _ = ws.close();
    drop((on_open, on_message, on_error, on_close));
    let events = found.borrow().clone();
    finished.then_some(events)
}

fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// `zone_kv` id of the "a publication is still owed" flag.
pub fn pending_id(owner: &str) -> String {
    format!("public_inbox_pending:v1:{owner}")
}

/// Whether a publication or retraction is still owed after the indexers could
/// not be read.
pub async fn pending(owner: &str) -> bool {
    kv_get(&pending_id(owner)).await.as_deref() == Some("1")
}

/// `zone_kv` id of the local baseline (newest lists seen or published).
pub fn baseline_id(owner: &str) -> String {
    format!("public_inbox_baseline:v1:{owner}")
}

async fn publish_to_indexers(
    signer: &dyn Signer,
    mode: Mode,
    resolution: Resolution,
) -> Result<Report, PublishError> {
    let owner = signer.public_key().to_string();
    let last = kv_get(&last_published_id(&owner))
        .await
        .and_then(|s| s.parse::<u64>().ok());
    let relay_url = crate::utils::relay_url::relay_url();
    let baseline: Existing = kv_get(&baseline_id(&owner))
        .await
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default();
    let outcome = publish_merged(
        &LiveSink,
        signer,
        INDEXERS,
        mode,
        &relay_url,
        &baseline,
        resolution,
        now_secs(),
        last,
    )
    .await;
    match &outcome {
        Ok(report) => {
            if let Ok(json) = serde_json::to_string(&report.baseline) {
                kv_put(&baseline_id(&owner), &json).await;
            }
            // Still owed until a quorum of indexers took it, so a retraction
            // that reached nobody is retried rather than forgotten.
            kv_put(
                &pending_id(&owner),
                if report.quorum_met() { "0" } else { "1" },
            )
            .await;
            // Remember the stamp actually used: it can be ahead of the clock.
            kv_put(&last_published_id(&owner), &report.created_at.to_string()).await;
        }
        Err(PublishError::Unreadable | PublishError::Shrunk { .. }) => {
            kv_put(&pending_id(&owner), "1").await;
        }
        Err(PublishError::Sign(_)) => {}
    }
    outcome
}

/// Record the member's choice and publish (`on`) or retract (`!on`).
/// The choice is stored first, so a failed network round never loses it; when
/// the indexers cannot be read nothing is published and the work stays owed
/// ([`pending`]) until a later session retries.
pub async fn set_opt_in(
    signer: &dyn Signer,
    on: bool,
    resolution: Resolution,
) -> Result<Report, PublishError> {
    let owner = signer.public_key().to_string();
    if !kv_put(&opt_in_id(&owner), if on { "1" } else { "0" }).await {
        return Err(PublishError::Sign(
            "could not save your choice in this browser".into(),
        ));
    }
    publish_to_indexers(
        signer,
        if on { Mode::Publish } else { Mode::Retract },
        resolution,
    )
    .await
}

/// Top-up used after a DM send: publish to the indexers once per session if the
/// member has opted in, or retract if a retraction is still owed. Does nothing
/// with the flag off. Callers run it as its own task so a send never waits on
/// it.
pub async fn top_up_if_opted_in(signer: &dyn Signer) {
    if !super::inbox_key::recipient_keys_enabled() || TOPPED_UP.with(|c| c.replace(true)) {
        return;
    }
    let owner = signer.public_key().to_string();
    let want = opted_in(&owner).await;
    if !want && !pending(&owner).await {
        return;
    }
    let mode = if want { Mode::Publish } else { Mode::Retract };
    if let Err(e) = publish_to_indexers(signer, mode, Resolution::Ask).await {
        web_sys::console::warn_1(&format!("[public-inbox] indexer publish failed: {e}").into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone_crypto::inbox_key::inbox_signer;

    const SK: &str = "0000000000000000000000000000000000000000000000000000000000000003";
    const RELAY: &str = "wss://forum.example.org";

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        futures::executor::block_on(f)
    }

    #[derive(Default)]
    struct Recorder {
        sent: RefCell<Vec<(String, NostrEvent)>>,
        refuse: Option<&'static str>,
        /// What each indexer holds; an indexer absent from the map is unreadable.
        held: Vec<(&'static str, Vec<NostrEvent>)>,
        fetches: Cell<usize>,
    }

    impl IndexerSink for Recorder {
        async fn send(&self, url: &str, events: &[NostrEvent]) -> bool {
            for e in events {
                self.sent.borrow_mut().push((url.to_string(), e.clone()));
            }
            self.refuse != Some(url)
        }
        async fn fetch(&self, url: &str, _author: &str) -> Option<Vec<NostrEvent>> {
            self.fetches.set(self.fetches.get() + 1);
            self.held
                .iter()
                .find(|(u, _)| *u == url)
                .map(|(_, e)| e.clone())
        }
    }

    fn signed(kind: u64, tags: Vec<Vec<String>>, at: u64) -> NostrEvent {
        block_on(inbox_signer(SK).unwrap().sign_event(UnsignedEvent {
            pubkey: inbox_signer(SK).unwrap().public_key().to_string(),
            created_at: at,
            kind,
            tags,
            content: String::new(),
        }))
        .unwrap()
    }

    fn owner() -> String {
        inbox_signer(SK).unwrap().public_key().to_string()
    }

    fn relay_tag(u: &str) -> Vec<String> {
        vec!["relay".into(), u.into()]
    }

    fn r_tag(u: &str, marker: Option<&str>) -> Vec<String> {
        let mut t = vec!["r".to_string(), u.to_string()];
        if let Some(m) = marker {
            t.push(m.to_string());
        }
        t
    }

    fn held_everywhere(events: Vec<NostrEvent>) -> Vec<(&'static str, Vec<NostrEvent>)> {
        INDEXERS.iter().map(|u| (*u, events.clone())).collect()
    }

    fn run(rec: &Recorder, mode: Mode, now: u64) -> Result<Report, PublishError> {
        run_with(rec, mode, now, &Existing::default(), Resolution::Ask)
    }

    fn run_with(
        rec: &Recorder,
        mode: Mode,
        now: u64,
        baseline: &Existing,
        resolution: Resolution,
    ) -> Result<Report, PublishError> {
        block_on(publish_merged(
            rec,
            &inbox_signer(SK).unwrap(),
            INDEXERS,
            mode,
            RELAY,
            baseline,
            resolution,
            now,
            None,
        ))
    }

    fn lists(urls: &[&str], at: u64) -> Vec<NostrEvent> {
        vec![
            signed(
                KIND_DM_RELAYS,
                urls.iter().map(|u| relay_tag(u)).collect(),
                at,
            ),
            signed(
                KIND_RELAY_LIST,
                urls.iter().map(|u| r_tag(u, None)).collect(),
                at,
            ),
        ]
    }

    fn baseline_of(urls: &[&str], at: u64) -> Existing {
        let l = lists(urls, at);
        Existing {
            dm: Some(l[0].clone()),
            list: Some(l[1].clone()),
        }
    }

    const A: &str = "wss://a.example";
    const B: &str = "wss://b.example";

    fn sent_of(rec: &Recorder, url: &str, kind: u64) -> NostrEvent {
        rec.sent
            .borrow()
            .iter()
            .find(|(u, e)| u == url && e.kind == kind)
            .map(|(_, e)| e.clone())
            .expect("event sent")
    }

    #[test]
    fn the_indexer_list_names_the_three_public_indexers() {
        assert_eq!(
            INDEXERS,
            &[
                "wss://purplepag.es",
                "wss://indexer.coracle.social",
                "wss://relay.nos.social"
            ]
        );
    }

    #[test]
    fn flag_off_hides_the_section_whatever_the_state() {
        for opted in [false, true] {
            for reg in [false, true] {
                for clean in [false, true] {
                    assert_eq!(toggle_state(false, opted, reg, clean), ToggleState::Hidden);
                }
            }
        }
    }

    #[test]
    fn toggle_is_disabled_without_a_registered_inbox_key() {
        assert_eq!(
            toggle_state(true, false, false, true),
            ToggleState::Disabled(Blocked::NoInboxKey)
        );
        assert!(Blocked::NoInboxKey.explanation().contains("inbox key"));
    }

    #[test]
    fn toggle_is_disabled_while_cleanup_is_not_finished() {
        assert_eq!(
            toggle_state(true, false, true, false),
            ToggleState::Disabled(Blocked::CleanupPending)
        );
    }

    #[test]
    fn toggle_is_enabled_with_both_preconditions_and_may_always_be_turned_off() {
        assert_eq!(toggle_state(true, false, true, true), ToggleState::Enabled);
        assert_eq!(toggle_state(true, true, false, false), ToggleState::Enabled);
    }

    #[test]
    fn cleanup_counts_as_unfinished_when_the_sweep_is_off() {
        assert!(!cleanup_finished_from(false, Some("1")));
        assert!(!cleanup_finished_from(true, None));
        assert!(!cleanup_finished_from(true, Some("0")));
        assert!(cleanup_finished_from(true, Some("1")));
    }

    #[test]
    fn with_nothing_on_the_indexers_publishing_names_only_our_relay() {
        let rec = Recorder {
            held: held_everywhere(vec![]),
            ..Default::default()
        };
        let report = run(&rec, Mode::Publish, 100).unwrap();
        assert_eq!(report.accepted.len(), INDEXERS.len());
        for url in INDEXERS {
            let dm = sent_of(&rec, url, KIND_DM_RELAYS);
            assert_eq!(dm.tags, vec![relay_tag(RELAY)], "{url}");
            let list = sent_of(&rec, url, KIND_RELAY_LIST);
            assert_eq!(list.tags, vec![r_tag(RELAY, None)], "{url}");
        }
        assert_eq!(rec.sent.borrow().len(), INDEXERS.len() * 2);
    }

    #[test]
    fn merge_keeps_foreign_relays() {
        let rec = Recorder {
            held: held_everywhere(vec![
                signed(KIND_DM_RELAYS, vec![relay_tag("wss://other.example")], 50),
                signed(
                    KIND_RELAY_LIST,
                    vec![
                        r_tag("wss://other.example", None),
                        r_tag("wss://reader.example", Some("read")),
                    ],
                    50,
                ),
            ]),
            ..Default::default()
        };
        run(&rec, Mode::Publish, 100).unwrap();
        let dm = sent_of(&rec, INDEXERS[0], KIND_DM_RELAYS);
        let urls: Vec<&str> = dm.tags.iter().map(|t| t[1].as_str()).collect();
        assert_eq!(urls, ["wss://other.example", RELAY]);
        let list = sent_of(&rec, INDEXERS[0], KIND_RELAY_LIST);
        let has = |u: &str, m: Option<&str>| list.tags.contains(&r_tag(u, m));
        assert!(has("wss://other.example", None));
        assert!(has("wss://reader.example", Some("read")));
        assert!(has(RELAY, None));
    }

    #[test]
    fn retraction_removes_only_our_relay() {
        let rec = Recorder {
            held: held_everywhere(vec![
                signed(
                    KIND_DM_RELAYS,
                    vec![relay_tag("wss://other.example"), relay_tag(RELAY)],
                    50,
                ),
                signed(
                    KIND_RELAY_LIST,
                    vec![r_tag("wss://other.example", None), r_tag(RELAY, None)],
                    50,
                ),
            ]),
            ..Default::default()
        };
        run(&rec, Mode::Retract, 100).unwrap();
        let dm = sent_of(&rec, INDEXERS[1], KIND_DM_RELAYS);
        assert_eq!(dm.tags, vec![relay_tag("wss://other.example")]);
        let list = sent_of(&rec, INDEXERS[1], KIND_RELAY_LIST);
        assert!(list.tags.contains(&r_tag("wss://other.example", None)));
        // No entry of any marker names us.
        assert!(list.tags.iter().all(|t| !t[1].starts_with(RELAY)));
    }

    #[test]
    fn retraction_drops_a_read_marked_entry_and_empties_only_when_nothing_is_left() {
        let rec = Recorder {
            held: held_everywhere(vec![
                signed(KIND_DM_RELAYS, vec![relay_tag(RELAY)], 50),
                signed(KIND_RELAY_LIST, vec![r_tag(RELAY, Some("read"))], 50),
            ]),
            ..Default::default()
        };
        run(&rec, Mode::Retract, 100).unwrap();
        assert!(sent_of(&rec, INDEXERS[0], KIND_DM_RELAYS).tags.is_empty());
        assert!(sent_of(&rec, INDEXERS[0], KIND_RELAY_LIST).tags.is_empty());
    }

    #[test]
    fn unreadable_indexers_publish_nothing() {
        let rec = Recorder::default();
        assert_eq!(run(&rec, Mode::Publish, 100), Err(PublishError::Unreadable));
        assert_eq!(run(&rec, Mode::Retract, 100), Err(PublishError::Unreadable));
        assert!(rec.sent.borrow().is_empty());
        assert_eq!(rec.fetches.get(), INDEXERS.len() * 2);
    }

    #[test]
    fn a_single_answer_without_a_baseline_is_not_enough() {
        let rec = Recorder {
            held: vec![(INDEXERS[2], vec![])],
            ..Default::default()
        };
        assert_eq!(run(&rec, Mode::Publish, 100), Err(PublishError::Unreadable));
        assert!(rec.sent.borrow().is_empty());
    }

    #[test]
    fn two_fresh_indexers_agreeing_publish_to_all_three() {
        let rec = Recorder {
            held: vec![
                (INDEXERS[0], lists(&[A], 50)),
                (INDEXERS[1], lists(&[A], 50)),
            ],
            ..Default::default()
        };
        let report = run(&rec, Mode::Publish, 100).unwrap();
        assert_eq!(report.accepted.len(), INDEXERS.len());
    }

    #[test]
    fn a_single_answer_that_agrees_with_the_baseline_is_enough() {
        let rec = Recorder {
            held: vec![(INDEXERS[0], lists(&[A, B], 200))],
            ..Default::default()
        };
        let base = baseline_of(&[A, B], 200);
        assert!(run_with(&rec, Mode::Publish, 300, &base, Resolution::Ask).is_ok());
    }

    #[test]
    fn a_single_stale_answer_cannot_shrink_the_list_the_baseline_remembers() {
        // The only responder serves the old list A; the baseline knows A+B.
        let rec = Recorder {
            held: vec![(INDEXERS[0], lists(&[A], 100))],
            ..Default::default()
        };
        let base = baseline_of(&[A, B], 200);
        assert_eq!(
            run_with(&rec, Mode::Publish, 300, &base, Resolution::Ask),
            Err(PublishError::Unreadable)
        );
        assert!(rec.sent.borrow().is_empty());
    }

    #[test]
    fn an_older_list_on_the_indexers_never_wins_over_the_baseline() {
        let rec = Recorder {
            held: held_everywhere(lists(&[A], 100)),
            ..Default::default()
        };
        let base = baseline_of(&[A, B], 200);
        run_with(&rec, Mode::Publish, 300, &base, Resolution::Ask).unwrap();
        let dm = sent_of(&rec, INDEXERS[0], KIND_DM_RELAYS);
        let urls: Vec<&str> = dm.tags.iter().map(|t| t[1].as_str()).collect();
        assert_eq!(urls, [A, B, RELAY]);
        assert_eq!(dm.created_at, 300);
    }

    #[test]
    fn a_newer_but_shrunk_list_prompts_and_publishes_nothing() {
        let rec = Recorder {
            held: held_everywhere(lists(&[A], 300)),
            ..Default::default()
        };
        let base = baseline_of(&[A, B], 200);
        let r = run_with(&rec, Mode::Publish, 400, &base, Resolution::Ask);
        assert_eq!(
            r,
            Err(PublishError::Shrunk {
                removed: vec![B.to_string()]
            })
        );
        assert!(rec.sent.borrow().is_empty());
    }

    #[test]
    fn retraction_honours_the_same_rule() {
        let rec = Recorder {
            held: held_everywhere(lists(&[A, RELAY], 300)),
            ..Default::default()
        };
        let base = baseline_of(&[A, B, RELAY], 200);
        let r = run_with(&rec, Mode::Retract, 400, &base, Resolution::Ask);
        assert!(matches!(r, Err(PublishError::Shrunk { .. })));
        assert!(rec.sent.borrow().is_empty());
    }

    #[test]
    fn keep_them_unions_the_baseline_and_publish_anyway_drops_it() {
        let rec = Recorder {
            held: held_everywhere(lists(&[A], 300)),
            ..Default::default()
        };
        let base = baseline_of(&[A, B], 200);
        run_with(&rec, Mode::Publish, 400, &base, Resolution::KeepThem).unwrap();
        let kept = sent_of(&rec, INDEXERS[0], KIND_DM_RELAYS);
        assert!(kept.tags.contains(&relay_tag(B)));

        let rec = Recorder {
            held: held_everywhere(lists(&[A], 300)),
            ..Default::default()
        };
        run_with(&rec, Mode::Publish, 400, &base, Resolution::Anyway).unwrap();
        let dropped = sent_of(&rec, INDEXERS[0], KIND_DM_RELAYS);
        assert!(!dropped.tags.contains(&relay_tag(B)));
    }

    #[test]
    fn keep_them_on_retraction_still_removes_our_relay() {
        let rec = Recorder {
            held: held_everywhere(lists(&[A], 300)),
            ..Default::default()
        };
        let base = baseline_of(&[A, B, RELAY], 200);
        run_with(&rec, Mode::Retract, 400, &base, Resolution::KeepThem).unwrap();
        let dm = sent_of(&rec, INDEXERS[0], KIND_DM_RELAYS);
        assert!(dm.tags.contains(&relay_tag(B)));
        assert!(!dm.tags.contains(&relay_tag(RELAY)));
    }

    #[test]
    fn the_baseline_is_updated_after_a_publish_and_kept_when_nobody_accepts() {
        let rec = Recorder {
            held: held_everywhere(lists(&[A], 50)),
            ..Default::default()
        };
        let report = run(&rec, Mode::Publish, 100).unwrap();
        let sent = sent_of(&rec, INDEXERS[0], KIND_DM_RELAYS);
        assert_eq!(report.baseline.dm.as_ref().map(|e| &e.id), Some(&sent.id));

        struct Refuse(Recorder);
        impl IndexerSink for Refuse {
            async fn send(&self, _: &str, _: &[NostrEvent]) -> bool {
                false
            }
            async fn fetch(&self, u: &str, a: &str) -> Option<Vec<NostrEvent>> {
                self.0.fetch(u, a).await
            }
        }
        let refuse = Refuse(Recorder {
            held: held_everywhere(lists(&[A], 50)),
            ..Default::default()
        });
        let base = baseline_of(&[A], 10);
        let r = block_on(publish_merged(
            &refuse,
            &inbox_signer(SK).unwrap(),
            INDEXERS,
            Mode::Publish,
            RELAY,
            &base,
            Resolution::Ask,
            100,
            None,
        ))
        .unwrap();
        assert_eq!(r.baseline, base);
    }

    #[test]
    fn the_newest_valid_list_wins_and_forged_or_foreign_ones_are_ignored() {
        let old = signed(KIND_DM_RELAYS, vec![relay_tag("wss://old.example")], 10);
        let new = signed(KIND_DM_RELAYS, vec![relay_tag("wss://new.example")], 20);
        let mut forged = signed(KIND_DM_RELAYS, vec![relay_tag("wss://evil.example")], 30);
        forged.sig = old.sig.clone();
        let mut foreign = signed(
            KIND_DM_RELAYS,
            vec![relay_tag("wss://not-mine.example")],
            40,
        );
        foreign.pubkey = "f".repeat(64);
        let all = vec![old, new.clone(), forged, foreign];
        assert_eq!(
            newest_valid(&all, &owner(), KIND_DM_RELAYS).map(|e| e.id.as_str()),
            Some(new.id.as_str())
        );
    }

    #[test]
    fn retracting_a_write_only_entry_removes_it_too() {
        let rec = Recorder {
            held: held_everywhere(vec![
                signed(KIND_DM_RELAYS, vec![relay_tag(A)], 50),
                signed(
                    KIND_RELAY_LIST,
                    vec![r_tag(A, None), r_tag(RELAY, Some("write"))],
                    50,
                ),
            ]),
            ..Default::default()
        };
        run(&rec, Mode::Retract, 100).unwrap();
        let list = sent_of(&rec, INDEXERS[0], KIND_RELAY_LIST);
        assert_eq!(list.tags, vec![r_tag(A, None)]);
    }

    #[test]
    fn a_publication_nobody_accepted_is_still_owed() {
        let none = Report {
            accepted: vec![],
            failed: INDEXERS.iter().map(|s| s.to_string()).collect(),
            baseline: Existing::default(),
            created_at: 0,
        };
        assert!(!none.quorum_met());
        let one = Report {
            accepted: vec![INDEXERS[0].to_string()],
            ..none.clone()
        };
        assert!(!one.quorum_met());
        let two = Report {
            accepted: vec![INDEXERS[0].to_string(), INDEXERS[1].to_string()],
            ..none
        };
        assert!(two.quorum_met());
    }

    #[test]
    fn the_report_carries_the_stamp_actually_used() {
        let rec = Recorder {
            held: held_everywhere(vec![signed(KIND_DM_RELAYS, vec![], 500)]),
            ..Default::default()
        };
        let r = run(&rec, Mode::Retract, 100).unwrap();
        assert_eq!(r.created_at, 501, "ahead of the clock, and remembered");
    }

    #[test]
    fn stamps_are_strictly_after_what_they_replace() {
        let rec = Recorder {
            held: held_everywhere(vec![signed(KIND_DM_RELAYS, vec![], 500)]),
            ..Default::default()
        };
        run(&rec, Mode::Publish, 100).unwrap();
        assert_eq!(sent_of(&rec, INDEXERS[0], KIND_DM_RELAYS).created_at, 501);
        assert_eq!(sent_of(&rec, INDEXERS[0], KIND_RELAY_LIST).created_at, 100);
    }

    #[test]
    fn an_indexer_that_refuses_is_reported_not_hidden() {
        let rec = Recorder {
            held: held_everywhere(vec![]),
            refuse: Some("wss://relay.nos.social"),
            ..Default::default()
        };
        let r = run(&rec, Mode::Publish, 1).unwrap();
        assert_eq!(r.failed, vec!["wss://relay.nos.social".to_string()]);
        assert_eq!(r.accepted.len(), 2);
    }

    #[test]
    fn a_retraction_in_the_same_second_still_supersedes_the_publication() {
        let first = next_created_at(500, None);
        let second = next_created_at(500, Some(first));
        assert_eq!(first, 500);
        assert!(second > first);
        assert_eq!(next_created_at(900, Some(500)), 900);
    }

    #[test]
    fn cleanup_is_finished_only_after_eose_and_every_wrap_settled() {
        let mut t = SweepTracker::default();
        t.started();
        t.started();
        assert_eq!(t.eose(), None);
        assert_eq!(t.done(), None);
        assert_eq!(t.done(), Some(true));
    }

    #[test]
    fn cleanup_is_not_finished_while_an_identity_grant_remains() {
        let mut t = SweepTracker::default();
        t.started();
        t.grant_left();
        assert_eq!(t.eose(), None);
        assert_eq!(t.done(), Some(false));
    }

    #[test]
    fn a_refused_grant_does_not_hold_cleanup_open() {
        assert!(!grant_blocks_cleanup(true, false, false));
    }

    #[test]
    fn a_valid_grant_still_waiting_for_its_replacement_holds_it_open() {
        assert!(grant_blocks_cleanup(true, true, false));
    }

    #[test]
    fn an_unanswered_admin_check_holds_it_open() {
        assert!(grant_blocks_cleanup(false, false, false));
    }

    #[test]
    fn a_deleted_grant_does_not_hold_it_open() {
        assert!(!grant_blocks_cleanup(true, true, true));
    }

    #[test]
    fn a_session_with_the_sweep_off_never_stores_finished() {
        assert!(!finished_to_store(false, true));
        assert!(finished_to_store(true, true));
        assert!(!finished_to_store(true, false));
    }

    #[test]
    fn an_empty_inbox_finishes_cleanup_at_eose() {
        let mut t = SweepTracker::default();
        assert_eq!(t.eose(), Some(true));
    }
}
