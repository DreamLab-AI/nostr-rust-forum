//! End-to-end simulation of the grant sync's pure parts, with real NIP-59
//! crypto and mock signers.
//!
//! Drives exactly what `ZoneKeyStore` drives in the browser: a
//! [`ScopePager`] per page against a fake relay, a [`WrapQueue`] of wraps,
//! [`open_for_sync`] (the store's open-and-classify step) with a real
//! [`PrfSigner`] or a mock NIP-07 extension that denies decrypts on a
//! script, `validate_grant` with an injected admin check, and the
//! [`GrantBacklog`] verdict and backfill markers. What it does not cover is
//! the wasm glue itself: IndexedDB writes, `spawn_local` scheduling, relay
//! subscription plumbing and timers.
//!
//! The fake relay orders wraps by a timestamp the test assigns (NIP-59
//! randomises a real wrap's `created_at`, and the order is what is under
//! test here); the local-relay integration test covers the relay's own
//! ordering of real wraps.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use async_trait::async_trait;
use nostr_bbs_core::keys::{generate_keypair, Keypair, SecretKey};
use nostr_bbs_core::signer::{PrfSigner, Signer, SignerError};
use nostr_bbs_core::{NostrEvent, UnsignedEvent};

use super::grant_backlog::{Attempt, GrantBacklog, KeyPhase, SignerKind, WrapOutcome};
use super::grant_paging::tests::FakeRelay;
use super::grant_paging::{warm_marker, GrantScope, Marker, PagerAction, ScopePager};
use super::inbox_key::{open_for_sync, Opener};
use super::tickets::{route, Route};
use super::wrap_queue::{Slot, WrapQueue};
use super::{build_grant_wrap, generate_zone_key, validate_grant};

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    futures::executor::block_on(f)
}

/// Number of DMs and grants in the shared fixture.
const DMS: usize = 1_150;
const GRANTS: usize = 30;

/// Wraps addressed to one member: DMs from strangers and zone-key grants
/// sealed by an admin, built once (real crypto is slow in a debug build).
struct Fixture {
    member_secret: [u8; 32],
    admin_pk: String,
    /// `(id, wrap)`; the first `DMS` are DMs, the rest grants.
    wraps: Vec<(String, NostrEvent)>,
    /// The `(zone, epoch)` each grant carries.
    grant_keys: HashSet<(String, u32)>,
}

impl Fixture {
    fn member(&self) -> PrfSigner {
        let secret = SecretKey::from_bytes(self.member_secret).expect("member key");
        let public = secret.public_key();
        PrfSigner::new(Keypair { secret, public })
    }

    fn events(&self) -> HashMap<String, NostrEvent> {
        self.wraps.iter().cloned().collect()
    }

    /// A relay holding every wrap, ordered newest first by its position:
    /// DMs on top, grants oldest, so the grants sit on the last pages.
    fn relay(&self) -> FakeRelay {
        let top = 1_900_000_000;
        FakeRelay {
            rows: self
                .wraps
                .iter()
                .enumerate()
                .map(|(i, (id, _))| (id.clone(), top - i as u64))
                .collect(),
            ..FakeRelay::default()
        }
    }

    fn grant_ids(&self) -> Vec<String> {
        self.wraps[DMS..].iter().map(|(id, _)| id.clone()).collect()
    }
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let member_kp = generate_keypair().unwrap();
        let member_secret = *member_kp.secret.as_bytes();
        let member_pk = member_kp.public.to_hex();
        let admin = PrfSigner::new(generate_keypair().unwrap());
        let mut wraps = Vec::with_capacity(DMS + GRANTS);
        for i in 0..DMS {
            let stranger = generate_keypair().unwrap();
            let w = nostr_bbs_core::gift_wrap::gift_wrap(
                stranger.secret.as_bytes(),
                &stranger.public.to_hex(),
                &member_pk,
                &format!("dm {i}"),
            )
            .unwrap();
            wraps.push((w.id.clone(), w));
        }
        let mut grant_keys = HashSet::new();
        for i in 0..GRANTS {
            let zone = format!("zone{i}");
            let key = generate_zone_key(&zone, 1, admin.public_key(), 100).unwrap();
            let w = block_on(build_grant_wrap(&admin, &member_pk, &key, 100)).unwrap();
            grant_keys.insert((zone, 1));
            wraps.push((w.id.clone(), w));
        }
        Fixture {
            member_secret,
            admin_pk: admin.public_key().to_string(),
            wraps,
            grant_keys,
        }
    })
}

/// Where a session's pages come from: `until` (inclusive, none for page 0)
/// in, the page's wraps out with the timestamp the relay ordered them by.
pub(super) trait PageSource {
    fn page(&mut self, until: Option<u64>) -> Vec<(NostrEvent, u64)>;
}

/// A [`FakeRelay`] over real wraps.
struct SimRelay<'a> {
    relay: FakeRelay,
    events: &'a HashMap<String, NostrEvent>,
}

impl PageSource for SimRelay<'_> {
    fn page(&mut self, until: Option<u64>) -> Vec<(NostrEvent, u64)> {
        self.relay
            .query(until)
            .into_iter()
            .map(|(id, ts)| (self.events[&id].clone(), ts))
            .collect()
    }
}

/// Decides whether decrypt call `n` (with this sender pubkey) is denied.
type DenyFn = Box<dyn Fn(u64, &str) -> bool>;

/// A NIP-07 extension stand-in: the member's key behind a decrypt policy.
/// `deny(n, sender)` decides call `n` (from 0) with the outer or inner
/// sender pubkey; a denial is the same `DecryptionFailed` the real NIP-07
/// glue returns for a refused prompt.
pub(super) struct Ext {
    key: PrfSigner,
    pub(super) calls: Cell<u64>,
    deny: DenyFn,
}

impl Ext {
    pub(super) fn new(key: PrfSigner, deny: impl Fn(u64, &str) -> bool + 'static) -> Self {
        Self {
            key,
            calls: Cell::new(0),
            deny: Box::new(deny),
        }
    }
}

#[async_trait(?Send)]
impl Signer for Ext {
    fn public_key(&self) -> &str {
        self.key.public_key()
    }
    async fn sign_event(&self, u: UnsignedEvent) -> Result<NostrEvent, SignerError> {
        self.key.sign_event(u).await
    }
    async fn nip44_encrypt(&self, p: &str, t: &str) -> Result<String, SignerError> {
        self.key.nip44_encrypt(p, t).await
    }
    async fn nip44_decrypt(&self, p: &str, t: &str) -> Result<String, SignerError> {
        let n = self.calls.get();
        self.calls.set(n + 1);
        if (self.deny)(n, p) {
            return Err(SignerError::DecryptionFailed(
                "nip44.decrypt() rejected: User denied permission".into(),
            ));
        }
        self.key.nip44_decrypt(p, t).await
    }
    async fn nip04_encrypt(&self, p: &str, t: &str) -> Result<String, SignerError> {
        self.key.nip04_encrypt(p, t).await
    }
    async fn nip04_decrypt(&self, p: &str, t: &str) -> Result<String, SignerError> {
        self.key.nip04_decrypt(p, t).await
    }
    fn raw_key_bytes(&self) -> Option<[u8; 32]> {
        None
    }
}

/// What one simulated sign-in ended with.
#[derive(Debug)]
pub(super) struct Outcome {
    pub(super) keys: HashSet<(String, u32)>,
    pub(super) backlog: GrantBacklog,
    pub(super) end: PagerAction,
    pub(super) markers: Vec<GrantScope>,
    pub(super) pages: u32,
    /// The floor to store with the markers.
    pub(super) floor: Option<u64>,
    /// Distinct wraps delivered.
    pub(super) delivered: usize,
    /// Fake clock at the end (ms).
    pub(super) now: f64,
}

/// One sign-in's grant sync for the identity scope, the way the store runs
/// it: wraps queued as pages deliver them, at most the queue's limit
/// running between deliveries, then the queue drained.
pub(super) struct Session<'a> {
    signer: &'a dyn Signer,
    kind: SignerKind,
    events: HashMap<String, NostrEvent>,
    /// The timestamp the relay ordered each wrap by (its `created_at` on a
    /// real relay).
    ordered_at: HashMap<String, u64>,
    admin: &'a dyn Fn(&str) -> Option<bool>,
    processed: &'a RefCell<HashSet<String>>,
    queue: WrapQueue<String>,
    backlog: GrantBacklog,
    seen: HashSet<String>,
    keys: HashSet<(String, u32)>,
    now: f64,
}

impl<'a> Session<'a> {
    pub(super) fn new(
        signer: &'a dyn Signer,
        kind: SignerKind,
        admin: &'a dyn Fn(&str) -> Option<bool>,
        processed: &'a RefCell<HashSet<String>>,
    ) -> Self {
        let mut queue = WrapQueue::new();
        queue.set_signer(kind);
        Self {
            signer,
            kind,
            events: HashMap::new(),
            ordered_at: HashMap::new(),
            admin,
            processed,
            queue,
            backlog: GrantBacklog::new(false, 0.0),
            seen: HashSet::new(),
            keys: HashSet::new(),
            now: 0.0,
        }
    }

    fn tick(&mut self) -> f64 {
        self.now += 10.0;
        self.now
    }

    /// `ZoneKeyStore::wrap_handler`.
    fn deliver(&mut self, ev: NostrEvent, ts: u64) {
        let id = ev.id.clone();
        self.ordered_at.insert(id.clone(), ts);
        self.events.entry(id.clone()).or_insert(ev);
        if !self.seen.insert(id.clone()) || self.processed.borrow().contains(&id) {
            return;
        }
        self.backlog.wrap_started();
        self.queue.push(id);
    }

    /// Run up to `budget` queued wraps (`ZoneKeyStore::run_wrap`).
    fn run(&mut self, budget: usize) {
        for _ in 0..budget {
            let Some(started) = self.queue.start_next() else {
                return;
            };
            let id = started.job.clone();
            let outcome = self.process(&id, started.attempt, started.slot);
            let now = self.tick();
            let ts = self.ordered_at[&id];
            self.backlog.wrap_done(now, &id, ts, outcome);
            self.queue.release(started.slot);
            match outcome {
                WrapOutcome::Refused => {
                    if self.queue.park(id, started.successes_at_start) {
                        self.backlog.wrap_started();
                    }
                }
                WrapOutcome::Retry => {
                    self.seen.remove(&id);
                }
                WrapOutcome::Settled
                | WrapOutcome::Unreadable
                | WrapOutcome::UnreadableBySigner => {}
            }
        }
    }

    /// `ZoneKeyStore::process_wrap`, minus IndexedDB.
    fn process(&mut self, id: &str, attempt: Attempt, slot: Slot) -> WrapOutcome {
        let ev = self.events[id].clone();
        let opened = block_on(open_for_sync(&ev, None, self.signer, self.kind, attempt));
        let (sealer, rumor, opener) = match opened {
            Ok(v) => v,
            Err(outcome) => return outcome,
        };
        if opener == Opener::Identity && self.kind == SignerKind::CanRefuse {
            for _ in 0..self.queue.signer_succeeded(slot) {
                self.backlog.wrap_started();
            }
        }
        match route(rumor.kind, false) {
            Route::Grant => match (self.admin)(&sealer) {
                None => WrapOutcome::Retry,
                Some(is_admin) => {
                    if let Ok(key) = validate_grant(&rumor, &sealer, is_admin, 200) {
                        self.keys.insert((key.zone, key.epoch));
                    }
                    self.processed.borrow_mut().insert(id.to_string());
                    WrapOutcome::Settled
                }
            },
            Route::Ignore | Route::Ticket => {
                self.processed.borrow_mut().insert(id.to_string());
                WrapOutcome::Settled
            }
        }
    }

    pub(super) fn sync(mut self, relay: &mut dyn PageSource, marker: Option<Marker>) -> Outcome {
        let mut pager = ScopePager::new();
        let mut until = None;
        let mut pages = 1;
        let end = loop {
            let page = pager.current_page().expect("pager running");
            for (ev, ts) in relay.page(until) {
                let processed = self.processed.borrow().contains(&ev.id);
                pager.observe(page, &ev.id, ts, processed);
                self.deliver(ev, ts);
            }
            // Wraps open while the next page is in flight.
            self.run(25);
            let end = pager.eose(page, warm_marker(marker, false)).unwrap();
            match end.then {
                PagerAction::Fetch { until: u, .. } => {
                    until = Some(u);
                    pages += 1;
                }
                PagerAction::Done { verified } => {
                    let now = self.tick();
                    self.backlog
                        .scope_delivered(GrantScope::Identity, verified, now);
                    break end.then;
                }
                PagerAction::GiveUp => {
                    let now = self.tick();
                    self.backlog.paging_gave_up(now);
                    break end.then;
                }
            }
        };
        self.run(usize::MAX);
        let markers = self.backlog.take_due_markers();
        Outcome {
            floor: self.backlog.marker_floor(),
            delivered: self.events.len(),
            keys: self.keys,
            backlog: self.backlog,
            end,
            markers,
            pages,
            now: self.now,
        }
    }
}

fn sim(relay: FakeRelay, events: &HashMap<String, NostrEvent>) -> SimRelay<'_> {
    SimRelay { relay, events }
}

fn all_admin(f: &'static Fixture) -> impl Fn(&str) -> Option<bool> {
    move |pk: &str| Some(pk == f.admin_pk)
}

fn settled_with_every_key(o: &Outcome, f: &Fixture) {
    assert_eq!(o.end, PagerAction::Done { verified: true });
    assert_eq!(o.keys, f.grant_keys, "every grant's key arrived");
    assert!(o.backlog.settled());
    assert_eq!(o.backlog.phase(o.now + 1e9), KeyPhase::Settled);
    assert_eq!(o.markers, vec![GrantScope::Identity]);
}

/// A local key, 1,180 wraps (three pages), every grant past the first.
#[test]
fn a_local_key_settles_every_grant_past_the_first_page() {
    let f = fixture();
    let (events, admin) = (f.events(), all_admin(f));
    let processed = RefCell::new(HashSet::new());
    let member = f.member();
    let o = Session::new(&member, SignerKind::Local, &admin, &processed)
        .sync(&mut sim(f.relay(), &events), None);
    settled_with_every_key(&o, f);
    assert!(o.pages >= 3, "{} pages", o.pages);
}

/// Without paging (one REQ of 1,000), none of these grants would arrive.
#[test]
fn the_grants_lie_beyond_the_first_page() {
    let f = fixture();
    let first: HashSet<String> = f.relay().query(None).into_iter().map(|r| r.0).collect();
    assert!(f.grant_ids().iter().all(|g| !first.contains(g)));
}

/// NIP-07, origin trusted from the start: same result, with the queue at
/// one slot only until the first decrypt succeeds.
#[test]
fn a_cooperative_nip07_signer_settles_every_grant() {
    let f = fixture();
    let (events, admin) = (f.events(), all_admin(f));
    let processed = RefCell::new(HashSet::new());
    let ext = Ext::new(f.member(), |_, _| false);
    let o = Session::new(&ext, SignerKind::CanRefuse, &admin, &processed)
        .sync(&mut sim(f.relay(), &events), None);
    settled_with_every_key(&o, f);
    // Two decrypts per wrap (wrap layer, seal layer), nothing repeated.
    assert_eq!(ext.calls.get(), 2 * (DMS + GRANTS) as u64);
}

/// The user denies the first prompts (four refusals), then approves: the
/// refused wraps are parked, queued again after the first success, and
/// settle. Nothing is lost and the marker is written.
#[test]
fn denied_prompts_then_an_approval_recover_every_wrap() {
    let f = fixture();
    let (events, admin) = (f.events(), all_admin(f));
    let processed = RefCell::new(HashSet::new());
    let ext = Ext::new(f.member(), |n, _| n < 4);
    let o = Session::new(&ext, SignerKind::CanRefuse, &admin, &processed)
        .sync(&mut sim(f.relay(), &events), None);
    settled_with_every_key(&o, f);
    assert_eq!(o.backlog.retrying(), 0);
}

/// The extension locks mid-backlog (Podkey's unlock wait times out and every
/// decrypt in that window fails), then is unlocked: the wraps refused while
/// locked are retried after the next success and the backlog settles.
#[test]
fn an_extension_locked_mid_backlog_recovers_after_unlock() {
    let f = fixture();
    let (events, admin) = (f.events(), all_admin(f));
    let processed = RefCell::new(HashSet::new());
    let ext = Ext::new(f.member(), |n, _| (1_000..1_400).contains(&n));
    let o = Session::new(&ext, SignerKind::CanRefuse, &admin, &processed)
        .sync(&mut sim(f.relay(), &events), None);
    settled_with_every_key(&o, f);
}

/// Finding 1: one wrap the extension can never decrypt (junk addressed to
/// the member) is refused, retried once after the signer has worked, then
/// taken as unreadable. It no longer holds the backlog open and the marker
/// back for every session.
#[test]
fn a_junk_wrap_under_nip07_is_unreadable_after_one_retry() {
    let f = fixture();
    let (events, admin) = (f.events(), all_admin(f));
    let processed = RefCell::new(HashSet::new());
    let junk_sender = f.wraps[7].1.pubkey.clone();
    let ext = Ext::new(f.member(), move |_, sender| sender == junk_sender);
    let o = Session::new(&ext, SignerKind::CanRefuse, &admin, &processed)
        .sync(&mut sim(f.relay(), &events), None);
    settled_with_every_key(&o, f);
    assert!(!processed.borrow().contains(&f.wraps[7].0), "left unmarked");
    // Every other wrap: two decrypts. The junk wrap: two attempts at its
    // outer layer, one refused and one after the signer worked.
    assert_eq!(ext.calls.get(), 2 * (DMS + GRANTS - 1) as u64 + 2);
}

/// Every prompt denied: no key, the backlog never settles (the page shows
/// keys-timed-out, never "not found"), and no marker.
#[test]
fn every_prompt_denied_leaves_the_backlog_open_without_a_marker() {
    let f = fixture();
    let (events, admin) = (f.events(), all_admin(f));
    let processed = RefCell::new(HashSet::new());
    let ext = Ext::new(f.member(), |_, _| true);
    let o = Session::new(&ext, SignerKind::CanRefuse, &admin, &processed)
        .sync(&mut sim(f.relay(), &events), None);
    assert!(o.keys.is_empty());
    assert!(!o.backlog.settled());
    assert_eq!(o.backlog.phase(o.now + 30_000.0), KeyPhase::Stalled);
    assert!(o.markers.is_empty());
    // One slot until a success: every wrap was tried once, none twice.
    assert_eq!(ext.calls.get(), (DMS + GRANTS) as u64);
}

/// A local key whose decrypt fails is final at once (not refused).
#[test]
fn a_local_key_never_parks_a_wrap() {
    let f = fixture();
    let (events, admin) = (f.events(), all_admin(f));
    let processed = RefCell::new(HashSet::new());
    let other = PrfSigner::new(generate_keypair().unwrap());
    // Wraps are addressed to the member, not to `other`: not a key held
    // here, so nothing is even decrypted, and nothing is held.
    let o = Session::new(&other, SignerKind::Local, &admin, &processed)
        .sync(&mut sim(f.relay(), &events), None);
    assert!(o.keys.is_empty());
    assert!(o.backlog.settled());
}

/// A transient failure mid-backlog (the admin check unanswered for one
/// session): the backlog stays open and no marker is written; the next
/// session, with the check answering, walks the whole history again (no
/// marker, so no warm stop), skips every processed wrap, and settles.
#[test]
fn a_retry_mid_backlog_writes_no_marker_and_the_next_session_recovers() {
    let f = fixture();
    let events = f.events();
    let processed = RefCell::new(HashSet::new());
    let member = f.member();
    let down = |_: &str| None;
    let first = Session::new(&member, SignerKind::Local, &down, &processed)
        .sync(&mut sim(f.relay(), &events), None);
    assert_eq!(first.end, PagerAction::Done { verified: true });
    assert!(first.keys.is_empty());
    assert_eq!(first.backlog.retrying(), GRANTS);
    assert!(!first.backlog.settled());
    assert!(first.markers.is_empty());
    assert_eq!(processed.borrow().len(), DMS, "DMs settled, grants left");

    let admin = all_admin(f);
    let second = Session::new(&member, SignerKind::Local, &admin, &processed)
        .sync(&mut sim(f.relay(), &events), None);
    settled_with_every_key(&second, f);
    assert_eq!(second.pages, first.pages, "no marker: walked to the end");
}

/// A warm session after a clean backfill: the marker lets it stop early,
/// and a grant that arrived since (on top) is still found.
#[test]
fn a_warm_session_stops_early_and_still_finds_a_new_grant() {
    let f = fixture();
    let mut events = f.events();
    let processed = RefCell::new(HashSet::new());
    let member = f.member();
    let admin = all_admin(f);
    // Below the fixture, 3,000 older wraps an earlier session processed
    // (skipped before any decrypt, so placeholders stand in for them).
    let mut history = f.relay();
    let bottom = history.rows.last().unwrap().1;
    for i in 0..3_000u64 {
        let id = format!("old{i:05}");
        processed.borrow_mut().insert(id.clone());
        events.insert(
            id.clone(),
            NostrEvent {
                id: id.clone(),
                ..f.wraps[0].1.clone()
            },
        );
        history.rows.push((id, bottom - 1 - i));
    }
    let cold = Session::new(&member, SignerKind::Local, &admin, &processed)
        .sync(&mut sim(history.clone(), &events), None);
    settled_with_every_key(&cold, f);
    // The marker is written well after every stored wrap...
    let marker = 1_900_000_000 + super::grant_paging::WARM_STOP_MARGIN_SECS + 1;
    // ...then a new grant arrives, backdated by NIP-59 below the marker but
    // inside the margin, as the newest wrap.
    let admin_signer = PrfSigner::new(generate_keypair().unwrap());
    let key = generate_zone_key("fresh", 1, admin_signer.public_key(), 100).unwrap();
    let fresh = block_on(build_grant_wrap(
        &admin_signer,
        member.public_key(),
        &key,
        100,
    ))
    .unwrap();
    events.insert(fresh.id.clone(), fresh.clone());
    let mut relay = history;
    relay.rows.insert(0, (fresh.id.clone(), marker - 3_600));
    let fresh_admin = admin_signer.public_key().to_string();
    let admin2 = move |pk: &str| Some(pk == fresh_admin);
    let warm = Session::new(&member, SignerKind::Local, &admin2, &processed).sync(
        &mut sim(relay, &events),
        Some(Marker {
            done_at: marker,
            floor: cold.floor,
        }),
    );
    assert_eq!(warm.keys, HashSet::from([("fresh".to_string(), 1)]));
    assert!(warm.backlog.settled());
    assert!(warm.pages < cold.pages, "{} < {}", warm.pages, cold.pages);
}

/// Security review finding 2, across two sessions. Session 1: the extension
/// fails twice on one old grant (locked for both attempts, the second after
/// it had decrypted other wraps). The grant ends UnreadableBySigner, the
/// backlog settles and the marker is written, with the grant's timestamp as
/// its floor. Session 2 (warm, extension working): 3,000 processed wraps sit
/// above the fixture, a full processed page that would be a warm stop by
/// the marker's time alone; the floor keeps the walk going down to the
/// grant, which now opens.
#[test]
fn a_grant_refused_twice_is_reached_again_by_the_next_warm_session() {
    let f = fixture();
    let mut events = f.events();
    let processed = RefCell::new(HashSet::new());
    let admin = all_admin(f);
    let mut relay = f.relay();
    let top = relay.rows[0].1;
    // Newer than the fixture, already processed by an earlier session.
    for i in 0..3_000u64 {
        let id = format!("new{i:05}");
        processed.borrow_mut().insert(id.clone());
        events.insert(
            id.clone(),
            NostrEvent {
                id: id.clone(),
                ..f.wraps[0].1.clone()
            },
        );
        relay.rows.insert(0, (id, top + 1 + i));
    }
    let (grant_id, grant_wrap) = f.wraps[DMS + 5].clone();
    let grant_sender = grant_wrap.pubkey.clone();
    let locked_on_grant = Ext::new(f.member(), move |_, sender| sender == grant_sender);
    let first = Session::new(&locked_on_grant, SignerKind::CanRefuse, &admin, &processed)
        .sync(&mut sim(relay.clone(), &events), None);
    assert!(
        first.backlog.settled(),
        "a twice-refused wrap does not hold it"
    );
    assert_eq!(first.markers, vec![GrantScope::Identity]);
    let grant_ts = relay.rows.iter().find(|(id, _)| *id == grant_id).unwrap().1;
    assert_eq!(first.floor, Some(grant_ts), "the marker carries the floor");
    assert_eq!(first.keys.len(), GRANTS - 1);
    assert!(!processed.borrow().contains(&grant_id));

    let done_at = top + 3_000 + super::grant_paging::WARM_STOP_MARGIN_SECS + 10;
    let marker = Marker {
        done_at,
        floor: first.floor,
    };
    let working = Ext::new(f.member(), |_, _| false);
    let second = Session::new(&working, SignerKind::CanRefuse, &admin, &processed)
        .sync(&mut sim(relay.clone(), &events), Some(marker));
    assert_eq!(second.keys.len(), 1, "the refused grant is found");
    assert!(second.backlog.settled());
    assert_eq!(second.floor, None);

    // Control: the same warm session without the floor stops at the first
    // page and never reaches the grant.
    let no_floor = Marker {
        done_at,
        floor: None,
    };
    let control = Session::new(&working, SignerKind::CanRefuse, &admin, &processed)
        .sync(&mut sim(relay, &events), Some(no_floor));
    assert_eq!(control.pages, 1);
    assert!(control.keys.is_empty());
}

/// Security re-review finding A, across two sessions. A warm device last
/// completed a backfill at D0. A grant lands a day later, dated (as the
/// relay allows) five days before it landed, below 3,000 wraps an earlier
/// session processed. Thirty days on, session 1's page 0 query fails and
/// comes back empty (KF-31): it must not write a fresh marker. Session 2
/// then pages with the old marker and still reaches the grant. With a fresh
/// marker from session 1 the processed wraps would be a warm stop above it.
#[test]
fn a_failed_page_zero_writes_no_marker_and_a_late_grant_is_still_reached() {
    let day = 24 * 60 * 60;
    let d0: u64 = 1_900_000_000;
    let member = PrfSigner::new(generate_keypair().unwrap());
    let admin_signer = PrfSigner::new(generate_keypair().unwrap());
    let key = generate_zone_key("late", 1, admin_signer.public_key(), 100).unwrap();
    let grant = block_on(build_grant_wrap(
        &admin_signer,
        member.public_key(),
        &key,
        100,
    ))
    .unwrap();
    let processed = RefCell::new(HashSet::new());
    let mut events = HashMap::new();
    let mut relay = FakeRelay::default();
    // Processed wraps a day after D0, newest first.
    for i in 0..3_000u64 {
        let id = format!("seen{i:05}");
        processed.borrow_mut().insert(id.clone());
        events.insert(
            id.clone(),
            NostrEvent {
                id: id.clone(),
                ..grant.clone()
            },
        );
        relay.rows.push((id, d0 + day + 3_000 - i));
    }
    // The late grant, dated five days before it landed (D0 + 1 day).
    relay.rows.push((grant.id.clone(), d0 - 4 * day));
    events.insert(grant.id.clone(), grant.clone());
    let fresh_admin = admin_signer.public_key().to_string();
    let admin = move |pk: &str| Some(pk == fresh_admin);
    let old = Marker {
        done_at: d0,
        floor: None,
    };

    let mut failing = relay.clone();
    failing.fail_queries = [0].into_iter().collect();
    let first = Session::new(&member, SignerKind::Local, &admin, &processed)
        .sync(&mut sim(failing, &events), Some(old));
    assert_eq!(first.end, PagerAction::Done { verified: false });
    assert!(
        first.markers.is_empty(),
        "no fresh marker over an empty page 0"
    );

    // The device keeps the marker it had, or writes the one session 1 made.
    let session_1_time = d0 + 30 * day;
    let kept = if first.markers.is_empty() {
        old
    } else {
        Marker {
            done_at: session_1_time,
            floor: first.floor,
        }
    };
    let second = Session::new(&member, SignerKind::Local, &admin, &processed)
        .sync(&mut sim(relay.clone(), &events), Some(kept));
    assert_eq!(second.keys, HashSet::from([("late".to_string(), 1)]));
    assert!(second.backlog.settled());

    // Control: had session 1 written a marker at its own time, the warm
    // stop would halt on the processed wraps and miss the grant.
    let fresh = Marker {
        done_at: session_1_time,
        floor: None,
    };
    let control = Session::new(&member, SignerKind::Local, &admin, &processed)
        .sync(&mut sim(relay, &events), Some(fresh));
    assert!(control.keys.is_empty());
}
