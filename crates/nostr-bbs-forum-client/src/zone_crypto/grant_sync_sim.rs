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
use super::grant_paging::{warm_marker, GrantScope, PagerAction, ScopePager};
use super::inbox_key::{open_for_sync, Opener};
use super::tickets::{route, Route};
use super::wrap_queue::WrapQueue;
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

/// Decides whether decrypt call `n` (with this sender pubkey) is denied.
type DenyFn = Box<dyn Fn(u64, &str) -> bool>;

/// A NIP-07 extension stand-in: the member's key behind a decrypt policy.
/// `deny(n, sender)` decides call `n` (from 0) with the outer or inner
/// sender pubkey; a denial is the same `DecryptionFailed` the real NIP-07
/// glue returns for a refused prompt.
struct Ext {
    key: PrfSigner,
    calls: Cell<u64>,
    deny: DenyFn,
}

impl Ext {
    fn new(key: PrfSigner, deny: impl Fn(u64, &str) -> bool + 'static) -> Self {
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
struct Outcome {
    keys: HashSet<(String, u32)>,
    backlog: GrantBacklog,
    end: PagerAction,
    markers: Vec<GrantScope>,
    pages: u32,
    /// Fake clock at the end (ms).
    now: f64,
}

/// One sign-in's grant sync for the identity scope, the way the store runs
/// it: wraps queued as pages deliver them, at most the queue's limit
/// running between deliveries, then the queue drained.
struct Session<'a> {
    signer: &'a dyn Signer,
    kind: SignerKind,
    events: &'a HashMap<String, NostrEvent>,
    admin: &'a dyn Fn(&str) -> Option<bool>,
    processed: &'a RefCell<HashSet<String>>,
    queue: WrapQueue<String>,
    backlog: GrantBacklog,
    seen: HashSet<String>,
    keys: HashSet<(String, u32)>,
    now: f64,
}

impl<'a> Session<'a> {
    fn new(
        signer: &'a dyn Signer,
        kind: SignerKind,
        events: &'a HashMap<String, NostrEvent>,
        admin: &'a dyn Fn(&str) -> Option<bool>,
        processed: &'a RefCell<HashSet<String>>,
    ) -> Self {
        let mut queue = WrapQueue::new();
        queue.set_signer(kind);
        Self {
            signer,
            kind,
            events,
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
    fn deliver(&mut self, id: &str) {
        if !self.seen.insert(id.to_string()) || self.processed.borrow().contains(id) {
            return;
        }
        self.backlog.wrap_started();
        self.queue.push(id.to_string());
    }

    /// Run up to `budget` queued wraps (`ZoneKeyStore::run_wrap`).
    fn run(&mut self, budget: usize) {
        for _ in 0..budget {
            let Some(started) = self.queue.start_next() else {
                return;
            };
            let id = started.job.clone();
            let outcome = self.process(&id, started.attempt);
            let now = self.tick();
            self.backlog.wrap_done(now, &id, outcome);
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
                WrapOutcome::Settled | WrapOutcome::Unreadable => {}
            }
        }
    }

    /// `ZoneKeyStore::process_wrap`, minus IndexedDB.
    fn process(&mut self, id: &str, attempt: Attempt) -> WrapOutcome {
        let ev = &self.events[id];
        let opened = block_on(open_for_sync(ev, None, self.signer, self.kind, attempt));
        let (sealer, rumor, opener) = match opened {
            Ok(v) => v,
            Err(outcome) => return outcome,
        };
        if opener == Opener::Identity && self.kind == SignerKind::CanRefuse {
            for _ in 0..self.queue.signer_succeeded() {
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

    fn sync(mut self, relay: &mut FakeRelay, marker: Option<u64>) -> Outcome {
        let mut pager = ScopePager::new();
        let mut until = None;
        let mut pages = 1;
        let end = loop {
            let page = pager.current_page().expect("pager running");
            for (id, ts) in relay.query(until) {
                let processed = self.processed.borrow().contains(&id);
                pager.observe(page, &id, ts, processed);
                self.deliver(&id);
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
            keys: self.keys,
            backlog: self.backlog,
            end,
            markers,
            pages,
            now: self.now,
        }
    }
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
    let o = Session::new(&member, SignerKind::Local, &events, &admin, &processed)
        .sync(&mut f.relay(), None);
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
    let o = Session::new(&ext, SignerKind::CanRefuse, &events, &admin, &processed)
        .sync(&mut f.relay(), None);
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
    let o = Session::new(&ext, SignerKind::CanRefuse, &events, &admin, &processed)
        .sync(&mut f.relay(), None);
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
    let o = Session::new(&ext, SignerKind::CanRefuse, &events, &admin, &processed)
        .sync(&mut f.relay(), None);
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
    let o = Session::new(&ext, SignerKind::CanRefuse, &events, &admin, &processed)
        .sync(&mut f.relay(), None);
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
    let o = Session::new(&ext, SignerKind::CanRefuse, &events, &admin, &processed)
        .sync(&mut f.relay(), None);
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
    let o = Session::new(&other, SignerKind::Local, &events, &admin, &processed)
        .sync(&mut f.relay(), None);
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
    let first = Session::new(&member, SignerKind::Local, &events, &down, &processed)
        .sync(&mut f.relay(), None);
    assert_eq!(first.end, PagerAction::Done { verified: true });
    assert!(first.keys.is_empty());
    assert_eq!(first.backlog.retrying(), GRANTS);
    assert!(!first.backlog.settled());
    assert!(first.markers.is_empty());
    assert_eq!(processed.borrow().len(), DMS, "DMs settled, grants left");

    let admin = all_admin(f);
    let second = Session::new(&member, SignerKind::Local, &events, &admin, &processed)
        .sync(&mut f.relay(), None);
    settled_with_every_key(&second, f);
    assert_eq!(second.pages, first.pages, "no marker: walked to the end");
}

/// A warm session after a clean backfill: the marker lets it stop early,
/// and a grant that arrived since (on top) is still found.
#[test]
fn a_warm_session_stops_early_and_still_finds_a_new_grant() {
    let f = fixture();
    let events = f.events();
    let processed = RefCell::new(HashSet::new());
    let member = f.member();
    let admin = all_admin(f);
    // Below the fixture, 3,000 older wraps an earlier session processed
    // (skipped before any decrypt, so they need no crypto here).
    let mut history = f.relay();
    let bottom = history.rows.last().unwrap().1;
    for i in 0..3_000u64 {
        let id = format!("old{i:05}");
        processed.borrow_mut().insert(id.clone());
        history.rows.push((id, bottom - 1 - i));
    }
    let cold = Session::new(&member, SignerKind::Local, &events, &admin, &processed)
        .sync(&mut history.clone(), None);
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
    let mut events = events.clone();
    events.insert(fresh.id.clone(), fresh.clone());
    let mut relay = history;
    relay.rows.insert(0, (fresh.id.clone(), marker - 3_600));
    let fresh_admin = admin_signer.public_key().to_string();
    let admin2 = move |pk: &str| Some(pk == fresh_admin);
    let warm = Session::new(&member, SignerKind::Local, &events, &admin2, &processed)
        .sync(&mut relay, Some(marker));
    assert_eq!(warm.keys, HashSet::from([("fresh".to_string(), 1)]));
    assert!(warm.backlog.settled());
    assert!(warm.pages < cold.pages, "{} < {}", warm.pages, cold.pages);
}
