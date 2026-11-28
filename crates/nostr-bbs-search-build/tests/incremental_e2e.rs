//! The nightly job end to end, against relay-shaped synthetic events: an
//! archivist builds the base from the relay (imported posts as ADR-2017
//! sealed envelopes, plus posts written in the forum), then a different
//! identity, the indexer, runs updates and compactions that reference the
//! archivist's objects, and a simulated browser verifies and searches every
//! manifest. No network, no real text: a deterministic stand-in embedder.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use nostr_bbs_core::keys::{signing_key_from_bytes, SecretKey};
use nostr_bbs_core::sealed::seal_original;
use nostr_bbs_core::{sign_event, NostrEvent, UnsignedEvent};
use nostr_bbs_sealed_search::build::q_partner;
use nostr_bbs_sealed_search::format::Kind;
use nostr_bbs_sealed_search::manifest::{HighWater, Manifest, KIND};
use nostr_bbs_sealed_search::seal::SearchKey;
use nostr_bbs_sealed_search::search::{Fetched, Index};
use nostr_bbs_sealed_search::DIM;
use nostr_bbs_search_build::embed::Embedder;
use nostr_bbs_search_build::harvest::harvest;
use nostr_bbs_search_build::memrelay::MemRelay;
use nostr_bbs_search_build::pipeline::{
    run_compact, run_full, run_update, status, Fold, Format, Job, JobError, Pins, Report,
    DEFAULT_OVERLAP_SECS,
};
use nostr_bbs_search_build::pod::DirPod;
use nostr_bbs_search_build::state::State;
use nostr_bbs_zone_migrate::keys::{KeyRing, KeySource, ZoneKey};
use sha2::{Digest, Sha256};

const ZONE: &str = "zone2";
const RELAY: &str = "wss://relay.test";
const CHANNEL: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const ARCHIVIST: [u8; 32] = [0xa1; 32];
const INDEXER: [u8; 32] = [0xa2; 32];
const STRANGER: [u8; 32] = [0xa3; 32];
const MIGRATOR: [u8; 32] = [0xb1; 32];
const ALICE: [u8; 32] = [0xc1; 32];
const BOB: [u8; 32] = [0xc2; 32];
const ZONE_E1: [u8; 32] = [0xd1; 32];
const ZONE_E2: [u8; 32] = [0xd2; 32];
const T0: u64 = 1_700_000_000;
const SHARD_ROWS: usize = 40;

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

fn sk(b: [u8; 32]) -> SecretKey {
    SecretKey::from_bytes(b).expect("test key")
}

fn pk(b: [u8; 32]) -> String {
    sk(b).public_key().to_hex()
}

fn sign(
    secret: [u8; 32],
    kind: u64,
    created_at: u64,
    tags: Vec<Vec<String>>,
    content: &str,
) -> NostrEvent {
    sign_event(
        UnsignedEvent {
            pubkey: pk(secret),
            created_at,
            kind,
            tags,
            content: content.into(),
        },
        &signing_key_from_bytes(&secret).expect("signing key"),
    )
    .expect("signed")
}

fn t(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

fn zk(epoch: u32, zone_secret: [u8; 32]) -> Vec<String> {
    t(&["zk", ZONE, &epoch.to_string(), &pk(zone_secret)])
}

/// A post written in the forum: NIP-44 from the author to the zone key.
fn native(author: [u8; 32], at: u64, text: &str, extra: Vec<Vec<String>>) -> NostrEvent {
    native_under(author, at, text, extra, 1, ZONE_E1)
}

fn native_under(
    author: [u8; 32],
    at: u64,
    text: &str,
    extra: Vec<Vec<String>>,
    epoch: u32,
    zone_secret: [u8; 32],
) -> NostrEvent {
    let zpk: [u8; 32] = hex::decode(pk(zone_secret)).unwrap().try_into().unwrap();
    let ct = nostr_bbs_core::nip44_encrypt(&author, &zpk, text).expect("nip44");
    let mut tags = vec![t(&["e", CHANNEL, "", "root"])];
    tags.extend(extra);
    tags.push(zk(epoch, zone_secret));
    sign(author, 42, at, tags, &ct)
}

/// An imported post: `(original, envelope)`. Only the envelope is on the relay.
fn imported(author: [u8; 32], at: u64, text: &str) -> (NostrEvent, NostrEvent) {
    let original = sign(author, 42, at, vec![t(&["e", CHANNEL, "", "root"])], text);
    let env = seal_original(&original, ZONE, 1, &pk(ZONE_E1), &sk(MIGRATOR)).expect("sealed");
    (original, env)
}

fn edit_of(target: &str) -> Vec<Vec<String>> {
    vec![t(&["e", target, "", "edit"])]
}

fn kind5(author: [u8; 32], at: u64, target: &str) -> NostrEvent {
    sign(author, 5, at, vec![t(&["e", target])], "")
}

/// Deterministic unit vectors from text: the same text always embeds the same.
struct HashEmbedder {
    calls: usize,
}

fn vector(text: &str) -> [f32; DIM] {
    let seed = Sha256::digest(text.as_bytes());
    let mut x = u64::from_le_bytes(seed[..8].try_into().unwrap()) | 1;
    let mut v = [0f32; DIM];
    for s in v.iter_mut() {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *s = ((x >> 33) as f32 / (1u64 << 31) as f32) - 0.5;
    }
    let n = v.iter().map(|a| a * a).sum::<f32>().sqrt();
    v.iter_mut().for_each(|a| *a /= n);
    v
}

impl Embedder for HashEmbedder {
    fn embed(&mut self, texts: &[&str]) -> Result<Vec<[f32; DIM]>, String> {
        self.calls += texts.len();
        Ok(texts.iter().map(|t| vector(t)).collect())
    }
}

fn ring(epochs: &[(u32, [u8; 32])]) -> KeyRing {
    let mut r = KeyRing::new();
    for (e, s) in epochs {
        r.insert(ZoneKey::new(ZONE, *e, &hex::encode(s), &pk(*s), KeySource::KeyFile).unwrap())
            .unwrap();
    }
    r
}

fn rules() -> nostr_bbs_search_build::harvest::Rules<'static> {
    nostr_bbs_search_build::harvest::Rules {
        now: 1_900_000_000,
        moderators: &[],
        channel_pins: &nostr_bbs_search_build::harvest::NO_CHANNEL_PINS,
    }
}

fn pins() -> Pins {
    Pins {
        model: "bge-small-en-v1.5".into(),
        model_sha256: "aa".repeat(32),
        vocab_sha256: "bb".repeat(32),
    }
}

struct Fixture {
    root: PathBuf,
    /// The indexer's author book (kept with its state between runs).
    book: nostr_bbs_search_build::harvest::AuthorBook,
    relay: MemRelay,
    publishers: Vec<String>,
    /// Imported originals by text, and live posts by text.
    originals: HashMap<String, (NostrEvent, NostrEvent)>,
    natives: HashMap<String, NostrEvent>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn base_text(i: usize) -> String {
    format!("base post number {i}")
}

/// 100 imported posts and 15 live ones, base built by the archivist (with
/// 40-row shards: two full shards and a partial one).
fn fixture(name: &str) -> Fixture {
    let root = std::env::temp_dir().join(format!("nbss-e2e-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let mut relay = MemRelay::new(Vec::new());
    let mut originals = HashMap::new();
    let mut natives = HashMap::new();
    for i in 0..100 {
        let author = if i % 2 == 0 { ALICE } else { BOB };
        let (o, e) = imported(author, T0 + i as u64, &base_text(i));
        relay.insert(e.clone());
        originals.insert(base_text(i), (o, e));
    }
    for i in 100..115 {
        let ev = native(ALICE, T0 + i as u64, &base_text(i), vec![]);
        relay.insert(ev.clone());
        natives.insert(base_text(i), ev);
    }
    let publishers = vec![pk(ARCHIVIST), pk(INDEXER)];
    let mut f = Fixture {
        book: Default::default(),
        root,
        relay,
        publishers,
        originals,
        natives,
    };
    // The archivist's base (full build from the relay).
    let me = sk(ARCHIVIST);
    let keys = ring(&[(1, ZONE_E1)]);
    let mut pod = DirPod::new(&f.root, ZONE, &pk(ARCHIVIST));
    let p = pins();
    let mut job = job(&me, &keys, &mut pod, &f.publishers, &p);
    let mut h = block_on(harvest(
        &mut f.relay,
        ZONE,
        &keys,
        None,
        &HashSet::new(),
        &rules(),
        &mut Default::default(),
    ))
    .unwrap();
    assert_eq!(h.rows.len(), 115);
    let rows = std::mem::take(&mut h.rows);
    let r = block_on(run_full(
        &mut job,
        None,
        rows,
        &HashSet::new(),
        Some(&h),
        &mut HashEmbedder { calls: 0 },
        Format::Auto,
    ))
    .unwrap();
    assert_eq!(r.index_version, Some(1));
    assert_eq!(r.rows_added, 115);
    // A first base, with no v2 manifest anywhere, is v1: every browser reads it.
    assert_eq!(browser_manifest(&f, None).content.v, 1);
    // The indexer seeds its author book from the zone before its first update.
    block_on(nostr_bbs_search_build::harvest::seed_book(
        &mut f.relay,
        ZONE,
        &ring(&[(1, ZONE_E1)]),
        &mut f.book,
    ))
    .unwrap();
    f
}

fn job<'a>(
    me: &'a SecretKey,
    ring: &'a KeyRing,
    pod: &'a mut DirPod,
    publishers: &'a [String],
    pins: &'a Pins,
) -> Job<'a, DirPod> {
    Job {
        zone: ZONE,
        relay_url: RELAY,
        publishers,
        me,
        ring,
        pod,
        cache: None,
        pins: Some(pins),
        shard_rows: SHARD_ROWS,
        now: 1_900_000_000,
        warnings: Vec::new(),
        moderators: &[],
        channel_pins: &nostr_bbs_search_build::harvest::NO_CHANNEL_PINS,
        max_excluded: nostr_bbs_sealed_search::manifest::MAX_EXCLUDED,
        retire_after_secs: nostr_bbs_search_build::pipeline::DEFAULT_RETIRE_AFTER_SECS,
    }
}

/// Indexer settings a test may change.
struct Opts {
    moderators: Vec<String>,
    now: u64,
    max_excluded: usize,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            moderators: Vec::new(),
            now: 1_900_000_000,
            max_excluded: nostr_bbs_sealed_search::manifest::MAX_EXCLUDED,
        }
    }
}

fn update_with(f: &mut Fixture, state: &mut State, o: &Opts) -> Result<Report, JobError> {
    let me = sk(INDEXER);
    let keys = ring(&[(1, ZONE_E1)]);
    let mut pod = DirPod::new(&f.root, ZONE, &pk(INDEXER));
    let p = pins();
    let publishers = f.publishers.clone();
    let mut j = job(&me, &keys, &mut pod, &publishers, &p);
    j.moderators = &o.moderators;
    j.now = o.now;
    j.max_excluded = o.max_excluded;
    block_on(run_update(
        &mut j,
        &mut f.relay,
        state,
        &mut f.book,
        &mut HashEmbedder { calls: 0 },
        None,
        DEFAULT_OVERLAP_SECS,
    ))
}

/// Run one indexer step against the fixture.
fn indexer<T>(
    f: &mut Fixture,
    state: &mut State,
    step: impl FnOnce(&mut Job<'_, DirPod>, &mut MemRelay, &mut State) -> T,
) -> T {
    let me = sk(INDEXER);
    let keys = ring(&[(1, ZONE_E1)]);
    let mut pod = DirPod::new(&f.root, ZONE, &pk(INDEXER));
    let p = pins();
    let publishers = f.publishers.clone();
    let mut j = job(&me, &keys, &mut pod, &publishers, &p);
    step(&mut j, &mut f.relay, state)
}

fn update(f: &mut Fixture, state: &mut State) -> Result<Report, JobError> {
    update_with(f, state, &Opts::default())
}

fn compact_partial(f: &mut Fixture, state: &mut State) -> Result<Report, JobError> {
    compact_with(f, state, Fold::Partial)
}

fn compact_with(f: &mut Fixture, state: &mut State, fold: Fold) -> Result<Report, JobError> {
    let me = sk(INDEXER);
    let keys = ring(&[(1, ZONE_E1)]);
    let mut pod = DirPod::new(&f.root, ZONE, &pk(INDEXER));
    let p = pins();
    let publishers = f.publishers.clone();
    let mut j = job(&me, &keys, &mut pod, &publishers, &p);
    block_on(run_compact(&mut j, &mut f.relay, state, &mut f.book, fold))
}

/// What a browser does: read `m.json` from every trusted publisher, keep the
/// newest that verifies over its high-water mark.
fn browser_manifest(f: &Fixture, hw: Option<&HighWater>) -> Manifest {
    let mut best: Option<Manifest> = None;
    for p in &f.publishers {
        let path = DirPod::new(&f.root, ZONE, p).path(p, "m.json");
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let ev: NostrEvent = serde_json::from_slice(&bytes).unwrap();
        let secret = |e: u32, p: &str| {
            (e == 1 && p == pk(ZONE_E1)).then(|| zeroize::Zeroizing::new(ZONE_E1))
        };
        if let Ok(m) = Manifest::accept(ev, ZONE, RELAY, &f.publishers, hw, secret) {
            if best
                .as_ref()
                .is_none_or(|b| m.content.index_version > b.content.index_version)
            {
                best = Some(m);
            }
        }
    }
    best.expect("a manifest verifies")
}

struct Loaded {
    ix: Index,
    objs: HashMap<String, Vec<u8>>,
}

fn load(f: &Fixture, m: &Manifest) -> Loaded {
    let keys: HashMap<(u32, String), SearchKey> = HashMap::from([(
        (1, pk(ZONE_E1)),
        SearchKey::derive(
            &ZONE_E1,
            ZONE,
            1,
            &hex::decode(pk(ZONE_E1)).unwrap().try_into().unwrap(),
        ),
    )]);
    let mut objs = HashMap::new();
    for o in &m.content.objects {
        let owner = m.owner_of(o);
        let path = DirPod::new(&f.root, ZONE, owner).path(owner, &o.name);
        objs.insert(
            o.name.clone(),
            std::fs::read(&path).unwrap_or_else(|_| panic!("{} missing", o.name)),
        );
    }
    let mut ix = Index::new(m.content.clone(), keys);
    for b in ix.wanted_bins() {
        let q = q_partner(&m.content, &b).unwrap().clone();
        let qb = &objs[&q.name];
        ix.add_shard(&b, &objs[&b.name], &qb[..qb.len().min(70_000)], qb.len())
            .expect("shard verifies");
    }
    assert!(ix.is_complete());
    Loaded { ix, objs }
}

/// Top hits as a member sees them: resolved through the relay (as
/// `verified_hits` does), so a post the relay no longer serves drops out.
fn shown(f: &mut Fixture, l: &Loaded, text: &str) -> Vec<String> {
    let hits = search(l, text);
    let served = block_on(nostr_bbs_search_build::harvest::present(
        &mut f.relay,
        &hits,
    ))
    .unwrap();
    hits.into_iter().filter(|h| served.contains(h)).collect()
}

fn search(l: &Loaded, text: &str) -> Vec<String> {
    let q = vector(text);
    let cands = l.ix.first_stage(&q, 80);
    let plan = l.ix.plan_rescore(&cands).unwrap();
    let fetched: Fetched = plan
        .iter()
        .map(|p| {
            (
                p.name.clone(),
                p.ranges
                    .iter()
                    .map(|&(a, b)| (a, l.objs[&p.name][a..b].to_vec()))
                    .collect(),
            )
        })
        .collect();
    l.ix.rescore(&q, &cands, &fetched, 5)
        .unwrap()
        .into_iter()
        .map(|h| h.id)
        .collect()
}

fn files(f: &Fixture, who: [u8; 32]) -> HashMap<String, Vec<u8>> {
    let dir = DirPod::new(&f.root, ZONE, &pk(who)).path(&pk(who), "m.json");
    let dir = dir.parent().unwrap();
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| {
                    (
                        e.file_name().to_string_lossy().to_string(),
                        std::fs::read(e.path()).unwrap(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn new_state() -> State {
    State::new(ZONE, RELAY, &pk(INDEXER))
}

#[test]
fn an_update_by_the_indexer_shares_the_archivists_base_and_finds_new_posts_not_deleted_ones() {
    let mut f = fixture("update");
    let archivist_files = files(&f, ARCHIVIST);
    let base = browser_manifest(&f, None);
    let mut state = new_state();

    // First run: no high-water mark yet, so the whole zone is read; every
    // post is already indexed and nothing is published.
    let r = update(&mut f, &mut state).unwrap();
    assert!(!r.published);
    assert_eq!(r.already_indexed, 115);
    assert_eq!(state.high_water, Some(T0 + 114));

    // New activity: M new posts, an edit, K deletions three ways.
    let t1 = T0 + 1_000;
    let new_texts: Vec<String> = (0..30).map(|i| format!("fresh post {i}")).collect();
    for (i, text) in new_texts.iter().enumerate() {
        f.relay.insert(native(BOB, t1 + i as u64, text, vec![]));
    }
    // Alice edits her imported post 10 (target: the ORIGINAL id).
    let (orig10, _) = f.originals[&base_text(10)].clone();
    f.relay.insert(native(
        ALICE,
        t1 + 50,
        "base post number 10, corrected",
        edit_of(&orig10.id),
    ));
    // Bob may not edit Alice's post 12: ignored.
    let (orig12, _) = f.originals[&base_text(12)].clone();
    f.relay
        .insert(native(BOB, t1 + 51, "hijacked text", edit_of(&orig12.id)));
    // Deletions: imported post 3 by its envelope id (a moderator: the relay
    // removes the envelope), imported post 5 by its inner id (the envelope
    // stays on the relay), live post 105 by its own id.
    let (orig3, env3) = f.originals[&base_text(3)].clone();
    f.relay.insert(kind5(STRANGER, t1 + 60, &env3.id));
    f.relay.remove(&env3.id);
    let (orig5, _) = f.originals[&base_text(5)].clone();
    f.relay.insert(kind5(BOB, t1 + 61, &orig5.id));
    let live105 = f.natives[&base_text(105)].clone();
    f.relay.insert(kind5(ALICE, t1 + 62, &live105.id));
    f.relay.remove(&live105.id);
    // One fresh post deleted before the run: never indexed.
    let doomed = native(BOB, t1 + 70, "regretted post", vec![]);
    f.relay.insert(doomed.clone());
    f.relay.insert(kind5(BOB, t1 + 71, &doomed.id));

    // STRANGER is a configured moderator (it deleted post 3's envelope).
    let mods = Opts {
        moderators: vec![pk(STRANGER)],
        ..Opts::default()
    };
    let r = update_with(&mut f, &mut state, &mods).unwrap();
    assert!(r.published);
    assert_eq!(r.index_version, Some(2));
    assert_eq!(
        r.rows_added,
        30 + 2,
        "30 fresh posts, the edit, and Bob's ignored edit post itself"
    );
    // Post 3's kind-5 names an envelope the relay has removed, and post 105
    // is gone from the relay too: the job's author book (filled when it
    // opened them) still establishes their authors, so the authors'
    // deletions count.
    assert_eq!(r.excluded_added, 4, "posts 3, 5, 10 (superseded) and 105");
    assert_eq!(state.index_version, Some(2));
    // Kind-5s do not move the mark; the newest zone post does.
    assert_eq!(state.high_water, Some(t1 + 70));

    // The archivist's pod was not touched.
    assert_eq!(files(&f, ARCHIVIST), archivist_files);

    let upd = browser_manifest(&f, Some(&base.high_water()));
    assert_eq!(upd.content.index_version, 2);
    assert_eq!(upd.event.pubkey, pk(INDEXER));
    // Every base object listed byte-for-byte: same name, sha256, size, held
    // by the archivist, header version 1.
    for o in &base.content.objects {
        let u = upd
            .content
            .objects
            .iter()
            .find(|u| u.name == o.name)
            .expect("base object carried");
        assert_eq!((u.sha256.as_str(), u.size), (o.sha256.as_str(), o.size));
        assert_eq!(upd.owner_of(u), pk(ARCHIVIST));
        assert_eq!(u.effective_version(&upd.content), 1);
    }
    // A browser with the base cached by sha256 downloads only the new pair.
    let cached: HashSet<&str> = base
        .content
        .objects
        .iter()
        .map(|o| o.sha256.as_str())
        .collect();
    let fresh: Vec<_> = upd
        .content
        .objects
        .iter()
        .filter(|o| !cached.contains(o.sha256.as_str()))
        .collect();
    assert_eq!(fresh.len(), 2);
    assert!(fresh.iter().all(|o| upd.owner_of(o) == pk(INDEXER)));

    let l = load(&f, &upd);
    // New posts are found, by their own id.
    let new_ids: HashMap<String, String> = f
        .relay
        .clone()
        .into_events()
        .into_iter()
        .filter(|e| e.kind == 42 && e.pubkey == pk(BOB))
        .map(|e| (e.id.clone(), e.id))
        .collect();
    for text in &new_texts {
        let top = search(&l, text)[0].clone();
        assert!(new_ids.contains_key(&top), "{text}");
    }
    let top = |text: &str| search(&l, text)[0].clone();
    // Excluded posts are never returned by the index, nor shown.
    for text in [base_text(3), base_text(5), base_text(10), base_text(105)] {
        let hits = search(&l, &text);
        for gone in [&orig3.id, &orig5.id, &orig10.id, &live105.id] {
            assert!(!hits.contains(gone), "{text}");
        }
        assert!(!shown(&mut f, &l, &text).contains(&orig3.id));
    }
    // The edit is found under its own id; post 12 is still Alice's original.
    let corrected = top("base post number 10, corrected");
    assert_ne!(corrected, orig10.id);
    assert_eq!(top(&base_text(12)), orig12.id);
    // An imported post resolves to its ORIGINAL id (the `#sealed` lookup).
    let (orig40, env40) = f.originals[&base_text(40)].clone();
    assert_eq!(top(&base_text(40)), orig40.id);
    assert_ne!(orig40.id, env40.id);
    assert_eq!(top("fresh post 0").len(), 64);

    // Refused: the same update re-signed by a key outside the trusted list,
    // and the base again once the update is accepted (lower version).
    let stranger = sign(
        STRANGER,
        KIND,
        1,
        Manifest::tags(&upd.content, RELAY),
        &serde_json::to_string(&upd.content).unwrap(),
    );
    assert!(Manifest::verify(stranger, ZONE, RELAY, &f.publishers, None).is_err());
    assert!(Manifest::verify(
        base.event.clone(),
        ZONE,
        RELAY,
        &f.publishers,
        Some(&upd.high_water())
    )
    .is_err());
    // And a run of the job finds nothing more to do.
    let r = update(&mut f, &mut state).unwrap();
    assert!(!r.published);
}

#[test]
fn compaction_folds_update_shards_drops_gone_rows_and_retires_objects_a_run_later() {
    let mut f = fixture("compact");
    let mut state = new_state();
    update(&mut f, &mut state).unwrap();
    // Two nightly updates.
    for night in 0..2u64 {
        for i in 0..15u64 {
            let at = T0 + 10_000 * (night + 1) + i;
            f.relay
                .insert(native(BOB, at, &format!("night {night} post {i}"), vec![]));
        }
        assert!(update(&mut f, &mut state).unwrap().published);
    }
    // Post 110 (a live post in the base's last, partial shard) is deleted by
    // an admin through the HTTP API: no kind-5, the relay just stops serving it.
    let live110 = f.natives[&base_text(110)].clone();
    f.relay.remove(&live110.id);
    // Post 113 (same shard) is deleted with a kind-5 by its author.
    let live118 = f.natives[&base_text(113)].clone();
    f.relay.insert(kind5(ALICE, T0 + 40_000, &live118.id));
    f.relay.remove(&live118.id);
    let r = update(&mut f, &mut state).unwrap();
    assert!(r.published, "the deletion is excluded");
    let before = indexer(&mut f, &mut state, |j, _, _| block_on(status(j)).unwrap());
    assert_eq!(before.index_version, 4);
    assert_eq!(before.excluded, 1);
    assert_eq!(
        before.partial_pairs, 3,
        "the base's last shard and two updates"
    );

    let r = compact_partial(&mut f, &mut state).unwrap();
    assert!(r.published);
    assert_eq!(r.folded_pairs, 3);
    assert_eq!(r.missing_rows, 1, "post 110: not served by the relay now");
    // Only positive evidence drops a row: 113 has an authorised kind-5; 110
    // is merely not served (withholding must never become a signed,
    // permanent exclusion), so its row is kept.
    assert_eq!(r.dropped_rows, 1, "post 113 only");
    assert_eq!(r.excluded_total, 0, "113 left the list with its row");
    let after = indexer(&mut f, &mut state, |j, _, _| block_on(status(j)).unwrap());
    assert_eq!(after.index_version, 5);
    assert_eq!(after.rows, before.rows - 1);
    assert_eq!(after.partial_pairs, 1);
    assert!(
        after.foreign_objects > 0,
        "full base shards stay in the archivist's pod"
    );

    let m = browser_manifest(&f, None);
    let l = load(&f, &m);
    assert_eq!(search(&l, "night 1 post 4")[0].len(), 64);
    assert!(!search(&l, &base_text(113)).contains(&live118.id));
    assert!(
        search(&l, &base_text(110)).contains(&live110.id),
        "kept, not shown by the relay"
    );
    // The folded update objects are retired, not yet deleted: a browser on
    // version 4 can still load it.
    assert_eq!(state.retired.len(), 4);
    let own = files(&f, INDEXER);
    assert!(state.retired.iter().all(|r| own.contains_key(&r.name)));
    // A run straight after (a manual rerun) keeps them: the grace period is
    // a duration, not a number of runs.
    let r = update(&mut f, &mut state).unwrap();
    assert!(!r.published);
    assert_eq!(r.objects_deleted, 0);
    assert_eq!(state.retired.len(), 4);
    // 48 hours later they go.
    let later = Opts {
        now: 1_900_000_000 + 48 * 3600,
        ..Opts::default()
    };
    let r = update_with(&mut f, &mut state, &later).unwrap();
    assert!(!r.published);
    assert_eq!(r.objects_deleted, 4);
    let own = files(&f, INDEXER);
    assert!(state.retired.is_empty());
    assert!(m
        .content
        .objects
        .iter()
        .all(|o| m.owner_of(o) != pk(INDEXER) || own.contains_key(&o.name)));

    // compact --all re-homes everything: no archivist object is referenced.
    let r = compact_with(&mut f, &mut state, Fold::All).unwrap();
    assert!(r.published);
    assert_eq!(r.objects_foreign, 0);
    let m = browser_manifest(&f, None);
    assert!(m
        .content
        .objects
        .iter()
        .all(|o| m.owner_of(o) == pk(INDEXER)));
    assert!(m
        .content
        .objects
        .iter()
        .all(|o| o.kind != Kind::Bin || o.count as usize <= SHARD_ROWS));
    let l = load(&f, &m);
    let (orig7, _) = f.originals[&base_text(7)].clone();
    assert_eq!(search(&l, &base_text(7))[0], orig7.id);
}

#[test]
fn refusals_keep_the_index_and_the_high_water_mark() {
    let mut f = fixture("refusals");
    let mut state = new_state();
    update(&mut f, &mut state).unwrap();
    let hw = state.high_water;

    // Unauthenticated relay: refused before anything is read (exit 4).
    let mut anon = MemRelay::new(Vec::new()).unauthenticated();
    let e = indexer(&mut f, &mut state, |j, _, s| {
        block_on(run_update(
            j,
            &mut anon,
            s,
            &mut Default::default(),
            &mut HashEmbedder { calls: 0 },
            None,
            0,
        ))
    })
    .unwrap_err();
    assert_eq!(e.exit_code(), 4);
    assert_eq!(state.high_water, hw);

    // A post under an epoch the indexer holds no key for: published around,
    // and the high-water mark stays below it (exit 3 in the CLI).
    let t1 = T0 + 5_000;
    f.relay.insert(native(BOB, t1, "visible post", vec![]));
    f.relay.insert(native_under(
        BOB,
        t1 + 1,
        "epoch two post",
        vec![],
        2,
        ZONE_E2,
    ));
    f.relay
        .insert(native(BOB, t1 + 2, "later visible post", vec![]));
    let r = update(&mut f, &mut state).unwrap();
    assert!(r.published);
    assert_eq!(r.missing_key, 1);
    assert_eq!(r.missing_epochs, vec![2]);
    assert_eq!(state.high_water, Some(t1));
    assert_eq!(r.rows_added, 2);

    // Too many rows missing from the relay: compaction refused (exit 5).
    for i in 100..115 {
        if let Some(ev) = f.natives.get(&base_text(i)) {
            f.relay.remove(&ev.id.clone());
        }
    }
    f.relay.insert(native(BOB, t1 + 10, "another", vec![]));
    update(&mut f, &mut state).unwrap();
    let before = indexer(&mut f, &mut state, |j, _, _| block_on(status(j)).unwrap());
    let r = compact_partial(&mut f, &mut state).unwrap();
    assert_eq!(r.missing_rows, 15, "reported");
    assert_eq!(r.dropped_rows, 0, "but kept: no evidence of deletion");
    let after = indexer(&mut f, &mut state, |j, _, _| block_on(status(j)).unwrap());
    assert_eq!(after.rows, before.rows);

    // The pods show an older index than the state recorded (exit 6).
    let mut ahead = state.clone();
    ahead.index_version = Some(ahead.index_version.unwrap() + 3);
    let e = update(&mut f, &mut ahead).unwrap_err();
    assert_eq!(e.exit_code(), 6);
    // Nothing on the pods changed version through any refusal.
    let cur = indexer(&mut f, &mut state, |j, _, _| block_on(status(j)).unwrap());
    assert_eq!(Some(cur.index_version), state.index_version);
}

#[test]
fn a_zone_the_relay_withholds_is_refused_not_read_as_empty() {
    let mut f = fixture("withheld");
    let mut state = new_state();
    // Authenticated, but outside the zone's cohorts: the relay answers every
    // zone REQ with nothing (exit 7), on the first run and on later ones.
    let mut gated = MemRelay::new(Vec::new());
    let mut seeded = f.book.clone();
    let e = indexer(&mut f, &mut state, |j, _, s| {
        block_on(run_update(
            j,
            &mut gated,
            s,
            &mut seeded,
            &mut HashEmbedder { calls: 0 },
            None,
            0,
        ))
    })
    .unwrap_err();
    assert_eq!(e.exit_code(), 7, "{e}");
    assert_eq!(state.high_water, None);
    let e = indexer(&mut f, &mut state, |j, _, s| {
        block_on(run_compact(
            j,
            &mut gated,
            s,
            &mut Default::default(),
            Fold::All,
        ))
    })
    .unwrap_err();
    assert_eq!(e.exit_code(), 7, "{e}");
    // A full build reading nothing refuses to publish an empty index.
    let e = indexer(&mut f, &mut state, |j, _, s| {
        block_on(run_full(
            j,
            Some(s),
            Vec::new(),
            &HashSet::new(),
            None,
            &mut HashEmbedder { calls: 0 },
            Format::Auto,
        ))
    })
    .unwrap_err();
    assert!(e.to_string().contains("empty"), "{e}");
}

#[test]
fn a_full_build_after_a_v2_manifest_is_v2_and_small_folds_tolerate_a_few_gone_rows() {
    let mut f = fixture("format");
    let mut state = new_state();
    update(&mut f, &mut state).unwrap();
    f.relay
        .insert(native(BOB, T0 + 9_000, "one more post", vec![]));
    assert!(update(&mut f, &mut state).unwrap().published);
    assert_eq!(browser_manifest(&f, None).content.v, 2);
    // Two posts of the base's partial shard go through the admin API: below
    // the 5% share of a small fold, but within the absolute floor.
    for i in [101, 102] {
        let id = f.natives[&base_text(i)].id.clone();
        f.relay.remove(&id);
    }
    let r = compact_partial(&mut f, &mut state).unwrap();
    assert_eq!(r.missing_rows, 2);
    // A full rebuild by the indexer now signs v2 (Auto), never v1 above a v2.
    let mut h = block_on(harvest(
        &mut f.relay,
        ZONE,
        &ring(&[(1, ZONE_E1)]),
        None,
        &HashSet::new(),
        &rules(),
        &mut Default::default(),
    ))
    .unwrap();
    let rows = std::mem::take(&mut h.rows);
    let r = indexer(&mut f, &mut state, |j, _, s| {
        block_on(run_full(
            j,
            Some(s),
            rows,
            &HashSet::new(),
            Some(&h),
            &mut HashEmbedder { calls: 0 },
            Format::Auto,
        ))
    })
    .unwrap();
    assert!(r.published);
    let m = browser_manifest(&f, None);
    assert_eq!(m.content.v, 2);
    assert_eq!(m.event.pubkey, pk(INDEXER));
}

#[test]
fn an_update_with_another_local_model_is_refused() {
    let mut f = fixture("model");
    let mut state = new_state();
    let me = sk(INDEXER);
    let keys = ring(&[(1, ZONE_E1)]);
    let mut pod = DirPod::new(&f.root, ZONE, &pk(INDEXER));
    let mut other = pins();
    other.model_sha256 = "cc".repeat(32);
    let publishers = f.publishers.clone();
    let mut j = job(&me, &keys, &mut pod, &publishers, &other);
    let e = block_on(run_update(
        &mut j,
        &mut f.relay,
        &mut state,
        &mut f.book,
        &mut HashEmbedder { calls: 0 },
        None,
        0,
    ))
    .unwrap_err();
    assert!(e.to_string().contains("model"), "{e}");
}

// ── Security review fixes ──────────────────────────────────────────────────

const DRIFT: u64 = nostr_bbs_core::event::MAX_CREATED_AT_DRIFT_SECS;

#[test]
fn bogus_foreign_or_future_events_cannot_move_the_high_water_mark() {
    let mut f = fixture("future");
    let mut state = new_state();
    update(&mut f, &mut state).unwrap();
    assert_eq!(state.high_water, Some(T0 + 114));
    // A far-future event whose signature does not verify.
    let mut bad = native(BOB, T0 + 200, "tampered", vec![]);
    bad.created_at = 4_000_000_000;
    f.relay.insert(bad);
    // A valid event of another zone.
    f.relay.insert(sign(
        BOB,
        42,
        4_000_000_001,
        vec![
            t(&["e", CHANNEL, "", "root"]),
            t(&["zk", "zone9", "1", &pk(ZONE_E1)]),
        ],
        "x",
    ));
    // A valid kind-5 naming nothing in this zone.
    f.relay.insert(kind5(BOB, 4_000_000_002, &"ab".repeat(32)));
    update(&mut f, &mut state).unwrap();
    assert_eq!(
        state.high_water,
        Some(T0 + 114),
        "none of them moves the mark"
    );
    // A valid post of this zone dated far ahead is indexed, but the mark
    // never goes past the job's clock.
    f.relay
        .insert(native(BOB, 4_000_000_003, "post from the future", vec![]));
    let r = update(&mut f, &mut state).unwrap();
    assert!(r.published);
    assert!(state.high_water.unwrap() <= 1_900_000_000 + DRIFT);
    assert_eq!(state.high_water, Some(1_900_000_000));
}

#[test]
fn a_second_the_relay_cannot_page_holds_the_mark_below_it() {
    let mut f = fixture("ambiguous");
    let mut state = new_state();
    update(&mut f, &mut state).unwrap();
    let s = T0 + 500;
    for i in 0..1_001 {
        f.relay
            .insert(native(BOB, s, &format!("same second {i}"), vec![]));
    }
    // A recent second (the job runs an hour later) holds the mark.
    let soon = nostr_bbs_search_build::harvest::Rules {
        now: s + 3_600,
        moderators: &[],
        channel_pins: &nostr_bbs_search_build::harvest::NO_CHANNEL_PINS,
    };
    let h = block_on(harvest(
        &mut f.relay,
        ZONE,
        &ring(&[(1, ZONE_E1)]),
        Some(T0),
        &HashSet::new(),
        &soon,
        &mut Default::default(),
    ))
    .unwrap();
    assert_eq!(h.ambiguous_seconds, vec![s]);
    let o = Opts {
        now: s + 3_600,
        ..Opts::default()
    };
    update_with(&mut f, &mut state, &o).unwrap();
    assert!(state.high_water.unwrap() < s, "{:?}", state.high_water);
}

#[test]
fn only_authors_and_configured_moderators_delete_posts() {
    let mut f = fixture("authority");
    let mut state = new_state();
    update(&mut f, &mut state).unwrap();
    // A stranger's kind-5 of Alice's imported post 20 (its original id).
    let (o20, _) = f.originals[&base_text(20)].clone();
    f.relay.insert(kind5(STRANGER, T0 + 3_000, &o20.id));
    let r = update(&mut f, &mut state).unwrap();
    assert_eq!(r.excluded_added, 0, "not the author, not a moderator");
    // Alice deleting her own imported post 22.
    let (o22, _) = f.originals[&base_text(22)].clone();
    f.relay.insert(kind5(ALICE, T0 + 3_001, &o22.id));
    let r = update(&mut f, &mut state).unwrap();
    assert_eq!(r.excluded_added, 1, "the original's author");
    // Once the stranger is a configured moderator, the earlier kind-5 counts.
    let o = Opts {
        moderators: vec![pk(STRANGER)],
        ..Opts::default()
    };
    let r = update_with(&mut f, &mut state, &o).unwrap();
    assert_eq!(r.excluded_added, 1, "a moderator deletes anyone's post");
}

#[test]
fn an_edit_of_a_post_the_relay_does_not_return_is_not_authority() {
    let mut f = fixture("edit-gone");
    let mut state = new_state();
    update(&mut f, &mut state).unwrap();
    let live105 = f.natives[&base_text(105)].clone();
    f.relay.remove(&live105.id);
    f.relay.insert(native(
        BOB,
        T0 + 4_000,
        "bob claims post 105",
        edit_of(&live105.id),
    ));
    let r = update(&mut f, &mut state).unwrap();
    assert_eq!(r.excluded_added, 0, "authorship unknown this run: skipped");
}

#[test]
fn equal_versions_resolve_to_the_first_listed_publisher_in_the_builder_too() {
    let mut f = fixture("tie");
    // The indexer's own version-1 index, built elsewhere and placed in its pod.
    let other = f.root.join("elsewhere");
    let me = sk(INDEXER);
    let keys = ring(&[(1, ZONE_E1)]);
    let p = pins();
    let publishers = f.publishers.clone();
    {
        let mut pod = DirPod::new(&other, ZONE, &pk(INDEXER));
        let mut j = job(&me, &keys, &mut pod, &publishers, &p);
        let mut h = block_on(harvest(
            &mut f.relay,
            ZONE,
            &keys,
            None,
            &HashSet::new(),
            &rules(),
            &mut Default::default(),
        ))
        .unwrap();
        let rows = std::mem::take(&mut h.rows);
        let r = block_on(run_full(
            &mut j,
            None,
            rows,
            &HashSet::new(),
            Some(&h),
            &mut HashEmbedder { calls: 0 },
            Format::Auto,
        ))
        .unwrap();
        assert_eq!(r.index_version, Some(1));
    }
    let from = DirPod::new(&other, ZONE, &pk(INDEXER)).path(&pk(INDEXER), "m.json");
    let to = DirPod::new(&f.root, ZONE, &pk(INDEXER)).path(&pk(INDEXER), "m.json");
    std::fs::create_dir_all(to.parent().unwrap()).unwrap();
    for e in std::fs::read_dir(from.parent().unwrap()).unwrap().flatten() {
        std::fs::copy(e.path(), to.parent().unwrap().join(e.file_name())).unwrap();
    }
    let mut state = new_state();
    let st = indexer(&mut f, &mut state, |j, _, _| block_on(status(j)).unwrap());
    assert_eq!(st.index_version, 1);
    assert_eq!(
        st.signer,
        pk(ARCHIVIST),
        "publishers are [archivist, indexer]"
    );
}

#[test]
fn a_full_exclusion_list_stops_with_its_own_exit_code() {
    let mut f = fixture("cap");
    let mut state = new_state();
    update(&mut f, &mut state).unwrap();
    for (i, n) in [100usize, 102, 104].iter().enumerate() {
        let ev = f.natives[&base_text(*n)].clone();
        f.relay.insert(kind5(ALICE, T0 + 5_000 + i as u64, &ev.id));
    }
    let o = Opts {
        max_excluded: 2,
        ..Opts::default()
    };
    let e = update_with(&mut f, &mut state, &o).unwrap_err();
    assert_eq!(e.exit_code(), 8, "{e}");
    assert!(e.to_string().contains("compact --all"), "{e}");
}

// ── Second security review ─────────────────────────────────────────────────

#[test]
fn a_moderator_deletion_needs_no_author() {
    let mut f = fixture("mod-no-author");
    let mut state = new_state();
    update(&mut f, &mut state).unwrap();
    // A live post and an imported one, removed by the relay at once on a
    // moderator's kind-5, whose authors the book does not hold.
    let live = f.natives[&base_text(107)].clone();
    f.relay.remove(&live.id);
    f.book.authors.remove(&live.id);
    let (o30, e30) = f.originals[&base_text(30)].clone();
    f.relay.remove(&e30.id);
    f.book.authors.remove(&o30.id);
    f.relay.insert(kind5(STRANGER, T0 + 6_000, &live.id));
    f.relay.insert(kind5(STRANGER, T0 + 6_001, &e30.id));
    let o = Opts {
        moderators: vec![pk(STRANGER)],
        ..Opts::default()
    };
    let r = update_with(&mut f, &mut state, &o).unwrap();
    assert_eq!(
        r.excluded_added, 2,
        "a moderator's deletion counts without an author"
    );
}

#[test]
fn an_unseeded_author_book_stops_the_first_update() {
    let mut f = fixture("unseeded");
    assert!(f.book.seeded, "seed_book marks the book");
    assert_eq!(f.book.authors.len(), 115);
    assert_eq!(f.book.envelopes.len(), 100);
    f.book = Default::default();
    let mut state = new_state();
    let e = update(&mut f, &mut state).unwrap_err();
    assert_eq!(e.exit_code(), 9, "{e}");
    assert_eq!(state.high_water, None);
}

#[test]
fn the_book_is_written_before_the_state() {
    let dir = std::env::temp_dir().join(format!("nbss-persist-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("not-a-dir"), "x").unwrap();
    let state_path = dir.join("zone2.state.json");
    let book_path = dir.join("not-a-dir").join("zone2.authors.json");
    let mut st = new_state();
    st.high_water = Some(42);
    let r = nostr_bbs_search_build::pipeline::persist(
        Some((&st, &state_path)),
        Some((
            &nostr_bbs_search_build::harvest::AuthorBook::default(),
            &book_path,
        )),
    );
    assert!(r.is_err());
    assert!(
        !state_path.exists(),
        "the mark must not move when the book was not written"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_operator_takedown_excludes_indexed_posts_in_the_next_manifest() {
    let mut f = fixture("takedown");
    let mut state = new_state();
    update(&mut f, &mut state).unwrap();
    let (o40, _) = f.originals[&base_text(40)].clone();
    let r = indexer(&mut f, &mut state, |j, _, s| {
        block_on(nostr_bbs_search_build::pipeline::run_takedown(
            j,
            s,
            &[o40.id.clone(), "ff".repeat(32)],
            "moderated through the admin API",
        ))
    })
    .unwrap();
    assert!(r.published);
    assert_eq!(r.excluded_added, 1, "only the indexed id");
    assert!(r.warnings.iter().any(|w| w.contains("not in the index")));
    let m = browser_manifest(&f, None);
    assert_eq!(m.event.pubkey, pk(INDEXER));
    assert!(m.content.excluded.contains(&o40.id));
    let l = load(&f, &m);
    assert!(!search(&l, &base_text(40)).contains(&o40.id));
}

#[test]
fn a_flood_of_irrelevant_or_old_events_cannot_pin_the_mark() {
    let mut f = fixture("stall");
    let mut state = new_state();
    update(&mut f, &mut state).unwrap();
    // 1,001 valid kind-5s at one second, each naming a random id of the
    // signer's own: nothing in this zone.
    let s = T0 + 50;
    for i in 0..1_001u32 {
        let target = hex::encode(sha2::Sha256::digest(i.to_be_bytes()));
        f.relay.insert(kind5(BOB, s, &target));
    }
    let o = Opts {
        now: T0 + 3_600,
        ..Opts::default()
    };
    update_with(&mut f, &mut state, &o).unwrap();
    assert_eq!(
        state.high_water,
        Some(T0 + 114),
        "irrelevant events hold nothing"
    );
    // 1,001 real posts in one second, long ago: released after the hold
    // period, loudly.
    let s2 = T0 + 500;
    for i in 0..1_001 {
        f.relay
            .insert(native(BOB, s2, &format!("old flood {i}"), vec![]));
    }
    let r = update(&mut f, &mut state).unwrap();
    assert!(state.high_water.unwrap() >= s2, "{:?}", state.high_water);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("could not be read completely")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn the_author_book_keeps_only_indexed_posts() {
    let mut f = fixture("prune");
    let mut state = new_state();
    update(&mut f, &mut state).unwrap();
    // Deleted before it was ever indexed: not kept.
    let doomed = native(BOB, T0 + 7_000, "short-lived", vec![]);
    f.relay.insert(doomed.clone());
    f.relay.insert(kind5(BOB, T0 + 7_001, &doomed.id));
    f.relay.insert(native(BOB, T0 + 7_002, "kept post", vec![]));
    update(&mut f, &mut state).unwrap();
    assert!(!f.book.authors.contains_key(&doomed.id));
    // Dropped by compaction: forgotten.
    let live113 = f.natives[&base_text(113)].clone();
    f.relay.insert(kind5(ALICE, T0 + 7_100, &live113.id));
    update(&mut f, &mut state).unwrap();
    let r = compact_partial(&mut f, &mut state).unwrap();
    assert!(r.dropped_rows >= 1);
    assert!(!f.book.authors.contains_key(&live113.id));
    assert!(f.book.authors.len() < 120);
}

// -- ADR-2037: channels pinned to another zone stay out of this index -------

fn pinned_to(zone: &str) -> nostr_bbs_search_build::harvest::ChannelPins {
    nostr_bbs_search_build::harvest::ChannelPins::from_zone_config_json(&format!(
        r#"[{{"id":"{ZONE}"}},{{"id":"{zone}","channels":["{CHANNEL}"]}}]"#
    ))
    .unwrap()
}

#[test]
fn posts_of_a_channel_pinned_to_another_zone_are_not_indexed() {
    let mut f = fixture("pinned-away");
    let pins = pinned_to("staff");
    let rules = nostr_bbs_search_build::harvest::Rules {
        channel_pins: &pins,
        ..rules()
    };
    let h = block_on(harvest(
        &mut f.relay,
        ZONE,
        &ring(&[(1, ZONE_E1)]),
        None,
        &HashSet::new(),
        &rules,
        &mut Default::default(),
    ))
    .unwrap();
    assert!(h.rows.is_empty(), "no row of the pinned channel is indexed");
    assert_eq!(h.pinned_elsewhere, 115);
    assert_eq!(
        h.newest, None,
        "skipped posts do not move the high-water mark"
    );
}

#[test]
fn a_reconcile_excludes_indexed_rows_of_a_channel_pinned_away() {
    let mut f = fixture("pinned-reconcile");
    // Every row the base indexed: imported originals by their original id,
    // live posts by their own id.
    let indexed: HashSet<String> = f
        .originals
        .values()
        .map(|(o, _)| o.id.clone())
        .chain(f.natives.values().map(|e| e.id.clone()))
        .collect();
    assert_eq!(indexed.len(), 115);
    let pins = pinned_to("staff");
    let rules = nostr_bbs_search_build::harvest::Rules {
        channel_pins: &pins,
        ..rules()
    };
    let h = block_on(harvest(
        &mut f.relay,
        ZONE,
        &ring(&[(1, ZONE_E1)]),
        None,
        &indexed,
        &rules,
        &mut f.book,
    ))
    .unwrap();
    let excluded: HashSet<String> = h.exclude.iter().cloned().collect();
    assert_eq!(
        excluded, indexed,
        "envelopes are excluded by their original's id"
    );
}

#[test]
fn a_channel_pinned_to_this_zone_or_no_pins_indexes_as_before() {
    for pins in [
        pinned_to(ZONE),
        nostr_bbs_search_build::harvest::NO_CHANNEL_PINS.clone(),
    ] {
        let mut f = fixture("pinned-here");
        let rules = nostr_bbs_search_build::harvest::Rules {
            channel_pins: &pins,
            ..rules()
        };
        let h = block_on(harvest(
            &mut f.relay,
            ZONE,
            &ring(&[(1, ZONE_E1)]),
            None,
            &HashSet::new(),
            &rules,
            &mut Default::default(),
        ))
        .unwrap();
        assert_eq!(h.rows.len(), 115);
        assert_eq!(h.pinned_elsewhere, 0);
    }
}
