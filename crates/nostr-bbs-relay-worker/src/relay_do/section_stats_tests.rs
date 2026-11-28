//! ADR-2038 section stats: the exact SQL against SQLite with the relay's
//! schema, checked against the clients' own `classify_topics` over the same
//! seeded events (deletions, edits, sealed and dual-present roots, expired
//! and crafted cross-channel events), plus caps, truncation, cost and the
//! admission matrix.

use super::*;
use crate::trust::resolve_channel_zone;
use nostr_bbs_core::NostrEvent;
use rusqlite::{types::Value, Connection};

const MIGRATION_0004: &str = include_str!("../../migrations/0004_event_tags.sql");
const MIGRATION_0017: &str = include_str!("../../migrations/0017_topic_root_channel_index.sql");
const NOW: u64 = 2_000_000;

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

fn db() -> Connection {
    let c = db_without_index();
    c.execute_batch(MIGRATION_0017).unwrap();
    c
}

/// The schema before migration 0017 (the roots index).
fn db_without_index() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(crate::EVENTS_CREATE_SQL).unwrap();
    c.execute_batch(crate::CHANNEL_CREATORS_CREATE_SQL).unwrap();
    c.execute_batch(MIGRATION_0004).unwrap();
    let _ = c.execute_batch(crate::EVENT_TAGS_TIME_COLUMN_SQL);
    for s in crate::PROBE_BLIND_STMTS {
        c.execute_batch(s).unwrap();
    }
    for s in crate::PAGING_INDEX_STMTS {
        c.execute_batch(s).unwrap();
    }
    c
}

fn store(c: &Connection, events: &[NostrEvent]) {
    let tx = c.unchecked_transaction().unwrap();
    {
        let mut s = tx
            .prepare(
                "INSERT INTO events (id, pubkey, created_at, kind, tags, content, sig) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )
            .unwrap();
        for e in events {
            s.execute(rusqlite::params![
                e.id,
                e.pubkey,
                e.created_at as i64,
                e.kind as i64,
                serde_json::to_string(&e.tags).unwrap(),
                e.content,
                e.sig
            ])
            .unwrap();
        }
    }
    tx.commit().unwrap();
}

fn delete(c: &Connection, id: &str) {
    c.execute("DELETE FROM events WHERE id = ?1", [id]).unwrap();
}

/// The SQLite side of [`StatsDb`], with the VM steps each statement took.
struct Sqlite<'a> {
    c: &'a Connection,
    steps: std::cell::RefCell<Vec<(&'static str, i32)>>,
}

impl<'a> Sqlite<'a> {
    fn new(c: &'a Connection) -> Self {
        Self {
            c,
            steps: Default::default(),
        }
    }

    fn rows<T: serde::de::DeserializeOwned>(
        &self,
        label: &'static str,
        sql: &str,
        params: Vec<Value>,
    ) -> Result<Vec<T>, String> {
        let mut s = self.c.prepare(sql).map_err(|e| e.to_string())?;
        let names: Vec<String> = s.column_names().map(|n| n.to_string()).collect();
        let out: Vec<T> = s
            .query_map(rusqlite::params_from_iter(params.iter()), |r| {
                let mut m = serde_json::Map::new();
                for (i, n) in names.iter().enumerate() {
                    let v = match r.get::<_, Value>(i)? {
                        Value::Null => serde_json::Value::Null,
                        Value::Integer(n) => serde_json::json!(n as f64),
                        Value::Real(f) => serde_json::json!(f),
                        Value::Text(t) => serde_json::Value::String(t),
                        Value::Blob(_) => serde_json::Value::Null,
                    };
                    m.insert(n.clone(), v);
                }
                Ok(serde_json::Value::Object(m))
            })
            .unwrap()
            .map(|v| serde_json::from_value(v.unwrap()).unwrap())
            .collect();
        let steps = s.get_status(rusqlite::StatementStatus::VmStep);
        self.steps.borrow_mut().push((label, steps));
        Ok(out)
    }

    fn steps(&self, label: &str) -> i32 {
        self.steps
            .borrow()
            .iter()
            .filter(|(l, _)| *l == label)
            .map(|(_, s)| *s)
            .sum()
    }
}

fn ids(ids: &[String]) -> Value {
    Value::Text(serde_json::to_string(ids).unwrap())
}

impl StatsDb for Sqlite<'_> {
    async fn roots(
        &self,
        channel: &str,
        now: u64,
        limit: usize,
        indexed: bool,
    ) -> Result<Vec<RootRow>, String> {
        let mut params = vec![
            Value::Text(channel.into()),
            Value::Integer(now as i64),
            Value::Integer(limit as i64),
        ];
        if indexed {
            self.rows("roots", &roots_indexed_sql(), params)
        } else {
            params.push(Value::Integer(ROOTS_VISIT_CAP as i64));
            self.rows("roots", &roots_walk_sql(), params)
        }
    }
    async fn stats(
        &self,
        channel: &str,
        now: u64,
        list: &[String],
        with_counts: bool,
    ) -> Result<Vec<StatsRow>, String> {
        self.rows(
            "stats",
            &stats_sql(with_counts),
            vec![
                Value::Text(channel.into()),
                Value::Integer(now as i64),
                ids(list),
                Value::Integer(ACTIVITY_WALK_ROWS),
                Value::Integer(COUNT_VISIT_CAP as i64),
            ],
        )
    }
    async fn exists(&self, channel: &str) -> Result<bool, String> {
        let n: i64 = self
            .c
            .query_row(
                &format!("SELECT COUNT(*) FROM ({EXISTS_SQL})"),
                [channel],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        self.steps.borrow_mut().push(("exists", 0));
        Ok(n > 0)
    }
}

fn answer(c: &Connection, channel: &str) -> SectionAnswer {
    run(&Sqlite::new(c), channel, true)
}

/// The answer through `db`, indexed or not; panics for a missing section.
fn run(db: &Sqlite<'_>, channel: &str, indexed: bool) -> SectionAnswer {
    block_on(compute(db, channel, NOW, indexed))
        .unwrap()
        .0
        .expect("the section exists")
}

// ---------------------------------------------------------------------------
// Event shapes, as the forum writes them
// ---------------------------------------------------------------------------

fn hex(n: u64) -> String {
    format!("{n:064x}")
}

fn tag(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn ev(id: &str, pk: &str, ts: u64, kind: u64, tags: Vec<Vec<String>>) -> NostrEvent {
    NostrEvent {
        id: id.to_string(),
        pubkey: pk.to_string(),
        created_at: ts,
        kind,
        tags,
        content: format!("c{id}"),
        sig: "00".repeat(64),
    }
}

fn root(id: &str, ch: &str, pk: &str, ts: u64) -> NostrEvent {
    let mut tags = nostr_bbs_client_core::topics::topic_root_tags(ch);
    tags.push(tag(&["p", pk]));
    ev(id, pk, ts, 42, tags)
}

fn reply(id: &str, ch: &str, root_id: &str, pk: &str, ts: u64) -> NostrEvent {
    ev(
        id,
        pk,
        ts,
        42,
        nostr_bbs_client_core::topics::topic_reply_tags(ch, root_id, "", None),
    )
}

fn edit(id: &str, ch: &str, root_id: &str, target: &str, pk: &str, ts: u64) -> NostrEvent {
    ev(
        id,
        pk,
        ts,
        42,
        nostr_bbs_client_core::topics::edit_tags(ch, Some((root_id, "")), target),
    )
}

/// A sealed envelope (outer shape only; the content is never opened here).
fn sealed(id: &str, ch: &str, inner: &str, reply_to: Option<&str>, ts: u64) -> NostrEvent {
    let mut tags = vec![
        tag(&["e", ch, "", "root"]),
        tag(&["zk", "staff", "1", &"ab".repeat(32)]),
        tag(&["sealed", inner, "1"]),
    ];
    match reply_to {
        Some(r) => tags.push(tag(&["e", r, "", "reply"])),
        None => tags.push(tag(&["t", "topic"])),
    }
    ev(id, MIGRATOR, ts, 42, tags)
}

const MIGRATOR: &str = "9999999999999999999999999999999999999999999999999999999999999999";

/// The oracle: the clients' `classify_topics` over what the client store
/// would file under `channel` (events whose own channel it is), minus
/// expired events. Deleted events are simply absent.
fn oracle(channel: &str, all: &[NostrEvent]) -> Vec<nostr_bbs_client_core::topics::TopicSummary> {
    let filed: Vec<NostrEvent> = all
        .iter()
        .filter(|e| nostr_bbs_core::sealed::channel_of(e) == Some(channel))
        .filter(|e| {
            !super::super::filter::tag_value(e, "expiration")
                .and_then(|x| x.parse::<u64>().ok())
                .is_some_and(|x| x < NOW)
        })
        .cloned()
        .collect();
    nostr_bbs_client_core::topics::classify_topics(channel, &filed)
}

/// Every relay topic is a classified topic with the same last activity and
/// reply count; every classified topic carrying the marker is listed.
fn assert_matches_oracle(a: &SectionAnswer, channel: &str, all: &[NostrEvent]) {
    let truth = oracle(channel, all);
    let by_id: HashMap<&str, &nostr_bbs_client_core::topics::TopicSummary> =
        truth.iter().map(|t| (t.id.as_str(), t)).collect();
    for t in &a.topics {
        let o = by_id
            .get(t.id.as_str())
            .unwrap_or_else(|| panic!("relay lists {} which classify_topics does not", t.id));
        assert_eq!(
            t.last_at,
            Some(o.last_activity),
            "last activity of {}",
            t.id
        );
        assert_eq!(t.replies, Some(o.reply_count as u64), "replies of {}", t.id);
        if let Some(pk) = &t.last_pubkey {
            assert_eq!(pk, &o.last_pubkey, "last author of {}", t.id);
        }
    }
    let listed: HashSet<&str> = a.topics.iter().map(|t| t.id.as_str()).collect();
    let stored: HashMap<&str, &NostrEvent> = all.iter().map(|e| (e.id.as_str(), e)).collect();
    for o in &truth {
        let marked = stored.get(o.id.as_str()).is_some_and(|e| {
            e.tags
                .iter()
                .any(|t| t.len() >= 2 && t[0] == "t" && t[1] == "topic")
        });
        if marked {
            assert!(
                listed.contains(o.id.as_str()),
                "marked topic {} missing",
                o.id
            );
        }
    }
    // Board order: newest activity first, ties by id.
    let keys: Vec<(u64, &str)> = a
        .topics
        .iter()
        .map(|t| (t.last_at.unwrap_or(t.created_at), t.id.as_str()))
        .collect();
    let mut sorted = keys.clone();
    sorted.sort_by(|x, y| y.0.cmp(&x.0).then(x.1.cmp(y.1)));
    assert_eq!(keys, sorted, "answer is in board order");
}

/// A small deterministic generator.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const C: &str = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";
const D: &str = "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0";

/// A seeded section: plain topics with replies, edits, reactions and
/// quotes; expired replies; sealed roots with sealed and live replies; a
/// dual-present original; a legacy unmarked root; crafted events in `D`
/// naming `C`'s roots; then a set of deletions. Returns what is stored.
fn seeded(c: &Connection, seed: u64) -> Vec<NostrEvent> {
    let mut rng = Lcg(seed);
    let mut next_id = 1_000u64;
    let mut id = || {
        next_id += 1;
        hex(next_id)
    };
    let mut all: Vec<NostrEvent> = Vec::new();
    let pk = |n: u64| format!("{:064x}", 0xa000 + n);
    let mut roots: Vec<String> = Vec::new();
    for t in 0..24u64 {
        let rid = id();
        let base = 1_000_000 + t * 1_000 + rng.below(500);
        all.push(root(&rid, C, &pk(t % 5), base));
        let n = rng.below(12);
        let mut last_reply: Option<String> = None;
        for k in 0..n {
            let r = id();
            all.push(reply(
                &r,
                C,
                &rid,
                &pk(rng.below(7)),
                base + 10 + k * 7 + rng.below(5),
            ));
            last_reply = Some(r);
        }
        // An edit newer than everything: never activity.
        if let Some(target) = &last_reply {
            if rng.below(2) == 0 {
                all.push(edit(&id(), C, &rid, target, &pk(1), base + 5_000));
            }
        }
        if rng.below(3) == 0 {
            all.push(edit(&id(), C, &rid, &rid, &pk(t % 5), base + 6_000));
        }
        // Reactions to the root (kind 7) and an expired reply.
        for _ in 0..rng.below(4) {
            all.push(ev(
                &id(),
                &pk(3),
                base + 7_000,
                7,
                vec![tag(&["e", &rid]), tag(&["p", &pk(0)])],
            ));
        }
        if rng.below(3) == 0 {
            let mut x = reply(&id(), C, &rid, &pk(2), base + 8_000);
            x.tags.push(tag(&["expiration", &(NOW - 1).to_string()]));
            all.push(x);
        }
        if rng.below(4) == 0 {
            let mut x = reply(&id(), C, &rid, &pk(4), base + 900);
            x.tags.push(tag(&["expiration", &(NOW + 100).to_string()]));
            all.push(x);
        }
        roots.push(rid);
    }
    // Sealed roots: replies name the ORIGINAL id (outer `reply` tag).
    for s in 0..3u64 {
        let env = id();
        let inner = id();
        let base = 1_100_000 + s * 50;
        all.push(sealed(&env, C, &inner, None, base));
        all.push(sealed(&id(), C, &id(), Some(&inner), base + 5));
        all.push(reply(&id(), C, &inner, &pk(6), base + 9 + s));
    }
    // Dual-present: the plaintext original beside its envelope.
    let orig = id();
    let env = id();
    all.push(root(&orig, C, &pk(2), 1_050_000));
    all.push(sealed(&env, C, &orig, None, 1_050_000));
    all.push(reply(&id(), C, &orig, &pk(3), 1_050_010));
    all.push(reply(&id(), C, &env, &pk(4), 1_050_020));
    // A legacy root without the marker (classify lists it; the relay cannot).
    all.push(ev(
        &id(),
        &pk(1),
        1_000_500,
        42,
        vec![tag(&["e", C, "", "root"])],
    ));
    // Crafted: a reply filed in D naming a C root, and a marked root of D
    // that also e-tags C without the root marker.
    all.push(reply(&id(), D, &roots[0], &pk(5), 1_999_000));
    all.push(ev(
        &id(),
        &pk(5),
        1_999_001,
        42,
        vec![
            tag(&["e", D, "", "root"]),
            tag(&["e", C]),
            tag(&["t", "topic"]),
        ],
    ));
    // A reply whose `reply` marker precedes a quote of the root.
    let quoted = id();
    all.push(ev(
        &quoted,
        &pk(6),
        1_002_400,
        42,
        vec![
            tag(&["e", C, "", "root"]),
            tag(&["e", &roots[2], "", "reply"]),
            tag(&["e", &roots[3], "", "quote"]),
        ],
    ));
    store(c, &all);

    // Deletions: a root, some replies (the newest of a topic among them).
    let mut gone: HashSet<String> = HashSet::new();
    gone.insert(roots[5].clone());
    let replies_of = |r: &str| -> Vec<String> {
        all.iter()
            .filter(|e| {
                e.kind == 42
                    && nostr_bbs_core::sealed::reply_root_of(e) == Some(r)
                    && nostr_bbs_client_core::topics::edit_target_of(e).is_none()
            })
            .map(|e| e.id.clone())
            .collect()
    };
    for r in [&roots[1], &roots[7], &roots[11]] {
        if let Some(newest) = all
            .iter()
            .filter(|e| replies_of(r).contains(&e.id))
            .max_by_key(|e| e.created_at)
        {
            gone.insert(newest.id.clone());
        }
    }
    for g in &gone {
        delete(c, g);
    }
    all.retain(|e| !gone.contains(&e.id));
    all
}

#[test]
fn answer_equals_classify_topics_on_seeded_sections() {
    for seed in 1..=12u64 {
        let c = db();
        let all = seeded(&c, seed);
        let a = answer(&c, C);
        assert!(!a.truncated);
        assert_matches_oracle(&a, C, &all);
        // 24 plain roots (one deleted), 3 sealed, 1 dual-present.
        assert_eq!(a.topics.len(), 23 + 3 + 1, "seed {seed}");
        // The fallback walk (no 0017 index) gives the same answer.
        let s = Sqlite::new(&c);
        let walked = run(&s, C, false);
        assert_eq!(walked.topics, a.topics, "seed {seed}: walk = index");
    }
}

#[test]
fn a_missing_index_falls_back_to_the_walk_and_says_so() {
    let c = db_without_index();
    store(&c, &[root(&hex(1), C, &hex(7), 100)]);
    let (a, absent) = block_on(compute(&Sqlite::new(&c), C, NOW, true)).unwrap();
    assert!(
        absent,
        "the index error is reported for the caller to remember"
    );
    assert_eq!(a.unwrap().topics.len(), 1);
    // A section with no roots and no kind-40 does not exist.
    let (none, _) = block_on(compute(&Sqlite::new(&c), D, NOW, false)).unwrap();
    assert_eq!(none, None);
}

#[test]
fn deleted_root_and_newest_reply_are_not_counted() {
    let c = db();
    let r = hex(1);
    let a1 = hex(2);
    let a2 = hex(3);
    store(
        &c,
        &[
            root(&r, C, &hex(9), 100),
            reply(&a1, C, &r, &hex(8), 110),
            reply(&a2, C, &r, &hex(7), 120),
        ],
    );
    let before = answer(&c, C);
    assert_eq!(before.topics[0].last_at, Some(120));
    assert_eq!(before.topics[0].replies, Some(2));
    delete(&c, &a2);
    let after = answer(&c, C);
    assert_eq!(after.topics[0].last_at, Some(110));
    assert_eq!(after.topics[0].replies, Some(1));
    assert_eq!(
        after.topics[0].last_pubkey.as_deref(),
        Some(hex(8).as_str())
    );
    delete(&c, &r);
    // No root and no kind-40 left: the section is unknown, refused like a
    // gated one. With its kind-40 stored it is an empty, existing section.
    let (gone, _) = block_on(compute(&Sqlite::new(&c), C, NOW, true)).unwrap();
    assert_eq!(gone, None);
    store(&c, &[ev(C, &hex(7), 1, 40, vec![])]);
    assert!(answer(&c, C).topics.is_empty());
}

#[test]
fn sealed_root_reports_envelope_id_with_original_and_hides_the_migrator() {
    let c = db();
    let env = hex(1);
    let inner = hex(2);
    store(
        &c,
        &[
            sealed(&env, C, &inner, None, 100),
            sealed(&hex(3), C, &hex(4), Some(&inner), 150),
        ],
    );
    let a = answer(&c, C);
    let t = &a.topics[0];
    assert_eq!(t.id, env);
    assert_eq!(t.original.as_deref(), Some(inner.as_str()));
    assert_eq!((t.last_at, t.replies), (Some(150), Some(1)));
    assert_eq!(
        t.last_pubkey, None,
        "a sealed reply's outer author is the migrator"
    );
    // A live reply naming the original is newer: its author is shown.
    store(&c, &[reply(&hex(5), C, &inner, &hex(6), 160)]);
    let t = answer(&c, C).topics[0].clone();
    assert_eq!((t.last_at, t.replies), (Some(160), Some(2)));
    assert_eq!(t.last_pubkey.as_deref(), Some(hex(6).as_str()));
}

#[test]
fn dual_present_original_is_the_topic_and_counts_replies_to_either_id() {
    let c = db();
    let orig = hex(1);
    let env = hex(2);
    store(
        &c,
        &[
            root(&orig, C, &hex(7), 100),
            sealed(&env, C, &orig, None, 100),
            reply(&hex(3), C, &orig, &hex(8), 110),
            reply(&hex(4), C, &env, &hex(9), 130),
        ],
    );
    let a = answer(&c, C);
    assert_eq!(a.topics.len(), 1);
    let t = &a.topics[0];
    assert_eq!(
        (t.id.as_str(), t.original.as_deref()),
        (orig.as_str(), None)
    );
    assert_eq!((t.last_at, t.replies), (Some(130), Some(2)));
}

#[test]
fn crafted_cross_channel_events_leak_nothing() {
    // A hidden channel D holds a reply naming C's root and a marked root
    // that also e-tags C: neither may reach C's readers.
    let c = db();
    let r = hex(1);
    store(
        &c,
        &[
            root(&r, C, &hex(7), 100),
            reply(&hex(2), D, &r, &hex(8), 500),
            ev(
                &hex(3),
                &hex(8),
                600,
                42,
                vec![
                    tag(&["e", D, "", "root"]),
                    tag(&["e", C]),
                    tag(&["t", "topic"]),
                ],
            ),
        ],
    );
    let a = answer(&c, C);
    assert_eq!(a.topics.len(), 1);
    assert_eq!(
        (a.topics[0].last_at, a.topics[0].replies),
        (Some(100), Some(0))
    );
}

#[test]
fn edits_and_reactions_are_not_activity() {
    let c = db();
    let r = hex(1);
    store(
        &c,
        &[
            root(&r, C, &hex(7), 100),
            reply(&hex(2), C, &r, &hex(8), 110),
            edit(&hex(3), C, &r, &hex(2), &hex(8), 900),
            edit(&hex(4), C, &r, &r, &hex(7), 950),
            ev(&hex(5), &hex(6), 990, 7, vec![tag(&["e", &r])]),
        ],
    );
    let t = answer(&c, C).topics[0].clone();
    assert_eq!((t.last_at, t.replies), (Some(110), Some(1)));
}

#[test]
fn expired_roots_and_replies_are_not_counted() {
    let c = db();
    let r = hex(1);
    let gone = hex(2);
    let mut exp_root = root(&gone, C, &hex(7), 200);
    exp_root
        .tags
        .push(tag(&["expiration", &(NOW - 5).to_string()]));
    let mut exp_reply = reply(&hex(3), C, &r, &hex(8), 300);
    exp_reply
        .tags
        .push(tag(&["expiration", &(NOW - 5).to_string()]));
    let mut live_reply = reply(&hex(4), C, &r, &hex(9), 250);
    live_reply
        .tags
        .push(tag(&["expiration", &(NOW + 5).to_string()]));
    store(
        &c,
        &[root(&r, C, &hex(7), 100), exp_root, exp_reply, live_reply],
    );
    let a = answer(&c, C);
    assert_eq!(a.topics.len(), 1);
    assert_eq!(
        (a.topics[0].last_at, a.topics[0].replies),
        (Some(250), Some(1))
    );
}

#[test]
fn more_roots_than_the_cap_truncate_to_the_newest() {
    let c = db();
    let events: Vec<NostrEvent> = (0..MAX_TOPICS as u64 + 5)
        .map(|n| root(&hex(n + 1), C, &hex(7), 1_000 + n))
        .collect();
    store(&c, &events);
    let a = answer(&c, C);
    assert!(a.truncated);
    assert_eq!(a.topics.len(), MAX_TOPICS);
    let oldest_kept = a.topics.iter().map(|t| t.created_at).min().unwrap();
    assert_eq!(oldest_kept, 1_005, "the oldest-created roots are dropped");
    assert_eq!(a.payload()["truncated"], serde_json::json!(true));
}

#[test]
fn a_topic_past_the_count_visit_cap_reports_an_unknown_count() {
    let c = db();
    let big = hex(1);
    let small = hex(2);
    let mut events = vec![root(&big, C, &hex(7), 100), root(&small, C, &hex(7), 101)];
    for n in 0..COUNT_VISIT_CAP {
        events.push(reply(&hex(10 + n), C, &big, &hex(8), 200 + n));
    }
    events.push(reply(&hex(5_000), C, &small, &hex(8), 150));
    store(&c, &events);
    let a = answer(&c, C);
    let by: HashMap<&str, &TopicStat> = a.topics.iter().map(|t| (t.id.as_str(), t)).collect();
    assert_eq!(by[big.as_str()].replies, None);
    assert_eq!(by[big.as_str()].last_at, Some(200 + COUNT_VISIT_CAP - 1));
    assert_eq!(by[small.as_str()].replies, Some(1));
}

#[test]
fn counting_stops_at_the_budget() {
    // 150 topics of 200 replies: the first statement (100 topics) visits
    // 20,000 count rows, the budget; the next reports activity only.
    let c = db();
    let mut events = Vec::new();
    let mut n = 10_000u64;
    for t in 0..150u64 {
        let r = hex(1 + t);
        events.push(root(&r, C, &hex(7), 100 + t));
        for k in 0..200u64 {
            n += 1;
            events.push(reply(&hex(n), C, &r, &hex(8), 100_000 + t * 1_000 + k));
        }
    }
    store(&c, &events);
    let a = answer(&c, C);
    let counted: Vec<bool> = a.topics.iter().map(|t| t.replies.is_some()).collect();
    let k = counted.iter().take_while(|x| **x).count();
    assert!(
        counted[k..].iter().all(|x| !x),
        "counted is a prefix: {counted:?}"
    );
    assert_eq!(k, STATS_BATCH, "{counted:?}");
    assert!(a.topics[..k].iter().all(|t| t.replies == Some(200)));
    assert!(
        a.topics.iter().all(|t| t.last_at.is_some()),
        "activity for all"
    );
}

#[test]
fn a_walk_that_runs_out_reports_unknown_activity_not_a_wrong_one() {
    let c = db();
    let r = hex(1);
    let mut events = vec![
        root(&r, C, &hex(7), 100),
        reply(&hex(2), C, &r, &hex(8), 110),
    ];
    for n in 0..ACTIVITY_WALK_ROWS as u64 {
        events.push(ev(
            &hex(100 + n),
            &hex(6),
            200 + n,
            7,
            vec![tag(&["e", &r])],
        ));
    }
    store(&c, &events);
    let t = answer(&c, C).topics[0].clone();
    assert_eq!(t.last_at, None);
    assert_eq!(t.last_pubkey, None);
    assert_eq!(t.replies, Some(1), "the count still holds");
}

#[test]
fn payload_lists_fields_in_board_order() {
    let c = db();
    store(
        &c,
        &[
            root(&hex(1), C, &hex(7), 100),
            root(&hex(2), C, &hex(7), 200),
            reply(&hex(3), C, &hex(1), &hex(8), 300),
        ],
    );
    let p = answer(&c, C).payload();
    assert_eq!(p["fields"], serde_json::json!(FIELDS));
    assert_eq!(p["channel"], serde_json::json!(C));
    assert_eq!(
        p["topics"],
        serde_json::json!([
            [hex(1), 100, 300, hex(8), 1, null],
            [hex(2), 200, 200, hex(7), 0, null]
        ])
    );
}

// ---------------------------------------------------------------------------
// Cost
// ---------------------------------------------------------------------------

/// Seed `topics` topics of `replies` replies each in `C`, plus `noise`
/// messages in `D`, and return the VM steps of each statement kind.
fn cost(topics: u64, replies: u64, noise: u64) -> (i32, i32, i32) {
    let c = db();
    let mut events = Vec::new();
    let mut n = 1_000_000u64;
    for t in 0..topics {
        let r = hex(1 + t);
        events.push(root(&r, C, &hex(7), 100 + t));
        for k in 0..replies {
            n += 1;
            events.push(reply(&hex(n), C, &r, &hex(8), 1_000 + t * replies + k));
        }
    }
    for k in 0..noise {
        n += 1;
        events.push(reply(&hex(n), D, &hex(999_999), &hex(8), 5_000_000 + k));
    }
    store(&c, &events);
    let s = Sqlite::new(&c);
    run(&s, C, true);
    (s.steps("roots"), s.steps("stats"), 0)
}

#[test]
fn root_cost_ignores_other_channels() {
    // Other channels' traffic costs the roots statement nothing.
    let (quiet, _, _) = cost(20, 5, 0);
    let (busy, _, _) = cost(20, 5, 20_000);
    assert!(busy < quiet * 2, "root steps {quiet} -> {busy}");
}

#[test]
fn stats_cost_stops_growing_with_topic_size() {
    // Every topic past the caps: doubling each topic's replies leaves the
    // statements' work where it was.
    let (_, a, _) = cost(10, 1_500, 0);
    let (_, b, _) = cost(10, 3_000, 0);
    assert!(b * 10 < a * 12, "stats steps {a} -> {b}");
}

/// Aliases of the base tables in the statements: a `SCAN` of any of them is
/// a full table scan. (`SCAN x` reads the bounded walk subquery, `SCAN jv`
/// / `jt` / `js` the JSON table-valued functions.)
const TABLE_ALIASES: [&str; 8] = ["events", "event_tags", "ev", "r", "t", "c", "w", "s"];

#[test]
fn no_statement_scans_events_or_the_channel() {
    let c = db();
    let base = || vec![Value::Text(C.into()), Value::Integer(NOW as i64)];
    let with = |mut v: Vec<Value>, more: Vec<Value>| {
        v.extend(more);
        v
    };
    for (sql, params) in [
        (roots_indexed_sql(), with(base(), vec![Value::Integer(10)])),
        (
            roots_walk_sql(),
            with(base(), vec![Value::Integer(10), Value::Integer(100)]),
        ),
        (
            stats_sql(true),
            with(
                base(),
                vec![
                    ids(&[hex(1)]),
                    Value::Integer(ACTIVITY_WALK_ROWS),
                    Value::Integer(10),
                ],
            ),
        ),
    ] {
        let plan: Vec<String> = c
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap()
            .query_map(rusqlite::params_from_iter(params.iter()), |r| {
                r.get::<_, String>(3)
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        for line in &plan {
            let mut words = line.split_whitespace();
            if words.next() == Some("SCAN") {
                let alias = words.next().unwrap_or("");
                assert!(
                    !TABLE_ALIASES.contains(&alias),
                    "full scan in plan: {plan:?}"
                );
            }
        }
        assert!(
            plan.iter().any(|l| l.contains("idx_event_tags_time")
                || l.contains("idx_event_tags_lookup")
                || l.contains("idx_events_topic_root_channel")),
            "plan: {plan:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Admission: the REQ/COUNT rule, by viewer class
// ---------------------------------------------------------------------------

const PINNED: &str = "5555555555555555555555555555555555555555555555555555555555555555";

/// "members": locked, encrypted; "lobby": public; "staff": hidden,
/// encrypted, pins `PINNED` (whose D1 row still says "members").
fn zones() -> ZoneConfig {
    ZoneConfig::from_json(&format!(
        r#"[{{"id":"members","required_cohorts":["members"],"visibility":"locked","encrypted":true}},
            {{"id":"lobby","required_cohorts":[],"visibility":"public"}},
            {{"id":"staff","required_cohorts":["staff"],"visibility":"hidden","encrypted":true,
              "channels":["{PINNED}"]}}]"#
    ))
    .with_encryption(true)
}

fn viewer(cohorts: &[&str], authed: bool, admin: bool) -> ViewerContext {
    ViewerContext {
        session_pubkey: authed.then(|| "s".repeat(64)),
        access_pubkey: authed.then(|| "s".repeat(64)),
        is_admin: admin,
        viewer_cohorts: cohorts.iter().map(|c| c.to_string()).collect(),
        viewer_is_admin: admin,
        recipient_keys: vec![],
    }
}

fn zone_of(
    channel: &str,
    d1: Result<Option<String>, ZoneLookupError>,
) -> Result<Option<String>, ZoneLookupError> {
    block_on(resolve_channel_zone(&zones(), channel, || {
        std::future::ready(d1)
    }))
}

#[test]
fn admission_matrix_matches_the_channel_read_rule() {
    let z = zones();
    let members = zone_of(C, Ok(Some("members".into())));
    let lobby = zone_of(C, Ok(Some("lobby".into())));
    let unscoped = zone_of(C, Ok(None));
    let failed = zone_of(C, Err(ZoneLookupError));
    let pinned = zone_of(PINNED, Ok(Some("members".into())));

    let anon = viewer(&[], false, false);
    let outsider = viewer(&["other"], true, false);
    let member = viewer(&["members"], true, false);
    let staff = viewer(&["staff"], true, false);
    let admin = viewer(&[], true, true);

    let cases = [
        (
            "unauthenticated, gated zone",
            &members,
            &anon,
            Admission::Refuse(REFUSE_AUTH),
        ),
        (
            "wrong cohort",
            &members,
            &outsider,
            Admission::Refuse(REFUSE_RESTRICTED),
        ),
        (
            "right cohort, encrypted zone",
            &members,
            &member,
            Admission::Admit,
        ),
        ("admin bypass", &members, &admin, Admission::Admit),
        (
            "public zone, unauthenticated",
            &lobby,
            &anon,
            Admission::Admit,
        ),
        (
            "unscoped channel, unauthenticated",
            &unscoped,
            &anon,
            Admission::Admit,
        ),
        (
            "zone lookup failed: closed",
            &failed,
            &member,
            Admission::Refuse(REFUSE_RESTRICTED),
        ),
        (
            "zone lookup failed, admin",
            &failed,
            &admin,
            Admission::Refuse(REFUSE_RESTRICTED),
        ),
        (
            "pinned: old-zone member",
            &pinned,
            &member,
            Admission::Refuse(REFUSE_RESTRICTED),
        ),
        ("pinned: new-zone member", &pinned, &staff, Admission::Admit),
        ("pinned: admin", &pinned, &admin, Admission::Admit),
        (
            "pinned: unauthenticated",
            &pinned,
            &anon,
            Admission::Refuse(REFUSE_AUTH),
        ),
    ];
    for (name, lookup, ctx, want) in cases {
        assert_eq!(admission(lookup, &z, ctx), want, "{name}");
        // The same answer the REQ/COUNT gate gives the channel's kind-42s.
        let delivered = matches!(
            channel_read_decision_for(42, lookup, &z, ctx),
            ReadDecision::Deliver
        );
        assert_eq!(delivered, want == Admission::Admit, "{name}: REQ parity");
    }
    assert_eq!(
        pinned,
        Ok(Some("staff".to_string())),
        "the pin decides before D1"
    );
}

#[test]
fn a_missing_section_is_refused_like_an_unreadable_one() {
    // `handle_section_stats` answers a section with no kind-40 and no
    // creator row with `refusal_for(ctx)`: the same text a gated one gets.
    assert_eq!(refusal_for(&viewer(&[], false, false)), REFUSE_AUTH);
    assert_eq!(refusal_for(&viewer(&["x"], true, false)), REFUSE_RESTRICTED);
    let c = db();
    let hits = |id: &str| -> i64 {
        c.query_row(&format!("SELECT COUNT(*) FROM ({EXISTS_SQL})"), [id], |r| {
            r.get(0)
        })
        .unwrap()
    };
    assert_eq!(hits(C), 0);
    store(&c, &[ev(C, &hex(7), 1, 40, vec![])]);
    assert_eq!(hits(C), 1);
    c.execute(
        "INSERT INTO channel_creators (channel_id, pubkey, created_at) VALUES (?1, 'p', 1)",
        [D],
    )
    .unwrap();
    assert_eq!(hits(D), 1, "a deleted kind-40 still has its creator row");
}

#[test]
fn requests_name_a_canonical_channel() {
    let ok = serde_json::json!({ "channel": C });
    assert_eq!(requested_channel(&ok).as_deref(), Some(C));
    for bad in [
        serde_json::json!({}),
        serde_json::json!({ "channel": C.to_uppercase() }),
        serde_json::json!({ "channel": &C[..63] }),
        serde_json::json!({ "channel": 5 }),
        serde_json::Value::Null,
    ] {
        assert_eq!(requested_channel(&bad), None, "{bad}");
    }
}

#[test]
fn nip11_advertises_the_verb_and_caps() {
    let a = super::super::section_stats_advert();
    assert_eq!(a["verb"], "SECTION-STATS");
    assert_eq!(a["version"], VERSION);
    assert_eq!(a["max_topics"], MAX_TOPICS);
}

/// Measurement for ADR-2038 (not a gate; run with `--ignored --nocapture`):
/// statement VM steps and native wall time for sections of growing size,
/// with other channels' traffic on the relay. SQLite here, not D1.
#[test]
#[ignore = "measurement, minutes of seeding; run by hand"]
fn measure_section_stats_cost() {
    for (topics, replies, noise_roots) in [
        (168u64, 20u64, 0u64),
        (168, 600, 0),
        (1_000, 100, 2_000),
        (2_000, 50, 5_000),
    ] {
        let c = db();
        let mut events = Vec::new();
        let mut n = 10_000_000u64;
        for t in 0..topics {
            let r = hex(1 + t);
            events.push(root(&r, C, &hex(7), 100 + t));
            for k in 0..replies {
                n += 1;
                events.push(reply(&hex(n), C, &r, &hex(8), 1_000 + t * replies + k));
            }
        }
        for k in 0..noise_roots {
            n += 1;
            events.push(root(&hex(n), D, &hex(7), 50 + k));
        }
        store(&c, &events);
        let s = Sqlite::new(&c);
        let t0 = std::time::Instant::now();
        let a = run(&s, C, true);
        let ms = t0.elapsed().as_millis();
        println!(
            "topics {topics:>5} x replies {replies:>4} = {:>7} msgs in C, {noise_roots:>5} other roots: \
             listed {:>4} truncated {:<5} counted {:>4} | steps roots {:>9} stats {:>9} | {ms} ms",
            topics * (replies + 1),
            a.topics.len(),
            a.truncated,
            a.topics.iter().filter(|t| t.replies.is_some()).count(),
            s.steps("roots"),
            s.steps("stats"),
        );
    }
}

/// Review scenarios (PR #134 follow-up), measured before and after the fix
/// (run with `--ignored --nocapture`): the common case, a topic buried in
/// reactions, and a small section on a relay with many topics elsewhere.
#[test]
#[ignore = "measurement; run by hand"]
fn measure_review_scenarios() {
    struct Case {
        name: &'static str,
        topics: u64,
        replies: u64,
        reactions_on_first: u64,
        other_roots: u64,
    }
    for case in [
        Case {
            name: "common: 300 topics x 30 replies, 2k roots elsewhere",
            topics: 300,
            replies: 30,
            reactions_on_first: 0,
            other_roots: 2_000,
        },
        Case {
            name: "worst: 20 topics, one with 3 replies + 50k reactions",
            topics: 20,
            replies: 3,
            reactions_on_first: 50_000,
            other_roots: 0,
        },
        Case {
            name: "worst: 10-topic section, 50k topic roots elsewhere",
            topics: 10,
            replies: 5,
            reactions_on_first: 0,
            other_roots: 50_000,
        },
    ] {
        let c = db();
        let mut events = Vec::new();
        let mut n = 10_000_000u64;
        for t in 0..case.topics {
            let r = hex(1 + t);
            events.push(root(&r, C, &hex(7), 100 + t));
            for k in 0..case.replies {
                n += 1;
                events.push(reply(&hex(n), C, &r, &hex(8), 1_000 + t * case.replies + k));
            }
        }
        for k in 0..case.reactions_on_first {
            n += 1;
            events.push(ev(
                &hex(n),
                &hex(6),
                900_000 + k,
                7,
                vec![tag(&["e", &hex(1)])],
            ));
        }
        for k in 0..case.other_roots {
            n += 1;
            events.push(root(&hex(n), D, &hex(7), 800_000 + k));
        }
        store(&c, &events);
        let s = Sqlite::new(&c);
        let t0 = std::time::Instant::now();
        let a = run(&s, C, true);
        let ms = t0.elapsed().as_millis();
        let steps = s.steps.borrow();
        let total: i64 = steps.iter().map(|(_, v)| *v as i64).sum();
        println!(
            "{:<55} statements {:>3} VM steps {:>10} | {:>4} ms | listed {:>4} counted {:>4} truncated {}",
            case.name,
            steps.len(),
            total,
            ms,
            a.topics.len(),
            a.topics.iter().filter(|t| t.replies.is_some()).count(),
            a.truncated
        );
    }
}

// ---------------------------------------------------------------------------
// PR #134 review: work bounded by rows visited, not only rows that qualify
// ---------------------------------------------------------------------------

/// Total VM steps of one answer for a section of 20 topics (5 replies each)
/// whose first topic also carries `reactions` kind-7 references, and a relay
/// holding `other_roots` topic roots in another channel, newer than ours.
fn visited_cost(reactions: u64, other_roots: u64, with_index: bool) -> (i64, SectionAnswer) {
    let c = if with_index { db() } else { db_without_index() };
    let mut events = Vec::new();
    let mut n = 50_000_000u64;
    for t in 0..20u64 {
        let r = hex(1 + t);
        events.push(root(&r, C, &hex(7), 100 + t));
        for k in 0..5u64 {
            n += 1;
            events.push(reply(&hex(n), C, &r, &hex(8), 1_000 + t * 5 + k));
        }
    }
    for k in 0..reactions {
        n += 1;
        events.push(ev(
            &hex(n),
            &hex(6),
            900_000 + k,
            7,
            vec![tag(&["e", &hex(1)])],
        ));
    }
    for k in 0..other_roots {
        n += 1;
        events.push(root(&hex(n), D, &hex(7), 800_000 + k));
    }
    store(&c, &events);
    let s = Sqlite::new(&c);
    let a = run(&s, C, with_index);
    let total = s.steps.borrow().iter().map(|(_, v)| *v as i64).sum();
    (total, a)
}

#[test]
fn a_topic_buried_in_reactions_costs_a_bounded_walk() {
    let (few, a) = visited_cost(4_000, 0, true);
    let (many, b) = visited_cost(16_000, 0, true);
    assert!(
        many * 10 < few * 13,
        "steps {few} -> {many}: the walk must stop at its cap"
    );
    let first = |x: &SectionAnswer| x.topics.iter().find(|t| t.id == hex(1)).cloned().unwrap();
    assert_eq!(
        first(&b).replies,
        None,
        "past the visit cap the count is unknown"
    );
    assert_eq!(first(&b).last_at, None, "and so is the last activity");
    assert_eq!(first(&a).replies, None);
    // Every other topic keeps its exact figures.
    assert!(b
        .topics
        .iter()
        .filter(|t| t.id != hex(1))
        .all(|t| t.replies == Some(5)));
}

#[test]
fn a_small_section_does_not_pay_for_the_whole_relay() {
    // With the 0017 index: the roots statement reads only this channel's.
    let (few, a) = visited_cost(0, 2_000, true);
    let (many, b) = visited_cost(0, 16_000, true);
    assert!(many * 10 < few * 13, "steps {few} -> {many}");
    assert_eq!((a.topics.len(), b.topics.len()), (20, 20));
    assert!(!b.truncated);
    // Without it: a bounded walk that says it stopped.
    let (_, w) = visited_cost(0, ROOTS_VISIT_CAP as u64 + 10, false);
    assert!(w.truncated, "a walk that hit its cap reports truncated");
}

#[test]
fn expiry_parses_as_the_req_path_does() {
    // REQ: `u64::parse` of the first `expiration` value, expired if < now.
    let c = db();
    let r = hex(1);
    let mut plus = reply(&hex(2), C, &r, &hex(8), 110);
    plus.tags.push(tag(&["expiration", "+1"]));
    let mut padded = reply(&hex(3), C, &r, &hex(8), 120);
    padded
        .tags
        .push(tag(&["expiration", &format!("{:0>24}", 5)]));
    let mut junk = reply(&hex(4), C, &r, &hex(8), 130);
    junk.tags.push(tag(&["expiration", "12x"]));
    store(&c, &[root(&r, C, &hex(7), 100), plus, padded, junk]);
    for e in ["+1", &format!("{:0>24}", 5), "12x"] {
        let parsed = e.parse::<u64>().ok().is_some_and(|x| x < NOW);
        assert_eq!(parsed, e != "12x", "{e}");
    }
    let t = answer(&c, C).topics[0].clone();
    assert_eq!(
        (t.replies, t.last_at),
        (Some(1), Some(130)),
        "only the unparsable one stays"
    );
}

// ---------------------------------------------------------------------------
// Single flight (PR #134 review finding 1)
// ---------------------------------------------------------------------------

#[test]
fn readers_of_one_channel_share_one_computation() {
    let sf = SingleFlight::default();
    let Role::Lead(lead) = sf.begin("a") else {
        panic!("first is the leader")
    };
    let Role::Wait(w1) = sf.begin("a") else {
        panic!("second waits")
    };
    let Role::Wait(w2) = sf.begin("a") else {
        panic!("third waits")
    };
    let answer: Shared = Ok(Some(serde_json::json!({"topics": []})));
    lead.finish(answer.clone());
    assert_eq!(block_on(w1.wait()), answer);
    assert_eq!(block_on(w2.wait()), answer);
    // Released: the next reader of the channel leads a new computation.
    assert!(matches!(sf.begin("a"), Role::Lead(_)));
}

#[test]
fn computations_are_capped_across_channels_and_released_on_drop() {
    let sf = SingleFlight::default();
    let a = sf.begin("a");
    let b = sf.begin("b");
    assert!(matches!((&a, &b), (Role::Lead(_), Role::Lead(_))));
    assert!(matches!(sf.begin("c"), Role::Busy), "cap {MAX_CONCURRENT}");
    let Role::Wait(w) = sf.begin("a") else {
        panic!("a is running")
    };
    drop(a); // abandoned (e.g. the request errored before finish)
    assert!(block_on(w.wait()).is_err(), "a waiter never hangs");
    assert!(matches!(sf.begin("c"), Role::Lead(_)), "slot released");
    drop(b);
}

/// Emit the statements, a seeded section and SQLite's own results to the
/// directory in `SECTION_STATS_D1_DIR`, so the same SQL can be run on a
/// local D1 (`wrangler d1 execute --local`) and compared (not a gate).
#[test]
#[ignore = "emits files for a local D1 check; run by hand"]
fn emit_local_d1_check() {
    let Ok(dir) = std::env::var("SECTION_STATS_D1_DIR") else {
        return;
    };
    let dir = std::path::Path::new(&dir);
    let c = db();
    let all = seeded(&c, 7);
    let quote = |s: &str| format!("'{}'", s.replace('\'', "''"));
    let mut seed = String::new();
    for e in &all {
        seed.push_str(&format!(
            "INSERT INTO events (id, pubkey, created_at, kind, tags, content, sig) VALUES ({}, {}, {}, {}, {}, {}, {});\n",
            quote(&e.id),
            quote(&e.pubkey),
            e.created_at,
            e.kind,
            quote(&serde_json::to_string(&e.tags).unwrap()),
            quote(&e.content),
            quote(&e.sig)
        ));
    }
    std::fs::write(dir.join("02-seed.sql"), seed).unwrap();
    std::fs::write(dir.join("01-0017.sql"), MIGRATION_0017).unwrap();
    let a = answer(&c, C);
    let keys: Vec<String> = a.topics.iter().map(|t| t.id.clone()).collect();
    let inline = |sql: &str, params: &[String]| {
        let mut out = sql.to_string();
        for (i, p) in params.iter().enumerate().rev() {
            out = out.replace(&format!("?{}", i + 1), p);
        }
        out
    };
    let (ch, now) = (quote(C), NOW.to_string());
    let stmts = [
        (
            "q_roots_indexed",
            inline(
                &roots_indexed_sql(),
                &[ch.clone(), now.clone(), "1001".into()],
            ),
        ),
        (
            "q_roots_walk",
            inline(
                &roots_walk_sql(),
                &[
                    ch.clone(),
                    now.clone(),
                    "1001".into(),
                    ROOTS_VISIT_CAP.to_string(),
                ],
            ),
        ),
        (
            "q_stats",
            inline(
                &stats_sql(true),
                &[
                    ch.clone(),
                    now.clone(),
                    quote(&serde_json::to_string(&keys).unwrap()),
                    ACTIVITY_WALK_ROWS.to_string(),
                    COUNT_VISIT_CAP.to_string(),
                ],
            ),
        ),
    ];
    let mut expected = serde_json::Map::new();
    for (name, sql) in &stmts {
        std::fs::write(dir.join(format!("{name}.sql")), format!("{sql};\n")).unwrap();
        let mut s = c.prepare(sql).unwrap();
        let cols: Vec<String> = s.column_names().map(|n| n.to_string()).collect();
        let rows: Vec<serde_json::Value> = s
            .query_map([], |r| {
                let mut m = serde_json::Map::new();
                for (i, n) in cols.iter().enumerate() {
                    let v = match r.get::<_, Value>(i)? {
                        Value::Null => serde_json::Value::Null,
                        Value::Integer(n) => serde_json::json!(n),
                        Value::Real(f) => serde_json::json!(f),
                        Value::Text(t) => serde_json::Value::String(t),
                        Value::Blob(_) => serde_json::Value::Null,
                    };
                    m.insert(n.clone(), v);
                }
                Ok(serde_json::Value::Object(m))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        expected.insert(name.to_string(), serde_json::Value::Array(rows));
    }
    std::fs::write(
        dir.join("expected.json"),
        serde_json::Value::Object(expected).to_string(),
    )
    .unwrap();
}
