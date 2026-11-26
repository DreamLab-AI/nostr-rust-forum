//! Offline sealing end to end over a SQLite database built from the relay's
//! migrations: seal-offline -> apply SQL -> commit -> online verify (fake
//! relay loaded from the database) -> purge-offline -> apply -> commit.

mod common;

use std::collections::HashMap;

use common::*;
use nostr_bbs_core::sealed::open_sealed;
use nostr_bbs_core::NostrEvent;
use nostr_bbs_zone_migrate::channels::ChannelSpec;
use nostr_bbs_zone_migrate::engine::{self, EngineError};
use nostr_bbs_zone_migrate::keys::{KeyRing, KeySource};
use nostr_bbs_zone_migrate::offline;
use nostr_bbs_zone_migrate::state::{State, Status};
use rusqlite::{params, Connection};

const MIGRATION_0009: &str =
    include_str!("../../nostr-bbs-relay-worker/migrations/0009_events.sql");
const MIGRATION_0004: &str =
    include_str!("../../nostr-bbs-relay-worker/migrations/0004_event_tags.sql");
const MIGRATION_0008: &str =
    include_str!("../../nostr-bbs-relay-worker/migrations/0008_whitelist.sql");

/// The relay's v3 tag writer and tombstone table (ensure_schema), as the
/// relay creates them (lib.rs PROBE_BLIND_STMTS / DELETED_EVENTS_CREATE_SQL).
const BOOT_SQL: &str = "
DROP TRIGGER IF EXISTS trg_event_tags_ai;
CREATE TRIGGER IF NOT EXISTS trg_event_tags_ai_v3 AFTER INSERT ON events BEGIN
  INSERT INTO event_tags (event_id, name, value, created_at)
  SELECT DISTINCT NEW.id, json_extract(je.value, '$[0]'), COALESCE(json_extract(je.value, '$[1]'), ''), NEW.created_at
  FROM json_each(NEW.tags) je
  WHERE json_type(je.value) = 'array' AND json_extract(je.value, '$[0]') IS NOT NULL
    AND json_extract(je.value, '$[0]') <> 'probe';
END;
CREATE TABLE IF NOT EXISTS deleted_events (id TEXT NOT NULL, pubkey TEXT NOT NULL, deleted_at INTEGER NOT NULL, PRIMARY KEY (id, pubkey));
CREATE TABLE IF NOT EXISTS channel_zones (channel_id TEXT PRIMARY KEY, zone TEXT NOT NULL, archived INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS admin_log (id INTEGER PRIMARY KEY AUTOINCREMENT, actor_pubkey TEXT, action TEXT, target_pubkey TEXT, target_id TEXT, previous_value TEXT, new_value TEXT, reason TEXT, created_at INTEGER);
";

fn db() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    init(&c);
    c
}

/// The relay schema plus the migrator's whitelist row and CHANNEL's binding.
fn init(c: &Connection) {
    c.execute_batch(MIGRATION_0009).unwrap();
    c.execute_batch(MIGRATION_0004).unwrap();
    let _ =
        c.execute_batch("ALTER TABLE event_tags ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0");
    c.execute_batch(MIGRATION_0008).unwrap();
    c.execute_batch(BOOT_SQL).unwrap();
    c.execute(
        "INSERT INTO whitelist (pubkey, added_at, is_admin) VALUES (?1, 0, 1)",
        [pk(MIGRATOR)],
    )
    .unwrap();
    c.execute(
        "INSERT INTO channel_zones (channel_id, zone) VALUES (?1, 'zone3')",
        [CHANNEL],
    )
    .unwrap();
}

fn topics(c: &Connection) -> HashMap<String, String> {
    offline::read_topic_channels(c, &offline::topics_of(&read(c))).unwrap()
}

fn store(c: &Connection, ev: &NostrEvent) {
    c.execute(
        "INSERT INTO events (id, pubkey, created_at, kind, tags, content, sig, d_tag, received_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '', 0)",
        params![ev.id, ev.pubkey, ev.created_at as i64, ev.kind as i64, serde_json::to_string(&ev.tags).unwrap(), ev.content, ev.sig],
    )
    .unwrap();
}

fn all_events(c: &Connection) -> Vec<NostrEvent> {
    let mut s = c
        .prepare("SELECT id, pubkey, created_at, kind, tags, content, sig FROM events")
        .unwrap();
    s.query_map([], |r| {
        Ok(NostrEvent {
            id: r.get(0)?,
            pubkey: r.get(1)?,
            created_at: r.get::<_, i64>(2)? as u64,
            kind: r.get::<_, i64>(3)? as u64,
            tags: serde_json::from_str(&r.get::<_, String>(4)?).unwrap(),
            content: r.get(5)?,
            sig: r.get(6)?,
        })
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

fn channels() -> Vec<ChannelSpec> {
    vec![ChannelSpec {
        id: CHANNEL.into(),
        zone: "zone3".into(),
    }]
}

fn ring() -> KeyRing {
    let mut r = KeyRing::new();
    r.insert(zone_key("zone3", 1, ZONE3_E1, KeySource::KeyFile))
        .unwrap();
    r
}

fn read(c: &Connection) -> HashMap<String, Vec<NostrEvent>> {
    let mut m = HashMap::new();
    m.insert(
        CHANNEL.to_string(),
        offline::read_channel_events(c, CHANNEL).unwrap(),
    );
    m
}

fn posts_created(c: &Connection) -> i64 {
    c.query_row(
        "SELECT posts_created FROM whitelist WHERE pubkey = ?1",
        [pk(MIGRATOR)],
        |r| r.get(0),
    )
    .unwrap()
}

#[test]
fn offline_seal_round_trips_through_online_verify_and_offline_purge() {
    let c = db();
    // The anchor: a live member post at the key, in the channel.
    store(&c, &live_zk_post(CHANNEL, "zone3", 1, ZONE3_E1));
    let originals: Vec<NostrEvent> = (0..300)
        .map(|i| {
            post(
                AUTHOR,
                CHANNEL,
                1_600_000_000 + i / 3,
                &format!("message {i}"),
            )
        })
        .collect();
    for o in &originals {
        store(&c, o);
    }
    offline::check_schema(&c).unwrap();
    let mut st = State::new(RELAY_URL, &pk(MIGRATOR));
    let mut sink = Sink::default();
    let report = sink
        .run(|h| {
            offline::seal_offline(
                &channels(),
                &read(&c),
                &topics(&c),
                &ring(),
                &sk(MIGRATOR),
                &mut st,
                None,
                h,
            )
        })
        .unwrap();
    assert_eq!(report.sealed.len(), 300);
    assert!(report.failed.is_empty());
    assert!(
        st.entries.values().all(|e| e.status == Status::Planned),
        "nothing sealed before commit"
    );

    // Write and apply the SQL (as wrangler d1 execute --file would).
    let dir = std::env::temp_dir().join(format!("zm-offline-{}", std::process::id()));
    let files =
        offline::write_seal_sql(&dir, &report.sealed, &pk(MIGRATOR), 128, 1_700_000_000).unwrap();
    assert_eq!(files.len(), 3);
    for f in &files {
        c.execute_batch(&std::fs::read_to_string(f).unwrap())
            .unwrap();
    }
    assert_eq!(posts_created(&c), 300, "one count per envelope inserted");
    // Re-applying is harmless: no duplicate rows, no extra counts.
    for f in &files {
        c.execute_batch(&std::fs::read_to_string(f).unwrap())
            .unwrap();
    }
    assert_eq!(posts_created(&c), 300);
    // The relay's trigger indexed the envelopes (the #e and #sealed lookups).
    let sealed_tags: i64 = c
        .query_row(
            "SELECT count(*) FROM event_tags WHERE name = 'sealed'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(sealed_tags, 300);
    let (received, last_active): (i64, i64) = c
        .query_row(
            "SELECT (SELECT max(received_at) FROM events WHERE pubkey = ?1), last_active_at FROM whitelist WHERE pubkey = ?1",
            [pk(MIGRATOR)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((received, last_active), (1_700_000_000, 1_700_000_000));

    // Commit: entries become sealed only now.
    let manifest: Vec<offline::ManifestEntry> =
        serde_json::from_slice(&std::fs::read(dir.join("seal-manifest.json")).unwrap()).unwrap();
    let outer_ids: Vec<String> = manifest.iter().map(|m| m.outer_id.clone()).collect();
    let outers = offline::read_events_by_id(&c, &outer_ids).unwrap();
    let committed = offline::commit_sealed(&mut st, &manifest, &outers, &ring());
    assert_eq!((committed.committed, committed.skipped.len()), (300, 0));

    // The ONLINE verify passes on offline-sealed data.
    let mut relay = FakeRelay::with_admin(&pk(MIGRATOR));
    for ev in all_events(&c) {
        relay.insert(ev);
    }
    let v = sink
        .run(|h| block_on(engine::verify(&mut relay, &ring(), &mut st, h)))
        .unwrap();
    assert_eq!(v.verified, 300);
    assert!(v.failed.is_empty());

    // Offline purge: tombstone + delete, as the relay's admin delete.
    let outer_ids: Vec<String> = st
        .entries
        .values()
        .filter_map(|e| e.outer_id.clone())
        .collect();
    let outers = offline::read_events_by_id(&c, &outer_ids).unwrap();
    let (items, failed) =
        offline::purge_candidates(&mut st, &ring(), &outers, &HashMap::new()).unwrap();
    assert_eq!((items.len(), failed.len()), (300, 0));
    let pdir = dir.join("purge");
    let pfiles =
        offline::write_purge_sql(&pdir, &items, &pk(MIGRATOR), 100, 1_700_000_100).unwrap();
    assert_eq!(pfiles.len(), 3);
    for f in &pfiles {
        c.execute_batch(&std::fs::read_to_string(f).unwrap())
            .unwrap();
    }
    let ids: Vec<String> = items.iter().map(|i| i.id.clone()).collect();
    let outer_ids: Vec<String> = items.iter().map(|i| i.outer_id.clone()).collect();
    let present = offline::present_ids(&c, &ids).unwrap();
    let gone = ids
        .iter()
        .filter(|i| !present.contains(*i))
        .cloned()
        .collect();
    let tomb = offline::tombstoned_ids(&c, &ids).unwrap();
    let envs = offline::present_ids(&c, &outer_ids).unwrap();
    let pc = offline::commit_purged(&mut st, &items, &gone, &tomb, &envs);
    assert_eq!(pc.committed, 300);
    // The envelopes stay and still open; the plaintext is gone.
    for o in &originals {
        assert!(!present.contains(&o.id));
    }
    let logs: i64 = c
        .query_row(
            "SELECT count(*) FROM admin_log WHERE action = 'events.delete'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(logs, 3);
    // A tombstoned original can never be re-inserted by a re-run: the
    // events insert is guarded the same way for any id.
    let resurrect = offline::envelope_insert_sql(&originals[0], 1);
    c.execute_batch(&resurrect).unwrap();
    assert!(offline::present_ids(&c, &[originals[0].id.clone()])
        .unwrap()
        .is_empty());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn offline_envelopes_match_online_envelopes_structurally() {
    // Same original sealed both ways: identical tags, signer, created_at and
    // opened inner event; only the NIP-44 nonce (content) and the id/sig differ.
    let c = db();
    store(&c, &live_zk_post(CHANNEL, "zone3", 1, ZONE3_E1));
    let o = post(AUTHOR, CHANNEL, 1_600_000_000, "hello");
    store(&c, &o);
    let mut st = State::new(RELAY_URL, &pk(MIGRATOR));
    let mut sink = Sink::default();
    let off = sink
        .run(|h| {
            offline::seal_offline(
                &channels(),
                &read(&c),
                &topics(&c),
                &ring(),
                &sk(MIGRATOR),
                &mut st,
                None,
                h,
            )
        })
        .unwrap();
    let a = &off.sealed[0].envelope;
    let b = nostr_bbs_core::sealed::seal_original(&o, "zone3", 1, &pk(ZONE3_E1), &sk(MIGRATOR))
        .unwrap();
    assert_eq!(a.tags, b.tags);
    assert_eq!(
        (a.pubkey.as_str(), a.created_at, a.kind),
        (b.pubkey.as_str(), b.created_at, b.kind)
    );
    let (ia, ib) = (
        open_sealed(a, &ZONE3_E1).unwrap(),
        open_sealed(&b, &ZONE3_E1).unwrap(),
    );
    assert_eq!(
        serde_json::to_string(&ia).unwrap(),
        serde_json::to_string(&ib).unwrap()
    );
}

#[test]
fn offline_seal_keeps_the_anchor_check_and_adopts_online_envelopes() {
    // No anchor (all plaintext, key from a file): refused exactly as online.
    let c = db();
    store(&c, &post(AUTHOR, CHANNEL, 1_600_000_000, "plain"));
    let mut st = State::new(RELAY_URL, &pk(MIGRATOR));
    let mut sink = Sink::default();
    let r = sink.run(|h| {
        offline::seal_offline(
            &channels(),
            &read(&c),
            &topics(&c),
            &ring(),
            &sk(MIGRATOR),
            &mut st,
            None,
            h,
        )
    });
    assert!(matches!(r, Err(EngineError::Refused(_))), "{r:?}");

    // An envelope the online run already published is adopted, not resealed.
    let c = db();
    store(&c, &live_zk_post(CHANNEL, "zone3", 1, ZONE3_E1));
    let o1 = post(AUTHOR, CHANNEL, 1_600_000_000, "one");
    let o2 = post(AUTHOR, CHANNEL, 1_600_000_001, "two");
    store(&c, &o1);
    store(&c, &o2);
    let online =
        nostr_bbs_core::sealed::seal_original(&o1, "zone3", 1, &pk(ZONE3_E1), &sk(MIGRATOR))
            .unwrap();
    store(&c, &online);
    let mut st = State::new(RELAY_URL, &pk(MIGRATOR));
    let report = sink
        .run(|h| {
            offline::seal_offline(
                &channels(),
                &read(&c),
                &topics(&c),
                &ring(),
                &sk(MIGRATOR),
                &mut st,
                None,
                h,
            )
        })
        .unwrap();
    assert_eq!((report.adopted, report.sealed.len()), (1, 1));
    assert_eq!(st.entries[&o1.id].status, Status::Sealed);
    assert_eq!(report.sealed[0].original_id, o2.id);
}

#[test]
fn purge_sql_never_deletes_plaintext_whose_envelope_is_gone() {
    // Review finding 1: the envelope guard is evaluated when the SQL RUNS.
    let c = db();
    store(&c, &live_zk_post(CHANNEL, "zone3", 1, ZONE3_E1));
    let o = post(AUTHOR, CHANNEL, 1_600_000_000, "keep me");
    store(&c, &o);
    let env = nostr_bbs_core::sealed::seal_original(&o, "zone3", 1, &pk(ZONE3_E1), &sk(MIGRATOR))
        .unwrap();
    store(&c, &env);
    let item = offline::PurgeItem {
        id: o.id.clone(),
        outer_id: env.id.clone(),
    };
    let sql = offline::purge_sql(std::slice::from_ref(&item), &pk(MIGRATOR), 5);
    // The envelope disappears between writing and applying the SQL.
    c.execute("DELETE FROM events WHERE id = ?1", [&env.id])
        .unwrap();
    c.execute_batch(&sql).unwrap();
    assert_eq!(
        offline::present_ids(&c, std::slice::from_ref(&o.id))
            .unwrap()
            .len(),
        1,
        "plaintext kept"
    );
    assert!(
        offline::tombstoned_ids(&c, std::slice::from_ref(&o.id))
            .unwrap()
            .is_empty(),
        "no tombstone"
    );
    let mut st = State::new(RELAY_URL, &pk(MIGRATOR));
    let r = offline::commit_purged(
        &mut st,
        &[item],
        &Default::default(),
        &Default::default(),
        &Default::default(),
    );
    assert_eq!(r.committed, 0);
}

#[test]
fn offline_refuses_a_mislisted_channel_and_misplaced_reply_topics() {
    // Review finding 2: the binding must match channel_zones.
    let bound: HashMap<String, String> = [(CHANNEL.to_string(), "zone3".to_string())].into();
    assert!(offline::binding_refusal(&channels(), &bound).is_none());
    let wrong = vec![ChannelSpec {
        id: CHANNEL.into(),
        zone: "zone2".into(),
    }];
    assert!(offline::binding_refusal(&wrong, &bound)
        .unwrap()
        .contains("bound to zone zone3"));
    let unbound = vec![ChannelSpec {
        id: OTHER_CHANNEL.into(),
        zone: "zone3".into(),
    }];
    assert!(offline::binding_refusal(&unbound, &bound)
        .unwrap()
        .contains("not bound"));

    // Review finding 3: a reply topic must be a kind-42 in the same channel.
    let c = db();
    store(&c, &live_zk_post(CHANNEL, "zone3", 1, ZONE3_E1));
    let root = post(AUTHOR, CHANNEL, 1_600_000_000, "root");
    store(&c, &root);
    let elsewhere = post(AUTHOR, OTHER_CHANNEL, 1_600_000_000, "other root");
    store(&c, &elsewhere);
    let reply = |topic: &str, n: u64| {
        sign(
            AUTHOR,
            42,
            1_600_000_100 + n,
            vec![
                tag(&["e", CHANNEL, "", "root"]),
                tag(&["e", topic, "", "reply"]),
            ],
            &format!("reply {n}"),
        )
    };
    let good = reply(&root.id, 1);
    let cross = reply(&elsewhere.id, 2);
    let made_up = reply(&"9".repeat(64), 3);
    let junk = reply("'); DROP TABLE events; --", 4);
    for e in [&good, &cross, &made_up, &junk] {
        store(&c, e);
    }
    let mut st = State::new(RELAY_URL, &pk(MIGRATOR));
    let mut sink = Sink::default();
    let report = sink
        .run(|h| {
            offline::seal_offline(
                &channels(),
                &read(&c),
                &topics(&c),
                &ring(),
                &sk(MIGRATOR),
                &mut st,
                None,
                h,
            )
        })
        .unwrap();
    let sealed: std::collections::HashSet<&str> = report
        .sealed
        .iter()
        .map(|s| s.original_id.as_str())
        .collect();
    assert!(sealed.contains(good.id.as_str()) && sealed.contains(root.id.as_str()));
    let failed: std::collections::HashSet<&str> =
        report.failed.iter().map(|(id, _)| id.as_str()).collect();
    for bad in [&cross, &made_up, &junk] {
        assert!(failed.contains(bad.id.as_str()), "{}", bad.content);
    }
}

#[test]
fn chunk_directories_must_be_fresh_and_purge_chunks_stay_relay_sized() {
    let dir = std::env::temp_dir().join(format!("zm-fresh-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("seal-0001.sql"), "old").unwrap();
    assert!(
        offline::write_seal_sql(&dir, &[], &pk(MIGRATOR), 10, 1).is_err(),
        "stale files refused"
    );
    let items: Vec<offline::PurgeItem> = (0..450u64)
        .map(|i| offline::PurgeItem {
            id: format!("{i:064x}"),
            outer_id: format!("{:064x}", i + 10_000),
        })
        .collect();
    let files = offline::write_purge_sql(&dir.join("p"), &items, &pk(MIGRATOR), 5_000, 1).unwrap();
    assert_eq!(
        files.len(),
        3,
        "capped at {} ids per chunk",
        offline::PURGE_CHUNK
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A topic root and a reply in CHANNEL, plus a legacy envelope of the reply
/// (the current envelope with the topic tag stripped, re-signed by the
/// migrator), stored in `c`. Returns (root, legacy envelope).
fn legacy_fixture(c: &Connection) -> (NostrEvent, NostrEvent) {
    store(c, &live_zk_post(CHANNEL, "zone3", 1, ZONE3_E1));
    let root = post(AUTHOR, CHANNEL, 1_600_000_000, "root");
    store(c, &root);
    let reply = sign(
        AUTHOR,
        42,
        1_600_000_001,
        vec![
            tag(&["e", CHANNEL, "", "root"]),
            tag(&["e", &root.id, "", "reply"]),
        ],
        "reply",
    );
    store(c, &reply);
    // A legacy envelope: the current one with the topic tag stripped (as the
    // earlier sealer wrote it), re-signed by the migrator.
    let current =
        nostr_bbs_core::sealed::seal_original(&reply, "zone3", 1, &pk(ZONE3_E1), &sk(MIGRATOR))
            .unwrap();
    let legacy = sign(
        MIGRATOR,
        42,
        reply.created_at,
        current
            .tags
            .iter()
            .filter(|t| !(t[0] == "e" && t.get(3).map(String::as_str) == Some("reply")))
            .cloned()
            .collect(),
        &current.content,
    );
    assert!(offline::is_legacy_envelope(&legacy, &reply));
    assert!(!offline::is_legacy_envelope(&current, &reply));
    store(c, &legacy);
    c.execute(
        "UPDATE whitelist SET posts_created = 1 WHERE pubkey = ?1",
        [pk(MIGRATOR)],
    )
    .unwrap();

    (root, legacy)
}

/// reseal-legacy over `c` (CHANNEL in zone3).
fn reseal_items(c: &Connection, root: &NostrEvent) -> Vec<offline::Reseal> {
    let envs = offline::read_migrator_envelopes(c, &channels(), &pk(MIGRATOR)).unwrap();
    let zones: HashMap<String, String> = [(CHANNEL.to_string(), "zone3".to_string())].into();
    let topics_map = offline::read_topic_channels(c, &[root.id.clone()].into()).unwrap();
    let (items, failed) =
        offline::reseal_legacy(&envs, &zones, &ring(), &sk(MIGRATOR), &topics_map);
    assert!(failed.is_empty(), "{failed:?}");
    items
}

fn bindings() -> HashMap<String, String> {
    [(CHANNEL.to_string(), "zone3".to_string())].into()
}

#[test]
fn reseal_legacy_replaces_an_unrecorded_legacy_envelope_and_verify_passes() {
    let c = db();
    let (root, legacy) = legacy_fixture(&c);
    // Not recorded in the state file at all (killed mid-save).
    let mut st = State::new(RELAY_URL, &pk(MIGRATOR));
    let envs = offline::read_migrator_envelopes(&c, &channels(), &pk(MIGRATOR)).unwrap();
    assert_eq!(envs.len(), 1);
    let zones: HashMap<String, String> = [(CHANNEL.to_string(), "zone3".to_string())].into();
    let topics_map = offline::read_topic_channels(&c, &[root.id.clone()].into()).unwrap();
    let (items, failed) =
        offline::reseal_legacy(&envs, &zones, &ring(), &sk(MIGRATOR), &topics_map);
    assert_eq!((items.len(), failed.len()), (1, 0));
    c.execute_batch(&offline::reseal_sql(&items, &pk(MIGRATOR), 9))
        .unwrap();
    // Old gone and tombstoned, new present with the topic tag, count unchanged.
    assert!(offline::present_ids(&c, std::slice::from_ref(&legacy.id))
        .unwrap()
        .is_empty());
    assert_eq!(
        offline::tombstoned_ids(&c, std::slice::from_ref(&legacy.id))
            .unwrap()
            .len(),
        1
    );
    let new = offline::read_events_by_id(&c, std::slice::from_ref(&items[0].envelope.id)).unwrap();
    assert_eq!(
        nostr_bbs_core::sealed::reply_root_of(&new[&items[0].envelope.id]),
        Some(root.id.as_str())
    );
    assert_eq!(posts_created(&c), 1);
    // Re-applying is harmless.
    c.execute_batch(&offline::reseal_sql(&items, &pk(MIGRATOR), 9))
        .unwrap();
    assert_eq!(posts_created(&c), 1);

    // Commit adds the unrecorded entry; the online verify passes.
    let manifest: Vec<offline::ManifestEntry> = items
        .iter()
        .map(|s| offline::ManifestEntry {
            id: s.original_id.clone(),
            outer_id: s.envelope.id.clone(),
            epoch: s.epoch,
            inner_sha256: s.inner_sha256.clone(),
        })
        .collect();
    // Unlisted channel: nothing recorded, no phantom entry.
    let r = offline::commit_sealed_with(&mut st, &manifest, &new, &ring(), true, &HashMap::new());
    assert_eq!((r.committed, r.skipped.len()), (0, 1));
    assert!(st.entries.is_empty());
    let r = offline::commit_sealed_with(&mut st, &manifest, &new, &ring(), true, &bindings());
    assert_eq!(r.committed, 1);
    let mut relay = FakeRelay::with_admin(&pk(MIGRATOR));
    for ev in all_events(&c) {
        relay.insert(ev);
    }
    let mut sink = Sink::default();
    let v = sink
        .run(|h| block_on(engine::verify(&mut relay, &ring(), &mut st, h)))
        .unwrap();
    assert_eq!((v.verified, v.failed.len()), (1, 0));
}

#[test]
fn two_reseal_files_for_one_envelope_leave_one_replacement() {
    let c = db();
    let (root, legacy) = legacy_fixture(&c);
    // Two runs before either is applied: NIP-44 is randomised, so the
    // replacements differ.
    let a = reseal_items(&c, &root);
    let b = reseal_items(&c, &root);
    assert_ne!(a[0].envelope.id, b[0].envelope.id);
    c.execute_batch(&offline::reseal_sql(&a, &pk(MIGRATOR), 9))
        .unwrap();
    c.execute_batch(&offline::reseal_sql(&b, &pk(MIGRATOR), 9))
        .unwrap();
    let ids = [
        legacy.id.clone(),
        a[0].envelope.id.clone(),
        b[0].envelope.id.clone(),
    ];
    let present = offline::present_ids(&c, &ids).unwrap();
    assert_eq!(present, [a[0].envelope.id.clone()].into());
    assert_eq!(posts_created(&c), 1);
}

#[test]
fn commit_rejects_a_manifest_envelope_not_signed_by_the_migrator() {
    let c = db();
    let (root, _legacy) = legacy_fixture(&c);
    let items = reseal_items(&c, &root);
    // The same envelope tags and content, signed by a zone member instead.
    let forged = sign(
        AUTHOR,
        42,
        items[0].envelope.created_at,
        items[0].envelope.tags.clone(),
        &items[0].envelope.content,
    );
    let manifest = vec![offline::ManifestEntry {
        id: items[0].original_id.clone(),
        outer_id: forged.id.clone(),
        epoch: items[0].epoch,
        inner_sha256: items[0].inner_sha256.clone(),
    }];
    let outers: HashMap<String, NostrEvent> = [(forged.id.clone(), forged)].into();
    let mut st = State::new(RELAY_URL, &pk(MIGRATOR));
    let r = offline::commit_sealed_with(&mut st, &manifest, &outers, &ring(), true, &bindings());
    assert_eq!(r.committed, 0);
    assert!(
        r.skipped[0].1.contains("not signed by the migrator"),
        "{r:?}"
    );
    assert!(st.entries.is_empty());
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "zm-offline-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn apply_direct_applies_generated_files_and_refuses_anything_else() {
    let dir = temp_dir("apply");
    let path = dir.join("d1.sqlite");
    let (root, legacy) = {
        let c = Connection::open(&path).unwrap();
        c.execute_batch("PRAGMA journal_mode = WAL;").unwrap();
        init(&c);
        legacy_fixture(&c)
    };
    let items = {
        let c = Connection::open(&path).unwrap();
        reseal_items(&c, &root)
    };
    let file = offline::write_reseal_sql(&dir.join("sql"), &items, &pk(MIGRATOR), 9).unwrap();

    // Not generated by the tool: refused before anything runs.
    let bare = dir.join("bare.sql");
    std::fs::write(&bare, "DELETE FROM events;\n").unwrap();
    let err = offline::apply_sql_direct(&path, &[file.clone(), bare]).unwrap_err();
    assert!(err.contains("not a file written by this tool"), "{err}");
    // Generated header but transaction control inside: rolled back.
    let sneaky = dir.join("sneaky.sql");
    std::fs::write(
        &sneaky,
        format!(
            "{}\nDELETE FROM events;\nCOMMIT;\n",
            offline::GENERATED_HEADER
        ),
    )
    .unwrap();
    let err = offline::apply_sql_direct(&path, &[sneaky]).unwrap_err();
    assert!(err.contains("transaction control"), "{err}");
    {
        let c = Connection::open(&path).unwrap();
        assert_eq!(
            offline::present_ids(&c, std::slice::from_ref(&legacy.id))
                .unwrap()
                .len(),
            1
        );
    }

    // The generated file applies, line by line, with the relay trigger.
    let done = offline::apply_sql_direct(&path, &[file]).unwrap();
    assert_eq!(done.len(), 1);
    let c = Connection::open(&path).unwrap();
    assert!(offline::present_ids(&c, std::slice::from_ref(&legacy.id))
        .unwrap()
        .is_empty());
    let sealed_rows: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM event_tags WHERE event_id = ?1 AND name = 'sealed'",
            [&items[0].envelope.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(sealed_rows, 1);
    assert_eq!(posts_created(&c), 1);
    drop(c);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn exclusive_lock_keeps_every_other_connection_out_in_both_journal_modes() {
    for mode in ["WAL", "DELETE"] {
        let dir = temp_dir("lock");
        let path = dir.join("d1.sqlite");
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(&format!("PRAGMA journal_mode = {mode};"))
                .unwrap();
            init(&c);
        }
        let held = offline::lock_exclusive(&path).unwrap();
        let probe = |what: &str| {
            let other = Connection::open(&path).unwrap();
            other
                .busy_timeout(std::time::Duration::from_millis(0))
                .unwrap();
            assert!(
                other
                    .query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, i64>(0))
                    .is_err(),
                "{mode}: a reader got in {what}"
            );
            assert!(
                other.execute("DELETE FROM whitelist", []).is_err(),
                "{mode}: a writer got in {what}"
            );
            assert!(
                offline::lock_exclusive(&path).is_err(),
                "{mode}: locked twice {what}"
            );
        };
        probe("after locking");
        // Between files: a committed transaction keeps the lock.
        held.execute_batch("BEGIN IMMEDIATE; UPDATE whitelist SET posts_created = 7; COMMIT;")
            .unwrap();
        probe("between transactions");
        drop(held);
        let c = Connection::open(&path).unwrap();
        assert_eq!(posts_created(&c), 7, "{mode}: released and committed");
        drop(c);
        std::fs::remove_dir_all(&dir).ok();
    }
}
