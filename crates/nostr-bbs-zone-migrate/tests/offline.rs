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
CREATE TABLE IF NOT EXISTS admin_log (id INTEGER PRIMARY KEY AUTOINCREMENT, actor_pubkey TEXT, action TEXT, target_pubkey TEXT, target_id TEXT, previous_value TEXT, new_value TEXT, reason TEXT, created_at INTEGER);
";

fn db() -> Connection {
    let c = Connection::open_in_memory().unwrap();
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
    c
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
    let (ids, failed) =
        offline::purge_candidates(&mut st, &ring(), &outers, &HashMap::new()).unwrap();
    assert_eq!((ids.len(), failed.len()), (300, 0));
    let pfiles = offline::write_purge_sql(&dir, &ids, &pk(MIGRATOR), 100, 1_700_000_100).unwrap();
    for f in &pfiles {
        c.execute_batch(&std::fs::read_to_string(f).unwrap())
            .unwrap();
    }
    let present = offline::present_ids(&c, &ids).unwrap();
    let gone = ids
        .iter()
        .filter(|i| !present.contains(*i))
        .cloned()
        .collect();
    let tomb = offline::tombstoned_ids(&c, &ids).unwrap();
    let pc = offline::commit_purged(&mut st, &ids, &gone, &tomb);
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
