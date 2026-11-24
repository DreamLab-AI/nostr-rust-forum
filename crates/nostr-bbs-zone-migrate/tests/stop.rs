//! A stop signal (engine::STOP) ends seal, purge and apply-direct between
//! steps with the state saved. Its own test binary: STOP is process-wide.

mod common;

use common::*;
use nostr_bbs_zone_migrate::channels::ChannelSpec;
use nostr_bbs_zone_migrate::engine;
use nostr_bbs_zone_migrate::offline;
use nostr_bbs_zone_migrate::state::{State, Status};

#[test]
fn stop_signal_ends_seal_purge_and_apply_between_steps() {
    let mut relay = FakeRelay::with_admin(&pk(MIGRATOR));
    for i in 0..3u64 {
        relay.insert(post(AUTHOR, CHANNEL, 1_600_000_000 + i, &format!("m{i}")));
    }
    relay.insert(live_zk_post(CHANNEL, "zone3", 2, ZONE3_E2));
    let ch = vec![ChannelSpec {
        id: CHANNEL.into(),
        zone: "zone3".into(),
    }];
    let keys = ring();
    let mut st = State::new(RELAY_URL, &pk(MIGRATOR));
    let mut sink = Sink::default();
    sink.run(|h| {
        block_on(engine::seal(
            &mut relay,
            &sk(MIGRATOR),
            &ch,
            &keys,
            &mut st,
            None,
            h,
        ))
    })
    .unwrap();
    sink.run(|h| block_on(engine::verify(&mut relay, &keys, &mut st, h)))
        .unwrap();
    assert_eq!(st.counts().verified, 3);

    engine::STOP.store(true, std::sync::atomic::Ordering::Relaxed);

    // Purge deletes nothing and says so.
    let p = sink
        .run(|h| block_on(engine::purge(&mut relay, &keys, &mut st, true, h)))
        .unwrap();
    assert!(p.stopped);
    assert_eq!((p.requests, p.deleted), (0, 0));
    assert!(st.entries.values().all(|e| e.status == Status::Verified));

    // Seal of a new post stops before sealing it.
    relay.insert(post(AUTHOR, CHANNEL, 1_600_000_010, "late"));
    let s = sink
        .run(|h| {
            block_on(engine::seal(
                &mut relay,
                &sk(MIGRATOR),
                &ch,
                &keys,
                &mut st,
                None,
                h,
            ))
        })
        .unwrap();
    assert!(s.stopped);
    assert_eq!(s.sealed, 0);

    // apply-direct applies no file.
    let dir = std::env::temp_dir().join(format!("zm-stop-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("d1.sqlite");
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TABLE events (id TEXT); CREATE TABLE event_tags (x); CREATE TABLE deleted_events (x);
             CREATE TABLE whitelist (x); CREATE TABLE channel_zones (x); CREATE TABLE admin_log (x);
             CREATE TRIGGER trg_event_tags_ai_v3 AFTER INSERT ON events BEGIN SELECT 1; END;",
        )
        .unwrap();
    let f = dir.join("a.sql");
    std::fs::write(
        &f,
        format!(
            "{}\nINSERT INTO events VALUES ('x');\n",
            offline::GENERATED_HEADER
        ),
    )
    .unwrap();
    let done = offline::apply_sql_direct(&path, &[f]).unwrap();
    assert!(done.is_empty());
    std::fs::remove_dir_all(&dir).ok();
}
