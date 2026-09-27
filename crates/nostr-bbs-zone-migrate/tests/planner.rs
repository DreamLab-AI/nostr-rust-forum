//! Planner and paging over synthetic events; no network.

mod common;

use common::*;
use nostr_bbs_core::sealed::seal_original;
use nostr_bbs_core::NostrEvent;
use nostr_bbs_zone_migrate::channels::ChannelSpec;
use nostr_bbs_zone_migrate::engine;
use nostr_bbs_zone_migrate::keys::KeyRing;
use nostr_bbs_zone_migrate::plan::scan_channel;
use nostr_bbs_zone_migrate::relay::{
    fetch_all, fetch_by_ids, Filter, MAX_IDS_PER_REQ, MAX_REQ_LIMIT,
};

fn spec() -> ChannelSpec {
    ChannelSpec {
        id: CHANNEL.into(),
        zone: "zone3".into(),
    }
}

#[test]
fn classifies_plaintext_envelopes_live_posts_and_forgeries() {
    let old = post(AUTHOR, CHANNEL, 100, "oldest");
    let mid = post(AUTHOR2, CHANNEL, 200, "middle");
    let new = post(AUTHOR, CHANNEL, 300, "newest");
    let envelope = seal_original(&mid, "zone3", 2, &pk(ZONE3_E2), &sk(MIGRATOR)).unwrap();
    let live = sign(
        AUTHOR,
        42,
        250,
        vec![
            tag(&["e", CHANNEL, "", "root"]),
            tag(&["zk", "zone3", "2", &pk(ZONE3_E2)]),
        ],
        "ciphertext",
    );
    let mut forged = post(AUTHOR, CHANNEL, 150, "genuine");
    forged.content = "edited after signing".into();
    // A reply elsewhere that merely mentions this channel in a non-root e-tag.
    let elsewhere = sign(
        AUTHOR,
        42,
        120,
        vec![
            tag(&["e", OTHER_CHANNEL, "", "root"]),
            tag(&["e", CHANNEL, "", "mention"]),
        ],
        "other channel",
    );
    let metadata = sign(AUTHOR, 41, 90, vec![tag(&["e", CHANNEL])], "{}");

    let events: Vec<NostrEvent> = vec![
        new.clone(),
        live,
        envelope,
        mid.clone(),
        forged.clone(),
        elsewhere,
        old.clone(),
        metadata,
    ];
    let scan = scan_channel(&spec(), &events, &ring());
    let p = &scan.plan;
    assert_eq!(p.seal_epoch, Some(2));
    assert_eq!(p.plaintext, 3);
    assert_eq!(p.already_sealed, 1);
    assert_eq!(p.would_seal, vec![old.id.clone(), new.id.clone()]);
    assert_eq!(p.invalid_signature, vec![forged.id.clone()]);
    assert_eq!(p.encrypted_posts, 1);
    assert_eq!(p.envelopes, 1);
    // Candidates are oldest first and carry their existing envelopes.
    let ids: Vec<&str> = scan
        .candidates
        .iter()
        .map(|c| c.original.id.as_str())
        .collect();
    assert_eq!(ids, vec![old.id.as_str(), mid.id.as_str(), new.id.as_str()]);
    assert_eq!(scan.candidates[1].envelopes.len(), 1);
    assert!(scan.envelopes_by_inner.contains_key(&mid.id));
}

#[test]
fn plan_without_keys_reports_the_zone_and_writes_nothing() {
    let mut relay = FakeRelay::with_admin(&pk(MIGRATOR));
    relay.insert(post(AUTHOR, CHANNEL, 100, "a"));
    let (plan, _) = block_on(engine::scan(&mut relay, &[spec()], &KeyRing::new())).unwrap();
    assert_eq!(plan.zones_without_key, vec!["zone3".to_string()]);
    assert_eq!(plan.channels[0].seal_epoch, None);
    assert_eq!(plan.totals(), (1, 0, 1));
    assert!(relay.published.is_empty());
    assert!(relay.delete_calls.is_empty());
    // One REQ per page, scoped to the channel's kind-42s at the relay's max limit.
    assert_eq!(relay.queries[0].kinds, Some(vec![42]));
    assert_eq!(relay.queries[0].e_tags, Some(vec![CHANNEL.to_string()]));
    assert_eq!(relay.queries[0].limit, Some(MAX_REQ_LIMIT));
}

fn dummy(i: usize, created_at: u64) -> NostrEvent {
    NostrEvent {
        id: format!("{i:064x}"),
        pubkey: "0".repeat(64),
        created_at,
        kind: 42,
        tags: vec![tag(&["e", CHANNEL, "", "root"])],
        content: String::new(),
        sig: String::new(),
    }
}

#[test]
fn paging_collects_every_event_across_pages_with_shared_seconds() {
    let mut relay = FakeRelay::default();
    // 2 600 events, ten per second, so page boundaries fall mid-second.
    for i in 0..2600 {
        relay.insert(dummy(i, 1_000 + (i as u64) / 10));
    }
    let fetched = block_on(fetch_all(&mut relay, &Filter::default())).unwrap();
    assert_eq!(fetched.events.len(), 2600);
    assert!(fetched.ambiguous_seconds.is_empty());
    assert!(relay.queries.iter().all(|f| f.limit == Some(MAX_REQ_LIMIT)));
    assert_eq!(relay.queries.len(), 3);
}

#[test]
fn paging_reports_a_second_holding_more_than_a_page() {
    let mut relay = FakeRelay::default();
    for i in 0..1200 {
        relay.insert(dummy(i, 500));
    }
    for i in 1200..1210 {
        relay.insert(dummy(i, 400));
    }
    let fetched = block_on(fetch_all(&mut relay, &Filter::default())).unwrap();
    assert_eq!(fetched.ambiguous_seconds, vec![500]);
    // Older events are still reached after stepping past the crowded second.
    assert_eq!(
        fetched
            .events
            .iter()
            .filter(|e| e.created_at == 400)
            .count(),
        10
    );
}

#[test]
fn id_lookups_are_batched_below_the_d1_parameter_cap() {
    let mut relay = FakeRelay::default();
    let mut ids: Vec<String> = (0..120)
        .map(|i| {
            relay.insert(dummy(i, 10));
            format!("{i:064x}")
        })
        .collect();
    ids.push("f".repeat(64));
    let got = block_on(fetch_by_ids(&mut relay, &ids)).unwrap();
    assert_eq!(got.len(), 120);
    assert_eq!(relay.queries.len(), 3);
    assert!(relay
        .queries
        .iter()
        .all(|f| f.ids.as_ref().unwrap().len() <= MAX_IDS_PER_REQ));
}
