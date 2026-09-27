//! End-to-end migration over an in-memory relay: seal → verify → purge,
//! resume, adoption, refusal paths, chunking and grant harvesting.

mod common;

use common::*;
use nostr_bbs_core::sealed::{open_sealed, parse_sealed};
use nostr_bbs_core::{sign_event, NostrEvent, UnsignedEvent};
use nostr_bbs_zone_migrate::channels::ChannelSpec;
use nostr_bbs_zone_migrate::engine::{self, EngineError, PURGE_REASON};
use nostr_bbs_zone_migrate::grants::{fetch_grants, KIND_ZONE_KEY_GRANT};
use nostr_bbs_zone_migrate::keys::{KeyRing, KeySource};
use nostr_bbs_zone_migrate::state::{State, Status, Step};

fn channels() -> Vec<ChannelSpec> {
    vec![ChannelSpec {
        id: CHANNEL.into(),
        zone: "zone3".into(),
    }]
}

fn new_state() -> State {
    State::new(RELAY_URL, &pk(MIGRATOR))
}

/// A relay holding `n` plaintext posts in CHANNEL plus one post elsewhere.
fn seeded(n: usize) -> (FakeRelay, Vec<NostrEvent>) {
    let mut relay = FakeRelay::with_admin(&pk(MIGRATOR));
    let originals: Vec<NostrEvent> = (0..n)
        .map(|i| {
            let author = if i % 2 == 0 { AUTHOR } else { AUTHOR2 };
            post(
                author,
                CHANNEL,
                1_600_000_000 + i as u64,
                &format!("message {i}"),
            )
        })
        .collect();
    for o in &originals {
        relay.insert(o.clone());
    }
    relay.insert(post(AUTHOR, OTHER_CHANNEL, 1_600_000_000, "not listed"));
    (relay, originals)
}

fn seal(
    relay: &mut FakeRelay,
    keys: &KeyRing,
    st: &mut State,
    limit: Option<usize>,
    sink: &mut Sink,
) -> Result<engine::SealReport, EngineError> {
    let ch = channels();
    sink.run(|h| block_on(engine::seal(relay, &sk(MIGRATOR), &ch, keys, st, limit, h)))
}

fn verify(
    relay: &mut FakeRelay,
    keys: &KeyRing,
    st: &mut State,
    sink: &mut Sink,
) -> engine::VerifyReport {
    sink.run(|h| block_on(engine::verify(relay, keys, st, h)))
        .unwrap()
}

fn purge(
    relay: &mut FakeRelay,
    keys: &KeyRing,
    st: &mut State,
    yes: bool,
    sink: &mut Sink,
) -> Result<engine::PurgeReport, EngineError> {
    sink.run(|h| block_on(engine::purge(relay, keys, st, yes, h)))
}

fn refused(r: Result<impl std::fmt::Debug, EngineError>) -> String {
    match r {
        Err(EngineError::Refused(msg)) => msg,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn full_run_seals_verifies_and_purges_preserving_every_original() {
    let (mut relay, originals) = seeded(5);
    let keys = ring();
    let mut st = new_state();
    let mut sink = Sink::default();

    let report = seal(&mut relay, &keys, &mut st, None, &mut sink).unwrap();
    assert_eq!((report.sealed, report.adopted, report.remaining), (5, 0, 0));
    assert!(report.failed.is_empty());
    assert_eq!(report.counts.sealed, 5);
    assert_eq!(relay.published.len(), 5);
    // Saved after recording the plan and after every entry.
    assert_eq!(sink.saves.len(), 6);

    // Every envelope is on the relay, sealed with the newest epoch, at the
    // original's created_at, and opens to the original byte for byte.
    for o in &originals {
        let entry = &st.entries[&o.id];
        assert_eq!(entry.status, Status::Sealed);
        assert_eq!(entry.epoch, Some(2));
        let outer = relay
            .events
            .iter()
            .find(|e| Some(&e.id) == entry.outer_id.as_ref())
            .unwrap();
        assert_eq!(outer.created_at, o.created_at);
        assert_eq!(parse_sealed(&outer.tags).unwrap().inner_id, o.id);
        let inner = open_sealed(outer, &ZONE3_E2).unwrap();
        assert_eq!(
            serde_json::to_string(&inner).unwrap(),
            serde_json::to_string(o).unwrap()
        );
    }
    // Sealing is oldest first.
    let published_inner: Vec<String> = relay
        .published
        .iter()
        .map(|e| parse_sealed(&e.tags).unwrap().inner_id)
        .collect();
    let expected: Vec<String> = originals.iter().map(|o| o.id.clone()).collect();
    assert_eq!(published_inner, expected);

    let v = verify(&mut relay, &keys, &mut st, &mut sink);
    assert_eq!((v.checked, v.verified), (5, 5));
    assert!(v.failed.is_empty());

    assert!(refused(purge(&mut relay, &keys, &mut st, false, &mut sink)).contains("--yes"));
    assert!(relay.delete_calls.is_empty());

    let p = purge(&mut relay, &keys, &mut st, true, &mut sink).unwrap();
    assert_eq!((p.requests, p.deleted), (1, 5));
    assert_eq!(p.counts.purged, 5);
    assert_eq!(relay.delete_calls[0].1, PURGE_REASON);
    for o in &originals {
        assert!(!relay.has(&o.id), "plaintext must be gone");
        assert!(relay.has(st.entries[&o.id].outer_id.as_ref().unwrap()));
    }
    // The unlisted channel is untouched and nothing was published as kind 5.
    assert_eq!(relay.events.iter().filter(|e| e.kind == 42).count(), 6);
    assert!(relay.published.iter().all(|e| e.kind == 42));

    // After purge, verify still proves the envelopes byte for byte via the
    // recorded digest, without any plaintext in the state file.
    let json = serde_json::to_string(&st).unwrap();
    assert!(!json.contains("message 0"));
    let mut resealed = st.clone();
    for e in resealed.entries.values_mut() {
        e.status = Status::Sealed;
    }
    let v = verify(&mut relay, &keys, &mut resealed, &mut sink);
    assert_eq!(v.verified, 5);
}

#[test]
fn seal_is_resumable_across_runs_and_state_reloads() {
    let (mut relay, _) = seeded(5);
    let keys = ring();
    let mut st = new_state();
    let mut sink = Sink::default();

    let first = seal(&mut relay, &keys, &mut st, Some(2), &mut sink).unwrap();
    assert!(first.limit_reached);
    assert_eq!((first.sealed, first.remaining), (2, 3));
    assert_eq!(relay.published.len(), 2);

    // Round-trip the last persisted snapshot through JSON, as a new process would.
    let saved = serde_json::to_string(sink.saves.last().unwrap()).unwrap();
    let mut reloaded = State::from_json(&saved, std::path::Path::new("state.json")).unwrap();
    assert_eq!(reloaded, st);

    let second = seal(&mut relay, &keys, &mut reloaded, None, &mut sink).unwrap();
    assert_eq!((second.sealed, second.remaining), (3, 0));
    assert_eq!(
        relay.published.len(),
        5,
        "sealed entries are not re-published"
    );

    let third = seal(&mut relay, &keys, &mut reloaded, None, &mut sink).unwrap();
    assert_eq!(third.sealed + third.adopted, 0);
    assert_eq!(relay.published.len(), 5);
}

#[test]
fn lost_state_adopts_envelopes_already_on_the_relay() {
    let (mut relay, _) = seeded(3);
    let keys = ring();
    let mut sink = Sink::default();
    seal(&mut relay, &keys, &mut new_state(), None, &mut sink).unwrap();
    assert_eq!(relay.published.len(), 3);

    let mut fresh = new_state();
    let report = seal(&mut relay, &keys, &mut fresh, None, &mut sink).unwrap();
    assert_eq!((report.adopted, report.sealed), (3, 0));
    assert_eq!(report.plan.channels[0].already_sealed, 3);
    assert_eq!(relay.published.len(), 3, "no duplicate envelopes");
    assert_eq!(fresh.counts().sealed, 3);
    assert_eq!(verify(&mut relay, &keys, &mut fresh, &mut sink).verified, 3);
}

#[test]
fn relay_rejection_marks_failed_and_blocks_purge() {
    let (mut relay, _) = seeded(2);
    relay.admins.clear();
    let keys = ring();
    let mut st = new_state();
    let mut sink = Sink::default();
    let report = seal(&mut relay, &keys, &mut st, None, &mut sink).unwrap();
    assert_eq!(report.failed.len(), 2);
    assert!(st.entries.values().all(|e| e.status
        == Status::Failed {
            step: Step::Seal,
            reason: "blocked: sealed originals are admin-only".into()
        }));
    let msg = refused(purge(&mut relay, &keys, &mut st, true, &mut sink));
    assert!(msg.contains("2 of 2 entries are not verified"), "{msg}");
    assert!(relay.delete_calls.is_empty());

    // Fixing the cause and re-running seal retries the failed entries.
    relay.admins.insert(pk(MIGRATOR));
    let report = seal(&mut relay, &keys, &mut st, None, &mut sink).unwrap();
    assert_eq!(report.sealed, 2);
}

#[test]
fn read_back_mismatch_or_missing_envelope_fails_the_entry() {
    let (mut relay, originals) = seeded(2);
    let keys = ring();
    let mut st = new_state();
    let mut sink = Sink::default();

    relay.tamper_next_store = true;
    let report = seal(&mut relay, &keys, &mut st, Some(1), &mut sink).unwrap();
    let e = &st.entries[&originals[0].id];
    assert!(
        matches!(&e.status, Status::Failed { step: Step::Seal, reason } if reason.contains("does not verify"))
    );
    assert!(e.outer_id.is_some() && e.inner_sha256.is_none());
    assert_eq!(report.failed.len(), 1);

    relay.drop_next_store = true;
    seal(&mut relay, &keys, &mut st, Some(1), &mut sink).unwrap();
    assert!(matches!(
        &st.entries[&originals[0].id].status,
        Status::Failed { reason, .. } if reason.contains("not returned")
    ));

    // verify does not touch entries that failed at seal.
    let v = verify(&mut relay, &keys, &mut st, &mut sink);
    assert_eq!(v.checked, 0);

    let report = seal(&mut relay, &keys, &mut st, None, &mut sink).unwrap();
    assert_eq!(report.sealed, 2);
    assert!(report.failed.is_empty());
}

#[test]
fn verify_catches_a_vanished_envelope_and_purge_refuses() {
    let (mut relay, originals) = seeded(3);
    let keys = ring();
    let mut st = new_state();
    let mut sink = Sink::default();
    seal(&mut relay, &keys, &mut st, None, &mut sink).unwrap();
    let gone = st.entries[&originals[1].id].outer_id.clone().unwrap();
    relay.events.retain(|e| e.id != gone);

    let v = verify(&mut relay, &keys, &mut st, &mut sink);
    assert_eq!(v.verified, 2);
    assert_eq!(
        v.failed,
        vec![(
            originals[1].id.clone(),
            "envelope not found on the relay".to_string()
        )]
    );
    assert!(refused(purge(&mut relay, &keys, &mut st, true, &mut sink)).contains("1 of 3"));
    assert!(relay.delete_calls.is_empty());
    for o in &originals {
        assert!(relay.has(&o.id));
    }

    // seal re-seals the failed-at-verify entry; verify then passes.
    let report = seal(&mut relay, &keys, &mut st, None, &mut sink).unwrap();
    assert_eq!(report.sealed, 1);
    assert_eq!(verify(&mut relay, &keys, &mut st, &mut sink).verified, 3);
}

#[test]
fn purge_rechecks_each_chunk_before_deleting() {
    let (mut relay, originals) = seeded(2);
    let keys = ring();
    let mut st = new_state();
    let mut sink = Sink::default();
    seal(&mut relay, &keys, &mut st, None, &mut sink).unwrap();
    verify(&mut relay, &keys, &mut st, &mut sink);
    // An envelope disappears between verify and purge.
    let gone = st.entries[&originals[0].id].outer_id.clone().unwrap();
    relay.events.retain(|e| e.id != gone);

    let msg = refused(purge(&mut relay, &keys, &mut st, true, &mut sink));
    assert!(msg.contains("nothing in that chunk was deleted"), "{msg}");
    assert!(relay.delete_calls.is_empty());
    assert!(relay.has(&originals[0].id) && relay.has(&originals[1].id));
    assert!(matches!(
        st.entries[&originals[0].id].status,
        Status::Failed {
            step: Step::Verify,
            ..
        }
    ));
}

#[test]
fn purge_refuses_an_empty_state_and_missing_keys() {
    let (mut relay, _) = seeded(1);
    let keys = ring();
    let mut sink = Sink::default();
    assert!(
        refused(purge(&mut relay, &keys, &mut new_state(), true, &mut sink)).contains("no entries")
    );

    let mut st = new_state();
    seal(&mut relay, &keys, &mut st, None, &mut sink).unwrap();
    verify(&mut relay, &keys, &mut st, &mut sink);
    let mut only_epoch1 = KeyRing::new();
    only_epoch1
        .insert(zone_key("zone3", 1, ZONE3_E1, KeySource::KeyFile))
        .unwrap();
    match purge(&mut relay, &only_epoch1, &mut st, true, &mut sink) {
        Err(EngineError::MissingKeys(z)) => assert_eq!(z, vec!["zone3:2".to_string()]),
        other => panic!("expected MissingKeys, got {other:?}"),
    }
    assert!(relay.delete_calls.is_empty());
}

#[test]
fn seal_without_a_zone_key_refuses_before_publishing() {
    let (mut relay, _) = seeded(2);
    let mut st = new_state();
    let mut sink = Sink::default();
    match seal(&mut relay, &KeyRing::new(), &mut st, None, &mut sink) {
        Err(EngineError::MissingKeys(z)) => assert_eq!(z, vec!["zone3".to_string()]),
        other => panic!("expected MissingKeys, got {other:?}"),
    }
    assert!(relay.published.is_empty());
    // The plan was still recorded so status shows what is pending.
    assert_eq!(st.counts().planned, 2);
}

#[test]
fn purge_deletes_in_chunks_of_at_most_200_and_handles_gone_and_skipped_ids() {
    let (mut relay, originals) = seeded(401);
    let keys = ring();
    let mut st = new_state();
    let mut sink = Sink::default();
    seal(&mut relay, &keys, &mut st, None, &mut sink).unwrap();
    assert_eq!(verify(&mut relay, &keys, &mut st, &mut sink).verified, 401);

    // One original already deleted (an interrupted earlier purge); another id
    // now names a non-kind-42 row, which the endpoint refuses to delete.
    let gone = originals[10].id.clone();
    relay.events.retain(|e| e.id != gone);
    let odd = originals[20].id.clone();
    let pos = relay.events.iter().position(|e| e.id == odd).unwrap();
    relay.events[pos].kind = 1;

    let p = purge(&mut relay, &keys, &mut st, true, &mut sink).unwrap();
    let sizes: Vec<usize> = relay
        .delete_calls
        .iter()
        .map(|(ids, _)| ids.len())
        .collect();
    assert_eq!(sizes, vec![200, 200, 1]);
    assert_eq!(p.requests, 3);
    assert_eq!(p.deleted, 399);
    assert_eq!(p.not_found, vec![gone.clone()]);
    assert_eq!(p.skipped, vec![odd.clone()]);
    assert_eq!(st.entries[&gone].status, Status::Purged);
    assert!(matches!(
        st.entries[&odd].status,
        Status::Failed {
            step: Step::Purge,
            ..
        }
    ));
    assert_eq!(p.counts.purged, 400);
}

#[test]
fn interrupted_purge_resumes_from_purged_entries() {
    let (mut relay, originals) = seeded(3);
    let keys = ring();
    let mut st = new_state();
    let mut sink = Sink::default();
    seal(&mut relay, &keys, &mut st, None, &mut sink).unwrap();
    verify(&mut relay, &keys, &mut st, &mut sink);
    // Pretend the first run purged one entry before dying.
    relay.events.retain(|e| e.id != originals[0].id);
    st.entries.get_mut(&originals[0].id).unwrap().status = Status::Purged;

    let p = purge(&mut relay, &keys, &mut st, true, &mut sink).unwrap();
    assert_eq!(relay.delete_calls[0].0.len(), 2);
    assert_eq!(p.deleted, 2);
    assert_eq!(st.counts().purged, 3);
}

// ── Grants ───────────────────────────────────────────────────────────────────

/// A zone-key grant wrapped to MIGRATOR by `sealer`, built with core
/// primitives exactly as the forum client's `build_grant_wrap` does.
fn grant_wrap(sealer: [u8; 32], rumor_kind: u64, zone_secret: [u8; 32], epoch: u32) -> NostrEvent {
    let me = pk(MIGRATOR);
    let content = format!(
        r#"{{"zone":"zone3","epoch":{epoch},"secret":"{}","pubkey":"{}","created_at":1}}"#,
        hex::encode(zone_secret),
        pk(zone_secret)
    );
    let rumor = UnsignedEvent {
        pubkey: pk(sealer),
        created_at: 1,
        kind: rumor_kind,
        tags: vec![tag(&["p", &me])],
        content,
    };
    let me_bytes: [u8; 32] = hex::decode(&me).unwrap().try_into().unwrap();
    let sealed_content =
        nostr_bbs_core::nip44::encrypt(&sealer, &me_bytes, &serde_json::to_string(&rumor).unwrap())
            .unwrap();
    let seal = sign_event(
        UnsignedEvent {
            pubkey: pk(sealer),
            created_at: 1,
            kind: 13,
            tags: vec![],
            content: sealed_content,
        },
        &nostr_bbs_core::keys::signing_key_from_bytes(&sealer).unwrap(),
    )
    .unwrap();
    nostr_bbs_core::gift_wrap::wrap_seal(&seal, &me).unwrap()
}

#[test]
fn grants_from_admins_are_accepted_and_others_refused_or_ignored() {
    let admin = [0x55; 32];
    let stranger = [0x66; 32];
    let mut relay = FakeRelay::with_admin(&pk(MIGRATOR));
    relay.admins.insert(pk(admin));
    relay.insert(grant_wrap(admin, KIND_ZONE_KEY_GRANT, ZONE3_E2, 2));
    relay.insert(grant_wrap(stranger, KIND_ZONE_KEY_GRANT, ZONE3_E1, 1));
    // An ordinary DM (kind-14 rumor) addressed to the migrator.
    relay.insert(
        nostr_bbs_core::gift_wrap::gift_wrap(&admin, &pk(admin), &pk(MIGRATOR), "hello").unwrap(),
    );
    // A wrap for someone else is never returned by the #p filter.
    relay.insert(
        nostr_bbs_core::gift_wrap::gift_wrap(&admin, &pk(admin), &pk(AUTHOR), "not yours").unwrap(),
    );

    let harvest = block_on(fetch_grants(&mut relay, &sk(MIGRATOR))).unwrap();
    assert_eq!(harvest.keys.len(), 1);
    let k = &harvest.keys[0];
    assert_eq!(
        (k.zone(), k.epoch(), k.pubkey()),
        ("zone3", 2, pk(ZONE3_E2).as_str())
    );
    assert_eq!(
        k.source(),
        &KeySource::Grant {
            granted_by: pk(admin)
        }
    );
    assert_eq!(harvest.rejected.len(), 1);
    assert!(harvest.rejected[0]
        .reason
        .contains("not sealed by an admin"));
    assert_eq!(harvest.ignored, 1);
    assert_eq!(relay.queries[0].p_tags, Some(vec![pk(MIGRATOR)]));
    assert_eq!(relay.queries[0].kinds, Some(vec![1059]));

    // The granted key seals and verifies a real run.
    let mut keys = KeyRing::new();
    for key in harvest.keys {
        keys.insert(key).unwrap();
    }
    relay.insert(post(AUTHOR, CHANNEL, 1_600_000_000, "granted"));
    let mut st = new_state();
    let mut sink = Sink::default();
    assert_eq!(
        seal(&mut relay, &keys, &mut st, None, &mut sink)
            .unwrap()
            .sealed,
        1
    );
    assert_eq!(verify(&mut relay, &keys, &mut st, &mut sink).verified, 1);
}
