//! End to end on a small synthetic Keybase archive: adapt → identities and
//! structure → keys → media → build into a relay D1 built from the real
//! migrations → parity → idempotent re-run → deferred operator import →
//! per-thread anchors → zone-migrate offline seal, commit, online verify →
//! search input → offline purge → parity after purge → re-run (no plaintext
//! comes back) → scrub → upload dump rehearsed twice into a fresh D1.

mod common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use common::*;
use nostr_bbs_bulk_import::d1;
use nostr_bbs_bulk_import::events::{Emit, MAX_EVENT_BYTES};
use nostr_bbs_bulk_import::identity::link_statement;
use nostr_bbs_bulk_import::pipeline::{self, BuildOptions, Phase, Work};
use nostr_bbs_bulk_import::{adapter, fsutil};
use nostr_bbs_core::keys::SecretKey;
use nostr_bbs_core::{sign_event, NostrEvent, UnsignedEvent};
use nostr_bbs_zone_migrate::channels::ChannelSpec;
use nostr_bbs_zone_migrate::keys::{KeyRing, KeySource, ZoneKey};
use nostr_bbs_zone_migrate::state::{State, Status};
use nostr_bbs_zone_migrate::{engine, offline};
use rusqlite::Connection;
use serde_json::json;

const C1: &str = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
const C2: &str = "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2";
const T0: u64 = 1_610_000_000;
/// A valid 1x1 PNG.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0xF8, 0xCF, 0xC0, 0xF0,
    0x1F, 0x00, 0x05, 0x00, 0x01, 0xFF, 0x89, 0x99, 0x3D, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,
    0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
];

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("bi-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn line(id: u64, at: u64, sender: &str, content: serde_json::Value) -> String {
    json!({"msg": {"id": id, "sent_at": at, "sender": {"username": sender}, "content": content}})
        .to_string()
}

fn text(body: &str) -> serde_json::Value {
    json!({"type": "text", "text": {"body": body}})
}

fn reply(body: &str, to: u64) -> serde_json::Value {
    json!({"type": "text", "text": {"body": body, "replyTo": to}})
}

/// A Keybase archive in the archiver's raw layout. With `hostile_asset`,
/// the image's manifest path points into a message file.
fn keybase_archive(dir: &Path, hostile_asset: bool) {
    let w = |rel: &str, s: &str| {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, s).unwrap();
    };
    w(
        "team.json",
        &json!({"name": "testteam", "channels": [
            {"id": C1, "topic": "general", "dir": "general"},
            {"id": C2, "topic": "photos", "dir": "photos"}],
          "members": [
            {"username": "alice", "fullName": "Alice A", "role": "writer"},
            {"username": "bob", "role": "writer"},
            {"username": "bob2", "role": "writer"},
            {"username": "meetbot", "role": "bot"},
            {"username": "jj", "role": "owner"}]})
        .to_string(),
    );
    w(
        "users/alice/profile.json",
        &json!({"username": "alice", "fullName": "Alice A", "bio": "hello there"}).to_string(),
    );
    let long = "é".repeat(50_000);
    let general = [
        line(1, T0, "alice", text("hello")),
        line(2, T0 + 10, "bob", reply("reply to alice", 1)),
        line(3, T0 + 20, "alice", text("tpyo")),
        line(
            4,
            T0 + 21,
            "alice",
            json!({"type": "edit", "edit": {"messageID": 3, "body": "typo fixed"}}),
        ),
        line(5, T0 + 30, "bob2", text("from my second account")),
        line(6, T0 + 40, "meetbot", text("bot noise")),
        line(7, T0 + 50, "alice", text("to be deleted")),
        line(
            8,
            T0 + 51,
            "alice",
            json!({"type": "delete", "delete": {"messageIDs": [7]}}),
        ),
        line(
            9,
            T0 + 60,
            "bob",
            json!({"type": "reaction", "reaction": {"m": 1, "b": ":+1:"}}),
        ),
        line(
            10,
            T0 + 61,
            "jj",
            json!({"type": "reaction", "reaction": {"m": 1, "b": "❤️"}}),
        ),
        line(11, T0 + 70, "jj", reply("operator says hi", 2)),
        line(12, T0 + 80, "alice", text(&long)),
        line(13, T0 + 90, "bob", reply("replying to the bot", 6)),
        line(14, T0 + 95, "bob", json!({"type": "join"})),
    ];
    w(
        "channels/general/messages/2021/2021-01.jsonl",
        &(general.join("\n") + "\n"),
    );
    let photos = [
        line(
            1,
            T0 + 100,
            "alice",
            json!({"type": "attachment", "attachment": {"object": {"filename": "cat.png", "title": "my cat", "size": PNG.len(), "mimeType": "image/png"}}}),
        ),
        line(
            2,
            T0 + 110,
            "bob",
            json!({"type": "attachment", "attachment": {"object": {"filename": "clip.mov", "title": "", "size": 3_500_000, "mimeType": "video/quicktime"}}}),
        ),
    ];
    w(
        "channels/photos/messages/2021/2021-02.jsonl",
        &(photos.join("\n") + "\n"),
    );
    let sha = fsutil::sha256_hex(PNG);
    let rel = format!("assets/{}/{sha}.png", &sha[..2]);
    std::fs::create_dir_all(dir.join(&rel).parent().unwrap()).unwrap();
    std::fs::write(dir.join(&rel), PNG).unwrap();
    let path = if hostile_asset {
        "channels/general/messages/2021/2021-01.jsonl".to_string()
    } else {
        rel
    };
    w(
        "assets/manifest.jsonl",
        &(json!({"key": sha, "sha256": sha, "status": "ok", "filename": "cat.png", "kind": "image", "outputs": {"main": {"path": path, "mime": "image/png"}}}).to_string() + "\n"),
    );
    w(
        "assets/refs.jsonl",
        &(json!({"key": "photos:1", "status": "done", "sha256": sha}).to_string()
            + "\n"
            + &json!({"key": "photos:2", "status": "deferred"}).to_string()
            + "\n"),
    );
}

fn write_key_file(path: &Path) -> SecretKey {
    let kp = nostr_bbs_core::keys::generate_keypair().unwrap();
    fsutil::write_private_atomic(path, hex::encode(kp.secret.as_bytes()).as_bytes()).unwrap();
    kp.secret
}

fn signed(sk: &SecretKey, kind: u64, at: u64, tags: Vec<Vec<String>>, content: &str) -> NostrEvent {
    sign_event(
        UnsignedEvent {
            pubkey: sk.public_key().to_hex(),
            created_at: at,
            kind,
            tags,
            content: content.into(),
        },
        &nostr_bbs_core::keys::signing_key_from_bytes(sk.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn has_magick() -> bool {
    std::process::Command::new("magick")
        .arg("-version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn count(c: &Connection, sql: &str) -> i64 {
    c.query_row(sql, [], |r| r.get(0)).unwrap()
}

fn by_import(c: &Connection, key_suffix: &str) -> NostrEvent {
    let id: String = c
        .query_row(
            "SELECT event_id FROM event_tags WHERE name = 'import' AND value LIKE '%' || ?1",
            [key_suffix],
            |r| r.get(0),
        )
        .unwrap();
    d1::read_events(c, &format!("WHERE id = '{id}'"))
        .unwrap()
        .remove(0)
}

#[test]
fn keybase_archive_to_sealed_upload_plan() {
    let root = tmp("main");
    let team = root.join("team");
    keybase_archive(&team, false);
    let w = Work::new(&root.join("work"));
    fsutil::create_private_dir(&w.dir).unwrap();

    // ── adapt
    let (archive, rep) = adapter::run(
        &adapter::keybase::KeybaseAdapter,
        &team,
        "testteam",
        &w.archive(),
    )
    .unwrap();
    assert_eq!(
        (
            rep.edits_applied,
            rep.deleted,
            rep.reactions,
            rep.attachments_ok
        ),
        (1, 1, 2, 1)
    );
    assert!(
        archive.authors.iter().any(|a| a.id == "meetbot" && a.bot),
        "bot role detected"
    );
    let raw = std::fs::read_to_string(w.archive().join("messages.jsonl")).unwrap();
    assert!(raw.contains("typo fixed") && !raw.contains("tpyo") && !raw.contains("to be deleted"));

    // ── identities: alice fresh, bob keeps a PROVEN live key, bob2 merges into bob,
    //    the bot is dropped, jj is the operator with deferred history
    let live = nostr_bbs_core::keys::generate_keypair().unwrap();
    let live_pk = live.public.to_hex();
    let proof = signed(
        &live.secret,
        27235,
        T0,
        vec![],
        &link_statement("keybase:testteam", "bob"),
    );
    std::fs::write(
        w.identities(),
        json!({"version": 1, "default": "require", "authors": {
            "alice": {"decision": "fresh"},
            "bob": {"decision": "existing", "pubkey": live_pk, "proof": proof},
            "bob2": {"decision": "merge", "into": "bob"},
            "meetbot": {"decision": "drop"},
            "jj": {"decision": "operator", "defer": true}}})
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        w.structure(),
        json!({"version": 1,
          "zones": [{"id": "zone2", "cohorts": ["zone2", "minimoonoir"], "encrypted": true}],
          "threads": {
            "rants": {"zone": "zone2", "section": "zone2-rants", "channel": {"new": {"name": "Rants", "about": "Archived"}}},
            "photos": {"zone": "zone2", "section": "zone2-photos", "channel": {"new": {"name": "Photos"}}}},
          "channels": {C1: {"thread": "rants"}, C2: {"thread": "photos"}}})
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        w.target(),
        r#"{"name":"pilot","pod":{"http":"http://127.0.0.1:8789"}}"#,
    )
    .unwrap();

    // ── titles: humanised defaults, one operator edit that a re-run keeps
    assert!(pipeline::load(&w).is_err(), "no titles.json yet");
    let (t, added) = pipeline::write_titles(&w).unwrap();
    assert_eq!(added.len(), 2);
    assert_eq!(t.get(C1), Some("General"));
    let mut edited = t.clone();
    edited.titles.insert(C2.into(), "Pictures of cats".into());
    std::fs::write(w.titles(), serde_json::to_vec(&edited).unwrap()).unwrap();
    let (t, added) = pipeline::write_titles(&w).unwrap();
    assert!(added.is_empty());
    assert_eq!(
        t.get(C2),
        Some("Pictures of cats"),
        "operator edits survive"
    );

    // ── keys (posters + archivist), operator public key recorded from its file
    let l = pipeline::load(&w).unwrap();
    let created = pipeline::ensure_keys(&w, &l).unwrap();
    assert!(
        created.contains(&"archivist".to_string())
            && created.contains(&"author:alice".to_string())
            && created.contains(&"archive:bob".to_string())
    );
    assert!(
        !created.iter().any(|c| c.contains("meetbot")),
        "no key for a dropped author"
    );
    let op_file = root.join("operator.key");
    let op_sk = write_key_file(&op_file);
    let mut ks = nostr_bbs_bulk_import::keystore::Keystore::load(&w.keys()).unwrap();
    ks.import_operator("operator", &op_file).unwrap();
    ks.save().unwrap();
    assert!(
        !std::fs::read_to_string(w.keys())
            .unwrap()
            .contains(&hex::encode(op_sk.as_bytes())),
        "operator secret stored"
    );
    let archivist = ks.get("archivist").unwrap().secret().unwrap();
    let archivist_pk = archivist.public_key().to_hex();
    let archive_bob = ks.get("archive:bob").unwrap().pk.clone();

    // ── media
    let magick = has_magick();
    if magick {
        let m = nostr_bbs_bulk_import::media::Magick::new(Path::new("magick"), &w.dir).unwrap();
        let (_, mr) =
            nostr_bbs_bulk_import::media::process_archive(&archive, &m, &w.media()).unwrap();
        assert_eq!((mr.images, mr.processed, mr.failed), (1, 1, 0));
    }

    // ── build into a relay D1 built from the real migrations
    let db_path = root.join("relay.sqlite");
    drop(relay_db(&db_path));
    let opts = BuildOptions {
        d1: db_path.clone(),
        emit: Emit::Normal,
        require_media: magick,
        operator_key: None,
        unlock: vec![],
    };
    let r = pipeline::build(&w, &opts).unwrap();
    assert!(r.inserted > 0 && r.unchanged == 0);
    assert_eq!(
        r.fitted, 1,
        "the 50k multibyte message is cut to the sealing budget"
    );
    let parity = pipeline::verify_parity(&w, &db_path, Phase::Built).unwrap();
    assert!(parity.problems.is_empty(), "{:?}", parity.problems);
    assert_eq!(parity.orphan_e_tags, 0);

    {
        let c = Connection::open(&db_path).unwrap();
        // shapes and content
        // topic roots are exactly their titles; provenance only in the import tag
        assert_eq!(by_import(&c, &format!("#root:{C1}")).content, "General");
        let root2 = by_import(&c, &format!("#root:{C2}"));
        assert_eq!(root2.content, "Pictures of cats");
        assert!(root2
            .tags
            .iter()
            .any(|t| t[0] == "import" && t[1] == format!("keybase:testteam#root:{C2}")));
        let hello = by_import(&c, &format!("#m:{C1}:1"));
        assert!(
            hello
                .content
                .contains("— reactions: 👍 ×1 (bob) · ❤️ ×1 (jj)"),
            "{}",
            hello.content
        );
        let bob_reply = by_import(&c, &format!("#m:{C1}:2"));
        assert_eq!(
            bob_reply.pubkey, archive_bob,
            "bob's history is signed by his archive key"
        );
        assert!(bob_reply
            .tags
            .iter()
            .any(|t| t.len() == 4 && t[1] == hello.id && t[3] == "quote"));
        let from_bob2 = by_import(&c, &format!("#m:{C1}:5"));
        assert_eq!(from_bob2.pubkey, archive_bob, "merged account signs as bob");
        let to_bot = by_import(&c, &format!("#m:{C1}:13"));
        assert!(to_bot
            .content
            .starts_with("↪ reply to a message that was not migrated"));
        let long = by_import(&c, &format!("#m:{C1}:12"));
        assert!(serde_json::to_string(&long).unwrap().len() <= MAX_EVENT_BYTES);
        let video = by_import(&c, &format!("#m:{C2}:2"));
        assert!(
            video
                .content
                .contains("[video not migrated: clip.mov, 3.3 MB, 2021-01-07]"),
            "{}",
            video.content
        );
        let cat = by_import(&c, &format!("#m:{C2}:1"));
        if magick {
            let sha = fsutil::sha256_hex(PNG);
            assert!(
                cat.content.contains(&format!(
                    "http://127.0.0.1:8789/pods/{archivist_pk}/media/zones/zone2/{sha}.webp"
                )),
                "{}",
                cat.content
            );
        }
        assert_eq!(
            count(
                &c,
                "SELECT count(*) FROM events WHERE content LIKE '%operator says hi%'"
            ),
            0,
            "deferred"
        );
        assert_eq!(
            count(
                &c,
                "SELECT count(*) FROM event_tags WHERE name IN ('zk', 'sealed')"
            ),
            0,
            "outer tags are the sealer's"
        );
        // control rows
        let wl = |pk: &str| {
            count(
                &c,
                &format!("SELECT count(*) FROM whitelist WHERE pubkey = '{pk}'"),
            )
        };
        assert_eq!(wl(&live_pk), 1, "proven live key whitelisted");
        assert_eq!(wl(&archive_bob), 0, "archive key never whitelisted");
        assert_eq!(
            count(
                &c,
                &format!("SELECT is_admin FROM whitelist WHERE pubkey = '{archivist_pk}'")
            ),
            1
        );
        assert_eq!(
            count(
                &c,
                "SELECT count(*) FROM whitelist WHERE cohorts LIKE '%agent%'"
            ),
            0
        );
        assert_eq!(count(&c, &format!("SELECT count(*) FROM pubkey_aliases WHERE old_pubkey = '{archive_bob}' AND new_pubkey = '{live_pk}'")), 1);
        assert_eq!(
            count(
                &c,
                "SELECT count(*) FROM channel_zones WHERE zone = 'zone2'"
            ),
            2
        );
        assert_eq!(count(&c, "SELECT count(*) FROM channel_creators"), 2);
        assert!(
            count(
                &c,
                "SELECT count(*) FROM admin_log WHERE reason = 'bulk-import'"
            ) >= 6
        );
        assert!(
            count(
                &c,
                &format!("SELECT posts_created FROM whitelist WHERE pubkey = '{archivist_pk}'")
            ) >= 4,
            "two threads, two roots"
        );
    }

    // ── idempotent re-run
    let again = pipeline::build(&w, &opts).unwrap();
    assert_eq!((again.signed, again.inserted), (0, 0));

    // ── DM migration is off by default: the step refuses without the opt-in,
    //    and an archive adapted without --include-dms carries no wraps
    let off = pipeline::import_dms(&w, &db_path, false, true, None)
        .unwrap_err()
        .to_string();
    assert!(off.contains("--include-dms"), "{off}");
    let empty = pipeline::import_dms(&w, &db_path, true, true, None)
        .unwrap_err()
        .to_string();
    assert!(empty.contains("holds no DM wraps"), "{empty}");

    // ── a second target (production) from the same work directory and keys:
    //    its own target file, D1 and state directory
    let prod_target = root.join("target-prod.json");
    std::fs::write(
        &prod_target,
        r#"{"name":"production","pod":{"http":"https://pods.example.org"}}"#,
    )
    .unwrap();
    let prod_db = root.join("prod.sqlite");
    drop(relay_db(&prod_db));
    let w_prod = Work::new(&w.dir)
        .with_target(Some(prod_target.clone()))
        .with_state(Some(root.join("state-prod")));
    let prod = pipeline::build(
        &w_prod,
        &BuildOptions {
            d1: prod_db.clone(),
            ..opts.clone()
        },
    )
    .unwrap();
    assert_eq!(
        prod.inserted, r.inserted,
        "same plan, same rows, other database"
    );
    if magick {
        let c = Connection::open(&prod_db).unwrap();
        assert!(by_import(&c, &format!("#m:{C2}:1"))
            .content
            .contains("https://pods.example.org/pods/"));
    }
    assert!(w_prod.seal().starts_with(root.join("state-prod")));
    // mixing targets in one state directory is refused (sealing freezes the URLs)
    let mixed = pipeline::build(
        &Work::new(&w.dir).with_target(Some(prod_target.clone())),
        &opts,
    );
    assert!(
        mixed.unwrap_err().to_string().contains("--state"),
        "the pilot state directory is bound to the pilot target"
    );

    // ── custody: export the archivist offline and retire it here; a re-run
    //    (which signs nothing as the archivist) still works
    let archivist_file = root.join("archivist.key");
    {
        let mut ks = nostr_bbs_bulk_import::keystore::Keystore::load(&w.keys()).unwrap();
        ks.export("archivist", &archivist_file).unwrap();
        ks.retire("archivist").unwrap();
        ks.save().unwrap();
    }
    assert!(!std::fs::read_to_string(w.keys())
        .unwrap()
        .contains(&hex::encode(archivist.as_bytes())));
    let retired = pipeline::build(&w, &opts).unwrap();
    assert_eq!((retired.signed, retired.inserted), (0, 0));
    // the retired archivist can be unlocked for one run from its exported file
    let unlocked = pipeline::build(
        &w,
        &BuildOptions {
            unlock: vec![("archivist".into(), archivist_file.clone())],
            ..opts.clone()
        },
    )
    .unwrap();
    assert_eq!(unlocked.inserted, 0);
    assert!(
        pipeline::build(
            &w,
            &BuildOptions {
                unlock: vec![("archivist".into(), op_file.clone())],
                ..opts.clone()
            },
        )
        .is_err(),
        "a key file that is not the recorded key is refused"
    );

    // ── the deferred operator history, signed by the operator key read for this run only
    assert!(
        pipeline::build(
            &w,
            &BuildOptions {
                emit: Emit::DeferredOnly,
                ..opts.clone()
            }
        )
        .is_err(),
        "needs --operator-key"
    );
    let dr = pipeline::build(
        &w,
        &BuildOptions {
            emit: Emit::DeferredOnly,
            operator_key: Some(op_file.clone()),
            ..opts.clone()
        },
    )
    .unwrap();
    assert_eq!(dr.inserted, 1);
    {
        let c = Connection::open(&db_path).unwrap();
        let op = by_import(&c, &format!("#m:{C1}:11"));
        assert_eq!(op.pubkey, op_sk.public_key().to_hex());
        let bob_reply = by_import(&c, &format!("#m:{C1}:2"));
        assert!(op
            .tags
            .iter()
            .any(|t| t.len() == 4 && t[1] == bob_reply.id && t[3] == "quote"));
    }

    // ── zone key (as minted and granted in the client), one archivist anchor per thread
    let zone_sk = nostr_bbs_core::keys::generate_keypair().unwrap().secret;
    let zone_pk = zone_sk.public_key().to_hex();
    let prep0 = pipeline::seal_prep(&w, &db_path, "ws://127.0.0.1:8787").unwrap();
    assert_eq!(
        prep0
            .missing
            .iter()
            .filter(|m| m.contains("no anchor"))
            .count(),
        2
    );
    assert!(
        pipeline::seal_prep(&w, &db_path, "wss://relay.example.org").is_err(),
        "loopback only"
    );
    {
        let c = Connection::open(&db_path).unwrap();
        for (id, _) in &prep0.channels {
            let anchor = signed(
                &archivist,
                42,
                T0 + 1_000,
                vec![
                    vec!["e".into(), id.clone(), "".into(), "root".into()],
                    vec!["zk".into(), "zone2".into(), "1".into(), zone_pk.clone()],
                ],
                "ciphertext",
            );
            d1::insert_event(&c, &anchor, T0 + 1_000).unwrap();
        }
    }
    let prep = pipeline::seal_prep(&w, &db_path, "ws://127.0.0.1:8787").unwrap();
    assert!(prep.missing.is_empty(), "{:?}", prep.missing);
    let channels: Vec<ChannelSpec> =
        serde_json::from_slice(&std::fs::read(w.seal().join("channels.json")).unwrap()).unwrap();
    assert_eq!(channels.len(), 2);

    // ── zone-migrate offline seal → apply → commit → online verify
    let mut ring = KeyRing::new();
    ring.insert(
        ZoneKey::new(
            "zone2",
            1,
            &hex::encode(zone_sk.as_bytes()),
            &zone_pk,
            KeySource::KeyFile,
        )
        .unwrap(),
    )
    .unwrap();
    let c = Connection::open(&db_path).unwrap();
    offline::check_schema(&c).unwrap();
    let ids: Vec<String> = channels.iter().map(|c| c.id.clone()).collect();
    assert!(
        offline::binding_refusal(&channels, &offline::read_channel_zones(&c, &ids).unwrap())
            .is_none(),
        "build bound the threads"
    );
    let read = |c: &Connection| -> HashMap<String, Vec<NostrEvent>> {
        channels
            .iter()
            .map(|ch| {
                (
                    ch.id.clone(),
                    offline::read_channel_events(c, &ch.id).unwrap(),
                )
            })
            .collect()
    };
    let events = read(&c);
    let topics = offline::read_topic_channels(&c, &offline::topics_of(&events)).unwrap();
    let mut st = State::new("ws://127.0.0.1:8787", &archivist_pk);
    let report = with_hooks(|h| {
        offline::seal_offline(
            &channels, &events, &topics, &ring, &archivist, &mut st, None, h,
        )
    })
    .unwrap();
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    let plaintext = count(&c, "SELECT count(*) FROM events WHERE kind = 42 AND id IN (SELECT event_id FROM event_tags WHERE name = 'import')");
    assert_eq!(
        report.sealed.len() as i64,
        plaintext,
        "every imported kind-42 (roots included) seals"
    );
    let sql_dir = w.seal().join("sql");
    let files =
        offline::write_seal_sql(&sql_dir, &report.sealed, &archivist_pk, 7, T0 + 2_000).unwrap();
    for f in &files {
        c.execute_batch(&std::fs::read_to_string(f).unwrap())
            .unwrap();
    }
    let manifest: Vec<offline::ManifestEntry> =
        serde_json::from_slice(&std::fs::read(sql_dir.join("seal-manifest.json")).unwrap())
            .unwrap();
    let outer_ids: Vec<String> = manifest.iter().map(|m| m.outer_id.clone()).collect();
    let outers = offline::read_events_by_id(&c, &outer_ids).unwrap();
    let committed = offline::commit_sealed(&mut st, &manifest, &outers, &ring);
    assert_eq!(committed.committed as i64, plaintext);
    let mut relay = FakeRelay {
        events: all_events(&c),
        admins: [archivist_pk.clone()].into(),
    };
    let v = with_hooks(|h| block_on(engine::verify(&mut relay, &ring, &mut st, h))).unwrap();
    assert_eq!(v.verified as i64, plaintext);
    let parity = pipeline::verify_parity(&w, &db_path, Phase::Sealed).unwrap();
    assert!(parity.problems.is_empty(), "{:?}", parity.problems);

    // ── search input (before purge): every sealed original, epoch and zone key from the envelope
    let n = pipeline::search_input(&w, &db_path).unwrap();
    assert_eq!(n as i64, plaintext);
    let docs = std::fs::read_to_string(w.search().join("docs.jsonl")).unwrap();
    assert!(docs.contains(&zone_pk) && docs.contains("\"epoch\":1"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(w.search().join("docs.jsonl"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    // ── offline purge → apply → commit
    let outer_ids: Vec<String> = st
        .entries
        .values()
        .filter_map(|e| e.outer_id.clone())
        .collect();
    let outers = offline::read_events_by_id(&c, &outer_ids).unwrap();
    let (items, failed) =
        offline::purge_candidates(&mut st, &ring, &outers, &HashMap::new()).unwrap();
    assert!(failed.is_empty());
    let pfiles = offline::write_purge_sql(
        &w.seal().join("purge"),
        &items,
        &archivist_pk,
        5,
        T0 + 3_000,
    )
    .unwrap();
    for f in &pfiles {
        c.execute_batch(&std::fs::read_to_string(f).unwrap())
            .unwrap();
    }
    let orig: Vec<String> = items.iter().map(|i| i.id.clone()).collect();
    let present = offline::present_ids(&c, &orig).unwrap();
    let gone = orig
        .iter()
        .filter(|i| !present.contains(*i))
        .cloned()
        .collect();
    let tomb = offline::tombstoned_ids(&c, &orig).unwrap();
    let envs = offline::present_ids(
        &c,
        &items.iter().map(|i| i.outer_id.clone()).collect::<Vec<_>>(),
    )
    .unwrap();
    let pc = offline::commit_purged(&mut st, &items, &gone, &tomb, &envs);
    assert_eq!(pc.committed as i64, plaintext);
    assert!(st.entries.values().all(|e| e.status == Status::Purged));
    drop(c);
    let parity = pipeline::verify_parity(&w, &db_path, Phase::Purged).unwrap();
    assert!(parity.problems.is_empty(), "{:?}", parity.problems);
    assert_eq!(
        parity.orphan_e_tags, 0,
        "replies resolve through the archivist's envelopes (F2)"
    );
    assert!(
        pipeline::search_input(&w, &db_path).is_err(),
        "search input after purge is refused"
    );

    // ── re-run after purge: nothing comes back
    let after = pipeline::build(&w, &opts).unwrap();
    assert_eq!((after.signed, after.inserted), (0, 0));
    {
        let c = Connection::open(&db_path).unwrap();
        assert_eq!(count(&c, "SELECT count(*) FROM events WHERE id IN (SELECT event_id FROM event_tags WHERE name = 'import') AND kind = 42"), 0);
    }
    pipeline::scrub(&db_path).unwrap();

    // ── a kept event (a profile from the old deployment) links an object in the OLD
    //    bucket: it goes into the bucket-to-bucket copy list, hostile paths do not
    let old_pk = "ef".repeat(32);
    {
        let c = Connection::open(&db_path).unwrap();
        let someone = nostr_bbs_core::keys::generate_keypair().unwrap().secret;
        let profile = signed(
            &someone,
            0,
            T0,
            vec![],
            &json!({"name": "kept", "picture": format!("https://old-pod.example/pods/{old_pk}/media/public/avatar.webp"),
                    "about": format!("https://old-pod.example/pods/{old_pk}/media/public/.acl https://old-pod.example/pods/{old_pk}/media/../x")})
            .to_string(),
        );
        d1::insert_event(&c, &profile, T0).unwrap();
    }
    // ── upload plan, rehearsed twice into a fresh D1
    let up = pipeline::upload_plan(&w, &db_path, None, 50).unwrap();
    assert!(up.chunks >= 1);
    let copy = std::fs::read_to_string(w.upload().join("r2-copy.jsonl")).unwrap();
    assert_eq!(up.r2_copy, 1, "{copy}");
    assert!(copy.contains(&format!("pods/{old_pk}/media/public/avatar.webp")));
    assert!(
        !copy.contains(&archivist_pk),
        "the import's own objects are uploaded, not copied"
    );
    assert!(
        w.seal().join("pod-objects.jsonl").exists(),
        "seal-prep recorded the pre-purge scan"
    );
    let dump = std::fs::read_to_string(w.upload().join("data-0001.sql")).unwrap();
    assert!(!dump.contains("INSERT OR IGNORE INTO event_tags") && !dump.contains("settings"));
    assert!(
        !dump.contains("é"),
        "non-ASCII text is hex-encoded in the dump"
    );
    let fresh = root.join("fresh.sqlite");
    let fc = relay_db(&fresh);
    let mut chunks: Vec<PathBuf> = std::fs::read_dir(w.upload())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("data-")
        })
        .collect();
    chunks.sort();
    pipeline::apply_dump(&fc, &chunks).unwrap();
    pipeline::apply_dump(&fc, &chunks).unwrap();
    let src = pipeline::table_counts(&Connection::open(&db_path).unwrap()).unwrap();
    assert_eq!(
        pipeline::table_counts(&fc).unwrap(),
        src,
        "rehearsal matches the source, twice applied"
    );
    let script = std::fs::read_to_string(w.upload().join("commands.sh")).unwrap();
    assert!(script.contains("set -euo pipefail") && script.contains("OLD_DB"));

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn keybase_asset_paths_outside_assets_are_refused() {
    let root = tmp("hostile");
    let team = root.join("team");
    keybase_archive(&team, true);
    let err = adapter::run(
        &adapter::keybase::KeybaseAdapter,
        &team,
        "t",
        &root.join("archive"),
    )
    .unwrap_err();
    assert!(err.to_string().contains("outside assets/"), "{err}");
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn schema_and_sql_mirrors_have_not_drifted() {
    let squash = |s: &str| {
        s.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .replace("\\ ", "")
    };
    let lib = squash(include_str!("../../nostr-bbs-relay-worker/src/lib.rs"));
    let admin = squash(include_str!(
        "../../nostr-bbs-relay-worker/src/user_admin.rs"
    ));
    let storage = squash(include_str!(
        "../../nostr-bbs-relay-worker/src/relay_do/storage.rs"
    ));
    for frag in [
        "CREATE TRIGGER IF NOT EXISTS trg_event_tags_ai_v3 AFTER INSERT ON events",
        "AND json_extract(je.value, '$[0]') <> 'probe'",
        "CREATE TABLE IF NOT EXISTS channel_zones (",
        "INSERT INTO channel_zones (channel_id, zone, archived)",
        "ON CONFLICT (channel_id) DO UPDATE SET zone = excluded.zone, archived = excluded.archived",
    ] {
        assert!(
            lib.contains(&squash(frag)),
            "relay lib.rs no longer has: {frag}"
        );
    }
    let alias = squash(d1::ALIAS_UPSERT_GUARDED_SQL);
    assert!(
        admin.contains(&alias.replace("\"", "")),
        "user_admin.rs ALIAS_UPSERT_GUARDED_SQL changed"
    );
    for frag in [
        "WHERE excluded.last_kind0_at >= profiles.last_kind0_at",
        "INSERT INTO channel_creators (channel_id, pubkey, created_at)",
        "AND (created_at > ?3 OR (created_at = ?3 AND id < ?1))",
    ] {
        assert!(
            storage.contains(&squash(frag)),
            "relay storage.rs no longer has: {frag}"
        );
    }
    assert!(squash(common::BOOT_SQL).contains("trg_event_tags_ai_v3"));
}

/// A title changes after the topics were built and sealed: `reset` removes
/// exactly the imported roots, messages and their stale envelopes (dry run
/// first), keeps the anchors, and the rebuilt root is the new title.
#[test]
fn reset_after_a_title_change_rebuilds_cleanly() {
    let root = tmp("reset");
    let team = root.join("team");
    keybase_archive(&team, false);
    let w = Work::new(&root.join("work"));
    fsutil::create_private_dir(&w.dir).unwrap();
    adapter::run(
        &adapter::keybase::KeybaseAdapter,
        &team,
        "testteam",
        &w.archive(),
    )
    .unwrap();
    std::fs::write(
        w.identities(),
        json!({"version": 1, "default": "fresh", "authors": {"meetbot": {"decision": "drop"}}})
            .to_string(),
    )
    .unwrap();
    std::fs::write(
        w.structure(),
        json!({"version": 1,
          "zones": [{"id": "zone2", "cohorts": ["zone2"], "encrypted": true}],
          "threads": {"rants": {"zone": "zone2", "section": "zone2-rants", "channel": {"new": {"name": "Rants"}}}},
          "channels": {C1: {"thread": "rants"}, C2: {"thread": "rants"}}})
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        w.target(),
        r#"{"name":"pilot","pod":{"http":"http://127.0.0.1:8789"}}"#,
    )
    .unwrap();
    pipeline::write_titles(&w).unwrap();
    let l = pipeline::load(&w).unwrap();
    pipeline::ensure_keys(&w, &l).unwrap();
    let archivist = nostr_bbs_bulk_import::keystore::Keystore::load(&w.keys())
        .unwrap()
        .get("archivist")
        .unwrap()
        .secret()
        .unwrap();
    let archivist_pk = archivist.public_key().to_hex();
    let db = root.join("relay.sqlite");
    drop(relay_db(&db));
    let opts = BuildOptions {
        d1: db.clone(),
        emit: Emit::Normal,
        require_media: false,
        operator_key: None,
        unlock: vec![],
    };
    let first = pipeline::build(&w, &opts).unwrap();

    // anchor + offline seal (not purged), as after a first sealing round
    let zone_sk = nostr_bbs_core::keys::generate_keypair().unwrap().secret;
    let zone_pk = zone_sk.public_key().to_hex();
    let prep = pipeline::seal_prep(&w, &db, "ws://127.0.0.1:8787").unwrap();
    let thread = prep.channels[0].0.clone();
    let channels = vec![ChannelSpec {
        id: thread.clone(),
        zone: "zone2".into(),
    }];
    {
        let c = Connection::open(&db).unwrap();
        let anchor = signed(
            &archivist,
            42,
            T0 + 1_000,
            vec![
                vec!["e".into(), thread.clone(), "".into(), "root".into()],
                vec!["zk".into(), "zone2".into(), "1".into(), zone_pk.clone()],
            ],
            "ciphertext",
        );
        d1::insert_event(&c, &anchor, T0 + 1_000).unwrap();
        let mut ring = KeyRing::new();
        ring.insert(
            ZoneKey::new(
                "zone2",
                1,
                &hex::encode(zone_sk.as_bytes()),
                &zone_pk,
                KeySource::KeyFile,
            )
            .unwrap(),
        )
        .unwrap();
        let events: HashMap<String, Vec<NostrEvent>> = [(
            thread.clone(),
            offline::read_channel_events(&c, &thread).unwrap(),
        )]
        .into();
        let topics = offline::read_topic_channels(&c, &offline::topics_of(&events)).unwrap();
        let mut st = State::new("ws://127.0.0.1:8787", &archivist_pk);
        let rep = with_hooks(|h| {
            offline::seal_offline(
                &channels, &events, &topics, &ring, &archivist, &mut st, None, h,
            )
        })
        .unwrap();
        assert!(!rep.sealed.is_empty() && rep.failed.is_empty());
        let files = offline::write_seal_sql(
            &w.seal().join("sql"),
            &rep.sealed,
            &archivist_pk,
            100,
            T0 + 2_000,
        )
        .unwrap();
        for f in &files {
            c.execute_batch(&std::fs::read_to_string(f).unwrap())
                .unwrap();
        }
    }
    let sealed_count = {
        let c = Connection::open(&db).unwrap();
        count(&c, "SELECT count(*) FROM event_tags WHERE name = 'sealed'")
    };

    // the operator renames a topic
    let mut t = nostr_bbs_bulk_import::titles::Titles::load(&w.titles()).unwrap();
    t.titles.insert(C1.into(), "Kids and shit".into());
    std::fs::write(w.titles(), serde_json::to_vec(&t).unwrap()).unwrap();

    // dry run: reports, changes nothing
    let dry = pipeline::reset(&w, &db, false).unwrap();
    assert!(!dry.executed);
    assert_eq!(dry.roots, 2);
    assert_eq!(dry.envelopes as i64, sealed_count);
    assert_eq!(dry.anchors_kept, 1);
    assert_eq!(
        (dry.roots + dry.messages) as i64,
        sealed_count,
        "every imported kind-42 had an envelope"
    );
    {
        let c = Connection::open(&db).unwrap();
        assert_eq!(
            count(&c, "SELECT count(*) FROM event_tags WHERE name = 'sealed'"),
            sealed_count
        );
    }

    // execute: exactly the imported kind-42s and their envelopes go; the rest stays
    let done = pipeline::reset(&w, &db, true).unwrap();
    assert!(done.executed && done.backup.as_ref().unwrap().join("seal").exists());
    {
        let c = Connection::open(&db).unwrap();
        assert_eq!(
            count(&c, "SELECT count(*) FROM events WHERE kind = 42"),
            1,
            "only the anchor is left"
        );
        assert_eq!(
            count(&c, "SELECT count(*) FROM events WHERE kind = 40"),
            1,
            "the thread header stays"
        );
        assert!(
            count(&c, "SELECT count(*) FROM events WHERE kind = 0") > 0,
            "profiles stay"
        );
        assert_eq!(
            count(
                &c,
                "SELECT count(*) FROM event_tags WHERE event_id NOT IN (SELECT id FROM events)"
            ),
            0
        );
    }

    // rebuild: the root is the new title, the tree is whole again
    let again = pipeline::build(&w, &opts).unwrap();
    assert_eq!(
        again.inserted,
        done.roots + done.messages,
        "the same roots and messages, re-signed; header and profiles kept"
    );
    assert!(first.inserted > again.inserted);
    {
        let c = Connection::open(&db).unwrap();
        assert_eq!(
            by_import(&c, &format!("#root:{C1}")).content,
            "Kids and shit"
        );
    }
    let parity = pipeline::verify_parity(&w, &db, Phase::Built).unwrap();
    assert!(parity.problems.is_empty(), "{:?}", parity.problems);

    // an envelope that is not an archivist seal of this import makes reset refuse
    {
        let c = Connection::open(&db).unwrap();
        let stranger = nostr_bbs_core::keys::generate_keypair().unwrap().secret;
        let fake = signed(
            &stranger,
            42,
            T0 + 5_000,
            vec![
                vec!["e".into(), thread.clone(), "".into(), "root".into()],
                vec!["sealed".into(), "ab".repeat(32), "1".into()],
            ],
            "x",
        );
        d1::insert_event(&c, &fake, T0 + 5_000).unwrap();
    }
    let err = pipeline::reset(&w, &db, false).unwrap_err().to_string();
    assert!(err.contains("not an archivist seal"), "{err}");
    std::fs::remove_dir_all(&root).unwrap();
}
