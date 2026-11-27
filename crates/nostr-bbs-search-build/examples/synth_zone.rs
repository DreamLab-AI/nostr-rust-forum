//! Synthetic zone events for local runs of the builder: imported posts as
//! ADR-2017 sealed envelopes and posts written in the forum (NIP-44 to the
//! zone key), with throwaway keys and generated sentences. Never real text.
//!
//! ```text
//! cargo run --release -p nostr-bbs-search-build --example synth_zone -- \
//!     OUT_DIR IMPORTED NATIVE START_TIME [SEED] [SENTENCES_PER_POST] [EXTRAS]
//! ```
//!
//! With `EXTRAS` = 1 it also reads the events already in `events.jsonl` and
//! appends, after the new posts: an edit of the first imported post by its
//! original author (targeting the original's id), a kind-5 by the second
//! imported post's author naming that original's id, and a kind-5 by the
//! first live post's author naming its id.
//!
//! Writes, into `OUT_DIR` (all mode 0600):
//! - `events.jsonl`: the events (append-only: run again with a later
//!   `START_TIME` and `IMPORTED = 0` for a night of new posts);
//! - `keys.json`: the zone key, in zone-migrate's key-file format;
//! - `archivist.key`, `indexer.key`: throwaway publisher keys (hex).
//!
//! The zone is `zone2`, epoch 1, and every key is derived from fixed bytes,
//! so runs agree with each other.

use std::io::Write;
use std::path::Path;

use nostr_bbs_core::keys::{signing_key_from_bytes, SecretKey};
use nostr_bbs_core::sealed::seal_original;
use nostr_bbs_core::{sign_event, NostrEvent, UnsignedEvent};

const ZONE: &str = "zone2";
const CHANNEL: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const ZONE_SECRET: [u8; 32] = [0x5a; 32];
const MIGRATOR: [u8; 32] = [0x5b; 32];
const ARCHIVIST: [u8; 32] = [0x5c; 32];
const INDEXER: [u8; 32] = [0x5d; 32];
const AUTHORS: [[u8; 32]; 3] = [[0x61; 32], [0x62; 32], [0x63; 32]];

const WORDS: &[&str] = &[
    "harbour",
    "lantern",
    "meadow",
    "copper",
    "river",
    "signal",
    "garden",
    "winter",
    "market",
    "orchard",
    "bridge",
    "compass",
    "festival",
    "library",
    "mountain",
    "pottery",
    "railway",
    "sailing",
    "theatre",
    "village",
    "weather",
    "kitchen",
    "bicycle",
    "concert",
    "ferry",
    "forest",
    "glacier",
    "island",
    "journal",
    "kettle",
    "ladder",
    "museum",
    "notebook",
    "opera",
    "pebble",
    "quarry",
    "rooftop",
    "sunrise",
    "tunnel",
    "umbrella",
    "valley",
    "workshop",
    "yacht",
    "zebra",
    "apricot",
    "biscuit",
    "cathedral",
    "dolphin",
    "engine",
    "falcon",
];

fn pk(b: [u8; 32]) -> String {
    SecretKey::from_bytes(b)
        .expect("fixed key")
        .public_key()
        .to_hex()
}

fn sign(secret: [u8; 32], created_at: u64, tags: Vec<Vec<String>>, content: &str) -> NostrEvent {
    sign_event(
        UnsignedEvent {
            pubkey: pk(secret),
            created_at,
            kind: 42,
            tags,
            content: content.into(),
        },
        &signing_key_from_bytes(&secret).expect("signing key"),
    )
    .expect("signed")
}

fn sentence(x: &mut u64) -> String {
    let n = 6 + (*x % 10) as usize;
    let mut words = Vec::with_capacity(n);
    for _ in 0..n {
        *x ^= *x << 13;
        *x ^= *x >> 7;
        *x ^= *x << 17;
        words.push(WORDS[(*x % WORDS.len() as u64) as usize]);
    }
    let mut s = words.join(" ");
    s.push('.');
    s
}

fn write_private(path: &Path, bytes: &[u8], append: bool) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(append)
        .write(true)
        .truncate(!append)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

fn author_key(pubkey: &str) -> Option<[u8; 32]> {
    AUTHORS.iter().copied().find(|a| pk(*a) == pubkey)
}

/// An edit and two deletions aimed at events already in `events.jsonl`.
fn extras_for(
    out: &Path,
    at: u64,
    zone_pk: &str,
    zone_pk_bytes: &[u8; 32],
) -> Result<String, Box<dyn std::error::Error>> {
    let existing = std::fs::read_to_string(out.join("events.jsonl"))?;
    let events: Vec<NostrEvent> = existing
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    let mut originals = events
        .iter()
        .filter(|e| nostr_bbs_core::sealed::has_sealed_tag(&e.tags))
        .map(|e| nostr_bbs_core::sealed::open_sealed(e, &ZONE_SECRET));
    let first = originals.next().ok_or("no imported post to edit")??;
    let second = originals.next().ok_or("no second imported post")??;
    let live = events
        .iter()
        .find(|e| e.kind == 42 && !nostr_bbs_core::sealed::has_sealed_tag(&e.tags))
        .ok_or("no live post")?;
    let root = vec![
        "e".to_string(),
        CHANNEL.into(),
        String::new(),
        "root".into(),
    ];
    let zk = vec![
        "zk".to_string(),
        ZONE.into(),
        "1".into(),
        zone_pk.to_string(),
    ];
    let editor = author_key(&first.pubkey).ok_or("unknown author")?;
    let ct = nostr_bbs_core::nip44_encrypt(&editor, zone_pk_bytes, "an edited imported post")?;
    let edit = sign(
        editor,
        at,
        vec![
            root,
            vec!["e".into(), first.id.clone(), String::new(), "edit".into()],
            zk,
        ],
        &ct,
    );
    let del = |author: [u8; 32], target: &str, when: u64| {
        sign_event(
            UnsignedEvent {
                pubkey: pk(author),
                created_at: when,
                kind: 5,
                tags: vec![vec!["e".into(), target.to_string()]],
                content: String::new(),
            },
            &signing_key_from_bytes(&author).expect("signing key"),
        )
        .expect("signed")
    };
    let d1 = del(
        author_key(&second.pubkey).ok_or("unknown author")?,
        &second.id,
        at + 1,
    );
    let d2 = del(
        author_key(&live.pubkey).ok_or("unknown author")?,
        &live.id,
        at + 2,
    );
    let mut s = String::new();
    for ev in [edit, d1, d2] {
        s.push_str(&serde_json::to_string(&ev)?);
        s.push('\n');
    }
    eprintln!(
        "extras: edit of {}, deletions of {} and {}",
        &first.id[..12],
        &second.id[..12],
        &live.id[..12]
    );
    Ok(s)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        return Err(
            "usage: synth_zone OUT_DIR IMPORTED NATIVE START_TIME [SEED] \
             [SENTENCES_PER_POST] [EXTRAS]"
                .into(),
        );
    }
    let out = Path::new(&args[1]);
    let imported: u64 = args[2].parse()?;
    let native: u64 = args[3].parse()?;
    let start: u64 = args[4].parse()?;
    let mut x: u64 = args.get(5).map_or(Ok(0x9e37_79b9), |s| s.parse())? | 1;
    let per_post: usize = args.get(6).map_or(Ok(1), |s| s.parse())?;
    let extras = args.get(7).is_some_and(|s| s == "1");
    std::fs::create_dir_all(out)?;
    let zone_pk = pk(ZONE_SECRET);
    let zone_pk_bytes: [u8; 32] = hex::decode(&zone_pk)?.try_into().map_err(|_| "pk")?;
    let migrator = SecretKey::from_bytes(MIGRATOR)?;
    let root = vec![
        "e".to_string(),
        CHANNEL.into(),
        String::new(),
        "root".into(),
    ];
    let zk = vec!["zk".to_string(), ZONE.into(), "1".into(), zone_pk.clone()];
    let mut lines = String::new();
    for i in 0..imported + native {
        let author = AUTHORS[(i % AUTHORS.len() as u64) as usize];
        let text = (0..per_post.max(1))
            .map(|_| sentence(&mut x))
            .collect::<Vec<_>>()
            .join(" ");
        let ev = if i < imported {
            let original = sign(author, start + i, vec![root.clone()], &text);
            seal_original(&original, ZONE, 1, &zone_pk, &migrator)?
        } else {
            let ct = nostr_bbs_core::nip44_encrypt(&author, &zone_pk_bytes, &text)?;
            sign(author, start + i, vec![root.clone(), zk.clone()], &ct)
        };
        lines.push_str(&serde_json::to_string(&ev)?);
        lines.push('\n');
    }
    if extras {
        let after = start + imported + native;
        lines.push_str(&extras_for(out, after, &zone_pk, &zone_pk_bytes)?);
    }
    write_private(&out.join("events.jsonl"), lines.as_bytes(), true)?;
    let keys = serde_json::json!({
        "version": 1,
        "owner": pk(INDEXER),
        "keys": [{"zone": ZONE, "epoch": 1, "secret": hex::encode(ZONE_SECRET), "pubkey": zone_pk}],
    });
    write_private(&out.join("keys.json"), keys.to_string().as_bytes(), false)?;
    write_private(
        &out.join("archivist.key"),
        hex::encode(ARCHIVIST).as_bytes(),
        false,
    )?;
    write_private(
        &out.join("indexer.key"),
        hex::encode(INDEXER).as_bytes(),
        false,
    )?;
    println!(
        "{{\"events\":{},\"archivist\":\"{}\",\"indexer\":\"{}\"}}",
        imported + native,
        pk(ARCHIVIST),
        pk(INDEXER)
    );
    Ok(())
}
