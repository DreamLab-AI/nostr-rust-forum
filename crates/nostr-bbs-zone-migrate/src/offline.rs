//! Offline sealing and purging: the same seal, checks and state as the
//! online path, but reading the relay's local D1 directly and writing SQL for
//! `wrangler d1 execute --local --file`, so a large history is sealed across
//! all cores instead of one envelope per relay round trip.
//!
//! The zone key comes from the same place as online (`--keys-file` and
//! grants harvested over the relay), and the same anchor check applies: the
//! key must match the zone's live encrypted posts. Only the I/O changes:
//!
//! 1. [`read_channel_events`] reads each listed channel's kind-42s from the
//!    D1 SQLite file (the rows a `#e` REQ returns), and
//!    [`crate::plan::scan_channel`] classifies them exactly as online.
//! 2. [`seal_offline`] records new originals as planned, adopts envelopes
//!    already present, then seals the rest in parallel with one
//!    [`OriginalSealer`] per zone (conversation key derived once) and
//!    self-checks every envelope (verify, open, compare byte for byte),
//!    as the online read-back does. Nothing is marked sealed yet.
//! 3. [`write_seal_sql`] writes the envelopes as chunked SQL with the rows
//!    the relay's accepted-event path writes (see [`envelope_insert_sql`]),
//!    plus a manifest; the operator applies the chunks with wrangler.
//! 4. [`commit_sealed`] re-reads each envelope from D1, re-opens it and only
//!    then marks the entry `sealed` in the state file, so the online
//!    `verify` and `purge` work unchanged.
//! 5. [`purge_candidates`] / [`write_purge_sql`] / [`commit_purged`] mirror
//!    `POST /api/admin/events/delete`: tombstone, then delete the kind-42
//!    row, with one `admin_log` row per chunk.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use nostr_bbs_core::keys::SecretKey;
use nostr_bbs_core::sealed::{channel_of, open_sealed_with_conversation_key, OriginalSealer};
use nostr_bbs_core::{verify_event, NostrEvent};
use rayon::prelude::*;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};

use crate::channels::ChannelSpec;
use crate::engine::{
    adopt, check_anchor, fail, needs_seal, require_keys, set_sealed, unanchored_purge_refusal,
    EngineError, Hooks, Plan,
};
use crate::keys::KeyRing;
use crate::plan::{scan_channel, ChannelScan};
use crate::state::{sha256_hex, Entry, State, Status, Step};

/// Envelopes per seal SQL chunk.
pub const DEFAULT_CHUNK: usize = 2_000;

/// Ids per purge SQL chunk and audit row: the relay's `MAX_DELETE_IDS`
/// (one `POST /api/admin/events/delete` call), which also keeps each audit
/// row well inside D1's statement size limit.
pub const PURGE_CHUNK: usize = 200;

/// Open the D1 SQLite file read-only (safe while the relay runs).
pub fn open_d1(path: &Path) -> rusqlite::Result<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
}

fn row_event(r: &rusqlite::Row<'_>) -> rusqlite::Result<Option<NostrEvent>> {
    let tags: String = r.get(4)?;
    let Ok(tags) = serde_json::from_str::<Vec<Vec<String>>>(&tags) else {
        return Ok(None);
    };
    Ok(Some(NostrEvent {
        id: r.get(0)?,
        pubkey: r.get(1)?,
        created_at: r.get::<_, i64>(2)? as u64,
        kind: r.get::<_, i64>(3)? as u64,
        tags,
        content: r.get(5)?,
        sig: r.get(6)?,
    }))
}

/// Every kind-42 carrying `["e", channel, ...]`: the rows the relay returns
/// for `{"kinds":[42], "#e":[channel]}` to an admin.
pub fn read_channel_events(db: &Connection, channel: &str) -> rusqlite::Result<Vec<NostrEvent>> {
    let mut s = db.prepare(
        "SELECT DISTINCT e.id, e.pubkey, e.created_at, e.kind, e.tags, e.content, e.sig \
         FROM event_tags t JOIN events e ON e.id = t.event_id \
         WHERE t.name = 'e' AND t.value = ?1 AND e.kind = 42",
    )?;
    let rows = s.query_map([channel], row_event)?;
    rows.filter_map(|r| r.transpose()).collect()
}

/// Every event naming `zone` in a `zk` tag (any kind).
pub fn read_zone_events(db: &Connection, zone: &str) -> rusqlite::Result<Vec<NostrEvent>> {
    let mut s = db.prepare(
        "SELECT DISTINCT e.id, e.pubkey, e.created_at, e.kind, e.tags, e.content, e.sig \
         FROM event_tags t JOIN events e ON e.id = t.event_id \
         WHERE t.name = 'zk' AND t.value = ?1",
    )?;
    let rows = s.query_map([zone], row_event)?;
    rows.filter_map(|r| r.transpose()).collect()
}

/// Events by id (absent ids are simply missing from the map).
pub fn read_events_by_id(
    db: &Connection,
    ids: &[String],
) -> rusqlite::Result<HashMap<String, NostrEvent>> {
    let mut out = HashMap::with_capacity(ids.len());
    let mut s = db.prepare(
        "SELECT id, pubkey, created_at, kind, tags, content, sig FROM events WHERE id = ?1",
    )?;
    for id in ids {
        match s.query_row([id], row_event) {
            Ok(Some(ev)) => {
                out.insert(ev.id.clone(), ev);
            }
            Ok(None) | Err(rusqlite::Error::QueryReturnedNoRows) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// The zone each channel is bound to in the relay's `channel_zones`
/// (absent: not bound).
pub fn read_channel_zones(
    db: &Connection,
    channels: &[String],
) -> rusqlite::Result<HashMap<String, String>> {
    let mut s = db.prepare("SELECT zone FROM channel_zones WHERE channel_id = ?1")?;
    let mut out = HashMap::new();
    for c in channels {
        match s.query_row([c], |r| r.get::<_, String>(0)) {
            Ok(z) => {
                out.insert(c.clone(), z);
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// Why `channels` must not be sealed offline as listed, if they must not:
/// every listed channel must be bound in `channel_zones` to exactly the
/// zone the channels file names (the relay refuses a sealed envelope into
/// a channel bound elsewhere or not at all; offline must not rely on the
/// channels file alone).
pub fn binding_refusal(
    channels: &[ChannelSpec],
    bound: &HashMap<String, String>,
) -> Option<String> {
    for c in channels {
        match bound.get(&c.id) {
            Some(z) if *z == c.zone => {}
            Some(z) => {
                return Some(format!(
                    "channel {} is bound to zone {z} in channel_zones, not {} as the channels file says",
                    c.id, c.zone
                ))
            }
            None => {
                return Some(format!(
                    "channel {} is not bound to any zone in channel_zones (the relay would refuse its envelopes)",
                    c.id
                ))
            }
        }
    }
    None
}

/// The channel each reply topic lives in, from D1: the root-marked channel
/// of the stored kind-42 with that id, or of the admin-authored sealed
/// envelope wrapping it (the relay's F2 resolution). Topics that resolve to
/// nothing, to a stored event that is not kind 42, or to envelopes that
/// disagree, are absent. Envelopes count only in the shape the relay's
/// `SEALED_ENVELOPES_FOR_SQL` accepts: a `sealed` tag for the topic with a
/// numeric version, and a `zk` tag.
pub fn read_topic_channels(
    db: &Connection,
    topics: &HashSet<String>,
) -> rusqlite::Result<HashMap<String, String>> {
    let mut by_id = db.prepare(
        "SELECT id, pubkey, created_at, kind, tags, content, sig FROM events WHERE id = ?1",
    )?;
    let mut sealed = db.prepare(
        "SELECT s.id, s.pubkey, s.created_at, s.kind, s.tags, s.content, s.sig \
         FROM event_tags t JOIN events s ON s.id = t.event_id AND s.kind = 42 \
         WHERE t.name = 'sealed' AND t.value = ?1 \
           AND s.pubkey IN (SELECT pubkey FROM whitelist WHERE is_admin = 1) LIMIT 8",
    )?;
    let mut out = HashMap::new();
    for topic in topics {
        let channel = match by_id.query_row([topic], row_event) {
            Ok(ev) => ev
                .as_ref()
                .filter(|e| e.kind == 42)
                .and_then(|e| channel_of(e).map(str::to_string)),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let rows: Vec<NostrEvent> = sealed
                    .query_map([topic], row_event)?
                    .filter_map(|r| r.transpose())
                    .collect::<rusqlite::Result<_>>()?;
                let relay_shape = |e: &&NostrEvent| {
                    let sealed_ok = e.tags.iter().any(|t| {
                        t.len() >= 3
                            && t[0] == "sealed"
                            && t[1] == *topic
                            && !t[2].is_empty()
                            && t[2].bytes().all(|b| b.is_ascii_digit())
                    });
                    sealed_ok
                        && e.tags
                            .iter()
                            .any(|t| t.first().map(String::as_str) == Some("zk"))
                };
                let chans: HashSet<&str> = rows
                    .iter()
                    .filter(relay_shape)
                    .filter_map(channel_of)
                    .collect();
                (chans.len() == 1).then(|| chans.into_iter().next().unwrap().to_string())
            }
            Err(e) => return Err(e),
        };
        if let Some(c) = channel {
            out.insert(topic.clone(), c);
        }
    }
    Ok(out)
}

/// The reply topics named by `events` (for [`read_topic_channels`]).
pub fn topics_of(events: &HashMap<String, Vec<NostrEvent>>) -> HashSet<String> {
    events
        .values()
        .flatten()
        .filter_map(|e| nostr_bbs_core::sealed::reply_root_of(e).map(str::to_string))
        .collect()
}

/// Why `original` (in `channel`) must not be sealed, if it must not: its
/// reply topic, if any, must be a 64-hex id of a kind-42 in the same
/// channel (the relay's F2 rule for kind-42 writes; also keeps untrusted
/// text out of the generated SQL).
pub fn topic_refusal(
    original: &NostrEvent,
    channel: &str,
    topic_channels: &HashMap<String, String>,
) -> Option<String> {
    let topic = nostr_bbs_core::sealed::reply_root_of(original)?;
    if topic.len() != 64
        || !topic
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Some("reply topic is not a 64-character lowercase hex id".into());
    }
    match topic_channels.get(topic) {
        Some(c) if c == channel => None,
        Some(_) => Some("reply topic is a message in another channel".into()),
        None => {
            Some("reply topic is not a stored message (topic roots must be imported first)".into())
        }
    }
}

/// Whether the relay's schema has what the envelope inserts depend on (the
/// tag-writing trigger and the tombstone table). Boot the relay once first.
pub fn check_schema(db: &Connection) -> Result<(), String> {
    let has = |kind: &str, name: &str| -> bool {
        db.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = ?1 AND name = ?2",
            [kind, name],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n > 0)
        .unwrap_or(false)
    };
    for (kind, name) in [
        ("table", "events"),
        ("table", "event_tags"),
        ("table", "deleted_events"),
        ("table", "whitelist"),
        ("table", "channel_zones"),
        ("table", "admin_log"),
        ("trigger", "trg_event_tags_ai_v3"),
    ] {
        if !has(kind, name) {
            return Err(format!(
                "the D1 has no {kind} {name}: boot the current relay once (ensure_schema) first"
            ));
        }
    }
    Ok(())
}

/// One self-checked envelope ready to write.
#[derive(Debug, Clone)]
pub struct SealedEnvelope {
    /// The original's id.
    pub original_id: String,
    /// The original's (and envelope's) `created_at`.
    pub created_at: u64,
    /// Epoch sealed to.
    pub epoch: u32,
    /// The envelope.
    pub envelope: NostrEvent,
    /// SHA-256 of the original's canonical JSON (what the state records).
    pub inner_sha256: String,
}

/// Result of [`seal_offline`].
#[derive(Debug, Default)]
pub struct OfflineSealReport {
    /// The plan the run started from.
    pub plan: Plan,
    /// Entries marked sealed because their envelope was already in D1.
    pub adopted: usize,
    /// Envelopes sealed and self-checked, oldest first, not yet written.
    pub sealed: Vec<SealedEnvelope>,
    /// Entries marked failed: `(original id, reason)`.
    pub failed: Vec<(String, String)>,
    /// Wall-clock seconds spent sealing (the parallel part).
    pub seal_seconds: f64,
}

/// Scan, plan, check the anchor, adopt and seal (see the module docs). The
/// key ring, anchor check, adopt rule and per-envelope self-check are the
/// online ones; `limit` caps how many originals are sealed this run.
#[allow(clippy::too_many_arguments)]
pub fn seal_offline(
    channels: &[ChannelSpec],
    channel_events: &HashMap<String, Vec<NostrEvent>>,
    topic_channels: &HashMap<String, String>,
    keys: &KeyRing,
    migrator: &SecretKey,
    state: &mut State,
    limit: Option<usize>,
    hooks: &mut Hooks<'_>,
) -> Result<OfflineSealReport, EngineError> {
    let scans: Vec<ChannelScan> = channels
        .iter()
        .map(|spec| {
            scan_channel(
                spec,
                channel_events
                    .get(&spec.id)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
                keys,
            )
        })
        .collect();
    let mut report = OfflineSealReport::default();
    for s in &scans {
        report.plan.channels.push(s.plan.clone());
    }

    let mut originals: HashMap<String, &NostrEvent> = HashMap::new();
    let mut envelopes: HashMap<String, &Vec<NostrEvent>> = HashMap::new();
    for scan in &scans {
        for c in &scan.candidates {
            originals.insert(c.original.id.clone(), &c.original);
        }
        for (inner, evs) in &scan.envelopes_by_inner {
            envelopes.insert(inner.clone(), evs);
        }
    }
    let mut added = 0usize;
    for scan in &scans {
        for c in &scan.candidates {
            if !state.entries.contains_key(&c.original.id) {
                state.entries.insert(
                    c.original.id.clone(),
                    Entry::planned(&scan.plan.channel, &scan.plan.zone, c.original.created_at),
                );
                added += 1;
            }
        }
    }
    if added > 0 {
        (hooks.progress)(&format!(
            "recorded {added} new plaintext originals as planned"
        ));
        (hooks.persist)(state)?;
    }

    let listed: HashSet<&str> = channels.iter().map(|c| c.id.as_str()).collect();
    let mut work: Vec<(String, u64)> = state
        .entries
        .iter()
        .filter(|(_, e)| listed.contains(e.channel.as_str()) && needs_seal(&e.status))
        .map(|(id, e)| (id.clone(), e.created_at))
        .collect();
    work.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));

    let zones: std::collections::BTreeSet<String> = work
        .iter()
        .map(|(id, _)| state.entries[id].zone.clone())
        .collect();
    let missing: Vec<String> = zones
        .iter()
        .filter(|z| keys.current(z).is_none())
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(EngineError::MissingKeys(missing));
    }
    // The online anchor check, unchanged: the seal key must be the key the
    // zone's live encrypted posts use. No unanchored path offline. Offline it
    // also runs per channel, so one anchored channel cannot vouch for a
    // mislisted second channel of the same zone.
    for zone in &zones {
        check_anchor(zone, keys, &scans)?;
        for scan in scans.iter().filter(|s| s.plan.zone == *zone) {
            check_anchor(zone, keys, std::slice::from_ref(scan))
                .map_err(|e| EngineError::Refused(format!("channel {}: {e}", scan.plan.channel)))?;
        }
    }

    // Adopt envelopes already in D1 (e.g. from the online run).
    let mut to_seal: Vec<(String, u64)> = Vec::new();
    for (id, created_at) in work {
        let channel = state.entries[&id].channel.clone();
        let existing = envelopes.get(&id).map(|v| v.as_slice()).unwrap_or(&[]);
        if let Some((outer, epoch, digest)) = adopt(
            existing,
            &id,
            &channel,
            originals.get(&id).copied(),
            keys,
            &migrator.public_key().to_hex(),
        ) {
            set_sealed(state, &id, epoch, &outer, digest);
            report.adopted += 1;
        } else {
            to_seal.push((id, created_at));
        }
    }
    if report.adopted > 0 {
        (hooks.progress)(&format!(
            "adopted {} envelopes already present",
            report.adopted
        ));
        (hooks.persist)(state)?;
    }
    if let Some(l) = limit {
        to_seal.truncate(l);
    }

    // One sealer per zone, and the conversation key for the self-check (the
    // same key: NIP-44 is symmetric, zone secret x migrator pubkey).
    let migrator_pk = migrator.public_key().to_hex();
    let mut sealers: HashMap<String, (OriginalSealer, zeroize::Zeroizing<[u8; 32]>, u32)> =
        HashMap::new();
    for zone in &zones {
        let key = keys.current(zone).expect("checked above");
        let sk = SecretKey::from_bytes(*migrator.as_bytes())
            .map_err(|e| EngineError::Refused(format!("migrator key: {e}")))?;
        let sealer = OriginalSealer::new(zone, key.epoch(), key.pubkey(), sk)
            .map_err(|e| EngineError::Refused(format!("zone {zone} key: {e}")))?;
        let mpk = nostr_bbs_core::keys::PublicKey::from_hex(&migrator_pk)
            .map_err(|e| EngineError::Refused(format!("migrator pubkey: {e}")))?;
        let ck = zeroize::Zeroizing::new(
            nostr_bbs_core::nip44::conversation_key(key.secret(), mpk.as_bytes())
                .map_err(|e| EngineError::Refused(format!("zone {zone} key: {e}")))?,
        );
        sealers.insert(zone.clone(), (sealer, ck, key.epoch()));
    }

    // F2 placement, as the relay checks it for every kind-42 write.
    let mut misplaced: Vec<(String, String)> = Vec::new();
    let jobs: Vec<(String, u64, String, String, &NostrEvent)> = to_seal
        .iter()
        .filter_map(|(id, ca)| {
            let e = &state.entries[id];
            let o = originals.get(id)?;
            if let Some(why) = topic_refusal(o, &e.channel, topic_channels) {
                misplaced.push((id.clone(), why));
                return None;
            }
            Some((id.clone(), *ca, e.zone.clone(), e.channel.clone(), *o))
        })
        .collect();
    let not_found: Vec<String> = to_seal
        .iter()
        .filter(|(id, _)| !originals.contains_key(id))
        .map(|(id, _)| id.clone())
        .collect();

    (hooks.progress)(&format!(
        "sealing {} originals on {} threads",
        jobs.len(),
        rayon::current_num_threads()
    ));
    let start = std::time::Instant::now();
    let results: Vec<Result<SealedEnvelope, (String, String)>> = jobs
        .par_iter()
        .map(|(id, created_at, zone, channel, original)| {
            let (sealer, ck, epoch) = &sealers[zone];
            let envelope = sealer
                .seal(original)
                .map_err(|e| (id.clone(), e.to_string()))?;
            let expected = serde_json::to_string(original).expect("event serialises");
            self_check(&envelope, id, channel, &migrator_pk, ck, &expected)
                .map_err(|r| (id.clone(), r))?;
            Ok(SealedEnvelope {
                original_id: id.clone(),
                created_at: *created_at,
                epoch: *epoch,
                inner_sha256: sha256_hex(expected.as_bytes()),
                envelope,
            })
        })
        .collect();
    report.seal_seconds = start.elapsed().as_secs_f64();

    for id in not_found {
        fail(
            state,
            &mut report.failed,
            &id,
            Step::Seal,
            "original not found in D1",
            None,
        );
    }
    for (id, why) in misplaced {
        fail(state, &mut report.failed, &id, Step::Seal, &why, None);
    }
    for r in results {
        match r {
            Ok(s) => report.sealed.push(s),
            Err((id, reason)) => fail(state, &mut report.failed, &id, Step::Seal, &reason, None),
        }
    }
    report.sealed.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then(a.original_id.cmp(&b.original_id))
    });
    if !report.failed.is_empty() {
        (hooks.persist)(state)?;
    }
    Ok(report)
}

/// The online read-back check for a freshly sealed envelope, without the
/// relay: id and signature verify, the channel is right, it opens with the
/// zone key (cached conversation key, bound to the migrator as author), it
/// wraps the original, and the inner JSON equals the original byte for byte.
pub fn self_check(
    outer: &NostrEvent,
    original_id: &str,
    channel: &str,
    migrator_pk: &str,
    ck: &[u8; 32],
    expected_inner: &str,
) -> Result<(), String> {
    if !verify_event(outer) {
        return Err("envelope id or signature does not verify".into());
    }
    if channel_of(outer) != Some(channel) {
        return Err("envelope is in a different channel".into());
    }
    let author = hex32(migrator_pk).ok_or("bad migrator pubkey")?;
    let inner = open_sealed_with_conversation_key(outer, &author, ck).map_err(|e| e.to_string())?;
    if inner.id != original_id {
        return Err("envelope wraps a different event".into());
    }
    if serde_json::to_string(&inner).expect("event serialises") != expected_inner {
        return Err("sealed inner event differs from the original".into());
    }
    Ok(())
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}

/// SQL string literal.
fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// The rows the relay writes when it accepts a sealed envelope from the
/// migrator (`save_event` then `handle_event`), as SQL:
///
/// - `events` with `d_tag` `''` (kind 42 has none) and `received_at` = now,
///   `ON CONFLICT (id) DO NOTHING` as `save_event`, and never for an id with a
///   `deleted_events` tombstone (the relay's `is_deleted` gate);
/// - `event_tags` by the relay's own trigger (`trg_event_tags_ai_v3`), never
///   by hand, so the topic tag and marker are indexed exactly as live;
/// - the migrator's `whitelist.posts_created + 1` per envelope actually
///   inserted (`changes()` is the insert's), as `increment_posts_created`.
///
/// Not written (as for the migrator's bulk import, see INGEST-PARITY.md):
/// live broadcast, push fan-out and search embeddings.
pub fn envelope_insert_sql(env: &NostrEvent, received_at: u64) -> String {
    envelope_insert_sql_if(env, received_at, "")
}

/// [`envelope_insert_sql`] with an extra SQL condition (`extra`, empty or
/// starting with ` AND `) on the insert.
fn envelope_insert_sql_if(env: &NostrEvent, received_at: u64, extra: &str) -> String {
    let tags = serde_json::to_string(&env.tags).expect("tags serialise");
    format!(
        "INSERT INTO events (id, pubkey, created_at, kind, tags, content, sig, d_tag, received_at) \
         SELECT {id}, {pk}, {ca}, {kind}, {tags}, {content}, {sig}, '', {received_at} \
         WHERE NOT EXISTS (SELECT 1 FROM deleted_events WHERE id = {id}){extra} \
         ON CONFLICT (id) DO NOTHING;\n\
         UPDATE whitelist SET posts_created = posts_created + changes() WHERE pubkey = {pk};\n",
        id = q(&env.id),
        pk = q(&env.pubkey),
        ca = env.created_at,
        kind = env.kind,
        tags = q(&tags),
        content = q(&env.content),
        sig = q(&env.sig),
    )
}

/// One envelope of a seal manifest (see [`write_seal_sql`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Original id.
    pub id: String,
    /// Envelope id.
    pub outer_id: String,
    /// Epoch sealed to.
    pub epoch: u32,
    /// SHA-256 of the original's canonical JSON.
    pub inner_sha256: String,
}

/// Write `sealed` as `seal-NNNN.sql` chunks of `chunk` envelopes in `dir`
/// (oldest first, so a topic root precedes its replies) plus
/// `seal-manifest.json`. Each chunk ends by stamping the migrator's
/// `last_active_at`. Returns the chunk paths.
pub fn write_seal_sql(
    dir: &Path,
    sealed: &[SealedEnvelope],
    migrator_pk: &str,
    chunk: usize,
    now: u64,
) -> std::io::Result<Vec<PathBuf>> {
    prepare_out_dir(dir)?;
    let mut paths = Vec::new();
    for (n, part) in sealed.chunks(chunk.max(1)).enumerate() {
        let mut sql = String::new();
        for s in part {
            sql.push_str(&envelope_insert_sql(&s.envelope, now));
        }
        let _ = writeln!(
            sql,
            "UPDATE whitelist SET last_active_at = MAX(COALESCE(last_active_at, 0), {now}) WHERE pubkey = {};",
            q(migrator_pk)
        );
        let path = dir.join(format!("seal-{:04}.sql", n + 1));
        write_generated(&path, &sql)?;
        paths.push(path);
    }
    let manifest: Vec<ManifestEntry> = sealed
        .iter()
        .map(|s| ManifestEntry {
            id: s.original_id.clone(),
            outer_id: s.envelope.id.clone(),
            epoch: s.epoch,
            inner_sha256: s.inner_sha256.clone(),
        })
        .collect();
    std::fs::write(
        dir.join("seal-manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("manifest serialises"),
    )?;
    Ok(paths)
}

/// Entries that failed a check: `(original id, reason)`.
pub type FailedEntries = Vec<(String, String)>;

/// Create `dir`, refusing one that already holds files: a reused directory
/// would keep chunk files of an earlier run that a shell glob applies too.
/// First line of every SQL file this tool writes; [`apply_sql_direct`]
/// refuses files without it (its line-by-line runner relies on the layout
/// the generators guarantee).
pub const GENERATED_HEADER: &str =
    "-- nostr-bbs-zone-migrate generated SQL: whole statements per line, no transaction control";

/// Write generated SQL with [`GENERATED_HEADER`] on top.
fn write_generated(path: &Path, sql: &str) -> std::io::Result<()> {
    std::fs::write(path, format!("{GENERATED_HEADER}\n{sql}"))
}

fn prepare_out_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    if std::fs::read_dir(dir)?.next().is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "{} is not empty: use a fresh directory per run",
                dir.display()
            ),
        ));
    }
    Ok(())
}

/// Counts from [`commit_sealed`] / [`commit_purged`].
#[derive(Debug, Default, Serialize)]
pub struct CommitReport {
    /// Entries moved to the new status.
    pub committed: usize,
    /// Entries left as they were: `(original id, why)`.
    pub skipped: Vec<(String, String)>,
}

/// Mark manifest entries `sealed` once their envelope is in D1 (`outers`,
/// by envelope id) and re-opens to the recorded original. Entries whose
/// chunk was not applied are left planned and listed.
pub fn commit_sealed(
    state: &mut State,
    manifest: &[ManifestEntry],
    outers: &HashMap<String, NostrEvent>,
    keys: &KeyRing,
) -> CommitReport {
    commit_sealed_with(state, manifest, outers, keys, false, &HashMap::new())
}

/// [`commit_sealed`]; with `reseal`, entries already `sealed` or `verified`
/// (under a legacy envelope) are re-recorded with the replacement and drop
/// back to `sealed` for re-verification, `purged` entries keep their status
/// but point at the replacement, and entries the state file lacks (an
/// envelope published but never recorded) are added, but only when the
/// envelope's channel is listed in `bindings` (channel → zone, from the
/// channels file) under the zone its `zk` tag names.
///
/// Every envelope must be the migrator's, carry a `zk` tag for the entry's
/// zone at the manifest epoch, verify, open in the entry's channel to the
/// manifest original and match its digest. Nothing is recorded, and no
/// entry added, before all of that passes.
pub fn commit_sealed_with(
    state: &mut State,
    manifest: &[ManifestEntry],
    outers: &HashMap<String, NostrEvent>,
    keys: &KeyRing,
    reseal: bool,
    bindings: &HashMap<String, String>,
) -> CommitReport {
    let mut report = CommitReport::default();
    let migrator = state.migrator.clone();
    for m in manifest {
        let mut skip = |why: String| report.skipped.push((m.id.clone(), why));
        let Some(outer) = outers.get(&m.outer_id) else {
            skip("envelope not in D1 (chunk not applied?)".into());
            continue;
        };
        let (channel, zone, new_entry) = match state.entries.get(&m.id) {
            Some(e) => {
                let replaceable = reseal
                    && matches!(e.status, Status::Sealed | Status::Verified | Status::Purged);
                if !needs_seal(&e.status) && !replaceable {
                    skip(format!("already {}", e.status.label()));
                    continue;
                }
                (e.channel.clone(), e.zone.clone(), false)
            }
            None if reseal => {
                let channel = channel_of(outer).unwrap_or_default().to_string();
                let Some(zone) = bindings.get(&channel) else {
                    skip("not in the state file and its channel is not listed".into());
                    continue;
                };
                (channel, zone.clone(), true)
            }
            None => {
                skip("not in the state file".into());
                continue;
            }
        };
        if outer.pubkey != migrator {
            skip("envelope is not signed by the migrator".into());
            continue;
        }
        if envelope_epoch(outer, &zone) != Some(m.epoch) {
            skip(format!("envelope has no zk tag for {zone}:{}", m.epoch));
            continue;
        }
        let Some(key) = keys.get(&zone, m.epoch) else {
            skip(format!("no key for {zone}:{}", m.epoch));
            continue;
        };
        match crate::engine::open_and_check(outer, &m.id, &channel, key.secret()) {
            Ok(inner) if sha256_hex(inner.as_bytes()) == m.inner_sha256 => {}
            Ok(_) => {
                skip("inner event differs from the manifest".into());
                continue;
            }
            Err(why) => {
                skip(why);
                continue;
            }
        }
        if new_entry {
            state.entries.insert(
                m.id.clone(),
                Entry::planned(&channel, &zone, outer.created_at),
            );
        }
        let e = state.entries.get_mut(&m.id).expect("entry exists");
        if e.status == Status::Purged {
            e.epoch = Some(m.epoch);
            e.outer_id = Some(m.outer_id.clone());
            e.inner_sha256 = Some(m.inner_sha256.clone());
        } else {
            set_sealed(state, &m.id, m.epoch, &m.outer_id, m.inner_sha256.clone());
        }
        report.committed += 1;
    }
    report
}

/// The epoch of `outer`'s `zk` tag for `zone`, if it has one.
pub fn envelope_epoch(outer: &NostrEvent, zone: &str) -> Option<u32> {
    outer
        .tags
        .iter()
        .find(|t| t.len() >= 3 && t[0] == "zk" && t[1] == zone)
        .and_then(|t| t[2].parse::<u32>().ok())
}

/// The `verified` entries that may be purged now, re-checked from D1 as the
/// online purge re-checks each chunk: the envelope (`outers`, by envelope
/// id) is present, verifies, opens and matches the recorded digest. Zones
/// sealed without an anchor need a member post at the sealed key first
/// (`zone_events`, every event naming the zone). Entries failing the check
/// are marked failed (verify step) as online.
pub fn purge_candidates(
    state: &mut State,
    keys: &KeyRing,
    outers: &HashMap<String, NostrEvent>,
    zone_events: &HashMap<String, Vec<NostrEvent>>,
) -> Result<(Vec<PurgeItem>, FailedEntries), EngineError> {
    let blocking = state
        .entries
        .values()
        .filter(|e| !matches!(e.status, Status::Verified | Status::Purged))
        .count();
    if blocking > 0 {
        return Err(EngineError::Refused(format!(
            "{blocking} entries are not verified; run seal and verify until every entry is verified"
        )));
    }
    let todo: Vec<String> = state
        .entries
        .iter()
        .filter(|(_, e)| e.status == Status::Verified)
        .map(|(id, _)| id.clone())
        .collect();
    require_keys(state, keys, &todo)?;
    let todo_zones: HashSet<String> = todo
        .iter()
        .map(|id| state.entries[id].zone.clone())
        .collect();
    for (zone, sealed) in state.unanchored_zones.clone() {
        if todo_zones.contains(&zone) {
            let evs = zone_events.get(&zone).map(Vec::as_slice).unwrap_or(&[]);
            if let Some(why) = unanchored_purge_refusal(&zone, &sealed, &state.migrator, evs) {
                return Err(EngineError::Refused(format!("{why}. Nothing was written.")));
            }
        }
    }
    let mut ok = Vec::new();
    let mut failed = Vec::new();
    for id in todo {
        let e = state.entries.get_mut(&id).expect("entry exists");
        let verdict = match (&e.outer_id, e.epoch, &e.inner_sha256) {
            (Some(outer_id), Some(epoch), Some(digest)) => match outers.get(outer_id) {
                None => Err("envelope not found in D1".to_string()),
                Some(outer) => {
                    let key = keys.get(&e.zone, epoch).expect("checked by require_keys");
                    crate::engine::open_and_check(outer, &id, &e.channel, key.secret()).and_then(
                        |inner| {
                            if sha256_hex(inner.as_bytes()) == *digest {
                                Ok(())
                            } else {
                                Err("inner event differs from the one sealed".to_string())
                            }
                        },
                    )
                }
            },
            _ => Err("no complete envelope record; run seal again".to_string()),
        };
        match verdict {
            Ok(()) => {
                let outer_id = e.outer_id.clone().expect("verdict checked outer_id");
                ok.push(PurgeItem { id, outer_id });
            }
            Err(reason) => {
                e.status = Status::Failed {
                    step: Step::Verify,
                    reason: reason.clone(),
                };
                failed.push((id, reason));
            }
        }
    }
    Ok((ok, failed))
}

/// One original to purge and the envelope that must still exist.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PurgeItem {
    /// The plaintext original's id.
    pub id: String,
    /// Its verified envelope's id.
    pub outer_id: String,
}

/// What `POST /api/admin/events/delete` does per id, as SQL: the event-row
/// tombstone (`TOMBSTONE_EVENT_ROW_SQL`, kind-42 rows only, `deleted_at` =
/// now) then `DELETE FROM events WHERE id = ? AND kind = 42`; plus one
/// `admin_log` row per chunk (`events.delete`). Both statements also require
/// the original's verified envelope to still be in `events` (its id, kind
/// 42, the migrator as author) when the SQL runs, so plaintext is never
/// deleted after its envelope has gone (deleted, restored over, or applied to
/// a different database).
pub fn purge_sql(items: &[PurgeItem], migrator_pk: &str, now: u64) -> String {
    let mut sql = String::new();
    for it in items {
        let guard = format!(
            "EXISTS (SELECT 1 FROM events WHERE id = {} AND kind = 42 AND pubkey = {})",
            q(&it.outer_id),
            q(migrator_pk)
        );
        let _ = writeln!(
            sql,
            "INSERT OR IGNORE INTO deleted_events (id, pubkey, deleted_at) \
             SELECT id, pubkey, {now} FROM events \
             WHERE id = {id} AND kind = 42 AND length(id) = 64 AND id NOT GLOB '*[^0-9a-f]*' AND {guard};\n\
             DELETE FROM events WHERE id = {id} AND kind = 42 AND {guard};",
            id = q(&it.id)
        );
    }
    let ids: Vec<&str> = items.iter().map(|i| i.id.as_str()).collect();
    let details = serde_json::json!({
        "count": ids.len(), "ids": ids, "notFound": [], "skipped": [],
    })
    .to_string();
    let _ = writeln!(
        sql,
        "INSERT INTO admin_log (actor_pubkey, action, target_pubkey, target_id, previous_value, new_value, reason, created_at) \
         VALUES ({}, 'events.delete', NULL, NULL, NULL, {}, 'zone-migrate purge-offline', {now});",
        q(migrator_pk),
        q(&details)
    );
    sql
}

/// Write [`purge_sql`] chunks (`purge-NNNN.sql`, `chunk` ids each) and
/// `purge-manifest.json` (the ids) in `dir`.
pub fn write_purge_sql(
    dir: &Path,
    items: &[PurgeItem],
    migrator_pk: &str,
    chunk: usize,
    now: u64,
) -> std::io::Result<Vec<PathBuf>> {
    prepare_out_dir(dir)?;
    let mut paths = Vec::new();
    for (n, part) in items.chunks(chunk.clamp(1, PURGE_CHUNK)).enumerate() {
        let path = dir.join(format!("purge-{:04}.sql", n + 1));
        write_generated(&path, &purge_sql(part, migrator_pk, now))?;
        paths.push(path);
    }
    std::fs::write(
        dir.join("purge-manifest.json"),
        serde_json::to_vec_pretty(items).expect("items serialise"),
    )?;
    Ok(paths)
}

/// Mark manifest ids `purged` once D1 no longer holds their plaintext row
/// and holds their tombstone (`gone`: ids absent from `events`; `tombstoned`:
/// ids present in `deleted_events`).
pub fn commit_purged(
    state: &mut State,
    items: &[PurgeItem],
    gone: &HashSet<String>,
    tombstoned: &HashSet<String>,
    envelopes_present: &HashSet<String>,
) -> CommitReport {
    let mut report = CommitReport::default();
    for PurgeItem { id, outer_id } in items {
        match state.entries.get_mut(id) {
            Some(e) if e.outer_id.as_deref() != Some(outer_id.as_str()) => report.skipped.push((
                id.clone(),
                "manifest envelope differs from the state file's".into(),
            )),
            Some(e)
                if e.status == Status::Verified
                    && gone.contains(id)
                    && tombstoned.contains(id)
                    && envelopes_present.contains(outer_id) =>
            {
                e.status = Status::Purged;
                report.committed += 1;
            }
            Some(e) if e.status == Status::Purged => {}
            Some(_) => report.skipped.push((
                id.clone(),
                "plaintext still in D1, no tombstone, or envelope missing".into(),
            )),
            None => report
                .skipped
                .push((id.clone(), "not in the state file".into())),
        }
    }
    report
}

/// Ids of `ids` that `events` still holds.
pub fn present_ids(db: &Connection, ids: &[String]) -> rusqlite::Result<HashSet<String>> {
    let mut s = db.prepare("SELECT 1 FROM events WHERE id = ?1")?;
    let mut out = HashSet::new();
    for id in ids {
        if s.exists([id])? {
            out.insert(id.clone());
        }
    }
    Ok(out)
}

/// Ids of `ids` that `deleted_events` holds.
pub fn tombstoned_ids(db: &Connection, ids: &[String]) -> rusqlite::Result<HashSet<String>> {
    let mut s = db.prepare("SELECT 1 FROM deleted_events WHERE id = ?1")?;
    let mut out = HashSet::new();
    for id in ids {
        if s.exists([id])? {
            out.insert(id.clone());
        }
    }
    Ok(out)
}

/// Run the statements of `sql`, line by line. Each generated SQL line holds
/// whole statements (no string literal spans a line: content, tags and ids
/// are single-line JSON/base64/hex, and newlines inside values are escaped
/// by JSON). Executing the multi-megabyte file in one `execute_batch` call
/// is quadratic (each statement re-scans the remaining tail): a
/// 10k-envelope chunk took ~35 s that way and ~3 s line by line.
fn run_statements(c: &Connection, sql: &str) -> Result<(), String> {
    for (n, line) in sql.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("--") {
            continue;
        }
        if let Some(why) = refused_statement(t) {
            return Err(format!("line {}: {why}", n + 1));
        }
        c.execute_batch(line)
            .map_err(|e| format!("line {}: {e}", n + 1))?;
    }
    Ok(())
}

/// Statements a generated file never holds and [`apply_sql_direct`]
/// refuses: transaction control (it would break one transaction per file),
/// PRAGMA, ATTACH/DETACH and VACUUM.
fn refused_statement(line: &str) -> Option<&'static str> {
    let first = line
        .split(|ch: char| !ch.is_ascii_alphabetic())
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    match first.as_str() {
        "BEGIN" | "COMMIT" | "END" | "ROLLBACK" | "SAVEPOINT" | "RELEASE" => {
            Some("transaction control is not allowed in an applied file")
        }
        "PRAGMA" | "ATTACH" | "DETACH" | "VACUUM" => {
            Some("PRAGMA, ATTACH, DETACH and VACUUM are not allowed in an applied file")
        }
        _ => None,
    }
}

/// Open the SQLite file read-write and take an exclusive lock held until
/// the connection closes (`locking_mode = EXCLUSIVE`, then a write
/// transaction to acquire it): no other process can read or write the file
/// meanwhile, in rollback-journal or WAL mode. Refused at once (no busy
/// wait) while another connection holds any lock.
pub fn lock_exclusive(path: &Path) -> Result<Connection, String> {
    let c = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    c.busy_timeout(std::time::Duration::from_millis(0))
        .map_err(|e| e.to_string())?;
    c.execute_batch("PRAGMA locking_mode = EXCLUSIVE; BEGIN EXCLUSIVE; COMMIT;")
        .map_err(|e| {
            format!(
                "cannot lock {} exclusively (stop every worker first): {e}",
                path.display()
            )
        })?;
    Ok(c)
}

/// Apply SQL chunk files directly to the D1 SQLite file, one transaction
/// per file, with the relay's own triggers firing as on any insert (the
/// tag-writing `trg_event_tags_ai_v3` included), so the rows equal what
/// `wrangler d1 execute --local --file` produces. Every worker using the
/// database must be STOPPED: the file is opened read-write and locked
/// exclusively (refused while another process holds it). Each file is one
/// transaction: a failed file is rolled back and the apply stops. Only files
/// this tool generated are accepted ([`GENERATED_HEADER`]; no transaction
/// control, PRAGMA or ATTACH lines). A stop signal ([`crate::engine::STOP`])
/// ends the apply between files. Returns per-file milliseconds for the
/// files applied.
pub fn apply_sql_direct(path: &Path, files: &[PathBuf]) -> Result<Vec<(PathBuf, u128)>, String> {
    let c = lock_exclusive(path)?;
    // A large page cache keeps the events/event_tags B-trees in memory.
    c.execute_batch("PRAGMA cache_size = -4000000; PRAGMA temp_store = MEMORY;")
        .map_err(|e| e.to_string())?;
    check_schema(&c)?;
    let mut sqls = Vec::with_capacity(files.len());
    for f in files {
        let sql = std::fs::read_to_string(f).map_err(|e| format!("{}: {e}", f.display()))?;
        if sql.lines().next() != Some(GENERATED_HEADER) {
            return Err(format!(
                "{}: not a file written by this tool (no generated-SQL header); nothing was applied",
                f.display()
            ));
        }
        sqls.push(sql);
    }
    let mut out = Vec::new();
    for (f, sql) in files.iter().zip(&sqls) {
        if crate::engine::stop_requested() {
            break;
        }
        let t = std::time::Instant::now();
        c.execute_batch("BEGIN IMMEDIATE;")
            .map_err(|e| e.to_string())?;
        if let Err(e) = run_statements(&c, sql) {
            let _ = c.execute_batch("ROLLBACK;");
            return Err(format!(
                "{}: {e} (rolled back; earlier files stay applied)",
                f.display()
            ));
        }
        c.execute_batch("COMMIT;").map_err(|e| e.to_string())?;
        out.push((f.clone(), t.elapsed().as_millis()));
    }
    Ok(out)
}

/// A sealed envelope in the earlier format (no outer topic tag on a reply,
/// no root marker on a topic root) and its current-format replacement.
#[derive(Debug, Clone)]
pub struct Reseal {
    /// The original's id (unchanged).
    pub original_id: String,
    /// The legacy envelope's id (removed).
    pub old_outer_id: String,
    /// The original's `created_at`.
    pub created_at: u64,
    /// Epoch sealed to.
    pub epoch: u32,
    /// The replacement envelope.
    pub envelope: NostrEvent,
    /// SHA-256 of the original's canonical JSON.
    pub inner_sha256: String,
}

/// Whether `outer` is an envelope sealed before the topic tag existed: its
/// original replies to a topic but the envelope carries no outer `reply`
/// tag, or its original is a topic root and the envelope carries no marker.
pub fn is_legacy_envelope(outer: &NostrEvent, original: &NostrEvent) -> bool {
    use nostr_bbs_core::sealed::{is_topic_root, reply_root_of, TOPIC_MARKER};
    let has_marker = outer
        .tags
        .iter()
        .any(|t| t.len() == 2 && t[0] == "t" && t[1] == TOPIC_MARKER);
    match reply_root_of(original) {
        Some(topic) => reply_root_of(outer) != Some(topic),
        None => is_topic_root(original) && !has_marker,
    }
}

/// Every sealed envelope by `migrator_pk` in the listed channels, from D1
/// (whether or not the state file records it: an envelope published but
/// never recorded is found too).
pub fn read_migrator_envelopes(
    db: &Connection,
    channels: &[ChannelSpec],
    migrator_pk: &str,
) -> rusqlite::Result<Vec<(String, NostrEvent)>> {
    let mut out = Vec::new();
    for c in channels {
        for ev in read_channel_events(db, &c.id)? {
            if ev.pubkey.eq_ignore_ascii_case(migrator_pk)
                && nostr_bbs_core::sealed::has_sealed_tag(&ev.tags)
            {
                out.push((c.id.clone(), ev));
            }
        }
    }
    Ok(out)
}

/// Open each of `envelopes` (channel, envelope) with the zone key named by
/// its `zk` tag, keep the legacy ones (see [`is_legacy_envelope`]) and seal
/// their originals again in the current format, in parallel, self-checked.
/// Failures (no key, does not open, F2 placement) are returned, not fatal.
pub fn reseal_legacy(
    envelopes: &[(String, NostrEvent)],
    zones: &HashMap<String, String>,
    keys: &KeyRing,
    migrator: &SecretKey,
    topic_channels: &HashMap<String, String>,
) -> (Vec<Reseal>, Vec<(String, String)>) {
    let migrator_pk = migrator.public_key().to_hex();
    let mpk = hex32(&migrator_pk).expect("hex pubkey");
    // One sealer and one conversation key per (zone, epoch) in use, built
    // once (the migrator secret is not copied per envelope).
    type Sealers = HashMap<(String, u32), (OriginalSealer, zeroize::Zeroizing<[u8; 32]>)>;
    let mut sealers: Sealers = HashMap::new();
    let mut setup_failed: HashMap<(String, u32), String> = HashMap::new();
    for (channel, outer) in envelopes {
        let Some(zone) = zones.get(channel) else {
            continue;
        };
        let Some(epoch) = envelope_epoch(outer, zone) else {
            continue;
        };
        let k = (zone.clone(), epoch);
        if sealers.contains_key(&k) || setup_failed.contains_key(&k) {
            continue;
        }
        let built = keys
            .get(zone, epoch)
            .ok_or_else(|| format!("no key for {zone}:{epoch}"))
            .and_then(|key| {
                let sk = SecretKey::from_bytes(*migrator.as_bytes()).map_err(|e| e.to_string())?;
                let sealer = OriginalSealer::new(zone, epoch, key.pubkey(), sk)
                    .map_err(|e| e.to_string())?;
                let ck = nostr_bbs_core::nip44::conversation_key(key.secret(), &mpk)
                    .map_err(|e| e.to_string())?;
                Ok((sealer, zeroize::Zeroizing::new(ck)))
            });
        match built {
            Ok(v) => {
                sealers.insert(k, v);
            }
            Err(why) => {
                setup_failed.insert(k, why);
            }
        }
    }
    let results: Vec<Result<Option<Reseal>, (String, String)>> = envelopes
        .par_iter()
        .map(|(channel, outer)| {
            let zone = zones.get(channel).ok_or_else(|| {
                (
                    outer.id.clone(),
                    "channel not in the channels file".to_string(),
                )
            })?;
            // The outer signature is the only proof the migrator wrote it
            // (any zone member can produce content that opens).
            if outer.pubkey != migrator_pk || !verify_event(outer) {
                return Err((
                    outer.id.clone(),
                    "envelope is not a verified migrator event".to_string(),
                ));
            }
            let epoch = envelope_epoch(outer, zone).ok_or_else(|| {
                (
                    outer.id.clone(),
                    "envelope has no zk tag for its zone".to_string(),
                )
            })?;
            let k = (zone.clone(), epoch);
            let (sealer, ck) = sealers.get(&k).ok_or_else(|| {
                (
                    outer.id.clone(),
                    setup_failed
                        .get(&k)
                        .cloned()
                        .unwrap_or_else(|| format!("no key for {zone}:{epoch}")),
                )
            })?;
            let original = open_sealed_with_conversation_key(outer, &mpk, ck)
                .map_err(|e| (outer.id.clone(), format!("does not open: {e}")))?;
            if !is_legacy_envelope(outer, &original) {
                return Ok(None);
            }
            if let Some(why) = topic_refusal(&original, channel, topic_channels) {
                return Err((original.id.clone(), why));
            }
            let envelope = sealer
                .seal(&original)
                .map_err(|e| (original.id.clone(), e.to_string()))?;
            let expected = serde_json::to_string(&original).expect("event serialises");
            self_check(
                &envelope,
                &original.id,
                channel,
                &migrator_pk,
                ck,
                &expected,
            )
            .map_err(|r| (original.id.clone(), r))?;
            if nostr_bbs_core::sealed::reply_root_of(&original).is_some()
                && nostr_bbs_core::sealed::reply_root_of(&envelope).is_none()
            {
                return Err((
                    original.id.clone(),
                    "replacement still lacks the topic tag".into(),
                ));
            }
            Ok(Some(Reseal {
                original_id: original.id.clone(),
                old_outer_id: outer.id.clone(),
                created_at: original.created_at,
                epoch,
                inner_sha256: sha256_hex(expected.as_bytes()),
                envelope,
            }))
        })
        .collect();
    let mut ok = Vec::new();
    let mut failed = Vec::new();
    for r in results {
        match r {
            Ok(Some(x)) => ok.push(x),
            Ok(None) => {}
            Err(e) => failed.push(e),
        }
    }
    ok.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then(a.original_id.cmp(&b.original_id))
    });
    (ok, failed)
}

/// SQL replacing legacy envelopes: per item, insert the new envelope (as
/// [`envelope_insert_sql`]) and only if it is now present, tombstone and
/// delete the legacy envelope exactly as `POST /api/admin/events/delete`
/// does (`TOMBSTONE_EVENT_ROW_SQL`, then `DELETE ... AND kind = 42`). The
/// original's `sealed` index never empties (new before old), and a
/// tombstone on the OLD envelope id never blocks the new one (different
/// id). posts_created: +1 for the new, -1 for the removed (net 0, as a
/// relay delete leaves the counter alone and the original counted once).
pub fn reseal_sql(items: &[Reseal], migrator_pk: &str, now: u64) -> String {
    let mut sql = String::new();
    for it in items {
        // The replacement goes in only while the legacy envelope is still
        // there: a second, differently randomised reseal file for the same
        // envelope then inserts nothing (no duplicate, no count drift).
        let old_present = format!(
            " AND EXISTS (SELECT 1 FROM events WHERE id = {} AND kind = 42 AND pubkey = {})",
            q(&it.old_outer_id),
            q(migrator_pk)
        );
        sql.push_str(&envelope_insert_sql_if(&it.envelope, now, &old_present));
        let guard = format!(
            "EXISTS (SELECT 1 FROM events WHERE id = {} AND kind = 42 AND pubkey = {})",
            q(&it.envelope.id),
            q(migrator_pk)
        );
        let _ = writeln!(
            sql,
            "INSERT OR IGNORE INTO deleted_events (id, pubkey, deleted_at) \
             SELECT id, pubkey, {now} FROM events WHERE id = {old} AND kind = 42 AND pubkey = {pk} AND {guard};\n\
             DELETE FROM events WHERE id = {old} AND kind = 42 AND pubkey = {pk} AND {guard};\n\
             UPDATE whitelist SET posts_created = posts_created - changes() WHERE pubkey = {pk};",
            old = q(&it.old_outer_id),
            pk = q(migrator_pk)
        );
    }
    sql
}

/// Write [`reseal_sql`] to `reseal-0001.sql` in a fresh `dir`, plus a
/// `seal-manifest.json` for the replacements (so `seal-offline-commit`
/// records them).
pub fn write_reseal_sql(
    dir: &Path,
    items: &[Reseal],
    migrator_pk: &str,
    now: u64,
) -> std::io::Result<PathBuf> {
    prepare_out_dir(dir)?;
    let path = dir.join("reseal-0001.sql");
    write_generated(&path, &reseal_sql(items, migrator_pk, now))?;
    let manifest: Vec<ManifestEntry> = items
        .iter()
        .map(|s| ManifestEntry {
            id: s.original_id.clone(),
            outer_id: s.envelope.id.clone(),
            epoch: s.epoch,
            inner_sha256: s.inner_sha256.clone(),
        })
        .collect();
    std::fs::write(
        dir.join("seal-manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("manifest serialises"),
    )?;
    Ok(path)
}
