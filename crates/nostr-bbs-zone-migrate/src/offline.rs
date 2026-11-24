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

/// Statements per envelope in a seal chunk: the insert and the activity count.
pub const DEFAULT_CHUNK: usize = 2_000;

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
        if let Some(ev) = s.query_row([id], row_event).ok().flatten() {
            out.insert(ev.id.clone(), ev);
        }
    }
    Ok(out)
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
    // zone's live encrypted posts use. No unanchored path offline.
    for zone in &zones {
        check_anchor(zone, keys, &scans)?;
    }

    // Adopt envelopes already in D1 (e.g. from the online run).
    let mut to_seal: Vec<(String, u64)> = Vec::new();
    for (id, created_at) in work {
        let channel = state.entries[&id].channel.clone();
        let existing = envelopes.get(&id).map(|v| v.as_slice()).unwrap_or(&[]);
        if let Some((outer, epoch, digest)) =
            adopt(existing, &id, &channel, originals.get(&id).copied(), keys)
        {
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
    let mut sealers: HashMap<String, (OriginalSealer, [u8; 32], u32)> = HashMap::new();
    for zone in &zones {
        let key = keys.current(zone).expect("checked above");
        let sk = SecretKey::from_bytes(*migrator.as_bytes())
            .map_err(|e| EngineError::Refused(format!("migrator key: {e}")))?;
        let sealer = OriginalSealer::new(zone, key.epoch(), key.pubkey(), sk)
            .map_err(|e| EngineError::Refused(format!("zone {zone} key: {e}")))?;
        let mpk = nostr_bbs_core::keys::PublicKey::from_hex(&migrator_pk)
            .map_err(|e| EngineError::Refused(format!("migrator pubkey: {e}")))?;
        let ck = nostr_bbs_core::nip44::conversation_key(key.secret(), mpk.as_bytes())
            .map_err(|e| EngineError::Refused(format!("zone {zone} key: {e}")))?;
        sealers.insert(zone.clone(), (sealer, ck, key.epoch()));
    }

    let jobs: Vec<(String, u64, String, String, &NostrEvent)> = to_seal
        .iter()
        .filter_map(|(id, ca)| {
            let e = &state.entries[id];
            originals
                .get(id)
                .map(|o| (id.clone(), *ca, e.zone.clone(), e.channel.clone(), *o))
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
    let tags = serde_json::to_string(&env.tags).expect("tags serialise");
    format!(
        "INSERT INTO events (id, pubkey, created_at, kind, tags, content, sig, d_tag, received_at) \
         SELECT {id}, {pk}, {ca}, {kind}, {tags}, {content}, {sig}, '', {received_at} \
         WHERE NOT EXISTS (SELECT 1 FROM deleted_events WHERE id = {id}) \
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
    std::fs::create_dir_all(dir)?;
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
        std::fs::write(&path, sql)?;
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
    let mut report = CommitReport::default();
    for m in manifest {
        let Some(e) = state.entries.get(&m.id) else {
            report
                .skipped
                .push((m.id.clone(), "not in the state file".into()));
            continue;
        };
        if !needs_seal(&e.status) {
            report
                .skipped
                .push((m.id.clone(), format!("already {}", e.status.label())));
            continue;
        }
        let Some(outer) = outers.get(&m.outer_id) else {
            report.skipped.push((
                m.id.clone(),
                "envelope not in D1 (chunk not applied?)".into(),
            ));
            continue;
        };
        let Some(key) = keys.get(&e.zone, m.epoch) else {
            report
                .skipped
                .push((m.id.clone(), format!("no key for {}:{}", e.zone, m.epoch)));
            continue;
        };
        match crate::engine::open_and_check(outer, &m.id, &e.channel, key.secret()) {
            Ok(inner) if sha256_hex(inner.as_bytes()) == m.inner_sha256 => {
                let (id, epoch, outer_id, digest) = (
                    m.id.clone(),
                    m.epoch,
                    m.outer_id.clone(),
                    m.inner_sha256.clone(),
                );
                set_sealed(state, &id, epoch, &outer_id, digest);
                report.committed += 1;
            }
            Ok(_) => report
                .skipped
                .push((m.id.clone(), "inner event differs from the manifest".into())),
            Err(why) => report.skipped.push((m.id.clone(), why)),
        }
    }
    report
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
) -> Result<(Vec<String>, FailedEntries), EngineError> {
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
            Ok(()) => ok.push(id),
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

/// What `POST /api/admin/events/delete` does per id, as SQL: the event-row
/// tombstone (`TOMBSTONE_EVENT_ROW_SQL`, `deleted_at` = now) then
/// `DELETE FROM events WHERE id = ? AND kind = 42`; plus one `admin_log` row
/// per chunk (`events.delete`, details `{count, ids, notFound, skipped}`).
pub fn purge_sql(ids: &[String], migrator_pk: &str, now: u64) -> String {
    let mut sql = String::new();
    for id in ids {
        let _ = writeln!(
            sql,
            "INSERT OR IGNORE INTO deleted_events (id, pubkey, deleted_at) \
             SELECT id, pubkey, {now} FROM events \
             WHERE id = {id} AND length(id) = 64 AND id NOT GLOB '*[^0-9a-f]*';\n\
             DELETE FROM events WHERE id = {id} AND kind = 42;",
            id = q(id)
        );
    }
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
    ids: &[String],
    migrator_pk: &str,
    chunk: usize,
    now: u64,
) -> std::io::Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir)?;
    let mut paths = Vec::new();
    for (n, part) in ids.chunks(chunk.max(1)).enumerate() {
        let path = dir.join(format!("purge-{:04}.sql", n + 1));
        std::fs::write(&path, purge_sql(part, migrator_pk, now))?;
        paths.push(path);
    }
    std::fs::write(
        dir.join("purge-manifest.json"),
        serde_json::to_vec_pretty(ids).expect("ids serialise"),
    )?;
    Ok(paths)
}

/// Mark manifest ids `purged` once D1 no longer holds their plaintext row
/// and holds their tombstone (`gone`: ids absent from `events`; `tombstoned`:
/// ids present in `deleted_events`).
pub fn commit_purged(
    state: &mut State,
    ids: &[String],
    gone: &HashSet<String>,
    tombstoned: &HashSet<String>,
) -> CommitReport {
    let mut report = CommitReport::default();
    for id in ids {
        match state.entries.get_mut(id) {
            Some(e)
                if e.status == Status::Verified && gone.contains(id) && tombstoned.contains(id) =>
            {
                e.status = Status::Purged;
                report.committed += 1;
            }
            Some(e) if e.status == Status::Purged => {}
            Some(_) => report
                .skipped
                .push((id.clone(), "plaintext still in D1 or no tombstone".into())),
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
