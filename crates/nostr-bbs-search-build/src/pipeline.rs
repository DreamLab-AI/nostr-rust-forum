//! Full builds, incremental updates and compactions of one zone's index.
//!
//! Every run starts from the newest manifest any trusted publisher's pod
//! holds (verified as a browser verifies it), publishes version + 1 signed by
//! this publisher, and writes only into this publisher's own pod: new objects
//! first, `m.json` last.
//!
//! - [`run_update`]: read the zone's posts since the state's high-water mark
//!   (less an overlap), seal the new ones into additional shards, exclude
//!   already-indexed posts that were deleted or edited, and list every
//!   earlier object unchanged, including objects another trusted publisher
//!   holds (the archivist's base). A browser with those cached downloads only
//!   the new objects.
//! - [`run_compact`]: fold shard pairs that are not full (update shards, a
//!   base's last shard) into fresh full ones, or every pair
//!   ([`Fold::All`]), re-packing rows verbatim (no embedding) and dropping
//!   rows that are excluded or that the relay no longer serves.
//! - [`run_full`]: build a whole new base from rows.
//!
//! Manifests are always content v2 (unless a full build asks for v1): a
//! browser built before v2 refuses them as unsupported and keeps using the
//! newest v1 manifest it can find (the archivist's), never a higher version
//! it would then hold as its rollback mark.
//!
//! Objects a manifest stops listing are deleted from this publisher's pod
//! one run later (the state's `retired` list), so a browser that read the
//! previous manifest can still load it. Objects in another publisher's pod
//! are never deleted (nobody else can write there).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;

use nostr_bbs_core::keys::SecretKey;
use nostr_bbs_core::{sign_event, NostrEvent, UnsignedEvent};
use nostr_bbs_sealed_search::build::{
    build, compact, open_pair, q_partner, update, BuildSpec, Built, DocRow, KeyMap, PairRows,
    Previous,
};
use nostr_bbs_sealed_search::format::{BinLayer, Kind, MAX_ROWS};
use nostr_bbs_sealed_search::manifest::{Manifest, ObjectRef, KIND, V2};
use nostr_bbs_sealed_search::seal::{open, SearchKey};
use nostr_bbs_sealed_search::search::{check_header, check_sealed, sha256_hex};
use nostr_bbs_zone_migrate::keys::KeyRing;
use nostr_bbs_zone_migrate::relay::Relay;
use serde::Serialize;

use crate::embed::Embedder;
use crate::harvest::{harvest, present, Harvest, HarvestError, ZoneRow};
use crate::pod::{ObjectCache, Pod, JSON, OCTET};
use crate::state::State;

/// Default overlap re-read before the high-water mark: the relay accepts
/// events up to `MAX_CREATED_AT_DRIFT_SECS` (7 days) in the past, so a post
/// stored today may carry a `created_at` that far back. Plus an hour.
pub const DEFAULT_OVERLAP_SECS: u64 = nostr_bbs_core::event::MAX_CREATED_AT_DRIFT_SECS + 3_600;

/// Default largest share of folded rows a compaction may find missing from
/// the relay before it refuses (a relay answering incompletely would
/// otherwise empty the index).
pub const DEFAULT_MAX_MISSING: f64 = 0.05;

/// The model files a manifest pins (review L5).
#[derive(Debug, Clone)]
pub struct Pins {
    /// Model label.
    pub model: String,
    /// Hex SHA-256 of the browser's Q8 GGUF.
    pub model_sha256: String,
    /// Hex SHA-256 of `vocab.txt`.
    pub vocab_sha256: String,
}

/// One zone's job: who publishes, what it trusts, where it writes.
pub struct Job<'a, P> {
    /// Zone id.
    pub zone: &'a str,
    /// The deployment's relay URL as clients use it (bound into manifests).
    pub relay_url: &'a str,
    /// Trusted publishers (`SEARCH_PUBLISHERS`); this publisher among them.
    pub publishers: &'a [String],
    /// This publisher's key.
    pub me: &'a SecretKey,
    /// Zone keys this publisher holds.
    pub ring: &'a KeyRing,
    /// The pods.
    pub pod: &'a mut P,
    /// Local cache of sealed objects, if any.
    pub cache: Option<&'a ObjectCache>,
    /// Model pins of the local model (full builds and updates; a
    /// compaction keeps the index's own, since it carries vectors over).
    pub pins: Option<&'a Pins>,
    /// Rows per shard (a pair with fewer is "not full" for compaction).
    pub shard_rows: usize,
    /// Current Unix time (manifest `created_at`).
    pub now: u64,
    /// Non-fatal findings (no secrets, no text).
    pub warnings: Vec<String>,
}

/// Why a run stopped. Each has its own process exit code.
#[derive(Debug, thiserror::Error)]
pub enum JobError {
    /// The relay session is not NIP-42 authenticated.
    #[error(transparent)]
    Unauthenticated(HarvestError),
    /// A compaction found too many rows missing from the relay.
    #[error("{missing} of {checked} folded rows are missing from the relay (limit {limit}); refusing to compact")]
    TooManyMissing {
        /// Rows the relay did not return.
        missing: usize,
        /// Rows asked for.
        checked: usize,
        /// Most allowed.
        limit: usize,
    },
    /// The pods show an older index than this job published.
    #[error("the newest manifest on the pods ({found}) is older than version {published} this job published: refusing to build on a rolled-back or withheld index")]
    RolledBack {
        /// What the pods show.
        found: String,
        /// What the state says was published.
        published: u64,
    },
    /// Anything else.
    #[error("{0}")]
    Other(String),
}

impl JobError {
    /// Process exit code: 4 unauthenticated relay, 5 too many rows missing,
    /// 6 rollback, 1 otherwise.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Unauthenticated(_) => 4,
            Self::TooManyMissing { .. } => 5,
            Self::RolledBack { .. } => 6,
            Self::Other(_) => 1,
        }
    }
}

impl From<String> for JobError {
    fn from(e: String) -> Self {
        Self::Other(e)
    }
}

impl From<HarvestError> for JobError {
    fn from(e: HarvestError) -> Self {
        match e {
            HarvestError::Unauthenticated => Self::Unauthenticated(e),
            HarvestError::Relay(r) => Self::Other(r.to_string()),
        }
    }
}

/// What a run did (printed as JSON). Counts and names only.
#[derive(Debug, Default, Serialize)]
pub struct Report {
    /// `full`, `update` or `compact`.
    pub mode: &'static str,
    /// Zone id.
    pub zone: String,
    /// Whether a new manifest was published.
    pub published: bool,
    /// The version published (or current, when nothing was).
    pub index_version: Option<u64>,
    /// The version it was built on.
    pub previous_version: Option<u64>,
    /// Rows sealed into new shards.
    pub rows_added: usize,
    /// Ids newly excluded.
    pub excluded_added: usize,
    /// Ids excluded in the manifest now.
    pub excluded_total: usize,
    /// Objects uploaded.
    pub objects_added: usize,
    /// Objects listed unchanged from the previous version.
    pub objects_carried: usize,
    /// Objects held in another publisher's pod.
    pub objects_foreign: usize,
    /// Objects deleted from this publisher's pod.
    pub objects_deleted: usize,
    /// Bytes uploaded in new objects.
    pub sealed_bytes_added: usize,
    /// Shard pairs a compaction folded.
    pub folded_pairs: usize,
    /// Rows a compaction left out.
    pub dropped_rows: usize,
    /// Of those, rows the relay no longer serves.
    pub missing_rows: usize,
    /// Kind-42 events read.
    pub events: usize,
    /// Kind-5 events read.
    pub deletions: usize,
    /// Posts left out as deleted.
    pub deleted: usize,
    /// Posts left out as superseded.
    pub superseded: usize,
    /// Posts already indexed.
    pub already_indexed: usize,
    /// Events that do not verify.
    pub invalid: usize,
    /// Events under a held key that do not open.
    pub undecryptable: usize,
    /// Events under epochs whose key is not held (held back).
    pub missing_key: usize,
    /// Those epochs.
    pub missing_epochs: Vec<u32>,
    /// The state's high-water mark after the run.
    pub high_water: Option<u64>,
    /// Seconds spent embedding.
    pub embed_s: f64,
    /// Rows embedded per second.
    pub embed_rows_per_s: f64,
    /// Seconds spent sealing.
    pub seal_s: f64,
    /// Non-fatal findings.
    pub warnings: Vec<String>,
}

impl Report {
    fn new(mode: &'static str, zone: &str) -> Self {
        Self {
            mode,
            zone: zone.to_string(),
            ..Self::default()
        }
    }

    fn harvested(&mut self, h: &Harvest) {
        self.events = h.events;
        self.deletions = h.deletions;
        self.deleted = h.deleted;
        self.superseded = h.superseded;
        self.already_indexed = h.already_indexed;
        self.invalid = h.invalid;
        self.undecryptable = h.undecryptable;
        self.missing_key = h.missing_key;
        self.missing_epochs = h.missing_epochs.iter().copied().collect();
    }
}

/// How much a compaction folds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fold {
    /// Pairs that are not full, per epoch, when there are at least two or
    /// one holds an excluded row.
    Partial,
    /// Every pair: the whole index is re-homed in this publisher's pod
    /// (after which other publishers' objects are no longer referenced).
    All,
}

/// The current index at a glance (`status`).
#[derive(Debug, Default, Serialize)]
pub struct Status {
    /// Zone id.
    pub zone: String,
    /// Newest index version on the pods (0 when there is none).
    pub index_version: u64,
    /// Its signer.
    pub signer: String,
    /// Content version (1 or 2).
    pub content_v: u32,
    /// Rows in the index (excluded ones included).
    pub rows: u64,
    /// Shard pairs.
    pub pairs: usize,
    /// Pairs with fewer rows than a full shard (compaction candidates).
    pub partial_pairs: usize,
    /// Objects held in another publisher's pod.
    pub foreign_objects: usize,
    /// Excluded ids.
    pub excluded: usize,
}

impl Status {
    /// One field as plain text, for scripts.
    pub fn field(&self, name: &str) -> Option<String> {
        Some(match name {
            "index_version" => self.index_version.to_string(),
            "signer" => self.signer.clone(),
            "content_v" => self.content_v.to_string(),
            "rows" => self.rows.to_string(),
            "pairs" => self.pairs.to_string(),
            "partial_pairs" => self.partial_pairs.to_string(),
            "foreign_objects" => self.foreign_objects.to_string(),
            "excluded" => self.excluded.to_string(),
            _ => return None,
        })
    }
}

fn spec<'s, P>(job: &'s Job<'_, P>, pins: &'s Pins, version: u64) -> BuildSpec<'s> {
    BuildSpec {
        zone: job.zone,
        version,
        model: &pins.model,
        model_sha256: &pins.model_sha256,
        vocab_sha256: &pins.vocab_sha256,
        shard_rows: job.shard_rows,
    }
}

fn local_pins<'p, P>(job: &Job<'p, P>) -> Result<&'p Pins, String> {
    job.pins
        .ok_or_else(|| "the model files are required (--model-dir, --model-q8)".to_string())
}

/// An update embeds new rows with the local model: it must be the model the
/// index was built with, or the new vectors would not be comparable.
fn check_same_model(pins: &Pins, m: &Manifest) -> Result<(), String> {
    if pins
        .model_sha256
        .eq_ignore_ascii_case(&m.content.model_sha256)
        && pins
            .vocab_sha256
            .eq_ignore_ascii_case(&m.content.vocab_sha256)
    {
        Ok(())
    } else {
        Err("the local model differs from the one the index pins: run a full build".into())
    }
}

fn me_hex<P>(job: &Job<'_, P>) -> String {
    job.me.public_key().to_hex()
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).map_err(|_| format!("{what} is not 64 hex"))?;
    Ok(out)
}

/// The search key of `(zone, epoch)` from the held key whose pubkey is
/// `zone_pk` (review M3: never by epoch alone).
fn search_key(ring: &KeyRing, zone: &str, epoch: u32, zone_pk: &str) -> Result<SearchKey, String> {
    let k = ring
        .get(zone, epoch)
        .filter(|k| k.pubkey().eq_ignore_ascii_case(zone_pk))
        .ok_or_else(|| format!("no held key for {zone} epoch {epoch} with the listed zone_pk"))?;
    Ok(SearchKey::derive(
        k.secret(),
        zone,
        epoch,
        &hex32(zone_pk, "zone_pk")?,
    ))
}

fn key_map<'r>(
    ring: &KeyRing,
    zone: &str,
    slots: impl IntoIterator<Item = (u32, &'r str)>,
) -> Result<KeyMap, String> {
    let mut keys = KeyMap::new();
    for (epoch, pk) in slots {
        let pkb = hex32(pk, "zone_pk")?;
        if let std::collections::hash_map::Entry::Vacant(slot) = keys.entry((epoch, pkb)) {
            slot.insert(search_key(ring, zone, epoch, pk)?);
        }
    }
    Ok(keys)
}

/// The newest manifest any trusted publisher's pod holds that verifies as a
/// browser would verify it. A manifest that does not verify is skipped with
/// a warning; a pod that does not answer stops the run (building on a
/// partial view could publish a version below one already out).
///
/// # Errors
///
/// When a pod request fails.
pub async fn newest_manifest<P: Pod>(job: &mut Job<'_, P>) -> Result<Option<Manifest>, JobError> {
    let mut best: Option<Manifest> = None;
    for p in job.publishers {
        let Some(bytes) = job.pod.get(p, "m.json").await? else {
            continue;
        };
        let ev: NostrEvent = match serde_json::from_slice(&bytes) {
            Ok(ev) => ev,
            Err(_) => {
                job.warnings
                    .push(format!("m.json of {} is not an event", &p[..8]));
                continue;
            }
        };
        match Manifest::verify(ev, job.zone, job.relay_url, job.publishers, None) {
            Ok(m)
                if best
                    .as_ref()
                    .is_none_or(|b| m.content.index_version > b.content.index_version) =>
            {
                best = Some(m)
            }
            Ok(_) => {}
            Err(e) => job
                .warnings
                .push(format!("m.json of {} refused: {e}", &p[..8])),
        }
    }
    Ok(best)
}

fn check_rollback(state: &State, cur: Option<&Manifest>) -> Result<(), JobError> {
    let Some(published) = state.index_version else {
        return Ok(());
    };
    let ok = cur.is_some_and(|m| {
        m.content.index_version > published
            || (m.content.index_version == published
                && state.event_id.as_deref() == Some(m.event.id.as_str()))
    });
    if ok {
        Ok(())
    } else {
        Err(JobError::RolledBack {
            found: cur.map_or("none".into(), |m| {
                format!("version {}", m.content.index_version)
            }),
            published,
        })
    }
}

/// The sealed bytes of `o`, from the cache or its owner's pod, checked
/// against the manifest's size and SHA-256.
async fn object_bytes<P: Pod>(
    job: &mut Job<'_, P>,
    m: &Manifest,
    o: &ObjectRef,
) -> Result<Vec<u8>, String> {
    if let Some(b) = job.cache.and_then(|c| c.get(&o.sha256)) {
        return Ok(b);
    }
    let owner = m.owner_of(o).to_lowercase();
    let b = job
        .pod
        .get(&owner, &o.name)
        .await?
        .ok_or_else(|| format!("{} is missing from the pod of {}", o.name, &owner[..8]))?;
    if b.len() as u64 != o.size || sha256_hex(&b) != o.sha256.to_lowercase() {
        return Err(format!("{} does not match the manifest", o.name));
    }
    if let Some(c) = job.cache {
        c.put(&o.sha256.to_lowercase(), &b)?;
    }
    Ok(b)
}

/// Every row id in `m`'s bin objects (excluded ones included: they are still
/// in the shards). Requires the key of every epoch the index holds.
async fn indexed_ids<P: Pod>(
    job: &mut Job<'_, P>,
    m: &Manifest,
) -> Result<HashSet<String>, String> {
    let mut ids = HashSet::new();
    let bins: Vec<ObjectRef> = m
        .content
        .objects
        .iter()
        .filter(|o| o.kind == Kind::Bin)
        .cloned()
        .collect();
    for o in bins {
        let key = search_key(job.ring, job.zone, o.epoch, &o.zone_pk)?;
        let b = object_bytes(job, m, &o).await?;
        check_sealed(&o, &b, b.len(), Some(&o.sha256.to_lowercase()))?;
        let layer = BinLayer::parse(&open(&key, &b)?)?;
        check_header(&layer.header, &o, &m.content)?;
        for r in 0..layer.header.count as usize {
            ids.insert(hex::encode(layer.id(r)));
        }
    }
    Ok(ids)
}

/// Delete retired objects (the previous run's) that `listed` does not name.
async fn delete_retired<P: Pod>(
    job: &mut Job<'_, P>,
    state: &mut State,
    listed: &HashSet<String>,
    report: &mut Report,
) {
    let mut keep = Vec::new();
    for n in std::mem::take(&mut state.retired) {
        if listed.contains(&n) {
            continue;
        }
        match job.pod.delete(&n).await {
            Ok(()) => report.objects_deleted += 1,
            Err(e) => {
                job.warnings.push(format!("deleting {n}: {e}"));
                keep.push(n);
            }
        }
    }
    state.retired = keep;
}

fn own_names(m: &Manifest, me: &str) -> HashSet<String> {
    m.content
        .objects
        .iter()
        .filter(|o| m.owner_of(o).eq_ignore_ascii_case(me))
        .map(|o| o.name.clone())
        .collect()
}

/// Upload `built`'s new objects, sign and upload its manifest (last), then
/// retire this publisher's objects the new manifest no longer lists: into
/// the state's grace list when there is a state, else deleted at once.
async fn publish<P: Pod>(
    job: &mut Job<'_, P>,
    state: Option<&mut State>,
    prev: Option<&Manifest>,
    built: Built,
    report: &mut Report,
) -> Result<Manifest, JobError> {
    let me = me_hex(job);
    for (name, bytes) in &built.objects {
        job.pod.put(name, bytes, OCTET).await?;
        report.sealed_bytes_added += bytes.len();
    }
    report.objects_added = built.objects.len();
    let sk = nostr_bbs_core::keys::signing_key_from_bytes(job.me.as_bytes())
        .map_err(|e| format!("signing key: {e}"))?;
    let unsigned = UnsignedEvent {
        pubkey: me.clone(),
        created_at: job.now,
        kind: KIND,
        tags: Manifest::tags(&built.content, job.relay_url),
        content: serde_json::to_string(&built.content).map_err(|e| e.to_string())?,
    };
    let ev = sign_event(unsigned, &sk).map_err(|e| format!("signing the manifest: {e:?}"))?;
    // Accept it exactly as a browser would before anything points at it.
    let hw = prev.map(Manifest::high_water);
    let m = Manifest::verify(ev, job.zone, job.relay_url, job.publishers, hw.as_ref())
        .map_err(|e| format!("the new manifest would be refused: {e}"))?;
    let json = serde_json::to_vec(&m.event).map_err(|e| e.to_string())?;
    job.pod.put("m.json", &json, JSON).await?;

    let listed = own_names(&m, &me);
    let dropped_now: Vec<String> = prev
        .map(|p| own_names(p, &me))
        .unwrap_or_default()
        .into_iter()
        .filter(|n| !listed.contains(n))
        .collect();
    match state {
        Some(state) => {
            delete_retired(job, state, &listed, report).await;
            state.retired.extend(dropped_now);
            state.retired.sort();
            state.retired.dedup();
            state.index_version = Some(m.content.index_version);
            state.event_id = Some(m.event.id.clone());
        }
        None => {
            for n in dropped_now {
                match job.pod.delete(&n).await {
                    Ok(()) => report.objects_deleted += 1,
                    Err(e) => job.warnings.push(format!("deleting {n}: {e}")),
                }
            }
        }
    }
    if let Some(c) = job.cache {
        c.retain(
            &m.content
                .objects
                .iter()
                .map(|o| o.sha256.to_lowercase())
                .collect(),
        );
    }
    report.published = true;
    report.index_version = Some(m.content.index_version);
    report.excluded_total = m.content.excluded.len();
    report.objects_foreign = m
        .content
        .objects
        .iter()
        .filter(|o| !m.owner_of(o).eq_ignore_ascii_case(&me))
        .count();
    Ok(m)
}

/// Embed `rows` and pair them with their ids and keys' slots.
fn embed_rows<E: Embedder>(
    rows: &[ZoneRow],
    embedder: &mut E,
    report: &mut Report,
) -> Result<Vec<DocRow>, String> {
    let t = Instant::now();
    let texts: Vec<&str> = rows.iter().map(|r| r.text.as_str()).collect();
    let vecs = embedder.embed(&texts)?;
    if vecs.len() != rows.len() {
        return Err("the embedder returned the wrong number of vectors".into());
    }
    report.embed_s = t.elapsed().as_secs_f64();
    report.embed_rows_per_s = rows.len() as f64 / report.embed_s.max(1e-9);
    rows.iter()
        .zip(vecs)
        .map(|(r, vec)| {
            Ok(DocRow {
                id: hex32(&r.id, "row id")?,
                epoch: r.epoch,
                zone_pk: hex32(&r.zone_pk, "zone_pk")?,
                vec,
            })
        })
        .collect()
}

/// Build and publish a whole new base from `rows` (minus `exclude`), at the
/// newest version on the pods + 1. With `state`, the rollback check applies
/// and, given the `harvest` the rows came from, the high-water mark moves.
///
/// # Errors
///
/// [`JobError`].
#[allow(clippy::too_many_arguments)]
pub async fn run_full<P: Pod, E: Embedder>(
    job: &mut Job<'_, P>,
    mut state: Option<&mut State>,
    rows: Vec<ZoneRow>,
    exclude: &HashSet<String>,
    harvested: Option<&Harvest>,
    embedder: &mut E,
    manifest_v1: bool,
) -> Result<Report, JobError> {
    let mut report = Report::new("full", job.zone);
    if let Some(h) = harvested {
        report.harvested(h);
    }
    let prev = newest_manifest(job).await?;
    if let Some(s) = state.as_deref() {
        check_rollback(s, prev.as_ref())?;
    }
    let version = prev.as_ref().map_or(1, |p| p.content.index_version + 1);
    report.previous_version = prev.as_ref().map(|p| p.content.index_version);
    let rows: Vec<ZoneRow> = rows
        .into_iter()
        .filter(|r| !exclude.contains(&r.id.to_lowercase()))
        .collect();
    let keys = key_map(
        job.ring,
        job.zone,
        rows.iter().map(|r| (r.epoch, r.zone_pk.as_str())),
    )?;
    let docs = embed_rows(&rows, embedder, &mut report)?;
    drop(rows);
    let t = Instant::now();
    let pins = local_pins(job)?;
    let mut built = build(&spec(job, pins, version), &docs, &keys)?;
    report.seal_s = t.elapsed().as_secs_f64();
    report.rows_added = docs.len();
    if !manifest_v1 {
        built.content.v = V2;
    }
    publish(job, state.as_deref_mut(), prev.as_ref(), built, &mut report).await?;
    if let (Some(s), Some(h)) = (state, harvested) {
        s.high_water = h.high_water(s.high_water);
        report.high_water = s.high_water;
    }
    report.warnings = std::mem::take(&mut job.warnings);
    Ok(report)
}

/// An incremental update (see the module docs). `since` overrides the
/// state's high-water mark (`Some(0)` reads the whole zone again: a
/// reconcile after an import, which adds only what is missing).
///
/// # Errors
///
/// [`JobError`]; in particular [`JobError::Unauthenticated`] before anything
/// is read, and [`JobError::RolledBack`] when the pods show an older index
/// than the state recorded.
pub async fn run_update<P: Pod, R: Relay, E: Embedder>(
    job: &mut Job<'_, P>,
    relay: &mut R,
    state: &mut State,
    embedder: &mut E,
    since: Option<u64>,
    overlap: u64,
) -> Result<Report, JobError> {
    let mut report = Report::new("update", job.zone);
    if !relay.session_authenticated() {
        return Err(HarvestError::Unauthenticated.into());
    }
    let cur = newest_manifest(job).await?.ok_or_else(|| {
        format!(
            "no index for {} on the pods yet: run a full build first",
            job.zone
        )
    })?;
    check_rollback(state, Some(&cur))?;
    report.previous_version = Some(cur.content.index_version);
    report.index_version = Some(cur.content.index_version);
    let pins = local_pins(job)?;
    check_same_model(pins, &cur)?;
    let indexed = indexed_ids(job, &cur).await?;
    let since = since.or(state.high_water.map(|h| h.saturating_sub(overlap)));
    let h = harvest(relay, job.zone, job.ring, since, &indexed).await?;
    report.harvested(&h);
    let exclude: Vec<String> = h
        .exclude
        .iter()
        .filter(|e| !cur.content.excluded.contains(*e))
        .cloned()
        .collect();
    report.excluded_added = exclude.len();
    if h.rows.is_empty() && exclude.is_empty() {
        let listed = own_names(&cur, &me_hex(job));
        delete_retired(job, state, &listed, &mut report).await;
        state.high_water = h.high_water(state.high_water);
        report.high_water = state.high_water;
        report.excluded_total = cur.content.excluded.len();
        report.warnings = std::mem::take(&mut job.warnings);
        return Ok(report);
    }
    let keys = key_map(
        job.ring,
        job.zone,
        h.rows.iter().map(|r| (r.epoch, r.zone_pk.as_str())),
    )?;
    let docs = embed_rows(&h.rows, embedder, &mut report)?;
    let t = Instant::now();
    let me = me_hex(job);
    let built = update(
        &spec(job, pins, cur.content.index_version + 1),
        Previous {
            content: &cur.content,
            signer: &cur.event.pubkey,
        },
        &me,
        &docs,
        &exclude,
        &keys,
    )?;
    report.seal_s = t.elapsed().as_secs_f64();
    report.rows_added = docs.len();
    report.objects_carried = cur.content.objects.len();
    publish(job, Some(state), Some(&cur), built, &mut report).await?;
    state.high_water = h.high_water(state.high_water);
    report.high_water = state.high_water;
    report.warnings = std::mem::take(&mut job.warnings);
    Ok(report)
}

/// A compaction (see the module docs and [`Fold`]). Rows of folded pairs
/// that are excluded, or that the relay no longer serves, are left out;
/// more than `max_missing` (a share of the rows checked) missing refuses the
/// run.
///
/// # Errors
///
/// [`JobError`]; [`JobError::TooManyMissing`] as above.
pub async fn run_compact<P: Pod, R: Relay>(
    job: &mut Job<'_, P>,
    relay: &mut R,
    state: &mut State,
    fold: Fold,
    max_missing: f64,
) -> Result<Report, JobError> {
    let mut report = Report::new("compact", job.zone);
    if !relay.session_authenticated() {
        return Err(HarvestError::Unauthenticated.into());
    }
    let cur = newest_manifest(job)
        .await?
        .ok_or_else(|| format!("no index for {} on the pods yet", job.zone))?;
    check_rollback(state, Some(&cur))?;
    report.previous_version = Some(cur.content.index_version);
    report.index_version = Some(cur.content.index_version);
    let full = job.shard_rows.clamp(1, MAX_ROWS) as u32;
    let excluded: HashSet<String> = cur.content.excluded.iter().cloned().collect();
    let candidates: Vec<ObjectRef> = cur
        .content
        .objects
        .iter()
        .filter(|o| o.kind == Kind::Bin && (fold == Fold::All || o.count < full))
        .cloned()
        .collect();
    let mut by_group: BTreeMap<(u32, String), Vec<(String, PairRows)>> = BTreeMap::new();
    for b in candidates {
        let q = q_partner(&cur.content, &b)
            .ok_or_else(|| format!("no int8 layer for {}", b.name))?
            .clone();
        let key = search_key(job.ring, job.zone, b.epoch, &b.zone_pk)?;
        let bb = object_bytes(job, &cur, &b).await?;
        let qb = object_bytes(job, &cur, &q).await?;
        let rows = open_pair(&cur.content, &b, &bb, &q, &qb, &key)?;
        by_group
            .entry((b.epoch, b.zone_pk.to_lowercase()))
            .or_default()
            .push((b.name.clone(), rows));
    }
    let mut fold_names = Vec::new();
    let mut opened = Vec::new();
    for (_, pairs) in by_group {
        let holds_excluded = pairs
            .iter()
            .any(|(_, p)| p.ids.iter().any(|id| excluded.contains(&hex::encode(id))));
        if fold == Fold::All || pairs.len() >= 2 || holds_excluded {
            for (n, p) in pairs {
                fold_names.push(n);
                opened.push(p);
            }
        }
    }
    if fold_names.is_empty() {
        let listed = own_names(&cur, &me_hex(job));
        delete_retired(job, state, &listed, &mut report).await;
        report.excluded_total = cur.content.excluded.len();
        report.warnings = std::mem::take(&mut job.warnings);
        return Ok(report);
    }
    let folded_ids: Vec<String> = opened
        .iter()
        .flat_map(|p| p.ids.iter().map(hex::encode))
        .collect();
    let to_check: Vec<String> = folded_ids
        .iter()
        .filter(|id| !excluded.contains(*id))
        .cloned()
        .collect();
    let served = present(relay, &to_check).await?;
    let missing: Vec<String> = to_check
        .iter()
        .filter(|id| !served.contains(*id))
        .cloned()
        .collect();
    let limit = (to_check.len() as f64 * max_missing.clamp(0.0, 1.0)).floor() as usize;
    if missing.len() > limit {
        return Err(JobError::TooManyMissing {
            missing: missing.len(),
            checked: to_check.len(),
            limit,
        });
    }
    let dropped: HashSet<String> = folded_ids
        .iter()
        .filter(|id| excluded.contains(*id))
        .cloned()
        .chain(missing.iter().cloned())
        .collect();
    report.folded_pairs = fold_names.len();
    report.dropped_rows = dropped.len();
    report.missing_rows = missing.len();
    let slots: Vec<(u32, String)> = opened
        .iter()
        .map(|p| (p.epoch, hex::encode(p.zone_pk)))
        .collect();
    let keys = key_map(
        job.ring,
        job.zone,
        slots.iter().map(|(e, p)| (*e, p.as_str())),
    )?;
    let t = Instant::now();
    let me = me_hex(job);
    let pins = Pins {
        model: cur.content.model.clone(),
        model_sha256: cur.content.model_sha256.clone(),
        vocab_sha256: cur.content.vocab_sha256.clone(),
    };
    let built = compact(
        &spec(job, &pins, cur.content.index_version + 1),
        Previous {
            content: &cur.content,
            signer: &cur.event.pubkey,
        },
        &me,
        &fold_names,
        &opened,
        &dropped,
        &keys,
    )?;
    report.seal_s = t.elapsed().as_secs_f64();
    report.rows_added = opened.iter().map(|p| p.ids.len()).sum::<usize>() - dropped.len();
    report.objects_carried = built.content.objects.len() - built.objects.len();
    publish(job, Some(state), Some(&cur), built, &mut report).await?;
    report.high_water = state.high_water;
    report.warnings = std::mem::take(&mut job.warnings);
    Ok(report)
}

/// The newest index on the pods at a glance.
///
/// # Errors
///
/// When a pod request fails.
pub async fn status<P: Pod>(job: &mut Job<'_, P>) -> Result<Status, JobError> {
    let me = me_hex(job);
    let full = job.shard_rows.clamp(1, MAX_ROWS) as u32;
    let Some(m) = newest_manifest(job).await? else {
        return Ok(Status {
            zone: job.zone.to_string(),
            ..Status::default()
        });
    };
    let bins: Vec<&ObjectRef> = m
        .content
        .objects
        .iter()
        .filter(|o| o.kind == Kind::Bin)
        .collect();
    let owners: HashMap<&str, usize> =
        m.content.objects.iter().fold(HashMap::new(), |mut acc, o| {
            *acc.entry(m.owner_of(o)).or_default() += 1;
            acc
        });
    Ok(Status {
        zone: job.zone.to_string(),
        index_version: m.content.index_version,
        signer: m.event.pubkey.clone(),
        content_v: m.content.v,
        rows: bins.iter().map(|o| u64::from(o.count)).sum(),
        pairs: bins.len(),
        partial_pairs: bins.iter().filter(|o| o.count < full).count(),
        foreign_objects: owners
            .iter()
            .filter(|(o, _)| !o.eq_ignore_ascii_case(&me))
            .map(|(_, n)| n)
            .sum(),
        excluded: m.content.excluded.len(),
    })
}
