//! Worker glue for the RVF v2 sharded index ([`crate::shard`]): R2 I/O, the
//! per-isolate caches, the query pipeline and copy-on-write ingest.
//!
//! - **Query.** Manifest (cached [`MANIFEST_TTL_MS`], then revalidated with a
//!   conditional GET), every shard's codes and public bitmap (cached per
//!   isolate, keyed by shard key + etag, fetched by one ranged GET each on a
//!   miss), a lookup-table first stage over the codes, then ranged GETs of the
//!   best `R` rows for exact rescoring. With a warm isolate a query costs
//!   `R` row reads and at most one manifest revalidation.
//! - **Ingest.** Reads the manifest and each touched shard, upserts, splits
//!   full shards, writes the results to **new** keys, then commits the manifest
//!   with `onlyIf: etagMatches`. A lost race deletes what it wrote and retries,
//!   so concurrent ingests never drop each other's vectors (v1 did).
//!
//! Workers allow six simultaneous R2 calls per invocation and queue the rest,
//! so `R` row reads cost about `ceil(R / 6)` R2 round trips.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use futures_util::future::join_all;
use worker::{Conditional, Env, Range, Result};

use crate::embed::DIM;
use crate::shard::{
    self, decode_shard, encode_shard, first_stage, manifest_key, rescore, shard_key,
    split_until_fits, upsert, Manifest, QueryLut, Row, ShardCodes, ShardInfo, ShardLayout,
    ROW_BYTES,
};

/// How long a cached manifest is trusted before a conditional revalidation.
pub const MANIFEST_TTL_MS: f64 = 5_000.0;
/// Upper bound on cached code bytes per isolate (48 MB of codes = 1M vectors).
pub const CODE_CACHE_MAX_BYTES: usize = 64 * 1024 * 1024;
/// Default number of first-stage candidates rescored exactly. Measured on real
/// bge-small vectors (250k): recall@10 = 0.955 at 80 (0.898 at 40, 0.974 at 200).
pub const DEFAULT_RESCORE: usize = 80;
/// Ingest commit attempts before reporting a conflict (409, client retries).
const COMMIT_ATTEMPTS: usize = 5;

thread_local! {
    static MANIFEST: RefCell<Option<CachedManifest>> = const { RefCell::new(None) };
    static CODES: RefCell<CodeCache> = RefCell::new(CodeCache::default());
    static R2_OPS: Cell<u32> = const { Cell::new(0) };
}

struct CachedManifest {
    store: String,
    etag: String,
    manifest: Rc<Manifest>,
    checked_ms: f64,
}

#[derive(Default)]
struct CodeCache {
    map: HashMap<String, (String, Rc<ShardCodes>, u64)>,
    bytes: usize,
    tick: u64,
}

impl CodeCache {
    fn get(&mut self, key: &str, etag: &str) -> Option<Rc<ShardCodes>> {
        self.tick += 1;
        let t = self.tick;
        match self.map.get_mut(key) {
            Some((e, c, used)) if e == etag => {
                *used = t;
                Some(c.clone())
            }
            _ => None,
        }
    }

    fn put(&mut self, key: String, etag: String, codes: Rc<ShardCodes>) {
        self.tick += 1;
        if let Some((_, old, _)) = self.map.remove(&key) {
            self.bytes -= old.bytes();
        }
        self.bytes += codes.bytes();
        self.map.insert(key, (etag, codes, self.tick));
        while self.bytes > CODE_CACHE_MAX_BYTES && self.map.len() > 1 {
            let Some(lru) = self.map.iter().min_by_key(|(_, v)| v.2).map(|(k, _)| k.clone()) else {
                break;
            };
            if let Some((_, c, _)) = self.map.remove(&lru) {
                self.bytes -= c.bytes();
            }
        }
    }
}

/// R2 operations issued by this isolate since the last [`take_r2_ops`].
pub fn take_r2_ops() -> u32 {
    R2_OPS.with(|c| c.replace(0))
}

fn count_op() {
    R2_OPS.with(|c| c.set(c.get() + 1));
}

fn now_ms() -> f64 {
    js_sys::Date::now()
}

// ---------------------------------------------------------------------------
// R2 helpers
// ---------------------------------------------------------------------------

async fn get_full(env: &Env, key: &str) -> Result<Option<(Vec<u8>, String)>> {
    count_op();
    let Some(obj) = env.bucket("VECTORS")?.get(key).execute().await? else {
        return Ok(None);
    };
    let etag = obj.etag();
    match obj.body() {
        Some(b) => Ok(Some((b.bytes().await?, etag))),
        None => Ok(None),
    }
}

async fn get_range(env: &Env, key: &str, offset: usize, length: usize) -> Result<Option<Vec<u8>>> {
    count_op();
    let obj = env
        .bucket("VECTORS")?
        .get(key)
        .range(Range::OffsetWithLength {
            offset: offset as u64,
            length: length as u64,
        })
        .execute()
        .await?;
    match obj.as_ref().and_then(|o| o.body()) {
        Some(b) => Ok(Some(b.bytes().await?)),
        None => Ok(None),
    }
}

/// Condition on a put.
enum PutIf<'a> {
    /// Unconditional (new, uniquely named objects).
    Always,
    /// Only if the object does not exist yet (first manifest).
    Absent,
    /// Only if the current etag matches (manifest commit).
    Etag(&'a str),
}

async fn put(env: &Env, key: &str, bytes: Vec<u8>, cond: PutIf<'_>) -> Result<Option<String>> {
    count_op();
    let bucket = env.bucket("VECTORS")?;
    let mut b = bucket.put(key, bytes);
    match cond {
        PutIf::Always => {}
        PutIf::Absent => {
            b = b.only_if(Conditional {
                etag_does_not_match: Some("*".to_string()),
                ..Default::default()
            })
        }
        PutIf::Etag(e) => {
            b = b.only_if(Conditional {
                etag_matches: Some(e.to_string()),
                ..Default::default()
            })
        }
    }
    Ok(b.execute().await?.map(|o| o.etag()))
}

async fn delete_keys(env: &Env, keys: &[String]) {
    if let Ok(bucket) = env.bucket("VECTORS") {
        for k in keys {
            count_op();
            let _ = bucket.delete(k.clone()).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// The current manifest, from the isolate cache when it is fresh.
///
/// `Ok(None)` means no v2 index exists (the caller falls back to v1).
pub async fn manifest(env: &Env, store: &str, force: bool) -> Result<Option<Rc<Manifest>>> {
    let now = now_ms();
    let cached = MANIFEST.with(|m| {
        m.borrow()
            .as_ref()
            .filter(|c| c.store == store)
            .map(|c| (c.etag.clone(), c.manifest.clone(), c.checked_ms))
    });
    if let Some((_, m, at)) = &cached {
        if !force && now - at < MANIFEST_TTL_MS {
            return Ok(Some(m.clone()));
        }
    }
    let key = manifest_key(store);
    count_op();
    let bucket = env.bucket("VECTORS")?;
    let mut req = bucket.get(&key);
    if let Some((etag, _, _)) = &cached {
        req = req.only_if(Conditional {
            etag_does_not_match: Some(etag.clone()),
            ..Default::default()
        });
    }
    let Some(obj) = req.execute().await? else {
        MANIFEST.with(|m| *m.borrow_mut() = None);
        return Ok(None);
    };
    let etag = obj.etag();
    let fresh = match obj.body() {
        Some(b) => Manifest::from_rvf(&b.bytes().await?).map(Rc::new),
        // Condition failed: unchanged since the cached copy.
        None => cached.as_ref().map(|c| c.1.clone()),
    };
    let Some(m) = fresh else {
        return Ok(None);
    };
    MANIFEST.with(|c| {
        *c.borrow_mut() = Some(CachedManifest {
            store: store.to_string(),
            etag,
            manifest: m.clone(),
            checked_ms: now,
        })
    });
    Ok(Some(m))
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

/// Result of a v2 search.
pub struct SearchOutcome {
    /// `(id, cosine)` best first.
    pub hits: Vec<(String, f32)>,
    /// Vectors in the index.
    pub total: usize,
    /// Embedding model of the index.
    pub model: String,
}

async fn shard_codes(env: &Env, s: &ShardInfo) -> Result<Option<Rc<ShardCodes>>> {
    if let Some(c) = CODES.with(|c| c.borrow_mut().get(&s.key, &s.etag)) {
        return Ok(Some(c));
    }
    let (a, b) = ShardLayout::new(s.count).hot_range();
    let Some(bytes) = get_range(env, &s.key, a, b - a).await? else {
        return Ok(None);
    };
    let Some(codes) = ShardCodes::from_hot_range(s.count, &bytes).map(Rc::new) else {
        return Ok(None);
    };
    CODES.with(|c| c.borrow_mut().put(s.key.clone(), s.etag.clone(), codes.clone()));
    Ok(Some(codes))
}

/// Search the v2 index. `Ok(None)` when no v2 index exists.
pub async fn search(
    env: &Env,
    store: &str,
    query: &[f32],
    k: usize,
    min_score: f32,
    rescore_n: usize,
) -> Result<Option<SearchOutcome>> {
    let mut force = false;
    for _ in 0..2 {
        let Some(m) = manifest(env, store, force).await? else {
            return Ok(None);
        };
        let shards: Vec<&ShardInfo> = m.shards.iter().filter(|s| s.public > 0 && s.count > 0).collect();
        let loaded = join_all(shards.iter().map(|s| shard_codes(env, s))).await;
        let mut codes = Vec::with_capacity(shards.len());
        let mut stale = false;
        for c in loaded {
            match c? {
                Some(c) => codes.push(c),
                None => stale = true,
            }
        }
        if stale && !force {
            // A shard the cached manifest names is gone: reload it once.
            force = true;
            continue;
        }
        let refs: Vec<&ShardCodes> = codes.iter().map(|c| c.as_ref()).collect();
        let r = rescore_n.max(k);
        let cands = first_stage(&QueryLut::new(query), &refs, r);
        let fetched = join_all(cands.iter().map(|(si, pos, _)| {
            let s = shards[*si];
            let off = ShardLayout::new(s.count).row_off(*pos);
            get_range(env, &s.key, off, ROW_BYTES)
        }))
        .await;
        let mut rows: Vec<((usize, usize), Vec<u8>)> = Vec::with_capacity(cands.len());
        let mut missing = false;
        for ((si, pos, _), f) in cands.iter().zip(fetched) {
            match f? {
                Some(b) => rows.push(((*si, *pos), b)),
                None => missing = true,
            }
        }
        if missing && !force {
            // A commit elsewhere replaced a shard between our manifest read
            // and the row reads: reload the manifest and search again once.
            force = true;
            continue;
        }
        let refs: Vec<((usize, usize), &[u8])> = rows.iter().map(|(p, b)| (*p, b.as_slice())).collect();
        return Ok(Some(SearchOutcome {
            hits: rescore(query, &refs, k, min_score),
            total: m.total(),
            model: m.model.clone(),
        }));
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Ingest
// ---------------------------------------------------------------------------

/// One entry to ingest.
pub struct NewEntry {
    /// Event id.
    pub id: String,
    /// Zone (validated by the caller).
    pub zone: String,
    /// Publicly searchable.
    pub public: bool,
    /// 384-dim vector.
    pub vec: [f32; DIM],
}

/// Ingest failure the caller maps to an HTTP status.
pub enum IngestError {
    /// The index holds vectors from a different model.
    ModelMismatch(String),
    /// Lost the manifest race on every attempt.
    Conflict,
    /// R2 or decode failure.
    Worker(worker::Error),
}

impl From<worker::Error> for IngestError {
    fn from(e: worker::Error) -> Self {
        Self::Worker(e)
    }
}

/// Summary of a committed ingest.
pub struct IngestOutcome {
    /// Vectors in the index after the commit.
    pub total: usize,
    /// Shards after the commit.
    pub shards: usize,
    /// Rows migrated from a v1 store in this call.
    pub migrated: usize,
}

/// Upsert `entries` into the v2 index, migrating a v1 store first if no v2
/// manifest exists yet. `v1_rows` is called only in that case.
pub async fn ingest<F, Fut>(
    env: &Env,
    store: &str,
    model: &str,
    entries: Vec<NewEntry>,
    nonce: &str,
    v1_rows: F,
) -> std::result::Result<IngestOutcome, IngestError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<Vec<Row>>>,
{
    let key = manifest_key(store);
    for attempt in 0..COMMIT_ATTEMPTS {
        if attempt > 0 {
            // Jittered backoff so racing writers stop colliding in lockstep.
            let ms = 10 + (js_sys::Math::random() * 40.0 * attempt as f64) as u64;
            worker::Delay::from(std::time::Duration::from_millis(ms)).await;
        }
        // Unique per write attempt: shard keys never collide with a racing
        // writer's, so a loser's cleanup deletes only its own objects.
        let attempt_nonce = format!("{nonce}{attempt}");
        let current = get_full(env, &key).await?;
        let (base, base_etag, migrated) = match &current {
            Some((bytes, etag)) => {
                let m = Manifest::from_rvf(bytes)
                    .ok_or_else(|| worker::Error::RustError("unreadable v2 manifest".into()))?;
                (m, Some(etag.clone()), Vec::new())
            }
            None => (Manifest::new(model), None, v1_rows().await?),
        };
        if base.total() > 0 && base.model != model && base.model != "unknown" && model != "unknown" {
            return Err(IngestError::ModelMismatch(base.model.clone()));
        }

        // Group new rows (migrated v1 rows first, then this batch) by target shard.
        let migrated_n = migrated.len();
        let groups = shard::group_by_shard(
            &base,
            migrated
                .into_iter()
                .map(|r| (shard::DEFAULT_ZONE.to_string(), r))
                .chain(entries.iter().map(|e| (e.zone.clone(), Row { id: e.id.clone(), public: e.public, vec: e.vec }))),
        );

        let generation = base.generation + 1;
        let mut written: Vec<String> = Vec::new();
        let mut replaced: Vec<usize> = Vec::new();
        let mut added: Vec<ShardInfo> = Vec::new();
        let mut failed = false;
        for shard::ShardBatch { target, zone, depth, prefix, rows: batch } in groups {
            let mut rows = match target {
                Some(t) => match get_full(env, &base.shards[t].key).await? {
                    Some((bytes, _)) => decode_shard(&bytes)
                        .ok_or_else(|| worker::Error::RustError("unreadable v2 shard".into()))?,
                    None => {
                        failed = true; // manifest moved on under us
                        break;
                    }
                },
                None => Vec::new(),
            };
            upsert(&mut rows, batch);
            for (d, p, part) in split_until_fits(rows, depth, prefix, base.shard_cap) {
                let k = shard_key(store, &zone, d, p, generation, &attempt_nonce);
                let public = part.iter().filter(|r| r.public).count();
                let count = part.len();
                let etag = put(env, &k, encode_shard(&part, &zone, d, p), PutIf::Always)
                    .await?
                    .ok_or_else(|| worker::Error::RustError("unconditional put refused".into()))?;
                written.push(k.clone());
                added.push(ShardInfo { zone: zone.clone(), depth: d, prefix: p, count, public, key: k, etag });
            }
            if let Some(t) = target {
                replaced.push(t);
            }
        }
        if failed {
            delete_keys(env, &written).await;
            continue;
        }
        let old_keys: Vec<String> = replaced.iter().map(|&t| base.shards[t].key.clone()).collect();
        let next = shard::commit(&base, &replaced, added, generation, model, migrated_n > 0);
        // The commit only lands if nobody else committed since we read: the
        // first manifest only if none exists, later ones only on our etag.
        let cond = match base_etag.as_deref() {
            Some(e) => PutIf::Etag(e),
            None => PutIf::Absent,
        };
        match put(env, &key, next.to_rvf(), cond).await? {
            Some(_) => {
                delete_keys(env, &old_keys).await;
                MANIFEST.with(|m| *m.borrow_mut() = None);
                return Ok(IngestOutcome { total: next.total(), shards: next.shards.len(), migrated: migrated_n });
            }
            None => {
                delete_keys(env, &written).await;
            }
        }
    }
    Err(IngestError::Conflict)
}
