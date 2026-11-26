//! RVF v2: sharded, quantised vector index (pure, host-testable).
//!
//! # Why
//!
//! The v1 store is one R2 object holding every vector as `f32`, plus one KV
//! value holding every id. Each `/search` read both in full, so the worker ran
//! out of its 128 MB isolate at a few tens of thousands of vectors. v2 keeps
//! the RVF segment format and the bge-small 384-dim model, and changes three
//! things:
//!
//! 1. **Shards.** Vectors are split by a hash of their id into shards of at
//!    most [`SHARD_CAP`] rows, per zone, using extendible hashing: a shard has a
//!    `depth` and a `prefix`, and owns every id whose hash starts with those
//!    `depth` bits. A full shard splits in two (depth + 1) without touching any
//!    other shard, so a small forum stays at one shard and ingest memory is
//!    bounded by one shard however large the index grows.
//! 2. **1-bit codes, scored asymmetrically.** Each vector also gets a 48-byte
//!    sign code. The first search stage scores the float query against every
//!    code with a per-query lookup table ([`QueryLut`]), which is cheap enough
//!    to cache every code in the isolate (12 MB at 250k vectors, 48 MB at 1M).
//! 3. **Exact rescoring of a short list.** The best `R` candidates are rescored
//!    against their full-precision rows, read by byte range from R2, with the
//!    same cosine arithmetic as v1 ([`crate::store::cosine_le_bytes`]), so the
//!    final scores are bit-identical to v1's.
//!
//! # Objects
//!
//! - `{store}.v2/manifest.rvf`: one `Manifest` segment holding [`Manifest`] as
//!   JSON. It is the only mutable object and is replaced with a conditional
//!   put (`etagMatches`), so concurrent ingests cannot lose each other's work.
//! - `{store}.v2/{zone}/{depth}-{prefix:016x}-g{generation}-{nonce}.rvf`:
//!   immutable shard objects (copy-on-write; the nonce is unique per write
//!   attempt, so racing writers never share a key). A reader holding an older manifest still
//!   reads consistent shards.
//!
//! # Shard layout (RVF segments, 64-byte headers, payloads padded to 64)
//!
//! | # | Segment | Payload |
//! |---|---|---|
//! | 1 | `Quant` (flags = [`QUANT_SIGN_V1`]) | `count` × 48-byte sign codes; dim `8j+b` is bit `b` of byte `j` |
//! | 2 | `Membership` | `ceil(count/8)` bytes; bit set = publicly searchable |
//! | 3 | `Hot` | `count` × [`ROW_BYTES`] rows: `[len u8][id, ID_SLOT-1 bytes][384 × f32 LE]` |
//! | 4 | `Meta` | JSON `{format, dim, count, quant, row_bytes, zone, depth, prefix}` |
//!
//! Every offset follows from `count` alone ([`ShardLayout`]), so a reader can
//! range-read the codes and bitmap (segments 1–2, contiguous) or a single row
//! without reading the shard header first.
//!
//! v1 objects stay readable: the worker falls back to them while no manifest
//! exists, and the first v2 ingest migrates them.

use std::collections::HashMap;
#[cfg(test)]
use std::collections::HashSet;

use rvf_types::constants::{SEGMENT_HEADER_SIZE, SEGMENT_MAGIC, SEGMENT_VERSION};
use rvf_types::segment::SegmentHeader;
use rvf_types::segment_type::SegmentType;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::embed::DIM;
use crate::store::{align64, cosine_le_bytes, read_header, write_header};

/// Manifest `format` value.
pub const MANIFEST_FORMAT: &str = "rvf-manifest-v2";
/// Shard `Meta` `format` value.
pub const SHARD_FORMAT: &str = "rvf-shard-v2";
/// Quantiser name recorded in the manifest and shard meta.
pub const QUANT_NAME: &str = "sign-1bit-v1";
/// `Quant` segment flags value for [`QUANT_NAME`].
pub const QUANT_SIGN_V1: u16 = 1;
/// Bytes per sign code (384 bits).
pub const CODE_BYTES: usize = DIM / 8;
/// Bytes reserved per id in a row: one length byte plus up to 71 id bytes.
pub const ID_SLOT: usize = 72;
/// Longest id a v2 row can hold.
pub const MAX_ID_LEN: usize = ID_SLOT - 1;
/// Bytes per full-precision row: id slot plus 384 little-endian `f32`.
pub const ROW_BYTES: usize = ID_SLOT + DIM * 4;
/// Most rows a shard holds before it splits. 8,192 rows ≈ 13 MB of rows and
/// 384 KB of codes, which keeps one ingest well inside a 128 MB isolate.
pub const SHARD_CAP: usize = 8192;
/// Deepest split allowed (2^24 shards per zone is far beyond any forum).
pub const MAX_DEPTH: u8 = 24;
/// Zone used when an ingest entry names none.
pub const DEFAULT_ZONE: &str = "_";

// ---------------------------------------------------------------------------
// Ids, zones, hashing
// ---------------------------------------------------------------------------

/// 64-bit routing hash of an id (first 8 bytes of SHA-256, big-endian).
pub fn id_hash(id: &str) -> u64 {
    let d = Sha256::digest(id.as_bytes());
    u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

/// Whether `hash` belongs to the shard `(depth, prefix)`.
pub fn owns(depth: u8, prefix: u64, hash: u64) -> bool {
    depth == 0 || hash >> (64 - u32::from(depth)) == prefix
}

/// A valid zone name: `_`, or 1–32 chars of `[a-z0-9-]`.
pub fn valid_zone(z: &str) -> bool {
    z == DEFAULT_ZONE
        || (!z.is_empty()
            && z.len() <= 32
            && z.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// One shard as recorded in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardInfo {
    /// Zone the shard belongs to.
    pub zone: String,
    /// Number of leading hash bits the shard owns.
    pub depth: u8,
    /// Value of those bits.
    pub prefix: u64,
    /// Rows in the shard.
    pub count: usize,
    /// Rows flagged public.
    pub public: usize,
    /// R2 object key.
    pub key: String,
    /// R2 etag of the object when it was written (cache key).
    pub etag: String,
}

/// The v2 index manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    /// Always [`MANIFEST_FORMAT`].
    pub format: String,
    /// Vector dimension (384).
    pub dim: usize,
    /// Embedding model label of every vector in the index.
    pub model: String,
    /// Quantiser ([`QUANT_NAME`]).
    pub quant: String,
    /// Split threshold the index was built with.
    pub shard_cap: usize,
    /// Bumped on every committed write; part of new shard keys.
    pub generation: u64,
    /// Set when the index was migrated from a v1 store.
    #[serde(default)]
    pub migrated_from_v1: bool,
    /// Every shard.
    pub shards: Vec<ShardInfo>,
}

impl Manifest {
    /// An empty manifest for `model`.
    pub fn new(model: &str) -> Self {
        Self {
            format: MANIFEST_FORMAT.into(),
            dim: DIM,
            model: model.into(),
            quant: QUANT_NAME.into(),
            shard_cap: SHARD_CAP,
            generation: 0,
            migrated_from_v1: false,
            shards: Vec::new(),
        }
    }

    /// Total rows.
    pub fn total(&self) -> usize {
        self.shards.iter().map(|s| s.count).sum()
    }

    /// Index into `shards` of the shard owning `hash` in `zone`, if any.
    pub fn shard_for(&self, zone: &str, hash: u64) -> Option<usize> {
        self.shards
            .iter()
            .position(|s| s.zone == zone && owns(s.depth, s.prefix, hash))
    }

    /// Serialise as an RVF buffer with one `Manifest` segment.
    pub fn to_rvf(&self) -> Vec<u8> {
        let json = serde_json::to_vec(self).unwrap_or_default();
        let mut out = Vec::with_capacity(SEGMENT_HEADER_SIZE + align64(json.len()));
        push_segment(&mut out, SegmentType::Manifest, 0, 0, &json);
        out
    }

    /// Parse an RVF manifest buffer. `None` unless it is a valid v2 manifest.
    pub fn from_rvf(data: &[u8]) -> Option<Self> {
        let (hdr, payload) = segments(data).into_iter().next()?;
        if hdr.seg_type != SegmentType::Manifest as u8 {
            return None;
        }
        let m: Manifest = serde_json::from_slice(payload).ok()?;
        (m.format == MANIFEST_FORMAT && m.dim == DIM && m.quant == QUANT_NAME).then_some(m)
    }
}

/// R2 key of the manifest for a store.
pub fn manifest_key(store_key: &str) -> String {
    format!("{store_key}.v2/manifest.rvf")
}

/// R2 key of a shard written at `generation` by the write attempt `nonce`.
///
/// The nonce is unique per write attempt. Two ingests that read the same
/// manifest compute the same generation; without the nonce they would write
/// the same key, and the loser's cleanup would delete the object the
/// winner's manifest points at.
pub fn shard_key(
    store_key: &str,
    zone: &str,
    depth: u8,
    prefix: u64,
    generation: u64,
    nonce: &str,
) -> String {
    format!("{store_key}.v2/{zone}/{depth}-{prefix:016x}-g{generation}-{nonce}.rvf")
}

// ---------------------------------------------------------------------------
// Segment helpers
// ---------------------------------------------------------------------------

fn push_segment(out: &mut Vec<u8>, ty: SegmentType, id: u64, flags: u16, payload: &[u8]) {
    let hdr = SegmentHeader {
        magic: SEGMENT_MAGIC,
        version: SEGMENT_VERSION,
        seg_type: ty as u8,
        flags,
        segment_id: id,
        payload_length: payload.len() as u64,
        timestamp_ns: 0,
        checksum_algo: 0,
        compression: 0,
        reserved_0: 0,
        reserved_1: 0,
        content_hash: [0u8; 16],
        uncompressed_len: 0,
        alignment_pad: 0,
    };
    let start = out.len();
    out.resize(start + SEGMENT_HEADER_SIZE, 0);
    write_header(&mut out[start..], &hdr);
    out.extend_from_slice(payload);
    out.resize(start + SEGMENT_HEADER_SIZE + align64(payload.len()), 0);
}

/// Every well-formed segment `(header, payload)` of an RVF buffer, stopping at
/// bad magic or a truncated payload (as the v1 reader does).
fn segments(data: &[u8]) -> Vec<(SegmentHeader, &[u8])> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + SEGMENT_HEADER_SIZE <= data.len() {
        let Some(h) = read_header(&data[off..off + SEGMENT_HEADER_SIZE]) else {
            break;
        };
        if !h.is_valid_magic() {
            break;
        }
        let start = off + SEGMENT_HEADER_SIZE;
        let len = h.payload_length as usize;
        if start + len > data.len() {
            break;
        }
        out.push((h, &data[start..start + len]));
        off = start + align64(len);
    }
    out
}

// ---------------------------------------------------------------------------
// Shard layout and (de)serialisation
// ---------------------------------------------------------------------------

/// Byte offsets inside a shard object, derived from its row count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardLayout {
    /// Rows.
    pub count: usize,
    /// Offset of the code bytes (segment 1 payload).
    pub codes_off: usize,
    /// Offset of the membership bitmap (segment 2 payload).
    pub bitmap_off: usize,
    /// Offset of row 0 (segment 3 payload).
    pub rows_off: usize,
}

impl ShardLayout {
    /// Layout for a shard of `count` rows.
    pub fn new(count: usize) -> Self {
        let codes_off = SEGMENT_HEADER_SIZE;
        let bitmap_off = codes_off + align64(count * CODE_BYTES) + SEGMENT_HEADER_SIZE;
        let rows_off = bitmap_off + align64(count.div_ceil(8)) + SEGMENT_HEADER_SIZE;
        Self {
            count,
            codes_off,
            bitmap_off,
            rows_off,
        }
    }

    /// The contiguous byte range `[start, end)` holding codes and bitmap,
    /// which is all the first search stage needs.
    pub fn hot_range(&self) -> (usize, usize) {
        (self.codes_off, self.bitmap_off + self.count.div_ceil(8))
    }

    /// Byte offset of row `pos`.
    pub fn row_off(&self, pos: usize) -> usize {
        self.rows_off + pos * ROW_BYTES
    }
}

/// One vector with its id and visibility.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    /// Event id (at most [`MAX_ID_LEN`] bytes).
    pub id: String,
    /// Publicly searchable.
    pub public: bool,
    /// Full-precision vector.
    pub vec: [f32; DIM],
}

/// The 48-byte sign code of a vector (bit set where the component is > 0).
pub fn sign_code(v: &[f32]) -> [u8; CODE_BYTES] {
    let mut c = [0u8; CODE_BYTES];
    for (i, x) in v.iter().take(DIM).enumerate() {
        if *x > 0.0 {
            c[i / 8] |= 1 << (i % 8);
        }
    }
    c
}

/// Encode rows as a shard object.
pub fn encode_shard(rows: &[Row], zone: &str, depth: u8, prefix: u64) -> Vec<u8> {
    let n = rows.len();
    let layout = ShardLayout::new(n);
    let mut codes = Vec::with_capacity(n * CODE_BYTES);
    let mut bitmap = vec![0u8; n.div_ceil(8)];
    let mut hot = Vec::with_capacity(n * ROW_BYTES);
    for (i, r) in rows.iter().enumerate() {
        codes.extend_from_slice(&sign_code(&r.vec));
        if r.public {
            bitmap[i / 8] |= 1 << (i % 8);
        }
        let id = r.id.as_bytes();
        let len = id.len().min(MAX_ID_LEN);
        let mut slot = [0u8; ID_SLOT];
        slot[0] = len as u8;
        slot[1..=len].copy_from_slice(&id[..len]);
        hot.extend_from_slice(&slot);
        for x in &r.vec {
            hot.extend_from_slice(&x.to_le_bytes());
        }
    }
    let meta = serde_json::json!({
        "format": SHARD_FORMAT, "dim": DIM, "count": n, "quant": QUANT_NAME,
        "row_bytes": ROW_BYTES, "zone": zone, "depth": depth, "prefix": prefix,
    });
    let meta = serde_json::to_vec(&meta).unwrap_or_default();
    let mut out =
        Vec::with_capacity(layout.rows_off + align64(hot.len()) + 2 * SEGMENT_HEADER_SIZE + 256);
    push_segment(&mut out, SegmentType::Quant, 0, QUANT_SIGN_V1, &codes);
    push_segment(&mut out, SegmentType::Membership, 1, 0, &bitmap);
    push_segment(&mut out, SegmentType::Hot, 2, 0, &hot);
    push_segment(&mut out, SegmentType::Meta, 3, 0, &meta);
    debug_assert_eq!(
        out[layout.rows_off - SEGMENT_HEADER_SIZE + 5],
        SegmentType::Hot as u8
    );
    out
}

/// Decode one row body (`ROW_BYTES` bytes).
pub fn decode_row(b: &[u8]) -> Option<Row> {
    if b.len() < ROW_BYTES {
        return None;
    }
    let len = usize::from(b[0]).min(MAX_ID_LEN);
    let id = std::str::from_utf8(&b[1..=len]).ok()?.to_string();
    let mut vec = [0f32; DIM];
    for (i, c) in b[ID_SLOT..ROW_BYTES].chunks_exact(4).enumerate() {
        vec[i] = f32::from_le_bytes([c[0], c[1], c[2], c[3]]);
    }
    Some(Row {
        id,
        public: false,
        vec,
    })
}

/// Decode a whole shard object into rows (ingest path).
pub fn decode_shard(data: &[u8]) -> Option<Vec<Row>> {
    let segs = segments(data);
    let quant = segs
        .iter()
        .find(|(h, _)| h.seg_type == SegmentType::Quant as u8)?;
    if quant.0.flags != QUANT_SIGN_V1 {
        return None;
    }
    let n = quant.1.len() / CODE_BYTES;
    let bitmap = segs
        .iter()
        .find(|(h, _)| h.seg_type == SegmentType::Membership as u8)?
        .1;
    let hot = segs
        .iter()
        .find(|(h, _)| h.seg_type == SegmentType::Hot as u8)?
        .1;
    if bitmap.len() < n.div_ceil(8) || hot.len() < n * ROW_BYTES {
        return None;
    }
    let mut rows = Vec::with_capacity(n);
    for i in 0..n {
        let mut r = decode_row(&hot[i * ROW_BYTES..(i + 1) * ROW_BYTES])?;
        r.public = bitmap[i / 8] >> (i % 8) & 1 == 1;
        rows.push(r);
    }
    Some(rows)
}

// ---------------------------------------------------------------------------
// Upsert and split (ingest)
// ---------------------------------------------------------------------------

/// Insert or replace `new` rows (by id) into `rows`. Order of existing rows is
/// kept; new ids append in input order. Returns how many were new.
pub fn upsert(rows: &mut Vec<Row>, new: Vec<Row>) -> usize {
    let mut at: HashMap<String, usize> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| (r.id.clone(), i))
        .collect();
    let mut added = 0;
    for r in new {
        if let Some(&i) = at.get(&r.id) {
            rows[i] = r;
        } else {
            at.insert(r.id.clone(), rows.len());
            rows.push(r);
            added += 1;
        }
    }
    added
}

/// Split `rows` of shard `(depth, prefix)` until every part has at most `cap`
/// rows. Returns `(depth, prefix, rows)` parts covering exactly the parent's
/// hash range, each preserving the parent's row order.
pub fn split_until_fits(
    rows: Vec<Row>,
    depth: u8,
    prefix: u64,
    cap: usize,
) -> Vec<(u8, u64, Vec<Row>)> {
    if rows.len() <= cap || depth >= MAX_DEPTH {
        return vec![(depth, prefix, rows)];
    }
    let d = depth + 1;
    let (mut lo, mut hi) = (Vec::new(), Vec::new());
    for r in rows {
        if id_hash(&r.id) >> (64 - u32::from(d)) & 1 == 0 {
            lo.push(r);
        } else {
            hi.push(r);
        }
    }
    let mut out = split_until_fits(lo, d, prefix << 1, cap);
    out.extend(split_until_fits(hi, d, (prefix << 1) | 1, cap));
    out
}

/// Rows bound for one shard in an ingest: the existing shard (index into
/// `Manifest::shards`) or, for a zone with no shard yet, a new root.
#[derive(Debug, Clone, PartialEq)]
pub struct ShardBatch {
    /// Existing shard index, or `None` for a new root shard of `zone`.
    pub target: Option<usize>,
    /// Zone.
    pub zone: String,
    /// Depth of the target (0 for a new root).
    pub depth: u8,
    /// Prefix of the target (0 for a new root).
    pub prefix: u64,
    /// Rows to upsert, in input order.
    pub rows: Vec<Row>,
}

/// Route `(zone, row)` pairs to their shards in `m`, in first-seen order.
pub fn group_by_shard(
    m: &Manifest,
    rows: impl IntoIterator<Item = (String, Row)>,
) -> Vec<ShardBatch> {
    let mut out: Vec<ShardBatch> = Vec::new();
    for (zone, row) in rows {
        let target = m.shard_for(&zone, id_hash(&row.id));
        let slot = out.iter().position(|g| match target {
            Some(t) => g.target == Some(t),
            None => g.target.is_none() && g.zone == zone,
        });
        match slot {
            Some(i) => out[i].rows.push(row),
            None => {
                let (depth, prefix) = target
                    .map(|t| (m.shards[t].depth, m.shards[t].prefix))
                    .unwrap_or((0, 0));
                out.push(ShardBatch {
                    target,
                    zone,
                    depth,
                    prefix,
                    rows: vec![row],
                });
            }
        }
    }
    out
}

/// The manifest after replacing the shards at `replaced` with `added`, at
/// `generation`. Untouched shards keep their order; new ones follow.
pub fn commit(
    base: &Manifest,
    replaced: &[usize],
    added: Vec<ShardInfo>,
    generation: u64,
    model: &str,
    migrated: bool,
) -> Manifest {
    let mut next = base.clone();
    if base.total() == 0 {
        next.model = model.to_string();
    }
    next.migrated_from_v1 |= migrated;
    next.shards = base
        .shards
        .iter()
        .enumerate()
        .filter(|(i, _)| !replaced.contains(i))
        .map(|(_, s)| s.clone())
        .chain(added)
        .collect();
    next.generation = generation;
    next
}

// ---------------------------------------------------------------------------
// Query: asymmetric code scoring, top-R, rescoring
// ---------------------------------------------------------------------------

/// Per-query lookup table: for each of the 48 code bytes and each byte value,
/// the sum over its 8 dims of `+q` where the bit is set and `-q` where not.
/// Scoring a code is then 48 table reads.
pub struct QueryLut(Vec<f32>);

impl QueryLut {
    /// Build the table for `query` (384 floats).
    pub fn new(query: &[f32]) -> Self {
        let mut t = vec![0f32; CODE_BYTES * 256];
        for j in 0..CODE_BYTES {
            let q = &query[j * 8..j * 8 + 8];
            for b in 0..256usize {
                let mut s = 0f32;
                for (k, qi) in q.iter().enumerate() {
                    if b >> k & 1 == 1 {
                        s += qi;
                    } else {
                        s -= qi;
                    }
                }
                t[j * 256 + b] = s;
            }
        }
        Self(t)
    }

    /// Approximate score of one 48-byte code (higher is closer).
    #[inline]
    pub fn score(&self, code: &[u8]) -> f32 {
        let mut s = 0f32;
        for (j, &b) in code.iter().enumerate().take(CODE_BYTES) {
            s += self.0[j * 256 + b as usize];
        }
        s
    }
}

/// Cached first-stage data of one shard: codes and public bitmap.
#[derive(Debug, Clone)]
pub struct ShardCodes {
    /// Rows in the shard.
    pub count: usize,
    /// `count * CODE_BYTES` code bytes.
    pub codes: Vec<u8>,
    /// Public bitmap.
    pub bitmap: Vec<u8>,
}

impl ShardCodes {
    /// Parse the bytes returned by a ranged read of [`ShardLayout::hot_range`].
    pub fn from_hot_range(count: usize, bytes: &[u8]) -> Option<Self> {
        let l = ShardLayout::new(count);
        let (start, end) = l.hot_range();
        if bytes.len() < end - start {
            return None;
        }
        let codes = bytes[..count * CODE_BYTES].to_vec();
        let b0 = l.bitmap_off - start;
        let bitmap = bytes[b0..b0 + count.div_ceil(8)].to_vec();
        Some(Self {
            count,
            codes,
            bitmap,
        })
    }

    /// Heap bytes held.
    pub fn bytes(&self) -> usize {
        self.codes.len() + self.bitmap.len()
    }

    fn is_public(&self, i: usize) -> bool {
        self.bitmap[i / 8] >> (i % 8) & 1 == 1
    }
}

/// A first-stage candidate: shard index (into the caller's list), row position
/// and approximate score.
pub type Candidate = (usize, usize, f32);

/// Best `r` **public** rows over all shards by approximate score. Non-public
/// rows are skipped here, before the cut, so every rescored candidate is
/// visible (fail-closed: a clear bit is never returned).
///
/// Memory is O(`r`): candidates go into a buffer of at most `4r`, which is cut
/// back to the best `r` whenever it fills. The order is total (score, then
/// shard, then position), so the result equals a full sort's top `r`.
pub fn first_stage(lut: &QueryLut, shards: &[&ShardCodes], r: usize) -> Vec<Candidate> {
    let cmp = |a: &Candidate, b: &Candidate| {
        b.2.partial_cmp(&a.2)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.cmp(&b.0))
            .then(a.1.cmp(&b.1))
    };
    if r == 0 {
        return Vec::new();
    }
    let cap = r.saturating_mul(4).max(64);
    let mut v: Vec<Candidate> = Vec::with_capacity(cap);
    let cut = |v: &mut Vec<Candidate>| {
        if v.len() > r {
            v.select_nth_unstable_by(r - 1, cmp);
            v.truncate(r);
        }
    };
    for (si, s) in shards.iter().enumerate() {
        for i in 0..s.count {
            if s.is_public(i) {
                v.push((
                    si,
                    i,
                    lut.score(&s.codes[i * CODE_BYTES..(i + 1) * CODE_BYTES]),
                ));
                if v.len() == cap {
                    cut(&mut v);
                }
            }
        }
    }
    cut(&mut v);
    v.sort_unstable_by(cmp);
    v
}

/// Rescore fetched rows exactly and return the best `k` `(id, score)` with
/// score `>= min_score`, by descending score then `(shard, pos)`.
///
/// `rows` pairs each candidate's `(shard, pos)` with its fetched row bytes.
/// Scores use the v1 arithmetic, so they are bit-identical to v1's.
pub fn rescore(
    query: &[f32],
    rows: &[((usize, usize), &[u8])],
    k: usize,
    min_score: f32,
) -> Vec<(String, f32)> {
    let mut v: Vec<((usize, usize), String, f32)> = rows
        .iter()
        .filter_map(|((s, p), b)| {
            if b.len() < ROW_BYTES {
                return None;
            }
            let score = cosine_le_bytes(query, &b[ID_SLOT..ROW_BYTES]);
            if score < min_score {
                return None;
            }
            let len = usize::from(b[0]).min(MAX_ID_LEN);
            let id = std::str::from_utf8(&b[1..=len]).ok()?.to_string();
            Some(((*s, *p), id, score))
        })
        .collect();
    v.sort_by(|a, b| {
        b.2.partial_cmp(&a.2)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.cmp(&b.0))
    });
    v.truncate(k);
    v.into_iter().map(|(_, id, s)| (id, s)).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn lcg_rows(n: usize, seed: u64, public_every: usize) -> Vec<Row> {
        let mut x = seed;
        let mut next = || {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((x >> 33) as f32 / (1u64 << 31) as f32) - 0.5
        };
        (0..n)
            .map(|i| {
                let mut vec = [0f32; DIM];
                for s in vec.iter_mut() {
                    *s = next();
                }
                Row {
                    id: format!("{:064x}", (i as u128 + 1) * 0x9e3779b97f4a7c15),
                    public: i % public_every != 1,
                    vec,
                }
            })
            .collect()
    }

    #[test]
    fn shard_roundtrip_and_layout() {
        let rows = lcg_rows(1000, 1, 3);
        let buf = encode_shard(&rows, "zone1", 2, 3);
        assert_eq!(decode_shard(&buf).unwrap(), rows);
        let l = ShardLayout::new(rows.len());
        // Ranged reads at the computed offsets see the same data.
        let (a, b) = l.hot_range();
        let sc = ShardCodes::from_hot_range(rows.len(), &buf[a..b]).unwrap();
        for (i, r) in rows.iter().enumerate() {
            assert_eq!(
                &sc.codes[i * CODE_BYTES..(i + 1) * CODE_BYTES],
                &sign_code(&r.vec)
            );
            assert_eq!(sc.is_public(i), r.public);
            let row = decode_row(&buf[l.row_off(i)..l.row_off(i) + ROW_BYTES]).unwrap();
            assert_eq!(row.id, r.id);
            assert_eq!(row.vec, r.vec);
        }
        // The empty shard is valid too.
        assert_eq!(decode_shard(&encode_shard(&[], "_", 0, 0)).unwrap(), vec![]);
    }

    #[test]
    fn v1_reader_ignores_v2_segments() {
        // A v1 decoder finds no Vec segment in a shard: it never misreads one.
        let buf = encode_shard(&lcg_rows(10, 2, 1), "_", 0, 0);
        assert_eq!(crate::store::rvf_count(&buf), 0);
    }

    #[test]
    fn manifest_roundtrip_and_rejects_others() {
        let mut m = Manifest::new("bge-small-en-v1.5@openai-compat");
        m.shards.push(ShardInfo {
            zone: "_".into(),
            depth: 1,
            prefix: 1,
            count: 5,
            public: 4,
            key: "k".into(),
            etag: "e".into(),
        });
        assert_eq!(Manifest::from_rvf(&m.to_rvf()).unwrap(), m);
        assert!(Manifest::from_rvf(&encode_shard(&[], "_", 0, 0)).is_none());
        assert!(Manifest::from_rvf(&[]).is_none());
        let mut bad = m.clone();
        bad.quant = "pq".into();
        assert!(Manifest::from_rvf(&bad.to_rvf()).is_none());
    }

    #[test]
    fn split_covers_range_and_respects_cap() {
        let rows = lcg_rows(5000, 3, 2);
        let parts = split_until_fits(rows.clone(), 0, 0, 1000);
        assert!(parts.len() >= 5);
        let mut seen = 0;
        for (d, p, rs) in &parts {
            assert!(rs.len() <= 1000);
            for r in rs {
                assert!(owns(*d, *p, id_hash(&r.id)));
            }
            seen += rs.len();
        }
        assert_eq!(seen, 5000);
        // Prefix-free cover: every hash is owned by exactly one part.
        for r in &rows {
            assert_eq!(
                parts
                    .iter()
                    .filter(|(d, p, _)| owns(*d, *p, id_hash(&r.id)))
                    .count(),
                1
            );
        }
    }

    #[test]
    fn upsert_replaces_by_id_and_appends_new() {
        let mut rows = lcg_rows(10, 4, 1);
        let mut upd = rows[3].clone();
        upd.public = false;
        upd.vec[0] = 9.0;
        let fresh = lcg_rows(12, 5, 1).pop().unwrap();
        let fresh = Row {
            id: "new".into(),
            ..fresh
        };
        assert_eq!(upsert(&mut rows, vec![upd.clone(), fresh.clone()]), 1);
        assert_eq!(rows.len(), 11);
        assert_eq!(rows[3], upd);
        assert_eq!(rows[10], fresh);
    }

    #[test]
    fn lut_matches_direct_asymmetric_score() {
        let rows = lcg_rows(50, 6, 1);
        let q = lcg_rows(1, 7, 1)[0].vec;
        let lut = QueryLut::new(&q);
        for r in &rows {
            let c = sign_code(&r.vec);
            let direct: f32 = (0..DIM)
                .map(|i| {
                    if c[i / 8] >> (i % 8) & 1 == 1 {
                        q[i]
                    } else {
                        -q[i]
                    }
                })
                .sum();
            assert!((lut.score(&c) - direct).abs() < 1e-4);
        }
    }

    #[test]
    fn first_stage_never_returns_private_rows() {
        let rows = lcg_rows(300, 8, 2); // every other row private
        let buf = encode_shard(&rows, "_", 0, 0);
        let l = ShardLayout::new(rows.len());
        let (a, b) = l.hot_range();
        let sc = ShardCodes::from_hot_range(rows.len(), &buf[a..b]).unwrap();
        // Query equal to a private row: it must still not surface.
        let lut = QueryLut::new(&rows[1].vec);
        let c = first_stage(&lut, &[&sc], 1000);
        assert_eq!(c.len(), rows.iter().filter(|r| r.public).count());
        assert!(c.iter().all(|(_, p, _)| rows[*p].public));
    }

    #[test]
    fn full_rescore_is_bit_identical_to_v1() {
        // With R >= N the v2 pipeline returns exactly v1's list.
        let mut rows = lcg_rows(2000, 9, 1);
        for r in &mut rows {
            r.public = true; // v1's search_rvf has no visibility filter
        }
        let parts = split_until_fits(rows.clone(), 0, 0, 600);
        let bufs: Vec<Vec<u8>> = parts
            .iter()
            .map(|(d, p, rs)| encode_shard(rs, "_", *d, *p))
            .collect();
        let codes: Vec<ShardCodes> = parts
            .iter()
            .zip(&bufs)
            .map(|((_, _, rs), b)| {
                let (x, y) = ShardLayout::new(rs.len()).hot_range();
                ShardCodes::from_hot_range(rs.len(), &b[x..y]).unwrap()
            })
            .collect();
        let refs: Vec<&ShardCodes> = codes.iter().collect();
        // v1 store of the same vectors (labels = index + 1).
        let entries: Vec<(u64, [f32; DIM])> = rows
            .iter()
            .enumerate()
            .map(|(i, r)| (i as u64 + 1, r.vec))
            .collect();
        let v1 = crate::store::build_rvf_bytes_for_test(&entries);
        let id_of: HashMap<u64, &str> = rows
            .iter()
            .enumerate()
            .map(|(i, r)| (i as u64 + 1, r.id.as_str()))
            .collect();
        for qi in 0..5 {
            let q = lcg_rows(1, 100 + qi, 1)[0].vec;
            for &(k, min) in &[(10usize, -1.0f32), (40, 0.05)] {
                let want: Vec<(String, f32)> = crate::store::search_rvf(&v1, &q, k, min)
                    .into_iter()
                    .map(|(l, s)| (id_of[&l].to_string(), s))
                    .collect();
                let cands = first_stage(&QueryLut::new(&q), &refs, rows.len());
                let fetched: Vec<((usize, usize), &[u8])> = cands
                    .iter()
                    .map(|(s, p, _)| {
                        let l = ShardLayout::new(parts[*s].2.len());
                        (
                            (*s, *p),
                            &bufs[*s][l.row_off(*p)..l.row_off(*p) + ROW_BYTES],
                        )
                    })
                    .collect();
                let got = rescore(&q, &fetched, k, min);
                if got != want {
                    let i = got.iter().zip(&want).position(|(a, b)| a != b);
                    panic!(
                        "k={k} min={min} len {} vs {} first diff {:?}: {:?} vs {:?}",
                        got.len(),
                        want.len(),
                        i,
                        i.map(|i| &got[i]),
                        i.map(|i| &want[i])
                    );
                }
            }
        }
    }

    /// Simulate ingest rounds natively: group, upsert, split, encode, commit.
    fn ingest_round(
        m: &Manifest,
        objects: &mut HashMap<String, Vec<u8>>,
        rows: Vec<(String, Row)>,
        cap: usize,
    ) -> Manifest {
        ingest_round_n(m, objects, rows, cap, "n")
    }

    fn ingest_round_n(
        m: &Manifest,
        objects: &mut HashMap<String, Vec<u8>>,
        rows: Vec<(String, Row)>,
        cap: usize,
        nonce: &str,
    ) -> Manifest {
        let gen = m.generation + 1;
        let mut replaced = Vec::new();
        let mut added = Vec::new();
        for g in group_by_shard(m, rows) {
            let mut cur = match g.target {
                Some(t) => decode_shard(&objects[&m.shards[t].key]).unwrap(),
                None => Vec::new(),
            };
            upsert(&mut cur, g.rows);
            for (d, p, part) in split_until_fits(cur, g.depth, g.prefix, cap) {
                let key = shard_key("t.rvf", &g.zone, d, p, gen, nonce);
                objects.insert(key.clone(), encode_shard(&part, &g.zone, d, p));
                added.push(ShardInfo {
                    zone: g.zone.clone(),
                    depth: d,
                    prefix: p,
                    count: part.len(),
                    public: part.iter().filter(|r| r.public).count(),
                    key,
                    etag: format!("e{gen}"),
                });
            }
            if let Some(t) = g.target {
                replaced.push(t);
            }
        }
        commit(m, &replaced, added, gen, "m", false)
    }

    fn search_all(
        m: &Manifest,
        objects: &HashMap<String, Vec<u8>>,
        q: &[f32],
        k: usize,
        r: usize,
    ) -> Vec<(String, f32)> {
        let shards: Vec<&ShardInfo> = m.shards.iter().filter(|s| s.public > 0).collect();
        let codes: Vec<ShardCodes> = shards
            .iter()
            .map(|s| {
                let (a, b) = ShardLayout::new(s.count).hot_range();
                ShardCodes::from_hot_range(s.count, &objects[&s.key][a..b]).unwrap()
            })
            .collect();
        let refs: Vec<&ShardCodes> = codes.iter().collect();
        let cands = first_stage(&QueryLut::new(q), &refs, r);
        let rows: Vec<((usize, usize), &[u8])> = cands
            .iter()
            .map(|(si, p, _)| {
                let s = shards[*si];
                let o = ShardLayout::new(s.count).row_off(*p);
                ((*si, *p), &objects[&s.key][o..o + ROW_BYTES])
            })
            .collect();
        rescore(q, &rows, k, -1.0)
    }

    #[test]
    fn v1_migration_then_ingest_matches_v1_search() {
        // A v1 store + mapping, migrated through rvf_entries, then more rows
        // in two later rounds (with splits and an upsert): v2 with R >= N
        // returns exactly what v1 returns over the same final vectors.
        let all = lcg_rows(1500, 21, 1);
        let all: Vec<Row> = all.into_iter().map(|r| Row { public: true, ..r }).collect();
        let v1_entries: Vec<(u64, [f32; DIM])> = all[..900]
            .iter()
            .enumerate()
            .map(|(i, r)| (i as u64 + 1, r.vec))
            .collect();
        let v1 = crate::store::build_rvf_bytes_for_test(&v1_entries);
        let label_to_id: HashMap<u64, String> = all[..900]
            .iter()
            .enumerate()
            .map(|(i, r)| (i as u64 + 1, r.id.clone()))
            .collect();
        let migrated: Vec<(String, Row)> = crate::store::rvf_entries(&v1)
            .map(|(l, vec)| {
                (
                    DEFAULT_ZONE.to_string(),
                    Row {
                        id: label_to_id[&l].clone(),
                        public: true,
                        vec,
                    },
                )
            })
            .collect();
        assert_eq!(migrated.len(), 900);
        let mut objects = HashMap::new();
        let mut m = ingest_round(&Manifest::new("m"), &mut objects, migrated, 256);
        m = ingest_round(
            &m,
            &mut objects,
            all[900..1200]
                .iter()
                .map(|r| (DEFAULT_ZONE.to_string(), r.clone()))
                .collect(),
            256,
        );
        // Round 3: new rows plus an upsert of row 5 to row 1300's vector.
        let mut moved = all[5].clone();
        moved.vec = all[1300].vec;
        let mut third: Vec<(String, Row)> = all[1200..]
            .iter()
            .map(|r| (DEFAULT_ZONE.to_string(), r.clone()))
            .collect();
        third.push((DEFAULT_ZONE.to_string(), moved.clone()));
        m = ingest_round(&m, &mut objects, third, 256);
        assert_eq!(m.total(), 1500);
        assert!(m.shards.len() >= 6 && m.shards.iter().all(|s| s.count <= 256));
        assert_eq!(m.generation, 3);
        // Reference: v1 over the final vector set.
        let mut finals = all.clone();
        finals[5] = moved;
        let entries: Vec<(u64, [f32; DIM])> = finals
            .iter()
            .enumerate()
            .map(|(i, r)| (i as u64 + 1, r.vec))
            .collect();
        let v1_final = crate::store::build_rvf_bytes_for_test(&entries);
        let ids: HashMap<u64, String> = finals
            .iter()
            .enumerate()
            .map(|(i, r)| (i as u64 + 1, r.id.clone()))
            .collect();
        for qi in 0..4 {
            let q = lcg_rows(1, 300 + qi, 1)[0].vec;
            let want: Vec<(String, f32)> = crate::store::search_rvf(&v1_final, &q, 10, -1.0)
                .into_iter()
                .map(|(l, s)| (ids[&l].clone(), s))
                .collect();
            let got = search_all(&m, &objects, &q, 10, 1500);
            let same_scores = got.iter().zip(&want).all(|(a, b)| a.1 == b.1);
            assert!(same_scores && got.len() == want.len(), "scores differ");
            assert_eq!(
                got.iter().map(|x| &x.0).collect::<HashSet<_>>(),
                want.iter().map(|x| &x.0).collect::<HashSet<_>>()
            );
        }
        // The upserted id exists once, in the shard its hash routes to.
        let owner = m.shard_for(DEFAULT_ZONE, id_hash(&all[5].id)).unwrap();
        assert!(decode_shard(&objects[&m.shards[owner].key])
            .unwrap()
            .iter()
            .any(|r| r.id == all[5].id));
    }

    #[test]
    fn retract_by_reingest_as_private_hides_the_row() {
        let rows: Vec<Row> = lcg_rows(50, 31, 1)
            .into_iter()
            .map(|r| Row { public: true, ..r })
            .collect();
        let mut objects = HashMap::new();
        let m = ingest_round(
            &Manifest::new("m"),
            &mut objects,
            rows.iter().map(|r| ("_".into(), r.clone())).collect(),
            8192,
        );
        let q = rows[7].vec;
        assert_eq!(search_all(&m, &objects, &q, 1, 50)[0].0, rows[7].id);
        let hidden = Row {
            public: false,
            ..rows[7].clone()
        };
        let m = ingest_round(&m, &mut objects, vec![("_".into(), hidden)], 8192);
        assert_eq!(m.total(), 50);
        assert!(search_all(&m, &objects, &q, 50, 50)
            .iter()
            .all(|(id, _)| id != &rows[7].id));
    }

    #[test]
    fn zones_get_separate_shards() {
        let rows = lcg_rows(20, 41, 1);
        let mut objects = HashMap::new();
        let input = rows.iter().enumerate().map(|(i, r)| {
            (
                if i % 2 == 0 {
                    "zone1".to_string()
                } else {
                    "_".to_string()
                },
                r.clone(),
            )
        });
        let m = ingest_round(&Manifest::new("m"), &mut objects, input.collect(), 8192);
        assert_eq!(m.shards.len(), 2);
        assert!(m.shards.iter().all(|s| s.count == 10));
        assert!(m
            .shards
            .iter()
            .any(|s| s.zone == "zone1" && s.key.contains("/zone1/")));
    }

    #[test]
    fn commit_keeps_untouched_shards_and_sets_model_once() {
        let mut m = Manifest::new("old");
        for p in 0..3u64 {
            m.shards.push(ShardInfo {
                zone: "_".into(),
                depth: 2,
                prefix: p,
                count: 1,
                public: 1,
                key: format!("k{p}"),
                etag: "e".into(),
            });
        }
        let add = ShardInfo {
            zone: "_".into(),
            depth: 3,
            prefix: 9,
            count: 2,
            public: 2,
            key: "n".into(),
            etag: "f".into(),
        };
        let n = commit(&m, &[1], vec![add.clone()], 4, "new", true);
        assert_eq!(
            n.shards.iter().map(|s| s.key.as_str()).collect::<Vec<_>>(),
            vec!["k0", "k2", "n"]
        );
        assert_eq!(n.model, "old"); // non-empty index keeps its model
        assert!(n.migrated_from_v1 && n.generation == 4);
        assert_eq!(
            commit(&Manifest::new("x"), &[], vec![add], 1, "new", false).model,
            "new"
        );
    }

    #[test]
    fn bounded_first_stage_equals_full_sort() {
        let rows = lcg_rows(5000, 51, 3);
        let parts = split_until_fits(rows, 0, 0, 700);
        let codes: Vec<ShardCodes> = parts
            .iter()
            .map(|(d, p, rs)| {
                let b = encode_shard(rs, "_", *d, *p);
                let (x, y) = ShardLayout::new(rs.len()).hot_range();
                ShardCodes::from_hot_range(rs.len(), &b[x..y]).unwrap()
            })
            .collect();
        let refs: Vec<&ShardCodes> = codes.iter().collect();
        let lut = QueryLut::new(&lcg_rows(1, 52, 1)[0].vec);
        let mut full: Vec<Candidate> = Vec::new();
        for (si, s) in refs.iter().enumerate() {
            for i in 0..s.count {
                if s.is_public(i) {
                    full.push((
                        si,
                        i,
                        lut.score(&s.codes[i * CODE_BYTES..(i + 1) * CODE_BYTES]),
                    ));
                }
            }
        }
        full.sort_by(|a, b| {
            b.2.partial_cmp(&a.2)
                .unwrap()
                .then(a.0.cmp(&b.0))
                .then(a.1.cmp(&b.1))
        });
        for r in [1usize, 7, 80, 300, 10_000] {
            let want: Vec<Candidate> = full.iter().take(r).copied().collect();
            assert_eq!(first_stage(&lut, &refs, r), want, "r={r}");
        }
    }

    #[test]
    fn racing_writers_never_share_or_delete_each_others_keys() {
        // Two ingests read the same base and touch the same (only) shard.
        let rows: Vec<Row> = lcg_rows(40, 61, 1);
        let mut objects = HashMap::new();
        let base = ingest_round(
            &Manifest::new("m"),
            &mut objects,
            rows[..20].iter().map(|r| ("_".into(), r.clone())).collect(),
            8192,
        );
        let before: std::collections::HashSet<String> = objects.keys().cloned().collect();
        let winner = ingest_round_n(
            &base,
            &mut objects,
            rows[20..30]
                .iter()
                .map(|r| ("_".into(), r.clone()))
                .collect(),
            8192,
            "w1",
        );
        let loser = ingest_round_n(
            &base,
            &mut objects,
            rows[30..].iter().map(|r| ("_".into(), r.clone())).collect(),
            8192,
            "l1",
        );
        assert_eq!(winner.generation, loser.generation);
        let wk: std::collections::HashSet<&String> = winner.shards.iter().map(|s| &s.key).collect();
        let lk: Vec<&String> = loser
            .shards
            .iter()
            .map(|s| &s.key)
            .filter(|k| !before.contains(*k))
            .collect();
        // The loser's cleanup set (what it wrote) never intersects the winner's committed keys.
        assert!(lk.iter().all(|k| !wk.contains(k)));
        for k in &lk {
            objects.remove(*k);
        }
        // Every key the committed manifest names still exists and decodes.
        for s in &winner.shards {
            assert_eq!(decode_shard(&objects[&s.key]).unwrap().len(), s.count);
        }
    }

    #[test]
    fn zone_and_hash_helpers() {
        assert!(valid_zone("_") && valid_zone("zone1") && valid_zone("a-b"));
        assert!(
            !valid_zone("")
                && !valid_zone("Zone")
                && !valid_zone("../x")
                && !valid_zone(&"a".repeat(33))
        );
        let h = id_hash("abc");
        assert!(owns(0, 0, h));
        assert!(owns(1, h >> 63, h) && !owns(1, (h >> 63) ^ 1, h));
        assert_eq!(id_hash("abc"), h);
        assert_eq!(
            shard_key("s.rvf", "_", 3, 5, 7, "ab"),
            "s.rvf.v2/_/3-0000000000000005-g7-ab.rvf"
        );
    }
}
