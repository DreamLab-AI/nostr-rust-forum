//! In-memory vector store with RVF binary format persistence.
//!
//! Stores 384-dim f32 vectors with u64 labels in memory. Persists to R2 as
//! RVF-format segments (SegmentHeader + payload) and id↔label mapping to KV.
//!
//! RVF layout on R2:
//!   [SegmentHeader(Vec, 0)] [f32 vectors packed: label_u64 + dim*f32 each]
//!   [SegmentHeader(Meta, 1)] [JSON id↔label mapping]
//!
//! v1 is read-only now: `/search` falls back to it while no v2 manifest
//! exists, and the first v2 ingest migrates it (see [`crate::shard`]).

use rvf_types::constants::SEGMENT_HEADER_SIZE;
#[cfg(test)]
use rvf_types::constants::{SEGMENT_MAGIC, SEGMENT_VERSION};
use rvf_types::segment::SegmentHeader;
use rvf_types::segment_type::SegmentType;

use std::cmp::Ordering;
#[cfg(test)]
use std::collections::HashMap;

use crate::embed::DIM;

/// Bytes per stored vector entry: u64 label + DIM * f32.
const ENTRY_SIZE: usize = 8 + DIM * 4; // 1544 bytes

/// In-memory decoded v1 store. Test-only: the equivalence oracle for
/// [`search_rvf`] and the v2 index (production reads v1 bytes in place and
/// writes only v2).
#[cfg(test)]
pub struct VectorStore {
    /// Packed storage: (label, embedding).
    entries: Vec<(u64, [f32; DIM])>,
    /// label -> position of its FIRST entry, so `insert` replaces in O(1)
    /// exactly the entry the old linear `find` would have replaced.
    index: HashMap<u64, usize>,
}

#[cfg(test)]
impl VectorStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            index: HashMap::new(),
        }
    }

    /// Number of vectors in the store.
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Insert a vector with the given label. Replaces if label exists.
    pub fn insert(&mut self, label: u64, embedding: &[f32]) {
        debug_assert_eq!(embedding.len(), DIM);
        let mut arr = [0.0f32; DIM];
        arr.copy_from_slice(embedding);

        // Replace existing
        if let Some(&pos) = self.index.get(&label) {
            self.entries[pos].1 = arr;
            return;
        }
        self.index.insert(label, self.entries.len());
        self.entries.push((label, arr));
    }

    fn push_loaded(&mut self, label: u64, emb: [f32; DIM]) {
        // A file can in principle hold a label twice; keep both entries (as
        // before) and index the first, which is the one `insert` replaces.
        self.index.entry(label).or_insert(self.entries.len());
        self.entries.push((label, emb));
    }

    /// Cosine similarity k-NN search. Returns (label, score) pairs sorted by
    /// descending score (1.0 = identical, 0.0 = orthogonal).
    ///
    /// # `k` is a raw candidate count, not a final result count
    ///
    /// This truncates to `k` with no knowledge of visibility, so any caller that
    /// filters the output (as `/search` does, through the public-label set) must
    /// pass an OVER-FETCHED `k` and cut to the real limit itself -- see
    /// `overfetch_k` / `visible_top_k` in `lib.rs`. Passing the user-facing `k`
    /// here and then filtering silently starves the result set whenever the top
    /// neighbours happen to be non-public.
    ///
    /// Test-only: production searches the persisted bytes with [`search_rvf`],
    /// and this decoded-store path is kept as its equivalence oracle.
    #[cfg(test)]
    pub fn search(&self, query: &[f32], k: usize, min_score: f32) -> Vec<(u64, f32)> {
        if self.entries.is_empty() || query.len() != DIM {
            return Vec::new();
        }

        let candidates = self
            .entries
            .iter()
            .enumerate()
            .map(|(pos, (label, vec))| (pos, *label, cosine_similarity(query, vec)))
            .filter(|(_, _, score)| *score >= min_score);
        top_k(candidates, k)
    }

    /// Deserialize from RVF binary format. Returns None on invalid data.
    ///
    /// Test-only convenience; the worker decodes only for ingest, through
    /// [`Self::from_rvf_bytes_with_spare`].
    #[cfg(test)]
    pub fn from_rvf_bytes(data: &[u8]) -> Option<Self> {
        Self::from_rvf_bytes_with_spare(data, 0)
    }

    /// Like [`Self::from_rvf_bytes`], reserving room for `spare` more vectors.
    ///
    /// Capacity is reserved once, for the stored count plus `spare`, so an
    /// ingest of `spare` new vectors never reallocates. Growing by doubling
    /// (the old behaviour) peaked at about 2x the decoded size, and a
    /// realloc on the first append copies old and new buffers side by side;
    /// either is what ran ingest out of the 256 MiB wasm memory first.
    pub fn from_rvf_bytes_with_spare(data: &[u8], spare: usize) -> Option<Self> {
        let mut store = Self::new();
        let n = vec_payloads(data).iter().map(|p| p.len() / ENTRY_SIZE).sum::<usize>();
        store.entries.reserve_exact(n.saturating_add(spare));
        store.index.reserve(n.saturating_add(spare));
        let mut offset = 0;

        while offset + SEGMENT_HEADER_SIZE <= data.len() {
            let hdr = read_header(&data[offset..offset + SEGMENT_HEADER_SIZE])?;
            if !hdr.is_valid_magic() {
                break;
            }

            let payload_start = offset + SEGMENT_HEADER_SIZE;
            let payload_len = hdr.payload_length as usize;
            if payload_start + payload_len > data.len() {
                break;
            }

            let payload = &data[payload_start..payload_start + payload_len];

            if hdr.seg_type == SegmentType::Vec as u8 {
                // Parse packed vector entries
                let mut pos = 0;
                while pos + ENTRY_SIZE <= payload.len() {
                    let label = u64::from_le_bytes(payload[pos..pos + 8].try_into().ok()?);
                    let mut emb = [0.0f32; DIM];
                    for (j, slot) in emb.iter_mut().enumerate().take(DIM) {
                        let fo = pos + 8 + j * 4;
                        *slot = f32::from_le_bytes(payload[fo..fo + 4].try_into().ok()?);
                    }
                    store.push_loaded(label, emb);
                    pos += ENTRY_SIZE;
                }
            }
            // Skip Meta and other segment types (we read mapping from KV)

            // Advance to next segment (aligned to 64 bytes)
            offset = payload_start + align64(payload_len);
        }

        Some(store)
    }
}

// ---------------------------------------------------------------------------
// Zero-copy search over the persisted bytes
// ---------------------------------------------------------------------------

/// Vec-segment payloads of an RVF buffer, walked exactly as
/// [`VectorStore::from_rvf_bytes`] walks them (stop at bad magic or a
/// truncated payload; skip non-Vec segments).
fn vec_payloads(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset + SEGMENT_HEADER_SIZE <= data.len() {
        let Some(hdr) = read_header(&data[offset..offset + SEGMENT_HEADER_SIZE]) else {
            break;
        };
        if !hdr.is_valid_magic() {
            break;
        }
        let payload_start = offset + SEGMENT_HEADER_SIZE;
        let payload_len = hdr.payload_length as usize;
        if payload_start + payload_len > data.len() {
            break;
        }
        if hdr.seg_type == SegmentType::Vec as u8 {
            out.push(&data[payload_start..payload_start + payload_len]);
        }
        offset = payload_start + align64(payload_len);
    }
    out
}

/// Every `(label, vector)` of a v1 RVF buffer, decoded one at a time (v1 → v2
/// migration).
pub fn rvf_entries(data: &[u8]) -> impl Iterator<Item = (u64, [f32; DIM])> + '_ {
    vec_payloads(data).into_iter().flat_map(|p| {
        p.chunks_exact(ENTRY_SIZE).map(|e| {
            let mut lb = [0u8; 8];
            lb.copy_from_slice(&e[..8]);
            let mut v = [0f32; DIM];
            for (i, c) in e[8..].chunks_exact(4).enumerate() {
                v[i] = f32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            }
            (u64::from_le_bytes(lb), v)
        })
    })
}

/// Vector count of a v1 store given only its first 64 bytes (the Vec segment
/// header the v1 writer always puts first). 0 if those bytes are not one.
pub fn rvf_count_from_first_header(first: &[u8]) -> usize {
    match first.get(..SEGMENT_HEADER_SIZE).and_then(read_header) {
        Some(h) if h.is_valid_magic() && h.seg_type == SegmentType::Vec as u8 => {
            h.payload_length as usize / ENTRY_SIZE
        }
        _ => 0,
    }
}

/// Number of whole vectors in an RVF buffer, without decoding any of them.
pub fn rvf_count(data: &[u8]) -> usize {
    vec_payloads(data).iter().map(|p| p.len() / ENTRY_SIZE).sum()
}

/// Cosine similarity of `query` against one packed little-endian entry body.
///
/// Same accumulation order as [`cosine_similarity`], so scores are
/// bit-identical to searching the decoded store.
pub(crate) fn cosine_le_bytes(query: &[f32], body: &[u8]) -> f32 {
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for (a, chunk) in query.iter().zip(body.chunks_exact(4)) {
        let b = f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        dot += a * b;
        norm_a += a * a;
        norm_b += b * b;
    }
    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom == 0.0 {
        0.0
    } else {
        dot / denom
    }
}

/// k-NN straight off the persisted RVF bytes.
///
/// Returns exactly what `VectorStore::from_rvf_bytes(data)?.search(..)` would,
/// without materialising a second copy of every vector: at 1,544 B per vector
/// that copy doubled peak memory, which is what binds against the 128 MB
/// isolate limit.
pub fn search_rvf(data: &[u8], query: &[f32], k: usize, min_score: f32) -> Vec<(u64, f32)> {
    if query.len() != DIM {
        return Vec::new();
    }
    let mut pos = 0usize;
    let mut candidates = Vec::new();
    for payload in vec_payloads(data) {
        for entry in payload.chunks_exact(ENTRY_SIZE) {
            let mut lb = [0u8; 8];
            lb.copy_from_slice(&entry[..8]);
            let score = cosine_le_bytes(query, &entry[8..]);
            if score >= min_score {
                candidates.push((pos, u64::from_le_bytes(lb), score));
            }
            pos += 1;
        }
    }
    top_k(candidates.into_iter(), k)
}

/// Best `k` of `(position, label, score)` candidates, by descending score and
/// then ascending position.
///
/// Scores are never NaN here (callers filter with `>= min_score`, which NaN
/// fails), so this is a total order: the result is deterministic, which the
/// old unstable full sort did not guarantee among equal scores. Selection is
/// O(n) plus O(k log k) instead of an O(n log n) sort of every candidate.
fn top_k(candidates: impl Iterator<Item = (usize, u64, f32)>, k: usize) -> Vec<(u64, f32)> {
    let cmp = |a: &(usize, u64, f32), b: &(usize, u64, f32)| {
        b.2.partial_cmp(&a.2)
            .unwrap_or(Ordering::Equal)
            .then(a.0.cmp(&b.0))
    };
    let mut v: Vec<(usize, u64, f32)> = candidates.collect();
    if k == 0 {
        return Vec::new();
    }
    if v.len() > k {
        v.select_nth_unstable_by(k - 1, cmp);
        v.truncate(k);
    }
    v.sort_unstable_by(cmp);
    v.into_iter().map(|(_, l, s)| (l, s)).collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Cosine similarity between two vectors (test oracle for [`cosine_le_bytes`]).
#[cfg(test)]
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for i in 0..a.len() {
        dot += a[i] * b[i];
        norm_a += a[i] * a[i];
        norm_b += b[i] * b[i];
    }
    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom == 0.0 {
        0.0
    } else {
        dot / denom
    }
}

/// Round up to next 64-byte boundary.
pub(crate) const fn align64(size: usize) -> usize {
    (size + 63) & !63
}

/// Write a SegmentHeader to a byte buffer (little-endian, matching repr(C) layout).
pub(crate) fn write_header(buf: &mut [u8], hdr: &SegmentHeader) {
    // Safety: SegmentHeader is repr(C) and 64 bytes. We write field by field
    // for portability (no reliance on alignment assumptions in WASM).
    buf[0..4].copy_from_slice(&hdr.magic.to_le_bytes());
    buf[4] = hdr.version;
    buf[5] = hdr.seg_type;
    buf[6..8].copy_from_slice(&hdr.flags.to_le_bytes());
    buf[8..16].copy_from_slice(&hdr.segment_id.to_le_bytes());
    buf[16..24].copy_from_slice(&hdr.payload_length.to_le_bytes());
    buf[24..32].copy_from_slice(&hdr.timestamp_ns.to_le_bytes());
    buf[32] = hdr.checksum_algo;
    buf[33] = hdr.compression;
    buf[34..36].copy_from_slice(&hdr.reserved_0.to_le_bytes());
    buf[36..40].copy_from_slice(&hdr.reserved_1.to_le_bytes());
    buf[40..56].copy_from_slice(&hdr.content_hash);
    buf[56..60].copy_from_slice(&hdr.uncompressed_len.to_le_bytes());
    buf[60..64].copy_from_slice(&hdr.alignment_pad.to_le_bytes());
}

/// Build a v1 RVF byte buffer from entries (test fixture: the layout the v1
/// writer produced, with a zero timestamp).
#[cfg(test)]
pub(crate) fn build_rvf_bytes_for_test(entries: &[(u64, [f32; DIM])]) -> Vec<u8> {
    let vec_payload_len = entries.len() * ENTRY_SIZE;
    let meta_json = serde_json::json!({
        "format": "rvf-wasm-v1",
        "dimensions": DIM,
        "count": entries.len(),
        "metric": "cosine",
    });
    let meta_bytes = serde_json::to_vec(&meta_json).unwrap_or_default();

    let vec_seg_padded = align64(vec_payload_len);
    let meta_seg_padded = align64(meta_bytes.len());
    let total = SEGMENT_HEADER_SIZE + vec_seg_padded + SEGMENT_HEADER_SIZE + meta_seg_padded;
    let mut buf = vec![0u8; total];

    let vec_hdr = SegmentHeader {
        magic: SEGMENT_MAGIC,
        version: SEGMENT_VERSION,
        seg_type: SegmentType::Vec as u8,
        flags: 0,
        segment_id: 0,
        payload_length: vec_payload_len as u64,
        timestamp_ns: 0,
        checksum_algo: 0,
        compression: 0,
        reserved_0: 0,
        reserved_1: 0,
        content_hash: [0u8; 16],
        uncompressed_len: 0,
        alignment_pad: 0,
    };
    write_header(&mut buf[..SEGMENT_HEADER_SIZE], &vec_hdr);

    let payload_start = SEGMENT_HEADER_SIZE;
    for (i, (label, emb)) in entries.iter().enumerate() {
        let offset = payload_start + i * ENTRY_SIZE;
        buf[offset..offset + 8].copy_from_slice(&label.to_le_bytes());
        for (j, val) in emb.iter().enumerate() {
            let fo = offset + 8 + j * 4;
            buf[fo..fo + 4].copy_from_slice(&val.to_le_bytes());
        }
    }

    let meta_hdr_start = SEGMENT_HEADER_SIZE + vec_seg_padded;
    let meta_hdr = SegmentHeader {
        magic: SEGMENT_MAGIC,
        version: SEGMENT_VERSION,
        seg_type: SegmentType::Meta as u8,
        flags: 0,
        segment_id: 1,
        payload_length: meta_bytes.len() as u64,
        timestamp_ns: 0,
        checksum_algo: 0,
        compression: 0,
        reserved_0: 0,
        reserved_1: 0,
        content_hash: [0u8; 16],
        uncompressed_len: 0,
        alignment_pad: 0,
    };
    write_header(
        &mut buf[meta_hdr_start..meta_hdr_start + SEGMENT_HEADER_SIZE],
        &meta_hdr,
    );

    let meta_payload_start = meta_hdr_start + SEGMENT_HEADER_SIZE;
    buf[meta_payload_start..meta_payload_start + meta_bytes.len()].copy_from_slice(&meta_bytes);

    buf
}

/// Read a SegmentHeader from a byte buffer.
pub(crate) fn read_header(buf: &[u8]) -> Option<SegmentHeader> {
    if buf.len() < SEGMENT_HEADER_SIZE {
        return None;
    }
    Some(SegmentHeader {
        magic: u32::from_le_bytes(buf[0..4].try_into().ok()?),
        version: buf[4],
        seg_type: buf[5],
        flags: u16::from_le_bytes(buf[6..8].try_into().ok()?),
        segment_id: u64::from_le_bytes(buf[8..16].try_into().ok()?),
        payload_length: u64::from_le_bytes(buf[16..24].try_into().ok()?),
        timestamp_ns: u64::from_le_bytes(buf[24..32].try_into().ok()?),
        checksum_algo: buf[32],
        compression: buf[33],
        reserved_0: u16::from_le_bytes(buf[34..36].try_into().ok()?),
        reserved_1: u32::from_le_bytes(buf[36..40].try_into().ok()?),
        content_hash: buf[40..56].try_into().ok()?,
        uncompressed_len: u32::from_le_bytes(buf[56..60].try_into().ok()?),
        alignment_pad: u32::from_le_bytes(buf[60..64].try_into().ok()?),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Make a unit vector pointing in dimension `dim_idx`.
    fn unit_vec(dim_idx: usize) -> [f32; DIM] {
        let mut v = [0.0f32; DIM];
        v[dim_idx] = 1.0;
        v
    }

    /// Make a vector with all components equal to `val`, then L2-normalize.
    fn uniform_vec(val: f32) -> [f32; DIM] {
        let mut v = [val; DIM];
        let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for x in v.iter_mut() {
                *x /= norm;
            }
        }
        v
    }

    // ── cosine_similarity ───────────────────────────────────────────────

    #[test]
    fn cosine_identical_vectors() {
        let v = unit_vec(0);
        let sim = cosine_similarity(&v, &v);
        assert!((sim - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_orthogonal_vectors() {
        let a = unit_vec(0);
        let b = unit_vec(1);
        let sim = cosine_similarity(&a, &b);
        assert!(sim.abs() < 1e-6);
    }

    #[test]
    fn cosine_opposite_vectors() {
        let a = unit_vec(0);
        let mut b = unit_vec(0);
        b[0] = -1.0;
        let sim = cosine_similarity(&a, &b);
        assert!((sim - (-1.0)).abs() < 1e-6);
    }

    #[test]
    fn cosine_zero_vector() {
        let a = [0.0f32; DIM];
        let b = unit_vec(0);
        let sim = cosine_similarity(&a, &b);
        assert_eq!(sim, 0.0);
    }

    #[test]
    fn cosine_both_zero() {
        let a = [0.0f32; DIM];
        let sim = cosine_similarity(&a, &a);
        assert_eq!(sim, 0.0);
    }

    #[test]
    fn cosine_similar_vectors() {
        let a = uniform_vec(1.0);
        let mut b = uniform_vec(1.0);
        b[0] += 0.001; // slightly perturb
        let sim = cosine_similarity(&a, &b);
        assert!(sim > 0.99);
    }

    // ── align64 ─────────────────────────────────────────────────────────

    #[test]
    fn align64_zero() {
        assert_eq!(align64(0), 0);
    }

    #[test]
    fn align64_one() {
        assert_eq!(align64(1), 64);
    }

    #[test]
    fn align64_exact() {
        assert_eq!(align64(64), 64);
    }

    #[test]
    fn align64_sixty_five() {
        assert_eq!(align64(65), 128);
    }

    #[test]
    fn align64_large() {
        assert_eq!(align64(1000), 1024);
    }

    // ── write_header / read_header roundtrip ────────────────────────────

    #[test]
    fn header_roundtrip() {
        let hdr = SegmentHeader {
            magic: SEGMENT_MAGIC,
            version: SEGMENT_VERSION,
            seg_type: SegmentType::Vec as u8,
            flags: 0x1234,
            segment_id: 42,
            payload_length: 9999,
            timestamp_ns: 123456789,
            checksum_algo: 1,
            compression: 2,
            reserved_0: 0xABCD,
            reserved_1: 0xDEADBEEF,
            content_hash: [0x11; 16],
            uncompressed_len: 8888,
            alignment_pad: 7777,
        };
        let mut buf = [0u8; SEGMENT_HEADER_SIZE];
        write_header(&mut buf, &hdr);
        let read = read_header(&buf).unwrap();

        assert_eq!(read.magic, hdr.magic);
        assert_eq!(read.version, hdr.version);
        assert_eq!(read.seg_type, hdr.seg_type);
        assert_eq!(read.flags, hdr.flags);
        assert_eq!(read.segment_id, hdr.segment_id);
        assert_eq!(read.payload_length, hdr.payload_length);
        assert_eq!(read.timestamp_ns, hdr.timestamp_ns);
        assert_eq!(read.checksum_algo, hdr.checksum_algo);
        assert_eq!(read.compression, hdr.compression);
        assert_eq!(read.reserved_0, hdr.reserved_0);
        assert_eq!(read.reserved_1, hdr.reserved_1);
        assert_eq!(read.content_hash, hdr.content_hash);
        assert_eq!(read.uncompressed_len, hdr.uncompressed_len);
        assert_eq!(read.alignment_pad, hdr.alignment_pad);
    }

    #[test]
    fn read_header_too_short() {
        let buf = [0u8; 10];
        assert!(read_header(&buf).is_none());
    }

    // ── VectorStore::new / count ────────────────────────────────────────

    #[test]
    fn new_store_is_empty() {
        let store = VectorStore::new();
        assert_eq!(store.count(), 0);
    }

    // ── insert ──────────────────────────────────────────────────────────

    #[test]
    fn insert_and_count() {
        let mut store = VectorStore::new();
        store.insert(1, &unit_vec(0));
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn insert_multiple() {
        let mut store = VectorStore::new();
        for i in 0..10 {
            store.insert(i, &unit_vec(i as usize % DIM));
        }
        assert_eq!(store.count(), 10);
    }

    #[test]
    fn insert_duplicate_replaces() {
        let mut store = VectorStore::new();
        store.insert(1, &unit_vec(0));
        store.insert(1, &unit_vec(1));
        assert_eq!(store.count(), 1);
        // Search should find the new vector
        let results = store.search(&unit_vec(1), 1, 0.0);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 1);
        assert!((results[0].1 - 1.0).abs() < 1e-6);
    }

    // ── search ──────────────────────────────────────────────────────────

    #[test]
    fn search_empty_store() {
        let store = VectorStore::new();
        let results = store.search(&unit_vec(0), 5, 0.0);
        assert!(results.is_empty());
    }

    #[test]
    fn search_finds_exact_match() {
        let mut store = VectorStore::new();
        store.insert(42, &unit_vec(0));
        let results = store.search(&unit_vec(0), 1, 0.0);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 42);
        assert!((results[0].1 - 1.0).abs() < 1e-6);
    }

    #[test]
    fn search_k_1() {
        let mut store = VectorStore::new();
        store.insert(1, &unit_vec(0));
        store.insert(2, &unit_vec(1));
        store.insert(3, &unit_vec(2));
        let results = store.search(&unit_vec(0), 1, 0.0);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 1);
    }

    #[test]
    fn search_k_5() {
        let mut store = VectorStore::new();
        for i in 0..10 {
            store.insert(i, &unit_vec(i as usize % DIM));
        }
        let results = store.search(&unit_vec(0), 5, 0.0);
        assert!(results.len() <= 5);
        // Best match should be label 0 (exact match)
        assert_eq!(results[0].0, 0);
    }

    #[test]
    fn search_k_10_more_than_store() {
        let mut store = VectorStore::new();
        store.insert(1, &unit_vec(0));
        store.insert(2, &unit_vec(1));
        let results = store.search(&unit_vec(0), 10, 0.0);
        // Should return at most 2 (store size)
        assert!(results.len() <= 2);
    }

    #[test]
    fn search_respects_min_score() {
        let mut store = VectorStore::new();
        store.insert(1, &unit_vec(0)); // cos=1.0 to query
        store.insert(2, &unit_vec(1)); // cos=0.0 to query
        let results = store.search(&unit_vec(0), 10, 0.5);
        // Only label 1 should pass min_score=0.5
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 1);
    }

    #[test]
    fn search_results_sorted_descending() {
        let mut store = VectorStore::new();
        // Insert 3 vectors at varying similarity to query
        let query = unit_vec(0);
        store.insert(1, &unit_vec(0)); // cos=1.0

        let mut similar = unit_vec(0);
        similar[1] = 0.5;
        store.insert(2, &similar); // high similarity

        store.insert(3, &unit_vec(1)); // cos=0.0

        let results = store.search(&query, 10, -1.0);
        // Verify descending order
        for i in 1..results.len() {
            assert!(results[i - 1].1 >= results[i].1);
        }
    }

    #[test]
    fn search_wrong_dimension_returns_empty() {
        let mut store = VectorStore::new();
        store.insert(1, &unit_vec(0));
        // Query with wrong dimension
        let wrong_dim = vec![1.0f32; DIM / 2];
        let results = store.search(&wrong_dim, 5, 0.0);
        assert!(results.is_empty());
    }

    // ── RVF serialization roundtrip ─────────────────────────────────────

    #[test]
    fn rvf_roundtrip_empty() {
        let entries: Vec<(u64, [f32; DIM])> = vec![];
        let bytes = build_rvf_bytes_for_test(&entries);
        let store = VectorStore::from_rvf_bytes(&bytes).unwrap();
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn rvf_roundtrip_single_entry() {
        let v = unit_vec(0);
        let entries = vec![(42u64, v)];
        let bytes = build_rvf_bytes_for_test(&entries);
        let store = VectorStore::from_rvf_bytes(&bytes).unwrap();
        assert_eq!(store.count(), 1);
        let results = store.search(&v, 1, 0.0);
        assert_eq!(results[0].0, 42);
        assert!((results[0].1 - 1.0).abs() < 1e-6);
    }

    #[test]
    fn rvf_roundtrip_multiple_entries() {
        let mut entries = Vec::new();
        for i in 0..5u64 {
            entries.push((i + 1, unit_vec(i as usize)));
        }
        let bytes = build_rvf_bytes_for_test(&entries);
        let store = VectorStore::from_rvf_bytes(&bytes).unwrap();
        assert_eq!(store.count(), 5);
    }

    #[test]
    fn rvf_from_invalid_data() {
        let garbage = [0xFF; 100];
        let result = VectorStore::from_rvf_bytes(&garbage);
        // Should return Some(empty) because magic check fails, breaking loop
        if let Some(store) = result {
            assert_eq!(store.count(), 0);
        }
    }

    #[test]
    fn rvf_from_truncated_data() {
        // Valid header but payload is truncated
        let v = unit_vec(0);
        let entries = vec![(1u64, v)];
        let mut bytes = build_rvf_bytes_for_test(&entries);
        // Truncate the payload
        bytes.truncate(SEGMENT_HEADER_SIZE + 10);
        let store = VectorStore::from_rvf_bytes(&bytes).unwrap();
        // Incomplete entry should not be loaded
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn rvf_from_empty_data() {
        let result = VectorStore::from_rvf_bytes(&[]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().count(), 0);
    }

    // ── O(1) insert, top-k selection, zero-copy search ────────────────────

    /// Deterministic pseudo-random vectors (LCG), no extra dev-dependency.
    fn lcg_vecs(n: usize, seed: u64) -> Vec<(u64, [f32; DIM])> {
        let mut x = seed;
        let mut next = || {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((x >> 33) as f32 / (1u64 << 31) as f32) - 0.5
        };
        (0..n)
            .map(|i| {
                let mut v = [0.0f32; DIM];
                for slot in v.iter_mut() {
                    *slot = next();
                }
                (i as u64 * 7 + 3, v)
            })
            .collect()
    }

    /// The pre-change algorithm: score all, full sort, truncate.
    fn reference_search(entries: &[(u64, [f32; DIM])], q: &[f32], k: usize, min: f32) -> Vec<(u64, f32)> {
        let mut r: Vec<(usize, u64, f32)> = entries
            .iter()
            .enumerate()
            .map(|(p, (l, v))| (p, *l, cosine_similarity(q, v)))
            .filter(|(_, _, s)| *s >= min)
            .collect();
        r.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap().then(a.0.cmp(&b.0)));
        r.truncate(k);
        r.into_iter().map(|(_, l, s)| (l, s)).collect()
    }

    #[test]
    fn search_paths_match_reference_exactly() {
        let entries = lcg_vecs(3_000, 42);
        let queries = lcg_vecs(12, 7);
        let bytes = build_rvf_bytes_for_test(&entries);
        let store = VectorStore::from_rvf_bytes(&bytes).unwrap();
        for (_, q) in &queries {
            for &(k, min) in &[(1, -1.0), (10, 0.0), (40, -1.0), (400, 0.05), (5_000, -1.0)] {
                let want = reference_search(&entries, q, k, min);
                assert_eq!(store.search(q, k, min), want, "store k={k} min={min}");
                // Bit-identical scores, identical order.
                assert_eq!(search_rvf(&bytes, q, k, min), want, "bytes k={k} min={min}");
            }
        }
    }

    #[test]
    fn top_k_breaks_ties_by_position() {
        let mut store = VectorStore::new();
        for l in [9u64, 4, 6] {
            store.insert(l, &unit_vec(0));
        }
        store.insert(1, &unit_vec(1));
        let got = store.search(&unit_vec(0), 2, -1.0);
        assert_eq!(got, vec![(9, 1.0), (4, 1.0)]);
        assert!(store.search(&unit_vec(0), 0, -1.0).is_empty());
    }

    #[test]
    fn rvf_count_and_search_handle_bad_input() {
        let entries = lcg_vecs(5, 1);
        let bytes = build_rvf_bytes_for_test(&entries);
        assert_eq!(rvf_count(&bytes), 5);
        assert_eq!(rvf_count(&[]), 0);
        assert_eq!(rvf_count(&[0xFF; 100]), 0);
        let mut cut = bytes.clone();
        cut.truncate(SEGMENT_HEADER_SIZE + 10);
        assert_eq!(rvf_count(&cut), 0);
        assert!(search_rvf(&cut, &entries[0].1, 3, -1.0).is_empty());
        assert!(search_rvf(&bytes, &[1.0; DIM / 2], 3, -1.0).is_empty());
        assert_eq!(search_rvf(&bytes, &entries[2].1, 1, -1.0)[0].0, entries[2].0);
    }

    #[test]
    fn insert_replaces_first_duplicate_after_load() {
        // A file holding a label twice: both load, insert replaces the first.
        let entries = vec![(5u64, unit_vec(0)), (5u64, unit_vec(1)), (6u64, unit_vec(2))];
        let bytes = build_rvf_bytes_for_test(&entries);
        let mut store = VectorStore::from_rvf_bytes(&bytes).unwrap();
        assert_eq!(store.count(), 3);
        store.insert(5, &unit_vec(3));
        assert_eq!(store.count(), 3);
        assert_eq!(store.search(&unit_vec(3), 1, 0.5), vec![(5, 1.0)]);
        assert_eq!(store.search(&unit_vec(1), 1, 0.5), vec![(5, 1.0)]);
        assert!(store.search(&unit_vec(0), 1, 0.5).is_empty());
        // New labels still append.
        store.insert(7, &unit_vec(4));
        assert_eq!(store.count(), 4);
    }

    #[test]
    fn spare_capacity_avoids_realloc_on_ingest() {
        let entries = lcg_vecs(1_000, 9);
        let bytes = build_rvf_bytes_for_test(&entries);
        let mut store = VectorStore::from_rvf_bytes_with_spare(&bytes, 500).unwrap();
        assert_eq!(store.count(), 1_000);
        let cap = store.entries.capacity();
        assert!(cap >= 1_500);
        for (l, v) in lcg_vecs(500, 10) {
            store.insert(l + 1_000_000, &v);
        }
        assert_eq!(store.count(), 1_500);
        assert_eq!(store.entries.capacity(), cap, "no reallocation within the spare");
        // Same content as a plain decode.
        let plain = VectorStore::from_rvf_bytes(&bytes).unwrap();
        assert_eq!(plain.count(), 1_000);
        assert_eq!(plain.entries[..], store.entries[..1_000]);
    }

    #[test]
    fn insert_many_is_fast_and_consistent() {
        let mut store = VectorStore::new();
        let entries = lcg_vecs(20_000, 3);
        for (l, v) in &entries {
            store.insert(*l, v);
        }
        for (l, v) in entries.iter().take(100) {
            store.insert(*l, v);
        }
        assert_eq!(store.count(), 20_000);
    }

    // ── ENTRY_SIZE constant ─────────────────────────────────────────────

    #[test]
    fn entry_size_matches_expected() {
        assert_eq!(ENTRY_SIZE, 8 + DIM * 4); // u64 label + DIM f32s
    }
}
