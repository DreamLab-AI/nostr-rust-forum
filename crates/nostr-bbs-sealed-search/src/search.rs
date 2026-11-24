//! The in-worker search index: verified, decrypted bin layers kept resident;
//! int8 rows read by age chunk for rescoring.
//!
//! I/O-agnostic and synchronous: the caller (browser worker or native test)
//! supplies bytes. Rescoring is two-phase — [`Index::plan_rescore`] says
//! which byte ranges of which `q-` objects are needed, the caller fetches
//! them (blob slices), then [`Index::rescore`] decrypts just those chunks.

use std::collections::{BTreeMap, HashMap};

use sha2::{Digest, Sha256};

use crate::format::{int8_row_offset, BinLayer, Header, Kind, Scope};
use crate::manifest::{Content, ObjectRef};
use crate::model::DIM;
use crate::quant::{dot_i8, top_r, Candidate, QueryLut, I8_ROW_BYTES};
use crate::seal::{self, header_len, open_range, ranges_for, SearchKey, SparseReader};

/// Exactly one X25519 recipient stanza and no other real recipient (review
/// H3/L4): refuses scrypt and multi-recipient files before age parses
/// further. age writes random `*-grease` stanzas, which carry no key and are
/// ignored here as age itself ignores them.
pub fn single_x25519_stanza(prefix: &[u8]) -> bool {
    let Some(hl) = header_len(prefix) else { return false };
    let Ok(text) = std::str::from_utf8(&prefix[..hl]) else { return false };
    let types: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("-> "))
        .map(|l| l.split(' ').next().unwrap_or(""))
        .filter(|t| !t.ends_with("-grease"))
        .collect();
    types == ["X25519"]
}

/// Hex SHA-256.
pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn check_header(h: &Header, o: &ObjectRef, c: &Content) -> Result<(), String> {
    let pk = hex::encode(h.zone_pk);
    if h.kind != o.kind
        || h.scope != Scope::Base
        || h.zone != c.zone
        || h.epoch != o.epoch
        || pk != o.zone_pk.to_lowercase()
        || h.shard != o.shard
        || h.index_version != c.index_version
        || h.count != o.count
    {
        return Err(format!("object {} header does not match the manifest", o.name));
    }
    Ok(())
}

/// Verify a sealed object against its manifest entry (size, hash, stanza).
pub fn check_sealed(o: &ObjectRef, sealed_prefix: &[u8], total: usize, full_sha: Option<&str>) -> Result<(), String> {
    if total as u64 != o.size {
        return Err(format!("object {} size mismatch", o.name));
    }
    if let Some(h) = full_sha {
        if h != o.sha256.to_lowercase() {
            return Err(format!("object {} hash mismatch", o.name));
        }
    }
    if !single_x25519_stanza(sealed_prefix) {
        return Err(format!("object {} is not a single-X25519 age file", o.name));
    }
    Ok(())
}

struct Shard {
    bin: BinLayer,
    q: ObjectRef,
    /// age header length of the q object and its NBSS header length.
    q_geom: Option<(usize, usize)>,
}

/// One rescoring request: plaintext ranges of one `q-` object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeRequest {
    /// Object name.
    pub name: String,
    /// Ciphertext byte ranges `[a, b)` to fetch.
    pub ranges: Vec<(usize, usize)>,
}

/// Fetched ciphertext ranges: object name → `[(offset, bytes)]`.
pub type Fetched = HashMap<String, Vec<(usize, Vec<u8>)>>;

/// A search hit.
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    /// Event id (hex).
    pub id: String,
    /// Rescored cosine (int8 approximation).
    pub score: f32,
    /// Zone epoch of the shard it came from (client checks the event's `zk`).
    pub epoch: u32,
    /// Hex zone key pubkey of that epoch.
    pub zone_pk: String,
}

/// The resident index for one zone.
pub struct Index {
    content: Content,
    keys: HashMap<(u32, String), SearchKey>,
    shards: Vec<Shard>,
}

impl Index {
    /// Start an index for a verified manifest with the keys the member holds
    /// (keyed by `(epoch, hex zone_pk)`).
    pub fn new(content: Content, keys: HashMap<(u32, String), SearchKey>) -> Self {
        Self { content, keys, shards: Vec::new() }
    }

    /// Bin objects in the manifest whose key is held (others are skipped:
    /// a member without an old epoch simply cannot search it).
    pub fn wanted_bins(&self) -> Vec<ObjectRef> {
        self.content
            .objects
            .iter()
            .filter(|o| o.kind == Kind::Bin && self.keys.contains_key(&(o.epoch, o.zone_pk.to_lowercase())))
            .cloned()
            .collect()
    }

    fn q_for(&self, b: &ObjectRef) -> Option<ObjectRef> {
        self.content
            .objects
            .iter()
            .find(|o| o.kind == Kind::Int8 && o.epoch == b.epoch && o.shard == b.shard && o.zone_pk == b.zone_pk)
            .cloned()
    }

    /// Add a bin object: checks size/hash/stanza, decrypts, checks the
    /// authenticated header against the manifest, keeps ids + codes.
    pub fn add_bin(&mut self, o: &ObjectRef, sealed: &[u8]) -> Result<(), String> {
        check_sealed(o, sealed, sealed.len(), Some(&sha256_hex(sealed)))?;
        let key = self.keys.get(&(o.epoch, o.zone_pk.to_lowercase())).ok_or("no key for object")?;
        let bin = BinLayer::parse(&seal::open(key, sealed)?)?;
        check_header(&bin.header, o, &self.content)?;
        let q = self.q_for(o).ok_or_else(|| format!("no int8 layer for {}", o.name))?;
        self.shards.push(Shard { bin, q, q_geom: None });
        Ok(())
    }

    /// Rows resident.
    pub fn rows(&self) -> usize {
        self.shards.iter().map(|s| s.bin.header.count as usize).sum()
    }

    /// Resident bytes (ids + codes).
    pub fn resident_bytes(&self) -> usize {
        self.shards.iter().map(|s| s.bin.ids.len() + s.bin.codes.len()).sum()
    }

    /// Names of `q-` objects whose geometry is not known yet (the caller
    /// supplies their first bytes and full length via [`Index::set_q_prefix`]).
    pub fn q_needing_prefix(&self) -> Vec<ObjectRef> {
        self.shards.iter().filter(|s| s.q_geom.is_none()).map(|s| s.q.clone()).collect()
    }

    /// Record a `q-` object's geometry from its first bytes (at least the age
    /// header plus the first chunk), verifying stanza, size, and the
    /// authenticated NBSS header in chunk 0 (review L4).
    pub fn set_q_prefix(&mut self, name: &str, prefix: &[u8], total: usize) -> Result<(), String> {
        let content = self.content.clone();
        let si = self.shards.iter().position(|s| s.q.name == name).ok_or("unknown q object")?;
        let o = self.shards[si].q.clone();
        check_sealed(&o, prefix, total, None)?;
        let key = self.keys.get(&(o.epoch, o.zone_pk.to_lowercase())).ok_or("no key")?;
        let hl = header_len(prefix).ok_or("no age header")?;
        let want = ranges_for(hl, total, 0, 1);
        let parts: Vec<(usize, Vec<u8>)> = want
            .iter()
            .map(|&(a, b)| prefix.get(a..b).map(|x| (a, x.to_vec())).ok_or("prefix too short"))
            .collect::<Result<_, _>>()?;
        let head = open_range(key, SparseReader::new(total, parts), 0, 256.min(o.count as usize * I8_ROW_BYTES + 128))
            .map_err(|_| "cannot open int8 chunk 0".to_string())?;
        let (h, nb) = Header::decode(&head)?;
        check_header(&h, &o, &content)?;
        self.shards[si].q_geom = Some((hl, nb));
        Ok(())
    }

    /// First stage: best `r` rows by the lookup-table score over every
    /// resident code.
    pub fn first_stage(&self, q: &[f32; DIM], r: usize) -> Vec<Candidate> {
        let lut = QueryLut::new(q);
        top_r(
            self.shards.iter().enumerate().flat_map(|(si, s)| {
                let lut = &lut;
                (0..s.bin.header.count as usize).map(move |row| (si, row, lut.score(s.bin.code(row))))
            }),
            r,
        )
    }

    /// Byte ranges to fetch for rescoring `cands`.
    pub fn plan_rescore(&self, cands: &[Candidate]) -> Result<Vec<RangeRequest>, String> {
        let mut by: BTreeMap<usize, Vec<(usize, usize)>> = BTreeMap::new();
        for &(si, row, _) in cands {
            let s = &self.shards[si];
            let (hl, nb) = s.q_geom.ok_or("q geometry unknown")?;
            let off = int8_row_offset(nb, row);
            for r in ranges_for(hl, s.q.size as usize, off, I8_ROW_BYTES) {
                by.entry(si).or_default().push(r);
            }
        }
        Ok(by
            .into_iter()
            .map(|(si, mut v)| {
                v.sort_unstable();
                v.dedup();
                RangeRequest { name: self.shards[si].q.name.clone(), ranges: v }
            })
            .collect())
    }

    /// Rescore `cands` from fetched ranges (`name → [(offset, bytes)]`) and
    /// return the best `k`. One age decryptor per shard; rows are read by
    /// seeking, so each touched chunk is authenticated once.
    pub fn rescore(&self, q: &[f32; DIM], cands: &[Candidate], fetched: &Fetched, k: usize) -> Result<Vec<Hit>, String> {
        let mut by: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for &(si, row, _) in cands {
            by.entry(si).or_default().push(row);
        }
        let mut scored: Vec<(f32, usize, usize)> = Vec::with_capacity(cands.len());
        for (si, mut rows) in by {
            rows.sort_unstable();
            rows.dedup();
            let s = &self.shards[si];
            let (_, nb) = s.q_geom.ok_or("q geometry unknown")?;
            let parts = fetched.get(&s.q.name).ok_or("missing fetched ranges")?.clone();
            let key = self.keys.get(&(s.q.epoch, s.q.zone_pk.to_lowercase())).ok_or("no key")?;
            let wanted: Vec<(usize, usize)> = rows.iter().map(|&r| (int8_row_offset(nb, r), I8_ROW_BYTES)).collect();
            let got = seal::open_ranges(key, SparseReader::new(s.q.size as usize, parts), &wanted)?;
            for (row, bytes) in rows.iter().zip(got) {
                scored.push((dot_i8(q, &bytes), si, *row));
            }
        }
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
        Ok(scored
            .into_iter()
            .take(k)
            .map(|(score, si, row)| {
                let s = &self.shards[si];
                Hit { id: hex::encode(s.bin.id(row)), score, epoch: s.bin.header.epoch, zone_pk: hex::encode(s.bin.header.zone_pk) }
            })
            .collect())
    }

    /// `n` decoy ids drawn deterministically-pseudorandomly from the
    /// resident ids (review H1: hide the hits in a superset), excluding
    /// `exclude`.
    pub fn decoys(&self, n: usize, seed: u64, exclude: &[String]) -> Vec<String> {
        let total = self.rows();
        let mut out = Vec::with_capacity(n);
        if total == 0 {
            return out;
        }
        let mut x = seed | 1;
        let mut guard = 0;
        while out.len() < n && guard < n * 20 {
            guard += 1;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let mut r = (x % total as u64) as usize;
            for s in &self.shards {
                let c = s.bin.header.count as usize;
                if r < c {
                    let id = hex::encode(s.bin.id(r));
                    if !exclude.contains(&id) && !out.contains(&id) {
                        out.push(id);
                    }
                    break;
                }
                r -= c;
            }
        }
        out
    }
}
