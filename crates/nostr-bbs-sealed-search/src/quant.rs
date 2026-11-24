//! Quantisation shared by the sealed index: 48-byte sign codes scored
//! asymmetrically through a per-query lookup table (first stage), and int8
//! rows with a per-row scale (exact-enough rescoring).
//!
//! Same sign-code convention and lookup-table scorer as the search worker's
//! RVF v2 index (`nostr-bbs-search-worker/src/shard.rs`).

use crate::DIM;

/// Bytes per sign code.
pub const CODE_BYTES: usize = DIM / 8;
/// Bytes per int8 row: f32 scale + 384 × i8.
pub const I8_ROW_BYTES: usize = 4 + DIM;

/// Sign code: bit `b` of byte `j` set when component `8j+b` is > 0.
pub fn sign_code(v: &[f32; DIM]) -> [u8; CODE_BYTES] {
    let mut c = [0u8; CODE_BYTES];
    for (i, x) in v.iter().enumerate() {
        if *x > 0.0 {
            c[i / 8] |= 1 << (i % 8);
        }
    }
    c
}

/// Per-query lookup table: `T[j][b]` = Σ over the 8 dims of byte `j` of `+q`
/// where bit set, `-q` where clear. Scoring a code is 48 table reads.
pub struct QueryLut(Vec<f32>);

impl QueryLut {
    /// Build for a query vector.
    pub fn new(q: &[f32; DIM]) -> Self {
        let mut t = vec![0f32; CODE_BYTES * 256];
        for j in 0..CODE_BYTES {
            for b in 0..256usize {
                let mut s = 0f32;
                for k in 0..8 {
                    let qi = q[j * 8 + k];
                    s += if b >> k & 1 == 1 { qi } else { -qi };
                }
                t[j * 256 + b] = s;
            }
        }
        Self(t)
    }

    /// Approximate score of one code (higher = closer).
    #[inline]
    pub fn score(&self, code: &[u8]) -> f32 {
        code.iter().take(CODE_BYTES).enumerate().map(|(j, &b)| self.0[j * 256 + b as usize]).sum()
    }
}

/// Encode a unit vector as an int8 row: `[scale f32 LE][384 × i8]`, with
/// `x ≈ i8 * scale / 127` and `scale = max |x|`.
pub fn encode_i8(v: &[f32; DIM]) -> [u8; I8_ROW_BYTES] {
    let scale = v.iter().fold(0f32, |m, x| m.max(x.abs())).max(1e-12);
    let mut out = [0u8; I8_ROW_BYTES];
    out[..4].copy_from_slice(&scale.to_le_bytes());
    for (i, x) in v.iter().enumerate() {
        out[4 + i] = ((x / scale * 127.0).round().clamp(-127.0, 127.0) as i8) as u8;
    }
    out
}

/// Approximate dot product of a query with an int8 row.
pub fn dot_i8(q: &[f32; DIM], row: &[u8]) -> f32 {
    let scale = f32::from_le_bytes([row[0], row[1], row[2], row[3]]);
    let mut s = 0f32;
    for (i, qi) in q.iter().enumerate() {
        s += qi * f32::from(row[4 + i] as i8);
    }
    s * scale / 127.0
}

/// A first-stage candidate: `(shard, row, score)`.
pub type Candidate = (usize, usize, f32);

fn cand_cmp(a: &Candidate, b: &Candidate) -> std::cmp::Ordering {
    b.2.partial_cmp(&a.2)
        .unwrap_or(std::cmp::Ordering::Equal)
        .then(a.0.cmp(&b.0))
        .then(a.1.cmp(&b.1))
}

/// Best `r` candidates from an iterator, O(r) memory, deterministic order
/// (score desc, then shard, then row).
pub fn top_r(it: impl Iterator<Item = Candidate>, r: usize) -> Vec<Candidate> {
    if r == 0 {
        return Vec::new();
    }
    let cap = r.saturating_mul(4).max(64);
    let mut v: Vec<Candidate> = Vec::with_capacity(cap);
    let cut = |v: &mut Vec<Candidate>| {
        if v.len() > r {
            v.select_nth_unstable_by(r - 1, cand_cmp);
            v.truncate(r);
        }
    };
    for c in it {
        v.push(c);
        if v.len() == cap {
            cut(&mut v);
        }
    }
    cut(&mut v);
    v.sort_unstable_by(cand_cmp);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(seed: u64) -> [f32; DIM] {
        let mut x = seed;
        let mut v = [0f32; DIM];
        for s in v.iter_mut() {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *s = ((x >> 33) as f32 / (1u64 << 31) as f32) - 0.5;
        }
        let n = v.iter().map(|a| a * a).sum::<f32>().sqrt();
        v.iter_mut().for_each(|a| *a /= n);
        v
    }

    #[test]
    fn lut_equals_direct_score() {
        let q = unit(1);
        let lut = QueryLut::new(&q);
        for s in 2..30 {
            let c = sign_code(&unit(s));
            let d: f32 = (0..DIM).map(|i| if c[i / 8] >> (i % 8) & 1 == 1 { q[i] } else { -q[i] }).sum();
            assert!((lut.score(&c) - d).abs() < 1e-4);
        }
    }

    #[test]
    fn int8_dot_is_close_to_f32() {
        for s in 0..50 {
            let (a, b) = (unit(s), unit(s + 1000));
            let exact: f32 = a.iter().zip(&b).map(|(x, y)| x * y).sum();
            assert!((dot_i8(&a, &encode_i8(&b)) - exact).abs() < 0.01);
        }
    }

    #[test]
    fn top_r_matches_full_sort() {
        let all: Vec<Candidate> = (0..5000).map(|i| (i % 7, i, ((i * 7919) % 10007) as f32)).collect();
        let mut full = all.clone();
        full.sort_by(cand_cmp);
        for r in [1, 10, 80, 999, 6000] {
            assert_eq!(top_r(all.iter().copied(), r), full.iter().take(r).copied().collect::<Vec<_>>());
        }
    }
}
