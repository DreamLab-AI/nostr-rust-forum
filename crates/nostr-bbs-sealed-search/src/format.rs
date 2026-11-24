//! Plaintext layout of sealed index objects.
//!
//! Every object's plaintext (authenticated by age) starts with a header that
//! binds it to its zone, epoch, shard, index version and kind; the client
//! checks it against the signed manifest before using a single row.
//!
//! ```text
//! "NBSS" | u16 version=1 | u8 kind (1=bin, 2=int8) | u8 scope (1=base, 2=author)
//! u8 zone_len | zone | u32 epoch | 32-byte zone_pk | u32 shard | u64 index_version | u32 count | u16 dim
//! [scope=author: 32-byte author pubkey]
//! ```
//!
//! - **bin** body: `count × 32-byte event id`, then `count × 48-byte sign code`.
//! - **int8** body: `count × [f32 scale][384 × i8]` (row `r` at a fixed offset,
//!   so a reader decrypts only the age chunk holding it).
//!
//! All integers little-endian.

use crate::model::DIM;
use crate::quant::{CODE_BYTES, I8_ROW_BYTES};

const MAGIC: &[u8; 4] = b"NBSS";
/// Most rows one object may declare (checked before any allocation).
pub const MAX_ROWS: usize = 32_768;
/// Format version.
pub const VERSION: u16 = 1;

/// Object kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Ids + sign codes (resident in the worker).
    Bin = 1,
    /// int8 rescoring rows (read by chunk).
    Int8 = 2,
}

/// Who may publish the object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Base index (admin or archivist).
    Base,
    /// Per-author update shard (Phase 2): rows for that author's own events.
    Author([u8; 32]),
}

/// The authenticated object header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Object kind.
    pub kind: Kind,
    /// Base or author scope.
    pub scope: Scope,
    /// Zone id (e.g. `zone2`).
    pub zone: String,
    /// Zone key epoch the object is sealed under.
    pub epoch: u32,
    /// x-only public key of that epoch's zone key (review M3).
    pub zone_pk: [u8; 32],
    /// Shard number within (zone, epoch).
    pub shard: u32,
    /// Index version (monotonic per zone).
    pub index_version: u64,
    /// Rows.
    pub count: u32,
}

impl Header {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(64);
        o.extend_from_slice(MAGIC);
        o.extend_from_slice(&VERSION.to_le_bytes());
        o.push(self.kind as u8);
        o.push(match self.scope {
            Scope::Base => 1,
            Scope::Author(_) => 2,
        });
        let z = self.zone.as_bytes();
        o.push(z.len() as u8);
        o.extend_from_slice(z);
        o.extend_from_slice(&self.epoch.to_le_bytes());
        o.extend_from_slice(&self.zone_pk);
        o.extend_from_slice(&self.shard.to_le_bytes());
        o.extend_from_slice(&self.index_version.to_le_bytes());
        o.extend_from_slice(&self.count.to_le_bytes());
        o.extend_from_slice(&(DIM as u16).to_le_bytes());
        if let Scope::Author(pk) = self.scope {
            o.extend_from_slice(&pk);
        }
        o
    }

    /// Decode; returns the header and its byte length.
    pub fn decode(b: &[u8]) -> Result<(Self, usize), String> {
        let take = |o: usize, n: usize| b.get(o..o + n).ok_or("truncated header");
        if take(0, 4)? != MAGIC {
            return Err("bad magic".into());
        }
        if u16::from_le_bytes(take(4, 2)?.try_into().unwrap()) != VERSION {
            return Err("unsupported version".into());
        }
        let kind = match take(6, 1)?[0] {
            1 => Kind::Bin,
            2 => Kind::Int8,
            _ => return Err("bad kind".into()),
        };
        let scope_b = take(7, 1)?[0];
        let zl = take(8, 1)?[0] as usize;
        let zone = std::str::from_utf8(take(9, zl)?).map_err(|_| "bad zone")?.to_string();
        let mut o = 9 + zl;
        let u32_at = |o: usize| -> Result<u32, String> { Ok(u32::from_le_bytes(take(o, 4)?.try_into().unwrap())) };
        let epoch = u32_at(o)?;
        let zone_pk: [u8; 32] = take(o + 4, 32)?.try_into().unwrap();
        o += 36;
        let shard = u32_at(o)?;
        let index_version = u64::from_le_bytes(take(o + 4, 8)?.try_into().unwrap());
        let count = u32_at(o + 12)?;
        let dim = u16::from_le_bytes(take(o + 16, 2)?.try_into().unwrap());
        o += 18;
        if count as usize > MAX_ROWS {
            return Err("row count over the shard cap".into());
        }
        if dim as usize != DIM {
            return Err("bad dim".into());
        }
        let scope = match scope_b {
            1 => Scope::Base,
            2 => {
                let pk: [u8; 32] = take(o, 32)?.try_into().unwrap();
                o += 32;
                Scope::Author(pk)
            }
            _ => return Err("bad scope".into()),
        };
        Ok((Self { kind, scope, zone, epoch, zone_pk, shard, index_version, count }, o))
    }

    /// Body length the header implies.
    pub fn body_len(&self) -> usize {
        let n = self.count as usize;
        match self.kind {
            Kind::Bin => n * (32 + CODE_BYTES),
            Kind::Int8 => n * I8_ROW_BYTES,
        }
    }
}

/// Plaintext of a bin object.
pub fn encode_bin(h: &Header, ids: &[[u8; 32]], codes: &[[u8; CODE_BYTES]]) -> Vec<u8> {
    debug_assert!(h.kind == Kind::Bin && ids.len() == codes.len() && ids.len() == h.count as usize);
    let mut o = h.encode();
    for id in ids {
        o.extend_from_slice(id);
    }
    for c in codes {
        o.extend_from_slice(c);
    }
    o
}

/// Plaintext of an int8 object.
pub fn encode_int8(h: &Header, rows: &[[u8; I8_ROW_BYTES]]) -> Vec<u8> {
    debug_assert!(h.kind == Kind::Int8 && rows.len() == h.count as usize);
    let mut o = h.encode();
    for r in rows {
        o.extend_from_slice(r);
    }
    o
}

/// A decoded, resident bin layer.
#[derive(Debug, Clone)]
pub struct BinLayer {
    /// Header.
    pub header: Header,
    /// `count × 32` id bytes.
    pub ids: Vec<u8>,
    /// `count × 48` code bytes.
    pub codes: Vec<u8>,
}

impl BinLayer {
    /// Parse a bin object's plaintext.
    pub fn parse(plain: &[u8]) -> Result<Self, String> {
        let (header, off) = Header::decode(plain)?;
        if header.kind != Kind::Bin {
            return Err("not a bin object".into());
        }
        let n = header.count as usize;
        if plain.len() != off + header.body_len() {
            return Err("bin length mismatch".into());
        }
        let ids = plain[off..off + n * 32].to_vec();
        let codes = plain[off + n * 32..].to_vec();
        Ok(Self { header, ids, codes })
    }

    /// Id of row `r`.
    pub fn id(&self, r: usize) -> [u8; 32] {
        self.ids[r * 32..r * 32 + 32].try_into().unwrap()
    }

    /// Code of row `r`.
    pub fn code(&self, r: usize) -> &[u8] {
        &self.codes[r * CODE_BYTES..(r + 1) * CODE_BYTES]
    }
}

/// Plaintext byte offset of int8 row `r` in an object whose header encodes to
/// `header_len` bytes.
pub fn int8_row_offset(header_len: usize, r: usize) -> usize {
    header_len + r * I8_ROW_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip_both_scopes() {
        for scope in [Scope::Base, Scope::Author([7u8; 32])] {
            let h = Header { kind: Kind::Int8, scope, zone: "zone2".into(), epoch: 3, zone_pk: [5u8; 32], shard: 9, index_version: 42, count: 5 };
            let b = h.encode();
            let (d, n) = Header::decode(&b).unwrap();
            assert_eq!(d, h);
            assert_eq!(n, b.len());
        }
        assert!(Header::decode(b"NBSX").is_err());
        assert!(Header::decode(&[]).is_err());
    }

    #[test]
    fn bin_layer_roundtrip_and_length_check() {
        let h = Header { kind: Kind::Bin, scope: Scope::Base, zone: "z".into(), epoch: 1, zone_pk: [5u8; 32], shard: 0, index_version: 1, count: 2 };
        let p = encode_bin(&h, &[[1u8; 32], [2u8; 32]], &[[3u8; CODE_BYTES], [4u8; CODE_BYTES]]);
        let l = BinLayer::parse(&p).unwrap();
        assert_eq!(l.id(1), [2u8; 32]);
        assert_eq!(l.code(0), &[3u8; CODE_BYTES]);
        assert!(BinLayer::parse(&p[..p.len() - 1]).is_err());
    }
}
