//! Sealing index objects with age (v1 format, X25519 recipient, STREAM
//! payload: ChaCha20-Poly1305 in 64 KiB chunks).
//!
//! # Key derivation
//!
//! ```text
//! okm = HKDF-SHA256(salt = "nostr-bbs/sealed-search/v1",
//!                   ikm  = zone epoch secret (32 bytes),
//!                   info = "age-x25519\0" || zone || "\0" || be32(epoch) || zone_pk)
//! ```
//!
//! `okm` is used as an age X25519 identity (the X25519 function clamps it).
//! The domain label separates it from every other use of the zone secret
//! (which is a secp256k1 scalar for NIP-44). The browser's main thread
//! derives `okm` and hands only `okm` to the search worker, which can then
//! open the zone's search index but never its messages.
//!
//! # Random access
//!
//! age's `StreamReader` implements `Seek`: reading one plaintext range
//! decrypts and authenticates only the chunk(s) holding it. [`SparseReader`]
//! lets the caller supply just the age header and those chunks (fetched as
//! blob slices), so a rescore never reads a whole int8 layer.

use std::io::{Read, Seek, SeekFrom, Write};
use std::str::FromStr;

use bech32::{ToBase32, Variant};
use zeroize::Zeroizing;

pub use crate::kdf::SearchKey;
/// age STREAM plaintext chunk size.
pub const CHUNK: usize = 64 * 1024;
/// age STREAM ciphertext chunk size (plaintext + 16-byte tag).
pub const CT_CHUNK: usize = CHUNK + 16;
/// Length of the payload nonce that follows the age header.
const NONCE_LEN: usize = 16;

fn identity(key: &SearchKey) -> age::x25519::Identity {
    let s = Zeroizing::new(
        bech32::encode("age-secret-key-", key.bytes().to_base32(), Variant::Bech32)
            .expect("valid hrp")
            .to_uppercase(),
    );
    age::x25519::Identity::from_str(&s).expect("32-byte bech32 identity")
}

/// The age recipient a search key opens.
pub fn recipient(key: &SearchKey) -> age::x25519::Recipient {
    identity(key).to_public()
}

/// Seal `plain` to the key's recipient (one fresh file key per object).
pub fn seal(key: &SearchKey, plain: &[u8]) -> Result<Vec<u8>, String> {
    let r = recipient(key);
    let enc = age::Encryptor::with_recipients(std::iter::once(&r as &dyn age::Recipient))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(plain.len() + plain.len() / CHUNK * 16 + 256);
    let mut w = enc.wrap_output(&mut out).map_err(|e| e.to_string())?;
    w.write_all(plain).map_err(|e| e.to_string())?;
    w.finish().map_err(|e| e.to_string())?;
    Ok(out)
}

fn decryptor<R: Read>(key: &SearchKey, r: R) -> Result<age::stream::StreamReader<R>, String> {
    let id = identity(key);
    age::Decryptor::new(r)
        .map_err(|e| e.to_string())?
        .decrypt(std::iter::once(&id as &dyn age::Identity))
        .map_err(|e| e.to_string())
}

/// Open a whole sealed object.
pub fn open(key: &SearchKey, sealed: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    decryptor(key, sealed)?.read_to_end(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

/// Byte length of the age header (through the MAC line), parsed from the
/// first bytes of a sealed object. The v1 header ends with `"--- " <MAC> "\n"`.
pub fn header_len(prefix: &[u8]) -> Option<usize> {
    let p = prefix.windows(5).position(|w| w == b"\n--- ")? + 1;
    let nl = prefix[p..].iter().position(|&b| b == b'\n')?;
    Some(p + nl + 1)
}

/// Ciphertext byte range `[start, end)` of payload chunk `i`, given the age
/// header length and the total sealed length (the last chunk is shorter).
pub fn chunk_range(header_len: usize, total: usize, i: usize) -> (usize, usize) {
    let start = header_len + NONCE_LEN + i * CT_CHUNK;
    (start, (start + CT_CHUNK).min(total))
}

/// The ciphertext ranges needed to read plaintext `[off, off + len)`: the
/// header plus nonce, every chunk the range touches, and the **final** chunk
/// (age's `StreamReader` reads it on a forward seek to learn the plaintext
/// length).
pub fn ranges_for(header_len: usize, total: usize, off: usize, len: usize) -> Vec<(usize, usize)> {
    let mut v = vec![(0, header_len + NONCE_LEN)];
    let (a, b) = (off / CHUNK, (off + len.max(1) - 1) / CHUNK);
    for i in a..=b {
        v.push(chunk_range(header_len, total, i));
    }
    let payload = total.saturating_sub(header_len + NONCE_LEN);
    let last = payload.saturating_sub(1) / CT_CHUNK;
    let r = chunk_range(header_len, total, last);
    if !v.contains(&r) {
        v.push(r);
    }
    v
}

/// A `Read + Seek` view of a sealed object of known total length where only
/// some byte ranges are present. Reading a missing byte is an error, so a
/// caller that forgot a chunk fails loudly instead of decrypting garbage.
pub struct SparseReader {
    total: u64,
    parts: Vec<(u64, Vec<u8>)>,
    pos: u64,
}

impl SparseReader {
    /// `parts` are `(offset, bytes)`; `total` is the full sealed length.
    pub fn new(total: usize, mut parts: Vec<(usize, Vec<u8>)>) -> Self {
        parts.sort_by_key(|p| p.0);
        Self { total: total as u64, parts: parts.into_iter().map(|(o, b)| (o as u64, b)).collect(), pos: 0 }
    }
}

impl Read for SparseReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.total || buf.is_empty() {
            return Ok(0);
        }
        for (o, b) in &self.parts {
            let end = o + b.len() as u64;
            if self.pos >= *o && self.pos < end {
                let n = ((end - self.pos) as usize).min(buf.len());
                let s = (self.pos - o) as usize;
                buf[..n].copy_from_slice(&b[s..s + n]);
                self.pos += n as u64;
                return Ok(n);
            }
        }
        Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, format!("byte {} not loaded", self.pos)))
    }
}

impl Seek for SparseReader {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        let p = match to {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.total as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if p < 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek before start"));
        }
        self.pos = p as u64;
        Ok(self.pos)
    }
}

/// Read several plaintext ranges from one sparse sealed object with a single
/// decryptor (one X25519 unwrap), seeking between them.
pub fn open_ranges(key: &SearchKey, src: SparseReader, wanted: &[(usize, usize)]) -> Result<Vec<Vec<u8>>, String> {
    let mut r = decryptor(key, src)?;
    let mut out = Vec::with_capacity(wanted.len());
    for &(off, len) in wanted {
        r.seek(SeekFrom::Start(off as u64)).map_err(|e| e.to_string())?;
        let mut b = vec![0u8; len];
        r.read_exact(&mut b).map_err(|e| e.to_string())?;
        out.push(b);
    }
    Ok(out)
}

/// Read plaintext `[off, off + len)` from a sparse sealed object (each chunk
/// read is authenticated by age).
pub fn open_range(key: &SearchKey, src: SparseReader, off: usize, len: usize) -> Result<Vec<u8>, String> {
    let mut r = decryptor(key, src)?;
    r.seek(SeekFrom::Start(off as u64)).map_err(|e| e.to_string())?;
    let mut out = vec![0u8; len];
    r.read_exact(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(zone: &str, epoch: u32) -> SearchKey {
        SearchKey::derive(&[9u8; 32], zone, epoch, &[1u8; 32])
    }

    #[test]
    fn seal_open_roundtrip_and_wrong_key_fails() {
        let k = key("zone2", 1);
        let plain: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let s = seal(&k, &plain).unwrap();
        assert_eq!(open(&k, &s).unwrap(), plain);
        assert!(open(&key("zone2", 2), &s).is_err());
        assert!(open(&key("zone3", 1), &s).is_err());
        // Tampering anywhere in the payload fails authentication.
        let mut t = s.clone();
        let i = t.len() - 100;
        t[i] ^= 1;
        assert!(open(&k, &t).is_err());
        // Truncation (drop the final chunk) fails.
        let hl = header_len(&s).unwrap();
        let cut = chunk_range(hl, s.len(), 2).0;
        assert!(open(&k, &s[..cut]).is_err());
    }

    #[test]
    fn many_seeks_in_a_large_object_need_only_planned_chunks() {
        // 2 MB object, rows read out of order with one decryptor: the shape
        // of a real rescore (this failed in the browser before the final
        // chunk was planned).
        let k = key("zone2", 1);
        let plain: Vec<u8> = (0..2_000_000u32).map(|i| (i * 13 % 251) as u8).collect();
        let s = seal(&k, &plain).unwrap();
        let hl = header_len(&s).unwrap();
        let wanted = [(1_500_000usize, 388usize), (70_000, 388), (1_999_000, 388), (0, 388), (900_123, 388)];
        let mut parts: Vec<(usize, Vec<u8>)> = Vec::new();
        for &(o, l) in &wanted {
            for (a, b) in ranges_for(hl, s.len(), o, l) {
                if !parts.iter().any(|p| p.0 == a) {
                    parts.push((a, s[a..b].to_vec()));
                }
            }
        }
        let got = open_ranges(&k, SparseReader::new(s.len(), parts), &wanted).unwrap();
        for ((o, l), g) in wanted.iter().zip(got) {
            assert_eq!(g, plain[*o..o + l]);
        }
    }

    #[test]
    fn random_access_reads_only_needed_chunks() {
        let k = key("zone4", 7);
        let plain: Vec<u8> = (0..500_000u32).map(|i| (i * 7 % 253) as u8).collect();
        let s = seal(&k, &plain).unwrap();
        let hl = header_len(&s).unwrap();
        for &(off, len) in &[(0usize, 10usize), (65_530, 20), (300_000, 388), (499_990, 10)] {
            let parts: Vec<(usize, Vec<u8>)> = ranges_for(hl, s.len(), off, len)
                .into_iter()
                .map(|(a, b)| (a, s[a..b].to_vec()))
                .collect();
            let got = open_range(&k, SparseReader::new(s.len(), parts), off, len).unwrap();
            assert_eq!(got, plain[off..off + len]);
        }
        // Missing chunk: loud error, not garbage.
        let parts = vec![(0, s[..hl + 16].to_vec())];
        assert!(open_range(&k, SparseReader::new(s.len(), parts), 300_000, 10).is_err());
        // A tampered chunk read by random access fails too.
        let (a, b) = chunk_range(hl, s.len(), 4);
        let mut bad = s[a..b].to_vec();
        bad[10] ^= 1;
        let parts = vec![(0, s[..hl + 16].to_vec()), (a, bad)];
        assert!(open_range(&k, SparseReader::new(s.len(), parts), 4 * CHUNK + 5, 10).is_err());
    }
}
