//! Building sealed index versions from embedded rows (used by the builder):
//!
//! - [`build`]: a whole index, every object at one version (a base);
//! - [`update`]: seal only new rows into additional shards and list every
//!   earlier object unchanged (same name, bytes and hash), so a browser that
//!   has them cached downloads only the new ones (manifest v2);
//! - [`compact`]: re-pack chosen shard pairs (rows opened with
//!   [`open_pair`]) into fresh shards, dropping rows no longer wanted, without
//!   re-embedding: sign codes and int8 rows are carried verbatim.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::format::{encode_bin, encode_int8, parse_int8, BinLayer, Header, Kind, Scope, MAX_ROWS};
use crate::manifest::{object_name, Content, ObjectRef, V1, V2};
use crate::quant::{encode_i8, sign_code, CODE_BYTES, I8_ROW_BYTES};
use crate::seal::{open, seal, SearchKey};
use crate::search::{check_header, check_sealed, sha256_hex};
use crate::DIM;

/// One document to index.
#[derive(Clone)]
pub struct DocRow {
    /// Event id the client resolves a hit to: a live post's own id, or a
    /// sealed original's ORIGINAL id (the envelope's `sealed` tag value).
    pub id: [u8; 32],
    /// Zone key epoch the event is encrypted under.
    pub epoch: u32,
    /// That epoch's x-only zone key pubkey.
    pub zone_pk: [u8; 32],
    /// FP32 unit embedding.
    pub vec: [f32; DIM],
}

/// A built (sealed) index version.
pub struct Built {
    /// Manifest content (to sign and publish as `m.json`).
    pub content: Content,
    /// `(object name, sealed bytes)` of the objects this version adds (an
    /// update or compaction lists earlier objects without re-sealing them).
    pub objects: Vec<(String, Vec<u8>)>,
}

/// Keys by `(epoch, zone_pk)`.
pub type KeyMap = HashMap<(u32, [u8; 32]), SearchKey>;

/// What to build.
pub struct BuildSpec<'a> {
    /// Zone id.
    pub zone: &'a str,
    /// Index version (strictly increasing per zone).
    pub version: u64,
    /// Model label.
    pub model: &'a str,
    /// Hex SHA-256 of the browser's Q8 GGUF.
    pub model_sha256: &'a str,
    /// Hex SHA-256 of `vocab.txt`.
    pub vocab_sha256: &'a str,
    /// Rows per shard (clamped to 1..=32768).
    pub shard_rows: usize,
}

/// The verified manifest an update or compaction starts from.
#[derive(Clone, Copy)]
pub struct Previous<'a> {
    /// Its content.
    pub content: &'a Content,
    /// Hex pubkey of its signer (the pod of objects without an `owner`).
    pub signer: &'a str,
}

/// The rows of one opened shard pair (or of new rows, quantised), in row
/// order: ids, sign codes and int8 rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairRows {
    /// Zone key epoch.
    pub epoch: u32,
    /// That epoch's x-only zone key pubkey.
    pub zone_pk: [u8; 32],
    /// Event ids.
    pub ids: Vec<[u8; 32]>,
    /// Sign codes.
    pub codes: Vec<[u8; CODE_BYTES]>,
    /// int8 rescoring rows.
    pub rows: Vec<[u8; I8_ROW_BYTES]>,
}

/// Sealed objects and manifest entries produced for some shards.
#[derive(Default)]
struct Sealed {
    refs: Vec<ObjectRef>,
    objects: Vec<(String, Vec<u8>)>,
}

/// Seal `rows` (one `(epoch, zone_pk)` group) into shard pairs numbered from
/// `first_shard`, at `version`, under `key`.
#[allow(clippy::too_many_arguments)]
fn seal_group(
    zone: &str,
    version: u64,
    rows: &PairRows,
    first_shard: u32,
    shard_rows: usize,
    key: &SearchKey,
    out: &mut Sealed,
) -> Result<(), String> {
    let (epoch, zone_pk) = (rows.epoch, rows.zone_pk);
    for (i, start) in (0..rows.ids.len()).step_by(shard_rows).enumerate() {
        let end = (start + shard_rows).min(rows.ids.len());
        let shard = first_shard
            .checked_add(u32::try_from(i).map_err(|_| "too many shards")?)
            .ok_or("shard number overflow")?;
        let count = (end - start) as u32;
        let head = |kind| Header {
            kind,
            scope: Scope::Base,
            zone: zone.into(),
            epoch,
            zone_pk,
            shard,
            index_version: version,
            count,
        };
        for (kind, plain) in [
            (
                Kind::Bin,
                encode_bin(
                    &head(Kind::Bin),
                    &rows.ids[start..end],
                    &rows.codes[start..end],
                ),
            ),
            (
                Kind::Int8,
                encode_int8(&head(Kind::Int8), &rows.rows[start..end]),
            ),
        ] {
            let sealed = seal(key, &plain)?;
            let name = object_name(kind, epoch, shard, version);
            out.refs.push(ObjectRef {
                name: name.clone(),
                kind,
                epoch,
                zone_pk: hex::encode(zone_pk),
                shard,
                count,
                size: sealed.len() as u64,
                sha256: sha256_hex(&sealed),
                owner: None,
                version: None,
            });
            out.objects.push((name, sealed));
        }
    }
    Ok(())
}

/// Quantise embedded rows, grouped by their own `(epoch, zone_pk)` (review
/// M4: a row is only ever sealed under its own epoch's key), in input order.
fn quantise(rows: &[DocRow]) -> BTreeMap<(u32, [u8; 32]), PairRows> {
    let mut groups: BTreeMap<(u32, [u8; 32]), PairRows> = BTreeMap::new();
    for r in rows {
        let g = groups
            .entry((r.epoch, r.zone_pk))
            .or_insert_with(|| PairRows {
                epoch: r.epoch,
                zone_pk: r.zone_pk,
                ids: Vec::new(),
                codes: Vec::new(),
                rows: Vec::new(),
            });
        g.ids.push(r.id);
        g.codes.push(sign_code(&r.vec));
        g.rows.push(encode_i8(&r.vec));
    }
    groups
}

fn key_for<'k>(keys: &'k KeyMap, epoch: u32, zone_pk: &[u8; 32]) -> Result<&'k SearchKey, String> {
    keys.get(&(epoch, *zone_pk))
        .ok_or_else(|| format!("no key for epoch {epoch}"))
}

fn content(
    spec: &BuildSpec<'_>,
    v: u32,
    objects: Vec<ObjectRef>,
    excluded: Vec<String>,
) -> Content {
    Content {
        v,
        zone: spec.zone.into(),
        index_version: spec.version,
        dim: DIM as u32,
        model: spec.model.into(),
        model_sha256: spec.model_sha256.into(),
        vocab_sha256: spec.vocab_sha256.into(),
        objects,
        excluded,
    }
}

/// Build a whole index version (every object at `spec.version`, shards
/// numbered from 0 per epoch). The content is v1; a publisher that must keep
/// older browsers off its manifests sets `v` to [`V2`] before signing (a v1
/// content is a valid v2 content).
pub fn build(spec: &BuildSpec<'_>, rows: &[DocRow], keys: &KeyMap) -> Result<Built, String> {
    let shard_rows = spec.shard_rows.clamp(1, MAX_ROWS);
    let mut out = Sealed::default();
    for ((epoch, zone_pk), g) in quantise(rows) {
        let key = key_for(keys, epoch, &zone_pk)?;
        seal_group(spec.zone, spec.version, &g, 0, shard_rows, key, &mut out)?;
    }
    Ok(Built {
        content: content(spec, V1, out.refs, Vec::new()),
        objects: out.objects,
    })
}

/// An earlier object listed unchanged in a newer version signed by `signer`:
/// same name, kind, slot, size and hash, with its `owner` (when not `signer`)
/// and the `version` its header was built at made explicit.
fn carry(o: &ObjectRef, prev: Previous<'_>, signer: &str, version: u64) -> ObjectRef {
    let owner = o.owner_or(prev.signer).to_lowercase();
    let built_at = o.effective_version(prev.content);
    ObjectRef {
        owner: (!owner.eq_ignore_ascii_case(signer)).then_some(owner),
        version: (built_at != version).then_some(built_at),
        ..o.clone()
    }
}

/// Next free shard number per `(epoch, lowercase zone_pk)` in `objects`.
fn next_shards<'a>(
    objects: impl IntoIterator<Item = &'a ObjectRef>,
) -> HashMap<(u32, String), u32> {
    let mut next: HashMap<(u32, String), u32> = HashMap::new();
    for o in objects {
        let n = next.entry((o.epoch, o.zone_pk.to_lowercase())).or_insert(0);
        *n = (*n).max(o.shard.saturating_add(1));
    }
    next
}

fn check_newer(spec: &BuildSpec<'_>, prev: Previous<'_>) -> Result<(), String> {
    if spec.version <= prev.content.index_version {
        return Err(format!(
            "version {} is not above the previous {}",
            spec.version, prev.content.index_version
        ));
    }
    if spec.zone != prev.content.zone {
        return Err("previous manifest is for another zone".into());
    }
    Ok(())
}

/// An incremental update: seal only `rows` (new posts) into additional
/// shards, numbered after each epoch's highest existing shard, and list every
/// object of `prev` unchanged. `exclude` adds ids (deleted or superseded posts
/// already in `prev`'s objects) to the manifest's exclusion list. The content
/// is v2, signed by `signer`.
pub fn update(
    spec: &BuildSpec<'_>,
    prev: Previous<'_>,
    signer: &str,
    rows: &[DocRow],
    exclude: &[String],
    keys: &KeyMap,
) -> Result<Built, String> {
    check_newer(spec, prev)?;
    let shard_rows = spec.shard_rows.clamp(1, MAX_ROWS);
    let mut objects: Vec<ObjectRef> = prev
        .content
        .objects
        .iter()
        .map(|o| carry(o, prev, signer, spec.version))
        .collect();
    let next = next_shards(&prev.content.objects);
    let mut out = Sealed::default();
    for ((epoch, zone_pk), g) in quantise(rows) {
        let key = key_for(keys, epoch, &zone_pk)?;
        let first = next
            .get(&(epoch, hex::encode(zone_pk)))
            .copied()
            .unwrap_or(0);
        seal_group(
            spec.zone,
            spec.version,
            &g,
            first,
            shard_rows,
            key,
            &mut out,
        )?;
    }
    objects.extend(out.refs);
    let excluded: BTreeSet<String> = prev
        .content
        .excluded
        .iter()
        .cloned()
        .chain(exclude.iter().map(|e| e.to_lowercase()))
        .collect();
    Ok(Built {
        content: content(spec, V2, objects, excluded.into_iter().collect()),
        objects: out.objects,
    })
}

/// The int8 partner of a bin object in `content`.
pub fn q_partner<'c>(content: &'c Content, bin: &ObjectRef) -> Option<&'c ObjectRef> {
    content.objects.iter().find(|o| {
        o.kind == Kind::Int8
            && o.epoch == bin.epoch
            && o.shard == bin.shard
            && o.zone_pk.eq_ignore_ascii_case(&bin.zone_pk)
    })
}

/// Open one shard pair of `content` (both objects whole), checking each
/// against its manifest entry (size, hash, single X25519 stanza) and its
/// authenticated header, and return its rows.
pub fn open_pair(
    content: &Content,
    bin: &ObjectRef,
    bin_sealed: &[u8],
    q: &ObjectRef,
    q_sealed: &[u8],
    key: &SearchKey,
) -> Result<PairRows, String> {
    if bin.kind != Kind::Bin || q.kind != Kind::Int8 {
        return Err("not a bin + int8 pair".into());
    }
    check_sealed(
        bin,
        bin_sealed,
        bin_sealed.len(),
        Some(&sha256_hex(bin_sealed)),
    )?;
    check_sealed(q, q_sealed, q_sealed.len(), Some(&sha256_hex(q_sealed)))?;
    let layer = BinLayer::parse(&open(key, bin_sealed)?)?;
    check_header(&layer.header, bin, content)?;
    let (qh, rows) = parse_int8(&open(key, q_sealed)?)?;
    check_header(&qh, q, content)?;
    if qh.shard != layer.header.shard || qh.count != layer.header.count {
        return Err(format!("{} and {} are not one shard", bin.name, q.name));
    }
    let n = layer.header.count as usize;
    Ok(PairRows {
        epoch: layer.header.epoch,
        zone_pk: layer.header.zone_pk,
        ids: (0..n).map(|r| layer.id(r)).collect(),
        codes: (0..n)
            .map(|r| <[u8; CODE_BYTES]>::try_from(layer.code(r)).expect("code width"))
            .collect(),
        rows,
    })
}

/// A compaction: replace the shard pairs whose bin objects are named in
/// `fold` by fresh shards holding their rows (from [`open_pair`], in
/// `opened`) minus the ids in `dropped`, and list every other object of
/// `prev` unchanged. Dropped ids leave the exclusion list (they are gone);
/// the rest of it stays. Rows are re-packed verbatim, so no embedding is
/// needed. The content is v2, signed by `signer`.
pub fn compact(
    spec: &BuildSpec<'_>,
    prev: Previous<'_>,
    signer: &str,
    fold: &[String],
    opened: &[PairRows],
    dropped: &HashSet<String>,
    keys: &KeyMap,
) -> Result<Built, String> {
    check_newer(spec, prev)?;
    let shard_rows = spec.shard_rows.clamp(1, MAX_ROWS);
    let folded_slots: HashSet<(u32, String, u32)> = prev
        .content
        .objects
        .iter()
        .filter(|o| o.kind == Kind::Bin && fold.contains(&o.name))
        .map(|o| (o.epoch, o.zone_pk.to_lowercase(), o.shard))
        .collect();
    if folded_slots.len() != fold.len() {
        return Err("a folded object is not a bin object of the previous manifest".into());
    }
    let kept: Vec<&ObjectRef> = prev
        .content
        .objects
        .iter()
        .filter(|o| !folded_slots.contains(&(o.epoch, o.zone_pk.to_lowercase(), o.shard)))
        .collect();
    let mut objects: Vec<ObjectRef> = kept
        .iter()
        .map(|o| carry(o, prev, signer, spec.version))
        .collect();
    // New shards are numbered after every shard of the previous version, so
    // no name or slot of a folded pair is reused.
    let next = next_shards(&prev.content.objects);
    let mut merged: BTreeMap<(u32, [u8; 32]), PairRows> = BTreeMap::new();
    for p in opened {
        let g = merged
            .entry((p.epoch, p.zone_pk))
            .or_insert_with(|| PairRows {
                epoch: p.epoch,
                zone_pk: p.zone_pk,
                ids: Vec::new(),
                codes: Vec::new(),
                rows: Vec::new(),
            });
        for i in 0..p.ids.len() {
            if !dropped.contains(&hex::encode(p.ids[i])) {
                g.ids.push(p.ids[i]);
                g.codes.push(p.codes[i]);
                g.rows.push(p.rows[i]);
            }
        }
    }
    let mut out = Sealed::default();
    for ((epoch, zone_pk), g) in merged {
        if g.ids.is_empty() {
            continue;
        }
        let key = key_for(keys, epoch, &zone_pk)?;
        let first = next
            .get(&(epoch, hex::encode(zone_pk)))
            .copied()
            .unwrap_or(0);
        seal_group(
            spec.zone,
            spec.version,
            &g,
            first,
            shard_rows,
            key,
            &mut out,
        )?;
    }
    objects.extend(out.refs);
    let excluded: Vec<String> = prev
        .content
        .excluded
        .iter()
        .filter(|e| !dropped.contains(*e))
        .cloned()
        .collect();
    Ok(Built {
        content: content(spec, V2, objects, excluded),
        objects: out.objects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::{Fetched, Index};

    fn unit(seed: u64) -> [f32; DIM] {
        let mut x = seed.wrapping_add(17);
        let mut v = [0f32; DIM];
        for s in v.iter_mut() {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *s = ((x >> 33) as f32 / (1u64 << 31) as f32) - 0.5;
        }
        let n = v.iter().map(|a| a * a).sum::<f32>().sqrt();
        v.iter_mut().for_each(|a| *a /= n);
        v
    }

    fn spec(zone: &str) -> BuildSpec<'_> {
        BuildSpec {
            zone,
            version: 3,
            model: "bge",
            model_sha256: "m",
            vocab_sha256: "v",
            shard_rows: 400,
        }
    }

    fn setup(n: usize) -> (Vec<DocRow>, KeyMap, Built) {
        let pk1 = [1u8; 32];
        let pk2 = [2u8; 32];
        let rows: Vec<DocRow> = (0..n)
            .map(|i| {
                let mut id = [0u8; 32];
                id[..8].copy_from_slice(&(i as u64).to_be_bytes());
                DocRow {
                    id,
                    epoch: if i % 3 == 0 { 2 } else { 1 },
                    zone_pk: if i % 3 == 0 { pk2 } else { pk1 },
                    vec: unit(i as u64),
                }
            })
            .collect();
        let mut keys = HashMap::new();
        keys.insert((1, pk1), SearchKey::derive(&[7; 32], "zone2", 1, &pk1));
        keys.insert((2, pk2), SearchKey::derive(&[8; 32], "zone2", 2, &pk2));
        let built = build(&spec("zone2"), &rows, &keys).unwrap();
        (rows, keys, built)
    }

    fn index_from(built: &Built, keys: &KeyMap) -> Index {
        let k2: HashMap<(u32, String), SearchKey> = keys
            .iter()
            .map(|((e, pk), k)| ((*e, hex::encode(pk)), k.clone()))
            .collect();
        let mut ix = Index::new(built.content.clone(), k2);
        let objs: HashMap<&str, &Vec<u8>> =
            built.objects.iter().map(|(n, b)| (n.as_str(), b)).collect();
        for o in ix.wanted_bins() {
            ix.add_bin(&o, objs[o.name.as_str()]).unwrap();
        }
        for q in ix.q_needing_prefix() {
            let b = objs[q.name.as_str()];
            ix.set_q_prefix(&q.name, &b[..b.len().min(70_000)], b.len())
                .unwrap();
        }
        ix
    }

    #[test]
    fn end_to_end_search_matches_exact_and_rejects_substitution() {
        let (rows, keys, built) = setup(1500);
        assert_eq!(built.objects.len(), 2 * (3 + 2)); // epoch1: 1000 rows → 3 shards, epoch2: 500 → 2
        let ix = index_from(&built, &keys);
        assert_eq!(ix.rows(), 1500);
        let objs: HashMap<&str, &Vec<u8>> =
            built.objects.iter().map(|(n, b)| (n.as_str(), b)).collect();
        for qi in [3usize, 100, 777, 1499] {
            let q = rows[qi].vec;
            let cands = ix.first_stage(&q, 1500);
            let plan = ix.plan_rescore(&cands).unwrap();
            let fetched: Fetched = plan
                .iter()
                .map(|p| {
                    (
                        p.name.clone(),
                        p.ranges
                            .iter()
                            .map(|&(a, b)| (a, objs[p.name.as_str()][a..b].to_vec()))
                            .collect(),
                    )
                })
                .collect();
            let hits = ix.rescore(&q, &cands, &fetched, 5).unwrap();
            assert_eq!(hits[0].id, hex::encode(rows[qi].id), "self is the top hit");
            assert_eq!(hits[0].epoch, rows[qi].epoch);
            assert!((hits[0].score - 1.0).abs() < 0.01);
        }
        // A member without epoch 2's key sees only epoch-1 shards.
        let mut k1 = keys.clone();
        k1.remove(&(2, [2u8; 32]));
        let k1s: HashMap<(u32, String), SearchKey> = k1
            .iter()
            .map(|((e, pk), k)| ((*e, hex::encode(pk)), k.clone()))
            .collect();
        assert!(Index::new(built.content.clone(), k1s)
            .wanted_bins()
            .iter()
            .all(|o| o.epoch == 1));
        // Substitution: a shard served under another shard's manifest entry fails.
        let k2: HashMap<(u32, String), SearchKey> = keys
            .iter()
            .map(|((e, pk), k)| ((*e, hex::encode(pk)), k.clone()))
            .collect();
        let mut ix2 = Index::new(built.content.clone(), k2.clone());
        let bins: Vec<ObjectRef> = ix2.wanted_bins();
        let mut swapped = bins[0].clone();
        swapped.size = objs[bins[1].name.as_str()].len() as u64;
        swapped.sha256 = sha256_hex(objs[bins[1].name.as_str()]);
        assert!(
            ix2.add_bin(&swapped, objs[bins[1].name.as_str()]).is_err(),
            "header must bind shard"
        );
        // An object sealed for zone3 (same secret!) never opens as zone2.
        let zone3_keys: KeyMap = HashMap::from([(
            (1, [1u8; 32]),
            SearchKey::derive(&[7; 32], "zone3", 1, &[1u8; 32]),
        )]);
        let other = build(&spec("zone3"), &rows[1..2], &zone3_keys).unwrap();
        let (oname, obytes) = &other.objects[0];
        let mut fake = bins[0].clone();
        fake.size = obytes.len() as u64;
        fake.sha256 = sha256_hex(obytes);
        let _ = oname;
        assert!(Index::new(built.content.clone(), k2)
            .add_bin(&fake, obytes)
            .is_err());
        // Tampered bytes: hash check.
        let mut t = objs[bins[0].name.as_str()].to_vec();
        let l = t.len();
        t[l - 5] ^= 1;
        assert!(ix2.add_bin(&bins[0], &t).is_err());
    }

    fn string_keys(keys: &KeyMap) -> HashMap<(u32, String), SearchKey> {
        keys.iter()
            .map(|((e, pk), k)| ((*e, hex::encode(pk)), k.clone()))
            .collect()
    }

    fn top_hits(ix: &Index, objs: &HashMap<&str, &Vec<u8>>, q: &[f32; DIM]) -> Vec<String> {
        let cands = ix.first_stage(q, 200);
        let plan = ix.plan_rescore(&cands).unwrap();
        let fetched: Fetched = plan
            .iter()
            .map(|p| {
                (
                    p.name.clone(),
                    p.ranges
                        .iter()
                        .map(|&(a, b)| (a, objs[p.name.as_str()][a..b].to_vec()))
                        .collect(),
                )
            })
            .collect();
        ix.rescore(q, &cands, &fetched, 3)
            .unwrap()
            .into_iter()
            .map(|h| h.id)
            .collect()
    }

    #[test]
    fn shards_added_one_at_a_time_answer_from_what_is_loaded() {
        let (rows, keys, built) = setup(1500);
        let objs: HashMap<&str, &Vec<u8>> =
            built.objects.iter().map(|(n, b)| (n.as_str(), b)).collect();
        let mut ix = Index::new(built.content.clone(), string_keys(&keys));
        let bins = ix.wanted_bins();
        assert_eq!(bins.len(), 5);
        assert!(!ix.is_complete());

        // One shard in: its own rows are found, others are simply absent.
        let q0 = ix.add_shard(&bins[0], objs[bins[0].name.as_str()], &[], 0);
        assert!(
            q0.is_err(),
            "an int8 prefix that does not verify is refused"
        );
        assert_eq!(ix.shard_count(), 0, "a refused shard is not kept");
        let qref = built
            .content
            .objects
            .iter()
            .find(|o| o.kind == Kind::Int8 && o.shard == bins[0].shard && o.epoch == bins[0].epoch)
            .unwrap()
            .clone();
        let qb = objs[qref.name.as_str()];
        let got = ix
            .add_shard(
                &bins[0],
                objs[bins[0].name.as_str()],
                &qb[..qb.len().min(70_000)],
                qb.len(),
            )
            .unwrap();
        assert_eq!(got.name, qref.name);
        assert_eq!(ix.shard_count(), 1);
        assert_eq!(ix.rows(), bins[0].count as usize);
        // Adding the same shard again changes nothing.
        ix.add_shard(
            &bins[0],
            objs[bins[0].name.as_str()],
            &qb[..qb.len().min(70_000)],
            qb.len(),
        )
        .unwrap();
        assert_eq!(ix.shard_count(), 1);

        // A row in the loaded shard is found while the rest is still to come.
        let in_first: Vec<usize> = (0..rows.len())
            .filter(|&i| rows[i].epoch == bins[0].epoch)
            .take(bins[0].count as usize)
            .collect();
        let probe = in_first[7];
        assert_eq!(
            top_hits(&ix, &objs, &rows[probe].vec)[0],
            hex::encode(rows[probe].id)
        );

        // The rest, in any order: the index ends up complete and whole.
        for b in bins.iter().skip(1).rev() {
            let q = built
                .content
                .objects
                .iter()
                .find(|o| o.kind == Kind::Int8 && o.shard == b.shard && o.epoch == b.epoch)
                .unwrap();
            let qb = objs[q.name.as_str()];
            ix.add_shard(
                b,
                objs[b.name.as_str()],
                &qb[..qb.len().min(70_000)],
                qb.len(),
            )
            .unwrap();
        }
        assert!(ix.is_complete());
        assert_eq!(ix.rows(), 1500);
        assert_eq!(ix.index_version(), 3);
        for qi in [0usize, 701, 1499] {
            assert_eq!(
                top_hits(&ix, &objs, &rows[qi].vec)[0],
                hex::encode(rows[qi].id)
            );
        }
    }

    #[test]
    fn decoys_are_drawn_from_the_index_and_exclude_hits() {
        let (rows, keys, built) = setup(300);
        let ix = index_from(&built, &keys);
        let hit = hex::encode(rows[5].id);
        let d = ix.decoys(40, 99, std::slice::from_ref(&hit));
        assert_eq!(d.len(), 40);
        assert!(!d.contains(&hit));
        let all: std::collections::HashSet<String> =
            rows.iter().map(|r| hex::encode(r.id)).collect();
        assert!(d.iter().all(|x| all.contains(x)));
    }
}
