//! Building a sealed index from embedded rows (used by the builder CLI).

use std::collections::{BTreeMap, HashMap};

use crate::format::{encode_bin, encode_int8, Header, Kind, Scope, MAX_ROWS};
use crate::manifest::{object_name, Content, ObjectRef};
use crate::quant::{encode_i8, sign_code};
use crate::seal::{seal, SearchKey};
use crate::search::sha256_hex;
use crate::DIM;

/// One document to index.
#[derive(Clone)]
pub struct DocRow {
    /// Event id the client will fetch (the outer envelope id for sealed history).
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
    /// `(object name, sealed bytes)`.
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

/// Build an index version. Rows are grouped by their own `(epoch, zone_pk)`
/// and sealed under that epoch's key only (review M4): a row never lands in
/// another epoch's shard.
pub fn build(spec: &BuildSpec<'_>, rows: &[DocRow], keys: &KeyMap) -> Result<Built, String> {
    let BuildSpec {
        zone,
        version,
        model,
        model_sha256,
        vocab_sha256,
        shard_rows,
    } = *spec;
    let shard_rows = shard_rows.clamp(1, MAX_ROWS);
    let mut groups: BTreeMap<(u32, [u8; 32]), Vec<&DocRow>> = BTreeMap::new();
    for r in rows {
        groups.entry((r.epoch, r.zone_pk)).or_default().push(r);
    }
    let mut objects = Vec::new();
    let mut refs = Vec::new();
    for ((epoch, zone_pk), g) in groups {
        let key = keys
            .get(&(epoch, zone_pk))
            .ok_or_else(|| format!("no key for epoch {epoch}"))?;
        for (shard, chunk) in g.chunks(shard_rows).enumerate() {
            let shard = shard as u32;
            let count = chunk.len() as u32;
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
            let ids: Vec<[u8; 32]> = chunk.iter().map(|r| r.id).collect();
            let codes: Vec<_> = chunk.iter().map(|r| sign_code(&r.vec)).collect();
            let i8s: Vec<_> = chunk.iter().map(|r| encode_i8(&r.vec)).collect();
            for (kind, plain) in [
                (Kind::Bin, encode_bin(&head(Kind::Bin), &ids, &codes)),
                (Kind::Int8, encode_int8(&head(Kind::Int8), &i8s)),
            ] {
                let sealed = seal(key, &plain)?;
                let name = object_name(kind, epoch, shard, version);
                refs.push(ObjectRef {
                    name: name.clone(),
                    kind,
                    epoch,
                    zone_pk: hex::encode(zone_pk),
                    shard,
                    count,
                    size: sealed.len() as u64,
                    sha256: sha256_hex(&sealed),
                });
                objects.push((name, sealed));
            }
        }
    }
    Ok(Built {
        content: Content {
            v: 1,
            zone: zone.into(),
            index_version: version,
            dim: DIM as u32,
            model: model.into(),
            model_sha256: model_sha256.into(),
            vocab_sha256: vocab_sha256.into(),
            objects: refs,
        },
        objects,
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
