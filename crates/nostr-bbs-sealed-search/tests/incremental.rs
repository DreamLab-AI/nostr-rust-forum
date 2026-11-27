//! Incremental sealed indexes end to end, as a browser sees them: a base
//! built by one publisher (the archivist), an update by another (the
//! indexer) that seals only new rows and excludes deleted ones, and a
//! compaction that folds the update shards. Synthetic vectors only.

use std::collections::{HashMap, HashSet};

use nostr_bbs_core::event::{sign_event_deterministic, NostrEvent, UnsignedEvent};
use nostr_bbs_sealed_search::build::{
    build, compact, open_pair, q_partner, update, BuildSpec, DocRow, KeyMap, PairRows, Previous,
};
use nostr_bbs_sealed_search::format::Kind;
use nostr_bbs_sealed_search::manifest::{Content, HighWater, Manifest, KIND, V2};
use nostr_bbs_sealed_search::seal::SearchKey;
use nostr_bbs_sealed_search::search::{Fetched, Index};
use nostr_bbs_sealed_search::DIM;

const RELAY: &str = "wss://relay.test";
const ARCHIVIST: u8 = 1;
const INDEXER: u8 = 2;
const STRANGER: u8 = 3;
const PK_E1: [u8; 32] = [0x41; 32];
const PK_E2: [u8; 32] = [0x42; 32];

fn sk(b: u8) -> k256::schnorr::SigningKey {
    k256::schnorr::SigningKey::from_bytes((&[b; 32]).into()).expect("test key")
}

fn pk(b: u8) -> String {
    hex::encode(sk(b).verifying_key().to_bytes())
}

fn sign(key: u8, content: &Content) -> NostrEvent {
    sign_event_deterministic(
        UnsignedEvent {
            pubkey: pk(key),
            created_at: 1,
            kind: KIND,
            tags: Manifest::tags(content, RELAY),
            content: serde_json::to_string(content).expect("content json"),
        },
        &sk(key),
    )
    .expect("signed manifest")
}

fn unit(seed: u64) -> [f32; DIM] {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(17);
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

fn row(i: u64) -> DocRow {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&i.to_be_bytes());
    id[31] = 0xee;
    DocRow {
        id,
        epoch: if i % 4 == 0 { 2 } else { 1 },
        zone_pk: if i % 4 == 0 { PK_E2 } else { PK_E1 },
        vec: unit(i),
    }
}

fn keys() -> KeyMap {
    HashMap::from([
        ((1, PK_E1), SearchKey::derive(&[7; 32], "zone2", 1, &PK_E1)),
        ((2, PK_E2), SearchKey::derive(&[8; 32], "zone2", 2, &PK_E2)),
    ])
}

fn spec(version: u64) -> BuildSpec<'static> {
    BuildSpec {
        zone: "zone2",
        version,
        model: "bge-small-en-v1.5",
        model_sha256: "m",
        vocab_sha256: "v",
        shard_rows: 300,
    }
}

/// Objects by `(owner pod, name)`, as the pods hold them.
type Pods = HashMap<(String, String), Vec<u8>>;

fn publish(pods: &mut Pods, owner: u8, built: &nostr_bbs_sealed_search::build::Built) {
    for (name, bytes) in &built.objects {
        pods.insert((pk(owner), name.clone()), bytes.clone());
    }
}

fn browser_keys() -> HashMap<(u32, String), SearchKey> {
    keys()
        .into_iter()
        .map(|((e, p), k)| ((e, hex::encode(p)), k))
        .collect()
}

/// What a browser does with a verified manifest: fetch each object from its
/// owner's pod, add every shard, then answer `q` with the top `k` ids.
fn load(m: &Manifest, pods: &Pods) -> (Index, HashMap<String, Vec<u8>>) {
    let mut ix = Index::new(m.content.clone(), browser_keys());
    let mut by_name = HashMap::new();
    for o in &m.content.objects {
        let bytes = pods
            .get(&(m.owner_of(o).to_string(), o.name.clone()))
            .unwrap_or_else(|| panic!("{} missing from {}", o.name, m.owner_of(o)))
            .clone();
        by_name.insert(o.name.clone(), bytes);
    }
    for b in ix.wanted_bins() {
        let q = q_partner(&m.content, &b).expect("int8 partner").clone();
        let qb = &by_name[&q.name];
        ix.add_shard(&b, &by_name[&b.name], &qb[..qb.len().min(70_000)], qb.len())
            .expect("shard verifies");
    }
    assert!(ix.is_complete());
    (ix, by_name)
}

fn top(ix: &Index, objs: &HashMap<String, Vec<u8>>, q: &[f32; DIM], k: usize) -> Vec<String> {
    let cands = ix.first_stage(q, 80);
    let plan = ix.plan_rescore(&cands).expect("plan");
    let fetched: Fetched = plan
        .iter()
        .map(|p| {
            (
                p.name.clone(),
                p.ranges
                    .iter()
                    .map(|&(a, b)| (a, objs[&p.name][a..b].to_vec()))
                    .collect(),
            )
        })
        .collect();
    ix.rescore(q, &cands, &fetched, k)
        .expect("rescore")
        .into_iter()
        .map(|h| h.id)
        .collect()
}

/// `c` re-labelled as version `v`, every object's header version explicit.
fn bumped(c: &Content, v: u64) -> Content {
    let mut out = c.clone();
    for o in out.objects.iter_mut() {
        o.version = Some(o.effective_version(c));
    }
    out.index_version = v;
    out
}

fn verify(ev: NostrEvent, hw: Option<&HighWater>) -> Result<Manifest, String> {
    Manifest::verify(ev, "zone2", RELAY, &[pk(ARCHIVIST), pk(INDEXER)], hw)
}

struct World {
    pods: Pods,
    base: Manifest,
    upd: Manifest,
    new_rows: Vec<DocRow>,
    deleted: Vec<DocRow>,
}

/// Base of `N` rows by the archivist, then an update by the indexer with `M`
/// new rows and `K` deletions of base rows.
fn world() -> World {
    const N: u64 = 1_000;
    const M: u64 = 120;
    let mut pods = Pods::new();
    let base_rows: Vec<DocRow> = (0..N).map(row).collect();
    let base_built = build(&spec(1), &base_rows, &keys()).expect("base");
    publish(&mut pods, ARCHIVIST, &base_built);
    let base = verify(sign(ARCHIVIST, &base_built.content), None).expect("base verifies");

    let new_rows: Vec<DocRow> = (N..N + M).map(row).collect();
    let deleted: Vec<DocRow> = [3u64, 4, 500, 999].into_iter().map(row).collect();
    let exclude: Vec<String> = deleted.iter().map(|r| hex::encode(r.id)).collect();
    let upd_built = update(
        &spec(2),
        Previous {
            content: &base.content,
            signer: &base.event.pubkey,
        },
        &pk(INDEXER),
        &new_rows,
        &exclude,
        &keys(),
    )
    .expect("update");
    publish(&mut pods, INDEXER, &upd_built);
    let upd = verify(sign(INDEXER, &upd_built.content), Some(&base.high_water()))
        .expect("update verifies over the base's high-water mark");
    World {
        pods,
        base,
        upd,
        new_rows,
        deleted,
    }
}

#[test]
fn an_update_shares_the_base_byte_for_byte_and_finds_new_rows_not_deleted_ones() {
    let w = world();
    assert_eq!(w.upd.content.v, V2);
    // Every base object is listed unchanged: same name, hash and size, held
    // in the archivist's pod, its header version the base's.
    for o in &w.base.content.objects {
        let carried = w
            .upd
            .content
            .objects
            .iter()
            .find(|u| u.name == o.name)
            .unwrap_or_else(|| panic!("{} not carried over", o.name));
        assert_eq!(carried.sha256, o.sha256);
        assert_eq!(carried.size, o.size);
        assert_eq!(w.upd.owner_of(carried), pk(ARCHIVIST));
        assert_eq!(carried.effective_version(&w.upd.content), 1);
    }
    // The update added objects only in the indexer's pod, at version 2.
    let added: Vec<_> = w
        .upd
        .content
        .objects
        .iter()
        .filter(|o| !w.base.content.objects.iter().any(|b| b.name == o.name))
        .collect();
    assert_eq!(added.len(), 4, "one new pair per epoch");
    assert!(added
        .iter()
        .all(|o| w.upd.owner_of(o) == pk(INDEXER) && o.effective_version(&w.upd.content) == 2));
    // A browser with the base cached (keyed by sha256) needs only these.
    let cached: HashSet<&str> = w
        .base
        .content
        .objects
        .iter()
        .map(|o| o.sha256.as_str())
        .collect();
    let to_fetch: Vec<_> = w
        .upd
        .content
        .objects
        .iter()
        .filter(|o| !cached.contains(o.sha256.as_str()))
        .map(|o| o.name.clone())
        .collect();
    assert_eq!(to_fetch.len(), added.len());

    let (ix, objs) = load(&w.upd, &w.pods);
    assert_eq!(ix.rows(), 1_120);
    assert_eq!(ix.live_rows(), 1_116);
    for r in w.new_rows.iter().step_by(17) {
        assert_eq!(
            top(&ix, &objs, &r.vec, 3)[0],
            hex::encode(r.id),
            "a new row is found"
        );
    }
    for r in &w.deleted {
        let hits = top(&ix, &objs, &r.vec, 10);
        assert!(
            !hits.contains(&hex::encode(r.id)),
            "a deleted row never shows"
        );
    }
    // Decoys never name an excluded row either.
    let dead: HashSet<String> = w.deleted.iter().map(|r| hex::encode(r.id)).collect();
    assert!(ix.decoys(500, 7, &[]).iter().all(|d| !dead.contains(d)));
    // And the base alone still answers for a deleted row: the exclusion, not
    // missing data, is what hides it.
    let (bix, bobjs) = load(&w.base, &w.pods);
    assert_eq!(
        top(&bix, &bobjs, &w.deleted[0].vec, 1)[0],
        hex::encode(w.deleted[0].id)
    );
}

#[test]
fn updates_from_untrusted_keys_or_lower_versions_are_refused() {
    let w = world();
    let hw = w.upd.high_water();
    // Signed by a key outside the trusted list.
    assert!(verify(sign(STRANGER, &w.upd.content), None).is_err());
    // A lower version than one already accepted (the base, after the update).
    assert!(verify(w.base.event.clone(), Some(&hw)).is_err());
    let mut older = w.upd.content.clone();
    older.index_version = 1;
    for o in older.objects.iter_mut() {
        if o.version == Some(1) {
            o.version = None;
        }
    }
    older
        .objects
        .retain(|o| o.version.unwrap_or(1) <= 1 && o.name.ends_with("-v1.age"));
    assert!(verify(sign(INDEXER, &older), Some(&hw)).is_err());
    // A trusted signer may not point at an untrusted pod.
    let honest = bumped(&w.upd.content, 3);
    assert!(verify(sign(INDEXER, &honest), Some(&hw)).is_ok());
    let mut foreign = honest.clone();
    foreign.objects[0].owner = Some(pk(STRANGER));
    assert!(verify(sign(INDEXER, &foreign), Some(&hw)).is_err());
    // An update whose object is swapped for another (hash mismatch) is
    // refused when the shard is added.
    let mut swapped = bumped(&w.upd.content, 3);
    let bins: Vec<usize> = swapped
        .objects
        .iter()
        .enumerate()
        .filter(|(_, o)| o.kind == Kind::Bin)
        .map(|(i, _)| i)
        .collect();
    let other = swapped.objects[bins[1]].clone();
    swapped.objects[bins[0]].sha256 = other.sha256.clone();
    swapped.objects[bins[0]].size = other.size;
    let m = verify(sign(INDEXER, &swapped), Some(&hw)).expect("well-formed manifest");
    let target = m.content.objects[bins[0]].clone();
    let bytes = &w.pods[&(m.owner_of(&other).to_string(), other.name.clone())];
    let mut ix = Index::new(m.content.clone(), browser_keys());
    assert!(
        ix.add_bin(&target, bytes).is_err(),
        "header binds the shard"
    );
}

#[test]
fn compaction_folds_update_shards_and_drops_excluded_rows() {
    let w = world();
    // A second update, so two partial pairs per epoch exist besides the base.
    let more: Vec<DocRow> = (2_000..2_050).map(row).collect();
    let upd2_built = update(
        &spec(3),
        Previous {
            content: &w.upd.content,
            signer: &w.upd.event.pubkey,
        },
        &pk(INDEXER),
        &more,
        &[],
        &keys(),
    )
    .expect("second update");
    let mut pods = w.pods.clone();
    publish(&mut pods, INDEXER, &upd2_built);
    let upd2 = verify(
        sign(INDEXER, &upd2_built.content),
        Some(&w.upd.high_water()),
    )
    .expect("v3");

    // Fold every pair not full (300 rows here): the base's last shard per
    // epoch and both updates. Rows excluded in folded pairs are dropped.
    let fold: Vec<String> = upd2
        .content
        .objects
        .iter()
        .filter(|o| o.kind == Kind::Bin && o.count < 300)
        .map(|o| o.name.clone())
        .collect();
    let kmap = keys();
    let mut opened: Vec<PairRows> = Vec::new();
    for name in &fold {
        let b = upd2
            .content
            .objects
            .iter()
            .find(|o| &o.name == name)
            .expect("bin");
        let q = q_partner(&upd2.content, b).expect("q");
        let bb = &pods[&(upd2.owner_of(b).to_string(), b.name.clone())];
        let qb = &pods[&(upd2.owner_of(q).to_string(), q.name.clone())];
        let pkb: [u8; 32] = hex::decode(&b.zone_pk)
            .expect("hex")
            .try_into()
            .expect("32");
        opened.push(open_pair(&upd2.content, b, bb, q, qb, &kmap[&(b.epoch, pkb)]).expect("opens"));
    }
    let in_folded: HashSet<String> = opened
        .iter()
        .flat_map(|p| p.ids.iter().map(hex::encode))
        .collect();
    let dropped: HashSet<String> = upd2
        .content
        .excluded
        .iter()
        .filter(|e| in_folded.contains(*e))
        .cloned()
        .collect();
    assert!(
        !dropped.is_empty(),
        "row 999 lives in a folded (partial) base shard"
    );
    let comp_built = compact(
        &spec(4),
        Previous {
            content: &upd2.content,
            signer: &upd2.event.pubkey,
        },
        &pk(INDEXER),
        &fold,
        &opened,
        &dropped,
        &kmap,
    )
    .expect("compact");
    publish(&mut pods, INDEXER, &comp_built);
    let comp = verify(sign(INDEXER, &comp_built.content), Some(&upd2.high_water())).expect("v4");

    // Full base shards are carried untouched; folded ones are gone.
    let names: HashSet<&str> = comp
        .content
        .objects
        .iter()
        .map(|o| o.name.as_str())
        .collect();
    for o in &w.base.content.objects {
        let folded = fold.iter().any(|f| {
            let b = upd2
                .content
                .objects
                .iter()
                .find(|x| &x.name == f)
                .expect("bin");
            b.epoch == o.epoch && b.shard == o.shard
        });
        assert_eq!(names.contains(o.name.as_str()), !folded, "{}", o.name);
    }
    // The dropped ids left the exclusion list; the others stay.
    assert!(comp.content.excluded.iter().all(|e| !dropped.contains(e)));
    assert_eq!(
        comp.content.excluded.len(),
        upd2.content.excluded.len() - dropped.len()
    );
    // Fewer, fuller pairs; same searchable rows.
    let (ix, objs) = load(&comp, &pods);
    assert_eq!(ix.live_rows(), 1_000 + 120 + 50 - 4);
    for r in w.new_rows.iter().chain(more.iter()).step_by(13) {
        assert_eq!(top(&ix, &objs, &r.vec, 3)[0], hex::encode(r.id));
    }
    for r in &w.deleted {
        assert!(!top(&ix, &objs, &r.vec, 10).contains(&hex::encode(r.id)));
    }
}
