//! Sealed per-zone search, main-thread side (sealed-search design §5–§6).
//!
//! For every encrypted zone whose effective search mode is `sealed` and for
//! which this member holds keys:
//!
//! 1. Fetch the signed manifest `m.json` from each configured publisher's pod
//!    (`__ENV__.SEARCH_PUBLISHERS`: admins and archivists, from config) and
//!    accept the newest one that verifies ([`Manifest::verify`]: signature,
//!    publisher, zone, this deployment's relay URL, the `zone_pk` bindings,
//!    and the per-zone high-water mark kept in `localStorage`).
//! 2. Fetch the sealed objects for the epochs this member holds (NIP-98 GET),
//!    check each against the manifest's size and SHA-256 (computed here, on
//!    the downloaded bytes), and cache them in IndexedDB as `Blob`s keyed by
//!    that hash (responses are `no-store`).
//! 3. Derive the per-epoch search key (`okm`) from the held key whose pubkey
//!    equals the manifest's `zone_pk` (never by `lookup(zone, epoch)`;
//!    pending keys skipped) and hand only `okm` to the search worker.
//!
//! The worker embeds the query on the device; it never fetches anything.
//! Hits are resolved by one relay REQ that hides them among decoy ids drawn
//! from the index (review H1), then opened with the existing zone crypto; a
//! hit counts only if it decrypts or opens and its `zk` tag names the zone,
//! epoch and key of the shard it came from (review M4).
//!
//! An index row's id is the id of the post as members see it. For a sealed
//! original (ADR-2017; every imported or migrated post) that is the ORIGINAL's
//! id, which the relay does not store: it holds only the envelope, under its
//! own id, naming the original in its `["sealed", <id>, "1"]` tag. The REQ
//! therefore asks for the ids both ways (`resolve_filters`) and maps each
//! envelope back by that tag (`verified_hits`).
//!
//! [`wipe`] (sign-out, owner switch) terminates the worker first, then deletes
//! the cache database.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use js_sys::{Array, Object, Promise, Reflect, Uint8Array};
use nostr_bbs_core::NostrEvent;
use nostr_bbs_sealed_search::kdf::SearchKey;
use nostr_bbs_sealed_search::manifest::{Content, HighWater, Manifest, ObjectRef};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroize;

use crate::relay::{Filter, RelayConnection};
use crate::zone_crypto::store::ZoneKeyStore;
use crate::zone_crypto::{parse_zk, read_outcome, ReadOutcome, ZoneKey};

/// IndexedDB database for sealed objects and the model (deleted by [`wipe`]).
const DB_NAME: &str = "nostr-bbs-sealed-search";
const STORE: &str = "objects";
/// Candidates rescored per query.
const RESCORE: u32 = 80;
/// Decoy ids per real hit in the resolving REQ (review H1).
const DECOYS_PER_HIT: u32 = 4;

/// A resolved, verified hit.
#[derive(Clone, Debug)]
pub struct SealedHit {
    /// The event to show (decrypted, or the opened sealed original).
    pub event: NostrEvent,
    /// Rescored similarity.
    pub score: f64,
}

/// Where a hit came from: `(zone, epoch, lowercase zone_pk, score)`.
type HitSource = (String, u32, String, f64);

/// The REQ filters that fetch hit and decoy `ids`: live zone-encrypted posts
/// by their own id, sealed originals (ADR-2017) by the inner id their
/// envelope names in its `sealed` tag (`#sealed`, which the relay indexes
/// like any tag, as [`ChannelStore::fetch_by_id`] does for one id).
///
/// [`ChannelStore::fetch_by_id`]: crate::stores::channels::ChannelStore::fetch_by_id
fn resolve_filters(ids: &[String]) -> Vec<Filter> {
    let n = ids.len() as u64;
    vec![
        Filter {
            ids: Some(ids.to_vec()),
            limit: Some(n),
            ..Default::default()
        },
        Filter {
            kinds: Some(vec![42]),
            sealed_tags: Some(ids.to_vec()),
            limit: Some(n),
            ..Default::default()
        },
    ]
}

/// The verified hits among `events` (as fetched by [`resolve_filters`]),
/// best first, one per hit id.
///
/// An event answers the hit named by its `sealed` tag when it is a sealed
/// envelope, otherwise the hit with its own id; events answering no hit are
/// decoys. It counts only if its `zk` tag names the zone, epoch and key of
/// the shard the hit came from, and it decrypts (a live post, whose id must
/// be the hit id) or opens to an original whose id is the hit id.
fn verified_hits(
    events: &[NostrEvent],
    want: &HashMap<String, HitSource>,
    lookup: impl Fn(&str, u32) -> Option<ZoneKey>,
) -> Vec<SealedHit> {
    let mut out: HashMap<String, SealedHit> = HashMap::new();
    for ev in events {
        let sealed = nostr_bbs_core::sealed::parse_sealed(&ev.tags);
        let hit_id = match &sealed {
            Some(r) => r.inner_id.clone(),
            None => ev.id.to_lowercase(),
        };
        if out.contains_key(&hit_id) {
            continue;
        }
        let Some((zone, epoch, zone_pk, score)) = want.get(&hit_id) else {
            continue; // a decoy
        };
        // The fetched event must be encrypted under the shard's exact key.
        match parse_zk(&ev.tags) {
            Some(zk) if zk.zone == *zone && zk.epoch == *epoch && zk.pubkey == *zone_pk => {}
            _ => continue,
        }
        let shown = match read_outcome(ev, &lookup) {
            ReadOutcome::Decrypted(text) if sealed.is_none() => NostrEvent {
                content: text,
                ..ev.clone()
            },
            ReadOutcome::Sealed(original) if original.id.eq_ignore_ascii_case(&hit_id) => original,
            _ => continue,
        };
        out.insert(
            hit_id,
            SealedHit {
                event: shown,
                score: *score,
            },
        );
    }
    let mut out: Vec<SealedHit> = out.into_values().collect();
    out.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.event.id.cmp(&b.event.id))
    });
    out
}

type Waiters = Rc<RefCell<HashMap<u32, (js_sys::Function, js_sys::Function)>>>;

struct Service {
    worker: web_sys::Worker,
    next_id: Cell<u32>,
    /// Request id → (resolve, reject).
    waiters: Waiters,
    _onmessage: Closure<dyn FnMut(web_sys::MessageEvent)>,
    model_ready: Cell<bool>,
    /// Zone → accepted manifest version.
    loaded: RefCell<HashMap<String, u64>>,
}

thread_local! {
    static SVC: RefCell<Option<Rc<Service>>> = const { RefCell::new(None) };
}

fn js_err(e: JsValue) -> String {
    e.as_string().unwrap_or_else(|| format!("{e:?}"))
}

fn get(o: &JsValue, k: &str) -> JsValue {
    Reflect::get(o, &JsValue::from_str(k)).unwrap_or(JsValue::UNDEFINED)
}

fn set(o: &Object, k: &str, v: impl Into<JsValue>) {
    let _ = Reflect::set(o, &JsValue::from_str(k), &v.into());
}

/// Publishers whose manifests are accepted (`__ENV__.SEARCH_PUBLISHERS`).
pub fn publishers() -> Vec<String> {
    nostr_bbs_sealed_search::manifest::parse_publishers(
        &crate::utils::relay_url::env_override("SEARCH_PUBLISHERS").unwrap_or_default(),
    )
}

/// Zones whose effective search mode is `sealed`.
pub fn sealed_zones() -> Vec<String> {
    crate::stores::zones::load_zones()
        .into_iter()
        .filter(|z| z.effective_search() == "sealed")
        .map(|z| z.id)
        .collect()
}

fn hw_key(zone: &str) -> String {
    format!("nbss:hw:{zone}")
}

fn load_hw(zone: &str) -> Option<HighWater> {
    let s = web_sys::window()?
        .local_storage()
        .ok()??
        .get_item(&hw_key(zone))
        .ok()??;
    serde_json::from_str(&s).ok()
}

fn store_hw(zone: &str, hw: &HighWater) {
    if let Some(ls) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = ls.set_item(
            &hw_key(zone),
            &serde_json::to_string(hw).unwrap_or_default(),
        );
    }
}

// ── IndexedDB (Blob values keyed by sha256) ─────────────────────────────────

async fn req_done(r: &web_sys::IdbRequest) -> Result<JsValue, String> {
    let p = Promise::new(&mut |res, rej| {
        let ok = Closure::once_into_js(move |_: web_sys::Event| {
            let _ = res.call0(&JsValue::NULL);
        });
        let bad = Closure::once_into_js(move |_: web_sys::Event| {
            let _ = rej.call0(&JsValue::NULL);
        });
        r.set_onsuccess(Some(ok.unchecked_ref()));
        r.set_onerror(Some(bad.unchecked_ref()));
    });
    JsFuture::from(p)
        .await
        .map_err(|_| "IndexedDB request failed".to_string())?;
    r.result().map_err(js_err)
}

async fn open_db() -> Result<web_sys::IdbDatabase, String> {
    let factory = web_sys::window()
        .and_then(|w| w.indexed_db().ok().flatten())
        .ok_or("IndexedDB unavailable")?;
    let req = factory.open_with_u32(DB_NAME, 1).map_err(js_err)?;
    let up = Closure::<dyn FnMut(web_sys::Event)>::new(move |ev: web_sys::Event| {
        if let Some(r) = ev
            .target()
            .and_then(|t| t.dyn_into::<web_sys::IdbOpenDbRequest>().ok())
        {
            if let Ok(db) = r
                .result()
                .and_then(|v| v.dyn_into::<web_sys::IdbDatabase>())
            {
                if !db.object_store_names().contains(STORE) {
                    let _ = db.create_object_store(STORE);
                }
            }
        }
    });
    req.set_onupgradeneeded(Some(up.as_ref().unchecked_ref()));
    let v = req_done(&req).await?;
    drop(up);
    v.dyn_into::<web_sys::IdbDatabase>().map_err(js_err)
}

async fn idb_get(db: &web_sys::IdbDatabase, key: &str) -> Result<Option<web_sys::Blob>, String> {
    let tx = db.transaction_with_str(STORE).map_err(js_err)?;
    let r = tx
        .object_store(STORE)
        .map_err(js_err)?
        .get(&JsValue::from_str(key))
        .map_err(js_err)?;
    Ok(req_done(&r).await?.dyn_into::<web_sys::Blob>().ok())
}

async fn idb_put(db: &web_sys::IdbDatabase, key: &str, blob: &web_sys::Blob) -> Result<(), String> {
    let tx = db
        .transaction_with_str_and_mode(STORE, web_sys::IdbTransactionMode::Readwrite)
        .map_err(js_err)?;
    let r = tx
        .object_store(STORE)
        .map_err(js_err)?
        .put_with_key(blob, &JsValue::from_str(key))
        .map_err(js_err)?;
    req_done(&r).await.map(|_| ())
}

async fn blob_bytes(b: &web_sys::Blob) -> Result<Vec<u8>, String> {
    let ab = JsFuture::from(b.array_buffer()).await.map_err(js_err)?;
    Ok(Uint8Array::new(&ab).to_vec())
}

fn bytes_blob(b: &[u8]) -> Result<web_sys::Blob, String> {
    let parts = Array::new();
    parts.push(&Uint8Array::from(b).buffer());
    web_sys::Blob::new_with_buffer_source_sequence(&parts).map_err(js_err)
}

fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// Fetch (NIP-98) or reuse a sealed object, verified against the manifest.
async fn cached_object(
    db: &web_sys::IdbDatabase,
    url: &str,
    o: &ObjectRef,
    signer: &dyn nostr_bbs_core::signer::Signer,
) -> Result<web_sys::Blob, String> {
    if let Some(b) = idb_get(db, &o.sha256).await? {
        return Ok(b);
    }
    let blob = crate::utils::restricted_media::fetch_restricted_object(url, signer)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let bytes = blob_bytes(&blob).await?;
    if bytes.len() as u64 != o.size || sha_hex(&bytes) != o.sha256.to_lowercase() {
        return Err(format!("object {} does not match the manifest", o.name));
    }
    let b = bytes_blob(&bytes)?;
    idb_put(db, &o.sha256, &b).await?;
    // Re-read so the worker gets the disk-backed blob, not this copy.
    Ok(idb_get(db, &o.sha256).await?.unwrap_or(b))
}

/// Fetch (plain GET from the client origin) or reuse the model files, pinned
/// by the manifest's hashes (review L5).
async fn cached_static(
    db: &web_sys::IdbDatabase,
    path: &str,
    sha: &str,
) -> Result<Vec<u8>, String> {
    let key = format!("static:{sha}");
    if let Some(b) = idb_get(db, &key).await? {
        return blob_bytes(&b).await;
    }
    let url = crate::base::base_href(&format!("/sealed-search/{path}"));
    let window = web_sys::window().ok_or("no window")?;
    let resp: web_sys::Response = JsFuture::from(window.fetch_with_str(&url))
        .await
        .map_err(js_err)?
        .unchecked_into();
    if !resp.ok() {
        return Err(format!("{path}: HTTP {}", resp.status()));
    }
    let ab = JsFuture::from(resp.array_buffer().map_err(js_err)?)
        .await
        .map_err(js_err)?;
    let bytes = Uint8Array::new(&ab).to_vec();
    if sha_hex(&bytes) != sha.to_lowercase() {
        return Err(format!("{path} does not match the manifest hash"));
    }
    idb_put(db, &key, &bytes_blob(&bytes)?).await?;
    Ok(bytes)
}

// ── Worker RPC ───────────────────────────────────────────────────────────────

async fn service() -> Result<Rc<Service>, String> {
    if let Some(s) = SVC.with(|s| s.borrow().clone()) {
        return Ok(s);
    }
    let url = crate::base::base_href("/sealed-search/loader.js");
    let worker = web_sys::Worker::new(&url).map_err(js_err)?;
    // Wait for the worker's {op:"booted"} before sending anything.
    let booted = Promise::new(&mut |res, _| {
        let once = Closure::once_into_js(move |_: web_sys::MessageEvent| {
            let _ = res.call0(&JsValue::NULL);
        });
        worker.set_onmessage(Some(once.unchecked_ref()));
    });
    JsFuture::from(booted).await.map_err(js_err)?;
    let waiters: Waiters = Rc::default();
    let w2 = waiters.clone();
    let onmessage =
        Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |ev: web_sys::MessageEvent| {
            let data = ev.data();
            let id = get(&data, "id").as_f64().unwrap_or(-1.0) as u32;
            let Some((ok, bad)) = w2.borrow_mut().remove(&id) else {
                return;
            };
            if get(&data, "op").as_string().as_deref() == Some("error") {
                let _ = bad.call1(&JsValue::NULL, &get(&data, "message"));
            } else {
                let _ = ok.call1(&JsValue::NULL, &data);
            }
        });
    worker.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    let svc = Rc::new(Service {
        worker,
        next_id: Cell::new(1),
        waiters,
        _onmessage: onmessage,
        model_ready: Cell::new(false),
        loaded: RefCell::new(HashMap::new()),
    });
    SVC.with(|s| *s.borrow_mut() = Some(svc.clone()));
    Ok(svc)
}

async fn rpc(svc: &Service, msg: Object, transfer: &Array) -> Result<JsValue, String> {
    let id = svc.next_id.get();
    svc.next_id.set(id + 1);
    set(&msg, "id", id as f64);
    let p = Promise::new(&mut |res, rej| {
        svc.waiters.borrow_mut().insert(id, (res, rej));
    });
    svc.worker
        .post_message_with_transfer(&msg, transfer)
        .map_err(js_err)?;
    JsFuture::from(p).await.map_err(js_err)
}

/// Make `zone`'s newest verified index searchable in the worker. Returns the
/// number of rows loaded, or `Ok(0)` when no publisher has an index for it.
pub async fn ensure_zone(
    zone: &str,
    store: &ZoneKeyStore,
    signer: &dyn nostr_bbs_core::signer::Signer,
) -> Result<usize, String> {
    let pubs = publishers();
    if pubs.is_empty() {
        return Ok(0);
    }
    let relay_url = crate::utils::relay_url::relay_url();
    let pod = crate::utils::relay_url::pod_api_base();
    let hw = load_hw(zone);
    // Newest verified manifest across publishers.
    let mut best: Option<(Manifest, String)> = None;
    for p in &pubs {
        let url = format!(
            "{}/pods/{p}/media/zones/{zone}/search/m.json",
            pod.trim_end_matches('/')
        );
        let Ok(blob) = crate::utils::restricted_media::fetch_restricted_object(&url, signer).await
        else {
            continue;
        };
        let Ok(ev) = serde_json::from_slice::<NostrEvent>(&blob_bytes(&blob).await?) else {
            continue;
        };
        match Manifest::verify(ev, zone, &relay_url, &pubs, hw.as_ref()) {
            Ok(m)
                if best
                    .as_ref()
                    .is_none_or(|(b, _)| m.content.index_version > b.content.index_version) =>
            {
                best = Some((m, p.clone()));
            }
            Ok(_) => {}
            Err(e) => web_sys::console::warn_1(
                &format!("[sealed-search] {zone}: manifest from {p} refused: {e}").into(),
            ),
        }
    }
    let Some((manifest, publisher)) = best else {
        return Ok(0);
    };
    let svc = service().await?;
    if svc.loaded.borrow().get(zone) == Some(&manifest.content.index_version) {
        return Ok(1);
    }
    let content: &Content = &manifest.content;

    // Keys held for the manifest's (epoch, zone_pk), matched by pubkey.
    let held: Vec<_> = store
        .all_for_zone(zone)
        .into_iter()
        .filter(|k| !k.pending_delivery)
        .collect();
    let mut okms: Vec<(u32, String, [u8; 32])> = Vec::new();
    for o in &content.objects {
        let pk = o.zone_pk.to_lowercase();
        if okms.iter().any(|(e, p, _)| *e == o.epoch && *p == pk) {
            continue;
        }
        let Some(k) = held
            .iter()
            .find(|k| k.epoch == o.epoch && k.pubkey.eq_ignore_ascii_case(&pk))
        else {
            continue;
        };
        let (Ok(mut secret), Ok(pkb)) = (hex::decode(&k.secret), hex::decode(&pk)) else {
            continue;
        };
        let (Ok(s32), Ok(p32)) = (
            <[u8; 32]>::try_from(secret.as_slice()),
            <[u8; 32]>::try_from(pkb.as_slice()),
        ) else {
            secret.zeroize();
            continue;
        };
        let okm = *SearchKey::derive(&s32, zone, o.epoch, &p32).bytes();
        secret.zeroize();
        okms.push((o.epoch, pk, okm));
    }
    if okms.is_empty() {
        return Ok(0);
    }

    let db = open_db().await?;
    if !svc.model_ready.get() {
        let mut model =
            cached_static(&db, "bge-small-en-v1.5-q8_0.gguf", &content.model_sha256).await?;
        let vocab = cached_static(&db, "vocab.txt", &content.vocab_sha256).await?;
        let (m, v) = (
            Uint8Array::from(model.as_slice()),
            Uint8Array::from(vocab.as_slice()),
        );
        model.zeroize();
        let msg = Object::new();
        set(&msg, "op", "init");
        set(&msg, "model", m.buffer());
        set(&msg, "vocab", v.buffer());
        let tr = Array::of2(&m.buffer(), &v.buffer());
        rpc(&svc, msg, &tr).await?;
        svc.model_ready.set(true);
    }

    let blobs = Object::new();
    for o in content.objects.iter().filter(|o| {
        okms.iter()
            .any(|(e, p, _)| *e == o.epoch && *p == o.zone_pk.to_lowercase())
    }) {
        let url = format!(
            "{}/pods/{publisher}/media/zones/{zone}/search/{}",
            pod.trim_end_matches('/'),
            o.name
        );
        let b = cached_object(&db, &url, o, signer).await?;
        set(&blobs, &o.name, b);
    }
    let keys = Array::new();
    let tr = Array::new();
    for (e, pk, mut okm) in okms {
        let k = Object::new();
        let arr = Uint8Array::from(okm.as_slice());
        okm.zeroize();
        set(&k, "epoch", e as f64);
        set(&k, "zone_pk", pk);
        set(&k, "okm", arr.clone());
        tr.push(&arr.buffer());
        keys.push(&k);
    }
    let msg = Object::new();
    set(&msg, "op", "load");
    set(&msg, "zone", zone);
    set(
        &msg,
        "content",
        serde_json::to_string(content).map_err(|e| e.to_string())?,
    );
    set(&msg, "keys", keys);
    set(&msg, "blobs", blobs);
    let r = rpc(&svc, msg, &tr).await?;
    store_hw(zone, &manifest.high_water());
    svc.loaded
        .borrow_mut()
        .insert(zone.to_string(), manifest.content.index_version);
    Ok(get(&r, "rows").as_f64().unwrap_or(0.0) as usize)
}

/// Search the loaded sealed zones; returns verified hits, best first.
pub async fn search(
    relay: &RelayConnection,
    store: &ZoneKeyStore,
    query: &str,
    k: u32,
) -> Result<Vec<SealedHit>, String> {
    let Some(svc) = SVC.with(|s| s.borrow().clone()) else {
        return Ok(Vec::new());
    };
    let zones: Vec<String> = svc.loaded.borrow().keys().cloned().collect();
    if zones.is_empty() || query.trim().is_empty() {
        return Ok(Vec::new());
    }
    let msg = Object::new();
    set(&msg, "op", "query");
    let za = Array::new();
    for z in &zones {
        za.push(&JsValue::from_str(z));
    }
    set(&msg, "zones", za);
    set(&msg, "text", query.trim());
    set(&msg, "k", k as f64);
    set(&msg, "r", RESCORE as f64);
    set(&msg, "decoys", (k * DECOYS_PER_HIT) as f64);
    let r = rpc(&svc, msg, &Array::new()).await?;

    let mut want: HashMap<String, HitSource> = HashMap::new();
    let mut ids: Vec<String> = Vec::new();
    for h in Array::from(&get(&r, "hits")).iter() {
        let id = get(&h, "id").as_string().unwrap_or_default().to_lowercase();
        want.insert(
            id.clone(),
            (
                get(&h, "zone").as_string().unwrap_or_default(),
                get(&h, "epoch").as_f64().unwrap_or(0.0) as u32,
                get(&h, "zone_pk")
                    .as_string()
                    .unwrap_or_default()
                    .to_lowercase(),
                get(&h, "score").as_f64().unwrap_or(0.0),
            ),
        );
        ids.push(id);
    }
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    for d in Array::from(&get(&r, "decoys")).iter() {
        if let Some(id) = get(&d, "id").as_string() {
            ids.push(id.to_lowercase());
        }
    }
    // Shuffle so the hits are not the first k ids of the REQ.
    let n = ids.len();
    for i in (1..n).rev() {
        let j = (js_sys::Math::random() * (i + 1) as f64) as usize;
        ids.swap(i, j.min(i));
    }

    let got: Rc<RefCell<Vec<NostrEvent>>> = Rc::default();
    let g2 = got.clone();
    let sid = relay.subscribe(
        resolve_filters(&ids),
        Rc::new(move |ev: NostrEvent| g2.borrow_mut().push(ev)),
        None,
    );
    let delay = Promise::new(&mut |resolve, _| {
        let _ = web_sys::window()
            .unwrap()
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 1_500);
    });
    let _ = JsFuture::from(delay).await;
    relay.unsubscribe(&sid);

    let events = got.borrow().clone();
    Ok(verified_hits(&events, &want, |z, e| store.lookup(z, e)))
}

/// Where the on-device index for encrypted zones stands, as a search UI
/// shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexState {
    /// Nothing to wait for: no encrypted zone this member can search, or its
    /// load finished without anything to search.
    Idle,
    /// The member's zone keys or the index are still on their way.
    Loading,
    /// At least one encrypted zone is searchable in the worker.
    Ready,
}

/// The index state when a search UI opens. `searchable` is "an encrypted zone
/// ([`sealed_zones`]) and an index publisher ([`publishers`]) are
/// configured"; `keys_ready` is "this member's stored zone keys are read";
/// `holds_key` is "a key for one of those zones is held"; `ready_now` is
/// [`ready`].
pub fn state_on_open(
    searchable: bool,
    keys_ready: bool,
    holds_key: bool,
    ready_now: bool,
) -> IndexState {
    if ready_now {
        IndexState::Ready
    } else if !searchable || (keys_ready && !holds_key) {
        IndexState::Idle
    } else {
        IndexState::Loading
    }
}

/// Whether any sealed zone is loaded in the worker.
pub fn ready() -> bool {
    SVC.with(|s| {
        s.borrow()
            .as_ref()
            .is_some_and(|s| !s.loaded.borrow().is_empty())
    })
}

/// Sign-out / owner switch: stop the worker (dropping its keys and index),
/// then delete the cache database (review L7: in that order, or the delete
/// blocks on the worker's connection). The non-secret high-water marks stay.
pub fn wipe() {
    if let Some(svc) = SVC.with(|s| s.borrow_mut().take()) {
        svc.worker.terminate();
        svc.waiters.borrow_mut().clear();
    }
    if let Some(f) = web_sys::window().and_then(|w| w.indexed_db().ok().flatten()) {
        let _ = f.delete_database(DB_NAME);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_to_load_means_no_loading_state() {
        // No sealed zone or no publisher: there is nothing to wait for.
        assert_eq!(
            crate::utils::sealed_search::state_on_open(false, true, true, false),
            IndexState::Idle
        );
        // Keys loaded, none held for a sealed zone: never "still loading".
        assert_eq!(
            crate::utils::sealed_search::state_on_open(true, true, false, false),
            IndexState::Idle
        );
    }

    #[test]
    fn loading_while_keys_or_index_are_on_their_way() {
        // Stored keys not yet read: the zones cannot be searched yet.
        assert_eq!(
            crate::utils::sealed_search::state_on_open(true, false, false, false),
            IndexState::Loading
        );
        assert_eq!(
            crate::utils::sealed_search::state_on_open(true, true, true, false),
            IndexState::Loading
        );
    }

    #[test]
    fn an_index_already_in_the_worker_is_ready() {
        assert_eq!(
            crate::utils::sealed_search::state_on_open(true, true, true, true),
            IndexState::Ready
        );
        assert_eq!(
            crate::utils::sealed_search::state_on_open(false, false, false, true),
            IndexState::Ready
        );
    }

    use crate::zone_crypto::zk_tag;
    use k256::schnorr::SigningKey;
    use nostr_bbs_core::keys::SecretKey;
    use nostr_bbs_core::sealed::seal_original;
    use nostr_bbs_core::{sign_event_deterministic, UnsignedEvent};

    const ALICE: [u8; 32] = [0x11; 32];
    const MIGRATOR: [u8; 32] = [0x22; 32];
    const ZONE: [u8; 32] = [0x33; 32];
    const OTHER_ZONE: [u8; 32] = [0x55; 32];

    fn pk_hex(sk: [u8; 32]) -> String {
        SecretKey::from_bytes(sk).unwrap().public_key().to_hex()
    }

    fn zone_key() -> ZoneKey {
        ZoneKey {
            zone: "zone2".into(),
            epoch: 5,
            secret: hex::encode(ZONE),
            pubkey: pk_hex(ZONE),
            granted_by: pk_hex(MIGRATOR),
            received_at: 0,
            group: None,
            pending_delivery: false,
        }
    }

    fn lookup(z: &str, e: u32) -> Option<ZoneKey> {
        (z == "zone2" && e == 5).then(zone_key)
    }

    fn root_tag() -> Vec<String> {
        vec!["e".into(), "c".repeat(64), "".into(), "root".into()]
    }

    fn signed(sk: [u8; 32], created_at: u64, tags: Vec<Vec<String>>, content: &str) -> NostrEvent {
        sign_event_deterministic(
            UnsignedEvent {
                pubkey: pk_hex(sk),
                created_at,
                kind: 42,
                tags,
                content: content.into(),
            },
            &SigningKey::from_bytes((&sk).into()).unwrap(),
        )
        .unwrap()
    }

    /// An imported post as the index knows it (its original id) and as the
    /// relay stores it (the sealed envelope, under another id).
    fn imported(created_at: u64, text: &str, zone_sk: [u8; 32]) -> (NostrEvent, NostrEvent) {
        let original = signed(ALICE, created_at, vec![root_tag()], text);
        let migrator = SecretKey::from_bytes(MIGRATOR).unwrap();
        let env = seal_original(&original, "zone2", 5, &pk_hex(zone_sk), &migrator).unwrap();
        (original, env)
    }

    fn live(created_at: u64, text: &str) -> NostrEvent {
        let zone_pk: [u8; 32] = hex::decode(pk_hex(ZONE)).unwrap().try_into().unwrap();
        let ct = nostr_bbs_core::nip44_encrypt(&ALICE, &zone_pk, text).unwrap();
        signed(
            ALICE,
            created_at,
            vec![root_tag(), zk_tag(&zone_key())],
            &ct,
        )
    }

    fn source(score: f64) -> HitSource {
        ("zone2".into(), 5, pk_hex(ZONE), score)
    }

    #[test]
    fn resolving_asks_for_sealed_originals_by_their_inner_id() {
        let ids = vec!["a".repeat(64), "b".repeat(64)];
        let json = serde_json::to_string(&resolve_filters(&ids)).unwrap();
        assert!(
            json.contains(&format!(r##""#sealed":["{}","{}"]"##, ids[0], ids[1])),
            "{json}"
        );
        assert!(
            json.contains(&format!(r#""ids":["{}","{}"]"#, ids[0], ids[1])),
            "{json}"
        );
    }

    #[test]
    fn a_sealed_envelope_answers_the_hit_named_by_its_sealed_tag() {
        // The live failure: the index holds the original's id, the relay
        // returns the envelope (another id), and the hit was dropped.
        let (original, env) = imported(1_600_000_000, "Glastonbury tickets", ZONE);
        assert_ne!(env.id, original.id);
        let want = HashMap::from([(original.id.clone(), source(0.99))]);
        let hits = verified_hits(&[env], &want, lookup);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].event.id, original.id);
        assert_eq!(hits[0].event.content, "Glastonbury tickets");
        assert_eq!(hits[0].event.pubkey, pk_hex(ALICE));
        assert!((hits[0].score - 0.99).abs() < 1e-9);
    }

    #[test]
    fn live_posts_still_resolve_by_their_own_id_and_rank_with_sealed_ones() {
        let post = live(1_700_000_000, "wartracker update");
        let (original, env) = imported(1_600_000_000, "ukraine map", ZONE);
        let want = HashMap::from([
            (post.id.clone(), source(0.7)),
            (original.id.clone(), source(0.9)),
        ]);
        let hits = verified_hits(&[post.clone(), env], &want, lookup);
        let ids: Vec<&str> = hits.iter().map(|h| h.event.id.as_str()).collect();
        assert_eq!(ids, [original.id.as_str(), post.id.as_str()]);
        assert_eq!(hits[1].event.content, "wartracker update");
    }

    #[test]
    fn decoys_duplicates_and_mismatched_keys_are_dropped() {
        let (original, env) = imported(1_600_000_000, "kept", ZONE);
        let (dup_original, dup_env) = (original.clone(), imported(1_600_000_000, "kept", ZONE).1);
        assert_eq!(dup_original.id, original.id);
        let (decoy_original, decoy_env) = imported(1_600_000_001, "decoy", ZONE);
        // Sealed under another zone key than the shard's: refused (review M4).
        let (wrong_original, wrong_env) = imported(1_600_000_002, "wrong key", OTHER_ZONE);
        let want = HashMap::from([
            (original.id.clone(), source(0.8)),
            (wrong_original.id.clone(), source(0.95)),
        ]);
        let hits = verified_hits(&[env, dup_env, decoy_env, wrong_env], &want, lookup);
        assert_eq!(hits.len(), 1, "one hit per id; decoy and wrong key dropped");
        assert_eq!(hits[0].event.id, original.id);
        assert_ne!(hits[0].event.id, decoy_original.id);
    }

    #[test]
    fn an_envelope_cannot_answer_for_another_hit_by_its_own_id() {
        // A sealed envelope whose OWN id is a hit, but which wraps another
        // original, must not be shown as that hit.
        let (_, env) = imported(1_600_000_000, "other", ZONE);
        let want = HashMap::from([(env.id.clone(), source(0.9))]);
        assert!(verified_hits(&[env], &want, lookup).is_empty());
    }
}
