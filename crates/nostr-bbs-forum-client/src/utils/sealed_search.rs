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
//! Hits are resolved by one relay `ids` REQ that hides them among decoy ids
//! drawn from the index (review H1), then opened with the existing zone
//! crypto; a hit counts only if it decrypts or opens and its `zk` tag names
//! the zone, epoch and key of the shard it came from (review M4).
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
use crate::zone_crypto::{parse_zk, read_outcome, ReadOutcome};

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
    let url = crate::app::base_href(&format!("/sealed-search/{path}"));
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
    let url = crate::app::base_href("/sealed-search/loader.js");
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

    // (zone, epoch, zone_pk, score) per hit id.
    let mut want: HashMap<String, (String, u32, String, f64)> = HashMap::new();
    let mut ids: Vec<String> = Vec::new();
    for h in Array::from(&get(&r, "hits")).iter() {
        let id = get(&h, "id").as_string().unwrap_or_default();
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
            ids.push(id);
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
        vec![Filter {
            ids: Some(ids),
            limit: Some(n as u64),
            ..Default::default()
        }],
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

    let mut out = Vec::new();
    for ev in got.borrow().iter() {
        let Some((zone, epoch, zone_pk, score)) = want.get(&ev.id).cloned() else {
            continue; // a decoy
        };
        // The fetched event must be encrypted under the shard's exact key.
        match parse_zk(&ev.tags) {
            Some(zk) if zk.zone == zone && zk.epoch == epoch && zk.pubkey == zone_pk => {}
            _ => continue,
        }
        let shown = match read_outcome(ev, |z, e| store.lookup(z, e)) {
            ReadOutcome::Decrypted(text) => NostrEvent {
                content: text,
                ..ev.clone()
            },
            ReadOutcome::Sealed(original) => original,
            _ => continue,
        };
        out.push(SealedHit {
            event: shown,
            score,
        });
    }
    out.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(out)
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
