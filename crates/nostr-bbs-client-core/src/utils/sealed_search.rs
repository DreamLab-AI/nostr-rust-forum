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
//!    that hash (responses are `no-store`). The cache holds only what the pod
//!    serves (sealed objects, public model files) and survives page loads for
//!    the same identity and relay; see [`cache`] for its rules.
//! 3. Derive the per-epoch search key (`okm`) from the held key whose pubkey
//!    equals the manifest's `zone_pk` (never by `lookup(zone, epoch)`;
//!    pending keys skipped) and hand only `okm` to the search worker.
//!
//! Loading starts at sign-in ([`autoload`]), a few shards at a time, and each
//! shard is searchable as soon as it is in the worker: [`readiness`] says how
//! far it is ([`Readiness`]), and a search UI re-runs its query as it moves
//! and does not say "no results" while it is loading. The worker lives as long
//! as the page: in-app navigation keeps it and its index.
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
//! [`wipe`] (sign-out, owner switch, key swap, relay change) terminates the
//! worker first, then deletes the cache database unless it belongs to the
//! identity still signed in (the page-load case).

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;

use futures_util::future::{FutureExt, LocalBoxFuture, Shared};
use futures_util::stream::StreamExt;
use js_sys::{Array, Object, Promise, Reflect, Uint8Array};
use leptos::prelude::*;
use nostr_bbs_core::NostrEvent;
use nostr_bbs_sealed_search::format::Kind;
use nostr_bbs_sealed_search::kdf::SearchKey;
use nostr_bbs_sealed_search::manifest::{Content, HighWater, Manifest, ObjectRef};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroize;

use crate::relay::{Filter, RelayConnection};
use crate::zone_crypto::store::ZoneKeyStore;
use crate::zone_crypto::{parse_zk, read_outcome, ReadOutcome, ZoneKey};

pub mod cache;
pub mod state;

use state::{aggregate, ZoneLoad};
pub use state::{Readiness, Unavailable};

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

/// A model load shared by every zone load that needs it.
type ModelInit = Shared<LocalBoxFuture<'static, Result<(), String>>>;

struct Service {
    worker: web_sys::Worker,
    next_id: Cell<u32>,
    /// Request id → (resolve, reject).
    waiters: Waiters,
    _onmessage: Closure<dyn FnMut(web_sys::MessageEvent)>,
    model_ready: Cell<bool>,
    /// The model load under way, if any.
    model_init: RefCell<Option<ModelInit>>,
    /// Zone → accepted manifest version, once every shard is in the worker.
    loaded: RefCell<HashMap<String, u64>>,
    /// Zone → rows in the worker.
    rows: RefCell<HashMap<String, usize>>,
    /// Zones with at least one shard in the worker (searchable, maybe partly).
    searchable: RefCell<HashSet<String>>,
    /// Zone → its loaded manifest content (what the cache must keep).
    kept: RefCell<HashMap<String, Content>>,
}

thread_local! {
    static SVC: RefCell<Option<Rc<Service>>> = const { RefCell::new(None) };
    /// Bumped by [`wipe`]: a load started before it stops at its next step
    /// and writes nothing more.
    static GEN: Cell<u64> = const { Cell::new(0) };
    /// Zone → (generation, promise of the load under way), so a second
    /// caller joins it instead of starting another.
    static INFLIGHT: RefCell<HashMap<String, (u64, Promise)>> = RefCell::new(HashMap::new());
    /// Zone → where its load stands.
    static ZONES: RefCell<BTreeMap<String, ZoneLoad>> = const { RefCell::new(BTreeMap::new()) };
    /// The aggregate of `ZONES` (or the state before any load), for search UIs.
    static READINESS: ArcRwSignal<Readiness> = ArcRwSignal::new(Readiness::Idle);
    /// Zone → when (ms) its manifest was last read: a loaded or index-less
    /// zone is not asked again within [`RECHECK_MS`].
    static CHECKED: RefCell<HashMap<String, f64>> = RefCell::new(HashMap::new());
    /// What [`autoload`] last started for: `pubkey|generation|zones held`.
    static AUTOLOADED: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Shard pairs (bin + int8) fetched and loaded at once: enough to hide
/// request latency, few enough that the first pairs arrive early on a link
/// the downloads saturate (measured ~5–6 MB/s, shared by every stream).
const PARALLEL_SHARDS: usize = 2;
/// A loaded zone's manifest is re-read at most this often (ms).
const RECHECK_MS: f64 = 5.0 * 60.0 * 1000.0;
/// [`autoload`] waits this long (ms) after sign-in, so the page paints first.
const AUTOLOAD_DELAY_MS: i32 = 1_500;
/// localStorage: fingerprint of the scope the object cache belongs to.
const SCOPE_KEY: &str = "nbss:scope";

fn js_err(e: JsValue) -> String {
    e.as_string().unwrap_or_else(|| format!("{e:?}"))
}

fn get(o: &JsValue, k: &str) -> JsValue {
    Reflect::get(o, &JsValue::from_str(k)).unwrap_or(JsValue::UNDEFINED)
}

fn set(o: &Object, k: &str, v: impl Into<JsValue>) {
    let _ = Reflect::set(o, &JsValue::from_str(k), &v.into());
}

/// Milliseconds since the page started (`performance.now()`).
fn now_ms() -> f64 {
    let g = js_sys::global();
    Reflect::get(&g, &JsValue::from_str("performance"))
        .ok()
        .and_then(|p| {
            let f = Reflect::get(&p, &JsValue::from_str("now"))
                .ok()?
                .dyn_into::<js_sys::Function>()
                .ok()?;
            f.call0(&p).ok()?.as_f64()
        })
        .unwrap_or_else(js_sys::Date::now)
}

/// A timing line at the console's verbose level (shown with "Verbose" on).
fn debug(msg: &str) {
    web_sys::console::debug_1(&format!("[sealed-search] +{:.0}ms {msg}", now_ms()).into());
}

async fn sleep_ms(ms: i32) {
    let p = Promise::new(&mut |resolve, _| {
        if let Some(w) = web_sys::window() {
            let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
        }
    });
    let _ = JsFuture::from(p).await;
}

/// Whether the browser asks to save data (`navigator.connection.saveData`).
fn save_data() -> bool {
    web_sys::window()
        .map(|w| get(&get(&w.navigator(), "connection"), "saveData"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn generation() -> u64 {
    GEN.with(Cell::get)
}

/// Whether a load started in `gen` for `svc` may go on.
fn alive(gen: u64, svc: Option<&Rc<Service>>) -> Result<(), String> {
    let same_svc =
        svc.is_none_or(|s| SVC.with(|c| c.borrow().as_ref().is_some_and(|cur| Rc::ptr_eq(cur, s))));
    if generation() == gen && same_svc {
        Ok(())
    } else {
        Err("sealed search was stopped (sign-out or key change)".into())
    }
}

fn publish(r: Readiness) {
    let s = READINESS.with(Clone::clone);
    if s.get_untracked() != r {
        s.set(r);
    }
}

fn zone_state(zone: &str) -> Option<ZoneLoad> {
    ZONES.with(|m| m.borrow().get(zone).cloned())
}

/// Record where `zone`'s load stands, for a load started in `gen`: a load
/// that outlived a [`wipe`] publishes nothing (a signed-out member must not
/// be told the index is still loading).
fn set_zone(gen: u64, zone: &str, z: ZoneLoad) {
    if generation() != gen {
        return;
    }
    let r = ZONES.with(|m| {
        let mut m = m.borrow_mut();
        m.insert(zone.to_string(), z);
        aggregate(m.values())
    });
    publish(r);
}

/// Where encrypted-zone search stands, tracked: read it in a reactive
/// closure or effect and it re-runs on every change (each shard loaded
/// changes `Loading { loaded, .. }`). While it is
/// [`Readiness::Loading`], [`search`] answers from the shards loaded so far
/// (partial results), and a UI must not say "no results"
/// ([`Readiness::hides_no_results`]); it re-runs the pending query on each
/// change instead.
pub fn readiness() -> Readiness {
    READINESS.with(Clone::clone).get()
}

/// [`readiness`] without tracking.
pub fn readiness_untracked() -> Readiness {
    READINESS.with(Clone::clone).get_untracked()
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

fn local_storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok()?
}

fn hw_key(zone: &str) -> String {
    format!("nbss:hw:{zone}")
}

fn load_hw(zone: &str) -> Option<HighWater> {
    let s = local_storage()?.get_item(&hw_key(zone)).ok()??;
    serde_json::from_str(&s).ok()
}

fn store_hw(zone: &str, hw: &HighWater) {
    if let Some(ls) = local_storage() {
        let _ = ls.set_item(
            &hw_key(zone),
            &serde_json::to_string(hw).unwrap_or_default(),
        );
    }
}

fn stored_scope() -> Option<String> {
    local_storage()?.get_item(SCOPE_KEY).ok()?
}

/// The scope of whoever the auth store says is on this device now (signed
/// in, or restored and locked), or `None` when signed out or when the auth
/// store is not reachable from here.
fn current_scope() -> Option<String> {
    let auth = use_context::<crate::auth::AuthStore>()?;
    let pubkey = auth.state.try_with_untracked(|s| s.pubkey.clone())??;
    Some(cache::scope_fingerprint(
        &pubkey,
        &crate::utils::relay_url::relay_url(),
    ))
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
    let db = v.dyn_into::<web_sys::IdbDatabase>().map_err(js_err)?;
    // Let a delete ([`wipe`]) proceed instead of waiting on this connection.
    let db2 = db.clone();
    let close = Closure::once_into_js(move |_: web_sys::Event| db2.close());
    db.set_onversionchange(Some(close.unchecked_ref()));
    Ok(db)
}

fn store_tx(
    db: &web_sys::IdbDatabase,
    mode: web_sys::IdbTransactionMode,
) -> Result<web_sys::IdbObjectStore, String> {
    db.transaction_with_str_and_mode(STORE, mode)
        .map_err(js_err)?
        .object_store(STORE)
        .map_err(js_err)
}

async fn idb_get(db: &web_sys::IdbDatabase, key: &str) -> Result<Option<web_sys::Blob>, String> {
    let r = store_tx(db, web_sys::IdbTransactionMode::Readonly)?
        .get(&JsValue::from_str(key))
        .map_err(js_err)?;
    Ok(req_done(&r).await?.dyn_into::<web_sys::Blob>().ok())
}

async fn idb_put(db: &web_sys::IdbDatabase, key: &str, blob: &web_sys::Blob) -> Result<(), String> {
    let r = store_tx(db, web_sys::IdbTransactionMode::Readwrite)?
        .put_with_key(blob, &JsValue::from_str(key))
        .map_err(js_err)?;
    req_done(&r).await.map(|_| ())
}

async fn idb_keys(db: &web_sys::IdbDatabase) -> Result<Vec<String>, String> {
    let r = store_tx(db, web_sys::IdbTransactionMode::Readonly)?
        .get_all_keys()
        .map_err(js_err)?;
    Ok(Array::from(&req_done(&r).await?)
        .iter()
        .filter_map(|k| k.as_string())
        .collect())
}

async fn idb_delete(db: &web_sys::IdbDatabase, key: &str) -> Result<(), String> {
    let r = store_tx(db, web_sys::IdbTransactionMode::Readwrite)?
        .delete(&JsValue::from_str(key))
        .map_err(js_err)?;
    req_done(&r).await.map(|_| ())
}

async fn idb_clear(db: &web_sys::IdbDatabase) -> Result<(), String> {
    let r = store_tx(db, web_sys::IdbTransactionMode::Readwrite)?
        .clear()
        .map_err(js_err)?;
    req_done(&r).await.map(|_| ())
}

/// Empty the object cache when it belongs to another scope (or to nobody
/// known: written before scopes were recorded), then record `pubkey`'s.
async fn ensure_scope(db: &web_sys::IdbDatabase, pubkey: &str) -> Result<(), String> {
    let cur = cache::scope_fingerprint(pubkey, &crate::utils::relay_url::relay_url());
    if cache::must_reset(stored_scope().as_deref(), &cur) {
        // Recorded before the await, so a second zone load starting now does
        // not empty the cache again under the first one's writes.
        if let Some(ls) = local_storage() {
            let _ = ls.set_item(SCOPE_KEY, &cur);
        }
        idb_clear(db).await?;
        debug("object cache emptied: it was not recorded for this identity and relay");
    }
    Ok(())
}

/// Hex SHA-256 of `buf` by the browser's WebCrypto, so the bytes need not be
/// copied into this module's memory.
async fn sha256_hex(buf: &js_sys::ArrayBuffer) -> Result<String, String> {
    let subtle = web_sys::window()
        .ok_or("no window")?
        .crypto()
        .map_err(js_err)?
        .subtle();
    let p = subtle
        .digest_with_str_and_buffer_source("SHA-256", buf)
        .map_err(js_err)?;
    let d = JsFuture::from(p).await.map_err(js_err)?;
    Ok(hex::encode(Uint8Array::new(&d).to_vec()))
}

/// Fetch (NIP-98) or reuse a sealed object, verified against the manifest
/// before it is cached.
async fn cached_object(
    db: &web_sys::IdbDatabase,
    url: &str,
    o: &ObjectRef,
    signer: &dyn nostr_bbs_core::signer::Signer,
    gen: u64,
) -> Result<web_sys::Blob, String> {
    let key = cache::object_key(o);
    if let Some(b) = idb_get(db, &key).await? {
        return Ok(b);
    }
    let t = now_ms();
    let blob = crate::utils::restricted_media::fetch_restricted_object(url, signer)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let ab: js_sys::ArrayBuffer = JsFuture::from(blob.array_buffer())
        .await
        .map_err(js_err)?
        .unchecked_into();
    if ab.byte_length() as u64 != o.size || sha256_hex(&ab).await? != o.sha256.to_lowercase() {
        return Err(format!("object {} does not match the manifest", o.name));
    }
    // Nothing is written for a session that ended meanwhile.
    alive(gen, None)?;
    idb_put(db, &key, &blob).await?;
    debug(&format!(
        "{}: fetched {} bytes in {:.0} ms (not cached before)",
        o.name,
        o.size,
        now_ms() - t
    ));
    // Re-read so the worker gets the disk-backed blob, not this copy.
    Ok(idb_get(db, &key).await?.unwrap_or(blob))
}

/// Fetch (plain GET from the client origin) or reuse a model file, pinned by
/// the manifest's hash (review L5). Returned as a `Blob`: the worker reads it.
async fn cached_static(
    db: &web_sys::IdbDatabase,
    path: &str,
    sha: &str,
    gen: u64,
) -> Result<web_sys::Blob, String> {
    let key = cache::static_key(sha);
    if let Some(b) = idb_get(db, &key).await? {
        return Ok(b);
    }
    let t = now_ms();
    let url = crate::base::base_href(&format!("/sealed-search/{path}"));
    let window = web_sys::window().ok_or("no window")?;
    let resp: web_sys::Response = JsFuture::from(window.fetch_with_str(&url))
        .await
        .map_err(js_err)?
        .unchecked_into();
    if !resp.ok() {
        return Err(format!("{path}: HTTP {}", resp.status()));
    }
    let ab: js_sys::ArrayBuffer = JsFuture::from(resp.array_buffer().map_err(js_err)?)
        .await
        .map_err(js_err)?
        .unchecked_into();
    if sha256_hex(&ab).await? != sha.to_lowercase() {
        return Err(format!("{path} does not match the manifest hash"));
    }
    let parts = Array::of1(&ab);
    let blob = web_sys::Blob::new_with_buffer_source_sequence(&parts).map_err(js_err)?;
    alive(gen, None)?;
    idb_put(db, &key, &blob).await?;
    debug(&format!(
        "{path}: fetched {} bytes in {:.0} ms (not cached before)",
        ab.byte_length(),
        now_ms() - t
    ));
    Ok(idb_get(db, &key).await?.unwrap_or(blob))
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
    // Another caller may have started one meanwhile: use the first.
    if let Some(s) = SVC.with(|s| s.borrow().clone()) {
        worker.terminate();
        return Ok(s);
    }
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
        model_init: RefCell::new(None),
        loaded: RefCell::new(HashMap::new()),
        rows: RefCell::new(HashMap::new()),
        searchable: RefCell::new(HashSet::new()),
        kept: RefCell::new(HashMap::new()),
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

/// Load the model into the worker once, however many zone loads ask.
async fn ensure_model(
    svc: &Rc<Service>,
    db: &web_sys::IdbDatabase,
    content: &Content,
    gen: u64,
) -> Result<(), String> {
    if svc.model_ready.get() {
        return Ok(());
    }
    let running = svc.model_init.borrow().clone();
    let fut = match running {
        Some(f) => f,
        None => {
            let (svc2, db2) = (svc.clone(), db.clone());
            let (model_sha, vocab_sha) =
                (content.model_sha256.clone(), content.vocab_sha256.clone());
            let f = async move {
                let t = now_ms();
                let (model, vocab) = futures_util::future::try_join(
                    cached_static(&db2, "bge-small-en-v1.5-q8_0.gguf", &model_sha, gen),
                    cached_static(&db2, "vocab.txt", &vocab_sha, gen),
                )
                .await?;
                let t_files = now_ms();
                alive(gen, Some(&svc2))?;
                let msg = Object::new();
                set(&msg, "op", "init");
                set(&msg, "model", model);
                set(&msg, "vocab", vocab);
                let r = rpc(&svc2, msg, &Array::new()).await?;
                svc2.model_ready.set(true);
                debug(&format!(
                    "model: files {:.0} ms, worker init {:.0} ms",
                    t_files - t,
                    get(&r, "ms").as_f64().unwrap_or(0.0)
                ));
                Ok(())
            }
            .boxed_local()
            .shared();
            *svc.model_init.borrow_mut() = Some(f.clone());
            f
        }
    };
    let r = fut.await;
    // Done either way: drop the shared future (it holds the service), so a
    // failed load can be retried.
    svc.model_init.borrow_mut().take();
    r
}

/// A manifest event from one publisher: `Ok(None)` when it answered that it
/// has none for this member (404, or refused), `Err` when it did not answer.
async fn fetch_manifest(
    url: &str,
    signer: &dyn nostr_bbs_core::signer::Signer,
) -> Result<Option<NostrEvent>, String> {
    use crate::utils::restricted_media::RestrictedFetchError;
    match crate::utils::restricted_media::fetch_restricted_object(url, signer).await {
        Ok(blob) => {
            let ab = JsFuture::from(blob.array_buffer()).await.map_err(js_err)?;
            Ok(serde_json::from_slice::<NostrEvent>(&Uint8Array::new(&ab).to_vec()).ok())
        }
        Err(RestrictedFetchError::Locked) => Ok(None),
        Err(RestrictedFetchError::Failed(m)) if m == "HTTP 404" => Ok(None),
        Err(RestrictedFetchError::Failed(m)) => Err(m),
    }
}

/// Make `zone`'s newest verified index searchable in the worker. Returns the
/// number of rows loaded, or `Ok(0)` when no publisher has an index for it.
///
/// Shards become searchable as they arrive ([`readiness`] counts them). A
/// call while the zone is already loading joins that load; a zone loaded
/// and confirmed current in the last few minutes returns at once.
pub async fn ensure_zone(
    zone: &str,
    store: &ZoneKeyStore,
    signer: &dyn nostr_bbs_core::signer::Signer,
) -> Result<usize, String> {
    let gen = generation();
    let joined = INFLIGHT.with(|m| {
        m.borrow()
            .get(zone)
            .filter(|(g, _)| *g == gen)
            .map(|(_, p)| p.clone())
    });
    if let Some(p) = joined {
        // Resolved with the row count, or with the error text.
        let v = JsFuture::from(p).await.map_err(js_err)?;
        return match v.as_f64() {
            Some(n) => Ok(n as usize),
            None => Err(v.as_string().unwrap_or_else(|| "load failed".into())),
        };
    }
    let mut resolve: Option<js_sys::Function> = None;
    let p = Promise::new(&mut |res, _| resolve = Some(res));
    INFLIGHT.with(|m| m.borrow_mut().insert(zone.to_string(), (gen, p)));
    let r = load_zone(zone, store, signer, gen).await;
    INFLIGHT.with(|m| {
        let mut m = m.borrow_mut();
        if m.get(zone).is_some_and(|(g, _)| *g == gen) {
            m.remove(zone);
        }
    });
    if let Some(res) = resolve {
        let v = match &r {
            Ok(n) => JsValue::from_f64(*n as f64),
            Err(e) => JsValue::from_str(e),
        };
        let _ = res.call1(&JsValue::NULL, &v);
    }
    r
}

async fn load_zone(
    zone: &str,
    store: &ZoneKeyStore,
    signer: &dyn nostr_bbs_core::signer::Signer,
    gen: u64,
) -> Result<usize, String> {
    let t0 = now_ms();
    // No usable key for the zone: nothing to load, and nothing to report
    // (a search UI asks for every sealed zone).
    if store.all_for_zone(zone).iter().all(|k| k.pending_delivery) {
        return Ok(0);
    }
    let prior = zone_state(zone);
    let was_ready = prior == Some(ZoneLoad::Ready);
    let fresh = CHECKED.with(|c| c.borrow().get(zone).is_some_and(|t| t0 - t < RECHECK_MS));
    if fresh && prior == Some(ZoneLoad::NoIndex) {
        return Ok(0);
    }
    if fresh && was_ready {
        if let Some(svc) = SVC.with(|s| s.borrow().clone()) {
            if svc.loaded.borrow().contains_key(zone) {
                return Ok(svc.rows.borrow().get(zone).copied().unwrap_or(1));
            }
        }
    }
    let pubs = publishers();
    if pubs.is_empty() {
        set_zone(gen, zone, ZoneLoad::NoIndex);
        return Ok(0);
    }
    // A re-check of a settled zone stays quiet unless it finds work to do.
    if !matches!(prior, Some(ZoneLoad::Ready | ZoneLoad::NoIndex)) {
        set_zone(gen, zone, ZoneLoad::Pending);
    }
    let relay_url = crate::utils::relay_url::relay_url();
    let pod = crate::utils::relay_url::pod_api_base();
    let pod = pod.trim_end_matches('/');
    let hw = load_hw(zone);
    // Every publisher at once; the newest verified manifest wins.
    let answers = futures_util::future::join_all(pubs.iter().map(|p| async move {
        let url = format!("{pod}/pods/{p}/media/zones/{zone}/search/m.json");
        (p, fetch_manifest(&url, signer).await)
    }))
    .await;
    alive(gen, None)?;
    let mut best: Option<(Manifest, String)> = None;
    let mut unreachable: Option<String> = None;
    for (p, answer) in answers {
        let ev = match answer {
            Ok(Some(ev)) => ev,
            Ok(None) => continue,
            Err(e) => {
                unreachable.get_or_insert(format!("publisher {}: {e}", &p[..8.min(p.len())]));
                continue;
            }
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
    debug(&format!("{zone}: manifest read in {:.0} ms", now_ms() - t0));
    let Some((manifest, publisher)) = best else {
        if was_ready {
            // Keep answering from what is loaded; try again next time.
            return Ok(SVC.with(|s| {
                s.borrow()
                    .as_ref()
                    .and_then(|s| s.rows.borrow().get(zone).copied())
                    .unwrap_or(0)
            }));
        }
        return match unreachable {
            Some(e) => {
                set_zone(gen, zone, ZoneLoad::Failed(e.clone()));
                Err(e)
            }
            None => {
                CHECKED.with(|c| c.borrow_mut().insert(zone.to_string(), now_ms()));
                set_zone(gen, zone, ZoneLoad::NoIndex);
                Ok(0)
            }
        };
    };
    let svc = service().await?;
    alive(gen, Some(&svc))?;
    let version = manifest.content.index_version;
    if svc.loaded.borrow().get(zone) == Some(&version) {
        CHECKED.with(|c| c.borrow_mut().insert(zone.to_string(), now_ms()));
        set_zone(gen, zone, ZoneLoad::Ready);
        return Ok(svc.rows.borrow().get(zone).copied().unwrap_or(1));
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
        if !was_ready {
            set_zone(gen, zone, ZoneLoad::NoIndex);
        }
        return Ok(0);
    }

    let db = open_db().await?;
    alive(gen, Some(&svc))?;
    let result = load_shards(
        &svc, &db, zone, &manifest, &publisher, pod, &okms, signer, gen, was_ready,
    )
    .await;
    db.close();
    for (_, _, okm) in okms.iter_mut() {
        okm.zeroize();
    }
    let rows = match result {
        Ok(rows) => rows,
        Err(e) => {
            if !was_ready && generation() == gen {
                set_zone(gen, zone, ZoneLoad::Failed(e.clone()));
            }
            return Err(e);
        }
    };
    alive(gen, Some(&svc))?;
    store_hw(zone, &manifest.high_water());
    svc.loaded.borrow_mut().insert(zone.to_string(), version);
    svc.rows.borrow_mut().insert(zone.to_string(), rows);
    CHECKED.with(|c| c.borrow_mut().insert(zone.to_string(), now_ms()));
    svc.kept
        .borrow_mut()
        .insert(zone.to_string(), manifest.content.clone());
    set_zone(gen, zone, ZoneLoad::Ready);
    debug(&format!(
        "{zone}: ready, {rows} rows, index version {version}, {:.0} ms in all",
        now_ms() - t0
    ));
    Ok(rows)
}

/// Fetch (or reuse) every shard this member can open and add each to the
/// worker as soon as its pair is in, a few at a time, while the model loads.
/// Returns the rows in the worker.
#[allow(clippy::too_many_arguments)]
async fn load_shards(
    svc: &Rc<Service>,
    db: &web_sys::IdbDatabase,
    zone: &str,
    manifest: &Manifest,
    publisher: &str,
    pod: &str,
    okms: &[(u32, String, [u8; 32])],
    signer: &dyn nostr_bbs_core::signer::Signer,
    gen: u64,
    was_ready: bool,
) -> Result<usize, String> {
    let content = &manifest.content;
    ensure_scope(db, signer.public_key()).await?;
    let content_json = serde_json::to_string(content).map_err(|e| e.to_string())?;
    let held = |o: &ObjectRef| {
        okms.iter()
            .any(|(e, p, _)| *e == o.epoch && *p == o.zone_pk.to_lowercase())
    };
    let pairs: Vec<(&ObjectRef, &ObjectRef)> = content
        .objects
        .iter()
        .filter(|o| o.kind == Kind::Bin && held(o))
        .filter_map(|b| {
            content
                .objects
                .iter()
                .find(|q| {
                    q.kind == Kind::Int8
                        && q.epoch == b.epoch
                        && q.shard == b.shard
                        && q.zone_pk == b.zone_pk
                })
                .map(|q| (b, q))
        })
        .collect();
    let total = pairs.len() as u32;
    let loaded = Cell::new(0u32);
    let rows = Cell::new(0usize);
    if !was_ready {
        set_zone(gen, zone, ZoneLoad::Loading { loaded: 0, total });
    }
    let url = |o: &ObjectRef| {
        format!(
            "{pod}/pods/{publisher}/media/zones/{zone}/search/{}",
            o.name
        )
    };
    let (url, content_json, loaded, rows) = (&url, &content_json, &loaded, &rows);
    let units = pairs.into_iter().map(|(b, q)| {
        async move {
            let t = now_ms();
            let (bb, qb) = futures_util::future::try_join(
                cached_object(db, &url(b), b, signer, gen),
                cached_object(db, &url(q), q, signer, gen),
            )
            .await?;
            let t_blobs = now_ms();
            alive(gen, Some(svc))?;
            let keys = Array::new();
            let tr = Array::new();
            for (e, pk, okm) in okms {
                // A fresh copy per message, transferred: none is left behind
                // on this side.
                let arr = Uint8Array::from(okm.as_slice());
                let k = Object::new();
                set(&k, "epoch", *e as f64);
                set(&k, "zone_pk", pk.as_str());
                set(&k, "okm", arr.clone());
                tr.push(&arr.buffer());
                keys.push(&k);
            }
            let blobs = Object::new();
            set(&blobs, &b.name, bb);
            set(&blobs, &q.name, qb);
            let msg = Object::new();
            set(&msg, "op", "add");
            set(&msg, "zone", zone);
            set(&msg, "content", content_json.as_str());
            set(&msg, "keys", keys);
            set(&msg, "shards", Array::of1(&JsValue::from_str(&b.name)));
            set(&msg, "blobs", blobs);
            let r = rpc(svc, msg, &tr).await?;
            alive(gen, Some(svc))?;
            loaded.set(loaded.get() + 1);
            rows.set(rows.get().max(get(&r, "rows").as_f64().unwrap_or(0.0) as usize));
            svc.searchable.borrow_mut().insert(zone.to_string());
            if !was_ready {
                set_zone(
                    gen,
                    zone,
                    ZoneLoad::Loading {
                        loaded: loaded.get(),
                        total,
                    },
                );
            }
            debug(&format!(
                "{zone}: shard {} in ({}/{total}): objects {:.0} ms, worker read {:.0} ms + open {:.0} ms",
                b.name,
                loaded.get(),
                t_blobs - t,
                get(&r, "read_ms").as_f64().unwrap_or(0.0),
                get(&r, "open_ms").as_f64().unwrap_or(0.0),
            ));
            Ok::<(), String>(())
        }
    });
    let shards = futures_util::stream::iter(units)
        .buffer_unordered(PARALLEL_SHARDS)
        .collect::<Vec<_>>();
    // Nothing answers before the model is in, so on a device without it the
    // model is fetched first, with the whole link to itself; the shards then
    // follow. With the model cached, both run at once.
    let model_cached = svc.model_ready.get()
        || idb_get(db, &cache::static_key(&content.model_sha256))
            .await?
            .is_some();
    let results = if model_cached {
        let (model, results) =
            futures_util::future::join(ensure_model(svc, db, content, gen), shards).await;
        model?;
        results
    } else {
        ensure_model(svc, db, content, gen).await?;
        shards.await
    };
    if let Some(e) = results.into_iter().find_map(Result::err) {
        return Err(e);
    }
    Ok(rows.get())
}

/// Load every sealed zone this member holds a key for, then prune cached
/// objects no current manifest names (when every zone's manifest is known).
pub async fn load_all(store: &ZoneKeyStore, signer: &dyn nostr_bbs_core::signer::Signer) {
    let gen = generation();
    let t = now_ms();
    let zones: Vec<String> = sealed_zones()
        .into_iter()
        .filter(|z| store.all_for_zone(z).iter().any(|k| !k.pending_delivery))
        .collect();
    debug(&format!("loading {} sealed zone(s)", zones.len()));
    futures_util::future::join_all(zones.iter().map(|z| async move {
        if let Err(e) = ensure_zone(z, store, signer).await {
            web_sys::console::warn_1(&format!("[sealed-search] {z}: {e}").into());
        }
    }))
    .await;
    if generation() != gen {
        return;
    }
    debug(&format!(
        "all sealed zones settled in {:.0} ms",
        now_ms() - t
    ));
    let states: Vec<ZoneLoad> = zones.iter().filter_map(|z| zone_state(z)).collect();
    if states.len() == zones.len() && cache::prune_allowed(&states) {
        if let Err(e) = prune(gen).await {
            web_sys::console::warn_1(&format!("[sealed-search] pruning the cache: {e}").into());
        }
    }
}

/// Delete cached objects that no loaded manifest names.
async fn prune(gen: u64) -> Result<(), String> {
    let Some(svc) = SVC.with(|s| s.borrow().clone()) else {
        return Ok(());
    };
    let keep = cache::keep_set(svc.kept.borrow().values());
    let db = open_db().await?;
    let existing = idb_keys(&db).await?;
    let stale = cache::stale_keys(&existing, &keep);
    for k in &stale {
        alive(gen, Some(&svc))?;
        idb_delete(&db, k).await?;
    }
    db.close();
    if !stale.is_empty() {
        debug(&format!(
            "pruned {} cached object(s) no current index names",
            stale.len()
        ));
    }
    Ok(())
}

/// Start loading encrypted-zone indexes at sign-in rather than at the first
/// search. Call once at the app root, after the zone-key store is provided.
///
/// Waits until the signed-in member's zone keys are read, then, after a
/// short delay so the page paints first, loads every sealed zone they hold
/// a key for ([`load_all`]): from this device's cache when it has the
/// objects, else from the pod. Publishes [`readiness`] throughout, including
/// before a load can start. When the browser asks to save data, the load
/// waits for the first search instead. Runs again for another identity, or
/// when a key for another sealed zone arrives.
pub fn autoload() {
    let Some(store) = crate::zone_crypto::store::try_use_zone_key_store() else {
        return;
    };
    let Some(auth) = use_context::<crate::auth::AuthStore>() else {
        return;
    };
    Effect::new(move |_| {
        let Some((authed, pubkey)) = auth
            .state
            .try_with(|s| (s.is_authenticated, s.pubkey.clone()))
        else {
            return;
        };
        let zones = sealed_zones();
        let configured = !zones.is_empty() && !publishers().is_empty();
        let keys_ready = store.ready_for(pubkey.as_deref());
        let held = if keys_ready {
            zones
                .iter()
                .filter(|z| !store.all_for_zone(z).is_empty())
                .count()
        } else {
            0
        };
        let signed_in = authed && pubkey.is_some();
        if let Some(r) = state::before_load(configured, signed_in, keys_ready, held > 0) {
            if ZONES.with(|m| m.borrow().is_empty()) {
                publish(r);
            }
            return;
        }
        let sig = format!("{}|{}|{held}", pubkey.unwrap_or_default(), generation());
        if AUTOLOADED.with(|a| a.borrow().as_deref() == Some(sig.as_str())) {
            return;
        }
        let Some(signer) = auth.get_signer() else {
            return;
        };
        AUTOLOADED.with(|a| *a.borrow_mut() = Some(sig));
        if save_data() {
            debug("the browser asks to save data: the index loads at the first search");
            publish(Readiness::Idle);
            return;
        }
        if ZONES.with(|m| m.borrow().is_empty()) {
            publish(Readiness::Loading {
                loaded: 0,
                total: 0,
            });
        }
        wasm_bindgen_futures::spawn_local(async move {
            sleep_ms(AUTOLOAD_DELAY_MS).await;
            load_all(&store, &*signer).await;
        });
    });
}

/// Start [`load_all`] in the background (a search UI opening, say, when
/// [`autoload`] waited because the browser asks to save data). Zones loading
/// already are joined, not loaded twice; loaded ones return at once.
pub fn start(store: ZoneKeyStore, signer: Rc<dyn nostr_bbs_core::signer::Signer>) {
    wasm_bindgen_futures::spawn_local(async move {
        load_all(&store, &*signer).await;
    });
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
    // Zones with any shard in the worker: while loading, the answer comes
    // from the shards loaded so far ([`readiness`] says it is partial).
    let zones: Vec<String> = svc.searchable.borrow().iter().cloned().collect();
    if zones.is_empty() || query.trim().is_empty() || !svc.model_ready.get() {
        return Ok(Vec::new());
    }
    let t0 = now_ms();
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

    let t_worker = now_ms();
    let got: Rc<RefCell<Vec<NostrEvent>>> = Rc::default();
    let g2 = got.clone();
    // Up to 1.5 s, or until the relay's authenticated end of stored events
    // (zone posts are members-only: an EOSE before AUTH is not the answer).
    let mut done: Option<js_sys::Function> = None;
    let delay = Promise::new(&mut |resolve, _| {
        if let Some(w) = web_sys::window() {
            let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 1_500);
        }
        done = Some(resolve);
    });
    let sid = relay.subscribe_with_receipt(
        resolve_filters(&ids),
        Rc::new(move |ev: NostrEvent| g2.borrow_mut().push(ev)),
        Rc::new(move |authenticated: bool| {
            if let (true, Some(f)) = (authenticated, done.as_ref()) {
                let _ = f.call0(&JsValue::NULL);
            }
        }),
    );
    let _ = JsFuture::from(delay).await;
    relay.unsubscribe(&sid);
    debug(&format!(
        "query: worker {:.0} ms (embed {:.0}, first stage {:.0}, rescore {:.0}), relay {:.0} ms, {} candidate(s)",
        t_worker - t0,
        get(&r, "embed_ms").as_f64().unwrap_or(0.0),
        get(&r, "first_ms").as_f64().unwrap_or(0.0),
        get(&r, "rescore_ms").as_f64().unwrap_or(0.0),
        now_ms() - t_worker,
        want.len(),
    ));

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

/// Sign-out / owner switch / key swap / relay change: stop the worker
/// (dropping its derived keys and index; loads in flight stop at their next
/// step), then delete the cache database (review L7: in that order, or the
/// delete blocks on the worker's connection). The non-secret high-water
/// marks stay.
///
/// The database is kept only when it belongs to the identity the auth store
/// reports now ([`cache::keep_on_wipe`]): the zone-key store sets its owner
/// at every page load, and that must not throw away a cache of sealed
/// objects that took minutes to download. It holds nothing decrypted, and
/// with the worker stopped no derived key is left to open it.
pub fn wipe() {
    GEN.with(|g| g.set(g.get() + 1));
    if let Some(svc) = SVC.with(|s| s.borrow_mut().take()) {
        svc.worker.terminate();
        svc.model_init.borrow_mut().take();
        // Settle every pending call, so the loads awaiting them end.
        let pending: Vec<_> = svc.waiters.borrow_mut().drain().collect();
        for (_, (_, reject)) in pending {
            let _ = reject.call1(&JsValue::NULL, &JsValue::from_str("sealed search stopped"));
        }
    }
    INFLIGHT.with(|m| m.borrow_mut().clear());
    ZONES.with(|m| m.borrow_mut().clear());
    CHECKED.with(|c| c.borrow_mut().clear());
    AUTOLOADED.with(|a| a.borrow_mut().take());
    publish(Readiness::Idle);
    let stored = stored_scope();
    if cache::keep_on_wipe(stored.as_deref(), current_scope().as_deref()) {
        debug("worker stopped; object cache kept (same identity and relay)");
        return;
    }
    if let Some(ls) = local_storage() {
        let _ = ls.remove_item(SCOPE_KEY);
    }
    if let Some(f) = web_sys::window().and_then(|w| w.indexed_db().ok().flatten()) {
        let _ = f.delete_database(DB_NAME);
    }
    debug("worker stopped; object cache deleted");
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
