//! Sealed-search Web Worker (sealed-search design §6).
//!
//! Runs in a dedicated worker with its own wasm heap. It has **no network
//! code**: the main thread hands it the (hash-checked) model bytes and the
//! cached sealed objects as `Blob`s, plus the derived per-epoch search keys.
//! Queries are embedded here, on the device, and never leave it.
//!
//! Protocol (JS objects in, JS objects out):
//! On start it posts `{op:"booted"}`. Every request carries an `id`, echoed
//! in its reply.
//!
//! - `{op:"init", id, model:ArrayBuffer, vocab:ArrayBuffer}` → `{op:"ready", id, ms, mem}`
//! - `{op:"load", id, zone, content:string, keys:[{epoch, zone_pk, okm:Uint8Array}], blobs:{name:Blob}}`
//!   → `{op:"loaded", id, zone, rows, resident_bytes, ms, mem}` (one index per zone; reloading
//!   a zone replaces it)
//! - `{op:"query", id, zones:[zone], text, k, r, decoys}` → `{op:"hits", id,
//!   hits:[{zone,id,score,epoch,zone_pk}], decoys:[{zone,id}], embed_ms, first_ms, rescore_ms, mem}`
//!   (top `k` merged across the zones by score)
//! - failures → `{op:"error", id, message}`

#[cfg(not(target_arch = "wasm32"))]
fn main() {}

#[cfg(target_arch = "wasm32")]
fn main() {
    worker::install();
}

#[cfg(target_arch = "wasm32")]
mod worker {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    use js_sys::{Array, Object, Reflect, Uint8Array};
    use nostr_bbs_sealed_search::manifest::Content;
    use nostr_bbs_sealed_search::model::Bge;
    use nostr_bbs_sealed_search::search::{Fetched, Index};
    use nostr_bbs_sealed_search::seal::SearchKey;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::{spawn_local, JsFuture};
    use web_sys::{Blob, DedicatedWorkerGlobalScope, MessageEvent};

    #[derive(Default)]
    struct State {
        model: Option<Bge>,
        /// One index per zone.
        indexes: HashMap<String, Index>,
        /// `q-` object blobs keyed by `zone/name` (names repeat across zones).
        q_blobs: HashMap<String, Blob>,
    }

    thread_local! {
        static STATE: Rc<RefCell<State>> = Rc::new(RefCell::new(State::default()));
    }

    fn scope() -> DedicatedWorkerGlobalScope {
        js_sys::global().unchecked_into()
    }

    fn now() -> f64 {
        js_sys::Date::now()
    }

    fn mem_bytes() -> f64 {
        let m: js_sys::WebAssembly::Memory = wasm_bindgen::memory().unchecked_into();
        let buf: js_sys::ArrayBuffer = m.buffer().unchecked_into();
        buf.byte_length() as f64
    }

    fn get(o: &JsValue, k: &str) -> JsValue {
        Reflect::get(o, &JsValue::from_str(k)).unwrap_or(JsValue::UNDEFINED)
    }

    fn set(o: &Object, k: &str, v: impl Into<JsValue>) {
        let _ = Reflect::set(o, &JsValue::from_str(k), &v.into());
    }

    fn post(o: Object) {
        let _ = scope().post_message(&o);
    }

    fn reply_error(id: JsValue, msg: String) {
        let o = Object::new();
        set(&o, "op", "error");
        set(&o, "id", id);
        set(&o, "message", msg);
        post(o);
    }

    fn bytes_of(v: &JsValue) -> Vec<u8> {
        Uint8Array::new(v).to_vec()
    }

    async fn blob_bytes(b: &Blob, a: usize, z: usize) -> Result<Vec<u8>, String> {
        let s = b.slice_with_f64_and_f64(a as f64, z as f64).map_err(|e| format!("{e:?}"))?;
        let ab = JsFuture::from(s.array_buffer()).await.map_err(|e| format!("{e:?}"))?;
        Ok(Uint8Array::new(&ab).to_vec())
    }

    async fn on_init(msg: JsValue) -> Result<Object, String> {
        let t = now();
        let model = bytes_of(&get(&msg, "model"));
        let msg = msg.clone();
        let vocab = String::from_utf8(bytes_of(&get(&msg, "vocab"))).map_err(|_| "vocab not utf-8")?;
        let bge = Bge::load_gguf_q8(&model, &vocab)?;
        drop(model);
        STATE.with(|s| s.borrow_mut().model = Some(bge));
        let o = Object::new();
        set(&o, "op", "ready");
        set(&o, "id", get(&msg, "id"));
        set(&o, "ms", now() - t);
        set(&o, "mem", mem_bytes());
        Ok(o)
    }

    async fn on_load(msg: JsValue) -> Result<Object, String> {
        let t = now();
        let zone = get(&msg, "zone").as_string().ok_or("zone")?;
        let content: Content = serde_json::from_str(&get(&msg, "content").as_string().ok_or("content")?)
            .map_err(|e| e.to_string())?;
        if content.zone != zone {
            return Err("manifest is for another zone".into());
        }
        let mut keys = HashMap::new();
        for k in Array::from(&get(&msg, "keys")).iter() {
            let epoch = get(&k, "epoch").as_f64().ok_or("epoch")? as u32;
            let pk = get(&k, "zone_pk").as_string().ok_or("zone_pk")?.to_lowercase();
            let okm: [u8; 32] = bytes_of(&get(&k, "okm")).try_into().map_err(|_| "okm length")?;
            keys.insert((epoch, pk), SearchKey::from_bytes(okm));
        }
        let blobs = get(&msg, "blobs");
        let blob = |name: &str| -> Result<Blob, String> {
            get(&blobs, name).dyn_into::<Blob>().map_err(|_| format!("missing blob {name}"))
        };
        let mut index = Index::new(content, keys);
        for o in index.wanted_bins() {
            let b = blob(&o.name)?;
            let bytes = blob_bytes(&b, 0, b.size() as usize).await?;
            index.add_bin(&o, &bytes)?;
        }
        let mut q_blobs = HashMap::new();
        for q in index.q_needing_prefix() {
            let b = blob(&q.name)?;
            let total = b.size() as usize;
            let prefix = blob_bytes(&b, 0, total.min(70_000)).await?;
            index.set_q_prefix(&q.name, &prefix, total)?;
            q_blobs.insert(format!("{zone}/{}", q.name), b);
        }
        let rows = index.rows();
        let resident = index.resident_bytes();
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            let prefix = format!("{zone}/");
            s.q_blobs.retain(|k, _| !k.starts_with(&prefix));
            s.q_blobs.extend(q_blobs);
            s.indexes.insert(zone.clone(), index);
        });
        let o = Object::new();
        set(&o, "op", "loaded");
        set(&o, "id", get(&msg, "id"));
        set(&o, "zone", zone);
        set(&o, "rows", rows as f64);
        set(&o, "resident_bytes", resident as f64);
        set(&o, "ms", now() - t);
        set(&o, "mem", mem_bytes());
        Ok(o)
    }

    async fn on_query(msg: JsValue) -> Result<Object, String> {
        let text = get(&msg, "text").as_string().ok_or("text")?;
        let k = get(&msg, "k").as_f64().unwrap_or(10.0) as usize;
        let r = get(&msg, "r").as_f64().unwrap_or(80.0) as usize;
        let n_decoys = get(&msg, "decoys").as_f64().unwrap_or(0.0) as usize;
        let zones: Vec<String> = Array::from(&get(&msg, "zones")).iter().filter_map(|z| z.as_string()).collect();
        let state = STATE.with(|s| s.clone());

        let t0 = now();
        let q = {
            let st = state.borrow();
            let m = st.model.as_ref().ok_or("model not loaded")?;
            m.embed(&[text.as_str()])?.pop().ok_or("no embedding")?
        };
        let t1 = now();
        let mut first_ms = 0.0;
        let mut all: Vec<(String, nostr_bbs_sealed_search::search::Hit)> = Vec::new();
        let mut decoys: Vec<(String, String)> = Vec::new();
        for zone in &zones {
            let ta = now();
            let planned = {
                let st = state.borrow();
                match st.indexes.get(zone) {
                    Some(ix) => {
                        let cands = ix.first_stage(&q, r.max(k));
                        let plan = ix.plan_rescore(&cands)?;
                        Some((cands, plan))
                    }
                    None => None,
                }
            };
            first_ms += now() - ta;
            let Some((cands, plan)) = planned else { continue };
            let mut fetched: Fetched = HashMap::new();
            for p in plan {
                let blob = state.borrow().q_blobs.get(&format!("{zone}/{}", p.name)).cloned().ok_or("q blob")?;
                let mut parts = Vec::with_capacity(p.ranges.len());
                for (a, z) in p.ranges {
                    parts.push((a, blob_bytes(&blob, a, z).await?));
                }
                fetched.insert(p.name, parts);
            }
            let st = state.borrow();
            let ix = st.indexes.get(zone).ok_or("index gone")?;
            let hits = ix.rescore(&q, &cands, &fetched, k)?;
            let ids: Vec<String> = hits.iter().map(|h| h.id.clone()).collect();
            let seed = (now() as u64) ^ 0x9e37_79b9_7f4a_7c15 ^ (zone.len() as u64);
            decoys.extend(ix.decoys(n_decoys * hits.len() / k.max(1), seed, &ids).into_iter().map(|d| (zone.clone(), d)));
            all.extend(hits.into_iter().map(|h| (zone.clone(), h)));
        }
        all.sort_by(|a, b| b.1.score.partial_cmp(&a.1.score).unwrap_or(std::cmp::Ordering::Equal));
        all.truncate(k);
        let t3 = now();
        let arr = Array::new();
        for (zone, h) in all {
            let o = Object::new();
            set(&o, "zone", zone);
            set(&o, "id", h.id);
            set(&o, "score", h.score as f64);
            set(&o, "epoch", h.epoch as f64);
            set(&o, "zone_pk", h.zone_pk);
            arr.push(&o);
        }
        let d = Array::new();
        for (zone, id) in decoys {
            let o = Object::new();
            set(&o, "zone", zone);
            set(&o, "id", id);
            d.push(&o);
        }
        let o = Object::new();
        set(&o, "op", "hits");
        set(&o, "id", get(&msg, "id"));
        set(&o, "hits", arr);
        set(&o, "decoys", d);
        set(&o, "embed_ms", t1 - t0);
        set(&o, "first_ms", first_ms);
        set(&o, "rescore_ms", t3 - t1 - first_ms);
        set(&o, "mem", mem_bytes());
        Ok(o)
    }

    pub fn install() {
        let cb = Closure::<dyn FnMut(MessageEvent)>::new(move |ev: MessageEvent| {
            let msg = ev.data();
            let op = get(&msg, "op").as_string().unwrap_or_default();
            let id = get(&msg, "id");
            spawn_local(async move {
                let res = match op.as_str() {
                    "init" => on_init(msg).await,
                    "load" => on_load(msg).await,
                    "query" => on_query(msg).await,
                    _ => Err(format!("unknown op {op}")),
                };
                match res {
                    Ok(o) => post(o),
                    Err(e) => reply_error(id, e),
                }
            });
        });
        scope().set_onmessage(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
        let o = Object::new();
        set(&o, "op", "booted");
        post(o);
    }
}
