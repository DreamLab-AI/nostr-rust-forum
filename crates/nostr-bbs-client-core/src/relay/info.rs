//! The relay's NIP-11 information document, fetched once per session.
//!
//! Capability checks read it: the zone-group bindings (ADR-2028) and the
//! `SECTION-STATS` request (ADR-2038), which a client sends only to a relay
//! that advertises it. A failed fetch is not cached, so a later caller asks
//! again; callers treat a failure as "not advertised".

use std::cell::RefCell;
use std::rc::Rc;

thread_local! {
    static DOC: RefCell<Option<Rc<serde_json::Value>>> = const { RefCell::new(None) };
    /// Callers waiting on a fetch already in flight (`Some` while one is).
    #[cfg(target_arch = "wasm32")]
    static WAITERS: RefCell<Option<Vec<Rc<super::OneShot<()>>>>> = const { RefCell::new(None) };
}

/// Start the fetch now, without waiting for it, so the document is cached by
/// the time a capability check needs it (called when the channel store
/// starts syncing, ahead of AUTH and of the first section visit).
pub fn prefetch() {
    #[cfg(target_arch = "wasm32")]
    if cached().is_none() {
        leptos::task::spawn_local(async {
            let _ = nip11().await;
        });
    }
}

/// The cached document, if it has been fetched.
pub fn cached() -> Option<Rc<serde_json::Value>> {
    DOC.with(|d| d.borrow().clone())
}

/// Store a document (the fetch's result, or a test's).
pub fn set(doc: serde_json::Value) {
    DOC.with(|d| *d.borrow_mut() = Some(Rc::new(doc)));
}

/// The relay's NIP-11 document: the cached copy, else the fetch in flight,
/// else one fetch.
#[cfg(target_arch = "wasm32")]
pub async fn nip11() -> Result<Rc<serde_json::Value>, String> {
    if let Some(doc) = cached() {
        return Ok(doc);
    }
    let joined = WAITERS.with(|w| {
        let mut w = w.borrow_mut();
        match w.as_mut() {
            Some(list) => {
                let slot = super::OneShot::new();
                list.push(slot.clone());
                Some(slot)
            }
            None => {
                *w = Some(Vec::new());
                None
            }
        }
    });
    if let Some(slot) = joined {
        slot.wait().await;
        return cached().ok_or_else(|| "NIP-11 unavailable".to_string());
    }
    let result = fetch().await;
    let waiters = WAITERS.with(|w| w.borrow_mut().take()).unwrap_or_default();
    for slot in waiters {
        slot.fill(());
    }
    result
}

#[cfg(target_arch = "wasm32")]
async fn fetch() -> Result<Rc<serde_json::Value>, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    let url = crate::utils::relay_url::relay_api_base();
    let headers = web_sys::Headers::new().map_err(|_| "headers")?;
    headers
        .set("Accept", "application/nostr+json")
        .map_err(|_| "headers")?;
    let init = web_sys::RequestInit::new();
    init.set_headers(&headers);
    let req = web_sys::Request::new_with_str_and_init(&url, &init).map_err(|_| "request")?;
    let win = web_sys::window().ok_or("no window")?;
    let resp: web_sys::Response = JsFuture::from(win.fetch_with_request(&req))
        .await
        .map_err(|_| "NIP-11 fetch failed")?
        .dyn_into()
        .map_err(|_| "NIP-11 response")?;
    if !resp.ok() {
        return Err(format!("NIP-11 HTTP {}", resp.status()));
    }
    let text = JsFuture::from(resp.text().map_err(|_| "NIP-11 body")?)
        .await
        .map_err(|_| "NIP-11 body")?
        .as_string()
        .ok_or("NIP-11 body")?;
    let doc: serde_json::Value = serde_json::from_str(&text).map_err(|_| "NIP-11 JSON")?;
    set(doc);
    cached().ok_or_else(|| "NIP-11 cache".to_string())
}

/// Native builds have no relay to ask: the cached document, if one was set.
#[cfg(not(target_arch = "wasm32"))]
pub async fn nip11() -> Result<Rc<serde_json::Value>, String> {
    cached().ok_or_else(|| "no NIP-11 document in a native build".to_string())
}
