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
}

/// The cached document, if it has been fetched.
pub fn cached() -> Option<Rc<serde_json::Value>> {
    DOC.with(|d| d.borrow().clone())
}

/// Store a document (the fetch's result, or a test's).
pub fn set(doc: serde_json::Value) {
    DOC.with(|d| *d.borrow_mut() = Some(Rc::new(doc)));
}

/// The relay's NIP-11 document: the cached copy, else one fetch.
#[cfg(target_arch = "wasm32")]
pub async fn nip11() -> Result<Rc<serde_json::Value>, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    if let Some(doc) = cached() {
        return Ok(doc);
    }
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
