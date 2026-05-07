//! Client-side NIP-98 HTTP Auth token creation and authenticated fetch.
//!
//! Wraps `nostr_bbs_core::create_nip98_token` for WASM usage with `js_sys::Date`
//! timestamps (since `SystemTime::now()` is not available in wasm32).
//!
//! ## Two paths
//!
//! - The original `fetch_with_nip98_{post,get}` take a 32-byte secret key and
//!   only support the PRF/local-key signing path.
//! - The Sprint v11 `fetch_with_nip98_{post,get}_signer` take any
//!   [`nostr_bbs_core::signer::Signer`] (PRF, NIP-07, future hardware bunkers)
//!   and route signing through the trait. They build the unsigned NIP-98
//!   event in-process, hand it to `signer.sign_event()`, then base64-encode
//!   the returned signed event.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use js_sys::Date;
use sha2::{Digest, Sha256};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::window;

use nostr_bbs_core::signer::Signer;
use nostr_bbs_core::UnsignedEvent;

/// NIP-98 HTTP Auth event kind.
const HTTP_AUTH_KIND: u64 = 27235;

/// Create a NIP-98 authorization token (base64-encoded signed event).
///
/// Uses `js_sys::Date::now()` for the timestamp since `SystemTime::now()`
/// is not available in wasm32-unknown-unknown.
pub fn create_nip98_token(
    secret_key: &[u8; 32],
    url: &str,
    method: &str,
    body: Option<&[u8]>,
) -> Result<String, Nip98ClientError> {
    let now_secs = (Date::now() / 1000.0) as u64;
    nostr_bbs_core::nip98::create_token_at(secret_key, url, method, body, now_secs)
        .map_err(|e| Nip98ClientError::TokenCreation(e.to_string()))
}

/// Fetch a URL with a NIP-98 `Authorization: Nostr <token>` header.
///
/// This is a convenience wrapper for POST requests with JSON body.
/// Signs the request body for the payload hash tag.
pub async fn fetch_with_nip98_post(
    url: &str,
    json_body: &str,
    secret_key: &[u8; 32],
) -> Result<String, Nip98ClientError> {
    let body_bytes = json_body.as_bytes();
    let token = create_nip98_token(secret_key, url, "POST", Some(body_bytes))?;
    let auth_header = format!("Nostr {token}");

    let win = window().ok_or(Nip98ClientError::NoBrowser)?;

    let init = web_sys::RequestInit::new();
    init.set_method("POST");

    let headers = web_sys::Headers::new().map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;
    headers
        .set("Authorization", &auth_header)
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;
    init.set_headers(&headers);
    init.set_body(&wasm_bindgen::JsValue::from_str(json_body));

    let request = web_sys::Request::new_with_str_and_init(url, &init)
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;

    let resp_val = JsFuture::from(win.fetch_with_request(&request))
        .await
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;

    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| Nip98ClientError::Fetch("Not a Response".into()))?;

    if !resp.ok() {
        let status = resp.status();
        if let Ok(text_promise) = resp.text() {
            if let Ok(text) = JsFuture::from(text_promise).await {
                if let Some(s) = text.as_string() {
                    return Err(Nip98ClientError::ServerError(format!("HTTP {status}: {s}")));
                }
            }
        }
        return Err(Nip98ClientError::ServerError(format!("HTTP {status}")));
    }

    let text_promise = resp
        .text()
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;
    let text = JsFuture::from(text_promise)
        .await
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;

    text.as_string()
        .ok_or_else(|| Nip98ClientError::Fetch("Response body not a string".into()))
}

/// Fetch any URL with GET and NIP-98 authorization.
pub async fn fetch_with_nip98_get(
    url: &str,
    secret_key: &[u8; 32],
) -> Result<String, Nip98ClientError> {
    let token = create_nip98_token(secret_key, url, "GET", None)?;
    let auth_header = format!("Nostr {token}");

    let win = window().ok_or(Nip98ClientError::NoBrowser)?;

    let init = web_sys::RequestInit::new();
    init.set_method("GET");

    let headers = web_sys::Headers::new().map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;
    headers
        .set("Authorization", &auth_header)
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;
    init.set_headers(&headers);

    let request = web_sys::Request::new_with_str_and_init(url, &init)
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;

    let resp_val = JsFuture::from(win.fetch_with_request(&request))
        .await
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;

    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| Nip98ClientError::Fetch("Not a Response".into()))?;

    if !resp.ok() {
        let status = resp.status();
        return Err(Nip98ClientError::ServerError(format!("HTTP {status}")));
    }

    let text_promise = resp
        .text()
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;
    let text = JsFuture::from(text_promise)
        .await
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;

    text.as_string()
        .ok_or_else(|| Nip98ClientError::Fetch("Response body not a string".into()))
}

#[derive(Debug, thiserror::Error)]
pub enum Nip98ClientError {
    #[error("No browser environment")]
    NoBrowser,

    #[error("Token creation failed: {0}")]
    TokenCreation(String),

    #[error("Fetch error: {0}")]
    Fetch(String),

    #[error("Server error: {0}")]
    ServerError(String),

    /// The configured Signer rejected or failed to sign the event.
    #[error("Signer error: {0}")]
    Signer(String),
}

// ---------------------------------------------------------------------------
// Sprint v11 — Signer-trait-based NIP-98
//
// These variants accept any `&dyn Signer` (PRF, NIP-07, hardware bunkers)
// instead of raw private-key bytes. The unsigned NIP-98 event is built here,
// signed by the trait object, then base64-encoded into the Authorization
// header.
//
// The Signer trait is `?Send` (single-threaded WASM) and async, so these
// fns are also async and must be awaited from a `spawn_local`-style task.
// ---------------------------------------------------------------------------

/// Build an unsigned NIP-98 event, sign it through the supplied [`Signer`],
/// and return the base64-encoded `Authorization: Nostr <token>` payload.
///
/// Mirrors `nostr_bbs_core::nip98::create_token_at` but routes the signing
/// step through the Signer trait so non-PRF backends (NIP-07, hardware) can
/// participate.
pub async fn create_nip98_token_with_signer(
    signer: &dyn Signer,
    url: &str,
    method: &str,
    body: Option<&[u8]>,
) -> Result<String, Nip98ClientError> {
    let now_secs = (Date::now() / 1000.0) as u64;

    let mut tags = vec![
        vec!["u".to_string(), url.to_string()],
        vec!["method".to_string(), method.to_string()],
    ];
    if let Some(body_bytes) = body {
        let hash = Sha256::digest(body_bytes);
        tags.push(vec!["payload".to_string(), hex::encode(hash)]);
    }

    let unsigned = UnsignedEvent {
        pubkey: signer.public_key().to_string(),
        created_at: now_secs,
        kind: HTTP_AUTH_KIND,
        tags,
        content: String::new(),
    };

    let signed = signer
        .sign_event(unsigned)
        .await
        .map_err(|e| Nip98ClientError::Signer(e.to_string()))?;

    let json = serde_json::to_string(&signed)
        .map_err(|e| Nip98ClientError::TokenCreation(e.to_string()))?;
    Ok(BASE64.encode(json.as_bytes()))
}

/// POST a JSON body to `url` with NIP-98 auth via the supplied Signer.
///
/// Drop-in replacement for [`fetch_with_nip98_post`] that works for any
/// [`Signer`] backend, not just PRF-derived raw keys.
pub async fn fetch_with_nip98_post_signer(
    url: &str,
    json_body: &str,
    signer: &dyn Signer,
) -> Result<String, Nip98ClientError> {
    let body_bytes = json_body.as_bytes();
    let token = create_nip98_token_with_signer(signer, url, "POST", Some(body_bytes)).await?;
    let auth_header = format!("Nostr {token}");

    let win = window().ok_or(Nip98ClientError::NoBrowser)?;

    let init = web_sys::RequestInit::new();
    init.set_method("POST");

    let headers = web_sys::Headers::new().map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;
    headers
        .set("Authorization", &auth_header)
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;
    init.set_headers(&headers);
    init.set_body(&wasm_bindgen::JsValue::from_str(json_body));

    let request = web_sys::Request::new_with_str_and_init(url, &init)
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;

    let resp_val = JsFuture::from(win.fetch_with_request(&request))
        .await
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;

    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| Nip98ClientError::Fetch("Not a Response".into()))?;

    if !resp.ok() {
        let status = resp.status();
        if let Ok(text_promise) = resp.text() {
            if let Ok(text) = JsFuture::from(text_promise).await {
                if let Some(s) = text.as_string() {
                    return Err(Nip98ClientError::ServerError(format!("HTTP {status}: {s}")));
                }
            }
        }
        return Err(Nip98ClientError::ServerError(format!("HTTP {status}")));
    }

    let text_promise = resp
        .text()
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;
    let text = JsFuture::from(text_promise)
        .await
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;

    text.as_string()
        .ok_or_else(|| Nip98ClientError::Fetch("Response body not a string".into()))
}

/// GET `url` with NIP-98 auth via the supplied Signer.
///
/// Drop-in replacement for [`fetch_with_nip98_get`] that works for any
/// [`Signer`] backend.
#[allow(dead_code)]
pub async fn fetch_with_nip98_get_signer(
    url: &str,
    signer: &dyn Signer,
) -> Result<String, Nip98ClientError> {
    let token = create_nip98_token_with_signer(signer, url, "GET", None).await?;
    let auth_header = format!("Nostr {token}");

    let win = window().ok_or(Nip98ClientError::NoBrowser)?;

    let init = web_sys::RequestInit::new();
    init.set_method("GET");

    let headers = web_sys::Headers::new().map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;
    headers
        .set("Authorization", &auth_header)
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;
    init.set_headers(&headers);

    let request = web_sys::Request::new_with_str_and_init(url, &init)
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;

    let resp_val = JsFuture::from(win.fetch_with_request(&request))
        .await
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;

    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| Nip98ClientError::Fetch("Not a Response".into()))?;

    if !resp.ok() {
        let status = resp.status();
        return Err(Nip98ClientError::ServerError(format!("HTTP {status}")));
    }

    let text_promise = resp
        .text()
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;
    let text = JsFuture::from(text_promise)
        .await
        .map_err(|e| Nip98ClientError::Fetch(format!("{e:?}")))?;

    text.as_string()
        .ok_or_else(|| Nip98ClientError::Fetch("Response body not a string".into()))
}
