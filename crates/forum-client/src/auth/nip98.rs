//! Client-side NIP-98 HTTP Auth token creation and authenticated fetch.
//!
//! Wraps `nostr_core::create_nip98_token` for WASM usage with `js_sys::Date`
//! timestamps (since `SystemTime::now()` is not available in wasm32).

use js_sys::Date;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::window;

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
    nostr_core::nip98::create_token_at(secret_key, url, method, body, now_secs)
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
}
