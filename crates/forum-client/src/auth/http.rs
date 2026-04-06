//! HTTP fetch helpers and WebAuthn response encoders for server communication.
//!
//! Handles JSON POST with error extraction, and encoding WebAuthn ceremony
//! results into the JSON format expected by the auth-api server.

use js_sys::Reflect;
use wasm_bindgen::prelude::*;

use super::passkey::PasskeyError;
use super::webauthn::{buffer_to_base64url, call_method};

// -- Response encoders --------------------------------------------------------

/// Encode a WebAuthn attestation (registration) response for server verification.
pub(super) fn encode_attestation_response(
    credential: &JsValue,
) -> Result<serde_json::Value, PasskeyError> {
    let id = Reflect::get(credential, &"id".into())
        .ok()
        .and_then(|v| v.as_string())
        .ok_or_else(|| PasskeyError::JsError("Missing credential.id".into()))?;

    let raw_id = Reflect::get(credential, &"rawId".into())
        .map_err(|_| PasskeyError::JsError("Missing rawId".into()))?;
    let raw_id_b64 = buffer_to_base64url(&raw_id)?;

    let response = Reflect::get(credential, &"response".into())
        .map_err(|_| PasskeyError::JsError("Missing response".into()))?;

    let client_data = Reflect::get(&response, &"clientDataJSON".into())
        .map_err(|_| PasskeyError::JsError("Missing clientDataJSON".into()))?;
    let client_data_b64 = buffer_to_base64url(&client_data)?;

    let attestation = Reflect::get(&response, &"attestationObject".into())
        .map_err(|_| PasskeyError::JsError("Missing attestationObject".into()))?;
    let attestation_b64 = buffer_to_base64url(&attestation)?;

    let transports = call_method(&response, "getTransports", &[])
        .map(|arr| {
            let js_arr = js_sys::Array::from(&arr);
            let mut v = Vec::new();
            for i in 0..js_arr.length() {
                if let Some(s) = js_arr.get(i).as_string() {
                    v.push(serde_json::Value::String(s));
                }
            }
            v
        })
        .unwrap_or_default();

    let cred_type = Reflect::get(credential, &"type".into())
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_else(|| "public-key".into());

    Ok(serde_json::json!({
        "id": id,
        "rawId": raw_id_b64,
        "response": {
            "clientDataJSON": client_data_b64,
            "attestationObject": attestation_b64,
            "transports": transports,
        },
        "type": cred_type,
    }))
}

/// Encode a WebAuthn assertion (authentication) response for server verification.
pub(super) fn encode_assertion_response(
    assertion: &JsValue,
) -> Result<serde_json::Value, PasskeyError> {
    let id = Reflect::get(assertion, &"id".into())
        .ok()
        .and_then(|v| v.as_string())
        .ok_or_else(|| PasskeyError::JsError("Missing assertion.id".into()))?;

    let raw_id = Reflect::get(assertion, &"rawId".into())
        .map_err(|_| PasskeyError::JsError("Missing rawId".into()))?;
    let raw_id_b64 = buffer_to_base64url(&raw_id)?;

    let response = Reflect::get(assertion, &"response".into())
        .map_err(|_| PasskeyError::JsError("Missing response".into()))?;

    let client_data = Reflect::get(&response, &"clientDataJSON".into())
        .map_err(|_| PasskeyError::JsError("Missing clientDataJSON".into()))?;
    let client_data_b64 = buffer_to_base64url(&client_data)?;

    let auth_data = Reflect::get(&response, &"authenticatorData".into())
        .map_err(|_| PasskeyError::JsError("Missing authenticatorData".into()))?;
    let auth_data_b64 = buffer_to_base64url(&auth_data)?;

    let signature = Reflect::get(&response, &"signature".into())
        .map_err(|_| PasskeyError::JsError("Missing signature".into()))?;
    let signature_b64 = buffer_to_base64url(&signature)?;

    let user_handle = Reflect::get(&response, &"userHandle".into()).ok();
    let user_handle_b64 = user_handle
        .as_ref()
        .filter(|v| !v.is_null() && !v.is_undefined())
        .and_then(|v| buffer_to_base64url(v).ok());

    let cred_type = Reflect::get(assertion, &"type".into())
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_else(|| "public-key".into());

    Ok(serde_json::json!({
        "id": id,
        "rawId": raw_id_b64,
        "response": {
            "clientDataJSON": client_data_b64,
            "authenticatorData": auth_data_b64,
            "signature": signature_b64,
            "userHandle": user_handle_b64,
        },
        "type": cred_type,
    }))
}

// -- Credential ID / user handle extraction -----------------------------------

/// Get the credential ID string from a WebAuthn result.
pub(super) fn get_credential_id(credential: &JsValue) -> Result<String, PasskeyError> {
    Reflect::get(credential, &"id".into())
        .ok()
        .and_then(|v| v.as_string())
        .ok_or_else(|| PasskeyError::JsError("Missing credential.id".into()))
}

/// Extract the userHandle bytes from an assertion response.
pub(super) fn get_user_handle(assertion: &JsValue) -> Result<Vec<u8>, PasskeyError> {
    use super::webauthn::arraybuffer_to_vec;
    let response = Reflect::get(assertion, &"response".into())
        .map_err(|_| PasskeyError::JsError("Missing response".into()))?;
    let user_handle = Reflect::get(&response, &"userHandle".into())
        .map_err(|_| PasskeyError::JsError("Missing userHandle".into()))?;
    if user_handle.is_null() || user_handle.is_undefined() {
        return Err(PasskeyError::JsError("userHandle is null".into()));
    }
    arraybuffer_to_vec(&user_handle)
}

// -- Fetch helper -------------------------------------------------------------

/// POST JSON to a URL and return the response body text.
///
/// Handles server error responses by extracting error codes and messages.
pub(super) async fn fetch_json_post(
    url: &str,
    body: &serde_json::Value,
) -> Result<String, PasskeyError> {
    use wasm_bindgen_futures::JsFuture;

    web_sys::console::log_1(&format!("[fetch_json_post] POST {url}").into());
    let win = web_sys::window().ok_or(PasskeyError::NoBrowser)?;
    let body_str =
        serde_json::to_string(body).map_err(|e| PasskeyError::Protocol(e.to_string()))?;
    web_sys::console::log_1(&format!("[fetch_json_post] body: {}", &body_str[..body_str.len().min(300)]).into());

    let init = web_sys::RequestInit::new();
    init.set_method("POST");

    let headers =
        web_sys::Headers::new().map_err(|e| PasskeyError::JsError(format!("Headers: {e:?}")))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| PasskeyError::JsError(format!("Set header: {e:?}")))?;
    init.set_headers(&headers);
    init.set_body(&JsValue::from_str(&body_str));

    let request = web_sys::Request::new_with_str_and_init(url, &init)
        .map_err(|e| PasskeyError::JsError(format!("Request: {e:?}")))?;

    let resp_val = JsFuture::from(win.fetch_with_request(&request))
        .await
        .map_err(|e| PasskeyError::Network(format!("{e:?}")))?;

    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| PasskeyError::Network("Not a Response".into()))?;

    let status = resp.status();
    web_sys::console::log_1(&format!("[fetch_json_post] status={status} ok={}", resp.ok()).into());

    if !resp.ok() {
        return Err(extract_server_error(&resp).await);
    }

    let text_promise = resp
        .text()
        .map_err(|e| PasskeyError::Network(format!("{e:?}")))?;
    let text = JsFuture::from(text_promise)
        .await
        .map_err(|e| PasskeyError::Network(format!("{e:?}")))?;

    let result = text.as_string()
        .ok_or_else(|| PasskeyError::Network("Response body not a string".into()));
    if let Ok(ref s) = result {
        web_sys::console::log_1(&format!("[fetch_json_post] response text ({} chars): {}", s.len(), &s[..s.len().min(500)]).into());
    }
    result
}

/// Extract a structured error from a non-OK HTTP response.
async fn extract_server_error(resp: &web_sys::Response) -> PasskeyError {
    use serde::Deserialize;
    use wasm_bindgen_futures::JsFuture;

    #[derive(Deserialize)]
    struct ErrorResponse {
        error: Option<String>,
        code: Option<String>,
    }

    if let Ok(text_promise) = resp.text() {
        if let Ok(text) = JsFuture::from(text_promise).await {
            if let Some(text_str) = text.as_string() {
                web_sys::console::error_1(&format!("[extract_server_error] HTTP {}: {text_str}", resp.status()).into());
                if let Ok(err_resp) = serde_json::from_str::<ErrorResponse>(&text_str) {
                    if let Some(code) = err_resp.code {
                        if code == "NO_CREDENTIAL" {
                            return PasskeyError::NoCredential;
                        }
                    }
                    if let Some(msg) = err_resp.error {
                        return PasskeyError::ServerError(msg);
                    }
                }
                return PasskeyError::ServerError(format!("HTTP {}: {text_str}", resp.status()));
            }
        }
    }
    PasskeyError::ServerError(format!("HTTP {}", resp.status()))
}
