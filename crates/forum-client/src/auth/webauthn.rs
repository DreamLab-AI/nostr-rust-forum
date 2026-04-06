//! WebAuthn ceremony helpers: JS object builders, PRF extraction, codec, and
//! JS interop utilities.
//!
//! Extracted from `passkey.rs` to keep each module under 500 lines. Response
//! encoders and HTTP fetch live in `super::http`.

use js_sys::{ArrayBuffer, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

use super::passkey::PasskeyError;

// -- JS object builders -------------------------------------------------------

/// Build `PublicKeyCredentialCreationOptions` from server JSON with PRF extension.
///
/// Uses a spread-like approach: converts the entire server JSON to a JS object
/// first (preserving ALL fields — like `{...json}` in TypeScript), then overrides
/// only the fields that need binary conversion (challenge, user.id,
/// excludeCredentials[].id) and adds the PRF extension. This ensures browser
/// extensions like ProtonPass that intercept and re-serialize the options object
/// receive the complete, spec-compliant structure.
pub(super) fn build_creation_options(
    json: &serde_json::Value,
    prf_salt_b64: &str,
) -> Result<JsValue, PasskeyError> {
    // Start with a complete JS object from the server JSON (like TS `{...json}`)
    let options = json_to_js(json)?;

    // Override challenge: base64url string → ArrayBuffer
    if let Some(challenge) = json.get("challenge").and_then(|v| v.as_str()) {
        let buf = base64url_to_uint8array(challenge)?;
        Reflect::set(&options, &"challenge".into(), &buf)?;
    }

    // Override user.id: base64url string → ArrayBuffer (keep name/displayName as-is)
    if let Some(user_json) = json.get("user") {
        let user_obj = Reflect::get(&options, &"user".into())
            .unwrap_or(JsValue::UNDEFINED);
        if !user_obj.is_undefined() && !user_obj.is_null() {
            if let Some(id) = user_json.get("id").and_then(|v| v.as_str()) {
                let buf = base64url_to_uint8array(id)?;
                Reflect::set(&user_obj, &"id".into(), &buf)?;
            }
        }
    }

    // Override excludeCredentials[].id: base64url string → ArrayBuffer
    if let Some(exclude) = json.get("excludeCredentials").and_then(|v| v.as_array()) {
        let arr = js_sys::Array::new();
        for cred in exclude {
            // Start from the full JSON object for each credential
            let cred_obj = json_to_js(cred)?;
            if let Some(id) = cred.get("id").and_then(|v| v.as_str()) {
                let buf = base64url_to_uint8array(id)?;
                Reflect::set(&cred_obj, &"id".into(), &buf)?;
            }
            arr.push(&cred_obj);
        }
        Reflect::set(&options, &"excludeCredentials".into(), &arr)?;
    }

    // Add extensions with PRF
    let extensions = Object::new();
    let prf = Object::new();
    let eval_obj = Object::new();
    let salt_buf = base64url_to_uint8array(prf_salt_b64)?;
    Reflect::set(&eval_obj, &"first".into(), &salt_buf)?;
    Reflect::set(&prf, &"eval".into(), &eval_obj)?;
    Reflect::set(&extensions, &"prf".into(), &prf)?;
    Reflect::set(&options, &"extensions".into(), &extensions)?;

    Ok(options)
}

/// Build `PublicKeyCredentialRequestOptions` from server JSON, optionally with PRF.
///
/// Same spread-like approach as `build_creation_options`: converts the entire
/// server JSON first, then overrides only the binary fields.
pub(super) fn build_request_options(
    json: &serde_json::Value,
    prf_salt_b64: Option<&str>,
) -> Result<JsValue, PasskeyError> {
    // Start with a complete JS object from the server JSON
    let options = json_to_js(json)?;

    // Override challenge: base64url string → ArrayBuffer
    if let Some(challenge) = json.get("challenge").and_then(|v| v.as_str()) {
        let buf = base64url_to_uint8array(challenge)?;
        Reflect::set(&options, &"challenge".into(), &buf)?;
    }

    // Override allowCredentials[].id: base64url string → ArrayBuffer
    if let Some(allow) = json.get("allowCredentials").and_then(|v| v.as_array()) {
        let arr = js_sys::Array::new();
        for cred in allow {
            let cred_obj = json_to_js(cred)?;
            if let Some(id) = cred.get("id").and_then(|v| v.as_str()) {
                let buf = base64url_to_uint8array(id)?;
                Reflect::set(&cred_obj, &"id".into(), &buf)?;
            }
            arr.push(&cred_obj);
        }
        Reflect::set(&options, &"allowCredentials".into(), &arr)?;
    }

    // Add extensions with PRF (if salt provided)
    if let Some(salt_b64) = prf_salt_b64 {
        let extensions = Object::new();
        let prf = Object::new();
        let eval_obj = Object::new();
        let salt_buf = base64url_to_uint8array(salt_b64)?;
        Reflect::set(&eval_obj, &"first".into(), &salt_buf)?;
        Reflect::set(&prf, &"eval".into(), &eval_obj)?;
        Reflect::set(&extensions, &"prf".into(), &prf)?;
        Reflect::set(&options, &"extensions".into(), &extensions)?;
    }

    Ok(options)
}

// -- PRF output extraction ----------------------------------------------------

/// Extract PRF output from a creation (registration) ceremony result.
pub(super) fn extract_prf_output_from_creation(
    credential: &JsValue,
) -> Result<Vec<u8>, PasskeyError> {
    let ext_results = call_method(credential, "getClientExtensionResults", &[])?;

    let prf = Reflect::get(&ext_results, &"prf".into())
        .map_err(|_| PasskeyError::PrfNotSupported("No PRF in extension results".into()))?;

    if prf.is_undefined() || prf.is_null() {
        return Err(PasskeyError::PrfNotSupported(
            "PRF extension not supported by this authenticator".into(),
        ));
    }

    // Check prf.enabled for creation
    let enabled = Reflect::get(&prf, &"enabled".into()).ok();
    if let Some(ref e) = enabled {
        if e.is_falsy() && !e.is_undefined() {
            return Err(PasskeyError::PrfNotSupported(
                "PRF extension not supported by this authenticator. Use a FIDO2 authenticator \
                 with PRF support (not Windows Hello or cross-device QR)."
                    .into(),
            ));
        }
    }

    let results = Reflect::get(&prf, &"results".into())
        .map_err(|_| PasskeyError::PrfNotSupported("No PRF results".into()))?;
    if results.is_undefined() || results.is_null() {
        return Err(PasskeyError::PrfNotSupported(
            "PRF extension not supported. Please use Chrome 116+, Safari 17.4+.".into(),
        ));
    }

    let first = Reflect::get(&results, &"first".into())
        .map_err(|_| PasskeyError::PrfNotSupported("No PRF first result".into()))?;
    if first.is_undefined() || first.is_null() {
        return Err(PasskeyError::PrfNotSupported(
            "PRF extension not supported. Please use Chrome 116+, Safari 17.4+.".into(),
        ));
    }

    arraybuffer_to_vec(&first)
}

/// Extract PRF output from an assertion (authentication) ceremony result.
pub(super) fn extract_prf_output_from_assertion(
    assertion: &JsValue,
) -> Result<Vec<u8>, PasskeyError> {
    let ext_results = call_method(assertion, "getClientExtensionResults", &[])?;

    let prf = Reflect::get(&ext_results, &"prf".into())
        .map_err(|_| PasskeyError::PrfNotSupported("No PRF in extension results".into()))?;

    if prf.is_undefined() || prf.is_null() {
        return Err(PasskeyError::PrfNotSupported(
            "PRF extension not available on this credential".into(),
        ));
    }

    let results = Reflect::get(&prf, &"results".into())
        .map_err(|_| PasskeyError::PrfNotSupported("No PRF results".into()))?;
    if results.is_undefined() || results.is_null() {
        return Err(PasskeyError::PrfNotSupported(
            "PRF extension not available on this credential".into(),
        ));
    }

    let first = Reflect::get(&results, &"first".into())
        .map_err(|_| PasskeyError::PrfNotSupported("No PRF first result".into()))?;
    if first.is_undefined() || first.is_null() {
        return Err(PasskeyError::PrfNotSupported(
            "PRF extension not available on this credential".into(),
        ));
    }

    arraybuffer_to_vec(&first)
}

// -- Hybrid transport check ---------------------------------------------------

/// Block cross-device QR (hybrid) transport which produces different PRF outputs.
pub(super) fn check_hybrid_transport(assertion: &JsValue) -> Result<(), PasskeyError> {
    let attachment = Reflect::get(assertion, &"authenticatorAttachment".into()).ok();
    let is_cross_platform = attachment
        .as_ref()
        .and_then(|v| v.as_string())
        .map(|s| s == "cross-platform")
        .unwrap_or(false);

    if !is_cross_platform {
        return Ok(());
    }

    let response = Reflect::get(assertion, &"response".into()).ok();
    if let Some(ref resp) = response {
        if let Ok(transports) = call_method(resp, "getTransports", &[]) {
            let arr = js_sys::Array::from(&transports);
            for i in 0..arr.length() {
                if let Some(t) = arr.get(i).as_string() {
                    if t == "hybrid" {
                        return Err(PasskeyError::HybridBlocked);
                    }
                }
            }
        }
    }

    Ok(())
}

// -- Base64url codec ----------------------------------------------------------

/// Decode a base64url-encoded string to raw bytes.
pub(super) fn base64url_to_bytes(input: &str) -> Result<Vec<u8>, PasskeyError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let cleaned = input.trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(cleaned)
        .map_err(|e| PasskeyError::Protocol(format!("base64url decode: {e}")))
}

/// Decode base64url to an ArrayBuffer suitable for WebAuthn APIs.
pub(super) fn base64url_to_uint8array(input: &str) -> Result<JsValue, PasskeyError> {
    let bytes = base64url_to_bytes(input)?;
    let arr = Uint8Array::new_with_length(bytes.len() as u32);
    arr.copy_from(&bytes);
    Ok(arr.buffer().into())
}

/// Encode an ArrayBuffer/Uint8Array to base64url (no padding).
pub(super) fn buffer_to_base64url(js_val: &JsValue) -> Result<String, PasskeyError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let bytes = arraybuffer_to_vec(js_val)?;
    Ok(URL_SAFE_NO_PAD.encode(&bytes))
}

/// Convert a JsValue (ArrayBuffer or Uint8Array) to a Vec<u8>.
pub(super) fn arraybuffer_to_vec(js_val: &JsValue) -> Result<Vec<u8>, PasskeyError> {
    if let Ok(arr) = js_val.clone().dyn_into::<Uint8Array>() {
        return Ok(arr.to_vec());
    }
    if let Ok(buf) = js_val.clone().dyn_into::<ArrayBuffer>() {
        let arr = Uint8Array::new(&buf);
        return Ok(arr.to_vec());
    }
    Err(PasskeyError::JsError(
        "Expected ArrayBuffer or Uint8Array".into(),
    ))
}

// -- JSON to JS helpers -------------------------------------------------------

/// Convert a serde_json::Value to a JsValue via serde_wasm_bindgen.
///
/// Uses `serialize_maps_as_objects(true)` so that `serde_json::Value::Object`
/// produces plain JS objects (with regular properties) instead of JS `Map`
/// instances. The WebAuthn API and browser extensions expect plain objects.
pub(super) fn json_to_js(value: &serde_json::Value) -> Result<JsValue, PasskeyError> {
    use serde::Serialize;
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    value
        .serialize(&serializer)
        .map_err(|e| PasskeyError::Protocol(format!("JSON to JS: {e}")))
}

/// Call a method on a JS object by name, with arguments.
pub(super) fn call_method(
    obj: &JsValue,
    method: &str,
    args: &[JsValue],
) -> Result<JsValue, PasskeyError> {
    let func = Reflect::get(obj, &JsValue::from_str(method))
        .map_err(|_| PasskeyError::JsError(format!("Missing method: {method}")))?;
    if func.is_undefined() {
        return Err(PasskeyError::JsError(format!("Method {method} not found")));
    }
    let func: js_sys::Function = func
        .dyn_into()
        .map_err(|_| PasskeyError::JsError(format!("{method} is not a function")))?;
    let args_arr = js_sys::Array::new();
    for a in args {
        args_arr.push(a);
    }
    func.apply(obj, &args_arr)
        .map_err(|e| PasskeyError::JsError(format!("{method} call failed: {e:?}")))
}
