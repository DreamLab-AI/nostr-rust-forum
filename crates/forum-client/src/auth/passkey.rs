//! WebAuthn PRF-based passkey registration and authentication.
//!
//! Ports `community-forum/src/lib/auth/passkey.ts` to Rust/WASM using web-sys
//! bindings for the Credential Management API. Low-level ceremony helpers and
//! codec routines live in `super::webauthn`.

use js_sys::{Object, Reflect};
use serde::Deserialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::window;
use zeroize::Zeroize;

use super::http::{
    encode_assertion_response, encode_attestation_response, fetch_json_post, get_credential_id,
    get_user_handle,
};
use super::nip98;
use super::webauthn::{
    build_creation_options, build_request_options, check_hybrid_transport,
    extract_prf_output_from_assertion, extract_prf_output_from_creation,
};

// -- Configuration ------------------------------------------------------------

fn auth_api_base() -> String {
    crate::utils::relay_url::auth_api_base()
}

// -- Result types -------------------------------------------------------------

pub struct PasskeyRegistrationResult {
    pub pubkey: String,
    pub privkey_bytes: [u8; 32],
    #[allow(dead_code)]
    pub credential_id: String,
    #[allow(dead_code)]
    pub web_id: Option<String>,
    #[allow(dead_code)]
    pub pod_url: Option<String>,
    #[allow(dead_code)]
    pub did_nostr: String,
}

impl Drop for PasskeyRegistrationResult {
    fn drop(&mut self) {
        self.privkey_bytes.zeroize();
    }
}

pub struct PasskeyAuthResult {
    pub pubkey: String,
    pub privkey_bytes: [u8; 32],
    #[allow(dead_code)]
    pub did_nostr: String,
    #[allow(dead_code)]
    pub web_id: Option<String>,
}

impl Drop for PasskeyAuthResult {
    fn drop(&mut self) {
        self.privkey_bytes.zeroize();
    }
}

// -- Server response types ----------------------------------------------------

#[derive(Deserialize)]
struct RegisterOptionsResponse {
    options: serde_json::Value,
    #[serde(rename = "prfSalt")]
    prf_salt: Option<String>,
}

#[derive(Deserialize)]
struct LoginOptionsResponse {
    options: serde_json::Value,
    #[serde(rename = "prfSalt")]
    prf_salt: Option<String>,
}

#[derive(Deserialize)]
struct RegisterVerifyResponse {
    #[serde(rename = "didNostr")]
    did_nostr: String,
    #[serde(rename = "webId")]
    web_id: Option<String>,
    #[serde(rename = "podUrl")]
    pod_url: Option<String>,
}

#[derive(Deserialize)]
struct LoginVerifyResponse {
    #[serde(rename = "didNostr")]
    did_nostr: String,
    #[serde(rename = "webId")]
    web_id: Option<String>,
}

#[derive(Deserialize)]
struct LookupResponse {
    pubkey: Option<String>,
}

// -- Public API ---------------------------------------------------------------

/// Register a new passkey with PRF extension and derive Nostr keypair.
///
/// Flow:
/// 1. POST /auth/register/options -> creation options + prfSalt
/// 2. navigator.credentials.create() with PRF extension
/// 3. Extract PRF output -> HKDF -> privkey -> pubkey
/// 4. POST /auth/register/verify -> didNostr, webId, podUrl
pub async fn register_passkey(
    display_name: &str,
) -> Result<PasskeyRegistrationResult, PasskeyError> {
    let base = auth_api_base();
    web_sys::console::log_1(&format!("[register_passkey] starting, base={base}").into());

    // Step 1: Get registration options from server
    let body = serde_json::json!({ "displayName": display_name });
    let resp_text = fetch_json_post(&format!("{base}/auth/register/options"), &body).await?;
    web_sys::console::log_1(&format!("[register_passkey] options response: {} chars", resp_text.len()).into());
    let opts_resp: RegisterOptionsResponse =
        serde_json::from_str(&resp_text).map_err(|e| {
            web_sys::console::error_1(&format!("[register_passkey] options parse error: {e}").into());
            web_sys::console::error_1(&format!("[register_passkey] raw text: {resp_text}").into());
            PasskeyError::Protocol(e.to_string())
        })?;

    let prf_salt_b64 = opts_resp
        .prf_salt
        .ok_or_else(|| PasskeyError::Protocol("Server did not return prfSalt".into()))?;

    // Step 2: Create passkey credential with PRF
    let credential = create_credential(&opts_resp.options, &prf_salt_b64).await?;

    // Step 3: Extract PRF output and derive keypair
    let prf_output = extract_prf_output_from_creation(&credential)?;
    let mut prf_bytes = [0u8; 32];
    if prf_output.len() < 32 {
        return Err(PasskeyError::PrfNotSupported("PRF output too short".into()));
    }
    prf_bytes.copy_from_slice(&prf_output[..32]);

    let keypair = nostr_core::derive_from_prf(&prf_bytes)
        .map_err(|e| PasskeyError::KeyDerivation(e.to_string()))?;
    prf_bytes.zeroize();

    let pubkey = keypair.public.to_hex();
    let mut privkey_bytes = [0u8; 32];
    privkey_bytes.copy_from_slice(keypair.secret.as_bytes());

    let credential_id = get_credential_id(&credential)?;

    // Step 4: Verify with server
    web_sys::console::log_1(&"[register_passkey] step 4: verify with server".into());
    let encoded_response = encode_attestation_response(&credential)?;
    let verify_body = serde_json::json!({
        "response": encoded_response,
        "pubkey": pubkey,
        "prfSalt": prf_salt_b64,
    });
    let verify_text =
        fetch_json_post(&format!("{base}/auth/register/verify"), &verify_body).await?;
    web_sys::console::log_1(&format!("[register_passkey] verify response: {} chars", verify_text.len()).into());
    let verify_resp: RegisterVerifyResponse =
        serde_json::from_str(&verify_text).map_err(|e| {
            web_sys::console::error_1(&format!("[register_passkey] verify parse error: {e}").into());
            web_sys::console::error_1(&format!("[register_passkey] raw text: {verify_text}").into());
            PasskeyError::Protocol(e.to_string())
        })?;

    Ok(PasskeyRegistrationResult {
        pubkey,
        privkey_bytes,
        credential_id,
        web_id: verify_resp.web_id,
        pod_url: verify_resp.pod_url,
        did_nostr: verify_resp.did_nostr,
    })
}

/// Authenticate with an existing passkey, re-deriving the Nostr privkey from PRF.
///
/// Supports two flows:
/// 1. Known pubkey: single assertion with PRF (fast path)
/// 2. Unknown pubkey: discoverable credential -> identify user -> PRF assertion
pub async fn authenticate_passkey(pubkey: Option<&str>) -> Result<PasskeyAuthResult, PasskeyError> {
    let base = auth_api_base();

    let resolved_pubkey = match pubkey {
        Some(pk) if !pk.is_empty() => pk.to_string(),
        _ => discover_pubkey_from_passkey(&base).await?,
    };

    // Get login options with PRF salt
    let body = serde_json::json!({ "pubkey": resolved_pubkey });
    let resp_text = fetch_json_post(&format!("{base}/auth/login/options"), &body).await?;
    let opts_resp: LoginOptionsResponse =
        serde_json::from_str(&resp_text).map_err(|e| PasskeyError::Protocol(e.to_string()))?;

    let prf_salt_b64 = opts_resp.prf_salt.ok_or_else(|| {
        PasskeyError::Protocol(
            "Your passkey credential does not have PRF data. Please re-register.".into(),
        )
    })?;

    // Authenticate with PRF
    let assertion = get_assertion(&opts_resp.options, &prf_salt_b64).await?;

    // Block hybrid transport (QR) which produces different PRF outputs
    check_hybrid_transport(&assertion)?;

    // Extract PRF output and derive keypair
    let prf_output = extract_prf_output_from_assertion(&assertion)?;
    let mut prf_bytes = [0u8; 32];
    if prf_output.len() < 32 {
        return Err(PasskeyError::PrfNotSupported("PRF output too short".into()));
    }
    prf_bytes.copy_from_slice(&prf_output[..32]);

    let keypair = nostr_core::derive_from_prf(&prf_bytes)
        .map_err(|e| PasskeyError::KeyDerivation(e.to_string()))?;
    prf_bytes.zeroize();

    let derived_pubkey = keypair.public.to_hex();
    let mut privkey_bytes = [0u8; 32];
    privkey_bytes.copy_from_slice(keypair.secret.as_bytes());

    // Verify with server (NIP-98 authenticated)
    let verify_url = if base.is_empty() {
        let origin = window()
            .map(|w| w.location().origin().unwrap_or_default())
            .unwrap_or_default();
        format!("{origin}/auth/login/verify")
    } else {
        format!("{base}/auth/login/verify")
    };

    let encoded_response = encode_assertion_response(&assertion)?;
    let verify_body = serde_json::json!({
        "response": encoded_response,
        "pubkey": derived_pubkey,
    });
    let verify_body_str =
        serde_json::to_string(&verify_body).map_err(|e| PasskeyError::Protocol(e.to_string()))?;

    let verify_resp_text =
        nip98::fetch_with_nip98_post(&verify_url, &verify_body_str, keypair.secret.as_bytes())
            .await?;

    let verify_resp: LoginVerifyResponse = serde_json::from_str(&verify_resp_text)
        .map_err(|e| PasskeyError::Protocol(e.to_string()))?;

    Ok(PasskeyAuthResult {
        pubkey: derived_pubkey,
        privkey_bytes,
        did_nostr: verify_resp.did_nostr,
        web_id: verify_resp.web_id,
    })
}

// -- Discoverable credential flow ---------------------------------------------

async fn discover_pubkey_from_passkey(base: &str) -> Result<String, PasskeyError> {
    let body = serde_json::json!({ "pubkey": "" });
    let resp_text = fetch_json_post(&format!("{base}/auth/login/options"), &body).await?;
    let opts_resp: LoginOptionsResponse =
        serde_json::from_str(&resp_text).map_err(|e| PasskeyError::Protocol(e.to_string()))?;

    let assertion = get_assertion_no_prf(&opts_resp.options).await?;

    // Try extracting pubkey from userHandle
    if let Ok(user_handle) = get_user_handle(&assertion) {
        let hex_str = hex::encode(&user_handle);
        if hex_str.len() == 64 && hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(hex_str);
        }
    }

    // Fallback: look up by credential ID
    let cred_id = get_credential_id(&assertion)?;
    let lookup_body = serde_json::json!({ "credentialId": cred_id });
    if let Ok(lookup_text) = fetch_json_post(&format!("{base}/auth/lookup"), &lookup_body).await {
        if let Ok(lookup) = serde_json::from_str::<LookupResponse>(&lookup_text) {
            if let Some(pk) = lookup.pubkey {
                if pk.len() == 64 && pk.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Ok(pk);
                }
            }
        }
    }

    Err(PasskeyError::Protocol(
        "Could not identify your account from the passkey. \
         Please try logging in from the original device."
            .into(),
    ))
}

// -- WebAuthn ceremony helpers ------------------------------------------------

/// Detect if `navigator.credentials.create` has been overridden by a browser
/// extension (e.g. ProtonPass, Bitwarden). Password manager extensions that
/// intercept WebAuthn use software authenticators that do NOT support the PRF
/// extension, making PRF-based key derivation impossible.
fn check_credentials_intercepted() -> Result<(), PasskeyError> {
    let win = window().ok_or(PasskeyError::NoBrowser)?;
    let navigator = win.navigator();
    let credentials: JsValue = navigator.credentials().into();

    // Get credentials.create and check if it's a native function.
    // Native functions have toString() returning "function create() { [native code] }".
    // Monkey-patched functions return the actual source or a different format.
    if let Ok(create_fn) = Reflect::get(&credentials, &"create".into()) {
        if !create_fn.is_undefined() && !create_fn.is_null() {
            if let Ok(func) = create_fn.dyn_into::<js_sys::Function>() {
                let fn_str = func.to_string().as_string().unwrap_or_default();
                if !fn_str.contains("[native code]") {
                    return Err(PasskeyError::PrfNotSupported(
                        "A password manager extension (e.g. ProtonPass) is intercepting \
                         passkey requests. This prevents the cryptographic key derivation \
                         needed for your Nostr identity. Please disable the extension's \
                         passkey feature for this site, or use the private key login instead."
                            .into(),
                    ));
                }
            }
        }
    }
    Ok(())
}

async fn create_credential(
    options_json: &serde_json::Value,
    prf_salt_b64: &str,
) -> Result<JsValue, PasskeyError> {
    let win = window().ok_or(PasskeyError::NoBrowser)?;
    let navigator = win.navigator();
    let credentials = navigator.credentials();

    // Detect password manager extensions that intercept WebAuthn — their
    // software authenticators don't support PRF, which we need for key derivation.
    check_credentials_intercepted()?;

    let pk_options = build_creation_options(options_json, prf_salt_b64)?;

    let cred_options = Object::new();
    Reflect::set(&cred_options, &"publicKey".into(), &pk_options)
        .map_err(|_| PasskeyError::JsError("Failed to set publicKey".into()))?;

    let promise = credentials
        .create_with_options(&web_sys::CredentialCreationOptions::from(JsValue::from(
            cred_options,
        )))
        .map_err(|e| PasskeyError::JsError(format!("{e:?}")))?;

    let result = JsFuture::from(promise).await.map_err(|e| {
        let msg = format!("{e:?}");
        // NotAllowedError during creation usually means:
        // - User cancelled the dialog
        // - Cross-device (QR/hybrid) authenticator that doesn't support PRF
        // - Timeout waiting for the authenticator
        if msg.contains("NotAllowedError") {
            PasskeyError::Cancelled(
                "Passkey creation failed. If you were using your phone via QR code, \
                 note that cross-device passkeys do not support the PRF extension \
                 required for Nostr key derivation. Please use:\n\
                 \u{2022} Your computer's built-in biometrics (Touch ID, Windows Hello fingerprint)\n\
                 \u{2022} A USB security key (YubiKey, etc.)\n\
                 \u{2022} Or choose \"Generate Key Pair\" instead."
                    .into(),
            )
        } else {
            PasskeyError::Cancelled(msg)
        }
    })?;

    if result.is_null() || result.is_undefined() {
        return Err(PasskeyError::Cancelled(
            "Passkey creation cancelled or failed".into(),
        ));
    }

    Ok(result)
}

async fn get_assertion(
    options_json: &serde_json::Value,
    prf_salt_b64: &str,
) -> Result<JsValue, PasskeyError> {
    let win = window().ok_or(PasskeyError::NoBrowser)?;
    let navigator = win.navigator();
    let credentials = navigator.credentials();

    check_credentials_intercepted()?;

    let pk_options = build_request_options(options_json, Some(prf_salt_b64))?;

    let cred_options = Object::new();
    Reflect::set(&cred_options, &"publicKey".into(), &pk_options)
        .map_err(|_| PasskeyError::JsError("Failed to set publicKey".into()))?;

    let promise = credentials
        .get_with_options(&web_sys::CredentialRequestOptions::from(JsValue::from(
            cred_options,
        )))
        .map_err(|e| PasskeyError::JsError(format!("{e:?}")))?;

    let result = JsFuture::from(promise)
        .await
        .map_err(|e| PasskeyError::Cancelled(format!("{e:?}")))?;

    if result.is_null() || result.is_undefined() {
        return Err(PasskeyError::Cancelled(
            "Passkey authentication cancelled".into(),
        ));
    }

    Ok(result)
}

async fn get_assertion_no_prf(options_json: &serde_json::Value) -> Result<JsValue, PasskeyError> {
    let win = window().ok_or(PasskeyError::NoBrowser)?;
    let navigator = win.navigator();
    let credentials = navigator.credentials();

    let pk_options = build_request_options(options_json, None)?;

    let cred_options = Object::new();
    Reflect::set(&cred_options, &"publicKey".into(), &pk_options)
        .map_err(|_| PasskeyError::JsError("Failed to set publicKey".into()))?;

    let promise = credentials
        .get_with_options(&web_sys::CredentialRequestOptions::from(JsValue::from(
            cred_options,
        )))
        .map_err(|e| PasskeyError::JsError(format!("{e:?}")))?;

    let result = JsFuture::from(promise)
        .await
        .map_err(|e| PasskeyError::Cancelled(format!("{e:?}")))?;

    if result.is_null() || result.is_undefined() {
        return Err(PasskeyError::Cancelled(
            "Passkey selection cancelled".into(),
        ));
    }

    Ok(result)
}

// -- Error type ---------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    #[error("No browser environment")]
    NoBrowser,

    #[error("PRF extension not supported: {0}")]
    PrfNotSupported(String),

    #[error(
        "Cross-device QR authentication produces a different key and cannot derive your \
             Nostr identity. Use the same device or authenticator used during registration."
    )]
    HybridBlocked,

    #[error("Passkey operation cancelled: {0}")]
    Cancelled(String),

    #[error(
        "No passkey registered for this account. Use private key login or create a new \
             account with passkey."
    )]
    NoCredential,

    #[error("Network error: {0}")]
    Network(String),

    #[error("Server error: {0}")]
    ServerError(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    #[error("JavaScript error: {0}")]
    JsError(String),

    #[error("NIP-98 error: {0}")]
    Nip98(String),
}

impl From<JsValue> for PasskeyError {
    fn from(e: JsValue) -> Self {
        Self::JsError(format!("{e:?}"))
    }
}

impl From<super::nip98::Nip98ClientError> for PasskeyError {
    fn from(e: super::nip98::Nip98ClientError) -> Self {
        Self::Nip98(e.to_string())
    }
}
