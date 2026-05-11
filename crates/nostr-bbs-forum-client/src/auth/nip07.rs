//! NIP-07: Browser Extension signing support.
//!
//! Provides JS interop with `window.nostr` (NIP-07 browser extensions like
//! nos2x, Alby, etc.) for pubkey retrieval and event signing without
//! exposing the private key to the web app.
//!
//! Also implements the [`nostr_bbs_core::signer::Signer`] trait via `Nip07Signer`
//! so extension sessions can be used uniformly with passkey/local-key sessions.

use async_trait::async_trait;
use nostr_bbs_core::signer::{Signer, SignerError};
use nostr_bbs_core::{NostrEvent, UnsignedEvent};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// Check if a NIP-07 browser extension is available (`window.nostr` exists).
pub fn has_nip07_extension() -> bool {
    if let Some(window) = web_sys::window() {
        match js_sys::Reflect::get(&window, &"nostr".into()) {
            Ok(val) => !val.is_undefined() && !val.is_null(),
            Err(_) => false,
        }
    } else {
        false
    }
}

/// Get the extension name if available (checks common extension identifiers).
pub fn get_extension_name() -> Option<String> {
    let window = web_sys::window()?;
    let nostr = js_sys::Reflect::get(&window, &"nostr".into()).ok()?;
    if nostr.is_undefined() || nostr.is_null() {
        return None;
    }
    // Try to read a name property (some extensions expose this)
    if let Ok(name) = js_sys::Reflect::get(&nostr, &"name".into()) {
        if let Some(s) = name.as_string() {
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    Some("NIP-07 Extension".to_string())
}

/// Get the public key from the NIP-07 extension.
///
/// Calls `window.nostr.getPublicKey()` which returns a Promise resolving
/// to a hex-encoded x-only public key string.
pub async fn nip07_get_pubkey() -> Result<String, String> {
    let window = web_sys::window().ok_or("No window object")?;
    let nostr =
        js_sys::Reflect::get(&window, &"nostr".into()).map_err(|_| "window.nostr not found")?;
    if nostr.is_undefined() || nostr.is_null() {
        return Err("NIP-07 extension not available".to_string());
    }

    let get_pk_fn = js_sys::Reflect::get(&nostr, &"getPublicKey".into())
        .map_err(|_| "getPublicKey not found on window.nostr")?;
    let get_pk_fn: js_sys::Function = get_pk_fn
        .dyn_into()
        .map_err(|_| "getPublicKey is not a function")?;

    let promise = get_pk_fn
        .call0(&nostr)
        .map_err(|e| format!("getPublicKey() call failed: {:?}", e))?;
    let promise: js_sys::Promise = promise
        .dyn_into()
        .map_err(|_| "getPublicKey() did not return a Promise")?;

    let result = JsFuture::from(promise)
        .await
        .map_err(|e| format!("getPublicKey() rejected: {:?}", e))?;

    result
        .as_string()
        .ok_or_else(|| "getPublicKey() did not return a string".to_string())
}

/// Sign an unsigned Nostr event using the NIP-07 extension.
///
/// Passes the unsigned event fields to `window.nostr.signEvent()`, which
/// computes the event ID, signs with the extension's private key, and
/// returns a fully signed `NostrEvent`.
pub async fn nip07_sign_event(event: &UnsignedEvent) -> Result<NostrEvent, String> {
    let window = web_sys::window().ok_or("No window object")?;
    let nostr =
        js_sys::Reflect::get(&window, &"nostr".into()).map_err(|_| "window.nostr not found")?;
    if nostr.is_undefined() || nostr.is_null() {
        return Err("NIP-07 extension not available".to_string());
    }

    // Build the unsigned event JS object (NIP-07 expects {kind, content, tags, created_at})
    let event_json =
        serde_json::to_string(event).map_err(|e| format!("Failed to serialize event: {e}"))?;
    let event_js: JsValue =
        js_sys::JSON::parse(&event_json).map_err(|_| "Failed to parse event as JS object")?;

    let sign_fn = js_sys::Reflect::get(&nostr, &"signEvent".into())
        .map_err(|_| "signEvent not found on window.nostr")?;
    let sign_fn: js_sys::Function = sign_fn
        .dyn_into()
        .map_err(|_| "signEvent is not a function")?;

    let promise = sign_fn
        .call1(&nostr, &event_js)
        .map_err(|e| format!("signEvent() call failed: {:?}", e))?;
    let promise: js_sys::Promise = promise
        .dyn_into()
        .map_err(|_| "signEvent() did not return a Promise")?;

    let result = JsFuture::from(promise)
        .await
        .map_err(|e| format!("signEvent() rejected: {:?}", e))?;

    let result_json =
        js_sys::JSON::stringify(&result).map_err(|_| "Failed to stringify signed event")?;
    let result_str = result_json
        .as_string()
        .ok_or("Signed event is not a string")?;

    serde_json::from_str::<NostrEvent>(&result_str)
        .map_err(|e| format!("Failed to parse signed event: {e}"))
}

// ── Nip07Signer ──────────────────────────────────────────────────────────────

/// A [`Signer`] that delegates all cryptographic operations to a NIP-07 browser
/// extension (`window.nostr`). No private key is ever exposed to the app.
pub struct Nip07Signer {
    pub(super) pubkey_hex: String,
}

impl Nip07Signer {
    /// Attempt to connect to `window.nostr` and retrieve the pubkey.
    ///
    /// Returns an error if the extension is not available or the user rejects
    /// the pubkey request.
    pub async fn try_connect() -> Result<Self, String> {
        if !has_nip07_extension() {
            return Err(
                "window.nostr not available — install a NIP-07 extension such as Alby or nos2x"
                    .to_string(),
            );
        }
        let pubkey_hex = nip07_get_pubkey().await?;
        Ok(Self { pubkey_hex })
    }

    /// Create a Nip07Signer directly from a known pubkey (e.g. for session restore).
    pub fn from_pubkey(pubkey_hex: String) -> Self {
        Self { pubkey_hex }
    }
}

#[async_trait(?Send)]
impl Signer for Nip07Signer {
    fn public_key(&self) -> &str {
        &self.pubkey_hex
    }

    async fn sign_event(&self, unsigned: UnsignedEvent) -> Result<NostrEvent, SignerError> {
        nip07_sign_event(&unsigned)
            .await
            .map_err(SignerError::Backend)
    }

    async fn nip44_encrypt(
        &self,
        recipient_pubkey_hex: &str,
        plaintext: &str,
    ) -> Result<String, SignerError> {
        nip07_nip44_encrypt(recipient_pubkey_hex, plaintext)
            .await
            .map_err(SignerError::EncryptionFailed)
    }

    async fn nip44_decrypt(
        &self,
        sender_pubkey_hex: &str,
        ciphertext: &str,
    ) -> Result<String, SignerError> {
        nip07_nip44_decrypt(sender_pubkey_hex, ciphertext)
            .await
            .map_err(SignerError::DecryptionFailed)
    }

    async fn nip04_encrypt(
        &self,
        recipient_pubkey_hex: &str,
        plaintext: &str,
    ) -> Result<String, SignerError> {
        // Fall back to NIP-44 if NIP-04 is not available
        nip07_nip44_encrypt(recipient_pubkey_hex, plaintext)
            .await
            .map_err(SignerError::EncryptionFailed)
    }

    async fn nip04_decrypt(
        &self,
        sender_pubkey_hex: &str,
        ciphertext: &str,
    ) -> Result<String, SignerError> {
        nip07_nip44_decrypt(sender_pubkey_hex, ciphertext)
            .await
            .map_err(SignerError::DecryptionFailed)
    }
}

/// NIP-44 encrypt via `window.nostr.nip44.encrypt(pubkey, plaintext)`.
async fn nip07_nip44_encrypt(
    recipient_pubkey_hex: &str,
    plaintext: &str,
) -> Result<String, String> {
    let window = web_sys::window().ok_or("No window object")?;
    let nostr =
        js_sys::Reflect::get(&window, &"nostr".into()).map_err(|_| "window.nostr not found")?;
    if nostr.is_undefined() || nostr.is_null() {
        return Err("NIP-07 extension not available".to_string());
    }

    let nip44 = js_sys::Reflect::get(&nostr, &"nip44".into())
        .map_err(|_| "window.nostr.nip44 not found")?;
    if nip44.is_undefined() || nip44.is_null() {
        return Err("window.nostr.nip44 not supported by this extension".to_string());
    }

    let encrypt_fn = js_sys::Reflect::get(&nip44, &"encrypt".into())
        .map_err(|_| "window.nostr.nip44.encrypt not found")?;
    let encrypt_fn: js_sys::Function = encrypt_fn
        .dyn_into()
        .map_err(|_| "nip44.encrypt is not a function")?;

    let promise = encrypt_fn
        .call2(
            &nip44,
            &JsValue::from_str(recipient_pubkey_hex),
            &JsValue::from_str(plaintext),
        )
        .map_err(|e| format!("nip44.encrypt() call failed: {:?}", e))?;
    let promise: js_sys::Promise = promise
        .dyn_into()
        .map_err(|_| "nip44.encrypt() did not return a Promise")?;

    let result = JsFuture::from(promise)
        .await
        .map_err(|e| format!("nip44.encrypt() rejected: {:?}", e))?;

    result
        .as_string()
        .ok_or_else(|| "nip44.encrypt() did not return a string".to_string())
}

/// NIP-44 decrypt via `window.nostr.nip44.decrypt(pubkey, ciphertext)`.
async fn nip07_nip44_decrypt(sender_pubkey_hex: &str, ciphertext: &str) -> Result<String, String> {
    let window = web_sys::window().ok_or("No window object")?;
    let nostr =
        js_sys::Reflect::get(&window, &"nostr".into()).map_err(|_| "window.nostr not found")?;
    if nostr.is_undefined() || nostr.is_null() {
        return Err("NIP-07 extension not available".to_string());
    }

    let nip44 = js_sys::Reflect::get(&nostr, &"nip44".into())
        .map_err(|_| "window.nostr.nip44 not found")?;
    if nip44.is_undefined() || nip44.is_null() {
        return Err("window.nostr.nip44 not supported by this extension".to_string());
    }

    let decrypt_fn = js_sys::Reflect::get(&nip44, &"decrypt".into())
        .map_err(|_| "window.nostr.nip44.decrypt not found")?;
    let decrypt_fn: js_sys::Function = decrypt_fn
        .dyn_into()
        .map_err(|_| "nip44.decrypt is not a function")?;

    let promise = decrypt_fn
        .call2(
            &nip44,
            &JsValue::from_str(sender_pubkey_hex),
            &JsValue::from_str(ciphertext),
        )
        .map_err(|e| format!("nip44.decrypt() call failed: {:?}", e))?;
    let promise: js_sys::Promise = promise
        .dyn_into()
        .map_err(|_| "nip44.decrypt() did not return a Promise")?;

    let result = JsFuture::from(promise)
        .await
        .map_err(|e| format!("nip44.decrypt() rejected: {:?}", e))?;

    result
        .as_string()
        .ok_or_else(|| "nip44.decrypt() did not return a string".to_string())
}
