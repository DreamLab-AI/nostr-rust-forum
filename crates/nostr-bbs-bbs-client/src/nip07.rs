//! NIP-07 browser-extension signing for the retro BBS.
//!
//! A self-contained mirror of the forum client's `auth::nip07`
//! (`nostr-bbs-forum-client/src/auth/nip07.rs`): a [`Signer`] that delegates
//! every cryptographic operation to a NIP-07 browser extension (`window.nostr`
//! — PodKey, nos2x, Alby). The private key never enters the web app, so a viewer
//! who signed in at `/community/` with a passkey/PodKey extension can sign, post,
//! and govern in the BBS without exposing any key material.
//!
//! The `window.nostr` interop is duplicated here rather than lifted into
//! `nostr-bbs-core` because core carries no `web-sys` / `wasm-bindgen-futures`
//! dependency and is compiled to wasm32 by all five Cloudflare Workers — pushing
//! a DOM-facing `web-sys` surface into core risks those worker builds. No
//! cryptography or bech32 is (re)implemented here: the signature is produced
//! inside the extension. The JS bridging is wasm-only; native builds (unit tests)
//! see stubs so the crate still compiles and the pure logic stays testable.

use async_trait::async_trait;
use nostr_bbs_core::signer::{Signer, SignerError};
use nostr_bbs_core::{NostrEvent, UnsignedEvent};

/// Whether a NIP-07 browser extension is available (`window.nostr` exists).
///
/// Always `false` off-wasm — a native unit-test build has no `window`.
#[cfg(target_arch = "wasm32")]
pub fn has_nip07_extension() -> bool {
    web_sys::window()
        .and_then(|w| js_sys::Reflect::get(&w, &"nostr".into()).ok())
        .map(|v| !v.is_undefined() && !v.is_null())
        .unwrap_or(false)
}

/// Native fallback: no browser extension off-wasm.
#[cfg(not(target_arch = "wasm32"))]
pub fn has_nip07_extension() -> bool {
    false
}

/// Get the public key from the NIP-07 extension.
///
/// Calls `window.nostr.getPublicKey()` (a Promise resolving to a hex-encoded
/// x-only public key string).
#[cfg(target_arch = "wasm32")]
pub async fn nip07_get_pubkey() -> Result<String, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;

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

/// Native fallback: no extension to query off-wasm.
#[cfg(not(target_arch = "wasm32"))]
pub async fn nip07_get_pubkey() -> Result<String, String> {
    Err("NIP-07 extension not available off-wasm".to_string())
}

// ── Nip07Signer ──────────────────────────────────────────────────────────────

/// A [`Signer`] that delegates all cryptographic operations to a NIP-07 browser
/// extension (`window.nostr`). No private key is ever exposed to the app; each
/// `sign_event` surfaces the extension's approval prompt.
pub struct Nip07Signer {
    pubkey_hex: String,
}

impl Nip07Signer {
    /// Create a `Nip07Signer` from a known x-only pubkey (hex). The pubkey is
    /// obtained once via [`nip07_get_pubkey`] (extension sign-in) or read from
    /// the adopted forum session; signing thereafter routes through the same
    /// `window.nostr` provider.
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
        // Fall back to NIP-44 if the extension exposes no NIP-04 surface.
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

// ── window.nostr interop (wasm) / native stubs ───────────────────────────────

/// Sign an unsigned event via `window.nostr.signEvent()`, which computes the id,
/// signs with the extension's key, and returns a fully signed `NostrEvent`.
#[cfg(target_arch = "wasm32")]
async fn nip07_sign_event(event: &UnsignedEvent) -> Result<NostrEvent, String> {
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    let window = web_sys::window().ok_or("No window object")?;
    let nostr =
        js_sys::Reflect::get(&window, &"nostr".into()).map_err(|_| "window.nostr not found")?;
    if nostr.is_undefined() || nostr.is_null() {
        return Err("NIP-07 extension not available".to_string());
    }

    // NIP-07 expects an unsigned {kind, content, tags, created_at, pubkey} object.
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

    // A user-rejected prompt rejects this Promise → propagated as Err (fail-closed).
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

#[cfg(not(target_arch = "wasm32"))]
async fn nip07_sign_event(_event: &UnsignedEvent) -> Result<NostrEvent, String> {
    Err("NIP-07 signing unavailable off-wasm".to_string())
}

/// NIP-44 encrypt via `window.nostr.nip44.encrypt(pubkey, plaintext)`.
#[cfg(target_arch = "wasm32")]
async fn nip07_nip44_encrypt(
    recipient_pubkey_hex: &str,
    plaintext: &str,
) -> Result<String, String> {
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

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

#[cfg(not(target_arch = "wasm32"))]
async fn nip07_nip44_encrypt(
    _recipient_pubkey_hex: &str,
    _plaintext: &str,
) -> Result<String, String> {
    Err("NIP-07 nip44 encrypt unavailable off-wasm".to_string())
}

/// NIP-44 decrypt via `window.nostr.nip44.decrypt(pubkey, ciphertext)`.
#[cfg(target_arch = "wasm32")]
async fn nip07_nip44_decrypt(sender_pubkey_hex: &str, ciphertext: &str) -> Result<String, String> {
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

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

#[cfg(not(target_arch = "wasm32"))]
async fn nip07_nip44_decrypt(
    _sender_pubkey_hex: &str,
    _ciphertext: &str,
) -> Result<String, String> {
    Err("NIP-07 nip44 decrypt unavailable off-wasm".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_pubkey_exposes_public_key() {
        let pk = "ab".repeat(32);
        let signer = Nip07Signer::from_pubkey(pk.clone());
        assert_eq!(signer.public_key(), pk);
    }

    #[test]
    fn has_extension_is_false_off_wasm() {
        // Native builds have no `window.nostr`; must fail closed so the BBS
        // never offers an extension sign-in that cannot work.
        assert!(!has_nip07_extension());
    }
}
