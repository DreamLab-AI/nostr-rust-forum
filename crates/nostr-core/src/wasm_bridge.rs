//! wasm-bindgen JS bridge exposing nostr-core functions to JavaScript.
//!
//! Compiled only for `wasm32` targets. Each function maps directly to a
//! nostr-core API, converting between JS-friendly types and Rust internals.

use wasm_bindgen::prelude::*;

use crate::event::{compute_event_id as compute_id_inner, UnsignedEvent};
use crate::keys;
use crate::nip44;
use crate::nip98;

// ── NIP-44 ──────────────────────────────────────────────────────────────────

/// Encrypt a plaintext string from sender to recipient using NIP-44 v2.
///
/// Returns base64-encoded ciphertext.
#[wasm_bindgen]
pub fn nip44_encrypt(
    sender_sk: &[u8],
    recipient_pk: &[u8],
    plaintext: &str,
) -> Result<String, JsValue> {
    let sk: [u8; 32] = sender_sk
        .try_into()
        .map_err(|_| JsValue::from_str("sender_sk must be 32 bytes"))?;
    let pk: [u8; 32] = recipient_pk
        .try_into()
        .map_err(|_| JsValue::from_str("recipient_pk must be 32 bytes"))?;
    nip44::encrypt(&sk, &pk, plaintext).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Decrypt a base64-encoded NIP-44 v2 ciphertext.
///
/// Returns the plaintext string.
#[wasm_bindgen]
pub fn nip44_decrypt(
    recipient_sk: &[u8],
    sender_pk: &[u8],
    ciphertext: &str,
) -> Result<String, JsValue> {
    let sk: [u8; 32] = recipient_sk
        .try_into()
        .map_err(|_| JsValue::from_str("recipient_sk must be 32 bytes"))?;
    let pk: [u8; 32] = sender_pk
        .try_into()
        .map_err(|_| JsValue::from_str("sender_pk must be 32 bytes"))?;
    nip44::decrypt(&sk, &pk, ciphertext).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ── Key derivation ──────────────────────────────────────────────────────────

/// Derive a Nostr keypair from WebAuthn PRF output using HKDF-SHA-256.
///
/// Returns a JS object `{ secretKey: Uint8Array(32), publicKey: string }`.
#[wasm_bindgen]
pub fn derive_keypair_from_prf(prf_output: &[u8]) -> Result<JsValue, JsValue> {
    let prf: [u8; 32] = prf_output
        .try_into()
        .map_err(|_| JsValue::from_str("prf_output must be 32 bytes"))?;
    let kp = keys::derive_from_prf(&prf).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let obj = js_sys::Object::new();
    let sk_array = js_sys::Uint8Array::from(kp.secret.as_bytes().as_slice());
    js_sys::Reflect::set(&obj, &"secretKey".into(), &sk_array)?;
    js_sys::Reflect::set(&obj, &"publicKey".into(), &kp.public.to_hex().into())?;
    Ok(obj.into())
}

// ── NIP-98 ──────────────────────────────────────────────────────────────────

/// Create a NIP-98 authorization token for an HTTP request.
///
/// `created_at` is a Unix timestamp (seconds). In browser, pass `Math.floor(Date.now() / 1000)`.
/// Returns a base64-encoded JSON string for `Authorization: Nostr <token>`.
#[wasm_bindgen]
pub fn create_nip98_token(
    secret_key: &[u8],
    url: &str,
    method: &str,
    body: Option<Vec<u8>>,
    created_at: Option<u32>,
) -> Result<String, JsValue> {
    let sk: [u8; 32] = secret_key
        .try_into()
        .map_err(|_| JsValue::from_str("secret_key must be 32 bytes"))?;
    let ts = created_at
        .map(|t| t as u64)
        .unwrap_or_else(|| (js_sys::Date::now() / 1000.0) as u64);
    nip98::create_token_at(&sk, url, method, body.as_deref(), ts)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Verify a NIP-98 `Authorization` header value.
///
/// Returns a JS object `{ pubkey, url, method, payloadHash, createdAt }`.
#[wasm_bindgen]
pub fn verify_nip98_token(
    auth_header: &str,
    url: &str,
    method: &str,
    body: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    let token = nip98::verify_token(auth_header, url, method, body.as_deref())
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    nip98_token_to_js(&token)
}

/// Verify a NIP-98 `Authorization` header value against an explicit Unix timestamp.
///
/// Use this variant in environments where you need deterministic timestamp
/// control (e.g. tests, replayed requests). `now` is Unix seconds.
///
/// Returns a JS object `{ pubkey, url, method, payloadHash, createdAt }`.
#[wasm_bindgen]
pub fn verify_nip98_token_at(
    auth_header: &str,
    url: &str,
    method: &str,
    body: Option<Vec<u8>>,
    now: u32,
) -> Result<JsValue, JsValue> {
    let token = nip98::verify_token_at(auth_header, url, method, body.as_deref(), now as u64)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    nip98_token_to_js(&token)
}

/// Convert a verified NIP-98 token to a JS object.
fn nip98_token_to_js(token: &nip98::Nip98Token) -> Result<JsValue, JsValue> {
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"pubkey".into(), &token.pubkey.clone().into())?;
    js_sys::Reflect::set(&obj, &"url".into(), &token.url.clone().into())?;
    js_sys::Reflect::set(&obj, &"method".into(), &token.method.clone().into())?;
    js_sys::Reflect::set(
        &obj,
        &"payloadHash".into(),
        &match &token.payload_hash {
            Some(h) => JsValue::from_str(h),
            None => JsValue::NULL,
        },
    )?;
    js_sys::Reflect::set(
        &obj,
        &"createdAt".into(),
        &JsValue::from_f64(token.created_at as f64),
    )?;
    Ok(obj.into())
}

// ── Event ID ────────────────────────────────────────────────────────────────

/// Compute the NIP-01 event ID (SHA-256 of canonical JSON).
///
/// Returns the 64-character hex event ID.
#[wasm_bindgen]
pub fn compute_event_id(
    pubkey: &str,
    created_at: u32,
    kind: u32,
    tags_json: &str,
    content: &str,
) -> Result<String, JsValue> {
    let tags: Vec<Vec<String>> =
        serde_json::from_str(tags_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let unsigned = UnsignedEvent {
        pubkey: pubkey.to_string(),
        created_at: created_at as u64,
        kind: kind as u64,
        tags,
        content: content.to_string(),
    };

    let id_bytes = compute_id_inner(&unsigned);
    Ok(hex::encode(id_bytes))
}

// ── Schnorr signing ─────────────────────────────────────────────────────────

/// Sign a message using BIP-340 Schnorr.
///
/// `secret_key` must be 32 bytes, `message` must be 32 bytes (pre-hashed).
/// Returns the 64-byte signature.
#[wasm_bindgen]
pub fn schnorr_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    let sk_bytes: [u8; 32] = secret_key
        .try_into()
        .map_err(|_| JsValue::from_str("secret_key must be 32 bytes"))?;
    let msg: [u8; 32] = message
        .try_into()
        .map_err(|_| JsValue::from_str("message must be 32 bytes"))?;

    let sk =
        keys::SecretKey::from_bytes(sk_bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let sig = sk
        .sign(&msg)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(sig.as_bytes().to_vec())
}

/// Verify a BIP-340 Schnorr signature.
///
/// `public_key` must be 32 bytes (x-only), `message` must be 32 bytes,
/// `signature` must be 64 bytes. Returns `true` if valid.
#[wasm_bindgen]
pub fn schnorr_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, JsValue> {
    let pk_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| JsValue::from_str("public_key must be 32 bytes"))?;
    let msg: [u8; 32] = message
        .try_into()
        .map_err(|_| JsValue::from_str("message must be 32 bytes"))?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| JsValue::from_str("signature must be 64 bytes"))?;

    let pk =
        keys::PublicKey::from_bytes(pk_bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let sig = keys::Signature::from_bytes(sig_bytes);
    match pk.verify(&msg, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Generate a new random Nostr keypair.
///
/// Returns `{ secretKey: Uint8Array(32), publicKey: string }`.
#[wasm_bindgen]
pub fn generate_keypair() -> Result<JsValue, JsValue> {
    let kp = keys::generate_keypair().map_err(|e| JsValue::from_str(&e.to_string()))?;
    let obj = js_sys::Object::new();
    let sk_array = js_sys::Uint8Array::from(kp.secret.as_bytes().as_slice());
    js_sys::Reflect::set(&obj, &"secretKey".into(), &sk_array)?;
    js_sys::Reflect::set(&obj, &"publicKey".into(), &kp.public.to_hex().into())?;
    Ok(obj.into())
}
