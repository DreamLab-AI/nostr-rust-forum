//! Durable key "bake" for the zone-bound BBS PWA install (ADR-109, Decision #2).
//!
//! WRITE side of the shared contract in [`nostr_bbs_core::boot_profile`]. When a
//! single-locked-zone member consents to installing the BBS as a home-screen app,
//! this module persists their existing secp256k1 secret into **origin storage**,
//! encrypted at rest, so the installed app can adopt it on launch without a
//! password (Android/desktop) or after a one-time rebind (iOS).
//!
//! What lands on disk (all referencing ONLY `nostr_bbs_core` constants so the
//! BBS unwrap path matches byte-for-byte):
//! - A **non-extractable** AES-GCM `CryptoKey` (`extractable: false`, so
//!   `exportKey`/`wrapKey` throw and the raw AES bytes never reach JS), stored
//!   as a live structured-clone handle in IndexedDB `BAKED_DB`/`BAKED_STORE`
//!   under `BAKED_RECORD_ID`.
//! - The AES-GCM ciphertext of the 32-byte secret ([`WrappedKeyEnvelope`],
//!   per-record random 12-byte IV), stored in the same record.
//! - A non-secret [`BootProfile`] in localStorage (`BOOTPROFILE_KEY`) naming the
//!   bound zone and bake time — the BBS boot reads it to enter one-shot mode.
//!
//! **Threat model (honest, per ADR-109).** The non-extractable wrap defeats only
//! passive offline/backup forensic dumps. Same-origin XSS and an unlocked device
//! are full compromise — WebCrypto does not protect against XSS. The consent copy
//! states this plainly; CSP/Trusted Types are separate hardening.
//!
//! wasm-only: every call touches `web-sys` Crypto/SubtleCrypto/IndexedDB. Pure
//! helpers (hex envelope, boot-profile construction) are unit-tested below.

use gloo::storage::{LocalStorage, Storage};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    IdbDatabase, IdbObjectStoreParameters, IdbOpenDbRequest, IdbRequest, IdbTransactionMode,
};

use nostr_bbs_core::{
    BootProfile, WrappedKeyEnvelope, AES_ALG, AES_IV_LEN, AES_KEY_BITS, BAKED_DB, BAKED_RECORD_ID,
    BAKED_STORE, BOOTPROFILE_KEY,
};

/// Field names inside the IndexedDB record (local to this crate + the BBS
/// unwrap path; not part of the cross-crate wire contract, but kept in sync
/// with `nostr-bbs-bbs-client::pwa`).
const REC_ID: &str = "id";
const REC_WRAP_KEY: &str = "wrapKey";
const REC_ENVELOPE: &str = "envelope";
const ENV_IV_HEX: &str = "iv_hex";
const ENV_CT_HEX: &str = "ct_hex";

/// IndexedDB schema version for `BAKED_DB`.
const BAKED_DB_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failure modes of the bake / unbake flow. `Js(_)` carries the debug-formatted
/// browser error for the console; the UI shows a friendly message instead.
#[derive(Debug, thiserror::Error)]
pub enum BakeError {
    /// No `window`/`crypto`/`subtle` available (non-browser or locked-down env).
    #[error("browser crypto unavailable")]
    NoCrypto,
    /// A WebCrypto or IndexedDB call rejected. Carries the debug string.
    #[error("bake operation failed: {0}")]
    Js(String),
    /// The BootProfile could not be serialized or written to localStorage.
    #[error("failed to persist boot profile: {0}")]
    Storage(String),
}

fn js_err(v: JsValue) -> BakeError {
    BakeError::Js(format!("{v:?}"))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Bake `secret` (the caller's 32-byte secp256k1 key) into origin storage bound
/// to `zone_id`. Idempotent per origin: re-baking overwrites the single record.
///
/// The caller reads the secret from `AuthStore::get_privkey_bytes()` (a
/// `Zeroizing<[u8; 32]>`) at the call site — this function never re-reads
/// `nostr_bbs_sk`. `secret` is only borrowed; wasm-bindgen copies it across the
/// JS boundary for the one `encrypt` call and the plaintext never lands in a
/// durable buffer here.
pub async fn bake(secret: &[u8; 32], zone_id: &str) -> Result<(), BakeError> {
    let crypto = web_sys::window()
        .and_then(|w| w.crypto().ok())
        .ok_or(BakeError::NoCrypto)?;
    let subtle = crypto.subtle();

    // (1) Non-extractable AES-256-GCM wrapping key.
    let gen_algo = js_object(&[(&"name".into(), &AES_ALG.into())]);
    js_sys::Reflect::set(&gen_algo, &"length".into(), &JsValue::from(AES_KEY_BITS))
        .map_err(js_err)?;
    let usages = js_sys::Array::of2(&"encrypt".into(), &"decrypt".into());
    let key_promise = subtle
        .generate_key_with_object(&gen_algo, false, &usages)
        .map_err(js_err)?;
    let wrap_key = JsFuture::from(key_promise).await.map_err(js_err)?;
    let wrap_key: web_sys::CryptoKey = wrap_key.dyn_into().map_err(js_err)?;

    // (2) Per-record random 12-byte IV.
    let mut iv = [0u8; AES_IV_LEN];
    crypto
        .get_random_values_with_u8_array(&mut iv)
        .map_err(js_err)?;

    // (3) AES-GCM encrypt of the raw secret → ciphertext (secret + GCM tag).
    let enc_algo = js_object(&[(&"name".into(), &AES_ALG.into())]);
    let iv_view = js_sys::Uint8Array::from(&iv[..]);
    js_sys::Reflect::set(&enc_algo, &"iv".into(), &iv_view).map_err(js_err)?;
    let ct_promise = subtle
        .encrypt_with_object_and_u8_array(&enc_algo, &wrap_key, &secret[..])
        .map_err(js_err)?;
    let ct_buf = JsFuture::from(ct_promise).await.map_err(js_err)?;
    let ct = js_sys::Uint8Array::new(&ct_buf).to_vec();

    let envelope = WrappedKeyEnvelope {
        iv_hex: hex::encode(iv),
        ct_hex: hex::encode(&ct),
    };

    // (4) Persist the live CryptoKey handle + ciphertext in IndexedDB. The key
    // is stored as a structured-clone handle (preserves non-extractable), never
    // as bytes.
    let db = open_baked_db().await.map_err(js_err)?;
    put_record(&db, &wrap_key, &envelope)
        .await
        .map_err(js_err)?;
    db.close();

    // (5) BootProfile last — its presence in localStorage is the "installed"
    // signal the BBS boot and this crate's `is_baked()` key off.
    let profile = BootProfile::new(zone_id.to_string(), js_now_secs());
    let json = serde_json::to_string(&profile).map_err(|e| BakeError::Storage(e.to_string()))?;
    LocalStorage::set(BOOTPROFILE_KEY, json).map_err(|e| BakeError::Storage(format!("{e:?}")))?;

    Ok(())
}

/// Forum-side "Forget this device": delete the baked IndexedDB record and the
/// localStorage BootProfile. BootProfile is removed first so a mid-failure never
/// leaves the app booting one-shot with no key to adopt.
pub async fn unbake() -> Result<(), BakeError> {
    // Remove the boot trigger first (best-effort, sync).
    LocalStorage::delete(BOOTPROFILE_KEY);

    let db = open_baked_db().await.map_err(js_err)?;
    let tx = db
        .transaction_with_str_and_mode(BAKED_STORE, IdbTransactionMode::Readwrite)
        .map_err(js_err)?;
    let store = tx.object_store(BAKED_STORE).map_err(js_err)?;
    let req = store
        .delete(&JsValue::from_str(BAKED_RECORD_ID))
        .map_err(js_err)?;
    idb_await(&req).await.map_err(js_err)?;
    db.close();
    Ok(())
}

/// Whether this origin currently carries a valid bake.
///
/// Keys off the localStorage BootProfile — cheap, synchronous under the hood,
/// and written last by [`bake`] / removed first by [`unbake`], so its presence
/// implies the IndexedDB key record is (or was) present. Avoids creating an
/// empty `BAKED_DB` on devices that never installed.
pub async fn is_baked() -> bool {
    LocalStorage::get::<String>(BOOTPROFILE_KEY)
        .ok()
        .and_then(|json| nostr_bbs_core::parse_boot_profile(&json))
        .is_some()
}

/// READ side for the forum's own `?pwa=1` one-shot boot: decrypt and return
/// the baked 32-byte secret, or `None` when nothing usable is stored.
///
/// Mirrors `nostr-bbs-bbs-client::pwa::unwrap_baked_secret` byte-for-byte
/// (same record shape, same Reflect-built AES-GCM params as [`bake`]), so a
/// key baked for either interface adopts in both — the installed app choice
/// is purely which manifest the user installed from. Failures are quiet
/// (`None`): the caller falls back to the normal login page.
pub async fn adopt_baked_secret() -> Option<zeroize::Zeroizing<[u8; 32]>> {
    use zeroize::Zeroize;

    let db = open_baked_db().await.ok()?;
    let tx = db.transaction_with_str(BAKED_STORE).ok()?;
    let store = tx.object_store(BAKED_STORE).ok()?;
    let req = store.get(&JsValue::from_str(BAKED_RECORD_ID)).ok()?;
    let record = idb_await(&req).await.ok()?;
    db.close();
    if record.is_undefined() || record.is_null() {
        return None;
    }

    let envelope = js_sys::Reflect::get(&record, &REC_ENVELOPE.into()).ok()?;
    let iv_hex = js_sys::Reflect::get(&envelope, &ENV_IV_HEX.into())
        .ok()?
        .as_string()?;
    let ct_hex = js_sys::Reflect::get(&envelope, &ENV_CT_HEX.into())
        .ok()?
        .as_string()?;
    let iv = hex::decode(&iv_hex).ok()?;
    let mut ct = hex::decode(&ct_hex).ok()?;
    if iv.len() != AES_IV_LEN {
        ct.zeroize();
        return None;
    }

    let wrap_key: web_sys::CryptoKey = js_sys::Reflect::get(&record, &REC_WRAP_KEY.into())
        .ok()?
        .dyn_into()
        .ok()?;

    let crypto = web_sys::window()?.crypto().ok()?;
    let subtle = crypto.subtle();
    let dec_algo = js_object(&[(&"name".into(), &AES_ALG.into())]);
    let iv_view = js_sys::Uint8Array::from(&iv[..]);
    js_sys::Reflect::set(&dec_algo, &"iv".into(), &iv_view).ok()?;

    let promise = match subtle.decrypt_with_object_and_u8_array(&dec_algo, &wrap_key, &ct) {
        Ok(p) => p,
        Err(_) => {
            ct.zeroize();
            return None;
        }
    };
    let plain_js = match JsFuture::from(promise).await {
        Ok(v) => v,
        Err(_) => {
            ct.zeroize();
            return None;
        }
    };
    ct.zeroize();

    let mut vec = js_sys::Uint8Array::new(&plain_js).to_vec();
    if vec.len() != 32 {
        vec.zeroize();
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&vec);
    vec.zeroize();
    Some(zeroize::Zeroizing::new(out))
}

// ---------------------------------------------------------------------------
// IndexedDB plumbing (mirrors stores::indexed_db, scoped to the baked-key DB)
// ---------------------------------------------------------------------------

/// Build a JS object from `(key, value)` pairs. Panics only on an impossible
/// `Reflect::set` failure on a fresh object (never in practice).
fn js_object(pairs: &[(&JsValue, &JsValue)]) -> js_sys::Object {
    let obj = js_sys::Object::new();
    for (k, v) in pairs {
        let _ = js_sys::Reflect::set(&obj, k, v);
    }
    obj
}

/// Current unix time in seconds (BootProfile `created_at`).
fn js_now_secs() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}

/// Resolve an `IdbRequest` to its result once `onsuccess`/`onerror` fires.
async fn idb_await(request: &IdbRequest) -> Result<JsValue, JsValue> {
    let promise = js_sys::Promise::new(&mut |resolve, reject| {
        let req_ok = request.clone();
        let on_success = Closure::once(move |_: web_sys::Event| {
            let result = req_ok.result().unwrap_or(JsValue::UNDEFINED);
            let _ = resolve.call1(&JsValue::NULL, &result);
        });
        let req_err = request.clone();
        let on_error = Closure::once(move |_: web_sys::Event| {
            let err = req_err
                .error()
                .ok()
                .flatten()
                .map(JsValue::from)
                .unwrap_or_else(|| JsValue::from_str("IDB request failed"));
            let _ = reject.call1(&JsValue::NULL, &err);
        });
        request.set_onsuccess(Some(on_success.as_ref().unchecked_ref()));
        request.set_onerror(Some(on_error.as_ref().unchecked_ref()));
        on_success.forget();
        on_error.forget();
    });
    JsFuture::from(promise).await
}

/// Open (or create) `BAKED_DB`, creating the `BAKED_STORE` object store with an
/// out-of-line key on `onupgradeneeded`.
async fn open_baked_db() -> Result<IdbDatabase, JsValue> {
    let factory = web_sys::window()
        .ok_or_else(|| JsValue::from_str("no window"))?
        .indexed_db()?
        .ok_or_else(|| JsValue::from_str("IndexedDB unavailable"))?;
    let request: IdbOpenDbRequest = factory.open_with_u32(BAKED_DB, BAKED_DB_VERSION)?;

    let upgrade = Closure::once(move |event: web_sys::Event| {
        let Some(target) = event.target() else { return };
        let Ok(open_req) = target.dyn_into::<IdbOpenDbRequest>() else {
            return;
        };
        let Ok(result) = open_req.result() else {
            return;
        };
        let Ok(db) = result.dyn_into::<IdbDatabase>() else {
            return;
        };
        if !db.object_store_names().contains(BAKED_STORE) {
            // Out-of-line key (no keyPath); records are put with an explicit key.
            let params = IdbObjectStoreParameters::new();
            if let Err(e) = db.create_object_store_with_optional_parameters(BAKED_STORE, &params) {
                web_sys::console::warn_1(
                    &format!("[bake] create_object_store failed: {e:?}").into(),
                );
            }
        }
    });
    request.set_onupgradeneeded(Some(upgrade.as_ref().unchecked_ref()));
    upgrade.forget();

    let db = idb_await(request.as_ref()).await?;
    db.dyn_into::<IdbDatabase>()
        .map_err(|_| JsValue::from_str("open() did not return IdbDatabase"))
}

/// Put the `{ id, wrapKey, envelope }` record under `BAKED_RECORD_ID`.
async fn put_record(
    db: &IdbDatabase,
    wrap_key: &web_sys::CryptoKey,
    envelope: &WrappedKeyEnvelope,
) -> Result<(), JsValue> {
    let tx = db.transaction_with_str_and_mode(BAKED_STORE, IdbTransactionMode::Readwrite)?;
    let store = tx.object_store(BAKED_STORE)?;

    let env_obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &env_obj,
        &ENV_IV_HEX.into(),
        &envelope.iv_hex.as_str().into(),
    )?;
    js_sys::Reflect::set(
        &env_obj,
        &ENV_CT_HEX.into(),
        &envelope.ct_hex.as_str().into(),
    )?;

    let record = js_sys::Object::new();
    js_sys::Reflect::set(&record, &REC_ID.into(), &BAKED_RECORD_ID.into())?;
    js_sys::Reflect::set(&record, &REC_WRAP_KEY.into(), wrap_key.as_ref())?;
    js_sys::Reflect::set(&record, &REC_ENVELOPE.into(), &env_obj)?;

    let req = store.put_with_key(&record, &JsValue::from_str(BAKED_RECORD_ID))?;
    idb_await(&req).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests (pure helpers only — the WebCrypto path is wasm-only, covered by the
// browser QE smoke in the plan's test matrix)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_hex_roundtrip() {
        // A 12-byte IV and a 48-byte ciphertext (32-byte secret + 16-byte tag).
        let iv = [0x1au8; AES_IV_LEN];
        let ct: Vec<u8> = (0u8..48).collect();
        let env = WrappedKeyEnvelope {
            iv_hex: hex::encode(iv),
            ct_hex: hex::encode(&ct),
        };
        assert_eq!(env.iv_hex.len(), AES_IV_LEN * 2);
        assert_eq!(env.ct_hex.len(), 48 * 2);
        assert_eq!(hex::decode(&env.iv_hex).unwrap(), iv);
        assert_eq!(hex::decode(&env.ct_hex).unwrap(), ct);
    }

    #[test]
    fn boot_profile_from_zone_id_is_valid() {
        let p = BootProfile::new("minimoonoir".to_string(), 1_784_000_000);
        assert!(p.validate());
        assert_eq!(p.zone, "minimoonoir");
        // Round-trips through the same serde the bake writes to localStorage.
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(nostr_bbs_core::parse_boot_profile(&json), Some(p));
    }
}
