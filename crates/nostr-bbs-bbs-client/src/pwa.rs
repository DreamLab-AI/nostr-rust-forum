//! Zone-bound one-shot PWA — the BBS-side install surface + baked-key adoption
//! (ADR-109). The forum client *bakes* a device-resident key (WebCrypto AES-GCM
//! wrap of the 32-byte secret under a non-extractable `CryptoKey` in IndexedDB,
//! plus a non-secret [`BootProfile`] in localStorage); this module is the
//! *reader*: on an installed home-screen launch it unwraps that key and installs
//! the signer, or — on iOS's isolated installed-app storage, where nothing is
//! baked — routes to a one-time rebind and then re-bakes locally so subsequent
//! launches are one-shot.
//!
//! Every storage/crypto parameter comes from [`nostr_bbs_core`] constants so the
//! forum bake and this unwrap match byte-for-byte (a drift would silently boot
//! the installed app signed-out).
//!
//! Pure, unit-tested helpers ([`rebind_path`], [`resolve_boot_zone_index`],
//! [`decode_envelope_hex`], and the manifest-invariant tests) live alongside the
//! wasm-only ceremony so the boot logic is testable on the native target.

use nostr_bbs_config::schema::Zone;
use nostr_bbs_core::{BootProfile, AES_IV_LEN};

#[cfg(target_arch = "wasm32")]
use nostr_bbs_core::{
    WrappedKeyEnvelope, AES_ALG, AES_KEY_BITS, BAKED_DB, BAKED_RECORD_ID, BAKED_STORE,
    BOOTPROFILE_KEY,
};

#[cfg(target_arch = "wasm32")]
use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
use zeroize::Zeroize;

#[cfg(target_arch = "wasm32")]
use crate::config::BbsConfig;
#[cfg(target_arch = "wasm32")]
use crate::signer::BbsSigner;

// ── Pure helpers (unit-tested on the native target) ─────────────────────────

/// Which one-time rebind flow the isolated iOS first launch offers.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RebindPath {
    /// The account has a usable passkey — a single WebAuthn PRF tap re-derives the
    /// SAME identity (no secret crosses the Safari→app boundary).
    Passkey,
    /// No passkey usable here — paste the nsec / recovery key once; it is then
    /// baked into this app's isolated storage so later launches are one-shot.
    PasteRecoveryKey,
}

/// Choose the rebind flow. `has_passkey` is computed at the call site as
/// "passkey support present AND a pubkey is known to authenticate against"
/// (`passkey_authenticate` needs the pubkey — there is no discovery oracle).
pub fn rebind_path(has_passkey: bool) -> RebindPath {
    if has_passkey {
        RebindPath::Passkey
    } else {
        RebindPath::PasteRecoveryKey
    }
}

/// Resolve the `cfg.zones` index a PWA boot should pin to.
///
/// - With a [`BootProfile`] (Android/desktop carry-in, or a prior local re-bake):
///   resolve its bound zone id exactly via
///   [`nostr_bbs_core::resolve_pinned_zone_index`]. `None` when that zone was
///   renamed/removed since the bake → the caller falls back to an unpinned boot
///   (never a widened one; the relay stays the boundary).
/// - Without one (iOS first launch, before the local re-bake — the BootProfile
///   sits in the isolated Safari bucket): fall back to the **sole locked zone**
///   (exactly one zone with non-empty `required_cohorts`), or the sole zone when
///   the deployment has just one. This is the single-locked-zone operator the
///   feature targets; ambiguous multi-zone deployments resolve to `None`.
pub fn resolve_boot_zone_index(
    boot_profile: &Option<BootProfile>,
    zones: &[Zone],
) -> Option<usize> {
    if let Some(bp) = boot_profile {
        let ids: Vec<String> = zones.iter().map(|z| z.id.clone()).collect();
        return nostr_bbs_core::resolve_pinned_zone_index(&bp.zone, &ids);
    }
    let locked: Vec<usize> = zones
        .iter()
        .enumerate()
        .filter(|(_, z)| !z.required_cohorts.is_empty())
        .map(|(i, _)| i)
        .collect();
    if locked.len() == 1 {
        return Some(locked[0]);
    }
    if zones.len() == 1 {
        return Some(0);
    }
    None
}

/// Hex-decode a [`WrappedKeyEnvelope`] into `(iv, ciphertext)`, validating the IV
/// length against [`AES_IV_LEN`]. `None` on any malformed hex or a wrong-length
/// IV — a corrupt record must read as "not baked", never a decrypt attempt with
/// a bad IV. Pure so the codec boundary is testable off-wasm.
pub fn decode_envelope_hex(iv_hex: &str, ct_hex: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let iv = hex::decode(iv_hex).ok()?;
    if iv.len() != AES_IV_LEN {
        return None;
    }
    let ct = hex::decode(ct_hex).ok()?;
    if ct.is_empty() {
        return None;
    }
    Some((iv, ct))
}

// ── IndexedDB version (local convention; matches the forum bake's v1 store) ──

/// The IndexedDB version both the forum bake and this unwrap open [`BAKED_DB`]
/// at. v1 with the [`BAKED_STORE`] created on `upgradeneeded` using out-of-line
/// keys — kept in lock-step with the writer so neither triggers a version bump
/// the other would see as a `VersionError`.
#[cfg(target_arch = "wasm32")]
const BAKED_DB_VERSION: u32 = 1;

// ── Baked-key adoption (wasm) ───────────────────────────────────────────────

/// Unwrap the baked 32-byte secp256k1 secret from origin IndexedDB, or `None`
/// when nothing is baked (iOS isolated storage / not yet installed / a corrupt
/// record / a decrypt failure). Uses ONLY [`nostr_bbs_core`] constants so it
/// matches the forum bake byte-for-byte. Transient buffers are zeroized.
#[cfg(target_arch = "wasm32")]
pub async fn unwrap_baked_secret() -> Option<zeroize::Zeroizing<[u8; 32]>> {
    let db = open_baked_db().await.ok()?;
    let record = idb_get_record(&db).await?;

    let (iv_hex, ct_hex) = read_envelope(&record)?;
    let (iv, mut ct) = decode_envelope_hex(&iv_hex, &ct_hex)?;

    let wrap_key: web_sys::CryptoKey = js_sys::Reflect::get(&record, &"wrapKey".into())
        .ok()?
        .dyn_into()
        .ok()?;

    let crypto = web_sys::window()?.crypto().ok()?;
    let subtle = crypto.subtle();
    let iv_arr = js_sys::Uint8Array::from(&iv[..]);
    let params = web_sys::AesGcmParams::new(AES_ALG, &iv_arr);

    let promise = match subtle.decrypt_with_object_and_u8_array(&params, &wrap_key, &ct) {
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

/// Bake a 32-byte secret into THIS app's origin storage (the iOS local re-bake
/// after a rebind): generate a non-extractable AES-GCM `CryptoKey`, wrap the
/// secret under a random IV, store `{ id, wrapKey, envelope }` in IndexedDB, and
/// write the [`BootProfile`] to localStorage. Mirrors the forum bake exactly so
/// the next launch's [`unwrap_baked_secret`] reads it back. The transient
/// plaintext is zeroized after the wrap.
#[cfg(target_arch = "wasm32")]
pub async fn bake_local(secret: &[u8; 32], zone_id: &str) -> Result<(), JsValue> {
    let crypto = web_sys::window()
        .ok_or_else(|| JsValue::from_str("no window"))?
        .crypto()?;
    let subtle = crypto.subtle();

    // (1) NON-EXTRACTABLE AES-GCM wrapping key.
    let gen_params = web_sys::AesKeyGenParams::new(AES_ALG, AES_KEY_BITS as u16);
    let usages = js_sys::Array::of2(&"encrypt".into(), &"decrypt".into());
    let key_js =
        JsFuture::from(subtle.generate_key_with_object(&gen_params, false, &usages)?).await?;
    let wrap_key: web_sys::CryptoKey = key_js.dyn_into()?;

    // (2) Random IV.
    let mut iv = [0u8; AES_IV_LEN];
    crypto.get_random_values_with_u8_array(&mut iv)?;
    let iv_arr = js_sys::Uint8Array::from(&iv[..]);

    // (3) Encrypt the secret.
    let enc_params = web_sys::AesGcmParams::new(AES_ALG, &iv_arr);
    let mut plain = *secret;
    let ct_result = subtle.encrypt_with_object_and_u8_array(&enc_params, &wrap_key, &plain);
    plain.zeroize();
    let ct_js = JsFuture::from(ct_result?).await?;
    let ct_vec = js_sys::Uint8Array::new(&ct_js).to_vec();

    let envelope = WrappedKeyEnvelope {
        iv_hex: hex::encode(iv),
        ct_hex: hex::encode(&ct_vec),
    };

    // (4) Persist the record + (5) the BootProfile.
    let db = open_baked_db().await?;
    put_record(&db, &wrap_key, &envelope).await?;
    write_boot_profile(zone_id)?;
    Ok(())
}

/// One-shot adoption: unwrap the baked key and install the signer, or route to
/// the iOS rebind screen when nothing is baked. Called from the boot once
/// (`app.rs`) when in pwa mode and no session was already adopted. `state` is
/// needed to route to [`crate::menu::Screen::Rebind`] on the no-baked-key path.
#[cfg(target_arch = "wasm32")]
pub async fn adopt_baked_or_rebind(
    signer: &BbsSigner,
    _cfg: &BbsConfig,
    state: crate::chrome::BbsState,
) {
    if let Some(secret) = unwrap_baked_secret().await {
        if signer.adopt_baked_key(&secret) {
            return;
        }
    }
    // iOS isolated storage / not baked / unwrap failed → one-time rebind.
    state.go(crate::menu::Screen::Rebind);
}

/// Delete the baked IndexedDB record and the localStorage BootProfile — the
/// BBS-side "Forget this device". On iOS this clears only the app's own isolated
/// bucket; it is after-the-fact and cannot protect a phone already in an
/// attacker's hands (the consent copy says exactly this).
#[cfg(target_arch = "wasm32")]
pub async fn forget_device() {
    if let Ok(db) = open_baked_db().await {
        if let Ok(tx) =
            db.transaction_with_str_and_mode(BAKED_STORE, web_sys::IdbTransactionMode::Readwrite)
        {
            if let Ok(store) = tx.object_store(BAKED_STORE) {
                if let Ok(req) = store.delete(&JsValue::from_str(BAKED_RECORD_ID)) {
                    let _ = idb_request_result(&req).await;
                }
            }
        }
    }
    use gloo::storage::{LocalStorage, Storage};
    LocalStorage::delete(BOOTPROFILE_KEY);
}

// ── beforeinstallprompt capture (wasm) ──────────────────────────────────────
//
// This page carries the manifest + SW, so it is the authoritative surface for
// the deferred install prompt. `beforeinstallprompt` fires only after a prior
// user gesture, so the install affordance appears reactively once `installable`
// flips — never on first paint.

#[cfg(target_arch = "wasm32")]
thread_local! {
    static DEFERRED_PROMPT: std::cell::RefCell<Option<send_wrapper::SendWrapper<JsValue>>> =
        const { std::cell::RefCell::new(None) };
    static INSTALLABLE: std::cell::Cell<Option<RwSignal<bool>>> = const { std::cell::Cell::new(None) };
}

/// The reactive "an install prompt is available" signal. The BBS install
/// affordance gates on this so it only appears after the deferred prompt lands.
#[cfg(target_arch = "wasm32")]
pub fn installable() -> RwSignal<bool> {
    INSTALLABLE.with(|c| {
        if let Some(sig) = c.get() {
            sig
        } else {
            let sig = RwSignal::new(false);
            c.set(Some(sig));
            sig
        }
    })
}

/// Register the `beforeinstallprompt` listener: prevent the mini-infobar, stash
/// the event, and flip [`installable`] so a gated button can later fire it.
#[cfg(target_arch = "wasm32")]
pub fn init_install_capture() {
    let sig = installable();
    let win = match web_sys::window() {
        Some(w) => w,
        None => return,
    };
    let cb = Closure::<dyn FnMut(web_sys::Event)>::new(move |ev: web_sys::Event| {
        ev.prevent_default();
        DEFERRED_PROMPT.with(|d| {
            *d.borrow_mut() = Some(send_wrapper::SendWrapper::new(JsValue::from(ev)));
        });
        sig.set(true);
    });
    let _ =
        win.add_event_listener_with_callback("beforeinstallprompt", cb.as_ref().unchecked_ref());
    cb.forget();
}

/// Whether a deferred install prompt is currently stashed (untracked read for
/// event handlers). Prefer the reactive [`installable`] signal in views.
#[cfg(target_arch = "wasm32")]
pub fn deferred_prompt_available() -> bool {
    DEFERRED_PROMPT.with(|d| d.borrow().is_some())
}

/// Fire the stashed `beforeinstallprompt` event's `prompt()`. Returns `false`
/// when no event is stashed (nothing to prompt). One-shot — the deferred event is
/// consumed and [`installable`] is reset after firing.
#[cfg(target_arch = "wasm32")]
pub async fn prompt_install() -> bool {
    let evt = DEFERRED_PROMPT.with(|d| d.borrow().as_ref().map(|w| (**w).clone()));
    let evt = match evt {
        Some(e) => e,
        None => return false,
    };
    let prompt_fn = match js_sys::Reflect::get(&evt, &"prompt".into()) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let func: js_sys::Function = match prompt_fn.dyn_into() {
        Ok(f) => f,
        Err(_) => return false,
    };
    match func.call0(&evt) {
        Ok(ret) => {
            if let Ok(promise) = ret.dyn_into::<js_sys::Promise>() {
                let _ = JsFuture::from(promise).await;
            }
        }
        Err(_) => return false,
    }
    DEFERRED_PROMPT.with(|d| *d.borrow_mut() = None);
    installable().set(false);
    true
}

// ── Service worker registration (wasm) ──────────────────────────────────────

/// Register the network-first BBS service worker. The script is requested
/// relative to the page (served under `/community/bbs/`), so the SW lives at
/// `/community/bbs/bbs-sw.js` and its default max scope is `/community/bbs/` —
/// no explicit scope option and no `Service-Worker-Allowed` header are needed,
/// and longest-scope-wins means it (not the forum `/community/` SW) controls BBS
/// fetches. Call only when the feature flag is on.
#[cfg(target_arch = "wasm32")]
pub fn register_sw() {
    let win = match web_sys::window() {
        Some(w) => w,
        None => return,
    };
    let container = win.navigator().service_worker();
    let promise = container.register("bbs-sw.js");
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = JsFuture::from(promise).await {
            web_sys::console::warn_1(
                &format!("[bbs-pwa] service worker registration failed: {e:?}").into(),
            );
        }
    });
}

// ── IndexedDB plumbing (wasm) ───────────────────────────────────────────────

/// Open (or create) [`BAKED_DB`] with the [`BAKED_STORE`] out-of-line-key store.
/// Idempotent: whichever of the forum bake / BBS unwrap opens first creates the
/// store; the other finds it present at the same version.
#[cfg(target_arch = "wasm32")]
async fn open_baked_db() -> Result<web_sys::IdbDatabase, JsValue> {
    let win = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;
    let factory = win
        .indexed_db()?
        .ok_or_else(|| JsValue::from_str("IndexedDB unavailable"))?;
    let request = factory.open_with_u32(BAKED_DB, BAKED_DB_VERSION)?;
    open_db_request(&request, |db| {
        // `onupgradeneeded` fires only on DB creation / version bump, so the store
        // never pre-exists here. Out-of-line keys (no keyPath): the record carries
        // its own `id` and is `put` with an explicit key. Ignore an error (a
        // benign already-exists) rather than pull in the `DomStringList` feature
        // just to guard a call that cannot collide.
        let _ = db.create_object_store(BAKED_STORE);
    })
    .await
}

/// Read the single baked record (`BAKED_RECORD_ID`) or `None` when absent.
#[cfg(target_arch = "wasm32")]
async fn idb_get_record(db: &web_sys::IdbDatabase) -> Option<JsValue> {
    let tx = db.transaction_with_str(BAKED_STORE).ok()?;
    let store = tx.object_store(BAKED_STORE).ok()?;
    let req = store.get(&JsValue::from_str(BAKED_RECORD_ID)).ok()?;
    let result = idb_request_result(&req).await.ok()?;
    if result.is_undefined() || result.is_null() {
        None
    } else {
        Some(result)
    }
}

/// Write the `{ id, wrapKey, envelope }` record with an explicit out-of-line key.
#[cfg(target_arch = "wasm32")]
async fn put_record(
    db: &web_sys::IdbDatabase,
    wrap_key: &web_sys::CryptoKey,
    envelope: &WrappedKeyEnvelope,
) -> Result<(), JsValue> {
    let tx =
        db.transaction_with_str_and_mode(BAKED_STORE, web_sys::IdbTransactionMode::Readwrite)?;
    let store = tx.object_store(BAKED_STORE)?;

    let record = js_sys::Object::new();
    js_sys::Reflect::set(&record, &"id".into(), &JsValue::from_str(BAKED_RECORD_ID))?;
    js_sys::Reflect::set(&record, &"wrapKey".into(), wrap_key.as_ref())?;
    let env_obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &env_obj,
        &"iv_hex".into(),
        &JsValue::from_str(&envelope.iv_hex),
    )?;
    js_sys::Reflect::set(
        &env_obj,
        &"ct_hex".into(),
        &JsValue::from_str(&envelope.ct_hex),
    )?;
    js_sys::Reflect::set(&record, &"envelope".into(), &env_obj)?;

    let req = store.put_with_key(&record, &JsValue::from_str(BAKED_RECORD_ID))?;
    idb_request_result(&req).await?;
    Ok(())
}

/// Extract `(iv_hex, ct_hex)` from the record's `envelope`, tolerating either a
/// nested `{iv_hex, ct_hex}` object (the serde_wasm_bindgen shape) or a JSON
/// string — so the reader stays robust to how the writer serialized it.
#[cfg(target_arch = "wasm32")]
fn read_envelope(record: &JsValue) -> Option<(String, String)> {
    let env = js_sys::Reflect::get(record, &"envelope".into()).ok()?;
    if let Some(s) = env.as_string() {
        let e: WrappedKeyEnvelope = serde_json::from_str(&s).ok()?;
        return Some((e.iv_hex, e.ct_hex));
    }
    let iv = js_sys::Reflect::get(&env, &"iv_hex".into())
        .ok()?
        .as_string()?;
    let ct = js_sys::Reflect::get(&env, &"ct_hex".into())
        .ok()?
        .as_string()?;
    Some((iv, ct))
}

/// Write the non-secret BootProfile to localStorage (`now` from the wasm clock).
#[cfg(target_arch = "wasm32")]
fn write_boot_profile(zone_id: &str) -> Result<(), JsValue> {
    use gloo::storage::{LocalStorage, Storage};
    let now = (js_sys::Date::now() / 1000.0) as i64;
    let bp = BootProfile::new(zone_id.to_string(), now);
    let json = serde_json::to_string(&bp).map_err(|e| JsValue::from_str(&e.to_string()))?;
    LocalStorage::set(BOOTPROFILE_KEY, json).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Resolve an `IdbRequest` to its result on `onsuccess`. Mirrors the forum
/// client's IDB helper so the reader/writer share one await shape.
#[cfg(target_arch = "wasm32")]
async fn idb_request_result(request: &web_sys::IdbRequest) -> Result<JsValue, JsValue> {
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

/// Resolve an `IdbOpenDbRequest`, running `on_upgrade` on `onupgradeneeded`.
#[cfg(target_arch = "wasm32")]
async fn open_db_request(
    request: &web_sys::IdbOpenDbRequest,
    on_upgrade: impl FnOnce(&web_sys::IdbDatabase) + 'static,
) -> Result<web_sys::IdbDatabase, JsValue> {
    let upgrade = Closure::once(move |event: web_sys::Event| {
        let Some(target) = event.target() else {
            return;
        };
        let Ok(open_req) = target.dyn_into::<web_sys::IdbOpenDbRequest>() else {
            return;
        };
        let Ok(result) = open_req.result() else {
            return;
        };
        if let Ok(db) = result.dyn_into::<web_sys::IdbDatabase>() {
            on_upgrade(&db);
        }
    });
    request.set_onupgradeneeded(Some(upgrade.as_ref().unchecked_ref()));
    upgrade.forget();

    let result = idb_request_result(request.as_ref()).await?;
    result
        .dyn_into::<web_sys::IdbDatabase>()
        .map_err(|_| JsValue::from_str("open() did not return IdbDatabase"))
}

// ── Tests (native, pure) ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(id: &str, required: &[&str]) -> Zone {
        Zone {
            id: id.to_string(),
            display_name: id.to_string(),
            required_cohorts: required.iter().map(|s| s.to_string()).collect(),
            write_cohorts: None,
            banner_image_url: None,
            accent_hex: None,
            visibility: Default::default(),
            encrypted: false,
            auto_approve: false,
        }
    }

    #[test]
    fn rebind_path_truth_table() {
        assert_eq!(rebind_path(true), RebindPath::Passkey);
        assert_eq!(rebind_path(false), RebindPath::PasteRecoveryKey);
    }

    #[test]
    fn envelope_hex_decode_roundtrip() {
        let iv = vec![0xabu8; AES_IV_LEN];
        let ct = vec![0xcdu8; 48];
        let (iv_out, ct_out) =
            decode_envelope_hex(&hex::encode(&iv), &hex::encode(&ct)).expect("decode");
        assert_eq!(iv_out, iv);
        assert_eq!(ct_out, ct);
    }

    #[test]
    fn envelope_hex_decode_rejects_bad_input() {
        // Wrong IV length.
        assert!(decode_envelope_hex(&hex::encode([0u8; 8]), &hex::encode([1u8; 32])).is_none());
        // Non-hex.
        assert!(decode_envelope_hex("zz", &hex::encode([1u8; 32])).is_none());
        // Empty ciphertext.
        assert!(decode_envelope_hex(&hex::encode([0u8; AES_IV_LEN]), "").is_none());
    }

    #[test]
    fn resolve_boot_zone_exact_from_profile() {
        let zones = vec![zone("public", &[]), zone("minimoonoir", &["members"])];
        let bp = Some(BootProfile::new("minimoonoir".into(), 1));
        assert_eq!(resolve_boot_zone_index(&bp, &zones), Some(1));
        // A bound zone that no longer exists → None (falls back to unpinned).
        let gone = Some(BootProfile::new("gone".into(), 1));
        assert_eq!(resolve_boot_zone_index(&gone, &zones), None);
    }

    #[test]
    fn resolve_boot_zone_ios_sole_locked_zone() {
        // No profile (iOS first launch): the sole locked zone is the pin.
        let zones = vec![zone("public", &[]), zone("minimoonoir", &["members"])];
        assert_eq!(resolve_boot_zone_index(&None, &zones), Some(1));
    }

    #[test]
    fn resolve_boot_zone_ios_single_zone() {
        let zones = vec![zone("only", &[])];
        assert_eq!(resolve_boot_zone_index(&None, &zones), Some(0));
    }

    #[test]
    fn resolve_boot_zone_ios_ambiguous_is_none() {
        // Two locked zones, no profile → cannot pick, stay unpinned.
        let zones = vec![zone("a", &["x"]), zone("b", &["y"]), zone("pub", &[])];
        assert_eq!(resolve_boot_zone_index(&None, &zones), None);
        assert_eq!(resolve_boot_zone_index(&None, &[]), None);
    }
}

// ── Manifest install-invariant tests (static-asset validity, no browser) ────
//
// (Step-20 follow-up: distinct concern from the boot logic above — asserts the
// manifest's install invariants at `cargo test` time via `include_str!`.)

#[cfg(test)]
mod manifest_tests {
    use serde_json::Value;

    const MANIFEST: &str = include_str!("../manifest.webmanifest");

    fn manifest() -> Value {
        serde_json::from_str(MANIFEST).expect("manifest.webmanifest is valid JSON")
    }

    #[test]
    fn scope_has_trailing_slash() {
        let m = manifest();
        let scope = m["scope"].as_str().expect("scope");
        assert!(scope.ends_with('/'), "scope must end with '/': {scope}");
    }

    #[test]
    fn start_url_is_within_scope_and_carries_pwa_flag() {
        let m = manifest();
        let scope = m["scope"].as_str().expect("scope");
        let start = m["start_url"].as_str().expect("start_url");
        // Containment: else the browser derives scope from start_url and silently
        // ignores the declared scope (SW control + link-capture break).
        assert!(
            start.starts_with(scope),
            "start_url {start} must be path-contained by scope {scope}"
        );
        // The one-shot boot flag must be present.
        assert!(
            start.contains("pwa=1"),
            "start_url must carry ?pwa=1: {start}"
        );
    }

    #[test]
    fn id_is_present_and_equals_scope() {
        let m = manifest();
        let id = m["id"].as_str().expect("id present");
        let scope = m["scope"].as_str().expect("scope");
        // An explicit, query-independent id so ?pwa=1 does not fork the installed
        // identity across deploys.
        assert_eq!(id, scope, "id must be the explicit stable scope string");
    }

    #[test]
    fn display_is_standalone() {
        assert_eq!(manifest()["display"].as_str(), Some("standalone"));
    }

    #[test]
    fn colours_present() {
        let m = manifest();
        assert!(m["theme_color"].as_str().is_some(), "theme_color required");
        assert!(
            m["background_color"].as_str().is_some(),
            "background_color required"
        );
    }

    #[test]
    fn icons_cover_192_any_512_any_512_maskable_without_combined_purpose() {
        let m = manifest();
        let icons = m["icons"].as_array().expect("icons array");
        let mut has_192_any = false;
        let mut has_512_any = false;
        let mut has_512_maskable = false;
        for icon in icons {
            let sizes = icon["sizes"].as_str().unwrap_or_default();
            let purpose = icon["purpose"].as_str().unwrap_or("any");
            // No file may combine any + maskable — some launchers reject/mis-crop.
            let purposes: Vec<&str> = purpose.split_whitespace().collect();
            assert!(
                !(purposes.contains(&"any") && purposes.contains(&"maskable")),
                "an icon combines 'any maskable' — must be separate files: {icon}"
            );
            match (sizes, purpose) {
                ("192x192", "any") => has_192_any = true,
                ("512x512", "any") => has_512_any = true,
                ("512x512", "maskable") => has_512_maskable = true,
                _ => {}
            }
        }
        assert!(has_192_any, "missing 192x192 purpose=any icon");
        assert!(has_512_any, "missing 512x512 purpose=any icon");
        assert!(has_512_maskable, "missing 512x512 purpose=maskable icon");
    }
}
