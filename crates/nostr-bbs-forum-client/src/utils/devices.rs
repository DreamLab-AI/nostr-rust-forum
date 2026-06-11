//! Revocable device-key client helper (ADR-099).
//!
//! A **device key** is a deterministic subkey of the account master
//! (ADR-094 — `nostr_bbs_core::derive_subkey(master, "device:<uuid>")`).
//! It is registered to its owner in the auth-worker `device_keys` registry and
//! honoured by our relay/forum, revocable from Settings. The master key never
//! leaves the browser and never reaches the phone: only the *device* key rides
//! the `/connect#k=` magic link (ADR-098) onto the phone.
//!
//! All three registry endpoints are NIP-98-authed **by the master** — the
//! owner is derived from the NIP-98 author server-side. We sign exactly the way
//! `pod_client` / `claim_username` do: through the auth-store [`Signer`] when
//! present, falling back to the in-memory raw key.
//!
//! ## Gating
//!
//! Reads `window.__ENV__.DEVICE_KEYS_ENABLED`. When absent/false the UI never
//! calls into this module, so the registry is never touched. Mirrors the
//! `window_env` runtime-config reader used by [`crate::utils::relay_url`].
//!
//! ## What never crosses the wire
//!
//! The derived device secret is bech32-encoded **in-WASM** for the `/connect`
//! QR and never POSTed. Only the device *pubkey* (64-hex) + a label are
//! registered.

use serde::Deserialize;

use crate::auth::nip98::{
    fetch_with_nip98_get_signer, fetch_with_nip98_post, fetch_with_nip98_post_signer,
};
use crate::auth::AuthStore;
use crate::utils::relay_url::auth_api_base;

/// A registered device key as returned by `GET /api/devices`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct DeviceKey {
    /// 64-hex device/child pubkey.
    pub device_pubkey: String,
    /// Human label ("My phone"). May be absent on legacy rows.
    #[serde(default)]
    pub label: Option<String>,
    /// Unix seconds the device was registered.
    #[serde(default)]
    pub created_at: u64,
    /// 0 = active, 1 = revoked.
    #[serde(default)]
    pub revoked: u8,
}

impl DeviceKey {
    /// True when the relay still honours this device.
    pub fn is_active(&self) -> bool {
        self.revoked == 0
    }
}

/// Result of registering a new device key: everything the tear-off / Settings
/// QR needs without ever re-deriving the secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredDevice {
    /// 64-hex device pubkey (registered).
    pub device_pubkey: String,
    /// bech32 `nsec1…` of the **device** key — for the `/connect#k=` QR only.
    pub device_nsec: String,
    /// The `device:<uuid>` derivation tag (diagnostic / not load-bearing).
    pub tag: String,
}

/// Errors from the device-key registry flow.
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error("no signer available")]
    NoSigner,
    #[error("master key unavailable")]
    NoMasterKey,
    #[error("subkey derivation failed: {0}")]
    Derive(String),
    #[error("nsec encode failed: {0}")]
    Encode(String),
    #[error("request failed: {0}")]
    Request(String),
    #[error("invalid response: {0}")]
    Parse(String),
}

/// Read `window.__ENV__.DEVICE_KEYS_ENABLED` as a boolean.
///
/// Accepts a JS boolean `true` or the strings `"true"`/`"1"` (config injectors
/// emit either shape). Anything else — including a missing `__ENV__` — is
/// `false`, so the whole feature stays inert by default (ADR-099).
pub fn device_keys_enabled() -> bool {
    let Some(window) = web_sys::window() else {
        return false;
    };
    let Ok(env) = js_sys::Reflect::get(&window, &"__ENV__".into()) else {
        return false;
    };
    if env.is_undefined() || env.is_null() {
        return false;
    }
    let Ok(val) = js_sys::Reflect::get(&env, &"DEVICE_KEYS_ENABLED".into()) else {
        return false;
    };
    if let Some(b) = val.as_bool() {
        return b;
    }
    if let Some(s) = val.as_string() {
        let s = s.trim().to_ascii_lowercase();
        return s == "true" || s == "1";
    }
    false
}

/// Derive a fresh device subkey from the master, register its pubkey via a
/// NIP-98 POST signed by the master, and return the device pubkey + nsec.
///
/// The master secret is taken from the auth store's in-memory key (the same
/// `get_privkey_bytes` path Settings already uses for nsec export). The derived
/// device secret is bech32-encoded in-WASM and returned for the `/connect` QR;
/// only the device *pubkey* is POSTed.
pub async fn register_device(
    auth: AuthStore,
    label: &str,
) -> Result<RegisteredDevice, DeviceError> {
    // 1. Master secret (raw bytes, auto-zeroizing).
    let master_bytes = auth.get_privkey_bytes().ok_or(DeviceError::NoMasterKey)?;
    let master_sk = nostr_bbs_core::SecretKey::from_bytes(*master_bytes)
        .map_err(|e| DeviceError::Derive(e.to_string()))?;

    // 2. Derive device subkey under a random `device:<uuid>` tag (ADR-094).
    let tag = format!("device:{}", uuid::Uuid::new_v4());
    let device_sk = nostr_bbs_core::derive_subkey(&master_sk, &tag)
        .map_err(|e| DeviceError::Derive(e.to_string()))?;
    let device_pubkey = device_sk.public_key().to_hex();
    let device_hex = hex::encode(device_sk.as_bytes());
    let device_nsec =
        nostr_bbs_core::encode_nsec(&device_hex).map_err(|e| DeviceError::Encode(e.to_string()))?;

    // 3. Register the device pubkey — NIP-98 signed by the MASTER.
    let signer = auth.get_signer().ok_or(DeviceError::NoSigner)?;
    let url = format!("{}/api/devices/register", auth_api_base());
    let body = serde_json::json!({ "device_pubkey": device_pubkey, "label": label }).to_string();
    fetch_with_nip98_post_signer(&url, &body, signer.as_ref())
        .await
        .map_err(|e| DeviceError::Request(e.to_string()))?;

    Ok(RegisteredDevice {
        device_pubkey,
        device_nsec,
        tag,
    })
}

/// Recovery-sheet variant: derive + register a device key signing the NIP-98
/// POST with the **master raw key** directly (the in-WASM signup key).
///
/// `master_hex` is the same 64-hex master the recovery sheet already renders —
/// no auth-store coupling, so this works mid-signup before a session settles.
/// The device secret is bech32-encoded in-WASM and returned for the `/connect`
/// QR; only the device *pubkey* is POSTed.
pub async fn register_device_with_master(
    master_hex: &str,
    label: &str,
) -> Result<RegisteredDevice, DeviceError> {
    let mut master_bytes = [0u8; 32];
    let raw = hex::decode(master_hex).map_err(|_| DeviceError::NoMasterKey)?;
    if raw.len() != 32 {
        return Err(DeviceError::NoMasterKey);
    }
    master_bytes.copy_from_slice(&raw);

    let master_sk = nostr_bbs_core::SecretKey::from_bytes(master_bytes)
        .map_err(|e| DeviceError::Derive(e.to_string()))?;

    let tag = format!("device:{}", uuid::Uuid::new_v4());
    let device_sk = nostr_bbs_core::derive_subkey(&master_sk, &tag)
        .map_err(|e| DeviceError::Derive(e.to_string()))?;
    let device_pubkey = device_sk.public_key().to_hex();
    let device_hex = hex::encode(device_sk.as_bytes());
    let device_nsec =
        nostr_bbs_core::encode_nsec(&device_hex).map_err(|e| DeviceError::Encode(e.to_string()))?;

    let url = format!("{}/api/devices/register", auth_api_base());
    let body = serde_json::json!({ "device_pubkey": device_pubkey, "label": label }).to_string();
    fetch_with_nip98_post(&url, &body, &master_bytes)
        .await
        .map_err(|e| DeviceError::Request(e.to_string()))?;

    Ok(RegisteredDevice {
        device_pubkey,
        device_nsec,
        tag,
    })
}

/// List the caller's registered device keys via `GET /api/devices`
/// (NIP-98 signed by the master; owner derived server-side).
pub async fn list_devices(auth: AuthStore) -> Result<Vec<DeviceKey>, DeviceError> {
    let signer = auth.get_signer().ok_or(DeviceError::NoSigner)?;
    let url = format!("{}/api/devices", auth_api_base());
    let raw = fetch_with_nip98_get_signer(&url, signer.as_ref())
        .await
        .map_err(|e| DeviceError::Request(e.to_string()))?;
    parse_device_list(&raw)
}

/// Revoke a device key via `POST /api/devices/revoke` (idempotent;
/// NIP-98 signed by the master). The relay stops honouring it immediately.
pub async fn revoke_device(auth: AuthStore, device_pubkey: &str) -> Result<(), DeviceError> {
    let signer = auth.get_signer().ok_or(DeviceError::NoSigner)?;
    let url = format!("{}/api/devices/revoke", auth_api_base());
    let body = serde_json::json!({ "device_pubkey": device_pubkey }).to_string();
    fetch_with_nip98_post_signer(&url, &body, signer.as_ref())
        .await
        .map_err(|e| DeviceError::Request(e.to_string()))?;
    Ok(())
}

/// Current UTC date as `YYYY-MM-DD` from the browser clock — used to label a
/// freshly-generated device key. Best-effort.
pub fn today_utc() -> String {
    let date = js_sys::Date::new_0();
    let y = date.get_utc_full_year();
    let m = date.get_utc_month() + 1;
    let d = date.get_utc_date();
    format!("{y:04}-{m:02}-{d:02}")
}

/// Render `data` as a self-contained SVG QR-code string (pure-Rust, in-WASM).
///
/// Mirrors the recovery-sheet helper so the Settings "add a device" flow can
/// render the device `/connect` QR without crossing the WASM/JS boundary.
/// Returns an empty string on the (practically impossible) encode failure.
pub fn qr_svg(data: &str) -> String {
    use qrcode::render::svg;
    use qrcode::{EcLevel, QrCode};
    match QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M) {
        Ok(code) => code
            .render::<svg::Color>()
            .min_dimensions(220, 220)
            .quiet_zone(true)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build(),
        Err(_) => String::new(),
    }
}

/// Build the ADR-098 `/connect#k=<device-nsec>` URL from the live browser
/// origin, with the FORUM_BASE prefix applied. The device secret rides the URL
/// *fragment* — never transmitted to the server. Returns `None` off-browser.
pub fn device_connect_url(device_nsec: &str) -> Option<String> {
    let origin = web_sys::window()?.location().origin().ok()?;
    Some(format!(
        "{origin}{}#k={device_nsec}",
        crate::app::base_href("/connect")
    ))
}

/// Parse a `GET /api/devices` body. Accepts either a bare JSON array or a
/// `{ "devices": [...] }` envelope (both shapes are common for these workers).
fn parse_device_list(raw: &str) -> Result<Vec<DeviceKey>, DeviceError> {
    if let Ok(list) = serde_json::from_str::<Vec<DeviceKey>>(raw) {
        return Ok(list);
    }
    #[derive(Deserialize)]
    struct Envelope {
        #[serde(default)]
        devices: Vec<DeviceKey>,
    }
    serde_json::from_str::<Envelope>(raw)
        .map(|e| e.devices)
        .map_err(|e| DeviceError::Parse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bare_array() {
        let raw = r#"[{"device_pubkey":"aa","label":"phone","created_at":1,"revoked":0}]"#;
        let v = parse_device_list(raw).unwrap();
        assert_eq!(v.len(), 1);
        assert!(v[0].is_active());
        assert_eq!(v[0].label.as_deref(), Some("phone"));
    }

    #[test]
    fn parse_envelope() {
        let raw = r#"{"devices":[{"device_pubkey":"bb","revoked":1}]}"#;
        let v = parse_device_list(raw).unwrap();
        assert_eq!(v.len(), 1);
        assert!(!v[0].is_active());
    }

    #[test]
    fn parse_empty() {
        assert!(parse_device_list("[]").unwrap().is_empty());
        assert!(parse_device_list(r#"{"devices":[]}"#).unwrap().is_empty());
    }
}
