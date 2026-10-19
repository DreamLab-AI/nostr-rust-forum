//! Web Push for the forum PWA (ADR-2023).
//!
//! Two jobs live here:
//!
//! 1. **Server push.** Ask for notification permission, subscribe the browser,
//!    register that subscription with the relay (`POST /api/push/subscribe`,
//!    NIP-98) and hand the service worker the credentials it needs to fetch
//!    pending counters when an empty, content-free push wakes it. Also edits
//!    the member's server-side alert preferences.
//! 2. **Tier 0 local alerts.** While the page is hidden and server push is not
//!    active on this device, a new in-app notification is also raised as a
//!    system notification through the service worker registration.
//!
//! The browser APIs live in `js/push.js`; this module is the typed, tested
//! orchestration around them. Nothing here ever reads or stores the Nostr
//! secret key: signing goes through the [`Signer`] the caller already holds.

use std::rc::Rc;

use gloo::storage::{LocalStorage, Storage};
use nostr_bbs_core::push::PushPrefs;
use nostr_bbs_core::signer::Signer;
use serde::Deserialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::auth::nip98::{fetch_with_nip98_get_signer, fetch_with_nip98_post_signer};
use crate::utils::relay_url::relay_api_base;

#[wasm_bindgen(module = "/js/push.js")]
extern "C" {
    #[wasm_bindgen(js_name = pushSupported)]
    fn js_supported() -> bool;
    #[wasm_bindgen(js_name = pushNotificationsSupported)]
    fn js_notifications_supported() -> bool;
    #[wasm_bindgen(js_name = pushPermission)]
    fn js_permission() -> String;
    #[wasm_bindgen(js_name = pushRequestPermission)]
    fn js_request_permission() -> js_sys::Promise;
    #[wasm_bindgen(js_name = pushIsStandalone)]
    fn js_is_standalone() -> bool;
    #[wasm_bindgen(js_name = pushSubscribe)]
    fn js_subscribe(vapid_public_key: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_name = pushCurrentEndpoint)]
    fn js_current_endpoint() -> js_sys::Promise;
    #[wasm_bindgen(js_name = pushUnsubscribe)]
    fn js_unsubscribe() -> js_sys::Promise;
    #[wasm_bindgen(js_name = pushStoreCfg)]
    fn js_store_cfg(json: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_name = pushClearCfg)]
    fn js_clear_cfg() -> js_sys::Promise;
    #[wasm_bindgen(js_name = pushBeacon)]
    fn js_beacon(url: &str, body: &str) -> bool;
    #[wasm_bindgen(js_name = pushShowLocal)]
    fn js_show_local(title: &str, body: &str, url: &str, tag: &str) -> js_sys::Promise;
}

/// `localStorage` flag: this device holds a live, registered push subscription.
const ACTIVE_KEY: &str = "nostrbbs:push_active";
/// `localStorage` copy of the drain credentials (the same JSON the service
/// worker reads from IndexedDB), so logout can tear the device down
/// synchronously, before the page navigates away.
const CFG_KEY: &str = "nostrbbs:push_cfg";
/// `localStorage` timestamp (ms) of the last successful registration refresh.
const REFRESHED_KEY: &str = "nostrbbs:push_refreshed_ms";
/// The relay forgets subscriptions the app has not refreshed for 90 days; the
/// client re-registers once a day when the app is opened.
const REFRESH_EVERY_MS: f64 = 24.0 * 60.0 * 60.0 * 1000.0;

// ---------------------------------------------------------------------------
// Permission state
// ---------------------------------------------------------------------------

/// The browser's notification permission, plus "cannot ask at all".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    /// Never asked.
    Default,
    /// Granted.
    Granted,
    /// Blocked by the user; only browser settings can undo it.
    Denied,
    /// No Notification / PushManager / service worker here.
    Unsupported,
}

impl Permission {
    /// Parse the `Notification.permission` string.
    pub fn parse(s: &str) -> Self {
        match s {
            "granted" => Permission::Granted,
            "denied" => Permission::Denied,
            "default" => Permission::Default,
            _ => Permission::Unsupported,
        }
    }
}

/// Whether this browser can do Web Push at all.
pub fn supported() -> bool {
    js_supported()
}

/// Whether system notifications (not necessarily server push) can be shown:
/// the Notification API plus a service worker to raise them through.
pub fn notifications_supported() -> bool {
    js_notifications_supported()
}

/// Wait for a prompt raised by [`request_permission_now`] and return the answer.
pub async fn await_permission(prompt: js_sys::Promise) -> Permission {
    match resolve(prompt).await {
        Ok(v) => Permission::parse(&v.as_string().unwrap_or_default()),
        Err(_) => permission(),
    }
}

/// Current permission.
pub fn permission() -> Permission {
    if !js_notifications_supported() {
        return Permission::Unsupported;
    }
    Permission::parse(&js_permission())
}

/// iOS only delivers Web Push to an app installed to the Home Screen.
pub fn needs_install() -> bool {
    crate::utils::pwa_install::platform_is_ios() && !js_is_standalone()
}

/// Whether this device currently holds a registered push subscription.
pub fn active_on_device() -> bool {
    LocalStorage::get::<String>(ACTIVE_KEY).is_ok_and(|v| v == "1")
}

fn set_active(on: bool) {
    if on {
        let _ = LocalStorage::set(ACTIVE_KEY, "1");
        let _ = LocalStorage::set(REFRESHED_KEY, js_sys::Date::now().to_string());
    } else {
        LocalStorage::delete(ACTIVE_KEY);
        LocalStorage::delete(REFRESHED_KEY);
    }
}

// ---------------------------------------------------------------------------
// Pure decisions (unit tested)
// ---------------------------------------------------------------------------

/// Whether the daily registration refresh is due. A missing or unreadable
/// timestamp, or a clock that went backwards, counts as due.
pub fn refresh_due(now_ms: f64, last_ms: Option<f64>) -> bool {
    match last_ms {
        None => true,
        Some(last) => now_ms < last || now_ms - last >= REFRESH_EVERY_MS,
    }
}

/// Whether a new in-app notification should also be raised as a system
/// notification right now: only while the page is hidden, permission is
/// granted, and server push is not already waking this device (otherwise the
/// member would be alerted twice).
pub fn should_show_local(page_hidden: bool, permission: Permission, push_active: bool) -> bool {
    page_hidden && permission == Permission::Granted && !push_active
}

/// The JSON the service worker reads from IndexedDB when a push arrives.
pub fn drain_cfg_json(api: &str, id: &str, token: &str, brand: &str) -> String {
    serde_json::json!({ "api": api, "id": id, "token": token, "brand": brand }).to_string()
}

/// Name shown as the title of system notifications: the operator's brand.
pub fn brand_label() -> String {
    let env = web_sys::window().and_then(|w| js_sys::Reflect::get(&w, &"__ENV__".into()).ok());
    for key in ["BRAND_LABEL", "FORUM_NAME", "NODE_NAME"] {
        let value = env
            .as_ref()
            .and_then(|e| js_sys::Reflect::get(e, &key.into()).ok())
            .and_then(|v| v.as_string())
            .filter(|s| !s.trim().is_empty());
        if let Some(v) = value {
            return v;
        }
    }
    "Community".to_string()
}

/// Minutes the local clock is ahead of UTC (`-getTimezoneOffset()`).
pub fn local_tz_offset_min() -> i16 {
    -(js_sys::Date::new_0().get_timezone_offset() as i32) as i16
}

/// Parse an `<input type="time">` value (`"HH:MM"`) to minutes after midnight.
pub fn parse_hhmm(s: &str) -> Option<u16> {
    let (h, m) = s.split_once(':')?;
    let (h, m) = (h.parse::<u16>().ok()?, m.parse::<u16>().ok()?);
    (h < 24 && m < 60).then_some(h * 60 + m)
}

/// Format minutes after midnight as `"HH:MM"`.
pub fn format_hhmm(min: u16) -> String {
    format!("{:02}:{:02}", (min / 60) % 24, min % 60)
}

// ---------------------------------------------------------------------------
// Relay API
// ---------------------------------------------------------------------------

/// `GET /api/push/config` reply.
#[derive(Clone, Debug, Deserialize)]
pub struct PushConfig {
    /// Operator switched Web Push on and the VAPID pair is consistent.
    pub enabled: bool,
    /// Uncompressed P-256 point, base64url: the `applicationServerKey`.
    #[serde(default)]
    pub public_key: String,
}

#[derive(Deserialize)]
struct SubscribeReply {
    id: String,
    token: String,
}

#[derive(Deserialize)]
struct PrefsReply {
    prefs: PushPrefs,
}

async fn resolve(p: js_sys::Promise) -> Result<JsValue, String> {
    JsFuture::from(p).await.map_err(|e| {
        e.as_string()
            .or_else(|| {
                js_sys::Reflect::get(&e, &"message".into())
                    .ok()
                    .and_then(|m| m.as_string())
            })
            .unwrap_or_else(|| "browser error".to_string())
    })
}

/// Fetch the relay's push configuration. `None` when the relay predates
/// ADR-2023, is unreachable, or has the feature off.
pub async fn fetch_config() -> Option<PushConfig> {
    let url = format!("{}/api/push/config", relay_api_base());
    let resp = JsFuture::from(web_sys::window()?.fetch_with_str(&url))
        .await
        .ok()?;
    let resp: web_sys::Response = resp.dyn_into().ok()?;
    if !resp.ok() {
        return None;
    }
    let text = JsFuture::from(resp.text().ok()?).await.ok()?.as_string()?;
    let cfg: PushConfig = serde_json::from_str(&text).ok()?;
    (cfg.enabled && !cfg.public_key.is_empty()).then_some(cfg)
}

/// Subscribe this browser and register it with the relay. `permission` must be
/// the promise returned by [`request_permission_now`] when permission was not
/// yet granted, so the prompt is raised synchronously inside the click handler
/// (Safari refuses it otherwise).
pub async fn enable(
    signer: Rc<dyn Signer>,
    brand: String,
    permission: Option<js_sys::Promise>,
) -> Result<(), String> {
    if !supported() {
        return Err("This browser does not support push notifications.".into());
    }
    if needs_install() {
        return Err("On iPhone and iPad, add this app to your Home Screen first, then turn alerts on from there.".into());
    }
    if let Some(p) = permission {
        let answer = resolve(p).await?.as_string().unwrap_or_default();
        if Permission::parse(&answer) != Permission::Granted {
            return Err("Notifications were not allowed. You can change this in your browser's site settings.".into());
        }
    } else if self::permission() != Permission::Granted {
        return Err("Notifications are blocked for this site in your browser settings.".into());
    }
    let cfg = fetch_config()
        .await
        .ok_or("Alerts are not available on this server.")?;
    register(signer.as_ref(), &cfg.public_key, &brand).await
}

/// Raise the permission prompt now, if it has not been answered. Call this
/// directly from the click handler, before spawning any async work.
pub fn request_permission_now() -> Option<js_sys::Promise> {
    (js_notifications_supported() && permission() == Permission::Default)
        .then(js_request_permission)
}

/// Subscribe in the browser, register with the relay, store drain credentials.
async fn register(signer: &dyn Signer, vapid_public_key: &str, brand: &str) -> Result<(), String> {
    let endpoint = resolve(js_subscribe(vapid_public_key))
        .await?
        .as_string()
        .ok_or("The browser returned no push endpoint.")?;
    let api = relay_api_base();
    let body = serde_json::json!({ "endpoint": endpoint }).to_string();
    let reply = fetch_with_nip98_post_signer(&format!("{api}/api/push/subscribe"), &body, signer)
        .await
        .map_err(|e| format!("Could not register this device: {e}"))?;
    let reply: SubscribeReply = serde_json::from_str(&reply)
        .map_err(|_| "Unexpected reply from the server.".to_string())?;
    resolve(js_store_cfg(&drain_cfg_json(
        &api,
        &reply.id,
        &reply.token,
        brand,
    )))
    .await?;
    set_active(true);
    Ok(())
}

/// The unsubscribe request for the stored drain credentials, if any: the URL and
/// JSON body of `POST /api/push/unsubscribe` (no signature; the token is the
/// proof of ownership).
pub fn teardown_request(cfg_json: &str) -> Option<(String, String)> {
    let v: serde_json::Value = serde_json::from_str(cfg_json).ok()?;
    let (api, id, token) = (
        v.get("api")?.as_str()?,
        v.get("id")?.as_str()?,
        v.get("token")?.as_str()?,
    );
    Some((
        format!("{api}/api/push/unsubscribe"),
        serde_json::json!({ "id": id, "token": token }).to_string(),
    ))
}

/// Turn alerts off for this device: tell the relay (with the device's own drain
/// credentials, so no signer is needed), drop the browser subscription, forget
/// the credentials. Each step runs even if an earlier one fails: leaving the
/// device marked active with a live drain token would keep waking it.
pub async fn disable() -> Result<(), String> {
    if let Some((url, body)) = LocalStorage::get::<String>(CFG_KEY)
        .ok()
        .and_then(|cfg| teardown_request(&cfg))
    {
        if let Some(window) = web_sys::window() {
            let init = web_sys::RequestInit::new();
            init.set_method("POST");
            init.set_body(&JsValue::from_str(&body));
            if let Ok(req) = web_sys::Request::new_with_str_and_init(&url, &init) {
                // Best effort: an unreachable relay forgets the row after a 410
                // from the push service or the 90-day sweep.
                let _ = JsFuture::from(window.fetch_with_request(&req)).await;
            }
        }
    }
    let _ = resolve(js_unsubscribe()).await;
    let _ = resolve(js_clear_cfg()).await;
    LocalStorage::delete(CFG_KEY);
    set_active(false);
    Ok(())
}

/// Logout hook: stop this device waking for the account that just signed out.
/// Synchronous up to the beacon, because logout navigates away immediately; the
/// browser-side cleanup finishes in the background where it can.
pub fn teardown_on_logout() {
    if !active_on_device() {
        return;
    }
    if let Some((url, body)) = LocalStorage::get::<String>(CFG_KEY)
        .ok()
        .and_then(|cfg| teardown_request(&cfg))
    {
        js_beacon(&url, &body);
    }
    LocalStorage::delete(CFG_KEY);
    set_active(false);
    wasm_bindgen_futures::spawn_local(async {
        let _ = resolve(js_unsubscribe()).await;
        let _ = resolve(js_clear_cfg()).await;
    });
}

/// Re-register once a day while the app is open, so a rotated browser
/// subscription is picked up and the relay does not sweep an active device.
/// A silent no-op unless this device is already subscribed.
pub async fn refresh_if_due(signer: Rc<dyn Signer>, brand: String) {
    if !active_on_device() {
        return;
    }
    if permission() != Permission::Granted {
        // Revoked in browser settings.
        set_active(false);
        return;
    }
    let last = LocalStorage::get::<String>(REFRESHED_KEY)
        .ok()
        .and_then(|s| s.parse::<f64>().ok());
    if !refresh_due(js_sys::Date::now(), last) {
        return;
    }
    // Stamp before the request, not after: every registration rotates the
    // bearer token, so two tabs refreshing together would leave the relay
    // holding one token and IndexedDB the other. The stamp makes the second
    // tab see the refresh as not due.
    let _ = LocalStorage::set(REFRESHED_KEY, js_sys::Date::now().to_string());
    if let Some(cfg) = fetch_config().await {
        if let Err(e) = register(signer.as_ref(), &cfg.public_key, &brand).await {
            web_sys::console::warn_1(&format!("[push] refresh failed: {e}").into());
        }
    }
}

/// Load the member's server-side alert preferences.
pub async fn load_prefs(signer: &dyn Signer) -> Result<PushPrefs, String> {
    let url = format!("{}/api/push/prefs", relay_api_base());
    let text = fetch_with_nip98_get_signer(&url, signer)
        .await
        .map_err(|e| format!("Could not load alert settings: {e}"))?;
    serde_json::from_str::<PrefsReply>(&text)
        .map(|r| r.prefs)
        .map_err(|_| "Unexpected reply from the server.".to_string())
}

/// Save the member's server-side alert preferences.
pub async fn save_prefs(signer: &dyn Signer, prefs: &PushPrefs) -> Result<PushPrefs, String> {
    let url = format!("{}/api/push/prefs", relay_api_base());
    let body = serde_json::to_string(prefs).map_err(|e| e.to_string())?;
    let text = fetch_with_nip98_post_signer(&url, &body, signer)
        .await
        .map_err(|e| format!("Could not save alert settings: {e}"))?;
    serde_json::from_str::<PrefsReply>(&text)
        .map(|r| r.prefs)
        .map_err(|_| "Unexpected reply from the server.".to_string())
}

// ---------------------------------------------------------------------------
// Tier 0: local system notification while hidden
// ---------------------------------------------------------------------------

/// Raise `title`/`body` as a system notification when [`should_show_local`]
/// holds. `url` is the in-app path opened on click. Callers pass generic text:
/// a system notification can appear on a lock screen.
pub fn show_local_if_hidden(title: &str, body: &str, url: &str, tag: &str) {
    let hidden = web_sys::window()
        .and_then(|w| w.document())
        .map(|d| d.hidden())
        .unwrap_or(false);
    if !should_show_local(hidden, permission(), active_on_device()) {
        return;
    }
    let promise = js_show_local(title, body, url, tag);
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = resolve(promise).await {
            web_sys::console::warn_1(&format!("[push] local notification failed: {e}").into());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_strings_parse() {
        assert_eq!(Permission::parse("granted"), Permission::Granted);
        assert_eq!(Permission::parse("denied"), Permission::Denied);
        assert_eq!(Permission::parse("default"), Permission::Default);
        assert_eq!(Permission::parse("unsupported"), Permission::Unsupported);
        assert_eq!(Permission::parse(""), Permission::Unsupported);
    }

    #[test]
    fn local_alerts_only_when_hidden_granted_and_not_already_pushed() {
        assert!(should_show_local(true, Permission::Granted, false));
        assert!(
            !should_show_local(false, Permission::Granted, false),
            "visible page shows it in-app"
        );
        assert!(!should_show_local(true, Permission::Default, false));
        assert!(!should_show_local(true, Permission::Denied, false));
        assert!(!should_show_local(true, Permission::Unsupported, false));
        assert!(
            !should_show_local(true, Permission::Granted, true),
            "server push already alerts this device"
        );
    }

    #[test]
    fn refresh_is_daily() {
        let day = REFRESH_EVERY_MS;
        assert!(refresh_due(1.0, None));
        assert!(!refresh_due(day - 1.0, Some(0.0)));
        assert!(refresh_due(day, Some(0.0)));
        assert!(refresh_due(5.0, Some(10.0)), "clock went backwards");
    }

    #[test]
    fn drain_credentials_are_the_shape_sw_js_reads() {
        let v: serde_json::Value = serde_json::from_str(&drain_cfg_json(
            "https://relay.example",
            "id1",
            "tok",
            "DreamLab",
        ))
        .unwrap();
        assert_eq!(
            v,
            serde_json::json!({ "api": "https://relay.example", "id": "id1", "token": "tok", "brand": "DreamLab" })
        );
    }

    #[test]
    fn teardown_request_is_built_from_the_stored_credentials() {
        let cfg = drain_cfg_json("https://relay.example", "id1", "tok", "DreamLab");
        let (url, body) = teardown_request(&cfg).unwrap();
        assert_eq!(url, "https://relay.example/api/push/unsubscribe");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({ "id": "id1", "token": "tok" })
        );
        assert!(teardown_request("not json").is_none());
        assert!(
            teardown_request(r#"{"api":"x"}"#).is_none(),
            "needs id and token"
        );
    }

    #[test]
    fn time_inputs_round_trip() {
        assert_eq!(parse_hhmm("00:00"), Some(0));
        assert_eq!(parse_hhmm("22:30"), Some(22 * 60 + 30));
        assert_eq!(parse_hhmm("23:59"), Some(1439));
        assert_eq!(parse_hhmm("24:00"), None);
        assert_eq!(parse_hhmm("12:60"), None);
        assert_eq!(parse_hhmm("noon"), None);
        assert_eq!(parse_hhmm(""), None);
        for m in [0u16, 59, 60, 1439] {
            assert_eq!(parse_hhmm(&format_hhmm(m)), Some(m));
        }
    }

    #[test]
    fn config_requires_enabled_and_a_key() {
        let on: PushConfig =
            serde_json::from_str(r#"{"enabled":true,"public_key":"BKey"}"#).unwrap();
        assert!(on.enabled && on.public_key == "BKey");
        let off: PushConfig = serde_json::from_str(r#"{"enabled":false}"#).unwrap();
        assert!(!off.enabled && off.public_key.is_empty());
    }
}
