//! Config-driven zone access model.
//!
//! The default zones are `public`, `members`, and `private`, but operators can
//! rename them via [`BbsConfig`]. All zone enforcement is client-side (UX
//! optimization); the relay is the source of truth.
//!
//! On authentication the user's whitelist entry is fetched from the relay's
//! `/api/check-whitelist?pubkey=` endpoint and the flags are populated.

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use crate::auth::use_auth;

// ---------------------------------------------------------------------------
// BbsConfig — runtime zone configuration
// ---------------------------------------------------------------------------

/// Runtime configuration for zone names and access semantics.
///
/// The default configuration provides three zones: `public` (home),
/// `members`, and `private`. Operators can override zone display names
/// by providing a `BbsConfig` in Leptos context before calling
/// [`provide_zone_access`].
#[derive(Clone, Debug)]
pub struct BbsConfig {
    /// Zone 0 identifier (used in access JSON and cohort matching).
    pub zone_public_id: String,
    /// Zone 1 identifier.
    pub zone_members_id: String,
    /// Zone 2 identifier.
    pub zone_private_id: String,
    /// Display name for zone 0.
    pub zone_public_name: String,
    /// Display name for zone 1.
    pub zone_members_name: String,
    /// Display name for zone 2.
    pub zone_private_name: String,
    /// Cohort strings that grant zone 0 access.
    pub zone_public_cohorts: Vec<String>,
    /// Cohort strings that grant zone 1 access.
    pub zone_members_cohorts: Vec<String>,
    /// Cohort strings that grant zone 2 access.
    pub zone_private_cohorts: Vec<String>,
}

impl Default for BbsConfig {
    fn default() -> Self {
        Self {
            zone_public_id: "home".into(),
            zone_members_id: "members".into(),
            zone_private_id: "private".into(),
            zone_public_name: "Home".into(),
            zone_members_name: "Members".into(),
            zone_private_name: "Private".into(),
            zone_public_cohorts: vec![
                "home".into(), "lobby".into(), "approved".into(), "cross-access".into(),
            ],
            zone_members_cohorts: vec![
                "members".into(), "business".into(), "business-only".into(),
                "trainers".into(), "trainees".into(), "ai-agents".into(),
                "agent".into(), "visionflow-full".into(), "cross-access".into(),
            ],
            zone_private_cohorts: vec![
                "private".into(), "private-only".into(), "private-business".into(),
                "cross-access".into(),
            ],
        }
    }
}

/// Retrieve the BBS config from context (or create the default).
pub fn use_bbs_config() -> BbsConfig {
    use_context::<BbsConfig>().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// ZoneAccess — reactive access state
// ---------------------------------------------------------------------------

/// Reactive zone access state provided via Leptos context.
#[derive(Clone, Debug)]
pub struct ZoneAccess {
    /// Whether the user has Home (public zone) access.
    pub home: Memo<bool>,
    /// Whether the user has Members zone access.
    pub members: Memo<bool>,
    /// Whether the user has Private zone access.
    pub private_zone: Memo<bool>,
    /// Whether the user is on the whitelist (any flag true).
    #[allow(dead_code)]
    pub is_whitelisted: Signal<bool>,
    /// Whether the user has admin privileges (from D1 whitelist).
    pub is_admin: RwSignal<bool>,
    /// Whether the zone access fetch has completed (success or error).
    pub loaded: RwSignal<bool>,
    /// Raw flags signal (set from relay response).
    #[allow(dead_code)]
    flags: RwSignal<(bool, bool, bool)>,
}

impl ZoneAccess {
    /// Check access for a zone by its string ID.
    #[allow(dead_code)]
    pub fn has_access(&self, zone_id: &str) -> bool {
        let cfg = use_bbs_config();
        if zone_id == cfg.zone_public_id || zone_id == "public-lobby" {
            self.home.get_untracked()
        } else if zone_id == cfg.zone_members_id {
            self.members.get_untracked()
        } else if zone_id == cfg.zone_private_id {
            self.private_zone.get_untracked()
        } else {
            false
        }
    }
}

/// Create and provide the zone access store into Leptos context.
///
/// Must be called after `provide_auth()`. When the user authenticates, fetches
/// their access flags from the relay's `/api/check-whitelist` endpoint.
pub fn provide_zone_access() {
    let auth = use_auth();
    let is_authed = auth.is_authenticated();
    let pubkey = auth.pubkey();
    let flags = RwSignal::new((false, false, false));
    let is_admin_sig = RwSignal::new(false);
    let loaded = RwSignal::new(false);

    let home = Memo::new(move |_| flags.get().0);
    let members = Memo::new(move |_| flags.get().1);
    let private_zone = Memo::new(move |_| flags.get().2);
    let is_whitelisted = Signal::derive(move || {
        let (h, d, m) = flags.get();
        h || d || m || is_authed.get()
    });

    let access = ZoneAccess {
        home,
        members,
        private_zone,
        is_whitelisted,
        is_admin: is_admin_sig,
        loaded,
        flags,
    };
    provide_context(access.clone());

    // Fetch access flags from relay when user authenticates
    Effect::new(move |_| {
        let authed = is_authed.get();
        let pk = pubkey.get();
        if authed {
            if let Some(pk) = pk {
                let flags_sig = flags;
                let admin_sig = is_admin_sig;
                let loaded_sig = loaded;
                loaded_sig.set(false);
                leptos::task::spawn_local(async move {
                    match fetch_user_access(&pk).await {
                        Ok((h, d, m, admin)) => {
                            web_sys::console::log_1(
                                &format!(
                                    "[zone_access] flags for {}: home={}, members={}, private={}, admin={}",
                                    &pk[..8], h, d, m, admin
                                )
                                .into(),
                            );
                            flags_sig.set((h, d, m));
                            admin_sig.set(admin);
                        }
                        Err(e) => {
                            web_sys::console::error_1(
                                &format!("[zone_access] failed to fetch access: {e}").into(),
                            );
                        }
                    }
                    loaded_sig.set(true);
                });
            }
        } else {
            flags.set((false, false, false));
            is_admin_sig.set(false);
            loaded.set(false);
        }
    });
}

/// Resolve the relay HTTP base URL for whitelist API calls.
fn relay_api_base() -> String {
    crate::utils::relay_url::relay_api_base()
}

/// Fetch the user's access flags from the relay's check-whitelist endpoint.
///
/// Returns `(home, members, private, is_admin)`.
/// Parses the `access` object first (new format). Falls back to normalizing
/// the `cohorts` array for backwards compatibility with old relay versions.
async fn fetch_user_access(pubkey: &str) -> Result<(bool, bool, bool, bool), String> {
    let cfg = use_bbs_config();
    let url = format!("{}/api/check-whitelist?pubkey={}", relay_api_base(), pubkey);
    let win = web_sys::window().ok_or("No window")?;
    let resp_val = JsFuture::from(win.fetch_with_str(&url))
        .await
        .map_err(|e| format!("fetch error: {e:?}"))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| "Not a Response".to_string())?;
    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let text = JsFuture::from(resp.text().map_err(|e| format!("{e:?}"))?)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let text_str = text.as_string().ok_or("Not a string")?;
    let val: serde_json::Value =
        serde_json::from_str(&text_str).map_err(|e| format!("JSON parse: {e}"))?;

    let is_admin = val.get("isAdmin").and_then(|v| v.as_bool()).unwrap_or(false);

    // New format: { access: { home, members, private } }
    if let Some(access) = val.get("access") {
        let home = access.get(&cfg.zone_public_id).and_then(|v| v.as_bool()).unwrap_or(false);
        let members = access.get(&cfg.zone_members_id).and_then(|v| v.as_bool()).unwrap_or(false);
        let private_zone = access.get(&cfg.zone_private_id).and_then(|v| v.as_bool()).unwrap_or(false);
        return Ok((home, members, private_zone, is_admin));
    }

    // Fallback: normalize from cohorts array
    if is_admin {
        return Ok((true, true, true, true));
    }

    let cohorts: Vec<String> = val["cohorts"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let home = cohorts.iter().any(|c| cfg.zone_public_cohorts.contains(c));
    let members = cohorts.iter().any(|c| cfg.zone_members_cohorts.contains(c));
    let private_zone = cohorts.iter().any(|c| cfg.zone_private_cohorts.contains(c));

    Ok((home, members, private_zone, false))
}

/// Retrieve the zone access store from context.
pub fn use_zone_access() -> ZoneAccess {
    expect_context::<ZoneAccess>()
}
