//! 3-flag zone access model: home, members, private.
//!
//! Provides reactive zone access context that maps user flags to visibility.
//! Zone enforcement is client-side (UX optimization); the relay is the
//! source of truth per ADR-022.
//!
//! On authentication, fetches the user's whitelist entry (including the
//! `access` object) from the relay's `/api/check-whitelist?pubkey=` endpoint.

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use crate::auth::use_auth;

/// Reactive zone access state provided via Leptos context.
#[derive(Clone, Debug)]
pub struct ZoneAccess {
    /// Whether the user has Home access.
    pub home: Memo<bool>,
    /// Whether the user has Members access.
    pub members: Memo<bool>,
    /// Whether the user has Minimoonoir access.
    pub private: Memo<bool>,
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
        match zone_id {
            "home" | "home-lobby" => self.home.get_untracked(),
            "members" => self.members.get_untracked(),
            "private" => self.private.get_untracked(),
            _ => false,
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
    let private = Memo::new(move |_| flags.get().2);
    let is_whitelisted = Signal::derive(move || {
        let (h, d, m) = flags.get();
        h || d || m || is_authed.get()
    });

    let access = ZoneAccess {
        home,
        members,
        private,
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

    let is_admin = val
        .get("isAdmin")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // New format: { access: { home, members, private } }
    if let Some(access) = val.get("access") {
        let home = access
            .get("home")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let members = access
            .get("members")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let private = access
            .get("private")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        return Ok((home, members, private, is_admin));
    }

    // Fallback: normalize from cohorts array
    if is_admin {
        return Ok((true, true, true, true));
    }

    let cohorts: Vec<String> = val["cohorts"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let home = cohorts
        .iter()
        .any(|c| matches!(c.as_str(), "home" | "lobby" | "approved" | "cross-access"));
    let members = cohorts.iter().any(|c| {
        matches!(
            c.as_str(),
            "members"
                | "business"
                | "business-only"
                | "trainers"
                | "trainees"
                | "ai-agents"
                | "agent"
                | "visionflow-full"
                | "cross-access"
        )
    });
    let private = cohorts.iter().any(|c| {
        matches!(
            c.as_str(),
            "private" | "private-only" | "private-business" | "cross-access"
        )
    });

    Ok((home, members, private, false))
}

/// Retrieve the zone access store from context.
pub fn use_zone_access() -> ZoneAccess {
    expect_context::<ZoneAccess>()
}
