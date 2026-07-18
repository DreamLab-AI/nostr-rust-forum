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
use crate::stores::zones::{load_zones, Zone};

/// Friendly copy shown to the user when the whitelist/access lookup fails.
///
/// Raw `JsValue` / fetch errors are logged to the browser console for
/// debugging; the user only ever sees this reassuring message.
const ACCESS_LOAD_ERROR: &str =
    "Could not load your access details — check your connection and try again.";

/// Reactive zone access state provided via Leptos context.
///
/// `Copy`: every field is a copyable reactive handle (`Memo`/`Signal`/
/// `RwSignal`), so `ZoneAccess` copies freely into the `move ||` reactive
/// closures that read `home_zone()` for zone-first nav/breadcrumbs (ADR-107)
/// without turning their enclosing `view!` children into `FnOnce`.
#[derive(Clone, Copy, Debug)]
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
    /// Raw cohort list for the authenticated user (from the relay's
    /// check-whitelist response). Drives config-driven zone membership so the
    /// tile renderer is no longer coupled to the legacy 3-flag model.
    pub cohorts: RwSignal<Vec<String>>,
    /// Bumped to force a re-fetch of the whitelist. Signup grants the user's
    /// cohorts server-side AFTER the client's initial fetch (username-claim
    /// creates the whitelist row), so a brand-new joiner would otherwise be
    /// stuck with the empty cohorts read before the grant landed. `refresh()`
    /// bumps this; the fetch effect tracks it and re-reads.
    refresh_trigger: RwSignal<u32>,
}

impl ZoneAccess {
    /// Force a re-fetch of the whitelist/cohorts from the relay. Call after an
    /// action that changes the user's server-side access (e.g. a new joiner's
    /// username-claim grants their cohorts) so the client picks up the grant
    /// without a full reload — driving the zone-first landing and tile gating.
    pub fn refresh(&self) {
        self.refresh_trigger.update(|n| *n = n.wrapping_add(1));
    }

    /// Config-driven membership check for an arbitrary zone.
    ///
    /// A zone is "entered" (rendered as a normal, openable tile) when the user
    /// is an admin, OR the zone requires no cohorts, OR the user holds one of
    /// the zone's `required_cohorts`. This mirrors the relay's read gate; the
    /// relay remains the security boundary (ADR-022).
    pub fn is_member_of(&self, zone: &crate::stores::zones::Zone) -> bool {
        if self.is_admin.get() {
            return true;
        }
        zone.is_member(&self.cohorts.get())
    }

    /// Reactively resolve the caller's home zone (ADR-107 — zone-first landing).
    ///
    /// Returns the single LOCKED zone the member is authorised for, or `None`
    /// for admins, multi-zone members, and until the whitelist/access fetch has
    /// completed (`loaded`). Reads `loaded`, `is_admin` and `cohorts` so callers
    /// re-run when any of them change. Only meaningful once `loaded` is true.
    pub fn home_zone(&self) -> Option<Zone> {
        // Read all three signals unconditionally so every caller is reactive on
        // each, regardless of the `loaded` early-return below.
        let loaded = self.loaded.get();
        let is_admin = self.is_admin.get();
        let cohorts = self.cohorts.get();
        if !loaded {
            return None;
        }
        home_zone_for(&load_zones(), &cohorts, is_admin)
    }
}

/// Pure home-zone derivation (ADR-107 — zone-first landing).
///
/// The "home zone" is the single LOCKED zone a member is authorised for. It is
/// `None` when:
/// - the user is an admin (admins see every zone, so there is no single home);
/// - no accessible locked zone exists; or
/// - more than one accessible locked zone exists (a genuine multi-zone member).
///
/// A zone counts only when it has non-empty `required_cohorts` (an open/public
/// landing zone, with empty `required_cohorts`, is never a home zone) AND the
/// user's cohorts satisfy [`Zone::is_member`].
pub fn home_zone_for(zones: &[Zone], cohorts: &[String], is_admin: bool) -> Option<Zone> {
    if is_admin {
        return None;
    }
    let mut locked_accessible = zones
        .iter()
        .filter(|z| !z.required_cohorts.is_empty() && z.is_member(cohorts));
    let first = locked_accessible.next()?;
    // Exactly one accessible locked zone → that is the home zone; two or more
    // means a genuine multi-zone member with no single landing target.
    match locked_accessible.next() {
        Some(_) => None,
        None => Some(first.clone()),
    }
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
    let cohorts_sig = RwSignal::new(Vec::<String>::new());
    let refresh_trigger = RwSignal::new(0u32);

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
        cohorts: cohorts_sig,
        refresh_trigger,
    };
    provide_context(access);

    // Fetch access flags from relay when user authenticates. Also re-runs when
    // `refresh_trigger` is bumped (e.g. by signup after the username-claim grants
    // the new joiner's cohorts server-side).
    Effect::new(move |_| {
        refresh_trigger.track();
        let authed = is_authed.get();
        let pk = pubkey.get();
        if authed {
            if let Some(pk) = pk {
                let flags_sig = flags;
                let admin_sig = is_admin_sig;
                let loaded_sig = loaded;
                let cohorts_set = cohorts_sig;
                loaded_sig.set(false);

                // Dev-auth: bypass the relay API and apply local flags
                #[cfg(feature = "dev-auth")]
                {
                    crate::auth::dev::dev_apply_zone_access(
                        admin_sig,
                        flags_sig,
                        loaded_sig,
                        cohorts_set,
                        &pk,
                    );
                }

                #[cfg(not(feature = "dev-auth"))]
                leptos::task::spawn_local(async move {
                    match fetch_user_access(&pk).await {
                        Ok((h, d, m, admin, cohorts)) => {
                            web_sys::console::log_1(
                                &format!(
                                    "[zone_access] flags for {}: home={}, members={}, private={}, admin={}, cohorts={:?}",
                                    &pk[..8], h, d, m, admin, cohorts
                                )
                                .into(),
                            );
                            flags_sig.set((h, d, m));
                            admin_sig.set(admin);
                            cohorts_set.set(cohorts);
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
            cohorts_sig.set(Vec::new());
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
/// Returns `(home, members, private, is_admin, cohorts)`.
/// Parses the `access` object first (new format). Falls back to normalizing
/// the `cohorts` array for backwards compatibility with old relay versions.
/// The raw `cohorts` array is always surfaced (when present) so config-driven
/// zones can compute membership without the legacy 3-flag mapping.
async fn fetch_user_access(pubkey: &str) -> Result<(bool, bool, bool, bool, Vec<String>), String> {
    let url = format!("{}/api/check-whitelist?pubkey={}", relay_api_base(), pubkey);
    let win = web_sys::window().ok_or_else(|| {
        web_sys::console::error_1(&"[zone_access] no window object available".into());
        ACCESS_LOAD_ERROR.to_string()
    })?;
    let resp_val = JsFuture::from(win.fetch_with_str(&url))
        .await
        .map_err(|e| {
            web_sys::console::error_1(
                &format!("[zone_access] fetch failed for {url}: {e:?}").into(),
            );
            ACCESS_LOAD_ERROR.to_string()
        })?;
    let resp: web_sys::Response = resp_val.dyn_into().map_err(|e| {
        web_sys::console::error_1(
            &format!("[zone_access] unexpected fetch response type: {e:?}").into(),
        );
        ACCESS_LOAD_ERROR.to_string()
    })?;
    if !resp.ok() {
        web_sys::console::error_1(
            &format!(
                "[zone_access] check-whitelist returned HTTP {}",
                resp.status()
            )
            .into(),
        );
        return Err(ACCESS_LOAD_ERROR.to_string());
    }
    let text_promise = resp.text().map_err(|e| {
        web_sys::console::error_1(
            &format!("[zone_access] failed to read response body: {e:?}").into(),
        );
        ACCESS_LOAD_ERROR.to_string()
    })?;
    let text = JsFuture::from(text_promise).await.map_err(|e| {
        web_sys::console::error_1(
            &format!("[zone_access] failed to await response body: {e:?}").into(),
        );
        ACCESS_LOAD_ERROR.to_string()
    })?;
    let text_str = text.as_string().ok_or_else(|| {
        web_sys::console::error_1(&"[zone_access] response body was not a string".into());
        ACCESS_LOAD_ERROR.to_string()
    })?;
    let val: serde_json::Value = serde_json::from_str(&text_str).map_err(|e| {
        web_sys::console::error_1(&format!("[zone_access] JSON parse failed: {e}").into());
        ACCESS_LOAD_ERROR.to_string()
    })?;

    let is_admin = val
        .get("isAdmin")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Raw cohort list — surfaced for config-driven zone membership regardless
    // of which access representation the relay returned.
    let cohorts: Vec<String> = val["cohorts"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

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
        return Ok((home, members, private, is_admin, cohorts));
    }

    // Fallback: normalize from cohorts array
    if is_admin {
        return Ok((true, true, true, true, cohorts));
    }

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

    Ok((home, members, private, false, cohorts))
}

/// Retrieve the zone access store from context.
pub fn use_zone_access() -> ZoneAccess {
    expect_context::<ZoneAccess>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stores::zones::ZoneVisibility;

    fn locked_zone(id: &str, cohort: &str) -> Zone {
        Zone {
            id: id.to_string(),
            slug: None,
            display_name: String::new(),
            required_cohorts: vec![cohort.to_string()],
            write_cohorts: None,
            banner_image_url: None,
            visibility: ZoneVisibility::Locked,
            encrypted: false,
            accent_hex: None,
        }
    }

    fn public_zone(id: &str) -> Zone {
        Zone {
            id: id.to_string(),
            slug: None,
            display_name: String::new(),
            required_cohorts: vec![],
            write_cohorts: None,
            banner_image_url: None,
            visibility: ZoneVisibility::Public,
            encrypted: false,
            accent_hex: None,
        }
    }

    #[test]
    fn home_zone_single_locked_membership_returns_it() {
        let zones = vec![public_zone("public"), locked_zone("business", "business")];
        let cohorts = vec!["business".to_string()];
        let hz = home_zone_for(&zones, &cohorts, false);
        assert_eq!(hz.map(|z| z.id), Some("business".to_string()));
    }

    #[test]
    fn home_zone_admin_is_none() {
        let zones = vec![locked_zone("business", "business")];
        let cohorts = vec!["business".to_string()];
        assert!(home_zone_for(&zones, &cohorts, true).is_none());
    }

    #[test]
    fn home_zone_multiple_locked_memberships_is_none() {
        let zones = vec![
            locked_zone("business", "business"),
            locked_zone("family", "family"),
        ];
        let cohorts = vec!["business".to_string(), "family".to_string()];
        assert!(home_zone_for(&zones, &cohorts, false).is_none());
    }

    #[test]
    fn home_zone_public_only_access_is_none() {
        // A member with no cohorts can only read the public zone; a public zone
        // (empty required_cohorts) never counts as a home zone.
        let zones = vec![public_zone("public"), locked_zone("business", "business")];
        let cohorts: Vec<String> = vec![];
        assert!(home_zone_for(&zones, &cohorts, false).is_none());
    }
}
