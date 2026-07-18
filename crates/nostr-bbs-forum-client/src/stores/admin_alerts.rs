//! Admin alert producer — surfaces new members awaiting zone access.
//!
//! With no `auto_approve` zone configured, a fresh joiner is auto-whitelisted
//! with only the base `members` cohort: they can use the public zone but every
//! locked zone renders as a locked tile until an admin grants a zone cohort
//! (Admin → Users). Nothing pushed that fact to admins — a new joiner was only
//! visible if an admin happened to open the panel.
//!
//! This producer polls the whitelist (NIP-98-signed GET, admin-gated
//! server-side so it is a no-op for non-admins even if invoked) whenever the
//! signed-in user is an admin, classifies members that hold **no zone-gating
//! cohort**, and raises a [`NotificationKind::JoinRequest`] bell notification
//! for each member not seen before, linking to the admin panel. The seen-set
//! persists in `localStorage` so alerts fire once per member per browser, and
//! a first-run burst (or a batch of joiners between polls) collapses into one
//! summary notification instead of flooding the bell.
//!
//! Context discipline: the auth / zone-access / notification handles are all
//! `Copy` context stores captured once in [`start_admin_alerts`] (inside the
//! component tree) and threaded through the poll chain — `use_*` context
//! lookups are NOT valid inside detached timers or spawned futures.

use std::collections::HashSet;

use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::admin::{fetch_whitelist_rows, WhitelistUser};
use crate::auth::{use_auth, AuthStore};
use crate::stores::notifications::{use_notification_store, NotificationKind, NotificationStoreV2};
use crate::stores::zone_access::{use_zone_access, ZoneAccess};
use crate::stores::zones::{load_zones, ZoneVisibility};

/// `localStorage` key holding the JSON array of already-alerted pubkeys.
const SEEN_KEY: &str = "nostrbbs_admin_seen_joiners";

/// Poll cadence (5 minutes) — new joiners are rare; the first poll fires
/// immediately on admin session start.
const POLL_MS: i32 = 300_000;

/// Above this many unseen joiners in one poll, collapse to a single summary
/// notification (first run on an established deployment would otherwise flood
/// the bell with historical members).
const BURST_CAP: usize = 5;

/// The cohorts that gate entry to any non-public zone. A member holding none
/// of these is "awaiting zone access".
pub(crate) fn zone_gate_cohorts() -> HashSet<String> {
    load_zones()
        .iter()
        .filter(|z| z.visibility != ZoneVisibility::Public)
        .flat_map(|z| z.required_cohorts.iter().cloned())
        .collect()
}

/// Members awaiting a zone grant: not an admin, not an agent, and holding no
/// zone-gating cohort. Agents are provisioned via config, not the admin panel,
/// so alerting on them would be noise.
pub(crate) fn awaiting_zone_access<'a>(
    users: &'a [WhitelistUser],
    gate: &HashSet<String>,
) -> Vec<&'a WhitelistUser> {
    users
        .iter()
        .filter(|u| {
            !u.is_admin
                && !u.cohorts.iter().any(|c| c == "agent")
                && !u.cohorts.iter().any(|c| gate.contains(c))
        })
        .collect()
}

/// Short human label for a member: display name, else claimed handle, else
/// truncated pubkey.
fn member_label(user: &WhitelistUser) -> String {
    for candidate in [user.display_name.as_deref(), user.handle.as_deref()]
        .into_iter()
        .flatten()
    {
        if !candidate.trim().is_empty() {
            return candidate.trim().to_string();
        }
    }
    let pk = &user.pubkey;
    if pk.len() > 12 {
        format!("{}…{}", &pk[..8], &pk[pk.len() - 4..])
    } else {
        pk.clone()
    }
}

fn load_seen() -> HashSet<String> {
    web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
        .and_then(|s| s.get_item(SEEN_KEY).ok())
        .flatten()
        .and_then(|raw| serde_json::from_str::<Vec<String>>(&raw).ok())
        .map(|v| v.into_iter().collect())
        .unwrap_or_default()
}

fn save_seen(seen: &HashSet<String>) {
    if let Some(storage) = web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
    {
        let list: Vec<&String> = seen.iter().collect();
        if let Ok(raw) = serde_json::to_string(&list) {
            let _ = storage.set_item(SEEN_KEY, &raw);
        }
    }
}

/// One poll: fetch, classify, notify unseen joiners, persist the seen-set.
async fn poll_once(auth: AuthStore, store: NotificationStoreV2) {
    let Some(signer) = auth.get_signer() else {
        return;
    };
    let Ok(rows) = fetch_whitelist_rows(&*signer).await else {
        // Transient network/auth failure — the next scheduled poll retries.
        return;
    };

    let gate = zone_gate_cohorts();
    let awaiting = awaiting_zone_access(&rows, &gate);

    let mut seen = load_seen();
    let unseen: Vec<&&WhitelistUser> = awaiting
        .iter()
        .filter(|u| !seen.contains(&u.pubkey))
        .collect();
    if unseen.is_empty() {
        return;
    }

    if unseen.len() > BURST_CAP {
        store.add(
            NotificationKind::JoinRequest,
            "New members awaiting access",
            &format!(
                "{} members have joined and are waiting for zone access.",
                unseen.len()
            ),
            Some("/admin"),
        );
    } else {
        for user in &unseen {
            store.add(
                NotificationKind::JoinRequest,
                "New member awaiting access",
                &format!(
                    "{} has joined — grant zone access in Admin.",
                    member_label(user)
                ),
                Some("/admin"),
            );
        }
    }
    for user in &unseen {
        seen.insert(user.pubkey.clone());
    }
    save_seen(&seen);
}

/// Self-rescheduling poll chain. Each hop re-checks admin status so the chain
/// goes quiet after logout / demotion without needing cancellation handles.
/// All three handles are `Copy` context stores captured at mount.
fn schedule_poll(auth: AuthStore, zone_access: ZoneAccess, store: NotificationStoreV2) {
    crate::utils::set_timeout_once(
        move || {
            if zone_access.is_admin.get_untracked() {
                spawn_local(async move {
                    poll_once(auth, store).await;
                    schedule_poll(auth, zone_access, store);
                });
            } else {
                schedule_poll(auth, zone_access, store);
            }
        },
        POLL_MS,
    );
}

/// Mount the producer (call once from the app root, after the auth,
/// zone-access and notification providers). Fires an immediate poll when the
/// session turns out to be an admin's, then polls on [`POLL_MS`].
pub fn start_admin_alerts() {
    let auth = use_auth();
    let zone_access = use_zone_access();
    let store = use_notification_store();
    let started = StoredValue::new(false);
    Effect::new(move |_| {
        if zone_access.is_admin.get() && !started.get_value() {
            started.set_value(true);
            spawn_local(async move {
                poll_once(auth, store).await;
                schedule_poll(auth, zone_access, store);
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(pubkey: &str, cohorts: &[&str], is_admin: bool) -> WhitelistUser {
        WhitelistUser {
            pubkey: pubkey.to_string(),
            cohorts: cohorts.iter().map(|s| s.to_string()).collect(),
            display_name: None,
            added_at: None,
            is_admin,
            real_name: None,
            handle: None,
        }
    }

    fn gate() -> HashSet<String> {
        ["friends", "family", "business"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn members_only_cohort_is_awaiting() {
        let users = vec![user("a", &["members"], false)];
        assert_eq!(awaiting_zone_access(&users, &gate()).len(), 1);
    }

    #[test]
    fn zone_cohort_holder_is_not_awaiting() {
        let users = vec![user("a", &["members", "friends"], false)];
        assert!(awaiting_zone_access(&users, &gate()).is_empty());
    }

    #[test]
    fn admins_and_agents_are_excluded() {
        let users = vec![
            user("a", &["members"], true),
            user("b", &["members", "agent"], false),
        ];
        assert!(awaiting_zone_access(&users, &gate()).is_empty());
    }

    #[test]
    fn empty_cohorts_is_awaiting() {
        let users = vec![user("a", &[], false)];
        assert_eq!(awaiting_zone_access(&users, &gate()).len(), 1);
    }

    #[test]
    fn member_label_prefers_display_name_then_handle_then_pubkey() {
        let mut u = user(
            "11ed64225dd5e2c5e18f61ad43d5ad9272d08739d3a20dd25886197b0738663c",
            &[],
            false,
        );
        assert_eq!(member_label(&u), "11ed6422…663c");
        u.handle = Some("beema".to_string());
        assert_eq!(member_label(&u), "beema");
        u.display_name = Some("Beema".to_string());
        assert_eq!(member_label(&u), "Beema");
    }
}
