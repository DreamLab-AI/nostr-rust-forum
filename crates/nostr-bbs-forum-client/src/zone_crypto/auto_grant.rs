//! Zone-key grants that do not wait for an admin to open the Encryption tab
//! (ADR-2016 follow-on: "a new member needs a grant on approval").
//!
//! Every grant is still built and sealed in an admin's browser, so the relay
//! and the host never hold a zone key. Two triggers:
//!
//! - **On allocation.** When an admin gives a member a cohort (the Members
//!   table, a section request, a registration), the admin's browser sends
//!   that member the key of every encrypted zone the cohort opens.
//! - **On sign-in.** Once per page load, an admin's browser checks every key
//!   it holds against the relay's roster and grants it to each eligible member
//!   its ledger has no record of. This covers members who arrive with no admin
//!   browser involved (invite redemption, `auto_approve` zones) and
//!   allocations made from a device that did not hold the key.
//!
//! Targets come from a fresh read of the relay's roster and follow the
//! Encryption tab's rules ([`grant_targets`], [`grant_plan`] with history), so
//! agents get a key only in an `agent_keys` zone. An admin signed in through a
//! NIP-07 extension is not sent a sign-in sweep: each grant is a NIP-44
//! encryption and a signature, which an extension may prompt for one by one.
//! The sweep tells that admin how many grants are waiting instead.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use leptos::prelude::*;
use nostr_bbs_core::signer::Signer;
use wasm_bindgen_futures::spawn_local;

use super::store::{try_use_zone_key_store, ZoneKeyStore};
use super::{build_grant_wrap, grant_plan, grant_targets, ZoneKey};
use crate::auth::{use_auth, AuthStore};
use crate::components::toast::{ToastStore, ToastVariant};
use crate::relay::RelayConnection;
use crate::stores::zones::load_zones;

fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// The parts of a zone that decide who holds its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneRule {
    /// Zone id, as in `ZONE_CONFIG`.
    pub id: String,
    /// Cohorts that admit a member to the zone.
    pub required_cohorts: Vec<String>,
    /// Whether agents receive the key.
    pub agent_keys: bool,
}

/// The encrypted zones of this deployment (empty with the encryption gate off).
pub fn encrypted_zone_rules() -> Vec<ZoneRule> {
    let gate_on = super::encryption_enabled();
    load_zones()
        .into_iter()
        .filter(|z| super::zone_is_encrypted(gate_on, z.encrypted))
        .map(|z| ZoneRule {
            id: z.id,
            required_cohorts: z.required_cohorts,
            agent_keys: z.agent_keys,
        })
        .collect()
}

/// The grants still owed, across every zone this admin holds a key for.
///
/// `held` maps zone id to the keys this admin holds for it; `sent` maps
/// `(zone, epoch)` to the members this device's ledger records as granted.
/// A member is owed a zone's newest key when they are one of its
/// [`grant_targets`] and the ledger has no record of it; with that grant go
/// the earlier keys they were not sent ([`grant_plan`] with history), so a
/// member who joins after a rotation can read the zone's older messages.
/// `only` narrows the recipients to those pubkeys (an allocation).
pub fn plan_missing(
    zones: &[ZoneRule],
    members: &[(String, Vec<String>)],
    me: &str,
    held: &HashMap<String, Vec<ZoneKey>>,
    sent: &HashMap<(String, u32), HashSet<String>>,
    only: Option<&HashSet<String>>,
) -> Vec<(ZoneKey, Vec<String>)> {
    let none = HashSet::new();
    let mut out = Vec::new();
    for zone in zones {
        let Some(keys) = held.get(&zone.id).filter(|k| !k.is_empty()) else {
            continue;
        };
        let Some(newest) = keys.iter().map(|k| k.epoch).max() else {
            continue;
        };
        let have = sent.get(&(zone.id.clone(), newest)).unwrap_or(&none);
        let recipients: Vec<String> =
            grant_targets(members, &zone.required_cohorts, me, zone.agent_keys)
                .into_iter()
                .filter(|pk| only.is_none_or(|o| o.contains(pk)))
                .filter(|pk| !have.contains(pk))
                .collect();
        if recipients.is_empty() {
            continue;
        }
        out.extend(grant_plan(keys, &recipients, true, |epoch| {
            sent.get(&(zone.id.clone(), epoch))
                .cloned()
                .unwrap_or_default()
        }));
    }
    out
}

/// What one run of grants did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GrantReport {
    /// Grants handed to the relay.
    pub sent: usize,
    /// Grants that could not be built or sent.
    pub failed: usize,
    /// Distinct members granted at least one key.
    pub members: usize,
}

/// Called with each grant once the relay has accepted it and it is recorded.
pub type OnRecorded = Rc<dyn Fn(&ZoneKey, &str)>;

/// Number of single grants in `plan`.
pub fn grant_count(plan: &[(ZoneKey, Vec<String>)]) -> usize {
    plan.iter().map(|(_, r)| r.len()).sum()
}

/// Send `plan`: one gift wrap per recipient and key, each recorded in this
/// device's ledger once the relay accepts it. `on_recorded` runs after each
/// record (the Encryption tab updates its "granted here" list from it).
pub async fn send_grants(
    store: ZoneKeyStore,
    relay: &RelayConnection,
    signer: &dyn Signer,
    plan: Vec<(ZoneKey, Vec<String>)>,
    on_recorded: OnRecorded,
) -> GrantReport {
    let members: HashSet<String> = plan.iter().flat_map(|(_, r)| r.iter().cloned()).collect();
    let mut report = GrantReport {
        members: members.len(),
        ..GrantReport::default()
    };
    for (key, recipients) in plan {
        for pk in recipients {
            let Ok(wrap) = build_grant_wrap(signer, &pk, &key, now_secs()).await else {
                report.failed += 1;
                continue;
            };
            let key_for_ack = key.clone();
            let on_recorded = on_recorded.clone();
            let on_ok = Rc::new(move |ok: bool, _msg: String| {
                if !ok {
                    return;
                }
                let key = key_for_ack.clone();
                let pk = pk.clone();
                let on_recorded = on_recorded.clone();
                spawn_local(async move {
                    store
                        .record_grants(&key.zone, key.epoch, std::slice::from_ref(&pk))
                        .await;
                    on_recorded(&key, &pk);
                });
            });
            if relay.publish_with_ack(&wrap, Some(on_ok)).is_err() {
                report.failed += 1;
            } else {
                report.sent += 1;
            }
        }
    }
    report
}

/// The handles a grant needs, captured while a reactive owner is in scope
/// (spawned tasks run without one, so `use_context` is unavailable there).
#[derive(Clone)]
pub struct AutoGrant {
    store: ZoneKeyStore,
    relay: RelayConnection,
    auth: AuthStore,
    toasts: Option<ToastStore>,
}

impl AutoGrant {
    /// Capture the handles, or `None` when this deployment has no encrypted
    /// zone or no zone-key store.
    pub fn capture() -> Option<Self> {
        if encrypted_zone_rules().is_empty() {
            return None;
        }
        Some(Self {
            store: try_use_zone_key_store()?,
            relay: use_context::<RelayConnection>()?,
            auth: use_auth(),
            toasts: use_context::<ToastStore>(),
        })
    }

    /// Whether this device's keys have been loaded from IndexedDB.
    pub fn keys_loaded(&self) -> Signal<bool> {
        self.store.hydrated.into()
    }

    /// Work out the grants owed, from a fresh roster read. `only` narrows
    /// them to those members.
    async fn plan(
        &self,
        signer: &dyn Signer,
        only: Option<&HashSet<String>>,
    ) -> Result<Vec<(ZoneKey, Vec<String>)>, String> {
        let zones = encrypted_zone_rules();
        let held: HashMap<String, Vec<ZoneKey>> = zones
            .iter()
            .map(|z| (z.id.clone(), self.store.all_for_zone(&z.id)))
            .filter(|(_, keys)| !keys.is_empty())
            .collect();
        if held.is_empty() {
            return Ok(Vec::new());
        }
        let rows = crate::admin::fetch_whitelist_rows(signer).await?;
        let members: Vec<(String, Vec<String>)> =
            rows.into_iter().map(|u| (u.pubkey, u.cohorts)).collect();
        let mut sent = HashMap::new();
        for keys in held.values() {
            for k in keys {
                let s = self.store.grants_sent(&k.zone, k.epoch).await;
                sent.insert((k.zone.clone(), k.epoch), s);
            }
        }
        let me = self.auth.pubkey().get_untracked().unwrap_or_default();
        Ok(plan_missing(&zones, &members, &me, &held, &sent, only))
    }

    async fn run(&self, only: Option<&HashSet<String>>) -> Result<GrantReport, String> {
        let signer = self
            .auth
            .get_signer()
            .ok_or_else(|| "Sign in again to grant zone keys.".to_string())?;
        let plan = self.plan(&*signer, only).await?;
        if plan.is_empty() {
            return Ok(GrantReport::default());
        }
        Ok(send_grants(self.store, &self.relay, &*signer, plan, Rc::new(|_, _| ())).await)
    }

    fn toast(&self, message: String, variant: ToastVariant) {
        if let Some(t) = self.toasts {
            t.show(message, variant);
        }
    }

    /// After `pubkey` was given a cohort: send them the key of every
    /// encrypted zone they now belong to that this device holds, and say so.
    pub fn after_allocation(&self, pubkey: &str) {
        let this = self.clone();
        let only: HashSet<String> = std::iter::once(pubkey.to_ascii_lowercase()).collect();
        spawn_local(async move {
            match this.run(Some(&only)).await {
                Ok(r) if r.sent > 0 && r.failed == 0 => this.toast(
                    format!("Sent {} zone key(s) to the member.", r.sent),
                    ToastVariant::Success,
                ),
                Ok(r) if r.failed > 0 => this.toast(
                    format!(
                        "{} zone key grant(s) could not be sent. Retry from Admin → Encryption.",
                        r.failed
                    ),
                    ToastVariant::Error,
                ),
                Ok(_) => {}
                Err(e) => this.toast(
                    format!("Zone keys were not granted: {e}"),
                    ToastVariant::Error,
                ),
            }
        });
    }

    /// The sign-in sweep: grant every held key to each eligible member this
    /// device has no record of granting. With a NIP-07 signer, only report.
    pub fn sweep(&self) {
        let this = self.clone();
        spawn_local(async move {
            let Some(signer) = this.auth.get_signer() else {
                return;
            };
            let extension = this.auth.state.with_untracked(|s| s.is_nip07);
            let plan = match this.plan(&*signer, None).await {
                Ok(p) => p,
                Err(e) => {
                    web_sys::console::warn_1(&format!("[zone-key] sweep skipped: {e}").into());
                    return;
                }
            };
            let waiting = grant_count(&plan);
            if waiting == 0 {
                return;
            }
            if extension {
                let members: HashSet<&String> = plan.iter().flat_map(|(_, r)| r.iter()).collect();
                this.toast(
                    format!(
                        "{} member(s) are missing a zone key. Grant them from Admin → Encryption.",
                        members.len()
                    ),
                    ToastVariant::Info,
                );
                return;
            }
            let r = send_grants(this.store, &this.relay, &*signer, plan, Rc::new(|_, _| ())).await;
            if r.failed > 0 {
                this.toast(
                    format!(
                        "Sent {} zone key grant(s); {} failed. Retry from Admin → Encryption.",
                        r.sent, r.failed
                    ),
                    ToastVariant::Error,
                );
            } else {
                this.toast(
                    format!(
                        "Sent zone keys to {} member(s) who were missing them.",
                        r.members
                    ),
                    ToastVariant::Success,
                );
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone_crypto::generate_zone_key;

    const ME: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn pk(c: char) -> String {
        c.to_string().repeat(64)
    }

    fn key(zone: &str, epoch: u32) -> ZoneKey {
        generate_zone_key(zone, epoch, ME, 0).expect("key")
    }

    fn rule(id: &str, cohort: &str, agent_keys: bool) -> ZoneRule {
        ZoneRule {
            id: id.into(),
            required_cohorts: vec![cohort.into()],
            agent_keys,
        }
    }

    fn members() -> Vec<(String, Vec<String>)> {
        vec![
            (ME.into(), vec!["admin".into(), "family".into()]),
            (pk('b'), vec!["family".into()]),
            (pk('c'), vec!["business".into()]),
            (pk('d'), vec!["family".into(), "agent".into()]),
        ]
    }

    fn held(zone: &str, epochs: &[u32]) -> HashMap<String, Vec<ZoneKey>> {
        let keys = epochs.iter().map(|e| key(zone, *e)).collect();
        HashMap::from([(zone.to_string(), keys)])
    }

    #[test]
    fn grants_the_newest_key_to_every_eligible_member_not_on_record() {
        let zones = [rule("zone3", "family", false)];
        let sent = HashMap::from([(("zone3".to_string(), 1), HashSet::from([ME.to_string()]))]);
        let plan = plan_missing(&zones, &members(), ME, &held("zone3", &[1]), &sent, None);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].0.epoch, 1);
        // b is in the zone; c is not; d is an agent in a zone without agent_keys.
        assert_eq!(plan[0].1, vec![pk('b')]);
    }

    #[test]
    fn agents_get_the_key_only_where_the_zone_allows_it() {
        let zones = [rule("zone4", "family", true)];
        let plan = plan_missing(
            &zones,
            &members(),
            ME,
            &held("zone4", &[1]),
            &HashMap::new(),
            None,
        );
        assert!(plan[0].1.contains(&pk('d')));
    }

    #[test]
    fn a_late_joiner_also_gets_the_keys_they_missed() {
        let zones = [rule("zone3", "family", false)];
        let everyone_else = HashSet::from([ME.to_string()]);
        let sent = HashMap::from([
            (("zone3".to_string(), 1), everyone_else.clone()),
            (("zone3".to_string(), 2), everyone_else),
        ]);
        let plan = plan_missing(&zones, &members(), ME, &held("zone3", &[1, 2]), &sent, None);
        let epochs: Vec<u32> = plan.iter().map(|(k, _)| k.epoch).collect();
        assert_eq!(epochs, vec![2, 1]);
        assert!(plan.iter().all(|(_, r)| r == &vec![pk('b')]));
    }

    #[test]
    fn nobody_is_granted_twice() {
        let zones = [rule("zone3", "family", false)];
        let all = HashSet::from([ME.to_string(), pk('b')]);
        let sent = HashMap::from([(("zone3".to_string(), 1), all)]);
        let plan = plan_missing(&zones, &members(), ME, &held("zone3", &[1]), &sent, None);
        assert!(plan.is_empty());
    }

    #[test]
    fn an_allocation_grants_only_that_member() {
        let zones = [
            rule("zone3", "family", false),
            rule("zone2", "business", false),
        ];
        let mut keys = held("zone3", &[1]);
        keys.extend(held("zone2", &[1]));
        let only = HashSet::from([pk('c')]);
        let plan = plan_missing(&zones, &members(), ME, &keys, &HashMap::new(), Some(&only));
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].0.zone, "zone2");
        assert_eq!(plan[0].1, vec![pk('c')]);
    }

    #[test]
    fn a_zone_this_device_holds_no_key_for_is_skipped() {
        let zones = [
            rule("zone3", "family", false),
            rule("zone2", "business", false),
        ];
        let plan = plan_missing(
            &zones,
            &members(),
            ME,
            &held("zone3", &[1]),
            &HashMap::new(),
            None,
        );
        assert!(plan.iter().all(|(k, _)| k.zone == "zone3"));
        assert_eq!(grant_count(&plan), 2); // me and b
    }
}
