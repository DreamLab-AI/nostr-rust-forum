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
//! NIP-07 extension is not sent a sign-in sweep (it still looks up inbox keys, to count who is owed a re-issue): each grant is a NIP-44
//! encryption and a signature, which an extension may prompt for one by one.
//! The sweep tells that admin how many grants are waiting instead.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use leptos::prelude::*;
use nostr_bbs_core::signer::Signer;
use wasm_bindgen_futures::spawn_local;

use super::inbox_key::{grant_target, lookup_inbox_key, recipient_keys_enabled, Lookup};
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

/// The outcome of planning the grants owed: what to auto-send now, and the
/// brand-new targets held back for a one-time admin confirmation.
///
/// The split is the first-grant confirmation gate (deepsec #1): the admin's
/// own relay is the membership authority (ADR-2016), so a compromised or
/// hostile relay could inject an attacker pubkey into a required cohort. The
/// sweep must not silently wrap the zone epoch key to a pubkey it has never
/// granted before on nothing but the relay's say-so. A never-granted pubkey is
/// surfaced in [`pending`](Self::pending) for the admin to confirm once; a
/// pubkey already in the ledger (granted a prior epoch) or on the persisted
/// approved set is "known" and auto-grants, so rotation stays automatic.
//
// Follow-up (option B, robust fix): signed membership records — each member
// admitted by an admin-signed join event the client verifies — so the client
// never trusts raw relay roster rows at all. That is an ADR-2016 trust-model
// change (the relay stops being the sole membership authority) and is tracked
// separately.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MissingPlan {
    /// Grants to send now: one `(key, recipients)` pair per epoch, to targets
    /// that are known (previously granted) or admin-approved.
    pub grants: Vec<(ZoneKey, Vec<String>)>,
    /// `(zone, pubkey)` pairs of never-before-granted targets. Not wrapped:
    /// surfaced for the admin to approve once (see
    /// [`AutoGrant::approve`](crate::zone_crypto::auto_grant::AutoGrant::approve)).
    pub pending: Vec<(String, String)>,
}

/// The grants still owed, across every zone this admin holds a key for, split
/// by the first-grant confirmation gate.
///
/// `held` maps zone id to the keys this admin holds for it; `sent` maps
/// `(zone, epoch)` to the members this device's ledger records as granted at
/// the key they would be granted at now. `known` maps zone id to the pubkeys
/// that may be auto-granted without a fresh confirmation — those the ledger
/// has ever granted any epoch of the zone, plus the persisted approved set.
///
/// A member is owed a zone's newest key when they are one of its
/// [`grant_targets`] and the ledger has no record of it; with that grant go
/// the earlier keys they were not sent ([`grant_plan`] with history), so a
/// member who joins after a rotation can read the zone's older messages. A
/// target that is `me`, or in `known` for the zone, auto-grants; any other
/// never-granted target lands in [`MissingPlan::pending`] instead — unless
/// `auto_grant_new` is set (an explicit admin allocation), when new targets
/// both auto-grant and are reported in `pending` so the caller can persist the
/// approval. `only` narrows the recipients to those pubkeys (an allocation).
// Each parameter is a distinct, named input (roster, identity, held keys,
// ledger history, the known/approved set, the allocation flag and the `only`
// filter); bundling them would hide rather than clarify, so the arg-count lint
// is allowed here deliberately.
#[allow(clippy::too_many_arguments)]
pub fn plan_missing(
    zones: &[ZoneRule],
    members: &[(String, Vec<String>)],
    me: &str,
    held: &HashMap<String, Vec<ZoneKey>>,
    sent: &HashMap<(String, u32), HashSet<String>>,
    known: &HashMap<String, HashSet<String>>,
    auto_grant_new: bool,
    only: Option<&HashSet<String>>,
) -> MissingPlan {
    let none = HashSet::new();
    let me_lower = me.to_ascii_lowercase();
    let mut out = MissingPlan::default();
    for zone in zones {
        let Some(keys) = held.get(&zone.id).filter(|k| !k.is_empty()) else {
            continue;
        };
        let Some(newest) = keys.iter().map(|k| k.epoch).max() else {
            continue;
        };
        let have = sent.get(&(zone.id.clone(), newest)).unwrap_or(&none);
        let known_z = known.get(&zone.id).unwrap_or(&none);
        let recipients = grant_targets(members, &zone.required_cohorts, me, zone.agent_keys)
            .into_iter()
            .filter(|pk| only.is_none_or(|o| o.contains(pk)))
            .filter(|pk| !have.contains(pk));
        let mut auto: Vec<String> = Vec::new();
        for pk in recipients {
            if pk == me_lower || known_z.contains(&pk) {
                auto.push(pk);
            } else {
                out.pending.push((zone.id.clone(), pk.clone()));
                if auto_grant_new {
                    auto.push(pk);
                }
            }
        }
        if auto.is_empty() {
            continue;
        }
        out.grants.extend(grant_plan(keys, &auto, true, |epoch| {
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

/// The key each of `members` should be granted at, from the auth-worker's
/// inbox-key lookup. Empty with `RECIPIENT_KEYS_ENABLED` off (no requests
/// made): every grant then goes to the member's identity, as before. A member
/// whose lookup failed maps to `Err`.
pub async fn resolve_targets(
    signer: &dyn Signer,
    members: &HashSet<String>,
) -> HashMap<String, Result<String, String>> {
    let mut out = HashMap::new();
    if !recipient_keys_enabled() {
        return out;
    }
    for m in members {
        let l: Lookup = lookup_inbox_key(signer, m).await;
        out.insert(m.clone(), grant_target(m, l));
    }
    out
}

/// The lookups that gave a key, as member to recipient key. A member whose
/// lookup failed is left out, so only a definite answer decides who is owed.
pub fn granted_targets(
    resolved: HashMap<String, Result<String, String>>,
) -> HashMap<String, String> {
    resolved
        .into_iter()
        .filter_map(|(m, t)| t.ok().map(|t| (m, t)))
        .collect()
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
    let targets = resolve_targets(signer, &members).await;
    // Tickets need the relay's zone-group bindings. A failed load falls back
    // to the 21453 grant for every recipient.
    if super::tickets::zone_groups_enabled() {
        if let Err(e) = super::tickets::ensure_bindings_loaded().await {
            web_sys::console::warn_1(&format!("[zone-key] bindings: {e}").into());
        }
    }
    for (key, recipients) in plan {
        for pk in recipients {
            // A failed lookup is not "no inbox key": wrapping to the identity
            // would put the grant back where the inbox key exists to keep it
            // from. The member stays unrecorded and is retried.
            let target = match targets.get(&pk) {
                Some(Ok(t)) => t.clone(),
                Some(Err(e)) => {
                    web_sys::console::warn_1(&format!("[zone-key] inbox lookup: {e}").into());
                    report.failed += 1;
                    continue;
                }
                None => pk.clone(),
            };
            // With ZONE_GROUPS_ENABLED, a zone bound to a group identity this
            // browser holds gets an NIP-171 ticket (ADR-2028 decision 2);
            // every other case keeps the 21453 grant.
            let ticket = if super::tickets::zone_groups_enabled() {
                super::tickets::issue_ticket_wrap(
                    &super::tickets::HeldGroupIdentities,
                    super::tickets::loaded_bindings().as_ref(),
                    &key,
                    &pk,
                    &target,
                    now_secs(),
                )
                .await
            } else {
                None
            };
            let built = match ticket {
                Some(t) => t,
                None => build_grant_wrap(signer, &target, &key, now_secs()).await,
            };
            let Ok(wrap) = built else {
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
                let target = target.clone();
                let on_recorded = on_recorded.clone();
                spawn_local(async move {
                    store
                        .record_grants(&key.zone, key.epoch, &[(pk.clone(), target)])
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

    /// Work out the grants owed, from a fresh roster read, split by the
    /// first-grant confirmation gate. `only` narrows them to those members;
    /// `auto_grant_new` auto-grants (and reports) never-granted targets instead
    /// of holding them pending — set for an explicit admin allocation, never
    /// for the silent sweep.
    async fn plan(
        &self,
        signer: &dyn Signer,
        only: Option<&HashSet<String>>,
        auto_grant_new: bool,
    ) -> Result<MissingPlan, String> {
        let zones = encrypted_zone_rules();
        let held: HashMap<String, Vec<ZoneKey>> = zones
            .iter()
            .map(|z| (z.id.clone(), self.store.all_for_zone(&z.id)))
            .filter(|(_, keys)| !keys.is_empty())
            .collect();
        if held.is_empty() {
            return Ok(MissingPlan::default());
        }
        let rows = crate::admin::fetch_whitelist_rows(signer).await?;
        let members: Vec<(String, Vec<String>)> =
            rows.into_iter().map(|u| (u.pubkey, u.cohorts)).collect();
        // Where each member's grant would go now. Empty with the flag off
        // (every member counts at their identity key, as before). An
        // extension admin looks up too: re-issuing needs the inbox keys, and
        // the cost is one signature prompt per lookup.
        let candidates: HashSet<String> = members
            .iter()
            .map(|(m, _)| m.clone())
            .filter(|m| only.is_none_or(|o| o.contains(m)))
            .collect();
        let targets = granted_targets(resolve_targets(signer, &candidates).await);
        let mut sent = HashMap::new();
        // Pubkeys that may be auto-granted without a fresh confirmation:
        // ever granted any held epoch (recipient key irrelevant, so a re-issue
        // to an existing member's new inbox key is never gated) plus the
        // persisted approved set. Built from the device's own ledger, never
        // the relay's roster.
        let mut known: HashMap<String, HashSet<String>> = HashMap::new();
        for (zone, keys) in &held {
            for k in keys {
                let s = self.store.grants_sent_to(&k.zone, k.epoch, &targets).await;
                sent.insert((k.zone.clone(), k.epoch), s);
            }
            let epochs: Vec<u32> = keys.iter().map(|k| k.epoch).collect();
            let mut k = self.store.members_ever_granted(zone, &epochs).await;
            k.extend(self.store.approved_targets(zone).await);
            known.insert(zone.clone(), k);
        }
        let me = self.auth.pubkey().get_untracked().unwrap_or_default();
        // First-run baseline: a device with NO record for a zone (ledger and
        // approved set both empty) has nothing to compare an injected roster
        // row against, so quarantining every owed member would only break
        // rotation on a fresh admin browser (the ledger is per-browser; there
        // is no durable "ever granted" source). Adopt the current eligible
        // roster as the baseline once and persist it; from then on the device
        // has a baseline and a genuinely new pubkey is held pending. A relay
        // compromised before a device's first sweep is adopted — documented in
        // ADR-2016; the robust fix is a durable admin-signed grant ledger.
        for zone in &zones {
            if known.get(&zone.id).is_none_or(HashSet::is_empty) && held.contains_key(&zone.id) {
                let base = grant_targets(&members, &zone.required_cohorts, &me, zone.agent_keys);
                for pk in &base {
                    self.store.approve_target(&zone.id, pk).await;
                }
                known.insert(zone.id.clone(), base.into_iter().collect());
            }
        }
        Ok(plan_missing(
            &zones,
            &members,
            &me,
            &held,
            &sent,
            &known,
            auto_grant_new,
            only,
        ))
    }

    async fn run(&self, only: Option<&HashSet<String>>) -> Result<GrantReport, String> {
        let signer = self
            .auth
            .get_signer()
            .ok_or_else(|| "Sign in again to grant zone keys.".to_string())?;
        // An allocation is an explicit admin action on this pubkey, not a
        // silent sweep: approve any never-granted target so it is granted now
        // and remembered, rather than held for a second confirmation.
        let plan = self.plan(&*signer, only, true).await?;
        for (zone, pk) in &plan.pending {
            self.store.approve_target(zone, pk).await;
        }
        if plan.grants.is_empty() {
            return Ok(GrantReport::default());
        }
        Ok(send_grants(
            self.store,
            &self.relay,
            &*signer,
            plan.grants,
            Rc::new(|_, _| ()),
        )
        .await)
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
    /// device has no record of granting, EXCEPT a pubkey never granted this
    /// zone before. A never-granted target is held for a one-time admin
    /// confirmation (the first-grant gate, deepsec #1) and surfaced here, not
    /// wrapped — so a hostile relay injecting an attacker pubkey into a cohort
    /// cannot make the sweep silently exfiltrate the zone key. With a NIP-07
    /// signer, only report.
    pub fn sweep(&self) {
        let this = self.clone();
        spawn_local(async move {
            let Some(signer) = this.auth.get_signer() else {
                return;
            };
            let extension = this.auth.state.with_untracked(|s| s.is_nip07);
            let plan = match this.plan(&*signer, None, false).await {
                Ok(p) => p,
                Err(e) => {
                    web_sys::console::warn_1(&format!("[zone-key] sweep skipped: {e}").into());
                    return;
                }
            };
            // Never-granted targets are held back: tell the admin to confirm
            // them in Admin → Encryption, and never wrap a key to them here.
            if !plan.pending.is_empty() {
                let new_pubkeys: HashSet<&String> = plan.pending.iter().map(|(_, pk)| pk).collect();
                this.toast(
                    format!(
                        "{} new member(s) are awaiting approval before a zone key is sent. \
                         Confirm them in Admin → Encryption.",
                        new_pubkeys.len()
                    ),
                    ToastVariant::Info,
                );
            }
            let waiting = grant_count(&plan.grants);
            if waiting == 0 {
                return;
            }
            if extension {
                let members: HashSet<&String> =
                    plan.grants.iter().flat_map(|(_, r)| r.iter()).collect();
                this.toast(
                    format!(
                        "{} member(s) are missing a zone key. Grant them from Admin → Encryption.",
                        members.len()
                    ),
                    ToastVariant::Info,
                );
                return;
            }
            let r = send_grants(
                this.store,
                &this.relay,
                &*signer,
                plan.grants,
                Rc::new(|_, _| ()),
            )
            .await;
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

    /// The `(zone, pubkey)` targets a sweep would hold for approval right now:
    /// never-granted pubkeys the relay's roster puts in a required cohort. The
    /// Encryption tab lists these so the admin can confirm each with
    /// [`approve`](Self::approve).
    pub async fn pending_targets(&self) -> Vec<(String, String)> {
        let Some(signer) = self.auth.get_signer() else {
            return Vec::new();
        };
        self.plan(&*signer, None, false)
            .await
            .map(|p| p.pending)
            .unwrap_or_default()
    }

    /// Confirm a never-granted `pubkey` as a legitimate target for `zone`:
    /// persist the approval so this and future sweeps auto-grant to it, then
    /// grant the zone's held keys to it now. The one admin action that lets a
    /// brand-new pubkey receive a zone key, closing the silent-exfiltration
    /// hole without a second confirmation per rotation.
    pub fn approve(&self, zone: &str, pubkey: &str) {
        let this = self.clone();
        let zone = zone.to_string();
        let pubkey = pubkey.to_ascii_lowercase();
        spawn_local(async move {
            this.store.approve_target(&zone, &pubkey).await;
            let only: HashSet<String> = std::iter::once(pubkey).collect();
            match this.run(Some(&only)).await {
                Ok(r) if r.sent > 0 && r.failed == 0 => this.toast(
                    format!("Approved and sent {} zone key(s).", r.sent),
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

    /// Known (previously granted or approved) targets for one zone.
    fn known(zone: &str, pks: &[String]) -> HashMap<String, HashSet<String>> {
        HashMap::from([(zone.to_string(), pks.iter().cloned().collect())])
    }

    #[test]
    fn grants_the_newest_key_to_every_eligible_member_not_on_record() {
        let zones = [rule("zone3", "family", false)];
        let sent = HashMap::from([(("zone3".to_string(), 1), HashSet::from([ME.to_string()]))]);
        // b was granted a prior epoch (known), so the gate does not hold them.
        let plan = plan_missing(
            &zones,
            &members(),
            ME,
            &held("zone3", &[1]),
            &sent,
            &known("zone3", &[pk('b')]),
            false,
            None,
        );
        assert_eq!(plan.grants.len(), 1);
        assert_eq!(plan.grants[0].0.epoch, 1);
        // b is in the zone; c is not; d is an agent in a zone without agent_keys.
        assert_eq!(plan.grants[0].1, vec![pk('b')]);
        assert!(plan.pending.is_empty());
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
            &known("zone4", &[pk('b'), pk('d')]),
            false,
            None,
        );
        assert!(plan.grants[0].1.contains(&pk('d')));
    }

    #[test]
    fn a_late_joiner_also_gets_the_keys_they_missed() {
        let zones = [rule("zone3", "family", false)];
        let everyone_else = HashSet::from([ME.to_string()]);
        let sent = HashMap::from([
            (("zone3".to_string(), 1), everyone_else.clone()),
            (("zone3".to_string(), 2), everyone_else),
        ]);
        let plan = plan_missing(
            &zones,
            &members(),
            ME,
            &held("zone3", &[1, 2]),
            &sent,
            &known("zone3", &[pk('b')]),
            false,
            None,
        );
        let epochs: Vec<u32> = plan.grants.iter().map(|(k, _)| k.epoch).collect();
        assert_eq!(epochs, vec![2, 1]);
        assert!(plan.grants.iter().all(|(_, r)| r == &vec![pk('b')]));
    }

    #[test]
    fn nobody_is_granted_twice() {
        let zones = [rule("zone3", "family", false)];
        let all = HashSet::from([ME.to_string(), pk('b')]);
        let sent = HashMap::from([(("zone3".to_string(), 1), all)]);
        let plan = plan_missing(
            &zones,
            &members(),
            ME,
            &held("zone3", &[1]),
            &sent,
            &known("zone3", &[pk('b')]),
            false,
            None,
        );
        assert!(plan.grants.is_empty());
        assert!(plan.pending.is_empty());
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
        // An allocation (auto_grant_new) grants a brand-new target and reports
        // it so the caller persists the approval.
        let plan = plan_missing(
            &zones,
            &members(),
            ME,
            &keys,
            &HashMap::new(),
            &HashMap::new(),
            true,
            Some(&only),
        );
        assert_eq!(plan.grants.len(), 1);
        assert_eq!(plan.grants[0].0.zone, "zone2");
        assert_eq!(plan.grants[0].1, vec![pk('c')]);
        assert_eq!(plan.pending, vec![("zone2".to_string(), pk('c'))]);
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
            &known("zone3", &[pk('b')]),
            false,
            None,
        );
        assert!(plan.grants.iter().all(|(k, _)| k.zone == "zone3"));
        assert_eq!(grant_count(&plan.grants), 2); // me and b
    }

    #[test]
    fn a_never_granted_pubkey_is_held_pending_not_auto_granted() {
        // deepsec #1: a hostile relay injects b (never granted this zone) into
        // the required cohort. The sweep must not wrap the epoch key to b.
        let zones = [rule("zone3", "family", false)];
        let plan = plan_missing(
            &zones,
            &members(),
            ME,
            &held("zone3", &[1]),
            &HashMap::new(),
            &HashMap::new(), // nothing known: b has never been granted
            false,
            None,
        );
        // Only me (always known) is auto-granted; b is surfaced for approval.
        assert_eq!(plan.grants.len(), 1);
        assert_eq!(plan.grants[0].1, vec![ME.to_string()]);
        assert_eq!(plan.pending, vec![("zone3".to_string(), pk('b'))]);
    }

    #[test]
    fn an_approved_pubkey_is_auto_granted() {
        // After approve() records b in the approved set, the same sweep grants
        // to it with no further confirmation.
        let zones = [rule("zone3", "family", false)];
        let sent = HashMap::from([(("zone3".to_string(), 1), HashSet::from([ME.to_string()]))]);
        let plan = plan_missing(
            &zones,
            &members(),
            ME,
            &held("zone3", &[1]),
            &sent,
            &known("zone3", &[pk('b')]), // b now approved
            false,
            None,
        );
        assert_eq!(plan.grants.len(), 1);
        assert_eq!(plan.grants[0].1, vec![pk('b')]);
        assert!(plan.pending.is_empty());
    }

    #[test]
    fn a_previously_granted_pubkey_auto_grants_on_a_new_epoch() {
        // Rotation stays automatic: b held epoch 1 (ledger record -> known) and
        // is auto-granted epoch 2 without any approval, even on a fresh sweep.
        let zones = [rule("zone3", "family", false)];
        let sent = HashMap::from([(
            ("zone3".to_string(), 1),
            HashSet::from([ME.to_string(), pk('b')]),
        )]);
        let plan = plan_missing(
            &zones,
            &members(),
            ME,
            &held("zone3", &[1, 2]),
            &sent,
            &known("zone3", &[pk('b')]), // ever-granted epoch 1 -> known
            false,
            None,
        );
        // Newest epoch 2 goes to b with no pending entry.
        assert!(plan.pending.is_empty());
        let epoch2 = plan.grants.iter().find(|(k, _)| k.epoch == 2).unwrap();
        assert!(epoch2.1.contains(&pk('b')));
    }

    #[test]
    fn me_is_always_granted_even_when_never_recorded() {
        // The admin's own identity is never held pending: they must be able to
        // read the zone they hold the key for.
        let zones = [rule("zone3", "family", false)];
        let plan = plan_missing(
            &zones,
            &members(),
            ME,
            &held("zone3", &[1]),
            &HashMap::new(),
            &HashMap::new(),
            false,
            None,
        );
        assert!(plan.grants.iter().any(|(_, r)| r.contains(&ME.to_string())));
        assert!(plan.pending.iter().all(|(_, pk)| pk != ME));
    }

    #[test]
    fn agents_are_still_excluded_from_pending_and_grants() {
        // d is an agent in a zone without agent_keys: never granted, never
        // even surfaced for approval.
        let d = pk('d');
        let zones = [rule("zone3", "family", false)];
        let plan = plan_missing(
            &zones,
            &members(),
            ME,
            &held("zone3", &[1]),
            &HashMap::new(),
            &HashMap::new(),
            false,
            None,
        );
        assert!(plan.grants.iter().all(|(_, r)| !r.contains(&d)));
        assert!(plan.pending.iter().all(|(_, pubkey)| pubkey != &d));
    }

    #[derive(Default)]
    struct MemKv(std::cell::RefCell<HashMap<String, String>>);
    impl super::super::grant_ledger::GrantKv for MemKv {
        async fn get(&self, id: &str) -> Option<String> {
            self.0.borrow().get(id).cloned()
        }
        async fn put(&self, id: &str, json: &str) -> bool {
            self.0.borrow_mut().insert(id.into(), json.into());
            true
        }
    }

    #[test]
    fn an_extension_admin_still_re_issues_to_a_member_with_a_v1_entry_and_a_new_inbox_key() {
        use super::super::grant_ledger::{ledger_id_v1, GrantLedger};
        let kv = MemKv::default();
        kv.0.borrow_mut().insert(
            ledger_id_v1("zone3", 1),
            serde_json::to_string(&[pk('b')]).unwrap(),
        );
        let ledger = GrantLedger::default();
        // Lookup results are the same whichever kind of signer asked.
        let targets = granted_targets(HashMap::from([
            (pk('b'), Ok(pk('9'))),
            (pk('c'), Err("HTTP 500".to_string())),
        ]));
        assert_eq!(targets.len(), 1);
        let have = futures::executor::block_on(ledger.sent_to(&kv, "zone3", 1, &targets));
        let sent = HashMap::from([(("zone3".to_string(), 1), have)]);
        let zones = [rule("zone3", "family", false)];
        // b is known: a v1 entry means b was granted a prior epoch, so a
        // re-issue to their new inbox key is auto, never gated.
        let plan = plan_missing(
            &zones,
            &members(),
            ME,
            &held("zone3", &[1]),
            &sent,
            &known("zone3", &[pk('b')]),
            false,
            None,
        );
        assert!(plan.grants[0].1.contains(&pk('b')));
        // Once recorded at the inbox key, b is no longer owed.
        futures::executor::block_on(ledger.record(&kv, "zone3", 1, &[(pk('b'), pk('9'))]));
        let have = futures::executor::block_on(ledger.sent_to(&kv, "zone3", 1, &targets));
        assert!(have.contains(&pk('b')));
    }
}
