//! Zone-key grants that do not wait for an admin to open the Encryption tab
//! (ADR-2016 follow-on: "a new member needs a grant on approval").
//!
//! Every grant is still built and sealed in an admin's browser, so the relay
//! and the host never hold a zone key. Two triggers:
//!
//! - **On allocation.** When an admin gives a member a cohort (the Members
//!   table, a section request, a registration), the admin's browser approves
//!   the member in, and sends them the key of, each encrypted zone that
//!   cohort opens, and no other.
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
//!
//! The relay's roster is not trusted to widen who holds a key (deepsec #1): the
//! sweep wraps a key only to `me` or to a pubkey that is "known" for the zone
//! (this device's ledger has granted it a held epoch, or an admin approved it).
//! Any other target is held pending for a one-time approval in Admin →
//! Encryption. An explicit allocation approves the member only in the zones
//! the cohorts it gave open ([`allocation_opened`]), then grants. The
//! Encryption tab's Create, Rotate and "Grant to members missing it" apply
//! the same gate ([`gate_split`]): known members get the key, anyone else is
//! held for approval.
//! An empty record approves nobody: a fresh browser sees every member as
//! awaiting approval (the tab approves them in bulk), and a zone whose
//! relay-held backup could not be read is reported unverified, its unknown
//! members neither granted nor called never-granted.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use leptos::prelude::*;
use nostr_bbs_core::signer::Signer;
use wasm_bindgen_futures::spawn_local;

use super::grant_backup::AckCounter;
use super::inbox_key::{grant_target, lookup_inbox_key, recipient_keys_enabled, Lookup};
use super::store::{try_use_zone_key_store, ZoneKeyStore};
use super::{build_grant_wrap, grant_plan, grant_targets, ZoneKey};
use crate::auth::{use_auth, AuthStore};
use crate::relay::RelayConnection;
use crate::stores::zones::load_zones;
use crate::toast::{ToastStore, ToastVariant};

/// How long a grant batch waits for the relay's acknowledgements before the
/// ledger backup is published with whatever was recorded.
const BACKUP_ACK_WAIT_MS: u32 = 10_000;

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
    /// Oldest epoch grants may hand out (see [`super::grantable_keys`]).
    pub history_from_epoch: Option<u32>,
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
            history_from_epoch: z.history_from_epoch,
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
/// approved set is "known" and auto-grants, so rotation stays automatic. In a
/// zone whose record could not be read, an unknown pubkey lands in
/// [`unverified`](Self::unverified) instead: it may have been granted from a
/// record this device could not see, so "never granted" would be a guess.
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
    /// `(zone, pubkey)` pairs not on this device's record, in a zone whose
    /// relay-held backup could not be read ([`GateRecords::unverified`]).
    /// Neither wrapped nor presented as never granted: the admin may retry
    /// the check, or approve them explicitly.
    pub unverified: Vec<(String, String)>,
    /// Zones this device holds keys for but may grant none of, because every
    /// held key is below the zone's `history_from_epoch` floor. Filled by
    /// [`AutoGrant::plan`], never by [`plan_missing`].
    pub floor_blocked: Vec<super::FloorBlock>,
    /// `(zone, epoch)` ledgers this device holds entries for but the relay
    /// holds no backup of (see [`super::grant_backup::needs_repair`]). Filled
    /// by `AutoGrant::plan`, never by [`plan_missing`].
    pub repair: Vec<(String, u32)>,
}

/// The grants still owed, across every zone this admin holds a key for, split
/// by the first-grant confirmation gate.
///
/// `held` maps zone id to the keys this admin holds for it; `sent` maps
/// `(zone, epoch)` to the members this device's ledger records as granted at
/// the key they would be granted at now. `gate.known` maps zone id to the
/// pubkeys that may be auto-granted without a fresh confirmation — those the
/// ledger has ever granted any epoch of the zone, plus the persisted approved
/// set — and `gate.unverified` names the zones whose record was not read.
///
/// A member is owed a zone's newest key when they are one of its
/// [`grant_targets`] and the ledger has no record of it; with that grant go
/// the earlier keys they were not sent ([`grant_plan`] with history), so a
/// member who joins after a rotation can read the zone's older messages.
/// Each zone's owed targets are split by [`gate_split`]: `me` and known
/// targets are granted, any other lands in [`MissingPlan::pending`] (or
/// [`MissingPlan::unverified`], in an unverified zone). `only` narrows the
/// recipients to those pubkeys (an allocation or approval). Nothing here
/// approves anybody: an explicit admin action records its approvals first
/// (see [`allocation_opened`]), and they reach this plan through `gate`.
pub fn plan_missing(
    zones: &[ZoneRule],
    members: &[(String, Vec<String>)],
    me: &str,
    held: &HashMap<String, Vec<ZoneKey>>,
    sent: &HashMap<(String, u32), HashSet<String>>,
    gate: &GateRecords,
    only: Option<&HashSet<String>>,
) -> MissingPlan {
    let none = HashSet::new();
    let mut out = MissingPlan::default();
    for zone in zones {
        let Some(keys) = held.get(&zone.id).filter(|k| !k.is_empty()) else {
            continue;
        };
        let Some(newest) = keys.iter().map(|k| k.epoch).max() else {
            continue;
        };
        let have = sent.get(&(zone.id.clone(), newest)).unwrap_or(&none);
        let recipients = grant_targets(members, &zone.required_cohorts, me, zone.agent_keys)
            .into_iter()
            .filter(|pk| only.is_none_or(|o| o.contains(pk)))
            .filter(|pk| !have.contains(pk));
        let split = gate_split(&zone.id, recipients, me, gate);
        out.pending.extend(split.pending);
        out.unverified.extend(split.unverified);
        if split.send.is_empty() {
            continue;
        }
        out.grants
            .extend(grant_plan(keys, &split.send, true, |epoch| {
                sent.get(&(zone.id.clone(), epoch))
                    .cloned()
                    .unwrap_or_default()
            }));
    }
    out
}

/// One zone's recipients, split by the first-grant gate (see [`gate_split`]).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GateSplit {
    /// Recipients that may be sent the key now: `me`, or known for the zone.
    pub send: Vec<String>,
    /// `(zone, pubkey)` pairs never granted and never approved for the zone.
    pub pending: Vec<(String, String)>,
    /// `(zone, pubkey)` pairs not on this device's record, in a zone whose
    /// relay-held record could not be read.
    pub unverified: Vec<(String, String)>,
}

/// The first-grant gate for one zone: which of `recipients` may be wrapped
/// the zone's key now, and which are held.
///
/// The single rule every grant path applies (the sign-in sweep, allocations
/// and approvals through [`plan_missing`], and the Encryption tab's Create,
/// Rotate and "Grant to members missing it"). A recipient is sent the key
/// when it is `me` or in `gate.known` for `zone` (granted a held epoch by
/// this device, or approved by an admin). Anyone else is held: in
/// [`GateSplit::unverified`] when the zone's record was not read, otherwise
/// in [`GateSplit::pending`]. The relay's roster decides who is a candidate,
/// never who is trusted.
pub fn gate_split(
    zone: &str,
    recipients: impl IntoIterator<Item = String>,
    me: &str,
    gate: &GateRecords,
) -> GateSplit {
    let none = HashSet::new();
    let me_lower = me.to_ascii_lowercase();
    let known = gate.known.get(zone).unwrap_or(&none);
    let unverified = gate.unverified.contains(zone);
    let mut out = GateSplit::default();
    for pk in recipients {
        let pk = pk.to_ascii_lowercase();
        if pk == me_lower || known.contains(&pk) {
            out.send.push(pk);
        } else if unverified {
            out.unverified.push((zone.to_string(), pk));
        } else {
            out.pending.push((zone.to_string(), pk));
        }
    }
    out
}

/// The `(zone, pubkey)` pairs an admin's allocation opens: `pubkey` in each
/// of `zones` whose required cohorts include one of `added`, the cohorts the
/// admin actually gave or approved.
///
/// Recorded as approvals before the grants are planned, so the allocation
/// grants exactly these zones. A zone the roster also places `pubkey` in
/// through some other cohort is not opened by this action: unless `pubkey`
/// is already known there, it stays pending for an explicit approval.
pub fn allocation_opened(
    zones: &[ZoneRule],
    pubkey: &str,
    added: &[String],
) -> Vec<(String, String)> {
    let pk = pubkey.to_ascii_lowercase();
    zones
        .iter()
        .filter(|z| z.required_cohorts.iter().any(|c| added.contains(c)))
        .map(|z| (z.id.clone(), pk.clone()))
        .collect()
}

/// What one of the Encryption tab's key actions (Create, Rotate, "Grant to
/// members missing it") will do: the grants to send now, and the members it
/// holds back.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TabPlan {
    /// `(key, recipients)` pairs to send now.
    pub grants: Vec<(ZoneKey, Vec<String>)>,
    /// `(zone, pubkey)` pairs held for an explicit admin approval.
    pub pending: Vec<(String, String)>,
    /// `(zone, pubkey)` pairs not sent because the zone's record was not read.
    pub unverified: Vec<(String, String)>,
}

impl TabPlan {
    /// Distinct members, other than `me`, the plan sends a key to.
    pub fn receiving(&self, me: &str) -> usize {
        let me = me.to_ascii_lowercase();
        self.grants
            .iter()
            .flat_map(|(_, r)| r.iter())
            .filter(|pk| **pk != me)
            .collect::<HashSet<_>>()
            .len()
    }

    /// Distinct members held back: awaiting approval, and unverified.
    pub fn held(&self) -> (usize, usize) {
        let distinct =
            |v: &[(String, String)]| v.iter().map(|(_, pk)| pk).collect::<HashSet<_>>().len();
        (distinct(&self.pending), distinct(&self.unverified))
    }

    /// The members held back, in words; `None` when nobody was.
    pub fn held_note(&self) -> Option<String> {
        let (pending, unverified) = self.held();
        let mut parts = Vec::new();
        if pending > 0 {
            parts.push(format!(
                "{pending} member(s) were not sent the key: they are awaiting your approval \
                 under \"New members awaiting approval\""
            ));
        }
        if unverified > 0 {
            parts.push(format!(
                "{unverified} member(s) were not sent the key because this zone's grant record \
                 could not be checked"
            ));
        }
        (!parts.is_empty()).then(|| format!("{}.", parts.join("; ")))
    }
}

/// The grants of a newly created or rotated `key` for the zone `rule`, to the
/// members of the roster `members`, split by [`gate_split`]: every known
/// member (and `me`) receives the key in one batch; anyone else is held.
pub fn plan_new_key(
    rule: &ZoneRule,
    members: &[(String, Vec<String>)],
    me: &str,
    key: &ZoneKey,
    gate: &GateRecords,
) -> TabPlan {
    let targets = grant_targets(members, &rule.required_cohorts, me, rule.agent_keys);
    let split = gate_split(&rule.id, targets, me, gate);
    TabPlan {
        grants: vec![(key.clone(), split.send)],
        pending: split.pending,
        unverified: split.unverified,
    }
}

/// The grants "Grant to members missing it" sends for `zone`: the held keys
/// to the members of `missing` that pass [`gate_split`] (with earlier epochs
/// when `include_history`, skipping members `earlier(epoch)` records as
/// already sent). The others are held.
pub fn plan_grant_missing(
    zone: &str,
    missing: &[String],
    me: &str,
    held: &[ZoneKey],
    gate: &GateRecords,
    include_history: bool,
    earlier: impl Fn(u32) -> HashSet<String>,
) -> TabPlan {
    let split = gate_split(zone, missing.iter().cloned(), me, gate);
    TabPlan {
        grants: grant_plan(held, &split.send, include_history, earlier),
        pending: split.pending,
        unverified: split.unverified,
    }
}

/// What this device's own records allow the first-grant gate to treat as
/// known, per zone, before [`plan_missing`] splits the owed grants.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GateRecords {
    /// Zone id to the pubkeys that may be auto-granted: those this device's
    /// ledger (with the relay-held backup merged in) has granted a held
    /// epoch, plus the persisted approved set.
    pub known: HashMap<String, HashSet<String>>,
    /// Zones whose relay-held backup could not be read for some held epoch
    /// (see [`super::grant_backup::backup_verified`]).
    pub unverified: HashSet<String>,
}

/// The gate's view of this device's records: `known` from the local ledger
/// and approved set, and `unread`, the zones whose backup was not read.
///
/// The roster plays no part. An empty or unreadable record never widens
/// approval: with nothing on record every member other than the admin is
/// pending (never granted, needs an explicit approval), and a zone whose
/// backup was not read is unverified, so its unknown members are not called
/// never granted either. Nobody is approved here; only an admin's explicit
/// action ([`AutoGrant::approve`], [`AutoGrant::approve_all`], an
/// allocation) approves.
pub fn gate_records(
    held: &HashMap<String, Vec<ZoneKey>>,
    known: HashMap<String, HashSet<String>>,
    unread: &HashSet<String>,
) -> GateRecords {
    GateRecords {
        known,
        unverified: unread
            .iter()
            .filter(|z| held.contains_key(*z))
            .cloned()
            .collect(),
    }
}

/// What one run of grants did. Only `accepted` grants reached a member;
/// every other count is a grant that did not, for a distinct reason.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GrantReport {
    /// Grants the relay accepted (`OK true`), recorded in the ledger.
    pub accepted: usize,
    /// Grants the relay refused (`OK false`). Not recorded; owed again.
    pub rejected: usize,
    /// Grants handed to the relay that it did not answer in time (or whose
    /// answer a reconnect dropped). Not recorded; owed again, though a late
    /// acceptance is still recorded when it arrives.
    pub unconfirmed: usize,
    /// Grants that could not be built or handed over (inbox lookup, signer
    /// or send failure). Not recorded; owed again.
    pub failed: usize,
    /// Grants withheld because the key is below its zone's
    /// `history_from_epoch` floor (see [`super::grantable_keys`]).
    pub withheld: usize,
    /// Distinct members with at least one accepted grant.
    pub members: usize,
}

impl GrantReport {
    /// Grants that did not reach their member, for whatever reason.
    pub fn problems(&self) -> usize {
        self.rejected + self.unconfirmed + self.failed + self.withheld
    }
}

/// Running count of one batch's grants as they are built, handed to the
/// relay and answered.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GrantTally {
    /// Grants handed to the relay.
    pub handed: usize,
    /// Grants that could not be built or handed over.
    pub failed: usize,
    /// Grants withheld below their zone's history floor.
    pub withheld: usize,
    /// Grants the relay accepted (`OK true`) and the ledger recorded.
    pub accepted: usize,
    /// Grants the relay refused (`OK false`).
    pub rejected: usize,
    /// Members with at least one accepted grant.
    pub accepted_members: HashSet<String>,
}

impl GrantTally {
    /// The batch's report, once the wait for answers is over: whatever was
    /// handed over and neither accepted nor refused by then is unconfirmed.
    pub fn report(&self) -> GrantReport {
        GrantReport {
            accepted: self.accepted,
            rejected: self.rejected,
            unconfirmed: self
                .handed
                .saturating_sub(self.accepted)
                .saturating_sub(self.rejected),
            failed: self.failed,
            withheld: self.withheld,
            members: self.accepted_members.len(),
        }
    }
}

/// A report put into words for a toast or status line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportSummary {
    /// What to tell the admin.
    pub text: String,
    /// Whether something went wrong (shown as an error, with a retry hint).
    pub problem: bool,
}

/// Put `r` into words; `None` when the run had nothing to send at all.
///
/// Every caller (allocation, approval, sweep, the Encryption tab) words its
/// outcome here, so a refused, unanswered or withheld grant is never shown as
/// sent, nor as silence.
pub fn report_summary(r: &GrantReport) -> Option<ReportSummary> {
    if r.accepted == 0 && r.problems() == 0 {
        return None;
    }
    if r.problems() == 0 {
        return Some(ReportSummary {
            text: format!(
                "Sent {} zone key grant(s) to {} member(s).",
                r.accepted, r.members
            ),
            problem: false,
        });
    }
    let mut parts = vec![format!("{} zone key grant(s) delivered", r.accepted)];
    if r.rejected > 0 {
        parts.push(format!("{} refused by the relay", r.rejected));
    }
    if r.unconfirmed > 0 {
        parts.push(format!("{} not confirmed by the relay", r.unconfirmed));
    }
    if r.failed > 0 {
        parts.push(format!("{} could not be sent", r.failed));
    }
    if r.withheld > 0 {
        parts.push(format!(
            "{} withheld (below the zone's history floor)",
            r.withheld
        ));
    }
    Some(ReportSummary {
        text: format!(
            "{}. Undelivered grants are still owed: retry from Admin → Encryption.",
            parts.join("; ")
        ),
        problem: true,
    })
}

/// Split `plan` at each zone's history floor (`floor_of`): the grants that
/// may go, and how many single grants were withheld because their key is
/// below the floor. The last check before anything is wrapped, so no path
/// (a pending key's own delivery included) can send a key below the floor.
pub fn withhold_below_floor(
    plan: Vec<(ZoneKey, Vec<String>)>,
    floor_of: impl Fn(&str) -> Option<u32>,
) -> (Vec<(ZoneKey, Vec<String>)>, usize) {
    let mut withheld = 0;
    let kept = plan
        .into_iter()
        .filter(|(k, r)| {
            let below = floor_of(&k.zone).is_some_and(|f| k.epoch < f);
            if below {
                withheld += r.len();
            }
            !below
        })
        .collect();
    (kept, withheld)
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
/// device's ledger once the relay accepts it (`OK true`), and only then. A
/// refused or unanswered grant is never recorded, so it stays owed, and the
/// report counts it as such. A key below its zone's history floor is
/// withheld. `on_recorded` runs after each record (the Encryption tab updates
/// its "granted here" list from it).
pub async fn send_grants(
    store: ZoneKeyStore,
    relay: &RelayConnection,
    signer: &dyn Signer,
    plan: Vec<(ZoneKey, Vec<String>)>,
    on_recorded: OnRecorded,
) -> GrantReport {
    let (plan, withheld) = withhold_below_floor(plan, super::history_floor);
    if withheld > 0 {
        web_sys::console::warn_1(
            &format!("[zone-key] {withheld} grant(s) withheld: key below the history floor").into(),
        );
    }
    let members: HashSet<String> = plan.iter().flat_map(|(_, r)| r.iter().cloned()).collect();
    let tally = Rc::new(std::cell::RefCell::new(GrantTally {
        withheld,
        ..GrantTally::default()
    }));
    let targets = resolve_targets(signer, &members).await;
    // Tickets need the relay's zone-group bindings. A failed load falls back
    // to the 21453 grant for every recipient.
    if super::tickets::zone_groups_enabled() {
        if let Err(e) = super::tickets::ensure_bindings_loaded().await {
            web_sys::console::warn_1(&format!("[zone-key] bindings: {e}").into());
        }
    }
    // Which `(zone, epoch)` ledgers this batch touches, and how many of its
    // grants the relay has accepted and the ledger recorded: the backup is
    // published once they are in (see `grant_backup`).
    let touched: Vec<(String, u32)> = {
        let mut t: Vec<(String, u32)> = plan
            .iter()
            .filter(|(_, r)| !r.is_empty())
            .map(|(k, _)| (k.zone.clone(), k.epoch))
            .collect();
        t.sort();
        t.dedup();
        t
    };
    let acks = AckCounter::new();
    for (key, recipients) in plan {
        for pk in recipients {
            // A failed lookup is not "no inbox key": wrapping to the identity
            // would put the grant back where the inbox key exists to keep it
            // from. The member stays unrecorded and is retried.
            let target = match targets.get(&pk) {
                Some(Ok(t)) => t.clone(),
                Some(Err(e)) => {
                    web_sys::console::warn_1(&format!("[zone-key] inbox lookup: {e}").into());
                    tally.borrow_mut().failed += 1;
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
                tally.borrow_mut().failed += 1;
                continue;
            };
            let key_for_ack = key.clone();
            let on_recorded = on_recorded.clone();
            let acks_for_ack = acks.clone();
            let tally_for_ack = tally.clone();
            let on_ok = Rc::new(move |ok: bool, msg: String| {
                if !ok {
                    // Refused: not recorded, so the member stays owed.
                    web_sys::console::warn_1(
                        &format!("[zone-key] grant refused by the relay: {msg}").into(),
                    );
                    tally_for_ack.borrow_mut().rejected += 1;
                    acks_for_ack.ack();
                    return;
                }
                let acks = acks_for_ack.clone();
                let tally = tally_for_ack.clone();
                let key = key_for_ack.clone();
                let pk = pk.clone();
                let target = target.clone();
                let on_recorded = on_recorded.clone();
                spawn_local(async move {
                    store
                        .record_grants(&key.zone, key.epoch, &[(pk.clone(), target)])
                        .await;
                    {
                        let mut t = tally.borrow_mut();
                        t.accepted += 1;
                        t.accepted_members.insert(pk.clone());
                    }
                    on_recorded(&key, &pk);
                    acks.ack();
                });
            });
            if relay.publish_with_ack(&wrap, Some(on_ok)).is_err() {
                tally.borrow_mut().failed += 1;
            } else {
                tally.borrow_mut().handed += 1;
            }
        }
    }
    // Wait for the relay's answers, so the report can tell accepted, refused
    // and unanswered apart, then keep the ledger on the relay too, so
    // "granted" survives clearing site data. The backup is best effort: the
    // local ledger stays authoritative on failure.
    let handed = tally.borrow().handed;
    acks.expect(handed);
    if !touched.is_empty() && handed > 0 {
        // The wraps are paced out of the send queue (one frame each), so the
        // ack window starts once they have all left, not when they were queued.
        relay
            .wait_until_sent(super::grant_backup::queue_wait_ms(relay.queued_frames()))
            .await;
        acks.wait(BACKUP_ACK_WAIT_MS).await;
        push_backups(relay, signer, store, &touched).await;
    }
    let done = tally.borrow();
    done.report()
}

/// What this device knows of one zone's grant record, for the first-grant
/// gate (see [`zone_record`]).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ZoneRecord {
    /// Pubkeys this device's ledger (with the relay-held backup merged in)
    /// has granted any of the keys read, plus the zone's approved set.
    pub known: HashSet<String>,
    /// Whether the relay-held backup of every key read was read (see
    /// [`super::grant_backup::backup_verified`]).
    pub verified: bool,
    /// `(zone, epoch)` ledgers held here whose backup the relay lacks (see
    /// [`super::grant_backup::needs_repair`]).
    pub repair: Vec<(String, u32)>,
}

/// Read `zone`'s grant record for the first-grant gate, over `keys` (the
/// zone's grantable keys): restore this admin's relay-held backup of each
/// into the local ledger (once per session once found), then collect the
/// members ever granted one of them and the approved set.
///
/// No inbox-key lookups: who is known does not depend on where a member's
/// grant would go, so the Encryption tab can read the gate without one
/// signature prompt per member. The roster plays no part.
pub async fn zone_record(
    relay: &RelayConnection,
    signer: &dyn Signer,
    store: ZoneKeyStore,
    zone: &str,
    keys: &[ZoneKey],
) -> ZoneRecord {
    let mut verified = true;
    let mut repair = Vec::new();
    for k in keys {
        // After clearing site data the local ledger is empty and everyone
        // would otherwise look ungranted. A relay that cannot answer leaves
        // the zone unverified.
        let pulled =
            super::grant_backup::pull_detailed(relay, signer, store, &k.zone, k.epoch).await;
        let local = store.export_grant_backup(&k.zone, k.epoch).await.len();
        let authed = relay.authenticated().get_untracked();
        let read = pulled.as_ref().map_err(String::as_str).copied();
        if !super::grant_backup::backup_verified(read, authed) {
            if let Err(e) = &pulled {
                web_sys::console::warn_1(
                    &format!("[zone-key] grant backup {zone}/{}: {e}", k.epoch).into(),
                );
            }
            verified = false;
        }
        if super::grant_backup::needs_repair(read, local, authed) {
            repair.push((k.zone.clone(), k.epoch));
        }
    }
    let epochs: Vec<u32> = keys.iter().map(|k| k.epoch).collect();
    let mut known = store.members_ever_granted(zone, &epochs).await;
    known.extend(store.approved_targets(zone).await);
    ZoneRecord {
        known,
        verified,
        repair,
    }
}

/// The gate for one zone as the Encryption tab acts on it: its record read
/// over the keys this device may grant (the same keys the sign-in sweep
/// reads), as [`GateRecords`].
pub async fn tab_gate(
    relay: &RelayConnection,
    signer: &dyn Signer,
    store: ZoneKeyStore,
    zone: &str,
    floor: Option<u32>,
) -> GateRecords {
    let held = super::grantable_keys(store.all_for_zone(zone), floor);
    let rec = zone_record(relay, signer, store, zone, &held).await;
    GateRecords {
        known: HashMap::from([(zone.to_string(), rec.known)]),
        unverified: if rec.verified {
            HashSet::new()
        } else {
            HashSet::from([zone.to_string()])
        },
    }
}

/// Publish this admin's backup of each `(zone, epoch)` in `which`, retrying
/// a failure once. Best effort: the local ledger stays authoritative.
pub async fn push_backups(
    relay: &RelayConnection,
    signer: &dyn Signer,
    store: ZoneKeyStore,
    which: &[(String, u32)],
) {
    for (zone, epoch) in which {
        if let Err(e) =
            super::grant_backup::push_retrying(relay, signer, store, zone, *epoch, now_secs).await
        {
            web_sys::console::warn_1(
                &format!("[zone-key] grant backup {zone}/{epoch}: {e}").into(),
            );
        }
    }
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

    /// Whether the signed-in identity's keys have been loaded from IndexedDB,
    /// tracked; `false` while signed out.
    pub fn keys_loaded(&self) -> Signal<bool> {
        let (store, auth) = (self.store, self.auth);
        Signal::derive(move || store.ready_for(auth.pubkey().get().as_deref()))
    }

    /// Work out the grants owed, from a fresh roster read, split by the
    /// first-grant confirmation gate. `only` narrows them to those members.
    /// Nobody is approved here: an explicit admin action records its
    /// approvals before planning.
    async fn plan(
        &self,
        signer: &dyn Signer,
        only: Option<&HashSet<String>>,
    ) -> Result<MissingPlan, String> {
        let zones = encrypted_zone_rules();
        let mut floor_blocked = Vec::new();
        let mut held: HashMap<String, Vec<ZoneKey>> = HashMap::new();
        for z in &zones {
            let all = self.store.all_for_zone(&z.id);
            if let Some(block) = super::floor_block(&z.id, &all, z.history_from_epoch) {
                web_sys::console::warn_1(&format!("[zone-key] {}", block.explain()).into());
                floor_blocked.push(block);
            }
            let keys = super::grantable_keys(all, z.history_from_epoch);
            if !keys.is_empty() {
                held.insert(z.id.clone(), keys);
            }
        }
        if held.is_empty() {
            return Ok(MissingPlan {
                floor_blocked,
                ..MissingPlan::default()
            });
        }
        let rows = crate::whitelist::fetch_whitelist_rows(signer).await?;
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
        let mut unread: HashSet<String> = HashSet::new();
        let mut repair: Vec<(String, u32)> = Vec::new();
        for (zone, keys) in &held {
            // Restores the relay-held record first, so `sent` below sees it.
            let rec = zone_record(&self.relay, signer, self.store, zone, keys).await;
            if !rec.verified {
                unread.insert(zone.clone());
            }
            repair.extend(rec.repair);
            known.insert(zone.clone(), rec.known);
            for k in keys {
                let s = self.store.grants_sent_to(&k.zone, k.epoch, &targets).await;
                sent.insert((k.zone.clone(), k.epoch), s);
            }
        }
        let me = self.auth.pubkey().get_untracked().unwrap_or_default();
        // No first-run baseline: a device with no record approves nobody (see
        // `gate_records`). The relay could have injected a pubkey before this
        // device's first sweep as easily as after it.
        let gate = gate_records(&held, known, &unread);
        let mut plan = plan_missing(&zones, &members, &me, &held, &sent, &gate, only);
        plan.repair = repair;
        plan.floor_blocked = floor_blocked;
        Ok(plan)
    }

    /// Plan and send the grants owed to `only`: only targets already known
    /// or approved are granted. Also returns the zones blocked by their
    /// history floor, for the caller to scope and report.
    async fn run(
        &self,
        only: Option<&HashSet<String>>,
    ) -> Result<(GrantReport, Vec<super::FloorBlock>), String> {
        let signer = self
            .auth
            .get_signer()
            .ok_or_else(|| "Sign in again to grant zone keys.".to_string())?;
        let plan = self.plan(&*signer, only).await?;
        if plan.grants.is_empty() {
            return Ok((GrantReport::default(), plan.floor_blocked));
        }
        let report = send_grants(
            self.store,
            &self.relay,
            &*signer,
            plan.grants,
            Rc::new(|_, _| ()),
        )
        .await;
        Ok((report, plan.floor_blocked))
    }

    fn toast(&self, message: String, variant: ToastVariant) {
        if let Some(t) = self.toasts {
            t.show(message, variant);
        }
    }

    /// Toast the outcome of an explicit grant run (allocation, approval).
    /// `nothing` is said when the run had nothing to send, so an explicit
    /// action never ends in silence.
    fn toast_run(&self, outcome: Result<GrantReport, String>, nothing: &str) {
        match outcome {
            Ok(r) => match report_summary(&r) {
                Some(s) if s.problem => self.toast(s.text, ToastVariant::Error),
                Some(s) => self.toast(s.text, ToastVariant::Success),
                None => self.toast(nothing.to_string(), ToastVariant::Info),
            },
            Err(e) => self.toast(
                format!("Zone keys were not granted: {e}"),
                ToastVariant::Error,
            ),
        }
    }

    /// After an admin gave `pubkey` the cohorts `added`: approve `pubkey` in
    /// each encrypted zone those cohorts open ([`allocation_opened`]), then
    /// send it the keys this device holds that it is owed, and say so.
    ///
    /// Only the zones `added` opens are approved. A zone the relay's roster
    /// places `pubkey` in through another cohort is granted only if `pubkey`
    /// is already known there; otherwise it stays pending for an explicit
    /// approval in Admin → Encryption.
    pub fn after_allocation(&self, pubkey: &str, added: &[String]) {
        let opened = allocation_opened(&encrypted_zone_rules(), pubkey, added);
        if opened.is_empty() {
            // No encrypted zone in the cohorts given: nothing is approved,
            // and nothing new is owed by this action.
            return;
        }
        let this = self.clone();
        let only: HashSet<String> = std::iter::once(pubkey.to_ascii_lowercase()).collect();
        spawn_local(async move {
            // The admin's decision, recorded whatever the relay answers next.
            for (zone, pk) in &opened {
                this.store.approve_target(zone, pk).await;
            }
            // Floor-blocked zones are not this member's to report: the sweep,
            // the Encryption tab and the console already name them.
            match this.run(Some(&only)).await.map(|(r, _)| r) {
                // Nothing owed (no encrypted zone in the new cohorts, or the
                // member already holds the keys) is not worth a toast here.
                Ok(r) if report_summary(&r).is_none() => {}
                outcome => this.toast_run(outcome, ""),
            }
        });
    }

    /// The sign-in sweep: grant every held key to each eligible member this
    /// device has no record of granting, EXCEPT a pubkey never granted this
    /// zone before. A never-granted target is held for a one-time admin
    /// confirmation (the first-grant gate, deepsec #1) and surfaced here, not
    /// wrapped — so a hostile relay injecting an attacker pubkey into a cohort
    /// cannot make the sweep silently exfiltrate the zone key. A zone whose
    /// record could not be read is reported, and only its known members are
    /// granted. With a NIP-07 signer, only report.
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
            for block in &plan.floor_blocked {
                this.toast(block.explain(), ToastVariant::Warning);
            }
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
            if !plan.unverified.is_empty() {
                let zones: HashSet<&String> = plan.unverified.iter().map(|(z, _)| z).collect();
                let pubkeys: HashSet<&String> = plan.unverified.iter().map(|(_, pk)| pk).collect();
                this.toast(
                    format!(
                        "Could not read the grant record for {} zone(s) from the relay, so {} \
                         member(s) not on this device's record were left alone. Check again \
                         from Admin → Encryption.",
                        zones.len(),
                        pubkeys.len()
                    ),
                    ToastVariant::Warning,
                );
            }
            // Backups the relay is missing although this device holds the
            // ledger: publish them unless this batch is about to (it pushes
            // what it touches). An extension admin is not prompted here.
            let touched: HashSet<(String, u32)> = plan
                .grants
                .iter()
                .filter(|(_, r)| !r.is_empty())
                .map(|(k, _)| (k.zone.clone(), k.epoch))
                .collect();
            let repair: Vec<(String, u32)> = plan
                .repair
                .iter()
                .filter(|z| !touched.contains(*z))
                .cloned()
                .collect();
            if !extension && !repair.is_empty() {
                // Detached: a slow or refusing relay must not hold up the
                // grants below. One attempt per key per session.
                let owner = signer.public_key().to_string();
                let repair: Vec<(String, u32)> = repair
                    .into_iter()
                    .filter(|(z, e)| super::grant_backup::claim_repair(&owner, z, *e))
                    .collect();
                if !repair.is_empty() {
                    let (relay, store, signer) = (this.relay.clone(), this.store, signer.clone());
                    spawn_local(async move {
                        push_backups(&relay, &*signer, store, &repair).await;
                    });
                }
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
            if let Some(s) = report_summary(&r) {
                let variant = if s.problem {
                    ToastVariant::Error
                } else {
                    ToastVariant::Success
                };
                this.toast(s.text, variant);
            }
        });
    }

    /// What a sweep would hold back right now, for the Encryption tab:
    /// never-granted targets to approve, targets left unverified because a
    /// zone's record could not be read, and zones blocked by their history
    /// floor. `Err` when the roster (or the signer) was unavailable: the tab
    /// then says it could not check, never "nothing awaiting approval".
    pub async fn pending_targets(&self) -> Result<PendingReview, String> {
        let signer = self
            .auth
            .get_signer()
            .ok_or_else(|| "Sign in again to check for members awaiting a key.".to_string())?;
        let p = self.plan(&*signer, None).await?;
        Ok(PendingReview {
            pending: p.pending,
            unverified: p.unverified,
            floor_blocked: p.floor_blocked,
        })
    }

    /// Confirm a never-granted `pubkey` as a legitimate target for `zone`:
    /// persist the approval so this and future sweeps auto-grant to it, then
    /// grant the zone's held keys to it now. The one admin action that lets a
    /// brand-new pubkey receive a zone key, closing the silent-exfiltration
    /// hole without a second confirmation per rotation. Only `zone` is
    /// approved: the same pubkey pending in another zone stays pending there.
    pub fn approve(&self, zone: &str, pubkey: &str) {
        self.approve_all(vec![(zone.to_string(), pubkey.to_ascii_lowercase())]);
    }

    /// [`approve`](Self::approve) every `(zone, pubkey)` in `targets` at
    /// once: persist each approval, then grant them all in one batch (one
    /// roster read and one backup push, not one per member).
    pub fn approve_all(&self, targets: Vec<(String, String)>) {
        if targets.is_empty() {
            return;
        }
        let this = self.clone();
        spawn_local(async move {
            for (zone, pk) in &targets {
                this.store
                    .approve_target(zone, &pk.to_ascii_lowercase())
                    .await;
            }
            let only: HashSet<String> = targets
                .iter()
                .map(|(_, pk)| pk.to_ascii_lowercase())
                .collect();
            let zones: HashSet<&String> = targets.iter().map(|(z, _)| z).collect();
            let outcome = this.run(Some(&only)).await.and_then(|(r, blocked)| {
                // A zone being approved that no key can be granted for is
                // the reason nothing went: say so, not "nothing was owed".
                let why: Vec<String> = blocked
                    .iter()
                    .filter(|b| zones.contains(&b.zone))
                    .map(super::FloorBlock::explain)
                    .collect();
                if report_summary(&r).is_none() && !why.is_empty() {
                    Err(format!("approved, but {}", why.join(" ")))
                } else {
                    Ok(r)
                }
            });
            this.toast_run(
                outcome,
                "Approved. Nothing was owed to send: the member(s) already hold this device's keys.",
            );
        });
    }
}

/// What the Encryption tab lists for the admin to act on (see
/// [`AutoGrant::pending_targets`]).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PendingReview {
    /// `(zone, pubkey)` targets never granted, awaiting approval.
    pub pending: Vec<(String, String)>,
    /// `(zone, pubkey)` targets whose grant status could not be checked
    /// (the zone's relay-held record was not read).
    pub unverified: Vec<(String, String)>,
    /// Zones whose held keys are all below the history floor.
    pub floor_blocked: Vec<super::FloorBlock>,
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
            history_from_epoch: None,
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

    /// Known (previously granted or approved) targets for one zone, with
    /// its record read.
    fn known(zone: &str, pks: &[String]) -> GateRecords {
        GateRecords {
            known: HashMap::from([(zone.to_string(), pks.iter().cloned().collect())]),
            unverified: HashSet::new(),
        }
    }

    /// The gate once each `(zone, pubkey)` in `pairs` has been approved.
    fn approved(pairs: &[(String, String)]) -> GateRecords {
        let mut known: HashMap<String, HashSet<String>> = HashMap::new();
        for (z, pk) in pairs {
            known.entry(z.clone()).or_default().insert(pk.clone());
        }
        GateRecords {
            known,
            unverified: HashSet::new(),
        }
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
        // An allocation of the business cohort approves c in zone2 (the
        // caller persists it), then grants through the gate.
        let opened = allocation_opened(&zones, &pk('c'), &["business".to_string()]);
        assert_eq!(opened, vec![("zone2".to_string(), pk('c'))]);
        let plan = plan_missing(
            &zones,
            &members(),
            ME,
            &keys,
            &HashMap::new(),
            &approved(&opened),
            Some(&only),
        );
        assert_eq!(plan.grants.len(), 1);
        assert_eq!(plan.grants[0].0.zone, "zone2");
        assert_eq!(plan.grants[0].1, vec![pk('c')]);
        assert!(plan.pending.is_empty());
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
            &GateRecords::default(), // nothing known: b has never been granted
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
            &GateRecords::default(),
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
            &GateRecords::default(),
            None,
        );
        assert!(plan.grants.iter().all(|(_, r)| !r.contains(&d)));
        assert!(plan.pending.iter().all(|(_, pubkey)| pubkey != &d));
    }

    #[test]
    fn an_empty_record_never_widens_approval() {
        // A fresh admin browser (no ledger, no approved set, relay answered
        // "no backup") must not adopt whatever roster the relay serves: a
        // pubkey injected before this device's first sweep would otherwise be
        // approved and sent the key with no admin decision.
        let zones = [rule("zone3", "family", false)];
        let held = held("zone3", &[1]);
        let gate = gate_records(&held, HashMap::new(), &HashSet::new());
        assert!(gate
            .known
            .get("zone3")
            .is_none_or(|k| !k.contains(&pk('b'))));
        assert!(gate.unverified.is_empty(), "the relay answered: verified");
        let plan = plan_missing(&zones, &members(), ME, &held, &HashMap::new(), &gate, None);
        assert_eq!(plan.pending, vec![("zone3".to_string(), pk('b'))]);
        assert!(plan.unverified.is_empty());
        assert!(plan.grants.iter().all(|(_, r)| r == &vec![ME.to_string()]));
    }

    #[test]
    fn an_unread_backup_approves_nothing() {
        // The relay never answered for the backup: the device cannot tell a
        // member granted elsewhere from an injected one, so nobody is adopted.
        let zones = [rule("zone3", "family", false)];
        let unread = HashSet::from(["zone3".to_string()]);
        let held = held("zone3", &[1]);
        let gate = gate_records(&held, HashMap::new(), &unread);
        assert!(gate.known.get("zone3").is_none_or(HashSet::is_empty));
        assert_eq!(gate.unverified, unread);
        // Its members are neither granted nor called never granted.
        let plan = plan_missing(&zones, &members(), ME, &held, &HashMap::new(), &gate, None);
        assert!(plan.pending.is_empty(), "not presented as never granted");
        assert_eq!(plan.unverified, vec![("zone3".to_string(), pk('b'))]);
        assert!(plan.grants.iter().all(|(_, r)| r == &vec![ME.to_string()]));
    }

    #[test]
    fn an_unverified_zone_still_grants_members_on_this_devices_record() {
        // Rotation keeps working through a flaky relay: b is on the local
        // ledger, so b is granted; e (unknown) waits for the check.
        let zones = [rule("zone3", "family", false)];
        let mut roster = members();
        roster.push((pk('e'), vec!["family".into()]));
        let held = held("zone3", &[1, 2]);
        let gate = gate_records(
            &held,
            HashMap::from([("zone3".to_string(), HashSet::from([pk('b')]))]),
            &HashSet::from(["zone3".to_string()]),
        );
        let plan = plan_missing(&zones, &roster, ME, &held, &HashMap::new(), &gate, None);
        let epoch2 = plan.grants.iter().find(|(k, _)| k.epoch == 2).unwrap();
        assert!(epoch2.1.contains(&pk('b')));
        assert!(plan.grants.iter().all(|(_, r)| !r.contains(&pk('e'))));
        assert_eq!(plan.unverified, vec![("zone3".to_string(), pk('e'))]);
        assert!(plan.pending.is_empty());
    }

    #[test]
    fn an_explicit_allocation_in_an_unverified_zone_still_grants() {
        // The admin named this pubkey: the backup state does not bear on it.
        let zones = [rule("zone3", "family", false)];
        let held = held("zone3", &[1]);
        let opened = allocation_opened(&zones, &pk('b'), &["family".to_string()]);
        assert_eq!(opened, vec![("zone3".to_string(), pk('b'))]);
        let gate = gate_records(
            &held,
            approved(&opened).known,
            &HashSet::from(["zone3".into()]),
        );
        let only = HashSet::from([pk('b')]);
        let plan = plan_missing(
            &zones,
            &members(),
            ME,
            &held,
            &HashMap::new(),
            &gate,
            Some(&only),
        );
        assert_eq!(plan.grants[0].1, vec![pk('b')]);
        assert!(plan.pending.is_empty());
        assert!(plan.unverified.is_empty());
    }

    /// A family zone's roster: the admin, two members this device has
    /// granted before (b, e), two the relay lists but nobody approved (c, f),
    /// and one outside the zone (g).
    fn family_roster() -> Vec<(String, Vec<String>)> {
        vec![
            (ME.into(), vec!["admin".into(), "family".into()]),
            (pk('b'), vec!["family".into()]),
            (pk('c'), vec!["family".into()]),
            (pk('e'), vec!["family".into()]),
            (pk('f'), vec!["family".into()]),
            (pk('g'), vec!["business".into()]),
        ]
    }

    fn sorted(mut v: Vec<String>) -> Vec<String> {
        v.sort();
        v
    }

    #[test]
    fn a_rotation_sends_the_new_key_to_known_members_only() {
        // The relay added c and f to the cohort; the admin clicks Rotate.
        // N = 2 known members (b, e) plus the admin receive epoch 2; M = 2
        // unknown members are held for approval and receive nothing.
        let zone = rule("zone3", "family", false);
        let gate = known("zone3", &[pk('b'), pk('e')]);
        let new_key = key("zone3", 2);
        let plan = plan_new_key(&zone, &family_roster(), ME, &new_key, &gate);
        assert_eq!(plan.grants.len(), 1, "one key, one batch");
        assert_eq!(plan.grants[0].0.epoch, 2);
        assert_eq!(
            sorted(plan.grants[0].1.clone()),
            sorted(vec![ME.to_string(), pk('b'), pk('e')])
        );
        assert_eq!(
            plan.pending,
            vec![
                ("zone3".to_string(), pk('c')),
                ("zone3".to_string(), pk('f'))
            ]
        );
        assert!(plan.unverified.is_empty());
    }

    #[test]
    fn a_rotation_in_an_unverified_zone_still_reaches_known_members() {
        let zone = rule("zone3", "family", false);
        let mut gate = known("zone3", &[pk('b'), pk('e')]);
        gate.unverified.insert("zone3".into());
        let plan = plan_new_key(&zone, &family_roster(), ME, &key("zone3", 2), &gate);
        assert_eq!(
            sorted(plan.grants[0].1.clone()),
            sorted(vec![ME.to_string(), pk('b'), pk('e')])
        );
        assert!(plan.pending.is_empty(), "not presented as never granted");
        assert_eq!(
            plan.unverified,
            vec![
                ("zone3".to_string(), pk('c')),
                ("zone3".to_string(), pk('f'))
            ]
        );
    }

    #[test]
    fn grant_missing_sends_to_known_members_only() {
        // Everyone but the admin is missing epoch 2; only b and e are known.
        let gate = known("zone3", &[pk('b'), pk('e')]);
        let missing = vec![pk('b'), pk('c'), pk('e'), pk('f')];
        let held = held("zone3", &[1, 2]);
        let plan = plan_grant_missing("zone3", &missing, ME, &held["zone3"], &gate, true, |_| {
            HashSet::new()
        });
        // Epoch 2 and, with history, epoch 1: both to the known pair only.
        let epochs: Vec<u32> = plan.grants.iter().map(|(k, _)| k.epoch).collect();
        assert_eq!(epochs, vec![2, 1]);
        for (_, r) in &plan.grants {
            assert_eq!(sorted(r.clone()), sorted(vec![pk('b'), pk('e')]));
        }
        assert_eq!(
            plan.pending,
            vec![
                ("zone3".to_string(), pk('c')),
                ("zone3".to_string(), pk('f'))
            ]
        );
        assert!(plan.unverified.is_empty());
    }

    #[test]
    fn approving_for_one_cohort_opens_only_that_cohorts_zone() {
        // The admin adds p to the public cohort. The relay also reports p in
        // the private cohort. Only the public zone may be approved and sent.
        let zones = [
            rule("zone_pub", "public", false),
            rule("zone_priv", "private", false),
        ];
        let p = pk('p');
        let roster = vec![
            (ME.to_string(), vec!["admin".into()]),
            (p.clone(), vec!["public".into(), "private".into()]),
        ];
        let mut keys = held("zone_pub", &[1]);
        keys.extend(held("zone_priv", &[1]));
        let only = HashSet::from([p.clone()]);
        // How `after_allocation` plans the grants for that allocation: it
        // records the opened pairs as approved, then plans through the gate.
        let opened = allocation_opened(&zones, &p, &["public".to_string()]);
        assert_eq!(opened, vec![("zone_pub".to_string(), p.clone())]);
        let plan = plan_missing(
            &zones,
            &roster,
            ME,
            &keys,
            &HashMap::new(),
            &approved(&opened),
            Some(&only),
        );
        let granted: Vec<&str> = plan
            .grants
            .iter()
            .filter(|(_, r)| r.contains(&p))
            .map(|(k, _)| k.zone.as_str())
            .collect();
        assert_eq!(granted, vec!["zone_pub"], "the private zone's key went out");
        assert_eq!(
            plan.pending,
            vec![("zone_priv".to_string(), p.clone())],
            "p stays pending in the zone the admin did not open"
        );
    }

    #[test]
    fn no_grant_below_the_floor_leaves_send_grants() {
        let plan = vec![
            (key("zone3", 4), vec![pk('b'), pk('c')]),
            (key("zone3", 5), vec![pk('b')]),
            (key("zone2", 1), vec![pk('b')]),
        ];
        let floor = |z: &str| (z == "zone3").then_some(5);
        let (kept, withheld) = withhold_below_floor(plan, floor);
        assert_eq!(withheld, 2);
        let kept: Vec<(String, u32)> = kept
            .iter()
            .map(|(k, _)| (k.zone.clone(), k.epoch))
            .collect();
        assert_eq!(
            kept,
            vec![("zone3".to_string(), 5), ("zone2".to_string(), 1)]
        );
        // A withheld grant is a problem in the report, never a success.
        let r = GrantTally {
            withheld: 2,
            ..GrantTally::default()
        }
        .report();
        let s = report_summary(&r).expect("something to say");
        assert!(s.problem && s.text.contains("history floor"), "{}", s.text);
    }

    fn tally(handed: usize, accepted: &[String], rejected: usize, failed: usize) -> GrantTally {
        GrantTally {
            handed,
            failed,
            withheld: 0,
            accepted: accepted.len(),
            rejected,
            accepted_members: accepted.iter().cloned().collect(),
        }
    }

    #[test]
    fn a_refused_or_unanswered_grant_is_never_reported_as_sent() {
        // Three grants handed over: b accepted, c refused, d never answered.
        let r = tally(3, &[pk('b')], 1, 0).report();
        assert_eq!(r.members, 1, "only members whose grant was accepted");
        let s = report_summary(&r).expect("something to say");
        assert!(s.problem, "a refusal is not a success: {}", s.text);
        assert!(s.text.contains("refused"), "{}", s.text);
        assert!(s.text.contains("not confirmed"), "{}", s.text);
        assert_eq!((r.accepted, r.rejected, r.unconfirmed), (1, 1, 1));
        // Nothing accepted at all, everything refused: still a problem.
        let r = tally(2, &[], 2, 0).report();
        let s = report_summary(&r).expect("something to say");
        assert!(s.problem);
        assert!(!s.text.starts_with("Sent"), "{}", s.text);
        // Every grant accepted: a plain success naming the members reached.
        let r = tally(2, &[pk('b'), pk('c')], 0, 0).report();
        let s = report_summary(&r).expect("something to say");
        assert!(!s.problem);
        assert!(s.text.contains("2 member(s)"), "{}", s.text);
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
            None,
        );
        assert!(plan.grants[0].1.contains(&pk('b')));
        // Once recorded at the inbox key, b is no longer owed.
        futures::executor::block_on(ledger.record(&kv, "zone3", 1, &[(pk('b'), pk('9'))]));
        let have = futures::executor::block_on(ledger.sent_to(&kv, "zone3", 1, &targets));
        assert!(have.contains(&pk('b')));
    }
}
