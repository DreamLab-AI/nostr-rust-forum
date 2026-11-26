//! Admin "Encryption" tab: zone keys for end-to-end encrypted zones (ADR-2016).
//!
//! One card per zone whose `ZONE_CONFIG` entry has `"encrypted": true`:
//! create the first key, grant it to members who are missing it, or rotate to
//! a new epoch. Grants are NIP-59 gift wraps sealed by this admin. The relay
//! cannot be asked who holds a key (wraps are readable only by their
//! recipient and signed by throwaway keys), so "granted" is this admin's own
//! ledger: kept on this device and backed up to the relay, encrypted to the
//! admin ([`crate::zone_crypto::grant_backup`]), so it survives clearing site
//! data. Grants sent by another admin, or before the backup existed, read as
//! "missing" until re-granted; re-sending is harmless. Agents (cohort `agent`) receive a key only in a
//! zone configured with `agent_keys`. Granting to a member who is missing the
//! current key can also send the earlier keys this admin holds, so someone
//! who joins after a rotation can read the zone's history.
//! Both actions re-read the member roster from the relay first, so a tab left
//! open across a cohort change never grants or rotates to a stale list. The
//! roster only names candidates: each action sends the key to members this
//! device has granted before or an admin approved, and holds anyone else for
//! approval ([`crate::zone_crypto::auto_grant::gate_split`]), so a pubkey the
//! relay adds to a cohort never receives a key from a click here.
//! Grants also go out without this tab: on allocation and at an admin's
//! sign-in ([`crate::zone_crypto::auto_grant`]).

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::admin::use_admin;
use crate::auth::use_auth;
use crate::components::copy_key::CopyKey;
use crate::relay::RelayConnection;
use crate::stores::zones::{load_zones, Zone};
use crate::utils::shorten_pubkey;
use crate::zone_crypto::auto_grant::{
    gate_split, plan_grant_missing, plan_new_key, report_summary, send_grants, tab_gate, AutoGrant,
    GateRecords, PendingReview, ZoneRule,
};
use crate::zone_crypto::store::{try_use_zone_key_store, ZoneKeyStore};
use crate::zone_crypto::{generate_zone_key, grant_targets, ZoneKey, AGENT_COHORT};

fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// The parts of `z` that decide who holds its key.
fn rule_of(z: &Zone) -> ZoneRule {
    ZoneRule {
        id: z.id.clone(),
        required_cohorts: z.required_cohorts.clone(),
        agent_keys: z.agent_keys,
        history_from_epoch: z.history_from_epoch,
    }
}

/// The Encryption tab.
#[component]
pub fn ZoneEncryptionTab() -> impl IntoView {
    let admin = use_admin();
    let auth = use_auth();
    let gate_on = crate::zone_crypto::encryption_enabled();
    let zones: Vec<Zone> = load_zones()
        .into_iter()
        .filter(|z| crate::zone_crypto::zone_is_encrypted(gate_on, z.encrypted))
        .collect();

    // The member list drives grant targeting; load it if the Members tab has
    // not been visited this session. Key actions stay disabled until it has
    // arrived, or a quick click would grant (or rotate) to the admin alone.
    let members_ready = RwSignal::new(!admin.state.users.with_untracked(|u| u.is_empty()));
    if !members_ready.get_untracked() {
        if let Some(signer) = auth.get_signer() {
            let admin = admin.clone();
            spawn_local(async move {
                let _ = admin.fetch_whitelist_signer(&*signer).await;
                let _ = members_ready.try_set(true);
            });
        } else {
            members_ready.set(true);
        }
    }

    let Some(keys) = try_use_zone_key_store() else {
        return view! { <p class="text-sm text-gray-400">"Zone encryption is unavailable in this build."</p> }
            .into_any();
    };

    // Bumped when a card's action holds members back, so the approval list
    // re-checks and shows them.
    let refresh = RwSignal::new(0u64);

    if zones.is_empty() {
        return view! {
            <p class="text-sm text-gray-400">
                "No zone is configured as encrypted. Set "
                <code>"encrypted = true"</code>
                " on a zone in the operator config to enable this."
            </p>
        }
        .into_any();
    }

    view! {
        <div class="space-y-6">
            <p class="text-sm text-gray-400 max-w-3xl">
                "Members of an encrypted zone read and write its messages with a shared zone key. \
                 The relay only ever stores ciphertext. Grant the key to each member once; rotate it \
                 when someone leaves so they cannot read anything posted afterwards. Agents get \
                 a key only in zones the operator configured with agent_keys."
            </p>
            <PendingApprovals refresh=refresh />
            {zones.into_iter().map(|z| view! { <ZoneKeyCard zone=z keys=keys members_ready=members_ready refresh=refresh /> }).collect_view()}
        </div>
    }
    .into_any()
}

/// First-grant confirmation gate (deepsec #1). The sign-in sweep auto-grants
/// the zone key only to members it has granted before or that an admin has
/// approved; a pubkey the relay's roster newly places in a required cohort is
/// held here for a one-time confirmation, so a hostile relay cannot make the
/// sweep silently wrap the zone key to an injected pubkey. Approving a target
/// records it and grants the key; rotation to already-known members stays
/// automatic and never appears here.
///
/// A browser with no grant record (a fresh device, or site data cleared with
/// no relay backup) lists every member here: "Approve all" confirms them in
/// one batch. Members of a zone whose relay-held record could not be read are
/// listed apart as unverified (check again, or approve explicitly), and a
/// failed check says so rather than showing an empty list.
#[component]
fn PendingApprovals(refresh: RwSignal<u64>) -> impl IntoView {
    let Some(auto) = AutoGrant::capture() else {
        return ().into_any();
    };
    // `StoredValue` is `Copy`, so the reactive list closure below stays `Fn`
    // (the `Show` children must be) while still reaching the captured handles.
    let auto = StoredValue::new(auto);
    let review: RwSignal<Option<Result<PendingReview, String>>> = RwSignal::new(None);

    let check = move || {
        review.set(None);
        spawn_local(async move {
            let r = auto.get_value().pending_targets().await;
            let _ = review.try_set(Some(r));
        });
    };
    // On mount, and again whenever a card's action held members back.
    Effect::new(move |_| {
        refresh.track();
        check();
    });

    let drop_rows = move |done: &[(String, String)]| {
        review.update(|r| {
            if let Some(Ok(v)) = r {
                v.pending.retain(|t| !done.contains(t));
                v.unverified.retain(|t| !done.contains(t));
            }
        });
    };
    let approve = move |zone: String, pubkey: String| {
        auto.get_value().approve(&zone, &pubkey);
        // Drop the row optimistically; the next check recomputes the set.
        drop_rows(&[(zone, pubkey)]);
    };
    let admin = use_admin();
    let approve_all = move |targets: Vec<(String, String)>| {
        let roster: HashMap<String, (Option<String>, Vec<String>)> =
            admin.state.users.with_untracked(|users| {
                users
                    .iter()
                    .map(|u| {
                        let name = u.display_name.clone().or_else(|| u.handle.clone());
                        (u.pubkey.to_ascii_lowercase(), (name, u.cohorts.clone()))
                    })
                    .collect()
            });
        let ask = approve_all_summary(&targets, &roster, APPROVE_ALL_LISTED);
        let ok = web_sys::window()
            .and_then(|w| w.confirm_with_message(&ask).ok())
            .unwrap_or(false);
        if !ok {
            return;
        }
        auto.get_value().approve_all(targets.clone());
        drop_rows(&targets);
    };

    let row = move |zone: String, pubkey: String| {
        let (z, pk) = (zone.clone(), pubkey.clone());
        view! {
            <li class="flex items-center justify-between gap-3 text-sm">
                <span class="flex items-center gap-2">
                    <code class="text-xs text-gray-300">{zone}</code>
                    <CopyKey full=pubkey />
                </span>
                <button
                    class="px-2 py-1 text-xs rounded bg-amber-600 hover:bg-amber-500 text-white"
                    on:click=move |_| approve(z.clone(), pk.clone())
                >
                    "Approve & send key"
                </button>
            </li>
        }
    };

    view! {
        {move || match review.get() {
            None => ().into_any(),
            Some(Err(e)) => view! {
                <div class="rounded border border-red-500/40 bg-red-500/5 p-4 space-y-2">
                    <h3 class="text-sm font-semibold text-red-300">"Could not check for members awaiting a key"</h3>
                    <p class="text-xs text-gray-400">{e}</p>
                    <button
                        class="px-2 py-1 text-xs rounded border border-gray-600 text-gray-200 hover:bg-gray-700"
                        on:click=move |_| check()
                    >"Check again"</button>
                </div>
            }.into_any(),
            Some(Ok(v)) => {
                let PendingReview { pending, unverified, floor_blocked } = v;
                let floors = (!floor_blocked.is_empty()).then(|| view! {
                    <div class="rounded border border-red-500/40 bg-red-500/5 p-4 space-y-1">
                        <h3 class="text-sm font-semibold text-red-300">"No key can be granted for some zones"</h3>
                        {floor_blocked.iter().map(|b| view! {
                            <p class="text-xs text-gray-400">{b.explain()}</p>
                        }).collect_view()}
                    </div>
                });
                let pending_box = (!pending.is_empty()).then(|| {
                    let all = pending.clone();
                    view! {
                        <div class="rounded border border-amber-500/40 bg-amber-500/5 p-4 space-y-3">
                            <div class="flex items-start justify-between gap-3">
                                <div>
                                    <h3 class="text-sm font-semibold text-amber-300">"New members awaiting approval"</h3>
                                    <p class="text-xs text-gray-400 max-w-3xl mt-1">
                                        "These pubkeys are in an encrypted zone's cohort but this browser has no \
                                         record of granting them its key. The sign-in sweep will not send the key \
                                         until you confirm each one here, which stops a compromised relay from \
                                         silently granting the key to an injected pubkey. A browser with no grant \
                                         record yet lists every member: confirm only members you recognise."
                                    </p>
                                </div>
                                {(all.len() > 1).then(|| view! {
                                    <button
                                        class="shrink-0 px-2 py-1 text-xs rounded border border-amber-500 text-amber-200 hover:bg-amber-500/10"
                                        on:click=move |_| approve_all(all.clone())
                                    >{format!("Approve all ({})", all.len())}</button>
                                })}
                            </div>
                            <ul class="space-y-2">
                                {pending.into_iter().map(|(z, pk)| row(z, pk)).collect_view()}
                            </ul>
                        </div>
                    }
                });
                let unverified_box = (!unverified.is_empty()).then(|| view! {
                    <div class="rounded border border-sky-500/40 bg-sky-500/5 p-4 space-y-3">
                        <div class="flex items-start justify-between gap-3">
                            <div>
                                <h3 class="text-sm font-semibold text-sky-300">"Grant status could not be checked"</h3>
                                <p class="text-xs text-gray-400 max-w-3xl mt-1">
                                    "The relay did not return this admin's grant record for these zones, so \
                                     these members may or may not have been granted already. Nothing was sent to \
                                     them. Check again once the relay answers, or approve a member you recognise."
                                </p>
                            </div>
                            <button
                                class="shrink-0 px-2 py-1 text-xs rounded border border-gray-600 text-gray-200 hover:bg-gray-700"
                                on:click=move |_| check()
                            >"Check again"</button>
                        </div>
                        <ul class="space-y-2">
                            {unverified.into_iter().map(|(z, pk)| row(z, pk)).collect_view()}
                        </ul>
                    </div>
                });
                view! { {floors} {pending_box} {unverified_box} }.into_any()
            }
        }}
    }
    .into_any()
}

/// How many pending members the "Approve all" confirmation lists by name.
const APPROVE_ALL_LISTED: usize = 20;

/// A roster display name made safe for one line of a plain-text dialog:
/// control characters (a newline could forge a line of the list) become
/// spaces, and the result is capped at 40 characters.
fn one_line_name(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let clean = clean.split_whitespace().collect::<Vec<_>>().join(" ");
    if clean.chars().count() > 40 {
        format!("{}…", clean.chars().take(39).collect::<String>())
    } else {
        clean
    }
}

/// The "Approve all" confirmation: every `(zone, pubkey)` in `targets`,
/// grouped by zone, each with its display name (where `roster` has one), the
/// first eight hex characters of its key and its cohorts. At most `cap`
/// members are listed; the rest are counted, so an unexpected key is
/// noticeable without a dialog too long to read.
fn approve_all_summary(
    targets: &[(String, String)],
    roster: &HashMap<String, (Option<String>, Vec<String>)>,
    cap: usize,
) -> String {
    let members: HashSet<&String> = targets.iter().map(|(_, pk)| pk).collect();
    let mut by_zone: std::collections::BTreeMap<&str, Vec<String>> = Default::default();
    for (zone, pk) in targets {
        let prefix = pk.get(..8).unwrap_or(pk);
        let line = match roster.get(&pk.to_ascii_lowercase()) {
            Some((name, cohorts)) => {
                let name = name.as_deref().map(one_line_name).unwrap_or_default();
                let cohorts = if cohorts.is_empty() {
                    "no cohort".to_string()
                } else {
                    cohorts
                        .iter()
                        .map(|c| one_line_name(c))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                format!("{name} ({prefix}…) · {cohorts}")
            }
            None => format!("({prefix}…) · not in the member list"),
        };
        by_zone.entry(zone.as_str()).or_default().push(line);
    }
    let mut lines = vec![
        format!(
            "Approve and send zone keys: {} grant(s) to {} member(s)? Confirm only if you \
             recognise every one: a compromised relay could have added a pubkey.",
            targets.len(),
            members.len()
        ),
        String::new(),
    ];
    let mut listed = 0;
    for (zone, mut entries) in by_zone {
        if listed >= cap {
            break;
        }
        entries.sort();
        lines.push(format!("{zone}:"));
        for e in entries.into_iter().take(cap - listed) {
            lines.push(format!("  {}", e.trim_start()));
            listed += 1;
        }
    }
    let rest = targets.len() - listed;
    if rest > 0 {
        lines.push(format!(
            "…and {rest} more not listed here. Approve them one at a time below to check each."
        ));
    }
    lines.join("\n")
}

/// The confirmation shown before a new key is created (`rotate` false) or
/// rotated in at `epoch`: how many members receive it now (`receiving`, the
/// admin not counted), and how many are held back. Rotation always asks;
/// creation asks only when someone is held back.
fn new_key_confirmation(
    rotate: bool,
    epoch: u32,
    receiving: usize,
    pending: usize,
    unverified: usize,
) -> Option<String> {
    if !rotate && pending + unverified == 0 {
        return None;
    }
    let mut lines = vec![
        if rotate {
            format!("Rotate to key epoch {epoch}?")
        } else {
            format!("Create key epoch {epoch}?")
        },
        String::new(),
        format!("{receiving} member(s) receive the key now (and you)."),
        format!(
            "{pending} member(s) are held for your approval and get nothing until you approve \
             them under \"New members awaiting approval\"."
        ),
    ];
    if unverified > 0 {
        lines.push(format!(
            "{unverified} member(s) get nothing for now: this zone's grant record could not be \
             checked."
        ));
    }
    if rotate {
        lines.push(String::new());
        lines.push(
            "Anyone removed from the zone cannot read messages posted after this. Older \
             messages stay readable with the keys members already hold."
                .into(),
        );
    }
    Some(lines.join("\n"))
}

#[derive(Clone, PartialEq)]
struct MemberRow {
    pubkey: String,
    name: String,
    /// `name` is the abridged key (no display name or handle): rendered as a
    /// click-to-copy key.
    name_is_key: bool,
    agent: bool,
}

#[component]
fn ZoneKeyCard(
    zone: Zone,
    keys: ZoneKeyStore,
    members_ready: RwSignal<bool>,
    refresh: RwSignal<u64>,
) -> impl IntoView {
    let admin = use_admin();
    let auth = use_auth();
    let relay = expect_context::<RelayConnection>();
    let zone = StoredValue::new(zone);

    let busy = RwSignal::new(false);
    let status: RwSignal<Option<String>> = RwSignal::new(None);
    let sent: RwSignal<HashSet<String>> = RwSignal::new(HashSet::new());
    // Also send earlier epochs to members being granted the current key, so a
    // late joiner can read older messages. On by default; the admin can opt out.
    let include_history = RwSignal::new(true);

    let me = move || auth.pubkey().get().unwrap_or_default();
    // The signed-in identity's keys, once loaded for that identity: never the
    // previous account's, even in the moment before the store switches.
    let keys_ready = move || keys.ready_for(auth.pubkey().get().as_deref());
    let latest = move || {
        if !keys_ready() {
            return None;
        }
        zone.with_value(|z| keys.latest_tracked(&z.id))
    };
    // Create and Rotate pick their epoch with `keyset::plan_mint`: never a
    // second key for an epoch in use or held by another account on this
    // browser, and no single post can block them.
    let channels = crate::stores::channels::use_channel_store();
    let mint_plan = move || {
        let zone_id = zone.with_value(|z| z.id.clone());
        let seen = keys.epochs_seen.with(|m| {
            m.iter()
                .filter(|((z, channel), _)| {
                    *z == zone_id
                        && crate::zone_crypto::store::channel_zone(channels, channel)
                            .is_some_and(|(cz, _, _)| cz == zone_id)
                })
                .flat_map(|(_, epochs)| epochs.iter().map(|(e, id)| (*e, id.clone())))
                .collect::<Vec<_>>()
        });
        let ready = channels.msg_eose_received.get() && keys_ready();
        // A new key goes straight to every member, so it may not be minted
        // below the zone's history floor (it could never be granted).
        crate::zone_crypto::keyset::floor_mint(
            crate::zone_crypto::keyset::plan_mint(
                &zone_id,
                latest().map(|k| k.epoch),
                &keys.device_epochs_for(&zone_id),
                &seen,
                ready,
            ),
            zone.with_value(|z| z.history_from_epoch),
        )
    };
    let mint_waiting = move || {
        !matches!(
            mint_plan(),
            crate::zone_crypto::keyset::MintPlan::Mint { .. }
        )
    };
    let mint_epoch = move || match mint_plan() {
        crate::zone_crypto::keyset::MintPlan::Mint { epoch, .. } => epoch.to_string(),
        _ => "…".into(),
    };
    // Refused (or displaced) keys for this zone, with the key held for the
    // same slot when there is one: (offered, held pubkey).
    let zone_conflicts = move || {
        let zone_id = zone.with_value(|z| z.id.clone());
        let held = keys.keys.get();
        keys.conflicts.with(|v| {
            v.iter()
                .filter(|r| r.key.zone == zone_id)
                .filter_map(|r| {
                    let h = held.get(&r.key.store_id())?;
                    crate::zone_crypto::conflicts(h, &r.key).then(|| (r.clone(), h.pubkey.clone()))
                })
                .collect::<Vec<_>>()
        })
    };

    // The first-grant gate for this zone (who this device knows, and whether
    // the relay-held record was read), for the button's count. Every action
    // reads it afresh before sending; this copy is only for display.
    let gate: RwSignal<Option<GateRecords>> = RwSignal::new(None);

    // Reload "granted from this device" and the gate whenever the current
    // epoch changes, or an action asks.
    let relay_for_ledger = relay.clone();
    Effect::new(move |_| {
        refresh.track();
        let latest_key = latest();
        if latest_key.is_none() {
            sent.set(HashSet::new());
        }
        let relay = relay_for_ledger.clone();
        let signer = auth.get_signer();
        let (zone_id, floor) = zone.with_value(|z| (z.id.clone(), z.history_from_epoch));
        spawn_local(async move {
            // Show what this device knows straight away, then fold in the
            // relay-held record (grants sent before site data was cleared, or
            // from another browser of this admin) and show that.
            if let Some(key) = &latest_key {
                let _ = sent.try_set(keys.grants_sent(&key.zone, key.epoch).await);
            }
            let Some(signer) = signer else {
                return;
            };
            let g = tab_gate(&relay, &*signer, keys, &zone_id, floor).await;
            if let Some(key) = &latest_key {
                let _ = sent.try_set(keys.grants_sent(&key.zone, key.epoch).await);
            }
            let _ = gate.try_set(Some(g));
        });
    });

    // Grants and rotations go to whoever the roster says is in the zone, so
    // re-read it from the relay right before sending. An admin tab left open
    // across a cohort change would otherwise act on a stale list — and hand
    // the new key to someone excluded since the tab was opened.
    let fresh_roster = {
        let admin = admin.clone();
        move |then: Box<dyn FnOnce()>| {
            let admin = admin.clone();
            let signer = auth.get_signer();
            busy.set(true);
            spawn_local(async move {
                if let Some(signer) = signer {
                    if let Err(e) = admin.fetch_whitelist_signer(&*signer).await {
                        busy.set(false);
                        status.set(Some(format!("Could not refresh the member list: {e}")));
                        return;
                    }
                }
                busy.set(false);
                then();
            });
        }
    };

    let rows = move || {
        let required = zone.with_value(|z| z.required_cohorts.clone());
        admin.state.users.with(|users| {
            let mut v: Vec<MemberRow> = users
                .iter()
                .filter(|u| u.cohorts.iter().any(|c| required.contains(c)))
                .map(|u| MemberRow {
                    pubkey: u.pubkey.to_ascii_lowercase(),
                    name: u
                        .display_name
                        .clone()
                        .or_else(|| u.handle.clone())
                        .unwrap_or_else(|| shorten_pubkey(&u.pubkey)),
                    name_is_key: u.display_name.is_none() && u.handle.is_none(),
                    agent: !zone.with_value(|z| z.agent_keys)
                        && u.cohorts.iter().any(|c| c == AGENT_COHORT),
                })
                .collect();
            v.sort_by_key(|r| r.name.to_lowercase());
            v
        })
    };

    // The roster as `(pubkey, cohorts)`, as last read from the relay.
    let roster = move || {
        admin.state.users.with(|users| {
            users
                .iter()
                .map(|u| (u.pubkey.clone(), u.cohorts.clone()))
                .collect::<Vec<(String, Vec<String>)>>()
        })
    };

    let targets = move || {
        let required = zone.with_value(|z| z.required_cohorts.clone());
        grant_targets(
            &roster(),
            &required,
            &me(),
            zone.with_value(|z| z.agent_keys),
        )
    };

    let missing = move || {
        let s = sent.get();
        targets()
            .into_iter()
            .filter(|pk| !s.contains(pk))
            .collect::<Vec<_>>()
    };

    // `missing`, split by the last gate read: `None` until it has loaded.
    let missing_split = move || {
        let m = missing();
        let zone_id = zone.with_value(|z| z.id.clone());
        let me = me();
        gate.with(|g| g.as_ref().map(|g| gate_split(&zone_id, m, &me, g)))
    };

    // Ask the approval list (and this card's gate) to re-check: members were
    // held back and should be listed.
    let held_back = move || {
        let _ = refresh.try_update(|n| *n = n.wrapping_add(1));
    };

    // Send each `(key, recipients)` pair: one gift wrap per recipient, recorded
    // once the relay accepts it. `held` says who the action held back, so the
    // outcome never reads as if everyone was reached.
    let grant = {
        let relay = relay.clone();
        move |plan: Vec<(ZoneKey, Vec<String>)>, held: Option<String>| {
            let Some(signer) = auth.get_signer() else {
                status.set(Some("Sign in again to grant keys.".into()));
                return;
            };
            // A key not yet delivered also goes to the admin's own identity, so
            // this browser's storage is never its only copy.
            let me_pk = me();
            let mut plan = plan;
            // A retry with nobody missing still has to deliver the pending key
            // to the admin, then adopt it.
            if let Some(k) = latest().filter(|k| k.pending_delivery) {
                if !plan
                    .iter()
                    .any(|(p, _)| p.epoch == k.epoch && p.pubkey == k.pubkey)
                {
                    plan.push((k, Vec::new()));
                }
            }
            let plan: Vec<(ZoneKey, Vec<String>)> = plan
                .into_iter()
                .map(|(k, mut r)| {
                    if k.pending_delivery && me_pk.len() == 64 && !r.contains(&me_pk) {
                        r.push(me_pk.clone());
                    }
                    (k, r)
                })
                .collect();
            // Each pending key in this run, with the recipients whose wrap the
            // relay has yet to accept. Emptied by the acks below.
            let awaiting: HashMap<(u32, String), HashSet<String>> = plan
                .iter()
                .filter(|(k, _)| k.pending_delivery)
                .map(|(k, r)| ((k.epoch, k.pubkey.clone()), r.iter().cloned().collect()))
                .collect();
            if !awaiting.is_empty() && me_pk.len() != 64 {
                status.set(Some(
                    "Sign in again: a new key has to reach your own account before it is used."
                        .into(),
                ));
                return;
            }
            let awaiting = Rc::new(RefCell::new(awaiting));
            // The identity sending: its pending key is settled even if the
            // acks land after it signed out.
            let sender = me_pk.clone();
            if plan.iter().all(|(_, r)| r.is_empty()) {
                status.set(Some(match &held {
                    Some(h) => format!("Nothing was sent. {h}"),
                    None => "Everyone eligible already has this key.".into(),
                }));
                return;
            }
            let members: HashSet<&String> = plan.iter().flat_map(|(_, r)| r.iter()).collect();
            let epochs = plan.len();
            busy.set(true);
            status.set(Some(format!(
                "Granting {} key(s) to {} member(s)…",
                epochs,
                members.len()
            )));
            let relay = relay.clone();
            spawn_local(async move {
                // The tab may be closed by the time the relay acks.
                let on_recorded = Rc::new(move |key: &ZoneKey, pk: &str| {
                    let _ = sent.try_update(|s| {
                        s.insert(pk.to_string());
                    });
                    // Adopt a pending key for sending only once the relay has
                    // accepted (`OK true`) every wrap of it in this run, the
                    // admin's own included. A queued or rejected wrap never
                    // gets here, so the key stays pending and the card says so.
                    let id = (key.epoch, key.pubkey.clone());
                    let done = {
                        let mut a = awaiting.borrow_mut();
                        match a.get_mut(&id) {
                            Some(left) => {
                                left.remove(pk);
                                left.is_empty()
                            }
                            None => false,
                        }
                    };
                    if done {
                        awaiting.borrow_mut().remove(&id);
                        keys.mark_delivered(&sender, &key.zone, key.epoch, &key.pubkey);
                    }
                });
                let report = send_grants(keys, &relay, &*signer, plan, on_recorded).await;
                let _ = busy.try_set(false);
                let outcome = match report_summary(&report) {
                    Some(s) if !s.problem => format!(
                        "{} Members receive the key next time they open the forum.",
                        s.text
                    ),
                    Some(s) => s.text,
                    None => "Nothing was sent — try again.".to_string(),
                };
                let _ = status.try_set(Some(match &held {
                    Some(h) => format!("{outcome} {h}"),
                    None => outcome,
                }));
            });
        }
    };

    let create_or_rotate = {
        let grant = grant.clone();
        let fresh_roster = fresh_roster.clone();
        let relay = relay.clone();
        move |rotate: bool| {
            let plan = mint_plan();
            let crate::zone_crypto::keyset::MintPlan::Mint {
                epoch: next_epoch, ..
            } = plan
            else {
                status.set(Some(
                    "A key cannot be created yet: see the note on this card.".into(),
                ));
                return;
            };
            // Planned below an epoch the zone's posts use: never mint that
            // silently, it may not take effect for members on the higher one.
            if let Some(ask) = crate::zone_crypto::keyset::mint_confirmation(&plan) {
                let ok = web_sys::window()
                    .and_then(|w| w.confirm_with_message(&ask).ok())
                    .unwrap_or(false);
                if !ok {
                    return;
                }
            }
            let grant = grant.clone();
            let relay = relay.clone();
            fresh_roster(Box::new(move || {
                let Some(signer) = auth.get_signer() else {
                    status.set(Some("Sign in again to create a key.".into()));
                    return;
                };
                let me = me();
                let rule = zone.with_value(rule_of);
                let members = roster();
                busy.set(true);
                spawn_local(async move {
                    // Who is known for the zone, read before the new key
                    // exists (it has no grants yet): the same record the
                    // sign-in sweep reads, never the roster.
                    let g =
                        tab_gate(&relay, &*signer, keys, &rule.id, rule.history_from_epoch).await;
                    let _ = busy.try_set(false);
                    // Re-plan after the round trips: a key may have arrived.
                    let crate::zone_crypto::keyset::MintPlan::Mint { epoch, .. } = mint_plan()
                    else {
                        status.set(Some(
                            "A key cannot be created yet: see the note on this card.".into(),
                        ));
                        return;
                    };
                    if epoch != next_epoch {
                        status.set(Some(format!(
                            "Keys changed while loading members (now epoch {epoch} would be next). Nothing was created; try again."
                        )));
                        return;
                    }
                    let mut key = match generate_zone_key(&rule.id, next_epoch, &me, now_secs()) {
                        Ok(k) => k,
                        Err(e) => {
                            status.set(Some(format!("Could not create a key: {e}")));
                            return;
                        }
                    };
                    // Saved before anything is sent, and refused if this
                    // device holds a different key for the epoch; not sent
                    // under until its grants land (see `pending_delivery`).
                    key.pending_delivery = true;
                    // The new key goes to every known member in one batch;
                    // anyone else is held for approval.
                    let plan = plan_new_key(&rule, &members, &me, &key, &g);
                    let (pending, unverified) = plan.held();
                    if let Some(ask) = new_key_confirmation(
                        rotate,
                        next_epoch,
                        plan.receiving(&me),
                        pending,
                        unverified,
                    ) {
                        let ok = web_sys::window()
                            .and_then(|w| w.confirm_with_message(&ask).ok())
                            .unwrap_or(false);
                        if !ok {
                            return;
                        }
                    }
                    let _ = gate.try_set(Some(g));
                    match keys.insert_local(key).await {
                        Ok(()) => {
                            if pending + unverified > 0 {
                                held_back();
                            }
                            let note = plan.held_note();
                            grant(plan.grants, note)
                        }
                        Err(why) => status.set(Some(why)),
                    }
                });
            }));
        }
    };
    let create_or_rotate = StoredValue::new_local(create_or_rotate);
    let grant = StoredValue::new_local(grant);
    let fresh_roster = StoredValue::new_local(fresh_roster);

    let relay_btn = StoredValue::new_local(relay.clone());
    let title = zone.with_value(|z| {
        if z.display_name.is_empty() {
            z.id.clone()
        } else {
            z.display_name.clone()
        }
    });

    view! {
        <section class="bg-gray-800/60 border border-gray-700 rounded-xl p-4 space-y-4">
            <header class="flex flex-wrap items-center justify-between gap-2">
                <div>
                    <h3 class="text-white font-semibold">{title}</h3>
                    <p class="text-xs text-gray-400">
                        {move || match latest() {
                            Some(k) if k.pending_delivery => format!(
                                "Key epoch {} is not delivered yet · new messages still use the previous key until it reaches members. Grant to retry.",
                                k.epoch
                            ),
                            Some(k) => format!("Key epoch {} · created or received here", k.epoch),
                            None => "No key on this device yet".to_string(),
                        }}
                    </p>
                </div>
                <div class="flex flex-wrap gap-2">
                    {move || latest().is_none().then(|| view! {
                        <button
                            class="px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-gray-900 text-sm font-semibold disabled:opacity-50"
                            disabled=move || busy.get() || !members_ready.get() || mint_waiting()
                            on:click=move |_| create_or_rotate.with_value(|f| f(false))
                        >{move || format!("Create key (epoch {})", mint_epoch())}</button>
                    })}
                    {move || latest().map(|_| {
                        view! {
                            <button
                                class="px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-gray-900 text-sm font-semibold disabled:opacity-50"
                                disabled=move || busy.get() || !members_ready.get()
                                    || (missing_split().map_or_else(|| missing().is_empty(), |s| s.send.is_empty())
                                        && !latest().is_some_and(|k| k.pending_delivery))
                                on:click=move |_| fresh_roster.with_value(|f| f(Box::new(move || {
                                    let recipients = missing();
                                    let history = include_history.get_untracked();
                                    let zone_id = zone.with_value(|z| z.id.clone());
                                    let floor = crate::zone_crypto::history_floor(&zone_id);
                                    let all = keys.all_for_zone(&zone_id);
                                    // Every held key below the floor: say why
                                    // nothing goes, rather than "everyone has it".
                                    if let Some(block) = crate::zone_crypto::floor_block(&zone_id, &all, floor) {
                                        status.set(Some(block.explain()));
                                        return;
                                    }
                                    let held = crate::zone_crypto::grantable_keys(all, floor);
                                    let relay_btn = relay_btn.get_value();
                                    let Some(signer_btn) = auth.get_signer() else {
                                        status.set(Some("Sign in again to grant keys.".into()));
                                        return;
                                    };
                                    let me_now = me();
                                    busy.set(true);
                                    spawn_local(async move {
                                        // Restores the relay-held record of every
                                        // grantable key, then says who is known.
                                        let g = tab_gate(&relay_btn, &*signer_btn, keys, &zone_id, floor).await;
                                        let mut earlier = std::collections::HashMap::new();
                                        for k in &held {
                                            earlier.insert(k.epoch, keys.grants_sent(&k.zone, k.epoch).await);
                                        }
                                        // Members the restored record shows as
                                        // granted the newest key are not missing.
                                        let have = held
                                            .iter()
                                            .map(|k| k.epoch)
                                            .max()
                                            .and_then(|e| earlier.get(&e).cloned())
                                            .unwrap_or_default();
                                        let recipients: Vec<String> =
                                            recipients.into_iter().filter(|pk| !have.contains(pk)).collect();
                                        let _ = busy.try_set(false);
                                        let plan = plan_grant_missing(
                                            &zone_id,
                                            &recipients,
                                            &me_now,
                                            &held,
                                            &g,
                                            history,
                                            |e| earlier.get(&e).cloned().unwrap_or_default(),
                                        );
                                        let _ = gate.try_set(Some(g));
                                        let (pending, unverified) = plan.held();
                                        if pending + unverified > 0 {
                                            held_back();
                                        }
                                        let note = plan.held_note();
                                        grant.with_value(|f| f(plan.grants, note));
                                    });
                                })))
                            >{move || match missing_split() {
                                Some(s) if !s.pending.is_empty() || !s.unverified.is_empty() => format!(
                                    "Grant to members missing it ({}) · {} held for approval",
                                    s.send.len(),
                                    s.pending.len() + s.unverified.len()
                                ),
                                Some(s) => format!("Grant to members missing it ({})", s.send.len()),
                                None => format!("Grant to members missing it ({})", missing().len()),
                            }}</button>
                            <button
                                class="px-3 py-1.5 rounded-lg border border-gray-600 text-gray-200 hover:bg-gray-700 text-sm disabled:opacity-50"
                                disabled=move || busy.get() || !members_ready.get() || mint_waiting()
                                on:click=move |_| create_or_rotate.with_value(|f| f(true))
                            >"Rotate key"</button>
                        }
                    })}
                </div>
            </header>

            {move || (latest().map(|k| k.epoch).unwrap_or(0) > 1).then(|| view! {
                <label class="flex items-center gap-2 text-sm text-gray-300">
                    <input
                        type="checkbox"
                        prop:checked=move || include_history.get()
                        on:change=move |ev| include_history.set(event_target_checked(&ev))
                    />
                    "Also send earlier keys, so new members can read older messages"
                </label>
            })}

            {move || {
                let missing = keys.unheld_epochs(&zone.with_value(|z| z.id.clone()));
                (!missing.is_empty() && keys_ready()).then(|| {
                    let list = missing.iter().map(|e| e.to_string()).collect::<Vec<_>>().join(", ");
                    view! {
                        <div class="flex flex-wrap items-center gap-2 text-sm text-amber-300">
                            <span>{format!(
                                "Messages here use key epoch {list}, which this device does not hold. A grant for it may already be waiting on the relay: re-check before creating or rotating a key."
                            )}</span>
                            <button
                                class="px-2 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 text-xs"
                                on:click=move |_| {
                                    let asked = keys.recheck_grants();
                                    status.set(Some(if asked {
                                        "Asked the relay for your grants again. A key found is adopted automatically.".into()
                                    } else {
                                        "Not connected to the relay yet; try again in a moment.".into()
                                    }));
                                }
                            >"Re-check grants"</button>
                        </div>
                    }
                })
            }}

            {move || match mint_plan() {
                crate::zone_crypto::keyset::MintPlan::Mint { note: Some(note), .. }
                | crate::zone_crypto::keyset::MintPlan::Blocked(note) => Some(view! {
                    <p class="text-xs text-amber-300">{note}</p>
                }),
                _ => None,
            }}

            {move || {
                let c = zone_conflicts();
                (!c.is_empty()).then(|| view! {
                    <div class="space-y-2" role="alert">
                        {c.into_iter().map(|(entry, held_pk)| {
                            let offered = entry.key.clone();
                            let short = |s: &str| s.get(..8).unwrap_or(s).to_string();
                            let origin = if entry.displaced {
                                "the key used before".to_string()
                            } else {
                                format!("granted by {}…", short(&offered.granted_by))
                            };
                            let text = format!(
                                "Two different keys for epoch {}: this device uses {}…; {}… ({}) was set aside. Posts that \"could not be decrypted\" usually mean the key in use is the stale one.",
                                offered.epoch,
                                short(&held_pk),
                                short(&offered.pubkey),
                                origin,
                            );
                            let label = if entry.displaced { "Use the earlier key" } else { "Use the granted key" };
                            view! {
                                <div class="flex flex-wrap items-center gap-2 text-sm text-red-300">
                                    <span>{text}</span>
                                    <button
                                        class="px-2 py-1 rounded bg-red-500/20 hover:bg-red-500/30 text-red-200 text-xs"
                                        on:click=move |_| {
                                            let entry = entry.clone();
                                            spawn_local(async move {
                                                let key = entry.key.clone();
                                                match keys.use_refused(&entry).await {
                                                    Ok(()) => status.set(Some(format!(
                                                        "Now using {}… for epoch {}; the other key is kept here in case you need it back.",
                                                        key.pubkey.get(..8).unwrap_or(&key.pubkey),
                                                        key.epoch
                                                    ))),
                                                    Err(why) => status.set(Some(why)),
                                                }
                                            });
                                        }
                                    >
                                        {label}
                                    </button>
                                </div>
                            }
                        }).collect_view()}
                    </div>
                })
            }}

            {move || status.get().map(|s| view! {
                <p class="text-sm text-amber-300" role="status">{s}</p>
            })}

            <p class="text-xs text-gray-500">
                {move || {
                    let t = targets().len();
                    let s = sent.with(|s| targets().iter().filter(|pk| s.contains(*pk)).count());
                    format!("{s} of {t} eligible members recorded as granted by you (including you). Grants sent by other admins show as missing.")
                }}
            </p>

            <ul class="divide-y divide-gray-700/60 text-sm">
                {move || {
                    let s = sent.get();
                    let me = me();
                    rows().into_iter().map(|r| {
                        let label = if r.agent {
                            ("excluded — agent", "text-gray-500")
                        } else if r.pubkey == me {
                            ("you", "text-green-400")
                        } else if s.contains(&r.pubkey) {
                            ("granted", "text-green-400")
                        } else {
                            ("missing", "text-amber-400")
                        };
                        view! {
                            <li class="flex items-center justify-between py-1.5 gap-3">
                                {if r.name_is_key {
                                    view! {
                                        <span class="truncate text-gray-200 font-mono">
                                            <CopyKey full=r.pubkey.clone() display=r.name.clone() />
                                        </span>
                                    }
                                    .into_any()
                                } else {
                                    view! {
                                        <span class="truncate text-gray-200" title=r.pubkey.clone()>{r.name.clone()}</span>
                                    }
                                    .into_any()
                                }}
                                <span class=format!("text-xs {}", label.1)>{label.0}</span>
                            </li>
                        }
                    }).collect_view()
                }}
            </ul>
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rotation_confirmation_counts_who_receives_and_who_is_held() {
        let ask = new_key_confirmation(true, 7, 3, 2, 0).expect("rotation always asks");
        assert!(ask.contains("Rotate to key epoch 7?"), "{ask}");
        assert!(ask.contains("3 member(s) receive the key now"), "{ask}");
        assert!(
            ask.contains("2 member(s) are held for your approval"),
            "{ask}"
        );
        assert!(!ask.contains("could not be checked"), "{ask}");
        let ask = new_key_confirmation(true, 7, 3, 0, 4).expect("rotation always asks");
        assert!(
            ask.contains("0 member(s) are held for your approval"),
            "{ask}"
        );
        assert!(ask.contains("4 member(s) get nothing for now"), "{ask}");
    }

    #[test]
    fn approve_all_lists_each_member_by_zone_with_name_key_and_cohorts() {
        let pk = |c: char| c.to_string().repeat(64);
        let roster = HashMap::from([
            (
                pk('b'),
                (Some("Alice".to_string()), vec!["family".to_string()]),
            ),
            (
                pk('c'),
                // A name that tries to forge a line of its own.
                (
                    Some("Mallory\n  Bob (dddddddd…) · family".to_string()),
                    vec!["family".to_string(), "business".to_string()],
                ),
            ),
        ]);
        let targets = vec![
            ("zone3".to_string(), pk('c')),
            ("zone2".to_string(), pk('b')),
            ("zone3".to_string(), pk('b')),
            ("zone3".to_string(), pk('e')),
        ];
        let text = approve_all_summary(&targets, &roster, 20);
        assert!(text.contains("4 grant(s) to 3 member(s)"), "{text}");
        let zone2 = text.find("zone2:").expect("zone2 group");
        let zone3 = text.find("zone3:").expect("zone3 group");
        assert!(zone2 < zone3, "zones in order: {text}");
        assert_eq!(text.matches("zone3:").count(), 1, "one header per zone");
        assert!(text.contains("Alice (bbbbbbbb…) · family"), "{text}");
        assert!(
            text.contains("(eeeeeeee…) · not in the member list"),
            "{text}"
        );
        assert!(text.contains("family, business"), "{text}");
        // A display name cannot add a line to the list.
        assert!(!text.contains("\n  Bob"), "{text}");
    }

    #[test]
    fn approve_all_caps_the_list_and_says_how_many_are_not_shown() {
        let roster = HashMap::new();
        let targets: Vec<(String, String)> = (0..25)
            .map(|i| ("zone3".to_string(), format!("{i:064x}")))
            .collect();
        let text = approve_all_summary(&targets, &roster, 20);
        assert_eq!(text.matches("not in the member list").count(), 20, "{text}");
        assert!(text.contains("and 5 more not listed"), "{text}");
    }

    #[test]
    fn creating_a_key_asks_only_when_someone_is_held() {
        assert_eq!(new_key_confirmation(false, 1, 5, 0, 0), None);
        let ask = new_key_confirmation(false, 1, 0, 5, 0).expect("held members");
        assert!(ask.contains("Create key epoch 1?"), "{ask}");
        assert!(ask.contains("5 member(s) are held"), "{ask}");
    }
}
