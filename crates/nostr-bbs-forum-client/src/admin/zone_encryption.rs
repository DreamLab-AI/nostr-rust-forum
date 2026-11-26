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
//! open across a cohort change never grants or rotates to a stale list.
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
use crate::zone_crypto::auto_grant::{report_summary, send_grants, AutoGrant, PendingReview};
use crate::zone_crypto::store::{try_use_zone_key_store, ZoneKeyStore};
use crate::zone_crypto::{generate_zone_key, grant_plan, grant_targets, ZoneKey, AGENT_COHORT};

fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
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
            <PendingApprovals />
            {zones.into_iter().map(|z| view! { <ZoneKeyCard zone=z keys=keys members_ready=members_ready /> }).collect_view()}
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
fn PendingApprovals() -> impl IntoView {
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
    check();

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
    let approve_all = move |targets: Vec<(String, String)>| {
        let ok = web_sys::window()
            .and_then(|w| {
                w.confirm_with_message(&format!(
                    "Approve and send zone keys to all {} listed member(s)? Confirm only if you \
                     recognise every one: a compromised relay could have added a pubkey.",
                    targets.len()
                ))
                .ok()
            })
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
fn ZoneKeyCard(zone: Zone, keys: ZoneKeyStore, members_ready: RwSignal<bool>) -> impl IntoView {
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

    // Reload "granted from this device" whenever the current epoch changes.
    let relay_for_ledger = relay.clone();
    Effect::new(move |_| {
        let Some(key) = latest() else {
            sent.set(HashSet::new());
            return;
        };
        let relay = relay_for_ledger.clone();
        let signer = auth.get_signer();
        spawn_local(async move {
            // Show what this device knows straight away, then fold in the
            // relay-held record (grants sent before site data was cleared, or
            // from another browser of this admin) and show that.
            sent.set(keys.grants_sent(&key.zone, key.epoch).await);
            if let Some(signer) = signer {
                if let Ok(n) = crate::zone_crypto::grant_backup::pull(
                    &relay, &*signer, keys, &key.zone, key.epoch,
                )
                .await
                {
                    if n > 0 {
                        let _ = sent.try_set(keys.grants_sent(&key.zone, key.epoch).await);
                    }
                }
            }
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

    let targets = move || {
        let required = zone.with_value(|z| z.required_cohorts.clone());
        admin.state.users.with(|users| {
            let members: Vec<(String, Vec<String>)> = users
                .iter()
                .map(|u| (u.pubkey.clone(), u.cohorts.clone()))
                .collect();
            grant_targets(
                &members,
                &required,
                &me(),
                zone.with_value(|z| z.agent_keys),
            )
        })
    };

    let missing = move || {
        let s = sent.get();
        targets()
            .into_iter()
            .filter(|pk| !s.contains(pk))
            .collect::<Vec<_>>()
    };

    // Send each `(key, recipients)` pair: one gift wrap per recipient, recorded
    // once the relay accepts it.
    let grant = {
        let relay = relay.clone();
        move |plan: Vec<(ZoneKey, Vec<String>)>| {
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
                status.set(Some("Everyone eligible already has this key.".into()));
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
                let _ = status.try_set(Some(match report_summary(&report) {
                    Some(s) if !s.problem => format!(
                        "{} Members receive the key next time they open the forum.",
                        s.text
                    ),
                    Some(s) => s.text,
                    None => "Nothing was sent — try again.".to_string(),
                }));
            });
        }
    };

    let create_or_rotate = {
        let grant = grant.clone();
        let fresh_roster = fresh_roster.clone();
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
            if rotate {
                let ok = web_sys::window()
                    .and_then(|w| {
                        w.confirm_with_message(&format!(
                            "Rotate to key epoch {next_epoch}? Everyone eligible gets the new key; \
                             anyone removed from the zone cannot read messages posted after this. \
                             Older messages stay readable with the keys members already hold."
                        ))
                        .ok()
                    })
                    .unwrap_or(false);
                if !ok {
                    return;
                }
            }
            let grant = grant.clone();
            fresh_roster(Box::new(move || {
                // Re-plan after the roster round trip: a key may have arrived.
                let crate::zone_crypto::keyset::MintPlan::Mint { epoch, .. } = mint_plan() else {
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
                let me = me();
                let zone_id = zone.with_value(|z| z.id.clone());
                match generate_zone_key(&zone_id, next_epoch, &me, now_secs()) {
                    Ok(mut key) => {
                        // Saved before anything is sent, and refused if this device
                        // holds a different key for the epoch; not sent under until
                        // its grants land (see `pending_delivery`).
                        key.pending_delivery = true;
                        let grant = grant.clone();
                        spawn_local(async move {
                            match keys.insert_local(key.clone()).await {
                                // A new key goes to everyone eligible; they already
                                // hold (or were offered) the earlier ones.
                                Ok(()) => grant(vec![(key, targets())]),
                                Err(why) => status.set(Some(why)),
                            }
                        });
                    }
                    Err(e) => status.set(Some(format!("Could not create a key: {e}"))),
                }
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
                                    || (missing().is_empty() && !latest().is_some_and(|k| k.pending_delivery))
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
                                    let signer_btn = auth.get_signer();
                                    spawn_local(async move {
                                        let mut earlier = std::collections::HashMap::new();
                                        if history {
                                            for k in &held {
                                                if let Some(sg) = &signer_btn {
                                                    let _ = crate::zone_crypto::grant_backup::pull(&relay_btn, &**sg, keys, &k.zone, k.epoch).await;
                                                }
                                                earlier.insert(k.epoch, keys.grants_sent(&k.zone, k.epoch).await);
                                            }
                                        }
                                        let plan = grant_plan(&held, &recipients, history, |e| {
                                            earlier.get(&e).cloned().unwrap_or_default()
                                        });
                                        grant.with_value(|g| g(plan));
                                    });
                                })))
                            >{move || format!("Grant to members missing it ({})", missing().len())}</button>
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
