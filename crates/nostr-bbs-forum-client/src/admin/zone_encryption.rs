//! Admin "Encryption" tab: zone keys for end-to-end encrypted zones (ADR-2016).
//!
//! One card per zone whose `ZONE_CONFIG` entry has `"encrypted": true`:
//! create the first key, grant it to members who are missing it, or rotate to
//! a new epoch. Grants are NIP-59 gift wraps sealed by this admin; which
//! members hold a key can only be known for grants sent from this device, so
//! the card says exactly that. Agents (cohort `agent`) never receive a key.

use std::collections::HashSet;
use std::rc::Rc;

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::admin::use_admin;
use crate::auth::use_auth;
use crate::relay::RelayConnection;
use crate::stores::zones::{load_zones, Zone};
use crate::utils::shorten_pubkey;
use crate::zone_crypto::store::{try_use_zone_key_store, ZoneKeyStore};
use crate::zone_crypto::{
    build_grant_wrap, generate_zone_key, grant_targets, ZoneKey, AGENT_COHORT,
};

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
    // not been visited this session.
    if admin.state.users.with_untracked(|u| u.is_empty()) {
        if let Some(signer) = auth.get_signer() {
            let admin = admin.clone();
            spawn_local(async move {
                let _ = admin.fetch_whitelist_signer(&*signer).await;
            });
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
                 when someone leaves so they cannot read anything posted afterwards. Agents are \
                 never given a key."
            </p>
            {zones.into_iter().map(|z| view! { <ZoneKeyCard zone=z keys=keys /> }).collect_view()}
        </div>
    }
    .into_any()
}

#[derive(Clone, PartialEq)]
struct MemberRow {
    pubkey: String,
    name: String,
    agent: bool,
}

#[component]
fn ZoneKeyCard(zone: Zone, keys: ZoneKeyStore) -> impl IntoView {
    let admin = use_admin();
    let auth = use_auth();
    let relay = expect_context::<RelayConnection>();
    let zone = StoredValue::new(zone);

    let busy = RwSignal::new(false);
    let status: RwSignal<Option<String>> = RwSignal::new(None);
    let sent: RwSignal<HashSet<String>> = RwSignal::new(HashSet::new());

    let latest = move || zone.with_value(|z| keys.latest_tracked(&z.id));

    // Reload "granted from this device" whenever the current epoch changes.
    Effect::new(move |_| {
        let Some(key) = latest() else {
            sent.set(HashSet::new());
            return;
        };
        spawn_local(async move {
            let s = keys.grants_sent(&key.zone, key.epoch).await;
            sent.set(s);
        });
    });

    let me = move || auth.pubkey().get().unwrap_or_default();

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

    // Grant `key` to `recipients`: one gift wrap each, recorded once the relay
    // accepts it.
    let grant = {
        let relay = relay.clone();
        move |key: ZoneKey, recipients: Vec<String>| {
            let Some(signer) = auth.get_signer() else {
                status.set(Some("Sign in again to grant keys.".into()));
                return;
            };
            if recipients.is_empty() {
                status.set(Some("Everyone eligible already has this key.".into()));
                return;
            }
            busy.set(true);
            status.set(Some(format!("Granting to {} member(s)…", recipients.len())));
            let relay = relay.clone();
            spawn_local(async move {
                let total = recipients.len();
                let mut failed = 0usize;
                for pk in recipients {
                    match build_grant_wrap(&*signer, &pk, &key, now_secs()).await {
                        Ok(wrap) => {
                            let key_for_ack = key.clone();
                            let pk_for_ack = pk.clone();
                            let on_ok = Rc::new(move |ok: bool, _msg: String| {
                                if ok {
                                    let key = key_for_ack.clone();
                                    let pk = pk_for_ack.clone();
                                    spawn_local(async move {
                                        keys.record_grants(
                                            &key.zone,
                                            key.epoch,
                                            std::slice::from_ref(&pk),
                                        )
                                        .await;
                                        // The tab may be closed by now.
                                        let _ = sent.try_update(|s| {
                                            s.insert(pk);
                                        });
                                    });
                                }
                            });
                            if relay.publish_with_ack(&wrap, Some(on_ok)).is_err() {
                                failed += 1;
                            }
                        }
                        Err(_) => failed += 1,
                    }
                }
                let _ = busy.try_set(false);
                let _ = status.try_set(Some(if failed == 0 {
                    format!("Sent {total} grant(s). Members receive the key next time they open the forum.")
                } else {
                    format!("Sent {} grant(s); {failed} could not be built or sent — try again.", total - failed)
                }));
            });
        }
    };

    let create_or_rotate = {
        let grant = grant.clone();
        move |rotate: bool| {
            let next_epoch = latest().map(|k| k.epoch + 1).unwrap_or(1);
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
            let me = me();
            let zone_id = zone.with_value(|z| z.id.clone());
            match generate_zone_key(&zone_id, next_epoch, &me, now_secs()) {
                Ok(key) => {
                    keys.insert(key.clone());
                    grant(key, targets());
                }
                Err(e) => status.set(Some(format!("Could not create a key: {e}"))),
            }
        }
    };
    let create_or_rotate = StoredValue::new_local(create_or_rotate);
    let grant = StoredValue::new_local(grant);

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
                            Some(k) => format!("Key epoch {} · created or received here", k.epoch),
                            None => "No key on this device yet".to_string(),
                        }}
                    </p>
                </div>
                <div class="flex flex-wrap gap-2">
                    {move || latest().is_none().then(|| view! {
                        <button
                            class="px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-gray-900 text-sm font-semibold disabled:opacity-50"
                            disabled=move || busy.get()
                            on:click=move |_| create_or_rotate.with_value(|f| f(false))
                        >"Create key (epoch 1)"</button>
                    })}
                    {move || latest().map(|key| {
                        let key_for_grant = key.clone();
                        view! {
                            <button
                                class="px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-gray-900 text-sm font-semibold disabled:opacity-50"
                                disabled=move || busy.get() || missing().is_empty()
                                on:click=move |_| {
                                    let k = key_for_grant.clone();
                                    grant.with_value(|g| g(k, missing()));
                                }
                            >{move || format!("Grant to members missing it ({})", missing().len())}</button>
                            <button
                                class="px-3 py-1.5 rounded-lg border border-gray-600 text-gray-200 hover:bg-gray-700 text-sm disabled:opacity-50"
                                disabled=move || busy.get()
                                on:click=move |_| create_or_rotate.with_value(|f| f(true))
                            >"Rotate key"</button>
                        }
                    })}
                </div>
            </header>

            {move || status.get().map(|s| view! {
                <p class="text-sm text-amber-300" role="status">{s}</p>
            })}

            <p class="text-xs text-gray-500">
                {move || {
                    let t = targets().len();
                    let s = sent.with(|s| targets().iter().filter(|pk| s.contains(*pk)).count());
                    format!("{s} of {t} eligible members granted from this device (including you).")
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
                                <span class="truncate text-gray-200" title=r.pubkey.clone()>{r.name.clone()}</span>
                                <span class=format!("text-xs {}", label.1)>{label.0}</span>
                            </li>
                        }
                    }).collect_view()
                }}
            </ul>
        </section>
    }
}
