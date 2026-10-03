//! Schedule a poker game: a NIP-52 calendar event (kind 31923) tagged
//! `poker`, with the invited members as `p` participants, a `chain` tag
//! naming the chain whose asset table it is played at (ADR-2021), and a
//! direct message to each of them with the time and that table's link.
//! Where more than one asset table is offered the organiser picks the chain;
//! the table open when the modal was opened is chosen first.
//!
//! The event goes to the relay like any other calendar event (the relay
//! admits calendar events from admins and moderators, ADR-022); the invites
//! are ordinary NIP-17 DMs from the organiser, so they reach members whether
//! or not they look at the events page.

use leptos::prelude::*;

use crate::auth::use_auth;
use crate::components::mention_autocomplete::{
    local_candidates, merge_candidates, search_profiles, MentionCandidate,
};
use crate::components::modal::Modal;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::dm::use_dm_store;
use crate::poker::{AssetTable, Stake};
use crate::relay::RelayConnection;

/// The modal.
#[component]
pub fn ScheduleGameModal(
    /// The tables on offer, for the stakes picker.
    stakes: Vec<Stake>,
    /// The asset tables on offer, for the chain picker; empty where only the
    /// practice table runs.
    tables: Vec<AssetTable>,
    /// The chain whose table was open, chosen first.
    chosen: Option<&'static str>,
    /// Called when the modal should close.
    on_close: Callback<()>,
) -> impl IntoView {
    let is_open = RwSignal::new(true);
    let title = RwSignal::new("Poker night".to_string());
    let date = RwSignal::new(String::new());
    let time = RwSignal::new("20:00".to_string());
    let minutes = RwSignal::new("120".to_string());
    let stake_bb = RwSignal::new(stakes.first().map(|s| s.bb).unwrap_or(20));
    let note = RwSignal::new(String::new());
    let query = RwSignal::new(String::new());
    let candidates: RwSignal<Vec<MentionCandidate>> = RwSignal::new(Vec::new());
    let invited: RwSignal<Vec<MentionCandidate>> = RwSignal::new(Vec::new());
    let error_msg: RwSignal<Option<String>> = RwSignal::new(None);
    let submitting = RwSignal::new(false);
    let stakes = StoredValue::new(stakes);
    let several = tables.len() > 1;
    let chain: RwSignal<Option<&'static str>> = RwSignal::new(
        chosen
            .filter(|id| tables.iter().any(|t| t.profile.id == *id))
            .or_else(|| tables.first().map(|t| t.profile.id)),
    );
    let tables = StoredValue::new(tables);
    // the chosen table's ticker; chips where no asset table runs
    let unit = move || -> &'static str {
        let id = chain.get();
        tables
            .with_value(|l| {
                l.iter()
                    .find(|t| Some(t.profile.id) == id)
                    .map(|t| t.profile.ticker.as_str())
            })
            .unwrap_or("chips")
    };

    let toasts = use_toasts();
    let auth = use_auth();
    let relay = expect_context::<RelayConnection>();
    let dm_store = use_dm_store();

    // Search as the organiser types; the relay's roster for an empty query.
    Effect::new(move |_| {
        let q = query.get().trim().to_string();
        wasm_bindgen_futures::spawn_local(async move {
            let network = search_profiles(&q, 8).await;
            let local = local_candidates(&q, 8);
            let me = auth.pubkey().get_untracked().unwrap_or_default();
            let chosen: Vec<String> = invited
                .get_untracked()
                .iter()
                .map(|c| c.pubkey.clone())
                .collect();
            let list: Vec<MentionCandidate> = merge_candidates(network, local, 8)
                .into_iter()
                .filter(|c| c.pubkey != me && !chosen.contains(&c.pubkey))
                .collect();
            candidates.set(list);
        });
    });

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        error_msg.set(None);
        let t = title.get_untracked().trim().to_string();
        if t.is_empty() {
            error_msg.set(Some("Give the game a title.".into()));
            return;
        }
        let (d, tm) = (date.get_untracked(), time.get_untracked());
        let Some(start) = parse_datetime(&d, &tm) else {
            error_msg.set(Some("Pick a date and a time.".into()));
            return;
        };
        let mins: u64 = minutes
            .get_untracked()
            .trim()
            .parse()
            .unwrap_or(120)
            .clamp(15, 24 * 60);
        let end = start + mins * 60;
        let bb = stake_bb.get_untracked();
        let on_chain = chain.get_untracked();
        let unit = untrack(unit);
        let stake = stakes.with_value(|s| s.iter().find(|s| s.bb == bb).copied());
        let stakes_line = stake
            .map(|s| {
                format!(
                    "Stakes {}/{} {unit}, buy-in {} {unit} per hand.",
                    s.sb, s.bb, s.buyin
                )
            })
            .unwrap_or_default();
        let note_text = note.get_untracked().trim().to_string();
        let description = if note_text.is_empty() {
            stakes_line.clone()
        } else {
            format!("{note_text}\n\n{stakes_line}")
        };
        let players = invited.get_untracked();
        let Some(signer) = auth.get_signer() else {
            error_msg.set(Some(
                "Your session has no signing key; sign in again.".into(),
            ));
            return;
        };
        let Some(me) = auth.pubkey().get_untracked() else {
            return;
        };
        submitting.set(true);
        let relay = relay.clone();
        let table_link = table_url(on_chain);
        let when = when_text(start);
        wasm_bindgen_futures::spawn_local(async move {
            let spec = nostr_bbs_core::CalendarEventSpec {
                title: t.clone(),
                start,
                end: Some(end),
                location: Some(format!("Community poker table — {table_link}")),
                description: Some(description),
                max_attendees: None,
                participants: players
                    .iter()
                    .map(|p| (p.pubkey.clone(), "player".to_string()))
                    .collect(),
                hashtags: vec!["poker".to_string()],
                extra_tags: on_chain
                    .map(|id| vec![("chain".to_string(), id.to_string())])
                    .unwrap_or_default(),
            };
            let event =
                match nostr_bbs_core::create_calendar_event_signer_spec(signer.as_ref(), &spec)
                    .await
                {
                    Ok(e) => e,
                    Err(e) => {
                        error_msg.set(Some(format!("Could not create the event: {e}")));
                        submitting.set(false);
                        return;
                    }
                };
            let toasts_ok = toasts;
            let on_ok = std::rc::Rc::new(move |accepted: bool, msg: String| {
                if accepted {
                    toasts_ok.show("Game scheduled", ToastVariant::Success);
                } else if msg.contains("whitelist") || msg.contains("admin") {
                    toasts_ok.show(
                        "The relay only takes calendar events from admins and moderators.",
                        ToastVariant::Error,
                    );
                } else {
                    toasts_ok.show(format!("Event rejected: {msg}"), ToastVariant::Error);
                }
            });
            if let Err(e) = relay.publish_with_ack(&event, Some(on_ok)) {
                error_msg.set(Some(format!("Could not send the event: {e}")));
                submitting.set(false);
                return;
            }
            // the invitations: one DM each
            let mut sent = 0usize;
            for p in &players {
                let text = format!(
                    "You're invited to {t} — {when}. {stakes_line} Open the forum's Table page at the time to sit: {table_link}"
                );
                if dm_store
                    .send_message(&relay, &p.pubkey, &text, signer.clone(), &me)
                    .is_ok()
                {
                    sent += 1;
                }
            }
            if sent > 0 {
                toasts.show(
                    format!("{sent} invitation{} sent", if sent == 1 { "" } else { "s" }),
                    ToastVariant::Success,
                );
            }
            submitting.set(false);
            on_close.run(());
        });
    };

    let on_modal_close = Callback::new(move |()| on_close.run(()));

    view! {
        <Modal
            is_open=is_open
            title="Schedule a poker game".to_string()
            max_width="560px".to_string()
            on_close=on_modal_close
        >
            <div>
                {move || error_msg.get().map(|msg| view! {
                    <div class="mb-4 bg-red-900/40 border border-red-700/50 rounded-lg px-3 py-2 text-sm text-red-300">{msg}</div>
                })}
                <form on:submit=on_submit class="space-y-4">
                    <label class="block text-sm text-gray-300">
                        "Title"
                        <input
                            type="text"
                            class="mt-1 w-full bg-gray-800 border border-gray-600 focus:border-amber-500 rounded-lg px-3 py-2 text-white text-sm focus:outline-none"
                            prop:value=move || title.get()
                            on:input=move |ev| title.set(event_target_value(&ev))
                        />
                    </label>
                    <div class="grid grid-cols-3 gap-3">
                        <label class="block text-sm text-gray-300">
                            "Date"
                            <input type="date" class="mt-1 w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm" prop:value=move || date.get() on:input=move |ev| date.set(event_target_value(&ev)) />
                        </label>
                        <label class="block text-sm text-gray-300">
                            "Time"
                            <input type="time" class="mt-1 w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm" prop:value=move || time.get() on:input=move |ev| time.set(event_target_value(&ev)) />
                        </label>
                        <label class="block text-sm text-gray-300">
                            "Minutes"
                            <input type="number" min="15" max="1440" class="mt-1 w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm" prop:value=move || minutes.get() on:input=move |ev| minutes.set(event_target_value(&ev)) />
                        </label>
                    </div>
                    {several.then(|| view! {
                        <label class="block text-sm text-gray-300">
                            "Table"
                            <select
                                class="mt-1 w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm"
                                on:change=move |ev| {
                                    let v = event_target_value(&ev);
                                    let id = tables.with_value(|l| l.iter().find(|t| t.profile.id == v).map(|t| t.profile.id));
                                    if id.is_some() {
                                        chain.set(id);
                                    }
                                }
                            >
                                {tables.with_value(|list| list.iter().map(|t| {
                                    let id = t.profile.id;
                                    view! { <option value=id selected=move || chain.get() == Some(id)>{format!("{} — {}", t.title(), id)}</option> }
                                }).collect_view())}
                            </select>
                        </label>
                    })}
                    <label class="block text-sm text-gray-300">
                        "Stakes"
                        <select
                            class="mt-1 w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm"
                            on:change=move |ev| {
                                if let Ok(bb) = event_target_value(&ev).parse::<u64>() {
                                    stake_bb.set(bb);
                                }
                            }
                        >
                            {stakes.with_value(|list| list.iter().map(|s| {
                                let (sb, bb, buyin) = (s.sb, s.bb, s.buyin);
                                let label = move || format!("{sb}/{bb} {} — buy-in {buyin}", unit());
                                view! { <option value=bb.to_string() selected=move || stake_bb.get() == bb>{label}</option> }
                            }).collect_view())}
                        </select>
                    </label>
                    <div class="block text-sm text-gray-300">
                        "Invite players"
                        <div class="mt-1 flex flex-wrap gap-1">
                            <For each=move || invited.get() key=|c| c.pubkey.clone() let:c>
                                {
                                    let pk = c.pubkey.clone();
                                    view! {
                                        <span class="inline-flex items-center gap-1 px-2 py-1 rounded-full bg-amber-500/20 text-amber-200 text-xs">
                                            {c.handle()}
                                            <button type="button" class="hover:text-white" aria-label="Remove" on:click=move |_| invited.update(|l| l.retain(|x| x.pubkey != pk))>"×"</button>
                                        </span>
                                    }
                                }
                            </For>
                        </div>
                        <input
                            type="text"
                            placeholder="Type a name…"
                            class="mt-1 w-full bg-gray-800 border border-gray-600 focus:border-amber-500 rounded-lg px-3 py-2 text-white text-sm focus:outline-none"
                            prop:value=move || query.get()
                            on:input=move |ev| query.set(event_target_value(&ev))
                        />
                        <ul class="mt-1 max-h-40 overflow-y-auto divide-y divide-gray-800 rounded-lg bg-gray-900/60">
                            <For each=move || candidates.get() key=|c| c.pubkey.clone() let:c>
                                {
                                    let pick = c.clone();
                                    view! {
                                        <li>
                                            <button
                                                type="button"
                                                class="w-full text-left px-3 py-2 text-xs text-gray-200 hover:bg-gray-800/60"
                                                on:click=move |_| {
                                                    let p = pick.clone();
                                                    invited.update(|l| if !l.iter().any(|x| x.pubkey == p.pubkey) { l.push(p) });
                                                    query.set(String::new());
                                                }
                                            >
                                                {c.handle()}
                                                {c.nip05.clone().filter(|n| !n.is_empty()).map(|n| view! { <span class="ml-2 text-gray-500">"@"{n}</span> })}
                                            </button>
                                        </li>
                                    }
                                }
                            </For>
                        </ul>
                    </div>
                    <label class="block text-sm text-gray-300">
                        "Note"
                        <textarea
                            class="mt-1 w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm"
                            rows="2"
                            prop:value=move || note.get()
                            on:input=move |ev| note.set(event_target_value(&ev))
                        ></textarea>
                    </label>
                    <div class="flex justify-end gap-2">
                        <button type="button" class="px-4 py-2 rounded-lg text-sm bg-gray-700 hover:bg-gray-600 text-gray-100" on:click=move |_| on_close.run(())>"Cancel"</button>
                        <button
                            type="submit"
                            class="px-4 py-2 rounded-lg text-sm font-semibold bg-amber-500 hover:bg-amber-400 text-gray-900 disabled:opacity-50"
                            prop:disabled=move || submitting.get()
                        >
                            {move || if submitting.get() { "Scheduling…" } else { "Schedule and invite" }}
                        </button>
                    </div>
                </form>
            </div>
        </Modal>
    }
}

/// `YYYY-MM-DD` + `HH:MM` in the browser's zone, as unix seconds.
fn parse_datetime(date: &str, time: &str) -> Option<u64> {
    if date.is_empty() || time.is_empty() {
        return None;
    }
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_str(&format!(
        "{date}T{time}:00"
    )));
    let ts = d.get_time();
    if ts.is_nan() {
        None
    } else {
        Some((ts / 1000.0) as u64)
    }
}

/// The table's absolute URL, for an invitation: the chosen chain's section
/// when the game is played at an asset table.
fn table_url(chain: Option<&str>) -> String {
    let origin = web_sys::window()
        .and_then(|w| w.location().origin().ok())
        .unwrap_or_default();
    let fragment = chain
        .map(|id| format!("#{}", crate::wallet::profile::anchor_of(id)))
        .unwrap_or_default();
    format!("{origin}{}{fragment}", crate::app::base_href("/table"))
}

/// A time in words for an invitation, in the browser's locale.
fn when_text(ts: u64) -> String {
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(ts as f64 * 1000.0));
    d.to_locale_string("en-GB", &wasm_bindgen::JsValue::UNDEFINED)
        .as_string()
        .unwrap_or_default()
}
