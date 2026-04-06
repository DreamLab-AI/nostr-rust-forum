//! Admin calendar management tab.
//!
//! Lists all calendar events (kind 31923) with RSVP counts, and provides
//! edit (re-publish) and delete (kind 5) actions.

use leptos::prelude::*;
use nostr_core::NostrEvent;
use std::rc::Rc;

use crate::auth::use_auth;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::components::user_display::use_display_name;
use crate::relay::{ConnectionState, Filter, RelayConnection};

/// A calendar event parsed from a kind 31923 Nostr event.
#[derive(Clone, Debug)]
struct CalendarEventEntry {
    id: String,
    d_tag: String,
    title: String,
    description: String,
    start_time: u64,
    end_time: Option<u64>,
    location: String,
    max_attendees: Option<u32>,
    host_pubkey: String,
    rsvp_accepted: u32,
    rsvp_declined: u32,
    rsvp_tentative: u32,
}

/// Admin calendar management view with event listing and delete actions.
#[component]
pub fn AdminCalendar() -> impl IntoView {
    let relay = expect_context::<RelayConnection>();
    let conn_state = relay.connection_state();

    let events = RwSignal::new(Vec::<CalendarEventEntry>::new());
    let loading = RwSignal::new(true);
    let sub_id: RwSignal<Option<String>> = RwSignal::new(None);

    let relay_for_sub = relay.clone();
    let relay_for_cleanup = relay.clone();

    // Subscribe to kind 31923 (calendar events)
    Effect::new(move |_| {
        let state = conn_state.get();
        if state != ConnectionState::Connected {
            return;
        }
        if sub_id.get_untracked().is_some() {
            return;
        }

        loading.set(true);

        let filter = Filter {
            kinds: Some(vec![31923]),
            ..Default::default()
        };

        let evts = events;
        let on_event = Rc::new(move |event: NostrEvent| {
            if event.kind != 31923 {
                return;
            }

            let entry = parse_calendar_event(&event);

            evts.update(|list| {
                // Replace if same d_tag (parameterized replaceable)
                if let Some(pos) = list.iter().position(|e| e.d_tag == entry.d_tag) {
                    list[pos] = entry;
                } else {
                    list.push(entry);
                }
                list.sort_by(|a, b| b.start_time.cmp(&a.start_time));
            });
        });

        let loading_sig = loading;
        let on_eose = Rc::new(move || {
            loading_sig.set(false);
        });

        let id = relay_for_sub.subscribe(vec![filter], on_event, Some(on_eose));
        sub_id.set(Some(id));

        // 8-second timeout: if EOSE never arrives, stop showing the loading state
        let loading_timeout = loading;
        crate::utils::set_timeout_once(
            move || {
                if loading_timeout.get_untracked() {
                    loading_timeout.set(false);
                }
            },
            8_000,
        );

        // Subscribe to kind 31925 (RSVP) events and increment counts
        let evts_for_rsvp = events;
        let on_rsvp_event = Rc::new(move |event: NostrEvent| {
            if event.kind != 31925 {
                return;
            }
            // Find the calendar event this RSVP refers to via "a" tag
            let a_tag = event
                .tags
                .iter()
                .find(|t| t.len() >= 2 && t[0] == "a")
                .map(|t| t[1].clone());
            let status = event
                .tags
                .iter()
                .find(|t| t.len() >= 2 && t[0] == "status")
                .map(|t| t[1].clone())
                .unwrap_or_default();
            // Also check "L" / "l" label tags for status (some clients use content)
            let status = if status.is_empty() {
                event.content.trim().to_lowercase()
            } else {
                status.to_lowercase()
            };

            if let Some(a_ref) = a_tag {
                // a_ref format: "31923:<pubkey>:<d-tag>"
                let d_tag = a_ref.split(':').nth(2).unwrap_or("").to_string();
                if !d_tag.is_empty() {
                    evts_for_rsvp.update(|list| {
                        if let Some(entry) = list.iter_mut().find(|e| e.d_tag == d_tag) {
                            match status.as_str() {
                                "accepted" | "yes" => entry.rsvp_accepted += 1,
                                "declined" | "no" => entry.rsvp_declined += 1,
                                "tentative" | "maybe" => entry.rsvp_tentative += 1,
                                _ => {}
                            }
                        }
                    });
                }
            }
        });

        relay_for_sub.subscribe(
            vec![Filter {
                kinds: Some(vec![31925]),
                ..Default::default()
            }],
            on_rsvp_event,
            None,
        );
    });

    on_cleanup(move || {
        if let Some(id) = sub_id.get_untracked() {
            relay_for_cleanup.unsubscribe(&id);
        }
    });

    view! {
        <div class="space-y-4">
            <div class="flex items-center justify-between">
                <h3 class="text-lg font-semibold text-white flex items-center gap-2">
                    {calendar_icon()}
                    "Calendar Events"
                </h3>
                <span class="text-xs text-gray-500">
                    {move || format!("{} events", events.get().len())}
                </span>
            </div>

            <Show when=move || loading.get()>
                <div class="bg-gray-800 border border-gray-700 rounded-lg p-8 text-center animate-pulse">
                    <p class="text-gray-500">"Loading calendar events..."</p>
                </div>
            </Show>

            <Show when=move || !loading.get()>
                {move || {
                    let ev_list = events.get();
                    if ev_list.is_empty() {
                        view! {
                            <div class="bg-gray-800 border border-gray-700 rounded-lg p-8 text-center">
                                <div class="w-12 h-12 mx-auto mb-3 rounded-full bg-gray-700 flex items-center justify-center">
                                    <svg class="w-6 h-6 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                        <rect x="3" y="4" width="18" height="18" rx="2" stroke-linecap="round" stroke-linejoin="round"/>
                                        <line x1="16" y1="2" x2="16" y2="6" stroke-linecap="round"/>
                                        <line x1="8" y1="2" x2="8" y2="6" stroke-linecap="round"/>
                                        <line x1="3" y1="10" x2="21" y2="10" stroke-linecap="round"/>
                                    </svg>
                                </div>
                                <p class="text-gray-400 font-medium">"No calendar events"</p>
                                <p class="text-gray-500 text-sm mt-1">"Create events from the Events page."</p>
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div class="space-y-3">
                                {ev_list.into_iter().map(|entry| {
                                    let entry_for_delete = entry.clone();
                                    let events_sig = events;
                                    view! {
                                        <AdminEventRow
                                            entry=entry
                                            on_delete=move || {
                                                delete_event(entry_for_delete.clone(), events_sig);
                                            }
                                        />
                                    }
                                }).collect_view()}
                            </div>
                        }.into_any()
                    }
                }}
            </Show>
        </div>
    }
}

/// A single event row in the admin calendar table.
#[component]
fn AdminEventRow<FD>(entry: CalendarEventEntry, on_delete: FD) -> impl IntoView
where
    FD: Fn() + 'static,
{
    let now = (js_sys::Date::now() / 1000.0) as u64;
    let is_past = entry.end_time.unwrap_or(entry.start_time) < now;

    let start_str = format_datetime(entry.start_time);
    let end_str = entry.end_time.map(format_datetime).unwrap_or_default();
    let pk_short = use_display_name(&entry.host_pubkey);
    let _total_rsvp = entry.rsvp_accepted + entry.rsvp_tentative;

    let card_opacity = if is_past { "opacity-60" } else { "" };

    view! {
        <div class=format!("bg-gray-800 border border-gray-700 rounded-lg p-4 hover:border-gray-600 transition-colors {}", card_opacity)>
            <div class="flex items-start justify-between gap-4">
                <div class="flex-1 min-w-0">
                    <h4 class="font-semibold text-white truncate">{entry.title.clone()}</h4>
                    {(!entry.description.is_empty()).then(|| view! {
                        <p class="text-sm text-gray-400 mt-0.5 line-clamp-2">{entry.description.clone()}</p>
                    })}
                    <div class="flex flex-wrap items-center gap-3 mt-2 text-xs text-gray-500">
                        <span class="inline-flex items-center gap-1">
                            <svg class="w-3 h-3 text-amber-500/70" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10"/>
                                <polyline points="12 6 12 12 16 14" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                            {start_str}
                            {(!end_str.is_empty()).then(|| format!(" - {}", end_str))}
                        </span>
                        {(!entry.location.is_empty()).then(|| {
                            let loc = entry.location.clone();
                            view! {
                                <span class="inline-flex items-center gap-1">
                                    <svg class="w-3 h-3 text-amber-500/70" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0118 0z"/>
                                        <circle cx="12" cy="10" r="3"/>
                                    </svg>
                                    {loc}
                                </span>
                            }
                        })}
                        <span class="font-mono">{pk_short}</span>
                    </div>

                    // RSVP stats
                    <div class="flex items-center gap-3 mt-2 text-xs">
                        <span class="text-emerald-400">{format!("{} accepted", entry.rsvp_accepted)}</span>
                        <span class="text-amber-400">{format!("{} tentative", entry.rsvp_tentative)}</span>
                        <span class="text-red-400">{format!("{} declined", entry.rsvp_declined)}</span>
                        {entry.max_attendees.map(|m| view! {
                            <span class="text-gray-500">{format!("(max {})", m)}</span>
                        })}
                    </div>
                </div>

                // Actions
                <div class="flex items-center gap-2 flex-shrink-0">
                    <button
                        on:click=move |_| on_delete()
                        class="text-xs bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 hover:border-red-500/40 rounded px-2.5 py-1 transition-colors"
                        title="Delete event"
                    >
                        "Delete"
                    </button>
                </div>
            </div>
        </div>
    }
}

/// Delete a calendar event by publishing a kind 5 (NIP-09) deletion event.
fn delete_event(entry: CalendarEventEntry, events: RwSignal<Vec<CalendarEventEntry>>) {
    let auth = use_auth();
    let toasts = use_toasts();
    let relay = expect_context::<RelayConnection>();

    let pubkey = match auth.pubkey().get_untracked() {
        Some(pk) => pk,
        None => {
            toasts.show("Not authenticated", ToastVariant::Error);
            return;
        }
    };

    let now = (js_sys::Date::now() / 1000.0) as u64;

    // NIP-09: kind 5 deletion event
    let unsigned = nostr_core::UnsignedEvent {
        pubkey,
        created_at: now,
        kind: 5,
        tags: vec![
            vec!["e".to_string(), entry.id.clone()],
            vec!["a".to_string(), format!("31923:{}:{}", entry.host_pubkey, entry.d_tag)],
        ],
        content: "Deleted calendar event".to_string(),
    };

    let entry_d_tag = entry.d_tag.clone();
    let entry_title = entry.title.clone();
    wasm_bindgen_futures::spawn_local(async move {
        match auth.sign_event_async(unsigned).await {
            Ok(signed) => {
                relay.publish(&signed);
                events.update(|list| list.retain(|e| e.d_tag != entry_d_tag));
                toasts.show(
                    format!("Deleted: {}", entry_title),
                    ToastVariant::Success,
                );
            }
            Err(e) => {
                toasts.show(format!("Failed to delete: {}", e), ToastVariant::Error);
            }
        }
    });
}

/// Parse a kind 31923 event into a CalendarEventEntry.
fn parse_calendar_event(event: &NostrEvent) -> CalendarEventEntry {
    let tag = |name: &str| -> Option<String> {
        event
            .tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == name)
            .map(|t| t[1].clone())
    };

    CalendarEventEntry {
        id: event.id.clone(),
        d_tag: tag("d").unwrap_or_default(),
        title: tag("title").unwrap_or_else(|| "Untitled".into()),
        description: event.content.clone(),
        start_time: tag("start")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        end_time: tag("end").and_then(|s| s.parse().ok()),
        location: tag("location").unwrap_or_default(),
        max_attendees: tag("max_attendees").and_then(|s| s.parse().ok()),
        host_pubkey: event.pubkey.clone(),
        rsvp_accepted: 0,
        rsvp_declined: 0,
        rsvp_tentative: 0,
    }
}

/// Format a UNIX timestamp into a human-readable date/time string.
fn format_datetime(ts: u64) -> String {
    let d = js_sys::Date::new_0();
    d.set_time((ts as f64) * 1000.0);
    format!(
        "{:02}/{:02}/{} {:02}:{:02}",
        d.get_date(),
        d.get_month() + 1,
        d.get_full_year(),
        d.get_hours(),
        d.get_minutes(),
    )
}

fn calendar_icon() -> impl IntoView {
    view! {
        <svg class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="4" width="18" height="18" rx="2"/>
            <line x1="16" y1="2" x2="16" y2="6"/>
            <line x1="8" y1="2" x2="8" y2="6"/>
            <line x1="3" y1="10" x2="21" y2="10"/>
        </svg>
    }
}
