//! Events listing page with relay-driven calendar events, RSVP support,
//! create event modal, and sidebar mini-calendar.

use leptos::prelude::*;
use leptos_router::components::A;
use nostr_core::{NostrEvent, RsvpStatus};
use std::collections::HashMap;
use std::rc::Rc;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::create_event_modal::CreateEventModal;
use crate::components::event_card::EventCard;
use crate::components::mini_calendar::MiniCalendar;
use crate::components::rsvp_buttons::RsvpButtons;
use crate::relay::{ConnectionState, Filter, RelayConnection};

/// Internal representation of a calendar event parsed from a kind 31923 event.
#[derive(Clone, Debug, PartialEq)]
struct CalendarEvent {
    id: String,
    d_tag: String,
    title: String,
    description: String,
    start_time: u64,
    end_time: u64,
    location: String,
    host_pubkey: String,
    max_attendees: Option<u32>,
    featured: bool,
}

/// RSVP data for an event.
#[derive(Clone, Debug, Default)]
struct RsvpData {
    accepted: u32,
    #[allow(dead_code)]
    declined: u32,
    #[allow(dead_code)]
    tentative: u32,
    my_status: Option<RsvpStatus>,
}

/// Events listing page with tab filtering, event cards, and sidebar calendar.
#[component]
pub fn EventsPage() -> impl IntoView {
    let relay = expect_context::<RelayConnection>();
    let conn_state = relay.connection_state();
    let auth = use_auth();
    let my_pubkey = auth.pubkey();

    let events = RwSignal::new(Vec::<CalendarEvent>::new());
    let rsvps: RwSignal<HashMap<String, RsvpData>> = RwSignal::new(HashMap::new());
    let active_tab = RwSignal::new("upcoming".to_string());
    let selected_day = RwSignal::new(Option::<u64>::None);
    let show_create_modal = RwSignal::new(false);
    let loading = RwSignal::new(true);

    let sub_ids: RwSignal<Vec<String>> = RwSignal::new(Vec::new());

    let zone_access = crate::stores::zone_access::use_zone_access();
    let is_admin_or_mod = Memo::new(move |_| zone_access.is_admin.get());

    let now_ts = (js_sys::Date::now() / 1000.0) as u64;

    // Subscribe to kind 31923 and kind 31925 when relay connects
    let relay_for_sub = relay.clone();
    let relay_for_cleanup = relay;
    Effect::new(move |_| {
        let state = conn_state.get();
        if state != ConnectionState::Connected {
            return;
        }
        if !sub_ids.get_untracked().is_empty() {
            return;
        }

        loading.set(true);

        // Calendar events
        let evts = events;
        let on_event = Rc::new(move |event: NostrEvent| {
            if event.kind != 31923 {
                return;
            }
            let parsed = parse_calendar_event(&event);
            evts.update(|list| {
                if let Some(pos) = list.iter().position(|e| e.d_tag == parsed.d_tag) {
                    list[pos] = parsed;
                } else {
                    list.push(parsed);
                }
            });
        });

        let loading_sig = loading;
        let on_eose = Rc::new(move || {
            loading_sig.set(false);
        });

        let sid1 = relay_for_sub.subscribe(
            vec![Filter {
                kinds: Some(vec![31923]),
                ..Default::default()
            }],
            on_event,
            Some(on_eose),
        );

        // RSVPs
        let rsvps_sig = rsvps;
        let my_pk = my_pubkey.get_untracked().unwrap_or_default();
        let on_rsvp = Rc::new(move |event: NostrEvent| {
            if event.kind != 31925 {
                return;
            }

            let event_ref = event
                .tags
                .iter()
                .find(|t| t.len() >= 2 && t[0] == "e")
                .map(|t| t[1].clone())
                .unwrap_or_default();

            if event_ref.is_empty() {
                return;
            }

            let status_str = event
                .tags
                .iter()
                .find(|t| t.len() >= 2 && t[0] == "status")
                .map(|t| t[1].as_str())
                .unwrap_or("");

            let status = match status_str {
                "accepted" => Some(RsvpStatus::Accept),
                "declined" => Some(RsvpStatus::Decline),
                "tentative" => Some(RsvpStatus::Tentative),
                _ => None,
            };

            let Some(status) = status else { return };
            let is_me = event.pubkey == my_pk;

            rsvps_sig.update(|map| {
                let data = map.entry(event_ref).or_default();
                match status {
                    RsvpStatus::Accept => data.accepted += 1,
                    RsvpStatus::Decline => data.declined += 1,
                    RsvpStatus::Tentative => data.tentative += 1,
                }
                if is_me {
                    data.my_status = Some(status);
                }
            });
        });

        let sid2 = relay_for_sub.subscribe(
            vec![Filter {
                kinds: Some(vec![31925]),
                ..Default::default()
            }],
            on_rsvp,
            None,
        );

        sub_ids.set(vec![sid1, sid2]);
    });

    on_cleanup(move || {
        for id in sub_ids.get_untracked() {
            relay_for_cleanup.unsubscribe(&id);
        }
    });

    // Filtered events based on active tab + optional day filter
    let filtered = Memo::new(move |_| {
        let tab = active_tab.get();
        let now = now_ts;
        let sel = selected_day.get();

        let mut list: Vec<CalendarEvent> = events
            .get()
            .into_iter()
            .filter(|e| {
                let time_match = match tab.as_str() {
                    "upcoming" => e.end_time >= now,
                    "past" => e.end_time < now,
                    "rsvps" => {
                        let r = rsvps.get();
                        r.get(&e.id)
                            .map(|d| d.my_status.is_some())
                            .unwrap_or(false)
                    }
                    _ => true,
                };

                let day_match = sel
                    .map(|day_ts| e.start_time >= day_ts && e.start_time < day_ts + 86400)
                    .unwrap_or(true);

                time_match && day_match
            })
            .collect();

        if tab == "past" {
            list.sort_by_key(|e| std::cmp::Reverse(e.start_time));
        } else {
            list.sort_by_key(|e| e.start_time);
        }
        list
    });

    // Event days for the mini calendar
    let event_days = Signal::derive(move || {
        let evts = events.get();
        let now = now_ts;
        let d = js_sys::Date::new_0();
        let current_month = d.get_month();
        let current_year = d.get_full_year();

        evts.iter()
            .filter(|e| e.end_time >= now)
            .filter_map(|e| {
                let ed = js_sys::Date::new_0();
                ed.set_time((e.start_time as f64) * 1000.0);
                let m = ed.get_month();
                let y = ed.get_full_year();
                if y == current_year && m == current_month {
                    Some(ed.get_date())
                } else {
                    None
                }
            })
            .collect::<Vec<u32>>()
    });

    let on_calendar_select = Callback::new(move |ts: u64| {
        let current = selected_day.get_untracked();
        if current == Some(ts) {
            selected_day.set(None);
        } else {
            selected_day.set(Some(ts));
        }
    });

    let on_clear_filter = move |_| {
        selected_day.set(None);
    };

    let on_event_created = Callback::new(move |_id: String| {
        // Event will appear via relay subscription automatically
    });

    let tab_class = move |tab: &'static str| {
        move || {
            if active_tab.get() == tab {
                "px-4 py-2 rounded-lg text-sm font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30 transition-colors"
            } else {
                "px-4 py-2 rounded-lg text-sm font-medium text-gray-400 hover:text-white hover:bg-gray-800 border border-transparent transition-colors"
            }
        }
    };

    view! {
        <div class="mesh-bg min-h-[80vh] relative overflow-hidden">
            <div class="ambient-orb ambient-orb-1" aria-hidden="true"></div>
            <div class="ambient-orb ambient-orb-2" aria-hidden="true"></div>

            <div class="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8 relative z-10">
                // Breadcrumb
                <nav class="breadcrumb-nav mb-6">
                    <A href=base_href("/") attr:class="hover:text-amber-400 transition-colors">"Home"</A>
                    <span class="breadcrumb-separator">"/"</span>
                    <span class="text-gray-400">"Events"</span>
                </nav>

                // Hero heading
                <div class="text-center mb-8">
                    <div class="relative inline-block">
                        <div class="absolute -z-10 w-64 h-64 rounded-full bg-amber-500/10 blur-3xl animate-ambient-breathe left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2"></div>
                        <h1 class="text-4xl sm:text-5xl font-bold candy-gradient mb-3">
                            "Events"
                        </h1>
                    </div>
                    <p class="text-gray-400 text-lg">
                        "Workshops, meetups, and community gatherings"
                    </p>
                </div>

                // Main layout: content + sidebar
                <div class="flex flex-col lg:flex-row gap-8">
                    // Left: event list
                    <div class="flex-1 max-w-[800px]">
                        // Tab pills + create button
                        <div class="flex items-center justify-between mb-6 flex-wrap gap-3">
                            <div class="flex gap-2">
                                <button
                                    class=tab_class("upcoming")
                                    on:click=move |_| {
                                        active_tab.set("upcoming".to_string());
                                        selected_day.set(None);
                                    }
                                >
                                    "Upcoming"
                                </button>
                                <button
                                    class=tab_class("past")
                                    on:click=move |_| {
                                        active_tab.set("past".to_string());
                                        selected_day.set(None);
                                    }
                                >
                                    "Past"
                                </button>
                                <button
                                    class=tab_class("rsvps")
                                    on:click=move |_| {
                                        active_tab.set("rsvps".to_string());
                                        selected_day.set(None);
                                    }
                                >
                                    "My RSVPs"
                                </button>
                                <button
                                    class=tab_class("birthdays")
                                    on:click=move |_| {
                                        active_tab.set("birthdays".to_string());
                                        selected_day.set(None);
                                    }
                                >
                                    "Birthdays"
                                </button>
                            </div>

                            <Show when=move || is_admin_or_mod.get()>
                                <button
                                    class="inline-flex items-center gap-1.5 bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-4 py-2 rounded-lg text-sm transition-colors"
                                    on:click=move |_| show_create_modal.set(true)
                                >
                                    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <line x1="12" y1="5" x2="12" y2="19" stroke-linecap="round"/>
                                        <line x1="5" y1="12" x2="19" y2="12" stroke-linecap="round"/>
                                    </svg>
                                    "Create Event"
                                </button>
                            </Show>
                        </div>

                        // Day filter indicator
                        <Show when=move || selected_day.get().is_some()>
                            <div class="flex items-center gap-2 mb-4 text-sm text-gray-400">
                                <span>"Filtered by day"</span>
                                <button
                                    class="text-amber-400 hover:text-amber-300 underline text-xs"
                                    on:click=on_clear_filter
                                >
                                    "Clear filter"
                                </button>
                            </div>
                        </Show>

                        // Birthdays tab
                        <Show when=move || active_tab.get() == "birthdays">
                            <BirthdayList />
                        </Show>

                        // Loading state
                        <Show when=move || active_tab.get() != "birthdays" && loading.get()>
                            <div class="space-y-4">
                                <div class="glass-card p-6 animate-pulse">
                                    <div class="h-4 bg-gray-700 rounded w-1/3 mb-3"></div>
                                    <div class="h-3 bg-gray-700 rounded w-2/3 mb-2"></div>
                                    <div class="h-3 bg-gray-700 rounded w-1/2"></div>
                                </div>
                            </div>
                        </Show>

                        // Event cards or empty state
                        <Show when=move || active_tab.get() != "birthdays" && !loading.get()>
                            <div class="space-y-4 fade-in">
                                {move || {
                                    let list = filtered.get();
                                    if list.is_empty() {
                                        view! {
                                            <div class="glass-card p-8 text-center">
                                                <div class="animate-gentle-float inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gray-800/60 border border-gray-700/50 text-gray-400 mb-4">
                                                    <svg class="w-7 h-7" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                                        <rect x="3" y="4" width="18" height="18" rx="2" ry="2" stroke-linecap="round" stroke-linejoin="round"/>
                                                        <line x1="16" y1="2" x2="16" y2="6" stroke-linecap="round"/>
                                                        <line x1="8" y1="2" x2="8" y2="6" stroke-linecap="round"/>
                                                        <line x1="3" y1="10" x2="21" y2="10" stroke-linecap="round"/>
                                                    </svg>
                                                </div>
                                                <h3 class="text-lg font-bold text-white mb-2">
                                                    {move || match active_tab.get().as_str() {
                                                        "upcoming" => "No upcoming events",
                                                        "past" => "No past events",
                                                        "rsvps" => "No RSVPs yet",
                                                        _ => "No events",
                                                    }}
                                                </h3>
                                                <p class="text-sm text-gray-400">
                                                    {move || match active_tab.get().as_str() {
                                                        "upcoming" => "Check back soon or create one yourself!",
                                                        "rsvps" => "RSVP to events and they will appear here.",
                                                        _ => "Events you attend will appear here.",
                                                    }}
                                                </p>
                                            </div>
                                        }.into_any()
                                    } else {
                                        list.into_iter().map(|evt| {
                                            let eid = evt.id.clone();
                                            let eid_rsvp = evt.id.clone();
                                            let max = evt.max_attendees;
                                            let rsvps_sig = rsvps;

                                            let current_rsvp = Signal::derive(move || {
                                                rsvps_sig.get().get(&eid_rsvp).and_then(|d| d.my_status)
                                            });

                                            let attendee_count = Signal::derive({
                                                let eid2 = eid.clone();
                                                move || {
                                                    rsvps_sig.get().get(&eid2).map(|d| d.accepted).unwrap_or(0)
                                                }
                                            });

                                            view! {
                                                <div>
                                                    <EventCard
                                                        title=evt.title
                                                        description=evt.description
                                                        start_time=evt.start_time
                                                        end_time=evt.end_time
                                                        location=evt.location
                                                        host_pubkey=evt.host_pubkey
                                                        featured=evt.featured
                                                    />
                                                    <div class="mt-2 ml-[72px]">
                                                        <RsvpButtons
                                                            event_id=eid
                                                            current_status=current_rsvp
                                                            attendee_count=attendee_count
                                                            max_attendees=max
                                                        />
                                                    </div>
                                                </div>
                                            }
                                        }).collect_view().into_any()
                                    }
                                }}
                            </div>
                        </Show>
                    </div>

                    // Right sidebar: mini calendar
                    <aside class="hidden lg:block flex-shrink-0">
                        <div class="sticky top-24">
                            <MiniCalendar
                                event_days=event_days
                                on_select=on_calendar_select
                            />
                        </div>
                    </aside>
                </div>
            </div>

            // Create Event Modal
            <Show when=move || show_create_modal.get()>
                <CreateEventModal
                    on_close=Callback::new(move |()| show_create_modal.set(false))
                    on_created=on_event_created
                />
            </Show>
        </div>
    }
}

// -- Birthday list component --------------------------------------------------

/// A birthday entry derived from user profile metadata (kind 0).
#[derive(Clone, Debug)]
struct BirthdayEntry {
    name: String,
    month: u32,
    day: u32,
}

/// Format month/day as "Mar 15".
fn format_birthday_date(month: u32, day: u32) -> String {
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let m = months.get((month.saturating_sub(1)) as usize).unwrap_or(&"???");
    format!("{} {}", m, day)
}

/// Birthday list sub-component.
///
/// Subscribes to kind 0 (profile metadata) events from the relay and parses
/// the `birthday` field (format: "MM-DD" or "YYYY-MM-DD") from each profile's
/// metadata JSON. Displays upcoming birthdays sorted by proximity to today.
#[component]
fn BirthdayList() -> impl IntoView {
    let relay = expect_context::<RelayConnection>();
    let conn_state = relay.connection_state();

    let birthdays = RwSignal::new(Vec::<BirthdayEntry>::new());
    let loading = RwSignal::new(true);
    let sub_id: RwSignal<Option<String>> = RwSignal::new(None);

    let relay_for_sub = relay.clone();
    let relay_for_cleanup = relay;

    // Subscribe to kind 0 profiles to extract birthday metadata
    Effect::new(move |_| {
        let state = conn_state.get();
        if state != ConnectionState::Connected {
            return;
        }
        if sub_id.get_untracked().is_some() {
            return;
        }

        let filter = Filter {
            kinds: Some(vec![0]),
            ..Default::default()
        };

        let bdays = birthdays;
        let on_event = Rc::new(move |event: NostrEvent| {
            if event.kind != 0 {
                return;
            }
            // Parse metadata JSON to extract name + birthday
            if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&event.content) {
                let birthday_str = meta.get("birthday")
                    .or_else(|| meta.get("bday"))
                    .and_then(|v| v.as_str());

                if let Some(bday) = birthday_str {
                    // Parse "MM-DD" or "YYYY-MM-DD"
                    let parts: Vec<&str> = bday.split('-').collect();
                    let (month, day) = if parts.len() == 3 {
                        // YYYY-MM-DD
                        (parts[1].parse::<u32>().unwrap_or(0), parts[2].parse::<u32>().unwrap_or(0))
                    } else if parts.len() == 2 {
                        // MM-DD
                        (parts[0].parse::<u32>().unwrap_or(0), parts[1].parse::<u32>().unwrap_or(0))
                    } else {
                        (0, 0)
                    };

                    if month >= 1 && month <= 12 && day >= 1 && day <= 31 {
                        let name = meta.get("display_name")
                            .or_else(|| meta.get("name"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let name = if name.is_empty() {
                            crate::components::user_display::use_display_name(&event.pubkey)
                        } else {
                            name
                        };

                        bdays.update(|list| {
                            // Deduplicate by pubkey — keep latest profile
                            list.retain(|b| b.name != name);
                            list.push(BirthdayEntry { name, month, day });
                        });
                    }
                }
            }
        });

        let loading_sig = loading;
        let on_eose = Rc::new(move || {
            loading_sig.set(false);
        });

        let id = relay_for_sub.subscribe(vec![filter], on_event, Some(on_eose));
        sub_id.set(Some(id));

        // Timeout fallback
        crate::utils::set_timeout_once(
            move || {
                if loading_sig.get_untracked() {
                    loading_sig.set(false);
                }
            },
            8_000,
        );
    });

    on_cleanup(move || {
        if let Some(id) = sub_id.get_untracked() {
            relay_for_cleanup.unsubscribe(&id);
        }
    });

    view! {
        <Show when=move || loading.get()>
            <div class="glass-card p-8 text-center animate-pulse">
                <p class="text-gray-500">"Loading birthdays..."</p>
            </div>
        </Show>

        <Show when=move || !loading.get()>
            {move || {
                let mut sorted = birthdays.get();
                let now_date = js_sys::Date::new_0();
                let cur_month = now_date.get_month() + 1;
                let cur_day = now_date.get_date();

                sorted.sort_by(|a, b| {
                    let a_up = if a.month > cur_month || (a.month == cur_month && a.day >= cur_day) { 0u8 } else { 1 };
                    let b_up = if b.month > cur_month || (b.month == cur_month && b.day >= cur_day) { 0u8 } else { 1 };
                    a_up.cmp(&b_up)
                        .then_with(|| a.month.cmp(&b.month))
                        .then_with(|| a.day.cmp(&b.day))
                });

                if sorted.is_empty() {
                    view! {
                        <div class="glass-card p-8 text-center">
                            <h3 class="text-lg font-bold text-white mb-2">"No birthdays yet"</h3>
                            <p class="text-sm text-gray-400">"Set your birthday in Settings to appear here."</p>
                        </div>
                    }.into_any()
                } else {
                    view! {
                        <div class="space-y-2 fade-in">
                            <p class="text-sm text-gray-400 mb-3">"Upcoming community birthdays"</p>
                            {sorted.into_iter().map(|b| {
                                let is_today = b.month == cur_month && b.day == cur_day;
                                let date_str = format_birthday_date(b.month, b.day);
                                view! {
                                    <div class=if is_today {
                                        "glass-card p-4 flex items-center gap-3 border-amber-500/30 bg-amber-500/5"
                                    } else {
                                        "glass-card p-4 flex items-center gap-3"
                                    }>
                                        <div class="w-10 h-10 rounded-full bg-pink-500/20 flex items-center justify-center flex-shrink-0">
                                            <svg class="w-5 h-5 text-pink-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                                <path d="M2 21h20M4 21V10a1 1 0 011-1h14a1 1 0 011 1v11M12 3v3M8 6h8a2 2 0 012 2H6a2 2 0 012-2z" stroke-linecap="round" stroke-linejoin="round"/>
                                                <path d="M12 3a1 1 0 100-2 1 1 0 000 2z" fill="currentColor"/>
                                            </svg>
                                        </div>
                                        <div class="flex-1 min-w-0">
                                            <span class="font-medium text-white">{b.name}</span>
                                            {is_today.then(|| view! {
                                                <span class="ml-2 text-xs bg-amber-500/20 text-amber-400 rounded-full px-2 py-0.5">"Today!"</span>
                                            })}
                                        </div>
                                        <span class="text-sm text-gray-400 flex-shrink-0">{date_str}</span>
                                    </div>
                                }
                            }).collect_view()}
                        </div>
                    }.into_any()
                }
            }}
        </Show>
    }
}

/// Parse a kind 31923 event into a CalendarEvent.
///
/// Supports two layouts:
/// 1. Tags-based: title/location in event tags, description in plain-text content.
/// 2. JSON content: NIP-52 allows `content` to be a JSON object with `name`,
///    `description`, `location` fields (common in some clients).
fn parse_calendar_event(event: &NostrEvent) -> CalendarEvent {
    let tag = |name: &str| -> Option<String> {
        event
            .tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == name)
            .map(|t| t[1].clone())
    };

    let start = tag("start")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    let end = tag("end")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(start + 3600);

    // Try parsing content as JSON for name/description/location fallback
    let content_json: Option<serde_json::Value> =
        serde_json::from_str(&event.content).ok();

    let json_str = |field: &str| -> Option<String> {
        content_json
            .as_ref()
            .and_then(|v| v.get(field))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };

    let title = tag("title")
        .or_else(|| json_str("name"))
        .unwrap_or_else(|| "Untitled".into());

    let description = json_str("description").unwrap_or_else(|| {
        // If content is not JSON, use it as plain text description
        if content_json.is_none() {
            event.content.clone()
        } else {
            String::new()
        }
    });

    let location = tag("location")
        .or_else(|| json_str("location"))
        .unwrap_or_default();

    CalendarEvent {
        id: event.id.clone(),
        d_tag: tag("d").unwrap_or_default(),
        title,
        description,
        start_time: start,
        end_time: end,
        location,
        host_pubkey: event.pubkey.clone(),
        max_attendees: tag("max_attendees").and_then(|s| s.parse().ok()),
        featured: false,
    }
}
