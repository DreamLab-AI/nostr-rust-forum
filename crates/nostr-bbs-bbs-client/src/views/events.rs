//! Community Events & Calendar (NIP-52 kinds 31923 & 31925).
//!
//! Renders upcoming & past events, redacted free/busy blocks (`["busy","1"]`),
//! live per-user deduped RSVPs (Accept / Tentative / Decline), poker game deep
//! links (`#/games/poker/<chain>`), and an admin Create Event form.

use std::collections::HashMap;
use std::rc::Rc;

use leptos::prelude::*;
use nostr_bbs_client_core::auth::use_auth;
use nostr_bbs_client_core::relay::{Filter, RelayConnection};
use nostr_bbs_client_core::stores::zone_access::use_zone_access;
use nostr_bbs_client_core::toast::{use_toasts, ToastVariant};
use nostr_bbs_core::calendar::{KIND_CALENDAR_EVENT, KIND_CALENDAR_RSVP};
use nostr_bbs_core::event::{NostrEvent, UnsignedEvent};

use crate::components::{AuthorChip, EmptyCard, MarkdownBody};
use crate::router::{use_router, Route};

#[derive(Clone, Debug)]
struct CalEvent {
    d_tag: String,
    title: String,
    description: String,
    start: u64,
    location: String,
    host: String,
    is_busy: bool,
    venue: String,
    poker: bool,
    chain: Option<String>,
}

fn tag_val<'a>(ev: &'a NostrEvent, key: &str) -> Option<&'a str> {
    ev.tags
        .iter()
        .find(|t| t.first().map(String::as_str) == Some(key))
        .and_then(|t| t.get(1))
        .map(String::as_str)
}

fn parse_event(ev: &NostrEvent) -> Option<CalEvent> {
    if ev.kind != KIND_CALENDAR_EVENT {
        return None;
    }
    let d_tag = tag_val(ev, "d")?.to_string();
    let start: u64 = tag_val(ev, "start")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let is_busy = tag_val(ev, "busy") == Some("1");
    let poker = ev.tags.iter().any(|t| {
        t.first().map(String::as_str) == Some("t") && t.get(1).map(String::as_str) == Some("poker")
    });
    Some(CalEvent {
        d_tag,
        title: tag_val(ev, "title").unwrap_or("Untitled Event").to_string(),
        description: ev.content.clone(),
        start,
        location: tag_val(ev, "location").unwrap_or("").to_string(),
        host: ev.pubkey.clone(),
        is_busy,
        venue: tag_val(ev, "venue").unwrap_or("").to_string(),
        poker,
        chain: tag_val(ev, "chain").map(str::to_string),
    })
}

fn fmt_ts(ts: u64) -> String {
    if ts == 0 {
        return "TBD".into();
    }
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64((ts as f64) * 1000.0));
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        d.get_full_year(),
        d.get_month() + 1,
        d.get_date(),
        d.get_hours(),
        d.get_minutes()
    )
}

/// Calendar & Events view (`#/events`).
#[component]
pub fn EventsView() -> impl IntoView {
    let router = use_router();
    let relay = expect_context::<RelayConnection>();
    let auth = use_auth();
    let zone_access = use_zone_access();
    let toasts = use_toasts();

    let events = RwSignal::new(HashMap::<String, CalEvent>::new());
    // event_coord ("31923:<host>:<d>") -> (user_pubkey -> status)
    let rsvps = RwSignal::new(HashMap::<String, HashMap<String, String>>::new());
    let tab = RwSignal::new("upcoming"); // "upcoming" | "past"
    let show_create = RwSignal::new(false);
    let new_title = RwSignal::new(String::new());
    let new_loc = RwSignal::new(String::new());
    let new_desc = RwSignal::new(String::new());
    let new_hours_from_now = RwSignal::new("24".to_string());

    let relay_sub = relay.clone();
    Effect::new(move |_| {
        let f = Filter {
            kinds: Some(vec![KIND_CALENDAR_EVENT, KIND_CALENDAR_RSVP]),
            limit: Some(300),
            ..Default::default()
        };
        let on_ev = Rc::new(move |ev: NostrEvent| {
            if ev.kind == KIND_CALENDAR_EVENT {
                if let Some(ce) = parse_event(&ev) {
                    let coord = format!("{}:{}:{}", KIND_CALENDAR_EVENT, ce.host, ce.d_tag);
                    events.update(|m| {
                        m.insert(coord, ce);
                    });
                }
            } else if ev.kind == KIND_CALENDAR_RSVP {
                if let (Some(a), Some(status)) = (tag_val(&ev, "a"), tag_val(&ev, "status")) {
                    let a = a.to_string();
                    let status = status.to_string();
                    let pk = ev.pubkey.clone();
                    rsvps.update(|m| {
                        m.entry(a).or_default().insert(pk, status);
                    });
                }
            }
        });
        let sub_id = relay_sub.subscribe(vec![f], on_ev, None);
        let r_clean = relay_sub.clone();
        on_cleanup(move || r_clean.unsubscribe(&sub_id));
    });

    let send_rsvp = {
        let relay = relay.clone();
        move |coord: String, host: String, status: &'static str| {
            let Some(signer) = auth.get_signer() else {
                toasts.show("Sign in to RSVP", ToastVariant::Warning);
                return;
            };
            let now = (js_sys::Date::now() / 1000.0) as u64;
            let unsigned = UnsignedEvent {
                pubkey: signer.public_key().to_string(),
                created_at: now,
                kind: KIND_CALENDAR_RSVP,
                tags: vec![
                    vec!["a".into(), coord.clone()],
                    vec!["d".into(), format!("rsvp-{coord}")],
                    vec!["p".into(), host],
                    vec!["status".into(), status.into()],
                ],
                content: String::new(),
            };
            let relay = relay.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match signer.sign_event(unsigned).await {
                    Ok(signed) => {
                        relay.publish(&signed);
                        toasts.show(format!("RSVP: {status}"), ToastVariant::Success);
                    }
                    Err(e) => toasts.show(format!("RSVP failed: {e}"), ToastVariant::Error),
                }
            });
        }
    };

    let create_event = {
        let relay = relay.clone();
        move |_| {
            let title = new_title.get_untracked().trim().to_string();
            if title.is_empty() {
                return;
            }
            let Some(signer) = auth.get_signer() else {
                return;
            };
            let now = (js_sys::Date::now() / 1000.0) as u64;
            let hrs: u64 = new_hours_from_now
                .get_untracked()
                .trim()
                .parse()
                .unwrap_or(24);
            let start = now + hrs * 3600;
            let end = start + 3600;
            let d = format!("evt-{now}");
            let mut tags = vec![
                vec!["d".into(), d],
                vec!["title".into(), title],
                vec!["start".into(), start.to_string()],
                vec!["end".into(), end.to_string()],
            ];
            let loc = new_loc.get_untracked().trim().to_string();
            if !loc.is_empty() {
                tags.push(vec!["location".into(), loc]);
            }
            let unsigned = UnsignedEvent {
                pubkey: signer.public_key().to_string(),
                created_at: now,
                kind: KIND_CALENDAR_EVENT,
                tags,
                content: new_desc.get_untracked().trim().to_string(),
            };
            let relay = relay.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match signer.sign_event(unsigned).await {
                    Ok(signed) => {
                        relay.publish(&signed);
                        new_title.set(String::new());
                        new_loc.set(String::new());
                        new_desc.set(String::new());
                        show_create.set(false);
                        toasts.show("Event published", ToastVariant::Success);
                    }
                    Err(e) => toasts.show(format!("Publish failed: {e}"), ToastVariant::Error),
                }
            });
        }
    };

    view! {
        <div class="tui-container">
            <div class="tui-page-head">
                <div>
                    <h1 class="tui-page-title">"📅 Events & Calendar"</h1>
                    <p class="tui-page-sub">"NIP-52 community schedule with free/busy projections and signed RSVPs."</p>
                </div>
                <div class="tui-actions">
                    {move || zone_access.is_admin.get().then(|| view! {
                        <button
                            type="button"
                            class="bbs-btn bbs-btn-primary"
                            on:click=move |_| show_create.update(|v| *v = !*v)
                        >{move || if show_create.get() { "× Close" } else { "+ New Event" }}</button>
                    })}
                </div>
            </div>

            <Show when=move || show_create.get() fallback=|| ()>
                <div class="tui-card tui-stack">
                    <strong>"Create Calendar Event (kind-31923)"</strong>
                    <input
                        class="bbs-input"
                        type="text"
                        placeholder="Event title…"
                        prop:value=move || new_title.get()
                        on:input=move |ev| new_title.set(event_target_value(&ev))
                    />
                    <div class="tui-row">
                        <input
                            class="bbs-input"
                            style="flex:1 1 180px"
                            type="text"
                            placeholder="Location / URL (optional)"
                            prop:value=move || new_loc.get()
                            on:input=move |ev| new_loc.set(event_target_value(&ev))
                        />
                        <input
                            class="bbs-input"
                            style="width:140px"
                            type="number"
                            placeholder="Hours from now"
                            prop:value=move || new_hours_from_now.get()
                            on:input=move |ev| new_hours_from_now.set(event_target_value(&ev))
                        />
                    </div>
                    <textarea
                        class="bbs-textarea"
                        placeholder="Details…"
                        prop:value=move || new_desc.get()
                        on:input=move |ev| new_desc.set(event_target_value(&ev))
                    ></textarea>
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-primary"
                        on:click={
                            let cb = create_event.clone();
                            move |ev| cb(ev)
                        }
                    >
                        "Publish Event ▶"
                    </button>
                </div>
            </Show>

            <div class="tui-tabs">
                <button
                    type="button"
                    class="tui-tab"
                    class:active=move || tab.get() == "upcoming"
                    on:click=move |_| tab.set("upcoming")
                >"Upcoming"</button>
                <button
                    type="button"
                    class="tui-tab"
                    class:active=move || tab.get() == "past"
                    on:click=move |_| tab.set("past")
                >"Past"</button>
            </div>

            {move || {
                let now = (js_sys::Date::now() / 1000.0) as u64;
                let want_upcoming = tab.get() == "upcoming";
                let mut list: Vec<(String, CalEvent)> = events
                    .get()
                    .into_iter()
                    .filter(|(_, e)| if want_upcoming { e.start >= now || e.start == 0 } else { e.start > 0 && e.start < now })
                    .collect();
                list.sort_by_key(|(_, e)| e.start);
                if !want_upcoming {
                    list.reverse();
                }

                if list.is_empty() {
                    return view! {
                        <EmptyCard
                            title="No events in this view"
                            body="Calendar events (kind-31923) stream from the relay as members schedule them."
                        />
                    }.into_any();
                }

                let rsvp_map = rsvps.get();
                let my_pk = auth.pubkey().get();

                view! {
                    <div class="tui-stack">
                        {list.into_iter().map(|(coord, ev)| {
                            if ev.is_busy {
                                return view! {
                                    <div class="tui-card tui-row-between">
                                        <div>
                                            <strong>"▪ Busy"</strong>
                                            {(!ev.venue.is_empty()).then(|| view! {
                                                <span class="tui-muted">" · venue: " {ev.venue}</span>
                                            })}
                                        </div>
                                        <span class="bbs-badge">{fmt_ts(ev.start)}</span>
                                    </div>
                                }.into_any();
                            }

                            let per_user = rsvp_map.get(&coord);
                            let going = per_user
                                .map(|m| m.values().filter(|s| s.as_str() == "accepted").count())
                                .unwrap_or(0);
                            let maybe = per_user
                                .map(|m| m.values().filter(|s| s.as_str() == "tentative").count())
                                .unwrap_or(0);
                            let mine = my_pk
                                .as_deref()
                                .and_then(|pk| per_user.and_then(|m| m.get(pk)))
                                .cloned();

                            let c1 = coord.clone();
                            let c2 = coord.clone();
                            let c3 = coord.clone();
                            let h1 = ev.host.clone();
                            let h2 = ev.host.clone();
                            let h3 = ev.host.clone();
                            let r1 = send_rsvp.clone();
                            let r2 = send_rsvp.clone();
                            let r3 = send_rsvp.clone();
                            let poker_chain = ev.chain.clone();

                            view! {
                                <div class="tui-card tui-card-accent tui-stack">
                                    <div class="tui-row-between">
                                        <strong>{ev.title}</strong>
                                        <span class="bbs-badge bbs-badge-accent">{fmt_ts(ev.start)}</span>
                                    </div>
                                    <div class="tui-row" style="font-size:0.82rem">
                                        <AuthorChip pubkey=ev.host />
                                        {(!ev.location.is_empty()).then(|| view! {
                                            <span class="tui-muted">"@ " {ev.location}</span>
                                        })}
                                        {ev.poker.then(|| view! {
                                            <button
                                                type="button"
                                                class="bbs-btn bbs-btn-sm bbs-btn-primary"
                                                on:click=move |_| router.go(Route::Poker { chain: poker_chain.clone() })
                                            >"♠ Join Poker Table"</button>
                                        })}
                                    </div>
                                    {(!ev.description.is_empty()).then(|| view! {
                                        <MarkdownBody content=ev.description />
                                    })}
                                    <div class="tui-row-between" style="padding-top:0.4rem;border-top:1px dashed var(--border)">
                                        <span class="tui-muted" style="font-size:0.8rem">
                                            {format!("{going} going · {maybe} maybe")}
                                        </span>
                                        <div class="tui-row">
                                            <button
                                                type="button"
                                                class="bbs-btn bbs-btn-sm"
                                                class:bbs-btn-primary=mine.as_deref() == Some("accepted")
                                                on:click=move |_| r1(c1.clone(), h1.clone(), "accepted")
                                            >"✓ Going"</button>
                                            <button
                                                type="button"
                                                class="bbs-btn bbs-btn-sm"
                                                class:bbs-btn-primary=mine.as_deref() == Some("tentative")
                                                on:click=move |_| r2(c2.clone(), h2.clone(), "tentative")
                                            >"? Maybe"</button>
                                            <button
                                                type="button"
                                                class="bbs-btn bbs-btn-sm"
                                                class:bbs-btn-danger=mine.as_deref() == Some("declined")
                                                on:click=move |_| r3(c3.clone(), h3.clone(), "declined")
                                            >"✗ No"</button>
                                        </div>
                                    </div>
                                </div>
                            }.into_any()
                        }).collect_view()}
                    </div>
                }.into_any()
            }}
        </div>
    }
}
