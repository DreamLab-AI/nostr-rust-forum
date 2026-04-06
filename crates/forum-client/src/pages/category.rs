//! Category browsing page -- shows sections within a specific zone/category.
//!
//! Route: /forums/:category
//! Subscribes to kind 40 channels whose `section` tag matches the category,
//! and renders them as section cards with message counts and last activity.

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use nostr_core::NostrEvent;
use std::collections::HashMap;
use std::rc::Rc;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::breadcrumb::{Breadcrumb, BreadcrumbItem};
use crate::components::empty_state::EmptyState;
use crate::components::section_card::SectionCard;
use crate::components::zone_hero::ZoneHero;
use crate::relay::{ConnectionState, Filter, RelayConnection};
use crate::stores::zone_access::use_zone_access;
use crate::utils::{capitalize, set_timeout_once};

/// Maps zone IDs to their child section IDs.
const ZONE_SECTIONS: &[(&str, &[&str])] = &[
    ("home", &["public-lobby"]),
    ("members", &["members-training", "members-projects", "members-bookings", "ai-general", "ai-claude-flow", "ai-visionflow"]),
    ("private", &["private-welcome", "private-events", "private-booking"]),
];

/// Resolve a channel's section tag to its parent zone ID.
fn section_to_zone_id(section: &str) -> Option<&'static str> {
    for &(zone_id, sections) in ZONE_SECTIONS {
        if sections.contains(&section) {
            return Some(zone_id);
        }
    }
    None
}

/// Get the section IDs belonging to a zone.
fn zone_section_ids(zone_id: &str) -> &'static [&'static str] {
    ZONE_SECTIONS
        .iter()
        .find(|&&(id, _)| id == zone_id)
        .map(|&(_, secs)| secs)
        .unwrap_or(&[])
}

/// Convert a section ID like "members-training" to "Training".
fn humanize_section_id(id: &str) -> String {
    let suffix = id.find('-').map(|i| &id[i + 1..]).unwrap_or(id);
    suffix
        .split('-')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().to_string() + c.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parsed section data from kind 40 events.
#[derive(Clone, Debug)]
struct SectionMeta {
    channel_id: String,
    name: String,
    description: String,
    _created_at: u64,
}

/// Category page showing sections within a specific category.
#[component]
pub fn CategoryPage() -> impl IntoView {
    let relay = expect_context::<RelayConnection>();
    let conn_state = relay.connection_state();
    let auth = use_auth();
    let is_authed = auth.is_authenticated();
    let zone_access = use_zone_access();

    let params = use_params_map();
    let category_slug = move || params.read().get("category").unwrap_or_default();

    // Check if this is a known zone
    let is_valid_zone = Memo::new(move |_| {
        let cat = category_slug();
        ZONE_SECTIONS.iter().any(|&(id, _)| id == cat.as_str())
    });

    // Zone access gate: category slug maps directly to zone ID
    let has_zone_access = Memo::new(move |_| {
        let cat = category_slug();
        match cat.as_str() {
            "home" => zone_access.home.get(),
            "members" => zone_access.members.get(),
            "private" => zone_access.private_zone.get(),
            _ => false,
        }
    });

    let sections = RwSignal::new(Vec::<SectionMeta>::new());
    let message_counts = RwSignal::new(HashMap::<String, u32>::new());
    let last_active_map = RwSignal::new(HashMap::<String, u64>::new());
    let loading = RwSignal::new(true);
    let eose_received = RwSignal::new(false);

    // -- New topic creation state --
    let show_new_topic = RwSignal::new(false);
    let topic_name = RwSignal::new(String::new());
    let topic_desc = RwSignal::new(String::new());
    let creating = RwSignal::new(false);
    let create_error = RwSignal::new(Option::<String>::None);
    let selected_section = RwSignal::new(String::new());

    let channel_sub_id: RwSignal<Option<String>> = RwSignal::new(None);
    let msg_sub_id: RwSignal<Option<String>> = RwSignal::new(None);

    let relay_for_ch = relay.clone();
    let relay_for_msgs = relay.clone();
    let relay_for_cleanup = relay;

    // Subscribe to kind 40 events, filter by section tag matching this category
    Effect::new(move |_| {
        let state = conn_state.get();
        if state != ConnectionState::Connected {
            return;
        }
        if channel_sub_id.get_untracked().is_some() {
            return;
        }

        loading.set(true);

        let filter = Filter {
            kinds: Some(vec![40]),
            ..Default::default()
        };

        let slug = category_slug();
        let sections_sig = sections;
        let on_event = Rc::new(move |event: NostrEvent| {
            if event.kind != 40 {
                return;
            }

            let section_tag = event
                .tags
                .iter()
                .find(|t| t.len() >= 2 && t[0] == "section")
                .map(|t| t[1].clone())
                .unwrap_or_default();

            // Match: exact match, case-insensitive match, or zone parent match
            let matches = section_tag == slug
                || section_tag.eq_ignore_ascii_case(&slug)
                || section_to_zone_id(&section_tag) == Some(slug.as_str());

            if !matches && !slug.is_empty() {
                return;
            }

            let (name, description) = parse_channel_content(&event.content);

            let meta = SectionMeta {
                channel_id: event.id.clone(),
                name,
                description,
                _created_at: event.created_at,
            };

            sections_sig.update(|list| {
                if !list.iter().any(|s| s.channel_id == meta.channel_id) {
                    list.push(meta);
                }
            });
        });

        let loading_sig = loading;
        let eose_sig = eose_received;
        let on_eose = Rc::new(move || {
            loading_sig.set(false);
            eose_sig.set(true);
        });

        let id = relay_for_ch.subscribe(vec![filter], on_event, Some(on_eose));
        channel_sub_id.set(Some(id));

        set_timeout_once(
            move || {
                if loading_sig.get_untracked() {
                    loading_sig.set(false);
                }
            },
            8000,
        );
    });

    // Subscribe to kind 42 messages for counts and last-active timestamps
    Effect::new(move |_| {
        if !eose_received.get() {
            return;
        }
        if msg_sub_id.get_untracked().is_some() {
            return;
        }

        let channel_ids: Vec<String> = sections
            .get_untracked()
            .iter()
            .map(|s| s.channel_id.clone())
            .collect();
        if channel_ids.is_empty() {
            return;
        }

        let msg_filter = Filter {
            kinds: Some(vec![42]),
            e_tags: Some(channel_ids),
            ..Default::default()
        };

        let counts = message_counts;
        let active = last_active_map;
        let on_msg = Rc::new(move |event: NostrEvent| {
            let cid = event
                .tags
                .iter()
                .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == "root")
                .or_else(|| event.tags.iter().find(|t| t.len() >= 2 && t[0] == "e"))
                .map(|t| t[1].clone());

            if let Some(cid) = cid {
                counts.update(|m| *m.entry(cid.clone()).or_insert(0) += 1);
                active.update(|m| {
                    let ts = m.entry(cid).or_insert(0);
                    if event.created_at > *ts {
                        *ts = event.created_at;
                    }
                });
            }
        });

        let id = relay_for_msgs.subscribe(vec![msg_filter], on_msg, None);
        msg_sub_id.set(Some(id));
    });

    on_cleanup(move || {
        if let Some(id) = channel_sub_id.get_untracked() {
            relay_for_cleanup.unsubscribe(&id);
        }
        if let Some(id) = msg_sub_id.get_untracked() {
            relay_for_cleanup.unsubscribe(&id);
        }
    });

    let display_name = move || {
        let slug = category_slug();
        match slug.as_str() {
            "home" => "Home".to_string(),
            "private" => "Private".to_string(),
            "members" => "Nostr BBS".to_string(),
            other => {
                // For section IDs like "public-lobby", humanize to "Lobby"
                if other.contains('-') {
                    let suffix = other.split_once('-').map(|(_, s)| s).unwrap_or(other);
                    suffix
                        .split('-')
                        .map(|w| {
                            let mut c = w.chars();
                            match c.next() {
                                None => String::new(),
                                Some(f) => f.to_uppercase().to_string() + c.as_str(),
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(" ")
                } else {
                    capitalize(other)
                }
            }
        }
    };

    // Map category slug to zone_id for ZoneHero
    let zone_id_for_hero = move || -> String {
        let slug = category_slug();
        match slug.as_str() {
            "home" | "members" | "private" => slug,
            _ => {
                // Resolve section ID to parent zone
                section_to_zone_id(&slug)
                    .unwrap_or("home")
                    .to_string()
            }
        }
    };

    // Icon path data per zone
    let zone_icon = move || -> &'static str {
        let slug = category_slug();
        if slug.starts_with("private") {
            // Moon
            "M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"
        } else {
            // Sparkle for Home and Nostr BBS
            "M12 2l2.4 7.2L22 12l-7.6 2.8L12 22l-2.4-7.2L2 12l7.6-2.8L12 2z"
        }
    };

    view! {
        <Show
            when=move || is_valid_zone.get()
            fallback=move || view! {
                <div class="max-w-lg mx-auto p-8 text-center">
                    <div class="glass-card p-8">
                        <div class="w-14 h-14 rounded-full bg-gray-500/10 flex items-center justify-center mx-auto mb-4">
                            <svg class="w-7 h-7 text-gray-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                <circle cx="12" cy="12" r="10" stroke-linecap="round"/>
                                <path d="M12 8v4M12 16h.01" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        </div>
                        <h2 class="text-xl font-bold text-white mb-2">"Zone Not Found"</h2>
                        <p class="text-gray-400 text-sm mb-4">
                            {move || format!("The zone \"{}\" does not exist.", category_slug())}
                        </p>
                        <a href=base_href("/forums") class="text-amber-400 hover:text-amber-300 text-sm underline">
                            "Back to Forums"
                        </a>
                    </div>
                </div>
            }
        >
        <Show
            when=move || has_zone_access.get()
            fallback=move || view! {
                <div class="max-w-lg mx-auto p-8 text-center">
                    <div class="glass-card p-8">
                        <div class="w-14 h-14 rounded-full bg-red-500/10 flex items-center justify-center mx-auto mb-4">
                            <svg class="w-7 h-7 text-red-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <path d="M7 11V7a5 5 0 0110 0v4" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        </div>
                        <h2 class="text-xl font-bold text-white mb-2">"Access Restricted"</h2>
                        <p class="text-gray-400 text-sm mb-4">
                            {move || format!("You don't have access to the {} zone.", capitalize(&category_slug()))}
                        </p>
                        <a href=base_href("/forums") class="text-amber-400 hover:text-amber-300 text-sm underline">
                            "Back to Forums"
                        </a>
                    </div>
                </div>
            }
        >
        <div class="max-w-5xl mx-auto p-4 sm:p-6">
            // Zone hero banner
            {move || view! {
                <ZoneHero
                    title=display_name()
                    description="Browse sections and start a discussion".to_string()
                    zone_id=zone_id_for_hero()
                    icon=zone_icon()
                />
            }}

            <Breadcrumb items=vec![
                BreadcrumbItem::link("Home", "/"),
                BreadcrumbItem::link("Forums", "/forums"),
                BreadcrumbItem::current(capitalize(&category_slug())),
            ] />

            // New Topic button + inline form
            <Show when=move || is_authed.get() && !loading.get()>
                <div class="mb-4">
                    <Show
                        when=move || !show_new_topic.get()
                        fallback=move || {
                            let relay_create = expect_context::<RelayConnection>();
                            let auth_create = use_auth();
                            let sections_sig = sections;
                            let zone_secs = zone_section_ids(&category_slug());
                            view! {
                                <div class="bg-gray-800 border border-gray-700 rounded-lg p-5 space-y-3">
                                    <h3 class="text-lg font-semibold text-white">"New Topic"</h3>
                                    <input
                                        type="text"
                                        maxlength="64"
                                        placeholder="Topic name"
                                        prop:value=move || topic_name.get()
                                        on:input=move |ev| topic_name.set(event_target_value(&ev))
                                        class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500"
                                    />
                                    <textarea
                                        placeholder="Description (optional)"
                                        rows="2"
                                        prop:value=move || topic_desc.get()
                                        on:input=move |ev| topic_desc.set(event_target_value(&ev))
                                        class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 resize-none"
                                    />
                                    // Section picker
                                    <div>
                                        <label class="block text-sm text-gray-400 mb-1">"Section"</label>
                                        <select
                                            on:change=move |ev| selected_section.set(event_target_value(&ev))
                                            class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500"
                                        >
                                            {zone_secs.iter().map(|&s| {
                                                let display = humanize_section_id(s);
                                                view! {
                                                    <option value=s>{display}</option>
                                                }
                                            }).collect_view()}
                                        </select>
                                    </div>
                                    {move || create_error.get().map(|e| view! {
                                        <p class="text-red-400 text-sm">{e}</p>
                                    })}
                                    <div class="flex gap-2">
                                        <button
                                            type="button"
                                            disabled=move || creating.get() || topic_name.get().trim().len() < 3
                                            on:click=move |_| {
                                                let name = topic_name.get_untracked();
                                                let desc = topic_desc.get_untracked();
                                                let section = selected_section.get_untracked();
                                                if section.is_empty() {
                                                    create_error.set(Some("Please select a section".into()));
                                                    return;
                                                }
                                                if name.trim().len() < 3 {
                                                    create_error.set(Some("Name must be at least 3 characters".into()));
                                                    return;
                                                }
                                                creating.set(true);
                                                create_error.set(None);

                                                match create_topic_event(&auth_create, &relay_create, &name, &desc, &section, create_error) {
                                                    Ok(meta) => {
                                                        // Add to local list immediately
                                                        sections_sig.update(|list| {
                                                            if !list.iter().any(|s| s.channel_id == meta.channel_id) {
                                                                list.push(meta);
                                                            }
                                                        });
                                                        topic_name.set(String::new());
                                                        topic_desc.set(String::new());
                                                        show_new_topic.set(false);
                                                    }
                                                    Err(e) => create_error.set(Some(e)),
                                                }
                                                creating.set(false);
                                            }
                                            class="bg-amber-500 hover:bg-amber-400 disabled:bg-gray-600 disabled:cursor-not-allowed text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors text-sm"
                                        >
                                            {move || if creating.get() { "Creating..." } else { "Create Topic" }}
                                        </button>
                                        <button
                                            type="button"
                                            on:click=move |_| {
                                                show_new_topic.set(false);
                                                create_error.set(None);
                                            }
                                            class="text-gray-400 hover:text-white px-3 py-2 text-sm transition-colors"
                                        >
                                            "Cancel"
                                        </button>
                                    </div>
                                </div>
                            }
                        }
                    >
                        <button
                            type="button"
                            on:click=move |_| {
                                let secs = zone_section_ids(&category_slug());
                                if let Some(&first) = secs.first() {
                                    selected_section.set(first.to_string());
                                }
                                show_new_topic.set(true);
                            }
                            class="flex items-center gap-2 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/20 px-4 py-2 rounded-lg transition-colors text-sm font-medium"
                        >
                            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10"/>
                                <line x1="12" y1="8" x2="12" y2="16"/>
                                <line x1="8" y1="12" x2="16" y2="12"/>
                            </svg>
                            "New Topic"
                        </button>
                    </Show>
                </div>
            </Show>

            // Loading
            <Show when=move || loading.get()>
                <div class="space-y-3">
                    <SectionSkeleton/>
                    <SectionSkeleton/>
                    <SectionSkeleton/>
                </div>
            </Show>

            // Content
            <Show when=move || !loading.get()>
                {move || {
                    let secs = sections.get();
                    let counts = message_counts.get();
                    let active = last_active_map.get();
                    let cat = category_slug();

                    if secs.is_empty() {
                        let empty_icon: Box<dyn FnOnce() -> leptos::prelude::AnyView + Send> = Box::new(|| view! {
                            <svg class="w-7 h-7 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                <path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        }.into_any());
                        let (title, desc) = if is_authed.get() {
                            ("No topics yet".to_string(), "Be the first — click \"New Topic\" above to start a conversation.".to_string())
                        } else {
                            ("No topics yet".to_string(), "Sign in to start a conversation.".to_string())
                        };
                        view! {
                            <EmptyState
                                icon=empty_icon
                                title=title
                                description=desc
                                action_label="Back to Forums".to_string()
                                action_href=base_href("/forums")
                            />
                        }.into_any()
                    } else {
                        let cards: Vec<_> = secs.iter().map(|s| {
                            let mc = counts.get(&s.channel_id).copied().unwrap_or(0);
                            let la = active.get(&s.channel_id).copied().unwrap_or(0);
                            view! {
                                <SectionCard
                                    name=s.name.clone()
                                    description=s.description.clone()
                                    channel_id=s.channel_id.clone()
                                    message_count=mc
                                    last_activity=la
                                    category=cat.clone()
                                />
                            }
                        }).collect();
                        view! {
                            <div class="space-y-3">
                                {cards.into_iter().collect_view()}
                            </div>
                        }.into_any()
                    }
                }}
            </Show>
        </div>
        </Show>
        </Show>
    }
}

/// Skeleton loader for section cards.
#[component]
fn SectionSkeleton() -> impl IntoView {
    view! {
        <div class="section-list-card">
            <div class="space-y-2">
                <div class="h-5 skeleton rounded w-1/3"></div>
                <div class="h-3 skeleton rounded w-2/3"></div>
                <div class="flex gap-3 mt-3">
                    <div class="h-3 skeleton rounded w-16"></div>
                    <div class="h-3 skeleton rounded w-20"></div>
                </div>
            </div>
        </div>
    }
}

/// Create a kind-40 channel event, sign it, and publish to the relay with ack.
/// Returns the `SectionMeta` for optimistic local insertion.
/// On relay rejection, the error signal is set asynchronously.
fn create_topic_event(
    auth: &crate::auth::AuthStore,
    relay: &RelayConnection,
    name: &str,
    description: &str,
    section: &str,
    error_signal: RwSignal<Option<String>>,
) -> Result<SectionMeta, String> {
    if relay.connection_state().get_untracked() != ConnectionState::Connected {
        return Err("Relay not connected".to_string());
    }

    let content = serde_json::json!({
        "name": name.trim(),
        "about": description.trim(),
        "picture": ""
    });

    let pubkey = auth
        .pubkey()
        .get_untracked()
        .ok_or_else(|| "Not authenticated".to_string())?;

    let now = (js_sys::Date::now() / 1000.0) as u64;
    let tags = vec![
        vec!["section".into(), section.into()],
        vec!["zone".into(), "1".into()],
    ];

    let unsigned = nostr_core::UnsignedEvent {
        pubkey,
        created_at: now,
        kind: 40,
        tags,
        content: serde_json::to_string(&content).unwrap(),
    };

    let signed = auth.sign_event(unsigned)?;
    let channel_id = signed.id.clone();

    // Publish with ack — show error asynchronously if relay rejects
    let on_ok = std::rc::Rc::new(move |accepted: bool, msg: String| {
        if !accepted {
            let display = if msg.contains("whitelist") {
                "Your account isn't active yet — try refreshing the page.".to_string()
            } else {
                format!("Relay rejected: {msg}")
            };
            error_signal.set(Some(display));
        }
    });
    let _ = relay.publish_with_ack(&signed, Some(on_ok));

    Ok(SectionMeta {
        channel_id,
        name: name.trim().to_string(),
        description: description.trim().to_string(),
        _created_at: now,
    })
}

/// Parse kind 40 event content JSON into (name, description).
fn parse_channel_content(content: &str) -> (String, String) {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(val) => {
            let name = val
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unnamed Section")
                .to_string();
            let desc = val
                .get("about")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            (name, desc)
        }
        Err(_) => ("Unnamed Section".to_string(), String::new()),
    }
}
