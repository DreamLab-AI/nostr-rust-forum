//! Category browsing page -- shows the SECTIONS within a zone and lets a user
//! open a new TOPIC inside one of them.
//!
//! Route: /forums/:category
//!
//! ## BBS composition (the contract this page restores)
//!
//! - A *zone* (config: public/Landing, friends, family, business) groups
//!   *sections*.
//! - A *section* is a kind-40 channel carrying a `["section", <slug>]` tag that
//!   routes to this zone (exact id match, or `<zone>-` prefix).
//! - A *topic* is a kind-42 root message (a thread) inside a section channel;
//!   replies e-tag the root.
//!
//! This page therefore lists the zone's *sections* (read from the shared
//! [`ChannelStore`](crate::stores::channels::ChannelStore) — NO per-page relay subscription) with per-section topic
//! counts, and offers a "New Topic" form whose **Section** dropdown is populated
//! from those same resolved sections. Creating a topic publishes a kind-42 root
//! e-tagging the selected section channel — it does NOT create a new channel.
//!
//! Previously this page (a) ran its own redundant kind-40/kind-42 subscriptions
//! that duplicated the store, and (b) populated the Section dropdown from a dead
//! hardcoded `ZONE_SECTIONS` const that had no entry for config-driven zones
//! (friends/family/business) — so the dropdown rendered empty while the section
//! tile rendered fine, and "New Topic" minted a *channel* instead of a thread.

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use std::rc::Rc;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::breadcrumb::{Breadcrumb, BreadcrumbItem};
use crate::components::empty_state::EmptyState;
use crate::components::section_card::SectionCard;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::components::zone_hero::ZoneHero;
use crate::relay::{ConnectionState, RelayConnection};
use crate::stores::channels::{use_channel_store, ChannelMeta};
use crate::stores::zone_access::use_zone_access;
use crate::stores::zones::{load_zones, section_to_zone, Zone, ZoneVisibility};
use crate::utils::capitalize;
use crate::utils::zone_theme::zone_accent_style_cfg;
use wasm_bindgen_futures::spawn_local;

/// The sections (kind-40 channels) belonging to `category_slug`, resolved from
/// the shared store using the SAME zone-routing logic the Forums index uses.
fn sections_for_zone(
    channels: &[ChannelMeta],
    category_slug: &str,
    zones: &[Zone],
) -> Vec<ChannelMeta> {
    let cat = category_slug.to_lowercase();
    let mut out: Vec<ChannelMeta> = channels
        .iter()
        .filter(|ch| {
            let section = if ch.section.is_empty() {
                zones.first().map(|z| z.id.clone()).unwrap_or_default()
            } else {
                ch.section.clone()
            };
            section_to_zone(&section, zones)
                .map(|z| z.to_lowercase() == cat)
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    // Stable, deterministic order: by name.
    out.sort_by_key(|a| a.name.to_lowercase());
    out
}

/// Category page showing the sections within a zone.
#[component]
pub fn CategoryPage() -> impl IntoView {
    let auth = use_auth();
    let is_authed = auth.is_authenticated();
    let zone_access = use_zone_access();
    // Copy signal for the empty-state closure below — admins get a direct path
    // to seed the zone's first section.
    let za_admin = zone_access.is_admin;
    // Copy for the zone-first breadcrumb (ADR-107); `ZoneAccess` is `Copy`.
    let za_breadcrumb = zone_access;
    let store = use_channel_store();
    let toasts = use_toasts();

    let params = use_params_map();
    let category_slug = move || params.read().get("category").unwrap_or_default();

    // Valid zone if it appears in the live ZONE_CONFIG.
    let is_valid_zone = Memo::new(move |_| {
        let cat = category_slug();
        load_zones().iter().any(|z| z.id == cat)
    });

    // Zone access gate: the category slug IS the zone ID (ADR-022 — relay is the
    // real boundary; unknown zones default accessible).
    let has_zone_access = Memo::new(move |_| {
        let cat = category_slug();
        match load_zones().into_iter().find(|z| z.id == cat) {
            Some(zone) => {
                zone.visibility == ZoneVisibility::Public || zone_access.is_member_of(&zone)
            }
            None => true,
        }
    });

    // Sections (channels) for this zone, derived reactively from the shared
    // store. `Signal::derive` (not `Memo`) — `ChannelMeta` is not `PartialEq`.
    let zone_sections = Signal::derive(move || {
        let chans = store.channels.get();
        let zones = load_zones();
        sections_for_zone(&chans, &category_slug(), &zones)
    });

    // Loading is true while the store is still fetching AND no section resolved.
    let store_loading = store.loading;
    let loading = Memo::new(move |_| store_loading.get() && zone_sections.with(|s| s.is_empty()));

    // -- New topic creation state --
    let show_new_topic = RwSignal::new(false);
    let topic_name = RwSignal::new(String::new());
    let creating = RwSignal::new(false);
    let create_error = RwSignal::new(Option::<String>::None);
    // Selected SECTION = the channel id of the section the topic lands in.
    let selected_section = RwSignal::new(String::new());

    // Keep `selected_section` valid: preselect the only/first section so the
    // form is immediately submittable instead of stuck on "Please select".
    Effect::new(move |_| {
        let secs = zone_sections.get();
        let cur = selected_section.get_untracked();
        let still_valid = !cur.is_empty() && secs.iter().any(|s| s.id == cur);
        if !still_valid {
            selected_section.set(secs.first().map(|s| s.id.clone()).unwrap_or_default());
        }
    });

    let display_name = move || {
        let slug = category_slug();
        load_zones()
            .into_iter()
            .find(|z| z.id == slug)
            .map(|z| z.label())
            .unwrap_or_else(|| capitalize(&slug))
    };

    // Zone gradient/icon are keyed off the slug; ZoneHero falls back gracefully
    // for config zones it doesn't special-case.
    let zone_id_for_hero = move || category_slug();
    let zone_icon = move || -> &'static str {
        // Sparkle is the neutral default for config zones.
        "M12 2l2.4 7.2L22 12l-7.6 2.8L12 22l-2.4-7.2L2 12l7.6-2.8L12 2z"
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
        // The page-root carries the zone accent as `--zone-accent`. Descendant
        // links/buttons here use it; it also cascades to anything navigated to
        // within the same subtree. The chat/thread pages mount under their own
        // routes (not as children here) so they cannot inherit it via cascade —
        // see the PR follow-up note for carrying the accent into thread.rs.
        <div
            class="max-w-5xl mx-auto p-4 sm:p-6"
            style=move || {
                let slug = category_slug();
                let accent = load_zones().into_iter().find(|z| z.id == slug).and_then(|z| z.accent_hex);
                zone_accent_style_cfg(&slug, accent.as_deref())
            }
        >
            // Zone hero banner
            {move || {
                let slug = category_slug();
                let zone = load_zones().into_iter().find(|z| z.id == slug);
                let banner = zone.as_ref().and_then(|z| z.banner_image_url.clone()).unwrap_or_default();
                let accent = zone.as_ref().and_then(|z| z.accent_hex.clone());
                let label = zone.map(|z| z.label());
                view! {
                    <ZoneHero
                        title=display_name()
                        description="Browse sections and start a topic".to_string()
                        zone_id=zone_id_for_hero()
                        icon=zone_icon()
                        banner_url=banner
                        zone_label=label.unwrap_or_default()
                        accent_hex=accent.unwrap_or_default()
                    />
                }
            }}

            // Switch-to-BBS sash: also under the ZONE hero so single-locked-zone
            // members (zone-first nav, ADR-107) — who never see the /forums index
            // — still meet it.
            {crate::components::bbs_sash::bbs_switch_sash()}

            // Zone-first breadcrumb (ADR-107): single-locked-zone members drop
            // the global "Forums" crumb (their landing IS the zone); everyone
            // else keeps Home › Forums › {Zone}.
            {move || {
                let zone_label = display_name();
                if za_breadcrumb.home_zone().is_some() {
                    view! {
                        <Breadcrumb items=vec![
                            BreadcrumbItem::link("Home", "/"),
                            BreadcrumbItem::current(zone_label),
                        ] />
                    }
                    .into_any()
                } else {
                    view! {
                        <Breadcrumb items=vec![
                            BreadcrumbItem::link("Home", "/"),
                            BreadcrumbItem::link("Forums", "/forums"),
                            BreadcrumbItem::current(zone_label),
                        ] />
                    }
                    .into_any()
                }
            }}

            // New Topic button + inline form. Discoverable on the page (not just
            // via direct URL): the trigger is always rendered for authed users
            // once the store has finished loading.
            <Show when=move || is_authed.get() && !loading.get()>
                <div class="mb-4">
                    <Show
                        when=move || !show_new_topic.get()
                        fallback=move || {
                            let relay_create = expect_context::<RelayConnection>();
                            let auth_create = use_auth();
                            let toasts = toasts;
                            view! {
                                <div class="bg-gray-800 border border-gray-700 rounded-lg p-5 space-y-3">
                                    <h3 class="text-lg font-semibold text-white">"New Topic"</h3>
                                    <input
                                        type="text"
                                        maxlength="80"
                                        placeholder="Topic title"
                                        prop:value=move || topic_name.get()
                                        on:input=move |ev| topic_name.set(event_target_value(&ev))
                                        class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500"
                                    />
                                    // Section picker — populated from the zone's
                                    // actual resolved sections (channels). The
                                    // <option> value is the channel id the topic
                                    // root e-tags.
                                    <div>
                                        <label class="block text-sm text-gray-400 mb-1">"Section"</label>
                                        <select
                                            on:change=move |ev| selected_section.set(event_target_value(&ev))
                                            prop:value=move || selected_section.get()
                                            class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500"
                                        >
                                            {move || {
                                                zone_sections.get().into_iter().map(|s| {
                                                    let id = s.id.clone();
                                                    let label = if s.name.is_empty() { s.id.clone() } else { s.name.clone() };
                                                    view! { <option value=id>{label}</option> }
                                                }).collect_view()
                                            }}
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
                                                let title = topic_name.get_untracked();
                                                let section_cid = selected_section.get_untracked();
                                                if section_cid.is_empty() {
                                                    create_error.set(Some("Please select a section".into()));
                                                    return;
                                                }
                                                if title.trim().len() < 3 {
                                                    create_error.set(Some("Title must be at least 3 characters".into()));
                                                    return;
                                                }
                                                creating.set(true);
                                                create_error.set(None);
                                                // Async sign so NIP-07 / extension (Podkey)
                                                // users can post — the sync signer needs a
                                                // local in-browser key.
                                                let relay = relay_create.clone();
                                                spawn_local(async move {
                                                    match publish_topic_root(
                                                        &auth_create,
                                                        &relay,
                                                        &section_cid,
                                                        &title,
                                                        toasts,
                                                    ).await {
                                                        Ok(()) => {
                                                            topic_name.set(String::new());
                                                            show_new_topic.set(false);
                                                            toasts.show(
                                                                "Topic created".to_string(),
                                                                ToastVariant::Success,
                                                            );
                                                        }
                                                        Err(e) => create_error.set(Some(e)),
                                                    }
                                                    creating.set(false);
                                                });
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
                        // Trigger is disabled (with a hint) when the zone has no
                        // sections yet — a topic needs a section to live in.
                        {move || {
                            let has_sections = !zone_sections.with(|s| s.is_empty());
                            if has_sections {
                                view! {
                                    <button
                                        type="button"
                                        on:click=move |_| {
                                            // Preselect first section so the form opens ready.
                                            if selected_section.get_untracked().is_empty() {
                                                if let Some(first) = zone_sections.get_untracked().first() {
                                                    selected_section.set(first.id.clone());
                                                }
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
                                }.into_any()
                            } else {
                                view! {
                                    <p class="text-gray-500 text-sm">
                                        "No sections exist in this zone yet."
                                    </p>
                                }.into_any()
                            }
                        }}
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

            // Content — the zone's sections as cards, each linking into its
            // topic list, with a per-section topic count derived from the store.
            <Show when=move || !loading.get()>
                {move || {
                    let secs = zone_sections.get();
                    let cat = category_slug();
                    let last_active = store.last_active.get();

                    if secs.is_empty() {
                        let empty_icon: Box<dyn FnOnce() -> leptos::prelude::AnyView + Send> = Box::new(|| view! {
                            <svg class="w-7 h-7 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                <path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        }.into_any());
                        // Admins get a "Create a section" CTA that deep-links to
                        // the admin panel's Channels tab (`?tab=channels`) — its
                        // "Create Channel" form is where sections are actually
                        // created (sections ARE channels). The admin panel's
                        // "Sections" tab is join-request approvals, not creation,
                        // so we must not land on bare /admin (Overview). Everyone
                        // else keeps the informational copy and a link back to
                        // the forums index.
                        if za_admin.get() {
                            view! {
                                <EmptyState
                                    icon=empty_icon
                                    title="No sections yet".to_string()
                                    description="This zone has no sections. Create the first one to get the community started.".to_string()
                                    action_label="Create a section".to_string()
                                    action_href=base_href("/admin?tab=channels")
                                />
                            }.into_any()
                        } else {
                            // Non-admins can't seed sections. Pick an escape that
                            // doesn't loop: a single-locked-zone member is
                            // auto-forwarded /forums → /forums/{home_zone}
                            // (ADR-107), so a "Back to Forums" link would bounce
                            // straight back to this same empty page. For them the
                            // real escape is the site root (matching the
                            // zone-first breadcrumb's "Home" crumb); multi-zone
                            // members and public-only users keep the forums index.
                            let (action_label, action_href) = if za_breadcrumb.home_zone().is_some() {
                                ("Back to Home".to_string(), base_href("/"))
                            } else {
                                ("Back to Forums".to_string(), base_href("/forums"))
                            };
                            view! {
                                <EmptyState
                                    icon=empty_icon
                                    title="No sections yet".to_string()
                                    description="This zone has no sections. An admin can seed one for the community.".to_string()
                                    action_label=action_label
                                    action_href=action_href
                                />
                            }.into_any()
                        }
                    } else {
                        let cards: Vec<_> = secs.iter().map(|s| {
                            let mc = store.count_for(&s.id);
                            let la = last_active.get(&s.id).copied().unwrap_or(0);
                            view! {
                                <SectionCard
                                    name=s.name.clone()
                                    description=s.description.clone()
                                    channel_id=s.id.clone()
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

/// Publish a new TOPIC: a kind-42 root message e-tagging the selected section
/// channel. The topic title becomes the message content (the thread starter).
/// This is the same shape `SectionPage` produces for a root post, so the new
/// topic appears in the section's message list immediately on relay echo.
async fn publish_topic_root(
    auth: &crate::auth::AuthStore,
    relay: &RelayConnection,
    section_channel_id: &str,
    title: &str,
    toasts: crate::components::toast::ToastStore,
) -> Result<(), String> {
    if relay.connection_state().get_untracked() != ConnectionState::Connected {
        return Err("Relay not connected".to_string());
    }

    let pubkey = auth
        .pubkey()
        .get_untracked()
        .ok_or_else(|| "Not authenticated".to_string())?;

    let now = (js_sys::Date::now() / 1000.0) as u64;
    // NIP-10 root marker pointing at the section channel (kind-40) id.
    let mut tags = vec![vec![
        "e".to_string(),
        section_channel_id.to_string(),
        String::new(),
        "root".to_string(),
    ]];
    // @handles typed into the topic title/body get ["p", pubkey] tags so
    // mentioned users / agents (e.g. @junkiejarvis) are addressable and
    // reachable via the relay's #p-filtered subscriptions.
    for hex in crate::components::mention_autocomplete::resolve_content_mentions(title) {
        if !tags
            .iter()
            .any(|t| t.len() >= 2 && t[0] == "p" && t[1] == hex)
        {
            tags.push(vec!["p".to_string(), hex]);
        }
    }

    let unsigned = nostr_bbs_core::UnsignedEvent {
        pubkey,
        created_at: now,
        kind: 42,
        tags,
        content: title.trim().to_string(),
    };

    let signed = auth.sign_event_async(unsigned).await?;

    // Publish with ack so relay rejections (e.g. not-yet-whitelisted) surface.
    let on_ok = Rc::new(move |accepted: bool, msg: String| {
        if !accepted {
            let display = if msg.contains("whitelist") {
                "Your account isn't active yet — try refreshing the page.".to_string()
            } else if msg.trim().is_empty() {
                "Topic rejected by relay".to_string()
            } else {
                format!("Topic rejected: {msg}")
            };
            toasts.show(display, ToastVariant::Error);
        }
    });
    relay
        .publish_with_ack(&signed, Some(on_ok))
        .map_err(|e| format!("Send failed: {e}"))?;

    Ok(())
}
