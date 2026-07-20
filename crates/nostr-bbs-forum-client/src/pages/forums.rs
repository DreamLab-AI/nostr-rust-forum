//! Forum index page -- displays all zones and their categories with hero cards.
//!
//! Subscribes to kind 40 (channel creation) events from the relay,
//! groups them by zone/category from the `section` tag, and renders
//! each zone with its categories as visually rich hero cards.

use leptos::prelude::AnyView;
use leptos::prelude::*;
use std::collections::HashMap;

use leptos_router::components::A;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::breadcrumb::{Breadcrumb, BreadcrumbItem};
use crate::components::category_card::CategoryCard;
use crate::components::empty_state::EmptyState;
use crate::stores::channels::use_channel_store;
use crate::stores::read_position::use_read_positions;
use crate::stores::zone_access::use_zone_access;
use crate::stores::zones::{load_zones, section_to_zone, Zone, ZoneVisibility};
use crate::utils::zone_theme::{resolved_accent_hex, zone_tile_style};

/// Per-section post tallies projected into each category card.
///
/// `total` is the existing "N posts" lifetime count; `unread` is the number of
/// messages newer than the user's last-read position across every channel in
/// the section (issue #24 — bright "N new" chip on the forum index).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SectionCounts {
    pub total: u32,
    pub unread: u32,
}

// -- Zone -> section routing --------------------------------------------------
// `section_to_zone` is the canonical resolver in `stores::zones` (imported above).
// Zone accent colour is resolved config-first via `resolved_accent_hex`
// (issue #43) — the old zone-id hash into an arbitrary palette is gone.

// -- Welcome card helpers -----------------------------------------------------

fn is_welcome_dismissed() -> bool {
    web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
        .and_then(|s| s.get_item("nostrbbs_welcome_dismissed").ok())
        .flatten()
        .is_some()
}

fn dismiss_welcome() {
    if let Some(storage) = web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
    {
        let _ = storage.set_item("nostrbbs_welcome_dismissed", "true");
    }
}

/// Main forum index page showing all zones and their categories.
/// Only shows zones the user has access to — inaccessible zones are hidden.
/// Reads from the shared ChannelStore — no per-page relay subscription.
#[component]
pub fn ForumsPage() -> impl IntoView {
    let store = use_channel_store();
    let read_store = use_read_positions();
    let loading = store.loading;
    let auth = use_auth();
    let is_authed = auth.is_authenticated();
    let welcome_name = auth.nickname();
    let show_welcome = RwSignal::new(!is_welcome_dismissed());
    let zone_access = use_zone_access();
    // Extract Copy signals so closures can capture them by value
    let za_loaded = zone_access.loaded;
    let za_cohorts = zone_access.cohorts;
    let za_admin = zone_access.is_admin;

    // Zone-first landing (ADR-107): a user authorised for exactly one locked
    // zone is auto-forwarded to that zone's channel list, so they land on their
    // zone's topics rather than the generic index. `home_zone()` returns `None`
    // until the access fetch completes (so we never forward prematurely) and for
    // admins / multi-zone members, who keep seeing the index unchanged. The
    // navigation replaces the history entry so "back" skips the bare index.
    {
        let za_forward = zone_access;
        let navigate = StoredValue::new(use_navigate());
        Effect::new(move |_| {
            if let Some(zone) = za_forward.home_zone() {
                let target = format!("/{}", crate::stores::zones::zone_slug(&zone));
                navigate.with_value(|nav| {
                    nav(
                        &target,
                        NavigateOptions {
                            replace: true,
                            ..Default::default()
                        },
                    );
                });
            }
        });
    }

    // Config-driven zone list, sourced once from `window.__ENV__.ZONE_CONFIG`
    // (falls back to the legacy 3-zone list). Stored in a StoredValue so the
    // render closures can clone it cheaply without re-parsing.
    let zones = StoredValue::new(load_zones());

    // Derive zone_id -> { section_id -> SectionCounts } from the shared store.
    // Reads `channels` (section routing), `channel_messages` (live post counts +
    // per-message timestamps) and the read-position timestamps so the Memo
    // re-runs whenever any of them change — including when a channel is marked
    // read, which clears the bright "N new" chip immediately.
    let zone_categories = Memo::new(move |_| {
        let chans = store.channels.get();
        let msgs = store.channel_messages.get();
        let read_ts = read_store.read_timestamps();
        let zs = zones.get_value();
        let mut map = HashMap::<String, HashMap<String, SectionCounts>>::new();
        for ch in &chans {
            let section = if ch.section.is_empty() {
                zs.first().map(|z| z.id.clone()).unwrap_or_default()
            } else {
                ch.section.clone()
            };
            if let Some(zone_id) = section_to_zone(&section, &zs) {
                let cats = map.entry(zone_id).or_default();
                let channel_msgs = msgs.get(&ch.id);
                let post_count = channel_msgs.map(|v| v.len() as u32).unwrap_or(0);
                // Unread = messages newer than this channel's last-read position.
                // A channel with no read position counts every message as unread
                // (it has never been opened). Read timestamps are the kind-42
                // `created_at` recorded by mark_read in the channel view.
                let last_read = read_ts.get(&ch.id).copied().unwrap_or(0);
                let unread_count = channel_msgs
                    .map(|v| v.iter().filter(|e| e.created_at > last_read).count() as u32)
                    .unwrap_or(0);
                // Ensure the section entry exists even if post_count == 0 so
                // the category card still renders (section is known to exist).
                let entry = cats.entry(section).or_default();
                entry.total += post_count;
                entry.unread += unread_count;
            }
        }
        map
    });

    // Live card labels (issue #44): when a section resolves to exactly one
    // channel, the index card shows that channel's kind-40/41 name and
    // description — so an admin rename propagates here too, instead of the
    // stale hardcoded `section_description` map. Multi-channel sections keep
    // the humanized section id (there is no single canonical channel to name
    // them after).
    let section_meta = Memo::new(move |_| {
        let chans = store.channels.get();
        let mut by_section = HashMap::<String, Vec<usize>>::new();
        for (i, ch) in chans.iter().enumerate() {
            if !ch.section.is_empty() {
                by_section.entry(ch.section.clone()).or_default().push(i);
            }
        }
        let mut meta = HashMap::<String, (String, String)>::new();
        for (section, idxs) in by_section {
            if let [only] = idxs.as_slice() {
                let ch = &chans[*only];
                if !ch.name.trim().is_empty() {
                    meta.insert(section, (ch.name.clone(), ch.description.clone()));
                }
            }
        }
        meta
    });

    view! {
        // Onboarding modal mounted globally in app.rs Layout — see N3e.

        <div class="max-w-6xl mx-auto p-4 sm:p-6">
            // Hero header
            <div class="relative mb-10 py-10 rounded-2xl overflow-hidden mesh-bg aurora-shimmer">
                <div class="ambient-orb ambient-orb-1" aria-hidden="true"></div>
                <div class="ambient-orb ambient-orb-2" aria-hidden="true"></div>
                <div class="relative z-10 text-center">
                    // Operator-branded (issue #21): same runtime name as the
                    // logged-out landing hero, so the index and home agree.
                    <h1 class="text-4xl sm:text-5xl font-bold candy-gradient mb-3">
                        {crate::utils::relay_url::forum_name()}
                    </h1>
                    <p class="text-gray-400 text-lg max-w-xl mx-auto">
                        "Explore zones, dive into categories, and join the conversation"
                    </p>
                </div>
            </div>

            {crate::components::bbs_sash::bbs_switch_sash()}

            <Breadcrumb items=vec![
                BreadcrumbItem::link("Home", "/"),
                BreadcrumbItem::current("Forums"),
            ] />

            // Welcome card — shown once to new users
            <Show when=move || is_authed.get() && show_welcome.get()>
                <div class="relative mb-6 p-6 rounded-2xl bg-gradient-to-br from-amber-500/10 via-orange-500/5 to-transparent border border-amber-500/20 backdrop-blur-sm overflow-hidden">
                    <div class="absolute -top-10 -right-10 w-40 h-40 rounded-full bg-amber-500/5 blur-3xl" aria-hidden="true"></div>
                    <button
                        class="absolute top-3 right-3 text-gray-500 hover:text-white p-1 rounded-lg hover:bg-gray-700/50 transition-colors"
                        on:click=move |_| {
                            dismiss_welcome();
                            show_welcome.set(false);
                        }
                        aria-label="Dismiss welcome message"
                    >
                        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="18" y1="6" x2="6" y2="18" stroke-linecap="round"/>
                            <line x1="6" y1="6" x2="18" y2="18" stroke-linecap="round"/>
                        </svg>
                    </button>
                    <div class="relative z-10">
                        <h2 class="text-xl font-bold text-white mb-2">
                            {move || {
                                let raw = welcome_name.get().unwrap_or_default();
                                // Strip trailing whitespace and ASCII punctuation so a
                                // display name ending in a title suffix (e.g.
                                // "…, PhD,") doesn't render "Welcome, …,!".
                                let name = raw.trim_end_matches(|c: char| {
                                    c.is_whitespace() || matches!(c, '.' | ',' | ';' | ':' | '!' | '-')
                                });
                                if name.is_empty() {
                                    "Welcome!".to_string()
                                } else {
                                    format!("Welcome, {}!", name)
                                }
                            }}
                        </h2>
                        <p class="text-gray-300 text-sm mb-3">
                            "This is your community hub. Forums are organized into zones \u{2014} "
                            "each zone has categories and topics for different discussions."
                        </p>
                        <p class="text-gray-400 text-xs">
                            "Start by exploring the "
                            {move || {
                                // Name the ACTUAL first public zone (or, failing
                                // that, the first configured zone) rather than a
                                // hardcoded "Home" — zones are operator-config
                                // driven via load_zones()/ZONE_CONFIG. Link the
                                // name straight to that zone's channel list.
                                let zs = zones.get_value();
                                let zone = zs
                                    .iter()
                                    .find(|z| z.visibility == ZoneVisibility::Public)
                                    .or_else(|| zs.first())
                                    .map(|z| (base_href(&format!("/{}", crate::stores::zones::zone_slug(z))), z.label()));
                                match zone {
                                    Some((href, label)) => view! {
                                        <A
                                            href=href
                                            attr:class="text-amber-400 font-medium hover:text-amber-300 transition-colors no-underline"
                                        >
                                            {label}
                                        </A>
                                        " zone below."
                                    }
                                    .into_any(),
                                    // No zones configured — fall back gracefully.
                                    None => view! { "zones below." }.into_any(),
                                }
                            }}
                        </p>
                    </div>
                </div>
            </Show>

            // Loading state
            <Show when=move || loading.get()>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
                    <ZoneSkeleton/>
                    <ZoneSkeleton/>
                    <ZoneSkeleton/>
                </div>
            </Show>

            // Zone sections — config-driven section tiles, each headed by its
            // banner. Member/public zones render normally; locked zones the user
            // can't enter render as greyed locked tiles; hidden zones the user
            // can't enter are omitted entirely. The relay is the real boundary.
            <Show when=move || !loading.get()>
                {move || {
                    let zc = zone_categories.get();
                    let sec_meta = section_meta.get();
                    let all_zones = zones.get_value();
                    let cohorts = za_cohorts.get();
                    let is_admin = za_admin.get();
                    let authed = is_authed.get();

                    // Per-zone classification:
                    //   member  -> normal openable tile
                    //   locked  -> greyed, non-openable tile (visibility=locked)
                    //   omitted -> not rendered (visibility=hidden, non-member)
                    let mut rendered: Vec<AnyView> = Vec::new();
                    for zone in &all_zones {
                        let is_member = is_admin || zone.is_member(&cohorts);
                        match (zone.visibility, is_member) {
                            // Public zone, or any zone the user is a member of:
                            // normal tile.
                            (ZoneVisibility::Public, _) | (_, true) => {
                                let cats = zc.get(&zone.id).cloned().unwrap_or_default();
                                rendered.push(zone_tile(zone, cats, &sec_meta));
                            }
                            // Locked zone, non-member: greyed locked tile.
                            (ZoneVisibility::Locked, false) => {
                                rendered.push(locked_tile(zone));
                            }
                            // Hidden zone, non-member: omit entirely.
                            (ZoneVisibility::Hidden, false) => {}
                        }
                    }

                    if rendered.is_empty() {
                        // Authenticated but zone access not yet fetched — show loading
                        if authed && !za_loaded.get() {
                            return view! {
                                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
                                    <ZoneSkeleton/>
                                    <ZoneSkeleton/>
                                    <ZoneSkeleton/>
                                </div>
                            }.into_any();
                        }

                        // Authenticated but no accessible zones — pending approval
                        if authed {
                            let clock_icon: Box<dyn FnOnce() -> leptos::prelude::AnyView + Send> = Box::new(|| view! {
                                <svg class="w-7 h-7 text-amber-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                    <circle cx="12" cy="12" r="10"/>
                                    <polyline points="12 6 12 12 16 14"/>
                                </svg>
                            }.into_any());
                            return view! {
                                <EmptyState
                                    icon=clock_icon
                                    title="Awaiting zone access".to_string()
                                    description="Your account is set up. An admin will grant you zone access shortly.".to_string()
                                />
                            }.into_any();
                        }

                        // Not authenticated — sign in prompt
                        let lock_icon: Box<dyn FnOnce() -> leptos::prelude::AnyView + Send> = Box::new(|| view! {
                            <svg class="w-7 h-7 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                <path d="M16 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
                                <circle cx="8.5" cy="7" r="4"/>
                                <line x1="20" y1="8" x2="20" y2="14"/>
                                <line x1="23" y1="11" x2="17" y2="11"/>
                            </svg>
                        }.into_any());
                        return view! {
                            <EmptyState
                                icon=lock_icon
                                title="Sign in to get started".to_string()
                                description="Create an account or log in to access the community forums.".to_string()
                            />
                        }.into_any();
                    }

                    rendered.into_iter().collect_view().into_any()
                }}
            </Show>
        </div>
    }
}

// -- Tile builders ------------------------------------------------------------

/// Render a normal, openable section tile for a member/public zone.
///
/// The tile is headed by the zone's `banner_image_url` (responsive, lazy,
/// `alt = display_name`) and lists the zone's category cards below. When the
/// zone has no topics yet it shows an "enter" link instead.
fn zone_tile(
    zone: &Zone,
    cats: HashMap<String, SectionCounts>,
    sec_meta: &HashMap<String, (String, String)>,
) -> AnyView {
    let zone_id = zone.id.clone();
    // URL slug (never the raw immutable zone id) fed to each CategoryCard's
    // href — the zone id keys existing posted content and channel `section`
    // tags and must never change, but the *emitted* URL should read
    // `/welcome/…` rather than `/zone1/…` when a slug alias is configured.
    let zone_slug = crate::stores::zones::zone_slug(zone).to_string();
    let label = zone.label();
    let label_alt = label.clone();
    // Issue #43: one accent hex, config-first (operator `accent_hex` when set,
    // else the built-in palette), drives the tile border/gradient, the accent
    // edge stripe, the heading colour and every category card — so a zone reads
    // as one colour end-to-end instead of a hash-picked Tailwind palette that
    // ignored config and could clash with the drill-down pages.
    let accent_hex = resolved_accent_hex(&zone.id, zone.accent_hex.as_deref());
    let tile_style = zone_tile_style(&accent_hex);
    let edge_style = format!("background: {}", accent_hex);
    let heading_style = format!("color: {}", accent_hex);
    let banner = zone.banner_image_url.clone().unwrap_or_default();
    let has_banner = !banner.is_empty();
    let has_cats = !cats.is_empty();
    // The zone's channel-list page (CategoryPage). The banner links here so a
    // single click on a zone always lands on its list of channels, never deep
    // inside one channel's linear chat.
    let zone_href = base_href(&format!(
        "/{}",
        crate::stores::zones::zone_path_for_id(&zone_id)
    ));

    let cards_view = if has_cats {
        let mut entries: Vec<(String, SectionCounts)> = cats.into_iter().collect();
        // Order: operator-pinned sections (zone.section_order) first, in that
        // order (lets a "primary" section like rants sit at the top of the zone
        // tile); every other section falls to alphabetical after them. Empty
        // section_order ⇒ the historic all-alphabetical order.
        entries.sort_by(|a, b| crate::stores::zones::section_cmp(&a.0, &b.0, &zone.section_order));
        let cards: Vec<_> = entries
            .into_iter()
            .map(|(section_id, counts)| {
                // Prefer the live channel name/description (kind-40/41, folds
                // admin renames — issue #44) when the section maps to exactly
                // one channel; otherwise humanize the section id and fall back
                // to the static description.
                let (display_name, description) = match sec_meta.get(&section_id) {
                    Some((name, desc)) if !desc.is_empty() => (name.clone(), desc.clone()),
                    Some((name, _)) => (name.clone(), section_description(&section_id).to_string()),
                    None => (
                        humanize_section_id(&section_id),
                        section_description(&section_id).to_string(),
                    ),
                };
                view! {
                    <CategoryCard
                        name=display_name
                        description=description
                        section_id=section_id
                        icon="sparkle"
                        post_count=counts.total
                        unread_count=counts.unread
                        accent_hex=accent_hex.clone()
                        zone_slug=zone_slug.clone()
                        zone_label=label.clone()
                    />
                }
            })
            .collect();
        view! {
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                {cards.into_iter().collect_view()}
            </div>
        }
        .into_any()
    } else {
        // Tint the empty-zone CTA with the zone accent too, so an empty zone
        // still reads in its own colour rather than a hardcoded amber.
        let cta_style = format!("color: {}", accent_hex);
        view! {
            <A href=zone_href.clone() attr:class="block glass-card-interactive p-4 text-center no-underline text-inherit">
                <p class="text-gray-400 text-sm mb-2">"No topics yet"</p>
                <span class="font-medium text-sm hover:opacity-80 transition-opacity" style=cta_style>
                    "Enter & start a conversation →"
                </span>
            </A>
        }
        .into_any()
    };

    view! {
        <section class="mb-10">
            // Banner-headed zone card. The whole banner links to the zone's
            // channel list (CategoryPage at /forums/{zone}); the section cards
            // below are deep-link shortcuts straight into a single channel.
            <A href=zone_href attr:class="block mb-4 no-underline text-inherit group">
                <div
                    class="relative rounded-2xl overflow-hidden border backdrop-blur-sm transition group-hover:ring-1 group-hover:ring-white/20"
                    style=tile_style
                >
                    // Accent edge — unmistakable zone identity at a glance
                    // (issue #43): a thin solid stripe down the left in the
                    // zone accent. The zone NAME text below stays the primary
                    // label, so colour is never the only signal (WCAG 1.4.1).
                    <div class="absolute inset-y-0 left-0 w-1 z-20 pointer-events-none" style=edge_style></div>
                    {has_banner.then(|| view! {
                        <img
                            src=banner.clone()
                            alt=label_alt
                            class="w-full h-40 sm:h-48 object-cover"
                            loading="lazy"
                        />
                        <div class="absolute inset-0 bg-gradient-to-t from-gray-900/90 via-gray-900/40 to-transparent pointer-events-none"></div>
                    })}
                    <div class=move || if has_banner {
                        "absolute bottom-0 left-0 right-0 z-10 p-5"
                    } else {
                        "relative z-10 p-6"
                    }>
                        <h2 class="text-xl sm:text-2xl font-bold" style=heading_style>{label}</h2>
                        <span class="text-sm text-gray-300 group-hover:text-white transition-colors">
                            "View channels →"
                        </span>
                    </div>
                </div>
            </A>

            {cards_view}
        </section>
    }
    .into_any()
}

/// Render a greyed, non-openable locked tile for a `visibility = locked` zone
/// the user is not a member of. Shows the banner (desaturated), the name, and a
/// lock affordance. There is no entry route — the relay would refuse anyway.
fn locked_tile(zone: &Zone) -> AnyView {
    let label = zone.label();
    let label_aria = format!("{} (locked)", label);
    let label_alt = label.clone();
    let banner = zone.banner_image_url.clone().unwrap_or_default();
    let has_banner = !banner.is_empty();

    view! {
        <section class="mb-10" aria-label=label_aria>
            <div class="relative rounded-2xl overflow-hidden border border-gray-700/60 bg-gray-800/40 cursor-not-allowed select-none">
                {has_banner.then(|| view! {
                    <img
                        src=banner.clone()
                        alt=label_alt
                        class="w-full h-40 sm:h-48 object-cover grayscale opacity-30"
                        loading="lazy"
                    />
                })}
                <div class="absolute inset-0 bg-gray-900/70 pointer-events-none"></div>
                <div class="absolute inset-0 z-10 flex flex-col items-center justify-center text-center p-5 gap-2">
                    <div class="w-11 h-11 rounded-full bg-gray-700/70 flex items-center justify-center">
                        <svg class="w-5 h-5 text-gray-300" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                            <path d="M7 11V7a5 5 0 0110 0v4"/>
                        </svg>
                    </div>
                    <h2 class="text-lg sm:text-xl font-bold text-gray-200">{label}</h2>
                    <span class="text-xs text-gray-400 uppercase tracking-wide">"Locked"</span>
                </div>
                // Reserve height when there is no banner so the tile still has body.
                {(!has_banner).then(|| view! { <div class="h-40 sm:h-48"></div> })}
            </div>
        </section>
    }
    .into_any()
}

/// Convert a section ID like "private-welcome" to "Welcome".
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

/// Human-friendly descriptions for known section IDs.
fn section_description(id: &str) -> &'static str {
    match id {
        "private-welcome" => "Welcome info for guests",
        "private-events" => "Upcoming events and activities",
        "private-booking" => "Room availability and reservations",
        "home-lobby" => "General discussion and introductions",
        "members-training" => "Training courses and materials",
        "members-projects" => "Active projects and collaboration",
        "members-bookings" => "Session and room bookings",
        "ai-general" => "General AI discussion",
        "ai-claude-flow" => "Claude Flow agent coordination",
        "ai-visionflow" => "VisionFlow AI agents",
        _ => "Browse topics in this section",
    }
}

#[component]
fn ZoneSkeleton() -> impl IntoView {
    view! {
        <div class="glass-card p-6">
            <div class="flex gap-3 mb-4">
                <div class="w-10 h-10 rounded-lg skeleton"></div>
                <div class="flex-1 space-y-2">
                    <div class="h-5 skeleton rounded w-1/3"></div>
                    <div class="h-3 skeleton rounded w-2/3"></div>
                </div>
            </div>
            <div class="h-24 skeleton rounded-lg"></div>
        </div>
    }
}
