//! Category hero card component for the forum index page.
//!
//! Renders a visually rich card with themed gradient, watermark icon,
//! aurora shimmer, and section count badge. Navigates to the category
//! page on click.

use leptos::prelude::*;
use leptos_router::components::A;

use crate::app::base_href;
use crate::utils::slug_hash::section_slug;
use crate::utils::zone_theme::hex_rgba;

/// Visually rich card representing a forum category.
#[component]
pub fn CategoryCard(
    /// Display name of the category.
    name: String,
    /// Short description text.
    description: String,
    /// Raw section tag for this category group (e.g. "home-lobby"). Hashed into
    /// the URL slug (#9) so the section tag/name never appears in the address.
    section_id: String,
    /// Icon identifier: "globe", "users", "code", or "shield".
    icon: &'static str,
    /// Total post count across all channels in this section.
    post_count: u32,
    /// Number of posts newer than the user's last-read position across the
    /// section's channels (issue #24). When > 0 a bright "N new" chip is shown
    /// alongside the muted total chip; when 0 the chip is omitted. Defaults to 0
    /// so callers that don't track read state keep their existing rendering.
    #[prop(default = 0)]
    unread_count: u32,
    /// Resolved zone accent hex (`#rrggbb`), config-first (issue #43). Every
    /// tint on the card — gradient overlay, count badge, watermark and header
    /// icon — is derived from this one value via [`hex_rgba`], so the card
    /// always matches its zone's tile instead of a hash-picked palette.
    accent_hex: String,
    /// URL slug for the parent zone — its configured `slug`
    /// ([`crate::stores::zones::zone_slug`]) or, absent that, its immutable
    /// `id`. Used to build the href; callers must resolve this from the zone,
    /// never pass the raw internal zone id directly, so URLs read `/welcome/…`
    /// rather than `/zone1/…` when a slug alias is configured.
    zone_slug: String,
    /// Human-readable zone label (the operator `display_name`, or a humanised
    /// id when absent) shown in the card's watermark badge.
    zone_label: String,
    /// Optional picture URL for background image.
    #[prop(optional, into)]
    picture: String,
) -> impl IntoView {
    // #9: the section tag is hashed into the URL — its plaintext (which can
    // reveal the section name) never appears in the address bar. The section
    // page resolves the hash back to the real channel for display.
    let href = base_href(&format!("/{}/{}", zone_slug, section_slug(&section_id)));

    // Inline styles derived from the single resolved accent hex (issue #43),
    // replacing the old per-key Tailwind class tables. Alphas mirror the weights
    // the classes carried: gradient ~0.20/0.10, badge fill 0.15 / border 0.30,
    // watermark 0.10. Any unparseable hex degrades to empty (harmless CSS).
    let gradient_style = format!(
        "background: linear-gradient(to bottom right, {}, {} 50%, transparent);",
        hex_rgba(&accent_hex, 0.20).unwrap_or_default(),
        hex_rgba(&accent_hex, 0.10).unwrap_or_default(),
    );

    let badge_style = format!(
        "background: {}; color: {}; border-color: {};",
        hex_rgba(&accent_hex, 0.15).unwrap_or_default(),
        accent_hex,
        hex_rgba(&accent_hex, 0.30).unwrap_or_default(),
    );

    let watermark_style = format!(
        "color: {};",
        hex_rgba(&accent_hex, 0.10).unwrap_or_default()
    );

    let count_label = if post_count == 0 {
        "No posts yet".to_string()
    } else if post_count == 1 {
        "1 post".to_string()
    } else {
        format!("{} posts", post_count)
    };

    // Bright "N new" chip (issue #24). Solid zone accent (issue #43) so unread
    // activity stands out against the muted total-count chip when scanning the
    // index; hidden when there is nothing new. `aria-label` is for screen readers.
    let has_unread = unread_count > 0;
    let unread_label = format!("{} new", unread_count);
    let unread_aria = format!(
        "{} unread post{}",
        unread_count,
        if unread_count == 1 { "" } else { "s" }
    );

    let name_display = name.clone();
    let desc_display = description.clone();
    let has_picture = !picture.is_empty();

    view! {
        <A href=href attr:class="block category-hero-card glass-card-interactive aurora-shimmer no-underline text-inherit">
            // Background image (when picture URL is available)
            {has_picture.then(|| {
                let pic = picture.clone();
                view! {
                    <img
                        src=pic
                        alt=""
                        class="absolute inset-0 w-full h-full object-cover rounded-xl opacity-20 pointer-events-none"
                        loading="lazy"
                    />
                    <div class="absolute inset-0 bg-gray-900/60 rounded-xl pointer-events-none"></div>
                }
            })}

            // Background gradient overlay
            <div class="absolute inset-0 pointer-events-none" style=gradient_style></div>

            // Watermark icon (large, semi-transparent) -- only when no image
            {(!has_picture).then(|| {
                view! {
                    <div class="absolute -right-4 -bottom-4 pointer-events-none" style=watermark_style>
                        <WatermarkIcon icon=icon/>
                    </div>
                }
            })}

            // Content
            <div class="relative z-10 p-5 flex flex-col justify-between min-h-[160px]">
                <div>
                    <div class="flex items-center gap-2 mb-2">
                        <CardIcon icon=icon accent_hex=accent_hex.clone()/>
                        <h3 class="text-lg font-bold text-white">{name_display}</h3>
                    </div>
                    <p class="text-sm text-gray-300 line-clamp-2 leading-relaxed">{desc_display}</p>
                </div>

                <div class="flex items-center justify-between mt-4">
                    <div class="flex items-center gap-2">
                        <span class="text-xs font-medium border rounded-full px-2.5 py-0.5" style=badge_style>
                            {count_label}
                        </span>
                        {has_unread.then(|| view! {
                            <span
                                class="inline-flex items-center gap-1 text-xs font-semibold rounded-full px-2.5 py-0.5 za-solid text-gray-900 shadow-sm animate-pulse"
                                aria-label=unread_aria
                            >
                                <span class="w-1.5 h-1.5 rounded-full bg-gray-900/70" aria-hidden="true"></span>
                                {unread_label}
                            </span>
                        })}
                    </div>
                    <span class="text-xs text-gray-500">
                        {zone_label}
                    </span>
                </div>
            </div>
        </A>
    }
}

/// Small inline icon for the card header.
#[component]
fn CardIcon(icon: &'static str, accent_hex: String) -> impl IntoView {
    // Wrapper carries the accent (issue #43): a faint accent fill plus
    // `color: <hex>` so the SVG's `stroke="currentColor"` picks up the accent
    // without threading a per-icon style through every match arm.
    let wrapper_style = format!(
        "background: {}; color: {};",
        hex_rgba(&accent_hex, 0.15).unwrap_or_default(),
        accent_hex,
    );

    let svg = match icon {
        "globe" => view! {
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <circle cx="12" cy="12" r="10"/>
                <path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10A15.3 15.3 0 0112 2z"/>
            </svg>
        }.into_any(),
        "users" => view! {
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
                <circle cx="9" cy="7" r="4"/>
                <path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/>
            </svg>
        }.into_any(),
        "code" => view! {
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <polyline points="16 18 22 12 16 6"/>
                <polyline points="8 6 2 12 8 18"/>
            </svg>
        }.into_any(),
        "shield" => view! {
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
        }.into_any(),
        "home" => view! {
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z" stroke-linecap="round" stroke-linejoin="round"/>
                <polyline points="9 22 9 12 15 12 15 22" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        "moon" => view! {
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        "sparkle" => view! {
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M12 2l2.4 7.2L22 12l-7.6 2.8L12 22l-2.4-7.2L2 12l7.6-2.8L12 2z" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        "bot" => view! {
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <rect x="3" y="11" width="18" height="10" rx="2" stroke-linecap="round" stroke-linejoin="round"/>
                <circle cx="12" cy="5" r="2" stroke-linecap="round"/>
                <path d="M12 7v4" stroke-linecap="round"/>
                <line x1="8" y1="16" x2="8" y2="16" stroke-linecap="round" stroke-width="2"/>
                <line x1="16" y1="16" x2="16" y2="16" stroke-linecap="round" stroke-width="2"/>
            </svg>
        }.into_any(),
        _ => view! { <span class="text-xs text-gray-400">"?"</span> }.into_any(),
    };

    view! {
        <div class="w-8 h-8 rounded-lg flex items-center justify-center" style=wrapper_style>{svg}</div>
    }
}

/// Large watermark SVG icon rendered behind the card content.
#[component]
fn WatermarkIcon(icon: &'static str) -> impl IntoView {
    match icon {
        "globe" => view! {
            <svg class="w-28 h-28" viewBox="0 0 24 24" fill="currentColor" stroke="none">
                <circle cx="12" cy="12" r="10" fill-opacity="0.5"/>
                <path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10A15.3 15.3 0 0112 2z" fill="none" stroke="currentColor" stroke-width="0.5"/>
            </svg>
        }.into_any(),
        "users" => view! {
            <svg class="w-28 h-28" viewBox="0 0 24 24" fill="currentColor" stroke="none">
                <circle cx="9" cy="7" r="4" fill-opacity="0.5"/>
                <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2" fill-opacity="0.3"/>
            </svg>
        }.into_any(),
        "code" => view! {
            <svg class="w-28 h-28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="0.8">
                <polyline points="16 18 22 12 16 6"/>
                <polyline points="8 6 2 12 8 18"/>
            </svg>
        }.into_any(),
        "shield" => view! {
            <svg class="w-28 h-28" viewBox="0 0 24 24" fill="currentColor" stroke="none">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill-opacity="0.4"/>
            </svg>
        }.into_any(),
        "home" => view! {
            <svg class="w-28 h-28" viewBox="0 0 24 24" fill="currentColor" stroke="none">
                <path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z" fill-opacity="0.4"/>
            </svg>
        }.into_any(),
        "moon" => view! {
            <svg class="w-28 h-28" viewBox="0 0 24 24" fill="currentColor" stroke="none">
                <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z" fill-opacity="0.4"/>
            </svg>
        }.into_any(),
        "sparkle" => view! {
            <svg class="w-28 h-28" viewBox="0 0 24 24" fill="currentColor" stroke="none">
                <path d="M12 2l2.4 7.2L22 12l-7.6 2.8L12 22l-2.4-7.2L2 12l7.6-2.8L12 2z" fill-opacity="0.4"/>
            </svg>
        }.into_any(),
        "bot" => view! {
            <svg class="w-28 h-28" viewBox="0 0 24 24" fill="currentColor" stroke="none">
                <rect x="3" y="11" width="18" height="10" rx="2" fill-opacity="0.4"/>
                <circle cx="12" cy="5" r="2" fill-opacity="0.3"/>
            </svg>
        }.into_any(),
        _ => view! { <span></span> }.into_any(),
    }
}
