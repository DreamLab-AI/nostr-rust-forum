//! Section list card component for the category browsing page.
//!
//! Renders a compact card for a single forum section with name, description,
//! message count, last activity timestamp, and a "new" badge for recent posts.

use leptos::prelude::*;
use leptos_router::components::A;

use crate::app::base_href;
use crate::utils::format_relative_time;

/// Card representing a section within a category.
#[component]
pub fn SectionCard(
    /// Display name of the section.
    name: String,
    /// Section description text.
    description: String,
    /// Nostr channel event id for this section.
    channel_id: String,
    /// Number of messages in this section.
    message_count: u32,
    /// Unix timestamp of the most recent message (0 = no messages).
    last_activity: u64,
    /// Parent category slug for building the href.
    category: String,
) -> impl IntoView {
    let section_slug = slugify(&name);
    let href = base_href(&format!("/forums/{}/{}", category, section_slug));

    let has_messages = last_activity > 0;
    let activity_display = format_relative_time(last_activity);

    let msg_label = if message_count == 1 {
        "1 message".to_string()
    } else {
        format!("{} messages", message_count)
    };

    // "New" badge: show if last activity was within the past 24 hours
    let is_recent = {
        let now = (js_sys::Date::now() / 1000.0) as u64;
        last_activity > 0 && now.saturating_sub(last_activity) < 86400
    };

    let has_desc = !description.is_empty();

    view! {
        <A href=href attr:class="block section-list-card no-underline text-inherit group">
            <div class="flex items-start justify-between gap-3">
                <div class="flex-1 min-w-0">
                    <div class="flex items-center gap-2 flex-wrap">
                        // Section icon
                        <div class="w-6 h-6 rounded flex items-center justify-center bg-amber-500/10 text-amber-400 flex-shrink-0">
                            <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        </div>
                        <h3 class="font-semibold text-white group-hover:text-amber-400 transition-colors truncate">
                            {name}
                        </h3>
                        {is_recent.then(|| view! {
                            <span class="text-[10px] font-bold uppercase tracking-wider text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 rounded px-1.5 py-0.5">
                                "new"
                            </span>
                        })}
                    </div>
                    {has_desc.then(|| view! {
                        <p class="text-sm text-gray-400 mt-1 truncate pl-8">{description}</p>
                    })}
                </div>

                // Stats badge
                <div class="flex-shrink-0 text-right">
                    <span class="text-xs text-amber-400 bg-amber-500/10 rounded px-2 py-0.5 font-medium">
                        {msg_label}
                    </span>
                </div>
            </div>

            // Bottom stats row
            <div class="mt-2 pt-2 border-t border-gray-700/50 flex items-center gap-4 pl-8 text-xs text-gray-500">
                <span class="flex items-center gap-1">
                    <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"/>
                        <polyline points="12 6 12 12 16 14"/>
                    </svg>
                    {if has_messages {
                        activity_display
                    } else {
                        "No activity yet".to_string()
                    }}
                </span>
                <span class="text-gray-600 font-mono text-[10px] hidden sm:inline" title=channel_id.clone()>
                    {format!("{}...", &channel_id[..8.min(channel_id.len())])}
                </span>
            </div>
        </A>
    }
}

/// Convert a section name to a URL slug.
fn slugify(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|seg| !seg.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}
