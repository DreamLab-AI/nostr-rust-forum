//! Channel card component for the channel list page.

use leptos::prelude::*;
use leptos_router::components::A;

use crate::app::base_href;
use crate::stores::read_position::use_read_positions;
use crate::utils::format_relative_time;

/// Props for the ChannelCard component.
#[derive(Clone, Debug)]
pub struct ChannelInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub section: String,
    #[allow(dead_code)]
    pub picture: String,
    pub message_count: u32,
    pub last_active: u64,
}

/// Display a single channel as a card in the channel list.
#[component]
pub fn ChannelCard(channel: ChannelInfo) -> impl IntoView {
    let href = base_href(&format!("/chat/{}", channel.id));
    let last_active_display = format_relative_time(channel.last_active);
    let has_messages = channel.last_active > 0;
    let msg_count_label = if channel.message_count == 1 {
        "1 post".to_string()
    } else {
        format!("{} posts", channel.message_count)
    };

    let (icon, icon_color) = get_section_icon(&channel.name);
    let icon_bg_class = format!(
        "w-12 h-12 rounded-lg flex items-center justify-center text-lg font-bold {}",
        icon_color
    );
    let name = channel.name.clone();
    let section = channel.section.clone();
    let description = channel.description.clone();
    let has_section = !section.is_empty();
    let has_description = !description.is_empty();
    let section_badge_class = get_section_badge_class(&section);

    // Unread badge from read-position store
    let read_store = use_read_positions();
    let unread = read_store.unread_count_signal(channel.id.clone());

    view! {
        <A href=href attr:class="block bg-gray-800 hover:bg-gray-750 border border-gray-700 hover:border-amber-500/30 rounded-lg transition-all duration-200 no-underline text-inherit hover:-translate-y-0.5 hover:shadow-lg hover:shadow-amber-500/5">
            <div class="p-4">
                <div class="flex gap-4">
                    // Category icon
                    <div class="flex-shrink-0">
                        <div class=icon_bg_class>
                            {icon}
                        </div>
                    </div>

                    // Channel info
                    <div class="flex-1 min-w-0">
                        <div class="flex items-start justify-between gap-2">
                            <div class="flex-1">
                                <div class="flex items-center gap-2 flex-wrap">
                                    <h3 class="font-bold text-white truncate">
                                        {name}
                                    </h3>
                                    {has_section.then(|| view! {
                                        <span class=section_badge_class>
                                            {section}
                                        </span>
                                    })}
                                </div>
                                {has_description.then(|| view! {
                                    <p class="text-sm text-gray-400 truncate mt-0.5">
                                        {description}
                                    </p>
                                })}
                            </div>

                            // Stats + unread badge
                            <div class="flex flex-col items-end gap-1 flex-shrink-0">
                                {move || {
                                    let count = unread.get();
                                    (count > 0).then(|| view! {
                                        <span class="inline-flex items-center justify-center min-w-[20px] h-5 px-1.5 text-xs font-bold text-gray-900 bg-amber-400 rounded-full">
                                            {if count > 99 { "99+".to_string() } else { count.to_string() }}
                                        </span>
                                    })
                                }}
                                <span class="text-xs text-amber-400 bg-amber-500/10 rounded px-2 py-0.5 font-medium">
                                    {msg_count_label}
                                </span>
                            </div>
                        </div>

                        // Last active
                        <div class="mt-2 pt-2 border-t border-gray-700 text-xs text-gray-500">
                            {if has_messages {
                                format!("Last active: {}", last_active_display)
                            } else {
                                "No messages yet — be the first to post!".to_string()
                            }}
                        </div>
                    </div>
                </div>
            </div>
        </A>
    }
}

/// Map channel name keywords to an icon character and Tailwind color class.
/// Returns (icon, "bg-{color}/10 text-{color}") pair.
fn get_section_icon(name: &str) -> (&'static str, &'static str) {
    let lower = name.to_lowercase();
    if lower.contains("general") {
        return ("G", "bg-blue-500/10 text-blue-400");
    }
    if lower.contains("music") || lower.contains("tuneage") {
        return ("M", "bg-pink-500/10 text-pink-400");
    }
    if lower.contains("event") || lower.contains("calendar") {
        return ("E", "bg-green-500/10 text-green-400");
    }
    if lower.contains("help") || lower.contains("support") {
        return ("?", "bg-purple-500/10 text-purple-400");
    }
    if lower.contains("announce") || lower.contains("news") {
        return ("!", "bg-amber-500/10 text-amber-400");
    }
    if lower.contains("random") || lower.contains("offtopic") {
        return ("~", "bg-indigo-500/10 text-indigo-400");
    }
    if lower.contains("tech") || lower.contains("dev") {
        return ("<>", "bg-cyan-500/10 text-cyan-400");
    }
    ("#", "bg-gray-500/10 text-gray-400")
}

/// Return a Tailwind class string for the section badge, colorized by section name.
fn get_section_badge_class(section: &str) -> String {
    let lower = section.to_lowercase();
    let color_classes = if lower.contains("general") {
        "text-blue-400 border-blue-500/30 bg-blue-500/5"
    } else if lower.contains("music") {
        "text-pink-400 border-pink-500/30 bg-pink-500/5"
    } else if lower.contains("event") {
        "text-green-400 border-green-500/30 bg-green-500/5"
    } else if lower.contains("tech") {
        "text-cyan-400 border-cyan-500/30 bg-cyan-500/5"
    } else if lower.contains("announce") {
        "text-amber-400 border-amber-500/30 bg-amber-500/5"
    } else if lower.contains("support") || lower.contains("help") {
        "text-purple-400 border-purple-500/30 bg-purple-500/5"
    } else if lower.contains("random") {
        "text-indigo-400 border-indigo-500/30 bg-indigo-500/5"
    } else {
        "text-gray-500 border-gray-600 bg-transparent"
    };
    format!("text-xs border rounded px-1.5 py-0.5 {}", color_classes)
}
