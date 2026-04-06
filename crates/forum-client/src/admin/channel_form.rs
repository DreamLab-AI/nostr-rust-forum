//! Channel creation form component for the admin panel.
//!
//! Provides a form with name, description, and section dropdown. Validates that
//! the name is at least 3 characters before enabling submission.

use leptos::prelude::*;


/// Predefined channel sections.
/// Format: (section_id, display_label).
const SECTIONS: &[(&str, &str)] = &[
    // Home
    ("public-lobby", "Home Lobby"),
    // Nostr BBS
    ("members-training", "Nostr BBS Training"),
    ("members-projects", "Nostr BBS Projects"),
    ("members-bookings", "Nostr BBS Bookings"),
    ("ai-general", "AI General"),
    ("ai-claude-flow", "AI Claude Flow"),
    ("ai-visionflow", "AI VisionFlow"),
    // Private
    ("private-welcome", "Private Welcome"),
    ("private-events", "Private Events"),
    ("private-booking", "Private Booking"),
];

/// Data submitted from the channel creation form.
#[derive(Clone, Debug)]
pub struct ChannelFormData {
    pub name: String,
    pub description: String,
    pub section: String,
    pub picture: String,
    pub zone: u8,
    pub cohort: Option<String>,
}

/// Channel creation form. Calls `on_submit` with the validated form data.
#[component]
pub fn ChannelForm<F>(on_submit: F) -> impl IntoView
where
    F: Fn(ChannelFormData) + 'static,
{
    let name = RwSignal::new(String::new());
    let description = RwSignal::new(String::new());
    let picture = RwSignal::new(String::new());
    let section = RwSignal::new(SECTIONS[0].0.to_string());
    let zone = RwSignal::new(0u8);
    let cohort = RwSignal::new(String::new());
    let validation_error = RwSignal::new(Option::<String>::None);
    let is_submitting = RwSignal::new(false);

    let is_valid = Memo::new(move |_| {
        let n = name.get();
        n.trim().len() >= 3
    });

    let on_name_input = move |ev: leptos::ev::Event| {
        let target = event_target_value(&ev);
        name.set(target);
        validation_error.set(None);
    };

    let on_desc_input = move |ev: leptos::ev::Event| {
        let target = event_target_value(&ev);
        description.set(target);
    };

    let on_picture_input = move |ev: leptos::ev::Event| {
        let target = event_target_value(&ev);
        picture.set(target);
    };

    let on_section_change = move |ev: leptos::ev::Event| {
        let target = event_target_value(&ev);
        section.set(target);
    };

    let on_zone_change = move |ev: leptos::ev::Event| {
        let val = event_target_value(&ev);
        zone.set(val.parse::<u8>().unwrap_or(0));
        // Clear cohort when switching to Public or Registered
        if zone.get_untracked() < 2 {
            cohort.set(String::new());
        }
    };

    let on_cohort_input = move |ev: leptos::ev::Event| {
        let target = event_target_value(&ev);
        cohort.set(target);
    };

    let on_form_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();

        let n = name.get_untracked();
        if n.trim().len() < 3 {
            validation_error.set(Some("Channel name must be at least 3 characters".into()));
            return;
        }

        is_submitting.set(true);
        let z = zone.get_untracked();
        let c = cohort.get_untracked();
        on_submit(ChannelFormData {
            name: n.trim().to_string(),
            description: description.get_untracked().trim().to_string(),
            section: section.get_untracked(),
            picture: picture.get_untracked().trim().to_string(),
            zone: z,
            cohort: if z >= 2 && !c.trim().is_empty() { Some(c.trim().to_string()) } else { None },
        });
        is_submitting.set(false);
        // Form reset is handled by the parent when it signals success via callback.
    };

    view! {
        <form
            on:submit=on_form_submit
            class="bg-gray-800 border border-gray-700 rounded-lg p-6 space-y-4"
        >
            <h3 class="text-lg font-semibold text-white flex items-center gap-2">
                {plus_circle_icon()}
                "Create Channel"
            </h3>

            // Name input
            <div class="space-y-1">
                <label for="channel-name" class="block text-sm font-medium text-gray-300">
                    "Channel Name"
                </label>
                <input
                    id="channel-name"
                    type="text"
                    maxlength="64"
                    prop:value=move || name.get()
                    on:input=on_name_input
                    placeholder="e.g. music-production"
                    class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors"
                />
                <div class="flex items-center justify-between">
                    {move || {
                        validation_error.get().map(|msg| view! {
                            <p class="text-red-400 text-sm">{msg}</p>
                        })
                    }}
                    <span class="text-xs text-gray-600 ml-auto">
                        {move || format!("{}/64", name.get().len())}
                    </span>
                </div>
            </div>

            // Description input
            <div class="space-y-1">
                <label for="channel-desc" class="block text-sm font-medium text-gray-300">
                    "Description"
                </label>
                <textarea
                    id="channel-desc"
                    prop:value=move || description.get()
                    on:input=on_desc_input
                    placeholder="What is this channel about?"
                    rows="3"
                    class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors resize-none"
                />
            </div>

            // Picture URL input
            <div class="space-y-1">
                <label for="channel-picture" class="block text-sm font-medium text-gray-300">
                    "Picture URL"
                </label>
                <input
                    id="channel-picture"
                    type="url"
                    maxlength="512"
                    prop:value=move || picture.get()
                    on:input=on_picture_input
                    placeholder="https://example.com/image.webp"
                    class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors"
                />
                <p class="text-xs text-gray-500">"Optional cover image URL for the channel card."</p>
            </div>

            // Section dropdown
            <div class="space-y-1">
                <label for="channel-section" class="block text-sm font-medium text-gray-300">
                    "Section"
                </label>
                <select
                    id="channel-section"
                    on:change=on_section_change
                    class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors"
                >
                    {SECTIONS.iter().map(|&(id, label)| {
                        let value = id.to_string();
                        let display = label.to_string();
                        view! {
                            <option value=value.clone() selected=move || section.get() == value>
                                {display}
                            </option>
                        }
                    }).collect_view()}
                </select>
                // Color indicator for selected section
                <div class="flex items-center gap-1.5 mt-1">
                    <span class=move || section_color_dot_class(&section.get())></span>
                    <span class="text-xs text-gray-500">
                        {move || {
                            let s = section.get();
                            let label = SECTIONS.iter()
                                .find(|&&(id, _)| id == s)
                                .map(|&(_, l)| l)
                                .unwrap_or(&s);
                            format!("Section: {}", label)
                        }}
                    </span>
                </div>
            </div>

            // Zone dropdown
            <div class="space-y-1">
                <label for="channel-zone" class="block text-sm font-medium text-gray-300">
                    "Access Zone"
                </label>
                <select
                    id="channel-zone"
                    on:change=on_zone_change
                    class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors"
                >
                    <option value="0" selected=move || zone.get() == 0>"Public"</option>
                    <option value="1" selected=move || zone.get() == 1>"Registered"</option>
                    <option value="2" selected=move || zone.get() == 2>"Cohort"</option>
                    <option value="3" selected=move || zone.get() == 3>"Private"</option>
                </select>
                <div class="flex items-center gap-1.5 mt-1">
                    <span class=move || zone_color_dot_class(zone.get())></span>
                    <span class="text-xs text-gray-500">
                        {move || match zone.get() { 0 => "Public", 1 => "Registered", 2 => "Cohort", _ => "Private" }}
                    </span>
                </div>
            </div>

            // Cohort input (shown only for zone >= 2)
            <Show when=move || { zone.get() >= 2 }>
                <div class="space-y-1">
                    <label for="channel-cohort" class="block text-sm font-medium text-gray-300">
                        "Required Cohort"
                    </label>
                    <input
                        id="channel-cohort"
                        type="text"
                        maxlength="64"
                        prop:value=move || cohort.get()
                        on:input=on_cohort_input
                        placeholder="e.g. music, vip, moderator"
                        class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors"
                    />
                    <p class="text-xs text-gray-500">"Users must belong to this cohort to access the channel."</p>
                </div>
            </Show>

            // Submit button
            <button
                type="submit"
                disabled=move || !is_valid.get() || is_submitting.get()
                class="w-full bg-amber-500 hover:bg-amber-400 disabled:bg-gray-600 disabled:cursor-not-allowed text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors flex items-center justify-center gap-1.5"
            >
                {move || {
                    if is_submitting.get() { "Creating..." } else { "Create Channel" }
                }}
            </button>
        </form>
    }
}

/// Return a Tailwind class for a small colored dot representing the section.
/// Color is derived from the parent zone.
fn section_color_dot_class(section: &str) -> &'static str {
    match section {
        // Private (purple)
        s if s.starts_with("private-") => "w-2 h-2 rounded-full bg-purple-400 inline-block",
        // Nostr BBS and AI (pink)
        s if s.starts_with("members-") || s.starts_with("ai-") => "w-2 h-2 rounded-full bg-pink-400 inline-block",
        _ => "w-2 h-2 rounded-full bg-amber-400 inline-block",
    }
}

/// Return a Tailwind class for a small colored dot representing the zone.
fn zone_color_dot_class(zone: u8) -> &'static str {
    match zone {
        0 => "w-2 h-2 rounded-full bg-amber-400 inline-block",
        1 => "w-2 h-2 rounded-full bg-blue-400 inline-block",
        2 => "w-2 h-2 rounded-full bg-purple-400 inline-block",
        3 => "w-2 h-2 rounded-full bg-emerald-400 inline-block",
        _ => "w-2 h-2 rounded-full bg-gray-500 inline-block",
    }
}

// -- SVG icon helpers ---------------------------------------------------------

fn plus_circle_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="8" x2="12" y2="16"/>
            <line x1="8" y1="12" x2="16" y2="12"/>
        </svg>
    }
}
