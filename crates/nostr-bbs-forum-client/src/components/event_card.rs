//! Visually rich event card for the events listing page.
//!
//! Renders a glass card with a date badge, event details, host info,
//! and an RSVP button. Uses `event-card` / `event-date-badge` CSS
//! classes from `style.css` plus `glass-card-interactive` for hover lift.

use leptos::prelude::*;

use crate::components::agent_badge::AgentBadge;
use crate::components::avatar::{Avatar, AvatarSize};
use crate::components::user_display::use_display_name_memo;

/// Month abbreviations for date badge display.
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Whether this event is in the past (for dimming).
fn is_past(end_time: u64) -> bool {
    let now = (js_sys::Date::now() / 1000.0) as u64;
    end_time < now
}

/// Format a UNIX timestamp to "HH:MM".
fn format_time(ts: u64) -> String {
    let d = js_sys::Date::new_0();
    d.set_time((ts as f64) * 1000.0);
    format!("{:02}:{:02}", d.get_hours(), d.get_minutes())
}

/// Extract (month_abbrev, day_number) from a UNIX timestamp.
fn extract_date_parts(ts: u64) -> (String, u32) {
    let d = js_sys::Date::new_0();
    d.set_time((ts as f64) * 1000.0);
    let month_idx = d.get_month() as usize;
    let month = MONTHS.get(month_idx).unwrap_or(&"???");
    (month.to_string(), d.get_date())
}

/// Human-readable venue label for a free/busy venue slug.
///
/// Title-cases the slug generically: `fairfield` -> "Fairfield". Operators
/// supply venue display names via config; the kit never hardcodes brand labels.
fn venue_label(slug: &str) -> String {
    let lower = slug.to_ascii_lowercase();
    let mut chars = lower.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// A compact, opaque "busy" card for redacted free/busy calendar blocks.
///
/// Renders a muted/greyed block labelled "Busy" (or "Busy at <Venue>" when a
/// venue is known), showing only the real start–end time range parsed from the
/// `start`/`end` tags. No title, no description, no "details visible per tier"
/// string, and no RSVP affordances — the slot is booked, the detail is hidden.
#[component]
pub(crate) fn BusyCard(
    /// UNIX timestamp for the block start.
    start_time: u64,
    /// UNIX timestamp for the block end.
    end_time: u64,
    /// Venue slug (e.g. `fairfield`), empty when unknown.
    venue: String,
) -> impl IntoView {
    let past = is_past(end_time);
    let (month, day) = extract_date_parts(start_time);
    let time_range = format!("{} - {}", format_time(start_time), format_time(end_time));

    let label = if venue.trim().is_empty() {
        "Busy".to_string()
    } else {
        format!("Busy at {}", venue_label(&venue))
    };

    let card_class = format!(
        "event-card glass-card-interactive p-4 grayscale-[0.4] {}",
        if past { "opacity-60" } else { "opacity-80" },
    );

    view! {
        <div class=card_class aria-label="Busy — details hidden">
            <div class="flex gap-4">
                // Muted date badge
                <div class="event-date-badge flex flex-col items-center justify-center grayscale opacity-80">
                    <span class="text-gray-400 text-xs font-semibold uppercase tracking-wide">
                        {month}
                    </span>
                    <span class="text-gray-300 text-2xl font-bold leading-tight">
                        {day}
                    </span>
                </div>

                // Busy detail (no title, no description, no RSVP)
                <div class="flex-1 min-w-0 flex flex-col justify-center gap-1.5">
                    <div class="flex items-center gap-2">
                        <span class="inline-flex items-center justify-center w-5 h-5 rounded-md bg-gray-700/60 text-gray-400">
                            <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="3" y="11" width="18" height="11" rx="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <path d="M7 11V7a5 5 0 0110 0v4" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        </span>
                        <h3 class="text-gray-300 font-semibold text-base">{label}</h3>
                    </div>

                    <span class="inline-flex items-center gap-1 text-xs text-gray-500">
                        <svg class="w-3.5 h-3.5 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10" stroke-linecap="round" stroke-linejoin="round"/>
                            <polyline points="12 6 12 12 16 14" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                        {time_range}
                    </span>
                </div>
            </div>
        </div>
    }
}

/// A single event card with date badge, details, host, and RSVP button.
///
/// Uses the `event-card` class for base styling and `glass-card-interactive`
/// for the hover lift effect. Past events are rendered at reduced opacity.
#[component]
pub(crate) fn EventCard(
    /// Event title.
    title: String,
    /// Short description.
    description: String,
    /// UNIX timestamp for event start.
    start_time: u64,
    /// UNIX timestamp for event end.
    end_time: u64,
    /// Location string (e.g. "Virtual - Discord" or "London, UK").
    location: String,
    /// Host's hex pubkey.
    host_pubkey: String,
    /// Whether this event should have the aurora shimmer effect.
    #[prop(optional)]
    featured: bool,
) -> impl IntoView {
    let past = is_past(end_time);
    let (month, day) = extract_date_parts(start_time);
    let time_range = format!("{} - {}", format_time(start_time), format_time(end_time));
    // Reactive: fills in the host's nickname when the kind-0 metadata lands.
    let host_display = use_display_name_memo(host_pubkey.clone());
    // Disclosure badge (COM-13/F2): marks the event host as an agent and names
    // its authorising principal when the host pubkey is active in the registry.
    let host_badge_pubkey = host_pubkey.clone();

    let card_class = format!(
        "event-card glass-card-interactive p-4 {} {}",
        if past { "opacity-70" } else { "" },
        if featured { "aurora-shimmer" } else { "" },
    );

    view! {
        <div class=card_class>
            <div class="flex gap-4">
                // Date badge
                <div class="event-date-badge flex flex-col items-center justify-center">
                    <span class="text-amber-400 text-xs font-semibold uppercase tracking-wide">
                        {month}
                    </span>
                    <span class="text-white text-2xl font-bold leading-tight">
                        {day}
                    </span>
                </div>

                // Event details
                <div class="flex-1 min-w-0 space-y-2">
                    <h3 class="text-white font-bold text-lg truncate">{title}</h3>

                    <p class="text-gray-400 text-sm leading-relaxed line-clamp-2">
                        {description}
                    </p>

                    // Time and location row
                    <div class="flex flex-wrap items-center gap-3 text-xs text-gray-500">
                        // Time range
                        <span class="inline-flex items-center gap-1">
                            <svg class="w-3.5 h-3.5 text-amber-500/70" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10" stroke-linecap="round" stroke-linejoin="round"/>
                                <polyline points="12 6 12 12 16 14" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                            {time_range}
                        </span>

                        // Location with pin icon
                        <span class="inline-flex items-center gap-1">
                            <svg class="w-3.5 h-3.5 text-amber-500/70" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0118 0z" stroke-linecap="round" stroke-linejoin="round"/>
                                <circle cx="12" cy="10" r="3" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                            {location}
                        </span>
                    </div>

                    // Host + RSVP row
                    <div class="flex items-center justify-between pt-1">
                        <div class="flex items-center gap-2">
                            <Avatar pubkey=host_pubkey size=AvatarSize::Sm />
                            <span class="text-xs text-gray-500">{move || host_display.get()}</span>
                            <AgentBadge pubkey=host_badge_pubkey compact=true />
                        </div>

                        {(!past).then(|| view! {
                            <button class="text-xs font-semibold px-3 py-1 rounded-lg bg-amber-500/15 text-amber-400 border border-amber-500/30 hover:bg-amber-500/25 transition-colors">
                                "RSVP"
                            </button>
                        })}
                    </div>
                </div>
            </div>
        </div>
    }
}
