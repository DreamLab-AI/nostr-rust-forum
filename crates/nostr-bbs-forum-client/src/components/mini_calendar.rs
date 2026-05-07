//! Compact calendar widget showing a single month grid.
//!
//! Renders inside a glass card, highlights today, and shows small amber dots
//! on days that have events. Month navigation via prev/next arrow buttons.
//! Clicking a day emits a callback with the selected UNIX timestamp (midnight).

use leptos::prelude::*;

/// Day-of-week header labels.
const DOW: [&str; 7] = ["S", "M", "T", "W", "T", "F", "S"];

/// Month names.
const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// Get the current (year, month_0based) from js_sys::Date.
fn current_year_month() -> (u32, u32) {
    let d = js_sys::Date::new_0();
    (d.get_full_year(), d.get_month())
}

/// Get today's day-of-month (1-based).
fn today_day() -> (u32, u32, u32) {
    let d = js_sys::Date::new_0();
    (d.get_full_year(), d.get_month(), d.get_date())
}

/// Number of days in a given month (0-indexed month).
fn days_in_month(year: u32, month: u32) -> u32 {
    // Day 0 of next month = last day of this month
    let d = js_sys::Date::new_with_year_month_day(year, (month + 1) as i32, 0);
    d.get_date()
}

/// Day of week (0 = Sunday) for the 1st of a given month.
fn first_dow(year: u32, month: u32) -> u32 {
    let d = js_sys::Date::new_with_year_month_day(year, month as i32, 1);
    d.get_day()
}

/// Build a UNIX timestamp for midnight on a given date.
fn midnight_ts(year: u32, month: u32, day: u32) -> u64 {
    let d = js_sys::Date::new_with_year_month_day(year, month as i32, day as i32);
    (d.get_time() / 1000.0) as u64
}

/// A single cell in the calendar grid.
#[derive(Clone, Debug)]
struct DayCell {
    /// Day number (1-based).
    day: u32,
    /// Whether this cell belongs to the current month.
    current_month: bool,
    /// Whether this is today.
    is_today: bool,
    /// Whether this day has events.
    has_event: bool,
}

/// Build the 6-row x 7-column grid of day cells for a given month.
fn build_grid(year: u32, month: u32, event_days: &[u32], today: (u32, u32, u32)) -> Vec<DayCell> {
    let num_days = days_in_month(year, month);
    let start_dow = first_dow(year, month);

    // Previous month fill
    let prev_month = if month == 0 { 11 } else { month - 1 };
    let prev_year = if month == 0 { year - 1 } else { year };
    let prev_days = days_in_month(prev_year, prev_month);

    let mut cells = Vec::with_capacity(42);

    // Leading cells from previous month
    for i in 0..start_dow {
        let d = prev_days - start_dow + i + 1;
        cells.push(DayCell {
            day: d,
            current_month: false,
            is_today: false,
            has_event: false,
        });
    }

    // Current month days
    for d in 1..=num_days {
        cells.push(DayCell {
            day: d,
            current_month: true,
            is_today: today.0 == year && today.1 == month && today.2 == d,
            has_event: event_days.contains(&d),
        });
    }

    // Trailing cells from next month (fill to 42 or nearest complete row)
    let rows_needed = cells.len().div_ceil(7) * 7;
    let trailing = rows_needed - cells.len();
    for d in 1..=(trailing as u32) {
        cells.push(DayCell {
            day: d,
            current_month: false,
            is_today: false,
            has_event: false,
        });
    }

    cells
}

/// Compact mini-calendar widget (~250px wide) for the events sidebar.
///
/// Shows a monthly grid with navigation arrows, highlights today,
/// marks days with events using an amber dot, and emits the selected
/// day's midnight UNIX timestamp on click.
#[component]
pub(crate) fn MiniCalendar(
    /// Days of the currently displayed month that have events (1-based).
    event_days: Signal<Vec<u32>>,
    /// Callback fired when a day is clicked. Receives midnight UNIX timestamp.
    on_select: Callback<u64>,
) -> impl IntoView {
    let (init_year, init_month) = current_year_month();
    let year_month = RwSignal::new((init_year, init_month));

    let prev_month = move |_| {
        year_month.update(|(y, m)| {
            if *m == 0 {
                *m = 11;
                *y -= 1;
            } else {
                *m -= 1;
            }
        });
    };

    let next_month = move |_| {
        year_month.update(|(y, m)| {
            if *m == 11 {
                *m = 0;
                *y += 1;
            } else {
                *m += 1;
            }
        });
    };

    view! {
        <div class="glass-card p-4 rounded-xl w-full max-w-[260px]">
            // Month/year header with navigation
            <div class="flex items-center justify-between mb-3">
                <button
                    class="p-1 rounded-md text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
                    on:click=prev_month
                    title="Previous month"
                >
                    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="15 18 9 12 15 6" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </button>

                <span class="text-sm font-semibold text-white">
                    {move || {
                        let (y, m) = year_month.get();
                        let month_name = MONTHS.get(m as usize).unwrap_or(&"???");
                        format!("{} {}", month_name, y)
                    }}
                </span>

                <button
                    class="p-1 rounded-md text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
                    on:click=next_month
                    title="Next month"
                >
                    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="9 18 15 12 9 6" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </button>
            </div>

            // Day-of-week headers
            <div class="grid grid-cols-7 gap-0.5 mb-1">
                {DOW.iter().map(|d| view! {
                    <div class="text-center text-[10px] font-medium text-gray-500 py-0.5">
                        {*d}
                    </div>
                }).collect_view()}
            </div>

            // Day grid
            <div class="grid grid-cols-7 gap-0.5">
                {move || {
                    let (y, m) = year_month.get();
                    let today = today_day();
                    let ev_days = event_days.get();
                    let cells = build_grid(y, m, &ev_days, today);

                    cells.into_iter().map(|cell| {
                        let day = cell.day;
                        let cm = cell.current_month;
                        let is_today = cell.is_today;
                        let has_evt = cell.has_event;

                        let cls = if !cm {
                            "text-center text-[11px] py-1 rounded-md text-gray-700 cursor-default relative"
                        } else if is_today {
                            "text-center text-[11px] py-1 rounded-md font-bold text-gray-900 bg-amber-400 shadow-[0_0_8px_rgba(245,158,11,0.4)] cursor-pointer relative"
                        } else {
                            "text-center text-[11px] py-1 rounded-md text-gray-300 hover:bg-gray-800 cursor-pointer transition-colors relative"
                        };

                        let on_click = move |_| {
                            if cm {
                                let (cy, cm_val) = year_month.get_untracked();
                                let ts = midnight_ts(cy, cm_val, day);
                                on_select.run(ts);
                            }
                        };

                        view! {
                            <div class=cls on:click=on_click>
                                {day}
                                {(has_evt && cm).then(|| view! {
                                    <span class="absolute bottom-0 left-1/2 -translate-x-1/2 w-1 h-1 rounded-full bg-amber-400"></span>
                                })}
                            </div>
                        }
                    }).collect_view()
                }}
            </div>
        </div>
    }
}
