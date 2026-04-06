//! Board statistics overview component.
//!
//! Displays four key metrics (messages, users, channels, online) in a
//! responsive glass card grid with count-up animation on load.

use leptos::prelude::*;
use std::cell::Cell;
use std::rc::Rc;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

/// A single stat entry used by the count-up animation.
#[allow(dead_code)]
struct StatDef {
    label: &'static str,
    icon: &'static str,
    target: u32,
    signal: RwSignal<u32>,
}

/// Board-wide statistics card showing messages, users, channels, and online count.
///
/// Numbers animate from 0 to target value over ~600ms using a stepped interval.
#[component]
pub fn BoardStats(
    /// Total messages across all channels.
    total_messages: Signal<u32>,
    /// Total unique users.
    total_users: Signal<u32>,
    /// Total channels.
    total_channels: Signal<u32>,
    /// Currently online user count.
    online_count: Signal<u32>,
) -> impl IntoView {
    // Animated display values (start at 0, count up to target)
    let display_messages = RwSignal::new(0u32);
    let display_users = RwSignal::new(0u32);
    let display_channels = RwSignal::new(0u32);
    let display_online = RwSignal::new(0u32);

    // Run count-up animation whenever source signals change
    Effect::new(move |_| {
        let targets = [
            (total_messages.get(), display_messages),
            (total_users.get(), display_users),
            (total_channels.get(), display_channels),
            (online_count.get(), display_online),
        ];

        for (target, display) in targets {
            animate_count(display, target);
        }
    });

    view! {
        <div class="bg-white/5 backdrop-blur-xl border border-white/10 rounded-2xl p-4 shadow-lg shadow-amber-500/10">
            <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
                <StatBox
                    icon="message"
                    value=display_messages
                    label="Messages"
                />
                <StatBox
                    icon="users"
                    value=display_users
                    label="Members"
                />
                <StatBox
                    icon="channel"
                    value=display_channels
                    label="Channels"
                />
                <StatBox
                    icon="online"
                    value=display_online
                    label="Online"
                />
            </div>
        </div>
    }
}

/// Individual stat box with icon, animated number, and label.
#[component]
fn StatBox(
    icon: &'static str,
    value: RwSignal<u32>,
    label: &'static str,
) -> impl IntoView {
    let icon_view = match icon {
        "message" => view! {
            <svg class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M7.5 8.25h9m-9 3H12m-9.75 1.51c0 1.6 1.123 2.994 2.707 3.227 1.129.166 2.27.293 3.423.379.35.026.67.21.865.501L12 21l2.755-4.133a1.14 1.14 0 01.865-.501 48.172 48.172 0 003.423-.379c1.584-.233 2.707-1.626 2.707-3.228V6.741c0-1.602-1.123-2.995-2.707-3.228A48.394 48.394 0 0012 3c-2.392 0-4.744.175-7.043.513C3.373 3.746 2.25 5.14 2.25 6.741v6.018z"
                    stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        "users" => view! {
            <svg class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z"
                    stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        "channel" => view! {
            <svg class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M5.25 8.25h15m-16.5 7.5h15m-1.8-13.5l-3.9 19.5m-2.1-19.5l-3.9 19.5"
                    stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        "online" => view! {
            <div class="flex items-center justify-center">
                <span class="w-3 h-3 rounded-full bg-green-500 animate-pulse shadow-lg shadow-green-500/50"></span>
            </div>
        }.into_any(),
        _ => view! { <span></span> }.into_any(),
    };

    view! {
        <div class="bg-white/5 rounded-xl p-3 text-center border border-white/5 hover:border-amber-500/20 transition-colors">
            <div class="flex justify-center mb-2">
                {icon_view}
            </div>
            <div class="text-2xl font-bold bg-gradient-to-r from-amber-400 to-orange-500 bg-clip-text text-transparent">
                {move || value.get()}
            </div>
            <div class="text-xs text-gray-400 mt-0.5">{label}</div>
        </div>
    }
}

/// Animate a signal from its current value to `target` over ~600ms using
/// `setInterval` with step increments. Self-cleans via `Rc<Cell<...>>`.
fn animate_count(signal: RwSignal<u32>, target: u32) {
    if target == 0 {
        signal.set(0);
        return;
    }

    let steps = 20u32;
    let interval_ms = 30; // 20 steps * 30ms = 600ms
    let step_size = (target as f64 / steps as f64).ceil() as u32;
    let current = Rc::new(Cell::new(0u32));

    // Store interval handle + closure so they can self-drop
    let handle: Rc<Cell<Option<i32>>> = Rc::new(Cell::new(None));
    let slot: Rc<Cell<Option<Closure<dyn FnMut()>>>> = Rc::new(Cell::new(None));

    let handle_c = handle.clone();
    let slot_c = slot.clone();

    let closure = Closure::wrap(Box::new(move || {
        let next = (current.get() + step_size).min(target);
        current.set(next);
        signal.set(next);

        if next >= target {
            // Clear interval and drop closure
            if let Some(h) = handle_c.take() {
                if let Some(w) = web_sys::window() {
                    w.clear_interval_with_handle(h);
                }
            }
            slot_c.set(None);
        }
    }) as Box<dyn FnMut()>);

    if let Some(window) = web_sys::window() {
        let h = window
            .set_interval_with_callback_and_timeout_and_arguments_0(
                closure.as_ref().unchecked_ref(),
                interval_ms,
            )
            .unwrap_or(0);
        handle.set(Some(h));
    }

    slot.set(Some(closure));
}
