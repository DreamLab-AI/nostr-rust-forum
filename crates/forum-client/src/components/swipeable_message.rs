//! Swipeable message wrapper with left/right swipe gesture detection.
//!
//! Wraps message content with pointer event handlers for horizontal swipe
//! gestures. Shows peek action icons during swipe and triggers callbacks
//! when the swipe threshold (60px) is exceeded.

use leptos::prelude::*;

/// Horizontal distance in pixels required to trigger a swipe action.
const SWIPE_THRESHOLD: f64 = 60.0;

/// Vertical distance that cancels a swipe (user is scrolling instead).
const SCROLL_CANCEL: f64 = 30.0;

/// Swipeable wrapper for message bubbles with left/right gesture detection.
///
/// - Tracks `pointerdown` -> `pointermove` -> `pointerup` events
/// - Reveals action icons during swipe (reply arrow right, trash left)
/// - Spring-back animation when released below threshold
/// - Ignores vertical scrolls via Y-delta check
#[component]
pub(crate) fn SwipeableMessage(
    /// The message content to wrap.
    children: Children,
    /// Callback for left swipe (e.g. delete/bookmark).
    #[prop(optional)]
    on_swipe_left: Option<Callback<()>>,
    /// Callback for right swipe (e.g. reply).
    #[prop(optional)]
    on_swipe_right: Option<Callback<()>>,
) -> impl IntoView {
    let offset_x = RwSignal::new(0.0f64);
    let is_swiping = RwSignal::new(false);
    let start_x = RwSignal::new(0.0f64);
    let start_y = RwSignal::new(0.0f64);
    let cancelled = RwSignal::new(false);

    let on_pointer_down = move |ev: web_sys::PointerEvent| {
        start_x.set(ev.client_x() as f64);
        start_y.set(ev.client_y() as f64);
        is_swiping.set(true);
        cancelled.set(false);
        offset_x.set(0.0);
    };

    let on_pointer_move = move |ev: web_sys::PointerEvent| {
        if !is_swiping.get_untracked() || cancelled.get_untracked() {
            return;
        }

        let dx = ev.client_x() as f64 - start_x.get_untracked();
        let dy = (ev.client_y() as f64 - start_y.get_untracked()).abs();

        // Cancel swipe if vertical movement exceeds threshold (user is scrolling)
        if dy > SCROLL_CANCEL {
            cancelled.set(true);
            offset_x.set(0.0);
            return;
        }

        // Only track if we have a handler for that direction
        let should_track = (dx < 0.0 && on_swipe_left.is_some())
            || (dx > 0.0 && on_swipe_right.is_some());

        if should_track {
            // Apply resistance: offset slows down past threshold
            let clamped = if dx.abs() > SWIPE_THRESHOLD {
                let extra = dx.abs() - SWIPE_THRESHOLD;
                let sign = dx.signum();
                sign * (SWIPE_THRESHOLD + extra * 0.3)
            } else {
                dx
            };
            offset_x.set(clamped);
        }
    };

    let on_pointer_up = move |_: web_sys::PointerEvent| {
        if !is_swiping.get_untracked() {
            return;
        }
        is_swiping.set(false);

        let dx = offset_x.get_untracked();
        if dx.abs() >= SWIPE_THRESHOLD && !cancelled.get_untracked() {
            if dx < 0.0 {
                if let Some(cb) = on_swipe_left {
                    cb.run(());
                }
            } else if dx > 0.0 {
                if let Some(cb) = on_swipe_right {
                    cb.run(());
                }
            }
        }

        // Spring back
        offset_x.set(0.0);
    };

    let transform_style = move || {
        let x = offset_x.get();
        if x == 0.0 {
            "transform: translateX(0); transition: transform 0.2s ease-out;".to_string()
        } else {
            format!("transform: translateX({}px); transition: none;", x)
        }
    };

    let left_peek_opacity = move || {
        let x = offset_x.get();
        if x < -10.0 {
            let progress = (x.abs() / SWIPE_THRESHOLD).min(1.0);
            format!("opacity: {};", progress)
        } else {
            "opacity: 0;".to_string()
        }
    };

    let right_peek_opacity = move || {
        let x = offset_x.get();
        if x > 10.0 {
            let progress = (x / SWIPE_THRESHOLD).min(1.0);
            format!("opacity: {};", progress)
        } else {
            "opacity: 0;".to_string()
        }
    };

    let body = children();

    view! {
        <div
            class="relative overflow-hidden"
            on:pointerdown=on_pointer_down
            on:pointermove=on_pointer_move
            on:pointerup=on_pointer_up
            on:pointercancel=move |_| { is_swiping.set(false); offset_x.set(0.0); }
            style="touch-action: pan-y;"
        >
            // Left action peek icon (trash/bookmark)
            {on_swipe_left.is_some().then(|| view! {
                <div
                    class="absolute right-2 top-1/2 -translate-y-1/2 flex items-center justify-center w-8 h-8 rounded-full bg-red-500/20 text-red-400 pointer-events-none"
                    style=left_peek_opacity
                >
                    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="3 6 5 6 21 6" stroke-linecap="round" stroke-linejoin="round"/>
                        <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"
                            stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </div>
            })}

            // Right action peek icon (reply arrow)
            {on_swipe_right.is_some().then(|| view! {
                <div
                    class="absolute left-2 top-1/2 -translate-y-1/2 flex items-center justify-center w-8 h-8 rounded-full bg-amber-500/20 text-amber-400 pointer-events-none"
                    style=right_peek_opacity
                >
                    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="9 17 4 12 9 7" stroke-linecap="round" stroke-linejoin="round"/>
                        <path d="M20 18v-2a4 4 0 00-4-4H4" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </div>
            })}

            // Swipeable content
            <div style=transform_style>
                {body}
            </div>
        </div>
    }
}
