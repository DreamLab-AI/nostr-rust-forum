//! Header Back control and the scroll memory behind it.
//!
//! The installed phone app has no browser back button. [`BackButton`] goes
//! back in history when the previous entry is a page of this forum (read from
//! the Navigation API, which knows about replaced entries and reloads), and
//! otherwise goes up one level of the hierarchy (see
//! [`crate::utils::back_nav`]). Where the Navigation API is missing it always
//! goes up: guessing from `history.length` could step out of the app.
//!
//! [`provide_scroll_memory`] keeps each list page's scroll position for the
//! session and puts it back when the member returns to that page, by Back,
//! by the system back gesture or by going up. The browser's own restoration
//! runs before the topic list has rendered, which is why members were "sent
//! back to the top of the forum".

use std::collections::HashMap;

use leptos::prelude::*;
use leptos_router::hooks::{use_location, use_navigate};
use leptos_router::NavigateOptions;
use wasm_bindgen::{JsCast, JsValue};

use crate::app::{base_href, current_app_path};
use crate::auth::use_auth;
use crate::stores::zone_access::use_zone_access;
use crate::stores::zones::{load_zones, resolve_zone_param};
use crate::utils::back_nav::{is_in_app_entry, restores_scroll, ForumRoute, FORUMS};

/// How long a restore keeps trying, in 50 ms steps (content arrives late).
const RESTORE_ATTEMPTS: u32 = 40;
const RESTORE_STEP_MS: i32 = 50;
/// Steps the restored position must hold, with the page tall enough, before
/// the restore stops re-asserting it (the outgoing page can still be in the
/// DOM for a moment after the route changes).
const RESTORE_HOLD_STEPS: u32 = 3;

#[derive(Default)]
struct ScrollState {
    /// Last known window scroll offset per app path, this session.
    positions: HashMap<String, f64>,
    /// The app path the window is showing.
    current: String,
    /// The page being returned to (by a popstate, or by Back going up), whose
    /// saved position is put back when the route reaches it.
    returning_to: Option<String>,
    /// Between leaving a page and the route reaching the next one, scroll
    /// events belong to neither (the DOM swap clamps the offset before the
    /// route change is seen here), so they are not recorded.
    frozen: bool,
    /// A restore is in progress; scroll events are not recorded meanwhile
    /// (content growing under it would overwrite the target).
    restoring: bool,
    /// Bumped to cancel a restore in progress.
    generation: u32,
}

/// Per-session scroll positions of list pages, provided by the layout.
#[derive(Clone, Copy)]
pub struct ScrollMemory {
    state: StoredValue<ScrollState>,
}

fn scroll_y() -> Option<f64> {
    web_sys::window().and_then(|w| w.scroll_y().ok())
}

impl ScrollMemory {
    /// The member is leaving the current page: keep its offset as it is now,
    /// before the next page replaces it, and stop recording until the route
    /// reaches the next page.
    fn leave(self) {
        let y = scroll_y();
        self.state.update_value(|s| {
            if !s.frozen && !s.restoring {
                if let Some(y) = y {
                    let current = s.current.clone();
                    s.positions.insert(current, y);
                }
            }
            s.frozen = true;
        });
    }

    /// Restore `path`'s saved position when the route reaches it.
    fn expect_return(self, path: String) {
        self.state.update_value(|s| s.returning_to = Some(path));
    }

    fn cancel_restore(self) {
        self.state.update_value(|s| {
            if s.restoring {
                s.restoring = false;
                s.generation = s.generation.wrapping_add(1);
            }
        });
    }

    fn restore(self, y: f64) {
        let Some(generation) = self.state.try_update_value(|s| {
            s.restoring = true;
            s.generation = s.generation.wrapping_add(1);
            s.generation
        }) else {
            return;
        };
        self.restore_step(generation, y, 0, 0);
    }

    /// Put the window at `y` once the page is tall enough to hold it, and
    /// keep it there until it has held for a few steps; at the deadline, go
    /// as far as the page allows.
    fn restore_step(self, generation: u32, y: f64, attempt: u32, held: u32) {
        let delay = if attempt == 0 { 0 } else { RESTORE_STEP_MS };
        crate::utils::set_timeout_once(
            move || {
                if self.state.try_with_value(|s| s.generation) != Some(generation) {
                    return;
                }
                let Some(window) = web_sys::window() else {
                    return;
                };
                let max = max_scroll(&window);
                let last = attempt >= RESTORE_ATTEMPTS;
                let mut held = held;
                if max + 1.0 >= y || last {
                    let target = y.min(max.max(0.0));
                    let now = window.scroll_y().unwrap_or(0.0);
                    if (now - target).abs() > 1.0 {
                        window.scroll_to_with_x_and_y(0.0, target);
                        held = 0;
                    } else {
                        held += 1;
                    }
                    if held >= RESTORE_HOLD_STEPS || last {
                        self.state.try_update_value(|s| {
                            if s.generation == generation {
                                s.restoring = false;
                                let current = s.current.clone();
                                s.positions.insert(current, target);
                            }
                        });
                        return;
                    }
                }
                self.restore_step(generation, y, attempt + 1, held);
            },
            delay,
        );
    }
}

fn max_scroll(window: &web_sys::Window) -> f64 {
    let height = window
        .document()
        .and_then(|d| d.document_element())
        .map(|el| el.scroll_height() as f64)
        .unwrap_or(0.0);
    let viewport = window
        .inner_height()
        .ok()
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    height - viewport
}

/// Install the scroll memory. Call once, inside the router (it reads the
/// location).
pub fn provide_scroll_memory() -> ScrollMemory {
    let location = use_location();
    let memory = ScrollMemory {
        state: StoredValue::new(ScrollState {
            current: current_app_path(&location.pathname.get_untracked()),
            ..Default::default()
        }),
    };
    provide_context(memory);

    // The browser would restore on popstate before the new page has its
    // content, landing at the top; this memory does it instead.
    if let Some(history) = web_sys::window().and_then(|w| w.history().ok()) {
        let _ = js_sys::Reflect::set(
            &history,
            &JsValue::from_str("scrollRestoration"),
            &JsValue::from_str("manual"),
        );
    }

    let on_scroll = window_event_listener(leptos::ev::scroll, move |_| {
        let Some(y) = scroll_y() else {
            return;
        };
        memory.state.update_value(|s| {
            if !s.restoring && !s.frozen {
                let current = s.current.clone();
                s.positions.insert(current, y);
            }
        });
    });
    // The router updates the location from its own popstate listener, but
    // the DOM is still the outgoing page here: take its offset now.
    let on_pop = window_event_listener(leptos::ev::popstate, move |_| {
        memory.leave();
        if let Some(pathname) = web_sys::window().and_then(|w| w.location().pathname().ok()) {
            memory.expect_return(current_app_path(&pathname));
        }
    });
    // An in-app link click: capture phase, so it runs before the router's
    // own (bubbling) click handler swaps the page.
    if let Some(window) = web_sys::window() {
        gloo::events::EventListener::new_with_options(
            &window,
            "click",
            gloo::events::EventListenerOptions::run_in_capture_phase(),
            move |ev| {
                let on_link = ev
                    .target()
                    .and_then(|t| t.dyn_into::<web_sys::Element>().ok())
                    .and_then(|el| el.closest("a[href]").ok().flatten())
                    .is_some();
                if on_link {
                    memory.leave();
                }
            },
        )
        // The layout lives as long as the app.
        .forget();
    }
    // The member taking over cancels a restore still waiting for content.
    let interrupts = [
        window_event_listener(leptos::ev::wheel, move |_| memory.cancel_restore()),
        window_event_listener(leptos::ev::touchstart, move |_| memory.cancel_restore()),
        window_event_listener(leptos::ev::keydown, move |_| memory.cancel_restore()),
    ];
    on_cleanup(move || {
        on_scroll.remove();
        on_pop.remove();
        interrupts.into_iter().for_each(|h| h.remove());
    });

    Effect::new(move |_| {
        let path = current_app_path(&location.pathname.get());
        let returning = memory.state.try_update_value(|s| {
            s.current = path.clone();
            s.frozen = false;
            if s.returning_to.take().as_deref() == Some(path.as_str()) {
                // Returning: the saved offset, or the top when none is known
                // (the outgoing page's offset is still applied otherwise).
                Some(s.positions.get(&path).copied().unwrap_or(0.0))
            } else {
                // A fresh visit starts at the top (the router scrolls there);
                // a restore still running for the page left is abandoned.
                if s.restoring {
                    s.restoring = false;
                    s.generation = s.generation.wrapping_add(1);
                }
                None
            }
        });
        if let Some(Some(y)) = returning {
            if restores_scroll(&path) {
                memory.restore(y);
            }
        }
    });

    memory
}

/// Whether the previous history entry is a page of this forum, per the
/// Navigation API. `false` where the API is missing.
fn previous_entry_in_app() -> bool {
    fn get(target: &JsValue, key: &str) -> Option<JsValue> {
        js_sys::Reflect::get(target, &JsValue::from_str(key))
            .ok()
            .filter(|v| !v.is_undefined() && !v.is_null())
    }
    let Some(window) = web_sys::window() else {
        return false;
    };
    let Some(navigation) = get(&window, "navigation") else {
        return false;
    };
    let Some(index) = get(&navigation, "currentEntry")
        .and_then(|e| get(&e, "index"))
        .and_then(|i| i.as_f64())
    else {
        return false;
    };
    if index < 1.0 {
        return false;
    }
    let Some(entries) = get(&navigation, "entries")
        .and_then(|f| f.dyn_into::<js_sys::Function>().ok())
        .and_then(|f| f.call0(&navigation).ok())
        .and_then(|a| a.dyn_into::<js_sys::Array>().ok())
    else {
        return false;
    };
    let Some(url) = get(&entries.get(index as u32 - 1), "url").and_then(|u| u.as_string()) else {
        return false;
    };
    let Ok(origin) = window.location().origin() else {
        return false;
    };
    is_in_app_entry(&url, &origin, &base_href(""))
}

fn back_icon() -> impl IntoView {
    view! {
        <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
            <polyline points="15 18 9 12 15 6" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

/// The header's Back control: shown on every page but the forum's front page
/// (`/`, `/forums`, and a single-zone member's home zone, which `/forums`
/// forwards to). Always visible on narrow screens and in the installed app
/// (`display-mode: standalone`); on desktop from the `lg` breakpoint, where
/// the header has room. A 44 px target with the accessible name "Back".
#[component]
pub fn BackButton() -> impl IntoView {
    let location = use_location();
    let navigate = StoredValue::new(use_navigate());
    let auth = use_auth();
    let zone_access = use_zone_access();
    let memory = use_context::<ScrollMemory>();

    let visible = Memo::new(move |_| {
        let path = current_app_path(&location.pathname.get());
        let route = ForumRoute::parse(&path);
        if route.is_front() {
            return false;
        }
        if let ForumRoute::Zone { zone, .. } = route {
            if let Some(home) = zone_access.home_zone() {
                let zones = load_zones();
                if resolve_zone_param(zone, &zones).is_some_and(|z| z.id == home.id) {
                    return false;
                }
            }
        }
        true
    });

    let on_click = move |_| {
        if previous_entry_in_app() {
            if let Some(history) = web_sys::window().and_then(|w| w.history().ok()) {
                let _ = history.back();
                return;
            }
        }
        let path = current_app_path(&location.pathname.get_untracked());
        let mut target = ForumRoute::parse(&path)
            .up_target()
            .unwrap_or_else(|| FORUMS.to_string());
        // Forums is members-only; a signed-out visitor goes to the landing.
        if target == FORUMS && !auth.is_authenticated().get_untracked() {
            target = "/".to_string();
        }
        if let Some(memory) = memory {
            memory.leave();
            memory.expect_return(target.clone());
        }
        // Replace, so the page left is not "history" for the next Back (a
        // cold topic would otherwise bounce between topic and section); no
        // router scroll-to-top, so a saved position can be restored.
        navigate.with_value(|nav| {
            nav(
                &target,
                NavigateOptions {
                    replace: true,
                    scroll: false,
                    ..Default::default()
                },
            )
        });
    };

    view! {
        <Show when=move || visible.get()>
            <button
                type="button"
                aria-label="Back"
                title="Back"
                class="inline-flex sm:hidden lg:inline-flex [@media(display-mode:standalone)]:inline-flex items-center justify-center shrink-0 w-11 h-11 -ml-2 rounded-lg text-gray-300 hover:text-amber-400 hover:bg-gray-800 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-400"
                on:click=on_click
            >
                {back_icon()}
            </button>
        </Show>
    }
}
