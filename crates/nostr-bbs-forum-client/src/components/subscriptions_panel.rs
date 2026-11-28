//! The forum's subscribed-topics panel and the topic-row subscribe controls.
//!
//! - [`SubscriptionsPanel`] (mounted once in the layout): on desktop a
//!   collapsible column fixed at the left under the header, overlaying the
//!   page rather than pushing it, so opening or closing it never moves the
//!   topic list; on mobile (≤ 640 px) an off-canvas drawer opened from a small
//!   edge tab (tap, or drag the tab), closed by swiping it left, tapping the
//!   scrim or pressing Escape, with focus trapped while open. There is no
//!   open-by-edge-swipe (that is the browser's back gesture) and no
//!   open-by-swipe from the page (that is the row swipe).
//! - [`SubscribeBell`]: the row's subscribe button.
//! - [`SwipeStrip`]: what the row swipe reveals.
//!
//! Everything comes from client-core (`stores::thread_subs`,
//! `stores::subs_panel`, `utils::swipe`); nothing is shown signed out.
//! Titles come only from locally decrypted events; a topic that cannot be
//! read shows a neutral placeholder.

use leptos::html;
use leptos::prelude::*;
use leptos_router::components::A;
use wasm_bindgen::JsCast;

use crate::app::base_href;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::stores::subs_panel::{
    swipe_label, toggle_label, unread_badge, use_subs_panel, SubscribeToggle, TITLE_PLACEHOLDER,
};
use crate::stores::thread_subs::{use_thread_subs, SubscribedTopic};
use crate::utils::swipe::{attach_row_swipe, RowSwipeGuard, RowSwipeState, SwipeDir};

/// The panel column / drawer.
const PANEL_CLASS: &str = "fixed left-0 top-16 bottom-0 w-64 max-w-[85vw] z-40 \
     bg-gray-900/95 backdrop-blur-md border-r border-gray-700/60 shadow-2xl flex flex-col";
/// The mobile drawer: as the column, but above the bottom navigation.
const DRAWER_CLASS: &str = "fixed left-0 top-16 bottom-0 w-64 max-w-[85vw] z-[55] \
     bg-gray-900/95 backdrop-blur-md border-r border-gray-700/60 shadow-2xl flex flex-col";
/// The scrim behind the mobile drawer (above the page and the bottom
/// navigation, below the drawer).
const SCRIM_CLASS: &str = "fixed inset-0 top-16 z-[54] bg-black/50";
/// The edge tab (desktop: when collapsed; mobile: when the drawer is shut).
const TAB_CLASS: &str = "fixed left-0 top-1/2 -translate-y-1/2 z-40 w-6 h-16 \
     rounded-r-md bg-gray-800/90 border border-l-0 border-gray-700/60 \
     text-gray-300 hover:text-amber-300 flex flex-col items-center justify-center gap-1 \
     focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-400";
/// The glowing new-post numeral to the left of a name.
const NUMERAL_CLASS: &str = "flex-shrink-0 min-w-[1.5rem] text-right tabular-nums text-xs \
     font-semibold text-amber-300 drop-shadow-[0_0_6px_rgba(251,191,36,0.85)]";
/// A topic name: one line, ellipsis.
const NAME_CLASS: &str = "min-w-0 flex-1 truncate";

fn bell_svg(filled: bool, class: &'static str) -> impl IntoView {
    let fill = if filled { "currentColor" } else { "none" };
    view! {
        <svg class=class viewBox="0 0 24 24" fill=fill stroke="currentColor" stroke-width="1.75" aria-hidden="true">
            <path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M13.73 21a2 2 0 01-3.46 0" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

/// The row's subscribe button: a real `<button>` with `aria-pressed`, a
/// tooltip and a visible focus ring, absolutely placed in space the row
/// reserves, so it never changes the row's height. Pressing it does not
/// follow the row's link.
#[component]
pub fn SubscribeBell(
    /// Topic root id.
    #[prop(into)]
    root: String,
    /// Channel id.
    #[prop(into)]
    channel: String,
) -> impl IntoView {
    let toggle = SubscribeToggle::new();
    let toasts = use_toasts();
    let root = StoredValue::new(root);
    let channel = StoredValue::new(channel);
    let pressed = Memo::new(move |_| toggle.pressed(&root.get_value()));
    let on_click = move |ev: web_sys::MouseEvent| {
        ev.prevent_default();
        ev.stop_propagation();
        if let Err(e) = toggle.toggle(&root.get_value(), &channel.get_value()) {
            toasts.show(e.to_string(), ToastVariant::Warning);
            toggle.clear_error();
        }
    };
    view! {
        <Show when=move || toggle.available()>
            <button
                type="button"
                class=move || {
                    if pressed.get() {
                        "absolute right-2 top-1/2 -translate-y-1/2 z-10 w-8 h-8 rounded-full flex items-center justify-center text-amber-300 hover:bg-gray-700/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-400"
                    } else {
                        "absolute right-2 top-1/2 -translate-y-1/2 z-10 w-8 h-8 rounded-full flex items-center justify-center text-gray-500 hover:text-amber-300 hover:bg-gray-700/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-400"
                    }
                }
                aria-pressed=move || if pressed.get() { "true" } else { "false" }
                aria-label=move || toggle_label(pressed.get())
                title=move || toggle_label(pressed.get())
                on:click=on_click
            >
                {move || bell_svg(pressed.get(), "w-4 h-4")}
            </button>
        </Show>
    }
}

/// What a row swipe reveals behind the row: the bell and what the swipe
/// will do, on the side the row is moving away from. Hidden at rest.
#[component]
pub fn SwipeStrip(
    /// The row's swipe state.
    state: RowSwipeState,
    /// Topic root id (for the label).
    #[prop(into)]
    root: String,
) -> impl IntoView {
    let subs = use_thread_subs();
    let root = StoredValue::new(root);
    view! {
        {move || state.revealing().map(|dir| {
            let pressed = subs.is_subscribed(&root.get_value());
            let side = match dir {
                // Row slides left: the strip shows on the right.
                SwipeDir::Left => "absolute inset-0 rounded-lg bg-amber-500/20 flex items-center justify-end gap-2 px-5 text-amber-200 text-sm font-medium",
                SwipeDir::Right => "absolute inset-0 rounded-lg bg-amber-500/20 flex items-center justify-start gap-2 px-5 text-amber-200 text-sm font-medium",
            };
            view! {
                <div class=side aria-hidden="true">
                    {bell_svg(!pressed, "w-4 h-4")}
                    <span>{swipe_label(pressed)}</span>
                </div>
            }
        })}
    }
}

/// Attach the row swipe to `frame` while a member is signed in; dropped with
/// the row (or on sign-out). Returns the state the row renders from.
pub fn use_row_subscribe_swipe(
    frame: NodeRef<html::Div>,
    root: String,
    channel: String,
) -> RowSwipeState {
    let state = RowSwipeState::new();
    let toggle = SubscribeToggle::new();
    let toasts = use_toasts();
    let guard: StoredValue<Option<RowSwipeGuard>, LocalStorage> = StoredValue::new_local(None);
    let root = StoredValue::new(root);
    let channel = StoredValue::new(channel);
    Effect::new(move |_| {
        let available = toggle.available();
        let Some(el) = frame.get() else {
            return;
        };
        let attached = guard.with_value(Option::is_some);
        if available && !attached {
            let el: web_sys::HtmlElement = el.unchecked_into();
            let g = attach_row_swipe(&el, state, move |_dir| {
                if let Err(e) = toggle.toggle(&root.get_value(), &channel.get_value()) {
                    toasts.show(e.to_string(), ToastVariant::Warning);
                    toggle.clear_error();
                }
            });
            guard.set_value(Some(g));
        } else if !available && attached {
            guard.set_value(None);
        }
    });
    state
}

/// One panel row: numeral (if unread), name (one line, full title as a
/// tooltip), linking to the topic.
#[component]
fn PanelRow(topic: SubscribedTopic, on_follow: Callback<()>) -> impl IntoView {
    let name = topic
        .title
        .clone()
        .unwrap_or_else(|| TITLE_PLACEHOLDER.to_string());
    let tooltip = name.clone();
    let unknown = topic.title.is_none();
    let badge = unread_badge(topic.unread, topic.capped);
    let label = match &badge {
        Some(b) => format!("{name}, {b} new"),
        None => name.clone(),
    };
    // Always laid out (empty at zero), so names line up and a count arriving
    // never moves the name.
    let numeral_text = badge.unwrap_or_default();
    let name_class = if unknown {
        "min-w-0 flex-1 truncate italic text-gray-500"
    } else {
        NAME_CLASS
    };
    let inner = view! {
        <span class="flex items-center gap-2 w-full">
            <span class=NUMERAL_CLASS aria-hidden="true">{numeral_text}</span>
            <span class=name_class>{name}</span>
        </span>
    };
    match topic.forum_path() {
        Some(path) => view! {
            <li>
                <A
                    href=base_href(&path)
                    attr:class="block px-3 py-2 rounded-md text-sm text-gray-200 hover:bg-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-400"
                    attr:title=tooltip
                    attr:aria-label=label
                    on:click=move |_| on_follow.run(())
                >
                    {inner}
                </A>
            </li>
        }
        .into_any(),
        None => view! {
            <li class="block px-3 py-2 text-sm text-gray-500" title=tooltip aria-label=label>{inner}</li>
        }
        .into_any(),
    }
}

/// The list inside the panel (shared by the column and the drawer).
#[component]
fn PanelBody(on_follow: Callback<()>) -> impl IntoView {
    let subs = use_thread_subs();
    let topics = subs.topics();
    let total = subs.total_unread();
    view! {
        <div class="flex-1 overflow-y-auto overscroll-contain px-1 py-2">
            {move || {
                let list = topics.get();
                if list.is_empty() {
                    view! {
                        <p class="px-3 py-4 text-sm text-gray-500">
                            "No subscribed topics yet. Use the bell on a topic to subscribe."
                        </p>
                    }
                    .into_any()
                } else {
                    view! {
                        <ul class="space-y-0.5">
                            {list.into_iter().map(|t| view! { <PanelRow topic=t on_follow=on_follow /> }).collect_view()}
                        </ul>
                    }
                    .into_any()
                }
            }}
        </div>
        <Show when=move || { total.get().count != 0 }>
            <div class="border-t border-gray-800 px-3 py-2">
                <button
                    type="button"
                    class="text-xs text-gray-400 hover:text-amber-300 underline underline-offset-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-400 rounded"
                    on:click=move |_| subs.mark_all_read()
                >
                    "Mark all read"
                </button>
            </div>
        </Show>
    }
}

/// The edge tab's unread marker: a numeral, or nothing at zero.
fn tab_marker() -> impl IntoView {
    let total = use_thread_subs().total_unread();
    move || {
        let t = total.get();
        unread_badge(t.count, t.capped).map(|b| {
            view! { <span class="text-[10px] leading-none font-semibold text-amber-300 drop-shadow-[0_0_4px_rgba(251,191,36,0.9)]">{b}</span> }
        })
    }
}

/// The subscribed-topics panel. Mount once in the layout; renders nothing
/// signed out.
#[component]
pub fn SubscriptionsPanel() -> impl IntoView {
    let subs = use_thread_subs();
    view! {
        <Show when=move || subs.available()>
            <PanelShell />
        </Show>
    }
}

#[component]
fn PanelShell() -> impl IntoView {
    let panel = use_subs_panel();
    view! {
        {move || if panel.is_mobile() {
            view! { <MobileDrawer /> }.into_any()
        } else {
            view! { <DesktopColumn /> }.into_any()
        }}
    }
}

#[component]
fn DesktopColumn() -> impl IntoView {
    let panel = use_subs_panel();
    let on_follow = Callback::new(|_| {});
    view! {
        {move || if panel.is_open() {
            view! {
                <aside class=PANEL_CLASS aria-label="Subscribed topics">
                    <div class="flex items-center justify-between px-3 h-11 border-b border-gray-800">
                        <h2 class="text-sm font-semibold text-gray-200">"Subscribed"</h2>
                        <button
                            type="button"
                            class="w-8 h-8 rounded-md text-gray-400 hover:text-white hover:bg-gray-800 flex items-center justify-center focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-400"
                            aria-label="Collapse subscribed topics"
                            title="Collapse"
                            on:click=move |_| panel.set_open(false)
                        >
                            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                                <path d="M15 18l-6-6 6-6" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        </button>
                    </div>
                    <PanelBody on_follow=on_follow />
                </aside>
            }
            .into_any()
        } else {
            view! {
                <button
                    type="button"
                    class=TAB_CLASS
                    aria-label="Show subscribed topics"
                    title="Subscribed topics"
                    aria-expanded="false"
                    on:click=move |_| panel.set_open(true)
                >
                    {bell_svg(false, "w-3.5 h-3.5")}
                    {tab_marker()}
                </button>
            }
            .into_any()
        }}
    }
}

/// Selector for the focusable elements of the drawer (focus trap).
const FOCUSABLE: &str = "a[href], button:not([disabled])";

#[component]
fn MobileDrawer() -> impl IntoView {
    let panel = use_subs_panel();
    let tab_ref = NodeRef::<html::Button>::new();
    let drawer_ref = NodeRef::<html::Div>::new();
    let close_ref = NodeRef::<html::Button>::new();
    let swipe = RowSwipeState::new();
    let guard: StoredValue<Option<RowSwipeGuard>, LocalStorage> = StoredValue::new_local(None);
    let was_open = StoredValue::new(false);

    let close = move || {
        panel.set_open(false);
    };

    // Open: focus into the drawer and bind its swipe-to-close. Close: return
    // focus to the tab.
    Effect::new(move |_| {
        let open = panel.is_open();
        if open {
            if let Some(el) = drawer_ref.get() {
                if guard.with_value(Option::is_none) {
                    let el: web_sys::HtmlElement = el.unchecked_into();
                    guard.set_value(Some(attach_row_swipe(&el, swipe, move |dir| {
                        if dir == SwipeDir::Left {
                            panel.set_open(false);
                        }
                    })));
                }
            }
            if let Some(b) = close_ref.get() {
                let _ = b.focus();
            }
            was_open.set_value(true);
        } else {
            guard.set_value(None);
            if was_open.get_value() {
                was_open.set_value(false);
                if let Some(t) = tab_ref.get() {
                    let _ = t.focus();
                }
            }
        }
    });

    // Focus trap and Escape while open.
    let on_keydown = move |ev: web_sys::KeyboardEvent| match ev.key().as_str() {
        "Escape" => {
            ev.prevent_default();
            close();
        }
        "Tab" => {
            let Some(drawer) = drawer_ref.get_untracked() else {
                return;
            };
            let Ok(list) = drawer.query_selector_all(FOCUSABLE) else {
                return;
            };
            let n = list.length();
            if n == 0 {
                return;
            }
            let first = list.item(0);
            let last = list.item(n - 1);
            let active = gloo::utils::document().active_element();
            let at = |node: &Option<web_sys::Node>| {
                node.as_ref()
                    .zip(active.as_ref())
                    .is_some_and(|(a, b)| a.is_same_node(Some(b)))
            };
            let target = if ev.shift_key() && at(&first) {
                last
            } else if !ev.shift_key() && at(&last) {
                first
            } else {
                None
            };
            if let Some(el) = target.and_then(|n| n.dyn_into::<web_sys::HtmlElement>().ok()) {
                ev.prevent_default();
                let _ = el.focus();
            }
        }
        _ => {}
    };

    // Tab: tap opens; dragging it rightwards opens too.
    let drag_from: StoredValue<Option<(i32, f64)>> = StoredValue::new(None);
    let on_tab_down = move |ev: web_sys::PointerEvent| {
        drag_from.set_value(Some((ev.pointer_id(), ev.client_x() as f64)));
    };
    let on_tab_move = move |ev: web_sys::PointerEvent| {
        if let Some((id, x0)) = drag_from.get_value() {
            if id == ev.pointer_id() && ev.client_x() as f64 - x0 > 24.0 {
                drag_from.set_value(None);
                panel.set_open(true);
            }
        }
    };
    let on_tab_end = move |_: web_sys::PointerEvent| drag_from.set_value(None);

    let on_follow = Callback::new(move |_| panel.set_open(false));
    let drawer_style = move || {
        // Follows a leftward drag; never further right than open.
        let dx = swipe.offset.get().min(0.0);
        let transition = if swipe.settling.get() && !swipe.reduced_motion {
            "transform 180ms ease-out"
        } else {
            "none"
        };
        format!("transform: translateX({dx}px); transition: {transition};")
    };

    view! {
        <Show
            when=move || panel.is_open()
            fallback=move || view! {
                <button
                    node_ref=tab_ref
                    type="button"
                    class=TAB_CLASS
                    style="touch-action: none;"
                    aria-label="Show subscribed topics"
                    title="Subscribed topics"
                    aria-expanded="false"
                    aria-controls="subs-drawer"
                    on:click=move |_| panel.set_open(true)
                    on:pointerdown=on_tab_down
                    on:pointermove=on_tab_move
                    on:pointerup=on_tab_end
                    on:pointercancel=on_tab_end
                >
                    {bell_svg(false, "w-3.5 h-3.5")}
                    {tab_marker()}
                </button>
            }
        >
            <div class=SCRIM_CLASS aria-hidden="true" on:click=move |_| close()></div>
            <div
                node_ref=drawer_ref
                id="subs-drawer"
                class=DRAWER_CLASS
                style=drawer_style
                role="dialog"
                aria-modal="true"
                aria-label="Subscribed topics"
                on:keydown=on_keydown
            >
                <div class="flex items-center justify-between px-3 h-11 border-b border-gray-800">
                    <h2 class="text-sm font-semibold text-gray-200">"Subscribed"</h2>
                    <button
                        node_ref=close_ref
                        type="button"
                        class="w-9 h-9 rounded-md text-gray-400 hover:text-white hover:bg-gray-800 flex items-center justify-center focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-400"
                        aria-label="Close subscribed topics"
                        on:click=move |_| close()
                    >
                        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                            <path d="M18 6L6 18M6 6l12 12" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                    </button>
                </div>
                <PanelBody on_follow=on_follow />
            </div>
        </Show>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classes(c: &str) -> Vec<&str> {
        c.split_whitespace().collect()
    }

    #[test]
    fn the_panel_overlays_and_never_pushes_the_page() {
        // Fixed, so opening or closing it moves nothing else (no CLS).
        for c in [PANEL_CLASS, DRAWER_CLASS, TAB_CLASS, SCRIM_CLASS] {
            assert!(classes(c).contains(&"fixed"), "{c}");
        }
        assert!(
            classes(PANEL_CLASS).contains(&"top-16"),
            "below the sticky header"
        );
    }

    #[test]
    fn names_stay_on_one_line_and_the_numeral_keeps_its_width() {
        assert!(classes(NAME_CLASS).contains(&"truncate"));
        let n = classes(NUMERAL_CLASS);
        assert!(n.contains(&"flex-shrink-0") && n.contains(&"tabular-nums"));
    }

    #[test]
    fn the_focus_trap_covers_links_and_buttons() {
        assert!(FOCUSABLE.contains("a[href]") && FOCUSABLE.contains("button"));
    }
}
