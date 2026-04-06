//! Slide-out notification center panel.
//!
//! Shows a list of all notifications from the NotificationStoreV2, grouped by
//! read status, with "Mark all read" action and click-to-navigate behavior.

use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;

use crate::stores::notifications::{use_notification_store, Notification, NotificationKind};
use crate::utils::format_relative_time;

/// Notification center panel, toggled by the notification bell.
#[component]
pub fn NotificationCenter(
    /// Whether the panel is open.
    is_open: RwSignal<bool>,
) -> impl IntoView {
    let store = use_notification_store();
    let _navigate = StoredValue::new(use_navigate());

    let on_mark_all = move |_| {
        store.mark_all_read();
    };

    let on_clear = move |_| {
        store.clear_all();
        is_open.set(false);
    };

    let on_backdrop = move |_| {
        is_open.set(false);
    };

    view! {
        <Show when=move || is_open.get()>
            // Backdrop
            <div
                class="fixed inset-0 z-40"
                on:click=on_backdrop
            ></div>

            // Panel
            <div class="fixed right-0 top-16 bottom-0 w-96 max-w-[90vw] z-50 glass-card border-l border-gray-700/50 shadow-2xl flex flex-col animate-slide-in-down">
                // Header
                <div class="flex items-center justify-between px-4 py-3 border-b border-gray-700/50 flex-shrink-0">
                    <span class="text-sm font-semibold text-white">"Notifications"</span>
                    <div class="flex items-center gap-2">
                        <button
                            class="text-xs text-amber-400 hover:text-amber-300 transition-colors"
                            on:click=on_mark_all
                        >
                            "Mark all read"
                        </button>
                        <button
                            class="text-xs text-gray-500 hover:text-red-400 transition-colors"
                            on:click=on_clear
                        >
                            "Clear"
                        </button>
                    </div>
                </div>

                // Notification list
                <div class="flex-1 overflow-y-auto">
                    {move || {
                        let items = store.items.get();
                        if items.is_empty() {
                            view! {
                                <div class="flex flex-col items-center justify-center py-16 text-center">
                                    <svg class="w-10 h-10 text-gray-600 mb-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                        <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"
                                            stroke-linecap="round" stroke-linejoin="round"/>
                                        <path d="M13.73 21a2 2 0 01-3.46 0"
                                            stroke-linecap="round" stroke-linejoin="round"/>
                                    </svg>
                                    <p class="text-sm text-gray-500">"No notifications"</p>
                                </div>
                            }.into_any()
                        } else {
                            items.into_iter().map(|n| {
                                let n_for_view = n.clone();
                                view! { <NotificationRow notification=n_for_view is_open=is_open /> }
                            }).collect_view().into_any()
                        }
                    }}
                </div>
            </div>
        </Show>
    }
}

/// A single notification row.
#[component]
fn NotificationRow(notification: Notification, is_open: RwSignal<bool>) -> impl IntoView {
    let store = use_notification_store();
    let navigate = StoredValue::new(use_navigate());

    let bg = if notification.read { "" } else { "bg-amber-500/5" };
    let dot_vis = if notification.read { "invisible" } else { "" };
    let time_str = format_relative_time(notification.timestamp);
    let title = notification.title.clone();
    let body = notification.body.clone();
    let link = notification.link.clone();
    let nid = notification.id.clone();
    let kind = notification.kind.clone();

    let on_click = move |_| {
        store.mark_read(&nid);
        if let Some(ref path) = link {
            let p = path.clone();
            navigate.with_value(|nav| nav(&p, NavigateOptions::default()));
            is_open.set(false);
        }
    };

    let icon_class = match kind {
        NotificationKind::Message => "text-blue-400",
        NotificationKind::Mention => "text-amber-400",
        NotificationKind::DM => "text-purple-400",
        NotificationKind::JoinRequest => "text-cyan-400",
        NotificationKind::JoinApproved => "text-emerald-400",
        NotificationKind::EventRSVP => "text-amber-400",
        NotificationKind::System => "text-gray-400",
    };

    view! {
        <div
            class=format!("px-4 py-3 border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors cursor-pointer {}", bg)
            on:click=on_click
        >
            <div class="flex items-start gap-2.5">
                <span class=format!("mt-0.5 flex-shrink-0 {}", icon_class)>
                    <NotificationIcon kind=kind />
                </span>
                <div class="flex-1 min-w-0">
                    <div class="flex items-center gap-1.5">
                        <span class=format!("w-1.5 h-1.5 rounded-full bg-amber-400 flex-shrink-0 {}", dot_vis)></span>
                        <span class="text-sm font-medium text-white truncate">{title}</span>
                    </div>
                    <p class="text-xs text-gray-400 mt-0.5 line-clamp-2">{body}</p>
                    <p class="text-[10px] text-gray-600 mt-1">{time_str}</p>
                </div>
            </div>
        </div>
    }
}

/// SVG icon for a notification kind.
#[component]
fn NotificationIcon(kind: NotificationKind) -> impl IntoView {
    match kind {
        NotificationKind::Message => view! {
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        NotificationKind::Mention => view! {
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="4"/>
                <path d="M16 8v5a3 3 0 006 0v-1a10 10 0 10-3.92 7.94" stroke-linecap="round"/>
            </svg>
        }.into_any(),
        NotificationKind::DM => view! {
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" stroke-linecap="round" stroke-linejoin="round"/>
                <polyline points="22,6 12,13 2,6" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        NotificationKind::JoinRequest => view! {
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M16 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2" stroke-linecap="round" stroke-linejoin="round"/>
                <circle cx="8.5" cy="7" r="4" stroke-linecap="round" stroke-linejoin="round"/>
                <line x1="20" y1="8" x2="20" y2="14" stroke-linecap="round"/>
                <line x1="23" y1="11" x2="17" y2="11" stroke-linecap="round"/>
            </svg>
        }.into_any(),
        NotificationKind::JoinApproved => view! {
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M22 11.08V12a10 10 0 11-5.93-9.14" stroke-linecap="round" stroke-linejoin="round"/>
                <polyline points="22 4 12 14.01 9 11.01" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        NotificationKind::EventRSVP => view! {
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="3" y="4" width="18" height="18" rx="2" stroke-linecap="round" stroke-linejoin="round"/>
                <line x1="16" y1="2" x2="16" y2="6" stroke-linecap="round"/>
                <line x1="8" y1="2" x2="8" y2="6" stroke-linecap="round"/>
                <line x1="3" y1="10" x2="21" y2="10" stroke-linecap="round"/>
            </svg>
        }.into_any(),
        NotificationKind::System => view! {
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="16" x2="12" y2="12" stroke-linecap="round"/>
                <line x1="12" y1="8" x2="12.01" y2="8" stroke-linecap="round"/>
            </svg>
        }.into_any(),
    }
}
