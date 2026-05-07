//! Fixed bottom navigation bar for mobile screens.
//!
//! Displays 5 nav items (Home, Chat, DMs, Forums, Profile) with SVG icons,
//! active route highlighting, and an unread-DM badge. Visibility is controlled
//! by the `.mobile-bottom-nav` CSS class (hidden above 639px).

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_location;

use crate::app::base_href;
use crate::auth::use_auth;

/// Unread DM count signal, provided at the layout level and consumed here.
#[derive(Clone, Copy)]
pub struct UnreadDmCount(pub RwSignal<u32>);

/// Provide the unread DM count context. Call once near the app root.
pub fn provide_unread_dm_count() -> UnreadDmCount {
    let count = UnreadDmCount(RwSignal::new(0));
    provide_context(count);
    count
}

/// Read the unread DM count from context.
pub fn use_unread_dm_count() -> UnreadDmCount {
    use_context::<UnreadDmCount>().unwrap_or_else(|| {
        let fallback = UnreadDmCount(RwSignal::new(0));
        provide_context(fallback);
        fallback
    })
}

/// Fixed bottom navigation bar visible only on mobile (< 640px).
///
/// Uses the `mobile-bottom-nav` and `mobile-nav-item` CSS classes from
/// `style.css` for layout, safe-area padding, and active indicator bar.
#[component]
pub(crate) fn MobileBottomNav() -> impl IntoView {
    let auth = use_auth();
    let is_authed = auth.is_authenticated();
    let location = use_location();
    let unread = use_unread_dm_count();

    let pathname = move || {
        let p = location.pathname.get();
        let base = option_env!("FORUM_BASE").unwrap_or("");
        if base.is_empty() {
            return p;
        }
        let stripped = p.strip_prefix(base).unwrap_or(&p);
        if stripped.is_empty() {
            "/".to_string()
        } else {
            stripped.to_string()
        }
    };

    let is_active = move |prefix: &'static str| {
        move || {
            let p = pathname();
            if prefix == "/" {
                p == "/"
            } else {
                p == prefix || p.starts_with(&format!("{}/", prefix))
            }
        }
    };

    let item_class = move |prefix: &'static str| {
        move || {
            let base = "mobile-nav-item";
            if (is_active(prefix))() {
                format!("{} active", base)
            } else {
                base.to_string()
            }
        }
    };

    view! {
        <Show when=move || is_authed.get()>
            <nav class="mobile-bottom-nav" role="navigation" aria-label="Mobile navigation">
                // Home
                <A href=base_href("/") attr:class=item_class("/")>
                    <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75">
                        <path d="M3 9.5L12 3l9 6.5V20a1 1 0 01-1 1H4a1 1 0 01-1-1V9.5z"
                            stroke-linecap="round" stroke-linejoin="round"/>
                        <polyline points="9 22 9 12 15 12 15 22"
                            stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                    <span>"Home"</span>
                </A>

                // Chat
                <A href=base_href("/chat") attr:class=item_class("/chat")>
                    <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75">
                        <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"
                            stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                    <span>"Chat"</span>
                </A>

                // DMs (with unread badge)
                <A href=base_href("/dm") attr:class=item_class("/dm")>
                    <div class="relative">
                        <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75">
                            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"
                                stroke-linecap="round" stroke-linejoin="round"/>
                            <polyline points="22,6 12,13 2,6"
                                stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                        {move || {
                            let count = unread.0.get();
                            (count > 0).then(|| {
                                let label = if count > 99 {
                                    "99+".to_string()
                                } else {
                                    count.to_string()
                                };
                                view! {
                                    <span class="notification-badge neon-pulse">{label}</span>
                                }
                            })
                        }}
                    </div>
                    <span>"DMs"</span>
                </A>

                // Forums
                <A href=base_href("/forums") attr:class=item_class("/forums")>
                    <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75">
                        <rect x="3" y="3" width="7" height="7" rx="1"
                            stroke-linecap="round" stroke-linejoin="round"/>
                        <rect x="14" y="3" width="7" height="7" rx="1"
                            stroke-linecap="round" stroke-linejoin="round"/>
                        <rect x="3" y="14" width="7" height="7" rx="1"
                            stroke-linecap="round" stroke-linejoin="round"/>
                        <rect x="14" y="14" width="7" height="7" rx="1"
                            stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                    <span>"Forums"</span>
                </A>

                // Profile
                <A href={
                    let auth = use_auth();
                    let pk = auth.pubkey();
                    move || {
                        match pk.get() {
                            Some(pk) => base_href(&format!("/profile/{}", pk)),
                            None => base_href("/settings"),
                        }
                    }
                } attr:class=item_class("/profile")>
                    <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75">
                        <circle cx="12" cy="8" r="4"
                            stroke-linecap="round" stroke-linejoin="round"/>
                        <path d="M20 21a8 8 0 10-16 0"
                            stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                    <span>"Profile"</span>
                </A>
            </nav>
        </Show>
    }
}
