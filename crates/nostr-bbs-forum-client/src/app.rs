//! Root application component with router, layout, and auth gate.

use leptos::prelude::*;
use leptos_router::components::{FlatRoutes, Route, Router, A};
use leptos_router::hooks::{use_location, use_navigate};
use leptos_router::path;
use leptos_router::NavigateOptions;

use crate::auth::{provide_auth, use_auth};
use crate::components::bookmarks_modal::provide_bookmarks;
use crate::components::bookmarks_modal::BookmarksModal;
use crate::components::fx::provide_render_tier;
use crate::components::global_search::GlobalSearch;
use crate::components::message_bubble::{provide_profile_modal_target, ProfileModalTarget};
use crate::components::mobile_bottom_nav::{provide_unread_dm_count, MobileBottomNav};
use crate::components::notification_bell::{provide_notifications, NotificationBell};
use crate::components::onboarding_modal::{provide_onboarding_prefill, OnboardingModal};
use crate::components::profile_modal::ProfileModal;
use crate::components::screen_reader::{provide_announcer, ScreenReaderAnnouncer};
use crate::components::session_timeout::SessionTimeout;
use crate::components::toast::{provide_toasts, ToastContainer};
use crate::components::user_display::provide_name_cache;
use crate::pages::{
    AdminPage, CategoryPage, ChannelPage, ChatPage, DmChatPage, DmListPage, EventsPage, ForumsPage,
    GovernancePage, HomePage, LoginPage, MarketplacePage, NoteViewPage, PendingPage,
    PodBrowserPage, ProfilePage, SearchPage, SectionPage, SettingsPage, SetupPage, SignupPage,
};
use crate::relay::{ConnectionState, RelayConnection};
use crate::stores::channels::{provide_channel_store, use_channel_store};
use crate::stores::mute::provide_mute_store;
use crate::stores::panel_registry::provide_panel_registry;
use crate::stores::preferences::provide_preferences;
use crate::stores::profile_cache::{provide_profile_cache, try_use_profile_cache};
use crate::stores::read_position::provide_read_positions;
use crate::stores::zone_access::provide_zone_access;

// -- Base path for sub-directory deployment -----------------------------------

/// Base URL prefix. Set `FORUM_BASE=/community` at compile time for production.
/// Empty/unset for local development (routes mount at root).
const FORUM_BASE: &str = match option_env!("FORUM_BASE") {
    Some(b) => b,
    None => "",
};

/// Build a full href by prepending the base path.
///
/// Use for `<A href=...>` and `window.location.set_href()`.
/// Do **NOT** use with `use_navigate()` — the router prepends `base` automatically.
pub(crate) fn base_href(path: &str) -> String {
    if FORUM_BASE.is_empty() {
        path.to_string()
    } else {
        format!("{}{}", FORUM_BASE, path)
    }
}

/// Strip `FORUM_BASE` from a browser path, returning a base-relative app path.
///
/// `current_app_path("/community/forums")` → `"/forums"` when `FORUM_BASE="/community"`.
/// Identity when `FORUM_BASE` is empty. Always returns a string starting with `/`.
///
/// Use this whenever you want to feed `location.pathname.get()` back into
/// `use_navigate(...)` or store it in a `returnTo` query — the router will
/// re-prefix the base on its own, so the value stored must NOT contain it.
pub(crate) fn current_app_path(pathname: &str) -> String {
    if FORUM_BASE.is_empty() {
        return pathname.to_string();
    }
    let stripped = pathname.strip_prefix(FORUM_BASE).unwrap_or(pathname);
    if stripped.is_empty() {
        "/".to_string()
    } else if stripped.starts_with('/') {
        stripped.to_string()
    } else {
        format!("/{stripped}")
    }
}

// -- SVG icon helpers ---------------------------------------------------------

fn brand_icon() -> impl IntoView {
    view! {
        <svg class="w-7 h-7 text-amber-400" viewBox="0 0 24 24" fill="none">
            <path d="M12 2L21.5 7.5V16.5L12 22L2.5 16.5V7.5L12 2Z"
                fill="currentColor" fill-opacity="0.2" stroke="currentColor" stroke-width="1.5"/>
            <circle cx="12" cy="12" r="3" fill="currentColor"/>
        </svg>
    }
}

fn chat_icon() -> impl IntoView {
    view! {
        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn dm_icon() -> impl IntoView {
    view! {
        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"
                stroke-linecap="round" stroke-linejoin="round"/>
            <polyline points="22,6 12,13 2,6" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn user_icon() -> impl IntoView {
    view! {
        <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"
                stroke-linecap="round" stroke-linejoin="round"/>
            <circle cx="12" cy="7" r="4" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn logout_icon() -> impl IntoView {
    view! {
        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"
                stroke-linecap="round" stroke-linejoin="round"/>
            <polyline points="16 17 21 12 16 7" stroke-linecap="round" stroke-linejoin="round"/>
            <line x1="21" y1="12" x2="9" y2="12" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn hamburger_icon() -> impl IntoView {
    view! {
        <svg class="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="3" y1="6" x2="21" y2="6" stroke-linecap="round"/>
            <line x1="3" y1="12" x2="21" y2="12" stroke-linecap="round"/>
            <line x1="3" y1="18" x2="21" y2="18" stroke-linecap="round"/>
        </svg>
    }
}

fn close_icon() -> impl IntoView {
    view! {
        <svg class="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18" stroke-linecap="round"/>
            <line x1="6" y1="6" x2="18" y2="18" stroke-linecap="round"/>
        </svg>
    }
}

fn governance_icon() -> impl IntoView {
    view! {
        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="3" stroke-linecap="round"/>
            <path d="M12 2v4m0 12v4M2 12h4m12 0h4m-2.93-7.07l-2.83 2.83m-8.48 8.48l-2.83 2.83m0-14.14l2.83 2.83m8.48 8.48l2.83 2.83"
                stroke-linecap="round"/>
        </svg>
    }
}

fn admin_icon() -> impl IntoView {
    view! {
        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn forums_icon() -> impl IntoView {
    view! {
        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="3" width="7" height="7" rx="1" stroke-linecap="round" stroke-linejoin="round"/>
            <rect x="14" y="3" width="7" height="7" rx="1" stroke-linecap="round" stroke-linejoin="round"/>
            <rect x="3" y="14" width="7" height="7" rx="1" stroke-linecap="round" stroke-linejoin="round"/>
            <rect x="14" y="14" width="7" height="7" rx="1" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn events_icon() -> impl IntoView {
    view! {
        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="4" width="18" height="18" rx="2" stroke-linecap="round" stroke-linejoin="round"/>
            <line x1="16" y1="2" x2="16" y2="6" stroke-linecap="round"/>
            <line x1="8" y1="2" x2="8" y2="6" stroke-linecap="round"/>
            <line x1="3" y1="10" x2="21" y2="10" stroke-linecap="round"/>
        </svg>
    }
}

fn pod_icon() -> impl IntoView {
    view! {
        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <ellipse cx="12" cy="5" rx="9" ry="3" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn settings_icon() -> impl IntoView {
    view! {
        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="3" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn loading_spinner() -> impl IntoView {
    view! {
        <div class="flex flex-col items-center justify-center min-h-[60vh] gap-4">
            <div class="animate-spin w-8 h-8 border-2 border-amber-400 border-t-transparent rounded-full"></div>
            <p class="text-gray-500 text-sm">"Loading..."</p>
        </div>
    }
}

fn redirect_spinner() -> impl IntoView {
    view! {
        <div class="flex flex-col items-center justify-center min-h-[60vh] gap-4">
            <div class="animate-spin w-8 h-8 border-2 border-amber-400 border-t-transparent rounded-full"></div>
            <p class="text-gray-400 text-sm">"Redirecting to login..."</p>
        </div>
    }
}

// -- App root -----------------------------------------------------------------

#[component]
pub fn App() -> impl IntoView {
    provide_auth();
    provide_zone_access();
    provide_render_tier();

    // Provide global context stores
    provide_toasts();
    provide_notifications();
    crate::stores::notifications::provide_notification_store();
    provide_bookmarks();
    provide_unread_dm_count();
    provide_name_cache();
    provide_profile_cache();
    provide_profile_modal_target();
    provide_onboarding_prefill();
    provide_read_positions();
    provide_mute_store();
    provide_preferences();
    provide_announcer();
    crate::stores::badges::provide_badges();
    provide_panel_registry();
    // Popover coordinator: only one header popover (Notifications,
    // Bookmarks, …) can be open at a time. Bug #18 — clicking one used
    // to leave the other open *and* intercept the channel cards behind
    // them.
    provide_context(crate::components::popover_coord::PopoverCoord::new());

    // Provide relay connection as context — connect/disconnect reactively with auth state
    let relay = RelayConnection::new();
    provide_context(relay.clone());
    provide_channel_store();

    let auth = use_auth();
    let is_authed = auth.is_authenticated();

    let auth_conn = auth;
    Effect::new(move |_| {
        if is_authed.get() {
            let r = expect_context::<RelayConnection>();
            let a = auth_conn;
            if a.state.get_untracked().is_nip07 {
                let a2 = a;
                let async_signer: crate::relay::AuthSignAsyncCallback =
                    std::rc::Rc::new(move |event| {
                        let auth = a2;
                        Box::pin(async move { auth.sign_event_async(event).await.ok() })
                    });
                r.set_auth_signer_async(async_signer);
            } else {
                let sync_signer = std::rc::Rc::new(move |event: nostr_bbs_core::UnsignedEvent| {
                    a.sign_event(event).ok()
                });
                r.set_auth_signer(sync_signer);
            }
            r.connect();
        } else {
            let r = expect_context::<RelayConnection>();
            r.disconnect();
        }
    });

    // Publish kind-0 profile event on first relay connect to trigger auto-whitelist.
    // Without this, new users who register/login are authenticated client-side but
    // the relay never sees them, so kind-42 messages get rejected ("not whitelisted").
    {
        let published_profile = RwSignal::new(false);
        let relay_state = relay.connection_state();
        let auth_k0 = auth;
        Effect::new(move |_| {
            if relay_state.get() != ConnectionState::Connected {
                return;
            }
            if !is_authed.get() {
                published_profile.set(false);
                return;
            }
            if published_profile.get_untracked() {
                return;
            }

            let auth = auth_k0;
            let r = expect_context::<RelayConnection>();
            let pubkey = match auth.pubkey().get_untracked() {
                Some(pk) => pk,
                None => return,
            };

            let nickname = auth.nickname().get_untracked().unwrap_or_default();
            let content = serde_json::json!({
                "name": nickname,
                "display_name": nickname,
            })
            .to_string();

            let now = (js_sys::Date::now() / 1000.0) as u64;
            let unsigned = nostr_bbs_core::UnsignedEvent {
                pubkey: pubkey.clone(),
                created_at: now,
                kind: 0,
                tags: vec![],
                content,
            };

            wasm_bindgen_futures::spawn_local(async move {
                match auth.sign_event_async(unsigned).await {
                    Ok(signed) => {
                        r.publish(&signed);
                        published_profile.set(true);
                        web_sys::console::log_1(
                            &format!(
                                "[app] Published kind-0 profile for auto-whitelist: {}",
                                &pubkey[..8]
                            )
                            .into(),
                        );
                    }
                    Err(e) => {
                        web_sys::console::warn_1(
                            &format!("[app] Failed to publish kind-0: {e}").into(),
                        );
                    }
                }
            });
        });
    }

    // Publish kind-10002 (relay list) on first login so peers can discover our relay.
    // This is a replaceable event, so publishing again is idempotent.
    {
        let published_relay_list = RwSignal::new(false);
        let relay_state = relay.connection_state();
        let auth_k10002 = auth;
        Effect::new(move |_| {
            if relay_state.get() != ConnectionState::Connected {
                return;
            }
            if !is_authed.get() {
                published_relay_list.set(false);
                return;
            }
            if published_relay_list.get_untracked() {
                return;
            }

            let auth = auth_k10002;
            let r = expect_context::<RelayConnection>();
            let pubkey = match auth.pubkey().get_untracked() {
                Some(pk) => pk,
                None => return,
            };

            let relay_url = crate::utils::relay_url::relay_url();
            let now = (js_sys::Date::now() / 1000.0) as u64;
            let unsigned = nostr_bbs_core::UnsignedEvent {
                pubkey: pubkey.clone(),
                created_at: now,
                kind: 10002,
                tags: vec![vec!["r".to_string(), relay_url]],
                content: String::new(),
            };

            wasm_bindgen_futures::spawn_local(async move {
                match auth.sign_event_async(unsigned).await {
                    Ok(signed) => {
                        r.publish(&signed);
                        published_relay_list.set(true);
                        web_sys::console::log_1(
                            &format!(
                                "[app] Published kind-10002 relay list for: {}",
                                &pubkey[..8]
                            )
                            .into(),
                        );
                    }
                    Err(e) => {
                        web_sys::console::warn_1(
                            &format!("[app] Failed to publish kind-10002: {e}").into(),
                        );
                    }
                }
            });
        });
    }

    // Subscribe to kind-0 metadata events on the relay and feed them into the
    // ProfileCache so every component that renders a pubkey gets a live
    // nickname as soon as the relay sends it. The subscription is unfiltered
    // (no `authors`) so we receive any kind-0 the relay emits — typically
    // the contact graph plus anyone who posts in our channels.
    {
        let kind0_sub_started = RwSignal::new(false);
        let relay_state = relay.connection_state();
        Effect::new(move |_| {
            if relay_state.get() != ConnectionState::Connected {
                return;
            }
            if kind0_sub_started.get_untracked() {
                return;
            }
            let cache = match try_use_profile_cache() {
                Some(c) => c,
                None => return,
            };
            let r = expect_context::<RelayConnection>();
            let filter = crate::relay::Filter {
                kinds: Some(vec![0]),
                limit: Some(500),
                ..Default::default()
            };
            let on_event: crate::relay::EventCallback =
                std::rc::Rc::new(move |event: nostr_bbs_core::NostrEvent| {
                    if event.kind == 0 && !event.content.is_empty() {
                        cache.upsert_from_kind0(&event.pubkey, &event.content, event.created_at);
                    }
                });
            r.subscribe(vec![filter], on_event, None);
            kind0_sub_started.set(true);
        });
    }

    // Subscribe to governance events (kinds 31400-31405) and feed them into the
    // PanelRegistry store so the governance page renders live agent panels.
    {
        let gov_sub_started = RwSignal::new(false);
        let relay_state = relay.connection_state();
        Effect::new(move |_| {
            if relay_state.get() != ConnectionState::Connected {
                return;
            }
            if gov_sub_started.get_untracked() {
                return;
            }
            let registry = crate::stores::panel_registry::use_panel_registry();
            let r = expect_context::<RelayConnection>();
            let filter = crate::relay::Filter {
                kinds: Some(vec![31400, 31401, 31402, 31403, 31404, 31405]),
                limit: Some(200),
                ..Default::default()
            };
            let on_event: crate::relay::EventCallback =
                std::rc::Rc::new(move |event: nostr_bbs_core::NostrEvent| {
                    registry.ingest_event(&event);
                });
            r.subscribe(vec![filter], on_event, None);
            gov_sub_started.set(true);
        });
    }

    // Start channel sync once relay connects (single subscription for all pages)
    let relay_conn = relay.connection_state();
    Effect::new(move |_| {
        if relay_conn.get() != ConnectionState::Connected {
            return;
        }
        let store = use_channel_store();
        let r = expect_context::<RelayConnection>();
        store.start_sync(&r);
    });

    // Start message count sync after channel EOSE
    Effect::new(move |_| {
        let store = use_channel_store();
        if !store.eose_received.get() {
            return;
        }
        let r = expect_context::<RelayConnection>();
        store.start_msg_sync(&r);
    });

    // Start badge sync after relay connects
    crate::stores::badges::init_badge_sync();

    // Cleanup on unmount
    {
        let relay_cleanup = relay;
        on_cleanup(move || {
            let store = use_channel_store();
            store.cleanup(&relay_cleanup);
        });
    }

    view! {
        <Router base=FORUM_BASE>
            <Layout>
                <FlatRoutes fallback=|| view! {
                    <div class="min-h-screen bg-gray-900 text-white flex items-center justify-center">
                        <div class="text-center">
                            <h1 class="text-6xl font-bold mb-4">"404"</h1>
                            <p class="text-gray-400 mb-8">"Page not found"</p>
                            <A href=base_href("/") attr:class="text-amber-400 hover:text-amber-300 underline">
                                "Go home"
                            </A>
                        </div>
                    </div>
                }>
                    // Public routes (no auth required)
                    <Route path=path!("/") view=HomePage />
                    <Route path=path!("/login") view=LoginPage />
                    <Route path=path!("/signup") view=SignupPage />
                    <Route path=path!("/view/:note_id") view=NoteViewPage />
                    // Auth-gated routes
                    <Route path=path!("/setup") view=AuthGatedSetup />
                    <Route path=path!("/pending") view=AuthGatedPending />
                    <Route path=path!("/chat") view=AuthGatedChat />
                    <Route path=path!("/chat/:channel_id") view=AuthGatedChannel />
                    <Route path=path!("/dm") view=AuthGatedDmList />
                    <Route path=path!("/dm/:pubkey") view=AuthGatedDmChat />
                    <Route path=path!("/forums") view=AuthGatedForums />
                    <Route path=path!("/forums/:category") view=AuthGatedCategory />
                    <Route path=path!("/forums/:category/:section") view=AuthGatedSection />
                    <Route path=path!("/events") view=AuthGatedEvents />
                    <Route path=path!("/profile/:pubkey") view=AuthGatedProfile />
                    <Route path=path!("/search") view=AuthGatedSearch />
                    <Route path=path!("/settings") view=AuthGatedSettings />
                    <Route path=path!("/admin") view=AdminPage />
                    <Route path=path!("/governance") view=AuthGatedGovernance />
                    <Route path=path!("/pod") view=AuthGatedPod />
                    <Route path=path!("/marketplace") view=MarketplacePage />
                </FlatRoutes>
            </Layout>
        </Router>
    }
}

// -- Layout -------------------------------------------------------------------

#[component]
fn Layout(children: Children) -> impl IntoView {
    let auth = use_auth();
    let is_authed = auth.is_authenticated();
    let nickname = auth.nickname();
    let pubkey = auth.pubkey();
    let mobile_open = RwSignal::new(false);
    let bookmarks_open = RwSignal::new(false);
    let profile_target_pk = RwSignal::new(String::new());
    let profile_open = RwSignal::new(false);

    // Bug #18: Bookmarks popover participates in the shared PopoverCoord so
    // opening it closes Notifications (and vice versa). Two-way sync:
    // - coord active → reflect into `bookmarks_open` so the modal renders
    // - `bookmarks_open` cleared by the modal's own close button → tell the
    //   coordinator so the next toggle behaves correctly.
    let coord = crate::components::popover_coord::use_popover_coord();
    const BOOKMARKS_KEY: &str = "bookmarks";
    Effect::new(move |_| {
        bookmarks_open.set(coord.is_active(BOOKMARKS_KEY));
    });
    Effect::new(move |_| {
        if !bookmarks_open.get() {
            coord.close(BOOKMARKS_KEY);
        }
    });

    // Watch for profile modal requests from any component
    Effect::new(move |_| {
        if let Some(target) = use_context::<ProfileModalTarget>() {
            if let Some(pk) = target.0.get() {
                profile_target_pk.set(pk);
                profile_open.set(true);
                target.0.set(None);
            }
        }
    });

    let location = use_location();
    // Strip FORUM_BASE prefix so nav comparisons work regardless of sub-directory.
    let pathname = move || {
        let p = location.pathname.get();
        if FORUM_BASE.is_empty() {
            return p;
        }
        let stripped = p.strip_prefix(FORUM_BASE).unwrap_or(&p);
        if stripped.is_empty() {
            "/".to_string()
        } else {
            stripped.to_string()
        }
    };

    // Resolve the logged-in user's display name through the layered profile
    // cache. Falls back to `auth.nickname()` (set during onboarding) and
    // finally to a shortened hex key + "Anonymous".
    let display_name = Memo::new(move |_| {
        if let Some(pk) = pubkey.get() {
            if !pk.is_empty() {
                let resolved = crate::components::user_display::use_display_name(&pk);
                if !resolved.is_empty() {
                    return resolved;
                }
            }
        }
        nickname.get().unwrap_or_else(|| "Anonymous".to_string())
    });

    let zone_access = crate::stores::zone_access::use_zone_access();
    let is_admin = Memo::new(move |_| zone_access.is_admin.get());

    // Helper: returns active or inactive CSS for nav links
    let nav_link_class = move |prefix: &'static str| {
        move || {
            let p = pathname();
            let active = if prefix == "/" {
                p == "/"
            } else {
                p == prefix || p.starts_with(&format!("{}/", prefix))
            };
            if active {
                "flex items-center gap-1.5 text-amber-400 transition-colors px-3 py-2 rounded-lg hover:bg-gray-800 font-medium"
            } else {
                "flex items-center gap-1.5 text-gray-300 hover:text-white transition-colors px-3 py-2 rounded-lg hover:bg-gray-800"
            }
        }
    };

    let mobile_link_class = move |prefix: &'static str| {
        move || {
            let p = pathname();
            let active = if prefix == "/" {
                p == "/"
            } else {
                p == prefix || p.starts_with(&format!("{}/", prefix))
            };
            if active {
                "flex items-center gap-2 text-amber-400 font-medium px-4 py-3 rounded-lg bg-amber-400/10"
            } else {
                "flex items-center gap-2 text-gray-300 hover:text-white px-4 py-3 rounded-lg hover:bg-gray-800 transition-colors"
            }
        }
    };

    let close_mobile = move |_| {
        mobile_open.set(false);
    };

    view! {
        <div class="min-h-screen bg-gray-900 text-white flex flex-col">
            // Skip navigation link
            <a
                href="#main-content"
                class="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-[100] focus:px-4 focus:py-2 focus:bg-amber-500 focus:text-gray-900 focus:rounded-lg focus:font-semibold focus:text-sm"
            >
                "Skip to main content"
            </a>

            // Screen reader announcer
            <ScreenReaderAnnouncer />

            // Header
            <header class="border-b border-gray-800/50 bg-gray-900/80 backdrop-blur-md sticky top-0 z-50">
                <nav class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
                    // Brand
                    <a href="/" class="flex items-center gap-2 text-xl sm:text-2xl font-bold text-amber-400 hover:text-amber-300 transition-colors">
                        {brand_icon()}
                        "Forum"
                    </a>

                    // Desktop nav
                    <div class="hidden sm:flex items-center gap-4">
                        <Show
                            when=move || is_authed.get()
                            fallback=move || view! {
                                <A href=base_href("/login") attr:class="text-gray-300 hover:text-white transition-colors px-3 py-2 rounded-lg hover:bg-gray-800">
                                    "Log In"
                                </A>
                                <A href=base_href("/signup") attr:class="bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors">
                                    "Sign Up"
                                </A>
                            }
                        >
                            <A href=base_href("/forums") attr:class=nav_link_class("/forums")>
                                {forums_icon()}
                                "Forums"
                            </A>
                            <A href=base_href("/chat") attr:class=nav_link_class("/chat")>
                                {chat_icon()}
                                "Chat"
                            </A>
                            <A href=base_href("/dm") attr:class=nav_link_class("/dm")>
                                {dm_icon()}
                                "DMs"
                            </A>
                            <A href=base_href("/events") attr:class=nav_link_class("/events")>
                                {events_icon()}
                                "Events"
                            </A>
                            <A href=base_href("/governance") attr:class=nav_link_class("/governance")>
                                {governance_icon()}
                                "Agents"
                            </A>
                            <A href=base_href("/pod") attr:class=nav_link_class("/pod")>
                                {pod_icon()}
                                "Pod"
                            </A>
                            {move || is_admin.get().then(|| view! {
                                <A href=base_href("/admin") attr:class=nav_link_class("/admin")>
                                    {admin_icon()}
                                    <span class="text-sm">"Admin"</span>
                                </A>
                            })}
                            <NotificationBell />
                            <button
                                class="text-gray-400 hover:text-amber-400 transition-colors p-2 rounded-lg hover:bg-gray-800"
                                on:click=move |_| coord.toggle(BOOKMARKS_KEY)
                                title="Bookmarks"
                            >
                                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M5 2h14a1 1 0 011 1v19.143a.5.5 0 01-.766.424L12 18.03l-7.234 4.536A.5.5 0 014 22.143V3a1 1 0 011-1z"/>
                                </svg>
                            </button>
                            <A href=base_href("/settings") attr:class="text-gray-400 hover:text-white transition-colors p-2 rounded-lg hover:bg-gray-800">
                                {settings_icon()}
                            </A>
                            <div class="flex items-center gap-1.5 bg-gray-800 px-3 py-1 rounded-full text-xs text-gray-300">
                                {user_icon()}
                                <span>{move || display_name.get()}</span>
                            </div>
                            <LogoutButton />
                        </Show>
                    </div>

                    // Mobile hamburger
                    <button
                        class="sm:hidden p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-800 transition-colors"
                        on:click=move |_| mobile_open.update(|v| *v = !*v)
                    >
                        <Show
                            when=move || mobile_open.get()
                            fallback=|| { hamburger_icon() }
                        >
                            {close_icon()}
                        </Show>
                    </button>
                </nav>

                // Mobile dropdown menu
                <Show when=move || mobile_open.get()>
                    <div class="sm:hidden border-t border-gray-800/50 bg-gray-900/95 backdrop-blur-md px-4 pb-4 pt-2 space-y-1">
                        <Show
                            when=move || is_authed.get()
                            fallback=move || view! {
                                <A href=base_href("/login") attr:class="block text-gray-300 hover:text-white px-4 py-3 rounded-lg hover:bg-gray-800 transition-colors" on:click=close_mobile>
                                    "Log In"
                                </A>
                                <A href=base_href("/signup") attr:class="block bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-4 py-3 rounded-lg transition-colors text-center" on:click=close_mobile>
                                    "Sign Up"
                                </A>
                            }
                        >
                            <A href=base_href("/forums") attr:class=mobile_link_class("/forums") on:click=close_mobile>
                                {forums_icon()}
                                "Forums"
                            </A>
                            <A href=base_href("/chat") attr:class=mobile_link_class("/chat") on:click=close_mobile>
                                {chat_icon()}
                                "Chat"
                            </A>
                            <A href=base_href("/dm") attr:class=mobile_link_class("/dm") on:click=close_mobile>
                                {dm_icon()}
                                "DMs"
                            </A>
                            <A href=base_href("/events") attr:class=mobile_link_class("/events") on:click=close_mobile>
                                {events_icon()}
                                "Events"
                            </A>
                            <A href=base_href("/governance") attr:class=mobile_link_class("/governance") on:click=close_mobile>
                                {governance_icon()}
                                "Agents"
                            </A>
                            <A href=base_href("/pod") attr:class=mobile_link_class("/pod") on:click=close_mobile>
                                {pod_icon()}
                                "Pod"
                            </A>
                            <A href=base_href("/settings") attr:class=mobile_link_class("/settings") on:click=close_mobile>
                                {settings_icon()}
                                "Settings"
                            </A>
                            {move || is_admin.get().then(|| view! {
                                <A href=base_href("/admin") attr:class=mobile_link_class("/admin") on:click=close_mobile>
                                    {admin_icon()}
                                    "Admin"
                                </A>
                            })}
                            <div class="border-t border-gray-800/50 mt-2 pt-2 flex items-center justify-between px-4 py-2">
                                <div class="flex items-center gap-2 text-gray-300 text-sm">
                                    {user_icon()}
                                    <span>{move || display_name.get()}</span>
                                </div>
                                <LogoutButton />
                            </div>
                        </Show>
                    </div>
                </Show>
            </header>

            <main id="main-content" class="flex-1" role="main">
                {children()}
            </main>

            // Global overlays and layout components
            <ToastContainer />
            <GlobalSearch />
            <SessionTimeout />
            <MobileBottomNav />
            <BookmarksModal is_open=bookmarks_open />
            // Username onboarding modal — self-gates on auth + localStorage flags
            <OnboardingModal />

            {move || {
                let pk = profile_target_pk.get();
                (!pk.is_empty()).then(|| view! {
                    <ProfileModal pubkey=pk is_open=profile_open />
                })
            }}

            // Footer
            <footer class="border-t border-gray-800/50 py-8 mt-auto">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div class="flex flex-col sm:flex-row items-center justify-between gap-4">
                        <div class="flex items-center gap-2 text-gray-500">
                            {brand_icon()}
                            <span class="text-sm">"Forum"</span>
                        </div>
                        <div class="flex items-center gap-3 text-xs text-gray-600">
                            <span>"End-to-end encrypted"</span>
                            <span class="text-gray-700">"|"</span>
                            <span>"Built with Rust + WASM"</span>
                        </div>
                        <div class="text-xs text-gray-600">"2026"</div>
                    </div>
                </div>
            </footer>
        </div>
    }
}

// -- Logout button ------------------------------------------------------------

#[component]
fn LogoutButton() -> impl IntoView {
    let auth = use_auth();

    let on_logout = move |_| {
        auth.logout();
    };

    view! {
        <button
            on:click=on_logout
            class="flex items-center gap-1.5 text-gray-400 hover:text-red-400 transition-colors px-3 py-2 rounded-lg border border-transparent hover:border-red-500/20 hover:bg-red-500/10 text-sm"
        >
            {logout_icon()}
            "Log Out"
        </button>
    }
}

// -- Auth-gated chat pages ----------------------------------------------------

/// Channel list with auth gate -- SPA-navigates to login if not authenticated.
#[component]
fn AuthGatedChat() -> impl IntoView {
    let auth = use_auth();
    let is_authed = auth.is_authenticated();
    let is_ready = auth.is_ready();
    let navigate = StoredValue::new(use_navigate());
    let location = use_location();

    Effect::new(move |_| {
        if is_ready.get() && !is_authed.get() {
            let current = current_app_path(&location.pathname.get());
            let target = login_redirect_target(&current);
            navigate.with_value(|nav| nav(&target, NavigateOptions::default()));
        }
    });

    view! {
        <Show when=move || is_ready.get() fallback=|| { loading_spinner() }>
            <Show when=move || is_authed.get() fallback=|| { redirect_spinner() }>
                <ChatPage />
            </Show>
        </Show>
    }
}

/// Single channel view with auth gate.
#[component]
fn AuthGatedChannel() -> impl IntoView {
    let auth = use_auth();
    let is_authed = auth.is_authenticated();
    let is_ready = auth.is_ready();
    let navigate = StoredValue::new(use_navigate());
    let location = use_location();

    Effect::new(move |_| {
        if is_ready.get() && !is_authed.get() {
            let current = current_app_path(&location.pathname.get());
            let target = login_redirect_target(&current);
            navigate.with_value(|nav| nav(&target, NavigateOptions::default()));
        }
    });

    view! {
        <Show when=move || is_ready.get() fallback=|| { loading_spinner() }>
            <Show when=move || is_authed.get() fallback=|| { redirect_spinner() }>
                <ChannelPage />
            </Show>
        </Show>
    }
}

/// DM conversation list with auth gate.
#[component]
fn AuthGatedDmList() -> impl IntoView {
    let auth = use_auth();
    let is_authed = auth.is_authenticated();
    let is_ready = auth.is_ready();
    let navigate = StoredValue::new(use_navigate());
    let location = use_location();

    Effect::new(move |_| {
        if is_ready.get() && !is_authed.get() {
            let current = current_app_path(&location.pathname.get());
            let target = login_redirect_target(&current);
            navigate.with_value(|nav| nav(&target, NavigateOptions::default()));
        }
    });

    view! {
        <Show when=move || is_ready.get() fallback=|| { loading_spinner() }>
            <Show when=move || is_authed.get() fallback=|| { redirect_spinner() }>
                <DmListPage />
            </Show>
        </Show>
    }
}

/// Single DM conversation with auth gate.
#[component]
fn AuthGatedDmChat() -> impl IntoView {
    let auth = use_auth();
    let is_authed = auth.is_authenticated();
    let is_ready = auth.is_ready();
    let navigate = StoredValue::new(use_navigate());
    let location = use_location();

    Effect::new(move |_| {
        if is_ready.get() && !is_authed.get() {
            let current = current_app_path(&location.pathname.get());
            let target = login_redirect_target(&current);
            navigate.with_value(|nav| nav(&target, NavigateOptions::default()));
        }
    });

    view! {
        <Show when=move || is_ready.get() fallback=|| { loading_spinner() }>
            <Show when=move || is_authed.get() fallback=|| { redirect_spinner() }>
                <DmChatPage />
            </Show>
        </Show>
    }
}

// -- Auth-gated v3.0 pages ----------------------------------------------------

/// Compute a `/login?returnTo=...` target from the current pathname, avoiding
/// redirect loops when the user is already on `/login` or `/signup`.
fn login_redirect_target(pathname: &str) -> String {
    if pathname.is_empty()
        || pathname == "/login"
        || pathname == "/signup"
        || !pathname.starts_with('/')
    {
        "/login".to_string()
    } else {
        format!("/login?returnTo={}", pathname)
    }
}

/// Macro-like helper: all new auth gates follow identical pattern.
macro_rules! auth_gated {
    ($name:ident, $page:ident) => {
        #[component]
        fn $name() -> impl IntoView {
            let auth = use_auth();
            let is_authed = auth.is_authenticated();
            let is_ready = auth.is_ready();
            let navigate = StoredValue::new(use_navigate());
            let location = use_location();

            Effect::new(move |_| {
                if is_ready.get() && !is_authed.get() {
                    let current = location.pathname.get();
                    let target = login_redirect_target(&current);
                    navigate.with_value(|nav| nav(&target, NavigateOptions::default()));
                }
            });

            view! {
                <Show when=move || is_ready.get() fallback=|| { loading_spinner() }>
                    <Show when=move || is_authed.get() fallback=|| { redirect_spinner() }>
                        <$page />
                    </Show>
                </Show>
            }
        }
    };
}

auth_gated!(AuthGatedSetup, SetupPage);
auth_gated!(AuthGatedPending, PendingPage);
auth_gated!(AuthGatedForums, ForumsPage);
auth_gated!(AuthGatedCategory, CategoryPage);
auth_gated!(AuthGatedSection, SectionPage);
auth_gated!(AuthGatedEvents, EventsPage);
auth_gated!(AuthGatedProfile, ProfilePage);
auth_gated!(AuthGatedSearch, SearchPage);
auth_gated!(AuthGatedSettings, SettingsPage);
auth_gated!(AuthGatedGovernance, GovernancePage);
auth_gated!(AuthGatedPod, PodBrowserPage);
