//! Re-imagined TUI Workspace Shell:
//! - Desktop: top status/breadcrumb bar + collapsible left sidebar + main pane
//!   + footer & `/` command bar.
//! - Mobile: compact top bar + native-scrolling workspace + slide-out drawer +
//!   sticky 5-tab bottom bar (with unread badges and safe-area padding).
//! - Power-user keyboard accelerators (`/`, `Cmd/Ctrl+K`, `[`, `T`, `ESC`, `?`)
//!   that yield cleanly to text inputs and never hijack touch scrolling.

use leptos::prelude::*;
use nostr_bbs_client_core::auth::use_auth;
use nostr_bbs_client_core::dm::use_dm_store;
use nostr_bbs_client_core::name_cache::use_display_name_tracked;
use nostr_bbs_client_core::relay::{ConnectionState, RelayConnection};
use nostr_bbs_client_core::stores::channels::use_channel_store;
use nostr_bbs_client_core::stores::notifications::use_notification_store;
use nostr_bbs_client_core::stores::panel_registry::use_panel_registry;
use nostr_bbs_client_core::stores::zone_access::use_zone_access;
use nostr_bbs_client_core::stores::zones::{load_zones, zone_slug, ZoneVisibility};
use nostr_bbs_client_core::toast::{use_toasts, ToastVariant};

use crate::components::{launch_sentry, BbsToastBar};
use crate::config::BbsConfig;
use crate::prefs::use_bbs_prefs;
use crate::router::{forum_href, parse_slash_command, use_router, CommandAction, Route};

/// Open state for the global Cmd/Ctrl+K search overlay.
#[derive(Clone, Copy)]
pub struct SearchPaletteState {
    pub open: RwSignal<bool>,
    pub prefill: RwSignal<String>,
}

impl SearchPaletteState {
    pub fn new() -> Self {
        Self {
            open: RwSignal::new(false),
            prefill: RwSignal::new(String::new()),
        }
    }

    pub fn open_with(&self, query: Option<String>) {
        if let Some(q) = query {
            self.prefill.set(q);
        }
        self.open.set(true);
    }
}

impl Default for SearchPaletteState {
    fn default() -> Self {
        Self::new()
    }
}

pub fn use_search_palette() -> SearchPaletteState {
    expect_context::<SearchPaletteState>()
}

/// Top-level workspace layout wrapping the active view.
#[component]
pub fn TuiShell(children: Children) -> impl IntoView {
    let prefs = use_bbs_prefs();
    let router = use_router();
    let search = use_search_palette();

    #[cfg(target_arch = "wasm32")]
    install_global_keys(router, prefs, search);
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (router, search);

    view! {
        <div class=move || format!("bbs-crt {}", prefs.theme.get().css_class())>
            <div class="tui-app">
                <TopBar />
                <div
                    class="tui-body"
                    class:sidebar-collapsed=move || prefs.sidebar_collapsed.get()
                >
                    <div
                        class="tui-drawer-backdrop"
                        class:mobile-open=move || prefs.mobile_drawer_open.get()
                        on:click=move |_| prefs.mobile_drawer_open.set(false)
                    ></div>
                    <Sidebar />
                    <main class="tui-main" id="bbs-main" tabindex="-1">
                        {children()}
                    </main>
                </div>
                <CommandBar />
                <DesktopFooter />
                <MobileBottomNav />
            </div>
            <BbsToastBar />
        </div>
    }
}

/// Top header bar (desktop + mobile).
#[component]
fn TopBar() -> impl IntoView {
    let cfg = use_context::<StoredValue<BbsConfig>>().expect("BbsConfig");
    let node_name = cfg.with_value(|c| c.node_name.clone());
    let router = use_router();
    let prefs = use_bbs_prefs();
    let search = use_search_palette();
    let auth = use_auth();
    let relay = expect_context::<RelayConnection>();
    let conn = relay.connection_state();
    let notifs = use_notification_store();
    let unread_notifs = notifs.unread_count();

    let toggle_nav = move |_| {
        #[cfg(target_arch = "wasm32")]
        {
            let narrow = web_sys::window()
                .and_then(|w| w.inner_width().ok())
                .and_then(|v| v.as_f64())
                .map(|w| w < 900.0)
                .unwrap_or(false);
            if narrow {
                prefs.mobile_drawer_open.update(|v| *v = !*v);
            } else {
                prefs.toggle_sidebar();
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        prefs.toggle_sidebar();
    };

    view! {
        <header class="tui-topbar">
            <div class="tui-topbar-left">
                <button
                    type="button"
                    class="bbs-icon-btn"
                    aria-label="Toggle navigation sidebar"
                    title="Toggle sidebar ([)"
                    on:click=toggle_nav
                >"≡"</button>
                <button
                    type="button"
                    class="tui-brand"
                    on:click=move |_| {
                        prefs.mobile_drawer_open.set(false);
                        router.go(Route::Zones);
                    }
                >
                    <span>">_"</span>
                    <span>{node_name}</span>
                </button>
                <span class="tui-crumb-sep">"/"</span>
                <span class="tui-route-title">{move || router.route.get().title()}</span>
            </div>

            <div class="tui-topbar-right">
                {move || {
                    let st = conn.get();
                    let authed = auth.is_authenticated().get();
                    match (st, authed) {
                        (ConnectionState::Connected, true) => view! {
                            <span class="tui-status-pill ok" title="Connected & authenticated">
                                "● ONLINE"
                            </span>
                        }.into_any(),
                        (ConnectionState::Connected, false) => view! {
                            <button
                                type="button"
                                class="tui-status-pill warn"
                                title="Connected — sign in to unlock gated zones and posting"
                                on:click=move |_| router.go(Route::Settings)
                            >
                                "◐ SIGN IN"
                            </button>
                        }.into_any(),
                        (ConnectionState::Connecting | ConnectionState::Reconnecting, _) => view! {
                            <span class="tui-status-pill warn">"◌ SYNC"</span>
                        }.into_any(),
                        _ => view! {
                            <span class="tui-status-pill bad">"○ OFFLINE"</span>
                        }.into_any(),
                    }
                }}

                <button
                    type="button"
                    class="bbs-icon-btn"
                    aria-label="Search (Ctrl+K)"
                    title="Search (⌘K / Ctrl+K)"
                    on:click=move |_| search.open_with(None)
                >"⌕"</button>

                <button
                    type="button"
                    class="bbs-icon-btn"
                    aria-label="Notifications"
                    title="Notifications"
                    on:click=move |_| router.go(Route::Notifications)
                >
                    "🔔"
                    {move || {
                        let n = unread_notifs.get();
                        (n > 0).then(|| view! {
                            <span class="tui-bnav-badge">{if n > 99 { "99+".into() } else { n.to_string() }}</span>
                        })
                    }}
                </button>

                <button
                    type="button"
                    class="bbs-icon-btn"
                    aria-label="Cycle phosphor theme"
                    title="Cycle phosphor theme (T)"
                    on:click=move |_| prefs.cycle_theme()
                >"◐"</button>

                {move || match auth.pubkey().get() {
                    Some(pk) => {
                        let pk_label = pk.clone();
                        let pk_nav = pk.clone();
                        view! {
                            <button
                                type="button"
                                class="bbs-btn bbs-btn-sm"
                                title="View your profile"
                                on:click=move |_| router.go(Route::Profile { pubkey: pk_nav.clone() })
                            >
                                {move || use_display_name_tracked(&pk_label)}
                            </button>
                        }.into_any()
                    }
                    None => view! {
                        <button
                            type="button"
                            class="bbs-btn bbs-btn-sm bbs-btn-primary"
                            on:click=move |_| router.go(Route::Settings)
                        >"Sign in"</button>
                    }.into_any(),
                }}
            </div>
        </header>
    }
}

/// Persistent desktop sidebar / mobile slide-out drawer.
#[component]
fn Sidebar() -> impl IntoView {
    let router = use_router();
    let prefs = use_bbs_prefs();
    let auth = use_auth();
    let channels = use_channel_store();
    let zone_access = use_zone_access();
    let dm = use_dm_store();
    let panels = use_panel_registry();
    let notifs = use_notification_store();

    let nav = move |r: Route| {
        prefs.mobile_drawer_open.set(false);
        router.go(r);
    };

    let dm_unread = dm.total_unread();

    let pending_gov = Memo::new(move |_| {
        let st = panels.state.get();
        st.actions
            .iter()
            .filter(|a| !st.decisions.get(&a.d_tag).is_some_and(|ds| !ds.is_empty()))
            .count()
    });

    let notif_unread = notifs.unread_count();

    view! {
        <aside
            class="tui-sidebar"
            class:mobile-open=move || prefs.mobile_drawer_open.get()
            aria-label="Workspace navigation"
        >
            // ── ZONES & BOARDS ─────────────────────────────────────────────
            <div class="tui-side-group">
                <div class="tui-side-heading">
                    <span>"ZONES & BOARDS"</span>
                    {move || (!router.pwa_mode.get()).then(|| view! {
                        <button
                            type="button"
                            class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                            on:click=move |_| nav(Route::Zones)
                        >"all"</button>
                    })}
                </div>
                {move || {
                    let zones = load_zones();
                    let pinned = router.pinned_zone.get();
                    let pwa = router.pwa_mode.get();
                    let is_admin = zone_access.is_admin.get();
                    let cohorts = zone_access.cohorts.get();
                    let all_channels = channels.channels.get();
                    let cur = router.route.get();

                    zones
                        .into_iter()
                        .filter(|z| {
                            if pwa {
                                if let Some(ref p) = pinned {
                                    return &z.id == p;
                                }
                            }
                            z.visibility != ZoneVisibility::Hidden
                                || is_admin
                                || z.is_member(&cohorts)
                        })
                        .map(|z| {
                            let zid = z.id.clone();
                            let zslug = zone_slug(&z).to_string();
                            let zname = z.label();
                            let zenc = z.encrypted;
                            let has_kanban = z.kanban;
                            let accent = z.accent_hex.clone().unwrap_or_default();
                            let style = if accent.is_empty() {
                                String::new()
                            } else {
                                format!("--accent:{accent}")
                            };
                            let zone_active = matches!(&cur, Route::Zone { slug } if slug == &zslug || slug == &zid);
                            let zone_boards: Vec<_> = all_channels
                                .iter()
                                .filter(|c| c.section == zid || c.section.starts_with(&format!("{zid}-")))
                                .cloned()
                                .collect();
                            let zid_nav = zslug.clone();
                            let zid_kb = zslug.clone();
                            let cur_for_boards = cur.clone();

                            view! {
                                <div class="tui-side-group" style=style>
                                    <button
                                        type="button"
                                        class="tui-side-item"
                                        class:active=zone_active
                                        on:click=move |_| nav(Route::Zone { slug: zid_nav.clone() })
                                    >
                                        <span class="tui-side-glyph">{if zenc { "🔒" } else { "▓" }}</span>
                                        <span class="tui-side-label">{zname}</span>
                                        <span class="tui-muted">{zone_boards.len()}</span>
                                    </button>
                                    {zone_boards.into_iter().take(8).map(|ch| {
                                        let ch_id = ch.id.clone();
                                        let ch_name = ch.name.clone();
                                        let z_ref = zslug.clone();
                                        let active_b = matches!(
                                            &cur_for_boards,
                                            Route::Board { channel_id, .. } | Route::Thread { channel_id, .. }
                                            if channel_id == &ch_id
                                        );
                                        view! {
                                            <button
                                                type="button"
                                                class="tui-side-item tui-side-sub-item"
                                                class:active=active_b
                                                on:click=move |_| nav(Route::Board {
                                                    zone: z_ref.clone(),
                                                    channel_id: ch_id.clone(),
                                                })
                                            >
                                                <span class="tui-side-glyph">"#"</span>
                                                <span class="tui-side-label">{ch_name}</span>
                                            </button>
                                        }
                                    }).collect_view()}
                                    {has_kanban.then(|| {
                                        let kb_active = matches!(&cur, Route::Kanban { zone } if zone == &zslug || zone == &zid);
                                        view! {
                                            <button
                                                type="button"
                                                class="tui-side-item tui-side-sub-item"
                                                class:active=kb_active
                                                on:click=move |_| nav(Route::Kanban { zone: zid_kb.clone() })
                                            >
                                                <span class="tui-side-glyph">"▤"</span>
                                                <span class="tui-side-label">"Kanban Board"</span>
                                            </button>
                                        }
                                    })}
                                </div>
                            }
                        })
                        .collect_view()
                }}
            </div>

            // ── COMMUNICATION ──────────────────────────────────────────────
            <div class="tui-side-group">
                <div class="tui-side-heading"><span>"COMMUNICATION"</span></div>
                <button
                    type="button"
                    class="tui-side-item"
                    class:active=move || matches!(router.route.get(), Route::DmList | Route::DmChat { .. })
                    on:click=move |_| nav(Route::DmList)
                >
                    <span class="tui-side-glyph">"✉"</span>
                    <span class="tui-side-label">"Direct Messages"</span>
                    {move || {
                        let n = dm_unread.get();
                        (n > 0).then(|| view! { <span class="tui-side-pill">{n}</span> })
                    }}
                </button>
                <button
                    type="button"
                    class="tui-side-item"
                    class:active=move || router.route.get() == Route::LiveFeed
                    on:click=move |_| nav(Route::LiveFeed)
                >
                    <span class="tui-side-glyph">"⚡"</span>
                    <span class="tui-side-label">"Live Feed"</span>
                </button>
                <button
                    type="button"
                    class="tui-side-item"
                    class:active=move || router.route.get() == Route::Notifications
                    on:click=move |_| nav(Route::Notifications)
                >
                    <span class="tui-side-glyph">"🔔"</span>
                    <span class="tui-side-label">"Notifications"</span>
                    {move || {
                        let n = notif_unread.get();
                        (n > 0).then(|| view! { <span class="tui-side-pill">{n}</span> })
                    }}
                </button>
            </div>

            // ── COMMUNITY ──────────────────────────────────────────────────
            <div class="tui-side-group">
                <div class="tui-side-heading"><span>"COMMUNITY"</span></div>
                <button
                    type="button"
                    class="tui-side-item"
                    class:active=move || router.route.get() == Route::Agents
                    on:click=move |_| nav(Route::Agents)
                >
                    <span class="tui-side-glyph">"◈"</span>
                    <span class="tui-side-label">"Agents & Governance"</span>
                    {move || {
                        let n = pending_gov.get();
                        (n > 0).then(|| view! { <span class="tui-side-pill">{n}</span> })
                    }}
                </button>
                <button
                    type="button"
                    class="tui-side-item"
                    class:active=move || router.route.get() == Route::Events
                    on:click=move |_| nav(Route::Events)
                >
                    <span class="tui-side-glyph">"📅"</span>
                    <span class="tui-side-label">"Events & Calendar"</span>
                </button>
                <button
                    type="button"
                    class="tui-side-item"
                    class:active=move || router.route.get() == Route::Knowledge
                    on:click=move |_| nav(Route::Knowledge)
                >
                    <span class="tui-side-glyph">"❖"</span>
                    <span class="tui-side-label">"Knowledge Board"</span>
                </button>
                <button
                    type="button"
                    class="tui-side-item"
                    class:active=move || matches!(router.route.get(), Route::Members | Route::Profile { .. })
                    on:click=move |_| nav(Route::Members)
                >
                    <span class="tui-side-glyph">"●"</span>
                    <span class="tui-side-label">"Members"</span>
                </button>
                <button
                    type="button"
                    class="tui-side-item"
                    class:active=move || router.route.get() == Route::Bookmarks
                    on:click=move |_| nav(Route::Bookmarks)
                >
                    <span class="tui-side-glyph">"★"</span>
                    <span class="tui-side-label">"Bookmarks"</span>
                </button>
            </div>

            // ── DOOR GAMES & ECONOMY ───────────────────────────────────────
            <div class="tui-side-group">
                <div class="tui-side-heading"><span>"DOOR GAMES & ECONOMY"</span></div>
                <button
                    type="button"
                    class="tui-side-item"
                    class:active=move || matches!(router.route.get(), Route::Games | Route::Poker { .. })
                    on:click=move |_| nav(Route::Games)
                >
                    <span class="tui-side-glyph">"▶"</span>
                    <span class="tui-side-label">"Door Games"</span>
                </button>
                <button
                    type="button"
                    class="tui-side-item"
                    class:active=move || router.route.get() == Route::Wallet
                    on:click=move |_| nav(Route::Wallet)
                >
                    <span class="tui-side-glyph">"₿"</span>
                    <span class="tui-side-label">"Sidestr Wallet"</span>
                </button>
            </div>

            // ── SYSTEM ─────────────────────────────────────────────────────
            <div class="tui-side-group">
                <div class="tui-side-heading"><span>"SYSTEM"</span></div>
                <button
                    type="button"
                    class="tui-side-item"
                    class:active=move || matches!(router.route.get(), Route::Pod { .. })
                    on:click=move |_| nav(Route::Pod { path: String::new() })
                >
                    <span class="tui-side-glyph">"▤"</span>
                    <span class="tui-side-label">"Solid Pod & Git"</span>
                </button>
                <button
                    type="button"
                    class="tui-side-item"
                    class:active=move || router.route.get() == Route::Settings
                    on:click=move |_| nav(Route::Settings)
                >
                    <span class="tui-side-glyph">"⚙"</span>
                    <span class="tui-side-label">{move || if auth.is_authenticated().get() { "Settings" } else { "Sign In / Settings" }}</span>
                </button>
                <button
                    type="button"
                    class="tui-side-item"
                    class:active=move || router.route.get() == Route::Help
                    on:click=move |_| nav(Route::Help)
                >
                    <span class="tui-side-glyph">"?"</span>
                    <span class="tui-side-label">"Help & Keys"</span>
                </button>
                // The same place in the modern forum: a board's section page,
                // a thread's topic page.
                <a class="tui-side-item" href=move || forum_href(&router.route.get(), channels) rel="noopener">
                    <span class="tui-side-glyph">"↗"</span>
                    <span class="tui-side-label">"Modern Forum"</span>
                </a>
            </div>
        </aside>
    }
}

/// `/` command bar (power-user accelerator).
#[component]
fn CommandBar() -> impl IntoView {
    let prefs = use_bbs_prefs();
    let router = use_router();
    // Looked up here: `/forum` runs in a handler, which has no reactive owner.
    #[cfg(target_arch = "wasm32")]
    let channels = use_channel_store();
    let search = use_search_palette();
    let toasts = use_toasts();
    let text = RwSignal::new(String::new());
    let input_ref = NodeRef::<leptos::html::Input>::new();

    Effect::new(move |_| {
        if prefs.cmd_open.get() {
            if let Some(el) = input_ref.get() {
                let _ = el.focus();
            }
        }
    });

    let submit = move || {
        let raw = text.get_untracked();
        text.set(String::new());
        prefs.cmd_open.set(false);
        match parse_slash_command(&raw) {
            CommandAction::Navigate(r) => router.go(r),
            CommandAction::Search(q) => search.open_with(q),
            CommandAction::CycleTheme => prefs.cycle_theme(),
            CommandAction::ToggleCrt => prefs.toggle_crt(),
            CommandAction::ToggleSidebar => prefs.toggle_sidebar(),
            CommandAction::LaunchSentry => launch_sentry(),
            CommandAction::OpenForum =>
            {
                #[cfg(target_arch = "wasm32")]
                if let Some(win) = web_sys::window() {
                    let _ = win
                        .location()
                        .set_href(&forum_href(&router.route.get_untracked(), channels));
                }
            }
            CommandAction::Back => router.back(),
            CommandAction::Unknown(cmd) if !cmd.is_empty() => {
                toasts.show(
                    format!("Unknown command '/{cmd}' — try /help"),
                    ToastVariant::Warning,
                );
            }
            CommandAction::Unknown(_) => {}
        }
    };

    view! {
        <Show when=move || prefs.cmd_open.get() fallback=|| ()>
            <div class="tui-cmdline" role="search">
                <span class="tui-cmdline-prompt">"/"</span>
                <input
                    node_ref=input_ref
                    type="text"
                    placeholder="zones · dm · agents · events · knowledge · poker · sentry · wallet · pod · search <q> · crt · theme"
                    prop:value=move || text.get()
                    on:input=move |ev| text.set(event_target_value(&ev))
                    on:keydown=move |ev| match ev.key().as_str() {
                        "Enter" => {
                            ev.prevent_default();
                            submit();
                        }
                        "Escape" => {
                            ev.prevent_default();
                            text.set(String::new());
                            prefs.cmd_open.set(false);
                        }
                        _ => {}
                    }
                />
                <button type="button" class="bbs-btn bbs-btn-sm" on:click=move |_| submit()>"Run"</button>
                <button
                    type="button"
                    class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                    on:click=move |_| {
                        text.set(String::new());
                        prefs.cmd_open.set(false);
                    }
                >"ESC"</button>
            </div>
        </Show>
    }
}

/// Compact desktop status/shortcut strip.
#[component]
fn DesktopFooter() -> impl IntoView {
    let router = use_router();
    let prefs = use_bbs_prefs();
    let search = use_search_palette();

    view! {
        <footer class="tui-footer">
            <div class="tui-fkeys">
                <button
                    type="button"
                    class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                    on:click=move |_| prefs.cmd_open.update(|v| *v = !*v)
                ><span class="tui-fk">"[/]"</span>" cmd"</button>
                <button
                    type="button"
                    class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                    on:click=move |_| search.open_with(None)
                ><span class="tui-fk">"[⌘K]"</span>" search"</button>
                <button
                    type="button"
                    class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                    on:click=move |_| prefs.toggle_sidebar()
                ><span class="tui-fk">"[[]"</span>" sidebar"</button>
                <button
                    type="button"
                    class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                    on:click=move |_| prefs.cycle_theme()
                ><span class="tui-fk">"[T]"</span>" theme: " {move || prefs.theme.get().label()}</button>
                <button
                    type="button"
                    class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                    on:click=move |_| router.go(Route::Help)
                ><span class="tui-fk">"[?]"</span>" help"</button>
            </div>
            <div>
                {move || router.route.get().to_hash()}
                " · CRT: "
                {move || if prefs.crt_effects.get() { "on" } else { "off" }}
            </div>
        </footer>
    }
}

/// Sticky mobile bottom navigation bar (5 thumb-friendly targets).
#[component]
fn MobileBottomNav() -> impl IntoView {
    let router = use_router();
    let prefs = use_bbs_prefs();
    let auth = use_auth();
    let dm = use_dm_store();
    let panels = use_panel_registry();

    let dm_unread = dm.total_unread();
    let gov_pending = Memo::new(move |_| {
        let st = panels.state.get();
        st.actions
            .iter()
            .filter(|a| !st.decisions.get(&a.d_tag).is_some_and(|ds| !ds.is_empty()))
            .count()
    });

    let nav = move |r: Route| {
        prefs.mobile_drawer_open.set(false);
        router.go(r);
    };

    view! {
        <nav class="tui-bottomnav" aria-label="Mobile navigation">
            <button
                type="button"
                class="tui-bnav-btn"
                class:active=move || matches!(
                    router.route.get(),
                    Route::Zones | Route::Zone { .. } | Route::Board { .. } | Route::Thread { .. } | Route::Kanban { .. }
                )
                on:click=move |_| nav(Route::Zones)
            >
                <span class="ico">"▓"</span>
                <span>"Zones"</span>
            </button>

            <button
                type="button"
                class="tui-bnav-btn"
                class:active=move || matches!(router.route.get(), Route::DmList | Route::DmChat { .. })
                on:click=move |_| nav(Route::DmList)
            >
                <span class="ico">"✉"</span>
                <span>"DMs"</span>
                {move || {
                    let n = dm_unread.get();
                    (n > 0).then(|| view! { <span class="tui-bnav-badge">{n}</span> })
                }}
            </button>

            <button
                type="button"
                class="tui-bnav-btn"
                class:active=move || router.route.get() == Route::Agents
                on:click=move |_| nav(Route::Agents)
            >
                <span class="ico">"◈"</span>
                <span>"Agents"</span>
                {move || {
                    let n = gov_pending.get();
                    (n > 0).then(|| view! { <span class="tui-bnav-badge">{n}</span> })
                }}
            </button>

            <button
                type="button"
                class="tui-bnav-btn"
                class:active=move || matches!(router.route.get(), Route::Games | Route::Poker { .. } | Route::Wallet)
                on:click=move |_| nav(Route::Games)
            >
                <span class="ico">"▶"</span>
                <span>"Games"</span>
            </button>

            <button
                type="button"
                class="tui-bnav-btn"
                class:active=move || prefs.mobile_drawer_open.get() || router.route.get() == Route::Settings
                on:click=move |_| {
                    if !auth.is_authenticated().get_untracked() {
                        nav(Route::Settings);
                    } else {
                        prefs.mobile_drawer_open.update(|v| *v = !*v);
                    }
                }
            >
                <span class="ico">{move || if auth.is_authenticated().get() { "≡" } else { "⏻" }}</span>
                <span>{move || if auth.is_authenticated().get() { "More" } else { "Sign in" }}</span>
            </button>
        </nav>
    }
}

/// Global keyboard shortcuts (never hijacks inputs/textareas/selects).
#[cfg(target_arch = "wasm32")]
fn install_global_keys(
    router: crate::router::Router,
    prefs: crate::prefs::BbsPrefs,
    search: SearchPaletteState,
) {
    use wasm_bindgen::prelude::*;
    let cb =
        Closure::<dyn FnMut(web_sys::KeyboardEvent)>::new(move |ev: web_sys::KeyboardEvent| {
            let key = ev.key();
            // Cmd/Ctrl+K always toggles global search.
            if (ev.ctrl_key() || ev.meta_key()) && key.eq_ignore_ascii_case("k") {
                ev.prevent_default();
                search.open.update(|v| *v = !*v);
                return;
            }
            if ev.ctrl_key() || ev.meta_key() || ev.alt_key() {
                return;
            }
            if prefs.cmd_open.get_untracked() || search.open.get_untracked() {
                if key == "Escape" {
                    prefs.cmd_open.set(false);
                    search.open.set(false);
                }
                return;
            }
            // Yield to any focused editable control.
            if let Some(el) = web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.active_element())
            {
                let tag = el.tag_name();
                if tag.eq_ignore_ascii_case("input")
                    || tag.eq_ignore_ascii_case("textarea")
                    || tag.eq_ignore_ascii_case("select")
                {
                    return;
                }
            }
            match key.as_str() {
                "/" => {
                    ev.prevent_default();
                    prefs.cmd_open.set(true);
                }
                "[" => {
                    ev.prevent_default();
                    prefs.toggle_sidebar();
                }
                "t" | "T" => prefs.cycle_theme(),
                "?" => router.go(Route::Help),
                "Escape" => {
                    if prefs.mobile_drawer_open.get_untracked() {
                        prefs.mobile_drawer_open.set(false);
                    } else {
                        router.back();
                    }
                }
                _ => {}
            }
        });
    if let Some(win) = web_sys::window() {
        let _ = win.add_event_listener_with_callback("keydown", cb.as_ref().unchecked_ref());
    }
    cb.forget();
}
