//! Root Leptos application component for the retro ASCII/BBS TUI client.
//!
//! Mounts the full [`nostr_bbs_client_core`] headless engine context stack
//! (identical to `nostr-bbs-forum-client` — zero drift across auth, relay,
//! encrypted zones, reactions, governance, DMs, badges, notifications, and
//! wallets), wires the hash-based [`Router`], handles ADR-109 `?pwa=1`
//! one-shot boot, and renders every view inside the responsive [`TuiShell`].

use leptos::prelude::*;
use nostr_bbs_client_core::agent_disclosure::provide_agent_disclosure;
use nostr_bbs_client_core::auth::{provide_auth, use_auth};
use nostr_bbs_client_core::dm::{provide_dm_store, use_dm_store};
use nostr_bbs_client_core::name_cache::provide_name_cache;
use nostr_bbs_client_core::relay::{ConnectionState, EventCallback, Filter, RelayConnection};
use nostr_bbs_client_core::stores::badges::{init_badge_sync, provide_badges};
use nostr_bbs_client_core::stores::case_projection::provide_case_projection_store;
use nostr_bbs_client_core::stores::channels::{provide_channel_store, use_channel_store};
use nostr_bbs_client_core::stores::custom_emoji::provide_custom_emoji_store;
use nostr_bbs_client_core::stores::mute::provide_mute_store;
use nostr_bbs_client_core::stores::notifications::{
    provide_notification_store, use_notification_store,
};
use nostr_bbs_client_core::stores::panel_registry::{provide_panel_registry, use_panel_registry};
use nostr_bbs_client_core::stores::preferences::provide_preferences;
use nostr_bbs_client_core::stores::profile_cache::{provide_profile_cache, try_use_profile_cache};
use nostr_bbs_client_core::stores::reactions::{provide_reaction_store, use_reaction_store};
use nostr_bbs_client_core::stores::read_position::provide_read_positions;
use nostr_bbs_client_core::stores::receipts::provide_receipt_store;
use nostr_bbs_client_core::stores::zone_access::provide_zone_access;
use nostr_bbs_client_core::toast::provide_toasts;
use nostr_bbs_client_core::utils;
use nostr_bbs_client_core::wallet::provide_wallet;
use nostr_bbs_client_core::zone_crypto;
use nostr_bbs_core::NostrEvent;

use crate::config::BbsConfig;
use crate::prefs::{provide_bbs_prefs, BbsPrefs};
use crate::pwa;
use crate::router::{provide_router, Route, Router};
use crate::shell::{SearchPaletteState, TuiShell};
use crate::views::{
    boards::{LiveFeedView, ZoneView, ZonesView},
    bookmarks::BookmarksView,
    dm::{DmChatView, DmListView},
    events::EventsView,
    games::{GamesView, PokerView},
    governance::AgentsView,
    kanban::KanbanView,
    knowledge::KnowledgeView,
    members::{MembersView, ProfileView},
    pod::PodView,
    search::SearchOverlay,
    system::{HelpView, LandingView, NotificationsView, RebindView, SettingsView},
    thread::{BoardView, ThreadView},
    wallet::WalletView,
};

fn initial_route_from_location() -> Route {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(hash) = web_sys::window().and_then(|w| w.location().hash().ok()) {
            if !hash.is_empty() {
                return Route::from_hash(&hash);
            }
        }
    }
    Route::Zones
}

/// Root BBS application component.
#[component]
pub fn App() -> impl IntoView {
    // 1. Load runtime configuration from `window.__ENV__`
    let cfg = BbsConfig::load();
    provide_context(cfg.clone());
    provide_context(StoredValue::new(cfg.clone()));

    // Capture deferred `beforeinstallprompt` (ADR-109)
    #[cfg(target_arch = "wasm32")]
    if cfg.pwa_enabled {
        pwa::init_install_capture();
    }

    // 2. Mount shared headless client-core providers (order matches forum-client)
    provide_auth();
    provide_zone_access();
    provide_toasts();
    provide_notification_store();
    provide_name_cache();
    provide_profile_cache();
    provide_read_positions();
    provide_mute_store();
    provide_preferences();
    provide_wallet();
    provide_custom_emoji_store();
    provide_badges();
    provide_panel_registry();
    provide_receipt_store();
    provide_case_projection_store();
    provide_agent_disclosure();

    // Relay + channels + encrypted zone keys + reactions + DMs
    let relay = RelayConnection::new();
    provide_context(relay.clone());
    provide_channel_store();
    zone_crypto::store::provide_zone_key_store(use_channel_store());
    provide_reaction_store();
    provide_dm_store();

    // 3. BBS UI preferences, search overlay state, and hash router
    let prefs = BbsPrefs::load(cfg.theme);
    prefs.install_sync();
    provide_bbs_prefs(prefs);
    provide_context(SearchPaletteState::new());

    let pwa_zone = if cfg.pwa_enabled && cfg.pwa_mode {
        pwa::resolve_boot_zone_index(&cfg.boot_profile, &cfg.zones)
            .and_then(|i| cfg.zones.get(i))
            .map(|z| z.slug.as_deref().unwrap_or(&z.id).to_string())
    } else {
        None
    };
    let initial = initial_route_from_location();
    let router = Router::new(initial, cfg.pwa_enabled && cfg.pwa_mode, pwa_zone.clone());
    provide_router(router);

    // Keep route synced with browser Back/Forward hash navigation
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::closure::Closure;
        use wasm_bindgen::JsCast;
        if let Some(win) = web_sys::window() {
            let r_hash = router;
            let cb = Closure::<dyn FnMut(web_sys::Event)>::new(move |_: web_sys::Event| {
                if let Some(h) = web_sys::window().and_then(|w| w.location().hash().ok()) {
                    let parsed = Route::from_hash(&h);
                    if r_hash.route.get_untracked() != parsed {
                        r_hash.route.set(parsed);
                    }
                }
            });
            let _ = win.add_event_listener_with_callback("hashchange", cb.as_ref().unchecked_ref());
            cb.forget();
        }
    }

    // 4. ADR-109 `?pwa=1` one-shot boot: adopt baked key or route to `#/rebind`
    let auth = use_auth();
    #[cfg(target_arch = "wasm32")]
    if cfg.pwa_enabled && cfg.pwa_mode {
        let resolved_slug = pwa_zone.unwrap_or_else(|| "public".into());
        if auth.is_authenticated().get_untracked() {
            router.enter_pwa(resolved_slug);
        } else {
            wasm_bindgen_futures::spawn_local(async move {
                pwa::adopt_baked_or_rebind(&auth, router, resolved_slug).await;
            });
        }
    }

    // 5. Connect relay reactively with auth state (and set NIP-42 AUTH signer)
    {
        let is_authed = auth.is_authenticated();
        Effect::new(move |_| {
            let r = expect_context::<RelayConnection>();
            if is_authed.get() {
                if auth.state().get_untracked().is_nip07 {
                    let a2 = auth;
                    let async_signer: nostr_bbs_client_core::relay::AuthSignAsyncCallback =
                        std::rc::Rc::new(move |event| {
                            let a = a2;
                            Box::pin(async move { a.sign_event_async(event).await.ok() })
                        });
                    r.set_auth_signer_async(async_signer);
                } else {
                    let a2 = auth;
                    let sync_signer =
                        std::rc::Rc::new(move |event: nostr_bbs_core::UnsignedEvent| {
                            a2.sign_event(event).ok()
                        });
                    r.set_auth_signer(sync_signer);
                }
            }
            r.connect();
        });
    }

    // 6. Subscribe to kind-0 profiles + governance (31400-31405) + channels + reactions
    {
        let relay_state = relay.connection_state();
        let kind0_started = RwSignal::new(false);
        let gov_started = RwSignal::new(false);

        Effect::new(move |_| {
            if relay_state.get() != ConnectionState::Connected {
                return;
            }
            let r = expect_context::<RelayConnection>();

            if !kind0_started.get_untracked() {
                if let Some(cache) = try_use_profile_cache() {
                    let filter = Filter {
                        kinds: Some(vec![0]),
                        limit: Some(500),
                        ..Default::default()
                    };
                    let on_ev: EventCallback = std::rc::Rc::new(move |ev: NostrEvent| {
                        if ev.kind == 0 && !ev.content.is_empty() {
                            cache.upsert_from_kind0(&ev.pubkey, &ev.content, ev.created_at);
                        }
                    });
                    r.subscribe(vec![filter], on_ev, None);
                    kind0_started.set(true);
                }
            }

            if !gov_started.get_untracked() {
                let registry = use_panel_registry();
                let filter = Filter {
                    kinds: Some(vec![31400, 31401, 31402, 31403, 31404, 31405]),
                    limit: Some(200),
                    ..Default::default()
                };
                let on_ev: EventCallback = std::rc::Rc::new(move |ev: NostrEvent| {
                    registry.ingest_event(&ev);
                });
                r.subscribe(vec![filter], on_ev, None);
                gov_started.set(true);
            }

            use_channel_store().start_sync(&r);
            use_reaction_store().start_sync(&r);
        });
    }

    // 7. Start broad message sync once channel list settles
    {
        let relay_conn = relay.connection_state();
        let msg_sync_deadline =
            utils::lookup::deadline_for(move || relay_conn.get() == ConnectionState::Connected);
        Effect::new(move |_| {
            if relay_conn.get() != ConnectionState::Connected {
                return;
            }
            let store = use_channel_store();
            let settled = utils::lookup::channel_list_settled(
                store.channel_receipt.get(),
                msg_sync_deadline.get(),
            );
            let count = store.channels.with(|c| c.len());
            if utils::lookup::history_known_empty(store.channel_receipt.get(), count) {
                store.msg_eose_received.set(true);
            }
            if !settled || count == 0 {
                return;
            }
            let r = expect_context::<RelayConnection>();
            store.start_msg_sync(&r);
        });
    }

    // 8. Zone-key grants (ADR-2016) once NIP-42 authenticated
    {
        let relay_authed = relay.authenticated();
        let zone_keys = zone_crypto::store::try_use_zone_key_store();
        let relay_for_keys = relay.clone();
        Effect::new(move |_| {
            if !zone_crypto::encryption_enabled() || !relay_authed.get() {
                return;
            }
            let (Some(store), Some(me), Some(signer)) =
                (zone_keys, auth.pubkey().get(), auth.get_signer())
            else {
                return;
            };
            if !store.ready_for(Some(&me)) {
                return;
            }
            let can_refuse = auth.state().with_untracked(|s| s.is_nip07);
            store.start_grant_sync(&relay_for_keys, signer, me, can_refuse);
        });
    }

    // 9. Start DM subscription & live notification sync once authenticated + connected
    {
        let dm = use_dm_store();
        let notifs = use_notification_store();
        notifs.init_sync();

        let relay_state = relay.connection_state();
        let relay_authed = relay.authenticated();
        let dm_owner: RwSignal<Option<String>> = RwSignal::new(None);
        Effect::new(move |_| {
            if relay_state.get() != ConnectionState::Connected || !relay_authed.get() {
                return;
            }
            let (Some(me), Some(signer)) = (auth.pubkey().get(), auth.get_signer()) else {
                return;
            };
            if dm_owner.get_untracked().as_deref() == Some(me.as_str()) {
                return;
            }
            let r = expect_context::<RelayConnection>();
            dm.subscribe_incoming(&r, signer, &me);
            dm_owner.set(Some(me));
        });
    }

    // 10. Start badge sync
    init_badge_sync();

    // Cleanup on unmount
    {
        let relay_cleanup = relay;
        on_cleanup(move || {
            use_channel_store().cleanup(&relay_cleanup);
            use_reaction_store().cleanup(&relay_cleanup);
        });
    }

    // Reactive root theme / CRT / text / motion classes
    let root_class = move || {
        let mut cls = format!("bbs-root {}", prefs.theme.get().css_class());
        if !prefs.crt_effects.get() {
            cls.push_str(" bbs-crt-off");
        }
        if prefs.text_large.get() {
            cls.push_str(" bbs-text-lg");
        }
        if prefs.reduced_motion.get() {
            cls.push_str(" bbs-reduced-motion");
        }
        cls
    };

    view! {
        <div class=root_class>
            <TuiShell>
                {move || match router.route.get() {
                    Route::Landing => view! { <LandingView/> }.into_any(),
                    Route::Zones => view! { <ZonesView/> }.into_any(),
                    Route::Zone { slug } => view! { <ZoneView slug=slug/> }.into_any(),
                    Route::Board { zone, channel_id } => {
                        view! { <BoardView zone=zone channel_id=channel_id/> }.into_any()
                    }
                    Route::Thread {
                        zone,
                        channel_id,
                        root_id,
                    } => {
                        view! { <ThreadView zone=zone channel_id=channel_id root_id=root_id/> }
                            .into_any()
                    }
                    Route::LiveFeed => view! { <LiveFeedView/> }.into_any(),
                    Route::Kanban { zone } => view! { <KanbanView zone=zone/> }.into_any(),
                    Route::Events => view! { <EventsView/> }.into_any(),
                    Route::Knowledge => view! { <KnowledgeView/> }.into_any(),
                    Route::Agents => view! { <AgentsView/> }.into_any(),
                    Route::DmList => view! { <DmListView/> }.into_any(),
                    Route::DmChat { pubkey } => view! { <DmChatView pubkey=pubkey/> }.into_any(),
                    Route::Games => view! { <GamesView/> }.into_any(),
                    Route::Poker { chain } => view! { <PokerView chain=chain/> }.into_any(),
                    Route::Wallet => view! { <WalletView/> }.into_any(),
                    Route::Pod { path } => view! { <PodView path=path/> }.into_any(),
                    Route::Members => view! { <MembersView/> }.into_any(),
                    Route::Profile { pubkey } => view! { <ProfileView pubkey=pubkey/> }.into_any(),
                    Route::Bookmarks => view! { <BookmarksView/> }.into_any(),
                    Route::Notifications => view! { <NotificationsView/> }.into_any(),
                    Route::Settings => view! { <SettingsView/> }.into_any(),
                    Route::Rebind => view! { <RebindView/> }.into_any(),
                    Route::Help => view! { <HelpView/> }.into_any(),
                }}
            </TuiShell>
            <SearchOverlay/>
        </div>
    }
}
