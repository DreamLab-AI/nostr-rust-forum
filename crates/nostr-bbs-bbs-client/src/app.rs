//! Root application: wires config, the relay client, theme, the keyboard model,
//! chrome, and the active screen together. Screen navigation is a
//! `RwSignal<Screen>` state machine (faithful to a BBS — number keys / `/`
//! commands, not URL routing).

use leptos::prelude::*;

use crate::chrome::{Banner, BbsState, BottomNav, CommandLine, Footer, StatusBar};
use crate::config::BbsConfig;
use crate::menu::Screen;
use crate::relay::RelayStore;
use crate::screens::ScreenView;

/// The BBS application root.
#[component]
pub fn App() -> impl IntoView {
    let cfg = BbsConfig::load();
    let relay_url = cfg.relay_url.clone();

    // Write-path signer. Adopt the forum client's same-origin session key if the
    // viewer already signed in at `/community/` with a local key; otherwise the
    // signer stays empty (write actions disabled) until a BBS sign-in. Adopting
    // registers the signer with the relay so NIP-42 AUTH challenges are answered.
    // Created before the nav state so the first render can gate on sign-in.
    let signer = crate::signer::BbsSigner::new();
    signer.adopt_forum_session();

    // Signed-out newcomers land on the onboarding screen; anyone with an adopted
    // session (signed in at `/community/`) drops straight into the main menu.
    let initial_screen = if signer.pubkey().get_untracked().is_some() {
        Screen::MainMenu
    } else {
        Screen::Landing
    };

    // Accessibility prefs (F13): persisted text-size + reduced-motion, the
    // latter defaulting to the OS `prefers-reduced-motion`.
    let (init_text_large, init_reduced) = load_prefs();

    let state = BbsState {
        screen: RwSignal::new(initial_screen),
        selection: RwSignal::new(0),
        theme: RwSignal::new(cfg.theme),
        cmd_open: RwSignal::new(false),
        cmd_text: RwSignal::new(String::new()),
        zone: RwSignal::new(None),
        board: RwSignal::new(None),
        thread: RwSignal::new(None),
        looking_around: RwSignal::new(false),
        text_large: RwSignal::new(init_text_large),
        reduced_motion: RwSignal::new(init_reduced),
    };
    let store = RelayStore::new();

    let cfg_stored = StoredValue::new(cfg);
    provide_context(cfg_stored);
    provide_context(store);
    provide_context(signer);

    // Encrypted-DM store (F8). Created here so it shares App's reactive owner,
    // exactly like RelayStore above.
    crate::dm::provide_dm_store();

    // Shared open-state for the F11 search palette (the `⌕` footer twin, the
    // `/search` command, and the Cmd/Ctrl+K accelerator all drive one overlay).
    provide_context(crate::search::SearchOpen::new());

    // Notifications (F12): provide the mentions/replies store and start watching
    // the shared kind-42 stream. Provided AFTER the relay + signer contexts it
    // reads; `init_sync` is idempotent.
    crate::notifications::provide_notification_store();
    let notif = crate::notifications::use_notification_store();
    notif.init_sync();

    // Open the relay connection once, after mount.
    Effect::new(move |_| {
        crate::relay::connect(store, &relay_url);
    });

    // Reflect the a11y prefs onto the document root (so the rem-based layout
    // scales / motion stops) and persist them whenever they change.
    Effect::new(move |_| {
        let text_large = state.text_large.get();
        let reduced_motion = state.reduced_motion.get();
        apply_prefs(text_large, reduced_motion);
    });

    // F12: opening Boards (where replies/mentions live) clears the unread badge.
    // `notif` is `Copy`; captured into the effect. Reads `state.screen` reactively.
    Effect::new(move |_| {
        if state.screen.get() == Screen::Boards {
            notif.mark_all_read();
        }
    });

    #[cfg(target_arch = "wasm32")]
    crate::chrome::install_key_handler(state, store, cfg_stored);

    view! {
        <div class=move || format!("bbs-crt {}", state.theme.get().css_class())>
            <div class="bbs-root">
                <StatusBar state=state />
                <Banner />
                <ScreenView state=state />
                <Footer state=state />
                <CommandLine state=state />
                <crate::search::SearchOverlay state=state />
                <BottomNav state=state />
            </div>
        </div>
    }
}

/// Initial a11y prefs `(text_large, reduced_motion)`. Persisted localStorage
/// values win; `reduced_motion` otherwise defaults to the OS
/// `prefers-reduced-motion`. Native (unit-test) target: both off.
#[cfg(target_arch = "wasm32")]
fn load_prefs() -> (bool, bool) {
    let storage = web_sys::window().and_then(|w| w.local_storage().ok().flatten());
    let read = |k: &str| storage.as_ref().and_then(|s| s.get_item(k).ok().flatten());
    let text_large = read("bbs_text_size").as_deref() == Some("large");
    let reduced_motion = match read("bbs_reduced_motion").as_deref() {
        Some("1") => true,
        Some("0") => false,
        _ => prefers_reduced_motion(),
    };
    (text_large, reduced_motion)
}

#[cfg(not(target_arch = "wasm32"))]
fn load_prefs() -> (bool, bool) {
    (false, false)
}

/// Whether the OS asks for reduced motion (`prefers-reduced-motion: reduce`).
#[cfg(target_arch = "wasm32")]
fn prefers_reduced_motion() -> bool {
    web_sys::window()
        .and_then(|w| {
            w.match_media("(prefers-reduced-motion: reduce)")
                .ok()
                .flatten()
        })
        .map(|m| m.matches())
        .unwrap_or(false)
}

/// Apply the a11y prefs as classes on `<html>` (so the whole rem-based layout
/// scales and CRT motion stops) and persist them to localStorage.
#[cfg(target_arch = "wasm32")]
fn apply_prefs(text_large: bool, reduced_motion: bool) {
    if let Some(html) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.document_element())
    {
        let cl = html.class_list();
        let _ = cl.toggle_with_force("bbs-text-large", text_large);
        let _ = cl.toggle_with_force("bbs-reduced-motion", reduced_motion);
    }
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.set_item("bbs_text_size", if text_large { "large" } else { "normal" });
        let _ = storage.set_item("bbs_reduced_motion", if reduced_motion { "1" } else { "0" });
    }
}

/// Native no-op — no document root or storage in unit tests.
#[cfg(not(target_arch = "wasm32"))]
fn apply_prefs(_text_large: bool, _reduced_motion: bool) {}
