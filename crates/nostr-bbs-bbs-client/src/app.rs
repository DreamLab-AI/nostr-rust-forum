//! Root application: wires config, the relay client, theme, the keyboard model,
//! chrome, and the active screen together. Screen navigation is a
//! `RwSignal<Screen>` state machine (faithful to a BBS — number keys / `/`
//! commands, not URL routing).

use leptos::prelude::*;

use crate::chrome::{Banner, BbsState, CommandLine, Footer, StatusBar};
use crate::config::BbsConfig;
use crate::menu::Screen;
use crate::relay::RelayStore;
use crate::screens::ScreenView;

/// The BBS application root.
#[component]
pub fn App() -> impl IntoView {
    let cfg = BbsConfig::load();
    let relay_url = cfg.relay_url.clone();

    let state = BbsState {
        screen: RwSignal::new(Screen::MainMenu),
        selection: RwSignal::new(0),
        theme: RwSignal::new(cfg.theme),
        cmd_open: RwSignal::new(false),
        cmd_text: RwSignal::new(String::new()),
        board: RwSignal::new(None),
    };
    let store = RelayStore::new();

    // Write-path signer. Adopt the forum client's same-origin session key if the
    // viewer already signed in at `/community/` with a local key; otherwise the
    // signer stays empty (write actions disabled) until a BBS sign-in. Adopting
    // registers the signer with the relay so NIP-42 AUTH challenges are answered.
    let signer = crate::signer::BbsSigner::new();
    signer.adopt_forum_session();

    let cfg_stored = StoredValue::new(cfg);
    provide_context(cfg_stored);
    provide_context(store);
    provide_context(signer);

    // Open the relay connection once, after mount.
    Effect::new(move |_| {
        crate::relay::connect(store, &relay_url);
    });

    #[cfg(target_arch = "wasm32")]
    crate::chrome::install_key_handler(state, store, cfg_stored);

    view! {
        <div class=move || format!("bbs-crt {}", state.theme.get().css_class())>
            <div class="bbs-root">
                <StatusBar />
                <Banner />
                <ScreenView state=state />
                <Footer state=state />
                <CommandLine state=state />
            </div>
        </div>
    }
}
