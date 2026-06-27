//! Root application: wires config, theme, the keyboard model, chrome, and the
//! active screen together. Screen navigation is a `RwSignal<Screen>` state
//! machine (faithful to a BBS — number keys / `/` commands, not URL routing).

use leptos::prelude::*;

use crate::chrome::{Banner, BbsState, CommandLine, Footer, StatusBar};
use crate::config::BbsConfig;
use crate::menu::Screen;
use crate::screens::ScreenView;

/// The BBS application root.
#[component]
pub fn App() -> impl IntoView {
    let cfg = BbsConfig::load();
    let state = BbsState {
        screen: RwSignal::new(Screen::MainMenu),
        selection: RwSignal::new(0),
        theme: RwSignal::new(cfg.theme),
        cmd_open: RwSignal::new(false),
        cmd_text: RwSignal::new(String::new()),
    };

    let cfg_stored = StoredValue::new(cfg);
    provide_context(cfg_stored);

    #[cfg(target_arch = "wasm32")]
    crate::chrome::install_key_handler(state, cfg_stored);

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
