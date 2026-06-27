//! BBS chrome: shared app state plus the status bar, banner, main menu,
//! command line, and footer / F-key legend components.

use leptos::prelude::*;

use crate::config::BbsConfig;
use crate::menu::{parse_command, Command, Screen};
use crate::theme::Theme;

/// Shared, `Copy` application state (all fields are `RwSignal`, which is `Copy`).
#[derive(Clone, Copy)]
pub struct BbsState {
    /// The active screen.
    pub screen: RwSignal<Screen>,
    /// Selection index within the active screen's list.
    pub selection: RwSignal<usize>,
    /// Active colour theme.
    pub theme: RwSignal<Theme>,
    /// Whether the `/` command line is open.
    pub cmd_open: RwSignal<bool>,
    /// Current command-line text.
    pub cmd_text: RwSignal<String>,
}

impl BbsState {
    /// Number of selectable rows on the active screen (for list navigation).
    pub fn list_len(&self, cfg: &BbsConfig) -> usize {
        match self.screen.get() {
            Screen::MainMenu => Screen::menu_order().len(),
            Screen::MessageBase => cfg.zones.len().max(1),
            _ => 0,
        }
    }

    /// Navigate to a screen, resetting the selection.
    pub fn go(&self, screen: Screen) {
        self.screen.set(screen);
        self.selection.set(0);
        self.cmd_open.set(false);
        self.cmd_text.set(String::new());
    }

    /// Apply a parsed command-line [`Command`].
    pub fn apply(&self, cmd: Command) {
        match cmd {
            Command::Go(s) => self.go(s),
            Command::Back => self.go(Screen::MainMenu),
            Command::Theme => self.theme.update(|t| *t = t.next()),
            Command::Quit => {
                self.go(Screen::MainMenu);
            }
            Command::Unknown => {}
        }
    }

    /// Activate the current selection (Enter). On the main menu this opens the
    /// highlighted screen.
    pub fn activate(&self) {
        if self.screen.get() == Screen::MainMenu {
            let idx = self.selection.get();
            if let Some(s) = Screen::menu_order().get(idx) {
                self.go(*s);
            }
        }
    }
}

/// Top status bar: connection indicator, node name, location, users.
#[component]
pub fn StatusBar() -> impl IntoView {
    let cfg = use_context::<StoredValue<BbsConfig>>().expect("config");
    let (online, node, loc) = cfg.with_value(|c| {
        (
            !c.relay_url.is_empty(),
            c.node_name.clone(),
            c.location.clone(),
        )
    });
    view! {
        <div class="bbs-statusbar">
            <span>
                <span class=move || if online { "ok" } else { "bad" }>
                    {move || if online { "● ONLINE" } else { "○ OFFLINE" }}
                </span>
                " │ " {node}
            </span>
            <span class="bbs-dim">{loc} " │ users: 1 │ NIP-01/42"</span>
        </div>
    }
}

/// ASCII banner masthead.
#[component]
pub fn Banner() -> impl IntoView {
    let cfg = use_context::<StoredValue<BbsConfig>>().expect("config");
    let node = cfg.with_value(|c| c.node_name.clone());
    let art = "\
 ╔══════════════════════════════════════════════════════════╗
 ║   ▄▄▄   ▄▄▄  ▄▄▄    nostr-rust-forum // retro terminal    ║
 ║   █▀▀▄ █▀▀▄ █▀▀     did:nostr · Solid pods · agent plane  ║
 ║   ▀▀▀  ▀▀▀  ▀▀▀                                           ║
 ╚══════════════════════════════════════════════════════════╝";
    view! {
        <pre class="bbs-banner">
            {art}
            "\n  "
            <span class="tagline">{node} " — press a number, or / for a command"</span>
        </pre>
    }
}

/// Two-column numbered main menu.
#[component]
pub fn MainMenu(state: BbsState) -> impl IntoView {
    let items = Screen::menu_order();
    view! {
        <div class="bbs-menu">
            {items
                .into_iter()
                .enumerate()
                .map(|(i, s)| {
                    let key = s.menu_key().unwrap_or(' ');
                    let selected = move || state.selection.get() == i;
                    view! {
                        <div
                            class="bbs-menu-item"
                            class:selected=selected
                            on:click=move |_| state.go(s)
                        >
                            "["<span class="key">{key}</span>"] "
                            {s.title()}
                        </div>
                    }
                })
                .collect_view()}
        </div>
    }
}

/// Footer with the F-key legend and current location.
#[component]
pub fn Footer(state: BbsState) -> impl IntoView {
    view! {
        <div class="bbs-footer">
            <div class="bbs-fkeys">
                <span><span class="fk">"[/]"</span>" cmd"</span>
                <span><span class="fk">"[ESC]"</span>" back"</span>
                <span><span class="fk">"[↑↓/jk]"</span>" move"</span>
                <span><span class="fk">"[ENTER]"</span>" select"</span>
                <span><span class="fk">"[T]"</span>" theme"</span>
                <span><span class="fk">"[0]"</span>" help"</span>
            </div>
            <div class="bbs-dim">
                "screen: " {move || state.screen.get().title()}
                " · theme: " {move || state.theme.get().label()}
            </div>
        </div>
    }
}

/// The `/`-activated command line.
#[component]
pub fn CommandLine(state: BbsState) -> impl IntoView {
    let input_ref = NodeRef::<leptos::html::Input>::new();
    // Focus the input whenever the command line opens.
    Effect::new(move |_| {
        if state.cmd_open.get() {
            if let Some(el) = input_ref.get() {
                let _ = el.focus();
            }
        }
    });
    let submit = move || {
        let cmd = parse_command(&state.cmd_text.get());
        state.apply(cmd);
        state.cmd_text.set(String::new());
        state.cmd_open.set(false);
    };
    view! {
        <Show when=move || state.cmd_open.get() fallback=|| ()>
            <div class="bbs-cmdline">
                <span class="prompt">"command/"</span>
                <input
                    node_ref=input_ref
                    prop:value=move || state.cmd_text.get()
                    on:input=move |ev| state.cmd_text.set(event_target_value(&ev))
                    on:keydown=move |ev| {
                        match ev.key().as_str() {
                            "Enter" => { ev.prevent_default(); submit(); }
                            "Escape" => {
                                ev.prevent_default();
                                state.cmd_text.set(String::new());
                                state.cmd_open.set(false);
                            }
                            _ => {}
                        }
                    }
                />
                <span class="bbs-blink">"_"</span>
            </div>
        </Show>
    }
}

/// Install a window-level keydown handler implementing the BBS keyboard model.
/// Leaks the closure for the app lifetime (a single global listener).
#[cfg(target_arch = "wasm32")]
pub fn install_key_handler(state: BbsState, cfg: StoredValue<BbsConfig>) {
    use crate::menu::wrap_index;
    use wasm_bindgen::prelude::*;
    let handler =
        Closure::<dyn FnMut(web_sys::KeyboardEvent)>::new(move |ev: web_sys::KeyboardEvent| {
            // While the command line is open the <input> owns the keystrokes.
            if state.cmd_open.get() {
                return;
            }
            let key = ev.key();
            match key.as_str() {
                "/" => {
                    ev.prevent_default();
                    state.cmd_open.set(true);
                }
                "Escape" => state.go(Screen::MainMenu),
                "Enter" => state.activate(),
                "ArrowUp" | "k" => {
                    let len = state.list_len(&cfg.get_value());
                    state.selection.update(|i| *i = wrap_index(*i, -1, len));
                }
                "ArrowDown" | "j" => {
                    let len = state.list_len(&cfg.get_value());
                    state.selection.update(|i| *i = wrap_index(*i, 1, len));
                }
                "t" | "T" => state.theme.update(|t| *t = t.next()),
                "?" => state.go(Screen::Help),
                d if d.len() == 1 && d.chars().next().is_some_and(|c| c.is_ascii_digit()) => {
                    if let Some(s) = Screen::from_menu_key(d.chars().next().unwrap()) {
                        state.go(s);
                    }
                }
                _ => {}
            }
        });
    if let Some(win) = web_sys::window() {
        let _ = win.add_event_listener_with_callback("keydown", handler.as_ref().unchecked_ref());
    }
    handler.forget();
}
