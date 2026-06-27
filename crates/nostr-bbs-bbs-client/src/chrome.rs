//! BBS chrome: shared app state plus the status bar, banner, main menu,
//! command line, and footer / F-key legend components.

use leptos::prelude::*;

use crate::ascii_img::AsciiImg;
use crate::config::BbsConfig;
use crate::menu::{parse_command, Command, Screen};
use crate::relay::RelayStore;
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
    /// Currently-open board (kind-40 channel id) within Message Base, if any.
    pub board: RwSignal<Option<String>>,
}

impl BbsState {
    /// Navigate to a screen, resetting the selection and any open board.
    pub fn go(&self, screen: Screen) {
        self.screen.set(screen);
        self.selection.set(0);
        self.board.set(None);
        self.cmd_open.set(false);
        self.cmd_text.set(String::new());
    }

    /// Apply a parsed command-line [`Command`].
    pub fn apply(&self, cmd: Command) {
        match cmd {
            Command::Go(s) => self.go(s),
            Command::Back => self.go(Screen::MainMenu),
            Command::Theme => self.theme.update(|t| *t = t.next()),
            Command::Quit => self.go(Screen::MainMenu),
            Command::Unknown => {}
        }
    }

    /// Activate the current selection on the main menu (Enter).
    pub fn activate_menu(&self) {
        if self.screen.get() == Screen::MainMenu {
            if let Some(s) = Screen::menu_order().get(self.selection.get()) {
                self.go(*s);
            }
        }
    }

    /// Open a Message Base board (kind-40 channel id).
    pub fn open_board(&self, channel_id: String) {
        self.board.set(Some(channel_id));
    }

    /// Close the open board, returning to the channel list.
    pub fn close_board(&self) {
        self.board.set(None);
    }
}

/// Top status bar: live connection indicator, node name, location.
#[component]
pub fn StatusBar() -> impl IntoView {
    let cfg = use_context::<StoredValue<BbsConfig>>().expect("config");
    let store = use_context::<RelayStore>().expect("relay");
    let (node, loc) = cfg.with_value(|c| (c.node_name.clone(), c.location.clone()));
    view! {
        <div class="bbs-statusbar">
            <span>
                <span class=move || if store.connected.get() { "ok" } else { "bad" }>
                    {move || if store.connected.get() { "● ONLINE" } else { "○ CONNECTING" }}
                </span>
                " │ " {node}
            </span>
            <span class="bbs-dim">{loc} " │ NIP-01/42"</span>
        </div>
    }
}

/// ASCII banner masthead.
#[component]
pub fn Banner() -> impl IntoView {
    let cfg = use_context::<StoredValue<BbsConfig>>().expect("config");
    let (node, banner_url) = cfg.with_value(|c| (c.node_name.clone(), c.banner_url.clone()));
    let art = "\
 ╔══════════════════════════════════════════════════════════╗
 ║   ▄▄▄   ▄▄▄  ▄▄▄    nostr-rust-forum // retro terminal    ║
 ║   █▀▀▄ █▀▀▄ █▀▀     did:nostr · Solid pods · agent plane  ║
 ║   ▀▀▀  ▀▀▀  ▀▀▀                                           ║
 ╚══════════════════════════════════════════════════════════╝";
    view! {
        // Optional banner image — rendered on-theme as ASCII, never a raw <img>.
        {banner_url.map(|src| view! {
            <div class="bbs-ascii-row bbs-banner-img">
                <AsciiImg src=src cols=100 />
            </div>
        })}
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
                            "[" <span class="key">{key}</span> "] " {s.title()}
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
                "screen: " {move || state.screen.get().title()} " · theme: "
                {move || state.theme.get().label()}
            </div>
        </div>
    }
}

/// The `/`-activated command line.
#[component]
pub fn CommandLine(state: BbsState) -> impl IntoView {
    let input_ref = NodeRef::<leptos::html::Input>::new();
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
                            "Enter" => {
                                ev.prevent_default();
                                submit();
                            }
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

/// Selectable-row count on the active screen (for ↑/↓ navigation).
#[cfg(target_arch = "wasm32")]
fn nav_len(state: &BbsState, store: &RelayStore) -> usize {
    match state.screen.get() {
        Screen::MainMenu => Screen::menu_order().len(),
        Screen::MessageBase if state.board.get().is_none() => store.channels.get().len(),
        _ => 0,
    }
}

/// Install a window-level keydown handler implementing the BBS keyboard model.
/// Leaks the closure for the app lifetime (a single global listener).
#[cfg(target_arch = "wasm32")]
pub fn install_key_handler(state: BbsState, store: RelayStore) {
    use crate::menu::wrap_index;
    use wasm_bindgen::prelude::*;
    let handler =
        Closure::<dyn FnMut(web_sys::KeyboardEvent)>::new(move |ev: web_sys::KeyboardEvent| {
            // While the command line is open the <input> owns the keystrokes.
            if state.cmd_open.get() {
                return;
            }
            match ev.key().as_str() {
                "/" => {
                    ev.prevent_default();
                    state.cmd_open.set(true);
                }
                "Escape" => {
                    if state.screen.get() == Screen::MessageBase && state.board.get().is_some() {
                        state.close_board();
                    } else {
                        state.go(Screen::MainMenu);
                    }
                }
                "Enter" => match state.screen.get() {
                    Screen::MainMenu => state.activate_menu(),
                    Screen::MessageBase if state.board.get().is_none() => {
                        let chans = store.channels.get();
                        if let Some(c) = chans.get(state.selection.get()) {
                            let id = c.id.clone();
                            state.open_board(id.clone());
                            crate::relay::subscribe_board(&id);
                        }
                    }
                    _ => {}
                },
                "ArrowUp" | "k" => {
                    let len = nav_len(&state, &store);
                    state.selection.update(|i| *i = wrap_index(*i, -1, len));
                }
                "ArrowDown" | "j" => {
                    let len = nav_len(&state, &store);
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
