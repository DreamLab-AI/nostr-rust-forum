//! BBS chrome: shared app state plus the status bar, banner, main menu,
//! command line, and footer / F-key legend components.

use leptos::prelude::*;

use crate::ascii_img::AsciiImg;
use crate::config::BbsConfig;
use crate::menu::{parse_command, Command, Screen};
use crate::relay::RelayStore;
use crate::signer::BbsSigner;
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
    /// Selected zone within the Boards drill-down: `None` = the top-level Zones
    /// screen; `Some(i)` = a configured `cfg.zones[i]`; `Some(OTHER_ZONE)` = the
    /// unmatched "Other" group. Boards navigate Zones → Boards-in-zone → posts.
    pub zone: RwSignal<Option<usize>>,
    /// Currently-open board (kind-40 channel id) within the selected zone, if any.
    pub board: RwSignal<Option<String>>,
    /// Currently-open thread within the board: the root kind-42 event id, or
    /// `None` for the board's thread list. Boards drill Zones → Boards → Threads
    /// → Thread view; this is the deepest level.
    pub thread: RwSignal<Option<String>>,
    /// Whether a signed-out viewer chose "look around" from the Landing screen —
    /// past onboarding, browsing read-only. The Landing screen is the signed-out
    /// entry until this is set (or the viewer signs in).
    pub looking_around: RwSignal<bool>,
    /// Accessibility preference: larger body type (persisted; applied as a class
    /// on the document root so the whole rem-based layout scales).
    pub text_large: RwSignal<bool>,
    /// Accessibility preference: suppress the CRT flicker / cursor blink /
    /// phosphor-ghost motion (persisted; defaults to the OS `prefers-reduced-motion`).
    pub reduced_motion: RwSignal<bool>,
}

impl BbsState {
    /// Navigate to a screen, resetting the selection and the Boards drill-down.
    pub fn go(&self, screen: Screen) {
        self.screen.set(screen);
        self.selection.set(0);
        self.zone.set(None);
        self.board.set(None);
        self.thread.set(None);
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
            Command::Sentry => crate::screens::launch_sentry(),
            Command::Search => crate::search::open_search(None),
            Command::Unknown => {}
        }
    }

    /// Activate the current selection on the main menu (Enter). Called from the
    /// global keydown handler (an imperative, non-reactive context), so the
    /// signal reads are untracked — there is no effect to subscribe.
    pub fn activate_menu(&self) {
        if self.screen.get_untracked() == Screen::MainMenu {
            if let Some(s) = Screen::menu_order().get(self.selection.get_untracked()) {
                self.go(*s);
            }
        }
    }

    /// Open a zone in the Boards drill-down (a `cfg.zones` index or `OTHER_ZONE`),
    /// showing that zone's boards. Resets the selection to the first board.
    pub fn open_zone(&self, zone_sel: usize) {
        self.zone.set(Some(zone_sel));
        self.board.set(None);
        self.selection.set(0);
    }

    /// Close the open zone, returning to the top-level Zones cards.
    pub fn close_zone(&self) {
        self.zone.set(None);
        self.board.set(None);
        self.thread.set(None);
        self.selection.set(0);
    }

    /// Open a board (kind-40 channel id) within the selected zone. Resets the
    /// thread drill-down to the board's thread list.
    pub fn open_board(&self, channel_id: String) {
        self.board.set(Some(channel_id));
        self.thread.set(None);
        self.selection.set(0);
    }

    /// Close the open board, returning to the zone's board list.
    pub fn close_board(&self) {
        self.board.set(None);
        self.thread.set(None);
        self.selection.set(0);
    }

    /// Open a thread (root kind-42 event id) within the current board.
    pub fn open_thread(&self, root_id: String) {
        self.thread.set(Some(root_id));
        self.selection.set(0);
    }

    /// Close the open thread, returning to the board's thread list.
    pub fn close_thread(&self) {
        self.thread.set(None);
        self.selection.set(0);
    }

    /// Leave the Landing screen to browse read-only ("look around").
    pub fn look_around(&self) {
        self.looking_around.set(true);
        self.go(Screen::MainMenu);
    }
}

/// Top status bar: live connection indicator, node name, location.
///
/// Three states, so "connected but not yet authenticated" no longer reads as
/// "node down": `○ CONNECTING` (socket not open) · `◐ SIGN IN TO READ`
/// (connected, no signer — NIP-42 reads are deny-by-default, so a signed-out
/// viewer sees empty zones; tap it to open the sign-in sheet) · `● ONLINE`
/// (connected and signed in).
#[component]
pub fn StatusBar(state: BbsState) -> impl IntoView {
    let cfg = use_context::<StoredValue<BbsConfig>>().expect("config");
    let store = use_context::<RelayStore>().expect("relay");
    let signer = use_context::<BbsSigner>();
    let (node, loc) = cfg.with_value(|c| (c.node_name.clone(), c.location.clone()));
    let authed = move || signer.and_then(|s| s.pubkey().get()).is_some();
    // Three-way status class: connecting / needs-auth / online.
    let status_class = move || {
        if !store.connected.get() {
            "bad"
        } else if authed() {
            "ok"
        } else {
            "warn"
        }
    };
    view! {
        <div class="bbs-statusbar">
            <span>
                <span
                    class=status_class
                    class:bbs-link=move || store.connected.get() && !authed()
                    role="button"
                    on:click=move |_| {
                        // Imperative click handler (not a reactive context) — read
                        // untracked so this doesn't warn about tracking outside an
                        // effect. Only the "needs auth" state is a live link.
                        let connected = store.connected.get_untracked();
                        let signed =
                            signer.and_then(|s| s.pubkey().get_untracked()).is_some();
                        if connected && !signed {
                            state.go(Screen::Settings);
                        }
                    }
                >
                    {move || {
                        if !store.connected.get() {
                            "\u{25CB} CONNECTING"
                        } else if authed() {
                            "\u{25CF} ONLINE"
                        } else {
                            "\u{25D0} SIGN IN TO READ"
                        }
                    }}
                </span>
                " │ " {node}
            </span>
            <span class="bbs-dim">{loc} " │ NIP-01/42"</span>
        </div>
    }
}

/// Persistent, skinned bottom navigation bar — the tap-first return path that
/// replaces the undocumented "swipe down from top" gesture as the *primary* way
/// home (the swipe stays as an accelerator). Menu / Boards / Agents are always
/// present; DMs and the "You" tab are auth-gated like the forum's mobile nav —
/// and when signed out the "You" slot becomes a first-class **Sign in** entry so
/// a newcomer always has a visible way in. The Boards item carries the F12
/// mentions/replies unread badge. The active screen is highlighted.
#[component]
pub fn BottomNav(state: BbsState) -> impl IntoView {
    let signer = use_context::<BbsSigner>();
    let authed = move || signer.and_then(|s| s.pubkey().get()).is_some();
    // F12: unread mentions/replies count for the Boards badge (a `Memo`, `Copy`).
    let unread = crate::notifications::use_notification_store().unread_count();
    view! {
        <nav class="bbs-bottomnav" aria-label="Primary navigation">
            <button
                class="bbs-navitem"
                class:active=move || state.screen.get() == Screen::MainMenu
                on:click=move |_| state.go(Screen::MainMenu)
            >
                <span class="ico">"\u{2261}"</span>
                <span class="lab">"Menu"</span>
            </button>
            <button
                class="bbs-navitem"
                class:active=move || state.screen.get() == Screen::Boards
                on:click=move |_| state.go(Screen::Boards)
            >
                <span class="ico">"\u{25A4}"</span>
                <span class="lab">"Boards"</span>
                {move || {
                    let n = unread.get();
                    (n > 0).then(|| {
                        let text = if n > 99 { "99+".to_string() } else { n.to_string() };
                        let label = format!("{n} unread notifications");
                        view! {
                            <span class="bbs-navbadge" role="status" aria-label=label>
                                {text}
                            </span>
                        }
                    })
                }}
            </button>
            {move || authed().then(|| view! {
                <button
                    class="bbs-navitem"
                    class:active=move || state.screen.get() == Screen::Dm
                    on:click=move |_| state.go(Screen::Dm)
                >
                    <span class="ico">"\u{2709}"</span>
                    <span class="lab">"DMs"</span>
                </button>
            })}
            <button
                class="bbs-navitem"
                class:active=move || state.screen.get() == Screen::Agents
                on:click=move |_| state.go(Screen::Agents)
            >
                <span class="ico">"\u{25B8}"</span>
                <span class="lab">"Agents"</span>
            </button>
            <button
                class="bbs-navitem"
                class:active=move || state.screen.get() == Screen::Settings
                on:click=move |_| state.go(Screen::Settings)
            >
                {move || if authed() {
                    view! { <span class="ico">"\u{2699}"</span><span class="lab">"You"</span> }.into_any()
                } else {
                    view! { <span class="ico">"\u{23FB}"</span><span class="lab">"Sign in"</span> }.into_any()
                }}
            </button>
        </nav>
    }
}

/// Banner masthead. Node name + tagline are operator branding
/// (`[branding].node_name` / `.tagline`), never a hardcoded upstream kit name.
/// Plain styled text rather than box-glyph art: nothing to misalign with long
/// node names, clip on narrow screens, or mojibake under a wrong charset.
#[component]
pub fn Banner() -> impl IntoView {
    let cfg = use_context::<StoredValue<BbsConfig>>().expect("config");
    let (node, tagline, banner_url) =
        cfg.with_value(|c| (c.node_name.clone(), c.tagline.clone(), c.banner_url.clone()));
    view! {
        // Optional banner image — rendered on-theme as ASCII, never a raw <img>.
        {banner_url.map(|src| view! {
            <div class="bbs-ascii-row bbs-banner-img">
                <AsciiImg src=src cols=100 />
            </div>
        })}
        <div class="bbs-banner">
            <div class="bbs-banner-node">{node}</div>
            <div class="bbs-banner-tag">{tagline}</div>
            <span class="tagline">"press a number, or / for a command (tap works too)"</span>
        </div>
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
                <span
                    class="fk bbs-link"
                    role="button"
                    tabindex="0"
                    aria-label="Open search"
                    on:click=move |_| crate::search::open_search(None)
                >"[\u{2315}]"</span>
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
        // Fired from the input's Enter/click handlers (imperative), so read the
        // text untracked — no reactive subscription is wanted here.
        let raw = state.cmd_text.get_untracked();
        // `/search <q>` (or `find <q>`) opens the global-search palette seeded
        // with the query. Handled before the screen-nav parser because the
        // `Command` enum is `Copy` and cannot carry the query `String`.
        if let Some(q) = crate::search::query::parse_search_command(&raw) {
            crate::search::open_search(Some(q));
            state.cmd_text.set(String::new());
            state.cmd_open.set(false);
            return;
        }
        let cmd = parse_command(&raw);
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

/// Selectable-row count on the active screen (for ↑/↓ navigation). Boards has
/// four depths: the Zones cards, a zone's board list, a board's thread list, and
/// the (unselectable) thread view. Called from the global keydown handler (an
/// imperative, non-reactive context), so all signal reads are untracked — there
/// is no effect to subscribe.
#[cfg(target_arch = "wasm32")]
fn nav_len(state: &BbsState, store: &RelayStore, cfg: &StoredValue<BbsConfig>) -> usize {
    match state.screen.get_untracked() {
        Screen::MainMenu => Screen::menu_order().len(),
        Screen::Boards => match state.board.get_untracked() {
            None => {
                let zone_ids: Vec<String> =
                    cfg.with_value(|c| c.zones.iter().map(|z| z.id.clone()).collect());
                match state.zone.get_untracked() {
                    None => {
                        crate::relay::zone_entries(&store.channels.get_untracked(), &zone_ids).len()
                    }
                    Some(z) => {
                        crate::relay::boards_in_zone(store.channels.get_untracked(), &zone_ids, z)
                            .len()
                    }
                }
            }
            // In a board: the thread LIST is row-selectable; the open thread view
            // is not (the composer owns it).
            Some(cid) if state.thread.get_untracked().is_none() => {
                crate::relay::group_threads(&store.posts.get_untracked(), &cid).len()
            }
            Some(_) => 0,
        },
        _ => 0,
    }
}

/// Install a window-level keydown handler implementing the BBS keyboard model.
/// Leaks the closure for the app lifetime (a single global listener).
#[cfg(target_arch = "wasm32")]
pub fn install_key_handler(state: BbsState, store: RelayStore, cfg: StoredValue<BbsConfig>) {
    use crate::menu::wrap_index;
    use wasm_bindgen::prelude::*;
    let handler =
        Closure::<dyn FnMut(web_sys::KeyboardEvent)>::new(move |ev: web_sys::KeyboardEvent| {
            // This runs in a raw JS event closure — an imperative, non-reactive
            // context — so every signal read below is untracked (there is no
            // effect to subscribe; a plain `.get()` here warns at runtime).
            // While the command line is open the <input> owns the keystrokes.
            if state.cmd_open.get_untracked() {
                return;
            }
            // Modifier combos (Cmd/Ctrl/Alt + key) are app/browser accelerators
            // (e.g. Cmd/Ctrl+K opens global search) — never BBS nav keys. Let
            // them through so they don't ALSO move the selection / open a screen.
            if ev.ctrl_key() || ev.meta_key() || ev.alt_key() {
                return;
            }
            // A focused text field (Settings sign-in key, board composer) owns its
            // keystrokes too — otherwise digits / j / k / t / ? typed into a field
            // leak to the global BBS navigation (e.g. a key starting "6…" jumps to
            // the Code screen). Bail whenever an <input>/<textarea> has focus.
            if let Some(el) = web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.active_element())
            {
                let tag = el.tag_name();
                if tag.eq_ignore_ascii_case("input") || tag.eq_ignore_ascii_case("textarea") {
                    return;
                }
                // A focused custom button (zone card, thread/member row, back
                // control, toggle) or native <button>/<a> owns Enter/Space — its
                // own handler activates it, so don't ALSO drive the global nav
                // model (which would double-navigate). Other keys still pass so
                // arrows / digits keep working while a control is focused.
                let k = ev.key();
                let is_button = tag.eq_ignore_ascii_case("button")
                    || tag.eq_ignore_ascii_case("a")
                    || el.get_attribute("role").as_deref() == Some("button");
                if is_button && (k == "Enter" || k == " " || k == "Spacebar") {
                    return;
                }
            }
            match ev.key().as_str() {
                "/" => {
                    ev.prevent_default();
                    state.cmd_open.set(true);
                }
                "Escape" => {
                    // Walk the Boards drill-down back one level per press: thread
                    // view → thread list → zone board list → Zones cards → menu.
                    let in_boards = state.screen.get_untracked() == Screen::Boards;
                    if in_boards && state.thread.get_untracked().is_some() {
                        state.close_thread();
                    } else if in_boards && state.board.get_untracked().is_some() {
                        state.close_board();
                    } else if in_boards && state.zone.get_untracked().is_some() {
                        state.close_zone();
                    } else {
                        state.go(Screen::MainMenu);
                    }
                }
                "Enter" => match state.screen.get_untracked() {
                    Screen::MainMenu => state.activate_menu(),
                    Screen::Boards => match state.board.get_untracked() {
                        None => {
                            let zone_ids: Vec<String> =
                                cfg.with_value(|c| c.zones.iter().map(|z| z.id.clone()).collect());
                            match state.zone.get_untracked() {
                                // Zones cards: open the selected zone.
                                None => {
                                    let entries = crate::relay::zone_entries(
                                        &store.channels.get_untracked(),
                                        &zone_ids,
                                    );
                                    if let Some((zsel, _)) =
                                        entries.get(state.selection.get_untracked())
                                    {
                                        state.open_zone(*zsel);
                                    }
                                }
                                // Board list: open the selected board in this zone.
                                Some(z) => {
                                    let boards = crate::relay::boards_in_zone(
                                        store.channels.get_untracked(),
                                        &zone_ids,
                                        z,
                                    );
                                    if let Some(c) = boards.get(state.selection.get_untracked()) {
                                        let id = c.id.clone();
                                        state.open_board(id.clone());
                                        crate::relay::subscribe_board(&id);
                                    }
                                }
                            }
                        }
                        // Thread list: open the selected thread. (In the thread
                        // view itself Enter is inert — the composer input owns it.)
                        Some(cid) if state.thread.get_untracked().is_none() => {
                            let threads =
                                crate::relay::group_threads(&store.posts.get_untracked(), &cid);
                            if let Some(t) = threads.get(state.selection.get_untracked()) {
                                state.open_thread(t.root.id.clone());
                            }
                        }
                        Some(_) => {}
                    },
                    _ => {}
                },
                "ArrowUp" | "k" => {
                    let len = nav_len(&state, &store, &cfg);
                    state.selection.update(|i| *i = wrap_index(*i, -1, len));
                }
                "ArrowDown" | "j" => {
                    let len = nav_len(&state, &store, &cfg);
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
