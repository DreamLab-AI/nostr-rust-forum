//! The ten BBS screens. Each maps to a real kit capability and reuses the kit's
//! own types (`nostr_bbs_config::Zone`, `nostr_bbs_core::governance`,
//! `nostr_bbs_core::did` / `solid_pod_rs::webid`) and live relay data
//! ([`RelayStore`]). Boards, Members, and Agents stream from the relay; the
//! pod browser surfaces the WebID/pod URLs.

use leptos::prelude::*;

use crate::agent::sample_panels;
use crate::ascii_img::{extract_image_urls, is_image_name, AsciiImg};
use crate::chrome::{BbsState, MainMenu};
use crate::config::BbsConfig;
use crate::identity::Identity;
use crate::menu::Screen;
use crate::pod::PodState;
use crate::relay::{self, RelayStore};
use crate::signer::BbsSigner;
use nostr_bbs_core::governance::{
    extract_d_tag, ActionStyle, PanelDefinition, KIND_ACTION_RESPONSE,
};

/// Inline status of a signed write (agent decision or board post).
#[derive(Clone)]
enum SendStatus {
    Idle,
    Sending,
    // Constructed only on the wasm publish-ack path; read by `suffix()` on both.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    Sent,
    Err(String),
}

impl SendStatus {
    /// Compact ASCII suffix rendered next to the control.
    fn suffix(&self) -> String {
        match self {
            SendStatus::Idle => String::new(),
            SendStatus::Sending => " …".to_string(),
            SendStatus::Sent => " ✓ signed".to_string(),
            SendStatus::Err(e) => format!(" ✗ {e}"),
        }
    }
}

/// A keydown handler that activates a `role="button"` control on Enter / Space,
/// so every tappable control is also keyboard-operable (WCAG: custom buttons
/// must respond to both keys, not just click). Pairs with `tabindex="0"`.
fn on_activate<F: Fn() + 'static>(action: F) -> impl Fn(web_sys::KeyboardEvent) + 'static {
    move |ev: web_sys::KeyboardEvent| {
        let k = ev.key();
        if k == "Enter" || k == " " || k == "Spacebar" {
            ev.prevent_default();
            action();
        }
    }
}

/// First non-blank line of `content`, truncated to `max` chars with an ellipsis
/// — the one-line preview for thread rows and breadcrumbs.
fn snippet(content: &str, max: usize) -> String {
    let line = content
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    if line.is_empty() {
        return "(no text)".to_string();
    }
    let mut out = String::new();
    for (n, ch) in line.chars().enumerate() {
        if n >= max {
            out.push('…');
            break;
        }
        out.push(ch);
    }
    out
}

/// A compact "time ago" label (`now`, `3m`, `2h`, `5d`) for a unix timestamp
/// relative to `now` — the thread-row last-activity column.
fn fmt_ago(now: u64, ts: u64) -> String {
    let d = now.saturating_sub(ts);
    if d < 60 {
        "now".to_string()
    } else if d < 3600 {
        format!("{}m", d / 60)
    } else if d < 86_400 {
        format!("{}h", d / 3600)
    } else {
        format!("{}d", d / 86_400)
    }
}

/// Current unix time in seconds (wasm clock; 0 on the native test target).
fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Render the active screen.
#[component]
pub fn ScreenView(state: BbsState) -> impl IntoView {
    let cfg = use_context::<StoredValue<BbsConfig>>().expect("config");
    let store = use_context::<RelayStore>().expect("relay");
    move || match state.screen.get() {
        Screen::Landing => landing(state, cfg).into_any(),
        Screen::Rebind => rebind(state, cfg).into_any(),
        Screen::MainMenu => view! { <MainMenu state=state /> }.into_any(),
        Screen::Agents => agents(store).into_any(),
        Screen::Boards => boards(state, store, cfg).into_any(),
        Screen::Chat => chat(store).into_any(),
        Screen::Dm => crate::dm::dm_screen(state, cfg).into_any(),
        Screen::Members => members(store, cfg).into_any(),
        Screen::Pod => pod(cfg).into_any(),
        Screen::Code => code(store).into_any(),
        Screen::Network => network(cfg, store).into_any(),
        Screen::Status => status(cfg, store).into_any(),
        Screen::Settings => settings(state, cfg).into_any(),
        Screen::Help => help().into_any(),
    }
}

/// Shared screen header.
fn header(screen: Screen) -> impl IntoView {
    view! {
        <div class="bbs-panel">
            <span class="title">"┌─ " {screen.title()} " ─────────────────────────────"</span>
            "\n  " <span class="bbs-dim">{screen.subtitle()}</span> "\n"
        </div>
    }
}

fn viewer(cfg: StoredValue<BbsConfig>) -> Option<Identity> {
    cfg.with_value(|c| {
        c.viewer_pubkey
            .as_deref()
            .and_then(|pk| Identity::derive(pk, &c.pod_api))
    })
}

/// Profile display name from a kind-0 metadata event.
fn profile_name(ev: &nostr_bbs_core::event::NostrEvent) -> String {
    serde_json::from_str::<serde_json::Value>(&ev.content)
        .ok()
        .and_then(|v| {
            v.get("display_name")
                .or_else(|| v.get("name"))
                .and_then(|n| n.as_str())
                .map(str::to_string)
        })
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| relay::short_id(&ev.pubkey))
}

/// Display label for a message author's pubkey, resolved from the loaded kind-0
/// `profiles` (display_name → name), falling back to a short id until that
/// author's profile has loaded. The BBS subscribes to `kinds:[0,40]`, so a
/// whitelisted author's nym is normally already present — this stops the board
/// from showing raw `<hex…hex>` handles where the main board shows a name.
pub(crate) fn author_label(profiles: &[nostr_bbs_core::event::NostrEvent], pubkey: &str) -> String {
    profiles
        .iter()
        .find(|ev| ev.pubkey == pubkey)
        .map(profile_name)
        .unwrap_or_else(|| relay::short_id(pubkey))
}

/// The `about` bio from a kind-0 metadata event, if present and non-empty.
fn profile_about(ev: &nostr_bbs_core::event::NostrEvent) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(&ev.content)
        .ok()
        .and_then(|v| {
            v.get("about")
                .and_then(|a| a.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
}

/// Logged-out onboarding landing — the signed-out entry screen. States what the
/// BBS is and how to get in within one phone screen, without opening Help:
/// a simple text masthead (operator node name + tagline, no box-glyph art so
/// nothing can mojibake or clip), three plain-language value-prop chips, and
/// three ≥44 px tap targets — Sign in (the sign-in sheet), Create account (the
/// forum at `/community/`), and Look around (browse read-only).
fn landing(state: BbsState, cfg: StoredValue<BbsConfig>) -> impl IntoView {
    let (node, tagline) = cfg.with_value(|c| (c.node_name.clone(), c.tagline.clone()));
    view! {
        <div class="bbs-landing">
            <div class="bbs-landing-masthead">{node}</div>
            <div class="bbs-landing-tagline">{tagline}</div>
            <div class="bbs-landing-props">
                <span class="bbs-prop">"\u{25B8} agent control plane"</span>
                <span class="bbs-prop">"\u{25B8} zone-gated boards"</span>
                <span class="bbs-prop">"\u{25B8} your own Solid pod"</span>
            </div>
            <div class="bbs-landing-cta">
                <span class="bbs-link accent bbs-cta" role="button"
                    on:click=move |_| state.go(Screen::Settings)
                >"[ \u{25B8} Sign in ]"</span>
                <a class="bbs-link accent bbs-cta" href="../" rel="noopener"
                >"[ \u{25B8} Create account \u{2197} ]"</a>
                <span class="bbs-link bbs-cta" role="button"
                    on:click=move |_| state.look_around()
                >"[ \u{25B8} Look around ]"</span>
            </div>
            <div class="bbs-dim bbs-landing-foot">
                "  New here? " <span class="accent">"Create account"</span>
                " sets you up at /community/ in seconds — no email or phone needed."
            </div>
        </div>
    }
}

/// (2) Boards — a tap-first drill-down: Zones (cards) → a zone's boards → posts.
/// Each level has an explicit tappable back control and a breadcrumb; the
/// keyboard model (↑↓ / ENTER / ESC) stays as an accelerator over the same
/// order.
fn boards(state: BbsState, store: RelayStore, cfg: StoredValue<BbsConfig>) -> impl IntoView {
    view! {
        {header(Screen::Boards)}
        {move || match state.board.get() {
            Some(id) => match state.thread.get() {
                // Deepest level: a thread's root + replies + reply composer.
                Some(root) => thread_view(state, store, cfg, id, root).into_any(),
                // A board opens on its thread list.
                None => thread_list(state, store, cfg, id).into_any(),
            },
            None => match state.zone.get() {
                Some(z) => board_list_for_zone(state, store, cfg, z).into_any(),
                // In pwa mode there is no Zones shelf — a None zone re-pins to the
                // bound zone and other zones are navigation-unreachable (the relay
                // stays the real boundary). Fall through to zones_screen only if
                // the pin is unresolved (a renamed/removed bound zone), never
                // widening access.
                None => {
                    if state.pwa_mode.get() {
                        match state.pinned_zone.get() {
                            Some(z) => board_list_for_zone(state, store, cfg, z).into_any(),
                            None => zones_screen(state, store, cfg).into_any(),
                        }
                    } else {
                        zones_screen(state, store, cfg).into_any()
                    }
                }
            },
        }}
    }
}

/// Resolve a zone selector to its `(display_name, accent_hex)`. `OTHER_ZONE`
/// (and any out-of-range index) becomes the neutral "Other" group.
fn zone_label(zone_sel: usize, zones: &[nostr_bbs_config::schema::Zone]) -> (String, String) {
    if zone_sel == relay::OTHER_ZONE {
        return ("Other".to_string(), String::new());
    }
    match zones.get(zone_sel) {
        Some(z) => (
            z.display_name.clone(),
            z.accent_hex.clone().unwrap_or_default(),
        ),
        None => ("Other".to_string(), String::new()),
    }
}

/// Top-level Zones screen — one accent **card** per configured zone (plus an
/// "Other" card when boards match no zone), each with its display name and board
/// count. Never a clipped `@handle`. Tap a card (or ↑↓ + ENTER) to open the zone.
fn zones_screen(state: BbsState, store: RelayStore, cfg: StoredValue<BbsConfig>) -> impl IntoView {
    move || {
        let zones = cfg.with_value(|c| c.zones.clone());
        let zone_ids: Vec<String> = zones.iter().map(|z| z.id.clone()).collect();
        let channels = store.channels.get();
        let entries = relay::zone_entries(&channels, &zone_ids);
        if entries.is_empty() {
            return view! {
                <div class="bbs-panel bbs-dim">
                    "  No zones yet. Zones and their boards load from config ([[zones]] in\n  forum.toml) and the relay; sign in if a zone looks empty (reads are\n  deny-by-default at the relay)."
                </div>
            }
            .into_any();
        }
        let cards = entries
            .into_iter()
            .enumerate()
            .map(|(i, (zsel, count))| {
                let (name, accent) = zone_label(zsel, &zones);
                let style = if accent.is_empty() {
                    String::new()
                } else {
                    format!("--accent:{accent}")
                };
                let count_label = format!("{count} board{}", if count == 1 { "" } else { "s" });
                let aria_label = format!("Open zone {name}, {count_label}");
                view! {
                    <div
                        // Real button semantics: keyboard-focusable, activatable by
                        // Enter/Space, ≥44 px — not a `role="option"` without a
                        // listbox parent (announced as static text) at 39 px.
                        class="bbs-row bbs-zone-card"
                        class:selected=move || state.selection.get() == i
                        style=style
                        role="button"
                        tabindex="0"
                        aria-label=aria_label
                        on:click=move |_| {
                            state.selection.set(i);
                            state.open_zone(zsel);
                        }
                        on:keydown=on_activate(move || {
                            state.selection.set(i);
                            state.open_zone(zsel);
                        })
                    >
                        <span class="accent bbs-chip">"\u{2593}"</span>
                        <span class="bbs-zone-name">{name}</span>
                        <span class="bbs-dim bbs-zone-count">{count_label}</span>
                    </div>
                }
            })
            .collect_view();
        view! {
            <div class="bbs-panel bbs-dim">"  Pick a zone to see its boards."</div>
            <div class="bbs-list">{cards}</div>
            <div class="bbs-panel bbs-dim">"  Tap a zone to open it (\u{2191}\u{2193} then Enter also work)."</div>
        }
        .into_any()
    }
}

/// One zone's board list — the middle drill-down level. A tappable `← Zones`
/// back control + breadcrumb, the zone's ASCII hero (desktop), then its boards
/// as ellipsised rows with a left accent chip. Friendly empty state when the
/// zone has no boards yet.
fn board_list_for_zone(
    state: BbsState,
    store: RelayStore,
    cfg: StoredValue<BbsConfig>,
    zone_sel: usize,
) -> impl IntoView {
    let zones = cfg.with_value(|c| c.zones.clone());
    let (zone_name, _accent) = zone_label(zone_sel, &zones);
    let hero = if zone_sel == relay::OTHER_ZONE {
        None
    } else {
        zones.get(zone_sel).map(zone_hero)
    };
    // In pwa mode the app IS this zone — there is nowhere to go "back" to, so the
    // "← Zones" crumb is suppressed (pwa mode is constant for the session, so an
    // untracked read is correct here).
    let pinned_app = state.pwa_mode.get_untracked();
    view! {
        <div class="bbs-panel bbs-crumb">
            {(!pinned_app).then(|| view! {
                <span class="bbs-link accent" role="button" tabindex="0"
                    aria-label="Back to zones"
                    on:click=move |_| state.close_zone()
                    on:keydown=on_activate(move || state.close_zone())
                >
                    "\u{2190} Zones"
                </span>
                <span class="bbs-dim">"  \u{203A}  "</span>
            })}
            <span class="accent">{zone_name}</span>
        </div>
        {hero}
        {move || {
            let zone_ids: Vec<String> = cfg.with_value(|c| c.zones.iter().map(|z| z.id.clone()).collect());
            let zones_ref = cfg.with_value(|c| c.zones.clone());
            let boards = relay::boards_in_zone(store.channels.get(), &zone_ids, zone_sel);
            if boards.is_empty() {
                return view! {
                    <div class="bbs-panel bbs-dim">
                        "  No boards in this zone yet. Boards (kind-40 channels) appear here as\n  they arrive from the relay — sign in if this zone is cohort-gated."
                    </div>
                }
                .into_any();
            }
            let rows = boards
                .into_iter()
                .enumerate()
                .map(move |(i, ev)| board_row(state, i, ev, &zones_ref, &zone_ids))
                .collect_view();
            view! {
                <div class="bbs-list">{rows}</div>
                <div class="bbs-panel bbs-dim">"  Tap a board to open it (\u{2191}\u{2193} then Enter also work)."</div>
            }
            .into_any()
        }}
    }
}

/// One zone's on-theme ASCII "section hero": an accent-tinted chip label and,
/// when the zone has a banner image, its ASCII render. Rendered inline above the
/// zone's own boards in the Boards list (see [`board_list`]).
fn zone_hero(z: &nostr_bbs_config::schema::Zone) -> impl IntoView {
    let url = z.banner_image_url.clone().filter(|u| !u.trim().is_empty());
    let accent = z.accent_hex.clone().unwrap_or_default();
    let style = if accent.is_empty() {
        String::new()
    } else {
        format!("--accent:{accent}")
    };
    let label = format!("\u{259E} {} \u{259A}", z.display_name);
    view! {
        <div class="bbs-section-hero" style=style>
            <div class="label">{label}</div>
            {url.map(|u| view! { <AsciiImg src=u cols=84 /> })}
        </div>
    }
}

/// One board row. `i` is the position in the zone-ordered channel list — the same
/// index the keyboard selection / ENTER use (see [`relay::flat_zone_order`]), so
/// click-open and arrow-nav stay consistent with the grouped visual order.
fn board_row(
    state: BbsState,
    i: usize,
    ev: nostr_bbs_core::event::NostrEvent,
    zones: &[nostr_bbs_config::schema::Zone],
    zone_ids: &[String],
) -> impl IntoView {
    // Resolved channel name (kind-40), hex only as a dim fallback inside
    // `channel_name`; never the raw id in the primary label.
    let name = relay::channel_name(&ev);
    // Tint the row to its configured zone's accent (matched by zone index, so a
    // section slug like "public-support" resolves to the "public" zone colour).
    let accent = relay::channel_zone_index(&ev, zone_ids)
        .and_then(|idx| zones.get(idx))
        .and_then(|z| z.accent_hex.clone())
        .unwrap_or_default();
    let style = if accent.is_empty() {
        String::new()
    } else {
        format!("--accent:{accent}")
    };
    let aria_label = format!("Open board {name}");
    // Mirror the keyboard Enter path: opening a board MUST also fire the kind-42
    // relay subscription, or a click-opened board shows a permanent blank (no
    // posts ever arrive). One closure, shared by click + keyboard activation.
    let open = {
        let chan_id = ev.id.clone();
        move || {
            state.selection.set(i);
            state.open_board(chan_id.clone());
            crate::relay::subscribe_board(&chan_id);
        }
    };
    let open_key = open.clone();
    view! {
        <div
            // A fixed-width left accent chip that is never clipped, and a name
            // that ellipsises instead of being padded to 24 chars and having its
            // zone `@handle` clipped off the right edge at 360 px. Button
            // semantics (focusable, Enter/Space) — not a bare `role="option"`.
            class="bbs-row bbs-board-row"
            class:selected=move || state.selection.get() == i
            style=style
            role="button"
            tabindex="0"
            aria-label=aria_label
            on:click=move |_| open()
            on:keydown=on_activate(open_key)
        >
            <span class="accent bbs-chip">"\u{2593}"</span>
            <span class="bbs-board-name">{name}</span>
        </div>
    }
}

/// Resolve `(zone_display_name, board_name)` for a channel from the loaded
/// kind-40 channels — the board was opened by tap/ENTER so it is present. Names,
/// never hex; falls back to a short id / "Other".
fn board_crumb(
    store: &RelayStore,
    cfg: StoredValue<BbsConfig>,
    channel_id: &str,
) -> (String, String) {
    let zones = cfg.with_value(|c| c.zones.clone());
    let zone_ids: Vec<String> = zones.iter().map(|z| z.id.clone()).collect();
    let channels = store.channels.get_untracked();
    let chan = channels.iter().find(|c| c.id == channel_id);
    let board = chan
        .map(relay::channel_name)
        .unwrap_or_else(|| relay::short_id(channel_id));
    let zone = chan
        .and_then(|c| relay::channel_zone_index(c, &zone_ids))
        .and_then(|i| zones.get(i))
        .map(|z| z.display_name.clone())
        .unwrap_or_else(|| "Other".to_string());
    (zone, board)
}

/// A board's THREAD LIST — the third drill-down level. A tappable `← Boards`
/// back control + `Zone › Board` breadcrumb (resolved names, not hex), one
/// tappable row per thread (root snippet + reply count + last activity),
/// top-anchored, a friendly empty state, and a "start a topic" composer pinned
/// below (posting here opens a NEW thread — `reply_to = None`).
fn thread_list(
    state: BbsState,
    store: RelayStore,
    cfg: StoredValue<BbsConfig>,
    channel_id: String,
) -> impl IntoView {
    let signer = use_context::<BbsSigner>();
    let pod_api = cfg.with_value(|c| c.pod_api.clone());
    let draft = RwSignal::new(String::new());
    let status = RwSignal::new(SendStatus::Idle);
    // A new-topic composer: no reply target, so the post is a thread root.
    let reply_to = RwSignal::new(None::<(String, String)>);
    let channel_for_send = channel_id.clone();
    let (crumb_zone, crumb_board) = board_crumb(&store, cfg, &channel_id);
    view! {
        <div class="bbs-panel bbs-crumb">
            <span class="bbs-link accent" role="button" tabindex="0"
                aria-label="Back to boards"
                on:click=move |_| state.close_board()
                on:keydown=on_activate(move || state.close_board())
            >
                "\u{2190} Boards"
            </span>
            <span class="bbs-dim">"  " {crumb_zone} "  \u{203A}  "</span>
            <span class="accent">{crumb_board}</span>
        </div>
        {move || {
            let threads = relay::group_threads(&store.posts.get(), &channel_id);
            if threads.is_empty() {
                return view! { <div class="bbs-panel bbs-dim">"  No topics here yet. Start one with the box below \u{2014}\n  or sign in to unlock cohort-gated zones (reads are deny-by-default)."</div> }.into_any();
            }
            let now = now_secs();
            let profiles = store.profiles.get();
            view! {
                <div class="bbs-list">
                    {threads
                        .into_iter()
                        .enumerate()
                        .map(|(i, t)| {
                            let who = author_label(&profiles, &t.root.pubkey);
                            let preview = snippet(&t.root.content, 52);
                            let replies = t.reply_count;
                            let ago = fmt_ago(now, t.last_activity);
                            let root_id = t.root.id.clone();
                            let open = move || state.open_thread(root_id.clone());
                            let open_key = open.clone();
                            let meta = format!(
                                "{} repl{} \u{00B7} {}",
                                replies,
                                if replies == 1 { "y" } else { "ies" },
                                ago,
                            );
                            let aria = format!("Open thread by {who}: {preview} ({meta})");
                            view! {
                                <div
                                    class="bbs-row bbs-thread-row"
                                    class:selected=move || state.selection.get() == i
                                    role="button"
                                    tabindex="0"
                                    aria-label=aria
                                    on:click=move |_| open()
                                    on:keydown=on_activate(open_key)
                                >
                                    <span class="accent bbs-chip">"\u{25B8}"</span>
                                    <span class="bbs-thread-snip">{preview}</span>
                                    <span class="bbs-dim bbs-thread-meta">{meta}</span>
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
            }.into_any()
        }}
        {board_composer(signer, channel_for_send, store, draft, status, reply_to, None, pod_api)}
    }
}

/// A THREAD VIEW — the deepest level: the root post and its replies in
/// chronological order, with a `← Topics` back control and a `Zone › Board ›
/// Topic` breadcrumb. The composer posts a reply to the thread root by default;
/// a per-post `[reply]` retargets it to that specific post.
fn thread_view(
    state: BbsState,
    store: RelayStore,
    cfg: StoredValue<BbsConfig>,
    channel_id: String,
    root_id: String,
) -> impl IntoView {
    let signer = use_context::<BbsSigner>();
    let pod_api = cfg.with_value(|c| c.pod_api.clone());
    let draft = RwSignal::new(String::new());
    let status = RwSignal::new(SendStatus::Idle);
    // Default reply target = the thread root, so posting continues this thread;
    // a per-post [reply] overrides it, and [clear] returns to the root.
    let root_author = store
        .posts
        .get_untracked()
        .iter()
        .find(|p| p.id == root_id)
        .map(|p| p.pubkey.clone());
    let default_reply = root_author.map(|a| (root_id.clone(), a));
    let reply_to = RwSignal::new(default_reply.clone());
    let (crumb_zone, crumb_board) = board_crumb(&store, cfg, &channel_id);
    let crumb_topic = store
        .posts
        .get_untracked()
        .iter()
        .find(|p| p.id == root_id)
        .map(|p| snippet(&p.content, 28))
        .unwrap_or_else(|| relay::short_id(&root_id));
    let channel_for_send = channel_id.clone();
    let root_for_msgs = root_id.clone();
    view! {
        <div class="bbs-panel bbs-crumb">
            <span class="bbs-link accent" role="button" tabindex="0"
                aria-label="Back to topics"
                on:click=move |_| state.close_thread()
                on:keydown=on_activate(move || state.close_thread())
            >
                "\u{2190} Topics"
            </span>
            <span class="bbs-dim">"  " {crumb_zone} " \u{203A} " {crumb_board} " \u{203A} "</span>
            <span class="accent">{crumb_topic}</span>
        </div>
        {move || {
            let msgs = relay::thread_messages(&store.posts.get(), &channel_id, &root_for_msgs);
            if msgs.is_empty() {
                return view! { <div class="bbs-panel bbs-dim">"  This topic hasn\u{2019}t loaded yet \u{2014} it may be in a cohort-gated zone.\n  Sign in, or reply below to start it off."</div> }.into_any();
            }
            let root_ref = root_for_msgs.clone();
            let profiles = store.profiles.get();
            view! {
                <div class="bbs-list">
                    {msgs
                        .into_iter()
                        .map(|p| {
                            let who = author_label(&profiles, &p.pubkey);
                            let body = p.content.clone();
                            let imgs = extract_image_urls(&p.content);
                            let reply_id = p.id.clone();
                            let reply_pk = p.pubkey.clone();
                            let is_root = p.id == root_ref;
                            view! {
                                <div class="bbs-row bbs-post-row" class:bbs-post-root=is_root>
                                    <span class="accent">{format!("<{who}> ")}</span>
                                    {body}
                                    " "
                                    <span class="bbs-link bbs-dim" role="button" tabindex="0"
                                        aria-label="Reply to this post"
                                        on:click=move |_| reply_to.set(Some((reply_id.clone(), reply_pk.clone())))
                                        on:keydown={
                                            let reply_id = p.id.clone();
                                            let reply_pk = p.pubkey.clone();
                                            on_activate(move || reply_to.set(Some((reply_id.clone(), reply_pk.clone()))))
                                        }
                                    >"[reply]"</span>
                                </div>
                                {imgs.into_iter().map(|src| view! {
                                    <div class="bbs-ascii-row"><AsciiImg src=src cols=64 /></div>
                                }).collect_view()}
                            }
                        })
                        .collect_view()}
                </div>
            }.into_any()
        }}
        {board_composer(signer, channel_for_send, store, draft, status, reply_to, default_reply, pod_api)}
    }
}

/// Extract lowercased `@handle` tokens (alphanumeric / `_` / `-`) from `content`.
fn parse_handles(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = content.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'@' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len()
                && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_' || bytes[j] == b'-')
            {
                j += 1;
            }
            if j > start {
                out.push(content[start..j].to_ascii_lowercase());
            }
            i = j.max(start);
        } else {
            i += 1;
        }
    }
    out
}

/// A kind-0 profile's `(name, display_name-without-spaces)`, both lowercased.
fn profile_handles(ev: &nostr_bbs_core::event::NostrEvent) -> (String, String) {
    serde_json::from_str::<serde_json::Value>(&ev.content)
        .ok()
        .map(|v| {
            let name = v
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let disp = v
                .get("display_name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_ascii_lowercase()
                .replace(' ', "");
            (name, disp)
        })
        .unwrap_or_default()
}

/// Resolve `@handle` mentions in `content` to `["p", pubkey]` tags by matching
/// each handle (case-insensitively) against loaded kind-0 profile `name` /
/// `display_name`. Skips handles already p-tagged in `existing` and de-dups.
///
/// This is what lets a BBS `@junkiejarvis` mention actually reach the agent:
/// agents subscribe with `{kinds:[42], #p:[<agent-pubkey>]}`, so a bare content
/// mention with no p-tag is invisible to them.
fn mention_ptags(
    content: &str,
    profiles: &[nostr_bbs_core::event::NostrEvent],
    existing: &[Vec<String>],
) -> Vec<Vec<String>> {
    let handles = parse_handles(content);
    if handles.is_empty() {
        return Vec::new();
    }
    let already: std::collections::HashSet<&str> = existing
        .iter()
        .filter(|t| t.first().map(String::as_str) == Some("p"))
        .filter_map(|t| t.get(1).map(String::as_str))
        .collect();
    let mut out: Vec<Vec<String>> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for ev in profiles {
        let (name, disp) = profile_handles(ev);
        let hit = handles
            .iter()
            .any(|h| (!name.is_empty() && *h == name) || (!disp.is_empty() && *h == disp));
        if hit && !already.contains(ev.pubkey.as_str()) && seen.insert(ev.pubkey.clone()) {
            out.push(vec!["p".to_string(), ev.pubkey.clone()]);
        }
    }
    out
}

#[cfg(test)]
mod mention_tests {
    use super::*;
    use nostr_bbs_core::event::NostrEvent;

    fn profile(pubkey: &str, name: &str, display: &str) -> NostrEvent {
        NostrEvent {
            id: String::new(),
            pubkey: pubkey.to_string(),
            created_at: 0,
            kind: 0,
            tags: vec![],
            content: format!(r#"{{"name":"{name}","display_name":"{display}"}}"#),
            sig: String::new(),
        }
    }

    #[test]
    fn parses_handles_case_insensitive() {
        assert_eq!(
            parse_handles("hi @JunkieJarvis and @bob-1!"),
            vec!["junkiejarvis", "bob-1"]
        );
        assert!(parse_handles("no mentions here").is_empty());
        assert_eq!(parse_handles("email a@b is not a handle start"), vec!["b"]);
    }

    #[test]
    fn author_label_resolves_nym_else_short_id() {
        let alice = "a".repeat(64);
        let bob = "b".repeat(64);
        let profiles = vec![profile(&alice, "alice", "Alice")];
        // Known author → display name (not the raw pubkey).
        assert_eq!(author_label(&profiles, &alice), "Alice");
        // Unknown author → short id, never the full 64-hex pubkey.
        let got = author_label(&profiles, &bob);
        assert_eq!(got, relay::short_id(&bob));
        assert_ne!(got, bob);
    }

    #[test]
    fn resolves_mention_to_ptag() {
        let profiles = vec![
            profile(
                "2de44d5622eef79519ac078f6e227a85aecbaefd561e4e50c5f51dfadbf916e9",
                "junkiejarvis",
                "JunkieJarvis",
            ),
            profile("aa".repeat(32).as_str(), "alice", "Alice"),
        ];
        let base = relay::channel_message_tags("chan", None);
        let tags = mention_ptags("@junkiejarvis what's on this week?", &profiles, &base);
        assert_eq!(
            tags,
            vec![vec![
                "p".to_string(),
                "2de44d5622eef79519ac078f6e227a85aecbaefd561e4e50c5f51dfadbf916e9".to_string()
            ]]
        );
    }

    #[test]
    fn skips_already_ptagged_and_dedups() {
        let jj = "2de44d5622eef79519ac078f6e227a85aecbaefd561e4e50c5f51dfadbf916e9";
        let profiles = vec![profile(jj, "junkiejarvis", "JunkieJarvis")];
        // Reply already p-tags jj as the parent author → no duplicate p-tag.
        let base = relay::channel_message_tags("chan", Some(("root".into(), jj.into())));
        assert!(mention_ptags("@junkiejarvis hi", &profiles, &base).is_empty());
    }

    #[test]
    fn unknown_handle_yields_nothing() {
        let profiles = vec![profile("aa".repeat(32).as_str(), "alice", "Alice")];
        assert!(mention_ptags("@nobody hello", &profiles, &[]).is_empty());
    }
}

/// Compose box for a board: a signed kind-42 channel message (NIP-28), posting a
/// new thread root (`reply_to = None`) or a reply to a selected post. Carries an
/// image affordance (F10): pick → validate → compress → PUT to the pod →
/// insert the URL, which posts as a normal kind-42 rendered on-theme as ASCII.
/// `default_reply` is the baseline reply target that `[clear]` returns to (the
/// thread root in a thread view; `None` in a thread list). Fails closed — hidden
/// with a prompt when no signer is available.
#[allow(clippy::too_many_arguments)]
fn board_composer(
    signer: Option<BbsSigner>,
    channel_id: String,
    store: RelayStore,
    draft: RwSignal<String>,
    status: RwSignal<SendStatus>,
    reply_to: RwSignal<Option<(String, String)>>,
    default_reply: Option<(String, String)>,
    pod_api: String,
) -> impl IntoView {
    // True while an image is compressing/uploading — drives the optimistic
    // "▞ IMG ▚ …uploading" placeholder before the URL lands in the draft.
    let img_pending = RwSignal::new(false);
    move || {
        let signed_in = signer.and_then(|s| s.pubkey().get()).is_some();
        if !signed_in {
            return view! {
                <div class="bbs-panel bbs-dim">
                    "  Sign in to post here — tap " <span class="accent">"Sign in"</span>
                    " on the bottom bar, or open Settings (" <span class="accent">"[9]"</span>
                    "). You can also sign in at /community/."
                </div>
            }
            .into_any();
        }
        let cid = channel_id.clone();
        let default_clear = default_reply.clone();
        // Local clone moved into the send closure — the outer view closure is
        // `Fn`, so we cannot move the captured `default_reply` out of it.
        let default_send = default_reply.clone();
        let send: std::rc::Rc<dyn Fn()> = std::rc::Rc::new(move || {
            let text = draft.get_untracked().trim().to_string();
            if text.is_empty() || matches!(status.get_untracked(), SendStatus::Sending) {
                return;
            }
            let signer = match signer {
                Some(s) => s,
                None => return,
            };
            let pubkey = match signer.pubkey_hex() {
                Some(pk) => pk,
                None => {
                    status.set(SendStatus::Err("sign in first".to_string()));
                    return;
                }
            };
            let signer_rc = match signer.get_signer() {
                Some(s) => s,
                None => {
                    status.set(SendStatus::Err("sign in first".to_string()));
                    return;
                }
            };
            let now = (js_sys::Date::now() / 1000.0) as u64;
            let mut tags = relay::channel_message_tags(&cid, reply_to.get_untracked());
            // Resolve @handle mentions to `["p", pubkey]` so agent mentions
            // (e.g. @junkiejarvis) reach the agent's `#p` subscription — a bare
            // content mention alone is invisible to it.
            let mentions = mention_ptags(&text, &store.profiles.get_untracked(), &tags);
            tags.extend(mentions);
            let unsigned = nostr_bbs_core::UnsignedEvent {
                pubkey,
                created_at: now,
                kind: 42,
                tags,
                content: text,
            };
            status.set(SendStatus::Sending);
            draft.set(String::new());
            // Return to the baseline reply target (thread root, or None).
            reply_to.set(default_send.clone());
            publish_signed(signer_rc, unsigned, status);
        });
        let send_click = send.clone();
        let send_key = send.clone();
        let file_input = NodeRef::<leptos::html::Input>::new();
        let pod_for_pick = pod_api.clone();
        view! {
            <div class="bbs-cmdline">
                {move || reply_to.get().map(|(id, _)| {
                    // Clone into locals inside the map callback — the outer view
                    // closure is `Fn`, so `default_clear` must be borrowed, not moved.
                    let d_click = default_clear.clone();
                    let d_key = default_clear.clone();
                    view! {
                        <span class="bbs-dim">
                            "↳ reply to " {relay::short_id(&id)} " "
                            <span class="bbs-link" role="button" tabindex="0"
                                on:click=move |_| reply_to.set(d_click.clone())
                                on:keydown=on_activate(move || reply_to.set(d_key.clone()))
                            >"[clear]"</span>
                            " "
                        </span>
                    }
                })}
                <span class="prompt">{move || if reply_to.get().is_some() { "reply/" } else { "post/" }}</span>
                <input
                    prop:value=move || draft.get()
                    on:input=move |ev| draft.set(event_target_value(&ev))
                    on:keydown=move |ev| {
                        if ev.key() == "Enter" {
                            ev.prevent_default();
                            send_key();
                        }
                    }
                />
                <span class="bbs-link accent" role="button" tabindex="0"
                    aria-label="Add an image"
                    on:click=move |_| { if let Some(inp) = file_input.get_untracked() { inp.click(); } }
                    on:keydown=on_activate(move || { if let Some(inp) = file_input.get_untracked() { inp.click(); } })
                >"[ \u{25B8} image ]"</span>
                <input
                    node_ref=file_input
                    type="file"
                    accept="image/*"
                    class="bbs-file-input"
                    on:change=move |ev| pick_image(ev, signer, pod_for_pick.clone(), draft, status, img_pending)
                />
                <span class="bbs-link accent" role="button" tabindex="0"
                    on:click=move |_| send_click()
                    on:keydown={ let s = send.clone(); on_activate(move || s()) }
                >"[ send ]"</span>
                <span class="bbs-dim">{move || status.get().suffix()}</span>
            </div>
            {move || img_pending.get().then(|| view! {
                <div class="bbs-ascii-row bbs-ascii-pending">
                    <pre class="ascii-img ascii-img-status">"[ compressing & uploading image … ]"</pre>
                </div>
            })}
        }
        .into_any()
    }
}

/// Handle a composer image pick (F10): validate client-side, then compress and
/// PUT to the pod off-thread. Friendly errors go through the `SendStatus::Err`
/// inline channel; the returned URL is appended to the draft so a normal send
/// posts it. wasm-only — the native build (unit tests) is a no-op.
#[cfg(target_arch = "wasm32")]
fn pick_image(
    ev: web_sys::Event,
    signer: Option<BbsSigner>,
    pod_api: String,
    draft: RwSignal<String>,
    status: RwSignal<SendStatus>,
    img_pending: RwSignal<bool>,
) {
    use wasm_bindgen::JsCast;
    let input: web_sys::HtmlInputElement = match ev
        .target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
    {
        Some(i) => i,
        None => return,
    };
    let file = match input.files().and_then(|fl| fl.get(0)) {
        Some(f) => f,
        None => return,
    };
    // Clear the input so re-picking the same file fires `change` again.
    input.set_value("");
    let signer = match signer {
        Some(s) => s,
        None => {
            status.set(SendStatus::Err("sign in to add an image".to_string()));
            return;
        }
    };
    // Client-side validation before any network call (friendly terminal errors).
    if !crate::upload::is_accepted_image(&file) {
        status.set(SendStatus::Err("only JPG/PNG/WEBP/GIF images".to_string()));
        return;
    }
    let size = file.size() as u64;
    if size > crate::upload::MAX_FILE_SIZE {
        let mb = (size as f64 / (1024.0 * 1024.0)).ceil() as u64;
        status.set(SendStatus::Err(format!(
            "that file is {mb} MB — the limit is 5 MB"
        )));
        return;
    }
    let pubkey = match signer.pubkey_hex() {
        Some(p) => p,
        None => {
            status.set(SendStatus::Err("sign in first".to_string()));
            return;
        }
    };
    let signer_rc = match signer.get_signer() {
        Some(s) => s,
        None => {
            status.set(SendStatus::Err("sign in first".to_string()));
            return;
        }
    };
    img_pending.set(true);
    status.set(SendStatus::Sending);
    wasm_bindgen_futures::spawn_local(async move {
        match crate::upload::compress_and_upload(&file, &pubkey, signer_rc.as_ref(), &pod_api).await
        {
            Ok(url) => {
                draft.update(|d| {
                    if !d.is_empty() && !d.ends_with(' ') {
                        d.push(' ');
                    }
                    d.push_str(&url);
                });
                status.set(SendStatus::Idle);
                img_pending.set(false);
            }
            Err(e) => {
                web_sys::console::error_1(&format!("[bbs-upload] {e}").into());
                status.set(SendStatus::Err(e));
                img_pending.set(false);
            }
        }
    });
}

/// Native no-op — the image pipeline is browser-only.
#[cfg(not(target_arch = "wasm32"))]
fn pick_image(
    _ev: web_sys::Event,
    _signer: Option<BbsSigner>,
    _pod_api: String,
    _draft: RwSignal<String>,
    _status: RwSignal<SendStatus>,
    _img_pending: RwSignal<bool>,
) {
}

/// (5) Pod — the live Solid pod browser (WebID-owned storage).
fn pod(cfg: StoredValue<BbsConfig>) -> impl IntoView {
    let id = viewer(cfg);
    let listing = RwSignal::new(PodState::Idle);
    // Pod base + viewer hex, used to build absolute URLs for image members so
    // they can be rendered on-theme as ASCII.
    let pod_api = cfg.with_value(|c| c.pod_api.clone());
    let hex = id
        .as_ref()
        .map(|i| i.pubkey_hex.clone())
        .unwrap_or_default();

    // Kick off the live container fetch when a viewer identity is present.
    if let Some(idv) = &id {
        let (pod_api, hex) = (
            cfg.with_value(|c| c.pod_api.clone()),
            idv.pubkey_hex.clone(),
        );
        if !pod_api.is_empty() {
            listing.set(PodState::Loading);
            #[cfg(target_arch = "wasm32")]
            wasm_bindgen_futures::spawn_local(async move {
                match crate::pod::fetch_container(&pod_api, &hex, "").await {
                    Ok(items) => listing.set(PodState::Loaded(items)),
                    Err(e) => listing.set(PodState::Error(e)),
                }
            });
            #[cfg(not(target_arch = "wasm32"))]
            let _ = (pod_api, hex);
        }
    }

    view! {
        {header(Screen::Pod)}
        {match id {
            Some(id) => view! {
                <div class="bbs-panel">
                    "  Your pod is private, identity-keyed storage (WAC deny-by-default).\n"
                    "  WebID   — your identity URL:  " <span class="accent">{id.webid.clone()}</span> "\n"
                    "  pod-git — clone your pod:     " <span class="bbs-dim">"git clone "</span> {id.git_clone.clone()} "\n"
                    <span class="bbs-dim">"  These are private paths — opening them raw in a browser is meant to return 401;\n  access needs your signed-in credentials.\n"</span>
                    "\n  /" {id.short()} "/"
                </div>
                {move || match listing.get() {
                    PodState::Idle | PodState::Loading => view! {
                        <div class="bbs-panel bbs-dim">"    … loading container"</div>
                    }.into_any(),
                    PodState::Error(e) => view! {
                        <div class="bbs-panel bbs-dim">
                            {if e.contains("401") || e.contains("403") || e.to_ascii_lowercase().contains("auth") {
                                "    Your pod is private (WAC deny-by-default). Browsing it needs an\n    authenticated request — sign in to view your files.".to_string()
                            } else {
                                format!("    pod unavailable: {e}")
                            }}
                        </div>
                    }.into_any(),
                    PodState::Loaded(items) if items.is_empty() => view! {
                        <div class="bbs-panel bbs-dim">"    (empty container)"</div>
                    }.into_any(),
                    PodState::Loaded(items) => view! {
                        <div class="bbs-list">
                            {items.into_iter().map(|r| {
                                let mark = if r.is_container { "▸ " } else { "· " };
                                let suffix = if r.is_container { "/" } else { "" };
                                let img_url = (!r.is_container && is_image_name(&r.name))
                                    .then(|| crate::pod::container_url(&pod_api, &hex, &r.name));
                                view! {
                                    <div class="bbs-row">
                                        "    " <span class="accent">{mark}</span>
                                        {r.name} {suffix}
                                    </div>
                                    {img_url.map(|src| view! {
                                        <div class="bbs-ascii-row"><AsciiImg src=src cols=72 /></div>
                                    })}
                                }
                            }).collect_view()}
                        </div>
                    }.into_any(),
                }}
            }.into_any(),
            None => view! {
                <div class="bbs-panel bbs-dim">
                    "  Sign in to browse your Solid pod. Each account owns a WebID pod with\n  WAC deny-by-default access control and a git-clonable history."
                </div>
            }.into_any(),
        }}
    }
}

/// (7) Network — relay (live status) + federation mesh.
fn network(cfg: StoredValue<BbsConfig>, store: RelayStore) -> impl IntoView {
    let (relay_url, pod) = cfg.with_value(|c| (c.relay_url.clone(), c.pod_api.clone()));
    let relay_disp = if relay_url.is_empty() {
        "(not configured)".to_string()
    } else {
        relay_url
    };
    let pod_disp = if pod.is_empty() {
        "(not configured)".to_string()
    } else {
        pod
    };
    view! {
        {header(Screen::Network)}
        <div class="bbs-list">
            <div class="bbs-row">
                <span class=move || if store.connected.get() { "accent" } else { "bbs-dim" }>
                    {move || if store.connected.get() { "◆ " } else { "◇ " }}
                </span>
                "relay   " <span class="bbs-dim">{relay_disp}</span>
            </div>
            <div class="bbs-row"><span class="accent">"◆ "</span>"pod     " <span class="bbs-dim">{pod_disp}</span></div>
            <div class="bbs-row"><span class="accent">"◆ "</span>"mesh    " <span class="bbs-dim">"federation peers load from [mesh].peer_relays (wss:// only)"</span></div>
        </div>
    }
}

/// (4) Members — did:nostr WebID profiles (live kind-0). Roster rows are
/// tappable → a profile panel (F15): kind-0 name/about/short-id + the member's
/// did:nostr and WebID, with a back control to the roster.
fn members(store: RelayStore, cfg: StoredValue<BbsConfig>) -> impl IntoView {
    let me = viewer(cfg);
    let pod_api = cfg.with_value(|c| c.pod_api.clone());
    // Selected member's pubkey — `None` shows the roster, `Some` the profile.
    let selected = RwSignal::new(None::<String>);
    view! {
        {header(Screen::Members)}
        {move || match selected.get() {
            Some(pk) => member_profile(selected, store, pod_api.clone(), pk).into_any(),
            None => {
                let profiles = store.profiles.get();
                if profiles.is_empty() {
                    return view! { <div class="bbs-panel bbs-dim">"  Member roster loads from the relay (kind-0). Each member is a did:nostr\n  identity with a WebID profile; private keys never leave the device."</div> }.into_any();
                }
                view! {
                    <div class="bbs-list">
                        {profiles
                            .into_iter()
                            .map(|ev| {
                                let name = profile_name(&ev);
                                let who = relay::short_id(&ev.pubkey);
                                let pk = ev.pubkey.clone();
                                let open = move || selected.set(Some(pk.clone()));
                                let open_key = open.clone();
                                let aria = format!("View profile of {name}");
                                view! {
                                    <div class="bbs-row bbs-member-row" role="button" tabindex="0"
                                        aria-label=aria
                                        on:click=move |_| open()
                                        on:keydown=on_activate(open_key)
                                    >
                                        <span class="accent bbs-chip">"\u{25CF}"</span>
                                        <span class="bbs-member-name">{name}</span>
                                        <span class="bbs-dim bbs-member-id">{format!("#{who}")}</span>
                                    </div>
                                }
                            })
                            .collect_view()}
                    </div>
                }.into_any()
            }
        }}
        {me.map(|id| view! {
            <div class="bbs-panel">"  you: " <span class="accent">{id.did.clone()}</span></div>
        })}
    }
}

/// One member's profile panel (F15): kind-0 name + about + short id, and the
/// resolved did:nostr / WebID. No raster avatar — this is an ASCII surface.
fn member_profile(
    selected: RwSignal<Option<String>>,
    store: RelayStore,
    pod_api: String,
    pubkey: String,
) -> impl IntoView {
    // The member was opened by tap, so their kind-0 (if any) is already loaded.
    let profiles = store.profiles.get_untracked();
    let ev = profiles.iter().find(|e| e.pubkey == pubkey);
    let name = ev
        .map(profile_name)
        .unwrap_or_else(|| relay::short_id(&pubkey));
    let about = ev.and_then(profile_about);
    let short = relay::short_id(&pubkey);
    let id = Identity::derive(&pubkey, &pod_api);
    view! {
        <div class="bbs-panel bbs-crumb">
            <span class="bbs-link accent" role="button" tabindex="0"
                aria-label="Back to members"
                on:click=move |_| selected.set(None)
                on:keydown=on_activate(move || selected.set(None))
            >
                "\u{2190} Members"
            </span>
        </div>
        <div class="bbs-panel bbs-idblock">
            "  \u{25CF} " <span class="accent">{name}</span> "\n"
            {about.map(|a| view! { "\n  " {a} "\n" })}
            "\n  short id : " <span class="bbs-dim">{short}</span> "\n"
            {id.map(|i| view! {
                "  did      : " <span class="accent">{i.did.clone()}</span> "\n"
                "  webid    : " <span class="bbs-dim">{i.webid.clone()}</span>
            }.into_any()).unwrap_or_else(|| view! { "  did      : " <span class="bbs-dim">"(unavailable)"</span> }.into_any())}
        </div>
    }
}

/// (3) Chat — live channel + encrypted DMs.
/// (3) Chat — a live "lobby" tail of recent channel messages (kind-42) across
/// all channels. Posting/threads live in BOARDS; encrypted DMs (NIP-44/59) are a
/// deferred follow-up. Subscribes to the shared kind-42 tail on entry.
fn chat(store: RelayStore) -> impl IntoView {
    relay::subscribe_chat();
    view! {
        {header(Screen::Chat)}
        <div class="bbs-panel bbs-dim">
            "  Recent messages stream here live. Reply or start a topic in BOARDS;\n  open the ✉ DMs tab for private, encrypted (NIP-44/59) threads."
        </div>
        {move || {
            let posts = store.posts.get();
            if posts.is_empty() {
                return view! {
                    <div class="bbs-panel bbs-dim">"  (waiting for live messages — reads are deny-by-default at the relay)"</div>
                }.into_any();
            }
            let profiles = store.profiles.get();
            view! {
                <div class="bbs-list">
                    {posts.into_iter().take(60).map(|p| {
                        let who = author_label(&profiles, &p.pubkey);
                        let body = p.content.clone();
                        let imgs = extract_image_urls(&p.content);
                        view! {
                            <div class="bbs-row"><span class="accent">{format!("<{who}> ")}</span>{body}</div>
                            {imgs.into_iter().map(|src| view! {
                                <div class="bbs-ascii-row"><AsciiImg src=src cols=64 /></div>
                            }).collect_view()}
                        }
                    }).collect_view()}
                </div>
            }.into_any()
        }}
    }
}

/// Sign `unsigned` with `signer`, publish it with an ack, and reflect the
/// outcome into `status`. wasm-only; a native build (unit tests) is a no-op.
fn publish_signed(
    signer: std::rc::Rc<dyn nostr_bbs_core::signer::Signer>,
    unsigned: nostr_bbs_core::UnsignedEvent,
    status: RwSignal<SendStatus>,
) {
    #[cfg(target_arch = "wasm32")]
    {
        wasm_bindgen_futures::spawn_local(async move {
            match signer.sign_event(unsigned).await {
                Ok(signed) => {
                    let on_ok: crate::relay::PublishAck =
                        std::rc::Rc::new(move |accepted: bool, message: String| {
                            if accepted {
                                status.set(SendStatus::Sent);
                            } else {
                                let msg = if message.trim().is_empty() {
                                    "rejected by relay".to_string()
                                } else {
                                    message
                                };
                                status.set(SendStatus::Err(msg));
                            }
                        });
                    crate::relay::publish_with_ack(&signed, Some(on_ok));
                }
                Err(e) => status.set(SendStatus::Err(format!("sign: {e}"))),
            }
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (signer, unsigned);
        status.set(SendStatus::Idle);
    }
}

/// Kick off a NIP-07 browser-extension sign-in (async — the extension may prompt
/// for the pubkey / approval). wasm-only; a native build (unit tests) is a no-op.
/// Failures surface on the signer's `error` signal, which the panel renders.
fn start_extension_login(signer: BbsSigner) {
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(async move {
        let _ = signer.login_with_extension().await;
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = signer;
}

/// F9 — native passkey sign-in. Runs the WebAuthn PRF ceremony on-device and,
/// on success, installs the derived keypair through the SAME path as the
/// generate/paste logins — so no backup sheet follows (the passkey IS the
/// backup). `saved_pubkey` is the adopted forum-session pubkey (if any): when
/// present the login ceremony re-authenticates it, else a fresh passkey is
/// registered on-device. `pending` guards against double-submit and drives the
/// button's "waiting for your passkey" state.
fn start_passkey_login(signer: BbsSigner, saved_pubkey: Option<String>, pending: RwSignal<bool>) {
    #[cfg(target_arch = "wasm32")]
    {
        if pending.get_untracked() {
            return;
        }
        pending.set(true);
        wasm_bindgen_futures::spawn_local(async move {
            match crate::passkey::passkey_sign_in(saved_pubkey).await {
                Ok(outcome) => signer.login_with_passkey(outcome.keypair),
                Err(e) => signer.error().set(Some(e.to_string())),
            }
            pending.set(false);
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (signer, saved_pubkey, pending);
    }
}

/// Context for an interactive (live) agent panel: the signer plus the panel's
/// `d` tag and definition event id, which key the published 31403 ActionResponse
/// (the publishing agent subscribes to responses on its panel `d` tag).
#[derive(Clone)]
struct PanelActionCtx {
    signer: BbsSigner,
    event_id: String,
    d_tag: String,
}

/// One action affordance. On a live panel it signs + publishes a 31403
/// ActionResponse and shows inline status; on a sample panel (`ctx = None`) it is
/// an inert label.
fn action_button(
    a: nostr_bbs_core::governance::ActionDef,
    ctx: Option<PanelActionCtx>,
) -> impl IntoView {
    let mark = match a.style {
        ActionStyle::Primary => "▶",
        ActionStyle::Secondary => "·",
        ActionStyle::Destructive => "✗",
    };
    match ctx {
        None => view! { <span class="accent">"[" {mark} " " {a.label} "] "</span> }.into_any(),
        Some(ctx) => {
            let status = RwSignal::new(SendStatus::Idle);
            let label = a.label.clone();
            let action_id = a.id.clone();
            let on_click = move |_| {
                if matches!(
                    status.get_untracked(),
                    SendStatus::Sending | SendStatus::Sent
                ) {
                    return;
                }
                let pubkey = match ctx.signer.pubkey_hex() {
                    Some(pk) => pk,
                    None => {
                        status.set(SendStatus::Err("sign in first".to_string()));
                        return;
                    }
                };
                let signer_rc = match ctx.signer.get_signer() {
                    Some(s) => s,
                    None => {
                        status.set(SendStatus::Err("sign in first".to_string()));
                        return;
                    }
                };
                let content = serde_json::json!({
                    "action": action_id.clone(),
                    "reasoning": format!(
                        "Human selected '{}' via the BBS agent control plane",
                        action_id
                    ),
                })
                .to_string();
                let now = (js_sys::Date::now() / 1000.0) as u64;
                let unsigned = nostr_bbs_core::UnsignedEvent {
                    pubkey,
                    created_at: now,
                    kind: KIND_ACTION_RESPONSE,
                    tags: vec![
                        vec!["d".to_string(), ctx.d_tag.clone()],
                        vec!["e".to_string(), ctx.event_id.clone()],
                    ],
                    content,
                };
                status.set(SendStatus::Sending);
                publish_signed(signer_rc, unsigned, status);
            };
            view! {
                <span class="bbs-link accent" role="button" on:click=on_click>
                    "[" {mark} " " {label} "]"
                    {move || status.get().suffix()}
                </span>
                " "
            }
            .into_any()
        }
    }
}

/// Render one agent control panel (kit governance schema) in ASCII. With
/// `action = Some`, the action buttons sign + publish a 31403 ActionResponse
/// (the human-in-the-loop decision); on sample panels (`None`) they are inert.
fn panel_view(agent: String, p: PanelDefinition, action: Option<PanelActionCtx>) -> impl IntoView {
    let actions = p.actions.clone();
    view! {
        <div class="bbs-panel">
            "\n  ╓─ " <span class="title">{p.title.clone()}</span>
            <span class="bbs-dim">"  @" {agent} " · " {format!("{:?}", p.schema)} " · ↻" {p.refresh_secs} "s"</span> "\n"
            "  ║ " <span class="bbs-dim">{p.description.clone()}</span> "\n"
            "  ╟─ fields: " {p.fields.iter().map(|f| f.label.clone()).collect::<Vec<_>>().join(" · ")} "\n"
            "  ╙─ "
            {actions
                .into_iter()
                .map(|a| action_button(a, action.clone()))
                .collect_view()}
        </div>
    }
}

/// (1) Agents — agent-governance control panels (live, else samples). This is
/// the headline feature: approve, reject, act — human-in-the-loop.
/// Launch the UA 571-C sentry-gun door game by dispatching the `bbs:sentry` DOM
/// event handled by the overlay script in index.html. Pure client-side, no auth.
/// Reached via the `/sentry` command or the door link on the Help screen — it
/// is an Easter egg, not the headline of this screen.
#[cfg(target_arch = "wasm32")]
pub(crate) fn launch_sentry() {
    if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
        if let Ok(ev) = web_sys::CustomEvent::new("bbs:sentry") {
            let _ = doc.dispatch_event(&ev);
        }
    }
}
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn launch_sentry() {}

fn agents(store: RelayStore) -> impl IntoView {
    let signer = use_context::<BbsSigner>();
    view! {
        {header(Screen::Agents)}
        <div class="bbs-panel bbs-dim">"  Registered agents publish interactive control panels; you sign decisions back."</div>
        {move || match signer.map(|s| s.pubkey().get()) {
            Some(Some(pk)) => view! {
                <div class="bbs-panel bbs-dim">
                    "  signed in as " <span class="accent">{relay::short_id(&pk)}</span>
                    " — decisions are signed back to the relay"
                </div>
            }.into_any(),
            _ => view! {
                <div class="bbs-panel bbs-dim">
                    "  Not signed in — tap " <span class="accent">"Sign in"</span>
                    " on the bottom bar (or Settings, " <span class="accent">"[9]"</span>
                    ") before acting on a panel."
                </div>
            }.into_any(),
        }}
        {move || {
            let live: Vec<(String, String, String, PanelDefinition)> = store
                .governance
                .get()
                .iter()
                .filter_map(|ev| {
                    let p = relay::parse_panel(ev)?;
                    let d = extract_d_tag(&ev.tags)?.to_string();
                    Some((relay::short_id(&ev.pubkey), ev.id.clone(), d, p))
                })
                .collect();
            if !live.is_empty() {
                return live
                    .into_iter()
                    .map(|(agent, event_id, d_tag, p)| {
                        let ctx = signer.map(|s| PanelActionCtx {
                            signer: s,
                            event_id,
                            d_tag,
                        });
                        panel_view(agent, p, ctx)
                    })
                    .collect_view()
                    .into_any();
            }
            // No live governance events yet — representative panels (inert).
            view! {
                <div class="bbs-panel bbs-dim">"  (no live agent panels — showing examples)"</div>
                {sample_panels()
                    .into_iter()
                    .map(|ap| panel_view(ap.agent.to_string(), ap.panel, None))
                    .collect_view()}
            }.into_any()
        }}
    }
}

/// (6) Code — shared snippets / pod files.
/// (6) Code — shared snippets: kind-42 messages that are fenced (```) or tagged
/// `#code` / `t=code`, surfaced from the live tail. Attachments live in the
/// author's Solid pod under /public. Post one from BOARDS. Reads the shared tail.
fn code(store: RelayStore) -> impl IntoView {
    relay::subscribe_chat();
    view! {
        {header(Screen::Code)}
        <div class="bbs-panel bbs-dim">
            "  Signed snippets — kind-42 posts fenced with ``` or tagged #code.\n  Attachments live in the author's Solid pod under /public. Share one from BOARDS."
        </div>
        {move || {
            let snippets: Vec<_> = store
                .posts
                .get()
                .into_iter()
                .filter(|p| {
                    p.content.contains("```")
                        || p.content.to_ascii_lowercase().contains("#code")
                        || p.tags.iter().any(|t| {
                            t.first().map(String::as_str) == Some("t")
                                && t.get(1).map(String::as_str) == Some("code")
                        })
                })
                .collect();
            if snippets.is_empty() {
                return view! {
                    <div class="bbs-panel bbs-dim">"  (no snippets yet — post a ``` fenced message in BOARDS)"</div>
                }.into_any();
            }
            let profiles = store.profiles.get();
            view! {
                <div class="bbs-list">
                    {snippets.into_iter().take(30).map(|p| {
                        let who = author_label(&profiles, &p.pubkey);
                        let body = p.content.clone();
                        view! {
                            <div class="bbs-panel">
                                <span class="bbs-dim">{format!("// {who}")}</span> "\n" {body}
                            </div>
                        }
                    }).collect_view()}
                </div>
            }.into_any()
        }}
    }
}

/// (8) Status — node / relay / pod / identity status (live counts).
fn status(cfg: StoredValue<BbsConfig>, store: RelayStore) -> impl IntoView {
    let (node, loc, relay_url, pod) = cfg.with_value(|c| {
        (
            c.node_name.clone(),
            c.location.clone(),
            c.relay_url.clone(),
            c.pod_api.clone(),
        )
    });
    let id = viewer(cfg);
    let did_line = id
        .as_ref()
        .map(|i| i.did.clone())
        .unwrap_or_else(|| "(not signed in)".into());
    let webid_line = id.map(|i| i.webid).unwrap_or_else(|| "—".into());
    view! {
        {header(Screen::Status)}
        <div class="bbs-panel">
            "  node      : " {node} "\n"
            "  location  : " {loc} "\n"
            "  relay     : " {if relay_url.is_empty() { "—".to_string() } else { relay_url }}
            "  " <span class=move || if store.connected.get() { "accent" } else { "bbs-dim" }>
                {move || if store.connected.get() { "[online]" } else { "[connecting]" }}
            </span> "\n"
            "  pod api   : " {if pod.is_empty() { "—".to_string() } else { pod }} "\n"
            "  identity  : " <span class="accent">{did_line}</span> "\n"
            "  webid     : " {webid_line} "\n"
            "  feeds     : "
            {move || format!("{} boards · {} users · {} agent panels",
                store.channels.get().len(), store.profiles.get().len(), store.governance.get().len())} "\n"
            "  protocol  : Nostr NIP-01/42/44/59/98 · did:nostr Multikey · Solid WAC\n"
            "  build     : nostr-bbs-bbs-client (Leptos CSR/WASM)"
        </div>
    }
}

/// (9) Settings — theme + accessibility prefs + identity + node.
fn settings(state: BbsState, cfg: StoredValue<BbsConfig>) -> impl IntoView {
    let node = cfg.with_value(|c| c.node_name.clone());
    let signer = use_context::<BbsSigner>();
    view! {
        {header(Screen::Settings)}
        <div class="bbs-panel">
            "  theme     : " <span class="accent">{move || state.theme.get().label()}</span> "   "
            <span class="bbs-link" role="button" tabindex="0"
                on:click=move |_| state.theme.update(|t| *t = t.next())
                on:keydown=on_activate(move || state.theme.update(|t| *t = t.next()))
            >"[ cycle (T) ]"</span> "\n"
            "  node      : " {node} "\n"
            "  identity  : keys derived from your passkey (PRF); never persisted server-side\n"
            "  storage   : per-user Solid pod (WAC deny-by-default)"
        </div>
        {a11y_panel(state)}
        {signer.map(sign_in_panel)}
        {install_banner()}
        {forget_device_panel(state, cfg)}
    }
}

/// ADR-109 install affordance. The BBS page carries the manifest + service
/// worker, so it is the surface that captures `beforeinstallprompt` — this button
/// appears **only after** that deferred event lands (`installable` flips, which
/// needs a prior user gesture), never on first paint, and firing it consumes the
/// prompt. wasm-only; the native build renders nothing.
#[cfg(target_arch = "wasm32")]
fn install_banner() -> impl IntoView {
    let installable = crate::pwa::installable();
    view! {
        {move || installable.get().then(|| view! {
            <div class="bbs-panel">
                "  ── install ───────────────────────────────────────\n"
                "  Add this BBS to your home screen for a one-tap, zone-bound app.\n"
                <span class="bbs-link accent bbs-cta" role="button" tabindex="0"
                    aria-label="Install this app to your home screen"
                    on:click=move |_| { wasm_bindgen_futures::spawn_local(async { crate::pwa::prompt_install().await; }); }
                    on:keydown=on_activate(move || { wasm_bindgen_futures::spawn_local(async { crate::pwa::prompt_install().await; }); })
                >"[ \u{25B8} Install to home screen ]"</span>
            </div>
        })}
    }
}

/// Native no-op — the install prompt is browser-only.
#[cfg(not(target_arch = "wasm32"))]
fn install_banner() -> impl IntoView {}

/// ADR-109 "Forget this device" (BBS-owned, Decision 6). Shown when this device
/// carries a bake (a BootProfile is present, or the app booted in pwa mode); it
/// deletes the wrapped key + BootProfile from this origin's storage and signs the
/// in-memory signer out. Local + after-the-fact — the copy states plainly that it
/// cannot protect a phone already in someone else's hands.
fn forget_device_panel(state: BbsState, cfg: StoredValue<BbsConfig>) -> impl IntoView {
    let signer = use_context::<BbsSigner>();
    // Synchronous "is this device baked?" proxy: a stored BootProfile, or a live
    // pwa-mode boot. The authoritative record is the IndexedDB key, cleared below.
    let baked = cfg.with_value(|c| c.boot_profile.is_some()) || state.pwa_mode.get_untracked();
    baked.then(|| {
        view! {
            <div class="bbs-panel">
                "  ── this device ───────────────────────────────────\n"
                <span class="bbs-dim">"  A signing key is saved on this phone so the app opens without a password.\n  'Forget this device' removes the saved key from this phone only \u{2014} it does\n  not protect a phone already in someone else\u{2019}s hands. If it is lost or stolen,\n  tell an admin at once to rotate your key.\n"</span>
                {signer.map(|s| view! {
                    <span class="bbs-link accent bbs-cta" role="button" tabindex="0"
                        aria-label="Forget this device"
                        on:click=move |_| start_forget_device(s, state)
                        on:keydown=on_activate(move || start_forget_device(s, state))
                    >"[ \u{2717} Forget this device ]"</span>
                })}
            </div>
        }
    })
}

/// Confirm, then delete the baked key + BootProfile from this origin and sign
/// out, dropping back out of pwa mode to the main menu. wasm-only.
fn start_forget_device(signer: BbsSigner, state: BbsState) {
    #[cfg(target_arch = "wasm32")]
    {
        let ok = web_sys::window()
            .and_then(|w| {
                w.confirm_with_message(
                    "Forget this device? This removes the saved key from this phone only.",
                )
                .ok()
            })
            .unwrap_or(false);
        if !ok {
            return;
        }
        wasm_bindgen_futures::spawn_local(async move {
            crate::pwa::forget_device().await;
            signer.logout();
            state.pwa_mode.set(false);
            state.pinned_zone.set(None);
            state.go(Screen::MainMenu);
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (signer, state);
}

/// Accessibility / density preferences (F13): text size + reduced motion. Both
/// persist to localStorage and apply as classes on the document root (see
/// `app::apply_prefs`); reduced motion defaults to the OS `prefers-reduced-motion`.
fn a11y_panel(state: BbsState) -> impl IntoView {
    view! {
        <div class="bbs-panel">
            "  ── accessibility ──────────────────────────────────\n"
            "  text size : "
            {toggle(
                "normal",
                move || !state.text_large.get(),
                move || state.text_large.set(false),
            )}
            " "
            {toggle(
                "large",
                move || state.text_large.get(),
                move || state.text_large.set(true),
            )}
            "\n"
            "  motion    : "
            {toggle(
                "full",
                move || !state.reduced_motion.get(),
                move || state.reduced_motion.set(false),
            )}
            " "
            {toggle(
                "reduced",
                move || state.reduced_motion.get(),
                move || state.reduced_motion.set(true),
            )}
        </div>
    }
}

/// A small `[ label ]` segmented toggle: highlighted (accent) when `active`,
/// keyboard- and tap-operable, invoking `set` to select this option.
fn toggle(
    label: &'static str,
    active: impl Fn() -> bool + Copy + Send + 'static,
    set: impl Fn() + Clone + 'static,
) -> impl IntoView {
    let set_key = set.clone();
    view! {
        <span
            class="bbs-toggle"
            class:active=active
            role="button"
            tabindex="0"
            attr:aria-pressed=move || if active() { "true" } else { "false" }
            on:click=move |_| set()
            on:keydown=on_activate(set_key)
        >
            "[ " {label} " ]"
        </span>
    }
}

/// Copy `text` to the clipboard (wasm). Best-effort via `navigator.clipboard.
/// writeText`, reached reflectively through `js_sys` so no extra `web-sys`
/// feature is needed; the returned promise and any failure are ignored (the hex
/// stays on screen to copy by hand).
#[cfg(target_arch = "wasm32")]
fn copy_to_clipboard(text: &str) {
    use wasm_bindgen::{JsCast, JsValue};
    let win = match web_sys::window() {
        Some(w) => w,
        None => return,
    };
    let nav = match js_sys::Reflect::get(&win, &JsValue::from_str("navigator")) {
        Ok(n) if !n.is_undefined() && !n.is_null() => n,
        _ => return,
    };
    let clip = match js_sys::Reflect::get(&nav, &JsValue::from_str("clipboard")) {
        Ok(c) if !c.is_undefined() && !c.is_null() => c,
        _ => return,
    };
    if let Ok(func) = js_sys::Reflect::get(&clip, &JsValue::from_str("writeText")) {
        if let Ok(f) = func.dyn_into::<js_sys::Function>() {
            let _ = f.call1(&clip, &JsValue::from_str(text));
        }
    }
}
#[cfg(not(target_arch = "wasm32"))]
fn copy_to_clipboard(_text: &str) {}

/// One-time key-backup sheet (F14): the secret shown once as nsec + hex, each
/// with a copy control, a blunt "no reset / no recovery" warning, and a
/// "written it down" confirm that dismisses the sheet. The BBS never persists a
/// generated/pasted key, so this is the only chance to save it.
fn backup_sheet(secret_hex: String, dismiss: impl Fn() + Clone + 'static) -> impl IntoView {
    let nsec = nostr_bbs_core::encode_nsec(&secret_hex).unwrap_or_default();
    let nsec_click = nsec.clone();
    let nsec_key = nsec.clone();
    let hex_click = secret_hex.clone();
    let hex_key = secret_hex.clone();
    let dismiss_key = dismiss.clone();
    view! {
        <div class="bbs-panel bbs-backup">
            <div class="bbs-backup-warn">"  \u{26A0} This key IS your account. There is no reset and no recovery \u{2014}\n  if you lose it the identity is gone. Save it now, offline."</div>
            <div class="bbs-signin-backup">
                "  nsec : " <span class="accent">{nsec}</span> "  "
                <span class="bbs-link" role="button" tabindex="0"
                    on:click=move |_| copy_to_clipboard(&nsec_click)
                    on:keydown=on_activate(move || copy_to_clipboard(&nsec_key))
                >"[ copy ]"</span>
            </div>
            <div class="bbs-signin-backup">
                "  hex  : " <span class="accent">{secret_hex}</span> "  "
                <span class="bbs-link" role="button" tabindex="0"
                    on:click=move |_| copy_to_clipboard(&hex_click)
                    on:keydown=on_activate(move || copy_to_clipboard(&hex_key))
                >"[ copy ]"</span>
            </div>
            <span class="bbs-link accent bbs-cta" role="button" tabindex="0"
                on:click=move |_| dismiss()
                on:keydown=on_activate(dismiss_key)
            >"[ \u{2713} I\u{2019}ve written it down ]"</span>
        </div>
    }
}

/// The BBS sign-in panel — a **vertical stack** of full-width, ≥44 px options in
/// priority order, so it works on a phone with no browser extension:
///   1. Sign in with extension (only when a NIP-07 provider is present)
///   2. Continue at /community/ (always — the extension-free primary path; the
///      adopted session carries back same-origin)
///   3. Paste an nsec / hex key (own full-width row) → Sign in
///   4. Generate a throwaway key → the F14 backup sheet (nsec + hex, shown once)
///
/// Signed in with a local key, a "Back up my key" control re-opens that sheet;
/// the key lives in memory only and the forum's same-origin local-key session is
/// adopted at load.
fn sign_in_panel(signer: BbsSigner) -> impl IntoView {
    let key_input = RwSignal::new(String::new());
    let generated = RwSignal::new(None::<String>);
    // Toggles the backup sheet for a signed-in local key.
    let show_backup = RwSignal::new(false);
    // F9: pending flag for the native passkey ceremony (biometric + round-trips).
    let passkey_pending = RwSignal::new(false);
    // Returning users carry a pubkey from the adopted forum session; when present
    // the passkey ceremony re-authenticates it, else it registers a new credential.
    let saved_pubkey = use_context::<StoredValue<BbsConfig>>()
        .and_then(|cfg| cfg.with_value(|c| c.viewer_pubkey.clone()));
    view! {
        <div class="bbs-panel">
            "  ── identity / sign-in ─────────────────────────────\n"
            {move || match signer.pubkey().get() {
                Some(pk) => {
                    // A readable local secret (adopted/pasted forum key) can be
                    // backed up here; a NIP-07 session exposes none, so no sheet.
                    let backup = signer.local_secret_hex();
                    view! {
                        "  signed in : " <span class="accent">{relay::short_id(&pk)}</span> "   "
                        <span class="bbs-link" role="button" tabindex="0"
                            on:click=move |_| { signer.logout(); generated.set(None); show_backup.set(false); }
                            on:keydown=on_activate(move || { signer.logout(); generated.set(None); show_backup.set(false); })
                        >"[ sign out ]"</span> "\n"
                        "  board posts & agent decisions are signed with this key (in memory only)\n"
                        {backup.clone().map(|_| view! {
                            <span class="bbs-link accent bbs-cta" role="button" tabindex="0"
                                on:click=move |_| show_backup.update(|b| *b = !*b)
                                on:keydown=on_activate(move || show_backup.update(|b| *b = !*b))
                            >"[ \u{25B8} Back up my key ]"</span>
                        })}
                        {move || if show_backup.get() {
                            backup.clone().map(|hex| backup_sheet(hex, move || show_backup.set(false)).into_any())
                        } else {
                            None
                        }}
                    }.into_any()
                }
                None => {
                    let login = move || {
                        let input = key_input.get_untracked();
                        if signer.login_with_key(&input).is_ok() {
                            key_input.set(String::new());
                            generated.set(None);
                        }
                    };
                    let login_key = login;
                    // Only offered when a NIP-07 provider (PodKey / nos2x / Alby)
                    // is present; signs via the extension with no key exposure.
                    let ext_available = crate::nip07::has_nip07_extension();
                    view! {
                        <div class="bbs-signin">
                            {ext_available.then(|| view! {
                                <span class="bbs-dim">"  Browser signer detected — signs with no key exposure:"</span>
                                <span class="bbs-link accent bbs-cta" role="button" tabindex="0"
                                    on:click=move |_| start_extension_login(signer)
                                    on:keydown=on_activate(move || start_extension_login(signer))
                                >"[ \u{25B8} Sign in with extension ]"</span>
                            })}
                            {crate::passkey::is_passkey_supported().then(|| {
                                let sp = saved_pubkey.clone();
                                let sp_key = saved_pubkey.clone();
                                view! {
                                    <span class="bbs-dim">"  Sign in with a passkey \u{2014} Face ID / Touch ID / fingerprint, no key to paste:"</span>
                                    <span class="bbs-link accent bbs-cta" role="button" tabindex="0"
                                        class:bbs-pending=move || passkey_pending.get()
                                        on:click=move |_| start_passkey_login(signer, sp.clone(), passkey_pending)
                                        on:keydown=on_activate(move || start_passkey_login(signer, sp_key.clone(), passkey_pending))
                                    >{move || if passkey_pending.get() {
                                        "[ \u{2026} waiting for your passkey ]"
                                    } else {
                                        "[ \u{25B8} Sign in with a passkey ]"
                                    }}</span>
                                }
                            })}
                            <span class="bbs-dim">"  Or continue at /community/ (opens the forum sign-in) \u{2014} works without a passkey:"</span>
                            <a class="bbs-link accent bbs-cta" href="../" rel="noopener"
                            >"[ \u{25B8} Continue at /community/ \u{2197} ]"</a>
                            <label class="bbs-dim" for="bbs-signin-key">"  Or paste an nsec / 64-char hex key:"</label>
                            <input
                                id="bbs-signin-key"
                                name="bbs-signin-key"
                                class="bbs-key"
                                autocomplete="off"
                                autocapitalize="none"
                                spellcheck="false"
                                placeholder="nsec1… or 64-char hex"
                                prop:value=move || key_input.get()
                                on:input=move |ev| key_input.set(event_target_value(&ev))
                                on:keydown=move |ev| { if ev.key() == "Enter" { ev.prevent_default(); login(); } }
                            />
                            <span class="bbs-link accent bbs-cta" role="button" tabindex="0"
                                on:click=move |_| login()
                                on:keydown=on_activate(login_key)
                            >"[ \u{25B8} Sign in ]"</span>
                            <span class="bbs-link bbs-cta" role="button" tabindex="0"
                                on:click=move |_| { if let Ok(hex) = signer.generate() { generated.set(Some(hex)); } }
                                on:keydown=on_activate(move || { if let Ok(hex) = signer.generate() { generated.set(Some(hex)); } })
                            >"[ Generate a throwaway key ]"</span>
                        </div>
                        {move || signer.error().get().map(|e| view! { <div class="bbs-dim">"  ✗ " {e}</div> })}
                    }.into_any()
                }
            }}
            // The one-time backup sheet for a freshly generated throwaway key lives
            // OUTSIDE the signed-in/out match: `generate()` installs the key and sets
            // the pubkey synchronously, so the signed-OUT arm (and anything nested in
            // it) is torn down the instant the key is created. Rendered here as a
            // sibling of the match, it survives that flip and shows the shown-once
            // nsec/hex + copy + confirm (F14). `generate()` deliberately never
            // persists the key, so this sheet is the only chance to save it.
            {move || generated.get().map(|hex| backup_sheet(hex, move || generated.set(None)).into_any())}
        </div>
    }
}

/// (0) Help — about the kit.
fn help() -> impl IntoView {
    view! {
        {header(Screen::Help)}
        <div class="bbs-panel">
            "  This is the retro terminal face of a Nostr + Solid community forum.\n\n"
            "  • Agents are control panels: software agents publish interactive panels\n"
            "    and you sign human decisions back — approve, reject, act.\n"
            "  • Boards are zone-gated channels with cohort-gated reads, enforced\n"
            "    deny-by-default at the relay.\n"
            "  • Pod is your own Solid pod — WebID-owned, WAC-controlled, git-clonable.\n"
            "  • Identity is a did:nostr Multikey DID; your key never leaves the device.\n\n"
            "  Tap the bottom bar to move around; tap a zone, then a board, to read it.\n"
            "  Power users: number keys jump to a screen, / opens the command line,\n"
            "  ESC steps back, T cycles the theme, ? opens Help.\n\n"
            "  • A door stands ajar… "
            <span class="bbs-link" on:click=move |_| launch_sentry()>
                "[ \u{25B6} UA 571-C SENTRY ]"
            </span>
        </div>
    }
}

/// ADR-109 iOS first-launch **rebind** — reached only during a PWA boot when no
/// baked key exists in this (isolated) installed-app bucket. It re-establishes
/// the SAME identity once (passkey PRF, or a one-time recovery-key paste), then
/// the caller re-bakes locally so subsequent launches are one-shot. Passkey vs
/// paste is chosen by [`crate::pwa::rebind_path`]: passkeys live in the OS
/// keychain (not per-origin storage), so a passkey path needs a known pubkey to
/// authenticate against; without one we fall back to paste.
fn rebind(state: BbsState, cfg: StoredValue<BbsConfig>) -> impl IntoView {
    let signer = use_context::<BbsSigner>().expect("signer");
    let saved_pubkey = cfg.with_value(|c| c.viewer_pubkey.clone());
    // "Has passkey" = passkey support AND a pubkey to authenticate against
    // (`passkey_authenticate` needs it — there is no discovery oracle).
    let has_passkey = crate::passkey::is_passkey_supported() && saved_pubkey.is_some();
    let key_input = RwSignal::new(String::new());
    let pending = RwSignal::new(false);
    let body = match crate::pwa::rebind_path(has_passkey) {
        crate::pwa::RebindPath::Passkey => {
            rebind_passkey_view(signer, cfg, state, saved_pubkey, pending).into_any()
        }
        crate::pwa::RebindPath::PasteRecoveryKey => {
            rebind_paste_view(signer, cfg, state, key_input).into_any()
        }
    };
    view! {
        {header(Screen::Rebind)}
        <div class="bbs-panel bbs-dim">
            "  This device needs to re-link once. Your identity is re-created here on this\n  device \u{2014} nothing is transferred. After this, the app opens straight into your\n  zone."
        </div>
        {body}
        {move || signer.error().get().map(|e| view! { <div class="bbs-dim">"  \u{2717} " {e}</div> })}
    }
}

/// Passkey rebind: a single "Unlock with passkey" tap re-derives the identical
/// key via WebAuthn PRF (iOS 17.4+ needs no gesture, but a tap is fine).
fn rebind_passkey_view(
    signer: BbsSigner,
    cfg: StoredValue<BbsConfig>,
    state: BbsState,
    saved_pubkey: Option<String>,
    pending: RwSignal<bool>,
) -> impl IntoView {
    view! {
        <div class="bbs-signin">
            <span class="bbs-dim">"  Unlock with your passkey \u{2014} Face ID / Touch ID / fingerprint. This\n  re-creates the same identity on this device; nothing is transferred."</span>
            <span class="bbs-link accent bbs-cta" role="button" tabindex="0"
                class:bbs-pending=move || pending.get()
                on:click={
                    let sp = saved_pubkey.clone();
                    move |_| start_rebind_passkey(signer, cfg, state, sp.clone(), pending)
                }
                on:keydown={
                    let sp = saved_pubkey.clone();
                    on_activate(move || start_rebind_passkey(signer, cfg, state, sp.clone(), pending))
                }
            >{move || if pending.get() {
                "[ \u{2026} waiting for your passkey ]"
            } else {
                "[ \u{25B8} Unlock with passkey ]"
            }}</span>
        </div>
    }
}

/// Paste rebind: paste the nsec / hex recovery key once; the caller installs it
/// and re-bakes it into this app's isolated storage so later launches are
/// one-shot.
fn rebind_paste_view(
    signer: BbsSigner,
    cfg: StoredValue<BbsConfig>,
    state: BbsState,
    key_input: RwSignal<String>,
) -> impl IntoView {
    let submit = move || start_rebind_paste(signer, cfg, state, key_input);
    view! {
        <div class="bbs-signin">
            <label class="bbs-dim" for="bbs-rebind-key">"  Paste your nsec / 64-char hex key once to re-link this device:"</label>
            <input
                id="bbs-rebind-key"
                name="bbs-rebind-key"
                class="bbs-key"
                autocomplete="off"
                autocapitalize="none"
                spellcheck="false"
                placeholder="nsec1… or 64-char hex"
                prop:value=move || key_input.get()
                on:input=move |ev| key_input.set(event_target_value(&ev))
                on:keydown=move |ev| { if ev.key() == "Enter" { ev.prevent_default(); submit(); } }
            />
            <span class="bbs-link accent bbs-cta" role="button" tabindex="0"
                on:click=move |_| submit()
                on:keydown=on_activate(submit)
            >"[ \u{25B8} Re-link this device ]"</span>
        </div>
    }
}

/// Run the passkey rebind ceremony, then re-bake + pin. wasm-only. `pubkey` is
/// the identity to re-authenticate (the Passkey path is only chosen when it is
/// `Some`; an empty pubkey makes `passkey_authenticate` fail closed).
fn start_rebind_passkey(
    signer: BbsSigner,
    cfg: StoredValue<BbsConfig>,
    state: BbsState,
    pubkey: Option<String>,
    pending: RwSignal<bool>,
) {
    #[cfg(target_arch = "wasm32")]
    {
        if pending.get_untracked() {
            return;
        }
        pending.set(true);
        let pubkey = pubkey.unwrap_or_default();
        let (boot_profile, zones) = cfg.with_value(|c| (c.boot_profile.clone(), c.zones.clone()));
        wasm_bindgen_futures::spawn_local(async move {
            match crate::passkey::passkey_authenticate(&pubkey).await {
                Ok(outcome) => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(outcome.keypair.secret.as_bytes());
                    let sk = zeroize::Zeroizing::new(arr);
                    {
                        use zeroize::Zeroize;
                        arr.zeroize();
                    }
                    signer.login_with_passkey(outcome.keypair);
                    complete_rebind(state, &boot_profile, &zones, &sk).await;
                }
                Err(e) => signer.error().set(Some(e.to_string())),
            }
            pending.set(false);
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (signer, cfg, state, pubkey, pending);
}

/// Parse the pasted recovery key, install it, then re-bake + pin. wasm-only.
fn start_rebind_paste(
    signer: BbsSigner,
    cfg: StoredValue<BbsConfig>,
    state: BbsState,
    key_input: RwSignal<String>,
) {
    #[cfg(target_arch = "wasm32")]
    {
        let input = key_input.get_untracked();
        match crate::signer::parse_secret_key(&input) {
            Ok(keypair) => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(keypair.secret.as_bytes());
                let sk = zeroize::Zeroizing::new(arr);
                {
                    use zeroize::Zeroize;
                    arr.zeroize();
                }
                // Install the identity in memory (the passkey/local path — the
                // BBS never persists a plaintext key; the durable copy is the
                // re-bake below).
                signer.login_with_passkey(keypair);
                key_input.set(String::new());
                let (boot_profile, zones) =
                    cfg.with_value(|c| (c.boot_profile.clone(), c.zones.clone()));
                wasm_bindgen_futures::spawn_local(async move {
                    complete_rebind(state, &boot_profile, &zones, &sk).await;
                });
            }
            Err(e) => signer.error().set(Some(e)),
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (signer, cfg, state, key_input);
}

/// After a successful rebind sign-in: resolve the bound zone (exact from a
/// BootProfile, else the sole locked zone), re-bake the secret into THIS app's
/// isolated storage so subsequent launches are one-shot, and enter the pinned
/// zone. When the zone is ambiguous the sign-in still stands, but there is no
/// one-shot pin — land on the main menu. wasm-only.
#[cfg(target_arch = "wasm32")]
async fn complete_rebind(
    state: BbsState,
    boot_profile: &Option<nostr_bbs_core::BootProfile>,
    zones: &[nostr_bbs_config::schema::Zone],
    secret: &[u8; 32],
) {
    match crate::pwa::resolve_boot_zone_index(boot_profile, zones) {
        Some(idx) => {
            let zone_id = zones[idx].id.clone();
            if let Err(e) = crate::pwa::bake_local(secret, &zone_id).await {
                web_sys::console::warn_1(&format!("[bbs-pwa] local re-bake failed: {e:?}").into());
            }
            state.enter_pwa(idx);
        }
        None => state.go(Screen::MainMenu),
    }
}
