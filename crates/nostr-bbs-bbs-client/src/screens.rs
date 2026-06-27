//! The ten BBS screens. Each maps to a real kit capability and reuses the kit's
//! own types (`nostr_bbs_config::Zone`, `nostr_bbs_core::governance`,
//! `nostr_bbs_core::did` / `solid_pod_rs::webid`). Live relay/pod loading is the
//! next layer; these views render the structure + any config-injected data now.

use leptos::prelude::*;

use crate::agent::sample_panels;
use crate::chrome::BbsState;
use crate::config::BbsConfig;
use crate::identity::Identity;
use crate::menu::Screen;
use nostr_bbs_config::schema::ZoneVisibility;
use nostr_bbs_core::governance::ActionStyle;

/// Render the active screen.
#[component]
pub fn ScreenView(state: BbsState) -> impl IntoView {
    let cfg = use_context::<StoredValue<BbsConfig>>().expect("config");
    move || match state.screen.get() {
        Screen::MainMenu => view! { <crate::chrome::MainMenu state=state /> }.into_any(),
        Screen::MessageBase => message_base(state, cfg).into_any(),
        Screen::FileBase => file_base(cfg).into_any(),
        Screen::NodeList => node_list(cfg).into_any(),
        Screen::UserList => user_list(cfg).into_any(),
        Screen::Chat => chat(cfg).into_any(),
        Screen::DoorGames => door_games().into_any(),
        Screen::CodeExchange => code_exchange().into_any(),
        Screen::SystemInfo => system_info(cfg).into_any(),
        Screen::Settings => settings(state, cfg).into_any(),
        Screen::Help => help().into_any(),
    }
}

/// Shared screen header.
fn header(screen: Screen) -> impl IntoView {
    view! {
        <div class="bbs-panel">
            <span class="title">"┌─ " {screen.title()} " ─────────────────────────────"</span>
            "\n  " <span class="bbs-dim">{screen.subtitle()}</span>
            "\n"
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

/// (1) Message Base — zones/boards from forum.toml, zone-gated kind-40/42.
fn message_base(state: BbsState, cfg: StoredValue<BbsConfig>) -> impl IntoView {
    let zones = cfg.with_value(|c| c.zones.clone());
    let empty = zones.is_empty();
    view! {
        {header(Screen::MessageBase)}
        <Show
            when=move || !empty
            fallback=|| view! {
                <div class="bbs-panel bbs-dim">
                    "  No zones configured. Define [[zones]] in forum.toml — each becomes a board\n  with cohort-gated read access enforced by the relay."
                </div>
            }
        >
            <div class="bbs-list">
                {zones
                    .clone()
                    .into_iter()
                    .enumerate()
                    .map(|(i, z)| {
                        let accent = z.accent_hex.clone().unwrap_or_default();
                        let vis = match z.visibility {
                            ZoneVisibility::Public => "public",
                            ZoneVisibility::Locked => "locked",
                            ZoneVisibility::Hidden => "hidden",
                        };
                        let cohorts = if z.required_cohorts.is_empty() {
                            "open".to_string()
                        } else {
                            z.required_cohorts.join(",")
                        };
                        let name = z.display_name.clone();
                        let style = if accent.is_empty() {
                            String::new()
                        } else {
                            format!("--accent:{accent}")
                        };
                        let selected = move || state.selection.get() == i;
                        view! {
                            <div class="bbs-row" class:selected=selected style=style>
                                <span class="accent">"▓ "</span>
                                {format!("{name:<22}")}
                                <span class="bbs-dim">{format!(" [{vis}] read: {cohorts}")}</span>
                            </div>
                        }
                    })
                    .collect_view()}
            </div>
        </Show>
        <div class="bbs-panel bbs-dim">"  ↑↓ select · ENTER open board · zone reads are deny-by-default at the relay"</div>
    }
}

/// (2) File Base — the Solid pod browser (WebID-owned storage).
fn file_base(cfg: StoredValue<BbsConfig>) -> impl IntoView {
    let id = viewer(cfg);
    view! {
        {header(Screen::FileBase)}
        {match id {
            Some(id) => view! {
                <div class="bbs-panel">
                    "  WebID    : " <span class="accent">{id.webid.clone()}</span> "\n"
                    "  pod-git  : " {id.git_clone.clone()} "\n\n"
                    "  /" {id.short()} "/\n"
                    "    ├── inbox/        " <span class="bbs-dim">"(append-only; agents post here)"</span> "\n"
                    "    ├── public/       " <span class="bbs-dim">"(world-readable, nosniff+sandbox)"</span> "\n"
                    "    ├── profile/card  " <span class="bbs-dim">"(WebID document)"</span> "\n"
                    "    └── private/      " <span class="bbs-dim">"(WAC deny-by-default)"</span>
                </div>
            }.into_any(),
            None => view! {
                <div class="bbs-panel bbs-dim">
                    "  Sign in to browse your Solid pod. Each account owns a WebID pod with\n  WAC deny-by-default access control and a git-clonable history."
                </div>
            }.into_any(),
        }}
    }
}

/// (3) Node List — relay + federation mesh.
fn node_list(cfg: StoredValue<BbsConfig>) -> impl IntoView {
    let (relay, pod) = cfg.with_value(|c| (c.relay_url.clone(), c.pod_api.clone()));
    let relay_disp = if relay.is_empty() {
        "(not configured)".into()
    } else {
        relay
    };
    let pod_disp = if pod.is_empty() {
        "(not configured)".into()
    } else {
        pod
    };
    view! {
        {header(Screen::NodeList)}
        <div class="bbs-list">
            <div class="bbs-row"><span class="accent">"◆ "</span>"relay   " <span class="bbs-dim">{relay_disp}</span></div>
            <div class="bbs-row"><span class="accent">"◆ "</span>"pod     " <span class="bbs-dim">{pod_disp}</span></div>
            <div class="bbs-row"><span class="accent">"◆ "</span>"mesh    " <span class="bbs-dim">"federation peers load from [mesh].peer_relays (wss:// only)"</span></div>
        </div>
    }
}

/// (4) User List — members as did:nostr WebID profiles.
fn user_list(cfg: StoredValue<BbsConfig>) -> impl IntoView {
    let id = viewer(cfg);
    view! {
        {header(Screen::UserList)}
        {match id {
            Some(id) => view! {
                <div class="bbs-list">
                    <div class="bbs-row">
                        <span class="accent">"● "</span> {id.short()}
                        <span class="bbs-dim">"  " {id.did.clone()} "  (you)"</span>
                    </div>
                </div>
            }.into_any(),
            None => view! { <div class="bbs-panel bbs-dim">"  Member roster loads from the relay. Each member is a did:nostr identity\n  with a WebID profile; private keys never leave the device."</div> }.into_any(),
        }}
    }
}

/// (5) Chat — live channel + encrypted DMs.
fn chat(_cfg: StoredValue<BbsConfig>) -> impl IntoView {
    view! {
        {header(Screen::Chat)}
        <div class="bbs-panel bbs-dim">
            "  Live channel posts (kind-42) and gift-wrapped DMs (NIP-44/59) stream over\n  the relay. AUTH (NIP-42) gates sealed DMs to the addressed recipient.\n\n  > _"
        </div>
    }
}

/// (6) Door Games — agent-governance control panels (human-in-the-loop).
fn door_games() -> impl IntoView {
    view! {
        {header(Screen::DoorGames)}
        <div class="bbs-panel bbs-dim">"  Registered agents publish interactive control panels; you sign decisions back."</div>
        {sample_panels()
            .into_iter()
            .map(|ap| {
                let p = ap.panel;
                view! {
                    <div class="bbs-panel">
                        "\n  ╓─ " <span class="title">{p.title.clone()}</span>
                        <span class="bbs-dim">"  @" {ap.agent} " · " {format!("{:?}", p.schema)} " · ↻" {p.refresh_secs} "s"</span> "\n"
                        "  ║ " <span class="bbs-dim">{p.description.clone()}</span> "\n"
                        "  ╟─ fields: " {p.fields.iter().map(|f| f.label.clone()).collect::<Vec<_>>().join(" · ")} "\n"
                        "  ╙─ "
                        {p.actions
                            .into_iter()
                            .map(|a| {
                                let mark = match a.style {
                                    ActionStyle::Primary => "▶",
                                    ActionStyle::Secondary => "·",
                                    ActionStyle::Destructive => "✗",
                                };
                                view! { <span class="accent">"[" {mark} " " {a.label} "] "</span> }
                            })
                            .collect_view()}
                    </div>
                }
            })
            .collect_view()}
    }
}

/// (7) Code Exchange — shared snippets / pod files.
fn code_exchange() -> impl IntoView {
    view! {
        {header(Screen::CodeExchange)}
        <div class="bbs-panel bbs-dim">"  Shared code snippets and pod-hosted files. Posts are signed Nostr events;\n  attachments live in the author's Solid pod under /public."</div>
    }
}

/// (8) System Info — node / relay / pod / identity status.
fn system_info(cfg: StoredValue<BbsConfig>) -> impl IntoView {
    let (node, loc, relay, pod) = cfg.with_value(|c| {
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
        {header(Screen::SystemInfo)}
        <div class="bbs-panel">
            "  node      : " {node} "\n"
            "  location  : " {loc} "\n"
            "  relay     : " {if relay.is_empty() { "—".into() } else { relay }} "\n"
            "  pod api   : " {if pod.is_empty() { "—".into() } else { pod }} "\n"
            "  identity  : " <span class="accent">{did_line}</span> "\n"
            "  webid     : " {webid_line} "\n"
            "  protocol  : Nostr NIP-01/42/44/59/98 · did:nostr Multikey · Solid WAC\n"
            "  governance: agent control-panel plane online (kind-3091x)\n"
            "  build     : nostr-bbs-bbs-client (Leptos CSR/WASM)"
        </div>
    }
}

/// (9) Settings — theme + identity + node.
fn settings(state: BbsState, cfg: StoredValue<BbsConfig>) -> impl IntoView {
    let node = cfg.with_value(|c| c.node_name.clone());
    view! {
        {header(Screen::Settings)}
        <div class="bbs-panel">
            "  theme     : " <span class="accent">{move || state.theme.get().label()}</span>
            "   "
            <span class="bbs-link" on:click=move |_| state.theme.update(|t| *t = t.next())>"[ cycle (T) ]"</span> "\n"
            "  node      : " {node} "\n"
            "  identity  : keys derived from your passkey (PRF); never persisted server-side\n"
            "  storage   : per-user Solid pod (WAC deny-by-default)"
        </div>
    }
}

/// (10) Help — about the kit.
fn help() -> impl IntoView {
    view! {
        {header(Screen::Help)}
        <div class="bbs-panel">
            "  This is the retro terminal face of a Nostr + Solid community forum.\n\n"
            "  • Boards (Message Base) are config-driven zones with cohort-gated reads,\n"
            "    enforced deny-by-default at the relay.\n"
            "  • Files (File Base) are your own Solid pod — WebID-owned, WAC-controlled,\n"
            "    git-clonable.\n"
            "  • Door Games are agent control panels: software agents publish interactive\n"
            "    panels and you sign human decisions back (the governance plane).\n"
            "  • Identity is a did:nostr Multikey DID; your key never leaves the device.\n\n"
            "  Keys: number to open a board · / for commands · ESC back · T theme · 0 help"
        </div>
    }
}
