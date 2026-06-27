//! The ten BBS screens. Each maps to a real kit capability and reuses the kit's
//! own types (`nostr_bbs_config::Zone`, `nostr_bbs_core::governance`,
//! `nostr_bbs_core::did` / `solid_pod_rs::webid`) and live relay data
//! ([`RelayStore`]). Message Base, User List, and Door Games stream from the
//! relay; the pod browser surfaces the WebID/pod URLs.

use leptos::prelude::*;

use crate::agent::sample_panels;
use crate::chrome::{BbsState, MainMenu};
use crate::config::BbsConfig;
use crate::identity::Identity;
use crate::menu::Screen;
use crate::pod::PodState;
use crate::relay::{self, RelayStore};
use nostr_bbs_core::governance::{ActionStyle, PanelDefinition};

/// Render the active screen.
#[component]
pub fn ScreenView(state: BbsState) -> impl IntoView {
    let cfg = use_context::<StoredValue<BbsConfig>>().expect("config");
    let store = use_context::<RelayStore>().expect("relay");
    move || match state.screen.get() {
        Screen::MainMenu => view! { <MainMenu state=state /> }.into_any(),
        Screen::MessageBase => message_base(state, store, cfg).into_any(),
        Screen::FileBase => file_base(cfg).into_any(),
        Screen::NodeList => node_list(cfg, store).into_any(),
        Screen::UserList => user_list(store, cfg).into_any(),
        Screen::Chat => chat().into_any(),
        Screen::DoorGames => door_games(store).into_any(),
        Screen::CodeExchange => code_exchange().into_any(),
        Screen::SystemInfo => system_info(cfg, store).into_any(),
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

/// Look up a zone's accent colour by id (for board tinting).
fn zone_accent(cfg: StoredValue<BbsConfig>, zone: &str) -> Option<String> {
    cfg.with_value(|c| {
        c.zones
            .iter()
            .find(|z| z.id == zone)
            .and_then(|z| z.accent_hex.clone())
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

/// (1) Message Base — live boards (kind-40) → posts (kind-42), zone-gated.
fn message_base(state: BbsState, store: RelayStore, cfg: StoredValue<BbsConfig>) -> impl IntoView {
    view! {
        {header(Screen::MessageBase)}
        {move || match state.board.get() {
            None => board_list(state, store, cfg).into_any(),
            Some(id) => board_posts(store, id).into_any(),
        }}
    }
}

fn board_list(state: BbsState, store: RelayStore, cfg: StoredValue<BbsConfig>) -> impl IntoView {
    view! {
        {move || {
            let chans = store.channels.get();
            if chans.is_empty() {
                return view! {
                    <div class="bbs-panel bbs-dim">
                        "  No boards yet. Channels (kind-40) appear here as they arrive from the\n  relay; each is a zone-gated board. Define [[zones]] in forum.toml to theme them."
                    </div>
                }.into_any();
            }
            view! {
                <div class="bbs-list">
                    {chans
                        .into_iter()
                        .enumerate()
                        .map(|(i, ev)| {
                            let name = relay::channel_name(&ev);
                            let zone = relay::channel_zone(&ev).unwrap_or_default();
                            let accent = zone_accent(cfg, &zone).unwrap_or_default();
                            let style = if accent.is_empty() {
                                String::new()
                            } else {
                                format!("--accent:{accent}")
                            };
                            let selected = move || state.selection.get() == i;
                            view! {
                                <div class="bbs-row" class:selected=selected style=style>
                                    <span class="accent">"▓ "</span>
                                    {format!("{name:<24}")}
                                    <span class="bbs-dim">
                                        {if zone.is_empty() { String::new() } else { format!(" @{zone}") }}
                                    </span>
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
                <div class="bbs-panel bbs-dim">"  ↑↓ select · ENTER open board · reads are deny-by-default at the relay"</div>
            }.into_any()
        }}
    }
}

fn board_posts(store: RelayStore, channel_id: String) -> impl IntoView {
    view! {
        <div class="bbs-panel">
            "  board " <span class="accent">{relay::short_id(&channel_id)}</span>
            <span class="bbs-dim">"   [ESC] back to boards"</span> "\n"
        </div>
        {move || {
            let cid = channel_id.clone();
            let posts: Vec<_> = store
                .posts
                .get()
                .into_iter()
                .filter(|p| relay::post_root_channel(p).as_deref() == Some(cid.as_str()))
                .collect();
            if posts.is_empty() {
                return view! { <div class="bbs-panel bbs-dim">"  (no messages yet — or you lack read access to this zone)"</div> }.into_any();
            }
            view! {
                <div class="bbs-list">
                    {posts
                        .into_iter()
                        .map(|p| {
                            let who = relay::short_id(&p.pubkey);
                            let body = p.content.clone();
                            view! {
                                <div class="bbs-row">
                                    <span class="accent">{format!("<{who}> ")}</span>
                                    {body}
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
            }.into_any()
        }}
    }
}

/// (2) File Base — the live Solid pod browser (WebID-owned storage).
fn file_base(cfg: StoredValue<BbsConfig>) -> impl IntoView {
    let id = viewer(cfg);
    let listing = RwSignal::new(PodState::Idle);

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
        {header(Screen::FileBase)}
        {match id {
            Some(id) => view! {
                <div class="bbs-panel">
                    "  WebID    : " <span class="accent">{id.webid.clone()}</span> "\n"
                    "  pod-git  : " {id.git_clone.clone()} "\n\n"
                    "  /" {id.short()} "/"
                </div>
                {move || match listing.get() {
                    PodState::Idle | PodState::Loading => view! {
                        <div class="bbs-panel bbs-dim">"    … loading container"</div>
                    }.into_any(),
                    PodState::Error(e) => view! {
                        <div class="bbs-panel bbs-dim">"    pod unavailable: " {e}</div>
                    }.into_any(),
                    PodState::Loaded(items) if items.is_empty() => view! {
                        <div class="bbs-panel bbs-dim">"    (empty container)"</div>
                    }.into_any(),
                    PodState::Loaded(items) => view! {
                        <div class="bbs-list">
                            {items.into_iter().map(|r| {
                                let mark = if r.is_container { "▸ " } else { "· " };
                                let suffix = if r.is_container { "/" } else { "" };
                                view! {
                                    <div class="bbs-row">
                                        "    " <span class="accent">{mark}</span>
                                        {r.name} {suffix}
                                    </div>
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

/// (3) Node List — relay (live status) + federation mesh.
fn node_list(cfg: StoredValue<BbsConfig>, store: RelayStore) -> impl IntoView {
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
        {header(Screen::NodeList)}
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

/// (4) User List — members as did:nostr WebID profiles (live kind-0).
fn user_list(store: RelayStore, cfg: StoredValue<BbsConfig>) -> impl IntoView {
    let me = viewer(cfg);
    view! {
        {header(Screen::UserList)}
        {move || {
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
                            view! {
                                <div class="bbs-row">
                                    <span class="accent">"● "</span> {format!("{name:<20}")}
                                    <span class="bbs-dim">{format!(" #{who}")}</span>
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
            }.into_any()
        }}
        {me.map(|id| view! {
            <div class="bbs-panel">"  you: " <span class="accent">{id.did.clone()}</span></div>
        })}
    }
}

/// (5) Chat — live channel + encrypted DMs.
fn chat() -> impl IntoView {
    view! {
        {header(Screen::Chat)}
        <div class="bbs-panel bbs-dim">
            "  Live channel posts (kind-42) and gift-wrapped DMs (NIP-44/59) stream over\n  the relay. AUTH (NIP-42) gates sealed DMs to the addressed recipient.\n\n  > _"
        </div>
    }
}

/// Render one agent control panel (kit governance schema) in ASCII.
fn panel_view(agent: String, p: PanelDefinition) -> impl IntoView {
    view! {
        <div class="bbs-panel">
            "\n  ╓─ " <span class="title">{p.title.clone()}</span>
            <span class="bbs-dim">"  @" {agent} " · " {format!("{:?}", p.schema)} " · ↻" {p.refresh_secs} "s"</span> "\n"
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
}

/// (6) Door Games — agent-governance control panels (live, else samples).
fn door_games(store: RelayStore) -> impl IntoView {
    view! {
        {header(Screen::DoorGames)}
        <div class="bbs-panel bbs-dim">"  Registered agents publish interactive control panels; you sign decisions back."</div>
        {move || {
            let live: Vec<_> = store
                .governance
                .get()
                .iter()
                .filter_map(|ev| relay::parse_panel(ev).map(|p| (relay::short_id(&ev.pubkey), p)))
                .collect();
            if !live.is_empty() {
                return live
                    .into_iter()
                    .map(|(agent, p)| panel_view(agent, p))
                    .collect_view()
                    .into_any();
            }
            // No live governance events yet — show representative panels so the
            // human-in-the-loop surface is visible.
            view! {
                <div class="bbs-panel bbs-dim">"  (no live agent panels — showing examples)"</div>
                {sample_panels()
                    .into_iter()
                    .map(|ap| panel_view(ap.agent.to_string(), ap.panel))
                    .collect_view()}
            }.into_any()
        }}
    }
}

/// (7) Code Exchange — shared snippets / pod files.
fn code_exchange() -> impl IntoView {
    view! {
        {header(Screen::CodeExchange)}
        <div class="bbs-panel bbs-dim">"  Shared code snippets and pod-hosted files. Posts are signed Nostr events;\n  attachments live in the author's Solid pod under /public."</div>
    }
}

/// (8) System Info — node / relay / pod / identity status (live counts).
fn system_info(cfg: StoredValue<BbsConfig>, store: RelayStore) -> impl IntoView {
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
        {header(Screen::SystemInfo)}
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

/// (9) Settings — theme + identity + node.
fn settings(state: BbsState, cfg: StoredValue<BbsConfig>) -> impl IntoView {
    let node = cfg.with_value(|c| c.node_name.clone());
    view! {
        {header(Screen::Settings)}
        <div class="bbs-panel">
            "  theme     : " <span class="accent">{move || state.theme.get().label()}</span> "   "
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
            "  • Boards (Message Base) are zone-gated channels with cohort-gated reads,\n"
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
