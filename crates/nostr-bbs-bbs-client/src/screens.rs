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

/// Render the active screen.
#[component]
pub fn ScreenView(state: BbsState) -> impl IntoView {
    let cfg = use_context::<StoredValue<BbsConfig>>().expect("config");
    let store = use_context::<RelayStore>().expect("relay");
    move || match state.screen.get() {
        Screen::MainMenu => view! { <MainMenu state=state /> }.into_any(),
        Screen::Agents => agents(store).into_any(),
        Screen::Boards => boards(state, store, cfg).into_any(),
        Screen::Chat => chat().into_any(),
        Screen::Members => members(store, cfg).into_any(),
        Screen::Pod => pod(cfg).into_any(),
        Screen::Code => code().into_any(),
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

/// (2) Boards — live boards (kind-40) → posts (kind-42), zone-gated.
fn boards(state: BbsState, store: RelayStore, cfg: StoredValue<BbsConfig>) -> impl IntoView {
    view! {
        {header(Screen::Boards)}
        {move || match state.board.get() {
            None => board_list(state, store, cfg).into_any(),
            Some(id) => board_posts(store, id).into_any(),
        }}
    }
}

/// Configured zones' banner images rendered as on-theme ASCII "section heroes"
/// at the top of the Message Base, each tinted to its zone accent.
fn section_heroes(cfg: StoredValue<BbsConfig>) -> impl IntoView {
    let zones = cfg.with_value(|c| c.zones.clone());
    view! {
        {zones
            .into_iter()
            .filter_map(|z| {
                let url = z.banner_image_url.clone().filter(|u| !u.trim().is_empty())?;
                let accent = z.accent_hex.clone().unwrap_or_default();
                let style = if accent.is_empty() {
                    String::new()
                } else {
                    format!("--accent:{accent}")
                };
                Some(view! {
                    <div class="bbs-section-hero" style=style>
                        <div class="label">{format!("\u{259E} {} \u{259A}", z.display_name)}</div>
                        <AsciiImg src=url cols=84 />
                    </div>
                })
            })
            .collect_view()}
    }
}

fn board_list(state: BbsState, store: RelayStore, cfg: StoredValue<BbsConfig>) -> impl IntoView {
    view! {
        {section_heroes(cfg)}
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
                            let chan_id = ev.id.clone();
                            view! {
                                <div
                                    class="bbs-row"
                                    class:selected=selected
                                    style=style
                                    role="option"
                                    attr:aria-selected=move || if state.selection.get() == i { "true" } else { "false" }
                                    on:click=move |_| {
                                        state.selection.set(i);
                                        state.open_board(chan_id.clone());
                                    }
                                >
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
    let signer = use_context::<BbsSigner>();
    let draft = RwSignal::new(String::new());
    let status = RwSignal::new(SendStatus::Idle);
    // Reply target: (parent event id, parent author pubkey). `None` = post to root.
    let reply_to = RwSignal::new(None::<(String, String)>);
    let channel_for_send = channel_id.clone();
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
                            // Any image URLs in the post render on-theme as ASCII.
                            let imgs = extract_image_urls(&p.content);
                            let reply_id = p.id.clone();
                            let reply_pk = p.pubkey.clone();
                            view! {
                                <div class="bbs-row">
                                    <span class="accent">{format!("<{who}> ")}</span>
                                    {body}
                                    " "
                                    <span class="bbs-link bbs-dim" role="button"
                                        on:click=move |_| reply_to.set(Some((reply_id.clone(), reply_pk.clone())))
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
        {board_composer(signer, channel_for_send, draft, status, reply_to)}
    }
}

/// Compose box for a board: a signed kind-42 channel message (NIP-28), posting
/// to the channel root or as a reply to a selected post. Fails closed — hidden
/// with a prompt when no signer is available.
fn board_composer(
    signer: Option<BbsSigner>,
    channel_id: String,
    draft: RwSignal<String>,
    status: RwSignal<SendStatus>,
    reply_to: RwSignal<Option<(String, String)>>,
) -> impl IntoView {
    move || {
        let signed_in = signer.and_then(|s| s.pubkey().get()).is_some();
        if !signed_in {
            return view! {
                <div class="bbs-panel bbs-dim">
                    "  Sign in (" <span class="accent">"[9] Settings"</span>
                    ", or at /community/) to post to this board."
                </div>
            }
            .into_any();
        }
        let cid = channel_id.clone();
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
            let tags = relay::channel_message_tags(&cid, reply_to.get_untracked());
            let unsigned = nostr_bbs_core::UnsignedEvent {
                pubkey,
                created_at: now,
                kind: 42,
                tags,
                content: text,
            };
            status.set(SendStatus::Sending);
            draft.set(String::new());
            reply_to.set(None);
            publish_signed(signer_rc, unsigned, status);
        });
        let send_click = send.clone();
        let send_key = send.clone();
        view! {
            <div class="bbs-cmdline">
                {move || reply_to.get().map(|(id, _)| view! {
                    <span class="bbs-dim">
                        "↳ reply to " {relay::short_id(&id)} " "
                        <span class="bbs-link" role="button" on:click=move |_| reply_to.set(None)>"[clear]"</span>
                        " "
                    </span>
                })}
                <span class="prompt">"post/"</span>
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
                <span class="bbs-link accent" role="button" on:click=move |_| send_click()>"[ send ]"</span>
                <span class="bbs-dim">{move || status.get().suffix()}</span>
            </div>
        }
        .into_any()
    }
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

/// (4) Members — did:nostr WebID profiles (live kind-0).
fn members(store: RelayStore, cfg: StoredValue<BbsConfig>) -> impl IntoView {
    let me = viewer(cfg);
    view! {
        {header(Screen::Members)}
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

/// (3) Chat — live channel + encrypted DMs.
fn chat() -> impl IntoView {
    view! {
        {header(Screen::Chat)}
        <div class="bbs-panel bbs-dim">
            "  Live channel posts (kind-42) and gift-wrapped DMs (NIP-44/59) stream over\n  the relay. AUTH (NIP-42) gates sealed DMs to the addressed recipient.\n\n  > _"
        </div>
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
        use nostr_bbs_core::signer::Signer;
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
                    "  not signed in — open " <span class="accent">"[9] Settings"</span>
                    " to sign in before acting on a panel"
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
fn code() -> impl IntoView {
    view! {
        {header(Screen::Code)}
        <div class="bbs-panel bbs-dim">"  Shared code snippets and pod-hosted files. Posts are signed Nostr events;\n  attachments live in the author's Solid pod under /public."</div>
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

/// (9) Settings — theme + identity + node.
fn settings(state: BbsState, cfg: StoredValue<BbsConfig>) -> impl IntoView {
    let node = cfg.with_value(|c| c.node_name.clone());
    let signer = use_context::<BbsSigner>();
    view! {
        {header(Screen::Settings)}
        <div class="bbs-panel">
            "  theme     : " <span class="accent">{move || state.theme.get().label()}</span> "   "
            <span class="bbs-link" on:click=move |_| state.theme.update(|t| *t = t.next())>"[ cycle (T) ]"</span> "\n"
            "  node      : " {node} "\n"
            "  identity  : keys derived from your passkey (PRF); never persisted server-side\n"
            "  storage   : per-user Solid pod (WAC deny-by-default)"
        </div>
        {signer.map(sign_in_panel)}
    }
}

/// The BBS sign-in panel: shows the current signed-in identity with a sign-out
/// affordance, or a key input (nsec / hex) + generate option when signed out.
/// The key lives in memory only; the forum's same-origin local-key session is
/// adopted automatically at load.
fn sign_in_panel(signer: BbsSigner) -> impl IntoView {
    let key_input = RwSignal::new(String::new());
    let generated = RwSignal::new(None::<String>);
    view! {
        <div class="bbs-panel">
            "  ── identity / sign-in ─────────────────────────────\n"
            {move || match signer.pubkey().get() {
                Some(pk) => view! {
                    "  signed in : " <span class="accent">{relay::short_id(&pk)}</span> "   "
                    <span class="bbs-link" role="button"
                        on:click=move |_| { signer.logout(); generated.set(None); }
                    >"[ sign out ]"</span> "\n"
                    "  board posts & agent decisions are signed with this key (in memory only)"
                }.into_any(),
                None => {
                    let login = move || {
                        let input = key_input.get_untracked();
                        if signer.login_with_key(&input).is_ok() {
                            key_input.set(String::new());
                            generated.set(None);
                        }
                    };
                    view! {
                        "  Signing in at " <span class="accent">"/community/"</span> " with a local key carries here.\n"
                        "  Or paste an nsec / 64-char hex key, or generate a throwaway key:\n"
                        <div class="bbs-cmdline">
                            <span class="prompt">"key/"</span>
                            <input
                                prop:value=move || key_input.get()
                                on:input=move |ev| key_input.set(event_target_value(&ev))
                                on:keydown=move |ev| { if ev.key() == "Enter" { ev.prevent_default(); login(); } }
                            />
                            <span class="bbs-link accent" role="button" on:click=move |_| login()>"[ sign in ]"</span>
                            " "
                            <span class="bbs-link" role="button"
                                on:click=move |_| { if let Ok(hex) = signer.generate() { generated.set(Some(hex)); } }
                            >"[ generate ]"</span>
                        </div>
                        {move || signer.error().get().map(|e| view! { <div class="bbs-dim">"  ✗ " {e}</div> })}
                        {move || generated.get().map(|hex| view! {
                            <div class="bbs-dim">"  new key (back this up — shown once): " <span class="accent">{hex}</span></div>
                        })}
                    }.into_any()
                }
            }}
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
            "  Keys: number to open a board · / for commands · ESC back · T theme · 0 help\n\n"
            "  • A door stands ajar… "
            <span class="bbs-link" on:click=move |_| launch_sentry()>
                "[ \u{25B6} UA 571-C SENTRY ]"
            </span>
        </div>
    }
}
