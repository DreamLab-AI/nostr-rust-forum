//! Zones directory, single-zone board list, and cross-channel live feed.

use leptos::prelude::*;
use nostr_bbs_client_core::auth::use_auth;
use nostr_bbs_client_core::relay::RelayConnection;
use nostr_bbs_client_core::stores::channels::use_channel_store;
use nostr_bbs_client_core::stores::read_position::use_read_positions;
use nostr_bbs_client_core::stores::zone_access::use_zone_access;
use nostr_bbs_client_core::stores::zones::{
    load_zones, resolve_zone_param, section_cmp, section_to_zone, zone_slug, ZoneVisibility,
};
use nostr_bbs_client_core::utils::format_relative_time;
use nostr_bbs_client_core::zone_crypto::encryption_enabled;
use nostr_bbs_client_core::zone_crypto::store::try_use_zone_key_store;

use crate::ascii_img::AsciiImg;
use crate::components::{AuthorChip, EmptyCard};
use crate::router::{use_router, Route};

/// Top-level Zones directory (`#/zones`).
#[component]
pub fn ZonesView() -> impl IntoView {
    let router = use_router();
    let channels = use_channel_store();
    let zone_access = use_zone_access();
    let zk_store = try_use_zone_key_store();
    let enc_gate = encryption_enabled();

    view! {
        <div class="tui-container">
            <div class="tui-page-head">
                <div>
                    <h1 class="tui-page-title">"▓ Zones & Message Bases"</h1>
                    <p class="tui-page-sub">
                        "Config-driven community zones with cohort gating and optional NIP-44 end-to-end encryption."
                    </p>
                </div>
                <div class="tui-actions">
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-sm"
                        on:click=move |_| router.go(Route::LiveFeed)
                    >"⚡ Live Feed"</button>
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-sm"
                        on:click=move |_| router.go(Route::Games)
                    >"▶ Door Games"</button>
                </div>
            </div>

            {move || {
                let zones = load_zones();
                let is_admin = zone_access.is_admin.get();
                let cohorts = zone_access.cohorts.get();
                let all_channels = channels.channels.get();

                let visible: Vec<_> = zones
                    .into_iter()
                    .filter(|z| {
                        z.visibility != ZoneVisibility::Hidden || is_admin || z.is_member(&cohorts)
                    })
                    .collect();

                if visible.is_empty() {
                    return view! {
                        <EmptyCard
                            title="No zones configured yet"
                            body="Zones load from ZONE_CONFIG (projected from forum.toml) and boards stream from the relay. Sign in if restricted zones are hidden."
                        />
                    }.into_any();
                }

                view! {
                    <div class="tui-grid">
                        {visible.into_iter().map(|z| {
                            let zid = z.id.clone();
                            let slug = zone_slug(&z).to_string();
                            let label = z.label();
                            let accent = z.accent_hex.clone().unwrap_or_default();
                            let style = if accent.is_empty() {
                                String::new()
                            } else {
                                format!("--accent:{accent}")
                            };
                            let is_member = is_admin || z.is_member(&cohorts);
                            let is_enc = enc_gate && z.encrypted;
                            let has_key = zk_store
                                .map(|s| s.latest_tracked(&zid).is_some())
                                .unwrap_or(false);
                            let has_kanban = z.kanban;
                            let board_count = all_channels
                                .iter()
                                .filter(|c| c.section == zid || c.section.starts_with(&format!("{zid}-")))
                                .count();
                            let vis_label = match z.visibility {
                                ZoneVisibility::Public => "PUBLIC",
                                ZoneVisibility::Locked => if is_member { "UNLOCKED" } else { "LOCKED" },
                                ZoneVisibility::Hidden => "PRIVATE",
                            };
                            let slug_open = slug.clone();
                            let slug_kb = slug.clone();

                            view! {
                                <div
                                    class="tui-card tui-card-accent tui-card-interactive tui-stack"
                                    style=style
                                    role="button"
                                    tabindex="0"
                                    on:click=move |_| router.go(Route::Zone { slug: slug_open.clone() })
                                >
                                    <div class="tui-row-between">
                                        <strong>{label}</strong>
                                        <span class="bbs-badge">{vis_label}</span>
                                    </div>
                                    <div class="tui-row">
                                        <span class="tui-muted">{format!("{board_count} board{}", if board_count == 1 { "" } else { "s" })}</span>
                                        {is_enc.then(|| view! {
                                            <span class=if has_key { "bbs-badge bbs-badge-ok" } else { "bbs-badge bbs-badge-warn" }>
                                                {if has_key { "🔒 E2E KEY READY" } else { "🔒 E2E" }}
                                            </span>
                                        })}
                                        {has_kanban.then(|| view! {
                                            <button
                                                type="button"
                                                class="bbs-btn bbs-btn-sm"
                                                on:click=move |ev| {
                                                    ev.stop_propagation();
                                                    router.go(Route::Kanban { zone: slug_kb.clone() });
                                                }
                                            >"▤ Kanban"</button>
                                        })}
                                    </div>
                                </div>
                            }
                        }).collect_view()}
                    </div>
                }.into_any()
            }}
        </div>
    }
}

/// Single zone view (`#/z/<slug>`): ASCII hero, E2E key status, Kanban shortcut, and board list.
#[component]
pub fn ZoneView(slug: String) -> impl IntoView {
    let router = use_router();
    let channels = use_channel_store();
    let read_pos = use_read_positions();
    let relay = expect_context::<RelayConnection>();
    let zk_store = try_use_zone_key_store();
    let enc_gate = encryption_enabled();

    let zones = load_zones();
    let zone = resolve_zone_param(&slug, &zones).cloned();
    let zone_id = zone
        .as_ref()
        .map(|z| z.id.clone())
        .unwrap_or_else(|| slug.clone());
    let zone_title = zone
        .as_ref()
        .map(|z| z.label())
        .unwrap_or_else(|| slug.clone());
    let accent = zone
        .as_ref()
        .and_then(|z| z.accent_hex.clone())
        .unwrap_or_default();
    let banner = zone
        .as_ref()
        .and_then(|z| z.banner_image_url.clone())
        .filter(|s| !s.trim().is_empty());
    let section_order = zone
        .as_ref()
        .map(|z| z.section_order.clone())
        .unwrap_or_default();
    let is_enc = enc_gate && zone.as_ref().is_some_and(|z| z.encrypted);
    let has_kanban = zone.as_ref().is_some_and(|z| z.kanban);
    let style = if accent.is_empty() {
        String::new()
    } else {
        format!("--accent:{accent}")
    };

    let slug_for_kb = slug.clone();
    let slug_for_rows = slug.clone();
    let zid_for_key = zone_id.clone();

    view! {
        <div class="tui-container" style=style>
            <div class="tui-crumb">
                {move || (!router.pwa_mode.get()).then(|| view! {
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                        on:click=move |_| router.go(Route::Zones)
                    >"← Zones"</button>
                    <span>"/"</span>
                })}
                <strong>{zone_title.clone()}</strong>
            </div>

            <div class="tui-page-head">
                <div>
                    <h1 class="tui-page-title">{zone_title.clone()}</h1>
                    <div class="tui-row" style="margin-top:0.3rem">
                        {is_enc.then(|| {
                            let zid = zid_for_key.clone();
                            move || {
                                let held = zk_store
                                    .map(|s| s.latest_tracked(&zid).is_some())
                                    .unwrap_or(false);
                                if held {
                                    view! {
                                        <span class="bbs-badge bbs-badge-ok">"🔒 End-to-End Encrypted · Key Active"</span>
                                    }.into_any()
                                } else {
                                    view! {
                                        <span class="bbs-badge bbs-badge-warn">"🔒 Encrypted Zone · Awaiting Key Grant"</span>
                                    }.into_any()
                                }
                            }
                        })}
                    </div>
                </div>
                <div class="tui-actions">
                    {has_kanban.then(|| view! {
                        <button
                            type="button"
                            class="bbs-btn bbs-btn-primary"
                            on:click=move |_| router.go(Route::Kanban { zone: slug_for_kb.clone() })
                        >"▤ Open Kanban Board"</button>
                    })}
                </div>
            </div>

            {banner.map(|src| view! {
                <div class="bbs-ascii-card">
                    <div class="bbs-ascii-card-head">
                        <span>"▞ ZONE BANNER ▚"</span>
                        <span>"phosphor ASCII"</span>
                    </div>
                    <AsciiImg src=src cols=84 />
                </div>
            })}

            {move || {
                let mut list: Vec<_> = channels
                    .channels
                    .get()
                    .into_iter()
                    .filter(|c| c.section == zone_id || c.section.starts_with(&format!("{zone_id}-")))
                    .collect();
                list.sort_by(|a, b| {
                    section_cmp(&a.section, &b.section, &section_order)
                        .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                });

                if list.is_empty() {
                    return view! {
                        <EmptyCard
                            title="No boards in this zone yet"
                            body="Boards (kind-40 channels) stream from the relay. If this zone is cohort-gated, sign in to unlock reads."
                        />
                    }.into_any();
                }

                let last_map = channels.last_active.get();
                // Unread per board, as the forum index's "N new" chip counts
                // it: messages newer than the board's read position.
                let read_ts = read_pos.read_timestamps();
                view! {
                    <div class="tui-stack">
                        {list.into_iter().map(|ch| {
                            let cid = ch.id.clone();
                            let cid_click = cid.clone();
                            let z_nav = slug_for_rows.clone();
                            let count = channels.count_for(&cid);
                            let unread = channels.channel_messages.with(|m| {
                                m.get(&cid).map_or(0, |evs| {
                                    nostr_bbs_client_core::topics::unread_count(
                                        evs,
                                        read_ts.get(&cid).copied().unwrap_or(0),
                                    )
                                })
                            });
                            let last_ts = last_map.get(&cid).copied().unwrap_or(ch.created_at);
                            let relay_click = relay.clone();

                            view! {
                                <div
                                    class="tui-card tui-card-accent tui-card-interactive"
                                    role="button"
                                    tabindex="0"
                                    on:click=move |_| {
                                        channels.ensure_subscribed(&relay_click, &cid_click);
                                        router.go(Route::Board {
                                            zone: z_nav.clone(),
                                            channel_id: cid_click.clone(),
                                        });
                                    }
                                >
                                    <div class="tui-row-between">
                                        <div>
                                            <strong>"# " {ch.name.clone()}</strong>
                                            {(!ch.description.is_empty()).then(|| view! {
                                                <p class="tui-muted" style="font-size:0.84rem;margin-top:0.15rem">
                                                    {ch.description.clone()}
                                                </p>
                                            })}
                                        </div>
                                        <div class="tui-row">
                                            {(unread > 0).then(|| view! {
                                                <span class="bbs-badge bbs-badge-accent">{format!("{unread} new")}</span>
                                            })}
                                            <span class="bbs-badge">{format!("{count} posts")}</span>
                                            <span class="tui-muted" style="font-size:0.78rem">
                                                {format_relative_time(last_ts)}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            }
                        }).collect_view()}
                    </div>
                }.into_any()
            }}
        </div>
    }
}

/// Cross-channel live activity feed (`#/live`).
#[component]
pub fn LiveFeedView() -> impl IntoView {
    let router = use_router();
    let channels = use_channel_store();
    let auth = use_auth();
    let zones = load_zones();

    view! {
        <div class="tui-container">
            <div class="tui-page-head">
                <div>
                    <h1 class="tui-page-title">"⚡ Live Channel Feed"</h1>
                    <p class="tui-page-sub">
                        "Recent signed messages across every board you can read. Tap any entry to jump straight into its thread."
                    </p>
                </div>
            </div>

            {move || {
                let ch_list = channels.channels.get();
                let map = channels.channel_messages.get();
                let mut all: Vec<(String, nostr_bbs_core::NostrEvent)> = Vec::new();
                for (cid, evs) in map {
                    for ev in evs {
                        all.push((cid.clone(), ev));
                    }
                }
                all.sort_by_key(|(_, e)| std::cmp::Reverse(e.created_at));
                all.truncate(80);

                if all.is_empty() {
                    let msg = if auth.is_authenticated().get() {
                        "Waiting for live messages from the relay…"
                    } else {
                        "No public messages loaded yet. Sign in to read cohort-gated boards."
                    };
                    return view! { <EmptyCard title="Quiet on the wire" body=msg /> }.into_any();
                }

                view! {
                    <div class="tui-stack">
                        {all.into_iter().map(|(cid, ev)| {
                            let ch_meta = ch_list.iter().find(|c| c.id == cid);
                            let ch_name = ch_meta
                                .map(|c| c.name.clone())
                                .unwrap_or_else(|| nostr_bbs_client_core::utils::shorten_pubkey(&cid));
                            let z_slug = ch_meta
                                .and_then(|c| section_to_zone(&c.section, &zones))
                                .unwrap_or_else(|| "public".to_string());
                            let root_id = nostr_bbs_core::thread::reply_parent(&ev)
                                .unwrap_or_else(|| ev.id.clone());
                            let preview: String = ev.content.chars().take(160).collect();
                            let ts = format_relative_time(ev.created_at);
                            let cid_go = cid.clone();

                            view! {
                                <div
                                    class="tui-card tui-card-interactive tui-stack"
                                    role="button"
                                    tabindex="0"
                                    on:click=move |_| router.go(Route::Thread {
                                        zone: z_slug.clone(),
                                        channel_id: cid_go.clone(),
                                        root_id: root_id.clone(),
                                        focus: None,
                                    })
                                >
                                    <div class="tui-row-between">
                                        <div class="tui-row">
                                            <AuthorChip pubkey=ev.pubkey.clone() />
                                            <span class="bbs-badge">"#" {ch_name}</span>
                                        </div>
                                        <span class="tui-muted" style="font-size:0.78rem">{ts}</span>
                                    </div>
                                    <div style="overflow-wrap:anywhere">{preview}</div>
                                </div>
                            }
                        }).collect_view()}
                    </div>
                }.into_any()
            }}
        </div>
    }
}
