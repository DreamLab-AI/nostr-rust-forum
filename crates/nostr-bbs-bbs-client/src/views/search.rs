//! Global search palette (`Cmd/Ctrl+K`, `/search`, or topbar `⌕`).
//!
//! Combines:
//! 1. Live local boards (`ChannelStore::channels`) and members (`ProfileCache`)
//! 2. Loaded channel messages (`ChannelStore::channel_messages`)
//! 3. Sealed per-zone local semantic search (`utils::sealed_search`) for
//!    encrypted zones when configured/ready!

use leptos::prelude::*;
use nostr_bbs_client_core::stores::channels::use_channel_store;
use nostr_bbs_client_core::stores::profile_cache::try_use_profile_cache;
use nostr_bbs_client_core::stores::zones::{load_zones, section_to_zone};
use nostr_bbs_client_core::utils::post_link::channel_of;
use nostr_bbs_client_core::utils::sealed_search;

use crate::router::{use_router, Route};
use crate::shell::use_search_palette;

#[derive(Clone, PartialEq)]
struct Hit {
    kind: &'static str,
    title: String,
    subtitle: String,
    route: Route,
}

/// Global Cmd/Ctrl+K search overlay modal.
#[component]
pub fn SearchOverlay() -> impl IntoView {
    let palette = use_search_palette();
    let router = use_router();
    let channels = use_channel_store();

    let query = RwSignal::new(String::new());
    let sealed_hits = RwSignal::new(Vec::<Hit>::new());
    let searching_sealed = RwSignal::new(false);
    let input_ref = NodeRef::<leptos::html::Input>::new();

    Effect::new(move |_| {
        if palette.open.get() {
            let pre = palette.prefill.get_untracked();
            if !pre.is_empty() {
                query.set(pre);
                palette.prefill.set(String::new());
            }
            if let Some(el) = input_ref.get() {
                let _ = el.focus();
            }
        }
    });

    // Trigger sealed per-zone search on query change when sealed zones exist.
    Effect::new(move |_| {
        let q = query.get().trim().to_string();
        if !palette.open.get() || q.len() < 2 {
            sealed_hits.set(Vec::new());
            return;
        }
        let szones = sealed_search::sealed_zones();
        #[cfg(not(target_arch = "wasm32"))]
        let _ = szones;
        #[cfg(target_arch = "wasm32")]
        if !szones.is_empty() {
            let relay_opt = use_context::<nostr_bbs_client_core::relay::RelayConnection>();
            let zk_opt = nostr_bbs_client_core::zone_crypto::store::try_use_zone_key_store();
            if let (Some(relay), Some(zk)) = (relay_opt, zk_opt) {
                searching_sealed.set(true);
                wasm_bindgen_futures::spawn_local(async move {
                    let mut found = Vec::new();
                    if let Ok(hits) = sealed_search::search(&relay, &zk, &q, 12).await {
                        for h in hits {
                            let preview = h.event.content.chars().take(120).collect::<String>();
                            let zone_tag = h
                                .event
                                .tags
                                .iter()
                                .find(|t| t.first().map(String::as_str) == Some("zk"))
                                .and_then(|t| t.get(1))
                                .cloned()
                                .unwrap_or_else(|| szones.first().cloned().unwrap_or_default());
                            // Open AT the post, as a POST hit does.
                            found.push(Hit {
                                kind: "🔒 SEALED",
                                title: preview,
                                subtitle: format!(
                                    "zone:{zone_tag} · score {:.0}%",
                                    h.score * 100.0
                                ),
                                route: Route::Go {
                                    event_id: h.event.id.clone(),
                                    channel: channel_of(&h.event),
                                },
                            });
                        }
                    }
                    sealed_hits.set(found);
                    searching_sealed.set(false);
                });
            }
        }
    });

    let local_hits = Memo::new(move |_| {
        let q = query.get().trim().to_ascii_lowercase();
        if q.is_empty() {
            return Vec::<Hit>::new();
        }
        let zones = load_zones();
        let mut out = Vec::new();

        // 1. Matching boards
        for ch in channels.channels.get() {
            if ch.name.to_ascii_lowercase().contains(&q)
                || ch.description.to_ascii_lowercase().contains(&q)
            {
                let z = section_to_zone(&ch.section, &zones).unwrap_or_else(|| "public".into());
                out.push(Hit {
                    kind: "BOARD",
                    title: format!("#{}", ch.name),
                    subtitle: ch.description.clone(),
                    route: Route::Board {
                        zone: z,
                        channel_id: ch.id.clone(),
                    },
                });
            }
        }

        // 2. Matching members
        if let Some(pc) = try_use_profile_cache() {
            for (pk, entry) in pc.entries.get() {
                let label = entry.best_label().unwrap_or_default();
                if label.to_ascii_lowercase().contains(&q) || pk.starts_with(&q) {
                    out.push(Hit {
                        kind: "MEMBER",
                        title: if label.is_empty() {
                            nostr_bbs_client_core::utils::shorten_pubkey(&pk)
                        } else {
                            label
                        },
                        subtitle: entry.about.clone().unwrap_or_default(),
                        route: Route::Profile { pubkey: pk },
                    });
                }
            }
        }

        // 3. Matching loaded channel messages. The store's lists include
        // `topic:<root>` and `roots:<channel>` lists, which are not channels
        // and repeat posts: each post counts once, under its own channel tag,
        // and opens AT the post (the `Go` resolver finds its topic).
        let ch_list = channels.channels.get();
        let mut seen = std::collections::HashSet::new();
        for evs in channels.channel_messages.get().into_values() {
            for ev in evs {
                if !ev.content.to_ascii_lowercase().contains(&q)
                    || !seen.insert(ev.id.to_ascii_lowercase())
                {
                    continue;
                }
                let cid = channel_of(&ev);
                let ch_name = cid
                    .as_deref()
                    .and_then(|c| ch_list.iter().find(|m| m.id == c))
                    .map(|c| c.name.as_str())
                    .unwrap_or("board");
                let title: String = ev.content.chars().take(100).collect();
                out.push(Hit {
                    kind: "POST",
                    title,
                    subtitle: format!("#{ch_name}"),
                    route: Route::Go {
                        event_id: ev.id.clone(),
                        channel: cid,
                    },
                });
                if out.len() >= 40 {
                    return out;
                }
            }
        }
        out.truncate(40);
        out
    });

    view! {
        <Show when=move || palette.open.get() fallback=|| ()>
            <div
                class="bbs-overlay"
                role="dialog"
                aria-modal="true"
                aria-label="Global search"
                on:click=move |_| palette.open.set(false)
            >
                <div class="bbs-modal" on:click=move |ev| ev.stop_propagation()>
                    <div class="bbs-modal-head">
                        <span>"⌕"</span>
                        <input
                            node_ref=input_ref
                            class="bbs-input"
                            style="border:0;background:transparent;padding:0.2rem"
                            type="search"
                            placeholder="Search boards, members, posts, and sealed encrypted zones…"
                            prop:value=move || query.get()
                            on:input=move |ev| query.set(event_target_value(&ev))
                            on:keydown=move |ev| {
                                if ev.key() == "Escape" {
                                    ev.prevent_default();
                                    palette.open.set(false);
                                }
                            }
                        />
                        <button
                            type="button"
                            class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                            on:click=move |_| palette.open.set(false)
                        >"ESC"</button>
                    </div>
                    <div class="bbs-modal-body">
                        {move || {
                            let q = query.get();
                            if q.trim().is_empty() {
                                return view! {
                                    <p class="tui-muted" style="padding:1rem;text-align:center">
                                        "Type to search across boards, members, messages, and sealed zones."
                                    </p>
                                }.into_any();
                            }
                            let mut hits = local_hits.get();
                            hits.extend(sealed_hits.get());
                            if hits.is_empty() {
                                let label = if searching_sealed.get() {
                                    "Searching sealed zones…"
                                } else {
                                    "No matching boards, members, or posts."
                                };
                                return view! {
                                    <p class="tui-muted" style="padding:1rem;text-align:center">{label}</p>
                                }.into_any();
                            }
                            view! {
                                <div class="tui-stack">
                                    {hits.into_iter().map(|h| {
                                        let r = h.route.clone();
                                        view! {
                                            <button
                                                type="button"
                                                class="tui-card tui-card-interactive"
                                                style="text-align:left;width:100%"
                                                on:click=move |_| {
                                                    palette.open.set(false);
                                                    router.go(r.clone());
                                                }
                                            >
                                                <div class="tui-row-between">
                                                    <strong>{h.title}</strong>
                                                    <span class="bbs-badge">{h.kind}</span>
                                                </div>
                                                {(!h.subtitle.is_empty()).then(|| view! {
                                                    <div class="tui-muted" style="font-size:0.8rem">{h.subtitle}</div>
                                                })}
                                            </button>
                                        }
                                    }).collect_view()}
                                </div>
                            }.into_any()
                        }}
                    </div>
                </div>
            </div>
        </Show>
    }
}
