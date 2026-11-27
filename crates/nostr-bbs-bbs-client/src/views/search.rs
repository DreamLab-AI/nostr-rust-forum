//! Global search palette (`Cmd/Ctrl+K`, `/search`, or topbar `⌕`).
//!
//! Combines:
//! 1. Live local boards (`ChannelStore::channels`) and members (`ProfileCache`)
//! 2. Loaded channel messages (`ChannelStore::channel_messages`)
//! 3. Sealed per-zone local semantic search (`utils::sealed_search`) for
//!    encrypted zones when configured/ready!

use leptos::prelude::*;
use nostr_bbs_client_core::stores::channels::{distinct_posts, use_channel_store};
use nostr_bbs_client_core::stores::profile_cache::try_use_profile_cache;
use nostr_bbs_client_core::stores::zones::{load_zones, section_to_zone};
#[cfg(target_arch = "wasm32")]
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

    // Sealed per-zone search: re-run on query change and on every change in
    // the encrypted index's readiness (each shard that arrives, then ready),
    // so a query typed while it loads fills in by itself. One search at a
    // time; a change meanwhile runs once more when it ends, and only the
    // newest query writes the list.
    let readiness = Memo::new(move |_| sealed_search::readiness());
    let run = SealedRun {
        open: palette.open,
        query,
        readiness,
        hits: sealed_hits,
        searching: searching_sealed,
        generation: StoredValue::new(0u64),
        busy: StoredValue::new(false),
        again: StoredValue::new(false),
    };
    Effect::new(move |_| {
        let open = palette.open.get();
        let q = query.get().trim().to_string();
        let _ = readiness.get();
        run.generation.update_value(|g| *g += 1);
        if !open || q.len() < 2 {
            sealed_hits.set(Vec::new());
        } else if run.busy.get_value() {
            run.again.set_value(true);
        } else {
            run.start(q);
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
        // and repeat posts: each post counts once, under its own channel
        // (`distinct_posts`), and opens AT the post (the `Go` resolver finds its topic).
        let ch_list = channels.channels.get();
        for (cid, ev) in channels.channel_messages.with(distinct_posts) {
            if !ev.content.to_ascii_lowercase().contains(&q) {
                continue;
            }
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
                            let state = readiness.get();
                            if hits.is_empty() {
                                let label = empty_label(&state, searching_sealed.get());
                                return view! {
                                    <p class="tui-muted" style="padding:1rem;text-align:center" role="status">{label}</p>
                                }.into_any();
                            }
                            view! {
                                {state.notice().map(|n| view! {
                                    <p class="tui-muted" style="padding:0.25rem 0.5rem;font-size:0.8rem" role="status">{n}</p>
                                })}
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

/// The palette's sealed-search state: one search at a time, re-run once
/// when the query or the index's readiness changed meanwhile, and only the
/// newest query writes `hits`.
#[derive(Clone, Copy)]
#[cfg_attr(
    not(target_arch = "wasm32"),
    expect(
        dead_code,
        reason = "the search loop that reads them runs in the browser only"
    )
)]
struct SealedRun {
    open: RwSignal<bool>,
    query: RwSignal<String>,
    readiness: Memo<sealed_search::Readiness>,
    hits: RwSignal<Vec<Hit>>,
    searching: RwSignal<bool>,
    generation: StoredValue<u64>,
    busy: StoredValue<bool>,
    again: StoredValue<bool>,
}

impl SealedRun {
    #[cfg(not(target_arch = "wasm32"))]
    fn start(self, _q: String) {}

    #[cfg(target_arch = "wasm32")]
    fn start(self, q: String) {
        let szones = sealed_search::sealed_zones();
        if szones.is_empty() {
            return;
        }
        let relay_opt = use_context::<nostr_bbs_client_core::relay::RelayConnection>();
        let zk_opt = nostr_bbs_client_core::zone_crypto::store::try_use_zone_key_store();
        let (Some(relay), Some(zk)) = (relay_opt, zk_opt) else {
            return;
        };
        // Nothing started yet (the browser asked to save data): start now.
        if self.readiness.get_untracked() == sealed_search::Readiness::Idle {
            if let Some(signer) = nostr_bbs_client_core::auth::use_auth().get_signer() {
                sealed_search::start(zk, signer);
            }
        }
        self.busy.set_value(true);
        self.searching.set(true);
        wasm_bindgen_futures::spawn_local(async move {
            let mut q = q;
            loop {
                let generation = self.generation.get_value();
                let found = match sealed_search::search(&relay, &zk, &q, 12).await {
                    Ok(hits) => sealed_rows(hits, &szones),
                    Err(_) => Vec::new(),
                };
                if self.generation.try_get_value() == Some(generation) {
                    self.hits.set(found);
                }
                if self.again.try_get_value() == Some(true) {
                    self.again.set_value(false);
                    q = self.query.get_untracked().trim().to_string();
                    if self.open.get_untracked() && q.len() >= 2 {
                        continue;
                    }
                }
                break;
            }
            let _ = self.busy.try_set_value(false);
            let _ = self.searching.try_set(false);
        });
    }
}

/// What the palette says when nothing matched: never "no matching" while the
/// encrypted index is still loading, since its matches may not be in yet.
fn empty_label(state: &sealed_search::Readiness, searching: bool) -> String {
    if let Some(n) = state.notice() {
        n
    } else if searching {
        "Searching sealed zones…".into()
    } else {
        "No matching boards, members, or posts.".into()
    }
}

/// Palette rows for sealed hits, opening AT the post as a POST hit does.
#[cfg(target_arch = "wasm32")]
fn sealed_rows(hits: Vec<sealed_search::SealedHit>, szones: &[String]) -> Vec<Hit> {
    hits.into_iter()
        .map(|h| {
            let preview = h.event.content.chars().take(120).collect::<String>();
            let zone_tag = h
                .event
                .tags
                .iter()
                .find(|t| t.first().map(String::as_str) == Some("zk"))
                .and_then(|t| t.get(1))
                .cloned()
                .unwrap_or_else(|| szones.first().cloned().unwrap_or_default());
            Hit {
                kind: "🔒 SEALED",
                title: preview,
                subtitle: format!("zone:{zone_tag} · score {:.0}%", h.score * 100.0),
                route: Route::Go {
                    event_id: h.event.id.clone(),
                    channel: channel_of(&h.event),
                },
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealed_search::{Readiness, Unavailable};

    #[test]
    fn no_matching_is_never_said_while_the_encrypted_index_loads() {
        let loading = Readiness::Loading {
            loaded: 3,
            total: 8,
        };
        assert!(empty_label(&loading, false).contains("3 of 8"));
        assert!(empty_label(&loading, true).contains("still loading"));
        let waiting_for_keys = Readiness::Loading {
            loaded: 0,
            total: 0,
        };
        assert!(empty_label(&waiting_for_keys, false).contains("still loading"));
        assert_eq!(
            empty_label(&Readiness::Ready, true),
            "Searching sealed zones…"
        );
        for settled in [
            Readiness::Ready,
            Readiness::Idle,
            Readiness::Unavailable(Unavailable::NoKeys),
        ] {
            assert_eq!(
                empty_label(&settled, false),
                "No matching boards, members, or posts."
            );
        }
    }
}
