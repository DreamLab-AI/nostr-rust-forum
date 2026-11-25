//! Section page -- the LIST OF TOPICS within a forum section (#8).
//! Route: /forums/:category/:section
//!
//! ## BBS composition (the contract this page restores)
//!
//! A *section* is a kind-40 channel. A *topic* is a kind-42 ROOT message inside
//! it (a thread starter, anchored to the channel id). This page renders the
//! section as a LIST OF TOPICS — each row showing the topic title, author,
//! reply count and last-activity — NOT a flat linear chat. Clicking a topic row
//! opens the [`crate::pages::ThreadPage`] at
//! `/forums/:category/:section/:topic`.
//!
//! The previous implementation rendered every kind-42 in the channel as a flat
//! chat log, collapsing the topic/reply hierarchy. The flat single-channel chat
//! still exists at `/chat/:channel_id` ([`crate::pages::ChannelPage`])
//! for direct deep-links, but the section view is now a true BBS topic list.
//!
//! ## Data sourcing
//!
//! Topics are derived from the shared [`ChannelStore`](crate::stores::channels::ChannelStore) — the same global
//! kind-40 / kind-42 subscriptions that drive the Forums index tiles. This
//! eliminates the previous local two-stage subscription, which raced the
//! NIP-42 AUTH handshake: an unauthenticated reader is zone-filtered to public
//! zones, so the friends/family/business kind-40 def never arrived, the local
//! `section_info` stayed `None`, and the gated kind-42 sub never started.
//! By reading from the store (which subscribes ONCE at app root and survives
//! the AUTH replay), the page is independent of AUTH timing.
//!
//! ## URL privacy (#9)
//!
//! The `:section` slug in the URL is a HASH of the channel id (see
//! [`crate::utils::slug_hash`]); the real section name is resolved from the
//! store for the heading/breadcrumb. Legacy plaintext section slugs still
//! resolve via the fallback resolver.

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_params_map;
use std::rc::Rc;
use wasm_bindgen_futures::spawn_local;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::access_denied::AccessDenied;
use crate::components::breadcrumb::{Breadcrumb, BreadcrumbItem};
use crate::components::message_input::MessageInput;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::components::topic_list::{classify_topics, with_topic_stats, TopicList, TopicSummary};
use crate::components::zone_hero::ZoneHero;
use crate::relay::{ConnectionState, RelayConnection};
use crate::stores::channels::{use_channel_store, ChannelMeta};
use crate::stores::read_position::use_read_positions;
use crate::stores::zone_access::use_zone_access;
use crate::stores::zones::{load_zones, section_to_zone, Zone, ZoneVisibility};
use crate::utils::capitalize;
use crate::utils::lookup::{
    deadline_for, key_state_memo, zone_is_encrypted, zone_is_gated, Lookup,
};
use crate::utils::slug_hash::matches_section_slug;
use crate::utils::zone_theme::zone_accent_style_cfg;

/// Map a zone slug to its display name. Config-driven: resolves against the
/// live `ZONE_CONFIG` zone list, falling back to a capitalised slug for unknown
/// zones. Bug #22: avoid showing URL slug "Private" when the zone has a
/// configured display name.
///
/// `pub(crate)` so the thread page can render the same breadcrumb zone label.
pub(crate) fn category_display_name(slug: &str) -> String {
    {
        let zs = load_zones();
        crate::stores::zones::resolve_zone_param(slug, &zs).cloned()
    }
    .map(|z| z.label())
    .unwrap_or_else(|| capitalize(slug))
}

/// Humanise a section slug for breadcrumb display when no channel resolves.
/// `home-lobby` → `Lobby`. Only used as a last-resort label (hashed slugs are
/// opaque, so this is effectively a fallback for legacy plaintext URLs).
fn humanize_section_slug(slug: &str) -> String {
    let suffix = slug.split_once('-').map(|(_, s)| s).unwrap_or(slug);
    suffix
        .split('-')
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().to_string() + chars.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Slugify a channel name the same way legacy route slugs were generated.
fn slugify(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Find the channel whose section/name maps to `(category_slug, section_slug)`,
/// using the SAME config-zone logic the Forums index uses.
///
/// LEGACY/PLAINTEXT resolver: a channel matches when its `section` tag routes
/// to the requested category zone (or the category is empty) AND its `section`
/// tag equals the section slug, OR its name/name-slug equals the section slug,
/// OR its id is prefixed by the slug (deep-link by id-prefix).
///
/// `pub(crate)` so the thread page can share the fallback path. The hashed-slug
/// match (#9) is tried first by callers; this is the back-compat fallback.
pub(crate) fn resolve_channel(
    channels: &[ChannelMeta],
    category_slug: &str,
    section_slug: &str,
    zones: &[Zone],
) -> Option<ChannelMeta> {
    // The URL param may be the zone's slug (short URLs, issue #45) or its
    // legacy id — canonicalise to the zone ID, which is what
    // `section_to_zone` yields for channel routing.
    let cat = crate::stores::zones::resolve_zone_param(category_slug, zones)
        .map(|z| z.id.to_lowercase())
        .unwrap_or_else(|| category_slug.to_lowercase());
    let sec = section_slug.to_lowercase();
    channels
        .iter()
        .find(|c| {
            let routes_to_category = cat.is_empty()
                || section_to_zone(&c.section, zones)
                    .map(|z| z.to_lowercase() == cat)
                    .unwrap_or(false);
            let section_matches = c.section.to_lowercase() == sec
                || slugify(&c.name) == section_slug
                || c.name.to_lowercase() == sec
                || c.id.starts_with(section_slug);
            routes_to_category && section_matches
        })
        .cloned()
}

/// Resolve a section channel for `(category, section_slug)` from the store,
/// trying the hashed slug (#9) first and falling back to the plaintext resolver.
fn resolve_section(
    channels: &[ChannelMeta],
    category_slug: &str,
    section_slug_param: &str,
    zones: &[Zone],
) -> Option<ChannelMeta> {
    // The URL param may be the zone's slug (short URLs, issue #45) or its
    // legacy id — canonicalise to the zone ID, which is what
    // `section_to_zone` yields for channel routing.
    let cat = crate::stores::zones::resolve_zone_param(category_slug, zones)
        .map(|z| z.id.to_lowercase())
        .unwrap_or_else(|| category_slug.to_lowercase());
    // Hashed form (#9): match the channel-id hash (SectionCard links) OR the
    // section-tag hash (CategoryCard links group channels by section tag).
    if let Some(found) = channels.iter().find(|c| {
        let routes_to_category = cat.is_empty()
            || section_to_zone(&c.section, zones)
                .map(|z| z.to_lowercase() == cat)
                .unwrap_or(false);
        routes_to_category
            && (matches_section_slug(&c.id, section_slug_param)
                || (!c.section.is_empty() && matches_section_slug(&c.section, section_slug_param)))
    }) {
        return Some(found.clone());
    }
    // Legacy plaintext fallback (old seeded / bookmarked links).
    resolve_channel(channels, category_slug, section_slug_param, zones)
}

#[component]
pub fn SectionPage() -> impl IntoView {
    let relay = expect_context::<RelayConnection>();
    let auth = use_auth();
    let zone_writer = crate::zone_crypto::store::ZoneWriter::capture();
    let store = use_channel_store();
    let read_store = use_read_positions();
    let zone_access = use_zone_access();
    // Copy for the zone-first breadcrumb (ADR-107); `ZoneAccess` is `Copy`.
    let za_breadcrumb = zone_access;
    let toasts = use_toasts();

    let params = use_params_map();
    let category_slug = move || params.read().get("category").unwrap_or_default();
    let section_slug = move || params.read().get("section").unwrap_or_default();

    // Canonicalised zone URL slug: the `:category` param may be the zone's
    // configured slug OR its immutable id (both resolve via
    // `resolve_zone_param` so legacy `/zone1/…` links keep working), but every
    // link THIS page emits must read `/welcome/…` — never the raw id — so a
    // user arriving via an id URL never sees it propagate into child links.
    let category_url_slug = move || {
        let raw = category_slug();
        let zs = load_zones();
        crate::stores::zones::resolve_zone_param(&raw, &zs)
            .map(|z| crate::stores::zones::zone_slug(z).to_string())
            .unwrap_or(raw)
    };

    // Zone access gate: the category slug IS the zone ID (ADR-022 — the relay
    // remains the real boundary; unknown zones default accessible).
    let has_zone_access = Memo::new(move |_| {
        let cat = category_slug();
        let zs = load_zones();
        let resolved = crate::stores::zones::resolve_zone_param(&cat, &zs).cloned();
        match resolved {
            Some(zone) => {
                zone.visibility == ZoneVisibility::Public || zone_access.is_member_of(&zone)
            }
            None => true,
        }
    });

    // Resolve the channel reactively from the shared store. `Signal::derive`
    // (not `Memo`) because `ChannelMeta` is not `PartialEq`.
    let resolved_channel = Signal::derive(move || {
        let chans = store.channels.get();
        let zones = load_zones();
        resolve_section(&chans, &category_slug(), &section_slug(), &zones)
    });

    // Pod container for images attached to a new topic: this channel's zone.
    let topic_media_target = Signal::derive(move || {
        crate::stores::zones::media_target_for_section(
            resolved_channel.get().map(|c| c.section).as_deref(),
        )
    });

    // Top up the per-channel subscription once the channel id is known.
    {
        let relay = relay.clone();
        Effect::new(move |_| {
            if let Some(ch) = resolved_channel.get() {
                store.ensure_subscribed(&relay, &ch.id);
            }
        });
    }

    // Topics: the kind-42 ROOTS in this channel, with reply counts + last
    // activity, derived from the shared store. A `Memo`, so the list is
    // classified once per store change however many views read it (with
    // paged history a channel can hold tens of thousands of messages).
    let topics_memo = Memo::new(move |_| {
        let cid = match resolved_channel.get() {
            Some(ch) => ch.id,
            None => return Vec::<TopicSummary>::new(),
        };
        // Every topic root (one root-list REQ, not windowed) plus the
        // channel's history window (replies, live posts, roots of older
        // channels without the marker).
        let roots_key = crate::stores::channels::roots_key(&cid);
        store.channel_messages.with(|m| {
            let roots = m.get(&roots_key).map(Vec::as_slice).unwrap_or(&[]);
            let window = m.get(&cid).map(Vec::as_slice).unwrap_or(&[]);
            if roots.is_empty() {
                return classify_topics(&cid, window);
            }
            let held: std::collections::HashSet<&str> =
                window.iter().map(|e| e.id.as_str()).collect();
            let mut all: Vec<nostr_bbs_core::NostrEvent> = window.to_vec();
            all.extend(
                roots
                    .iter()
                    .filter(|r| !held.contains(r.id.as_str()))
                    .cloned(),
            );
            classify_topics(&cid, &all)
        })
    });
    // The window holds a fraction of a long topic: take the relay's exact
    // reply total and newest reply where they are in. A separate Memo, so a
    // stats answer re-folds the summaries without re-classifying the window.
    let classified = topics_memo;
    let topics_memo = Memo::new(move |_| {
        with_topic_stats(classified.get(), |t| {
            let total = store.total_for(&crate::stores::channels::topic_key(&t.id));
            (total, store.topic_latest(&t.id))
        })
    });

    // Ask for those stats for the listed topics (top of the list first),
    // in batches, once per topic per session.
    {
        let relay_for_stats = expect_context::<RelayConnection>();
        Effect::new(move |_| {
            let Some(ch) = resolved_channel.get() else {
                return;
            };
            let gated = zone_is_gated(&category_slug(), &load_zones());
            if !store.history_receipt(&ch.id).settles(gated) {
                return;
            }
            let ids: Vec<String> =
                topics_memo.with(|ts| ts.iter().map(|t| t.id.clone()).collect());
            store.request_topic_stats(&relay_for_stats, &ch.id, &ids, gated);
        });
    }
    let topics: Signal<Vec<TopicSummary>> = topics_memo.into();

    // Fetch the section's topic roots once (decision ii: sealed roots carry
    // ["t","topic"]), so dormant topics are listed without paging the channel.
    {
        let relay_for_roots = expect_context::<RelayConnection>();
        Effect::new(move |_| {
            if let Some(ch) = resolved_channel.get() {
                let gated = zone_is_gated(&category_slug(), &load_zones());
                if store.history_receipt(&ch.id).settles(gated) {
                    store.request_topic_roots(&relay_for_roots, &ch.id, gated);
                }
            }
        });
    }

    // Mark this channel read when its topic list is viewed (BBS reading flow).
    //
    // The forum index ("N new" chip) computes unread as messages newer than the
    // channel's last-read position, but the BBS flow (zones → sections → topics)
    // never recorded one — only the flat /chat view (channel.rs) did — so every
    // post counted as "new" forever. Mirroring channel.rs:431, we record the
    // LATEST kind-42 message's id + created_at the moment a user opens this
    // section's topic list. The index Memo subscribes to `read_timestamps()`, so
    // it re-runs and clears the chip on return.
    //
    // Gated on the latest message id so the Effect is a no-op once that channel
    // is already marked at its newest message — it only re-fires when a genuinely
    // newer message arrives, never on every render.
    {
        let last_marked = RwSignal::new(String::new());
        Effect::new(move |_| {
            let cid = match resolved_channel.get() {
                Some(ch) => ch.id,
                None => return,
            };
            // Latest kind-42 message in the channel (max created_at, tie-broken by
            // id for determinism — matches the index's `created_at >` semantics).
            let latest = store.channel_messages.with(|m| {
                m.get(&cid).and_then(|events| {
                    events
                        .iter()
                        .filter(|e| e.kind == 42)
                        .max_by(|a, b| {
                            a.created_at
                                .cmp(&b.created_at)
                                .then_with(|| a.id.cmp(&b.id))
                        })
                        .map(|e| (e.id.clone(), e.created_at))
                })
            });
            if let Some((last_id, last_ts)) = latest {
                if last_marked.get_untracked() != last_id {
                    read_store.mark_read(&cid, &last_id, last_ts);
                    last_marked.set(last_id);
                }
            }
        });
    }

    // Found / loading / not found, for the section and then its topic list.
    // Absence is only reported on the relay's EOSE for the subscription that
    // would have carried the thing (the channel list for the section, this
    // channel's history query for its topics) or after the deadline — never on
    // `store.loading`, which clears on the first channel-list EOSE (or at once
    // from cache) and so let "Section Not Found" and "No topics yet" show
    // before a cold deep link had synced.
    // Re-armed per section: the route component is reused across sections.
    let deadline = deadline_for(move || (category_slug(), section_slug()));
    let section_lookup = Memo::new(move |_| {
        let gated = zone_is_gated(&category_slug(), &load_zones());
        Lookup::decide(
            resolved_channel.with(Option::is_some),
            store.channel_receipt.get().settles(gated),
            deadline.get(),
        )
    });
    // An encrypted zone's list is not "empty" while the member's keys are
    // still arriving. No zone-key store means nothing here can decrypt, so
    // there is nothing to wait for.
    let zone_keys = crate::zone_crypto::store::try_use_zone_key_store();
    let auth_pubkey = auth.pubkey();
    let keys = key_state_memo(
        move || {
            zone_keys.is_some()
                && zone_is_encrypted(
                    &category_slug(),
                    &load_zones(),
                    crate::zone_crypto::encryption_enabled(),
                )
        },
        move |now| zone_keys.and_then(|z| z.key_phase_for(auth_pubkey.get().as_deref(), now)),
        deadline,
    );
    let topics_lookup = Memo::new(move |_| {
        section_lookup.get().then(|| {
            let gated = zone_is_gated(&category_slug(), &load_zones());
            let cid = resolved_channel.get().map(|c| c.id).unwrap_or_default();
            Lookup::decide_with_keys(
                topics.with(|t| !t.is_empty()),
                store.history_receipt(&cid).settles(gated),
                keys.get(),
                deadline.get(),
            )
        })
    });
    let section_loading = Memo::new(move |_| section_lookup.get().is_loading());

    let header_name = move || {
        resolved_channel
            .get()
            .map(|c| c.name)
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| humanize_section_slug(&section_slug()))
    };
    let header_desc = move || resolved_channel.get().map(|c| c.description);

    // -- New-topic composer state --
    let show_new_topic = RwSignal::new(false);
    let create_error = RwSignal::new(Option::<String>::None);
    // Re-fills the composer if the publish fails (relay rejection / not
    // resolved), so the user never loses a topic they typed. `MessageInput`
    // clears its content on send, then restores from this signal on failure.
    let topic_restore = RwSignal::new(Option::<String>::None);
    let is_authed = auth.is_authenticated();

    // Gate with a one-shot self-heal refresh (see [`zone_access_gate`]) so a
    // just-granted member doesn't flash "Access Denied" on a stale cohort read
    // right after an invite redeem — it auto-retries once, showing a neutral
    // "checking" state meanwhile.
    let access_gate = crate::stores::zone_access::zone_access_gate(
        zone_access,
        is_authed.into(),
        has_zone_access.into(),
    );

    // `relay` (RelayConnection) is non-Copy; the new-topic composer's on:click
    // sits inside two <Show> children closures, which must be `Fn`. Capturing
    // `relay` directly would move it out of the children env (FnOnce, E0525), so
    // hold it in a Copy StoredValue the children can copy into the handler.
    let composer_relay = StoredValue::new(relay.clone());

    let category_for_topics = Signal::derive(category_url_slug);

    view! {
        <Show
            when=move || {
                access_gate.get() == crate::stores::zone_access::AccessGate::Granted
            }
            fallback=move || {
                // Still resolving (initial fetch or one-shot self-heal retry) →
                // neutral "checking" state, never "Access Denied".
                if access_gate.get() == crate::stores::zone_access::AccessGate::Checking {
                    view! {
                        <div class="max-w-lg mx-auto p-8 text-center">
                            <div class="glass-card p-8">
                                <div class="w-12 h-12 rounded-full border-2 border-gray-700 border-t-amber-400 animate-spin mx-auto mb-4"></div>
                                <p class="text-gray-400 text-sm">"Checking your access…"</p>
                            </div>
                        </div>
                    }
                    .into_any()
                } else {
                    view! { <AccessDenied zone_id=category_slug() /> }.into_any()
                }
            }
        >
        // Root carries the zone accent as `--zone-accent` for descendants.
        <div
            class="max-w-4xl mx-auto p-4 sm:p-6"
            style=move || {
                let slug = category_slug();
                let zs = load_zones();
                let accent = crate::stores::zones::resolve_zone_param(&slug, &zs)
                    .and_then(|z| z.accent_hex.clone());
                zone_accent_style_cfg(&slug, accent.as_deref())
            }
        >
            // Zone-identity banner for visual consistency with the category page
            // (#30/#21): the section page now shows the owning zone's configured
            // banner image and palette, not just a bare heading.
            {move || {
                let slug = category_slug();
                let zs = load_zones();
                let zone = crate::stores::zones::resolve_zone_param(&slug, &zs).cloned();
                let banner = zone.as_ref().and_then(|z| z.banner_image_url.clone()).unwrap_or_default();
                let accent = zone.as_ref().and_then(|z| z.accent_hex.clone());
                let label = zone.as_ref().map(|z| z.label()).unwrap_or_default();
                view! {
                    <ZoneHero
                        title=category_display_name(&slug)
                        description="Topics in this section".to_string()
                        zone_id=slug.clone()
                        // Sparkle: neutral default icon, matching the category page.
                        icon="M12 2l2.4 7.2L22 12l-7.6 2.8L12 22l-2.4-7.2L2 12l7.6-2.8L12 2z"
                        banner_url=banner
                        zone_label=label
                        accent_hex=accent.unwrap_or_default()
                    />
                }
            }}

            // Zone-first breadcrumb (ADR-107): single-locked-zone members drop
            // the global "Forums" crumb but keep the zone as the landing link;
            // everyone else keeps Home › Forums › {Zone} › {Section}.
            {move || {
                let slug = category_slug();
                let zone_label = category_display_name(&slug);
                let zone_href = format!("/{}", category_url_slug());
                let section_label = header_name();
                if za_breadcrumb.home_zone().is_some() {
                    view! {
                        <Breadcrumb items=vec![
                            BreadcrumbItem::link("Home", "/"),
                            BreadcrumbItem::link(zone_label, zone_href),
                            BreadcrumbItem::current(section_label),
                        ] />
                    }
                    .into_any()
                } else {
                    view! {
                        <Breadcrumb items=vec![
                            BreadcrumbItem::link("Home", "/"),
                            BreadcrumbItem::link("Forums", "/forums"),
                            BreadcrumbItem::link(zone_label, zone_href),
                            BreadcrumbItem::current(section_label),
                        ] />
                    }
                    .into_any()
                }
            }}

            <div class="flex items-start justify-between gap-3 mt-2 mb-4">
                <div class="min-w-0">
                    <h1 class="text-2xl font-bold text-white">{header_name}</h1>
                    {move || header_desc().and_then(|d| {
                        if d.is_empty() { None } else {
                            Some(view! { <p class="text-sm text-gray-400 mt-1">{d}</p> })
                        }
                    })}
                    <span class="inline-block mt-2 text-xs text-gray-500 border border-gray-600 rounded px-1.5 py-0.5">
                        {move || {
                            let n = topics.get().len();
                            if n == 1 { "1 topic".to_string() } else { format!("{n} topics") }
                        }}
                    </span>
                </div>

                <Show when=move || is_authed.get() && !section_loading.get()>
                    <button
                        type="button"
                        on:click=move |_| {
                            show_new_topic.update(|v| *v = !*v);
                            create_error.set(None);
                        }
                        class="flex-shrink-0 flex items-center gap-2 za-chip-btn border px-4 py-2 rounded-lg transition-colors text-sm font-medium"
                    >
                        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"/>
                            <line x1="12" y1="8" x2="12" y2="16"/>
                            <line x1="8" y1="12" x2="16" y2="12"/>
                        </svg>
                        "New Topic"
                    </button>
                </Show>
            </div>

            // Inline new-topic composer. Reuses the shared `MessageInput` so the
            // topic body gets the same `@`-mention autocomplete (network search +
            // local roster + selection) as replies — fixing the inability to tag
            // a not-yet-cached member when *starting* a topic (the plain textarea
            // had no autocomplete and never queried `/api/profiles/search`). The
            // mentions picked from the dropdown are emitted as `["p", pubkey]`
            // tags on the kind-42 root. Publishes the same shape category.rs uses,
            // so the new topic appears in this list immediately on relay echo.
            <Show when=move || show_new_topic.get()>
                <div class="bg-gray-800 border border-gray-700 rounded-lg p-4 mb-5 space-y-2">
                    <MessageInput
                        media_target=topic_media_target
                        placeholder="Start a new topic — the first line becomes the title"
                        // Attach an image when starting a topic (parity with replies,
                        // which already set this). Without it the composer renders no
                        // image button, so users clicked the preview toggle and saw
                        // "Nothing to preview" (2026-07-20 fix).
                        enable_image_upload=true
                        // `MessageInput` fires `on_send` alongside `on_send_with_mentions`;
                        // we drive creation from the mentions variant and no-op the other.
                        on_send=Callback::new(|_: String| {})
                        on_send_with_mentions=Callback::new(move |(body, mentions): (String, Vec<String>)| {
                            let cid = resolved_channel.get_untracked().map(|c| c.id).unwrap_or_default();
                            if cid.is_empty() {
                                create_error.set(Some("Section not resolved yet".into()));
                                topic_restore.set(Some(body));
                                return;
                            }
                            if body.trim().len() < 3 {
                                create_error.set(Some("Topic must be at least 3 characters".into()));
                                topic_restore.set(Some(body));
                                return;
                            }
                            create_error.set(None);
                            // Sign via the async path so NIP-07 / extension (Podkey)
                            // users can post — the sync signer only works for an
                            // in-browser local key.
                            let relay = composer_relay.get_value();
                            let body_for_restore = body.clone();
                            spawn_local(async move {
                                match publish_topic_root(&auth, zone_writer, &relay, &cid, &body, mentions, toasts).await {
                                    Ok(()) => {
                                        show_new_topic.set(false);
                                        toasts.show("Topic created".to_string(), ToastVariant::Success);
                                    }
                                    Err(e) => {
                                        create_error.set(Some(e));
                                        topic_restore.set(Some(body_for_restore));
                                    }
                                }
                            });
                        })
                        restore_failed=topic_restore
                    />
                    {move || create_error.get().map(|e| view! {
                        <p class="text-red-400 text-sm">{e}</p>
                    })}
                    <button
                        type="button"
                        on:click=move |_| { show_new_topic.set(false); create_error.set(None); }
                        class="text-gray-400 hover:text-white px-3 py-1 text-sm transition-colors"
                    >
                        "Cancel"
                    </button>
                </div>
            </Show>

            {move || {
                let state = topics_lookup.get();
                if state.is_loading() {
                    view! {
                        <div class="flex flex-col items-center justify-center py-20 gap-3">
                            <div class="animate-spin w-6 h-6 border-2 za-spinner rounded-full"></div>
                            <span class="text-gray-400 text-sm">{if state == Lookup::KeysLoading {
                                "Fetching your keys for this zone\u{2026}"
                            } else {
                                "Loading topics..."
                            }}</span>
                        </div>
                    }.into_any()
                } else if !matches!(state, Lookup::TimedOut | Lookup::KeysTimedOut)
                    && resolved_channel.with(Option::is_some)
                {
                    // Found or authoritatively empty: TopicList renders both.
                    let ch_id = resolved_channel.get().map(|c| c.id).unwrap_or_default();
                    // Topics are newest first, so older history loads at the
                    // END of the list: scrolling there (or the control) pages
                    // back until the start of the channel.
                    let history_cid = Signal::derive(move || resolved_channel.get().map(|c| c.id));
                    let history_gated = Signal::derive(move || zone_is_gated(&category_slug(), &load_zones()));
                    // The complete root list already lists every topic:
                    // channel paging (older or newer) would add none.
                    let topics_complete = Signal::derive(move || {
                        resolved_channel
                            .get()
                            .is_some_and(|c| store.topic_roots_complete(&c.id))
                    });
                    // Bounded window: once older pages have evicted the
                    // newest topics, a loader above the list brings them back.
                    view! {
                        <crate::components::history_loader::HistoryLoader
                            channel_id=history_cid
                            gated=history_gated
                            label="Load newer topics"
                            direction=crate::components::history_loader::HistoryDirection::Newer
                            exhausted=topics_complete
                        />
                        <TopicList
                            channel_id=ch_id
                            category=category_for_topics.get()
                            topics=topics
                        />
                        <crate::components::history_loader::HistoryLoader
                            channel_id=history_cid
                            gated=history_gated
                            label="Load older topics"
                            exhausted=topics_complete
                        />
                    }.into_any()
                } else {
                    // Not found on a receipt, or no receipt before the
                    // deadline. A timeout must not read as "empty", so it gets
                    // its own wording rather than TopicList's "No topics yet".
                    let (heading, detail) = match (state, resolved_channel.with(Option::is_some)) {
                        (Lookup::TimedOut, true) => (
                            "Topics Unavailable",
                            "This section's topics did not finish loading. Check your connection and try again.",
                        ),
                        (Lookup::KeysTimedOut, _) => (
                            "Topics Unavailable",
                            "Your keys for this zone are taking too long to arrive. Reload to try again.",
                        ),
                        (Lookup::TimedOut, false) => (
                            "Section Unavailable",
                            "This section did not finish loading. Check your connection and try again.",
                        ),
                        _ => (
                            "Section Not Found",
                            "This section could not be found in this zone.",
                        ),
                    };
                    view! {
                        <div class="glass-card p-8 text-center">
                            <h2 class="text-xl font-bold text-white mb-2">{heading}</h2>
                            <p class="text-gray-400 text-sm mb-4">{detail}</p>
                            <A href=base_href(&format!("/{}", category_url_slug())) attr:class="za-text hover:opacity-80 text-sm underline">
                                "Back to zone"
                            </A>
                        </div>
                    }.into_any()
                }
            }}
        </div>
        </Show>
    }
}

/// Publish a new TOPIC: a kind-42 root message e-tagging the section channel.
/// The body's first line becomes the topic title in the list. Mirrors
/// `category.rs::publish_topic_root` so both entry points produce the same
/// shape and the topic appears in this list on relay echo.
async fn publish_topic_root(
    auth: &crate::auth::AuthStore,
    zone_writer: crate::zone_crypto::store::ZoneWriter,
    relay: &RelayConnection,
    section_channel_id: &str,
    body: &str,
    mentions: Vec<String>,
    toasts: crate::components::toast::ToastStore,
) -> Result<(), String> {
    if relay.connection_state().get_untracked() != ConnectionState::Connected {
        return Err("Relay not connected".to_string());
    }
    let pubkey = auth
        .pubkey()
        .get_untracked()
        .ok_or_else(|| "Not authenticated".to_string())?;

    let now = (js_sys::Date::now() / 1000.0) as u64;
    // The topic marker lists the root in the section's root list
    // (`#t:["topic"]`), as sealed roots are, so it is never only reachable
    // by paging the channel's history.
    let mut tags = vec![
        vec![
            "e".to_string(),
            section_channel_id.to_string(),
            String::new(),
            "root".to_string(),
        ],
        vec![
            "t".to_string(),
            nostr_bbs_core::sealed::TOPIC_MARKER.to_string(),
        ],
    ];
    // @handles get ["p", pubkey] tags so mentioned users / agents (e.g.
    // @junkiejarvis) are addressable and reachable via the relay's #p-filtered
    // subscriptions. Two sources, de-duped: the pubkeys the user picked from the
    // autocomplete dropdown (authoritative — covers members not yet in the
    // ProfileCache, which content resolution alone would miss), then any further
    // @handles resolvable from the content for mentions typed without selecting.
    let mut mention_pubkeys = mentions;
    for hex in crate::components::mention_autocomplete::resolve_content_mentions(body) {
        if !mention_pubkeys.contains(&hex) {
            mention_pubkeys.push(hex);
        }
    }
    for hex in mention_pubkeys {
        if !tags
            .iter()
            .any(|t| t.len() >= 2 && t[0] == "p" && t[1] == hex)
        {
            tags.push(vec!["p".to_string(), hex]);
        }
    }
    let unsigned = nostr_bbs_core::UnsignedEvent {
        pubkey,
        created_at: now,
        kind: 42,
        tags,
        content: body.trim().to_string(),
    };
    // Encrypted zone (ADR-2016): encrypt to the zone key, or refuse without one.
    let unsigned = zone_writer
        .prepare(section_channel_id, auth.get_signer(), unsigned)
        .await?;
    let signed = auth.sign_event_async(unsigned).await?;

    let on_ok = Rc::new(move |accepted: bool, msg: String| {
        if !accepted {
            let display = if let Some(why) = crate::zone_crypto::explain_relay_rejection(&msg) {
                why
            } else if msg.contains("whitelist") {
                "Your account isn't active yet — try refreshing the page.".to_string()
            } else if msg.trim().is_empty() {
                "Topic rejected by relay".to_string()
            } else {
                format!("Topic rejected: {msg}")
            };
            toasts.show(display, ToastVariant::Error);
        }
    });
    relay
        .publish_with_ack(&signed, Some(on_ok))
        .map_err(|e| format!("Send failed: {e}"))?;
    Ok(())
}

// The previous flat-chat helpers (`event_to_message`, message rendering, typing
// indicators, auto-scroll, notice toasts) were removed: the section view is now
// a topic list, not a chat log. Per-message rendering, reactions, and the live
// chat composer live on `/chat/:channel_id` (ChannelPage) and the per-topic
// ThreadPage.
