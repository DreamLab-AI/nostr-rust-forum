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
use std::collections::HashMap;
use std::rc::Rc;
use wasm_bindgen_futures::spawn_local;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::access_denied::AccessDenied;
use crate::components::breadcrumb::{Breadcrumb, BreadcrumbItem};
use crate::components::canonical_address::keep_address_canonical;
use crate::components::message_input::MessageInput;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::components::topic_list::{
    classify_topics, with_topic_stats, TopicList, TopicListSkeleton, TopicSummary, UPDATED_CLASS,
    UPDATED_HIDDEN_CLASS,
};
use crate::components::zone_hero::ZoneHero;
use crate::relay::{ConnectionState, RelayConnection};
use crate::stores::channels::{use_channel_store, ChannelMeta};
use crate::stores::read_position::use_read_positions;
use crate::stores::zone_access::use_zone_access;
use crate::stores::zones::{load_zones, section_to_zone, Zone, ZoneVisibility};
use crate::topics::{
    first_paint_ready, older_paging_armed, sealed_aliases, updated_accessible_name, updated_label,
    BoardInputs, FrozenBoard, FIRST_PAINT_TIMEOUT_MS, FREEZE_CAP_MS,
};
use crate::utils::capitalize;
use crate::utils::lookup::{
    deadline_for, key_state_memo, zone_is_encrypted, zone_is_gated, Lookup,
};
use crate::utils::section_url::{canonical_section_path, find_by_section_slug};
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
    // Hashed form (#9): the channel-id hash (canonical), or the section-tag
    // hash old Forums index links carry.
    if let Some(found) = find_by_section_slug(channels, category_slug, section_slug_param, zones) {
        return Some(found.clone());
    }
    // Legacy plaintext fallback (old seeded / bookmarked links).
    resolve_channel(channels, category_slug, section_slug_param, zones)
}

/// What the topic area of the section page shows. The page's branch is
/// driven by a memo of this alone, so a write to the channel list that
/// changes nothing here (a reconnect, an AUTH replay, another channel's
/// rename) never tears down the topic list, its rows or its history loaders.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ListBranch {
    /// Skeleton rows: the lookup is still loading (`keys`: waiting on this
    /// zone's keys), or the topics are found but the first paint is held
    /// (see [`first_paint_ready`]).
    Skeleton { keys: bool },
    /// The topic list of this channel, found or authoritatively empty.
    List(String),
    /// Not found on a receipt, or no receipt before the deadline.
    Unavailable {
        heading: &'static str,
        detail: &'static str,
    },
}

/// One visit to a section: its channel id and a counter that moves on
/// every change of channel.
type Visit = (Option<String>, u64);

/// The visit after `prev` for channel `cid`: the same while the channel
/// stays, the next counter when it changes.
fn next_visit(prev: Option<&Visit>, cid: Option<String>) -> Visit {
    match prev {
        Some((p, n)) if *p == cid => (cid, *n),
        Some((_, n)) => (cid, n + 1),
        None => (cid, 0),
    }
}

/// The branch for lookup `state` of channel `cid`. Once a channel's list is
/// painted it stays painted (`prev`) while its lookup holds; until then a
/// found list is held as skeleton rows until `ready` says it may paint.
fn list_branch(
    prev: Option<&ListBranch>,
    state: Lookup,
    cid: Option<String>,
    ready: impl FnOnce() -> bool,
) -> ListBranch {
    match (state, cid) {
        (Lookup::Loading, _) => ListBranch::Skeleton { keys: false },
        (Lookup::KeysLoading, _) => ListBranch::Skeleton { keys: true },
        (Lookup::Found | Lookup::NotFound, Some(cid)) => {
            let painted = matches!(prev, Some(ListBranch::List(p)) if *p == cid);
            if painted || ready() {
                ListBranch::List(cid)
            } else {
                ListBranch::Skeleton { keys: false }
            }
        }
        // A timeout must not read as "empty", so it gets its own wording
        // rather than TopicList's "No topics yet".
        (Lookup::TimedOut, Some(_)) => ListBranch::Unavailable {
            heading: "Topics Unavailable",
            detail: "This section's topics did not finish loading. Check your connection and try again.",
        },
        (Lookup::KeysTimedOut, _) => ListBranch::Unavailable {
            heading: "Topics Unavailable",
            detail: "Your keys for this zone could not all be fetched or checked: the relay or the admin check did not answer, or they are taking too long. Nothing here is missing for certain. Reload to try again.",
        },
        (Lookup::TimedOut, None) => ListBranch::Unavailable {
            heading: "Section Unavailable",
            detail: "This section did not finish loading. Check your connection and try again.",
        },
        (Lookup::Found | Lookup::NotFound, None) => ListBranch::Unavailable {
            heading: "Section Not Found",
            detail: "This section could not be found in this zone.",
        },
    }
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
    // The resolved channel's id, as a Memo: unchanged channel-list writes
    // stop here. Everything that only needs the id reads this.
    let channel_id =
        Memo::new(move |_| resolved_channel.with(|c| c.as_ref().map(|c| c.id.clone())));

    // One URL per section: an old form (section-tag hash, `/forums/…`, zone
    // id) is replaced in place by the canonical one once the channel resolves.
    keep_address_canonical(move || {
        resolved_channel
            .get()
            .and_then(|ch| canonical_section_path(&ch, &load_zones()))
    });

    // "Continue where you left off" (utils::resume): remember this section
    // (route plus zone and section names, no content) once it resolves.
    Effect::new(move |_| {
        if !has_zone_access.get() {
            return;
        }
        let (Some(pk), Some(ch)) = (auth.pubkey().get(), resolved_channel.get()) else {
            return;
        };
        // Always the canonical section id (the channel-id hash), whichever
        // form the address had: an old form is about to be replaced.
        let slug = crate::utils::slug_hash::section_slug(&ch.id);
        let name = if ch.name.trim().is_empty() {
            humanize_section_slug(&slug)
        } else {
            ch.name.clone()
        };
        if let Some(point) = crate::utils::resume::point_for(
            &load_zones(),
            &category_slug(),
            Some((&slug, &name)),
            None,
        ) {
            crate::utils::resume::remember(&pk, &point);
        }
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
            if let Some(cid) = channel_id.get() {
                store.ensure_subscribed(&relay, &cid);
            }
        });
    }

    // Topics: the kind-42 ROOTS in this channel, with reply counts + last
    // activity, derived from the shared store. A `Memo`, so the list is
    // classified once per store change however many views read it (with
    // paged history a channel can hold tens of thousands of messages).
    let topics_memo = Memo::new(move |_| {
        let Some(cid) = channel_id.get() else {
            return Vec::<TopicSummary>::new();
        };
        // Every topic root (one root-list REQ, not windowed) plus the
        // channel's history window (replies, live posts, roots of older
        // channels without the marker).
        let roots_key = crate::stores::channels::roots_key(&cid);
        store.channel_messages.with(|m| {
            let roots = m.get(&roots_key).map(Vec::as_slice).unwrap_or(&[]);
            let window = m.get(&cid).map(Vec::as_slice).unwrap_or(&[]);
            classify_topics(&cid, &crate::topics::board_events(window, roots))
        })
    });
    // The window holds a fraction of a long topic: take the relay's exact
    // reply total and newest reply where they are in. A separate Memo, so a
    // stats answer re-folds the summaries without re-classifying the window.
    let classified = topics_memo;
    // ADR-2038: the relay's section stats give every marked topic its true
    // last activity and reply count in one answer. Folded into the structure
    // the board orders by (the per-topic stats below never are), so the list
    // is in true order when it freezes.
    let section_stats = Memo::new(move |_| channel_id.get().and_then(|c| store.section_stats(&c)));
    let section_stats_settled = Memo::new(move |_| {
        channel_id
            .get()
            .is_some_and(|c| store.section_stats_settled(&c))
    });
    let structured = Memo::new(move |_| {
        crate::topics::section_stats::fold_section_stats(
            classified.get(),
            section_stats.get().as_deref(),
        )
    });
    let topics_memo = Memo::new(move |_| {
        with_topic_stats(structured.get(), |t| {
            let total = store.total_for(&crate::stores::channels::topic_key(&t.id));
            (total, store.topic_latest(&t.id))
        })
    });

    // Ask for those stats for the listed topics (top of the list first),
    // in batches, once per topic per session: once the section stats have
    // answered or failed, and only for figures they do not carry (all of
    // them when they failed, an old relay included).
    {
        let relay_for_stats = expect_context::<RelayConnection>();
        Effect::new(move |_| {
            let Some(cid) = channel_id.get() else {
                return;
            };
            let gated = zone_is_gated(&category_slug(), &load_zones());
            if !store.history_receipt(&cid).settles(gated) || !section_stats_settled.get() {
                return;
            }
            let stats = section_stats.get();
            let ids: Vec<String> = topics_memo.with(|ts| {
                ts.iter()
                    .filter(|t| stats.as_ref().is_none_or(|s| s.needs_pump(&t.id)))
                    .map(|t| t.id.clone())
                    .collect()
            });
            store.request_topic_stats(&relay_for_stats, &cid, &ids, gated);
        });
    }
    let topics: Signal<Vec<TopicSummary>> = topics_memo.into();

    // Fetch the section's topic roots once (decision ii: sealed roots carry
    // ["t","topic"]), so dormant topics are listed without paging the channel.
    // A new visit (the first run, or a switch to another section) may ask a
    // root list that failed earlier again at once; a re-run for the same
    // channel respects its backoff (see `ChannelStore::request_topic_roots`).
    {
        let relay_for_roots = expect_context::<RelayConnection>();
        Effect::new(move |prev: Option<Option<String>>| {
            let current = channel_id.get();
            if let Some(cid) = current.as_deref() {
                if prev.flatten().as_deref() != Some(cid) {
                    store.rearm_topic_roots(cid);
                    store.rearm_section_stats(cid);
                }
                // Sent alongside the history REQ rather than after its
                // answer (one round trip less before first paint). A gated
                // zone's root list only counts once AUTH is done, so it
                // goes out then: its timeout does not run during sign-in.
                // Re-run on a change of the channel's history as well, so a
                // root list that failed is asked again once its backoff has
                // run out (`request_topic_roots` holds it until then).
                let gated = zone_is_gated(&category_slug(), &load_zones());
                let _ = store.history_receipt(cid);
                if !gated || relay_for_roots.authenticated().get() {
                    store.request_topic_roots(&relay_for_roots, cid, gated);
                    // ADR-2038: the section's topic stats, in the same
                    // round trip and under the same AUTH rule.
                    store.request_section_stats(&relay_for_roots, cid);
                }
            }
            current
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
            let Some(cid) = channel_id.get() else {
                return;
            };
            // Latest kind-42 message in the channel (max created_at, tie-broken by
            // id for determinism — matches the index's `created_at >` semantics).
            let latest = store.channel_messages.with(|m| {
                m.get(&cid)
                    .and_then(|events| crate::topics::latest_post(events))
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
            channel_id.with(Option::is_some),
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
            let cid = channel_id.get().unwrap_or_default();
            Lookup::decide_with_keys(
                topics.with(|t| !t.is_empty()),
                store.history_receipt(&cid).settles(gated),
                keys.get(),
                deadline.get(),
            )
        })
    });
    let section_loading = Memo::new(move |_| section_lookup.get().is_loading());

    // First paint (cause: a list painted on its first topic, then filled in
    // by the root list under the reader). A found list is held as skeleton
    // rows until the history window has its settled answer, the root list
    // has answered (or failed) and the section stats (ADR-2038) have
    // answered (or failed), or FIRST_PAINT_TIMEOUT_MS after it was found:
    // the section stats never hold the paint past that same timeout. The
    // per-topic stats are not waited for. A store that already holds all
    // three paints at once.
    let roots_answered = Memo::new(move |_| {
        channel_id
            .get()
            .is_some_and(|cid| store.topic_roots_answered(&cid))
    });
    let roots_failed = Memo::new(move |_| {
        channel_id
            .get()
            .is_some_and(|cid| store.topic_roots_failed(&cid))
    });
    // This visit: the channel and a counter that moves on every change of
    // channel (A -> B -> A is three visits), derived synchronously. Timers
    // and the board are tied to it, so nothing from an earlier visit lands
    // in a later one.
    let visit = Memo::new(move |prev: Option<&Visit>| next_visit(prev, channel_id.get()));
    let hold_expired = RwSignal::new(Option::<Visit>::None);
    {
        let armed = StoredValue::new(Option::<Visit>::None);
        Effect::new(move |_| {
            let this = visit.get();
            if this.0.is_none()
                || !matches!(topics_lookup.get(), Lookup::Found | Lookup::NotFound)
                || armed.with_value(|a| a.as_ref() == Some(&this))
            {
                return;
            }
            armed.set_value(Some(this.clone()));
            crate::utils::set_timeout_once(
                move || {
                    let _ = hold_expired.try_set(Some(this));
                },
                FIRST_PAINT_TIMEOUT_MS,
            );
        });
    }
    let hold_expired_here =
        Memo::new(move |_| visit.with(|v| hold_expired.with(|e| e.as_ref() == Some(v))));
    let branch = Memo::new(move |prev: Option<&ListBranch>| {
        let cid = channel_id.get();
        list_branch(prev, topics_lookup.get(), cid.clone(), || {
            let window_settled = cid.as_deref().is_some_and(|c| {
                store
                    .history_receipt(c)
                    .settles(zone_is_gated(&category_slug(), &load_zones()))
            });
            first_paint_ready(
                window_settled,
                roots_answered.get() || roots_failed.get(),
                section_stats_settled.get(),
                hold_expired_here.get(),
            )
        })
    });

    // Display order (cause: every stats answer re-sorted the painted list).
    // `FrozenBoard`: provisional while the section loads, in the true order
    // from structure and the section stats (the window's activity, the
    // relay's per-section answer, then root creation; the per-topic stats
    // never enter it), then frozen once, for the visit, when the window has
    // settled and the root list and the section stats have each answered or
    // failed (or FREEZE_CAP_MS after rows first show). After that no row
    // moves; "↻ N updated" offers real activity newer than the freeze, and
    // a row that arrived late below a row of lower known activity. Navigating away and back starts
    // afresh. Every input is a Memo, so the board does not re-run on other
    // channels' traffic.
    // The board's rows, stamped with the visit they belong to; only rows of
    // this visit are rendered (a section switch shows nothing of the last
    // section's rows while the board catches up).
    let order = RwSignal::new((Option::<Visit>::None, Vec::<String>::new()));
    let shown_order = Memo::new(move |_| {
        visit.with(|v| {
            order.with(|(for_visit, ids)| {
                if for_visit.as_ref() == Some(v) {
                    ids.clone()
                } else {
                    Vec::new()
                }
            })
        })
    });
    // A row still shown whose topic left the lists (evicted from the
    // window, kept in place by the board) keeps its last known figures.
    let by_id = Memo::new(move |prev: Option<&HashMap<String, TopicSummary>>| {
        let mut map = topics.with(|ts| {
            ts.iter()
                .map(|t| (t.id.clone(), t.clone()))
                .collect::<HashMap<_, _>>()
        });
        if let Some(prev) = prev {
            shown_order.with(|shown| {
                for id in shown {
                    if !map.contains_key(id) {
                        if let Some(t) = prev.get(id) {
                            map.insert(id.clone(), t.clone());
                        }
                    }
                }
            });
        }
        map
    });
    // Sealed envelopes and their originals in this channel's lists.
    let sealed_pairs = Memo::new(move |_| {
        let Some(cid) = channel_id.get() else {
            return Vec::new();
        };
        let roots_key = crate::stores::channels::roots_key(&cid);
        store.channel_messages.with(|m| {
            let mut pairs = Vec::new();
            for key in [&cid, &roots_key] {
                if let Some(events) = m.get(key) {
                    pairs.extend(sealed_aliases(events));
                }
            }
            pairs
        })
    });
    // The window counts once it has its settled answer and still holds the
    // channel's newest messages (older paging can detach it).
    let window_settled = Memo::new(move |_| {
        let gated = zone_is_gated(&category_slug(), &load_zones());
        channel_id.get().is_some_and(|c| {
            store.history_receipt(&c).settles(gated)
                && store.history_cursor(&c).newer_from.is_none()
        })
    });
    // The freeze cap: FREEZE_CAP_MS after the list first shows rows.
    let cap_expired = RwSignal::new(Option::<Visit>::None);
    {
        let armed = StoredValue::new(Option::<Visit>::None);
        Effect::new(move |_| {
            let this = visit.get();
            let showing =
                matches!(branch.get(), ListBranch::List(_)) && !topics.with(Vec::is_empty);
            if this.0.is_none() || !showing || armed.with_value(|a| a.as_ref() == Some(&this)) {
                return;
            }
            armed.set_value(Some(this.clone()));
            crate::utils::set_timeout_once(
                move || {
                    let _ = cap_expired.try_set(Some(this));
                },
                FREEZE_CAP_MS,
            );
        });
    }
    let ready_to_freeze = Memo::new(move |_| {
        let capped = visit.with(|v| cap_expired.with(|c| c.as_ref() == Some(v)));
        crate::topics::section_stats::freeze_ready(
            window_settled.get(),
            roots_answered.get() || roots_failed.get(),
            section_stats_settled.get(),
            capped,
        )
    });
    // The newest activity known: every topic's (stats included) and the
    // window's newest message (an edit can come back as a newest reply).
    let newest_known = Memo::new(move |_| {
        let topics_newest = topics.with(|ts| ts.iter().map(|t| t.last_activity).max().unwrap_or(0));
        let window_newest = channel_id.get().and_then(|c| {
            store
                .channel_messages
                .with(|m| m.get(&c).and_then(|evs| crate::topics::latest_post(evs)))
                .map(|(_, ts)| ts)
        });
        topics_newest.max(window_newest.unwrap_or(0))
    });
    let me = auth.pubkey();
    // (channel, its board)
    // The store's deletion decision for a row, from its last known author
    // (a sealed original's author matters).
    let is_deleted = move |id: &str| {
        let author = by_id.with_untracked(|m| m.get(id).map(|t| t.pubkey.clone()));
        store.deletion_honoured(zone_keys, id, author.as_deref().unwrap_or(""))
    };
    // (visit, its board)
    let board = StoredValue::new((visit.get_untracked(), FrozenBoard::new()));
    Effect::new(move |_| {
        let this = visit.get();
        let ready = ready_to_freeze.get();
        let newest = newest_known.get();
        let me_now = me.get();
        let now_secs = (js_sys::Date::now() / 1000.0) as u64;
        let stats = section_stats.get();
        let baseline_settled = window_settled.get() || stats.is_some();
        let known = |id: &str| stats.as_ref().is_some_and(|s| s.activity_known(id));
        let next = structured.with(|structure| {
            board.try_update_value(|(for_visit, b)| {
                if *for_visit != this {
                    *for_visit = this.clone();
                    *b = FrozenBoard::new();
                }
                sealed_pairs.with(|pairs| b.note_aliases(pairs.iter().cloned()));
                // An original opened as it arrived never had its envelope
                // in a list: the zone cache knows the pair.
                b.note_aliases(structure.iter().filter_map(|t| {
                    crate::zone_crypto::store::restored_envelope_of(zone_keys, &t.id)
                        .map(|env| (env, t.id.clone()))
                }));
                b.update(
                    structure,
                    &BoardInputs {
                        me: me_now.as_deref(),
                        ready_to_freeze: ready,
                        newest_known: newest,
                        now_secs,
                        deleted: &is_deleted,
                        baseline_settled,
                        activity_known: &known,
                    },
                );
                b.shown().to_vec()
            })
        });
        if let Some(next) = next {
            let stamped = (Some(this), next);
            if order.with_untracked(|current| *current != stamped) {
                order.set(stamped);
            }
        }
    });
    let updated = Memo::new(move |_| {
        shown_order.track();
        let this = visit.get();
        let me = me.get();
        topics.with(|sorted| {
            board
                .try_with_value(|(for_visit, b)| {
                    if *for_visit == this {
                        b.updated(sorted, me.as_deref())
                    } else {
                        0
                    }
                })
                .unwrap_or(0)
        })
    });

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
                // `try_with`: this closure can re-run after the route has
                // disposed the page (see `history_loader::read_cursor`).
                let Some(slug) = params.try_with(|p| p.get("category").unwrap_or_default()) else {
                    return ().into_any();
                };
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
                        // `try_*` in this page's nested closures: Leptos 0.7
                        // drops them a task hop after the route disposed the
                        // page, and a store write in between re-runs them
                        // (see `history_loader::read_cursor`).
                        {move || {
                            let n = shown_order.try_with(Vec::len).unwrap_or_default();
                            if n == 1 { "1 topic".to_string() } else { format!("{n} topics") }
                        }}
                    </span>
                    // Always laid out, hidden at zero: its appearing never
                    // moves the list below.
                    <button
                        type="button"
                        class=move || if updated.try_get().unwrap_or(0) == 0 {
                            UPDATED_HIDDEN_CLASS
                        } else {
                            UPDATED_CLASS
                        }
                        disabled=move || updated.try_get().unwrap_or(0) == 0
                        aria-label=move || updated_accessible_name(updated.try_get().unwrap_or(0))
                        title="Re-sort by latest activity"
                        on:click=move |_| {
                            let newest = newest_known.get_untracked();
                            let now_secs = (js_sys::Date::now() / 1000.0) as u64;
                            let Some(this) = visit.try_get_untracked() else {
                                return;
                            };
                            // Only this visit's board (never the last section's).
                            let Some(Some(shown)) = topics
                                .try_with_untracked(|sorted| {
                                    board.try_update_value(|(for_visit, b)| {
                                        (*for_visit == this).then(|| {
                                            b.repaint(sorted, newest, now_secs, &is_deleted);
                                            b.shown().to_vec()
                                        })
                                    })
                                })
                                .flatten()
                            else {
                                return;
                            };
                            order.set((Some(this), shown));
                        }
                    >
                        {move || updated_label(updated.try_get().unwrap_or(0))}
                    </button>
                </div>

                <Show when=move || {
                    is_authed.try_get().unwrap_or(false) && section_loading.try_get() == Some(false)
                }>
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
                let Some(branch) = branch.try_get() else {
                    return ().into_any();
                };
                match branch {
                    ListBranch::Skeleton { keys } => view! {
                        <TopicListSkeleton
                            status=if keys {
                                "Fetching your keys for this zone\u{2026}"
                            } else {
                                "Loading topics\u{2026}"
                            }
                            visible_status=keys
                        />
                    }.into_any(),
                    ListBranch::List(cid) => {
                        // Topics are newest first, so older history loads at
                        // the END of the list: scrolling there (or the
                        // control) pages back until the start of the channel.
                        let history_cid = Signal::from(channel_id);
                        let history_gated = Signal::derive(move || zone_is_gated(&category_slug(), &load_zones()));
                        // The complete root list already lists every topic:
                        // channel paging (older or newer) would add none.
                        let topics_complete = Signal::derive(move || {
                            channel_id
                                .get()
                                .is_some_and(|c| store.topic_roots_complete(&c))
                        });
                        // Older pages are not pulled until the root list has
                        // answered (before that, dormant roots would land in a
                        // list already on screen), failed, or the first-paint
                        // hold has expired: a slow or refusing relay never
                        // switches paging off.
                        let older_exhausted = Signal::derive(move || {
                            !older_paging_armed(
                                topics_complete.get(),
                                roots_answered.get(),
                                roots_failed.get(),
                                hold_expired_here.get(),
                            )
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
                                channel_id=cid
                                category=category_for_topics.get_untracked()
                                order=shown_order.into()
                                topics=by_id
                            />
                            <crate::components::history_loader::HistoryLoader
                                channel_id=history_cid
                                gated=history_gated
                                label="Load older topics"
                                exhausted=older_exhausted
                            />
                        }.into_any()
                    }
                    ListBranch::Unavailable { heading, detail } => view! {
                        <div class="glass-card p-8 text-center">
                            <h2 class="text-xl font-bold text-white mb-2">{heading}</h2>
                            <p class="text-gray-400 text-sm mb-4">{detail}</p>
                            <A href=base_href(&format!("/{}", untrack(category_url_slug))) attr:class="za-text hover:opacity-80 text-sm underline">
                                "Back to zone"
                            </A>
                        </div>
                    }.into_any(),
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
    let mut tags = crate::topics::topic_root_tags(section_channel_id);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_return_to_a_section_is_a_new_visit() {
        let a = || Some("a".to_string());
        let first = next_visit(None, a());
        assert_eq!(
            next_visit(Some(&first), a()),
            first,
            "same channel, same visit"
        );
        let b = next_visit(Some(&first), Some("b".to_string()));
        let again = next_visit(Some(&b), a());
        assert_eq!(again.0, a());
        assert_ne!(
            again, first,
            "A -> B -> A: a stale timer from the first visit is ignored"
        );
    }

    #[test]
    fn loading_shows_skeleton_rows() {
        assert_eq!(
            list_branch(None, Lookup::Loading, None, || true),
            ListBranch::Skeleton { keys: false }
        );
        assert_eq!(
            list_branch(None, Lookup::KeysLoading, Some("c".into()), || true),
            ListBranch::Skeleton { keys: true }
        );
    }

    #[test]
    fn a_found_list_is_held_until_it_may_paint() {
        let cid = || Some("c".to_string());
        assert_eq!(
            list_branch(None, Lookup::Found, cid(), || false),
            ListBranch::Skeleton { keys: false }
        );
        assert_eq!(
            list_branch(None, Lookup::Found, cid(), || true),
            ListBranch::List("c".into())
        );
        // An authoritatively empty section is held the same way, then
        // shows TopicList's "No topics yet".
        assert_eq!(
            list_branch(None, Lookup::NotFound, cid(), || true),
            ListBranch::List("c".into())
        );
    }

    #[test]
    fn a_painted_list_stays_painted_and_the_same_value() {
        // The memo's value is unchanged, so the branch is not rebuilt; the
        // readiness inputs are not even read.
        let prev = ListBranch::List("c".into());
        assert_eq!(
            list_branch(Some(&prev), Lookup::Found, Some("c".into()), || {
                panic!("readiness is not re-checked once painted")
            }),
            prev
        );
        // Found and NotFound are one branch: the first topic arriving in an
        // empty section does not rebuild the list.
        assert_eq!(
            list_branch(Some(&prev), Lookup::NotFound, Some("c".into()), || false),
            prev
        );
        // Another section starts afresh.
        assert_eq!(
            list_branch(Some(&prev), Lookup::Found, Some("d".into()), || false),
            ListBranch::Skeleton { keys: false }
        );
    }

    #[test]
    fn absence_and_timeouts_have_their_own_wording() {
        let heading = |b: ListBranch| match b {
            ListBranch::Unavailable { heading, .. } => heading,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            heading(list_branch(
                None,
                Lookup::TimedOut,
                Some("c".into()),
                || true
            )),
            "Topics Unavailable"
        );
        assert_eq!(
            heading(list_branch(None, Lookup::TimedOut, None, || true)),
            "Section Unavailable"
        );
        assert_eq!(
            heading(list_branch(None, Lookup::KeysTimedOut, None, || true)),
            "Topics Unavailable"
        );
        assert_eq!(
            heading(list_branch(None, Lookup::NotFound, None, || true)),
            "Section Not Found"
        );
    }
}
