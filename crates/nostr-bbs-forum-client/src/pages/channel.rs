//! Single channel view page -- the FLAT, linear chat of one channel (kind-42).
//! Route: /chat/:channel_id
//!
//! ## Redirect to the threaded topic-list (soak-fix 2026-07)
//!
//! This page's flat composer publishes ROOT-only kind-42 events (only
//! `["e", channel_id, "", "root"]`, no NIP-10 "reply" marker), so a post made
//! here becomes a NEW TOPIC rather than a threaded reply. Every deep-link that
//! used to land here (notifications, search, bookmarks, note-view, channel
//! cards) is therefore REDIRECTED to the section topic-list
//! (`/:category/:section`, [`crate::pages::SectionPage`]), whose
//! per-topic [`crate::pages::ThreadPage`] composer threads replies
//! correctly. Fixing it at this single resolver covers all entry points at once.
//!
//! The redirect resolves `channel_id` → its owning zone/section from the shared
//! [`ChannelStore`] and navigates (with `replace`) as soon as that is known. The
//! flat view is only ever shown as a graceful FALLBACK for a channel that never
//! resolves (e.g. a stale link to a deleted channel) — while resolution is
//! pending a neutral spinner shows instead of the root-only composer.
//!
//! ## Relationship to the BBS section view (#8 reconciliation)
//!
//! A *section* (kind-40 channel) is presented two ways:
//! - `/forums/:category/:section` ([`crate::pages::SectionPage`]) — the
//!   BBS TOPIC LIST: kind-42 roots with reply counts, the canonical browse view.
//! - `/chat/:channel_id` (this page) — the flat, real-time chat log of every
//!   message in the channel, now only reached as the unresolvable-channel
//!   fallback described above.
//!
//! When the fallback flat view IS shown it offers a "View as topics" link back
//! to the channel's BBS section view (with the privacy-hashed section slug, #9);
//! that link is omitted when the channel's owning zone cannot be resolved.

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::{use_navigate, use_params_map};
use leptos_router::NavigateOptions;
use nostr_bbs_core::NostrEvent;
use std::rc::Rc;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::badge::{Badge, BadgeVariant};
use crate::components::channel_stats::ChannelStats;
use crate::components::export_modal::ExportModal;
use crate::components::mention_text::normalise_mention_pubkey;
use crate::components::message_bubble::{MessageBubble, MessageData};
use crate::components::message_input::MessageInput;
use crate::components::pinned_messages::{PinnedMessage, PinnedMessages};
use crate::components::thread_view::ThreadReply;
use crate::relay::{ConnectionState, Filter, RelayConnection};
#[allow(unused_imports)]
use crate::stores::channels::ChannelStore;
use crate::stores::read_position::use_read_positions;
use crate::stores::zones::{load_zones, section_to_zone};
use crate::utils::bootstrap::{derive_phase, BootstrapSignals};
use crate::utils::reconcile::{absent_from, id_set, Reconciliation};
use crate::utils::section_url::canonical_section_path;
use crate::utils::zone_theme::zone_accent_style_cfg;
use crate::utils::{arrow_left_svg, set_timeout_once};

/// Bounded deadline for a deep-link bootstrap, in milliseconds.
///
/// ADR-092 closeout: this is a FAILURE deadline, not a success timer. When it
/// fires without a receipt the page reports a named failure; when a receipt
/// arrives after it, the receipt still wins (see
/// [`crate::utils::bootstrap::derive_phase`]).
const BOOTSTRAP_DEADLINE_MS: i32 = 8000;

/// Parsed channel metadata from the kind 40 event.
#[derive(Clone, Debug, PartialEq)]
struct ChannelHeader {
    name: String,
    description: String,
    /// Whether the channel is archived (no new messages allowed).
    archived: bool,
}

/// Single channel view: message list + compose input.
#[component]
pub fn ChannelPage() -> impl IntoView {
    let relay = expect_context::<RelayConnection>();
    let auth = use_auth();
    let conn_state = relay.connection_state();

    let params = use_params_map();
    let channel_id = move || params.read().get("channel_id").unwrap_or_default();

    // BBS topic-list PATH for this channel (app-relative, no `FORUM_BASE`):
    // resolve the channel (and thus its owning zone) from the shared store,
    // then build the privacy-hashed section URL (#9). `None` when the
    // channel/zone is not yet known.
    //
    // Two consumers, one resolver: the raw path feeds `use_navigate` in the
    // flat→threaded redirect below (the router re-adds the base), and
    // `section_topics_href` adds the base for the fallback "View as topics"
    // `<A>` link.
    let section_topics_path = {
        let store = use_context::<ChannelStore>();
        Signal::derive(move || {
            let raw = channel_id();
            if raw.is_empty() {
                return None;
            }
            let store = store?;
            let zones = load_zones();
            let needle_lower = raw.to_lowercase();
            store.channels.with(|list| {
                list.iter()
                    .find(|c| {
                        c.id == raw
                            || c.name.to_lowercase() == needle_lower
                            || c.section.to_lowercase() == needle_lower
                    })
                    .and_then(|c| canonical_section_path(c, &zones))
            })
        })
    };
    let section_topics_href =
        Signal::derive(move || section_topics_path.get().map(|p| base_href(&p)));

    // Route the flat view to the THREADED topic-list (soak-fix 2026-07).
    //
    // The flat composer on this page publishes ROOT-only kind-42 events (only
    // `["e", channel_id, "", "root"]`, no NIP-10 "reply" marker), so every post
    // made here becomes a NEW TOPIC instead of a threaded reply — the reported
    // "reply creates a new topic" bug. Every deep-link that used to land here
    // (notifications, search, bookmarks, note-view, channel cards) is redirected
    // to the section topic-list, whose per-topic `ThreadPage` composer threads
    // replies correctly. Doing it here, at the single resolver, fixes all of
    // those entry points at once.
    //
    // `replace` so the flat URL never lingers in history (Back returns to where
    // the deep-link was clicked, not into a redirect bounce). `redirected`
    // guards a single fire. Resolution waits on the store: until the owning zone
    // is known the target is `None`, the flat view is withheld (a neutral
    // spinner shows), and the flat composer is only ever mounted as a graceful
    // fallback for a channel that never resolves (e.g. a stale link to a deleted
    // channel).
    let navigate = StoredValue::new(use_navigate());
    let redirected = RwSignal::new(false);
    Effect::new(move |_| {
        if redirected.get_untracked() {
            return;
        }
        if let Some(path) = section_topics_path.get() {
            redirected.set(true);
            navigate.with_value(|nav| {
                nav(
                    &path,
                    NavigateOptions {
                        replace: true,
                        ..Default::default()
                    },
                )
            });
        }
    });

    // Only reveal the flat composer once the channel proves unresolvable: the
    // store has finished its initial channel load (EOSE) and still has no owning
    // zone for this id. Before that we are either about to redirect (target
    // resolved) or still waiting, so the redirect spinner shows instead of the
    // root-only composer.
    let store_eose = use_context::<ChannelStore>().map(|s| s.eose_received);
    let show_flat_fallback = Signal::derive(move || {
        section_topics_path.get().is_none() && store_eose.map(|s| s.get()).unwrap_or(true)
    });

    // Zone accent carry-through (issue #29): /chat/:channel_id has no :category
    // route param, so resolve the channel's owning zone from its `section` tag
    // via the canonical resolver and expose its signature colour as the
    // `--zone-accent` CSS custom property on the page root. The prominent accent
    // elements below read it through `var(--zone-accent)`, so the chat page wears
    // the same colour as its zone hero / category page. Defaults to the neutral
    // accent until the channel resolves from the store.
    let zone_accent = {
        let store = use_context::<ChannelStore>();
        Signal::derive(move || {
            let raw = channel_id();
            let zones = load_zones();
            let resolved_zone = store.and_then(|store| {
                let needle_lower = raw.to_lowercase();
                store.channels.with(|list| {
                    list.iter()
                        .find(|c| {
                            c.id == raw
                                || c.name.to_lowercase() == needle_lower
                                || c.section.to_lowercase() == needle_lower
                        })
                        .and_then(|c| {
                            let section = if c.section.is_empty() {
                                raw.clone()
                            } else {
                                c.section.clone()
                            };
                            section_to_zone(&section, &zones)
                        })
                })
            });
            // Fall back to resolving the raw param as a section, then to the
            // first zone, so the root always carries a coherent accent.
            let zone = resolved_zone
                .or_else(|| section_to_zone(&raw, &zones))
                .unwrap_or_default();
            let accent = zones
                .iter()
                .find(|z| z.id == zone)
                .and_then(|z| z.accent_hex.clone());
            zone_accent_style_cfg(&zone, accent.as_deref())
        })
    };

    // Read-position store for mark-as-read
    let read_store = use_read_positions();

    // State
    let messages = RwSignal::new(Vec::<MessageData>::new());
    // The kind-40 header as fetched (archived flag, first paint)...
    let channel_info_raw: RwSignal<Option<ChannelHeader>> = RwSignal::new(None);
    // ...and what is shown: name and description from the store's channel
    // entry, which folds the latest kind-41 edit (fold_meta_into), exactly as
    // the channel list and section/thread headers do. A renamed channel shows
    // one name everywhere.
    let store_for_header = use_context::<ChannelStore>();
    let channel_info = Memo::new(move |_| {
        let raw = channel_info_raw.get()?;
        let cid = channel_id();
        let folded = store_for_header.and_then(|s| {
            s.channels
                .with(|list| list.iter().find(|c| c.id == cid).cloned())
        });
        Some(effective_header(raw, folded.as_ref()))
    });
    let pinned = RwSignal::new(Vec::<PinnedMessage>::new());
    // Held in a `StoredValue` (Copy) so the reply-divider closure below can be
    // move-captured into the `Show`-gated flat view without making that view
    // `FnOnce`.
    let last_read_event_id = StoredValue::new(read_store.last_read_event_id(&channel_id()));
    let error_msg: RwSignal<Option<String>> = RwSignal::new(None);
    let show_export = RwSignal::new(false);
    // Paged history: the channel id and `#e` needles of the first-page REQ,
    // reused by every older page, and whether the reader is signed in (only
    // an authenticated answer then counts; see `ChannelStore::load_older`).
    let history_needles = StoredValue::new(None::<(String, Vec<String>)>);
    let signed_in = auth.is_authenticated();

    // Derived signals for ChannelStats
    // The channel's true total (relay COUNT + live since), not the size of
    // the history window on screen.
    let store_for_count = use_context::<ChannelStore>();
    let message_count = Signal::derive(move || {
        let held = messages.with(Vec::len) as u32;
        let Some(store) = store_for_count else {
            return held;
        };
        history_needles
            .with_value(|n| n.as_ref().map(|(cid, _)| cid.clone()))
            .map_or(held, |cid| store.total_for(&cid).max(held))
    });
    let member_count = Signal::derive(move || {
        let msgs = messages.get();
        let mut unique = std::collections::HashSet::new();
        for m in &msgs {
            unique.insert(m.pubkey.as_str());
        }
        unique.len() as u32
    });
    let messages_container = NodeRef::<leptos::html::Div>::new();

    // Track subscription IDs for cleanup. `channel_sub_id` is the kind-40
    // by-id query; `replay_sub_ids` collects narrow kind-42 subs opened by
    // the on-discovery replay path so they get torn down on unmount —
    // without this, leaked subs from previous channel pages keep firing
    // into the global ChannelStore signals and trigger
    // "Tried to access a reactive value that has already been disposed"
    // panics under fast navigation.
    let channel_sub_id: RwSignal<Option<String>> = RwSignal::new(None);
    let replay_sub_ids: RwSignal<Vec<String>> = RwSignal::new(Vec::new());

    // -- Deep-link bootstrap receipts (ADR-092 closeout) ---------------------
    //
    // Success is an OBSERVED condition, never a clock. `metadata_eose` is the
    // relay signing off the kind-40 lookup, `replay_eose` the same for the
    // narrow kind-42 history query, and `messages_present` the target events
    // actually resolving into the store. The deadline below is a FAILURE path
    // only: when it fires without a receipt the page names the failure and
    // offers a retry instead of quietly clearing the spinner as if the channel
    // had loaded and were empty.
    let metadata_eose = RwSignal::new(false);
    let replay_eose = RwSignal::new(false);
    let bootstrap_deadline = RwSignal::new(false);
    // Bumped by the retry button; the subscription Effect reads it reactively
    // so a retry re-opens the queries and re-arms the deadline.
    let retry_nonce = RwSignal::new(0u32);

    // Clone relay for each closure that needs it
    let relay_for_sub = relay.clone();
    let relay_for_send = relay.clone();
    let zone_writer_for_send = crate::zone_crypto::store::ZoneWriter::capture();
    let relay_for_history = relay.clone();
    let relay_for_cleanup = relay;

    // Reactive header fallback (ADR-092): re-run whenever `store.channels`
    // changes, so a deep-link that arrives BEFORE the channel list has
    // loaded still transitions out of "Loading…" once metadata streams in.
    //
    // Also matches by `section` so slug-style URLs (e.g. /chat/home-lobby)
    // resolve as well as hex-id URLs.
    //
    // Note: the previous `ensure_subscribed` Effect was removed in favour of
    // the kind-40 by-id query below — that path already replays the channel's
    // kind-42 history once metadata arrives, and the duplicate Effect was
    // implicated in "Tried to access a reactive value that has already been
    // disposed" panics on deep-link unmount.
    if let Some(store) = use_context::<ChannelStore>() {
        Effect::new(move |_| {
            // Don't clobber a header already populated by the kind-40 query.
            if channel_info_raw.with_untracked(|c| c.is_some()) {
                return;
            }
            let cid = channel_id();
            if cid.is_empty() {
                return;
            }
            let needle_lower = cid.to_lowercase();
            store.channels.with(|list| {
                if let Some(found) = list.iter().find(|c| {
                    c.id == cid
                        || c.name.to_lowercase() == needle_lower
                        || c.section.to_lowercase() == needle_lower
                }) {
                    channel_info_raw.set(Some(ChannelHeader {
                        name: found.name.clone(),
                        description: found.description.clone(),
                        archived: false,
                    }));
                }
            });
        });
    }

    // Subscribe to channel metadata (kind 40) when connected.
    // Messages come from ChannelStore's shared kind-42 subscription — the
    // Cloudflare DO relay ignores duplicate REQs on the same WebSocket, so
    // we cannot create a second kind-42 subscription.
    let applied_retry_nonce = StoredValue::new(0u32);
    Effect::new(move |_| {
        let state = conn_state.get();
        let cid = channel_id();
        // Read reactively so pressing "Try again" re-opens the queries.
        let nonce = retry_nonce.get();
        if nonce != applied_retry_nonce.get_value() {
            applied_retry_nonce.set_value(nonce);
            // Tear the previous attempt down before starting another, so a
            // retry cannot leak REQs that keep firing into the shared store.
            if let Some(id) = channel_sub_id.get_untracked() {
                relay_for_sub.unsubscribe(&id);
            }
            for id in replay_sub_ids.get_untracked() {
                relay_for_sub.unsubscribe(&id);
            }
            channel_sub_id.set(None);
            replay_sub_ids.set(Vec::new());
            metadata_eose.set(false);
            replay_eose.set(false);
            bootstrap_deadline.set(false);
        }
        if state != ConnectionState::Connected || cid.is_empty() {
            return;
        }

        // Already subscribed
        if channel_sub_id.get_untracked().is_some() {
            return;
        }

        error_msg.set(None);

        // Fetch channel metadata (kind 40, by event id)
        let channel_filter = Filter {
            ids: Some(vec![cid.clone()]),
            kinds: Some(vec![40]),
            ..Default::default()
        };

        let channel_info_sig = channel_info_raw;
        let store_for_kind40 = use_context::<ChannelStore>();
        // Captured here, inside the effect's owner: the relay callbacks below
        // run without one (ADR-2016 decryption at ingest).
        let zone_keys = crate::zone_crypto::store::try_use_zone_key_store();
        let relay_for_retry = relay_for_sub.clone();
        let on_channel_event = Rc::new(move |event: NostrEvent| {
            if event.kind == 40 {
                let header = parse_channel_metadata(&event.content);
                channel_info_sig.set(Some(header));

                // ADR-092: seed the channel into the global store so the
                // shared kind-42 resolver can match historical events. Also
                // open a *retry* kind-42 sub keyed on all known identifiers
                // (hex id + name + section) — the broad kind-42 sub fires
                // before this kind-40-by-id query completes, so any events
                // for this channel that arrived earlier were dropped by the
                // resolver (channel wasn't in store.channels yet). The retry
                // sub replays them.
                if let Some(store) = store_for_kind40.as_ref() {
                    let (name, description, picture) =
                        crate::stores::channels::parse_channel_content(&event.content);
                    let section = event
                        .tags
                        .iter()
                        .find(|t| t.len() >= 2 && t[0] == "section")
                        .map(|t| t[1].clone())
                        .unwrap_or_default();
                    let meta = crate::stores::channels::ChannelMeta {
                        id: event.id.clone(),
                        name: name.clone(),
                        description,
                        section: section.clone(),
                        picture,
                        created_at: event.created_at,
                    };
                    store.channels.update(|list| {
                        if !list.iter().any(|c| c.id == meta.id) {
                            list.push(meta);
                        }
                    });

                    // The channel's newest page of kind-42 history, over all
                    // identifier variants (hex id + name + section: legacy
                    // posts may carry slug-style e-tags). It is the first page
                    // of the paged history (`ChannelStore::load_older` walks
                    // back from it) and stays open for live posts.
                    //
                    // Until the authoritative answer, deliveries are buffered
                    // and applied in one store update per EOSE instead of one
                    // per event. The answer counts as authoritative once it is
                    // authenticated, or at once for a signed-out reader: an
                    // anonymous answer omits gated zones and must not set the
                    // "start of history" mark for a member. Deliveries are
                    // counted before admission, as the relay sent them.
                    let store_for_replay = *store;
                    let zone_keys_for_replay = zone_keys;
                    let cid_for_replay = event.id.clone();
                    let wait_auth = signed_in.get_untracked();
                    #[derive(Default)]
                    struct FirstPage {
                        delivered: u64,
                        oldest: Option<u64>,
                        buffered: Vec<(String, NostrEvent)>,
                        live: bool,
                    }
                    let first = Rc::new(std::cell::RefCell::new(FirstPage::default()));
                    let first_for_event = first.clone();
                    let cid_for_event = cid_for_replay.clone();
                    let on_replay = Rc::new(move |ev: NostrEvent| {
                        let ts = ev.created_at;
                        let ingested =
                            store_for_replay.ingest(zone_keys_for_replay, ev, &cid_for_event);
                        let mut f = first_for_event.borrow_mut();
                        if f.live {
                            drop(f);
                            if let Some(x) = ingested {
                                store_for_replay.apply_page(vec![x]);
                            }
                            return;
                        }
                        f.delivered += 1;
                        f.oldest = Some(f.oldest.map_or(ts, |o| o.min(ts)));
                        if let Some(x) = ingested {
                            f.buffered.push(x);
                        }
                    });
                    let mut needles: Vec<String> = vec![event.id.clone()];
                    if !name.is_empty() {
                        needles.push(name);
                    }
                    if !section.is_empty() {
                        needles.push(section);
                    }
                    history_needles.set_value(Some((cid_for_replay.clone(), needles.clone())));
                    store_for_replay.request_total(&relay_for_retry, &cid_for_replay);
                    // EOSE on the narrow history query is the relay's own
                    // receipt that it has sent the newest page it holds for
                    // this channel — the real bootstrap-success signal (ADR-092).
                    let on_replay_eose = Rc::new(move |authed: bool| {
                        let authoritative = authed || !wait_auth;
                        let (buffered, page) = {
                            let mut f = first.borrow_mut();
                            if f.live {
                                return;
                            }
                            f.live = authoritative;
                            let page = crate::stores::channels::PageOutcome {
                                delivered: f.delivered,
                                oldest: f.oldest,
                            };
                            (std::mem::take(&mut f.buffered), page)
                        };
                        store_for_replay.apply_page(buffered);
                        if authoritative {
                            store_for_replay.record_first_page(&cid_for_replay, page);
                        }
                        replay_eose.set(true);
                    });
                    let sub_id = relay_for_retry.subscribe_with_receipt(
                        vec![Filter {
                            kinds: Some(vec![42]),
                            e_tags: Some(needles),
                            limit: Some(crate::stores::channels::HISTORY_PAGE),
                            ..Default::default()
                        }],
                        on_replay,
                        on_replay_eose,
                    );
                    replay_sub_ids.update(|ids| ids.push(sub_id));
                }
            }
        });

        // EOSE on the kind-40 lookup: the relay has answered. If nothing came
        // back the channel is not there, which is an ANSWER, not a timeout —
        // `channel_absent` below turns it into a named failure straight away
        // rather than making the user wait out the deadline.
        let on_metadata_eose = Rc::new(move || {
            metadata_eose.set(true);
        });
        let id1 = relay_for_sub.subscribe(
            vec![channel_filter],
            on_channel_event,
            Some(on_metadata_eose),
        );
        channel_sub_id.set(Some(id1));

        // Arm the bounded FAILURE deadline for this attempt. It never reports
        // success: `derive_phase` checks the receipts first, so an answer that
        // arrives after the deadline still resolves to Ready.
        set_timeout_once(
            move || {
                bootstrap_deadline.set(true);
            },
            BOOTSTRAP_DEADLINE_MS,
        );
    });

    // Read messages from ChannelStore's shared kind-42 subscription.
    // The store resolves each event's channel identity and groups them by ID.
    // This Effect re-runs whenever channel_messages changes (new events arrive).
    Effect::new(move |_| {
        let raw_cid = channel_id();
        if raw_cid.is_empty() {
            return;
        }

        let store = match use_context::<ChannelStore>() {
            Some(s) => s,
            None => return,
        };

        // Resolve slug/section/id to a concrete cid using the store's lookup.
        // ADR-092: deep-links via slug must still locate their events.
        let cid = store.resolve_channel(&raw_cid).unwrap_or(raw_cid.clone());

        // The rendered set is a PROJECTION of the store snapshot, never an
        // accumulation of everything ever delivered (ADR-091 closeout). A
        // channel whose entry has disappeared entirely reconciles against an
        // empty snapshot, which clears the view rather than freezing the last
        // state on screen.
        //
        // Work out the diff WITHOUT touching the signal, so a store update that
        // does not affect this channel writes nothing. An unconditional
        // `update` notifies subscribers even when the list is unchanged, which
        // re-runs the auto-scroll effect and pulls the viewport to the bottom
        // while the reader is scrolled up. The store is read in place (`with`),
        // never cloned: with paged history a channel can hold tens of
        // thousands of messages, and only the new ones are copied out.
        let (stale, to_add, recontent) = store.channel_messages.with(|all| {
            let channel_events: &[NostrEvent] = all
                .get(&cid)
                .or_else(|| all.get(&raw_cid))
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            messages.with_untracked(|list| {
                let present = id_set(channel_events, |e| e.id.as_str());
                let stale: std::collections::HashSet<String> = list
                    .iter()
                    .filter(|m| !present.contains(m.id.as_str()))
                    .map(|m| m.id.clone())
                    .collect();
                let rendered = id_set(&list[..], |m| m.id.as_str());
                let to_add: Vec<NostrEvent> =
                    absent_from(channel_events, &rendered, |e| e.id.as_str())
                        .into_iter()
                        .cloned()
                        .collect();
                // A survivor whose text changed in the store: a zone key arrived
                // and its message decrypted (ADR-2016). Patched in place below.
                let by_id: std::collections::HashMap<&str, &str> = channel_events
                    .iter()
                    .map(|e| (e.id.as_str(), e.content.as_str()))
                    .collect();
                let recontent: std::collections::HashMap<String, String> = list
                    .iter()
                    .filter_map(|m| {
                        by_id
                            .get(m.id.as_str())
                            .filter(|c| **c != m.content)
                            .map(|c| (m.id.clone(), c.to_string()))
                    })
                    .collect();
                (stale, to_add, recontent)
            })
        });
        let outcome = Reconciliation {
            removed: stale.len(),
            added: to_add.len(),
        };
        if !outcome.changed() && recontent.is_empty() {
            return;
        }

        messages.update(|list| {
            // 1. Drop anything the store no longer has. This is the half that
            //    was missing: without it a NIP-09 deletion (or an EOSE prune)
            //    leaves the post on screen forever and the derived post/member
            //    counts can only ever go up.
            if !stale.is_empty() {
                list.retain(|m| !stale.contains(&m.id));
            }
            if !recontent.is_empty() {
                for m in list.iter_mut() {
                    if let Some(c) = recontent.get(&m.id) {
                        m.content = c.clone();
                    }
                }
            }

            // 2. Merge in what is new, in time order. Survivors are NOT
            //    rebuilt, so their per-message reactive state (thread replies)
            //    and the scroll anchor around them are preserved. The store
            //    hands events over sorted, so an older page is one merge of two
            //    sorted runs and a live post is an append, never a re-sort.
            let added: Vec<MessageData> = to_add
                .iter()
                .map(|event| message_data(event, &cid))
                .collect();
            merge_by_time(list, added);
        });
    });

    // -- Bootstrap phase (ADR-092 closeout) ----------------------------------
    //
    // Derived from receipts the page has actually observed, so "loaded" means
    // loaded. The deadline only ever produces a FAILURE, and a receipt that
    // arrives after it still wins.
    let store_for_phase = use_context::<ChannelStore>();
    let bootstrap = Memo::new(move |_| {
        let channel_resolved = channel_info.with(|c| c.is_some());
        let store_channels_ready = store_for_phase
            .map(|s| s.eose_received.get())
            .unwrap_or(false);
        let store_messages_ready = store_for_phase
            .map(|s| s.msg_eose_received.get())
            .unwrap_or(false);
        derive_phase(BootstrapSignals {
            connected: conn_state.get() == ConnectionState::Connected,
            channel_resolved,
            // The relay answered the kind-40 lookup AND the store finished its
            // channel list, and neither produced this channel: a definitive
            // negative, reported now rather than after the deadline.
            channel_absent: metadata_eose.get() && store_channels_ready && !channel_resolved,
            // Either the narrow history query or the store's broad kind-42
            // subscription signed off — both are real EOSE receipts.
            replay_complete: replay_eose.get() || store_messages_ready,
            messages_present: !messages.with(|m| m.is_empty()),
            deadline_passed: bootstrap_deadline.get(),
        })
    });
    let show_spinner = Signal::derive(move || bootstrap.get().is_pending());
    let bootstrap_failure = Signal::derive(move || {
        let phase = bootstrap.get();
        if phase.is_failed() {
            Some((phase.message().to_string(), phase.is_retryable()))
        } else {
            None
        }
    });

    // Retry: bump the nonce. The subscription Effect owns the relay handle, so
    // it does the teardown-and-reopen; this closure captures nothing but a
    // `Copy` signal, which keeps it usable from a reactive view.
    let do_retry = move |_| {
        retry_nonce.update(|n| *n = n.wrapping_add(1));
    };

    // -- Scroll: follow new posts, keep the reader's place across pages ----
    //
    // `near_bottom` is kept by the scroll handler: a new post at the bottom
    // pulls the view down only when the reader was already there and the
    // window holds the newest messages, never while they read history.
    //
    // A history page lands at one end and the bounded window evicts at the
    // other, so the height above the reader can grow or shrink in the same
    // update. `utils::scroll_anchor` notes a visible row before the page is
    // applied and scrolls by however far it moved afterwards; `paging` keeps
    // the follow-new-posts scroll out of the way meanwhile. The container
    // sets `overflow-anchor: none` so the browser's own anchoring does not
    // fight it.
    let near_bottom = StoredValue::new(true);
    let paging = StoredValue::new(false);
    let row_anchor = StoredValue::new_local(None::<crate::utils::scroll_anchor::Anchor>);
    let store_for_history = use_context::<ChannelStore>();
    type PageHooks = (Rc<dyn Fn()>, Rc<dyn Fn()>);
    let page_hooks = move || -> PageHooks {
        let before: Rc<dyn Fn()> = Rc::new(move || {
            paging.set_value(true);
            let container = messages_container
                .get_untracked()
                .map(web_sys::Element::from);
            row_anchor.set_value(crate::utils::scroll_anchor::capture(container.as_ref()));
        });
        let after: Rc<dyn Fn()> = Rc::new(move || {
            let anchor = row_anchor.try_update_value(Option::take).flatten();
            let container = messages_container
                .get_untracked()
                .map(web_sys::HtmlElement::from);
            if let Some(a) = anchor {
                crate::utils::scroll_anchor::restore(a, container);
            }
            // After the restore's zero-delay timeout.
            set_timeout_once(move || paging.set_value(false), 0);
        });
        (before, after)
    };
    let relay_for_newer = relay_for_history.clone();
    let request_older = StoredValue::new_local(Rc::new(move || {
        let Some(store) = store_for_history else {
            return;
        };
        let Some((cid, needles)) = history_needles.get_value() else {
            return;
        };
        let (before, after) = page_hooks();
        store.load_older(
            &relay_for_history,
            &cid,
            needles,
            signed_in.get_untracked(),
            before,
            after,
        );
    }) as Rc<dyn Fn()>);
    let request_newer = {
        let relay = relay_for_newer;
        StoredValue::new_local(Rc::new(move || {
            let Some(store) = store_for_history else {
                return;
            };
            let Some((cid, needles)) = history_needles.get_value() else {
                return;
            };
            let (before, after) = page_hooks();
            store.load_newer(
                &relay,
                &cid,
                needles,
                signed_in.get_untracked(),
                before,
                after,
            );
        }) as Rc<dyn Fn()>)
    };
    let on_messages_scroll = move |_: leptos::ev::Event| {
        let Some(c) = messages_container.get_untracked() else {
            return;
        };
        let el: web_sys::HtmlElement = c.into();
        let top = el.scroll_top();
        let from_bottom = el.scroll_height() - top - el.client_height();
        near_bottom.set_value(from_bottom < 120);
        if top < 400 {
            request_older.with_value(|f| f());
        } else if from_bottom < 400 {
            // Only does anything while the window is detached from the newest.
            request_newer.with_value(|f| f());
        }
    };
    // The history state of this channel, for the indicator above the list.
    let history_state = Signal::derive(move || {
        let store = store_for_history?;
        let cid = history_needles.with_value(|n| n.as_ref().map(|(c, _)| c.clone()))?;
        // Tracks `history` so the indicator follows each page.
        Some(store.history_cursor(&cid))
    });
    // The id of the first message after the reader's last-read one, where the
    // "New messages" divider goes.
    let divider_before = Memo::new(move |_| {
        let last_read = last_read_event_id.get_value();
        if last_read.is_empty() {
            return None;
        }
        messages.with(|list| {
            let i = list.iter().position(|m| m.id == last_read)?;
            list.get(i + 1).map(|m| m.id.clone())
        })
    });

    let last_newest = StoredValue::new(None::<String>);
    Effect::new(move |_| {
        let (count, newest, last) = messages.with(|m| {
            (
                m.len(),
                m.last().map(|x| x.id.clone()),
                m.last().map(|x| (x.id.clone(), x.created_at)),
            )
        });
        let prev_newest = last_newest.get_value();
        last_newest.set_value(newest.clone());
        let attached =
            history_state.with_untracked(|c| c.as_ref().is_none_or(|c| c.newer_from.is_none()));
        if let Some(container) = messages_container.get() {
            let el: web_sys::HtmlElement = container.into();
            if newest != prev_newest && near_bottom.get_value() && attached && !paging.get_value() {
                set_timeout_once(
                    move || {
                        el.set_scroll_top(el.scroll_height());
                    },
                    50,
                );
            }
        }
        // Mark channel as read when messages load or new ones arrive (never
        // backwards: `mark_read` only advances).
        if count > 0 {
            if let Some((id, created_at)) = last {
                let cid = channel_id();
                read_store.mark_read(&cid, &id, created_at);
            }
        }
    });

    // Cleanup on unmount: tear down the kind-40 by-id sub AND every
    // narrow kind-42 replay sub opened during this page's lifetime. Leaked
    // subs would otherwise keep firing into global ChannelStore signals
    // from disposed reactive scopes, surfacing as
    // "Tried to access a reactive value that has already been disposed"
    // panics on subsequent navigations.
    on_cleanup(move || {
        if let Some(id) = channel_sub_id.get_untracked() {
            relay_for_cleanup.unsubscribe(&id);
        }
        let ids = replay_sub_ids.get_untracked();
        for id in ids {
            relay_for_cleanup.unsubscribe(&id);
        }
    });

    // Draft restore: a post refused before sending (encrypted zone without a
    // key, ADR-2016) goes back into the composer instead of being lost.
    let restore_failed = RwSignal::new(None::<String>);

    // Send message handler
    let do_send_text = move |(content, mention_pubkeys): (String, Vec<String>)| {
        let cid = channel_id();
        if cid.is_empty() {
            return;
        }

        let pubkey = auth.pubkey().get_untracked().unwrap_or_default();
        if pubkey.is_empty() {
            error_msg.set(Some("Not authenticated".to_string()));
            return;
        }

        let now = (js_sys::Date::now() / 1000.0) as u64;
        let content_for_index = content.clone();
        // Root e-tag first, then one ["p", pubkey] per @-mention selected in
        // the composer so mentioned users are addressable per NIP-10.
        let mut tags = vec![vec![
            "e".to_string(),
            cid.clone(),
            String::new(),
            "root".to_string(),
        ]];
        for pk in mention_pubkeys {
            if let Some(hex) = normalise_mention_pubkey(&pk) {
                if !tags.iter().any(|t| t[0] == "p" && t[1] == hex) {
                    tags.push(vec!["p".to_string(), hex]);
                }
            }
        }
        // Also resolve @handles typed directly into the content (not picked from
        // the dropdown) so e.g. @junkiejarvis still gets a ["p", pubkey] tag and
        // the relay delivers the message to the agent's #p-filtered subscription.
        for hex in crate::components::mention_autocomplete::resolve_content_mentions(&content) {
            if !tags
                .iter()
                .any(|t| t.len() >= 2 && t[0] == "p" && t[1] == hex)
            {
                tags.push(vec!["p".to_string(), hex]);
            }
        }
        let unsigned = nostr_bbs_core::UnsignedEvent {
            pubkey: pubkey.clone(),
            created_at: now,
            kind: 42,
            tags,
            content,
        };

        let relay = relay_for_send.clone();
        let zone_writer = zone_writer_for_send;
        wasm_bindgen_futures::spawn_local(async move {
            // Encrypted zone (ADR-2016): encrypt to the zone key, or refuse
            // without one — the draft is kept, nothing is sent in plaintext.
            let unsigned = match zone_writer.prepare(&cid, auth.get_signer(), unsigned).await {
                Ok(u) => u,
                Err(e) => {
                    error_msg.set(Some(e));
                    restore_failed.set(Some(content_for_index));
                    return;
                }
            };
            match auth.sign_event_async(unsigned).await {
                Ok(signed) => {
                    relay.publish(&signed);

                    // No indexing from the client (sealed-search design):
                    // encrypted zones are indexed offline into sealed per-zone
                    // shards searched in the browser, public zones get no
                    // search, and server mode (Phase 3) indexes server-side.
                }
                Err(e) => {
                    error_msg.set(Some(e));
                }
            }
        });
    };

    let send_callback = Callback::new(do_send_text);
    // Pod container for attached images: this channel's zone (strict).
    let store_for_media = use_context::<ChannelStore>();
    let channel_media_target = Signal::derive(move || {
        let cid = channel_id();
        let section = store_for_media.and_then(|st| {
            st.channels
                .with(|cs| cs.iter().find(|c| c.id == cid).map(|c| c.section.clone()))
        });
        crate::stores::zones::media_target_for_section(section.as_deref())
    });
    // MessageInput fires `on_send` alongside `on_send_with_mentions`; all
    // publish work lives in the mentions path, so the plain path is a no-op.
    let noop_send = Callback::new(|_: String| {});
    let is_authed = auth.is_authenticated();

    // Channel archived state (derived from metadata)
    let is_archived = Memo::new(move |_| channel_info.get().map(|c| c.archived).unwrap_or(false));

    // Derive avatar letter from channel name
    let avatar_letter = move || {
        channel_info
            .get()
            .map(|c| {
                c.name
                    .chars()
                    .next()
                    .unwrap_or('#')
                    .to_uppercase()
                    .to_string()
            })
            .unwrap_or_else(|| "#".to_string())
    };

    view! {
        <Show
            when=move || show_flat_fallback.get()
            fallback=|| view! {
                // Resolving the owning zone → about to redirect to the threaded
                // topic-list. Neutral spinner (matches the app-level redirect
                // spinner) rather than a flash of the root-only flat composer.
                <div class="flex flex-col items-center justify-center h-[calc(100vh-64px)] gap-3">
                    <div class="animate-spin w-6 h-6 border-2 border-amber-400 border-t-transparent rounded-full"></div>
                    <span class="text-gray-400 text-sm">"Opening topics\u{2026}"</span>
                </div>
            }
        >
        <div class="flex flex-col h-[calc(100vh-64px)]" style=move || zone_accent.get()>
            // Channel header
            <div class="bg-gray-800 border-b border-gray-700 relative">
                <div class="p-4">
                    <div class="max-w-4xl mx-auto">
                        <div class="flex items-center gap-3 mb-1">
                            <A href=base_href("/chat") attr:class="text-gray-400 hover:text-white transition-colors p-1 rounded hover:bg-gray-700">
                                {arrow_left_svg()}
                            </A>
                            // Channel avatar — tinted with the zone accent (#29)
                            <div
                                class="w-8 h-8 rounded-full text-[color:var(--zone-accent)] flex items-center justify-center text-sm font-bold flex-shrink-0"
                                style="background:color-mix(in srgb, var(--zone-accent) 20%, transparent)"
                            >
                                {avatar_letter}
                            </div>
                            <h1 class="text-2xl font-bold text-white">
                                {move || {
                                    channel_info.get()
                                        .map(|c| c.name)
                                        .unwrap_or_else(|| "Loading...".to_string())
                                }}
                            </h1>
                            // "View as topics": jump to the BBS topic-list view
                            // of this same channel (#8 reconciliation). Hidden
                            // until the owning zone resolves from the store.
                            {move || section_topics_href.get().map(|href| view! {
                                <A
                                    href=href
                                    attr:class="ml-auto flex items-center gap-1.5 text-xs text-[color:var(--zone-accent)] hover:opacity-80 border rounded-lg px-2.5 py-1 transition-colors"
                                    attr:style="border-color:color-mix(in srgb, var(--zone-accent) 30%, transparent)"
                                >
                                    <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <line x1="8" y1="6" x2="21" y2="6" stroke-linecap="round"/>
                                        <line x1="8" y1="12" x2="21" y2="12" stroke-linecap="round"/>
                                        <line x1="8" y1="18" x2="21" y2="18" stroke-linecap="round"/>
                                        <circle cx="3.5" cy="6" r="1" fill="currentColor"/>
                                        <circle cx="3.5" cy="12" r="1" fill="currentColor"/>
                                        <circle cx="3.5" cy="18" r="1" fill="currentColor"/>
                                    </svg>
                                    "View as topics"
                                </A>
                            })}
                        </div>
                        {move || {
                            channel_info.get().and_then(|c| {
                                if c.description.is_empty() {
                                    None
                                } else {
                                    Some(view! {
                                        <p class="text-sm text-gray-400 ml-14">
                                            {c.description}
                                        </p>
                                    })
                                }
                            })
                        }}
                        <div class="flex items-center gap-2 mt-1 ml-14">
                            <ChannelStats
                                message_count=message_count
                                member_count=member_count
                            />
                            // Export button
                            <button
                                class="text-gray-500 hover:text-[color:var(--zone-accent)] transition-colors p-1 rounded hover:bg-gray-700/50"
                                title="Export messages"
                                on:click=move |_| show_export.set(true)
                            >
                                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" stroke-linecap="round" stroke-linejoin="round"/>
                                    <polyline points="7 10 12 15 17 10" stroke-linecap="round" stroke-linejoin="round"/>
                                    <line x1="12" y1="15" x2="12" y2="3" stroke-linecap="round"/>
                                </svg>
                            </button>
                            // Connection indicator
                            {move || {
                                let state = conn_state.get();
                                match state {
                                    ConnectionState::Connected => view! {
                                        <Badge text="Connected".to_string() variant=BadgeVariant::Success />
                                    }.into_any(),
                                    ConnectionState::Reconnecting => view! {
                                        <Badge text="Reconnecting".to_string() variant=BadgeVariant::Warning pulse=true />
                                    }.into_any(),
                                    _ => view! {
                                        <Badge text="Disconnected".to_string() variant=BadgeVariant::Error />
                                    }.into_any(),
                                }
                            }}
                        </div>
                    </div>
                </div>
                // Subtle bottom gradient line
                <div class="absolute bottom-0 left-0 right-0 h-px" style="background:linear-gradient(to right, transparent, color-mix(in srgb, var(--zone-accent) 20%, transparent), transparent)"></div>
            </div>

            // Error banner
            {move || {
                error_msg.get().map(|msg| view! {
                    <div class="max-w-4xl mx-auto p-2">
                        <div class="bg-yellow-900/50 border border-yellow-700 rounded-lg px-4 py-2 flex items-center justify-between">
                            <span class="text-yellow-200 text-sm">{msg}</span>
                            <button class="text-yellow-400 hover:text-yellow-200 text-xs ml-4"
                                on:click=move |_| error_msg.set(None)
                            >
                                "dismiss"
                            </button>
                        </div>
                    </div>
                })
            }}

            // Archive banner
            <Show when=move || is_archived.get()>
                <div class="max-w-4xl mx-auto px-4 pt-2">
                    <div class="bg-gray-800/80 border border-gray-600/50 rounded-lg px-4 py-3 flex items-center gap-3">
                        <svg class="w-5 h-5 text-gray-500 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="21 8 21 21 3 21 3 8" stroke-linecap="round" stroke-linejoin="round"/>
                            <rect x="1" y="3" width="22" height="5" rx="1" stroke-linecap="round" stroke-linejoin="round"/>
                            <line x1="10" y1="12" x2="14" y2="12" stroke-linecap="round"/>
                        </svg>
                        <span class="text-sm text-gray-400">
                            "This section is archived. No new messages can be posted."
                        </span>
                    </div>
                </div>
            </Show>

            // Messages area
            <div
                class="flex-1 overflow-y-auto bg-gray-900 relative"
                style="overflow-anchor: none"
                node_ref=messages_container
                on:scroll=on_messages_scroll
            >
                // Top fade gradient to indicate scrollability
                <div class="sticky top-0 left-0 right-0 h-6 bg-gradient-to-b from-gray-900 to-transparent z-10 pointer-events-none"></div>

                <div class="max-w-4xl mx-auto px-4 pb-4">
                    // Pinned messages banner
                    {
                        let cid = channel_id();
                        view! { <PinnedMessages channel_id=cid pinned=pinned /> }
                    }

                    // Bootstrap failure (ADR-092): a bounded deadline with no
                    // receipt, or a definitive "no such channel", is reported as
                    // a named failure. It is NEVER allowed to look like a
                    // successfully-loaded empty channel.
                    {move || {
                        bootstrap_failure.get().map(|(message, retryable)| view! {
                            <div
                                class="my-6 rounded-lg border border-amber-700/60 bg-amber-950/40 px-4 py-3"
                                role="alert"
                                aria-live="polite"
                            >
                                <div class="flex items-start gap-3">
                                    <svg class="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <circle cx="12" cy="12" r="9"/>
                                        <line x1="12" y1="8" x2="12" y2="13" stroke-linecap="round"/>
                                        <line x1="12" y1="16" x2="12" y2="16" stroke-linecap="round"/>
                                    </svg>
                                    <div class="flex-1">
                                        <h3 class="text-amber-200 text-sm font-semibold mb-1">
                                            "Section could not be loaded"
                                        </h3>
                                        <p class="text-amber-100/80 text-sm">{message}</p>
                                    </div>
                                    <Show when=move || retryable>
                                        <button
                                            class="text-xs font-medium text-amber-200 border border-amber-600/70 rounded-lg px-3 py-1.5 hover:bg-amber-900/50 transition-colors flex-shrink-0"
                                            on:click=do_retry
                                        >
                                            "Try again"
                                        </button>
                                    </Show>
                                </div>
                            </div>
                        })
                    }}

                    {move || {
                        if show_spinner.get() {
                            let status = bootstrap.get().message();
                            view! {
                                <div class="flex flex-col items-center justify-center py-20 gap-3">
                                    <svg class="w-6 h-6 text-[color:var(--zone-accent)] animate-spin" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                    </svg>
                                    <span class="text-gray-400 text-sm">{status}</span>
                                </div>
                            }.into_any()
                        } else {
                            let msgs = messages.get();
                            if msgs.is_empty() {
                                // Only assert emptiness on a real receipt. A
                                // failed bootstrap has already rendered its own
                                // banner above and must not also claim the
                                // channel is empty (ADR-092).
                                if !bootstrap.get().is_ready() {
                                    return ().into_any();
                                }
                                view! {
                                    <div class="flex flex-col items-center justify-center py-20 text-center">
                                        <div class="w-14 h-14 rounded-full bg-gray-800 flex items-center justify-center mb-4">
                                            <svg class="w-7 h-7 text-gray-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                                                <path stroke-linecap="round" stroke-linejoin="round" d="M12 20.25c4.97 0 9-3.694 9-8.25s-4.03-8.25-9-8.25S3 7.444 3 12c0 2.104.859 4.023 2.273 5.48.432.447.74 1.04.586 1.641a4.483 4.483 0 01-.923 1.785A5.969 5.969 0 006 21c1.282 0 2.47-.402 3.445-1.087.81.22 1.668.337 2.555.337z"/>
                                            </svg>
                                        </div>
                                        <h3 class="text-white font-semibold mb-1">"No messages yet"</h3>
                                        <p class="text-gray-500 text-sm">"Be the first to start this conversation."</p>
                                    </div>
                                }.into_any()
                            } else {
                                // Keyed by id and content: a page prepended
                                // above, or a post appended below, renders
                                // only its own rows, and a message whose text
                                // changed (a zone key arrived) is re-rendered.
                                // The VirtualList component is not used: it
                                // needs one fixed row height, and bubbles vary
                                // (images, replies, threads, the divider).
                                view! {
                                    <div class="space-y-1">
                                        {move || history_state.get().map(|h| {
                                            let label = if h.loading {
                                                "Loading older messages…"
                                            } else if h.exhausted {
                                                "Start of section history"
                                            } else {
                                                ""
                                            };
                                            view! {
                                                <div class="flex justify-center py-2 text-xs text-gray-500" data-history-state=move || if h.exhausted { "start" } else if h.loading { "loading" } else { "more" }>
                                                    {if label.is_empty() {
                                                        view! {
                                                            <button
                                                                class="text-xs text-gray-400 hover:text-gray-200 underline"
                                                                on:click=move |_| request_older.with_value(|f| f())
                                                            >
                                                                "Load older messages"
                                                            </button>
                                                        }.into_any()
                                                    } else {
                                                        view! { <span>{label}</span> }.into_any()
                                                    }}
                                                </div>
                                            }
                                        })}
                                        <For
                                            each=move || messages.get()
                                            key=|m| (m.id.clone(), content_key(&m.content))
                                            children=move |msg| {
                                                let id = msg.id.clone();
                                                let anchor_id = msg.id.clone();
                                                view! {
                                                    <>
                                                        {move || (divider_before.get().as_deref() == Some(id.as_str())).then(|| view! {
                                                            <div class="flex items-center gap-3 py-2">
                                                                <div class="flex-1 h-px" style="background:color-mix(in srgb, var(--zone-accent) 35%, transparent)"></div>
                                                                <span class="text-xs font-medium text-[color:var(--zone-accent)]">"New messages"</span>
                                                                <div class="flex-1 h-px" style="background:color-mix(in srgb, var(--zone-accent) 35%, transparent)"></div>
                                                            </div>
                                                        })}
                                                        <div data-anchor-id=anchor_id>
                                                            <MessageBubble message=msg/>
                                                        </div>
                                                    </>
                                                }
                                            }
                                        />
                                        {move || history_state.get().filter(|h| h.newer_from.is_some()).map(|h| view! {
                                            <div class="flex justify-center py-2 text-xs text-gray-500" data-history-direction="newer" data-history-state=if h.loading { "loading" } else { "newer" }>
                                                {if h.loading {
                                                    view! { <span>"Loading\u{2026}"</span> }.into_any()
                                                } else {
                                                    view! {
                                                        <button
                                                            class="text-xs text-gray-400 hover:text-gray-200 underline"
                                                            on:click=move |_| request_newer.with_value(|f| f())
                                                        >
                                                            "Load newer messages"
                                                        </button>
                                                    }.into_any()
                                                }}
                                            </div>
                                        })}
                                    </div>
                                }.into_any()
                            }
                        }
                    }}
                </div>
            </div>

            // Compose area (only when authenticated and channel is not archived)
            <Show when=move || is_authed.get() && !is_archived.get()>
                <div class="bg-gray-800 border-t border-gray-700 p-3">
                    <div class="max-w-4xl mx-auto">
                        <MessageInput
                            on_send=noop_send
                            on_send_with_mentions=send_callback
                            enable_image_upload=true
                            media_target=channel_media_target
                            channel_id=channel_id()
                            restore_failed=restore_failed
                        />
                    </div>
                </div>
            </Show>

            // Export modal
            <Show when=move || show_export.get()>
                {move || {
                    let cid = channel_id();
                    let msgs = messages.get();
                    view! {
                        <ExportModal
                            channel_id=cid
                            messages=msgs
                            on_close=Callback::new(move |()| show_export.set(false))
                        />
                    }
                }}
            </Show>
        </div>
        </Show>
    }
}

/// A short fingerprint of a message's text for the list key, so a row is
/// re-rendered when its content changes (a zone key arrived and it decrypted).
fn content_key(content: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    content.hash(&mut h);
    h.finish()
}

/// The rendered form of one stored kind-42 in channel `cid`.
fn message_data(event: &NostrEvent, cid: &str) -> MessageData {
    let reply_to = event
        .tags
        .iter()
        .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == "reply")
        .or_else(|| {
            event
                .tags
                .iter()
                .filter(|t| t.len() >= 2 && t[0] == "e")
                .nth(1)
        })
        .map(|t| t[1].clone());
    let reply_pk = event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == "p")
        .map(|t| t[1].clone());
    MessageData {
        id: event.id.clone(),
        pubkey: event.pubkey.clone(),
        content: event.content.clone(),
        created_at: event.created_at,
        reply_to_id: reply_to,
        reply_to_pubkey: reply_pk,
        reply_to_content: None,
        is_hidden: false,
        channel_id: cid.to_string(),
        thread_replies: RwSignal::new(Vec::<ThreadReply>::new()),
    }
}

/// Merge `added` (any order) into `list` (sorted by `created_at`), keeping
/// it sorted. Rendered messages stay ahead of new ones with the same
/// timestamp. One linear merge, or a plain append when everything new is
/// at least as recent as the newest rendered message.
fn merge_by_time<T: HasCreatedAt>(list: &mut Vec<T>, mut added: Vec<T>) {
    if added.is_empty() {
        return;
    }
    added.sort_by_key(HasCreatedAt::created_at);
    if list
        .last()
        .is_none_or(|last| last.created_at() <= added[0].created_at())
    {
        list.extend(added);
        return;
    }
    let old = std::mem::take(list);
    list.reserve(old.len() + added.len());
    let mut a = old.into_iter().peekable();
    let mut b = added.into_iter().peekable();
    loop {
        let take_old = match (a.peek(), b.peek()) {
            (Some(x), Some(y)) => x.created_at() <= y.created_at(),
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };
        let next = if take_old { a.next() } else { b.next() };
        list.extend(next);
    }
}

/// Timestamp accessor for [`merge_by_time`].
trait HasCreatedAt {
    fn created_at(&self) -> u64;
}

impl HasCreatedAt for MessageData {
    fn created_at(&self) -> u64 {
        self.created_at
    }
}

/// Parse kind 40 event content JSON into channel name, description, and archived status.
/// The header a channel page shows: the store's channel entry (which folds
/// the latest kind-41 over the kind-40, last-write-wins) supplies name and
/// description; the kind-40 header supplies them until the entry exists, and
/// the archived flag (kind-41 edits do not carry it).
fn effective_header(
    raw: ChannelHeader,
    folded: Option<&crate::stores::channels::ChannelMeta>,
) -> ChannelHeader {
    match folded {
        Some(meta) => ChannelHeader {
            name: if meta.name.trim().is_empty() {
                raw.name
            } else {
                meta.name.clone()
            },
            description: meta.description.clone(),
            archived: raw.archived,
        },
        None => raw,
    }
}

fn parse_channel_metadata(content: &str) -> ChannelHeader {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(val) => ChannelHeader {
            name: val
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unnamed section")
                .to_string(),
            description: val
                .get("about")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            archived: val
                .get("archived")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        },
        Err(_) => ChannelHeader {
            name: "Unnamed section".to_string(),
            description: String::new(),
            archived: false,
        },
    }
}

#[cfg(test)]
mod merge_tests {
    use super::{merge_by_time, HasCreatedAt};

    #[derive(Debug, PartialEq)]
    struct M(&'static str, u64);
    impl HasCreatedAt for M {
        fn created_at(&self) -> u64 {
            self.1
        }
    }

    #[test]
    fn an_older_page_merges_in_front_and_a_live_post_appends() {
        let mut list = vec![M("c", 30), M("d", 40)];
        merge_by_time(&mut list, vec![M("b", 20), M("a", 10), M("c2", 30)]);
        assert_eq!(
            list,
            vec![M("a", 10), M("b", 20), M("c", 30), M("c2", 30), M("d", 40)],
            "time order; a rendered message stays ahead of a new one with its timestamp"
        );
        merge_by_time(&mut list, vec![M("e", 50)]);
        assert_eq!(list.last(), Some(&M("e", 50)));
    }
}

#[cfg(test)]
mod header_tests {
    use super::{effective_header, ChannelHeader};
    use crate::stores::channels::{fold_meta_into, ChannelMeta, MetaUpdate};
    use std::collections::HashMap;

    #[test]
    fn a_kind41_rename_shows_on_the_channel_page_as_in_the_list() {
        let raw = ChannelHeader {
            name: "Fairfield Events".into(),
            description: "old".into(),
            archived: true,
        };
        let mut list = vec![ChannelMeta {
            id: "c".into(),
            name: "Fairfield Events".into(),
            description: "old".into(),
            section: String::new(),
            picture: String::new(),
            created_at: 100,
        }];
        let mut ts = HashMap::new();
        // Before any edit: the kind-40.
        assert_eq!(
            effective_header(raw.clone(), Some(&list[0])).name,
            "Fairfield Events"
        );
        // The same fold the channel list uses applies the latest kind-41.
        let edit = MetaUpdate {
            channel_id: "c".into(),
            name: Some("Events".into()),
            about: Some("new".into()),
            picture: None,
            created_at: 200,
        };
        assert!(fold_meta_into(&mut list, &mut ts, &edit));
        let shown = effective_header(raw.clone(), Some(&list[0]));
        assert_eq!(
            (shown.name.as_str(), shown.description.as_str()),
            ("Events", "new")
        );
        assert!(shown.archived, "archived still comes from the kind-40");
        // No store entry yet: the kind-40 header.
        assert_eq!(effective_header(raw, None).name, "Fairfield Events");
    }
}
