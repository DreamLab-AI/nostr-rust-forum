//! Board topic list + full threaded conversation view.
//!
//! Full parity with `nostr-bbs-forum-client`, on the SAME topic model
//! (client-core [`topics`](nostr_bbs_client_core::topics)):
//! - a board lists its TOPICS (kind-42 roots, from the channel window plus
//!   the section's root list), newest activity first, with the relay's
//!   exact reply count and last poster; a reply is never listed as a topic
//! - a thread shows the topic's root and replies oldest first from the
//!   topic's own paged list, lands at the newest post (or a linked one) and
//!   pages older replies on request
//! - NIP-28 kind-42 topics/replies + NIP-22 kind-1111 comments
//! - End-to-end encrypted zones (ADR-2016/2017) via shared `ZoneKeyStore` / `ZoneWriter`
//! - Markdown rendering + on-theme phosphor `AsciiImg`, tap for the original picture
//! - NIP-25 kind-7 reactions (+ custom emoji + kind-5 undo)
//! - Author edits (`edit` marker), NIP-09 deletions, NIP-56 reports (kind-1984)
//! - Per-identity auto-saved drafts (`draft:v2:`), bookmarks, mute, read positions
//! - Image picker + clipboard image paste via NIP-98 Solid Pod PUT

use std::collections::HashMap;
use std::rc::Rc;

use leptos::prelude::*;
use nostr_bbs_client_core::auth::use_auth;
use nostr_bbs_client_core::relay::RelayConnection;
use nostr_bbs_client_core::stores::channels::{
    roots_key, topic_key, use_channel_store, ChannelStore,
};
use nostr_bbs_client_core::stores::custom_emoji::use_custom_emoji_store;
use nostr_bbs_client_core::stores::mute::use_mute_store;
use nostr_bbs_client_core::stores::profile_cache::try_use_profile_cache;
use nostr_bbs_client_core::stores::reactions::use_reaction_store;
use nostr_bbs_client_core::stores::read_position::use_read_positions;
use nostr_bbs_client_core::stores::zones::{load_zones, resolve_zone_param};
use nostr_bbs_client_core::toast::{use_toasts, ToastVariant};
use nostr_bbs_client_core::topics::{
    board_events, classify_topics, edit_tags, find_topic_root, first_paint_ready,
    first_row_in_full_view, history_settled, landing_target, latest_post, latest_version,
    post_anchor_id, sealed_aliases, thread_events, thread_replies, topic_reply_tags,
    topic_root_tags, topic_title, updated_accessible_name, updated_label, with_topic_stats,
    FrozenBoard, Landing, ReplyView, TopicSummary, FIRST_PAINT_TIMEOUT_MS,
};
use nostr_bbs_client_core::utils::lookup::zone_is_gated;
use nostr_bbs_client_core::utils::scroll_anchor;
use nostr_bbs_client_core::utils::{format_relative_time, set_timeout_once, shorten_pubkey};
use nostr_bbs_client_core::zone_crypto::store::{
    restored_envelope_of, try_use_zone_key_store, ZoneWriter,
};
use nostr_bbs_client_core::zone_crypto::{encryption_enabled, has_zk_tag};
use nostr_bbs_core::event::{NostrEvent, UnsignedEvent};

use crate::ascii_img::{extract_image_urls, is_protected_media, AsciiImg};
use crate::components::{AuthorChip, EmptyCard, MarkdownBody};
use crate::config::BbsConfig;
use crate::router::{use_router, Route};
use crate::views::bookmarks::{is_bookmarked, toggle_bookmark, BookmarkItem};

const BUILTIN_REACTIONS: &[&str] = &["👍", "❤️", "😂", "🔥", "🎉", "👀", "💯", "🙌"];

/// Id of the scrolling content pane (`shell.rs`): the BBS scrolls it, not
/// the window.
const MAIN_PANE_ID: &str = "bbs-main";

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn draft_key(pubkey: &str, scope: &str) -> String {
    format!("draft:v2:{pubkey}:{scope}")
}

fn load_draft(pubkey: Option<&str>, scope: &str) -> String {
    #[cfg(target_arch = "wasm32")]
    if let Some(pk) = pubkey {
        if let Some(st) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
            return st
                .get_item(&draft_key(pk, scope))
                .ok()
                .flatten()
                .unwrap_or_default();
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (pubkey, scope);
    String::new()
}

fn save_draft(pubkey: Option<&str>, scope: &str, text: &str) {
    #[cfg(target_arch = "wasm32")]
    if let Some(pk) = pubkey {
        if let Some(st) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
            let k = draft_key(pk, scope);
            if text.trim().is_empty() {
                let _ = st.remove_item(&k);
            } else {
                let _ = st.set_item(&k, text);
            }
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (pubkey, scope, text);
}

fn snippet(content: &str, max: usize) -> String {
    let line = content
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("(no text)");
    let mut out = String::new();
    for (i, ch) in line.chars().enumerate() {
        if i >= max {
            out.push('…');
            break;
        }
        out.push(ch);
    }
    out
}

/// "N reply" / "N replies".
fn replies_label(n: u32) -> String {
    format!("{n} repl{}", if n == 1 { "y" } else { "ies" })
}

/// The content pane, for scroll anchoring and landing.
fn main_pane() -> Option<web_sys::HtmlElement> {
    use wasm_bindgen::JsCast;
    web_sys::window()?
        .document()?
        .get_element_by_id(MAIN_PANE_ID)?
        .dyn_into::<web_sys::HtmlElement>()
        .ok()
}

/// Whether the reader is at the top of the board: the content pane is not
/// scrolled, or row `id` (the first shown, by its `data-anchor-id`) lies
/// wholly inside the pane.
fn at_board_top(id: &str) -> bool {
    let Some(pane) = main_pane() else {
        return false;
    };
    if pane.scroll_top() <= 1 {
        return true;
    }
    let id: String = id.chars().filter(char::is_ascii_alphanumeric).collect();
    let view = pane.get_bounding_client_rect();
    pane.query_selector(&format!("[data-anchor-id=\"{id}\"]"))
        .ok()
        .flatten()
        .is_some_and(|el| {
            let r = el.get_bounding_client_rect();
            first_row_in_full_view(r.top(), r.bottom(), view.top(), view.bottom())
        })
}

/// Page `key`'s list one step (`older`, else newer) keeping the reader's
/// place: the row on screen before the page lands is where it is after.
/// Called from click handlers, which have no reactive owner: the store is
/// passed in, never looked up from context here.
fn page_keeping_place(
    store: ChannelStore,
    relay: &RelayConnection,
    key: &str,
    needles: Vec<String>,
    gated: bool,
    older: bool,
) {
    let anchor: Rc<std::cell::RefCell<Option<scroll_anchor::Anchor>>> = Rc::default();
    let before = {
        let anchor = anchor.clone();
        Rc::new(move || {
            let pane = main_pane();
            *anchor.borrow_mut() = scroll_anchor::capture(pane.as_deref());
        }) as Rc<dyn Fn()>
    };
    let after = Rc::new(move || {
        if let Some(a) = anchor.borrow_mut().take() {
            scroll_anchor::restore(a, main_pane());
        }
    }) as Rc<dyn Fn()>;
    if older {
        store.load_older(relay, key, needles, gated, before, after);
    } else {
        store.load_newer(relay, key, needles, gated, before, after);
    }
}

/// Board topic list (`#/z/<zone>/b/<channel_id>`): the section's topics,
/// newest activity first, as the forum's section page lists them.
#[component]
pub fn BoardView(zone: String, channel_id: String) -> impl IntoView {
    let router = use_router();
    let relay = expect_context::<RelayConnection>();
    let channels = use_channel_store();
    let auth = use_auth();
    let read_pos = use_read_positions();
    let zk_store = try_use_zone_key_store();
    let enc_gate = encryption_enabled();

    let zones = load_zones();
    let resolved_zone = resolve_zone_param(&zone, &zones).cloned();
    let zone_name = resolved_zone
        .as_ref()
        .map(|z| z.label())
        .unwrap_or_else(|| zone.clone());
    let zone_id = resolved_zone
        .as_ref()
        .map(|z| z.id.clone())
        .unwrap_or_else(|| zone.clone());
    let is_enc = enc_gate && resolved_zone.as_ref().is_some_and(|z| z.encrypted);
    // A gated zone withholds history until AUTH: only the authenticated
    // answer counts (`SyncReceipt::settles`).
    let gated = zone_is_gated(&zone, &zones);
    let cid = StoredValue::new(channel_id.clone());

    // The channel's history, then (once that answer counts) its first page
    // for paging and the section's root list: every topic, dormant ones
    // included, without paging the channel. Asked before AUTH in a gated
    // zone the root list came back empty and was never asked again.
    {
        let relay = relay.clone();
        // A new visit may ask a root list that failed earlier again at
        // once (its backoff otherwise holds).
        channels.rearm_topic_roots(&cid.get_value());
        Effect::new(move |_| {
            let cid = cid.get_value();
            channels.ensure_subscribed(&relay, &cid);
            // The root list goes out alongside the history REQ (once AUTH
            // is done in a gated zone, where only that answer counts), not
            // after its answer: one round trip less before first paint.
            if !gated || relay.authenticated().get() {
                channels.request_topic_roots(&relay, &cid, gated);
            }
            if channels.history_receipt(&cid).settles(gated) {
                channels.settle_first_page(&cid, gated);
            }
        });
    }

    // Topics: the roots among the window and the root list, replies folded
    // in (client-core, as the forum's section page). A Memo, so the list is
    // classified once per store change.
    let classified = Memo::new(move |_| {
        let cid = cid.get_value();
        channels.channel_messages.with(|m| {
            let window = m.get(&cid).map(Vec::as_slice).unwrap_or(&[]);
            let roots = m.get(&roots_key(&cid)).map(Vec::as_slice).unwrap_or(&[]);
            classify_topics(&cid, &board_events(window, roots))
        })
    });
    // The window holds a fraction of a long topic: the relay's exact reply
    // total and newest reply where they are in.
    let topics = Memo::new(move |_| {
        with_topic_stats(classified.get(), |t| {
            (
                channels.total_for(&topic_key(&t.id)),
                channels.topic_latest(&t.id),
            )
        })
    });
    {
        let relay = relay.clone();
        Effect::new(move |_| {
            let cid = cid.get_value();
            if !channels.history_receipt(&cid).settles(gated) {
                return;
            }
            let ids: Vec<String> = topics.with(|ts| ts.iter().map(|t| t.id.clone()).collect());
            channels.request_topic_stats(&relay, &cid, &ids, gated);
        });
    }

    // What counts as new is what arrived since the reader last opened the
    // board; opening it then marks the channel read at its newest post.
    let last_read_at_open = read_pos
        .last_read_timestamp(channel_id.clone())
        .get_untracked();
    Effect::new(move |_| {
        let cid = cid.get_value();
        let latest = channels
            .channel_messages
            .with(|m| m.get(&cid).and_then(|evs| latest_post(evs)));
        if let Some((id, ts)) = latest {
            read_pos.mark_read(&cid, &id, ts);
        }
    });

    let settled = Memo::new(move |_| {
        let cid = cid.get_value();
        channels.history_receipt(&cid).settles(gated) && channels.topic_roots_answered(&cid)
    });

    // First paint: once topics are found the board waits (on its "Loading
    // topics" card) for its history window's settled answer and its root
    // list (answered or failed), or FIRST_PAINT_TIMEOUT_MS, so dormant topics
    // do not land under the reader. Stats are not waited for: they never
    // move a painted row. A store that already holds both paints at once.
    let hold_expired = RwSignal::new(false);
    {
        let armed = StoredValue::new(false);
        Effect::new(move |_| {
            if topics.with(Vec::is_empty) || armed.get_value() {
                return;
            }
            armed.set_value(true);
            set_timeout_once(
                move || {
                    let _ = hold_expired.try_set(true);
                },
                FIRST_PAINT_TIMEOUT_MS,
            );
        });
    }
    // Latched: once painted, the board stays painted.
    let painted = Memo::new(move |prev: Option<&bool>| {
        let cid = cid.get_value();
        prev.copied().unwrap_or(false)
            || first_paint_ready(
                channels.history_receipt(&cid).settles(gated),
                channels.topic_roots_answered(&cid) || channels.topic_roots_failed(&cid),
                hold_expired.get() && !topics.with(Vec::is_empty),
            )
    });
    // Sealed envelopes and their originals in this board's lists: a sealed
    // root opens under its original id, and swaps in place.
    let sealed_pairs = Memo::new(move |_| {
        let cid = cid.get_value();
        let roots = roots_key(&cid);
        channels.channel_messages.with(|m| {
            let mut pairs = Vec::new();
            for key in [&cid, &roots] {
                if let Some(events) = m.get(key) {
                    pairs.extend(sealed_aliases(events));
                }
            }
            pairs
        })
    });

    // Display order: painted in the true order of what is known then, then
    // frozen (`FrozenBoard`): stats, counts and decrypts change a row's
    // figures, never its place; a sealed root swaps in place; the reader's
    // own new topic goes on top; other new activity waits for "↻ N
    // updated". Leaving the board and coming back paints afresh.
    let true_ids =
        Memo::new(move |_| topics.with(|ts| ts.iter().map(|t| t.id.clone()).collect::<Vec<_>>()));
    let by_id = Memo::new(move |_| {
        topics.with(|ts| {
            ts.iter()
                .map(|t| (t.id.clone(), t.clone()))
                .collect::<HashMap<_, _>>()
        })
    });
    let order = RwSignal::new(if painted.get_untracked() {
        true_ids.get_untracked()
    } else {
        Vec::new()
    });
    let board = StoredValue::new(None::<FrozenBoard>);
    {
        let me = auth.pubkey();
        Effect::new(move |_| {
            let shown = painted.get();
            let next = topics.with(|sorted| {
                board.try_update_value(|frozen| {
                    if !shown {
                        return (false, Vec::new());
                    }
                    let b = frozen.get_or_insert_with(|| FrozenBoard::paint(sorted));
                    sealed_pairs.with(|pairs| b.note_aliases(pairs.iter().cloned()));
                    // An original opened as it arrived never had its
                    // envelope in a list: the zone cache knows the pair.
                    b.note_aliases(sorted.iter().filter_map(|t| {
                        restored_envelope_of(zk_store, &t.id).map(|env| (env, t.id.clone()))
                    }));
                    b.update(sorted, me.get_untracked().as_deref());
                    (true, b.shown().to_vec())
                })
            });
            let Some((frozen, next)) = next else {
                return;
            };
            if order.with_untracked(|current| *current != next) {
                // Keep the row on screen where it is, unless the reader is
                // at the top of the board, where their new topic is seen.
                let at_top = order.with_untracked(|o| o.first().is_some_and(|id| at_board_top(id)));
                let anchor = if frozen && !at_top {
                    scroll_anchor::capture(main_pane().as_deref())
                } else {
                    None
                };
                order.set(next);
                if let Some(a) = anchor {
                    scroll_anchor::restore(a, main_pane());
                }
            }
        });
    }
    // Real activity newer than the paint, not late stats.
    let updated = Memo::new(move |_| {
        order.track();
        topics.with(|sorted| {
            board
                .try_with_value(|b| b.as_ref().map_or(0, |b| b.updated(sorted)))
                .unwrap_or(0)
        })
    });
    // Older history adds topics only while the root list is incomplete.
    let can_load_older = Memo::new(move |_| {
        let cid = cid.get_value();
        !channels.topic_roots_complete(&cid)
            && channels.history_cursor(&cid).next_request().is_some()
    });
    let loading_older = Memo::new(move |_| channels.history_cursor(&cid.get_value()).loading);

    let show_new_topic = RwSignal::new(false);
    // Render closures here read page-owned values with `try_*`: Leptos 0.7
    // drops a page's nested render effects a task hop after the router has
    // disposed the page, and a store write in between (the next page's
    // first effects, for the same channel) re-runs them; `get` then panics
    // (the forum's `history_loader::read_cursor` has the details).
    let channel_name = move || {
        let id = cid.try_get_value().unwrap_or_default();
        channels
            .channels
            .with(|cs| cs.iter().find(|c| c.id == id).map(|c| c.name.clone()))
            .unwrap_or_else(|| shorten_pubkey(&id))
    };
    let zone_back = zone.clone();
    let zone_rows = StoredValue::new(zone.clone());
    let relay_older = relay.clone();

    view! {
        <div class="tui-container">
            <div class="tui-crumb">
                <button
                    type="button"
                    class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                    on:click=move |_| router.go(Route::Zone { slug: zone_back.clone() })
                >"← " {zone_name.clone()}</button>
                <span>"/"</span>
                <strong>"# " {channel_name}</strong>
            </div>

            <div class="tui-page-head">
                <div>
                    <h1 class="tui-page-title">"# " {channel_name}</h1>
                    {is_enc.then(|| {
                        let zid = zone_id.clone();
                        move || {
                            let has_key = zk_store
                                .map(|s| s.latest_tracked(&zid).is_some())
                                .unwrap_or(false);
                            view! {
                                <span class=if has_key { "bbs-badge bbs-badge-ok" } else { "bbs-badge bbs-badge-warn" }>
                                    {if has_key { "🔒 E2E Encrypted · Unlocked" } else { "🔒 E2E Encrypted · Waiting for Key" }}
                                </span>
                            }
                        }
                    })}
                </div>
                <div class="tui-actions">
                    // Always laid out, hidden at zero: its appearing never
                    // moves the list below.
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-ghost bbs-btn-sm bbs-updated-btn"
                        class:bbs-hidden-keep-space=move || updated.try_get().unwrap_or(0) == 0
                        disabled=move || updated.try_get().unwrap_or(0) == 0
                        aria-label=move || updated_accessible_name(updated.try_get().unwrap_or(0))
                        title="Re-sort by latest activity"
                        on:click=move |_| {
                            let Some(shown) = topics
                                .try_with_untracked(|sorted| {
                                    board.try_update_value(|b| {
                                        b.as_mut().map(|b| {
                                            b.repaint(sorted);
                                            b.shown().to_vec()
                                        })
                                    })
                                })
                                .flatten()
                                .flatten()
                            else {
                                return;
                            };
                            order.set(shown);
                        }
                    >
                        {move || updated_label(updated.try_get().unwrap_or(0))}
                    </button>
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-primary"
                        on:click=move |_| show_new_topic.update(|v| *v = !*v)
                    >
                        {move || if show_new_topic.try_get().unwrap_or(false) { "× Close Composer" } else { "+ New Topic" }}
                    </button>
                </div>
            </div>

            <Show when=move || show_new_topic.try_get().unwrap_or(false) fallback=|| ()>
                <PostComposer
                    channel_id=cid.get_value()
                    zone_id=zone_id.clone()
                    topic=None
                    reply_to=RwSignal::new(None)
                    placeholder="Start a new topic (Markdown supported · paste or attach images)…"
                    on_sent=Callback::new(move |_| show_new_topic.set(false))
                />
            </Show>

            {move || {
                if !order.try_with(Vec::is_empty).unwrap_or(false) {
                    return ().into_any();
                }
                let held = !topics.try_with(Vec::is_empty).unwrap_or(true);
                let (title, body) = if held || !settled.try_get().unwrap_or(false) {
                    ("Loading topics…", "Fetching this board's topics (and zone keys if encrypted) from the relay.")
                } else if auth.is_authenticated().get() {
                    ("Board is empty", "No topics in this board yet. Tap '+ New Topic' to start the conversation.")
                } else {
                    ("Board is empty", "No topics loaded yet. If this is a gated zone, sign in to read and post.")
                };
                view! { <EmptyCard title=title body=body /> }.into_any()
            }}

            <div class="tui-stack">
                // Keyed by topic id alone: a stats answer or a decrypted
                // title updates a row in place, it never rebuilds it.
                <For
                    each=move || order.try_get().unwrap_or_default()
                    key=|id| id.clone()
                    children=move |id: String| {
                        view! {
                            <TopicRow
                                id=id
                                topics=by_id
                                zone=zone_rows.try_get_value().unwrap_or_default()
                                channel_id=cid.try_get_value().unwrap_or_default()
                                last_read_at_open=last_read_at_open
                                encrypted=is_enc
                            />
                        }
                    }
                />
            </div>

            <Show when=move || can_load_older.try_get().unwrap_or(false) fallback=|| ()>
                {
                    let relay = relay_older.clone();
                    view! {
                        <button
                            type="button"
                            class="bbs-btn bbs-btn-sm"
                            disabled=move || loading_older.try_get().unwrap_or(true)
                            on:click=move |_| {
                                let Some(cid) = cid.try_get_value() else {
                                    return;
                                };
                                page_keeping_place(channels, &relay, &cid, vec![cid.clone()], gated, true);
                            }
                        >
                            {move || if loading_older.try_get().unwrap_or(false) { "… Loading" } else { "▼ Load older topics" }}
                        </button>
                    }
                }
            </Show>
        </div>
    }
}

/// One topic row: title, NEW and lock badges, reply count, the most recent
/// poster and the time of the latest activity, and the starter when someone
/// else spoke last.
///
/// The row reads its topic from `topics` by id and each field through its
/// own memo, so late fields update in place. Every line has a fixed height
/// (`bbs.css`, `.bbs-topic-*`), so they never change the row's height.
#[component]
fn TopicRow(
    id: String,
    topics: Memo<HashMap<String, TopicSummary>>,
    zone: String,
    channel_id: String,
    /// The channel's read position when the board was opened: a topic
    /// active since then is NEW.
    last_read_at_open: u64,
    encrypted: bool,
) -> impl IntoView {
    let router = use_router();
    let root_id = id.clone();
    let anchor_id = id.clone();
    // A topic briefly missing from the map (the row is about to go) keeps
    // showing what it showed.
    let topic = Memo::new(move |prev: Option<&Option<TopicSummary>>| {
        topics
            .try_with(|m| m.get(&id).cloned())
            .flatten()
            .or_else(|| prev.cloned().flatten())
    });
    let field = move |f: fn(&TopicSummary) -> String| {
        Memo::new(move |_| {
            topic
                .try_with(|t| t.as_ref().map(f))
                .flatten()
                .unwrap_or_default()
        })
    };
    let title = field(|t| topic_title(&t.content));
    let last_pk = field(|t| t.last_pubkey.clone());
    let author_pk = field(|t| t.pubkey.clone());
    let replies = field(|t| replies_label(t.reply_count));
    let activity = field(|t| format_relative_time(t.last_activity));
    let started_by_other = Memo::new(move |_| {
        topic
            .try_with(|t| {
                t.as_ref()
                    .is_some_and(|t| t.reply_count > 0 && t.last_pubkey != t.pubkey)
            })
            .unwrap_or(false)
    });
    let is_unread = Memo::new(move |_| {
        topic
            .try_with(|t| {
                t.as_ref()
                    .is_some_and(|t| t.last_activity > last_read_at_open)
            })
            .unwrap_or(false)
    });
    view! {
        <div
            class="tui-card tui-card-interactive tui-stack bbs-topic-row"
            role="button"
            tabindex="0"
            data-anchor-id=anchor_id
            on:click=move |_| router.go(Route::Thread {
                zone: zone.clone(),
                channel_id: channel_id.clone(),
                root_id: root_id.clone(),
                focus: None,
            })
        >
            <div class="tui-row-between bbs-topic-head">
                <div class="tui-row bbs-topic-title-row">
                    {move || is_unread.try_get().unwrap_or(false).then(|| view! { <span class="bbs-badge bbs-badge-accent">"NEW"</span> })}
                    {encrypted.then(|| view! { <span class="bbs-badge bbs-badge-ok">"🔒"</span> })}
                    // The whole title on hover: one line on a desktop
                    // ellipsises it.
                    <strong
                        class="bbs-topic-title"
                        title=move || title.try_get().unwrap_or_default()
                    >
                        {move || title.try_get().unwrap_or_default()}
                    </strong>
                </div>
                <span class="bbs-badge bbs-topic-replies">{move || replies.try_get().unwrap_or_default()}</span>
            </div>
            <div class="tui-row-between bbs-topic-meta" style="font-size:0.8rem">
                <div class="tui-row bbs-topic-people">
                    <span class="tui-muted">"last by"</span>
                    {move || view! { <AuthorChip pubkey=last_pk.try_get().unwrap_or_default() /> }}
                    {move || started_by_other.try_get().unwrap_or(false).then(|| view! {
                        <span class="tui-muted">"· started by"</span>
                        <AuthorChip pubkey=author_pk.try_get().unwrap_or_default() />
                    })}
                </div>
                <span class="tui-muted bbs-topic-time">{move || activity.try_get().unwrap_or_default()}</span>
            </div>
        </div>
    }
}

/// Scroll the landing into place inside the content pane: a focus target is
/// centred (and outlined once when `flash`); otherwise the pane goes to the
/// very bottom, where the newest post sits above the reply composer.
fn pin_landing(target: &str, is_focus: bool, flash: bool) {
    let Some(doc) = web_sys::window().and_then(|w| w.document()) else {
        return;
    };
    if is_focus {
        let Some(el) = doc.get_element_by_id(&post_anchor_id(target)) else {
            return;
        };
        let opts = web_sys::ScrollIntoViewOptions::new();
        opts.set_block(web_sys::ScrollLogicalPosition::Center);
        el.scroll_into_view_with_scroll_into_view_options(&opts);
        if flash {
            let cl = el.class_list();
            let _ = cl.add_1("bbs-post-focus");
            set_timeout_once(
                move || {
                    let _ = cl.remove_1("bbs-post-focus");
                },
                2_500,
            );
        }
        return;
    }
    if let Some(pane) = doc.get_element_by_id(MAIN_PANE_ID) {
        pane.set_scroll_top(pane.scroll_height());
    }
}

/// Threaded conversation view (`#/z/<zone>/b/<channel_id>/t/<root_id>`,
/// `…/p/<focus>` for a linked post), as the forum's thread page shows it:
/// the topic's root and replies oldest first, from the topic's own paged
/// list, landing at the newest post (or `focus`).
#[component]
pub fn ThreadView(
    zone: String,
    channel_id: String,
    root_id: String,
    focus: Option<String>,
) -> impl IntoView {
    let router = use_router();
    let relay = expect_context::<RelayConnection>();
    let channels = use_channel_store();
    let mute = use_mute_store();
    let read_pos = use_read_positions();

    let zones = load_zones();
    let resolved_zone = resolve_zone_param(&zone, &zones).cloned();
    let zone_id = resolved_zone
        .as_ref()
        .map(|z| z.id.clone())
        .unwrap_or_else(|| zone.clone());
    let is_enc = encryption_enabled() && resolved_zone.as_ref().is_some_and(|z| z.encrypted);
    let gated = zone_is_gated(&zone, &zones);
    let cid = StoredValue::new(channel_id.clone());
    let wanted_root = StoredValue::new(root_id.to_lowercase());

    {
        let relay = relay.clone();
        Effect::new(move |_| channels.ensure_subscribed(&relay, &cid.get_value()));
    }

    // The topic's own paged list (`topic:<root>`, paged by `#e:[root]`),
    // once the root is known; live posts still arrive in the channel list.
    let topic_list = RwSignal::new(None::<String>);
    // `Signal::derive` (not `Memo`): `NostrEvent` is not `PartialEq`.
    let events = Signal::derive(move || {
        let cid = cid.get_value();
        let channel = channels.list_events(&cid);
        let roots = channels.list_events(&roots_key(&cid));
        let topic = topic_list.get().map(|key| {
            (
                channels.list_events(&key),
                channels.history_cursor(&key).newer_from,
            )
        });
        thread_events(&channel, &roots, topic)
    });

    // The root, once seen, is kept: paging towards newer replies evicts the
    // oldest messages, and a root is usually its topic's oldest.
    let pinned_root = StoredValue::new(None::<NostrEvent>);
    let topic_root = Signal::derive(move || {
        let want = wanted_root.get_value();
        let found = events.with(|evs| {
            find_topic_root(evs, &cid.get_value(), |id| id.eq_ignore_ascii_case(&want))
        });
        match found {
            Some(root) => {
                pinned_root.set_value(Some(root.clone()));
                Some(root)
            }
            None => pinned_root.get_value(),
        }
    });

    // A root not loaded yet: ask the section's root list once the history
    // answer counts, then the root itself by id (a sealed root by the inner
    // id its envelope names).
    {
        let relay = relay.clone();
        let fetched = StoredValue::new(false);
        Effect::new(move |_| {
            if topic_root.with(Option::is_some) {
                return;
            }
            let cid = cid.get_value();
            if !channels.history_receipt(&cid).settles(gated) {
                return;
            }
            channels.request_topic_roots(&relay, &cid, gated);
            if !fetched.get_value() {
                fetched.set_value(true);
                channels.fetch_by_id(&relay, &wanted_root.get_value());
            }
        });
    }

    // Start the topic's own list once its root is known: register it, load
    // its newest page and ask the relay for its true reply count.
    {
        let relay = relay.clone();
        Effect::new(move |_| {
            let Some(root) = topic_root.get() else {
                return;
            };
            let cid = cid.get_value();
            let key = channels.register_topic(&cid, &root.id);
            if topic_list.get_untracked().as_deref() != Some(key.as_str()) {
                topic_list.set(Some(key.clone()));
            }
            let cursor = channels.history_cursor(&key);
            if !cursor.started && !cursor.loading {
                channels.reload_newest(&relay, &key, vec![root.id.to_lowercase()], gated);
            }
            channels.request_total_of(&relay, &key, &root.id.to_lowercase());
        });
    }

    // Replies oldest first, each at its author's latest edit, quotes
    // resolved (client-core, as the forum's thread page).
    let replies = Memo::new(move |_| {
        let Some(root) = topic_root.get() else {
            return Vec::<ReplyView>::new();
        };
        events.with(|evs| thread_replies(&root, evs))
    });
    let root_view = Memo::new(move |_| {
        let root = topic_root.get()?;
        let (content, created_at, edited) = events.with(|evs| latest_version(&root, evs));
        Some(ReplyView {
            id: root.id.clone(),
            pubkey: root.pubkey.clone(),
            content,
            created_at,
            edited,
            quote: None,
            tags: root.tags.clone(),
        })
    });

    // The topic's true reply count: the relay's count plus replies seen since.
    Effect::new(move |_| {
        let Some(key) = topic_list.get() else {
            return;
        };
        replies.with(|rs| {
            for r in rs {
                channels.note_inserted(&key, &r.id, r.created_at);
            }
        });
    });
    let reply_total = Memo::new(move |_| {
        let shown = replies.with(Vec::len) as u32;
        topic_list
            .get()
            .map_or(shown, |key| channels.total_for(&key).max(shown))
    });

    // Reading the topic marks its channel read at the newest post held.
    Effect::new(move |_| {
        let cid = cid.get_value();
        if let Some((id, ts)) = events.with(|evs| latest_post(evs)) {
            read_pos.mark_read(&cid, &id, ts);
        }
    });

    // Paging the topic's own list.
    let cursor = Memo::new(move |_| topic_list.get().map(|key| channels.history_cursor(&key)));
    let can_load_older =
        Memo::new(move |_| cursor.with(|c| c.as_ref().is_some_and(|c| c.next_request().is_some())));
    let detached =
        Memo::new(move |_| cursor.with(|c| c.as_ref().is_some_and(|c| c.newer_from.is_some())));
    let paging = Memo::new(move |_| cursor.with(|c| c.as_ref().is_some_and(|c| c.loading)));
    let page = {
        let relay = relay.clone();
        move |older: bool| {
            let (Some(key), Some(root)) = (topic_list.get_untracked(), topic_root.get_untracked())
            else {
                return;
            };
            page_keeping_place(
                channels,
                &relay,
                &key,
                vec![root.id.to_lowercase()],
                gated,
                older,
            );
        }
    };
    let page_older = page.clone();
    let page_newer = page;

    // -- Landing ----------------------------------------------------------
    //
    // Opening a topic lands at the very bottom: the newest post with the
    // reply composer under it. A linked post (`focus`) is centred instead and
    // outlined once. Replies stream in and media grows posts after first
    // paint, so the pin re-applies on every reply and every resize of the
    // thread until the ceiling or until the reader scrolls, taps or types
    // (client-core `Landing`, as the forum's thread page).
    let focus = StoredValue::new(focus);
    let landing = StoredValue::new(Landing::default());
    let schedule_pin = move |final_pin: bool| {
        set_timeout_once(
            move || {
                let Some(state) = landing.try_get_value() else {
                    return;
                };
                if !state.may_pin(final_pin) {
                    return;
                }
                let Some((target, is_focus)) = state.target else {
                    return;
                };
                let flash = is_focus && !state.flashed;
                if flash {
                    landing.try_update_value(|l| l.flashed = true);
                }
                pin_landing(&target, is_focus, flash);
            },
            60,
        );
    };
    let landing_history_settled = Memo::new(move |_| {
        let cid = cid.get_value();
        let topic = topic_list.get().map(|key| channels.history_cursor(&key));
        history_settled(
            channels.history_receipt(&cid).settles(gated),
            topic.as_ref(),
        )
    });
    Effect::new(move |_| {
        let Some(root) = topic_root.get() else {
            return;
        };
        let reply_ids: Vec<String> = replies.with(|rs| rs.iter().map(|r| r.id.clone()).collect());
        let settled = landing_history_settled.get();
        let target = focus.with_value(|f| landing_target(f.as_deref(), &root.id, &reply_ids));
        let now = js_sys::Date::now();
        let (repin, final_pin) = landing
            .try_update_value(|l| {
                if l.touched {
                    return (false, false);
                }
                l.target = target;
                let final_pin = l.note_history(settled);
                (l.grow(now), final_pin)
            })
            .unwrap_or((false, false));
        if repin || final_pin {
            schedule_pin(final_pin);
        }
    });
    // Growth of the thread (images, embeds) re-pins too.
    let thread_ref = NodeRef::<leptos::html::Div>::new();
    Effect::new(move |_| {
        use wasm_bindgen::JsCast;
        let Some(el) = thread_ref.get() else {
            return;
        };
        let on_resize = wasm_bindgen::closure::Closure::<dyn FnMut()>::new(move || {
            let now = js_sys::Date::now();
            if landing.try_update_value(|l| l.grow(now)).unwrap_or(false) {
                schedule_pin(false);
            }
        });
        if let Ok(observer) = web_sys::ResizeObserver::new(on_resize.as_ref().unchecked_ref()) {
            observer.observe(&el);
            let guard = send_wrapper::SendWrapper::new((observer, on_resize));
            on_cleanup(move || {
                let (observer, on_resize) = guard.take();
                observer.disconnect();
                drop(on_resize);
            });
        }
    });
    // Any deliberate input by the reader ends the landing phase.
    let end_landing = move || {
        let now = js_sys::Date::now();
        landing.try_update_value(|l| l.reader_input(now));
    };
    let input_listeners = [
        window_event_listener(leptos::ev::wheel, move |_| end_landing()),
        window_event_listener(leptos::ev::touchmove, move |_| end_landing()),
        window_event_listener(leptos::ev::keydown, move |_| end_landing()),
        window_event_listener(leptos::ev::pointerdown, move |_| end_landing()),
    ];
    on_cleanup(move || input_listeners.into_iter().for_each(|h| h.remove()));

    // The post the next reply quotes (None = a plain reply to the topic).
    let reply_to = RwSignal::new(None::<(String, String)>);
    let topic_sig: Signal<Option<NostrEvent>> = topic_root;

    let z_back = zone.clone();
    let cid_back = channel_id.clone();
    let zone_cards = StoredValue::new(zone.clone());
    // Render closures below read page-owned values with `try_*`; see
    // `BoardView` for why.
    let topic_heading = move || {
        root_view
            .try_with(|r| r.as_ref().map(|r| snippet(&r.content, 90)))
            .flatten()
            .unwrap_or_else(|| "Thread".to_string())
    };

    view! {
        <div class="tui-container">
            <div class="tui-crumb">
                <button
                    type="button"
                    class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                    on:click=move |_| router.go(Route::Board {
                        zone: z_back.clone(),
                        channel_id: cid_back.clone(),
                    })
                >"← Topics"</button>
                <span>"/"</span>
                <strong>{topic_heading}</strong>
                {is_enc.then(|| view! { <span class="bbs-badge bbs-badge-ok">"🔒 E2E"</span> })}
                {move || topic_root.try_with(Option::is_some).unwrap_or(false).then(|| view! {
                    <span class="bbs-badge">{move || replies_label(reply_total.try_get().unwrap_or_default())}</span>
                })}
            </div>

            <div class="tui-stack" node_ref=thread_ref>
                {move || topic_root.try_with(Option::is_none).unwrap_or(false).then(|| view! {
                    <EmptyCard
                        title="Loading thread…"
                        body="Fetching messages (and zone keys if encrypted) from the relay."
                    />
                })}

                {move || {
                    let older = page_older.clone();
                    can_load_older.try_get().unwrap_or(false).then(move || view! {
                        <button
                            type="button"
                            class="bbs-btn bbs-btn-sm"
                            disabled=move || paging.try_get().unwrap_or(true)
                            on:click=move |_| older(true)
                        >
                            {move || if paging.try_get().unwrap_or(false) { "… Loading" } else { "▲ Load older posts" }}
                        </button>
                    })
                }}

                {move || root_view.try_get().flatten().map(|r| view! {
                    <ThreadPost
                        post=r
                        is_root=true
                        is_encrypted_zone=is_enc
                        zone=zone_cards.try_get_value().unwrap_or_default()
                        channel_id=cid.try_get_value().unwrap_or_default()
                        topic=topic_sig
                        reply_to=reply_to
                        muted_check=mute
                    />
                })}

                <For
                    each=move || replies.try_get().unwrap_or_default()
                    key=|r| (r.id.clone(), nostr_bbs_client_core::topics::view_key(r))
                    children=move |r: ReplyView| view! {
                        <ThreadPost
                            post=r
                            is_root=false
                            is_encrypted_zone=is_enc
                            zone=zone_cards.try_get_value().unwrap_or_default()
                            channel_id=cid.try_get_value().unwrap_or_default()
                            topic=topic_sig
                            reply_to=reply_to
                            muted_check=mute
                        />
                    }
                />

                {move || {
                    let newer = page_newer.clone();
                    detached.try_get().unwrap_or(false).then(move || view! {
                        <button
                            type="button"
                            class="bbs-btn bbs-btn-sm"
                            disabled=move || paging.try_get().unwrap_or(true)
                            on:click=move |_| newer(false)
                        >
                            {move || if paging.try_get().unwrap_or(false) { "… Loading" } else { "▼ Load newer posts" }}
                        </button>
                    })
                }}
            </div>

            <PostComposer
                channel_id=channel_id.clone()
                zone_id=zone_id
                topic=Some(topic_sig)
                reply_to=reply_to
                placeholder="Write a reply (Markdown · @mention · paste/attach image)…"
                on_sent=Callback::new(|_| {})
            />
        </div>
    }
}

/// One post of a thread, hidden behind "Show anyway" when its author is
/// muted, and otherwise a [`PostCard`].
#[component]
fn ThreadPost(
    post: ReplyView,
    is_root: bool,
    is_encrypted_zone: bool,
    zone: String,
    channel_id: String,
    topic: Signal<Option<NostrEvent>>,
    reply_to: RwSignal<Option<(String, String)>>,
    muted_check: nostr_bbs_client_core::stores::mute::MuteStore,
) -> impl IntoView {
    let auth = use_auth();
    let muted = muted_check.is_user_muted(&post.pubkey);
    let reveal_muted = RwSignal::new(false);
    let author = post.pubkey.clone();
    let is_mine = move || auth.pubkey().get().as_deref() == Some(author.as_str());
    let post = StoredValue::new(post);
    move || {
        if muted && !reveal_muted.get() {
            view! {
                <div class="tui-card tui-row-between">
                    <span class="tui-muted">"Muted author hidden"</span>
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-sm"
                        on:click=move |_| reveal_muted.set(true)
                    >"Show anyway"</button>
                </div>
            }
            .into_any()
        } else {
            view! {
                <PostCard
                    post=post.get_value()
                    is_root=is_root
                    is_mine=is_mine()
                    is_encrypted_zone=is_encrypted_zone
                    zone=zone.clone()
                    channel_id=channel_id.clone()
                    topic=topic
                    reply_to=reply_to
                />
            }
            .into_any()
        }
    }
}

/// One rendered post card with Markdown, ASCII/Raw image toggle, reactions,
/// reply, bookmark, edit, delete, and report controls.
#[component]
fn PostCard(
    post: ReplyView,
    is_root: bool,
    is_mine: bool,
    is_encrypted_zone: bool,
    zone: String,
    channel_id: String,
    /// The topic's root, for the tags of an edit and a bookmark's thread.
    topic: Signal<Option<NostrEvent>>,
    reply_to: RwSignal<Option<(String, String)>>,
) -> impl IntoView {
    let auth = use_auth();
    let relay = expect_context::<RelayConnection>();
    let toasts = use_toasts();
    let reactions_store = use_reaction_store();
    // Captured during setup: handlers and the publish task have no reactive
    // owner, so a context lookup there finds no zone keys and an encrypted
    // zone's edit would go out unencrypted (and be refused).
    let writer = ZoneWriter::capture();
    let custom_emoji = use_custom_emoji_store();

    let ev_id = post.id.clone();
    let author_pk = post.pubkey.clone();
    let is_e2e = has_zk_tag(&post.tags);
    let is_edited = post.edited;
    let imgs = extract_image_urls(&post.content);
    // The post in the forum, for images the BBS cannot render: its
    // canonical topic URL, focused on this post.
    let post_forum_href = {
        let channels = use_channel_store();
        let root_id = if is_root {
            Some(post.id.clone())
        } else {
            topic.with_untracked(|t| t.as_ref().map(|t| t.id.clone()))
        };
        let route = match root_id {
            Some(root_id) => Route::Thread {
                zone: zone.clone(),
                channel_id: channel_id.clone(),
                root_id,
                focus: Some(post.id.clone()),
            },
            None => Route::Go {
                event_id: post.id.clone(),
                channel: Some(channel_id.clone()),
            },
        };
        let zones = load_zones();
        channels
            .channels
            .with_untracked(|cs| nostr_bbs_client_core::base_href(&route.forum_path(&zones, cs)))
    };

    let show_picker = RwSignal::new(false);
    let editing = RwSignal::new(false);
    let edit_text = RwSignal::new(post.content.clone());
    let bm_tick = RwSignal::new(0u32);

    let reactions_sig = reactions_store.reactions_for(&ev_id);

    let toggle_react = {
        let ev_id = ev_id.clone();
        let author_pk = author_pk.clone();
        let relay = relay.clone();
        move |emoji: String| {
            let Some(signer) = auth.get_signer() else {
                toasts.show("Sign in to react", ToastVariant::Warning);
                return;
            };
            let me = signer.public_key().to_string();
            let ev_id = ev_id.clone();
            let author_pk = author_pk.clone();
            let relay = relay.clone();
            if let Some(prev_id) = reactions_store.my_reaction_id(&ev_id, &emoji, &me) {
                // Undo via NIP-09 kind-5
                let unsigned = UnsignedEvent {
                    pubkey: me,
                    created_at: (js_sys::Date::now() / 1000.0) as u64,
                    kind: 5,
                    tags: vec![
                        vec!["e".into(), prev_id.clone()],
                        vec!["k".into(), "7".into()],
                    ],
                    content: String::new(),
                };
                reactions_store.remove_local(&prev_id);
                wasm_bindgen_futures::spawn_local(async move {
                    if let Ok(signed) = signer.sign_event(unsigned).await {
                        relay.publish(&signed);
                    }
                });
            } else {
                let unsigned = UnsignedEvent {
                    pubkey: me.clone(),
                    created_at: (js_sys::Date::now() / 1000.0) as u64,
                    kind: 7,
                    tags: vec![vec!["e".into(), ev_id.clone()], vec!["p".into(), author_pk]],
                    content: emoji.clone(),
                };
                wasm_bindgen_futures::spawn_local(async move {
                    if let Ok(signed) = signer.sign_event(unsigned).await {
                        reactions_store.add_local(&signed.id, &ev_id, &emoji, &me);
                        relay.publish(&signed);
                    }
                });
            }
        }
    };

    let save_edit = {
        let ev_id = ev_id.clone();
        let cid = channel_id.clone();
        let relay = relay.clone();
        move |_| {
            let body = edit_text.get_untracked().trim().to_string();
            if body.is_empty() {
                return;
            }
            let Some(signer) = auth.get_signer() else {
                return;
            };
            let me = signer.public_key().to_string();
            let cid = cid.clone();
            let ev_id = ev_id.clone();
            let relay = relay.clone();
            editing.set(false);
            // As the forum tags an edit: it stays in the topic's paged list
            // and keeps reaching the root author.
            let root = topic.get_untracked();
            let tags = edit_tags(
                &cid,
                root.as_ref().map(|r| (r.id.as_str(), r.pubkey.as_str())),
                &ev_id,
            );
            wasm_bindgen_futures::spawn_local(async move {
                let unsigned = UnsignedEvent {
                    pubkey: me,
                    created_at: (js_sys::Date::now() / 1000.0) as u64,
                    kind: 42,
                    tags,
                    content: body,
                };
                let unsigned = match writer.prepare(&cid, Some(signer.clone()), unsigned).await {
                    Ok(u) => u,
                    Err(e) => {
                        toasts.show(e, ToastVariant::Error);
                        return;
                    }
                };
                match signer.sign_event(unsigned).await {
                    Ok(signed) => {
                        relay.publish(&signed);
                        toasts.show("Edit published", ToastVariant::Success);
                    }
                    Err(e) => toasts.show(format!("Sign failed: {e}"), ToastVariant::Error),
                }
            });
        }
    };

    let delete_post = {
        let ev_id = ev_id.clone();
        let relay = relay.clone();
        move |_| {
            let Some(signer) = auth.get_signer() else {
                return;
            };
            let ev_id = ev_id.clone();
            let relay = relay.clone();
            let unsigned = UnsignedEvent {
                pubkey: signer.public_key().to_string(),
                created_at: (js_sys::Date::now() / 1000.0) as u64,
                kind: 5,
                tags: vec![
                    vec!["e".into(), ev_id.clone()],
                    vec!["k".into(), "42".into()],
                ],
                content: "deleted by author".into(),
            };
            wasm_bindgen_futures::spawn_local(async move {
                match signer.sign_event(unsigned).await {
                    Ok(signed) => {
                        relay.publish(&signed);
                        toasts.show("Deletion published (NIP-09)", ToastVariant::Success);
                    }
                    Err(e) => toasts.show(format!("Delete failed: {e}"), ToastVariant::Error),
                }
            });
        }
    };

    let report_post = {
        let ev_id = ev_id.clone();
        let author_pk = author_pk.clone();
        let relay = relay.clone();
        move |_| {
            let Some(signer) = auth.get_signer() else {
                toasts.show("Sign in to report", ToastVariant::Warning);
                return;
            };
            let unsigned = UnsignedEvent {
                pubkey: signer.public_key().to_string(),
                created_at: (js_sys::Date::now() / 1000.0) as u64,
                kind: 1984,
                tags: vec![
                    vec!["e".into(), ev_id.clone(), "other".into()],
                    vec!["p".into(), author_pk.clone()],
                ],
                content: "Reported via BBS client".into(),
            };
            let relay = relay.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match signer.sign_event(unsigned).await {
                    Ok(signed) => {
                        relay.publish(&signed);
                        toasts.show("Report submitted (NIP-56)", ToastVariant::Info);
                    }
                    Err(e) => toasts.show(format!("Report failed: {e}"), ToastVariant::Error),
                }
            });
        }
    };

    let bm_id = ev_id.clone();
    let bm_author = author_pk.clone();
    let bm_preview = if is_encrypted_zone {
        "🔒 Encrypted post".to_string()
    } else {
        snippet(&post.content, 100)
    };
    let bm_created = post.created_at;

    let reply_id = ev_id.clone();
    let reply_pk = author_pk.clone();
    let save_edit_cb = Callback::new(save_edit);
    let toggle_react_cb = Callback::new(toggle_react);

    view! {
        <article
            class="bbs-post"
            class:bbs-post-root=is_root
            class:bbs-post-reply-indent=!is_root
            id=post_anchor_id(&post.id)
            // Scroll anchor for paging (replies only: the root always
            // leads, so it never moves when older replies land under it).
            data-anchor-id=(!is_root).then(|| post.id.clone())
        >
            <header class="bbs-post-header">
                <div class="tui-row">
                    <AuthorChip pubkey=author_pk.clone() />
                    {is_e2e.then(|| view! { <span class="bbs-badge bbs-badge-ok">"🔒"</span> })}
                    {is_edited.then(|| view! { <span class="bbs-badge">"edited"</span> })}
                </div>
                <span class="bbs-post-meta">{format_relative_time(post.created_at)}</span>
            </header>

            {post.quote.clone().map(|q| view! {
                <div class="bbs-quote tui-muted" style="font-size:0.82rem;border-left:2px solid var(--border);padding-left:0.5rem">
                    "↳ " <AuthorChip pubkey=q.pubkey /> " " {q.snippet}
                </div>
            })}

            {move || if editing.get() {
                view! {
                    <div class="tui-stack">
                        <textarea
                            class="bbs-textarea"
                            prop:value=move || edit_text.get()
                            on:input=move |ev| edit_text.set(event_target_value(&ev))
                        ></textarea>
                        <div class="tui-row">
                            <button type="button" class="bbs-btn bbs-btn-primary bbs-btn-sm" on:click=move |ev| save_edit_cb.run(ev)>
                                "Save Edit"
                            </button>
                            <button type="button" class="bbs-btn bbs-btn-sm" on:click=move |_| editing.set(false)>
                                "Cancel"
                            </button>
                        </div>
                    </div>
                }.into_any()
            } else {
                view! { <MarkdownBody content=post.content.clone() /> }.into_any()
            }}

            {(!imgs.is_empty()).then(|| view! {
                <div class="tui-stack">
                    {imgs.into_iter().map(|src| view! { <PostImage src=src forum_href=post_forum_href.clone() /> }).collect_view()}
                </div>
            })}

            <footer class="bbs-post-footer">
                {move || {
                    let list = reactions_sig.get();
                    list.into_iter().map(|r| {
                        let em = r.emoji.clone();
                        view! {
                            <button
                                type="button"
                                class="bbs-react-pill"
                                class:active=r.reacted_by_me
                                on:click=move |_| toggle_react_cb.run(em.clone())
                            >
                                <span>{r.emoji}</span>
                                <span>{r.count}</span>
                            </button>
                        }
                    }).collect_view()
                }}

                <button
                    type="button"
                    class="bbs-react-pill"
                    title="Add reaction"
                    on:click=move |_| show_picker.update(|v| *v = !*v)
                >"☺+"</button>

                <button
                    type="button"
                    class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                    on:click=move |_| {
                        reply_to.set(Some((reply_id.clone(), reply_pk.clone())));
                        if let Some(el) = web_sys::window()
                            .and_then(|w| w.document())
                            .and_then(|d| d.get_element_by_id("bbs-reply-composer"))
                        {
                            el.scroll_into_view();
                        }
                    }
                >"↳ Reply"</button>

                <button
                    type="button"
                    class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                    on:click=move |_| {
                        let pk = auth.pubkey().get_untracked();
                        let root_id = topic
                            .get_untracked()
                            .map(|r| r.id)
                            .unwrap_or_else(|| bm_id.clone());
                        let saved = toggle_bookmark(
                            pk.as_deref(),
                            BookmarkItem {
                                event_id: bm_id.clone(),
                                zone: zone.clone(),
                                channel_id: channel_id.clone(),
                                root_id,
                                author: bm_author.clone(),
                                preview: bm_preview.clone(),
                                created_at: bm_created,
                            },
                        );
                        bm_tick.update(|n| *n += 1);
                        toasts.show(
                            if saved { "Bookmarked" } else { "Bookmark removed" },
                            ToastVariant::Info,
                        );
                    }
                >
                    {
                        let bm_check_id = ev_id.clone();
                        move || {
                            let _ = bm_tick.get();
                            let pk = auth.pubkey().get();
                            if is_bookmarked(pk.as_deref(), &bm_check_id) {
                                "★ Saved"
                            } else {
                                "☆ Save"
                            }
                        }
                    }
                </button>

                {is_mine.then(|| view! {
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                        on:click=move |_| editing.set(true)
                    >"Edit"</button>
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                        on:click=delete_post.clone()
                    >"Delete"</button>
                })}

                {(!is_mine).then(|| view! {
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                        on:click=report_post.clone()
                    >"Report"</button>
                })}
            </footer>

            <Show when=move || show_picker.get() fallback=|| ()>
                <div class="tui-row" style="padding-top:0.35rem">
                    {move || {
                        let mut all: Vec<String> = BUILTIN_REACTIONS.iter().map(|s| s.to_string()).collect();
                        for c in custom_emoji.emojis() {
                            if !all.contains(&c) {
                                all.push(c);
                            }
                        }
                        all.into_iter().map(|em| {
                            let em_click = em.clone();
                            view! {
                                <button
                                    type="button"
                                    class="bbs-react-pill"
                                    on:click=move |_| {
                                        toggle_react_cb.run(em_click.clone());
                                        show_picker.set(false);
                                    }
                                >{em}</button>
                            }
                        }).collect_view()
                    }}
                </div>
            </Show>
        </article>
    }
}

/// On-theme phosphor ASCII image card: tap the art for the original picture
/// (see [`AsciiImg`]).
///
/// Protected media (a zone image: see [`is_protected_media`]) is never sent
/// for rendering: its card shows a placeholder naming the file and linking to
/// the post in the forum (`forum_href`), and the placeholder's toggle fetches
/// the picture with the member's own credentials.
#[component]
fn PostImage(src: String, forum_href: String) -> impl IntoView {
    let protected = is_protected_media(&src);
    let cols = {
        #[cfg(target_arch = "wasm32")]
        {
            web_sys::window()
                .and_then(|w| w.inner_width().ok())
                .and_then(|v| v.as_f64())
                .map(|w| if w < 640.0 { 40 } else { 68 })
                .unwrap_or(68)
        }
        #[cfg(not(target_arch = "wasm32"))]
        68
    };
    view! {
        <div class="bbs-ascii-card">
            <div class="bbs-ascii-card-head">
                <span>"▞ IMG ▚"</span>
                {protected.then(|| view! { <span title="Protected zone media">"🔒"</span> })}
            </div>
            <AsciiImg src=src cols=cols forum_href=forum_href />
        </div>
    }
}

/// Rich Markdown + Image + Encrypted-Zone Composer shared by BoardView and ThreadView.
///
/// `topic` is `None` for a new topic (a root with the topic marker) and the
/// topic's root for a reply, which threads under the root as the forum's
/// replies do; `reply_to` is the post a reply quotes (`None` = the topic).
#[component]
fn PostComposer(
    channel_id: String,
    zone_id: String,
    topic: Option<Signal<Option<NostrEvent>>>,
    reply_to: RwSignal<Option<(String, String)>>,
    placeholder: &'static str,
    on_sent: Callback<()>,
) -> impl IntoView {
    let router = use_router();
    let auth = use_auth();
    // Captured during setup, as the forum does: the send handler and its
    // publish task have no reactive owner, so a context lookup there finds
    // no zone keys (an encrypted zone's post would go out unencrypted and be
    // refused) and no profile cache (typed @mentions would get no `p` tag).
    let writer = ZoneWriter::capture();
    let profiles = try_use_profile_cache();
    let relay = expect_context::<RelayConnection>();
    let toasts = use_toasts();
    let cfg = use_context::<StoredValue<BbsConfig>>().expect("BbsConfig");

    let initial_draft = load_draft(auth.pubkey().get_untracked().as_deref(), &channel_id);
    let text = RwSignal::new(initial_draft);
    let sending = RwSignal::new(false);
    let uploading = RwSignal::new(false);
    let file_ref = NodeRef::<leptos::html::Input>::new();

    // Auto-save per-identity draft
    let cid_draft = channel_id.clone();
    Effect::new(move |_| {
        let val = text.get();
        let pk = auth.pubkey().get();
        save_draft(pk.as_deref(), &cid_draft, &val);
    });

    let submit = {
        let cid = channel_id.clone();
        let relay = relay.clone();
        move || {
            let body = text.get_untracked().trim().to_string();
            if body.is_empty() || sending.get_untracked() {
                return;
            }
            let Some(signer) = auth.get_signer() else {
                toasts.show("Sign in first to post", ToastVariant::Warning);
                return;
            };
            // Built now, from the resolved root: a reply threads under the
            // topic root (quoting the tapped post), a new topic carries the
            // topic marker, exactly as the forum tags them.
            let rtarget = reply_to.get_untracked();
            let mut tags = match topic {
                None => topic_root_tags(&cid),
                Some(root) => {
                    let Some(root) = root.get_untracked() else {
                        toasts.show("The topic is still loading", ToastVariant::Warning);
                        return;
                    };
                    let quote = rtarget.as_ref().map(|(id, pk)| (id.as_str(), pk.as_str()));
                    topic_reply_tags(&cid, &root.id, &root.pubkey, quote)
                }
            };
            let me = signer.public_key().to_string();
            let cid = cid.clone();
            let relay = relay.clone();
            sending.set(true);

            wasm_bindgen_futures::spawn_local(async move {
                // Resolve @handles against ProfileCache
                if let Some(pc) = profiles {
                    let handles: Vec<String> = body
                        .split_whitespace()
                        .filter_map(|w| w.strip_prefix('@'))
                        .map(|h| {
                            h.trim_matches(|c: char| {
                                !c.is_ascii_alphanumeric() && c != '_' && c != '-'
                            })
                            .to_ascii_lowercase()
                        })
                        .filter(|h| !h.is_empty())
                        .collect();
                    if !handles.is_empty() {
                        let entries = pc.entries.get_untracked();
                        for (pk, entry) in entries {
                            let hit = entry
                                .name
                                .as_deref()
                                .map(|n| handles.contains(&n.to_ascii_lowercase()))
                                .unwrap_or(false)
                                || entry
                                    .display_name
                                    .as_deref()
                                    .map(|n| {
                                        handles.contains(&n.to_ascii_lowercase().replace(' ', ""))
                                    })
                                    .unwrap_or(false);
                            if hit
                                && !tags.iter().any(|t| {
                                    t.first().map(String::as_str) == Some("p")
                                        && t.get(1).map(String::as_str) == Some(pk.as_str())
                                })
                            {
                                tags.push(vec!["p".into(), pk]);
                            }
                        }
                    }
                }

                let unsigned = UnsignedEvent {
                    pubkey: me,
                    created_at: (js_sys::Date::now() / 1000.0) as u64,
                    kind: 42,
                    tags,
                    content: body,
                };
                let unsigned = match writer.prepare(&cid, Some(signer.clone()), unsigned).await {
                    Ok(u) => u,
                    Err(e) => {
                        sending.set(false);
                        toasts.show(e, ToastVariant::Error);
                        return;
                    }
                };
                match signer.sign_event(unsigned).await {
                    Ok(signed) => {
                        let toasts_ack = toasts;
                        let cb = Rc::new(move |ok: bool, msg: String| {
                            if !ok {
                                toasts_ack.show(
                                    if msg.is_empty() {
                                        "Relay rejected post".to_string()
                                    } else {
                                        format!("Relay rejected: {msg}")
                                    },
                                    ToastVariant::Error,
                                );
                            }
                        });
                        let _ = relay.publish_with_ack(&signed, Some(cb));
                        text.set(String::new());
                        reply_to.set(None);
                        on_sent.run(());
                    }
                    Err(e) => toasts.show(format!("Sign failed: {e}"), ToastVariant::Error),
                }
                sending.set(false);
            });
        }
    };

    let on_pick_file = {
        let zid = zone_id.clone();
        move |ev: web_sys::Event| {
            #[cfg(target_arch = "wasm32")]
            {
                use wasm_bindgen::JsCast;
                let Some(inp) = ev
                    .target()
                    .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                else {
                    return;
                };
                let Some(file) = inp.files().and_then(|fl| fl.get(0)) else {
                    return;
                };
                inp.set_value("");
                let Some(signer) = auth.get_signer() else {
                    toasts.show("Sign in to upload images", ToastVariant::Warning);
                    return;
                };
                let pk = signer.public_key().to_string();
                let pod_api = cfg.with_value(|c| c.pod_api.clone());
                let zid = zid.clone();
                uploading.set(true);
                wasm_bindgen_futures::spawn_local(async move {
                    let effective_pod = if !pod_api.is_empty() {
                        pod_api
                    } else {
                        nostr_bbs_client_core::utils::relay_url::pod_api_base()
                    };
                    let _ = zid;
                    let res = crate::upload::compress_and_upload(
                        &file,
                        &pk,
                        signer.as_ref(),
                        &effective_pod,
                    )
                    .await;
                    match res {
                        Ok(url) => {
                            text.update(|d| {
                                if !d.is_empty() && !d.ends_with('\n') && !d.ends_with(' ') {
                                    d.push('\n');
                                }
                                d.push_str(&url);
                            });
                            toasts.show("Image uploaded to pod", ToastVariant::Success);
                        }
                        Err(e) => toasts.show(format!("Upload failed: {e}"), ToastVariant::Error),
                    }
                    uploading.set(false);
                });
            }
            #[cfg(not(target_arch = "wasm32"))]
            let _ = (ev, &zid, &cfg);
        }
    };

    let submit_click = submit.clone();
    let submit_key = submit.clone();

    view! {
        {move || if !auth.is_authenticated().get() {
            view! {
                <div class="tui-card tui-row-between">
                    <span class="tui-muted">"Sign in to post or reply in this board."</span>
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-primary bbs-btn-sm"
                        on:click=move |_| router.go(Route::Settings)
                    >"Sign in"</button>
                </div>
            }.into_any()
        } else {
            let sc = submit_click.clone();
            let sk = submit_key.clone();
            let op = on_pick_file.clone();
            view! {
                <div class="bbs-composer" id="bbs-reply-composer">
                    {move || reply_to.get().map(|(id, _)| view! {
                        <div class="tui-row-between" style="font-size:0.8rem">
                            <span class="tui-muted">"↳ Quoting " {shorten_pubkey(&id)} " · replies to the topic"</span>
                            <button
                                type="button"
                                class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                                on:click=move |_| reply_to.set(None)
                            >"Reply to topic"</button>
                        </div>
                    })}
                    <textarea
                        class="bbs-textarea"
                        placeholder=placeholder
                        prop:value=move || text.get()
                        on:input=move |ev| text.set(event_target_value(&ev))
                        on:keydown=move |ev| {
                            if (ev.ctrl_key() || ev.meta_key()) && ev.key() == "Enter" {
                                ev.prevent_default();
                                sk();
                            }
                        }
                    ></textarea>
                    <div class="tui-row-between">
                        <div class="tui-row">
                            <button
                                type="button"
                                class="bbs-btn bbs-btn-sm"
                                disabled=move || uploading.get()
                                on:click=move |_| {
                                    if let Some(el) = file_ref.get_untracked() {
                                        el.click();
                                    }
                                }
                            >
                                {move || if uploading.get() { "… Uploading" } else { "▞ Image" }}
                            </button>
                            <input
                                node_ref=file_ref
                                type="file"
                                accept="image/*"
                                class="bbs-file-input"
                                on:change=op
                            />
                            <span class="tui-muted" style="font-size:0.76rem">"Ctrl+Enter to send"</span>
                        </div>
                        <button
                            type="button"
                            class="bbs-btn bbs-btn-primary"
                            disabled=move || sending.get() || text.get().trim().is_empty()
                            on:click=move |_| sc()
                        >
                            {move || if sending.get() { "Sending…" } else { "Send ▶" }}
                        </button>
                    </div>
                </div>
            }.into_any()
        }}
    }
}

#[cfg(test)]
mod tests {
    /// The sheet's text with comments removed, for rule checks.
    fn css() -> String {
        let raw = include_str!("../../assets/bbs.css");
        let mut out = String::new();
        let mut rest = raw;
        while let Some(at) = rest.find("/*") {
            out.push_str(&rest[..at]);
            rest = rest[at..]
                .find("*/")
                .map_or("", |end| &rest[at + end + 2..]);
        }
        out.push_str(rest);
        out
    }

    /// The body of the first rule whose selector list ends with `selector`,
    /// searching from `from`.
    fn rule<'a>(css: &'a str, selector: &str, from: usize) -> &'a str {
        let at = css[from..]
            .find(&format!("{selector} {{"))
            .map(|i| from + i)
            .unwrap_or_else(|| panic!("no rule for {selector}"));
        let body = &css[at..];
        &body[..body.find('}').expect("rule closes")]
    }

    #[test]
    fn topic_rows_have_fixed_line_heights() {
        let css = css();
        // Neither line of a row wraps, so "started by" or a long title never
        // adds a line.
        assert!(rule(&css, ".bbs-topic-meta", 0).contains("flex-wrap: nowrap"));
        assert!(rule(&css, ".bbs-topic-title-row", 0).contains("flex-wrap: nowrap"));
        assert!(rule(&css, ".bbs-topic-people", 0).contains("flex-wrap: nowrap"));
        let title = rule(&css, ".bbs-topic-title", 0);
        assert!(title.contains("white-space: nowrap") && title.contains("text-overflow: ellipsis"));
        // The reply count and time keep their width.
        assert!(rule(&css, ".bbs-topic-time", 0).contains("flex: 0 0 auto"));
    }

    #[test]
    fn phone_titles_always_take_two_lines() {
        // In the 2x phone layout the title may wrap to two lines and always
        // reserves both (em, so it follows the text scale).
        let css = css();
        let phone = css.find("--fs-mobile: 2;").expect("the phone media query");
        let title = rule(&css, ".bbs-topic-title", phone);
        assert!(title.contains("-webkit-line-clamp: 2"));
        assert!(title.contains("min-height: 3em"));
        assert!(title.contains("white-space: normal"));
    }

    #[test]
    fn the_updated_control_keeps_its_space_when_hidden() {
        let css = css();
        let hidden = rule(&css, ".bbs-hidden-keep-space", 0);
        assert!(hidden.contains("visibility: hidden"));
        assert!(!hidden.contains("display: none"));
    }
}
