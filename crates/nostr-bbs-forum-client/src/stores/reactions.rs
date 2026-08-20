//! Shared NIP-25 reaction store (kind-7 emoji reactions + kind-5 un-reacts).
//!
//! Subscribes once at app root to kind-7 (reactions) and kind-5 (deletions) and
//! aggregates, per reacted-to event, how many distinct users reacted with each
//! emoji. All message cards read from the same reactive signal via
//! [`ReactionStore::reactions_for`] — no per-card subscription.
//!
//! ## Data model
//!
//! - `aggregate`: `target_event_id -> emoji -> {reactor_pubkey}`. The count of an
//!   emoji is the size of its pubkey set, so a user reacting twice with the same
//!   emoji still counts once (NIP-25: one reaction per user per emoji per event).
//! - `index`: `kind7_event_id -> ReactionRef`. A kind-5 deletion references the
//!   kind-7 event id it removes, so this reverse map is what lets an un-react
//!   subtract the right (target, emoji, pubkey) triple.
//! - `tombstones`: kind-7 ids removed by a kind-5 that has already been seen. A
//!   deletion can arrive BEFORE the reaction it deletes (backfill order is not
//!   guaranteed — see [`crate::stores::channels`]); the tombstone suppresses the
//!   kind-7 when it later lands.
//!
//! ## Trust model
//!
//! Identical to the kind-5 message-deletion fold in `channels.rs`: the relay is
//! whitelist + NIP-42 AUTH gated and enforces WHO may delete (a user may delete
//! only their own events). The client folds any stored/broadcast kind-5 that
//! targets a known kind-7 without re-checking authorship; re-checking here would
//! duplicate — and could disagree with — the server's authority.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use leptos::prelude::*;
use nostr_bbs_core::NostrEvent;

use crate::components::reaction_bar::Reaction;
use crate::relay::{Filter, RelayConnection};
use crate::stores::channels::deletion_targets;

// -- Types --------------------------------------------------------------------

/// The (target, emoji, reactor) a single kind-7 reaction resolves to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReactionRef {
    /// Lowercased id of the event that was reacted to.
    pub target: String,
    /// The reaction emoji (NIP-25 `content`; empty is normalised to "+").
    pub emoji: String,
    /// Lowercased pubkey of the user who reacted.
    pub pubkey: String,
}

/// `target_event_id -> emoji -> {reactor_pubkey}` (all keys lowercased).
type Aggregate = HashMap<String, HashMap<String, HashSet<String>>>;
/// `kind7_event_id -> ReactionRef` (all ids/pubkeys lowercased).
type ReactionIndex = HashMap<String, ReactionRef>;

// -- ReactionStore ------------------------------------------------------------

/// Global reaction store provided via Leptos context. Subscribe once at app
/// root; every message card reads the same signals.
#[derive(Clone, Copy)]
pub struct ReactionStore {
    /// target → emoji → set of reactor pubkeys. Bumped on every fold so
    /// [`reactions_for`](Self::reactions_for) derivations re-run.
    aggregate: RwSignal<Aggregate>,
    /// kind-7 id → the reaction it represents (for kind-5 deletion + un-react).
    index: RwSignal<ReactionIndex>,
    /// kind-7 ids deleted by a kind-5 (suppresses out-of-order arrival).
    tombstones: RwSignal<HashSet<String>>,
    sub_id: RwSignal<Option<String>>,
}

impl ReactionStore {
    fn new() -> Self {
        Self {
            aggregate: RwSignal::new(HashMap::new()),
            index: RwSignal::new(HashMap::new()),
            tombstones: RwSignal::new(HashSet::new()),
            sub_id: RwSignal::new(None),
        }
    }

    /// Start the relay subscription. Called once from App root after connect.
    ///
    /// A single BROAD `{kinds: [5, 7]}` subscription (mirrors the broad kind-42
    /// message sub in [`crate::stores::channels`]) rather than a per-event
    /// `#e`-filtered REQ: message ids load asynchronously and lazily, so the
    /// client rarely has the full id set up front, and a broad sub means a card
    /// scrolled into view already has its reactions cached. Idempotent: a second
    /// call while a sub is live is a no-op.
    pub(crate) fn start_sync(&self, relay: &RelayConnection) {
        if self.sub_id.get_untracked().is_some() {
            return;
        }

        let aggregate = self.aggregate;
        let index = self.index;
        let tombstones = self.tombstones;

        let on_event = Rc::new(move |event: NostrEvent| match event.kind {
            7 => {
                if let Some(r) = parse_reaction(&event) {
                    let id = event.id.to_lowercase();
                    aggregate.update(|agg| {
                        index.update(|idx| {
                            tombstones.update(|tomb| {
                                fold_add(agg, idx, tomb, id, r);
                            });
                        });
                    });
                }
            }
            5 => {
                let deleted = deletion_targets(&event);
                if !deleted.is_empty() {
                    aggregate.update(|agg| {
                        index.update(|idx| {
                            tombstones.update(|tomb| {
                                fold_remove(agg, idx, tomb, &deleted);
                            });
                        });
                    });
                }
            }
            _ => {}
        });

        let id = relay.subscribe(
            vec![Filter {
                kinds: Some(vec![5, 7]),
                ..Default::default()
            }],
            on_event,
            None,
        );
        self.sub_id.set(Some(id));
    }

    /// A reactive list of grouped reactions for one event, ordered most-reacted
    /// first. Re-runs when the aggregate changes OR the logged-in user changes
    /// (so `reacted_by_me` highlighting flips on login/logout).
    pub fn reactions_for(&self, event_id: &str) -> Signal<Vec<Reaction>> {
        let target = event_id.to_lowercase();
        let aggregate = self.aggregate;
        let auth = crate::auth::use_auth();
        Signal::derive(move || {
            let me = auth.pubkey().get().unwrap_or_default().to_lowercase();
            aggregate.with(|agg| build_reactions(agg.get(&target), &me))
        })
    }

    /// Whether `pubkey` has an active `emoji` reaction on `target`.
    pub fn has_my_reaction(&self, target: &str, emoji: &str, pubkey: &str) -> bool {
        let target = target.to_lowercase();
        let pubkey = pubkey.to_lowercase();
        self.aggregate.with_untracked(|agg| {
            agg.get(&target)
                .and_then(|by_emoji| by_emoji.get(emoji))
                .map(|pks| pks.contains(&pubkey))
                .unwrap_or(false)
        })
    }

    /// The id of `pubkey`'s own kind-7 event for `(target, emoji)`, needed to
    /// address a NIP-09 kind-5 deletion when un-reacting. `None` if that
    /// reaction's originating event has not been seen (e.g. reacted on another
    /// device and the replay has not arrived yet).
    pub fn my_reaction_id(&self, target: &str, emoji: &str, pubkey: &str) -> Option<String> {
        let target = target.to_lowercase();
        let pubkey = pubkey.to_lowercase();
        self.index.with_untracked(|idx| {
            idx.iter()
                .find(|(_, r)| r.target == target && r.emoji == emoji && r.pubkey == pubkey)
                .map(|(id, _)| id.clone())
        })
    }

    /// Optimistically record a freshly-signed kind-7 so the pill updates without
    /// waiting for the relay echo. Idempotent with the echoed event (set insert +
    /// index overwrite by the same id).
    pub fn add_local(&self, kind7_id: &str, target: &str, emoji: &str, pubkey: &str) {
        let r = ReactionRef {
            target: target.to_lowercase(),
            emoji: emoji.to_string(),
            pubkey: pubkey.to_lowercase(),
        };
        let id = kind7_id.to_lowercase();
        self.aggregate.update(|agg| {
            self.index.update(|idx| {
                self.tombstones.update(|tomb| {
                    fold_add(agg, idx, tomb, id, r);
                });
            });
        });
    }

    /// Optimistically remove a kind-7 by id (the un-react path), mirroring the
    /// kind-5 deletion fold so it is idempotent with the relay echo.
    pub fn remove_local(&self, kind7_id: &str) {
        let deleted = [kind7_id.to_lowercase()];
        self.aggregate.update(|agg| {
            self.index.update(|idx| {
                self.tombstones.update(|tomb| {
                    fold_remove(agg, idx, tomb, &deleted);
                });
            });
        });
    }

    /// Cleanup the subscription on unmount.
    pub(crate) fn cleanup(&self, relay: &RelayConnection) {
        if let Some(id) = self.sub_id.get_untracked() {
            relay.unsubscribe(&id);
        }
    }
}

// -- Context helpers ----------------------------------------------------------

/// Provide the reaction store. Call once in App root.
pub fn provide_reaction_store() {
    provide_context(ReactionStore::new());
}

/// Get the reaction store from context.
pub fn use_reaction_store() -> ReactionStore {
    expect_context::<ReactionStore>()
}

// -- Pure helpers (unit-tested) -----------------------------------------------

/// Normalise a kind-7 `content` into a display token. NIP-25 uses an empty
/// content (and "+") for a generic like; both render as "+".
fn normalise_emoji(content: &str) -> String {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        "+".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Resolve a kind-7 event into the `(target, emoji, reactor)` it represents, or
/// `None` when it is not a reaction (wrong kind) or carries no `e` tag.
///
/// Per NIP-25 the reacted-to event is the LAST `e` tag; this client publishes a
/// single `e` tag, so first == last, but taking the last keeps interop correct
/// for reactions authored by other NIP-25 clients.
pub fn parse_reaction(event: &NostrEvent) -> Option<ReactionRef> {
    if event.kind != 7 {
        return None;
    }
    let target = event
        .tags
        .iter()
        .rfind(|t| t.len() >= 2 && t[0] == "e")
        .map(|t| t[1].to_lowercase())
        .filter(|id| !id.is_empty())?;
    Some(ReactionRef {
        target,
        emoji: normalise_emoji(&event.content),
        pubkey: event.pubkey.to_lowercase(),
    })
}

/// Fold a kind-7 reaction into the aggregate + index.
///
/// A tombstoned id (its kind-5 already seen) is dropped so an out-of-order
/// reaction can't resurrect a removed pill. Otherwise the reactor is added to
/// the `(target, emoji)` set and the id is indexed for later deletion.
pub fn fold_add(
    aggregate: &mut Aggregate,
    index: &mut ReactionIndex,
    tombstones: &HashSet<String>,
    kind7_id: String,
    r: ReactionRef,
) {
    if tombstones.contains(&kind7_id) {
        return;
    }
    aggregate
        .entry(r.target.clone())
        .or_default()
        .entry(r.emoji.clone())
        .or_default()
        .insert(r.pubkey.clone());
    index.insert(kind7_id, r);
}

/// Fold kind-5 deletions: tombstone each id and, when it names a known kind-7,
/// subtract that reactor from the `(target, emoji)` set, pruning empties so a
/// zero-count pill disappears.
pub fn fold_remove(
    aggregate: &mut Aggregate,
    index: &mut ReactionIndex,
    tombstones: &mut HashSet<String>,
    deleted: &[String],
) {
    for id in deleted {
        let id = id.to_lowercase();
        tombstones.insert(id.clone());
        if let Some(r) = index.remove(&id) {
            if let Some(by_emoji) = aggregate.get_mut(&r.target) {
                if let Some(pks) = by_emoji.get_mut(&r.emoji) {
                    pks.remove(&r.pubkey);
                    if pks.is_empty() {
                        by_emoji.remove(&r.emoji);
                    }
                }
                if by_emoji.is_empty() {
                    aggregate.remove(&r.target);
                }
            }
        }
    }
}

/// Build the display list for one target's emoji map, ordered most-reacted
/// first (ties broken by emoji for stable rendering). `me` is the lowercased
/// pubkey of the logged-in user, used to flag `reacted_by_me`.
pub fn build_reactions(
    by_emoji: Option<&HashMap<String, HashSet<String>>>,
    me: &str,
) -> Vec<Reaction> {
    let mut out: Vec<Reaction> = match by_emoji {
        Some(map) => map
            .iter()
            .filter(|(_, pks)| !pks.is_empty())
            .map(|(emoji, pks)| Reaction {
                emoji: emoji.clone(),
                count: pks.len() as u32,
                reacted_by_me: !me.is_empty() && pks.contains(me),
            })
            .collect(),
        None => Vec::new(),
    };
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.emoji.cmp(&b.emoji)));
    out
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(id: &str, pubkey: &str, kind: u64, content: &str, tags: &[&[&str]]) -> NostrEvent {
        NostrEvent {
            id: id.to_string(),
            pubkey: pubkey.to_string(),
            created_at: 0,
            kind,
            tags: tags
                .iter()
                .map(|t| t.iter().map(|s| s.to_string()).collect())
                .collect(),
            content: content.to_string(),
            sig: String::new(),
        }
    }

    #[test]
    fn parse_reaction_extracts_target_emoji_reactor() {
        let e = ev(
            "r1",
            "ALICE",
            7,
            "\u{1F44D}",
            &[&["e", "POST1"], &["p", "bob"]],
        );
        let r = parse_reaction(&e).unwrap();
        assert_eq!(r.target, "post1"); // lowercased
        assert_eq!(r.emoji, "\u{1F44D}");
        assert_eq!(r.pubkey, "alice"); // lowercased
    }

    #[test]
    fn parse_reaction_prefers_last_e_tag() {
        // NIP-25: the reacted-to event is the last `e` tag.
        let e = ev(
            "r1",
            "alice",
            7,
            "\u{2764}",
            &[&["e", "root"], &["e", "post2"]],
        );
        assert_eq!(parse_reaction(&e).unwrap().target, "post2");
    }

    #[test]
    fn parse_reaction_normalises_empty_content_to_plus() {
        let e = ev("r1", "alice", 7, "", &[&["e", "post1"]]);
        assert_eq!(parse_reaction(&e).unwrap().emoji, "+");
    }

    #[test]
    fn parse_reaction_rejects_non_kind7_and_missing_e_tag() {
        assert!(parse_reaction(&ev("x", "a", 1, "\u{1F44D}", &[&["e", "p"]])).is_none());
        assert!(parse_reaction(&ev("x", "a", 7, "\u{1F44D}", &[&["p", "someone"]])).is_none());
    }

    #[test]
    fn distinct_users_same_emoji_counted_once_each() {
        let mut agg = Aggregate::new();
        let mut idx = ReactionIndex::new();
        let tomb = HashSet::new();
        fold_add(
            &mut agg,
            &mut idx,
            &tomb,
            "r1".into(),
            ReactionRef {
                target: "post1".into(),
                emoji: "\u{1F44D}".into(),
                pubkey: "alice".into(),
            },
        );
        fold_add(
            &mut agg,
            &mut idx,
            &tomb,
            "r2".into(),
            ReactionRef {
                target: "post1".into(),
                emoji: "\u{1F44D}".into(),
                pubkey: "bob".into(),
            },
        );
        let out = build_reactions(agg.get("post1"), "alice");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].count, 2);
        assert!(out[0].reacted_by_me);
    }

    #[test]
    fn same_user_same_emoji_is_idempotent() {
        let mut agg = Aggregate::new();
        let mut idx = ReactionIndex::new();
        let tomb = HashSet::new();
        let r = ReactionRef {
            target: "post1".into(),
            emoji: "\u{1F44D}".into(),
            pubkey: "alice".into(),
        };
        fold_add(&mut agg, &mut idx, &tomb, "r1".into(), r.clone());
        fold_add(&mut agg, &mut idx, &tomb, "r1".into(), r);
        assert_eq!(build_reactions(agg.get("post1"), "")[0].count, 1);
    }

    #[test]
    fn deletion_removes_reactor_and_prunes_empty_pill() {
        let mut agg = Aggregate::new();
        let mut idx = ReactionIndex::new();
        let mut tomb = HashSet::new();
        fold_add(
            &mut agg,
            &mut idx,
            &tomb,
            "r1".into(),
            ReactionRef {
                target: "post1".into(),
                emoji: "\u{2764}".into(),
                pubkey: "alice".into(),
            },
        );
        // NIP-09 kind-5 targeting the kind-7 id.
        fold_remove(&mut agg, &mut idx, &mut tomb, &["r1".into()]);
        assert!(build_reactions(agg.get("post1"), "alice").is_empty());
        assert!(tomb.contains("r1"));
    }

    #[test]
    fn deletion_before_reaction_suppresses_it() {
        // Kind-5 arrives before the kind-7 it deletes (backfill order).
        let mut agg = Aggregate::new();
        let mut idx = ReactionIndex::new();
        let mut tomb = HashSet::new();
        fold_remove(&mut agg, &mut idx, &mut tomb, &["r1".into()]);
        fold_add(
            &mut agg,
            &mut idx,
            &tomb,
            "r1".into(),
            ReactionRef {
                target: "post1".into(),
                emoji: "\u{1F44D}".into(),
                pubkey: "alice".into(),
            },
        );
        assert!(build_reactions(agg.get("post1"), "").is_empty());
    }

    #[test]
    fn deletion_keeps_other_users_reactions() {
        let mut agg = Aggregate::new();
        let mut idx = ReactionIndex::new();
        let mut tomb = HashSet::new();
        fold_add(
            &mut agg,
            &mut idx,
            &tomb,
            "r1".into(),
            ReactionRef {
                target: "post1".into(),
                emoji: "\u{1F44D}".into(),
                pubkey: "alice".into(),
            },
        );
        fold_add(
            &mut agg,
            &mut idx,
            &tomb,
            "r2".into(),
            ReactionRef {
                target: "post1".into(),
                emoji: "\u{1F44D}".into(),
                pubkey: "bob".into(),
            },
        );
        fold_remove(&mut agg, &mut idx, &mut tomb, &["r1".into()]);
        let out = build_reactions(agg.get("post1"), "alice");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].count, 1); // only bob remains
        assert!(!out[0].reacted_by_me); // alice's reaction was removed
    }

    #[test]
    fn build_reactions_orders_by_count_desc_then_emoji() {
        let mut agg = Aggregate::new();
        let mut idx = ReactionIndex::new();
        let tomb = HashSet::new();
        // heart: 1, thumbs: 2
        fold_add(
            &mut agg,
            &mut idx,
            &tomb,
            "r1".into(),
            ReactionRef {
                target: "p".into(),
                emoji: "\u{2764}".into(),
                pubkey: "a".into(),
            },
        );
        fold_add(
            &mut agg,
            &mut idx,
            &tomb,
            "r2".into(),
            ReactionRef {
                target: "p".into(),
                emoji: "\u{1F44D}".into(),
                pubkey: "a".into(),
            },
        );
        fold_add(
            &mut agg,
            &mut idx,
            &tomb,
            "r3".into(),
            ReactionRef {
                target: "p".into(),
                emoji: "\u{1F44D}".into(),
                pubkey: "b".into(),
            },
        );
        let out = build_reactions(agg.get("p"), "");
        assert_eq!(out[0].emoji, "\u{1F44D}"); // count 2 first
        assert_eq!(out[1].emoji, "\u{2764}"); // count 1 second
    }
}
