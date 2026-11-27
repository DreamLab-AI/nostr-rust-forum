//! Badge store backed by relay kind-8 (NIP-58 badge award) events.
//!
//! Provides `BadgeStore` via Leptos context. Fetches badge awards for the
//! current user's pubkey from the relay and exposes them as reactive signals.
//! Badge definitions are static (compiled in); awards come from kind-8 events.

use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use std::rc::Rc;

use crate::auth::use_auth;
use crate::relay::{Filter, RelayConnection};

// -- Badge definitions --------------------------------------------------------

/// Static badge metadata matching PRD 4.2.2 NIP-58 definitions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BadgeDefinition {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    /// CSS class for the badge icon color.
    pub color_class: &'static str,
    /// SVG icon identifier (resolved at render time).
    pub icon: BadgeIcon,
    /// Whether this badge is manually granted by admin.
    pub manual: bool,
}

/// Icon type for badge rendering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BadgeIcon {
    Pioneer,
    FirstPost,
    Conversationalist,
    Contributor,
    Helpful,
    Explorer,
    Trusted,
    FoundingMember,
    Moderator,
    OG,
}

/// All badge definitions from the PRD.
pub const BADGE_DEFINITIONS: &[BadgeDefinition] = &[
    BadgeDefinition {
        id: "pioneer",
        name: "Pioneer",
        description: "One of the first 20 community members",
        color_class: "text-amber-400",
        icon: BadgeIcon::Pioneer,
        manual: true,
    },
    BadgeDefinition {
        id: "first-post",
        name: "First Post",
        description: "Published your first message",
        color_class: "text-green-400",
        icon: BadgeIcon::FirstPost,
        manual: false,
    },
    BadgeDefinition {
        id: "conversationalist",
        name: "Conversationalist",
        description: "Published 10 or more messages",
        color_class: "text-blue-400",
        icon: BadgeIcon::Conversationalist,
        manual: false,
    },
    BadgeDefinition {
        id: "contributor",
        name: "Contributor",
        description: "Published 50 or more messages",
        color_class: "text-purple-400",
        icon: BadgeIcon::Contributor,
        manual: false,
    },
    BadgeDefinition {
        id: "helpful",
        name: "Helpful",
        description: "5 or more posts with 3+ reactions each",
        color_class: "text-pink-400",
        icon: BadgeIcon::Helpful,
        manual: false,
    },
    BadgeDefinition {
        id: "explorer",
        name: "Explorer",
        description: "Posted in 5 or more channels",
        color_class: "text-cyan-400",
        icon: BadgeIcon::Explorer,
        manual: false,
    },
    BadgeDefinition {
        id: "trusted",
        name: "Trusted",
        description: "Reached Trust Level 3",
        color_class: "text-emerald-400",
        icon: BadgeIcon::Trusted,
        manual: false,
    },
    BadgeDefinition {
        id: "founding-member",
        name: "Founding Member",
        description: "Registered before launch",
        color_class: "text-orange-400",
        icon: BadgeIcon::FoundingMember,
        manual: true,
    },
    BadgeDefinition {
        id: "moderator",
        name: "Community Moderator",
        description: "TL3 with 10+ resolved reports",
        color_class: "text-red-400",
        icon: BadgeIcon::Moderator,
        manual: false,
    },
    BadgeDefinition {
        id: "og",
        name: "OG",
        description: "1+ year community member",
        color_class: "text-yellow-300",
        icon: BadgeIcon::OG,
        manual: false,
    },
];

/// Look up a badge definition by its ID.
pub fn badge_def(id: &str) -> Option<&'static BadgeDefinition> {
    BADGE_DEFINITIONS.iter().find(|b| b.id == id)
}

// -- Earned badge -------------------------------------------------------------

/// A badge earned by a user, linking an award event to its definition.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct EarnedBadge {
    /// Badge definition ID.
    pub badge_id: String,
    /// Timestamp of the award event.
    pub awarded_at: u64,
    /// Event ID of the kind-8 award.
    pub event_id: String,
}

// -- Fetch state --------------------------------------------------------------

/// How long a completed badge fetch is treated as current.
pub const BADGE_TTL_SECS: f64 = 300.0;

/// State of a badge-award fetch.
///
/// The previous design had a single `loaded: bool` that a five-second timeout
/// set to `true` whether or not the relay had answered. That conflates three
/// different situations — still loading, "the relay says this user has no
/// badges", and "we never got an answer" — and the profile page rendered the
/// last two identically as "No badges earned yet". A missing answer is not the
/// same claim as an empty answer, so the state says which it is.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BadgeFetchState {
    /// The subscription is open and has not reached EOSE.
    Loading,
    /// The relay reached EOSE at `as_of` (epoch seconds) — whatever we hold is
    /// the complete answer as of then.
    Loaded { as_of: f64 },
    /// The deadline passed without an EOSE. `last_ok` carries the previous
    /// complete answer's timestamp, when there was one.
    Unavailable { last_ok: Option<f64> },
}

/// What the badge section should render.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BadgeListView {
    /// Waiting on the first answer, nothing to show yet.
    Loading,
    /// The relay answered and this user has no badges. The only case where
    /// "No badges earned yet" is a true statement.
    Empty { as_of: f64 },
    /// Badges to show, with the age of the snapshot they came from.
    Awarded {
        count: usize,
        as_of: Option<f64>,
        stale: bool,
    },
    /// No answer, and nothing cached to fall back on. Badge status is unknown —
    /// explicitly not "this user has none".
    Unavailable { last_ok: Option<f64> },
}

/// Derive what to render from the fetch state and how many awards are held.
///
/// Awards already streamed in are always shown, even mid-fetch or after a
/// timeout — they are real events, and hiding them would lose information. What
/// changes with the state is whether an EMPTY list is presented as a fact
/// (`Empty`) or as an absence of information (`Unavailable`), and whether the
/// snapshot behind a non-empty list is flagged as stale.
pub fn badge_list_view(state: BadgeFetchState, count: usize, now: f64, ttl: f64) -> BadgeListView {
    match state {
        BadgeFetchState::Loading => {
            if count == 0 {
                BadgeListView::Loading
            } else {
                BadgeListView::Awarded {
                    count,
                    as_of: None,
                    stale: false,
                }
            }
        }
        BadgeFetchState::Loaded { as_of } => {
            let stale = crate::utils::freshness::is_stale(as_of, now, ttl);
            if count > 0 {
                BadgeListView::Awarded {
                    count,
                    as_of: Some(as_of),
                    stale,
                }
            } else if stale {
                // An empty answer that has aged out is no longer a claim about
                // now; say we do not know rather than assert "none".
                BadgeListView::Unavailable {
                    last_ok: Some(as_of),
                }
            } else {
                BadgeListView::Empty { as_of }
            }
        }
        BadgeFetchState::Unavailable { last_ok } => {
            if count > 0 {
                BadgeListView::Awarded {
                    count,
                    as_of: last_ok,
                    stale: true,
                }
            } else {
                BadgeListView::Unavailable { last_ok }
            }
        }
    }
}

// -- Reactive store -----------------------------------------------------------

/// Reactive badge store, provided via context.
#[derive(Clone, Copy)]
pub struct BadgeStore {
    /// Badges earned by the current user.
    pub badges: RwSignal<Vec<EarnedBadge>>,
    /// Whether badge data has been loaded from the relay.
    pub loaded: RwSignal<bool>,
    /// Explicit fetch state — loading, complete-at, or unavailable.
    pub state: RwSignal<BadgeFetchState>,
}

impl BadgeStore {
    fn new() -> Self {
        Self {
            badges: RwSignal::new(Vec::new()),
            loaded: RwSignal::new(false),
            state: RwSignal::new(BadgeFetchState::Loading),
        }
    }

    /// Fetch badge awards (kind-8) for a given pubkey from the relay.
    pub fn fetch_for_pubkey(&self, pubkey: &str) {
        let relay = expect_context::<RelayConnection>();
        let badges = self.badges;
        let loaded = self.loaded;
        let pk = pubkey.to_string();

        // Query kind-8 events where p tag matches the pubkey
        let filter = Filter {
            kinds: Some(vec![8]),
            p_tags: Some(vec![pk.clone()]),
            limit: Some(100),
            ..Default::default()
        };

        let on_event = Rc::new(move |event: nostr_bbs_core::NostrEvent| {
            if event.kind != 8 {
                return;
            }
            // Extract badge ID from the `a` tag (format: "30009:<pubkey>:<badge-id>")
            let badge_id = event
                .tags
                .iter()
                .find(|t| t.len() >= 2 && t[0] == "a")
                .and_then(|t| t[1].rsplit(':').next())
                .map(String::from);

            if let Some(bid) = badge_id {
                badges.update(|list| {
                    // Deduplicate by badge_id
                    if !list.iter().any(|b| b.badge_id == bid) {
                        list.push(EarnedBadge {
                            badge_id: bid,
                            awarded_at: event.created_at,
                            event_id: event.id.clone(),
                        });
                    }
                });
            }
        });

        // EOSE is the relay's receipt that it has sent every award it holds.
        // That, and only that, makes the list authoritative.
        let state = self.state;
        let on_eose = Rc::new(move || {
            loaded.set(true);
            state.set(BadgeFetchState::Loaded {
                as_of: js_sys::Date::now() / 1000.0,
            });
        });

        let sub_id = relay.subscribe(vec![filter], on_event, Some(on_eose));

        // Bounded deadline. It is a FAILURE path: reaching it without an EOSE
        // means the answer never arrived, which is recorded as `Unavailable`
        // rather than being passed off as a complete, empty result.
        let relay_cleanup = relay.clone();
        crate::utils::set_timeout_once(
            move || {
                relay_cleanup.unsubscribe(&sub_id);
                loaded.set(true);
                state.update(|s| {
                    if matches!(s, BadgeFetchState::Loading) {
                        *s = BadgeFetchState::Unavailable { last_ok: None };
                    }
                });
            },
            5_000,
        );
    }

    /// Check if the user has a specific badge.
    #[allow(dead_code)]
    pub fn has_badge(&self, badge_id: &str) -> bool {
        self.badges
            .get_untracked()
            .iter()
            .any(|b| b.badge_id == badge_id)
    }

    /// Get badge IDs as a reactive memo.
    #[allow(dead_code)]
    pub fn badge_ids(&self) -> Memo<Vec<String>> {
        let badges = self.badges;
        Memo::new(move |_| badges.get().iter().map(|b| b.badge_id.clone()).collect())
    }
}

// -- Context providers --------------------------------------------------------

/// Provide the badge store context. Call once near the app root.
pub fn provide_badges() {
    let store = BadgeStore::new();
    provide_context(store);
}

/// Read the badge store from context.
pub fn use_badges() -> BadgeStore {
    use_context::<BadgeStore>().unwrap_or_else(|| {
        let store = BadgeStore::new();
        provide_context(store);
        store
    })
}

/// Initialize badge fetching for the current authenticated user.
/// Call this after auth is established and relay is connected.
pub fn init_badge_sync() {
    let auth = use_auth();
    let store = use_badges();

    Effect::new(move |_| {
        if store.loaded.get_untracked() {
            return;
        }
        if let Some(pk) = auth.pubkey().get() {
            store.fetch_for_pubkey(&pk);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: f64 = BADGE_TTL_SECS;
    const NOW: f64 = 1_000_000.0;

    #[test]
    fn nothing_yet_is_loading_not_empty() {
        assert_eq!(
            badge_list_view(BadgeFetchState::Loading, 0, NOW, TTL),
            BadgeListView::Loading
        );
    }

    #[test]
    fn awards_stream_in_before_the_answer_completes() {
        assert_eq!(
            badge_list_view(BadgeFetchState::Loading, 2, NOW, TTL),
            BadgeListView::Awarded {
                count: 2,
                as_of: None,
                stale: false
            }
        );
    }

    /// The defect: a fetch that never answered used to render exactly like
    /// "this user has no badges".
    #[test]
    fn a_failed_fetch_is_not_the_same_as_having_no_badges() {
        let none = badge_list_view(BadgeFetchState::Loaded { as_of: NOW }, 0, NOW, TTL);
        let broken = badge_list_view(BadgeFetchState::Unavailable { last_ok: None }, 0, NOW, TTL);
        assert_eq!(none, BadgeListView::Empty { as_of: NOW });
        assert_eq!(broken, BadgeListView::Unavailable { last_ok: None });
        assert_ne!(none, broken);
    }

    #[test]
    fn an_eose_with_no_awards_is_an_authoritative_empty() {
        assert_eq!(
            badge_list_view(BadgeFetchState::Loaded { as_of: NOW - 10.0 }, 0, NOW, TTL),
            BadgeListView::Empty { as_of: NOW - 10.0 }
        );
    }

    #[test]
    fn an_empty_answer_that_aged_out_stops_asserting_emptiness() {
        assert_eq!(
            badge_list_view(
                BadgeFetchState::Loaded {
                    as_of: NOW - TTL - 1.0
                },
                0,
                NOW,
                TTL
            ),
            BadgeListView::Unavailable {
                last_ok: Some(NOW - TTL - 1.0)
            }
        );
    }

    #[test]
    fn a_complete_answer_carries_its_as_of_and_freshness() {
        assert_eq!(
            badge_list_view(BadgeFetchState::Loaded { as_of: NOW - 5.0 }, 3, NOW, TTL),
            BadgeListView::Awarded {
                count: 3,
                as_of: Some(NOW - 5.0),
                stale: false
            }
        );
        assert_eq!(
            badge_list_view(
                BadgeFetchState::Loaded {
                    as_of: NOW - TTL - 5.0
                },
                3,
                NOW,
                TTL
            ),
            BadgeListView::Awarded {
                count: 3,
                as_of: Some(NOW - TTL - 5.0),
                stale: true
            }
        );
    }

    #[test]
    fn awards_already_held_survive_a_timeout_but_are_marked_stale() {
        assert_eq!(
            badge_list_view(
                BadgeFetchState::Unavailable {
                    last_ok: Some(NOW - 30.0)
                },
                2,
                NOW,
                TTL
            ),
            BadgeListView::Awarded {
                count: 2,
                as_of: Some(NOW - 30.0),
                stale: true
            }
        );
    }

    #[test]
    fn every_view_is_distinguishable() {
        let views = [
            badge_list_view(BadgeFetchState::Loading, 0, NOW, TTL),
            badge_list_view(BadgeFetchState::Loaded { as_of: NOW }, 0, NOW, TTL),
            badge_list_view(BadgeFetchState::Loaded { as_of: NOW }, 1, NOW, TTL),
            badge_list_view(BadgeFetchState::Unavailable { last_ok: None }, 0, NOW, TTL),
        ];
        for (i, a) in views.iter().enumerate() {
            for (j, b) in views.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "views {i} and {j} render the same");
                }
            }
        }
    }

    #[test]
    fn badge_definitions_are_all_resolvable() {
        for def in BADGE_DEFINITIONS {
            assert!(badge_def(def.id).is_some(), "unresolvable badge {}", def.id);
        }
        assert!(badge_def("not-a-badge").is_none());
    }
}
