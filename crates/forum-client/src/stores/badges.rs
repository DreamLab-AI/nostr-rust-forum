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

// -- Reactive store -----------------------------------------------------------

/// Reactive badge store, provided via context.
#[derive(Clone, Copy)]
pub struct BadgeStore {
    /// Badges earned by the current user.
    pub badges: RwSignal<Vec<EarnedBadge>>,
    /// Whether badge data has been loaded from the relay.
    pub loaded: RwSignal<bool>,
}

impl BadgeStore {
    fn new() -> Self {
        Self {
            badges: RwSignal::new(Vec::new()),
            loaded: RwSignal::new(false),
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

        let on_event = Rc::new(move |event: nostr_core::NostrEvent| {
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

        let on_eose = Rc::new(move || {
            loaded.set(true);
        });

        let sub_id = relay.subscribe(vec![filter], on_event, Some(on_eose));

        // Timeout after 5 seconds
        let relay_cleanup = relay.clone();
        crate::utils::set_timeout_once(
            move || {
                relay_cleanup.unsubscribe(&sub_id);
                loaded.set(true);
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
        Memo::new(move |_| {
            badges
                .get()
                .iter()
                .map(|b| b.badge_id.clone())
                .collect()
        })
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
