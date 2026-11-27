//! Agent disclosure badge (COM-13/F2, ADR-106 Decision 3).
//!
//! Fetches the active agent set from the relay's public
//! `GET /api/agents/disclosure` endpoint and caches it in a Leptos context.
//! [`AgentBadge`] reads that cache reactively and, when a rendered author
//! pubkey belongs to an active agent, shows a visually distinct AGENT pill
//! naming the authorising principal (`registered_by`).
//!
//! Trust root: the authorising principal is always sourced from the server-side
//! registry, never from event content. A self-declared "I am an agent" tag
//! carries no badge; a registry-active agent always carries one. This mirrors
//! the relay's own registered-agent write gate, keeping disclosure honest.
//!
//! The cache is provided once at the app root, so the active set is fetched
//! once for the whole page rather than per badge.
//!
//! ## Freshness and failure are part of the disclosure
//!
//! The registry is a live, mutable record: a key can be registered, revoked, or
//! re-registered under a different principal at any time. A client that fetches
//! it once and fails silently therefore tells the reader something false. The
//! previous implementation did exactly that — a failed fetch logged a warning
//! and left the map empty, and an empty map renders no badge, which is the same
//! thing the UI shows for "this author is a human". A reader could not tell
//! "not an agent" from "we could not find out".
//!
//! So the cache carries an explicit [`DisclosureStatus`] — `Loading`, `Loaded`
//! with the timestamp it was fetched, or `Error` — and the badge derives a
//! [`BadgeState`] from it that distinguishes:
//!
//! - **loading** — no answer yet, agent status unknown (muted marker);
//! - **loaded and fresh** — the registry is authoritative; no badge means human;
//! - **agent** — an AGENT pill naming the authorising principal, carrying the
//!   as-of time in its tooltip and marked when the snapshot is stale;
//! - **stale / error** — the snapshot is past its freshness window or could not
//!   be read at all, so agent status is UNKNOWN and says so.
//!
//! Freshness is bounded ([`DISCLOSURE_TTL_SECS`]) and the cache refreshes
//! itself on an interval, backing off to a shorter retry after a failure, so an
//! already-open tab recovers from a transient outage and picks up registration
//! changes without being reloaded.
//!
//! Trust root: the authorising principal is always sourced from the server-side
//! registry, never from event content.

use leptos::prelude::*;

use crate::components::badge::{Badge, BadgeSize, BadgeVariant};
use crate::components::copy_key::KeyGlyph;

#[allow(unused_imports)]
pub use nostr_bbs_client_core::agent_disclosure::{
    as_of_of, badge_state, badge_title, format_as_of, freshness_of, now_secs,
    provide_agent_disclosure, try_use_agent_disclosure, AgentDisclosure, AgentDisclosureCache,
    BadgeState, DisclosureStatus, Freshness, DISCLOSURE_TTL_SECS,
};

/// Disclosure badge for a rendered author pubkey.
///
/// Four visually distinct outcomes, never collapsed into one another:
///
/// | State | Rendering |
/// |---|---|
/// | agent, fresh register | blue `AGENT · <principal>` pill |
/// | agent, stale register | same pill marked `·?`, tooltip carries the as-of |
/// | register unavailable / stale, author not listed | muted `AGENT?` pill — status unknown |
/// | register fresh, author not listed | nothing (the author is not an agent) |
/// | first fetch in flight | muted `·` placeholder |
///
/// The principal is resolved to a human label where kind-0 metadata exists
/// (`display_name` > `name` > NIP-05 > shortened pubkey). Every tooltip states
/// when the register was last read, so freshness is always inspectable.
#[component]
pub fn AgentBadge(
    /// The author pubkey being rendered.
    pubkey: String,
    /// Compact size for dense author lines.
    #[prop(optional)]
    compact: bool,
) -> impl IntoView {
    let pubkey_for_lookup = pubkey;

    // Reactive: re-evaluates when the fetch resolves, fails, or refreshes.
    let state = Memo::new(move |_| {
        let Some(cache) = try_use_agent_disclosure() else {
            // No cache in context at all: we have not looked, so we do not
            // know. Reporting "not an agent" here would be a claim we cannot
            // support.
            return BadgeState::Unknown {
                freshness: Freshness::Unknown,
                as_of: None,
            };
        };
        let entry = cache.lookup(&pubkey_for_lookup);
        badge_state(
            &cache.status(),
            entry.as_ref(),
            now_secs(),
            DISCLOSURE_TTL_SECS,
        )
    });

    // Human label for the authorising principal, resolved through the shared
    // profile cache. Falls back to the shortened principal pubkey while (or if)
    // its kind-0 metadata is unavailable.
    let principal_label = Memo::new(move |_| match state.get() {
        BadgeState::Agent { registered_by, .. } => Some(
            crate::components::user_display::use_display_name_tracked(&registered_by),
        ),
        _ => None,
    });

    let size = if compact {
        BadgeSize::Sm
    } else {
        BadgeSize::Md
    };

    view! {
        {move || {
            let current = state.get();
            let now = now_secs();
            match current {
                // Fresh register, author not listed: the only honest silence.
                BadgeState::NotAnAgent => ().into_any(),
                BadgeState::Agent { freshness, ref registered_by, .. } => {
                    let principal_pk = registered_by.clone();
                    let principal = principal_label
                        .get()
                        .unwrap_or_else(|| "an administrator".to_string());
                    let title = badge_title(&current, &principal, now);
                    let text = if freshness == Freshness::Fresh {
                        format!("AGENT \u{b7} {principal}")
                    } else {
                        // Same pill, explicitly marked as possibly out of date.
                        format!("AGENT \u{b7} {principal} \u{b7}?")
                    };
                    // While the principal has no profile name the pill shows
                    // its abridged key: a copy glyph beside the pill copies
                    // the full key (raised above any stretched-link overlay).
                    view! {
                        <span title=title>
                            <Badge text=text variant=BadgeVariant::Info size=size />
                        </span>
                        <KeyGlyph pubkey=principal_pk class="relative z-10" />
                    }
                    .into_any()
                }
                // The register could not be read (or has aged out): agent
                // status is unknown, and an unbadged author must NOT be read
                // as a human.
                BadgeState::Unknown { .. } => {
                    let title = badge_title(&current, "", now);
                    view! {
                        <span title=title>
                            <Badge
                                text="AGENT?".to_string()
                                variant=BadgeVariant::Ghost
                                size=size
                            />
                        </span>
                    }
                    .into_any()
                }
                // First fetch still in flight.
                BadgeState::Loading => {
                    let title = badge_title(&current, "", now);
                    view! {
                        <span
                            class="inline-block w-1.5 h-1.5 rounded-full bg-gray-600 align-middle ml-1 animate-pulse"
                            title=title
                            aria-hidden="true"
                        ></span>
                    }
                    .into_any()
                }
            }
        }}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: f64 = DISCLOSURE_TTL_SECS;
    const NOW: f64 = 1_000_000.0;

    fn agent(pubkey: &str, principal: &str) -> AgentDisclosure {
        AgentDisclosure {
            pubkey: pubkey.to_string(),
            name: "test-agent".to_string(),
            registered_by: principal.to_string(),
        }
    }

    fn loaded(age: f64) -> DisclosureStatus {
        DisclosureStatus::Loaded { as_of: NOW - age }
    }

    fn failed(last_ok: Option<f64>) -> DisclosureStatus {
        DisclosureStatus::Error {
            message: "HTTP 503".to_string(),
            last_ok: last_ok.map(|age| NOW - age),
        }
    }

    // -- Freshness ------------------------------------------------------------

    #[test]
    fn a_recent_snapshot_is_fresh() {
        assert_eq!(freshness_of(&loaded(10.0), NOW, TTL), Freshness::Fresh);
        assert_eq!(freshness_of(&loaded(TTL), NOW, TTL), Freshness::Fresh);
    }

    #[test]
    fn a_snapshot_past_the_window_is_stale() {
        assert_eq!(freshness_of(&loaded(TTL + 1.0), NOW, TTL), Freshness::Stale);
    }

    #[test]
    fn no_snapshot_is_unknown_freshness() {
        assert_eq!(
            freshness_of(&DisclosureStatus::Loading, NOW, TTL),
            Freshness::Unknown
        );
        assert_eq!(freshness_of(&failed(None), NOW, TTL), Freshness::Unknown);
    }

    #[test]
    fn a_failed_refresh_reports_the_last_good_snapshots_freshness() {
        assert_eq!(freshness_of(&failed(Some(5.0)), NOW, TTL), Freshness::Fresh);
        assert_eq!(
            freshness_of(&failed(Some(TTL + 5.0)), NOW, TTL),
            Freshness::Stale
        );
    }

    // -- The defect being closed ---------------------------------------------

    /// The whole point: a one-shot fetch failure used to render exactly the
    /// same as "this author has no badges". It must not.
    #[test]
    fn a_fetch_failure_is_not_the_same_as_not_being_an_agent() {
        let human = badge_state(&loaded(0.0), None, NOW, TTL);
        let broken = badge_state(&failed(None), None, NOW, TTL);
        assert_eq!(human, BadgeState::NotAnAgent);
        assert_eq!(
            broken,
            BadgeState::Unknown {
                freshness: Freshness::Unknown,
                as_of: None
            }
        );
        assert_ne!(human, broken);
    }

    #[test]
    fn loading_is_not_the_same_as_not_being_an_agent() {
        let loading = badge_state(&DisclosureStatus::Loading, None, NOW, TTL);
        assert_eq!(loading, BadgeState::Loading);
        assert_ne!(loading, BadgeState::NotAnAgent);
    }

    #[test]
    fn a_stale_snapshot_stops_asserting_that_an_author_is_human() {
        let state = badge_state(&loaded(TTL + 1.0), None, NOW, TTL);
        assert_eq!(
            state,
            BadgeState::Unknown {
                freshness: Freshness::Stale,
                as_of: Some(NOW - TTL - 1.0)
            }
        );
    }

    #[test]
    fn a_still_fresh_snapshot_survives_a_failed_refresh() {
        // The refresh failed but the last good answer is inside its window, so
        // it remains authoritative until the window closes.
        assert_eq!(
            badge_state(&failed(Some(5.0)), None, NOW, TTL),
            BadgeState::NotAnAgent
        );
        // …and once it ages out, the answer becomes unknown rather than
        // silently continuing to read as "human".
        assert!(matches!(
            badge_state(&failed(Some(TTL + 1.0)), None, NOW, TTL),
            BadgeState::Unknown { .. }
        ));
    }

    // -- Agent states ---------------------------------------------------------

    #[test]
    fn a_registered_agent_carries_its_principal_and_freshness() {
        let entry = agent("agentpk", "adminpk");
        assert_eq!(
            badge_state(&loaded(10.0), Some(&entry), NOW, TTL),
            BadgeState::Agent {
                registered_by: "adminpk".to_string(),
                freshness: Freshness::Fresh,
                as_of: Some(NOW - 10.0),
            }
        );
    }

    #[test]
    fn a_registered_agent_from_a_stale_snapshot_is_marked_stale_not_hidden() {
        let entry = agent("agentpk", "adminpk");
        let state = badge_state(&loaded(TTL + 60.0), Some(&entry), NOW, TTL);
        match state {
            BadgeState::Agent { freshness, .. } => assert_eq!(freshness, Freshness::Stale),
            other => panic!("stale agent was not still an agent: {other:?}"),
        }
    }

    #[test]
    fn an_agent_known_only_from_a_snapshot_survives_a_failed_refresh() {
        let entry = agent("agentpk", "adminpk");
        assert!(matches!(
            badge_state(&failed(Some(30.0)), Some(&entry), NOW, TTL),
            BadgeState::Agent { .. }
        ));
    }

    // -- As-of presentation ---------------------------------------------------

    #[test]
    fn as_of_is_surfaced_for_every_state_that_has_one() {
        assert_eq!(as_of_of(&loaded(10.0)), Some(NOW - 10.0));
        assert_eq!(as_of_of(&failed(Some(10.0))), Some(NOW - 10.0));
        assert_eq!(as_of_of(&failed(None)), None);
        assert_eq!(as_of_of(&DisclosureStatus::Loading), None);
    }

    #[test]
    fn as_of_formats_in_plain_words() {
        assert_eq!(format_as_of(None, NOW), "never checked");
        assert_eq!(format_as_of(Some(NOW), NOW), "just now");
        assert_eq!(format_as_of(Some(NOW - 44.0), NOW), "just now");
        assert_eq!(format_as_of(Some(NOW - 60.0), NOW), "1 minute ago");
        assert_eq!(format_as_of(Some(NOW - 600.0), NOW), "10 minutes ago");
        assert_eq!(format_as_of(Some(NOW - 3600.0), NOW), "1 hour ago");
        assert_eq!(format_as_of(Some(NOW - 7200.0), NOW), "2 hours ago");
        assert_eq!(format_as_of(Some(NOW - 86_400.0), NOW), "1 day ago");
        assert_eq!(format_as_of(Some(NOW - 259_200.0), NOW), "3 days ago");
    }

    #[test]
    fn a_clock_skewed_future_timestamp_does_not_produce_negative_ages() {
        assert_eq!(format_as_of(Some(NOW + 500.0), NOW), "just now");
    }

    #[test]
    fn titles_state_the_freshness_and_never_claim_more_than_we_know() {
        let fresh = badge_state(&loaded(5.0), Some(&agent("a", "admin")), NOW, TTL);
        let fresh_title = badge_title(&fresh, "Alice", NOW);
        assert!(fresh_title.contains("Alice"));
        assert!(fresh_title.contains("just now"));

        let stale = badge_state(&loaded(TTL + 5.0), Some(&agent("a", "admin")), NOW, TTL);
        let stale_title = badge_title(&stale, "Alice", NOW);
        assert!(stale_title.contains("may be out of date"));

        let unknown = badge_state(&failed(None), None, NOW, TTL);
        let unknown_title = badge_title(&unknown, "", NOW);
        assert!(unknown_title.contains("unavailable"));
        assert!(unknown_title.contains("never checked"));

        assert_eq!(badge_title(&BadgeState::NotAnAgent, "", NOW), "");
        assert!(badge_title(&BadgeState::Loading, "", NOW).contains("Checking"));
    }

    #[test]
    fn every_state_is_distinguishable_from_every_other() {
        let states = [
            badge_state(&DisclosureStatus::Loading, None, NOW, TTL),
            badge_state(&loaded(1.0), None, NOW, TTL),
            badge_state(&loaded(1.0), Some(&agent("a", "admin")), NOW, TTL),
            badge_state(&loaded(TTL + 1.0), None, NOW, TTL),
            badge_state(&failed(None), None, NOW, TTL),
        ];
        for (i, a) in states.iter().enumerate() {
            for (j, b) in states.iter().enumerate() {
                if i != j && !(i == 3 && j == 4) && !(i == 4 && j == 3) {
                    assert_ne!(a, b, "states {i} and {j} are indistinguishable");
                }
            }
        }
        // Stale-loaded and hard-failed are both "unknown", but carry different
        // freshness so the tooltip can still tell them apart.
        assert_ne!(
            badge_title(&states[3], "", NOW),
            badge_title(&states[4], "", NOW)
        );
    }

    #[test]
    fn a_malformed_or_partial_response_never_downgrades_an_author_to_human() {
        // The fetch filters unparseable records out; whatever survives is a
        // partial snapshot. An author missing from a partial snapshot that is
        // itself past its window must read as unknown, not human.
        let state = badge_state(&loaded(TTL + 1.0), None, NOW, TTL);
        assert!(matches!(state, BadgeState::Unknown { .. }));
    }
}
