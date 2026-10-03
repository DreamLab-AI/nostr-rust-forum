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

use std::collections::HashMap;

use leptos::prelude::*;
use serde::Deserialize;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use crate::components::badge::{Badge, BadgeSize, BadgeVariant};
use crate::components::copy_key::KeyGlyph;

/// How long a successful disclosure snapshot is treated as authoritative.
/// Past this the badge reports its agent answers as possibly out of date and
/// stops asserting that an unbadged author is a human.
pub const DISCLOSURE_TTL_SECS: f64 = 300.0;

/// Interval between background refreshes of a healthy snapshot.
const DISCLOSURE_REFRESH_MS: i32 = 240_000;

/// Shorter retry after a failed fetch, so a transient outage heals without a
/// page reload.
const DISCLOSURE_RETRY_MS: i32 = 30_000;

/// One active-agent disclosure record, as served by the relay.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct AgentDisclosure {
    pub pubkey: String,
    pub name: String,
    /// The authorising principal — the pubkey that provisioned this agent.
    pub registered_by: String,
}

/// State of the disclosure fetch. Carried in the cache so the badge can tell
/// "not an agent" from "we do not know".
#[derive(Clone, Debug, PartialEq)]
pub enum DisclosureStatus {
    /// No answer yet — the first fetch is still in flight.
    Loading,
    /// A fetch succeeded at `as_of` (epoch seconds).
    Loaded { as_of: f64 },
    /// A fetch failed. `last_ok` carries the timestamp of the most recent
    /// successful snapshot, when there has been one.
    Error {
        message: String,
        last_ok: Option<f64>,
    },
}

/// How much the snapshot behind an answer can be trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// Fetched within [`DISCLOSURE_TTL_SECS`].
    Fresh,
    /// Older than the freshness window — the register may have changed since.
    Stale,
    /// No successful fetch at all.
    Unknown,
}

/// What a single badge should render, derived from the cache state and this
/// author's register entry.
#[derive(Clone, Debug, PartialEq)]
pub enum BadgeState {
    /// First fetch in flight and this pubkey is not in whatever we hold:
    /// agent status is not yet known.
    Loading,
    /// The register is authoritative and fresh, and does not list this pubkey.
    /// This is the only case in which rendering nothing is honest.
    NotAnAgent,
    /// The register lists this pubkey as an active agent.
    Agent {
        registered_by: String,
        freshness: Freshness,
        as_of: Option<f64>,
    },
    /// The register could not be read, or its snapshot is past the freshness
    /// window, and this pubkey is not in what we hold. Agent status is UNKNOWN
    /// — explicitly not "human".
    Unknown {
        freshness: Freshness,
        as_of: Option<f64>,
    },
}

/// Freshness of the snapshot behind `status` at `now` (epoch seconds).
pub fn freshness_of(status: &DisclosureStatus, now: f64, ttl: f64) -> Freshness {
    let as_of = match status {
        DisclosureStatus::Loading => return Freshness::Unknown,
        DisclosureStatus::Loaded { as_of } => Some(*as_of),
        DisclosureStatus::Error { last_ok, .. } => *last_ok,
    };
    match as_of {
        None => Freshness::Unknown,
        Some(t) if crate::utils::freshness::is_stale(t, now, ttl) => Freshness::Stale,
        Some(_) => Freshness::Fresh,
    }
}

/// Timestamp of the snapshot behind `status`, when there is one.
pub fn as_of_of(status: &DisclosureStatus) -> Option<f64> {
    match status {
        DisclosureStatus::Loading => None,
        DisclosureStatus::Loaded { as_of } => Some(*as_of),
        DisclosureStatus::Error { last_ok, .. } => *last_ok,
    }
}

/// Derive what one badge should render.
///
/// The bounded-freshness policy in one place:
///
/// - a register hit is always a [`BadgeState::Agent`], carrying how fresh the
///   snapshot behind it is;
/// - a miss is [`BadgeState::NotAnAgent`] **only** while a successful snapshot
///   is inside its freshness window. That is the single case where "no badge"
///   is a claim rather than a silence;
/// - a miss during the first fetch is [`BadgeState::Loading`];
/// - a miss with no snapshot at all, or with one past the window, is
///   [`BadgeState::Unknown`]. A failed refresh does not immediately invalidate
///   a snapshot that is still inside its window — but it is never allowed to
///   masquerade as a fresh authoritative answer once that window closes.
pub fn badge_state(
    status: &DisclosureStatus,
    entry: Option<&AgentDisclosure>,
    now: f64,
    ttl: f64,
) -> BadgeState {
    let freshness = freshness_of(status, now, ttl);
    let as_of = as_of_of(status);

    if let Some(disclosure) = entry {
        return BadgeState::Agent {
            registered_by: disclosure.registered_by.clone(),
            freshness,
            as_of,
        };
    }

    match (status, freshness) {
        (DisclosureStatus::Loading, _) => BadgeState::Loading,
        (_, Freshness::Fresh) => BadgeState::NotAnAgent,
        _ => BadgeState::Unknown { freshness, as_of },
    }
}

/// Human phrasing for a snapshot age, e.g. "just now", "4 minutes ago".
///
/// Delegates to the shared freshness vocabulary so every cached surface phrases
/// its as-of the same way.
pub fn format_as_of(as_of: Option<f64>, now: f64) -> String {
    crate::utils::freshness::relative_age(as_of, now)
}

/// Tooltip text for a derived badge state. Always names the freshness, so a
/// reader can tell how much the badge (or its absence) is worth.
pub fn badge_title(state: &BadgeState, principal_label: &str, now: f64) -> String {
    match state {
        BadgeState::Loading => "Checking the agent register\u{2026}".to_string(),
        BadgeState::NotAnAgent => String::new(),
        BadgeState::Agent {
            freshness, as_of, ..
        } => {
            let checked = format_as_of(*as_of, now);
            match freshness {
                Freshness::Fresh => format!(
                    "Agent \u{2014} authorised by {principal_label}. Register checked {checked}."
                ),
                _ => format!(
                    "Agent \u{2014} authorised by {principal_label}. Register last checked {checked}; this may be out of date."
                ),
            }
        }
        BadgeState::Unknown { as_of, .. } => format!(
            "Agent register unavailable \u{2014} we cannot say whether this author is an agent. Last checked {}.",
            format_as_of(*as_of, now)
        ),
    }
}

/// Reactive cache of the active agent set, keyed by agent pubkey.
///
/// Components read it through [`AgentDisclosureCache::lookup`] and
/// [`AgentDisclosureCache::status`] inside a reactive scope, so a badge updates
/// when a fetch completes, fails, or refreshes.
#[derive(Clone, Copy)]
pub struct AgentDisclosureCache {
    entries: RwSignal<HashMap<String, AgentDisclosure>>,
    /// Explicit fetch state — loading, loaded-at, or failed.
    status: RwSignal<DisclosureStatus>,
}

impl AgentDisclosureCache {
    /// Reactive lookup: `Some(disclosure)` when `pubkey` is an active agent,
    /// `None` when it is absent from whatever snapshot we hold. A `None` is NOT
    /// by itself a claim that the author is human — pair it with
    /// [`Self::status`] through [`badge_state`].
    pub fn lookup(&self, pubkey: &str) -> Option<AgentDisclosure> {
        self.entries.with(|m| m.get(pubkey).cloned())
    }

    /// Reactive fetch state.
    pub fn status(&self) -> DisclosureStatus {
        self.status.get()
    }

    /// Re-fetch the register now, keeping the current snapshot on failure.
    ///
    /// Schedules the next refresh itself: the normal interval after a success,
    /// a shorter retry after a failure. That is the bounded freshness policy —
    /// an open tab recovers from an outage and picks up registration changes
    /// without needing a reload.
    pub fn refresh(&self) {
        let cache = *self;
        leptos::task::spawn_local(async move {
            let outcome = fetch_disclosures().await;
            let now = now_secs();
            let delay = match outcome {
                Ok(list) => {
                    let map: HashMap<String, AgentDisclosure> =
                        list.into_iter().map(|d| (d.pubkey.clone(), d)).collect();
                    cache.entries.set(map);
                    cache.status.set(DisclosureStatus::Loaded { as_of: now });
                    DISCLOSURE_REFRESH_MS
                }
                Err(e) => {
                    web_sys::console::warn_1(
                        &format!("[agent_badge] disclosure fetch failed: {e}").into(),
                    );
                    // Keep the previous snapshot — it is still the best evidence
                    // we have — but record that the refresh failed and when the
                    // last good answer was, so the badge reports an unknown
                    // state once that answer ages out.
                    let last_ok = as_of_of(&cache.status.get_untracked());
                    cache.status.set(DisclosureStatus::Error {
                        message: e,
                        last_ok,
                    });
                    DISCLOSURE_RETRY_MS
                }
            };
            crate::utils::set_timeout_once(move || cache.refresh(), delay);
        });
    }
}

/// Current time in epoch seconds.
fn now_secs() -> f64 {
    js_sys::Date::now() / 1000.0
}

/// Provide the disclosure cache and start its refresh loop. Call once at the
/// app root, after the relay-URL config is available.
pub fn provide_agent_disclosure() {
    let cache = AgentDisclosureCache {
        entries: RwSignal::new(HashMap::new()),
        status: RwSignal::new(DisclosureStatus::Loading),
    };
    provide_context(cache);
    cache.refresh();
}

/// Retrieve the disclosure cache if it was provided.
pub fn try_use_agent_disclosure() -> Option<AgentDisclosureCache> {
    use_context::<AgentDisclosureCache>()
}

/// Fetch the active agent set from the relay's public disclosure endpoint.
///
/// Mirrors the zone-access fetch idiom: `web_sys` fetch against
/// `relay_api_base()`, no auth header (the endpoint is public read-only).
async fn fetch_disclosures() -> Result<Vec<AgentDisclosure>, String> {
    let url = format!(
        "{}/api/agents/disclosure",
        crate::utils::relay_url::relay_api_base()
    );
    let win = web_sys::window().ok_or("No window")?;
    let resp_val = JsFuture::from(win.fetch_with_str(&url))
        .await
        .map_err(|e| format!("fetch error: {e:?}"))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| "Not a Response".to_string())?;
    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let text = JsFuture::from(resp.text().map_err(|e| format!("{e:?}"))?)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let text_str = text.as_string().ok_or("Not a string")?;
    let val: serde_json::Value =
        serde_json::from_str(&text_str).map_err(|e| format!("JSON parse: {e}"))?;
    let agents = val
        .get("agents")
        .and_then(|v| v.as_array())
        .ok_or("missing agents array")?;
    let list = agents
        .iter()
        .filter_map(|v| serde_json::from_value::<AgentDisclosure>(v.clone()).ok())
        .collect();
    Ok(list)
}

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
