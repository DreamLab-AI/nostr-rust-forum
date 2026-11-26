//! Agent disclosure cache & freshness model (COM-13/F2, ADR-106 Decision 3).
//!
//! Fetches the active agent set from the relay's public
//! `GET /api/agents/disclosure` endpoint and caches it in Leptos context.
//! Consumed by both `forum-client` (`AgentBadge`, `KnowledgePage`) and
//! `bbs-client` (agent pills, governance, Colloquy knowledge board).

use std::collections::HashMap;

use leptos::prelude::*;
use serde::Deserialize;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

/// How long a successful disclosure snapshot is treated as authoritative.
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

/// State of the disclosure fetch.
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
    Loading,
    NotAnAgent,
    Agent {
        registered_by: String,
        freshness: Freshness,
        as_of: Option<f64>,
    },
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
pub fn format_as_of(as_of: Option<f64>, now: f64) -> String {
    crate::utils::freshness::relative_age(as_of, now)
}

/// Tooltip text for a derived badge state.
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
#[derive(Clone, Copy)]
pub struct AgentDisclosureCache {
    entries: RwSignal<HashMap<String, AgentDisclosure>>,
    status: RwSignal<DisclosureStatus>,
}

impl AgentDisclosureCache {
    /// Reactive lookup: `Some(disclosure)` when `pubkey` is an active agent.
    pub fn lookup(&self, pubkey: &str) -> Option<AgentDisclosure> {
        self.entries.with(|m| m.get(pubkey).cloned())
    }

    /// Reactive fetch state.
    pub fn status(&self) -> DisclosureStatus {
        self.status.get()
    }

    /// Re-fetch the register now, keeping the current snapshot on failure.
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
pub fn now_secs() -> f64 {
    js_sys::Date::now() / 1000.0
}

/// Provide the disclosure cache and start its refresh loop.
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
