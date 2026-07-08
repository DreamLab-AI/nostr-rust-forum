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
//! once for the whole page rather than per badge. It fails open: a fetch error
//! leaves the map empty, so a missing disclosure renders no badge rather than a
//! wrong one.

use std::collections::HashMap;

use leptos::prelude::*;
use serde::Deserialize;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use crate::components::badge::{Badge, BadgeSize, BadgeVariant};

/// One active-agent disclosure record, as served by the relay.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct AgentDisclosure {
    pub pubkey: String,
    pub name: String,
    /// The authorising principal — the pubkey that provisioned this agent.
    pub registered_by: String,
}

/// Reactive cache of the active agent set, keyed by agent pubkey.
///
/// Empty until the disclosure fetch resolves; components read it through
/// [`AgentDisclosureCache::lookup`] inside a reactive scope so the badge
/// appears when the fetch completes.
#[derive(Clone, Copy)]
pub struct AgentDisclosureCache {
    entries: RwSignal<HashMap<String, AgentDisclosure>>,
    /// Set once the disclosure fetch has resolved (success or error).
    loaded: RwSignal<bool>,
}

impl AgentDisclosureCache {
    /// Reactive lookup: `Some(disclosure)` when `pubkey` is an active agent,
    /// `None` for a human (or before the fetch resolves). Subscribes to the
    /// entries signal, so an enclosing closure re-runs when the set fills.
    pub fn lookup(&self, pubkey: &str) -> Option<AgentDisclosure> {
        self.entries.with(|m| m.get(pubkey).cloned())
    }

    /// Whether the disclosure fetch has resolved.
    #[allow(dead_code)]
    pub fn is_loaded(&self) -> bool {
        self.loaded.get()
    }
}

/// Provide the disclosure cache and kick off the one-shot fetch. Call once at
/// the app root, after the relay-URL config is available.
pub fn provide_agent_disclosure() {
    let cache = AgentDisclosureCache {
        entries: RwSignal::new(HashMap::new()),
        loaded: RwSignal::new(false),
    };
    provide_context(cache);

    leptos::task::spawn_local(async move {
        match fetch_disclosures().await {
            Ok(list) => {
                let map: HashMap<String, AgentDisclosure> =
                    list.into_iter().map(|d| (d.pubkey.clone(), d)).collect();
                cache.entries.set(map);
            }
            Err(e) => {
                web_sys::console::warn_1(
                    &format!("[agent_badge] disclosure fetch failed: {e}").into(),
                );
            }
        }
        cache.loaded.set(true);
    });
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
/// Renders nothing for a human (pubkey absent from the active registry) and a
/// distinct AGENT pill naming the authorising principal for an active agent.
/// The principal is resolved to a human label where kind-0 metadata exists
/// (`display_name` > `name` > NIP-05 > shortened pubkey).
#[component]
pub fn AgentBadge(
    /// The author pubkey being rendered.
    pubkey: String,
    /// Compact size for dense author lines.
    #[prop(optional)]
    compact: bool,
) -> impl IntoView {
    let pubkey_for_lookup = pubkey;

    // Reactive disclosure lookup — re-evaluates when the fetch resolves.
    let disclosure = Memo::new(move |_| {
        try_use_agent_disclosure().and_then(|c| c.lookup(&pubkey_for_lookup))
    });

    // Human label for the authorising principal, resolved through the shared
    // profile cache. Falls back to the shortened principal pubkey while (or if)
    // its kind-0 metadata is unavailable.
    let principal_label = Memo::new(move |_| {
        disclosure.get().map(|d| {
            crate::components::user_display::use_display_name_tracked(&d.registered_by)
        })
    });

    let size = if compact { BadgeSize::Sm } else { BadgeSize::Md };

    view! {
        {move || {
            principal_label.get().map(|principal| {
                let text = format!("AGENT · {principal}");
                let title = format!("Agent — authorised by {principal}");
                view! {
                    <span title=title>
                        <Badge text=text variant=BadgeVariant::Info size=size />
                    </span>
                }
            })
        }}
    }
}
