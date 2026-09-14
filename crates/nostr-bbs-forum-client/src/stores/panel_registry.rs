//! Panel registry store for the Agent Control Surface Protocol.
//!
//! Maintains a reactive collection of agent-published PanelDefinitions
//! (kind 31400) and ActionRequests (kind 31402) received from the relay.
//! The governance page subscribes to this store to render panels dynamically.

use std::collections::HashMap;

use leptos::prelude::*;

use nostr_bbs_core::governance::{self, PanelDefinition};

use crate::utils::governance_view::{
    self, CaseBoundary, ChainStep, PanelContext, PanelRef,
};

/// The NIP-33 address of a replaceable governance event: the author plus its
/// `d` tag.
///
/// Panels are keyed by this, never by the `d` tag alone. A `d` tag is chosen by
/// whoever publishes the event, and the relay admits governance events from any
/// *registered* agent — so keying on it alone lets one registered agent publish
/// a 31400 with another operator's `d` tag and replace their panel wholesale.
/// Since ADR-2011 that panel carries the operator's task-property declaration,
/// so a `d`-tag collision would be a way to **lower another operator's
/// escalation boundary** — precisely the boundary this client is supposed to
/// read. Composite keying closes it, and makes 31405 retirement ownership-safe
/// for free: an agent can only address, and so only retire, its own panel.
pub fn panel_address(agent_pubkey: &str, d_tag: &str) -> String {
    format!("{}:{}", agent_pubkey.to_ascii_lowercase(), d_tag)
}

#[derive(Debug, Clone, PartialEq)]
pub struct PanelEntry {
    pub d_tag: String,
    pub agent_pubkey: String,
    pub definition: PanelDefinition,
    pub last_updated: u64,
    pub event_id: String,
    /// The 31400's raw tags. Kept because the operator's task-property triple
    /// and panel policy (ADR-2011, FR6.3/FR6.4) may ride the tags rather than
    /// the definition body — agentbox stamps tags, this client's own types
    /// carry them in content, and [`PanelContext::from_panel`] reads both.
    pub tags: Vec<Vec<String>>,
}

impl PanelEntry {
    /// The operator declaration this panel contributes to a request's boundary.
    pub fn context(&self) -> PanelContext {
        PanelContext::from_panel(&self.tags, Some(&self.definition))
    }

    /// This panel's NIP-33 address, which is its key in the registry.
    pub fn address(&self) -> String {
        panel_address(&self.agent_pubkey, &self.d_tag)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActionEntry {
    pub d_tag: String,
    pub agent_pubkey: String,
    pub fields: serde_json::Value,
    pub reasoning: Option<String>,
    pub priority: String,
    pub created_at: u64,
    pub event_id: String,
    /// Agent-declared confidence in the requested action (F5), displayed at
    /// decision time. Sourced from the 31402 ActionRequest, never inferred.
    pub confidence: Option<f32>,
    /// Agent-declared risk tier (F7), sourced from the 31402 ActionRequest.
    ///
    /// **Telemetry only.** Since ADR-2011 no surface routes, gates or
    /// suppresses on this field (DDD §6 invariant 3): that is the effective
    /// tier's job, and the effective tier is what
    /// [`ActionEntry::boundary`] computes. It is still carried and still
    /// rendered, because declared-versus-effective divergence is how a
    /// habitually under-tiering agent becomes visible.
    pub risk_tier: Option<String>,
    /// Where the reviewer can go to see the change in its own context (FR2.1).
    /// Scheme-validated on ingest ([`governance_view::safe_context_url`]): the
    /// governance subscription carries no `authors` filter, so this value is
    /// attacker-controlled and ends up in an `href`.
    pub context_url: Option<String>,
    /// The 31402's raw tags, needed to resolve the panel, read a tag-declared
    /// task-property triple, and recognise a seeded probe.
    pub tags: Vec<Vec<String>>,
}

impl ActionEntry {
    /// The request as the agent published it, re-parsed for the boundary
    /// computation. Cheap and total: a malformed body yields an empty request
    /// rather than a panic, and an empty request simply declares nothing.
    fn request(&self) -> governance::ActionRequest {
        governance::ActionRequest {
            fields: self.fields.clone(),
            reasoning: self.reasoning.clone(),
            context_url: self.context_url.clone(),
            risk_tier: self.risk_tier.as_deref().map(governance::RiskTier::parse),
            confidence: self.confidence,
            task_properties: governance::TaskProperties::from_tags(&self.tags),
            probe: governance::extract_tag(&self.tags, governance::TAG_PROBE)
                .map(str::to_string),
        }
    }

    /// The tier and policy that actually govern this case (ADR-2011).
    ///
    /// `panel` is the 31400 this request belongs to, where the registry could
    /// resolve one. Computed rather than read back from the relay because the
    /// member surface has no authenticated read; the computation is the *same*
    /// pure `nostr-bbs-core` code the relay runs over the same inputs, so both
    /// sides necessarily agree.
    ///
    /// `calibration_sample` is the exception and is **not** computed: selection
    /// is HMAC'd under a relay-held secret so the requesting agent cannot grind
    /// its freely-chosen `d` tag out of being sampled, which means the client
    /// has no key with which to recompute it and must not be given one. It
    /// comes from [`crate::stores::case_projection`], and `false` where the
    /// relay has said nothing.
    pub fn boundary(
        &self,
        panel: Option<&PanelContext>,
        calibration_sample: bool,
    ) -> CaseBoundary {
        governance_view::compute_boundary(
            &self.agent_pubkey,
            &self.tags,
            &self.request(),
            panel,
            governance_view::advertised_default_tier(),
            calibration_sample,
        )
    }

}

/// A single human decision (kind-31403 `ActionResponse`) on a case, tracked so
/// the surfaces can render the supersession history for a panel/action (F6,
/// `DDD-judgment-broker-context.md` §7a). Keyed under the case `d`-tag.
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionEntry {
    pub d_tag: String,
    pub event_id: String,
    pub signer_pubkey: String,
    /// The decision action string (`approve`/`reject`/…).
    pub outcome: String,
    pub reason: String,
    pub created_at: u64,
    /// When this is a *superseding* decision (§7a.2), the prior decision EVENT id
    /// it supersedes (from the `e`-tag `supersedes` marker); `None` otherwise.
    pub supersedes: Option<String>,
    /// The request EVENT id this decision binds to, from its plain `e` tag.
    ///
    /// A `d` tag alone does not identify a case — it is chosen by the
    /// publisher — so the chain rendered on a card is filtered to decisions
    /// bound to **that request's** event id. Without it a 31403 carrying a
    /// colliding `d` tag would land on a victim case's chain, where a forged
    /// `approve` would read as decided (revealing a probe, DDD §6 invariant 7)
    /// and a forged `delegate` would offer a stranger the controls.
    pub request_event_id: Option<String>,
    /// For a `Delegate` outcome, the pubkey the admin delegated the case to
    /// (FR6.2). Carried so the surfaces can tell a delegated reviewer that this
    /// one case is theirs to decide (DDD §6 invariant 6).
    pub delegate_to: Option<String>,
}

/// A decision as rendered in the supersession history: the entry plus whether a
/// later authorised decision has superseded it, and whether it is the current
/// effective decision for the case (§7a.3 — "the most recent authorised
/// kind-31403 in the reference chain").
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionView {
    pub entry: DecisionEntry,
    pub superseded: bool,
    pub effective: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PanelRegistryState {
    /// Keyed by [`panel_address`] — author plus `d` tag — never by `d` alone.
    pub panels: HashMap<String, PanelEntry>,
    pub actions: Vec<ActionEntry>,
    /// Keyed by [`panel_address`], for the same reason as `panels`.
    pub panel_states: HashMap<String, serde_json::Value>,
    /// The `(created_at, event_id)` of the newest 31401/31404 applied to each
    /// panel address, so a replayed older state snapshot or diff cannot undo a
    /// newer one.
    pub panel_state_seen: HashMap<String, (u64, String)>,
    /// Decision history per case `d`-tag, oldest-first. Feeds the supersession
    /// history surfaces (F6).
    pub decisions: HashMap<String, Vec<DecisionEntry>>,
}

impl PanelRegistryState {
    /// Whether a 31401/31404 for `address` is newer than the last one applied,
    /// recording it when it is. NIP-33 replaceability for panel state.
    fn accept_panel_state(&mut self, address: &str, created_at: u64, event_id: &str) -> bool {
        if let Some((held_at, held_id)) = self.panel_state_seen.get(address) {
            if !supersedes_held(created_at, event_id, *held_at, held_id) {
                return false;
            }
        }
        self.panel_state_seen
            .insert(address.to_string(), (created_at, event_id.to_string()));
        true
    }
}

#[derive(Clone, Copy)]
pub struct PanelRegistry {
    pub state: RwSignal<PanelRegistryState>,
}

pub fn provide_panel_registry() {
    let registry = PanelRegistry {
        state: RwSignal::new(PanelRegistryState::default()),
    };
    provide_context(registry);
}

pub fn use_panel_registry() -> PanelRegistry {
    expect_context::<PanelRegistry>()
}

impl PanelRegistry {
    pub fn ingest_event(&self, event: &nostr_bbs_core::NostrEvent) {
        if !governance::is_governance_kind(event.kind) {
            return;
        }

        let d_tag = governance::extract_d_tag(&event.tags)
            .unwrap_or("")
            .to_string();

        match event.kind {
            governance::KIND_PANEL_DEFINITION => {
                if let Ok(def) = serde_json::from_str::<PanelDefinition>(&event.content) {
                    let address = panel_address(&event.pubkey, &d_tag);
                    self.state.update(|s| {
                        // NIP-33 replaceability: a replayed older 31400 must not
                        // roll back the operator's declaration.
                        if let Some(held) = s.panels.get(&address) {
                            if !supersedes_held(
                                event.created_at,
                                &event.id,
                                held.last_updated,
                                &held.event_id,
                            ) {
                                return;
                            }
                        }
                        s.panels.insert(
                            address,
                            PanelEntry {
                                d_tag,
                                agent_pubkey: event.pubkey.clone(),
                                definition: def,
                                last_updated: event.created_at,
                                event_id: event.id.clone(),
                                tags: event.tags.clone(),
                            },
                        );
                    });
                }
            }
            governance::KIND_ACTION_REQUEST => {
                let priority = governance::extract_tag(&event.tags, "priority")
                    .unwrap_or("medium")
                    .to_string();

                if let Ok(req) = serde_json::from_str::<governance::ActionRequest>(&event.content) {
                    self.state.update(|s| {
                        // NIP-33 replaceability, per (pubkey, d): a republished
                        // request REPLACES its earlier version rather than
                        // sitting beside it, and a replayed older one is
                        // ignored. Two agents sharing a `d` tag keep separate
                        // cases, because the address includes the author.
                        let held = s.actions.iter().position(|a| {
                            a.d_tag == d_tag && a.agent_pubkey.eq_ignore_ascii_case(&event.pubkey)
                        });
                        if let Some(i) = held {
                            if !supersedes_held(
                                event.created_at,
                                &event.id,
                                s.actions[i].created_at,
                                &s.actions[i].event_id,
                            ) {
                                return;
                            }
                            s.actions.remove(i);
                        }
                        s.actions.push(ActionEntry {
                            d_tag,
                            agent_pubkey: event.pubkey.clone(),
                            fields: req.fields,
                            reasoning: req.reasoning,
                            priority,
                            created_at: event.created_at,
                            event_id: event.id.clone(),
                            confidence: req.confidence,
                            risk_tier: req
                                .risk_tier
                                .map(|t| t.as_str().to_string())
                                .or_else(|| {
                                    governance::extract_tag(&event.tags, "risk-tier")
                                        .map(|t| governance::RiskTier::parse(t).as_str().to_string())
                                }),
                            // Scheme-validated at INGEST so a `javascript:`
                            // URI never enters the reactive store. The view
                            // re-checks before binding an href; either alone
                            // would do, both means a future ingest path cannot
                            // reopen the sink.
                            context_url: req
                                .context_url
                                .as_deref()
                                .and_then(governance_view::safe_context_url),
                            tags: event.tags.clone(),
                        });
                    });
                }
            }
            governance::KIND_ACTION_RESPONSE => {
                // F6 (DDD §7a): track human decisions so the surfaces can render
                // the supersession history. A superseding decision carries an
                // `e`-tag with the `supersedes` marker referencing the prior
                // decision event.
                let parsed_outcome =
                    governance::broker::DecisionOutcome::from_response_content(&event.content);
                let outcome = parsed_outcome
                    .as_ref()
                    .map(|o| o.action_str().to_string())
                    .unwrap_or_else(|| "decision".to_string());
                // FR6.2: keep the delegation target so a delegated reviewer can
                // be offered the controls for exactly that case.
                let delegate_to = match &parsed_outcome {
                    Some(governance::broker::DecisionOutcome::Delegate { delegate_to }) => {
                        Some(delegate_to.clone())
                    }
                    _ => None,
                };
                let reason = serde_json::from_str::<serde_json::Value>(&event.content)
                    .ok()
                    .and_then(|v| {
                        v.get("reasoning")
                            .and_then(|r| r.as_str())
                            .map(str::to_string)
                    })
                    .unwrap_or_default();
                let supersedes =
                    governance::extract_supersedes_target(&event.tags).map(str::to_string);
                // The plain `e` tag (no marker) names the request being decided;
                // a marked one (`supersedes`, `appeal`) names something else.
                let request_event_id = event
                    .tags
                    .iter()
                    .find(|t| {
                        t.first().map(String::as_str) == Some("e")
                            && t.get(3).map(String::as_str).unwrap_or("").is_empty()
                    })
                    .and_then(|t| t.get(1))
                    .cloned();
                self.state.update(|s| {
                    let chain = s.decisions.entry(d_tag.clone()).or_default();
                    if chain.iter().any(|e| e.event_id == event.id) {
                        return;
                    }
                    chain.push(DecisionEntry {
                        d_tag,
                        event_id: event.id.clone(),
                        signer_pubkey: event.pubkey.clone(),
                        outcome,
                        reason,
                        created_at: event.created_at,
                        supersedes,
                        request_event_id,
                        delegate_to,
                    });
                    chain.sort_by_key(|e| e.created_at);
                });
            }
            governance::KIND_PANEL_STATE => {
                let address = panel_address(&event.pubkey, &d_tag);
                if let Ok(state_data) = serde_json::from_str::<serde_json::Value>(&event.content) {
                    self.state.update(|s| {
                        if !s.accept_panel_state(&address, event.created_at, &event.id) {
                            return;
                        }
                        s.panel_states.insert(address.clone(), state_data);
                        if let Some(panel) = s.panels.get_mut(&address) {
                            panel.last_updated = event.created_at;
                        }
                    });
                }
            }
            governance::KIND_PANEL_UPDATE => {
                let address = panel_address(&event.pubkey, &d_tag);
                if let Ok(diff) = serde_json::from_str::<serde_json::Value>(&event.content) {
                    self.state.update(|s| {
                        if !s.accept_panel_state(&address, event.created_at, &event.id) {
                            return;
                        }
                        let current = s
                            .panel_states
                            .entry(address.clone())
                            .or_insert_with(|| serde_json::Value::Object(Default::default()));
                        if let (Some(base), Some(patch)) =
                            (current.as_object_mut(), diff.as_object())
                        {
                            for (k, v) in patch {
                                base.insert(k.clone(), v.clone());
                            }
                        }
                        if let Some(panel) = s.panels.get_mut(&address) {
                            panel.last_updated = event.created_at;
                        }
                    });
                }
            }
            governance::KIND_PANEL_RETIRED => {
                // Addressed, so an agent can only ever retire its own panel:
                // a 31405 naming another operator's `d` tag addresses nothing.
                let address = panel_address(&event.pubkey, &d_tag);
                self.state.update(|s| {
                    // A retirement older than the panel it names is a replay,
                    // not a retirement.
                    if let Some(held) = s.panels.get(&address) {
                        if held.last_updated > event.created_at {
                            return;
                        }
                    }
                    s.panels.remove(&address);
                    s.panel_states.remove(&address);
                    s.panel_state_seen.remove(&address);
                });
            }
            _ => {}
        }
    }
}

/// Whether an incoming replaceable event supersedes the one already held.
///
/// NIP-33: kinds 31400-31405 are parameterized-replaceable, and the newest
/// `created_at` wins per `(kind, pubkey, d)` address, with the **lowest event
/// id** breaking a tie (NIP-01). Without this rule an agent can simply REPLAY
/// its own earlier 31400 to roll the operator's task-property declaration back
/// to a looser one — ADR-2011's boundary defeated by a replayed envelope rather
/// than a forged one — or republish a 31402 so that two versions of one case sit
/// side by side, one of them carrying whichever tier it prefers.
///
/// Pure over the two (timestamp, id) pairs so the rule is testable and stated
/// once rather than re-derived at each of the five ingest arms.
pub fn supersedes_held(
    incoming_at: u64,
    incoming_id: &str,
    held_at: u64,
    held_id: &str,
) -> bool {
    match incoming_at.cmp(&held_at) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        // Same second: NIP-01 breaks the tie on the lowest event id, which is
        // arbitrary but identical on every client, so two clients never render
        // different versions of the same case.
        std::cmp::Ordering::Equal => incoming_id < held_id,
    }
}

/// Resolve the rendered supersession chain for a case `d`-tag (F6, DDD §7a.3).
///
/// Pure over the decision list so it is unit-testable without a reactive store.
/// Marks each decision `superseded` when a later decision in the chain references
/// its event id (`supersedes`), and marks the single most-recent non-superseded
/// decision `effective` — "the current effective decision for a case is the most
/// recent authorised kind-31403 in the reference chain; superseded events remain
/// visible as history".
pub fn resolve_decision_chain(entries: &[DecisionEntry]) -> Vec<DecisionView> {
    use std::collections::HashSet;
    let superseded_ids: HashSet<&str> = entries
        .iter()
        .filter_map(|e| e.supersedes.as_deref())
        .collect();

    // Oldest-first for display; the effective one is the newest not superseded.
    let mut sorted: Vec<&DecisionEntry> = entries.iter().collect();
    sorted.sort_by_key(|e| e.created_at);

    let effective_event_id = sorted
        .iter()
        .rev()
        .find(|e| !superseded_ids.contains(e.event_id.as_str()))
        .map(|e| e.event_id.clone());

    sorted
        .into_iter()
        .map(|e| {
            let superseded = superseded_ids.contains(e.event_id.as_str());
            DecisionView {
                entry: e.clone(),
                superseded,
                effective: Some(&e.event_id) == effective_event_id.as_ref(),
            }
        })
        .collect()
}

/// Resolve the panel that governs a request, from the panels observed so far.
///
/// Pure over the panel collection so the resolution order is testable without a
/// reactive store. Mirrors the relay's `resolve_panel_tags` exactly: the NIP-33
/// `a` tag, then a plain `panel` tag naming the `d` on the requesting agent's
/// own panels, then the most recently updated panel that agent published. A
/// request whose panel cannot be resolved is not refused — it simply has no
/// operator declaration to be tightened by, and falls back to its own
/// declaration and the relay's advertised default.
pub fn resolve_panel_for<'a>(
    panels: &'a HashMap<String, PanelEntry>,
    request_tags: &[Vec<String>],
    request_pubkey: &str,
) -> Option<&'a PanelEntry> {
    match governance_view::resolve_panel_ref(request_tags, request_pubkey) {
        PanelRef::Addressed { pubkey, d_tag } | PanelRef::Named { pubkey, d_tag } => {
            panels.get(&panel_address(&pubkey, &d_tag))
        }
        PanelRef::LatestFromAgent { pubkey } => panels
            .values()
            .filter(|p| p.agent_pubkey.eq_ignore_ascii_case(&pubkey))
            .max_by_key(|p| p.last_updated),
    }
}

/// Reduce a rendered decision chain to the delegation/decided-ness view rules
/// in [`crate::utils::governance_view`].
pub fn chain_steps(chain: &[DecisionView]) -> Vec<ChainStep> {
    chain
        .iter()
        .map(|v| ChainStep {
            event_id: v.entry.event_id.clone(),
            signer_pubkey: v.entry.signer_pubkey.clone(),
            outcome: v.entry.outcome.clone(),
            delegate_to: v.entry.delegate_to.clone(),
            superseded: v.superseded,
            effective: v.effective,
        })
        .collect()
}

/// Keep only the decisions bound to `request_event_id` by their plain `e` tag.
///
/// A case is a request EVENT, not a `d` tag: the `d` tag is chosen by whoever
/// publishes, so two authors can collide on one. Filtering by the bound request
/// id is what stops a 31403 on some other case appearing on this card — where a
/// forged `approve` would make the case read as decided and reveal its probe
/// (DDD §6 invariant 7), and a forged `delegate` would offer a stranger the
/// controls (invariant 6).
///
/// A decision carrying no plain `e` tag binds to nothing and is dropped: every
/// 31403 this client has ever published carries one, and so does the relay's
/// own correlation path, so strictness costs no legitimate history.
pub fn bind_to_request<'a>(
    entries: &'a [DecisionEntry],
    request_event_id: &str,
) -> Vec<&'a DecisionEntry> {
    entries
        .iter()
        .filter(|e| e.request_event_id.as_deref() == Some(request_event_id))
        .collect()
}

impl PanelRegistry {
    /// The rendered supersession chain for a `d`-tag (F6). Empty when no
    /// decisions have been observed for it.
    ///
    /// Unscoped: used by the PANEL card, where there is no request event to
    /// bind to. For a decision card use [`Self::case_chain`], which binds.
    pub fn decision_chain(&self, d_tag: &str) -> Vec<DecisionView> {
        let s = self.state.read();
        match s.decisions.get(d_tag) {
            Some(entries) => resolve_decision_chain(entries),
            None => Vec::new(),
        }
    }

    /// The supersession chain for one case, scoped to the decisions bound to
    /// that request's event id.
    pub fn case_chain(&self, d_tag: &str, request_event_id: &str) -> Vec<DecisionView> {
        let s = self.state.read();
        match s.decisions.get(d_tag) {
            Some(entries) => {
                let bound: Vec<DecisionEntry> = bind_to_request(entries, request_event_id)
                    .into_iter()
                    .cloned()
                    .collect();
                resolve_decision_chain(&bound)
            }
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_bbs_core::NostrEvent;

    fn dec(event_id: &str, at: u64, outcome: &str, supersedes: Option<&str>) -> DecisionEntry {
        DecisionEntry {
            d_tag: "case-1".into(),
            event_id: event_id.into(),
            signer_pubkey: "signer".into(),
            outcome: outcome.into(),
            reason: "r".into(),
            created_at: at,
            supersedes: supersedes.map(str::to_string),
            request_event_id: Some("req-1".into()),
            delegate_to: None,
        }
    }

    fn panel(d_tag: &str, agent: &str, updated: u64, tags: Vec<Vec<String>>) -> PanelEntry {
        PanelEntry {
            d_tag: d_tag.into(),
            agent_pubkey: agent.into(),
            definition: PanelDefinition {
                title: "t".into(),
                description: "d".into(),
                version: "1.0.0".into(),
                schema: governance::PanelSchema::ActionInbox,
                fields: vec![],
                actions: vec![],
                layout: governance::LayoutHint::InboxTable,
                capabilities: vec![],
                refresh_secs: 30,
                task_properties: None,
                calibration_sample_rate: None,
                max_pending_hours: None,
                probe_agent: None,
            },
            last_updated: updated,
            event_id: format!("ev-{d_tag}"),
            tags,
        }
    }

    fn panel_map(entries: Vec<PanelEntry>) -> HashMap<String, PanelEntry> {
        entries.into_iter().map(|p| (p.address(), p)).collect()
    }

    fn action(d_tag: &str, agent: &str, tags: Vec<Vec<String>>) -> ActionEntry {
        ActionEntry {
            d_tag: d_tag.into(),
            agent_pubkey: agent.into(),
            fields: serde_json::json!({"op": "delete"}),
            reasoning: None,
            priority: "medium".into(),
            created_at: 1_000,
            event_id: format!("req-{d_tag}"),
            confidence: None,
            risk_tier: Some("low".into()),
            context_url: None,
            tags,
        }
    }

    fn tag(k: &str, v: &str) -> Vec<String> {
        vec![k.to_string(), v.to_string()]
    }

    #[test]
    fn a_request_resolves_its_panel_by_address_then_name_then_latest() {
        let panels = panel_map(vec![
            panel("p-old", "agent", 100, vec![]),
            panel("p-new", "agent", 200, vec![]),
        ]);
        // Addressed.
        assert_eq!(
            resolve_panel_for(&panels, &[tag("a", "31400:agent:p-old")], "agent")
                .unwrap()
                .d_tag,
            "p-old"
        );
        // Named.
        assert_eq!(
            resolve_panel_for(&panels, &[tag("panel", "p-old")], "agent")
                .unwrap()
                .d_tag,
            "p-old"
        );
        // Neither: the agent's most recently updated panel.
        assert_eq!(
            resolve_panel_for(&panels, &[], "agent").unwrap().d_tag,
            "p-new"
        );
        // An address naming another agent's panel does not resolve — one agent
        // must not borrow another operator's declaration.
        assert!(resolve_panel_for(&panels, &[tag("a", "31400:other:p-old")], "agent").is_none());
        // An agent with no panels at all.
        assert!(resolve_panel_for(&panels, &[], "stranger").is_none());
    }

    #[test]
    fn suppression_reads_the_effective_tier_not_the_agents_declaration() {
        // DDD §6 invariant 3. The agent declares `low`; the operator's panel
        // declares the work irreversible. The member surface must show it.
        let panels = panel_map(vec![panel(
            "p-1",
            "agent",
            100,
            vec![tag("tp-reversibility", "irreversible")],
        )]);
        let item = action("case-1", "agent", vec![tag("panel", "p-1")]);
        let ctx = resolve_panel_for(&panels, &item.tags, &item.agent_pubkey).map(|p| p.context());
        assert_eq!(item.risk_tier.as_deref(), Some("low"));
        assert_eq!(item.boundary(ctx.as_ref(), false).effective, governance::RiskTier::High);
        assert!(item.boundary(ctx.as_ref(), false).is_member_visible());

        // Without that operator declaration the same `low` request is hidden.
        let bare = panel_map(vec![panel("p-1", "agent", 100, vec![tag("calibration-sample-rate", "0")])]);
        let ctx = resolve_panel_for(&bare, &item.tags, &item.agent_pubkey).map(|p| p.context());
        assert!(!item.boundary(ctx.as_ref(), false).is_member_visible());
    }

    fn panel_event(d_tag: &str, agent: &str, created_at: u64, stakes: &str) -> NostrEvent {
        NostrEvent {
            id: format!("ev-{d_tag}-{created_at}"),
            pubkey: agent.into(),
            created_at,
            kind: governance::KIND_PANEL_DEFINITION,
            tags: vec![tag("d", d_tag), tag("tp-stakes", stakes)],
            content: serde_json::json!({
                "title": "t", "description": "d", "version": "1.0.0",
                "schema": "action-inbox", "fields": [], "actions": [],
                "layout": "inbox-table"
            })
            .to_string(),
            sig: String::new(),
        }
    }

    fn request_event(d_tag: &str, agent: &str, created_at: u64, tier: &str) -> NostrEvent {
        NostrEvent {
            id: format!("req-{d_tag}-{created_at}"),
            pubkey: agent.into(),
            created_at,
            kind: governance::KIND_ACTION_REQUEST,
            tags: vec![tag("d", d_tag), tag("risk-tier", tier)],
            content: serde_json::json!({ "fields": { "n": created_at } }).to_string(),
            sig: String::new(),
        }
    }

    fn fresh_registry() -> PanelRegistry {
        PanelRegistry {
            state: RwSignal::new(PanelRegistryState::default()),
        }
    }

    #[test]
    fn an_older_panel_never_rolls_back_a_newer_operator_declaration() {
        // NIP-33: kinds 31400-31405 are parameterized-replaceable and
        // newest-`created_at` wins per (kind, pubkey, d). Without that rule an
        // agent could REPLAY its own earlier, looser 31400 and roll the
        // operator's escalation boundary back down — ADR-2011 defeated by a
        // replayed envelope rather than a forged one.
        let r = fresh_registry();
        r.ingest_event(&panel_event("p-1", "operator", 200, "critical"));
        let addr = panel_address("operator", "p-1");
        assert_eq!(
            r.state.read_untracked().panels[&addr].definition.task_properties, None,
            "the triple rides tags here, not content"
        );
        assert_eq!(r.state.read_untracked().panels[&addr].last_updated, 200);

        // Replay of the older, looser declaration.
        r.ingest_event(&panel_event("p-1", "operator", 100, "bounded"));
        let s = r.state.read_untracked();
        assert_eq!(s.panels[&addr].last_updated, 200, "older event replaced a newer one");
        assert_eq!(
            s.panels[&addr].context().task_properties.unwrap().stakes,
            governance::Stakes::Critical,
            "the operator's tighter declaration was rolled back"
        );
    }

    #[test]
    fn a_newer_panel_does_replace_an_older_one() {
        let r = fresh_registry();
        r.ingest_event(&panel_event("p-1", "operator", 100, "bounded"));
        r.ingest_event(&panel_event("p-1", "operator", 200, "critical"));
        let addr = panel_address("operator", "p-1");
        let s = r.state.read_untracked();
        assert_eq!(s.panels[&addr].last_updated, 200);
        assert_eq!(
            s.panels[&addr].context().task_properties.unwrap().stakes,
            governance::Stakes::Critical
        );
    }

    #[test]
    fn a_republished_request_replaces_rather_than_duplicating() {
        // 31402 is parameterized-replaceable too. Appending both versions
        // showed one case twice — and let an agent publish a second, lower
        // tier that sits alongside the first rather than superseding it.
        let r = fresh_registry();
        r.ingest_event(&request_event("case-1", "agent", 100, "critical"));
        r.ingest_event(&request_event("case-1", "agent", 200, "low"));
        let s = r.state.read_untracked();
        assert_eq!(s.actions.len(), 1, "one case, one card");
        assert_eq!(s.actions[0].created_at, 200);
        assert_eq!(s.actions[0].risk_tier.as_deref(), Some("low"));
    }

    #[test]
    fn an_older_republished_request_is_ignored() {
        let r = fresh_registry();
        r.ingest_event(&request_event("case-1", "agent", 200, "critical"));
        r.ingest_event(&request_event("case-1", "agent", 100, "low"));
        let s = r.state.read_untracked();
        assert_eq!(s.actions.len(), 1);
        assert_eq!(s.actions[0].created_at, 200);
        assert_eq!(
            s.actions[0].risk_tier.as_deref(),
            Some("critical"),
            "a replayed older request lowered the tier"
        );
    }

    #[test]
    fn two_agents_sharing_a_d_tag_keep_separate_cases() {
        // Replaceability is per (pubkey, d), so one agent's republish must not
        // displace another's case that happens to share a `d` tag.
        let r = fresh_registry();
        r.ingest_event(&request_event("case-1", "agent-a", 100, "critical"));
        r.ingest_event(&request_event("case-1", "agent-b", 200, "low"));
        assert_eq!(r.state.read_untracked().actions.len(), 2);
    }

    #[test]
    fn a_duplicate_of_the_same_event_is_ingested_once() {
        let r = fresh_registry();
        let ev = request_event("case-1", "agent", 100, "low");
        r.ingest_event(&ev);
        r.ingest_event(&ev);
        assert_eq!(r.state.read_untracked().actions.len(), 1);
    }

    #[test]
    fn panels_are_addressed_by_author_and_d_tag_so_one_agent_cannot_clobber_another() {
        // Since ADR-2011 a panel carries the operator's task-property
        // declaration, so a `d`-tag collision would be a way to lower another
        // operator's escalation boundary.
        let honest = panel("p-1", "operator", 100, vec![tag("tp-stakes", "critical")]);
        let hostile = panel("p-1", "attacker", 200, vec![tag("tp-stakes", "bounded")]);
        let mut panels = HashMap::new();
        panels.insert(honest.address(), honest);
        panels.insert(hostile.address(), hostile);
        assert_eq!(panels.len(), 2, "the hostile panel did not replace the honest one");

        // A request against the operator's panel still resolves the operator's
        // declaration, and so still floors at `high`.
        let item = action("case-1", "operator", vec![tag("a", "31400:operator:p-1")]);
        let ctx = resolve_panel_for(&panels, &item.tags, &item.agent_pubkey)
            .map(|p| p.context())
            .expect("the operator's panel resolves");
        assert_eq!(
            item.boundary(Some(&ctx), false).effective,
            governance::RiskTier::High
        );

        // And an unaddressed request from the attacker resolves the
        // attacker's own panel, never the operator's.
        let theirs = action("case-2", "attacker", vec![]);
        let resolved = resolve_panel_for(&panels, &theirs.tags, &theirs.agent_pubkey).unwrap();
        assert_eq!(resolved.agent_pubkey, "attacker");
    }

    #[test]
    fn a_decision_on_another_case_never_lands_on_this_cards_chain() {
        // A colliding `d` tag must not let a forged `approve` make this case
        // read as decided (which would reveal its probe) or a forged
        // `delegate` offer a stranger the controls.
        let mine = dec("dec-1", 1, "approve", None); // bound to req-1
        let mut theirs = dec("dec-2", 2, "approve", None);
        theirs.request_event_id = Some("req-999".into());
        let mut unbound = dec("dec-3", 3, "delegate", None);
        unbound.request_event_id = None;

        let all = vec![mine, theirs, unbound];
        let bound = bind_to_request(&all, "req-1");
        assert_eq!(bound.len(), 1);
        assert_eq!(bound[0].event_id, "dec-1");

        // Nothing at all is bound to a case with no decisions of its own.
        assert!(bind_to_request(&all, "req-42").is_empty());
    }

    #[test]
    fn a_delegation_outcome_carries_its_target_into_the_chain_steps() {
        let reviewer = "d".repeat(64);
        let mut d = dec("dec-1", 1, "delegate", None);
        d.delegate_to = Some(reviewer.clone());
        let steps = chain_steps(&resolve_decision_chain(&[d]));
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].delegate_to.as_deref(), Some(&*reviewer));
        assert!(crate::utils::governance_view::is_decidable_by(
            &steps,
            Some(&reviewer),
            false
        ));
    }

    #[test]
    fn single_decision_is_effective_and_not_superseded() {
        let chain = resolve_decision_chain(&[dec("A", 1, "approve", None)]);
        assert_eq!(chain.len(), 1);
        assert!(chain[0].effective);
        assert!(!chain[0].superseded);
    }

    #[test]
    fn supersession_chain_marks_superseded_and_effective() {
        // A (approve) superseded by B (reject) superseded by C (approve).
        let entries = vec![
            dec("A", 1, "approve", None),
            dec("B", 2, "reject", Some("A")),
            dec("C", 3, "approve", Some("B")),
        ];
        let chain = resolve_decision_chain(&entries);
        assert_eq!(chain.len(), 3);
        // Oldest-first ordering.
        assert_eq!(chain[0].entry.event_id, "A");
        assert_eq!(chain[2].entry.event_id, "C");
        // A and B are superseded; C is the current effective decision.
        assert!(chain[0].superseded && !chain[0].effective);
        assert!(chain[1].superseded && !chain[1].effective);
        assert!(!chain[2].superseded && chain[2].effective);
    }
}
