//! Panel registry store for the Agent Control Surface Protocol.
//!
//! Maintains a reactive collection of agent-published PanelDefinitions
//! (kind 31400) and ActionRequests (kind 31402) received from the relay.
//! The governance page subscribes to this store to render panels dynamically.

use std::collections::HashMap;

use leptos::prelude::*;

use nostr_bbs_core::governance::{self, PanelDefinition};

#[derive(Debug, Clone, PartialEq)]
pub struct PanelEntry {
    pub d_tag: String,
    pub agent_pubkey: String,
    pub definition: PanelDefinition,
    pub last_updated: u64,
    pub event_id: String,
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
    /// Drives member-surface suppression via [`ActionEntry::is_member_visible`].
    pub risk_tier: Option<String>,
}

impl ActionEntry {
    /// F7 (approval-fatigue response): whether the member (non-admin) surface
    /// shows this request. A `low` risk tier is suppressed so a member sees only
    /// the requests a tier says warrant attention. This is a **view filter** —
    /// the 31402/31403 events still exist in the store and stay visible on the
    /// admin surface and through the decisions read API (ADR-106 Decision 4). An
    /// unlabelled request (no tier) is shown (fail-open on visibility).
    pub fn is_member_visible(&self) -> bool {
        match &self.risk_tier {
            Some(t) => !governance::RiskTier::parse(t).is_member_suppressed(),
            None => true,
        }
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
    pub panels: HashMap<String, PanelEntry>,
    pub actions: Vec<ActionEntry>,
    pub panel_states: HashMap<String, serde_json::Value>,
    /// Decision history per case `d`-tag, oldest-first. Feeds the supersession
    /// history surfaces (F6).
    pub decisions: HashMap<String, Vec<DecisionEntry>>,
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
                    self.state.update(|s| {
                        s.panels.insert(
                            d_tag.clone(),
                            PanelEntry {
                                d_tag,
                                agent_pubkey: event.pubkey.clone(),
                                definition: def,
                                last_updated: event.created_at,
                                event_id: event.id.clone(),
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
                        if s.actions.iter().any(|a| a.event_id == event.id) {
                            return;
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
                            risk_tier: req.risk_tier.map(|t| t.as_str().to_string()),
                        });
                    });
                }
            }
            governance::KIND_ACTION_RESPONSE => {
                // F6 (DDD §7a): track human decisions so the surfaces can render
                // the supersession history. A superseding decision carries an
                // `e`-tag with the `supersedes` marker referencing the prior
                // decision event.
                let outcome =
                    governance::broker::DecisionOutcome::from_response_content(&event.content)
                        .map(|o| o.action_str().to_string())
                        .unwrap_or_else(|| "decision".to_string());
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
                    });
                    chain.sort_by_key(|e| e.created_at);
                });
            }
            governance::KIND_PANEL_STATE => {
                if let Ok(state_data) = serde_json::from_str::<serde_json::Value>(&event.content) {
                    self.state.update(|s| {
                        s.panel_states.insert(d_tag.clone(), state_data);
                        if let Some(panel) = s.panels.get_mut(&d_tag) {
                            panel.last_updated = event.created_at;
                        }
                    });
                }
            }
            governance::KIND_PANEL_UPDATE => {
                if let Ok(diff) = serde_json::from_str::<serde_json::Value>(&event.content) {
                    self.state.update(|s| {
                        let current = s
                            .panel_states
                            .entry(d_tag.clone())
                            .or_insert_with(|| serde_json::Value::Object(Default::default()));
                        if let (Some(base), Some(patch)) =
                            (current.as_object_mut(), diff.as_object())
                        {
                            for (k, v) in patch {
                                base.insert(k.clone(), v.clone());
                            }
                        }
                        if let Some(panel) = s.panels.get_mut(&d_tag) {
                            panel.last_updated = event.created_at;
                        }
                    });
                }
            }
            governance::KIND_PANEL_RETIRED => {
                self.state.update(|s| {
                    s.panels.remove(&d_tag);
                    s.panel_states.remove(&d_tag);
                });
            }
            _ => {}
        }
    }

    pub fn panel_count(&self) -> Memo<usize> {
        let state = self.state;
        Memo::new(move |_| state.read().panels.len())
    }

    pub fn pending_action_count(&self) -> Memo<usize> {
        let state = self.state;
        Memo::new(move |_| state.read().actions.len())
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

impl PanelRegistry {
    /// The rendered supersession chain for a case `d`-tag (F6). Empty when no
    /// decisions have been observed for it.
    pub fn decision_chain(&self, d_tag: &str) -> Vec<DecisionView> {
        let s = self.state.read();
        match s.decisions.get(d_tag) {
            Some(entries) => resolve_decision_chain(entries),
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(event_id: &str, at: u64, outcome: &str, supersedes: Option<&str>) -> DecisionEntry {
        DecisionEntry {
            d_tag: "case-1".into(),
            event_id: event_id.into(),
            signer_pubkey: "signer".into(),
            outcome: outcome.into(),
            reason: "r".into(),
            created_at: at,
            supersedes: supersedes.map(str::to_string),
        }
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
