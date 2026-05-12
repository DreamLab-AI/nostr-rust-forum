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
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PanelRegistryState {
    pub panels: HashMap<String, PanelEntry>,
    pub actions: Vec<ActionEntry>,
    pub panel_states: HashMap<String, serde_json::Value>,
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
                        s.actions.push(ActionEntry {
                            d_tag,
                            agent_pubkey: event.pubkey.clone(),
                            fields: req.fields,
                            reasoning: req.reasoning,
                            priority,
                            created_at: event.created_at,
                            event_id: event.id.clone(),
                        });
                    });
                }
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
                        let current = s.panel_states.entry(d_tag.clone()).or_insert_with(|| serde_json::Value::Object(Default::default()));
                        if let (Some(base), Some(patch)) = (current.as_object_mut(), diff.as_object()) {
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
