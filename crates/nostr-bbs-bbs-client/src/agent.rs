//! Agent-governance control panels, built from the kit's real
//! [`nostr_bbs_core::governance`] schema.
//!
//! In production these [`PanelDefinition`]s arrive as governance events
//! (`is_governance_kind`) over the relay and are validated with
//! `validate_governance_event`; the human signs an
//! [`ActionResponse`](nostr_bbs_core::governance::ActionResponse) back. The
//! BBS "Door Games" screen renders the SAME panel shape in ASCII, so it is a
//! genuine surface onto the human-in-the-loop agent plane rather than a mock.
//!
//! Until the relay transport is wired in, [`sample_panels`] returns
//! representative panels so the screen renders standalone.

use nostr_bbs_core::governance::{
    ActionDef, ActionStyle, FieldDef, FieldType, LayoutHint, PanelCapability, PanelDefinition,
    PanelSchema,
};

/// A registered agent and the control panel it publishes.
pub struct AgentPanel {
    /// Short agent handle shown in the door list.
    pub agent: &'static str,
    /// The panel definition (kit governance schema).
    pub panel: PanelDefinition,
}

fn field(name: &str, label: &str, ty: FieldType) -> FieldDef {
    FieldDef {
        name: name.to_string(),
        field_type: ty,
        label: label.to_string(),
    }
}

fn action(id: &str, label: &str, style: ActionStyle) -> ActionDef {
    ActionDef {
        id: id.to_string(),
        label: label.to_string(),
        style,
    }
}

/// Representative agent panels demonstrating the governance plane.
pub fn sample_panels() -> Vec<AgentPanel> {
    vec![
        AgentPanel {
            agent: "mod-bot",
            panel: PanelDefinition {
                title: "Moderation Inbox".to_string(),
                description: "Pending reports awaiting a human decision.".to_string(),
                version: "1.0.0".to_string(),
                schema: PanelSchema::ActionInbox,
                fields: vec![
                    field("subject", "Reported event", FieldType::String),
                    field("reporter", "Reporter", FieldType::String),
                    field("category", "Category", FieldType::Enum),
                    field("opened", "Opened", FieldType::Timestamp),
                ],
                actions: vec![
                    action("approve", "Approve", ActionStyle::Primary),
                    action("dismiss", "Dismiss", ActionStyle::Secondary),
                    action("ban", "Ban author", ActionStyle::Destructive),
                ],
                layout: LayoutHint::InboxTable,
                capabilities: vec![PanelCapability::Filter, PanelCapability::BulkAction],
                refresh_secs: 30,
            },
        },
        AgentPanel {
            agent: "ops-agent",
            panel: PanelDefinition {
                title: "Relay Health".to_string(),
                description: "Live status board for relay & federation peers.".to_string(),
                version: "1.0.0".to_string(),
                schema: PanelSchema::StatusBoard,
                fields: vec![
                    field("peer", "Peer", FieldType::String),
                    field("latency_ms", "Latency (ms)", FieldType::Int),
                    field("connected", "Up", FieldType::Bool),
                ],
                actions: vec![action("reconnect", "Reconnect", ActionStyle::Primary)],
                layout: LayoutHint::CardGrid,
                capabilities: vec![PanelCapability::Sort],
                refresh_secs: 10,
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_panels_use_governance_schema() {
        let panels = sample_panels();
        assert_eq!(panels.len(), 2);
        let inbox = &panels[0].panel;
        assert_eq!(inbox.schema, PanelSchema::ActionInbox);
        assert_eq!(inbox.fields.len(), 4);
        // A destructive action must be present and correctly styled.
        assert!(inbox
            .actions
            .iter()
            .any(|a| a.style == ActionStyle::Destructive && a.id == "ban"));
    }

    #[test]
    fn panels_serialize_as_governance_events() {
        // The panels must round-trip through the kit's serde representation so
        // they are wire-compatible with real governance events.
        for ap in sample_panels() {
            let json = serde_json::to_string(&ap.panel).expect("serialize");
            let back: PanelDefinition = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, ap.panel);
        }
    }
}
