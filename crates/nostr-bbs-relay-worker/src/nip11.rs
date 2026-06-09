//! NIP-11 Relay Information Document.
//!
//! Returns a JSON document describing relay capabilities, limits, and retention
//! policies per <https://github.com/nostr-protocol/nips/blob/master/11.md>.

use nostr_bbs_core::governance::{
    KIND_ACTION_REQUEST, KIND_ACTION_RESPONSE, KIND_PANEL_DEFINITION, KIND_PANEL_RETIRED,
    KIND_PANEL_STATE, KIND_PANEL_UPDATE,
};
use serde_json::json;
use worker::Env;

/// Build the NIP-11 relay information JSON value.
///
/// The relay name is taken from the `RELAY_NAME` env var (falling back to
/// "nostr-bbs Relay"). The pubkey and contact fields are left empty since
/// admin status is now dynamic (stored in D1).
pub fn relay_info(env: &Env) -> serde_json::Value {
    let relay_name = env
        .var("RELAY_NAME")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "nostr-bbs Relay".to_string());

    let admin_pubkey = String::new();
    let contact = String::new();

    json!({
        "name": relay_name,
        "description": "Private whitelist-only Nostr relay (nostr-bbs).",
        "pubkey": admin_pubkey,
        "contact": contact,
        // NIP-56 (kind-1984 reports) is enforced relay-side: trust-gated
        // submission, report projection, and auto-hide moderation all run in
        // `nip_handlers`. It was previously implemented but unadvertised; add
        // it so the info document accurately reflects relay capability.
        //
        // NIP-17 (private direct messages) is NOT advertised. The relay
        // accepts and recipient-gates kind-1059 gift wraps (NIP-59), but
        // NIP-17 additionally requires inbox routing: kind-14 chat messages
        // delivered to the recipient's declared DM relays (kind-10050). No
        // such inbox routing exists here, so advertising NIP-17 would
        // overstate capability — only the NIP-59 transport is implemented.
        "supported_nips": [1, 9, 11, 16, 29, 33, 40, 42, 45, 50, 56, 59, 65, 90, 98],
        "software": "https://github.com/DreamLab-AI/nostr-rust-forum",
        "version": "3.0.0",
        "limitation": {
            "max_message_length": 65536,
            "max_content_length": 65536,
            "max_event_tags": 2000,
            "max_subscriptions": 20,
            "max_filters": 10,
            "max_limit": 1000,
            "max_subid_length": 64,
            "auth_required": false,
            "payment_required": false,
            "restricted_writes": true,
        },
        "retention": [
            { "kinds": [0], "time": serde_json::Value::Null },
            { "kinds": [3], "time": serde_json::Value::Null },
            { "kinds": [1], "time": 7776000 },
            { "kinds": [7], "time": 2592000 },
            { "kinds": [9024], "time": 86400 },
            { "kinds": [[10000, 19999]], "time": serde_json::Value::Null },
            { "kinds": [[30000, 39999]], "time": serde_json::Value::Null },
        ],
        // DreamLab namespaced extension: the Agent Control Surface Protocol.
        // This relay gates governance kinds 31400-31405 behind the
        // `agent_registry` table (only registered `did:nostr` agent pubkeys may
        // publish PanelDefinition/ActionRequest/etc.; humans respond via 31403).
        // A NIP-11-reading agent uses this block to discover that the relay
        // speaks the mesh governance protocol and which kinds it enforces.
        // Kind numbers are sourced from the canonical `governance` constants to
        // prevent drift. Namespaced under `dreamlab` so it never collides with
        // standard NIP-11 fields.
        "dreamlab": {
            "agent_control_surface": {
                "enabled": true,
                "registry_gated": true,
                "panel_definition_kind": KIND_PANEL_DEFINITION,
                "panel_state_kind": KIND_PANEL_STATE,
                "action_request_kind": KIND_ACTION_REQUEST,
                "action_response_kind": KIND_ACTION_RESPONSE,
                "panel_update_kind": KIND_PANEL_UPDATE,
                "panel_retired_kind": KIND_PANEL_RETIRED,
                "agent_auth": "nip98",
                "agent_identity": "did:nostr",
            }
        },
    })
}
