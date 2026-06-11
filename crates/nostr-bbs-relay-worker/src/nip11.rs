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
        "version": env!("CARGO_PKG_VERSION"),
        "limitation": {
            "max_message_length": 65536,
            "max_content_length": 65536,
            "max_event_tags": 2000,
            "max_subscriptions": 20,
            "max_filters": 10,
            "max_limit": 1000,
            "max_subid_length": 64,
            // Gap 7 (truthful relay-info): the relay sends a NIP-42 AUTH
            // challenge on connect and lists 42 in supported_nips, but writes
            // are NOT gated on completing the AUTH handshake — the gate is on
            // the *signed event's pubkey* being whitelisted (see
            // nip_handlers::handle_event `is_whitelisted`). So `auth_required`
            // is false in the strict NIP-42 sense (no AUTH round-trip is
            // forced before EVENT), but writes are still trust-gated. The
            // `restricted_writes` flag plus the `dreamlab.write_policy` block
            // below describe the actual model so a standard client does not
            // mistake this for an open relay.
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
            // Gap 7: make the whitelist-gated write model explicit. Standard
            // NIP-11 only has the boolean `restricted_writes`; this block says
            // *how* writes are restricted so a client knows a rejection is not
            // a NIP-42 AUTH failure but a trust/whitelist decision keyed on the
            // signed event's pubkey. `auth_method: "whitelist"` (not "nip42")
            // is the truthful description: the EVENT itself proves identity,
            // and admission is decided against the relay's whitelist + trust
            // levels, not against a completed AUTH session.
            "write_policy": {
                "model": "whitelist",
                "auth_method": "whitelist",
                "nip42_challenge_sent": true,
                "nip42_required_for_write": false,
                "rejection_message": "blocked: pubkey not whitelisted",
            },
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
