//! NIP-11 Relay Information Document.
//!
//! Returns a JSON document describing relay capabilities, limits, and retention
//! policies per <https://github.com/nostr-protocol/nips/blob/master/11.md>.

use serde_json::json;
use worker::Env;

/// Build the NIP-11 relay information JSON value.
///
/// The relay name is taken from the `RELAY_NAME` env var (falling back to
/// "Nostr BBS Relay"). The pubkey and contact fields are left empty since
/// admin status is now dynamic (stored in D1).
pub fn relay_info(env: &Env) -> serde_json::Value {
    let relay_name = env
        .var("RELAY_NAME")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "Nostr BBS Relay".to_string());

    let admin_pubkey = String::new();
    let contact = String::new();

    json!({
        "name": relay_name,
        "description": "Private whitelist-only Nostr relay for the Nostr BBS community.",
        "pubkey": admin_pubkey,
        "contact": contact,
        "supported_nips": [1, 9, 11, 16, 29, 33, 40, 42, 45, 50, 98],
        "software": "https://github.com/example/nostr-bbs-rs",
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
    })
}
