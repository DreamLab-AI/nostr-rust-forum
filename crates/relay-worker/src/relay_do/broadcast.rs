//! Event broadcasting, NIP-16 event treatment classification,
//! rate limiting, and wire protocol helpers.

use nostr_core::event::NostrEvent;
use worker::*;

use super::filter::event_matches_filters;
use super::NostrRelayDO;

// ---------------------------------------------------------------------------
// NIP-16 event treatment
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EventTreatment {
    Regular,
    Replaceable,
    Ephemeral,
    ParameterizedReplaceable,
}

pub(crate) fn event_treatment(kind: u64) -> EventTreatment {
    if (20000..30000).contains(&kind) {
        EventTreatment::Ephemeral
    } else if (10000..20000).contains(&kind) || kind == 0 || kind == 3 {
        EventTreatment::Replaceable
    } else if (30000..40000).contains(&kind) {
        EventTreatment::ParameterizedReplaceable
    } else {
        EventTreatment::Regular
    }
}

// ---------------------------------------------------------------------------
// Broadcasting
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    pub(crate) fn broadcast_event(&self, event: &NostrEvent) {
        let sessions = self.sessions.borrow();
        for (_id, session) in sessions.iter() {
            for (sub_id, filters) in &session.subscriptions {
                if event_matches_filters(event, filters) {
                    Self::send_event(&session.ws, sub_id, event);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/// Maximum events per second per IP.
const MAX_EVENTS_PER_SECOND: usize = 10;

impl NostrRelayDO {
    pub(crate) fn check_rate_limit(&self, ip: &str) -> bool {
        let now = js_sys::Date::now();
        let cutoff = now - 1000.0;

        let mut rate_limits = self.rate_limits.borrow_mut();
        let timestamps = rate_limits.entry(ip.to_string()).or_default();
        timestamps.retain(|&ts| ts >= cutoff);

        if timestamps.len() >= MAX_EVENTS_PER_SECOND {
            return false;
        }
        timestamps.push(now);
        true
    }
}

// ---------------------------------------------------------------------------
// Wire protocol helpers
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    pub(crate) fn send(ws: &WebSocket, msg: &serde_json::Value) {
        if let Ok(json_str) = serde_json::to_string(msg) {
            let _ = ws.send_with_str(&json_str);
        }
    }

    pub(crate) fn send_ok(ws: &WebSocket, id: &str, ok: bool, msg: &str) {
        Self::send(ws, &serde_json::json!(["OK", id, ok, msg]));
    }

    pub(crate) fn send_notice(ws: &WebSocket, msg: &str) {
        Self::send(ws, &serde_json::json!(["NOTICE", msg]));
    }

    pub(crate) fn send_event(ws: &WebSocket, sub_id: &str, event: &NostrEvent) {
        Self::send(ws, &serde_json::json!(["EVENT", sub_id, event]));
    }

    pub(crate) fn send_eose(ws: &WebSocket, sub_id: &str) {
        Self::send(ws, &serde_json::json!(["EOSE", sub_id]));
    }

    pub(crate) fn send_auth(ws: &WebSocket, challenge: &str) {
        Self::send(ws, &serde_json::json!(["AUTH", challenge]));
    }

    pub(crate) fn send_count(ws: &WebSocket, sub_id: &str, count: u64) {
        Self::send(ws, &serde_json::json!(["COUNT", sub_id, { "count": count }]));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── event_treatment ──────────────────────────────────────────────────

    #[test]
    fn regular_kind_1() {
        assert_eq!(event_treatment(1), EventTreatment::Regular);
    }

    #[test]
    fn regular_kind_4() {
        assert_eq!(event_treatment(4), EventTreatment::Regular);
    }

    #[test]
    fn regular_kind_7() {
        assert_eq!(event_treatment(7), EventTreatment::Regular);
    }

    #[test]
    fn regular_kind_40() {
        assert_eq!(event_treatment(40), EventTreatment::Regular);
    }

    #[test]
    fn regular_kind_42() {
        assert_eq!(event_treatment(42), EventTreatment::Regular);
    }

    #[test]
    fn regular_kind_9735() {
        assert_eq!(event_treatment(9735), EventTreatment::Regular);
    }

    #[test]
    fn replaceable_kind_0_profile() {
        assert_eq!(event_treatment(0), EventTreatment::Replaceable);
    }

    #[test]
    fn replaceable_kind_3_contacts() {
        assert_eq!(event_treatment(3), EventTreatment::Replaceable);
    }

    #[test]
    fn replaceable_kind_10000() {
        assert_eq!(event_treatment(10000), EventTreatment::Replaceable);
    }

    #[test]
    fn replaceable_kind_10002() {
        assert_eq!(event_treatment(10002), EventTreatment::Replaceable);
    }

    #[test]
    fn replaceable_kind_19999() {
        assert_eq!(event_treatment(19999), EventTreatment::Replaceable);
    }

    #[test]
    fn ephemeral_kind_20000() {
        assert_eq!(event_treatment(20000), EventTreatment::Ephemeral);
    }

    #[test]
    fn ephemeral_kind_25000() {
        assert_eq!(event_treatment(25000), EventTreatment::Ephemeral);
    }

    #[test]
    fn ephemeral_kind_29999() {
        assert_eq!(event_treatment(29999), EventTreatment::Ephemeral);
    }

    #[test]
    fn parameterized_replaceable_kind_30000() {
        assert_eq!(event_treatment(30000), EventTreatment::ParameterizedReplaceable);
    }

    #[test]
    fn parameterized_replaceable_kind_30023_article() {
        assert_eq!(event_treatment(30023), EventTreatment::ParameterizedReplaceable);
    }

    #[test]
    fn parameterized_replaceable_kind_39999() {
        assert_eq!(event_treatment(39999), EventTreatment::ParameterizedReplaceable);
    }

    // ── boundary tests ──────────────────────────────────────────────────

    #[test]
    fn boundary_9999_is_regular() {
        assert_eq!(event_treatment(9999), EventTreatment::Regular);
    }

    #[test]
    fn boundary_10000_is_replaceable() {
        assert_eq!(event_treatment(10000), EventTreatment::Replaceable);
    }

    #[test]
    fn boundary_20000_is_ephemeral() {
        assert_eq!(event_treatment(20000), EventTreatment::Ephemeral);
    }

    #[test]
    fn boundary_30000_is_param_replaceable() {
        assert_eq!(event_treatment(30000), EventTreatment::ParameterizedReplaceable);
    }

    #[test]
    fn boundary_40000_is_regular() {
        assert_eq!(event_treatment(40000), EventTreatment::Regular);
    }

    // ── NIP-98 kind 27235 is regular (not in any special range) ─────────

    #[test]
    fn nip98_kind_27235_is_ephemeral() {
        // 27235 falls in ephemeral range (20000..30000)
        assert_eq!(event_treatment(27235), EventTreatment::Ephemeral);
    }

    // ── kind 0 and 3 special cases ──────────────────────────────────────

    #[test]
    fn kind_0_and_3_are_replaceable_despite_low_range() {
        // NIP-01 specifies kinds 0 and 3 are replaceable, even though
        // they're below the 10000-19999 range
        assert_eq!(event_treatment(0), EventTreatment::Replaceable);
        assert_eq!(event_treatment(3), EventTreatment::Replaceable);
    }

    #[test]
    fn kind_1_is_not_replaceable() {
        assert_ne!(event_treatment(1), EventTreatment::Replaceable);
    }

    #[test]
    fn kind_2_is_regular() {
        assert_eq!(event_treatment(2), EventTreatment::Regular);
    }
}
