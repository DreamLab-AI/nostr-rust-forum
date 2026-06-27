//! Event broadcasting, NIP-16 event treatment classification,
//! rate limiting, and wire protocol helpers.

use nostr_bbs_core::event::NostrEvent;
use worker::*;

use super::calendar_projection;
use super::filter::{event_matches_filters, tag_value, NostrFilter};
use super::nip_handlers::ReadDecision;
use super::NostrRelayDO;
use crate::zone_config::ZoneConfig;

// ---------------------------------------------------------------------------
// NIP-16 event treatment
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum EventTreatment {
    Regular,
    Replaceable,
    Ephemeral,
    ParameterizedReplaceable,
}

#[doc(hidden)]
pub fn event_treatment(kind: u64) -> EventTreatment {
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

/// A broadcast delivery candidate: a session's authed pubkey (if any), its
/// WebSocket, and a snapshot of its (sub_id, filters) subscriptions.
type DeliveryCandidate = (Option<String>, WebSocket, Vec<(String, Vec<NostrFilter>)>);

impl NostrRelayDO {
    pub(crate) async fn broadcast_event(&self, event: &NostrEvent) {
        // NIP-59: kind-1059 (Sealed DMs) must only be delivered to the session
        // whose authenticated pubkey matches the event's `p` tag recipient.
        let kind_1059_recipient: Option<String> = if event.kind == 1059 {
            tag_value(event, "p")
        } else {
            None
        };

        // Only zone-scoped kinds (kind-40 defs, kind-42 content, NIP-52 calendar)
        // require the per-recipient read gate. Everything else broadcasts to every
        // matching subscriber as before, so the common hot path adds no async work.
        let needs_gate = event.kind == 40
            || event.kind == 42
            || calendar_projection::is_projected_calendar_kind(event.kind);

        // Snapshot delivery candidates so we never hold the `sessions` borrow
        // across the async zone/cohort lookups in the read gate below.
        let candidates: Vec<DeliveryCandidate> = {
            let sessions = self.sessions.borrow();
            sessions
                .values()
                .map(|s| {
                    (
                        s.authed_pubkey.clone(),
                        s.ws.clone(),
                        s.subscriptions
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect(),
                    )
                })
                .collect()
        };

        let zones = if needs_gate {
            Some(ZoneConfig::load(&self.env))
        } else {
            None
        };

        for (authed_pubkey, ws, subscriptions) in &candidates {
            // For kind-1059 events, skip sessions not authenticated as the
            // intended recipient.
            if let Some(ref recipient) = kind_1059_recipient {
                match authed_pubkey {
                    Some(pk) if pk == recipient => {}
                    _ => continue,
                }
            }

            // Apply the SAME per-recipient read gate REQ uses, so the live-push
            // path cannot leak zone-private channel content or non-public calendar
            // events to a subscriber who could not have read them via an initial
            // REQ. `deliver` is the (possibly calendar-projected) event to send,
            // or None to withhold; for non-zone-scoped events the gate is skipped.
            let deliver: Option<NostrEvent> = if let Some(zones) = &zones {
                if !subscriptions
                    .iter()
                    .any(|(_, filters)| event_matches_filters(event, filters))
                {
                    continue;
                }
                let ctx = self.resolve_viewer_context(authed_pubkey.clone()).await;
                match self.authorize_event(event, &ctx, zones).await {
                    ReadDecision::Deliver => Some(event.clone()),
                    ReadDecision::DeliverAs(out) => Some(out),
                    ReadDecision::Withhold => continue,
                }
            } else {
                None
            };

            for (sub_id, filters) in subscriptions {
                if event_matches_filters(event, filters) {
                    match &deliver {
                        Some(out) => Self::send_event(ws, sub_id, out),
                        None => Self::send_event(ws, sub_id, event),
                    }
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
        Self::send(
            ws,
            &serde_json::json!(["COUNT", sub_id, { "count": count }]),
        );
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
        assert_eq!(
            event_treatment(30000),
            EventTreatment::ParameterizedReplaceable
        );
    }

    #[test]
    fn parameterized_replaceable_kind_30023_article() {
        assert_eq!(
            event_treatment(30023),
            EventTreatment::ParameterizedReplaceable
        );
    }

    #[test]
    fn parameterized_replaceable_kind_39999() {
        assert_eq!(
            event_treatment(39999),
            EventTreatment::ParameterizedReplaceable
        );
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
        assert_eq!(
            event_treatment(30000),
            EventTreatment::ParameterizedReplaceable
        );
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

    // ── NIP-65 kind-10002 (relay list) is replaceable ───────────────────

    #[test]
    fn nip65_kind_10002_relay_list_is_replaceable() {
        // kind-10002 falls in the replaceable range (10000..20000)
        assert_eq!(event_treatment(10002), EventTreatment::Replaceable);
    }

    // ── NIP-31 kind-31990 (handler information) is parameterized-replaceable ──

    #[test]
    fn kind_31990_handler_info_is_param_replaceable() {
        // kind-31990 falls in the parameterized replaceable range (30000..40000)
        assert_eq!(
            event_treatment(31990),
            EventTreatment::ParameterizedReplaceable
        );
    }

    // ── NIP-59 kind-1059 (sealed DM) is regular ─────────────────────────

    #[test]
    fn nip59_kind_1059_sealed_dm_is_regular() {
        // kind-1059 is a regular event (no special replacement semantics)
        assert_eq!(event_treatment(1059), EventTreatment::Regular);
    }
}
