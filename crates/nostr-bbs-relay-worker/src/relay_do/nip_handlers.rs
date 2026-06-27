//! NIP-specific protocol handlers for the Nostr relay.
//!
//! - NIP-01: EVENT, REQ, CLOSE
//! - NIP-09: Deletion processing
//! - NIP-42: AUTH challenge/response
//! - NIP-45: COUNT
//! - Event validation.
//! - Trust-level gating (TL0-TL3) for event kinds.
//! - Zone enforcement on EVENT and REQ.
//! - F11 (PRD-010): Federated kind allowlist filtering for mesh peers.

use nostr_bbs_core::event::NostrEvent;
use nostr_bbs_core::governance;
use nostr_bbs_core::{KIND_BAN, KIND_MUTE, KIND_REPORT_NIP56, KIND_UNBAN, KIND_UNMUTE};
use wasm_bindgen::JsValue;
use worker::*;

use crate::auth;
use crate::moderation;
use crate::trust::{self, TrustLevel};
use crate::zone_config::ZoneConfig;

use super::broadcast::{event_treatment, EventTreatment};
use super::calendar_projection;
use super::filter::{self, NostrFilter};
use super::NostrRelayDO;

use nostr_bbs_core::KIND_CALENDAR_RSVP;

// ---------------------------------------------------------------------------
// Security limits
// ---------------------------------------------------------------------------

const MAX_CONTENT_SIZE: usize = 64 * 1024;
const MAX_REGISTRATION_CONTENT_SIZE: usize = 8 * 1024;
const MAX_TAG_COUNT: usize = 2000;
const MAX_TAG_VALUE_SIZE: usize = 1024;
const MAX_TIMESTAMP_DRIFT: u64 = 60 * 60 * 24 * 7;
const MAX_SUBSCRIPTIONS: usize = 20;

/// NIP-59: gift-wrap event kind. Signed by a fresh ephemeral key per message;
/// recipient-gated via the first `["p", <hex>]` tag rather than the author.
const GIFT_WRAP_KIND: u64 = 1059;

/// NIP-29: Admin-only group management/moderation kinds.
fn is_nip29_admin_kind(kind: u64) -> bool {
    (9000..=9020).contains(&kind) || (39000..=39002).contains(&kind)
}

/// Phase C (write side): whether an RSVP (kind 31925) is permitted to be written,
/// given the AUTHOR's resolved projection tier for the RSVP's TARGET event.
///
/// An RSVP attaches its author to a target event. If the author can only see that
/// target as free/busy (`FreeBusy`) or not at all (`Omit`), accepting the RSVP is a
/// privacy/integrity leak. Only a `Full` tier (which already covers admins/owners
/// via `project_tier`'s short-circuit) is write-permitted.
///
/// Pure predicate over the already-resolved tier so the gate decision is
/// unit-testable without a `worker::Env` / D1. The caller resolves the target
/// zone/venue from D1 and computes the tier via
/// [`calendar_projection::project_tier`].
pub fn rsvp_write_permitted(tier: &calendar_projection::Projection) -> bool {
    matches!(tier, calendar_projection::Projection::Full)
}

/// Phase C (write side): whether a zone-tagged calendar event (31922/31923) is
/// permitted to be written. A zone-tagged event requires the author to hold write
/// access to that zone; an untagged event is unscoped and always permitted here.
///
/// `has_write` is the already-resolved
/// [`trust::has_zone_write_access`](crate::trust::has_zone_write_access) result.
/// Pure predicate so the decision is unit-testable without a `worker::Env`.
pub fn calendar_write_permitted(zone: Option<&str>, has_write: bool) -> bool {
    match zone {
        Some(_) => has_write,
        None => true,
    }
}

/// NIP-59: extract the gift-wrap (kind-1059) RECIPIENT pubkey from the first
/// `["p", <hex>]` tag. Returns `None` when the event is not a gift wrap, or when
/// no non-empty `p` tag is present. The recipient — not the ephemeral author —
/// is the principal the membership gate is applied to.
///
/// Pure over the event so the routing decision is unit-testable without an
/// `is_whitelisted` D1 lookup / `worker::Env`.
pub fn gift_wrap_recipient(event: &NostrEvent) -> Option<String> {
    if event.kind != GIFT_WRAP_KIND {
        return None;
    }
    match filter::tag_value(event, "p") {
        Some(pk) if !pk.is_empty() => Some(pk),
        _ => None,
    }
}

/// P1-6: whether an event must be rejected by the governance ActionResponse
/// admin gate. Returns `true` when the event is kind-31403 (approve/reject of
/// an agent action request) and the signer is NOT an admin.
///
/// Extracted as a pure predicate so the gate decision is unit-testable without
/// a `worker::Env` / `WebSocket`.
pub fn governance_response_blocked(kind: u64, is_admin: bool) -> bool {
    kind == governance::KIND_ACTION_RESPONSE && !is_admin
}

/// ADR-099: resolve the EFFECTIVE principal a session's access derives from.
///
/// When device keys are enabled and the authing `pubkey` is a registered,
/// non-revoked device key, its session "acts as" the OWNER for READ scope and
/// the OWNER is the principal the write-gate allowlist is checked against. The
/// device's own signature is verified UNCHANGED upstream — this only rebinds
/// *who is treated as the principal* for access, never the event's pubkey/sig.
///
/// `device_owner` is the already-resolved `device_owner(pubkey)` D1 lookup
/// (`Some(owner)` for a non-revoked device row, `None` otherwise). `enabled` is
/// `DEVICE_KEYS_ENABLED == "true"`.
///
/// Gate-off (`enabled == false`) ⇒ identity passthrough: returns `pubkey`
/// verbatim, so a device key is just an unknown pubkey and every existing gate
/// behaves exactly as before. Gate-on with no device row ⇒ also passthrough.
///
/// Pure over its inputs so the resolution is unit-testable without a
/// `worker::Env` / D1.
pub fn effective_principal(pubkey: &str, device_owner: Option<&str>, enabled: bool) -> String {
    if enabled {
        if let Some(owner) = device_owner {
            return owner.to_string();
        }
    }
    pubkey.to_string()
}

// ---------------------------------------------------------------------------
// NIP-01: EVENT handling
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    pub(crate) async fn handle_event(&self, ws: &WebSocket, ip: &str, event: NostrEvent) {
        // Rate limit
        if !self.check_rate_limit(ip) {
            Self::send_notice(ws, "rate limit exceeded");
            return;
        }

        // Validate event structure
        if !Self::validate_event(&event) {
            Self::send_ok(ws, &event.id, false, "invalid: event validation failed");
            return;
        }

        // NIP-40: Reject events with an expired `expiration` tag
        if let Some(exp) = filter::tag_value(&event, "expiration") {
            if let Ok(exp_ts) = exp.parse::<u64>() {
                if exp_ts < auth::js_now_secs() {
                    Self::send_ok(ws, &event.id, false, "invalid: event expired");
                    return;
                }
            }
        }

        // Verify event ID and Schnorr signature before any side effects
        // including admission state changes or activity tracking.
        if nostr_bbs_core::verify_event_strict(&event).is_err() {
            Self::send_ok(
                ws,
                &event.id,
                false,
                "invalid: event id or signature verification failed",
            );
            return;
        }

        // NIP-59 gift wraps (kind-1059) are signed by a fresh ephemeral key per
        // message, so the author is intentionally NOT a member and the standard
        // author-membership check would always reject them. Instead, gate on the
        // RECIPIENT carried in the first `["p", <hex>]` tag: accept only if that
        // recipient is a whitelisted member. This bounds gift-wrap acceptance to
        // messages addressed to existing members (no spam to non-members) while
        // permitting the ephemeral author.
        if event.kind == GIFT_WRAP_KIND {
            let recipient_ok = match gift_wrap_recipient(&event) {
                Some(pk) => self.is_whitelisted(&pk).await,
                None => false,
            };
            if !recipient_ok {
                Self::send_ok(
                    ws,
                    &event.id,
                    false,
                    "blocked: gift-wrap recipient not whitelisted",
                );
                return;
            }
        } else {
            // ADR-099: a device-authored event is admitted under its OWNER's
            // allowlist. `effective_pubkey` returns the owner for a registered
            // non-revoked device key when DEVICE_KEYS_ENABLED, else the author
            // pubkey verbatim (gate-off / non-device ⇒ unchanged behaviour). The
            // event's signature was already verified strictly above against the
            // device's own key; we only rebind WHO the allowlist is checked for.
            let allowlist_pubkey = self.effective_pubkey(&event.pubkey).await;
            if !self.is_whitelisted(&allowlist_pubkey).await {
                Self::send_ok(ws, &event.id, false, "blocked: pubkey not whitelisted");
                return;
            }
        }

        // F11 (PRD-010): When mesh federation is active, events arriving from
        // a recognised mesh peer (listed in MESH_ALLOWED_REMOTE_DIDS) are
        // filtered against the federated_kinds allowlist. Local clients whose
        // pubkey is NOT in the remote DIDs list bypass this check entirely.
        if self.is_mesh_peer(&event.pubkey) && !self.is_federated_kind_allowed(event.kind) {
            Self::send_ok(
                ws,
                &event.id,
                false,
                "blocked: event kind not in federated_kinds allowlist",
            );
            return;
        }

        // Suspension and silence check
        let (suspended, silenced) = trust::check_suspension(&event.pubkey, &self.env).await;
        if suspended {
            Self::send_ok(ws, &event.id, false, "blocked: account suspended");
            return;
        }
        if silenced {
            Self::send_ok(
                ws,
                &event.id,
                false,
                "blocked: account silenced (read-only)",
            );
            return;
        }

        // WI-2: kind-1 / kind-42 ingress check against moderation_actions
        // (60s DO cache). Applies to any content-producing kind we care
        // about. Admins bypass so they can e.g. publish warnings even
        // while under moderation for other reasons.
        //
        // P2-03: use admin_cache to avoid redundant D1 queries on every event.
        if matches!(event.kind, 1 | 42)
            && !self.admin_cache.is_admin(&event.pubkey, &self.env).await
            && self.mod_cache.is_blocked(&event.pubkey, &self.env).await
        {
            Self::send_ok(ws, &event.id, false, "blocked: author is banned or muted");
            return;
        }

        // Trust-level gating for specific event kinds
        // P2-03: cached lookup — same TTL entry reused from above if still fresh.
        let is_admin = self.admin_cache.is_admin(&event.pubkey, &self.env).await;
        if !is_admin {
            let trust_level = trust::get_trust_level(&event.pubkey, &self.env).await;

            // kind-40 (channel creation): TL2+ required
            if event.kind == 40 && trust_level < TrustLevel::Regular {
                Self::send_ok(
                    ws,
                    &event.id,
                    false,
                    "restricted: TL2+ required for channel creation",
                );
                return;
            }

            // kind-41 (channel metadata/pin): TL2+ for own channel, TL3+ for any
            if event.kind == 41 {
                let Some(channel_id) = filter::tag_value(&event, "e") else {
                    Self::send_ok(ws, &event.id, false, "invalid: missing channel tag");
                    return;
                };
                if trust_level < TrustLevel::Regular {
                    Self::send_ok(
                        ws,
                        &event.id,
                        false,
                        "restricted: TL2+ required for channel metadata",
                    );
                    return;
                }
                // If TL2 (not TL3), verify they are the channel creator
                if trust_level < TrustLevel::Trusted
                    && !self.is_channel_creator(&event.pubkey, &channel_id).await
                {
                    Self::send_ok(
                        ws,
                        &event.id,
                        false,
                        "restricted: TL3+ required to modify others' channels",
                    );
                    return;
                }
            }

            // kind-1984 (report): TL1+ required
            if event.kind == KIND_REPORT_NIP56 && trust_level < TrustLevel::Member {
                Self::send_ok(
                    ws,
                    &event.id,
                    false,
                    "restricted: TL1+ required to report content",
                );
                return;
            }

            // kind-5 (deletion): own events always allowed; others' events require TL3+
            if event.kind == 5 {
                let targets_others = self.deletion_targets_others(&event).await;
                if targets_others && trust_level < TrustLevel::Trusted {
                    Self::send_ok(
                        ws,
                        &event.id,
                        false,
                        "restricted: TL3+ required to delete others' events",
                    );
                    return;
                }
            }
        }

        // NIP-29: Admin-only group management kinds
        if is_nip29_admin_kind(event.kind) {
            // NIP-29 TODO: This enforces the h-tag/admin gate, but full group
            // metadata should be relay-key-generated rather than accepted from
            // arbitrary clients.
            if filter::tag_value(&event, "h").is_none() {
                Self::send_ok(ws, &event.id, false, "invalid: missing group tag");
                return;
            }
            if !is_admin {
                Self::send_ok(ws, &event.id, false, "blocked: admin-only group action");
                return;
            }
        }

        // Agent Control Surface Protocol: governance kinds (31400-31405) are
        // only accepted from pubkeys registered in the agent_registry table.
        // Human responses (kind 31403, approve/reject of agent action requests)
        // are exempt from the agent-registry gate but, per P1-6, MUST come from
        // an admin -- they are privileged decisions, not generic member actions.
        if governance::is_governance_kind(event.kind)
            && event.kind != governance::KIND_ACTION_RESPONSE
            && !self.is_registered_agent(&event.pubkey).await
        {
            Self::send_ok(
                ws,
                &event.id,
                false,
                "blocked: pubkey not in agent registry",
            );
            return;
        }

        // P1-6: kind-31403 ActionResponse (approve/reject) is admin-only. Uses
        // the same admin check as the moderation mirror. Reject non-admins.
        if governance_response_blocked(event.kind, is_admin) {
            Self::send_ok(
                ws,
                &event.id,
                false,
                "blocked: admin-only governance action response",
            );
            return;
        }

        // Zone enforcement for channel messages (kind-42)
        if event.kind == 42 {
            let Some(channel_id) = filter::tag_value(&event, "e") else {
                Self::send_ok(ws, &event.id, false, "invalid: missing channel tag");
                return;
            };
            let zone = trust::get_channel_zone(&channel_id, &self.env)
                .await
                .unwrap_or_else(|| "home".to_string());
            // Writes route through the write gate (write_cohorts ?? required_cohorts)
            // so a public zone can be read-by-all yet write-restricted.
            if !is_admin && !trust::has_zone_write_access(&event.pubkey, &zone, &self.env).await {
                Self::send_ok(ws, &event.id, false, "zone access denied");
                return;
            }
        }

        // Phase C (write side): NIP-52 calendar kinds carry their access binding
        // natively, not via a channel-id lookup. The READ path projects them
        // per-tier; the WRITE path must validate the author against the SAME
        // data-tier rules so a lower-tier author cannot inject an RSVP into, or a
        // calendar event onto, a zone they cannot fully see/write.
        //
        //   - 31925 RSVP: an RSVP attaches the author to a target event. If the
        //     author can only see that target as free/busy (or not at all), the
        //     RSVP is a privacy/integrity leak — it surfaces participation in an
        //     event the author isn't a full participant of. We resolve the TARGET
        //     from D1 (never an author-mirrored tag, which is spoofable) and
        //     compute the AUTHOR's projection tier for it; accept only on Full.
        //     Admins/owners are inherently Full. An unresolvable target denies for
        //     non-admins (deny-by-default: blocks pre-publishing RSVPs to a target
        //     that isn't visible yet).
        //
        //   - 31922/31923 calendar events: a zone-tagged event must come from an
        //     author with write access to that zone (mirrors kind-42). Untagged
        //     calendar events are unscoped and keep prior behaviour.
        if event.kind == KIND_CALENDAR_RSVP && !is_admin {
            let permitted = match self.resolve_rsvp_target(&event).await {
                Some((zone, venue)) => {
                    // `is_owner=false`: a non-admin author is never the relay owner.
                    // `project_tier` short-circuits admins/owners to Full anyway;
                    // here we ask the author's own tier for the TARGET's real zone.
                    let (author_cohorts, author_cohort_admin) =
                        trust::get_viewer_cohorts(&event.pubkey, &self.env).await;
                    let tier = calendar_projection::project_tier(
                        &author_cohorts,
                        &zone,
                        venue.as_deref(),
                        false,
                        author_cohort_admin,
                    );
                    rsvp_write_permitted(&tier)
                }
                // Target not resolvable: deny by default for non-admins. Prevents
                // pre-publishing an RSVP to an event that is not yet visible.
                None => false,
            };
            if !permitted {
                Self::send_ok(ws, &event.id, false, "blocked: rsvp not permitted");
                return;
            }
        } else if matches!(
            event.kind,
            nostr_bbs_core::KIND_CALENDAR_DATE_EVENT | nostr_bbs_core::KIND_CALENDAR_EVENT
        ) && !is_admin
        {
            // Only zone-tagged calendar events are write-gated; untagged events
            // are unscoped and retain prior behaviour.
            let zone = nostr_bbs_core::read_zone_tag(&event);
            let has_write = match zone {
                Some(z) => trust::has_zone_write_access(&event.pubkey, z, &self.env).await,
                None => false,
            };
            if !calendar_write_permitted(zone, has_write) {
                Self::send_ok(ws, &event.id, false, "blocked: zone access denied");
                return;
            }
        }

        // NIP-16 event treatment
        let treatment = event_treatment(event.kind);

        if treatment == EventTreatment::Ephemeral {
            Self::send_ok(ws, &event.id, true, "");
            self.broadcast_event(&event).await;
            return;
        }

        // Save to D1
        if self.save_event(&event, treatment).await {
            Self::send_ok(ws, &event.id, true, "");
            self.broadcast_event(&event).await;

            // Activity tracking: increment posts_created and update last_active
            // for content-producing event kinds (kind-1 text, kind-42 channel msg,
            // kind-40 channel create, kind-7 reaction, kind-1984 report).
            if matches!(event.kind, 1 | 7 | 40 | 42 | KIND_REPORT_NIP56) {
                trust::increment_posts_created(&event.pubkey, &self.env).await;
            }
            trust::update_last_active(&event.pubkey, &self.env).await;

            // After activity update, check for trust promotion
            let _ = trust::check_promotion(&event.pubkey, &self.env).await;

            // NIP-09: Process deletion events -- remove targeted events by same author
            if event.kind == 5 {
                self.process_deletion(&event).await;
            }

            // NIP-56: Process report events -- insert into reports table and check auto-hide
            if event.kind == KIND_REPORT_NIP56 {
                self.process_report(&event).await;
            }

            // WI-2 + P0-4(a): mirror moderation-action Nostr events (kind 30910
            // ban, 30911 mute, 30915 unban, 30916 unmute) into the local
            // `moderation_actions` table so the ingress gate can reject content
            // from muted/banned authors AND so a lifted ban/mute stops being
            // enforced. Only respected when the signer is an admin on this relay.
            if matches!(event.kind, KIND_BAN | KIND_MUTE | KIND_UNBAN | KIND_UNMUTE) && is_admin {
                self.mirror_moderation_action(&event).await;
                if let Some(target) = filter::tag_value(&event, "p") {
                    self.mod_cache.invalidate(&target);
                }
            }

            // Agent Control Surface: project ActionRequest events (31402)
            // into the broker_cases table for D1-queryable governance inbox.
            if event.kind == governance::KIND_ACTION_REQUEST {
                self.project_action_request(&event).await;
            }

            // Agent Control Surface: project ActionResponse events (31403)
            // into broker_decisions and update the broker_cases state.
            if event.kind == governance::KIND_ACTION_RESPONSE {
                self.project_action_response(&event).await;
            }
        } else {
            Self::send_ok(ws, &event.id, false, "error: failed to save event");
        }
    }

    fn validate_event(event: &NostrEvent) -> bool {
        if event.id.len() != 64 || event.pubkey.len() != 64 || event.sig.len() != 128 {
            return false;
        }

        let is_reg = event.kind == 0 || event.kind == 9024;
        let max_content = if is_reg {
            MAX_REGISTRATION_CONTENT_SIZE
        } else {
            MAX_CONTENT_SIZE
        };
        if event.content.len() > max_content {
            return false;
        }

        if event.tags.len() > MAX_TAG_COUNT {
            return false;
        }
        for tag in &event.tags {
            for v in tag {
                if v.len() > MAX_TAG_VALUE_SIZE {
                    return false;
                }
            }
        }

        let now = auth::js_now_secs();
        let drift = now.abs_diff(event.created_at);
        if drift > MAX_TIMESTAMP_DRIFT {
            return false;
        }

        true
    }
}

// ---------------------------------------------------------------------------
// NIP-01: REQ / CLOSE handling
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    pub(crate) async fn handle_req(
        &self,
        session_id: u64,
        sub_id: &str,
        filters: Vec<NostrFilter>,
    ) {
        let ws = {
            let sessions = self.sessions.borrow();
            match sessions.get(&session_id) {
                Some(s) => s.ws.clone(),
                None => return,
            }
        };

        // Check subscription limit
        {
            let sessions = self.sessions.borrow();
            if let Some(session) = sessions.get(&session_id) {
                if session.subscriptions.len() >= MAX_SUBSCRIPTIONS {
                    Self::send_notice(&ws, "too many subscriptions");
                    return;
                }
            }
        }

        // Store subscription in memory
        {
            let mut sessions = self.sessions.borrow_mut();
            if let Some(session) = sessions.get_mut(&session_id) {
                session
                    .subscriptions
                    .insert(sub_id.to_string(), filters.clone());
            }
        }

        // Persist subscriptions to DO storage so they survive hibernation
        self.save_subscriptions(session_id).await;

        // Determine the requesting session's pubkey and zone access for filtering
        let session_pubkey = {
            let sessions = self.sessions.borrow();
            sessions
                .get(&session_id)
                .and_then(|s| s.authed_pubkey.clone())
        };

        // NIP-59: kind-1059 (Sealed DM) read gate + mandatory #p rewrite. Shared
        // with the COUNT path so both reject unauthenticated kind-1059 reads and
        // bind results to the authed recipient identically.
        let filters = match Self::gate_kind_1059_filters(filters, &session_pubkey) {
            Some(f) => f,
            None => {
                Self::send_notice(
                    &ws,
                    "auth-required: must authenticate to receive kind-1059 DMs",
                );
                return;
            }
        };

        // Query D1 for matching events
        let events = self.query_events(&filters).await;

        // Resolve the viewer's effective read scope once (ADR-099 device→owner
        // rebinding, admin status, calendar cohorts), then apply the SHARED
        // per-event zone/cohort/NIP-52-calendar gate (`authorize_event`). The
        // exact same gate runs on the COUNT and live-broadcast paths, so the
        // three read paths can never diverge on what a viewer may read.
        let zones = ZoneConfig::load(&self.env);
        let ctx = self.resolve_viewer_context(session_pubkey.clone()).await;

        // Count events actually DELIVERED to the reader this REQ (post-gate). An
        // event withheld by zone access was never read, so we tally survivors and
        // batch a single `posts_read` increment at EOSE for the TL0→TL1 promotion.
        let mut delivered: i32 = 0;
        for event in &events {
            match self.authorize_event(event, &ctx, &zones).await {
                ReadDecision::Deliver => {
                    Self::send_event(&ws, sub_id, event);
                    delivered += 1;
                }
                ReadDecision::DeliverAs(out) => {
                    Self::send_event(&ws, sub_id, &out);
                    delivered += 1;
                }
                ReadDecision::Withhold => {}
            }
        }
        Self::send_eose(&ws, sub_id);

        // O1: count this REQ's reads toward TL0→TL1 promotion. Gate on an
        // authenticated session and at least one delivered event; the
        // `increment_posts_read_by` UPDATE is whitelist-scoped, so a
        // non-member authed pubkey is a harmless no-op. We charge the read to
        // the literal session pubkey (the identity that subscribed), not the
        // device→owner `access_pubkey` rebinding used for zone reads. After the
        // batched increment, run the same `check_promotion` the EVENT path uses
        // so a reader can cross the threshold without needing to also write.
        if delivered > 0 {
            if let Some(pk) = &session_pubkey {
                trust::increment_posts_read_by(pk, delivered, &self.env).await;
                // ADR-102: a delivered read is activity. Stamp `last_active_at`
                // so a read-only member's inactivity clock resets, mirroring
                // the EVENT path's `update_last_active`. Without this, an active
                // lurker who never writes would drift past the ~6-month
                // inactivity gate and be demoted by the cron sweep despite
                // reading daily. The UPDATE is whitelist-scoped, so a non-member
                // authed pubkey is a harmless no-op.
                trust::update_last_active(pk, &self.env).await;
                let _ = trust::check_promotion(pk, &self.env).await;
            }
        }
    }

    /// Phase C: project a single NIP-52 calendar event for one viewer.
    ///
    /// The projector is the COMPLETE access decision — there is no upstream zone
    /// read-gate for calendar kinds. A live probe proved a gate-then-project
    /// ordering wrong: the gate omitted any event in a zone the viewer was not a
    /// member of, so the FreeBusy / cross-zone-Full tiers never ran. The pure
    /// projector applies the operator-approved matrix end to end
    /// (full / free-busy-redacted / omit), deny-by-default for unknown zones.
    ///
    /// For RSVPs (kind 31925) the target event's zone AND venue are resolved from
    /// the STORED referenced event (never from an author-mirrored tag on the RSVP,
    /// which is spoofable with the gate removed). The RSVP is served only when the
    /// viewer's tier for the target is `Full` — an RSVP leaks participants, so a
    /// free/busy tier omits it. If the target cannot be resolved, the RSVP is
    /// served only to admin or the RSVP's owner (deny-by-default).
    async fn project_calendar_for_viewer(
        &self,
        event: &NostrEvent,
        session_pubkey: &Option<String>,
        viewer_cohorts: &[String],
        viewer_is_admin: bool,
        _zones: &ZoneConfig,
    ) -> Option<NostrEvent> {
        let is_owner = session_pubkey
            .as_deref()
            .map(|pk| pk == event.pubkey)
            .unwrap_or(false);

        // RSVPs: the TARGET event's tier decides. Resolve zone + venue from the
        // stored referenced event (spoof-resistant). Serve only on a Full tier;
        // a FreeBusy/Omit tier would leak the participant list.
        if event.kind == KIND_CALENDAR_RSVP {
            let Some((zone, venue)) = self.resolve_rsvp_target(event).await else {
                // Target unresolvable: deny by default, admin/owner only.
                return if viewer_is_admin || is_owner {
                    Some(event.clone())
                } else {
                    None
                };
            };
            let tier = calendar_projection::project_tier(
                viewer_cohorts,
                &zone,
                venue.as_deref(),
                is_owner,
                viewer_is_admin,
            );
            return match tier {
                calendar_projection::Projection::Full => Some(event.clone()),
                // FreeBusy or Omit ⇒ withhold the RSVP entirely (it would leak
                // participation in an event the viewer only sees as a busy block,
                // or not at all).
                _ => None,
            };
        }

        // Calendar events (31922/31923): the projector decides everything.
        calendar_projection::project_calendar_event(
            viewer_cohorts,
            event,
            is_owner,
            viewer_is_admin,
        )
    }

    /// Resolve the owning zone slug AND venue of a calendar RSVP's TARGET event by
    /// reading the referenced event's stored `zone`/`venue` tags from D1. The RSVP
    /// references its target via an `e` (event id) tag.
    ///
    /// SECURITY: the target's zone/venue are read from the STORED event, never
    /// from any tag the RSVP author mirrored onto the RSVP itself — with the read
    /// gate removed, an author-mirrored `zone=public` on an RSVP targeting a
    /// family event would otherwise leak that event. Returns `None` when the
    /// target cannot be resolved.
    async fn resolve_rsvp_target(&self, rsvp: &NostrEvent) -> Option<(String, Option<String>)> {
        let db = self.env.d1("DB").ok()?;

        #[derive(serde::Deserialize)]
        struct TagsRow {
            tags: String,
        }

        // Look up the referenced calendar event and read its zone + venue tags.
        let target_id = filter::tag_value(rsvp, "e")?;
        let stmt = db.prepare("SELECT tags FROM events WHERE id = ?1 LIMIT 1");
        let row = stmt
            .bind(&[JsValue::from_str(&target_id)])
            .ok()?
            .first::<TagsRow>(None)
            .await
            .ok()??;
        let tags: Vec<Vec<String>> = serde_json::from_str(&row.tags).ok()?;
        let zone = tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == nostr_bbs_core::ZONE_TAG)
            .map(|t| t[1].clone())?;
        let venue = tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == nostr_bbs_core::VENUE_TAG)
            .map(|t| t[1].clone());
        Some((zone, venue))
    }

    pub(crate) async fn handle_close(&self, session_id: u64, sub_id: &str) {
        {
            let mut sessions = self.sessions.borrow_mut();
            if let Some(session) = sessions.get_mut(&session_id) {
                session.subscriptions.remove(sub_id);
            }
        }

        // Persist updated subscriptions to DO storage
        self.save_subscriptions(session_id).await;
    }
}

// ---------------------------------------------------------------------------
// NIP-42: AUTH challenge/response
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Handle an AUTH response from a client (kind 22242 event).
    pub(crate) async fn handle_auth(&self, session_id: u64, ws: &WebSocket, event: NostrEvent) {
        // Must be kind 22242
        if event.kind != 22242 {
            Self::send_ok(ws, &event.id, false, "invalid: expected kind 22242");
            return;
        }

        // Verify signature
        if nostr_bbs_core::verify_event_strict(&event).is_err() {
            Self::send_ok(
                ws,
                &event.id,
                false,
                "invalid: signature verification failed",
            );
            return;
        }

        // Verify challenge tag matches session challenge
        let challenge_tag = filter::tag_value(&event, "challenge");
        let expected_challenge = {
            let sessions = self.sessions.borrow();
            sessions.get(&session_id).map(|s| s.challenge.clone())
        };

        match (challenge_tag, expected_challenge) {
            (Some(c), Some(expected)) if c == expected => {}
            _ => {
                Self::send_ok(ws, &event.id, false, "invalid: challenge mismatch");
                return;
            }
        }

        // Timestamp must be within 10 minutes
        let now = auth::js_now_secs();
        if now.abs_diff(event.created_at) > 600 {
            Self::send_ok(ws, &event.id, false, "invalid: auth event too old");
            return;
        }

        // Mark session as authenticated
        {
            let mut sessions = self.sessions.borrow_mut();
            if let Some(session) = sessions.get_mut(&session_id) {
                session.authed_pubkey = Some(event.pubkey.clone());
            }
        }

        // Persist auth state to DO storage so it survives hibernation
        self.save_auth(session_id, &event.pubkey).await;

        Self::send_ok(ws, &event.id, true, "");
    }
}

// ---------------------------------------------------------------------------
// Shared read-authorization (REQ / COUNT / live broadcast)
// ---------------------------------------------------------------------------

/// Resolved read scope for one viewer (session). Computed once per REQ/COUNT,
/// or once per candidate session on the broadcast path, then reused for every
/// event so the three read paths apply identical zone/cohort gating.
pub(crate) struct ViewerContext {
    pub session_pubkey: Option<String>,
    pub access_pubkey: Option<String>,
    pub is_admin: bool,
    pub viewer_cohorts: Vec<String>,
    pub viewer_is_admin: bool,
}

/// Per-event read decision shared by every read path.
pub(crate) enum ReadDecision {
    /// Deliver the event verbatim.
    Deliver,
    /// Deliver this calendar-projected / redacted replacement instead.
    DeliverAs(NostrEvent),
    /// Withhold the event from this viewer (zone/cohort/projection denial).
    Withhold,
}

impl NostrRelayDO {
    /// NIP-59 kind-1059 (Sealed DM) read gate + mandatory `#p` rewrite.
    ///
    /// If any filter requests kind-1059, the session must be authenticated; each
    /// such filter is rewritten to require `#p == authed pubkey`, preventing a
    /// client from reading another user's sealed DMs. Returns `None` when the
    /// request must be rejected (kind-1059 requested by an unauthenticated
    /// session). Shared by REQ and COUNT so neither can leak DMs.
    fn gate_kind_1059_filters(
        filters: Vec<NostrFilter>,
        session_pubkey: &Option<String>,
    ) -> Option<Vec<NostrFilter>> {
        let needs_kind_1059 = filters
            .iter()
            .any(|f| f.kinds.as_ref().is_some_and(|k| k.contains(&1059)));
        if !needs_kind_1059 {
            return Some(filters);
        }
        session_pubkey.as_ref().map(|authed_pk| {
            filters
                .into_iter()
                .map(|mut f| {
                    if f.kinds.as_ref().is_some_and(|k| k.contains(&1059)) {
                        f.extra
                            .insert("#p".to_string(), serde_json::json!([authed_pk]));
                    }
                    f
                })
                .collect::<Vec<_>>()
        })
    }

    /// Resolve a viewer's effective read scope (ADR-099 device→owner rebinding,
    /// admin status, calendar cohorts). The kind-1059 DM `#p` filter is bound to
    /// the literal `session_pubkey` upstream and deliberately NOT rebound here —
    /// only cohort/zone READ scope is rebound to the owner.
    pub(crate) async fn resolve_viewer_context(
        &self,
        session_pubkey: Option<String>,
    ) -> ViewerContext {
        let access_pubkey: Option<String> = match &session_pubkey {
            Some(pk) => Some(self.effective_pubkey(pk).await),
            None => None,
        };
        let is_admin = match &access_pubkey {
            Some(pk) => self.admin_cache.is_admin(pk, &self.env).await,
            None => false,
        };
        let (viewer_cohorts, cohort_admin) = match &access_pubkey {
            Some(pk) => trust::get_viewer_cohorts(pk, &self.env).await,
            None => (Vec::new(), false),
        };
        let viewer_is_admin = is_admin || cohort_admin;
        ViewerContext {
            session_pubkey,
            access_pubkey,
            is_admin,
            viewer_cohorts,
            viewer_is_admin,
        }
    }

    /// Apply the zone / cohort / NIP-52-calendar read gate to a single event for
    /// one resolved viewer. THE single source of truth for read authorization,
    /// shared by REQ, COUNT, and live broadcast.
    ///
    /// Decision matrix for a NON-member (non-admin), per zone visibility:
    ///   Public : defs + content served to everyone (incl. unauth).
    ///   Locked : defs served (tile renders) but content withheld.
    ///   Hidden : defs AND content omitted.
    /// Members (cohort match) and admins always receive both. NIP-52 calendar
    /// kinds are decided entirely by `project_calendar_for_viewer` (the per-tier
    /// projection IS the access decision), deny-by-default for unknown zones.
    pub(crate) async fn authorize_event(
        &self,
        event: &NostrEvent,
        ctx: &ViewerContext,
        zones: &ZoneConfig,
    ) -> ReadDecision {
        if calendar_projection::is_projected_calendar_kind(event.kind) {
            return match self
                .project_calendar_for_viewer(
                    event,
                    &ctx.session_pubkey,
                    &ctx.viewer_cohorts,
                    ctx.viewer_is_admin,
                    zones,
                )
                .await
            {
                Some(out) => ReadDecision::DeliverAs(out),
                None => ReadDecision::Withhold,
            };
        }

        // Zone-scoped channel kinds: kind-40 defs (channel id == event id),
        // kind-42 content (channel id == `e` tag).
        let channel_id: Option<String> = match event.kind {
            40 => Some(event.id.clone()),
            42 => filter::tag_value(event, "e"),
            _ => None,
        };

        if let Some(cid) = channel_id {
            let zone = trust::get_channel_zone(&cid, &self.env)
                .await
                .unwrap_or_else(|| "home".to_string());

            if !ctx.is_admin {
                let is_member = match &ctx.access_pubkey {
                    Some(pk) => trust::has_zone_access(pk, &zone, &self.env).await,
                    None => zones.is_public_read(&zone),
                };
                if !is_member {
                    if event.kind == 40 {
                        // Channel definition: served only if the zone is not
                        // Hidden (Locked/Public tiles render).
                        if !zones.defs_visible_to_nonmember(&zone) {
                            return ReadDecision::Withhold;
                        }
                    } else {
                        // Channel content (kind-42): withheld from non-members of
                        // Locked/Hidden zones.
                        return ReadDecision::Withhold;
                    }
                }
            }
        }

        ReadDecision::Deliver
    }
}

// ---------------------------------------------------------------------------
// NIP-45: COUNT
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Handle a COUNT request: return the number of matching events the session
    /// is AUTHORIZED to read.
    ///
    /// Applies the same read authorization as REQ (kind-1059 auth gate + `#p`
    /// rewrite, then the per-event zone/cohort/calendar gate). Without this,
    /// COUNT is an existence/count oracle that leaks how many sealed DMs a pubkey
    /// has received and message counts for Locked/Hidden zones and gated calendar
    /// events — all of which REQ correctly withholds.
    pub(crate) async fn handle_count(
        &self,
        session_id: u64,
        ws: &WebSocket,
        sub_id: &str,
        filters: Vec<NostrFilter>,
    ) {
        let session_pubkey = {
            let sessions = self.sessions.borrow();
            sessions
                .get(&session_id)
                .and_then(|s| s.authed_pubkey.clone())
        };

        // kind-1059 gate identical to REQ; deny-by-default → count 0 on reject.
        let filters = match Self::gate_kind_1059_filters(filters, &session_pubkey) {
            Some(f) => f,
            None => {
                Self::send_count(ws, sub_id, 0);
                return;
            }
        };

        let events = self.query_events(&filters).await;
        let zones = ZoneConfig::load(&self.env);
        let ctx = self.resolve_viewer_context(session_pubkey).await;

        let mut count: u64 = 0;
        for event in &events {
            match self.authorize_event(event, &ctx, &zones).await {
                ReadDecision::Deliver | ReadDecision::DeliverAs(_) => count += 1,
                ReadDecision::Withhold => {}
            }
        }
        Self::send_count(ws, sub_id, count);
    }
}

// ---------------------------------------------------------------------------
// NIP-09: Deletion processing
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Process a kind-5 deletion event: delete targeted events by the same author.
    pub(crate) async fn process_deletion(&self, deletion_event: &NostrEvent) {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return,
        };

        // Collect "e" tags (direct event ID targets)
        let target_ids: Vec<&str> = deletion_event
            .tags
            .iter()
            .filter(|t| t.len() >= 2 && t[0] == "e")
            .map(|t| t[1].as_str())
            .collect();

        // Delete events owned by the same pubkey
        for target_id in &target_ids {
            let stmt = db.prepare("DELETE FROM events WHERE id = ?1 AND pubkey = ?2");
            let _ = match stmt.bind(&[
                JsValue::from_str(target_id),
                JsValue::from_str(&deletion_event.pubkey),
            ]) {
                Ok(s) => s.run().await,
                Err(_) => continue,
            };
        }

        // Collect "a" tags (parameterized replaceable targets: "kind:pubkey:d-tag")
        let a_targets: Vec<&str> = deletion_event
            .tags
            .iter()
            .filter(|t| t.len() >= 2 && t[0] == "a")
            .map(|t| t[1].as_str())
            .collect();

        for a_ref in &a_targets {
            let parts: Vec<&str> = a_ref.split(':').collect();
            if parts.len() < 3 {
                continue;
            }
            let kind: f64 = match parts[0].parse() {
                Ok(k) => k,
                Err(_) => continue,
            };
            let pubkey = parts[1];
            let d_tag = parts[2];

            // Only allow deletion of own events
            if pubkey != deletion_event.pubkey {
                continue;
            }

            let stmt =
                db.prepare("DELETE FROM events WHERE kind = ?1 AND pubkey = ?2 AND d_tag = ?3");
            let _ = match stmt.bind(&[
                JsValue::from_f64(kind),
                JsValue::from_str(pubkey),
                JsValue::from_str(d_tag),
            ]) {
                Ok(s) => s.run().await,
                Err(_) => continue,
            };
        }
    }
}

// ---------------------------------------------------------------------------
// Trust / zone helper methods
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Check whether a pubkey is the creator of a channel (kind-40 event).
    pub(crate) async fn is_channel_creator(&self, pubkey: &str, channel_id: &str) -> bool {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return false,
        };

        #[derive(serde::Deserialize)]
        struct ChannelCreatorRow {
            pubkey: String,
        }

        let stmt = db.prepare("SELECT pubkey FROM events WHERE id = ?1 AND kind = 40 LIMIT 1");
        match stmt.bind(&[JsValue::from_str(channel_id)]) {
            Ok(s) => match s.first::<ChannelCreatorRow>(None).await {
                Ok(Some(row)) => row.pubkey == pubkey,
                _ => false,
            },
            Err(_) => false,
        }
    }

    /// ADR-099: whether device-key honouring is enabled. Reads the
    /// `DEVICE_KEYS_ENABLED` Worker var; only the exact string `"true"` enables
    /// the feature. Absent/empty/any-other value ⇒ disabled (default off).
    pub(crate) fn device_keys_enabled(&self) -> bool {
        match self.env.var("DEVICE_KEYS_ENABLED") {
            Ok(val) => val.to_string() == "true",
            Err(_) => false,
        }
    }

    /// ADR-099 (read-only here; the auth-worker owns writes): resolve the OWNER
    /// account for a registered, non-revoked device key.
    ///
    /// Returns `Some(owner_pubkey)` for a `device_keys` row whose `revoked = 0`,
    /// else `None`. Fail-safe: a missing `device_keys` table (not provisioned
    /// yet) or any D1 error yields `None` — a device key then resolves to no
    /// owner and is treated as an ordinary unknown pubkey.
    pub(crate) async fn device_owner(&self, pubkey: &str) -> Option<String> {
        let db = self.env.d1("DB").ok()?;

        #[derive(serde::Deserialize)]
        struct OwnerRow {
            owner_pubkey: String,
        }

        let stmt = db.prepare(
            "SELECT owner_pubkey FROM device_keys WHERE device_pubkey = ?1 AND revoked = 0 LIMIT 1",
        );
        // A missing table surfaces as a prepare/bind/exec error; `.ok()?` maps it
        // to `None` (fail-safe), so the relay behaves as if no device exists.
        let bound = stmt.bind(&[JsValue::from_str(pubkey)]).ok()?;
        match bound.first::<OwnerRow>(None).await {
            Ok(Some(row)) => Some(row.owner_pubkey),
            _ => None,
        }
    }

    /// ADR-099: resolve the EFFECTIVE principal for `pubkey`, applied to read
    /// scope (cohorts/zone access) and the write-gate allowlist check.
    ///
    /// Gated by `DEVICE_KEYS_ENABLED`. When off, this is a pure identity
    /// passthrough (no D1 read at all) — guaranteeing zero behaviour change. When
    /// on, a registered non-revoked device key resolves to its OWNER; otherwise
    /// the input pubkey is returned unchanged.
    pub(crate) async fn effective_pubkey(&self, pubkey: &str) -> String {
        if !self.device_keys_enabled() {
            return pubkey.to_string();
        }
        let owner = self.device_owner(pubkey).await;
        effective_principal(pubkey, owner.as_deref(), true)
    }

    pub(crate) async fn is_registered_agent(&self, pubkey: &str) -> bool {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return false,
        };

        #[derive(serde::Deserialize)]
        struct AgentActiveRow {
            active: u32,
        }

        let stmt = db.prepare("SELECT active FROM agent_registry WHERE pubkey = ?1 LIMIT 1");
        match stmt.bind(&[JsValue::from_str(pubkey)]) {
            Ok(s) => match s.first::<AgentActiveRow>(None).await {
                Ok(Some(row)) => row.active == 1,
                _ => false,
            },
            Err(_) => false,
        }
    }

    pub(crate) async fn project_action_request(&self, event: &NostrEvent) {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return,
        };

        let d_tag = governance::extract_d_tag(&event.tags).unwrap_or(&event.id);
        let category =
            governance::extract_tag(&event.tags, "category").unwrap_or("manual_submission");
        let subject_kind = governance::extract_tag(&event.tags, "subject-kind").unwrap_or("opaque");
        let subject_id = governance::extract_tag(&event.tags, "subject-id").unwrap_or("");
        let title = governance::extract_tag(&event.tags, "title").unwrap_or("Untitled");
        let priority: u32 = governance::extract_tag(&event.tags, "priority")
            .and_then(|p| p.parse().ok())
            .unwrap_or(50);

        let stmt = db.prepare(
            "INSERT OR REPLACE INTO broker_cases \
             (id, category, subject_kind, subject_id, title, summary, state, priority, \
              created_by, nostr_event_id, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'open', ?7, ?8, ?9, ?10, ?10)",
        );
        if let Ok(bound) = stmt.bind(&[
            JsValue::from_str(d_tag),
            JsValue::from_str(category),
            JsValue::from_str(subject_kind),
            JsValue::from_str(subject_id),
            JsValue::from_str(title),
            JsValue::from_str(&event.content),
            JsValue::from_f64(priority as f64),
            JsValue::from_str(&event.pubkey),
            JsValue::from_str(&event.id),
            JsValue::from_f64(event.created_at as f64),
        ]) {
            let _ = bound.run().await;
        }
    }

    pub(crate) async fn project_action_response(&self, event: &NostrEvent) {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return,
        };

        let case_id = governance::extract_d_tag(&event.tags).unwrap_or("");
        if case_id.is_empty() {
            return;
        }

        let action = serde_json::from_str::<governance::ActionResponse>(&event.content)
            .map(|r| r.action)
            .unwrap_or_else(|_| "unknown".to_string());

        let reasoning = serde_json::from_str::<governance::ActionResponse>(&event.content)
            .map(|r| r.reasoning)
            .unwrap_or_default();

        let decision_id = format!("dec-{}", &event.id[..16.min(event.id.len())]);

        let stmt = db.prepare(
            "INSERT OR IGNORE INTO broker_decisions \
             (decision_id, case_id, outcome, broker_pubkey, reasoning, decided_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        );
        if let Ok(bound) = stmt.bind(&[
            JsValue::from_str(&decision_id),
            JsValue::from_str(case_id),
            JsValue::from_str(&action),
            JsValue::from_str(&event.pubkey),
            JsValue::from_str(&reasoning),
            JsValue::from_f64(event.created_at as f64),
        ]) {
            let _ = bound.run().await;
        }

        let new_state = match action.as_str() {
            "approve" => "resolved",
            "reject" => "rejected",
            _ => "under_review",
        };
        let update_stmt = db.prepare(
            "UPDATE broker_cases SET state = ?1, assigned_to = ?2, updated_at = ?3 WHERE id = ?4",
        );
        if let Ok(bound) = update_stmt.bind(&[
            JsValue::from_str(new_state),
            JsValue::from_str(&event.pubkey),
            JsValue::from_f64(event.created_at as f64),
            JsValue::from_str(case_id),
        ]) {
            let _ = bound.run().await;
        }
    }

    /// Check whether a kind-5 deletion event targets events by other authors.
    ///
    /// Returns `true` if any `e` tag references an event not authored by the
    /// deletion event's pubkey.
    pub(crate) async fn deletion_targets_others(&self, event: &NostrEvent) -> bool {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return false,
        };

        #[derive(serde::Deserialize)]
        struct EventPubkeyRow {
            pubkey: String,
        }

        let target_ids: Vec<&str> = event
            .tags
            .iter()
            .filter(|t| t.len() >= 2 && t[0] == "e")
            .map(|t| t[1].as_str())
            .collect();

        for target_id in &target_ids {
            let stmt = db.prepare("SELECT pubkey FROM events WHERE id = ?1 LIMIT 1");
            match stmt.bind(&[JsValue::from_str(target_id)]) {
                Ok(s) => {
                    if let Ok(Some(row)) = s.first::<EventPubkeyRow>(None).await {
                        if row.pubkey != event.pubkey {
                            return true;
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        false
    }
}

// ---------------------------------------------------------------------------
// F11 (PRD-010): Federated kind allowlist helpers
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Check whether the event's pubkey belongs to a known mesh peer.
    ///
    /// Returns `true` when:
    ///   1. `MESH_MODE` is set to a value other than `"standalone"` (or empty), AND
    ///   2. `MESH_ALLOWED_REMOTE_DIDS` contains the pubkey.
    ///
    /// When `MESH_MODE` is `"standalone"` (the default) or the env var is absent,
    /// this always returns `false` — all events are treated as local.
    pub(crate) fn is_mesh_peer(&self, pubkey: &str) -> bool {
        let mesh_mode = match self.env.var("MESH_MODE") {
            Ok(val) => val.to_string(),
            Err(_) => return false,
        };

        if mesh_mode.is_empty() || mesh_mode == "standalone" {
            return false;
        }

        let allowed_dids = match self.env.var("MESH_ALLOWED_REMOTE_DIDS") {
            Ok(val) => val.to_string(),
            Err(_) => return false,
        };

        if allowed_dids.is_empty() {
            return false;
        }

        allowed_dids.split(',').any(|did| did.trim() == pubkey)
    }

    /// Check whether a given event kind is in the `MESH_FEDERATED_KINDS`
    /// allowlist.
    ///
    /// Reads `MESH_FEDERATED_KINDS` from the Worker env (comma-separated list
    /// of u64 values). When the env var is absent or empty, returns `false`
    /// (fail-closed: no kinds allowed from peers by default).
    pub(crate) fn is_federated_kind_allowed(&self, kind: u64) -> bool {
        let kinds_str = match self.env.var("MESH_FEDERATED_KINDS") {
            Ok(val) => val.to_string(),
            Err(_) => return false,
        };

        if kinds_str.is_empty() {
            return false;
        }

        kinds_str
            .split(',')
            .filter_map(|s| s.trim().parse::<u64>().ok())
            .any(|k| k == kind)
    }
}

// ---------------------------------------------------------------------------
// NIP-56: Report processing
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Process a kind-1984 report event.
    ///
    /// Extracts the `e` tag (reported event), `p` tag (reported pubkey), and
    /// reason from the `report` tag or content. Inserts into the `reports`
    /// table and triggers auto-hide if the threshold is reached.
    pub(crate) async fn process_report(&self, report_event: &NostrEvent) {
        // Extract the reported event ID from the `e` tag
        let reported_event_id = match filter::tag_value(report_event, "e") {
            Some(id) => id,
            None => return, // Invalid report: no `e` tag
        };

        // Extract the reported pubkey from the `p` tag
        let reported_pubkey = match filter::tag_value(report_event, "p") {
            Some(pk) => pk,
            None => return, // Invalid report: no `p` tag
        };

        // Extract reason from `report` tag first, fall back to content
        let reason = filter::tag_value(report_event, "report").unwrap_or_else(|| {
            if report_event.content.is_empty() {
                "other".to_string()
            } else {
                report_event.content.clone()
            }
        });

        // Separate structured reason from free-text
        let (reason_code, reason_text) = match reason.as_str() {
            r @ ("nudity" | "profanity" | "illegal" | "spam" | "impersonation") => {
                // Structured reason; content may hold additional free-text
                let text = if report_event.content.is_empty() {
                    None
                } else {
                    Some(report_event.content.as_str())
                };
                (r.to_string(), text)
            }
            _ => {
                // Free-text reason
                ("other".to_string(), Some(reason.as_str()))
            }
        };

        let _ = moderation::insert_report(
            &self.env,
            &report_event.id,
            &report_event.pubkey,
            &reported_event_id,
            &reported_pubkey,
            &reason_code,
            reason_text,
        )
        .await;
    }

    /// WI-2 + P0-4(a): mirror a kind-30910 (ban), 30911 (mute), 30915 (unban),
    /// or 30916 (unmute) event into the local `moderation_actions` table.
    /// Idempotent via `event_id` dedup -- re-receiving the same event is a
    /// no-op. Missing target pubkey (no `p` tag) silently drops the mirror.
    /// Unban/unmute rows are written as their own action rows (preserving
    /// signer + target + created_at) so `load_state` can apply latest-wins and
    /// cancel a prior ban/mute.
    pub(crate) async fn mirror_moderation_action(&self, event: &NostrEvent) {
        let action = match event.kind {
            KIND_BAN => "ban",
            KIND_MUTE => "mute",
            KIND_UNBAN => "unban",
            KIND_UNMUTE => "unmute",
            _ => return,
        };

        let Some(target) = filter::tag_value(event, "p") else {
            return;
        };

        // expires_at: mutes may carry a NIP-40 style `expiration` tag. Bans,
        // unbans and unmutes never expire; we persist NULL.
        let expires_at: Option<i64> = if action == "mute" {
            filter::tag_value(event, "expiration").and_then(|s| s.parse::<i64>().ok())
        } else {
            None
        };

        let reason: Option<&str> = if event.content.is_empty() {
            None
        } else {
            Some(event.content.as_str())
        };

        let Ok(db) = self.env.d1("DB") else {
            return;
        };

        let row_id = format!("mirror:{}", event.id);
        // P0-4(a): persist the event's signed `created_at` (not receipt time) so
        // `load_state` latest-wins ordering between ban/unban (and mute/unmute)
        // follows the admin's intended sequence even under out-of-order delivery.
        let created_at = event.created_at;

        let sql = "INSERT INTO moderation_actions \
             (id, action, target_pubkey, performed_by, reason, expires_at, event_id, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
             ON CONFLICT (id) DO NOTHING";
        let Ok(stmt) = db.prepare(sql).bind(&[
            JsValue::from_str(&row_id),
            JsValue::from_str(action),
            JsValue::from_str(&target),
            JsValue::from_str(&event.pubkey),
            reason.map(JsValue::from_str).unwrap_or(JsValue::NULL),
            expires_at
                .map(|v| JsValue::from_f64(v as f64))
                .unwrap_or(JsValue::NULL),
            JsValue::from_str(&event.id),
            JsValue::from_f64(created_at as f64),
        ]) else {
            return;
        };
        let _ = stmt.run().await;
    }
}

// ---------------------------------------------------------------------------
// Phase C (write side): data-tier write validation tests
// ---------------------------------------------------------------------------
//
// The EVENT (write) gate for calendar kinds mirrors the READ projection. These
// tests drive the same decision the handler executes: the AUTHOR's projection
// tier for an RSVP's TARGET (resolved zone/venue from D1) feeds `project_tier`,
// then `rsvp_write_permitted` accepts only `Full`; a zone-tagged calendar event
// feeds `calendar_write_permitted` with the author's resolved write access. The
// D1 lookups themselves are exercised by integration tests; here we pin the
// pure decision boundary that those lookups feed into.
#[cfg(test)]
mod count_auth_tests {
    //! Read-authorization gate shared by REQ and COUNT. COUNT previously called
    //! `query_events` directly with no gating, leaking existence/counts of sealed
    //! DMs and zone-private content; it now routes through this same gate.
    use super::*;

    fn filter(json: serde_json::Value) -> NostrFilter {
        serde_json::from_value(json).expect("valid filter")
    }

    #[test]
    fn non_dm_filter_passes_through_unauthenticated() {
        let filters = vec![filter(serde_json::json!({ "kinds": [1] }))];
        assert!(NostrRelayDO::gate_kind_1059_filters(filters, &None).is_some());
    }

    #[test]
    fn kind_1059_rejected_when_unauthenticated() {
        let filters = vec![filter(serde_json::json!({ "kinds": [1059] }))];
        // Deny-by-default: an unauthenticated COUNT/REQ for sealed DMs is rejected.
        assert!(NostrRelayDO::gate_kind_1059_filters(filters, &None).is_none());
    }

    #[test]
    fn kind_1059_injects_p_tag_for_authed_pubkey() {
        let pk = "a".repeat(64);
        let filters = vec![filter(serde_json::json!({ "kinds": [1059] }))];
        let out = NostrRelayDO::gate_kind_1059_filters(filters, &Some(pk.clone()))
            .expect("authed kind-1059 read allowed");
        assert_eq!(out[0].extra.get("#p"), Some(&serde_json::json!([pk])));
    }

    #[test]
    fn kind_1059_overrides_client_supplied_p_tag() {
        let pk = "a".repeat(64);
        let attacker_target = "b".repeat(64);
        let filters = vec![filter(
            serde_json::json!({ "kinds": [1059], "#p": [attacker_target] }),
        )];
        let out = NostrRelayDO::gate_kind_1059_filters(filters, &Some(pk.clone()))
            .expect("authed kind-1059 read allowed");
        // The #p constraint must be rebound to the authed pubkey so a client
        // cannot count/read another user's sealed DMs.
        assert_eq!(out[0].extra.get("#p"), Some(&serde_json::json!([pk])));
    }
}

#[cfg(test)]
mod write_gate_tests {
    use super::super::calendar_projection::{
        project_tier, Projection, COHORT_BUSINESS, COHORT_FAMILY, COHORT_FRIENDS, ZONE_BUSINESS,
        ZONE_FAMILY,
    };
    use super::*;

    fn cohorts(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// Helper: compute the author's RSVP write decision exactly as `handle_event`
    /// does — resolved target (zone, venue) + author cohorts → tier → permitted.
    fn rsvp_decision(
        author_cohorts: &[String],
        author_cohort_admin: bool,
        target_zone: &str,
        target_venue: Option<&str>,
    ) -> bool {
        let tier = project_tier(
            author_cohorts,
            target_zone,
            target_venue,
            false,
            author_cohort_admin,
        );
        rsvp_write_permitted(&tier)
    }

    // ---- RSVP write gate (kind 31925) --------------------------------------

    #[test]
    fn friends_author_rsvp_to_business_venue_target_rejected() {
        // EVIDENCE replay: a friends-cohort author RSVPs to a business-zone event
        // she only sees as free/busy (business@primary venue). Author tier =
        // FreeBusy ⇒ write rejected.
        assert!(
            !rsvp_decision(
                &cohorts(&[COHORT_FRIENDS]),
                false,
                ZONE_BUSINESS,
                Some("primary"),
            ),
            "friends author must not RSVP to a business target she only sees as free/busy"
        );
        // Off-site business target (no shared venue): friends tier = Omit ⇒ reject.
        assert!(!rsvp_decision(
            &cohorts(&[COHORT_FRIENDS]),
            false,
            ZONE_BUSINESS,
            None
        ));
    }

    #[test]
    fn family_author_rsvp_to_business_target_accepted() {
        // family tier is Full on every zone, including business ⇒ RSVP permitted.
        assert!(rsvp_decision(
            &cohorts(&[COHORT_FAMILY]),
            false,
            ZONE_BUSINESS,
            Some("primary"),
        ));
        assert!(rsvp_decision(
            &cohorts(&[COHORT_FAMILY]),
            false,
            ZONE_BUSINESS,
            None
        ));
    }

    #[test]
    fn owner_admin_author_rsvp_accepted() {
        // Admin author (cohort_admin flag) → project_tier short-circuits to Full,
        // regardless of target zone ⇒ permitted. (A non-cohort author flagged
        // admin in the handler bypasses this gate entirely; this asserts the tier
        // short-circuit for the cohort-admin path.)
        assert!(rsvp_decision(&[], true, ZONE_FAMILY, None));
        assert!(rsvp_decision(&[], true, ZONE_BUSINESS, Some("primary")));
    }

    #[test]
    fn business_author_rsvp_to_own_business_zone_accepted() {
        // A business author RSVPing to a business-zone target sees it Full ⇒ ok.
        assert!(rsvp_decision(
            &cohorts(&[COHORT_BUSINESS]),
            false,
            ZONE_BUSINESS,
            None
        ));
        // ...but a business author RSVPing to a FAMILY target sees Omit ⇒ reject.
        assert!(!rsvp_decision(
            &cohorts(&[COHORT_BUSINESS]),
            false,
            ZONE_FAMILY,
            None
        ));
    }

    #[test]
    fn rsvp_write_permitted_only_on_full_tier() {
        assert!(rsvp_write_permitted(&Projection::Full));
        assert!(!rsvp_write_permitted(&Projection::FreeBusy));
        assert!(!rsvp_write_permitted(&Projection::Omit));
    }

    // ---- Calendar event write gate (kind 31922/31923) ----------------------

    #[test]
    fn calendar_write_into_non_member_zone_rejected() {
        // Zone-tagged event, author lacks write access ⇒ rejected.
        assert!(!calendar_write_permitted(Some(ZONE_BUSINESS), false));
    }

    #[test]
    fn calendar_write_into_member_zone_accepted() {
        // Zone-tagged event, author holds write access ⇒ accepted.
        assert!(calendar_write_permitted(Some(ZONE_BUSINESS), true));
    }

    #[test]
    fn untagged_calendar_event_keeps_prior_behaviour() {
        // No zone tag → unscoped → permitted regardless of zone-write resolution.
        assert!(calendar_write_permitted(None, false));
        assert!(calendar_write_permitted(None, true));
    }

    // ---- NIP-59 gift-wrap (kind 1059) recipient routing --------------------
    //
    // The handler's recipient gate is `is_whitelisted(recipient)`, which needs a
    // `worker::Env` / D1 and so cannot run in isolation. These tests pin the PURE
    // decision the handler feeds into that lookup: `gift_wrap_recipient` resolves
    // the principal the membership check is applied to. `Some(pk)` ⇒ the gate runs
    // against `pk` (admitted iff whitelisted); `None` ⇒ fail-closed reject; for a
    // normal kind ⇒ `None`, so the author `is_whitelisted` branch runs as before.

    fn mk_event(kind: u64, tags: Vec<Vec<String>>) -> NostrEvent {
        NostrEvent {
            id: "00".repeat(32),
            pubkey: "ab".repeat(32),
            created_at: 0,
            kind,
            tags,
            content: String::new(),
            sig: "cd".repeat(64),
        }
    }

    fn p(hex: &str) -> Vec<String> {
        vec!["p".to_string(), hex.to_string()]
    }

    #[test]
    fn gift_wrap_with_p_tag_routes_membership_to_recipient() {
        // kind-1059 carrying a #p recipient ⇒ gate that recipient (not the
        // ephemeral author). The handler then admits iff that recipient is
        // whitelisted; here we pin the recipient resolution + the boolean gate.
        let recipient = "11".repeat(32);
        let ev = mk_event(GIFT_WRAP_KIND, vec![p(&recipient)]);
        assert_eq!(
            gift_wrap_recipient(&ev).as_deref(),
            Some(recipient.as_str())
        );
        // Whitelisted recipient ⇒ admitted; non-whitelisted ⇒ rejected.
        let admitted =
            |whitelisted: bool| gift_wrap_recipient(&ev).is_some() && whitelisted;
        assert!(admitted(true));
        assert!(!admitted(false));
    }

    #[test]
    fn gift_wrap_without_or_empty_p_tag_rejected() {
        // No #p tag ⇒ no resolvable recipient ⇒ fail-closed reject.
        let ev_missing = mk_event(GIFT_WRAP_KIND, vec![vec!["e".to_string(), "ff".repeat(32)]]);
        assert_eq!(gift_wrap_recipient(&ev_missing), None);
        // Empty #p value ⇒ treated as absent ⇒ reject.
        let ev_empty = mk_event(GIFT_WRAP_KIND, vec![p("")]);
        assert_eq!(gift_wrap_recipient(&ev_empty), None);
    }

    #[test]
    fn normal_kind_does_not_route_to_recipient_gate() {
        // A normal kind (e.g. kind-1) with a #p tag is NOT recipient-gated; the
        // author `is_whitelisted` branch still applies (gift_wrap_recipient → None).
        let ev = mk_event(1, vec![p(&"22".repeat(32))]);
        assert_eq!(gift_wrap_recipient(&ev), None);
    }
}

// ---------------------------------------------------------------------------
// ADR-099: revocable device-key access resolution tests
// ---------------------------------------------------------------------------
//
// The async `device_owner` / `effective_pubkey` / `is_whitelisted` methods need
// a `worker::Env` / D1 and cannot run in isolation. These tests pin the PURE
// decision the handler feeds those lookups into:
//   - `effective_principal` resolves the principal access derives from (the
//     device→owner mapping, gated). This is the exact function the async
//     `effective_pubkey` calls after resolving `device_owner(pubkey)` from D1.
//   - `access_admitted` replays the write-gate boolean the handler computes:
//     `is_whitelisted(effective_principal(author, owner, enabled))`.
// The D1 `device_owner` query (missing-table → None) and the env gate read are
// exercised by integration tests against a real D1; here we pin the resolution
// and the access boundary those feed.
#[cfg(test)]
mod device_key_tests {
    use super::*;

    const DEVICE: &str = "de";
    const OWNER: &str = "01";
    const OTHER: &str = "99";

    fn dev() -> String {
        DEVICE.repeat(32)
    }
    fn owner() -> String {
        OWNER.repeat(32)
    }

    // ---- pure resolution: effective_principal -----------------------------

    #[test]
    fn device_resolves_to_owner_when_enabled() {
        // Registered, non-revoked device row (device_owner → Some(owner)) and the
        // feature on ⇒ the session acts as the OWNER for access.
        assert_eq!(
            effective_principal(&dev(), Some(&owner()), true),
            owner(),
            "an enabled, registered device key must resolve to its owner"
        );
    }

    #[test]
    fn revoked_or_unknown_device_resolves_to_self() {
        // `device_owner` returns `None` for a revoked row (the query filters
        // `revoked = 0`) AND for an unknown pubkey AND for a missing table
        // (fail-safe). All three reach here as `None` ⇒ identity passthrough.
        assert_eq!(effective_principal(&dev(), None, true), dev());
    }

    #[test]
    fn gate_off_is_identity_passthrough() {
        // DEVICE_KEYS_ENABLED off ⇒ even a known device→owner mapping is ignored;
        // the device key is just an unknown pubkey, current behaviour unchanged.
        assert_eq!(effective_principal(&dev(), Some(&owner()), false), dev());
        // And a non-device pubkey is of course unchanged too.
        assert_eq!(effective_principal(&dev(), None, false), dev());
    }

    // ---- access decision: write-gate allowlist replay ---------------------
    //
    // The handler admits a (non-gift-wrap) event iff
    // `is_whitelisted(effective_pubkey(author))`. We model `is_whitelisted` as a
    // membership set and replay the exact composition.

    /// Replay of the handler's write-gate: admit iff the EFFECTIVE principal is
    /// whitelisted. `whitelisted` models the `is_whitelisted` D1 set.
    fn access_admitted(
        author: &str,
        device_owner: Option<&str>,
        enabled: bool,
        whitelisted: &[String],
    ) -> bool {
        let principal = effective_principal(author, device_owner, enabled);
        whitelisted.contains(&principal)
    }

    #[test]
    fn device_event_admitted_iff_owner_whitelisted() {
        // Owner IS whitelisted, device is NOT ⇒ enabled device event admitted
        // under the owner's allowlist.
        let wl = vec![owner()];
        assert!(
            access_admitted(&dev(), Some(&owner()), true, &wl),
            "device-authored event must be admitted when its owner is whitelisted"
        );
    }

    #[test]
    fn device_event_rejected_when_owner_not_whitelisted() {
        // Owner NOT whitelisted ⇒ rejected even though it is a valid device row.
        let wl = vec![OTHER.repeat(32)];
        assert!(!access_admitted(&dev(), Some(&owner()), true, &wl));
    }

    #[test]
    fn device_event_rejected_when_gate_off_even_if_owner_whitelisted() {
        // Gate off ⇒ the device pubkey itself is checked. Owner whitelisted but
        // device not ⇒ rejected. This is the "fully inert" guarantee: a device
        // key is just an unknown pubkey.
        let wl = vec![owner()];
        assert!(!access_admitted(&dev(), Some(&owner()), false, &wl));
    }

    #[test]
    fn revoked_device_rejected_even_when_enabled() {
        // Revoked ⇒ `device_owner` is None ⇒ the device pubkey is checked, not
        // the owner ⇒ rejected (owner whitelisted but device not).
        let wl = vec![owner()];
        assert!(!access_admitted(&dev(), None, true, &wl));
    }

    #[test]
    fn non_device_author_unchanged() {
        // An ordinary author (no device row) is checked against itself in both
        // gate states — no behaviour change for the common path.
        let author = "ab".repeat(32);
        let wl = vec![author.clone()];
        assert!(access_admitted(&author, None, true, &wl));
        assert!(access_admitted(&author, None, false, &wl));
        // ...and a non-whitelisted ordinary author is rejected, gate on or off.
        let wl_empty: Vec<String> = vec![];
        assert!(!access_admitted(&author, None, true, &wl_empty));
        assert!(!access_admitted(&author, None, false, &wl_empty));
    }
}
