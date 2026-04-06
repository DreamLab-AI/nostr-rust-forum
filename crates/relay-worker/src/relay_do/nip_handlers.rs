//! NIP-specific protocol handlers for the Nostr relay.
//!
//! - NIP-01: EVENT, REQ, CLOSE
//! - NIP-09: Deletion processing
//! - NIP-42: AUTH challenge/response
//! - NIP-45: COUNT
//! - Event validation.
//! - Trust-level gating (TL0-TL3) for event kinds.
//! - Zone enforcement on EVENT and REQ.

use nostr_core::event::NostrEvent;
use wasm_bindgen::JsValue;
use worker::*;

use crate::auth;
use crate::moderation;
use crate::trust::{self, TrustLevel};

use super::broadcast::{event_treatment, EventTreatment};
use super::filter::{self, NostrFilter};
use super::NostrRelayDO;

// ---------------------------------------------------------------------------
// Security limits
// ---------------------------------------------------------------------------

const MAX_CONTENT_SIZE: usize = 64 * 1024;
const MAX_REGISTRATION_CONTENT_SIZE: usize = 8 * 1024;
const MAX_TAG_COUNT: usize = 2000;
const MAX_TAG_VALUE_SIZE: usize = 1024;
const MAX_TIMESTAMP_DRIFT: u64 = 60 * 60 * 24 * 7;
const MAX_SUBSCRIPTIONS: usize = 20;

/// NIP-29: Admin-only group management kinds.
const NIP29_ADMIN_KINDS: &[u64] = &[9000, 9001, 9005, 39000];

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

        // Events that bypass whitelist gating:
        // - kind 0: profile metadata (triggers auto-whitelist)
        // - kind 9021: join request
        // - kind 9024: registration metadata
        // NOTE: kind-40 (channel creation) no longer bypasses -- it requires TL2+.
        let is_bypass = matches!(event.kind, 0 | 9021 | 9024);
        if !is_bypass && !self.is_whitelisted(&event.pubkey).await {
            Self::send_ok(ws, &event.id, false, "blocked: pubkey not whitelisted");
            return;
        }

        // Auto-whitelist: when a new user publishes their first kind-0 profile event
        // (or any bypass event before they're whitelisted), add them to the whitelist
        // with the "lobby" cohort so they can participate immediately.
        if is_bypass && !self.is_whitelisted(&event.pubkey).await {
            self.auto_whitelist(&event.pubkey).await;
        }

        // Suspension and silence check
        let (suspended, silenced) = trust::check_suspension(&event.pubkey, &self.env).await;
        if suspended {
            Self::send_ok(ws, &event.id, false, "blocked: account suspended");
            return;
        }
        if silenced {
            Self::send_ok(ws, &event.id, false, "blocked: account silenced (read-only)");
            return;
        }

        // Trust-level gating for specific event kinds
        let is_admin = auth::is_admin(&event.pubkey, &self.env).await;
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
                if trust_level < TrustLevel::Trusted {
                    if let Some(channel_id) = filter::tag_value(&event, "e") {
                        if !self.is_channel_creator(&event.pubkey, &channel_id).await {
                            Self::send_ok(
                                ws,
                                &event.id,
                                false,
                                "restricted: TL3+ required to modify others' channels",
                            );
                            return;
                        }
                    }
                }
            }

            // kind-1984 (report): TL1+ required
            if event.kind == 1984 && trust_level < TrustLevel::Member {
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
        if NIP29_ADMIN_KINDS.contains(&event.kind) && !is_admin {
            Self::send_ok(ws, &event.id, false, "blocked: admin-only group action");
            return;
        }

        // Zone enforcement for channel messages (kind-42)
        if event.kind == 42 {
            if let Some(channel_id) = filter::tag_value(&event, "e") {
                let zone = trust::get_channel_zone(&channel_id, &self.env)
                    .await
                    .unwrap_or_else(|| "home".to_string());
                if !is_admin
                    && !trust::has_zone_access(&event.pubkey, &zone, &self.env).await
                {
                    Self::send_ok(ws, &event.id, false, "zone access denied");
                    return;
                }
            }
        }

        // Verify event ID and Schnorr signature via nostr_core
        if nostr_core::verify_event_strict(&event).is_err() {
            Self::send_ok(
                ws,
                &event.id,
                false,
                "invalid: event id or signature verification failed",
            );
            return;
        }

        // NIP-16 event treatment
        let treatment = event_treatment(event.kind);

        if treatment == EventTreatment::Ephemeral {
            Self::send_ok(ws, &event.id, true, "");
            self.broadcast_event(&event);
            return;
        }

        // Save to D1
        if self.save_event(&event, treatment).await {
            Self::send_ok(ws, &event.id, true, "");
            self.broadcast_event(&event);

            // Activity tracking: increment posts_created and update last_active
            // for content-producing event kinds (kind-1 text, kind-42 channel msg,
            // kind-40 channel create, kind-7 reaction, kind-1984 report).
            if matches!(event.kind, 1 | 7 | 40 | 42 | 1984) {
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
            if event.kind == 1984 {
                self.process_report(&event).await;
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

        // Query D1 for matching events
        let events = self.query_events(&filters).await;

        // Zone-filter: exclude events from channels the user lacks zone access for.
        // Only applies to kind-42 (channel messages) events.
        for event in &events {
            if event.kind == 42 {
                if let Some(channel_id) = filter::tag_value(event, "e") {
                    if let Some(ref pk) = session_pubkey {
                        let zone = trust::get_channel_zone(&channel_id, &self.env)
                            .await
                            .unwrap_or_else(|| "home".to_string());
                        let is_admin = auth::is_admin(pk, &self.env).await;
                        if !is_admin
                            && !trust::has_zone_access(pk, &zone, &self.env).await
                        {
                            continue; // skip this event
                        }
                    }
                }
            }
            Self::send_event(&ws, sub_id, event);
        }
        Self::send_eose(&ws, sub_id);
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
        if nostr_core::verify_event_strict(&event).is_err() {
            Self::send_ok(ws, &event.id, false, "invalid: signature verification failed");
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
// NIP-45: COUNT
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Handle a COUNT request: return the number of matching events.
    ///
    /// Reuses `query_events()` which already handles NIP-40 expiration filtering
    /// at the application layer and correctly processes tag filters.
    pub(crate) async fn handle_count(
        &self,
        ws: &WebSocket,
        sub_id: &str,
        filters: Vec<NostrFilter>,
    ) {
        let events = self.query_events(&filters).await;
        Self::send_count(ws, sub_id, events.len() as u64);
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
            let stmt = db.prepare(
                "DELETE FROM events WHERE id = ?1 AND pubkey = ?2",
            );
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

            let stmt = db.prepare(
                "DELETE FROM events WHERE kind = ?1 AND pubkey = ?2 AND d_tag = ?3",
            );
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
        let reason = filter::tag_value(report_event, "report")
            .unwrap_or_else(|| {
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
}
