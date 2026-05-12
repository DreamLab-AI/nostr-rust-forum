//! NIP-specific protocol handlers for the Nostr relay.
//!
//! - NIP-01: EVENT, REQ, CLOSE
//! - NIP-09: Deletion processing
//! - NIP-42: AUTH challenge/response
//! - NIP-45: COUNT
//! - Event validation.
//! - Trust-level gating (TL0-TL3) for event kinds.
//! - Zone enforcement on EVENT and REQ.

use nostr_bbs_core::event::NostrEvent;
use nostr_bbs_core::governance;
use nostr_bbs_core::{KIND_BAN, KIND_MUTE, KIND_REPORT_NIP56};
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

/// NIP-29: Admin-only group management/moderation kinds.
fn is_nip29_admin_kind(kind: u64) -> bool {
    (9000..=9020).contains(&kind) || (39000..=39002).contains(&kind)
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

        if !self.is_whitelisted(&event.pubkey).await {
            Self::send_ok(ws, &event.id, false, "blocked: pubkey not whitelisted");
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
        // Human responses (kind 31403) are allowed from any whitelisted user.
        if governance::is_governance_kind(event.kind)
            && event.kind != governance::KIND_ACTION_RESPONSE
        {
            if !self.is_registered_agent(&event.pubkey).await {
                Self::send_ok(
                    ws,
                    &event.id,
                    false,
                    "blocked: pubkey not in agent registry",
                );
                return;
            }
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
            if !is_admin && !trust::has_zone_access(&event.pubkey, &zone, &self.env).await {
                Self::send_ok(ws, &event.id, false, "zone access denied");
                return;
            }
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

            // WI-2: mirror moderation-action Nostr events (kind 30910 ban,
            // 30911 mute) into the local `moderation_actions` table so the
            // ingress gate can reject content from muted/banned authors.
            // Only respected when the signer is an admin on this relay.
            if matches!(event.kind, KIND_BAN | KIND_MUTE) && is_admin {
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

        // NIP-59: kind-1059 AUTH gating.
        // If any filter requests kind-1059 (Sealed DMs), the session must be
        // authenticated. We inject a mandatory #p tag constraint so that only
        // events addressed to the authenticated pubkey are returned, preventing
        // cross-recipient leakage.
        let filters = {
            let needs_kind_1059 = filters
                .iter()
                .any(|f| f.kinds.as_ref().is_some_and(|k| k.contains(&1059)));
            if needs_kind_1059 {
                match &session_pubkey {
                    None => {
                        Self::send_notice(
                            &ws,
                            "auth-required: must authenticate to receive kind-1059 DMs",
                        );
                        return;
                    }
                    Some(authed_pk) => {
                        // Rewrite each filter that includes kind-1059 to also require
                        // a #p tag matching the authenticated pubkey.
                        filters
                            .into_iter()
                            .map(|mut f| {
                                if f.kinds.as_ref().is_some_and(|k| k.contains(&1059)) {
                                    // Enforce the #p filter for the authed pubkey.
                                    // We override any existing #p to prevent a client
                                    // from requesting another user's DMs.
                                    f.extra
                                        .insert("#p".to_string(), serde_json::json!([authed_pk]));
                                }
                                f
                            })
                            .collect::<Vec<_>>()
                    }
                }
            } else {
                filters
            }
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
                        let is_admin = self.admin_cache.is_admin(pk, &self.env).await;
                        if !is_admin && !trust::has_zone_access(pk, &zone, &self.env).await {
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
        let category = governance::extract_tag(&event.tags, "category")
            .unwrap_or("manual_submission");
        let subject_kind = governance::extract_tag(&event.tags, "subject-kind")
            .unwrap_or("opaque");
        let subject_id = governance::extract_tag(&event.tags, "subject-id")
            .unwrap_or("");
        let title = governance::extract_tag(&event.tags, "title")
            .unwrap_or("Untitled");
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

    /// WI-2: mirror a kind-30910 (ban) or kind-30911 (mute) event into the
    /// local `moderation_actions` table. Idempotent via `event_id` dedup --
    /// re-receiving the same event is a no-op. Missing target pubkey (no
    /// `p` tag) silently drops the mirror.
    pub(crate) async fn mirror_moderation_action(&self, event: &NostrEvent) {
        let action = match event.kind {
            30910 => "ban",
            30911 => "mute",
            _ => return,
        };

        let Some(target) = filter::tag_value(event, "p") else {
            return;
        };

        // expires_at: mutes may carry a NIP-40 style `expiration` tag. Bans
        // never expire; we persist NULL.
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
        let now = auth::js_now_secs();

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
            JsValue::from_f64(now as f64),
        ]) else {
            return;
        };
        let _ = stmt.run().await;
    }
}
