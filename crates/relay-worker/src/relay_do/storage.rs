//! D1 event storage and whitelist management.
//!
//! Handles persisting events to D1, querying events for subscriptions,
//! and whitelist/auto-whitelist logic including first-user-is-admin.

use nostr_core::event::NostrEvent;
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::*;

use crate::auth;

use super::broadcast::EventTreatment;
use super::filter::{self, CountResult, NostrFilter};
use super::NostrRelayDO;

// ---------------------------------------------------------------------------
// Security limits
// ---------------------------------------------------------------------------

const MAX_QUERY_LIMIT: u32 = 1000;

// ---------------------------------------------------------------------------
// D1 row type for query results
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct EventRow {
    id: String,
    pubkey: String,
    created_at: f64,
    kind: f64,
    tags: String,
    content: String,
    sig: String,
}

impl EventRow {
    fn into_nostr_event(self) -> Option<NostrEvent> {
        let tags: Vec<Vec<String>> = serde_json::from_str(&self.tags).ok()?;
        Some(NostrEvent {
            id: self.id,
            pubkey: self.pubkey,
            created_at: self.created_at as u64,
            kind: self.kind as u64,
            tags,
            content: self.content,
            sig: self.sig,
        })
    }
}

// ---------------------------------------------------------------------------
// D1 event storage
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    pub(crate) async fn save_event(&self, event: &NostrEvent, treatment: EventTreatment) -> bool {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return false,
        };

        let d_tag = filter::d_tag_value(event);
        let tags_json = match serde_json::to_string(&event.tags) {
            Ok(j) => j,
            Err(_) => return false,
        };
        let now = auth::js_now_secs();

        let insert_stmt = db.prepare(
            "INSERT INTO events (id, pubkey, created_at, kind, tags, content, sig, d_tag, received_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
             ON CONFLICT (id) DO NOTHING",
        );

        let insert_binds = [
            JsValue::from_str(&event.id),
            JsValue::from_str(&event.pubkey),
            JsValue::from_f64(event.created_at as f64),
            JsValue::from_f64(event.kind as f64),
            JsValue::from_str(&tags_json),
            JsValue::from_str(&event.content),
            JsValue::from_str(&event.sig),
            JsValue::from_str(&d_tag),
            JsValue::from_f64(now as f64),
        ];

        match treatment {
            EventTreatment::Replaceable => {
                let delete_stmt = db.prepare(
                    "DELETE FROM events WHERE pubkey = ?1 AND kind = ?2 AND created_at < ?3",
                );
                let delete_binds = [
                    JsValue::from_str(&event.pubkey),
                    JsValue::from_f64(event.kind as f64),
                    JsValue::from_f64(event.created_at as f64),
                ];

                let delete_bound = match delete_stmt.bind(&delete_binds) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                let insert_bound = match insert_stmt.bind(&insert_binds) {
                    Ok(s) => s,
                    Err(_) => return false,
                };

                db.batch(vec![delete_bound, insert_bound]).await.is_ok()
            }
            EventTreatment::ParameterizedReplaceable => {
                let delete_stmt = db.prepare(
                    "DELETE FROM events WHERE pubkey = ?1 AND kind = ?2 AND d_tag = ?3 AND created_at < ?4",
                );
                let delete_binds = [
                    JsValue::from_str(&event.pubkey),
                    JsValue::from_f64(event.kind as f64),
                    JsValue::from_str(&d_tag),
                    JsValue::from_f64(event.created_at as f64),
                ];

                let delete_bound = match delete_stmt.bind(&delete_binds) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                let insert_bound = match insert_stmt.bind(&insert_binds) {
                    Ok(s) => s,
                    Err(_) => return false,
                };

                db.batch(vec![delete_bound, insert_bound]).await.is_ok()
            }
            EventTreatment::Regular => match insert_stmt.bind(&insert_binds) {
                Ok(s) => s.run().await.is_ok(),
                Err(_) => false,
            },
            EventTreatment::Ephemeral => true,
        }
    }

    pub(crate) async fn query_events(&self, filters: &[NostrFilter]) -> Vec<NostrEvent> {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return Vec::new(),
        };

        let now = auth::js_now_secs();
        let mut events = Vec::new();

        for filter in filters {
            let mut conditions: Vec<String> = Vec::new();
            let mut params: Vec<JsValue> = Vec::new();
            let mut param_idx = 1u32;

            Self::build_filter_conditions(filter, &mut conditions, &mut params, &mut param_idx);

            let where_clause = if conditions.is_empty() {
                String::new()
            } else {
                format!("WHERE {}", conditions.join(" AND "))
            };

            let limit = filter.limit.unwrap_or(500).min(MAX_QUERY_LIMIT);
            let limit_placeholder = format!("?{param_idx}");
            params.push(JsValue::from_f64(limit as f64));

            let sql = format!(
                "SELECT id, pubkey, created_at, kind, tags, content, sig \
                 FROM events {where_clause} \
                 ORDER BY created_at DESC LIMIT {limit_placeholder}"
            );

            let result = match db.prepare(&sql).bind(&params) {
                Ok(stmt) => match stmt.all().await {
                    Ok(r) => r,
                    Err(_) => continue,
                },
                Err(_) => continue,
            };

            let rows: Vec<EventRow> = match result.results() {
                Ok(r) => r,
                Err(_) => continue,
            };

            for row in rows {
                if let Some(event) = row.into_nostr_event() {
                    // NIP-40: Skip expired events at application layer
                    if let Some(exp) = filter::tag_value(&event, "expiration") {
                        if let Ok(exp_ts) = exp.parse::<u64>() {
                            if exp_ts < now {
                                continue;
                            }
                        }
                    }
                    events.push(event);
                }
            }
        }

        events
    }
}

// ---------------------------------------------------------------------------
// Whitelist check
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    pub(crate) async fn is_whitelisted(&self, pubkey: &str) -> bool {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return false,
        };

        let now = auth::js_now_secs();
        let stmt = match db
            .prepare("SELECT 1 as found FROM whitelist WHERE pubkey = ?1 AND (expires_at IS NULL OR expires_at > ?2)")
            .bind(&[JsValue::from_str(pubkey), JsValue::from_f64(now as f64)])
        {
            Ok(s) => s,
            Err(_) => return false,
        };

        matches!(stmt.first::<serde_json::Value>(None).await, Ok(Some(_)))
    }

    /// Auto-whitelist a new user with the "members" cohort.
    ///
    /// Called when a user publishes their first kind-0 profile event. Gives them
    /// immediate access to the Nostr BBS zone without admin intervention.
    /// Admin can later assign additional cohorts for other zones.
    ///
    /// **First-user-is-admin**: If the whitelist table is empty, the first user
    /// to register automatically becomes admin with all-zone access.
    pub(crate) async fn auto_whitelist(&self, pubkey: &str) {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return,
        };

        let now = auth::js_now_secs();

        // Check if any admin exists (more robust than checking if table is empty --
        // handles the case where users registered but none got admin due to bugs)
        let no_admin_exists = {
            let stmt = db.prepare("SELECT COUNT(*) as cnt FROM whitelist WHERE is_admin = 1");
            match stmt.first::<CountResult>(None).await {
                Ok(Some(row)) => (row.cnt as u64) == 0,
                _ => false,
            }
        };

        if no_admin_exists {
            // Promote this user to admin with all zones.
            // Use UPSERT so it works whether the user is new or already in the whitelist.
            let stmt = db.prepare(
                "INSERT INTO whitelist (pubkey, cohorts, added_at, added_by, is_admin) \
                 VALUES (?1, ?2, ?3, ?4, 1) \
                 ON CONFLICT (pubkey) DO UPDATE SET \
                   cohorts = excluded.cohorts, \
                   is_admin = 1",
            );
            if let Ok(bound) = stmt.bind(&[
                JsValue::from_str(pubkey),
                JsValue::from_str(r#"["home","members","private"]"#),
                JsValue::from_f64(now as f64),
                JsValue::from_str("auto-registration"),
            ]) {
                let _ = bound.run().await;
            }
            worker::console_log!(
                "[auto_whitelist] No admin exists -- promoting {} to admin with all zones",
                &pubkey[..8]
            );
        } else {
            // Normal registration: members zone only, not admin
            let stmt = db.prepare(
                "INSERT INTO whitelist (pubkey, cohorts, added_at, added_by, is_admin) \
                 VALUES (?1, ?2, ?3, ?4, 0) \
                 ON CONFLICT (pubkey) DO NOTHING",
            );
            if let Ok(bound) = stmt.bind(&[
                JsValue::from_str(pubkey),
                JsValue::from_str(r#"["members"]"#),
                JsValue::from_f64(now as f64),
                JsValue::from_str("auto-registration"),
            ]) {
                let _ = bound.run().await;
            }
        }
    }
}
