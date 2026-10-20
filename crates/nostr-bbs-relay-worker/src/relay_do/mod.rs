//! Nostr Relay Durable Object (NIP-01 WebSocket relay).
//!
//! Handles WebSocket connections, NIP-01 message protocol (EVENT/REQ/CLOSE),
//! event validation, Schnorr signature verification via `nostr_bbs_core`, whitelist
//! gating, and subscription-based event broadcasting.
//!
//! Uses D1 for persistent event storage and in-memory maps for per-connection
//! subscriptions and rate limiting.
//!
//! The `DurableObject` trait methods take `&self`, so all mutable state is
//! wrapped in `RefCell` for interior mutability. This is safe because the DO
//! runs single-threaded in a V8 isolate.
//!
//! ## Module structure
//!
//! - `session` -- Session lifecycle (find, recover, remove, idle alarm)
//! - `filter` -- NIP-01 filter type, SQL query builder, in-memory matching
//! - `broadcast` -- Event broadcasting, NIP-16 treatment, wire protocol, rate limiting
//! - `nip_handlers` -- NIP-01/09/42/45 protocol handlers, event storage, whitelist

mod broadcast;
mod calendar_projection;
mod filter;
mod mod_cache;
mod nip42;
mod nip_handlers;
mod push_fanout;
mod read_cache;
pub(crate) mod receipts;
mod session;
mod storage;

use crate::auth::AdminCache;
pub(crate) use mod_cache::ModCache;
use read_cache::{ActivityLedger, TtlCache, LOOKUP_TTL_SECS};

#[cfg(feature = "test-exports")]
#[doc(hidden)]
pub mod test_exports {
    pub use super::broadcast::{event_treatment, EventTreatment};
    pub use super::filter::{d_tag_value, event_matches_filters, tag_value, NostrFilter};
    pub use super::mod_cache::{resolve_block, ActionRow, Block, ModCache};
    pub use super::nip42::{
        allowlist_denial_reason, canonical_relay_url, evaluate_auth_event, is_protected_read_kind,
        parse_auth_mode, protected_read_blocked, relay_urls_match, write_auth_ok, AuthMode,
        AuthVerdict, AUTH_MAX_SKEW_SECS, KIND_AUTH, PROTECTED_READ_KINDS,
    };
    pub use super::nip_handlers::{
        device_keys_enabled_var, effective_principal, is_ban_gated_kind, response_admission,
        ResponseAdmission,
    };
}

use std::cell::RefCell;
use std::collections::HashMap;

use nostr_bbs_core::event::NostrEvent;
use worker::*;

use session::{generate_challenge, SessionInfo};

// NIP-42 AUTH mode parsing is shared with the NIP-11 relay-info document
// (`crate::nip11`) so the advertised `auth_required` can never drift from the
// mode the handlers actually enforce.
pub(crate) use nip42::{parse_auth_mode, AuthMode, PROTECTED_READ_KINDS};

/// Maximum WebSocket connections per IP address.
const MAX_CONNECTIONS_PER_IP: u32 = 20;

/// Maximum filters accepted per REQ/COUNT frame. Matches the `max_filters`
/// value advertised in NIP-11 (`nip11.rs`). Each filter is a separate D1 query
/// in `query_events`, so an uncapped frame is a request-amplification DoS
/// (especially on the unauthenticated COUNT path).
const MAX_FILTERS: usize = 10;

// ---------------------------------------------------------------------------
// Durable Object
// ---------------------------------------------------------------------------

/// DO-storage key holding the next session id to issue (see
/// [`NostrRelayDO::allocate_session_id`]).
pub(crate) const SESSION_ID_MARK_KEY: &str = "session_id_mark";

#[durable_object]
pub struct NostrRelayDO {
    pub(crate) state: State,
    pub(crate) env: Env,
    pub(crate) sessions: RefCell<HashMap<u64, SessionInfo>>,
    pub(crate) next_session_id: RefCell<u64>,
    pub(crate) rate_limits: RefCell<HashMap<String, Vec<f64>>>,
    /// Lazily-resolved per-IP message budget per rolling second (EVENT/REQ/
    /// COUNT frames). `RATE_LIMIT_MSGS_PER_SEC` env var, else the built-in
    /// default. Cached after first read — `Env::var` crosses the JS boundary.
    pub(crate) rate_limit_per_sec: std::cell::Cell<Option<usize>>,
    pub(crate) connection_counts: RefCell<HashMap<String, u32>>,
    /// WI-2: 60s-TTL cache of active ban/mute actions keyed by target pubkey.
    pub(crate) mod_cache: ModCache,
    /// P2-03: 5-minute TTL cache for admin status, eliminating redundant D1
    /// queries on the EVENT hot path.
    pub(crate) admin_cache: AdminCache,
    /// ADR-2018: 60s-TTL memo of channel → zone (positive results only).
    pub(crate) channel_zone_cache: TtlCache<String>,
    /// ADR-2018: 60s-TTL memo of pubkey → (cohorts, whitelist is_admin).
    pub(crate) cohort_cache: TtlCache<(Vec<String>, bool)>,
    /// ADR-2018: 60s-TTL memo of device pubkey → owner (None = not a device key).
    pub(crate) device_owner_cache: TtlCache<Option<String>>,
    /// Phase 2: 60s memo of recipient key → `(owner, revoked)` (None = unregistered).
    pub(crate) recipient_row_cache: TtlCache<Option<(String, bool)>>,
    /// Phase 2: 60s memo of owner → unrevoked inbox keys. Never filled at AUTH:
    /// `save_auth` persists only the pubkey, so it is looked up on demand.
    pub(crate) recipient_keys_cache: TtlCache<Vec<String>>,
    /// ADR-2018: per-pubkey throttle for the trust-ledger activity writes.
    pub(crate) activity: ActivityLedger,
}

impl DurableObject for NostrRelayDO {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            sessions: RefCell::new(HashMap::new()),
            next_session_id: RefCell::new(1),
            rate_limits: RefCell::new(HashMap::new()),
            rate_limit_per_sec: std::cell::Cell::new(None),
            connection_counts: RefCell::new(HashMap::new()),
            mod_cache: ModCache::new(),
            admin_cache: AdminCache::new(),
            channel_zone_cache: TtlCache::new(LOOKUP_TTL_SECS),
            cohort_cache: TtlCache::new(LOOKUP_TTL_SECS),
            device_owner_cache: TtlCache::new(LOOKUP_TTL_SECS),
            recipient_row_cache: TtlCache::new(LOOKUP_TTL_SECS),
            recipient_keys_cache: TtlCache::new(LOOKUP_TTL_SECS),
            activity: ActivityLedger::new(),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        if req.headers().get("Upgrade")?.as_deref() != Some("websocket") {
            return Response::error("Expected WebSocket", 426);
        }

        let ip = req
            .headers()
            .get("CF-Connecting-IP")?
            .unwrap_or_else(|| "unknown".to_string());

        // Connection rate limit. The slot is reserved in the same borrow as the
        // check: this method awaits below, and a second upgrade arriving in one
        // of those windows would otherwise read the same pre-increment count and
        // slip past the cap. Every early return after this point releases it.
        {
            let mut counts = self.connection_counts.borrow_mut();
            if !reserve_connection_slot(&mut counts, &ip, MAX_CONNECTIONS_PER_IP) {
                return Response::error("Too many connections", 429);
            }
        }

        // A DO woken from hibernation by this connection has lost its
        // in-memory sessions but still holds their sockets. Recover them
        // before allocating an id (so it cannot collide with a live socket's)
        // and before this connection publishes anything (so broadcasts reach
        // them). No-op when nothing hibernated.
        self.recover_untracked_sessions().await;

        let pair = match WebSocketPair::new() {
            Ok(pair) => pair,
            Err(e) => {
                release_connection_slot(&mut self.connection_counts.borrow_mut(), &ip);
                return Err(e);
            }
        };
        let server = pair.server;
        let client = pair.client;

        let session_id = self.allocate_session_id().await;

        // Tag the WebSocket so session data survives DO hibernation.
        // Tags are persisted by the runtime even when in-memory state is lost.
        self.state.accept_websocket_with_tags(
            &server,
            &[&format!("sid:{session_id}"), &format!("ip:{ip}")],
        );

        let challenge = generate_challenge(session_id);
        {
            let mut sessions = self.sessions.borrow_mut();
            sessions.insert(
                session_id,
                SessionInfo {
                    ws: server,
                    ip: ip.clone(),
                    subscriptions: HashMap::new(),
                    authed_pubkey: None,
                    challenge: challenge.clone(),
                },
            );
        }

        // NIP-42: persist the challenge to DO storage BEFORE sending it, so a
        // hibernation that occurs before the client answers can restore the same
        // challenge in `recover_session` and the client's original AUTH response
        // still validates (otherwise the recovered session mints a new challenge
        // the client never saw and every AUTH fails "challenge mismatch").
        self.save_challenge(session_id, &challenge).await;

        // NIP-42: Send AUTH challenge to the newly connected client
        {
            let sessions = self.sessions.borrow();
            if let Some(session) = sessions.get(&session_id) {
                Self::send_auth(&session.ws, &challenge);
            }
        }

        Response::from_websocket(client)
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let msg = match message {
            WebSocketIncomingMessage::String(s) => s,
            WebSocketIncomingMessage::Binary(b) => String::from_utf8(b).unwrap_or_default(),
        };

        // Try to find the session in memory. If the DO woke from hibernation,
        // the in-memory sessions map is empty -- recover from WebSocket tags.
        let session_id = match self.find_session_id(&ws) {
            Some(id) => id,
            None => self.recover_session(&ws).await,
        };

        let ip = self
            .sessions
            .borrow()
            .get(&session_id)
            .map(|s| s.ip.clone())
            .unwrap_or_else(|| "unknown".into());

        let parsed: serde_json::Value = match serde_json::from_str(&msg) {
            Ok(v) => v,
            Err(_) => {
                Self::send_notice(&ws, "Invalid JSON");
                return Ok(());
            }
        };

        let arr = match parsed.as_array() {
            Some(a) if a.len() >= 2 => a.clone(),
            _ => {
                Self::send_notice(&ws, "Invalid message format");
                return Ok(());
            }
        };

        let msg_type = match arr[0].as_str() {
            Some(t) => t.to_string(),
            None => {
                Self::send_notice(&ws, "Invalid message format");
                return Ok(());
            }
        };

        match msg_type.as_str() {
            "EVENT" => {
                let event: NostrEvent = match serde_json::from_value(arr[1].clone()) {
                    Ok(e) => e,
                    Err(_) => {
                        Self::send_notice(&ws, "Invalid event");
                        return Ok(());
                    }
                };
                self.handle_event(session_id, &ws, &ip, event).await;
            }
            "REQ" => {
                let sub_id = match arr[1].as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        Self::send_notice(&ws, "Invalid subscription ID");
                        return Ok(());
                    }
                };
                let filters: Vec<filter::NostrFilter> = arr[2..]
                    .iter()
                    .filter_map(|v| serde_json::from_value(v.clone()).ok())
                    .collect();
                if filters.len() > MAX_FILTERS {
                    Self::send_notice(&ws, "too many filters (max 10)");
                    return Ok(());
                }
                self.handle_req(session_id, &ip, &sub_id, filters).await;
            }
            "CLOSE" => {
                // CLOSE and AUTH are frames too: leaving them off the limiter let
                // a client flood the DO for free. A CLOSE for a subscription the
                // session holds is exempt: it only sheds load.
                let sub_id = arr[1].as_str();
                let holds = sub_id.is_some_and(|id| {
                    self.sessions
                        .borrow()
                        .get(&session_id)
                        .is_some_and(|s| s.subscriptions.contains_key(id))
                });
                if !close_admitted(holds, || self.check_rate_limit(&ip)) {
                    Self::send_notice(&ws, "rate limit exceeded");
                    return Ok(());
                }
                if let Some(sub_id) = sub_id {
                    self.handle_close(session_id, sub_id).await;
                }
            }
            "AUTH" => {
                if !self.check_rate_limit(&ip) {
                    // Answer with a refused OK so the client knows to retry
                    // rather than sit unauthenticated behind a silent notice.
                    match arr[1].get("id").and_then(|v| v.as_str()) {
                        Some(id) => Self::send_ok(&ws, id, false, "rate-limited: slow down"),
                        None => Self::send_notice(&ws, "rate limit exceeded"),
                    }
                    return Ok(());
                }
                let auth_event: NostrEvent = match serde_json::from_value(arr[1].clone()) {
                    Ok(e) => e,
                    Err(_) => {
                        Self::send_notice(&ws, "Invalid auth event");
                        return Ok(());
                    }
                };
                self.handle_auth(session_id, &ws, auth_event).await;
            }
            "COUNT" => {
                let sub_id = match arr[1].as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        Self::send_notice(&ws, "Invalid subscription ID");
                        return Ok(());
                    }
                };
                let filters: Vec<filter::NostrFilter> = arr[2..]
                    .iter()
                    .filter_map(|v| serde_json::from_value(v.clone()).ok())
                    .collect();
                if filters.len() > MAX_FILTERS {
                    Self::send_notice(&ws, "too many filters (max 10)");
                    return Ok(());
                }
                self.handle_count(session_id, &ip, &ws, &sub_id, filters)
                    .await;
            }
            _ => {
                Self::send_notice(&ws, &format!("Unknown message type: {msg_type}"));
            }
        }

        Ok(())
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        self.remove_session(&ws).await;
        Ok(())
    }

    async fn websocket_error(&self, ws: WebSocket, _error: Error) -> Result<()> {
        self.remove_session(&ws).await;
        Ok(())
    }

    /// Alarm handler: if no sessions remain, clear in-memory state so the DO
    /// can be evicted. If sessions exist (a new connection arrived during the
    /// timeout window), the alarm is a no-op.
    async fn alarm(&self) -> Result<Response> {
        if self.sessions.borrow().is_empty() {
            self.rate_limits.borrow_mut().clear();
            self.connection_counts.borrow_mut().clear();
            console_log!("[RelayDO] Idle timeout -- cleared in-memory state for eviction");
        }
        Response::ok("ok")
    }
}

/// Whether a CLOSE frame is processed. A CLOSE for a subscription the session
/// holds is always honoured (it only sheds load, and holdings are bounded by
/// `MAX_SUBSCRIPTIONS`); a CLOSE for an unknown id must pass the frame limiter,
/// which is consulted only then so a held-id CLOSE spends no budget.
pub(crate) fn close_admitted(
    holds_subscription: bool,
    within_budget: impl FnOnce() -> bool,
) -> bool {
    holds_subscription || within_budget()
}

/// Reserve one connection slot for `ip` if it is under `max`. The check and the
/// increment share one `&mut` borrow, so no `.await` can fall between them.
pub(crate) fn reserve_connection_slot(
    counts: &mut HashMap<String, u32>,
    ip: &str,
    max: u32,
) -> bool {
    let count = counts.get(ip).copied().unwrap_or(0);
    if count >= max {
        return false;
    }
    counts.insert(ip.to_string(), count + 1);
    true
}

/// Release a slot taken by [`reserve_connection_slot`], dropping the entry at zero.
pub(crate) fn release_connection_slot(counts: &mut HashMap<String, u32>, ip: &str) {
    match counts.get(ip).copied().unwrap_or(1) {
        0 | 1 => {
            counts.remove(ip);
        }
        n => {
            counts.insert(ip.to_string(), n - 1);
        }
    }
}

#[cfg(test)]
mod connection_slot_tests {
    use super::*;

    #[test]
    fn close_of_a_held_subscription_skips_the_limiter() {
        assert!(close_admitted(true, || panic!(
            "limiter must not be consulted"
        )));
        assert!(close_admitted(false, || true));
        assert!(!close_admitted(false, || false));
    }

    #[test]
    fn reservation_stops_at_the_cap_and_release_frees_a_slot() {
        let mut counts = HashMap::new();
        assert!(reserve_connection_slot(&mut counts, "1.1.1.1", 2));
        assert!(reserve_connection_slot(&mut counts, "1.1.1.1", 2));
        assert!(!reserve_connection_slot(&mut counts, "1.1.1.1", 2));
        // Another address has its own budget.
        assert!(reserve_connection_slot(&mut counts, "2.2.2.2", 2));
        release_connection_slot(&mut counts, "1.1.1.1");
        assert!(reserve_connection_slot(&mut counts, "1.1.1.1", 2));
    }

    #[test]
    fn release_removes_the_entry_at_zero_and_tolerates_unknown_ips() {
        let mut counts = HashMap::new();
        assert!(reserve_connection_slot(&mut counts, "1.1.1.1", 2));
        release_connection_slot(&mut counts, "1.1.1.1");
        assert!(counts.is_empty());
        release_connection_slot(&mut counts, "9.9.9.9");
        assert!(counts.is_empty());
    }
}
