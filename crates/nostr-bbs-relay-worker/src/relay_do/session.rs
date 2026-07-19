//! Session management for the Nostr relay Durable Object.
//!
//! Handles WebSocket session lifecycle: finding sessions by WebSocket reference,
//! recovering sessions after DO hibernation (including subscriptions and auth
//! state from DO transactional storage), removing sessions on disconnect,
//! and idle timeout scheduling.

use std::collections::HashMap;

use wasm_bindgen::JsValue;
use worker::*;

use super::filter::NostrFilter;
use super::NostrRelayDO;

// ---------------------------------------------------------------------------
// Session state per WebSocket connection
// ---------------------------------------------------------------------------

pub(crate) struct SessionInfo {
    pub ws: WebSocket,
    pub ip: String,
    pub subscriptions: HashMap<String, Vec<NostrFilter>>,
    /// NIP-42: Authenticated pubkey (set after successful AUTH).
    pub authed_pubkey: Option<String>,
    /// NIP-42: Challenge string sent to client on connect.
    pub challenge: String,
}

// ---------------------------------------------------------------------------
// Session management methods on NostrRelayDO
// ---------------------------------------------------------------------------

/// Idle timeout: evict DO from memory if no sessions for 60 seconds.
/// Cloudflare bills per-wall-clock-second, so keeping an empty DO alive
/// burns money for zero utility.
const IDLE_TIMEOUT_MS: i64 = 60_000;

impl NostrRelayDO {
    pub(crate) fn find_session_id(&self, ws: &WebSocket) -> Option<u64> {
        let target: &JsValue = ws.as_ref();
        let sessions = self.sessions.borrow();
        for (id, session) in sessions.iter() {
            let candidate: &JsValue = session.ws.as_ref();
            if target.loose_eq(candidate) {
                return Some(*id);
            }
        }
        None
    }

    /// Recover a session after the DO woke from hibernation.
    ///
    /// When the Durable Object hibernates, in-memory state (sessions, rate
    /// limits) is lost. The runtime preserves WebSocket connections and their
    /// tags. This method reads the tags attached during `accept_websocket_with_tags`
    /// to reconstruct session entries, then restores subscriptions and auth
    /// state from DO transactional storage so that event broadcasting and
    /// authenticated operations continue working across hibernation boundaries.
    ///
    /// Lints:
    /// - `map_entry`: whether to insert depends on async storage loads that
    ///   must run between the `contains_key` check and the `insert`, so the
    ///   `Entry` API (which wants both computed up front) doesn't fit.
    ///
    /// Borrow discipline: the DO runs single-threaded in a V8 isolate, so
    /// there is no *concurrent* borrow hazard, but an `.await` still yields
    /// to the executor and can let a re-entrant call reach `self.sessions`
    /// before this call resumes. Holding a `RefMut` across an `.await` would
    /// make that reentry panic (`RefCell` already borrowed) or observe a
    /// half-updated map. So every `sessions` borrow here is scoped to end
    /// before the next `.await` -- check-and-release, `.await` the storage
    /// load while unborrowed, then re-borrow (re-checking) to apply it.
    #[allow(clippy::map_entry)]
    pub(crate) async fn recover_session(&self, ws: &WebSocket) -> u64 {
        let tags = self.state.get_tags(ws);

        let mut recovered_id: Option<u64> = None;
        let mut recovered_ip = "unknown".to_string();

        for tag in &tags {
            if let Some(id_str) = tag.strip_prefix("sid:") {
                recovered_id = id_str.parse().ok();
            } else if let Some(ip_str) = tag.strip_prefix("ip:") {
                recovered_ip = ip_str.to_string();
            }
        }

        let session_id = recovered_id.unwrap_or_else(|| {
            let mut next = self.next_session_id.borrow_mut();
            let id = *next;
            *next += 1;
            id
        });

        // Ensure next_session_id stays ahead of recovered IDs
        {
            let mut next = self.next_session_id.borrow_mut();
            if session_id >= *next {
                *next = session_id + 1;
            }
        }

        let storage = self.state.storage();

        // NIP-42 across hibernation: the challenge issued to this session at
        // connect time was persisted to DO storage (`ws_chal:{id}`). RESTORE it
        // so a client that connected — but had not yet authed — before the DO
        // hibernated can still answer its ORIGINAL challenge. Minting a fresh
        // one here (as the code previously did) left that client answering an
        // old challenge the recovered session no longer knew, so its AUTH failed
        // "challenge mismatch" forever. If no persisted challenge is found we
        // mint a new one AND re-send AUTH so the client answers the new value.
        let persisted_challenge = Self::load_challenge(&storage, session_id).await;
        let (challenge, reissue_challenge) = recovered_challenge(persisted_challenge, session_id);
        if reissue_challenge {
            Self::persist_challenge(&storage, session_id, &challenge).await;
            Self::send_auth(ws, &challenge);
        }

        // Also recover any other connected WebSockets we've lost track of.
        let all_ws = self.state.get_websockets();

        for other_ws in all_ws {
            let other_tags = self.state.get_tags(&other_ws);
            let mut other_sid: Option<u64> = None;
            let mut other_ip = "unknown".to_string();
            for tag in &other_tags {
                if let Some(id_str) = tag.strip_prefix("sid:") {
                    other_sid = id_str.parse().ok();
                } else if let Some(ip_str) = tag.strip_prefix("ip:") {
                    other_ip = ip_str.to_string();
                }
            }
            let Some(sid) = other_sid else {
                continue;
            };

            // Check-and-release: no borrow held across the `.await` below.
            let already_tracked = self.sessions.borrow().contains_key(&sid);
            if already_tracked {
                continue;
            }

            // Restore this other session's NIP-42 challenge (see the primary
            // session above): reuse the persisted value so a pending AUTH still
            // validates, else mint + persist + re-issue AUTH on its socket.
            let persisted_ch = Self::load_challenge(&storage, sid).await;
            let (ch, reissue) = recovered_challenge(persisted_ch, sid);
            if reissue {
                Self::persist_challenge(&storage, sid, &ch).await;
                Self::send_auth(&other_ws, &ch);
            }

            // Restore subscriptions and auth state from DO storage. The
            // `sessions` RefCell is not borrowed while these await.
            let subscriptions = Self::load_subscriptions(&storage, sid).await;
            let authed_pubkey = Self::load_auth(&storage, sid).await;

            // Re-borrow to apply; re-check in case a re-entrant call raced
            // ahead and inserted this sid while we were awaiting storage.
            {
                let mut sessions = self.sessions.borrow_mut();
                if !sessions.contains_key(&sid) {
                    sessions.insert(
                        sid,
                        SessionInfo {
                            ws: other_ws,
                            ip: other_ip,
                            subscriptions,
                            authed_pubkey,
                            challenge: ch,
                        },
                    );
                }
            }

            let mut next = self.next_session_id.borrow_mut();
            if sid >= *next {
                *next = sid + 1;
            }
        }

        // If the current WS wasn't covered by the get_websockets loop
        // (shouldn't happen, but be safe), insert it.
        let current_tracked = self.sessions.borrow().contains_key(&session_id);
        if !current_tracked {
            let subscriptions = Self::load_subscriptions(&storage, session_id).await;
            let authed_pubkey = Self::load_auth(&storage, session_id).await;

            let mut sessions = self.sessions.borrow_mut();
            if !sessions.contains_key(&session_id) {
                sessions.insert(
                    session_id,
                    SessionInfo {
                        ws: ws.clone(),
                        ip: recovered_ip,
                        subscriptions,
                        authed_pubkey,
                        challenge,
                    },
                );
            }
        }

        let (total, sub_count, auth_count) = {
            let sessions = self.sessions.borrow();
            let sub_count: usize = sessions.values().map(|s| s.subscriptions.len()).sum();
            let auth_count = sessions
                .values()
                .filter(|s| s.authed_pubkey.is_some())
                .count();
            (sessions.len(), sub_count, auth_count)
        };
        console_log!(
            "[RelayDO] Recovered {} session(s) from hibernation (active: #{}, {} subs, {} authed)",
            total,
            session_id,
            sub_count,
            auth_count,
        );

        session_id
    }

    /// Load persisted subscriptions for a session from DO transactional storage.
    async fn load_subscriptions(
        storage: &worker::durable::Storage,
        session_id: u64,
    ) -> HashMap<String, Vec<NostrFilter>> {
        let key = format!("ws_sub:{session_id}");
        match storage.get::<String>(&key).await {
            Ok(Some(json)) => serde_json::from_str(&json).unwrap_or_default(),
            _ => HashMap::new(),
        }
    }

    /// Load persisted auth pubkey for a session from DO transactional storage.
    async fn load_auth(storage: &worker::durable::Storage, session_id: u64) -> Option<String> {
        let key = format!("ws_auth:{session_id}");
        storage.get::<String>(&key).await.unwrap_or_default()
    }

    /// Load the persisted NIP-42 challenge for a session from DO transactional
    /// storage. Returns `None` when absent (the DO never persisted it, or it was
    /// cleared on disconnect), signalling that the recovering session must mint
    /// and re-issue a fresh challenge.
    async fn load_challenge(storage: &worker::durable::Storage, session_id: u64) -> Option<String> {
        let key = format!("ws_chal:{session_id}");
        storage.get::<String>(&key).await.unwrap_or_default()
    }

    /// Persist a session's NIP-42 challenge to DO transactional storage so it
    /// survives hibernation and a pre-hibernation AUTH response still validates.
    async fn persist_challenge(
        storage: &worker::durable::Storage,
        session_id: u64,
        challenge: &str,
    ) {
        let key = format!("ws_chal:{session_id}");
        if let Err(e) = storage.put(&key, challenge.to_string()).await {
            console_log!(
                "[RelayDO] Failed to persist challenge for #{}: {:?}",
                session_id,
                e
            );
        }
    }

    /// Persist the challenge issued to a freshly-connected session (called from
    /// `fetch`). Mirrors [`save_auth`](Self::save_auth) / [`save_subscriptions`]
    /// so the AUTH handshake survives a hibernation that occurs before the client
    /// answers the challenge.
    pub(crate) async fn save_challenge(&self, session_id: u64, challenge: &str) {
        Self::persist_challenge(&self.state.storage(), session_id, challenge).await;
    }

    /// Persist current subscription state for a session to DO transactional storage.
    pub(crate) async fn save_subscriptions(&self, session_id: u64) {
        let subs_json = {
            let sessions = self.sessions.borrow();
            match sessions.get(&session_id) {
                Some(session) => serde_json::to_string(&session.subscriptions).ok(),
                None => None,
            }
        };
        if let Some(json) = subs_json {
            let key = format!("ws_sub:{session_id}");
            if let Err(e) = self.state.storage().put(&key, json).await {
                console_log!(
                    "[RelayDO] Failed to persist subscriptions for #{}: {:?}",
                    session_id,
                    e
                );
            }
        }
    }

    /// Persist auth state for a session to DO transactional storage.
    pub(crate) async fn save_auth(&self, session_id: u64, pubkey: &str) {
        let key = format!("ws_auth:{session_id}");
        if let Err(e) = self.state.storage().put(&key, pubkey.to_string()).await {
            console_log!(
                "[RelayDO] Failed to persist auth for #{}: {:?}",
                session_id,
                e
            );
        }
    }

    /// Remove all persisted state for a session from DO transactional storage.
    async fn clear_session_storage(&self, session_id: u64) {
        let storage = self.state.storage();
        let _ = storage.delete(&format!("ws_sub:{session_id}")).await;
        let _ = storage.delete(&format!("ws_auth:{session_id}")).await;
        let _ = storage.delete(&format!("ws_chal:{session_id}")).await;
    }

    pub(crate) async fn remove_session(&self, ws: &WebSocket) {
        // Try find_session_id first; fall back to tag-based lookup
        let session_id_opt = self.find_session_id(ws).or_else(|| {
            let tags = self.state.get_tags(ws);
            tags.iter()
                .find_map(|t| t.strip_prefix("sid:").and_then(|s| s.parse().ok()))
        });
        if let Some(session_id) = session_id_opt {
            let ip = {
                let sessions = self.sessions.borrow();
                sessions.get(&session_id).map(|s| s.ip.clone())
            };
            self.sessions.borrow_mut().remove(&session_id);

            // Clean up persisted session state from DO storage
            self.clear_session_storage(session_id).await;

            if let Some(ip) = ip {
                let mut counts = self.connection_counts.borrow_mut();
                let count = counts.get(&ip).copied().unwrap_or(1);
                if count <= 1 {
                    counts.remove(&ip);
                } else {
                    counts.insert(ip, count - 1);
                }
            }

            // If no sessions remain, schedule an idle timeout alarm so the
            // DO evicts itself and stops billing.
            if self.sessions.borrow().is_empty() {
                self.schedule_idle_alarm();
            }
        }
    }

    /// Schedule an alarm to evict the DO if still idle after `IDLE_TIMEOUT_MS`.
    /// The `set_alarm` JS binding fires synchronously in the Workers runtime;
    /// we intentionally drop the resulting promise/future.
    #[allow(clippy::let_underscore_future)]
    pub(crate) fn schedule_idle_alarm(&self) {
        let now = js_sys::Date::now() as i64;
        let _ = self.state.storage().set_alarm(now + IDLE_TIMEOUT_MS);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decide the NIP-42 challenge for a session recovered from hibernation.
///
/// Returns `(challenge, reissue)`:
/// - `reissue == false`: the persisted challenge was restored verbatim, so a
///   client that connected before hibernation and is now answering its ORIGINAL
///   challenge validates. Do NOT re-send AUTH (that would rotate the challenge
///   and invalidate the client's in-flight response).
/// - `reissue == true`: no usable persisted challenge existed, so a fresh one
///   was minted; the caller MUST persist it and re-send AUTH so the client
///   answers the new value.
///
/// Pure over its inputs so the restore-vs-reissue decision is unit-testable
/// without a `worker::State` / DO storage.
pub(crate) fn recovered_challenge(persisted: Option<String>, session_id: u64) -> (String, bool) {
    match persisted {
        Some(c) if !c.is_empty() => (c, false),
        _ => (generate_challenge(session_id), true),
    }
}

/// Generate a unique challenge string for NIP-42 AUTH.
///
/// NIP-42 challenge unpredictability is the entire security property of the
/// AUTH handshake — a predictable challenge lets a network attacker forge an
/// AUTH response. `js_sys::Math::random()` is a non-cryptographic PRNG; this
/// implementation uses `getrandom` which on the CF Workers runtime delegates
/// to `crypto.getRandomValues` (a CSPRNG). The session id is XOR-mixed in to
/// preserve uniqueness across collisions in the unlikely event two sessions
/// observe the same 128-bit draw.
pub(crate) fn generate_challenge(session_id: u64) -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("crypto.getRandomValues unavailable");
    let r1 = u64::from_be_bytes(bytes[..8].try_into().expect("8 bytes"));
    let r2 = u64::from_be_bytes(bytes[8..].try_into().expect("8 bytes"));
    format!("{:016x}{:016x}", r1, r2 ^ session_id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovered_challenge_reuses_persisted_value() {
        // A persisted challenge must be restored verbatim with reissue=false so
        // a pre-hibernation AUTH response validates across the boundary.
        let (ch, reissue) = recovered_challenge(Some("deadbeef".to_string()), 7);
        assert_eq!(ch, "deadbeef");
        assert!(!reissue, "persisted challenge must not trigger a re-issue");
    }

    #[test]
    fn recovered_challenge_mints_when_absent() {
        // No persisted challenge => mint a fresh one and signal a re-issue.
        let (ch, reissue) = recovered_challenge(None, 42);
        assert_eq!(ch.len(), 32, "challenge is 128 bits hex-encoded");
        assert!(reissue, "absent challenge must trigger mint + re-issue");
    }

    #[test]
    fn recovered_challenge_treats_empty_as_absent() {
        // An empty stored string is not a usable challenge; treat as absent.
        let (ch, reissue) = recovered_challenge(Some(String::new()), 3);
        assert_eq!(ch.len(), 32);
        assert!(reissue);
    }

    #[test]
    fn generate_challenge_is_unique_and_sized() {
        let a = generate_challenge(1);
        let b = generate_challenge(1);
        assert_eq!(a.len(), 32);
        assert_ne!(a, b, "CSPRNG-backed challenges must differ");
    }
}
