//! In-memory mock relay + socket for loopback testing (no real WebSocket).
//!
//! [`MockRelay`] is a minimal NIP-01/NIP-42 relay living entirely in memory: it
//! stores events, answers `REQ` subscriptions (replay + live push), and
//! acknowledges `EVENT`/`AUTH`. Each [`MockRelay::connect`] hands back a
//! [`MockSocket`] implementing [`crate::transport::MeshSocket`], so a
//! [`crate::transport::RelayTransport`] can be exercised end-to-end without any
//! I/O. It supports the subset of NIP-01 filtering the mesh needs: `#p` tag and
//! `kinds`.
//!
//! This is `#[cfg(any(test, feature = "mock"))]`-free on purpose — it is a
//! first-class part of the crate's public surface so downstream substrates
//! (agentbox, VisionClaw) can reuse it in *their* conformance suites.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

use async_trait::async_trait;
use serde_json::Value;

use crate::transport::{MeshError, MeshSocket};

#[derive(Default)]
struct ClientState {
    inbound: VecDeque<String>,
    subs: Vec<(String, Filter)>,
    authed: bool,
}

#[derive(Clone, Default)]
struct Filter {
    kinds: Option<Vec<u64>>,
    p_tags: Option<Vec<String>>,
}

impl Filter {
    fn from_value(v: &Value) -> Self {
        let kinds = v
            .get("kinds")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_u64).collect());
        let p_tags = v
            .get("#p")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect());
        Filter { kinds, p_tags }
    }

    fn matches(&self, event: &Value) -> bool {
        if let Some(kinds) = &self.kinds {
            let k = event.get("kind").and_then(Value::as_u64).unwrap_or(u64::MAX);
            if !kinds.contains(&k) {
                return false;
            }
        }
        if let Some(ps) = &self.p_tags {
            let ok = event
                .get("tags")
                .and_then(Value::as_array)
                .map(|tags| {
                    tags.iter().any(|t| {
                        let t = t.as_array();
                        matches!(t, Some(arr)
                            if arr.first().and_then(Value::as_str) == Some("p")
                                && arr.get(1).and_then(Value::as_str).map(|v| ps.iter().any(|p| p == v)).unwrap_or(false))
                    })
                })
                .unwrap_or(false);
            if !ok {
                return false;
            }
        }
        true
    }
}

#[derive(Default)]
struct RelayState {
    clients: HashMap<usize, ClientState>,
    events: Vec<Value>,
    next_id: usize,
}

/// A minimal in-memory Nostr relay for tests and cross-substrate conformance.
#[derive(Clone)]
pub struct MockRelay {
    state: Rc<RefCell<RelayState>>,
}

impl MockRelay {
    /// A fresh, empty relay.
    pub fn new() -> Self {
        MockRelay { state: Rc::new(RefCell::new(RelayState::default())) }
    }

    /// Connect a new client, returning its socket.
    pub fn connect(&self) -> MockSocket {
        let mut st = self.state.borrow_mut();
        let id = st.next_id;
        st.next_id += 1;
        st.clients.insert(id, ClientState::default());
        MockSocket { client_id: id, state: Rc::clone(&self.state) }
    }

    /// Number of events the relay currently stores (fan-out assertions).
    pub fn stored_event_count(&self) -> usize {
        self.state.borrow().events.len()
    }

    fn handle_frame(&self, client_id: usize, text: &str) -> Result<(), MeshError> {
        let arr: Vec<Value> = serde_json::from_str(text)
            .map_err(|e| MeshError::Protocol(format!("mock relay: bad frame: {e}")))?;
        let tag = arr.first().and_then(Value::as_str).unwrap_or("");
        match tag {
            "EVENT" => {
                let event = arr.get(1).cloned().unwrap_or(Value::Null);
                let event_id = event.get("id").and_then(Value::as_str).unwrap_or("").to_string();
                {
                    let mut st = self.state.borrow_mut();
                    st.events.push(event.clone());
                }
                // Push to every client whose subscription matches.
                let deliveries = self.plan_deliveries(&event);
                let mut st = self.state.borrow_mut();
                for (cid, sub_id) in deliveries {
                    if let Some(c) = st.clients.get_mut(&cid) {
                        let frame = Value::Array(vec![
                            Value::String("EVENT".into()),
                            Value::String(sub_id),
                            event.clone(),
                        ]);
                        c.inbound.push_back(frame.to_string());
                    }
                }
                // OK ack to sender.
                if let Some(c) = st.clients.get_mut(&client_id) {
                    let ok = Value::Array(vec![
                        Value::String("OK".into()),
                        Value::String(event_id),
                        Value::Bool(true),
                        Value::String(String::new()),
                    ]);
                    c.inbound.push_back(ok.to_string());
                }
                Ok(())
            }
            "REQ" => {
                let sub_id = arr.get(1).and_then(Value::as_str).unwrap_or("").to_string();
                let filters: Vec<Filter> = arr.iter().skip(2).map(Filter::from_value).collect();
                let stored = self.state.borrow().events.clone();
                let mut st = self.state.borrow_mut();
                if let Some(c) = st.clients.get_mut(&client_id) {
                    for f in &filters {
                        c.subs.push((sub_id.clone(), f.clone()));
                    }
                    for ev in &stored {
                        if filters.iter().any(|f| f.matches(ev)) {
                            let frame = Value::Array(vec![
                                Value::String("EVENT".into()),
                                Value::String(sub_id.clone()),
                                ev.clone(),
                            ]);
                            c.inbound.push_back(frame.to_string());
                        }
                    }
                    let eose = Value::Array(vec![
                        Value::String("EOSE".into()),
                        Value::String(sub_id.clone()),
                    ]);
                    c.inbound.push_back(eose.to_string());
                }
                Ok(())
            }
            "AUTH" => {
                let mut st = self.state.borrow_mut();
                if let Some(c) = st.clients.get_mut(&client_id) {
                    c.authed = true;
                }
                Ok(())
            }
            "CLOSE" => {
                let sub_id = arr.get(1).and_then(Value::as_str).unwrap_or("").to_string();
                let mut st = self.state.borrow_mut();
                if let Some(c) = st.clients.get_mut(&client_id) {
                    c.subs.retain(|(s, _)| s != &sub_id);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Compute (client_id, sub_id) pairs an event should be pushed to.
    fn plan_deliveries(&self, event: &Value) -> Vec<(usize, String)> {
        let st = self.state.borrow();
        let mut out = Vec::new();
        for (cid, client) in &st.clients {
            for (sub_id, filter) in &client.subs {
                if filter.matches(event) {
                    out.push((*cid, sub_id.clone()));
                }
            }
        }
        out
    }
}

impl Default for MockRelay {
    fn default() -> Self {
        MockRelay::new()
    }
}

/// A client socket into a [`MockRelay`], implementing [`MeshSocket`].
#[derive(Clone)]
pub struct MockSocket {
    client_id: usize,
    state: Rc<RefCell<RelayState>>,
}

impl MockSocket {
    /// Whether the relay has marked this client authenticated (NIP-42).
    pub fn is_authenticated(&self) -> bool {
        self.state
            .borrow()
            .clients
            .get(&self.client_id)
            .map(|c| c.authed)
            .unwrap_or(false)
    }
}

#[async_trait(?Send)]
impl MeshSocket for MockSocket {
    async fn send_text(&self, msg: &str) -> Result<(), MeshError> {
        // Reconstruct a temporary relay handle sharing the same state.
        let relay = MockRelay { state: Rc::clone(&self.state) };
        relay.handle_frame(self.client_id, msg)
    }

    async fn recv_text(&self) -> Result<Option<String>, MeshError> {
        let mut st = self.state.borrow_mut();
        Ok(st
            .clients
            .get_mut(&self.client_id)
            .and_then(|c| c.inbound.pop_front()))
    }
}
