//! An in-memory, read-only relay over NIP-01 events: a JSONL export of a
//! zone's events (`--from-events`), or a test fixture.
//!
//! It answers REQs with the same filter semantics the kit relay applies to
//! the fields the builder uses (`ids`, `kinds`, `#e`, `#p`, `#zk`,
//! `#sealed`, `since`, `until`, `limit`; newest first, `limit` capped at
//! [`MAX_REQ_LIMIT`]).

use std::path::Path;

use nostr_bbs_core::NostrEvent;
use nostr_bbs_zone_migrate::relay::{
    DeleteOutcome, Filter, PublishOutcome, Relay, RelayError, MAX_REQ_LIMIT,
};

/// The in-memory relay.
#[derive(Debug, Default, Clone)]
pub struct MemRelay {
    events: Vec<NostrEvent>,
    authenticated: bool,
    /// Every filter asked, in order (for tests).
    pub queries: Vec<Filter>,
}

impl MemRelay {
    /// A relay holding `events`, answering as an authenticated session.
    pub fn new(events: Vec<NostrEvent>) -> Self {
        let mut r = Self {
            events: Vec::new(),
            authenticated: true,
            queries: Vec::new(),
        };
        for ev in events {
            r.insert(ev);
        }
        r
    }

    /// Read NIP-01 events, one JSON object per line (blank lines skipped).
    ///
    /// # Errors
    ///
    /// When the file cannot be read or a line is not an event (the message
    /// names the line number only, never its content).
    pub fn from_jsonl(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let mut events = Vec::new();
        for (i, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let ev: NostrEvent = serde_json::from_str(line)
                .map_err(|_| format!("{} line {} is not an event", path.display(), i + 1))?;
            events.push(ev);
        }
        Ok(Self::new(events))
    }

    /// Answer as an unauthenticated session (tests of the refusal paths).
    pub fn unauthenticated(mut self) -> Self {
        self.authenticated = false;
        self
    }

    /// Store an event (ignored when its id is already held).
    pub fn insert(&mut self, ev: NostrEvent) {
        if !self.events.iter().any(|e| e.id == ev.id) {
            self.events.push(ev);
        }
    }

    /// Remove an event, as the relay does on an authorised kind-5.
    pub fn remove(&mut self, id: &str) {
        self.events.retain(|e| e.id != id);
    }

    /// The events held.
    pub fn into_events(self) -> Vec<NostrEvent> {
        self.events
    }

    /// Events held.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether no event is held.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    fn matches(f: &Filter, ev: &NostrEvent) -> bool {
        let tag = |name: &str, vals: &Option<Vec<String>>| {
            vals.as_ref().is_none_or(|vals| {
                ev.tags
                    .iter()
                    .any(|t| t.len() >= 2 && t[0] == name && vals.contains(&t[1]))
            })
        };
        f.ids.as_ref().is_none_or(|ids| ids.contains(&ev.id))
            && f.kinds.as_ref().is_none_or(|k| k.contains(&ev.kind))
            && tag("e", &f.e_tags)
            && tag("p", &f.p_tags)
            && tag("zk", &f.zk_tags)
            && tag("sealed", &f.sealed_tags)
            && f.since.is_none_or(|s| ev.created_at >= s)
            && f.until.is_none_or(|u| ev.created_at <= u)
    }
}

impl Relay for MemRelay {
    fn session_authenticated(&self) -> bool {
        self.authenticated
    }

    async fn query(&mut self, filter: &Filter) -> Result<Vec<NostrEvent>, RelayError> {
        self.queries.push(filter.clone());
        let limit = filter.limit.unwrap_or(500).min(MAX_REQ_LIMIT) as usize;
        let mut out: Vec<NostrEvent> = self
            .events
            .iter()
            .filter(|e| Self::matches(filter, e))
            .cloned()
            .collect();
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.id.cmp(&b.id)));
        out.truncate(limit);
        Ok(out)
    }

    async fn publish(&mut self, _event: &NostrEvent) -> Result<PublishOutcome, RelayError> {
        Ok(PublishOutcome {
            accepted: false,
            message: "blocked: read-only relay".into(),
        })
    }

    async fn is_admin(&mut self, _pubkey: &str) -> Result<bool, RelayError> {
        Ok(false)
    }

    async fn delete_events(
        &mut self,
        _ids: &[String],
        _reason: &str,
    ) -> Result<DeleteOutcome, RelayError> {
        Err(RelayError::Protocol("read-only relay".into()))
    }
}
