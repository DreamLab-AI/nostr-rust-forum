//! Shared test kit: an in-memory relay implementing the public `Relay` trait,
//! fixed test keys and event builders. No network.

#![allow(dead_code)]

use std::collections::HashSet;

use nostr_bbs_core::keys::{signing_key_from_bytes, SecretKey};
use nostr_bbs_core::sealed::has_sealed_tag;
use nostr_bbs_core::{sign_event, NostrEvent, UnsignedEvent};
use nostr_bbs_zone_migrate::engine::Hooks;
use nostr_bbs_zone_migrate::keys::{KeyRing, KeySource, ZoneKey};
use nostr_bbs_zone_migrate::relay::{
    DeleteOutcome, Filter, PublishOutcome, Relay, RelayError, MAX_DELETE_IDS, MAX_REQ_LIMIT,
};
use nostr_bbs_zone_migrate::state::{State, StateError};

pub const CHANNEL: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
pub const OTHER_CHANNEL: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
pub const RELAY_URL: &str = "wss://relay.test";

pub const AUTHOR: [u8; 32] = [0x11; 32];
pub const AUTHOR2: [u8; 32] = [0x12; 32];
pub const MIGRATOR: [u8; 32] = [0x22; 32];
pub const ZONE3_E1: [u8; 32] = [0x33; 32];
pub const ZONE3_E2: [u8; 32] = [0x34; 32];

/// Drive a future whose awaits never truly suspend (the fake relay is
/// synchronous) without an executor dependency.
pub fn block_on<F: std::future::Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

pub fn sk(bytes: [u8; 32]) -> SecretKey {
    SecretKey::from_bytes(bytes).unwrap()
}

pub fn pk(bytes: [u8; 32]) -> String {
    sk(bytes).public_key().to_hex()
}

pub fn sign(
    secret: [u8; 32],
    kind: u64,
    created_at: u64,
    tags: Vec<Vec<String>>,
    content: &str,
) -> NostrEvent {
    sign_event(
        UnsignedEvent {
            pubkey: pk(secret),
            created_at,
            kind,
            tags,
            content: content.to_string(),
        },
        &signing_key_from_bytes(&secret).unwrap(),
    )
    .unwrap()
}

pub fn tag(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// A plaintext kind-42 in `channel`.
pub fn post(secret: [u8; 32], channel: &str, created_at: u64, content: &str) -> NostrEvent {
    sign(
        secret,
        42,
        created_at,
        vec![tag(&["e", channel, "", "root"])],
        content,
    )
}

pub fn zone_key(zone: &str, epoch: u32, secret: [u8; 32], source: KeySource) -> ZoneKey {
    ZoneKey::new(zone, epoch, &hex::encode(secret), &pk(secret), source).unwrap()
}

/// Key ring holding zone3 epochs 1 and 2 (epoch 2 seals).
pub fn ring() -> KeyRing {
    let mut r = KeyRing::new();
    r.insert(zone_key("zone3", 1, ZONE3_E1, KeySource::KeyFile))
        .unwrap();
    r.insert(zone_key("zone3", 2, ZONE3_E2, KeySource::KeyFile))
        .unwrap();
    r
}

/// Collects persisted snapshots and progress lines.
#[derive(Default)]
pub struct Sink {
    pub saves: Vec<State>,
    pub lines: Vec<String>,
}

impl Sink {
    pub fn run<T>(&mut self, f: impl FnOnce(&mut Hooks<'_>) -> T) -> T {
        let saves = &mut self.saves;
        let lines = &mut self.lines;
        let mut persist = |s: &State| -> Result<(), StateError> {
            saves.push(s.clone());
            Ok(())
        };
        let mut progress = |l: &str| lines.push(l.to_string());
        let mut hooks = Hooks {
            persist: &mut persist,
            progress: &mut progress,
        };
        f(&mut hooks)
    }
}

/// In-memory relay with the kit relay's read and write semantics that the
/// migrator depends on.
#[derive(Default)]
pub struct FakeRelay {
    pub events: Vec<NostrEvent>,
    pub admins: HashSet<String>,
    pub queries: Vec<Filter>,
    pub published: Vec<NostrEvent>,
    pub delete_calls: Vec<(Vec<String>, String)>,
    /// Corrupt the content of the next stored envelope (read-back must fail).
    pub tamper_next_store: bool,
    /// Accept the next event with OK true but do not store it.
    pub drop_next_store: bool,
}

impl FakeRelay {
    pub fn with_admin(admin: &str) -> Self {
        let mut r = Self::default();
        r.admins.insert(admin.to_string());
        r
    }

    pub fn insert(&mut self, ev: NostrEvent) {
        if !self.events.iter().any(|e| e.id == ev.id) {
            self.events.push(ev);
        }
    }

    pub fn has(&self, id: &str) -> bool {
        self.events.iter().any(|e| e.id == id)
    }

    fn matches(f: &Filter, ev: &NostrEvent) -> bool {
        let tag_match = |name: &str, vals: &Option<Vec<String>>| {
            vals.as_ref().is_none_or(|vals| {
                ev.tags
                    .iter()
                    .any(|t| t.len() >= 2 && t[0] == name && vals.contains(&t[1]))
            })
        };
        f.ids.as_ref().is_none_or(|ids| ids.contains(&ev.id))
            && f.kinds.as_ref().is_none_or(|k| k.contains(&ev.kind))
            && tag_match("e", &f.e_tags)
            && tag_match("p", &f.p_tags)
            && f.until.is_none_or(|u| ev.created_at <= u)
    }
}

impl Relay for FakeRelay {
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

    async fn publish(&mut self, event: &NostrEvent) -> Result<PublishOutcome, RelayError> {
        self.published.push(event.clone());
        if has_sealed_tag(&event.tags) && !self.admins.contains(&event.pubkey) {
            return Ok(PublishOutcome {
                accepted: false,
                message: "blocked: sealed originals are admin-only".into(),
            });
        }
        if std::mem::take(&mut self.drop_next_store) {
            return Ok(PublishOutcome {
                accepted: true,
                message: String::new(),
            });
        }
        let mut stored = event.clone();
        if std::mem::take(&mut self.tamper_next_store) {
            stored.content = "AgAAAA".into();
        }
        self.insert(stored);
        Ok(PublishOutcome {
            accepted: true,
            message: String::new(),
        })
    }

    async fn is_admin(&mut self, pubkey: &str) -> Result<bool, RelayError> {
        Ok(self.admins.contains(pubkey))
    }

    async fn delete_events(
        &mut self,
        ids: &[String],
        reason: &str,
    ) -> Result<DeleteOutcome, RelayError> {
        if ids.is_empty() || ids.len() > MAX_DELETE_IDS {
            return Err(RelayError::Http {
                status: 400,
                body: r#"{"error":"ids must hold 1..=200 entries"}"#.into(),
            });
        }
        self.delete_calls.push((ids.to_vec(), reason.to_string()));
        let mut out = DeleteOutcome::default();
        for id in ids {
            match self.events.iter().position(|e| &e.id == id) {
                None => out.not_found.push(id.clone()),
                Some(i) if self.events[i].kind != 42 => out.skipped.push(id.clone()),
                Some(i) => {
                    self.events.remove(i);
                    out.deleted += 1;
                }
            }
        }
        Ok(out)
    }
}
