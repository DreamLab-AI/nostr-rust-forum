//! Shared fixtures: a relay D1 built from the real migrations plus the
//! boot SQL, a fake relay for zone-migrate's online verify, hooks.

#![allow(dead_code)]

use std::collections::HashSet;
use std::path::Path;

use nostr_bbs_core::NostrEvent;
use nostr_bbs_zone_migrate::engine::Hooks;
use nostr_bbs_zone_migrate::relay::{
    DeleteOutcome, Filter, PublishOutcome, Relay, RelayError, MAX_REQ_LIMIT,
};
use nostr_bbs_zone_migrate::state::{State, StateError};
use rusqlite::Connection;

const M0001: &str = include_str!("../../../nostr-bbs-relay-worker/migrations/0001_profiles.sql");
const M0003: &str =
    include_str!("../../../nostr-bbs-relay-worker/migrations/0003_pubkey_aliases.sql");
const M0004: &str = include_str!("../../../nostr-bbs-relay-worker/migrations/0004_event_tags.sql");
const M0008: &str = include_str!("../../../nostr-bbs-relay-worker/migrations/0008_whitelist.sql");
const M0009: &str = include_str!("../../../nostr-bbs-relay-worker/migrations/0009_events.sql");
const M0015: &str =
    include_str!("../../../nostr-bbs-relay-worker/migrations/0015_event_tags_time_backfill.sql");
const M0016: &str =
    include_str!("../../../nostr-bbs-relay-worker/migrations/0016_pubkey_aliases_many_to_one.sql");

/// What the relay's `ensure_schema()` adds on boot that the migrations do
/// not (lib.rs `PROBE_BLIND_STMTS`, `DELETED_EVENTS_CREATE_SQL`, the
/// `channel_zones` and `admin_log` creates). The drift test holds these
/// fragments against lib.rs.
pub const BOOT_SQL: &str = "
DROP TRIGGER IF EXISTS trg_event_tags_ai;
DROP TRIGGER IF EXISTS trg_event_tags_ai_v2;
CREATE TRIGGER IF NOT EXISTS trg_event_tags_ai_v3 AFTER INSERT ON events BEGIN
  INSERT INTO event_tags (event_id, name, value, created_at)
  SELECT DISTINCT NEW.id, json_extract(je.value, '$[0]'), COALESCE(json_extract(je.value, '$[1]'), ''), NEW.created_at
  FROM json_each(NEW.tags) je
  WHERE json_type(je.value) = 'array' AND json_extract(je.value, '$[0]') IS NOT NULL
    AND json_extract(je.value, '$[0]') <> 'probe';
END;
CREATE TRIGGER IF NOT EXISTS trg_event_tags_probe_blind AFTER INSERT ON event_tags WHEN NEW.name = 'probe'
  BEGIN DELETE FROM event_tags WHERE event_id = NEW.event_id AND name = 'probe'; END;
CREATE TABLE IF NOT EXISTS deleted_events (id TEXT NOT NULL, pubkey TEXT NOT NULL, deleted_at INTEGER NOT NULL, PRIMARY KEY (id, pubkey));
CREATE TABLE IF NOT EXISTS channel_zones (channel_id TEXT PRIMARY KEY, zone TEXT NOT NULL DEFAULT 'home', archived INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS admin_log (id INTEGER PRIMARY KEY AUTOINCREMENT, actor_pubkey TEXT NOT NULL, action TEXT NOT NULL, target_pubkey TEXT, target_id TEXT, previous_value TEXT, new_value TEXT, reason TEXT, created_at INTEGER NOT NULL);
";

/// A relay D1 file at `path`: the migrations the importer touches, 0009
/// first, then the boot SQL, as a deployment gets after the runbook's
/// migration pass and one relay boot.
pub fn relay_db(path: &Path) -> Connection {
    let _ = std::fs::remove_file(path);
    let c = Connection::open(path).unwrap();
    // 0004's trigger reads `events`, which 0009 creates: 0009 first (it is
    // IF NOT EXISTS, so the numeric pass re-runs it harmlessly), as the
    // pilot's apply-migrations.sh and the upload runbook do.
    for m in [M0009, M0001, M0003, M0004, M0008, M0009, M0015, M0016] {
        c.execute_batch(m).unwrap();
    }
    c.execute_batch(BOOT_SQL).unwrap();
    c
}

pub fn block_on<F: std::future::Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

/// Hooks that keep nothing (the test inspects the state directly).
pub fn with_hooks<T>(f: impl FnOnce(&mut Hooks<'_>) -> T) -> T {
    let mut persist = |_: &State| -> Result<(), StateError> { Ok(()) };
    let mut checkpoint = |_: &State| -> Result<(), StateError> { Ok(()) };
    let mut progress = |_: &str| {};
    let mut hooks = Hooks {
        persist: &mut persist,
        checkpoint: &mut checkpoint,
        progress: &mut progress,
    };
    f(&mut hooks)
}

/// Every event in the database.
pub fn all_events(c: &Connection) -> Vec<NostrEvent> {
    let mut s = c
        .prepare("SELECT id, pubkey, created_at, kind, tags, content, sig FROM events")
        .unwrap();
    s.query_map([], |r| {
        Ok(NostrEvent {
            id: r.get(0)?,
            pubkey: r.get(1)?,
            created_at: r.get::<_, i64>(2)? as u64,
            kind: r.get::<_, i64>(3)? as u64,
            tags: serde_json::from_str(&r.get::<_, String>(4)?).unwrap(),
            content: r.get(5)?,
            sig: r.get(6)?,
        })
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

/// An in-memory relay with the read semantics zone-migrate's `verify`
/// relies on (a copy of zone-migrate's own test relay, reduced).
#[derive(Default)]
pub struct FakeRelay {
    pub events: Vec<NostrEvent>,
    pub admins: HashSet<String>,
}

impl FakeRelay {
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
            && tag_match("zk", &f.zk_tags)
            && f.until.is_none_or(|u| ev.created_at <= u)
    }
}

impl Relay for FakeRelay {
    async fn query(&mut self, filter: &Filter) -> Result<Vec<NostrEvent>, RelayError> {
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
        self.events.push(event.clone());
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
        _ids: &[String],
        _reason: &str,
    ) -> Result<DeleteOutcome, RelayError> {
        Err(RelayError::Http {
            status: 405,
            body: "the e2e test purges offline".into(),
        })
    }
}
