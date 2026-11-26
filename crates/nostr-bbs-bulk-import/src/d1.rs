//! The local D1 writer: ingest parity with the relay, a ledger, and the
//! control-plane rows an offline build cannot get from admin endpoints.
//!
//! Writes go straight into the D1 SQLite file (the miniflare file under
//! `--persist-to …/d1/…`, or any SQLite built from the relay migrations),
//! one `BEGIN IMMEDIATE` transaction per batch, with every value bound
//! (never interpolated). The relay must be **down**: an open database is
//! refused rather than waited for.
//!
//! Rows written per event, mirroring `relay_do/storage.rs` `save_event`:
//!
//! | Row | SQL |
//! |---|---|
//! | `events` | plain insert for regular kinds; insert-if-not-beaten + prune for replaceable kinds (0, 3, 10000–19999) and addressable kinds (30000–39999); every insert refuses an id tombstoned in `deleted_events` (the relay's `is_deleted` gate) |
//! | `event_tags` | the relay trigger `trg_event_tags_ai_v3`, never by hand |
//! | `channel_creators` | kind 40, first write wins, only when the event row was inserted |
//! | `profiles` | kind 0, the relay's guarded upsert, only when the event row was inserted |
//!
//! Control rows ([`ControlPlan`]): `whitelist` through
//! [`nostr_bbs_core::whitelist_sql::WHITELIST_GRANT_COHORTS_SQL`] (merge-only
//! cohorts) plus a separate `is_admin` update, `channel_zones` with the
//! admin endpoint's upsert, `pubkey_aliases` with the relay's guarded upsert,
//! and `posts_created` / `last_active_at` as `MAX` over the ledger.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use nostr_bbs_core::NostrEvent;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::error::ImportError;
use crate::events::LedgerRow;
use crate::fsutil;

/// Events per transaction.
pub const BATCH: usize = 500;

/// Kinds the relay counts as posts (`nip_handlers.rs` `counts_as_post`).
pub const COUNTS_AS_POST: &[u64] = &[1, 7, 9, 40, 42, 1984];

/// The relay's tag writer (installed by `ensure_schema`).
pub const TAG_TRIGGER: &str = "trg_event_tags_ai_v3";
/// The tag cleaner on delete (migration 0004).
pub const TAG_DELETE_TRIGGER: &str = "trg_event_tags_ad";

const INSERT_SQL: &str =
    "INSERT INTO events (id, pubkey, created_at, kind, tags, content, sig, d_tag, received_at) \
     SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9 \
     WHERE NOT EXISTS (SELECT 1 FROM deleted_events WHERE id = ?1 AND pubkey = ?2) \
     ON CONFLICT (id) DO NOTHING";

const REPLACEABLE_INSERT_SQL: &str =
    "INSERT INTO events (id, pubkey, created_at, kind, tags, content, sig, d_tag, received_at) \
     SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9 \
     WHERE NOT EXISTS (SELECT 1 FROM events WHERE pubkey = ?2 AND kind = ?4 AND id <> ?1 \
         AND (created_at > ?3 OR (created_at = ?3 AND id < ?1))) \
       AND NOT EXISTS (SELECT 1 FROM deleted_events WHERE id = ?1 AND pubkey = ?2) \
     ON CONFLICT (id) DO NOTHING";

const REPLACEABLE_PRUNE_SQL: &str =
    "DELETE FROM events WHERE pubkey = ?2 AND kind = ?4 AND id <> ?1 \
     AND (created_at < ?3 OR (created_at = ?3 AND id > ?1))";

const ADDRESSABLE_INSERT_SQL: &str = "INSERT INTO events (id, pubkey, created_at, kind, tags, content, sig, d_tag, received_at) \
     SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9 \
     WHERE NOT EXISTS (SELECT 1 FROM events WHERE pubkey = ?2 AND kind = ?4 AND d_tag = ?8 AND id <> ?1 \
         AND (created_at > ?3 OR (created_at = ?3 AND id < ?1))) \
       AND NOT EXISTS (SELECT 1 FROM deleted_events WHERE id = ?1 AND pubkey = ?2) \
     ON CONFLICT (id) DO NOTHING";

const ADDRESSABLE_PRUNE_SQL: &str =
    "DELETE FROM events WHERE pubkey = ?2 AND kind = ?4 AND d_tag = ?5 AND id <> ?1 \
     AND (created_at < ?3 OR (created_at = ?3 AND id > ?1))";

const CHANNEL_CREATORS_SQL: &str = "INSERT INTO channel_creators (channel_id, pubkey, created_at) \
     VALUES (?1, ?2, ?3) ON CONFLICT (channel_id) DO NOTHING";

const PROFILE_SQL: &str = "INSERT INTO profiles \
        (pubkey, name, display_name, picture, banner, about, nip05, lud16, last_kind0_at, raw_event) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
     ON CONFLICT (pubkey) DO UPDATE SET \
         name = excluded.name, display_name = excluded.display_name, picture = excluded.picture, \
         banner = excluded.banner, about = excluded.about, nip05 = excluded.nip05, lud16 = excluded.lud16, \
         last_kind0_at = excluded.last_kind0_at, raw_event = excluded.raw_event \
     WHERE excluded.last_kind0_at >= profiles.last_kind0_at";

/// `POST /api/admin/channel-zone`'s upsert (`lib.rs`).
pub const CHANNEL_ZONE_SQL: &str = "INSERT INTO channel_zones (channel_id, zone, archived) \
     VALUES (?1, ?2, ?3) \
     ON CONFLICT (channel_id) DO UPDATE SET zone = excluded.zone, archived = excluded.archived";

/// `user_admin.rs` `ALIAS_UPSERT_GUARDED_SQL`: no chains, no loops. Binds:
/// new, old, created_by, created_at, reason.
pub const ALIAS_UPSERT_GUARDED_SQL: &str = "INSERT INTO pubkey_aliases \
     (new_pubkey, old_pubkey, created_by, created_at, reason) \
     SELECT ?1, ?2, ?3, ?4, ?5 \
     WHERE NOT EXISTS (SELECT 1 FROM pubkey_aliases WHERE new_pubkey = ?2) \
       AND NOT EXISTS (SELECT 1 FROM pubkey_aliases WHERE old_pubkey = ?1) \
     ON CONFLICT (old_pubkey) DO UPDATE SET \
        new_pubkey = excluded.new_pubkey, created_by = excluded.created_by, \
        created_at = excluded.created_at, reason = excluded.reason";

/// Open the D1 file for writing. Refuses when another process holds it
/// (the relay is running): the build needs the stack down.
pub fn open_rw(path: &Path) -> Result<Connection, ImportError> {
    if !path.is_file() {
        return Err(ImportError::Refused(format!(
            "{} is not a D1 SQLite file (boot the relay once, then stop it)",
            path.display()
        )));
    }
    let c = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    c.busy_timeout(std::time::Duration::from_millis(0))?;
    c.execute_batch("BEGIN IMMEDIATE; ROLLBACK;").map_err(|_| {
        ImportError::Refused(format!(
            "{} is locked: stop the local relay (wrangler dev) before building",
            path.display()
        ))
    })?;
    Ok(c)
}

/// Open the D1 file read-only (safe while the relay runs).
pub fn open_ro(path: &Path) -> Result<Connection, ImportError> {
    Ok(Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?)
}

/// Refuse a database the relay has not booted (tables and triggers made by
/// the migrations and `ensure_schema`).
pub fn check_schema(c: &Connection) -> Result<(), ImportError> {
    let mut missing = Vec::new();
    for (kind, name) in [
        ("table", "events"),
        ("table", "event_tags"),
        ("table", "channel_creators"),
        ("table", "profiles"),
        ("table", "channel_zones"),
        ("table", "whitelist"),
        ("table", "deleted_events"),
        ("table", "pubkey_aliases"),
        ("table", "admin_log"),
        ("trigger", TAG_TRIGGER),
        ("trigger", TAG_DELETE_TRIGGER),
    ] {
        let n: i64 = c.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = ?1 AND name = ?2",
            params![kind, name],
            |r| r.get(0),
        )?;
        if n == 0 {
            missing.push(format!("{kind} {name}"));
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(ImportError::Refused(format!(
            "the D1 is missing {}: apply the relay migrations and boot the current relay once (ensure_schema), then stop it",
            missing.join(", ")
        )))
    }
}

/// The state directory's binding to one database and one target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunBinding {
    /// Always 1.
    pub version: u32,
    /// Canonical path of the D1 file.
    pub d1: String,
    /// Target name.
    pub target: String,
    /// Pod URL embedded in content.
    pub pod_http: String,
    /// `<source>:<source_id>`.
    pub provenance: String,
}

impl RunBinding {
    /// Bind `state_dir` (create `run.json`) or check an existing binding.
    pub fn bind(state_dir: &Path, want: &RunBinding) -> Result<(), ImportError> {
        fsutil::create_private_dir(state_dir)?;
        let p = state_dir.join("run.json");
        match std::fs::read(&p) {
            Ok(b) => {
                let have: RunBinding = serde_json::from_slice(&b)
                    .map_err(|e| ImportError::Format(format!("{}: {e}", p.display())))?;
                if &have != want {
                    return Err(ImportError::Refused(format!(
                        "state directory {} is bound to d1={} target={} ({}) source={}; this run is d1={} target={} ({}) source={}. Use another --state directory",
                        state_dir.display(), have.d1, have.target, have.pod_http, have.provenance, want.d1, want.target, want.pod_http, want.provenance
                    )));
                }
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => fsutil::write_private_atomic(
                &p,
                &serde_json::to_vec_pretty(want).expect("binding serialises"),
            ),
            Err(e) => Err(ImportError::io(&p, e)),
        }
    }
}

/// The ledger: what this source already stored, by key.
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    path: PathBuf,
    /// Key → row.
    pub rows: HashMap<String, LedgerRow>,
}

impl Ledger {
    /// Load `state/ledger.jsonl` (a torn last line is ignored), then add
    /// every row D1 holds for `provenance` through its `import` tags and
    /// append those the file lacked (a crash between commit and append).
    pub fn load(state_dir: &Path, c: &Connection, provenance: &str) -> Result<Self, ImportError> {
        let path = state_dir.join("ledger.jsonl");
        let mut rows = HashMap::new();
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                for line in text.lines() {
                    if let Ok(r) = serde_json::from_str::<LedgerRow>(line) {
                        rows.insert(r.k.clone(), r);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(ImportError::io(&path, e)),
        }
        let prefix = format!("{provenance}#");
        let mut s = c.prepare(
            "SELECT t.value, e.id, e.pubkey, e.created_at, e.kind FROM event_tags t JOIN events e ON e.id = t.event_id \
             WHERE t.name = 'import' AND substr(t.value, 1, length(?1)) = ?1",
        )?;
        let from_db: Vec<LedgerRow> = s
            .query_map([&prefix], |r| {
                Ok(LedgerRow {
                    k: r.get(0)?,
                    id: r.get(1)?,
                    pk: r.get(2)?,
                    t: r.get::<_, i64>(3)? as u64,
                    kind: r.get::<_, i64>(4)? as u64,
                })
            })?
            .collect::<Result<_, _>>()?;
        let mut heal = String::new();
        for r in from_db {
            match rows.get(&r.k) {
                Some(have) if have.id == r.id => {}
                Some(have) => {
                    return Err(ImportError::Refused(format!(
                        "ledger and D1 disagree for {}: ledger id {} but D1 holds {}",
                        r.k, have.id, r.id
                    )))
                }
                None => {
                    heal.push_str(&serde_json::to_string(&r).expect("row serialises"));
                    heal.push('\n');
                    rows.insert(r.k.clone(), r);
                }
            }
        }
        if !heal.is_empty() {
            fsutil::append_private(&path, heal.as_bytes())?;
        }
        Ok(Ledger { path, rows })
    }

    fn append(&mut self, new: &[LedgerRow]) -> Result<(), ImportError> {
        if new.is_empty() {
            return Ok(());
        }
        let mut buf = String::new();
        for r in new {
            buf.push_str(&serde_json::to_string(r).expect("row serialises"));
            buf.push('\n');
        }
        fsutil::append_private(&self.path, buf.as_bytes())?;
        for r in new {
            self.rows.insert(r.k.clone(), r.clone());
        }
        Ok(())
    }

    /// Keep only the rows `keep` accepts, rewriting the ledger file
    /// atomically (used by `reset`).
    pub fn retain(&mut self, keep: impl Fn(&LedgerRow) -> bool) -> Result<(), ImportError> {
        self.rows.retain(|_, r| keep(r));
        let mut rows: Vec<&LedgerRow> = self.rows.values().collect();
        rows.sort_by(|a, b| a.k.cmp(&b.k));
        let mut buf = String::new();
        for r in rows {
            buf.push_str(&serde_json::to_string(r).expect("row serialises"));
            buf.push('\n');
        }
        fsutil::write_private_atomic(&self.path, buf.as_bytes())
    }

    /// Ledgered ids that D1 has tombstoned: non-zero once a purge ran.
    pub fn purged_count(&self, c: &Connection) -> Result<usize, ImportError> {
        let mut s = c.prepare("SELECT 1 FROM deleted_events WHERE id = ?1 AND pubkey = ?2")?;
        let mut n = 0;
        for r in self.rows.values() {
            if s.exists(params![r.id, r.pk])? {
                n += 1;
            }
        }
        Ok(n)
    }
}

fn d_tag(ev: &NostrEvent) -> String {
    ev.tags
        .iter()
        .find(|t| t.first().map(String::as_str) == Some("d"))
        .and_then(|t| t.get(1).cloned())
        .unwrap_or_default()
}

/// Insert one event with the relay's rows. Returns whether the event row
/// was inserted.
pub fn insert_event(
    tx: &Connection,
    ev: &NostrEvent,
    received_at: u64,
) -> Result<bool, ImportError> {
    let tags = serde_json::to_string(&ev.tags).expect("tags serialise");
    let d = d_tag(ev);
    let k = ev.kind;
    let replaceable = k == 0 || k == 3 || (10_000..20_000).contains(&k);
    let addressable = (30_000..40_000).contains(&k);
    let binds = params![
        ev.id,
        ev.pubkey,
        ev.created_at as i64,
        k as i64,
        tags,
        ev.content,
        ev.sig,
        d,
        received_at as i64
    ];
    let n = if replaceable {
        let n = tx.prepare_cached(REPLACEABLE_INSERT_SQL)?.execute(binds)?;
        tx.prepare_cached(REPLACEABLE_PRUNE_SQL)?.execute(params![
            ev.id,
            ev.pubkey,
            ev.created_at as i64,
            k as i64
        ])?;
        n
    } else if addressable {
        let n = tx.prepare_cached(ADDRESSABLE_INSERT_SQL)?.execute(binds)?;
        tx.prepare_cached(ADDRESSABLE_PRUNE_SQL)?.execute(params![
            ev.id,
            ev.pubkey,
            ev.created_at as i64,
            k as i64,
            d
        ])?;
        n
    } else {
        tx.prepare_cached(INSERT_SQL)?.execute(binds)?
    };
    if n == 0 {
        return Ok(false);
    }
    if k == 40 {
        tx.prepare_cached(CHANNEL_CREATORS_SQL)?.execute(params![
            ev.id,
            ev.pubkey,
            ev.created_at as i64
        ])?;
    }
    if k == 0 {
        if let Ok(serde_json::Value::Object(o)) =
            serde_json::from_str::<serde_json::Value>(&ev.content)
        {
            let f = |key: &str| o.get(key).and_then(|v| v.as_str()).map(str::to_string);
            let raw = serde_json::json!({"id": ev.id, "pubkey": ev.pubkey, "created_at": ev.created_at, "kind": ev.kind, "tags": ev.tags, "content": ev.content, "sig": ev.sig}).to_string();
            tx.prepare_cached(PROFILE_SQL)?.execute(params![
                ev.pubkey,
                f("name"),
                f("display_name").or_else(|| f("displayName")),
                f("picture"),
                f("banner"),
                f("about"),
                f("nip05"),
                f("lud16"),
                ev.created_at as i64,
                raw
            ])?;
        }
    }
    Ok(true)
}

/// What [`apply_events`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ApplyReport {
    /// Events whose row was inserted.
    pub inserted: usize,
    /// Events already present, superseded or tombstoned.
    pub unchanged: usize,
    /// Transactions committed.
    pub batches: usize,
}

/// Insert `(ledger key, event)` pairs in batches of [`BATCH`], one
/// transaction each; the ledger is appended after each commit.
pub fn apply_events(
    c: &mut Connection,
    ledger: &mut Ledger,
    events: &[(String, NostrEvent)],
    mut progress: impl FnMut(usize, usize),
) -> Result<ApplyReport, ImportError> {
    let now = fsutil::now();
    let mut report = ApplyReport::default();
    for chunk in events.chunks(BATCH) {
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut rows = Vec::new();
        for (key, ev) in chunk {
            if insert_event(&tx, ev, now)? {
                report.inserted += 1;
            } else {
                report.unchanged += 1;
            }
            let stored: Option<String> = tx
                .prepare_cached("SELECT id FROM events WHERE id = ?1")?
                .query_row([&ev.id], |r| r.get(0))
                .optional()?;
            if stored.is_some() {
                rows.push(LedgerRow {
                    k: key.clone(),
                    id: ev.id.clone(),
                    pk: ev.pubkey.clone(),
                    t: ev.created_at,
                    kind: ev.kind,
                });
            }
        }
        tx.commit()?;
        ledger.append(&rows)?;
        report.batches += 1;
        progress(report.inserted + report.unchanged, events.len());
    }
    Ok(report)
}

/// One whitelist row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WhitelistRow {
    /// Pubkey.
    pub pubkey: String,
    /// Cohorts merged in.
    pub cohorts: Vec<String>,
    /// Admin.
    pub admin: bool,
}

/// Control-plane rows for an offline build. Every grant also gets the
/// `admin_log` row the relay's admin endpoint would write (actor = the
/// archivist, reason `bulk-import`), so offline changes stay auditable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ControlPlan {
    /// Pubkey recorded as the actor of the audit rows.
    pub actor: String,
    /// Whitelist grants.
    pub whitelist: Vec<WhitelistRow>,
    /// New thread id → zone.
    pub channel_zones: Vec<(String, String)>,
    /// `(old/archive key, live key)`.
    pub aliases: Vec<(String, String)>,
}

const AUDIT_SQL: &str = "INSERT INTO admin_log (actor_pubkey, action, target_pubkey, target_id, previous_value, new_value, reason, created_at) \
     SELECT ?1, ?2, ?3, ?4, ?5, ?6, 'bulk-import', ?7 \
     WHERE NOT EXISTS (SELECT 1 FROM admin_log WHERE action = ?2 AND target_pubkey IS ?3 AND target_id IS ?4 \
                       AND new_value IS ?6 AND reason = 'bulk-import')";

/// Write the control rows, their audit rows and the activity counters
/// (idempotent).
pub fn apply_control(
    c: &mut Connection,
    plan: &ControlPlan,
    ledger: &Ledger,
) -> Result<(), ImportError> {
    let now = fsutil::now() as i64;
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let audit = |tx: &rusqlite::Transaction<'_>,
                 action: &str,
                 tpk: Option<&str>,
                 tid: Option<&str>,
                 prev: Option<&str>,
                 new: Option<&str>|
     -> Result<(), ImportError> {
        tx.prepare_cached(AUDIT_SQL)?
            .execute(params![plan.actor, action, tpk, tid, prev, new, now])?;
        Ok(())
    };
    for w in &plan.whitelist {
        if w.cohorts.iter().any(|x| x == "agent") {
            return Err(ImportError::Refused(
                "the agent cohort is never granted".into(),
            ));
        }
        let cohorts = serde_json::to_string(&w.cohorts).expect("cohorts serialise");
        tx.prepare_cached(nostr_bbs_core::whitelist_sql::WHITELIST_GRANT_COHORTS_SQL)?
            .execute(params![w.pubkey, cohorts, now, "bulk-import"])?;
        audit(
            &tx,
            "whitelist_add",
            Some(&w.pubkey),
            None,
            None,
            Some(&cohorts),
        )?;
        if w.admin {
            tx.prepare_cached("UPDATE whitelist SET is_admin = 1 WHERE pubkey = ?1")?
                .execute([&w.pubkey])?;
            audit(
                &tx,
                "admin_grant",
                Some(&w.pubkey),
                None,
                Some("0"),
                Some("1"),
            )?;
        }
    }
    for (ch, zone) in &plan.channel_zones {
        tx.prepare_cached(CHANNEL_ZONE_SQL)?
            .execute(params![ch, zone, 0])?;
        audit(&tx, "channel_zone_set", None, Some(ch), None, Some(zone))?;
    }
    for (old, new) in &plan.aliases {
        let n = tx
            .prepare_cached(ALIAS_UPSERT_GUARDED_SQL)?
            .execute(params![
                new.to_lowercase(),
                old.to_lowercase(),
                "bulk-import",
                now,
                "archive key of an imported history"
            ])?;
        if n == 0 {
            let have: Option<String> = tx
                .prepare_cached("SELECT new_pubkey FROM pubkey_aliases WHERE old_pubkey = ?1")?
                .query_row([old.to_lowercase()], |r| r.get(0))
                .optional()?;
            if have.as_deref() == Some(new.to_lowercase().as_str()) {
                audit(
                    &tx,
                    "pubkey_alias_set",
                    Some(&new.to_lowercase()),
                    Some(&old.to_lowercase()),
                    None,
                    None,
                )?;
            } else {
                return Err(ImportError::Refused(format!(
                    "alias {}… → {}… refused by the chain guard (one of the keys is already linked)",
                    &old[..8.min(old.len())],
                    &new[..8.min(new.len())]
                )));
            }
        } else {
            audit(
                &tx,
                "pubkey_alias_set",
                Some(&new.to_lowercase()),
                Some(&old.to_lowercase()),
                None,
                None,
            )?;
        }
    }
    let mut per: BTreeMap<&str, (i64, i64)> = BTreeMap::new();
    for r in ledger.rows.values() {
        if COUNTS_AS_POST.contains(&r.kind) {
            let e = per.entry(r.pk.as_str()).or_insert((0, 0));
            e.0 += 1;
            e.1 = e.1.max(r.t as i64);
        }
    }
    for (pk, (n, last)) in per {
        tx.prepare_cached(
            "UPDATE whitelist SET posts_created = MAX(posts_created, ?2), last_active_at = MAX(COALESCE(last_active_at, 0), ?3) WHERE pubkey = ?1",
        )?
        .execute(params![pk, n, last])?;
    }
    tx.commit()?;
    Ok(())
}

/// Read a channel zone binding.
pub fn channel_zone(c: &Connection, channel: &str) -> Result<Option<String>, ImportError> {
    Ok(c.query_row(
        "SELECT zone FROM channel_zones WHERE channel_id = ?1",
        [channel],
        |r| r.get(0),
    )
    .optional()?)
}

/// Whether a kind-40 with this id is stored.
pub fn has_channel(c: &Connection, id: &str) -> Result<bool, ImportError> {
    Ok(
        c.prepare_cached("SELECT 1 FROM events WHERE id = ?1 AND kind = 40")?
            .exists([id])?,
    )
}

/// Read every stored event (for parity checks and the upload dump).
pub fn read_events(c: &Connection, where_sql: &str) -> Result<Vec<NostrEvent>, ImportError> {
    let mut s = c.prepare(&format!(
        "SELECT id, pubkey, created_at, kind, tags, content, sig FROM events {where_sql}"
    ))?;
    let rows = s.query_map([], |r| {
        let tags: String = r.get(4)?;
        Ok(NostrEvent {
            id: r.get(0)?,
            pubkey: r.get(1)?,
            created_at: r.get::<_, i64>(2)? as u64,
            kind: r.get::<_, i64>(3)? as u64,
            tags: serde_json::from_str(&tags).unwrap_or_default(),
            content: r.get(5)?,
            sig: r.get(6)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// The `event_tags` rows the v3 trigger writes for `ev`: DISTINCT
/// `(name, value)` pairs of array tags with a name, `probe` excluded.
pub fn expected_tag_rows(ev: &NostrEvent) -> usize {
    let set: BTreeSet<(&str, &str)> = ev
        .tags
        .iter()
        .filter_map(|t| {
            let name = t.first()?.as_str();
            (name != "probe").then(|| (name, t.get(1).map(String::as_str).unwrap_or("")))
        })
        .collect();
    set.len()
}
