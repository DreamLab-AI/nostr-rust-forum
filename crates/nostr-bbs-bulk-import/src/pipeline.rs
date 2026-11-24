//! The pipeline steps the CLI runs, over one work directory.
//!
//! ```text
//! <work>/archive/          intermediate archive (adapt)
//! <work>/identities.json   identity decisions (template: plan)
//! <work>/structure.json    channel → thread map (template: plan)
//! <work>/target.json       embedded URLs
//! <work>/keys.json         secrets (keys), 0600
//! <work>/media/            optimised images + manifest (media)
//! <work>/state/            ledger.jsonl + run.json (build)
//! <work>/seal/             channels.json + RUNBOOK.md (seal-prep)
//! <work>/search/docs.jsonl search-build input (search-input), 0600
//! <work>/upload/           dump, object lists, runbook (upload-plan)
//! ```

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use nostr_bbs_core::NostrEvent;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use crate::d1::{self, ControlPlan, Ledger, RunBinding, WhitelistRow};
use crate::error::ImportError;
use crate::events::{self, Emit, SignInput};
use crate::format::Archive;
use crate::fsutil;
use crate::identity::{self, IdentityFile, IdentityPlan, Signer, ARCHIVIST, OPERATOR};
use crate::keystore::{Keystore, Role};
use crate::media::MediaManifest;
use crate::plan::{self, ImportPlan, Part};
use crate::structure::{Structure, ThreadChannel};
use crate::target::Target;

/// Paths inside a work directory.
#[derive(Debug, Clone)]
pub struct Work {
    /// The work directory.
    pub dir: PathBuf,
}

impl Work {
    /// A work directory (created 0700 on first write).
    pub fn new(dir: &Path) -> Self {
        Work {
            dir: dir.to_path_buf(),
        }
    }
    /// `archive/`.
    pub fn archive(&self) -> PathBuf {
        self.dir.join("archive")
    }
    /// `identities.json`.
    pub fn identities(&self) -> PathBuf {
        self.dir.join("identities.json")
    }
    /// `structure.json`.
    pub fn structure(&self) -> PathBuf {
        self.dir.join("structure.json")
    }
    /// `target.json`.
    pub fn target(&self) -> PathBuf {
        self.dir.join("target.json")
    }
    /// `keys.json`.
    pub fn keys(&self) -> PathBuf {
        self.dir.join("keys.json")
    }
    /// `media/`.
    pub fn media(&self) -> PathBuf {
        self.dir.join("media")
    }
    /// `state/`.
    pub fn state(&self) -> PathBuf {
        self.dir.join("state")
    }
    /// `seal/`.
    pub fn seal(&self) -> PathBuf {
        self.dir.join("seal")
    }
    /// `search/`.
    pub fn search(&self) -> PathBuf {
        self.dir.join("search")
    }
    /// `upload/`.
    pub fn upload(&self) -> PathBuf {
        self.dir.join("upload")
    }
}

fn read(path: &Path) -> Result<Vec<u8>, ImportError> {
    std::fs::read(path).map_err(|e| ImportError::io(path, e))
}

/// Everything the planning steps need, loaded and validated.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// The archive.
    pub archive: Archive,
    /// The resolved identities.
    pub ids: IdentityPlan,
    /// The structure.
    pub structure: Structure,
    /// The plan.
    pub plan: ImportPlan,
}

/// Load and validate the archive, identities and structure; build the plan.
pub fn load(work: &Work) -> Result<Loaded, ImportError> {
    let archive = Archive::open(&work.archive())?;
    let ids_file = IdentityFile::parse(&read(&work.identities())?)?;
    let structure = Structure::parse(&read(&work.structure())?)?;
    structure.validate(&archive)?;
    let ids = identity::plan(&archive, &ids_file)?;
    let plan = plan::build(&archive, &ids, &structure);
    Ok(Loaded {
        archive,
        ids,
        structure,
        plan,
    })
}

/// Write `identities.json` and `structure.json` templates (refuses to
/// overwrite either).
pub fn write_templates(work: &Work, zone: &str) -> Result<(), ImportError> {
    let archive = Archive::open(&work.archive())?;
    for (path, bytes) in [
        (
            work.identities(),
            serde_json::to_vec_pretty(&IdentityFile::template(&archive)).expect("serialises"),
        ),
        (
            work.structure(),
            serde_json::to_vec_pretty(&Structure::template(&archive, zone)).expect("serialises"),
        ),
    ] {
        if path.exists() {
            return Err(ImportError::Refused(format!(
                "{} exists; edit it instead",
                path.display()
            )));
        }
        fsutil::write_private_atomic(&path, &bytes)?;
    }
    Ok(())
}

/// Keystore labels this import needs keys for: the signers of planned
/// messages (posters only), plus the archivist; never the operator.
pub fn needed_labels(l: &Loaded) -> BTreeMap<String, Role> {
    let mut out = BTreeMap::new();
    let signers: BTreeSet<&str> = l.plan.messages.iter().map(|m| m.signer.as_str()).collect();
    for (label, role) in &l.ids.generate {
        if label == ARCHIVIST || signers.contains(label.as_str()) {
            out.insert(label.clone(), *role);
        }
    }
    out.insert(ARCHIVIST.into(), Role::Archivist);
    out
}

/// Generate the keys the plan needs (existing keys are kept). Returns the
/// labels created.
pub fn ensure_keys(work: &Work, l: &Loaded) -> Result<Vec<String>, ImportError> {
    let mut ks = Keystore::load(&work.keys())?;
    let mut created = Vec::new();
    for (label, role) in needed_labels(l) {
        if ks.ensure(&label, role)?.1 {
            created.push(label);
        }
    }
    ks.save()?;
    l.ids.check_keys(&ks)?;
    Ok(created)
}

/// What [`build`] did.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BuildReport {
    /// Plan counts.
    pub plan: plan::PlanStats,
    /// Events signed this run.
    pub signed: usize,
    /// Ledgered items reused.
    pub reused: usize,
    /// Event rows inserted.
    pub inserted: usize,
    /// Events already present or tombstoned.
    pub unchanged: usize,
    /// Messages cut to the sealing budget.
    pub fitted: usize,
    /// Images written as placeholders because their media are missing.
    pub images_missing: usize,
    /// Whitelist rows written.
    pub whitelisted: usize,
    /// Aliases written.
    pub aliases: usize,
    /// Set when the run imported new plaintext after a purge (seal again).
    pub needs_second_seal: bool,
}

/// Options for [`build`].
#[derive(Debug, Clone)]
pub struct BuildOptions {
    /// The D1 SQLite file.
    pub d1: PathBuf,
    /// Which messages to emit.
    pub emit: Emit,
    /// Refuse when an image's media are missing (default true).
    pub require_media: bool,
    /// The operator's 0600 key file, read for this run only.
    pub operator_key: Option<PathBuf>,
}

/// Sign and write the plan into the local D1 (see [`crate::d1`]).
pub fn build(work: &Work, opts: &BuildOptions) -> Result<BuildReport, ImportError> {
    let l = load(work)?;
    let target = Target::parse(&read(&work.target())?)?;
    let mut ks = Keystore::load(&work.keys())?;
    for label in needed_labels(&l).keys() {
        if ks.get(label).is_none() {
            return Err(ImportError::Refused(format!(
                "keystore has no key {label:?}: run `keys` first"
            )));
        }
    }
    l.ids.check_keys(&ks)?;
    let operator_signs = l
        .plan
        .messages
        .iter()
        .any(|m| m.signer == OPERATOR && m.deferred == (opts.emit == Emit::DeferredOnly));
    if operator_signs {
        if ks.get(OPERATOR).is_none() {
            return Err(ImportError::Refused(
                "the operator's public key is not recorded: `keys import --from FILE` first".into(),
            ));
        }
        match &opts.operator_key {
            Some(f) => ks.unlock(OPERATOR, f)?,
            None => {
                return Err(ImportError::Refused(
                    "this run signs operator messages: pass --operator-key FILE (0600)".into(),
                ))
            }
        }
    }
    let media = MediaManifest::load(&work.media())?;
    if opts.require_media {
        let missing: Vec<&str> = l
            .plan
            .messages
            .iter()
            .flat_map(|m| m.parts.iter())
            .filter_map(|p| match p {
                Part::Image(i) if media.main_of(&i.sha256).is_none() => Some(i.sha256.as_str()),
                _ => None,
            })
            .collect();
        if !missing.is_empty() {
            return Err(ImportError::Refused(format!(
                "{} image(s) have no processed media (first {}): run `media` first, or pass --allow-missing-media to write placeholders",
                missing.len(),
                &missing[0][..16]
            )));
        }
    }
    let mut c = d1::open_rw(&opts.d1)?;
    d1::check_schema(&c)?;
    let canonical = opts
        .d1
        .canonicalize()
        .map_err(|e| ImportError::io(&opts.d1, e))?;
    RunBinding::bind(
        &work.state(),
        &RunBinding {
            version: 1,
            d1: canonical.display().to_string(),
            target: target.name.clone(),
            pod_http: target.pod.http.clone(),
            provenance: l.plan.provenance.clone(),
        },
    )?;
    let mut ledger = Ledger::load(&work.state(), &c, &l.plan.provenance)?;
    let purged = ledger.purged_count(&c)?;

    for (key, t) in &l.structure.threads {
        if let ThreadChannel::Existing(id) = &t.channel {
            if !d1::has_channel(&c, id)? {
                return Err(ImportError::Refused(format!(
                    "thread {key:?}: kind-40 {id} is not stored in this D1"
                )));
            }
            match d1::channel_zone(&c, id)? {
                Some(z) if z == t.zone => {}
                other => {
                    return Err(ImportError::Refused(format!(
                        "thread {key:?}: channel {id} is bound to {:?} in channel_zones, not {:?}",
                        other, t.zone
                    )))
                }
            }
        }
    }

    let signed = events::sign(&SignInput {
        plan: &l.plan,
        structure: &l.structure,
        ids: &l.ids,
        keys: &ks,
        media: &media,
        target: &target,
        ledger: &ledger.rows,
        emit: opts.emit,
    })?;
    let new_plaintext = signed.events.iter().any(|(_, e)| e.kind == 42);
    if purged > 0 && new_plaintext && opts.emit == Emit::Normal {
        return Err(ImportError::Refused(format!(
            "this D1 has been purged ({purged} ledgered originals tombstoned) and the plan would add new plaintext; only `build --deferred-only` may run after a purge"
        )));
    }
    let applied = d1::apply_events(&mut c, &mut ledger, &signed.events, |_, _| {})?;
    let control = control_plan(&l, &ks, &ledger)?;
    d1::apply_control(&mut c, &control, &ledger)?;
    Ok(BuildReport {
        plan: l.plan.stats.clone(),
        signed: signed.events.len(),
        reused: signed.reused,
        inserted: applied.inserted,
        unchanged: applied.unchanged,
        fitted: signed.fitted,
        images_missing: signed.images_missing,
        whitelisted: control.whitelist.len(),
        aliases: control.aliases.len(),
        needs_second_seal: purged > 0 && new_plaintext,
    })
}

/// The control rows for the current plan, keys and ledger.
pub fn control_plan(
    l: &Loaded,
    ks: &Keystore,
    ledger: &Ledger,
) -> Result<ControlPlan, ImportError> {
    let cohorts = l.structure.member_cohorts();
    let mut wl: BTreeMap<String, WhitelistRow> = BTreeMap::new();
    let mut add = |pk: &str, admin: bool| {
        let e = wl.entry(pk.to_string()).or_insert(WhitelistRow {
            pubkey: pk.to_string(),
            cohorts: cohorts.clone(),
            admin: false,
        });
        e.admin |= admin;
    };
    let archivist = ks
        .get(ARCHIVIST)
        .ok_or_else(|| ImportError::Refused("no archivist key".into()))?;
    let actor = archivist.pk.clone();
    add(&archivist.pk, true);
    if let Some(op) = ks.get(OPERATOR) {
        if l.ids.needs_operator {
            add(&op.pk, true);
        }
    }
    let signers: BTreeSet<&str> = l.plan.messages.iter().map(|m| m.signer.as_str()).collect();
    let mut aliases = BTreeSet::new();
    for r in l.ids.authors.values() {
        match (&r.signer, &r.live_pubkey) {
            (Signer::Key { label, .. }, Some(live)) => {
                // The live key is whitelisted (and so granted the zone key) only
                // when a signature proves the mapping; the archive key never.
                if r.live_proven {
                    add(live, false);
                }
                if let Some(a) = ks.get(label) {
                    aliases.insert((a.pk.clone(), live.clone()));
                }
            }
            (Signer::Key { label, .. }, None)
                if label.starts_with("author:") && signers.contains(label.as_str()) =>
            {
                if let Some(k) = ks.get(label) {
                    add(&k.pk, false);
                }
            }
            _ => {}
        }
    }
    let mut zones = Vec::new();
    for (key, t) in &l.structure.threads {
        if matches!(t.channel, ThreadChannel::New { .. }) {
            if let Some(row) = ledger
                .rows
                .get(&format!("{}#thread:{key}", l.plan.provenance))
            {
                zones.push((row.id.clone(), t.zone.clone()));
            }
        }
    }
    Ok(ControlPlan {
        actor,
        whitelist: wl.into_values().collect(),
        channel_zones: zones,
        aliases: aliases.into_iter().collect(),
    })
}

/// Thread key → kind-40 id (existing, or the ledgered new header).
pub fn thread_ids(l: &Loaded, ledger: &Ledger) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (key, t) in &l.structure.threads {
        match &t.channel {
            ThreadChannel::Existing(id) => {
                out.insert(key.clone(), id.clone());
            }
            ThreadChannel::New { .. } => {
                if let Some(r) = ledger
                    .rows
                    .get(&format!("{}#thread:{key}", l.plan.provenance))
                {
                    out.insert(key.clone(), r.id.clone());
                }
            }
        }
    }
    out
}

/// What [`seal_prep`] found.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SealPrep {
    /// `[{"id","zone"}]` written to `seal/channels.json`.
    pub channels: Vec<(String, String)>,
    /// Preconditions still missing; sealing must wait until empty.
    pub missing: Vec<String>,
}

fn is_loopback_ws(url: &str) -> bool {
    url::Url::parse(url).is_ok_and(|u| {
        matches!(u.scheme(), "ws" | "wss")
            && matches!(
                u.host_str(),
                Some("127.0.0.1") | Some("localhost") | Some("[::1]") | Some("::1")
            )
    })
}

/// Write `seal/channels.json` and `seal/RUNBOOK.md` and check the sealing
/// preconditions in D1 (read-only; the relay may run). `relay` must be a
/// loopback ws URL.
pub fn seal_prep(work: &Work, d1_path: &Path, relay: &str) -> Result<SealPrep, ImportError> {
    if !is_loopback_ws(relay) {
        return Err(ImportError::Refused(format!("--relay {relay} is not a loopback ws:// URL: sealing runs against the LOCAL relay only")));
    }
    let l = load(work)?;
    let ks = Keystore::load(&work.keys())?;
    let archivist = ks
        .get(ARCHIVIST)
        .ok_or_else(|| ImportError::Refused("no archivist key: run `keys`".into()))?;
    let c = d1::open_ro(d1_path)?;
    d1::check_schema(&c)?;
    let ledger = Ledger::load(&work.state(), &c, &l.plan.provenance)?;
    let tids = thread_ids(&l, &ledger);
    let mut prep = SealPrep::default();
    let used: BTreeSet<&str> = l.plan.roots.iter().map(|r| r.thread.as_str()).collect();
    for (key, t) in &l.structure.threads {
        if !used.contains(key.as_str()) || !l.structure.zone_of(key).is_some_and(|z| z.encrypted) {
            continue;
        }
        let Some(id) = tids.get(key) else {
            prep.missing.push(format!(
                "thread {key:?} has no stored kind-40 yet: run `build`"
            ));
            continue;
        };
        prep.channels.push((id.clone(), t.zone.clone()));
        if d1::channel_zone(&c, id)?.as_deref() != Some(t.zone.as_str()) {
            prep.missing.push(format!(
                "thread {key:?} ({id}) is not bound to {} in channel_zones",
                t.zone
            ));
        }
        let anchors: i64 = c.query_row(
            "SELECT count(*) FROM events e WHERE e.kind = 42 \
               AND EXISTS (SELECT 1 FROM event_tags t WHERE t.event_id = e.id AND t.name = 'e' AND t.value = ?1) \
               AND EXISTS (SELECT 1 FROM event_tags t WHERE t.event_id = e.id AND t.name = 'zk' AND t.value = ?2) \
               AND NOT EXISTS (SELECT 1 FROM event_tags t WHERE t.event_id = e.id AND t.name = 'sealed')",
            params![id, t.zone],
            |r| r.get(0),
        )?;
        if anchors == 0 {
            prep.missing.push(format!(
                "thread {key:?} ({id}) has no anchor: post one zk-encrypted message in it as the archivist (after minting and granting the {} key)",
                t.zone
            ));
        }
    }
    let row: Option<(i64, String)> = c
        .query_row(
            "SELECT COALESCE(is_admin, 0), cohorts FROM whitelist WHERE pubkey = ?1",
            [&archivist.pk],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match row {
        None => prep
            .missing
            .push("the archivist is not whitelisted: run `build`".into()),
        Some((admin, cohorts)) => {
            if admin != 1 {
                prep.missing.push("the archivist is not an admin".into());
            }
            if serde_json::from_str::<Vec<String>>(&cohorts)
                .unwrap_or_default()
                .iter()
                .any(|c| c == "agent")
            {
                prep.missing
                    .push("the archivist carries the agent cohort (grants skip agent keys)".into());
            }
        }
    }
    let dir = work.seal();
    fsutil::create_private_dir(&dir)?;
    let list: Vec<serde_json::Value> = prep
        .channels
        .iter()
        .map(|(id, z)| serde_json::json!({"id": id, "zone": z}))
        .collect();
    fsutil::write_private_atomic(
        &dir.join("channels.json"),
        &serde_json::to_vec_pretty(&list).expect("serialises"),
    )?;
    fsutil::write_private_atomic(
        &dir.join("RUNBOOK.md"),
        seal_runbook(work, d1_path, relay).as_bytes(),
    )?;
    Ok(prep)
}

fn seal_runbook(work: &Work, d1_path: &Path, relay: &str) -> String {
    let w = work.dir.display();
    let d = d1_path.display();
    format!(
        r#"# Sealing runbook (generated by nostr-bbs-import seal-prep)

Prerequisites: `seal-prep` reports nothing missing; the zone key is minted and granted in the
client; every thread holds an archivist anchor; a backup of the D1 file exists.

The archivist key goes into the environment from a 0600 file, never on a command line:

    nostr-bbs-import keys export --work {w} --label archivist --out {w}/seal/archivist.key
    export NOSTR_BBS_MIGRATE_KEY="$(cat {w}/seal/archivist.key)"
    ZM="nostr-bbs-zone-migrate --relay {relay} --channels {w}/seal/channels.json --fetch-grants --state {w}/seal/state.json"

| Stack | Step |
|---|---|
| up   | `$ZM seal-offline --d1 {d} --sql-out {w}/seal/sql` |
| down | `$ZM apply-direct --d1 {d} {w}/seal/sql/seal-*.sql` |
| up   | `$ZM seal-offline-commit --d1 {d} --manifest {w}/seal/sql/seal-manifest.json` |
| up   | `$ZM verify` |
| any  | `nostr-bbs-import search-input --work {w} --d1 {d}` (BEFORE purge) |
| any  | `nostr-bbs-import verify-parity --work {w} --d1 {d} --phase sealed` |
| up   | `$ZM purge-offline --d1 {d} --sql-out {w}/seal/purge --yes` |
| down | `$ZM apply-direct --d1 {d} {w}/seal/purge/purge-*.sql` |
| up   | `$ZM purge-offline-commit --d1 {d} --manifest {w}/seal/purge/purge-manifest.json` |
| any  | `nostr-bbs-import verify-parity --work {w} --d1 {d} --phase purged` |

Afterwards: `unset NOSTR_BBS_MIGRATE_KEY; shred -u {w}/seal/archivist.key`. If a zone key file was
ever used instead of a grant, rotate the zone in the client.
"#
    )
}

/// Write `search/docs.jsonl` (0600) from the sealed envelopes and their
/// still-present originals. Returns the row count.
pub fn search_input(work: &Work, d1_path: &Path) -> Result<usize, ImportError> {
    let l = load(work)?;
    let ks = Keystore::load(&work.keys())?;
    let archivist = ks
        .get(ARCHIVIST)
        .ok_or_else(|| ImportError::Refused("no archivist key".into()))?;
    let c = d1::open_ro(d1_path)?;
    let ledger = Ledger::load(&work.state(), &c, &l.plan.provenance)?;
    let threads: BTreeSet<String> = thread_ids(&l, &ledger).into_values().collect();
    let envelopes = d1::read_events(
        &c,
        "WHERE kind = 42 AND id IN (SELECT event_id FROM event_tags WHERE name = 'sealed')",
    )?;
    let mut out = String::new();
    let mut n = 0;
    let mut missing = 0;
    for env in envelopes {
        if env.pubkey != archivist.pk {
            continue;
        }
        let tag = |name: &str| {
            env.tags
                .iter()
                .find(|t| t.first().map(String::as_str) == Some(name))
        };
        let Some(chan) = env
            .tags
            .iter()
            .find(|t| {
                t.first().map(String::as_str) == Some("e")
                    && t.get(3).map(String::as_str) == Some("root")
            })
            .and_then(|t| t.get(1))
        else {
            continue;
        };
        if !threads.contains(chan) {
            continue;
        }
        let (Some(sealed), Some(zk)) = (tag("sealed"), tag("zk")) else {
            continue;
        };
        let (Some(orig), Some(epoch), Some(zone_pk)) = (
            sealed.get(1),
            zk.get(2).and_then(|e| e.parse::<u32>().ok()),
            zk.get(3),
        ) else {
            continue;
        };
        let text: Option<String> = c
            .query_row(
                "SELECT content FROM events WHERE id = ?1 AND kind = 42",
                [orig],
                |r| r.get(0),
            )
            .optional()?;
        let Some(text) = text else {
            missing += 1;
            continue;
        };
        out.push_str(
            &serde_json::json!({"id": orig, "text": text, "epoch": epoch, "zone_pk": zone_pk})
                .to_string(),
        );
        out.push('\n');
        n += 1;
    }
    if missing > 0 {
        return Err(ImportError::Refused(format!(
            "{missing} sealed original(s) are already gone from D1: search-input must run after seal-offline-commit and BEFORE purge"
        )));
    }
    fsutil::create_private_dir(&work.search())?;
    fsutil::write_private_atomic(&work.search().join("docs.jsonl"), out.as_bytes())?;
    Ok(n)
}

/// One parity problem.
pub type Problem = String;

/// Phase checked by [`verify_parity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// After `build`.
    Built,
    /// After `seal-offline-commit`.
    Sealed,
    /// After `purge-offline-commit`.
    Purged,
}

/// Parity counts and problems.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ParityReport {
    /// Ledger rows.
    pub ledger: usize,
    /// Kind-42 rows in the import's threads (plaintext and envelopes).
    pub kind42: usize,
    /// `event_tags` rows checked.
    pub tag_rows: usize,
    /// Orphan e-tags found (must be 0).
    pub orphan_e_tags: usize,
    /// Everything wrong.
    pub problems: Vec<Problem>,
}

/// Check the invariants of `docs/bulk-import/DESIGN.md` §12.
pub fn verify_parity(
    work: &Work,
    d1_path: &Path,
    phase: Phase,
) -> Result<ParityReport, ImportError> {
    let l = load(work)?;
    let ks = Keystore::load(&work.keys())?;
    let c = d1::open_ro(d1_path)?;
    let ledger = Ledger::load(&work.state(), &c, &l.plan.provenance)?;
    let mut r = ParityReport {
        ledger: ledger.rows.len(),
        ..Default::default()
    };
    let threads: BTreeMap<String, String> = thread_ids(&l, &ledger);
    let thread_set: BTreeSet<&str> = threads.values().map(String::as_str).collect();
    let admins: BTreeSet<String> = {
        let mut s = c.prepare("SELECT pubkey FROM whitelist WHERE is_admin = 1")?;
        let v = s
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<_, _>>()?;
        v
    };
    let tombstoned = |id: &str| -> Result<bool, ImportError> {
        Ok(
            c.prepare_cached("SELECT 1 FROM deleted_events WHERE id = ?1")?
                .exists([id])?,
        )
    };

    // every ledgered key maps to a stored event, unless purged
    for row in ledger.rows.values() {
        let present = c
            .prepare_cached("SELECT 1 FROM events WHERE id = ?1")?
            .exists([&row.id])?;
        if !present {
            let ok = phase == Phase::Purged && row.kind == 42 && tombstoned(&row.id)?;
            if !ok {
                r.problems
                    .push(format!("ledgered {} ({}) is not stored", row.k, row.id));
            }
        }
    }
    let planned_now: usize =
        l.plan.messages.iter().filter(|m| !m.deferred).count() + l.plan.roots.len();
    let ledgered_42 = ledger.rows.values().filter(|x| x.kind == 42).count();
    if ledgered_42 < planned_now {
        r.problems.push(format!(
            "{} planned kind-42 items but {} ledgered",
            planned_now, ledgered_42
        ));
    }

    // events in the import's threads
    let in_threads: Vec<NostrEvent> = d1::read_events(&c, "WHERE kind = 42")?
        .into_iter()
        .filter(|e| {
            e.tags.iter().any(|t| {
                t.first().map(String::as_str) == Some("e")
                    && t.get(3).map(String::as_str) == Some("root")
                    && t.get(1).is_some_and(|v| thread_set.contains(v.as_str()))
            })
        })
        .collect();
    r.kind42 = in_threads.len();
    let by_id: HashMap<&str, &NostrEvent> = in_threads.iter().map(|e| (e.id.as_str(), e)).collect();
    let channel_of = |e: &NostrEvent| -> Option<String> {
        e.tags
            .iter()
            .find(|t| {
                t.first().map(String::as_str) == Some("e")
                    && t.get(3).map(String::as_str) == Some("root")
            })
            .and_then(|t| t.get(1).cloned())
    };
    // F2 resolution: an id resolves when stored as a kind-42 in the channel, or
    // wrapped by an admin envelope in the same channel.
    let mut sealed_by: HashMap<String, Vec<&NostrEvent>> = HashMap::new();
    for e in &in_threads {
        if let Some(t) = e
            .tags
            .iter()
            .find(|t| t.first().map(String::as_str) == Some("sealed"))
        {
            if let Some(v) = t.get(1) {
                sealed_by.entry(v.clone()).or_default().push(e);
            }
        }
    }
    let resolves = |id: &str, chan: &str| -> bool {
        by_id
            .get(id)
            .is_some_and(|p| channel_of(p).as_deref() == Some(chan))
            || sealed_by.get(id).is_some_and(|envs| {
                envs.iter().any(|env| {
                    admins.contains(&env.pubkey) && channel_of(env).as_deref() == Some(chan)
                })
            })
    };
    for e in &in_threads {
        let Some(chan) = channel_of(e) else { continue };
        if !d1::has_channel(&c, &chan)? {
            r.orphan_e_tags += 1;
            r.problems.push(format!(
                "{}: root channel {chan} is not a stored kind-40",
                e.id
            ));
        }
        for t in &e.tags {
            if t.first().map(String::as_str) != Some("e") {
                continue;
            }
            let marker = t.get(3).map(String::as_str).unwrap_or("");
            if marker == "reply" || marker == "quote" {
                let target = t.get(1).map(String::as_str).unwrap_or("");
                if !resolves(target, &chan) {
                    r.orphan_e_tags += 1;
                    r.problems.push(format!(
                        "{}: {marker} target {target} does not resolve in {chan}",
                        e.id
                    ));
                }
            }
        }
        if phase == Phase::Purged && e.content.is_empty() {
            continue;
        }
    }
    // the tag index: exactly the v3 trigger's rows for every stored event
    let all = d1::read_events(&c, "")?;
    let expected: usize = all.iter().map(d1::expected_tag_rows).sum();
    let actual: i64 = c.query_row("SELECT count(*) FROM event_tags", [], |x| x.get(0))?;
    r.tag_rows = actual as usize;
    if expected != actual as usize {
        r.problems.push(format!(
            "event_tags has {actual} rows, the trigger rule gives {expected}"
        ));
    }
    let stale: i64 = c.query_row(
        "SELECT count(*) FROM event_tags WHERE event_id NOT IN (SELECT id FROM events)",
        [],
        |x| x.get(0),
    )?;
    if stale > 0 {
        r.problems
            .push(format!("{stale} event_tags rows belong to deleted events"));
    }
    // control rows
    let archivist = ks
        .get(ARCHIVIST)
        .ok_or_else(|| ImportError::Refused("no archivist key".into()))?;
    if !admins.contains(&archivist.pk) {
        r.problems.push("the archivist is not an admin".into());
    }
    for label in ks.labels() {
        if let Some(k) = ks.get(label) {
            if k.role == Role::Archive
                && c.prepare_cached("SELECT 1 FROM whitelist WHERE pubkey = ?1")?
                    .exists([&k.pk])?
            {
                r.problems
                    .push(format!("archive key {label:?} is whitelisted"));
            }
        }
    }
    for (key, id) in &threads {
        if let Some(z) = l.structure.threads.get(key).map(|t| t.zone.clone()) {
            if d1::channel_zone(&c, id)?.as_deref() != Some(z.as_str()) {
                r.problems
                    .push(format!("thread {key:?} is not bound to {z}"));
            }
        }
    }
    // phase-specific
    let encrypted_threads: BTreeSet<&str> = threads
        .iter()
        .filter(|(k, _)| l.structure.zone_of(k).is_some_and(|z| z.encrypted))
        .map(|(_, id)| id.as_str())
        .collect();
    let plaintext_in_sealed = in_threads
        .iter()
        .filter(|e| channel_of(e).is_some_and(|ch| encrypted_threads.contains(ch.as_str())))
        .filter(|e| {
            !e.tags
                .iter()
                .any(|t| matches!(t.first().map(String::as_str), Some("sealed") | Some("zk")))
        })
        .count();
    match phase {
        Phase::Built => {}
        Phase::Sealed => {
            for row in ledger.rows.values().filter(|x| x.kind == 42) {
                let in_enc = by_id
                    .get(row.id.as_str())
                    .and_then(|e| channel_of(e))
                    .is_some_and(|ch| encrypted_threads.contains(ch.as_str()));
                if in_enc && !sealed_by.contains_key(&row.id) {
                    r.problems.push(format!("{} has no envelope", row.k));
                }
            }
        }
        Phase::Purged => {
            if plaintext_in_sealed > 0 {
                r.problems.push(format!(
                    "{plaintext_in_sealed} plaintext kind-42 left in encrypted threads"
                ));
            }
            for row in ledger.rows.values().filter(|x| x.kind == 42) {
                if sealed_by.contains_key(&row.id) && !tombstoned(&row.id)? {
                    r.problems
                        .push(format!("{} is sealed but not tombstoned", row.k));
                }
            }
        }
    }
    Ok(r)
}

/// A SQL text literal for the dump. Anything that is not plain printable
/// ASCII without `;`, `'` or comment markers is written as
/// `CAST(X'<utf-8 hex>' AS TEXT)`, so no statement splitter (wrangler's
/// included) can misread untrusted archive text.
fn sql_text(s: &str) -> String {
    let plain = s
        .bytes()
        .all(|b| (0x20..0x7f).contains(&b) && b != b';' && b != b'\'')
        && !s.contains("--")
        && !s.contains("/*");
    if plain {
        format!("'{s}'")
    } else {
        format!("CAST(X'{}' AS TEXT)", hex::encode(s.as_bytes()))
    }
}

fn sql_value(v: rusqlite::types::ValueRef<'_>) -> String {
    use rusqlite::types::ValueRef;
    match v {
        ValueRef::Null => "NULL".into(),
        ValueRef::Integer(i) => i.to_string(),
        ValueRef::Real(f) => format!("{f:?}"),
        ValueRef::Text(t) => sql_text(&String::from_utf8_lossy(t)),
        ValueRef::Blob(b) => format!("X'{}'", hex::encode(b)),
    }
}

/// Substitute `?N` placeholders with literal SQL values in one pass (a
/// value that itself contains `?2` is never re-substituted).
fn bind_literals(sql: &str, values: &[String]) -> String {
    let mut out = String::with_capacity(sql.len() + 256);
    let b = sql.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'?' {
            let mut j = i + 1;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if j > i + 1 {
                if let Some(v) = sql[i + 1..j]
                    .parse::<usize>()
                    .ok()
                    .and_then(|n| values.get(n.wrapping_sub(1)))
                {
                    out.push_str(v);
                    i = j;
                    continue;
                }
            }
        }
        let ch = sql[i..].chars().next().expect("in bounds");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Tables dumped as `INSERT OR IGNORE` (column lists read from the schema).
pub const DUMP_TABLES: &[&str] = &[
    "events",
    "deleted_events",
    "channel_creators",
    "channel_zones",
    "profiles",
    "pubkey_aliases",
    "admin_log",
];

/// Statements per dump chunk.
pub const DUMP_CHUNK: usize = 2_000;

/// Write the allowlisted dump of `c` as `data-NNNN.sql` chunks in `dir`.
/// Returns the chunk paths and per-table row counts.
pub fn write_dump(
    c: &Connection,
    dir: &Path,
) -> Result<(Vec<PathBuf>, BTreeMap<String, usize>), ImportError> {
    fsutil::create_private_dir(dir)?;
    let mut stmts: Vec<String> = Vec::new();
    let mut counts = BTreeMap::new();
    for table in DUMP_TABLES {
        let mut cols: Vec<String> = {
            let mut s = c.prepare(&format!("PRAGMA table_info({table})"))?;
            let v = s
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<Result<Vec<_>, _>>()?;
            v
        };
        if cols.is_empty() {
            continue;
        }
        if *table == "admin_log" {
            cols.retain(|x| x != "id");
        }
        let list = cols.join(", ");
        let order = if *table == "events" {
            " ORDER BY created_at, id"
        } else {
            ""
        };
        let mut s = c.prepare(&format!("SELECT {list} FROM {table}{order}"))?;
        let mut rows = s.query([])?;
        let mut n = 0;
        while let Some(row) = rows.next()? {
            let vals: Vec<String> = (0..cols.len())
                .map(|i| row.get_ref(i).map(sql_value))
                .collect::<Result<_, _>>()?;
            let stmt = if *table == "admin_log" {
                // no primary key to ignore on: skip an identical row already present
                let cond: Vec<String> = cols
                    .iter()
                    .zip(&vals)
                    .map(|(k, v)| {
                        if v == "NULL" {
                            format!("{k} IS NULL")
                        } else {
                            format!("{k} = {v}")
                        }
                    })
                    .collect();
                format!("INSERT INTO admin_log ({list}) SELECT {} WHERE NOT EXISTS (SELECT 1 FROM admin_log WHERE {});", vals.join(", "), cond.join(" AND "))
            } else {
                format!(
                    "INSERT OR IGNORE INTO {table} ({list}) VALUES ({});",
                    vals.join(", ")
                )
            };
            stmts.push(stmt);
            n += 1;
        }
        counts.insert(table.to_string(), n);
    }
    // whitelist: merge-only cohorts, admin flag, MAX counters
    let mut s = c.prepare("SELECT pubkey, cohorts, added_at, added_by, COALESCE(is_admin, 0), posts_created, last_active_at FROM whitelist")?;
    let mut rows = s.query([])?;
    let mut n = 0;
    let grant = nostr_bbs_core::whitelist_sql::WHITELIST_GRANT_COHORTS_SQL;
    while let Some(row) = rows.next()? {
        let pk: String = row.get(0)?;
        let cohorts: String = row.get(1)?;
        let added_at: i64 = row.get(2)?;
        let added_by: String = row.get(3)?;
        let admin: i64 = row.get(4)?;
        let posts: i64 = row.get(5)?;
        let last: Option<i64> = row.get(6)?;
        let g = bind_literals(
            grant,
            &[
                sql_text(&pk),
                sql_text(&cohorts),
                added_at.to_string(),
                sql_text(&added_by),
            ],
        );
        stmts.push(format!("{g};"));
        if admin == 1 {
            stmts.push(format!(
                "UPDATE whitelist SET is_admin = 1 WHERE pubkey = {};",
                sql_text(&pk)
            ));
        }
        stmts.push(format!(
            "UPDATE whitelist SET posts_created = MAX(posts_created, {posts}), last_active_at = MAX(COALESCE(last_active_at, 0), {}) WHERE pubkey = {};",
            last.unwrap_or(0),
            sql_text(&pk)
        ));
        n += 1;
    }
    counts.insert("whitelist".into(), n);
    let mut paths = Vec::new();
    for (i, chunk) in stmts.chunks(DUMP_CHUNK).enumerate() {
        let p = dir.join(format!("data-{:04}.sql", i + 1));
        fsutil::write_private_atomic(&p, (chunk.join("\n") + "\n").as_bytes())?;
        paths.push(p);
    }
    Ok((paths, counts))
}

/// Apply dump chunks to `c` (the rehearsal path; production uses wrangler).
pub fn apply_dump(c: &Connection, paths: &[PathBuf]) -> Result<(), ImportError> {
    for p in paths {
        let sql = std::fs::read_to_string(p).map_err(|e| ImportError::io(p, e))?;
        c.execute_batch(&format!("BEGIN; {sql} COMMIT;"))?;
    }
    Ok(())
}

/// Per-table counts used to compare a rehearsal with its source.
pub fn table_counts(c: &Connection) -> Result<BTreeMap<String, i64>, ImportError> {
    let mut out = BTreeMap::new();
    for t in DUMP_TABLES.iter().chain(["event_tags", "whitelist"].iter()) {
        let n: i64 = c
            .query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))
            .unwrap_or(-1);
        out.insert(t.to_string(), n);
    }
    Ok(out)
}

/// What [`upload_plan`] wrote.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UploadReport {
    /// Dump chunks.
    pub chunks: usize,
    /// Rows per dumped table.
    pub rows: BTreeMap<String, usize>,
    /// R2 objects listed.
    pub r2_objects: usize,
    /// Bytes in the archivist's pod.
    pub pod_bytes: u64,
    /// Warnings (quota and the like).
    pub warnings: Vec<String>,
}

/// Write `upload/` (see `docs/bulk-import/DESIGN.md` §10).
pub fn upload_plan(
    work: &Work,
    d1_path: &Path,
    search_out: Option<&Path>,
    pod_quota_mb: u64,
) -> Result<UploadReport, ImportError> {
    let l = load(work)?;
    let ks = Keystore::load(&work.keys())?;
    let archivist = ks
        .get(ARCHIVIST)
        .ok_or_else(|| ImportError::Refused("no archivist key".into()))?;
    let media = MediaManifest::load(&work.media())?;
    let c = d1::open_ro(d1_path)?;
    let dir = work.upload();
    fsutil::create_private_dir(&dir)?;
    let (paths, rows) = write_dump(&c, &dir)?;
    let mut report = UploadReport {
        chunks: paths.len(),
        rows,
        ..Default::default()
    };

    // R2 objects: every (zone, image) pair the plan links, plus search files
    let mut objects: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let media_dir = work.media().canonicalize().unwrap_or(work.media());
    for m in &l.plan.messages {
        let Some(zone) = l.structure.zone_of(&m.thread).map(|z| z.id.clone()) else {
            continue;
        };
        for p in &m.parts {
            if let Part::Image(img) = p {
                if let Some(e) = media.objects.get(&img.sha256).filter(|e| e.status == "ok") {
                    for o in [&e.main, &e.thumb].into_iter().flatten() {
                        let key = format!("pods/{}/media/zones/{zone}/{}", archivist.pk, o.name);
                        objects.insert(key.clone(), serde_json::json!({"key": key, "file": media_dir.join(&o.file), "content_type": o.mime, "bytes": o.bytes, "sha256": o.sha256, "owner": archivist.pk}));
                    }
                }
            }
        }
    }
    if let Some(sdir) = search_out {
        let zones: BTreeSet<&str> = l
            .structure
            .zones
            .iter()
            .filter(|z| z.encrypted)
            .map(|z| z.id.as_str())
            .collect();
        if zones.len() != 1 {
            return Err(ImportError::Refused("--search-out needs exactly one encrypted zone in structure.json (run one search build per zone)".into()));
        }
        let zone = zones.into_iter().next().expect("one zone");
        let mut entries: Vec<PathBuf> = std::fs::read_dir(sdir)
            .map_err(|e| ImportError::io(sdir, e))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .collect();
        entries.sort();
        for f in entries {
            let name = f
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            let key = format!("pods/{}/media/zones/{zone}/search/{name}", archivist.pk);
            let bytes = std::fs::metadata(&f)
                .map_err(|e| ImportError::io(&f, e))?
                .len();
            let ct = if name == "m.json" {
                "application/json"
            } else {
                "application/octet-stream"
            };
            objects.insert(key.clone(), serde_json::json!({"key": key, "file": f, "content_type": ct, "bytes": bytes, "sha256": fsutil::sha256_file(&f)?, "owner": archivist.pk}));
        }
    }
    report.r2_objects = objects.len();
    report.pod_bytes = objects.values().filter_map(|o| o["bytes"].as_u64()).sum();
    let mut lines = String::new();
    for o in objects.values() {
        lines.push_str(&o.to_string());
        lines.push('\n');
    }
    fsutil::write_private_atomic(&dir.join("r2-objects.jsonl"), lines.as_bytes())?;
    let quota = format!(
        "-- Auth database (REPLAY_DB): account the bulk-uploaded objects to the archivist's pod.\n\
         INSERT INTO quota_usage (pubkey, used_bytes, updated_at) VALUES ({pk}, {b}, {now}) \
         ON CONFLICT (pubkey) DO UPDATE SET used_bytes = MAX(quota_usage.used_bytes, excluded.used_bytes), updated_at = excluded.updated_at;\n",
        pk = sql_text(&archivist.pk),
        b = report.pod_bytes,
        now = fsutil::now()
    );
    fsutil::write_private_atomic(&dir.join("quota.sql"), quota.as_bytes())?;
    if report.pod_bytes > pod_quota_mb * 1_048_576 {
        report.warnings.push(format!(
            "the archivist pod needs {:.1} MiB, above the pod quota of {pod_quota_mb} MiB: raise POD_QUOTA_MB or set the archivist's limit with the admin /.quota call before uploading",
            report.pod_bytes as f64 / 1_048_576.0
        ));
    }
    let chunks: Vec<String> = paths
        .iter()
        .map(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string()
        })
        .collect();
    fsutil::write_private_atomic(
        &dir.join("commands.sh"),
        upload_commands(&chunks).as_bytes(),
    )?;
    fsutil::write_private_atomic(&dir.join("RUNBOOK.md"), upload_runbook(&report).as_bytes())?;
    Ok(report)
}

fn upload_commands(chunks: &[String]) -> String {
    let mut s = String::from(
        "#!/usr/bin/env bash\n# Generated by nostr-bbs-import upload-plan. NOT run by the tool. Review, then run step by step\n\
         # from a shell that holds the NEW stack's Cloudflare credentials. NEW_DB, NEW_BUCKET, AUTH_DB and\n\
         # RELAY_CONFIG name the new stack's resources; OLD_DB, OLD_BUCKET and OLD_AUTH_DB name the live\n\
         # stack's, only so this script can refuse them.\n\
         set -euo pipefail\n\
         : \"${NEW_DB:?}\" \"${NEW_BUCKET:?}\" \"${AUTH_DB:?}\" \"${RELAY_CONFIG:?}\" \"${RELAY_MIGRATIONS:?}\" \"${OLD_DB:?}\" \"${OLD_BUCKET:?}\" \"${OLD_AUTH_DB:?}\"\n\
         if [ \"$NEW_DB\" = \"$OLD_DB\" ] || [ \"$NEW_BUCKET\" = \"$OLD_BUCKET\" ] || [ \"$AUTH_DB\" = \"$OLD_AUTH_DB\" ]; then\n\
         \x20 echo 'refusing: a NEW resource names the live stack' >&2; exit 1\nfi\n\
         export WRANGLER_SEND_METRICS=false\n\n\
         # 1. schema: 0009 first (0004's trigger reads events), then every relay migration in order,\n\
         #    then boot the new relay once (ensure_schema). Not `migrations apply`: its order runs 0004 first.\n\
         wrangler d1 execute \"$NEW_DB\" --remote -c \"$RELAY_CONFIG\" --file \"$RELAY_MIGRATIONS/0009_events.sql\"\n\
         for f in \"$RELAY_MIGRATIONS\"/0*.sql; do wrangler d1 execute \"$NEW_DB\" --remote -c \"$RELAY_CONFIG\" --file \"$f\"; done\n\
         echo 'Boot the new relay once now (open its URL), then press Enter'; read -r _\n\
         # the new database must hold no events before the import\n\
         n=$(wrangler d1 execute \"$NEW_DB\" --remote -c \"$RELAY_CONFIG\" --json --command 'SELECT count(*) AS n FROM events' | jq -r '.[0].results[0].n')\n\
         if [ \"$n\" != \"0\" ]; then echo \"refusing: $NEW_DB already holds $n events\" >&2; exit 1; fi\n\n# 2. data\n",
    );
    for c in chunks {
        s.push_str(&format!("wrangler d1 execute \"$NEW_DB\" --remote -c \"$RELAY_CONFIG\" --file \"$(dirname \"$0\")/{c}\"\n"));
    }
    s.push_str(
        "\n# 3. objects (key, file, content type from r2-objects.jsonl)\n\
         jq -r '[.key, .file, .content_type] | @tsv' \"$(dirname \"$0\")/r2-objects.jsonl\" | while IFS=\"$(printf '\\t')\" read -r key file ct; do\n\
         \x20 wrangler r2 object put \"$NEW_BUCKET/$key\" --file \"$file\" --content-type \"$ct\" --remote\n\
         done\n\n# 4. pod accounting on the auth database\n\
         wrangler d1 execute \"$AUTH_DB\" --remote --file \"$(dirname \"$0\")/quota.sql\"\n",
    );
    s
}

fn upload_runbook(r: &UploadReport) -> String {
    format!(
        r#"# Upload and cutover runbook (generated by nostr-bbs-import upload-plan)

Nothing here has been run. The tool never runs a remote command.

* Dump: {chunks} chunk(s) `data-NNNN.sql`, every row `INSERT OR IGNORE` (re-running a chunk is
  harmless). Rows: {rows:?}. Never dumped: `event_tags` (the relay trigger rebuilds it from
  `events`) and `settings` (boot marker rows).
* Objects: {objs} in `r2-objects.jsonl` ({mib:.1} MiB in the archivist's pod), `quota.sql` for the
  auth database.

1. Stand the NEW stack up alongside the old one: new worker names, a new D1, a new R2 bucket and
   new KV namespaces, config projected from the same forum config. Do not touch the old stack.
2. Relay migrations with `wrangler d1 execute <new db> --remote --file`: `0009_events.sql` first
   (`0004`'s trigger reads `events`), then every file in numeric order (`event_tags`, its delete
   trigger and the alias table exist only in the migrations; `migrations apply` would run `0004`
   first and fail on a fresh database). Then boot the new relay once so `ensure_schema()`
   installs the v3 tag trigger, `channel_zones`, `admin_log` and the rest.
3. `wrangler d1 execute <new db> --remote --file data-NNNN.sql` for every chunk, in order.
4. Upload the objects (`commands.sh` step 3), then run `quota.sql` on the auth database. Sign in
   once as the archivist on the new stack so its pod is provisioned.
5. Check: event and tag counts on the new D1 match `nostr-bbs-import upload-rehearse`; open a
   sealed topic as a member and read it.
6. Cutover: one revertable website commit points the forum at the new stack. Freeze the old stack
   read-only (do not delete it). Roll back by reverting that commit.
{warn}"#,
        chunks = r.chunks,
        rows = r.rows,
        objs = r.r2_objects,
        mib = r.pod_bytes as f64 / 1_048_576.0,
        warn = if r.warnings.is_empty() {
            String::new()
        } else {
            format!(
                "\nWarnings:\n\n{}\n",
                r.warnings
                    .iter()
                    .map(|w| format!("* {w}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        }
    )
}

/// After the purge: rewrite the D1 file so deleted plaintext does not
/// linger in free pages or the WAL (`secure_delete`, `VACUUM`, a truncating
/// checkpoint). The stack must be down. Filesystem-level copies (snapshots,
/// backups, the archive and media directories) are the operator's to destroy
/// (SECURITY.md, residue checklist).
pub fn scrub(d1_path: &Path) -> Result<(), ImportError> {
    let c = d1::open_rw(d1_path)?;
    c.execute_batch("PRAGMA secure_delete = ON; VACUUM;")?;
    c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
        .optional()?;
    Ok(())
}

/// Import DMs: verbatim copies to the kept live keys (and the operator),
/// plus optional re-wraps of the operator's sent DMs (old key from a 0600
/// file).
pub fn import_dms(
    work: &Work,
    d1_path: &Path,
    allow_stale_grants: bool,
    rewrap_old_key: Option<&Path>,
) -> Result<serde_json::Value, ImportError> {
    let l = load(work)?;
    let mut c = d1::open_rw(d1_path)?;
    d1::check_schema(&c)?;
    let mut ledger = Ledger::load(&work.state(), &c, &l.plan.provenance)?;
    let ks = Keystore::load(&work.keys())?;
    // Recipients that may receive a copied wrap: live keys kept by proven
    // `existing` identities that are whitelisted here, and the operator.
    let in_whitelist = |pk: &str| -> Result<bool, ImportError> {
        Ok(
            c.prepare_cached("SELECT 1 FROM whitelist WHERE pubkey = ?1")?
                .exists([pk])?,
        )
    };
    let mut whitelisted: BTreeSet<String> = BTreeSet::new();
    for r in l.ids.authors.values() {
        if let (Some(live), true) = (&r.live_pubkey, r.live_proven) {
            if in_whitelist(live)? {
                whitelisted.insert(live.clone());
            }
        }
    }
    if let Some(op) = ks.get(OPERATOR) {
        if in_whitelist(&op.pk)? {
            whitelisted.insert(op.pk.clone());
        }
    }
    let (copies, copy_report) =
        crate::dm::copy_plan(&l.archive.dms, &whitelisted, allow_stale_grants)?;
    let mut evs: Vec<(String, NostrEvent)> = copies
        .into_iter()
        .map(|w| (format!("{}#dm:{}", l.plan.provenance, w.id), w))
        .collect();
    let mut rewrap = None;
    if let Some(f) = rewrap_old_key {
        let old = crate::keystore::read_secret_file(f)?;
        let new_pk = ks
            .get(OPERATOR)
            .ok_or_else(|| ImportError::Refused("import the operator's current key first".into()))?
            .pk
            .clone();
        let (out, rep) = crate::dm::rewrap_operator_sent(&l.archive.dms, &old, &new_pk)?;
        for (from, w) in out {
            let key = format!("{}#dm-rewrap:{from}", l.plan.provenance);
            if !ledger.rows.contains_key(&key) {
                evs.push((key, w));
            }
        }
        rewrap = Some(rep);
    }
    evs.retain(|(k, _)| !ledger.rows.contains_key(k));
    let applied = d1::apply_events(&mut c, &mut ledger, &evs, |_, _| {})?;
    Ok(serde_json::json!({"copy": copy_report, "rewrap": rewrap, "inserted": applied.inserted}))
}
