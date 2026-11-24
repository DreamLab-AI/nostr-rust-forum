//! Command-line front end: argument parsing, key loading, output.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use nostr_bbs_core::keys::SecretKey;
use nostr_bbs_zone_migrate::channels::{list_channels, parse_channels, ChannelSpec};
use nostr_bbs_zone_migrate::engine::{self, Hooks, Plan};
use nostr_bbs_zone_migrate::grants::{fetch_grants_with, GroupBinding, RejectedGrant};
use nostr_bbs_zone_migrate::identity::{identity_from_env, parse_identity, IDENTITY_ENV};
use nostr_bbs_zone_migrate::keys::{parse_key_file, KeyRing};
use nostr_bbs_zone_migrate::offline;
use nostr_bbs_zone_migrate::relay::{fetch_all, http_origin, Filter, Relay};
use nostr_bbs_zone_migrate::state::{self, State, Status};
use serde::Serialize;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use nostr_bbs_zone_migrate::net::NetRelay;

/// Declare `$hooks`: engine hooks that save `$path` atomically after each
/// change and log progress lines to stderr.
macro_rules! hooks {
    ($hooks:ident, $path:expr, $every:expr) => {
        let path: &Path = $path;
        let every: usize = ($every).max(1);
        let mut persist = |s: &State| state::save_atomic(path, s);
        let mut since_save = 0usize;
        let mut checkpoint = |s: &State| {
            since_save += 1;
            if since_save >= every {
                since_save = 0;
                state::save_atomic(path, s)
            } else {
                Ok(())
            }
        };
        let mut progress = |line: &str| eprintln!("{line}");
        let mut $hooks = Hooks {
            persist: &mut persist,
            checkpoint: &mut checkpoint,
            progress: &mut progress,
        };
    };
}

/// SIGINT / SIGTERM request a stop for the commands whose loops check
/// [`engine::STOP`] (`seal`, `purge`, `apply-direct`): they finish the
/// current entry, chunk or file, save the state and stop. A second signal
/// exits at once (code 130). Other commands keep the default behaviour
/// (the handler is not installed for them), so a signal always stops them.
fn install_stop_handler() {
    std::thread::spawn(|| {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
        else {
            return;
        };
        rt.block_on(async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let (Ok(mut int), Ok(mut term)) = (
                    signal(SignalKind::interrupt()),
                    signal(SignalKind::terminate()),
                ) else {
                    return;
                };
                tokio::select! {
                    _ = int.recv() => {}
                    _ = term.recv() => {}
                }
                eprintln!(
                    "stop requested: finishing the current step and saving the state (signal again to exit now)"
                );
                engine::STOP.store(true, std::sync::atomic::Ordering::Relaxed);
                tokio::select! {
                    _ = int.recv() => {}
                    _ = term.recv() => {}
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
                eprintln!(
                    "stop requested: finishing the current step and saving the state (signal again to exit now)"
                );
                engine::STOP.store(true, std::sync::atomic::Ordering::Relaxed);
                let _ = tokio::signal::ctrl_c().await;
            }
            eprintln!("second stop signal: exiting now");
            std::process::exit(130);
        });
    });
}

/// Exit code when a step ran to completion but some entries failed.
const EXIT_ENTRIES_FAILED: u8 = 2;

#[derive(Parser)]
#[command(
    name = "nostr-bbs-zone-migrate",
    version,
    about = "Seal the plaintext history of encrypted zones into sealed-original envelopes, verify, then purge the plaintext (ADR-2017).",
    after_help = concat!(
        "The admin secret key is read from the environment variable NOSTR_BBS_MIGRATE_KEY ",
        "(64 hex or nsec), never from a flag.\n",
        "Runbook: docs/security/encrypted-zone-history-migration.md"
    )
)]
struct Cli {
    /// Save the state file every N recorded entries (and always at the end of
    /// each phase and on SIGINT/SIGTERM). Resume after a crash adopts
    /// anything published but not yet recorded.
    #[arg(long, global = true, value_name = "N", default_value_t = 2000)]
    persist_every: usize,

    /// Relay WebSocket URL (wss://…); its HTTP API is served on the same origin.
    #[arg(long, global = true, value_name = "URL")]
    relay: Option<String>,

    /// JSON channels file: [{"id":"<64-hex>","zone":"zone3"}, …].
    #[arg(long, global = true, value_name = "PATH")]
    channels: Option<PathBuf>,

    /// JSON zone-key file ({"version":1,"owner":…,"keys":[…]}, agentbox zone-keys.json schema).
    #[arg(long, global = true, value_name = "PATH")]
    keys_file: Option<PathBuf>,

    /// Also use zone-key grants addressed to the admin key (kind-1059 wraps sealed by an admin).
    #[arg(long, global = true)]
    fetch_grants: bool,

    /// File holding the admin's zone-inbox secret (hex or nsec, 0600). With --fetch-grants, grants
    /// addressed to the inbox key are opened too (inbox key first, then the identity).
    #[arg(long, global = true, value_name = "PATH")]
    inbox_key: Option<PathBuf>,

    /// With --fetch-grants: accept NIP-171 kind-1014 epoch tickets signed by this zone's group
    /// identity, as `<zone>=<64-hex group pubkey>` (repeatable). Tickets signed by any other key
    /// are refused.
    #[arg(long, global = true, value_name = "ZONE=HEX")]
    group_pubkey: Vec<GroupBinding>,

    /// State file recording the run (required by seal, verify, purge, status).
    #[arg(long, global = true, value_name = "PATH")]
    state: Option<PathBuf>,

    /// Print a machine-readable JSON summary on stdout.
    #[arg(long, global = true)]
    json: bool,

    /// List the relay's kind-40 channels with their section tag, then exit.
    #[arg(long)]
    print_channels: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Clone)]
enum Command {
    /// Dry run (default): per channel, plaintext count, already-sealed count and ids to seal. Writes nothing.
    Plan,
    /// Publish an envelope per planned original, read it back and check it. Resumable.
    Seal {
        /// Seal at most this many originals in this run.
        #[arg(long, value_name = "N")]
        limit: Option<usize>,
        /// Allow the FIRST encryption of an all-plaintext zone (no encrypted
        /// post on the relay to anchor the key). Refused unless the relay holds
        /// no zone-encrypted post of the zone and the key is the latest grant
        /// this sealer received.
        #[arg(long)]
        allow_unanchored_first_encryption: bool,
        /// With --allow-unanchored-first-encryption: the key distributed to
        /// members, ZONE=EPOCH:PUBKEY (repeatable). Required.
        #[arg(long, value_name = "ZONE=EPOCH:PUBKEY", value_parser = parse_expect_zone_key)]
        expect_zone_key: Vec<(String, u32, String)>,
    },
    /// Re-fetch and re-open every recorded envelope.
    Verify,
    /// Delete the plaintext originals. Refuses unless every entry is verified.
    Purge {
        /// Confirm the irreversible deletion.
        #[arg(long)]
        yes: bool,
    },
    /// Print the state file's counts by status.
    Status,
    /// Seal from the relay's local D1 on all cores and write SQL chunks plus a
    /// manifest (apply with `wrangler d1 execute --local --file`, then run
    /// seal-offline-commit). Same key ring and anchor check as seal.
    SealOffline {
        /// The relay's D1 SQLite file (under --persist-to .../d1/...).
        #[arg(long, value_name = "FILE")]
        d1: PathBuf,
        /// Directory for seal-NNNN.sql and seal-manifest.json.
        #[arg(long, value_name = "DIR")]
        sql_out: PathBuf,
        /// Envelopes per SQL chunk.
        #[arg(long, default_value_t = offline::DEFAULT_CHUNK)]
        chunk: usize,
        /// Sealing threads (default: all cores).
        #[arg(long)]
        threads: Option<usize>,
        /// Seal at most this many originals.
        #[arg(long, value_name = "N")]
        limit: Option<usize>,
    },
    /// Apply SQL chunk files (seal-offline / purge-offline output) straight to
    /// the D1 SQLite file, one transaction per file, triggers firing as under
    /// wrangler. Every worker using the database must be stopped (the file is
    /// locked exclusively). Faster than wrangler d1 execute for bulk applies.
    ApplyDirect {
        /// The D1 SQLite file.
        #[arg(long, value_name = "FILE")]
        d1: PathBuf,
        /// SQL files, applied in the order given.
        #[arg(required = true, value_name = "SQL")]
        files: Vec<PathBuf>,
    },
    /// Replace this sealer's envelopes that predate the outer topic tag (found
    /// in D1, recorded or not) with current-format envelopes: writes
    /// reseal-0001.sql (insert new, then tombstone + delete old, as the admin
    /// delete) and a seal-manifest.json. Apply it, then run
    /// seal-offline-commit --reseal, then verify.
    ResealLegacy {
        /// The relay's D1 SQLite file.
        #[arg(long, value_name = "FILE")]
        d1: PathBuf,
        /// Directory for reseal-0001.sql and seal-manifest.json (must be empty).
        #[arg(long, value_name = "DIR")]
        sql_out: PathBuf,
    },
    /// After applying seal-offline's chunks: re-read each envelope from D1,
    /// re-open it, and mark the entry sealed. Unapplied entries stay planned.
    SealOfflineCommit {
        /// The relay's D1 SQLite file.
        #[arg(long, value_name = "FILE")]
        d1: PathBuf,
        /// seal-manifest.json from seal-offline.
        #[arg(long, value_name = "FILE")]
        manifest: PathBuf,
        /// The manifest is from reseal-legacy: re-record already-sealed entries
        /// with their replacement envelope (they need verify again).
        #[arg(long)]
        reseal: bool,
    },
    /// Write SQL that purges the verified plaintext exactly as the relay's
    /// admin delete does (tombstone, delete, audit row). Re-checks every
    /// envelope from D1 first. Writes nothing to D1 itself.
    PurgeOffline {
        /// The relay's D1 SQLite file.
        #[arg(long, value_name = "FILE")]
        d1: PathBuf,
        /// Directory for purge-NNNN.sql and purge-manifest.json.
        #[arg(long, value_name = "DIR")]
        sql_out: PathBuf,
        /// Ids per SQL chunk.
        #[arg(long, default_value_t = offline::DEFAULT_CHUNK)]
        chunk: usize,
        /// Confirm the irreversible deletion the SQL performs.
        #[arg(long)]
        yes: bool,
    },
    /// After applying purge-offline's chunks: mark entries purged whose
    /// plaintext is gone from D1 and tombstoned.
    PurgeOfflineCommit {
        /// The relay's D1 SQLite file.
        #[arg(long, value_name = "FILE")]
        d1: PathBuf,
        /// purge-manifest.json from purge-offline.
        #[arg(long, value_name = "FILE")]
        manifest: PathBuf,
    },
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Command::Plan => "plan",
            Command::Seal { .. } => "seal",
            Command::Verify => "verify",
            Command::Purge { .. } => "purge",
            Command::Status => "status",
            Command::SealOffline { .. } => "seal-offline",
            Command::SealOfflineCommit { .. } => "seal-offline-commit",
            Command::ResealLegacy { .. } => "reseal-legacy",
            Command::ApplyDirect { .. } => "apply-direct",
            Command::PurgeOffline { .. } => "purge-offline",
            Command::PurgeOfflineCommit { .. } => "purge-offline-commit",
        }
    }
}

/// Top-level failure: a message for stderr and an exit code.
struct Failure(String);

impl<E: std::fmt::Display> From<E> for Failure {
    fn from(e: E) -> Self {
        Failure(e.to_string())
    }
}

pub fn main() -> ExitCode {
    let cli = Cli::parse();
    if matches!(
        cli.command,
        Some(Command::Seal { .. } | Command::Purge { .. } | Command::ApplyDirect { .. })
    ) {
        install_stop_handler();
    }
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: cannot start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(cli)) {
        Ok(code) => code,
        Err(Failure(msg)) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode, Failure> {
    let command = cli.command.clone().unwrap_or(Command::Plan);

    if !cli.print_channels {
        if let Command::Status = command {
            return status(&cli);
        }
    }
    // Needs neither a relay nor a key: it only applies SQL already written.
    if let Command::ApplyDirect { d1, files } = &command {
        let t = std::time::Instant::now();
        let done = offline::apply_sql_direct(d1, files).map_err(Failure)?;
        for (f, ms) in &done {
            eprintln!("{} {ms} ms", f.display());
        }
        eprintln!(
            "apply-direct: {} of {} files in {} ms",
            done.len(),
            files.len(),
            t.elapsed().as_millis()
        );
        if done.len() < files.len() {
            return Err(Failure(format!(
                "stopped by signal after {} files; the rest were not applied (each applied file is complete)",
                done.len()
            )));
        }
        return Ok(ExitCode::SUCCESS);
    }

    let relay_url = cli
        .relay
        .clone()
        .ok_or_else(|| Failure("--relay wss://… is required".into()))?;
    let origin = http_origin(&relay_url).map_err(Failure)?;
    let me = identity_from_env()?;
    let me_pk = me.public_key().to_hex();

    eprintln!("connecting to {relay_url} as {me_pk}");
    let mut relay = NetRelay::connect(&relay_url, &origin, &me).await?;
    if !relay.authenticated() {
        eprintln!("note: the relay did not ask for NIP-42 AUTH; continuing unauthenticated");
    }
    if !relay.is_admin(&me_pk).await? {
        return Err(Failure(format!(
            "{me_pk} is not an admin on this relay (GET {origin}/api/check-whitelist); \
             the relay accepts sealed originals only from admins. Check {IDENTITY_ENV}"
        )));
    }

    if cli.print_channels {
        return print_channels(&cli, &mut relay).await;
    }

    let (keys, grant_report) = load_keys(&cli, &mut relay, &me).await?;
    let mut out = json!({
        "command": command.name(),
        "relay": relay_url,
        "migrator": me_pk,
        "keys": keys.summaries(),
    });
    if let Some(g) = &grant_report {
        out["grants"] = serde_json::to_value(g)?;
    }

    let code = match command {
        Command::Plan => {
            let channels = channels(&cli)?;
            let (plan, _) = engine::scan(&mut relay, &channels, &keys).await?;
            print_plan(&plan);
            out["plan"] = serde_json::to_value(&plan)?;
            ExitCode::SUCCESS
        }
        Command::Seal {
            limit,
            allow_unanchored_first_encryption,
            expect_zone_key,
        } => {
            let channels = channels(&cli)?;
            let path = state_path(&cli)?;
            let mut st = load_or_new(path, &relay_url, &me_pk)?;
            hooks!(hooks, path, cli.persist_every);
            let report = engine::seal_with(
                &mut relay,
                &me,
                &channels,
                &keys,
                &mut st,
                engine::SealOptions {
                    limit,
                    allow_unanchored_first_encryption,
                    expect_zone_keys: &expect_zone_key,
                },
                &mut hooks,
            )
            .await?;
            print_plan(&report.plan);
            eprintln!(
                "seal: {} sealed, {} adopted, {} failed, {} still to seal{}",
                report.sealed,
                report.adopted,
                report.failed.len(),
                report.remaining,
                if report.limit_reached {
                    " (stopped at --limit)"
                } else if report.stopped {
                    " (stopped by signal)"
                } else {
                    ""
                }
            );
            print_failures(&report.failed);
            out["result"] = serde_json::to_value(&report)?;
            exit_for(report.failed.is_empty())
        }
        Command::Verify => {
            let path = state_path(&cli)?;
            let mut st = load_existing(path, &relay_url, &me_pk)?;
            hooks!(hooks, path, cli.persist_every);
            let report = engine::verify(&mut relay, &keys, &mut st, &mut hooks).await?;
            print_failures(&report.failed);
            out["result"] = serde_json::to_value(&report)?;
            exit_for(report.failed.is_empty())
        }
        Command::Purge { yes } => {
            let path = state_path(&cli)?;
            let mut st = load_existing(path, &relay_url, &me_pk)?;
            hooks!(hooks, path, cli.persist_every);
            let report = engine::purge(&mut relay, &keys, &mut st, yes, &mut hooks).await?;
            eprintln!(
                "purge: {} deleted over {} requests, {} already gone, {} skipped (not kind 42){}",
                report.deleted,
                report.requests,
                report.not_found.len(),
                report.skipped.len(),
                if report.stopped {
                    " (stopped by signal)"
                } else {
                    ""
                }
            );
            out["result"] = serde_json::to_value(&report)?;
            exit_for(report.skipped.is_empty() && !report.stopped)
        }
        Command::Status => unreachable!("handled above"),
        Command::SealOffline {
            d1,
            sql_out,
            chunk,
            threads,
            limit,
        } => {
            let channels = channels(&cli)?;
            let path = state_path(&cli)?;
            let mut st = load_or_new(path, &relay_url, &me_pk)?;
            let db =
                offline::open_d1(&d1).map_err(|e| Failure(format!("{}: {e}", d1.display())))?;
            offline::check_schema(&db).map_err(Failure)?;
            let mut events = std::collections::HashMap::new();
            for c in &channels {
                let evs = offline::read_channel_events(&db, &c.id)
                    .map_err(|e| Failure(format!("reading channel {}: {e}", c.id)))?;
                eprintln!("read {} kind-42 rows for channel {}", evs.len(), c.id);
                events.insert(c.id.clone(), evs);
            }
            // The relay refuses a sealed envelope into a channel not bound to
            // the zone; offline checks the binding itself (channel_zones).
            let ids: Vec<String> = channels.iter().map(|c| c.id.clone()).collect();
            let bound = offline::read_channel_zones(&db, &ids)
                .map_err(|e| Failure(format!("reading channel_zones: {e}")))?;
            if let Some(why) = offline::binding_refusal(&channels, &bound) {
                return Err(Failure(format!("refusing to seal offline: {why}")));
            }
            let topic_channels = offline::read_topic_channels(&db, &offline::topics_of(&events))
                .map_err(|e| Failure(format!("resolving reply topics: {e}")))?;
            if let Some(n) = threads {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(n)
                    .build_global()
                    .map_err(|e| Failure(format!("--threads {n}: {e}")))?;
            }
            hooks!(hooks, path, cli.persist_every);
            let report = offline::seal_offline(
                &channels,
                &events,
                &topic_channels,
                &keys,
                &me,
                &mut st,
                limit,
                &mut hooks,
            )?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let files = offline::write_seal_sql(&sql_out, &report.sealed, &me_pk, chunk, now)
                .map_err(|e| Failure(format!("{}: {e}", sql_out.display())))?;
            let rate = report.sealed.len() as f64 / report.seal_seconds.max(1e-9);
            eprintln!(
                "seal-offline: {} sealed in {:.2}s ({rate:.0}/s on {} threads), {} adopted, {} failed; \
                 {} SQL chunks in {}. Apply them, then run seal-offline-commit.",
                report.sealed.len(),
                report.seal_seconds,
                rayon::current_num_threads(),
                report.adopted,
                report.failed.len(),
                files.len(),
                sql_out.display()
            );
            out["result"] = json!({
                "sealed": report.sealed.len(), "adopted": report.adopted,
                "failed": report.failed, "seal_seconds": report.seal_seconds,
                "events_per_second": rate, "threads": rayon::current_num_threads(),
                "chunks": files,
            });
            exit_for(report.failed.is_empty())
        }
        Command::ApplyDirect { .. } => unreachable!("handled above"),
        Command::ResealLegacy { d1, sql_out } => {
            let channels = channels(&cli)?;
            let db =
                offline::open_d1(&d1).map_err(|e| Failure(format!("{}: {e}", d1.display())))?;
            offline::check_schema(&db).map_err(Failure)?;
            let ids: Vec<String> = channels.iter().map(|c| c.id.clone()).collect();
            let bound = offline::read_channel_zones(&db, &ids)
                .map_err(|e| Failure(format!("reading channel_zones: {e}")))?;
            if let Some(why) = offline::binding_refusal(&channels, &bound) {
                return Err(Failure(format!("refusing to reseal: {why}")));
            }
            let envelopes = offline::read_migrator_envelopes(&db, &channels, &me_pk)
                .map_err(|e| Failure(format!("reading envelopes: {e}")))?;
            let mut events = std::collections::HashMap::new();
            for c in &channels {
                events.insert(
                    c.id.clone(),
                    offline::read_channel_events(&db, &c.id).map_err(|e| Failure(e.to_string()))?,
                );
            }
            // Topics of the ORIGINALS are inside the envelopes: resolve them
            // after opening, from the channels' plaintext and envelopes.
            let mut topics = offline::topics_of(&events);
            let zones: std::collections::HashMap<String, String> = channels
                .iter()
                .map(|c| (c.id.clone(), c.zone.clone()))
                .collect();
            for (ch, outer) in &envelopes {
                let key = zones
                    .get(ch)
                    .and_then(|z| keys.get(z, offline::envelope_epoch(outer, z)?));
                if let Some(k) = key {
                    if let Ok(o) = nostr_bbs_core::sealed::open_sealed(outer, k.secret()) {
                        if let Some(t) = nostr_bbs_core::sealed::reply_root_of(&o) {
                            topics.insert(t.to_string());
                        }
                    }
                }
            }
            let topic_channels = offline::read_topic_channels(&db, &topics)
                .map_err(|e| Failure(format!("resolving reply topics: {e}")))?;
            let (items, failed) =
                offline::reseal_legacy(&envelopes, &zones, &keys, &me, &topic_channels);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let file = offline::write_reseal_sql(&sql_out, &items, &me_pk, now)
                .map_err(|e| Failure(format!("{}: {e}", sql_out.display())))?;
            eprintln!(
                "reseal-legacy: {} of {} envelopes are legacy and were resealed, {} failed; wrote {}",
                items.len(),
                envelopes.len(),
                failed.len(),
                file.display()
            );
            out["result"] = json!({ "resealed": items.len(), "scanned": envelopes.len(), "failed": failed, "sql": file });
            exit_for(failed.is_empty())
        }
        Command::SealOfflineCommit {
            d1,
            manifest,
            reseal,
        } => {
            let path = state_path(&cli)?;
            let mut st = load_existing(path, &relay_url, &me_pk)?;
            let entries: Vec<offline::ManifestEntry> = serde_json::from_slice(
                &std::fs::read(&manifest)
                    .map_err(|e| Failure(format!("{}: {e}", manifest.display())))?,
            )?;
            let db =
                offline::open_d1(&d1).map_err(|e| Failure(format!("{}: {e}", d1.display())))?;
            let outer_ids: Vec<String> = entries.iter().map(|m| m.outer_id.clone()).collect();
            let outers = offline::read_events_by_id(&db, &outer_ids)
                .map_err(|e| Failure(format!("reading envelopes: {e}")))?;
            let bindings: std::collections::HashMap<String, String> = channels(&cli)?
                .into_iter()
                .map(|c| (c.id, c.zone))
                .collect();
            let report =
                offline::commit_sealed_with(&mut st, &entries, &outers, &keys, reseal, &bindings);
            state::save_atomic(path, &st).map_err(|e| Failure(e.to_string()))?;
            eprintln!(
                "seal-offline-commit: {} marked sealed, {} left as they were",
                report.committed,
                report.skipped.len()
            );
            out["result"] = serde_json::to_value(&report)?;
            exit_for(report.skipped.is_empty())
        }
        Command::PurgeOffline {
            d1,
            sql_out,
            chunk,
            yes,
        } => {
            if !yes {
                return Err(Failure(
                    "purge deletes the plaintext originals irreversibly; re-run with --yes".into(),
                ));
            }
            let path = state_path(&cli)?;
            let mut st = load_existing(path, &relay_url, &me_pk)?;
            let db =
                offline::open_d1(&d1).map_err(|e| Failure(format!("{}: {e}", d1.display())))?;
            offline::check_schema(&db).map_err(Failure)?;
            let outer_ids: Vec<String> = st
                .entries
                .values()
                .filter_map(|e| e.outer_id.clone())
                .collect();
            let outers = offline::read_events_by_id(&db, &outer_ids)
                .map_err(|e| Failure(format!("reading envelopes: {e}")))?;
            let mut zone_events = std::collections::HashMap::new();
            for zone in st.unanchored_zones.keys() {
                zone_events.insert(
                    zone.clone(),
                    offline::read_zone_events(&db, zone)
                        .map_err(|e| Failure(format!("zone {zone}: {e}")))?,
                );
            }
            let (ids, failed) = offline::purge_candidates(&mut st, &keys, &outers, &zone_events)?;
            state::save_atomic(path, &st).map_err(|e| Failure(e.to_string()))?;
            if !failed.is_empty() {
                return Err(Failure(format!(
                    "{} envelopes no longer open and match (first: {} — {}); nothing written",
                    failed.len(),
                    failed[0].0,
                    failed[0].1
                )));
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let files = offline::write_purge_sql(&sql_out, &ids, &me_pk, chunk, now)
                .map_err(|e| Failure(format!("{}: {e}", sql_out.display())))?;
            eprintln!(
                "purge-offline: {} ids in {} SQL chunks in {}. Apply them, then run purge-offline-commit.",
                ids.len(),
                files.len(),
                sql_out.display()
            );
            out["result"] = json!({ "ids": ids.len(), "chunks": files });
            ExitCode::SUCCESS
        }
        Command::PurgeOfflineCommit { d1, manifest } => {
            let path = state_path(&cli)?;
            let mut st = load_existing(path, &relay_url, &me_pk)?;
            let items: Vec<offline::PurgeItem> = serde_json::from_slice(
                &std::fs::read(&manifest)
                    .map_err(|e| Failure(format!("{}: {e}", manifest.display())))?,
            )?;
            let db =
                offline::open_d1(&d1).map_err(|e| Failure(format!("{}: {e}", d1.display())))?;
            let ids: Vec<String> = items.iter().map(|i| i.id.clone()).collect();
            let outer_ids: Vec<String> = items.iter().map(|i| i.outer_id.clone()).collect();
            let envelopes =
                offline::present_ids(&db, &outer_ids).map_err(|e| Failure(e.to_string()))?;
            let present = offline::present_ids(&db, &ids).map_err(|e| Failure(e.to_string()))?;
            let gone: std::collections::HashSet<String> = ids
                .iter()
                .filter(|i| !present.contains(*i))
                .cloned()
                .collect();
            let tomb = offline::tombstoned_ids(&db, &ids).map_err(|e| Failure(e.to_string()))?;
            let report = offline::commit_purged(&mut st, &items, &gone, &tomb, &envelopes);
            state::save_atomic(path, &st).map_err(|e| Failure(e.to_string()))?;
            eprintln!(
                "purge-offline-commit: {} marked purged, {} left as they were",
                report.committed,
                report.skipped.len()
            );
            out["result"] = serde_json::to_value(&report)?;
            exit_for(report.skipped.is_empty())
        }
    };
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    }
    Ok(code)
}

fn exit_for(clean: bool) -> ExitCode {
    if clean {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_ENTRIES_FAILED)
    }
}

#[derive(Serialize)]
struct GrantReport {
    accepted: usize,
    rejected: Vec<RejectedGrant>,
    ignored: usize,
}

/// Read the admin's zone-inbox secret from a file (hex or nsec). The file
/// content is zeroised after parsing and errors never echo it.
fn read_inbox_key(path: &Path) -> Result<SecretKey, Failure> {
    let text = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|e| Failure(format!("inbox key file {}: {e}", path.display())))?,
    );
    parse_identity(&text).map_err(|_| {
        Failure(format!(
            "inbox key file {}: not a 64-hex key or nsec",
            path.display()
        ))
    })
}

async fn load_keys(
    cli: &Cli,
    relay: &mut NetRelay,
    me: &SecretKey,
) -> Result<(KeyRing, Option<GrantReport>), Failure> {
    let mut ring = KeyRing::new();
    if let Some(path) = &cli.keys_file {
        let text = Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|e| Failure(format!("key file {}: {e}", path.display())))?,
        );
        let file = parse_key_file(&text)?;
        if file.owner != me.public_key().to_hex() {
            eprintln!(
                "warning: key file owner {} is not the admin key in use",
                file.owner
            );
        }
        let n = file.keys.len();
        for key in file.keys {
            ring.insert(key)?;
        }
        eprintln!("loaded {n} zone keys from {}", path.display());
    }
    let mut report = None;
    if cli.fetch_grants {
        let inbox = match &cli.inbox_key {
            Some(path) => Some(read_inbox_key(path)?),
            None => None,
        };
        let harvest = fetch_grants_with(relay, me, inbox.as_ref(), &cli.group_pubkey).await?;
        let accepted = harvest.keys.len();
        for key in harvest.keys {
            ring.insert(key)?;
        }
        for r in &harvest.rejected {
            eprintln!("refused grant {}: {}", r.wrap_id, r.reason);
        }
        eprintln!(
            "grants: {accepted} accepted, {} refused, {} other gift wraps ignored",
            harvest.rejected.len(),
            harvest.ignored
        );
        report = Some(GrantReport {
            accepted,
            rejected: harvest.rejected,
            ignored: harvest.ignored,
        });
    }
    for s in ring.summaries() {
        eprintln!("zone key {}:{} {}", s.zone, s.epoch, s.pubkey);
    }
    Ok((ring, report))
}

fn channels(cli: &Cli) -> Result<Vec<ChannelSpec>, Failure> {
    let path = cli.channels.as_ref().ok_or_else(|| {
        Failure("--channels <path> is required (use --print-channels to list them)".into())
    })?;
    let text = std::fs::read_to_string(path)
        .map_err(|e| Failure(format!("channels file {}: {e}", path.display())))?;
    Ok(parse_channels(&text)?)
}

fn state_path(cli: &Cli) -> Result<&Path, Failure> {
    cli.state
        .as_deref()
        .ok_or_else(|| Failure("--state <path> is required for this command".into()))
}

fn set_aside_tmp(path: &Path) -> Result<(), Failure> {
    if let Some(aside) =
        state::set_aside_stale_tmp(path).map_err(|e| Failure(format!("{}: {e}", path.display())))?
    {
        eprintln!(
            "note: a leftover {}.tmp (an interrupted save) was moved to {}; the state file itself is the last complete save",
            path.display(),
            aside.display()
        );
    }
    Ok(())
}

fn load_or_new(path: &Path, relay: &str, me: &str) -> Result<State, Failure> {
    set_aside_tmp(path)?;
    match state::load(path)? {
        Some(s) => {
            s.check_matches(relay, me)?;
            Ok(s)
        }
        None => Ok(State::new(relay, me)),
    }
}

fn load_existing(path: &Path, relay: &str, me: &str) -> Result<State, Failure> {
    set_aside_tmp(path)?;
    let s = state::load(path)?.ok_or_else(|| {
        Failure(format!(
            "state file {} does not exist; run seal first",
            path.display()
        ))
    })?;
    s.check_matches(relay, me)?;
    Ok(s)
}

fn status(cli: &Cli) -> Result<ExitCode, Failure> {
    let path = state_path(cli)?;
    let st = state::load(path)?
        .ok_or_else(|| Failure(format!("state file {} does not exist", path.display())))?;
    let c = st.counts();
    eprintln!(
        "{}: relay {}, migrator {}\n  total {}  planned {}  sealed {}  verified {}  purged {}  failed {}",
        path.display(),
        st.relay,
        st.migrator,
        c.total,
        c.planned,
        c.sealed,
        c.verified,
        c.purged,
        c.failed
    );
    let failed: Vec<Value> = st
        .entries
        .iter()
        .filter_map(|(id, e)| match &e.status {
            Status::Failed { step, reason } => {
                eprintln!("  failed {id} at {step:?}: {reason}");
                Some(json!({ "id": id, "step": step, "reason": reason }))
            }
            _ => None,
        })
        .collect();
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "command": "status",
                "relay": st.relay,
                "migrator": st.migrator,
                "counts": c,
                "failed": failed,
            }))?
        );
    }
    Ok(ExitCode::SUCCESS)
}

async fn print_channels(cli: &Cli, relay: &mut NetRelay) -> Result<ExitCode, Failure> {
    let fetched = fetch_all(
        relay,
        &Filter {
            kinds: Some(vec![40]),
            ..Filter::default()
        },
    )
    .await?;
    let listed = list_channels(&fetched.events);
    for c in &listed {
        eprintln!(
            "{}  section={:<16} {}",
            c.id,
            if c.section.is_empty() {
                "-"
            } else {
                &c.section
            },
            c.name
        );
    }
    eprintln!("{} channels", listed.len());
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&listed)?);
    }
    Ok(ExitCode::SUCCESS)
}

fn print_plan(plan: &Plan) {
    for c in &plan.channels {
        eprintln!(
            "channel {} ({}, seal key epoch {}): {} plaintext, {} already sealed, {} to seal, \
             {} bad signatures, {} encrypted posts, {} envelopes",
            c.channel,
            c.zone,
            c.seal_epoch
                .map(|e| e.to_string())
                .unwrap_or_else(|| "none".into()),
            c.plaintext,
            c.already_sealed,
            c.would_seal.len(),
            c.invalid_signature.len(),
            c.encrypted_posts,
            c.envelopes
        );
        for id in &c.would_seal {
            eprintln!("  would seal {id}");
        }
        for id in &c.invalid_signature {
            eprintln!("  bad signature, left as is: {id}");
        }
    }
    let (p, a, w) = plan.totals();
    eprintln!("total: {p} plaintext, {a} already sealed, {w} to seal");
    if !plan.zones_without_key.is_empty() {
        eprintln!(
            "warning: no zone key held for {}; seal will refuse until one is (--keys-file or --fetch-grants)",
            plan.zones_without_key.join(", ")
        );
    }
    for (channel, second) in &plan.incomplete_seconds {
        eprintln!(
            "warning: channel {channel} has more than one relay page of events at created_at {second}; some may be missing from this plan"
        );
    }
}

fn print_failures(failed: &[(String, String)]) {
    for (id, reason) in failed {
        eprintln!("  failed {id}: {reason}");
    }
}

/// Parse `ZONE=EPOCH:PUBKEY` for `--expect-zone-key`.
fn parse_expect_zone_key(s: &str) -> Result<(String, u32, String), String> {
    let (zone, rest) = s.split_once('=').ok_or("expected ZONE=EPOCH:PUBKEY")?;
    let (epoch, pk) = rest.split_once(':').ok_or("expected ZONE=EPOCH:PUBKEY")?;
    let epoch = epoch.parse::<u32>().map_err(|_| "EPOCH must be a number")?;
    if zone.is_empty() || pk.len() != 64 || !pk.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("ZONE must be non-empty and PUBKEY 64 hex characters".into());
    }
    Ok((zone.to_string(), epoch, pk.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(line: &str) -> Cli {
        Cli::try_parse_from(line.split_whitespace()).unwrap()
    }

    #[test]
    fn clap_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    /// The runbook's `$M` prefix, followed by each documented subcommand.
    #[test]
    fn runbook_command_lines_parse() {
        let m = "nostr-bbs-zone-migrate --relay wss://relay.example.org \
                 --channels channels.json --fetch-grants --state migrate-state.json";
        let cli = parse(&format!("{m} plan"));
        assert!(matches!(cli.command, Some(Command::Plan)));
        assert_eq!(cli.relay.as_deref(), Some("wss://relay.example.org"));
        assert!(cli.fetch_grants);
        assert!(matches!(
            parse(&format!("{m} seal --limit 20")).command,
            Some(Command::Seal {
                limit: Some(20),
                allow_unanchored_first_encryption: false,
                ..
            })
        ));
        assert!(matches!(
            parse(&format!("{m} seal")).command,
            Some(Command::Seal {
                limit: None,
                allow_unanchored_first_encryption: false,
                ..
            })
        ));
        assert!(matches!(
            parse(&format!(
                "{m} seal --allow-unanchored-first-encryption --expect-zone-key zone3=2:{}",
                "a".repeat(64)
            ))
            .command,
            Some(Command::Seal {
                limit: None,
                allow_unanchored_first_encryption: true,
                ref expect_zone_key,
            }) if expect_zone_key.len() == 1 && expect_zone_key[0].1 == 2
        ));
        assert!(parse_expect_zone_key("zone3=x:abc").is_err());
        assert!(parse_expect_zone_key("zone3:2").is_err());
        assert!(matches!(
            parse(&format!("{m} verify")).command,
            Some(Command::Verify)
        ));
        assert!(matches!(
            parse(&format!("{m} purge --yes")).command,
            Some(Command::Purge { yes: true })
        ));
        assert!(matches!(
            parse(&format!("{m} purge")).command,
            Some(Command::Purge { yes: false })
        ));
        assert!(matches!(
            parse(&format!("{m} status")).command,
            Some(Command::Status)
        ));
        // `plan` is the default, and global options also follow the subcommand.
        assert!(parse(m).command.is_none());
        let cli = parse("nostr-bbs-zone-migrate verify --relay wss://r --state s.json --json");
        assert!(cli.json && cli.state.is_some());
        assert!(parse("nostr-bbs-zone-migrate --relay wss://r --print-channels").print_channels);
    }

    #[test]
    fn inbox_key_flag_is_optional_and_reads_a_file() {
        assert!(parse("nostr-bbs-zone-migrate --relay wss://r plan")
            .inbox_key
            .is_none());
        let cli = parse(
            "nostr-bbs-zone-migrate --relay wss://r --fetch-grants --inbox-key /k/inbox plan",
        );
        assert_eq!(cli.inbox_key.as_deref(), Some(Path::new("/k/inbox")));
        let dir = std::env::temp_dir().join(format!("zm-inbox-{}", std::process::id()));
        std::fs::write(&dir, format!("{}\n", "11".repeat(32))).unwrap();
        assert!(read_inbox_key(&dir).is_ok());
        std::fs::write(&dir, "nonsense").unwrap();
        assert!(read_inbox_key(&dir).is_err());
        std::fs::remove_file(&dir).unwrap();
        assert!(read_inbox_key(Path::new("/nonexistent/zm-inbox")).is_err());
    }

    #[test]
    fn there_is_no_flag_for_the_secret_key() {
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("NOSTR_BBS_MIGRATE_KEY"));
        for flag in ["--key", "--nsec", "--secret"] {
            assert!(Cli::try_parse_from(["x", flag, "abc"]).is_err(), "{flag}");
        }
    }
}
