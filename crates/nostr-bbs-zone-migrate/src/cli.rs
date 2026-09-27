//! Command-line front end: argument parsing, key loading, output.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use nostr_bbs_core::keys::SecretKey;
use nostr_bbs_zone_migrate::channels::{list_channels, parse_channels, ChannelSpec};
use nostr_bbs_zone_migrate::engine::{self, Hooks, Plan};
use nostr_bbs_zone_migrate::grants::{fetch_grants, RejectedGrant};
use nostr_bbs_zone_migrate::identity::{identity_from_env, IDENTITY_ENV};
use nostr_bbs_zone_migrate::keys::{parse_key_file, KeyRing};
use nostr_bbs_zone_migrate::relay::{fetch_all, http_origin, Filter, Relay};
use nostr_bbs_zone_migrate::state::{self, State, Status};
use serde::Serialize;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::net::NetRelay;

/// Declare `$hooks`: engine hooks that save `$path` atomically after each
/// change and log progress lines to stderr.
macro_rules! hooks {
    ($hooks:ident, $path:expr) => {
        let path: &Path = $path;
        let mut persist = |s: &State| state::save_atomic(path, s);
        let mut progress = |line: &str| eprintln!("{line}");
        let mut $hooks = Hooks {
            persist: &mut persist,
            progress: &mut progress,
        };
    };
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

#[derive(Subcommand, Clone, Copy)]
enum Command {
    /// Dry run (default): per channel, plaintext count, already-sealed count and ids to seal. Writes nothing.
    Plan,
    /// Publish an envelope per planned original, read it back and check it. Resumable.
    Seal {
        /// Seal at most this many originals in this run.
        #[arg(long, value_name = "N")]
        limit: Option<usize>,
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
}

impl Command {
    fn name(self) -> &'static str {
        match self {
            Command::Plan => "plan",
            Command::Seal { .. } => "seal",
            Command::Verify => "verify",
            Command::Purge { .. } => "purge",
            Command::Status => "status",
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
    let command = cli.command.unwrap_or(Command::Plan);

    if !cli.print_channels {
        if let Command::Status = command {
            return status(&cli);
        }
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
        Command::Seal { limit } => {
            let channels = channels(&cli)?;
            let path = state_path(&cli)?;
            let mut st = load_or_new(path, &relay_url, &me_pk)?;
            hooks!(hooks, path);
            let report = engine::seal(
                &mut relay, &me, &channels, &keys, &mut st, limit, &mut hooks,
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
            hooks!(hooks, path);
            let report = engine::verify(&mut relay, &keys, &mut st, &mut hooks).await?;
            print_failures(&report.failed);
            out["result"] = serde_json::to_value(&report)?;
            exit_for(report.failed.is_empty())
        }
        Command::Purge { yes } => {
            let path = state_path(&cli)?;
            let mut st = load_existing(path, &relay_url, &me_pk)?;
            hooks!(hooks, path);
            let report = engine::purge(&mut relay, &keys, &mut st, yes, &mut hooks).await?;
            eprintln!(
                "purge: {} deleted over {} requests, {} already gone, {} skipped (not kind 42)",
                report.deleted,
                report.requests,
                report.not_found.len(),
                report.skipped.len()
            );
            out["result"] = serde_json::to_value(&report)?;
            exit_for(report.skipped.is_empty())
        }
        Command::Status => unreachable!("handled above"),
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
        let harvest = fetch_grants(relay, me).await?;
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

fn load_or_new(path: &Path, relay: &str, me: &str) -> Result<State, Failure> {
    match state::load(path)? {
        Some(s) => {
            s.check_matches(relay, me)?;
            Ok(s)
        }
        None => Ok(State::new(relay, me)),
    }
}

fn load_existing(path: &Path, relay: &str, me: &str) -> Result<State, Failure> {
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
            Some(Command::Seal { limit: Some(20) })
        ));
        assert!(matches!(
            parse(&format!("{m} seal")).command,
            Some(Command::Seal { limit: None })
        ));
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
    fn there_is_no_flag_for_the_secret_key() {
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("NOSTR_BBS_MIGRATE_KEY"));
        for flag in ["--key", "--nsec", "--secret"] {
            assert!(Cli::try_parse_from(["x", flag, "abc"]).is_err(), "{flag}");
        }
    }
}
